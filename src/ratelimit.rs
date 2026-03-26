//! Rate limiting helpers for bug bounty programs.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use http::header::RETRY_AFTER;
use reqwest::{Client, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};
use url::Url;

use crate::error::BugscopeError;
use crate::scope::ScopePattern;

/// Rate limiting configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Default requests per second for unmatched URLs.
    #[serde(default = "default_requests_per_second")]
    pub default_requests_per_second: f64,
    /// Maximum exponential backoff retries after a `429`.
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    /// Pattern-specific rules evaluated in order.
    #[serde(default)]
    pub rules: Vec<RateLimitRule>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default_requests_per_second: default_requests_per_second(),
            max_retries: default_max_retries(),
            rules: Vec::new(),
        }
    }
}

/// A single rate-limit rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// Domain, wildcard domain, IP, or CIDR pattern.
    pub pattern: String,
    /// Requests per second for this pattern.
    pub requests_per_second: f64,
    /// Bucket size for bursts.
    #[serde(default = "default_burst")]
    pub burst: u32,
    /// Maximum retry-after delay honored for this rule.
    #[serde(default = "default_retry_after_cap", with = "humantime_serde")]
    pub retry_after_cap: Duration,
}

impl Default for RateLimitRule {
    fn default() -> Self {
        Self {
            pattern: "*".to_string(),
            requests_per_second: default_requests_per_second(),
            burst: default_burst(),
            retry_after_cap: default_retry_after_cap(),
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledRule {
    matcher: Option<ScopePattern>,
    requests_per_second: f64,
    burst: f64,
    retry_after_cap: Duration,
}

#[derive(Debug, Clone)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
    backoff_until: Option<Instant>,
    consecutive_429s: u32,
}

/// Async rate limiter with pattern-aware policies.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    config: RateLimitConfig,
    rules: Arc<Vec<CompiledRule>>,
    states: Arc<Mutex<Vec<BucketState>>>,
}

impl RateLimitConfig {
    /// Load rate limits from a TOML file.
    ///
    /// # Errors
    /// Returns an error when the file cannot be read or parsed.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, BugscopeError> {
        let path = path.as_ref();
        let contents =
            std::fs::read_to_string(path).map_err(|error| BugscopeError::io(path.into(), error))?;
        toml::from_str(&contents).map_err(|error| BugscopeError::parse(path.into(), error))
    }

    /// Override all requests-per-second values with a CLI-provided limit.
    pub fn override_requests_per_second(&mut self, requests_per_second: f64) {
        self.default_requests_per_second = requests_per_second;
        for rule in &mut self.rules {
            rule.requests_per_second = requests_per_second;
        }
    }
}

impl RateLimiter {
    /// Build a rate limiter from configuration.
    ///
    /// # Errors
    /// Returns an error when a scope pattern is invalid.
    pub fn new(config: RateLimitConfig) -> Result<Self, BugscopeError> {
        validate_rate_limit(
            "default_requests_per_second",
            config.default_requests_per_second,
        )?;
        let mut compiled = Vec::with_capacity(config.rules.len() + 1);
        compiled.push(CompiledRule {
            matcher: None,
            requests_per_second: config.default_requests_per_second,
            burst: 1.0,
            retry_after_cap: default_retry_after_cap(),
        });

        for rule in &config.rules {
            validate_rate_limit(
                &format!("rules[{}].requests_per_second", compiled.len() - 1),
                rule.requests_per_second,
            )?;
            validate_burst(
                &format!("rules[{}].burst", compiled.len() - 1),
                rule.burst,
            )?;
            let matcher = if rule.pattern == "*" {
                None
            } else {
                Some(ScopePattern::parse(&rule.pattern)?)
            };

            compiled.push(CompiledRule {
                matcher,
                requests_per_second: rule.requests_per_second,
                burst: f64::from(rule.burst.max(1)),
                retry_after_cap: rule.retry_after_cap,
            });
        }

        let now = Instant::now();
        let states = compiled
            .iter()
            .map(|rule| BucketState {
                tokens: rule.burst,
                last_refill: now,
                backoff_until: None,
                consecutive_429s: 0,
            })
            .collect::<Vec<_>>();

        Ok(Self {
            config,
            rules: Arc::new(compiled),
            states: Arc::new(Mutex::new(states)),
        })
    }

    /// Wait until the URL is allowed under the configured limit.
    ///
    /// # Errors
    /// Returns an error when the matching rule contains an invalid scope pattern.
    pub async fn acquire(&self, url: &Url) -> Result<(), BugscopeError> {
        loop {
            let rule_index = self.rule_index(url);
            let wait_duration = {
                let mut states = self.states.lock().await;
                let state = &mut states[rule_index];
                let rule = &self.rules[rule_index];
                refill(state, rule);

                if let Some(backoff_until) = state.backoff_until {
                    let now = Instant::now();
                    if backoff_until > now {
                        Some(backoff_until - now)
                    } else {
                        state.backoff_until = None;
                        None
                    }
                } else if state.tokens >= 1.0 {
                    state.tokens -= 1.0;
                    None
                } else {
                    let deficit = 1.0 - state.tokens;
                    Some(Duration::from_secs_f64(
                        deficit / rule.requests_per_second.max(f64::EPSILON),
                    ))
                }
            };

            match wait_duration {
                Some(duration) => sleep(duration).await,
                None => return Ok(()),
            }
        }
    }

    /// Update backoff state based on an HTTP response.
    pub async fn record_response(&self, url: &Url, response: &Response) {
        let rule_index = self.rule_index(url);
        let mut states = self.states.lock().await;
        let state = &mut states[rule_index];
        let rule = &self.rules[rule_index];

        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            state.consecutive_429s = state.consecutive_429s.saturating_add(1);
            let delay = retry_after_delay(response).map_or_else(
                || {
                    let multiplier = 2_u32.saturating_pow(state.consecutive_429s.saturating_sub(1));
                    Duration::from_secs_f64(
                        (1.0 / rule.requests_per_second.max(f64::EPSILON)) * f64::from(multiplier),
                    )
                    .min(rule.retry_after_cap)
                },
                |duration| duration.min(rule.retry_after_cap),
            );
            state.backoff_until = Some(Instant::now() + delay);
        } else if state
            .backoff_until
            .map_or(true, |backoff| Instant::now() >= backoff)
        {
            state.consecutive_429s = 0;
            state.backoff_until = None;
        }
    }

    /// Execute a request while applying rate limits and automatic 429 backoff.
    ///
    /// # Errors
    /// Returns an error when the underlying request fails.
    pub async fn execute(
        &self,
        client: &Client,
        request: Request,
    ) -> Result<Response, BugscopeError> {
        let request_url = request.url().clone();
        let mut attempt = 0_usize;
        let mut current_request = request;

        loop {
            self.acquire(&request_url).await?;
            let retry_request = current_request.try_clone();
            let response = client.execute(current_request).await?;
            self.record_response(&request_url, &response).await;

            if response.status() != StatusCode::TOO_MANY_REQUESTS
                || attempt >= self.config.max_retries
            {
                return Ok(response);
            }

            let Some(next_request) = retry_request else {
                return Ok(response);
            };

            attempt += 1;
            current_request = next_request;
        }
    }

    fn rule_index(&self, url: &Url) -> usize {
        let Some(host) = url.host_str() else {
            return 0;
        };

        self.rules
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(index, rule)| {
                rule.matcher
                    .as_ref()
                    .and_then(|matcher| matcher.matches(host).then_some(index))
            })
            .unwrap_or(0)
    }
}

fn refill(state: &mut BucketState, rule: &CompiledRule) {
    let now = Instant::now();
    let elapsed = now.duration_since(state.last_refill).as_secs_f64();
    if elapsed > 0.0 {
        state.tokens = (state.tokens + elapsed * rule.requests_per_second).min(rule.burst);
        state.last_refill = now;
    }
}

fn retry_after_delay(response: &Response) -> Option<Duration> {
    let value = response.headers().get(RETRY_AFTER)?.to_str().ok()?;
    value.parse::<u64>().ok().map(Duration::from_secs)
}

fn validate_burst(field: &str, burst: u32) -> Result<(), BugscopeError> {
    if burst == 0 || burst > 10_000 {
        return Err(BugscopeError::InvalidRateLimit {
            field: field.to_string(),
            value: burst.to_string(),
        });
    }
    Ok(())
}

fn validate_rate_limit(field: &str, requests_per_second: f64) -> Result<(), BugscopeError> {
    if !requests_per_second.is_finite() || requests_per_second <= 0.0 {
        return Err(BugscopeError::InvalidRateLimit {
            field: field.to_string(),
            value: requests_per_second.to_string(),
        });
    }

    if requests_per_second > max_requests_per_second() {
        return Err(BugscopeError::InvalidRateLimit {
            field: field.to_string(),
            value: requests_per_second.to_string(),
        });
    }

    Ok(())
}

const fn default_requests_per_second() -> f64 {
    2.0
}

const fn default_max_retries() -> usize {
    2
}

const fn default_burst() -> u32 {
    1
}

const fn default_retry_after_cap() -> Duration {
    Duration::from_secs(30)
}

const fn max_requests_per_second() -> f64 {
    10_000.0
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant as StdInstant};

    use http::StatusCode;
    use reqwest::Client;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::BugscopeError;

    use super::{RateLimitConfig, RateLimitRule, RateLimiter};

    #[test]
    fn override_requests_per_second_updates_rules() {
        let mut config = RateLimitConfig {
            rules: vec![RateLimitRule {
                pattern: "*.example.com".to_string(),
                requests_per_second: 5.0,
                ..RateLimitRule::default()
            }],
            ..RateLimitConfig::default()
        };

        config.override_requests_per_second(3.0);
        assert!((config.default_requests_per_second - 3.0).abs() < f64::EPSILON);
        assert!((config.rules[0].requests_per_second - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn load_config_from_toml() {
        let toml = r#"
            default_requests_per_second = 1.5
            max_retries = 4

            [[rules]]
            pattern = "*.example.com"
            requests_per_second = 0.5
            burst = 2
            retry_after_cap = "10s"
        "#;

        let config: RateLimitConfig = toml::from_str(toml).expect("config");
        assert!((config.default_requests_per_second - 1.5).abs() < f64::EPSILON);
        assert_eq!(config.max_retries, 4);
        assert_eq!(config.rules[0].burst, 2);
    }

    #[test]
    fn invalid_pattern_is_rejected() {
        let config = RateLimitConfig {
            rules: vec![RateLimitRule {
                pattern: "exa*mple.com".to_string(),
                requests_per_second: 1.0,
                ..RateLimitRule::default()
            }],
            ..RateLimitConfig::default()
        };

        match RateLimiter::new(config) {
            Err(BugscopeError::InvalidScopePattern { pattern }) => {
                assert_eq!(pattern, "exa*mple.com");
            }
            other => panic!("expected invalid scope pattern error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_excessive_default_rate_limit() {
        let config = RateLimitConfig {
            default_requests_per_second: 10_001.0,
            ..RateLimitConfig::default()
        };

        assert!(RateLimiter::new(config).is_err());
    }

    #[test]
    fn rejects_non_positive_rule_rate_limit() {
        let config = RateLimitConfig {
            rules: vec![RateLimitRule {
                pattern: "*.example.com".to_string(),
                requests_per_second: 0.0,
                ..RateLimitRule::default()
            }],
            ..RateLimitConfig::default()
        };

        assert!(RateLimiter::new(config).is_err());
    }

    #[tokio::test]
    async fn acquires_immediately_for_first_request() {
        let limiter = RateLimiter::new(RateLimitConfig::default()).expect("limiter");
        let url = Url::parse("https://example.com").expect("url");
        let start = StdInstant::now();

        limiter.acquire(&url).await.expect("acquire");

        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn second_request_waits_for_default_rule() {
        let limiter = RateLimiter::new(RateLimitConfig {
            default_requests_per_second: 20.0,
            ..RateLimitConfig::default()
        })
        .expect("limiter");
        let url = Url::parse("https://example.com").expect("url");

        limiter.acquire(&url).await.expect("first");
        let start = StdInstant::now();
        limiter.acquire(&url).await.expect("second");

        assert!(start.elapsed() >= Duration::from_millis(45));
    }

    #[tokio::test]
    async fn uses_pattern_specific_rule() {
        let limiter = RateLimiter::new(RateLimitConfig {
            default_requests_per_second: 100.0,
            rules: vec![RateLimitRule {
                pattern: "*.example.com".to_string(),
                requests_per_second: 10.0,
                ..RateLimitRule::default()
            }],
            ..RateLimitConfig::default()
        })
        .expect("limiter");

        let url = Url::parse("https://api.example.com").expect("url");
        limiter.acquire(&url).await.expect("first");
        let start = StdInstant::now();
        limiter.acquire(&url).await.expect("second");

        assert!(start.elapsed() >= Duration::from_millis(90));
    }

    #[tokio::test]
    async fn burst_allows_multiple_immediate_requests() {
        let limiter = RateLimiter::new(RateLimitConfig {
            default_requests_per_second: 1.0,
            rules: vec![RateLimitRule {
                pattern: "*.example.com".to_string(),
                requests_per_second: 1.0,
                burst: 2,
                ..RateLimitRule::default()
            }],
            ..RateLimitConfig::default()
        })
        .expect("limiter");
        let url = Url::parse("https://api.example.com").expect("url");

        let start = StdInstant::now();
        limiter.acquire(&url).await.expect("first");
        limiter.acquire(&url).await.expect("second");

        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn unmatched_hosts_use_default_rule() {
        let limiter = RateLimiter::new(RateLimitConfig {
            default_requests_per_second: 15.0,
            rules: vec![RateLimitRule {
                pattern: "*.example.com".to_string(),
                requests_per_second: 100.0,
                ..RateLimitRule::default()
            }],
            ..RateLimitConfig::default()
        })
        .expect("limiter");
        let url = Url::parse("https://outside.test").expect("url");

        limiter.acquire(&url).await.expect("first");
        let start = StdInstant::now();
        limiter.acquire(&url).await.expect("second");

        assert!(start.elapsed() >= Duration::from_millis(60));
    }

    #[tokio::test]
    async fn records_backoff_after_429() {
        let server = MockServer::start().await;
        let limiter = RateLimiter::new(RateLimitConfig::default()).expect("limiter");
        let client = Client::new();
        let url = Url::parse(&server.uri()).expect("url");

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(
                StatusCode::TOO_MANY_REQUESTS.as_u16(),
            ))
            .mount(&server)
            .await;

        let request = client.get(server.uri()).build().expect("request");
        let response = limiter.execute(&client, request).await.expect("response");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        let start = StdInstant::now();
        limiter.acquire(&url).await.expect("backoff acquire");
        assert!(start.elapsed() >= Duration::from_millis(450));
    }

    #[tokio::test]
    async fn honors_retry_after_header() {
        let server = MockServer::start().await;
        let limiter = RateLimiter::new(RateLimitConfig::default()).expect("limiter");
        let client = Client::new();
        let url = Url::parse(&server.uri()).expect("url");

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(StatusCode::TOO_MANY_REQUESTS.as_u16())
                    .insert_header("Retry-After", "1"),
            )
            .mount(&server)
            .await;

        let request = client.get(server.uri()).build().expect("request");
        let response = limiter.execute(&client, request).await.expect("response");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        let start = StdInstant::now();
        limiter.acquire(&url).await.expect("backoff acquire");
        assert!(start.elapsed() >= Duration::from_millis(950));
    }

    #[tokio::test]
    async fn retries_after_429_when_request_is_cloneable() {
        let server = MockServer::start().await;
        let limiter = RateLimiter::new(RateLimitConfig {
            max_retries: 1,
            ..RateLimitConfig::default()
        })
        .expect("limiter");
        let client = Client::new();

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(StatusCode::TOO_MANY_REQUESTS.as_u16())
                    .insert_header("Retry-After", "0"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(StatusCode::OK.as_u16()))
            .mount(&server)
            .await;

        let request = client.get(server.uri()).build().expect("request");
        let response = limiter.execute(&client, request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
