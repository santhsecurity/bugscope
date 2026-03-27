//! Scope parsing and enforcement for security scanners.

use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;

use idna::domain_to_ascii;
use ipnet::IpNet;
use regex::Regex;
use reqwest::{Client, Method, Request, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::BugscopeError;
use crate::headers::HeaderSet;
use crate::ratelimit::RateLimiter;

/// A bug bounty or security program scope definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BountyProgram {
    /// The platform hosting the program.
    pub platform: Platform,
    /// The human-readable program name.
    pub name: String,
    /// Explicitly allowed targets.
    #[serde(default)]
    pub in_scope: Vec<ScopeTarget>,
    /// Explicitly excluded targets.
    #[serde(default)]
    pub out_of_scope: Vec<ScopeTarget>,
}

/// A single target entry within a program scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeTarget {
    /// The raw target value.
    pub target: String,
    /// The target category.
    pub target_type: TargetType,
    /// Whether the program says this target is bounty eligible.
    pub eligible_for_bounty: bool,
    /// The maximum severity accepted for this target, when specified.
    pub max_severity: Option<String>,
}

/// A supported bounty platform identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Platform {
    /// `HackerOne`.
    HackerOne,
    /// `Bugcrowd`.
    Bugcrowd,
    /// `Intigriti`.
    Intigriti,
    /// `YesWeHack`.
    YesWeHack,
    /// Any other platform.
    Other(String),
}

impl Platform {
    /// Construct a `HackerOne` platform identifier.
    #[must_use]
    pub fn hackerone() -> Self {
        Self::HackerOne
    }

    /// Construct a `Bugcrowd` platform identifier.
    #[must_use]
    pub fn bugcrowd() -> Self {
        Self::Bugcrowd
    }

    /// Construct an `Intigriti` platform identifier.
    #[must_use]
    pub fn intigriti() -> Self {
        Self::Intigriti
    }

    /// Construct a `YesWeHack` platform identifier.
    #[must_use]
    pub fn yeswehack() -> Self {
        Self::YesWeHack
    }

    /// Construct a custom platform identifier.
    #[must_use]
    pub fn custom(name: impl Into<String>) -> Self {
        Self::Other(name.into())
    }

    /// Return the normalized key used in config files.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::HackerOne => "hackerone".to_string(),
            Self::Bugcrowd => "bugcrowd".to_string(),
            Self::Intigriti => "intigriti".to_string(),
            Self::YesWeHack => "yeswehack".to_string(),
            Self::Other(value) => value.to_ascii_lowercase(),
        }
    }

    /// Return the display suffix used in platform-specific headers.
    #[must_use]
    pub fn header_suffix(&self) -> String {
        match self {
            Self::HackerOne => "HackerOne".to_string(),
            Self::Bugcrowd => "Bugcrowd".to_string(),
            Self::Intigriti => "Intigriti".to_string(),
            Self::YesWeHack => "YesWeHack".to_string(),
            Self::Other(value) => value.clone(),
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.key())
    }
}

impl Default for Platform {
    fn default() -> Self {
        Self::Other("custom".to_string())
    }
}

impl Serialize for Platform {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.key())
    }
}

impl<'de> Deserialize<'de> for Platform {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(parse_platform(&value))
    }
}

/// A supported target category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetType {
    /// An exact domain or hostname.
    Domain,
    /// A wildcard domain.
    Wildcard,
    /// An IP range or CIDR.
    IpRange,
    /// A specific URL or URL path prefix.
    Url,
    /// A mobile app identifier.
    Mobile,
    /// An API-specific target.
    Api,
    /// Any other target type.
    Other(String),
}

impl Serialize for TargetType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self {
            Self::Domain => "domain",
            Self::Wildcard => "wildcard",
            Self::IpRange => "ip_range",
            Self::Url => "url",
            Self::Mobile => "mobile",
            Self::Api => "api",
            Self::Other(value) => value.as_str(),
        })
    }
}

impl<'de> Deserialize<'de> for TargetType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(parse_target_type(&value))
    }
}

#[derive(Debug, Deserialize)]
struct ScopeFileRecord {
    program: String,
    platform: String,
    #[serde(default)]
    in_scope: Vec<ScopeFileTarget>,
    #[serde(default)]
    out_of_scope: Vec<ScopeFileTarget>,
}

#[derive(Debug, Deserialize)]
struct ScopeFileTarget {
    target: String,
    #[serde(rename = "type")]
    target_type: String,
    #[serde(default)]
    eligible_for_bounty: Option<bool>,
    #[serde(default)]
    max_severity: Option<String>,
}

/// URL scope configuration used by request guards and rate limiting.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScopeConfig {
    /// Allowed domains, wildcard domains, IPs, or CIDRs.
    #[serde(default)]
    pub in_scope: Vec<String>,
    /// Explicit exclusions checked before `in_scope`.
    #[serde(default)]
    pub out_of_scope: Vec<String>,
    #[serde(skip)]
    compiled: OnceLock<Result<CompiledScopeConfig, String>>,
}

impl Clone for ScopeConfig {
    fn clone(&self) -> Self {
        Self {
            in_scope: self.in_scope.clone(),
            out_of_scope: self.out_of_scope.clone(),
            compiled: OnceLock::new(),
        }
    }
}

impl PartialEq for ScopeConfig {
    fn eq(&self, other: &Self) -> bool {
        self.in_scope == other.in_scope && self.out_of_scope == other.out_of_scope
    }
}

impl Eq for ScopeConfig {}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            in_scope: Vec::new(),
            out_of_scope: Vec::new(),
            compiled: OnceLock::new(),
        }
    }
}

impl From<&BountyProgram> for ScopeConfig {
    fn from(program: &BountyProgram) -> Self {
        Self {
            in_scope: program
                .in_scope
                .iter()
                .map(|target| target.target.clone())
                .collect(),
            out_of_scope: program
                .out_of_scope
                .iter()
                .map(|target| target.target.clone())
                .collect(),
            compiled: OnceLock::new(),
        }
    }
}

impl ScopeConfig {
    /// Load a scope file from TOML.
    ///
    /// # Errors
    /// Returns an error when the file cannot be read or parsed.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, BugscopeError> {
        let path = path.as_ref();
        let contents =
            std::fs::read_to_string(path).map_err(|error| BugscopeError::io(path.into(), error))?;
        toml::from_str(&contents).map_err(|error| BugscopeError::parse(path.into(), error))
    }

    /// Check whether a URL is in scope.
    ///
    /// # Errors
    /// Returns an error when the URL or a configured scope pattern is invalid.
    pub fn is_in_scope(&self, url: &str) -> Result<bool, BugscopeError> {
        let parsed = Url::parse(url).map_err(|error| BugscopeError::url(url, error))?;
        self.is_url_in_scope(&parsed)
    }

    /// Check whether a parsed URL is in scope.
    ///
    /// # Errors
    /// Returns an error when a configured scope pattern is invalid.
    pub fn is_url_in_scope(&self, url: &Url) -> Result<bool, BugscopeError> {
        let Some(host) = url.host_str() else {
            return Ok(false);
        };

        let compiled = self.compiled_patterns()?;
        if compiled
            .out_of_scope
            .iter()
            .any(|pattern| pattern.matches(host))
        {
            return Ok(false);
        }

        Ok(compiled
            .in_scope
            .iter()
            .any(|pattern| pattern.matches(host)))
    }

    /// Return an error if a URL is out of scope.
    ///
    /// # Errors
    /// Returns an error when the URL is out of scope or the configuration is invalid.
    pub fn ensure_in_scope(&self, url: &Url) -> Result<(), BugscopeError> {
        if self.is_url_in_scope(url)? {
            Ok(())
        } else {
            Err(BugscopeError::OutOfScope {
                url: url.as_str().to_string(),
            })
        }
    }

    fn compiled_patterns(&self) -> Result<&CompiledScopeConfig, BugscopeError> {
        let compiled = self.compiled.get_or_init(|| compile_scope_patterns(self));
        compiled
            .as_ref()
            .map_err(|pattern| BugscopeError::InvalidScopePattern {
                pattern: pattern.clone(),
            })
    }
}

#[derive(Debug)]
struct CompiledScopeConfig {
    in_scope: Vec<ScopePattern>,
    out_of_scope: Vec<ScopePattern>,
}

fn compile_scope_patterns(config: &ScopeConfig) -> Result<CompiledScopeConfig, String> {
    let in_scope = config
        .in_scope
        .iter()
        .map(|pattern| ScopePattern::parse(pattern).map_err(|_| pattern.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let out_of_scope = config
        .out_of_scope
        .iter()
        .map(|pattern| ScopePattern::parse(pattern).map_err(|_| pattern.clone()))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CompiledScopeConfig {
        in_scope,
        out_of_scope,
    })
}

/// Parse a scope file from disk.
///
/// Supports JSON, TOML, and plain text or HTML inputs.
///
/// # Errors
/// Returns an error when the file cannot be read or parsed.
pub fn parse_scope_file(path: impl AsRef<Path>) -> Result<BountyProgram, BugscopeError> {
    let path = path.as_ref();
    let content =
        std::fs::read_to_string(path).map_err(|error| BugscopeError::io(path.into(), error))?;
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("json") => parse_scope_json(&content, path),
        Some(ext) if ext.eq_ignore_ascii_case("toml") => parse_scope_toml(&content, path),
        _ => parse_scope_text(
            &content,
            infer_program_name(path),
            infer_platform_from_str(&content),
        ),
    }
}

/// Parse scope content from a string.
///
/// # Errors
/// Returns an error when the source cannot be parsed.
pub fn parse_scope_str(
    content: impl AsRef<str>,
    format_hint: Option<&str>,
    name: impl Into<String>,
    platform_hint: Option<Platform>,
) -> Result<BountyProgram, BugscopeError> {
    let content = content.as_ref();
    match format_hint.map(str::to_ascii_lowercase) {
        Some(value) if value == "json" => parse_scope_json(content, Path::new("<inline.json>")),
        Some(value) if value == "toml" => parse_scope_toml(content, Path::new("<inline.toml>")),
        _ => parse_scope_text(
            content,
            name.into(),
            platform_hint.unwrap_or_else(|| infer_platform_from_str(content)),
        ),
    }
}

/// Parse a TOML scope document.
///
/// # Errors
/// Returns an error when the TOML is invalid.
pub fn parse_scope_toml(
    content: impl AsRef<str>,
    path: impl AsRef<Path>,
) -> Result<BountyProgram, BugscopeError> {
    let path = path.as_ref();
    let file: ScopeFileRecord = toml::from_str(content.as_ref())
        .map_err(|error| BugscopeError::parse(path.into(), error))?;
    Ok(program_from_record(file))
}

/// Fetch and parse a scope definition from a URL.
///
/// # Errors
/// Returns an error when the request fails or the response cannot be parsed.
pub async fn fetch_scope(source: impl AsRef<str>) -> Result<BountyProgram, BugscopeError> {
    let normalized = normalize_source_url(source.as_ref());
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("bugscope/0.1")
        .build()?;
    let response = client.get(&normalized).send().await?.error_for_status()?;
    let body = response.text().await?;
    let platform = infer_platform_from_str(&normalized);
    let name = infer_program_name_from_url(&normalized);

    let normalized_path = Path::new(&normalized);
    if normalized_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        return parse_scope_json(&body, Path::new("<remote.json>"));
    }
    if normalized_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
    {
        return parse_scope_toml(&body, Path::new("<remote.toml>"));
    }

    parse_scope_text(&body, name, platform)
}

/// Expand wildcard targets using the default DNS resolver.
pub async fn expand_wildcards(scope: &[ScopeTarget]) -> Vec<String> {
    expand_wildcards_with_resolver(scope, |host| async move { resolves(&host).await }).await
}

/// Expand wildcard targets using a caller-provided resolver.
pub async fn expand_wildcards_with_resolver<I, S, F, Fut>(scope: I, resolver: F) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: std::borrow::Borrow<ScopeTarget>,
    F: Fn(String) -> Fut,
    Fut: Future<Output = bool>,
{
    let mut expanded = BTreeSet::new();
    for target in scope {
        let target = target.borrow();
        if !matches!(target.target_type, TargetType::Wildcard) {
            continue;
        }

        let base = target.target.trim_start_matches("*.");
        let candidates = wildcard_candidates(base);
        for candidate in &candidates {
            expanded.insert(candidate.clone());
        }

        for candidate in candidates {
            if resolver(candidate.clone()).await {
                expanded.insert(candidate);
            }
        }
    }

    expanded.into_iter().collect()
}

/// Return exact in-scope targets after exclusions.
#[must_use]
pub fn targets_from_scope(program: &BountyProgram) -> Vec<String> {
    let mut targets = BTreeSet::new();
    for target in &program.in_scope {
        if matches!(target.target_type, TargetType::Wildcard) {
            continue;
        }
        if is_target_in_scope(program, &target.target) {
            targets.insert(target.target.clone());
        }
    }
    targets.into_iter().collect()
}

/// Check whether a candidate target is in scope for a program.
#[must_use]
pub fn is_target_in_scope(program: &BountyProgram, candidate: impl AsRef<str>) -> bool {
    let normalized = normalize_target(candidate.as_ref());
    let included = program
        .in_scope
        .iter()
        .any(|scope| matches_scope_target(scope, &normalized));
    let excluded = program
        .out_of_scope
        .iter()
        .any(|scope| matches_scope_target(scope, &normalized));

    included && !excluded
}

/// Check whether a wildcard pattern matches a candidate host.
#[must_use]
pub fn wildcard_matches(pattern: impl AsRef<str>, candidate: impl AsRef<str>) -> bool {
    let pattern = pattern.as_ref();
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };

    let candidate = normalize_target(candidate.as_ref());
    candidate != suffix && candidate.ends_with(&format!(".{suffix}"))
}

fn parse_scope_json(content: &str, path: &Path) -> Result<BountyProgram, BugscopeError> {
    let file: ScopeFileRecord =
        serde_json::from_str(content).map_err(|error| BugscopeError::json(path.into(), error))?;
    Ok(program_from_record(file))
}

fn program_from_record(file: ScopeFileRecord) -> BountyProgram {
    BountyProgram {
        platform: parse_platform(&file.platform),
        name: file.program,
        in_scope: file
            .in_scope
            .into_iter()
            .map(|target| ScopeTarget {
                target: normalize_target(&target.target),
                target_type: parse_target_type(&target.target_type),
                eligible_for_bounty: target.eligible_for_bounty.unwrap_or(true),
                max_severity: target.max_severity,
            })
            .collect(),
        out_of_scope: file
            .out_of_scope
            .into_iter()
            .map(|target| ScopeTarget {
                target: normalize_target(&target.target),
                target_type: parse_target_type(&target.target_type),
                eligible_for_bounty: target.eligible_for_bounty.unwrap_or(false),
                max_severity: target.max_severity,
            })
            .collect(),
    }
}

fn parse_scope_text(
    content: &str,
    name: String,
    platform: Platform,
) -> Result<BountyProgram, BugscopeError> {
    let clean = strip_html(content)?;
    static SEVERITY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)\b(critical|high|medium|low|info)\b").unwrap_or_else(|_| unreachable!())
    });
    let mut in_scope = Vec::new();
    let mut out_of_scope = Vec::new();
    let mut seen_in = HashSet::new();
    let mut seen_out = HashSet::new();
    let mut current_scope = ScopeSection::InScope;

    for line in clean.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let lower = line.to_ascii_lowercase();
        if is_out_scope_heading(&lower) {
            current_scope = ScopeSection::OutOfScope;
            continue;
        }
        if is_in_scope_heading(&lower) {
            current_scope = ScopeSection::InScope;
            continue;
        }

        let max_severity = SEVERITY_RE
            .captures(line)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_ascii_lowercase());

        for extracted in extract_targets_from_line(line)? {
            let normalized = normalize_target(&extracted.target);
            let entry = ScopeTarget {
                target: normalized.clone(),
                target_type: infer_target_type(&normalized, Some(&lower)),
                eligible_for_bounty: matches!(current_scope, ScopeSection::InScope),
                max_severity: max_severity.clone(),
            };

            match current_scope {
                ScopeSection::InScope => {
                    if seen_in.insert(normalized) {
                        in_scope.push(entry);
                    }
                }
                ScopeSection::OutOfScope => {
                    if seen_out.insert(normalized) {
                        out_of_scope.push(entry);
                    }
                }
            }
        }
    }

    Ok(BountyProgram {
        platform,
        name,
        in_scope,
        out_of_scope,
    })
}

fn strip_html(content: &str) -> Result<String, BugscopeError> {
    static SCRIPT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?is)<script.*?</script>").unwrap_or_else(|_| unreachable!())
    });
    static STYLE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?is)<style.*?</style>").unwrap_or_else(|_| unreachable!())
    });
    static TAG_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?is)<[^>]+>").unwrap_or_else(|_| unreachable!()));

    let without_scripts = SCRIPT_RE.replace_all(content, "\n");
    let without_styles = STYLE_RE.replace_all(&without_scripts, "\n");
    let without_tags = TAG_RE.replace_all(&without_styles, "\n");
    Ok(without_tags.replace("&amp;", "&").replace("&nbsp;", " "))
}

fn extract_targets_from_line(line: &str) -> Result<Vec<ScopeTarget>, BugscopeError> {
    static URL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
            .unwrap_or_else(|_| unreachable!())
    });
    static CIDR_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b").unwrap_or_else(|_| unreachable!())
    });
    static WILDCARD_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"\*\.[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap_or_else(|_| unreachable!())
    });
    static DOMAIN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"\b[a-z0-9][a-z0-9.-]+\.[a-z]{2,}\b").unwrap_or_else(|_| unreachable!())
    });
    static MOBILE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)\b(?:com|net|io)\.[a-z0-9_.-]+\b").unwrap_or_else(|_| unreachable!())
    });

    let mut targets = Vec::new();
    let mut seen = HashSet::new();

    for matched in URL_RE
        .find_iter(line)
        .map(|m| m.as_str().trim_end_matches('.'))
    {
        let normalized = normalize_target(matched);
        if seen.insert(normalized.clone()) {
            targets.push(ScopeTarget {
                target: normalized,
                target_type: infer_target_type(matched, Some(line)),
                eligible_for_bounty: true,
                max_severity: None,
            });
        }
    }

    for matched in CIDR_RE.find_iter(line).map(|m| m.as_str()) {
        let normalized = normalize_target(matched);
        if seen.insert(normalized.clone()) {
            targets.push(ScopeTarget {
                target: normalized,
                target_type: TargetType::IpRange,
                eligible_for_bounty: true,
                max_severity: None,
            });
        }
    }

    for matched in WILDCARD_RE.find_iter(line).map(|m| m.as_str()) {
        let normalized = normalize_target(matched);
        if seen.insert(normalized.clone()) {
            targets.push(ScopeTarget {
                target: normalized,
                target_type: TargetType::Wildcard,
                eligible_for_bounty: true,
                max_severity: None,
            });
        }
    }

    for matched in DOMAIN_RE.find_iter(line).map(|m| m.as_str()) {
        let normalized = normalize_target(matched);
        if seen.insert(normalized.clone()) {
            targets.push(ScopeTarget {
                target: normalized,
                target_type: infer_target_type(matched, Some(line)),
                eligible_for_bounty: true,
                max_severity: None,
            });
        }
    }

    for matched in MOBILE_RE.find_iter(line).map(|m| m.as_str()) {
        let normalized = normalize_target(matched);
        if seen.insert(normalized.clone()) {
            targets.push(ScopeTarget {
                target: normalized,
                target_type: TargetType::Mobile,
                eligible_for_bounty: true,
                max_severity: None,
            });
        }
    }

    Ok(targets)
}

fn parse_platform(value: &str) -> Platform {
    infer_platform_from_str(value)
}

fn parse_target_type(value: &str) -> TargetType {
    match value.trim().to_ascii_lowercase().as_str() {
        "domain" => TargetType::Domain,
        "wildcard" => TargetType::Wildcard,
        "ip_range" | "iprange" | "cidr" => TargetType::IpRange,
        "url" => TargetType::Url,
        "mobile" => TargetType::Mobile,
        "api" => TargetType::Api,
        other => TargetType::Other(other.to_string()),
    }
}

fn infer_target_type(target: &str, context: Option<&str>) -> TargetType {
    let lower_target = target.to_ascii_lowercase();
    let lower_context = context.unwrap_or_default().to_ascii_lowercase();

    if lower_target.starts_with("*.") {
        TargetType::Wildcard
    } else if lower_target.starts_with("http://") || lower_target.starts_with("https://") {
        if lower_target.contains("/api") || lower_context.contains(" api ") {
            TargetType::Api
        } else {
            TargetType::Url
        }
    } else if lower_target.contains('/') {
        TargetType::Url
    } else if (lower_target.contains(':') && !lower_target.contains('.'))
        || lower_context.contains("android")
        || lower_context.contains("ios")
        || lower_context.contains("mobile")
    {
        TargetType::Mobile
    } else if lower_target.contains('/') && lower_target.chars().any(|ch| ch.is_ascii_digit()) {
        TargetType::IpRange
    } else {
        TargetType::Domain
    }
}

fn infer_platform_from_str(value: &str) -> Platform {
    let lower = value.to_ascii_lowercase();
    if lower.contains("hackerone") {
        Platform::HackerOne
    } else if lower.contains("bugcrowd") {
        Platform::Bugcrowd
    } else if lower.contains("intigriti") {
        Platform::Intigriti
    } else if lower.contains("yeswehack") {
        Platform::YesWeHack
    } else {
        Platform::Other("custom".to_string())
    }
}

fn infer_program_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("scope")
        .to_string()
}

fn infer_program_name_from_url(url: &str) -> String {
    url.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .unwrap_or("program")
        .to_string()
}

fn normalize_source_url(source: &str) -> String {
    if source.starts_with("http://") || source.starts_with("https://") {
        source.to_string()
    } else {
        format!("https://{source}")
    }
}

pub(crate) fn normalize_target(target: &str) -> String {
    target
        .trim()
        .trim_matches('`')
        .trim_end_matches('/')
        .trim_end_matches(',')
        .trim_end_matches(';')
        .to_ascii_lowercase()
}

fn wildcard_candidates(base: &str) -> Vec<String> {
    const COMMON: &[&str] = &[
        "www", "api", "app", "dev", "staging", "test", "admin", "portal", "cdn", "static",
    ];

    COMMON
        .iter()
        .map(|prefix| format!("{prefix}.{base}"))
        .collect()
}

async fn resolves(host: &str) -> bool {
    tokio::net::lookup_host((host, 443))
        .await
        .map(|mut addrs| addrs.any(|addr: SocketAddr| addr.ip().is_ipv4() || addr.ip().is_ipv6()))
        .unwrap_or(false)
}

pub(crate) fn matches_scope_target(scope: &ScopeTarget, candidate: &str) -> bool {
    match scope.target_type {
        TargetType::Wildcard => wildcard_matches(&scope.target, candidate),
        TargetType::IpRange => match ScopePattern::parse(&scope.target) {
            Ok(pattern) => pattern.matches(candidate),
            Err(_) => false,
        },
        TargetType::Url => normalize_target(&scope.target) == normalize_target(candidate),
        _ => normalize_host_like(&scope.target) == normalize_host_like(candidate),
    }
}

pub(crate) fn normalize_host_like(candidate: &str) -> String {
    let without_scheme = candidate
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host = host.split(':').next().unwrap_or(host);
    let normalized = normalize_target(host);
    domain_to_ascii(&normalized).unwrap_or(normalized)
}

fn is_in_scope_heading(lower: &str) -> bool {
    (lower.contains("in scope") || lower.contains("eligible target"))
        && !lower.contains("out of scope")
}

fn is_out_scope_heading(lower: &str) -> bool {
    lower.contains("out of scope")
        || lower.contains("out-of-scope")
        || lower.contains("not eligible")
        || lower.contains("excluded target")
}

enum ScopeSection {
    InScope,
    OutOfScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScopePattern {
    Domain(String),
    Wildcard(String),
    Ip(IpAddr),
    Cidr(IpNet),
}

impl ScopePattern {
    pub(crate) fn parse(pattern: &str) -> Result<Self, BugscopeError> {
        // Reject null bytes and other control characters early
        if pattern.contains('\0') {
            return Err(BugscopeError::InvalidScopePattern {
                pattern: pattern.to_string(),
            });
        }

        let normalized = normalize_host_like(pattern);

        if let Ok(ip) = IpAddr::from_str(&normalized) {
            return Ok(Self::Ip(ip));
        }

        if let Ok(cidr) = IpNet::from_str(&normalized) {
            return Ok(Self::Cidr(cidr));
        }

        if let Some(stripped) = normalized.strip_prefix("*.") {
            // Reject wildcard-only patterns like "*" or "*."
            if stripped.is_empty() || stripped.contains('*') {
                return Err(BugscopeError::InvalidScopePattern {
                    pattern: pattern.to_string(),
                });
            }
            return Ok(Self::Wildcard(validate_idn_host(stripped, pattern)?));
        }

        if normalized.is_empty() || normalized.contains('*') || normalized.contains('/') {
            return Err(BugscopeError::InvalidScopePattern {
                pattern: pattern.to_string(),
            });
        }

        Ok(Self::Domain(validate_idn_host(&normalized, pattern)?))
    }

    pub(crate) fn matches(&self, host: &str) -> bool {
        let normalized_host = normalize_host_like(host);

        match self {
            Self::Domain(domain) => normalized_host == *domain,
            Self::Wildcard(domain) => {
                normalized_host.len() > domain.len()
                    && normalized_host.ends_with(domain)
                    && normalized_host
                        .strip_suffix(domain)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
            Self::Ip(ip) => normalized_host
                .parse::<IpAddr>()
                .is_ok_and(|candidate| candidate == *ip),
            Self::Cidr(network) => normalized_host
                .parse::<IpAddr>()
                .is_ok_and(|candidate| network.contains(&candidate)),
        }
    }
}

fn validate_idn_host(host: &str, pattern: &str) -> Result<String, BugscopeError> {
    domain_to_ascii(host).map_err(|_| BugscopeError::InvalidScopePattern {
        pattern: pattern.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::ScopeConfig;
    use url::Url;

    #[test]
    fn caches_compiled_scope_patterns_for_repeated_lookups() {
        let config = ScopeConfig {
            in_scope: vec!["*.example.com".to_string()],
            out_of_scope: vec!["admin.example.com".to_string()],
            ..ScopeConfig::default()
        };
        let allowed = Url::parse("https://api.example.com").expect("allowed url");
        let blocked = Url::parse("https://admin.example.com").expect("blocked url");

        assert!(config.is_url_in_scope(&allowed).expect("allowed"));
        assert!(config.compiled.get().is_some());
        assert!(!config.is_url_in_scope(&blocked).expect("blocked"));
    }

    #[test]
    fn invalid_scope_pattern_is_cached_as_error() {
        let config = ScopeConfig {
            in_scope: vec!["exa*mple.com".to_string()],
            ..ScopeConfig::default()
        };
        let url = Url::parse("https://example.com").expect("url");

        assert!(config.is_url_in_scope(&url).is_err());
        assert!(config.compiled.get().is_some());
        assert!(config.is_url_in_scope(&url).is_err());
    }
}

/// A reqwest wrapper that enforces scope before sending requests.
#[derive(Debug, Clone)]
pub struct ScopeGuard {
    client: Client,
    scope: ScopeConfig,
    headers: Option<HeaderSet>,
    rate_limiter: Option<RateLimiter>,
}

impl ScopeGuard {
    /// Create a new scope guard.
    #[must_use]
    pub fn new(client: Client, scope: ScopeConfig) -> Self {
        Self {
            client,
            scope,
            headers: None,
            rate_limiter: None,
        }
    }

    /// Attach a validated header set to every outgoing request.
    #[must_use]
    pub fn with_headers(mut self, headers: HeaderSet) -> Self {
        self.headers = Some(headers);
        self
    }

    /// Attach a rate limiter to the guard.
    #[must_use]
    pub fn with_rate_limiter(mut self, rate_limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    /// Start a scoped request.
    ///
    /// # Errors
    /// Returns an error when the URL is invalid or out of scope.
    pub fn request(&self, method: Method, url: &str) -> Result<RequestBuilder, BugscopeError> {
        if !self.scope.is_in_scope(url)? {
            return Err(BugscopeError::OutOfScope {
                url: url.to_string(),
            });
        }

        Ok(self.client.request(method, url))
    }

    /// Execute a request after validating scope.
    ///
    /// # Errors
    /// Returns an error when the request is out of scope or the underlying client fails.
    pub async fn execute(&self, mut request: Request) -> Result<Response, BugscopeError> {
        self.scope.ensure_in_scope(request.url())?;

        if let Some(headers) = &self.headers {
            headers.apply(&mut request);
        }

        if let Some(rate_limiter) = &self.rate_limiter {
            return rate_limiter.execute(&self.client, request).await;
        }

        Ok(self.client.execute(request).await?)
    }
}
