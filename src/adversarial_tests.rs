#[cfg(test)]
mod adversarial_tests {
    use crate::headers::{HeaderInjector, HeaderProfile};
    use crate::ratelimit::{RateLimitConfig, RateLimitRule, RateLimiter};
    use crate::scope::{Platform, ScopeConfig, ScopePattern};
    use std::collections::BTreeMap;
    use url::Url;

    #[test]
    fn test_scope_pattern_wildcard_1() {
        let pattern = ScopePattern::parse("*.example1.com").unwrap();
        assert!(pattern.matches("api.example1.com"));
        assert!(pattern.matches("v1.api.example1.com"));
        assert!(!pattern.matches("example1.com"));
        assert!(!pattern.matches("anotherexample1.com"));
    }

    #[test]
    fn test_scope_pattern_wildcard_2() {
        let pattern = ScopePattern::parse("*.example2.com").unwrap();
        assert!(pattern.matches("api.example2.com"));
        assert!(pattern.matches("v1.api.example2.com"));
        assert!(!pattern.matches("example2.com"));
        assert!(!pattern.matches("anotherexample2.com"));
    }

    #[test]
    fn test_scope_pattern_wildcard_3() {
        let pattern = ScopePattern::parse("*.example3.com").unwrap();
        assert!(pattern.matches("api.example3.com"));
        assert!(pattern.matches("v1.api.example3.com"));
        assert!(!pattern.matches("example3.com"));
        assert!(!pattern.matches("anotherexample3.com"));
    }

    #[test]
    fn test_scope_pattern_wildcard_4() {
        let pattern = ScopePattern::parse("*.example4.com").unwrap();
        assert!(pattern.matches("api.example4.com"));
        assert!(pattern.matches("v1.api.example4.com"));
        assert!(!pattern.matches("example4.com"));
        assert!(!pattern.matches("anotherexample4.com"));
    }

    #[test]
    fn test_scope_pattern_wildcard_5() {
        let pattern = ScopePattern::parse("*.example5.com").unwrap();
        assert!(pattern.matches("api.example5.com"));
        assert!(pattern.matches("v1.api.example5.com"));
        assert!(!pattern.matches("example5.com"));
        assert!(!pattern.matches("anotherexample5.com"));
    }

    #[test]
    fn test_scope_pattern_wildcard_6() {
        let pattern = ScopePattern::parse("*.example6.com").unwrap();
        assert!(pattern.matches("api.example6.com"));
        assert!(pattern.matches("v1.api.example6.com"));
        assert!(!pattern.matches("example6.com"));
        assert!(!pattern.matches("anotherexample6.com"));
    }

    #[test]
    fn test_scope_pattern_wildcard_7() {
        let pattern = ScopePattern::parse("*.example7.com").unwrap();
        assert!(pattern.matches("api.example7.com"));
        assert!(pattern.matches("v1.api.example7.com"));
        assert!(!pattern.matches("example7.com"));
        assert!(!pattern.matches("anotherexample7.com"));
    }

    #[test]
    fn test_scope_pattern_wildcard_8() {
        let pattern = ScopePattern::parse("*.example8.com").unwrap();
        assert!(pattern.matches("api.example8.com"));
        assert!(pattern.matches("v1.api.example8.com"));
        assert!(!pattern.matches("example8.com"));
        assert!(!pattern.matches("anotherexample8.com"));
    }

    #[test]
    fn test_scope_pattern_wildcard_9() {
        let pattern = ScopePattern::parse("*.example9.com").unwrap();
        assert!(pattern.matches("api.example9.com"));
        assert!(pattern.matches("v1.api.example9.com"));
        assert!(!pattern.matches("example9.com"));
        assert!(!pattern.matches("anotherexample9.com"));
    }

    #[test]
    fn test_scope_pattern_wildcard_10() {
        let pattern = ScopePattern::parse("*.example10.com").unwrap();
        assert!(pattern.matches("api.example10.com"));
        assert!(pattern.matches("v1.api.example10.com"));
        assert!(!pattern.matches("example10.com"));
        assert!(!pattern.matches("anotherexample10.com"));
    }

    #[test]
    fn test_scope_pattern_ip_1() {
        let pattern = ScopePattern::parse("192.168.1.1").unwrap();
        assert!(pattern.matches("192.168.1.1"));
        assert!(!pattern.matches("192.168.1.2"));
    }

    #[test]
    fn test_scope_pattern_ip_2() {
        let pattern = ScopePattern::parse("192.168.1.2").unwrap();
        assert!(pattern.matches("192.168.1.2"));
        assert!(!pattern.matches("192.168.1.3"));
    }

    #[test]
    fn test_scope_pattern_ip_3() {
        let pattern = ScopePattern::parse("192.168.1.3").unwrap();
        assert!(pattern.matches("192.168.1.3"));
        assert!(!pattern.matches("192.168.1.4"));
    }

    #[test]
    fn test_scope_pattern_ip_4() {
        let pattern = ScopePattern::parse("192.168.1.4").unwrap();
        assert!(pattern.matches("192.168.1.4"));
        assert!(!pattern.matches("192.168.1.5"));
    }

    #[test]
    fn test_scope_pattern_ip_5() {
        let pattern = ScopePattern::parse("192.168.1.5").unwrap();
        assert!(pattern.matches("192.168.1.5"));
        assert!(!pattern.matches("192.168.1.6"));
    }

    #[test]
    fn test_platform_parsing_1() {
        let p = Platform::custom(format!("Platform{}", 1));
        assert_eq!(p.key(), format!("platform{}", 1));
    }

    #[test]
    fn test_platform_parsing_2() {
        let p = Platform::custom(format!("Platform{}", 2));
        assert_eq!(p.key(), format!("platform{}", 2));
    }

    #[test]
    fn test_platform_parsing_3() {
        let p = Platform::custom(format!("Platform{}", 3));
        assert_eq!(p.key(), format!("platform{}", 3));
    }

    #[test]
    fn test_platform_parsing_4() {
        let p = Platform::custom(format!("Platform{}", 4));
        assert_eq!(p.key(), format!("platform{}", 4));
    }

    #[test]
    fn test_platform_parsing_5() {
        let p = Platform::custom(format!("Platform{}", 5));
        assert_eq!(p.key(), format!("platform{}", 5));
    }

    #[test]
    fn test_scope_exclusion_1() {
        let mut config = ScopeConfig::default();
        config.in_scope = vec!["*.example1.com".to_string()];
        config.out_of_scope = vec!["admin.example1.com".to_string()];

        let url_in = Url::parse("https://api.example1.com").unwrap();
        let url_out = Url::parse("https://admin.example1.com").unwrap();

        assert!(config.is_url_in_scope(&url_in).unwrap());
        assert!(!config.is_url_in_scope(&url_out).unwrap());
    }

    #[test]
    fn test_scope_exclusion_2() {
        let mut config = ScopeConfig::default();
        config.in_scope = vec!["*.example2.com".to_string()];
        config.out_of_scope = vec!["admin.example2.com".to_string()];

        let url_in = Url::parse("https://api.example2.com").unwrap();
        let url_out = Url::parse("https://admin.example2.com").unwrap();

        assert!(config.is_url_in_scope(&url_in).unwrap());
        assert!(!config.is_url_in_scope(&url_out).unwrap());
    }

    #[test]
    fn test_scope_exclusion_3() {
        let mut config = ScopeConfig::default();
        config.in_scope = vec!["*.example3.com".to_string()];
        config.out_of_scope = vec!["admin.example3.com".to_string()];

        let url_in = Url::parse("https://api.example3.com").unwrap();
        let url_out = Url::parse("https://admin.example3.com").unwrap();

        assert!(config.is_url_in_scope(&url_in).unwrap());
        assert!(!config.is_url_in_scope(&url_out).unwrap());
    }

    #[test]
    fn test_scope_exclusion_4() {
        let mut config = ScopeConfig::default();
        config.in_scope = vec!["*.example4.com".to_string()];
        config.out_of_scope = vec!["admin.example4.com".to_string()];

        let url_in = Url::parse("https://api.example4.com").unwrap();
        let url_out = Url::parse("https://admin.example4.com").unwrap();

        assert!(config.is_url_in_scope(&url_in).unwrap());
        assert!(!config.is_url_in_scope(&url_out).unwrap());
    }

    #[test]
    fn test_scope_exclusion_5() {
        let mut config = ScopeConfig::default();
        config.in_scope = vec!["*.example5.com".to_string()];
        config.out_of_scope = vec!["admin.example5.com".to_string()];

        let url_in = Url::parse("https://api.example5.com").unwrap();
        let url_out = Url::parse("https://admin.example5.com").unwrap();

        assert!(config.is_url_in_scope(&url_in).unwrap());
        assert!(!config.is_url_in_scope(&url_out).unwrap());
    }

    #[test]
    fn test_header_injection_0() {
        let mut extra_headers = BTreeMap::new();
        extra_headers.insert("X-Inject".to_string(), format!("val{}ue", "\r"));
        let mut profile = HeaderProfile::default();
        profile.extra_headers = extra_headers;
        assert!(HeaderInjector::build_headers(&profile).is_err());
    }

    #[test]
    fn test_header_injection_1() {
        let mut extra_headers = BTreeMap::new();
        extra_headers.insert("X-Inject".to_string(), format!("val{}ue", "\n"));
        let mut profile = HeaderProfile::default();
        profile.extra_headers = extra_headers;
        assert!(HeaderInjector::build_headers(&profile).is_err());
    }

    #[test]
    fn test_header_injection_2() {
        let mut extra_headers = BTreeMap::new();
        extra_headers.insert("X-Inject".to_string(), format!("val{}ue", "\0"));
        let mut profile = HeaderProfile::default();
        profile.extra_headers = extra_headers;
        assert!(HeaderInjector::build_headers(&profile).is_err());
    }

    #[test]
    fn test_header_injection_3() {
        let mut extra_headers = BTreeMap::new();
        extra_headers.insert("X-Inject".to_string(), format!("val{}ue", "\x07"));
        let mut profile = HeaderProfile::default();
        profile.extra_headers = extra_headers;
        assert!(HeaderInjector::build_headers(&profile).is_err());
    }

    #[test]
    fn test_header_injection_4() {
        let mut extra_headers = BTreeMap::new();
        extra_headers.insert("X-Inject".to_string(), format!("val{}ue", "\x1B"));
        let mut profile = HeaderProfile::default();
        profile.extra_headers = extra_headers;
        assert!(HeaderInjector::build_headers(&profile).is_err());
    }

    #[test]
    fn test_rate_limit_config_1() {
        let config = RateLimitConfig {
            default_requests_per_second: 1.5,
            rules: vec![RateLimitRule {
                pattern: "*.test1.com".to_string(),
                requests_per_second: 1.0,
                ..RateLimitRule::default()
            }],
            ..RateLimitConfig::default()
        };
        let limiter = RateLimiter::new(config);
        assert!(limiter.is_ok());
    }

    #[test]
    fn test_rate_limit_config_2() {
        let config = RateLimitConfig {
            default_requests_per_second: 2.5,
            rules: vec![RateLimitRule {
                pattern: "*.test2.com".to_string(),
                requests_per_second: 2.0,
                ..RateLimitRule::default()
            }],
            ..RateLimitConfig::default()
        };
        let limiter = RateLimiter::new(config);
        assert!(limiter.is_ok());
    }

    #[test]
    fn test_rate_limit_config_3() {
        let config = RateLimitConfig {
            default_requests_per_second: 3.5,
            rules: vec![RateLimitRule {
                pattern: "*.test3.com".to_string(),
                requests_per_second: 3.0,
                ..RateLimitRule::default()
            }],
            ..RateLimitConfig::default()
        };
        let limiter = RateLimiter::new(config);
        assert!(limiter.is_ok());
    }

    #[test]
    fn test_rate_limit_config_4() {
        let config = RateLimitConfig {
            default_requests_per_second: 4.5,
            rules: vec![RateLimitRule {
                pattern: "*.test4.com".to_string(),
                requests_per_second: 4.0,
                ..RateLimitRule::default()
            }],
            ..RateLimitConfig::default()
        };
        let limiter = RateLimiter::new(config);
        assert!(limiter.is_ok());
    }

    #[test]
    fn test_rate_limit_config_5() {
        let config = RateLimitConfig {
            default_requests_per_second: 5.5,
            rules: vec![RateLimitRule {
                pattern: "*.test5.com".to_string(),
                requests_per_second: 5.0,
                ..RateLimitRule::default()
            }],
            ..RateLimitConfig::default()
        };
        let limiter = RateLimiter::new(config);
        assert!(limiter.is_ok());
    }
}
