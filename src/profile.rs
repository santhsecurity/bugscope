//! Persistent program profiles and finding classification.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::scope::{matches_scope_target, BountyProgram, Platform, ScopeTarget};

/// A saved bounty or scoped security profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BountyProfile {
    /// Human-readable name.
    pub name: String,
    /// Platform this program is on.
    pub platform: Platform,
    /// Platform handle or program slug.
    pub handle: String,
    /// Your username on this platform.
    pub username: Option<String>,
    /// In-scope targets.
    pub in_scope: Vec<ScopeTarget>,
    /// Out-of-scope targets.
    pub out_of_scope: Vec<ScopeTarget>,
    /// Exclusion rules for findings.
    pub exclusions: Vec<ExclusionRule>,
    /// Custom headers injected on every request.
    pub headers: HashMap<String, String>,
    /// Maximum requests per second.
    pub rate_limit: u32,
    /// Minimum severity to consider reportable.
    pub min_severity: String,
    /// Optional notes.
    pub notes: Option<String>,
}

impl Default for BountyProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            platform: Platform::default(),
            handle: String::new(),
            username: None,
            in_scope: Vec::new(),
            out_of_scope: Vec::new(),
            exclusions: Vec::new(),
            headers: HashMap::new(),
            rate_limit: 1,
            min_severity: "low".to_string(),
            notes: None,
        }
    }
}

/// A rule that marks certain findings as excluded by the program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionRule {
    /// Rule name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Template IDs that match this exclusion.
    pub template_ids: Vec<String>,
    /// Template tags that match this exclusion.
    pub tags: Vec<String>,
}

/// Classification applied to a finding after profile filtering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingTag {
    /// This finding is reportable to the program.
    Reportable,
    /// This finding matches a program exclusion.
    Excluded(String),
    /// This finding's target is out of program scope.
    OutOfScope,
    /// This finding is below the program's minimum severity.
    BelowMinSeverity,
}

/// Common bug bounty exclusions shared by many programs.
#[must_use]
pub fn common_exclusions() -> Vec<ExclusionRule> {
    vec![
        ExclusionRule {
            name: "missing-headers".to_string(),
            description: "Missing HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)"
                .to_string(),
            template_ids: vec![
                "http-missing-security-headers".to_string(),
                "missing-x-frame-options".to_string(),
                "missing-content-type-header".to_string(),
                "missing-csp-header".to_string(),
                "missing-hsts-header".to_string(),
                "missing-referrer-policy".to_string(),
                "missing-permissions-policy".to_string(),
            ],
            tags: vec!["headers".to_string(), "generic".to_string()],
        },
        ExclusionRule {
            name: "ssl-configuration".to_string(),
            description: "SSL/TLS configuration issues (weak ciphers, protocol versions)"
                .to_string(),
            template_ids: vec![
                "ssl-weak-cipher".to_string(),
                "tls-version-check".to_string(),
                "ssl-certificate-expired".to_string(),
            ],
            tags: vec!["ssl".to_string(), "tls".to_string()],
        },
        ExclusionRule {
            name: "missing-cookie-flags".to_string(),
            description: "Missing Secure/HttpOnly/SameSite flags on cookies".to_string(),
            template_ids: vec![
                "missing-cookie-samesite-strict".to_string(),
                "missing-cookie-httponly".to_string(),
                "missing-cookie-secure".to_string(),
            ],
            tags: vec!["cookie".to_string(), "samesite".to_string()],
        },
        ExclusionRule {
            name: "rate-limiting".to_string(),
            description: "Missing rate limiting on endpoints".to_string(),
            template_ids: vec!["rate-limit-check".to_string()],
            tags: vec!["rate-limit".to_string()],
        },
        ExclusionRule {
            name: "clickjacking".to_string(),
            description: "Clickjacking on non-state-changing pages".to_string(),
            template_ids: vec!["clickjacking-check".to_string()],
            tags: vec!["clickjacking".to_string()],
        },
    ]
}

/// Classify a finding against a saved profile.
#[must_use]
pub fn classify_finding(
    template_id: impl AsRef<str>,
    template_tags: &[String],
    target: impl AsRef<str>,
    severity: impl AsRef<str>,
    profile: &BountyProfile,
) -> FindingTag {
    if !is_in_scope(target.as_ref(), &profile.in_scope, &profile.out_of_scope) {
        return FindingTag::OutOfScope;
    }

    if is_below_min_severity(severity.as_ref(), &profile.min_severity) {
        return FindingTag::BelowMinSeverity;
    }

    for rule in &profile.exclusions {
        if rule
            .template_ids
            .iter()
            .any(|id| id == template_id.as_ref())
        {
            return FindingTag::Excluded(rule.name.clone());
        }

        if !rule.tags.is_empty()
            && template_tags
                .iter()
                .any(|tag| rule.tags.iter().any(|rule_tag| rule_tag == tag))
        {
            return FindingTag::Excluded(rule.name.clone());
        }
    }

    FindingTag::Reportable
}

/// Generate platform-specific headers for a profile.
#[must_use]
pub fn platform_headers(profile: &BountyProfile) -> HashMap<String, String> {
    let mut headers = profile.headers.clone();

    if let Some(username) = &profile.username {
        match profile.platform {
            Platform::HackerOne => {
                headers
                    .entry("X-HackerOne-Research".to_string())
                    .or_insert_with(|| username.clone());
                headers
                    .entry("X-Bug-Bounty".to_string())
                    .or_insert_with(|| format!("HackerOne/{username}"));
            }
            Platform::Bugcrowd => {
                headers
                    .entry("X-Bugcrowd-Ninja".to_string())
                    .or_insert_with(|| username.clone());
                headers
                    .entry("X-Request-Purpose".to_string())
                    .or_insert_with(|| "Research".to_string());
                headers
                    .entry("X-Bug-Bounty".to_string())
                    .or_insert_with(|| format!("Bugcrowd/{username}"));
            }
            Platform::Intigriti => {
                headers
                    .entry("X-Intigriti-Research".to_string())
                    .or_insert_with(|| username.clone());
                headers
                    .entry("X-Bug-Bounty".to_string())
                    .or_insert_with(|| format!("Intigriti/{username}"));
            }
            Platform::YesWeHack => {
                headers
                    .entry("X-YesWeHack-Research".to_string())
                    .or_insert_with(|| username.clone());
                headers
                    .entry("X-Bug-Bounty".to_string())
                    .or_insert_with(|| format!("YesWeHack/{username}"));
            }
            Platform::Other(_) => {
                headers
                    .entry("X-Bug-Bounty".to_string())
                    .or_insert_with(|| username.clone());
            }
        }
    }

    headers
}

/// Default profile directory.
#[must_use]
pub fn profiles_dir() -> PathBuf {
    std::env::var("HOME")
        .map_or_else(|_| PathBuf::from("."), PathBuf::from)
        .join(".bugscope")
        .join("profiles")
}

/// Save a profile to disk as YAML.
///
/// # Errors
/// Returns an error when the profile cannot be serialized or written.
pub fn save_profile(profile: &BountyProfile) -> std::io::Result<PathBuf> {
    let dir = profiles_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.yaml", profile.name));
    let yaml = serde_yaml::to_string(profile)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    std::fs::write(&path, yaml)?;
    Ok(path)
}

/// Load a profile by name.
///
/// # Errors
/// Returns an error when the file cannot be read or parsed.
pub fn load_profile(name: &str) -> std::io::Result<BountyProfile> {
    let path = profiles_dir().join(format!("{name}.yaml"));
    let content = std::fs::read_to_string(&path)?;
    serde_yaml::from_str(&content)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))
}

/// List all saved profile names.
///
/// # Errors
/// Returns an error when the profile directory cannot be read.
pub fn list_profiles() -> std::io::Result<Vec<String>> {
    let dir = profiles_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        if let Some(name) = entry
            .path()
            .file_stem()
            .and_then(|value| value.to_str())
            .map(String::from)
        {
            if entry.path().extension().is_some_and(|ext| ext == "yaml") {
                names.push(name);
            }
        }
    }
    names.sort();
    Ok(names)
}

/// Create a profile from a parsed program.
#[must_use]
pub fn profile_from_program(
    program: &BountyProgram,
    handle: impl Into<String>,
    username: Option<String>,
) -> BountyProfile {
    let handle = handle.into();
    BountyProfile {
        name: handle.clone(),
        platform: program.platform.clone(),
        handle,
        username,
        in_scope: program.in_scope.clone(),
        out_of_scope: program.out_of_scope.clone(),
        exclusions: common_exclusions(),
        headers: HashMap::new(),
        rate_limit: default_rate_limit(&program.platform),
        min_severity: "low".to_string(),
        notes: None,
    }
}

fn is_in_scope(target: &str, in_scope: &[ScopeTarget], out_of_scope: &[ScopeTarget]) -> bool {
    for entry in out_of_scope {
        if matches_scope_target(entry, target) {
            return false;
        }
    }

    if in_scope.is_empty() {
        return true;
    }

    in_scope
        .iter()
        .any(|entry| matches_scope_target(entry, target))
}

fn is_below_min_severity(severity: &str, min: &str) -> bool {
    let rank = |value: &str| match value.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };
    rank(severity) < rank(min)
}

fn default_rate_limit(platform: &Platform) -> u32 {
    match platform {
        Platform::HackerOne | Platform::Bugcrowd | Platform::Intigriti => 2,
        Platform::YesWeHack => 5,
        Platform::Other(_) => 1,
    }
}
