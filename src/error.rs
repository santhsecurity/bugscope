//! Error types for the bugscope crate.

use std::path::PathBuf;

/// Standardized library error for scope parsing, configuration, and runtime handling.
#[derive(Debug, thiserror::Error)]
pub enum BugscopeError {
    /// Failed to determine the user's home directory.
    #[error("failed to determine the home directory for bugscope state. Fix: set `HOME` or construct `BugscopePaths` with an explicit root directory.")]
    NoHomeDirectory,

    /// Failed to read a file on disk.
    #[error("failed to read configuration file at {path}: {source}. Fix: verify the file exists, is readable, and uses the expected TOML, JSON, or YAML format for that loader.")]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse a TOML document.
    #[error("failed to parse TOML configuration from {path}: {source}. Fix: keep expected sections such as `[scope]`, `[credentials]`, and `[rate_limits]` well-formed.")]
    Parse {
        /// The path of the malformed file.
        path: PathBuf,
        /// The underlying TOML deserialization error.
        #[source]
        source: toml::de::Error,
    },

    /// Failed to parse a JSON document.
    #[error("failed to parse JSON configuration from {path}: {source}. Fix: verify the file is valid JSON and matches the expected bugscope schema.")]
    Json {
        /// The path of the malformed file.
        path: PathBuf,
        /// The underlying JSON deserialization error.
        #[source]
        source: serde_json::Error,
    },

    /// Failed to parse a YAML document.
    #[error("failed to parse YAML configuration from {path}: {source}. Fix: verify the file is valid YAML and matches the expected bugscope schema.")]
    Yaml {
        /// The path of the malformed file.
        path: PathBuf,
        /// The underlying YAML deserialization error.
        #[source]
        source: serde_yaml::Error,
    },

    /// A URL could not be parsed.
    #[error("failed to parse URL `{url}`: {source}. Fix: pass an absolute URL such as `https://app.example.com/path`.")]
    Url {
        /// The input URL string.
        url: String,
        /// The underlying URL parser error.
        #[source]
        source: url::ParseError,
    },

    /// A scope matcher was malformed.
    #[error("invalid scope pattern `{pattern}`. Fix: use exact hosts, wildcard hosts like `*.example.com`, CIDRs like `203.0.113.0/24`, or full URLs.")]
    InvalidScopePattern {
        /// The invalid pattern string.
        pattern: String,
    },

    /// A scope definition could not be parsed.
    #[error("failed to parse scope configuration from `{path}`: {details}. Fix: provide `program`, `platform`, and well-typed in-scope/out-of-scope target entries.")]
    ScopeParse {
        /// The file path that was being parsed.
        path: PathBuf,
        /// The parse error.
        details: String,
    },

    /// A bounty profile could not be parsed.
    #[error("failed to parse bounty profile from `{path}`: {details}. Fix: verify the profile contains required fields like `name`, `platform`, `handle`, and valid scope targets.")]
    ProfileParse {
        /// The file path that was being parsed.
        path: PathBuf,
        /// The parse error.
        details: String,
    },

    /// A bounty profile name is invalid.
    #[error("invalid profile name `{name}`. Fix: use a filesystem-safe slug such as `acme-prod` or `hackerone-acme`.")]
    InvalidProfileName {
        /// The invalid profile name.
        name: String,
    },

    /// A request was blocked because it was outside of scope.
    #[error("blocked out-of-scope request to {url}. Fix: update `ScopeConfig`, choose an in-scope target, or explicitly add the target to your engagement scope before sending requests.")]
    OutOfScope {
        /// The blocked URL.
        url: String,
    },

    /// A header name or value was invalid.
    #[error("invalid HTTP header `{name}`. Fix: use an ASCII header name and a value without newlines or control characters.")]
    InvalidHeader {
        /// The header name that failed validation.
        name: String,
    },

    /// A rate-limit configuration value was invalid.
    #[error("invalid rate limit for `{field}`: {value}. Fix: use a positive numeric value such as `1.5` requests per second or a valid duration cap.")]
    InvalidRateLimit {
        /// The field that failed validation.
        field: String,
        /// The invalid value.
        value: String,
    },

    /// A named platform profile was not found.
    #[error("no header profile configured for platform `{platform}`. Fix: use a supported platform key or add a custom header profile for that platform.")]
    UnknownPlatform {
        /// The platform name.
        platform: String,
    },

    /// An engagement file was not found.
    #[error("engagement `{name}` was not found. Fix: create `{name}.toml` under the engagements directory or switch to an existing engagement name.")]
    MissingEngagement {
        /// The requested engagement name.
        name: String,
    },

    /// A regex used for scope parsing could not be compiled.
    #[error("failed to compile an internal parser regex: {0}. Fix: report this crate bug if it happens in released code, because user input should not trigger it.")]
    Regex(#[from] regex::Error),

    /// A reqwest operation failed.
    #[error("HTTP client error: {0}. Fix: verify DNS, TLS, proxy, and network connectivity for the target URL.")]
    Http(#[from] reqwest::Error),
}

impl BugscopeError {
    /// Create an `Io` error bound to a path.
    #[must_use]
    pub fn io(path: PathBuf, source: std::io::Error) -> Self {
        Self::Io { path, source }
    }

    /// Create a TOML `Parse` error bound to a path.
    #[must_use]
    pub fn parse(path: PathBuf, source: toml::de::Error) -> Self {
        Self::Parse { path, source }
    }

    /// Create a JSON parse error bound to a path.
    #[must_use]
    pub fn json(path: PathBuf, source: serde_json::Error) -> Self {
        Self::Json { path, source }
    }

    /// Create a YAML parse error bound to a path.
    #[must_use]
    pub fn yaml(path: PathBuf, source: serde_yaml::Error) -> Self {
        Self::Yaml { path, source }
    }

    /// Create a `ScopeParse` error builder.
    #[must_use]
    pub fn scope_parse(path: PathBuf, source: impl Into<String>) -> Self {
        Self::ScopeParse {
            path,
            details: source.into(),
        }
    }

    /// Create a `ProfileParse` error builder.
    #[must_use]
    pub fn profile_parse(path: PathBuf, source: impl Into<String>) -> Self {
        Self::ProfileParse {
            path,
            details: source.into(),
        }
    }

    /// Create a URL parsing error.
    #[must_use]
    pub fn url(url: impl Into<String>, source: url::ParseError) -> Self {
        Self::Url {
            url: url.into(),
            source,
        }
    }
}
