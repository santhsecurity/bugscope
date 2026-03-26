//! Header injection helpers for bounty program authorization.

use std::collections::BTreeMap;
use std::path::Path;

use http::header::{HeaderName, HeaderValue, AUTHORIZATION};
use reqwest::Request;
use serde::{Deserialize, Serialize};

use crate::error::BugscopeError;
use crate::scope::Platform;

/// Authentication behavior for a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    /// `Authorization: Bearer <token>`
    #[default]
    Bearer,
    /// `Authorization: Token <token>`
    Token,
    /// `Authorization: <token>`
    Raw,
}

/// Header configuration for a single platform or engagement.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HeaderProfile {
    /// Platform name.
    pub platform: Option<Platform>,
    /// Researcher handle or username.
    pub handle: Option<String>,
    /// Program identifier.
    pub program: Option<String>,
    /// API token or access token.
    pub token: Option<String>,
    /// Authorization scheme.
    #[serde(default)]
    pub auth_scheme: AuthScheme,
    /// Additional static headers.
    #[serde(default)]
    pub extra_headers: BTreeMap<String, String>,
}

impl HeaderProfile {
    /// Create a profile with platform-specific auth defaults.
    #[must_use]
    pub fn for_platform(platform: Platform) -> Self {
        let auth_scheme = if platform.key() == "bugcrowd" {
            AuthScheme::Token
        } else {
            AuthScheme::Bearer
        };

        Self {
            platform: Some(platform),
            auth_scheme,
            ..Self::default()
        }
    }
}

/// A set of validated headers ready to apply to a request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderSet {
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl HeaderSet {
    /// Iterate over the validated headers.
    pub fn iter(&self) -> impl Iterator<Item = &(HeaderName, HeaderValue)> {
        self.headers.iter()
    }

    /// Apply the header set to a request.
    pub fn apply(&self, request: &mut Request) {
        request.headers_mut().extend(self.headers.iter().cloned());
    }
}

/// Injects bug bounty headers into requests.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HeaderInjector {
    /// Named platform profiles.
    #[serde(default)]
    pub platforms: BTreeMap<String, HeaderProfile>,
}

impl HeaderInjector {
    /// Load profiles from a TOML file.
    ///
    /// # Errors
    /// Returns an error when the file cannot be read or parsed.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, BugscopeError> {
        let path = path.as_ref();
        let contents =
            std::fs::read_to_string(path).map_err(|error| BugscopeError::io(path.into(), error))?;
        toml::from_str(&contents).map_err(|error| BugscopeError::parse(path.into(), error))
    }

    /// Resolve a profile for a platform key.
    ///
    /// # Errors
    /// Returns an error when the platform is not configured.
    pub fn profile(&self, platform: &str) -> Result<&HeaderProfile, BugscopeError> {
        self.platforms
            .get(platform)
            .ok_or_else(|| BugscopeError::UnknownPlatform {
                platform: platform.to_string(),
            })
    }

    /// Build a validated header set from a profile.
    ///
    /// # Errors
    /// Returns an error when a header name or value is invalid.
    pub fn build_headers(profile: &HeaderProfile) -> Result<HeaderSet, BugscopeError> {
        let mut headers = Vec::new();
        let platform = profile
            .platform
            .clone()
            .unwrap_or_else(|| Platform::custom("Custom"));
        let platform_header = format!("X-Bug-Bounty-{}", platform.header_suffix());

        if let Some(handle) = &profile.handle {
            headers.push((
                parse_header_name(&platform_header)?,
                parse_header_value(handle, &platform_header)?,
            ));
        }

        if let Some(token) = &profile.token {
            let value = match profile.auth_scheme {
                AuthScheme::Bearer => format!("Bearer {token}"),
                AuthScheme::Token => format!("Token {token}"),
                AuthScheme::Raw => token.clone(),
            };
            headers.push((AUTHORIZATION, parse_header_value(&value, "Authorization")?));
        }

        if let Some(program) = &profile.program {
            headers.push((
                parse_header_name("X-Bug-Bounty-Program")?,
                parse_header_value(program, "X-Bug-Bounty-Program")?,
            ));
        }

        for (name, value) in &profile.extra_headers {
            headers.push((parse_header_name(name)?, parse_header_value(value, name)?));
        }

        Ok(HeaderSet { headers })
    }

    /// Inject a profile's headers into a reqwest request.
    ///
    /// # Errors
    /// Returns an error when a header is invalid.
    pub fn inject_headers(
        &self,
        mut request: Request,
        profile: &HeaderProfile,
    ) -> Result<Request, BugscopeError> {
        let headers = Self::build_headers(profile)?;
        headers.apply(&mut request);
        Ok(request)
    }
}

fn parse_header_name(name: &str) -> Result<HeaderName, BugscopeError> {
    HeaderName::try_from(name).map_err(|_| BugscopeError::InvalidHeader {
        name: name.to_string(),
    })
}

fn parse_header_value(value: &str, name: &str) -> Result<HeaderValue, BugscopeError> {
    if value.is_empty()
        || value
            .chars()
            .any(|ch| matches!(ch, '\r' | '\n') || (ch.is_ascii_control() && ch != '\t'))
    {
        return Err(BugscopeError::InvalidHeader {
            name: name.to_string(),
        });
    }

    HeaderValue::from_str(value).map_err(|_| BugscopeError::InvalidHeader {
        name: name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use reqwest::header::AUTHORIZATION;

    use super::{AuthScheme, HeaderInjector, HeaderProfile};
    use crate::scope::Platform;

    #[test]
    fn rejects_header_values_with_crlf() {
        let mut extra_headers = BTreeMap::new();
        extra_headers.insert("X-Test".to_string(), "safe\r\nInjected: nope".to_string());
        let profile = HeaderProfile {
            extra_headers,
            ..HeaderProfile::default()
        };

        assert!(HeaderInjector::build_headers(&profile).is_err());
    }

    #[test]
    fn rejects_empty_authorization_value() {
        let profile = HeaderProfile {
            platform: Some(Platform::bugcrowd()),
            token: Some(String::new()),
            auth_scheme: AuthScheme::Raw,
            ..HeaderProfile::default()
        };

        assert!(HeaderInjector::build_headers(&profile).is_err());
    }

    #[test]
    fn builds_expected_authorization_header() {
        let profile = HeaderProfile {
            token: Some("abc123".to_string()),
            auth_scheme: AuthScheme::Bearer,
            ..HeaderProfile::default()
        };

        let header_set = HeaderInjector::build_headers(&profile).expect("valid headers");
        let authorization = header_set
            .iter()
            .find(|(name, _)| name == AUTHORIZATION)
            .expect("authorization header");

        assert_eq!(authorization.1.to_str().expect("ascii"), "Bearer abc123");
    }
}
