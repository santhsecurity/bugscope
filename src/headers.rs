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
    /// Creates a header profile preloaded with the default auth scheme for a platform.
    ///
    /// `Bugcrowd` uses `Token` auth by default while the other built-in platforms use
    /// `Bearer`.
    ///
    /// # Parameters
    ///
    /// - `platform`: Platform whose default header behavior should be used.
    ///
    /// # Returns
    ///
    /// Returns a [`HeaderProfile`] with `platform` set and `auth_scheme`
    /// initialized.
    ///
    /// # Panics
    ///
    /// This function does not panic.
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
    /// Iterates over the validated header pairs stored in this set.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns an iterator over `(HeaderName, HeaderValue)` tuples in insertion order.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn iter(&self) -> impl Iterator<Item = &(HeaderName, HeaderValue)> {
        self.headers.iter()
    }

    /// Appends every validated header in this set to a reqwest request.
    ///
    /// # Parameters
    ///
    /// - `request`: Request to mutate in place.
    ///
    /// # Returns
    ///
    /// This function returns no value.
    ///
    /// # Panics
    ///
    /// This function does not panic.
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

    /// Resolves a named platform profile from the loaded platform map.
    ///
    /// # Parameters
    ///
    /// - `platform`: Platform key such as `hackerone` or `bugcrowd`.
    ///
    /// # Returns
    ///
    /// Returns a shared reference to the matching [`HeaderProfile`].
    ///
    /// # Errors
    ///
    /// Returns an error when `platform` is not present in `self.platforms`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn profile(&self, platform: &str) -> Result<&HeaderProfile, BugscopeError> {
        self.platforms
            .get(platform)
            .ok_or_else(|| BugscopeError::UnknownPlatform {
                platform: platform.to_string(),
            })
    }

    /// Converts a header profile into a validated request-ready [`HeaderSet`].
    ///
    /// # Parameters
    ///
    /// - `profile`: Profile describing program handle, token, and extra headers.
    ///
    /// # Returns
    ///
    /// Returns a [`HeaderSet`] containing only validated header names and values.
    ///
    /// # Errors
    ///
    /// Returns an error when any header name or value is invalid.
    ///
    /// # Panics
    ///
    /// This function does not panic.
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

    /// Applies a profile's derived headers to a reqwest request.
    ///
    /// # Parameters
    ///
    /// - `request`: Request to enrich with bug bounty headers.
    /// - `profile`: Profile that describes which headers should be added.
    ///
    /// # Returns
    ///
    /// Returns the mutated request with validated headers attached.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile produces an invalid header.
    ///
    /// # Panics
    ///
    /// This function does not panic.
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
