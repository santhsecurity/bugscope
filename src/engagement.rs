//! Engagement loading helpers.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::BugscopePaths;
use crate::error::BugscopeError;
use crate::headers::HeaderProfile;
use crate::ratelimit::RateLimitConfig;
use crate::scope::{Platform, ScopeConfig};

/// Full engagement configuration for a program.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct EngagementConfig {
    /// Program name used on disk and in logs.
    pub program_name: String,
    /// Platform name.
    pub platform: Platform,
    /// Scope configuration for the program.
    #[serde(default)]
    pub scope: ScopeConfig,
    /// Credentials and headers for the program.
    #[serde(default)]
    pub credentials: HeaderProfile,
    /// Rate limits for the program.
    #[serde(default)]
    pub rate_limits: RateLimitConfig,
    /// Optional analyst notes.
    pub notes: Option<String>,
}

impl EngagementConfig {
    /// Loads a single engagement file from disk and normalizes missing credential metadata.
    ///
    /// # Parameters
    ///
    /// - `path`: Path to the TOML engagement file to load.
    ///
    /// # Returns
    ///
    /// Returns the parsed [`EngagementConfig`]. If the credentials section omits a
    /// platform, this method copies the top-level engagement platform into it.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or when the TOML is invalid.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, BugscopeError> {
        let path = path.as_ref();
        let contents =
            std::fs::read_to_string(path).map_err(|error| BugscopeError::io(path.into(), error))?;
        let mut config: Self =
            toml::from_str(&contents).map_err(|error| BugscopeError::parse(path.into(), error))?;

        if config.credentials.platform.is_none() {
            config.credentials.platform = Some(config.platform.clone());
        }

        Ok(config)
    }
}

/// Loader and selector for engagement files under `~/.bugscope/engagements`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngagementStore {
    paths: BugscopePaths,
}

impl Default for EngagementStore {
    fn default() -> Self {
        Self {
            paths: BugscopePaths::discover().unwrap_or_else(|_| BugscopePaths::new(".bugscope")),
        }
    }
}

impl EngagementStore {
    /// Creates an engagement store rooted at a specific [`BugscopePaths`] layout.
    ///
    /// # Parameters
    ///
    /// - `paths`: Filesystem layout used to resolve engagement files and the active selector.
    ///
    /// # Returns
    ///
    /// Returns a new [`EngagementStore`] backed by `paths`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn new(paths: BugscopePaths) -> Self {
        Self { paths }
    }

    /// Discover the default engagement store.
    ///
    /// # Errors
    /// Returns an error when the bugscope home directory cannot be resolved.
    pub fn discover() -> Result<Self, BugscopeError> {
        Ok(Self::new(BugscopePaths::discover()?))
    }

    /// Returns the TOML path where a named engagement should live.
    ///
    /// # Parameters
    ///
    /// - `name`: Logical engagement name without the `.toml` suffix.
    ///
    /// # Returns
    ///
    /// Returns `<engagements_dir>/<name>.toml`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn engagement_path(&self, name: &str) -> PathBuf {
        self.paths.engagements_dir().join(format!("{name}.toml"))
    }

    /// Loads a named engagement from the configured engagements directory.
    ///
    /// # Parameters
    ///
    /// - `name`: Engagement name without the `.toml` extension.
    ///
    /// # Returns
    ///
    /// Returns the parsed [`EngagementConfig`] for `name`.
    ///
    /// # Errors
    ///
    /// Returns an error when the engagement file is missing, unreadable, or malformed.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn load(&self, name: &str) -> Result<EngagementConfig, BugscopeError> {
        let path = self.engagement_path(name);
        if !path.exists() {
            return Err(BugscopeError::MissingEngagement {
                name: name.to_string(),
            });
        }
        EngagementConfig::load_from_path(path)
    }

    /// Lists all engagement names found in the engagements directory.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns engagement file stems sorted lexicographically. Missing engagement
    /// directories are treated as empty.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory exists but cannot be read.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn list(&self) -> Result<Vec<String>, BugscopeError> {
        let dir = self.paths.engagements_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut names = std::fs::read_dir(&dir)
            .map_err(|error| BugscopeError::io(dir.clone(), error))?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                entry
                    .path()
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .map(ToOwned::to_owned)
            })
            .collect::<Vec<_>>();
        names.sort();
        Ok(names)
    }

    /// Persists the active engagement selector to disk.
    ///
    /// # Parameters
    ///
    /// - `name`: Engagement name that should become active for later lookups.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` after writing the selector file.
    ///
    /// # Errors
    ///
    /// Returns an error when the root directory cannot be created or the selector
    /// file cannot be written.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn switch(&self, name: &str) -> Result<(), BugscopeError> {
        std::fs::create_dir_all(self.paths.root())
            .map_err(|error| BugscopeError::io(self.paths.root().into(), error))?;
        std::fs::write(self.paths.active_engagement_file(), name)
            .map_err(|error| BugscopeError::io(self.paths.active_engagement_file(), error))
    }

    /// Reads the active engagement selector if one has been stored.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns `Some(name)` when the selector file exists and contains a non-empty
    /// engagement name, otherwise returns `None`.
    ///
    /// # Errors
    ///
    /// Returns an error when the selector file exists but cannot be read.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn active_name(&self) -> Result<Option<String>, BugscopeError> {
        let path = self.paths.active_engagement_file();
        if !path.exists() {
            return Ok(None);
        }

        let name =
            std::fs::read_to_string(&path).map_err(|error| BugscopeError::io(path, error))?;
        let trimmed = name.trim();
        if trimmed.is_empty() {
            Ok(None)
        } else {
            Ok(Some(trimmed.to_string()))
        }
    }

    /// Loads the engagement currently selected by [`Self::switch`], if one exists.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(config))` when an active engagement name is present and
    /// resolves successfully, or `Ok(None)` when no selector is set.
    ///
    /// # Errors
    ///
    /// Returns an error when the selector file cannot be read or the selected
    /// engagement cannot be loaded.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn load_active(&self) -> Result<Option<EngagementConfig>, BugscopeError> {
        match self.active_name()? {
            Some(name) => self.load(&name).map(Some),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::config::BugscopePaths;

    use super::{EngagementConfig, EngagementStore};

    fn example_engagement() -> &'static str {
        r#"
            program_name = "acme"
            platform = "hackerone"
            notes = "Coordinate through the program slack."

            [scope]
            in_scope = ["example.com", "*.example.com"]
            out_of_scope = ["admin.example.com"]

            [credentials]
            handle = "alice"
            token = "secret"

            [rate_limits]
            default_requests_per_second = 2.0
        "#
    }

    #[test]
    fn loads_engagement_from_toml() {
        let config: EngagementConfig = toml::from_str(example_engagement()).expect("engagement");
        assert_eq!(config.program_name, "acme");
        assert_eq!(config.credentials.handle.as_deref(), Some("alice"));
    }

    #[test]
    fn fills_credentials_platform_from_engagement_platform() {
        let temp = tempdir().expect("tempdir");
        let file = temp.path().join("acme.toml");
        std::fs::write(&file, example_engagement()).expect("write");

        let config = EngagementConfig::load_from_path(&file).expect("load");
        assert_eq!(
            config.credentials.platform.expect("platform").key(),
            "hackerone"
        );
        assert_eq!(config.credentials.handle.as_deref(), Some("alice"));
        assert_eq!(config.credentials.token.as_deref(), Some("secret"));
        assert_eq!(
            config.notes.as_deref(),
            Some("Coordinate through the program slack.")
        );
        assert_eq!(config.program_name, "acme");
    }

    #[test]
    fn lists_engagements_sorted() {
        let temp = tempdir().expect("tempdir");
        let paths = BugscopePaths::new(temp.path().join(".bugscope"));
        let store = EngagementStore::new(paths.clone());
        std::fs::create_dir_all(paths.engagements_dir()).expect("dir");
        std::fs::write(store.engagement_path("zeta"), example_engagement()).expect("write");
        std::fs::write(store.engagement_path("alpha"), example_engagement()).expect("write");

        assert_eq!(store.list().expect("list"), vec!["alpha", "zeta"]);
    }

    #[test]
    fn switches_active_engagement() {
        let temp = tempdir().expect("tempdir");
        let store = EngagementStore::new(BugscopePaths::new(temp.path().join(".bugscope")));

        store.switch("acme").expect("switch");
        assert_eq!(
            store.active_name().expect("active"),
            Some("acme".to_string())
        );
        let active_file = store.paths.active_engagement_file();
        let contents = std::fs::read_to_string(active_file).expect("active file");
        assert_eq!(contents, "acme");
    }

    #[test]
    fn missing_engagement_returns_error() {
        let temp = tempdir().expect("tempdir");
        let store = EngagementStore::new(BugscopePaths::new(temp.path().join(".bugscope")));

        assert!(store.load("missing").is_err());
    }

    #[test]
    fn load_active_returns_none_when_unset() {
        let temp = tempdir().expect("tempdir");
        let store = EngagementStore::new(BugscopePaths::new(temp.path().join(".bugscope")));

        assert!(store.load_active().expect("load").is_none());
    }
}
