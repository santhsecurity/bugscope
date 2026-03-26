//! Common path resolution helpers for `bugscope`.

use std::path::{Path, PathBuf};

use crate::error::BugscopeError;

/// Filesystem locations used by bugscope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BugscopePaths {
    root: PathBuf,
}

impl BugscopePaths {
    /// Resolve the default bugscope root.
    ///
    /// Uses `BUGSCOPE_HOME` when set, otherwise falls back to `~/.bugscope`.
    ///
    /// # Errors
    /// Returns an error when the user home directory cannot be determined.
    pub fn discover() -> Result<Self, BugscopeError> {
        if let Ok(path) = std::env::var("BUGSCOPE_HOME") {
            return Ok(Self {
                root: PathBuf::from(path),
            });
        }

        let home = dirs::home_dir().ok_or(BugscopeError::NoHomeDirectory)?;
        Ok(Self {
            root: home.join(".bugscope"),
        })
    }

    /// Construct bugscope paths from a specific root.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Return the bugscope root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return the engagements directory.
    #[must_use]
    pub fn engagements_dir(&self) -> PathBuf {
        self.root.join("engagements")
    }

    /// Return the active engagement selector file.
    #[must_use]
    pub fn active_engagement_file(&self) -> PathBuf {
        self.root.join("active")
    }

    /// Return the default scope file path.
    #[must_use]
    pub fn scope_file(&self) -> PathBuf {
        self.root.join("scope.toml")
    }

    /// Return the profiles directory path.
    #[must_use]
    pub fn profiles_dir(&self) -> PathBuf {
        self.root.join("profiles")
    }

    /// Return the default headers file path.
    #[must_use]
    pub fn headers_file(&self) -> PathBuf {
        self.root.join("headers.toml")
    }

    /// Return the default rate-limit file path.
    #[must_use]
    pub fn rate_limits_file(&self) -> PathBuf {
        self.root.join("ratelimits.toml")
    }
}
