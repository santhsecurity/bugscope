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

    /// Constructs a full set of `bugscope` filesystem paths from a caller-supplied root.
    ///
    /// This is useful when tests or embedded tools want to avoid the default
    /// `BUGSCOPE_HOME` or `~/.bugscope` discovery behavior.
    ///
    /// # Parameters
    ///
    /// - `root`: Base directory under which `bugscope` should place engagements,
    ///   profiles, scope files, and rate-limit configuration.
    ///
    /// # Returns
    ///
    /// Returns a new [`BugscopePaths`] that derives all other paths from `root`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the root directory currently used for `bugscope` state.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns a shared reference to the configured root path.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the directory that stores engagement TOML files.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns `<root>/engagements`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn engagements_dir(&self) -> PathBuf {
        self.root.join("engagements")
    }

    /// Returns the file used to remember the active engagement name.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns `<root>/active`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn active_engagement_file(&self) -> PathBuf {
        self.root.join("active")
    }

    /// Returns the default top-level scope file path.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns `<root>/scope.toml`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn scope_file(&self) -> PathBuf {
        self.root.join("scope.toml")
    }

    /// Returns the directory used to persist bounty profiles.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns `<root>/profiles`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn profiles_dir(&self) -> PathBuf {
        self.root.join("profiles")
    }

    /// Returns the default header-profile configuration path.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns `<root>/headers.toml`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn headers_file(&self) -> PathBuf {
        self.root.join("headers.toml")
    }

    /// Returns the default rate-limit configuration path.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns `<root>/ratelimits.toml`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn rate_limits_file(&self) -> PathBuf {
        self.root.join("ratelimits.toml")
    }
}
