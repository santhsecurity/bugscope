//! `clap` integration helpers.

use std::path::PathBuf;

use clap::Args;

use crate::engagement::{EngagementConfig, EngagementStore};
use crate::error::BugscopeError;
use crate::scope::Platform;

/// Reusable arguments that any security CLI can flatten into its own parser.
#[derive(Debug, Clone, PartialEq, Eq, Default, Args)]
pub struct BugscopeArgs {
    /// Path to a scope TOML file.
    #[arg(long)]
    pub scope_file: Option<PathBuf>,

    /// Engagement name to load from `~/.bugscope/engagements`.
    #[arg(long)]
    pub engagement: Option<String>,

    /// Bounty platform profile to use for header injection.
    #[arg(long)]
    pub bounty_platform: Option<String>,

    /// Override the request rate as requests per second.
    #[arg(long)]
    pub rate_limit: Option<u32>,
}

impl BugscopeArgs {
    /// Load an engagement specified by `--engagement`.
    ///
    /// # Errors
    /// Returns an error when the engagement store or file cannot be loaded.
    pub fn load_engagement(&self) -> Result<Option<EngagementConfig>, BugscopeError> {
        let Some(name) = &self.engagement else {
            return Ok(None);
        };

        EngagementStore::discover()?.load(name).map(Some)
    }

    /// Return the selected platform from CLI or engagement config.
    #[must_use]
    pub fn selected_platform(&self, engagement: Option<&EngagementConfig>) -> Option<Platform> {
        self.bounty_platform
            .as_ref()
            .map(|value| Platform::custom(value.clone()))
            .or_else(|| engagement.map(|config| config.platform.clone()))
    }

    /// Return the CLI rate-limit override as requests per second.
    #[must_use]
    pub fn rate_limit_override(&self) -> Option<f64> {
        self.rate_limit.map(f64::from)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::Parser;

    use crate::engagement::EngagementConfig;
    use crate::scope::Platform;

    use super::BugscopeArgs;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        bugscope: BugscopeArgs,
    }

    #[test]
    fn parses_flattened_args() {
        let cli = TestCli::parse_from([
            "scan",
            "--scope-file",
            "scope.toml",
            "--bounty-platform",
            "hackerone",
            "--rate-limit",
            "5",
        ]);

        assert_eq!(
            cli.bugscope.scope_file.as_deref(),
            Some(Path::new("scope.toml"))
        );
        assert_eq!(cli.bugscope.bounty_platform.as_deref(), Some("hackerone"));
        assert_eq!(cli.bugscope.rate_limit, Some(5));
    }

    #[test]
    fn prefers_cli_platform_over_engagement_platform() {
        let args = BugscopeArgs {
            bounty_platform: Some("custom".to_string()),
            ..BugscopeArgs::default()
        };
        let engagement = EngagementConfig {
            program_name: "acme".to_string(),
            platform: Platform::hackerone(),
            scope: crate::scope::ScopeConfig::default(),
            credentials: crate::headers::HeaderProfile::default(),
            rate_limits: crate::ratelimit::RateLimitConfig::default(),
            notes: None,
        };

        assert_eq!(
            args.selected_platform(Some(&engagement))
                .expect("platform")
                .key(),
            "custom"
        );
    }

    #[test]
    fn uses_engagement_platform_when_cli_is_unset() {
        let args = BugscopeArgs::default();
        let engagement = EngagementConfig {
            program_name: "acme".to_string(),
            platform: Platform::hackerone(),
            scope: crate::scope::ScopeConfig::default(),
            credentials: crate::headers::HeaderProfile::default(),
            rate_limits: crate::ratelimit::RateLimitConfig::default(),
            notes: None,
        };

        assert_eq!(
            args.selected_platform(Some(&engagement))
                .expect("platform")
                .key(),
            "hackerone"
        );
    }

    #[test]
    fn rate_limit_override_maps_to_float() {
        let args = BugscopeArgs {
            rate_limit: Some(7),
            ..BugscopeArgs::default()
        };

        assert_eq!(args.rate_limit_override(), Some(7.0));
    }
}
