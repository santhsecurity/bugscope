//! Scope parsing, rate limiting, engagement loading, and header injection for security scanners.
//!
//! `bugscope` exists to keep scanners from drifting out of program scope while still making it
//! easy to apply program-specific auth headers, engagement selection, and rate limits from disk.

#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::unnecessary_wraps)]

pub mod cli;
pub mod config;
pub mod engagement;
pub mod error;
pub mod headers;
pub mod profile;
pub mod ratelimit;
pub mod registry;
pub mod scope;

pub use cli::BugscopeArgs;
pub use config::BugscopePaths;
pub use engagement::{EngagementConfig, EngagementStore};
pub use error::BugscopeError;
pub use headers::{AuthScheme, HeaderInjector, HeaderProfile, HeaderSet};
pub use profile::{
    classify_finding, common_exclusions, list_profiles, load_profile, platform_headers,
    profile_from_program, profiles_dir, save_profile, BountyProfile, ExclusionRule, FindingTag,
};
pub use ratelimit::{RateLimitConfig, RateLimitRule, RateLimiter};
pub use registry::{BountyRegistryEntry, REGISTRY};
pub use scope::{
    expand_wildcards, expand_wildcards_with_resolver, fetch_scope, is_target_in_scope,
    parse_scope_file, parse_scope_str, parse_scope_toml, targets_from_scope, wildcard_matches,
    BountyProgram, Platform, ScopeConfig, ScopeGuard, ScopeTarget, TargetType,
};

#[cfg(test)]
mod adversarial_tests;
