//! Shared registry entries for verified bounty programs.

/// A registered bounty target entry.
#[derive(Debug, Clone)]
pub struct BountyRegistryEntry {
    /// Program name.
    pub name: &'static str,
    /// Platform identifier.
    pub platform: &'static str,
    /// Primary domain.
    pub domain: &'static str,
    /// Maximum requests per second.
    pub rate_limit: u32,
    /// Whether automated scanning is confirmed allowed.
    pub scanning_confirmed: bool,
    /// Program tier.
    pub tier: u8,
}

/// The shared registry of known bounty programs.
pub const REGISTRY: &[BountyRegistryEntry] = &[
    BountyRegistryEntry {
        name: "ATG",
        platform: "yeswehack",
        domain: "atg.se",
        rate_limit: 10,
        scanning_confirmed: true,
        tier: 1,
    },
    BountyRegistryEntry {
        name: "Easyship",
        platform: "yeswehack",
        domain: "easyship.com",
        rate_limit: 10,
        scanning_confirmed: true,
        tier: 1,
    },
    BountyRegistryEntry {
        name: "BMW Group",
        platform: "intigriti",
        domain: "bmw.com",
        rate_limit: 2,
        scanning_confirmed: true,
        tier: 1,
    },
];
