//! Runtime configuration for the address-history index.
//!
//! Mirrors the design from `ADDRESS_INDEX.md`: a runtime opt-out
//! (`--addressindex=0` / `-noindex=address`) gates index work without
//! the conditional-compilation churn of a Cargo feature flag. CFs are
//! created unconditionally on DB open; only the per-block emission and
//! the protocol-side endpoints check `enabled`.

/// Default cap for concurrent per-scripthash subscriptions. Plumbed in
/// M5 via `--addrindexsubscriptions=N`. Generous enough for typical
/// mobile-wallet xpub-derivation patterns (~20-200 scripthashes per
/// wallet) without unbounded memory growth.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = 10_000;

/// Per-channel `tokio::broadcast` capacity for status updates. Slow
/// consumers see `RecvError::Lagged` and resync from a fresh
/// `confirmed_history` query (M5).
pub const DEFAULT_PER_CHANNEL_CAPACITY: usize = 32;

#[derive(Clone, Debug)]
pub struct AddressIndexConfig {
    /// Whether per-block emission of address-index rows is active.
    /// Disabled via `--addressindex=0` or `-noindex=address`.
    pub enabled: bool,
    /// Maximum number of concurrent scripthash subscriptions.
    pub max_subscriptions: usize,
    /// Buffer depth of each per-scripthash broadcast channel.
    pub per_channel_capacity: usize,
}

impl Default for AddressIndexConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_subscriptions: DEFAULT_MAX_SUBSCRIPTIONS,
            per_channel_capacity: DEFAULT_PER_CHANNEL_CAPACITY,
        }
    }
}
