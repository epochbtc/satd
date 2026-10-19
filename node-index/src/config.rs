//! Runtime configuration for the address-history index.
//!
//! A runtime opt-out (`--addressindex=0` / `-noindex=address`) gates
//! index work without the conditional-compilation churn of a Cargo
//! feature flag. CFs are created unconditionally on DB open; only the
//! per-block emission and the protocol-side endpoints check `enabled`.

/// Default cap for concurrent per-scripthash subscriptions. Plumbed in
/// via `--addrindexsubscriptions=N`. Generous enough for typical
/// mobile-wallet xpub-derivation patterns (~20-200 scripthashes per
/// wallet) without unbounded memory growth.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = 10_000;

/// Per-channel `tokio::broadcast` capacity for status updates. Slow
/// consumers see `RecvError::Lagged` and resync from a fresh
/// `confirmed_history` query.
pub const DEFAULT_PER_CHANNEL_CAPACITY: usize = 32;

/// Default cap on the transactions in one scripthash's history that a
/// public read surface (Electrum `get_history` / `get_balance` /
/// `listunspent` / `subscribe` status, Esplora address stats and UTXO
/// list) will serve. Above it the request is refused with
/// [`IndexError::HistoryTooLarge`](crate::IndexError::HistoryTooLarge)
/// after reading at most `cap + 1` transactions' rows. 200,000 is the
/// Electrum surface's long-standing `get_history` cap.
pub const DEFAULT_MAX_HISTORY_ENTRIES: usize = 200_000;

#[derive(Clone, Debug)]
pub struct AddressIndexConfig {
    /// Whether per-block emission of address-index rows is active.
    /// Disabled via `--addressindex=0` or `-noindex=address`.
    pub enabled: bool,
    /// Maximum number of concurrent scripthash subscriptions.
    pub max_subscriptions: usize,
    /// Buffer depth of each per-scripthash broadcast channel.
    pub per_channel_capacity: usize,
    /// History cap for the subscription status recompute: a subscribed
    /// scripthash whose history grows past it gets no further status
    /// pushes (its status cannot be computed without reading the whole
    /// history). Defaults to [`DEFAULT_MAX_HISTORY_ENTRIES`], the same
    /// cap the Electrum handlers apply.
    pub max_history_entries: usize,
}

impl Default for AddressIndexConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_subscriptions: DEFAULT_MAX_SUBSCRIPTIONS,
            per_channel_capacity: DEFAULT_PER_CHANNEL_CAPACITY,
            max_history_entries: DEFAULT_MAX_HISTORY_ENTRIES,
        }
    }
}
