//! Runtime configuration for the address-history index.
//!
//! A runtime opt-out (`--addressindex=0` / `-noindex=address`) gates
//! index work without the conditional-compilation churn of a Cargo
//! feature flag. CFs are created unconditionally on DB open; only the
//! per-block emission and the protocol-side endpoints check `enabled`.

/// Default cap for concurrent per-scripthash subscriptions, server-wide:
/// every Electrum connection and Esplora SSE stream shares it. Plumbed in
/// via `--addrindexsubscriptions=N`.
///
/// Five Electrum connections at their default cap of 10,000 (a large
/// desktop wallet each) fit together. It moves with that cap: at 10,000
/// against a per-connection 1,000, ten wallets filled it, and raising only
/// the per-connection cap would let one wallet take it all (#1121).
/// Measured cost per subscribed scripthash: about 4.6 KB, so about 230 MB
/// when full, and a history read after every block, on the blocking pool:
/// about 30-55 µs for a short history on a warm index (one to three
/// seconds per block when full), about 0.2-0.35 ms at 20 transactions.
pub const DEFAULT_MAX_SUBSCRIPTIONS: usize = 50_000;

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
