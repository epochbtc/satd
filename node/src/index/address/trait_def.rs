//! The `AddressIndex` trait — read-side surface used by the operator
//! RPCs (M3) and, in later milestones, by Electrum / Esplora /
//! Silent-Payments query layers.
//!
//! The trait is intentionally minimal. Mempool history and the
//! subscription registry land in M4 / M5; their methods live on the
//! trait now so consumers can hold a `dyn AddressIndex` that won't
//! change shape across the milestone series.

use tokio::sync::broadcast;

use crate::index::address::keys::Scripthash;
use crate::index::address::subscribe::SubscribeError;
use crate::index::address::types::{
    HistoryEntry, IndexError, MempoolHistoryEntry, StatusUpdate, Utxo,
};

pub trait AddressIndex: Send + Sync {
    /// All confirmed funding + spending rows for `sh`, ordered by
    /// `(height, txid, vout/vin)` ascending. Returns `Err(Disabled)`
    /// when the index is gated off via `--addressindex=0`.
    fn confirmed_history(&self, sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError>;

    /// Unconfirmed (mempool) entries for `sh`.
    fn mempool_history(&self, sh: &Scripthash) -> Vec<MempoolHistoryEntry>;

    /// `(confirmed_balance_sat, unconfirmed_delta_sat)`. Confirmed
    /// balance is the sum of live UTXOs for `sh`. The unconfirmed delta
    /// is signed so a tx that spends more than it funds shows negative.
    fn balance(&self, sh: &Scripthash) -> Result<(u64, i64), IndexError>;

    /// Live UTXOs for `sh`, in `(height, txid, vout)` ascending order.
    fn utxos(&self, sh: &Scripthash) -> Result<Vec<Utxo>, IndexError>;

    /// Subscribe to per-scripthash status updates. Returns a
    /// `tokio::broadcast::Receiver<StatusUpdate>` that fires on each
    /// real state change for `sh` (Electrum-compatible status hash).
    /// Returns `Err(CapReached)` if the configured subscription cap
    /// would be exceeded by adding a new scripthash.
    fn subscribe(
        &self,
        sh: Scripthash,
    ) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError>;
}
