//! The `AddressIndex` trait — read-side surface used by the operator
//! RPCs (M3) and, in later milestones, by Electrum / Esplora /
//! Silent-Payments query layers.
//!
//! The trait is intentionally minimal. Mempool history and the
//! subscription registry land in M4 / M5; their methods live on the
//! trait now so consumers can hold a `dyn AddressIndex` that won't
//! change shape across the milestone series.

use tokio::sync::broadcast;

use crate::keys::Scripthash;
use crate::subscribe::SubscribeError;
use crate::types::{
    HistoryEntry, IndexError, MempoolHistoryEntry, StatusUpdate, Utxo,
};

pub trait AddressIndex: Send + Sync {
    /// All confirmed funding + spending rows for `sh`, ordered by
    /// `(height, txid, vout/vin)` ascending. Returns `Err(Disabled)`
    /// when the index is gated off via `--addressindex=0`.
    fn confirmed_history(&self, sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError>;

    /// Like `confirmed_history`, but stops iterating once `limit` rows
    /// have been collected. Round-1 review M4: lets handlers enforce
    /// per-request caps without forcing a full RocksDB scan + Vec
    /// allocation up to the cap. Default impl forwards to the
    /// unbounded variant + truncates so non-Rocks backends don't break.
    fn confirmed_history_limited(
        &self,
        sh: &Scripthash,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>, IndexError> {
        let mut v = self.confirmed_history(sh)?;
        v.truncate(limit);
        Ok(v)
    }

    /// Unconfirmed (mempool) entries for `sh`.
    fn mempool_history(&self, sh: &Scripthash) -> Vec<MempoolHistoryEntry>;

    /// `(confirmed_balance_sat, unconfirmed_delta_sat)`. Confirmed
    /// balance is the sum of live UTXOs for `sh`. The unconfirmed delta
    /// is signed so a tx that spends more than it funds shows negative.
    fn balance(&self, sh: &Scripthash) -> Result<(u64, i64), IndexError>;

    /// Live UTXOs for `sh`, in `(height, txid, vout)` ascending order.
    fn utxos(&self, sh: &Scripthash) -> Result<Vec<Utxo>, IndexError>;

    /// Like `utxos`, but stops once `limit` UTXOs have been
    /// collected. Round-1 review M4. The walk still has to inspect
    /// funding rows past the limit because each row needs a
    /// `has_coin` check before we know it's a live UTXO; the cap
    /// applies to the *output* count, which is the wire-relevant
    /// dimension. Default impl forwards to the unbounded variant +
    /// truncates.
    fn utxos_limited(&self, sh: &Scripthash, limit: usize) -> Result<Vec<Utxo>, IndexError> {
        let mut v = self.utxos(sh)?;
        v.truncate(limit);
        Ok(v)
    }

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
