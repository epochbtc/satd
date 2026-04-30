//! Mempool variant of the address-history index.
//!
//! Two HashMaps drive the index:
//!
//! - `by_scripthash[sh]` → set of txids in the mempool whose
//!   funding-or-spending touches `sh`.
//! - `by_txid[txid]` → list of scripthashes that the tx touches.
//!
//! `by_txid` is the inverse so a removal event (confirm / RBF / evict)
//! is O(scripthashes_per_tx) rather than O(mempool_size).
//!
//! Drives `RocksAddressIndex::mempool_history`, the unconfirmed-delta
//! component of `balance`, and (via M5) per-scripthash status updates.
//!
//! The index is populated by `mempool_index_task`, which subscribes to
//! `MempoolEvent` broadcasts. A slow subscriber that misses events
//! resyncs from a fresh `mempool.snapshot` rather than panicking.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::RwLock;

use bitcoin::{Transaction, Txid};

use crate::chain::state::ChainState;
use crate::index::address::keys::{Scripthash, scripthash_of};
use crate::mempool::events::MempoolEvent;
use crate::mempool::pool::Mempool;

/// In-memory address-index of mempool transactions.
#[derive(Default)]
pub struct MempoolAddrIndex {
    /// Scripthash → set of txids whose funding/spending touches it.
    by_scripthash: HashMap<Scripthash, HashSet<Txid>>,
    /// Txid → per-scripthash signed deltas the tx contributes. Stores
    /// deltas (not raw amounts) so removal subtracts exactly what the
    /// tx added, even if multiple txs touch the same scripthash. The
    /// keys also serve as the inverse-of-by_scripthash so removal is
    /// O(scripthashes_per_tx).
    by_txid: HashMap<Txid, Vec<(Scripthash, i64)>>,
    /// Per-scripthash unconfirmed delta in satoshis. Sum of per-tx
    /// contributions in `by_txid` for that scripthash. Removed on
    /// admission/removal in lock-step so it stays exact.
    delta_sat: HashMap<Scripthash, i64>,
}

impl MempoolAddrIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mempool entries whose funding/spending touches `sh`.
    pub fn entries_for(&self, sh: &Scripthash) -> Vec<Txid> {
        self.by_scripthash
            .get(sh)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Signed unconfirmed delta in satoshis for `sh`. 0 if the
    /// scripthash has no mempool entries.
    pub fn delta(&self, sh: &Scripthash) -> i64 {
        self.delta_sat.get(sh).copied().unwrap_or(0)
    }

    /// `(scripthashes_touched, scripthashes_per_value_change)` accessor
    /// used by tests.
    #[cfg(test)]
    pub fn debug_state(&self) -> (usize, usize) {
        (self.by_scripthash.len(), self.by_txid.len())
    }

    /// Record a tx admission: `funding` lists the (scripthash,
    /// amount_sat) pairs for outputs; `spending` lists the
    /// (scripthash, amount_sat) for resolved inputs.
    fn add_tx(
        &mut self,
        txid: Txid,
        funding: &[(Scripthash, u64)],
        spending: &[(Scripthash, u64)],
    ) {
        // Idempotent: a duplicate Enter (e.g. after a Lagged resync)
        // must not double-count.
        if self.by_txid.contains_key(&txid) {
            return;
        }

        // Coalesce funding + spending into per-scripthash signed
        // deltas. A tx that funds and spends the same scripthash
        // contributes a single net entry, so removal cleanly inverts.
        let mut deltas: HashMap<Scripthash, i64> = HashMap::new();
        for (sh, amount) in funding {
            *deltas.entry(*sh).or_insert(0) += *amount as i64;
        }
        for (sh, amount) in spending {
            *deltas.entry(*sh).or_insert(0) -= *amount as i64;
        }

        let mut touched: Vec<(Scripthash, i64)> = deltas.into_iter().collect();
        touched.sort_unstable_by_key(|(sh, _)| *sh);
        for (sh, delta) in &touched {
            self.by_scripthash.entry(*sh).or_default().insert(txid);
            *self.delta_sat.entry(*sh).or_insert(0) += *delta;
        }
        self.by_txid.insert(txid, touched);
    }

    /// Forget everything we know about `txid`. Inverse of `add_tx`:
    /// subtracts exactly the per-scripthash deltas the tx contributed
    /// so any other mempool tx touching the same scripthash retains
    /// its accurate delta.
    fn remove_tx(&mut self, txid: &Txid) {
        let touched = match self.by_txid.remove(txid) {
            Some(t) => t,
            None => return,
        };
        for (sh, delta) in &touched {
            if let Some(set) = self.by_scripthash.get_mut(sh) {
                set.remove(txid);
                if set.is_empty() {
                    self.by_scripthash.remove(sh);
                }
            }
            if let Some(entry) = self.delta_sat.get_mut(sh) {
                *entry -= *delta;
                if *entry == 0 {
                    self.delta_sat.remove(sh);
                }
            }
        }
    }

    /// Drop everything and rebuild from a mempool snapshot. Used after
    /// a `RecvError::Lagged` so the index re-converges with the
    /// canonical mempool state.
    pub fn resync_from(
        &mut self,
        snapshot: &[(Txid, bitcoin::Transaction)],
        chain_state: &ChainState,
        mempool: &Mempool,
    ) {
        self.by_scripthash.clear();
        self.by_txid.clear();
        self.delta_sat.clear();
        for (txid, tx) in snapshot {
            let (funding, spending) = resolve_scripthashes(tx, chain_state, mempool);
            self.add_tx(*txid, &funding, &spending);
        }
    }
}

/// `(scripthash, amount_sat)` — used in pairs by the mempool variant
/// for funding outputs and resolved spending inputs.
pub type ScriptHashAmount = (Scripthash, u64);

/// Resolve a transaction's input + output scripthashes. Outputs are
/// trivial (hash the output's `script_pubkey`); inputs require looking
/// up the prev_output's scriptPubKey from the chain UTXO set or, if
/// the parent tx is itself in the mempool, from the mempool entry.
///
/// Coinbase inputs are skipped (no prev_output). Inputs that fail to
/// resolve are logged and dropped — the tx shouldn't have been
/// admitted in that case, but we don't want to panic the index task
/// over a transient race.
pub fn resolve_scripthashes(
    tx: &Transaction,
    chain_state: &ChainState,
    mempool: &Mempool,
) -> (Vec<ScriptHashAmount>, Vec<ScriptHashAmount>) {
    let mut funding = Vec::with_capacity(tx.output.len());
    for out in &tx.output {
        let sh = scripthash_of(&out.script_pubkey);
        funding.push((sh, out.value.to_sat()));
    }

    let mut spending = Vec::with_capacity(tx.input.len());
    for input in &tx.input {
        if input.previous_output.is_null() {
            continue;
        }
        if let Some(coin) = chain_state.get_coin(&input.previous_output) {
            let sh = scripthash_of(&coin.script_pubkey);
            spending.push((sh, coin.amount));
            continue;
        }
        // Mempool ancestor: parent tx is already in the pool.
        if let Some(parent) = mempool.get(&input.previous_output.txid) {
            let vout = input.previous_output.vout as usize;
            if let Some(parent_out) = parent.tx.output.get(vout) {
                let sh = scripthash_of(&parent_out.script_pubkey);
                spending.push((sh, parent_out.value.to_sat()));
                continue;
            }
        }
        // Could not resolve — log once at debug, skip the input. The
        // mempool admission validator already enforced that prev_output
        // was visible at acceptance time, so a miss here is a transient
        // race (eg. block connected between Enter event emit and our
        // resolve call).
        tracing::debug!(
            "address-index: failed to resolve input prev_output for {}:{}",
            input.previous_output.txid,
            input.previous_output.vout
        );
    }

    (funding, spending)
}

/// Background task: subscribe to mempool events and keep the index in
/// sync. Runs until shutdown is signalled.
pub async fn mempool_index_task(
    index: Arc<RwLock<MempoolAddrIndex>>,
    mempool: Arc<Mempool>,
    chain_state: Arc<ChainState>,
    mut rx: tokio::sync::broadcast::Receiver<MempoolEvent>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            event = rx.recv() => {
                match event {
                    Ok(MempoolEvent::Enter { txid, .. }) => {
                        let entry = match mempool.get(&txid) {
                            Some(e) => e,
                            None => {
                                // Tx was removed between Enter emit and
                                // our lookup. The follow-up Leave* event
                                // would be a no-op anyway; skip.
                                continue;
                            }
                        };
                        let (funding, spending) = resolve_scripthashes(
                            &entry.tx, &chain_state, &mempool,
                        );
                        index.write().unwrap().add_tx(txid, &funding, &spending);
                    }
                    Ok(MempoolEvent::LeaveConfirmed { txid, .. })
                    | Ok(MempoolEvent::LeaveEvicted { txid, .. })
                    | Ok(MempoolEvent::LeaveReplaced { txid, .. }) => {
                        index.write().unwrap().remove_tx(&txid);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Subscriber fell behind — drain stale events
                        // and resync from the canonical mempool.
                        let snapshot: Vec<(Txid, bitcoin::Transaction)> = mempool
                            .get_all_entries()
                            .into_iter()
                            .map(|(txid, e)| (txid, e.tx))
                            .collect();
                        index.write().unwrap().resync_from(
                            &snapshot, &chain_state, &mempool,
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn fixture_txid(byte: u8) -> Txid {
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    #[test]
    fn test_address_index_mempool_add_then_query() {
        let mut idx = MempoolAddrIndex::new();
        let sh = [0xab; 32];
        let txid = fixture_txid(1);
        idx.add_tx(txid, &[(sh, 1000)], &[]);

        assert_eq!(idx.entries_for(&sh), vec![txid]);
        assert_eq!(idx.delta(&sh), 1000);
    }

    #[test]
    fn test_address_index_mempool_add_funding_and_spending() {
        let mut idx = MempoolAddrIndex::new();
        let sh = [0xcd; 32];
        let txid = fixture_txid(2);
        // Tx funds 2000 to sh and consumes 500 from sh — net +1500.
        idx.add_tx(txid, &[(sh, 2000)], &[(sh, 500)]);

        assert_eq!(idx.entries_for(&sh), vec![txid]);
        assert_eq!(idx.delta(&sh), 1500);
    }

    #[test]
    fn test_address_index_mempool_remove() {
        let mut idx = MempoolAddrIndex::new();
        let sh = [0x11; 32];
        let txid = fixture_txid(3);
        idx.add_tx(txid, &[(sh, 5000)], &[]);
        idx.remove_tx(&txid);

        assert!(idx.entries_for(&sh).is_empty());
        // Per-tx delta tracking: the delta drops back to zero exactly,
        // and the now-empty entry is removed.
        assert_eq!(idx.delta(&sh), 0);
        let (n_sh, n_tx) = idx.debug_state();
        assert_eq!(n_sh, 0);
        assert_eq!(n_tx, 0);
    }

    #[test]
    fn test_address_index_mempool_remove_one_of_two_preserves_other_delta() {
        // Two mempool txs both fund the same scripthash. Removing one
        // must leave the other's delta intact — a fix for the prior
        // wholesale `delta_sat.remove` behavior.
        let mut idx = MempoolAddrIndex::new();
        let sh = [0xee; 32];
        let txid_a = fixture_txid(10);
        let txid_b = fixture_txid(11);

        idx.add_tx(txid_a, &[(sh, 1000)], &[]);
        idx.add_tx(txid_b, &[(sh, 2500)], &[]);
        assert_eq!(idx.delta(&sh), 3500);

        idx.remove_tx(&txid_a);
        assert_eq!(idx.delta(&sh), 2500, "removing one tx must subtract only its delta");
        assert_eq!(idx.entries_for(&sh), vec![txid_b]);

        idx.remove_tx(&txid_b);
        assert_eq!(idx.delta(&sh), 0);
        let (n_sh, _) = idx.debug_state();
        assert_eq!(n_sh, 0);
    }

    #[test]
    fn test_address_index_mempool_self_funding_and_spending_net_delta() {
        // A single tx that funds and spends the same scripthash should
        // contribute exactly its net delta on add and remove cleanly.
        let mut idx = MempoolAddrIndex::new();
        let sh = [0xff; 32];
        let txid = fixture_txid(12);
        idx.add_tx(txid, &[(sh, 800)], &[(sh, 300)]);
        assert_eq!(idx.delta(&sh), 500);

        idx.remove_tx(&txid);
        assert_eq!(idx.delta(&sh), 0);
        let (n_sh, n_tx) = idx.debug_state();
        assert_eq!(n_sh, 0);
        assert_eq!(n_tx, 0);
    }

    #[test]
    fn test_address_index_mempool_idempotent_re_add() {
        let mut idx = MempoolAddrIndex::new();
        let sh = [0x22; 32];
        let txid = fixture_txid(4);
        idx.add_tx(txid, &[(sh, 1000)], &[]);
        idx.add_tx(txid, &[(sh, 1000)], &[]); // duplicate Enter (e.g. lagged resync)

        // Still one entry, delta unchanged.
        assert_eq!(idx.entries_for(&sh).len(), 1);
        assert_eq!(idx.delta(&sh), 1000);
    }

    #[test]
    fn test_address_index_mempool_unrelated_scripthash_not_touched() {
        let mut idx = MempoolAddrIndex::new();
        let sh_a = [0x33; 32];
        let sh_b = [0x44; 32];
        let txid = fixture_txid(5);
        idx.add_tx(txid, &[(sh_a, 1000)], &[]);

        assert_eq!(idx.entries_for(&sh_a).len(), 1);
        assert!(idx.entries_for(&sh_b).is_empty());
        assert_eq!(idx.delta(&sh_b), 0);
    }
}
