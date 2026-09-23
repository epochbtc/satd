//! A delegating [`Store`] wrapper for tests that need to control what the
//! storage layer *answers*, not just what it holds.
//!
//! Two kinds of fact are otherwise unreachable from a test:
//!
//! - **Storage failures.** [`Store::for_each_block_index`] returning `Err` is
//!   the difference between "no connectable child exists" and "we could not
//!   look", and the connector's recovery path has to tell them apart. A real
//!   backend only produces that on a corrupt SST or an IO fault.
//! - **Index configuration.** [`InMemoryStore`] hardcodes `has_txindex()` to
//!   true and inherits the trait's `tx_index_complete()` default of true, so no
//!   in-memory test could build a report for a node that runs without the
//!   index, or one whose index is known incomplete. Those are the two shapes
//!   that must *not* be reported as damage, and nothing could pin them.
//!
//! Every method delegates. That matters more than it looks: most of the trait
//! is defaulted, and several defaults are answers rather than errors —
//! `for_each_block_index` defaults to `Ok(empty)`, `tx_index_complete` to
//! `true`. A wrapper that forgets one silently reports a healthy chain as
//! having no blocks.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bitcoin::{BlockHash, OutPoint, Txid};

use super::db::InMemoryStore;
use super::{
    AddrFundingKey, AddrSpendingKey, Coin, Scripthash, SpendingRef, Store, StoreBatch, StoreError,
    UndoData,
};
use crate::storage::blockindex::BlockIndexEntry;

/// Handles onto a [`ControllableStore`]'s switches, cloneable and independent
/// of who owns the store.
///
/// `ChainState` takes `Box<dyn Store>` and keeps it, so a test that wants to
/// change the store's behaviour partway — which is the whole point, since
/// `ChainState::new` scans the block index itself and a store that fails from
/// birth cannot be built into a chain — cannot reach it through the box.
#[derive(Clone)]
pub(crate) struct StoreControls {
    fail_block_index_scan: Arc<AtomicBool>,
    txindex: Arc<AtomicBool>,
    txindex_complete: Arc<AtomicBool>,
    coin_gate: Arc<std::sync::Mutex<Option<ArmedCoinGate>>>,
    fail_next_write: Arc<AtomicBool>,
    /// How many times each ordinal read has been called. The index read
    /// paths resolve ordinals to txids in one batch per scan rather than
    /// one per row; nothing about the returned rows shows which of the
    /// two a caller did, so the count is the only way to pin it.
    get_tx_seq_calls: Arc<AtomicU64>,
    txids_of_seqs_calls: Arc<AtomicU64>,
}

/// A one-shot rendezvous armed on a specific outpoint: the first coin read
/// that reaches this store and covers the outpoint signals `entered` and then
/// blocks until released. This is how a test holds one thread *inside* a read
/// (e.g. a reorg's input resolution) while another thread mutates the same
/// chain — the only way to make a cross-thread interleaving deterministic.
///
/// Note the store this fires in is the *inner* store: reads served by the
/// `CoinCache`'s dirty map or clean LRU never get here. A test that needs the
/// gate to fire must first arrange for the read to miss the cache (flush, then
/// shrink/displace the clean LRU).
struct ArmedCoinGate {
    outpoint: OutPoint,
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

/// Test-side handle for an armed coin gate.
pub(crate) struct CoinGateHandle {
    entered: std::sync::mpsc::Receiver<()>,
    release: std::sync::mpsc::SyncSender<()>,
}

impl CoinGateHandle {
    /// Block until the gated thread reaches the read. Panics after 30s so a
    /// test where the thread never gets there fails instead of hanging.
    pub(crate) fn wait_entered(&self) {
        self.entered
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("gated thread never reached the armed coin read");
    }

    /// Let the parked thread continue.
    pub(crate) fn release(&self) {
        let _ = self.release.send(());
    }
}

impl StoreControls {
    /// Make every subsequent block-index scan fail, standing in for a corrupt
    /// SST or an IO fault.
    pub(crate) fn fail_block_index_scans(&self, yes: bool) {
        self.fail_block_index_scan.store(yes, Ordering::SeqCst);
    }

    /// Set what the store reports for `-txindex` and for whether that index was
    /// ever fully built. `InMemoryStore` hardcodes the first to true and
    /// inherits the trait default `true` for the second, so without this no
    /// test can build a report for a node that runs no index, or one whose
    /// index is known incomplete — the two shapes that must not be reported as
    /// damage.
    pub(crate) fn set_txindex(&self, enabled: bool, complete: bool) {
        self.txindex.store(enabled, Ordering::SeqCst);
        self.txindex_complete.store(complete, Ordering::SeqCst);
    }

    /// Arm the one-shot coin gate on `outpoint`. See [`ArmedCoinGate`].
    pub(crate) fn arm_coin_gate(&self, outpoint: OutPoint) -> CoinGateHandle {
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        *self.coin_gate.lock().unwrap() = Some(ArmedCoinGate {
            outpoint,
            entered: entered_tx,
            release: release_rx,
        });
        CoinGateHandle {
            entered: entered_rx,
            release: release_tx,
        }
    }

    /// Make the next batch write fail, once, standing in for a transient
    /// backing-store fault (ENOSPC, an IO error). One-shot so a test can arm
    /// it, observe the failure, and then let the retry through without
    /// racing a second disarm.
    ///
    /// The write is refused before anything is applied, so the store is left
    /// exactly as it was — which is what the real backends do too, RocksDB
    /// applying a `WriteBatch` atomically.
    pub(crate) fn fail_next_write(&self) {
        self.fail_next_write.store(true, Ordering::SeqCst);
    }

    /// How many `get_tx_seq` calls the store has served since the last
    /// reset.
    pub(crate) fn get_tx_seq_calls(&self) -> u64 {
        self.get_tx_seq_calls.load(Ordering::SeqCst)
    }

    /// How many `txids_of_seqs` calls the store has served since the last
    /// reset. One per scan is the contract; one per row is the defect.
    pub(crate) fn txids_of_seqs_calls(&self) -> u64 {
        self.txids_of_seqs_calls.load(Ordering::SeqCst)
    }

    /// Zero both ordinal-read counters, so a test can set up state
    /// without the setup's reads counting against the assertion.
    pub(crate) fn reset_ordinal_read_counts(&self) {
        self.get_tx_seq_calls.store(0, Ordering::SeqCst);
        self.txids_of_seqs_calls.store(0, Ordering::SeqCst);
    }
}

/// An [`InMemoryStore`] whose failure modes and index configuration can be set
/// from a test.
pub(crate) struct ControllableStore {
    inner: InMemoryStore,
    controls: StoreControls,
}

impl ControllableStore {
    /// Park the calling thread if the coin gate is armed for any of
    /// `outpoints`. One-shot: the gate is disarmed before parking, so the
    /// releasing thread's own reads of the same outpoint pass through.
    fn maybe_park(&self, outpoints: &[OutPoint]) {
        let armed = {
            let mut slot = self.controls.coin_gate.lock().unwrap();
            match slot.as_ref() {
                Some(g) if outpoints.contains(&g.outpoint) => slot.take(),
                _ => None,
            }
        };
        if let Some(g) = armed {
            let _ = g.entered.send(());
            let _ = g.release.recv_timeout(std::time::Duration::from_secs(30));
        }
    }

    /// A store that behaves exactly like [`InMemoryStore`] until told otherwise
    /// — including its hardcoded "the index is on and complete".
    pub(crate) fn new() -> Self {
        Self {
            inner: InMemoryStore::new(),
            controls: StoreControls {
                fail_block_index_scan: Arc::new(AtomicBool::new(false)),
                txindex: Arc::new(AtomicBool::new(true)),
                txindex_complete: Arc::new(AtomicBool::new(true)),
                coin_gate: Arc::new(std::sync::Mutex::new(None)),
                fail_next_write: Arc::new(AtomicBool::new(false)),
                get_tx_seq_calls: Arc::new(AtomicU64::new(0)),
                txids_of_seqs_calls: Arc::new(AtomicU64::new(0)),
            },
        }
    }

    /// Handles that outlive moving the store into a `ChainState`.
    pub(crate) fn controls(&self) -> StoreControls {
        self.controls.clone()
    }
}

impl Store for ControllableStore {
    fn for_each_block_index(
        &self,
        visit: &mut dyn FnMut(BlockHash, BlockIndexEntry),
    ) -> Result<crate::storage::BlockIndexScanStats, StoreError> {
        // Visit first, *then* fail. A scan that errors before visiting
        // anything is the easy case — there is no partial result to misuse.
        // The case worth pinning is a fault partway through a scan that has
        // already seen candidates, because that is where "the best child" and
        // "the best of what we reached" diverge, and where a caller has to
        // decide which of the two it trusts. Failing at the end of the visit
        // is that case with a deterministic ordering, which the underlying
        // `HashMap` iteration order would not otherwise give.
        let stats = self.inner.for_each_block_index(visit)?;
        if self.controls.fail_block_index_scan.load(Ordering::SeqCst) {
            return Err(StoreError::Database("injected block-index scan fault".into()));
        }
        Ok(stats)
    }

    fn has_txindex(&self) -> bool {
        self.controls.txindex.load(Ordering::SeqCst)
    }

    fn tx_index_complete(&self) -> bool {
        self.controls.txindex_complete.load(Ordering::SeqCst)
    }

    // ---- everything below is straight delegation ----

    fn flush_durable(&self) -> Result<(), StoreError> {
        self.inner.flush_durable()
    }
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        self.inner.get_block_index(hash)
    }
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        // Covers `get_coins_batch` too: the trait default resolves a batch
        // through per-outpoint `get_coin` calls.
        self.maybe_park(std::slice::from_ref(outpoint));
        self.inner.get_coin(outpoint)
    }
    fn has_coin(&self, outpoint: &OutPoint) -> bool {
        self.inner.has_coin(outpoint)
    }
    fn get_tip(&self) -> Option<BlockHash> {
        self.inner.get_tip()
    }
    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        self.inner.get_block_hash_by_height(height)
    }
    fn get_cumulative_tx_count(&self, hash: &BlockHash) -> Option<u64> {
        self.inner.get_cumulative_tx_count(hash)
    }
    fn chain_tx_backfill_complete(&self) -> bool {
        self.inner.chain_tx_backfill_complete()
    }
    fn mark_chain_tx_backfill_complete(&self) -> Result<(), StoreError> {
        self.inner.mark_chain_tx_backfill_complete()
    }
    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        self.write_batch_recoverable(batch, crate::storage::WriteMode::Normal)
            .map_err(|(_, e)| e)
    }
    fn write_batch_recoverable(
        &self,
        batch: StoreBatch,
        mode: crate::storage::WriteMode,
    ) -> Result<(), (Option<Box<StoreBatch>>, StoreError)> {
        if self.controls.fail_next_write.swap(false, Ordering::SeqCst) {
            // Refused before anything is applied, so the batch comes back
            // whole — the contract the real backends meet by writing
            // atomically.
            return Err((
                Some(Box::new(batch)),
                StoreError::Database("injected write fault".into()),
            ));
        }
        self.inner.write_batch_recoverable(batch, mode)
    }
    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData> {
        self.inner.get_undo(hash)
    }
    fn for_each_height_hash(
        &self,
        visit: &mut dyn FnMut(u32, BlockHash),
    ) -> Result<crate::storage::HeightHashScanStats, StoreError> {
        self.inner.for_each_height_hash(visit)
    }
    fn coin_count(&self) -> u64 {
        self.inner.coin_count()
    }
    fn for_each_coin_snapshot(
        &self,
        f: &mut dyn FnMut(&OutPoint, &Coin) -> Result<(), StoreError>,
    ) -> Result<crate::storage::CoinSnapshotBase, StoreError> {
        self.inner.for_each_coin_snapshot(f)
    }
    fn coin_total_amount(&self) -> u64 {
        self.inner.coin_total_amount()
    }
    fn utxo_height_hist(&self) -> Vec<u64> {
        self.inner.utxo_height_hist()
    }
    fn utxo_recent_heights(&self) -> Option<crate::storage::RecentHeightWindow> {
        self.inner.utxo_recent_heights()
    }
    fn build_recent_window(
        &self,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<crate::storage::RecentWindowBuild, StoreError> {
        self.inner.build_recent_window(cancel)
    }
    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash> {
        self.inner.get_tx_location(txid)
    }
    fn get_tx_seq(&self, txid: &Txid) -> Option<u64> {
        self.controls.get_tx_seq_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_tx_seq(txid)
    }
    fn txids_of_seqs(&self, seqs: &[u64]) -> Vec<Option<Txid>> {
        self.controls
            .txids_of_seqs_calls
            .fetch_add(1, Ordering::SeqCst);
        self.inner.txids_of_seqs(seqs)
    }
    fn block_of_seq(&self, seq: u64) -> Option<(u64, u32)> {
        self.inner.block_of_seq(seq)
    }
    fn clear_chainstate(&self) -> Result<(), StoreError> {
        self.inner.clear_chainstate()
    }
    fn clear_all(&self) -> Result<(), StoreError> {
        self.inner.clear_all()
    }
    fn iter_addr_funding(&self, sh: &Scripthash) -> Vec<(AddrFundingKey, u64)> {
        self.inner.iter_addr_funding(sh)
    }
    fn iter_addr_spending(&self, sh: &Scripthash) -> Vec<(AddrSpendingKey, OutPoint)> {
        self.inner.iter_addr_spending(sh)
    }
    fn lookup_spends_of_tx(&self, txid: &Txid) -> Result<Vec<(u32, SpendingRef)>, StoreError> {
        self.inner.lookup_spends_of_tx(txid)
    }
    fn lookup_spend(&self, outpoint: &OutPoint) -> Result<Option<SpendingRef>, StoreError> {
        self.inner.lookup_spend(outpoint)
    }
    fn get_sp_tweaks_row(&self, height: u32) -> Option<node_sp_index::SpBlockRow> {
        self.inner.get_sp_tweaks_row(height)
    }
    fn silent_payment_index_complete(&self) -> bool {
        self.inner.silent_payment_index_complete()
    }
    fn mark_silent_payment_index_complete(&self) -> Result<(), StoreError> {
        self.inner.mark_silent_payment_index_complete()
    }
    fn read_sp_backfill_cursor(&self) -> node_sp_index::cursor::BackfillCursor {
        self.inner.read_sp_backfill_cursor()
    }
    fn read_sp_backfill_last_error(&self) -> Option<String> {
        self.inner.read_sp_backfill_last_error()
    }
    fn write_sp_backfill_last_error(&self, msg: &str) -> Result<(), StoreError> {
        self.inner.write_sp_backfill_last_error(msg)
    }
    #[cfg(feature = "block-filter-index")]
    fn get_filter(&self, filter_type: u8, height: u32) -> Option<Vec<u8>> {
        self.inner.get_filter(filter_type, height)
    }
    #[cfg(feature = "block-filter-index")]
    fn get_filter_header(&self, filter_type: u8, height: u32) -> Option<[u8; 32]> {
        self.inner.get_filter_header(filter_type, height)
    }
    #[cfg(feature = "block-filter-index")]
    fn block_filter_index_complete(&self) -> bool {
        self.inner.block_filter_index_complete()
    }
    #[cfg(feature = "block-filter-index")]
    fn mark_block_filter_index_complete(&self) -> Result<(), StoreError> {
        self.inner.mark_block_filter_index_complete()
    }
    #[cfg(feature = "block-filter-index")]
    fn read_filter_backfill_cursor(&self) -> node_filter_index::cursor::BackfillCursor {
        self.inner.read_filter_backfill_cursor()
    }
    #[cfg(feature = "block-filter-index")]
    fn read_filter_backfill_last_error(&self) -> Option<String> {
        self.inner.read_filter_backfill_last_error()
    }
    #[cfg(feature = "block-filter-index")]
    fn write_filter_backfill_last_error(&self, msg: &str) -> Result<(), StoreError> {
        self.inner.write_filter_backfill_last_error(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StoreBatch;
    use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};

    /// Every trait method this wrapper forgets silently answers with the
    /// trait default, and for the ordinal reads that default is "no
    /// row" — which a caller cannot tell apart from a genuinely absent
    /// transaction. The module doc calls this out for the block-index
    /// scan; the ordinal reads are the same hazard, and the counters
    /// make "did the call actually reach the inner store" observable.
    #[test]
    fn controllable_store_forwards_every_ordinal_read() {
        let store = ControllableStore::new();
        let controls = store.controls();

        let g = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let hash = g.block_hash();
        let txid = g.txdata[0].compute_txid();
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((
            hash,
            BlockIndexEntry {
                header: g.header,
                height: 0,
                status: BlockStatus::Valid,
                num_tx: 1,
                file_number: 0,
                data_pos: 0,
                chainwork: [0u8; 32],
            },
        ));
        batch.height_hash_puts.push((0, hash));
        batch.tx_loc_puts.push((txid, 0));
        batch.txseq_txid_puts.push((0, txid));
        batch.txseq_block_puts.push((0, 0));
        store.write_batch(batch).unwrap();

        controls.reset_ordinal_read_counts();
        assert_eq!(store.get_tx_seq(&txid), Some(0));
        assert_eq!(store.txids_of_seqs(&[0]), vec![Some(txid)]);
        assert_eq!(store.block_of_seq(0), Some((0, 0)));
        assert_eq!(store.get_tx_location(&txid), Some(hash));

        assert_eq!(
            controls.get_tx_seq_calls(),
            1,
            "get_tx_seq must reach the inner store, not the trait default"
        );
        assert_eq!(
            controls.txids_of_seqs_calls(),
            1,
            "txids_of_seqs must reach the inner store, not the trait default"
        );
    }
}
