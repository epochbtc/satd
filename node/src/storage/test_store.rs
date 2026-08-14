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
use std::sync::atomic::{AtomicBool, Ordering};

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
}

/// An [`InMemoryStore`] whose failure modes and index configuration can be set
/// from a test.
pub(crate) struct ControllableStore {
    inner: InMemoryStore,
    controls: StoreControls,
}

impl ControllableStore {
    /// A store that behaves exactly like [`InMemoryStore`] until told otherwise
    /// — including its hardcoded "the index is on and complete".
    pub(crate) fn new() -> Self {
        Self {
            inner: InMemoryStore::new(),
            controls: StoreControls {
                fail_block_index_scan: Arc::new(AtomicBool::new(false)),
                txindex: Arc::new(AtomicBool::new(true)),
                txindex_complete: Arc::new(AtomicBool::new(true)),
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
        self.inner.write_batch(batch)
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
    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash> {
        self.inner.get_tx_location(txid)
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
