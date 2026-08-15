//! A [`Store`] view that splits one logical chainstate across a SHARED
//! block store and a PRIVATE coins store.
//!
//! AssumeUTXO runs a background chainstate that validates genesis →
//! `snapshot_height` while the snapshot chainstate serves the tip. The
//! background must build its own UTXO set (so the snapshot chainstate's
//! coins are never disturbed) yet write the blocks it downloads into the
//! ONE shared block store — block files plus the `block_index` and
//! height→hash map — so that after handoff the snapshot chainstate can
//! still locate every historical block. Two fully-separate chainstates
//! that drop the background DB at handoff would lose those historical
//! block-index positions; this split is exactly what prevents that.
//!
//! Routing:
//! - `block_index`, height→hash, txindex  → `block_store` (shared)
//! - coins, undo, tip                      → `coins_store` (private)
//!
//! Block-store writes go through the SAME backing store (a `CoinCache`
//! in production) that the snapshot chainstate reads from, so the shared
//! `block_index` cache never serves a stale entry for a height the
//! background just connected.

use std::sync::Arc;

use bitcoin::{BlockHash, OutPoint, Txid};

use crate::storage::blockindex::BlockIndexEntry;
use crate::storage::coinview::Coin;
use crate::storage::undo::UndoData;
use crate::storage::{
    BlockIndexScanStats, CoinSnapshotBase, Store, StoreBatch, StoreError, WriteMode,
};

/// Routes block-store operations to a shared store and coins/undo/tip to
/// a private one. See the module docs for the AssumeUTXO motivation.
pub struct SplitStore {
    /// Shared block store: `block_index`, height→hash, txindex. In
    /// production this is the snapshot chainstate's `CoinCache`, so both
    /// chainstates observe one coherent block index.
    block_store: Arc<dyn Store>,
    /// Private coins store: coins, undo, tip. A separate RocksDB
    /// (`chainstate_background/`) that is discarded after handoff.
    coins_store: Arc<dyn Store>,
    /// The snapshot chainstate's `accept_lock`, held around every write to
    /// the *shared* block store.
    ///
    /// The block store is that chainstate's `CoinCache`, so the background
    /// catch-up thread is a second writer into a cache the snapshot
    /// chainstate reorgs. The background's batches are coin-free, which
    /// means they take the cache's pass-through branch — a discard cannot
    /// destroy them — but the pass-through is not free of shared state: it
    /// prunes superseded entries out of the cache's pending batch on the
    /// way through, a mutation that must not interleave with a reorg
    /// staging entries into that same buffer. A reorg holds `accept_lock`
    /// from its checkpoint flush through to its commit or abort, so taking
    /// it here serializes the background write against the whole window
    /// and keeps the holder list's claim — one chain mutator at a time —
    /// true on the AssumeUTXO path too. It does not need to be held across
    /// the background's own validation work, which touches only the
    /// private store, so the contention is one write's worth per
    /// background block.
    ///
    /// `None` for a `SplitStore` with no chainstate above it (tests).
    block_store_lock: Option<Arc<parking_lot::Mutex<()>>>,
}

impl SplitStore {
    pub fn new(
        block_store: Arc<dyn Store>,
        coins_store: Arc<dyn Store>,
        block_store_lock: Option<Arc<parking_lot::Mutex<()>>>,
    ) -> Self {
        Self {
            block_store,
            coins_store,
            block_store_lock,
        }
    }

    /// The single door for writes into the *shared* block store. Every
    /// path — `write_batch`, `write_batch_mode`, `write_batch_recoverable` —
    /// must route its block half through here: the shared store belongs to
    /// the snapshot chainstate, and any serialization that chainstate
    /// imposes on shared writes has to cover all of the doors or it covers
    /// none. This function is the merge of two earlier half-measures — one
    /// that took the lock, one that returned the recoverable shape — and it
    /// must keep doing both; splitting them again reintroduces a door that
    /// only one of the two properties covers.
    ///
    /// The write runs under the snapshot chainstate's `accept_lock` (see
    /// [`Self::block_store_lock`]), so a background catch-up write cannot
    /// interleave with that chainstate's own mutations.
    ///
    /// Block-half writes are always `WriteMode::Normal`: the block index
    /// stays durable even while the heavy coins writes run BulkLoad during
    /// the background catch-up.
    fn write_block_half(
        &self,
        batch: StoreBatch,
    ) -> Result<(), (Option<Box<StoreBatch>>, StoreError)> {
        let _guard = self.block_store_lock.as_ref().map(|l| l.lock());
        self.block_store
            .write_batch_recoverable(batch, WriteMode::Normal)
    }

    /// Partition a batch into `(block-store mutations, coins-store
    /// mutations)`. Block-index/height/txindex rows are moved out into
    /// the block batch; everything else (coins, undo, tip — and any
    /// secondary-index rows, which the background never emits because it
    /// runs with those indexes disabled) stays in the original batch and
    /// goes to the coins store.
    /// Inverse of [`Self::split_batch`]: fold the block half back into the
    /// coins half so a failed write can hand the caller one batch again.
    fn rejoin(block_batch: StoreBatch, mut coins_batch: StoreBatch) -> StoreBatch {
        coins_batch.merge(block_batch);
        coins_batch
    }

    fn split_batch(mut batch: StoreBatch) -> (StoreBatch, StoreBatch) {
        let block_batch = StoreBatch {
            block_index_puts: std::mem::take(&mut batch.block_index_puts),
            height_hash_puts: std::mem::take(&mut batch.height_hash_puts),
            height_hash_removes: std::mem::take(&mut batch.height_hash_removes),
            tx_index_puts: std::mem::take(&mut batch.tx_index_puts),
            tx_index_removes: std::mem::take(&mut batch.tx_index_removes),
            // Cumulative tx counts live with the block index in the shared
            // store so the served (snapshot) chain and the background's
            // genesis→base fills land in one CF — visible to getchaintxstats
            // before and after handoff.
            chain_tx_puts: std::mem::take(&mut batch.chain_tx_puts),
            ..StoreBatch::default()
        };
        (block_batch, batch)
    }
}

impl Store for SplitStore {
    // ---- block store (shared) ----
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        self.block_store.get_block_index(hash)
    }

    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        self.block_store.get_block_hash_by_height(height)
    }

    fn get_cumulative_tx_count(&self, hash: &BlockHash) -> Option<u64> {
        self.block_store.get_cumulative_tx_count(hash)
    }

    fn chain_tx_backfill_complete(&self) -> bool {
        self.block_store.chain_tx_backfill_complete()
    }

    fn mark_chain_tx_backfill_complete(&self) -> Result<(), StoreError> {
        self.block_store.mark_chain_tx_backfill_complete()
    }

    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash> {
        self.block_store.get_tx_location(txid)
    }

    fn has_txindex(&self) -> bool {
        self.block_store.has_txindex()
    }

    /// Delegated for the same reason as `has_txindex` above: `tx_index_puts`
    /// and `tx_index_removes` are routed to the block store, so its marker is
    /// the one describing the rows this store actually reads. The trait
    /// default is `true` ("non-Rocks backends are freshly built"), which is
    /// the fail-open answer here — it would tell a consistency audit that a
    /// known-incomplete index is complete.
    fn tx_index_complete(&self) -> bool {
        self.block_store.tx_index_complete()
    }

    fn for_each_block_index(
        &self,
        visit: &mut dyn FnMut(BlockHash, BlockIndexEntry),
    ) -> Result<BlockIndexScanStats, StoreError> {
        self.block_store.for_each_block_index(visit)
    }

    /// The height index is routed to the block store on write, so that is
    /// where the scan has to read from.
    fn for_each_height_hash(
        &self,
        visit: &mut dyn FnMut(u32, BlockHash),
    ) -> Result<crate::storage::HeightHashScanStats, StoreError> {
        self.block_store.for_each_height_hash(visit)
    }

    // ---- coins store (private) ----
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.coins_store.get_coin(outpoint)
    }

    fn has_coin(&self, outpoint: &OutPoint) -> bool {
        self.coins_store.has_coin(outpoint)
    }

    fn get_coins_batch(&self, outpoints: &[OutPoint]) -> Vec<Option<Coin>> {
        self.coins_store.get_coins_batch(outpoints)
    }

    fn get_tip(&self) -> Option<BlockHash> {
        self.coins_store.get_tip()
    }

    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData> {
        self.coins_store.get_undo(hash)
    }

    fn coin_count(&self) -> u64 {
        self.coins_store.coin_count()
    }

    fn coin_total_amount(&self) -> u64 {
        self.coins_store.coin_total_amount()
    }

    fn utxo_height_hist(&self) -> Vec<u64> {
        self.coins_store.utxo_height_hist()
    }

    fn for_each_coin_snapshot(
        &self,
        f: &mut dyn FnMut(&OutPoint, &Coin) -> Result<(), StoreError>,
    ) -> Result<CoinSnapshotBase, StoreError> {
        self.coins_store.for_each_coin_snapshot(f)
    }

    // ---- writes ----
    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        let (block_batch, coins_batch) = Self::split_batch(batch);
        // Shared block store first, private coins+tip second. The
        // background's progress is defined by its tip (in the coins
        // store); committing the block index before the tip means a
        // crash in between leaves the block index slightly ahead, and
        // re-connecting that block on restart is idempotent (same
        // block-index put, coins re-applied). The reverse order could
        // strand a tip pointing at a block whose index never landed.
        self.write_block_half(block_batch).map_err(|(_, e)| e)?;
        self.coins_store.write_batch(coins_batch)?;
        Ok(())
    }

    fn write_batch_mode(&self, batch: StoreBatch, mode: WriteMode) -> Result<(), StoreError> {
        let (block_batch, coins_batch) = Self::split_batch(batch);
        // Block index stays durable; only the heavy coins writes honor
        // BulkLoad during the background catch-up IBD.
        self.write_block_half(block_batch).map_err(|(_, e)| e)?;
        self.coins_store.write_batch_mode(coins_batch, mode)?;
        Ok(())
    }

    fn write_batch_recoverable(
        &self,
        batch: StoreBatch,
        mode: WriteMode,
    ) -> Result<(), (Option<Box<StoreBatch>>, StoreError)> {
        let (block_batch, coins_batch) = Self::split_batch(batch);
        // A batch here spans two backing stores and is not atomic across
        // them — it never was; see the ordering note in `write_batch`. So
        // recoverability depends on which half failed.
        //
        // Block half first: nothing has been applied yet, so the two halves
        // can be reassembled and handed back whole.
        if let Err((returned, e)) = self.write_block_half(block_batch) {
            return Err((
                returned.map(|b| Box::new(Self::rejoin(*b, coins_batch))),
                e,
            ));
        }
        // Coins half: the block half is already in, and it must NOT come
        // back for replay — its rows are absolute index/height/txindex
        // puts, and replaying them later could resurrect a status a newer
        // writer has since retired (#322's shape). The coins store's own
        // returned batch is exactly the unapplied remainder: hand that back
        // as-is, and a restore preserves the coins delta (and the tip that
        // rides with it) while the durable block rows stay put. Restoring
        // only the remainder is what the trait contract asks for — see
        // `Store::write_batch_recoverable`.
        self.coins_store.write_batch_recoverable(coins_batch, mode)
    }

    fn flush_durable(&self) -> Result<(), StoreError> {
        // Both halves: the coins store carries the WAL-less (BulkLoad)
        // writes, but the shared block store must honor the same
        // "durable after this returns" contract callers rely on.
        self.block_store.flush_durable()?;
        self.coins_store.flush_durable()
    }

    fn clear_chainstate(&self) -> Result<(), StoreError> {
        // Only the private coins store; never the shared block index.
        self.coins_store.clear_chainstate()
    }

    fn clear_all(&self) -> Result<(), StoreError> {
        // Only the private coins store; the shared block store belongs to
        // the snapshot chainstate and must not be cleared from here.
        self.coins_store.clear_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};
    use crate::storage::coinview::Coin;
    use crate::storage::rocksdb_store::RocksDbStore;
    use bitcoin::hashes::Hash;

    fn store(dir: &std::path::Path) -> Arc<dyn Store> {
        Arc::new(RocksDbStore::open(dir, false, 16, false, -1).unwrap())
    }

    fn outpoint(byte: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32])),
            vout: 0,
        }
    }

    fn coin(amount: u64) -> Coin {
        Coin {
            amount,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            height: 1,
            coinbase: false,
        }
    }

    fn genesis_entry() -> (BlockHash, BlockIndexEntry) {
        let g = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let entry = BlockIndexEntry {
            header: g.header,
            height: 0,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        };
        (g.block_hash(), entry)
    }

    /// The background catch-up thread writes block-index rows into the
    /// *snapshot* chainstate's coin cache, which that chainstate reorgs.
    /// Holding the chainstate's `accept_lock` around the write serializes
    /// it against a reorg's whole window — the write mutates the cache's
    /// shared pending batch on its way through (see `block_store_lock`), so
    /// letting it land mid-reorg would interleave two writers in the one
    /// buffer the rollback reasons about. The unserialized version of this
    /// is the #567 defect shape, on the AssumeUTXO path.
    ///
    /// Proof shape: while the lock is held, the write cannot complete no
    /// matter how far its thread has progressed, because it needs the lock.
    #[test]
    fn a_shared_block_store_write_waits_for_the_chainstates_accept_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let bdir = tempfile::tempdir().unwrap();
        let cdir = tempfile::tempdir().unwrap();
        let block_store = store(bdir.path());
        let coins_store = store(cdir.path());
        let lock = Arc::new(parking_lot::Mutex::new(()));
        let split = SplitStore::new(block_store.clone(), coins_store.clone(), Some(lock.clone()));

        let (hash, entry) = genesis_entry();
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry));

        let done = AtomicBool::new(false);
        std::thread::scope(|s| {
            let guard = lock.lock();
            s.spawn(|| {
                split.write_batch(batch).unwrap();
                done.store(true, Ordering::SeqCst);
            });
            std::thread::sleep(std::time::Duration::from_millis(200));
            assert!(
                !done.load(Ordering::SeqCst),
                "the shared block store was written while the chainstate lock was held"
            );
            assert!(block_store.get_block_index(&hash).is_none());
            drop(guard);
        });

        assert!(done.load(Ordering::SeqCst), "and completes once it is free");
        assert!(block_store.get_block_index(&hash).is_some());
    }

    /// Block half fails first: nothing has been applied anywhere, so the
    /// caller gets the whole batch back, rejoined — both halves, tip
    /// included — and either store reads as untouched.
    #[test]
    fn recoverable_block_half_failure_returns_the_whole_batch() {
        use crate::storage::test_store::ControllableStore;

        let block_store = ControllableStore::new();
        let block_controls = block_store.controls();
        let cdir = tempfile::tempdir().unwrap();
        let split = SplitStore::new(Arc::new(block_store), store(cdir.path()), None);

        let (hash, entry) = genesis_entry();
        let op = outpoint(0x11);
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        batch.coin_puts.push((op, coin(1_000)));
        batch.tip = Some(hash);

        block_controls.fail_next_write();
        let (returned, _e) = split
            .write_batch_recoverable(batch, WriteMode::Normal)
            .expect_err("the injected block-half fault must surface");
        let returned = *returned.expect("nothing was applied, so the batch comes back");
        assert_eq!(returned.block_index_puts.len(), 1, "block half returned");
        assert_eq!(returned.coin_puts.len(), 1, "coins half returned");
        assert_eq!(returned.tip, Some(hash), "tip returned");
        assert!(split.get_block_index(&hash).is_none(), "block store untouched");
        assert!(split.get_coin(&op).is_none(), "coins store untouched");
    }

    /// Coins half fails after the block half landed: the caller gets back
    /// exactly the unapplied remainder — the coins half, tip included, with
    /// the block rows absent — so a restore replays nothing that is already
    /// durable. Returning the full rejoined batch here would re-put block
    /// rows later and could resurrect a status a newer writer retired;
    /// returning `None` (as this once did) needlessly threw the coins delta
    /// away.
    #[test]
    fn recoverable_coins_half_failure_returns_only_the_unapplied_remainder() {
        use crate::storage::test_store::ControllableStore;

        let bdir = tempfile::tempdir().unwrap();
        let coins_store = ControllableStore::new();
        let coins_controls = coins_store.controls();
        let split = SplitStore::new(store(bdir.path()), Arc::new(coins_store), None);

        let (hash, entry) = genesis_entry();
        let op = outpoint(0x12);
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        batch.height_hash_puts.push((0, hash));
        batch.coin_puts.push((op, coin(2_000)));
        batch.tip = Some(hash);

        coins_controls.fail_next_write();
        let (returned, _e) = split
            .write_batch_recoverable(batch, WriteMode::Normal)
            .expect_err("the injected coins-half fault must surface");
        let returned = *returned.expect("the coins half is recoverable");
        assert_eq!(
            returned.block_index_puts.len(),
            0,
            "the applied block half must NOT come back for replay"
        );
        assert_eq!(returned.height_hash_puts.len(), 0, "height rows are block-half");
        assert_eq!(returned.coin_puts.len(), 1, "the unapplied coins half comes back");
        assert_eq!(returned.tip, Some(hash), "the tip rides with the coins half");
        assert!(
            split.get_block_index(&hash).is_some(),
            "the block half landed durably before the fault"
        );
        assert!(split.get_coin(&op).is_none(), "the coins store applied nothing");
    }

    #[test]
    fn write_batch_routes_block_index_to_block_store_and_coins_to_coins_store() {
        let bdir = tempfile::tempdir().unwrap();
        let cdir = tempfile::tempdir().unwrap();
        let block_store = store(bdir.path());
        let coins_store = store(cdir.path());
        let split = SplitStore::new(block_store.clone(), coins_store.clone(), None);

        let (hash, entry) = genesis_entry();
        let op = outpoint(0xAB);

        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        batch.height_hash_puts.push((0, hash));
        batch.coin_puts.push((op, coin(5_000)));
        batch.tip = Some(hash);
        split.write_batch(batch).unwrap();

        // Block index + height→hash landed in the shared block store only.
        assert!(block_store.get_block_index(&hash).is_some());
        assert_eq!(block_store.get_block_hash_by_height(0), Some(hash));
        assert!(coins_store.get_block_index(&hash).is_none());

        // Coins + tip landed in the private coins store only.
        assert!(coins_store.get_coin(&op).is_some());
        assert_eq!(coins_store.get_tip(), Some(hash));
        assert!(block_store.get_coin(&op).is_none());
        assert!(block_store.get_tip().is_none());

        // Reads through the split land on the right side.
        assert!(split.get_block_index(&hash).is_some());
        assert_eq!(split.get_block_hash_by_height(0), Some(hash));
        assert!(split.get_coin(&op).is_some());
        assert_eq!(split.get_tip(), Some(hash));
        assert_eq!(split.coin_count(), coins_store.coin_count());
    }

    /// `flush_durable` must reach BOTH halves. Flushing only the coins
    /// store leaves the shared block store's memtable contents volatile,
    /// breaking the "durable after this returns" contract callers
    /// (IBD completion, reindex, shutdown) rely on.
    #[test]
    fn flush_durable_reaches_both_stores() {
        use crate::storage::db::InMemoryStore;

        let block_store = InMemoryStore::new();
        let coins_store = InMemoryStore::new();
        let block_flushes = block_store.flush_durable_counter();
        let coins_flushes = coins_store.flush_durable_counter();

        let split = SplitStore::new(Arc::new(block_store), Arc::new(coins_store), None);
        split.flush_durable().unwrap();

        assert_eq!(block_flushes.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(coins_flushes.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
