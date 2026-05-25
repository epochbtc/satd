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
}

impl SplitStore {
    pub fn new(block_store: Arc<dyn Store>, coins_store: Arc<dyn Store>) -> Self {
        Self {
            block_store,
            coins_store,
        }
    }

    /// Partition a batch into `(block-store mutations, coins-store
    /// mutations)`. Block-index/height/txindex rows are moved out into
    /// the block batch; everything else (coins, undo, tip — and any
    /// secondary-index rows, which the background never emits because it
    /// runs with those indexes disabled) stays in the original batch and
    /// goes to the coins store.
    fn split_batch(mut batch: StoreBatch) -> (StoreBatch, StoreBatch) {
        let block_batch = StoreBatch {
            block_index_puts: std::mem::take(&mut batch.block_index_puts),
            height_hash_puts: std::mem::take(&mut batch.height_hash_puts),
            height_hash_removes: std::mem::take(&mut batch.height_hash_removes),
            tx_index_puts: std::mem::take(&mut batch.tx_index_puts),
            tx_index_removes: std::mem::take(&mut batch.tx_index_removes),
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

    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash> {
        self.block_store.get_tx_location(txid)
    }

    fn has_txindex(&self) -> bool {
        self.block_store.has_txindex()
    }

    fn for_each_block_index(
        &self,
        visit: &mut dyn FnMut(BlockHash, BlockIndexEntry),
    ) -> Result<BlockIndexScanStats, StoreError> {
        self.block_store.for_each_block_index(visit)
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
        self.block_store.write_batch(block_batch)?;
        self.coins_store.write_batch(coins_batch)?;
        Ok(())
    }

    fn write_batch_mode(&self, batch: StoreBatch, mode: WriteMode) -> Result<(), StoreError> {
        let (block_batch, coins_batch) = Self::split_batch(batch);
        // Block index stays durable; only the heavy coins writes honor
        // BulkLoad during the background catch-up IBD.
        self.block_store.write_batch(block_batch)?;
        self.coins_store.write_batch_mode(coins_batch, mode)?;
        Ok(())
    }

    fn flush_durable(&self) -> Result<(), StoreError> {
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

    #[test]
    fn write_batch_routes_block_index_to_block_store_and_coins_to_coins_store() {
        let bdir = tempfile::tempdir().unwrap();
        let cdir = tempfile::tempdir().unwrap();
        let block_store = store(bdir.path());
        let coins_store = store(cdir.path());
        let split = SplitStore::new(block_store.clone(), coins_store.clone());

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
}
