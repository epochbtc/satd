pub mod blockindex;
pub mod coin_cache;
pub mod coinview;
pub mod db;
pub mod flatfile;
pub mod rocksdb_store;
pub mod undo;

use bitcoin::{BlockHash, OutPoint, Txid};

use crate::index::address::{
    AddrFundingKey, AddrFundingRow, AddrSpendingKey, AddrSpendingRow,
};
use crate::storage::blockindex::BlockIndexEntry;
use crate::storage::coinview::Coin;
use crate::storage::undo::UndoData;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Atomic batch of writes for a single block connection/disconnection.
#[derive(Default)]
pub struct StoreBatch {
    pub block_index_puts: Vec<(BlockHash, BlockIndexEntry)>,
    pub coin_puts: Vec<(OutPoint, Coin)>,
    /// (outpoint, spent_amount, spent_height) — carried for O(1) counter/histogram updates.
    pub coin_removes: Vec<(OutPoint, u64, u32)>,
    pub tip: Option<BlockHash>,
    pub height_hash_puts: Vec<(u32, BlockHash)>,
    pub height_hash_removes: Vec<u32>,
    pub undo_puts: Vec<(BlockHash, UndoData)>,
    pub tx_index_puts: Vec<(Txid, BlockHash)>,
    pub tx_index_removes: Vec<Txid>,
    /// Address-history index funding rows. Populated in M2.
    pub addr_funding_puts: Vec<AddrFundingRow>,
    /// Address-history index spending rows. Populated in M2.
    pub addr_spending_puts: Vec<AddrSpendingRow>,
    /// Address-history funding keys to remove (used by `disconnect_block`).
    pub addr_funding_removes: Vec<AddrFundingKey>,
    /// Address-history spending keys to remove (used by `disconnect_block`).
    pub addr_spending_removes: Vec<AddrSpendingKey>,
}

impl StoreBatch {
    /// Merge another batch into this one (for atomic multi-block operations).
    pub fn merge(&mut self, other: StoreBatch) {
        self.block_index_puts.extend(other.block_index_puts);
        self.coin_puts.extend(other.coin_puts);
        self.coin_removes.extend(other.coin_removes);
        if other.tip.is_some() {
            self.tip = other.tip;
        }
        self.height_hash_puts.extend(other.height_hash_puts);
        self.height_hash_removes.extend(other.height_hash_removes);
        self.undo_puts.extend(other.undo_puts);
        self.tx_index_puts.extend(other.tx_index_puts);
        self.tx_index_removes.extend(other.tx_index_removes);
        self.addr_funding_puts.extend(other.addr_funding_puts);
        self.addr_spending_puts.extend(other.addr_spending_puts);
        self.addr_funding_removes.extend(other.addr_funding_removes);
        self.addr_spending_removes.extend(other.addr_spending_removes);
    }
}

/// Write-durability mode for `Store::write_batch`.
///
/// `Normal` is the safe default: writes go through the WAL so a crash
/// recovers to the last committed write. `BulkLoad` disables the WAL
/// for IBD, trading some crash-recovery latency for ~20-50% less write
/// I/O during the sync. A `Store::flush()` must be called periodically
/// in this mode (and before switching back to `Normal`) to bound the
/// amount of work replayed after a crash.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum WriteMode {
    #[default]
    Normal,
    BulkLoad,
}

/// Abstract storage backend for block index, UTXO set, and metadata.
pub trait Store: Send + Sync {
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry>;
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin>;
    fn has_coin(&self, outpoint: &OutPoint) -> bool;
    fn get_tip(&self) -> Option<BlockHash>;
    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash>;
    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError>;
    /// Write with the given durability mode. Default delegates to
    /// `write_batch` (ignoring the mode) — concrete backends that can honor
    /// `BulkLoad` should override.
    fn write_batch_mode(&self, batch: StoreBatch, _mode: WriteMode) -> Result<(), StoreError> {
        self.write_batch(batch)
    }
    /// Force any in-memory state to durable storage. Used after a run of
    /// `BulkLoad` writes to ensure crash recovery is bounded.
    /// Default: no-op (in-memory or always-synchronous backends).
    fn flush_durable(&self) -> Result<(), StoreError> {
        Ok(())
    }
    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData>;
    fn coin_count(&self) -> u64;
    /// Sum the total amount (in satoshis) across all UTXOs.
    fn coin_total_amount(&self) -> u64;
    /// UTXO creation height histogram. Each element is the count of UTXOs created
    /// in a 1000-block range: index 0 = heights 0-999, index 1 = 1000-1999, etc.
    fn utxo_height_hist(&self) -> Vec<u64>;
    /// Look up which block contains a transaction (txindex).
    /// Returns None if txindex is disabled or the txid is not found.
    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash>;
    /// Whether this store has txindex enabled.
    fn has_txindex(&self) -> bool;
    /// Clear UTXO set, undo data, tx index, and tip. Keep block index intact.
    /// Used by `-reindex-chainstate`.
    fn clear_chainstate(&self) -> Result<(), StoreError>;
    /// Clear everything: block index, UTXO set, undo data, tx index, height index, tip.
    /// Used by `-reindex`.
    fn clear_all(&self) -> Result<(), StoreError>;

    /// Batch lookup of multiple coins. Default implementation calls get_coin() in a loop.
    /// RocksDB overrides with multi_get_cf() for significantly better I/O scheduling.
    fn get_coins_batch(&self, outpoints: &[OutPoint]) -> Vec<Option<Coin>> {
        outpoints.iter().map(|op| self.get_coin(op)).collect()
    }

    /// Live-resize the block cache (e.g. RocksDB's shared LRU). Called by
    /// the adaptive-dbcache controller. Default: no-op for backends without
    /// a resizable cache.
    fn resize_block_cache(&self, _bytes: usize) {}

    /// Current block-cache capacity in bytes if observable. Default: 0.
    fn block_cache_capacity_bytes(&self) -> usize {
        0
    }
}
