pub mod blockindex;
pub mod coin_cache;
pub mod coinview;
pub mod db;
pub mod flatfile;
pub mod redb_store;
pub mod undo;

use bitcoin::{BlockHash, OutPoint, Txid};

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
    pub coin_removes: Vec<OutPoint>,
    pub tip: Option<BlockHash>,
    pub height_hash_puts: Vec<(u32, BlockHash)>,
    pub height_hash_removes: Vec<u32>,
    pub undo_puts: Vec<(BlockHash, UndoData)>,
    pub tx_index_puts: Vec<(Txid, BlockHash)>,
    pub tx_index_removes: Vec<Txid>,
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
    }
}

/// Abstract storage backend for block index, UTXO set, and metadata.
pub trait Store: Send + Sync {
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry>;
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin>;
    fn has_coin(&self, outpoint: &OutPoint) -> bool;
    fn get_tip(&self) -> Option<BlockHash>;
    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash>;
    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError>;
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
}
