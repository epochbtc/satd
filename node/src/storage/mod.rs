pub mod blockindex;
pub mod coinview;
pub mod db;
pub mod flatfile;

use bitcoin::{BlockHash, OutPoint};

use crate::storage::blockindex::BlockIndexEntry;
use crate::storage::coinview::Coin;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Atomic batch of writes for a single block connection.
#[derive(Default)]
pub struct StoreBatch {
    pub block_index_puts: Vec<(BlockHash, BlockIndexEntry)>,
    pub coin_puts: Vec<(OutPoint, Coin)>,
    pub coin_removes: Vec<OutPoint>,
    pub tip: Option<BlockHash>,
    pub height_hash_puts: Vec<(u32, BlockHash)>,
}

/// Abstract storage backend for block index, UTXO set, and metadata.
pub trait Store: Send + Sync {
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry>;
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin>;
    fn has_coin(&self, outpoint: &OutPoint) -> bool;
    fn get_tip(&self) -> Option<BlockHash>;
    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash>;
    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError>;
}
