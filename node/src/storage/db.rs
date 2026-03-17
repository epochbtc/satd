use bitcoin::{BlockHash, OutPoint};
use bitcoin::hashes::Hash;
use std::path::Path;

use crate::storage::blockindex::BlockIndexEntry;
use crate::storage::coinview::{outpoint_to_key, Coin};
use crate::storage::undo::UndoData;
use crate::storage::{Store, StoreBatch, StoreError};

const CF_BLOCK_INDEX: &str = "block_index";
const CF_COINS: &str = "coins";
const CF_HEIGHT_INDEX: &str = "height_index";
const CF_UNDO: &str = "undo";

fn block_hash_to_bytes(hash: &BlockHash) -> &[u8] {
    hash.as_ref()
}

fn block_hash_from_bytes(bytes: &[u8]) -> Option<BlockHash> {
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let inner = bitcoin::hashes::sha256d::Hash::from_byte_array(arr);
    Some(BlockHash::from_raw_hash(inner))
}

/// RocksDB-backed storage for block index, UTXO set, and metadata.
pub struct RocksDbStore {
    db: rocksdb::DB,
}

impl RocksDbStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_descriptors = vec![
            rocksdb::ColumnFamilyDescriptor::new("default", rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_BLOCK_INDEX, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_COINS, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_HEIGHT_INDEX, rocksdb::Options::default()),
            rocksdb::ColumnFamilyDescriptor::new(CF_UNDO, rocksdb::Options::default()),
        ];

        let db =
            rocksdb::DB::open_cf_descriptors(&opts, path, cf_descriptors).map_err(|e| {
                StoreError::Database(format!("Failed to open RocksDB at {}: {}", path.display(), e))
            })?;

        Ok(Self { db })
    }
}

impl Store for RocksDbStore {
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        let cf = self.db.cf_handle(CF_BLOCK_INDEX)?;
        let value = self.db.get_cf(&cf, block_hash_to_bytes(hash)).ok()??;
        bincode::deserialize(&value).ok()
    }

    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        let cf = self.db.cf_handle(CF_COINS)?;
        let key = outpoint_to_key(outpoint);
        let value = self.db.get_cf(&cf, &key).ok()??;
        bincode::deserialize(&value).ok()
    }

    fn has_coin(&self, outpoint: &OutPoint) -> bool {
        self.get_coin(outpoint).is_some()
    }

    fn get_tip(&self) -> Option<BlockHash> {
        let value = self.db.get(b"tip").ok()??;
        block_hash_from_bytes(&value)
    }

    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        let cf = self.db.cf_handle(CF_HEIGHT_INDEX)?;
        let key = height.to_le_bytes();
        let value = self.db.get_cf(&cf, key).ok()??;
        block_hash_from_bytes(&value)
    }

    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        let mut wb = rocksdb::WriteBatch::default();

        if let Some(cf) = self.db.cf_handle(CF_BLOCK_INDEX) {
            for (hash, entry) in &batch.block_index_puts {
                let value = bincode::serialize(entry)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                wb.put_cf(&cf, block_hash_to_bytes(hash), &value);
            }
        }

        if let Some(cf) = self.db.cf_handle(CF_COINS) {
            for (outpoint, coin) in &batch.coin_puts {
                let key = outpoint_to_key(outpoint);
                let value = bincode::serialize(coin)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                wb.put_cf(&cf, &key, &value);
            }
            for outpoint in &batch.coin_removes {
                let key = outpoint_to_key(outpoint);
                wb.delete_cf(&cf, &key);
            }
        }

        if let Some(cf) = self.db.cf_handle(CF_HEIGHT_INDEX) {
            for (height, hash) in &batch.height_hash_puts {
                wb.put_cf(&cf, height.to_le_bytes(), block_hash_to_bytes(hash));
            }
            for height in &batch.height_hash_removes {
                wb.delete_cf(&cf, height.to_le_bytes());
            }
        }

        if let Some(cf) = self.db.cf_handle(CF_UNDO) {
            for (hash, undo) in &batch.undo_puts {
                let value = bincode::serialize(undo)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                wb.put_cf(&cf, block_hash_to_bytes(hash), &value);
            }
        }

        if let Some(hash) = &batch.tip {
            wb.put(b"tip", block_hash_to_bytes(hash));
        }

        self.db
            .write(wb)
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData> {
        let cf = self.db.cf_handle(CF_UNDO)?;
        let value = self.db.get_cf(&cf, block_hash_to_bytes(hash)).ok()??;
        bincode::deserialize(&value).ok()
    }

    fn coin_count(&self) -> u64 {
        let cf = match self.db.cf_handle(CF_COINS) {
            Some(cf) => cf,
            None => return 0,
        };
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        iter.count() as u64
    }

    fn coin_total_amount(&self) -> u64 {
        let cf = match self.db.cf_handle(CF_COINS) {
            Some(cf) => cf,
            None => return 0,
        };
        let mut total: u64 = 0;
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            if let Ok((_key, value)) = item {
                if let Ok(coin) = bincode::deserialize::<Coin>(&value) {
                    total = total.saturating_add(coin.amount);
                }
            }
        }
        total
    }
}

/// In-memory storage backend for testing.
pub struct InMemoryStore {
    block_index:
        std::sync::RwLock<std::collections::HashMap<BlockHash, BlockIndexEntry>>,
    coins: std::sync::RwLock<std::collections::HashMap<OutPoint, Coin>>,
    tip: std::sync::RwLock<Option<BlockHash>>,
    height_index: std::sync::RwLock<std::collections::HashMap<u32, BlockHash>>,
    undo: std::sync::RwLock<std::collections::HashMap<BlockHash, UndoData>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            block_index: std::sync::RwLock::new(std::collections::HashMap::new()),
            coins: std::sync::RwLock::new(std::collections::HashMap::new()),
            tip: std::sync::RwLock::new(None),
            height_index: std::sync::RwLock::new(std::collections::HashMap::new()),
            undo: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Store for InMemoryStore {
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        self.block_index.read().unwrap().get(hash).cloned()
    }

    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.coins.read().unwrap().get(outpoint).cloned()
    }

    fn has_coin(&self, outpoint: &OutPoint) -> bool {
        self.coins.read().unwrap().contains_key(outpoint)
    }

    fn get_tip(&self) -> Option<BlockHash> {
        *self.tip.read().unwrap()
    }

    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        self.height_index.read().unwrap().get(&height).copied()
    }

    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        let mut bi = self.block_index.write().unwrap();
        let mut coins = self.coins.write().unwrap();
        let mut tip = self.tip.write().unwrap();
        let mut hi = self.height_index.write().unwrap();
        let mut undo = self.undo.write().unwrap();

        for (hash, entry) in batch.block_index_puts {
            bi.insert(hash, entry);
        }
        for (outpoint, coin) in batch.coin_puts {
            coins.insert(outpoint, coin);
        }
        for outpoint in batch.coin_removes {
            coins.remove(&outpoint);
        }
        if let Some(hash) = batch.tip {
            *tip = Some(hash);
        }
        for (height, hash) in batch.height_hash_puts {
            hi.insert(height, hash);
        }
        for height in batch.height_hash_removes {
            hi.remove(&height);
        }
        for (hash, data) in batch.undo_puts {
            undo.insert(hash, data);
        }

        Ok(())
    }

    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData> {
        self.undo.read().unwrap().get(hash).cloned()
    }

    fn coin_count(&self) -> u64 {
        self.coins.read().unwrap().len() as u64
    }

    fn coin_total_amount(&self) -> u64 {
        self.coins
            .read()
            .unwrap()
            .values()
            .map(|c| c.amount)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::blockindex::{BlockStatus, work_for_bits};
    use bitcoin::pow::CompactTarget;

    fn make_test_entry() -> BlockIndexEntry {
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        BlockIndexEntry {
            header: genesis.header,
            height: 0,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: work_for_bits(CompactTarget::from_consensus(0x207fffff)),
        }
    }

    #[test]
    fn test_inmemory_block_index_roundtrip() {
        let store = InMemoryStore::new();
        let entry = make_test_entry();
        let hash = entry.header.block_hash();

        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry.clone()));
        batch.tip = Some(hash);
        batch.height_hash_puts.push((0, hash));
        store.write_batch(batch).unwrap();

        assert_eq!(store.get_tip().unwrap(), hash);
        let recovered = store.get_block_index(&hash).unwrap();
        assert_eq!(recovered.height, 0);
        assert_eq!(store.get_block_hash_by_height(0).unwrap(), hash);
    }

    #[test]
    fn test_inmemory_coin_roundtrip() {
        let store = InMemoryStore::new();
        let outpoint = OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0x42; 32]),
            ),
            vout: 0,
        };
        let coin = Coin {
            amount: 5_000_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: true,
        };

        let mut batch = StoreBatch::default();
        batch.coin_puts.push((outpoint, coin.clone()));
        store.write_batch(batch).unwrap();

        assert!(store.has_coin(&outpoint));
        let recovered = store.get_coin(&outpoint).unwrap();
        assert_eq!(recovered.amount, 5_000_000_000);

        // Remove
        let mut batch2 = StoreBatch::default();
        batch2.coin_removes.push(outpoint);
        store.write_batch(batch2).unwrap();
        assert!(!store.has_coin(&outpoint));
    }
}
