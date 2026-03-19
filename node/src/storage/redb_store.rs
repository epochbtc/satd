use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, Txid};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;

use crate::storage::blockindex::BlockIndexEntry;
use crate::storage::coinview::{outpoint_to_key, Coin};
use crate::storage::undo::UndoData;
use crate::storage::{Store, StoreBatch, StoreError};

const BLOCK_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("block_index");
const COINS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("coins");
const HEIGHT_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("height_index");
const UNDO: TableDefinition<&[u8], &[u8]> = TableDefinition::new("undo");
const TX_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("tx_index");
const METADATA: TableDefinition<&[u8], &[u8]> = TableDefinition::new("metadata");

const TIP_KEY: &[u8] = b"tip";

fn hash_bytes(hash: &BlockHash) -> &[u8] {
    hash.as_ref()
}

fn hash_from_bytes(bytes: &[u8]) -> Option<BlockHash> {
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Some(BlockHash::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(arr),
    ))
}

fn txid_bytes(txid: &Txid) -> &[u8] {
    txid.as_ref()
}

/// Pure-Rust storage backend using redb (replaces RocksDB).
pub struct RedbStore {
    db: Database,
    txindex_enabled: bool,
}

impl RedbStore {
    pub fn open(path: &Path, txindex: bool) -> Result<Self, StoreError> {
        let db_path = path.join("chainstate.redb");
        let db = Database::create(&db_path).map_err(|e| {
            StoreError::Database(format!(
                "Failed to open redb at {}: {}",
                db_path.display(),
                e
            ))
        })?;

        // Create all tables on first open
        {
            let txn = db
                .begin_write()
                .map_err(|e| StoreError::Database(e.to_string()))?;
            // Opening a table creates it if it doesn't exist
            let _ = txn.open_table(BLOCK_INDEX);
            let _ = txn.open_table(COINS);
            let _ = txn.open_table(HEIGHT_INDEX);
            let _ = txn.open_table(UNDO);
            let _ = txn.open_table(METADATA);
            if txindex {
                let _ = txn.open_table(TX_INDEX);
            }
            txn.commit()
                .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        Ok(Self {
            db,
            txindex_enabled: txindex,
        })
    }
}

impl Store for RedbStore {
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(BLOCK_INDEX).ok()?;
        let value = table.get(hash_bytes(hash)).ok()??;
        bincode::deserialize(value.value()).ok()
    }

    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(COINS).ok()?;
        let key = outpoint_to_key(outpoint);
        let value = table.get(key.as_slice()).ok()??;
        bincode::deserialize(value.value()).ok()
    }

    fn has_coin(&self, outpoint: &OutPoint) -> bool {
        let Ok(txn) = self.db.begin_read() else {
            return false;
        };
        let Ok(table) = txn.open_table(COINS) else {
            return false;
        };
        let key = outpoint_to_key(outpoint);
        matches!(table.get(key.as_slice()), Ok(Some(_)))
    }

    fn get_tip(&self) -> Option<BlockHash> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(METADATA).ok()?;
        let value = table.get(TIP_KEY).ok()??;
        hash_from_bytes(value.value())
    }

    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(HEIGHT_INDEX).ok()?;
        let key = height.to_le_bytes();
        let value = table.get(key.as_slice()).ok()??;
        hash_from_bytes(value.value())
    }

    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Block index
        {
            let mut table = txn
                .open_table(BLOCK_INDEX)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            for (hash, entry) in &batch.block_index_puts {
                let value = bincode::serialize(entry)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                table
                    .insert(hash_bytes(hash), value.as_slice())
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
        }

        // Coins (UTXO set)
        {
            let mut table = txn
                .open_table(COINS)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            for (outpoint, coin) in &batch.coin_puts {
                let key = outpoint_to_key(outpoint);
                let value = bincode::serialize(coin)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                table
                    .insert(key.as_slice(), value.as_slice())
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
            for outpoint in &batch.coin_removes {
                let key = outpoint_to_key(outpoint);
                let _ = table.remove(key.as_slice());
            }
        }

        // Height index
        {
            let mut table = txn
                .open_table(HEIGHT_INDEX)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            for (height, hash) in &batch.height_hash_puts {
                table
                    .insert(height.to_le_bytes().as_slice(), hash_bytes(hash))
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
            for height in &batch.height_hash_removes {
                let _ = table.remove(height.to_le_bytes().as_slice());
            }
        }

        // Undo data
        {
            let mut table = txn
                .open_table(UNDO)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            for (hash, undo) in &batch.undo_puts {
                let value = bincode::serialize(undo)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                table
                    .insert(hash_bytes(hash), value.as_slice())
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
        }

        // Tx index
        if self.txindex_enabled
            && (!batch.tx_index_puts.is_empty() || !batch.tx_index_removes.is_empty())
        {
            let mut table = txn
                .open_table(TX_INDEX)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            for (txid, block_hash) in &batch.tx_index_puts {
                table
                    .insert(txid_bytes(txid), hash_bytes(block_hash))
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
            for txid in &batch.tx_index_removes {
                let _ = table.remove(txid_bytes(txid));
            }
        }

        // Metadata (tip)
        if let Some(hash) = &batch.tip {
            let mut table = txn
                .open_table(METADATA)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            table
                .insert(TIP_KEY, hash_bytes(hash))
                .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        txn.commit()
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(UNDO).ok()?;
        let value = table.get(hash_bytes(hash)).ok()??;
        bincode::deserialize(value.value()).ok()
    }

    fn coin_count(&self) -> u64 {
        let Ok(txn) = self.db.begin_read() else {
            return 0;
        };
        let Ok(table) = txn.open_table(COINS) else {
            return 0;
        };
        let Ok(iter) = table.iter() else {
            return 0;
        };
        iter.count() as u64
    }

    fn coin_total_amount(&self) -> u64 {
        let Ok(txn) = self.db.begin_read() else {
            return 0;
        };
        let Ok(table) = txn.open_table(COINS) else {
            return 0;
        };
        let mut total: u64 = 0;
        let Ok(iter) = table.iter() else {
            return 0;
        };
        for entry in iter {
            if let Ok((_key, value)) = entry
                && let Ok(coin) = bincode::deserialize::<Coin>(value.value()) {
                    total = total.saturating_add(coin.amount);
                }
        }
        total
    }

    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash> {
        if !self.txindex_enabled {
            return None;
        }
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(TX_INDEX).ok()?;
        let value = table.get(txid_bytes(txid)).ok()??;
        hash_from_bytes(value.value())
    }

    fn has_txindex(&self) -> bool {
        self.txindex_enabled
    }
}
