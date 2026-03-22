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
const UTXO_COUNT_KEY: &[u8] = b"utxo_count";
const TOTAL_AMOUNT_KEY: &[u8] = b"total_amount";
const UTXO_HEIGHT_HIST_KEY: &[u8] = b"utxo_height_hist";
/// Each histogram bucket covers this many blocks.
const HEIGHT_HIST_BUCKET: u32 = 1000;

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

        // Skip the blocking UTXO counter migration on startup.
        // Counters are maintained incrementally during write_batch(),
        // so they'll be accurate for any database that has been through
        // at least one flush. For legacy databases without counters,
        // coin_count/coin_total_amount will return 0 until a manual
        // reindex or the values accumulate from connected blocks.

        Ok(Self {
            db,
            txindex_enabled: txindex,
        })
    }

    /// Initialize UTXO counters by scanning the COINS table if they don't exist yet.
    /// This is a one-time migration for existing databases.
    fn init_utxo_counters(db: &redb::Database) -> Result<(), StoreError> {
        // Check if counters already exist
        {
            let txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
            let table = txn.open_table(METADATA).map_err(|e| StoreError::Database(e.to_string()))?;
            let has_counters = table.get(UTXO_COUNT_KEY).map_err(|e| StoreError::Database(e.to_string()))?.is_some();
            let has_hist = table.get(UTXO_HEIGHT_HIST_KEY).map_err(|e| StoreError::Database(e.to_string()))?.is_some();
            if has_counters && has_hist {
                return Ok(()); // Already initialized
            }
        }

        tracing::info!("Initializing UTXO counters (one-time migration)...");
        let txn = db.begin_read().map_err(|e| StoreError::Database(e.to_string()))?;
        let table = txn.open_table(COINS).map_err(|e| StoreError::Database(e.to_string()))?;
        let iter = table.iter().map_err(|e| StoreError::Database(e.to_string()))?;

        let mut count: u64 = 0;
        let mut total_amount: u64 = 0;
        let mut height_hist: Vec<u64> = Vec::new();
        for (_key, value) in iter.flatten() {
            count += 1;
            if let Ok(coin) = bincode::deserialize::<Coin>(value.value()) {
                total_amount = total_amount.saturating_add(coin.amount);
                let bucket = (coin.height / HEIGHT_HIST_BUCKET) as usize;
                if bucket >= height_hist.len() {
                    height_hist.resize(bucket + 1, 0);
                }
                height_hist[bucket] += 1;
            }
        }
        drop(txn);

        // Write the counters
        let txn = db.begin_write().map_err(|e| StoreError::Database(e.to_string()))?;
        {
            let mut table = txn.open_table(METADATA).map_err(|e| StoreError::Database(e.to_string()))?;
            table.insert(UTXO_COUNT_KEY, count.to_le_bytes().as_slice())
                .map_err(|e| StoreError::Database(e.to_string()))?;
            table.insert(TOTAL_AMOUNT_KEY, total_amount.to_le_bytes().as_slice())
                .map_err(|e| StoreError::Database(e.to_string()))?;
            let hist_bytes = bincode::serialize(&height_hist)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            table.insert(UTXO_HEIGHT_HIST_KEY, hist_bytes.as_slice())
                .map_err(|e| StoreError::Database(e.to_string()))?;
        }
        txn.commit().map_err(|e| StoreError::Database(e.to_string()))?;

        tracing::info!(count, total_amount, buckets = height_hist.len(), "UTXO counters initialized");
        Ok(())
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

        // Coins (UTXO set) with counter tracking
        let mut hist_deltas: std::collections::HashMap<usize, i64> = std::collections::HashMap::new();
        let (count_delta, amount_delta) = {
            let mut table = txn
                .open_table(COINS)
                .map_err(|e| StoreError::Database(e.to_string()))?;
            let mut count_delta: i64 = 0;
            let mut amount_delta: i64 = 0;

            // Process removes
            for (outpoint, spent_amount) in &batch.coin_removes {
                let key = outpoint_to_key(outpoint);
                if let Ok(Some(existing)) = table.remove(key.as_slice()) {
                    count_delta -= 1;
                    amount_delta -= *spent_amount as i64;
                    // Need height for histogram — deserialize only for that
                    if let Ok(coin) = bincode::deserialize::<Coin>(existing.value()) {
                        let bucket = (coin.height / HEIGHT_HIST_BUCKET) as usize;
                        *hist_deltas.entry(bucket).or_default() -= 1;
                    }
                }
            }

            for (outpoint, coin) in &batch.coin_puts {
                let key = outpoint_to_key(outpoint);
                let value = bincode::serialize(coin)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                table
                    .insert(key.as_slice(), value.as_slice())
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                count_delta += 1;
                amount_delta += coin.amount as i64;
                let bucket = (coin.height / HEIGHT_HIST_BUCKET) as usize;
                *hist_deltas.entry(bucket).or_default() += 1;
            }

            (count_delta, amount_delta)
        };

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

        // Metadata (tip + UTXO counters)
        {
            let mut table = txn
                .open_table(METADATA)
                .map_err(|e| StoreError::Database(e.to_string()))?;

            if let Some(hash) = &batch.tip {
                table
                    .insert(TIP_KEY, hash_bytes(hash))
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }

            // Update UTXO height histogram
            if !hist_deltas.is_empty() {
                let mut hist: Vec<u64> = table
                    .get(UTXO_HEIGHT_HIST_KEY)
                    .map_err(|e| StoreError::Database(e.to_string()))?
                    .and_then(|v| bincode::deserialize(v.value()).ok())
                    .unwrap_or_default();
                for (&bucket, &delta) in &hist_deltas {
                    if bucket >= hist.len() {
                        hist.resize(bucket + 1, 0);
                    }
                    hist[bucket] = (hist[bucket] as i64 + delta).max(0) as u64;
                }
                let hist_bytes = bincode::serialize(&hist)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                table
                    .insert(UTXO_HEIGHT_HIST_KEY, hist_bytes.as_slice())
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }

            // Update UTXO counters if any coin operations occurred
            if count_delta != 0 || amount_delta != 0 {
                let old_count = table
                    .get(UTXO_COUNT_KEY)
                    .map_err(|e| StoreError::Database(e.to_string()))?
                    .map(|v| {
                        let bytes: [u8; 8] = v.value().try_into().unwrap_or([0; 8]);
                        u64::from_le_bytes(bytes)
                    })
                    .unwrap_or(0);
                let old_amount = table
                    .get(TOTAL_AMOUNT_KEY)
                    .map_err(|e| StoreError::Database(e.to_string()))?
                    .map(|v| {
                        let bytes: [u8; 8] = v.value().try_into().unwrap_or([0; 8]);
                        u64::from_le_bytes(bytes)
                    })
                    .unwrap_or(0);

                let new_count = (old_count as i64 + count_delta) as u64;
                let new_amount = (old_amount as i64 + amount_delta) as u64;

                table
                    .insert(UTXO_COUNT_KEY, new_count.to_le_bytes().as_slice())
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                table
                    .insert(TOTAL_AMOUNT_KEY, new_amount.to_le_bytes().as_slice())
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
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
        let Ok(table) = txn.open_table(METADATA) else {
            return 0;
        };
        table
            .get(UTXO_COUNT_KEY)
            .ok()
            .flatten()
            .map(|v| {
                let bytes: [u8; 8] = v.value().try_into().unwrap_or([0; 8]);
                u64::from_le_bytes(bytes)
            })
            .unwrap_or(0)
    }

    fn coin_total_amount(&self) -> u64 {
        let Ok(txn) = self.db.begin_read() else {
            return 0;
        };
        let Ok(table) = txn.open_table(METADATA) else {
            return 0;
        };
        table
            .get(TOTAL_AMOUNT_KEY)
            .ok()
            .flatten()
            .map(|v| {
                let bytes: [u8; 8] = v.value().try_into().unwrap_or([0; 8]);
                u64::from_le_bytes(bytes)
            })
            .unwrap_or(0)
    }

    fn utxo_height_hist(&self) -> Vec<u64> {
        let Ok(txn) = self.db.begin_read() else {
            return Vec::new();
        };
        let Ok(table) = txn.open_table(METADATA) else {
            return Vec::new();
        };
        table
            .get(UTXO_HEIGHT_HIST_KEY)
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize(v.value()).ok())
            .unwrap_or_default()
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

    fn clear_chainstate(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(|e| StoreError::Database(e.to_string()))?;
        // Delete and recreate tables to clear all entries
        let _ = txn.delete_table(COINS);
        let _ = txn.delete_table(UNDO);
        let _ = txn.delete_table(METADATA);
        if self.txindex_enabled {
            let _ = txn.delete_table(TX_INDEX);
        }
        // Recreate empty tables
        let _ = txn.open_table(COINS);
        let _ = txn.open_table(UNDO);
        let _ = txn.open_table(METADATA);
        if self.txindex_enabled {
            let _ = txn.open_table(TX_INDEX);
        }
        txn.commit().map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }

    fn clear_all(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(|e| StoreError::Database(e.to_string()))?;
        let _ = txn.delete_table(BLOCK_INDEX);
        let _ = txn.delete_table(HEIGHT_INDEX);
        let _ = txn.delete_table(COINS);
        let _ = txn.delete_table(UNDO);
        let _ = txn.delete_table(METADATA);
        if self.txindex_enabled {
            let _ = txn.delete_table(TX_INDEX);
        }
        // Recreate empty tables
        let _ = txn.open_table(BLOCK_INDEX);
        let _ = txn.open_table(HEIGHT_INDEX);
        let _ = txn.open_table(COINS);
        let _ = txn.open_table(UNDO);
        let _ = txn.open_table(METADATA);
        if self.txindex_enabled {
            let _ = txn.open_table(TX_INDEX);
        }
        txn.commit().map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::blockindex::{BlockIndexEntry, BlockStatus, work_for_bits};
    use crate::storage::coinview::Coin;
    use crate::storage::undo::{OutPointSer, UndoData};
    use crate::storage::{Store, StoreBatch};
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;
    use bitcoin::{BlockHash, OutPoint, Txid};

    fn temp_store(txindex: bool) -> (RedbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbStore::open(dir.path(), txindex).unwrap();
        (store, dir)
    }

    fn regtest_genesis_entry() -> (BlockHash, BlockIndexEntry) {
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let hash = genesis.block_hash();
        let entry = BlockIndexEntry {
            header: genesis.header,
            height: 0,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: work_for_bits(CompactTarget::from_consensus(0x207fffff)),
        };
        (hash, entry)
    }

    fn make_outpoint(txid_byte: u8, vout: u32) -> OutPoint {
        let inner = bitcoin::hashes::sha256d::Hash::from_byte_array([txid_byte; 32]);
        OutPoint {
            txid: Txid::from_raw_hash(inner),
            vout,
        }
    }

    fn make_coin(amount: u64, height: u32) -> Coin {
        Coin {
            amount,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
            height,
            coinbase: false,
        }
    }

    fn make_block_hash(byte: u8) -> BlockHash {
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    #[test]
    fn test_redb_block_index_roundtrip() {
        let (store, _dir) = temp_store(false);
        let (hash, entry) = regtest_genesis_entry();

        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry.clone()));
        store.write_batch(batch).unwrap();

        let recovered = store.get_block_index(&hash).unwrap();
        assert_eq!(recovered.height, entry.height);
        assert_eq!(recovered.num_tx, entry.num_tx);
        assert_eq!(recovered.status, entry.status);
        assert_eq!(recovered.chainwork, entry.chainwork);
        assert_eq!(recovered.header.prev_blockhash, entry.header.prev_blockhash);
    }

    #[test]
    fn test_redb_coin_roundtrip() {
        let (store, _dir) = temp_store(false);
        let op = make_outpoint(0xAA, 0);
        let coin = make_coin(50_000, 1);

        let mut batch = StoreBatch::default();
        batch.coin_puts.push((op, coin.clone()));
        store.write_batch(batch).unwrap();

        let recovered = store.get_coin(&op).unwrap();
        assert_eq!(recovered.amount, coin.amount);
        assert_eq!(recovered.height, coin.height);
        assert!(store.has_coin(&op));

        // Remove the coin
        let mut batch2 = StoreBatch::default();
        batch2.coin_removes.push((op, 5_000_000_000));
        store.write_batch(batch2).unwrap();

        assert!(store.get_coin(&op).is_none());
        assert!(!store.has_coin(&op));
    }

    #[test]
    fn test_redb_tip_roundtrip() {
        let (store, _dir) = temp_store(false);
        let hash = make_block_hash(0x42);

        let batch = StoreBatch { tip: Some(hash), ..Default::default() };
        store.write_batch(batch).unwrap();

        let recovered = store.get_tip().unwrap();
        assert_eq!(recovered, hash);
    }

    #[test]
    fn test_redb_height_index_roundtrip() {
        let (store, _dir) = temp_store(false);
        let hash = make_block_hash(0x11);

        let mut batch = StoreBatch::default();
        batch.height_hash_puts.push((100, hash));
        store.write_batch(batch).unwrap();

        let recovered = store.get_block_hash_by_height(100).unwrap();
        assert_eq!(recovered, hash);

        // Non-existent height returns None
        assert!(store.get_block_hash_by_height(999).is_none());
    }

    #[test]
    fn test_redb_undo_roundtrip() {
        let (store, _dir) = temp_store(false);
        let block_hash = make_block_hash(0x22);
        let op = make_outpoint(0x01, 0);
        let coin = make_coin(1_000_000, 50);
        let undo = UndoData {
            spent_coins: vec![(OutPointSer::from(&op), coin)],
        };

        let mut batch = StoreBatch::default();
        batch.undo_puts.push((block_hash, undo));
        store.write_batch(batch).unwrap();

        let recovered = store.get_undo(&block_hash).unwrap();
        assert_eq!(recovered.spent_coins.len(), 1);
        assert_eq!(recovered.spent_coins[0].1.amount, 1_000_000);
    }

    #[test]
    fn test_redb_txindex_enabled() {
        let (store, _dir) = temp_store(true);
        assert!(store.has_txindex());

        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xBB; 32]));
        let block_hash = make_block_hash(0xCC);

        let mut batch = StoreBatch::default();
        batch.tx_index_puts.push((txid, block_hash));
        store.write_batch(batch).unwrap();

        let recovered = store.get_tx_location(&txid).unwrap();
        assert_eq!(recovered, block_hash);
    }

    #[test]
    fn test_redb_txindex_disabled() {
        let (store, _dir) = temp_store(false);
        assert!(!store.has_txindex());

        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xDD; 32]));
        assert!(store.get_tx_location(&txid).is_none());
    }

    #[test]
    fn test_redb_coin_count() {
        let (store, _dir) = temp_store(false);

        let mut batch = StoreBatch::default();
        for i in 0..3u8 {
            batch.coin_puts.push((make_outpoint(i + 1, 0), make_coin(1000 * (i as u64 + 1), 0)));
        }
        store.write_batch(batch).unwrap();

        assert_eq!(store.coin_count(), 3);

        // Remove one coin
        let mut batch2 = StoreBatch::default();
        batch2.coin_removes.push((make_outpoint(0x02, 0), 200));
        store.write_batch(batch2).unwrap();

        assert_eq!(store.coin_count(), 2);
    }

    #[test]
    fn test_redb_coin_total_amount() {
        let (store, _dir) = temp_store(false);

        let mut batch = StoreBatch::default();
        batch.coin_puts.push((make_outpoint(0x01, 0), make_coin(1_000, 0)));
        batch.coin_puts.push((make_outpoint(0x02, 0), make_coin(2_000, 0)));
        batch.coin_puts.push((make_outpoint(0x03, 0), make_coin(3_000, 0)));
        store.write_batch(batch).unwrap();

        assert_eq!(store.coin_total_amount(), 6_000);
    }

    #[test]
    fn test_redb_batch_atomicity() {
        let (store, _dir) = temp_store(true);
        let (genesis_hash, genesis_entry) = regtest_genesis_entry();
        let tip_hash = make_block_hash(0xFF);
        let op = make_outpoint(0x10, 0);
        let coin = make_coin(999, 0);
        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xEE; 32]));

        // Write everything in one batch
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((genesis_hash, genesis_entry.clone()));
        batch.coin_puts.push((op, coin));
        batch.tip = Some(tip_hash);
        batch.height_hash_puts.push((0, genesis_hash));
        batch.tx_index_puts.push((txid, genesis_hash));
        store.write_batch(batch).unwrap();

        // Verify all operations applied
        assert!(store.get_block_index(&genesis_hash).is_some());
        assert!(store.has_coin(&op));
        assert_eq!(store.get_tip().unwrap(), tip_hash);
        assert_eq!(store.get_block_hash_by_height(0).unwrap(), genesis_hash);
        assert_eq!(store.get_tx_location(&txid).unwrap(), genesis_hash);
    }
}
