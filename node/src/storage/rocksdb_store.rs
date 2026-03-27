use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, Txid};
use rocksdb::{
    BlockBasedOptions, BoundColumnFamily, Cache, ColumnFamilyDescriptor, DBCompressionType,
    DBWithThreadMode, MultiThreaded, Options, WriteBatch,
};
use std::path::Path;
use std::sync::Arc;

use crate::storage::blockindex::BlockIndexEntry;
use crate::storage::coinview::{outpoint_to_key, Coin};
use crate::storage::undo::UndoData;
use crate::storage::{Store, StoreBatch, StoreError};

const CF_BLOCK_INDEX: &str = "block_index";
const CF_COINS: &str = "coins";
const CF_HEIGHT_INDEX: &str = "height_index";
const CF_UNDO: &str = "undo";
const CF_TX_INDEX: &str = "tx_index";
const CF_METADATA: &str = "metadata";

const TIP_KEY: &[u8] = b"tip";
const UTXO_COUNT_KEY: &[u8] = b"utxo_count";
const TOTAL_AMOUNT_KEY: &[u8] = b"total_amount";
const UTXO_HEIGHT_HIST_KEY: &[u8] = b"utxo_height_hist";
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

type DB = DBWithThreadMode<MultiThreaded>;

/// RocksDB storage backend with compression and bloom filters.
pub struct RocksDbStore {
    db: DB,
    txindex_enabled: bool,
    block_cache: Cache,
}

impl RocksDbStore {
    pub fn open(path: &Path, txindex: bool, cache_mb: usize) -> Result<Self, StoreError> {
        let db_path = path.join("chainstate");

        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        // Shared block cache across all column families
        let cache_bytes = cache_mb.max(16) * 1_000_000;
        let block_cache = Cache::new_lru_cache(cache_bytes);

        // DB-level options
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.increase_parallelism((cpus / 2).max(2) as i32);
        db_opts.set_max_background_jobs(6);
        db_opts.set_atomic_flush(true);
        db_opts.set_max_total_wal_size(256 * 1024 * 1024);
        db_opts.set_bytes_per_sync(1024 * 1024);
        db_opts.set_wal_bytes_per_sync(1024 * 1024);

        let compression_per_level = [
            DBCompressionType::None, // L0
            DBCompressionType::None, // L1
            DBCompressionType::Lz4,  // L2
            DBCompressionType::Lz4,  // L3
            DBCompressionType::Lz4,  // L4
            DBCompressionType::Lz4,  // L5
            DBCompressionType::Zstd, // L6
        ];

        // Column family options builder
        let make_cf_opts = |bloom: bool, write_buf_mb: usize| -> Options {
            let mut cf_opts = Options::default();

            let mut table_opts = BlockBasedOptions::default();
            table_opts.set_block_cache(&block_cache);
            table_opts.set_block_size(16 * 1024); // 16 KB for SSD
            table_opts.set_cache_index_and_filter_blocks(true);
            table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
            table_opts.set_format_version(5);

            if bloom {
                table_opts.set_bloom_filter(10.0, false);
                table_opts.set_whole_key_filtering(true);
            }

            cf_opts.set_block_based_table_factory(&table_opts);
            cf_opts.set_write_buffer_size(write_buf_mb * 1024 * 1024);
            cf_opts.set_max_write_buffer_number(3);
            cf_opts.set_level_compaction_dynamic_level_bytes(true);
            cf_opts.set_max_bytes_for_level_base(512 * 1024 * 1024);
            cf_opts.set_target_file_size_base(64 * 1024 * 1024);
            cf_opts.set_compression_per_level(&compression_per_level);
            cf_opts.set_bottommost_compression_type(DBCompressionType::Zstd);

            cf_opts
        };

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_COINS, make_cf_opts(true, 64)),
            ColumnFamilyDescriptor::new(CF_BLOCK_INDEX, make_cf_opts(false, 8)),
            ColumnFamilyDescriptor::new(CF_HEIGHT_INDEX, make_cf_opts(false, 8)),
            ColumnFamilyDescriptor::new(CF_UNDO, make_cf_opts(false, 16)),
            ColumnFamilyDescriptor::new(CF_TX_INDEX, make_cf_opts(false, 16)),
            ColumnFamilyDescriptor::new(CF_METADATA, make_cf_opts(false, 2)),
        ];

        let db = DB::open_cf_descriptors(&db_opts, &db_path, cf_descriptors).map_err(|e| {
            StoreError::Database(format!(
                "Failed to open RocksDB at {}: {}",
                db_path.display(),
                e
            ))
        })?;

        Ok(Self {
            db,
            txindex_enabled: txindex,
            block_cache,
        })
    }

    fn cf(&self, name: &str) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(name)
            .unwrap_or_else(|| panic!("column family '{}' not found", name))
    }

    /// Build column family options for (re)creation.
    fn cf_options(&self, name: &str) -> Options {
        let is_coins = name == CF_COINS;
        let write_buf_mb = match name {
            CF_COINS => 64,
            CF_UNDO | CF_TX_INDEX => 16,
            CF_BLOCK_INDEX | CF_HEIGHT_INDEX => 8,
            _ => 2,
        };

        let compression_per_level = [
            DBCompressionType::None,
            DBCompressionType::None,
            DBCompressionType::Lz4,
            DBCompressionType::Lz4,
            DBCompressionType::Lz4,
            DBCompressionType::Lz4,
            DBCompressionType::Zstd,
        ];

        let mut cf_opts = Options::default();
        let mut table_opts = BlockBasedOptions::default();
        table_opts.set_block_cache(&self.block_cache);
        table_opts.set_block_size(16 * 1024);
        table_opts.set_cache_index_and_filter_blocks(true);
        table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        table_opts.set_format_version(5);
        if is_coins {
            table_opts.set_bloom_filter(10.0, false);
            table_opts.set_whole_key_filtering(true);
        }
        cf_opts.set_block_based_table_factory(&table_opts);
        cf_opts.set_write_buffer_size(write_buf_mb * 1024 * 1024);
        cf_opts.set_max_write_buffer_number(3);
        cf_opts.set_level_compaction_dynamic_level_bytes(true);
        cf_opts.set_max_bytes_for_level_base(512 * 1024 * 1024);
        cf_opts.set_target_file_size_base(64 * 1024 * 1024);
        cf_opts.set_compression_per_level(&compression_per_level);
        cf_opts.set_bottommost_compression_type(DBCompressionType::Zstd);
        cf_opts
    }

    /// O(1) column family clear: drop and recreate with original options.
    fn drop_and_recreate_cf(&self, name: &str) -> Result<(), StoreError> {
        let opts = self.cf_options(name);
        self.db
            .drop_cf(name)
            .map_err(|e| StoreError::Database(format!("drop_cf({}): {}", name, e)))?;
        self.db
            .create_cf(name, &opts)
            .map_err(|e| StoreError::Database(format!("create_cf({}): {}", name, e)))?;
        Ok(())
    }

    fn read_u64_meta(&self, key: &[u8]) -> u64 {
        let cf = self.cf(CF_METADATA);
        self.db
            .get_cf(&cf, key)
            .ok()
            .flatten()
            .map(|v| {
                let bytes: [u8; 8] = v[..].try_into().unwrap_or([0; 8]);
                u64::from_le_bytes(bytes)
            })
            .unwrap_or(0)
    }
}

impl Store for RocksDbStore {
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        let cf = self.cf(CF_BLOCK_INDEX);
        let value = self.db.get_cf(&cf, hash_bytes(hash)).ok()??;
        bincode::deserialize(&value).ok()
    }

    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        let cf = self.cf(CF_COINS);
        let key = outpoint_to_key(outpoint);
        let value = self.db.get_cf(&cf, key).ok()??;
        Coin::deserialize_compact(&value)
    }

    fn has_coin(&self, outpoint: &OutPoint) -> bool {
        let cf = self.cf(CF_COINS);
        let key = outpoint_to_key(outpoint);
        matches!(self.db.get_pinned_cf(&cf, key), Ok(Some(_)))
    }

    fn get_tip(&self) -> Option<BlockHash> {
        let cf = self.cf(CF_METADATA);
        let value = self.db.get_cf(&cf, TIP_KEY).ok()??;
        hash_from_bytes(&value)
    }

    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        let cf = self.cf(CF_HEIGHT_INDEX);
        let key = height.to_le_bytes();
        let value = self.db.get_cf(&cf, key).ok()??;
        hash_from_bytes(&value)
    }

    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        let mut wb = WriteBatch::default();

        let cf_bi = self.cf(CF_BLOCK_INDEX);
        let cf_coins = self.cf(CF_COINS);
        let cf_hi = self.cf(CF_HEIGHT_INDEX);
        let cf_undo = self.cf(CF_UNDO);
        let cf_meta = self.cf(CF_METADATA);

        // Block index
        for (hash, entry) in &batch.block_index_puts {
            let value =
                bincode::serialize(entry).map_err(|e| StoreError::Serialization(e.to_string()))?;
            wb.put_cf(&cf_bi, hash_bytes(hash), &value);
        }

        // Coins with counter tracking
        let mut hist_deltas: std::collections::HashMap<usize, i64> =
            std::collections::HashMap::new();
        let mut count_delta: i64 = 0;
        let mut amount_delta: i64 = 0;

        for (outpoint, spent_amount, spent_height) in &batch.coin_removes {
            let key = outpoint_to_key(outpoint);
            count_delta -= 1;
            amount_delta -= *spent_amount as i64;
            let bucket = (*spent_height / HEIGHT_HIST_BUCKET) as usize;
            *hist_deltas.entry(bucket).or_default() -= 1;
            wb.delete_cf(&cf_coins, key);
        }

        for (outpoint, coin) in &batch.coin_puts {
            let key = outpoint_to_key(outpoint);
            let value = coin.serialize_compact();
            wb.put_cf(&cf_coins, key, &value);
            count_delta += 1;
            amount_delta += coin.amount as i64;
            let bucket = (coin.height / HEIGHT_HIST_BUCKET) as usize;
            *hist_deltas.entry(bucket).or_default() += 1;
        }

        // Height index
        for (height, hash) in &batch.height_hash_puts {
            wb.put_cf(&cf_hi, height.to_le_bytes(), hash_bytes(hash));
        }
        for height in &batch.height_hash_removes {
            wb.delete_cf(&cf_hi, height.to_le_bytes());
        }

        // Undo data
        for (hash, undo) in &batch.undo_puts {
            let value =
                bincode::serialize(undo).map_err(|e| StoreError::Serialization(e.to_string()))?;
            wb.put_cf(&cf_undo, hash_bytes(hash), &value);
        }

        // Tx index
        if self.txindex_enabled
            && (!batch.tx_index_puts.is_empty() || !batch.tx_index_removes.is_empty())
        {
            let cf_txi = self.cf(CF_TX_INDEX);
            for (txid, block_hash) in &batch.tx_index_puts {
                wb.put_cf(&cf_txi, txid_bytes(txid), hash_bytes(block_hash));
            }
            for txid in &batch.tx_index_removes {
                wb.delete_cf(&cf_txi, txid_bytes(txid));
            }
        }

        // Metadata: tip
        if let Some(hash) = &batch.tip {
            wb.put_cf(&cf_meta, TIP_KEY, hash_bytes(hash));
        }

        // Metadata: UTXO height histogram
        if !hist_deltas.is_empty() {
            let mut hist: Vec<u64> = self
                .db
                .get_cf(&cf_meta, UTXO_HEIGHT_HIST_KEY)
                .ok()
                .flatten()
                .and_then(|v| bincode::deserialize(&v).ok())
                .unwrap_or_default();
            for (&bucket, &delta) in &hist_deltas {
                if bucket >= hist.len() {
                    hist.resize(bucket + 1, 0);
                }
                hist[bucket] = (hist[bucket] as i64 + delta).max(0) as u64;
            }
            let hist_bytes = bincode::serialize(&hist)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            wb.put_cf(&cf_meta, UTXO_HEIGHT_HIST_KEY, &hist_bytes);
        }

        // Metadata: UTXO counters
        if count_delta != 0 || amount_delta != 0 {
            let old_count = self.read_u64_meta(UTXO_COUNT_KEY);
            let old_amount = self.read_u64_meta(TOTAL_AMOUNT_KEY);

            let new_count = (old_count as i64 + count_delta) as u64;
            let new_amount = (old_amount as i64 + amount_delta) as u64;

            wb.put_cf(&cf_meta, UTXO_COUNT_KEY, new_count.to_le_bytes());
            wb.put_cf(&cf_meta, TOTAL_AMOUNT_KEY, new_amount.to_le_bytes());
        }

        // Atomic commit across all column families
        self.db
            .write(wb)
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData> {
        let cf = self.cf(CF_UNDO);
        let value = self.db.get_cf(&cf, hash_bytes(hash)).ok()??;
        bincode::deserialize(&value).ok()
    }

    fn coin_count(&self) -> u64 {
        self.read_u64_meta(UTXO_COUNT_KEY)
    }

    fn coin_total_amount(&self) -> u64 {
        self.read_u64_meta(TOTAL_AMOUNT_KEY)
    }

    fn utxo_height_hist(&self) -> Vec<u64> {
        let cf = self.cf(CF_METADATA);
        self.db
            .get_cf(&cf, UTXO_HEIGHT_HIST_KEY)
            .ok()
            .flatten()
            .and_then(|v| bincode::deserialize(&v).ok())
            .unwrap_or_default()
    }

    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash> {
        if !self.txindex_enabled {
            return None;
        }
        let cf = self.cf(CF_TX_INDEX);
        let value = self.db.get_cf(&cf, txid_bytes(txid)).ok()??;
        hash_from_bytes(&value)
    }

    fn has_txindex(&self) -> bool {
        self.txindex_enabled
    }

    fn clear_chainstate(&self) -> Result<(), StoreError> {
        let cfs = if self.txindex_enabled {
            vec![CF_COINS, CF_UNDO, CF_METADATA, CF_TX_INDEX]
        } else {
            vec![CF_COINS, CF_UNDO, CF_METADATA]
        };
        for cf_name in cfs {
            self.drop_and_recreate_cf(cf_name)?;
        }
        Ok(())
    }

    fn clear_all(&self) -> Result<(), StoreError> {
        let all_cfs = [
            CF_BLOCK_INDEX,
            CF_COINS,
            CF_HEIGHT_INDEX,
            CF_UNDO,
            CF_METADATA,
            CF_TX_INDEX,
        ];
        for cf_name in all_cfs {
            self.drop_and_recreate_cf(cf_name)?;
        }
        Ok(())
    }

    fn get_coins_batch(&self, outpoints: &[OutPoint]) -> Vec<Option<Coin>> {
        if outpoints.is_empty() {
            return Vec::new();
        }
        let cf = self.cf(CF_COINS);
        let keys: Vec<[u8; 36]> = outpoints.iter().map(outpoint_to_key).collect();
        // multi_get_cf expects (&impl AsColumnFamilyRef, key) — Arc<BoundCF> impls it
        let cf_keys: Vec<_> = keys.iter().map(|k| (&cf, k.as_slice())).collect();
        self.db
            .multi_get_cf(cf_keys)
            .into_iter()
            .map(|result| {
                result
                    .ok()
                    .flatten()
                    .and_then(|v| Coin::deserialize_compact(&v))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::blockindex::{work_for_bits, BlockIndexEntry, BlockStatus};
    use crate::storage::coinview::Coin;
    use crate::storage::undo::{OutPointSer, UndoData};
    use crate::storage::{Store, StoreBatch};
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;
    use bitcoin::{BlockHash, OutPoint, Txid};

    fn temp_store(txindex: bool) -> (RocksDbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbStore::open(dir.path(), txindex, 16).unwrap();
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
    fn test_block_index_roundtrip() {
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
    fn test_coin_roundtrip() {
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
        batch2.coin_removes.push((op, 5_000_000_000, 1));
        store.write_batch(batch2).unwrap();

        assert!(store.get_coin(&op).is_none());
        assert!(!store.has_coin(&op));
    }

    #[test]
    fn test_tip_roundtrip() {
        let (store, _dir) = temp_store(false);
        let hash = make_block_hash(0x42);

        let batch = StoreBatch {
            tip: Some(hash),
            ..Default::default()
        };
        store.write_batch(batch).unwrap();

        let recovered = store.get_tip().unwrap();
        assert_eq!(recovered, hash);
    }

    #[test]
    fn test_height_index_roundtrip() {
        let (store, _dir) = temp_store(false);
        let hash = make_block_hash(0x11);

        let mut batch = StoreBatch::default();
        batch.height_hash_puts.push((100, hash));
        store.write_batch(batch).unwrap();

        let recovered = store.get_block_hash_by_height(100).unwrap();
        assert_eq!(recovered, hash);

        assert!(store.get_block_hash_by_height(999).is_none());
    }

    #[test]
    fn test_undo_roundtrip() {
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
    fn test_txindex_enabled() {
        let (store, _dir) = temp_store(true);
        assert!(store.has_txindex());

        let txid =
            Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xBB; 32]));
        let block_hash = make_block_hash(0xCC);

        let mut batch = StoreBatch::default();
        batch.tx_index_puts.push((txid, block_hash));
        store.write_batch(batch).unwrap();

        let recovered = store.get_tx_location(&txid).unwrap();
        assert_eq!(recovered, block_hash);
    }

    #[test]
    fn test_txindex_disabled() {
        let (store, _dir) = temp_store(false);
        assert!(!store.has_txindex());

        let txid =
            Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xDD; 32]));
        assert!(store.get_tx_location(&txid).is_none());
    }

    #[test]
    fn test_coin_count() {
        let (store, _dir) = temp_store(false);

        let mut batch = StoreBatch::default();
        for i in 0..3u8 {
            batch
                .coin_puts
                .push((make_outpoint(i + 1, 0), make_coin(1000 * (i as u64 + 1), 0)));
        }
        store.write_batch(batch).unwrap();

        assert_eq!(store.coin_count(), 3);

        let mut batch2 = StoreBatch::default();
        batch2.coin_removes.push((make_outpoint(0x02, 0), 200, 0));
        store.write_batch(batch2).unwrap();

        assert_eq!(store.coin_count(), 2);
    }

    #[test]
    fn test_coin_total_amount() {
        let (store, _dir) = temp_store(false);

        let mut batch = StoreBatch::default();
        batch
            .coin_puts
            .push((make_outpoint(0x01, 0), make_coin(1_000, 0)));
        batch
            .coin_puts
            .push((make_outpoint(0x02, 0), make_coin(2_000, 0)));
        batch
            .coin_puts
            .push((make_outpoint(0x03, 0), make_coin(3_000, 0)));
        store.write_batch(batch).unwrap();

        assert_eq!(store.coin_total_amount(), 6_000);
    }

    #[test]
    fn test_batch_atomicity() {
        let (store, _dir) = temp_store(true);
        let (genesis_hash, genesis_entry) = regtest_genesis_entry();
        let tip_hash = make_block_hash(0xFF);
        let op = make_outpoint(0x10, 0);
        let coin = make_coin(999, 0);
        let txid =
            Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xEE; 32]));

        let mut batch = StoreBatch::default();
        batch
            .block_index_puts
            .push((genesis_hash, genesis_entry.clone()));
        batch.coin_puts.push((op, coin));
        batch.tip = Some(tip_hash);
        batch.height_hash_puts.push((0, genesis_hash));
        batch.tx_index_puts.push((txid, genesis_hash));
        store.write_batch(batch).unwrap();

        assert!(store.get_block_index(&genesis_hash).is_some());
        assert!(store.has_coin(&op));
        assert_eq!(store.get_tip().unwrap(), tip_hash);
        assert_eq!(
            store.get_block_hash_by_height(0).unwrap(),
            genesis_hash
        );
        assert_eq!(store.get_tx_location(&txid).unwrap(), genesis_hash);
    }

    #[test]
    fn test_clear_chainstate() {
        let (store, _dir) = temp_store(true);
        let (hash, entry) = regtest_genesis_entry();
        let op = make_outpoint(0x10, 0);
        let coin = make_coin(999, 0);
        let txid =
            Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xEE; 32]));

        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        batch.coin_puts.push((op, coin));
        batch.tip = Some(hash);
        batch.height_hash_puts.push((0, hash));
        batch.tx_index_puts.push((txid, hash));
        store.write_batch(batch).unwrap();

        store.clear_chainstate().unwrap();

        // Block index and height index preserved
        assert!(store.get_block_index(&hash).is_some());
        assert!(store.get_block_hash_by_height(0).is_some());
        // Chainstate cleared
        assert!(!store.has_coin(&op));
        assert!(store.get_tip().is_none());
        assert!(store.get_tx_location(&txid).is_none());
    }

    #[test]
    fn test_clear_all() {
        let (store, _dir) = temp_store(true);
        let (hash, entry) = regtest_genesis_entry();

        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        batch.tip = Some(hash);
        batch.height_hash_puts.push((0, hash));
        store.write_batch(batch).unwrap();

        store.clear_all().unwrap();

        assert!(store.get_block_index(&hash).is_none());
        assert!(store.get_tip().is_none());
        assert!(store.get_block_hash_by_height(0).is_none());
    }

    #[test]
    fn test_utxo_height_histogram() {
        let (store, _dir) = temp_store(false);

        let mut batch = StoreBatch::default();
        // Coins in bucket 0 (height 0-999) and bucket 1 (height 1000-1999)
        batch
            .coin_puts
            .push((make_outpoint(0x01, 0), make_coin(1_000, 500)));
        batch
            .coin_puts
            .push((make_outpoint(0x02, 0), make_coin(2_000, 999)));
        batch
            .coin_puts
            .push((make_outpoint(0x03, 0), make_coin(3_000, 1500)));
        store.write_batch(batch).unwrap();

        let hist = store.utxo_height_hist();
        assert_eq!(hist[0], 2); // two coins in bucket 0
        assert_eq!(hist[1], 1); // one coin in bucket 1
    }
}
