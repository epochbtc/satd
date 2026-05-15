//! Offline undo CF prune + format migrator.
//!
//! Two operations in a single pass over the `undo` column family:
//!
//! 1. **Prune.** Drop rows for blocks at height `< prune_below`. The
//!    only consumers of undo data are the disconnect path (bounded by
//!    reorg depth — never anywhere near 2016 blocks) and the BIP 158
//!    filter index backfill (only for blocks it hasn't yet covered).
//!    The caller computes `prune_below` from those two constraints —
//!    see [`UndoMigrateConfig::prune_below`] for the exact recipe.
//!
//! 2. **Migrate.** For non-pruned rows still on disk in the legacy v0
//!    bincode shape (`Vec<(OutPointSer, Coin)>`), decode and re-emit
//!    in v1 ([`crate::storage::undo::UndoData::serialize_v1`]) —
//!    ~60% smaller per row on typical P2WPKH spends. Rows already in
//!    v1 are detected by magic peek and left untouched.
//!
//! ## Safety model
//!
//! - **Offline only.** RocksDB is single-writer; running the migrator
//!   against a live datadir would conflict with the node process.
//!   The sat-cli wrapper enforces this at the binary boundary by
//!   refusing to start when the LOCK file exists.
//! - **Atomic per-batch.** Writes are flushed every
//!   [`UndoMigrateConfig::batch_size`] rows as one `WriteBatch`, so a
//!   crash mid-migration leaves only fully-applied prefixes of work.
//!   The remaining rows are still in v0 and will be picked up by a
//!   re-run.
//! - **Dry-run.** With `dry_run = true`, the migrator walks the CF
//!   and reports stats without writing or deleting anything. This is
//!   the recommended first-touch on a real datadir — projected
//!   bytes-saved come from this read-only pass.
//!
//! ## Returned stats
//!
//! [`UndoMigrateStats`] is the single source of truth for what
//! happened. The sat-cli renderer pretty-prints it; programmatic
//! callers (future ops automation) consume it directly.

use std::collections::HashMap;
use std::time::Instant;

use bitcoin::BlockHash;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};

use crate::storage::rocksdb_store::{
    CF_BLOCK_INDEX, CF_UNDO, RocksDbStore, hash_from_bytes,
};
use crate::storage::undo::UndoData;

#[derive(Debug, Clone, Copy)]
pub struct UndoMigrateConfig {
    /// Drop undo rows whose block height is strictly less than this
    /// value. Setting `prune_below = 0` disables pruning (migrate-
    /// only mode). The caller is responsible for ensuring this value
    /// respects every undo consumer:
    /// `prune_below = min(tip - keep_recent, filter_index_cursor)`.
    pub prune_below: u32,
    /// If `true`, scan-and-report without writing or deleting. Use
    /// this on a real datadir before committing to the change — the
    /// `bytes_after` and per-category counters tell you what the
    /// real run would do.
    pub dry_run: bool,
    /// Maximum rows accumulated in a single `WriteBatch` before
    /// flushing to RocksDB. Larger batches amortize fsync overhead;
    /// smaller batches mean less re-work on crash. 10k rows is a
    /// reasonable default for mainnet-tip migration.
    pub batch_size: usize,
}

impl Default for UndoMigrateConfig {
    fn default() -> Self {
        Self {
            prune_below: 0,
            dry_run: false,
            batch_size: 10_000,
        }
    }
}

/// What happened during the migration pass. All counts are exact;
/// `bytes_before` and `bytes_after` are the sum of value byte
/// lengths read off disk before any conversion, and the byte length
/// of the values we would (or did) write back, respectively.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UndoMigrateStats {
    pub rows_scanned: u64,
    /// Rows whose block height fell below `prune_below`. With
    /// `dry_run = true`, this is the count of rows that *would* be
    /// pruned. Pruned rows do not contribute to `bytes_after`.
    pub rows_pruned: u64,
    /// Rows whose data was rewritten from v0 bincode into v1
    /// compact format. Already-v1 rows are not counted here.
    pub rows_migrated: u64,
    /// Rows whose data was already in v1 format and left untouched.
    pub rows_already_v1: u64,
    /// Rows whose key didn't decode as a 32-byte block hash, or
    /// whose block hash had no entry in `block_index` (orphan undo
    /// from a long-discarded fork, or corruption). These rows are
    /// neither pruned nor rewritten — they sit out the migration
    /// and surface as a non-zero count so the operator can decide.
    pub rows_skipped_unknown_height: u64,
    /// Rows that failed to decode even after dispatching v0/v1.
    /// Left in place; non-zero counts indicate genuine corruption.
    pub rows_decode_failed: u64,
    /// Sum of value bytes for every row we read off disk.
    pub bytes_before: u64,
    /// Sum of value bytes for every row that remains after the run
    /// (rewritten v1 rows count their new size; pruned rows
    /// contribute zero; untouched rows count their existing size).
    pub bytes_after: u64,
    pub duration_ms: u64,
}

impl UndoMigrateStats {
    /// Net bytes reclaimed: `bytes_before - bytes_after`. Useful for
    /// the sat-cli renderer.
    pub fn bytes_reclaimed(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UndoMigrateError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("rocksdb error: {0}")]
    RocksDb(String),
}

/// Run the prune + migrate pass against the open `store`. Returns
/// [`UndoMigrateStats`] describing the outcome. Use `config.dry_run
/// = true` to scan without modifying anything.
pub fn prune_and_migrate_undo(
    store: &RocksDbStore,
    config: UndoMigrateConfig,
) -> Result<UndoMigrateStats, UndoMigrateError> {
    let started = Instant::now();

    // 1. Build hash -> height lookup from block_index. ~1M entries on
    //    mainnet is ~36 MB — cheaper than a get_cf per undo row.
    let heights = load_block_heights(store)?;

    // 2. Walk the undo CF, classify each row, accumulate writes in
    //    batches, flush every `batch_size` rows.
    let mut stats = UndoMigrateStats::default();
    let mut batch = WriteBatch::default();
    let mut batch_rows = 0usize;

    let cf_undo = store.cf(CF_UNDO);
    let iter = store
        .raw_db()
        .iterator_cf(&cf_undo, rocksdb::IteratorMode::Start);

    for item in iter {
        let (key, value) = item.map_err(|e| UndoMigrateError::RocksDb(e.to_string()))?;
        stats.rows_scanned += 1;
        stats.bytes_before += value.len() as u64;

        let Some(hash) = hash_from_bytes(&key) else {
            // Key isn't a 32-byte hash — leave it where it is and
            // surface the count. We don't blindly delete unknown
            // keys; this CF is local state but could in principle
            // contain a future schema we don't recognise.
            stats.rows_skipped_unknown_height += 1;
            stats.bytes_after += value.len() as u64;
            continue;
        };

        let Some(&height) = heights.get(&hash) else {
            // Undo row whose block_index entry is gone (orphan from
            // a long-discarded fork, or partial corruption). Don't
            // touch — keep its bytes counted, surface the count.
            stats.rows_skipped_unknown_height += 1;
            stats.bytes_after += value.len() as u64;
            continue;
        };

        if height < config.prune_below {
            // Past the prune horizon — drop it.
            stats.rows_pruned += 1;
            if !config.dry_run {
                batch.delete_cf(&cf_undo, &key);
                batch_rows += 1;
            }
            continue;
        }

        // In the keep range. Already v1? Leave it alone.
        if value.len() >= crate::storage::undo::V1_MAGIC.len()
            && value[..crate::storage::undo::V1_MAGIC.len()]
                == crate::storage::undo::V1_MAGIC
        {
            stats.rows_already_v1 += 1;
            stats.bytes_after += value.len() as u64;
            continue;
        }

        // v0 row in the keep range — decode and rewrite.
        let decoded = match UndoData::deserialize(&value) {
            Ok(u) => u,
            Err(_) => {
                stats.rows_decode_failed += 1;
                stats.bytes_after += value.len() as u64;
                continue;
            }
        };
        let new_bytes = decoded.serialize_v1();
        stats.bytes_after += new_bytes.len() as u64;
        stats.rows_migrated += 1;
        if !config.dry_run {
            batch.put_cf(&cf_undo, &key, &new_bytes);
            batch_rows += 1;
        }

        if batch_rows >= config.batch_size {
            store
                .raw_db()
                .write(std::mem::take(&mut batch))
                .map_err(|e| UndoMigrateError::RocksDb(e.to_string()))?;
            batch_rows = 0;
        }
    }

    if batch_rows > 0 {
        store
            .raw_db()
            .write(batch)
            .map_err(|e| UndoMigrateError::RocksDb(e.to_string()))?;
    }

    stats.duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    Ok(stats)
}

/// One-pass scan of `block_index` building a hash -> height map for
/// the migrator's per-row height check. Bad rows are surfaced via
/// `BlockIndexScanStats` from the `Store::for_each_block_index`
/// trait method (which the migrator currently doesn't propagate —
/// the migrator's `rows_skipped_unknown_height` already accounts
/// for them via the lookup miss path).
fn load_block_heights(
    store: &RocksDbStore,
) -> Result<HashMap<BlockHash, u32>, UndoMigrateError> {
    let cf = store.cf(CF_BLOCK_INDEX);
    let iter = store
        .raw_db()
        .iterator_cf(&cf, rocksdb::IteratorMode::Start);
    let mut heights: HashMap<BlockHash, u32> = HashMap::new();
    for item in iter {
        let (k, v) = item.map_err(|e| UndoMigrateError::RocksDb(e.to_string()))?;
        let Some(hash) = hash_from_bytes(&k) else {
            continue;
        };
        let Ok(entry) = bincode::deserialize::<crate::storage::blockindex::BlockIndexEntry>(&v)
        else {
            continue;
        };
        heights.insert(hash, entry.height);
    }
    Ok(heights)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Store;
    use crate::storage::StoreBatch;
    use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};
    use crate::storage::coinview::Coin;
    use crate::storage::rocksdb_store::hash_bytes;
    use crate::storage::undo::{OutPointSer, V1_MAGIC};
    use bitcoin::OutPoint;
    use bitcoin::block::Header;
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;
    use bitcoin::{BlockHash, TxMerkleNode};

    fn dummy_header() -> Header {
        Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        }
    }

    fn dummy_entry(height: u32) -> BlockIndexEntry {
        BlockIndexEntry {
            header: dummy_header(),
            height,
            status: BlockStatus::DataStored,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        }
    }

    fn make_hash(n: u8) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(bytes))
    }

    fn make_outpoint(txid_byte: u8, vout: u32) -> OutPoint {
        let inner = bitcoin::hashes::sha256d::Hash::from_byte_array([txid_byte; 32]);
        OutPoint {
            txid: bitcoin::Txid::from_raw_hash(inner),
            vout,
        }
    }

    fn make_coin(amount: u64, height: u32) -> Coin {
        Coin {
            amount,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x00, 0x14, 0xab, 0xab]),
            height,
            coinbase: false,
        }
    }

    fn open_store(dir: &std::path::Path) -> RocksDbStore {
        RocksDbStore::open(dir, false, 16, false, -1).unwrap()
    }

    /// Helper: write a v0 (legacy bincode) undo row directly into the
    /// CF, bypassing the store's write_batch (which now always emits
    /// v1). Lets us populate test fixtures matching what's on disk
    /// pre-migration.
    fn put_v0_undo(store: &RocksDbStore, block_hash: BlockHash, spents: Vec<(OutPoint, Coin)>) {
        #[derive(serde::Serialize)]
        struct V0Wire {
            spent_coins: Vec<(OutPointSer, Coin)>,
        }
        let wire = V0Wire {
            spent_coins: spents
                .into_iter()
                .map(|(op, c)| (OutPointSer::from(&op), c))
                .collect(),
        };
        let bytes = bincode::serialize(&wire).unwrap();
        let cf = store.cf(CF_UNDO);
        store
            .raw_db()
            .put_cf(&cf, hash_bytes(&block_hash), &bytes)
            .unwrap();
    }

    #[test]
    fn migrate_v0_to_v1_in_keep_range() {
        // A v0 undo row whose height is >= prune_below must be
        // rewritten in place to v1 format. Verify the row is still
        // readable after migration AND that the on-disk value starts
        // with V1_MAGIC.
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(tmp.path());

        let hash = make_hash(1);
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, dummy_entry(100)));
        store.write_batch(batch).unwrap();
        put_v0_undo(
            &store,
            hash,
            vec![(make_outpoint(0xA1, 0), make_coin(1_000, 50))],
        );

        let stats = prune_and_migrate_undo(
            &store,
            UndoMigrateConfig {
                prune_below: 50, // height 100 > 50, stays
                dry_run: false,
                batch_size: 1,
            },
        )
        .unwrap();
        assert_eq!(stats.rows_scanned, 1);
        assert_eq!(stats.rows_migrated, 1);
        assert_eq!(stats.rows_pruned, 0);
        assert_eq!(stats.rows_already_v1, 0);
        assert!(stats.bytes_after < stats.bytes_before, "v1 should be smaller");

        // Verify on-disk shape is v1 now.
        let cf = store.cf(CF_UNDO);
        let raw = store
            .raw_db()
            .get_cf(&cf, hash_bytes(&hash))
            .unwrap()
            .unwrap();
        assert_eq!(&raw[..V1_MAGIC.len()], &V1_MAGIC);

        // Decoded payload still recovers the same coin.
        let recovered = store.get_undo(&hash).unwrap();
        assert_eq!(recovered.spent_coins.len(), 1);
        assert_eq!(recovered.spent_coins[0].amount, 1_000);
    }

    #[test]
    fn prune_old_undo_below_horizon() {
        // A v0 undo row whose block height < prune_below must be
        // deleted outright.
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(tmp.path());

        let hash = make_hash(2);
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, dummy_entry(10)));
        store.write_batch(batch).unwrap();
        put_v0_undo(
            &store,
            hash,
            vec![(make_outpoint(0xB2, 0), make_coin(5_000, 5))],
        );

        let stats = prune_and_migrate_undo(
            &store,
            UndoMigrateConfig {
                prune_below: 100, // height 10 < 100, prune
                dry_run: false,
                batch_size: 1,
            },
        )
        .unwrap();
        assert_eq!(stats.rows_pruned, 1);
        assert_eq!(stats.rows_migrated, 0);
        assert_eq!(stats.bytes_after, 0, "pruned row contributes 0 to bytes_after");
        assert!(store.get_undo(&hash).is_none());
    }

    #[test]
    fn already_v1_rows_left_untouched() {
        // An undo row already in v1 format (i.e. written by the
        // post-PR-195 code path) must not be re-encoded or counted
        // as migrated.
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(tmp.path());

        let hash = make_hash(3);
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, dummy_entry(200)));
        let undo = UndoData {
            spent_coins: vec![make_coin(9_999, 199)],
        };
        // write_batch emits v1 since PR 195.
        batch.undo_puts.push((hash, undo.clone()));
        store.write_batch(batch).unwrap();

        // Snapshot the on-disk bytes so we can compare post-migrate.
        let cf = store.cf(CF_UNDO);
        let before = store
            .raw_db()
            .get_cf(&cf, hash_bytes(&hash))
            .unwrap()
            .unwrap();

        let stats = prune_and_migrate_undo(
            &store,
            UndoMigrateConfig {
                prune_below: 100,
                dry_run: false,
                batch_size: 1,
            },
        )
        .unwrap();
        assert_eq!(stats.rows_already_v1, 1);
        assert_eq!(stats.rows_migrated, 0);
        assert_eq!(stats.rows_pruned, 0);

        let after = store
            .raw_db()
            .get_cf(&cf, hash_bytes(&hash))
            .unwrap()
            .unwrap();
        assert_eq!(before, after, "v1 row must be byte-for-byte identical after migrate");
    }

    #[test]
    fn dry_run_does_not_write() {
        // With dry_run = true, the migrator reports stats but the CF
        // is unchanged. Verify by snapshotting the row's value before
        // and after.
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(tmp.path());

        let keep_hash = make_hash(4);
        let prune_hash = make_hash(5);
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((keep_hash, dummy_entry(500)));
        batch.block_index_puts.push((prune_hash, dummy_entry(10)));
        store.write_batch(batch).unwrap();
        put_v0_undo(
            &store,
            keep_hash,
            vec![(make_outpoint(0xC1, 0), make_coin(1, 1))],
        );
        put_v0_undo(
            &store,
            prune_hash,
            vec![(make_outpoint(0xC2, 0), make_coin(2, 2))],
        );

        let cf = store.cf(CF_UNDO);
        let keep_before = store
            .raw_db()
            .get_cf(&cf, hash_bytes(&keep_hash))
            .unwrap()
            .unwrap();
        let prune_before_present = store
            .raw_db()
            .get_cf(&cf, hash_bytes(&prune_hash))
            .unwrap()
            .is_some();

        let stats = prune_and_migrate_undo(
            &store,
            UndoMigrateConfig {
                prune_below: 100,
                dry_run: true,
                batch_size: 1,
            },
        )
        .unwrap();
        assert_eq!(stats.rows_pruned, 1);
        assert_eq!(stats.rows_migrated, 1);

        // CF must be unchanged.
        let keep_after = store
            .raw_db()
            .get_cf(&cf, hash_bytes(&keep_hash))
            .unwrap()
            .unwrap();
        let prune_after_present = store
            .raw_db()
            .get_cf(&cf, hash_bytes(&prune_hash))
            .unwrap()
            .is_some();
        assert_eq!(keep_before, keep_after, "dry-run must not rewrite kept rows");
        assert_eq!(
            prune_before_present, prune_after_present,
            "dry-run must not delete pruned rows",
        );
    }

    #[test]
    fn skipped_when_block_index_missing() {
        // An undo row whose block hash has no entry in block_index
        // (orphan from a long-discarded fork) must not be touched —
        // we surface it via rows_skipped_unknown_height instead of
        // pruning or rewriting blindly.
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(tmp.path());

        let orphan_hash = make_hash(6);
        // No block_index entry; just an undo row.
        put_v0_undo(
            &store,
            orphan_hash,
            vec![(make_outpoint(0xD1, 0), make_coin(7, 7))],
        );

        let stats = prune_and_migrate_undo(
            &store,
            UndoMigrateConfig {
                prune_below: 100,
                dry_run: false,
                batch_size: 1,
            },
        )
        .unwrap();
        assert_eq!(stats.rows_skipped_unknown_height, 1);
        assert_eq!(stats.rows_pruned, 0);
        assert_eq!(stats.rows_migrated, 0);
        // Row must still be present and readable.
        let recovered = store.get_undo(&orphan_hash).unwrap();
        assert_eq!(recovered.spent_coins.len(), 1);
    }

    #[test]
    fn batch_size_does_not_change_outcome() {
        // Run twice with different batch_size against equivalent
        // starting state — final CF content must match. Validates
        // that batch boundaries don't drop or duplicate rows.
        let make_fixture = || {
            let tmp = tempfile::tempdir().unwrap();
            let store = open_store(tmp.path());
            let mut batch = StoreBatch::default();
            for i in 0..50u8 {
                let h = make_hash(i);
                batch.block_index_puts.push((h, dummy_entry(100 + i as u32)));
            }
            store.write_batch(batch).unwrap();
            for i in 0..50u8 {
                let h = make_hash(i);
                put_v0_undo(
                    &store,
                    h,
                    vec![(make_outpoint(i, 0), make_coin(1000 + i as u64, 50))],
                );
            }
            (store, tmp)
        };

        let (store_a, _t_a) = make_fixture();
        let stats_a = prune_and_migrate_undo(
            &store_a,
            UndoMigrateConfig {
                prune_below: 120,
                dry_run: false,
                batch_size: 3,
            },
        )
        .unwrap();

        let (store_b, _t_b) = make_fixture();
        let stats_b = prune_and_migrate_undo(
            &store_b,
            UndoMigrateConfig {
                prune_below: 120,
                dry_run: false,
                batch_size: 1000,
            },
        )
        .unwrap();

        assert_eq!(stats_a.rows_scanned, stats_b.rows_scanned);
        assert_eq!(stats_a.rows_pruned, stats_b.rows_pruned);
        assert_eq!(stats_a.rows_migrated, stats_b.rows_migrated);

        // Cross-check final state: every kept hash decodes to the
        // same content under both batch sizes.
        for i in 0..50u8 {
            let h = make_hash(i);
            let a = store_a.get_undo(&h);
            let b = store_b.get_undo(&h);
            assert_eq!(
                a.is_some(),
                b.is_some(),
                "presence mismatch for hash byte {}",
                i,
            );
            if let (Some(a), Some(b)) = (a, b) {
                assert_eq!(a, b, "decoded content mismatch for hash byte {}", i);
            }
        }
    }
}
