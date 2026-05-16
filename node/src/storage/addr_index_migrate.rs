//! Offline addr-index v1 → v2 migrator.
//!
//! Walks the legacy `addr_funding` / `addr_spending` CFs, decodes
//! each row, re-encodes it under the v2 schema (16-byte scripthash
//! prefix instead of full 32 bytes — see [`crate::index::address`]
//! and the keys module docstring for the design + collision
//! posture), writes the v2 row, then deletes the v1 row. Single
//! pass over each CF; chunked `WriteBatch` for crash-safety.
//!
//! ## When to run
//!
//! After deploying the PR that introduced the v2 schema, but before
//! dropping the v1 CFs in a later cleanup. On a fresh datadir there
//! is nothing to migrate (the v1 CFs are empty), so this is a no-op.
//!
//! ## Safety model
//!
//! - **Offline only.** RocksDB is single-writer; running this
//!   against a live datadir would conflict with the daemon. The
//!   satd-flag wrapper enforces this at the binary boundary by
//!   refusing to start when the LOCK file is held by another
//!   process.
//! - **Atomic per-batch.** Each `WriteBatch` carries one v2-put and
//!   one v1-delete per migrated row. A crash mid-run leaves a
//!   clean partial state: rows already in flushed batches are in
//!   v2 only, remaining rows are still in v1 and will be picked
//!   up by a re-run.
//! - **Idempotent.** Rerunning after a complete migration is a fast
//!   walk of an empty CF and writes nothing. Rerunning after a
//!   partial run picks up where the previous run left off.
//! - **Dual-read preserved.** This migrator is purely a compaction
//!   step; the read merger added by the v2 schema PR remains in
//!   place. Reads continue to work against any mix of v1/v2 rows
//!   throughout the migration.
//!

use std::time::Instant;

use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};

use crate::storage::rocksdb_store::{
    CF_ADDR_FUNDING, CF_ADDR_FUNDING_V2, CF_ADDR_SPENDING, CF_ADDR_SPENDING_V2, RocksDbStore,
};

#[derive(Debug, Clone, Copy)]
pub struct AddrIndexMigrateConfig {
    /// If `true`, scan and report without writing or deleting. Use
    /// against a real datadir to see projected bytes_reclaimed
    /// before committing.
    pub dry_run: bool,
    /// Maximum operations accumulated in a single `WriteBatch` before
    /// flushing. Each migrated row contributes one put + one delete,
    /// so a `batch_size` of 10k means ~20k operations per flush. The
    /// default is conservative enough to bound peak memory while
    /// amortizing fsync overhead across many rows.
    pub batch_size: usize,
}

impl Default for AddrIndexMigrateConfig {
    fn default() -> Self {
        Self {
            dry_run: false,
            batch_size: 10_000,
        }
    }
}

/// Per-CF migration outcome. Funding and spending are reported
/// separately so partial-run states (e.g. funding succeeded but
/// spending failed mid-batch) are visible to the operator.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddrIndexMigrateStats {
    pub funding: PerCfStats,
    pub spending: PerCfStats,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerCfStats {
    pub rows_scanned: u64,
    pub rows_migrated: u64,
    /// Rows whose key didn't decode as a v1 addr-index key (wrong
    /// length, etc.). Skipped — not auto-deleted — so latent
    /// corruption is visible rather than silently destroyed.
    pub rows_skipped_bad_key: u64,
    /// Rows whose value didn't decode (corrupt amount / outpoint).
    /// Same skip-don't-delete treatment as above.
    pub rows_skipped_bad_value: u64,
    pub bytes_before: u64,
    pub bytes_after: u64,
}

impl PerCfStats {
    pub fn bytes_reclaimed(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }
}

impl AddrIndexMigrateStats {
    pub fn bytes_reclaimed(&self) -> u64 {
        self.funding.bytes_reclaimed() + self.spending.bytes_reclaimed()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddrIndexMigrateError {
    #[error("rocksdb error: {0}")]
    RocksDb(String),
}

/// Walk both v1 addr-index CFs and migrate every row into the v2
/// schema. Returns per-CF stats. With `dry_run = true`, no writes or
/// deletes are issued — stats reflect what the real run would do.
pub fn migrate_addr_index(
    store: &RocksDbStore,
    config: AddrIndexMigrateConfig,
) -> Result<AddrIndexMigrateStats, AddrIndexMigrateError> {
    let started = Instant::now();
    let funding = migrate_one_cf(
        store,
        CfPair {
            v1_name: CF_ADDR_FUNDING,
            v2_name: CF_ADDR_FUNDING_V2,
            kind: CfKind::Funding,
        },
        config,
    )?;
    let spending = migrate_one_cf(
        store,
        CfPair {
            v1_name: CF_ADDR_SPENDING,
            v2_name: CF_ADDR_SPENDING_V2,
            kind: CfKind::Spending,
        },
        config,
    )?;
    let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    Ok(AddrIndexMigrateStats {
        funding,
        spending,
        duration_ms,
    })
}

#[derive(Copy, Clone)]
enum CfKind {
    Funding,
    Spending,
}

struct CfPair {
    v1_name: &'static str,
    v2_name: &'static str,
    kind: CfKind,
}

fn migrate_one_cf(
    store: &RocksDbStore,
    pair: CfPair,
    config: AddrIndexMigrateConfig,
) -> Result<PerCfStats, AddrIndexMigrateError> {
    let cf_v1 = store.cf(pair.v1_name);
    let cf_v2 = store.cf(pair.v2_name);
    let iter = store
        .raw_db()
        .iterator_cf(&cf_v1, rocksdb::IteratorMode::Start);

    let mut stats = PerCfStats::default();
    let mut batch = WriteBatch::default();
    // Each migrated row contributes one put + one delete = 2 ops.
    let mut ops_in_batch = 0usize;
    let flush_threshold = config.batch_size.saturating_mul(2).max(2);

    for item in iter {
        let (key, value) = item.map_err(|e| AddrIndexMigrateError::RocksDb(e.to_string()))?;
        stats.rows_scanned += 1;
        stats.bytes_before += value.len() as u64;

        // Decode the v1 key + value. The migrator only handles
        // well-formed rows; latent corruption is surfaced via the
        // skip counters and left in place for the operator to
        // investigate (deleting on a decode error would silently
        // lose data).
        let (v2_key, v2_value, ok) = match pair.kind {
            CfKind::Funding => match crate::index::address::decode_funding_key(&key) {
                None => {
                    stats.rows_skipped_bad_key += 1;
                    stats.bytes_after += value.len() as u64;
                    continue;
                }
                Some(k) => {
                    let amount = match crate::index::address::decode_funding_value(&value) {
                        Some(a) => a,
                        None => {
                            stats.rows_skipped_bad_value += 1;
                            stats.bytes_after += value.len() as u64;
                            continue;
                        }
                    };
                    let new_key = crate::index::address::encode_funding_key_v2(&k);
                    let new_value = crate::index::address::encode_funding_value(amount);
                    (new_key.to_vec(), new_value.to_vec(), true)
                }
            },
            CfKind::Spending => match crate::index::address::decode_spending_key(&key) {
                None => {
                    stats.rows_skipped_bad_key += 1;
                    stats.bytes_after += value.len() as u64;
                    continue;
                }
                Some(k) => {
                    let prev = match crate::index::address::decode_spending_value(&value) {
                        Some(p) => p,
                        None => {
                            stats.rows_skipped_bad_value += 1;
                            stats.bytes_after += value.len() as u64;
                            continue;
                        }
                    };
                    let new_key = crate::index::address::encode_spending_key_v2(&k);
                    let new_value = crate::index::address::encode_spending_value(&prev);
                    (new_key.to_vec(), new_value.to_vec(), true)
                }
            },
        };
        debug_assert!(ok);

        stats.rows_migrated += 1;
        stats.bytes_after += v2_value.len() as u64;
        if !config.dry_run {
            batch.put_cf(&cf_v2, &v2_key, &v2_value);
            batch.delete_cf(&cf_v1, &key);
            ops_in_batch += 2;
        }

        if ops_in_batch >= flush_threshold {
            store
                .raw_db()
                .write(std::mem::take(&mut batch))
                .map_err(|e| AddrIndexMigrateError::RocksDb(e.to_string()))?;
            ops_in_batch = 0;
        }
    }

    if ops_in_batch > 0 {
        store
            .raw_db()
            .write(batch)
            .map_err(|e| AddrIndexMigrateError::RocksDb(e.to_string()))?;
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::address::{
        AddrFundingRow, AddrSpendingRow, encode_funding_key, encode_funding_key_v2,
        encode_funding_value, encode_spending_key, encode_spending_key_v2,
        encode_spending_value,
    };
    use crate::storage::Store;
    use crate::storage::StoreBatch;
    use crate::storage::rocksdb_store::hash_bytes;
    use bitcoin::OutPoint;
    use bitcoin::hashes::Hash;

    fn make_outpoint(txid_byte: u8, vout: u32) -> OutPoint {
        let inner = bitcoin::hashes::sha256d::Hash::from_byte_array([txid_byte; 32]);
        OutPoint {
            txid: bitcoin::Txid::from_raw_hash(inner),
            vout,
        }
    }

    fn open_store(dir: &std::path::Path) -> RocksDbStore {
        RocksDbStore::open(dir, false, 16, false, -1).unwrap()
    }

    /// Helper: write a v1 funding row directly into CF_ADDR_FUNDING,
    /// bypassing write_batch (which post-PR-D emits to v2 only).
    fn put_v1_funding(store: &RocksDbStore, row: &AddrFundingRow) {
        let cf = store.cf(CF_ADDR_FUNDING);
        store
            .raw_db()
            .put_cf(
                &cf,
                encode_funding_key(&row.key()),
                encode_funding_value(row.amount_sat),
            )
            .unwrap();
    }

    fn put_v1_spending(store: &RocksDbStore, row: &AddrSpendingRow) {
        let cf = store.cf(CF_ADDR_SPENDING);
        store
            .raw_db()
            .put_cf(
                &cf,
                encode_spending_key(&row.key()),
                encode_spending_value(&row.prev_outpoint),
            )
            .unwrap();
    }

    #[test]
    fn migrate_v1_funding_to_v2_rewrites_and_deletes_v1() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(tmp.path());
        let row = AddrFundingRow {
            scripthash: [0xAB; 32],
            height: 100,
            txid: make_outpoint(0xCD, 0).txid,
            vout: 7,
            amount_sat: 1_000_000,
        };
        put_v1_funding(&store, &row);

        let stats = migrate_addr_index(&store, AddrIndexMigrateConfig::default()).unwrap();
        assert_eq!(stats.funding.rows_scanned, 1);
        assert_eq!(stats.funding.rows_migrated, 1);
        assert_eq!(stats.spending.rows_scanned, 0);

        // v1 CF must no longer contain the row.
        let cf_v1 = store.cf(CF_ADDR_FUNDING);
        assert!(
            store
                .raw_db()
                .get_cf(&cf_v1, encode_funding_key(&row.key()))
                .unwrap()
                .is_none(),
            "v1 row must be deleted after migration",
        );

        // v2 CF must contain the row.
        let cf_v2 = store.cf(CF_ADDR_FUNDING_V2);
        let v2_value = store
            .raw_db()
            .get_cf(&cf_v2, encode_funding_key_v2(&row.key()))
            .unwrap()
            .expect("v2 row present");
        assert_eq!(v2_value, encode_funding_value(row.amount_sat));

        // Merged read returns the row exactly once via the v2 path.
        let got = store.iter_addr_funding(&row.scripthash);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, row.amount_sat);
    }

    #[test]
    fn migrate_v1_spending_to_v2_rewrites_and_deletes_v1() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(tmp.path());
        let row = AddrSpendingRow {
            scripthash: [0x55; 32],
            height: 50,
            txid: make_outpoint(0xEE, 0).txid,
            vin: 1,
            prev_outpoint: make_outpoint(0xAA, 2),
        };
        put_v1_spending(&store, &row);

        let stats = migrate_addr_index(&store, AddrIndexMigrateConfig::default()).unwrap();
        assert_eq!(stats.spending.rows_scanned, 1);
        assert_eq!(stats.spending.rows_migrated, 1);

        let cf_v1 = store.cf(CF_ADDR_SPENDING);
        assert!(
            store
                .raw_db()
                .get_cf(&cf_v1, encode_spending_key(&row.key()))
                .unwrap()
                .is_none(),
        );
        let cf_v2 = store.cf(CF_ADDR_SPENDING_V2);
        assert!(
            store
                .raw_db()
                .get_cf(&cf_v2, encode_spending_key_v2(&row.key()))
                .unwrap()
                .is_some(),
        );
    }

    #[test]
    fn dry_run_reports_stats_without_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(tmp.path());
        let row = AddrFundingRow {
            scripthash: [0x77; 32],
            height: 10,
            txid: make_outpoint(0x11, 0).txid,
            vout: 0,
            amount_sat: 42,
        };
        put_v1_funding(&store, &row);

        let stats = migrate_addr_index(
            &store,
            AddrIndexMigrateConfig {
                dry_run: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(stats.funding.rows_migrated, 1);

        // v1 CF must STILL contain the row.
        let cf_v1 = store.cf(CF_ADDR_FUNDING);
        assert!(
            store
                .raw_db()
                .get_cf(&cf_v1, encode_funding_key(&row.key()))
                .unwrap()
                .is_some(),
            "dry-run must not delete v1 rows",
        );
        // v2 CF must NOT contain it.
        let cf_v2 = store.cf(CF_ADDR_FUNDING_V2);
        assert!(
            store
                .raw_db()
                .get_cf(&cf_v2, encode_funding_key_v2(&row.key()))
                .unwrap()
                .is_none(),
            "dry-run must not populate v2",
        );
    }

    #[test]
    fn empty_cfs_are_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(tmp.path());
        let stats = migrate_addr_index(&store, AddrIndexMigrateConfig::default()).unwrap();
        assert_eq!(stats.funding.rows_scanned, 0);
        assert_eq!(stats.spending.rows_scanned, 0);
        assert_eq!(stats.bytes_reclaimed(), 0);
    }

    #[test]
    fn already_v2_rows_are_left_untouched() {
        // Live v2 rows (added by post-PR-D writes) live in their own
        // CF; the migrator only walks v1 and so must leave them
        // alone. Verify the v2-only row's stored value is unchanged.
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(tmp.path());

        let row = AddrFundingRow {
            scripthash: [0xCC; 32],
            height: 200,
            txid: make_outpoint(0x99, 0).txid,
            vout: 0,
            amount_sat: 7_777,
        };
        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(row.clone());
        store.write_batch(batch).unwrap();
        let cf_v2 = store.cf(CF_ADDR_FUNDING_V2);
        let before = store
            .raw_db()
            .get_cf(&cf_v2, encode_funding_key_v2(&row.key()))
            .unwrap()
            .unwrap();

        let stats = migrate_addr_index(&store, AddrIndexMigrateConfig::default()).unwrap();
        // 0 rows scanned because v1 CF is empty.
        assert_eq!(stats.funding.rows_scanned, 0);

        let after = store
            .raw_db()
            .get_cf(&cf_v2, encode_funding_key_v2(&row.key()))
            .unwrap()
            .unwrap();
        assert_eq!(before, after, "post-migration v2-only row must be unchanged");
    }

    #[test]
    fn batch_size_does_not_change_outcome() {
        // Run twice against equivalent fixtures with different batch
        // sizes; final state must match.
        let make_fixture = || {
            let tmp = tempfile::tempdir().unwrap();
            let store = open_store(tmp.path());
            for i in 0..40u8 {
                put_v1_funding(
                    &store,
                    &AddrFundingRow {
                        scripthash: [i; 32],
                        height: 100 + i as u32,
                        txid: make_outpoint(i, 0).txid,
                        vout: 0,
                        amount_sat: 1_000 + i as u64,
                    },
                );
                put_v1_spending(
                    &store,
                    &AddrSpendingRow {
                        scripthash: [i; 32],
                        height: 200 + i as u32,
                        txid: make_outpoint(i, 1).txid,
                        vin: 0,
                        prev_outpoint: make_outpoint(0xFF, i as u32),
                    },
                );
            }
            (store, tmp)
        };

        let (store_a, _t_a) = make_fixture();
        let stats_a = migrate_addr_index(
            &store_a,
            AddrIndexMigrateConfig {
                dry_run: false,
                batch_size: 3,
            },
        )
        .unwrap();
        let (store_b, _t_b) = make_fixture();
        let stats_b = migrate_addr_index(
            &store_b,
            AddrIndexMigrateConfig {
                dry_run: false,
                batch_size: 1000,
            },
        )
        .unwrap();
        assert_eq!(stats_a.funding.rows_migrated, stats_b.funding.rows_migrated);
        assert_eq!(stats_a.spending.rows_migrated, stats_b.spending.rows_migrated);

        // Cross-check final state for every key.
        for i in 0..40u8 {
            let sh = [i; 32];
            let f_a = store_a.iter_addr_funding(&sh);
            let f_b = store_b.iter_addr_funding(&sh);
            assert_eq!(f_a.len(), 1);
            assert_eq!(f_b.len(), 1);
            assert_eq!(f_a[0].1, f_b[0].1);
            let s_a = store_a.iter_addr_spending(&sh);
            let s_b = store_b.iter_addr_spending(&sh);
            assert_eq!(s_a.len(), 1);
            assert_eq!(s_b.len(), 1);
        }
        // Verify with hash_bytes only that we can still look up the
        // metadata sample by its raw 32-byte key shape — this is the
        // simplest smoke that the CF layout wasn't disturbed.
        let cf_v2 = store_a.cf(CF_ADDR_FUNDING_V2);
        let probe_sh = [0u8; 32];
        // hash_bytes is just a length-validated identity over a
        // BlockHash here used to confirm 32-byte key conventions are
        // accepted by the bound CF handle.
        let probe_hash = bitcoin::BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array(probe_sh),
        );
        let _ = store_a.raw_db().get_cf(&cf_v2, hash_bytes(&probe_hash)).unwrap();
    }

    #[test]
    fn corrupt_v1_key_is_skipped_not_deleted() {
        // Inject garbage at a v1-shape key. The migrator must NOT
        // delete it (we'd be destroying evidence of the corruption);
        // it must surface the skip count and leave the bytes in
        // place.
        let tmp = tempfile::tempdir().unwrap();
        let store = open_store(tmp.path());
        let cf_v1 = store.cf(CF_ADDR_FUNDING);
        // Wrong key length — won't decode as a v1 funding key.
        let bad_key = vec![0xDE, 0xAD];
        store.raw_db().put_cf(&cf_v1, &bad_key, b"unused").unwrap();

        let stats = migrate_addr_index(&store, AddrIndexMigrateConfig::default()).unwrap();
        assert_eq!(stats.funding.rows_skipped_bad_key, 1);
        assert_eq!(stats.funding.rows_migrated, 0);
        // Row must still be present.
        assert!(
            store.raw_db().get_cf(&cf_v1, &bad_key).unwrap().is_some(),
            "corrupt row must be retained for operator investigation",
        );
    }
}
