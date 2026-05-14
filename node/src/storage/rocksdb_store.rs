use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, Txid};
use rocksdb::{
    BlockBasedOptions, BoundColumnFamily, Cache, ColumnFamilyDescriptor, DBCompressionType,
    DBWithThreadMode, FlushOptions, IteratorMode, MultiThreaded, Options, SliceTransform,
    WriteBatch, WriteOptions,
};
use std::path::Path;
use std::sync::Arc;

use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};
use crate::storage::coinview::{Coin, outpoint_to_key};
use crate::storage::undo::UndoData;
use crate::storage::{Store, StoreBatch, StoreError, WriteMode};

const CF_BLOCK_INDEX: &str = "block_index";
const CF_COINS: &str = "coins";
const CF_HEIGHT_INDEX: &str = "height_index";
const CF_UNDO: &str = "undo";
const CF_TX_INDEX: &str = "tx_index";
const CF_METADATA: &str = "metadata";
const CF_ADDR_FUNDING: &str = "addr_funding";
const CF_ADDR_SPENDING: &str = "addr_spending";
/// Confirmed-side spend index: `prev_outpoint -> SpendingRef`. Written
/// alongside the address-index spending rows; the two CFs answer
/// different shapes of the same question.
const CF_OUTPOINT_SPEND: &str = "outpoint_spend";
/// BIP 158 compact-block-filter blobs, keyed by
/// `(filter_type:u8 || height_be:u32)`. Value: raw GCS-encoded filter.
/// Sibling to `cf_filter_header`.
#[cfg(feature = "block-filter-index")]
const CF_FILTER: &str = "block_filter";
/// BIP 157 chained filter headers (32 bytes each). Same key shape as
/// `cf_filter`. Persisted alongside the filter blob so we never
/// recompute the header chain at read time.
#[cfg(feature = "block-filter-index")]
const CF_FILTER_HEADER: &str = "block_filter_header";
/// Temp CF created lazily when a deferred backfill starts. Holds
/// `(outpoint -> scripthash)` rows used by pass 2 to resolve input
/// scripthashes without reading flat-file undo data. Dropped wholesale
/// on Completed or Cancelled.
const CF_ADDR_BACKFILL_TEMP: &str = "addr_backfill_outpoint_to_scripthash";

const TIP_KEY: &[u8] = b"tip";
const UTXO_COUNT_KEY: &[u8] = b"utxo_count";
const TOTAL_AMOUNT_KEY: &[u8] = b"total_amount";
const UTXO_HEIGHT_HIST_KEY: &[u8] = b"utxo_height_hist";
const HEIGHT_HIST_BUCKET: u32 = 1000;
const SCHEMA_KEY: &[u8] = b"schema_version";
/// `outpoint_spend.complete` metadata flag. `b"\x01"` when the
/// outpoint_spend CF holds rows for every input on the active chain
/// up to the chain tip; `b"\x00"` (or missing) when the CF was added
/// to a pre-existing datadir that already has historical
/// addr_spending rows from before this index landed.
///
/// The flag is stamped true on:
/// 1. fresh datadir creation,
/// 2. completion of `clear_chainstate` / `clear_all` (after which a
///    re-sync repopulates everything),
/// 3. address-backfill `mark_completed` (pass 2 writes both addr +
///    outpoint rows for the snapshot range).
///
/// On open: if absent and `addr_spending` has historical rows, stamp
/// false so subsequent restarts continue to surface the gap even
/// after live `connect_block` has appended new rows. (Review H6.)
const OUTPOINT_SPEND_COMPLETE_KEY: &[u8] = b"outpoint_spend.complete";
/// `tx_index.complete` metadata flag — symmetric to
/// `outpoint_spend.complete` but for the `tx_index` CF that backs
/// `getrawtransaction` / `gettxlocation` and Esplora's `/tx/:txid`
/// confirmed-side lookup. Stamped true on fresh datadir, on
/// `clear_chainstate` / `clear_all`. False when an upgraded datadir
/// has historical block-index entries but the tx_index CF is empty
/// (the operator previously ran with `txindex=0`). (Round-3 H1.)
const TX_INDEX_COMPLETE_KEY: &[u8] = b"tx_index.complete";
/// Persisted "address-history index is complete for the active chain"
/// marker. Mirrors `TX_INDEX_COMPLETE_KEY` — set true after a clean
/// backfill (or on fresh datadirs that started with addressindex=1
/// from genesis); cleared atomically when a block connects while
/// addressindex is disabled. Round-1 review H2.
const ADDRESS_INDEX_COMPLETE_KEY: &[u8] = b"address_index.complete";
/// Persisted "BIP 158 filter index is complete for the active chain"
/// marker. Symmetric to `ADDRESS_INDEX_COMPLETE_KEY`: set true on
/// fresh datadirs that started with `--blockfilterindex=basic` from
/// genesis, or after a successful filter backfill (PR-3); cleared
/// atomically when a block connects while `blockfilterindex=0`. Both
/// the `getblockfilter` RPC and the BIP 157 P2P arms refuse to serve
/// when this flag is false.
#[cfg(feature = "block-filter-index")]
const BLOCK_FILTER_INDEX_COMPLETE_KEY: &[u8] = b"block_filter_index.complete";
/// Persisted "highest filter-row height we've stamped" marker. Read at
/// startup to validate the completeness marker against actual coverage.
/// Updated by `connect_block` only; reorg-disconnect doesn't roll it
/// back (the active chain's tip is the read-time oracle, the
/// persisted value is just an upper bound).
#[cfg(feature = "block-filter-index")]
const BLOCK_FILTER_INDEX_TIP_HEIGHT_KEY: &[u8] = b"block_filter_index.tip_height";
const CURRENT_SCHEMA_VERSION: u32 = 2; // v2 = compact varint coins

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

/// Encode `(txid || vout BE)` as the temp-CF key. 36 bytes; same shape
/// as `outpoint_to_key` (varint-style) is avoided here so the key is
/// trivially decodable in tests and panics-on-truncation diagnostics.
fn backfill_temp_key(op: &OutPoint) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..32].copy_from_slice(op.txid.as_ref());
    key[32..].copy_from_slice(&op.vout.to_be_bytes());
    key
}

type DB = DBWithThreadMode<MultiThreaded>;

/// RocksDB storage backend with compression and bloom filters.
pub struct RocksDbStore {
    db: DB,
    txindex_enabled: bool,
    /// Whether per-block address-index emission is active. When
    /// `false` and a block connects, the persisted
    /// `address_index.complete` marker is cleared atomically so a
    /// future Electrum / Esplora address-surface bind refuses until
    /// the operator runs a backfill / reindex (Round-1 review H2).
    addressindex_enabled: bool,
    /// Whether per-block BIP 158 filter-index emission is active.
    /// Same invalidation contract as `addressindex_enabled`: when
    /// `false` and a block connects, the persisted
    /// `block_filter_index.complete` marker is cleared atomically so
    /// the BIP 157 P2P service refuses until the operator runs a
    /// filter backfill / reindex.
    #[cfg(feature = "block-filter-index")]
    blockfilterindex_enabled: bool,
    /// Shared LRU across all column families. Cloneable Arc; the FFI layer
    /// is thread-safe for `set_capacity`, so a clone plus an interior mutex
    /// is enough to allow live resize from a separate task.
    block_cache: parking_lot::Mutex<Cache>,
    /// Tracked separately because the RocksDB Cache API has no
    /// `get_capacity` getter — only usage.
    block_cache_capacity: std::sync::atomic::AtomicUsize,
}

impl RocksDbStore {
    pub fn open(
        path: &Path,
        txindex: bool,
        cache_mb: usize,
        reindex: bool,
        max_open_files: i32,
    ) -> Result<Self, StoreError> {
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
        // Bound the table reader cache. Without this, RocksDB defaults to
        // -1 (keep every SST open for the lifetime of the DB), so a chain-
        // state that has accumulated tens of thousands of SSTs during a
        // compaction backlog will hold tens of thousands of fds and load
        // every per-SST bloom/index block — the failure mode that wedged
        // a 78-GB process during a mainnet IBD. A small positive cap
        // forces RocksDB to evict cold SST handles and keeps the per-SST
        // metadata footprint proportional to working-set size, not on-
        // disk file count.
        db_opts.set_max_open_files(max_open_files);

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
        let make_cf_opts =
            |bloom: bool, write_buf_mb: usize, prefix_len: Option<usize>| -> Options {
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

                // Fixed-length key prefix lets `prefix_iterator_cf` short-
                // circuit to the matching SST block (and engages the bloom
                // filter for prefix-presence checks). Used by the address-
                // history CFs whose first 32 bytes are `sha256(spk)`.
                if let Some(len) = prefix_len {
                    cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(len));
                }

                cf_opts
            };

        let mut cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_COINS, make_cf_opts(true, 64, None)),
            ColumnFamilyDescriptor::new(CF_BLOCK_INDEX, make_cf_opts(false, 8, None)),
            ColumnFamilyDescriptor::new(CF_HEIGHT_INDEX, make_cf_opts(false, 8, None)),
            ColumnFamilyDescriptor::new(CF_UNDO, make_cf_opts(false, 16, None)),
            ColumnFamilyDescriptor::new(CF_TX_INDEX, make_cf_opts(false, 16, None)),
            ColumnFamilyDescriptor::new(CF_METADATA, make_cf_opts(false, 2, None)),
            // Address-history index. Bloom on for fast point lookups,
            // 32 MB write-buffer because per-block emission is write-
            // heavy during IBD, and a fixed 32-byte prefix-extractor so
            // `prefix_iterator_cf` over a single scripthash short-
            // circuits to the matching SST blocks instead of scanning.
            ColumnFamilyDescriptor::new(CF_ADDR_FUNDING, make_cf_opts(true, 32, Some(32))),
            ColumnFamilyDescriptor::new(CF_ADDR_SPENDING, make_cf_opts(true, 32, Some(32))),
            // outpoint_spend: bloom on (point lookups dominate), 16 MB
            // write-buf because the row is small (40-byte value, 36-byte
            // key) and one row per non-coinbase input — heavier than
            // tx_index but lighter than addr_spending. 32-byte prefix
            // (txid) lets `outspends` for a tx fan out cheaply.
            ColumnFamilyDescriptor::new(CF_OUTPOINT_SPEND, make_cf_opts(true, 16, Some(32))),
        ];

        // BIP 158 filter index. Bloom on (point lookups dominate
        // `getcfilters`/`getblockfilter`); 16 MB write-buf because
        // every connected block produces one ~30 KB filter blob plus
        // a 32-byte header row. No prefix extractor: keys are 5 bytes
        // `(filter_type[1] || height_be[4])`, so a fixed-prefix
        // optimization would only help iterators that span filter
        // types — we have one filter type for v1.
        #[cfg(feature = "block-filter-index")]
        {
            cf_descriptors.push(ColumnFamilyDescriptor::new(
                CF_FILTER,
                make_cf_opts(true, 16, None),
            ));
            cf_descriptors.push(ColumnFamilyDescriptor::new(
                CF_FILTER_HEADER,
                make_cf_opts(true, 8, None),
            ));
        }

        // The deferred-backfill temp CF is created lazily when an
        // operator triggers `backfillindex address`. RocksDB demands
        // every existing CF be declared at open time, so probe the DB
        // dir once and include the temp CF descriptor if it's present.
        // Skipped on first-open (path doesn't exist yet) — list_cf
        // requires the DB directory to exist.
        if db_path.exists()
            && let Ok(existing_cfs) = DB::list_cf(&Options::default(), &db_path)
            && existing_cfs.iter().any(|n| n == CF_ADDR_BACKFILL_TEMP)
        {
            cf_descriptors.push(ColumnFamilyDescriptor::new(
                CF_ADDR_BACKFILL_TEMP,
                make_cf_opts(true, 32, None),
            ));
        }

        let db = DB::open_cf_descriptors(&db_opts, &db_path, cf_descriptors).map_err(|e| {
            StoreError::Database(format!(
                "Failed to open RocksDB at {}: {}",
                db_path.display(),
                e
            ))
        })?;

        // Schema version check: ensure coin format matches this binary.
        // Skip when reindexing — the DB is about to be cleared.
        if !reindex {
            let cf_meta = db.cf_handle(CF_METADATA).expect("metadata CF missing");
            match db.get_cf(&cf_meta, SCHEMA_KEY) {
                Ok(Some(v)) => {
                    let stored = u32::from_le_bytes(v[..].try_into().unwrap_or([0; 4]));
                    if stored != CURRENT_SCHEMA_VERSION {
                        return Err(StoreError::Database(format!(
                            "Chainstate schema version mismatch: DB has v{}, binary expects v{}. \
                             Run with --reindex to rebuild.",
                            stored, CURRENT_SCHEMA_VERSION
                        )));
                    }
                }
                Ok(None) => {
                    let cf_coins = db.cf_handle(CF_COINS).expect("coins CF missing");
                    let has_coins = db
                        .iterator_cf(&cf_coins, IteratorMode::Start)
                        .next()
                        .is_some();
                    if has_coins {
                        return Err(StoreError::Database(
                            "Existing chainstate has no schema version (pre-compact format). \
                             Run with --reindex to rebuild."
                                .to_string(),
                        ));
                    }
                    Self::stamp_schema(&db, CURRENT_SCHEMA_VERSION)?;
                }
                Err(e) => {
                    return Err(StoreError::Database(format!(
                        "Failed to read schema version: {}",
                        e
                    )));
                }
            }
        } else {
            // Reindexing — stamp version (clear_all will erase it, but
            // write_schema_version below handles the re-stamp after clear).
        }

        let store = Self {
            db,
            txindex_enabled: txindex,
            // Default true; main.rs flips this to `config.addressindex`
            // via `with_addressindex_enabled` before wrapping the store
            // in CoinCache. Tests / lower-level callers that don't
            // exercise the address-index path keep the default.
            addressindex_enabled: true,
            // Default false (the runtime opt-in is `--blockfilterindex=basic`);
            // main.rs flips it via `with_blockfilterindex_enabled`. Default
            // false matches the addr-side cleared-marker invariant: when
            // the index is *off*, every connected block clears the
            // completeness marker atomically.
            #[cfg(feature = "block-filter-index")]
            blockfilterindex_enabled: false,
            block_cache: parking_lot::Mutex::new(block_cache),
            block_cache_capacity: std::sync::atomic::AtomicUsize::new(cache_bytes),
        };
        // outpoint_spend completeness marker (review H6 round 2).
        //
        // Three reachable open-time states for the marker:
        //
        // 1. Marker present and `\x01` → CF was fully populated by an
        //    earlier sync / clear / backfill. Trust it.
        // 2. Marker present and `\x00` → previous open detected an
        //    incomplete state. Persist it so the warning fires on
        //    every subsequent open until the operator runs a clear.
        // 3. Marker missing → either a fresh datadir (no historical
        //    addr_spending rows yet) or an upgrade from pre-#99
        //    (addr_spending populated but outpoint_spend empty).
        //    Decide which by looking at addr_spending; stamp the
        //    correct value so the diagnostic doesn't disappear once
        //    `connect_block` starts appending new outpoint_spend rows.
        let marker = store.read_outpoint_spend_complete();
        if marker.is_none() {
            let addr_has_rows = store
                .db
                .cf_handle(CF_ADDR_SPENDING)
                .and_then(|cf| {
                    store
                        .db
                        .iterator_cf(&cf, IteratorMode::Start)
                        .next()
                        .map(|item| item.is_ok())
                })
                .unwrap_or(false);
            store.write_outpoint_spend_complete(!addr_has_rows)?;
        }
        if !store.outpoint_spend_complete() {
            tracing::warn!(
                target: "storage",
                "outpoint_spend index is incomplete relative to addr_spending: \
                 historical /tx/:txid/outspend lookups will return false 'unspent' \
                 answers until you restart with --reindex-chainstate (recommended \
                 after upgrade from a satd version that predates this index)"
            );
        }

        // tx_index.complete marker — round-3 H1, refined in round-4
        // H1 to a one-way invalidation flag.
        //
        // Trust the persisted value once stamped. The previous
        // round's "recompute on every open" logic interpreted
        // "tx_index CF has any rows" as complete, which silently
        // re-flipped the marker to true after a partial-txindex run
        // (e.g. legacy empty + one txindex-on block + Esplora restart
        // would let stale historical 404s through). The corrected
        // contract:
        //
        //   - Fresh datadir (no `block_index` rows yet) → stamp true.
        //     No history to be missing.
        //   - Legacy datadir without the marker (block_index has
        //     rows but the flag was never written) → stamp false.
        //     Esplora must refuse until `--reindex-chainstate`.
        //     This is conservative — even legitimate
        //     full-txindex-from-genesis datadirs see a one-time
        //     reindex prompt — but the alternative was to silently
        //     accept partial histories.
        //   - Marker already present → don't touch it. `clear_*`
        //     paths re-stamp true; `connect_block` paths stamp
        //     false in `write_batch_mode` when txindex is disabled.
        if store.read_tx_index_complete().is_none() {
            let block_index_has_rows = store
                .db
                .cf_handle(CF_BLOCK_INDEX)
                .and_then(|cf| {
                    store
                        .db
                        .iterator_cf(&cf, IteratorMode::Start)
                        .next()
                        .map(|item| item.is_ok())
                })
                .unwrap_or(false);
            store.write_tx_index_complete(!block_index_has_rows)?;
        }
        if txindex && !store.tx_index_complete() {
            tracing::warn!(
                target: "storage",
                "tx_index CF is enabled but on-disk data is incomplete (this datadir was \
                 previously synced with --txindex=0). Confirmed /tx/:txid lookups will \
                 false-404 historical transactions until you restart with \
                 --reindex-chainstate."
            );
        }

        // address_index.complete marker — round-1 review H2.
        //
        // Mirrors the tx_index path. Three reachable open-time states:
        //
        //   - Fresh datadir (no `block_index` rows yet) → stamp true.
        //     No history to be missing.
        //   - Legacy datadir without the marker (block_index has rows
        //     but the flag was never written) → stamp false. Electrum
        //     / Esplora address-surface bind refuses until backfill
        //     completes.
        //   - Marker already present → don't touch it. Backfill
        //     `mark_completed` re-stamps true; `connect_block` paths
        //     stamp false in `write_batch_mode` when addressindex is
        //     disabled (set after `with_addressindex_enabled`).
        if store.read_address_index_complete().is_none() {
            let block_index_has_rows = store
                .db
                .cf_handle(CF_BLOCK_INDEX)
                .and_then(|cf| {
                    store
                        .db
                        .iterator_cf(&cf, IteratorMode::Start)
                        .next()
                        .map(|item| item.is_ok())
                })
                .unwrap_or(false);
            store.write_address_index_complete(!block_index_has_rows)?;
        }

        // block_filter_index.complete marker — same shape as the
        // address-index marker above. Three reachable open-time states:
        //
        //   - Fresh datadir (no `block_index` rows yet) → stamp true.
        //     No history to be missing.
        //   - Legacy datadir without the marker (block_index has rows
        //     but the flag was never written) → stamp false. The BIP
        //     157 P2P service refuses to advertise/serve until backfill
        //     completes (PR-3) or the operator runs `--reindex-chainstate`.
        //   - Marker already present → don't touch it. Backfill
        //     `mark_block_filter_index_complete` re-stamps true; per-block
        //     `write_batch_mode` clears it when blockfilterindex is
        //     disabled at runtime (set after `with_blockfilterindex_enabled`).
        #[cfg(feature = "block-filter-index")]
        if store.read_block_filter_index_complete().is_none() {
            let block_index_has_rows = store
                .db
                .cf_handle(CF_BLOCK_INDEX)
                .and_then(|cf| {
                    store
                        .db
                        .iterator_cf(&cf, IteratorMode::Start)
                        .next()
                        .map(|item| item.is_ok())
                })
                .unwrap_or(false);
            store.write_block_filter_index_complete(!block_index_has_rows)?;
        }
        Ok(store)
    }

    /// Set whether per-block address-index emission is active. Call
    /// before any `write_batch_mode` runs so the persisted
    /// `address_index.complete` marker stays consistent with the
    /// configured behaviour. Default is `true`.
    pub fn with_addressindex_enabled(mut self, enabled: bool) -> Self {
        self.addressindex_enabled = enabled;
        if !enabled {
            tracing::info!(
                target: "storage",
                "address index emission disabled; future block connects will clear \
                 the address_index.complete marker — Electrum / Esplora address \
                 surfaces will refuse to bind until a backfill completes."
            );
        }
        self
    }

    /// Set whether per-block BIP 158 filter-index emission is active.
    /// Call before any `write_batch_mode` runs so the persisted
    /// `block_filter_index.complete` marker stays consistent with the
    /// configured behaviour. Default is `false` (matches the
    /// `--blockfilterindex=0` Bitcoin-Core default).
    #[cfg(feature = "block-filter-index")]
    pub fn with_blockfilterindex_enabled(mut self, enabled: bool) -> Self {
        self.blockfilterindex_enabled = enabled;
        if !enabled {
            tracing::info!(
                target: "storage",
                "block filter index emission disabled; future block connects will clear \
                 the block_filter_index.complete marker — the BIP 157 P2P service and \
                 getblockfilter RPC will refuse to serve until a backfill / reindex \
                 completes."
            );
        }
        self
    }

    /// Read the `outpoint_spend.complete` marker from the metadata CF.
    /// Returns `None` when the key doesn't exist (fresh datadir or
    /// pre-marker upgrade).
    fn read_outpoint_spend_complete(&self) -> Option<bool> {
        let cf = self.db.cf_handle(CF_METADATA)?;
        match self.db.get_cf(&cf, OUTPOINT_SPEND_COMPLETE_KEY) {
            Ok(Some(v)) => v.first().map(|b| *b != 0),
            _ => None,
        }
    }

    fn write_outpoint_spend_complete(&self, value: bool) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| StoreError::Database("metadata CF missing".into()))?;
        self.db
            .put_cf(&cf, OUTPOINT_SPEND_COMPLETE_KEY, [u8::from(value)])
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    fn read_tx_index_complete(&self) -> Option<bool> {
        let cf = self.db.cf_handle(CF_METADATA)?;
        match self.db.get_cf(&cf, TX_INDEX_COMPLETE_KEY) {
            Ok(Some(v)) => v.first().map(|b| *b != 0),
            _ => None,
        }
    }

    fn write_tx_index_complete(&self, value: bool) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| StoreError::Database("metadata CF missing".into()))?;
        self.db
            .put_cf(&cf, TX_INDEX_COMPLETE_KEY, [u8::from(value)])
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    fn read_address_index_complete(&self) -> Option<bool> {
        let cf = self.db.cf_handle(CF_METADATA)?;
        match self.db.get_cf(&cf, ADDRESS_INDEX_COMPLETE_KEY) {
            Ok(Some(v)) => v.first().map(|b| *b != 0),
            _ => None,
        }
    }

    fn write_address_index_complete(&self, value: bool) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| StoreError::Database("metadata CF missing".into()))?;
        self.db
            .put_cf(&cf, ADDRESS_INDEX_COMPLETE_KEY, [u8::from(value)])
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    #[cfg(feature = "block-filter-index")]
    fn read_block_filter_index_complete(&self) -> Option<bool> {
        let cf = self.db.cf_handle(CF_METADATA)?;
        match self.db.get_cf(&cf, BLOCK_FILTER_INDEX_COMPLETE_KEY) {
            Ok(Some(v)) => v.first().map(|b| *b != 0),
            _ => None,
        }
    }

    #[cfg(feature = "block-filter-index")]
    fn write_block_filter_index_complete(&self, value: bool) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| StoreError::Database("metadata CF missing".into()))?;
        self.db
            .put_cf(&cf, BLOCK_FILTER_INDEX_COMPLETE_KEY, [u8::from(value)])
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    fn cf(&self, name: &str) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(name)
            .unwrap_or_else(|| panic!("column family '{}' not found", name))
    }

    /// Build column family options for (re)creation.
    fn cf_options(&self, name: &str) -> Options {
        // Bloom-filtered CFs are those that see point-lookups in
        // hot paths (UTXO + address-index reads + filter-index reads).
        #[cfg(feature = "block-filter-index")]
        let bloom = matches!(
            name,
            CF_COINS
                | CF_ADDR_FUNDING
                | CF_ADDR_SPENDING
                | CF_OUTPOINT_SPEND
                | CF_FILTER
                | CF_FILTER_HEADER
        );
        #[cfg(not(feature = "block-filter-index"))]
        let bloom = matches!(
            name,
            CF_COINS | CF_ADDR_FUNDING | CF_ADDR_SPENDING | CF_OUTPOINT_SPEND
        );
        let write_buf_mb = match name {
            CF_COINS => 64,
            CF_ADDR_FUNDING | CF_ADDR_SPENDING => 32,
            CF_OUTPOINT_SPEND => 16,
            CF_UNDO | CF_TX_INDEX => 16,
            CF_BLOCK_INDEX | CF_HEIGHT_INDEX => 8,
            #[cfg(feature = "block-filter-index")]
            CF_FILTER => 16,
            #[cfg(feature = "block-filter-index")]
            CF_FILTER_HEADER => 8,
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
        table_opts.set_block_cache(&self.block_cache.lock());
        table_opts.set_block_size(16 * 1024);
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
        // Address-index + outpoint-spend CFs share a 32-byte fixed
        // prefix. Mirror the prefix-extractor we set on initial CF
        // creation so `drop_and_recreate_cf` (used by `clear_*` paths)
        // preserves it.
        if matches!(name, CF_ADDR_FUNDING | CF_ADDR_SPENDING | CF_OUTPOINT_SPEND) {
            cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(32));
        }
        cf_opts
    }

    /// Write schema version to the metadata CF.
    fn stamp_schema(db: &DB, version: u32) -> Result<(), StoreError> {
        let cf_meta = db.cf_handle(CF_METADATA).expect("metadata CF missing");
        let mut wb = WriteBatch::default();
        wb.put_cf(&cf_meta, SCHEMA_KEY, version.to_le_bytes());
        db.write(wb)
            .map_err(|e| StoreError::Database(e.to_string()))
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
        let coin = Coin::deserialize_compact(&value);
        if coin.is_none() {
            tracing::error!(
                "corrupt coin: failed to deserialize {} bytes for {}:{}",
                value.len(),
                outpoint.txid,
                outpoint.vout
            );
        }
        coin
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
        self.write_batch_mode(batch, WriteMode::Normal)
    }

    fn write_batch_mode(&self, batch: StoreBatch, mode: WriteMode) -> Result<(), StoreError> {
        let mut wb = WriteBatch::default();

        let cf_bi = self.cf(CF_BLOCK_INDEX);
        let cf_coins = self.cf(CF_COINS);
        let cf_hi = self.cf(CF_HEIGHT_INDEX);
        let cf_undo = self.cf(CF_UNDO);
        let cf_meta = self.cf(CF_METADATA);

        // tx_index.complete one-way invalidation (round-4 H1).
        //
        // If the runtime has txindex disabled but this batch is
        // connecting/reorging blocks (any coin movement), the
        // tx_index CF will not get the rows for those blocks. Stamp
        // the completeness marker false IN THE SAME `WriteBatch` as
        // the chainstate update so the invalidation is atomic with
        // the connect — a crash mid-write either rolls everything
        // back or commits both. `coin_puts` is the connect signal
        // (every connected non-empty block creates outputs);
        // `coin_removes` covers the disconnect-with-txindex-off case
        // where existing tx_index rows for the now-undone block
        // become stale.
        if !self.txindex_enabled && (!batch.coin_puts.is_empty() || !batch.coin_removes.is_empty())
        {
            wb.put_cf(&cf_meta, TX_INDEX_COMPLETE_KEY, [0u8]);
        }

        // Same invalidation contract for the address-index marker
        // (round-1 review H2). When `addressindex` is disabled and a
        // block connects/disconnects, the address-history CFs diverge
        // from the chain — atomic-with-the-batch clearing makes the
        // diagnostic survive any crash window.
        if !self.addressindex_enabled
            && (!batch.coin_puts.is_empty() || !batch.coin_removes.is_empty())
        {
            wb.put_cf(&cf_meta, ADDRESS_INDEX_COMPLETE_KEY, [0u8]);
        }

        // Same invalidation contract for the BIP 158 filter-index marker.
        // When `blockfilterindex` is disabled at runtime and a block
        // connects/disconnects, the filter CFs diverge from the chain;
        // clear the marker atomically.
        #[cfg(feature = "block-filter-index")]
        if !self.blockfilterindex_enabled
            && (!batch.coin_puts.is_empty() || !batch.coin_removes.is_empty())
        {
            wb.put_cf(&cf_meta, BLOCK_FILTER_INDEX_COMPLETE_KEY, [0u8]);
        }

        // Block index
        //
        // Dominance filter mirroring `CachedStore::write_batch`'s rule:
        // a HeaderOnly write must not clobber an on-disk DataStored or
        // Valid entry. Most callers hit this through the cache, which
        // already drops dominated writes before they reach us — but
        // any path that bypasses the cache (e.g. tests, direct
        // `Store::write_batch`) would otherwise reintroduce the same
        // race the cache fix closed: `accept_headers`' HeaderOnly
        // batch clobbering a concurrent `store_block`'s DataStored
        // update, leaving `has_block_data()` permanently false and
        // stalling the connect loop. Silent-keep (no error, no log
        // spam) matches the cache behavior.
        for (hash, entry) in &batch.block_index_puts {
            if entry.status == BlockStatus::HeaderOnly
                && let Some(existing_bytes) = self
                    .db
                    .get_cf(&cf_bi, hash_bytes(hash))
                    .map_err(|e| StoreError::Database(e.to_string()))?
                && let Ok(existing) = bincode::deserialize::<BlockIndexEntry>(&existing_bytes)
                && matches!(existing.status, BlockStatus::DataStored | BlockStatus::Valid)
            {
                continue;
            }
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

        // Address-history index. CFs are present unconditionally —
        // gating on emit-side (M2) keeps the write_batch path simple.
        // Empty-batch fast-path avoids touching the CF handles when
        // the index is disabled or the block had no relevant rows.
        if !batch.addr_funding_puts.is_empty() || !batch.addr_funding_removes.is_empty() {
            let cf_af = self.cf(CF_ADDR_FUNDING);
            for row in &batch.addr_funding_puts {
                let key = crate::index::address::encode_funding_key(&row.key());
                let value = crate::index::address::encode_funding_value(row.amount_sat);
                wb.put_cf(&cf_af, key, value);
            }
            for key in &batch.addr_funding_removes {
                let encoded = crate::index::address::encode_funding_key(key);
                wb.delete_cf(&cf_af, encoded);
            }
        }
        if !batch.addr_spending_puts.is_empty() || !batch.addr_spending_removes.is_empty() {
            let cf_as = self.cf(CF_ADDR_SPENDING);
            for row in &batch.addr_spending_puts {
                let key = crate::index::address::encode_spending_key(&row.key());
                let value = crate::index::address::encode_spending_value(&row.prev_outpoint);
                wb.put_cf(&cf_as, key, value);
            }
            for key in &batch.addr_spending_removes {
                let encoded = crate::index::address::encode_spending_key(key);
                wb.delete_cf(&cf_as, encoded);
            }
        }

        // outpoint_spend index: same atomic-with-chainstate contract as
        // the addr-CFs. Empty-batch fast-path skips the CF handle.
        if !batch.outpoint_spend_puts.is_empty() || !batch.outpoint_spend_removes.is_empty() {
            let cf_os = self.cf(CF_OUTPOINT_SPEND);
            for (op, sref) in &batch.outpoint_spend_puts {
                let key = node_index::encode_outpoint_key(op);
                let value = node_index::encode_spend_value(sref);
                wb.put_cf(&cf_os, key, value);
            }
            for op in &batch.outpoint_spend_removes {
                let key = node_index::encode_outpoint_key(op);
                wb.delete_cf(&cf_os, key);
            }
        }

        // BIP 158 filter index. Filter blob and chained filter header
        // ride the same atomic batch as the chainstate update, so a
        // crash mid-write rolls everything back together — protocol
        // handlers can never observe a filter row whose chain segment
        // is partially committed. Empty-batch fast-path skips both CFs.
        #[cfg(feature = "block-filter-index")]
        {
            if !batch.filter_puts.is_empty()
                || !batch.filter_header_puts.is_empty()
                || !batch.filter_removes.is_empty()
            {
                use node_filter_index::encode_filter_key;
                let cf_f = self.cf(CF_FILTER);
                let cf_fh = self.cf(CF_FILTER_HEADER);
                let mut max_height: Option<u32> = None;
                for row in &batch.filter_puts {
                    let key = encode_filter_key(&row.key);
                    wb.put_cf(&cf_f, key, &row.filter);
                    max_height = Some(max_height.map_or(row.key.height, |h| h.max(row.key.height)));
                }
                for row in &batch.filter_header_puts {
                    let key = encode_filter_key(&row.key);
                    wb.put_cf(&cf_fh, key, row.header);
                    max_height = Some(max_height.map_or(row.key.height, |h| h.max(row.key.height)));
                }
                for k in &batch.filter_removes {
                    let key = encode_filter_key(k);
                    wb.delete_cf(&cf_f, key);
                    wb.delete_cf(&cf_fh, key);
                }
                // Persisted high-water tip-height. Connect-only update;
                // disconnect-time decrement is handled implicitly by
                // letting the read path use the active-chain tip
                // (chain_state.tip_height()) as the authoritative
                // bound, with this value as the "ever-stamped" upper
                // bound for diagnostics.
                if let Some(h) = max_height {
                    wb.put_cf(&cf_meta, BLOCK_FILTER_INDEX_TIP_HEIGHT_KEY, h.to_be_bytes());
                }
            }
        }

        // Backfill temp CF: only present while a backfill is in flight.
        // We refuse to commit a batch that produced temp puts but
        // arrived at the store after the CF was already dropped — that
        // would commit funding rows + cursor advance without the
        // matching `(outpoint -> scripthash)` rows pass 2 needs, and
        // pass 2 would later fail with TempCfMiss. Returning an error
        // before the WriteBatch is applied preserves the all-or-nothing
        // contract and forces the runner to stop cleanly.
        if !batch.addr_backfill_temp_puts.is_empty() {
            let cf_temp = self.db.cf_handle(CF_ADDR_BACKFILL_TEMP).ok_or_else(|| {
                StoreError::Database(format!(
                    "backfill temp CF '{}' is not open; refusing to commit a batch with {} \
                     pass-1 mappings (the runner should stop and let the operator restart)",
                    CF_ADDR_BACKFILL_TEMP,
                    batch.addr_backfill_temp_puts.len(),
                ))
            })?;
            for (outpoint, sh) in &batch.addr_backfill_temp_puts {
                let key = backfill_temp_key(outpoint);
                wb.put_cf(&cf_temp, key, sh);
            }
        }

        // Metadata: backfill cursor advance. Atomic with the addr-CF and
        // (when present) temp-CF writes above, so resume is consistent.
        if let Some(adv) = &batch.backfill_cursor_advance {
            use crate::index::address::cursor as cur;
            wb.put_cf(&cf_meta, cur::META_KEY_STATE, [adv.state.as_byte()]);
            wb.put_cf(&cf_meta, cur::META_KEY_PASS, [adv.pass]);
            wb.put_cf(
                &cf_meta,
                cur::META_KEY_CURSOR_HEIGHT,
                adv.cursor_height.to_be_bytes(),
            );
            wb.put_cf(
                &cf_meta,
                cur::META_KEY_SNAPSHOT_HEIGHT,
                adv.snapshot_height.to_be_bytes(),
            );
            wb.put_cf(
                &cf_meta,
                cur::META_KEY_STARTED_AT,
                adv.started_at_unix.to_be_bytes(),
            );
            // Snapshot-tip hash. All-zero hash is the "don't care" sentinel
            // (set by per-block batches that aren't the start
            // transition); skip the write so we don't clobber the
            // anchor recorded by start(). Only `start()` and friends
            // emit a non-zero hash here.
            if adv.snapshot_tip_hash != [0u8; 32] {
                wb.put_cf(&cf_meta, cur::META_KEY_SNAPSHOT_HASH, adv.snapshot_tip_hash);
            }
        }

        // Metadata: filter-index backfill cursor advance. Atomic with
        // the cf_filter / cf_filter_header writes above so a kill -9
        // mid-batch leaves cursor and rows in lockstep.
        #[cfg(feature = "block-filter-index")]
        if let Some(adv) = &batch.filter_backfill_cursor_advance {
            use node_filter_index::cursor as fcur;
            wb.put_cf(&cf_meta, fcur::META_KEY_STATE, [adv.state.as_byte()]);
            wb.put_cf(
                &cf_meta,
                fcur::META_KEY_CURSOR_HEIGHT,
                adv.cursor_height.to_be_bytes(),
            );
            wb.put_cf(
                &cf_meta,
                fcur::META_KEY_SNAPSHOT_HEIGHT,
                adv.snapshot_height.to_be_bytes(),
            );
            wb.put_cf(
                &cf_meta,
                fcur::META_KEY_STARTED_AT,
                adv.started_at_unix.to_be_bytes(),
            );
            if adv.snapshot_tip_hash != [0u8; 32] {
                wb.put_cf(
                    &cf_meta,
                    fcur::META_KEY_SNAPSHOT_HASH,
                    adv.snapshot_tip_hash,
                );
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
            let hist_bytes =
                bincode::serialize(&hist).map_err(|e| StoreError::Serialization(e.to_string()))?;
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

        // Atomic commit across all column families.
        // In BulkLoad mode we skip the WAL — the writer (connect loop during
        // IBD) is responsible for calling `flush_durable` periodically so the
        // amount of work lost on crash is bounded. `atomic_flush(true)` +
        // `DataStored`-vs-`Valid` block-index markers ensure recovery is
        // consistent: on restart any `DataStored` block not reflected in the
        // tip pointer simply gets re-connected.
        let mut wopts = WriteOptions::default();
        if mode == WriteMode::BulkLoad {
            wopts.disable_wal(true);
        }
        // Snapshot row counts before the write so we only bump
        // committed-row counters after the write succeeds. Pre-commit
        // emission (the previous behavior) leaked counts from blocks
        // that produced a batch but failed validation later in the
        // pipeline.
        let funding_put_count = batch.addr_funding_puts.len() as u64;
        let funding_remove_count = batch.addr_funding_removes.len() as u64;
        let spending_put_count = batch.addr_spending_puts.len() as u64;
        let spending_remove_count = batch.addr_spending_removes.len() as u64;
        self.db
            .write_opt(wb, &wopts)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        if funding_put_count > 0 {
            crate::index::address::stats::add_funding_rows(funding_put_count);
        }
        if funding_remove_count > 0 {
            crate::index::address::stats::add_funding_removes(funding_remove_count);
        }
        if spending_put_count > 0 {
            crate::index::address::stats::add_spending_rows(spending_put_count);
        }
        if spending_remove_count > 0 {
            crate::index::address::stats::add_spending_removes(spending_remove_count);
        }
        Ok(())
    }

    fn flush_durable(&self) -> Result<(), StoreError> {
        // Synchronous flush of every column family's memtable to SST files.
        // With `atomic_flush(true)` set at DB open time, all CFs are flushed
        // atomically — either the post-flush state is fully persisted or
        // nothing is. `wait(true)` ensures the call returns only once the
        // flush is durable on disk.
        let mut fopts = FlushOptions::default();
        fopts.set_wait(true);
        self.db
            .flush_opt(&fopts)
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    fn resize_block_cache(&self, bytes: usize) {
        // The RocksDB `Cache` is an Arc-wrapped handle over a thread-safe C++
        // LRU. `set_capacity` takes `&mut self` for Rust borrow-checker
        // reasons only; the underlying FFI is safe to call concurrently.
        // We hold a Mutex<Cache> purely to satisfy the signature.
        let mut cache = self.block_cache.lock();
        cache.set_capacity(bytes);
        self.block_cache_capacity
            .store(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    fn block_cache_capacity_bytes(&self) -> usize {
        self.block_cache_capacity
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn chainstate_l0_files(&self) -> u64 {
        let cf = self.cf(CF_COINS);
        self.db
            .property_int_value_cf(&cf, "rocksdb.num-files-at-level0")
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    fn chainstate_pending_compaction_bytes(&self) -> u64 {
        let cf = self.cf(CF_COINS);
        self.db
            .property_int_value_cf(&cf, "rocksdb.estimate-pending-compaction-bytes")
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    fn compact_chainstate(&self) -> Result<(), StoreError> {
        // Full-range manual compaction of the coins CF. Synchronous: returns
        // once RocksDB finishes the compaction. With None/None bounds we
        // sweep every level of the CF, which is what the periodic compactor
        // wants when L0 has accumulated faster than the background scheduler
        // can drain it. We deliberately do not pass `CompactOptions` to
        // change exclusive_manual_compaction; the default (true) blocks
        // automatic compactions on this CF for the duration, which is fine
        // because we're forcing the work anyway.
        let cf = self.cf(CF_COINS);
        self.db
            .compact_range_cf::<&[u8], &[u8]>(&cf, None, None);
        // compact_range_cf is fire-and-wait in the FFI; the call returns
        // only after compaction completes. There is no error channel from
        // the C++ side here — failures surface via subsequent operations.
        Ok(())
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
        let mut cfs = if self.txindex_enabled {
            vec![CF_COINS, CF_UNDO, CF_METADATA, CF_TX_INDEX]
        } else {
            vec![CF_COINS, CF_UNDO, CF_METADATA]
        };
        // Address-history index sits in chainstate and must clear too,
        // otherwise -reindex-chainstate would leave stale rows that
        // reference UTXOs the new chainstate is about to overwrite.
        cfs.push(CF_ADDR_FUNDING);
        cfs.push(CF_ADDR_SPENDING);
        cfs.push(CF_OUTPOINT_SPEND);
        // Same reasoning for the BIP 158 filter index: -reindex-chainstate
        // is going to rebuild filters from genesis via the normal
        // connect_block emit path.
        #[cfg(feature = "block-filter-index")]
        {
            cfs.push(CF_FILTER);
            cfs.push(CF_FILTER_HEADER);
        }
        for cf_name in cfs {
            self.drop_and_recreate_cf(cf_name)?;
        }
        // Backfill temp CF: drop wholesale (don't recreate — it's
        // lazily created when a backfill starts). After clear_chainstate
        // any in-flight backfill cursor in metadata is also gone, so
        // leaving the temp CF would orphan its data.
        self.drop_backfill_temp_cf()?;
        // Re-stamp schema version after metadata CF was recreated
        Self::stamp_schema(&self.db, CURRENT_SCHEMA_VERSION)?;
        // Re-stamp outpoint_spend.complete + tx_index.complete +
        // address_index.complete: -reindex-chainstate produces a
        // from-empty re-population which connect_block will fill
        // atomically across all index CFs (round-3 H1, round-2-review
        // H2). Without the address re-stamp the operator's documented
        // remediation (`--reindex-chainstate`) would silently leave
        // Electrum / Esplora address surfaces refusing to bind.
        self.write_outpoint_spend_complete(true)?;
        self.write_tx_index_complete(true)?;
        self.write_address_index_complete(true)?;
        #[cfg(feature = "block-filter-index")]
        self.write_block_filter_index_complete(true)?;
        Ok(())
    }

    fn clear_all(&self) -> Result<(), StoreError> {
        let mut all_cfs: Vec<&str> = vec![
            CF_BLOCK_INDEX,
            CF_COINS,
            CF_HEIGHT_INDEX,
            CF_UNDO,
            CF_METADATA,
            CF_TX_INDEX,
            CF_ADDR_FUNDING,
            CF_ADDR_SPENDING,
            CF_OUTPOINT_SPEND,
        ];
        #[cfg(feature = "block-filter-index")]
        {
            all_cfs.push(CF_FILTER);
            all_cfs.push(CF_FILTER_HEADER);
        }
        for cf_name in all_cfs {
            self.drop_and_recreate_cf(cf_name)?;
        }
        // Backfill temp CF: drop without recreate (lazy create on first
        // backfill start). See clear_chainstate.
        self.drop_backfill_temp_cf()?;
        // Re-stamp schema version after metadata CF was recreated
        Self::stamp_schema(&self.db, CURRENT_SCHEMA_VERSION)?;
        // Same three completeness markers as `clear_chainstate` —
        // see comment there for the round-2-review H2 rationale.
        self.write_outpoint_spend_complete(true)?;
        self.write_tx_index_complete(true)?;
        self.write_address_index_complete(true)?;
        #[cfg(feature = "block-filter-index")]
        self.write_block_filter_index_complete(true)?;
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
            .enumerate()
            .map(|(i, result)| {
                result.ok().flatten().and_then(|v| {
                    let coin = Coin::deserialize_compact(&v);
                    if coin.is_none() {
                        tracing::error!(
                            "corrupt coin: failed to deserialize {} bytes for {}:{}",
                            v.len(),
                            outpoints[i].txid,
                            outpoints[i].vout
                        );
                    }
                    coin
                })
            })
            .collect()
    }

    fn iter_addr_funding(
        &self,
        sh: &crate::index::address::Scripthash,
    ) -> Vec<(crate::index::address::AddrFundingKey, u64)> {
        self.iter_addr_funding_limited(sh, usize::MAX)
    }

    fn iter_addr_funding_limited(
        &self,
        sh: &crate::index::address::Scripthash,
        limit: usize,
    ) -> Vec<(crate::index::address::AddrFundingKey, u64)> {
        let cf = self.cf(CF_ADDR_FUNDING);
        // The CF carries a 32-byte fixed prefix-extractor, so
        // `prefix_iterator_cf` short-circuits via the matching SST
        // index/bloom and terminates at the first row whose first 32
        // bytes leave the prefix. With a `limit`, we stop iterating
        // once we've collected that many rows — `usize::MAX` is the
        // unlimited sentinel used by the unbounded `iter_addr_funding`
        // wrapper above.
        let mut out: Vec<(crate::index::address::AddrFundingKey, u64)> = Vec::new();
        for item in self.db.prefix_iterator_cf(&cf, sh) {
            if out.len() >= limit {
                break;
            }
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            // Defensive: prefix_iterator may yield trailing rows whose
            // prefix is past `sh` once the underlying memtable was
            // compacted across the prefix boundary. Verify before
            // decoding.
            if k.len() < 32 || &k[..32] != sh {
                break;
            }
            let key = match crate::index::address::decode_funding_key(&k) {
                Some(k) => k,
                None => continue,
            };
            let amount = match crate::index::address::decode_funding_value(&v) {
                Some(a) => a,
                None => continue,
            };
            out.push((key, amount));
        }
        out
    }

    fn iter_addr_spending(
        &self,
        sh: &crate::index::address::Scripthash,
    ) -> Vec<(crate::index::address::AddrSpendingKey, OutPoint)> {
        self.iter_addr_spending_limited(sh, usize::MAX)
    }

    fn iter_addr_spending_limited(
        &self,
        sh: &crate::index::address::Scripthash,
        limit: usize,
    ) -> Vec<(crate::index::address::AddrSpendingKey, OutPoint)> {
        let cf = self.cf(CF_ADDR_SPENDING);
        let mut out: Vec<(crate::index::address::AddrSpendingKey, OutPoint)> = Vec::new();
        for item in self.db.prefix_iterator_cf(&cf, sh) {
            if out.len() >= limit {
                break;
            }
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if k.len() < 32 || &k[..32] != sh {
                break;
            }
            let key = match crate::index::address::decode_spending_key(&k) {
                Some(k) => k,
                None => continue,
            };
            let prev = match crate::index::address::decode_spending_value(&v) {
                Some(p) => p,
                None => continue,
            };
            out.push((key, prev));
        }
        out
    }

    fn outpoint_spend_complete(&self) -> bool {
        // Default to false when the metadata key is missing — that
        // shouldn't happen post-`open()` but we'd rather under-claim
        // completeness than over-claim it.
        self.read_outpoint_spend_complete().unwrap_or(false)
    }

    fn mark_outpoint_spend_complete(&self) -> Result<(), StoreError> {
        self.write_outpoint_spend_complete(true)
    }

    fn tx_index_complete(&self) -> bool {
        self.read_tx_index_complete().unwrap_or(false)
    }

    fn address_index_complete(&self) -> bool {
        // Default false when the marker is missing — under-claim
        // rather than over-claim. Round-1 review H2.
        self.read_address_index_complete().unwrap_or(false)
    }

    fn mark_address_index_complete(&self) -> Result<(), StoreError> {
        self.write_address_index_complete(true)
    }

    #[cfg(feature = "block-filter-index")]
    fn get_filter(&self, filter_type: u8, height: u32) -> Option<Vec<u8>> {
        let cf = self.cf(CF_FILTER);
        let key = node_filter_index::encode_filter_key(&node_filter_index::FilterKey {
            filter_type,
            height,
        });
        self.db.get_cf(&cf, key).ok().flatten()
    }

    #[cfg(feature = "block-filter-index")]
    fn get_filter_header(&self, filter_type: u8, height: u32) -> Option<[u8; 32]> {
        let cf = self.cf(CF_FILTER_HEADER);
        let key = node_filter_index::encode_filter_key(&node_filter_index::FilterKey {
            filter_type,
            height,
        });
        let v = self.db.get_cf(&cf, key).ok().flatten()?;
        if v.len() != 32 {
            tracing::error!(
                target: "storage",
                "filter header at height {} has unexpected length {} (want 32)",
                height,
                v.len()
            );
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Some(out)
    }

    #[cfg(feature = "block-filter-index")]
    fn block_filter_index_complete(&self) -> bool {
        // Default false when the marker is missing — under-claim
        // rather than over-claim. Same convention as
        // `address_index_complete`.
        self.read_block_filter_index_complete().unwrap_or(false)
    }

    #[cfg(feature = "block-filter-index")]
    fn mark_block_filter_index_complete(&self) -> Result<(), StoreError> {
        self.write_block_filter_index_complete(true)
    }

    fn lookup_spend(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<node_index::SpendingRef>, StoreError> {
        let cf = self.cf(CF_OUTPOINT_SPEND);
        let key = node_index::encode_outpoint_key(outpoint);
        match self.db.get_cf(&cf, key) {
            Ok(Some(v)) => match node_index::decode_spend_value(&v) {
                Some(sref) => Ok(Some(sref)),
                None => {
                    // A row exists but its value is malformed. Fail
                    // loud so corruption is visible — silently
                    // returning None would mask a real spend as
                    // unspent in the answers `SpendIndex` callers
                    // rely on (Esplora outspend, gettxspendingprevout).
                    let msg = format!(
                        "outpoint_spend: corrupt value for {}:{} (got {} bytes)",
                        outpoint.txid,
                        outpoint.vout,
                        v.len()
                    );
                    tracing::error!(target: "storage", "{}", msg);
                    Err(StoreError::Database(msg))
                }
            },
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Database(e.to_string())),
        }
    }

    fn create_backfill_temp_cf(&self) -> Result<(), StoreError> {
        if self.db.cf_handle(CF_ADDR_BACKFILL_TEMP).is_some() {
            return Ok(());
        }
        // Bloom + 16-byte prefix-extractor (txid prefix). We lookup by
        // exact 36-byte key, but a prefix of the txid is enough to bucket
        // bloom checks usefully. Write buffer 32 MB matches the addr CFs.
        let mut cf_opts = Options::default();
        let mut table_opts = BlockBasedOptions::default();
        table_opts.set_block_cache(&self.block_cache.lock());
        table_opts.set_block_size(16 * 1024);
        table_opts.set_cache_index_and_filter_blocks(true);
        table_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        table_opts.set_format_version(5);
        table_opts.set_bloom_filter(10.0, false);
        table_opts.set_whole_key_filtering(true);
        cf_opts.set_block_based_table_factory(&table_opts);
        cf_opts.set_write_buffer_size(32 * 1024 * 1024);
        cf_opts.set_max_write_buffer_number(3);
        cf_opts.set_level_compaction_dynamic_level_bytes(true);
        cf_opts.set_max_bytes_for_level_base(512 * 1024 * 1024);
        cf_opts.set_target_file_size_base(64 * 1024 * 1024);
        // Compress aggressively — temp CF is write-heavy then drop;
        // bottommost compression doesn't matter because compaction
        // rarely catches up before drop.
        cf_opts.set_compression_type(DBCompressionType::Lz4);
        self.db
            .create_cf(CF_ADDR_BACKFILL_TEMP, &cf_opts)
            .map_err(|e| {
                StoreError::Database(format!("create_cf({}): {}", CF_ADDR_BACKFILL_TEMP, e))
            })
    }

    fn drop_backfill_temp_cf(&self) -> Result<(), StoreError> {
        if self.db.cf_handle(CF_ADDR_BACKFILL_TEMP).is_none() {
            return Ok(());
        }
        self.db
            .drop_cf(CF_ADDR_BACKFILL_TEMP)
            .map_err(|e| StoreError::Database(format!("drop_cf({}): {}", CF_ADDR_BACKFILL_TEMP, e)))
    }

    fn backfill_temp_cf_exists(&self) -> bool {
        self.db.cf_handle(CF_ADDR_BACKFILL_TEMP).is_some()
    }

    fn lookup_backfill_temp(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<crate::index::address::Scripthash>, StoreError> {
        let cf = match self.db.cf_handle(CF_ADDR_BACKFILL_TEMP) {
            Some(c) => c,
            None => return Ok(None),
        };
        let key = backfill_temp_key(outpoint);
        match self.db.get_cf(&cf, key) {
            Ok(Some(v)) => {
                if v.len() != 32 {
                    return Err(StoreError::Database(format!(
                        "corrupt backfill temp value: {} bytes (expected 32)",
                        v.len()
                    )));
                }
                let mut sh = [0u8; 32];
                sh.copy_from_slice(&v);
                Ok(Some(sh))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Database(e.to_string())),
        }
    }

    fn read_backfill_cursor(&self) -> crate::index::address::cursor::BackfillCursor {
        use crate::index::address::cursor as cur;
        let cf = self.cf(CF_METADATA);
        let read_u8 = |k: &[u8]| -> Option<u8> {
            self.db
                .get_cf(&cf, k)
                .ok()
                .flatten()
                .and_then(|v| v.first().copied())
        };
        let read_u32_be = |k: &[u8]| -> Option<u32> {
            self.db.get_cf(&cf, k).ok().flatten().and_then(|v| {
                if v.len() == 4 {
                    Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
                } else {
                    None
                }
            })
        };
        let read_u64_be = |k: &[u8]| -> Option<u64> {
            self.db.get_cf(&cf, k).ok().flatten().and_then(|v| {
                if v.len() == 8 {
                    Some(u64::from_be_bytes([
                        v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
                    ]))
                } else {
                    None
                }
            })
        };
        let snapshot_tip_hash: [u8; 32] = self
            .db
            .get_cf(&cf, cur::META_KEY_SNAPSHOT_HASH)
            .ok()
            .flatten()
            .and_then(|v| {
                if v.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&v);
                    Some(h)
                } else {
                    None
                }
            })
            .unwrap_or([0u8; 32]);
        cur::BackfillCursor {
            state: read_u8(cur::META_KEY_STATE)
                .map(cur::BackfillState::from_byte)
                .unwrap_or(cur::BackfillState::Idle),
            pass: read_u8(cur::META_KEY_PASS).unwrap_or(0),
            cursor_height: read_u32_be(cur::META_KEY_CURSOR_HEIGHT).unwrap_or(0),
            snapshot_height: read_u32_be(cur::META_KEY_SNAPSHOT_HEIGHT).unwrap_or(0),
            started_at_unix: read_u64_be(cur::META_KEY_STARTED_AT).unwrap_or(0),
            snapshot_tip_hash,
        }
    }

    fn read_backfill_last_error(&self) -> Option<String> {
        use crate::index::address::cursor as cur;
        let cf = self.cf(CF_METADATA);
        self.db
            .get_cf(&cf, cur::META_KEY_LAST_ERROR)
            .ok()
            .flatten()
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
            .filter(|s| !s.is_empty())
    }

    fn write_backfill_last_error(&self, msg: &str) -> Result<(), StoreError> {
        use crate::index::address::cursor as cur;
        let cf = self.cf(CF_METADATA);
        // Truncate to LAST_ERROR_MAX_BYTES at a UTF-8 char boundary so
        // we never persist invalid UTF-8.
        let bytes = if msg.len() <= cur::LAST_ERROR_MAX_BYTES {
            msg.as_bytes().to_vec()
        } else {
            let mut idx = cur::LAST_ERROR_MAX_BYTES;
            while idx > 0 && !msg.is_char_boundary(idx) {
                idx -= 1;
            }
            msg.as_bytes()[..idx].to_vec()
        };
        if bytes.is_empty() {
            // Empty string clears the slot.
            self.db
                .delete_cf(&cf, cur::META_KEY_LAST_ERROR)
                .map_err(|e| StoreError::Database(e.to_string()))
        } else {
            self.db
                .put_cf(&cf, cur::META_KEY_LAST_ERROR, &bytes)
                .map_err(|e| StoreError::Database(e.to_string()))
        }
    }

    #[cfg(feature = "block-filter-index")]
    fn read_filter_backfill_cursor(&self) -> node_filter_index::cursor::BackfillCursor {
        use node_filter_index::cursor as fcur;
        let cf = self.cf(CF_METADATA);
        let read_u8 = |k: &[u8]| -> Option<u8> {
            self.db
                .get_cf(&cf, k)
                .ok()
                .flatten()
                .and_then(|v| v.first().copied())
        };
        let read_u32_be = |k: &[u8]| -> Option<u32> {
            self.db.get_cf(&cf, k).ok().flatten().and_then(|v| {
                if v.len() == 4 {
                    Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
                } else {
                    None
                }
            })
        };
        let read_u64_be = |k: &[u8]| -> Option<u64> {
            self.db.get_cf(&cf, k).ok().flatten().and_then(|v| {
                if v.len() == 8 {
                    Some(u64::from_be_bytes([
                        v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
                    ]))
                } else {
                    None
                }
            })
        };
        let snapshot_tip_hash: [u8; 32] = self
            .db
            .get_cf(&cf, fcur::META_KEY_SNAPSHOT_HASH)
            .ok()
            .flatten()
            .and_then(|v| {
                if v.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&v);
                    Some(h)
                } else {
                    None
                }
            })
            .unwrap_or([0u8; 32]);
        fcur::BackfillCursor {
            state: read_u8(fcur::META_KEY_STATE)
                .map(fcur::BackfillState::from_byte)
                .unwrap_or(fcur::BackfillState::Idle),
            cursor_height: read_u32_be(fcur::META_KEY_CURSOR_HEIGHT).unwrap_or(0),
            snapshot_height: read_u32_be(fcur::META_KEY_SNAPSHOT_HEIGHT).unwrap_or(0),
            started_at_unix: read_u64_be(fcur::META_KEY_STARTED_AT).unwrap_or(0),
            snapshot_tip_hash,
        }
    }

    #[cfg(feature = "block-filter-index")]
    fn read_filter_backfill_last_error(&self) -> Option<String> {
        use node_filter_index::cursor as fcur;
        let cf = self.cf(CF_METADATA);
        self.db
            .get_cf(&cf, fcur::META_KEY_LAST_ERROR)
            .ok()
            .flatten()
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
            .filter(|s| !s.is_empty())
    }

    #[cfg(feature = "block-filter-index")]
    fn write_filter_backfill_last_error(&self, msg: &str) -> Result<(), StoreError> {
        use node_filter_index::cursor as fcur;
        let cf = self.cf(CF_METADATA);
        let bytes = if msg.len() <= fcur::LAST_ERROR_MAX_BYTES {
            msg.as_bytes().to_vec()
        } else {
            let mut idx = fcur::LAST_ERROR_MAX_BYTES;
            while idx > 0 && !msg.is_char_boundary(idx) {
                idx -= 1;
            }
            msg.as_bytes()[..idx].to_vec()
        };
        if bytes.is_empty() {
            self.db
                .delete_cf(&cf, fcur::META_KEY_LAST_ERROR)
                .map_err(|e| StoreError::Database(e.to_string()))
        } else {
            self.db
                .put_cf(&cf, fcur::META_KEY_LAST_ERROR, &bytes)
                .map_err(|e| StoreError::Database(e.to_string()))
        }
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

    fn temp_store(txindex: bool) -> (RocksDbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbStore::open(dir.path(), txindex, 16, false, -1).unwrap();
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
    fn block_index_header_only_does_not_clobber_data_stored() {
        // Reproduces the race the cache layer's dominance check closes,
        // mirrored at the RocksDB layer: a HeaderOnly write arriving
        // after a DataStored/Valid write for the same hash must be
        // dropped, not allowed to downgrade the on-disk entry.
        let (store, _dir) = temp_store(false);
        let (hash, mut datastored) = regtest_genesis_entry();
        datastored.status = BlockStatus::DataStored;
        datastored.file_number = 7;
        datastored.data_pos = 1234;

        let mut batch1 = StoreBatch::default();
        batch1.block_index_puts.push((hash, datastored.clone()));
        store.write_batch(batch1).unwrap();
        assert_eq!(
            store.get_block_index(&hash).unwrap().status,
            BlockStatus::DataStored
        );

        // Now attempt a HeaderOnly write (simulating accept_headers
        // racing a store_block that just landed). Must be a silent
        // no-op, not a downgrade.
        let header_only = BlockIndexEntry {
            status: BlockStatus::HeaderOnly,
            file_number: 0,
            data_pos: 0,
            ..datastored.clone()
        };
        let mut batch2 = StoreBatch::default();
        batch2.block_index_puts.push((hash, header_only));
        store.write_batch(batch2).unwrap();

        let recovered = store.get_block_index(&hash).unwrap();
        assert_eq!(
            recovered.status,
            BlockStatus::DataStored,
            "HeaderOnly write must not clobber DataStored"
        );
        assert_eq!(recovered.file_number, 7);
        assert_eq!(recovered.data_pos, 1234);
    }

    #[test]
    fn block_index_upgrades_apply_normally() {
        // The dominance filter is one-directional. A HeaderOnly → Valid
        // upgrade must still apply (this is the normal flow:
        // accept_headers writes HeaderOnly, then store_block + connect
        // upgrade to DataStored/Valid).
        let (store, _dir) = temp_store(false);
        let (hash, mut header_only) = regtest_genesis_entry();
        header_only.status = BlockStatus::HeaderOnly;
        header_only.file_number = 0;
        header_only.data_pos = 0;

        let mut batch1 = StoreBatch::default();
        batch1.block_index_puts.push((hash, header_only.clone()));
        store.write_batch(batch1).unwrap();
        assert_eq!(
            store.get_block_index(&hash).unwrap().status,
            BlockStatus::HeaderOnly
        );

        // DataStored upgrade applies.
        let datastored = BlockIndexEntry {
            status: BlockStatus::DataStored,
            file_number: 3,
            data_pos: 99,
            ..header_only.clone()
        };
        let mut batch2 = StoreBatch::default();
        batch2.block_index_puts.push((hash, datastored));
        store.write_batch(batch2).unwrap();

        let recovered = store.get_block_index(&hash).unwrap();
        assert_eq!(recovered.status, BlockStatus::DataStored);
        assert_eq!(recovered.file_number, 3);
        assert_eq!(recovered.data_pos, 99);

        // Valid upgrade applies.
        let valid = BlockIndexEntry {
            status: BlockStatus::Valid,
            ..recovered
        };
        let mut batch3 = StoreBatch::default();
        batch3.block_index_puts.push((hash, valid));
        store.write_batch(batch3).unwrap();
        assert_eq!(
            store.get_block_index(&hash).unwrap().status,
            BlockStatus::Valid
        );
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

        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xBB; 32]));
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

        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xDD; 32]));
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
        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xEE; 32]));

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
        assert_eq!(store.get_block_hash_by_height(0).unwrap(), genesis_hash);
        assert_eq!(store.get_tx_location(&txid).unwrap(), genesis_hash);
    }

    #[test]
    fn test_clear_chainstate() {
        let (store, _dir) = temp_store(true);
        let (hash, entry) = regtest_genesis_entry();
        let op = make_outpoint(0x10, 0);
        let coin = make_coin(999, 0);
        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xEE; 32]));

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

    #[test]
    fn test_address_index_cfs_created_on_open() {
        let (store, _dir) = temp_store(false);
        // CF handles must resolve. cf() panics on missing CF, so this
        // exercises the descriptor registration path end-to-end.
        let _af = store.cf(CF_ADDR_FUNDING);
        let _as_ = store.cf(CF_ADDR_SPENDING);
    }

    #[test]
    fn test_address_index_cfs_persist_across_reopen() {
        // Auto-creation should also be idempotent: reopening an
        // existing datadir must not error and must keep the CFs.
        let dir = tempfile::tempdir().unwrap();
        {
            let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
            let _af = store.cf(CF_ADDR_FUNDING);
        }
        let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        let _af = store.cf(CF_ADDR_FUNDING);
        let _as_ = store.cf(CF_ADDR_SPENDING);
    }

    #[test]
    fn test_address_index_write_batch_funding_put_then_read() {
        use crate::index::address::{AddrFundingRow, encode_funding_key, encode_funding_value};

        let (store, _dir) = temp_store(false);
        let row = AddrFundingRow {
            scripthash: [0xAB; 32],
            height: 42,
            txid: make_outpoint(0xCD, 0).txid,
            vout: 7,
            amount_sat: 123_456_789,
        };

        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(row.clone());
        store.write_batch(batch).unwrap();

        // Read directly via the encoded key — verifies the writer
        // serialized exactly what the codec specifies.
        let cf = store.cf(CF_ADDR_FUNDING);
        let encoded = encode_funding_key(&row.key());
        let raw = store.db.get_cf(&cf, encoded).unwrap().expect("row present");
        assert_eq!(
            raw.as_slice(),
            encode_funding_value(row.amount_sat).as_slice()
        );
    }

    #[test]
    fn test_address_index_write_batch_spending_put_then_remove() {
        use crate::index::address::{AddrSpendingRow, encode_spending_key, encode_spending_value};

        let (store, _dir) = temp_store(false);
        let prev = make_outpoint(0xEE, 3);
        let row = AddrSpendingRow {
            scripthash: [0x10; 32],
            height: 99,
            txid: make_outpoint(0x55, 0).txid,
            vin: 2,
            prev_outpoint: prev,
        };

        // Put.
        let mut batch = StoreBatch::default();
        batch.addr_spending_puts.push(row.clone());
        store.write_batch(batch).unwrap();

        let cf = store.cf(CF_ADDR_SPENDING);
        let encoded_key = encode_spending_key(&row.key());
        let raw = store
            .db
            .get_cf(&cf, encoded_key)
            .unwrap()
            .expect("row present");
        assert_eq!(
            raw.as_slice(),
            encode_spending_value(&row.prev_outpoint).as_slice()
        );

        // Remove via the same key. Round-trips the deletion path used
        // by `disconnect_block` in M2.
        let mut rm = StoreBatch::default();
        rm.addr_spending_removes.push(row.key());
        store.write_batch(rm).unwrap();
        assert!(store.db.get_cf(&cf, encoded_key).unwrap().is_none());
    }

    #[test]
    fn test_outpoint_spend_write_batch_put_then_lookup() {
        let (store, _dir) = temp_store(false);
        let prev = make_outpoint(0x77, 2);
        let sref = node_index::SpendingRef {
            spending_txid: make_outpoint(0xab, 0).txid,
            spending_vin: 4,
            height: 100,
        };

        let mut batch = StoreBatch::default();
        batch.outpoint_spend_puts.push((prev, sref));
        store.write_batch(batch).unwrap();

        let got = store.lookup_spend(&prev).unwrap();
        assert_eq!(got, Some(sref));
    }

    #[test]
    fn test_outpoint_spend_write_batch_remove_clears_row() {
        let (store, _dir) = temp_store(false);
        let prev = make_outpoint(0x66, 0);
        let sref = node_index::SpendingRef {
            spending_txid: make_outpoint(0x99, 0).txid,
            spending_vin: 0,
            height: 7,
        };

        let mut put = StoreBatch::default();
        put.outpoint_spend_puts.push((prev, sref));
        store.write_batch(put).unwrap();
        assert!(store.lookup_spend(&prev).unwrap().is_some());

        let mut rm = StoreBatch::default();
        rm.outpoint_spend_removes.push(prev);
        store.write_batch(rm).unwrap();
        assert_eq!(store.lookup_spend(&prev).unwrap(), None);
    }

    #[test]
    fn test_outpoint_spend_lookup_unknown_returns_none() {
        let (store, _dir) = temp_store(false);
        let unknown = make_outpoint(0xff, 9);
        assert_eq!(store.lookup_spend(&unknown).unwrap(), None);
    }

    #[test]
    fn test_outpoint_spend_lookup_on_corrupt_value_returns_error() {
        let (store, _dir) = temp_store(false);
        let prev = make_outpoint(0xaa, 0);
        // Inject a malformed value (wrong length) directly via the CF
        // handle, bypassing the codec. This simulates an on-disk
        // corruption or a future codec mismatch.
        let cf = store.cf(CF_OUTPOINT_SPEND);
        let key = node_index::encode_outpoint_key(&prev);
        store
            .db
            .put_cf(&cf, key, b"too-short")
            .expect("inject corrupt row");

        match store.lookup_spend(&prev) {
            Err(StoreError::Database(msg)) => {
                assert!(
                    msg.contains("corrupt value"),
                    "expected corrupt diag, got {msg}"
                );
            }
            Err(other) => panic!("expected Database error, got {other:?}"),
            Ok(v) => panic!("expected Err on corrupt value, got Ok({v:?})"),
        }
    }

    #[test]
    fn test_outpoint_spend_complete_true_on_fresh_datadir() {
        let (store, _dir) = temp_store(false);
        // Fresh datadir → marker stamped true on first open.
        assert!(store.outpoint_spend_complete());
    }

    #[test]
    fn test_outpoint_spend_complete_false_on_legacy_upgrade() {
        // Simulate a pre-#99 datadir: addr_spending rows present, no
        // outpoint_spend marker. Open() must detect and stamp false.
        let dir = tempfile::tempdir().unwrap();
        {
            // First open: write a synthetic addr_spending row, then
            // delete the marker to simulate a pre-marker state.
            let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
            let row = crate::index::address::AddrSpendingRow {
                scripthash: [0x42; 32],
                height: 1,
                txid: make_outpoint(0xab, 0).txid,
                vin: 0,
                prev_outpoint: make_outpoint(0x55, 0),
            };
            let mut batch = StoreBatch::default();
            batch.addr_spending_puts.push(row);
            store.write_batch(batch).unwrap();
            // Wipe the marker (simulating a datadir from before this
            // schema bump).
            let cf = store.cf(CF_METADATA);
            store
                .db
                .delete_cf(&cf, OUTPOINT_SPEND_COMPLETE_KEY)
                .unwrap();
        }
        let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        assert!(!store.outpoint_spend_complete());
    }

    #[test]
    fn test_outpoint_spend_complete_marker_persists_across_reopen() {
        // Once stamped false, the warning must keep firing on each
        // restart even after live connect_block has appended new
        // outpoint_spend rows. (Round-2 H6 contract.)
        let dir = tempfile::tempdir().unwrap();
        {
            let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
            // Force the marker false via the helper; this is what
            // open() does when it detects a legacy datadir.
            store.write_outpoint_spend_complete(false).unwrap();
        }
        let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        assert!(!store.outpoint_spend_complete());
    }

    #[test]
    fn test_outpoint_spend_complete_after_clear_chainstate() {
        let (store, _dir) = temp_store(false);
        store.write_outpoint_spend_complete(false).unwrap();
        assert!(!store.outpoint_spend_complete());
        store.clear_chainstate().unwrap();
        // -reindex-chainstate stamps complete because every block
        // will be re-applied via connect_block.
        assert!(store.outpoint_spend_complete());
    }

    // ── address_index.complete marker (round-1 review H2) ────────

    #[test]
    fn test_address_index_complete_true_on_fresh_datadir() {
        let (store, _dir) = temp_store(false);
        // Fresh datadir → marker stamped true on first open. Mirrors
        // the outpoint_spend / tx_index pattern.
        assert!(store.address_index_complete());
    }

    #[test]
    fn test_address_index_complete_legacy_upgrade_stamps_false() {
        // Simulate an upgraded datadir: block_index has rows but the
        // address_index.complete marker was never stamped.
        let dir = tempfile::tempdir().unwrap();
        {
            let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
            // Synthesize a block_index row by writing a synthetic
            // value directly into the CF. The legacy-detection path
            // only checks "any row in CF_BLOCK_INDEX", not the row
            // shape, so we can sidestep the full BlockIndexEntry
            // serialization here.
            let cf_bi = store.cf(CF_BLOCK_INDEX);
            store.db.put_cf(&cf_bi, [0u8; 32], [0u8; 4]).unwrap();
            // Erase the marker so the next open sees a legacy state.
            let cf = store.cf(CF_METADATA);
            store.db.delete_cf(&cf, ADDRESS_INDEX_COMPLETE_KEY).unwrap();
        }
        let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        assert!(
            !store.address_index_complete(),
            "legacy datadir without marker must stamp false on open"
        );
    }

    #[test]
    fn test_address_index_complete_cleared_on_connect_with_addressindex_off() {
        // The bug round-1 H2 catches: with addressindex disabled,
        // a connecting block must clear the marker so future
        // electrum binds refuse.
        let (store, _dir) = temp_store(false);
        let store = store.with_addressindex_enabled(false);
        // Marker starts true on fresh datadir.
        assert!(store.address_index_complete());

        // Synthesize a connecting batch with a coin put. The marker
        // is cleared atomically with the write.
        let mut batch = StoreBatch::default();
        let outpoint = make_outpoint(0xaa, 0);
        let coin = crate::storage::Coin {
            amount: 1000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 100,
            coinbase: false,
        };
        batch.coin_puts.push((outpoint, coin));
        store.write_batch(batch).unwrap();

        assert!(
            !store.address_index_complete(),
            "connect-with-addressindex-off must clear the marker"
        );
    }

    #[test]
    fn test_address_index_complete_marker_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
            store.write_address_index_complete(false).unwrap();
        }
        let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        assert!(!store.address_index_complete());
    }

    #[test]
    fn test_mark_address_index_complete_stamps_true() {
        let (store, _dir) = temp_store(false);
        store.write_address_index_complete(false).unwrap();
        assert!(!store.address_index_complete());
        // The backfill-completion path stamps true.
        store.mark_address_index_complete().unwrap();
        assert!(store.address_index_complete());
    }

    #[test]
    fn test_address_index_complete_after_clear_chainstate() {
        // Round-2-review H2: -reindex-chainstate must re-stamp the
        // address marker alongside tx_index and outpoint_spend, or
        // the documented remediation leaves Electrum / Esplora
        // permanently refusing to bind.
        let (store, _dir) = temp_store(false);
        store.write_address_index_complete(false).unwrap();
        assert!(!store.address_index_complete());
        store.clear_chainstate().unwrap();
        assert!(
            store.address_index_complete(),
            "clear_chainstate must re-stamp address_index.complete"
        );
        // Sister markers should also be true (sanity check the
        // existing contract).
        assert!(store.tx_index_complete());
        assert!(store.outpoint_spend_complete());
    }

    #[test]
    fn test_address_index_complete_after_clear_all() {
        // Same contract for full --reindex via clear_all.
        let (store, _dir) = temp_store(false);
        store.write_address_index_complete(false).unwrap();
        assert!(!store.address_index_complete());
        store.clear_all().unwrap();
        assert!(
            store.address_index_complete(),
            "clear_all must re-stamp address_index.complete"
        );
    }

    // ── iter_addr_funding/spending_limited (round-1 review M4) ────

    #[test]
    fn test_iter_addr_funding_limited_aborts_at_cap() {
        use crate::index::address::AddrFundingRow;
        let (store, _dir) = temp_store(false);

        let sh = [0xab; 32];
        let mut batch = StoreBatch::default();
        for i in 0..50u32 {
            batch.addr_funding_puts.push(AddrFundingRow {
                scripthash: sh,
                height: i,
                txid: make_outpoint(0x10 + (i as u8 % 8), 0).txid,
                vout: i,
                amount_sat: 1000 + (i as u64),
            });
        }
        store.write_batch(batch).unwrap();

        // Unbounded read returns all 50 rows.
        assert_eq!(store.iter_addr_funding(&sh).len(), 50);

        // Limited read stops at the cap.
        assert_eq!(store.iter_addr_funding_limited(&sh, 10).len(), 10);
        assert_eq!(store.iter_addr_funding_limited(&sh, 0).len(), 0);
        // limit > total: returns total.
        assert_eq!(store.iter_addr_funding_limited(&sh, 100).len(), 50);
    }

    #[test]
    fn test_iter_addr_spending_limited_aborts_at_cap() {
        use crate::index::address::AddrSpendingRow;
        let (store, _dir) = temp_store(false);

        let sh = [0xcd; 32];
        let mut batch = StoreBatch::default();
        for i in 0..30u32 {
            batch.addr_spending_puts.push(AddrSpendingRow {
                scripthash: sh,
                height: i,
                txid: make_outpoint(0x20 + (i as u8 % 8), 0).txid,
                vin: 0,
                prev_outpoint: make_outpoint(0xff, i),
            });
        }
        store.write_batch(batch).unwrap();

        assert_eq!(store.iter_addr_spending(&sh).len(), 30);
        assert_eq!(store.iter_addr_spending_limited(&sh, 5).len(), 5);
    }

    #[test]
    fn test_outpoint_spend_persists_across_reopen() {
        // Verifies the CF descriptor is registered on subsequent opens
        // (so an existing chainstate-on-disk doesn't fail to mount).
        let dir = tempfile::tempdir().unwrap();
        let prev = make_outpoint(0x33, 1);
        let sref = node_index::SpendingRef {
            spending_txid: make_outpoint(0x44, 0).txid,
            spending_vin: 2,
            height: 50,
        };
        {
            let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
            let mut batch = StoreBatch::default();
            batch.outpoint_spend_puts.push((prev, sref));
            store.write_batch(batch).unwrap();
        }
        let store2 = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        assert_eq!(store2.lookup_spend(&prev).unwrap(), Some(sref));
    }

    #[test]
    fn test_address_index_empty_batch_does_not_touch_cfs() {
        // Sanity: the empty-batch fast-path in write_batch_mode must
        // not panic or write spurious rows.
        let (store, _dir) = temp_store(false);
        store.write_batch(StoreBatch::default()).unwrap();
        // Both CFs must still be empty.
        let af = store.cf(CF_ADDR_FUNDING);
        let as_ = store.cf(CF_ADDR_SPENDING);
        assert!(
            store
                .db
                .iterator_cf(&af, IteratorMode::Start)
                .next()
                .is_none()
        );
        assert!(
            store
                .db
                .iterator_cf(&as_, IteratorMode::Start)
                .next()
                .is_none()
        );
    }

    #[test]
    fn test_address_index_metrics_reflect_committed_rows_only() {
        use crate::index::address::{AddrFundingRow, AddrSpendingRow, scripthash_of, stats};

        // Use a fresh process snapshot to compute deltas — the static
        // counters accumulate across tests in the same binary.
        let before = stats::snapshot();

        let (store, _dir) = temp_store(false);
        let sh = scripthash_of(&bitcoin::ScriptBuf::new());
        let txid = bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [0xab; 32],
        ));

        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(AddrFundingRow {
            scripthash: sh,
            height: 1,
            txid,
            vout: 0,
            amount_sat: 1000,
        });
        batch.addr_spending_puts.push(AddrSpendingRow {
            scripthash: sh,
            height: 1,
            txid,
            vin: 0,
            prev_outpoint: bitcoin::OutPoint::null(),
        });
        store.write_batch(batch).unwrap();

        let after = stats::snapshot();
        // Counters are process-wide and other parallel tests can bump
        // them between snapshots, so assert >= our own contribution
        // rather than equality.
        assert!(
            after.funding_rows > before.funding_rows,
            "committed-rows counter must reflect successful write (before {}, after {})",
            before.funding_rows,
            after.funding_rows
        );
        assert!(
            after.spending_rows > before.spending_rows,
            "committed-rows counter must reflect successful write (before {}, after {})",
            before.spending_rows,
            after.spending_rows
        );
    }
}
