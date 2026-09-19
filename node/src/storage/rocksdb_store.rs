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
use crate::storage::profile::StorageTuning;
use crate::storage::undo::UndoData;
use crate::storage::{Store, StoreBatch, StoreError, WriteMode};
use node_index::TxSeq;

pub(crate) const CF_BLOCK_INDEX: &str = "block_index";
const CF_COINS: &str = "coins";
const CF_HEIGHT_INDEX: &str = "height_index";
pub(crate) const CF_UNDO: &str = "undo";
/// `txid -> txseq[5]`. The transaction index, re-keyed: instead of the
/// containing block's 32-byte hash, a 5-byte chain-order ordinal that
/// carries the block *and* the position within it. Point-lookup only.
const CF_TX_LOC: &str = "tx_loc";
/// `txseq[5] -> txid[32]`, the inverse of `tx_loc`. This is what lets
/// every other index key on ordinals instead of repeating the txid: the
/// storage layer resolves rows back to txids before they leave it, in
/// one batched `multi_get` per scan. Keys are dense and ascending, so
/// RocksDB's prefix-delta encoding compresses them to near nothing and
/// the family costs roughly what the txids themselves do.
const CF_TXSEQ_TXID: &str = "txseq_txid";
/// `first_txseq[5] -> height[4]`. One row per connected block.
/// `seek_for_prev` turns any ordinal back into its block; the difference
/// is the transaction's index within the block. Ungated — four bytes per
/// block, and every ordinal read needs it.
const CF_TXSEQ_BLOCK: &str = "txseq_block";
const CF_METADATA: &str = "metadata";
/// Cumulative-transaction-count index: `block_hash -> u64_le`. The value
/// is the number of transactions in the chain through (and including)
/// that block. Written by `connect_block` for active-chain blocks and by
/// the AssumeUTXO snapshot seed; backed by a one-shot startup backfill on
/// upgraded datadirs. Consumed by `getchaintxstats`. Hash-keyed, so a
/// reorg needs no deletion — a stale block's value stays correct for that
/// block and is simply not on the active chain.
const CF_CHAIN_TX: &str = "chain_tx";
/// Address-history CFs. Keys carry a 16-byte scripthash prefix rather
/// than a full 32-byte scripthash.
///
/// The funding side is `_v3`: `sh[16] || txseq[5] || vout[3]`, 32 bytes
/// a row against the 64 its predecessor took, because a chain-order
/// ordinal replaces the height and txid it used to carry — both
/// recoverable through `txseq_block` and `txseq_txid`.
///
/// The spending side is still `_v2`. Its suffix is fossilized from the
/// storage-format cleanup that dropped the unsuffixed CFs.
pub(crate) const CF_ADDR_FUNDING_V3: &str = "addr_funding_v3";
pub(crate) const CF_ADDR_SPENDING_V2: &str = "addr_spending_v2";
/// Confirmed-side spend index: `funding_txseq[5] || vout[3]` ->
/// `spending_txseq[5] || vin[3]`. Written alongside the address-index
/// spending rows; the two CFs answer different shapes of the same
/// question.
///
/// Sixteen bytes a row where the txid-keyed predecessor took
/// seventy-six: both ends are named by transaction ordinal, and the two
/// 32-byte hashes the old value carried are recovered through
/// `txseq_txid` in one batched lookup per scan. The 5-byte ordinal
/// prefix makes "every spend of transaction N" a prefix scan, replacing
/// the 32-byte txid prefix the old layout used for the same query.
const CF_SPENT: &str = "spent";
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
/// Width of a backfill temp-CF value: `scripthash[32] || txseq[5]`.
/// Pass 1 records both because pass 2 needs both and can recompute
/// neither without a second read of the funding output's block.
const TEMP_VALUE_LEN: usize = 32 + node_index::TXSEQ_LEN;

/// BIP 352 silent-payment tweak index. One row per block from taproot
/// activation upward, keyed `height_be[4]`. Always compiled (runtime
/// opt-in, not a cargo feature); single-sourced from the codec crate so
/// the name can never drift.
const CF_SP_TWEAKS: &str = node_sp_index::CF_SP_TWEAKS;

/// Every column family this store can create, plus RocksDB's default CF.
/// `flush_durable` flushes exactly this list (filtered to the CFs that
/// exist on the open DB), so a CF missing here would silently lose its
/// WAL-less (BulkLoad) writes on process exit. `open()` asserts every
/// descriptor it creates is listed — add new CFs HERE first.
const ALL_CFS: &[&str] = &[
    "default",
    CF_COINS,
    CF_BLOCK_INDEX,
    CF_HEIGHT_INDEX,
    CF_UNDO,
    CF_TX_LOC,
    CF_TXSEQ_TXID,
    CF_TXSEQ_BLOCK,
    CF_METADATA,
    CF_CHAIN_TX,
    CF_ADDR_FUNDING_V3,
    CF_ADDR_SPENDING_V2,
    CF_SPENT,
    // Gated exactly like the descriptors `open()` creates for them: on a
    // consensus-only build (`--no-default-features`) this store can never
    // create or write these CFs, so listing them would break the
    // "descriptor created => listed here" correspondence in both
    // directions.
    #[cfg(feature = "block-filter-index")]
    CF_FILTER,
    #[cfg(feature = "block-filter-index")]
    CF_FILTER_HEADER,
    CF_ADDR_BACKFILL_TEMP,
    CF_SP_TWEAKS,
];

/// Every column family the per-CF diagnostics report on, in
/// largest-by-observed-load order so the most operationally relevant
/// entries survive a truncated log line. This is the single source for
/// `query_cf_property`, `sst_bytes_by_cf` and `estimated_keys_by_cf`;
/// keeping one list means a new CF cannot be added to some diagnostics
/// and missed by others, which is how `chain_tx` went unreported for
/// three releases. `diag_cf_list_names_every_descriptor` asserts this
/// list and `ALL_CFS` name the same families.
const DIAG_CFS: &[&str] = &[
    CF_ADDR_SPENDING_V2,
    CF_ADDR_FUNDING_V3,
    CF_SPENT,
    CF_UNDO,
    CF_COINS,
    CF_TX_LOC,
    CF_TXSEQ_TXID,
    CF_TXSEQ_BLOCK,
    CF_BLOCK_INDEX,
    CF_HEIGHT_INDEX,
    CF_CHAIN_TX,
    CF_METADATA,
    #[cfg(feature = "block-filter-index")]
    CF_FILTER,
    #[cfg(feature = "block-filter-index")]
    CF_FILTER_HEADER,
    CF_ADDR_BACKFILL_TEMP,
    CF_SP_TWEAKS,
];

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
const SPENT_COMPLETE_KEY: &[u8] = b"spent.complete";
/// `tx_loc.complete` metadata flag — symmetric to
/// `outpoint_spend.complete` but for the transaction-ordinal families
/// that back `getrawtransaction` / `gettxlocation` and Esplora's
/// `/tx/:txid` confirmed-side lookup. Stamped true on fresh datadir, on
/// `clear_chainstate` / `clear_all`. False when an upgraded datadir has
/// historical block-index entries but the ordinal families are empty
/// (the operator previously ran with both indexes off). (Round-3 H1.)
///
/// A new key rather than a rename of `tx_index.complete`: a schema-4
/// datadir is the only one that can reach this code, and the old key's
/// value described a column family that no longer exists.
const TX_LOC_COMPLETE_KEY: &[u8] = b"tx_loc.complete";
/// `chain_tx.backfill_complete` metadata flag. True once the one-shot
/// cumulative-tx-count backfill has populated `CF_CHAIN_TX` for the
/// active chain. Absent/false on an upgraded datadir before the backfill
/// runs; stamped true on fresh datadirs and after the backfill completes.
const CHAIN_TX_BACKFILL_COMPLETE_KEY: &[u8] = b"chain_tx.backfill_complete";
/// Lowest height whose block data this node still holds — Core's
/// `pruneheight`. Absent on a node that has never pruned, which is exactly
/// how Core decides whether to emit the field at all.
const PRUNE_HEIGHT_KEY: &[u8] = b"prune.height";
/// Persisted "address-history index is complete for the active chain"
/// marker. Mirrors `TX_LOC_COMPLETE_KEY` — set true after a clean
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
// v2: compact varint coins. v3: storage-format cleanup — v1 undo
// dual-read and v1 address-history CFs were dropped. v4: the
// transaction index is keyed on dense chain-order ordinals (`tx_loc`,
// `txseq_txid`, `txseq_block`) instead of `txid -> block_hash`. v5:
// coins carry their funding transaction's ordinal and the spend index
// (`spent`) is keyed on it. v6: address-index funding rows key on it
// too (`addr_funding_v3`).
//
// A chainstate stamped at any earlier version is refused: the binary
// cannot read rows in a layout it no longer knows, and there is no
// in-place upgrade because the new families have to be built from the
// blocks. `-reindex-chainstate` rebuilds them in one pass.
const CURRENT_SCHEMA_VERSION: u32 = 6;

/// Column families this binary no longer creates or reads. Discovered on
/// open, declared bare so RocksDB will mount the DB at all, and dropped
/// immediately after the schema check has confirmed the chainstate is at
/// the current version (so a datadir that still *depends* on their rows
/// is refused before they are discarded).
///
/// `addr_funding` / `addr_spending` are the pre-cleanup address-history
/// CFs; `tx_index` is the txid-keyed transaction index that the ordinal
/// families replaced in schema 4.
const RETIRED_CF_NAMES: &[&str] = &[
    "addr_funding",
    "addr_spending",
    "tx_index",
    "outpoint_spend",
    "addr_funding_v2",
];

/// Resolve raw v3 funding rows into the public `(AddrFundingKey, amount)`
/// shape and put them in the documented `(height, txid, vout)` order.
///
/// On-disk the rows are ordinal-keyed, so a prefix scan already yields
/// them in chain order — which differs from the documented order only in
/// how transactions of the *same block* tie-break. The sort settles
/// that, so the iteration order the trait promises, and every consumer
/// that relies on it (the lockstep merge in
/// `confirmed_distinct_history_limited`, Electrum's `listunspent`), is
/// unchanged by the re-keying.
///
/// "txid order" is `Txid`'s own `Ord`: its internal byte order, which is
/// what the previous schema laid down on disk (the key carried the raw
/// 32 bytes) and what the lockstep merge compares by. Display-hex order
/// is the *reverse* byte order, and sorting by it would put the two
/// streams the merge consumes out of step with each other.
///
/// One batched resolution for the whole scan, not one per row: see
/// [`crate::index::resolve::resolve_txseqs`].
///
/// A row whose ordinal does not resolve is local corruption — the rows
/// are written in the same atomic batch as the ordinal families — so it
/// is logged and skipped rather than emitted with an invented txid a
/// consumer would read as real.
pub(crate) fn resolve_funding_rows_for(
    store: &dyn Store,
    sh: &crate::index::address::Scripthash,
    raw: Vec<(u64, u32, u64)>,
) -> Vec<(crate::index::address::AddrFundingKey, u64)> {
    if raw.is_empty() {
        return Vec::new();
    }
    let seqs: Vec<u64> = raw.iter().map(|(seq, _, _)| *seq).collect();
    let resolved = crate::index::resolve::resolve_txseqs(store, &seqs);
    let mut out: Vec<(crate::index::address::AddrFundingKey, u64)> = Vec::with_capacity(raw.len());
    for ((txseq, vout, amount), r) in raw.into_iter().zip(resolved) {
        let Some(r) = r else {
            tracing::error!(
                target: "storage",
                scripthash_prefix = %hex::encode(&sh[..8]),
                txseq,
                vout,
                "addr_funding_v3 row references a transaction ordinal with no \
                 reverse-map entry; skipping it. This is local index corruption — \
                 rebuild with --reindex-chainstate."
            );
            continue;
        };
        out.push((
            // Re-attach the caller's full scripthash. Collisions
            // (different full scripthashes sharing this 16-byte prefix)
            // are admitted by design — see the module docstring in
            // `node_index::keys`.
            crate::index::address::AddrFundingKey {
                scripthash: *sh,
                height: r.height,
                txid: r.txid,
                vout,
            },
            amount,
        ));
    }
    out.sort_by(|(a, _), (b, _)| {
        (a.height, a.txid, a.vout).cmp(&(b.height, b.txid, b.vout))
    });
    out
}

/// Turn a `spent` row's value into the public [`SpendingRef`] shape.
///
/// `None` when the spending transaction's ordinal does not resolve,
/// which on a healthy chainstate cannot happen — the `spent` row and the
/// ordinal rows are written in the same atomic batch. Treating it as
/// "no spend" rather than inventing a txid keeps a corrupt row from
/// being reported as a real spend by a transaction that does not exist.
fn resolve_spending_ref(
    store: &dyn Store,
    spending_txseq: u64,
    vin: u32,
) -> Option<node_index::SpendingRef> {
    let resolved = crate::index::resolve::resolve_txseqs(store, &[spending_txseq])
        .into_iter()
        .next()
        .flatten()?;
    Some(node_index::SpendingRef {
        spending_txid: resolved.txid,
        spending_vin: vin,
        height: resolved.height,
    })
}

pub(crate) fn hash_bytes(hash: &BlockHash) -> &[u8] {
    hash.as_ref()
}

pub(crate) fn hash_from_bytes(bytes: &[u8]) -> Option<BlockHash> {
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
    /// Whether per-block BIP 352 silent-payment-index emission is active.
    /// Same invalidation contract as the address / filter flags: when
    /// `false` and a block connects, the persisted `sp_index.complete`
    /// marker is cleared atomically so an SP tweak-serving surface
    /// refuses until the operator runs an SP backfill / reindex. Always
    /// compiled (the SP index follows the address-index model).
    silentpaymentindex_enabled: bool,
    /// Shared LRU across all column families. Cloneable Arc; the FFI layer
    /// is thread-safe for `set_capacity`, so a clone plus an interior mutex
    /// is enough to allow live resize from a separate task.
    block_cache: parking_lot::Mutex<Cache>,
    /// Tracked separately because the RocksDB Cache API has no
    /// `get_capacity` getter — only usage.
    block_cache_capacity: std::sync::atomic::AtomicUsize,
    /// Resolved storage tuning, kept so `drop_and_recreate_cf` rebuilds
    /// dropped CFs with the same profile-specific options the rest of
    /// the DB was opened with (matters for `clear_chainstate` and
    /// reindex flows).
    tuning: StorageTuning,
}

impl RocksDbStore {
    /// Open the chainstate with default storage tuning (`ssd` profile).
    /// Tests and lower-level callers that don't care about the profile
    /// use this; `satd` wires its CLI-resolved tuning through
    /// [`open_with_tuning`](Self::open_with_tuning).
    pub fn open(
        path: &Path,
        txindex: bool,
        cache_mb: usize,
        reindex: bool,
        max_open_files: i32,
    ) -> Result<Self, StoreError> {
        Self::open_with_tuning(
            path,
            txindex,
            cache_mb,
            reindex,
            max_open_files,
            StorageTuning::default(),
        )
    }

    /// Snapshot the live database into `path` using RocksDB's
    /// checkpoint mechanism: SST files are hardlinked (instant and
    /// near-free on the same filesystem), the WAL and manifest are
    /// copied. `path` must not exist yet. Used by the offline
    /// chainstate-repair tool to take a cheap rollback point before
    /// writing; restoring is `mv` the checkpoint over `chainstate/`.
    pub fn create_checkpoint(&self, path: &Path) -> Result<(), StoreError> {
        let cp = rocksdb::checkpoint::Checkpoint::new(&self.db)
            .map_err(|e| StoreError::Database(e.to_string()))?;
        cp.create_checkpoint(path).map_err(|e| StoreError::Database(e.to_string()))
    }

    /// Open the chainstate with explicit storage tuning. `path` is the
    /// node datadir; the RocksDB instance lives in its `chainstate/`
    /// subdirectory. See [`StorageTuning`] for the per-field semantics;
    /// the resolved values are logged at INFO so an operator can verify
    /// what RocksDB is actually running with.
    pub fn open_with_tuning(
        path: &Path,
        txindex: bool,
        cache_mb: usize,
        reindex: bool,
        max_open_files: i32,
        tuning: StorageTuning,
    ) -> Result<Self, StoreError> {
        Self::open_at(
            &path.join("chainstate"),
            txindex,
            cache_mb,
            reindex,
            max_open_files,
            tuning,
        )
    }

    /// Open a RocksDB chainstate rooted at an explicit directory, rather
    /// than the datadir's default `chainstate/` subdir. This is the entry
    /// point for opening a *second* chainstate alongside the primary one
    /// (e.g. AssumeUTXO's `chainstate_background/`), where the caller
    /// chooses the subdirectory. `open`/`open_with_tuning` are thin
    /// wrappers that pass `<datadir>/chainstate`.
    pub fn open_at(
        chainstate_dir: &Path,
        txindex: bool,
        cache_mb: usize,
        reindex: bool,
        max_open_files: i32,
        tuning: StorageTuning,
    ) -> Result<Self, StoreError> {
        let db_path = chainstate_dir.to_path_buf();

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
        db_opts.set_max_background_jobs(tuning.max_background_jobs);
        db_opts.set_max_subcompactions(tuning.max_subcompactions);
        db_opts.set_atomic_flush(true);
        db_opts.set_max_total_wal_size(tuning.max_total_wal_size);
        db_opts.set_bytes_per_sync(tuning.bytes_per_sync);
        db_opts.set_wal_bytes_per_sync(tuning.wal_bytes_per_sync);

        // Loud warnings for override combinations likely to recreate
        // the failure mode that motivated this module. We log but
        // don't refuse to start — the override surface exists for
        // emergency operator tuning. See `StorageTuning::validate`.
        for warning in tuning.validate() {
            tracing::warn!(target: "storage", "{}", warning);
        }
        tracing::info!(
            target: "storage",
            profile = %tuning.profile,
            max_background_jobs = tuning.max_background_jobs,
            max_subcompactions = tuning.max_subcompactions,
            max_total_wal_mb = tuning.max_total_wal_size / (1024 * 1024),
            bytes_per_sync_mb = tuning.bytes_per_sync / (1024 * 1024),
            hot_cf_target_file_size_mb = tuning.hot_cf_target_file_size_base / (1024 * 1024),
            "RocksDB storage tuning resolved"
        );
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

        // Column family options builder. `hot=true` opts into the
        // tuning profile's `hot_cf_target_file_size_base` — used for
        // the high-write secondary indexes whose bottom-level
        // compaction throughput dominates total IBD storage growth.
        let make_cf_opts =
            |bloom: bool, write_buf_mb: usize, prefix_len: Option<usize>, hot: bool| -> Options {
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
                let target_file_size = if hot {
                    tuning.hot_cf_target_file_size_base
                } else {
                    64 * 1024 * 1024
                };
                cf_opts.set_target_file_size_base(target_file_size);
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
            ColumnFamilyDescriptor::new(CF_COINS, make_cf_opts(true, 64, None, false)),
            ColumnFamilyDescriptor::new(CF_BLOCK_INDEX, make_cf_opts(false, 8, None, false)),
            ColumnFamilyDescriptor::new(CF_HEIGHT_INDEX, make_cf_opts(false, 8, None, false)),
            // undo: hot — append-only row per input, never compaction-
            // friendly. Larger SST target reduces the count of files
            // that pile up at the bottom level during IBD.
            ColumnFamilyDescriptor::new(CF_UNDO, make_cf_opts(false, 16, None, true)),
            // tx_loc: bloom ON, unlike the `tx_index` it replaces. Every
            // read of this family is a point lookup on a 32-byte hash
            // with no locality, which is exactly the shape a bloom
            // filter is for; `tx_index` went without one only because
            // nothing else in the read path depended on it being fast.
            // The address index now resolves spends through it.
            ColumnFamilyDescriptor::new(CF_TX_LOC, make_cf_opts(true, 16, None, false)),
            // txseq_txid: no bloom. Keys are dense and ascending, so a
            // lookup lands in a block the index already narrowed to, and
            // the bloom would be pure overhead on a family written once
            // per transaction.
            ColumnFamilyDescriptor::new(CF_TXSEQ_TXID, make_cf_opts(false, 16, None, false)),
            // txseq_block: one small row per block. Same shape as
            // chain_tx, and read by `seek_for_prev` rather than by point
            // lookup, so no bloom.
            ColumnFamilyDescriptor::new(CF_TXSEQ_BLOCK, make_cf_opts(false, 2, None, false)),
            ColumnFamilyDescriptor::new(CF_METADATA, make_cf_opts(false, 2, None, false)),
            // chain_tx: one 8-byte row per block (block_hash -> cumulative
            // tx count). Small, point-lookup only (getchaintxstats), no
            // prefix scans. Modest write-buffer; no bloom needed at this
            // row count.
            ColumnFamilyDescriptor::new(CF_CHAIN_TX, make_cf_opts(false, 2, None, false)),
            // Address-history index. Bloom on for fast point lookups,
            // 32 MB write-buffer because per-block emission is write-
            // heavy during IBD, and a fixed 16-byte prefix-extractor so
            // `prefix_iterator_cf` over a single scripthash short-
            // circuits to the matching SST blocks instead of scanning.
            // Marked hot.
            ColumnFamilyDescriptor::new(
                CF_ADDR_FUNDING_V3,
                make_cf_opts(true, 32, Some(16), true),
            ),
            ColumnFamilyDescriptor::new(
                CF_ADDR_SPENDING_V2,
                make_cf_opts(true, 32, Some(16), true),
            ),
            // spent: bloom on (point lookups dominate), 16 MB write-buf
            // because the row is small (8-byte key, 8-byte value) and
            // one row per non-coinbase input — heavier than the
            // transaction index but lighter than addr_spending. A
            // 5-byte prefix (the funding ordinal) lets `outspends` for a
            // transaction fan out cheaply; that was 32 bytes when the
            // key carried a txid. Also hot — write rate matches
            // addr_spending.
            ColumnFamilyDescriptor::new(CF_SPENT, make_cf_opts(true, 16, Some(5), true)),
            // BIP 352 silent-payment tweak index. Bloom on (point lookups
            // for serving and the rescan fast path dominate); 16 MB
            // write-buf because per-block emission is write-heavy during
            // IBD when enabled. No prefix extractor: keys are 4-byte
            // `height_be`, so access is point-lookup / height-range like
            // the filter CF. Created unconditionally — the runtime flag,
            // not a cargo feature, gates emission.
            ColumnFamilyDescriptor::new(CF_SP_TWEAKS, make_cf_opts(true, 16, None, false)),
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
                make_cf_opts(true, 16, None, false),
            ));
            cf_descriptors.push(ColumnFamilyDescriptor::new(
                CF_FILTER_HEADER,
                make_cf_opts(true, 8, None, false),
            ));
        }

        // Some CFs are created lazily or are leftovers from the
        // pre-storage-cleanup era. RocksDB demands every existing CF
        // be declared at open time, so probe the DB dir once and
        // include any such descriptors that match what's on disk.
        // Skipped on first-open (path doesn't exist yet) — list_cf
        // requires the DB directory to exist.
        let existing_cfs: Vec<String> = if db_path.exists() {
            DB::list_cf(&Options::default(), &db_path).unwrap_or_default()
        } else {
            Vec::new()
        };
        if existing_cfs.iter().any(|n| n == CF_ADDR_BACKFILL_TEMP) {
            cf_descriptors.push(ColumnFamilyDescriptor::new(
                CF_ADDR_BACKFILL_TEMP,
                make_cf_opts(true, 32, None, false),
            ));
        }
        // Pre-cleanup `addr_funding` / `addr_spending`. Register with
        // bare opts so RocksDB opens; we drop them after the schema
        // check confirms it's safe to discard.
        for legacy in RETIRED_CF_NAMES {
            if existing_cfs.iter().any(|n| n == legacy) {
                cf_descriptors.push(ColumnFamilyDescriptor::new(*legacy, Options::default()));
            }
        }

        // Every CF we create must be in ALL_CFS so `flush_durable` covers
        // it — a CF missing from that list loses its WAL-less (BulkLoad)
        // writes on process exit. Legacy CFs are exempt: they're dropped
        // right after open and never written.
        for d in &cf_descriptors {
            let name = d.name();
            debug_assert!(
                ALL_CFS.contains(&name) || RETIRED_CF_NAMES.contains(&name),
                "column family `{name}` is not listed in ALL_CFS; \
                 flush_durable would not persist its BulkLoad writes"
            );
        }

        let db = DB::open_cf_descriptors(&db_opts, &db_path, cf_descriptors).map_err(|e| {
            StoreError::Database(format!(
                "Failed to open RocksDB at {}: {}",
                db_path.display(),
                e
            ))
        })?;

        // Schema version check: ensure on-disk format matches this
        // binary. Skip when reindexing — the DB is about to be cleared.
        if !reindex {
            let cf_meta = db.cf_handle(CF_METADATA).expect("metadata CF missing");
            match db.get_cf(&cf_meta, SCHEMA_KEY) {
                Ok(Some(v)) => {
                    let stored = u32::from_le_bytes(v[..].try_into().unwrap_or([0; 4]));
                    if stored == CURRENT_SCHEMA_VERSION {
                        // Already at current version.
                    } else {
                        // No in-place upgrade arm. Schema 4 changed how
                        // the transaction index is *keyed*, not just what
                        // it contains, so there is nothing to re-stamp:
                        // the new families have to be built from the
                        // blocks, which is exactly what
                        // `-reindex-chainstate` does.
                        return Err(StoreError::Database(format!(
                            "Chainstate schema version mismatch: DB has v{}, binary expects v{}. \
                             Run with --reindex-chainstate to rebuild from existing block files.",
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
                             Run with --reindex-chainstate to rebuild from existing block files."
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

        // Drop the legacy address-history CFs now that the schema
        // check has either confirmed the chainstate is at the current
        // version (so any leftover legacy CFs are empty residue from a
        // prior optimization-stack migration) or `--reindex` was
        // requested (chainstate is about to be wiped anyway). Doing
        // this AFTER the schema check ensures a v2 chainstate with
        // populated legacy CFs is rejected before we can discard the
        // rows it still depends on.
        for legacy in RETIRED_CF_NAMES {
            if db.cf_handle(legacy).is_some() {
                db.drop_cf(legacy).map_err(|e| {
                    StoreError::Database(format!("Failed to drop legacy CF '{}': {}", legacy, e))
                })?;
            }
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
            // Default false (the runtime opt-in is `--silentpaymentindex=1`);
            // main.rs flips it via `with_silentpaymentindex_enabled`. Same
            // cleared-marker invariant as the addr / filter flags: when the
            // index is off, every connected block clears the SP completeness
            // marker atomically.
            silentpaymentindex_enabled: false,
            block_cache: parking_lot::Mutex::new(block_cache),
            block_cache_capacity: std::sync::atomic::AtomicUsize::new(cache_bytes),
            tuning,
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
        let marker = store.read_spent_complete();
        if marker.is_none() {
            // Pre-PR-D datadirs only have addr_spending; post-PR-D
            // writes go to addr_spending_v2. Either presence means
            // the historical-rows-without-marker state we want to
            // detect, so we OR across both CFs.
            let cf_has_rows = |cf_name: &str| -> bool {
                store
                    .db
                    .cf_handle(cf_name)
                    .and_then(|cf| {
                        store
                            .db
                            .iterator_cf(&cf, IteratorMode::Start)
                            .next()
                            .map(|item| item.is_ok())
                    })
                    .unwrap_or(false)
            };
            let addr_has_rows = cf_has_rows(CF_ADDR_SPENDING_V2);
            store.write_spent_complete(!addr_has_rows)?;
        }
        if !store.spent_complete() {
            tracing::warn!(
                target: "storage",
                "outpoint_spend index is incomplete relative to addr_spending: \
                 historical /tx/:txid/outspend lookups will return false 'unspent' \
                 answers until you restart with --reindex-chainstate (recommended \
                 after upgrade from a satd version that predates this index)"
            );
        }

        // tx_loc.complete marker — round-3 H1, refined in round-4
        // H1 to a one-way invalidation flag.
        //
        // Trust the persisted value once stamped. The previous
        // round's "recompute on every open" logic interpreted
        // "the transaction index has any rows" as complete, which silently
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
        //     false in `write_batch_mode` when *neither* txindex nor
        //     addressindex is on (either one writes the families).
        if store.read_tx_loc_complete().is_none() {
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
            store.write_tx_loc_complete(!block_index_has_rows)?;
        }
        if txindex && !store.tx_index_complete() {
            tracing::warn!(
                target: "storage",
                "the tx_loc transaction index is enabled but on-disk data is incomplete \
                 (this datadir was previously synced with --txindex=0 and \
                 --addressindex=0). Confirmed /tx/:txid lookups will false-404 \
                 historical transactions until you restart with --reindex-chainstate."
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

        // chain_tx.backfill_complete marker. Same three open-time states:
        //   - Fresh datadir (no block_index rows) → stamp true; connects
        //     populate chain_tx from genesis, no backfill needed.
        //   - Upgraded datadir (block_index has rows, marker absent) →
        //     stamp false so the one-shot startup backfill runs.
        //   - Marker already present → leave it (the backfill / clear_*
        //     paths own it thereafter).
        if store.read_chain_tx_backfill_complete().is_none() {
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
            store.write_chain_tx_backfill_complete(!block_index_has_rows)?;
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

        // sp_index.complete marker — same three-state open-time logic as
        // the filter marker above.
        //
        //   - Fresh datadir (no `block_index` rows yet) → stamp true. A
        //     from-genesis sync with `--silentpaymentindex=1` populates
        //     every block at/above taproot activation with no holes, so
        //     it is complete by construction.
        //   - Legacy datadir without the marker (block_index has rows but
        //     the flag was never written) → stamp false. An SP tweak
        //     serving surface refuses until the operator runs
        //     `backfillindex silentpayment` (PR-3) or `--reindex-chainstate`.
        //   - Marker already present → don't touch it. Backfill
        //     `mark_silent_payment_index_complete` re-stamps true; per-block
        //     `write_batch_mode` clears it when silentpaymentindex is
        //     disabled at runtime (set after `with_silentpaymentindex_enabled`).
        if store.read_silent_payment_index_complete().is_none() {
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
            store.write_silent_payment_index_complete(!block_index_has_rows)?;
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

    /// Set whether per-block BIP 352 silent-payment-index emission is
    /// active. Call before any `write_batch_mode` runs so the persisted
    /// `sp_index.complete` marker stays consistent with the configured
    /// behaviour. Default is `false` (matches the `--silentpaymentindex=0`
    /// default). Always compiled — the SP index follows the address-index
    /// model, not a cargo feature.
    pub fn with_silentpaymentindex_enabled(mut self, enabled: bool) -> Self {
        self.silentpaymentindex_enabled = enabled;
        if !enabled {
            tracing::info!(
                target: "storage",
                "silent-payment index emission disabled; future block connects will clear \
                 the sp_index.complete marker — the tweak-serving surfaces will refuse to \
                 serve until a backfill / reindex completes."
            );
        }
        self
    }

    /// Read the `sp_index.complete` marker from the metadata CF. Returns
    /// `None` when the key doesn't exist (fresh datadir or pre-marker
    /// upgrade) so the open-time stamp can distinguish "never set" from
    /// an explicit false.
    fn read_silent_payment_index_complete(&self) -> Option<bool> {
        let cf = self.db.cf_handle(CF_METADATA)?;
        match self
            .db
            .get_cf(&cf, node_sp_index::cursor::META_KEY_COMPLETE)
        {
            Ok(Some(v)) => v.first().map(|b| *b != 0),
            _ => None,
        }
    }

    /// Write the `sp_index.complete` marker. `true` means the index has
    /// no holes from taproot activation to the tip.
    fn write_silent_payment_index_complete(&self, value: bool) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| StoreError::Database("metadata CF missing".into()))?;
        self.db
            .put_cf(
                &cf,
                node_sp_index::cursor::META_KEY_COMPLETE,
                [u8::from(value)],
            )
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    /// Read the `outpoint_spend.complete` marker from the metadata CF.
    /// Returns `None` when the key doesn't exist (fresh datadir or
    /// pre-marker upgrade).
    fn read_spent_complete(&self) -> Option<bool> {
        let cf = self.db.cf_handle(CF_METADATA)?;
        match self.db.get_cf(&cf, SPENT_COMPLETE_KEY) {
            Ok(Some(v)) => v.first().map(|b| *b != 0),
            _ => None,
        }
    }

    fn write_spent_complete(&self, value: bool) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| StoreError::Database("metadata CF missing".into()))?;
        self.db
            .put_cf(&cf, SPENT_COMPLETE_KEY, [u8::from(value)])
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    fn read_tx_loc_complete(&self) -> Option<bool> {
        let cf = self.db.cf_handle(CF_METADATA)?;
        match self.db.get_cf(&cf, TX_LOC_COMPLETE_KEY) {
            Ok(Some(v)) => v.first().map(|b| *b != 0),
            _ => None,
        }
    }

    fn write_tx_loc_complete(&self, value: bool) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| StoreError::Database("metadata CF missing".into()))?;
        self.db
            .put_cf(&cf, TX_LOC_COMPLETE_KEY, [u8::from(value)])
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    fn read_chain_tx_backfill_complete(&self) -> Option<bool> {
        let cf = self.db.cf_handle(CF_METADATA)?;
        match self.db.get_cf(&cf, CHAIN_TX_BACKFILL_COMPLETE_KEY) {
            Ok(Some(v)) => v.first().map(|b| *b != 0),
            _ => None,
        }
    }

    fn write_chain_tx_backfill_complete(&self, value: bool) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| StoreError::Database("metadata CF missing".into()))?;
        self.db
            .put_cf(&cf, CHAIN_TX_BACKFILL_COMPLETE_KEY, [u8::from(value)])
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    fn read_prune_height(&self) -> Option<u32> {
        let cf = self.db.cf_handle(CF_METADATA)?;
        match self.db.get_cf(&cf, PRUNE_HEIGHT_KEY) {
            Ok(Some(v)) if v.len() == 4 => {
                Some(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
            }
            _ => None,
        }
    }

    fn write_prune_height(&self, value: u32) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(CF_METADATA)
            .ok_or_else(|| StoreError::Database("metadata CF missing".into()))?;
        self.db
            .put_cf(&cf, PRUNE_HEIGHT_KEY, value.to_le_bytes())
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

    pub(crate) fn cf(&self, name: &str) -> Arc<BoundColumnFamily<'_>> {
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
                | CF_ADDR_FUNDING_V3
                | CF_ADDR_SPENDING_V2
                | CF_SPENT
                | CF_TX_LOC
                | CF_FILTER
                | CF_FILTER_HEADER
                | CF_SP_TWEAKS
        );
        #[cfg(not(feature = "block-filter-index"))]
        let bloom = matches!(
            name,
            CF_COINS
                | CF_ADDR_FUNDING_V3
                | CF_ADDR_SPENDING_V2
                | CF_SPENT
                | CF_TX_LOC
                | CF_SP_TWEAKS
        );
        let write_buf_mb = match name {
            CF_COINS => 64,
            CF_ADDR_FUNDING_V3 | CF_ADDR_SPENDING_V2 => 32,
            CF_SPENT => 16,
            CF_UNDO | CF_TX_LOC | CF_TXSEQ_TXID => 16,
            CF_BLOCK_INDEX | CF_HEIGHT_INDEX => 8,
            #[cfg(feature = "block-filter-index")]
            CF_FILTER => 16,
            #[cfg(feature = "block-filter-index")]
            CF_FILTER_HEADER => 8,
            CF_SP_TWEAKS => 16,
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
        // Hot CFs (high-write secondary indexes) opt into the profile's
        // larger `hot_cf_target_file_size_base`. See `make_cf_opts` in
        // `open_with_tuning` for the same hot/non-hot split applied on
        // initial open.
        let hot = matches!(
            name,
            CF_ADDR_FUNDING_V3 | CF_ADDR_SPENDING_V2 | CF_SPENT | CF_UNDO
        );
        let target_file_size = if hot {
            self.tuning.hot_cf_target_file_size_base
        } else {
            64 * 1024 * 1024
        };
        cf_opts.set_target_file_size_base(target_file_size);
        cf_opts.set_compression_per_level(&compression_per_level);
        cf_opts.set_bottommost_compression_type(DBCompressionType::Zstd);
        // Address-index CFs share a 16-byte fixed prefix; outpoint-
        // spend uses a 32-byte (txid) prefix. Mirror the
        // prefix-extractor we set on initial CF creation so
        // `drop_and_recreate_cf` (used by `clear_*` paths) preserves it.
        if matches!(name, CF_ADDR_FUNDING_V3 | CF_ADDR_SPENDING_V2) {
            cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(16));
        } else if matches!(name, CF_SPENT) {
            cf_opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(
                node_index::TXSEQ_LEN,
            ));
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

    /// Query a per-CF integer property across every CF this binary
    /// registers. Returns `(cf_name, value)` pairs in declaration
    /// order; CFs not present in the live DB (feature-gated, or older
    /// datadir without the temp CF) are silently skipped. Properties
    /// that error or are absent on a CF report 0 rather than
    /// disappearing — the caller's log line stays self-explanatory.
    ///
    /// Used by both the pending-compaction diagnostic
    /// (`rocksdb.estimate-pending-compaction-bytes`) and the SST size
    /// diagnostic (`rocksdb.total-sst-files-size`). Other RocksDB
    /// integer properties with the same shape can hook in here.
    ///
    /// The ordering mirrors the diagnostic-log priority — largest-by-
    /// observed-load CFs first — so the most operationally relevant
    /// entries appear even when the log line is truncated by
    /// downstream tooling.
    fn query_cf_property(&self, property: &str) -> Vec<(&'static str, u64)> {
        DIAG_CFS
            .iter()
            .filter_map(|name| {
                let cf = self.db.cf_handle(name)?;
                let value = self
                    .db
                    .property_int_value_cf(&cf, property)
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                Some((*name, value))
            })
            .collect()
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

impl RocksDbStore {
    /// The whole batch write, reading `batch` rather than consuming it —
    /// which is what lets `write_batch_recoverable` hand it back when the
    /// write fails. Nothing here ever needed ownership: rows are
    /// serialized into a RocksDB `WriteBatch`, never moved out.
    fn write_batch_inner(&self, batch: &StoreBatch, mode: WriteMode) -> Result<(), StoreError> {
        let mut wb = WriteBatch::default();

        let cf_bi = self.cf(CF_BLOCK_INDEX);
        let cf_coins = self.cf(CF_COINS);
        let cf_hi = self.cf(CF_HEIGHT_INDEX);
        let cf_undo = self.cf(CF_UNDO);
        let cf_meta = self.cf(CF_METADATA);

        // tx_loc.complete one-way invalidation (round-4 H1).
        //
        // If the runtime has both transaction-index consumers disabled
        // but this batch is connecting/reorging blocks (any coin
        // movement), the ordinal families will not get the rows for
        // those blocks. Stamp
        // the completeness marker false IN THE SAME `WriteBatch` as
        // the chainstate update so the invalidation is atomic with
        // the connect — a crash mid-write either rolls everything
        // back or commits both. `coin_puts` is the connect signal
        // (every connected non-empty block creates outputs);
        // `coin_removes` covers the disconnect-with-txindex-off case
        // where existing ordinal rows for the now-undone block
        // become stale.
        //
        // The gate is "neither index is on", not "txindex is off": the
        // address index writes the same families, so a node running
        // `-txindex=0 -addressindex=1` keeps them complete and must not
        // have the marker cleared under it.
        if !self.txindex_enabled
            && !self.addressindex_enabled
            && (!batch.coin_puts.is_empty() || !batch.coin_removes.is_empty())
        {
            wb.put_cf(&cf_meta, TX_LOC_COMPLETE_KEY, [0u8]);
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

        // Same invalidation contract for the BIP 352 SP-index marker.
        // When `silentpaymentindex` is disabled at runtime and a block
        // connects/disconnects, the sp_tweaks CF diverges from the chain;
        // clear the marker atomically so the tweak-serving surfaces refuse
        // until a backfill / reindex re-fills the range.
        if !self.silentpaymentindex_enabled
            && (!batch.coin_puts.is_empty() || !batch.coin_removes.is_empty())
        {
            wb.put_cf(&cf_meta, node_sp_index::cursor::META_KEY_COMPLETE, [0u8]);
        }

        // Block index
        //
        // Dominance filter: a HeaderOnly write must never clobber an
        // existing DataStored or Valid entry. The cache layer
        // (`CachedStore::write_batch_mode`) is supposed to filter
        // dominated entries before we see them, but we keep this check
        // for two reasons:
        //
        //   1. Any path that bypasses the cache (tests, direct
        //      `Store::write_batch` calls) would otherwise reintroduce
        //      the race that produced the 2026-05-12 wedge — ~435
        //      block-index entries on a single mainnet IBD instance
        //      flipped from DataStored to HeaderOnly with file=0 pos=0
        //      (the placeholder values accept_headers writes), leaving
        //      `has_block_data()` permanently false at every hole.
        //
        //   2. The check has to be **batch-aware**, not just disk-aware.
        //      RocksDB's `WriteBatch` keeps the last `put_cf` per key,
        //      so if a single batch contains [(X, DataStored), (X,
        //      HeaderOnly)] (insertion order), the disk ends up with
        //      HeaderOnly. Tracking `seen_in_batch` catches this; the
        //      disk-state read alone misses it because the
        //      not-yet-committed prior put isn't visible to `get_cf`.
        //
        // Silent-keep (no error, no log spam) matches the cache behavior.
        let mut seen_in_batch: std::collections::HashMap<BlockHash, BlockStatus> =
            std::collections::HashMap::new();
        for (hash, entry) in &batch.block_index_puts {
            // Dominance guard: a HeaderOnly put must not overwrite an
            // existing DataStored/Valid value. Check the in-batch
            // history first (a prior put in this same WriteBatch is
            // invisible to `get_cf` until commit), then fall back to
            // disk. Errors propagate — F3 fix (PR #184 re-review): the
            // previous `.ok().flatten()` / `deserialize(...).ok()`
            // chain silently disabled the guard if RocksDB returned
            // an error or an existing entry was unparseable. Failing
            // closed (refuse the write) preserves dominance even
            // under storage faults; the operator sees a real error
            // and can investigate rather than ending up with a
            // silently downgraded HeaderOnly entry overwriting
            // forensic evidence.
            let dominant_status = if entry.status == BlockStatus::HeaderOnly {
                match seen_in_batch.get(hash).copied() {
                    Some(s) => Some(s),
                    None => match self
                        .db
                        .get_cf(&cf_bi, hash_bytes(hash))
                        .map_err(|e| {
                            StoreError::Database(format!(
                                "block-index dominance guard get_cf({}): {}",
                                hash, e
                            ))
                        })? {
                        Some(bytes) => {
                            let existing: BlockIndexEntry = bincode::deserialize(&bytes)
                                .map_err(|e| {
                                    StoreError::Serialization(format!(
                                        "block-index dominance guard deserialize({}): {}",
                                        hash, e
                                    ))
                                })?;
                            Some(existing.status)
                        }
                        None => None,
                    },
                }
            } else {
                None
            };
            if matches!(
                dominant_status,
                Some(BlockStatus::DataStored) | Some(BlockStatus::Valid)
            ) {
                continue;
            }
            let value =
                bincode::serialize(entry).map_err(|e| StoreError::Serialization(e.to_string()))?;
            wb.put_cf(&cf_bi, hash_bytes(hash), &value);
            seen_in_batch.insert(*hash, entry.status);
        }

        // Coins with counter tracking.
        //
        // Puts BEFORE removes — this order is load-bearing. A RocksDB
        // WriteBatch is a log (the last operation per key wins), and a
        // batch may carry the same outpoint in both lists: connect_block
        // emits a put+remove PAIR for an output created and spent within
        // one block, and disconnect_block emits the mirror image
        // (undo-restore put + created-output remove). In both shapes the
        // correct final state is ABSENT, so the remove must win. The
        // live path never exercises this (CoinCache nets pairs out
        // before flushing), but a direct write_batch caller with
        // removes-first would silently RESURRECT spent coins — caught
        // live by the chainstate-repair dry run on mainnet block
        // 952,978 (2,382 pairs). Counter math is order-independent: a
        // pair contributes ±0 to count/amount/histogram, matching its
        // net-absent state. Every other CF family below already applies
        // puts-then-removes; InMemoryStore does too.
        let mut hist_deltas: std::collections::HashMap<usize, i64> =
            std::collections::HashMap::new();
        let mut count_delta: i64 = 0;
        let mut amount_delta: i64 = 0;

        for (outpoint, coin) in &batch.coin_puts {
            let key = outpoint_to_key(outpoint);
            let value = coin.serialize_compact();
            wb.put_cf(&cf_coins, key, &value);
            count_delta += 1;
            amount_delta += coin.amount as i64;
            let bucket = (coin.height / HEIGHT_HIST_BUCKET) as usize;
            *hist_deltas.entry(bucket).or_default() += 1;
        }

        for (outpoint, spent_amount, spent_height) in &batch.coin_removes {
            let key = outpoint_to_key(outpoint);
            count_delta -= 1;
            amount_delta -= *spent_amount as i64;
            let bucket = (*spent_height / HEIGHT_HIST_BUCKET) as usize;
            *hist_deltas.entry(bucket).or_default() -= 1;
            wb.delete_cf(&cf_coins, key);
        }

        // Height index
        for (height, hash) in &batch.height_hash_puts {
            wb.put_cf(&cf_hi, height.to_le_bytes(), hash_bytes(hash));
        }
        for height in &batch.height_hash_removes {
            wb.delete_cf(&cf_hi, height.to_le_bytes());
        }

        // Undo data — v1-only on disk (compact, no outpoints).
        for (hash, undo) in &batch.undo_puts {
            let value = undo.serialize_v1();
            wb.put_cf(&cf_undo, hash_bytes(hash), &value);
        }

        // Transaction-ordinal families.
        //
        // `tx_loc` and `txseq_txid` ride the same gate: either index
        // wants them. `-txindex` wants txid -> location; `-addressindex`
        // wants both directions, because its rows key on ordinals and
        // have to resolve back to txids before they leave the store. A
        // validating-only node pays for neither.
        let want_tx_ordinals = self.txindex_enabled || self.addressindex_enabled;
        if want_tx_ordinals && (!batch.tx_loc_puts.is_empty() || !batch.tx_loc_removes.is_empty()) {
            let cf_txl = self.cf(CF_TX_LOC);
            for (txid, seq) in &batch.tx_loc_puts {
                wb.put_cf(&cf_txl, txid_bytes(txid), node_index::encode_txseq(TxSeq(*seq)));
            }
            for txid in &batch.tx_loc_removes {
                wb.delete_cf(&cf_txl, txid_bytes(txid));
            }
        }
        if want_tx_ordinals
            && (!batch.txseq_txid_puts.is_empty() || !batch.txseq_txid_removes.is_empty())
        {
            let cf_seq = self.cf(CF_TXSEQ_TXID);
            for (seq, txid) in &batch.txseq_txid_puts {
                wb.put_cf(
                    &cf_seq,
                    node_index::encode_txseq(TxSeq(*seq)),
                    txid_bytes(txid),
                );
            }
            for seq in &batch.txseq_txid_removes {
                wb.delete_cf(&cf_seq, node_index::encode_txseq(TxSeq(*seq)));
            }
        }
        // `txseq_block` is ungated. It is four bytes per block, and it is
        // the only thing that can turn an ordinal back into a height — so
        // a node that turns `-addressindex` on later would otherwise have
        // ordinals it cannot place without a full reindex.
        if !batch.txseq_block_puts.is_empty() || !batch.txseq_block_removes.is_empty() {
            let cf_tsb = self.cf(CF_TXSEQ_BLOCK);
            for (first_txseq, height) in &batch.txseq_block_puts {
                wb.put_cf(
                    &cf_tsb,
                    node_index::encode_txseq(TxSeq(*first_txseq)),
                    height.to_be_bytes(),
                );
            }
            for first_txseq in &batch.txseq_block_removes {
                wb.delete_cf(&cf_tsb, node_index::encode_txseq(TxSeq(*first_txseq)));
            }
        }

        // Cumulative tx count (chain_tx). Always written when present —
        // unlike tx_index it is not gated on a runtime flag. Hash-keyed,
        // so there are no removals on disconnect.
        if !batch.chain_tx_puts.is_empty() {
            let cf_ctx = self.cf(CF_CHAIN_TX);
            for (block_hash, count) in &batch.chain_tx_puts {
                wb.put_cf(&cf_ctx, hash_bytes(block_hash), count.to_le_bytes());
            }
        }

        // Address-history index. CFs are present unconditionally —
        // gating on emit-side (M2) keeps the write_batch path simple.
        // Empty-batch fast-path avoids touching the CF handles when
        // the index is disabled or the block had no relevant rows.
        if !batch.addr_funding_puts.is_empty() || !batch.addr_funding_removes.is_empty() {
            let cf_af = self.cf(CF_ADDR_FUNDING_V3);
            for row in &batch.addr_funding_puts {
                let key = crate::index::address::encode_funding_key_v3(&row.key());
                let value = crate::index::address::encode_funding_value(row.amount_sat);
                wb.put_cf(&cf_af, key, value);
            }
            for key in &batch.addr_funding_removes {
                let encoded = crate::index::address::encode_funding_key_v3(key);
                wb.delete_cf(&cf_af, encoded);
            }
        }
        if !batch.addr_spending_puts.is_empty() || !batch.addr_spending_removes.is_empty() {
            let cf_as = self.cf(CF_ADDR_SPENDING_V2);
            for row in &batch.addr_spending_puts {
                let key = crate::index::address::encode_spending_key_v2(&row.key());
                let value = crate::index::address::encode_spending_value(&row.prev_outpoint);
                wb.put_cf(&cf_as, key, value);
            }
            for key in &batch.addr_spending_removes {
                let encoded = crate::index::address::encode_spending_key_v2(key);
                wb.delete_cf(&cf_as, encoded);
            }
        }

        // spent index: same atomic-with-chainstate contract as the
        // addr-CFs. Empty-batch fast-path skips the CF handle.
        if !batch.spent_puts.is_empty() || !batch.spent_removes.is_empty() {
            let cf_sp = self.cf(CF_SPENT);
            for row in &batch.spent_puts {
                wb.put_cf(
                    &cf_sp,
                    node_index::encode_spent_key(row.funding_txseq, row.vout),
                    node_index::encode_spent_value(row.spending_txseq, row.vin),
                );
            }
            for (funding_txseq, vout) in &batch.spent_removes {
                wb.delete_cf(&cf_sp, node_index::encode_spent_key(*funding_txseq, *vout));
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

        // BIP 352 silent-payment tweak rows. Same atomic-with-chainstate
        // guarantee as the filter rows: a crash mid-write rolls the tweak
        // rows back with the chain segment, so a served row can never
        // describe a block whose chainstate is only partially committed.
        // The row embeds its block hash, so it is self-authenticating on
        // read. Empty-batch fast-path skips the CF handle lookup.
        let sp_put_count = batch.sp_tweak_puts.len() as u64;
        let sp_remove_count = batch.sp_tweak_removes.len() as u64;
        if !batch.sp_tweak_puts.is_empty() || !batch.sp_tweak_removes.is_empty() {
            use node_sp_index::encode_sp_key;
            let cf_sp = self.cf(CF_SP_TWEAKS);
            for (height, row) in &batch.sp_tweak_puts {
                wb.put_cf(&cf_sp, encode_sp_key(*height), row.encode());
            }
            for height in &batch.sp_tweak_removes {
                wb.delete_cf(&cf_sp, encode_sp_key(*height));
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
            for (outpoint, sh, funding_txseq) in &batch.addr_backfill_temp_puts {
                let key = backfill_temp_key(outpoint);
                let mut value = [0u8; TEMP_VALUE_LEN];
                value[..32].copy_from_slice(sh);
                value[32..].copy_from_slice(&node_index::encode_txseq(node_index::TxSeq(
                    *funding_txseq,
                )));
                wb.put_cf(&cf_temp, key, value);
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

        // Metadata: SP-index backfill cursor advance. Atomic with the
        // cf_sp_tweaks writes above so a kill -9 mid-batch leaves cursor
        // and rows in lockstep. Same all-zero snapshot-hash sentinel as
        // the filter advance.
        if let Some(adv) = &batch.sp_backfill_cursor_advance {
            use node_sp_index::cursor as scur;
            wb.put_cf(&cf_meta, scur::META_KEY_STATE, [adv.state.as_byte()]);
            wb.put_cf(
                &cf_meta,
                scur::META_KEY_CURSOR_HEIGHT,
                adv.cursor_height.to_be_bytes(),
            );
            wb.put_cf(
                &cf_meta,
                scur::META_KEY_SNAPSHOT_HEIGHT,
                adv.snapshot_height.to_be_bytes(),
            );
            wb.put_cf(
                &cf_meta,
                scur::META_KEY_STARTED_AT,
                adv.started_at_unix.to_be_bytes(),
            );
            if adv.snapshot_tip_hash != [0u8; 32] {
                wb.put_cf(&cf_meta, scur::META_KEY_SNAPSHOT_HASH, adv.snapshot_tip_hash);
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
        if sp_put_count > 0 {
            crate::index::silent_payments::stats::add_rows(sp_put_count);
        }
        if sp_remove_count > 0 {
            crate::index::silent_payments::stats::add_row_removes(sp_remove_count);
        }
        Ok(())
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

    fn get_cumulative_tx_count(&self, hash: &BlockHash) -> Option<u64> {
        let cf = self.cf(CF_CHAIN_TX);
        let value = self.db.get_cf(&cf, hash_bytes(hash)).ok()??;
        let arr: [u8; 8] = value.as_slice().try_into().ok()?;
        Some(u64::from_le_bytes(arr))
    }

    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        self.write_batch_mode(batch, WriteMode::Normal)
    }

    fn write_batch_mode(&self, batch: StoreBatch, mode: WriteMode) -> Result<(), StoreError> {
        self.write_batch_inner(&batch, mode)
    }

    fn write_batch_recoverable(
        &self,
        batch: StoreBatch,
        mode: WriteMode,
    ) -> Result<(), (Option<Box<StoreBatch>>, StoreError)> {
        match self.write_batch_inner(&batch, mode) {
            Ok(()) => Ok(()),
            // RocksDB applies a `WriteBatch` atomically, so a failure here
            // left nothing behind and the batch can be replayed whole.
            Err(e) => Err((Some(Box::new(batch)), e)),
        }
    }

    fn flush_durable(&self) -> Result<(), StoreError> {
        // Synchronous flush of every column family's memtable to SST files.
        //
        // This MUST enumerate the column families explicitly. `DB::flush_opt`
        // flushes only the *default* CF — which holds none of our data — and
        // `atomic_flush(true)` does NOT promote a single-CF manual flush to
        // an all-CF flush. Relying on `flush_opt` here silently dropped every
        // WAL-less (BulkLoad) write still in a data-CF memtable on any exit
        // that skips the DB destructor (std::process::exit, SIGKILL, abort):
        // that lost mainnet block 952978's connect delta and rolled a
        // finished reindex back 21 blocks. The regression test
        // `flush_durable_persists_walless_writes_in_data_cfs` pins this.
        //
        // With `atomic_flush(true)` the listed CFs flush as one atomic unit;
        // `wait(true)` returns only once the flush is durable on disk.
        let mut fopts = FlushOptions::default();
        fopts.set_wait(true);
        let handles: Vec<_> = ALL_CFS
            .iter()
            .filter_map(|name| self.db.cf_handle(name))
            .collect();
        let refs: Vec<&_> = handles.iter().collect();
        self.db
            .flush_cfs_opt(&refs, &fopts)
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

    fn pending_compaction_bytes_by_cf(&self) -> Vec<(&'static str, u64)> {
        self.query_cf_property("rocksdb.estimate-pending-compaction-bytes")
    }

    fn sst_bytes_by_cf(&self) -> Vec<(&'static str, u64)> {
        // `get_column_family_metadata_cf` returns the LSM-level summary
        // directly (sum of file sizes across all levels, in bytes).
        // We previously queried the `rocksdb.total-sst-files-size`
        // integer property here, but on the live mainnet datadir it
        // came back as `Ok(None)` for every CF and was silently
        // coerced to 0 by the property helper — see the 2026-05-14
        // diagnostic log where the chainstate is hundreds of GB on disk
        // yet the diagnostic reported `total_mb=0` with an empty
        // `per_cf=`. The metadata API is the documented, non-stringly-
        // typed accessor for the same number and does not depend on
        // the rocksdb property registry recognising the name.
        DIAG_CFS
            .iter()
            .filter_map(|name| {
                let cf = self.db.cf_handle(name)?;
                let meta = self.db.get_column_family_metadata_cf(&cf);
                Some((*name, meta.size))
            })
            .collect()
    }

    fn estimated_keys_by_cf(&self) -> Vec<(&'static str, u64)> {
        // `rocksdb.estimate-num-keys` is exact while the data is still in
        // the memtable and approximate once compaction has merged
        // overwrites and tombstones. That is precise enough to multiply by
        // a known row width and see where a chainstate's disk went.
        self.query_cf_property("rocksdb.estimate-num-keys")
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
        match UndoData::deserialize(&value) {
            Ok(u) => Some(u),
            Err(e) => {
                // Log so an operator chasing "undo data missing" can
                // distinguish genuine absence from a decode failure.
                // The schema-version check at open should make this
                // unreachable for legacy formats, but a corrupt row
                // would otherwise look identical to a missing row.
                tracing::error!(
                    target: "storage",
                    block_hash = %hash,
                    error = %e,
                    "undo row failed to decode; treating as missing"
                );
                None
            }
        }
    }

    fn for_each_block_index(
        &self,
        visit: &mut dyn FnMut(BlockHash, BlockIndexEntry),
    ) -> Result<crate::storage::BlockIndexScanStats, StoreError> {
        let cf = self.cf(CF_BLOCK_INDEX);
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut stats = crate::storage::BlockIndexScanStats::default();
        for item in iter {
            let (k, v) = item.map_err(|e| StoreError::Database(e.to_string()))?;
            let Some(hash) = hash_from_bytes(&k) else {
                stats.skipped_bad_key += 1;
                continue;
            };
            let Ok(entry) = bincode::deserialize::<BlockIndexEntry>(&v) else {
                stats.skipped_bad_value += 1;
                continue;
            };
            visit(hash, entry);
        }
        Ok(stats)
    }

    fn for_each_height_hash(
        &self,
        visit: &mut dyn FnMut(u32, BlockHash),
    ) -> Result<crate::storage::HeightHashScanStats, StoreError> {
        let cf = self.cf(CF_HEIGHT_INDEX);
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut stats = crate::storage::HeightHashScanStats::default();
        for item in iter {
            let (k, v) = item.map_err(|e| StoreError::Database(e.to_string()))?;
            let Ok(key) = <[u8; 4]>::try_from(k.as_ref()) else {
                stats.skipped_bad_key += 1;
                continue;
            };
            let Some(hash) = hash_from_bytes(&v) else {
                stats.skipped_bad_value += 1;
                continue;
            };
            visit(u32::from_le_bytes(key), hash);
        }
        Ok(stats)
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
        // Three point reads where there used to be one: txid -> ordinal,
        // ordinal -> block, height -> hash. In exchange the index rows
        // that mention this transaction no longer carry a copy of its
        // txid. Callers that also want the position in the block should
        // use `get_tx_seq` + `block_of_seq` and index `txdata` directly
        // rather than reading the block and scanning it.
        let seq = self.get_tx_seq(txid)?;
        let (_first, height) = self.block_of_seq(seq)?;
        self.get_block_hash_by_height(height)
    }

    fn get_tx_seq(&self, txid: &Txid) -> Option<u64> {
        // Deliberately not gated on `txindex_enabled`: the address index
        // writes this family too and needs it regardless of what
        // `-txindex` says. `has_txindex()` remains the `-txindex` flag.
        let cf = self.cf(CF_TX_LOC);
        let value = self.db.get_cf(&cf, txid_bytes(txid)).ok()??;
        node_index::decode_txseq(&value).map(|s| s.0)
    }

    fn txids_of_seqs(&self, seqs: &[u64]) -> Vec<Option<Txid>> {
        if seqs.is_empty() {
            return Vec::new();
        }
        let cf = self.cf(CF_TXSEQ_TXID);
        let keys: Vec<[u8; node_index::TXSEQ_LEN]> = seqs
            .iter()
            .map(|s| node_index::encode_txseq(TxSeq(*s)))
            .collect();
        let cf_keys: Vec<_> = keys.iter().map(|k| (&cf, k.as_slice())).collect();
        self.db
            .multi_get_cf(cf_keys)
            .into_iter()
            .map(|result| {
                result.ok().flatten().and_then(|v| {
                    if v.len() != 32 {
                        return None;
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&v);
                    Some(Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array(arr),
                    ))
                })
            })
            .collect()
    }

    fn block_of_seq(&self, seq: u64) -> Option<(u64, u32)> {
        let cf = self.cf(CF_TXSEQ_BLOCK);
        let target = node_index::encode_txseq(TxSeq(seq));
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_for_prev(target);
        if !iter.valid() {
            return None;
        }
        let first_txseq = node_index::decode_txseq(iter.key()?)?.0;
        let height_bytes: [u8; 4] = iter.value()?.try_into().ok()?;
        let height = u32::from_be_bytes(height_bytes);

        // `seek_for_prev` lands on the last block for *any* larger
        // ordinal, including one past the tip, so the row it found has
        // to be checked against that block's transaction count. Without
        // this an ordinal beyond the chain would resolve to the tip
        // block and a caller would index past the end of `txdata`.
        let num_tx = self
            .get_block_hash_by_height(height)
            .and_then(|h| self.get_block_index(&h))
            .map(|e| e.num_tx as u64)?;
        if seq >= first_txseq + num_tx {
            return None;
        }
        Some((first_txseq, height))
    }

    fn has_txindex(&self) -> bool {
        self.txindex_enabled
    }

    fn clear_chainstate(&self) -> Result<(), StoreError> {
        let mut cfs = vec![CF_COINS, CF_UNDO, CF_METADATA];
        // The transaction-ordinal families ride the same gate as their
        // writes: either index populates them, so either index's node
        // has rows to rebuild.
        if self.txindex_enabled || self.addressindex_enabled {
            cfs.push(CF_TX_LOC);
            cfs.push(CF_TXSEQ_TXID);
        }
        // `txseq_block` is written unconditionally, so it always clears.
        cfs.push(CF_TXSEQ_BLOCK);
        // Address-history index sits in chainstate and must clear too,
        // otherwise -reindex-chainstate would leave stale rows that
        // reference UTXOs the new chainstate is about to overwrite.
        cfs.push(CF_ADDR_FUNDING_V3);
        cfs.push(CF_ADDR_SPENDING_V2);
        cfs.push(CF_SPENT);
        // Cumulative-tx-count index: rebuilt from genesis by the reindex
        // replay's connect_block calls, so clear it here and re-stamp the
        // backfill marker below (same reasoning as the ordinal families).
        cfs.push(CF_CHAIN_TX);
        // Same reasoning for the BIP 158 filter index: -reindex-chainstate
        // is going to rebuild filters from genesis via the normal
        // connect_block emit path.
        #[cfg(feature = "block-filter-index")]
        {
            cfs.push(CF_FILTER);
            cfs.push(CF_FILTER_HEADER);
        }
        // BIP 352 tweak index: same reasoning — -reindex-chainstate
        // rebuilds rows from genesis via the connect_block emit path.
        cfs.push(CF_SP_TWEAKS);
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
        // Re-stamp outpoint_spend.complete + tx_loc.complete +
        // address_index.complete: -reindex-chainstate produces a
        // from-empty re-population which connect_block will fill
        // atomically across all index CFs (round-3 H1, round-2-review
        // H2). Without the address re-stamp the operator's documented
        // remediation (`--reindex-chainstate`) would silently leave
        // Electrum / Esplora address surfaces refusing to bind.
        self.write_spent_complete(true)?;
        self.write_tx_loc_complete(true)?;
        self.write_address_index_complete(true)?;
        // The reindex replay repopulates chain_tx from genesis via
        // connect_block, so the cumulative index is complete afterward.
        self.write_chain_tx_backfill_complete(true)?;
        #[cfg(feature = "block-filter-index")]
        self.write_block_filter_index_complete(true)?;
        // BIP 352 SP index: -reindex-chainstate re-emits tweak rows from
        // genesis via connect_block, so the index is complete afterward.
        // If silentpaymentindex is disabled at runtime the per-block clear
        // resets this to false on the first connect (same as the filter
        // marker), so re-stamping true here is safe either way.
        self.write_silent_payment_index_complete(true)?;
        Ok(())
    }

    fn clear_all(&self) -> Result<(), StoreError> {
        // Only the cfg-gated filter-CF pushes below mutate this.
        #[cfg_attr(not(feature = "block-filter-index"), allow(unused_mut))]
        let mut all_cfs: Vec<&str> = vec![
            CF_BLOCK_INDEX,
            CF_COINS,
            CF_HEIGHT_INDEX,
            CF_UNDO,
            CF_METADATA,
            CF_TX_LOC,
            CF_TXSEQ_TXID,
            CF_TXSEQ_BLOCK,
            CF_ADDR_FUNDING_V3,
            CF_ADDR_SPENDING_V2,
            CF_SPENT,
            CF_CHAIN_TX,
            CF_SP_TWEAKS,
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
        // Same completeness markers as `clear_chainstate` —
        // see comment there for the round-2-review H2 rationale.
        self.write_spent_complete(true)?;
        self.write_tx_loc_complete(true)?;
        self.write_address_index_complete(true)?;
        self.write_chain_tx_backfill_complete(true)?;
        #[cfg(feature = "block-filter-index")]
        self.write_block_filter_index_complete(true)?;
        self.write_silent_payment_index_complete(true)?;
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

    fn for_each_coin_snapshot(
        &self,
        f: &mut dyn FnMut(&OutPoint, &Coin) -> Result<(), StoreError>,
    ) -> Result<crate::storage::CoinSnapshotBase, StoreError> {
        // Acquire a RocksDB snapshot — point-in-time view that isolates
        // the iteration from concurrent writes. The snapshot covers ALL
        // column families at one sequence number, so the tip pointer,
        // the block-index entry, the UTXO count and the coin rows are
        // mutually consistent. `write_batch_mode` commits all of them in
        // one atomic `WriteBatch`, so this snapshot can never straddle a
        // half-applied block. We must read the base from THIS snapshot
        // (not the in-memory tip) — see `CoinSnapshotBase` docs.
        let snap = self.db.snapshot();
        let cf_meta = self.cf(CF_METADATA);
        let cf_bi = self.cf(CF_BLOCK_INDEX);
        let cf_coins = self.cf(CF_COINS);

        // Base tip from the snapshot's metadata CF.
        let tip_val = snap
            .get_cf(&cf_meta, TIP_KEY)
            .map_err(|e| StoreError::Database(e.to_string()))?
            .ok_or_else(|| StoreError::Database("snapshot has no tip marker".into()))?;
        let base_hash = hash_from_bytes(&tip_val)
            .ok_or_else(|| StoreError::Database("snapshot tip marker is corrupt".into()))?;

        // Height of the base block, from the snapshot's block-index CF.
        // The block index may live in a DIFFERENT store than the coins:
        // the AssumeUTXO background coins DB (`chainstate_background/`)
        // shares the snapshot chainstate's block index, so its own
        // block-index CF is empty. In that case there is no entry here
        // and the height is not knowable from this DB alone — fall back
        // to 0. The handoff that hashes the background coins reads the
        // true base height/hash from the anchor, not from this value. For
        // the primary chainstate the entry is always present, so this is
        // the real height and behavior is unchanged.
        let base_height = snap
            .get_cf(&cf_bi, hash_bytes(&base_hash))
            .map_err(|e| StoreError::Database(e.to_string()))?
            .and_then(|bi_val| bincode::deserialize::<BlockIndexEntry>(&bi_val).ok())
            .map(|entry| entry.height)
            .unwrap_or(0);

        // UTXO count from the same snapshot. Missing key == empty set.
        let coin_count = match snap
            .get_cf(&cf_meta, UTXO_COUNT_KEY)
            .map_err(|e| StoreError::Database(e.to_string()))?
        {
            Some(v) if v.len() == 8 => {
                let mut a = [0u8; 8];
                a.copy_from_slice(&v);
                u64::from_le_bytes(a)
            }
            _ => 0,
        };

        let mut coins_written = 0u64;
        for kv in snap.iterator_cf(&cf_coins, IteratorMode::Start) {
            let (key, value) = kv.map_err(|e| StoreError::Database(e.to_string()))?;
            if key.len() != 36 {
                return Err(StoreError::Database(format!(
                    "unexpected coin key length: {}",
                    key.len()
                )));
            }
            let mut key_arr = [0u8; 36];
            key_arr.copy_from_slice(&key);
            let outpoint = crate::storage::coinview::key_to_outpoint(&key_arr);
            let coin = Coin::deserialize_compact(&value).ok_or_else(|| {
                StoreError::Serialization(format!(
                    "corrupt coin record at {}:{}",
                    outpoint.txid, outpoint.vout
                ))
            })?;
            f(&outpoint, &coin)?;
            coins_written += 1;
        }
        Ok(crate::storage::CoinSnapshotBase {
            base_hash,
            base_height,
            coin_count,
            coins_written,
        })
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
        let cf = self.cf(CF_ADDR_FUNDING_V3);
        let sh_prefix = &sh[..crate::index::address::SCRIPTHASH_PREFIX_LEN];
        let mut raw: Vec<(u64, u32, u64)> = Vec::new();
        for item in self.db.prefix_iterator_cf(&cf, sh_prefix) {
            if raw.len() >= limit {
                break;
            }
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if k.len() != crate::index::address::KEY_LEN_V3 || &k[..sh_prefix.len()] != sh_prefix {
                break;
            }
            let payload = match crate::index::address::decode_funding_key_v3(&k) {
                Some(p) => p,
                None => continue,
            };
            let amount = match crate::index::address::decode_funding_value(&v) {
                Some(a) => a,
                None => continue,
            };
            raw.push((payload.txseq, payload.vout, amount));
        }
        resolve_funding_rows_for(self, sh, raw)
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
        let mut out: Vec<(crate::index::address::AddrSpendingKey, OutPoint)> = Vec::new();
        let cf = self.cf(CF_ADDR_SPENDING_V2);
        let sh_prefix = &sh[..crate::index::address::SCRIPTHASH_PREFIX_LEN];
        let mut count = 0usize;
        for item in self.db.prefix_iterator_cf(&cf, sh_prefix) {
            if count >= limit {
                break;
            }
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if k.len() != crate::index::address::KEY_LEN_V2 || &k[..sh_prefix.len()] != sh_prefix {
                break;
            }
            let payload = match crate::index::address::decode_spending_key_v2(&k) {
                Some(p) => p,
                None => continue,
            };
            let prev = match crate::index::address::decode_spending_value(&v) {
                Some(p) => p,
                None => continue,
            };
            let key = crate::index::address::reconstruct_spending_key(sh, payload);
            out.push((key, prev));
            count += 1;
        }
        out
    }

    fn spent_complete(&self) -> bool {
        // Default to false when the metadata key is missing — that
        // shouldn't happen post-`open()` but we'd rather under-claim
        // completeness than over-claim it.
        self.read_spent_complete().unwrap_or(false)
    }

    fn mark_spent_complete(&self) -> Result<(), StoreError> {
        self.write_spent_complete(true)
    }

    fn mark_index_incomplete_after_snapshot(&self) -> Result<(), StoreError> {
        self.write_spent_complete(false)?;
        self.write_address_index_complete(false)?;
        Ok(())
    }

    fn tx_index_complete(&self) -> bool {
        self.read_tx_loc_complete().unwrap_or(false)
    }

    fn chain_tx_backfill_complete(&self) -> bool {
        // Default false when the marker is missing so the one-shot
        // backfill runs on an upgraded datadir that predates this CF.
        self.read_chain_tx_backfill_complete().unwrap_or(false)
    }

    fn mark_chain_tx_backfill_complete(&self) -> Result<(), StoreError> {
        self.write_chain_tx_backfill_complete(true)
    }

    fn prune_height(&self) -> Option<u32> {
        self.read_prune_height()
    }

    fn set_prune_height(&self, height: u32) -> Result<(), StoreError> {
        self.write_prune_height(height)
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

    fn get_sp_tweaks_row(&self, height: u32) -> Option<node_sp_index::SpBlockRow> {
        // Error-swallowing convenience view over the checked read: a read or
        // decode failure logs loudly and returns `None` (callers on this path —
        // e.g. the disconnect/undo bookkeeping — treat absent and errored
        // alike). The serving path uses `get_sp_tweaks_row_checked` instead so
        // it can surface the error to the client.
        match self.get_sp_tweaks_row_checked(height) {
            Ok(row) => row,
            Err(e) => {
                tracing::error!(target: "storage", "{e}");
                None
            }
        }
    }

    fn get_sp_tweaks_row_checked(
        &self,
        height: u32,
    ) -> Result<Option<node_sp_index::SpBlockRow>, StoreError> {
        let cf = self.cf(CF_SP_TWEAKS);
        let raw = self
            .db
            .get_cf(&cf, node_sp_index::encode_sp_key(height))
            .map_err(|e| {
                StoreError::Database(format!("sp_tweaks read at height {height} failed: {e}"))
            })?;
        match raw {
            None => Ok(None),
            // The row is written by our own codec inside the chainstate-atomic
            // batch, so a decode failure means on-disk corruption or a version
            // this binary predates — surface it rather than fabricate a partial
            // row or fake an empty height.
            Some(bytes) => node_sp_index::SpBlockRow::decode(&bytes).map(Some).map_err(|e| {
                StoreError::Database(format!(
                    "sp_tweaks row at height {height} failed to decode: {e}"
                ))
            }),
        }
    }

    fn silent_payment_index_complete(&self) -> bool {
        // Default false when the marker is missing — under-claim rather
        // than over-claim, same convention as the filter/address indexes.
        let cf = self.cf(CF_METADATA);
        matches!(
            self.db.get_cf(&cf, node_sp_index::cursor::META_KEY_COMPLETE),
            Ok(Some(v)) if v.first() == Some(&1)
        )
    }

    fn mark_silent_payment_index_complete(&self) -> Result<(), StoreError> {
        self.write_silent_payment_index_complete(true)
    }

    fn read_sp_backfill_cursor(&self) -> node_sp_index::cursor::BackfillCursor {
        use node_sp_index::cursor as scur;
        let cf = self.cf(CF_METADATA);
        // One consistent view across all the cursor's keys. The runner writes
        // state / cursor_height / snapshot_height in a single `WriteBatch`,
        // so independent `get_cf` calls can straddle a write — most
        // damagingly across a restart, where the previous run's
        // `cursor_height` pairs with the new `snapshot_height` and the
        // progress gauge reads high for a backfill that just began (#549).
        let snap = self.db.snapshot();
        let read_u8 = |k: &[u8]| -> Option<u8> {
            snap
                .get_cf(&cf, k)
                .ok()
                .flatten()
                .and_then(|v| v.first().copied())
        };
        let read_u32_be = |k: &[u8]| -> Option<u32> {
            snap.get_cf(&cf, k).ok().flatten().and_then(|v| {
                if v.len() == 4 {
                    Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
                } else {
                    None
                }
            })
        };
        let read_u64_be = |k: &[u8]| -> Option<u64> {
            snap.get_cf(&cf, k).ok().flatten().and_then(|v| {
                if v.len() == 8 {
                    Some(u64::from_be_bytes([
                        v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
                    ]))
                } else {
                    None
                }
            })
        };
        let snapshot_tip_hash: [u8; 32] = snap
            .get_cf(&cf, scur::META_KEY_SNAPSHOT_HASH)
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
        scur::BackfillCursor {
            state: read_u8(scur::META_KEY_STATE)
                .map(scur::BackfillState::from_byte)
                .unwrap_or(scur::BackfillState::Idle),
            cursor_height: read_u32_be(scur::META_KEY_CURSOR_HEIGHT).unwrap_or(0),
            snapshot_height: read_u32_be(scur::META_KEY_SNAPSHOT_HEIGHT).unwrap_or(0),
            started_at_unix: read_u64_be(scur::META_KEY_STARTED_AT).unwrap_or(0),
            snapshot_tip_hash,
        }
    }

    fn read_sp_backfill_last_error(&self) -> Option<String> {
        use node_sp_index::cursor as scur;
        let cf = self.cf(CF_METADATA);
        self.db
            .get_cf(&cf, scur::META_KEY_LAST_ERROR)
            .ok()
            .flatten()
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
            .filter(|s| !s.is_empty())
    }

    fn write_sp_backfill_last_error(&self, msg: &str) -> Result<(), StoreError> {
        use node_sp_index::cursor as scur;
        let cf = self.cf(CF_METADATA);
        let bytes = if msg.len() <= scur::LAST_ERROR_MAX_BYTES {
            msg.as_bytes().to_vec()
        } else {
            let mut idx = scur::LAST_ERROR_MAX_BYTES;
            while idx > 0 && !msg.is_char_boundary(idx) {
                idx -= 1;
            }
            msg.as_bytes()[..idx].to_vec()
        };
        if bytes.is_empty() {
            self.db
                .delete_cf(&cf, scur::META_KEY_LAST_ERROR)
                .map_err(|e| StoreError::Database(e.to_string()))
        } else {
            self.db
                .put_cf(&cf, scur::META_KEY_LAST_ERROR, bytes)
                .map_err(|e| StoreError::Database(e.to_string()))
        }
    }

    fn lookup_spend(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<node_index::SpendingRef>, StoreError> {
        // Three steps where the txid-keyed layout took one: the spent
        // outpoint's funding transaction has to be named by ordinal
        // before the row can be found, and the row names its spender the
        // same way. In exchange the row itself is 16 bytes instead of 76.
        let Some(funding_txseq) = self.get_tx_seq(&outpoint.txid) else {
            // No ordinal for the funding transaction means nothing ever
            // indexed it, which is the same answer as "no spend row".
            return Ok(None);
        };
        let cf = self.cf(CF_SPENT);
        let key = node_index::encode_spent_key(funding_txseq, outpoint.vout);
        let raw = match self.db.get_cf(&cf, key) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(e) => return Err(StoreError::Database(e.to_string())),
        };
        let Some((spending_txseq, vin)) = node_index::decode_spent_value(&raw) else {
            // A row exists but its value is malformed. Fail loud so
            // corruption is visible — silently returning None would mask
            // a real spend as unspent in the answers `SpendIndex` callers
            // rely on (Esplora outspend).
            let msg = format!(
                "spent: corrupt value for {}:{} (got {} bytes)",
                outpoint.txid,
                outpoint.vout,
                raw.len()
            );
            tracing::error!(target: "storage", "{}", msg);
            return Err(StoreError::Database(msg));
        };
        Ok(resolve_spending_ref(self, spending_txseq, vin))
    }

    fn lookup_spends_of_tx(
        &self,
        txid: &Txid,
    ) -> Result<Vec<(u32, node_index::SpendingRef)>, StoreError> {
        // One txid lookup and one prefix scan for the whole
        // transaction, which is what the 5-byte ordinal prefix on this
        // family is for. Esplora's `/tx/:txid/outspends` used to pay one
        // point read per output.
        let Some(funding_txseq) = self.get_tx_seq(txid) else {
            return Ok(Vec::new());
        };
        let cf = self.cf(CF_SPENT);
        let prefix = node_index::encode_txseq(node_index::TxSeq(funding_txseq));
        let mut rows: Vec<(u32, u64, u32)> = Vec::new();
        for item in self.db.prefix_iterator_cf(&cf, prefix) {
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(e) => return Err(StoreError::Database(e.to_string())),
            };
            // A prefix iterator can run past the prefix it was seeded
            // with; stop at the first key that is not ours.
            if k.len() != node_index::SPENT_KEY_LEN || k[..prefix.len()] != prefix {
                break;
            }
            let Some((_, vout)) = node_index::decode_spent_key(&k) else {
                continue;
            };
            let Some((spending_txseq, vin)) = node_index::decode_spent_value(&v) else {
                continue;
            };
            rows.push((vout, spending_txseq, vin));
        }
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        // Resolve every spender in one batch rather than one per row.
        let seqs: Vec<u64> = rows.iter().map(|(_, seq, _)| *seq).collect();
        let resolved = crate::index::resolve::resolve_txseqs(self, &seqs);
        Ok(rows
            .into_iter()
            .zip(resolved)
            .filter_map(|((vout, _, vin), r)| {
                let r = r?;
                Some((
                    vout,
                    node_index::SpendingRef {
                        spending_txid: r.txid,
                        spending_vin: vin,
                        height: r.height,
                    },
                ))
            })
            .collect())
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
    ) -> Result<Option<(crate::index::address::Scripthash, u64)>, StoreError> {
        let cf = match self.db.cf_handle(CF_ADDR_BACKFILL_TEMP) {
            Some(c) => c,
            None => return Ok(None),
        };
        let key = backfill_temp_key(outpoint);
        match self.db.get_cf(&cf, key) {
            Ok(Some(v)) => {
                // Exact length, not a minimum. The temp CF is written by
                // pass 1 and read by pass 2 of the same run, so a value
                // of any other width is a row from a different layout —
                // and a short read would hand pass 2 an ordinal it
                // invented rather than one pass 1 recorded.
                if v.len() != TEMP_VALUE_LEN {
                    return Err(StoreError::Database(format!(
                        "corrupt backfill temp value: {} bytes (expected {TEMP_VALUE_LEN})",
                        v.len()
                    )));
                }
                let mut sh = [0u8; 32];
                sh.copy_from_slice(&v[..32]);
                let seq = node_index::decode_txseq(&v[32..])
                    .ok_or_else(|| {
                        StoreError::Database("corrupt backfill temp ordinal".to_string())
                    })?
                    .0;
                Ok(Some((sh, seq)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Database(e.to_string())),
        }
    }

    fn read_backfill_cursor(&self) -> crate::index::address::cursor::BackfillCursor {
        use crate::index::address::cursor as cur;
        let cf = self.cf(CF_METADATA);
        // One consistent view across every key (this family also carries
        // `pass`). The runner writes
        // state / cursor_height / snapshot_height in a single `WriteBatch`,
        // so independent `get_cf` calls can straddle a write — most
        // damagingly across a restart, where the previous run's
        // `cursor_height` pairs with the new `snapshot_height` and the
        // progress gauge reads high for a backfill that just began (#549).
        let snap = self.db.snapshot();
        let read_u8 = |k: &[u8]| -> Option<u8> {
            snap
                .get_cf(&cf, k)
                .ok()
                .flatten()
                .and_then(|v| v.first().copied())
        };
        let read_u32_be = |k: &[u8]| -> Option<u32> {
            snap.get_cf(&cf, k).ok().flatten().and_then(|v| {
                if v.len() == 4 {
                    Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
                } else {
                    None
                }
            })
        };
        let read_u64_be = |k: &[u8]| -> Option<u64> {
            snap.get_cf(&cf, k).ok().flatten().and_then(|v| {
                if v.len() == 8 {
                    Some(u64::from_be_bytes([
                        v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
                    ]))
                } else {
                    None
                }
            })
        };
        let snapshot_tip_hash: [u8; 32] = snap
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
        // One consistent view across all the cursor's keys. The runner writes
        // state / cursor_height / snapshot_height in a single `WriteBatch`,
        // so independent `get_cf` calls can straddle a write — most
        // damagingly across a restart, where the previous run's
        // `cursor_height` pairs with the new `snapshot_height` and the
        // progress gauge reads high for a backfill that just began (#549).
        let snap = self.db.snapshot();
        let read_u8 = |k: &[u8]| -> Option<u8> {
            snap
                .get_cf(&cf, k)
                .ok()
                .flatten()
                .and_then(|v| v.first().copied())
        };
        let read_u32_be = |k: &[u8]| -> Option<u32> {
            snap.get_cf(&cf, k).ok().flatten().and_then(|v| {
                if v.len() == 4 {
                    Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
                } else {
                    None
                }
            })
        };
        let read_u64_be = |k: &[u8]| -> Option<u64> {
            snap.get_cf(&cf, k).ok().flatten().and_then(|v| {
                if v.len() == 8 {
                    Some(u64::from_be_bytes([
                        v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
                    ]))
                } else {
                    None
                }
            })
        };
        let snapshot_tip_hash: [u8; 32] = snap
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
    use crate::storage::undo::UndoData;
    use crate::storage::{Store, StoreBatch};
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;
    use bitcoin::{BlockHash, OutPoint, Txid};

    fn temp_store(txindex: bool) -> (RocksDbStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = RocksDbStore::open(dir.path(), txindex, 16, false, -1).unwrap();
        (store, dir)
    }

    /// StoreBatch remove-wins contract: a key in BOTH coin_puts and
    /// coin_removes of one batch must end absent (connect emits such
    /// pairs for intra-block spends; disconnect emits the mirror
    /// shape). A RocksDB WriteBatch is last-write-wins per key, so this
    /// pins the puts-before-removes application order — the pre-fix
    /// removes-first order resurrected the spent coin. Counters must
    /// reflect the net state: the pair contributes nothing.
    /// The diagnostics must cover every family the binary can create.
    /// `chain_tx` was missing from both hand-maintained lists for three
    /// releases, so `getstoragefootprint` would have under-reported the
    /// chainstate by a whole family with no sign anything was absent.
    /// `ALL_CFS` is the sanctioned proxy for "descriptor created": the
    /// `debug_assert!` in `open()` already enforces descriptor ⊆
    /// `ALL_CFS`, so equality with `DIAG_CFS` closes the loop.
    #[test]
    fn diag_cf_list_names_every_descriptor() {
        let mut all: Vec<&str> = ALL_CFS.iter().copied().filter(|n| *n != "default").collect();
        let mut diag: Vec<&str> = DIAG_CFS.to_vec();
        all.sort_unstable();
        diag.sort_unstable();
        assert_eq!(
            all, diag,
            "DIAG_CFS and ALL_CFS must name the same column families; \
             a family in ALL_CFS but not DIAG_CFS is invisible to \
             getstoragefootprint and the startup diagnostics"
        );
    }

    /// The `debug_assert!` in `open()` enforces "descriptor created =>
    /// listed in ALL_CFS", but only in debug builds and only for CFs the
    /// open path actually reaches. This asserts the same correspondence
    /// from the other side and unconditionally: open a store, list what
    /// RocksDB actually created, and require `ALL_CFS` to name exactly
    /// that. A CF missing from `ALL_CFS` loses its WAL-less BulkLoad
    /// writes on process exit — which looks like a clean shutdown and a
    /// silently truncated index.
    #[test]
    fn all_cfs_names_every_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _store = RocksDbStore::open(dir.path(), true, 16, false, -1).unwrap();
        }
        let mut created = DB::list_cf(&Options::default(), dir.path().join("chainstate")).unwrap();
        // The backfill temp CF is created lazily when a backfill starts,
        // so a freshly opened store has not made it yet.
        created.retain(|n| n != CF_ADDR_BACKFILL_TEMP);
        created.sort();

        let mut listed: Vec<String> = ALL_CFS
            .iter()
            .filter(|n| **n != CF_ADDR_BACKFILL_TEMP)
            .map(|n| n.to_string())
            .collect();
        listed.sort();

        assert_eq!(
            created, listed,
            "ALL_CFS must name exactly the column families open() creates; \
             a missing one loses its BulkLoad writes on flush_durable"
        );
    }

    /// `estimated_keys_by_cf` must report the rows actually written.
    /// RocksDB's `estimate-num-keys` is exact while the data is still
    /// memtable-resident, which is the case for a freshly written temp
    /// store, so this is a tight assertion rather than an order-of-
    /// magnitude one.
    #[test]
    fn estimated_keys_by_cf_counts_written_rows() {
        let (store, _dir) = temp_store(false);

        let mut batch = StoreBatch::default();
        for i in 0..1_000u32 {
            let op = OutPoint {
                txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                    [(i % 251) as u8; 32],
                )),
                vout: i,
            };
            batch.coin_puts.push((op, make_coin(1_000 + i as u64, 1)));
        }
        let (genesis_hash, genesis_entry) = regtest_genesis_entry();
        for i in 0..10u8 {
            let mut entry = genesis_entry.clone();
            entry.height = i as u32;
            batch
                .block_index_puts
                .push((if i == 0 { genesis_hash } else { make_block_hash(i) }, entry));
        }
        store.write_batch(batch).unwrap();

        let counts: std::collections::HashMap<&str, u64> =
            store.estimated_keys_by_cf().into_iter().collect();
        let coins = *counts
            .get(CF_COINS)
            .expect("coins must appear in the key estimate");
        let blocks = *counts
            .get(CF_BLOCK_INDEX)
            .expect("block_index must appear in the key estimate");
        assert!(
            coins.abs_diff(1_000) <= 100,
            "coins key estimate {coins} should be within 10% of 1000"
        );
        assert!(
            blocks.abs_diff(10) <= 1,
            "block_index key estimate {blocks} should be within 10% of 10"
        );
        assert!(
            counts.contains_key(CF_CHAIN_TX),
            "chain_tx must be reported even when empty — an absent family \
             and an empty one are different findings"
        );
    }

    #[test]
    fn write_batch_remove_wins_for_put_remove_pairs() {
        let (store, _dir) = temp_store(false);

        let mk_op = |seed: u8| OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [seed; 32],
            )),
            vout: 0,
        };
        let mk_coin = |amount: u64| Coin {
            amount,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 7,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        };

        let paired = mk_op(1);
        let kept = mk_op(2);
        let mut batch = StoreBatch::default();
        batch.coin_puts.push((paired, mk_coin(1_000)));
        batch.coin_puts.push((kept, mk_coin(2_000)));
        batch.coin_removes.push((paired, 1_000, 7));
        store.write_batch(batch).unwrap();

        assert!(
            store.get_coin(&paired).is_none(),
            "put+remove pair must net to absent — the remove wins"
        );
        assert!(store.get_coin(&kept).is_some(), "unpaired put must survive");
        assert_eq!(store.coin_count(), 1, "counters must match the net state");
        assert_eq!(store.coin_total_amount(), 2_000);
    }

    /// `seek_for_prev` answers "the nearest block row at or before this
    /// ordinal" for *any* ordinal, including one past the tip, so the
    /// found row has to be checked against the block's transaction
    /// count. Without the bound, an ordinal beyond the chain resolves to
    /// the last block and a caller indexes past the end of `txdata`.
    #[test]
    fn block_of_seq_rejects_an_ordinal_past_the_last_block() {
        let (store, _dir) = temp_store(true);
        let (hash, mut entry) = regtest_genesis_entry();
        entry.height = 0;
        entry.num_tx = 3;

        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        batch.height_hash_puts.push((0, hash));
        batch.txseq_block_puts.push((0, 0));
        store.write_batch(batch).unwrap();

        assert_eq!(store.block_of_seq(0), Some((0, 0)));
        assert_eq!(store.block_of_seq(2), Some((0, 0)), "last tx of the block");
        assert_eq!(
            store.block_of_seq(3),
            None,
            "one past the block's transaction count is past the chain"
        );
        assert_eq!(store.block_of_seq(1_000_000), None);
    }

    /// The remove-wins contract, for the three ordinal families. A reorg
    /// frees a range of ordinals and the replacement chain reuses them
    /// immediately, so a put and a remove for the same key inside one
    /// batch is routine rather than exotic — and a RocksDB `WriteBatch`
    /// is last-write-wins per key, so the apply order is what decides.
    #[test]
    fn write_batch_remove_wins_for_ordinal_families() {
        let (store, _dir) = temp_store(true);
        let paired =
            Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xA1; 32]));
        let kept = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xA2; 32]));
        let (hash, mut entry) = regtest_genesis_entry();
        entry.num_tx = 2;

        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        batch.height_hash_puts.push((0, hash));
        batch.tx_loc_puts.push((paired, 0));
        batch.tx_loc_puts.push((kept, 1));
        batch.tx_loc_removes.push(paired);
        batch.txseq_txid_puts.push((0, paired));
        batch.txseq_txid_puts.push((1, kept));
        batch.txseq_txid_removes.push(0);
        batch.txseq_block_puts.push((0, 0));
        batch.txseq_block_puts.push((10, 5));
        batch.txseq_block_removes.push(10);
        store.write_batch(batch).unwrap();

        assert_eq!(
            store.get_tx_seq(&paired),
            None,
            "tx_loc put+remove pair must net to absent — the remove wins"
        );
        assert_eq!(store.get_tx_seq(&kept), Some(1), "unpaired put must survive");
        assert_eq!(
            store.txids_of_seqs(&[0, 1]),
            vec![None, Some(kept)],
            "txseq_txid must follow the same contract"
        );
        assert_eq!(
            store.block_of_seq(5),
            None,
            "txseq_block put+remove pair must net to absent"
        );
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
            txseq: node_index::TXSEQ_UNKNOWN,
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
    fn block_index_dominance_guard_fails_closed_on_corrupt_existing_value() {
        // Regression for review F3 (PR #184 re-review): the dominance
        // guard previously used `.ok().flatten()` for the RocksDB read
        // and `.ok()` for deserialization, so a read error or an
        // unparseable existing entry silently disabled the guard and
        // allowed a HeaderOnly write to land — overwriting forensic
        // evidence of the original corruption.
        //
        // The fix surfaces deserialize failure as `StoreError::
        // Serialization`. Verify by: writing junk bytes directly to
        // the block_index CF under a known hash, then attempting a
        // HeaderOnly write_batch for that hash. The batch must fail,
        // and the junk bytes must remain on disk so an operator can
        // diagnose the underlying corruption rather than seeing it
        // silently masked.
        let (store, _dir) = temp_store(false);
        let (hash, _) = regtest_genesis_entry();

        // Inject corrupt bytes directly via the inner db handle —
        // bypasses write_batch's normal serialize path.
        let cf_bi = store.cf(CF_BLOCK_INDEX);
        store.db.put_cf(&cf_bi, hash_bytes(&hash), b"not-a-block-index-entry")
            .expect("direct put_cf for corrupt fixture");

        // Now attempt a HeaderOnly write for the same hash. The
        // dominance guard must reject the whole batch.
        let header_only = BlockIndexEntry {
            status: BlockStatus::HeaderOnly,
            file_number: 0,
            data_pos: 0,
            ..regtest_genesis_entry().1
        };
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, header_only));
        let res = store.write_batch(batch);
        assert!(
            matches!(res, Err(StoreError::Serialization(_))),
            "expected StoreError::Serialization, got {:?}",
            res
        );

        // The corrupt bytes must still be on disk — the failed batch
        // did not silently overwrite them.
        let raw = store.db.get_cf(&cf_bi, hash_bytes(&hash))
            .expect("get_cf")
            .expect("entry still present");
        assert_eq!(
            raw, b"not-a-block-index-entry",
            "corrupt entry must survive the rejected dominance check"
        );
    }

    #[test]
    fn block_index_in_batch_dominance_keeps_highest_status() {
        // RocksDB's WriteBatch keeps the last `put_cf` per key, so a
        // batch carrying both (X, DataStored) and (X, HeaderOnly) for
        // the same hash would land on disk as HeaderOnly. The inner
        // store's dominance filter has to be batch-aware to catch this
        // — checking only the on-disk state is not enough because the
        // earlier `put_cf` in the same batch isn't visible to `get_cf`.
        //
        // Order 1: DataStored first, HeaderOnly second.
        let (store, _dir) = temp_store(false);
        let (hash, mut datastored) = regtest_genesis_entry();
        datastored.status = BlockStatus::DataStored;
        datastored.file_number = 4;
        datastored.data_pos = 42;
        let header_only = BlockIndexEntry {
            status: BlockStatus::HeaderOnly,
            file_number: 0,
            data_pos: 0,
            ..datastored.clone()
        };

        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, datastored.clone()));
        batch.block_index_puts.push((hash, header_only.clone()));
        store.write_batch(batch).unwrap();

        let recovered = store.get_block_index(&hash).unwrap();
        assert_eq!(
            recovered.status,
            BlockStatus::DataStored,
            "in-batch HeaderOnly write must not clobber an earlier DataStored write"
        );
        assert_eq!(recovered.file_number, 4);
        assert_eq!(recovered.data_pos, 42);

        // Order 2: HeaderOnly first, DataStored second — last writer
        // wins for the upgrade direction.
        let (store2, _dir2) = temp_store(false);
        let mut batch2 = StoreBatch::default();
        batch2.block_index_puts.push((hash, header_only));
        batch2.block_index_puts.push((hash, datastored.clone()));
        store2.write_batch(batch2).unwrap();
        let recovered2 = store2.get_block_index(&hash).unwrap();
        assert_eq!(recovered2.status, BlockStatus::DataStored);
        assert_eq!(recovered2.file_number, 4);
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

    /// The scan has to round-trip the real on-disk key encoding. Heights are
    /// stored little-endian, so lexicographic iteration order is not numeric
    /// — a scan that assumed otherwise would still return every row, which is
    /// all its caller needs, but decoding the key wrongly would silently
    /// report the wrong heights as present.
    #[test]
    fn height_hash_scan_returns_every_row_with_its_true_height() {
        let (store, _dir) = temp_store(false);

        // Heights chosen to straddle byte boundaries, where a wrong-endian
        // decode would reorder or corrupt them.
        let heights = [0u32, 1, 255, 256, 65_535, 65_536, 956_337, 962_163];
        let mut batch = StoreBatch::default();
        for (i, h) in heights.iter().enumerate() {
            batch.height_hash_puts.push((*h, make_block_hash(i as u8)));
        }
        store.write_batch(batch).unwrap();

        let mut seen: Vec<(u32, BlockHash)> = Vec::new();
        let stats = store
            .for_each_height_hash(&mut |h, hash| seen.push((h, hash)))
            .unwrap();
        assert_eq!(stats, crate::storage::HeightHashScanStats::default());

        seen.sort_by_key(|(h, _)| *h);
        let mut expected: Vec<(u32, BlockHash)> = heights
            .iter()
            .enumerate()
            .map(|(i, h)| (*h, make_block_hash(i as u8)))
            .collect();
        expected.sort_by_key(|(h, _)| *h);
        assert_eq!(seen, expected);
    }

    /// A row removed from the index must not come back in the scan — the
    /// caller uses absence to decide a height needs repair.
    #[test]
    fn height_hash_scan_omits_removed_rows() {
        let (store, _dir) = temp_store(false);
        let mut batch = StoreBatch::default();
        batch.height_hash_puts.push((10, make_block_hash(0x10)));
        batch.height_hash_puts.push((11, make_block_hash(0x11)));
        store.write_batch(batch).unwrap();

        let batch = StoreBatch {
            height_hash_removes: vec![10],
            ..Default::default()
        };
        store.write_batch(batch).unwrap();

        let mut seen: Vec<u32> = Vec::new();
        store
            .for_each_height_hash(&mut |h, _| seen.push(h))
            .unwrap();
        assert_eq!(seen, vec![11]);
    }

    /// Pins the apply-order contract that `StoreBatch::merge` depends on.
    ///
    /// A single `WriteBatch` writes every put and then every remove, so a
    /// batch that is NOT disjoint by key resolves to "removed" no matter
    /// which op the caller issued last. That is why `merge` deduplicates
    /// keyed puts/removes rather than relying on ordering — reversing the
    /// loops here would just move the data loss to the opposite sequence.
    #[test]
    fn keyed_index_put_and_remove_in_one_batch_resolves_to_removed() {
        let (store, _dir) = temp_store(true);
        let hash = make_block_hash(0x12);
        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x34; 32]));

        let mut batch = StoreBatch::default();
        batch.height_hash_puts.push((100, hash));
        batch.height_hash_removes.push(100);
        batch.tx_loc_puts.push((txid, 7));
        batch.tx_loc_removes.push(txid);
        batch.txseq_txid_puts.push((7, txid));
        batch.txseq_txid_removes.push(7);
        batch.txseq_block_puts.push((7, 100));
        batch.txseq_block_removes.push(7);
        store.write_batch(batch).unwrap();

        assert!(
            store.get_block_hash_by_height(100).is_none(),
            "apply order changed: `StoreBatch::merge` must keep keyed puts \
             and removes disjoint, and this test documents why"
        );
        assert!(store.get_tx_location(&txid).is_none());
    }

    #[test]
    fn test_undo_roundtrip() {
        let (store, _dir) = temp_store(false);
        let block_hash = make_block_hash(0x22);
        let coin = make_coin(1_000_000, 50);
        let undo = UndoData {
            spent_coins: vec![coin],
        };

        let mut batch = StoreBatch::default();
        batch.undo_puts.push((block_hash, undo));
        store.write_batch(batch).unwrap();

        let recovered = store.get_undo(&block_hash).unwrap();
        assert_eq!(recovered.spent_coins.len(), 1);
        assert_eq!(recovered.spent_coins[0].amount, 1_000_000);
    }

    #[test]
    fn for_each_block_index_surfaces_decode_skip_counts() {
        // Regression for the M4 review finding: `for_each_block_index`
        // used to silently skip rows whose key/value failed to decode,
        // which made the blockfile audit understate references and hide
        // `block_index` corruption. The trait now returns
        // `BlockIndexScanStats`; counts must reflect both failure modes.
        let (store, _dir) = temp_store(false);

        // Insert one legitimate row through the normal write path.
        let (hash, entry) = regtest_genesis_entry();
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        store.write_batch(batch).unwrap();

        // Inject corrupt rows directly into the CF, bypassing
        // write_batch. Two distinct shapes:
        //   - bad key: shorter than 32 bytes, so `hash_from_bytes`
        //     returns None.
        //   - bad value: a 32-byte hash key but garbage bytes for the
        //     entry, so bincode::deserialize fails.
        let cf = store.cf(CF_BLOCK_INDEX);
        store
            .db
            .put_cf(&cf, b"too-short-key", b"irrelevant")
            .unwrap();
        let bad_value_hash = make_block_hash(0xAB);
        store
            .db
            .put_cf(&cf, hash_bytes(&bad_value_hash), b"definitely-not-bincode")
            .unwrap();

        let mut seen = 0u64;
        let stats = store
            .for_each_block_index(&mut |_h, _e| {
                seen += 1;
            })
            .unwrap();
        assert_eq!(seen, 1, "only the legitimate row should reach the visitor");
        assert_eq!(stats.skipped_bad_key, 1);
        assert_eq!(stats.skipped_bad_value, 1);
    }

    #[test]
    fn test_txindex_enabled() {
        let (store, _dir) = temp_store(true);
        assert!(store.has_txindex());

        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xBB; 32]));
        let (block_hash, mut entry) = regtest_genesis_entry();
        entry.height = 0;
        entry.num_tx = 1;

        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((block_hash, entry));
        batch.height_hash_puts.push((0, block_hash));
        batch.tx_loc_puts.push((txid, 0));
        batch.txseq_txid_puts.push((0, txid));
        batch.txseq_block_puts.push((0, 0));
        store.write_batch(batch).unwrap();

        // `get_tx_location` is composed from the two ordinal families
        // plus the height index; all three have to be right for it to
        // answer, which is why the fixture writes the block rows too.
        assert_eq!(store.get_tx_seq(&txid), Some(0));
        assert_eq!(store.txids_of_seqs(&[0]), vec![Some(txid)]);
        assert_eq!(store.block_of_seq(0), Some((0, 0)));
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
        batch.tx_loc_puts.push((txid, 0));
        batch.txseq_txid_puts.push((0, txid));
        batch.txseq_block_puts.push((0, 0));
        store.write_batch(batch).unwrap();

        assert!(store.get_block_index(&genesis_hash).is_some());
        assert!(store.has_coin(&op));
        assert_eq!(store.get_tip().unwrap(), tip_hash);
        assert_eq!(store.get_block_hash_by_height(0).unwrap(), genesis_hash);
        assert_eq!(store.get_tx_location(&txid).unwrap(), genesis_hash);
    }

    /// Regression: `ChainState` holds a `Box<dyn Store>` that is in
    /// fact a `CoinCache` wrapping `RocksDbStore`. The Store trait
    /// provides empty defaults for the per-CF diagnostics, so a
    /// missing delegation on `CoinCache` short-circuits to those
    /// defaults and reports zero — which is what shipped in #189/#192
    /// and showed up as `RocksDB SST size snapshot total_mb=0
    /// per_cf=` on the live mainnet node despite ~890 GB of SSTs.
    /// This test goes through `CoinCache` (mirroring production)
    /// rather than calling `RocksDbStore` directly.
    #[test]
    fn coin_cache_delegates_per_cf_diagnostics() {
        use crate::storage::coin_cache::CoinCache;
        let dir = tempfile::tempdir().unwrap();
        let inner = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        // Hold a direct handle to the RocksDB so we can flush coins
        // explicitly after write. After moving inner into CoinCache
        // we can no longer touch RocksDB internals; cheaper to flush
        // first via the bare store, then wrap.
        let mut batch = StoreBatch::default();
        for i in 0..512u32 {
            batch
                .coin_puts
                .push((make_outpoint((i & 0xff) as u8, i), make_coin(i as u64, i)));
        }
        inner.write_batch(batch).unwrap();
        // Flush the coins CF so its bytes land in an SST visible to
        // the metadata API.
        let cf = inner.cf(CF_COINS);
        let mut fopts = rocksdb::FlushOptions::default();
        fopts.set_wait(true);
        inner.db.flush_cfs_opt(&[&cf], &fopts).unwrap();
        drop(cf);

        let cache = CoinCache::new(Box::new(inner), 16);
        let breakdown = cache.sst_bytes_by_cf();
        assert!(
            !breakdown.is_empty(),
            "CoinCache must forward sst_bytes_by_cf to the inner store, \
             not return the trait default empty vec"
        );
        let coins = breakdown
            .iter()
            .find(|(name, _)| *name == CF_COINS)
            .map(|(_, b)| *b)
            .expect("coins CF must appear in breakdown");
        assert!(
            coins > 0,
            "coins CF SST size must be non-zero after flush; got breakdown={:?}",
            breakdown
        );

        // pending_compaction_bytes_by_cf delegates the same way; assert
        // it returns the same shape (one entry per registered CF). It
        // may be all-zero on a fresh DB, hence we only check shape.
        let pending = cache.pending_compaction_bytes_by_cf();
        assert!(
            !pending.is_empty(),
            "CoinCache must forward pending_compaction_bytes_by_cf to the \
             inner store, not return the trait default empty vec"
        );
        assert_eq!(
            pending.len(),
            breakdown.len(),
            "the two per-CF diagnostics must enumerate the same CF set"
        );
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
        batch.tx_loc_puts.push((txid, 0));
        batch.txseq_txid_puts.push((0, txid));
        batch.txseq_block_puts.push((0, 0));
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
        let _af = store.cf(CF_ADDR_FUNDING_V3);
        let _as_ = store.cf(CF_ADDR_SPENDING_V2);
    }

    #[test]
    fn test_address_index_cfs_persist_across_reopen() {
        // Auto-creation should also be idempotent: reopening an
        // existing datadir must not error and must keep the CFs.
        let dir = tempfile::tempdir().unwrap();
        {
            let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
            let _af = store.cf(CF_ADDR_FUNDING_V3);
        }
        let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        let _af = store.cf(CF_ADDR_FUNDING_V3);
        let _as_ = store.cf(CF_ADDR_SPENDING_V2);
    }

    #[test]
    fn open_at_isolates_two_chainstates_under_one_datadir() {
        // AssumeUTXO runs a primary (snapshot) chainstate at
        // `<datadir>/chainstate` and a background chainstate at
        // `<datadir>/chainstate_background`. They must be independent
        // RocksDB instances: a write to one is invisible to the other,
        // and each persists to its own subdir.
        let dir = tempfile::tempdir().unwrap();
        let datadir = dir.path();
        let bg_path = datadir.join("chainstate_background");

        let primary = RocksDbStore::open(datadir, false, 16, false, -1).unwrap();
        let background =
            RocksDbStore::open_at(&bg_path, false, 16, false, -1, StorageTuning::default())
                .unwrap();

        let op_primary = make_outpoint(0x11, 0);
        let op_bg = make_outpoint(0x22, 0);

        let mut b = StoreBatch::default();
        b.coin_puts.push((op_primary, make_coin(1_000, 1)));
        primary.write_batch(b).unwrap();

        let mut b = StoreBatch::default();
        b.coin_puts.push((op_bg, make_coin(2_000, 2)));
        background.write_batch(b).unwrap();

        // Each store sees only its own coin.
        assert!(primary.get_coin(&op_primary).is_some());
        assert!(primary.get_coin(&op_bg).is_none());
        assert!(background.get_coin(&op_bg).is_some());
        assert!(background.get_coin(&op_primary).is_none());

        // Both subdirs exist on disk and are distinct.
        assert!(datadir.join("chainstate").is_dir());
        assert!(bg_path.is_dir());

        // The background DB persists to its chosen subdir: drop and
        // reopen via open_at, its coin survives and the primary's never
        // bled across.
        drop(background);
        let reopened =
            RocksDbStore::open_at(&bg_path, false, 16, false, -1, StorageTuning::default())
                .unwrap();
        assert!(reopened.get_coin(&op_bg).is_some());
        assert!(reopened.get_coin(&op_primary).is_none());
    }

    #[test]
    fn test_address_index_write_batch_funding_put_then_read() {
        use crate::index::address::{AddrFundingRowV3, encode_funding_key_v3, encode_funding_value};

        let (store, _dir) = temp_store(false);
        let row = AddrFundingRowV3 {
            scripthash: [0xAB; 32],
            txseq: 42,
            vout: 7,
            amount_sat: 123_456_789,
        };

        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(row);
        store.write_batch(batch).unwrap();

        let cf = store.cf(CF_ADDR_FUNDING_V3);
        let encoded = encode_funding_key_v3(&row.key());
        let raw = store
            .db
            .get_cf(&cf, encoded)
            .unwrap()
            .expect("row present");
        assert_eq!(
            raw.as_slice(),
            encode_funding_value(row.amount_sat).as_slice()
        );
    }

    #[test]
    fn test_address_index_write_batch_spending_put_then_remove() {
        use crate::index::address::{
            AddrSpendingRow, encode_spending_key_v2, encode_spending_value,
        };

        let (store, _dir) = temp_store(false);
        let prev = make_outpoint(0xEE, 3);
        let row = AddrSpendingRow {
            scripthash: [0x10; 32],
            height: 99,
            txid: make_outpoint(0x55, 0).txid,
            vin: 2,
            prev_outpoint: prev,
        };

        let mut batch = StoreBatch::default();
        batch.addr_spending_puts.push(row.clone());
        store.write_batch(batch).unwrap();

        let cf = store.cf(CF_ADDR_SPENDING_V2);
        let encoded = encode_spending_key_v2(&row.key());
        let raw = store
            .db
            .get_cf(&cf, encoded)
            .unwrap()
            .expect("row present");
        assert_eq!(
            raw.as_slice(),
            encode_spending_value(&row.prev_outpoint).as_slice()
        );

        // Remove round-trips the deletion path used by disconnect_block.
        let mut rm = StoreBatch::default();
        rm.addr_spending_removes.push(row.key());
        store.write_batch(rm).unwrap();
        assert!(store.db.get_cf(&cf, encoded).unwrap().is_none());
    }

    /// Seed the rows a `spent` lookup needs to resolve: one block at
    /// `height` whose transactions start at `first_txseq`, and a
    /// forward/reverse ordinal pair for each txid given.
    ///
    /// The spend index no longer stores the identifiers it returns —
    /// that is the point — so a fixture has to provide what they resolve
    /// through, exactly as a connected block would.
    fn seed_ordinal_block(
        store: &RocksDbStore,
        height: u32,
        first_txseq: u64,
        txids: &[Txid],
    ) -> BlockHash {
        let hash = make_block_hash(0x50 + height as u8);
        let (_, mut entry) = regtest_genesis_entry();
        entry.height = height;
        entry.num_tx = txids.len() as u32;
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        batch.height_hash_puts.push((height, hash));
        batch.txseq_block_puts.push((first_txseq, height));
        for (i, txid) in txids.iter().enumerate() {
            batch.tx_loc_puts.push((*txid, first_txseq + i as u64));
            batch.txseq_txid_puts.push((first_txseq + i as u64, *txid));
        }
        store.write_batch(batch).unwrap();
        hash
    }

    /// Pass 1 of the address backfill records a scripthash *and* the
    /// funding transaction's ordinal, because pass 2 needs both and can
    /// recompute neither without re-reading the funding output's block.
    ///
    /// The length check is exact rather than a minimum: a value of any
    /// other width is a row from a different layout, and reading the
    /// first 32 bytes of one would hand pass 2 an ordinal it invented.
    #[test]
    fn backfill_temp_value_carries_the_ordinal_and_rejects_v2_length() {
        let (store, _dir) = temp_store(false);
        store.create_backfill_temp_cf().unwrap();
        let op = make_outpoint(0x5e, 3);
        let sh = [0x7a; 32];

        let mut batch = StoreBatch::default();
        batch.addr_backfill_temp_puts.push((op, sh, 4_242));
        store.write_batch(batch).unwrap();

        assert_eq!(
            store.lookup_backfill_temp(&op).unwrap(),
            Some((sh, 4_242)),
            "pass 2 reads back both halves"
        );

        // A bare 32-byte value — the shape pass 1 wrote before the
        // ordinal was added — must be refused, not silently truncated.
        let cf = store.cf(CF_ADDR_BACKFILL_TEMP);
        store
            .db
            .put_cf(&cf, backfill_temp_key(&op), sh)
            .expect("inject a previous-layout row");
        match store.lookup_backfill_temp(&op) {
            Err(StoreError::Database(msg)) => assert!(
                msg.contains("corrupt backfill temp value"),
                "expected a corruption diagnostic, got {msg}"
            ),
            other => panic!("a 32-byte value must be refused, got {other:?}"),
        }
    }

    #[test]
    fn test_spent_write_batch_put_then_lookup() {
        let (store, _dir) = temp_store(false);
        let funding = make_outpoint(0x77, 2);
        let spender = make_outpoint(0xab, 0).txid;
        // Funding transaction at ordinal 10 (height 5), spender at
        // ordinal 20 (height 100).
        seed_ordinal_block(&store, 5, 10, &[funding.txid]);
        seed_ordinal_block(&store, 100, 20, &[spender]);

        let mut batch = StoreBatch::default();
        batch.spent_puts.push(node_index::SpentRow {
            funding_txseq: 10,
            vout: funding.vout,
            spending_txseq: 20,
            vin: 4,
        });
        store.write_batch(batch).unwrap();

        // The row carries two ordinals and sixteen bytes; what comes
        // back is the txid and height the caller expects.
        assert_eq!(
            store.lookup_spend(&funding).unwrap(),
            Some(node_index::SpendingRef {
                spending_txid: spender,
                spending_vin: 4,
                height: 100,
            })
        );
    }

    #[test]
    fn test_spent_write_batch_remove_clears_row() {
        let (store, _dir) = temp_store(false);
        let funding = make_outpoint(0x66, 0);
        let spender = make_outpoint(0x99, 0).txid;
        seed_ordinal_block(&store, 1, 3, &[funding.txid]);
        seed_ordinal_block(&store, 7, 9, &[spender]);

        let mut put = StoreBatch::default();
        put.spent_puts.push(node_index::SpentRow {
            funding_txseq: 3,
            vout: 0,
            spending_txseq: 9,
            vin: 0,
        });
        store.write_batch(put).unwrap();
        assert!(store.lookup_spend(&funding).unwrap().is_some());

        let mut rm = StoreBatch::default();
        rm.spent_removes.push((3, 0));
        store.write_batch(rm).unwrap();
        assert_eq!(store.lookup_spend(&funding).unwrap(), None);
    }

    /// One prefix scan returns every spend of a transaction, which is
    /// what the 5-byte ordinal key prefix is for. Unspent outputs are
    /// absent rather than present-and-empty.
    #[test]
    fn test_spent_lookup_spends_of_tx_returns_every_spent_output() {
        let (store, _dir) = temp_store(false);
        let funding = make_outpoint(0x21, 0).txid;
        let spender_a = make_outpoint(0x22, 0).txid;
        let spender_b = make_outpoint(0x23, 0).txid;
        seed_ordinal_block(&store, 1, 100, &[funding]);
        seed_ordinal_block(&store, 2, 200, &[spender_a, spender_b]);

        let mut batch = StoreBatch::default();
        // vouts 0 and 2 spent; vout 1 left unspent.
        batch.spent_puts.push(node_index::SpentRow {
            funding_txseq: 100,
            vout: 0,
            spending_txseq: 200,
            vin: 0,
        });
        batch.spent_puts.push(node_index::SpentRow {
            funding_txseq: 100,
            vout: 2,
            spending_txseq: 201,
            vin: 1,
        });
        // A spend of a *different* funding transaction, to prove the
        // prefix scan stops at its own prefix.
        batch.spent_puts.push(node_index::SpentRow {
            funding_txseq: 101,
            vout: 0,
            spending_txseq: 200,
            vin: 3,
        });
        store.write_batch(batch).unwrap();

        let got = store.lookup_spends_of_tx(&funding).unwrap();
        assert_eq!(
            got,
            vec![
                (
                    0,
                    node_index::SpendingRef {
                        spending_txid: spender_a,
                        spending_vin: 0,
                        height: 2
                    }
                ),
                (
                    2,
                    node_index::SpendingRef {
                        spending_txid: spender_b,
                        spending_vin: 1,
                        height: 2
                    }
                ),
            ],
            "only this transaction's spent outputs, in vout order"
        );
    }

    #[test]
    fn test_spent_lookup_unknown_returns_none() {
        let (store, _dir) = temp_store(false);
        let unknown = make_outpoint(0xff, 9);
        assert_eq!(store.lookup_spend(&unknown).unwrap(), None);
    }

    #[test]
    fn test_spent_lookup_on_corrupt_value_returns_error() {
        let (store, _dir) = temp_store(false);
        let prev = make_outpoint(0xaa, 0);
        seed_ordinal_block(&store, 1, 42, &[prev.txid]);
        // Inject a malformed value (wrong length) directly via the CF
        // handle, bypassing the codec. This simulates an on-disk
        // corruption or a future codec mismatch.
        let cf = store.cf(CF_SPENT);
        let key = node_index::encode_spent_key(42, prev.vout);
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
    fn test_spent_complete_true_on_fresh_datadir() {
        let (store, _dir) = temp_store(false);
        // Fresh datadir → marker stamped true on first open.
        assert!(store.spent_complete());
    }

    #[test]
    fn test_spent_complete_false_on_legacy_upgrade() {
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
                .delete_cf(&cf, SPENT_COMPLETE_KEY)
                .unwrap();
        }
        let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        assert!(!store.spent_complete());
    }

    #[test]
    fn test_spent_complete_marker_persists_across_reopen() {
        // Once stamped false, the warning must keep firing on each
        // restart even after live connect_block has appended new
        // outpoint_spend rows. (Round-2 H6 contract.)
        let dir = tempfile::tempdir().unwrap();
        {
            let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
            // Force the marker false via the helper; this is what
            // open() does when it detects a legacy datadir.
            store.write_spent_complete(false).unwrap();
        }
        let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        assert!(!store.spent_complete());
    }

    #[test]
    fn test_spent_complete_after_clear_chainstate() {
        let (store, _dir) = temp_store(false);
        store.write_spent_complete(false).unwrap();
        assert!(!store.spent_complete());
        store.clear_chainstate().unwrap();
        // -reindex-chainstate stamps complete because every block
        // will be re-applied via connect_block.
        assert!(store.spent_complete());
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
            txseq: node_index::TXSEQ_UNKNOWN,
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
        assert!(store.spent_complete());
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
        use crate::index::address::AddrFundingRowV3;
        let (store, _dir) = temp_store(false);

        // Fifty rows, one per block, each in its own transaction — the
        // ordinal scaffolding has to exist or the rows resolve to
        // nothing and the iterator (correctly) drops them.
        let sh = [0xab; 32];
        let txids: Vec<Txid> = (0..50u32)
            .map(|i| make_outpoint(0x10 + (i as u8 % 8), i).txid)
            .collect();
        for (i, txid) in txids.iter().enumerate() {
            seed_ordinal_block(&store, i as u32, i as u64, std::slice::from_ref(txid));
        }
        let mut batch = StoreBatch::default();
        for i in 0..50u32 {
            batch.addr_funding_puts.push(AddrFundingRowV3 {
                scripthash: sh,
                txseq: i as u64,
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

    /// A txid whose internal bytes start with `first` and end with `last`.
    /// `Txid`'s `Ord` compares internal bytes, so `first` decides it;
    /// the display hex is the reverse, so `last` decides that. Picking
    /// the two to disagree is what tells the three orders apart.
    fn txid_with_ends(first: u8, last: u8) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[0] = first;
        bytes[31] = last;
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(bytes))
    }

    /// The documented iteration order is `(height, txid, vout)`, but on
    /// disk the rows sort by *ordinal*, which is block position. Within
    /// a block the two disagree, so the store sorts the resolved rows
    /// before returning them.
    ///
    /// "txid order" is `Txid`'s `Ord` — internal byte order, which the
    /// previous schema had on disk and the lockstep merge in
    /// `confirmed_distinct_history_limited` compares by. The fixture is
    /// built so that block order, internal order and display-hex order
    /// are three different orders: a store that returned the raw scan
    /// *or* sorted by display hex fails it (round-1 review, PR 803 H1).
    ///
    /// This is the RocksDB-path guard, and it is not redundant with the
    /// `lookups.rs` order test: that one runs against `InMemoryStore`,
    /// which has its own sort, so it passes with this one deleted.
    #[test]
    fn iter_addr_rows_come_back_in_the_documented_order_not_ordinal_order() {
        use crate::index::address::AddrFundingRowV3;
        let (store, _dir) = temp_store(false);
        let sh = [0x3e; 32];

        // One block, three transactions. Block position ascends with the
        // *last* byte, so display-hex order equals block order and
        // internal order is its exact reverse.
        let txids = [
            txid_with_ends(0x03, 0x01),
            txid_with_ends(0x02, 0x02),
            txid_with_ends(0x01, 0x03),
        ];
        assert!(
            txids[0] > txids[1] && txids[1] > txids[2],
            "fixture premise: block position and txid order disagree"
        );
        assert!(
            txids[0].to_string() < txids[1].to_string()
                && txids[1].to_string() < txids[2].to_string(),
            "fixture premise: display-hex order is block order, not txid order"
        );
        seed_ordinal_block(&store, 4, 100, &txids);

        let mut batch = StoreBatch::default();
        for i in 0..txids.len() {
            batch.addr_funding_puts.push(AddrFundingRowV3 {
                scripthash: sh,
                txseq: 100 + i as u64,
                vout: 0,
                amount_sat: 1,
            });
        }
        store.write_batch(batch).unwrap();

        let mut expected = txids.to_vec();
        expected.sort();
        let funding: Vec<Txid> = store
            .iter_addr_funding(&sh)
            .into_iter()
            .map(|(k, _)| k.txid)
            .collect();
        assert_eq!(
            funding, expected,
            "funding rows must come back in (height, txid, vout) order, \
             not the ordinal order they are stored in"
        );
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
    fn prefix_collisions_admitted() {
        // Two different full scripthashes that share the first 16
        // bytes will both surface in a read for either. The
        // module-level docstring spells out this collision-tolerant
        // posture; the test pins it so an accidental tightening
        // (e.g. adding a full-scripthash redundancy check) is loud.
        use crate::index::address::AddrFundingRowV3;

        let (store, _dir) = temp_store(false);
        let sh_alice = {
            let mut sh = [0u8; 32];
            sh[..16].copy_from_slice(&[0xAB; 16]);
            sh[16..].copy_from_slice(&[0x01; 16]);
            sh
        };
        let sh_mallory = {
            let mut sh = [0u8; 32];
            sh[..16].copy_from_slice(&[0xAB; 16]); // collides on prefix
            sh[16..].copy_from_slice(&[0x99; 16]);
            sh
        };

        seed_ordinal_block(&store, 1, 10, &[make_outpoint(0xA1, 0).txid]);
        seed_ordinal_block(&store, 2, 20, &[make_outpoint(0xA2, 0).txid]);
        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(AddrFundingRowV3 {
            scripthash: sh_alice,
            txseq: 10,
            vout: 0,
            amount_sat: 1,
        });
        batch.addr_funding_puts.push(AddrFundingRowV3 {
            scripthash: sh_mallory,
            txseq: 20,
            vout: 0,
            amount_sat: 2,
        });
        store.write_batch(batch).unwrap();

        // Querying with Alice's full scripthash returns BOTH rows
        // because they're indistinguishable at the 16-byte prefix.
        // Returned keys carry Alice's scripthash (the caller's
        // identity) even for Mallory's row — that's the trade-off.
        let got = store.iter_addr_funding(&sh_alice);
        assert_eq!(
            got.len(),
            2,
            "a prefix collision must yield both rows, not silently filter",
        );
        for (k, _) in &got {
            assert_eq!(k.scripthash, sh_alice);
        }
    }

    #[test]
    fn test_spent_persists_across_reopen() {
        // Verifies the CF descriptor is registered on subsequent opens
        // (so an existing chainstate-on-disk doesn't fail to mount).
        let dir = tempfile::tempdir().unwrap();
        let prev = make_outpoint(0x33, 1);
        let spender = make_outpoint(0x44, 0).txid;
        {
            let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
            seed_ordinal_block(&store, 1, 5, &[prev.txid]);
            seed_ordinal_block(&store, 50, 60, &[spender]);
            let mut batch = StoreBatch::default();
            batch.spent_puts.push(node_index::SpentRow {
                funding_txseq: 5,
                vout: prev.vout,
                spending_txseq: 60,
                vin: 2,
            });
            store.write_batch(batch).unwrap();
        }
        let store2 = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        assert_eq!(
            store2.lookup_spend(&prev).unwrap(),
            Some(node_index::SpendingRef {
                spending_txid: spender,
                spending_vin: 2,
                height: 50,
            })
        );
    }

    #[test]
    fn test_address_index_empty_batch_does_not_touch_cfs() {
        // Sanity: the empty-batch fast-path in write_batch_mode must
        // not panic or write spurious rows.
        let (store, _dir) = temp_store(false);
        store.write_batch(StoreBatch::default()).unwrap();
        // Both CFs must still be empty.
        let af = store.cf(CF_ADDR_FUNDING_V3);
        let as_ = store.cf(CF_ADDR_SPENDING_V2);
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
        use crate::index::address::{AddrFundingRowV3, AddrSpendingRow, scripthash_of, stats};

        // Use a fresh process snapshot to compute deltas — the static
        // counters accumulate across tests in the same binary.
        let before = stats::snapshot();

        let (store, _dir) = temp_store(false);
        let sh = scripthash_of(&bitcoin::ScriptBuf::new());
        let txid = bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [0xab; 32],
        ));

        let mut batch = StoreBatch::default();
        batch.addr_funding_puts.push(AddrFundingRowV3 {
            scripthash: sh,
            txseq: 1,
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

    /// Create a datadir that *looks* like one written by a previous
    /// satd build (schema-version stamped, legacy CFs registered in
    /// the manifest). The optional `legacy_rows` populates the legacy
    /// CFs with a single junk row so we can exercise the "non-empty"
    /// branch. Returns the datadir path (the parent of the RocksDB
    /// `chainstate/` directory; matches what `RocksDbStore::open`
    /// expects as its `path` argument) plus the temp dir guard.
    fn synth_prior_datadir(
        schema_version: u32,
        legacy_rows: bool,
    ) -> (std::path::PathBuf, tempfile::TempDir) {
        synth_prior_datadir_with(schema_version, legacy_rows, false)
    }

    fn synth_prior_datadir_with(
        schema_version: u32,
        legacy_rows: bool,
        v0_undo_row: bool,
    ) -> (std::path::PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let datadir = dir.path().to_path_buf();
        let path = datadir.join("chainstate");
        std::fs::create_dir_all(&path).unwrap();

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_METADATA, Options::default()),
            ColumnFamilyDescriptor::new(CF_COINS, Options::default()),
            ColumnFamilyDescriptor::new(CF_UNDO, Options::default()),
            ColumnFamilyDescriptor::new("addr_funding", Options::default()),
            ColumnFamilyDescriptor::new("addr_spending", Options::default()),
        ];
        let db = DB::open_cf_descriptors(&opts, &path, cfs).unwrap();
        RocksDbStore::stamp_schema(&db, schema_version).unwrap();
        if legacy_rows {
            let af = db.cf_handle("addr_funding").unwrap();
            let as_ = db.cf_handle("addr_spending").unwrap();
            db.put_cf(&af, b"row", b"junk").unwrap();
            db.put_cf(&as_, b"row", b"junk").unwrap();
        }
        if v0_undo_row {
            // Bytes that DON'T start with V1_MAGIC — simulates a row
            // written by the pre-cleanup bincode-format undo path.
            let cf_undo = db.cf_handle(CF_UNDO).unwrap();
            db.put_cf(&cf_undo, b"hash", [0x01u8, 0, 0, 0, 0, 0, 0, 0])
                .unwrap();
        }
        drop(db);
        (datadir, dir)
    }

    /// Read the persisted schema marker without going through
    /// `RocksDbStore::open` (which would refuse on mismatch).
    fn read_schema_version_raw(datadir: &std::path::Path) -> Option<u32> {
        let path = datadir.join("chainstate");
        let opts = Options::default();
        let existing = DB::list_cf(&opts, &path).unwrap_or_default();
        let cfs: Vec<_> = existing
            .into_iter()
            .map(|n| ColumnFamilyDescriptor::new(n, Options::default()))
            .collect();
        let db = DB::open_cf_descriptors(&opts, &path, cfs).unwrap();
        let cf_meta = db.cf_handle(CF_METADATA)?;
        let raw = db.get_cf(&cf_meta, SCHEMA_KEY).ok()??;
        Some(u32::from_le_bytes(raw[..].try_into().ok()?))
    }

    #[test]
    fn open_with_legacy_addr_cfs_at_current_schema_drops_them() {
        // Migration-tooling residue: legacy `addr_funding` /
        // `addr_spending` CFs registered in the manifest but empty,
        // chainstate stamped at the current schema version. Open must
        // succeed and drop the legacy CFs.
        let (path, _dir) = synth_prior_datadir(CURRENT_SCHEMA_VERSION, false);
        let store = RocksDbStore::open(&path, false, 16, false, -1)
            .expect("open should succeed: legacy CFs are empty and schema is current");
        assert!(
            store.db.cf_handle("addr_funding").is_none(),
            "legacy addr_funding CF must be dropped",
        );
        assert!(
            store.db.cf_handle("addr_spending").is_none(),
            "legacy addr_spending CF must be dropped",
        );
        // Re-opening must still succeed (the drop is persisted in the manifest).
        drop(store);
        let _ = RocksDbStore::open(&path, false, 16, false, -1).expect("reopen ok");
    }

    /// Every schema older than the current one is refused, with the
    /// message that names the recovery. There is no in-place upgrade arm
    /// any more: schema 4 changed how the transaction index is *keyed*,
    /// so there is nothing to re-stamp — the new families have to be
    /// built from the blocks, which is what `-reindex-chainstate` does.
    ///
    /// Opening a v3 datadir under a v4 binary without refusing would be
    /// the worst outcome available: `tx_index` still holds rows, the
    /// binary reads none of them, and every confirmed lookup would
    /// silently answer "not found" on a chain that has the transaction.
    #[test]
    fn a_prior_schema_datadir_is_refused_with_the_reindex_chainstate_message() {
        for stored in [2u32, 3] {
            let (path, _dir) = synth_prior_datadir(stored, false);
            let err = RocksDbStore::open(&path, false, 16, false, -1)
                .err()
                .unwrap_or_else(|| panic!("open should refuse a v{stored} chainstate"));
            let msg = match err {
                StoreError::Database(s) => s,
                other => panic!("expected Database error, got {:?}", other),
            };
            assert!(
                msg.contains(&format!("DB has v{stored}")),
                "error should name the stored version: {msg}"
            );
            assert!(
                msg.contains(&format!("binary expects v{CURRENT_SCHEMA_VERSION}")),
                "error should name the expected version: {msg}"
            );
            assert!(
                msg.contains("--reindex-chainstate"),
                "error should name the recovery: {msg}"
            );
            // And the refusal must be durable: a second open sees the
            // same stored version, not a marker the failed open moved.
            assert_eq!(read_schema_version_raw(&path), Some(stored));
        }
    }

    #[test]
    fn reindex_open_drops_legacy_cfs_even_with_rows() {
        // Reindex flow: chainstate is about to be wiped anyway, so
        // non-empty legacy CFs are not a refusal — they get dropped
        // as part of opening for the reindex.
        let (path, _dir) = synth_prior_datadir(CURRENT_SCHEMA_VERSION - 1, true);
        let store = RocksDbStore::open(&path, false, 16, true, -1)
            .expect("reindex open should succeed regardless of schema or legacy CFs");
        assert!(store.db.cf_handle("addr_funding").is_none());
        assert!(store.db.cf_handle("addr_spending").is_none());
    }

    /// `flush_durable` must persist WAL-less (BulkLoad) writes in EVERY
    /// column family, not just the default CF. A WAL-less write that is
    /// still in a memtable after `flush_durable` returns will be silently
    /// lost on any exit that skips the DB destructor (std::process::exit,
    /// SIGKILL, panic-abort) — exactly the mainnet 952978 data-loss bug.
    ///
    /// The assertion uses the per-CF active-memtable entry count so it
    /// does not depend on close/reopen semantics (RocksDB flushes WAL-less
    /// memtables on a *clean* close, which would mask the bug).
    #[test]
    fn flush_durable_persists_walless_writes_in_data_cfs() {
        let (store, _dir) = temp_store(true);

        // A realistic connect batch: coins, block index, undo, height
        // index, tip, ordinals — written WAL-less as during IBD/reindex.
        let (hash, entry) = regtest_genesis_entry();
        let mut batch = StoreBatch::default();
        batch.coin_puts.push((make_outpoint(0xAA, 0), make_coin(50_000, 1)));
        batch.block_index_puts.push((hash, entry));
        batch.tip = Some(hash);
        batch.height_hash_puts.push((1, hash));
        let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xAA; 32]));
        batch.tx_loc_puts.push((txid, 0));
        batch.txseq_txid_puts.push((0, txid));
        batch.txseq_block_puts.push((0, 1));
        store
            .write_batch_mode(batch, WriteMode::BulkLoad)
            .unwrap();

        store.flush_durable().unwrap();

        // After a durable flush, no data CF may still hold the write in
        // its (volatile, WAL-less) active memtable.
        for cf_name in [
            CF_COINS,
            CF_BLOCK_INDEX,
            CF_HEIGHT_INDEX,
            CF_TX_LOC,
            CF_TXSEQ_TXID,
            CF_TXSEQ_BLOCK,
            CF_METADATA,
        ] {
            let cf = store.cf(cf_name);
            let entries = store
                .db
                .property_int_value_cf(&cf, "rocksdb.num-entries-active-mem-table")
                .unwrap()
                .unwrap_or(0);
            assert_eq!(
                entries, 0,
                "CF `{cf_name}` still has {entries} entries in its active memtable \
                 after flush_durable(); WAL-less writes there will be lost on \
                 process exit without a clean DB close"
            );
        }

        // And the data must actually be readable back.
        assert!(store.get_coin(&make_outpoint(0xAA, 0)).is_some());
    }
}
