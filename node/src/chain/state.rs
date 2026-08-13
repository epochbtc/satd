use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, Network, OutPoint};
use parking_lot::{Mutex, RwLock};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::chain::checkpoints::{self, Checkpoint};
use crate::chain::{connect, disconnect};
use crate::storage::blockindex::{BlockIndexEntry, BlockStatus, add_u256, work_for_bits};
use crate::storage::coin_cache::CoinCache;
use crate::storage::coinview::Coin;
use crate::storage::flatfile::{FlatFileManager, FlatFilePos};
use crate::storage::{Store, StoreError};
use crate::validation;
use crate::validation::script::{NoopVerifier, ScriptVerifier};

/// Current wall-clock time in seconds since the Unix epoch, for the
/// future-block-time consensus check. Returns 0 if the system clock is
/// before the epoch (impossible in practice), which only makes the check
/// stricter, never laxer.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Controls script verification skipping during IBD.
/// Matches Bitcoin Core's `--assumevalid` semantics as a superset.
#[derive(Debug, Clone)]
pub enum AssumeValid {
    /// Verify all scripts (equivalent to `--assumevalid=0`).
    Disabled,
    /// Skip script verification for blocks at or below the given hash.
    /// The hash must appear in the block index before skipping takes effect.
    Hash(BlockHash),
    /// Skip script verification for blocks older than a cutoff duration.
    /// satd extension (`--assumevalid=all`) — trusts the network for the existing
    /// chain but fully verifies recent and new blocks.
    /// The cutoff is controlled by `--assumevalidage` (default: 86400 seconds / 24 hours).
    All { max_age_secs: u64 },
}

/// Per-network default assumevalid hashes.
/// These are well-known blocks deep in the chain that the community has validated.
/// Matches Bitcoin Core's approach of shipping a default per release.
pub fn default_assumevalid(network: Network) -> AssumeValid {
    match network {
        Network::Bitcoin => {
            // Bitcoin Core v28.0 default (height 840,000)
            AssumeValid::Hash(
                "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
                    .parse()
                    .unwrap(),
            )
        }
        Network::Signet => {
            // Signet block at height 218,000 (before the heavy-tx region)
            AssumeValid::Hash(
                "000000f085851d46ad302bcc9246d00435ec24f2095fb9cfa9523837bbac1da3"
                    .parse()
                    .unwrap(),
            )
        }
        Network::Testnet => {
            // Testnet3 — no default yet
            AssumeValid::Disabled
        }
        Network::Testnet4 => {
            // Testnet4 — no default yet; validate everything
            AssumeValid::Disabled
        }
        Network::Regtest => {
            // Regtest has no meaningful default
            AssumeValid::Disabled
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("duplicate")]
    Duplicate,
    #[error("bad-prevblk")]
    BadPrevBlock,
    /// The parent is a block this chainstate never connected. Distinct from
    /// [`Self::BadPrevBlock`], which the connector reads as "the frontier is
    /// fork-blocked" and recovers from by handing off to the reorg path. That
    /// recovery is wrong here and actively harmful: it clears the operator
    /// warning on the grounds that the transition is self-healing, and this
    /// one never heals — the coins those ancestors created are simply absent.
    #[error("parent-never-connected")]
    ParentNeverConnected,
    #[error("Block decode failed")]
    DecodeFailed,
    #[error("checkpoint mismatch at height {0}")]
    CheckpointMismatch(u32),
    #[error("{0}")]
    Validation(#[from] validation::ValidationError),
    #[error("{0}")]
    Connect(#[from] connect::ConnectError),
    #[error("{0}")]
    Storage(#[from] StoreError),
    #[error("block file write failed: {0}")]
    FlatFile(String),
    #[error("{0}")]
    Disconnect(#[from] disconnect::DisconnectError),
    #[error("snapshot load failed: {0}")]
    Snapshot(String),
    #[error("block not found")]
    BlockNotFound,
    #[error("{0}")]
    InvalidArgument(String),
}

/// Outcome of [`ChainState::resume_pending_snapshot`] at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotResume {
    /// No pending snapshot — normal startup.
    None,
    /// Re-attached a background validator for a snapshot at `height`.
    Resumed { height: u32 },
    /// A loaded snapshot was durably rejected by background validation;
    /// the caller should refuse to start and force operator recovery.
    Rejected,
}

/// Result of a successful [`ChainState::load_utxo_snapshot`].
#[derive(Debug, Clone)]
pub struct LoadSnapshotSummary {
    pub coins_loaded: u64,
    pub base_height: u32,
    pub base_hash: BlockHash,
    pub tip_height: u32,
}

/// Outcome of [`ChainState::repair_block_data`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockDataRepair {
    /// The block's bytes were missing or unreadable and have been rewritten
    /// from the supplied copy; the index entry now points at the new record.
    Repaired { height: u32 },
    /// The stored bytes read back fine; nothing was written.
    AlreadyPresent { height: u32 },
}

/// Result of a `repair_block_index_holes` pass.
#[derive(Debug, Default, Clone)]
pub struct RepairOutcome {
    /// HeaderOnly block-index entries above tip at the start of the
    /// pass.
    pub holes_found: usize,
    /// Holes resolved by finding the block data in a flat file.
    pub repaired: usize,
    /// Holes where the block data was not present in any flat file —
    /// the operator will need to re-download these via normal IBD.
    pub still_missing: usize,
    /// Total blocks read from flat files during the scan (a measure of
    /// scan throughput and progress).
    pub blocks_scanned: u64,
    pub elapsed_secs: u64,
}

struct ChainTip {
    hash: BlockHash,
    height: u32,
}

/// Data returned by `perform_reorg` so the caller can build a complete
/// `ReorgRecord` once side-chain reconnection has finished. Recording
/// the record at fork-disconnect time (the obvious-but-wrong spot)
/// would misreport `fork_hash` as the new tip and leave
/// `reconnected` empty.
///
/// `disconnected_txs` carries the non-coinbase transactions from the
/// disconnected blocks so the caller can re-offer them to the mempool
/// *after* the side chain has fully reconnected. Re-adding inside
/// `perform_reorg` would validate against the fork-point UTXO set, not
/// the final post-reorg active chain.
///
/// `disconnected_with_height` lets the caller emit
/// `BlockDisconnected` chain events at the *end* of a successful
/// reorg, not inline during the disconnect loop. Inline emission
/// would notify subscribers about a tentative state that might be
/// rolled back if a later reconnect fails.
#[derive(Debug, Clone)]
struct ReorgDisconnectInfo {
    old_tip: BlockHash,
    old_height: u32,
    /// Hashes disconnected, walked old-tip-first toward the fork parent.
    disconnected: Vec<BlockHash>,
    /// (hash, height) pairs in walk-back order (newest disconnected
    /// first → fork-parent last). Used by the deferred chain-event
    /// emission in `connect_tip`.
    disconnected_with_height: Vec<(BlockHash, u32)>,
    /// Non-coinbase transactions from disconnected blocks, in
    /// fork-parent-first order so the caller can re-add parents before
    /// children (chained mempool acceptance).
    disconnected_txs: Vec<bitcoin::Transaction>,
}

/// Staged reorg record: all the inputs to `ReorgRecord::new` except the
/// final tip. The tip is appended only after the final triggering
/// block's `connect_block` + commit + tip update all succeed. Keeping
/// this in-memory and emitting it last means `getreorghistory` never
/// shows a record whose claimed new_tip never actually activated.
struct PendingReorgRecord {
    fork_height: u32,
    old_tip: BlockHash,
    old_height: u32,
    disconnected: Vec<BlockHash>,
    /// Side-chain blocks already reconnected + committed, fork-parent-
    /// first, not yet including the final triggering block.
    reconnected_so_far: Vec<BlockHash>,
    /// Reconnected side-chain blocks paired with their heights. The
    /// height belongs to that block on the new chain — used both for
    /// the post-reorg mempool cleanup (so `remove_for_block` reports
    /// the actual confirmation height per block, not the final tip
    /// height) and for the triggering-block-failure rollback.
    reconnected_blocks: Vec<(bitcoin::Block, u32)>,
    /// Non-coinbase txs from the disconnected blocks, fork-parent-first.
    /// Re-offered to the mempool after the full reorg has activated so
    /// validation runs against the new chain, not the fork point.
    disconnected_txs: Vec<bitcoin::Transaction>,
    /// (hash, height) of the original-chain blocks the reorg
    /// disconnected, newest-first. Used both for the triggering-block-
    /// failure rollback and for the deferred `BlockDisconnected` chain
    /// event emission at the end of a successful reorg.
    original_disconnected: Vec<(BlockHash, u32)>,
}

/// Central chain state manager.
pub struct ChainState {
    store: std::sync::Arc<CoinCache>,
    flat_files: Arc<Mutex<FlatFileManager>>,
    /// Path to the blocks directory, for mutex-free reads.
    blocks_dir: PathBuf,
    /// Blocks-dir obfuscation key (Core v28+ `xor.dat`; zero = plaintext),
    /// captured from the `FlatFileManager` so the mutex-free direct readers
    /// (`read_block_direct`, the prefetch pipeline) de-obfuscate the same way.
    blocks_xor_key: [u8; 8],
    tip: RwLock<ChainTip>,
    pub network: Network,
    script_verifier: Arc<dyn ScriptVerifier>,
    assumevalid: AssumeValid,
    checkpoints: Vec<Checkpoint>,
    /// Whether the checkpoint set is enforced (Core `-checkpoints`, default
    /// true). Set to false by `-checkpoints=0` to skip checkpoint validation.
    enforce_checkpoints: bool,
    /// Highest header height stored (may be ahead of connected block tip during IBD).
    headers_tip_height: AtomicU32,
    /// Most-work header chain tip seen so far — `(hash, chainwork)` — analogous
    /// to Bitcoin Core's `pindexBestHeader`. Updated by `accept_header` /
    /// `accept_headers` whenever a header carries strictly more work. Used to
    /// drive fork-aware block requests: unlike `headers_tip_height` (a height,
    /// monotonic via `fetch_max`) and `get_block_hash_by_height` (the pollutable
    /// "best-known-at-height" index), this names the actual most-work chain, so
    /// a competing chain that is heavier-but-shorter is still pursued.
    best_header: RwLock<(BlockHash, [u8; 32])>,
    /// Cached block timestamps for MTP computation (avoids 22 DB reads per block).
    /// Stores (height, timestamp) pairs for the last ~12 blocks.
    mtp_cache: Mutex<Vec<(u32, u32)>>,
    /// Number of threads for parallel script verification.
    num_threads: usize,
    /// Address-history index runtime config. Threaded into every
    /// `connect_block` / `disconnect_block` call so emission is gated
    /// at runtime without cfg ceremony.
    address_index: crate::index::address::AddressIndexConfig,
    /// BIP 158 compact-block-filter index runtime config. Same
    /// per-call threading as `address_index` — enables filter
    /// emission at end-of-tx-loop in `connect_block` and the inverse
    /// row-removal in `disconnect_block`.
    #[cfg(feature = "block-filter-index")]
    filter_index: crate::index::filter::FilterIndexConfig,
    /// BIP 352 silent-payment tweak index runtime config. Threaded into
    /// every `connect_block` / `disconnect_block` call like
    /// `address_index`. Always present (runtime opt-in, not a cargo
    /// feature).
    sp_index: crate::index::silent_payments::SpIndexConfig,
    /// Persistent reorg history + optional webhook dispatch.
    /// Lazily initialized by `open_reorg_log` — may be absent in tests
    /// that don't care about reorg observability.
    reorg_log: std::sync::OnceLock<std::sync::Arc<crate::chain::reorg_log::ReorgLog>>,
    /// Active node warnings (connect failures, storage issues, etc.).
    /// Always present — warnings are a core operational surface.
    warnings: std::sync::Arc<crate::warnings::NodeWarnings>,
    /// Mempool handle for reorg re-add. Set by `set_mempool` after
    /// construction to avoid a circular Arc cycle (mempool needs
    /// chain_state for UTXO lookups). When unset (test backends),
    /// the reorg re-add path is a no-op.
    mempool: std::sync::OnceLock<std::sync::Arc<crate::mempool::pool::Mempool>>,
    /// Chain-event broadcaster. Populated via `set_chain_event_sender`;
    /// consumed by the address-index notifier task (M5) and any
    /// future observability subscribers. Test backends that don't
    /// need chain notifications skip the wiring; emit is a no-op.
    chain_event_tx: parking_lot::Mutex<
        Option<tokio::sync::broadcast::Sender<crate::chain::events::ChainEvent>>,
    >,
    /// Lock-free monotonic counter bumped on every successful connect.
    /// Read by the stall watchdog to detect connector wedges without
    /// taking the `tip` RwLock, which is precisely the lock the wedge
    /// might be holding. The watchdog observes a stalled value if and
    /// only if the connect path stopped completing — independent of
    /// what state the rest of the runtime is in.
    connect_heartbeat: AtomicU64,
    /// Lock-free monotonic counter bumped on every iteration of the
    /// P2P manager's main `select!` loop. Complements
    /// [`Self::connect_heartbeat`]: that counter only advances when a
    /// block is connected, which is silent for many minutes at mainnet
    /// tip; this counter advances on every loop iteration (default
    /// 500 ms) regardless of block arrivals. The stall watchdog reads
    /// both and considers the node stalled only when *both* counters
    /// have been silent for the threshold — so the default threshold
    /// (300 s) stays valid at tip without false positives, while still
    /// catching true loop-wedge conditions promptly during IBD.
    manager_heartbeat: AtomicU64,
    /// Fine-grained per-phase heartbeat for `connect_preprocessed_block`
    /// and `connect::connect_block`. The single `connect_heartbeat`
    /// counter tells the watchdog *that* the connector wedged; this
    /// tracker tells it *where*. See `connect_phase.rs` for the phase
    /// definitions. Arc'd so the watchdog (a separate `std::thread`)
    /// can share it with the connector.
    connect_phases: std::sync::Arc<crate::chain::connect_phase::ConnectPhaseTracker>,
    /// AssumeUTXO background chainstate. `None` on a normally-synced node
    /// (every existing code path is unchanged). `Some` only between a
    /// successful `loadtxoutset` and the handoff that validates
    /// genesis→snapshot_height. While present, `self` is the *snapshot*
    /// chainstate serving the user-facing tip; the background validates
    /// the history behind it and is dropped (its DB removed) at handoff.
    background: RwLock<Option<Arc<crate::chain::background::BackgroundChainState>>>,
    /// Custom signet challenge script (BIP 325), set via
    /// `-signetchallenge`. When present (signet only), every accepted
    /// block's signet solution is verified against it and the P2P magic
    /// is derived from it. `None` for all other networks and for the
    /// default signet (which satd does not solution-check today).
    signet_challenge: Option<Vec<u8>>,
    /// Serializes the entire `accept_block` critical section so that at
    /// most one thread mutates this (primary) chainstate at a time.
    ///
    /// The P2P side already has a single-writer invariant: every network
    /// block funnels through one `block_processor` thread. But
    /// `submitblock` (and internal mining) call `accept_block` directly
    /// from RPC worker threads, so without this lock a miner-submitted
    /// block can race the connect thread — two writers interleaving into
    /// the shared `CoinCache` dirty map / `pending_batch` and both writing
    /// `tip`, corrupting the UTXO delta (issue #262 follow-up: the second
    /// concurrent writer, distinct from the flush-vs-reorg race that
    /// #268's `flush_guard` already closed).
    ///
    /// Uncontended on the IBD, reindex, and steady-state P2P paths (each
    /// drives `accept_block` from a single thread), so the cost there is a
    /// single uncontended lock/unlock. It contends only in exactly the
    /// racing case it exists to prevent. Scoped to the primary chainstate;
    /// the AssumeUTXO background catch-up mutates a *separate* `ChainState`
    /// and neither needs nor touches this lock.
    accept_lock: Mutex<()>,
}

impl ChainState {
    /// Create a new ChainState. If the store is empty, initializes with the genesis block.
    /// The store is wrapped in a CoinCache for in-memory UTXO batching.
    /// `dbcache_mb` controls the total write cache size in MB (default 450).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Box<dyn Store>,
        mut flat_files: FlatFileManager,
        network: Network,
        script_verifier: Box<dyn ScriptVerifier>,
        assumevalid: AssumeValid,
        dbcache_mb: u64,
        num_threads: usize,
        address_index: crate::index::address::AddressIndexConfig,
        filter_index: crate::index::filter::FilterIndexConfig,
        sp_index: crate::index::silent_payments::SpIndexConfig,
    ) -> Result<Self, ChainError> {
        // The `filter_index` field it feeds is cfg-gated, but the parameter is
        // not: every caller passes a config regardless of build, so the
        // signature stays stable across feature combinations. Consume it
        // explicitly on a consensus-only build.
        #[cfg(not(feature = "block-filter-index"))]
        let _ = filter_index;

        let genesis = bitcoin::constants::genesis_block(network);
        let genesis_hash = genesis.block_hash();
        let blocks_dir = flat_files.blocks_dir().to_path_buf();
        let blocks_xor_key = flat_files.xor_key();

        let checkpoints = checkpoints::checkpoints_for_network(network);

        // Share the script verifier with any background chainstate
        // (AssumeUTXO) via Arc. Callers still pass a Box; the conversion
        // is free and keeps every existing call site unchanged.
        let script_verifier: Arc<dyn ScriptVerifier> = Arc::from(script_verifier);

        // Wrap the store in a CoinCache for batched UTXO writes
        let store = std::sync::Arc::new(CoinCache::new(store, dbcache_mb));

        // Check if we have an existing tip
        if let Some(tip_hash) = store.get_tip()
            && let Some(entry) = store.get_block_index(&tip_hash) {
                // Find the highest stored header via binary search.
                // Headers may be ahead of blocks if we crashed during IBD.
                let mut htip = entry.height;
                // First, probe exponentially to find an upper bound
                let mut probe = 1u32;
                while store.get_block_hash_by_height(htip + probe).is_some() {
                    htip += probe;
                    probe *= 2;
                }
                // Binary search between htip and htip + probe
                let mut lo = htip;
                let mut hi = htip + probe;
                while lo < hi {
                    let mid = lo + (hi - lo) / 2;
                    if store.get_block_hash_by_height(mid + 1).is_some() {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                htip = lo;

                // Seed the best-header pointer from the highest-CHAINWORK
                // header in the index — NOT the highest-height header, which
                // the pollutable best-known-at-height index would give and
                // which can name a competing branch after a crash. One-time
                // O(n) scan at load; thereafter maintained incrementally by
                // chainwork in accept_header/accept_headers/accept_block. Seeded
                // with the active tip so a scan miss still yields a sane value.
                let mut best_header = (tip_hash, entry.chainwork);
                // Propagate a scan failure rather than swallowing it: a
                // block_index that cannot be iterated is corruption that
                // must fail startup loudly, not silently degrade the
                // competing-chain pull path to the active tip.
                let scan_stats = store.for_each_block_index(&mut |h, e| {
                    if compare_u256(&e.chainwork, &best_header.1) > 0 {
                        best_header = (h, e.chainwork);
                    }
                })?;
                // Rows dropped mid-scan (bad key / bad value) don't return
                // Err but DO mean the best-header seed may have missed a
                // heavier branch — surface them instead of masking.
                if scan_stats.skipped_bad_key > 0 || scan_stats.skipped_bad_value > 0 {
                    tracing::warn!(
                        skipped_bad_key = scan_stats.skipped_bad_key,
                        skipped_bad_value = scan_stats.skipped_bad_value,
                        "block_index scan skipped undecodable rows while seeding \
                         best-header; index may be partially corrupt"
                    );
                }

                tracing::info!(
                    height = entry.height,
                    headers_tip = htip,
                    hash = %tip_hash,
                    "Loaded chain tip from storage"
                );
                let cs = Self {
                    store,
                    flat_files: Arc::new(Mutex::new(flat_files)),
                    blocks_dir,
                    blocks_xor_key,
                    tip: RwLock::new(ChainTip {
                        hash: tip_hash,
                        height: entry.height,
                    }),
                    network,
                    script_verifier,
                    assumevalid,
                    checkpoints,
                    enforce_checkpoints: true,
                    headers_tip_height: AtomicU32::new(htip),
                    best_header: RwLock::new(best_header),
                    mtp_cache: Mutex::new(Vec::with_capacity(12)),
                    num_threads,
                    address_index,
                    sp_index,
                    #[cfg(feature = "block-filter-index")]
                    filter_index,
                    reorg_log: std::sync::OnceLock::new(),
                    warnings: std::sync::Arc::new(crate::warnings::NodeWarnings::new()),
                    mempool: std::sync::OnceLock::new(),
                    chain_event_tx: parking_lot::Mutex::new(None),
                    connect_heartbeat: AtomicU64::new(0),
                    manager_heartbeat: AtomicU64::new(0),
                    connect_phases: std::sync::Arc::new(
                        crate::chain::connect_phase::ConnectPhaseTracker::new(),
                    ),
                    background: RwLock::new(None),
                    signet_challenge: None,
                    accept_lock: Mutex::new(()),
                };
                // Self-heal a tip left durably `Invalid` by a crash mid-
                // invalidateblock (no-op in the normal case).
                cs.reconcile_invalid_tip()?;
                return Ok(cs);
            }

        // Fresh node: store genesis block.
        //
        // `-reindex-chainstate` drops `CF_METADATA` (which holds the tip
        // pointer) but keeps `CF_BLOCK_INDEX` intact, so we land here on
        // a non-fresh datadir. In that case genesis is already on disk
        // at its original `(file_number, data_pos)` — reuse that
        // position instead of appending a duplicate. Two reasons:
        //   1. Avoids wasting ~285 bytes of flat-file slack on every
        //      reindex-chainstate run.
        //   2. The append outright fails when `blocks/` is read-only —
        //      for example when a sibling node points its `blocks/`
        //      symlink at a primary's `blocks/` directory whose files
        //      are mode 644 satd:satd. Without this branch a validation
        //      node sharing `blocks/` with a primary can never
        //      `-reindex-chainstate`.
        tracing::info!("Initializing chain with genesis block");

        let flat_pos = if let Some(entry) = store.get_block_index(&genesis_hash) {
            tracing::info!(
                file_number = entry.file_number,
                data_pos = entry.data_pos,
                "Genesis already in block_index; reusing flat-file position"
            );
            FlatFilePos {
                file_number: entry.file_number,
                data_pos: entry.data_pos,
            }
        } else {
            let block_data = serialize(&genesis);
            let pos = flat_files
                .write_block(&block_data, network_magic(network))
                .map_err(|e| ChainError::FlatFile(e.to_string()))?;
            // Same data-before-pointer ordering `write_block_durable`
            // enforces on the steady-state paths. This one runs once per
            // datadir and predates the `ChainState` that owns that helper,
            // so it syncs inline.
            flat_files
                .sync_all()
                .map_err(|e| ChainError::FlatFile(e.to_string()))?;
            pos
        };

        let parent_work = [0u8; 32];
        let noop = NoopVerifier; // Genesis has no scripts to verify
        let batch = connect::connect_block(&connect::ConnectParams {
            replay_plan: None,
            store: &*store,
            block: &genesis,
            height: 0,
            parent_chainwork: &parent_work,
            flat_pos,
            script_verifier: &noop,
            median_time_past: 0,
            network,
            pre_verified_txs: None,
            num_threads: 1,
            precomputed_txids: None,
            address_index: &address_index,
            sp_index: &sp_index,
            #[cfg(feature = "block-filter-index")]
            filter_index: &filter_index,
            phase_tracker: None,
        })?;
        store.write_batch(batch)?;

        Ok(Self {
            store,
            flat_files: Arc::new(Mutex::new(flat_files)),
            blocks_dir,
            blocks_xor_key,
            tip: RwLock::new(ChainTip {
                hash: genesis_hash,
                height: 0,
            }),
            network,
            script_verifier,
            assumevalid,
            checkpoints,
            enforce_checkpoints: true,
            headers_tip_height: AtomicU32::new(0),
            best_header: RwLock::new((genesis_hash, work_for_bits(genesis.header.bits))),
            mtp_cache: Mutex::new(Vec::with_capacity(12)),
            num_threads,
            address_index,
            sp_index,
            #[cfg(feature = "block-filter-index")]
            filter_index,
            reorg_log: std::sync::OnceLock::new(),
            warnings: std::sync::Arc::new(crate::warnings::NodeWarnings::new()),
            mempool: std::sync::OnceLock::new(),
            chain_event_tx: parking_lot::Mutex::new(None),
            connect_heartbeat: AtomicU64::new(0),
            manager_heartbeat: AtomicU64::new(0),
            connect_phases: std::sync::Arc::new(
                crate::chain::connect_phase::ConnectPhaseTracker::new(),
            ),
            background: RwLock::new(None),
            signet_challenge: None,
            accept_lock: Mutex::new(()),
        })
    }

    /// Set the custom signet challenge (BIP 325). Call once, before the
    /// `ChainState` is shared (wrapped in an `Arc`). On signet this
    /// enables block-solution validation and custom P2P magic.
    pub fn set_signet_challenge(&mut self, challenge: Option<Vec<u8>>) {
        self.signet_challenge = challenge;
    }

    /// Enable or disable enforcement of the built-in block checkpoints
    /// (Core `-checkpoints`, default enabled). Call once, before the
    /// `ChainState` is shared (wrapped in an `Arc`). `-checkpoints=0`
    /// disables checkpoint validation in `connect_block`.
    pub fn set_enforce_checkpoints(&mut self, enforce: bool) {
        self.enforce_checkpoints = enforce;
    }

    /// Effective P2P network magic. Custom-signet challenges derive their
    /// own magic (BIP 325); everything else uses the `bitcoin` crate's
    /// per-network value.
    pub fn p2p_magic(&self) -> bitcoin::p2p::Magic {
        match &self.signet_challenge {
            Some(ch) if self.network == Network::Signet => {
                crate::validation::signet::signet_magic(ch)
            }
            _ => bitcoin::p2p::Magic::from(self.network),
        }
    }

    /// Verify a block's signet solution when a custom challenge is
    /// configured (BIP 325). No-op on every other network and on the
    /// default signet (no challenge set).
    fn check_signet_solution(&self, block: &Block) -> Result<(), crate::validation::ValidationError> {
        if let Some(ch) = &self.signet_challenge {
            let genesis_hash = bitcoin::constants::genesis_block(self.network).block_hash();
            validation::signet::check_signet_block_solution(block, ch, genesis_hash)?;
        }
        Ok(())
    }

    /// Wire the mempool handle for reorg re-add. Called once at
    /// startup after both ChainState and Mempool are constructed.
    /// Test backends that don't exercise the reorg re-add path skip
    /// this; the per-perform_reorg branch tolerates absence.
    pub fn set_mempool(
        &self,
        mempool: std::sync::Arc<crate::mempool::pool::Mempool>,
    ) {
        let _ = self.mempool.set(mempool);
    }

    /// Wire a chain-event broadcaster. Called once at startup so the
    /// address-index notifier (and any future observers) can subscribe
    /// to BlockConnected / BlockDisconnected notifications. Mirrors
    /// `Mempool::set_event_sender` to keep the wiring shape uniform.
    pub fn set_chain_event_sender(
        &self,
        tx: tokio::sync::broadcast::Sender<crate::chain::events::ChainEvent>,
    ) {
        *self.chain_event_tx.lock() = Some(tx);
    }

    // ---- AssumeUTXO background chainstate ----

    /// Attach a background chainstate that re-validates genesis→
    /// `snapshot_height` behind a loaded AssumeUTXO snapshot. Called by
    /// `loadtxoutset`. The background shares this chainstate's block
    /// store, flat files, and script verifier; it keeps its own UTXO set
    /// in `bg_dir` (`<datadir>/chainstate_background`).
    #[allow(clippy::too_many_arguments)]
    pub fn attach_background(
        &self,
        bg_dir: PathBuf,
        snapshot_height: u32,
        snapshot_hash: BlockHash,
        target_utxo_hash: [u8; 32],
        dbcache_mb: u64,
        max_open_files: i32,
    ) -> Result<(), ChainError> {
        let bg = crate::chain::background::BackgroundChainState::open(
            self.store.clone() as Arc<dyn crate::storage::Store>,
            self.flat_files.clone(),
            self.script_verifier.clone(),
            self.checkpoints.clone(),
            self.enforce_checkpoints,
            self.network,
            self.num_threads,
            bg_dir,
            snapshot_height,
            snapshot_hash,
            target_utxo_hash,
            dbcache_mb,
            max_open_files,
        )?;
        // Persist the anchor identity so a restart before handoff can
        // re-attach the background (the primary tip may have advanced past
        // the snapshot height, so the tip alone can't name the anchor).
        // Best-effort: a failure here only affects cross-restart resume,
        // not this session.
        if let Err(e) = crate::chain::background::write_anchor_marker(
            bg.bg_dir(),
            snapshot_height,
            &snapshot_hash,
            &target_utxo_hash,
        ) {
            tracing::warn!(
                error = %e,
                "AssumeUTXO: could not persist the background anchor marker; \
                 a restart before handoff will not auto-resume validation"
            );
        }
        *self.background.write() = Some(Arc::new(bg));
        Ok(())
    }

    /// On startup, re-attach a pending AssumeUTXO background validator if
    /// one was left behind by a previous run, or refuse to start if that
    /// snapshot was durably rejected. `net_datadir` is the network datadir
    /// (parent of `chainstate/`). Presence of `chainstate_background/`
    /// means a snapshot was loaded and handoff did not complete (a
    /// successful handoff removes the dir).
    pub fn resume_pending_snapshot(
        &self,
        net_datadir: &std::path::Path,
        dbcache_mb: u64,
        max_open_files: i32,
    ) -> Result<SnapshotResume, ChainError> {
        let bg_dir = net_datadir.join("chainstate_background");
        if !bg_dir.exists() {
            return Ok(SnapshotResume::None);
        }
        if bg_dir.join(".rejected").exists() {
            return Ok(SnapshotResume::Rejected);
        }
        match crate::chain::background::read_anchor_marker(&bg_dir) {
            Some((height, blockhash, target)) => {
                self.attach_background(
                    bg_dir,
                    height,
                    blockhash,
                    target,
                    dbcache_mb,
                    max_open_files,
                )?;
                Ok(SnapshotResume::Resumed { height })
            }
            None => Err(ChainError::Snapshot(format!(
                "found a background chainstate dir at {} with no anchor marker; refusing to \
                 start with an ambiguous pending snapshot. Remove it to discard the pending \
                 snapshot.",
                bg_dir.display()
            ))),
        }
    }

    /// The active background chainstate, if one is attached (i.e. an
    /// AssumeUTXO snapshot is loaded and not yet validated).
    pub fn background(&self) -> Option<Arc<crate::chain::background::BackgroundChainState>> {
        self.background.read().clone()
    }

    /// Whether a background chainstate is currently attached.
    pub fn has_background(&self) -> bool {
        self.background.read().is_some()
    }

    /// Connect one historical block to the background chainstate (driven
    /// by the catch-up loop). When the connect reaches `snapshot_height`,
    /// runs the handoff verification. Returns `None` when no background is
    /// attached (the normal, non-AssumeUTXO case).
    pub fn background_connect_block(
        &self,
        block: &Block,
    ) -> Result<Option<crate::chain::background::BackgroundConnect>, ChainError> {
        let bg = match self.background() {
            Some(b) => b,
            None => return Ok(None),
        };
        let outcome = bg.connect_next_block(block)?;
        if outcome.reached_snapshot {
            self.run_background_handoff(&bg)?;
        }
        Ok(Some(outcome))
    }

    /// Re-attempt the handoff for a background that has already reached its
    /// snapshot height.
    ///
    /// The handoff is normally driven from [`Self::background_connect_block`],
    /// i.e. only after a *successful connect*. That leaves a hole: if the
    /// handoff itself fails on I/O — `verify_at_snapshot` flushes coins and
    /// hashes the UTXO set, either of which can hit ENOSPC or a RocksDB error
    /// — it returns `Err` **before** reaching either `mark_rejected` arm, and
    /// the background tip is already at `snapshot_height`. No further connect
    /// is possible, so nothing can ever call the handoff again and the
    /// snapshot stays pending forever. The catch-up loop's wait branch says it
    /// will "wait and re-check"; this is what makes that true.
    ///
    /// Returns `Ok(false)` when there is nothing to do (no background
    /// attached, or it has not reached the snapshot height yet).
    pub fn retry_background_handoff(&self) -> Result<bool, ChainError> {
        let Some(bg) = self.background() else {
            return Ok(false);
        };
        if bg.tip_height() < bg.snapshot_height() {
            return Ok(false);
        }
        self.run_background_handoff(&bg)?;
        Ok(true)
    }

    /// Resolve the handoff once the background reaches `snapshot_height`.
    ///
    /// On a hash match: mark validated by dropping the background and
    /// removing its private DB (the shared block store now holds the full
    /// genesis→tip block index).
    ///
    /// On a mismatch the node has just *proven* the active snapshot is
    /// invalid, so we fail closed: persist a durable rejected marker (so
    /// the rejection survives restart and startup refuses to keep serving
    /// the snapshot), raise a loud error warning, and return an error so
    /// the catch-up driver halts instead of continuing to advance an
    /// invalid chain. We do NOT panic. Full demote-to-primary recovery is
    /// a follow-up; until then the operator must reindex/reload.
    fn run_background_handoff(
        &self,
        bg: &Arc<crate::chain::background::BackgroundChainState>,
    ) -> Result<(), ChainError> {
        use crate::chain::background::HandoffOutcome;
        match bg.verify_at_snapshot()? {
            HandoffOutcome::Validated => {
                tracing::info!(
                    height = bg.snapshot_height(),
                    "AssumeUTXO: background validation matched the anchor; completing handoff"
                );
                let dir = bg.bg_dir().to_path_buf();
                *self.background.write() = None;
                if let Err(e) = std::fs::remove_dir_all(&dir) {
                    tracing::warn!(
                        error = %e,
                        dir = %dir.display(),
                        "AssumeUTXO: could not remove background chainstate dir after handoff"
                    );
                }
                Ok(())
            }
            HandoffOutcome::HashMismatch { expected, actual } => {
                tracing::error!(
                    expected = %hex::encode(expected),
                    actual = %hex::encode(actual),
                    "AssumeUTXO: background UTXO-set hash does NOT match the anchor — snapshot is invalid"
                );
                bg.mark_rejected();
                self.warnings.record(
                    "assumeutxo-validation-failed",
                    crate::warnings::Severity::Error,
                    "AssumeUTXO snapshot failed background validation: UTXO-set hash \
                     mismatch at the snapshot height. The loaded snapshot is not \
                     trustworthy; reindex or reload a valid snapshot.",
                    serde_json::json!({
                        "expected_hash_serialized_3": hex::encode(expected),
                        "actual_hash_serialized_3": hex::encode(actual),
                        "snapshot_height": bg.snapshot_height(),
                    }),
                );
                Err(ChainError::Snapshot(format!(
                    "background validation FAILED at height {}: UTXO-set hash {} does not match \
                     the anchor {}",
                    bg.snapshot_height(),
                    hex::encode(actual),
                    hex::encode(expected),
                )))
            }
            HandoffOutcome::BaseMismatch { expected, actual } => {
                tracing::error!(
                    expected = %expected,
                    actual = %actual,
                    "AssumeUTXO: background tip at snapshot height is not the anchor block"
                );
                bg.mark_rejected();
                self.warnings.record(
                    "assumeutxo-validation-failed",
                    crate::warnings::Severity::Error,
                    "AssumeUTXO snapshot failed background validation: the block at the \
                     snapshot height does not match the anchor block hash; reindex or \
                     reload a valid snapshot.",
                    serde_json::json!({
                        "expected_base": expected.to_string(),
                        "actual_base": actual.to_string(),
                        "snapshot_height": bg.snapshot_height(),
                    }),
                );
                Err(ChainError::Snapshot(format!(
                    "background validation FAILED at height {}: base block {} does not match \
                     the anchor {}",
                    bg.snapshot_height(),
                    actual,
                    expected,
                )))
            }
        }
    }

    /// Stream snapshot coins into the snapshot chainstate's coin set,
    /// rejecting malformed input. Returns the number of coins loaded.
    ///
    /// Validation: every `(txid, vout)` outpoint must be **strictly
    /// increasing** in `(txid_bytes, vout)` order (Core's snapshot order),
    /// which rejects duplicates and disorder without a large seen-set;
    /// `vout` must fit in `u32`; and the running count must not exceed the
    /// header's. Duplicates would otherwise overwrite the same coin row
    /// (same final hash) while double-incrementing the persisted UTXO
    /// counters, and an oversized `vout` would silently truncate the key.
    fn stream_snapshot_coins<R: std::io::Read>(
        &self,
        reader: &mut R,
        meta: &crate::storage::compressed_coin::SnapshotMetadata,
    ) -> Result<u64, ChainError> {
        use crate::storage::compressed_coin as cc;

        let mut loaded = 0u64;
        let mut prev: Option<([u8; 32], u32)> = None;
        let mut batch = crate::storage::StoreBatch::default();
        while loaded < meta.coins_count {
            let mut txid_bytes = [0u8; 32];
            reader
                .read_exact(&mut txid_bytes)
                .map_err(|e| ChainError::Snapshot(format!("truncated snapshot (txid): {e}")))?;
            let group = cc::read_compact_size(reader)
                .map_err(|e| ChainError::Snapshot(format!("bad group size: {e}")))?;
            if group == 0 {
                return Err(ChainError::Snapshot(
                    "snapshot has an empty txid group".into(),
                ));
            }
            let txid = bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array(txid_bytes),
            );
            for _ in 0..group {
                let vout_u64 = cc::read_compact_size(reader)
                    .map_err(|e| ChainError::Snapshot(format!("bad vout: {e}")))?;
                if vout_u64 > u64::from(u32::MAX) {
                    return Err(ChainError::Snapshot(format!(
                        "snapshot vout {vout_u64} exceeds u32::MAX"
                    )));
                }
                let vout = vout_u64 as u32;
                if let Some((prev_txid, prev_vout)) = prev {
                    let strictly_increasing = txid_bytes > prev_txid
                        || (txid_bytes == prev_txid && vout > prev_vout);
                    if !strictly_increasing {
                        return Err(ChainError::Snapshot(
                            "snapshot outpoints are not strictly increasing (duplicate or \
                             out-of-order)"
                                .into(),
                        ));
                    }
                }
                prev = Some((txid_bytes, vout));

                let coin = cc::deserialize_coin(reader)
                    .map_err(|e| ChainError::Snapshot(format!("bad coin record: {e}")))?;
                batch
                    .coin_puts
                    .push((bitcoin::OutPoint { txid, vout }, coin));
                loaded += 1;
                if loaded > meta.coins_count {
                    return Err(ChainError::Snapshot(
                        "snapshot contains more coins than its header declares".into(),
                    ));
                }
                if batch.coin_puts.len() >= 10_000 {
                    self.store.write_batch_mode(
                        std::mem::take(&mut batch),
                        crate::storage::WriteMode::BulkLoad,
                    )?;
                }
            }
        }
        if !batch.coin_puts.is_empty() {
            self.store
                .write_batch_mode(batch, crate::storage::WriteMode::BulkLoad)?;
        }
        self.store.flush_durable()?;
        Ok(loaded)
    }

    /// Point the active tip at the snapshot base block and persist it.
    fn adopt_snapshot_tip(
        &self,
        anchor: &crate::chain::assumeutxo::AssumeUtxoData,
    ) -> Result<(), ChainError> {
        let tip_batch = crate::storage::StoreBatch {
            tip: Some(anchor.blockhash),
            height_hash_puts: vec![(anchor.height, anchor.blockhash)],
            // Seed the cumulative tx count at the snapshot base from the
            // hardcoded anchor so getchaintxstats reports the correct
            // chain-wide total immediately, before the background has
            // validated any pre-snapshot blocks. Forward connects build on
            // this; the background fills the genesis→base range over time.
            chain_tx_puts: vec![(anchor.blockhash, anchor.nchaintx)],
            ..Default::default()
        };
        self.store.write_batch(tip_batch)?;
        {
            let mut tip = self.tip.write();
            tip.hash = anchor.blockhash;
            tip.height = anchor.height;
        }
        self.headers_tip_height
            .fetch_max(anchor.height, Ordering::Relaxed);
        self.store.flush()?;
        Ok(())
    }

    /// Undo a partial snapshot activation: detach + remove the background
    /// chainstate, clear any loaded coins, and reset the tip to genesis.
    /// Best-effort (used on an error path) — failures are logged, not
    /// propagated, since the caller is already returning an error.
    fn rollback_snapshot_load(&self) {
        if let Some(bg) = self.background.write().take()
            && let Err(e) = std::fs::remove_dir_all(bg.bg_dir())
        {
            tracing::warn!(
                error = %e,
                dir = %bg.bg_dir().display(),
                "snapshot rollback: could not remove background chainstate dir"
            );
        }
        if let Err(e) = self.store.clear_chainstate() {
            tracing::error!(error = %e, "snapshot rollback: clear_chainstate failed");
        }
        let genesis = bitcoin::constants::genesis_block(self.network).block_hash();
        let reset = crate::storage::StoreBatch {
            tip: Some(genesis),
            ..Default::default()
        };
        if let Err(e) = self.store.write_batch(reset) {
            tracing::error!(error = %e, "snapshot rollback: tip reset failed");
        }
        {
            let mut tip = self.tip.write();
            tip.hash = genesis;
            tip.height = 0;
        }
    }

    /// Load a Bitcoin Core-format UTXO snapshot into THIS (snapshot)
    /// chainstate and attach a background chainstate to validate the
    /// history behind it. `anchor` is the trusted
    /// [`AssumeUtxoData`](crate::chain::assumeutxo::AssumeUtxoData) the
    /// snapshot must match — the RPC layer looks it up by base block
    /// hash; tests pass a synthetic one.
    ///
    /// Steps: parse + validate the header against the anchor and our
    /// network; require a fresh chainstate (tip at genesis) with the
    /// anchor's base header already in the block index; stream the coins
    /// in; set the tip to the base block; recompute `hash_serialized_3`
    /// over the loaded set and **reject** (rolling back) if it does not
    /// match the anchor; then attach the background chainstate. The
    /// background later re-validates genesis→base and completes the
    /// handoff (see [`Self::background_connect_block`]).
    pub fn load_utxo_snapshot<R: std::io::Read>(
        &self,
        reader: &mut R,
        anchor: crate::chain::assumeutxo::AssumeUtxoData,
        bg_dir: PathBuf,
        dbcache_mb: u64,
        max_open_files: i32,
    ) -> Result<LoadSnapshotSummary, ChainError> {
        use crate::storage::compressed_coin as cc;

        // 1. Header: magic/version (in deserialize), network, base hash.
        let meta = cc::SnapshotMetadata::deserialize(reader)
            .map_err(|e| ChainError::Snapshot(format!("bad snapshot header: {e}")))?;
        if meta.network_magic != network_magic(self.network) {
            return Err(ChainError::Snapshot(
                "snapshot network magic does not match this node's network".into(),
            ));
        }
        if meta.base_blockhash != anchor.blockhash {
            return Err(ChainError::Snapshot(
                "snapshot base block hash does not match the requested anchor".into(),
            ));
        }

        // 2. Preconditions: the base header must be known at the anchor
        //    height (headers synced), and this must be a fresh chainstate.
        let base_entry = self
            .store
            .get_block_index(&anchor.blockhash)
            .ok_or_else(|| {
                ChainError::Snapshot(
                    "snapshot base header is not in the block index — sync headers past the \
                     snapshot height first"
                        .into(),
                )
            })?;
        if base_entry.height != anchor.height {
            return Err(ChainError::Snapshot(format!(
                "block index height {} for the snapshot base disagrees with the anchor height {}",
                base_entry.height, anchor.height
            )));
        }
        if self.tip_height() != 0 {
            return Err(ChainError::Snapshot(
                "loadtxoutset requires a fresh chainstate (tip at genesis)".into(),
            ));
        }

        // 3. Attach the background validator BEFORE mutating the active
        //    chainstate. Opening the background DB is the failure-prone
        //    step (locked dir, incompatible contents, I/O); doing it
        //    first means a failure here cannot strand the node on an
        //    unvalidated snapshot. From this point on, ANY error rolls
        //    the whole activation back (see `rollback_snapshot_load`).
        self.attach_background(
            bg_dir,
            anchor.height,
            anchor.blockhash,
            anchor.hash_serialized_3,
            dbcache_mb,
            max_open_files,
        )?;

        // 4. Stream coins into the snapshot chainstate's coin set,
        //    validating the stream (strictly-increasing outpoints, vout
        //    bound, count drift) so a malformed file cannot inflate the
        //    persisted UTXO counters while still matching the anchor hash.
        let loaded = match self.stream_snapshot_coins(reader, &meta) {
            Ok(n) => n,
            Err(e) => {
                self.rollback_snapshot_load();
                return Err(e);
            }
        };

        // 5. Point the tip at the base block.
        if let Err(e) = self.adopt_snapshot_tip(&anchor) {
            self.rollback_snapshot_load();
            return Err(e);
        }

        // 6. Recompute the UTXO-set hash AND verify the loaded coin count
        //    against the header, rolling back on any mismatch. This
        //    rejects a tampered file immediately, before the slow
        //    background validation.
        let (actual, base) = match cc::hash_utxo_set(&*self.store) {
            Ok(v) => v,
            Err(e) => {
                self.rollback_snapshot_load();
                return Err(e.into());
            }
        };
        if actual != anchor.hash_serialized_3 {
            self.rollback_snapshot_load();
            return Err(ChainError::Snapshot(format!(
                "loaded UTXO-set hash {} does not match the anchor {} — snapshot rejected",
                hex::encode(actual),
                hex::encode(anchor.hash_serialized_3),
            )));
        }
        if base.coin_count != meta.coins_count || base.coins_written != meta.coins_count {
            self.rollback_snapshot_load();
            return Err(ChainError::Snapshot(format!(
                "snapshot coin-count mismatch: header declares {}, persisted count {}, \
                 iterated {} — snapshot rejected",
                meta.coins_count, base.coin_count, base.coins_written,
            )));
        }

        tracing::info!(
            height = anchor.height,
            coins = loaded,
            base = %anchor.blockhash,
            "AssumeUTXO: snapshot loaded; background validation started"
        );

        Ok(LoadSnapshotSummary {
            coins_loaded: loaded,
            base_height: anchor.height,
            base_hash: anchor.blockhash,
            tip_height: anchor.height,
        })
    }

    /// Subscribe to live chain events. Returns `None` if no sender
    /// has been wired (typical in tests).
    pub fn subscribe_chain_events(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<crate::chain::events::ChainEvent>> {
        self.chain_event_tx
            .lock()
            
            .as_ref()
            .map(|tx| tx.subscribe())
    }

    /// Emit a chain event. Best-effort: a slow consumer that misses
    /// events sees `RecvError::Lagged`; emission never blocks the
    /// connect/disconnect path.
    fn emit_chain_event(&self, event: crate::chain::events::ChainEvent) {
        // Invariant guarding the API-runtime split (see `rpc::access` and the
        // read-only RPC listener): block-level chain events — and therefore
        // block connection / disconnection / reorg — must originate on the
        // core runtime, never the bounded API runtime. If a chain-mutating
        // path ran on the API runtime, the cross-runtime wakeup could reorder
        // the address-index status notifier ahead of the inline index write,
        // delivering a stale all-zeros status to SSE/Electrum subscribers.
        //
        // The API runtime's worker threads are named "satd-api"; assert we
        // are not on one. This is the structural backstop for the read-only
        // listener's method classification: even a *misclassified* future
        // block-connecting RPC (wrongly allowed onto the API runtime) trips
        // this on the very first block it connects. `debug_assert` keeps
        // release builds unaffected while the regtest suite — which connects
        // blocks in nearly every test — actively enforces it in CI.
        debug_assert_ne!(
            std::thread::current().name(),
            Some("satd-api"),
            "block-level chain event emitted from the API runtime; block \
             connection must stay on the core runtime (see rpc::access)"
        );
        if let Some(tx) = self.chain_event_tx.lock().as_ref() {
            let _ = tx.send(event);
        }
    }

    /// Access the shared warnings surface. Always present; use to
    /// record or clear operational issues from anywhere in the node.
    pub fn warnings(&self) -> &std::sync::Arc<crate::warnings::NodeWarnings> {
        &self.warnings
    }

    /// Attach a reorg log. Must be called before the chain state sees
    /// any reorgs; subsequent calls are no-ops (OnceLock).
    pub fn attach_reorg_log(&self, log: std::sync::Arc<crate::chain::reorg_log::ReorgLog>) {
        let _ = self.reorg_log.set(log);
    }

    /// Access the attached reorg log, if any. None if `attach_reorg_log`
    /// was never called (the test path).
    pub fn reorg_log(&self) -> Option<&std::sync::Arc<crate::chain::reorg_log::ReorgLog>> {
        self.reorg_log.get()
    }

    pub fn tip_hash(&self) -> BlockHash {
        self.tip.read().hash
    }

    pub fn tip_height(&self) -> u32 {
        self.tip.read().height
    }

    /// Cheap liveness probe for the systemd watchdog. Returns true if the
    /// tip lock is not held by a wedged writer (try_read succeeds). A
    /// healthy node returns instantly; a node where a connect-block path
    /// has deadlocked while holding the write lock returns false.
    ///
    /// Non-blocking by design — the watchdog tick must never wait on a
    /// stuck subsystem.
    pub fn is_responsive(&self) -> bool {
        self.tip.try_read().is_some()
    }

    /// Read the active-chain tip's hash and height under a single
    /// `tip.read()` guard. Callers that need both fields together —
    /// e.g. the address-index backfill's `verify_anchor_active` — must
    /// use this method instead of two separate `tip_hash()` /
    /// `tip_height()` calls; otherwise a chain extension between the
    /// two reads can pair an old hash with a new height (or vice
    /// versa) and produce false reorg-invalidated diagnostics.
    pub fn tip_snapshot(&self) -> (BlockHash, u32) {
        let tip = self.tip.read();
        (tip.hash, tip.height)
    }

    /// Initial-block-download heuristic from a tip timestamp. Matches the
    /// `initialblockdownload` signal in `getblockchaininfo`
    /// (`rpc::blockchain`): the node is considered to be in IBD while its
    /// active-chain tip is more than 24h behind wall-clock time. Shared so
    /// the RPC and the per-block flush gate use one definition.
    pub(crate) fn tip_time_is_ibd(tip_time: u32) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        (tip_time as u64) + 86_400 < now
    }

    /// Whether the node is in initial block download, judged by the active
    /// tip's timestamp. Returns `true` when the tip header is unavailable
    /// (treated as far-behind) so callers fail safe toward "still syncing".
    pub fn is_initial_block_download(&self) -> bool {
        let tip_time = self
            .get_block_index(&self.tip_hash())
            .map(|e| e.header.time)
            .unwrap_or(0);
        Self::tip_time_is_ibd(tip_time)
    }

    /// Flush the UTXO write cache to disk. Call periodically during IBD
    /// and on graceful shutdown.
    pub fn flush_coin_cache(&self) -> Result<(), StoreError> {
        self.store.flush()
    }

    /// Number of dirty entries in the write cache.
    pub fn cache_dirty_count(&self) -> u32 {
        self.store.dirty_count()
    }

    /// Dirty coin flush threshold derived from the dbcache budget.
    pub fn flush_threshold(&self) -> u32 {
        self.store.flush_threshold()
    }

    /// Total coin cache size (dirty + clean entries).
    pub fn cache_size(&self) -> usize {
        self.store.cache_size()
    }

    /// Live count of L0 SST files in the chainstate column family. The IBD
    /// connector reads this between blocks to decide whether to pause and
    /// let RocksDB compaction catch up.
    pub fn chainstate_l0_files(&self) -> u64 {
        self.store.chainstate_l0_files()
    }

    /// RocksDB's estimate of pending compaction work, in bytes, for the
    /// chainstate column family. Used by the periodic compactor and in
    /// stall-watchdog diagnostics.
    pub fn chainstate_pending_compaction_bytes(&self) -> u64 {
        self.store.chainstate_pending_compaction_bytes()
    }

    /// Per-column-family pending-compaction-bytes breakdown. Surfaced
    /// by the periodic diagnostic logger so operators can see *which*
    /// CF is falling behind — the chainstate-wide `coins`-only number
    /// missed the actual culprits during the mainnet IBD disk-fill
    /// incident.
    pub fn pending_compaction_bytes_by_cf(&self) -> Vec<(&'static str, u64)> {
        self.store.pending_compaction_bytes_by_cf()
    }

    /// Per-column-family on-disk SST size in bytes. Pairs with the
    /// pending-compaction breakdown to answer two related questions:
    /// pending = "is the LSM keeping up?", sst_bytes = "where do the
    /// GBs live?". Logged once at startup and inside the 60s
    /// diagnostic snapshot.
    pub fn sst_bytes_by_cf(&self) -> Vec<(&'static str, u64)> {
        self.store.sst_bytes_by_cf()
    }

    /// Force a synchronous full-range compaction of the chainstate column
    /// family. Drains the dirty overlay first so the compaction includes
    /// pending writes. Long-running: returns only when RocksDB completes
    /// the compaction.
    pub fn compact_chainstate(&self) -> Result<(), StoreError> {
        self.store.compact_chainstate()
    }

    /// Diagnose slack in the block flat files: compare every `block_index`
    /// reference against the on-disk `blk*.dat` sizes and report per-file
    /// referenced vs total bytes. Read-only. Cost is one seek+read of an
    /// 8-byte header per indexed block (~minute on the current mainnet).
    pub fn audit_block_files(
        &self,
    ) -> Result<crate::storage::blockfile_audit::BlockfileAuditReport, crate::storage::blockfile_audit::AuditError>
    {
        crate::storage::blockfile_audit::audit_blockfiles(&*self.store, &self.blocks_dir)
    }

    /// Emit a Bitcoin Core-format UTXO snapshot file at `path` from the
    /// current tip. The output is byte-compatible with `bitcoin-cli
    /// dumptxoutset` and can be loaded into either Core or satd via
    /// `loadtxoutset` (once that RPC lands in PR 5/5).
    ///
    /// The snapshot does not pause block processing. Instead, the base
    /// block, height, coin count and coin rows are all read from one
    /// RocksDB point-in-time snapshot inside `for_each_coin_snapshot`,
    /// which is internally consistent even if blocks connect during the
    /// dump (every chainstate commit is one atomic `WriteBatch`).
    ///
    /// Refuses to overwrite an existing file at `path` (matching Core).
    pub fn dump_utxo_snapshot(&self, path: &Path) -> Result<DumpSummary, DumpError> {
        // Early refusal to clobber an existing dump at the final path
        // (matches Core, and gives a clean error before doing any work).
        // This check is advisory only: it races a concurrent creator,
        // so the *authoritative* no-overwrite guarantee is enforced at
        // finalization time by `finalize_dump_path`, which links the
        // temp file to the target without replacing an existing file.
        if path.exists() {
            return Err(DumpError::RefuseOverwrite(path.to_path_buf()));
        }

        // Write to `<path>.incomplete` and atomically `rename(2)` on
        // success. A crash or kill -9 mid-dump leaves an obvious
        // `.incomplete` corpse rather than a half-written final file
        // (operator-recoverable, no manual cleanup of the target path).
        let temp_path = make_incomplete_path(path);

        // Acquire output file first (with O_EXCL — fails if a stale
        // `.incomplete` from a prior crash is in the way; operator
        // must remove it). Done BEFORE the tip lock so file-permission
        // and disk-full errors surface immediately without holding the
        // chainstate hostage.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(DumpError::Io)?;

        // From this point on, any error path must remove `temp_path`
        // so the operator can retry. Encapsulated in a closure-style
        // RAII-ish pattern using a guard.
        let mut guard = TempFileGuard::new(temp_path.clone());

        let result = self.dump_utxo_snapshot_inner(path, file, &temp_path);

        match result {
            Ok(summary) => {
                // Success: the inner fn already moved the temp file to
                // the final path via `finalize_dump_path`, so there's no
                // `.incomplete` corpse to clean up. Disarm the guard.
                guard.disarm();
                Ok(summary)
            }
            Err(e) => {
                // Guard's Drop will remove temp_path. Return the original
                // error.
                Err(e)
            }
        }
    }

    fn dump_utxo_snapshot_inner(
        &self,
        final_path: &Path,
        file: File,
        temp_path: &Path,
    ) -> Result<DumpSummary, DumpError> {
        use crate::storage::compressed_coin as cc;

        // Flush coin-cache dirty entries into the inner Store before
        // iterating, so the Store's snapshot sees every committed write.
        self.flush_coin_cache()?;

        // The snapshot's base block, height and coin count are read by
        // `for_each_coin_snapshot` from the SAME RocksDB point-in-time
        // view as the coins themselves (see `CoinSnapshotBase`). We do
        // NOT read them from the in-memory tip: block connection commits
        // the coin batch before publishing the in-memory tip, so an
        // in-memory base could name a block the snapshot's coins don't
        // correspond to. Because the base is only known once the
        // snapshot is taken (inside the iteration), we first write a
        // placeholder header, stream the coins, then seek back and
        // rewrite the header with the real base/count.
        //
        // BufWriter wraps the file; bytes flow ONLY into the file.
        // The HASH_SERIALIZED_3 hasher below sees a DIFFERENT byte
        // stream (TxOutSer-formatted), not the file bytes.
        let mut writer = BufWriter::new(file);
        let placeholder = cc::SnapshotMetadata {
            version: cc::SNAPSHOT_VERSION,
            network_magic: network_magic(self.network),
            base_blockhash: {
                use bitcoin::hashes::Hash;
                bitcoin::BlockHash::all_zeros()
            },
            coins_count: 0,
        };
        placeholder.serialize(&mut writer)?;

        // Streaming state. The iteration order is `(txid, vout)`
        // ascending (RocksDB key sort, matches Core), so coins from
        // the same txid are contiguous. We group them and emit Core's
        // per-txid record format on each transition.
        //
        // `hs3_engine` accumulates the HASH_SERIALIZED_3 hash — Core's
        // `hash_serialized` from `kernel/coinstats.cpp`. Each coin's
        // TxOutSer contribution is fed in. The final digest is what
        // matches `m_assumeutxo_data.hash_serialized` for that height.
        // Bracket the borrow on `writer` so it's released before we
        // touch the file again for the header rewrite/flush/fsync/rename.
        let (base, hs3_engine) = {
            let mut state = DumpState {
                writer: &mut writer,
                hs3_engine: bitcoin::hashes::sha256::HashEngine::default(),
                txout_buf: Vec::with_capacity(80),
                current_txid: None,
                current_group: Vec::new(),
                coins_written: 0,
                out_err: None,
            };

            let base = self.store.for_each_coin_snapshot(&mut |op, coin| {
                state.visit(op, coin);
                Ok(())
            })?;

            if let Some(e) = state.out_err.take() {
                return Err(e);
            }

            // Flush the final group (everything since the last txid change).
            state.flush_final_group()?;

            (base, state.hs3_engine)
        };

        let base_hash = base.base_hash;
        let base_height = base.base_height;
        let coins_written = base.coins_written;

        // Both counts come from the same snapshot now, so a mismatch is
        // genuine chainstate corruption rather than a benign write race.
        if coins_written != base.coin_count {
            return Err(DumpError::CountMismatch {
                expected: base.coin_count,
                actual: coins_written,
            });
        }

        // Rewrite the header in place with the snapshot-consistent base
        // and count. The header is a fixed 51 bytes, so this never
        // overruns into the coin records.
        {
            use std::io::{Seek, SeekFrom};
            writer.seek(SeekFrom::Start(0))?;
            let meta = cc::SnapshotMetadata {
                version: cc::SNAPSHOT_VERSION,
                network_magic: network_magic(self.network),
                base_blockhash: base_hash,
                coins_count: base.coin_count,
            };
            meta.serialize(&mut writer)?;
        }

        // Flush BufWriter to OS, then fsync the file. Without the
        // fsync, an OS crash after this point could leave the renamed
        // final file shorter than what we reported in `hash_serialized_3`
        // — a false-positive cross-validation.
        writer.flush()?;
        writer.get_ref().sync_all()?;
        // BufWriter's drop ensures the underlying file is closed
        // before we attempt the rename.
        drop(writer);

        // Core finalizes hash_serialized_3 with `HashWriter::GetHash()`
        // — a DOUBLE SHA-256 (`kernel/coinstats.cpp` FinalizeHash). The
        // result is a `uint256` whose `ToString()` (and therefore the
        // value quoted in `m_assumeutxo_data` / `dumptxoutset`'s
        // `txoutset_hash`) is the byte-reversed form. We reverse the
        // raw digest so `hash_serialized_3` is stored in the same
        // natural order the anchor table uses (see
        // `chain::assumeutxo::decode_sha256`). A single SHA-256, or the
        // un-reversed digest, will NOT match Core.
        let first = bitcoin::hashes::sha256::Hash::from_engine(hs3_engine);
        let double = bitcoin::hashes::sha256::Hash::hash(first.as_byte_array());
        let mut hash_serialized_3 = double.to_byte_array();
        hash_serialized_3.reverse();

        // Finalize without replacing: a plain `rename(2)` would silently
        // clobber a file that appeared at `final_path` after the early
        // `path.exists()` check (POSIX rename replaces the destination).
        // `finalize_dump_path` refuses instead. After this point the user
        // can see the file at the requested path; before, it lived as
        // `.incomplete`.
        finalize_dump_path(temp_path, final_path)?;

        Ok(DumpSummary {
            coins_written,
            base_hash,
            base_height,
            path: final_path.to_path_buf(),
            hash_serialized_3,
        })
    }

    /// Read the lock-free connect-heartbeat counter. Bumped on every
    /// successful connector iteration; read by the stall watchdog as its
    /// progress signal. Value is monotonic but not interpretable as a
    /// height — only its delta over time matters.
    pub fn connect_heartbeat(&self) -> u64 {
        self.connect_heartbeat.load(Ordering::Relaxed)
    }

    /// Bump the connect-heartbeat counter. Called by the connector after
    /// each successful block connect (in both IBD and steady-state paths)
    /// so the watchdog has a lock-free way to observe forward progress.
    pub fn bump_connect_heartbeat(&self) {
        self.connect_heartbeat.fetch_add(1, Ordering::Relaxed);
    }

    /// Read the lock-free manager-heartbeat counter. Bumped on every
    /// iteration of the P2P manager's main loop (~every 500 ms);
    /// stays silent only if the manager loop itself is wedged or the
    /// tokio runtime is parked. Read by the stall watchdog as a
    /// "loop is alive" signal independent of block arrivals.
    pub fn manager_heartbeat(&self) -> u64 {
        self.manager_heartbeat.load(Ordering::Relaxed)
    }

    /// Bump the manager-heartbeat counter. Called once per iteration
    /// of `PeerManager::run`'s main loop, regardless of whether work
    /// was performed or a block was connected on that tick.
    pub fn bump_manager_heartbeat(&self) {
        self.manager_heartbeat.fetch_add(1, Ordering::Relaxed);
    }

    /// Per-phase tracker for `connect_preprocessed_block`. The stall
    /// watchdog reads from this to identify which phase the connector
    /// wedged in (see `connect_phase.rs`). Returns an `Arc` clone so the
    /// watchdog can hold a reference without the borrow checker
    /// extending `ChainState`'s lifetime over the watchdog thread.
    pub fn connect_phases(
        &self,
    ) -> std::sync::Arc<crate::chain::connect_phase::ConnectPhaseTracker> {
        std::sync::Arc::clone(&self.connect_phases)
    }

    pub fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        self.store.get_block_index(hash)
    }

    pub fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        self.store.get_block_hash_by_height(height)
    }

    /// Direct store handle for tests that need to construct index states the
    /// public API cannot reach — e.g. a stale sibling block that exists in the
    /// block index but is deliberately absent from the height index.
    #[cfg(test)]
    pub(crate) fn store_for_test(&self) -> &dyn Store {
        &*self.store
    }

    /// Cumulative transaction count through (and including) the given
    /// block, or `None` if not yet recorded (e.g. a pre-snapshot block an
    /// AssumeUTXO background hasn't validated). Backs `getchaintxstats`.
    pub fn cumulative_tx_count(&self, hash: &BlockHash) -> Option<u64> {
        self.store.get_cumulative_tx_count(hash)
    }

    pub fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.store.get_coin(outpoint)
    }

    /// Undo data (the coins spent) for a connected block — one `Coin` per
    /// non-coinbase input in connect order. The decoupled watch matcher uses
    /// this for input-side script matching: by the time it scans a connected
    /// block, those prevouts have already been removed from the live UTXO set,
    /// so the spent `scriptPubKey`s are only recoverable from undo.
    pub fn get_undo(&self, hash: &BlockHash) -> Option<crate::storage::undo::UndoData> {
        self.store.get_undo(hash)
    }

    /// Check if we have block data (not just a header) for a block.
    pub fn has_block_data(&self, hash: &BlockHash) -> bool {
        self.store
            .get_block_index(hash)
            .map(|e| matches!(e.status, BlockStatus::Valid | BlockStatus::DataStored))
            .unwrap_or(false)
    }

    /// Accept a block header without block data (for headers-first sync).
    /// Validates PoW and difficulty but does not process transactions.
    pub fn accept_header(&self, header: &bitcoin::block::Header) -> Result<BlockHash, ChainError> {
        let hash = header.block_hash();

        // Already known?
        if self.store.get_block_index(&hash).is_some() {
            return Err(ChainError::Duplicate);
        }

        // Parent must exist
        let parent = self
            .store
            .get_block_index(&header.prev_blockhash)
            .ok_or(ChainError::BadPrevBlock)?;

        let new_height = parent.height + 1;

        // PoW validation
        validation::pow::check_proof_of_work(header)?;

        // Difficulty check. `get_ancestor` (by height) seeds retarget boundaries;
        // the testnet min-difficulty walk-back uses `get_by_hash` (parent
        // pointers) so it is immune to height→hash index gaps.
        validation::pow::check_difficulty(
            header,
            &parent,
            self.network,
            |h| {
                let hash = self.store.get_block_hash_by_height(h)?;
                self.store.get_block_index(&hash)
            },
            |h| self.store.get_block_index(h),
        )?;

        // Store as header-only
        let chainwork =
            crate::storage::blockindex::add_u256(&parent.chainwork, &crate::storage::blockindex::work_for_bits(header.bits));
        let entry = BlockIndexEntry {
            header: *header,
            height: new_height,
            status: BlockStatus::HeaderOnly,
            num_tx: 0,
            file_number: 0,
            data_pos: 0,
            chainwork,
        };

        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        // The height->hash index is the ACTIVE (connected) chain. Header-only
        // acceptance must never write into its active region (heights <= the
        // block tip): a competing fork announced *below* our tip would
        // otherwise clobber the active entry there (last-write-wins), silently
        // corrupting the index that `--reindex-chainstate` faithfully replays
        // — the root cause of the 951k `bad-cb-height` reindex loop. Heights
        // *above* the tip are header-chain territory (the IBD scheduler and the
        // getheaders locator legitimately need them); the block stays reachable
        // by hash + `best_header` regardless, so the fork-aware competing-chain
        // pull (#315) is unaffected.
        //
        // The above-tip test and the write must be ATOMIC w.r.t. block
        // connection: `accept_block` (submitblock / internal mine, on an RPC
        // thread) advances the tip under `accept_lock`, so without holding it
        // here a height that was above-tip at the test could be at-tip by the
        // write and still clobber. Take the lock across the test+commit.
        {
            let _accept_guard = self.accept_lock.lock();
            if new_height > self.tip_height() {
                batch.height_hash_puts.push((new_height, hash));
            }
            self.store.write_batch(batch)?;
        }

        // Track highest header for locator construction
        self.headers_tip_height.fetch_max(new_height, Ordering::Relaxed);
        self.update_best_header(hash, chainwork);

        Ok(hash)
    }

    /// Accept a batch of headers in a single write transaction.
    /// Returns (accepted_count, last_error). Stops on non-Duplicate errors.
    pub fn accept_headers(
        &self,
        headers: &[bitcoin::block::Header],
    ) -> (u32, Option<ChainError>) {
        let mut batch = crate::storage::StoreBatch::default();
        let mut accepted = 0u32;
        let mut max_height = 0u32;
        let mut best_in_batch: Option<(BlockHash, [u8; 32])> = None;

        for header in headers {
            let hash = header.block_hash();

            // Already known?
            if let Some(existing) = self.store.get_block_index(&hash) {
                // Crash-resume repair: if a block was stored (DataStored) but its
                // height→hash mapping was never written (e.g. accept_headers was
                // never called for it, or it was lost in a pending_batch that was
                // never flushed), restore it so the forward connect loop can find
                // it. Restricted to DataStored (NOT Valid) on purpose: connect
                // writes a block's Valid entry and its height→hash atomically in
                // one batch, so a Valid block with a *missing* mapping is never a
                // crash artifact — it is a block a reorg DISCONNECTED (disconnect
                // removes the mapping but leaves the status Valid). Restoring that
                // would re-point height→hash at a no-longer-active block, exactly
                // the clobber this change exists to prevent.
                if existing.status == BlockStatus::DataStored
                    && self.store.get_block_hash_by_height(existing.height).is_none()
                {
                    batch.height_hash_puts.push((existing.height, hash));
                    max_height = max_height.max(existing.height);
                }
                continue; // skip block_index write — entry already exists
            }

            // Also check the current batch for parent (handles consecutive headers)
            let parent = self
                .store
                .get_block_index(&header.prev_blockhash)
                .or_else(|| {
                    batch
                        .block_index_puts
                        .iter()
                        .find(|(h, _)| *h == header.prev_blockhash)
                        .map(|(_, e)| e.clone())
                });

            let parent = match parent {
                Some(p) => p,
                None => return (accepted, Some(ChainError::BadPrevBlock)),
            };

            let new_height = parent.height + 1;

            // PoW validation
            if let Err(e) = validation::pow::check_proof_of_work(header) {
                return (accepted, Some(e.into()));
            }

            // Difficulty check
            if let Err(e) = validation::pow::check_difficulty(
                header,
                &parent,
                self.network,
                |h| {
                    // Retarget seed by height: check batch first for recently
                    // accepted headers, then store.
                    batch
                        .height_hash_puts
                        .iter()
                        .find(|(bh, _)| *bh == h)
                        .and_then(|(_, hash)| {
                            batch
                                .block_index_puts
                                .iter()
                                .find(|(bih, _)| bih == hash)
                                .map(|(_, e)| e.clone())
                        })
                        .or_else(|| {
                            let hash = self.store.get_block_hash_by_height(h)?;
                            self.store.get_block_index(&hash)
                        })
                },
                |h| {
                    // Min-difficulty walk-back by parent hash: in-batch headers
                    // (this batch's predecessors) first, then the store. Using
                    // parent pointers — not the height index — makes the walk
                    // immune to height→hash gaps.
                    batch
                        .block_index_puts
                        .iter()
                        .find(|(bih, _)| bih == h)
                        .map(|(_, e)| e.clone())
                        .or_else(|| self.store.get_block_index(h))
                },
            ) {
                return (accepted, Some(e.into()));
            }

            let chainwork = crate::storage::blockindex::add_u256(
                &parent.chainwork,
                &crate::storage::blockindex::work_for_bits(header.bits),
            );
            let entry = BlockIndexEntry {
                header: *header,
                height: new_height,
                status: BlockStatus::HeaderOnly,
                num_tx: 0,
                file_number: 0,
                data_pos: 0,
                chainwork,
            };

            batch.block_index_puts.push((hash, entry));
            // Stage the height->hash write for every accepted header; the
            // authoritative "strictly above the active tip" filter is applied
            // once, atomically under `accept_lock`, just before the commit below
            // (see there for the rationale). Staging all of them keeps the
            // in-batch difficulty-ancestor lookup above able to resolve
            // consecutive headers by height within this batch.
            batch.height_hash_puts.push((new_height, hash));
            accepted += 1;
            max_height = max_height.max(new_height);
            if best_in_batch
                .as_ref()
                .is_none_or(|(_, w)| compare_u256(&chainwork, w) > 0)
            {
                best_in_batch = Some((hash, chainwork));
            }
        }

        if accepted > 0 || !batch.height_hash_puts.is_empty() {
            // Commit the height->hash writes atomically w.r.t. block connection.
            // `accept_block` (submitblock / internal mine, on an RPC thread)
            // advances the active tip under `accept_lock`; without holding it
            // here, an entry staged as above-tip during the loop could be at-tip
            // by the time we write and clobber the active-chain entry there. Take
            // the lock, drop any staged height->hash entry that is no longer
            // strictly above the (possibly just-advanced) tip, then write — so
            // only genuine header-chain entries reach the index. `block_index_puts`
            // are hash-keyed and need no such filter.
            {
                let _accept_guard = self.accept_lock.lock();
                let tip_height = self.tip_height();
                batch.height_hash_puts.retain(|(h, _)| *h > tip_height);
                if let Err(e) = self.store.write_batch(batch) {
                    return (0, Some(e.into()));
                }
            }
            self.headers_tip_height
                .fetch_max(max_height, Ordering::Relaxed);
            if let Some((h, w)) = best_in_batch {
                self.update_best_header(h, w);
            }
        }

        (accepted, None)
    }

    /// Get the highest header height stored (may be ahead of block tip during IBD).
    pub fn headers_tip_height(&self) -> u32 {
        self.headers_tip_height.load(Ordering::Relaxed)
    }

    /// Advance the best-header pointer if `chainwork` is strictly more than the
    /// current best (first-seen wins ties, matching consensus).
    fn update_best_header(&self, hash: BlockHash, chainwork: [u8; 32]) {
        let mut best = self.best_header.write();
        if compare_u256(&chainwork, &best.1) > 0 {
            *best = (hash, chainwork);
        }
    }

    /// The most-work header chain tip seen so far (analogous to Core's
    /// `pindexBestHeader`).
    pub fn best_header_hash(&self) -> BlockHash {
        self.best_header.read().0
    }

    /// Ensure the in-memory `best_header` pointer is at least the active tip.
    ///
    /// A `--reindex` constructs `ChainState` from an empty index (the
    /// best-header pointer is seeded at genesis), then the replay advances the
    /// active tip *without* going through `accept_header`/`accept_block`, the
    /// only writers of `best_header`. The pointer is therefore left behind the
    /// rebuilt tip, which (a) makes `check_block_index` see the selection
    /// pointer lagging the active chain and (b) leaves the node unable to
    /// recognize it is caught up — `missing_blocks_for_best_header_chain`
    /// returns empty until the first peer `headers` re-seeds the pointer.
    /// Re-seed it from the rebuilt tip. A no-op when the pointer already
    /// out-works the tip (e.g. header-only branches loaded from a kept index
    /// under `--reindex-chainstate`), since [`update_best_header`] keeps the max.
    pub fn refresh_best_header_to_tip(&self) {
        let tip_hash = self.tip_hash();
        if let Some(entry) = self.get_block_index(&tip_hash) {
            self.update_best_header(tip_hash, entry.chainwork);
        }
    }

    /// Structural consistency audit of the on-disk block index against the
    /// active chain — a startup analogue of Bitcoin Core's `CheckBlockIndex`
    /// (Core runs its check continuously after every connect/disconnect; this
    /// runs once at startup and after a reindex).
    ///
    /// Metadata-only: it reads block-index entries (header, height, status,
    /// chainwork), never block data, so it is cheap enough to gate behind
    /// `-checkblockindex` (default on for regtest/CI, off for mainnet). It
    /// walks the active chain by `prev_blockhash` from the tip down to the
    /// bottom of the range this chainstate owns — genesis normally, or the
    /// AssumeUTXO snapshot base when a background chainstate is still filling
    /// the pre-snapshot range — and, at every height, cross-checks: the
    /// entry's stored `height` equals
    /// its position in the chain; the `height -> hash` map agrees with the
    /// prev-link walk; chainwork strictly increases and satisfies the exact
    /// recurrence `child.chainwork == parent.chainwork + work(child.bits)`;
    /// and no active block is marked `Invalid`. It also verifies the chain
    /// bottoms out at the network genesis and that `best_header` is never
    /// behind the active tip in work.
    ///
    /// Walking the prev-links (rather than the `height -> hash` map) is the
    /// whole point: it does not trust the structure that reorg bugs corrupt,
    /// so a side block clobbering a height entry surfaces as a disagreement
    /// between the map and the prev-walk. That is exactly the failure that
    /// polluted heights 951540–951945 and made `--reindex-chainstate` abort
    /// at `bad-cb-height`.
    ///
    /// Returns the tip height verified, or a description of the first
    /// inconsistency found.
    pub fn check_block_index(
        &self,
        progress: Option<Arc<crate::startup_progress::StartupProgress>>,
    ) -> Result<u32, String> {
        let tip_hash = self.tip_hash();
        let tip_height = self.tip_height();
        let genesis = bitcoin::constants::genesis_block(self.network).block_hash();

        // Under AssumeUTXO the active (snapshot) chainstate is authoritative
        // only for [snapshot_height, tip]: `adopt_snapshot_tip` seeds a single
        // height->hash entry at the base and the background chainstate fills
        // the genesis->base range lazily over hours/days, so heights below the
        // base may legitimately be absent from the map. Scope the walk to the
        // range this chainstate owns (the background validates the rest as it
        // connects), so the audit does not false-fail mid-background-sync.
        let floor = self.background().map(|bg| bg.snapshot_height()).unwrap_or(0);

        if let Some(p) = &progress {
            p.set_phase("checkblockindex", "Verifying block-index consistency…");
        }
        tracing::info!(tip_height, floor, "Starting block-index consistency audit");

        let mut hash = tip_hash;
        let mut height = tip_height;
        // The block we descended from (one height up): (height, chainwork,
        // its own work) — used to verify the chainwork recurrence.
        let mut child: Option<(u32, [u8; 32], [u8; 32])> = None;

        loop {
            let entry = self.get_block_index(&hash).ok_or_else(|| {
                format!("active block {hash} at height {height} is missing from the block index")
            })?;

            // (1) stored height matches the active-chain position
            if entry.height != height {
                return Err(format!(
                    "block {hash} has stored height {} but sits at active-chain position {height}",
                    entry.height
                ));
            }

            // (4) an active-chain block must never be marked Invalid
            if entry.status == BlockStatus::Invalid {
                return Err(format!(
                    "active block {hash} at height {height} is marked Invalid"
                ));
            }

            // (2) the height->hash map must agree with the prev-link walk.
            //     This is the side-block-clobber / 951k-pollution detector.
            match self.get_block_hash_by_height(height) {
                Some(h) if h == hash => {}
                other => {
                    return Err(format!(
                        "height->hash[{height}] = {other:?}, but the active chain (by prev-links) \
                         has {hash}"
                    ));
                }
            }

            // (3) chainwork recurrence against the child we descended from
            if let Some((child_height, child_chainwork, child_work)) = child {
                if compare_u256(&child_chainwork, &entry.chainwork) <= 0 {
                    return Err(format!(
                        "chainwork is not strictly increasing between heights {height} and \
                         {child_height}"
                    ));
                }
                if add_u256(&entry.chainwork, &child_work) != child_chainwork {
                    return Err(format!(
                        "chainwork recurrence is broken at height {child_height}: stored work != \
                         parent work + work(bits)"
                    ));
                }
            }

            // Bottom of the audited range. Without AssumeUTXO this is genesis
            // (verify it); with a snapshot it is the snapshot base, validated
            // by the per-iteration checks above — stop there, the background
            // owns everything below.
            if height == floor {
                if floor == 0 && hash != genesis {
                    return Err(format!(
                        "active chain bottoms out at {hash}, not the {:?} genesis {genesis}",
                        self.network
                    ));
                }
                break;
            }

            // Liveness + progress for the mainnet case (~950k point lookups):
            // refresh the stall-watchdog heartbeat and the startup status so a
            // long audit is neither mistaken for a hang nor reported under a
            // stale phase.
            if height.is_multiple_of(50_000) {
                self.bump_connect_heartbeat();
                if let Some(p) = &progress {
                    p.set_current(u64::from(tip_height - height));
                }
                tracing::info!(height, "Block-index audit in progress");
            }

            child = Some((height, entry.chainwork, work_for_bits(entry.header.bits)));
            hash = entry.header.prev_blockhash;
            height -= 1;
        }

        // best_header (the most-work header tip) must never be behind the
        // active tip in work — if it is, the chainwork pointer and the active
        // chain disagree about which chain is best.
        let best_cw = self
            .get_block_index(&self.best_header_hash())
            .map(|e| e.chainwork);
        let tip_cw = self.get_block_index(&tip_hash).map(|e| e.chainwork);
        if let (Some(best), Some(tip)) = (best_cw, tip_cw)
            && compare_u256(&best, &tip) < 0
        {
            return Err(format!(
                "best_header chainwork is behind the active tip at height {tip_height}"
            ));
        }

        Ok(tip_height)
    }

    /// Blocks we must download to connect the best-work header chain we know
    /// of, in connect order (oldest first), up to `max_request`. Walks back
    /// from the best-work header tip (`best_header`, the most-work chain — NOT
    /// the pollutable height index) via `prev_blockhash` to the point it joins
    /// the active chain, collecting every block along the way that we lack data
    /// for (skipping but walking PAST any side block we already have).
    ///
    /// Returns empty when the best header chain does not out-work the active
    /// tip (we are already on — or ahead of — the best chain), or when the fork
    /// point is not reached within the bounded walk (a pathologically deep
    /// fork: requesting an unanchored deep run makes no progress, so we decline
    /// rather than spin).
    ///
    /// This is the fork-aware replacement for a forward-by-active-height walk:
    /// a competing chain forks *below* its tip, so some of its blocks sit at
    /// heights at or below our active tip. A height-indexed forward walk
    /// (`tip+1, tip+2, …`) never requests those fork blocks, and without the
    /// fork block's data a reorg onto the competing chain can never reconnect
    /// — the exact reason a synced listener failed to adopt a longer chain
    /// announced by an inbound peer. Walking to the active-chain fork (rather
    /// than stopping at the first block we happen to have) also requests a hole
    /// that sits *below* an already-present side block, which a "stop at first
    /// data" walk would strand.
    pub fn missing_blocks_for_best_header_chain(&self, max_request: usize) -> Vec<BlockHash> {
        if max_request == 0 {
            return Vec::new();
        }
        let tip_hash = self.tip_hash();
        let Some(tip_entry) = self.store.get_block_index(&tip_hash) else {
            return Vec::new();
        };
        // The most-work header chain tip (tracked by chainwork in
        // accept_header/accept_headers/accept_block), not the height index.
        let best_hash = self.best_header_hash();
        let Some(best_entry) = self.store.get_block_index(&best_hash) else {
            return Vec::new();
        };
        if compare_u256(&best_entry.chainwork, &tip_entry.chainwork) <= 0 {
            return Vec::new();
        }

        // Walk back from the best-work header tip, collecting blocks we lack
        // data for (newest first), until the chain joins the ACTIVE chain (the
        // fork point) — not merely until the first block we happen to have, so
        // a missing block below an already-present side block is still
        // collected. Bounded: if the fork point isn't reached within
        // `MAX_WALK`, return empty rather than request an unanchored deep run
        // that can never connect (which would re-request every cycle forever).
        const MAX_WALK: usize = 16_384;
        let mut missing: Vec<BlockHash> = Vec::new();
        let mut h = best_hash;
        let mut height = best_entry.height;
        let mut reached_fork = false;
        for _ in 0..MAX_WALK {
            // On the active chain? Then `h` is the fork point — stop.
            if self.active_chain_hash_at_height(height) == Some(h) {
                reached_fork = true;
                break;
            }
            let Some(e) = self.store.get_block_index(&h) else {
                break;
            };
            if !self.has_block_data(&h) {
                missing.push(h);
            }
            if height == 0 {
                // Genesis is always on the active chain; treat as fork reached.
                reached_fork = true;
                break;
            }
            h = e.header.prev_blockhash;
            height -= 1;
        }
        if !reached_fork {
            return Vec::new();
        }
        // Oldest first so the peer's (ordered) getdata response connects in
        // dependency order; cap to the caller's batch size.
        missing.reverse();
        missing.truncate(max_request);
        missing
    }

    /// True if the best-work *header* chain has strictly more work than the
    /// active tip — i.e. a reorg onto a competing chain is warranted but the
    /// active chain is not yet on it.
    ///
    /// The IBD connector connects strictly linearly by height (`tip+1`) and
    /// cannot perform a reorg. When a competing same-height fork appears at the
    /// connect frontier, the connector loops forever on `bad-prevblk` (the
    /// block at `tip+1` builds on a parent that is not the active tip) while
    /// the height-indexed scheduler reports itself complete and never requests
    /// the missing fork block. The connector uses this predicate to detect
    /// that situation and hand off to the steady-state path, which *is*
    /// reorg-capable (fork-aware block pull via
    /// [`Self::missing_blocks_for_best_header_chain`] + `ActivateBestChain`).
    pub fn best_header_beats_active_tip(&self) -> bool {
        let tip = self.tip_hash();
        let best = self.best_header_hash();
        if tip == best {
            return false;
        }
        let (Some(tip_entry), Some(best_entry)) = (
            self.store.get_block_index(&tip),
            self.store.get_block_index(&best),
        ) else {
            return false;
        };
        compare_u256(&best_entry.chainwork, &tip_entry.chainwork) > 0
    }

    /// True unless the height-indexed block at `tip+1` builds on a *different*
    /// parent than the active tip — i.e. the connect frontier is fork-blocked.
    ///
    /// The linear-by-height IBD scheduler cannot reorg, so it must NOT be
    /// (re)created while the frontier is fork-blocked: the block it would try
    /// to connect at `tip+1` is on a competing branch whose parent isn't the
    /// active tip, and it would loop on `bad-prevblk` forever. When this
    /// returns false, the reorg-capable steady-state path is left to move the
    /// active tip onto the better chain; once it does, the new `tip+1` links to
    /// the new tip, this returns true again, and bulk IBD can resume. This is
    /// self-correcting at any fork depth or position (not just a 1-block tip
    /// fork). Returns true when there is no block at `tip+1` yet (nothing to
    /// suppress) or its index entry is missing.
    pub fn frontier_connects_to_tip(&self) -> bool {
        let tip = self.tip_hash();
        let next_height = self.tip_height() + 1;
        match self.get_block_hash_by_height(next_height) {
            None => true,
            Some(h) => match self.store.get_block_index(&h) {
                Some(e) => e.header.prev_blockhash == tip,
                None => true,
            },
        }
    }

    /// Whether assumevalid is configured (not Disabled).
    /// Used to decide whether prefetch should run script pre-verification.
    pub fn is_assumevalid_active(&self) -> bool {
        !matches!(self.assumevalid, AssumeValid::Disabled)
    }

    /// Check if script verification should be skipped (assumevalid optimization).
    fn should_skip_scripts(&self, height: u32) -> bool {
        match &self.assumevalid {
            AssumeValid::Disabled => false,
            AssumeValid::Hash(av_hash) => {
                // Check if we've seen the assumevalid block in the index
                if let Some(entry) = self.store.get_block_index(av_hash) {
                    return height <= entry.height;
                }
                // Haven't seen it yet — might still be syncing headers.
                // Conservative: don't skip until we've confirmed the hash exists.
                false
            }
            AssumeValid::All { max_age_secs } => {
                // Skip scripts for blocks whose header timestamp is older than the cutoff.
                // This naturally transitions to full verification once the node catches up.
                if let Some(hash) = self.store.get_block_hash_by_height(height)
                    && let Some(entry) = self.store.get_block_index(&hash)
                {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let block_time = entry.header.time as u64;
                    return now.saturating_sub(block_time) > *max_age_secs;
                }
                false
            }
        }
    }

    /// Compute median time past (MTP) for a given height.
    /// MTP is the median of the timestamps of the previous 11 blocks.
    pub fn get_median_time_past(&self, height: u32) -> u32 {
        let start = height.saturating_sub(11);
        let range_len = (height - start) as usize;

        // Try to satisfy entirely from cache
        let cache = self.mtp_cache.lock();
        let mut timestamps: Vec<u32> = Vec::with_capacity(range_len);
        for h in start..height {
            if let Some((_, ts)) = cache.iter().find(|(ch, _)| *ch == h) {
                timestamps.push(*ts);
            }
        }
        drop(cache);

        if timestamps.len() == range_len && !timestamps.is_empty() {
            // Cache hit — all timestamps found
            timestamps.sort();
            return timestamps[timestamps.len() / 2];
        }

        // Cache miss — fall back to store lookups
        timestamps.clear();
        for h in start..height {
            if let Some(hash) = self.store.get_block_hash_by_height(h)
                && let Some(entry) = self.store.get_block_index(&hash) {
                    timestamps.push(entry.header.time);
                }
        }
        if timestamps.is_empty() {
            return 0;
        }
        timestamps.sort();
        timestamps[timestamps.len() / 2]
    }

    /// Authoritative active-chain lookup: the hash of the block at `height` on
    /// the *active* chain, or `None` if `height` is above the tip.
    ///
    /// Unlike [`get_block_hash_by_height`](Self::get_block_hash_by_height),
    /// which reads the `height_hash` index ("best known at height" — pollutable
    /// by side-chain `store_block`/header paths, see
    /// `test_reorg_fork_point_immune_to_polluted_height_hash`), this walks back
    /// from the tip via `prev_blockhash`, so it never returns a side-chain
    /// block. Use it where active-chain membership must be exact. Cost is
    /// `O(tip_height - height)`; querying the tip itself is free.
    pub fn active_chain_hash_at_height(&self, height: u32) -> Option<BlockHash> {
        let (tip_hash, tip_height) = self.tip_snapshot();
        if height > tip_height {
            return None;
        }
        let mut cur = tip_hash;
        let mut h = tip_height;
        while h > height {
            let entry = self.store.get_block_index(&cur)?;
            cur = entry.header.prev_blockhash;
            h -= 1;
        }
        Some(cur)
    }

    /// Push a block's timestamp into the MTP cache after connection.
    pub fn push_mtp_cache(&self, height: u32, timestamp: u32) {
        let mut cache = self.mtp_cache.lock();
        cache.push((height, timestamp));
        // Keep only the last 12 entries
        if cache.len() > 12 {
            cache.remove(0);
        }
    }

    /// Pop the highest entry from MTP cache (used on disconnect).
    pub fn pop_mtp_cache(&self, height: u32) {
        let mut cache = self.mtp_cache.lock();
        cache.retain(|(h, _)| *h != height);
    }

    /// Get the total number of UTXOs in the set.
    pub fn coin_count(&self) -> u64 {
        self.store.coin_count()
    }

    /// Get the total amount (in satoshis) across all UTXOs.
    pub fn coin_total_amount(&self) -> u64 {
        self.store.coin_total_amount()
    }

    /// Get UTXO creation height histogram (1000-block buckets).
    pub fn utxo_height_hist(&self) -> Vec<u64> {
        self.store.utxo_height_hist()
    }

    /// Access the script verifier (for mempool use).
    pub fn script_verifier(&self) -> &dyn ScriptVerifier {
        &*self.script_verifier
    }

    /// Identify which concrete engine is on the authoritative verification
    /// path. Used by the prefetch pipeline so its speculative-verify matches
    /// whichever engine the user configured as primary.
    pub fn primary_engine(&self) -> crate::validation::script::PrimaryEngine {
        self.script_verifier.primary_engine()
    }

    /// Get an Arc reference to the store for read-only access by prefetch workers.
    pub fn store_ref(&self) -> &std::sync::Arc<CoinCache> {
        &self.store
    }

    /// Whether the silent-payment tweak index is enabled for this instance.
    pub fn silent_payment_index_enabled(&self) -> bool {
        self.sp_index.enabled
    }

    /// Switch the coin-cache / backing-store write mode. Use `BulkLoad`
    /// during IBD to disable the WAL on RocksDB writes (major I/O win);
    /// the caller must invoke `flush_durable` periodically so crash-
    /// recovery replay stays bounded. `Normal` restores per-write
    /// durability for steady-state operation.
    pub fn set_write_mode(&self, mode: crate::storage::WriteMode) {
        // Sync the flat files first. `CoinCache::set_write_mode` flushes
        // memtables on the BulkLoad→Normal transition (so WAL-less writes are
        // not stranded), and that flush is the *store-level* one — it has no
        // flat-file step in front of it, which is the exact inverse of the
        // ordering `flush_durable` exists to enforce. Callers are supposed to
        // call `flush_durable` first, but the IBD guard proceeds with the mode
        // switch even when that call fails, so make the ordering hold here
        // rather than depending on every caller getting it right.
        if let Err(e) = self.flat_files.lock().sync_all() {
            tracing::error!(
                error = %e,
                "flat-file sync before a write-mode switch failed; \
                 block index entries may become durable ahead of their data"
            );
        }
        self.store.set_write_mode(mode);
    }

    /// Force all cached writes to durable storage. Intended to be called
    /// periodically during `BulkLoad` IBD, and unconditionally before
    /// switching back to `Normal` mode or shutting down.
    ///
    /// Ordering matters: flat-file block data is fsync'd FIRST, then the
    /// RocksDB memtables (which hold `block_index` entries pointing into
    /// those files). The reverse order could persist an index entry whose
    /// referenced block data is still page-cache-only — a power loss then
    /// leaves a truncated file behind a valid-looking index ("block data
    /// missing"). This mirrors Bitcoin Core's `FlushBlockFile`-before-
    /// chainstate-flush sequence in `FlushStateToDisk`.
    pub fn flush_durable(&self) -> Result<(), crate::storage::StoreError> {
        use crate::storage::Store;
        self.flat_files.lock().sync_all()?;
        self.store.flush_durable()
    }

    /// Append a block record to the flat files, upholding the "data before
    /// the index entry that references it" ordering `flush_durable`
    /// documents. Every caller that follows this with a `block_index` write
    /// carrying the returned [`FlatFilePos`] MUST come through here.
    ///
    /// `flush_durable`'s ordering only binds at a flush. Between flushes the
    /// two streams are independently buffered — the flat-file append sits in
    /// the page cache until `sync_all`, and RocksDB's WAL is written without
    /// `WriteOptions::sync` — and which one the kernel writes back first is
    /// undefined. A kernel panic or power loss in that window commits the
    /// pointer and drops the payload, leaving a `DataStored` entry over a
    /// truncated record: `getblock` returns "Block data not available", any
    /// index backfill walking that height fails hard, and the block cannot be
    /// served to peers. Consensus is unaffected (the UTXO delta was already
    /// applied), so the node looks healthy until something re-reads history.
    ///
    /// Observed on a mainnet node at height 954866: the record was
    /// cut at a 4 KiB page boundary and the next block was appended at the
    /// resulting EOF, 1.6 MB short of where the index said it ended.
    ///
    /// **The sync is unconditional, including under `BulkLoad`.** An earlier
    /// version of this fix skipped it during IBD, reasoning that `BulkLoad`
    /// disables the WAL so an index entry could only become durable through
    /// `flush_durable` — which syncs the flat files first. That reasoning is
    /// wrong: disabling the WAL does not stop a memtable from being flushed
    /// to an SST on its own. `write_buffer_size` is per-CF and
    /// `set_atomic_flush(true)` (see `rocksdb_store.rs`) makes every listed
    /// CF flush as one unit whenever any of them fills, so the 64 MB `coins`
    /// buffer filling during IBD drags `block_index` to disk with it — while
    /// the flat files are only fsync'd every ~1000 blocks. IBD was in fact
    /// the *more* exposed path, not the safe one.
    ///
    /// The cost is one fsync per stored block. In steady state that is
    /// nothing (one block per ~10 minutes). During IBD it is real but
    /// bounded, and paying it is not optional: correctness of the block store
    /// is not something to trade for sync throughput. Amortizing it properly
    /// means deferring `block_index` writes until the record they reference
    /// has been synced — Bitcoin Core's model — which is a larger change than
    /// this fix and is tracked separately.
    fn write_block_durable(&self, block_data: &[u8]) -> Result<FlatFilePos, ChainError> {
        let mut flat = self.flat_files.lock();
        let pos = flat
            .write_block(block_data, network_magic(self.network))
            .map_err(|e| ChainError::FlatFile(e.to_string()))?;
        flat.sync_all()
            .map_err(|e| ChainError::FlatFile(e.to_string()))?;
        Ok(pos)
    }

    /// Re-derive the flat-file append offset from the file on disk.
    ///
    /// Opening a datadir already does this, so it matters only when the block
    /// files change underneath a running node — which in practice means tests
    /// simulating a crash-truncation without a restart. See
    /// [`FlatFileManager::resync_append_pos`].
    pub fn resync_block_append_pos(&self) -> Result<(), ChainError> {
        self.flat_files
            .lock()
            .resync_append_pos()
            .map_err(|e| ChainError::FlatFile(e.to_string()))
    }

    /// Get the blocks directory path.
    pub fn blocks_dir(&self) -> &std::path::Path {
        &self.blocks_dir
    }

    /// Blocks-dir obfuscation key (Core v28+ `xor.dat`; zero = plaintext).
    pub fn blocks_xor_key(&self) -> [u8; 8] {
        self.blocks_xor_key
    }

    /// Scan flat files and repair `block_index` entries above the current
    /// tip that are stuck in `HeaderOnly` despite the block data being
    /// present on disk.
    ///
    /// Why this exists: a historical race in `CachedStore::write_batch`'s
    /// dominance filter (see `coin_cache.rs`) — and the lack of an
    /// equivalent guard at the inner RocksDB layer until recently — let
    /// `accept_headers`' HeaderOnly batch overwrite a concurrent
    /// `store_block`'s DataStored update. The flat file writes were
    /// non-transactional with the index, so the block bytes are still on
    /// disk; only the index entry was wiped (file=0 pos=0, the
    /// placeholder accept_headers writes for HeaderOnly).
    ///
    /// Without repair, the connect loop wedges permanently at the first
    /// hole: `has_block_data()` returns false, the IBD scheduler can
    /// re-request the block, but with peer churn there's no guarantee
    /// any peer stays connected long enough to redeliver — and even if
    /// one does, the next hole 100 heights up wedges us again. Mainnet
    /// instance, 2026-05-12: 435 holes across a 3084-height window.
    ///
    /// Scan cost: one sequential pass over every flat file (~134 MB
    /// each). On the affected mainnet datadir, ~670 GB total → ~20 min
    /// at typical SSD bandwidth. The pass is skipped entirely when
    /// there are no holes above the tip, so a healthy node pays only
    /// the index walk.
    /// One-shot, index-only backfill of the cumulative-tx-count CF
    /// (`chain_tx`) for an upgraded datadir that predates it. Reads
    /// `num_tx` from the existing block index — no block-body reads, no
    /// re-validation — so it is cheap (minutes) and never a reindex.
    /// Gated by the `chain_tx.backfill_complete` marker; a no-op once
    /// stamped. Returns the number of block entries written.
    ///
    /// Walks the active chain downward from the tip via `prev_blockhash`
    /// (authoritative — never the `height_hash` index, which can be polluted
    /// by side-chain `store_block`/header paths) to find its start, then
    /// applies cumulative counts upward. The start is one of:
    ///   * genesis (height 0) → cumulative begins at 0,
    ///   * a block whose cumulative is already known (a prior partial run
    ///     or a seeded snapshot base) → resume from it,
    ///   * a snapshot base whose pre-snapshot ancestor is absent/`HeaderOnly`
    ///     (an AssumeUTXO node whose background hasn't validated genesis→base)
    ///     → seed from the hardcoded anchor's `nchaintx`.
    pub fn backfill_chain_tx_counts(&self) -> Result<u64, ChainError> {
        if self.store.chain_tx_backfill_complete() {
            return Ok(0);
        }
        let (tip_hash, tip_height) = self.tip_snapshot();
        if tip_height == 0 {
            // Genesis-only (or empty): the walk below is skipped, but we must
            // still record the genesis cumulative. connect_block reads the
            // parent's cumulative via get_cumulative_tx_count().unwrap_or(0),
            // so if chain_tx[genesis] is absent the first connected block
            // (height 1) treats genesis as 0 txs and undercounts the whole
            // chain by the genesis tx forever. The tip IS genesis here.
            if self.store.get_cumulative_tx_count(&tip_hash).is_none() {
                let entry = self.store.get_block_index(&tip_hash).ok_or_else(|| {
                    ChainError::Storage(crate::storage::StoreError::Database(
                        "missing genesis block index entry".to_string(),
                    ))
                })?;
                let mut batch = crate::storage::StoreBatch::default();
                batch.chain_tx_puts.push((tip_hash, entry.num_tx as u64));
                self.store.write_batch(batch)?;
                self.store.flush()?;
            }
            self.store.mark_chain_tx_backfill_complete()?;
            return Ok(0);
        }

        // Collect (hash, num_tx) descending the active chain from the tip via
        // prev_blockhash — never get_block_hash_by_height, whose index can be
        // clobbered by a side-chain block at an active height. Following parent
        // links visits only active-chain blocks, so a polluting side block is
        // never counted (and the real active block is never skipped). Stop at:
        //   * a block whose cumulative is already recorded (resume point), or
        //   * genesis (height 0), or
        //   * a block with no real tx count (absent/HeaderOnly entry) — the
        //     bottom of the connected range, i.e. an AssumeUTXO snapshot base
        //     whose pre-snapshot ancestors aren't validated yet.
        let mut collected: Vec<(BlockHash, u64)> = Vec::new();
        let mut resume_cum: Option<u64> = None; // cumulative just below the lowest collected block
        let mut cur = tip_hash;
        let mut h = tip_height;
        loop {
            if let Some(c) = self.store.get_cumulative_tx_count(&cur) {
                // Already known — this block is done; start above it.
                resume_cum = Some(c);
                break;
            }
            let Some(entry) = self.store.get_block_index(&cur) else {
                // Entry absent: bottom of the stored chain. The lowest
                // collected block is the snapshot base (handled below).
                break;
            };
            // HeaderOnly/Invalid blocks carry no real num_tx; they are below
            // the connected active range, so the lowest collected block is the
            // start. Valid/DataStored/Pruned all retain a real tx count.
            if !matches!(
                entry.status,
                BlockStatus::Valid | BlockStatus::DataStored | BlockStatus::Pruned
            ) {
                break;
            }
            collected.push((cur, entry.num_tx as u64));
            if h == 0 {
                resume_cum = Some(0); // below genesis
                break;
            }
            cur = entry.header.prev_blockhash;
            h -= 1;
        }

        // If we stopped on a gap (not genesis, not a known cumulative), the
        // lowest collected block is a snapshot base; seed its cumulative
        // from the hardcoded anchor. `anchor.nchaintx` is the count through
        // (and including) the base, so seed the value *below* it.
        if resume_cum.is_none() {
            let (base_hash, base_num_tx) = *collected
                .last()
                .expect("loop pushes at least one entry before a gap break");
            match crate::chain::assumeutxo::lookup_by_blockhash(self.network, &base_hash) {
                Some(anchor) => resume_cum = Some(anchor.nchaintx.saturating_sub(base_num_tx)),
                None => {
                    // Active chain starts above genesis but the base isn't a
                    // recognized anchor — can't seed. Leave the marker unset
                    // so a later start retries; surface loudly.
                    tracing::warn!(
                        start_hash = %base_hash,
                        "chain_tx backfill: active chain starts above genesis but its base is \
                         not a recognized AssumeUTXO anchor; skipping (getchaintxstats.txcount \
                         will omit until resolved)"
                    );
                    return Ok(0);
                }
            }
        }

        // Apply cumulative counts ascending, flushing in bounded chunks.
        let mut cum = resume_cum.expect("resume_cum set above");
        let mut written = 0u64;
        let mut batch = crate::storage::StoreBatch::default();
        const CHUNK: usize = 50_000;
        for (hash, num_tx) in collected.into_iter().rev() {
            cum += num_tx;
            batch.chain_tx_puts.push((hash, cum));
            written += 1;
            if batch.chain_tx_puts.len() >= CHUNK {
                self.store.write_batch(std::mem::take(&mut batch))?;
            }
        }
        if !batch.chain_tx_puts.is_empty() {
            self.store.write_batch(batch)?;
        }
        self.store.flush()?;
        self.store.mark_chain_tx_backfill_complete()?;
        Ok(written)
    }

    /// Audit the height→hash index for gaps at or below the tip and rederive
    /// what can be rederived. See
    /// [`crate::chain::height_index_repair`] for what it will and will not
    /// touch.
    ///
    /// Independent of [`Self::repair_block_index_holes`]: that pass inspects
    /// only heights strictly above the tip, this one writes only heights at or
    /// below it, so the two never touch the same row.
    pub fn repair_height_index(
        &self,
    ) -> Result<crate::chain::height_index_repair::HeightIndexAudit, ChainError> {
        let tip_hash = self.tip_hash();
        let tip_height = self.tip_height();
        Ok(
            crate::chain::height_index_repair::audit_and_repair_height_index(
                &*self.store,
                tip_hash,
                tip_height,
            )?,
        )
    }

    /// The block the tip is standing on must be one whose UTXO delta this
    /// chainstate has actually applied.
    ///
    /// Both sequential connect paths already require
    /// `prev_blockhash == tip`, which pins the *shape* of the chain but says
    /// nothing about whether that parent was ever connected. On a synced
    /// mainnet node the in-memory tip advanced eight blocks past the last
    /// block actually connected, and every one of those connects satisfied
    /// the prev-hash check on the way up (see #567). This is the missing
    /// half: the parent must also be a block that ran through
    /// `connect_block`, which is the only writer of `BlockStatus::Valid`.
    ///
    /// Two exemptions, both cases where the coins are present without this
    /// chainstate having connected the block:
    ///
    /// - `Pruned` — connected, then had its block data removed.
    /// - The AssumeUTXO snapshot base — its coins were streamed in wholesale
    ///   by `loadtxoutset`, and its entry stays `HeaderOnly`/`DataStored`
    ///   until the background chainstate has re-validated all of
    ///   genesis→base. Without this exemption an AssumeUTXO node could never
    ///   connect base+1, which is the entire point of a snapshot. The
    ///   exemption expires on its own: once the background finishes it has
    ///   written `Valid` for the base like any other block, and it only
    ///   applies while a background chainstate is attached.
    fn require_connected_parent(
        &self,
        parent_hash: &BlockHash,
        connecting: &BlockHash,
        height: u32,
    ) -> Result<(), ChainError> {
        let Some(parent) = self.store.get_block_index(parent_hash) else {
            return Err(ChainError::ParentNeverConnected);
        };
        if matches!(parent.status, BlockStatus::Valid | BlockStatus::Pruned) {
            return Ok(());
        }
        if self
            .background()
            .is_some_and(|bg| bg.snapshot_hash() == *parent_hash)
        {
            return Ok(());
        }
        // Loud: this means the in-memory tip and the connected chain have
        // diverged, which is silent UTXO-set corruption if it proceeds.
        tracing::error!(
            block = %connecting,
            height,
            parent = %parent_hash,
            parent_height = parent.height,
            parent_status = ?parent.status,
            "refusing to connect onto a parent this chainstate never connected"
        );
        Err(ChainError::ParentNeverConnected)
    }

    /// Check that every recent ancestor of the tip is a block this chainstate
    /// actually connected. See [`crate::chain::tip_ancestry`] for what a
    /// failure means and why an unvalidated AssumeUTXO floor is not one.
    ///
    /// Read-only. Unlike [`Self::repair_height_index`] there is nothing to
    /// repair in place: the remedy for a hole is to replay the missing blocks.
    pub fn audit_tip_ancestry(&self) -> crate::chain::tip_ancestry::TipAncestryAudit {
        crate::chain::tip_ancestry::audit_tip_ancestry(
            &*self.store,
            self.tip_hash(),
            self.tip_height(),
            crate::chain::tip_ancestry::DEFAULT_ANCESTRY_WINDOW,
            self.background().map(|bg| bg.snapshot_height()),
        )
    }

    pub fn repair_block_index_holes(&self) -> Result<RepairOutcome, ChainError> {
        use crate::storage::flatfile::FlatFilePos;
        let tip_height = self.tip_height();
        let headers_tip = self.headers_tip_height();
        let span_start = std::time::Instant::now();

        // Index walk: pass 1 — find HeaderOnly heights and track the
        // maximum DataStored/Valid height above tip, plus the
        // file_number range that those DataStored entries span.
        //
        // The heuristic: a HeaderOnly hole only matters if there's a
        // DataStored entry STRICTLY ABOVE it (height > hole.height).
        // That's the wedge signature — a hole in an already-downloaded
        // region the connector will eventually walk through.
        //
        // A HeaderOnly entry at, or above, the highest DataStored is
        // just normal IBD-in-progress (header accepted, block not yet
        // downloaded) — there is by construction no block data on
        // disk for it. Pre-filtering these out is what makes startup
        // fast in normal operation: a 130k-entry IBD frontier doesn't
        // trigger a flat-file scan.
        //
        // The file range (`min_ds_file`..=`max_ds_file`) bounds the
        // flat-file scan. Blocks at heights between `tip+1` and
        // `max_ds_height` were written to disk while we held those
        // heights in flight; arrival order is approximately, but not
        // exactly, height-ordered, so we widen the file range by the
        // min/max we actually see. Files outside that range cannot
        // contain the missing data.
        let mut all_above: Vec<(u32, BlockHash, BlockIndexEntry)> = Vec::new();
        let mut max_datastored_height: u32 = tip_height;
        let mut min_ds_file: Option<u32> = None;
        let mut max_ds_file: Option<u32> = None;
        for h in (tip_height + 1)..=headers_tip {
            let Some(hash) = self.store.get_block_hash_by_height(h) else {
                continue;
            };
            let Some(entry) = self.store.get_block_index(&hash) else {
                continue;
            };
            match entry.status {
                BlockStatus::DataStored | BlockStatus::Valid => {
                    if h > max_datastored_height {
                        max_datastored_height = h;
                    }
                    let f = entry.file_number;
                    min_ds_file = Some(min_ds_file.map_or(f, |m| m.min(f)));
                    max_ds_file = Some(max_ds_file.map_or(f, |m| m.max(f)));
                }
                BlockStatus::HeaderOnly => {
                    all_above.push((h, hash, entry));
                }
                _ => {}
            }
        }

        // Pass 2: filter HeaderOnly entries down to corruption
        // candidates — those strictly below the highest DataStored.
        let mut holes: std::collections::HashMap<BlockHash, BlockIndexEntry> =
            std::collections::HashMap::new();
        let mut ibd_frontier_skipped = 0usize;
        for (height, hash, entry) in all_above {
            if height < max_datastored_height {
                holes.insert(hash, entry);
            } else {
                ibd_frontier_skipped += 1;
            }
        }

        let mut outcome = RepairOutcome {
            holes_found: holes.len(),
            ..Default::default()
        };

        if holes.is_empty() {
            tracing::debug!(
                tip_height,
                headers_tip,
                max_datastored_height,
                ibd_frontier_skipped,
                elapsed_ms = span_start.elapsed().as_millis() as u64,
                "Block-index hole repair: no corruption holes above tip"
            );
            return Ok(outcome);
        }

        // File range scan: only walk files that contained DataStored
        // entries in the affected height range. Anything outside that
        // range can't be the block we're looking for.
        let (start_file, end_file) = match (min_ds_file, max_ds_file) {
            (Some(s), Some(e)) => (s, e),
            _ => {
                // No DataStored entries above tip (would have been
                // caught by the holes.is_empty() check, but defensive).
                return Ok(outcome);
            }
        };

        tracing::info!(
            holes = holes.len(),
            ibd_frontier_skipped,
            tip_height,
            max_datastored_height,
            file_range_start = start_file,
            file_range_end = end_file,
            "Block-index hole repair: scanning targeted flat-file range"
        );

        // Targeted flat-file scan with early termination once every
        // hole is resolved. `for_each_block_in_files` reads each file
        // sequentially; the visitor returns Break the moment `holes`
        // is empty.
        let mut repair_batch = crate::storage::StoreBatch::default();
        let mut blocks_scanned: u64 = 0;
        let scan_result = {
            let flat_files = self.flat_files.lock();
            flat_files.for_each_block_in_files(
                start_file..=end_file,
                |block_bytes, pos: FlatFilePos| {
                    blocks_scanned += 1;
                    let Ok(block) =
                        bitcoin::consensus::deserialize::<Block>(block_bytes)
                    else {
                        return std::ops::ControlFlow::Continue(());
                    };
                    let hash = block.block_hash();
                    if let Some(entry) = holes.remove(&hash) {
                        let repaired = BlockIndexEntry {
                            status: BlockStatus::DataStored,
                            file_number: pos.file_number,
                            data_pos: pos.data_pos,
                            num_tx: block.txdata.len() as u32,
                            // header, height, chainwork carry over.
                            ..entry
                        };
                        repair_batch.block_index_puts.push((hash, repaired));
                    }
                    if holes.is_empty() {
                        std::ops::ControlFlow::Break(())
                    } else {
                        std::ops::ControlFlow::Continue(())
                    }
                },
            )
        };
        if let Err(e) = scan_result {
            return Err(ChainError::FlatFile(e.to_string()));
        }

        outcome.blocks_scanned = blocks_scanned;
        outcome.repaired = repair_batch.block_index_puts.len();
        outcome.still_missing = holes.len();
        outcome.elapsed_secs = span_start.elapsed().as_secs();

        if outcome.repaired > 0 {
            self.store.write_batch(repair_batch)?;
            // Durable flush so a crash before the next periodic flush
            // doesn't lose the repair work and leave us re-scanning at
            // next startup.
            use crate::storage::Store;
            if let Err(e) = self.store.flush_durable() {
                tracing::warn!(
                    error = %e,
                    "Block-index hole repair: flush_durable failed after repair write"
                );
            }
        }

        tracing::info!(
            holes_found = outcome.holes_found,
            repaired = outcome.repaired,
            still_missing = outcome.still_missing,
            blocks_scanned = outcome.blocks_scanned,
            elapsed_secs = outcome.elapsed_secs,
            "Block-index hole repair complete"
        );

        Ok(outcome)
    }

    /// Connect a pre-processed block from the prefetch pipeline.
    ///
    /// The block has already been read from flat files, deserialized, and had
    /// context-free checks run. The main savings is skipping flat file I/O
    /// on the connect thread.
    pub fn connect_preprocessed_block(
        &self,
        pre: crate::chain::prefetch::PreprocessedBlock,
    ) -> Result<BlockHash, ChainError> {
        use crate::chain::connect_phase::ConnectPhase;
        let phases = &*self.connect_phases;
        phases.enter(ConnectPhase::EnterConnect);

        let trace_id = rand::random::<u32>();
        let _span = tracing::info_span!(
            "connect",
            trace_id = trace_id,
            height = pre.height,
            block = %pre.entry.header.block_hash()
        )
        .entered();
        // Verify parent is current tip (same check as connect_stored_block)
        let current_tip = self.tip_hash();
        if pre.entry.header.prev_blockhash != current_tip {
            phases.enter(ConnectPhase::Idle);
            return Err(ChainError::BadPrevBlock);
        }

        // Block must be in DataStored state
        if pre.entry.status != BlockStatus::DataStored {
            phases.enter(ConnectPhase::Idle);
            return Err(ChainError::Duplicate);
        }

        // The tip must be a block whose coins were actually applied, not just
        // one whose hash matches. Re-read rather than trusting `pre.parent`:
        // the prefetcher captured that entry before the parent connected, so
        // its status is stale by construction.
        //
        // "Re-read", not "read from disk": the store here is the `CoinCache`,
        // and its block-index LRU answers before the inner store does. So this
        // sees the intent of writes still buffered in the pending batch, and
        // catches a divergence that has reached disk only on the first connect
        // after a restart, or once the entry has been evicted. That is a real
        // limit on what it can detect — the startup ancestry audit is the pass
        // that reads the persisted state cold.
        if let Err(e) =
            self.require_connected_parent(&current_tip, &pre.hash, pre.height)
        {
            phases.enter(ConnectPhase::Idle);
            return Err(e);
        }

        // The identity check `connect_stored_block` performs on the record it
        // reads from the flat file. This path never reads the flat file — the
        // prefetcher hands over a decoded block — so the equivalent question
        // is whether the three things about to be committed agree: the block
        // being validated, the index entry authorizing it, and the hash the
        // tip is set to. `tip.hash = pre.hash` is otherwise written without
        // ever being reconciled against `pre.block`.
        let block_hash = pre.block.block_hash();
        if block_hash != pre.hash
            || pre.entry.header.block_hash() != pre.hash
            || pre.entry.height != pre.height
        {
            tracing::error!(
                declared = %pre.hash,
                block = %block_hash,
                entry = %pre.entry.header.block_hash(),
                declared_height = pre.height,
                entry_height = pre.entry.height,
                "preprocessed block is internally inconsistent"
            );
            phases.enter(ConnectPhase::Idle);
            return Err(ChainError::FlatFile(format!(
                "preprocessed block {}: block {block_hash}, entry {} at height {}",
                pre.hash,
                pre.entry.header.block_hash(),
                pre.entry.height
            )));
        }

        // Determine script verifier.
        // If the prefetcher pre-verified scripts for some transactions,
        // wrap the verifier to skip those (they've already been checked
        // against the same coins the connect thread will validate).
        let use_noop = self.should_skip_scripts(pre.height);
        let noop = NoopVerifier;
        let base_verifier: &dyn ScriptVerifier =
            if use_noop { &noop } else { &*self.script_verifier };

        // Connect block using the pre-fetched data.
        // Wins: flat file I/O eliminated, cache warmed, pre-verified scripts skipped.
        //
        // Speculative pre-verification: prefetch workers verify scripts using
        // the same ConsensusVerifier (cpp FFI). If all inputs still exist when
        // the connect thread resolves them, the verification result is valid
        // (coins are immutable). Shadow dispatch for pre-verified txs is
        // handled by dispatch_shadow() in connect_block.
        let pre_verified = if !pre.script_verified_txs.is_empty() {
            Some(&pre.script_verified_txs)
        } else {
            None
        };
        let batch = connect::connect_block(&connect::ConnectParams {
            replay_plan: None,
            store: &*self.store,
            block: &pre.block,
            height: pre.height,
            parent_chainwork: &pre.parent.chainwork,
            flat_pos: pre.flat_pos,
            script_verifier: base_verifier,
            median_time_past: pre.mtp,
            network: self.network,
            pre_verified_txs: pre_verified,
            num_threads: self.num_threads,
            precomputed_txids: Some(&pre.txids),
            address_index: &self.address_index,
            sp_index: &self.sp_index,
            #[cfg(feature = "block-filter-index")]
            filter_index: &self.filter_index,
            phase_tracker: Some(phases),
        })?;

        // Atomic commit
        phases.enter(ConnectPhase::WriteBatch);
        self.store.write_batch(batch)?;

        // Update in-memory tip
        phases.enter(ConnectPhase::TipWrite);
        {
            let mut tip = self.tip.write();
            tip.hash = pre.hash;
            tip.height = pre.height;
        }

        // Update MTP cache
        self.push_mtp_cache(pre.height, pre.entry.header.time);

        phases.enter(ConnectPhase::Idle);
        Ok(pre.hash)
    }

    /// Read a full block from flat file storage.
    /// Look up which block contains a transaction (requires -txindex).
    pub fn get_tx_location(&self, txid: &bitcoin::Txid) -> Option<BlockHash> {
        self.store.get_tx_location(txid)
    }

    pub fn get_block(&self, hash: &BlockHash) -> Option<Block> {
        let entry = self.store.get_block_index(hash)?;
        // HeaderOnly/Pruned entries never carry local block data. An `Invalid`
        // block (set only by `invalidate_block`) KEEPS its data on disk, and
        // both Core's `getblock` and the reorg/watch machinery — which
        // re-reads a just-disconnected block to emit `TxidUnconfirmed` — must
        // still read it; serve it as long as it actually held a block
        // (num_tx > 0; every block has at least a coinbase). A header-only
        // entry that was invalidated (num_tx == 0) has no data to read.
        match entry.status {
            BlockStatus::HeaderOnly | BlockStatus::Pruned => return None,
            BlockStatus::Invalid if entry.num_tx == 0 => return None,
            _ => {}
        }
        let pos = FlatFilePos {
            file_number: entry.file_number,
            data_pos: entry.data_pos,
        };
        // Past this point the index entry *asserts* the bytes are here: the
        // status is not `HeaderOnly`/`Pruned`, and every block has at least a
        // coinbase. So a read or deserialize failure is not "we do not have
        // this block", it is local corruption — a live entry pointing at bytes
        // that are missing, truncated, or malformed.
        //
        // The distinction is the whole of issue #533. Returning a bare `None`
        // makes corruption indistinguishable from pruning to every caller, and
        // the index runners turn that into "missing block data (pruned or
        // corrupt?)" — which is where a mainnet node sat with a block truncated
        // to 2083 of 1619761 bytes, failing the same backfill on every restart
        // with nothing in the warnings system and no operator-actionable
        // signal. `None` is still the return value, because that is what the
        // callers are built around; what changes is that the condition is now
        // *reported*.
        let data = match self.flat_files.lock().read_block(&pos) {
            Ok(data) => data,
            Err(e) => {
                self.report_corrupt_block_data(hash, &entry, &pos, &format!("read failed: {e}"));
                return None;
            }
        };
        let block: Block = match bitcoin::consensus::deserialize(&data) {
            Ok(block) => block,
            Err(e) => {
                self.report_corrupt_block_data(
                    hash,
                    &entry,
                    &pos,
                    &format!("record does not deserialize ({} bytes on disk): {e}", data.len()),
                );
                return None;
            }
        };
        // Verify the record we landed on is the block we asked for.
        //
        // The recorded offset can describe the wrong record — that is the
        // whole failure class the flat-file durability work addresses, and a
        // mis-recorded offset lands on another record's *start*, not on
        // garbage, so deserialization succeeds and returns a different block
        // under the requested hash. Without this check `getblock` serves the
        // wrong block, `block_data_readable` reports a broken entry as
        // healthy, and `getblockfrompeer` refuses to repair it.
        if block.block_hash() != *hash {
            self.report_corrupt_block_data(
                hash,
                &entry,
                &pos,
                &format!(
                    "record holds a different block ({}); the entry points at the wrong offset",
                    block.block_hash()
                ),
            );
            return None;
        }
        Some(block)
    }

    /// Report a live `block_index` entry whose block data is unusable.
    ///
    /// Reached only when the entry claims the bytes are present, so every
    /// caller of this is a genuine local-storage fault rather than a pruned or
    /// absent block. Logs at error and raises a standing warning, which is what
    /// puts it in front of an operator: `getwarnings`, the TUI, and
    /// `-alertnotify`/the alerting surface all read the warnings registry.
    ///
    /// The warning id is per block, so a node with several damaged records
    /// reports each one instead of collapsing them, and a repeat read of the
    /// same block refreshes the existing entry rather than adding another.
    /// Nothing clears these: the condition is durable until the operator
    /// repairs it with `getblockfrompeer`, and a cleared-on-next-read warning
    /// would flap.
    fn report_corrupt_block_data(
        &self,
        hash: &BlockHash,
        entry: &BlockIndexEntry,
        pos: &FlatFilePos,
        detail: &str,
    ) {
        tracing::error!(
            block = %hash,
            height = entry.height,
            file_number = pos.file_number,
            data_pos = pos.data_pos,
            detail,
            "Block data is unusable behind a live block_index entry (local corruption). \
             Repair it with: getblockfrompeer <blockhash> <peerid>"
        );
        self.warnings.record(
            &format!("blockdata.corrupt.{hash}"),
            crate::warnings::Severity::Error,
            format!(
                "Block {hash} at height {} has a block_index entry but unusable data ({detail}); \
                 repair with getblockfrompeer",
                entry.height
            ),
            serde_json::json!({
                "block": hash.to_string(),
                "height": entry.height,
                "file_number": pos.file_number,
                "data_pos": pos.data_pos,
                "detail": detail,
            }),
        );
    }

    /// Read the block at a given active-chain height. Returns `None` for
    /// heights past the tip, missing block index entries, or pruned/invalid
    /// blocks. Used by the address-index backfill runner.
    pub fn read_block_at_height(&self, height: u32) -> Option<Block> {
        let hash = self.store.get_block_hash_by_height(height)?;
        // Preserve the documented "skip invalid" contract: unlike `get_block`
        // (which serves invalidated blocks for getblock/reorg re-reads), the
        // backfill runner must never process a block that has been
        // invalidated out of the active chain.
        if self.store.get_block_index(&hash)?.status == BlockStatus::Invalid {
            return None;
        }
        self.get_block(&hash)
    }

    /// Read a block from flat files without acquiring the flat_files mutex.
    /// Safe because read_block() opens a fresh file handle each time.
    fn read_block_direct(&self, pos: &FlatFilePos) -> Option<Block> {
        let path = self.blocks_dir.join(format!("blk{:05}.dat", pos.file_number));
        let mut file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(file = %path.display(), "read_block_direct: open failed: {}", e);
                return None;
            }
        };
        use std::io::{Read, Seek, SeekFrom};
        if let Err(e) = file.seek(SeekFrom::Start(pos.data_pos as u64)) {
            tracing::warn!(file = %path.display(), pos = pos.data_pos, "read_block_direct: seek failed: {}", e);
            return None;
        }
        let mut header = [0u8; 8];
        if let Err(e) = file.read_exact(&mut header) {
            tracing::warn!(file = %path.display(), pos = pos.data_pos, "read_block_direct: header read failed: {}", e);
            return None;
        }
        crate::storage::flatfile::xor_in_place(&mut header, &self.blocks_xor_key, pos.data_pos as u64);
        let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if size == 0 || size > 4_000_000 {
            tracing::warn!(file = %path.display(), pos = pos.data_pos, size, "read_block_direct: invalid block size");
            return None;
        }
        let mut data = vec![0u8; size];
        if let Err(e) = file.read_exact(&mut data) {
            tracing::warn!(file = %path.display(), pos = pos.data_pos, size, "read_block_direct: data read failed: {}", e);
            return None;
        }
        crate::storage::flatfile::xor_in_place(&mut data, &self.blocks_xor_key, pos.data_pos as u64 + 8);
        match bitcoin::consensus::deserialize(&data) {
            Ok(block) => Some(block),
            Err(e) => {
                tracing::warn!(file = %path.display(), pos = pos.data_pos, size, "read_block_direct: deserialize failed: {}", e);
                None
            }
        }
    }

    /// Store block data to disk without connecting it to the chain.
    /// Used during parallel IBD: blocks arrive out of order and are stored
    /// immediately, then connected sequentially later.
    ///
    /// Returns `(block_hash, height)` on success.
    pub fn store_block(&self, block: &Block) -> Result<(BlockHash, u32), ChainError> {
        let block_hash = block.block_hash();

        // Check for duplicate — skip if already DataStored or Valid
        if let Some(existing) = self.store.get_block_index(&block_hash)
            && existing.status != BlockStatus::HeaderOnly
        {
            return Err(ChainError::Duplicate);
        }

        // Parent must exist as at least HeaderOnly
        let prev_hash = block.header.prev_blockhash;
        let parent = self
            .store
            .get_block_index(&prev_hash)
            .ok_or(ChainError::BadPrevBlock)?;

        // Never store a block descending from an explicitly-invalidated one
        // (Core: "bad-prevblk"). Keeps the invalidated subtree from being
        // re-populated with data behind the operator's back.
        if parent.status == BlockStatus::Invalid {
            return Err(ChainError::BadPrevBlock);
        }

        let new_height = parent.height + 1;

        // Structural + witness block validation
        validation::block::check_block(block, self.network, new_height)?;

        // PoW validation
        validation::pow::check_proof_of_work(&block.header)?;

        // Difficulty check
        let store_ref = &*self.store;
        validation::pow::check_difficulty(
            &block.header,
            &parent,
            self.network,
            |h| {
                let hash = store_ref.get_block_hash_by_height(h)?;
                store_ref.get_block_index(&hash)
            },
            |h| store_ref.get_block_index(h),
        )?;

        // Signet block-solution check (BIP 325), custom signet only.
        self.check_signet_solution(block)?;

        // Checkpoint validation
        if self.enforce_checkpoints
            && !checkpoints::check_against_checkpoints(new_height, &block_hash, &self.checkpoints)
        {
            return Err(ChainError::CheckpointMismatch(new_height));
        }

        // Write raw block to flat file, durably enough that the index entry
        // below can never outlive the bytes it points at.
        let block_data = serialize(block);
        let flat_pos = self.write_block_durable(&block_data)?;

        // Store block index entry as DataStored
        let chainwork = add_u256(&parent.chainwork, &work_for_bits(block.header.bits));
        let entry = BlockIndexEntry {
            header: block.header,
            height: new_height,
            status: BlockStatus::DataStored,
            num_tx: block.txdata.len() as u32,
            file_number: flat_pos.file_number,
            data_pos: flat_pos.data_pos,
            chainwork,
        };

        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((block_hash, entry));
        // Write height_hash so the forward connect loop can find this block even
        // if accept_headers was never called (e.g. crash-resume or out-of-order
        // sync). Same active-chain rule as header acceptance: only ABOVE the
        // active tip. The IBD connect loop only ever reads height_hash forward
        // (tip+1, tip+2, …), so a stored block below the tip is a competing-fork
        // block we must not let clobber the active-chain entry there — the same
        // bad-cb-height pollution, reached through the block-store door. The
        // block stays reachable by hash for the competing-chain pull.
        //
        // The above-tip test and the write are atomic w.r.t. block connection:
        // hold `accept_lock` so a concurrent `accept_block` (submitblock /
        // internal mine) can't advance the tip onto this height between the test
        // and the commit. (This path runs on the single P2P block thread, which
        // does not otherwise hold the lock, so the acquisition is uncontended on
        // the normal IBD path and contends only with a racing RPC submit.)
        {
            let _accept_guard = self.accept_lock.lock();
            if new_height > self.tip_height() {
                batch.height_hash_puts.push((new_height, block_hash));
            }
            self.store.write_batch(batch)?;
        }

        Ok((block_hash, new_height))
    }

    /// Whether this block's stored bytes can actually be read back.
    ///
    /// Distinct from the `block_index` status: a `DataStored`/`Valid` entry
    /// asserts that data was written, but the record it points at can be
    /// truncated or unreadable (see [`Self::write_block_durable`]). Callers
    /// deciding whether a block needs re-fetching must ask this, not the
    /// status flag.
    pub fn block_data_readable(&self, hash: &BlockHash) -> bool {
        self.get_block(hash).is_some()
    }

    /// Gate for [`Self::repair_block_data`]: only an entry that claims to hold
    /// data is a repairable hole. See that function's docs for why
    /// `HeaderOnly`, `Pruned` and `Invalid` are each refused.
    fn check_repairable(hash: &BlockHash, entry: &BlockIndexEntry) -> Result<(), ChainError> {
        match entry.status {
            BlockStatus::DataStored | BlockStatus::Valid => Ok(()),
            BlockStatus::HeaderOnly => Err(ChainError::InvalidArgument(format!(
                "block {hash} at height {} is header-only, not a data hole; \
                 it must be downloaded through the normal block path so the \
                 checkpoint, signet and invalidated-parent checks apply",
                entry.height
            ))),
            BlockStatus::Pruned => Err(ChainError::InvalidArgument(format!(
                "block {hash} at height {} is pruned; refusing to repopulate \
                 data the prune accounting no longer tracks",
                entry.height
            ))),
            BlockStatus::Invalid => Err(ChainError::InvalidArgument(format!(
                "block {hash} at height {} is marked invalid; refusing to \
                 write data for it",
                entry.height
            ))),
        }
    }

    /// Rewrite the on-disk copy of a block whose data is missing or
    /// unreadable, repointing its `block_index` entry at the new record.
    ///
    /// This is the recovery half of the durability hole
    /// [`Self::write_block_durable`] closes: an index entry that outlived the
    /// bytes it referenced leaves the node with no way to serve, re-read, or
    /// backfill over that height, and until now no way to fix it short of a
    /// full resync. `block` is an untrusted copy supplied by a peer (see
    /// `getblockfrompeer`).
    ///
    /// Authentication chain, given that we look the entry up *by the hash of
    /// the block we were handed*:
    /// - the hash matching a `block_index` entry means the header is one we
    ///   already accepted (PoW, difficulty, and checkpoints checked then);
    /// - the block hash commits to the merkle root, and
    ///   [`validation::block::check_block`] ties the txdata to that root,
    ///   rejects CVE-2012-2459 mutation, and — the part that matters here —
    ///   applies the BIP 141 witness rules, which pin the witness bytes the
    ///   block hash does not cover (a stripped, padded, or truncated coinbase
    ///   witness is refused, as is a witness-stripped copy that presents as
    ///   witness-free).
    ///
    /// So a peer can only supply the genuine block or be rejected. Status is
    /// preserved exactly: a `Valid` block stays `Valid` (its UTXO delta was
    /// applied long ago and is not revisited).
    ///
    /// **Only `DataStored`/`Valid` entries are repairable.** This function
    /// exists for one narrow job — an entry that claims to hold data whose
    /// record is gone — and deliberately refuses everything else:
    ///
    /// - `HeaderOnly` is not a hole, it is a block we never fetched. It must
    ///   go through `store_block`, which applies the checkpoint and signet
    ///   block-solution checks and the invalidated-parent refusal that
    ///   `accept_header` does not, writes the `height_hash` row, and wakes the
    ///   connect machinery. Filling it in here would store data for a block
    ///   contradicting a checkpoint, or under an operator-invalidated parent,
    ///   and would then leave it `DataStored` but unconnected.
    /// - `Pruned` and `Invalid` are deliberate decisions — operator pruning or
    ///   a consensus/operator rejection — and silently repopulating them would
    ///   contradict the decision that produced them (and, for `Pruned`,
    ///   desynchronize the prune accounting).
    pub fn repair_block_data(&self, block: &Block) -> Result<BlockDataRepair, ChainError> {
        let hash = block.block_hash();
        let entry = self
            .store
            .get_block_index(&hash)
            .ok_or(ChainError::BlockNotFound)?;

        Self::check_repairable(&hash, &entry)?;

        // The height this block is judged at gates a consensus rule (segwit
        // activation), so take it from the block's own parent link rather than
        // from the entry alone. `prev_blockhash` is inside the 80 bytes the
        // block hash commits to, and the hash is how we found `entry` — so the
        // link is authenticated, while `entry.height` is index state of the
        // very index this function exists to repair. The two must agree: a
        // disagreement means the index is inconsistent, and writing block
        // bytes on the strength of it is exactly what not to do. Refuse, and
        // deliberately NOT as `ChainError::Validation` — the peer is not at
        // fault and must not be banned for our damaged index.
        let parent_height = self
            .store
            .get_block_index(&block.header.prev_blockhash)
            .ok_or(ChainError::BadPrevBlock)?
            .height;
        let height = parent_height + 1;
        if height != entry.height {
            return Err(ChainError::InvalidArgument(format!(
                "block {hash}: index entry says height {} but its parent chain says {height}; \
                 refusing to repair against an inconsistent index",
                entry.height
            )));
        }

        // The P2P entry point rejects mutated blocks before routing here, but
        // this is a `pub` API whose contract is "authenticate the bytes", and
        // the 64-byte-transaction merkle collision is the one way a different
        // transaction list can sit under the same merkle root. Re-check it so
        // the guarantee does not depend on the caller.
        if validation::block::is_block_mutated(
            block,
            validation::block::segwit_active_at(self.network, height),
        ) {
            return Err(ChainError::Validation(
                validation::ValidationError::BadTxDuplicate,
            ));
        }
        validation::block::check_block(block, self.network, height)?;

        // Only *now* decide whether there is anything to do. The check is
        // "are the stored bytes the canonical block", not "do they parse":
        // a copy that deserializes and hashes correctly can still be
        // non-canonical in its witnesses (nothing in the block hash covers
        // them), and short-circuiting on readability alone would make this RPC
        // unable to repair the one corruption it can actually detect.
        // Ordering it after validation also means a peer's bad bytes can never
        // displace a good stored copy — they are rejected before we look.
        if let Some(stored) = self.get_block(&hash)
            && validation::block::check_block(&stored, self.network, height).is_ok()
        {
            return Ok(BlockDataRepair::AlreadyPresent { height });
        }

        // Append the record BEFORE taking `accept_lock`. `write_block_durable`
        // takes the flat-file mutex, and `store_block` holds `accept_lock`
        // while writing its batch *after* releasing that mutex — acquiring
        // them in the other order here would invert the pairing.
        let block_data = serialize(block);
        let flat_pos = self.write_block_durable(&block_data)?;

        let _accept_guard = self.accept_lock.lock();

        // Re-read under the lock. `accept_lock` serializes this against
        // `accept_block`, `store_block`, `invalidate_block` and
        // `reconsider_block`; it does NOT exclude the connect thread, which
        // rewrites index entries without taking it. So this narrows the window
        // rather than closing it — a concurrent connect committing the entry it
        // captured earlier would still clobber the repair, and the operator's
        // recourse is to re-run the RPC.
        //
        // Two things can have changed since the checks above: a concurrent
        // accept may have supplied this block's data (then leave its entry
        // alone — our record simply becomes flat-file slack), or the entry may
        // have been invalidated or pruned (then the refusal above applies, and
        // must not be bypassed by having already written the record).
        let entry = self
            .store
            .get_block_index(&hash)
            .ok_or(ChainError::BlockNotFound)?;
        Self::check_repairable(&hash, &entry)?;
        // Same "canonical, not merely readable" test as above — a concurrent
        // writer may have landed a good copy while we were validating, but a
        // parse-able bad one is still a hole.
        if let Some(stored) = self.get_block(&hash)
            && validation::block::check_block(&stored, self.network, height).is_ok()
        {
            return Ok(BlockDataRepair::AlreadyPresent { height });
        }
        // The entry was re-read under the lock, so re-confirm the height the
        // validation above was gated on still describes it.
        if entry.height != height {
            return Err(ChainError::InvalidArgument(format!(
                "block {hash}: height changed from {height} to {} while repairing",
                entry.height
            )));
        }

        let mut repaired = entry;
        repaired.file_number = flat_pos.file_number;
        repaired.data_pos = flat_pos.data_pos;
        // Re-derived from a merkle-authenticated body, so this cannot drift
        // from the truth; `status` is left exactly as it was.
        repaired.num_tx = block.txdata.len() as u32;

        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((hash, repaired));
        self.store.write_batch(batch)?;

        tracing::info!(
            %hash,
            height,
            file_number = flat_pos.file_number,
            data_pos = flat_pos.data_pos,
            "Repaired block data from a peer-supplied copy"
        );

        Ok(BlockDataRepair::Repaired {
            height,
        })
    }

    /// Connect an already-stored block (DataStored) to the chain tip.
    /// The block's parent must be the current chain tip.
    ///
    /// Returns the block hash on success.
    pub fn connect_stored_block(&self, hash: &BlockHash) -> Result<BlockHash, ChainError> {
        let entry = self
            .store
            .get_block_index(hash)
            .ok_or(ChainError::BadPrevBlock)?;
        use crate::chain::connect_phase::ConnectPhase;
        let phases = &*self.connect_phases;
        phases.enter(ConnectPhase::EnterConnect);
        let trace_id = rand::random::<u32>();
        let _span = tracing::info_span!(
            "connect_stored",
            trace_id = trace_id,
            height = entry.height,
            block = %hash
        )
        .entered();

        if entry.status != BlockStatus::DataStored {
            phases.enter(ConnectPhase::Idle);
            return Err(ChainError::Duplicate);
        }

        // Parent must be current tip (sequential connection)
        let current_tip = self.tip_hash();
        if entry.header.prev_blockhash != current_tip {
            phases.enter(ConnectPhase::Idle);
            return Err(ChainError::BadPrevBlock);
        }

        // Read block from flat file (mutex-free)
        let flat_pos = FlatFilePos {
            file_number: entry.file_number,
            data_pos: entry.data_pos,
        };
        let block = self
            .read_block_direct(&flat_pos)
            .ok_or(ChainError::FlatFile("failed to read stored block".to_string()))?;
        // Verify the record is the block the entry claims, exactly as
        // `get_block` and the reindex paths (`require_planned_block`) do. A
        // mis-recorded offset lands on another record's *start*, not on
        // garbage, so deserialization succeeds and hands back a different
        // block — and here that block would be connected: a sibling at the
        // same height with the same parent can validate, after which
        // `connect_block` writes `height_hash[h]` and `block_index` for the
        // sibling while this function sets the in-memory tip to `hash`.
        if block.block_hash() != *hash {
            tracing::error!(
                %hash,
                found = %block.block_hash(),
                height = entry.height,
                file_number = flat_pos.file_number,
                data_pos = flat_pos.data_pos,
                "block index entry points at a different block's record"
            );
            return Err(ChainError::FlatFile(format!(
                "block {hash}: stored record holds {} instead",
                block.block_hash()
            )));
        }

        let parent = self
            .store
            .get_block_index(&entry.header.prev_blockhash)
            .ok_or(ChainError::BadPrevBlock)?;
        // Matching the prev hash pins the chain's shape but not that the
        // parent's coins were ever applied. See `require_connected_parent`.
        // Return the tracker to Idle like the other early exits: the connector
        // parks in its retry condvar after this, and a tracker left in
        // `EnterConnect` makes the stall watchdog's forensics dump blame a
        // phase nothing is executing.
        if let Err(e) = self.require_connected_parent(&current_tip, hash, entry.height) {
            phases.enter(ConnectPhase::Idle);
            return Err(e);
        }

        // Determine script verifier
        let use_noop = self.should_skip_scripts(entry.height);
        let noop = NoopVerifier;
        let verifier: &dyn ScriptVerifier = if use_noop { &noop } else { &*self.script_verifier };

        // Connect block
        let mtp = self.get_median_time_past(entry.height);
        let batch = connect::connect_block(&connect::ConnectParams {
            replay_plan: None,
            store: &*self.store,
            block: &block,
            height: entry.height,
            parent_chainwork: &parent.chainwork,
            flat_pos,
            script_verifier: verifier,
            median_time_past: mtp,
            network: self.network,
            pre_verified_txs: None,
            num_threads: self.num_threads,
            precomputed_txids: None,
            address_index: &self.address_index,
            sp_index: &self.sp_index,
            #[cfg(feature = "block-filter-index")]
            filter_index: &self.filter_index,
            phase_tracker: Some(phases),
        })?;

        // Atomic commit
        phases.enter(ConnectPhase::WriteBatch);
        self.store.write_batch(batch)?;

        // Update in-memory tip
        phases.enter(ConnectPhase::TipWrite);
        {
            let mut tip = self.tip.write();
            tip.hash = *hash;
            tip.height = entry.height;
        }

        // Update MTP cache with this block's timestamp
        self.push_mtp_cache(entry.height, entry.header.time);

        phases.enter(ConnectPhase::Idle);
        Ok(*hash)
    }

    /// Rebuild the UTXO set by replaying all blocks from flat files.
    /// Block index and flat files must be intact. Used by `-reindex-chainstate`.
    ///
    /// `stop_at` matches the `-stopatheight` flag: when set, replay halts
    /// cleanly after connecting that height (subsequent heights in the
    /// block index are left for a future run). This is the load-bearing
    /// `-stopatheight` check for reindex — the chain-event watcher used
    /// by the normal IBD path is not yet wired at reindex time, so it
    /// cannot stop reindex on its own.
    ///
    /// `progress` (if provided) receives total / current / stop_height
    /// updates so the startup RPC can render a gauge that distinguishes
    /// the file tip (total) from the configured stop target.
    /// `prev_tip` is the tip the chainstate was on before it was cleared —
    /// hash and height, read from the metadata column family by the caller
    /// before clearing. The height is a floor the replay must reach or it
    /// fails closed; the hash is the tie-break incumbent. Both must come from
    /// authoritative state: see the note on `incumbent` below for what
    /// happened when the hash was re-derived from the height→hash index.
    ///
    /// `satd` additionally runs the same coverage check *before* clearing, so
    /// a datadir that cannot be rebuilt is rejected with the chainstate still
    /// intact. The check here is defence in depth and covers other callers.
    pub fn reindex_chainstate(
        &self,
        stop_at: Option<u32>,
        progress: Option<Arc<crate::startup_progress::StartupProgress>>,
        prev_tip: Option<(BlockHash, u32)>,
    ) -> Result<(), ChainError> {
        // Decide which chain to replay before touching anything. Selecting by
        // chainwork over the block index, rather than walking the height→hash
        // index, is what keeps a polluted index from splicing two branches into
        // one chainstate — see `chain::replay_plan`.
        //
        // Flush first: `for_each_block_index` reads through the coin cache to
        // the backing store, so an entry still sitting in the dirty cache would
        // be invisible to the scan and its branch silently excluded. At startup
        // (the only caller) the cache is empty and this is a no-op; it is here
        // so the planner's view can never be a partial one.
        self.store.flush()?;
        let genesis_hash = bitcoin::constants::genesis_block(self.network).block_hash();
        // The pre-clear tip doubles as the tie-break incumbent: on an exact
        // chainwork tie the branch the node was already on wins, matching the
        // consensus first-seen rule that `find_best_valid_tip` implements by
        // returning the active tip. Without it a node holding a fully-received
        // stale sibling at its tip height would, on a coin flip, rebuild onto
        // the orphan and have to be reorged back by its peers.
        //
        // The hash is passed in from the metadata CF, NOT looked up by height.
        // An earlier version did `get_block_hash_by_height(required_height)`,
        // which reintroduced a dependency on the height→hash index at the one
        // height where pollution was actually observed (#322) — and the
        // incumbent is decisive on a tie, so a polluted row handed the win to
        // the stale sibling and rebuilt the whole chainstate onto the orphan.
        // Every other input to selection is recomputed from headers precisely
        // so a damaged index cannot steer the replay; this one must be too.
        let (incumbent, required_height) = match prev_tip {
            Some((hash, height)) => (Some(hash), Some(height)),
            None => (None, None),
        };
        let plan = Arc::new(
            crate::chain::replay_plan::plan_replay_from_block_index(
                &*self.store,
                genesis_hash,
                incumbent,
            )
            .map_err(ChainError::Storage)?,
        );
        // Say which chain was selected — see the equivalent line on the
        // flat-file path for why this is not optional.
        tracing::info!(
            tip = %plan.tip_hash(),
            tip_height = plan.tip_height(),
            incumbent = ?incumbent.map(|h| h.to_string()),
            "Chainstate reindex: selected the most-work branch to replay"
        );

        // Fail closed when the block index cannot produce the chain the node
        // already had. Selection admits only `DataStored`/`Valid` blocks and
        // requires every ancestor to qualify, so one ineligible block low in
        // the chain truncates the plan — or empties it. A pruned node is the
        // guaranteed case: every block below the prune horizon is `Pruned`, so
        // nothing resolves and the plan is genesis alone. Reporting success
        // there would leave the node serving height 0 with an empty UTXO set,
        // while `clear_chainstate` has already stamped the tx and address
        // indexes complete — so Electrum and Esplora would answer "no history"
        // for every address. Before this check the replay did exactly that;
        // the pre-plan code failed loudly instead, on the unreadable block.
        if let Some(required) = required_height
            && plan.tip_height() < required
        {
            tracing::error!(
                required,
                planned = plan.tip_height(),
                "reindex: the block index has no fully-connectable chain reaching the height \
                 the chainstate was already at. This datadir cannot be rebuilt with \
                 --reindex-chainstate — a pruned range or a hole in the block index breaks the \
                 ancestry. Run a full --reindex to rebuild the block index from the block files."
            );
            return Err(ChainError::BadPrevBlock);
        }

        // The replay starts at genesis or not at all.
        //
        // A partial chainstate used to be resumed when it sat on the selected
        // branch. That is what makes this replay's central safety property
        // conditional, so it is no longer allowed.
        //
        // The property: every block this replay connects has its indexed header
        // checked against the block file before anything reads it
        // (`require_planned_block`), and everything the replay derives from an
        // indexed header — the parent link, the chainwork, and the timestamps
        // that MTP is the median of — is therefore backed by the block files.
        // That argument is inductive, and it only closes if the run starts at
        // genesis. Resume punches an unbounded hole in it: BIP68 evaluates a
        // spent coin's MTP at the coin's *creation* height, which can be
        // anywhere in history, so a resumed run reads timestamps out of index
        // entries that neither it nor anything else ever reconciled. Verifying
        // them is not bounded work — a coin spent at the tip can be older than
        // any window — and reading the whole chain back to check costs more
        // than replaying it.
        //
        // Nothing is lost. `main.rs` calls `clear_chainstate()` immediately
        // before this on every `-reindex-chainstate` run, so the daemon has
        // always started from genesis; a crashed replay re-run through the flag
        // is cleared and restarted, not resumed. This makes that the rule
        // rather than a coincidence of the caller.
        let resume_height = self.tip_height();
        if resume_height > 0 {
            tracing::error!(
                height = resume_height,
                chain_tip = %self.tip_hash(),
                "reindex: refusing to resume a partially-replayed chainstate. The UTXO set \
                 must be cleared first so the replay starts at genesis — every block it \
                 connects is verified against the block files, and resuming would validate \
                 the blocks above the resume point against index entries below it that \
                 nothing checked. Re-run -reindex-chainstate (which clears it), or run a \
                 full --reindex to rebuild the block index from the block files."
            );
            return Err(ChainError::BadPrevBlock);
        }

        if let Some(p) = &progress {
            p.set_total(plan.tip_height() as u64);
            p.set_stop_height(stop_at.map(|h| h as u64));
        }

        // Pipeline the replay like the IBD connect loop. A plain serial
        // read->connect->write loop leaves both CPU and disk idle between
        // blocks: each iteration waits on a flat-file read, then UTXO
        // lookups, then a WAL'd write, with nothing overlapping. Instead we
        // enter BulkLoad (WAL off) and run the prefetcher so worker threads
        // read, deserialize, hash txids, warm the UTXO cache (and, in
        // assumevalid mode, speculatively verify scripts) for blocks AHEAD
        // of the connect cursor. Normal write mode + a durable flush are
        // restored on EVERY exit path (including the `?` error paths in the
        // inner replay), so BulkLoad semantics never leak into steady state.
        self.set_write_mode(crate::storage::WriteMode::BulkLoad);
        let result = self.reindex_replay(plan, stop_at, progress);
        let flush_result = self.flush_durable();
        self.set_write_mode(crate::storage::WriteMode::Normal);
        if let Err(e) = flush_result {
            tracing::error!(
                error = %e,
                "reindex: durable flush on exit failed; the replayed chainstate is NOT \
                 durable (WAL-less writes may still be memtable-only). Failing the \
                 reindex rather than reporting a completion the disk cannot back."
            );
            // Fail closed: a reindex that "completed" without a durable
            // checkpoint reports success while the tail of its writes can
            // vanish on exit — the exact shape of the 952914-rollback bug.
            return result.and(Err(ChainError::Storage(e)));
        }
        result
    }

    /// Inner replay loop for [`Self::reindex_chainstate`]. Runs under
    /// BulkLoad with the prefetch pipeline; the caller restores Normal write
    /// mode regardless of how this returns.
    fn reindex_replay(
        &self,
        plan: Arc<crate::chain::replay_plan::ReplayPlan>,
        stop_at: Option<u32>,
        progress: Option<Arc<crate::startup_progress::StartupProgress>>,
    ) -> Result<(), ChainError> {
        // Periodic durable checkpoint cadence. The dirty-cache threshold
        // (see `flush_threshold`) handles memory pressure; this bounds the
        // replay window on a crash/OOM so progress sticks. 1000 mirrors the
        // production IBD connect loop.
        const DURABLE_FLUSH_EVERY: u32 = 1000;

        let start_height = self.tip_height() + 1; // genesis already connected
        self.verify_replay_mtp_window(&plan, start_height)?;
        let workers = self.num_threads.max(1);
        let prefetch = crate::chain::prefetch::start_prefetcher(
            self.store_ref().clone() as Arc<dyn crate::storage::Store + Send + Sync>,
            self.blocks_dir().to_path_buf(),
            self.blocks_xor_key,
            Some(plan.clone()),
            start_height,
            workers,
            128, // lookahead blocks, matching the IBD connect loop
            self.is_assumevalid_active(),
            self.primary_engine(),
            self.network,
        );

        // Weight-aware ETA over the replay, reused from the IBD connect loop.
        // The replay is the same per-block cost profile as IBD, so the cost
        // weights apply directly. Target the configured `-stopatheight` when
        // set — the loop below exits there, so an ETA to the full file tip
        // would be materially inflated.
        // Clamp like the flat-file path: a `-stopatheight` above the plan tip
        // would aim the progress gauge and ETA at a height the replay cannot
        // reach, so neither ever converges.
        let target_height = stop_at
            .map(|h| h.min(plan.tip_height()))
            .unwrap_or_else(|| plan.tip_height());
        let mut eta_est = crate::ibd_eta::IbdEtaEstimator::new(
            start_height,
            target_height,
            self.network == Network::Bitcoin,
        );
        let mut interval_start = std::time::Instant::now();
        let mut last_interval: u32 = start_height / 1000;
        if let Some(p) = &progress {
            // Switch to driver-controlled ETA immediately and suppress the
            // linear fallback: with ~50x cost variation across history a
            // naive remaining/rate ETA is meaningless here.
            p.set_eta(None);
        }

        // Run the replay in an inner closure so the prefetch workers are
        // ALWAYS shut down afterward — including on the `?` error paths. A
        // bare early return (connect failure, flat-file read failure, a
        // flush error, etc.) would drop the handle without setting shutdown
        // or joining, leaving detached workers reading the store/block files
        // after a failed reindex.
        let result = (|| -> Result<(), ChainError> {
            let mut height = start_height;
            while let Some(hash) = plan.hash_at(height) {
                // Prefer the prefetched, pre-processed block; fall back to a
                // direct read on a miss (cold start, or a worker behind the
                // cursor). Both paths connect via `connect_block` directly,
                // bypassing the `DataStored` precondition the IBD connect
                // methods enforce — after `clear_chainstate` the block-index
                // entries are still `Valid` from the original sync.
                match prefetch.take_block(height) {
                    Some(pre) if pre.hash == hash => self.reindex_connect_prefetched(&plan, pre)?,
                    _ => self.reindex_connect_direct(&plan, height, hash)?,
                }
                prefetch.advance_cursor(height + 1);
                self.bump_connect_heartbeat();

                // Emit a chain event so subscribers see reindex progress as
                // they would IBD. No-op when the broadcaster isn't wired yet
                // (the normal `-reindex-chainstate` startup case).
                self.emit_chain_event(crate::chain::events::ChainEvent::BlockConnected {
                    hash,
                    height,
                });

                // Bound memory: drain the in-memory dirty set to RocksDB when
                // it crosses the threshold (a full reindex once hit 122 GiB
                // RSS at ~block 430k before the OOM killer fired).
                if self.store.dirty_count() > self.store.flush_threshold() {
                    self.store.flush()?;
                }

                if height.is_multiple_of(DURABLE_FLUSH_EVERY) {
                    self.store.flush()?;
                    self.store.flush_durable()?;
                }

                // Feed the ETA estimator one observation per 1000-block
                // interval.
                let cur_interval = height / 1000;
                if cur_interval > last_interval {
                    let secs = interval_start.elapsed().as_secs_f64();
                    let spans = (cur_interval - last_interval) as f64;
                    eta_est.record_interval(cur_interval * 1000, secs / spans);
                    interval_start = std::time::Instant::now();
                    last_interval = cur_interval;
                }

                if let Some(p) = &progress
                    && height.is_multiple_of(100)
                {
                    p.set_current(height as u64);
                    p.set_eta(eta_est.estimate_eta(height, target_height));
                }

                if height.is_multiple_of(10_000) {
                    tracing::info!(height, "Reindexing chainstate...");
                }

                // Honor `-stopatheight`: exit after the targeted height is
                // durable. Subsequent heights, if present in the block index,
                // are left for a follow-up run (no chainstate rollback).
                if let Some(target) = stop_at
                    && height >= target
                {
                    if let Some(p) = &progress {
                        p.set_current(height as u64);
                    }
                    tracing::info!(
                        height,
                        target,
                        "Reached -stopatheight during chainstate reindex; exiting"
                    );
                    self.store.flush()?;
                    self.store.flush_durable()?;
                    return Ok(());
                }

                height += 1;
            }
            // Final flush so the reindexed tip is durable before we return.
            self.store.flush()?;
            self.store.flush_durable()?;
            if let Some(p) = &progress {
                p.set_current((height - 1) as u64);
            }
            tracing::info!(height = height - 1, "Chainstate reindex complete");
            Ok(())
        })();

        // Always join the prefetch workers, whether the replay succeeded,
        // hit `-stopatheight`, or errored out.
        prefetch.stop();
        result
    }

    /// Fail closed unless `header` extends the block the chainstate currently
    /// ends at.
    ///
    /// The one invariant every replay loop depends on: `connect_block` applies
    /// a UTXO delta computed against the *current* set, so handing it a block
    /// from a different branch either aborts on an already-spent input
    /// (`bad-txns-inputs-missingorspent`) or — when the branches happen not to
    /// conflict — silently commits a UTXO set that no longer matches
    /// consensus. `connect_stored_block` has always enforced this on the IBD
    /// path; the reindex paths did not, and both ways of picking the next
    /// block to replay have gone wrong in production:
    ///
    ///   * `-reindex` connected every genesis-reachable block, side chains
    ///     included, and died at mainnet 916308 (the first fork point on
    ///     disk);
    ///   * `-reindex-chainstate` selects by height→hash, which is derived
    ///     state that has been observed polluted with a fork block (#322, and
    ///     the `bad-cb-height` reindex loop that followed it).
    ///
    /// So the check is on the connect, not on any one selection strategy: a
    /// future bug in either picker surfaces here, loudly, before it can touch
    /// the UTXO set.
    fn require_extends_tip(
        &self,
        header: &bitcoin::block::Header,
        height: u32,
    ) -> Result<(), ChainError> {
        let tip = self.tip_hash();
        if header.prev_blockhash != tip {
            tracing::error!(
                height,
                block = %header.block_hash(),
                parent = %header.prev_blockhash,
                chain_tip = %tip,
                "reindex: refusing to connect a block that does not extend the \
                 replayed chain — it belongs to a different branch"
            );
            return Err(ChainError::BadPrevBlock);
        }
        Ok(())
    }

    /// The bytes read at `flat_pos` must be the block the plan selected.
    ///
    /// `flat_pos` comes from the block index, and a damaged block index is the
    /// thing `-reindex-chainstate` is run to repair — so the position can point
    /// at a different, perfectly well-formed record. Nothing downstream would
    /// notice. `connect_block` derives everything from the block it is handed
    /// and writes *that* block's hash, height row and UTXO delta, while the
    /// caller sets the in-memory tip to the *plan's* hash. The next
    /// `require_extends_tip` compares against that in-memory tip and passes, so
    /// the replay runs to completion with the persisted chainstate and the
    /// in-memory tip naming different blocks.
    ///
    /// `require_extends_tip` does not subsume this. On the prefetched path it
    /// sees the real block's header, so the wrong record must at least be a
    /// child of the current tip — but a stale sibling of the planned block is
    /// exactly that, and it is the shape corruption actually takes here. On the
    /// direct path it sees the *index's* header for the planned hash, which
    /// extends the chain by construction, so it constrains nothing at all.
    /// `indexed` is the header stored under `planned` in the block index. It
    /// must equal the header of the block actually on disk. `get_block_index`
    /// keys on the hash, but nothing constrains the stored header to be the one
    /// that hashes to that key — so an index damaged in the header bytes can
    /// name a parent the block does not have, and both replay paths take the
    /// parent (and therefore the cumulative chainwork) from that link.
    fn require_planned_block(
        &self,
        height: u32,
        planned: BlockHash,
        block: &Block,
        indexed: &bitcoin::block::Header,
        flat_pos: FlatFilePos,
    ) -> Result<(), ChainError> {
        let found = block.block_hash();
        if found != planned {
            tracing::error!(
                height,
                expected = %planned,
                found = %found,
                file_number = flat_pos.file_number,
                data_pos = flat_pos.data_pos,
                "reindex: the block index points at the wrong record; the index is corrupt. \
                 Run a full --reindex to rebuild it from the block files."
            );
            return Err(ChainError::BadPrevBlock);
        }
        if *indexed != block.header {
            tracing::error!(
                height,
                block = %planned,
                indexed_parent = %indexed.prev_blockhash,
                actual_parent = %block.header.prev_blockhash,
                "reindex: the block index holds a header that is not the one in the block \
                 file; the index is corrupt. Run a full --reindex to rebuild it from the \
                 block files."
            );
            return Err(ChainError::BadPrevBlock);
        }
        Ok(())
    }

    /// Verify the index headers that the first blocks' MTP will be computed
    /// from — in practice, genesis.
    ///
    /// Every block a replay connects has its indexed header checked against the
    /// block file before anything reads it (`require_planned_block`), and MTP
    /// reads timestamps out of those same indexed headers, so induction covers
    /// the whole run: an ancestor with a forged timestamp fails its own connect
    /// first. The induction needs a base case, and genesis is it — the replay
    /// starts *above* genesis, so its entry is the one header MTP consumes that
    /// no connect ever validates. Compared against the network constant.
    ///
    /// The loop generalizes to a start above genesis, which the resume refusal
    /// in `reindex_chainstate` currently rules out; it stays here so a future
    /// change that relaxes that does not silently reopen the hole.
    fn verify_replay_mtp_window(
        &self,
        plan: &crate::chain::replay_plan::ReplayPlan,
        start_height: u32,
    ) -> Result<(), ChainError> {
        for h in start_height.saturating_sub(11)..start_height {
            let Some(hash) = plan.hash_at(h) else {
                continue;
            };
            let entry = self.store.get_block_index(&hash).ok_or_else(|| {
                tracing::error!(height = h, block = %hash, "reindex: no block index entry for a block in the MTP window");
                ChainError::BadPrevBlock
            })?;
            if h == 0 {
                // Genesis has no flat-file record to compare against on every
                // datadir; the constant is the authority.
                let genesis = bitcoin::constants::genesis_block(self.network);
                if entry.header != genesis.header {
                    tracing::error!(
                        block = %hash,
                        "reindex: the block index holds a genesis header that is not this                          network's genesis. Run a full --reindex."
                    );
                    return Err(ChainError::BadPrevBlock);
                }
                continue;
            }
            let flat_pos = FlatFilePos {
                file_number: entry.file_number,
                data_pos: entry.data_pos,
            };
            let block = self.read_block_direct(&flat_pos).ok_or_else(|| {
                tracing::error!(
                    height = h,
                    block = %hash,
                    file_number = flat_pos.file_number,
                    data_pos = flat_pos.data_pos,
                    "reindex: cannot read a block in the MTP window from the flat files"
                );
                ChainError::FlatFile("cannot read MTP-window block during reindex".into())
            })?;
            self.require_planned_block(h, hash, &block, &entry.header, flat_pos)?;
        }
        Ok(())
    }

    /// Connect a prefetched, pre-processed block during reindex. Reuses the
    /// prefetcher's deserialized block, precomputed txids, and (in
    /// assumevalid mode) speculatively pre-verified scripts. Does NOT check
    /// `entry.status` — reindex replays `Valid` entries (see `reindex_replay`).
    fn reindex_connect_prefetched(
        &self,
        plan: &crate::chain::replay_plan::ReplayPlan,
        pre: crate::chain::prefetch::PreprocessedBlock,
    ) -> Result<(), ChainError> {
        // The prefetch worker labels the block with the hash the plan asked
        // for, not one derived from the bytes it read (see
        // `prefetch::preprocess_block`), so this is the only place the two can
        // be reconciled — and this is the path that carries the replay. The
        // direct read below is just the prefetch-miss fallback.
        // `pre.parent` was resolved by the worker from `pre.entry.header`, so
        // the header-agreement half of this check is what makes that parent —
        // and the chainwork taken from it — trustworthy.
        self.require_planned_block(
            pre.height,
            pre.hash,
            &pre.block,
            &pre.entry.header,
            pre.flat_pos,
        )?;
        self.require_extends_tip(&pre.block.header, pre.height)?;
        // Normally already done by the prefetch worker, off this thread.
        if !pre.context_free_checked {
            validation::block::check_block(&pre.block, self.network, pre.height)?;
        }
        let use_noop = self.should_skip_scripts(pre.height);
        let noop = NoopVerifier;
        let verifier: &dyn ScriptVerifier =
            if use_noop { &noop } else { &*self.script_verifier };
        let pre_verified = if pre.script_verified_txs.is_empty() {
            None
        } else {
            Some(&pre.script_verified_txs)
        };
        let batch = connect::connect_block(&connect::ConnectParams {
            replay_plan: Some(plan),
            store: &*self.store,
            block: &pre.block,
            height: pre.height,
            parent_chainwork: &pre.parent.chainwork,
            flat_pos: pre.flat_pos,
            script_verifier: verifier,
            median_time_past: pre.mtp,
            network: self.network,
            pre_verified_txs: pre_verified,
            num_threads: self.num_threads,
            precomputed_txids: Some(&pre.txids),
            address_index: &self.address_index,
            sp_index: &self.sp_index,
            #[cfg(feature = "block-filter-index")]
            filter_index: &self.filter_index,
            phase_tracker: None,
        })?;
        self.store.write_batch(batch)?;
        let mut tip = self.tip.write();
        tip.hash = pre.hash;
        tip.height = pre.height;
        Ok(())
    }

    /// Connect a block during reindex by reading it directly from the flat
    /// files (prefetch miss). Same connect path as
    /// [`Self::reindex_connect_prefetched`], minus the prefetched extras.
    ///
    /// Takes the plan because MTP must be resolved through it, not through the
    /// height→hash index — see the `mtp` binding below.
    fn reindex_connect_direct(
        &self,
        plan: &crate::chain::replay_plan::ReplayPlan,
        height: u32,
        hash: BlockHash,
    ) -> Result<(), ChainError> {
        let entry = self
            .store
            .get_block_index(&hash)
            .ok_or(ChainError::BadPrevBlock)?;
        let flat_pos = FlatFilePos {
            file_number: entry.file_number,
            data_pos: entry.data_pos,
        };
        let block = self.read_block_direct(&flat_pos).ok_or_else(|| {
            tracing::error!(
                height,
                block = %hash,
                file_number = flat_pos.file_number,
                data_pos = flat_pos.data_pos,
                "reindex: cannot read block from the flat files"
            );
            ChainError::FlatFile("cannot read block during reindex".into())
        })?;
        // Validate the record BEFORE anything reads a header, then work from
        // `block.header` alone. The indexed header was the sole input to the
        // extends-tip guard and the parent lookup, and it is not trustworthy
        // here: `get_block_index` keys on the hash but nothing constrains the
        // stored header to be the one that hashes to that key, so an index
        // damaged in the header bytes — the thing `-reindex-chainstate`
        // repairs — could assert a parent link the block itself does not have.
        // The guard would then pass on a forged `prev_blockhash` while
        // `connect_block` received a differently-parented block, and the
        // cumulative chainwork would be measured from whatever entry that
        // forged link named.
        self.require_planned_block(height, hash, &block, &entry.header, flat_pos)?;
        self.require_extends_tip(&block.header, height)?;
        // The flat-file record framing carries no checksum, so a bit flipped
        // inside a transaction payload survives every check above: the 80-byte
        // header still hashes to the planned block. Only re-deriving the block
        // from its own bytes catches it (issue #505).
        validation::block::check_block(&block, self.network, height)?;
        let parent = self
            .store
            .get_block_index(&block.header.prev_blockhash)
            .ok_or(ChainError::BadPrevBlock)?;

        let use_noop = self.should_skip_scripts(height);
        let noop = NoopVerifier;
        let verifier: &dyn ScriptVerifier =
            if use_noop { &noop } else { &*self.script_verifier };

        // Resolve MTP through the plan, exactly as the prefetch path does.
        //
        // `get_median_time_past` walks the height→hash index, which is the
        // derived state this whole replay exists to distrust — and it is read
        // here at heights *below* the connect cursor, where a resumed replay
        // has not rewritten it. Rows written by the original sync survive
        // there, so a #322-shaped polluted row (a fork block owning a height)
        // contributes a timestamp from the wrong branch. MTP gates BIP113
        // locktimes, so that is a consensus input, and having the two replay
        // paths derive it from different sources made it depend on whether the
        // prefetcher happened to hit — which at replay startup it never does.
        let mtp = connect::median_time_past_with_plan(&*self.store, Some(plan), height);
        let batch = connect::connect_block(&connect::ConnectParams {
            replay_plan: Some(plan),
            store: &*self.store,
            block: &block,
            height,
            parent_chainwork: &parent.chainwork,
            flat_pos,
            script_verifier: verifier,
            median_time_past: mtp,
            network: self.network,
            pre_verified_txs: None,
            num_threads: self.num_threads,
            precomputed_txids: None,
            address_index: &self.address_index,
            sp_index: &self.sp_index,
            #[cfg(feature = "block-filter-index")]
            filter_index: &self.filter_index,
            phase_tracker: None,
        })?;
        self.store.write_batch(batch)?;
        let mut tip = self.tip.write();
        tip.hash = hash;
        tip.height = height;
        Ok(())
    }


    /// Plan the replay of a from-genesis reindex over the block tree built by
    /// the phase-1 flat-file scan.
    ///
    /// Flat files are a block *tree*, not a chain. Core and satd both persist
    /// every block they fully receive — including ones a later reorg orphaned
    /// — so on any node that has been live through a reorg the tree has fork
    /// points: one parent with two children. The replay has to pick the
    /// most-work branch and connect only that, exactly as the live path's
    /// `find_best_valid_tip` does.
    ///
    /// The previous implementation BFS'd the whole tree and connected every
    /// genesis-reachable block as if it extended the tip. At the first fork
    /// that either aborted the reindex with `bad-txns-inputs-missingorspent`
    /// (both branches spending the same coin) or — worse, when the branches
    /// did not conflict — silently applied the losing branch's UTXO delta on
    /// top of the winning chain and reported success with a corrupt UTXO set.
    ///
    /// Selection is by cumulative chainwork, not depth: depth happens to agree
    /// on mainnet but is the wrong metric, and a difficulty-transition fork
    /// can make the shorter branch the heavier one.
    ///
    /// Both walks are iterative — a mainnet chain is ~1M blocks deep and
    /// recursion would overflow the stack.
    fn plan_reindex_chain(
        children: &std::collections::HashMap<BlockHash, Vec<BlockHash>>,
        header_by_hash: &std::collections::HashMap<BlockHash, ReindexHeaderRef>,
        genesis: BlockHash,
    ) -> ReindexPlan {
        use std::collections::{HashSet, VecDeque};

        // Pass 1: breadth-first from genesis, carrying each block's height and
        // its chainwork relative to genesis (the genesis term is a constant
        // offset shared by every candidate, so omitting it cannot change the
        // comparison). `>` — strictly greater work — means an equal-work
        // candidate never displaces the one already chosen.
        //
        // Be precise about which candidate that is, because the obvious
        // reading is wrong. BFS dequeues in *height* order, so on an exact
        // work tie the winner is the branch whose tip is **shallower**, and
        // flat-file scan order only decides ties *within* the same height.
        // For same-height siblings — the only shape that occurs in practice,
        // since equal work at different depths needs a mixed-difficulty fork —
        // that is first-seen, matching the consensus rule `find_best_valid_tip`
        // implements. For the exotic case (branch A: 10 easy blocks written
        // first; branch B: 3 hard blocks of exactly equal cumulative work) it
        // picks B, which is NOT first-seen.
        //
        // Left as-is deliberately: exact work equality across differing depths
        // requires a contrived difficulty mix, both branches are valid, and the
        // node reorgs to whichever its peers extend. Documented rather than
        // claimed away — the sibling planner
        // (`replay_plan::plan_replay_from_block_index`) uses an explicit
        // incumbent-then-lowest-hash rule instead, so the two can disagree on
        // such a tie.
        let mut best: (BlockHash, u32, [u8; 32]) = (genesis, 0, [0u8; 32]);
        let mut queue: VecDeque<(BlockHash, u32, [u8; 32])> = VecDeque::new();
        queue.push_back((genesis, 0, [0u8; 32]));
        while let Some((hash, height, work)) = queue.pop_front() {
            if compare_u256(&work, &best.2) > 0 {
                best = (hash, height, work);
            }
            let Some(child_hashes) = children.get(&hash) else {
                continue;
            };
            for child in child_hashes {
                // Every non-genesis node in `children` came from a scanned
                // record, so its header is present; skip defensively rather
                // than panicking on an impossible map.
                let Some(entry) = header_by_hash.get(child) else {
                    continue;
                };
                let child_work = add_u256(&work, &work_for_bits(entry.header.bits));
                queue.push_back((*child, height + 1, child_work));
            }
        }

        // Walk back from the winning tip to genesis, then reverse: the blocks
        // to connect, in connect order. Genesis itself is already connected by
        // chain init and is not part of the path.
        let (tip_hash, tip_height, _) = best;
        let mut path: Vec<BlockHash> = Vec::with_capacity(tip_height as usize);
        let mut cursor = tip_hash;
        while cursor != genesis {
            path.push(cursor);
            match header_by_hash.get(&cursor) {
                Some(entry) => cursor = entry.header.prev_blockhash,
                // Unreachable for a tip produced by the walk above, which only
                // descends through blocks that have header entries.
                None => break,
            }
        }
        path.reverse();
        let path_set: HashSet<BlockHash> = path.iter().copied().collect();

        // Pass 2: everything else reachable from genesis is a side-chain
        // block. Its data is on disk and was in the block index before the
        // reindex cleared it, so re-index it (header + `DataStored`, never a
        // height→hash entry) rather than dropping it: that keeps
        // `getblockheader` on an orphaned hash working across a reindex, and
        // leaves the branch available to `find_best_valid_tip` should it later
        // be extended past the active tip.
        let mut side: Vec<(BlockHash, u32, [u8; 32])> = Vec::new();
        queue.push_back((genesis, 0, [0u8; 32]));
        while let Some((hash, height, work)) = queue.pop_front() {
            // Side blocks are indexed WITHOUT a height→hash row, because that
            // row names the active chain. That holds only for heights the
            // active chain also occupies: `accept_headers` restores a
            // "missing" height→hash row for any `DataStored` entry whose
            // height is vacant, so a side block above the selected tip would
            // have one written for it on the next headers message — putting a
            // losing branch into the active-chain index after all. Selection
            // is by work rather than depth, so a lighter-but-longer branch can
            // reach above the tip; leave those blocks unindexed, exactly as
            // they were before a reindex indexed side chains at all.
            if hash != genesis && !path_set.contains(&hash) && height <= tip_height {
                side.push((hash, height, work));
            }
            let Some(child_hashes) = children.get(&hash) else {
                continue;
            };
            for child in child_hashes {
                let Some(entry) = header_by_hash.get(child) else {
                    continue;
                };
                let child_work = add_u256(&work, &work_for_bits(entry.header.bits));
                queue.push_back((*child, height + 1, child_work));
            }
        }

        ReindexPlan {
            path,
            tip_height,
            side,
        }
    }

    /// Rebuild the block index and UTXO set by streaming `blk*.dat` files.
    /// Used by `-reindex` when the chain database has been cleared.
    ///
    /// Three passes:
    ///   1. Stream every record in the flat files, parsing only the 80-byte
    ///      header. Build `header_by_hash` and the `parent → children`
    ///      multimap. At the current mainnet height (~950k blocks, which
    ///      hashbrown rounds up to 2^21 buckets) that is ~254 MB for
    ///      `header_by_hash` and ~166 MB for `children` including its
    ///      per-parent `Vec` allocations; planning adds a ~30 MB path and a
    ///      ~69 MB membership set, for a ~518 MB peak. `children` is dropped
    ///      as soon as planning ends so the multi-day connect phase does not
    ///      hold it alongside the coin cache. The original implementation
    ///      eagerly held every full block in memory (~900 GB on mainnet),
    ///      which OOM-killed the node.
    ///   2. [`Self::plan_reindex_chain`]: pick the most-work branch of that
    ///      tree and order it genesis→tip. Side-chain blocks are separated
    ///      out here and never enter the connect loop.
    ///   3. Walk the chosen path in order. For each hash, read the raw block
    ///      from the flat file, deserialize, run `connect_block`, drop the
    ///      block. Peak memory is one block payload at a time. Side-chain
    ///      blocks are index-only entries written at the end.
    ///
    /// `progress` (if provided) is updated with the per-phase counters so
    /// the startup RPC can render `current/total` to operators.
    ///
    /// `stop_at` matches the `-stopatheight` flag: when set, the
    /// connect phase exits cleanly after the targeted height is
    /// durable. Headers past the target are still scanned in phase 1
    /// (planning needs the full parent→children map to pick the branch
    /// correctly), but no further blocks are connected.
    pub fn reindex_from_flat_files(
        &self,
        stop_at: Option<u32>,
        progress: Option<Arc<crate::startup_progress::StartupProgress>>,
    ) -> Result<(), ChainError> {
        use std::collections::HashMap;

        // Periodic flush cadence — same reasoning as `reindex_chainstate`:
        // without it the in-memory dirty set held weeks of writes for a
        // mainnet reindex and pinned 100+ GiB of RSS.
        const DURABLE_FLUSH_EVERY: u32 = 1000;

        type HeaderRef = ReindexHeaderRef;

        // Phase 1: scan flat files, parse only headers.
        if let Some(p) = &progress {
            p.set_phase("reindex_scan", "Scanning block files (phase 1/2)");
        }
        let mut header_by_hash: HashMap<BlockHash, HeaderRef> = HashMap::new();
        let mut children: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
        let mut scanned: u64 = 0;
        {
            let flat_files = self.flat_files.lock();
            flat_files
                .for_each_block(|block_bytes, pos| {
                    if block_bytes.len() < 80 {
                        return std::ops::ControlFlow::Continue(());
                    }
                    let header: bitcoin::block::Header =
                        match bitcoin::consensus::deserialize(&block_bytes[..80]) {
                            Ok(h) => h,
                            Err(_) => return std::ops::ControlFlow::Continue(()),
                        };
                    let hash = header.block_hash();
                    scanned += 1;
                    // Branch selection is driven by `bits`, so `bits` has to be
                    // backed by work actually done. An 80-byte header always
                    // deserializes — every field is a fixed-width integer — so
                    // a single flipped bit in a record's `nBits` exponent
                    // yields a well-formed header claiming an astronomical
                    // target, which would then out-score the honest chain and,
                    // since `connect_block` checks no PoW either, be connected
                    // and persisted as the tip. Checking the hash against the
                    // claimed target closes that off: a harder target the block
                    // does not meet is rejected, and an easier one only lowers
                    // its own score.
                    if validation::pow::check_proof_of_work(&header).is_err() {
                        tracing::warn!(
                            block = %hash,
                            "reindex: flat-file record fails proof of work; not indexing it"
                        );
                        return std::ops::ControlFlow::Continue(());
                    }
                    // The same block can be on disk more than once (a
                    // re-download, or a crash-resume that re-wrote it). Keep
                    // the first copy: a repeated `children` edge would walk
                    // that block's whole subtree again per copy (exponential
                    // in the number of duplicated ancestors) and emit
                    // duplicate side-chain index entries. Which copy is kept
                    // only matters if one of them is damaged, and the flat-file
                    // scanner already refuses to yield a record whose length
                    // header does not bound a complete payload — so both copies
                    // are structurally intact and byte-identical. First-wins
                    // also keeps the sibling ordering below deterministic.
                    if header_by_hash.contains_key(&hash) {
                        return std::ops::ControlFlow::Continue(());
                    }
                    children
                        .entry(header.prev_blockhash)
                        .or_default()
                        .push(hash);
                    header_by_hash.insert(hash, HeaderRef { header, pos });
                    if let Some(p) = &progress
                        && scanned.is_multiple_of(1000)
                    {
                        p.set_current(scanned);
                    }
                    std::ops::ControlFlow::Continue(())
                })
                .map_err(|e| ChainError::FlatFile(format!("scan flat files: {}", e)))?;
        }
        let total = scanned;
        if let Some(p) = &progress {
            p.set_total(total);
            p.set_current(total);
        }
        tracing::info!(scanned, "Phase 1: indexed block headers from flat files");

        // Phase 2: pick the branch to replay, then fetch each block from disk
        // and connect it in chain order.
        let genesis_hash = bitcoin::constants::genesis_block(self.network).block_hash();

        // The Phase-1 scan counts every physical block record on disk. On a node
        // whose flat files accumulated duplicate, orphaned (non-genesis-
        // reachable) or side-chain records, that count can substantially exceed
        // the real chain height — and using it as the connect target makes the
        // progress bar top out early (it can never reach 100%) and the ETA
        // project to a height that will never be connected. Derive the true
        // target from the block tree instead: the most-work branch's tip is the
        // block Phase 3 will actually connect to.
        let plan = Self::plan_reindex_chain(&children, &header_by_hash, genesis_hash);
        // Always state which chain was selected, even when there is no fork.
        //
        // The failure this replay path exists to fix was "it replayed the wrong
        // chain", and diagnosing it took a three-day run followed by a custom
        // scan of 5661 flat files — because nothing in the log ever said which
        // branch had been chosen. One line here is the difference between
        // confirming the selection from a log and reproducing the whole job.
        tracing::info!(
            tip = %plan
                .path
                .last()
                .map(|h| h.to_string())
                .unwrap_or_else(|| "genesis".into()),
            tip_height = plan.tip_height,
            connecting = plan.path.len(),
            side_chain_blocks = plan.side.len(),
            scanned = total,
            "Phase 2: selected the most-work branch to replay"
        );
        // Records on disk but no chain out of genesis means the flat files are
        // unusable — a wrong network's blocks dir, a truncated first file, a
        // missing blk00000.dat. Connecting nothing and reporting a completed
        // reindex would leave the node serving height 0 as though that were
        // the answer.
        if plan.path.is_empty() && total > 0 {
            tracing::error!(
                scanned = total,
                "reindex: scanned block records but none form a chain from genesis; the block \
                 files cannot be replayed. Check that the blocks directory belongs to this \
                 network and that blk00000.dat is present and intact."
            );
            return Err(ChainError::BadPrevBlock);
        }

        // `children` is dead once the plan exists; without this it stays
        // resident (~166 MB on mainnet) for the entire multi-day connect phase,
        // competing with the coin cache.
        drop(children);
        let connect_target_height = plan.tip_height;
        // `-stopatheight` caps the connect target when it lands below the tip.
        let target_height = stop_at
            .map(|h| h.min(connect_target_height))
            .unwrap_or(connect_target_height);

        if let Some(p) = &progress {
            p.set_phase("reindex_connect", "Replaying blocks (phase 2/2)");
            p.set_total(target_height as u64);
            p.set_stop_height(stop_at.map(|h| h as u64));
            // Switch the ETA into driver-controlled mode up front so the
            // generic linear estimate never briefly shows a bogus tiny ETA
            // over the trivial early blocks before the weight-aware estimator
            // has data.
            p.set_eta(None);
        }
        // Weight-aware ETA over the heavy connect phase (reused from IBD). The
        // connect target is the true genesis-reachable tip height (not the raw
        // phase-1 record count), so the estimate converges on the real finish.
        let mut eta_est =
            crate::ibd_eta::IbdEtaEstimator::new(0, target_height, self.network == Network::Bitcoin);
        let mut interval_start = std::time::Instant::now();
        let mut last_interval: u32 = 0;

        let mut connected: u32 = 0;
        // Set when a block on the planned path cannot be replayed. See the
        // handling after the loop for why this stops the replay rather than
        // failing it (issue #542).
        let mut halted: Option<(BlockHash, u32, String)> = None;
        for hash in &plan.path {
            let hash = *hash;
            let entry = match header_by_hash.remove(&hash) {
                Some(v) => v,
                None => continue,
            };

            // The parent lookup comes before the read so that `height` is known
            // for the halt diagnostics below, which report on a block whose
            // bytes may be exactly what is unreadable.
            let parent = self
                .store
                .get_block_index(&entry.header.prev_blockhash)
                .ok_or(ChainError::BadPrevBlock)?;
            let height = parent.height + 1;

            // Re-read the raw block from disk; we only kept the header during
            // phase 1.
            let Some(block) = self.read_block_direct(&entry.pos) else {
                halted = Some((hash, height, "block data unreadable on disk".to_string()));
                break;
            };
            // `plan_reindex_chain` builds the path by walking parent pointers,
            // so this holds by construction — which is exactly why it is worth
            // asserting: it is the guard that keeps a future change to the
            // planner from silently reintroducing a side-chain connect.
            self.require_extends_tip(&block.header, height)?;
            // The block files are the *sole* source of truth on this path —
            // the block index is being rebuilt from them — and their framing
            // carries no checksum. `scan_one_file` validated magic and length;
            // this is what validates the payload (issue #505).
            if let Err(e) = validation::block::check_block(&block, self.network, height) {
                halted = Some((hash, height, format!("fails validation: {e}")));
                break;
            }

            let use_noop = self.should_skip_scripts(height);
            let noop = NoopVerifier;
            let verifier: &dyn ScriptVerifier =
                if use_noop { &noop } else { &*self.script_verifier };

            let mtp = self.get_median_time_past(height);
            let batch = connect::connect_block(&connect::ConnectParams {
                replay_plan: None,
                store: &*self.store,
                block: &block,
                height,
                parent_chainwork: &parent.chainwork,
                flat_pos: entry.pos,
                script_verifier: verifier,
                median_time_past: mtp,
                network: self.network,
                pre_verified_txs: None,
                num_threads: self.num_threads,
                precomputed_txids: None,
                address_index: &self.address_index,
                sp_index: &self.sp_index,
                #[cfg(feature = "block-filter-index")]
                filter_index: &self.filter_index,
                phase_tracker: None,
            })?;
            self.store.write_batch(batch)?;

            {
                let mut tip = self.tip.write();
                tip.hash = hash;
                tip.height = height;
            }

            // See note in `reindex_chainstate`: emit even though the
            // broadcaster is typically unset at reindex time, so that
            // moving the wiring earlier needs no further change.
            self.emit_chain_event(crate::chain::events::ChainEvent::BlockConnected {
                hash,
                height,
            });

            // Same memory + durability discipline as `reindex_chainstate`.
            if self.store.dirty_count() > self.store.flush_threshold() {
                self.store.flush()?;
            }
            if height.is_multiple_of(DURABLE_FLUSH_EVERY) {
                self.store.flush()?;
                self.store.flush_durable()?;
            }

            connected += 1;
            // Feed the ETA estimator one observation per 1000-block interval.
            let cur_interval = height / 1000;
            if cur_interval > last_interval {
                let secs = interval_start.elapsed().as_secs_f64();
                let spans = (cur_interval - last_interval) as f64;
                eta_est.record_interval(cur_interval * 1000, secs / spans);
                interval_start = std::time::Instant::now();
                last_interval = cur_interval;
            }
            if let Some(p) = &progress
                && connected.is_multiple_of(100)
            {
                p.set_current(connected as u64);
                p.set_eta(eta_est.estimate_eta(height, target_height));
            }
            if connected.is_multiple_of(10_000) {
                tracing::info!(connected, height, "Reindexing from flat files...");
            }

            // Honor `-stopatheight`: exit the replay phase after the
            // targeted height is durable. Same semantics as
            // `reindex_chainstate` — no rollback for already-connected
            // heights, and remaining headers stay queued for a later
            // run (the connector just stops draining the BFS queue).
            if let Some(target) = stop_at
                && height >= target
            {
                if let Some(p) = &progress {
                    p.set_current(connected as u64);
                }
                tracing::info!(
                    connected,
                    height,
                    target,
                    "Reached -stopatheight during flat-file reindex; exiting"
                );
                self.store.flush()?;
                self.store.flush_durable()?;
                return Ok(());
            }
        }

        // A block on the planned path could not be replayed.
        //
        // This must not fail the reindex, and that is the whole point of issue
        // #542. By the time this code runs the caller has already called
        // `clear_all()`, so returning `Err` leaves the node with **no**
        // chainstate at all, and the retry re-derives the same plan and dies at
        // the same block — an unrecoverable state produced by the recovery
        // tool. The block that triggers it is durably on disk from an older
        // release, so an upgrade alone can arm it.
        //
        // Stopping instead is recoverable in the ordinary way: everything below
        // this height is fully replayed and durable, no index entry is written
        // for the offending block or anything above it, and normal IBD then
        // fetches those heights from peers — which is also how the bad bytes
        // get replaced, since a peer's copy no longer collides with a stored
        // entry. Side-chain indexing is skipped for the same reason a
        // `-stopatheight` run skips it: the index would describe a tree the
        // chainstate has not caught up to.
        //
        // What this must never be is *quiet*. A reindex that stops early and
        // reports success is the "completed reindex over a partial chain" shape
        // (issue #504), so the halt is logged at error, recorded as a standing
        // warning so it reaches `getwarnings`/`-alertnotify`, and kept out of
        // the "complete" log line below.
        if let Some((hash, height, reason)) = halted {
            tracing::error!(
                block = %hash,
                height,
                reason = %reason,
                connected,
                "Reindex stopped early: this block cannot be replayed from the block files. \
                 Heights below it are intact; the node will sync the rest from peers. \
                 To repair the stored copy, use getblockfrompeer once connected."
            );
            self.warnings.record(
                "reindex.halted",
                crate::warnings::Severity::Error,
                format!(
                    "Reindex stopped at height {height} ({reason}); \
                     the chain above it will be re-fetched from peers"
                ),
                serde_json::json!({
                    "block": hash.to_string(),
                    "height": height,
                    "reason": reason,
                    "connected": connected,
                }),
            );
            self.store.flush()?;
            self.store.flush_durable()?;
            if let Some(p) = &progress {
                p.set_current(connected as u64);
            }
            return Ok(());
        }

        // Re-index the side-chain blocks the replay skipped. Only after a full
        // replay: a `-stopatheight` run left main-chain blocks unconnected too,
        // and the index entries would then describe a tree the chainstate has
        // not caught up to.
        self.index_reindex_side_chain(&plan.side, &header_by_hash)?;

        // Final durable checkpoint so the reindexed tip survives a crash.
        self.store.flush()?;
        self.store.flush_durable()?;
        if let Some(p) = &progress {
            p.set_current(connected as u64);
        }
        tracing::info!(connected, "Reindex from flat files complete");
        Ok(())
    }

    /// Write header + `DataStored` index entries for the side-chain blocks a
    /// flat-file reindex found but did not connect.
    ///
    /// Deliberately narrow:
    ///   * Proof of work is re-checked. Re-checking PoW is what stops a
    ///     doctored flat file from injecting an index entry claiming more
    ///     chainwork than it did the work for, which is the property that
    ///     matters for selection: work cannot be forged, so such a branch
    ///     cannot *win*.
    ///   * The record is reconciled with the entry about to be written, and
    ///     run through `check_block`. This path is the only producer of
    ///     `DataStored` entries whose bytes were never validated — on the live
    ///     path `accept_block` checks a block before it is written to the flat
    ///     files. It matters because nothing downstream re-derives them:
    ///     `connect_stored_block` reads `flat_pos` and connects, without
    ///     comparing the bytes to the entry's hash or header and without
    ///     `check_block`. So a mispointed or corrupt record indexed here is
    ///     applied verbatim if the branch is ever activated, while the tip
    ///     advances to the *indexed* hash.
    ///   * Contextual validity is still not checked — see the note below.
    ///
    ///     Note what this does NOT buy. An earlier version of this comment
    ///     said the reorg path validates before connecting; it does not.
    ///     `reorg_to` connects through `connect::connect_block`, which runs
    ///     neither `check_proof_of_work` nor `check_difficulty` — every
    ///     difficulty-schedule, timestamp and checkpoint rule lives in
    ///     `accept_header`/`accept_block`, which the reindex bypasses. So a
    ///     side entry with wrong `bits` for its retarget window can be indexed
    ///     and, if later extended, connected, where the live path would have
    ///     rejected it. The main-chain reindex path has the same gap and
    ///     always has, so this is not a regression — but it is not covered by
    ///     the reorg path either.
    ///   * No `height_hash` entry is ever written. The height→hash index names
    ///     the *active* chain; letting a losing branch write there is the
    ///     bad-cb-height pollution that wedged a mainnet node (#322).
    fn index_reindex_side_chain(
        &self,
        side: &[(BlockHash, u32, [u8; 32])],
        header_by_hash: &std::collections::HashMap<BlockHash, ReindexHeaderRef>,
    ) -> Result<(), ChainError> {
        if side.is_empty() {
            return Ok(());
        }
        // Genesis's own chainwork is the offset `plan_reindex_chain` factored
        // out of every candidate; add it back so the stored values are
        // comparable with the ones `connect_block` writes.
        let genesis_work = self
            .store
            .get_block_index(&bitcoin::constants::genesis_block(self.network).block_hash())
            .map(|e| e.chainwork)
            .unwrap_or([0u8; 32]);

        let mut batch = crate::storage::StoreBatch::default();
        let mut indexed = 0u64;
        let mut skipped = 0u64;
        for (hash, height, work) in side {
            let Some(entry) = header_by_hash.get(hash) else {
                skipped += 1;
                continue;
            };
            if validation::pow::check_proof_of_work(&entry.header).is_err() {
                tracing::warn!(
                    block = %hash,
                    height,
                    "reindex: side-chain block fails proof of work; not indexing"
                );
                skipped += 1;
                continue;
            }
            // `num_tx` is not derivable from the 80-byte header phase 1 kept,
            // so read the block back. Side-chain blocks are a handful even on a
            // long-lived mainnet node, so this stays cheap.
            let Some(block) = self.read_block_direct(&entry.pos) else {
                tracing::warn!(
                    block = %hash,
                    height,
                    "reindex: side-chain block unreadable from flat file; not indexing"
                );
                skipped += 1;
                continue;
            };
            if block.block_hash() != *hash || block.header != entry.header {
                tracing::warn!(
                    block = %hash,
                    height,
                    found = %block.block_hash(),
                    file_number = entry.pos.file_number,
                    data_pos = entry.pos.data_pos,
                    "reindex: side-chain record does not match the header scanned from it;                      not indexing"
                );
                skipped += 1;
                continue;
            }
            if let Err(e) = validation::block::check_block(&block, self.network, *height) {
                tracing::warn!(
                    block = %hash,
                    height,
                    error = %e,
                    "reindex: side-chain block fails context-free validation; not indexing"
                );
                skipped += 1;
                continue;
            }
            batch.block_index_puts.push((
                *hash,
                BlockIndexEntry {
                    header: entry.header,
                    height: *height,
                    status: BlockStatus::DataStored,
                    num_tx: block.txdata.len() as u32,
                    file_number: entry.pos.file_number,
                    data_pos: entry.pos.data_pos,
                    chainwork: add_u256(&genesis_work, work),
                },
            ));
            indexed += 1;
        }
        if !batch.block_index_puts.is_empty() {
            self.store.write_batch(batch)?;
        }
        tracing::info!(
            indexed,
            skipped,
            "Reindex: indexed side-chain blocks (not connected)"
        );
        Ok(())
    }

    /// Accept a new block into the chain.
    pub fn accept_block(&self, block: &Block) -> Result<BlockHash, ChainError> {
        // Serialize the whole accept→connect→commit critical section. The
        // connect thread already holds this implicitly (it is the sole P2P
        // writer); the guard exists to stop a concurrent `submitblock` /
        // internal-mine call on an RPC worker thread from interleaving a
        // second `accept_block` into the shared coin cache and `tip`. Held
        // for the full body — including the reorg path and the trailing
        // per-block flush — so the entire mutation is atomic w.r.t. other
        // writers. Uncontended on IBD/reindex/normal-P2P (single writer);
        // see the `accept_lock` field doc.
        let _accept_guard = self.accept_lock.lock();

        let block_hash = block.block_hash();
        let trace_id = rand::random::<u32>();
        let _span = tracing::info_span!(
            "accept_block",
            trace_id = trace_id,
            block = %block_hash
        )
        .entered();

        // Reorg record staged by the side-chain branch below and emitted
        // only after the final tip-extending connect/commit succeeds. If
        // that final step fails we never persist the record, which keeps
        // getreorghistory honest: it always describes reorgs that
        // actually became the active chain tip.
        let mut pending_reorg: Option<PendingReorgRecord> = None;

        // Flush-exclusion held only while a reorg is mutating the cache
        // across multiple steps (issue #262 follow-up). Acquired just
        // before the pre-reorg checkpoint flush and released the moment the
        // cache holds a consistent full-reorg delta (after the triggering
        // block commits) or on abort — so concurrent external flushes
        // (`gettxoutsetinfo`, `dumptxoutset`, the filter backfill runner)
        // cannot persist a partially-applied reorg. `None` for the common
        // tip-extending path, which never leaves the cache inconsistent.
        let mut reorg_excl: Option<crate::storage::coin_cache::FlushExclusion> = None;

        // Check for duplicate (HeaderOnly entries are OK — we're now providing data)
        if let Some(existing) = self.store.get_block_index(&block_hash)
            && existing.status != BlockStatus::HeaderOnly {
                return Err(ChainError::Duplicate);
            }

        // Find parent
        let prev_hash = block.header.prev_blockhash;
        let parent = self
            .store
            .get_block_index(&prev_hash)
            .ok_or(ChainError::BadPrevBlock)?;

        // Refuse to build on a parent that was explicitly invalidated
        // (Core: "bad-prevblk"). `invalidate_block` marks the whole subtree
        // `Invalid`, so this guard preserves the "not-Invalid ⟹ no Invalid
        // ancestor" invariant that `find_best_valid_tip` relies on: a block
        // descending from an invalidated one can never re-enter the candidate
        // set until a matching `reconsider_block` clears the mark.
        if parent.status == BlockStatus::Invalid {
            return Err(ChainError::BadPrevBlock);
        }

        let new_height = parent.height + 1;

        // Structural + witness block validation
        validation::block::check_block(block, self.network, new_height)?;

        // PoW validation
        validation::pow::check_proof_of_work(&block.header)?;

        // Difficulty check
        let store_ref = &*self.store;
        validation::pow::check_difficulty(
            &block.header,
            &parent,
            self.network,
            |h| {
                let hash = store_ref.get_block_hash_by_height(h)?;
                store_ref.get_block_index(&hash)
            },
            |h| store_ref.get_block_index(h),
        )?;

        // Timestamp check (median time past). The MTP ancestor walk follows the
        // candidate block's own parent pointers (not the active-chain height
        // index), so a block on a competing branch is judged against its own
        // ancestors — required for reorgs onto lower-timestamp testnet4 forks.
        validation::pow::check_timestamp(&block.header, &parent, |h| store_ref.get_block_index(h))?;

        // Future-timestamp check (Core: time-too-new, 2h ahead of now).
        // Historical blocks always pass; only live, ahead-of-clock blocks
        // are rejected.
        validation::pow::check_future_timestamp(&block.header, unix_now_secs())?;

        // Mandatory block-version gate (Core: bad-version) — BIP34/66/65.
        connect::check_block_version(&block.header, new_height, self.network)?;

        // Signet block-solution check (BIP 325), custom signet only.
        self.check_signet_solution(block)?;

        // Checkpoint validation
        if self.enforce_checkpoints
            && !checkpoints::check_against_checkpoints(new_height, &block_hash, &self.checkpoints)
        {
            tracing::warn!(
                height = new_height,
                hash = %block_hash,
                "Block rejected: checkpoint mismatch"
            );
            return Err(ChainError::CheckpointMismatch(new_height));
        }

        // Write raw block to flat file, durably enough that the index entry
        // below can never outlive the bytes it points at.
        let block_data = serialize(block);
        let flat_pos = self.write_block_durable(&block_data)?;

        // Check if this extends the current tip or is a side chain
        let current_tip = self.tip_hash();
        let new_chainwork = add_u256(&parent.chainwork, &work_for_bits(block.header.bits));

        if prev_hash != current_tip {
            // Side chain block — store it first
            let entry = BlockIndexEntry {
                header: block.header,
                height: new_height,
                status: BlockStatus::DataStored,
                num_tx: block.txdata.len() as u32,
                file_number: flat_pos.file_number,
                data_pos: flat_pos.data_pos,
                chainwork: new_chainwork,
            };
            let mut batch = crate::storage::StoreBatch::default();
            batch.block_index_puts.push((block_hash, entry.clone()));
            self.store.write_batch(batch)?;

            // Check if this side chain now has more work than the current tip
            let tip_entry = self.store.get_block_index(&current_tip)
                .ok_or(ChainError::BadPrevBlock)?;
            if compare_u256(&new_chainwork, &tip_entry.chainwork) <= 0 {
                // Side chain has less or equal work — don't reorg
                return Ok(block_hash);
            }

            // During IBD, if the side chain is far ahead of our tip, don't attempt
            // reorg — the intermediate blocks will arrive and connect in order.
            // This avoids expensive failed reorg attempts when blocks arrive
            // out of order from multiple peers.
            if new_height > tip_entry.height + 128 {
                return Ok(block_hash);
            }

            // Side chain has more work — find fork point and reorg
            tracing::info!(
                new_height,
                old_tip_height = tip_entry.height,
                "Reorg: side chain has more work, activating"
            );

            // Walk back from both the active tip and the side-chain
            // tip in parallel until they meet at a common ancestor
            // — that is the fork point.
            //
            // We deliberately do NOT use `BlockStatus::Valid` (stale
            // disconnected blocks keep that marker) nor
            // `get_block_hash_by_height` (the height index is a
            // "best-known-at-height" lookup populated by
            // accept_header / accept_headers / store_block too, not
            // an active-chain-only oracle). Walking ancestor pointers
            // is bounded by reorg depth (<= 128 by the IBD guard at
            // line ~1265) and only consults `prev_blockhash` /
            // `height`, both of which are immutable per block.
            let fork_entry = {
                let mut active_hash = current_tip;
                let mut active_height = tip_entry.height;
                let mut side_hash = prev_hash;
                let mut side_height = new_height.saturating_sub(1);

                // Equalize heights: walk the deeper walker back.
                while active_height > side_height {
                    let entry = self
                        .store
                        .get_block_index(&active_hash)
                        .ok_or(ChainError::BadPrevBlock)?;
                    active_hash = entry.header.prev_blockhash;
                    active_height -= 1;
                }
                while side_height > active_height {
                    let entry = self
                        .store
                        .get_block_index(&side_hash)
                        .ok_or(ChainError::BadPrevBlock)?;
                    side_hash = entry.header.prev_blockhash;
                    side_height -= 1;
                }

                // Walk both back together until they meet.
                while active_hash != side_hash {
                    let a_entry = self
                        .store
                        .get_block_index(&active_hash)
                        .ok_or(ChainError::BadPrevBlock)?;
                    let s_entry = self
                        .store
                        .get_block_index(&side_hash)
                        .ok_or(ChainError::BadPrevBlock)?;
                    active_hash = a_entry.header.prev_blockhash;
                    side_hash = s_entry.header.prev_blockhash;
                }

                self.store
                    .get_block_index(&active_hash)
                    .ok_or(ChainError::BadPrevBlock)?
            };

            // AssumeUTXO reorg-depth guard: while a snapshot is loaded,
            // this (snapshot) chainstate's UTXO base IS the snapshot
            // block — it has connected no blocks below `snapshot_height`.
            // A reorg whose fork point is below the snapshot height would
            // try to disconnect blocks the snapshot assumes as final and
            // that this chainstate never connected. Decline the reorg
            // (keep the side-chain block stored) rather than corrupt the
            // snapshot base. The background chainstate is what validates
            // that buried history.
            if let Some(bg) = self.background()
                && fork_entry.height < bg.snapshot_height()
            {
                tracing::warn!(
                    fork_height = fork_entry.height,
                    snapshot_height = bg.snapshot_height(),
                    new_height,
                    "AssumeUTXO: refusing reorg below the snapshot height"
                );
                return Ok(block_hash);
            }

            // Atomic-reorg durable checkpoint (issue #262). Flush the
            // pre-reorg active chain to the inner store so it becomes the
            // exact rollback target. Every reorg write below
            // (disconnect, reconnect, triggering connect) lands in the
            // coin cache only — never on disk — until the reorg fully
            // succeeds and a later flush commits it. On any failure we
            // call `abort_reorg`, which discards the whole cache delta and
            // restores the tip to this checkpoint. This replaces the old
            // `rollback_partial_reorg` block-body replay, which could
            // itself fail (e.g. "block data missing during rollback
            // reconnect") and leave FRESH coins elided — the root cause of
            // the silent UTXO drop. If the checkpoint flush itself fails we
            // abort before mutating any chain state.
            //
            // Take the flush-exclusion lock FIRST, then flush the
            // checkpoint through it. Holding it blocks concurrent external
            // flushes for the rest of the reorg, so none can persist a
            // partially-applied reorg between here and the triggering
            // commit/abort. The checkpoint flush goes through the held
            // handle (no re-acquire).
            let excl = self.store.lock_flush_exclusion();
            excl.flush()?;
            reorg_excl = Some(excl);

            // Disconnect blocks from current tip down to fork point.
            // The returned info carries the data we need to build an
            // accurate reorg record once reconnection is complete.
            let disconnect_info = match self.perform_reorg(&fork_entry, current_tip) {
                Ok(info) => info,
                Err(e) => {
                    // perform_reorg only mutates the cache via its single
                    // batch write + tip update; abort restores both.
                    let old_height = self
                        .store
                        .get_block_index(&current_tip)
                        .map(|en| en.height)
                        .unwrap_or(tip_entry.height);
                    self.abort_reorg(current_tip, old_height);
                    return Err(e);
                }
            };

            // Reconnect the side chain from the fork point up to (but not
            // including) the new block; the new block itself connects via
            // the shared path below. BOTH the collection walk and the
            // per-block reconnect run inside the closure so that ANY
            // failure — a missing/evicted block index as well as a block
            // that fails to connect — is caught and routed through
            // `abort_reorg`, never escaping with `?` and stranding a
            // partially-reorged chainstate at the fork point. The pre-reorg
            // checkpoint flush makes that abort a pure in-cache discard.
            let mut reconnected_hashes: Vec<BlockHash> = Vec::new();
            let mut reconnected_blocks: Vec<(bitcoin::Block, u32)> = Vec::new();

            let side_result: Result<(), ChainError> = (|| {
                // Collect side-chain blocks fork+1..=prev, forward order.
                let mut to_connect = Vec::new();
                {
                    let mut hash = prev_hash;
                    let fork_hash = fork_entry.header.block_hash();
                    while hash != fork_hash {
                        to_connect.push(hash);
                        let e = self
                            .store
                            .get_block_index(&hash)
                            .ok_or(ChainError::BadPrevBlock)?;
                        hash = e.header.prev_blockhash;
                    }
                    to_connect.reverse();
                }
                for side_hash in &to_connect {
                    let side_block = self
                        .get_block(side_hash)
                        .ok_or(ChainError::FlatFile(
                            "block data missing for reorg connect".to_string(),
                        ))?;
                    let side_entry = self
                        .store
                        .get_block_index(side_hash)
                        .ok_or(ChainError::BadPrevBlock)?;
                    let parent_entry = self
                        .store
                        .get_block_index(&side_entry.header.prev_blockhash)
                        .ok_or(ChainError::BadPrevBlock)?;
                    // The blocks a reorg reconnects need the same parent
                    // check as the block that triggered it. The check below
                    // the reorg only ever sees the triggering block, by which
                    // point its parent has just been stamped `Valid` by this
                    // loop — so without this, a reorg forking at a block this
                    // chainstate never connected rebuilds the whole side
                    // branch on top of the hole and commits a new tip. The
                    // first iteration checks the fork point itself; later ones
                    // re-check a parent this loop connected, which is cheap
                    // and keeps the invariant local to the loop that relies on
                    // it. Inside the closure, so `?` routes through
                    // `abort_reorg` like every other failure here.
                    self.require_connected_parent(
                        &side_entry.header.prev_blockhash,
                        side_hash,
                        side_entry.height,
                    )?;
                    let use_noop = self.should_skip_scripts(side_entry.height);
                    let noop = NoopVerifier;
                    let verifier: &dyn ScriptVerifier =
                        if use_noop { &noop } else { &*self.script_verifier };
                    let mtp = self.get_median_time_past(side_entry.height);
                    let side_flat_pos = FlatFilePos {
                        file_number: side_entry.file_number,
                        data_pos: side_entry.data_pos,
                    };
                    let batch = connect::connect_block(&connect::ConnectParams {
                        replay_plan: None,
                        store: &*self.store,
                        block: &side_block,
                        height: side_entry.height,
                        parent_chainwork: &parent_entry.chainwork,
                        flat_pos: side_flat_pos,
                        script_verifier: verifier,
                        median_time_past: mtp,
                        network: self.network,
                        pre_verified_txs: None,
                        num_threads: 1,
                        precomputed_txids: None,
                        address_index: &self.address_index,
                        sp_index: &self.sp_index,
            #[cfg(feature = "block-filter-index")]
            filter_index: &self.filter_index,
                        phase_tracker: None,
                    })?;
                    self.store.write_batch(batch)?;
                    {
                        let mut tip = self.tip.write();
                        tip.hash = *side_hash;
                        tip.height = side_entry.height;
                    }
                    reconnected_hashes.push(*side_hash);
                    reconnected_blocks.push((side_block, side_entry.height));
                    // Chain event for this side block is staged and
                    // emitted at the end of `connect_tip` only after
                    // the entire reorg + mempool reconcile commits.
                    // Emitting inline would notify subscribers about a
                    // state that rollback could still revert.
                    tracing::info!(
                        height = side_entry.height,
                        hash = %side_hash,
                        "Reorg: block connected"
                    );
                }
                Ok(())
            })();

            if let Err(e) = side_result {
                tracing::warn!(
                    error = %e,
                    "Reorg side-chain reconnect failed; discarding the cache delta and restoring the pre-reorg tip"
                );
                // Atomic rollback (#262): drop the entire in-cache reorg
                // delta and restore the tip to the pre-reorg checkpoint.
                // Cannot fail — no block-body replay.
                self.abort_reorg(disconnect_info.old_tip, disconnect_info.old_height);
                return Err(e);
            }

            // Stage the reorg record for persistence *after* the final
            // triggering block's connect+commit succeeds below. Writing it
            // here would predict a new_tip that might never be reached if
            // the final `connect_block` fails validation.
            pending_reorg = Some(PendingReorgRecord {
                fork_height: fork_entry.height,
                old_tip: disconnect_info.old_tip,
                old_height: disconnect_info.old_height,
                disconnected: disconnect_info.disconnected,
                reconnected_so_far: reconnected_hashes,
                reconnected_blocks,
                disconnected_txs: disconnect_info.disconnected_txs,
                // Carry the original-chain (hash, height) pairs
                // through both for the triggering-block failure
                // rollback and for the deferred BlockDisconnected
                // event emission once the reorg fully commits.
                original_disconnected: disconnect_info.disconnected_with_height,
            });

            // Fall through to connect the new block as a tip-extending block
        }

        // The block about to be connected must sit on a parent this chainstate
        // actually connected. The two sequential-connect paths check this; a
        // synced node does not use them — it arrives here, from P2P, from
        // `submitblock` and from internal mining — and the divergence this
        // guards against was observed on a synced node. Placed after the reorg
        // fallthrough so it sees the tip the reorg left behind, not the one it
        // started from.
        //
        // Rolled back like every other failure exit in this region. Reaching
        // here with `pending_reorg` set means the reorg has already
        // disconnected the old chain, reconnected the side branch and advanced
        // `self.tip` onto it, with the whole delta buffered in the coin cache
        // and `reorg_excl` held so no external flush can persist half of it.
        // Returning bare would drop that guard at scope exit and leave the tip
        // standing on a partially-applied reorg — the exact shape this guard
        // exists to refuse, reintroduced by the guard itself.
        if let Err(e) = self.require_connected_parent(&prev_hash, &block_hash, new_height) {
            if let Some(pending) = pending_reorg.as_ref() {
                tracing::warn!(
                    error = %e,
                    "Reorg triggering block sits on an unconnected parent; discarding the cache delta and restoring the pre-reorg tip"
                );
                self.abort_reorg(pending.old_tip, pending.old_height);
            }
            return Err(e);
        }

        // Determine script verifier: skip if below assumevalid height
        let use_noop = self.should_skip_scripts(new_height);
        let noop = NoopVerifier;
        let verifier: &dyn ScriptVerifier = if use_noop { &noop } else { &*self.script_verifier };

        // Connect block (process transactions, update UTXOs, verify scripts).
        // If the triggering block fails inside an in-progress reorg, roll
        // the chain back to the pre-reorg active chain before returning
        // the error — otherwise the failed candidate would leave the
        // node permanently advanced onto a partial side-chain prefix.
        let mtp = self.get_median_time_past(new_height);
        let connect_attempt = connect::connect_block(&connect::ConnectParams {
            replay_plan: None,
            store: &*self.store,
            block,
            height: new_height,
            parent_chainwork: &parent.chainwork,
            flat_pos,
            script_verifier: verifier,
            median_time_past: mtp,
            network: self.network,
            pre_verified_txs: None,
            num_threads: self.num_threads,
            precomputed_txids: None,
            address_index: &self.address_index,
            sp_index: &self.sp_index,
            #[cfg(feature = "block-filter-index")]
            filter_index: &self.filter_index,
            phase_tracker: None,
        });
        let batch = match connect_attempt {
            Ok(b) => b,
            Err(e) => {
                if let Some(pending) = pending_reorg.as_ref() {
                    tracing::warn!(
                        error = %e,
                        "Reorg triggering block validation failed; discarding the cache delta and restoring the pre-reorg tip"
                    );
                    self.abort_reorg(pending.old_tip, pending.old_height);
                }
                return Err(e.into());
            }
        };

        if let Err(e) = self.store.write_batch(batch) {
            if let Some(pending) = pending_reorg.as_ref() {
                tracing::warn!(
                    error = %e,
                    "Reorg triggering block commit failed; discarding the cache delta and restoring the pre-reorg tip"
                );
                self.abort_reorg(pending.old_tip, pending.old_height);
            }
            return Err(e.into());
        }

        // Update in-memory tip
        {
            let mut tip = self.tip.write();
            tip.hash = block_hash;
            tip.height = new_height;
        }

        // Reorg fully committed: the cache now holds a consistent
        // full-reorg delta. Release the flush-exclusion lock so the
        // mempool reconcile, chain-event emission, and the Layer-1
        // per-block flush below run unguarded (they only ever observe a
        // consistent cache) and external flushes can proceed. A no-op for
        // the tip-extending path (never acquired). Dropping here also
        // guarantees the Layer-1 `self.store.flush()` at the tail does not
        // self-deadlock on the still-held guard.
        drop(reorg_excl.take());

        // The reorg (if one happened) is now fully complete: disconnect,
        // all intermediate reconnections, and the final tip-extending
        // connect have all committed. Now reconcile mempool against the
        // new chain *before* persisting the reorg record:
        //
        // 1. For each intermediate side-chain block that reconnected,
        //    evict mempool txs whose inputs are now spent by it. The
        //    final triggering block's `remove_for_block` is the
        //    caller's responsibility (`accept_block` returns Ok).
        //
        // 2. Re-offer disconnected-block transactions to the mempool.
        //    Validation runs against the live chain — at this point
        //    the tip is the final new chain tip — so a tx that
        //    conflicts with any reconnected side-chain block is
        //    rejected by `accept_transaction` rather than admitted.
        //
        // The reorg record is persisted after the mempool reconcile so
        // operators see a fully-consistent state when the record
        // appears in `getreorghistory`.
        // Mempool reconcile, performed *before* BlockConnected is
        // emitted so the address-index notifier and any other chain
        // subscribers see a mempool that already reflects the
        // confirmations from this block. Without this ordering, a
        // subscriber reacting to BlockConnected could observe a tx
        // both as "confirmed at this height" (from the chain) and as
        // "still mempool" (because the post-accept caller hasn't run
        // remove_for_block yet) and emit an impossible intermediate
        // status hash.
        if let Some(mempool) = self.mempool.get() {
            if let Some(pending) = pending_reorg.as_ref() {
                // Pass each side block's actual height — passing
                // new_tip_height here would mis-report confirmation
                // heights to mempool-event subscribers, who would see
                // every intermediate-block confirmation labelled with
                // the final tip height.
                for (side_block, side_height) in &pending.reconnected_blocks {
                    mempool.remove_for_block(side_block, *side_height);
                }
            }
            // Triggering block's mempool cleanup. Idempotent with the
            // caller's post-accept_block remove_for_block, so duplicate
            // calls are safe.
            mempool.remove_for_block(block, new_height);

            if let Some(pending) = pending_reorg.as_ref() {
                for tx in &pending.disconnected_txs {
                    let txid = tx.compute_txid();
                    if let Err(e) = mempool.accept_transaction(
                        tx.clone(),
                        self,
                        &*self.script_verifier,
                        crate::mempool::pool::TxSource::Reload,
                        // Reorged-out txs re-enter and quarantine normally; never refused.
                        false,
                    ) {
                        tracing::debug!(
                            %txid,
                            err = ?e,
                            "Reorg: re-add to mempool failed (likely conflict with new chain)"
                        );
                    }
                }
            }
        }

        // Reorg chain-event emission is deferred until here — past
        // the rollback decision points and past the mempool reconcile
        // — so subscribers see events only for a reorg that actually
        // committed. If side-chain reconnect or the triggering block
        // had failed, control returned with `Err` from the matching
        // rollback branch above and these events never fire.
        //
        // Order: BlockDisconnected (newest disconnected first → fork-
        // parent last), then side-chain BlockConnected (oldest first),
        // then the triggering block's BlockConnected. Subscribers can
        // walk the diff top-down and see a fully-consistent chainstate
        // + mempool by the time each event lands.
        if let Some(pending) = pending_reorg.take() {
            // First-class reorg marker, emitted once before the per-block
            // disconnect/connect sequence so subscribers have an explicit
            // fork-point signal (rather than inferring one). The new tip is
            // the triggering block.
            self.emit_chain_event(crate::chain::events::ChainEvent::Reorg {
                from_height: pending.old_height,
                old_tip: pending.old_tip,
                to_height: new_height,
                new_tip: block_hash,
            });
            for (hash, height) in &pending.original_disconnected {
                self.emit_chain_event(
                    crate::chain::events::ChainEvent::BlockDisconnected {
                        hash: *hash,
                        height: *height,
                    },
                );
            }
            for (side_block, side_height) in &pending.reconnected_blocks {
                self.emit_chain_event(crate::chain::events::ChainEvent::BlockConnected {
                    hash: side_block.block_hash(),
                    height: *side_height,
                });
            }

            if let Some(log) = self.reorg_log.get() {
                let mut reconnected = pending.reconnected_so_far;
                reconnected.push(block_hash);
                let record = crate::chain::reorg_log::ReorgRecord::new(
                    pending.fork_height,
                    pending.old_tip,
                    block_hash,
                    pending.old_height,
                    pending.disconnected,
                    reconnected,
                );
                log.record(record);
            }
        }

        // Update MTP cache with this block's timestamp
        self.push_mtp_cache(new_height, block.header.time);

        // Notify the address-index notifier (and any future
        // observability subscribers) that the triggering block is in
        // place. Best-effort: emission never blocks the connect path.
        // Mempool reconcile above ensures subscribers don't see the
        // pre-cleanup mempool.
        self.emit_chain_event(crate::chain::events::ChainEvent::BlockConnected {
            hash: block_hash,
            height: new_height,
        });

        tracing::info!(
            height = new_height,
            hash = %block_hash,
            txs = block.txdata.len(),
            "Block connected"
        );

        // Mitigation for the FRESH-elision-on-failed-reorg bug (#262).
        // Outside IBD, flush the coin cache after every connected block so
        // freshly-created coins become durable — and lose their FRESH
        // (elidable) status — before any *subsequent* block can trigger a
        // reorg that disconnects them. The bug needs a multi-block dirty
        // window at the tip: a still-FRESH coin disconnected by a reorg
        // turns into `Spent { fresh: true }` and is elided at the next
        // flush, silently dropping a live coin. At the tip this is one
        // flush per block (~10 min on mainnet), negligible cost. During
        // IBD/reindex the connector loop's threshold-gated flush governs
        // instead and this is skipped, since `block` is the new tip its
        // timestamp is the tip time. A flush failure here does not
        // un-connect the block (it is already committed), so we log loudly
        // and continue rather than returning a misleading error — the
        // coins remain in cache for the next flush attempt.
        if !Self::tip_time_is_ibd(block.header.time)
            && let Err(e) = self.store.flush()
        {
            tracing::error!(
                error = %e,
                height = new_height,
                hash = %block_hash,
                "Per-block coin-cache flush failed after tip connect (#262 mitigation); coins remain dirty in cache"
            );
        }

        // Keep the best-header pointer at least as high as the active tip.
        // Locally-mined / directly-connected blocks never pass through
        // `accept_header`, so without this the pointer would lag the tip after
        // mining and `missing_blocks_for_best_header_chain` would compare
        // against a stale work value.
        self.update_best_header(block_hash, new_chainwork);

        Ok(block_hash)
    }

    /// Abort an in-progress reorg atomically and infallibly (issue #262).
    ///
    /// Precondition: the caller flushed the pre-reorg active chain to the
    /// inner store before starting the reorg (see the checkpoint flush in
    /// `accept_block`), so the inner store holds the exact pre-reorg
    /// chainstate and every reorg write so far lives only in the coin
    /// cache. This drops that entire uncommitted cache delta and restores
    /// the in-memory tip to the pre-reorg tip.
    ///
    /// Unlike the previous `rollback_partial_reorg`, this performs no
    /// block-body replay and cannot fail — the failure mode that silently
    /// dropped FRESH coins (a rollback reconnect that itself errored with
    /// "block data missing", leaving disconnected-but-FRESH coins elided)
    /// is structurally impossible here.
    fn abort_reorg(&self, old_tip: BlockHash, old_height: u32) {
        self.store.discard_uncommitted();
        let mut tip = self.tip.write();
        tip.hash = old_tip;
        tip.height = old_height;
    }

    /// Disconnect blocks from current tip down to the fork point (parent of the new chain).
    /// All disconnections are batched into a single atomic write.
    fn perform_reorg(
        &self,
        fork_entry: &BlockIndexEntry,
        old_tip: BlockHash,
    ) -> Result<ReorgDisconnectInfo, ChainError> {
        let trace_id = rand::random::<u32>();
        let _span = tracing::info_span!(
            "reorg",
            trace_id = trace_id,
            old_tip = %old_tip,
            fork_height = fork_entry.height
        )
        .entered();
        let fork_hash = fork_entry.header.block_hash();
        let mut current = old_tip;
        let mut combined_batch = crate::storage::StoreBatch::default();
        let mut disconnected_hashes: Vec<BlockHash> = Vec::new();
        // Per-block non-coinbase txs collected newest-disconnect-first.
        // We hold them in nested vecs so we can reverse the *block*
        // order without scrambling intra-block tx order — chained tx
        // graphs within a block need parents-before-children preserved.
        let mut disconnected_txs_by_block: Vec<Vec<bitcoin::Transaction>> = Vec::new();
        // (hash, height) pairs for the disconnect chain-event emission.
        // Captured during walk-back so we can emit in walk-back order
        // after commit (matching the canonical "disconnect old → connect
        // new" ordering Electrum/Esplora consumers expect).
        let mut disconnected_with_height: Vec<(BlockHash, u32)> = Vec::new();
        let old_height = self
            .store
            .get_block_index(&old_tip)
            .map(|e| e.height)
            .unwrap_or(fork_entry.height);

        // Walk back from old tip to fork point, accumulating disconnect batches
        loop {
            if current == fork_hash {
                break;
            }

            let entry = self.store.get_block_index(&current)
                .ok_or(ChainError::BadPrevBlock)?;

            let block = self.get_block(&current)
                .ok_or(ChainError::FlatFile("block data missing for reorg".to_string()))?;

            let undo = self.store.get_undo(&current)
                .ok_or(ChainError::FlatFile("undo data missing for reorg".to_string()))?;

            let prev_hash = entry.header.prev_blockhash;
            let batch = disconnect::disconnect_block(
                &block,
                &undo,
                entry.height,
                prev_hash,
                &self.address_index,
                #[cfg(feature = "block-filter-index")]
                &self.filter_index,
                &self.sp_index,
            )?;
            combined_batch.merge(batch);

            // Capture non-coinbase txs for mempool re-add, in block
            // order. Block order is preserved so a child tx in the same
            // block doesn't get re-offered before its parent.
            let block_txs: Vec<bitcoin::Transaction> =
                block.txdata.iter().skip(1).cloned().collect();
            disconnected_txs_by_block.push(block_txs);

            disconnected_hashes.push(current);
            disconnected_with_height.push((current, entry.height));
            tracing::info!(height = entry.height, hash = %current, "Block disconnected");
            current = prev_hash;
        }

        // Atomic commit of all disconnections
        self.store.write_batch(combined_batch)?;

        // Update in-memory tip to fork point
        {
            let mut tip = self.tip.write();
            tip.hash = fork_hash;
            tip.height = fork_entry.height;
        }

        // Block order: walk reversed so oldest disconnected block comes
        // first (parents-before-children across blocks). Tx order
        // within each block is preserved.
        //
        // We deliberately do NOT re-add inside perform_reorg: re-adding
        // here would validate against the fork-point UTXO set, not the
        // final post-reorg active chain. A side-chain block reconnected
        // after this call could spend the same input as a re-added tx,
        // leaving an invalid tx in the mempool. The caller in
        // `connect_tip` performs the re-add after all reconnects.
        disconnected_txs_by_block.reverse();
        let disconnected_txs: Vec<bitcoin::Transaction> =
            disconnected_txs_by_block.into_iter().flatten().collect();

        // NOTE: We deliberately do NOT persist a reorg record here. The
        // caller knows the real new-tip and the full reconnected list;
        // recording at this point would stamp fork_hash as "new tip"
        // and leave reconnected empty — misleading for operators.
        //
        // We also deliberately do NOT emit `BlockDisconnected` chain
        // events here. Emitting inline would notify subscribers about
        // a tentative state that the reorg may still roll back if a
        // later reconnect fails. `connect_tip` emits the staged
        // events at the end of a successful reorg.
        Ok(ReorgDisconnectInfo {
            old_tip,
            old_height,
            disconnected: disconnected_hashes,
            disconnected_with_height,
            disconnected_txs,
        })
    }
    // --- invalidateblock / reconsiderblock (Bitcoin Core parity) ----------

    /// Mark `hash` (and every data-carrying descendant) invalid, then
    /// re-activate the best remaining valid chain — Bitcoin Core's
    /// `invalidateblock`.
    ///
    /// If `hash` is on the active chain, the active chain is rolled back past
    /// it and the best connectable valid chain becomes the new tip — that may
    /// be just the invalid block's parent (a pure truncation) or a competing
    /// side chain that now carries the most work. The `Invalid` mark is
    /// persisted in the block index, so the block is never reconnected until a
    /// matching [`Self::reconsider_block`] clears it. If `hash` was only on a
    /// side chain the active tip is unaffected.
    ///
    /// Returns [`ChainError::BlockNotFound`] for an unknown hash and
    /// [`ChainError::InvalidArgument`] when asked to invalidate genesis.
    pub fn invalidate_block(&self, hash: BlockHash) -> Result<(), ChainError> {
        let _accept_guard = self.accept_lock.lock();

        let entry = self
            .store
            .get_block_index(&hash)
            .ok_or(ChainError::BlockNotFound)?;

        if entry.height == 0 {
            return Err(ChainError::InvalidArgument(
                "cannot invalidate the genesis block".to_string(),
            ));
        }

        // AssumeUTXO: while a snapshot is loaded this chainstate connected no
        // blocks at/below `snapshot_height` (its UTXO base IS the snapshot), so
        // it holds no undo data to roll them back. Refuse to invalidate a block
        // whose rollback would reach at/below the snapshot height — the same
        // guard `accept_block`'s reorg path enforces — rather than failing
        // mid-disconnect on missing undo. The background chainstate validates
        // that buried history.
        if let Some(bg) = self.background()
            && entry.height <= bg.snapshot_height()
        {
            return Err(ChainError::InvalidArgument(format!(
                "cannot invalidate a block at or below the AssumeUTXO snapshot height ({})",
                bg.snapshot_height()
            )));
        }

        // Flush block-index writes still buffered in the coin cache to the
        // inner store: the full-index scans below (`for_each_block_index` does
        // not overlay the cache's `pending_batch`) must see a consistent view,
        // or a descendant that exists only in the pending batch would be
        // missed by `mark_subtree_invalid`.
        self.store.flush()?;

        // Mark the block + every descendant invalid and PERSIST it BEFORE
        // touching the active chain. This is now safe because `get_block`
        // serves an invalidated block's data, so the subsequent disconnect can
        // still read the blocks it rolls back. Marking first means a crash
        // mid-operation can never leave a durably-truncated tip whose
        // disconnected block is still `Valid` — a state that would silently
        // re-activate and reverse the invalidation on the next block.
        self.mark_subtree_invalid(hash)?;

        // Re-activate the best valid chain. If `hash` was on the active chain
        // the current tip is now invalid (a descendant of `hash`), so the best
        // valid candidate differs and a reorg follows — a pure truncation to
        // the parent, or onto a competing side chain that now carries more
        // work. If `hash` was only on a side chain the active tip stays best
        // and this is a no-op.
        self.activate_best_chain()
    }

    /// Clear the `Invalid` mark on `hash` and its descendants, then
    /// re-activate the best valid chain — Bitcoin Core's `reconsiderblock`.
    /// If the reconsidered chain now carries the most work it becomes the
    /// active tip. Unknown hashes return [`ChainError::BlockNotFound`].
    /// Reconsidering a block that was never invalidated is a no-op success.
    pub fn reconsider_block(&self, hash: BlockHash) -> Result<(), ChainError> {
        let _accept_guard = self.accept_lock.lock();

        if self.store.get_block_index(&hash).is_none() {
            return Err(ChainError::BlockNotFound);
        }

        // See `invalidate_block`: flush so the full-index subtree scan sees a
        // view consistent with `get_block_index`.
        self.store.flush()?;

        self.clear_subtree_invalid(hash)?;
        self.activate_best_chain()
    }

    /// Self-heal an active tip that is durably marked `Invalid` — the state a
    /// crash leaves behind if it strikes `invalidate_block` after the subtree
    /// was marked but before the re-activation committed. Re-activates the best
    /// valid chain, which disconnects the invalid blocks and moves the tip to a
    /// valid ancestor (or a competing chain). A cheap no-op when the tip is
    /// valid (the normal case), so it is safe to call unconditionally at
    /// startup. Without this, a node could boot with its tip on an invalidated
    /// block and reject every extension as `bad-prevblk`.
    pub fn reconcile_invalid_tip(&self) -> Result<(), ChainError> {
        let tip = self.tip_hash();
        let invalid = self
            .store
            .get_block_index(&tip)
            .map(|e| e.status == BlockStatus::Invalid)
            .unwrap_or(false);
        if !invalid {
            return Ok(());
        }
        tracing::warn!(
            %tip,
            "Active tip is marked Invalid (crash during invalidateblock?); re-activating the best valid chain"
        );
        let _accept_guard = self.accept_lock.lock();
        self.activate_best_chain()
    }

    /// Build a `prev_blockhash -> [children]` adjacency map over the entire
    /// block index. O(N) — acceptable for the rare, operator-driven
    /// invalidate/reconsider paths. Used to walk a block's descendant subtree.
    fn block_index_children(
        &self,
    ) -> Result<std::collections::HashMap<BlockHash, Vec<BlockHash>>, ChainError> {
        let mut children: std::collections::HashMap<BlockHash, Vec<BlockHash>> =
            std::collections::HashMap::new();
        self.store.for_each_block_index(&mut |h, entry| {
            children
                .entry(entry.header.prev_blockhash)
                .or_default()
                .push(h);
        })?;
        Ok(children)
    }

    /// Mark `root` and all of its descendants `Invalid` (Core's
    /// FAILED_VALID + FAILED_CHILD). `Pruned` descendants are left alone.
    fn mark_subtree_invalid(&self, root: BlockHash) -> Result<(), ChainError> {
        let children = self.block_index_children()?;
        let mut batch = crate::storage::StoreBatch::default();
        let mut stack = vec![root];
        while let Some(h) = stack.pop() {
            if let Some(mut e) = self.store.get_block_index(&h)
                && e.status != BlockStatus::Invalid
                && e.status != BlockStatus::Pruned
            {
                e.status = BlockStatus::Invalid;
                batch.block_index_puts.push((h, e));
            }
            if let Some(cs) = children.get(&h) {
                stack.extend(cs.iter().copied());
            }
        }
        // `write_batch` updates the block-index LRU in lock-step (an Invalid
        // write is never HeaderOnly, so the dominance filter never drops it).
        if !batch.block_index_puts.is_empty() {
            self.store.write_batch(batch)?;
        }
        Ok(())
    }

    /// Clear the `Invalid` mark on `root` and its descendants, restoring each
    /// to `DataStored` (carries block data) or `HeaderOnly` (`num_tx == 0`,
    /// i.e. a header we never had the block for). `connect_block` re-stamps
    /// `Valid` if the block is reconnected by the following re-activation.
    fn clear_subtree_invalid(&self, root: BlockHash) -> Result<(), ChainError> {
        let children = self.block_index_children()?;
        let mut batch = crate::storage::StoreBatch::default();
        let mut stack = vec![root];
        while let Some(h) = stack.pop() {
            if let Some(mut e) = self.store.get_block_index(&h)
                && e.status == BlockStatus::Invalid
            {
                // A HeaderOnly entry has num_tx == 0 (no block ever has zero
                // transactions — the coinbase is mandatory), so this exactly
                // recovers the pre-invalidation data/no-data distinction.
                e.status = if e.num_tx == 0 {
                    BlockStatus::HeaderOnly
                } else {
                    BlockStatus::DataStored
                };
                batch.block_index_puts.push((h, e));
            }
            if let Some(cs) = children.get(&h) {
                stack.extend(cs.iter().copied());
            }
        }
        if !batch.block_index_puts.is_empty() {
            self.store.write_batch(batch)?;
        }
        Ok(())
    }

    /// Whether `entry`'s entire ancestry back to the active chain (or genesis)
    /// is present and non-invalid — i.e. it could be connected right now. Used
    /// by [`Self::find_best_valid_tip`] to skip candidates whose path has a
    /// gap (a `HeaderOnly`/`Invalid`/missing ancestor).
    fn is_connectable(&self, entry: &BlockIndexEntry) -> Result<bool, ChainError> {
        let mut h = entry.header.block_hash();
        let mut height = entry.height;
        loop {
            // Reached the active chain — everything below is connected.
            if self.active_chain_hash_at_height(height) == Some(h) {
                return Ok(true);
            }
            let e = match self.store.get_block_index(&h) {
                Some(e) => e,
                None => return Ok(false),
            };
            if !matches!(e.status, BlockStatus::DataStored | BlockStatus::Valid) {
                return Ok(false);
            }
            if height == 0 {
                // Genesis is always on the active chain.
                return Ok(true);
            }
            h = e.header.prev_blockhash;
            height -= 1;
        }
    }

    /// The data-carrying, non-invalid, fully-connectable block with the most
    /// chainwork — the chain we should be on. Returns the current active tip
    /// when nothing connectable beats it (consensus first-seen tie rule:
    /// equal-work side chains never displace the active tip). When the active
    /// tip is itself invalid (just invalidated), the best connectable
    /// alternative is returned unconditionally.
    fn find_best_valid_tip(&self) -> Result<BlockIndexEntry, ChainError> {
        let current_tip = self.tip_hash();
        let tip_entry = self
            .store
            .get_block_index(&current_tip)
            .ok_or(ChainError::BadPrevBlock)?;
        let tip_valid = matches!(
            tip_entry.status,
            BlockStatus::DataStored | BlockStatus::Valid
        );

        let mut candidates: Vec<BlockIndexEntry> = Vec::new();
        self.store.for_each_block_index(&mut |_h, e| {
            if matches!(e.status, BlockStatus::DataStored | BlockStatus::Valid) {
                candidates.push(e);
            }
        })?;
        // Most chainwork first; ties broken by hash for determinism (the
        // iteration order of `for_each_block_index` is unspecified).
        candidates.sort_by(|a, b| match compare_u256(&a.chainwork, &b.chainwork) {
            1 => std::cmp::Ordering::Less,
            -1 => std::cmp::Ordering::Greater,
            _ => a.header.block_hash().cmp(&b.header.block_hash()),
        });

        for cand in &candidates {
            let ch = cand.header.block_hash();
            if ch == current_tip {
                // The active tip is the best connectable block (or the
                // highest-work of a tie we won't switch away from): stay.
                return Ok(cand.clone());
            }
            if tip_valid && compare_u256(&cand.chainwork, &tip_entry.chainwork) <= 0 {
                // No remaining candidate has strictly more work than the
                // still-valid tip — keep it.
                return Ok(tip_entry);
            }
            if self.is_connectable(cand)? {
                return Ok(cand.clone());
            }
        }
        // Unreachable in practice when the tip was invalidated: the fork
        // parent is always a connectable candidate. Falls back to the tip.
        Ok(tip_entry)
    }

    /// Connect the best available valid chain if it differs from the current
    /// tip (Core's ActivateBestChain, scoped to candidates already present
    /// locally). Caller must hold `accept_lock`.
    fn activate_best_chain(&self) -> Result<(), ChainError> {
        let best = self.find_best_valid_tip()?;
        if best.header.block_hash() == self.tip_hash() {
            return Ok(());
        }
        self.reorg_to(&best)
    }

    /// Find the common ancestor (fork point) of the active tip and `target`
    /// by walking both back via `prev_blockhash`. Immune to height-index
    /// pollution (consults only immutable `prev_blockhash`/`height`).
    fn find_fork(
        &self,
        tip_entry: &BlockIndexEntry,
        target: &BlockIndexEntry,
    ) -> Result<BlockIndexEntry, ChainError> {
        let mut active_hash = tip_entry.header.block_hash();
        let mut active_height = tip_entry.height;
        let mut side_hash = target.header.block_hash();
        let mut side_height = target.height;

        while active_height > side_height {
            let e = self
                .store
                .get_block_index(&active_hash)
                .ok_or(ChainError::BadPrevBlock)?;
            active_hash = e.header.prev_blockhash;
            active_height -= 1;
        }
        while side_height > active_height {
            let e = self
                .store
                .get_block_index(&side_hash)
                .ok_or(ChainError::BadPrevBlock)?;
            side_hash = e.header.prev_blockhash;
            side_height -= 1;
        }
        while active_hash != side_hash {
            let a = self
                .store
                .get_block_index(&active_hash)
                .ok_or(ChainError::BadPrevBlock)?;
            let s = self
                .store
                .get_block_index(&side_hash)
                .ok_or(ChainError::BadPrevBlock)?;
            active_hash = a.header.prev_blockhash;
            side_hash = s.header.prev_blockhash;
        }
        self.store
            .get_block_index(&active_hash)
            .ok_or(ChainError::BadPrevBlock)
    }

    /// Reorg the active chain onto `target`: disconnect from the current tip
    /// down to the fork point, then reconnect the `target` branch. Reuses the
    /// same #262 atomic-checkpoint discipline as `accept_block`'s reorg path
    /// (pre-reorg flush + flush-exclusion held across the whole mutation, with
    /// `abort_reorg` as the infallible in-cache rollback). Caller must hold
    /// `accept_lock`. `target == fork` is a pure truncation (empty reconnect).
    fn reorg_to(&self, target: &BlockIndexEntry) -> Result<(), ChainError> {
        let current_tip = self.tip_hash();
        let tip_entry = self
            .store
            .get_block_index(&current_tip)
            .ok_or(ChainError::BadPrevBlock)?;
        let fork_entry = self.find_fork(&tip_entry, target)?;
        let fork_hash = fork_entry.header.block_hash();
        let target_hash = target.header.block_hash();

        // AssumeUTXO reorg-depth guard (mirrors `accept_block`): never roll
        // back at/below the snapshot height — this chainstate has no undo data
        // there. Defense-in-depth: `invalidate_block` rejects up front, but
        // `reconsider_block`/`activate_best_chain` reach `reorg_to` directly.
        if let Some(bg) = self.background()
            && fork_entry.height < bg.snapshot_height()
        {
            return Err(ChainError::InvalidArgument(format!(
                "refusing reorg below the AssumeUTXO snapshot height ({})",
                bg.snapshot_height()
            )));
        }

        // Atomic-reorg durable checkpoint (#262): flush the pre-reorg chain so
        // it is the exact rollback target, then hold the flush-exclusion for
        // the whole reorg so no external flush can persist a partial state.
        let excl = self.store.lock_flush_exclusion();
        excl.flush()?;
        let mut reorg_excl = Some(excl);

        // Disconnect from current tip down to the fork point.
        let disconnect_info = match self.perform_reorg(&fork_entry, current_tip) {
            Ok(info) => info,
            Err(e) => {
                self.abort_reorg(current_tip, tip_entry.height);
                return Err(e);
            }
        };

        // Reconnect the target branch fork+1..=target. The collection walk and
        // the per-block connect both run inside the closure so ANY failure is
        // routed through `abort_reorg` rather than stranding a partial chain.
        let mut reconnected_hashes: Vec<BlockHash> = Vec::new();
        let mut reconnected_blocks: Vec<(bitcoin::Block, u32)> = Vec::new();
        let reconnect: Result<(), ChainError> = (|| {
            let mut to_connect = Vec::new();
            let mut hash = target_hash;
            while hash != fork_hash {
                to_connect.push(hash);
                let e = self
                    .store
                    .get_block_index(&hash)
                    .ok_or(ChainError::BadPrevBlock)?;
                hash = e.header.prev_blockhash;
            }
            to_connect.reverse();
            for h in &to_connect {
                let block = self.get_block(h).ok_or(ChainError::FlatFile(
                    "block data missing for reorg connect".to_string(),
                ))?;
                let e = self
                    .store
                    .get_block_index(h)
                    .ok_or(ChainError::BadPrevBlock)?;
                let parent_entry = self
                    .store
                    .get_block_index(&e.header.prev_blockhash)
                    .ok_or(ChainError::BadPrevBlock)?;
                let use_noop = self.should_skip_scripts(e.height);
                let noop = NoopVerifier;
                let verifier: &dyn ScriptVerifier =
                    if use_noop { &noop } else { &*self.script_verifier };
                let mtp = self.get_median_time_past(e.height);
                let flat_pos = FlatFilePos {
                    file_number: e.file_number,
                    data_pos: e.data_pos,
                };
                let batch = connect::connect_block(&connect::ConnectParams {
                    replay_plan: None,
                    store: &*self.store,
                    block: &block,
                    height: e.height,
                    parent_chainwork: &parent_entry.chainwork,
                    flat_pos,
                    script_verifier: verifier,
                    median_time_past: mtp,
                    network: self.network,
                    pre_verified_txs: None,
                    num_threads: 1,
                    precomputed_txids: None,
                    address_index: &self.address_index,
                    sp_index: &self.sp_index,
                    #[cfg(feature = "block-filter-index")]
                    filter_index: &self.filter_index,
                    phase_tracker: None,
                })?;
                self.store.write_batch(batch)?;
                {
                    let mut tip = self.tip.write();
                    tip.hash = *h;
                    tip.height = e.height;
                }
                reconnected_hashes.push(*h);
                reconnected_blocks.push((block, e.height));
            }
            Ok(())
        })();
        if let Err(e) = reconnect {
            self.abort_reorg(disconnect_info.old_tip, disconnect_info.old_height);
            return Err(e);
        }

        // Reorg committed: the cache holds a consistent full-reorg delta.
        // Release the flush-exclusion so the trailing flush + mempool
        // reconcile + event emission run unguarded.
        drop(reorg_excl.take());

        let new_tip = self.tip_hash();
        let new_height = self.tip_height();

        // Mempool reconcile: clear confirmations from each reconnected block,
        // then re-offer the disconnected-block txs against the new chain.
        if let Some(mempool) = self.mempool.get() {
            for (block, height) in &reconnected_blocks {
                mempool.remove_for_block(block, *height);
            }
            for tx in &disconnect_info.disconnected_txs {
                if let Err(e) = mempool.accept_transaction(
                    tx.clone(),
                    self,
                    &*self.script_verifier,
                    crate::mempool::pool::TxSource::Reload,
                    false,
                ) {
                    tracing::debug!(
                        err = ?e,
                        "invalidate/reconsider reorg: mempool re-add failed (likely conflict)"
                    );
                }
            }
        }

        // Chain events, in the canonical order (Reorg marker → disconnect
        // newest-first → reconnect oldest-first).
        self.emit_chain_event(crate::chain::events::ChainEvent::Reorg {
            from_height: disconnect_info.old_height,
            old_tip: disconnect_info.old_tip,
            to_height: new_height,
            new_tip,
        });
        for (hash, height) in &disconnect_info.disconnected_with_height {
            self.emit_chain_event(crate::chain::events::ChainEvent::BlockDisconnected {
                hash: *hash,
                height: *height,
            });
        }
        for (block, height) in &reconnected_blocks {
            self.emit_chain_event(crate::chain::events::ChainEvent::BlockConnected {
                hash: block.block_hash(),
                height: *height,
            });
        }

        if let Some(log) = self.reorg_log.get() {
            let record = crate::chain::reorg_log::ReorgRecord::new(
                fork_entry.height,
                disconnect_info.old_tip,
                new_tip,
                disconnect_info.old_height,
                disconnect_info.disconnected.clone(),
                reconnected_hashes.clone(),
            );
            log.record(record);
        }

        for (block, height) in &reconnected_blocks {
            self.push_mtp_cache(*height, block.header.time);
        }

        // Durably commit the new chainstate (the operator-driven reorg is rare
        // and deliberate; flushing keeps the on-disk tip consistent and closes
        // the multi-block FRESH-elision window of #262). A flush failure does
        // not un-commit the in-memory reorg, so log loudly and continue.
        if let Err(e) = self.store.flush() {
            tracing::error!(
                error = %e,
                new_tip = %new_tip,
                "Coin-cache flush failed after invalidate/reconsider reorg; coins remain dirty in cache"
            );
        }

        tracing::info!(
            old_tip = %disconnect_info.old_tip,
            old_height = disconnect_info.old_height,
            %new_tip,
            new_height,
            "invalidate/reconsider: activated best valid chain"
        );
        Ok(())
    }

    /// Prune old block data files whose blocks are deep enough in the chain.
    /// `keep_blocks` is the number of recent blocks to keep data for.
    /// Returns the number of files deleted.
    pub fn prune_blocks(&self, keep_blocks: u32) -> u32 {
        let tip_height = self.tip_height();
        if tip_height <= keep_blocks {
            return 0;
        }
        let prune_below = tip_height - keep_blocks;

        // Collect file_numbers used by pruneable blocks (height <= prune_below)
        let mut pruneable_files: std::collections::HashMap<u32, Vec<(BlockHash, u32)>> =
            std::collections::HashMap::new();
        for h in 0..=prune_below {
            if let Some(hash) = self.store.get_block_hash_by_height(h)
                && let Some(entry) = self.store.get_block_index(&hash)
                && entry.status == BlockStatus::Valid
            {
                pruneable_files
                    .entry(entry.file_number)
                    .or_default()
                    .push((hash, h));
            }
        }

        // Collect file_numbers used by recent blocks (must NOT be deleted)
        let mut keep_files: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for h in (prune_below + 1)..=tip_height {
            if let Some(hash) = self.store.get_block_hash_by_height(h)
                && let Some(entry) = self.store.get_block_index(&hash)
            {
                keep_files.insert(entry.file_number);
            }
        }

        let mut deleted = 0u32;
        let mut flat_files = self.flat_files.lock();
        let mut batch = crate::storage::StoreBatch::default();

        for (file_num, blocks) in &pruneable_files {
            // Only delete files that have NO recent blocks in them
            if keep_files.contains(file_num) {
                continue;
            }
            // Only delete if the file actually exists (not already pruned)
            if !flat_files.file_exists(*file_num) {
                continue;
            }
            if let Err(e) = flat_files.delete_file(*file_num) {
                tracing::warn!(file = file_num, "Failed to delete block file: {}", e);
                continue;
            }
            // Mark all blocks in this file as Pruned
            for (hash, height) in blocks {
                if let Some(mut entry) = self.store.get_block_index(hash) {
                    entry.status = BlockStatus::Pruned;
                    batch.block_index_puts.push((*hash, entry));
                }
                tracing::debug!(file = file_num, height, "Block data pruned");
            }
            deleted += 1;
            tracing::info!(file = file_num, "Deleted block file");
        }
        drop(flat_files);

        if !batch.block_index_puts.is_empty()
            && let Err(e) = self.store.write_batch(batch)
        {
            tracing::error!("Failed to update block index after pruning: {}", e);
        }

        deleted
    }

    /// Check if a block has been pruned.
    pub fn is_pruned(&self, hash: &BlockHash) -> bool {
        self.store
            .get_block_index(hash)
            .map(|e| e.status == BlockStatus::Pruned)
            .unwrap_or(false)
    }
}

/// Read-side surface for the silent-payment tweak index (the
/// `getsilentpaymentblockdata` RPC, the streaming `tweaks` category replay,
/// and the D4 rescan fast path). Backed by the same durable rows the connect
/// path commits atomically with the chainstate.
impl node_sp_index::SpIndex for ChainState {
    fn tweaks_at(&self, height: u32) -> Result<node_sp_index::SpBlockRow, node_sp_index::SpIndexError> {
        if !self.sp_index.enabled {
            return Err(node_sp_index::SpIndexError::Disabled);
        }
        // Checked read: distinguish a genuine absence (NotFound) from a storage
        // or decode failure (Storage). A silent skip on a real error would leave
        // an undetectable gap in an unclamped tweaks-only cold-sync.
        match self.store.get_sp_tweaks_row_checked(height) {
            Ok(Some(row)) => Ok(row),
            Ok(None) => Err(node_sp_index::SpIndexError::NotFound(height)),
            Err(e) => Err(node_sp_index::SpIndexError::Storage(e.to_string())),
        }
    }

    fn activation_height(&self) -> u32 {
        // The trait contract is "the lowest height that carries a tweak row",
        // which is the same floor the backfill walks from and the same floor
        // `connect_block` emits at — including the `.max(1)`. Genesis IS
        // connected through `connect_block` (see `ChainState::new`), so on the
        // chains where taproot is active from height 0 the `.max(1)` is what
        // keeps a height-0 row from existing on one path and not the other;
        // it is not merely defensive. Sharing the definition keeps all three
        // from drifting the way the progress origin did.
        crate::index::silent_payments::walk_start(self.network)
    }

    fn is_complete(&self) -> bool {
        if !self.sp_index.enabled || !self.store.silent_payment_index_complete() {
            return false;
        }
        // The marker alone is not authoritative: it is stamped at open time and
        // can outlive a subsequent backfill that is still running or has failed.
        // A redundant backfill on an already-complete datadir that hits a reorg
        // fails mid-walk, and its stale-row cleanup can punch holes while the
        // marker stays set — so serving off the marker alone would stream a
        // gapped index unclamped (silently dropping heights for scanning
        // clients). Require the backfill cursor to be quiescent (Idle or
        // Completed) too, mirroring `render_status`'s `synced` gate so the
        // serving surface and the `getindexinfo` status can never disagree.
        use node_sp_index::cursor::BackfillState;
        matches!(
            self.store.read_sp_backfill_cursor().state,
            BackfillState::Idle | BackfillState::Completed
        )
    }
}

/// One flat-file record located by the phase-1 scan of a from-genesis
/// reindex: the parsed 80-byte header, plus where the full block lives.
struct ReindexHeaderRef {
    header: bitcoin::block::Header,
    pos: FlatFilePos,
}

/// What a from-genesis reindex should replay, as decided by
/// [`ChainState::plan_reindex_chain`] over the phase-1 block tree.
struct ReindexPlan {
    /// The most-work branch's blocks in connect order, genesis excluded.
    path: Vec<BlockHash>,
    /// Height of that branch's tip — the connect target for progress/ETA.
    tip_height: u32,
    /// Genesis-reachable blocks off that branch, as `(hash, height,
    /// chainwork-relative-to-genesis)`. Indexed but never connected.
    side: Vec<(BlockHash, u32, [u8; 32])>,
}

/// Compare two big-endian U256 values. Returns -1, 0, or 1.
pub(crate) fn compare_u256(a: &[u8; 32], b: &[u8; 32]) -> i32 {
    for i in 0..32 {
        if a[i] > b[i] {
            return 1;
        }
        if a[i] < b[i] {
            return -1;
        }
    }
    0
}

/// Summary returned by [`ChainState::dump_utxo_snapshot`].
#[derive(Debug, Clone)]
pub struct DumpSummary {
    pub coins_written: u64,
    pub base_hash: BlockHash,
    pub base_height: u32,
    pub path: PathBuf,
    /// Bitcoin Core's `hash_serialized_3` value over the dumped UTXO
    /// set — the double SHA-256 (`HashWriter::GetHash()`) over the
    /// `TxOutSer` stream from `kernel/coinstats.cpp`, byte-reversed to
    /// the `uint256` display form. This is what Core's `dumptxoutset`
    /// reports as `txoutset_hash`, and the value stored in
    /// `m_assumeutxo_data.hash_serialized` for the corresponding
    /// height. **Not** the SHA-256 of the snapshot file bytes.
    pub hash_serialized_3: [u8; 32],
}

/// Errors raised by [`ChainState::dump_utxo_snapshot`].
#[derive(Debug, thiserror::Error)]
pub enum DumpError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("storage error: {0}")]
    Store(#[from] StoreError),
    #[error("refusing to overwrite existing file: {0}")]
    RefuseOverwrite(PathBuf),
    #[error("coin count mismatch (expected {expected}, wrote {actual})")]
    CountMismatch { expected: u64, actual: u64 },
}

/// Inner streaming state for [`ChainState::dump_utxo_snapshot_inner`].
/// Holds the per-txid grouping buffer, the HASH_SERIALIZED_3 engine,
/// and a place to park I/O errors that occur inside the iteration
/// closure.
struct DumpState<'w> {
    writer: &'w mut BufWriter<File>,
    hs3_engine: bitcoin::hashes::sha256::HashEngine,
    txout_buf: Vec<u8>,
    current_txid: Option<bitcoin::Txid>,
    current_group: Vec<(u32, Coin)>,
    coins_written: u64,
    out_err: Option<DumpError>,
}

impl DumpState<'_> {
    fn visit(&mut self, op: &OutPoint, coin: &Coin) {
        if self.out_err.is_some() {
            return;
        }

        // Group by txid. The store cursor yields keys in
        // `(txid, vout_le)` order — vout is the 4-byte LE encoding in
        // satd's coins CF key. That is NOT the order Core's coins DB
        // uses: Core encodes vout as a VARINT in the key, so its cursor
        // (and therefore both the snapshot file layout and the
        // order-dependent hash_serialized_3 stream) visits a txid's
        // outputs in *integer* vout order. The two agree for vout < 256
        // but diverge above. We buffer the whole group and re-sort by
        // integer vout in `emit_current_group` before emitting — both
        // the file bytes and the hash feed happen there, in Core's
        // order. Feeding the hash here (in cursor order) is what made
        // the 840k cross-validation hash mismatch for the ~157k txids
        // with vout >= 256.
        if self.current_txid != Some(op.txid) {
            if self.current_txid.is_some()
                && let Err(e) = self.emit_current_group()
            {
                self.out_err = Some(e);
                return;
            }
            self.current_txid = Some(op.txid);
        }
        self.current_group.push((op.vout, coin.clone()));
    }

    fn emit_current_group(&mut self) -> Result<(), DumpError> {
        use crate::storage::compressed_coin as cc;

        let txid = match self.current_txid {
            Some(t) => t,
            None => return Ok(()),
        };

        // Sort by integer vout to match Core's VARINT-keyed cursor
        // order. Load-bearing for both the file layout and the
        // order-dependent hash_serialized_3 (see `visit`).
        self.current_group.sort_by_key(|(vout, _)| *vout);

        // Per Core `WriteUTXOSnapshot`:
        //   txid (32 bytes)
        //   CompactSize(coins.size())
        //   for each coin:
        //     CompactSize(vout)
        //     Coin (TxOutCompression: varint(code) || ...)
        self.writer.write_all(&txid[..])?;
        cc::write_compact_size(self.writer, self.current_group.len() as u64)?;
        for (vout, coin) in &self.current_group {
            // Feed HASH_SERIALIZED_3 in the same (txid, vout-asc) order
            // Core uses. This serialization is distinct from the file's
            // per-coin form; it exists only to match Core's
            // `m_assumeutxo_data.hash_serialized`.
            self.txout_buf.clear();
            let op = OutPoint {
                txid,
                vout: *vout,
            };
            cc::write_txout_ser(&mut self.txout_buf, &op, coin).map_err(DumpError::Io)?;
            bitcoin::hashes::HashEngine::input(&mut self.hs3_engine, &self.txout_buf);

            cc::write_compact_size(self.writer, u64::from(*vout))?;
            cc::serialize_coin(self.writer, coin)?;
        }
        self.coins_written += self.current_group.len() as u64;
        self.current_group.clear();
        Ok(())
    }

    fn flush_final_group(&mut self) -> Result<(), DumpError> {
        if self.current_txid.is_some() {
            self.emit_current_group()?;
            self.current_txid = None;
        }
        Ok(())
    }
}

/// Build the `<path>.incomplete` temp path for the dump.
fn make_incomplete_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".incomplete");
    path.with_file_name(name)
}

/// Move the completed temp file to `final_path` WITHOUT replacing an
/// existing destination.
///
/// `std::fs::rename` would silently overwrite a file created at
/// `final_path` after `dump_utxo_snapshot`'s early `path.exists()` check
/// (POSIX `rename(2)` replaces the target). Instead we hard-link the
/// temp file to `final_path` — `link(2)` fails with `EEXIST` if the
/// target already exists, so an existing `final_path` yields
/// [`DumpError::RefuseOverwrite`] and is never destroyed — then unlink
/// the temp name.
///
/// A single uniform implementation (rather than `renameat2(NOREPLACE)`
/// on glibc) is deliberate: `libc::renameat2` is not exposed for the
/// musl target, and the release binaries we ship are musl-static, so a
/// glibc-only fast path would mean testing a code path we never ship.
/// `final_path` and the `.incomplete` temp share a directory (hence a
/// filesystem), so the link always succeeds when the target is free.
fn finalize_dump_path(temp_path: &Path, final_path: &Path) -> Result<(), DumpError> {
    match std::fs::hard_link(temp_path, final_path) {
        Ok(()) => {
            // The data is already durable at `final_path` via the shared
            // inode; dropping the temp name is best-effort cleanup.
            let _ = std::fs::remove_file(temp_path);
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            Err(DumpError::RefuseOverwrite(final_path.to_path_buf()))
        }
        Err(e) => Err(DumpError::Io(e)),
    }
}

/// RAII guard that removes a temp file on drop unless [`Self::disarm`]
/// has been called. Ensures error paths in `dump_utxo_snapshot` don't
/// leave a `.incomplete` corpse on disk.
struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            // Best-effort: log but don't propagate. The dump operation
            // already returned its error; we're just cleaning up the
            // .incomplete corpse so the operator can retry without
            // manual filesystem surgery.
            let _ = std::fs::remove_file(&path);
        }
    }
}

pub(crate) fn network_magic(network: Network) -> [u8; 4] {
    match network {
        Network::Bitcoin => [0xf9, 0xbe, 0xb4, 0xd9],
        Network::Testnet => [0x0b, 0x11, 0x09, 0x07],
        Network::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
        Network::Signet => [0x0a, 0x03, 0xcf, 0x40],
        Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;

    pub(crate) fn make_chain_state() -> (ChainState, std::path::PathBuf) {
        // A process-wide counter guarantees a unique datadir per call: two
        // tests running on parallel threads can otherwise hit the same
        // `subsec_nanos()` and share a `blocks/` dir, corrupting each other's
        // flat files ("failed to read stored block").
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "satd-chain-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        let blocks_dir = dir.join("blocks");
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap();
        (cs, dir)
    }

    /// Force `height_hash[height] = hash`, simulating a polluted index. Used by
    /// tests that verify consumers stay immune to a `height_hash` that
    /// disagrees with the active chain. (The writers — accept_header(s) and
    /// store_block — no longer produce this state, so tests inject it directly.)
    fn pollute_height_hash(cs: &ChainState, height: u32, hash: BlockHash) {
        let mut batch = crate::storage::StoreBatch::default();
        batch.height_hash_puts.push((height, hash));
        cs.store.write_batch(batch).unwrap();
    }

    /// Mine `n` regtest blocks into `cs` via the proven
    /// accept_header→store_block→connect_stored_block path, returning the
    /// connected blocks in height order.
    fn build_and_connect_chain(cs: &ChainState, n: u32) -> Vec<Block> {
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut parent = genesis.block_hash();
        let mut blocks = Vec::new();
        for h in 1..=n {
            let b = build_test_block(parent, h, 1_300_000_000 + h);
            cs.accept_header(&b.header).unwrap();
            cs.store_block(&b).unwrap();
            cs.connect_stored_block(&b.block_hash()).unwrap();
            parent = b.block_hash();
            blocks.push(b);
        }
        blocks
    }

    /// Truncate the flat file so `hash`'s record can no longer be read,
    /// reproducing the shape of the mainnet-954866 hole: the `block_index`
    /// entry survives and still claims `DataStored`/`Valid`, but the bytes it
    /// points at are gone.
    /// Overwrite a block's stored record in place with different bytes of the
    /// same length. Used to plant a copy that parses but is not canonical.
    fn overwrite_block_record(
        cs: &ChainState,
        dir: &std::path::Path,
        hash: &BlockHash,
        replacement: &Block,
    ) {
        use std::io::{Seek, SeekFrom, Write};
        let entry = cs.get_block_index(hash).expect("entry must exist");
        let bytes = serialize(replacement);
        let path = dir
            .join("blocks")
            .join(format!("blk{:05}.dat", entry.file_number));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open flat file");
        // The 8-byte record header carries the payload length, so rewrite it
        // too rather than assuming the replacement is the same size.
        f.seek(SeekFrom::Start(entry.data_pos as u64 + 4))
            .expect("seek to the size field");
        f.write_all(&(bytes.len() as u32).to_le_bytes())
            .expect("rewrite record size");
        f.write_all(&bytes).expect("rewrite record payload");
        drop(f);
        cs.flat_files
            .lock()
            .resync_append_pos()
            .expect("resync append offset");
    }

    fn punch_block_data_hole(cs: &ChainState, dir: &std::path::Path, hash: &BlockHash) {
        let entry = cs.get_block_index(hash).expect("entry must exist");
        let path = dir
            .join("blocks")
            .join(format!("blk{:05}.dat", entry.file_number));
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open flat file");
        // Cut the file at the record's payload start: the header is readable,
        // the body is not — exactly what a lost page-cache tail leaves behind.
        f.set_len(entry.data_pos as u64 + 8).expect("truncate");
        drop(f);
        // A real crash-truncation is followed by a restart, which derives the
        // append offset from the file length. Do the same here: without it the
        // manager's cached `current_pos` still describes the pre-truncation
        // file and would misreport where the repair's record landed.
        cs.flat_files
            .lock()
            .resync_append_pos()
            .expect("resync append offset as a restart would");
        assert!(
            !cs.block_data_readable(hash),
            "the fixture must actually make the block unreadable"
        );
    }

    /// The durability invariant behind the mainnet-954866 hole: in `Normal`
    /// write mode nothing may leave a `block_index` entry referencing block
    /// bytes that are still only in the page cache. `store_block` and
    /// `accept_block` must therefore hand back a *synced* flat file.
    #[test]
    fn normal_mode_block_writes_are_synced_before_the_index_entry() {
        let (cs, dir) = make_chain_state();
        cs.set_write_mode(crate::storage::WriteMode::Normal);

        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let b1 = build_test_block(genesis.block_hash(), 1, 1_300_000_001);
        cs.accept_header(&b1.header).unwrap();
        cs.store_block(&b1).unwrap();
        assert!(
            !cs.flat_files.lock().has_unsynced_writes(),
            "store_block must fsync the block record before its index entry \
             can reach disk"
        );

        cs.connect_stored_block(&b1.block_hash()).unwrap();
        let b2 = build_test_block(b1.block_hash(), 2, 1_300_000_002);
        cs.accept_block(&b2).unwrap();
        assert!(
            !cs.flat_files.lock().has_unsynced_writes(),
            "accept_block must fsync the block record before its index entry \
             can reach disk"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `BulkLoad` gets the same treatment as `Normal` — deliberately, and this
    /// test exists to stop the exemption from being reintroduced.
    ///
    /// An earlier revision skipped the fsync during IBD, reasoning that
    /// `BulkLoad` disables the WAL so an index entry could only become durable
    /// through `flush_durable`, which syncs the flat files first. That is
    /// wrong: disabling the WAL does not stop RocksDB from flushing a memtable
    /// to an SST on its own, and with `set_atomic_flush(true)` the 64 MB
    /// `coins` write buffer filling during IBD drags `block_index` to disk with
    /// it — while the flat files are only fsync'd every ~1000 blocks. IBD was
    /// the *more* exposed path, not the safe one.
    #[test]
    fn bulkload_mode_block_writes_are_synced_too() {
        let (cs, dir) = make_chain_state();
        cs.set_write_mode(crate::storage::WriteMode::BulkLoad);

        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let b1 = build_test_block(genesis.block_hash(), 1, 1_300_000_001);
        cs.accept_header(&b1.header).unwrap();
        cs.store_block(&b1).unwrap();
        assert!(
            !cs.flat_files.lock().has_unsynced_writes(),
            "BulkLoad must fsync the record too: WAL-less index entries still \
             reach disk on their own via automatic memtable flushes"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The repair must be able to replace bytes that *parse* but are not the
    /// canonical block. Gating on "does `get_block` return something" made the
    /// one corruption this RPC can actually detect — a non-canonical witness,
    /// which leaves the block hash and merkle root intact — unrepairable, so
    /// the tool built for the job could not do it.
    #[test]
    fn repair_block_data_replaces_a_readable_but_noncanonical_copy() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 3);
        let target = blocks[1].clone();
        let hash = target.block_hash();

        // Overwrite the stored record with a witness-mutated copy: identical
        // block hash, identical merkle root, junk appended to the coinbase
        // witness. This is what a hostile peer could have planted.
        let mut forged = target.clone();
        forged.txdata[0].input[0].witness.push([0xde; 64]);
        assert_eq!(forged.block_hash(), hash, "the forgery must be hash-invisible");
        assert_ne!(serialize(&forged), serialize(&target));
        overwrite_block_record(&cs, &dir, &hash, &forged);

        assert!(
            cs.get_block(&hash).is_some(),
            "the forged copy must still be readable — that is the point"
        );
        assert_eq!(
            cs.get_block(&hash).as_ref(),
            Some(&forged),
            "fixture premise: the forged bytes are what is stored"
        );

        let outcome = cs
            .repair_block_data(&target)
            .expect("an honest copy must be accepted over a non-canonical one");
        assert_eq!(outcome, BlockDataRepair::Repaired { height: 2 });
        assert_eq!(
            cs.get_block(&hash).as_ref(),
            Some(&target),
            "the canonical bytes must now be stored"
        );

        // ...and a second repair with the same good copy is a no-op.
        assert_eq!(
            cs.repair_block_data(&target).unwrap(),
            BlockDataRepair::AlreadyPresent { height: 2 }
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A peer offering a non-canonical copy must never displace a good stored
    /// one — validation runs before the "is it already present" question.
    #[test]
    fn repair_block_data_refuses_a_noncanonical_copy_over_a_good_one() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 3);
        let target = blocks[1].clone();
        let hash = target.block_hash();

        let mut forged = target.clone();
        forged.txdata[0].input[0].witness.push([0xde; 64]);

        let err = cs.repair_block_data(&forged).expect_err("must be rejected");
        assert!(
            matches!(err, ChainError::Validation(_)),
            "a witness forgery is peer fault: {err:?}"
        );
        assert_eq!(
            cs.get_block(&hash).as_ref(),
            Some(&target),
            "the good stored copy must be untouched"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The segwit gate is a consensus rule, so the height it is taken from
    /// must be cross-checked against the block's own parent link rather than
    /// trusted from the index this function exists to repair. A disagreement
    /// is refused — and NOT as a validation error, because the peer is not at
    /// fault and must not be banned for our damaged index.
    #[test]
    fn repair_block_data_refuses_when_the_index_height_disagrees_with_the_chain() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 3);
        let target = blocks[1].clone();
        let hash = target.block_hash();

        punch_block_data_hole(&cs, &dir, &hash);

        // Corrupt just the height on the entry, leaving the parent link alone.
        let mut entry = cs.get_block_index(&hash).unwrap();
        entry.height = 999_999;
        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((hash, entry));
        cs.store.write_batch(batch).unwrap();

        let err = cs
            .repair_block_data(&target)
            .expect_err("an inconsistent index must not be repaired against");
        assert!(
            !matches!(err, ChainError::Validation(_)),
            "must not be a validation error — the peer would be banned for it: {err:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repair_block_data_restores_an_unreadable_block() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 3);
        let target = blocks[1].clone();
        let hash = target.block_hash();
        let before = cs.get_block_index(&hash).unwrap();

        punch_block_data_hole(&cs, &dir, &hash);

        let outcome = cs.repair_block_data(&target).expect("repair must succeed");
        assert_eq!(
            outcome,
            BlockDataRepair::Repaired { height: 2 }
        );

        // The block reads back byte-identically, and the entry was repointed
        // without disturbing anything else about it.
        assert_eq!(cs.get_block(&hash).as_ref(), Some(&target));
        let after = cs.get_block_index(&hash).unwrap();
        assert_eq!(after.status, before.status, "status must be preserved");
        assert_eq!(after.height, before.height);
        assert_eq!(after.chainwork, before.chainwork);
        assert_eq!(after.header, before.header);
        assert_ne!(
            (after.file_number, after.data_pos),
            (before.file_number, before.data_pos),
            "the entry must point at the newly written record"
        );

        // The chain is still intact around the repaired height.
        assert_eq!(cs.tip_height(), 3);
        assert_eq!(cs.check_block_index(None), Ok(3));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repair_block_data_is_a_noop_when_the_data_is_readable() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 2);
        let target = blocks[0].clone();
        let before = cs.get_block_index(&target.block_hash()).unwrap();

        assert_eq!(
            cs.repair_block_data(&target).unwrap(),
            BlockDataRepair::AlreadyPresent { height: 1 }
        );
        let after = cs.get_block_index(&target.block_hash()).unwrap();
        assert_eq!(
            (after.file_number, after.data_pos),
            (before.file_number, before.data_pos),
            "a readable block must not be rewritten"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repair_block_data_rejects_a_block_we_never_accepted_a_header_for() {
        let (cs, dir) = make_chain_state();
        build_and_connect_chain(&cs, 1);
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let stranger = build_test_block(genesis.block_hash(), 1, 1_999_999_999);

        assert!(matches!(
            cs.repair_block_data(&stranger),
            Err(ChainError::BlockNotFound)
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The peer supplying the repair copy is untrusted. A body that does not
    /// match the header we already accepted must be refused rather than
    /// written over the hole.
    #[test]
    fn repair_block_data_rejects_a_body_that_does_not_match_the_header() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 2);
        let target = blocks[1].clone();
        let hash = target.block_hash();
        punch_block_data_hole(&cs, &dir, &hash);

        // Keep the authentic header, swap in foreign txdata. The merkle root
        // no longer matches, which is what `check_block` catches.
        let mut forged = target.clone();
        forged.txdata = build_test_block(blocks[0].block_hash(), 2, 1_300_000_777).txdata;
        assert_eq!(
            forged.header, target.header,
            "the fixture keeps the accepted header"
        );

        let err = cs
            .repair_block_data(&forged)
            .expect_err("a mismatched body must be rejected");
        assert!(
            matches!(err, ChainError::Validation(_)),
            "expected a validation failure, got {err:?}"
        );
        assert!(
            !cs.block_data_readable(&hash),
            "a rejected repair must not leave the entry pointing at bad data"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repair_block_data_refuses_invalidated_blocks() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 3);
        let target = blocks[2].clone();
        let hash = target.block_hash();

        cs.invalidate_block(hash).expect("invalidate");
        assert_eq!(
            cs.get_block_index(&hash).unwrap().status,
            BlockStatus::Invalid
        );

        let err = cs
            .repair_block_data(&target)
            .expect_err("an invalidated block must not be repaired");
        assert!(
            matches!(err, ChainError::InvalidArgument(_)),
            "expected InvalidArgument, got {err:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `HeaderOnly` entry is not a data hole, and repairing it would bypass
    /// the checkpoint / signet-solution / invalidated-parent gates that only
    /// `store_block` applies. It must be refused so the block goes through the
    /// normal download path — which also actually connects it.
    #[test]
    fn repair_block_data_refuses_header_only_entries() {
        let (cs, dir) = make_chain_state();
        build_and_connect_chain(&cs, 1);
        let tip = cs.tip_hash();
        let next = build_test_block(tip, 2, 1_300_000_002);
        cs.accept_header(&next.header).unwrap();
        assert_eq!(
            cs.get_block_index(&next.block_hash()).unwrap().status,
            BlockStatus::HeaderOnly
        );

        let err = cs
            .repair_block_data(&next)
            .expect_err("header-only is not a repairable hole");
        assert!(
            matches!(err, ChainError::InvalidArgument(_)),
            "expected InvalidArgument, got {err:?}"
        );
        // Still header-only: the repair must not have written anything.
        assert_eq!(
            cs.get_block_index(&next.block_hash()).unwrap().status,
            BlockStatus::HeaderOnly
        );

        // ...and the normal path still accepts it, which is the point.
        cs.store_block(&next).expect("store_block must accept it");
        cs.connect_stored_block(&next.block_hash()).unwrap();
        assert_eq!(cs.tip_height(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An index entry whose offset lands on a *different* valid record must
    /// read as missing, not as that other block. Deserialization succeeds in
    /// this case, so only a hash check catches it — without one `getblock`
    /// serves the wrong block and the repair path refuses to act.
    #[test]
    fn a_block_index_entry_pointing_at_another_record_reads_as_missing() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 3);
        let victim = blocks[1].block_hash();
        let other = cs.get_block_index(&blocks[2].block_hash()).unwrap();

        // Repoint the height-2 entry at the height-3 block's record.
        let mut entry = cs.get_block_index(&victim).unwrap();
        entry.file_number = other.file_number;
        entry.data_pos = other.data_pos;
        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((victim, entry));
        cs.store.write_batch(batch).unwrap();

        assert!(
            cs.get_block(&victim).is_none(),
            "a record that decodes but is a different block must not be served"
        );
        assert!(
            !cs.block_data_readable(&victim),
            "and it must be reported as a hole so a repair can fix it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_block_index_passes_then_catches_height_map_pollution() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 5);
        assert_eq!(cs.tip_height(), 5);

        // A healthy chain audits clean and reports the tip height.
        assert_eq!(cs.check_block_index(None), Ok(5));

        // Reproduce the 951k reorg corruption: point the height->hash map at
        // the WRONG block for an interior height (height 3 -> the height-5
        // block). The prev-link walk still yields the true chain, so the
        // disagreement must be caught — exactly the divergence that
        // --reindex-chainstate could not detect before it tripped over it as
        // bad-cb-height.
        let wrong = blocks[4].block_hash(); // the block at height 5
        let mut batch = crate::storage::StoreBatch::default();
        batch.height_hash_puts.push((3, wrong));
        cs.store.write_batch(batch).unwrap();

        let err = cs
            .check_block_index(None)
            .expect_err("a polluted height->hash map must fail the audit");
        assert!(
            err.contains("height->hash[3]"),
            "expected a height->hash[3] mismatch, got: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_block_index_catches_stored_height_mismatch() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 4);
        assert_eq!(cs.check_block_index(None), Ok(4));

        // Corrupt the stored height of the height-2 block's index entry.
        let h2 = blocks[1].block_hash();
        let mut entry = cs.get_block_index(&h2).unwrap();
        entry.height = 99;
        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((h2, entry));
        cs.store.write_batch(batch).unwrap();

        let err = cs
            .check_block_index(None)
            .expect_err("a stored-height mismatch must fail the audit");
        assert!(
            err.contains("stored height 99"),
            "expected a stored-height mismatch, got: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refresh_best_header_to_tip_clears_post_reindex_lag() {
        let (cs, dir) = make_chain_state();
        build_and_connect_chain(&cs, 5);
        assert_eq!(cs.check_block_index(None), Ok(5));

        // Reproduce the post-`--reindex` state: the replay advances the active
        // tip but never touches `best_header`, so the pointer is left behind at
        // genesis. The audit must flag the selection pointer lagging the chain
        // (this is what made every reindex integration test hang at startup).
        let genesis = bitcoin::constants::genesis_block(cs.network);
        *cs.best_header.write() = (genesis.block_hash(), work_for_bits(genesis.header.bits));
        let err = cs
            .check_block_index(None)
            .expect_err("a best_header behind the active tip must fail the audit");
        assert!(
            err.contains("best_header"),
            "expected a best_header lag error, got: {err}"
        );

        // The post-reindex re-seed restores the invariant.
        cs.refresh_best_header_to_tip();
        assert_eq!(cs.check_block_index(None), Ok(5));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accept_header_does_not_clobber_active_height_index_with_subtip_fork() {
        // The 951k bad-cb-height root cause: a competing fork announced *below*
        // the active tip was accepted as headers, and the unconditional
        // height->hash write clobbered the active-chain entries at the fork
        // heights (last-write-wins). --reindex-chainstate then replayed the
        // fork's blocks at those heights and aborted on bad-cb-height.
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 5);
        assert_eq!(cs.tip_height(), 5);
        assert_eq!(cs.check_block_index(None), Ok(5));

        let active3 = blocks[2].block_hash(); // active block at height 3
        let active4 = blocks[3].block_hash(); // active block at height 4

        // A peer announces a competing fork branching off the height-2 block,
        // supplying alternative headers at heights 3 and 4 — both at or below
        // our tip of 5. Distinct timestamps yield distinct hashes (the coinbase
        // commits the timestamp), so these are genuinely new headers.
        let fork_parent = blocks[1].block_hash(); // height 2
        let f3 = build_test_block(fork_parent, 3, 1_400_000_003);
        let f4 = build_test_block(f3.block_hash(), 4, 1_400_000_004);
        assert_ne!(f3.block_hash(), active3);
        assert_ne!(f4.block_hash(), active4);

        cs.accept_header(&f3.header).unwrap();
        cs.accept_header(&f4.header).unwrap();

        // The fork headers are still known by hash, so the fork-aware
        // competing-chain pull (#315) can reach them via best_header/prev-links.
        assert!(cs.get_block_index(&f3.block_hash()).is_some());
        assert!(cs.get_block_index(&f4.block_hash()).is_some());

        // But the active-chain height index was NOT clobbered: heights at or
        // below the tip belong exclusively to the connected chain.
        assert_eq!(cs.get_block_hash_by_height(3), Some(active3));
        assert_eq!(cs.get_block_hash_by_height(4), Some(active4));

        // The structural audit stays clean — a subsequent --reindex-chainstate
        // would replay the true active chain, never the fork.
        assert_eq!(cs.check_block_index(None), Ok(5));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_block_does_not_clobber_active_height_index_with_subtip_fork() {
        // The IBD block-store path (`store_block`) is the second door to the
        // same bad-cb-height pollution: a peer relays a valid competing block
        // below the tip, store_block writes its height→hash, and a later
        // --reindex-chainstate replays it at the wrong height.
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 5);
        assert_eq!(cs.tip_height(), 5);
        let active3 = blocks[2].block_hash();

        // A valid block on a fork branching off height 2, so it lands at
        // height 3 (≤ our tip of 5). store_block validates PoW/difficulty/
        // checkpoints and persists it, but must not touch the active height map.
        let f3 = build_test_block(blocks[1].block_hash(), 3, 1_500_000_003);
        assert_ne!(f3.block_hash(), active3);
        let (stored_hash, stored_height) = cs.store_block(&f3).unwrap();
        assert_eq!(stored_height, 3);

        // Stored (reachable by hash) but the active-chain slot is intact.
        assert!(cs.get_block_index(&stored_hash).is_some());
        assert_eq!(cs.get_block_hash_by_height(3), Some(active3));
        assert_eq!(cs.check_block_index(None), Ok(5));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accept_headers_repair_does_not_restore_a_disconnected_block() {
        // The crash-resume repair must not re-point height→hash at a block a
        // reorg disconnected. A Valid block with a missing mapping is exactly
        // that (connect writes status+mapping atomically; disconnect drops the
        // mapping but leaves the status Valid), so the repair is restricted to
        // DataStored. Here we simulate the post-disconnect state by removing the
        // mapping for a Valid block and re-announcing its header.
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 5);
        let h5 = blocks[4].block_hash();
        assert_eq!(cs.get_block_index(&h5).unwrap().status, BlockStatus::Valid);

        let mut batch = crate::storage::StoreBatch::default();
        batch.height_hash_removes.push(5);
        cs.store.write_batch(batch).unwrap();
        assert_eq!(cs.get_block_hash_by_height(5), None);

        // Re-announce the disconnected block's header: the repair branch sees a
        // Valid (not DataStored) block and must leave the mapping absent.
        let (_accepted, err) = cs.accept_headers(&[blocks[4].header]);
        assert!(err.is_none(), "re-announcing a known header should not error: {err:?}");
        assert_eq!(
            cs.get_block_hash_by_height(5),
            None,
            "repair must not restore the mapping for a disconnected Valid block"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accept_header_height_commit_serializes_under_accept_lock() {
        // The above-tip guard must be atomic with block connection: a concurrent
        // accept_block (submitblock/mine) advances the tip under accept_lock, so
        // accept_header must hold the same lock across its test+commit or a
        // header that was above-tip at the test could clobber an entry the tip
        // has since advanced onto. Prove accept_header's commit is gated on
        // accept_lock: while we hold the lock (standing in for an in-progress
        // accept_block), accept_header cannot complete — `done` cannot become
        // true regardless of how far the worker has progressed, because the
        // commit requires the lock. This is deterministic, not timing-dependent.
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 3);
        let h4 = build_test_block(blocks[2].block_hash(), 4, 1_600_000_004);
        let h4_hash = h4.block_hash();
        let done = AtomicBool::new(false);

        std::thread::scope(|s| {
            let guard = cs.accept_lock.lock();
            s.spawn(|| {
                cs.accept_header(&h4.header).expect("accept H4");
                done.store(true, Ordering::SeqCst);
            });
            std::thread::sleep(Duration::from_millis(200));
            assert!(
                !done.load(Ordering::SeqCst),
                "accept_header committed its height write while accept_lock was held"
            );
            drop(guard);
        });

        assert!(done.load(Ordering::SeqCst), "accept_header completes once the lock is free");
        assert_eq!(
            cs.get_block_hash_by_height(4),
            Some(h4_hash),
            "the above-tip header is committed after the lock releases"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Build a `ChainState` over an `InMemoryStore` pre-seeded with a fake
    /// active chain: `num_tx_by_height[i]` is the tx count for the block at
    /// height `i` (index 0 = genesis). No `chain_tx` rows are written, so
    /// the resulting state mimics an upgraded datadir whose cumulative
    /// index hasn't been backfilled. Returns the chain state, its temp dir,
    /// and the per-height block hashes.
    fn chain_state_with_seeded_chain(
        num_tx_by_height: &[u32],
    ) -> (ChainState, std::path::PathBuf, Vec<BlockHash>) {
        let dir = std::env::temp_dir().join(format!(
            "satd-chaintx-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let store = InMemoryStore::new();
        let base_header = bitcoin::constants::genesis_block(Network::Regtest).header;
        let mut batch = crate::storage::StoreBatch::default();
        let mut hashes = Vec::new();
        // Link each block to its predecessor via prev_blockhash so an
        // active-chain ancestor walk (e.g. get_chain_tx_stats) resolves
        // correctly; height 0 keeps the genesis (all-zeros) parent.
        let mut prev_hash = base_header.prev_blockhash;
        for (h, &num_tx) in num_tx_by_height.iter().enumerate() {
            let mut arr = [0u8; 32];
            arr[0] = h as u8;
            arr[1] = (h >> 8) as u8;
            arr[3] = 0x5A; // distinguish from real hashes
            let hash = BlockHash::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array(arr),
            );
            let mut header = base_header;
            header.time = 1_500_000_000 + h as u32 * 600;
            header.prev_blockhash = prev_hash;
            prev_hash = hash;
            let entry = BlockIndexEntry {
                header,
                height: h as u32,
                status: BlockStatus::Valid,
                num_tx,
                file_number: 0,
                data_pos: 0,
                chainwork: [0u8; 32],
            };
            batch.block_index_puts.push((hash, entry));
            batch.height_hash_puts.push((h as u32, hash));
            hashes.push(hash);
        }
        batch.tip = Some(*hashes.last().unwrap());
        store.write_batch(batch).unwrap();

        let blocks_dir = dir.join("blocks");
        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();
        let cs = ChainState::new(
            Box::new(store),
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap();
        (cs, dir, hashes)
    }

    #[test]
    fn cumulative_tx_count_tracks_connects() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 5);

        // Genesis carries 1 tx; expected cumulative climbs by each block's
        // tx count. Verify per height against an independent running sum.
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut expected = genesis.txdata.len() as u64;
        assert_eq!(cs.cumulative_tx_count(&genesis.block_hash()), Some(expected));
        for (i, b) in blocks.iter().enumerate() {
            expected += b.txdata.len() as u64;
            assert_eq!(
                cs.cumulative_tx_count(&b.block_hash()),
                Some(expected),
                "cumulative mismatch at connected block index {i}"
            );
        }
        assert_eq!(cs.cumulative_tx_count(&cs.tip_hash()), Some(expected));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalidate_tip_truncates_then_reconsider_restores() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 5);
        let tip5 = blocks[4].block_hash();
        let block4 = blocks[3].block_hash();
        assert_eq!(cs.tip_height(), 5);
        assert_eq!(cs.tip_hash(), tip5);

        // Invalidating the tip truncates the active chain to its parent.
        cs.invalidate_block(tip5).unwrap();
        assert_eq!(cs.tip_height(), 4);
        assert_eq!(cs.tip_hash(), block4);
        assert_eq!(
            cs.get_block_index(&tip5).unwrap().status,
            BlockStatus::Invalid
        );
        // The block's data is still readable (Core parity + the reorg/watch
        // machinery re-reads a just-disconnected block); only its index status
        // changed.
        assert!(cs.get_block(&tip5).is_some());

        // Reconsidering restores it and re-activates the chain.
        cs.reconsider_block(tip5).unwrap();
        assert_eq!(cs.tip_height(), 5);
        assert_eq!(cs.tip_hash(), tip5);
        assert!(cs.get_block(&tip5).is_some());
        assert_eq!(
            cs.get_block_index(&tip5).unwrap().status,
            BlockStatus::Valid
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalidate_midchain_block_reorgs_to_competing_fork() {
        let (cs, dir) = make_chain_state();
        // Main chain heights 1..=5 (active tip).
        let main = build_and_connect_chain(&cs, 5);
        let block2 = main[1].block_hash(); // fork point (height 2)
        let main3 = main[2].block_hash();

        // Competing fork off block2: heights 3,4,5 with distinct timestamps
        // (so distinct hashes), stored as a side chain of EQUAL work — not
        // auto-selected, so only invalidation can switch us onto it.
        let mut parent = block2;
        let mut side = Vec::new();
        for h in 3..=5 {
            let b = build_test_block(parent, h, 1_400_000_000 + h);
            cs.accept_header(&b.header).unwrap();
            cs.store_block(&b).unwrap();
            parent = b.block_hash();
            side.push(b);
        }
        // Active chain is still the main chain (side has equal work, stored
        // but not connected).
        assert_eq!(cs.tip_hash(), main[4].block_hash());

        // Invalidate main height-3: main 3,4,5 become Invalid and the active
        // chain reorgs onto the side fork.
        cs.invalidate_block(main3).unwrap();
        assert_eq!(cs.tip_height(), 5);
        assert_eq!(cs.tip_hash(), side[2].block_hash());
        // Main 3/4/5 are invalid; side 3'/4'/5' are now Valid (connected).
        for b in &main[2..] {
            assert_eq!(
                cs.get_block_index(&b.block_hash()).unwrap().status,
                BlockStatus::Invalid
            );
        }
        for b in &side {
            assert_eq!(
                cs.get_block_index(&b.block_hash()).unwrap().status,
                BlockStatus::Valid
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalidate_rejects_genesis_and_unknown() {
        let (cs, dir) = make_chain_state();
        build_and_connect_chain(&cs, 2);
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        assert!(matches!(
            cs.invalidate_block(genesis),
            Err(ChainError::InvalidArgument(_))
        ));
        let bogus = BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([7u8; 32]),
        );
        assert!(matches!(
            cs.invalidate_block(bogus),
            Err(ChainError::BlockNotFound)
        ));
        assert!(matches!(
            cs.reconsider_block(bogus),
            Err(ChainError::BlockNotFound)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cannot_extend_an_invalidated_block() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 3);
        let block2 = blocks[1].block_hash();

        // Invalidate height-2: 2 and 3 become Invalid, tip truncates to 1.
        cs.invalidate_block(block2).unwrap();
        assert_eq!(cs.tip_height(), 1);

        // A new block building on the invalidated block2 is rejected.
        let child = build_test_block(block2, 3, 1_500_000_999);
        assert!(matches!(
            cs.store_block(&child),
            Err(ChainError::BadPrevBlock)
        ));
        assert!(matches!(
            cs.accept_block(&child),
            Err(ChainError::BadPrevBlock)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalidate_side_chain_block_leaves_active_tip() {
        let (cs, dir) = make_chain_state();
        let main = build_and_connect_chain(&cs, 3);
        let main_tip = main[2].block_hash();
        let block1 = main[0].block_hash();

        // A shorter side fork off block1 (height 2), stored but never activated.
        let side = build_test_block(block1, 2, 1_700_000_222);
        cs.accept_header(&side.header).unwrap();
        cs.store_block(&side).unwrap();
        assert_eq!(cs.tip_hash(), main_tip, "side store does not change the tip");

        // Invalidating a side-chain block must not touch the active chain.
        cs.invalidate_block(side.block_hash()).unwrap();
        assert_eq!(cs.tip_hash(), main_tip);
        assert_eq!(cs.tip_height(), 3);
        assert_eq!(
            cs.get_block_index(&side.block_hash()).unwrap().status,
            BlockStatus::Invalid
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconsider_reorgs_back_onto_restored_chain() {
        let (cs, dir) = make_chain_state();
        let main = build_and_connect_chain(&cs, 5);
        let block2 = main[1].block_hash();
        let main3 = main[2].block_hash();
        let main5 = main[4].block_hash();

        // Invalidate a mid-chain block → truncates to its parent (height 2).
        cs.invalidate_block(main3).unwrap();
        assert_eq!(cs.tip_hash(), block2);
        assert_eq!(cs.tip_height(), 2);

        // Reconsidering it restores the subtree; the restored chain out-works
        // the truncated tip, so the active chain reorgs back onto it via a
        // multi-block reconnect (3 → 4 → 5).
        cs.reconsider_block(main3).unwrap();
        assert_eq!(cs.tip_hash(), main5);
        assert_eq!(cs.tip_height(), 5);
        for b in &main[2..] {
            assert_eq!(
                cs.get_block_index(&b.block_hash()).unwrap().status,
                BlockStatus::Valid
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_invalid_tip_self_heals_a_crashed_invalidate() {
        let (cs, dir) = make_chain_state();
        let main = build_and_connect_chain(&cs, 3);
        let tip3 = main[2].block_hash();
        let block2 = main[1].block_hash();

        // Simulate a crash mid-`invalidate_block`: the subtree was marked
        // Invalid but the re-activation never ran, so the durable tip still
        // points at the (now Invalid) block.
        cs.mark_subtree_invalid(tip3).unwrap();
        assert_eq!(cs.tip_hash(), tip3, "tip unchanged by marking alone");
        assert_eq!(
            cs.get_block_index(&tip3).unwrap().status,
            BlockStatus::Invalid
        );

        // Startup reconciliation moves the tip off the invalid block onto the
        // best valid ancestor.
        cs.reconcile_invalid_tip().unwrap();
        assert_eq!(cs.tip_hash(), block2);
        assert_eq!(cs.tip_height(), 2);

        // Idempotent: a valid tip is a no-op.
        cs.reconcile_invalid_tip().unwrap();
        assert_eq!(cs.tip_hash(), block2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_blocks_walks_back_to_fork_including_tip_height() {
        let (cs, dir) = make_chain_state();
        // Active chain at height 1 (chain A, has data).
        build_and_connect_chain(&cs, 1);

        // A competing HEADER chain forking at genesis: B1,B2,B3 (headers only,
        // no block data), out-working the active tip.
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let mut parent = genesis;
        let mut bhashes = Vec::new();
        for h in 1..=3 {
            let b = build_test_block(parent, h, 1_600_000_000 + h);
            cs.accept_header(&b.header).unwrap();
            parent = b.block_hash();
            bhashes.push(b.block_hash());
        }

        // The fork-aware walk requests B1,B2,B3 in connect order — crucially
        // including B1 at height 1 (== our tip height), which a forward-by-
        // height walk from tip+1 would have skipped, stranding the reorg.
        let missing = cs.missing_blocks_for_best_header_chain(128);
        assert_eq!(missing, bhashes);

        // Batch cap is honored (oldest first).
        let capped = cs.missing_blocks_for_best_header_chain(2);
        assert_eq!(capped, bhashes[..2]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn best_header_beats_active_tip_detects_competing_chain() {
        let (cs, dir) = make_chain_state();
        // Active chain at height 2 (has data).
        build_and_connect_chain(&cs, 2);
        // No competing chain yet → tip is best.
        assert!(!cs.best_header_beats_active_tip());

        // A competing HEADER chain forking at genesis, longer (more work),
        // headers only — the exact shape that wedges the linear IBD connector.
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let mut parent = genesis;
        for h in 1..=3 {
            let b = build_test_block(parent, h, 1_700_000_000 + h);
            cs.accept_header(&b.header).unwrap();
            parent = b.block_hash();
        }
        // The best header chain now out-works the active tip.
        assert!(cs.best_header_beats_active_tip());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn frontier_connects_to_tip_detects_fork_blocked_frontier() {
        let (cs, dir) = make_chain_state();
        build_and_connect_chain(&cs, 2); // active tip A2 at height 2
        // Nothing at tip+1 yet → frontier is not fork-blocked; IBD may run.
        assert!(cs.frontier_connects_to_tip());

        // Competing higher-work header chain B1..B3 forking at genesis. The
        // above-tip height index now maps height 3 → B3 (whose parent is B2,
        // not the active tip A2) — exactly the fork-blocked frontier that
        // wedges the linear connector.
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let mut parent = genesis;
        for h in 1..=3 {
            let b = build_test_block(parent, h, 1_700_000_000 + h);
            cs.accept_header(&b.header).unwrap();
            parent = b.block_hash();
        }
        // get_block_hash_by_height(3) is now the competing B3, prev != tip.
        assert!(
            !cs.frontier_connects_to_tip(),
            "a fork-blocked connect frontier must suppress IBD (re)creation"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_blocks_empty_when_already_on_best_chain() {
        let (cs, dir) = make_chain_state();
        build_and_connect_chain(&cs, 3);
        // No competing header chain out-works the tip, and we have all data.
        assert!(cs.missing_blocks_for_best_header_chain(128).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_blocks_collects_a_hole_below_a_present_side_block() {
        let (cs, dir) = make_chain_state();
        build_and_connect_chain(&cs, 1); // active height 1 (A1)

        // Competing header chain B1..B4 (more work), with data for ONLY B3 —
        // a present side block with missing neighbours above and below it.
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let mut parent = genesis;
        let mut b = Vec::new();
        for h in 1..=4 {
            let blk = build_test_block(parent, h, 1_650_000_000 + h);
            cs.accept_header(&blk.header).unwrap();
            parent = blk.block_hash();
            b.push(blk);
        }
        cs.store_block(&b[2]).unwrap(); // B3 has data; B1,B2,B4 do not

        // The walk must continue PAST the present B3 and still collect the
        // hole below it (B1, B2) as well as B4 — a "stop at first data" walk
        // would strand B1/B2 and the reorg could never reconnect.
        let missing = cs.missing_blocks_for_best_header_chain(128);
        assert_eq!(
            missing,
            vec![b[0].block_hash(), b[1].block_hash(), b[3].block_hash()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backfill_chain_tx_counts_rebuilds_and_is_idempotent() {
        // num_tx by height: genesis=1, then 2,3,4 → cumulative 1,3,6,10.
        let (cs, dir, hashes) = chain_state_with_seeded_chain(&[1, 2, 3, 4]);
        // Pre-backfill: no cumulative recorded.
        assert_eq!(cs.cumulative_tx_count(&hashes[3]), None);

        let written = cs.backfill_chain_tx_counts().unwrap();
        assert_eq!(written, 4);
        assert_eq!(cs.cumulative_tx_count(&hashes[0]), Some(1));
        assert_eq!(cs.cumulative_tx_count(&hashes[1]), Some(3));
        assert_eq!(cs.cumulative_tx_count(&hashes[2]), Some(6));
        assert_eq!(cs.cumulative_tx_count(&hashes[3]), Some(10));

        // Second run is a no-op (marker stamped).
        assert_eq!(cs.backfill_chain_tx_counts().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn getchaintxstats_reports_cumulative_and_honors_blockhash() {
        let (cs, dir, hashes) = chain_state_with_seeded_chain(&[1, 2, 3, 4]);
        cs.backfill_chain_tx_counts().unwrap();

        // Default (tip): cumulative through height 3 = 10; window of 30 is
        // clamped to height 3 → window sums heights 1..=3 = 2+3+4 = 9.
        let tip_stats =
            crate::rpc::blockchain::get_chain_tx_stats(&cs, None, None).unwrap();
        assert_eq!(tip_stats["txcount"], 10);
        assert_eq!(tip_stats["window_tx_count"], 9);
        assert_eq!(tip_stats["window_final_block_height"], 3);

        // Explicit historical blockhash (height 2): cumulative = 6, window
        // of 2 sums heights 1..=2 = 2+3 = 5.
        let hist =
            crate::rpc::blockchain::get_chain_tx_stats(&cs, Some(2), Some(hashes[2])).unwrap();
        assert_eq!(hist["txcount"], 6);
        assert_eq!(hist["window_block_count"], 2);
        assert_eq!(hist["window_tx_count"], 5);
        assert_eq!(hist["window_final_block_height"], 2);

        // An unknown block hash → error.
        let bogus = BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [0xEE; 32],
        ));
        assert!(crate::rpc::blockchain::get_chain_tx_stats(&cs, None, Some(bogus)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_seed_sets_cumulative_at_base() {
        let (cs, dir) = make_chain_state();
        let base_hash = BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x7E; 32]),
        );
        let anchor = crate::chain::assumeutxo::AssumeUtxoData {
            height: 840_000,
            blockhash: base_hash,
            nchaintx: 1_009_000_000,
            hash_serialized_3: [0u8; 32],
        };
        cs.adopt_snapshot_tip(&anchor).unwrap();
        // The served snapshot tip reports the anchor's cumulative count
        // immediately, before any background validation.
        assert_eq!(cs.cumulative_tx_count(&base_hash), Some(1_009_000_000));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn getchaintxstats_omits_txcount_when_not_counted() {
        // Seed a chain but do NOT backfill: cumulative is absent.
        let (cs, dir, _hashes) = chain_state_with_seeded_chain(&[1, 2, 3, 4]);
        let stats = crate::rpc::blockchain::get_chain_tx_stats(&cs, None, None).unwrap();
        // Core omits txcount, window_tx_count, and txrate when the cumulative
        // counts at the window endpoints aren't available (window_tx_count is
        // their difference). window_interval is still emitted.
        assert!(
            stats.get("txcount").is_none(),
            "txcount must be omitted when cumulative is unavailable, got: {stats}"
        );
        assert!(
            stats.get("window_tx_count").is_none(),
            "window_tx_count must be omitted when cumulative is unavailable, got: {stats}"
        );
        assert!(
            stats.get("txrate").is_none(),
            "txrate must be omitted when window_tx_count is unavailable, got: {stats}"
        );
        assert!(stats.get("window_interval").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backfill_seeds_genesis_cumulative_on_genesis_only_datadir() {
        // Upgraded datadir with only genesis indexed and no chain_tx rows: the
        // backfill must still record chain_tx[genesis] (= genesis num_tx)
        // before stamping the marker. Otherwise the next connected block reads
        // its parent's cumulative as 0 (unwrap_or) and undercounts the whole
        // chain by the genesis tx forever.
        let (cs, dir, hashes) = chain_state_with_seeded_chain(&[1]);
        assert_eq!(cs.tip_height(), 0);
        assert_eq!(cs.cumulative_tx_count(&hashes[0]), None);

        // Genesis-only walk writes nothing (returns 0) but must seed genesis.
        assert_eq!(cs.backfill_chain_tx_counts().unwrap(), 0);
        assert_eq!(cs.cumulative_tx_count(&hashes[0]), Some(1));

        // Idempotent: marker stamped, value preserved.
        assert_eq!(cs.backfill_chain_tx_counts().unwrap(), 0);
        assert_eq!(cs.cumulative_tx_count(&hashes[0]), Some(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backfill_chain_tx_counts_ignores_polluted_height_index() {
        // Regression for the Round-3 review finding: the upgraded-datadir
        // backfill must follow the active chain via prev_blockhash, not the
        // pollutable height_hash index. We seed a chain (cumulative 1,3,6,10),
        // then clobber height_hash[2] to point at a bogus side block. The
        // backfill must still count the real active blocks and never the side
        // block.
        let (cs, dir, hashes) = chain_state_with_seeded_chain(&[1, 2, 3, 4]);

        // Inject a side block at height 2 and repoint the height index at it.
        let bogus = BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [0xB0; 32],
        ));
        let base_header = bitcoin::constants::genesis_block(Network::Regtest).header;
        let bogus_entry = BlockIndexEntry {
            header: base_header,
            height: 2,
            status: BlockStatus::Valid,
            num_tx: 99, // would corrupt the totals if it were ever counted
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        };
        let mut pollute = crate::storage::StoreBatch::default();
        pollute.block_index_puts.push((bogus, bogus_entry));
        pollute.height_hash_puts.push((2, bogus));
        cs.store.write_batch(pollute).unwrap();
        assert_eq!(cs.get_block_hash_by_height(2), Some(bogus), "test premise");

        let written = cs.backfill_chain_tx_counts().unwrap();
        assert_eq!(written, 4);
        // Real active chain counted correctly; the side block never counted.
        assert_eq!(cs.cumulative_tx_count(&hashes[0]), Some(1));
        assert_eq!(cs.cumulative_tx_count(&hashes[1]), Some(3));
        assert_eq!(cs.cumulative_tx_count(&hashes[2]), Some(6));
        assert_eq!(cs.cumulative_tx_count(&hashes[3]), Some(10));
        assert_eq!(cs.cumulative_tx_count(&bogus), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn getchaintxstats_window_interval_uses_median_time_past() {
        // 13 blocks (heights 0..=12), one tx each, header times 600s apart
        // (T + 600*h). Core measures window_interval as the MTP difference of
        // the endpoint blocks, not the raw header-time difference.
        let (cs, dir, _hashes) = chain_state_with_seeded_chain(&[1u32; 13]);
        cs.backfill_chain_tx_counts().unwrap();

        // Default window = min(30, 12) = 12 → start at genesis (height 0).
        //   MTP(tip=12)   = median of heights [2..=12] = ts[7] = T + 4200
        //   MTP(start=0)  = median of heights [0..=0]  = ts[0] = T
        //   window_interval = 4200   (raw header diff would be 12*600 = 7200)
        let stats = crate::rpc::blockchain::get_chain_tx_stats(&cs, None, None).unwrap();
        assert_eq!(stats["window_final_block_height"], 12);
        assert_eq!(stats["window_interval"].as_u64().unwrap(), 4200);
        assert_ne!(
            stats["window_interval"].as_u64().unwrap(),
            7200,
            "window_interval must be the MTP difference, not the raw header-time difference"
        );
        // window_tx_count = cum[12] - cum[0] = 13 - 1 = 12; txrate over MTP interval.
        assert_eq!(stats["window_tx_count"].as_u64().unwrap(), 12);
        let txrate = stats["txrate"].as_f64().unwrap();
        assert!((txrate - 12.0 / 4200.0).abs() < 1e-12, "txrate {txrate}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn background_handoff_validates_and_drops_on_hash_match() {
        let (cs, dir) = make_chain_state();
        let n = 5u32;
        let blocks = build_and_connect_chain(&cs, n);
        assert_eq!(cs.tip_height(), n);
        let snapshot_hash = cs.tip_hash();

        // Anchor = the primary's UTXO-set hash at the snapshot height.
        cs.store.flush().unwrap();
        let (anchor, _) =
            crate::storage::compressed_coin::hash_utxo_set(&*cs.store).unwrap();

        // Attach a background that must reproduce that hash by
        // re-validating genesis→N into its own coins DB.
        let bg_dir = dir.join("chainstate_background");
        cs.attach_background(bg_dir.clone(), n, snapshot_hash, anchor, 64, -1)
            .unwrap();
        assert!(cs.has_background());

        for b in &blocks {
            cs.background_connect_block(b).unwrap();
        }

        // Hash matched at the snapshot height → handoff completed: the
        // background is dropped and its private DB removed.
        assert!(
            !cs.has_background(),
            "background should be dropped after a successful handoff"
        );
        assert!(
            !bg_dir.exists(),
            "background DB dir should be removed after handoff"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn background_connect_reuses_prestored_block_data() {
        // The live catch-up driver stores each downloaded historical block
        // via `store_block` (status DataStored) into the SHARED flat files,
        // then wakes the connector. `background_connect_block` must REUSE
        // that on-disk copy rather than writing the block a second time —
        // otherwise the whole genesis→snapshot range is duplicated on disk.
        use crate::storage::blockindex::BlockStatus;

        let (cs, dir) = make_chain_state();

        // Build a short chain and store (but do NOT connect to the primary)
        // each block, mirroring the live flow where the primary tip starts
        // at the snapshot height and never connects the historical range.
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut parent = genesis.block_hash();
        let mut blocks = Vec::new();
        for h in 1..=3u32 {
            let b = build_test_block(parent, h, 1_300_000_000 + h);
            cs.accept_header(&b.header).unwrap();
            cs.store_block(&b).unwrap();
            parent = b.block_hash();
            blocks.push(b);
        }
        assert_eq!(cs.tip_height(), 0, "primary tip must stay at genesis");

        // Record where store_block placed block #1.
        let h1 = blocks[0].block_hash();
        let pre = cs.get_block_index(&h1).expect("block 1 stored");
        assert_eq!(pre.status, BlockStatus::DataStored);
        let (pre_file, pre_pos) = (pre.file_number, pre.data_pos);

        // Attach a background validating toward snapshot_height = 3. We only
        // connect block #1 (below the snapshot), so the handoff never runs
        // and the dummy anchor is never checked.
        let bg_dir = dir.join("chainstate_background");
        cs.attach_background(bg_dir, 3, blocks[2].block_hash(), [0u8; 32], 64, -1)
            .unwrap();

        let outcome = cs
            .background_connect_block(&blocks[0])
            .unwrap()
            .expect("background attached");
        assert_eq!(outcome.height, 1);
        assert!(!outcome.reached_snapshot);

        // The shared block-index entry now reads Valid but still points at
        // the SAME flat-file position store_block wrote — proof the block
        // data was reused, not appended a second time.
        let post = cs.get_block_index(&h1).expect("block 1 still indexed");
        assert_eq!(post.status, BlockStatus::Valid);
        assert_eq!(
            (post.file_number, post.data_pos),
            (pre_file, pre_pos),
            "background connect must reuse the pre-stored flat position, not rewrite the block"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn background_handoff_keeps_chainstate_and_warns_on_hash_mismatch() {
        let (cs, dir) = make_chain_state();
        let n = 4u32;
        let blocks = build_and_connect_chain(&cs, n);
        let snapshot_hash = cs.tip_hash();

        // A deliberately wrong anchor: the background's recomputed hash
        // will not match.
        let bad_anchor = [0x42u8; 32];
        let bg_dir = dir.join("chainstate_background");
        cs.attach_background(bg_dir.clone(), n, snapshot_hash, bad_anchor, 64, -1)
            .unwrap();

        // Connecting blocks below the snapshot height succeeds; the block
        // that reaches the snapshot height triggers the handoff, which now
        // FAILS CLOSED on the hash mismatch and returns an error.
        let mut last: Result<_, ChainError> = Ok(None);
        for b in &blocks {
            last = cs.background_connect_block(b);
        }
        assert!(
            matches!(last, Err(ChainError::Snapshot(_))),
            "the handoff at the snapshot height must fail closed on a hash mismatch, got {last:?}"
        );

        // Background retained + durably marked rejected; a loud warning is
        // recorded and getchainstates surfaces the rejected state.
        let bg = cs.background().expect("background retained on mismatch");
        assert!(bg.is_rejected(), "snapshot must be durably marked rejected");
        let warned = cs
            .warnings()
            .as_strings()
            .iter()
            .any(|w| w.contains("AssumeUTXO") || w.to_lowercase().contains("validation"));
        assert!(warned, "a validation-failure warning should be recorded");
        let states = crate::rpc::blockchain::get_chain_states(&cs);
        assert_eq!(states["chainstates"][0]["assumeutxo_rejected"], true);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_utxo_snapshot_adopts_tip_and_attaches_background() {
        use crate::chain::assumeutxo::AssumeUtxoData;

        // Source chain: mine 5 blocks and dump its UTXO snapshot.
        let (src, src_dir) = make_chain_state();
        let blocks = build_and_connect_chain(&src, 5);
        let snap_height = 5u32;
        let snap_hash = src.tip_hash();
        let snap_path = src_dir.join("snap.dat");
        let dump = src.dump_utxo_snapshot(&snap_path).unwrap();

        let anchor = AssumeUtxoData {
            height: snap_height,
            blockhash: snap_hash,
            nchaintx: 0,
            hash_serialized_3: dump.hash_serialized_3,
        };

        // Fresh node: sync only the headers, then load the snapshot.
        let (dst, dst_dir) = make_chain_state();
        for b in &blocks {
            dst.accept_header(&b.header).unwrap();
        }
        assert_eq!(dst.tip_height(), 0, "fresh node starts at genesis");

        let bg_dir = dst_dir.join("chainstate_background");
        let mut f = std::fs::File::open(&snap_path).unwrap();
        let summary = dst
            .load_utxo_snapshot(&mut f, anchor, bg_dir, 64, -1)
            .expect("snapshot load should succeed against a matching anchor");

        assert_eq!(summary.tip_height, snap_height);
        assert_eq!(summary.coins_loaded, dump.coins_written);
        assert_eq!(dst.tip_height(), snap_height);
        assert_eq!(dst.tip_hash(), snap_hash);
        assert!(dst.has_background(), "background must be attached after load");

        // getchainstates now reports two chainstates: the snapshot
        // (validated=false, carries snapshot_blockhash) and background.
        let states = crate::rpc::blockchain::get_chain_states(&dst);
        let arr = states["chainstates"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["validated"], false);
        assert_eq!(arr[0]["snapshot_blockhash"], snap_hash.to_string());

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&dst_dir);
    }

    #[test]
    fn live_catchup_flow_store_then_connect_reaches_handoff() {
        // End-to-end of the live driver's per-block flow: after
        // loadtxoutset, the catch-up downloader `store_block`s each
        // historical block (DataStored) and the connector
        // `background_connect_block`s them in order. On reaching
        // snapshot_height the handoff validates against the real anchor and
        // drops the background — exactly what the wired loops do, minus the
        // P2P transport.
        use crate::chain::assumeutxo::AssumeUtxoData;

        let (src, src_dir) = make_chain_state();
        let blocks = build_and_connect_chain(&src, 5);
        let snap_height = 5u32;
        let snap_hash = src.tip_hash();
        let snap_path = src_dir.join("snap.dat");
        let dump = src.dump_utxo_snapshot(&snap_path).unwrap();
        let anchor = AssumeUtxoData {
            height: snap_height,
            blockhash: snap_hash,
            nchaintx: 0,
            hash_serialized_3: dump.hash_serialized_3,
        };

        // Fresh node: headers only, then load the snapshot.
        let (dst, dst_dir) = make_chain_state();
        for b in &blocks {
            dst.accept_header(&b.header).unwrap();
        }
        let bg_dir = dst_dir.join("chainstate_background");
        let mut f = std::fs::File::open(&snap_path).unwrap();
        dst.load_utxo_snapshot(&mut f, anchor, bg_dir.clone(), 64, -1)
            .expect("snapshot load should succeed");
        assert_eq!(dst.tip_height(), snap_height);
        assert!(dst.has_background());

        // Drive the historical range exactly as the wired loops do.
        for (i, b) in blocks.iter().enumerate() {
            dst.store_block(b).unwrap();
            let outcome = dst
                .background_connect_block(b)
                .unwrap()
                .expect("background attached until handoff");
            let expected_height = i as u32 + 1;
            assert_eq!(outcome.height, expected_height);
            assert_eq!(outcome.reached_snapshot, expected_height == snap_height);
        }

        // Handoff completed on the real anchor: background dropped + removed,
        // and the primary tip is unchanged at the snapshot height.
        assert!(!dst.has_background(), "handoff should drop the background");
        assert!(!bg_dir.exists(), "background DB dir should be removed");
        assert_eq!(dst.tip_height(), snap_height);

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&dst_dir);
    }

    #[test]
    fn load_utxo_snapshot_rejects_and_rolls_back_on_hash_mismatch() {
        use crate::chain::assumeutxo::AssumeUtxoData;

        let (src, src_dir) = make_chain_state();
        let blocks = build_and_connect_chain(&src, 4);
        let snap_hash = src.tip_hash();
        let snap_path = src_dir.join("snap.dat");
        let _dump = src.dump_utxo_snapshot(&snap_path).unwrap();

        // Anchor with a deliberately wrong UTXO-set hash.
        let bad_anchor = AssumeUtxoData {
            height: 4,
            blockhash: snap_hash,
            nchaintx: 0,
            hash_serialized_3: [0x42u8; 32],
        };

        let (dst, dst_dir) = make_chain_state();
        for b in &blocks {
            dst.accept_header(&b.header).unwrap();
        }
        let bg_dir = dst_dir.join("chainstate_background");
        let mut f = std::fs::File::open(&snap_path).unwrap();
        let err = dst
            .load_utxo_snapshot(&mut f, bad_anchor, bg_dir, 64, -1)
            .expect_err("a hash mismatch must be rejected");
        assert!(matches!(err, ChainError::Snapshot(_)));

        // Rolled back to a fresh genesis chainstate; no background.
        assert_eq!(dst.tip_height(), 0);
        assert!(!dst.has_background());

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&dst_dir);
    }

    #[test]
    fn load_utxo_snapshot_rolls_back_when_attach_background_fails() {
        use crate::chain::assumeutxo::AssumeUtxoData;

        let (src, src_dir) = make_chain_state();
        let blocks = build_and_connect_chain(&src, 3);
        let snap_hash = src.tip_hash();
        let snap_path = src_dir.join("snap.dat");
        let dump = src.dump_utxo_snapshot(&snap_path).unwrap();
        let anchor = AssumeUtxoData {
            height: 3,
            blockhash: snap_hash,
            nchaintx: 0,
            hash_serialized_3: dump.hash_serialized_3,
        };

        let (dst, dst_dir) = make_chain_state();
        for b in &blocks {
            dst.accept_header(&b.header).unwrap();
        }

        // Force attach_background to fail by planting a regular FILE where
        // the background chainstate dir must be opened.
        let bg_dir = dst_dir.join("chainstate_background");
        std::fs::write(&bg_dir, b"not a directory").unwrap();

        let mut f = std::fs::File::open(&snap_path).unwrap();
        let err = dst
            .load_utxo_snapshot(&mut f, anchor, bg_dir, 64, -1)
            .expect_err("attach_background must fail when its dir is unusable");
        // The anchor hash is VALID here; the failure is purely the
        // background open. The node must not be left bootstrapped.
        assert!(matches!(err, ChainError::Storage(_) | ChainError::Snapshot(_)));
        assert_eq!(dst.tip_height(), 0, "tip must stay at genesis");
        assert!(!dst.has_background(), "no background may be attached");
        assert_eq!(dst.coin_count(), 0, "no snapshot coins may persist");

        let _ = std::fs::remove_dir_all(&src_dir);
        let _ = std::fs::remove_dir_all(&dst_dir);
    }

    /// Build a snapshot byte stream by hand (header + raw txid groups) so
    /// tests can inject malformed input.
    #[allow(clippy::type_complexity)]
    fn craft_snapshot(
        base: BlockHash,
        declared_count: u64,
        groups: &[([u8; 32], Vec<(u64, crate::storage::coinview::Coin)>)],
    ) -> Vec<u8> {
        use crate::storage::compressed_coin as cc;
        let mut buf = Vec::new();
        let meta = cc::SnapshotMetadata {
            version: cc::SNAPSHOT_VERSION,
            network_magic: network_magic(Network::Regtest),
            base_blockhash: base,
            coins_count: declared_count,
        };
        meta.serialize(&mut buf).unwrap();
        for (txid_bytes, coins) in groups {
            buf.extend_from_slice(txid_bytes);
            cc::write_compact_size(&mut buf, coins.len() as u64).unwrap();
            for (vout, coin) in coins {
                cc::write_compact_size(&mut buf, *vout).unwrap();
                cc::serialize_coin(&mut buf, coin).unwrap();
            }
        }
        buf
    }

    fn tiny_coin() -> crate::storage::coinview::Coin {
        crate::storage::coinview::Coin {
            amount: 1_000,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            height: 1,
            coinbase: false,
        }
    }

    /// Build a fresh node with the height-1 base header synced (tip at
    /// genesis), plus an anchor pointing at that base. Used by the
    /// malformed-stream tests; the anchor hash is irrelevant because the
    /// load fails while streaming, before the hash check.
    fn dst_with_base_header() -> (
        ChainState,
        std::path::PathBuf,
        crate::chain::assumeutxo::AssumeUtxoData,
    ) {
        use crate::chain::assumeutxo::AssumeUtxoData;
        let (src, src_dir) = make_chain_state();
        let blocks = build_and_connect_chain(&src, 1);
        let base = src.tip_hash();
        let _ = std::fs::remove_dir_all(&src_dir);

        let (dst, dst_dir) = make_chain_state();
        dst.accept_header(&blocks[0].header).unwrap();
        let anchor = AssumeUtxoData {
            height: 1,
            blockhash: base,
            nchaintx: 0,
            hash_serialized_3: [0u8; 32],
        };
        (dst, dst_dir, anchor)
    }

    #[test]
    fn load_utxo_snapshot_rejects_duplicate_outpoint() {
        let (dst, dst_dir, anchor) = dst_with_base_header();
        let base = anchor.blockhash;
        // One txid group with the SAME vout twice — a duplicate outpoint
        // that would double-count if accepted.
        let bytes = craft_snapshot(
            base,
            2,
            &[([0x11u8; 32], vec![(0u64, tiny_coin()), (0u64, tiny_coin())])],
        );
        let bg_dir = dst_dir.join("chainstate_background");
        let err = dst
            .load_utxo_snapshot(&mut bytes.as_slice(), anchor, bg_dir, 64, -1)
            .expect_err("duplicate outpoint must be rejected");
        assert!(matches!(err, ChainError::Snapshot(_)));
        assert_eq!(dst.tip_height(), 0);
        assert!(!dst.has_background());
        assert_eq!(dst.coin_count(), 0);

        let _ = std::fs::remove_dir_all(&dst_dir);
    }

    #[test]
    fn load_utxo_snapshot_rejects_oversized_vout() {
        let (dst, dst_dir, anchor) = dst_with_base_header();
        let base = anchor.blockhash;
        // A single coin whose vout exceeds u32::MAX.
        let bytes = craft_snapshot(
            base,
            1,
            &[([0x22u8; 32], vec![(u64::from(u32::MAX) + 1, tiny_coin())])],
        );
        let bg_dir = dst_dir.join("chainstate_background");
        let err = dst
            .load_utxo_snapshot(&mut bytes.as_slice(), anchor, bg_dir, 64, -1)
            .expect_err("vout > u32::MAX must be rejected");
        assert!(matches!(err, ChainError::Snapshot(_)));
        assert_eq!(dst.tip_height(), 0);
        assert!(!dst.has_background());

        let _ = std::fs::remove_dir_all(&dst_dir);
    }

    #[test]
    fn resume_pending_snapshot_none_when_no_dir() {
        let (cs, dir) = make_chain_state();
        assert_eq!(
            cs.resume_pending_snapshot(&dir, 64, -1).unwrap(),
            SnapshotResume::None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resume_pending_snapshot_refuses_when_rejected() {
        let (cs, dir) = make_chain_state();
        let bg_dir = dir.join("chainstate_background");
        std::fs::create_dir_all(&bg_dir).unwrap();
        std::fs::write(bg_dir.join(".rejected"), b"x").unwrap();
        assert_eq!(
            cs.resume_pending_snapshot(&dir, 64, -1).unwrap(),
            SnapshotResume::Rejected
        );
        assert!(!cs.has_background());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resume_pending_snapshot_errors_on_missing_marker() {
        let (cs, dir) = make_chain_state();
        let bg_dir = dir.join("chainstate_background");
        std::fs::create_dir_all(&bg_dir).unwrap();
        assert!(
            cs.resume_pending_snapshot(&dir, 64, -1).is_err(),
            "a background dir with no anchor marker must refuse startup"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn background_resume_uses_private_tip_not_shared_block_index() {
        // Primary chain to height 5; the shared block index covers 0..5.
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 5);
        let snap_hash = cs.tip_hash();
        let bg_dir = dir.join("chainstate_background");
        cs.attach_background(bg_dir.clone(), 5, snap_hash, [0u8; 32], 64, -1)
            .unwrap();

        // Connect only the first 3 blocks to the background → its private
        // coins tip is height 3 while the shared block index is at 5.
        for b in &blocks[..3] {
            cs.background_connect_block(b).unwrap();
        }
        // Flush so the private tip is durable, then drop the in-memory
        // background to release its RocksDB lock and resume from disk. It
        // must resume from the PRIVATE coins tip (3), not the shared
        // block-index height (5).
        cs.background().unwrap().flush().unwrap();
        assert_eq!(cs.background().unwrap().tip_height(), 3);
        *cs.background.write() = None;
        match cs.resume_pending_snapshot(&dir, 64, -1).unwrap() {
            SnapshotResume::Resumed { height } => assert_eq!(height, 5),
            other => panic!("expected Resumed, got {other:?}"),
        }
        let bg = cs.background().unwrap();
        assert_eq!(
            bg.tip_height(),
            3,
            "background must resume from its private coins tip, not the shared block index"
        );
        assert_eq!(bg.snapshot_height(), 5);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_genesis_initialization() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);

        assert_eq!(cs.tip_height(), 0);
        assert_eq!(cs.tip_hash(), genesis.block_hash());

        let entry = cs.get_block_index(&genesis.block_hash()).unwrap();
        assert_eq!(entry.height, 0);
        assert_eq!(entry.status, BlockStatus::Valid);

        let read_back = cs.get_block(&genesis.block_hash()).unwrap();
        assert_eq!(read_back.block_hash(), genesis.block_hash());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_duplicate_rejection() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);

        let result = cs.accept_block(&genesis);
        assert!(matches!(result, Err(ChainError::Duplicate)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression for the `-reindex-chainstate` + read-only blocks/
    /// scenario: `clear_chainstate` wipes the tip pointer but keeps
    /// `CF_BLOCK_INDEX` intact, so `ChainState::new` lands in the
    /// "fresh node" branch on a non-fresh datadir. Without the
    /// genesis-flat-pos reuse, that branch unconditionally appends a
    /// duplicate genesis to flat files — which (a) wastes ~285 bytes
    /// of slack on every reindex-chainstate and (b) outright fails
    /// when `blocks/` is read-only at the file-mode level (e.g. a
    /// sibling validation node that symlinks to a primary's
    /// `blocks/` dir whose `blk*.dat` are mode 644 satd:satd).
    ///
    /// This test feeds `ChainState::new` a store that has a genesis
    /// `BlockIndexEntry` at a distinctive `(file_number=12,
    /// data_pos=34)` but no tip, then asserts that no new file is
    /// written to `blocks_dir` and the existing flat_pos survives.
    #[test]
    fn chain_state_new_reuses_genesis_flatpos_when_block_index_populated() {
        use crate::storage::blockindex::BlockIndexEntry;
        use crate::storage::StoreBatch;

        let dir = std::env::temp_dir().join(format!(
            "satd-genesis-reuse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks_dir = dir.join("blocks");
        std::fs::create_dir_all(&blocks_dir).unwrap();

        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        // Seed the store with a genesis block_index entry at a
        // distinctive flat_pos (12, 34) — chosen so we can later
        // distinguish "reused" from "overwritten by fresh append at
        // (0, 0)". Tip stays None: that's the post-`clear_chainstate`
        // shape.
        let store = Box::new(InMemoryStore::new());
        let genesis_entry = BlockIndexEntry {
            header: genesis.header,
            height: 0,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 12,
            data_pos: 34,
            chainwork: [0u8; 32],
        };
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((genesis_hash, genesis_entry));
        batch.height_hash_puts.push((0, genesis_hash));
        store.write_batch(batch).unwrap();

        // Sanity: pre-conditions match what `clear_chainstate` leaves
        // behind — tip cleared, block_index intact at (12, 34).
        assert!(store.get_tip().is_none());
        let pre = store.get_block_index(&genesis_hash).unwrap();
        assert_eq!(pre.file_number, 12);
        assert_eq!(pre.data_pos, 34);

        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap();

        // Tip is now at genesis (re-established by connect_block via
        // the seeded entry).
        assert_eq!(cs.tip_height(), 0);
        assert_eq!(cs.tip_hash(), genesis_hash);

        // The existing flat_pos survived — `ChainState::new` reused
        // it instead of appending a fresh genesis at (0, 0).
        let post = cs.get_block_index(&genesis_hash).unwrap();
        assert_eq!(
            post.file_number, 12,
            "genesis flat_pos.file_number changed; chain init re-appended"
        );
        assert_eq!(
            post.data_pos, 34,
            "genesis flat_pos.data_pos changed; chain init re-appended"
        );

        // And no blk*.dat file was created in blocks_dir.
        let blk_files: Vec<_> = std::fs::read_dir(&blocks_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("blk")
            })
            .collect();
        assert!(
            blk_files.is_empty(),
            "blocks_dir should be empty; got {:?}",
            blk_files
                .iter()
                .map(|e| e.file_name())
                .collect::<Vec<_>>()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Both heartbeat counters start at zero and advance independently
    /// on bump. The stall watchdog relies on this to distinguish
    /// "connector idle but loop alive" (steady-state tip) from "loop
    /// itself is wedged" (true stall).
    #[test]
    fn test_heartbeats_independent() {
        let (cs, dir) = make_chain_state();
        // Fresh ChainState: connect heartbeat starts at 0, manager
        // heartbeat starts at 0. (Genesis init does not bump connect.)
        let connect_start = cs.connect_heartbeat();
        let manager_start = cs.manager_heartbeat();
        assert_eq!(manager_start, 0);

        cs.bump_manager_heartbeat();
        assert_eq!(cs.manager_heartbeat(), manager_start + 1);
        assert_eq!(
            cs.connect_heartbeat(),
            connect_start,
            "bump_manager_heartbeat must not touch connect_heartbeat"
        );

        cs.bump_connect_heartbeat();
        assert_eq!(cs.connect_heartbeat(), connect_start + 1);
        assert_eq!(
            cs.manager_heartbeat(),
            manager_start + 1,
            "bump_connect_heartbeat must not touch manager_heartbeat"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Build a valid regtest block at the given height with the given parent hash and timestamp.
    pub(crate) fn build_test_block(parent_hash: BlockHash, height: u32, time: u32) -> Block {
        use bitcoin::block::Header;
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::pow::CompactTarget;
        use bitcoin::transaction;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

        let bits = CompactTarget::from_consensus(0x207fffff);

        // BIP 34 coinbase scriptSig: push height, then push the timestamp
        // as extra nonce to ensure each block's coinbase has a unique txid.
        let height_script = bitcoin::script::Builder::new()
            .push_int(height as i64)
            .push_int(time as i64)
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();

        let coinbase_input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: height_script,
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let coinbase_output = TxOut {
            value: Amount::from_sat(5_000_000_000),
            script_pubkey: ScriptBuf::new(),
        };

        let coinbase_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![coinbase_input],
            output: vec![coinbase_output],
        };

        let txdata = vec![coinbase_tx];

        // Build block with a dummy merkle root first, then compute the real one
        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x20000000),
                prev_blockhash: parent_hash,
                merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32]),
                ),
                time,
                bits,
                nonce: 0,
            },
            txdata,
        };

        // Set the real merkle root
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        // Mine: find a nonce whose hash satisfies PoW for 0x207fffff
        let target = crate::storage::blockindex::target_from_compact(bits);
        for nonce in 0u32..1_000_000 {
            block.header.nonce = nonce;
            let hash_bytes = *block.block_hash().as_raw_hash().as_byte_array();
            // Block hash is displayed as little-endian but the byte array from
            // to_byte_array() is the internal representation. For comparison with
            // a big-endian target we need to reverse it.
            let mut hash_be = [0u8; 32];
            for i in 0..32 {
                hash_be[i] = hash_bytes[31 - i];
            }
            // hash_be <= target means PoW satisfied
            let mut ok = true;
            for i in 0..32 {
                if hash_be[i] < target[i] {
                    break;
                }
                if hash_be[i] > target[i] {
                    ok = false;
                    break;
                }
            }
            if ok {
                return block;
            }
        }
        panic!("Failed to mine test block within 1,000,000 nonce iterations");
    }

    /// Like `build_test_block` but appends a second transaction that spends
    /// `spend`. Pass a non-existent outpoint to produce a block that is
    /// context-free valid (well-formed, correct merkle root, mined) yet
    /// fails `connect_block` with a missing-input error — exactly what is
    /// needed to force a reorg's *triggering* block to fail at connect.
    pub(crate) fn build_test_block_spending(
        parent_hash: BlockHash,
        height: u32,
        time: u32,
        spend: bitcoin::OutPoint,
    ) -> Block {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::pow::CompactTarget;
        use bitcoin::transaction;
        use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

        // Start from a normal coinbase-only block, then graft the spend tx
        // in and re-mine (merkle root and PoW both change).
        let mut block = build_test_block(parent_hash, height, time);
        let spend_tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spend,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        block.txdata.push(spend_tx);
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        let bits = CompactTarget::from_consensus(0x207fffff);
        let target = crate::storage::blockindex::target_from_compact(bits);
        for nonce in 0u32..2_000_000 {
            block.header.nonce = nonce;
            let hash_bytes = *block.block_hash().as_raw_hash().as_byte_array();
            let mut hash_be = [0u8; 32];
            for i in 0..32 {
                hash_be[i] = hash_bytes[31 - i];
            }
            let mut ok = true;
            for i in 0..32 {
                if hash_be[i] < target[i] {
                    break;
                }
                if hash_be[i] > target[i] {
                    ok = false;
                    break;
                }
            }
            if ok {
                return block;
            }
        }
        panic!("Failed to mine spending test block within 2,000,000 nonce iterations");
    }

    /// Like `build_test_block_spending`, but the grafted transaction is
    /// *non-final*: a time-based `lock_time` paired with a non-MAX sequence.
    ///
    /// This makes the MTP a caller computed observable. `connect_block` runs
    /// the BIP113 locktime comparison at the top of its per-transaction loop,
    /// before it resolves any input, so the block's fate distinguishes the two:
    /// an MTP below `lock_time` gives `LocktimeNotFinal`, and an MTP at or
    /// above it lets the transaction through to input resolution, which then
    /// fails on the deliberately missing outpoint. Two different errors, from
    /// nothing but the MTP.
    pub(crate) fn build_test_block_timelocked(
        parent_hash: BlockHash,
        height: u32,
        time: u32,
        spend: bitcoin::OutPoint,
        lock_time: u32,
    ) -> Block {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::pow::CompactTarget;
        use bitcoin::{Sequence, hashes::Hash};

        let mut block = build_test_block_spending(parent_hash, height, time, spend);
        let tx = block.txdata.last_mut().expect("grafted spend tx");
        tx.lock_time = LockTime::from_consensus(lock_time);
        // Any sequence below MAX opts the transaction into locktime enforcement.
        tx.input[0].sequence = Sequence::from_consensus(0xffff_fffe);
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        let bits = CompactTarget::from_consensus(0x207fffff);
        let target = crate::storage::blockindex::target_from_compact(bits);
        for nonce in 0u32..2_000_000 {
            block.header.nonce = nonce;
            let hash_bytes = *block.block_hash().as_raw_hash().as_byte_array();
            let mut hash_be = [0u8; 32];
            for i in 0..32 {
                hash_be[i] = hash_bytes[31 - i];
            }
            let mut ok = true;
            for i in 0..32 {
                if hash_be[i] < target[i] {
                    break;
                }
                if hash_be[i] > target[i] {
                    ok = false;
                    break;
                }
            }
            if ok {
                return block;
            }
        }
        panic!("Failed to mine time-locked test block within 2,000,000 nonce iterations");
    }

    /// Regression for issue #262: a reorg whose triggering block fails to
    /// connect must leave the original active chain — and its still-FRESH
    /// (un-flushed) coins — fully intact and durable. The old replay-based
    /// rollback could leave disconnected FRESH coins marked
    /// `Spent { fresh: true }` and silently elide them at the next flush;
    /// the atomic flush-checkpoint + cache-delta-discard path cannot.
    #[test]
    fn test_failed_reorg_preserves_fresh_coins() {
        use bitcoin::hashes::Hash;

        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Chain A: genesis -> A1 -> A2. Coins are FRESH — deliberately
        // never flushed, reproducing the unflushed-tip window.
        let a1 = build_test_block(genesis_hash, 1, 1_700_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a2 = build_test_block(a1_hash, 2, 1_700_000_002);
        let a2_hash = cs.accept_block(&a2).expect("accept A2");
        assert_eq!(cs.tip_height(), 2);
        assert_eq!(cs.tip_hash(), a2_hash);

        let a1_op = OutPoint { txid: a1.txdata[0].compute_txid(), vout: 0 };
        let a2_op = OutPoint { txid: a2.txdata[0].compute_txid(), vout: 0 };
        assert!(cs.get_coin(&a1_op).is_some(), "A1 coin present before reorg");
        assert!(cs.get_coin(&a2_op).is_some(), "A2 coin present before reorg");

        // Competing chain B with strictly more work (3 blocks > 2). B1/B2
        // are valid side blocks; B3 is the triggering block and is invalid
        // — it spends a non-existent outpoint, so it fails at connect.
        let b1 = build_test_block(genesis_hash, 1, 1_700_000_011);
        let b1_hash = cs.accept_block(&b1).expect("store B1 side block");
        let b2 = build_test_block(b1_hash, 2, 1_700_000_012);
        let b2_hash = cs.accept_block(&b2).expect("store B2 side block");
        // Tip is unchanged: B has only equal work so far.
        assert_eq!(cs.tip_hash(), a2_hash, "no reorg before B has more work");

        let bogus = OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0x9e; 32]),
            ),
            vout: 0,
        };
        let b3 = build_test_block_spending(b2_hash, 3, 1_700_000_013, bogus);
        let res = cs.accept_block(&b3);
        assert!(
            res.is_err(),
            "reorg triggering block spending a non-existent coin must fail to connect"
        );

        // The original chain must be fully restored.
        assert_eq!(cs.tip_height(), 2, "tip height restored to chain A");
        assert_eq!(cs.tip_hash(), a2_hash, "tip hash restored to chain A");
        assert!(cs.get_coin(&a1_op).is_some(), "A1 coin survives failed reorg");
        assert!(cs.get_coin(&a2_op).is_some(), "A2 coin survives failed reorg");

        // The crux: flush. A pre-fix bug would elide the disconnected-then-
        // not-restored FRESH coins here, silently dropping live UTXOs.
        cs.flush_coin_cache().expect("flush after failed reorg");
        assert!(
            cs.get_coin(&a1_op).is_some(),
            "A1 coin must survive the post-failure flush (no FRESH elision)"
        );
        assert!(
            cs.get_coin(&a2_op).is_some(),
            "A2 coin must survive the post-failure flush (no FRESH elision)"
        );
        assert_eq!(cs.coin_count(), 2, "exactly the two chain-A coins remain");

        // Sanity: the node still accepts the next valid block on chain A.
        let a3 = build_test_block(a2_hash, 3, 1_700_000_020);
        cs.accept_block(&a3).expect("chain A still extendable after failed reorg");
        assert_eq!(cs.tip_height(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two threads call `accept_block` at once — modeling a `submitblock`
    /// RPC (or internal mine) racing the connect thread. `accept_lock`
    /// must serialize them so the shared coin cache and `tip` are never
    /// mutated by two writers concurrently. The assertion is that the
    /// final chainstate is internally consistent (tip and UTXO set agree)
    /// and survives a flush + extend; an interleaved connect would desync
    /// them. Also guards against `accept_lock` deadlocking itself.
    #[test]
    fn test_concurrent_accept_block_is_serialized() {
        use std::sync::Barrier;

        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Two competing height-1 blocks with equal work. Distinct
        // timestamps → distinct block hashes and distinct coinbase txids.
        let x = build_test_block(genesis_hash, 1, 1_700_100_001);
        let y = build_test_block(genesis_hash, 1, 1_700_100_002);
        let x_hash = x.block_hash();
        let y_hash = y.block_hash();

        // Barrier forces both threads into `accept_block` at the same
        // instant, maximizing the overlap the lock has to absorb.
        let barrier = Barrier::new(2);
        std::thread::scope(|s| {
            let (bx, csx, xb) = (&barrier, &cs, &x);
            s.spawn(move || {
                bx.wait();
                csx.accept_block(xb).expect("accept X");
            });
            let (by, csy, yb) = (&barrier, &cs, &y);
            s.spawn(move || {
                by.wait();
                csy.accept_block(yb).expect("accept Y");
            });
        });

        // Exactly one became the tip at height 1; the other is a stored
        // side block (equal work → no reorg). A corrupted interleave would
        // leave tip height != 1 or the UTXO set out of sync with the tip.
        assert_eq!(cs.tip_height(), 1, "tip advanced by exactly one block");
        let tip = cs.tip_hash();
        assert!(tip == x_hash || tip == y_hash, "tip is one of the two competitors");
        assert_eq!(cs.coin_count(), 1, "exactly the winning coinbase is live");

        let winner = if tip == x_hash { &x } else { &y };
        let win_op = OutPoint { txid: winner.txdata[0].compute_txid(), vout: 0 };
        assert!(cs.get_coin(&win_op).is_some(), "winning coinbase is in the UTXO set");

        // Survives a flush + a further extend — proving the loser's connect
        // attempt left no half-applied delta behind.
        cs.flush_coin_cache().expect("flush after concurrent accept");
        assert_eq!(cs.coin_count(), 1, "coin set stable across flush");
        let next = build_test_block(tip, 2, 1_700_100_010);
        cs.accept_block(&next).expect("chain extendable after concurrent accept");
        assert_eq!(cs.tip_height(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reorg_longer_chain_wins() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();
        assert_eq!(cs.tip_height(), 0);

        // Build chain A: genesis -> A1 -> A2
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");

        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        let a2_hash = cs.accept_block(&a2).expect("accept A2");

        assert_eq!(cs.tip_hash(), a2_hash);
        assert_eq!(cs.tip_height(), 2);

        // Build chain B: genesis -> B1 -> B2 -> B3 (different timestamps => different hashes)
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_003);
        let b1_hash = cs.accept_block(&b1).expect("accept B1");
        // B1 is a side chain block; tip should still be A2
        assert_eq!(cs.tip_hash(), a2_hash);

        let b2 = build_test_block(b1_hash, 2, 1_300_000_004);
        let b2_hash = cs.accept_block(&b2).expect("accept B2");
        // Equal work (2 blocks each); no reorg
        assert_eq!(cs.tip_hash(), a2_hash);

        let b3 = build_test_block(b2_hash, 3, 1_300_000_005);
        let b3_hash = cs.accept_block(&b3).expect("accept B3");
        // B chain now has more work => reorg
        assert_eq!(cs.tip_hash(), b3_hash);
        assert_eq!(cs.tip_height(), 3);

        assert_eq!(cs.get_block_hash_by_height(1), Some(b1_hash));
        assert_eq!(cs.get_block_hash_by_height(2), Some(b2_hash));
        assert_eq!(cs.get_block_hash_by_height(3), Some(b3_hash));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cumulative_tx_count_survives_reorg() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();
        let genesis_txs = genesis.txdata.len() as u64;

        // Chain A: genesis -> A1 -> A2 (tip).
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        let a2_hash = cs.accept_block(&a2).expect("accept A2");
        assert_eq!(cs.tip_hash(), a2_hash);

        // Chain B: genesis -> B1 -> B2 -> B3 outweighs A → reorg.
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_003);
        let b1_hash = cs.accept_block(&b1).expect("accept B1");
        let b2 = build_test_block(b1_hash, 2, 1_300_000_004);
        let b2_hash = cs.accept_block(&b2).expect("accept B2");
        let b3 = build_test_block(b2_hash, 3, 1_300_000_005);
        let b3_hash = cs.accept_block(&b3).expect("accept B3");
        assert_eq!(cs.tip_hash(), b3_hash);

        // New tip's cumulative reflects the B chain from genesis.
        let expected = genesis_txs
            + b1.txdata.len() as u64
            + b2.txdata.len() as u64
            + b3.txdata.len() as u64;
        assert_eq!(cs.cumulative_tx_count(&b3_hash), Some(expected));

        // The orphaned A2 is off the active chain → getchaintxstats refuses it.
        let err = crate::rpc::blockchain::get_chain_tx_stats(&cs, Some(1), Some(a2_hash))
            .unwrap_err();
        assert!(err.contains("not in main chain"), "got: {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn getchaintxstats_rejects_blockhash_when_height_index_polluted() {
        // Regression for the Round-2 review finding: getchaintxstats must use
        // an authoritative active-chain check, not the pollutable height_hash
        // index. A side block stored via store_block clobbers height_hash at
        // its height even though the active chain is unchanged.
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Active chain: genesis -> A1 -> A2 (A1 is active at height 1).
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        cs.accept_block(&a2).expect("accept A2");

        // A side block at height 1. store_block no longer clobbers the active
        // height index (that pollution is the bug this stack fixes), so inject
        // the polluted entry directly — this test verifies the CONSUMER is
        // immune to a height_hash that disagrees with the active chain.
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_010);
        let b1_hash = b1.block_hash();
        cs.store_block(&b1).expect("store B1");
        pollute_height_hash(&cs, 1, b1_hash);
        assert_eq!(
            cs.get_block_hash_by_height(1),
            Some(b1_hash),
            "test premise: height_hash[1] polluted with the side block"
        );

        // The side block must be rejected even though height_hash[1] == B1 …
        let err = crate::rpc::blockchain::get_chain_tx_stats(&cs, Some(1), Some(b1_hash))
            .unwrap_err();
        assert!(err.contains("not in main chain"), "got: {err}");

        // … and the genuinely-active A1 must be accepted even though the height
        // index no longer points at it.
        let ok = crate::rpc::blockchain::get_chain_tx_stats(&cs, Some(1), Some(a1_hash))
            .expect("A1 is on the active chain");
        assert_eq!(ok["window_final_block_height"], 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reorg_fork_point_immune_to_polluted_height_hash() {
        // The height_hash index is "best known at height" — populated
        // by accept_header / accept_headers / store_block as well as
        // by connect_block — so it is NOT an active-chain oracle. A
        // side-chain block at the same height as an active block, if
        // stored via `store_block`, will overwrite that height's
        // entry with the side block's hash, even though the active
        // chain is unchanged. Fork-point discovery must not depend
        // on this index.
        //
        // Scenario:
        //   1. Active chain: genesis -> A1 -> A2.
        //   2. store_block(B1) — side at height 1, overwrites
        //      height_hash[1] from A1 to B1 even though A1 is active.
        //   3. Build B2, B3 via accept_block (side chain, more work).
        //   4. accept_block(B3) triggers reorg.
        //   5. Fork point must resolve to genesis (the real common
        //      ancestor), not B1 (the polluted height_hash entry).
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        let _a2_hash = cs.accept_block(&a2).expect("accept A2");
        // After connect_block: height_hash[1] = A1.
        assert_eq!(cs.get_block_hash_by_height(1), Some(a1_hash));

        // Build a side block at height 1 and store it, then inject the polluted
        // height_hash[1] = B1 directly. (store_block no longer clobbers the
        // active index — the fix — so we recreate the disagreement to prove
        // fork-point discovery is immune to it.)
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_010);
        let b1_hash = b1.block_hash();
        let _ = cs.store_block(&b1).expect("store B1");
        pollute_height_hash(&cs, 1, b1_hash);
        assert_eq!(
            cs.get_block_hash_by_height(1),
            Some(b1_hash),
            "premise: height_hash[1] polluted with the side block"
        );

        // Extend B with two more blocks via accept_block — heavier
        // chain than A.
        let b2 = build_test_block(b1_hash, 2, 1_300_000_011);
        let b2_hash = cs.accept_block(&b2).expect("accept B2");
        let b3 = build_test_block(b2_hash, 3, 1_300_000_012);
        let b3_hash = cs.accept_block(&b3).expect("accept B3");

        // Reorg must succeed: fork point is genesis, B3 is the new tip.
        // The previous height-index-based fork-point logic would have
        // matched at B1 (because height_hash[1] = B1) and tried to
        // disconnect the active chain toward B1, which isn't on it.
        assert_eq!(cs.tip_hash(), b3_hash);
        assert_eq!(cs.tip_height(), 3);
        assert_eq!(cs.get_block_hash_by_height(1), Some(b1_hash));
        assert_eq!(cs.get_block_hash_by_height(2), Some(b2_hash));
        assert_eq!(cs.get_block_hash_by_height(3), Some(b3_hash));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_active_chain_range_immune_to_polluted_height_hash() {
        // `BlockCursorSource::active_chain_range` (the streaming cursor-replay
        // accessor) must read the genuine active chain, not the pollutable
        // height_hash index. Otherwise durable replay could emit a side-chain
        // block to a streaming consumer as a "confirmed" BlockConnected — the
        // exact false-confirmation hazard the resync path also guards against.
        use crate::events::BlockCursorSource;
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Active chain: genesis -> A1 -> A2 (tip at height 2).
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        let a2_hash = cs.accept_block(&a2).expect("accept A2");

        // Inject a polluted height_hash[1] = B1 (store_block no longer clobbers
        // the active index — the fix), to prove the consumer reads the active
        // chain regardless.
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_010);
        let b1_hash = b1.block_hash();
        let _ = cs.store_block(&b1).expect("store B1");
        pollute_height_hash(&cs, 1, b1_hash);
        assert_eq!(
            cs.get_block_hash_by_height(1),
            Some(b1_hash),
            "premise: height_hash[1] is polluted with the side block",
        );

        // active_chain_range must walk back from the tip and return the ACTIVE
        // hashes (A1, A2), immune to the polluted index.
        let range = cs.active_chain_range(1, 2);
        assert_eq!(
            range,
            vec![(1, a1_hash), (2, a2_hash)],
            "active_chain_range must return the active chain, not height_hash[1] = B1",
        );
        // A sub-range and a clamp-to-tip both behave.
        assert_eq!(cs.active_chain_range(2, 2), vec![(2, a2_hash)]);
        assert_eq!(cs.active_chain_range(1, 99), vec![(1, a1_hash), (2, a2_hash)]);
        assert!(cs.active_chain_range(3, 3).is_empty(), "above tip → empty");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reorg_chain_events_emitted_after_full_commit() {
        // Reorg-event ordering: subscribers must see BlockDisconnected
        // events for the old chain followed by BlockConnected events
        // for the new chain, all delivered after the reorg has fully
        // committed (chain + mempool reconcile). No events should
        // appear ahead of the final triggering block's connect.
        use crate::chain::events::ChainEvent;
        let (cs, dir) = make_chain_state();
        let (chain_tx, mut chain_rx) =
            tokio::sync::broadcast::channel::<ChainEvent>(64);
        cs.set_chain_event_sender(chain_tx);
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Active chain A: genesis -> A1 -> A2.
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        let a2_hash = cs.accept_block(&a2).expect("accept A2");

        // Drain pre-reorg connect events.
        let mut pre_events = Vec::new();
        while let Ok(ev) = chain_rx.try_recv() {
            pre_events.push(ev);
        }
        assert_eq!(pre_events.len(), 2, "two BlockConnected before reorg");

        // Heavier B: genesis -> B1 -> B2 -> B3 — triggers reorg on B3.
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_010);
        let b1_hash = cs.accept_block(&b1).expect("accept B1");
        let b2 = build_test_block(b1_hash, 2, 1_300_000_011);
        let b2_hash = cs.accept_block(&b2).expect("accept B2");
        let b3 = build_test_block(b2_hash, 3, 1_300_000_012);
        let b3_hash = cs.accept_block(&b3).expect("accept B3");

        // Collect the events emitted during accept_block(B3). Side
        // chain blocks B1/B2 are stored as side-chain (no reorg),
        // so only their accept calls drained nothing — they don't
        // emit BlockConnected at storage time. The reorg fires when
        // B3 is accepted.
        let mut events = Vec::new();
        while let Ok(ev) = chain_rx.try_recv() {
            events.push(ev);
        }
        // Expected: Reorg marker first, then BlockDisconnected(A2),
        // BlockDisconnected(A1), BlockConnected(B1), BlockConnected(B2),
        // BlockConnected(B3).
        assert_eq!(events.len(), 6, "events emitted: {:?}", events);
        assert!(matches!(
            events[0],
            ChainEvent::Reorg { from_height: 2, old_tip, to_height: 3, new_tip }
                if old_tip == a2_hash && new_tip == b3_hash
        ), "first event (reorg marker): {:?}", events[0]);
        assert!(matches!(
            events[1],
            ChainEvent::BlockDisconnected { hash, height: 2 } if hash == a2_hash
        ), "second event: {:?}", events[1]);
        assert!(matches!(
            events[2],
            ChainEvent::BlockDisconnected { hash, height: 1 } if hash == a1_hash
        ), "third event: {:?}", events[2]);
        assert!(matches!(
            events[3],
            ChainEvent::BlockConnected { hash, height: 1 } if hash == b1_hash
        ), "fourth event: {:?}", events[3]);
        assert!(matches!(
            events[4],
            ChainEvent::BlockConnected { hash, height: 2 } if hash == b2_hash
        ), "fifth event: {:?}", events[4]);
        assert!(matches!(
            events[5],
            ChainEvent::BlockConnected { hash, height: 3 } if hash == b3_hash
        ), "sixth event: {:?}", events[5]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reorg_back_to_previously_disconnected_branch() {
        // Stale-Valid fork-point regression: a previously disconnected
        // ancestor still carries BlockStatus::Valid, so the old
        // status-only fork-point search would stop at that stale
        // ancestor and try to disconnect the live chain toward a hash
        // that isn't on it. The new search uses the height index and
        // walks past the stale block to the real active fork point.
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Active chain A: genesis -> A1 -> A2.
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        let a2_hash = cs.accept_block(&a2).expect("accept A2");
        assert_eq!(cs.tip_hash(), a2_hash);

        // Heavier B: genesis -> B1 -> B2 -> B3. Reorgs over A.
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_010);
        let b1_hash = cs.accept_block(&b1).expect("accept B1");
        let b2 = build_test_block(b1_hash, 2, 1_300_000_011);
        let b2_hash = cs.accept_block(&b2).expect("accept B2");
        let b3 = build_test_block(b2_hash, 3, 1_300_000_012);
        let b3_hash = cs.accept_block(&b3).expect("accept B3");
        assert_eq!(cs.tip_hash(), b3_hash);
        // Sanity: A2 was disconnected but its block-index status is
        // still Valid — exactly the condition the old fork-point
        // search would trip on.
        let a2_entry = cs.get_block_index(&a2_hash).unwrap();
        assert_eq!(a2_entry.status, BlockStatus::Valid);
        assert_eq!(cs.get_block_hash_by_height(2), Some(b2_hash));

        // Now extend the previously-disconnected A branch with new
        // blocks A3 -> A4 -> A5, beating B's work.
        let a3 = build_test_block(a2_hash, 3, 1_300_000_020);
        let a3_hash = cs.accept_block(&a3).expect("accept A3");
        let a4 = build_test_block(a3_hash, 4, 1_300_000_021);
        let a4_hash = cs.accept_block(&a4).expect("accept A4");
        let a5 = build_test_block(a4_hash, 5, 1_300_000_022);
        let a5_hash = cs.accept_block(&a5).expect("accept A5");

        // Reorg should activate to A5 (the heavier chain).
        assert_eq!(cs.tip_hash(), a5_hash);
        assert_eq!(cs.tip_height(), 5);
        assert_eq!(cs.get_block_hash_by_height(1), Some(a1_hash));
        assert_eq!(cs.get_block_hash_by_height(2), Some(a2_hash));
        assert_eq!(cs.get_block_hash_by_height(3), Some(a3_hash));
        assert_eq!(cs.get_block_hash_by_height(4), Some(a4_hash));
        assert_eq!(cs.get_block_hash_by_height(5), Some(a5_hash));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reorg_shorter_chain_no_switch() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build chain A: genesis -> A1 -> A2 -> A3
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        let a2_hash = cs.accept_block(&a2).expect("accept A2");
        let a3 = build_test_block(a2_hash, 3, 1_300_000_003);
        let a3_hash = cs.accept_block(&a3).expect("accept A3");

        assert_eq!(cs.tip_hash(), a3_hash);
        assert_eq!(cs.tip_height(), 3);

        // Submit B1 forking from genesis (shorter chain, less work)
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_010);
        cs.accept_block(&b1).expect("accept B1");

        // Tip should remain A3
        assert_eq!(cs.tip_hash(), a3_hash);
        assert_eq!(cs.tip_height(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reorg_equal_work_no_switch() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build chain A: genesis -> A1
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        assert_eq!(cs.tip_hash(), a1_hash);

        // Submit B1 forking from genesis (equal work)
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_010);
        cs.accept_block(&b1).expect("accept B1");

        // Tip should remain A1 (equal work => no switch)
        assert_eq!(cs.tip_hash(), a1_hash);
        assert_eq!(cs.tip_height(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reorg_utxo_consistency() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build chain A: genesis -> A1 -> A2
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a1_coinbase_txid = a1.txdata[0].compute_txid();

        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        cs.accept_block(&a2).expect("accept A2");
        let a2_coinbase_txid = a2.txdata[0].compute_txid();

        // Verify A-chain UTXOs exist before reorg
        let a1_cb_op = OutPoint { txid: a1_coinbase_txid, vout: 0 };
        let a2_cb_op = OutPoint { txid: a2_coinbase_txid, vout: 0 };
        assert!(cs.get_coin(&a1_cb_op).is_some());
        assert!(cs.get_coin(&a2_cb_op).is_some());

        // Build chain B: genesis -> B1 -> B2 -> B3 (more work => triggers reorg)
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_003);
        let b1_hash = cs.accept_block(&b1).expect("accept B1");
        let b1_coinbase_txid = b1.txdata[0].compute_txid();

        let b2 = build_test_block(b1_hash, 2, 1_300_000_004);
        let b2_hash = cs.accept_block(&b2).expect("accept B2");
        let b2_coinbase_txid = b2.txdata[0].compute_txid();

        let b3 = build_test_block(b2_hash, 3, 1_300_000_005);
        cs.accept_block(&b3).expect("accept B3");
        let b3_coinbase_txid = b3.txdata[0].compute_txid();

        // Reorg should have happened — tip is B3
        assert_eq!(cs.tip_height(), 3, "tip should be at height 3 after reorg");
        assert_eq!(cs.tip_hash(), b3.block_hash(), "tip should be B3");

        // After reorg: A-chain coinbase UTXOs must NOT exist
        assert!(
            cs.get_coin(&OutPoint { txid: a1_coinbase_txid, vout: 0 }).is_none(),
            "A1 coinbase UTXO should not exist after reorg"
        );
        assert!(
            cs.get_coin(&OutPoint { txid: a2_coinbase_txid, vout: 0 }).is_none(),
            "A2 coinbase UTXO should not exist after reorg"
        );

        // B-chain coinbase UTXOs must exist
        assert!(
            cs.get_coin(&OutPoint { txid: b1_coinbase_txid, vout: 0 }).is_some(),
            "B1 coinbase UTXO should exist after reorg"
        );
        assert!(
            cs.get_coin(&OutPoint { txid: b2_coinbase_txid, vout: 0 }).is_some(),
            "B2 coinbase UTXO should exist after reorg"
        );
        assert!(
            cs.get_coin(&OutPoint { txid: b3_coinbase_txid, vout: 0 }).is_some(),
            "B3 coinbase UTXO should exist after reorg"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_checkpoint_mismatch_rejected() {
        // Build a ChainState with a fake checkpoint at height 1 that won't match
        use crate::chain::checkpoints::Checkpoint;

        let dir = std::env::temp_dir().join(format!(
            "satd-checkpoint-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks_dir = dir.join("blocks");
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();
        let mut cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap();

        // Inject a fake checkpoint at height 1 with an impossible hash
        let fake_hash: BlockHash = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        cs.checkpoints = vec![Checkpoint { height: 1, hash: fake_hash }];

        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let result = cs.accept_block(&block1);
        assert!(
            matches!(result, Err(ChainError::CheckpointMismatch(1))),
            "Block at checkpoint height with wrong hash should be rejected, got {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_prune_blocks() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build a chain of 5 blocks
        let mut parent = genesis_hash;
        let mut hashes = vec![genesis_hash];
        for i in 1..=5u32 {
            let block = build_test_block(parent, i, 1_300_000_000 + i);
            parent = cs.accept_block(&block).unwrap_or_else(|_| panic!("accept block {}", i));
            hashes.push(parent);
        }
        assert_eq!(cs.tip_height(), 5);

        // Verify we can read all blocks
        for h in &hashes {
            assert!(cs.get_block(h).is_some(), "block should be readable");
        }

        // Prune keeping only the last 2 blocks (blocks 4 and 5 kept, 0-3 pruned)
        let deleted = cs.prune_blocks(2);
        // All blocks are in file 0, and blocks 4,5 are also in file 0,
        // so the file should NOT be deleted (contains recent blocks too)
        // This tests the safety check.
        assert_eq!(deleted, 0, "Should not delete file containing recent blocks");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_pruned_block_returns_none() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build a single block
        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let hash1 = cs.accept_block(&block1).unwrap();

        // Manually mark it as pruned
        let mut entry = cs.get_block_index(&hash1).unwrap();
        entry.status = BlockStatus::Pruned;
        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((hash1, entry));
        cs.store.write_batch(batch).unwrap();

        // get_block should return None for pruned blocks
        assert!(cs.get_block(&hash1).is_none());
        assert!(cs.is_pruned(&hash1));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_store_block_creates_data_stored() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        // First, accept the header so the block's parent chain is known
        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        cs.accept_header(&block1.header).unwrap();

        // Store the block without connecting
        let (hash, height) = cs.store_block(&block1).unwrap();
        assert_eq!(hash, block1.block_hash());
        assert_eq!(height, 1);

        // Verify it's DataStored, not Valid
        let entry = cs.get_block_index(&hash).unwrap();
        assert_eq!(entry.status, BlockStatus::DataStored);
        assert_eq!(entry.height, 1);

        // Tip should still be genesis (not connected)
        assert_eq!(cs.tip_height(), 0);
        assert_eq!(cs.tip_hash(), genesis_hash);

        // Block data should be readable from flat file
        assert!(cs.has_block_data(&hash));
        assert!(cs.get_block(&hash).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_connect_stored_block() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        cs.accept_header(&block1.header).unwrap();
        let (hash, _) = cs.store_block(&block1).unwrap();

        // Connect the stored block
        let connected_hash = cs.connect_stored_block(&hash).unwrap();
        assert_eq!(connected_hash, hash);

        // Tip should now be at height 1
        assert_eq!(cs.tip_height(), 1);
        assert_eq!(cs.tip_hash(), hash);

        // Entry should be Valid now
        let entry = cs.get_block_index(&hash).unwrap();
        assert_eq!(entry.status, BlockStatus::Valid);

        // Coinbase UTXO should exist
        let coinbase_txid = block1.txdata[0].compute_txid();
        assert!(cs.get_coin(&OutPoint { txid: coinbase_txid, vout: 0 }).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_connect_stored_block_wrong_order() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        // Create blocks 1 and 2
        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let block1_hash = block1.block_hash();
        cs.accept_header(&block1.header).unwrap();
        let (_, _) = cs.store_block(&block1).unwrap();

        let block2 = build_test_block(block1_hash, 2, 1_300_000_002);
        cs.accept_header(&block2.header).unwrap();
        let (hash2, _) = cs.store_block(&block2).unwrap();

        // Try to connect block 2 before block 1 — should fail
        let result = cs.connect_stored_block(&hash2);
        assert!(
            matches!(result, Err(ChainError::BadPrevBlock)),
            "Connecting height 2 before 1 should fail, got {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_store_block_duplicate() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        cs.accept_header(&block1.header).unwrap();
        cs.store_block(&block1).unwrap();

        // Store same block again — should be Duplicate
        let result = cs.store_block(&block1);
        assert!(
            matches!(result, Err(ChainError::Duplicate)),
            "Storing same block twice should fail, got {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_header_creates_header_only() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let hash = cs.accept_header(&block1.header).unwrap();

        let entry = cs.get_block_index(&hash).unwrap();
        assert_eq!(
            entry.status,
            BlockStatus::HeaderOnly,
            "accept_header should create HeaderOnly entry"
        );
        assert_eq!(entry.height, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_header_requires_parent() {
        let (cs, dir) = make_chain_state();

        // Build a header whose prev_blockhash is unknown
        let fake_parent: BlockHash = "0000000000000000000000000000000000000000000000000000000000abcdef"
            .parse()
            .unwrap();
        let block = build_test_block(fake_parent, 1, 1_300_000_001);

        let result = cs.accept_header(&block.header);
        assert!(
            matches!(result, Err(ChainError::BadPrevBlock)),
            "accept_header with unknown parent should return BadPrevBlock, got {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_header_duplicate_returns_duplicate() {
        // accept_header returns Err(Duplicate) for already-known headers
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        cs.accept_header(&block1.header).unwrap();
        let result = cs.accept_header(&block1.header);

        assert!(
            matches!(result, Err(ChainError::Duplicate)),
            "Duplicate accept_header should return Err(Duplicate), got {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_header_bad_pow() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build a valid test block, then corrupt its nonce so PoW is invalid
        let mut block = build_test_block(genesis_hash, 1, 1_300_000_001);
        // Set bits to mainnet difficulty (extremely hard) — the hash won't meet it
        block.header.bits = bitcoin::pow::CompactTarget::from_consensus(0x1d00ffff);

        let result = cs.accept_header(&block.header);
        // This should fail either on PoW check or difficulty check (regtest expects 0x207fffff)
        assert!(
            result.is_err(),
            "accept_header with bad PoW/difficulty should fail, got {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_header_updates_headers_tip() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        assert_eq!(cs.headers_tip_height(), 0, "Initial headers_tip should be 0");

        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let hash1 = cs.accept_header(&block1.header).unwrap();

        assert_eq!(
            cs.headers_tip_height(),
            1,
            "headers_tip_height should be 1 after accepting header at height 1"
        );

        let block2 = build_test_block(hash1, 2, 1_300_000_002);
        cs.accept_header(&block2.header).unwrap();

        assert_eq!(
            cs.headers_tip_height(),
            2,
            "headers_tip_height should be 2 after accepting header at height 2"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_should_skip_scripts_disabled() {
        let (cs, dir) = make_chain_state();
        // make_chain_state creates with AssumeValid::Disabled
        assert!(
            !cs.should_skip_scripts(0),
            "should_skip_scripts should be false at height 0 with Disabled"
        );
        assert!(
            !cs.should_skip_scripts(100),
            "should_skip_scripts should be false at height 100 with Disabled"
        );
        assert!(
            !cs.should_skip_scripts(1_000_000),
            "should_skip_scripts should be false at height 1M with Disabled"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_should_skip_scripts_hash() {
        // Create a ChainState with AssumeValid::Hash pointing to a block we'll connect.
        let dir = std::env::temp_dir().join(format!(
            "satd-av-hash-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks_dir = dir.join("blocks");
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();

        // First build the chain to find the block hash
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let block1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let block1_hash = block1.block_hash();

        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Hash(block1_hash),
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap();

        // Before accepting the block, should_skip_scripts returns false
        // (hash not yet in index)
        assert!(
            !cs.should_skip_scripts(0),
            "Before block is known, should not skip scripts"
        );

        // Accept the block (connects it, adding to index)
        cs.accept_block(&block1).unwrap();

        // Now the hash is in the index at height 1
        // Height <= 1 should skip scripts
        assert!(
            cs.should_skip_scripts(0),
            "Height 0 <= 1, should skip scripts"
        );
        assert!(
            cs.should_skip_scripts(1),
            "Height 1 <= 1, should skip scripts"
        );
        // Height > 1 should NOT skip scripts
        assert!(
            !cs.should_skip_scripts(2),
            "Height 2 > 1, should not skip scripts"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_get_median_time_past_short_chain() {
        // Build a chain shorter than 11 blocks and verify MTP uses available blocks.
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        // Build 3 blocks with known timestamps.
        // t3 is between t1 and t2 (out of chronological order) to test sorting.
        // All must be above MTP at their respective heights to pass timestamp validation.
        let t1 = 1_300_000_100;
        let t2 = 1_300_000_200;
        let t3 = 1_300_000_150; // Out of order vs t2 to test sorting

        let b1 = build_test_block(genesis_hash, 1, t1);
        let h1 = cs.accept_block(&b1).unwrap();

        let b2 = build_test_block(h1, 2, t2);
        let h2 = cs.accept_block(&b2).unwrap();

        let b3 = build_test_block(h2, 3, t3);
        cs.accept_block(&b3).unwrap();

        // MTP at height 4 uses blocks at heights max(0, 4-11)..4 = 0..4
        // Timestamps: genesis.time, t1, t2, t3
        // genesis.time for regtest = 1296688602
        // Sorted: [1296688602, 1_300_000_100, 1_300_000_150, 1_300_000_200]
        // Median of 4 elements = element at index 2 = 1_300_000_150
        let mtp = cs.get_median_time_past(4);
        let genesis_time = genesis.header.time;
        let mut timestamps = [genesis_time, t1, t2, t3];
        timestamps.sort();
        let expected_median = timestamps[timestamps.len() / 2];
        assert_eq!(
            mtp, expected_median,
            "MTP should be the median of available block timestamps"
        );

        // Also verify MTP at height 1 (only genesis block)
        let mtp_1 = cs.get_median_time_past(1);
        assert_eq!(mtp_1, genesis_time, "MTP at height 1 should be genesis time");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reorg_10_blocks() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build chain A: 10 blocks from genesis
        let mut parent_a = genesis_hash;
        let mut a_hashes = Vec::new();
        for i in 1..=10u32 {
            let block = build_test_block(parent_a, i, 1_400_000_000 + i);
            parent_a = cs.accept_block(&block).unwrap_or_else(|e| panic!("accept A{}: {}", i, e));
            a_hashes.push(parent_a);
        }
        assert_eq!(cs.tip_height(), 10);
        assert_eq!(cs.tip_hash(), *a_hashes.last().unwrap());

        // Collect A-chain coinbase outpoints (to verify removal after reorg)
        let mut a_coinbase_outpoints = Vec::new();
        for hash in &a_hashes {
            let blk = cs.get_block(hash).unwrap();
            let txid = blk.txdata[0].compute_txid();
            a_coinbase_outpoints.push(OutPoint { txid, vout: 0 });
        }
        // Verify A-chain UTXOs exist
        for op in &a_coinbase_outpoints {
            assert!(cs.get_coin(op).is_some(), "A-chain UTXO should exist before reorg");
        }

        // Build chain B: 11 blocks from genesis (more work => triggers reorg)
        let mut parent_b = genesis_hash;
        let mut b_hashes = Vec::new();
        for i in 1..=11u32 {
            let block = build_test_block(parent_b, i, 1_500_000_000 + i);
            parent_b = cs.accept_block(&block).unwrap_or_else(|e| panic!("accept B{}: {}", i, e));
            b_hashes.push(parent_b);
        }

        // Tip should now be chain B
        assert_eq!(cs.tip_height(), 11);
        assert_eq!(cs.tip_hash(), *b_hashes.last().unwrap());

        // All A-chain coinbase UTXOs from unique blocks should be removed
        for (idx, op) in a_coinbase_outpoints.iter().enumerate() {
            assert!(
                cs.get_coin(op).is_none(),
                "A{} coinbase UTXO should not exist after reorg",
                idx + 1
            );
        }

        // B-chain coinbase UTXOs should exist
        for (idx, hash) in b_hashes.iter().enumerate() {
            let blk = cs.get_block(hash).unwrap();
            let txid = blk.txdata[0].compute_txid();
            let op = OutPoint { txid, vout: 0 };
            assert!(
                cs.get_coin(&op).is_some(),
                "B{} coinbase UTXO should exist after reorg",
                idx + 1
            );
        }

        // Height→hash mappings should point to B chain
        for (idx, hash) in b_hashes.iter().enumerate() {
            let h = (idx + 1) as u32;
            assert_eq!(
                cs.get_block_hash_by_height(h),
                Some(*hash),
                "Height {} should map to B-chain block",
                h
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reorg_utxo_consistency_coin_count() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Genesis coinbase is unspendable so coin_count starts at 0
        let initial_count = cs.coin_count();
        assert_eq!(initial_count, 0, "genesis should have 0 spendable UTXOs");

        // Build chain A: genesis -> A1 -> A2 (each adds 1 coinbase UTXO)
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        cs.accept_block(&a2).expect("accept A2");

        // Should have A1 + A2 = 2 UTXOs
        assert_eq!(cs.coin_count(), 2, "should have 2 UTXOs after chain A");

        // Build chain B: genesis -> B1 -> B2 -> B3 (more work => reorg)
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_010);
        let b1_hash = cs.accept_block(&b1).expect("accept B1");
        let b2 = build_test_block(b1_hash, 2, 1_300_000_011);
        let b2_hash = cs.accept_block(&b2).expect("accept B2");
        let b3 = build_test_block(b2_hash, 3, 1_300_000_012);
        cs.accept_block(&b3).expect("accept B3");

        // After reorg: A1, A2 coins removed; B1, B2, B3 coins added
        // Total = B1(1) + B2(1) + B3(1) = 3
        assert_eq!(cs.tip_height(), 3);
        assert_eq!(
            cs.coin_count(),
            3,
            "After reorg: should have 3 B-chain UTXOs"
        );

        // Verify A-chain coins are gone
        let a1_txid = a1.txdata[0].compute_txid();
        let a2_txid = a2.txdata[0].compute_txid();
        assert!(
            cs.get_coin(&OutPoint { txid: a1_txid, vout: 0 }).is_none(),
            "A1 coinbase should be removed after reorg"
        );
        assert!(
            cs.get_coin(&OutPoint { txid: a2_txid, vout: 0 }).is_none(),
            "A2 coinbase should be removed after reorg"
        );

        // Verify B-chain coins exist
        let b1_txid = b1.txdata[0].compute_txid();
        let b2_txid = b2.txdata[0].compute_txid();
        let b3_txid = b3.txdata[0].compute_txid();
        assert!(cs.get_coin(&OutPoint { txid: b1_txid, vout: 0 }).is_some());
        assert!(cs.get_coin(&OutPoint { txid: b2_txid, vout: 0 }).is_some());
        assert!(cs.get_coin(&OutPoint { txid: b3_txid, vout: 0 }).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_headers_batch() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build 100 headers chained together
        let mut headers = Vec::with_capacity(100);
        let mut parent = genesis_hash;
        for i in 1..=100u32 {
            let block = build_test_block(parent, i, 1_300_000_000 + i);
            parent = block.block_hash();
            headers.push(block.header);
        }

        let (accepted, err) = cs.accept_headers(&headers);
        assert_eq!(accepted, 100, "All 100 headers should be accepted");
        assert!(err.is_none(), "No error expected, got {:?}", err);
        assert_eq!(cs.headers_tip_height(), 100, "headers_tip should be 100");

        // Verify height→hash mappings exist for all
        for i in 1..=100u32 {
            assert!(
                cs.get_block_hash_by_height(i).is_some(),
                "Height {} should have a hash mapping",
                i
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_accept_headers_skips_known() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build 20 headers
        let mut headers = Vec::with_capacity(20);
        let mut parent = genesis_hash;
        for i in 1..=20u32 {
            let block = build_test_block(parent, i, 1_300_000_000 + i);
            parent = block.block_hash();
            headers.push(block.header);
        }

        // Accept first 10
        let (accepted1, err1) = cs.accept_headers(&headers[..10]);
        assert_eq!(accepted1, 10);
        assert!(err1.is_none());
        assert_eq!(cs.headers_tip_height(), 10);

        // Accept all 20 again — first 10 should be skipped as known
        let (accepted2, err2) = cs.accept_headers(&headers);
        assert_eq!(
            accepted2, 10,
            "Only 10 new headers should be accepted (first 10 are known)"
        );
        assert!(err2.is_none());
        assert_eq!(cs.headers_tip_height(), 20);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_median_time_past_less_than_11() {
        // Build a chain of 5 blocks with known timestamps.
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        let timestamps: [u32; 5] = [
            1_300_000_100,
            1_300_000_200,
            1_300_000_150,
            1_300_000_300,
            1_300_000_250,
        ];

        let mut parent = genesis_hash;
        for (i, &ts) in timestamps.iter().enumerate() {
            let block = build_test_block(parent, (i + 1) as u32, ts);
            parent = cs.accept_block(&block).unwrap_or_else(|e| panic!("accept block {}: {}", i + 1, e));
        }
        assert_eq!(cs.tip_height(), 5);

        // MTP at height 6 (next block) uses blocks 0..6, i.e., heights 0-5
        // Timestamps: genesis.time, 1_300_000_100, 1_300_000_200, 1_300_000_150,
        //             1_300_000_300, 1_300_000_250
        // That's 6 timestamps (less than 11).
        let genesis_time = genesis.header.time;
        let mut all_ts = vec![genesis_time];
        all_ts.extend_from_slice(&timestamps);
        all_ts.sort();
        let expected = all_ts[all_ts.len() / 2];

        let mtp = cs.get_median_time_past(6);
        assert_eq!(
            mtp, expected,
            "MTP with <11 blocks should use median of available timestamps"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_median_time_past_exactly_11() {
        // Build 12 blocks, verify MTP at height 12 is median of blocks 1-11's timestamps.
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        // Build 12 blocks with incrementing timestamps
        let base_time = 1_300_000_000u32;
        let mut parent = genesis_hash;
        let mut block_timestamps = Vec::new();
        for i in 1..=12u32 {
            let ts = base_time + i * 100;
            let block = build_test_block(parent, i, ts);
            parent = cs.accept_block(&block).unwrap_or_else(|e| panic!("accept block {}: {}", i, e));
            block_timestamps.push(ts);
        }
        assert_eq!(cs.tip_height(), 12);

        // MTP at height 12: uses blocks at heights max(0, 12-11)..12 = 1..12
        // That's blocks 1-11 (11 timestamps)
        let mut mtp_timestamps: Vec<u32> = block_timestamps[0..11].to_vec();
        mtp_timestamps.sort();
        let expected = mtp_timestamps[mtp_timestamps.len() / 2];

        let mtp = cs.get_median_time_past(12);
        assert_eq!(
            mtp, expected,
            "MTP at height 12 should be median of blocks 1-11"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_connect_stored_block_sequential() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build and store 5 blocks (accept headers, then store data)
        let mut blocks = Vec::new();
        let mut parent = genesis_hash;
        for i in 1..=5u32 {
            let block = build_test_block(parent, i, 1_300_000_000 + i);
            parent = block.block_hash();
            blocks.push(block);
        }

        // Accept all headers first
        let headers: Vec<_> = blocks.iter().map(|b| b.header).collect();
        let (accepted, err) = cs.accept_headers(&headers);
        assert_eq!(accepted, 5);
        assert!(err.is_none());

        // Store all blocks (without connecting)
        let mut hashes = Vec::new();
        for block in &blocks {
            let (hash, _) = cs.store_block(block).expect("store_block");
            hashes.push(hash);

            // Verify DataStored status
            let entry = cs.get_block_index(&hash).unwrap();
            assert_eq!(entry.status, BlockStatus::DataStored);
        }

        // Tip should still be genesis
        assert_eq!(cs.tip_height(), 0);

        // Connect them one by one in order
        for (i, hash) in hashes.iter().enumerate() {
            let connected = cs.connect_stored_block(hash).unwrap_or_else(|e| panic!(
                "connect_stored_block {} at height {}: {}",
                hash,
                i + 1,
                e
            ));
            assert_eq!(connected, *hash);
            assert_eq!(cs.tip_height(), (i + 1) as u32);
            assert_eq!(cs.tip_hash(), *hash);

            // Status should now be Valid
            let entry = cs.get_block_index(hash).unwrap();
            assert_eq!(
                entry.status,
                BlockStatus::Valid,
                "Block at height {} should be Valid after connect",
                i + 1
            );
        }

        assert_eq!(cs.tip_height(), 5);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_connect_stored_block_wrong_order_skip() {
        // Store blocks 1-5, try to connect block 3 before block 2. Should fail.
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut blocks = Vec::new();
        let mut parent = genesis_hash;
        for i in 1..=5u32 {
            let block = build_test_block(parent, i, 1_300_000_000 + i);
            parent = block.block_hash();
            blocks.push(block);
        }

        // Accept headers and store all blocks
        let headers: Vec<_> = blocks.iter().map(|b| b.header).collect();
        cs.accept_headers(&headers);
        let mut hashes = Vec::new();
        for block in &blocks {
            let (hash, _) = cs.store_block(block).unwrap();
            hashes.push(hash);
        }

        // Connect block 1 (should succeed — parent is genesis = current tip)
        cs.connect_stored_block(&hashes[0]).expect("connect block 1");
        assert_eq!(cs.tip_height(), 1);

        // Try to connect block 3 (skipping block 2) — should fail with BadPrevBlock
        let result = cs.connect_stored_block(&hashes[2]);
        assert!(
            matches!(result, Err(ChainError::BadPrevBlock)),
            "Connecting block 3 before block 2 should fail with BadPrevBlock, got {:?}",
            result
        );

        // Tip should still be at height 1
        assert_eq!(cs.tip_height(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Force `hash`'s block-index status, bypassing the writers, and drop the
    /// overlay so the next read sees it. Reproduces the persisted shape of
    /// #567, where the `Valid` writes for a run of blocks never reached disk
    /// while the tip pointer moved past them.
    fn force_status(cs: &ChainState, hash: &BlockHash, status: BlockStatus) {
        let mut entry = cs.get_block_index(hash).expect("entry must exist");
        entry.status = status;
        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((*hash, entry));
        cs.store.write_batch(batch).unwrap();
        cs.store.invalidate_block_index_cache(hash);
    }

    /// A reorg must not rebuild a branch on top of a block that was never
    /// connected.
    ///
    /// The parent check below the reorg only ever sees the *triggering* block,
    /// and by then this loop has already stamped its parent `Valid` — so the
    /// fork point itself went unchecked. A reorg forking at a hole would
    /// reconnect the entire side branch onto it and commit a new tip, which is
    /// the #567 damage arrived at from the other direction.
    ///
    /// Also pins the rollback: a refusal mid-reorg must restore the pre-reorg
    /// tip rather than strand the chain at the fork point.
    #[test]
    fn reorg_refuses_to_rebuild_onto_an_unconnected_fork_point() {
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        // Active chain: genesis -> A1 -> A2.
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        let a2_hash = cs.accept_block(&a2).expect("accept A2");
        assert_eq!(cs.tip_hash(), a2_hash);

        // A1 becomes a block this chainstate never connected. Its hash is
        // untouched, so every prev-hash check on the way still passes.
        force_status(&cs, &a1_hash, BlockStatus::DataStored);

        // A competing branch forking at A1, with more work once B3 lands.
        let b2 = build_test_block(a1_hash, 2, 1_300_000_003);
        cs.accept_block(&b2).expect("accept B2 as a side block");
        let b3 = build_test_block(b2.block_hash(), 3, 1_300_000_004);

        let result = cs.accept_block(&b3);
        assert!(
            matches!(result, Err(ChainError::ParentNeverConnected)),
            "a reorg onto an unconnected fork point must be refused, got {result:?}"
        );
        assert_eq!(
            cs.tip_hash(),
            a2_hash,
            "the refused reorg must restore the pre-reorg tip, not strand the chain"
        );
        assert_eq!(cs.tip_height(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The tip's hash matching a block's `prev_blockhash` is not evidence the
    /// tip's coins were ever applied. #567: the in-memory tip advanced eight
    /// blocks past the last block actually connected, and every connect on the
    /// way up satisfied the prev-hash check.
    #[test]
    fn connect_refuses_a_parent_that_was_never_connected() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 5);
        assert_eq!(cs.tip_height(), 5);

        let next = build_test_block(cs.tip_hash(), 6, 1_300_000_006);
        cs.accept_header(&next.header).unwrap();
        cs.store_block(&next).unwrap();

        // The tip reads as a block this chainstate never connected. Its hash
        // is untouched, so the prev-hash check still passes.
        force_status(&cs, &blocks[4].block_hash(), BlockStatus::DataStored);

        let result = cs.connect_stored_block(&next.block_hash());
        assert!(
            matches!(result, Err(ChainError::ParentNeverConnected)),
            "connecting onto an unconnected parent must be refused, got {result:?}"
        );
        assert_eq!(cs.tip_height(), 5, "the tip must not have moved");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The AssumeUTXO snapshot base is `DataStored` until the background
    /// chainstate has re-validated all of genesis→base, which can take days.
    /// Connecting base+1 must not wait for that — it is the entire point of a
    /// snapshot.
    #[test]
    fn connect_allows_the_assumeutxo_snapshot_base_as_parent() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 5);
        let base = blocks[4].block_hash();

        let next = build_test_block(cs.tip_hash(), 6, 1_300_000_006);
        cs.accept_header(&next.header).unwrap();
        cs.store_block(&next).unwrap();

        // A snapshot base looks exactly like the #567 damage from the block
        // index alone: never connected here, yet its coins are present.
        force_status(&cs, &base, BlockStatus::DataStored);

        // Perturbation: with no background attached, this is indistinguishable
        // from damage and must be refused.
        assert!(
            matches!(
                cs.connect_stored_block(&next.block_hash()),
                Err(ChainError::ParentNeverConnected)
            ),
            "without a snapshot base to point at, an unconnected parent is damage"
        );

        cs.store.flush().unwrap();
        let (anchor, _) = crate::storage::compressed_coin::hash_utxo_set(&*cs.store).unwrap();
        cs.attach_background(dir.join("chainstate_background"), 5, base, anchor, 64, -1)
            .unwrap();

        cs.connect_stored_block(&next.block_hash())
            .expect("base+1 must connect while the background is still validating");
        assert_eq!(cs.tip_height(), 6);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `connect_stored_block` verifies that the record it read is the block it
    /// is connecting. `connect_preprocessed_block` reads no record — the
    /// prefetcher hands it a decoded block — but it commits `tip.hash =
    /// pre.hash` without ever reconciling that hash against `pre.block`. A
    /// prefetcher that paired a block with the wrong entry would connect one
    /// block's coins and name a different block as the tip.
    #[test]
    fn connect_preprocessed_rejects_a_block_that_is_not_its_declared_hash() {
        use crate::chain::prefetch::PreprocessedBlock;
        use std::collections::HashSet;

        let (cs, dir) = make_chain_state();
        build_and_connect_chain(&cs, 5);

        let next = build_test_block(cs.tip_hash(), 6, 1_300_000_006);
        cs.accept_header(&next.header).unwrap();
        cs.store_block(&next).unwrap();
        let entry = cs.get_block_index(&next.block_hash()).unwrap();
        let parent = cs.get_block_index(&cs.tip_hash()).unwrap();

        // A sibling at the same height with the same parent: it validates,
        // which is exactly what makes the mismatch dangerous.
        let sibling = build_test_block(cs.tip_hash(), 6, 1_300_000_007);
        assert_ne!(sibling.block_hash(), next.block_hash());

        let pre = PreprocessedBlock {
            height: 6,
            hash: next.block_hash(),
            block: sibling,
            entry: entry.clone(),
            parent,
            flat_pos: crate::storage::flatfile::FlatFilePos {
                file_number: entry.file_number,
                data_pos: entry.data_pos,
            },
            mtp: cs.get_median_time_past(6),
            txids: Vec::new(),
            script_verified_txs: HashSet::new(),
            context_free_checked: false,
        };

        let result = cs.connect_preprocessed_block(pre);
        assert!(
            matches!(result, Err(ChainError::FlatFile(_))),
            "a preprocessed block that is not its declared hash must be refused, got {result:?}"
        );
        assert_eq!(cs.tip_height(), 5, "the tip must not have moved");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The exemption is one block wide. Once the live chain has built on the
    /// base, an unconnected block *above* it is damage again.
    #[test]
    fn snapshot_base_exemption_does_not_extend_above_the_base() {
        let (cs, dir) = make_chain_state();
        let blocks = build_and_connect_chain(&cs, 5);
        let base = blocks[3].block_hash();

        let next = build_test_block(cs.tip_hash(), 6, 1_300_000_006);
        cs.accept_header(&next.header).unwrap();
        cs.store_block(&next).unwrap();

        cs.store.flush().unwrap();
        let (anchor, _) = crate::storage::compressed_coin::hash_utxo_set(&*cs.store).unwrap();
        cs.attach_background(dir.join("chainstate_background"), 4, base, anchor, 64, -1)
            .unwrap();

        // The tip (height 5) is one above the base, and never connected.
        force_status(&cs, &blocks[4].block_hash(), BlockStatus::DataStored);

        assert!(
            matches!(
                cs.connect_stored_block(&next.block_hash()),
                Err(ChainError::ParentNeverConnected)
            ),
            "only the base itself is exempt"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dump_utxo_snapshot_roundtrip_via_codec() {
        use crate::storage::compressed_coin::{
            deserialize_coin, read_compact_size, write_txout_ser, SnapshotMetadata,
            SNAPSHOT_MAGIC_BYTES, SNAPSHOT_VERSION,
        };
        use std::io::BufReader;
        use std::io::Read as _;

        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Five blocks → five coinbase UTXOs. Each coinbase is in its
        // own txid, so the dump produces 5 single-coin groups.
        let mut parent = genesis_hash;
        for i in 1..=5u32 {
            let block = build_test_block(parent, i, 1_300_000_000 + i);
            parent = cs.accept_block(&block).expect("accept_block");
        }
        assert_eq!(cs.tip_height(), 5);

        let snapshot_path = dir.join("dump.snapshot");
        let summary = cs
            .dump_utxo_snapshot(&snapshot_path)
            .expect("dump_utxo_snapshot");
        assert_eq!(summary.coins_written, 5);
        assert_eq!(summary.base_height, 5);
        assert_eq!(summary.base_hash, cs.tip_hash());
        assert_eq!(summary.path, snapshot_path);

        // Verify the temp file is gone (rename succeeded).
        let temp_path = make_incomplete_path(&snapshot_path);
        assert!(!temp_path.exists(), "leftover .incomplete file");

        // Parse the file back via the Core-format reader. The file
        // structure is: SnapshotMetadata(51) || repeat[ txid(32) ||
        // CompactSize(coins_in_group) || repeat[ CompactSize(vout) ||
        // Coin ] ].
        let file = File::open(&snapshot_path).expect("open snapshot");
        let mut reader = BufReader::new(file);
        let meta = SnapshotMetadata::deserialize(&mut reader).expect("parse header");
        assert_eq!(meta.version, SNAPSHOT_VERSION);
        assert_eq!(meta.network_magic, [0xfa, 0xbf, 0xb5, 0xda]); // regtest
        assert_eq!(meta.base_blockhash, cs.tip_hash());
        assert_eq!(meta.coins_count, 5);

        // Independently hash the UTXO set via TxOutSer (the
        // HASH_SERIALIZED_3 algorithm) and verify it matches what
        // `dump_utxo_snapshot` reported. This is the cross-validation
        // contract against Core's `m_assumeutxo_data.hash_serialized`.
        let mut hs3 = bitcoin::hashes::sha256::HashEngine::default();
        let mut record_buf = Vec::with_capacity(80);

        let mut decoded = 0u64;
        while decoded < meta.coins_count {
            // Read one txid group.
            let mut txid_bytes = [0u8; 32];
            reader.read_exact(&mut txid_bytes).expect("read txid");
            let txid = bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array(txid_bytes),
            );
            let group_size = read_compact_size(&mut reader).expect("read group size");
            for _ in 0..group_size {
                let vout = read_compact_size(&mut reader).expect("read vout");
                let coin = deserialize_coin(&mut reader).expect("decode coin");
                let op = bitcoin::OutPoint {
                    txid,
                    vout: vout as u32,
                };
                // Independently feed the HASH_SERIALIZED_3 hasher.
                record_buf.clear();
                write_txout_ser(&mut record_buf, &op, &coin).unwrap();
                bitcoin::hashes::HashEngine::input(&mut hs3, &record_buf);
                decoded += 1;
            }
        }
        assert_eq!(decoded, 5);

        // Finalize exactly as the dump does: double SHA-256
        // (Core's HashWriter::GetHash) then byte-reverse to the
        // natural order used by the anchor table.
        let expected_hs3 = {
            let first = bitcoin::hashes::sha256::Hash::from_engine(hs3);
            let double = bitcoin::hashes::sha256::Hash::hash(first.as_byte_array());
            let mut b = double.to_byte_array();
            b.reverse();
            b
        };
        assert_eq!(
            summary.hash_serialized_3, expected_hs3,
            "reported hash_serialized_3 must equal independent recomputation"
        );

        // The shared `Hs3Hasher` / `hash_utxo_set` helper (used by the
        // AssumeUTXO background-validation handoff) must produce the
        // identical hash over the same chainstate — this keeps the
        // handoff comparison in lockstep with the cross-validated dump
        // path without re-deriving the algorithm.
        cs.store.flush().unwrap();
        let (helper_hash, helper_base) =
            crate::storage::compressed_coin::hash_utxo_set(&*cs.store).unwrap();
        assert_eq!(
            helper_hash, summary.hash_serialized_3,
            "hash_utxo_set must match dumptxoutset's reported hash_serialized_3"
        );
        assert_eq!(helper_base.base_hash, summary.base_hash);
        assert_eq!(helper_base.coin_count, meta.coins_count);

        // EOF after the last group.
        let mut tail = [0u8; 1];
        assert_eq!(
            reader.read(&mut tail).unwrap(),
            0,
            "snapshot has trailing bytes"
        );

        // First 5 bytes are the snapshot magic.
        let raw = std::fs::read(&snapshot_path).unwrap();
        assert_eq!(&raw[..5], &SNAPSHOT_MAGIC_BYTES);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dump_base_comes_from_store_snapshot_not_in_memory_tip() {
        // Regression for the dumptxoutset base/coins race. The snapshot's
        // base block MUST be read from the same store snapshot as the
        // coins, never from the in-memory `ChainState` tip: block
        // connection commits the coin batch to the store BEFORE
        // publishing the in-memory tip, so a base read from the in-memory
        // tip can name a block whose coins the snapshot doesn't contain.
        //
        // We reproduce that skew directly. Connect 5 blocks (store and
        // in-memory tip in sync), then poison ONLY the in-memory tip with
        // a bogus hash/height and dump. The reported base must track the
        // store's real height-5 tip, not the poisoned in-memory value —
        // which is exactly what the pre-fix code (reading `self.tip`)
        // would have emitted.
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut parent = genesis_hash;
        for i in 1..=5u32 {
            let block = build_test_block(parent, i, 1_300_000_000 + i);
            parent = cs.accept_block(&block).expect("accept_block");
        }
        let real_tip = cs.tip_hash();
        assert_eq!(cs.tip_height(), 5);

        // Poison the in-memory tip; the store still reflects height 5.
        {
            let bogus = {
                use bitcoin::hashes::Hash;
                BlockHash::from_byte_array([0x7c; 32])
            };
            let mut tip = cs.tip.write();
            tip.hash = bogus;
            tip.height = 999;
        }

        let path = dir.join("base-from-store.dat");
        let summary = cs.dump_utxo_snapshot(&path).expect("dump");

        assert_eq!(
            summary.base_hash, real_tip,
            "dump base must come from the store snapshot, not the in-memory tip"
        );
        assert_eq!(summary.base_height, 5);
        assert_eq!(summary.coins_written, 5);

        // The on-disk header (rewritten after iteration) must agree.
        let file = File::open(&path).expect("open snapshot");
        let mut reader = std::io::BufReader::new(file);
        let meta = crate::storage::compressed_coin::SnapshotMetadata::deserialize(&mut reader)
            .expect("parse header");
        assert_eq!(meta.base_blockhash, real_tip);
        assert_eq!(meta.coins_count, 5);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dump_finalize_refuses_to_clobber_concurrently_created_target() {
        // Finding 2 regression: the early `path.exists()` check is
        // advisory; the authoritative no-overwrite guarantee is enforced
        // at finalization. Simulate a target that appears AFTER that
        // early check by calling `finalize_dump_path` directly against a
        // destination that already exists. It must refuse, not clobber.
        let (_, dir) = make_chain_state();
        std::fs::create_dir_all(&dir).unwrap();
        let temp_path = dir.join("snap.dat.incomplete");
        let final_path = dir.join("snap.dat");
        std::fs::write(&temp_path, b"freshly completed dump").unwrap();
        std::fs::write(&final_path, b"PRECIOUS pre-existing file").unwrap();

        let err = finalize_dump_path(&temp_path, &final_path)
            .expect_err("must refuse to overwrite existing target");
        assert!(matches!(err, DumpError::RefuseOverwrite(_)));

        // The pre-existing file is untouched.
        assert_eq!(
            std::fs::read(&final_path).unwrap(),
            b"PRECIOUS pre-existing file"
        );

        // And a free target succeeds, moving the temp file into place.
        let fresh = dir.join("fresh.dat");
        finalize_dump_path(&temp_path, &fresh).expect("finalize into free path");
        assert_eq!(std::fs::read(&fresh).unwrap(), b"freshly completed dump");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dump_utxo_snapshot_removes_temp_on_error() {
        // RefuseOverwrite errors before any temp file is created, so
        // exercise a different error path: pre-create the temp file
        // and verify that `create_new` rejects it, AND that no other
        // file is left behind. This documents the corpse-cleanup
        // contract.
        let (cs, dir) = make_chain_state();
        let snapshot_path = dir.join("clean.dat");
        let temp_path = make_incomplete_path(&snapshot_path);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&temp_path, b"stale corpse from a prior crashed run").unwrap();

        let err = cs
            .dump_utxo_snapshot(&snapshot_path)
            .expect_err("should fail on stale .incomplete");
        // The error surfaces as Io(AlreadyExists) from `create_new`.
        assert!(matches!(err, DumpError::Io(_)));

        // The pre-existing corpse must NOT be deleted by the guard —
        // it belongs to the operator. Our guard only owns paths we
        // successfully created via create_new.
        let corpse = std::fs::read(&temp_path).unwrap();
        assert_eq!(corpse, b"stale corpse from a prior crashed run");

        // And the final path was never created.
        assert!(!snapshot_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dump_utxo_snapshot_refuses_overwrite() {
        let (cs, dir) = make_chain_state();
        let path = dir.join("preexisting.dat");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, b"do not clobber me").unwrap();

        let err = cs
            .dump_utxo_snapshot(&path)
            .expect_err("should refuse overwrite");
        assert!(matches!(err, DumpError::RefuseOverwrite(_)));

        // File contents must be unchanged.
        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"do not clobber me");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dump_utxo_snapshot_empty_utxo_set() {
        let (cs, dir) = make_chain_state();
        // Genesis only — its coinbase is unspendable so coin_count() is 0.
        assert_eq!(cs.coin_count(), 0);

        let path = dir.join("empty.dat");
        let summary = cs.dump_utxo_snapshot(&path).expect("dump empty");
        assert_eq!(summary.coins_written, 0);

        // File should be exactly 51 bytes (just the header).
        let len = std::fs::metadata(&path).unwrap().len();
        assert_eq!(len, 51);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_flush_coin_cache() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Connect several blocks
        let mut parent = genesis_hash;
        for i in 1..=5u32 {
            let block = build_test_block(parent, i, 1_300_000_000 + i);
            parent = cs.accept_block(&block).unwrap_or_else(|e| panic!("accept block {}: {}", i, e));
        }
        assert_eq!(cs.tip_height(), 5);

        // Flush the coin cache — should not error
        cs.flush_coin_cache().expect("flush_coin_cache should succeed");

        // Verify coin_count reflects all connected blocks' UTXOs
        // Genesis coinbase is unspendable, so only the 5 block coinbases count
        assert_eq!(
            cs.coin_count(),
            5,
            "After flush, coin_count should reflect 5 coinbase UTXOs"
        );

        // Verify individual coins still accessible after flush
        for i in 1..=5u32 {
            let hash = cs.get_block_hash_by_height(i).unwrap();
            let block = cs.get_block(&hash).unwrap();
            let txid = block.txdata[0].compute_txid();
            assert!(
                cs.get_coin(&OutPoint { txid, vout: 0 }).is_some(),
                "Coinbase at height {} should be accessible after flush",
                i
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_headers_tip_binary_search() {
        // Accept 1000 headers, create a new ChainState from the same store
        // (simulating restart). Verify headers_tip_height is correctly found.
        let dir = std::env::temp_dir().join(format!(
            "satd-bsearch-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks_dir = dir.join("blocks");
        let store = Box::new(InMemoryStore::new());

        // We need a shared store between the two ChainState instances.
        // Since InMemoryStore is behind Box<dyn Store>, we clone the data
        // by accepting headers first, then creating a new ChainState on a
        // fresh store and manually replaying. Instead, use a simpler approach:
        // accept headers in one CS, then verify its headers_tip_height directly.
        // The binary search runs inside ChainState::new when the store has an
        // existing tip, so we test that by connecting blocks (not just headers)
        // to set the tip, then accepting more headers to push headers_tip ahead.

        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap();

        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Connect 5 blocks to set a non-genesis tip
        let mut parent = genesis_hash;
        for i in 1..=5u32 {
            let block = build_test_block(parent, i, 1_300_000_000 + i);
            parent = cs.accept_block(&block).unwrap_or_else(|e| panic!("accept block {}: {}", i, e));
        }
        assert_eq!(cs.tip_height(), 5);

        // Now accept 995 more headers (heights 6-1000) without connecting blocks
        let mut header_parent = parent;
        let mut headers = Vec::with_capacity(995);
        for i in 6..=1000u32 {
            let block = build_test_block(header_parent, i, 1_300_000_000 + i);
            header_parent = block.block_hash();
            headers.push(block.header);
        }
        let (accepted, err) = cs.accept_headers(&headers);
        assert_eq!(accepted, 995);
        assert!(err.is_none());
        assert_eq!(cs.headers_tip_height(), 1000);

        // Now simulate a restart: create a new ChainState from the same store.
        // We can't reuse InMemoryStore directly (it's consumed), but we can
        // verify the binary search logic by checking that the current CS
        // correctly reports headers_tip_height = 1000 even though only 5 blocks
        // are connected as tip.
        assert_eq!(cs.tip_height(), 5, "Block tip should be 5");
        assert_eq!(
            cs.headers_tip_height(),
            1000,
            "Headers tip should be 1000 (5 connected + 995 header-only)"
        );

        // Verify some header-only entries exist at various heights
        for h in [6, 100, 500, 999, 1000] {
            let hash = cs.get_block_hash_by_height(h).unwrap_or_else(|| panic!(
                "Height {} should have a hash mapping",
                h
            ));
            let entry = cs.get_block_index(&hash).unwrap();
            assert_eq!(
                entry.status,
                BlockStatus::HeaderOnly,
                "Block at height {} should be HeaderOnly",
                h
            );
            assert_eq!(entry.height, h);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: `reindex_chainstate` used to never flush the in-memory
    /// dirty-cache, so a full-chain reindex accumulated every UTXO mutation
    /// unbounded. On mainnet this hit 122 GiB RSS at block ~430k before
    /// OOM-killed the process. With the fix, the periodic durable-flush
    /// at 1000-block boundaries fires and the final flush drains the
    /// dirty set before return.
    #[test]
    fn reindex_chainstate_flushes_periodically_and_at_end() {
        let (cs, dir) = make_chain_state();
        // Build 1200 blocks — past the 1000-block durable-flush cadence
        // so the periodic-flush path fires at least once mid-reindex
        // (in addition to the final flush on completion).
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut parent = genesis.block_hash();
        for h in 1..=1200u32 {
            let block = build_test_block(parent, h, 1_300_000_000 + h);
            parent = cs.accept_block(&block).unwrap();
        }

        // Clear chainstate + reset in-memory tip so reindex starts fresh.
        // `accept_block` above already flushed many times; baseline from
        // here so we're only counting reindex-triggered flushes.
        cs.store.flush().unwrap(); // drain anything outstanding
        cs.store.clear_chainstate().unwrap();
        {
            let mut tip = cs.tip.write();
            tip.hash = genesis.block_hash();
            tip.height = 0;
        }
        let flushes_before = cs
            .store
            .flush_count
            .load(std::sync::atomic::Ordering::Relaxed);

        cs.reindex_chainstate(None, None, None).unwrap();

        let flushes_after = cs
            .store
            .flush_count
            .load(std::sync::atomic::Ordering::Relaxed);
        let reindex_flushes = flushes_after - flushes_before;

        // Without the fix: zero flushes fire during reindex (dirty set
        // grows unbounded and the function never calls flush()). With
        // the fix: at least one mid-reindex flush at height 1000 plus a
        // final flush at completion = ≥ 2.
        assert!(
            reindex_flushes >= 2,
            "reindex must flush at least periodic + final; got {reindex_flushes}"
        );

        // And the final flush must drain the dirty set, otherwise the
        // in-memory state survives past return.
        assert_eq!(
            cs.store.dirty_count(),
            0,
            "dirty cache not drained by final flush after reindex"
        );

        // Verify correctness: tip is back at the last block.
        assert_eq!(cs.tip_height(), 1200);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Open a second `ChainState` with an empty database over an existing
    /// `blocks/` directory — exactly the state `-reindex` leaves behind
    /// (`store.clear_all()`, then `ChainState::new` re-seeds genesis, then the
    /// flat-file replay runs).
    fn reindexing_chain_state_over(dir: &std::path::Path) -> ChainState {
        ChainState::new(
            Box::new(InMemoryStore::new()),
            FlatFileManager::new(&dir.join("blocks")).unwrap(),
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap()
    }

    /// Regression: a flat-file reindex must replay only the most-work branch.
    ///
    /// Flat files hold every block the node ever fully received, including
    /// orphaned ones, so any node that has been live through a reorg has fork
    /// points on disk. The old replay BFS'd the whole tree and connected every
    /// genesis-reachable block as if it extended the tip. Where the two
    /// branches did not conflict that *succeeded* — silently applying the
    /// losing block's UTXO delta on top of the winning chain and reporting a
    /// completed reindex over a corrupt UTXO set. This is the silent half of
    /// the bug; `reindex_from_flat_files_survives_conflicting_stale_sibling`
    /// covers the loud half.
    #[test]
    fn reindex_from_flat_files_does_not_index_a_corrupt_side_chain_record() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut parent = genesis_hash;
        let mut main_hashes = Vec::new();
        for h in 1..=3u32 {
            let b = build_test_block(parent, h, 1_709_000_000 + h);
            parent = cs.accept_block(&b).expect("accept main block");
            main_hashes.push(parent);
        }
        let main_tip = parent;

        // A sibling of block 2 whose payload is corrupt: the header is intact,
        // so the flat-file scan indexes it under the right hash and it passes
        // the PoW re-check, but its transactions no longer match its merkle
        // root. Written straight to the flat files — never accepted — so the
        // scan finds only the corrupt copy, as an in-place bit flip would leave
        // it.
        let mut sibling = build_test_block(main_hashes[0], 2, 1_709_000_999);
        let sibling_hash = sibling.block_hash();
        let mut script = sibling.txdata[0].input[0].script_sig.to_bytes();
        let last = script.len() - 1;
        script[last] ^= 0xff;
        sibling.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from(script);
        assert_eq!(
            sibling.block_hash(),
            sibling_hash,
            "the header must be untouched"
        );
        assert!(
            validation::pow::check_proof_of_work(&sibling.header).is_ok(),
            "the fixture must get past the PoW re-check to reach the new one"
        );
        cs.flat_files
            .lock()
            .write_block(
                &bitcoin::consensus::serialize(&sibling),
                network_magic(Network::Regtest),
            )
            .expect("write corrupt sibling record");

        cs.flush_coin_cache().expect("flush before snapshotting");
        cs.store.flush().unwrap();

        let re = reindexing_chain_state_over(&dir);
        re.reindex_from_flat_files(None, None)
            .expect("a bad side-chain block must not abort the reindex");

        assert_eq!(re.tip_hash(), main_tip, "the main chain must still replay");
        assert_eq!(re.tip_height(), 3);
        assert!(
            re.store.get_block_index(&sibling_hash).is_none(),
            "a block whose bytes fail validation was indexed as DataStored —              `connect_stored_block` would apply them verbatim if the branch won"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Issue #542. A main-chain block whose stored bytes fail validation must
    /// stop the replay, not fail it.
    ///
    /// The caller has already wiped the chainstate by the time the replay runs,
    /// so an `Err` here leaves the node with nothing *and* re-derives the same
    /// plan on every retry — an unrecoverable state produced by the recovery
    /// tool, armed by an upgrade alone because the offending block is already
    /// on disk from an older release.
    #[test]
    fn reindex_from_flat_files_stops_at_an_unreplayable_main_chain_block() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut parent = genesis_hash;
        let mut main_hashes = Vec::new();
        for h in 1..=3u32 {
            let b = build_test_block(parent, h, 1_709_100_000 + h);
            parent = cs.accept_block(&b).expect("accept main block");
            main_hashes.push(parent);
        }

        // Corrupt block 2's payload in place, leaving its header — and so its
        // hash — untouched, as an in-place bit flip would. Phase 1 scans the
        // header and puts the block on the planned path; the payload then fails
        // `check_block` on its merkle root.
        let mut corrupt = build_test_block(main_hashes[0], 2, 1_709_100_002);
        assert_eq!(corrupt.block_hash(), main_hashes[1], "test setup: same block");
        let mut script = corrupt.txdata[0].input[0].script_sig.to_bytes();
        let last = script.len() - 1;
        script[last] ^= 0xff;
        corrupt.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from(script);
        assert_eq!(
            corrupt.block_hash(),
            main_hashes[1],
            "test setup: the header must be untouched"
        );
        overwrite_block_record(&cs, &dir, &main_hashes[1], &corrupt);

        cs.flush_coin_cache().expect("flush before snapshotting");
        cs.store.flush().unwrap();

        let re = reindexing_chain_state_over(&dir);
        re.reindex_from_flat_files(None, None)
            .expect("an unreplayable block must stop the reindex, not fail it");

        assert_eq!(
            re.tip_height(),
            1,
            "everything below the bad block must stay replayed and durable"
        );
        assert_eq!(re.tip_hash(), main_hashes[0]);

        // No index entry for the bad block or anything above it: that is what
        // lets normal IBD re-fetch those heights from peers, since a peer's
        // copy no longer collides with a stored entry.
        for (i, hash) in main_hashes.iter().enumerate().skip(1) {
            assert!(
                re.store.get_block_index(hash).is_none(),
                "block {} was indexed; a peer's copy can no longer replace it",
                i + 1
            );
        }

        // And it must not be quiet — a reindex that stops early and reports
        // success is the "completed reindex over a partial chain" shape.
        let warnings = re.warnings().list();
        let halted = warnings
            .iter()
            .find(|w| w.id == "reindex.halted")
            .expect("the halt must reach the warnings registry");
        assert_eq!(halted.severity, crate::warnings::Severity::Error);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Issue #533. A live `block_index` entry whose data is unreadable is local
    /// corruption, not pruning, and must be reported as such.
    #[test]
    fn unreadable_block_data_behind_a_live_entry_raises_a_warning() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let b1 = build_test_block(genesis_hash, 1, 1_709_200_001);
        let h1 = cs.accept_block(&b1).expect("accept");

        assert!(cs.get_block(&h1).is_some(), "readable before the hole");
        assert!(
            cs.warnings().list().is_empty(),
            "no warning before the corruption"
        );

        punch_block_data_hole(&cs, &dir, &h1);

        assert!(
            cs.get_block(&h1).is_none(),
            "`None` stays the return value; callers are built around it"
        );
        let id = format!("blockdata.corrupt.{h1}");
        let warnings = cs.warnings().list();
        let w = warnings
            .iter()
            .find(|w| w.id == id)
            .expect("corruption must be distinguishable from pruning");
        assert_eq!(w.severity, crate::warnings::Severity::Error);
        assert!(
            w.message.contains("getblockfrompeer"),
            "the warning must name the repair: {}",
            w.message
        );

        // Per block, so several damaged records report separately, and a repeat
        // read refreshes rather than accumulating.
        assert!(cs.get_block(&h1).is_none());
        assert_eq!(
            cs.warnings().list().iter().filter(|w| w.id == id).count(),
            1
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reindex_from_flat_files_ignores_non_conflicting_stale_sibling() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Main chain: genesis -> m1 .. m5.
        let mut parent = genesis_hash;
        let mut main_hashes = Vec::new();
        let mut blocks = Vec::new();
        for h in 1..=5u32 {
            let b = build_test_block(parent, h, 1_700_100_000 + h);
            parent = cs.accept_block(&b).expect("accept main block");
            main_hashes.push(parent);
            blocks.push(b);
        }
        let main_tip = parent;

        // A stale sibling of m3: same parent (m2), no transactions in common,
        // so connecting it on top of m3 would NOT fail — it would just add a
        // coinbase that never existed on the active chain.
        let stale = build_test_block(main_hashes[1], 3, 1_700_200_003);
        let stale_hash = cs.accept_block(&stale).expect("store stale sibling");
        assert_eq!(cs.tip_hash(), main_tip, "equal work must not reorg the tip");
        let stale_coin = OutPoint {
            txid: stale.txdata[0].compute_txid(),
            vout: 0,
        };

        cs.flush_coin_cache().expect("flush before snapshotting");
        let expected_coins = cs.store.coin_count();

        // Reindex from the flat files with an empty database.
        let re = reindexing_chain_state_over(&dir);
        re.reindex_from_flat_files(None, None)
            .expect("reindex must not abort on a fork point");

        assert_eq!(re.tip_hash(), main_tip, "replayed the wrong branch");
        assert_eq!(re.tip_height(), 5);
        re.flush_coin_cache().expect("flush reindexed state");
        assert!(
            re.get_coin(&stale_coin).is_none(),
            "stale sibling's coinbase leaked into the reindexed UTXO set"
        );
        assert_eq!(
            re.store.coin_count(),
            expected_coins,
            "reindexed UTXO set does not match the pre-reindex set"
        );

        // The whole active chain must be addressable by height, and the stale
        // block must not own any height.
        for (i, h) in main_hashes.iter().enumerate() {
            assert_eq!(
                re.store.get_block_hash_by_height(i as u32 + 1),
                Some(*h),
                "height->hash wrong at {}",
                i + 1
            );
        }

        // The stale block's data is still on disk, so it stays addressable by
        // hash — `getblockheader` on an orphaned hash keeps working across a
        // reindex — but as DataStored, never connected.
        let stale_entry = re
            .store
            .get_block_index(&stale_hash)
            .expect("stale sibling must still be indexed after reindex");
        assert_eq!(stale_entry.status, BlockStatus::DataStored);
        assert_eq!(stale_entry.height, 3);
        assert_eq!(
            stale_entry.num_tx,
            stale.txdata.len() as u32,
            "side-chain index entry must carry the real transaction count"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression for the production failure this fix came from: a mainnet
    /// `-reindex` over Core's block files aborted with
    /// `bad-txns-inputs-missingorspent` at height 916308, the first fork point
    /// on disk. The old replay connected the stale sibling first (valid on top
    /// of its parent), then fed the main-chain block the same coin — already
    /// spent — and died three days into the rebuild.
    #[test]
    fn reindex_from_flat_files_survives_conflicting_stale_sibling() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // 101 blocks so block 1's coinbase is mature and spendable at 102.
        let mut parent = genesis_hash;
        let first = build_test_block(parent, 1, 1_700_300_001);
        parent = cs.accept_block(&first).expect("accept block 1");
        for h in 2..=101u32 {
            let b = build_test_block(parent, h, 1_700_300_000 + h);
            parent = cs.accept_block(&b).expect("accept filler block");
        }
        let mature = OutPoint {
            txid: first.txdata[0].compute_txid(),
            vout: 0,
        };

        // Two competing blocks at height 102, both spending the same coin.
        let main = build_test_block_spending(parent, 102, 1_700_300_102, mature);
        let main_hash = cs.accept_block(&main).expect("accept main 102");
        let stale = build_test_block_spending(parent, 102, 1_700_400_102, mature);
        let stale_hash = cs.accept_block(&stale).expect("store stale 102");
        assert_ne!(main_hash, stale_hash);
        assert_eq!(cs.tip_hash(), main_hash, "equal work must not reorg the tip");

        let re = reindexing_chain_state_over(&dir);
        re.reindex_from_flat_files(None, None)
            .expect("reindex must not abort on a double-spending stale sibling");

        assert_eq!(re.tip_hash(), main_hash);
        assert_eq!(re.tip_height(), 102);
        assert!(
            re.get_coin(&mature).is_none(),
            "the mature coin must be spent exactly once, by the main chain"
        );
        assert_eq!(
            re.store.get_block_hash_by_height(102),
            Some(main_hash),
            "stale sibling must not own height 102"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The winning branch is not necessarily the one written to disk first. A
    /// node that reorged has the abandoned branch earlier in its flat files;
    /// the replay must still land on the branch with the most work and demote
    /// the abandoned one to side-chain index entries.
    #[test]
    fn reindex_from_flat_files_follows_the_reorg_winner() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Branch A (written first): genesis -> a1 .. a5.
        let mut parent = genesis_hash;
        let mut a_hashes = Vec::new();
        for h in 1..=5u32 {
            let b = build_test_block(parent, h, 1_700_500_000 + h);
            parent = cs.accept_block(&b).expect("accept A block");
            a_hashes.push(parent);
        }
        assert_eq!(cs.tip_height(), 5);

        // Branch B forks at a2 and overtakes: heights 3..8.
        let mut parent = a_hashes[1];
        let mut b_hashes = Vec::new();
        for h in 3..=8u32 {
            let b = build_test_block(parent, h, 1_700_600_000 + h);
            parent = cs.accept_block(&b).expect("accept B block");
            b_hashes.push(parent);
        }
        let b_tip = parent;
        assert_eq!(cs.tip_hash(), b_tip, "live node must have reorged to B");
        assert_eq!(cs.tip_height(), 8);

        cs.flush_coin_cache().expect("flush before snapshotting");
        let expected_coins = cs.store.coin_count();

        let re = reindexing_chain_state_over(&dir);
        re.reindex_from_flat_files(None, None).expect("reindex");

        assert_eq!(re.tip_hash(), b_tip, "replay must follow the most work");
        assert_eq!(re.tip_height(), 8);
        re.flush_coin_cache().expect("flush reindexed state");
        assert_eq!(re.store.coin_count(), expected_coins);

        // A's abandoned tail (a3..a5) is indexed but not on the active chain.
        for (i, h) in a_hashes.iter().enumerate().skip(2) {
            let e = re
                .store
                .get_block_index(h)
                .expect("abandoned branch must stay indexed");
            assert_eq!(e.status, BlockStatus::DataStored);
            assert_eq!(e.height, i as u32 + 1);
            assert_ne!(
                re.store.get_block_hash_by_height(i as u32 + 1),
                Some(*h),
                "abandoned branch must not own a height in the active index"
            );
        }
        // B owns every height above the fork.
        for (i, h) in b_hashes.iter().enumerate() {
            assert_eq!(re.store.get_block_hash_by_height(i as u32 + 3), Some(*h));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `-reindex-chainstate` used to pick the block to replay at each height
    /// from the height→hash index. That index is derived state, and it has been
    /// observed polluted with a fork block in production (#322, and the
    /// `bad-cb-height` reindex loop that followed). Given such an index the old
    /// replay connected the fork block, carried on with the main chain on top of
    /// it, and returned `Ok` over a UTXO set assembled from two branches.
    ///
    /// The replay now selects by chainwork over the block index, so a polluted
    /// height index cannot misdirect it at all — it is not consulted. The
    /// replay both completes and rewrites the bad entry.
    #[test]
    fn reindex_chainstate_ignores_a_polluted_height_index() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut parent = genesis_hash;
        let mut main_hashes = Vec::new();
        for h in 1..=5u32 {
            let b = build_test_block(parent, h, 1_701_000_000 + h);
            parent = cs.accept_block(&b).expect("accept main block");
            main_hashes.push(parent);
        }
        let main_tip = *main_hashes.last().unwrap();
        // Stale sibling of block 3, stored but never on the active chain.
        let stale = build_test_block(main_hashes[1], 3, 1_701_100_003);
        let stale_hash = cs.accept_block(&stale).expect("store stale sibling");
        assert_eq!(cs.tip_hash(), main_tip);
        let stale_coin = OutPoint {
            txid: stale.txdata[0].compute_txid(),
            vout: 0,
        };

        cs.flush_coin_cache().expect("flush before snapshotting");
        let expected_coins = cs.store.coin_count();

        cs.store.flush().unwrap();
        cs.store.clear_chainstate().unwrap();
        {
            let mut tip = cs.tip.write();
            tip.hash = genesis_hash;
            tip.height = 0;
        }
        // The shape a polluted index takes: a fork block owning a height.
        pollute_height_hash(&cs, 3, stale_hash);

        cs.reindex_chainstate(None, None, None)
            .expect("chainwork selection must not be misled by the height index");

        assert_eq!(cs.tip_hash(), main_tip, "replayed the wrong branch");
        assert_eq!(cs.tip_height(), 5);
        cs.flush_coin_cache().expect("flush replayed state");
        assert!(
            cs.get_coin(&stale_coin).is_none(),
            "stale block's coinbase leaked into the replayed UTXO set"
        );
        assert_eq!(
            cs.store.coin_count(),
            expected_coins,
            "replayed UTXO set does not match the pre-reindex set"
        );
        assert_eq!(
            cs.store.get_block_hash_by_height(3),
            Some(main_hashes[2]),
            "the replay must rewrite the polluted height entry"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A polluted height→hash row at the TIP height must not steer the
    /// tie-break.
    ///
    /// Deep review found the planner re-deriving its tie-break incumbent with
    /// `get_block_hash_by_height(required_height)` — the exact derived state
    /// this module exists to distrust, read at the exact height where #322
    /// pollution was observed. The incumbent *wins* an exact chainwork tie, so
    /// a polluted row handed the win to an equal-work stale sibling and rebuilt
    /// the whole chainstate onto the orphan: the inverse of the fix's purpose.
    /// The sibling test above pollutes a mid-chain height, where the loser is
    /// excluded on work and the incumbent never gets a say; only a tie at the
    /// tip exercises this.
    ///
    /// The incumbent is now the authoritative tip hash, passed in from the
    /// metadata CF before it is cleared.
    #[test]
    fn reindex_chainstate_tie_break_ignores_a_polluted_height_index() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut parent = genesis_hash;
        let mut main_hashes = Vec::new();
        for h in 1..=4u32 {
            let b = build_test_block(parent, h, 1_704_000_000 + h);
            parent = cs.accept_block(&b).expect("accept main block");
            main_hashes.push(parent);
        }
        let real_tip = *main_hashes.last().unwrap();
        let real_height = cs.tip_height();
        assert_eq!(real_height, 4);

        // An equal-work sibling OF THE TIP: same parent, same bits, so the two
        // branches tie exactly on cumulative chainwork and the incumbent rule
        // is what decides.
        let sibling = build_test_block(main_hashes[2], 4, 1_704_000_999);
        let sibling_hash = cs.accept_block(&sibling).expect("store tip sibling");
        assert_ne!(sibling_hash, real_tip, "fixture must produce a distinct sibling");
        assert_eq!(cs.tip_hash(), real_tip, "equal work must not reorg the tip");

        cs.flush_coin_cache().expect("flush before snapshotting");
        cs.store.flush().unwrap();
        cs.store.clear_chainstate().unwrap();
        {
            let mut tip = cs.tip.write();
            tip.hash = genesis_hash;
            tip.height = 0;
        }
        // The #322 shape, at the height where it decides a tie.
        pollute_height_hash(&cs, real_height, sibling_hash);

        cs.reindex_chainstate(None, None, Some((real_tip, real_height)))
            .expect("replay must succeed");

        assert_eq!(
            cs.tip_hash(),
            real_tip,
            "the tie-break must follow the authoritative tip, not the polluted row"
        );
        assert_eq!(
            cs.store.get_block_hash_by_height(real_height),
            Some(real_tip),
            "the replay must rewrite the polluted height entry"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A block index whose `flat_pos` points at the wrong record must fail the
    /// replay, on the path that actually carries it.
    ///
    /// The prefetch worker labels each block with the hash the *plan* asked for
    /// while reading the bytes from the *index's* `flat_pos`, and never
    /// reconciles the two. So a corrupt position yielded a `PreprocessedBlock`
    /// claiming to be the planned block while holding a different one:
    /// `connect_block` wrote that block's hash, height row and UTXO delta, and
    /// the caller then set the in-memory tip to the plan's hash. Every later
    /// `require_extends_tip` compares against the in-memory tip and passes, so
    /// the replay ran to completion and reported success with the persisted
    /// chainstate and the in-memory tip naming different blocks.
    ///
    /// `require_extends_tip` is not enough here: it sees the real block's
    /// header on this path, so the wrong record must be a child of the current
    /// tip — which a stale sibling of the planned block is, and that is the
    /// shape the corruption takes.
    ///
    /// This calls the connect directly rather than driving a full reindex: the
    /// prefetcher is a race between background workers and the connect cursor,
    /// so a whole-replay fixture cannot guarantee the hit lands on this path
    /// instead of the direct-read fallback.
    #[test]
    fn reindex_prefetched_connect_rejects_a_block_index_pointing_at_the_wrong_record() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // The planned block, and an equal-work sibling of it that is also on
        // disk — the wrong-but-well-formed record a corrupt position lands on.
        let planned = build_test_block(genesis_hash, 1, 1_705_000_001);
        let planned_hash = cs.accept_block(&planned).expect("accept planned block");
        let wrong = build_test_block(genesis_hash, 1, 1_705_000_999);
        let wrong_hash = cs.accept_block(&wrong).expect("store sibling");
        assert_ne!(planned_hash, wrong_hash, "fixture must produce two records");
        assert_eq!(
            wrong.header.prev_blockhash, genesis_hash,
            "the wrong record must still extend the tip, or require_extends_tip \
             would reject it and prove nothing"
        );

        cs.flush_coin_cache().expect("flush before clearing");
        cs.store.flush().unwrap();
        let entry = cs.store.get_block_index(&planned_hash).expect("planned entry");
        let parent = cs.store.get_block_index(&genesis_hash).expect("genesis entry");
        cs.store.clear_chainstate().unwrap();
        {
            let mut tip = cs.tip.write();
            tip.hash = genesis_hash;
            tip.height = 0;
        }

        let flat_pos = FlatFilePos {
            file_number: entry.file_number,
            data_pos: entry.data_pos,
        };
        let pre = crate::chain::prefetch::PreprocessedBlock {
            height: 1,
            hash: planned_hash, // from the plan
            txids: wrong.txdata.iter().map(|tx| tx.compute_txid()).collect(),
            block: wrong.clone(), // from the corrupt flat_pos
            entry,
            parent,
            flat_pos,
            mtp: cs.get_median_time_past(1),
            script_verified_txs: std::collections::HashSet::new(),
            context_free_checked: false,
        };

        let plan =
            crate::chain::replay_plan::plan_replay_from_block_index(&*cs.store, genesis_hash, None)
                .expect("plan the replay");
        let err = cs
            .reindex_connect_prefetched(&plan, pre)
            .expect_err("a record that is not the planned block must not connect");
        assert!(
            matches!(err, ChainError::BadPrevBlock),
            "unexpected error: {err:?}"
        );
        assert_eq!(
            cs.tip_hash(),
            genesis_hash,
            "the tip must not advance past a block the replay refused"
        );
        cs.flush_coin_cache().expect("flush after the refusal");
        assert!(
            cs.get_coin(&OutPoint {
                txid: wrong.txdata[0].compute_txid(),
                vout: 0,
            })
            .is_none(),
            "the wrong record's coinbase reached the UTXO set"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Search a nonce so `header` satisfies the regtest target. Needed to forge
    /// an index entry that survives the planner's PoW check — without it the
    /// planner drops the block and the replay fails for the wrong reason.
    fn remine_header(header: &mut bitcoin::block::Header) {
        use bitcoin::hashes::Hash;
        let target = crate::storage::blockindex::target_from_compact(header.bits);
        for nonce in 0u32..u32::MAX {
            header.nonce = nonce;
            let hash_bytes = *header.block_hash().as_raw_hash().as_byte_array();
            let mut hash_be = [0u8; 32];
            for i in 0..32 {
                hash_be[i] = hash_bytes[31 - i];
            }
            if hash_be <= target {
                return;
            }
        }
        panic!("failed to re-mine a forged header");
    }

    /// Put a block on disk and in the block index without connecting it — the
    /// state a reindex finds for every block above the chainstate's tip.
    fn store_block_without_connecting(cs: &ChainState, block: &Block, height: u32) {
        use crate::storage::blockindex::{BlockIndexEntry, BlockStatus, add_u256, work_for_bits};
        let pos = cs
            .flat_files
            .lock()
            .write_block(
                &bitcoin::consensus::serialize(block),
                network_magic(Network::Regtest),
            )
            .expect("write block record");
        let parent = cs
            .store
            .get_block_index(&block.header.prev_blockhash)
            .expect("parent entry");
        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((
            block.block_hash(),
            BlockIndexEntry {
                header: block.header,
                height,
                status: BlockStatus::DataStored,
                num_tx: block.txdata.len() as u32,
                file_number: pos.file_number,
                data_pos: pos.data_pos,
                chainwork: add_u256(&parent.chainwork, &work_for_bits(block.header.bits)),
            },
        ));
        cs.store.write_batch(batch).expect("index the block");
        cs.store.invalidate_block_index_cache(&block.block_hash());
        cs.store.flush().expect("flush the index write");
    }

    /// A block whose payload was corrupted after it was written must fail the
    /// replay (issue #505).
    ///
    /// The flat-file record framing carries no checksum — `scan_one_file`
    /// validates magic and length — so a bit flipped inside a transaction
    /// payload leaves the 80-byte header hashing correctly. It passes the PoW
    /// re-check, it passes the planned-record check, and before this it was
    /// connected: the corrupted UTXO delta landed and the reindex reported
    /// success. Core runs `CheckBlock` on every block during reindex.
    ///
    /// Corrupted structurally rather than by seeking into the file, so the
    /// fixture does not depend on record layout or the blocks-dir xor key: one
    /// byte of the coinbase's extra-nonce push is flipped and the original
    /// header — merkle root included — is kept.
    #[test]
    fn reindex_chainstate_rejects_a_block_whose_payload_was_corrupted() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut parent = genesis_hash;
        let mut hashes = Vec::new();
        let mut blocks = Vec::new();
        for h in 1..=3u32 {
            let b = build_test_block(parent, h, 1_707_000_000 + h);
            parent = cs.accept_block(&b).expect("accept block");
            hashes.push(parent);
            blocks.push(b);
        }

        let mut corrupted = blocks[1].clone();
        let mut script = corrupted.txdata[0].input[0].script_sig.to_bytes();
        let last = script.len() - 1;
        script[last] ^= 0xff;
        corrupted.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from(script);
        assert_eq!(
            corrupted.block_hash(),
            hashes[1],
            "the header must be untouched — that is the whole difficulty"
        );
        assert_ne!(
            corrupted.compute_merkle_root().unwrap(),
            corrupted.header.merkle_root,
            "the fixture must actually break the commitment"
        );

        // Write the corrupted bytes as a new record and point block 2's index
        // entry at it, exactly as a bit flip in place would look.
        let pos = cs
            .flat_files
            .lock()
            .write_block(
                &bitcoin::consensus::serialize(&corrupted),
                network_magic(Network::Regtest),
            )
            .expect("write corrupted record");
        cs.flush_coin_cache().expect("flush before clearing");
        cs.store.flush().unwrap();

        let mut entry = cs.store.get_block_index(&hashes[1]).expect("block 2 entry");
        entry.file_number = pos.file_number;
        entry.data_pos = pos.data_pos;
        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((hashes[1], entry));
        cs.store.write_batch(batch).expect("repoint block 2");
        cs.store.invalidate_block_index_cache(&hashes[1]);
        cs.store.flush().unwrap();

        cs.store.clear_chainstate().unwrap();
        {
            let mut tip = cs.tip.write();
            tip.hash = genesis_hash;
            tip.height = 0;
        }

        let err = cs
            .reindex_chainstate(None, None, Some((hashes[2], 3)))
            .expect_err("a block that does not match its own merkle root must not connect");
        assert!(
            matches!(
                err,
                ChainError::Validation(crate::validation::ValidationError::BadMerkleRoot)
            ),
            "unexpected error: {err:?}"
        );
        assert!(
            cs.tip_height() < 2,
            "the corrupted block connected anyway (tip at {})",
            cs.tip_height()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The base case of the replay's induction: genesis.
    ///
    /// Every block the replay connects has its indexed header checked against
    /// the block file before anything reads it, and MTP is the median of those
    /// indexed timestamps — so the run validates everything it consumes, given
    /// a trustworthy starting point. Genesis is the exception: the replay
    /// starts above it, so no connect ever validates its entry, and blocks 1
    /// through 11 take their MTP partly from it. It is compared against the
    /// network constant instead.
    #[test]
    fn reindex_chainstate_refuses_a_forged_genesis_entry() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut parent = genesis_hash;
        let mut hashes = Vec::new();
        for h in 1..=3u32 {
            let b = build_test_block(parent, h, 1_710_000_000 + h);
            parent = cs.accept_block(&b).expect("accept block");
            hashes.push(parent);
        }
        let main_tip = parent;

        cs.flush_coin_cache().expect("flush before clearing");
        cs.store.flush().unwrap();

        // Genesis keeps its hash as the index key while its stored header says
        // something else — the timestamp blocks 1..11 would average in.
        let mut forged = cs
            .store
            .get_block_index(&genesis_hash)
            .expect("genesis entry");
        forged.header.time += 10_000;
        remine_header(&mut forged.header);
        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((genesis_hash, forged));
        cs.store.write_batch(batch).expect("write forged genesis entry");
        cs.store.invalidate_block_index_cache(&genesis_hash);
        cs.store.flush().unwrap();

        cs.store.clear_chainstate().unwrap();
        {
            let mut tip = cs.tip.write();
            tip.hash = genesis_hash;
            tip.height = 0;
        }

        let err = cs
            .reindex_chainstate(None, None, Some((main_tip, 3)))
            .expect_err("a genesis entry that is not this network's genesis must stop the replay");
        assert!(
            matches!(err, ChainError::BadPrevBlock),
            "unexpected error: {err:?}"
        );
        assert_eq!(cs.tip_height(), 0, "nothing may connect on a forged base case");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The MTP the replay validates against must come from the plan, not from
    /// the height→hash index.
    ///
    /// `get_median_time_past` resolves each of the eleven preceding heights
    /// through the height→hash index — the derived state this replay exists to
    /// distrust — and the prefetch path had already been given a plan-driven
    /// MTP precisely because of that. Only the direct read still used it, so
    /// the consensus input depended on whether the prefetcher happened to hit,
    /// which at replay startup it never does.
    ///
    /// The rows it reads sit *below* the connect cursor, and a resumed replay
    /// never rewrites them: they are whatever the original sync left, which is
    /// exactly where the #322 pollution (a fork block owning a height) was
    /// observed. MTP gates BIP113 locktimes, so a timestamp from the wrong
    /// branch is a validity decision made against a chain the node is not
    /// replaying.
    ///
    /// Observable through a non-final, time-locked transaction: the polluted
    /// MTP falls below its locktime and the block is rejected as non-final,
    /// while the real branch's MTP clears it and the block goes on to fail at
    /// input resolution instead. The missing-input error IS the pass.
    #[test]
    fn reindex_direct_connect_takes_mtp_from_the_plan_not_the_height_index() {
        const BASE: u32 = 1_705_000_000;
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut parent = genesis_hash;
        let mut hashes = vec![genesis_hash];
        for h in 1..=12u32 {
            let b = build_test_block(parent, h, BASE + 100 * h);
            parent = cs.accept_block(&b).expect("accept main block");
            hashes.push(parent);
        }

        // A stale sibling of height 10, timestamped low enough to drag the
        // median down when it usurps that height's row. It must still be
        // above its own ancestors' MTP or it would not have been storable.
        let stale = build_test_block(hashes[9], 10, BASE + 650);
        let stale_hash = cs.accept_block(&stale).expect("store stale sibling");
        assert_eq!(cs.tip_hash(), hashes[12], "the sibling must not win the tip");

        // Block 13 goes on disk and into the index WITHOUT being connected —
        // the state a reindex actually finds. It cannot be accepted normally:
        // its transaction spends an outpoint that does not exist, which is the
        // second half of the observable.
        let bogus = OutPoint {
            txid: stale.txdata[0].compute_txid(),
            vout: 7,
        };
        let lock_time = BASE + 680;
        let b13 = build_test_block_timelocked(hashes[12], 13, BASE + 1300, bogus, lock_time);
        let h13 = b13.block_hash();
        store_block_without_connecting(&cs, &b13, 13);

        let plan = crate::chain::replay_plan::plan_replay_from_block_index(
            &*cs.store,
            genesis_hash,
            Some(hashes[12]),
        )
        .expect("plan the replay");
        assert_eq!(plan.hash_at(13), Some(h13), "plan must reach block 13");

        // The #322 shape, at a height inside block 13's MTP window.
        pollute_height_hash(&cs, 10, stale_hash);
        // A fresh process reindexing at startup has an empty MTP cache, so the
        // store lookups are what run. Warm entries here would mask that.
        cs.mtp_cache.lock().clear();

        let planned_mtp = connect::median_time_past_with_plan(&*cs.store, Some(&plan), 13);
        let indexed_mtp = cs.get_median_time_past(13);
        assert_eq!(planned_mtp, BASE + 700, "MTP of the branch being replayed");
        assert_eq!(indexed_mtp, BASE + 650, "MTP the polluted rows produce");
        assert!(
            indexed_mtp < lock_time && planned_mtp >= lock_time,
            "fixture must straddle the locktime: {indexed_mtp} < {lock_time} <= {planned_mtp}"
        );

        let err = cs
            .reindex_connect_direct(&plan, 13, h13)
            .expect_err("block 13 spends a nonexistent outpoint");
        assert!(
            matches!(
                err,
                ChainError::Connect(connect::ConnectError::MissingOrSpentInput { .. })
            ),
            "expected the locktime check to pass on the replayed branch's MTP and the \
             connect to fail on the missing input; got {err:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The indexed header must match the header in the block file.
    ///
    /// `get_block_index` keys on the block hash, but nothing constrains the
    /// header stored under that key to be the one that hashes to it — and an
    /// index damaged in the header bytes is squarely what `-reindex-chainstate`
    /// is run to repair. Both replay paths took the parent link, and therefore
    /// the cumulative chainwork handed to `connect_block`, from that stored
    /// header, and the direct path additionally checked the extends-tip guard
    /// against it rather than against the block it was about to connect.
    ///
    /// Forged here in `bits`, the field that decides the branch's work in
    /// selection: an entry claiming more work than the block file supports
    /// steers the plan onto a chain the files do not back. Verifying the
    /// record's hash does not catch this — the block on disk IS the planned
    /// block; only the index's copy of its header is a lie.
    #[test]
    fn reindex_direct_connect_rejects_an_indexed_header_the_block_file_contradicts() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let b1 = build_test_block(genesis_hash, 1, 1_706_000_001);
        let h1 = cs.accept_block(&b1).expect("accept block 1");
        let b2 = build_test_block(h1, 2, 1_706_000_002);
        let h2 = cs.accept_block(&b2).expect("accept block 2");

        cs.flush_coin_cache().expect("flush before clearing");
        cs.store.flush().unwrap();

        // Forge the stored header's difficulty. The parent link is left intact,
        // so the extends-tip guard passes and the record at `flat_pos` is still
        // the planned block: this check is the only thing standing in the way.
        let mut forged = cs.store.get_block_index(&h2).expect("entry for block 2");
        forged.header.bits = bitcoin::pow::CompactTarget::from_consensus(0x207ffffe);
        assert_ne!(forged.header, b2.header, "fixture must forge something");
        assert_eq!(
            forged.header.prev_blockhash, b2.header.prev_blockhash,
            "the forgery must leave the parent link alone"
        );
        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((h2, forged));
        cs.store.write_batch(batch).expect("write forged entry");
        cs.store.invalidate_block_index_cache(&h2);

        cs.store.clear_chainstate().unwrap();
        {
            let mut tip = cs.tip.write();
            tip.hash = h1;
            tip.height = 1;
        }

        let plan =
            crate::chain::replay_plan::plan_replay_from_block_index(&*cs.store, genesis_hash, None)
                .expect("plan the replay");
        assert_eq!(plan.hash_at(2), Some(h2), "plan must reach block 2");

        let err = cs
            .reindex_connect_direct(&plan, 2, h2)
            .expect_err("a header the block file contradicts must not connect");
        assert!(
            matches!(err, ChainError::BadPrevBlock),
            "unexpected error: {err:?}"
        );
        assert_eq!(cs.tip_hash(), h1, "the tip must not advance past the refusal");
        cs.flush_coin_cache().expect("flush after the refusal");
        assert!(
            cs.get_coin(&OutPoint {
                txid: b2.txdata[0].compute_txid(),
                vout: 0,
            })
            .is_none(),
            "the block connected despite a forged indexed header"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The critical fail-open found in review: selection admits only
    /// `DataStored`/`Valid` blocks and requires every ancestor to qualify, so a
    /// single ineligible block low in the chain empties the plan. The replay
    /// then connected nothing and returned `Ok`.
    ///
    /// A pruned node is the guaranteed case — every block below the prune
    /// horizon is `Pruned` — and the outcome was a node serving height 0 with
    /// an empty UTXO set, while `clear_chainstate` had already stamped the tx
    /// and address indexes complete. Before the plan existed this failed
    /// loudly, on the unreadable pruned block.
    #[test]
    fn reindex_chainstate_refuses_to_replay_a_truncated_chain() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut parent = genesis_hash;
        for h in 1..=6u32 {
            let b = build_test_block(parent, h, 1_703_000_000 + h);
            parent = cs.accept_block(&b).expect("accept block");
        }
        let real_tip = cs.tip_hash();
        let real_height = cs.tip_height();
        assert_eq!(real_height, 6);

        // Drain the cache's pending block-index writes first: a later flush
        // would otherwise replay the original `Valid` entry over the `Pruned`
        // one written below.
        cs.store.flush().unwrap();

        // Mark block 2 unreplayable, exactly as pruning does. Everything above
        // it now has an ineligible ancestor.
        let pruned_hash = cs.store.get_block_hash_by_height(2).unwrap();
        let mut entry = cs.store.get_block_index(&pruned_hash).unwrap();
        entry.status = BlockStatus::Pruned;
        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((pruned_hash, entry));
        cs.store.write_batch(batch).unwrap();
        assert_eq!(
            cs.store.get_block_index(&pruned_hash).unwrap().status,
            BlockStatus::Pruned,
            "fixture did not take effect"
        );

        cs.store.clear_chainstate().unwrap();
        {
            let mut tip = cs.tip.write();
            tip.hash = genesis_hash;
            tip.height = 0;
        }

        let err = cs
            .reindex_chainstate(None, None, Some((real_tip, real_height)))
            .expect_err("a replay that cannot reach the previous height must fail, not report success");
        assert!(
            matches!(err, ChainError::BadPrevBlock),
            "expected a coverage failure, got {err:?}"
        );
        assert_eq!(
            cs.tip_height(),
            0,
            "the failed replay must not leave a partial chainstate advertised as complete"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A partially-replayed chainstate is never resumed — not even when it sits
    /// on the branch now selected, which used to be allowed.
    ///
    /// The replay's safety property is inductive: each block's indexed header
    /// is checked against the block file before anything reads it, so the
    /// parent links, chainwork and MTP timestamps it derives from indexed
    /// headers are all backed by the block files. Starting above genesis breaks
    /// the induction, and BIP68 makes the hole unbounded — it evaluates a spent
    /// coin's MTP at the coin's creation height, which can be anywhere in
    /// history, so a resumed run reads timestamps from entries nothing
    /// reconciled. `main.rs` clears the chainstate before every
    /// `-reindex-chainstate`, so the daemon never resumed in the first place.
    #[test]
    fn reindex_chainstate_refuses_to_resume_a_partial_chainstate() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut parent = genesis_hash;
        let mut hashes = Vec::new();
        for h in 1..=5u32 {
            let b = build_test_block(parent, h, 1_702_000_000 + h);
            parent = cs.accept_block(&b).expect("accept main block");
            hashes.push(parent);
        }
        let main_tip = parent;

        cs.flush_coin_cache().expect("flush before clearing");
        cs.store.flush().unwrap();
        cs.store.clear_chainstate().unwrap();
        // A previous run replayed as far as height 3 — on the winning branch,
        // the case the old guard let through.
        {
            let mut tip = cs.tip.write();
            tip.hash = hashes[2];
            tip.height = 3;
        }

        let err = cs
            .reindex_chainstate(None, None, Some((main_tip, 5)))
            .expect_err("a partial chainstate must not be resumed, on-branch or not");
        assert!(
            matches!(err, ChainError::BadPrevBlock),
            "expected a refusal, got {err:?}"
        );
        assert_eq!(
            cs.tip_height(),
            3,
            "the refusal must not touch the chainstate it declined to extend"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Side-chain blocks are indexed without a height→hash row because that row
    /// names the active chain. `accept_headers` restores a "missing" row for
    /// any `DataStored` entry whose height is vacant, so a side block ABOVE the
    /// selected tip would get one written on the next headers message —
    /// re-creating the active-chain pollution the omission exists to prevent.
    /// Those blocks must be left unindexed.
    #[test]
    fn reindex_from_flat_files_does_not_index_side_blocks_above_the_tip() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Main chain to 5, then a competing branch from block 2 that overtakes
        // to 8 — so after the reorg the abandoned A-branch tail sits at heights
        // 3..5, all at or below the winning tip.
        let mut parent = genesis_hash;
        let mut a_hashes = Vec::new();
        for h in 1..=5u32 {
            let b = build_test_block(parent, h, 1_704_000_000 + h);
            parent = cs.accept_block(&b).expect("accept A block");
            a_hashes.push(parent);
        }
        let mut parent = a_hashes[1];
        for h in 3..=8u32 {
            let b = build_test_block(parent, h, 1_704_100_000 + h);
            parent = cs.accept_block(&b).expect("accept B block");
        }
        let b_tip = parent;
        assert_eq!(cs.tip_hash(), b_tip);

        let re = reindexing_chain_state_over(&dir);
        re.reindex_from_flat_files(None, None).expect("reindex");
        assert_eq!(re.tip_height(), 8);

        // Every indexed side block must sit at a height the active chain also
        // occupies, so `accept_headers` can never see a vacant height for one.
        for h in a_hashes.iter().skip(2) {
            let e = re.store.get_block_index(h).expect("side block indexed");
            assert!(
                e.height <= re.tip_height(),
                "indexed a side block above the tip at height {}",
                e.height
            );
            assert!(
                re.store.get_block_hash_by_height(e.height).is_some(),
                "height {} is vacant, so accept_headers would claim it for the side block",
                e.height
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A block can legitimately appear on disk more than once (crash-resume
    /// re-write, re-download). Phase 1 must collapse the copies: a repeated
    /// `children` edge makes the planner re-walk that block's whole subtree per
    /// copy and emit duplicate side-chain index entries.
    #[test]
    fn reindex_from_flat_files_tolerates_duplicate_records() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut parent = genesis_hash;
        let mut blocks = Vec::new();
        for h in 1..=5u32 {
            let b = build_test_block(parent, h, 1_700_900_000 + h);
            parent = cs.accept_block(&b).expect("accept block");
            blocks.push(b);
        }
        let main_tip = parent;
        cs.flush_coin_cache().expect("flush before snapshotting");
        let expected_coins = cs.store.coin_count();

        // Append second copies of blocks 2 and 3 to the flat files, mimicking
        // the duplicate records a real datadir accumulates.
        {
            let mut flat = cs.flat_files.lock();
            for b in &blocks[1..3] {
                flat.write_block(&serialize(b), network_magic(Network::Regtest))
                    .expect("write duplicate record");
            }
        }

        let re = reindexing_chain_state_over(&dir);
        re.reindex_from_flat_files(None, None)
            .expect("reindex over duplicated records");

        assert_eq!(re.tip_hash(), main_tip);
        assert_eq!(re.tip_height(), 5, "duplicates must not inflate the chain");
        re.flush_coin_cache().expect("flush reindexed state");
        assert_eq!(
            re.store.coin_count(),
            expected_coins,
            "a duplicate record must not double-apply its UTXO delta"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `-stopatheight` still halts the replay mid-chain. Side-chain blocks are
    /// deliberately not indexed on that path: the chainstate stops short of the
    /// tree the entries would describe.
    #[test]
    fn reindex_from_flat_files_honors_stop_at_height_without_indexing_side_chain() {
        let (cs, dir) = make_chain_state();
        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        let mut parent = genesis_hash;
        let mut main_hashes = Vec::new();
        for h in 1..=6u32 {
            let b = build_test_block(parent, h, 1_700_700_000 + h);
            parent = cs.accept_block(&b).expect("accept main block");
            main_hashes.push(parent);
        }
        let stale = build_test_block(main_hashes[1], 3, 1_700_800_003);
        let stale_hash = cs.accept_block(&stale).expect("store stale sibling");

        let re = reindexing_chain_state_over(&dir);
        re.reindex_from_flat_files(Some(4), None)
            .expect("reindex to -stopatheight");

        assert_eq!(re.tip_height(), 4);
        assert_eq!(re.tip_hash(), main_hashes[3]);
        assert!(
            re.store.get_block_index(&stale_hash).is_none(),
            "a halted replay must not index side-chain blocks it did not reach"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reindex_chainstate_reproduces_utxo_set() {
        // The pipelined reindex (prefetcher + BulkLoad) must rebuild a
        // byte-identical UTXO set. Build a chain, snapshot its UTXO-set
        // hash, wipe the chainstate (keeping the block index), replay, and
        // compare. 300 blocks is long enough for the prefetch workers to
        // run ahead of the connect cursor, so both the prefetched and
        // direct-read connect paths are exercised.
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut parent = genesis.block_hash();
        for h in 1..=300u32 {
            let block = build_test_block(parent, h, 1_300_000_000 + h);
            parent = cs.accept_block(&block).unwrap();
        }
        cs.store.flush().unwrap();
        let count_before = cs.coin_count();
        let (hash_before, _) =
            crate::storage::compressed_coin::hash_utxo_set(&*cs.store).unwrap();
        assert_eq!(cs.tip_height(), 300);

        // Wipe chainstate (block index is preserved) and reset the in-memory
        // tip, mirroring `-reindex-chainstate` startup.
        cs.store.clear_chainstate().unwrap();
        {
            let mut tip = cs.tip.write();
            tip.hash = genesis.block_hash();
            tip.height = 0;
        }

        cs.reindex_chainstate(None, None, None).unwrap();
        cs.store.flush().unwrap();

        assert_eq!(cs.tip_height(), 300, "reindex must restore the tip height");
        assert_eq!(
            cs.coin_count(),
            count_before,
            "coin count must match after reindex"
        );
        let (hash_after, _) =
            crate::storage::compressed_coin::hash_utxo_set(&*cs.store).unwrap();
        assert_eq!(
            hash_after, hash_before,
            "reindexed UTXO set must be byte-identical to the original"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `reindex_chainstate` must honor `-stopatheight`: when a target
    /// height is given, replay halts cleanly at that height even when
    /// the block index extends past it. The chain-event watcher that
    /// implements `-stopatheight` for the normal IBD path is not wired
    /// at reindex time, so reindex has to enforce the bound itself.
    #[test]
    fn reindex_chainstate_honors_stop_at() {
        let (cs, dir) = make_chain_state();
        // Build 600 blocks. We'll stop at 400 — well past the first
        // periodic-flush boundary so we exercise the durable-flush
        // path too, but with enough remaining to confirm we don't
        // run past the target.
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut parent = genesis.block_hash();
        for h in 1..=600u32 {
            let block = build_test_block(parent, h, 1_300_000_000 + h);
            parent = cs.accept_block(&block).unwrap();
        }
        cs.store.flush().unwrap();
        cs.store.clear_chainstate().unwrap();
        {
            let mut tip = cs.tip.write();
            tip.hash = genesis.block_hash();
            tip.height = 0;
        }

        let progress = crate::startup_progress::StartupProgress::new();
        progress.set_phase("reindex_chainstate", "Replaying UTXO set");
        cs.reindex_chainstate(Some(400), Some(progress.clone()), None)
            .unwrap();

        assert_eq!(cs.tip_height(), 400, "reindex must stop at the target");
        let snap = progress.snapshot();
        assert_eq!(
            snap.stop_height,
            Some(400),
            "progress must surface the stop target so the TUI can render it"
        );
        assert_eq!(snap.total, 600, "progress total must reflect file tip");
        assert_eq!(snap.current, 400, "current must end exactly at stop_at");
        // Regression guard for the reindex-chainstate ETA (issue #254): the
        // replay loop must feed the weight-aware estimator via `set_eta`. At
        // the stop target current == target, so `estimate_eta` returns
        // `Some(0)` and the snapshot surfaces it. If the `set_eta` wiring is
        // ever dropped the phase falls back to the linear estimate, which is
        // `None` here (denominator == current) — so this pins that the daemon
        // actually populates `eta_secs` for the `reindex_chainstate` phase
        // rather than leaving the TUI's ETA blank for the whole reindex.
        assert_eq!(
            snap.eta_secs,
            Some(0),
            "reindex must feed the ETA estimator so getstartupinfo reports eta_secs"
        );

        // Final flush must still drain the dirty set so the tip at 400
        // is durable; the operator restarts and continues from here.
        assert_eq!(
            cs.store.dirty_count(),
            0,
            "dirty cache not drained by final flush at stop_at"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Synthetic block tree for the `plan_reindex_chain` unit tests: builds the
    /// `parent → children` and `hash → header` maps the phase-1 flat-file scan
    /// would have produced. `edges` is `(parent, child, nbits)` in the order the
    /// records appear on disk, which is the order the planner sees them and
    /// therefore the tie-break order.
    fn synthetic_reindex_tree(
        edges: &[(BlockHash, BlockHash, u32)],
    ) -> (
        std::collections::HashMap<BlockHash, Vec<BlockHash>>,
        std::collections::HashMap<BlockHash, ReindexHeaderRef>,
    ) {
        use bitcoin::pow::CompactTarget;
        use std::collections::HashMap;
        let mut children: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
        let mut headers: HashMap<BlockHash, ReindexHeaderRef> = HashMap::new();
        for (parent, child, bits) in edges {
            children.entry(*parent).or_default().push(*child);
            headers.insert(
                *child,
                ReindexHeaderRef {
                    header: bitcoin::block::Header {
                        version: bitcoin::block::Version::from_consensus(0x20000000),
                        prev_blockhash: *parent,
                        merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                            bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32]),
                        ),
                        time: 0,
                        bits: CompactTarget::from_consensus(*bits),
                        nonce: 0,
                    },
                    pos: FlatFilePos {
                        file_number: 0,
                        data_pos: 0,
                    },
                },
            );
        }
        (children, headers)
    }

    fn test_hash(n: u8) -> BlockHash {
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([n; 32]))
    }

    /// The connect target must be the real genesis-reachable tip, not the
    /// phase-1 record count. On a node whose flat files accumulated
    /// duplicate/orphan/side-chain records the record count overshoots the
    /// chain tip — which made the progress bar top out below 100% and the ETA
    /// project past the real finish. Orphan strands (root is nobody's child)
    /// and losing side branches must not raise the target, and must not enter
    /// the connect path.
    #[test]
    fn plan_reindex_chain_ignores_orphans_and_short_forks() {
        const EASY: u32 = 0x207fffff;
        let genesis = test_hash(0);
        let (a, b, c, d, e) = (
            test_hash(1),
            test_hash(2),
            test_hash(3),
            test_hash(4),
            test_hash(5),
        );
        // Orphan strand not reachable from genesis (its root is nobody's child).
        let (orphan_root, x, y) = (test_hash(100), test_hash(101), test_hash(102));

        let (children, headers) = synthetic_reindex_tree(&[
            // Main chain: genesis -> a -> b -> c -> d  (tip height 4)
            (genesis, a, EASY),
            (a, b, EASY),
            // Fork at b: c continues the main chain, e is a shorter side branch.
            (b, c, EASY),
            (b, e, EASY),
            (c, d, EASY),
            // Orphan strand: orphan_root -> x -> y.
            (orphan_root, x, EASY),
            (x, y, EASY),
        ]);

        let plan = ChainState::plan_reindex_chain(&children, &headers, genesis);
        assert_eq!(
            plan.tip_height, 4,
            "connect target must be the deepest genesis-reachable block"
        );
        assert_eq!(
            plan.path,
            vec![a, b, c, d],
            "path must be the winning branch in connect order"
        );
        // The raw record count (a,b,c,d,e,x,y = 7 distinct blocks) is strictly
        // larger than the real tip — exactly the over-count the plan removes.
        assert!(7 > plan.tip_height);
        // The losing branch is reported as side chain; the orphan strand is not
        // reachable from genesis and is reported at all.
        assert_eq!(plan.side.iter().map(|s| s.0).collect::<Vec<_>>(), vec![e]);
        assert_eq!(plan.side[0].1, 3, "side-chain height comes from the tree");
    }

    /// Selection is by cumulative chainwork, not depth. A single block at a
    /// harder target outweighs two at an easy one; picking by depth would
    /// replay the wrong branch across a difficulty transition.
    #[test]
    fn plan_reindex_chain_picks_most_work_not_deepest() {
        const EASY: u32 = 0x207fffff; // regtest floor — work ≈ 2
        const HARD: u32 = 0x1d00ffff; // mainnet genesis target — work ≈ 2^32
        let genesis = test_hash(0);
        let (deep1, deep2, heavy) = (test_hash(1), test_hash(2), test_hash(3));

        let (children, headers) = synthetic_reindex_tree(&[
            // Deeper branch first, so a first-seen tie-break would also pick it.
            (genesis, deep1, EASY),
            (deep1, deep2, EASY),
            (genesis, heavy, HARD),
        ]);

        let plan = ChainState::plan_reindex_chain(&children, &headers, genesis);
        assert_eq!(
            plan.path,
            vec![heavy],
            "the heavier one-block branch must win over the deeper easy branch"
        );
        assert_eq!(plan.tip_height, 1);
        // Only `deep1` is reported: it sits at height 1, which the selected
        // chain also occupies. `deep2` is at height 2, above the tip, and side
        // blocks above the tip are deliberately left unindexed — an indexed
        // one would have a vacant height for `accept_headers` to claim.
        let side: Vec<_> = plan.side.iter().map(|s| s.0).collect();
        assert_eq!(side, vec![deep1]);
    }

    /// Equal-work fork at the SAME height: the branch seen first in flat-file
    /// order wins, which is the reindex analogue of the consensus first-seen
    /// rule. The loser is reported as side chain rather than silently dropped.
    ///
    /// Scoped to same-height siblings on purpose — see `plan_reindex_chain`:
    /// across differing depths BFS order makes the shallower tip win, not the
    /// first-seen one.
    #[test]
    fn plan_reindex_chain_equal_work_keeps_first_seen() {
        const EASY: u32 = 0x207fffff;
        let genesis = test_hash(0);
        let (a, first, second) = (test_hash(1), test_hash(2), test_hash(3));

        let (children, headers) = synthetic_reindex_tree(&[
            (genesis, a, EASY),
            (a, first, EASY),
            (a, second, EASY),
        ]);

        let plan = ChainState::plan_reindex_chain(&children, &headers, genesis);
        assert_eq!(plan.path, vec![a, first]);
        let side: Vec<_> = plan.side.iter().map(|s| s.0).collect();
        assert_eq!(side, vec![second]);
    }

    /// Degenerate input: a children map with no genesis entry (genesis-only
    /// datadir, or genesis missing from the scan) yields an empty path and
    /// height 0, no panic.
    #[test]
    fn plan_reindex_chain_handles_genesis_only() {
        use std::collections::HashMap;
        let genesis = test_hash(0);
        let children: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
        let headers: HashMap<BlockHash, ReindexHeaderRef> = HashMap::new();
        let plan = ChainState::plan_reindex_chain(&children, &headers, genesis);
        assert_eq!(plan.tip_height, 0);
        assert!(plan.path.is_empty());
        assert!(plan.side.is_empty());
    }

    /// The replay plan is what now powers chainstate-reindex progress
    /// reporting (it replaced a height→hash probe). Its tip height must track
    /// the real chain across a few shapes: genesis-only, and a chain past a
    /// power-of-two boundary.
    #[test]
    fn replay_plan_tip_height_tracks_the_chain() {
        use crate::chain::replay_plan::plan_replay_from_block_index;
        let (cs, dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);

        // Pristine: only genesis.
        cs.store.flush().unwrap();
        let plan = plan_replay_from_block_index(&*cs.store, genesis.block_hash(), None).unwrap();
        assert_eq!(plan.tip_height(), 0);
        assert_eq!(plan.tip_hash(), genesis.block_hash());

        let mut parent = genesis.block_hash();
        for h in 1..=257u32 {
            let block = build_test_block(parent, h, 1_300_000_000 + h);
            parent = cs.accept_block(&block).unwrap();
        }
        cs.store.flush().unwrap();
        let plan = plan_replay_from_block_index(&*cs.store, genesis.block_hash(), None).unwrap();
        assert_eq!(plan.tip_height(), 257);
        assert_eq!(plan.tip_hash(), parent);
        assert_eq!(plan.hash_at(0), Some(genesis.block_hash()));
        assert_eq!(plan.hash_at(258), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// repair_block_index_holes scans flat files and restores DataStored
    /// entries that were wiped to HeaderOnly. Reproduces the mainnet
    /// 2026-05-12 corruption shape: block data is still in the flat
    /// file, but the block_index entry was clobbered to
    /// `HeaderOnly { file_number: 0, data_pos: 0 }`, AND there is at
    /// least one DataStored block at a higher height — the heuristic
    /// that distinguishes corruption from a normal IBD frontier.
    #[test]
    fn test_repair_block_index_holes_restores_datastored_from_flat_files() {
        let (cs, dir) = make_chain_state();

        // Build a 5-block chain on top of genesis. accept_block writes
        // them as DataStored + Valid and the flat files hold all 5.
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut parent = genesis.block_hash();
        let mut blocks: Vec<Block> = Vec::new();
        let mut height = 1u32;
        let mut time = genesis.header.time + 1;
        for _ in 0..5 {
            let blk = build_test_block(parent, height, time);
            parent = blk.block_hash();
            cs.accept_block(&blk).unwrap();
            blocks.push(blk);
            height += 1;
            time += 1;
        }
        cs.flush_coin_cache().unwrap();
        assert_eq!(cs.tip_height(), 5);

        // Corrupt block 4 (middle of the "above tip" range). Leave
        // block 5 intact as DataStored — this matches the mainnet
        // shape where height N is HeaderOnly but heights >N stay
        // DataStored, and is what the repair heuristic keys off of.
        let inner = cs.store.inner_for_test();

        let target = blocks[3].block_hash(); // height 4
        let original = cs.get_block_index(&target).unwrap();
        let corrupt = BlockIndexEntry {
            status: BlockStatus::HeaderOnly,
            file_number: 0,
            data_pos: 0,
            num_tx: 0,
            ..original.clone()
        };
        let mut batch = crate::storage::StoreBatch::default();
        batch.block_index_puts.push((target, corrupt));
        inner.write_batch(batch).unwrap();
        cs.store.invalidate_block_index_cache(&target);

        // Rewind tip pointer (in-memory + persisted) to height 3 so
        // block 4 is "above tip" from the repair's POV. headers_tip
        // isn't bumped by accept_block, so set it directly.
        {
            let mut tip = cs.tip.write();
            tip.hash = blocks[2].block_hash();
            tip.height = 3;
        }
        let tip_batch = crate::storage::StoreBatch {
            tip: Some(blocks[2].block_hash()),
            ..Default::default()
        };
        cs.store.write_batch(tip_batch).unwrap();
        cs.flush_coin_cache().unwrap();
        cs.headers_tip_height.fetch_max(5, Ordering::Relaxed);

        assert!(
            !cs.has_block_data(&target),
            "corruption setup must leave has_block_data=false"
        );

        let outcome = cs.repair_block_index_holes().unwrap();
        assert_eq!(outcome.holes_found, 1);
        assert_eq!(outcome.repaired, 1);
        assert_eq!(outcome.still_missing, 0);

        cs.store.invalidate_block_index_cache(&target);
        assert!(cs.has_block_data(&target));
        let repaired = cs.get_block_index(&target).unwrap();
        assert_eq!(repaired.status, BlockStatus::DataStored);
        assert_eq!(repaired.num_tx as usize, blocks[3].txdata.len());
        let read_back = cs.get_block(&target).unwrap();
        assert_eq!(read_back.block_hash(), target);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Heuristic test: HeaderOnly entries at the IBD frontier (no
    /// DataStored entry above them) are NOT scanned for. These are
    /// normal in-progress IBD state, not corruption, and scanning the
    /// flat files for them would burn ~20 minutes of disk reads on
    /// every restart for a healthy node mid-IBD.
    #[test]
    fn test_repair_block_index_holes_skips_ibd_frontier() {
        let (cs, _dir) = make_chain_state();

        // Build 3 blocks, then corrupt blocks 4 and 5 to HeaderOnly —
        // but with NO DataStored above them. This is the IBD-frontier
        // shape: headers accepted, blocks not yet downloaded.
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut parent = genesis.block_hash();
        let mut blocks: Vec<Block> = Vec::new();
        let mut h_acc = 1u32;
        let mut t_acc = genesis.header.time + 1;
        for _ in 0..5 {
            let blk = build_test_block(parent, h_acc, t_acc);
            parent = blk.block_hash();
            cs.accept_block(&blk).unwrap();
            blocks.push(blk);
            h_acc += 1;
            t_acc += 1;
        }
        cs.flush_coin_cache().unwrap();

        // Mark heights 4 AND 5 as HeaderOnly (the entire above-tip
        // range). There is no DataStored above either — both look like
        // normal IBD frontier.
        let inner = cs.store.inner_for_test();
        for i in [3usize, 4] {
            let hash = blocks[i].block_hash();
            let original = cs.get_block_index(&hash).unwrap();
            let corrupt = BlockIndexEntry {
                status: BlockStatus::HeaderOnly,
                file_number: 0,
                data_pos: 0,
                num_tx: 0,
                ..original.clone()
            };
            let mut batch = crate::storage::StoreBatch::default();
            batch.block_index_puts.push((hash, corrupt));
            inner.write_batch(batch).unwrap();
            cs.store.invalidate_block_index_cache(&hash);
        }

        // Rewind tip to 3.
        {
            let mut tip = cs.tip.write();
            tip.hash = blocks[2].block_hash();
            tip.height = 3;
        }
        let tip_batch = crate::storage::StoreBatch {
            tip: Some(blocks[2].block_hash()),
            ..Default::default()
        };
        cs.store.write_batch(tip_batch).unwrap();
        cs.flush_coin_cache().unwrap();
        cs.headers_tip_height.fetch_max(5, Ordering::Relaxed);

        let outcome = cs.repair_block_index_holes().unwrap();
        assert_eq!(
            outcome.holes_found, 0,
            "frontier HeaderOnly entries must not count as repair holes"
        );
        assert_eq!(outcome.blocks_scanned, 0, "no scan should occur");
    }

    /// Healthy node: repair is a fast no-op.
    #[test]
    fn test_repair_block_index_holes_no_holes_is_fast_noop() {
        let (cs, dir) = make_chain_state();
        let outcome = cs.repair_block_index_holes().unwrap();
        assert_eq!(outcome.holes_found, 0);
        assert_eq!(outcome.repaired, 0);
        assert_eq!(outcome.still_missing, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
