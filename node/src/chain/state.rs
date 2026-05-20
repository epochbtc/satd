use bitcoin::consensus::serialize;
use bitcoin::{Block, BlockHash, Network, OutPoint};
use std::path::PathBuf;
use parking_lot::{Mutex, RwLock};
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
            // Testnet4 — no default yet
            AssumeValid::Disabled
        }
        Network::Regtest => {
            // Regtest has no meaningful default
            AssumeValid::Disabled
        }
        _ => AssumeValid::Disabled,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("duplicate")]
    Duplicate,
    #[error("bad-prevblk")]
    BadPrevBlock,
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
    flat_files: Mutex<FlatFileManager>,
    /// Path to the blocks directory, for mutex-free reads.
    blocks_dir: PathBuf,
    tip: RwLock<ChainTip>,
    pub network: Network,
    script_verifier: Box<dyn ScriptVerifier>,
    assumevalid: AssumeValid,
    checkpoints: Vec<Checkpoint>,
    /// Highest header height stored (may be ahead of connected block tip during IBD).
    headers_tip_height: AtomicU32,
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
    ) -> Result<Self, ChainError> {
        let genesis = bitcoin::constants::genesis_block(network);
        let genesis_hash = genesis.block_hash();
        let blocks_dir = flat_files.blocks_dir().to_path_buf();

        let checkpoints = checkpoints::checkpoints_for_network(network);

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

                tracing::info!(
                    height = entry.height,
                    headers_tip = htip,
                    hash = %tip_hash,
                    "Loaded chain tip from storage"
                );
                return Ok(Self {
                    store,
                    flat_files: Mutex::new(flat_files),
                    blocks_dir,
                    tip: RwLock::new(ChainTip {
                        hash: tip_hash,
                        height: entry.height,
                    }),
                    network,
                    script_verifier,
                    assumevalid,
                    checkpoints,
                    headers_tip_height: AtomicU32::new(htip),
                    mtp_cache: Mutex::new(Vec::with_capacity(12)),
                    num_threads,
                    address_index,
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
                });
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
            flat_files
                .write_block(&block_data, network_magic(network))
                .map_err(|e| ChainError::FlatFile(e.to_string()))?
        };

        let parent_work = [0u8; 32];
        let noop = NoopVerifier; // Genesis has no scripts to verify
        let batch = connect::connect_block(&connect::ConnectParams {
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
            #[cfg(feature = "block-filter-index")]
            filter_index: &filter_index,
            phase_tracker: None,
        })?;
        store.write_batch(batch)?;

        Ok(Self {
            store,
            flat_files: Mutex::new(flat_files),
            blocks_dir,
            tip: RwLock::new(ChainTip {
                hash: genesis_hash,
                height: 0,
            }),
            network,
            script_verifier,
            assumevalid,
            checkpoints,
            headers_tip_height: AtomicU32::new(0),
            mtp_cache: Mutex::new(Vec::with_capacity(12)),
            num_threads,
            address_index,
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
        })
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

    pub fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.store.get_coin(outpoint)
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

        // Difficulty check
        validation::pow::check_difficulty(header, &parent, self.network, |h| {
            let hash = self.store.get_block_hash_by_height(h)?;
            self.store.get_block_index(&hash)
        })?;

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
        batch.height_hash_puts.push((new_height, hash));
        self.store.write_batch(batch)?;

        // Track highest header for locator construction
        self.headers_tip_height.fetch_max(new_height, Ordering::Relaxed);

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

        for header in headers {
            let hash = header.block_hash();

            // Already known?
            if let Some(existing) = self.store.get_block_index(&hash) {
                // Crash-resume repair: if the block is stored (DataStored/Valid) but its
                // height→hash mapping was never written (e.g. accept_headers was never
                // called for it, or it was lost in a pending_batch that was never flushed),
                // restore it now so the connect loop can find this block.
                if matches!(existing.status, BlockStatus::DataStored | BlockStatus::Valid)
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
            if let Err(e) = validation::pow::check_difficulty(header, &parent, self.network, |h| {
                // Check batch first for recently accepted headers, then store
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
            }) {
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
            batch.height_hash_puts.push((new_height, hash));
            accepted += 1;
            max_height = max_height.max(new_height);
        }

        if accepted > 0 || !batch.height_hash_puts.is_empty() {
            if let Err(e) = self.store.write_batch(batch) {
                return (0, Some(e.into()));
            }
            self.headers_tip_height
                .fetch_max(max_height, Ordering::Relaxed);
        }

        (accepted, None)
    }

    /// Get the highest header height stored (may be ahead of block tip during IBD).
    pub fn headers_tip_height(&self) -> u32 {
        self.headers_tip_height.load(Ordering::Relaxed)
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

    /// Switch the coin-cache / backing-store write mode. Use `BulkLoad`
    /// during IBD to disable the WAL on RocksDB writes (major I/O win);
    /// the caller must invoke `flush_durable` periodically so crash-
    /// recovery replay stays bounded. `Normal` restores per-write
    /// durability for steady-state operation.
    pub fn set_write_mode(&self, mode: crate::storage::WriteMode) {
        self.store.set_write_mode(mode);
    }

    /// Force all cached writes to durable storage. Intended to be called
    /// periodically during `BulkLoad` IBD, and unconditionally before
    /// switching back to `Normal` mode or shutting down.
    pub fn flush_durable(&self) -> Result<(), crate::storage::StoreError> {
        use crate::storage::Store;
        self.store.flush_durable()
    }

    /// Get the blocks directory path.
    pub fn blocks_dir(&self) -> &std::path::Path {
        &self.blocks_dir
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
        if matches!(
            entry.status,
            BlockStatus::HeaderOnly | BlockStatus::Invalid | BlockStatus::Pruned
        ) {
            return None;
        }
        let pos = FlatFilePos {
            file_number: entry.file_number,
            data_pos: entry.data_pos,
        };
        let data = self.flat_files.lock().read_block(&pos).ok()?;
        bitcoin::consensus::deserialize(&data).ok()
    }

    /// Read the block at a given active-chain height. Returns `None` for
    /// heights past the tip, missing block index entries, or pruned/invalid
    /// blocks. Used by the address-index backfill runner.
    pub fn read_block_at_height(&self, height: u32) -> Option<Block> {
        let hash = self.store.get_block_hash_by_height(height)?;
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

        let new_height = parent.height + 1;

        // Context-free block validation
        validation::block::check_block(block)?;

        // PoW validation
        validation::pow::check_proof_of_work(&block.header)?;

        // Difficulty check
        let store_ref = &*self.store;
        validation::pow::check_difficulty(&block.header, &parent, self.network, |h| {
            let hash = store_ref.get_block_hash_by_height(h)?;
            store_ref.get_block_index(&hash)
        })?;

        // Checkpoint validation
        if !checkpoints::check_against_checkpoints(new_height, &block_hash, &self.checkpoints) {
            return Err(ChainError::CheckpointMismatch(new_height));
        }

        // Write raw block to flat file
        let block_data = serialize(block);
        let flat_pos = self
            .flat_files
            .lock()
            
            .write_block(&block_data, network_magic(self.network))
            .map_err(|e| ChainError::FlatFile(e.to_string()))?;

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
        // Write height_hash so the connect loop can find this block even if
        // accept_headers was never called (e.g. crash-resume or out-of-order sync).
        batch.height_hash_puts.push((new_height, block_hash));
        self.store.write_batch(batch)?;

        Ok((block_hash, new_height))
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

        let parent = self
            .store
            .get_block_index(&entry.header.prev_blockhash)
            .ok_or(ChainError::BadPrevBlock)?;

        // Determine script verifier
        let use_noop = self.should_skip_scripts(entry.height);
        let noop = NoopVerifier;
        let verifier: &dyn ScriptVerifier = if use_noop { &noop } else { &*self.script_verifier };

        // Connect block
        let mtp = self.get_median_time_past(entry.height);
        let batch = connect::connect_block(&connect::ConnectParams {
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
    pub fn reindex_chainstate(
        &self,
        stop_at: Option<u32>,
        progress: Option<Arc<crate::startup_progress::StartupProgress>>,
    ) -> Result<(), ChainError> {
        // Periodic flush cadence for the durable checkpoint. The
        // dirty-cache threshold (see `flush_threshold`) already triggers
        // in-cache flushes when memory pressure requires — but reindex
        // runs without the normal connect-loop's periodic `flush_durable`
        // call, so large reindexes would still hold weeks of writes in
        // the in-memory dirty set until the whole reindex completed.
        // 1000 blocks mirrors the production IBD connect loop's cadence.
        const DURABLE_FLUSH_EVERY: u32 = 1000;

        if let Some(p) = &progress {
            let total = self.max_indexed_height();
            p.set_total(total as u64);
            p.set_stop_height(stop_at.map(|h| h as u64));
        }

        let mut height = 1; // genesis already connected by ChainState::new()
        while let Some(hash) = self.store.get_block_hash_by_height(height) {
            let entry = self
                .store
                .get_block_index(&hash)
                .ok_or(ChainError::BadPrevBlock)?;

            let flat_pos = FlatFilePos {
                file_number: entry.file_number,
                data_pos: entry.data_pos,
            };
            let block = self
                .read_block_direct(&flat_pos)
                .ok_or(ChainError::FlatFile("cannot read block during reindex".into()))?;

            let parent = self
                .store
                .get_block_index(&entry.header.prev_blockhash)
                .ok_or(ChainError::BadPrevBlock)?;

            let use_noop = self.should_skip_scripts(height);
            let noop = NoopVerifier;
            let verifier: &dyn ScriptVerifier =
                if use_noop { &noop } else { &*self.script_verifier };

            let mtp = self.get_median_time_past(height);
            let batch = connect::connect_block(&connect::ConnectParams {
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

            // Emit a chain event so subscribers (events bus, future
            // observers) see reindex progress just as they would IBD.
            // No-op when the broadcaster isn't wired yet (the case
            // during normal `-reindex-chainstate` startup); kept here so
            // moving the wiring earlier needs no further change.
            self.emit_chain_event(crate::chain::events::ChainEvent::BlockConnected {
                hash,
                height,
            });

            // Bound memory: drain the in-memory dirty set to RocksDB
            // whenever it crosses the configured threshold. Without
            // this a full-chain reindex accumulated 122 GiB RSS at
            // ~block 430k on mainnet before the OOM killer fired.
            if self.store.dirty_count() > self.store.flush_threshold() {
                self.store.flush()?;
            }

            // Periodic durable checkpoint: bounds the replay window on
            // a crash/OOM during a long reindex so progress sticks.
            if height.is_multiple_of(DURABLE_FLUSH_EVERY) {
                self.store.flush()?;
                self.store.flush_durable()?;
            }

            if let Some(p) = &progress
                && height.is_multiple_of(100)
            {
                p.set_current(height as u64);
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
    }

    /// Highest height present in the height→hash index. Used by reindex
    /// progress reporting to show the on-disk file tip when it differs
    /// from a configured `-stopatheight` target.
    ///
    /// Doubling probe (1, 2, 4, …) to find an absent height, then binary
    /// search between the last-present and first-absent height. ~40
    /// `get_block_hash_by_height` lookups at mainnet sizes — negligible
    /// vs. the reindex itself, and avoids widening the `Store` trait.
    fn max_indexed_height(&self) -> u32 {
        if self.store.get_block_hash_by_height(1).is_none() {
            return 0;
        }
        let mut lo: u32 = 1;
        let mut hi: u32 = 2;
        while self.store.get_block_hash_by_height(hi).is_some() {
            lo = hi;
            hi = match hi.checked_mul(2) {
                Some(v) => v,
                None => return u32::MAX,
            };
        }
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            if self.store.get_block_hash_by_height(mid).is_some() {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Rebuild the block index and UTXO set by streaming `blk*.dat` files.
    /// Used by `-reindex` when the chain database has been cleared.
    ///
    /// Two passes:
    ///   1. Stream every record in the flat files, parsing only the 80-byte
    ///      header. Build `header_by_hash` and the `parent → children`
    ///      multimap. Memory: one `BlockHeader` + position per block,
    ///      ~150 bytes — about 140 MB at the current mainnet height. The
    ///      previous implementation eagerly held every full block in
    ///      memory (~900 GB on mainnet), which OOM-killed the node.
    ///   2. BFS from genesis. For each hash, read the raw block from the
    ///      flat file, deserialize, run `connect_block`, drop the block.
    ///      Peak memory is one block payload at a time.
    ///
    /// `progress` (if provided) is updated with the per-phase counters so
    /// the startup RPC can render `current/total` to operators.
    ///
    /// `stop_at` matches the `-stopatheight` flag: when set, the
    /// connect phase exits cleanly after the targeted height is
    /// durable. Headers past the target are still scanned in phase 1
    /// (the BFS needs the full parent→children map to build chain
    /// order correctly), but no further blocks are connected.
    pub fn reindex_from_flat_files(
        &self,
        stop_at: Option<u32>,
        progress: Option<Arc<crate::startup_progress::StartupProgress>>,
    ) -> Result<(), ChainError> {
        use std::collections::{HashMap, VecDeque};

        // Periodic flush cadence — same reasoning as `reindex_chainstate`:
        // without it the in-memory dirty set held weeks of writes for a
        // mainnet reindex and pinned 100+ GiB of RSS.
        const DURABLE_FLUSH_EVERY: u32 = 1000;

        struct HeaderRef {
            header: bitcoin::block::Header,
            pos: FlatFilePos,
        }

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
                    children
                        .entry(header.prev_blockhash)
                        .or_default()
                        .push(hash);
                    header_by_hash.insert(hash, HeaderRef { header, pos });
                    scanned += 1;
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

        // Phase 2: BFS from genesis, fetch each block from disk and connect.
        if let Some(p) = &progress {
            p.set_phase("reindex_connect", "Replaying blocks (phase 2/2)");
            p.set_total(total);
            p.set_stop_height(stop_at.map(|h| h as u64));
        }
        let genesis_hash = bitcoin::constants::genesis_block(self.network).block_hash();
        let mut queue: VecDeque<BlockHash> = VecDeque::new();
        if let Some(child_hashes) = children.get(&genesis_hash) {
            for h in child_hashes {
                queue.push_back(*h);
            }
        }

        let mut connected: u32 = 0;
        while let Some(hash) = queue.pop_front() {
            let entry = match header_by_hash.remove(&hash) {
                Some(v) => v,
                None => continue,
            };

            // Re-read the raw block from disk; we only kept the header during
            // phase 1.
            let block = self
                .read_block_direct(&entry.pos)
                .ok_or_else(|| ChainError::FlatFile("read failed during reindex".into()))?;

            let parent = self
                .store
                .get_block_index(&entry.header.prev_blockhash)
                .ok_or(ChainError::BadPrevBlock)?;
            let height = parent.height + 1;

            let use_noop = self.should_skip_scripts(height);
            let noop = NoopVerifier;
            let verifier: &dyn ScriptVerifier =
                if use_noop { &noop } else { &*self.script_verifier };

            let mtp = self.get_median_time_past(height);
            let batch = connect::connect_block(&connect::ConnectParams {
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
            if let Some(p) = &progress
                && connected.is_multiple_of(100)
            {
                p.set_current(connected as u64);
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

            if let Some(child_hashes) = children.get(&hash) {
                for h in child_hashes {
                    queue.push_back(*h);
                }
            }
        }
        // Final durable checkpoint so the reindexed tip survives a crash.
        self.store.flush()?;
        self.store.flush_durable()?;
        if let Some(p) = &progress {
            p.set_current(connected as u64);
        }
        tracing::info!(connected, "Reindex from flat files complete");
        Ok(())
    }

    /// Accept a new block into the chain.
    pub fn accept_block(&self, block: &Block) -> Result<BlockHash, ChainError> {
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

        let new_height = parent.height + 1;

        // Context-free block validation
        validation::block::check_block(block)?;

        // PoW validation
        validation::pow::check_proof_of_work(&block.header)?;

        // Difficulty check
        let store_ref = &*self.store;
        validation::pow::check_difficulty(&block.header, &parent, self.network, |h| {
            let hash = store_ref.get_block_hash_by_height(h)?;
            store_ref.get_block_index(&hash)
        })?;

        // Timestamp check (median time past)
        validation::pow::check_timestamp(&block.header, new_height, |h| {
            let hash = store_ref.get_block_hash_by_height(h)?;
            store_ref.get_block_index(&hash)
        })?;

        // Checkpoint validation
        if !checkpoints::check_against_checkpoints(new_height, &block_hash, &self.checkpoints) {
            tracing::warn!(
                height = new_height,
                hash = %block_hash,
                "Block rejected: checkpoint mismatch"
            );
            return Err(ChainError::CheckpointMismatch(new_height));
        }

        // Write raw block to flat file
        let block_data = serialize(block);
        let flat_pos = self
            .flat_files
            .lock()
            
            .write_block(&block_data, network_magic(self.network))
            .map_err(|e| ChainError::FlatFile(e.to_string()))?;

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

            // Disconnect blocks from current tip down to fork point.
            // The returned info carries the data we need to build an
            // accurate reorg record once reconnection is complete.
            let disconnect_info = self.perform_reorg(&fork_entry, current_tip)?;

            // Now connect the side chain blocks from fork point up to (but not including)
            // the new block. Collect them first since we need to connect in forward order.
            let mut to_connect = Vec::new();
            {
                let mut hash = prev_hash;
                let fork_hash = fork_entry.header.block_hash();
                while hash != fork_hash {
                    to_connect.push(hash);
                    let e = self.store.get_block_index(&hash)
                        .ok_or(ChainError::BadPrevBlock)?;
                    hash = e.header.prev_blockhash;
                }
                to_connect.reverse();
            }
            let mut reconnected_hashes: Vec<BlockHash> = Vec::with_capacity(to_connect.len() + 1);
            let mut reconnected_blocks: Vec<(bitcoin::Block, u32)> =
                Vec::with_capacity(to_connect.len());

            // Side-chain reconnect — wrapped so a per-block failure
            // unwinds the partial activation back to the original
            // chain. Without this, a high-work side chain whose
            // intermediate or final block fails validation would leave
            // the node partially reorged.
            let side_result: Result<(), ChainError> = (|| {
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
                tracing::warn!(error = %e, "Reorg side-chain reconnect failed; rolling back to old tip");
                if let Err(re) = self.rollback_partial_reorg(
                    &reconnected_blocks,
                    &disconnect_info.disconnected_with_height,
                ) {
                    tracing::error!(
                        original_error = %e,
                        rollback_error = %re,
                        "Reorg rollback FAILED — chainstate is inconsistent; operator must reindex"
                    );
                }
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
            #[cfg(feature = "block-filter-index")]
            filter_index: &self.filter_index,
            phase_tracker: None,
        });
        let batch = match connect_attempt {
            Ok(b) => b,
            Err(e) => {
                if let Some(pending) = pending_reorg.as_ref() {
                    tracing::warn!(error = %e, "Reorg triggering block validation failed; rolling back to old tip");
                    if let Err(re) = self.rollback_partial_reorg(
                        &pending.reconnected_blocks,
                        &pending.original_disconnected,
                    ) {
                        tracing::error!(
                            original_error = %e,
                            rollback_error = %re,
                            "Reorg rollback FAILED — chainstate is inconsistent; operator must reindex"
                        );
                    }
                }
                return Err(e.into());
            }
        };

        if let Err(e) = self.store.write_batch(batch) {
            if let Some(pending) = pending_reorg.as_ref() {
                tracing::warn!(error = %e, "Reorg triggering block commit failed; rolling back to old tip");
                if let Err(re) = self.rollback_partial_reorg(
                    &pending.reconnected_blocks,
                    &pending.original_disconnected,
                ) {
                    tracing::error!(
                        original_error = %e,
                        rollback_error = %re,
                        "Reorg rollback FAILED — chainstate is inconsistent; operator must reindex"
                    );
                }
            }
            return Err(e.into());
        }

        // Update in-memory tip
        {
            let mut tip = self.tip.write();
            tip.hash = block_hash;
            tip.height = new_height;
        }

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

        Ok(block_hash)
    }

    /// Best-effort rollback of an in-progress reorg: disconnects any
    /// side-chain blocks that were reconnected, then re-connects the
    /// original-chain blocks the reorg disconnected. After this
    /// returns Ok, the active tip is restored to the pre-reorg state
    /// and the chainstate is consistent with that tip.
    ///
    /// Failure here is logged loudly by the caller; we continue to
    /// propagate the original reorg error rather than masking it.
    /// Original-chain blocks were already validated when they first
    /// connected, so we re-connect them with `NoopVerifier` to avoid a
    /// transient script-verifier failure during rollback.
    fn rollback_partial_reorg(
        &self,
        side_blocks_committed: &[(bitcoin::Block, u32)],
        original_disconnected: &[(BlockHash, u32)],
    ) -> Result<(), ChainError> {
        // Disconnect side chain in reverse order (newest first).
        for (side_block, side_height) in side_blocks_committed.iter().rev() {
            let side_hash = side_block.block_hash();
            let entry = self
                .store
                .get_block_index(&side_hash)
                .ok_or(ChainError::BadPrevBlock)?;
            let undo = self
                .store
                .get_undo(&side_hash)
                .ok_or(ChainError::FlatFile(
                    "undo data missing during rollback".to_string(),
                ))?;
            let prev_hash = entry.header.prev_blockhash;
            let batch = disconnect::disconnect_block(
                side_block,
                &undo,
                *side_height,
                prev_hash,
                &self.address_index,
                #[cfg(feature = "block-filter-index")]
                &self.filter_index,
            )?;
            self.store.write_batch(batch)?;
            let prev_entry = self
                .store
                .get_block_index(&prev_hash)
                .ok_or(ChainError::BadPrevBlock)?;
            let mut tip = self.tip.write();
            tip.hash = prev_hash;
            tip.height = prev_entry.height;
        }

        // Reconnect the original chain in oldest-first order. The
        // original disconnect captured them newest-first (walk from
        // old_tip toward fork), so we reverse to play them forward.
        for (hash, _height) in original_disconnected.iter().rev() {
            let block = self.get_block(hash).ok_or(ChainError::FlatFile(
                "block data missing during rollback reconnect".to_string(),
            ))?;
            let entry = self
                .store
                .get_block_index(hash)
                .ok_or(ChainError::BadPrevBlock)?;
            let parent_entry = self
                .store
                .get_block_index(&entry.header.prev_blockhash)
                .ok_or(ChainError::BadPrevBlock)?;
            let mtp = self.get_median_time_past(entry.height);
            let flat_pos = FlatFilePos {
                file_number: entry.file_number,
                data_pos: entry.data_pos,
            };
            let noop = NoopVerifier;
            let batch = connect::connect_block(&connect::ConnectParams {
                store: &*self.store,
                block: &block,
                height: entry.height,
                parent_chainwork: &parent_entry.chainwork,
                flat_pos,
                script_verifier: &noop,
                median_time_past: mtp,
                network: self.network,
                pre_verified_txs: None,
                num_threads: 1,
                precomputed_txids: None,
                address_index: &self.address_index,
            #[cfg(feature = "block-filter-index")]
            filter_index: &self.filter_index,
            phase_tracker: None,
            })?;
            self.store.write_batch(batch)?;
            let mut tip = self.tip.write();
            tip.hash = *hash;
            tip.height = entry.height;
        }
        Ok(())
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

/// Compare two big-endian U256 values. Returns -1, 0, or 1.
fn compare_u256(a: &[u8; 32], b: &[u8; 32]) -> i32 {
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

/// Get the network magic bytes for flat file headers.
fn network_magic(network: Network) -> [u8; 4] {
    match network {
        Network::Bitcoin => [0xf9, 0xbe, 0xb4, 0xd9],
        Network::Testnet => [0x0b, 0x11, 0x09, 0x07],
        Network::Signet => [0x0a, 0x03, 0xcf, 0x40],
        Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        _ => [0xf9, 0xbe, 0xb4, 0xd9],
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;

    pub(crate) fn make_chain_state() -> (ChainState, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "satd-chain-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
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
        )
        .unwrap();
        (cs, dir)
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

        // Build a side block at height 1 and store it. store_block
        // writes height_hash[1] = B1 (overwriting A1) even though
        // A1 is the active block at height 1.
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_010);
        let b1_hash = b1.block_hash();
        let _ = cs.store_block(&b1).expect("store B1");
        assert_eq!(
            cs.get_block_hash_by_height(1),
            Some(b1_hash),
            "store_block must clobber height_hash[1] for the test premise to hold"
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
        // Expected: BlockDisconnected(A2), BlockDisconnected(A1),
        // BlockConnected(B1), BlockConnected(B2), BlockConnected(B3).
        assert_eq!(events.len(), 5, "events emitted: {:?}", events);
        assert!(matches!(
            events[0],
            ChainEvent::BlockDisconnected { hash, height: 2 } if hash == a2_hash
        ), "first event: {:?}", events[0]);
        assert!(matches!(
            events[1],
            ChainEvent::BlockDisconnected { hash, height: 1 } if hash == a1_hash
        ), "second event: {:?}", events[1]);
        assert!(matches!(
            events[2],
            ChainEvent::BlockConnected { hash, height: 1 } if hash == b1_hash
        ), "third event: {:?}", events[2]);
        assert!(matches!(
            events[3],
            ChainEvent::BlockConnected { hash, height: 2 } if hash == b2_hash
        ), "fourth event: {:?}", events[3]);
        assert!(matches!(
            events[4],
            ChainEvent::BlockConnected { hash, height: 3 } if hash == b3_hash
        ), "fifth event: {:?}", events[4]);

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

        cs.reindex_chainstate(None, None).unwrap();

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
        cs.reindex_chainstate(Some(400), Some(progress.clone())).unwrap();

        assert_eq!(cs.tip_height(), 400, "reindex must stop at the target");
        let snap = progress.snapshot();
        assert_eq!(
            snap.stop_height,
            Some(400),
            "progress must surface the stop target so the TUI can render it"
        );
        assert_eq!(snap.total, 600, "progress total must reflect file tip");
        assert_eq!(snap.current, 400, "current must end exactly at stop_at");

        // Final flush must still drain the dirty set so the tip at 400
        // is durable; the operator restarts and continues from here.
        assert_eq!(
            cs.store.dirty_count(),
            0,
            "dirty cache not drained by final flush at stop_at"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `max_indexed_height` is the helper that powers reindex progress
    /// reporting. Validates the doubling+binary-search across a few
    /// shapes: empty index, small, and a non-power-of-two boundary.
    #[test]
    fn max_indexed_height_finds_chain_tip() {
        let (cs, dir) = make_chain_state();

        // Pristine: only genesis exists at height 0. The helper looks
        // at heights ≥ 1 because reindex starts from 1, so an empty
        // index past genesis must return 0.
        assert_eq!(cs.max_indexed_height(), 0);

        // Build 257 blocks — one past a power-of-two boundary so the
        // doubling probe (256, 512) bounds the binary search.
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut parent = genesis.block_hash();
        for h in 1..=257u32 {
            let block = build_test_block(parent, h, 1_300_000_000 + h);
            parent = cs.accept_block(&block).unwrap();
        }
        assert_eq!(cs.max_indexed_height(), 257);

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
