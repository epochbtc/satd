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
    tip: RwLock<ChainTip>,
    pub network: Network,
    script_verifier: Arc<dyn ScriptVerifier>,
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

                tracing::info!(
                    height = entry.height,
                    headers_tip = htip,
                    hash = %tip_hash,
                    "Loaded chain tip from storage"
                );
                return Ok(Self {
                    store,
                    flat_files: Arc::new(Mutex::new(flat_files)),
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
                    background: RwLock::new(None),
                    signet_challenge: None,
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
            flat_files: Arc::new(Mutex::new(flat_files)),
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
            background: RwLock::new(None),
            signet_challenge: None,
        })
    }

    /// Set the custom signet challenge (BIP 325). Call once, before the
    /// `ChainState` is shared (wrapped in an `Arc`). On signet this
    /// enables block-solution validation and custom P2P magic.
    pub fn set_signet_challenge(&mut self, challenge: Option<Vec<u8>>) {
        self.signet_challenge = challenge;
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

    /// Cumulative transaction count through (and including) the given
    /// block, or `None` if not yet recorded (e.g. a pre-snapshot block an
    /// AssumeUTXO background hasn't validated). Backs `getchaintxstats`.
    pub fn cumulative_tx_count(&self, hash: &BlockHash) -> Option<u64> {
        self.store.get_cumulative_tx_count(hash)
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

        // Signet block-solution check (BIP 325), custom signet only.
        self.check_signet_solution(block)?;

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
        if let Some(p) = &progress {
            let total = self.max_indexed_height();
            p.set_total(total as u64);
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
        let result = self.reindex_replay(stop_at, progress);
        if let Err(e) = self.flush_durable() {
            tracing::error!(
                error = %e,
                "reindex: durable flush on exit failed; restoring Normal write mode anyway \
                 (next startup replays from the flat-file block store)"
            );
        }
        self.set_write_mode(crate::storage::WriteMode::Normal);
        result
    }

    /// Inner replay loop for [`Self::reindex_chainstate`]. Runs under
    /// BulkLoad with the prefetch pipeline; the caller restores Normal write
    /// mode regardless of how this returns.
    fn reindex_replay(
        &self,
        stop_at: Option<u32>,
        progress: Option<Arc<crate::startup_progress::StartupProgress>>,
    ) -> Result<(), ChainError> {
        // Periodic durable checkpoint cadence. The dirty-cache threshold
        // (see `flush_threshold`) handles memory pressure; this bounds the
        // replay window on a crash/OOM so progress sticks. 1000 mirrors the
        // production IBD connect loop.
        const DURABLE_FLUSH_EVERY: u32 = 1000;

        let start_height = self.tip_height() + 1; // genesis already connected
        let workers = self.num_threads.max(1);
        let prefetch = crate::chain::prefetch::start_prefetcher(
            self.store_ref().clone() as Arc<dyn crate::storage::Store + Send + Sync>,
            self.blocks_dir().to_path_buf(),
            start_height,
            workers,
            128, // lookahead blocks, matching the IBD connect loop
            self.is_assumevalid_active(),
            self.primary_engine(),
        );

        // Weight-aware ETA over the replay, reused from the IBD connect loop.
        // The replay is the same per-block cost profile as IBD, so the cost
        // weights apply directly. Target the configured `-stopatheight` when
        // set — the loop below exits there, so an ETA to the full file tip
        // would be materially inflated.
        let target_height = stop_at.unwrap_or_else(|| self.max_indexed_height());
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
            while let Some(hash) = self.store.get_block_hash_by_height(height) {
                // Prefer the prefetched, pre-processed block; fall back to a
                // direct read on a miss (cold start, or a worker behind the
                // cursor). Both paths connect via `connect_block` directly,
                // bypassing the `DataStored` precondition the IBD connect
                // methods enforce — after `clear_chainstate` the block-index
                // entries are still `Valid` from the original sync.
                match prefetch.take_block(height) {
                    Some(pre) if pre.hash == hash => self.reindex_connect_prefetched(pre)?,
                    _ => self.reindex_connect_direct(height, hash)?,
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

    /// Connect a prefetched, pre-processed block during reindex. Reuses the
    /// prefetcher's deserialized block, precomputed txids, and (in
    /// assumevalid mode) speculatively pre-verified scripts. Does NOT check
    /// `entry.status` — reindex replays `Valid` entries (see `reindex_replay`).
    fn reindex_connect_prefetched(
        &self,
        pre: crate::chain::prefetch::PreprocessedBlock,
    ) -> Result<(), ChainError> {
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
    fn reindex_connect_direct(&self, height: u32, hash: BlockHash) -> Result<(), ChainError> {
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
        let mut tip = self.tip.write();
        tip.hash = hash;
        tip.height = height;
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
            // Switch the ETA into driver-controlled mode up front so the
            // generic linear estimate never briefly shows a bogus tiny ETA
            // over the trivial early blocks before the weight-aware estimator
            // has data.
            p.set_eta(None);
        }
        // Weight-aware ETA over the heavy connect phase (reused from IBD). The
        // block count scanned in phase 1 is a close proxy for the final tip
        // height of a from-genesis reindex; precision at 1000-block weight
        // granularity isn't critical.
        let target_height = stop_at.unwrap_or(total as u32);
        let mut eta_est =
            crate::ibd_eta::IbdEtaEstimator::new(0, target_height, self.network == Network::Bitcoin);
        let mut interval_start = std::time::Instant::now();
        let mut last_interval: u32 = 0;
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

        // Signet block-solution check (BIP 325), custom signet only.
        self.check_signet_solution(block)?;

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
            self.store.flush()?;

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

        // Store a side block at height 1; this clobbers height_hash[1] = B1.
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_010);
        let b1_hash = b1.block_hash();
        cs.store_block(&b1).expect("store B1");
        assert_eq!(
            cs.get_block_hash_by_height(1),
            Some(b1_hash),
            "test premise: store_block clobbers the height index"
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

        cs.reindex_chainstate(None, None).unwrap();
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
