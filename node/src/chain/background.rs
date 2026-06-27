//! AssumeUTXO background chainstate.
//!
//! After `loadtxoutset` installs a snapshot UTXO set at `snapshot_height`,
//! the node's primary [`ChainState`](crate::chain::state::ChainState)
//! serves the tip from that snapshot while a *background* chainstate
//! re-validates the history genesis→`snapshot_height` to confirm the
//! snapshot was honest. The background:
//!
//! - builds its OWN UTXO set in a private RocksDB
//!   (`chainstate_background/`), so the snapshot chainstate's coins are
//!   never disturbed;
//! - writes the blocks it downloads into the ONE shared block store
//!   (block files + `block_index`) via [`SplitStore`], so after handoff
//!   the snapshot chainstate can still locate every historical block;
//! - on reaching `snapshot_height`, hashes its UTXO set with Core's
//!   `hash_serialized_3` and compares it to the hardcoded anchor. A match
//!   is the handoff: the background DB is dropped and the snapshot is
//!   marked validated. A mismatch is NOT a panic — the snapshot is
//!   flagged and the operator warned (see `ChainState`'s handoff).
//!
//! Blocks below `snapshot_height` are deeply buried and checkpoint-
//! protected, so the background only ever connects linearly in-order and
//! needs none of the primary's reorg machinery.

use std::path::PathBuf;
use std::sync::Arc;

use bitcoin::consensus::serialize;
use bitcoin::{Block, BlockHash, Network};
use parking_lot::RwLock;

use crate::chain::checkpoints::{self, Checkpoint};
use crate::chain::connect;
use crate::chain::state::{ChainError, network_magic};
use crate::storage::coin_cache::CoinCache;
use crate::storage::compressed_coin::hash_utxo_set;
use crate::storage::profile::StorageTuning;
use crate::storage::rocksdb_store::RocksDbStore;
use crate::storage::split_store::SplitStore;
use crate::storage::Store;
use crate::validation;
use crate::validation::script::ScriptVerifier;

/// Marker file (in the background dir) recording the anchor a pending
/// snapshot is validating toward, so startup can re-attach the background
/// validator after a restart (the primary tip may have advanced past the
/// snapshot height, so it alone can't identify the anchor).
const ANCHOR_MARKER: &str = ".anchor";

/// Persist the anchor identity next to the background coins DB.
pub fn write_anchor_marker(
    bg_dir: &std::path::Path,
    height: u32,
    blockhash: &BlockHash,
    target_hash: &[u8; 32],
) -> std::io::Result<()> {
    let v = serde_json::json!({
        "height": height,
        "blockhash": blockhash.to_string(),
        "hash_serialized_3": hex::encode(target_hash),
    });
    let bytes = serde_json::to_vec(&v).map_err(std::io::Error::other)?;
    std::fs::write(bg_dir.join(ANCHOR_MARKER), bytes)
}

/// Read the anchor marker written by [`write_anchor_marker`], if present
/// and well-formed.
pub fn read_anchor_marker(bg_dir: &std::path::Path) -> Option<(u32, BlockHash, [u8; 32])> {
    let raw = std::fs::read(bg_dir.join(ANCHOR_MARKER)).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let height = u32::try_from(v.get("height")?.as_u64()?).ok()?;
    let blockhash: BlockHash = v.get("blockhash")?.as_str()?.parse().ok()?;
    let bytes = hex::decode(v.get("hash_serialized_3")?.as_str()?).ok()?;
    let target: [u8; 32] = bytes.try_into().ok()?;
    Some((height, blockhash, target))
}

/// Result of connecting one block to the background chainstate.
#[derive(Debug, Clone, Copy)]
pub struct BackgroundConnect {
    pub height: u32,
    /// True when this connect brought the background tip up to
    /// `snapshot_height` — the caller should now run the handoff check.
    pub reached_snapshot: bool,
}

/// Outcome of the handoff verification at `snapshot_height`.
#[derive(Debug, Clone)]
pub enum HandoffOutcome {
    /// The background's UTXO set hash and base block match the anchor.
    Validated,
    /// The recomputed `hash_serialized_3` does not match the anchor —
    /// the snapshot was buggy or malicious.
    HashMismatch { expected: [u8; 32], actual: [u8; 32] },
    /// The background tip block at `snapshot_height` is not the anchor's
    /// block hash (should be impossible if headers were validated, but
    /// checked defensively).
    BaseMismatch { expected: BlockHash, actual: BlockHash },
}

/// A chainstate that validates genesis→`snapshot_height` behind a loaded
/// AssumeUTXO snapshot. See the module docs.
pub struct BackgroundChainState {
    /// Routes block-index/header ops to the shared block store and
    /// coins/undo/tip to [`Self::coins`]. This is what `connect_block`
    /// reads and writes through.
    split: Arc<SplitStore>,
    /// The private background coins cache (`chainstate_background/`).
    /// Held concretely so we can `flush` before the handoff hash.
    coins: Arc<CoinCache>,
    /// Shared flat files — the SAME `blocks/` the snapshot chainstate
    /// uses, so downloaded historical blocks are visible to both.
    flat_files: Arc<parking_lot::Mutex<crate::storage::flatfile::FlatFileManager>>,
    /// Shared script verifier (Arc-cloned from the primary).
    script_verifier: Arc<dyn ScriptVerifier>,
    checkpoints: Vec<Checkpoint>,
    /// Whether checkpoint validation is enforced (Core `-checkpoints`),
    /// forwarded from the primary chainstate so `-checkpoints=0` disables
    /// it on the background re-validation path too.
    enforce_checkpoints: bool,
    network: Network,
    num_threads: usize,
    /// On-disk directory of the private coins DB, removed at handoff.
    bg_dir: PathBuf,
    /// Anchor we validate toward.
    snapshot_height: u32,
    snapshot_hash: BlockHash,
    target_utxo_hash: [u8; 32],
    /// Background's connected tip `(hash, height)`, genesis→snapshot.
    tip: RwLock<(BlockHash, u32)>,
}

impl BackgroundChainState {
    /// Open (or resume) a background chainstate. `block_store` is the
    /// snapshot chainstate's store (shared block index + height map);
    /// `flat_files`/`script_verifier` are Arc-shared from the primary.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        block_store: Arc<dyn Store>,
        flat_files: Arc<parking_lot::Mutex<crate::storage::flatfile::FlatFileManager>>,
        script_verifier: Arc<dyn ScriptVerifier>,
        checkpoints: Vec<Checkpoint>,
        enforce_checkpoints: bool,
        network: Network,
        num_threads: usize,
        bg_dir: PathBuf,
        snapshot_height: u32,
        snapshot_hash: BlockHash,
        target_utxo_hash: [u8; 32],
        dbcache_mb: u64,
        max_open_files: i32,
    ) -> Result<Self, ChainError> {
        let bg_db = RocksDbStore::open_at(
            &bg_dir,
            false,
            dbcache_mb as usize,
            false,
            max_open_files,
            StorageTuning::default(),
        )?;
        let coins = Arc::new(CoinCache::new(Box::new(bg_db), dbcache_mb));

        // Resume from the persisted background tip if present; otherwise
        // start at genesis (an empty UTXO set — the genesis coinbase is
        // unspendable and never enters the set).
        let (tip_hash, tip_height) = match coins.get_tip() {
            Some(h) => {
                let height = block_store
                    .get_block_index(&h)
                    .map(|e| e.height)
                    .unwrap_or(0);
                (h, height)
            }
            None => (bitcoin::constants::genesis_block(network).block_hash(), 0),
        };

        let split = Arc::new(SplitStore::new(
            block_store,
            coins.clone() as Arc<dyn Store>,
        ));

        Ok(Self {
            split,
            coins,
            flat_files,
            script_verifier,
            checkpoints,
            enforce_checkpoints,
            network,
            num_threads,
            bg_dir,
            snapshot_height,
            snapshot_hash,
            target_utxo_hash,
            tip: RwLock::new((tip_hash, tip_height)),
        })
    }

    pub fn tip_hash(&self) -> BlockHash {
        self.tip.read().0
    }

    pub fn tip_height(&self) -> u32 {
        self.tip.read().1
    }

    pub fn snapshot_height(&self) -> u32 {
        self.snapshot_height
    }

    pub fn snapshot_hash(&self) -> BlockHash {
        self.snapshot_hash
    }

    /// On-disk directory of the private coins DB (removed at handoff).
    pub fn bg_dir(&self) -> &std::path::Path {
        &self.bg_dir
    }

    /// Path of the durable "this snapshot failed background validation"
    /// marker. Its presence makes the rejection survive restart so the
    /// node refuses to keep serving a known-invalid snapshot.
    fn rejected_marker(&self) -> PathBuf {
        self.bg_dir.join(".rejected")
    }

    /// Persist the rejected marker (best-effort) after a validation
    /// mismatch at the snapshot height.
    pub fn mark_rejected(&self) {
        if let Err(e) = std::fs::write(
            self.rejected_marker(),
            b"AssumeUTXO snapshot failed background validation\n",
        ) {
            tracing::error!(
                error = %e,
                dir = %self.bg_dir.display(),
                "AssumeUTXO: could not write the rejected marker"
            );
        }
    }

    /// Whether this snapshot has been durably marked rejected.
    pub fn is_rejected(&self) -> bool {
        self.rejected_marker().exists()
    }

    /// Flush the private coin cache so the background tip + coins are
    /// durable. The catch-up driver should call this periodically so a
    /// crash resumes from a recent (consistent) private tip rather than
    /// redoing the whole validation.
    pub fn flush(&self) -> Result<(), ChainError> {
        self.coins.flush().map_err(ChainError::from)
    }

    /// True once the background has connected up to `snapshot_height`.
    pub fn is_at_snapshot(&self) -> bool {
        self.tip_height() >= self.snapshot_height
    }

    /// Connect the next block (must extend the background tip and sit at
    /// or below `snapshot_height`). Runs full consensus validation with
    /// the shared verifier; the block is written to the shared flat files
    /// and its index entry to the shared block store, while coins/undo/tip
    /// go to the private background DB.
    pub fn connect_next_block(&self, block: &Block) -> Result<BackgroundConnect, ChainError> {
        let block_hash = block.block_hash();
        let prev_hash = block.header.prev_blockhash;

        let (cur_hash, _cur_height) = *self.tip.read();
        if prev_hash != cur_hash {
            return Err(ChainError::BadPrevBlock);
        }

        let store_ref: &dyn Store = &*self.split;
        let parent = store_ref
            .get_block_index(&prev_hash)
            .ok_or(ChainError::BadPrevBlock)?;
        let new_height = parent.height + 1;
        if new_height > self.snapshot_height {
            // The background only validates up to the snapshot height.
            return Err(ChainError::BadPrevBlock);
        }

        // Full context-free + contextual validation, mirroring
        // `ChainState::accept_block` (minus side-chain/reorg handling,
        // which cannot occur on this linear in-order replay).
        validation::block::check_block(block)?;
        validation::pow::check_proof_of_work(&block.header)?;
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
        // MTP walks the candidate's own parent pointers (see `check_timestamp`).
        validation::pow::check_timestamp(&block.header, &parent, |h| store_ref.get_block_index(h))?;
        // Mandatory block-version gate (Core: bad-version) — BIP34/66/65.
        // Deterministic, height-based; mirrors the live accept path.
        connect::check_block_version(&block.header, new_height, self.network)?;
        if self.enforce_checkpoints
            && !checkpoints::check_against_checkpoints(new_height, &block_hash, &self.checkpoints)
        {
            return Err(ChainError::CheckpointMismatch(new_height));
        }

        // The block data may already be in the SHARED flat files: the
        // live catch-up downloader stores each arriving historical block
        // via `ChainState::store_block` before waking the connector. Reuse
        // that copy when present — writing again would duplicate the entire
        // genesis→snapshot block data (hundreds of GB on mainnet). Only
        // write when the block isn't stored yet (e.g. a test or a caller
        // that connects without pre-storing).
        let flat_pos = match store_ref.get_block_index(&block_hash) {
            Some(entry)
                if matches!(
                    entry.status,
                    crate::storage::blockindex::BlockStatus::DataStored
                        | crate::storage::blockindex::BlockStatus::Valid
                ) =>
            {
                crate::storage::flatfile::FlatFilePos {
                    file_number: entry.file_number,
                    data_pos: entry.data_pos,
                }
            }
            _ => {
                let block_data = serialize(block);
                self.flat_files
                    .lock()
                    .write_block(&block_data, network_magic(self.network))
                    .map_err(|e| ChainError::FlatFile(e.to_string()))?
            }
        };

        let mtp = connect::get_median_time_past(store_ref, new_height);
        // The background runs with secondary indexes disabled.
        let addr_index = crate::index::address::AddressIndexConfig::default();
        #[cfg(feature = "block-filter-index")]
        let filter_index = crate::index::filter::FilterIndexConfig::default();

        let batch = connect::connect_block(&connect::ConnectParams {
            store: store_ref,
            block,
            height: new_height,
            parent_chainwork: &parent.chainwork,
            flat_pos,
            script_verifier: &*self.script_verifier,
            median_time_past: mtp,
            network: self.network,
            pre_verified_txs: None,
            num_threads: self.num_threads,
            precomputed_txids: None,
            address_index: &addr_index,
            #[cfg(feature = "block-filter-index")]
            filter_index: &filter_index,
            phase_tracker: None,
        })?;

        // SplitStore routes: block_index/height/txindex → shared store,
        // coins/undo/tip → private background DB.
        self.split.write_batch(batch)?;

        *self.tip.write() = (block_hash, new_height);

        Ok(BackgroundConnect {
            height: new_height,
            reached_snapshot: new_height == self.snapshot_height,
        })
    }

    /// Verify the background's UTXO set at `snapshot_height` against the
    /// anchor. Flushes the private coin cache first so the snapshot view
    /// sees every committed coin. Does NOT mutate any persistent
    /// validated/rejected marker — that is the caller's (ChainState's)
    /// job once it decides how to act on the outcome.
    pub fn verify_at_snapshot(&self) -> Result<HandoffOutcome, ChainError> {
        let (tip_hash, _) = *self.tip.read();
        if tip_hash != self.snapshot_hash {
            return Ok(HandoffOutcome::BaseMismatch {
                expected: self.snapshot_hash,
                actual: tip_hash,
            });
        }

        self.coins.flush()?;
        let (actual, base) = hash_utxo_set(&*self.coins)?;
        if base.base_hash != self.snapshot_hash {
            return Ok(HandoffOutcome::BaseMismatch {
                expected: self.snapshot_hash,
                actual: base.base_hash,
            });
        }
        if actual != self.target_utxo_hash {
            return Ok(HandoffOutcome::HashMismatch {
                expected: self.target_utxo_hash,
                actual,
            });
        }
        Ok(HandoffOutcome::Validated)
    }
}
