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
        validation::pow::check_difficulty(&block.header, &parent, self.network, |h| {
            let hash = store_ref.get_block_hash_by_height(h)?;
            store_ref.get_block_index(&hash)
        })?;
        validation::pow::check_timestamp(&block.header, new_height, |h| {
            let hash = store_ref.get_block_hash_by_height(h)?;
            store_ref.get_block_index(&hash)
        })?;
        if !checkpoints::check_against_checkpoints(new_height, &block_hash, &self.checkpoints) {
            return Err(ChainError::CheckpointMismatch(new_height));
        }

        // Write the block into the SHARED flat files so the snapshot
        // chainstate can read it after handoff.
        let block_data = serialize(block);
        let flat_pos = self
            .flat_files
            .lock()
            .write_block(&block_data, network_magic(self.network))
            .map_err(|e| ChainError::FlatFile(e.to_string()))?;

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
