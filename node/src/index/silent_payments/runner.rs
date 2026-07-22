//! Single-pass deferred-backfill runner for the BIP 352 silent-payment
//! tweak index.
//!
//! Walks every block from **taproot activation** to a snapshot height
//! taken at task start, populating `cf_sp_tweaks`. Per block, read the
//! block + persisted undo data and feed the spent prev-output
//! scriptPubKeys into the shared BIP 352 kernel (`build_sp_row`). No temp
//! CF, no second pass — and, unlike the filter index, no tail-catch-up:
//! SP tweak rows are self-authenticating (they embed the hash of the
//! block they describe) and do not chain, so rows the live `connect_block`
//! path emitted for heights above the snapshot are already correct.
//!
//! ## Why start at taproot activation
//!
//! No BIP 352 output can be paid before taproot activated (§3.2), and the
//! live connect path applies the same gate. Walking from activation makes
//! the backfill produce byte-identical rows to a from-genesis sync (the
//! PR-8 acceleration differential). On regtest taproot activates at
//! height 0, but genesis is never connected via `connect_block`, so the
//! walk still starts at height 1 to match the live path.
//!
//! ## Active-chain selection and reorg safety
//!
//! At `start()` time the runner records the chain tip hash as
//! `snapshot_tip_hash` in the persisted cursor and walks back via
//! `prev_blockhash` to build a `Vec<BlockHash>` indexed by height. All
//! subsequent block reads use that vector — *not* the live height index,
//! which can transiently point at header-only blocks for heights past the
//! tip after a reorg. Before each batch we re-check that the live
//! active-chain block at `snapshot_height` is still our anchor; a reorg
//! aborts the run with `ReorgInvalidated → Failed` rather than committing
//! rows for blocks no longer on the active chain.
//!
//! ## Write durability
//!
//! Backfill writes go through `Store::write_batch_mode(WriteMode::Normal)`
//! explicitly so cursor + row advances stay durable even when the chain
//! is in `BulkLoad` (WAL-disabled) mode for IBD.
//!
//! ## Concurrency with live `connect_block`
//!
//! - Backfill writes rows for heights ≤ snapshot_height.
//! - Live `connect_block` writes rows for heights > snapshot_height.
//! - Disjoint height prefixes → no key collisions; an exact-key duplicate
//!   via reorg-disconnect→reconnect at h ≤ snapshot is caught by the
//!   per-batch reorg check above and aborts the run.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, ScriptBuf};

use node_sp_index::SpIndexConfig;
use node_sp_index::cursor::BackfillState;

use crate::chain::state::ChainState;
use crate::index::silent_payments::backfill::{BackfillError, BackfillHandle};
use crate::index::silent_payments::emit::build_sp_row;
use crate::storage::{SpBackfillCursorWrite, Store, StoreBatch, WriteMode};

/// Inter-task command from RPC handlers to the supervisor.
#[derive(Debug)]
pub enum BackfillCommand {
    /// Operator invoked `backfillindex silentpayment`. Supervisor spawns
    /// a fresh runner unless one is already in flight.
    Start,
}

/// Periodic durable-flush cadence. Mirrors the IBD connect loop's
/// 1000-block durable checkpoint so backfill cursor + tweak rows are
/// bounded on disk even when the chain is in `BulkLoad` (WAL-disabled)
/// mode for IBD.
const DURABLE_FLUSH_EVERY_N_BLOCKS: u32 = 1000;

/// In-memory snapshot of the active chain at runner start time.
struct ActiveChainSnapshot {
    hashes: Vec<BlockHash>,
}

impl ActiveChainSnapshot {
    fn snapshot_height(&self) -> u32 {
        (self.hashes.len() - 1) as u32
    }

    fn anchor_hash(&self) -> BlockHash {
        self.hashes[self.snapshot_height() as usize]
    }
}

/// Drives a single backfill run end-to-end. One runner per
/// `BackfillCommand::Start`; the supervisor enforces "at most one".
pub struct BackfillRunner {
    pub handle: Arc<BackfillHandle>,
    pub chain: Arc<ChainState>,
    pub cfg: SpIndexConfig,
    pub shutdown: tokio::sync::watch::Receiver<bool>,
}

impl BackfillRunner {
    /// Lowest height that can carry a BIP 352 tweak row: taproot
    /// activation, but never below 1 (genesis is never connected via
    /// `connect_block`, so the live path emits no row there).
    fn walk_start(&self) -> u32 {
        crate::validation::script::activation_heights(self.chain.network)
            .taproot
            .max(1)
    }

    /// Run to completion (or pause/cancel/shutdown). Synchronous; callers
    /// should `tokio::task::spawn_blocking` this.
    pub fn run(self) -> Result<(), BackfillError> {
        // Refuse to run when the SP index is turned off. Without this
        // guard, an auto-resume after `--silentpaymentindex=0` would
        // advance the cursor to Completed without writing rows.
        if !self.cfg.enabled {
            return Err(BackfillError::SilentPaymentIndexDisabled);
        }

        // Defensive: the supervisor should only spawn us for active
        // backfill states (Running or Paused).
        let cur = self.handle.cursor();
        if !matches!(cur.state, BackfillState::Running | BackfillState::Paused) {
            return Err(BackfillError::Chain(format!(
                "runner spawned with unexpected state {} (expected Running or Paused)",
                cur.state.label()
            )));
        }

        let snapshot = self.acquire_snapshot()?;
        let cur = self.handle.cursor();
        self.run_pass(&snapshot, cur.cursor_height)?;

        self.handle
            .mark_completed(self.chain.store_ref().as_ref())?;
        tracing::info!(
            snapshot_height = snapshot.snapshot_height(),
            walk_start = self.walk_start(),
            "sp-index backfill: completed"
        );
        Ok(())
    }

    fn acquire_snapshot(&self) -> Result<ActiveChainSnapshot, BackfillError> {
        let cur = self.handle.cursor();
        let anchor_hash = BlockHash::from_byte_array(cur.snapshot_tip_hash);
        self.verify_anchor_active(cur.snapshot_height, anchor_hash)?;
        self.walk_back(cur.snapshot_height, anchor_hash)
    }

    /// Build the height→hash vector for the snapshot's active chain. Walks
    /// back from the anchor via `prev_blockhash` and stops at `walk_start`
    /// — heights below taproot activation carry no tweak rows, so their
    /// slots stay all-zero (never read by `read_via_snapshot`).
    fn walk_back(
        &self,
        anchor_height: u32,
        anchor_hash: BlockHash,
    ) -> Result<ActiveChainSnapshot, BackfillError> {
        let walk_start = self.walk_start();
        let mut hashes = vec![BlockHash::all_zeros(); (anchor_height + 1) as usize];
        let mut h = anchor_height;
        let mut current = anchor_hash;
        loop {
            hashes[h as usize] = current;
            if h == 0 || h <= walk_start {
                break;
            }
            let entry = self
                .chain
                .store_ref()
                .get_block_index(&current)
                .ok_or_else(|| {
                    BackfillError::Chain(format!(
                        "snapshot walk: missing block index entry for {} at height {}",
                        current, h
                    ))
                })?;
            current = entry.header.prev_blockhash;
            h -= 1;
        }
        Ok(ActiveChainSnapshot { hashes })
    }

    /// Cheap reorg check: confirm the live active-chain block at
    /// `snapshot_height` is still our anchor hash. Walks back from the
    /// current tip via `prev_blockhash` so we consult only active-chain
    /// ancestry.
    fn verify_anchor_active(
        &self,
        snapshot_height: u32,
        anchor_hash: BlockHash,
    ) -> Result<(), BackfillError> {
        let (tip_hash, tip_height) = self.chain.tip_snapshot();
        if tip_height < snapshot_height {
            return Err(BackfillError::ReorgInvalidated {
                height: snapshot_height,
                detail: format!(
                    "tip dropped below snapshot height (tip {} < snapshot {})",
                    tip_height, snapshot_height
                ),
            });
        }
        let mut current = tip_hash;
        let mut h = tip_height;
        while h > snapshot_height {
            let entry = self
                .chain
                .store_ref()
                .get_block_index(&current)
                .ok_or_else(|| BackfillError::ReorgInvalidated {
                    height: snapshot_height,
                    detail: format!("missing block-index entry walking back from tip {}", current),
                })?;
            current = entry.header.prev_blockhash;
            h -= 1;
        }
        if current != anchor_hash {
            return Err(BackfillError::ReorgInvalidated {
                height: snapshot_height,
                detail: format!(
                    "anchor {} no longer on active chain at height {} (live: {})",
                    anchor_hash, snapshot_height, current
                ),
            });
        }
        Ok(())
    }

    /// Walk the OLD snapshot for the heights backfill has already touched,
    /// find divergences against the live active chain, and emit
    /// `sp_tweak_removes` for any OLD blocks no longer active. Bounded
    /// work: reads only divergent blocks (typically <10 for a normal
    /// reorg). Mirrors the filter-index `cleanup_stale_rows_after_reorg`.
    pub fn cleanup_stale_rows_after_reorg(
        chain: &ChainState,
        handle: &BackfillHandle,
    ) -> Result<(), BackfillError> {
        let cur = handle.cursor();
        if cur.snapshot_height == 0 {
            return Ok(());
        }
        let walk_start = crate::validation::script::activation_heights(chain.network)
            .taproot
            .max(1);
        let old_anchor = BlockHash::from_byte_array(cur.snapshot_tip_hash);
        let mut old_hashes = vec![BlockHash::all_zeros(); (cur.snapshot_height + 1) as usize];
        {
            let mut h = cur.snapshot_height;
            let mut current = old_anchor;
            loop {
                old_hashes[h as usize] = current;
                if h == 0 || h <= walk_start {
                    break;
                }
                let entry = chain.store_ref().get_block_index(&current).ok_or_else(|| {
                    BackfillError::Chain(format!(
                        "reorg cleanup: missing block index for {} at height {}",
                        current, h
                    ))
                })?;
                current = entry.header.prev_blockhash;
                h -= 1;
            }
        }

        let (live_tip_hash, live_tip_height) = chain.tip_snapshot();
        let live_hashes_len = (live_tip_height as usize + 1).max(1);
        let mut live_hashes = vec![BlockHash::all_zeros(); live_hashes_len];
        {
            let mut h = live_tip_height;
            let mut current = live_tip_hash;
            loop {
                live_hashes[h as usize] = current;
                if h == 0 {
                    break;
                }
                let entry = chain.store_ref().get_block_index(&current).ok_or_else(|| {
                    BackfillError::Chain(format!(
                        "reorg cleanup: missing block index walking live tip back at height {}",
                        h
                    ))
                })?;
                current = entry.header.prev_blockhash;
                h -= 1;
            }
        }

        // Only heights in [walk_start, cursor_height] can carry a row the
        // backfill wrote, so bound the divergence scan there.
        let touched_high = cur.cursor_height;
        let mut total_removes = 0u64;
        for h in walk_start..=touched_high {
            let old_hash = old_hashes[h as usize];
            let live_hash = live_hashes.get(h as usize).copied();
            if live_hash == Some(old_hash) {
                continue;
            }
            let mut batch = StoreBatch::default();
            batch.sp_tweak_removes.push(h);
            chain
                .store_ref()
                .write_batch_mode(batch, WriteMode::Normal)?;
            total_removes += 1;
        }
        if total_removes > 0 {
            tracing::info!(
                rows = total_removes,
                "sp-index reorg cleanup: removed stale rows for divergent OLD blocks"
            );
            chain.store_ref().flush_durable()?;
        }
        Ok(())
    }

    fn read_via_snapshot(
        &self,
        snapshot: &ActiveChainSnapshot,
        h: u32,
    ) -> Result<bitcoin::Block, BackfillError> {
        let hash = *snapshot.hashes.get(h as usize).ok_or_else(|| {
            BackfillError::Chain(format!(
                "snapshot index out of range: h={} (snapshot_height={})",
                h,
                snapshot.snapshot_height()
            ))
        })?;
        self.chain.get_block(&hash).ok_or_else(|| {
            BackfillError::Chain(format!(
                "missing block data for {} at height {} (pruned or corrupt?)",
                hash, h
            ))
        })
    }

    fn run_pass(
        &self,
        snapshot: &ActiveChainSnapshot,
        resume_from: u32,
    ) -> Result<(), BackfillError> {
        let snapshot_height = snapshot.snapshot_height();
        let anchor = snapshot.anchor_hash();
        let started_at_unix = self.handle.cursor().started_at_unix;
        let snapshot_tip_hash = self.handle.cursor().snapshot_tip_hash;
        let debug_delay = debug_delay_ms();
        let walk_start = self.walk_start();

        // Chain not yet synced past taproot activation: nothing to walk.
        // The cursor stays at 0 and `mark_completed` (called by `run`)
        // stamps the completeness marker — an index with no eligible
        // blocks is trivially complete.
        if walk_start > snapshot_height {
            return Ok(());
        }

        // Fresh start (resume_from == 0) begins at `walk_start`; a resume
        // after kill -9 picks up just past the last stamped height. We
        // never persist a cursor_height below `walk_start`, so
        // resume_from is either 0 or in [walk_start, snapshot_height].
        let begin = if resume_from == 0 {
            walk_start
        } else {
            resume_from + 1
        };

        for h in begin..=snapshot_height {
            self.check_pause_loop()?;
            self.verify_anchor_active(snapshot_height, anchor)?;
            if debug_delay > 0 {
                std::thread::sleep(Duration::from_millis(debug_delay));
            }

            let block = self.read_via_snapshot(snapshot, h)?;
            let block_hash = block.header.block_hash();
            let undo = self
                .chain
                .store_ref()
                .get_undo(&block_hash)
                .ok_or(BackfillError::MissingUndo(h))?;

            // Build prev-output script map from undo data. The undo
            // entries are in connect-order across non-coinbase txs;
            // rebuild the (prev_outpoint -> scriptPubKey) map by walking
            // txs forward in lockstep with the undo cursor — the same
            // shape the filter backfill uses.
            let mut prev_map: HashMap<OutPoint, ScriptBuf> = HashMap::new();
            let mut undo_cursor = 0usize;
            for tx in &block.txdata {
                if tx.is_coinbase() {
                    continue;
                }
                for input in &tx.input {
                    let coin = undo
                        .spent_coins
                        .get(undo_cursor)
                        .ok_or(BackfillError::MissingUndo(h))?;
                    prev_map.insert(input.previous_output, coin.script_pubkey.clone());
                    undo_cursor += 1;
                }
            }

            let mut batch = StoreBatch::default();
            if let Some(row) =
                build_sp_row(&self.cfg, &block, block_hash, &prev_map).map_err(|e| {
                    BackfillError::Emit {
                        height: h,
                        detail: e.to_string(),
                    }
                })?
            {
                batch.sp_tweak_puts.push((h, row));
            }
            batch.sp_backfill_cursor_advance = Some(SpBackfillCursorWrite {
                state: BackfillState::Running,
                cursor_height: h,
                snapshot_height,
                started_at_unix,
                // Don't re-write the anchor on every batch — the
                // sentinel-zero hash skips the metadata write so the
                // anchor recorded by start() is preserved.
                snapshot_tip_hash: [0u8; 32],
            });
            self.chain
                .store_ref()
                .write_batch_mode(batch, WriteMode::Normal)?;

            let mut cur = self.handle.cursor();
            cur.cursor_height = h;
            cur.snapshot_height = snapshot_height;
            self.handle.set_cursor(cur);

            self.verify_anchor_active(snapshot_height, anchor)?;

            if h.is_multiple_of(DURABLE_FLUSH_EVERY_N_BLOCKS) {
                tracing::info!(h, snapshot_height, "sp-index backfill: progress");
                if let Err(e) = self.chain.store_ref().flush_durable() {
                    tracing::warn!(error = %e, "sp-index backfill: periodic flush_durable failed");
                }
            }
        }

        // The started_at_unix / snapshot_tip_hash locals are only read on
        // the fresh-start path; silence unused warnings on a pure resume.
        let _ = (started_at_unix, snapshot_tip_hash);
        Ok(())
    }

    fn check_pause_loop(&self) -> Result<(), BackfillError> {
        loop {
            if *self.shutdown.borrow() {
                return Err(BackfillError::Shutdown);
            }
            if self.handle.is_cancelled() {
                self.handle
                    .mark_cancelled(self.chain.store_ref().as_ref())?;
                return Err(BackfillError::Cancelled);
            }
            if !self.handle.is_paused() {
                if self.handle.cursor().state == BackfillState::Paused {
                    let _ = self.handle.mark_running(self.chain.store_ref().as_ref());
                }
                return Ok(());
            }
            if self.handle.cursor().state == BackfillState::Running {
                let _ = self.handle.mark_paused(self.chain.store_ref().as_ref());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

/// Disk-space pre-flight gate. Refuses if free bytes on the chain data
/// dir are below `PREFLIGHT_REQUIRED_FREE_BYTES`. Non-fatal on platforms
/// where free space can't be queried.
pub fn preflight_disk(chain: &ChainState) -> Result<(), BackfillError> {
    use crate::index::silent_payments::backfill::PREFLIGHT_REQUIRED_FREE_BYTES;
    let datadir = chain.blocks_dir();
    let have = match free_disk_bytes(datadir) {
        Some(b) => b,
        None => {
            tracing::warn!(
                "sp-index backfill: could not read free-disk space, skipping pre-flight gate"
            );
            return Ok(());
        }
    };
    if have < PREFLIGHT_REQUIRED_FREE_BYTES {
        return Err(BackfillError::Chain(format!(
            "insufficient free disk for sp-index backfill: have {} bytes, need {} bytes (~6 GB)",
            have, PREFLIGHT_REQUIRED_FREE_BYTES,
        )));
    }
    Ok(())
}

fn debug_delay_ms() -> u64 {
    std::env::var("SATD_SP_BACKFILL_DEBUG_DELAY_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|v| v.min(5_000))
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn free_disk_bytes(path: &std::path::Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: zero-init s; libc::statvfs is the canonical free-space syscall.
    unsafe {
        let mut s: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(cpath.as_ptr(), &mut s) != 0 {
            return None;
        }
        Some(s.f_bavail.saturating_mul(s.f_frsize))
    }
}

#[cfg(not(target_os = "linux"))]
fn free_disk_bytes(_path: &std::path::Path) -> Option<u64> {
    None
}
