//! Single-pass deferred-backfill runner for the BIP 158 filter index.
//!
//! Walks every block from genesis to a snapshot height taken at task
//! start, populating `cf_filter` and `cf_filter_header`. Unlike the
//! address-index two-pass runner, this is a single forward walk: per
//! block, read the block + persisted undo data and feed the spent
//! prev-output scriptPubKeys directly into
//! `BlockFilter::new_script_filter`. No temp CF, no second pass.
//!
//! ## Active-chain selection and reorg safety
//!
//! At `start()` time the runner records the chain tip hash as
//! `snapshot_tip_hash` in the persisted cursor and walks back via
//! `prev_blockhash` to build a `Vec<BlockHash>` indexed by height.
//! All subsequent block reads use that vector — *not* the live height
//! index, which can transiently point at header-only blocks for
//! heights past the tip after a reorg.
//!
//! Before each batch we check that the live active-chain block at
//! `snapshot_height` is still our anchor hash. If a reorg invalidated
//! the anchor, the runner aborts with `ReorgInvalidated → Failed`
//! rather than committing rows for blocks no longer on the active
//! chain. The operator restarts via `backfillindex blockfilter`,
//! which captures a fresh snapshot.
//!
//! ## Write durability
//!
//! Backfill writes go through `Store::write_batch_mode(WriteMode::Normal)`
//! explicitly so cursor + row advances stay durable even when the
//! chain is in `BulkLoad` (WAL-disabled) mode for IBD.
//!
//! ## Concurrency with live `connect_block`
//!
//! - Backfill writes filter rows for heights ≤ snapshot_height.
//! - Live `connect_block` writes filter rows for heights > snapshot_height.
//! - Disjoint height prefixes → no key collisions; an exact-key
//!   duplicate via reorg-disconnect→reconnect at h ≤ snapshot is
//!   caught by the per-batch reorg check above and aborts the run.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, ScriptBuf};

use node_filter_index::FilterIndexConfig;
use node_filter_index::cursor::BackfillState;

use crate::chain::state::ChainState;
use crate::index::filter::backfill::{BackfillError, BackfillHandle};
use crate::index::filter::emit::{GENESIS_PREV_FILTER_HEADER, build_filter_row_pair};
use crate::storage::{FilterBackfillCursorWrite, Store, StoreBatch, WriteMode};

/// Inter-task command from RPC handlers to the supervisor.
#[derive(Debug)]
pub enum BackfillCommand {
    /// Operator invoked `backfillindex blockfilter`. Supervisor spawns
    /// a fresh runner unless one is already in flight.
    Start,
}

/// Pre-flight: refuse to start a backfill if free disk is below this
/// threshold. Filter blobs at mainnet tip total ~6 GB; require 10 GB
/// headroom to absorb compaction churn and continued IBD writes.
pub const PREFLIGHT_REQUIRED_FREE_BYTES: u64 = 10 * 1_073_741_824;

/// Periodic durable-flush cadence. Mirrors the IBD connect loop's
/// 1000-block durable checkpoint so backfill cursor + filter rows are
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
    pub cfg: FilterIndexConfig,
    pub shutdown: tokio::sync::watch::Receiver<bool>,
}

impl BackfillRunner {
    /// Run to completion (or pause/cancel/shutdown). Synchronous;
    /// callers should `tokio::task::spawn_blocking` this.
    pub fn run(self) -> Result<(), BackfillError> {
        // Refuse to run when the filter index is turned off. Without
        // this guard, an auto-resume after `--blockfilterindex=0`
        // would advance the cursor to Completed without writing rows.
        // Mirrors the address-index review-1 finding #4 contract.
        if !self.cfg.enabled {
            return Err(BackfillError::FilterIndexDisabled);
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

        // Tail catch-up: while the runner was filling 0..=snapshot_height
        // the live `connect_block` may have emitted filter rows for
        // heights > snapshot_height that chain off the all-zero genesis
        // header (because the prev-header at snapshot_height didn't
        // exist yet at live-emit time). After the snapshot pass, walk
        // forward from snapshot+1 to the current tip, recomputing
        // headers from the just-stamped snapshot tail. Loop until the
        // tip stops moving so concurrent live extensions converge —
        // this is what closes the H1 chain-corruption window the
        // 2026-05-04 review flagged.
        self.run_tail_catchup(snapshot.snapshot_height())?;

        self.handle
            .mark_completed(self.chain.store_ref().as_ref())?;
        tracing::info!(
            snapshot_height = snapshot.snapshot_height(),
            "filter-index backfill: completed"
        );
        Ok(())
    }

    /// Tail catch-up phase: re-emit filter rows + correctly chained
    /// filter headers for every height from `snapshot_height + 1` to
    /// the current chain tip. Live `connect_block` may have produced
    /// header rows above the snapshot that chain off the all-zero
    /// fallback (the connect-time emit cannot wait for backfill
    /// without blocking the chain). We overwrite those rows here.
    ///
    /// Loops until the tip stops advancing — concurrent live block
    /// connections during the catch-up would otherwise leave a
    /// trailing window of stale headers. In steady state this converges
    /// in one or two iterations.
    fn run_tail_catchup(&self, snapshot_height: u32) -> Result<(), BackfillError> {
        let mut cursor = snapshot_height;
        loop {
            self.check_pause_loop()?;
            let (tip_hash, tip_height) = self.chain.tip_snapshot();
            if tip_height <= cursor {
                return Ok(());
            }
            // Walk back from the live tip to `cursor + 1` and rewrite
            // every header in that range with a correctly-chained
            // value. Block-hash-by-walk-back rather than via the
            // height index to avoid header-only entries.
            let mut hashes = vec![bitcoin::BlockHash::all_zeros(); (tip_height + 1) as usize];
            let mut h = tip_height;
            let mut current = tip_hash;
            while h > cursor {
                hashes[h as usize] = current;
                let entry = self
                    .chain
                    .store_ref()
                    .get_block_index(&current)
                    .ok_or_else(|| {
                        BackfillError::Chain(format!(
                            "tail catch-up: missing block index for {} at height {}",
                            current, h
                        ))
                    })?;
                current = entry.header.prev_blockhash;
                h -= 1;
            }
            // current is now the hash at `cursor` (the snapshot tail
            // boundary on the first iteration, or the previous
            // catch-up boundary on subsequent iterations). Use
            // `header_at(cursor)` as the chain root.
            let mut prev_header = self
                .chain
                .store_ref()
                .get_filter_header(node_filter_index::FILTER_TYPE_BASIC, cursor)
                .ok_or_else(|| {
                    BackfillError::Chain(format!(
                        "tail catch-up: missing filter header at boundary height {}",
                        cursor
                    ))
                })?;
            for h in (cursor + 1)..=tip_height {
                self.check_pause_loop()?;
                let hash = hashes[h as usize];
                let block = self.chain.get_block(&hash).ok_or_else(|| {
                    BackfillError::Chain(format!(
                        "tail catch-up: missing block data for {} at height {}",
                        hash, h
                    ))
                })?;
                let undo = self
                    .chain
                    .store_ref()
                    .get_undo(&hash)
                    .ok_or(BackfillError::MissingUndo(h))?;
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
                if let Some((row, header_row)) =
                    build_filter_row_pair(&self.cfg, h, &block, &prev_map, &prev_header).map_err(
                        |e| BackfillError::Chain(format!("tail catch-up emit at {h}: {e}")),
                    )?
                {
                    prev_header = header_row.header;
                    batch.filter_puts.push(row);
                    batch.filter_header_puts.push(header_row);
                }
                self.chain
                    .store_ref()
                    .write_batch_mode(batch, WriteMode::Normal)?;
            }
            tracing::info!(
                from = cursor + 1,
                to = tip_height,
                "filter-index backfill: tail catch-up walked"
            );
            cursor = tip_height;
            // Loop: if a fresh live block landed during the walk,
            // tip_height moved and we need another pass.
        }
    }

    fn acquire_snapshot(&self) -> Result<ActiveChainSnapshot, BackfillError> {
        let cur = self.handle.cursor();
        let anchor_hash = BlockHash::from_byte_array(cur.snapshot_tip_hash);
        self.verify_anchor_active(cur.snapshot_height, anchor_hash)?;
        self.walk_back(cur.snapshot_height, anchor_hash)
    }

    fn walk_back(
        &self,
        anchor_height: u32,
        anchor_hash: BlockHash,
    ) -> Result<ActiveChainSnapshot, BackfillError> {
        let mut hashes = vec![BlockHash::all_zeros(); (anchor_height + 1) as usize];
        let mut h = anchor_height;
        let mut current = anchor_hash;
        loop {
            hashes[h as usize] = current;
            if h == 0 {
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
    /// current tip via `prev_blockhash` so we consult only active-
    /// chain ancestry.
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
                    detail: format!(
                        "missing block-index entry walking back from tip {}",
                        current
                    ),
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

    /// Walk the OLD snapshot for the heights backfill has already
    /// touched, find divergences against the live active chain, and
    /// emit `filter_removes` for any OLD blocks no longer active.
    /// Bounded work: reads only divergent blocks (typically <10 for a
    /// normal reorg). Mirrors the address-index `cleanup_stale_rows_after_reorg`.
    pub fn cleanup_stale_rows_after_reorg(
        chain: &ChainState,
        handle: &BackfillHandle,
    ) -> Result<(), BackfillError> {
        let cur = handle.cursor();
        if cur.snapshot_height == 0 {
            return Ok(());
        }
        let old_anchor = BlockHash::from_byte_array(cur.snapshot_tip_hash);
        let mut old_hashes = vec![BlockHash::all_zeros(); (cur.snapshot_height + 1) as usize];
        {
            let mut h = cur.snapshot_height;
            let mut current = old_anchor;
            loop {
                old_hashes[h as usize] = current;
                if h == 0 {
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

        let touched_high = cur.cursor_height;
        let mut total_removes = 0u64;
        for h in 1..=touched_high {
            let old_hash = old_hashes[h as usize];
            let live_hash = live_hashes.get(h as usize).copied();
            if live_hash == Some(old_hash) {
                continue;
            }
            let mut batch = StoreBatch::default();
            batch.filter_removes.push(node_filter_index::FilterKey {
                filter_type: node_filter_index::FILTER_TYPE_BASIC,
                height: h,
            });
            chain
                .store_ref()
                .write_batch_mode(batch, WriteMode::Normal)?;
            total_removes += 1;
        }
        if total_removes > 0 {
            tracing::info!(
                rows = total_removes,
                "filter-index reorg cleanup: removed stale rows for divergent OLD blocks"
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

        // Genesis block (height 0): the only spent inputs are the
        // coinbase null outpoint, which BIP 158 SCRIPT_FILTER ignores.
        // Emit the filter row when starting from scratch.
        if resume_from == 0 {
            self.check_pause_loop()?;
            self.verify_anchor_active(snapshot_height, anchor)?;
            let block = self.read_via_snapshot(snapshot, 0)?;
            let prev_map: HashMap<OutPoint, ScriptBuf> = HashMap::new();
            let mut batch = StoreBatch::default();
            if let Some((row, header_row)) =
                build_filter_row_pair(&self.cfg, 0, &block, &prev_map, &GENESIS_PREV_FILTER_HEADER)
                    .map_err(|e| BackfillError::Chain(format!("genesis filter emit: {e}")))?
            {
                batch.filter_puts.push(row);
                batch.filter_header_puts.push(header_row);
            }
            batch.filter_backfill_cursor_advance = Some(FilterBackfillCursorWrite {
                state: BackfillState::Running,
                cursor_height: 0,
                snapshot_height,
                started_at_unix,
                snapshot_tip_hash,
            });
            self.chain
                .store_ref()
                .write_batch_mode(batch, WriteMode::Normal)?;
            let mut cur = self.handle.cursor();
            cur.cursor_height = 0;
            self.handle.set_cursor(cur);
        }

        // Heights 1..=snapshot_height. Resume_from = 0 picks up at
        // height 1 (genesis was just stamped); resume_from > 0 skips
        // back to where the kill -9 left us. The chained filter
        // header is read from the on-disk row at h-1, which is the
        // last cursor advance's emission.
        for h in (resume_from + 1)..=snapshot_height {
            self.check_pause_loop()?;
            self.verify_anchor_active(snapshot_height, anchor)?;
            if debug_delay > 0 {
                std::thread::sleep(Duration::from_millis(debug_delay));
            }

            let block = self.read_via_snapshot(snapshot, h)?;
            let undo = self
                .chain
                .store_ref()
                .get_undo(&block.header.block_hash())
                .ok_or(BackfillError::MissingUndo(h))?;

            // Build prev-output script map from undo data. The undo
            // entries are in connect-order across non-coinbase txs;
            // rebuild the (prev_outpoint -> scriptPubKey) map by
            // walking txs forward in lockstep with the undo cursor —
            // same shape as `disconnect_block`'s reverse walk.
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
                    // The v1 undo format stores only the spent coin, in
                    // connect-order — the outpoint is the input's
                    // `previous_output`. No cross-check possible here.
                    prev_map.insert(input.previous_output, coin.script_pubkey.clone());
                    undo_cursor += 1;
                }
            }

            // Read the prev-block filter header from cf_filter_header.
            // For h == 1 this is the genesis row we just stamped.
            let prev_header = self
                .chain
                .store_ref()
                .get_filter_header(node_filter_index::FILTER_TYPE_BASIC, h - 1)
                .unwrap_or(GENESIS_PREV_FILTER_HEADER);

            let mut batch = StoreBatch::default();
            if let Some((row, header_row)) =
                build_filter_row_pair(&self.cfg, h, &block, &prev_map, &prev_header)
                    .map_err(|e| BackfillError::Chain(format!("filter emit at height {h}: {e}")))?
            {
                batch.filter_puts.push(row);
                batch.filter_header_puts.push(header_row);
            }
            batch.filter_backfill_cursor_advance = Some(FilterBackfillCursorWrite {
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
                tracing::info!(h, snapshot_height, "filter-index backfill: progress");
                if let Err(e) = self.chain.store_ref().flush_durable() {
                    tracing::warn!(error = %e, "filter-index backfill: periodic flush_durable failed");
                }
            }
        }
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

/// Disk-space pre-flight gate. Refuses if free bytes on the chain
/// data dir are below `PREFLIGHT_REQUIRED_FREE_BYTES`. Non-fatal on
/// platforms where free space can't be queried.
pub fn preflight_disk(chain: &ChainState) -> Result<(), BackfillError> {
    let datadir = chain.blocks_dir();
    let have = match free_disk_bytes(datadir) {
        Some(b) => b,
        None => {
            tracing::warn!(
                "filter-index backfill: could not read free-disk space, skipping pre-flight gate"
            );
            return Ok(());
        }
    };
    if have < PREFLIGHT_REQUIRED_FREE_BYTES {
        return Err(BackfillError::Chain(format!(
            "insufficient free disk for filter backfill: have {} bytes, need {} bytes (~10 GB)",
            have, PREFLIGHT_REQUIRED_FREE_BYTES,
        )));
    }
    Ok(())
}

fn debug_delay_ms() -> u64 {
    std::env::var("SATD_FILTER_BACKFILL_DEBUG_DELAY_MS")
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
