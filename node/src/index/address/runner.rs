//! Two-pass deferred-backfill runner.
//!
//! Walks every block from genesis to a snapshot height taken at task
//! start, populating the `addr_funding` (pass 1) and `addr_spending`
//! (pass 2) CFs without re-reading flat-file undo data. Pass 1 also
//! materializes a temporary `(outpoint -> scripthash)` CF
//! (`addr_backfill_outpoint_to_scripthash`) that pass 2 consults to
//! resolve each input's scripthash.
//!
//! The supervisor in `main.rs` owns serialization (one runner at a
//! time) and crash-recovery: on startup if `cursor.state == Running`
//! the runner is respawned at `cursor_height + 1` of the current pass.
//! `Paused` is sticky across restart — the supervisor will not
//! auto-respawn until the operator calls `resumeindex`.
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
//! Before each batch we check that the live height index still has
//! `snapshot_tip_hash` at `snapshot_height`. If a reorg invalidated
//! the anchor, the runner aborts with `ReorgInvalidated → Failed`
//! rather than committing rows for blocks no longer on the active
//! chain. The operator restarts via `backfillindex address`, which
//! captures a fresh snapshot.
//!
//! ## Write durability
//!
//! Backfill writes go through `Store::write_batch_mode(WriteMode::Normal)`
//! explicitly so cursor + row + temp-CF advances stay durable even
//! when the chain is in `BulkLoad` (WAL-disabled) mode for IBD.
//!
//! ## Concurrency with live `connect_block`
//!
//! - Backfill writes addr-CF rows for heights ≤ snapshot
//! - Live writes addr-CF rows for heights > snapshot
//! - Disjoint height prefixes → no key collisions; an exact-key
//!   duplicate via reorg-disconnect→reconnect at h ≤ snapshot is
//!   caught by the per-batch reorg check above and aborts the run.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint};

use crate::chain::state::ChainState;
use crate::index::address::backfill::{BackfillError, BackfillHandle};
use crate::index::address::config::AddressIndexConfig;
use crate::index::address::cursor::BackfillState;
use crate::index::address::keys::{AddrFundingRow, AddrSpendingRow, scripthash_of};
use crate::storage::{BackfillCursorWrite, Store, StoreBatch, WriteMode};

/// Inter-task command from RPC handlers to the supervisor.
#[derive(Debug)]
pub enum BackfillCommand {
    /// Operator invoked `backfillindex address`. Supervisor spawns a
    /// fresh runner unless one is already in flight.
    Start,
}

/// Pre-flight: refuse to start a backfill if free disk is below this
/// threshold. Two-pass mode allocates the temp CF (~56 GB peak on
/// mainnet) plus headroom for live IBD continuation and compaction.
pub const PREFLIGHT_REQUIRED_FREE_BYTES: u64 = 80 * 1_073_741_824;

/// Periodic durable-flush cadence. Mirrors the IBD connect loop's
/// 1000-block durable checkpoint so backfill cursor + addr-CF +
/// temp-CF advances are bounded on disk even when the chain is in
/// `BulkLoad` (WAL-disabled) mode for IBD. See review finding #8.
const DURABLE_FLUSH_EVERY_N_BLOCKS: u32 = 1000;

/// In-memory snapshot of the active chain at runner start time.
/// `hashes[h]` is the active-chain block hash at height `h`. Indexed
/// 0..=snapshot_height inclusive.
struct ActiveChainSnapshot {
    hashes: Vec<BlockHash>,
}

impl ActiveChainSnapshot {
    fn snapshot_height(&self) -> u32 {
        // hashes is non-empty post-construction; height 0 = genesis only.
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
    pub cfg: AddressIndexConfig,
    pub shutdown: tokio::sync::watch::Receiver<bool>,
}

impl BackfillRunner {
    /// Run to completion (or pause/cancel/shutdown). Synchronous;
    /// callers should `tokio::task::spawn_blocking` this.
    ///
    /// The RPC handler (or the supervisor on auto-resume) is
    /// responsible for synchronously transitioning the cursor to
    /// `Running` and creating the temp CF *before* spawning a runner.
    /// The runner refuses any other entry state — that lets duplicate
    /// `backfillindex` calls be rejected atomically at the RPC layer
    /// rather than racing inside the supervisor.
    pub fn run(self) -> Result<(), BackfillError> {
        // Refuse to run when the address index is turned off. Without
        // this guard, an auto-resume after `--addressindex=0` would
        // advance the cursor to Completed without writing rows, and a
        // later re-enable would silently leave gaps in history. See
        // review finding #4.
        if !self.cfg.enabled {
            return Err(BackfillError::AddressIndexDisabled);
        }

        // Defensive: the supervisor should only spawn us for state ==
        // Running (fresh start went through RPC; auto-resume only
        // fires on Running). Anything else is a bug.
        let cur = self.handle.cursor();
        if cur.state != BackfillState::Running {
            return Err(BackfillError::Chain(format!(
                "runner spawned with unexpected state {} (expected Running)",
                cur.state.label()
            )));
        }

        // Verify the temp CF exists (created by the RPC handler) and
        // build the active-chain snapshot from the persisted anchor.
        // A reorg that invalidated the anchor between RPC dispatch and
        // runner start surfaces as ReorgInvalidated → Failed.
        let snapshot = self.acquire_snapshot()?;

        // Pass 1: funding rows + temp CF. Resume from cursor_height
        // when picking up after pause/crash.
        let cur = self.handle.cursor();
        if cur.pass <= 1 {
            self.run_pass_1(&snapshot, cur.cursor_height)?;
            self.handle
                .advance_to_pass_2(self.chain.store_ref().as_ref())?;
        }

        // Pass 2: spending rows via temp-CF lookup.
        let cur = self.handle.cursor();
        let resume_from = if cur.pass == 2 { cur.cursor_height } else { 0 };
        self.run_pass_2(&snapshot, resume_from)?;

        // Mark Completed before dropping the temp CF so a crash between
        // these two steps replays the drop on next start (idempotent).
        self.handle
            .mark_completed(self.chain.store_ref().as_ref())?;
        self.chain.store_ref().drop_backfill_temp_cf()?;
        tracing::info!(
            snapshot_height = snapshot.snapshot_height(),
            "addr-index backfill: completed"
        );
        Ok(())
    }

    /// Read the persisted anchor (`snapshot_tip_hash`,
    /// `snapshot_height`), verify it's still on the active chain, and
    /// walk back from there to build the in-memory hash vector.
    /// Called both on fresh-start (RPC just persisted the anchor) and
    /// on resume.
    fn acquire_snapshot(&self) -> Result<ActiveChainSnapshot, BackfillError> {
        if !self.chain.store_ref().backfill_temp_cf_exists() {
            return Err(BackfillError::Chain(
                "backfill temp CF is missing — \
                 run cancelindex address to clear stale state and retry"
                    .into(),
            ));
        }
        let cur = self.handle.cursor();
        let anchor_hash = BlockHash::from_byte_array(cur.snapshot_tip_hash);
        self.verify_anchor_active(cur.snapshot_height, anchor_hash)?;
        self.walk_back(cur.snapshot_height, anchor_hash)
    }

    /// Walk back from `(anchor_height, anchor_hash)` to genesis using
    /// `prev_blockhash`, building a per-height hash vector.
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
            let entry = self.chain.store_ref().get_block_index(&current).ok_or_else(|| {
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

    /// Cheap reorg check: confirm the live height index still has our
    /// anchor hash at `snapshot_height`. Called between batches so the
    /// runner aborts before committing stale rows.
    fn verify_anchor_active(
        &self,
        snapshot_height: u32,
        anchor_hash: BlockHash,
    ) -> Result<(), BackfillError> {
        let live = self.chain.store_ref().get_block_hash_by_height(snapshot_height);
        if live != Some(anchor_hash) {
            return Err(BackfillError::ReorgInvalidated {
                height: snapshot_height,
                detail: format!(
                    "anchor {} no longer matches active chain (live: {:?})",
                    anchor_hash, live
                ),
            });
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

    fn run_pass_1(
        &self,
        snapshot: &ActiveChainSnapshot,
        resume_from: u32,
    ) -> Result<(), BackfillError> {
        let snapshot_height = snapshot.snapshot_height();
        let anchor = snapshot.anchor_hash();
        let started_at_unix = self.handle.cursor().started_at_unix;
        let debug_delay = debug_delay_ms();

        for h in (resume_from + 1)..=snapshot_height {
            self.check_pause_loop()?;
            // Reorg detection (cheap O(1) point lookup). Catches
            // reorgs that happened since the last batch.
            self.verify_anchor_active(snapshot_height, anchor)?;
            if debug_delay > 0 {
                std::thread::sleep(Duration::from_millis(debug_delay));
            }

            let block = self.read_via_snapshot(snapshot, h)?;

            let mut batch = StoreBatch::default();
            for tx in &block.txdata {
                let txid = tx.compute_txid();
                for (vout, output) in tx.output.iter().enumerate() {
                    let sh = scripthash_of(&output.script_pubkey);
                    batch.addr_funding_puts.push(AddrFundingRow {
                        scripthash: sh,
                        height: h,
                        txid,
                        vout: vout as u32,
                        amount_sat: output.value.to_sat(),
                    });
                    batch
                        .addr_backfill_temp_puts
                        .push((OutPoint { txid, vout: vout as u32 }, sh));
                }
            }
            batch.backfill_cursor_advance = Some(BackfillCursorWrite {
                state: BackfillState::Running,
                pass: 1,
                cursor_height: h,
                snapshot_height,
                started_at_unix,
                snapshot_tip_hash: [0u8; 32], // anchor unchanged; skip write
            });
            // Force WriteMode::Normal so cursor + row + temp-CF
            // advances are durable even when the chain is in BulkLoad
            // (WAL-disabled) mode for IBD. See review finding #8.
            self.chain
                .store_ref()
                .write_batch_mode(batch, WriteMode::Normal)?;

            let mut cur = self.handle.cursor();
            cur.cursor_height = h;
            cur.pass = 1;
            cur.snapshot_height = snapshot_height;
            self.handle.set_cursor(cur);

            if h.is_multiple_of(DURABLE_FLUSH_EVERY_N_BLOCKS) {
                tracing::info!(
                    pass = 1,
                    h,
                    snapshot_height,
                    "addr-index backfill: pass 1 progress"
                );
                // Bound the WAL-replay window even when the chain is
                // in BulkLoad mode. flush_durable() blocks until the
                // memtable hits SST, so cursor + rows up to here are
                // truly persistent on a kill -9 thereafter.
                if let Err(e) = self.chain.store_ref().flush_durable() {
                    tracing::warn!(error = %e, "addr-index backfill: periodic flush_durable failed");
                }
            }
        }
        Ok(())
    }

    fn run_pass_2(
        &self,
        snapshot: &ActiveChainSnapshot,
        resume_from: u32,
    ) -> Result<(), BackfillError> {
        let snapshot_height = snapshot.snapshot_height();
        let anchor = snapshot.anchor_hash();
        let started_at_unix = self.handle.cursor().started_at_unix;
        let debug_delay = debug_delay_ms();

        for h in (resume_from + 1)..=snapshot_height {
            self.check_pause_loop()?;
            self.verify_anchor_active(snapshot_height, anchor)?;
            if debug_delay > 0 {
                std::thread::sleep(Duration::from_millis(debug_delay));
            }

            let block = self.read_via_snapshot(snapshot, h)?;

            let mut batch = StoreBatch::default();
            for tx in block.txdata.iter().filter(|t| !t.is_coinbase()) {
                let txid = tx.compute_txid();
                for (vin, input) in tx.input.iter().enumerate() {
                    let prev = input.previous_output;
                    let sh = self
                        .chain
                        .store_ref()
                        .lookup_backfill_temp(&prev)?
                        .ok_or(BackfillError::TempCfMiss(prev))?;
                    batch.addr_spending_puts.push(AddrSpendingRow {
                        scripthash: sh,
                        height: h,
                        txid,
                        vin: vin as u32,
                        prev_outpoint: prev,
                    });
                }
            }
            batch.backfill_cursor_advance = Some(BackfillCursorWrite {
                state: BackfillState::Running,
                pass: 2,
                cursor_height: h,
                snapshot_height,
                started_at_unix,
                snapshot_tip_hash: [0u8; 32],
            });
            self.chain
                .store_ref()
                .write_batch_mode(batch, WriteMode::Normal)?;

            let mut cur = self.handle.cursor();
            cur.cursor_height = h;
            cur.pass = 2;
            self.handle.set_cursor(cur);

            if h.is_multiple_of(DURABLE_FLUSH_EVERY_N_BLOCKS) {
                tracing::info!(
                    pass = 2,
                    h,
                    snapshot_height,
                    "addr-index backfill: pass 2 progress"
                );
                if let Err(e) = self.chain.store_ref().flush_durable() {
                    tracing::warn!(error = %e, "addr-index backfill: periodic flush_durable failed");
                }
            }
        }
        Ok(())
    }

    /// Check pause/cancel/shutdown flags between batches. Returns
    /// `Err(Cancelled)` or `Err(Shutdown)` as appropriate; otherwise
    /// returns `Ok(())` after waiting out any pause window.
    fn check_pause_loop(&self) -> Result<(), BackfillError> {
        loop {
            if *self.shutdown.borrow() {
                return Err(BackfillError::Shutdown);
            }
            if self.handle.is_cancelled() {
                self.handle
                    .mark_cancelled(self.chain.store_ref().as_ref())?;
                self.chain.store_ref().drop_backfill_temp_cf()?;
                return Err(BackfillError::Cancelled);
            }
            if !self.handle.is_paused() {
                // Paused → Running mirror when an operator hits
                // `resumeindex` mid-pause.
                if self.handle.cursor().state == BackfillState::Paused {
                    let _ = self.handle.mark_running(self.chain.store_ref().as_ref());
                }
                return Ok(());
            }
            // First entry into pause: persist Paused so a restart
            // during a paused run stays paused.
            if self.handle.cursor().state == BackfillState::Running {
                let _ = self.handle.mark_paused(self.chain.store_ref().as_ref());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

}

/// Disk-space pre-flight gate. Refuses if free bytes on the chain
/// data dir are below `PREFLIGHT_REQUIRED_FREE_BYTES`. Non-fatal on
/// platforms where free space can't be queried (treated as best
/// effort: don't block the operator). Called synchronously from the
/// `backfillindex` RPC handler so a failure surfaces to the caller
/// rather than getting buried in a runner log.
pub fn preflight_disk(chain: &ChainState) -> Result<(), BackfillError> {
    let datadir = chain.blocks_dir();
    let have = match free_disk_bytes(datadir) {
        Some(b) => b,
        None => {
            tracing::warn!(
                "addr-index backfill: could not read free-disk space, skipping pre-flight gate"
            );
            return Ok(());
        }
    };
    if have < PREFLIGHT_REQUIRED_FREE_BYTES {
        return Err(BackfillError::InsufficientDisk {
            have,
            need: PREFLIGHT_REQUIRED_FREE_BYTES,
        });
    }
    Ok(())
}

/// Test/operations debug knob: per-block sleep injected between
/// batches. Reads `SATD_BACKFILL_DEBUG_DELAY_MS` at every batch (not
/// cached) so tests can flip it mid-run. Default 0; production never
/// sets it. Bounded at 5000 ms to bound pathological misuse.
fn debug_delay_ms() -> u64 {
    std::env::var("SATD_BACKFILL_DEBUG_DELAY_MS")
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
    // SAFETY: we zero-init `s` and pass a valid C string; libc::statvfs
    // is the canonical free-space syscall on Linux.
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
