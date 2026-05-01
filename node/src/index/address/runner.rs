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
//!
//! Concurrency with live `connect_block`:
//! - Backfill writes addr-CF rows for heights ≤ snapshot
//! - Live writes addr-CF rows for heights > snapshot
//! - Disjoint height prefixes → no key collisions; even an exact-key
//!   duplicate (via reorg-disconnect→reconnect at a height ≤ snapshot)
//!   is idempotent because `(scripthash, height, txid, vout)` rows
//!   carry the same value bytes.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::OutPoint;

use crate::chain::state::ChainState;
use crate::index::address::backfill::{BackfillError, BackfillHandle};
use crate::index::address::config::AddressIndexConfig;
use crate::index::address::cursor::BackfillState;
use crate::index::address::keys::{AddrFundingRow, AddrSpendingRow, scripthash_of};
use crate::storage::{BackfillCursorWrite, Store, StoreBatch};

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
    pub fn run(self) -> Result<(), BackfillError> {
        let cur = self.handle.cursor();
        let resuming = matches!(cur.state, BackfillState::Running | BackfillState::Paused);

        // Pre-flight only on a fresh start. Resume paths trust the
        // operator who started the original run.
        if !resuming {
            self.preflight()?;
        }

        // Acquire snapshot height + temp CF.
        let snapshot = if resuming {
            // The temp CF must already exist for a Running/Paused
            // resume — it was created on the original start. If the
            // process was killed mid-creation, we treat that as a
            // corrupt resume and refuse.
            if !self.chain.store_ref().backfill_temp_cf_exists() {
                return Err(BackfillError::Chain(
                    "resume requested but backfill temp CF is missing — \
                     run cancelindex address to clear stale state and retry"
                        .into(),
                ));
            }
            cur.snapshot_height
        } else {
            let tip = self.chain.tip_height();
            self.chain.store_ref().create_backfill_temp_cf()?;
            self.handle.start(self.chain.store_ref().as_ref(), tip)?;
            tip
        };

        if snapshot == 0 {
            // Nothing to backfill (empty chain). Mark Completed and
            // drop the temp CF.
            self.handle.mark_completed(self.chain.store_ref().as_ref())?;
            self.chain.store_ref().drop_backfill_temp_cf()?;
            tracing::info!("addr-index backfill: empty chain — nothing to do");
            return Ok(());
        }

        // Pass 1: funding rows + temp CF. Resume from cursor_height
        // when picking up after pause/crash.
        let cur = self.handle.cursor();
        if cur.pass <= 1 {
            self.run_pass_1(snapshot, cur.cursor_height)?;
            self.handle
                .advance_to_pass_2(self.chain.store_ref().as_ref())?;
        }

        // Pass 2: spending rows via temp-CF lookup.
        let cur = self.handle.cursor();
        let resume_from = if cur.pass == 2 { cur.cursor_height } else { 0 };
        self.run_pass_2(snapshot, resume_from)?;

        // Mark Completed before dropping the temp CF so a crash between
        // these two steps replays the drop on next start (idempotent).
        self.handle
            .mark_completed(self.chain.store_ref().as_ref())?;
        self.chain.store_ref().drop_backfill_temp_cf()?;
        tracing::info!(
            snapshot_height = snapshot,
            "addr-index backfill: completed"
        );
        Ok(())
    }

    fn run_pass_1(&self, snapshot: u32, resume_from: u32) -> Result<(), BackfillError> {
        let debug_delay = debug_delay_ms();
        for h in (resume_from + 1)..=snapshot {
            self.check_pause_loop()?;
            if debug_delay > 0 {
                std::thread::sleep(Duration::from_millis(debug_delay));
            }

            let block = self
                .chain
                .read_block_at_height(h)
                .ok_or_else(|| {
                    BackfillError::Chain(format!(
                        "pass 1: missing block at height {} (pruned or corrupt?)",
                        h
                    ))
                })?;

            let mut batch = StoreBatch::default();
            for tx in &block.txdata {
                let txid = tx.compute_txid();
                for (vout, output) in tx.output.iter().enumerate() {
                    let sh = scripthash_of(&output.script_pubkey);
                    if self.cfg.enabled {
                        batch.addr_funding_puts.push(AddrFundingRow {
                            scripthash: sh,
                            height: h,
                            txid,
                            vout: vout as u32,
                            amount_sat: output.value.to_sat(),
                        });
                    }
                    // Always populate the temp CF, even if the live
                    // index is disabled. Pass 2 needs it; if the
                    // operator disabled the index entirely, the runner
                    // shouldn't have been spawned in the first place
                    // (RPC handler gates on `cfg.enabled`).
                    batch
                        .addr_backfill_temp_puts
                        .push((OutPoint { txid, vout: vout as u32 }, sh));
                }
            }
            batch.backfill_cursor_advance = Some(BackfillCursorWrite {
                state: BackfillState::Running,
                pass: 1,
                cursor_height: h,
                snapshot_height: snapshot,
                started_at_unix: self.handle.cursor().started_at_unix,
            });
            self.chain.store_ref().write_batch(batch)?;

            // Mirror the persisted advance into the in-memory cursor
            // so `getindexinfo` and pause/cancel observers see fresh
            // state.
            let mut cur = self.handle.cursor();
            cur.cursor_height = h;
            cur.pass = 1;
            cur.snapshot_height = snapshot;
            self.handle.set_cursor(cur);

            if h.is_multiple_of(1000) {
                tracing::info!(
                    pass = 1,
                    h,
                    snapshot,
                    "addr-index backfill: pass 1 progress"
                );
            }
        }
        Ok(())
    }

    fn run_pass_2(&self, snapshot: u32, resume_from: u32) -> Result<(), BackfillError> {
        let debug_delay = debug_delay_ms();
        for h in (resume_from + 1)..=snapshot {
            self.check_pause_loop()?;
            if debug_delay > 0 {
                std::thread::sleep(Duration::from_millis(debug_delay));
            }

            let block = self
                .chain
                .read_block_at_height(h)
                .ok_or_else(|| {
                    BackfillError::Chain(format!(
                        "pass 2: missing block at height {} (pruned or corrupt?)",
                        h
                    ))
                })?;

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
                    if self.cfg.enabled {
                        batch.addr_spending_puts.push(AddrSpendingRow {
                            scripthash: sh,
                            height: h,
                            txid,
                            vin: vin as u32,
                            prev_outpoint: prev,
                        });
                    }
                }
            }
            batch.backfill_cursor_advance = Some(BackfillCursorWrite {
                state: BackfillState::Running,
                pass: 2,
                cursor_height: h,
                snapshot_height: snapshot,
                started_at_unix: self.handle.cursor().started_at_unix,
            });
            self.chain.store_ref().write_batch(batch)?;

            let mut cur = self.handle.cursor();
            cur.cursor_height = h;
            cur.pass = 2;
            self.handle.set_cursor(cur);

            if h.is_multiple_of(1000) {
                tracing::info!(
                    pass = 2,
                    h,
                    snapshot,
                    "addr-index backfill: pass 2 progress"
                );
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
                // Mirror the persisted state from Paused→Running
                // when an operator hits resume mid-pause.
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

    fn preflight(&self) -> Result<(), BackfillError> {
        let datadir = self.chain.blocks_dir();
        // statvfs for free bytes. Errors are non-fatal — if we can't
        // read free space, allow the run rather than blocking the
        // operator. (They can always cancel.)
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
