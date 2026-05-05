//! Stall detection and forced compaction.
//!
//! Two dedicated `std::thread`s — deliberately not tokio tasks. During the
//! 2026-05 mainnet IBD wedge the entire tokio runtime parked itself (every
//! worker in `futex_do_wait`, no progress for nine hours, RPC accept queue
//! piled up to 3084 backlogged connections). A watchdog scheduled on the
//! same runtime that froze would have frozen with it, so this module spawns
//! its own OS threads. Forced compaction is also long-running and synchronous
//! — putting it on a tokio worker would consume one until the call returns.
//!
//! The two threads are independent:
//!
//! * **Stall watchdog**: tracks the chain tip's last forward-progress
//!   timestamp. If the tip hasn't advanced for `stall_threshold`, it emits
//!   per-thread state from `/proc/self/task/*` (TID, comm, kernel state,
//!   wchan) so the operator has post-mortem evidence of which threads were
//!   parked on what futex, and after `abort_after` of continued silence it
//!   calls `std::process::abort()` so systemd restarts the unit. Without
//!   this, a wedged process can sit in the same broken state indefinitely
//!   and the operator only finds out when a downstream client times out.
//!
//! * **Periodic compactor**: every `interval` it inspects the chainstate's
//!   L0 SST count and pending-compaction-bytes estimate. If either is over
//!   threshold it forces a synchronous compaction of the chainstate column
//!   family. This is the backstop for cases where the connector's per-
//!   iteration backpressure (in `net::manager::ibd_connect_loop`) doesn't
//!   pause the writes long enough for RocksDB's background compactors to
//!   catch up — typically because the operator chose `--maxahead=all` and
//!   sustained write pressure for the duration of the IBD.
//!
//! Both threads honor `shutdown_rx` by polling its `borrow()` synchronously
//! at each tick. They never `.await` it — that would re-introduce the
//! tokio-runtime dependency we set out to avoid.

use crate::chain::state::ChainState;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Spawn the stall watchdog on a dedicated `std::thread`.
///
/// `stall_threshold` is how long without forward connector progress before
/// the watchdog dumps thread states. `abort_after` is how much *additional*
/// silence after the dump before the watchdog calls `std::process::abort()`.
///
/// Progress is observed via [`ChainState::connect_heartbeat`], a lock-free
/// counter bumped on every successful connect. The watchdog deliberately
/// does **not** read `tip_height()` because that takes a read on the same
/// `RwLock<ChainTip>` that `connect_block` writes — exactly the lock the
/// wedge we are protecting against could be holding. Reading an atomic
/// counter avoids that dependency entirely; whatever else is happening in
/// the runtime, this thread can always observe the heartbeat.
///
/// During IBD the heartbeat advances roughly every 100-500ms at 6 blk/s on
/// mainnet, so 5 minutes is conservative. Outside IBD the cadence is
/// per-block (≈10 min on mainnet) — operators who want the watchdog active
/// in steady-state should set a threshold well above one block interval.
pub fn spawn_stall_watchdog(
    chain_state: Arc<ChainState>,
    stall_threshold: Duration,
    abort_after: Duration,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    if stall_threshold.is_zero() {
        tracing::info!("Stall watchdog disabled (stall_threshold=0)");
        return;
    }
    std::thread::Builder::new()
        .name("stall-watchdog".into())
        .spawn(move || {
            tracing::info!(
                stall_threshold_secs = stall_threshold.as_secs(),
                abort_after_secs = abort_after.as_secs(),
                "Stall watchdog started"
            );
            let poll = Duration::from_secs(15);
            let mut last_seen_heartbeat = chain_state.connect_heartbeat();
            let mut last_advance = Instant::now();
            let mut dumped_for_this_stall = false;
            loop {
                std::thread::sleep(poll);
                if *shutdown_rx.borrow() {
                    tracing::info!("Stall watchdog shutting down");
                    return;
                }
                let heartbeat = chain_state.connect_heartbeat();
                if heartbeat != last_seen_heartbeat {
                    last_seen_heartbeat = heartbeat;
                    last_advance = Instant::now();
                    if dumped_for_this_stall {
                        tracing::info!(
                            heartbeat,
                            "Connector advanced after a previously-detected \
                             stall; watchdog returning to nominal state"
                        );
                        dumped_for_this_stall = false;
                    }
                    continue;
                }
                let stalled_for = last_advance.elapsed();
                if stalled_for >= stall_threshold && !dumped_for_this_stall {
                    capture_forensics(stalled_for, heartbeat, &chain_state);
                    dumped_for_this_stall = true;
                }
                if dumped_for_this_stall && stalled_for >= stall_threshold + abort_after {
                    tracing::error!(
                        stalled_secs = stalled_for.as_secs(),
                        heartbeat,
                        "Stall persists past abort deadline; calling \
                         std::process::abort() so systemd restarts the unit. \
                         Forensics dumped above."
                    );
                    // abort, not exit: skips destructors (we cannot trust
                    // that the wedged threads will release locks on Drop),
                    // produces a coredump if `ulimit -c` is set, and gives
                    // systemd a non-zero exit code regardless of how the
                    // unit's `SuccessExitStatus=` is configured.
                    std::process::abort();
                }
            }
        })
        .expect("failed to spawn stall-watchdog thread");
}

/// Spawn the periodic forced-compaction thread.
///
/// `interval` is how often we wake to check; `l0_compact_at` is the L0 file
/// count at or above which we force a compaction. Setting `interval` to
/// `Duration::ZERO` disables the thread entirely, which is what tests and
/// non-RocksDB backends should do.
///
/// Compaction is synchronous in the rocksdb FFI; this thread will block in
/// the call for as long as it takes. That is the point — running it on a
/// tokio worker would tie that worker up for the duration. Concurrent
/// connector writes are fine; RocksDB serializes them with the manual
/// compaction internally.
pub fn spawn_periodic_compactor(
    chain_state: Arc<ChainState>,
    interval: Duration,
    l0_compact_at: u64,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    if interval.is_zero() || l0_compact_at == 0 {
        tracing::info!("Periodic compactor disabled");
        return;
    }
    std::thread::Builder::new()
        .name("rocksdb-compactor".into())
        .spawn(move || {
            tracing::info!(
                interval_secs = interval.as_secs(),
                l0_compact_at,
                "Periodic forced-compaction thread started"
            );
            // Sleep in small slices so shutdown is responsive even when the
            // configured interval is long (e.g. 30 minutes).
            let slice = Duration::from_secs(5);
            loop {
                let mut waited = Duration::ZERO;
                while waited < interval {
                    std::thread::sleep(slice);
                    if *shutdown_rx.borrow() {
                        tracing::info!("Periodic compactor shutting down");
                        return;
                    }
                    waited += slice;
                }
                let l0 = chain_state.chainstate_l0_files();
                let pending = chain_state.chainstate_pending_compaction_bytes();
                if l0 < l0_compact_at {
                    tracing::debug!(
                        l0_files = l0,
                        threshold = l0_compact_at,
                        pending_compaction_bytes = pending,
                        "Periodic compactor: L0 below threshold, skipping"
                    );
                    continue;
                }
                tracing::info!(
                    l0_files = l0,
                    threshold = l0_compact_at,
                    pending_compaction_bytes = pending,
                    "Periodic compactor: L0 above threshold, forcing chainstate \
                     compaction"
                );
                let started = Instant::now();
                match chain_state.compact_chainstate() {
                    Ok(_) => {
                        let after_l0 = chain_state.chainstate_l0_files();
                        let after_pending = chain_state.chainstate_pending_compaction_bytes();
                        tracing::info!(
                            elapsed_secs = started.elapsed().as_secs(),
                            l0_before = l0,
                            l0_after = after_l0,
                            pending_before = pending,
                            pending_after = after_pending,
                            "Periodic compactor: chainstate compaction complete"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            elapsed_secs = started.elapsed().as_secs(),
                            "Periodic compactor: forced compaction failed"
                        );
                    }
                }
            }
        })
        .expect("failed to spawn rocksdb-compactor thread");
}

/// Best-effort post-mortem dump for a detected stall. We can't get full
/// userspace stacks without `gdb` (which the systemd unit's hardening
/// usually blocks via cleared `PR_SET_DUMPABLE`), but `/proc/self/task/*`
/// always works and gives us the per-thread kernel-side picture: name,
/// state, and the symbol the thread is parked on. The 2026-05 forensic
/// captured exactly this shape and made the diagnosis possible: 94 threads
/// all in `futex_do_wait` with zero in `R` or `D` state proved the wedge
/// was synchronization, not I/O.
fn capture_forensics(stalled_for: Duration, heartbeat: u64, chain_state: &ChainState) {
    let l0 = chain_state.chainstate_l0_files();
    let pending = chain_state.chainstate_pending_compaction_bytes();
    let dirty = chain_state.cache_dirty_count();
    tracing::error!(
        stalled_secs = stalled_for.as_secs(),
        heartbeat,
        chainstate_l0_files = l0,
        chainstate_pending_compaction_bytes = pending,
        coin_cache_dirty_count = dirty,
        "Stall watchdog: connector heartbeat has not advanced; capturing \
         thread states from /proc/self/task. Look for many threads in \
         `futex` for a synchronization deadlock; many in `D` for stuck I/O."
    );
    let task_dir = std::path::Path::new("/proc/self/task");
    let entries = match std::fs::read_dir(task_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "Stall watchdog: cannot read /proc/self/task");
            return;
        }
    };
    let mut count = 0;
    for entry in entries.flatten() {
        let tid = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        let comm = read_trim(&path.join("comm"));
        let wchan = read_trim(&path.join("wchan"));
        let state = read_state(&path.join("status"));
        tracing::error!(
            target: "stall_watchdog",
            tid = %tid,
            comm = %comm,
            state = %state,
            wchan = %wchan,
            "thread"
        );
        count += 1;
    }
    tracing::error!(threads_dumped = count, "Stall watchdog: forensics complete");
}

fn read_trim(path: &std::path::Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn read_state(status_path: &std::path::Path) -> String {
    std::fs::read_to_string(status_path)
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("State:"))
        .map(|l| l.trim_start_matches("State:").trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// Sanity-check the `/proc/self/task/*` reader: on any Linux test host
    /// the current process must have at least one task entry (itself), and
    /// reading it must produce a non-empty `comm` and a `State:` line. If
    /// this regresses (e.g. by accidentally moving to `/proc/<pid>/task`
    /// with a stale pid, or by trimming the state line wrong) the watchdog
    /// would emit empty diagnostic rows during a real stall — which is the
    /// failure mode this test exists to catch.
    #[test]
    fn forensics_reader_returns_self_thread_metadata() {
        let task_dir = Path::new("/proc/self/task");
        if !task_dir.exists() {
            eprintln!("skipping: /proc/self/task not available");
            return;
        }
        let mut found_any = false;
        for entry in std::fs::read_dir(task_dir).unwrap().flatten() {
            let comm = super::read_trim(&entry.path().join("comm"));
            let state = super::read_state(&entry.path().join("status"));
            assert!(!comm.is_empty(), "comm should be non-empty for tid={:?}", entry.file_name());
            assert!(!state.is_empty(), "state should be non-empty for tid={:?}", entry.file_name());
            // The first letter of state is the canonical short code (R, S, D, …).
            let code = state.chars().next().unwrap();
            assert!(
                matches!(code, 'R' | 'S' | 'D' | 'T' | 't' | 'X' | 'Z' | 'I'),
                "unexpected state code {:?} for tid={:?}",
                code,
                entry.file_name()
            );
            found_any = true;
        }
        assert!(found_any, "no /proc/self/task entries found — reader is broken");
    }
}
