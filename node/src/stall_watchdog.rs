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
//!   parked on what futex. It then attempts a graceful shutdown via
//!   `SIGTERM` (which the main task handles with its own bounded
//!   `--max-shutdown-secs` flush deadline) and only falls through to
//!   `std::process::abort()` if the graceful path is itself stuck.
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
/// the watchdog dumps thread states. `abort_after` is the additional grace
/// after the forensic dump before the watchdog forces process exit. During
/// that grace window the watchdog first attempts a graceful shutdown by
/// raising `SIGTERM` to itself; only if the process is still alive when
/// `abort_after` fully elapses does it fall through to `std::process::abort()`.
///
/// Why graceful-then-abort: RocksDB is crash-consistent and BulkLoad-mode
/// writes replay from the flat-file block store on next start, so a direct
/// abort would not corrupt the DB — but trying graceful first lets the
/// existing `--max-shutdown-secs`-bounded flush path stamp a clean-shutdown
/// marker and persist the post-last-checkpoint memtable. If the same lock
/// the wedge is holding also blocks graceful shutdown, that path runs into
/// its own bounded timeout and force-exits via `process::exit`, and the
/// watchdog's outer fence still fires if for some reason neither path
/// completes.
///
/// Progress is observed via two lock-free counters on [`ChainState`]:
///
/// * [`ChainState::connect_heartbeat`] — bumped on every successful
///   block connect. Reliable progress signal during IBD (≈6 blk/s on
///   mainnet) but silent for many minutes at tip between blocks.
/// * [`ChainState::manager_heartbeat`] — bumped on every iteration of
///   the P2P manager's main loop (~500 ms). Tracks "the loop is alive"
///   independent of whether a block was processed on this tick.
///
/// The watchdog resets its stall timer whenever *either* counter
/// advances, so a stall is only reported when **both** have been silent
/// for the full threshold. This keeps the 300 s default valid at
/// mainnet tip (where `connect_heartbeat` is naturally idle between
/// blocks) while still catching true wedges: a real lockup parks the
/// manager loop and the connector together, so neither counter moves.
///
/// The watchdog deliberately does **not** read `tip_height()` because
/// that takes a read on the same `RwLock<ChainTip>` that `connect_block`
/// writes — exactly the lock the wedge we are protecting against could
/// be holding. Reading atomic counters avoids that dependency entirely;
/// whatever else is happening in the runtime, this thread can always
/// observe the heartbeats.
///
/// During IBD both counters advance every few hundred milliseconds, so
/// 5 minutes is very conservative. At mainnet tip the connector
/// counter can pause for ≥10 min between blocks but the manager
/// counter keeps advancing, so the threshold remains valid without
/// per-phase tuning.
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
            let mut last_seen_connect = chain_state.connect_heartbeat();
            let mut last_seen_manager = chain_state.manager_heartbeat();
            let mut last_advance = Instant::now();
            let mut dumped_for_this_stall = false;
            let mut sigterm_sent = false;
            loop {
                std::thread::sleep(poll);
                if *shutdown_rx.borrow() {
                    tracing::info!("Stall watchdog shutting down");
                    return;
                }
                let connect_hb = chain_state.connect_heartbeat();
                let manager_hb = chain_state.manager_heartbeat();
                // Reset the stall timer if *either* heartbeat advanced.
                // At mainnet tip `connect_hb` can stay flat for >10 min
                // between blocks; `manager_hb` keeps ticking as long as
                // the P2P loop and tokio runtime are alive. A true
                // wedge parks both, which is what we want to detect.
                let advanced =
                    connect_hb != last_seen_connect || manager_hb != last_seen_manager;
                if advanced {
                    last_seen_connect = connect_hb;
                    last_seen_manager = manager_hb;
                    last_advance = Instant::now();
                    if dumped_for_this_stall {
                        tracing::info!(
                            connect_heartbeat = connect_hb,
                            manager_heartbeat = manager_hb,
                            "Heartbeats advanced after a previously-detected \
                             stall; watchdog returning to nominal state"
                        );
                        dumped_for_this_stall = false;
                        sigterm_sent = false;
                    }
                    continue;
                }
                let stalled_for = last_advance.elapsed();
                if stalled_for >= stall_threshold && !dumped_for_this_stall {
                    capture_forensics(stalled_for, connect_hb, manager_hb, &chain_state);
                    dumped_for_this_stall = true;
                }
                // First escalation: raise SIGTERM so the existing main()
                // shutdown path runs (which has its own bounded flush
                // deadline). Sending SIGTERM is idempotent in effect — we
                // gate it on `sigterm_sent` so a stuck graceful path
                // doesn't spam signals.
                if dumped_for_this_stall && !sigterm_sent && stalled_for >= stall_threshold {
                    tracing::error!(
                        stalled_secs = stalled_for.as_secs(),
                        connect_heartbeat = connect_hb,
                        manager_heartbeat = manager_hb,
                        "Stall watchdog: raising SIGTERM to attempt graceful \
                         shutdown via the bounded --max-shutdown-secs flush path. \
                         Will force-abort if the process is still alive after \
                         the abort_after grace window."
                    );
                    raise_sigterm();
                    sigterm_sent = true;
                }
                if dumped_for_this_stall && stalled_for >= stall_threshold + abort_after {
                    tracing::error!(
                        stalled_secs = stalled_for.as_secs(),
                        connect_heartbeat = connect_hb,
                        manager_heartbeat = manager_hb,
                        "Stall persists past abort deadline; calling \
                         std::process::abort() so systemd restarts the unit. \
                         Graceful shutdown via SIGTERM did not complete in time. \
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

/// Raise `SIGTERM` to our own process so the main shutdown path (which
/// already has a bounded `--max-shutdown-secs` flush+exit machinery) takes
/// over. We use the `libc` raw signal API rather than `nix::sys::signal`
/// to avoid a new dependency; `raise(3)` is async-signal-safe and well-
/// defined for self-signaling. A failure here is non-fatal — the watchdog
/// will fall through to `abort()` after the grace window — so we only log.
fn raise_sigterm() {
    // SAFETY: `libc::raise` is async-signal-safe and takes no pointer
    // arguments. The only failure mode is `EINVAL` for an unrecognized
    // signal number, which `SIGTERM` is not.
    let rc = unsafe { libc::raise(libc::SIGTERM) };
    if rc != 0 {
        tracing::error!(
            errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            "Stall watchdog: libc::raise(SIGTERM) failed; will rely on \
             outer abort fence"
        );
    }
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

/// Per-column-family pending-compaction diagnostic. Wakes every
/// `interval` (default 60s in `satd`) and emits one INFO line listing
/// the largest pending-compaction-bytes counts per CF.
///
/// This is the missing observability that turned a known failure mode
/// (LSM falling behind on the secondary indexes) into a silent
/// disk-fill: the existing compactor only reads `coins`, which stays
/// healthy throughout. Watching `addr_spending` / `addr_funding` /
/// `outpoint_spend` / `undo` is what would have surfaced the
/// 2026-05-13 incident hours earlier.
///
/// Runs on its own OS thread (matching `spawn_periodic_compactor`)
/// rather than a tokio task, so it survives the same wedge categories
/// that motivated the stall watchdog.
pub fn spawn_compaction_diagnostic(
    chain_state: Arc<ChainState>,
    interval: Duration,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    if interval.is_zero() {
        tracing::info!("Compaction diagnostic disabled");
        return;
    }
    std::thread::Builder::new()
        .name("rocksdb-diag".into())
        .spawn(move || {
            tracing::info!(
                interval_secs = interval.as_secs(),
                "Compaction diagnostic thread started"
            );
            let slice = Duration::from_secs(5);
            loop {
                let mut waited = Duration::ZERO;
                while waited < interval {
                    std::thread::sleep(slice);
                    if *shutdown_rx.borrow() {
                        tracing::info!("Compaction diagnostic shutting down");
                        return;
                    }
                    waited += slice;
                }
                let mut breakdown = chain_state.pending_compaction_bytes_by_cf();
                // Sort by pending bytes desc so the most-loaded CFs
                // appear first in the log line — even if downstream
                // tooling truncates, the signal stays visible.
                breakdown.sort_by(|a, b| b.1.cmp(&a.1));
                let total: u64 = breakdown.iter().map(|(_, b)| *b).sum();
                let mb = |b: u64| b / (1024 * 1024);
                // Render as a single key=value sequence per CF for
                // easy grep/awk parsing. Skip CFs with zero pending
                // to keep the line readable on healthy systems.
                let parts: Vec<String> = breakdown
                    .iter()
                    .filter(|(_, b)| *b > 0)
                    .map(|(name, b)| format!("{}={}M", name, mb(*b)))
                    .collect();
                let l0 = chain_state.chainstate_l0_files();
                tracing::info!(
                    target: "storage",
                    pending_total_mb = mb(total),
                    coins_l0_files = l0,
                    per_cf = %parts.join(" "),
                    "RocksDB pending-compaction snapshot"
                );
            }
        })
        .expect("failed to spawn rocksdb-diag thread");
}

/// Best-effort post-mortem dump for a detected stall. We can't get full
/// userspace stacks without `gdb` (which the systemd unit's hardening
/// usually blocks via cleared `PR_SET_DUMPABLE`), but `/proc/self/task/*`
/// always works and gives us the per-thread kernel-side picture: name,
/// state, and the symbol the thread is parked on. The 2026-05 forensic
/// captured exactly this shape and made the diagnosis possible: 94 threads
/// all in `futex_do_wait` with zero in `R` or `D` state proved the wedge
/// was synchronization, not I/O.
fn capture_forensics(
    stalled_for: Duration,
    connect_heartbeat: u64,
    manager_heartbeat: u64,
    chain_state: &ChainState,
) {
    let l0 = chain_state.chainstate_l0_files();
    let pending = chain_state.chainstate_pending_compaction_bytes();
    let dirty = chain_state.cache_dirty_count();
    tracing::error!(
        stalled_secs = stalled_for.as_secs(),
        connect_heartbeat,
        manager_heartbeat,
        chainstate_l0_files = l0,
        chainstate_pending_compaction_bytes = pending,
        coin_cache_dirty_count = dirty,
        "Stall watchdog: both connect and manager heartbeats have been \
         silent past the threshold; capturing thread states from \
         /proc/self/task. Look for many threads in `futex` for a \
         synchronization deadlock; many in `D` for stuck I/O."
    );

    // Phase-level forensics: the connect path stamps an atomic phase on
    // every major transition (`pre_resolve_coins`, `verify_dispatch`,
    // `verify_join`, `write_batch`, etc.). The phase with the smallest
    // entered_age_ms relative to *now* is the phase the connector is
    // currently wedged in. Per-phase entry counts are a built-in profile
    // of where the connector spends iterations during normal operation,
    // and on a stalled iteration tell us how far it progressed before
    // wedging.
    let phases = chain_state.connect_phases();
    let current = phases.current();
    let age_ms = phases.entered_age_ms();
    let counts = phases.snapshot_counts();
    tracing::error!(
        phase = current.as_str(),
        phase_age_ms = age_ms,
        "Stall watchdog: connector phase at moment of stall — the connector \
         is wedged inside this phase, see per-phase counts below for what \
         was reached during normal operation."
    );
    for (i, &count) in counts
        .iter()
        .enumerate()
        .take(crate::chain::connect_phase::ConnectPhase::COUNT)
    {
        let phase = crate::chain::connect_phase::ConnectPhase::from_index(i);
        tracing::error!(
            target: "stall_watchdog",
            phase = phase.as_str(),
            count,
            "Stall watchdog: phase entry count since startup"
        );
    }
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
    /// at least one task entry must produce a readable `comm` and a
    /// well-formed `State:` line.
    ///
    /// We don't assert per-entry invariants because threads in this test
    /// process can exit between the `read_dir` enumeration and the per-tid
    /// `comm` / `status` reads — a real race when the broader test suite
    /// runs concurrently. The watchdog tolerates this in production (it
    /// just logs an empty row for the dead thread), so the test does the
    /// same: skip entries whose reads come back empty, and fail only if
    /// *no* entry was readable at all (which would indicate the reader
    /// itself regressed — e.g. accidentally pointing at a stale pid or
    /// trimming the State line wrong).
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
            if comm.is_empty() || state.is_empty() {
                // Thread exited between read_dir and our per-tid reads;
                // the production watchdog tolerates this same race.
                continue;
            }
            // First letter of state is the canonical short code (R, S, D, …).
            let code = state.chars().next().unwrap();
            assert!(
                matches!(code, 'R' | 'S' | 'D' | 'T' | 't' | 'X' | 'Z' | 'I'),
                "unexpected state code {:?} for tid={:?}",
                code,
                entry.file_name()
            );
            found_any = true;
        }
        assert!(found_any, "no readable /proc/self/task entries — reader is broken");
    }
}
