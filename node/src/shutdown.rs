//! Clean-shutdown marker: a single file whose presence at startup indicates
//! the previous process exited after a successful coin-cache flush.
//!
//! The marker is a pure operator-facing signal. Even when it is absent, the
//! node recovers correctly via the existing `DataStored → Valid` replay path
//! in the IBD connect loop — so no durability logic depends on it. What the
//! marker buys us is:
//!
//! - Visibility: `getsysteminfo` and the TUI can tell the operator whether
//!   the last shutdown was clean, surfacing dirty-shutdown cases that might
//!   otherwise go unnoticed on slow hardware (Umbrel, Pi).
//! - A foothold for future optimizations (e.g. skipping scans that only
//!   matter after a dirty exit).
//!
//! The marker contains a small JSON payload with the observed tip hash,
//! tip height, and shutdown timestamp. The contents are advisory — if the
//! file is malformed we treat it as "not present" and log a warning.
//!
//! The module also holds what the end of a shutdown needs to stop the
//! node's own threads before the process exits ([`ThreadStop`],
//! [`join_within`]) and to exit without running C++ static destructors
//! underneath any thread that is still running ([`exit_now`]).

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::storage::StoreError;

/// Outcome of awaiting a bounded shutdown flush. The main binary uses this
/// to decide whether to write the clean-shutdown marker, log an error, or
/// force-exit with [`exit_now`] — the only way to actually honor
/// `--max-shutdown-secs` when the flush is stuck inside a blocking FFI call
/// that tokio cannot abort.
#[derive(Debug, PartialEq, Eq)]
pub enum BoundedFlushOutcome {
    /// Flush completed successfully within the deadline; marker may be written.
    Clean,
    /// Flush ran to completion but returned an error; no marker.
    FlushError(String),
    /// The oneshot sender was dropped before signalling (thread panic?).
    ChannelDropped,
    /// Flush exceeded the deadline. Caller MUST force the process to exit —
    /// the underlying `spawn_blocking` or `std::thread` task cannot be
    /// aborted, so any normal return would let the runtime wait for it.
    TimedOut,
}

/// Await a flush completion signal with a hard deadline.
///
/// Extracted so unit tests can exercise the timeout arbitration logic
/// without needing a running satd. The main binary wires the sender side
/// to a dedicated `std::thread` that calls `flush_coin_cache`.
pub async fn await_bounded_flush(
    flush_rx: tokio::sync::oneshot::Receiver<Result<(), StoreError>>,
    deadline: Duration,
) -> BoundedFlushOutcome {
    match tokio::time::timeout(deadline, flush_rx).await {
        Ok(Ok(Ok(()))) => BoundedFlushOutcome::Clean,
        Ok(Ok(Err(e))) => BoundedFlushOutcome::FlushError(e.to_string()),
        Ok(Err(_)) => BoundedFlushOutcome::ChannelDropped,
        Err(_) => BoundedFlushOutcome::TimedOut,
    }
}

/// A stop request that an OS thread sleeps on.
///
/// A thread that polls a flag between `thread::sleep` calls notices a stop
/// only when its sleep ends, 15 s later for the stall watchdog, which can be
/// after the process has begun to exit. [`ThreadStop::sleep`] returns as soon
/// as [`ThreadStop::stop`] is called, so the thread can be joined straight
/// away.
#[derive(Clone, Default)]
pub struct ThreadStop(std::sync::Arc<(parking_lot::Mutex<bool>, parking_lot::Condvar)>);

impl ThreadStop {
    /// Ask every thread sleeping on this, or on a clone of it, to stop.
    pub fn stop(&self) {
        let (lock, cvar) = &*self.0;
        *lock.lock() = true;
        cvar.notify_all();
    }

    /// Whether [`stop`](Self::stop) has been called.
    pub fn is_stopped(&self) -> bool {
        *self.0.0.lock()
    }

    /// Sleep for `duration`, or until a stop is requested. Returns `true` if
    /// a stop was requested, before or during the sleep.
    pub fn sleep(&self, duration: Duration) -> bool {
        let (lock, cvar) = &*self.0;
        let mut stopped = lock.lock();
        if !*stopped {
            let _ = cvar.wait_while_for(&mut stopped, |stopped| !*stopped, duration);
        }
        *stopped
    }
}

/// A named thread, as [`join_within`] takes and returns them.
pub type NamedThread = (&'static str, std::thread::JoinHandle<()>);

/// Join `threads`, waiting at most `timeout` for them to finish. Returns the
/// threads still running at the deadline, unjoined. A thread that panicked
/// counts as finished, and its name is logged.
pub fn join_within(threads: Vec<NamedThread>, timeout: Duration) -> Vec<NamedThread> {
    let deadline = std::time::Instant::now() + timeout;
    let mut running = threads;
    loop {
        let (finished, still): (Vec<_>, Vec<_>) =
            running.into_iter().partition(|(_, handle)| handle.is_finished());
        for (name, handle) in finished {
            if handle.join().is_err() {
                tracing::error!(thread = name, "thread panicked before shutdown joined it");
            }
        }
        running = still;
        if running.is_empty() || std::time::Instant::now() >= deadline {
            return running;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// End the process now with `code`, without running `atexit` handlers or C++
/// static destructors.
///
/// Returning from `main` and `std::process::exit` both end in libc's
/// `exit()`, which destroys every C++ static, RocksDB's among them: its
/// option-type maps and the ZSTD decompression-context cache. A thread still
/// inside RocksDB at that moment uses freed memory, and a node that had shut
/// down cleanly died of SIGSEGV after logging `satd stopped` (#868, #37).
/// `_exit` skips the destructors. Nothing satd relies on at exit lives in
/// them: logs go to stdout and stderr, both flushed here, and a clean
/// shutdown flushes the chainstate before calling this.
pub fn exit_now(code: i32) -> ! {
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    // SAFETY: `_exit` takes no pointers, cannot fail and does not return.
    unsafe { libc::_exit(code) }
}

/// Run `f`; if it panics, end the process with [`exit_now`] and the exit
/// code of an unhandled panic (101).
///
/// A panic that unwound out of `main` would drop the runtime, which waits
/// without limit for blocking tasks, and then end the process through
/// libc's `exit()`, under the node's threads (#868). The panic hook has
/// already reported the panic by the time this exits.
pub fn exit_now_on_panic<T>(f: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_) => exit_now(101),
    }
}

/// A stop asked for, by SIGTERM or SIGINT, while the node is still starting
/// up (#907).
///
/// The running node's own handler takes those signals only once startup has
/// finished, and startup includes the block replays of `-reindex`,
/// `-reindex-chainstate` and `-upgradechainstate`, which run for hours or
/// days. `satd` registers the signals as it starts instead, and records a
/// request here. A replay polls [`StartupStop::is_requested`] between blocks
/// and while it connects one, abandons the block in progress, and stops at
/// the last block it connected, flushed. Every other part of startup
/// ends the process at once, as it did before satd handled the signals.
///
/// Clones share one state.
#[derive(Clone, Default)]
pub struct StartupStop(std::sync::Arc<parking_lot::Mutex<StartupStopState>>);

#[derive(Default)]
struct StartupStopState {
    requested: bool,
    replaying: bool,
    finished: bool,
    /// Test seam: the poll of [`StartupStop::is_requested`] that requests a
    /// stop, so a test can stop a replay at a chosen block.
    #[cfg(test)]
    request_on_poll: Option<u64>,
    #[cfg(test)]
    polls: u64,
}

/// What [`StartupStop::request`] found running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopRequest {
    /// A replay is running, and stops at the last block it connected.
    ReplayStops,
    /// Nothing running can stop part-way: end the process now.
    ExitNow,
    /// Startup is over; the running node's own handler has the signal.
    StartupFinished,
}

impl StartupStop {
    /// Record a stop request, and say who acts on it.
    pub fn request(&self) -> StopRequest {
        let mut s = self.0.lock();
        if s.finished {
            return StopRequest::StartupFinished;
        }
        s.requested = true;
        if s.replaying {
            StopRequest::ReplayStops
        } else {
            StopRequest::ExitNow
        }
    }

    /// Whether a stop has been requested. A replay polls this between blocks.
    pub fn is_requested(&self) -> bool {
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut s = self.0.lock();
        #[cfg(test)]
        {
            s.polls += 1;
            if s.request_on_poll == Some(s.polls) {
                s.requested = true;
            }
        }
        s.requested
    }

    /// A replay that polls [`Self::is_requested`] is starting. From here
    /// until [`Self::end_replay`], a request leaves the stop to it.
    pub fn begin_replay(&self) {
        self.0.lock().replaying = true;
    }

    /// The replay has returned. Returns whether a stop was requested, before
    /// or during it: the caller then ends startup itself, since a request
    /// that arrived after the replay's last poll was left to it.
    pub fn end_replay(&self) -> bool {
        let mut s = self.0.lock();
        s.replaying = false;
        s.requested
    }

    /// Startup is over. Later requests are the running node's.
    pub fn finish(&self) {
        self.0.lock().finished = true;
    }

    /// Request a stop on the `n`th poll of [`Self::is_requested`], counting
    /// from 1.
    #[cfg(test)]
    pub(crate) fn request_on_poll(&self, n: u64) {
        let mut s = self.0.lock();
        s.request_on_poll = Some(n);
        s.polls = 0;
    }
}

/// End the process the way the default action of `signal` (SIGTERM or
/// SIGINT) would have, for a stop requested in a part of startup that cannot
/// stop part-way.
///
/// Before #907 such a signal killed the process at once, and a supervisor
/// treats death by SIGTERM as a clean stop, so the default action is
/// restored and the signal raised again. PID 1 of a PID namespace ignores a
/// signal whose action is the default, which is how a containerised replay
/// used to run until its SIGKILL. There the raise returns, and the process
/// exits with the status a shell reports for death by the signal, 128 plus
/// its number.
pub fn exit_by_signal(signal: libc::c_int) -> ! {
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    // SAFETY: restoring a signal's default action and raising it take no
    // pointers; neither can leave the process in an unsound state.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
    exit_now(128 + signal)
}

/// Filename of the marker inside the network datadir.
pub const MARKER_FILENAME: &str = ".clean_shutdown";

/// Payload written into the marker. All fields are advisory. Missing or
/// malformed fields are tolerated — the marker's *presence* is the signal.
#[derive(Debug, Clone)]
pub struct CleanShutdownRecord {
    pub tip_hash: String,
    pub tip_height: u32,
    pub shutdown_unix_secs: u64,
}

/// Return the marker path for a given network-scoped datadir.
pub fn marker_path(net_datadir: &Path) -> PathBuf {
    net_datadir.join(MARKER_FILENAME)
}

/// Called once at startup, before opening the chain database.
///
/// If a marker exists we unlink it and return its parsed contents. The
/// unlink happens *before* any mutable work, so a crash during startup
/// leaves us correctly detecting "dirty" on the next run.
pub fn consume_marker(net_datadir: &Path) -> Option<CleanShutdownRecord> {
    let path = marker_path(net_datadir);
    let contents = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(?path, error = %e, "Could not read clean-shutdown marker; treating as dirty");
            let _ = fs::remove_file(&path);
            return None;
        }
    };

    // Best-effort unlink. We proceed with whatever we read even if unlink
    // fails — worst case we'll re-read the same contents next run.
    if let Err(e) = fs::remove_file(&path) {
        tracing::warn!(?path, error = %e, "Could not unlink clean-shutdown marker");
    }

    match parse_record(&contents) {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Clean-shutdown marker malformed; treating as dirty (marker unlinked)"
            );
            None
        }
    }
}

/// Called at the end of graceful shutdown, *after* `flush_coin_cache` +
/// `flush_durable` have succeeded within the configured timeout. Writes a
/// small JSON record atomically (write-tmp + rename).
pub fn write_marker(net_datadir: &Path, tip_hash: &str, tip_height: u32) -> io::Result<()> {
    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = format!(
        "{{\"tip_hash\":\"{}\",\"tip_height\":{},\"shutdown_unix_secs\":{}}}\n",
        tip_hash, tip_height, unix_secs
    );
    let final_path = marker_path(net_datadir);
    let tmp_path = final_path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

fn parse_record(s: &str) -> Result<CleanShutdownRecord, String> {
    // Deliberately no serde dependency — the fields are simple and the
    // forward-compat story is "ignore unknown, fall back to defaults".
    let trimmed = s.trim();
    let inner = trimmed
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| "not a JSON object".to_string())?;
    let mut tip_hash: Option<String> = None;
    let mut tip_height: Option<u32> = None;
    let mut shutdown_unix_secs: Option<u64> = None;
    for field in inner.split(',') {
        let (k, v) = field
            .split_once(':')
            .ok_or_else(|| format!("malformed field: {field}"))?;
        let k = k.trim().trim_matches('"');
        let v = v.trim();
        match k {
            "tip_hash" => tip_hash = Some(v.trim_matches('"').to_string()),
            "tip_height" => tip_height = v.parse().ok(),
            "shutdown_unix_secs" => shutdown_unix_secs = v.parse().ok(),
            _ => {}
        }
    }
    Ok(CleanShutdownRecord {
        tip_hash: tip_hash.unwrap_or_default(),
        tip_height: tip_height.unwrap_or(0),
        shutdown_unix_secs: shutdown_unix_secs.unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "satd-shutdown-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// #907. Outside a replay a stop ends the process; inside one it is left
    /// to the replay, which `end_replay` then reports; once startup has
    /// finished it is the running node's, and is not recorded here.
    #[test]
    fn a_startup_stop_goes_to_whoever_can_act_on_it() {
        let stop = StartupStop::default();
        assert!(!stop.is_requested());
        assert_eq!(stop.request(), StopRequest::ExitNow);
        assert!(stop.is_requested());

        let stop = StartupStop::default();
        stop.begin_replay();
        assert!(!stop.end_replay(), "no request, nothing to report");
        stop.begin_replay();
        assert_eq!(stop.request(), StopRequest::ReplayStops);
        assert_eq!(stop.request(), StopRequest::ReplayStops, "a second request changes nothing");
        assert!(stop.is_requested(), "the replay sees it");
        assert!(stop.end_replay(), "and so does its caller");
        assert_eq!(stop.request(), StopRequest::ExitNow, "after the replay, startup exits");

        let stop = StartupStop::default();
        stop.finish();
        assert_eq!(stop.request(), StopRequest::StartupFinished);
        assert!(!stop.is_requested(), "the running node's stop is not recorded here");
    }

    /// The clones a replay and the signal watcher hold are one stop.
    #[test]
    fn startup_stop_clones_share_one_state() {
        let stop = StartupStop::default();
        let replay = stop.clone();
        stop.begin_replay();
        assert_eq!(stop.request(), StopRequest::ReplayStops);
        assert!(replay.is_requested());
    }

    #[test]
    fn consume_returns_none_when_missing() {
        let dir = tempdir();
        assert!(consume_marker(&dir).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_then_consume_roundtrips_fields() {
        let dir = tempdir();
        write_marker(&dir, "abc123", 1234).unwrap();
        assert!(marker_path(&dir).exists());
        let rec = consume_marker(&dir).unwrap();
        assert_eq!(rec.tip_hash, "abc123");
        assert_eq!(rec.tip_height, 1234);
        // Marker should be unlinked after consumption.
        assert!(!marker_path(&dir).exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn consume_unlinks_even_when_malformed() {
        let dir = tempdir();
        fs::write(marker_path(&dir), b"this is not json").unwrap();
        assert!(consume_marker(&dir).is_none());
        assert!(
            !marker_path(&dir).exists(),
            "malformed marker must be unlinked"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_overwrites_existing_marker_atomically() {
        let dir = tempdir();
        write_marker(&dir, "first", 1).unwrap();
        write_marker(&dir, "second", 2).unwrap();
        // No stale .tmp file left behind.
        assert!(!marker_path(&dir).with_extension("tmp").exists());
        let rec = consume_marker(&dir).unwrap();
        assert_eq!(rec.tip_hash, "second");
        assert_eq!(rec.tip_height, 2);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_record_tolerates_unknown_fields() {
        let rec = parse_record(
            r#"{"tip_hash":"x","tip_height":42,"shutdown_unix_secs":99,"future_field":123}"#,
        )
        .unwrap();
        assert_eq!(rec.tip_hash, "x");
        assert_eq!(rec.tip_height, 42);
        assert_eq!(rec.shutdown_unix_secs, 99);
    }

    // ----------------------------------------------------------------
    // await_bounded_flush — exercises the timeout arbitration logic so
    // we can prove the TimedOut branch fires when a flush doesn't
    // complete in time. The main binary translates TimedOut into
    // std::process::exit(1), which is what actually bounds shutdown.
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn bounded_flush_clean_on_immediate_ok() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tx.send(Ok(())).unwrap();
        let outcome = await_bounded_flush(rx, Duration::from_secs(5)).await;
        assert_eq!(outcome, BoundedFlushOutcome::Clean);
    }

    #[tokio::test]
    async fn bounded_flush_surfaces_flush_error() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tx.send(Err(crate::storage::StoreError::Database("boom".into())))
            .unwrap();
        let outcome = await_bounded_flush(rx, Duration::from_secs(5)).await;
        match outcome {
            BoundedFlushOutcome::FlushError(msg) => assert!(msg.contains("boom")),
            other => panic!("expected FlushError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn bounded_flush_channel_dropped_when_sender_gone() {
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), StoreError>>();
        drop(tx);
        let outcome = await_bounded_flush(rx, Duration::from_secs(5)).await;
        assert_eq!(outcome, BoundedFlushOutcome::ChannelDropped);
    }

    #[tokio::test]
    async fn bounded_flush_times_out_when_sender_is_slow() {
        // Keep the sender alive but never signal. The deadline should fire
        // and the outcome must be TimedOut — which the main binary reacts
        // to by calling `exit_now(1)`, the actual enforcement of
        // --max-shutdown-secs.
        let (_tx_kept_alive, rx) = tokio::sync::oneshot::channel::<Result<(), StoreError>>();
        let t0 = std::time::Instant::now();
        let outcome = await_bounded_flush(rx, Duration::from_millis(50)).await;
        let elapsed = t0.elapsed();
        assert_eq!(outcome, BoundedFlushOutcome::TimedOut);
        // Deadline must have been honored (within a generous slack for CI
        // scheduling jitter).
        assert!(
            elapsed < Duration::from_millis(500),
            "timeout should fire quickly; elapsed={:?}",
            elapsed
        );
    }

    /// A stop ends a sleep that has already started, which is what lets
    /// shutdown join a thread straight away instead of after its interval.
    ///
    /// Perturbation: sleep with `std::thread::sleep` and only then check the
    /// flag, and the sleeper takes the full hour.
    #[test]
    fn a_stop_ends_a_sleep_in_progress() {
        let stop = ThreadStop::default();
        let (woke_tx, woke_rx) = std::sync::mpsc::channel();
        let sleeper = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let _ = woke_tx.send(stop.sleep(Duration::from_secs(3600)));
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        stop.stop();
        assert_eq!(
            woke_rx.recv_timeout(Duration::from_secs(5)),
            Ok(true),
            "the sleeper must wake on the stop and report it"
        );
        sleeper.join().unwrap();
        assert!(stop.is_stopped());
        assert!(
            stop.sleep(Duration::from_secs(3600)),
            "a sleep after the stop returns at once"
        );
    }

    #[test]
    fn a_sleep_without_a_stop_runs_its_length() {
        let stop = ThreadStop::default();
        let t0 = std::time::Instant::now();
        assert!(!stop.sleep(Duration::from_millis(50)));
        assert!(t0.elapsed() >= Duration::from_millis(50));
    }

    /// `join_within` names what is still running at the deadline, and does
    /// not wait for it past the deadline.
    #[test]
    fn join_within_names_the_threads_still_running() {
        let stop = ThreadStop::default();
        let quick = std::thread::spawn(|| {});
        let slow = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                stop.sleep(Duration::from_secs(3600));
            })
        };
        let t0 = std::time::Instant::now();
        let left = join_within(
            vec![("quick", quick), ("slow", slow)],
            Duration::from_millis(200),
        );
        let names: Vec<_> = left.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, vec!["slow"]);
        assert!(t0.elapsed() < Duration::from_secs(5));
        stop.stop();
        assert!(join_within(left, Duration::from_secs(5)).is_empty());
    }

    /// A thread that panicked has finished: it is joined, not reported as
    /// still running.
    #[test]
    fn join_within_counts_a_panicked_thread_as_finished() {
        let panicked = std::thread::spawn(|| panic!("expected by the test"));
        let left = join_within(vec![("panicked", panicked)], Duration::from_secs(5));
        assert!(left.is_empty());
    }

    /// Set by the exit tests below when they re-run this test binary as a
    /// child process; names the way the child ends.
    const EXIT_PROBE: &str = "SATD_EXIT_PROBE";
    const EXIT_HANDLERS_RAN: &str = "exit handlers ran";

    /// The child half of the exit tests, and a no-op in an ordinary run. It
    /// registers an `atexit` handler, which libc's `exit()` runs from the
    /// same list as the C++ static destructors, then ends the process the
    /// way `EXIT_PROBE` names.
    #[test]
    fn exit_probe_child() {
        let Ok(how) = std::env::var(EXIT_PROBE) else {
            return;
        };
        extern "C" fn announce() {
            let line = format!("{EXIT_HANDLERS_RAN}\n");
            // SAFETY: writes a live buffer of the given length to stdout.
            unsafe { libc::write(1, line.as_ptr().cast(), line.len()) };
        }
        // SAFETY: registers a plain `extern "C"` function.
        assert_eq!(unsafe { libc::atexit(announce) }, 0);
        match how.as_str() {
            // SAFETY: ends the process; nothing here outlives it. The one
            // `exit()` satd's `the_node_never_exits_through_libc_exit` allows.
            "exit" => unsafe { libc::exit(3) }, // exit-guard: allowed
            "exit_now" => exit_now(3),
            "panic" => exit_now_on_panic(|| panic!("expected by the test")),
            other => panic!("unknown exit probe {other}"),
        }
    }

    /// Run [`exit_probe_child`] in a child process; its exit code, and
    /// whether its exit handlers ran.
    fn run_exit_probe(how: &str) -> (Option<i32>, bool) {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["shutdown::tests::exit_probe_child", "--exact", "--nocapture"])
            .env(EXIT_PROBE, how)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        (out.status.code(), stdout.contains(EXIT_HANDLERS_RAN))
    }

    /// The control for the two tests below: libc's `exit()` runs the
    /// handlers, so their absence there means something.
    #[test]
    fn exit_runs_the_exit_handlers() {
        assert_eq!(run_exit_probe("exit"), (Some(3), true));
    }

    #[test]
    fn exit_now_skips_the_exit_handlers() {
        assert_eq!(run_exit_probe("exit_now"), (Some(3), false));
    }

    #[test]
    fn a_panic_exits_now_with_the_panic_exit_code() {
        assert_eq!(run_exit_probe("panic"), (Some(101), false));
    }
}
