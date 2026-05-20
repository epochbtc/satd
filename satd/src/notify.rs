//! Service-manager lifecycle notifications.
//!
//! Wraps the systemd `sd_notify(3)` protocol so satd can tell systemd what
//! state it's in (loading, ready, stopping) and prevent the unit from being
//! killed during long-running startup phases like reindex.
//!
//! ## Why this is non-trivial
//!
//! systemd's default `TimeoutStartSec=90s` will SIGKILL a `Type=notify` unit
//! that hasn't sent `READY=1` within the budget. Reindex on a fully-synced
//! mainnet node runs for hours. Static `TimeoutStartSec=infinity` is the
//! crude fix; the right fix is `EXTEND_TIMEOUT_USEC=N` heartbeats: each
//! message tells systemd "we're alive, give us another N microseconds." The
//! heartbeat IS the liveness check — if satd goes silent for >N usec, the
//! unit gets killed (correctly, since it's stuck).
//!
//! See `man 5 systemd.service` and `man 3 sd_notify`.
//!
//! ## Behaviour on non-systemd hosts
//!
//! `sd_notify` looks at the `NOTIFY_SOCKET` env var, set by systemd before
//! exec'ing the service. On macOS, OpenRC, runit, plain shell, etc. the
//! variable is absent and every notify call short-circuits to `Ok(())`. The
//! heartbeat task still runs but writes nothing — cheap (one atomic load
//! per 30s tick).

use std::sync::Arc;
use std::time::Duration;

use node::startup_progress::StartupProgress;
use sd_notify::NotifyState;
use tokio::sync::oneshot;

/// Heartbeat cadence. Picked so it sits comfortably below the
/// `EXTEND_TIMEOUT_USEC` window we ask for (120s) — 4× headroom keeps the
/// unit alive across a single dropped tick (long GC pause, brief
/// scheduler stall).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Each heartbeat asks systemd to extend the start timeout by this many
/// microseconds from receipt time. 120 seconds at 30s heartbeat cadence
/// = 4× safety margin.
const EXTEND_TIMEOUT_USEC: u64 = 120_000_000;

/// Spawn the startup heartbeat task.
///
/// The task ticks every [`HEARTBEAT_INTERVAL`], reads the current snapshot
/// from `progress`, formats a `STATUS=...` line, and sends both `STATUS`
/// and `EXTEND_TIMEOUT_USEC=...` via sd_notify. It exits when `stop_rx`
/// is dropped or signalled — call sites send the signal once they've
/// emitted [`notify_ready`].
///
/// Panics: never. All sd_notify failures are logged at WARN and swallowed
/// so a transient socket error can't take down the process. We'd rather
/// systemd time us out (and surface the underlying issue) than abort
/// satd because the notify socket vanished.
pub fn spawn_startup_heartbeat(
    progress: Arc<StartupProgress>,
    stop_rx: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    spawn_startup_heartbeat_with_interval(progress, stop_rx, HEARTBEAT_INTERVAL)
}

/// Same as [`spawn_startup_heartbeat`] but with a caller-supplied tick
/// interval. Public-in-crate so tests can drive the loop on millisecond
/// cadences without waiting 30 real seconds.
pub(crate) fn spawn_startup_heartbeat_with_interval(
    progress: Arc<StartupProgress>,
    stop_rx: oneshot::Receiver<()>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate first tick; satd has just started and the
        // initial STATUS line was already emitted by `notify_status` at
        // the top of main().
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;

        let mut stop_rx = stop_rx;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let snap = progress.snapshot();
                    let status = format_status(&snap);
                    let extend = format!("EXTEND_TIMEOUT_USEC={EXTEND_TIMEOUT_USEC}");
                    let states = [
                        NotifyState::Status(&status),
                        NotifyState::Custom(&extend),
                    ];
                    if let Err(e) = sd_notify::notify(&states) {
                        tracing::warn!(error = %e, "sd_notify heartbeat failed");
                    }
                }
                _ = &mut stop_rx => {
                    return;
                }
            }
        }
    })
}

/// Format a one-line `STATUS=...` value from a startup snapshot. Includes
/// progress fraction when totals are known so `systemctl status satd`
/// shows live reindex progress.
fn format_status(snap: &node::startup_progress::StartupSnapshot) -> String {
    if snap.total > 0 {
        let pct = (snap.current as f64 / snap.total as f64 * 100.0) as u32;
        format!(
            "{} ({}/{}, {}%)",
            snap.message, snap.current, snap.total, pct
        )
    } else {
        snap.message.clone()
    }
}

/// Push a one-shot `STATUS=...` line. Use for short-lived state changes
/// outside the heartbeat path (e.g. "Listeners bound, finalizing init"
/// just before [`notify_ready`]).
pub fn notify_status(message: &str) {
    if let Err(e) = sd_notify::notify(&[NotifyState::Status(message)]) {
        tracing::warn!(error = %e, "sd_notify STATUS failed");
    }
}

/// Tell systemd the service is ready to handle requests. After this
/// returns, the `Type=notify` unit transitions to `active (running)` and
/// dependent units start.
///
/// Call exactly once, after every listener is bound.
pub fn notify_ready() {
    if let Err(e) = sd_notify::notify(&[
        NotifyState::Ready,
        NotifyState::Status("Ready"),
    ]) {
        tracing::warn!(error = %e, "sd_notify READY failed");
    }
}

/// Subsystem health probe consumed by the watchdog heartbeat. Returning
/// false on any tick suppresses that tick's `WATCHDOG=1` send; if
/// suppression persists past the unit's `WatchdogSec=`, systemd kills
/// the unit and `Restart=always` brings us back. Implementations MUST
/// be non-blocking — the watchdog tick runs on the tokio runtime and a
/// slow probe inflates the tick interval enough to miss the deadline
/// even when the underlying subsystem is fine.
pub trait WatchdogProbe: Send + Sync + 'static {
    /// True when the subsystem is healthy enough to advertise liveness.
    /// Must not block.
    fn healthy(&self) -> bool;
    /// Short identifier (e.g. "chainstate") used in suppression-log
    /// lines. Keep stable — operators grep for it.
    fn name(&self) -> &'static str;
}

/// Spawn the post-ready watchdog heartbeat.
///
/// Reads `WATCHDOG_USEC` from the environment (systemd sets this when
/// `WatchdogSec=` is configured in the unit) and ticks at half that
/// interval. Each tick polls every probe — any `healthy() == false`
/// suppresses the tick and logs a single WARN naming the failing
/// probe. When all probes report healthy, sends `WATCHDOG=1` via
/// sd_notify.
///
/// If `WATCHDOG_USEC` is unset (non-systemd host, or the unit doesn't
/// configure `WatchdogSec=`), the spawned task is a no-op that just
/// drains `stop_rx` so the caller's send doesn't dangle. Same binary
/// works under OpenRC, runit, macOS, plain shell.
///
/// Cancel via `stop_rx` during shutdown, BEFORE [`notify_stopping`],
/// so a final missed tick doesn't race the unit transitioning to
/// `deactivating`.
pub fn spawn_watchdog_heartbeat(
    probes: Vec<Box<dyn WatchdogProbe>>,
    stop_rx: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let Some(usec) = read_watchdog_usec() else {
        // No watchdog configured. Spawn a no-op drain so the caller's
        // stop send doesn't panic on a missing receiver.
        return tokio::spawn(async move {
            let _ = stop_rx.await;
        });
    };
    let tick = Duration::from_micros(usec / 2);
    spawn_watchdog_heartbeat_with_interval(probes, stop_rx, tick)
}

/// Same as [`spawn_watchdog_heartbeat`] but with a caller-supplied tick
/// interval (bypassing the `WATCHDOG_USEC` lookup). Public-in-crate so
/// tests don't depend on systemd-managed env vars; production callers
/// use the public function.
pub(crate) fn spawn_watchdog_heartbeat_with_interval(
    probes: Vec<Box<dyn WatchdogProbe>>,
    stop_rx: oneshot::Receiver<()>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Delay (not Burst) — under a runtime stall, the default Burst
        // would fire many WATCHDOG=1 in rapid succession on recovery,
        // briefly masking a real subsequent stall. Skip the missed
        // ticks and resume cadence from now.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick — gives subsystems a moment to
        // settle after notify_ready before the first probe.
        ticker.tick().await;

        let mut stop_rx = stop_rx;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let mut unhealthy: Option<&'static str> = None;
                    for probe in &probes {
                        if !probe.healthy() {
                            unhealthy = Some(probe.name());
                            break;
                        }
                    }
                    if let Some(name) = unhealthy {
                        tracing::warn!(
                            subsystem = name,
                            "watchdog tick suppressed — subsystem reports unhealthy"
                        );
                    } else if let Err(e) =
                        sd_notify::notify(&[NotifyState::Watchdog])
                    {
                        tracing::warn!(error = %e, "sd_notify WATCHDOG=1 failed");
                    }
                }
                _ = &mut stop_rx => {
                    return;
                }
            }
        }
    })
}

/// Parse `WATCHDOG_USEC` from the environment. systemd sets it when
/// `WatchdogSec=` is configured; absent or zero means there's no
/// watchdog to feed. Per `sd_watchdog_enabled(3)`, `WATCHDOG_PID` (if
/// set) must match our PID — otherwise the env vars belong to a parent
/// and we ignore them. Matches libsystemd's reference behavior.
fn read_watchdog_usec() -> Option<u64> {
    let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    if usec == 0 {
        return None;
    }
    if let Ok(pid_str) = std::env::var("WATCHDOG_PID") {
        let want_pid: u32 = pid_str.parse().ok()?;
        if want_pid != std::process::id() {
            return None;
        }
    }
    Some(usec)
}

/// Tell systemd we're shutting down. Lets the unit transition to
/// `deactivating` immediately rather than waiting for the process to
/// actually exit, which gives operators accurate state in
/// `systemctl status` during the (potentially long) RocksDB flush.
///
/// Call once, as the very first thing on receipt of SIGTERM / Ctrl-C /
/// RPC stop.
pub fn notify_stopping() {
    if let Err(e) = sd_notify::notify(&[
        NotifyState::Stopping,
        NotifyState::Status("Flushing RocksDB and shutting down"),
    ]) {
        tracing::warn!(error = %e, "sd_notify STOPPING failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the two Linux tests that mutate `NOTIFY_SOCKET`. Cargo
    /// runs `#[test]`s in parallel by default (`--test-threads=N` where
    /// N is CPU count), so without this guard test A could `remove_var`
    /// while test B is mid-`sd_notify::notify`, or both could set
    /// different sock paths and lose datagrams to the wrong listener.
    /// Using a hand-rolled mutex avoids pulling in `serial_test` for
    /// two tests.
    #[cfg(target_os = "linux")]
    static NOTIFY_SOCKET_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn format_status_no_total() {
        let snap = node::startup_progress::StartupSnapshot {
            phase: "opening_db".to_string(),
            message: "Opening database...".to_string(),
            current: 0,
            total: 0,
            stop_height: None,
        };
        assert_eq!(format_status(&snap), "Opening database...");
    }

    #[test]
    fn format_status_with_progress() {
        let snap = node::startup_progress::StartupSnapshot {
            phase: "reindex_connect".to_string(),
            message: "Replaying blocks".to_string(),
            current: 250_000,
            total: 800_000,
            stop_height: None,
        };
        assert_eq!(
            format_status(&snap),
            "Replaying blocks (250000/800000, 31%)"
        );
    }

    #[test]
    fn format_status_complete() {
        let snap = node::startup_progress::StartupSnapshot {
            phase: "reindex_connect".to_string(),
            message: "Replaying blocks".to_string(),
            current: 100,
            total: 100,
            stop_height: None,
        };
        assert_eq!(format_status(&snap), "Replaying blocks (100/100, 100%)");
    }

    /// End-to-end test: bind a UnixDatagram, point NOTIFY_SOCKET at it,
    /// call each public helper, and assert the wire-protocol bytes that
    /// show up on the receive side. This is what systemd would see.
    ///
    /// Linux-only — `sd_notify` only does anything on Linux (the `notify`
    /// crate's macOS path is a no-op stub) and the AF_UNIX SOCK_DGRAM
    /// behaviour we rely on differs on macOS.
    #[cfg(target_os = "linux")]
    #[test]
    fn helpers_emit_systemd_wire_protocol() {
        use std::os::unix::net::UnixDatagram;

        // Serialize against the heartbeat test below — both touch
        // NOTIFY_SOCKET. Hold the guard for the entire test body
        // (recover from poisoning so a panic in the other test doesn't
        // wedge this one).
        let _guard = NOTIFY_SOCKET_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&sock_path).expect("bind");
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");

        // SAFETY: NOTIFY_SOCKET is process-wide. NOTIFY_SOCKET_GUARD
        // (above) serializes the two tests that touch it.
        unsafe {
            std::env::set_var("NOTIFY_SOCKET", &sock_path);
        }

        let mut buf = [0u8; 4096];

        notify_status("Loading block index");
        let n = listener.recv(&mut buf).expect("recv status");
        assert_eq!(&buf[..n], b"STATUS=Loading block index\n");

        notify_ready();
        let n = listener.recv(&mut buf).expect("recv ready");
        let msg = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(msg.contains("READY=1"), "got: {msg:?}");
        assert!(msg.contains("STATUS=Ready"), "got: {msg:?}");

        notify_stopping();
        let n = listener.recv(&mut buf).expect("recv stopping");
        let msg = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(msg.contains("STOPPING=1"), "got: {msg:?}");
        assert!(
            msg.contains("STATUS=Flushing RocksDB and shutting down"),
            "got: {msg:?}"
        );

        unsafe {
            std::env::remove_var("NOTIFY_SOCKET");
        }
    }

    /// Heartbeat task: drive the ticker on a 50ms interval, confirm the
    /// right wire bytes hit the socket, then signal stop and confirm it
    /// exits. Multi-threaded runtime so the blocking recv on the listener
    /// can park without starving the spawned heartbeat task.
    // The mutex guard is intentionally held across awaits to serialize
    // the entire test body against the sibling NOTIFY_SOCKET test —
    // exactly the cross-test race the guard exists to prevent. The
    // underlying lock is uncontended on local runs (different test
    // threads typically schedule at different points) and the worst
    // case is one test waiting on the other, not deadlock.
    #[allow(clippy::await_holding_lock)]
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn heartbeat_emits_status_and_extend_timeout() {
        use std::os::unix::net::UnixDatagram;

        // Serialize against the wire-protocol test above — both touch
        // NOTIFY_SOCKET. Block on a std mutex inside an async test is
        // fine here: the lock is uncontended in normal local runs
        // (different test threads typically schedule at different
        // points), and contention only happens when both linux tests
        // run concurrently, which is exactly the case we want to
        // serialize.
        let _guard = NOTIFY_SOCKET_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&sock_path).expect("bind");
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        // SAFETY: NOTIFY_SOCKET is process-wide. NOTIFY_SOCKET_GUARD
        // (above) serializes the two tests that touch it.
        unsafe {
            std::env::set_var("NOTIFY_SOCKET", &sock_path);
        }

        let progress = StartupProgress::new();
        progress.set_phase("reindex_connect", "Replaying blocks");
        progress.set_total(1_000);
        progress.set_current(500);

        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let handle = spawn_startup_heartbeat_with_interval(
            progress.clone(),
            stop_rx,
            Duration::from_millis(50),
        );

        // Heartbeat skips the first tick, so the first datagram lands
        // ~100ms in. Run the blocking recv on a dedicated blocking task
        // so it can't starve the heartbeat task on a busy executor.
        let recv_task = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 4096];
            let n = listener.recv(&mut buf).expect("recv heartbeat");
            String::from_utf8(buf[..n].to_vec()).expect("utf8")
        });
        let msg = recv_task.await.expect("recv task");
        assert!(
            msg.contains("STATUS=Replaying blocks (500/1000, 50%)"),
            "got: {msg:?}"
        );
        assert!(msg.contains("EXTEND_TIMEOUT_USEC=120000000"), "got: {msg:?}");

        // Stop signal — task should drop out of its select arm and finish.
        stop_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("task did not exit within timeout")
            .expect("task panicked");

        unsafe {
            std::env::remove_var("NOTIFY_SOCKET");
        }
    }

    /// Test probe — flips healthy/unhealthy via an AtomicBool.
    #[cfg(target_os = "linux")]
    struct AtomicProbe {
        name: &'static str,
        healthy: std::sync::atomic::AtomicBool,
    }

    #[cfg(target_os = "linux")]
    impl AtomicProbe {
        fn new(name: &'static str, healthy: bool) -> Self {
            Self {
                name,
                healthy: std::sync::atomic::AtomicBool::new(healthy),
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl WatchdogProbe for std::sync::Arc<AtomicProbe> {
        fn healthy(&self) -> bool {
            self.healthy.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    /// `WATCHDOG_USEC` parsing: absent / zero / mismatched PID all
    /// return None; valid PID + non-zero usec returns Some.
    ///
    /// Holds NOTIFY_SOCKET_GUARD only because it serializes any test
    /// that mutates process-global env vars.
    #[cfg(target_os = "linux")]
    #[test]
    fn read_watchdog_usec_handles_all_states() {
        let _guard = NOTIFY_SOCKET_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        // SAFETY: NOTIFY_SOCKET_GUARD serializes env-var mutators.
        unsafe {
            std::env::remove_var("WATCHDOG_USEC");
            std::env::remove_var("WATCHDOG_PID");
        }
        assert_eq!(read_watchdog_usec(), None, "unset → None");

        unsafe {
            std::env::set_var("WATCHDOG_USEC", "0");
        }
        assert_eq!(read_watchdog_usec(), None, "zero → None");

        unsafe {
            std::env::set_var("WATCHDOG_USEC", "30000000");
            std::env::set_var("WATCHDOG_PID", "1");
        }
        assert_eq!(
            read_watchdog_usec(),
            None,
            "WATCHDOG_PID=1 (init) doesn't match ours → None"
        );

        unsafe {
            std::env::set_var(
                "WATCHDOG_PID",
                std::process::id().to_string(),
            );
        }
        assert_eq!(
            read_watchdog_usec(),
            Some(30_000_000),
            "valid usec + our PID → Some"
        );

        unsafe {
            std::env::remove_var("WATCHDOG_USEC");
            std::env::remove_var("WATCHDOG_PID");
        }
    }

    /// Heartbeat fires `WATCHDOG=1` on each tick when every probe is
    /// healthy. Mirror of the startup-heartbeat smoke test but for the
    /// post-ready watchdog path.
    #[allow(clippy::await_holding_lock)]
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watchdog_fires_when_probes_healthy() {
        use std::os::unix::net::UnixDatagram;

        let _guard = NOTIFY_SOCKET_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&sock_path).expect("bind");
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        unsafe {
            std::env::set_var("NOTIFY_SOCKET", &sock_path);
        }

        let probe = std::sync::Arc::new(AtomicProbe::new("test_probe", true));
        let probes: Vec<Box<dyn WatchdogProbe>> = vec![Box::new(probe.clone())];

        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let handle = spawn_watchdog_heartbeat_with_interval(
            probes,
            stop_rx,
            Duration::from_millis(50),
        );

        // First tick is skipped, so the first datagram lands ~100ms in.
        let recv_task = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 4096];
            let n = listener.recv(&mut buf).expect("recv watchdog");
            String::from_utf8(buf[..n].to_vec()).expect("utf8")
        });
        let msg = recv_task.await.expect("recv task");
        assert!(msg.contains("WATCHDOG=1"), "got: {msg:?}");

        stop_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("task did not exit within timeout")
            .expect("task panicked");

        unsafe {
            std::env::remove_var("NOTIFY_SOCKET");
        }
    }

    /// Heartbeat suppresses `WATCHDOG=1` when any probe reports
    /// unhealthy. Verified by checking the socket reads time out — no
    /// datagram should arrive while the probe is false.
    #[allow(clippy::await_holding_lock)]
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watchdog_suppresses_when_probe_unhealthy() {
        use std::io::ErrorKind;
        use std::os::unix::net::UnixDatagram;

        let _guard = NOTIFY_SOCKET_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());

        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&sock_path).expect("bind");
        listener
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("read timeout");
        unsafe {
            std::env::set_var("NOTIFY_SOCKET", &sock_path);
        }

        let probe = std::sync::Arc::new(AtomicProbe::new("test_probe", false));
        let probes: Vec<Box<dyn WatchdogProbe>> = vec![Box::new(probe.clone())];

        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let handle = spawn_watchdog_heartbeat_with_interval(
            probes,
            stop_rx,
            Duration::from_millis(50),
        );

        // 500ms read timeout × ticker fires every 50ms = expected several
        // suppressed ticks. None should reach the socket.
        let recv_task = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 4096];
            match listener.recv(&mut buf) {
                Ok(n) => Err(format!(
                    "unexpected datagram while probe unhealthy: {:?}",
                    String::from_utf8_lossy(&buf[..n])
                )),
                Err(e) if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut =>
                {
                    Ok(())
                }
                Err(e) => Err(format!("unexpected recv error: {e}")),
            }
        });
        recv_task.await.expect("recv task").expect("suppression");

        stop_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("task did not exit within timeout")
            .expect("task panicked");

        unsafe {
            std::env::remove_var("NOTIFY_SOCKET");
        }
    }
}
