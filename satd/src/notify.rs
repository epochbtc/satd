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

    #[test]
    fn format_status_no_total() {
        let snap = node::startup_progress::StartupSnapshot {
            phase: "opening_db".to_string(),
            message: "Opening database...".to_string(),
            current: 0,
            total: 0,
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

        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&sock_path).expect("bind");
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");

        // SAFETY: tests in this module set NOTIFY_SOCKET for the duration
        // of the case to stand in for systemd's exec setup. Cargo's
        // default test threading runs each `#[test]` in its own thread,
        // but env access is process-wide; mark this test #[serial] if
        // additional NOTIFY_SOCKET-using tests are added later.
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
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn heartbeat_emits_status_and_extend_timeout() {
        use std::os::unix::net::UnixDatagram;

        let dir = tempfile::tempdir().expect("tempdir");
        let sock_path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&sock_path).expect("bind");
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
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
}
