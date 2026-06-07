//! Bitcoin Core notification shell-hooks: `-blocknotify`, `-alertnotify`,
//! `-startupnotify`, `-shutdownnotify`.
//!
//! Each runs an operator-supplied shell command on a node lifecycle event,
//! with `%s` substituted where Core substitutes it (the block hash for
//! `-blocknotify`, the warning text for `-alertnotify`; the startup/shutdown
//! hooks take no substitution). The command runs as `sh -c <cmd>`, matching
//! Core's `runCommand`.
//!
//! ## These are convenience hooks, not the integration path
//!
//! They exist purely so an existing Bitcoin Core `bitcoin.conf` boots
//! unedited. The supported, production way to build on satd is the
//! **Streaming Consumption API** (gRPC / WebSocket / ZMQ), which is
//! reorg-safe, replayable, and decoupled from consensus — a fork-and-replace
//! shell hook is none of those. The lifecycle hooks (`startupnotify` /
//! `shutdownnotify`) overlap your service manager (systemd
//! `ExecStartPost=` / `ExecStopPost=`), which is the better home for them.
//!
//! ## Why event-driven hooks run SERIALLY
//!
//! `-blocknotify` and `-alertnotify` fire on a stream of events. Each is
//! driven by a single dedicated task that runs one command at a time —
//! never a detached spawn-per-event. `BlockConnected` also fires for every
//! block replayed during IBD and `-reindex` (thousands/sec from disk); a
//! spawn-per-block would fork-bomb the host. Because each task is an
//! independent subscriber, a slow hook only delays its own subsequent
//! notifications (and, once its channel overflows, coalesces them) — it
//! never stalls block connection.
//!
//! Non-zero exits and spawn failures are logged WITHOUT the command body,
//! which may embed credentials.

use tokio::sync::{broadcast, mpsc};

/// Rationale appended to the startup warning for the event-driven hooks
/// (`-blocknotify` / `-alertnotify`): these exist for Core compatibility,
/// but the supported integration path is the Streaming Consumption API.
pub const STREAMING_API_NOTICE: &str =
    "This shell-hook notifier is provided for Bitcoin Core convenience/compatibility only — for \
     building on satd, consume node events via the Streaming Consumption API (gRPC / WebSocket / \
     ZMQ), which is reorg-safe, replayable, and decoupled from consensus. See the Streaming \
     Consumption API chapter of the manual.";

/// Rationale appended to the startup warning for the lifecycle hooks
/// (`-startupnotify` / `-shutdownnotify`): these are Core-compatibility
/// conveniences; the supported homes are the service manager
/// (systemd `ExecStartPost=` / `ExecStopPost=`) for lifecycle actions and
/// the Streaming Consumption API for building on node state.
pub const LIFECYCLE_NOTICE: &str =
    "This shell hook is provided for Bitcoin Core convenience/compatibility only — prefer your \
     service manager for lifecycle actions (systemd ExecStartPost= / ExecStopPost=), and the \
     Streaming Consumption API (gRPC / WebSocket / ZMQ) for building integrations on satd.";

/// Run a notify command once: `sh -c <template>` with `%s` replaced by
/// `subst` (when `Some`). Awaited, so callers serialize back-to-back runs.
/// Never panics; failures are logged at WARN without the command body.
pub async fn run_once(kind: &'static str, template: &str, subst: Option<&str>) {
    let cmd = match subst {
        Some(s) => template.replace("%s", s),
        None => template.to_string(),
    };
    match tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .status()
        .await
    {
        Ok(status) if status.success() => {}
        Ok(status) => tracing::warn!(%status, kind, "notify command exited non-zero"),
        Err(e) => tracing::warn!(error = %e, kind, "failed to run notify command"),
    }
}

/// Spawn the `-blocknotify` dispatcher: run `template` (with `%s` → block
/// hash) once per connected block, serially, on a dedicated broadcast
/// subscriber. See the module docs for why this never spawns per block.
pub fn spawn_block_notifier(
    mut rx: broadcast::Receiver<node::chain::events::ChainEvent>,
    template: String,
) {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(node::chain::events::ChainEvent::BlockConnected { hash, .. }) => {
                    run_once("blocknotify", &template, Some(&hash.to_string())).await;
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        skipped = n,
                        "blocknotify lagged; some block notifications were dropped"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    });
}

/// Spawn the `-alertnotify` dispatcher: run `template` (with `%s` → the
/// warning text) once per newly-raised node warning, serially, draining the
/// alert channel fed by [`node::warnings::NodeWarnings`]. The task exits
/// when every sender is dropped.
pub fn spawn_alert_notifier(mut rx: mpsc::UnboundedReceiver<String>, template: String) {
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            run_once("alertnotify", &template, Some(&msg)).await;
        }
    });
}
