//! Node-health detectors: the emitters behind
//! [`StatusEvent`](crate::events::StatusEvent).
//!
//! One task watches six conditions the daemon can observe about *itself* and
//! publishes a status event whenever one is entered or recovers. The same
//! transitions are mirrored into the [`NodeWarnings`] registry, so
//! `getwarnings`, the Core-compatible `-alertnotify` hook, and the streaming
//! `status` category can never disagree about node state.
//!
//! # Firing model
//!
//! Detectors are **level-triggered**: a standing condition raises once on entry
//! and clears once on recovery. Every standing condition has a *hysteresis gap*
//! between its raise and clear lines (a clear threshold above the raise
//! threshold, a hold time, or both), because the alternative — clearing at the
//! same value that raises — turns a metric hovering at the line into a pager
//! storm. The gaps are fixed constants (§ [`hysteresis`]); the raise thresholds
//! are operator-configurable and SIGHUP-live.
//!
//! Two conditions have no recovered state and are emitted as one-shot edges:
//! IBD finishing, and a reorg deeper than the configured floor landing.
//!
//! # Durability
//!
//! Status events are not replayable (no cursor, not in the replay ring). What
//! makes health alerting at-least-once across a restart is that this task
//! re-evaluates from scratch: a condition that is still true when the node
//! comes back is raised again, because the detector has no memory of having
//! raised it before. A condition that both raised and fully cleared while a
//! consumer was away is stale by definition and is not reconstructed.
//!
//! # Cost
//!
//! The poll loop runs every [`POLL_INTERVAL`] and reads only atomics and
//! lock-cheap accessors plus one `statvfs`. The chain-event half is driven by
//! the existing broadcast. Publishing is best-effort: with no `status`
//! subscriber and no webhook attached, the envelope is dropped by the
//! publisher's zero-receiver path.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::{broadcast, watch};
use tokio::time::{Duration, MissedTickBehavior, interval};

use crate::chain::events::ChainEvent;
use crate::chain::reorg_log::ReorgRecord;
use crate::chain::state::ChainState;
use crate::events::status::{StatusEvent, StatusKind, StatusSeverity};
use crate::events::{EventPublisher, StatusState};
use crate::mempool::pool::Mempool;
use crate::net::manager::PeerManager;
use crate::warnings::{NodeWarnings, Severity};

/// How often the polled detectors (`disk_low`, `mempool_congested`,
/// `peer_floor`, and the tip-stall timer) re-evaluate.
pub const POLL_INTERVAL: Duration = Duration::from_secs(15);

/// How far back to search the reorg log on each poll.
///
/// The whole ring, deliberately. A bounded window was a second way to lose an
/// edge permanently: `deep_reorg` is never reconstructed, so any delay of this
/// task past the window — API-runtime saturation, a `statvfs` blocking on a
/// hung mount, a VM pause, `SIGSTOP` — dropped every reorg older than it out of
/// view for good. The window bought nothing, because [`ReorgSeen`] is already
/// an exact de-duplicator; the only cost of scanning everything is cloning at
/// most `DEFAULT_RING_CAPACITY` (256) records per poll.
const REORG_LOG_LOOKBACK_SECS: u64 = u64::MAX;

/// Fixed hysteresis constants. Deliberately not configurable: six raise
/// thresholds is already a lot of operator surface, and these ratios only need
/// to be "enough of a gap that a metric sitting on the line does not flap".
pub mod hysteresis {
    use super::Duration;

    /// `disk_low` clears at 1.5× the raise floor — recovering from a disk
    /// alert usually means deleting something, and clearing at exactly the
    /// floor would re-raise on the next block written.
    pub const DISK_CLEAR_RATIO_NUM: u64 = 3;
    pub const DISK_CLEAR_RATIO_DEN: u64 = 2;

    /// `mempool_congested` clears below 0.75× the raise line. A mempool at its
    /// cap evicts continuously, so occupancy oscillates around the cap by
    /// design; a tight clear line would emit a raise/clear pair per block.
    pub const MEMPOOL_CLEAR_RATIO_NUM: u64 = 3;
    pub const MEMPOOL_CLEAR_RATIO_DEN: u64 = 4;

    /// `peer_floor` requires the condition to hold for this long in *either*
    /// direction. Peer counts dip transiently during normal churn (a peer
    /// disconnects, the manager dials a replacement within seconds); alerting
    /// on the instantaneous count would be noise.
    pub const PEER_HOLD: Duration = Duration::from_secs(60);

    /// Grace from detector start until the node's first peer, during which
    /// `peer_floor` does not raise. Outbound connections are dialed
    /// concurrently with the rest of startup and the poll's first tick fires
    /// immediately, so without a grace every node alerts once on the way up.
    /// The grace ends at the first peer, so it does not blunt the alert for a
    /// node that connects and *later* loses its peers.
    pub const PEER_STARTUP_GRACE: Duration = Duration::from_secs(90);
}

/// Operator-tunable raise thresholds, shared with the SIGHUP reload path.
///
/// Every threshold is "0 disables this detector" — an operator who does not
/// want a given alert sets it to zero rather than having to know a magic
/// sentinel. All fields are plain atomics: the reload path stores, the detector
/// loads, and a torn read is impossible for these widths.
#[derive(Debug)]
pub struct AlertThresholds {
    tip_stall_secs: AtomicU64,
    disk_free_bytes: AtomicU64,
    mempool_full_pct: AtomicU64,
    peer_floor: AtomicU64,
    reorg_depth: AtomicU64,
}

/// Default raise thresholds, mirrored by the `alert*` config-key defaults.
pub mod defaults {
    /// One hour without a connected block. Not gated on IBD — see
    /// `check_tip_stall_values`, which explains why at length. At mainnet's 10-minute
    /// target roughly 0.25 % of blocks take longer than an hour by chance, so
    /// this fires spuriously about once every few days on a healthy node —
    /// deliberate: a stalled node is worth a look, and an operator who finds it
    /// noisy raises the value (the manual documents the trade).
    pub const TIP_STALL_SECS: u64 = 3_600;

    /// The `tip_stall` default for `network`.
    ///
    /// Disabled on regtest, for the same reason as the peer floor and the reorg
    /// depth: regtest blocks exist only when someone calls
    /// `generatetoaddress`, so an idle chain is its resting state and not a
    /// stall. `last_connect` is seeded at detector start and advanced only by
    /// `BlockConnected`, so a developer's node left running for an hour while
    /// they write code — or a harness that mines a fixture and then sits —
    /// raises a *critical* alert. That pins `getwarnings`, holds `has_errors()`
    /// true, and puts up the TUI's blocking modal, on a chain that is behaving
    /// exactly as designed.
    ///
    /// Every other network keeps the hour. The spurious-raise rate on mainnet
    /// is a deliberate trade documented on [`TIP_STALL_SECS`], and a test
    /// network that goes an hour without a block is worth reporting even though
    /// its hashrate is thin — unlike a reorg a few blocks deep, a stall there is
    /// not an ordinary property of the network.
    pub fn tip_stall_for(network: bitcoin::Network) -> u64 {
        match network {
            bitcoin::Network::Regtest => 0,
            _ => TIP_STALL_SECS,
        }
    }
    /// 10 GiB. Enough headroom to notice before a mainnet node wedges mid-block
    /// (the 2026-05-13 dogfood incident was a silent disk-fill).
    pub const DISK_FREE_MB: u64 = 10_240;
    /// Percent of the mempool byte cap.
    pub const MEMPOOL_FULL_PCT: u64 = 90;
    /// Connected peers, on a network where a node is expected to have some.
    pub const PEER_FLOOR: u64 = 3;

    /// The `peer_floor` default for `network`, capped by `connect_peers` — the
    /// number of `-connect=` addresses the operator configured.
    ///
    /// Disabled on regtest only. A regtest node is routinely run entirely
    /// alone, so "fewer than 3 peers" is its normal operating state rather than
    /// a fault, and the default would raise a critical warning that can never
    /// clear — one that drives `getwarnings`, `-alertnotify`, and the TUI's
    /// blocking modal, which is a poor greeting for every developer's first run.
    ///
    /// Every other network keeps the real floor, signet included. Signet is a
    /// public network with real peers; a peer-starved signet node is broken in
    /// exactly the way this alert exists to report, and defaulting it off would
    /// make the detector's silence indistinguishable from health —
    /// `satd_alert_active{kind="peer_floor"}` reads 0 either way. An operator
    /// running a deliberately isolated signet can set `alertpeerfloor=0`.
    ///
    /// `-connect=` is the same trap as regtest wearing different clothes. It
    /// pins the node to exactly the addresses given and suppresses both DNS
    /// seeding and the fixed seeds, so a node with one or two of them can never
    /// reach a floor of 3 — no code path is left that would add a peer. The
    /// floor is a property of the configuration, not only of the network, so it
    /// follows the count the operator declared. Capping rather than disabling
    /// keeps the alert working for what it is actually good for here: a
    /// `-connect=` node that had all its configured peers and then lost one.
    pub fn peer_floor_for(network: bitcoin::Network, connect_peers: usize) -> u64 {
        match network {
            bitcoin::Network::Regtest => 0,
            _ if connect_peers > 0 => PEER_FLOOR.min(connect_peers as u64),
            _ => PEER_FLOOR,
        }
    }
    /// Blocks rolled back, on a chain where a reorg this deep is an incident.
    pub const REORG_DEPTH: u64 = 3;

    /// Blocks rolled back, on a chain where reorgs are an ordinary property of
    /// the network rather than an incident.
    pub const REORG_DEPTH_TEST_NETWORK: u64 = 10;

    /// The `deep_reorg` default for `network`.
    ///
    /// Depth 3 means completely different things on different chains, and the
    /// alert is only worth having if crossing it means something is wrong.
    ///
    /// On mainnet a 3-block reorg is a genuine incident: it costs real hashrate
    /// to produce, and it invalidates transactions that merchants have begun
    /// treating as settled. Waking someone is the correct response.
    ///
    /// The test networks are not economically secured, and reorgs a few blocks
    /// deep are a *normal operating property* of them — a consequence of thin,
    /// volatile hashrate (and, on testnet, of the difficulty exception). Paging
    /// on those is paging on the network working as designed, and an alert that
    /// fires during normal operation is one operators learn to ignore, which
    /// costs them the mainnet alert too. The floor is raised rather than
    /// disabled: a reorg past the 6-confirmation convention has invalidated
    /// something a wallet would have called final, and that is worth reporting
    /// on any chain. An operator who wants the mainnet sensitivity sets
    /// `alertreorgdepth=3` explicitly.
    ///
    /// Regtest is off entirely. Test harnesses reorg deliberately and
    /// constantly — `invalidateblock` and competing-chain tests are the point —
    /// so any threshold would fire on the suite doing its job.
    ///
    /// An unrecognized future network takes the test-network value: new
    /// networks are overwhelmingly test networks, and the failure mode of
    /// guessing that way (an alert that fires slightly less often than it
    /// could) is the milder one.
    pub fn reorg_depth_for(network: bitcoin::Network) -> u64 {
        match network {
            bitcoin::Network::Bitcoin => REORG_DEPTH,
            bitcoin::Network::Regtest => 0,
            _ => REORG_DEPTH_TEST_NETWORK,
        }
    }
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self::new(
            defaults::TIP_STALL_SECS,
            defaults::DISK_FREE_MB,
            defaults::MEMPOOL_FULL_PCT,
            defaults::PEER_FLOOR,
            defaults::REORG_DEPTH,
        )
    }
}

impl AlertThresholds {
    /// Build from the operator's configured values. `disk_free_mb` is taken in
    /// mebibytes (the config unit) and stored as bytes.
    pub fn new(
        tip_stall_secs: u64,
        disk_free_mb: u64,
        mempool_full_pct: u64,
        peer_floor: u64,
        reorg_depth: u64,
    ) -> Self {
        let s = Self {
            tip_stall_secs: AtomicU64::new(0),
            disk_free_bytes: AtomicU64::new(0),
            mempool_full_pct: AtomicU64::new(0),
            peer_floor: AtomicU64::new(0),
            reorg_depth: AtomicU64::new(0),
        };
        s.set_tip_stall_secs(tip_stall_secs);
        s.set_disk_free_mb(disk_free_mb);
        s.set_mempool_full_pct(mempool_full_pct);
        s.set_peer_floor(peer_floor);
        s.set_reorg_depth(reorg_depth);
        s
    }

    pub fn set_tip_stall_secs(&self, v: u64) {
        self.tip_stall_secs.store(v, Ordering::Relaxed);
    }
    pub fn set_disk_free_mb(&self, mb: u64) {
        self.disk_free_bytes
            .store(mb.saturating_mul(1024 * 1024), Ordering::Relaxed);
    }
    /// Values above 100 are clamped: a percentage over 100 can never be reached,
    /// which would silently disable the detector rather than doing what the
    /// operator meant.
    pub fn set_mempool_full_pct(&self, v: u64) {
        self.mempool_full_pct.store(v.min(100), Ordering::Relaxed);
    }
    pub fn set_peer_floor(&self, v: u64) {
        self.peer_floor.store(v, Ordering::Relaxed);
    }
    pub fn set_reorg_depth(&self, v: u64) {
        self.reorg_depth.store(v, Ordering::Relaxed);
    }

    pub fn tip_stall_secs(&self) -> u64 {
        self.tip_stall_secs.load(Ordering::Relaxed)
    }
    pub fn disk_free_bytes(&self) -> u64 {
        self.disk_free_bytes.load(Ordering::Relaxed)
    }
    pub fn mempool_full_pct(&self) -> u64 {
        self.mempool_full_pct.load(Ordering::Relaxed)
    }
    pub fn peer_floor(&self) -> u64 {
        self.peer_floor.load(Ordering::Relaxed)
    }
    pub fn reorg_depth(&self) -> u64 {
        self.reorg_depth.load(Ordering::Relaxed)
    }
}

/// Live health readings, published by the detector task and read by the
/// `/metrics` renderer. Separate from [`AlertThresholds`] because these flow the
/// other way: the detector writes, everything else reads.
#[derive(Debug, Default)]
pub struct HealthState {
    /// One flag per [`StatusKind`], indexed by position in [`StatusKind::ALL`].
    /// Edge kinds stay `false` — they have no standing state.
    active: [AtomicBool; StatusKind::ALL.len()],
    /// Seconds since the last block connected (or since the detector started,
    /// whichever is more recent — see `spawn_health_detectors`).
    last_connect_age_secs: AtomicU64,
    /// Last observed free space under the data directory. `u64::MAX` means
    /// "not yet sampled / unavailable", which the renderer skips rather than
    /// reporting a misleading zero.
    disk_free_bytes: AtomicU64,
    /// The threshold value in force when each condition was raised, indexed as
    /// `active`. Read by [`clear_if_threshold_relaxed`] to tell "the reading
    /// recovered" apart from "the operator moved the line".
    raised_at_threshold: [AtomicU64; StatusKind::ALL.len()],
    /// Latched once the node has had at least one peer. Gates the
    /// `peer_floor` hold clock so a node that has not finished dialing out yet
    /// does not alert on a startup transient.
    saw_first_peer: AtomicBool,
}

/// Sentinel for "no disk reading yet" — distinct from a genuine zero-free-space
/// reading, which is exactly the situation an operator most needs to see.
const DISK_UNKNOWN: u64 = u64::MAX;

impl HealthState {
    pub fn new() -> Self {
        Self {
            disk_free_bytes: AtomicU64::new(DISK_UNKNOWN),
            ..Default::default()
        }
    }

    /// Whether a standing condition is currently raised.
    pub fn is_active(&self, kind: StatusKind) -> bool {
        self.slot(kind).load(Ordering::Relaxed)
    }

    /// Seconds since the last connected block (or since detector start).
    pub fn last_connect_age_secs(&self) -> u64 {
        self.last_connect_age_secs.load(Ordering::Relaxed)
    }

    /// Last sampled free space under the data directory, or `None` if the
    /// filesystem has not been (or cannot be) interrogated.
    pub fn disk_free_bytes(&self) -> Option<u64> {
        match self.disk_free_bytes.load(Ordering::Relaxed) {
            DISK_UNKNOWN => None,
            v => Some(v),
        }
    }

    /// Test hook: drive a standing flag without running a detector.
    #[cfg(test)]
    pub fn set_active_for_test(&self, kind: StatusKind, on: bool) {
        self.set_active(kind, on);
    }

    /// Test hook: seed a free-space reading (or clear it back to unknown).
    #[cfg(test)]
    pub fn set_disk_free_for_test(&self, free: Option<u64>) {
        self.disk_free_bytes
            .store(free.unwrap_or(DISK_UNKNOWN), Ordering::Relaxed);
    }

    fn slot(&self, kind: StatusKind) -> &AtomicBool {
        let idx = StatusKind::ALL
            .iter()
            .position(|k| *k == kind)
            .expect("every StatusKind is in StatusKind::ALL");
        &self.active[idx]
    }

    fn set_active(&self, kind: StatusKind, on: bool) {
        self.slot(kind).store(on, Ordering::Relaxed);
    }

    fn threshold_slot(&self, kind: StatusKind) -> &AtomicU64 {
        let idx = StatusKind::ALL
            .iter()
            .position(|k| *k == kind)
            .expect("every StatusKind is in StatusKind::ALL");
        &self.raised_at_threshold[idx]
    }
}

/// Everything the detector task reads. Grouped into a struct because the
/// spawn function would otherwise take eight positional arguments.
pub struct HealthInputs {
    pub chain_state: Arc<ChainState>,
    pub mempool: Arc<Mempool>,
    pub peer_manager: Arc<PeerManager>,
    pub publisher: Arc<EventPublisher>,
    pub warnings: Arc<NodeWarnings>,
    pub thresholds: Arc<AlertThresholds>,
    /// Directory whose free space `disk_low` watches — the blocks directory
    /// when it is split out, since that is what actually grows.
    pub disk_watch_path: std::path::PathBuf,
}

/// Spawn the health-detector task and return the state handle the `/metrics`
/// renderer reads.
///
/// Spawns on the *calling* runtime, so the daemon must call this from within
/// the isolated API runtime: a detector that shared the consensus runtime could
/// have its poll delayed by block connection, which is the exact opposite of
/// what a stall detector is for.
pub fn spawn_health_detectors(
    inputs: HealthInputs,
    chain_rx: broadcast::Receiver<ChainEvent>,
    shutdown: watch::Receiver<bool>,
) -> Arc<HealthState> {
    let state = Arc::new(HealthState::new());
    let task_state = state.clone();
    tokio::spawn(async move {
        run_detectors(inputs, chain_rx, shutdown, task_state).await;
    });
    state
}


async fn run_detectors(
    inputs: HealthInputs,
    mut chain_rx: broadcast::Receiver<ChainEvent>,
    mut shutdown: watch::Receiver<bool>,
    state: Arc<HealthState>,
) {
    let HealthInputs {
        chain_state,
        mempool,
        peer_manager,
        publisher,
        warnings,
        thresholds,
        disk_watch_path,
    } = inputs;

    let mut poll = interval(POLL_INTERVAL);
    // A delayed tick must not turn into a burst of catch-up ticks: each tick
    // does a `statvfs`, and a runtime hiccup should cost one late poll, not N
    // immediate ones.
    poll.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Seed the stall clock from *now*, not from the tip's timestamp. A node
    // that was down for hours has a stale tip but will connect its backlog
    // within seconds of starting; seeding from the tip would page the operator
    // for a stall that is really just a restart.
    let mut last_connect = Instant::now();
    // IBD completion is a one-shot per process, and only meaningful for a node
    // that actually started in IBD — otherwise every restart of a synced node
    // would announce that it finished syncing.
    let mut ibd_pending = chain_state.is_initial_block_download();
    // Which reorg-log records have already been reported. Seeded from what the
    // log already holds so a restart does not re-announce reorgs that predate
    // it: `deep_reorg` is an edge event, and D3 re-raises standing conditions
    // across a restart, not edges.
    let mut reorgs_seen = ReorgSeen::default();
    if let Some(log) = chain_state.reorg_log() {
        reorgs_seen.seed(&log.history(REORG_LOG_LOOKBACK_SECS));
    }
    // Hold-time trackers for `peer_floor`: the condition must persist in either
    // direction before it is acted on.
    let mut peers_below_since: Option<Instant> = None;
    let mut peers_ok_since: Option<Instant> = None;
    // Anchors the `peer_floor` startup grace. Distinct from `last_connect`,
    // which is reset by every block.
    let detector_start = Instant::now();
    // Outstanding `statvfs`, collected on the following poll. See `check_disk`.
    let mut disk_probe: Option<DiskProbe> = None;

    loop {
        tokio::select! {
            // Unconditional, like every other shutdown handler in the tree.
            // `changed()` returns `Err` immediately and forever once the last
            // sender drops, while `borrow()` still reads whatever value was
            // last set — so gating the return on `*shutdown.borrow()` turns a
            // dropped sender into a 100%-CPU spin on an API worker instead of a
            // clean exit. A sender dropped without setting `true` means nobody
            // is left to ask us to stop, which is a stop.
            _ = shutdown.changed() => return,
            ev = chain_rx.recv() => {
                match ev {
                    Ok(ChainEvent::BlockConnected { height, .. }) => {
                        last_connect = Instant::now();
                        state.last_connect_age_secs.store(0, Ordering::Relaxed);
                        clear_if_active(
                            &state, &warnings, &publisher,
                            StatusKind::TipStall,
                            format!("tip advanced to height {height}"),
                            |e| e.with_detail("height", height),
                        );
                        if ibd_pending && !chain_state.is_initial_block_download() {
                            ibd_pending = false;
                            emit(
                                &warnings,
                                &publisher,
                                StatusEvent::edge(
                                    StatusKind::IbdComplete,
                                    format!("initial block download complete at height {height}"),
                                )
                                .with_detail("height", height),
                            );
                        }
                    }
                    Ok(ChainEvent::BlockDisconnected { .. })
                    | Ok(ChainEvent::Reorg { .. }) => {
                        // Reorg depth is read from the reorg log at poll time,
                        // not reconstructed from these events. See
                        // `scan_reorg_log`.
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // Nothing here depends on a complete event run. The
                        // tip-stall clock is advanced by `BlockConnected`, but
                        // a drop only delays it: the next retained connect
                        // still arrives and still resets it, and a node with no
                        // further blocks is stalled — which is what the
                        // detector is for. Reorg depth comes from the durable
                        // log, not from these events. Lag is worth a line and
                        // nothing more.
                        tracing::debug!(
                            target: "health",
                            dropped = n,
                            "chain-event lag in the health detector",
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
            _ = poll.tick() => {
                // Report any reorg the log recorded since the last poll.
                // Depth comes from the record, never from counting events.
                scan_reorg_log(
                    &warnings, &publisher, &thresholds, &chain_state, &mut reorgs_seen,
                );
                let age = last_connect.elapsed().as_secs();
                state.last_connect_age_secs.store(age, Ordering::Relaxed);
                check_tip_stall(&state, &warnings, &publisher, &thresholds, &chain_state, age);
                check_disk(
                    &state, &warnings, &publisher, &thresholds, &disk_watch_path,
                    &mut disk_probe, DISK_PROBE_BUDGET,
                )
                .await;
                check_mempool(&state, &warnings, &publisher, &thresholds, &mempool);
                check_peers(
                    &state, &warnings, &publisher, &thresholds, &peer_manager,
                    &mut peers_below_since, &mut peers_ok_since, &detector_start,
                );
            }
        }
    }
}

/// Publish a status event and mirror it into the warnings registry.
///
/// Only conditions worth operator attention become warnings: an `info` event
/// (IBD finishing) is good news, not a problem, and would otherwise sit in
/// `getwarnings` forever. A `raised` event records one, a `cleared` event
/// removes it.
///
/// An `edge` event pages but records nothing — see the note at the call site.
/// The registry is for conditions that are true *now* and that something will
/// later clear; a deep reorg is history, and history has its own log.
fn emit(warnings: &NodeWarnings, publisher: &EventPublisher, event: StatusEvent) {
    let id = event.kind.warning_id();
    match event.state {
        StatusState::Cleared => warnings.clear(&id),
        StatusState::Raised | StatusState::Edge => {
            if event.severity >= StatusSeverity::Warning {
                let severity = match event.severity {
                    StatusSeverity::Critical => Severity::Error,
                    _ => Severity::Warn,
                };
                // An edge observation fires the shell hook but does **not**
                // become a standing warning.
                //
                // `NodeWarnings` holds conditions that are currently true and
                // that something will later clear; its own contract says
                // history-style events keep their own logs, and that an active
                // warning means a problem to go fix. A deep reorg has no
                // resolved state, so nothing would ever clear it — it would pin
                // `getwarnings`, hold `has_errors()` true for the life of the
                // process, and keep the TUI's blocking modal up. On signet and
                // testnet4, where reorgs several blocks deep are ordinary, the
                // first one would do that permanently. The durable record is
                // `ReorgLog` plus the `status` event; this is only the page.
                if event.state == StatusState::Edge {
                    warnings.notify_event(&id, severity, event.message.clone());
                } else {
                    let context = serde_json::to_value(&event.details)
                        .unwrap_or(serde_json::Value::Null);
                    warnings.record(&id, severity, event.message.clone(), context);
                }
            }
        }
    }
    tracing::info!(
        target: "health",
        kind = event.kind.as_str(),
        state = ?event.state,
        severity = event.severity.as_str(),
        "{}",
        event.message,
    );
    publisher.publish_status(event);
}

/// Raise a standing condition if it is not already raised.
fn raise_if_new(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    kind: StatusKind,
    threshold: u64,
    message: String,
    details: impl FnOnce(StatusEvent) -> StatusEvent,
) {
    // Remember the line this is being raised against, so a later poll can tell
    // a recovered reading from a retuned threshold. See
    // `clear_if_threshold_relaxed`.
    //
    // Refreshed on every evaluation where the raise predicate holds, not only
    // on the raise edge. Storing it only on the edge leaves the slot stale
    // across a retune that keeps the condition raised, and the next recovery
    // into the hysteresis band then reads as "the operator moved the line":
    // raise at 93% against a 90% threshold, retune *down* to 80% (still
    // raised, so an edge-only store keeps 90), ease to 78% — below the new
    // raise line, above the new clear line — and the stale 90 ≠ 80 clears an
    // alert that both the old and new hysteresis lines say to hold.
    state.threshold_slot(kind).store(threshold, Ordering::Relaxed);
    if state.is_active(kind) {
        return;
    }
    state.set_active(kind, true);
    emit(warnings, publisher, details(StatusEvent::raised(kind, message)));
}

/// Clear a standing condition whose **threshold moved** rather than whose
/// reading recovered.
///
/// Every level-triggered detector clears on a hysteresis-widened predicate: disk
/// clears at 1.5× the floor, mempool at 0.75× the raise line. That gap is there
/// to stop a value hovering at the line from flapping, and it does its job — but
/// it must not also trap the operator who retunes the threshold *because* the
/// alert is firing. Raising the threshold moves both the raise line and the
/// clear line, so the current reading can land in the new dead band where
/// neither branch runs, and the alert stays raised against a threshold it no
/// longer violates.
///
/// For `mempool_congested` that trap is inescapable rather than merely awkward:
/// the percentage clamps at 100, so the highest reachable clear line is 75% of
/// the cap. Once occupancy is at or above that, no value of
/// `alertmempoolfullpct` can clear a raised alert — only disabling the detector
/// outright.
///
/// So: if the raise predicate no longer holds under the *current* threshold, and
/// that threshold differs from the one the condition was raised against, clear.
/// A reading that recovers on its own still goes through the hysteresis path;
/// this only fires when the operator actually moved the line.
fn clear_if_threshold_relaxed(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    kind: StatusKind,
    threshold: u64,
    message: String,
    details: impl FnOnce(StatusEvent) -> StatusEvent,
) {
    if !state.is_active(kind) {
        return;
    }
    if state.threshold_slot(kind).load(Ordering::Relaxed) == threshold {
        return;
    }
    clear_if_active(state, warnings, publisher, kind, message, details);
}

/// Clear a standing condition if it is currently raised.
fn clear_if_active(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    kind: StatusKind,
    message: String,
    details: impl FnOnce(StatusEvent) -> StatusEvent,
) {
    if !state.is_active(kind) {
        return;
    }
    state.set_active(kind, false);
    emit(warnings, publisher, details(StatusEvent::cleared(kind, message)));
}

/// A disabled detector must not leave a previously-raised condition standing
/// forever: if the operator turns the threshold off while it is raised, clear it
/// (with the reason) rather than stranding a warning nothing will ever retract.
fn clear_because_disabled(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    kind: StatusKind,
) {
    clear_with_reason(
        state,
        warnings,
        publisher,
        kind,
        format!("{} detector disabled by configuration", kind.as_str()),
        "detector_disabled",
    );
}

/// Clear a standing condition because the detector can no longer evaluate it,
/// tagging the wire event with *why*.
///
/// `reason` is a stable token a receiver may route on, so it has to distinguish
/// causes an operator would act on differently: "you turned this off" and "the
/// input this detector divides by went to zero" are not the same message.
fn clear_with_reason(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    kind: StatusKind,
    message: String,
    reason: &'static str,
) {
    clear_if_active(
        state,
        warnings,
        publisher,
        kind,
        message,
        |e| e.with_detail("reason", reason),
    );
}

fn check_tip_stall(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    chain_state: &ChainState,
    age_secs: u64,
) {
    check_tip_stall_values(
        state,
        warnings,
        publisher,
        thresholds,
        chain_state.is_initial_block_download(),
        chain_state.tip_height(),
        age_secs,
    );
}

/// The tip-stall detector's decision logic, over plain readings.
///
/// Split from [`check_tip_stall`] so the IBD latch is testable without a live
/// `ChainState` — the tests exercise this exact code rather than a
/// reimplementation of it.
fn check_tip_stall_values(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    in_ibd: bool,
    tip_height: u32,
    age_secs: u64,
) {
    let threshold = thresholds.tip_stall_secs();
    if threshold == 0 {
        clear_because_disabled(state, warnings, publisher, StatusKind::TipStall);
        return;
    }
    // `in_ibd` deliberately does not suppress this alert.
    //
    // It is tempting to: during a genuine sync the tip advances in bursts and a
    // stall alert would be noise. But `is_initial_block_download` is not a sync
    // flag — it compares the tip header's timestamp against the wall clock, so
    // a node that is fully caught up and then *stops* re-enters it a day later,
    // exactly when the operator most needs to hear from it.
    //
    // Latching on "we once saw a non-IBD tip" does not close that hole, because
    // the latch lives in this process and restarting is an operator's first
    // move during a stall. A node restarted while already wedged never observes
    // a non-IBD tip, so the latch never arms and this detector goes silent
    // permanently — at precisely the moment it should be paging.
    //
    // `age_secs` already encodes the thing worth gating on. A node that is
    // really syncing connects blocks continuously, which keeps the age far
    // below any sane threshold and suppresses the alert on its own. A node that
    // reads as "in IBD" but has connected nothing for the whole threshold is
    // stalled whether it is wedged mid-sync or wedged at the tip, and both
    // warrant the page. The message — "no block connected for Ns" — is true
    // either way.
    let _ = in_ibd;
    if age_secs >= threshold {
        raise_if_new(
            state,
            warnings,
            publisher,
            StatusKind::TipStall,
            threshold,
            format!("no block connected for {age_secs}s (threshold {threshold}s)"),
            |e| {
                e.with_detail("seconds_since_block", age_secs)
                    .with_detail("threshold_seconds", threshold)
                    .with_detail("tip_height", tip_height)
            },
        );
    } else {
        // The fast clear is event-driven (on `BlockConnected`), because the
        // point of the alert is that it lifts the instant the chain moves. This
        // is the slow one: it exists for the case where the *threshold* moved
        // instead of the tip. An operator who raises `alerttipstallseconds` via
        // SIGHUP to quiet a firing alert would otherwise stay raised until some
        // future block connects — and on a chain that only looks stalled under
        // the old threshold, that block may be a long way off.
        clear_if_active(
            state,
            warnings,
            publisher,
            StatusKind::TipStall,
            format!("tip age {age_secs}s is within the threshold ({threshold}s)"),
            |e| {
                e.with_detail("seconds_since_block", age_secs)
                    .with_detail("threshold_seconds", threshold)
            },
        );
    }
}

/// Sample the watched volume and evaluate `disk_low`.
///
/// `async` purely so the `statvfs` can go to `spawn_blocking`. `disk_watch_path`
/// defaults to `blocksdir`, which operators routinely point at NFS or iSCSI, and
/// `statvfs` on a hung network mount blocks uninterruptibly. Called inline it
/// would park an API-runtime worker and — since every detector shares this one
/// task — freeze *all* of them, `tip_stall` and `deep_reorg` included, for as
/// long as the mount stayed wedged.
/// How many stalled polls between repeat warnings about an unresponsive
/// filesystem. At the 15 s poll interval this is roughly hourly.
const STALL_LOG_EVERY: u32 = 240;

/// How long one poll will wait on an outstanding `statvfs` before giving up on
/// it for this tick. Comfortably under the poll interval, so a filesystem that
/// answers at all is read inline and the detector never falls behind; a
/// filesystem that does not answer costs this much per poll and nothing more.
const DISK_PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// An outstanding `statvfs`, carried across polls so a filesystem that never
/// answers strands exactly one blocking thread instead of one per poll.
struct DiskProbe {
    handle: tokio::task::JoinHandle<Option<u64>>,
    /// Consecutive polls this probe has failed to finish in. Drives the
    /// log-rate limiting only.
    stalled_polls: u32,
}

async fn check_disk(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    path: &std::path::Path,
    pending: &mut Option<DiskProbe>,
    budget: std::time::Duration,
) {
    // Sample before any early return, so `satd_disk_free_bytes` is populated
    // whatever the detector's configuration. An operator who sets
    // `alertdiskfreemb=0` has usually done so *because* they alert on the gauge
    // in Prometheus instead of via satd; returning before the filesystem read
    // would delete the series out from under their own rule, silently. An
    // unreadable filesystem reports "unknown" rather than a zero that would
    // read as "completely full".
    //
    // The probe is collected on the *next* poll rather than awaited on this
    // one. `statvfs` on a hard NFS mount whose server has gone away does not
    // return, and `spawn_blocking(..).await` inherits that wait in full: it
    // moves the syscall off the detector's thread but still parks the detector
    // on the `JoinHandle`. Every other detector — tip stall, deep reorg,
    // mempool, peers — then stops running, `chain_rx` stops being drained, and
    // every gauge freezes at its last value, so an external Prometheus rule on
    // tip age cannot fire either. A wedged mount would silently disable the
    // whole alerting subsystem, which is the one condition alerting exists for.
    //
    // A timeout around the join would not fix it: `tokio::time::timeout`
    // abandons the handle but cannot cancel a blocking task, so each poll would
    // strand another thread and exhaust the (bounded) blocking pool within
    // hours — trading a wedged detector for a wedged runtime. Holding the
    // handle across polls bounds the damage at exactly one stuck thread.
    let sample = match pending.as_mut() {
        Some(probe) => {
            // `&mut JoinHandle` is itself a future, so a timeout here does NOT
            // consume the handle — which is the whole point. `timeout(_, handle)`
            // by value would abandon it, and since a blocking task cannot be
            // cancelled, the next poll would spawn another and the one after
            // that another, exhausting the bounded blocking pool within hours.
            match tokio::time::timeout(budget, &mut probe.handle).await {
                Ok(joined) => joined.unwrap_or(None),
                Err(_) => {
                    probe.stalled_polls += 1;
                    let stalls = probe.stalled_polls;
                    // Loud once, then hourly: a hung filesystem is worth saying,
                    // and worth repeating for whoever reads the log later, but
                    // four identical lines a minute buries everything else.
                    if stalls == 1 || stalls.is_multiple_of(STALL_LOG_EVERY) {
                        tracing::warn!(
                            target: "health",
                            path = %path.display(),
                            stalled_polls = stalls,
                            budget_secs = budget.as_secs(),
                            "disk-space probe has not returned; the filesystem is \
                             not responding. Free-space alerting is stalled until \
                             it does — every other health detector keeps running.",
                        );
                    }
                    // Leave the gauge and the alert verdict on their last known
                    // values. Overwriting with "unknown" would clear a
                    // `disk_low` that is very likely still true — an
                    // unresponsive mount is not evidence the disk drained.
                    return;
                }
            }
        }
        // First poll of the process: nothing outstanding to collect. Start one
        // below and read it next tick.
        None => {
            let path = path.to_path_buf();
            *pending = Some(DiskProbe {
                handle: tokio::task::spawn_blocking(move || {
                    crate::diskspace::free_disk_bytes(&path)
                }),
                stalled_polls: 0,
            });
            // "Not measured yet" must not reach the gauge as "unmeasurable".
            return;
        }
    };
    // Collected: start the next one so the following poll has something to read.
    {
        let path = path.to_path_buf();
        *pending = Some(DiskProbe {
            handle: tokio::task::spawn_blocking(move || crate::diskspace::free_disk_bytes(&path)),
            stalled_polls: 0,
        });
    }
    state
        .disk_free_bytes
        .store(sample.unwrap_or(DISK_UNKNOWN), Ordering::Relaxed);
    // Log on the raise edge only. Firing this every poll while the condition
    // holds is 4 identical WARN lines a minute — 5,760 a day — which buries the
    // rest of the log for exactly as long as the operator has a real problem.
    // Checked before `check_disk_values` runs, so `is_active` still reads the
    // previous poll's verdict.
    if let Some(free) = sample
        && free < thresholds.disk_free_bytes()
        && !state.is_active(StatusKind::DiskLow)
    {
        // The path is deliberately NOT a wire detail. It goes to every `status`
        // subscriber, every webhook receiver, and onward into APNs/FCM push
        // bodies — an absolute datadir path typically containing the operator's
        // username. The node's own log records which volume this is.
        tracing::warn!(
            target: "health",
            path = %path.display(),
            free_bytes = free,
            threshold_bytes = thresholds.disk_free_bytes(),
            "free space below the configured floor"
        );
    }
    check_disk_values(state, warnings, publisher, thresholds, sample);
}

/// The disk detector's decision logic, over a plain reading.
///
/// Split from [`check_disk`] so the threshold and hysteresis behavior is
/// testable without driving a real filesystem to a target free-space level —
/// the tests exercise this exact code rather than a reimplementation of it.
/// `free` is `None` when the volume could not be interrogated.
fn check_disk_values(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    free: Option<u64>,
) {
    let floor = thresholds.disk_free_bytes();
    // The disabled-clear is checked before the unreadable-filesystem return,
    // not after. If the watched volume becomes uninterrogable while `disk_low`
    // is raised (the blocks volume is unmounted, `-blocksdir` points somewhere
    // that disappeared), an early return below would leave the alert raised
    // with no way to clear it — not even by setting `alertdiskfreemb=0`, which
    // is the documented escape hatch for every other detector.
    if floor == 0 {
        clear_because_disabled(state, warnings, publisher, StatusKind::DiskLow);
        return;
    }
    let Some(free) = free else {
        return;
    };
    let clear_at = floor
        .saturating_mul(hysteresis::DISK_CLEAR_RATIO_NUM)
        / hysteresis::DISK_CLEAR_RATIO_DEN;
    if free < floor {
        raise_if_new(
            state,
            warnings,
            publisher,
            StatusKind::DiskLow,
            floor,
            format!(
                "free space {} MiB below floor {} MiB",
                free / (1024 * 1024),
                floor / (1024 * 1024)
            ),
            |e| {
                e.with_detail("free_bytes", free)
                    .with_detail("threshold_bytes", floor)
            },
        );
    } else if free >= clear_at {
        clear_if_active(
            state,
            warnings,
            publisher,
            StatusKind::DiskLow,
            format!("free space recovered to {} MiB", free / (1024 * 1024)),
            |e| {
                e.with_detail("free_bytes", free)
                    .with_detail("clear_threshold_bytes", clear_at)
            },
        );
    } else {
        clear_if_threshold_relaxed(
            state,
            warnings,
            publisher,
            StatusKind::DiskLow,
            floor,
            format!(
                "free space {} MiB is within the floor ({} MiB)",
                free / (1024 * 1024),
                floor / (1024 * 1024)
            ),
            |e| {
                e.with_detail("free_bytes", free)
                    .with_detail("threshold_bytes", floor)
            },
        );
    }
}

fn check_mempool(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    mempool: &Mempool,
) {
    check_mempool_values(
        state,
        warnings,
        publisher,
        thresholds,
        mempool.max_size_bytes() as u64,
        mempool.acting_bytes() as u64,
        mempool.min_fee_rate(),
    );
}

/// The mempool detector's decision logic, over plain readings.
///
/// Split from [`check_mempool`] so the thresholds/hysteresis behavior is
/// testable without filling a real mempool to a target occupancy — the tests
/// exercise this exact code rather than a reimplementation of it.
fn check_mempool_values(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    cap: u64,
    used: u64,
    min_fee: u64,
) {
    let pct = thresholds.mempool_full_pct();
    if pct == 0 {
        clear_because_disabled(state, warnings, publisher, StatusKind::MempoolCongested);
        return;
    }
    if cap == 0 {
        // `maxmempool=0` is accepted and is SIGHUP-live. A bare return would
        // strand a raised alert with no path back: there is no occupancy ratio
        // against a zero cap, so neither the raise nor the clear branch can
        // ever run again.
        //
        // This is *not* `detector_disabled`: `alertmempoolfullpct` is still
        // armed and the operator did not turn anything off — their mempool cap
        // went to zero, which is itself worth surfacing. A receiver that
        // suppresses `detector_disabled` (reasonably, since it means "you asked
        // for this") would otherwise swallow it.
        clear_with_reason(
            state,
            warnings,
            publisher,
            StatusKind::MempoolCongested,
            "mempool cap is zero; congestion cannot be evaluated".to_string(),
            "mempool_cap_zero",
        );
        return;
    }
    let raise_at = cap.saturating_mul(pct) / 100;
    let clear_at = raise_at.saturating_mul(hysteresis::MEMPOOL_CLEAR_RATIO_NUM)
        / hysteresis::MEMPOOL_CLEAR_RATIO_DEN;
    if used >= raise_at {
        raise_if_new(
            state,
            warnings,
            publisher,
            StatusKind::MempoolCongested,
            pct,
            format!("mempool at {}% of its {} MiB cap", used * 100 / cap, cap / (1024 * 1024)),
            |e| {
                e.with_detail("bytes_used", used)
                    .with_detail("bytes_cap", cap)
                    .with_detail("threshold_pct", pct)
                    // The floor a transaction must beat to be accepted right
                    // now: the actionable half of a congestion alert.
                    .with_detail("mempoolminfee_sat_per_kvb", min_fee)
            },
        );
    } else if used < clear_at {
        clear_if_active(
            state,
            warnings,
            publisher,
            StatusKind::MempoolCongested,
            format!("mempool back to {}% of its cap", used * 100 / cap),
            |e| {
                e.with_detail("bytes_used", used)
                    .with_detail("bytes_cap", cap)
            },
        );
    } else {
        clear_if_threshold_relaxed(
            state,
            warnings,
            publisher,
            StatusKind::MempoolCongested,
            pct,
            format!(
                "mempool at {}% is within the threshold ({}%)",
                used * 100 / cap,
                pct
            ),
            |e| {
                e.with_detail("bytes_used", used)
                    .with_detail("bytes_cap", cap)
                    .with_detail("threshold_pct", pct)
            },
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn check_peers(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    peer_manager: &PeerManager,
    below_since: &mut Option<Instant>,
    ok_since: &mut Option<Instant>,
    started: &Instant,
) {
    check_peers_values(
        state,
        warnings,
        publisher,
        thresholds,
        peer_manager.connection_count() as u64,
        peer_manager.outbound_count() as u64,
        below_since,
        ok_since,
        started,
        Instant::now(),
    );
}

/// The peer detector's decision logic, over plain readings and an injected
/// clock.
///
/// Split from [`check_peers`] so the startup grace and hold behavior are
/// testable without a live `PeerManager` or real elapsed time — the tests
/// exercise this exact code rather than a reimplementation of it.
#[allow(clippy::too_many_arguments)]
fn check_peers_values(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    total: u64,
    outbound: u64,
    below_since: &mut Option<Instant>,
    ok_since: &mut Option<Instant>,
    started: &Instant,
    now: Instant,
) {
    let floor = thresholds.peer_floor();
    if floor == 0 {
        *below_since = None;
        *ok_since = None;
        clear_because_disabled(state, warnings, publisher, StatusKind::PeerFloor);
        return;
    }
    let inbound = total.saturating_sub(outbound);

    if total > 0 && !state.saw_first_peer.swap(true, Ordering::Relaxed) {
        // First peer of this process. Normal operation starts here, so the hold
        // clock starts here too — otherwise a node whose first peer arrives
        // late in the startup grace ends the grace and finds a hold that has
        // already elapsed, firing the alert in that very poll while it is still
        // filling its remaining outbound slots.
        *below_since = Some(now);
    }

    if total < floor {
        *ok_since = None;
        let since = *below_since.get_or_insert(now);
        // Startup grace. `tokio::time::interval` fires its first tick
        // immediately, so without this the hold clock starts at t≈0 and a node
        // that simply has not finished dialing out yet alerts at t≈PEER_HOLD.
        //
        // The grace defers the *start* of the hold rather than shortening it: a
        // grace that merely suppressed the raise until t=GRACE would fire the
        // instant it expired, since the hold would have run out alongside it.
        // Once the node has seen a peer the grace is over for good — a node
        // that loses its peers later is not in a startup transient and should
        // alert after an ordinary hold.
        let hold_from = if state.saw_first_peer.load(Ordering::Relaxed) {
            since
        } else {
            since.max(*started + hysteresis::PEER_STARTUP_GRACE)
        };
        if now.duration_since(hold_from) >= hysteresis::PEER_HOLD {
            raise_if_new(
                state,
                warnings,
                publisher,
                StatusKind::PeerFloor,
                floor,
                format!("only {total} peers connected (floor {floor})"),
                |e| {
                    e.with_detail("peers", total)
                        .with_detail("peers_outbound", outbound)
                        .with_detail("peers_inbound", inbound)
                        .with_detail("threshold", floor)
                },
            );
        }
    } else {
        *below_since = None;
        let since = *ok_since.get_or_insert(now);
        if now.duration_since(since) >= hysteresis::PEER_HOLD {
            clear_if_active(
                state,
                warnings,
                publisher,
                StatusKind::PeerFloor,
                format!("{total} peers connected (floor {floor})"),
                |e| {
                    e.with_detail("peers", total)
                        .with_detail("peers_outbound", outbound)
                        .with_detail("peers_inbound", inbound)
                },
            );
        }
    }
}

/// How many reported reorgs to remember. The log's own ring holds
/// [`DEFAULT_RING_CAPACITY`](crate::chain::reorg_log::DEFAULT_RING_CAPACITY)
/// (256) records, and a poll can only ever show us those, so twice that is
/// comfortably more than can be re-presented.
const REORG_SEEN_CAPACITY: usize = 512;

/// Which reorg-log records the detector has already reported.
///
/// A **set of identities**, deliberately not a high-water mark over the clock.
///
/// The earlier version compared `rec.ts_unix_secs` against a wall-clock value
/// seeded at startup and dropped anything older. Both sides ride
/// `SystemTime::now()`, so a single backwards step — NTP correcting a fast RTC
/// after boot, a hypervisor resyncing after live migration, an operator running
/// `date -s` — silenced *every* reorg alert until the clock caught back up to
/// the seeded value, with no event, no warning and no `-alertnotify`. The
/// watermark never reset and `deep_reorg` is an edge, so those alerts were not
/// delayed; they were gone.
///
/// Identity is `(ts, old_tip, new_tip)`. Every component comes from the record
/// itself, so rescanning the same record is stable, and a clock that jumps in
/// either direction changes nothing about whether a reorg is recognized as one
/// we have already reported. Including the timestamp keeps a flapping chain
/// (A→B, B→A, A→B again) from collapsing its third reorg onto its first.
#[derive(Debug, Default)]
struct ReorgSeen {
    seen: std::collections::HashSet<String>,
    order: std::collections::VecDeque<String>,
}

impl ReorgSeen {
    fn key(rec: &ReorgRecord) -> String {
        format!("{}:{}:{}", rec.ts_unix_secs, rec.old_tip, rec.new_tip)
    }

    /// Mark `rec` as seen; returns whether it had not been seen before.
    fn mark_new(&mut self, rec: &ReorgRecord) -> bool {
        let key = Self::key(rec);
        if !self.seen.insert(key.clone()) {
            return false;
        }
        self.order.push_back(key);
        while self.order.len() > REORG_SEEN_CAPACITY {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        true
    }

    /// Mark everything already in the log as seen, without reporting it.
    ///
    /// Called once at task start so a restart does not re-page for reorgs the
    /// previous process already alerted on. This replaces the old "seed a
    /// timestamp from the current clock" trick and does not depend on a clock
    /// at all.
    fn seed(&mut self, records: &[ReorgRecord]) {
        for rec in records {
            self.mark_new(rec);
        }
    }
}

/// Emit `deep_reorg` for every reorg the log has recorded since the last poll.
///
/// Depth, fork height and the reconnected chain all come from the record,
/// which `perform_reorg` writes and fsyncs before pushing it to the ring that
/// `history()` reads. This is what the design specifies — "depth from
/// `ReorgRecord`" — and it is the only source that is right by construction.
///
/// The previous implementation reconstructed depth by counting
/// `BlockDisconnected` events off the chain broadcast. That ring holds 64
/// entries and a reorg of depth D emits `2D + 2` events in one await-free
/// burst, so the count was truncated — or the `Reorg` marker itself dropped,
/// losing the reorg entirely — at roughly the depth where this alert starts to
/// matter. It also had to infer the new tip from the first reconnect, which is
/// `fork_height + 1` rather than the tip.
fn scan_reorg_log(
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    chain_state: &ChainState,
    seen: &mut ReorgSeen,
) {
    let Some(log) = chain_state.reorg_log() else {
        return;
    };
    report_reorgs(
        warnings,
        publisher,
        thresholds,
        log.history(REORG_LOG_LOOKBACK_SECS),
        seen,
    );
}

/// The reporting half of [`scan_reorg_log`], split from the log lookup so it
/// can be driven from a hand-built record list without a whole `ChainState`.
fn report_reorgs(
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    records: Vec<ReorgRecord>,
    seen: &mut ReorgSeen,
) {
    let threshold = thresholds.reorg_depth();
    for rec in records {
        // Mark before the threshold test: a record the current threshold
        // ignores is still one we have seen, and a later SIGHUP lowering the
        // threshold must not resurrect it.
        if !seen.mark_new(&rec) {
            continue;
        }
        if threshold == 0 || u64::from(rec.depth) < threshold {
            continue;
        }
        let from_height = rec.fork_height.saturating_add(rec.depth);
        // `reconnected` is fork-parent-exclusive and includes the block whose
        // connection triggered the reorg, so this is the new tip exactly.
        let to_height = rec
            .fork_height
            .saturating_add(u32::try_from(rec.reconnected.len()).unwrap_or(u32::MAX));
        emit(
            warnings,
            publisher,
            StatusEvent::edge(
                StatusKind::DeepReorg,
                format!(
                    "reorg rolled back {} blocks (from height {from_height} to \
                     {to_height}; threshold {threshold})",
                    rec.depth
                ),
            )
            .with_detail("depth", rec.depth)
            .with_detail("from_height", from_height)
            .with_detail("to_height", to_height)
            .with_detail("fork_height", rec.fork_height)
            .with_detail("threshold", threshold),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EdgeIdentity, NodeEventBody};

    fn publisher() -> Arc<EventPublisher> {
        EventPublisher::new(
            EdgeIdentity::new([0x11; 16], None).unwrap(),
            64,
        )
    }

    /// Drain the published status events from a receiver, as `(kind, state)`.
    fn drained(
        rx: &mut broadcast::Receiver<crate::events::NodeEvent>,
    ) -> Vec<(StatusKind, StatusState)> {
        let mut out = Vec::new();
        while let Ok(env) = rx.try_recv() {
            if let NodeEventBody::Status(s) = env.body {
                out.push((s.kind, s.state));
            }
        }
        out
    }

    #[test]
    fn thresholds_round_trip_and_clamp() {
        let t = AlertThresholds::new(30, 2, 150, 4, 7);
        assert_eq!(t.tip_stall_secs(), 30);
        assert_eq!(t.disk_free_bytes(), 2 * 1024 * 1024);
        // A percentage above 100 is unreachable and would silently disable the
        // detector, so it clamps instead.
        assert_eq!(t.mempool_full_pct(), 100);
        assert_eq!(t.peer_floor(), 4);
        assert_eq!(t.reorg_depth(), 7);
    }

    #[test]
    fn defaults_match_the_documented_values() {
        let t = AlertThresholds::default();
        assert_eq!(t.tip_stall_secs(), 3_600);
        assert_eq!(t.disk_free_bytes(), 10_240 * 1024 * 1024);
        assert_eq!(t.mempool_full_pct(), 90);
        assert_eq!(t.peer_floor(), 3);
        assert_eq!(t.reorg_depth(), 3);
    }

    /// Regtest blocks exist only when a test mines them, so an idle chain is
    /// its resting state — not a stall worth a critical alert that pins
    /// `getwarnings` and the TUI modal.
    #[test]
    fn tip_stall_default_is_disabled_only_on_regtest() {
        use bitcoin::Network;
        assert_eq!(defaults::tip_stall_for(Network::Regtest), 0);
        // A stall is not an ordinary property of a thin-hashrate chain the way
        // a shallow reorg is, so unlike `reorg_depth_for` the test networks are
        // not relaxed — they are simply expected to make blocks.
        assert_eq!(defaults::tip_stall_for(Network::Bitcoin), defaults::TIP_STALL_SECS);
        assert_eq!(defaults::tip_stall_for(Network::Signet), defaults::TIP_STALL_SECS);
        assert_eq!(defaults::tip_stall_for(Network::Testnet4), defaults::TIP_STALL_SECS);
    }

    #[test]
    fn peer_floor_default_is_disabled_only_on_regtest() {
        use bitcoin::Network;
        // A regtest node normally has no peers at all, so defaulting the floor
        // to 3 raises a critical warning 90s into every run that can never
        // clear.
        assert_eq!(defaults::peer_floor_for(Network::Regtest, 0), 0);
        // Signet is a public network with real peers. A peer-starved signet
        // node is broken in exactly the way this alert reports, and defaulting
        // it off would make the detector's silence indistinguishable from
        // health.
        assert_eq!(defaults::peer_floor_for(Network::Signet, 0), defaults::PEER_FLOOR);
        assert_eq!(defaults::peer_floor_for(Network::Bitcoin, 0), defaults::PEER_FLOOR);
        assert_eq!(defaults::peer_floor_for(Network::Testnet4, 0), defaults::PEER_FLOOR);

        // `-connect=` is the same trap as regtest: it suppresses DNS and fixed
        // seeds, so the node can never hold more peers than were named and a
        // stock floor of 3 would stand in `getblockchaininfo.warnings` forever.
        assert_eq!(defaults::peer_floor_for(Network::Bitcoin, 1), 1);
        assert_eq!(defaults::peer_floor_for(Network::Signet, 2), 2);
        // Capped, not mirrored — past the stock floor the ordinary threshold
        // governs, so a node wired to eight peers is not held to needing eight.
        assert_eq!(defaults::peer_floor_for(Network::Bitcoin, 8), defaults::PEER_FLOOR);
        // Regtest stays off; the network already answered this.
        assert_eq!(defaults::peer_floor_for(Network::Regtest, 1), 0);
    }

    /// Depth 3 is an incident on mainnet and an ordinary Tuesday on a test
    /// chain. Firing `-alertnotify` for the latter trains operators to ignore
    /// the alert, which costs them the mainnet one too.
    #[test]
    fn reorg_depth_default_is_network_conditional() {
        use bitcoin::Network;
        // Mainnet: a 3-block reorg costs real hashrate and invalidates
        // transactions merchants have started treating as settled.
        assert_eq!(defaults::reorg_depth_for(Network::Bitcoin), 3);
        // Test networks: reorgs a few blocks deep are the network working as
        // designed. Raised, not disabled — past 6 confirmations a wallet has
        // been told something false, and that is worth reporting anywhere.
        for n in [Network::Signet, Network::Testnet, Network::Testnet4] {
            assert_eq!(
                defaults::reorg_depth_for(n),
                defaults::REORG_DEPTH_TEST_NETWORK,
                "{n:?} should not page on routine reorgs",
            );
            assert!(
                defaults::reorg_depth_for(n) > 6,
                "{n:?} default must sit above the confirmation convention",
            );
        }
        // Regtest reorgs on purpose, constantly, as the test suite's whole job.
        assert_eq!(defaults::reorg_depth_for(Network::Regtest), 0);
    }

    #[test]
    fn raise_is_edge_triggered_not_repeated_per_poll() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();

        for _ in 0..5 {
            raise_if_new(
                &state,
                &warnings,
                &pubr,
                StatusKind::DiskLow,
                1,
                "low".into(),
                |e| e,
            );
        }
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::DiskLow, StatusState::Raised)],
            "a standing condition raises once, not once per evaluation",
        );
        assert!(state.is_active(StatusKind::DiskLow));
        // And the warning is recorded once (repeats would only bump `count`).
        assert_eq!(warnings.count(), 1);

        for _ in 0..5 {
            clear_if_active(
                &state,
                &warnings,
                &pubr,
                StatusKind::DiskLow,
                "ok".into(),
                |e| e,
            );
        }
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::DiskLow, StatusState::Cleared)],
        );
        assert!(!state.is_active(StatusKind::DiskLow));
        assert_eq!(warnings.count(), 0, "clearing removes the warning");
    }

    #[test]
    fn info_severity_does_not_create_a_warning() {
        // `ibd_complete` is good news; a warning for it would sit in
        // `getwarnings` forever with nothing to clear it.
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        emit(
            &warnings,
            &pubr,
            StatusEvent::edge(StatusKind::IbdComplete, "done"),
        );
        assert_eq!(warnings.count(), 0);
    }

    #[test]
    fn critical_maps_to_error_severity_warning() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        emit(
            &warnings,
            &pubr,
            StatusEvent::raised(StatusKind::TipStall, "stalled"),
        );
        let w = warnings.list();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].id, "alert.tip_stall");
        assert_eq!(w[0].severity, Severity::Error);
        assert!(warnings.has_errors());
    }

    #[test]
    fn warning_severity_maps_to_warn() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        emit(
            &warnings,
            &pubr,
            StatusEvent::raised(StatusKind::PeerFloor, "few peers"),
        );
        assert_eq!(warnings.list()[0].severity, Severity::Warn);
        assert!(!warnings.has_errors());
    }

    #[tokio::test]
    async fn disabling_a_detector_clears_a_standing_condition() {
        // Otherwise turning the threshold off would strand a raised alert that
        // nothing will ever retract.
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 0);

        state.set_active(StatusKind::DiskLow, true);
        warnings.record("alert.disk_low", Severity::Error, "low", serde_json::Value::Null);

        // Two polls: the probe is started on the first and collected on the
        // second (see `check_disk` on why it is never awaited inline).
        let mut probe = None;
        for _ in 0..2 {
            check_disk(
                &state,
                &warnings,
                &pubr,
                &thresholds,
                std::path::Path::new("."),
                &mut probe,
                DISK_PROBE_BUDGET,
            )
            .await;
        }
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::DiskLow, StatusState::Cleared)],
        );
        assert_eq!(warnings.count(), 0);
    }

    #[test]
    fn raising_the_disk_floor_clears_a_standing_alert() {
        // The operator decides the current free space is acceptable after all
        // and raises the floor to quiet the pager. The reading has not moved,
        // so it lands inside the *new* hysteresis band — between the new raise
        // line and the new clear line — where neither branch runs. Without the
        // threshold-relaxation clear the alert stays raised against a floor it
        // no longer violates, and on a filling disk free space only goes down,
        // so it would never clear on its own.
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();

        // 10 MiB floor, 5 MiB free ⇒ raised.
        let thresholds = AlertThresholds::new(0, 10, 0, 0, 0);
        sample_disk(&state, &warnings, &pubr, &thresholds, 5 * 1024 * 1024);
        assert_eq!(drained(&mut rx), vec![(StatusKind::DiskLow, StatusState::Raised)]);

        // Retune the floor down to 4 MiB. 5 MiB free is above the new floor but
        // below the new 6 MiB clear line: the dead band.
        thresholds.set_disk_free_mb(4);
        sample_disk(&state, &warnings, &pubr, &thresholds, 5 * 1024 * 1024);
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::DiskLow, StatusState::Cleared)],
            "a retuned threshold must be able to clear its own alert"
        );
        assert!(!state.is_active(StatusKind::DiskLow));
    }

    #[test]
    fn raising_the_mempool_threshold_clears_a_standing_alert() {
        // The unescapable case. `alertmempoolfullpct` clamps at 100, and the
        // clear line is 0.75× the raise line, so the highest reachable clear
        // line is 75% of the cap. Once occupancy is at or above that, *no*
        // value of the setting can clear a raised alert — the operator's only
        // escape would be disabling the detector outright.
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        const CAP: u64 = 300 * 1024 * 1024;
        let used = CAP * 93 / 100;

        // 90% threshold against 93% occupancy ⇒ raised.
        let thresholds = AlertThresholds::new(0, 0, 90, 0, 0);
        check_mempool_values(&state, &warnings, &pubr, &thresholds, CAP, used, 1000);
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::MempoolCongested, StatusState::Raised)]
        );

        // Raise it to 95 to quiet the alert: 93 < 95 so no raise, and
        // 93 >= 0.75*95 so no hysteresis clear. Dead band.
        thresholds.set_mempool_full_pct(95);
        check_mempool_values(&state, &warnings, &pubr, &thresholds, CAP, used, 1000);
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::MempoolCongested, StatusState::Cleared)],
            "no value of alertmempoolfullpct could otherwise clear this"
        );
    }

    #[test]
    fn disk_hysteresis_gap_prevents_flapping() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        // 1 MiB floor ⇒ clears at 1.5 MiB.
        let thresholds = AlertThresholds::new(0, 1, 0, 0, 0);
        let floor = thresholds.disk_free_bytes();

        // Just below the floor raises.
        sample_disk(&state, &warnings, &pubr, &thresholds, floor - 1);
        assert_eq!(drained(&mut rx), vec![(StatusKind::DiskLow, StatusState::Raised)]);
        // Just *above* the floor does NOT clear — that is the hysteresis gap.
        sample_disk(&state, &warnings, &pubr, &thresholds, floor + 1);
        assert!(drained(&mut rx).is_empty(), "clearing at the raise line would flap");
        assert!(state.is_active(StatusKind::DiskLow));
        // Above 1.5× clears.
        sample_disk(&state, &warnings, &pubr, &thresholds, floor * 3 / 2 + 1);
        assert_eq!(drained(&mut rx), vec![(StatusKind::DiskLow, StatusState::Cleared)]);
    }

    /// Drive the real disk detector at a synthetic free-space reading.
    ///
    /// A thin adapter over [`check_disk_values`] — deliberately not a
    /// reimplementation of its branch structure. An earlier version of these
    /// tests mirrored the detector's if/else here, which meant deleting the
    /// production `clear_if_threshold_relaxed` arm left every one of them green.
    fn sample_disk(
        state: &HealthState,
        warnings: &NodeWarnings,
        publisher: &EventPublisher,
        thresholds: &AlertThresholds,
        free: u64,
    ) {
        check_disk_values(state, warnings, publisher, thresholds, Some(free));
    }

    /// The retune-down case. `clear_if_threshold_relaxed` exists to release an
    /// alert whose *threshold* moved, but it must not release one whose
    /// threshold moved in the direction that keeps it firing. Storing the
    /// remembered line only on the raise edge left it stale across exactly that
    /// retune, so the next reading inside the hysteresis band read as "the
    /// operator moved the line" and cleared an alert both the old and the new
    /// hysteresis say to hold.
    #[test]
    fn lowering_the_mempool_threshold_while_raised_does_not_defeat_hysteresis() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let cap = 1_000_000u64;
        let thresholds = AlertThresholds::new(0, 0, 90, 0, 0);

        // 93% against a 90% line raises.
        check_mempool_values(&state, &warnings, &pubr, &thresholds, cap, 930_000, 1);
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::MempoolCongested, StatusState::Raised)]
        );

        // Operator retunes *down* to 80%, wanting an earlier warning. Still
        // over the line, so it stays raised and emits nothing.
        thresholds.set_mempool_full_pct(80);
        check_mempool_values(&state, &warnings, &pubr, &thresholds, cap, 930_000, 1);
        assert!(drained(&mut rx).is_empty(), "still above the new line");
        assert!(state.is_active(StatusKind::MempoolCongested));

        // Ease to 78%: below the new raise line (80%), above the new clear line
        // (60%) — squarely in the hysteresis band. It must hold.
        check_mempool_values(&state, &warnings, &pubr, &thresholds, cap, 780_000, 1);
        assert!(
            drained(&mut rx).is_empty(),
            "78% is inside the hysteresis band for an 80% threshold; clearing \
             here is the stale-slot bug"
        );
        assert!(state.is_active(StatusKind::MempoolCongested));

        // Below the clear line it does clear, on the ordinary path.
        check_mempool_values(&state, &warnings, &pubr, &thresholds, cap, 550_000, 1);
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::MempoolCongested, StatusState::Cleared)]
        );
    }

    /// The retune-*up* case still works — this is what the relaxed clear is for.
    #[test]
    fn raising_the_mempool_threshold_still_clears_from_inside_the_band() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let cap = 1_000_000u64;
        let thresholds = AlertThresholds::new(0, 0, 90, 0, 0);

        check_mempool_values(&state, &warnings, &pubr, &thresholds, cap, 930_000, 1);
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::MempoolCongested, StatusState::Raised)]
        );
        // 93% now sits below a 95% raise line but above the 71.25% clear line:
        // the dead band. Only the relaxed clear can release it.
        thresholds.set_mempool_full_pct(95);
        check_mempool_values(&state, &warnings, &pubr, &thresholds, cap, 930_000, 1);
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::MempoolCongested, StatusState::Cleared)]
        );
    }

    /// `maxmempool=0` is not the operator switching the detector off, and a
    /// receiver routing on `reason` must be able to tell the two apart.
    #[test]
    fn a_zero_mempool_cap_is_not_reported_as_detector_disabled() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 90, 0, 0);

        check_mempool_values(&state, &warnings, &pubr, &thresholds, 1_000_000, 950_000, 1);
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::MempoolCongested, StatusState::Raised)]
        );

        check_mempool_values(&state, &warnings, &pubr, &thresholds, 0, 0, 1);
        let env = rx.try_recv().expect("a zero cap must clear the standing alert");
        let NodeEventBody::Status(s) = env.body else {
            panic!("expected a status event")
        };
        assert_eq!(s.state, StatusState::Cleared);
        assert_eq!(
            s.details.get("reason").map(String::as_str),
            Some("mempool_cap_zero"),
            "`detector_disabled` means the operator turned it off; a consumer \
             suppressing that would swallow a zeroed mempool cap"
        );
    }

    /// A node restarted while already wedged must still page.
    ///
    /// This is the case an in-process latch cannot cover. The node is synced
    /// but its chain stopped; >24h later the tip-age predicate reads "in IBD"
    /// again. The operator restarts — the first thing anyone does — so the
    /// process never observes a non-IBD tip and a latch would never arm. The
    /// detector has to raise anyway.
    #[test]
    fn tip_stall_raises_on_a_node_restarted_while_already_wedged() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();

        let on = AlertThresholds::new(3600, 0, 0, 0, 0);
        // in_ibd = true on the very first evaluation, and never false.
        check_tip_stall_values(&state, &warnings, &pubr, &on, true, 100, 108_000);
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::TipStall, StatusState::Raised)],
            "a wedged node reads as 'in IBD' by tip age; that must not silence it"
        );
    }

    /// The flip side: a node that really is syncing connects blocks, which
    /// keeps the age low and suppresses the alert without any IBD predicate.
    #[test]
    fn a_syncing_node_connecting_blocks_does_not_raise_tip_stall() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();

        let on = AlertThresholds::new(3600, 0, 0, 0, 0);
        check_tip_stall_values(&state, &warnings, &pubr, &on, true, 100, 12);
        assert!(
            drained(&mut rx).is_empty(),
            "blocks are arriving; there is no stall to report"
        );
    }

    #[test]
    fn peer_startup_grace_is_followed_by_a_full_hold() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 3, 0);
        let started = Instant::now();
        let (mut below, mut ok) = (None, None);

        let at = |d: Duration| started + d;
        let poll = |now: Instant, total: u64, below: &mut _, ok: &mut _| {
            check_peers_values(
                &state, &warnings, &pubr, &thresholds, total, total, below, ok, &started, now,
            );
        };

        // Inside the grace, no peers: silent.
        poll(at(Duration::ZERO), 0, &mut below, &mut ok);
        poll(at(hysteresis::PEER_STARTUP_GRACE / 2), 0, &mut below, &mut ok);
        assert!(drained(&mut rx).is_empty(), "still dialing out");

        // The instant the grace ends, the hold must start fresh — not already
        // be satisfied by time spent inside the grace.
        poll(at(hysteresis::PEER_STARTUP_GRACE + Duration::from_secs(1)), 0, &mut below, &mut ok);
        assert!(
            drained(&mut rx).is_empty(),
            "the grace must not merely delay the raise to t=GRACE"
        );

        // A full hold after the grace, still starved: now it raises.
        poll(
            at(hysteresis::PEER_STARTUP_GRACE + hysteresis::PEER_HOLD + Duration::from_secs(2)),
            0,
            &mut below,
            &mut ok,
        );
        assert_eq!(drained(&mut rx), vec![(StatusKind::PeerFloor, StatusState::Raised)]);
    }

    /// Latching "we have seen a peer" ends the grace, but must not fire the
    /// alert in the very poll the first peer arrives while the node is still
    /// filling its remaining outbound slots.
    #[test]
    fn the_first_peer_arriving_does_not_immediately_raise() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 3, 0);
        let started = Instant::now();
        let (mut below, mut ok) = (None, None);

        check_peers_values(
            &state, &warnings, &pubr, &thresholds, 0, 0, &mut below, &mut ok, &started,
            started,
        );
        // First peer lands late in the grace: 1 < floor of 3, and the latch
        // drops the grace — but the hold has to start here, not at t=0.
        let t = started + hysteresis::PEER_STARTUP_GRACE - Duration::from_secs(1);
        check_peers_values(
            &state, &warnings, &pubr, &thresholds, 1, 1, &mut below, &mut ok, &started, t,
        );
        assert!(
            drained(&mut rx).is_empty(),
            "the node just got its first peer; it is still filling outbound slots"
        );
    }

    /// An operator who sets `alertdiskfreemb=0` has usually done so because
    /// they alert on the Prometheus gauge instead. Disabling the alert must not
    /// delete the series out from under their own rule.
    #[tokio::test]
    async fn the_disk_gauge_is_sampled_even_when_the_alert_is_disabled() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 0);
        assert_eq!(thresholds.disk_free_bytes(), 0, "detector off");

        let mut probe = None;
        let call = async |probe: &mut Option<DiskProbe>| {
            check_disk(
                &state, &warnings, &pubr, &thresholds, std::path::Path::new("."), probe,
                DISK_PROBE_BUDGET,
            )
            .await;
        };
        // First poll starts the probe and publishes nothing: "not measured yet"
        // must not reach the gauge as "unmeasurable".
        call(&mut probe).await;
        assert!(
            state.disk_free_bytes().is_none(),
            "the first poll only starts the probe",
        );
        assert!(probe.is_some(), "and leaves it outstanding");
        // Second poll collects it.
        call(&mut probe).await;
        assert!(
            state.disk_free_bytes().is_some(),
            "the gauge must be populated whatever the alert's configuration"
        );
    }

    /// The finding: `statvfs` on a hard NFS mount whose server has gone away
    /// never returns. Awaiting it inline parked the whole detector loop — tip
    /// stall, deep reorg, mempool and peer checks all stopped, and every gauge
    /// froze, so even an external Prometheus rule on tip age could not fire.
    ///
    /// A probe that never finishes must therefore (a) not block the poll, and
    /// (b) not spawn a replacement each poll, which would strand one blocking
    /// thread per tick and exhaust the pool within hours.
    #[tokio::test]
    async fn a_wedged_filesystem_does_not_stall_the_detector_or_leak_threads() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 0);

        // Stand in for the hung syscall: a blocking task that never returns.
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let mut probe = Some(DiskProbe {
            handle: tokio::task::spawn_blocking(move || {
                let _ = release_rx.recv();
                None
            }),
            stalled_polls: 0,
        });

        for expected in 1..=3u32 {
            // Each call must RETURN — if this hangs, the bug is back.
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                check_disk(
                    &state,
                    &warnings,
                    &pubr,
                    &thresholds,
                    std::path::Path::new("."),
                    &mut probe,
                    // Tiny budget: the point is that a stuck probe is abandoned
                    // for this tick, not how long we are willing to wait.
                    std::time::Duration::from_millis(1),
                ),
            )
            .await
            .expect("check_disk must not block on an unresponsive filesystem");
            assert_eq!(
                probe.as_ref().expect("the stuck probe is retained").stalled_polls,
                expected,
                "the same probe is carried forward, not replaced",
            );
        }
        // Let the fake syscall finish so the runtime can shut down cleanly.
        let _ = release_tx.send(());
    }

    /// Build a reorg-log record with a controlled timestamp and shape.
    ///
    /// `reconnected` is a *count*: the number of blocks the new chain put back
    /// above the fork, which is what fixes the new-tip height.
    fn rec(ts: u64, fork_height: u32, depth: u32, reconnected: usize, tag: u8) -> ReorgRecord {
        ReorgRecord {
            ts_unix_secs: ts,
            depth,
            fork_height,
            old_tip: format!("{tag:064x}"),
            new_tip: format!("{:064x}", tag.wrapping_add(0x80)),
            disconnected: (0..depth).map(|i| format!("d{i}")).collect(),
            reconnected: (0..reconnected).map(|i| format!("r{i}")).collect(),
        }
    }

    fn detail(env: &crate::events::NodeEvent, key: &str) -> String {
        let NodeEventBody::Status(s) = &env.body else {
            panic!("expected a status event")
        };
        s.details.get(key).cloned().unwrap_or_default()
    }

    #[test]
    fn deep_reorg_fires_only_at_or_above_the_threshold() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 3);
        let mut seen = ReorgSeen::default();

        report_reorgs(&warnings, &pubr, &thresholds, vec![rec(1000, 98, 2, 3, 1)], &mut seen);
        assert!(drained(&mut rx).is_empty(), "a 2-deep reorg is below the floor");

        report_reorgs(&warnings, &pubr, &thresholds, vec![rec(1001, 97, 3, 4, 2)], &mut seen);
        assert_eq!(drained(&mut rx), vec![(StatusKind::DeepReorg, StatusState::Edge)]);
    }

    #[test]
    fn deep_reorg_reports_true_depth_and_fork_height() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 1);
        let mut seen = ReorgSeen::default();

        // fork at 896, 4 rolled back (old tip 900), 6 reconnected (new tip 902).
        report_reorgs(&warnings, &pubr, &thresholds, vec![rec(1000, 896, 4, 6, 1)], &mut seen);
        let env = rx.try_recv().unwrap();
        assert_eq!(detail(&env, "depth"), "4");
        assert_eq!(detail(&env, "from_height"), "900");
        assert_eq!(detail(&env, "to_height"), "902");
        assert_eq!(detail(&env, "fork_height"), "896");
    }

    /// The new tip is the end of the reconnected chain, not its first block.
    ///
    /// Reconnects are emitted oldest-first, so an implementation that reads the
    /// new tip off the first `BlockConnected` after a disconnect run reports
    /// `fork_height + 1` — below the *old* tip — for every reorg with a
    /// replacement chain, which is every reorg deep enough to alert on.
    #[test]
    fn to_height_is_the_new_tip_not_the_first_reconnect() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 1);
        let mut seen = ReorgSeen::default();

        report_reorgs(&warnings, &pubr, &thresholds, vec![rec(1000, 100, 3, 4, 1)], &mut seen);
        let env = rx.try_recv().unwrap();
        assert_eq!(detail(&env, "to_height"), "104");
        assert_ne!(detail(&env, "to_height"), "101", "that is the first reconnect");
    }

    /// A reorg whose record predates the last one seen must still be reported.
    ///
    /// `ReorgRecord::ts_unix_secs` is `SystemTime::now()`, so a backwards clock
    /// step — NTP correcting a fast RTC after boot, a hypervisor resync after
    /// live migration, `date -s` — makes later reorgs carry *earlier*
    /// timestamps. The previous implementation kept a high-water mark over that
    /// timestamp and dropped anything below it, which silenced every reorg
    /// alert until the clock caught back up. `deep_reorg` is an edge, so those
    /// alerts were not delayed, they were gone.
    ///
    /// Control: with the old `if rec.ts_unix_secs < self.ts { return false }`
    /// watermark, the second `report_reorgs` here emits nothing and the final
    /// assertion fails.
    #[test]
    fn a_reorg_is_reported_even_when_the_clock_steps_backwards() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 1);
        let mut seen = ReorgSeen::default();

        // A reorg at t=2000, reported normally.
        report_reorgs(&warnings, &pubr, &thresholds, vec![rec(2000, 100, 4, 2, 1)], &mut seen);
        assert!(rx.try_recv().is_ok(), "the first reorg reports");

        // The clock steps back 20 minutes; the next genuine reorg is stamped
        // t=800. It is a different reorg (different tips) and must still page.
        report_reorgs(&warnings, &pubr, &thresholds, vec![rec(800, 200, 5, 3, 2)], &mut seen);
        let env = rx
            .try_recv()
            .expect("a reorg after a backwards clock step must still be reported");
        assert_eq!(detail(&env, "depth"), "5");
    }

    /// The same record rescanned across polls reports exactly once — the
    /// property that lets the lookback window be the whole ring.
    #[test]
    fn rescanning_the_log_does_not_re_report_a_reorg() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 1);
        let mut seen = ReorgSeen::default();

        let records = vec![rec(1000, 100, 4, 2, 1), rec(1001, 200, 5, 3, 2)];
        for _ in 0..5 {
            report_reorgs(&warnings, &pubr, &thresholds, records.clone(), &mut seen);
        }
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 2, "two distinct reorgs, five scans, two reports");
    }

    /// Seeding marks what the log already holds as reported, so a restart does
    /// not re-page for reorgs the previous process already alerted on.
    #[test]
    fn seeding_suppresses_reorgs_that_predate_the_process() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 1);
        let mut seen = ReorgSeen::default();

        let old = vec![rec(1000, 100, 9, 2, 1)];
        seen.seed(&old);
        report_reorgs(&warnings, &pubr, &thresholds, old, &mut seen);
        assert!(rx.try_recv().is_err(), "a seeded reorg must not re-page");

        report_reorgs(&warnings, &pubr, &thresholds, vec![rec(1001, 300, 9, 2, 3)], &mut seen);
        assert!(rx.try_recv().is_ok(), "but a new one still does");
    }

    /// A truncation reorg — rolled back with nothing to replace it — leaves the
    /// tip at the fork.
    #[test]
    fn a_truncation_reorg_reports_the_fork_as_the_new_tip() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 1);
        let mut seen = ReorgSeen::default();

        report_reorgs(&warnings, &pubr, &thresholds, vec![rec(1000, 99, 6, 0, 1)], &mut seen);
        let env = rx.try_recv().unwrap();
        assert_eq!(detail(&env, "depth"), "6");
        assert_eq!(detail(&env, "from_height"), "105");
        assert_eq!(detail(&env, "to_height"), "99");
    }

    /// The log is rescanned on every poll and keeps records for 300 s, so
    /// without a watermark one reorg would re-alert every 15 s for 5 minutes.
    #[test]
    fn a_reorg_is_reported_once_however_often_the_log_is_scanned() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 1);
        let mut seen = ReorgSeen::default();
        let records = vec![rec(1000, 96, 4, 5, 1)];

        report_reorgs(&warnings, &pubr, &thresholds, records.clone(), &mut seen);
        assert_eq!(drained(&mut rx).len(), 1);
        for _ in 0..5 {
            report_reorgs(&warnings, &pubr, &thresholds, records.clone(), &mut seen);
        }
        assert!(drained(&mut rx).is_empty(), "a rescan must not re-alert");
    }

    /// Two reorgs can land in the same second — a tip race, or back-to-back
    /// `invalidateblock`. A watermark that stored only a timestamp would
    /// swallow the second.
    #[test]
    fn two_reorgs_in_the_same_second_are_both_reported() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 1);
        let mut seen = ReorgSeen::default();

        report_reorgs(
            &warnings,
            &pubr,
            &thresholds,
            vec![rec(1000, 96, 4, 5, 1), rec(1000, 90, 7, 8, 2)],
            &mut seen,
        );
        assert_eq!(drained(&mut rx).len(), 2);
    }

    /// A record the threshold ignored is still a record we have seen. Lowering
    /// `alertreorgdepth` by SIGHUP must not resurrect reorgs from the window.
    #[test]
    fn a_sub_threshold_reorg_is_not_resurrected_by_lowering_the_threshold() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let mut seen = ReorgSeen::default();
        let records = vec![rec(1000, 98, 2, 3, 1)];

        report_reorgs(&warnings, &pubr, &AlertThresholds::new(0, 0, 0, 0, 10), records.clone(), &mut seen);
        assert!(drained(&mut rx).is_empty());

        report_reorgs(&warnings, &pubr, &AlertThresholds::new(0, 0, 0, 0, 1), records, &mut seen);
        assert!(drained(&mut rx).is_empty(), "already seen at the old threshold");
    }

    #[test]
    fn deep_reorg_disabled_by_zero_threshold() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 0);
        let mut seen = ReorgSeen::default();
        report_reorgs(&warnings, &pubr, &thresholds, vec![rec(1000, 50, 50, 51, 1)], &mut seen);
        assert!(drained(&mut rx).is_empty());
    }

    #[test]
    fn health_state_tracks_per_kind_flags_independently() {
        let state = HealthState::new();
        state.set_active(StatusKind::DiskLow, true);
        assert!(state.is_active(StatusKind::DiskLow));
        for k in StatusKind::ALL {
            if k != StatusKind::DiskLow {
                assert!(!state.is_active(k), "{k:?} must be independent");
            }
        }
    }

    #[test]
    fn disk_free_is_unknown_until_sampled() {
        // A zero here would render as "completely full" on the metrics page.
        let state = HealthState::new();
        assert_eq!(state.disk_free_bytes(), None);
        state.disk_free_bytes.store(42, Ordering::Relaxed);
        assert_eq!(state.disk_free_bytes(), Some(42));
    }
}
