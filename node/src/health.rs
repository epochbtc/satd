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
use crate::chain::state::ChainState;
use crate::events::status::{StatusEvent, StatusKind, StatusSeverity};
use crate::events::{EventPublisher, StatusState};
use crate::mempool::pool::Mempool;
use crate::net::manager::PeerManager;
use crate::warnings::{NodeWarnings, Severity};

/// How often the polled detectors (`disk_low`, `mempool_congested`,
/// `peer_floor`, and the tip-stall timer) re-evaluate.
pub const POLL_INTERVAL: Duration = Duration::from_secs(15);

/// How far back to search the reorg log when recovering a lag-interrupted depth
/// count. Generous because the match is exact (on the abandoned tip height), so
/// a wide window costs nothing in precision — only a longer `Vec` to scan.
const REORG_LOG_LOOKBACK_SECS: u64 = 300;

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
    /// One hour without a connected block, outside IBD. At mainnet's 10-minute
    /// target roughly 0.25 % of blocks take longer than an hour by chance, so
    /// this fires spuriously about once every few days on a healthy node —
    /// deliberate: a stalled node is worth a look, and an operator who finds it
    /// noisy raises the value (the manual documents the trade).
    pub const TIP_STALL_SECS: u64 = 3_600;
    /// 10 GiB. Enough headroom to notice before a mainnet node wedges mid-block
    /// (the 2026-05-13 dogfood incident was a silent disk-fill).
    pub const DISK_FREE_MB: u64 = 10_240;
    /// Percent of the mempool byte cap.
    pub const MEMPOOL_FULL_PCT: u64 = 90;
    /// Connected peers, on a network where a node is expected to have some.
    pub const PEER_FLOOR: u64 = 3;

    /// The `peer_floor` default for `network`.
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
    pub fn peer_floor_for(network: bitcoin::Network) -> u64 {
        match network {
            bitcoin::Network::Regtest => 0,
            _ => PEER_FLOOR,
        }
    }
    /// Blocks rolled back.
    pub const REORG_DEPTH: u64 = 3;
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
    /// Latched once the node has been observed out of initial block download.
    /// See the IBD guard in [`check_tip_stall`]: `is_initial_block_download()`
    /// can flip back to `true` on a long-stalled node, which would otherwise
    /// permanently freeze that detector.
    left_ibd: AtomicBool,
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

/// Tracks a reorg in flight so `deep_reorg` can report the true depth.
///
/// `ChainEvent::Reorg` carries the old and new tip heights but not the fork
/// point, so depth is not derivable from the marker alone. It *is* derivable
/// from the sequence the connect path emits — marker, one `BlockDisconnected`
/// per rolled-back block, then the reconnects — so the detector counts
/// disconnects between the marker and the next connect. That is exactly
/// `old_height - fork_height`, the same number `ReorgRecord` records, with no
/// extra plumbing into the consensus path.
enum ReorgTracking {
    Idle,
    Counting {
        from_height: u32,
        disconnected: u32,
        /// When counting started. A reorg that ends in a connect finalizes
        /// immediately; a *truncation* reorg (`invalidateblock`, or a chain
        /// rolled back with nothing to replace it) emits disconnects and then
        /// simply stops, so the poll loop finalizes a count that has gone
        /// quiet. Without this, a truncation-shaped reorg would go unreported
        /// until the next block arrived — which could be never.
        started: Instant,
    },
    /// The disconnect run was interrupted by broadcast lag, so the count we
    /// have is an undercount. The true depth is in the reorg log — but not yet.
    ///
    /// `perform_reorg` emits `ChainEvent::Reorg` and every disconnect and
    /// reconnect *first*, and only then calls `ReorgLog::record`, which fsyncs
    /// the JSONL append before pushing to the in-memory ring that `history()`
    /// reads. So at the instant lag is observed the record is typically absent,
    /// and the newest record present belongs to some *earlier* reorg. Reading
    /// it there either drops the report silently or attributes another reorg's
    /// depth and fork point to this one.
    ///
    /// Instead: hold the marker's abandoned-tip height, wait a poll, and match
    /// the record by that height.
    LagRecovery {
        /// Abandoned tip from the `Reorg` marker: `fork_height + depth`.
        from_height: u32,
        /// What we counted before lag hit. A lower bound on the true depth.
        counted: u32,
        started: Instant,
    },
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
    let mut reorg = ReorgTracking::Idle;
    // Hold-time trackers for `peer_floor`: the condition must persist in either
    // direction before it is acted on.
    let mut peers_below_since: Option<Instant> = None;
    let mut peers_ok_since: Option<Instant> = None;
    // Anchors the `peer_floor` startup grace. Distinct from `last_connect`,
    // which is reset by every block.
    let detector_start = Instant::now();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
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
                        if let ReorgTracking::Counting { from_height, disconnected, .. } = reorg {
                            finish_reorg(
                                &warnings, &publisher, &thresholds,
                                from_height, disconnected, height,
                            );
                            reorg = ReorgTracking::Idle;
                        }
                    }
                    Ok(ChainEvent::BlockDisconnected { .. }) => {
                        if let ReorgTracking::Counting { disconnected, .. } = &mut reorg {
                            *disconnected += 1;
                        }
                    }
                    Ok(ChainEvent::Reorg { from_height, .. }) => {
                        reorg = ReorgTracking::Counting {
                            from_height,
                            disconnected: 0,
                            started: Instant::now(),
                        };
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // The disconnect run we were counting is incomplete, so
                        // the counted depth would be an undercount.
                        //
                        // Abandoning it outright is not acceptable here: the
                        // chain-event ring holds 64 entries and a reorg emits
                        // one marker plus one event per disconnected *and*
                        // reconnected block, so lag becomes likely at roughly
                        // the depth where this alert starts to matter. That
                        // would make `deep_reorg` least reliable for the largest
                        // reorgs — the ones it exists to report.
                        //
                        // The depth is not actually lost: the reorg log holds
                        // the committed record with the true fork height. Fall
                        // back to it and report from ground truth.
                        tracing::debug!(
                            target: "health",
                            dropped = n,
                            "chain-event lag during reorg depth count; \
                             falling back to the reorg log",
                        );
                        reorg = match reorg {
                            ReorgTracking::Counting { from_height, disconnected, .. } => {
                                ReorgTracking::LagRecovery {
                                    from_height,
                                    counted: disconnected,
                                    started: Instant::now(),
                                }
                            }
                            // Lag outside a reorg tells us nothing about depth.
                            other => other,
                        };
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
            _ = poll.tick() => {
                // Finalize a truncation reorg that emitted its disconnects and
                // then went quiet (no replacement chain to connect).
                if let ReorgTracking::Counting { from_height, disconnected, started } = reorg
                    && started.elapsed() >= POLL_INTERVAL
                {
                    finish_reorg(
                        &warnings, &publisher, &thresholds,
                        from_height, disconnected, chain_state.tip_height(),
                    );
                    reorg = ReorgTracking::Idle;
                }
                // Resolve a lag-interrupted count against the reorg log, now
                // that the record has had a poll interval to be written and
                // pushed to the ring. Match on the abandoned tip height from
                // the marker rather than taking the newest record, so a reorg
                // that happened earlier in the window cannot be reported as
                // this one.
                if let ReorgTracking::LagRecovery { from_height, counted, started } = reorg
                    && started.elapsed() >= POLL_INTERVAL
                {
                    let exact = chain_state.reorg_log().and_then(|log| {
                        log.history(REORG_LOG_LOOKBACK_SECS)
                            .into_iter()
                            .find(|r| r.fork_height.saturating_add(r.depth) == from_height)
                    });
                    match exact {
                        Some(rec) => finish_reorg(
                            &warnings, &publisher, &thresholds,
                            from_height, rec.depth, chain_state.tip_height(),
                        ),
                        None => {
                            // No matching record: the log is disabled, pruned,
                            // or the write failed. Report the undercount rather
                            // than nothing — a deep reorg that reads shallow is
                            // recoverable by an operator, silence is not — and
                            // mark the depth as a floor so a consumer does not
                            // treat it as exact.
                            tracing::warn!(
                                target: "health",
                                from_height,
                                counted,
                                "no reorg-log record matched a lag-interrupted \
                                 depth count; reporting a lower bound",
                            );
                            finish_reorg_bounded(
                                &warnings, &publisher, &thresholds,
                                from_height, counted, chain_state.tip_height(), false,
                            );
                        }
                    }
                    reorg = ReorgTracking::Idle;
                }
                let age = last_connect.elapsed().as_secs();
                state.last_connect_age_secs.store(age, Ordering::Relaxed);
                check_tip_stall(&state, &warnings, &publisher, &thresholds, &chain_state, age);
                check_disk(&state, &warnings, &publisher, &thresholds, &disk_watch_path);
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
/// `getwarnings` forever. A `cleared` event removes the warning; an `edge` event
/// records one that stays until restart, which is correct for `deep_reorg` — it
/// happened, and nothing "un-happens" it.
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
                let context = serde_json::to_value(&event.details)
                    .unwrap_or(serde_json::Value::Null);
                // An edge observation is a distinct event every time it
                // happens, and its warning never clears — so it must opt out of
                // the first-time-only `-alertnotify` dedup, or only the first
                // deep reorg of a process would ever page anyone.
                if event.state == StatusState::Edge {
                    warnings.record_recurring(&id, severity, event.message.clone(), context);
                } else {
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
    // The latch is evaluated before the disabled check, because it is a
    // property of the node rather than of this detector's configuration.
    // Behind the `threshold == 0` return it would never be set on a node
    // running with the detector off — so enabling `alerttipstallseconds` on an
    // already-wedged node (tip >24h stale, hence "in IBD" again by the
    // predicate below) would wedge the detector permanently, which is the exact
    // failure the latch exists to prevent.
    if !state.left_ibd.load(Ordering::Relaxed) && !in_ibd {
        state.left_ibd.store(true, Ordering::Relaxed);
    }
    let threshold = thresholds.tip_stall_secs();
    if threshold == 0 {
        clear_because_disabled(state, warnings, publisher, StatusKind::TipStall);
        return;
    }
    // During IBD the tip legitimately does not advance for long stretches
    // (header sync, a slow peer, a big block batch). The condition this alert
    // exists for — "a caught-up node stopped following the chain" — is
    // meaningless until IBD is done.
    //
    // The check is latched. `is_initial_block_download()` is not a one-way
    // door: it is a function of wall-clock time against the tip header's
    // timestamp (tip older than ~24h ⇒ "still syncing"), so a node whose tip
    // stops advancing crosses *back* into it a day later. Without the latch a
    // partitioned node would raise `tip_stall` at the 1h mark and then, at the
    // 24h mark, freeze: every later poll would return here before reaching
    // either the raise or the clear branch, so a SIGHUP retune of
    // `alerttipstallseconds` would apply to the atomic and do nothing visible.
    // Once a node has been caught up, it is never "in IBD" again for this
    // detector's purposes.
    if !state.left_ibd.load(Ordering::Relaxed) {
        return;
    }
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

fn check_disk(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    path: &std::path::Path,
) {
    // Sample before any early return, so `satd_disk_free_bytes` is populated
    // whatever the detector's configuration. An operator who sets
    // `alertdiskfreemb=0` has usually done so *because* they alert on the gauge
    // in Prometheus instead of via satd; returning before the filesystem read
    // would delete the series out from under their own rule, silently. An
    // unreadable filesystem reports "unknown" rather than a zero that would
    // read as "completely full".
    let sample = crate::diskspace::free_disk_bytes(path);
    state
        .disk_free_bytes
        .store(sample.unwrap_or(DISK_UNKNOWN), Ordering::Relaxed);
    if let Some(free) = sample
        && free < thresholds.disk_free_bytes()
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

fn finish_reorg(
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    from_height: u32,
    disconnected: u32,
    to_height: u32,
) {
    finish_reorg_bounded(
        warnings,
        publisher,
        thresholds,
        from_height,
        disconnected,
        to_height,
        true,
    );
}

/// As [`finish_reorg`], but able to report a depth that is only a lower bound.
///
/// `depth_exact = false` marks a count that broadcast lag truncated and the
/// reorg log could not confirm. The event still fires — a deep reorg reported
/// shallow is something an operator can act on, silence is not — but the wire
/// says so, because "6 blocks" and "at least 6 blocks" warrant different
/// responses.
fn finish_reorg_bounded(
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    from_height: u32,
    disconnected: u32,
    to_height: u32,
    depth_exact: bool,
) {
    let threshold = thresholds.reorg_depth();
    if threshold == 0 || u64::from(disconnected) < threshold {
        return;
    }
    let qualifier = if depth_exact { "" } else { "at least " };
    emit(
        warnings,
        publisher,
        StatusEvent::edge(
            StatusKind::DeepReorg,
            format!(
                "reorg rolled back {qualifier}{disconnected} blocks (from height \
                 {from_height} to {to_height}; threshold {threshold})"
            ),
        )
        .with_detail("depth", disconnected)
        .with_detail("depth_exact", depth_exact)
        .with_detail("from_height", from_height)
        .with_detail("to_height", to_height)
        .with_detail("fork_height", from_height.saturating_sub(disconnected))
        .with_detail("threshold", threshold),
    );
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

    #[test]
    fn peer_floor_default_is_disabled_only_on_regtest() {
        use bitcoin::Network;
        // A regtest node normally has no peers at all, so defaulting the floor
        // to 3 raises a critical warning 90s into every run that can never
        // clear.
        assert_eq!(defaults::peer_floor_for(Network::Regtest), 0);
        // Signet is a public network with real peers. A peer-starved signet
        // node is broken in exactly the way this alert reports, and defaulting
        // it off would make the detector's silence indistinguishable from
        // health.
        assert_eq!(defaults::peer_floor_for(Network::Signet), defaults::PEER_FLOOR);
        assert_eq!(defaults::peer_floor_for(Network::Bitcoin), defaults::PEER_FLOOR);
        assert_eq!(defaults::peer_floor_for(Network::Testnet4), defaults::PEER_FLOOR);
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

    #[test]
    fn disabling_a_detector_clears_a_standing_condition() {
        // Otherwise turning the threshold off would strand a raised alert that
        // nothing will ever retract.
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 0);

        state.set_active(StatusKind::DiskLow, true);
        warnings.record("alert.disk_low", Severity::Error, "low", serde_json::Value::Null);

        check_disk(
            &state,
            &warnings,
            &pubr,
            &thresholds,
            std::path::Path::new("."),
        );
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

    /// The latch has to be set even while the detector is switched off, or
    /// enabling it on a node that is already wedged — tip >24h stale, hence
    /// "in IBD" again by the predicate — wedges the detector permanently.
    #[test]
    fn enabling_tip_stall_on_a_wedged_node_is_not_blocked_by_the_ibd_latch() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();

        // Detector off, node caught up: nothing is emitted, but the latch must
        // still record that this node has been out of IBD.
        let off = AlertThresholds::new(0, 0, 0, 0, 0);
        check_tip_stall_values(&state, &warnings, &pubr, &off, false, 100, 10);
        assert!(drained(&mut rx).is_empty());
        assert!(
            state.left_ibd.load(Ordering::Relaxed),
            "the latch is a property of the node, not of this detector's config"
        );

        // Node wedges. 30h of no blocks puts it back "in IBD" by the tip-time
        // predicate. Operator enables the detector to find out why nothing is
        // moving — it must raise.
        let on = AlertThresholds::new(3600, 0, 0, 0, 0);
        check_tip_stall_values(&state, &warnings, &pubr, &on, true, 100, 108_000);
        assert_eq!(
            drained(&mut rx),
            vec![(StatusKind::TipStall, StatusState::Raised)],
            "a node that has been caught up is never 'in IBD' again for this \
             detector's purposes"
        );
    }

    /// A node that has never seen a peer gets a grace period, and then a full
    /// hold — not a hold that ran concurrently with the grace.
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
    #[test]
    fn the_disk_gauge_is_sampled_even_when_the_alert_is_disabled() {
        let state = HealthState::new();
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 0);
        assert_eq!(thresholds.disk_free_bytes(), 0, "detector off");

        check_disk(&state, &warnings, &pubr, &thresholds, std::path::Path::new("."));
        assert!(
            state.disk_free_bytes().is_some(),
            "the gauge must be populated whatever the alert's configuration"
        );
    }

    #[test]
    fn deep_reorg_fires_only_at_or_above_the_threshold() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 3);

        finish_reorg(&warnings, &pubr, &thresholds, 100, 2, 101);
        assert!(drained(&mut rx).is_empty(), "a 2-deep reorg is below the floor");

        finish_reorg(&warnings, &pubr, &thresholds, 100, 3, 102);
        assert_eq!(drained(&mut rx), vec![(StatusKind::DeepReorg, StatusState::Edge)]);
    }

    #[test]
    fn deep_reorg_reports_true_depth_and_fork_height() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 1);

        finish_reorg(&warnings, &pubr, &thresholds, 900, 4, 902);
        let env = rx.try_recv().unwrap();
        let NodeEventBody::Status(s) = env.body else {
            panic!("expected a status event")
        };
        assert_eq!(s.details.get("depth").map(String::as_str), Some("4"));
        assert_eq!(s.details.get("from_height").map(String::as_str), Some("900"));
        assert_eq!(s.details.get("to_height").map(String::as_str), Some("902"));
        // fork = old tip height − blocks rolled back.
        assert_eq!(s.details.get("fork_height").map(String::as_str), Some("896"));
    }

    #[test]
    fn deep_reorg_disabled_by_zero_threshold() {
        let warnings = NodeWarnings::new();
        let pubr = publisher();
        let mut rx = pubr.subscribe();
        let thresholds = AlertThresholds::new(0, 0, 0, 0, 0);
        finish_reorg(&warnings, &pubr, &thresholds, 100, 50, 101);
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
