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
    /// Connected peers.
    pub const PEER_FLOOR: u64 = 3;
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
                        // The disconnect run we were counting may be incomplete,
                        // so the depth would be wrong. Abandon this reorg rather
                        // than report a number we cannot stand behind; the tip
                        // clock is re-derived on the next connect regardless.
                        tracing::debug!(
                            target: "health",
                            dropped = n,
                            "chain-event lag; abandoning in-flight reorg depth count",
                        );
                        reorg = ReorgTracking::Idle;
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
                let age = last_connect.elapsed().as_secs();
                state.last_connect_age_secs.store(age, Ordering::Relaxed);
                check_tip_stall(&state, &warnings, &publisher, &thresholds, &chain_state, age);
                check_disk(&state, &warnings, &publisher, &thresholds, &disk_watch_path);
                check_mempool(&state, &warnings, &publisher, &thresholds, &mempool);
                check_peers(
                    &state, &warnings, &publisher, &thresholds, &peer_manager,
                    &mut peers_below_since, &mut peers_ok_since,
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
                warnings.record(&id, severity, event.message.clone(), context);
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
    message: String,
    details: impl FnOnce(StatusEvent) -> StatusEvent,
) {
    if state.is_active(kind) {
        return;
    }
    state.set_active(kind, true);
    emit(warnings, publisher, details(StatusEvent::raised(kind, message)));
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
    clear_if_active(
        state,
        warnings,
        publisher,
        kind,
        format!("{} detector disabled by configuration", kind.as_str()),
        |e| e.with_detail("reason", "detector_disabled"),
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
    let threshold = thresholds.tip_stall_secs();
    if threshold == 0 {
        clear_because_disabled(state, warnings, publisher, StatusKind::TipStall);
        return;
    }
    // During IBD the tip legitimately does not advance for long stretches
    // (header sync, a slow peer, a big block batch). The condition this alert
    // exists for — "a caught-up node stopped following the chain" — is
    // meaningless until IBD is done.
    if chain_state.is_initial_block_download() {
        return;
    }
    if age_secs >= threshold {
        raise_if_new(
            state,
            warnings,
            publisher,
            StatusKind::TipStall,
            format!("no block connected for {age_secs}s (threshold {threshold}s)"),
            |e| {
                e.with_detail("seconds_since_block", age_secs)
                    .with_detail("threshold_seconds", threshold)
                    .with_detail("tip_height", chain_state.tip_height())
            },
        );
    }
    // The clear side is event-driven (on `BlockConnected`), not polled: the
    // whole point is that the alert lifts the instant the chain moves.
}

fn check_disk(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    path: &std::path::Path,
) {
    let floor = thresholds.disk_free_bytes();
    let Some(free) = crate::diskspace::free_disk_bytes(path) else {
        // Unreadable filesystem: report "unknown" rather than a zero that would
        // read as "completely full".
        state.disk_free_bytes.store(DISK_UNKNOWN, Ordering::Relaxed);
        return;
    };
    state.disk_free_bytes.store(free, Ordering::Relaxed);
    if floor == 0 {
        clear_because_disabled(state, warnings, publisher, StatusKind::DiskLow);
        return;
    }
    let clear_at = floor
        .saturating_mul(hysteresis::DISK_CLEAR_RATIO_NUM)
        / hysteresis::DISK_CLEAR_RATIO_DEN;
    if free < floor {
        raise_if_new(
            state,
            warnings,
            publisher,
            StatusKind::DiskLow,
            format!(
                "free space {} MiB below floor {} MiB on {}",
                free / (1024 * 1024),
                floor / (1024 * 1024),
                path.display()
            ),
            |e| {
                e.with_detail("free_bytes", free)
                    .with_detail("threshold_bytes", floor)
                    .with_detail("path", path.display())
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
    }
}

fn check_mempool(
    state: &HealthState,
    warnings: &NodeWarnings,
    publisher: &EventPublisher,
    thresholds: &AlertThresholds,
    mempool: &Mempool,
) {
    let pct = thresholds.mempool_full_pct();
    if pct == 0 {
        clear_because_disabled(state, warnings, publisher, StatusKind::MempoolCongested);
        return;
    }
    let cap = mempool.max_size_bytes() as u64;
    if cap == 0 {
        return;
    }
    let used = mempool.acting_bytes() as u64;
    let raise_at = cap.saturating_mul(pct) / 100;
    let clear_at = raise_at.saturating_mul(hysteresis::MEMPOOL_CLEAR_RATIO_NUM)
        / hysteresis::MEMPOOL_CLEAR_RATIO_DEN;
    if used >= raise_at {
        let min_fee = mempool.min_fee_rate();
        raise_if_new(
            state,
            warnings,
            publisher,
            StatusKind::MempoolCongested,
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
) {
    let floor = thresholds.peer_floor();
    if floor == 0 {
        *below_since = None;
        *ok_since = None;
        clear_because_disabled(state, warnings, publisher, StatusKind::PeerFloor);
        return;
    }
    let total = peer_manager.connection_count() as u64;
    let outbound = peer_manager.outbound_count() as u64;
    let inbound = total.saturating_sub(outbound);
    let now = Instant::now();

    if total < floor {
        *ok_since = None;
        let since = *below_since.get_or_insert(now);
        if now.duration_since(since) >= hysteresis::PEER_HOLD {
            raise_if_new(
                state,
                warnings,
                publisher,
                StatusKind::PeerFloor,
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
    let threshold = thresholds.reorg_depth();
    if threshold == 0 || u64::from(disconnected) < threshold {
        return;
    }
    emit(
        warnings,
        publisher,
        StatusEvent::edge(
            StatusKind::DeepReorg,
            format!(
                "reorg rolled back {disconnected} blocks (from height {from_height} \
                 to {to_height}; threshold {threshold})"
            ),
        )
        .with_detail("depth", disconnected)
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

    /// Exercise `check_disk`'s raise/clear logic against a synthetic free-space
    /// reading, bypassing the real `statvfs`.
    fn sample_disk(
        state: &HealthState,
        warnings: &NodeWarnings,
        publisher: &EventPublisher,
        thresholds: &AlertThresholds,
        free: u64,
    ) {
        let floor = thresholds.disk_free_bytes();
        let clear_at =
            floor.saturating_mul(hysteresis::DISK_CLEAR_RATIO_NUM) / hysteresis::DISK_CLEAR_RATIO_DEN;
        if free < floor {
            raise_if_new(state, warnings, publisher, StatusKind::DiskLow, "low".into(), |e| {
                e.with_detail("free_bytes", free)
            });
        } else if free >= clear_at {
            clear_if_active(state, warnings, publisher, StatusKind::DiskLow, "ok".into(), |e| {
                e.with_detail("free_bytes", free)
            });
        }
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
