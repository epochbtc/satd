//! Per-phase heartbeat for the IBD connect path.
//!
//! Background: the stall watchdog (`node/src/stall_watchdog.rs`) detects
//! that the chain tip hasn't advanced for `stall_threshold` seconds via a
//! single `connect_heartbeat` counter on `ChainState`. The counter is
//! bumped *once per successful block connect*, so when a stall fires the
//! operator knows the connect loop iteration didn't complete — but not
//! which step of the iteration is wedged. The 2026-05-11 incident
//! (#178) is the second time this has bitten us, and the resulting
//! forensics dump (95 thread states from `/proc/self/task`) was not by
//! itself sufficient to pinpoint the wedge phase.
//!
//! This module adds a finer-grained tracker: an atomic phase enum plus
//! the wall-clock timestamp at which the connector entered that phase.
//! Both are updated as the connector traverses `connect_preprocessed_block`
//! and the internals of `connect::connect_block`. The watchdog reads them
//! when it dumps forensics so the operator gets a single line like
//! `phase=verify_join, phase_age_ms=298400` — definitive proof that the
//! connector wedged waiting for parallel script verification workers to
//! join.
//!
//! Per-phase entry counts are also tracked. During normal operation they
//! distribute roughly proportionally to the wall-clock cost of each phase
//! and form a built-in profiler for the connect hot path; on a stall the
//! per-phase deltas since the previous heartbeat tell us how far the
//! current iteration progressed before getting stuck.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Distinct phases of the IBD connect path. Ordered roughly by the
/// sequence the connector visits them in.
///
/// Variants 0–9 cover the inside of `connect_preprocessed_block` /
/// `connect::connect_block`. Variants 10–14 cover the outer
/// `block_processor` loop: waiting for headers, waiting for block
/// data, condvar park, flush calls. The outer phases were added after
/// the first deployment of the inner tracker showed `phase=idle` at
/// wedge time — `idle` was the connect-block tracker's resting state,
/// but the connector itself was wedged outside `connect_block`
/// entirely. With the outer phases we get a unique non-idle phase no
/// matter where in the loop the wedge fires.
///
/// `Idle` is now a true resting state — only set briefly between
/// `TipWrite` and the next loop iteration, so `phase=idle` at wedge
/// time means the wedge is in code we haven't instrumented yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectPhase {
    Idle = 0,
    EnterConnect = 1,
    PreResolveCoins = 2,
    PerTxValidate = 3,
    VerifyDispatch = 4,
    VerifyJoin = 5,
    ShadowDispatch = 6,
    PostVerifyChecks = 7,
    WriteBatch = 8,
    TipWrite = 9,
    /// block_processor: no header yet for next_height; waiting on
    /// connect_signal condvar (1s timeout).
    WaitingForHeader = 10,
    /// block_processor: header present but `has_block_data` returned
    /// false; waiting on connect_signal condvar.
    WaitingForBlockData = 11,
    /// block_processor: idle wait (everything caught up).
    CondvarWait = 12,
    /// block_processor: flushing coin cache to RocksDB (can take seconds
    /// for large dirty sets during IBD).
    FlushingCoinCache = 13,
    /// block_processor: durable flush at IBD completion (RocksDB sync).
    FlushDurable = 14,
}

impl ConnectPhase {
    /// Stable short name for logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::EnterConnect => "enter_connect",
            Self::PreResolveCoins => "pre_resolve_coins",
            Self::PerTxValidate => "per_tx_validate",
            Self::VerifyDispatch => "verify_dispatch",
            Self::VerifyJoin => "verify_join",
            Self::ShadowDispatch => "shadow_dispatch",
            Self::PostVerifyChecks => "post_verify_checks",
            Self::WriteBatch => "write_batch",
            Self::TipWrite => "tip_write",
            Self::WaitingForHeader => "waiting_for_header",
            Self::WaitingForBlockData => "waiting_for_block_data",
            Self::CondvarWait => "condvar_wait",
            Self::FlushingCoinCache => "flushing_coin_cache",
            Self::FlushDurable => "flush_durable",
        }
    }

    /// Inverse of `as u8` for the watchdog's snapshot iteration. Returns
    /// `Idle` for unknown indices — chosen over `None` so the watchdog
    /// dump never panics on a malformed counter (which would silently
    /// suppress the forensics that are the whole reason this exists).
    pub const fn from_index(i: usize) -> Self {
        match i {
            1 => Self::EnterConnect,
            2 => Self::PreResolveCoins,
            3 => Self::PerTxValidate,
            4 => Self::VerifyDispatch,
            5 => Self::VerifyJoin,
            6 => Self::ShadowDispatch,
            7 => Self::PostVerifyChecks,
            8 => Self::WriteBatch,
            9 => Self::TipWrite,
            10 => Self::WaitingForHeader,
            11 => Self::WaitingForBlockData,
            12 => Self::CondvarWait,
            13 => Self::FlushingCoinCache,
            14 => Self::FlushDurable,
            _ => Self::Idle,
        }
    }

    /// Total number of phase variants — used to size the counts array.
    pub const COUNT: usize = 15;
}

/// Lock-free tracker for the connector's current phase. Held by an
/// `Arc` on `ChainState` so the watchdog (a separate `std::thread`)
/// can observe it without sharing a runtime with the connector.
///
/// All operations are `Relaxed`-ordered atomics. Strict ordering between
/// the phase byte and the entry timestamp isn't required because:
/// - The watchdog reads each field at most a few times per dump and
///   tolerates seeing a slightly inconsistent pair (e.g. phase=X but
///   timestamp from phase Y) — the age-in-phase derived from a slight
///   mismatch is at most a few microseconds off, well below the
///   resolution at which a 300-second stall is interesting.
/// - The hot path (the connector) sees only its own writes, so
///   intra-thread ordering is what matters there and that's already
///   guaranteed by program order.
pub struct ConnectPhaseTracker {
    phase: AtomicU8,
    entered_unix_nanos: AtomicU64,
    counts: [AtomicU64; ConnectPhase::COUNT],
}

impl Default for ConnectPhaseTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectPhaseTracker {
    pub fn new() -> Self {
        Self {
            phase: AtomicU8::new(ConnectPhase::Idle as u8),
            entered_unix_nanos: AtomicU64::new(now_unix_nanos()),
            counts: [(); ConnectPhase::COUNT].map(|_| AtomicU64::new(0)),
        }
    }

    /// Record that the connector has entered `phase`. Stamps the
    /// wall-clock instant and bumps the per-phase entry counter.
    /// Called several times per block — keep the work cheap.
    pub fn enter(&self, phase: ConnectPhase) {
        self.phase.store(phase as u8, Ordering::Relaxed);
        self.entered_unix_nanos
            .store(now_unix_nanos(), Ordering::Relaxed);
        self.counts[phase as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Phase the connector last entered. Returns `Idle` if the counter
    /// has somehow been corrupted (the watchdog must never panic).
    pub fn current(&self) -> ConnectPhase {
        ConnectPhase::from_index(self.phase.load(Ordering::Relaxed) as usize)
    }

    /// Unix nanoseconds at which the connector last called `enter`.
    pub fn entered_unix_nanos(&self) -> u64 {
        self.entered_unix_nanos.load(Ordering::Relaxed)
    }

    /// Age of the current phase entry in milliseconds, computed against
    /// the current wall clock. Returns 0 if the system clock has gone
    /// backwards (e.g. after an NTP step) — we'd rather show "0ms" than
    /// a wraparound near `u64::MAX`.
    pub fn entered_age_ms(&self) -> u64 {
        let now = now_unix_nanos();
        let entered = self.entered_unix_nanos();
        now.saturating_sub(entered) / 1_000_000
    }

    /// Snapshot of per-phase entry counts. Used by the watchdog to log
    /// where the connector spends its iterations during normal operation
    /// and which phases it actually reached during a stalled iteration.
    pub fn snapshot_counts(&self) -> [u64; ConnectPhase::COUNT] {
        let mut out = [0u64; ConnectPhase::COUNT];
        for (i, c) in self.counts.iter().enumerate() {
            out[i] = c.load(Ordering::Relaxed);
        }
        out
    }
}

/// Wall-clock nanoseconds since the unix epoch. Returns 0 on the rare
/// SystemTime error path (e.g. clock before epoch) — the tracker
/// callers tolerate 0 gracefully (it just makes `entered_age_ms` large).
fn now_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_updates_phase_and_timestamp() {
        let t = ConnectPhaseTracker::new();
        assert_eq!(t.current(), ConnectPhase::Idle);

        t.enter(ConnectPhase::VerifyJoin);
        assert_eq!(t.current(), ConnectPhase::VerifyJoin);
        // Age should be ~0ms — we just set it.
        assert!(t.entered_age_ms() < 100, "age was {}ms", t.entered_age_ms());

        // Counts isolate per-phase.
        let counts = t.snapshot_counts();
        assert_eq!(counts[ConnectPhase::VerifyJoin as usize], 1);
        assert_eq!(counts[ConnectPhase::Idle as usize], 0);
    }

    #[test]
    fn from_index_maps_round_trip() {
        for v in 0..ConnectPhase::COUNT {
            let phase = ConnectPhase::from_index(v);
            assert_eq!(phase as usize, v);
        }
        // Bogus indices clamp to Idle, never panic.
        assert_eq!(ConnectPhase::from_index(255), ConnectPhase::Idle);
    }

    #[test]
    fn counts_accumulate() {
        let t = ConnectPhaseTracker::new();
        for _ in 0..5 {
            t.enter(ConnectPhase::VerifyDispatch);
            t.enter(ConnectPhase::VerifyJoin);
        }
        let counts = t.snapshot_counts();
        assert_eq!(counts[ConnectPhase::VerifyDispatch as usize], 5);
        assert_eq!(counts[ConnectPhase::VerifyJoin as usize], 5);
    }
}
