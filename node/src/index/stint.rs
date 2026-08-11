//! Working-time rate meter shared by the three deferred index backfills.
//!
//! `getindexinfo` reports an `estimated_remaining_seconds` for each of the
//! address, filter and silent-payment backfills. That number used to be
//! `(now - started_at_unix) * (1 - r) / r`, where `started_at_unix` is
//! stamped once by `BackfillHandle::start` and then copied forward by
//! `persist` across every pause, resume and daemon restart. So the elapsed
//! term measured wall-clock since the run was *first* started, not time
//! spent working, and every idle hour was extrapolated as if the walk had
//! been grinding through it. Pausing 48h at r=0.10 and resuming projected
//! 20 days against ~54h of real work left; a week of downtime projected 65
//! days (#546). Measuring progress from taproot activation (#532) made
//! this worse rather than better, because `r` is genuinely small early in
//! a mainnet walk.
//!
//! The fix measures a **stint**: one uninterrupted span of a runner
//! actually walking blocks. A stint is anchored when a runner starts
//! walking, re-anchored when it comes back from a pause, and dropped when
//! it pauses or exits. Rate is `(r_now - r_at_anchor) / stint_elapsed` —
//! the throughput being achieved right now, not an average diluted by idle
//! time.
//!
//! ## Why nothing is persisted
//!
//! #546 suggested persisting an `elapsed_working_seconds` (or a resume
//! height) in the cursor. This deliberately does not: an accumulator has
//! to be flushed periodically or a `kill -9` loses it, and a persisted
//! anchor goes stale across exactly the crash-and-restart case the fix
//! exists for — the process comes back with `state = Running` and an
//! anchor pointing at whenever it last wrote, so the downtime gets counted
//! all over again. An in-memory anchor cannot survive the downtime by
//! construction. The cost is a few seconds of "no estimate" after a
//! restart while the new stint accumulates, and the persisted cursor
//! format is unchanged.
//!
//! Working in progress *ratio* rather than block counts keeps one
//! implementation for all three families, including the address index's
//! two-pass weighting — its ratio is monotone across the pass boundary, so
//! a stint that spans it measures the same way.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Minimum stint length before an estimate is offered.
///
/// Short enough that an operator watching `getindexinfo` after
/// `resumeindex` sees a number almost immediately, long enough to skip the
/// first instants of a stint, where the elapsed term is so small that
/// dividing by it amplifies everything.
///
/// This bounds *elapsed time*, which on its own does not bound the number
/// of blocks sampled — see [`MIN_STINT_PROGRESS`].
pub const MIN_STINT: Duration = Duration::from_secs(2);

/// Minimum forward progress, as a fraction of the whole walk, before an
/// estimate is offered.
///
/// [`MIN_STINT`] alone does not prevent a single block from dominating the
/// rate; it only prevents sub-second sampling. On a mainnet silent-payment
/// walk (~252k blocks) one block is ~4e-6 of the ratio, so a stint that
/// spends its first 2.1s on one large block plus a cold undo read would
/// extrapolate ~6 days, displayed immediately after a resume and then
/// collapsing to minutes on the next poll. Requiring a floor on progress
/// as well means the rate is always averaged over a batch: ~25 blocks on
/// that walk, and proportionally fewer on a shorter one, where a bad
/// estimate is also shorter-lived.
pub const MIN_STINT_PROGRESS: f64 = 0.0001;

#[derive(Debug, Clone, Copy)]
struct Stint {
    began: Instant,
    ratio_at_begin: f64,
}

/// Rate meter for one backfill handle. `None` means no runner is
/// currently walking, which is the correct state to report no ETA from.
#[derive(Default)]
pub struct StintMeter {
    current: Mutex<Option<Stint>>,
}

impl StintMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Anchor a fresh stint at the current progress ratio. Discards any
    /// previous anchor — a re-anchor is exactly what resuming from a
    /// pause needs.
    pub fn begin(&self, ratio_now: f64) {
        *self.current.lock() = Some(Stint {
            began: Instant::now(),
            ratio_at_begin: ratio_now,
        });
    }

    /// Stop the clock. Idempotent: the pause loop calls this on every
    /// iteration for as long as the pause lasts.
    pub fn end(&self) {
        *self.current.lock() = None;
    }

    /// Seconds of work remaining at the rate measured over the current
    /// stint, or `None` when no estimate can be justified: no stint in
    /// flight, too little of it elapsed, or no forward progress within it.
    ///
    /// `ratio_now` is read by the caller before this locks, so the two are
    /// not one atomic snapshot. The dangerous direction is closed:
    /// `progressed <= 0` returns `None`, so an anchor *ahead* of the ratio
    /// passed in degrades to no estimate rather than to a negative or huge
    /// one. The open direction is benign and self-correcting — if a runner
    /// restarts in the gap, a stale-high `ratio_now` against a fresh anchor
    /// reports an ETA that is too small for one poll. It needs the reader
    /// to be preempted for longer than `MIN_STINT` between the two reads,
    /// and the next poll corrects it. Tying them together would mean
    /// threading a generation counter through all three families for a
    /// transient wrong number on a progress display; not worth it.
    pub fn estimate_remaining_secs(&self, ratio_now: f64) -> Option<u64> {
        let stint = (*self.current.lock())?;
        remaining_seconds(stint.began.elapsed(), stint.ratio_at_begin, ratio_now)
    }

    /// Whether a stint is currently anchored.
    #[cfg(test)]
    pub(crate) fn is_anchored(&self) -> bool {
        self.current.lock().is_some()
    }

    /// Shift the current anchor back in time, leaving its *ratio* alone.
    ///
    /// This is what lets a test exercise a stint that the code under test
    /// anchored, rather than one the test anchored for it — back-dating in
    /// place keeps whatever ratio the production path recorded, so a bug
    /// in that path still shows up in the estimate.
    #[cfg(test)]
    pub(crate) fn backdate_anchor(&self, ago: Duration) {
        if let Some(stint) = self.current.lock().as_mut() {
            stint.began = stint.began.checked_sub(ago).unwrap_or(stint.began);
        }
    }

    /// Back-date the anchor so tests can exercise stint lengths without
    /// sleeping. Saturates at the process start instant.
    #[cfg(test)]
    pub(crate) fn begin_backdated(&self, ratio_now: f64, ago: Duration) {
        let began = Instant::now().checked_sub(ago).unwrap_or_else(Instant::now);
        *self.current.lock() = Some(Stint {
            began,
            ratio_at_begin: ratio_now,
        });
    }
}

/// The estimate itself, split out from the clock so it can be tested
/// against exact elapsed times.
fn remaining_seconds(elapsed: Duration, ratio_at_begin: f64, ratio_now: f64) -> Option<u64> {
    if elapsed < MIN_STINT {
        return None;
    }
    if !ratio_now.is_finite() || !ratio_at_begin.is_finite() {
        return None;
    }
    // Already there: no work left to estimate.
    if ratio_now >= 1.0 {
        return None;
    }
    // Too little forward progress in this stint to divide by. Covers the
    // equal case (nothing walked yet), a ratio that went backwards — which
    // a reorg-aborted run could in principle produce — and the handful of
    // blocks whose individual timing would otherwise set the whole rate.
    let progressed = ratio_now - ratio_at_begin;
    if progressed < MIN_STINT_PROGRESS {
        return None;
    }
    let secs = elapsed.as_secs_f64() * ((1.0 - ratio_now) / progressed);
    if !secs.is_finite() {
        return None;
    }
    // Both factors are positive and finite here, so the cast neither
    // saturates in practice nor goes negative.
    Some(secs as u64)
}

/// Ends the stint when dropped. Held by the runner across its whole walk
/// so that every exit path — completion, pause-then-shutdown, `?` on a
/// storage error, or an unwinding panic — leaves the meter with no anchor
/// rather than one that keeps aging while nothing is walking.
///
/// `#[must_use]` because binding it to `_` instead of a named `_stint`
/// drops it immediately, clearing the anchor before the first block is
/// walked and silently disabling every ETA. That is a one-character
/// mistake with no other symptom.
#[must_use = "the stint ends the moment this guard is dropped; bind it for the \
              duration of the walk (`let _stint = ...`), not to `_`"]
pub struct StintGuard(Arc<StintMeter>);

impl StintGuard {
    pub fn new(meter: Arc<StintMeter>, ratio_now: f64) -> Self {
        meter.begin(ratio_now);
        Self(meter)
    }
}

impl Drop for StintGuard {
    fn drop(&mut self) {
        self.0.end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn estimates_from_progress_within_the_stint() {
        // A quarter of the walk in an hour => three quarters left => ~3h.
        let eta = remaining_seconds(HOUR, 0.0, 0.25).expect("estimate");
        assert!(
            (10_700..=10_900).contains(&eta),
            "expected ~10800s, got {eta}"
        );
    }

    /// The bug in #546, stated as a test: what the stint measures must be
    /// the work done *in it*, not the position reached. A backfill resumed
    /// at r=0.10 that reaches r=0.15 in an hour has 0.85 left at
    /// 0.05/hour, i.e. 17 hours — the old formula divided by the absolute
    /// ratio instead and returned 1h * 0.85/0.15 ≈ 5.7h.
    #[test]
    fn rate_is_measured_from_the_anchor_not_from_zero() {
        let eta = remaining_seconds(HOUR, 0.10, 0.15).expect("estimate");
        assert!(
            (61_000..=61_500).contains(&eta),
            "expected ~61200s (17h), got {eta}"
        );
        let from_zero = remaining_seconds(HOUR, 0.0, 0.15).expect("estimate");
        assert!(
            from_zero < eta / 2,
            "anchoring at zero must not reproduce the correct answer \
             ({from_zero} vs {eta}), or this test proves nothing"
        );
    }

    /// The reported symptom, end to end through the meter: run for an
    /// hour to r=0.10, pause 48h, resume, work ten more minutes to r=0.11.
    ///
    /// The old formula got this wrong twice over — it counted the 48h
    /// pause as elapsed working time *and* divided by the absolute ratio —
    /// for `(48h + 10min) * 0.89/0.11` = 1_402_800s, about 16 days against
    /// a real ~15 hours. Re-anchoring on resume is what fixes both: the
    /// clock and the origin move together, so neither term can carry the
    /// pause forward.
    #[test]
    fn a_long_pause_cannot_inflate_the_estimate() {
        let m = StintMeter::new();
        m.begin_backdated(0.0, HOUR);
        m.end(); // operator pauses; 48h of wall-clock passes
        m.begin_backdated(0.10, Duration::from_secs(600));

        let eta = m.estimate_remaining_secs(0.11).expect("estimate");
        // 0.01 of the walk per 600s, 0.89 left => ~53_400s (~15h).
        assert!(
            (52_000..=55_000).contains(&eta),
            "expected ~53400s, got {eta}"
        );
        assert!(
            eta < 1_402_800 / 10,
            "must be nowhere near the pause-inclusive figure, got {eta}"
        );
    }

    #[test]
    fn no_estimate_without_forward_progress() {
        // Nothing walked yet in this stint.
        assert_eq!(remaining_seconds(HOUR, 0.25, 0.25), None);
        // Ratio went backwards.
        assert_eq!(remaining_seconds(HOUR, 0.25, 0.20), None);
    }

    #[test]
    fn no_estimate_before_the_minimum_stint() {
        assert_eq!(remaining_seconds(MIN_STINT - Duration::from_millis(1), 0.0, 0.5), None);
        assert!(remaining_seconds(MIN_STINT, 0.0, 0.5).is_some());
    }

    #[test]
    fn no_estimate_once_complete() {
        assert_eq!(remaining_seconds(HOUR, 0.5, 1.0), None);
        assert_eq!(remaining_seconds(HOUR, 0.5, 1.5), None);
    }

    #[test]
    fn non_finite_ratios_do_not_produce_an_estimate() {
        assert_eq!(remaining_seconds(HOUR, f64::NAN, 0.5), None);
        assert_eq!(remaining_seconds(HOUR, 0.0, f64::NAN), None);
        assert_eq!(remaining_seconds(HOUR, f64::NEG_INFINITY, 0.5), None);
    }

    #[test]
    fn meter_reports_nothing_until_a_stint_is_anchored() {
        let m = StintMeter::new();
        assert_eq!(m.estimate_remaining_secs(0.5), None);
        m.begin_backdated(0.25, HOUR);
        assert!(m.estimate_remaining_secs(0.5).is_some());
        m.end();
        assert_eq!(m.estimate_remaining_secs(0.5), None);
    }

    /// Re-anchoring restarts both the clock and the origin, which is what
    /// makes a resume forget the pause rather than average over it.
    #[test]
    fn re_anchoring_discards_the_previous_stint() {
        let m = StintMeter::new();
        m.begin_backdated(0.0, HOUR);
        m.begin_backdated(0.40, Duration::from_secs(60));
        let eta = m.estimate_remaining_secs(0.50).expect("estimate");
        // 0.10 in 60s => 0.50 left => 300s. The discarded first stint
        // would have given 1h * 0.5/0.5 = 3600s.
        assert!((280..=320).contains(&eta), "expected ~300s, got {eta}");
    }

    /// The guard both *starts* and ends the stint. Constructing it must
    /// anchor at the ratio it was handed — nothing else anchors on the
    /// runner's behalf, so if this call went missing every ETA would be
    /// permanently `None` with no other symptom.
    #[test]
    fn guard_anchors_on_construction_and_clears_on_drop() {
        let m = Arc::new(StintMeter::new());
        assert!(!m.is_anchored());
        {
            let _g = StintGuard::new(m.clone(), 0.25);
            assert!(m.is_anchored(), "constructing the guard must anchor a stint");
            // Back-date in place, so the anchor's *ratio* is still the one
            // the guard recorded. An anchor at 0.0 would give 3600s here.
            m.backdate_anchor(HOUR);
            let eta = m.estimate_remaining_secs(0.50).expect("estimate");
            assert!(
                (7000..=7400).contains(&eta),
                "0.25 walked in 1h leaves 0.50 => ~7200s, got {eta}"
            );
        }
        assert!(
            !m.is_anchored(),
            "the guard must clear the anchor when the runner leaves"
        );
    }

    /// A panicking runner must not leave the meter aging. Same contract as
    /// the drop test, exercised through an unwind because that is the path
    /// a runner bug actually takes.
    #[test]
    fn guard_ends_the_stint_on_unwind() {
        let m = Arc::new(StintMeter::new());
        let m2 = m.clone();
        // AssertUnwindSafe because the meter's interior mutability is the
        // thing under test: the guard's Drop must leave it in the "no
        // stint" state, which is a valid state to observe post-unwind.
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _g = StintGuard::new(m2.clone(), 0.25);
            assert!(m2.is_anchored());
            panic!("runner blew up mid-walk");
        }));
        assert!(res.is_err());
        assert!(!m.is_anchored());
    }

    /// The time floor alone does not bound how many blocks were sampled.
    /// A stint that has been running long enough but has barely moved must
    /// not extrapolate from that sliver.
    #[test]
    fn a_sliver_of_progress_does_not_produce_an_estimate() {
        // One block of a ~252k-block mainnet walk, after a full 2s.
        let one_block = 1.0 / 252_000.0;
        assert_eq!(
            remaining_seconds(Duration::from_millis(2100), 0.30, 0.30 + one_block),
            None,
            "a single block must not set the rate for the whole walk"
        );
        // Either side of the floor. Not *on* it: `(r + p) - r` is not
        // exactly `p` in binary floating point, so an assertion at the
        // exact boundary tests the rounding, not the rule.
        assert_eq!(
            remaining_seconds(HOUR, 0.30, 0.30 + MIN_STINT_PROGRESS * 0.5),
            None
        );
        assert!(remaining_seconds(HOUR, 0.30, 0.30 + MIN_STINT_PROGRESS * 2.0).is_some());
    }
}
