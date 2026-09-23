//! Per-connection variable difficulty.
//!
//! Each connection's share difficulty is steered so the miner submits about
//! one share per [`VardiffConfig::target_interval`], whatever its hashrate:
//! often enough to see that it is working, rarely enough not to flood the
//! node.
//!
//! Shares arrive at random, so a short window says little: a miner exactly on
//! target submits three shares in 90 seconds only on average, and a window
//! that happens to hold seven reads as a miner at more than twice its real
//! speed. Reacting to every such window made the difficulty wander across a
//! factor of seventeen within an hour on one device.
//!
//! So the difficulty changes only when the shares since the last change are
//! **significantly** off target: when a Poisson count at the target rate
//! would fall that far from what was seen with probability at most
//! [`VardiffConfig::significance`]. The evidence needed shrinks with the size
//! of the error, which gives both behaviours wanted. A miner that is wildly
//! off — a new device at a difficulty ten times too low, or one that stopped
//! submitting — is corrected within seconds or minutes; a miner close to
//! target is left alone until many shares show a real difference. Other
//! Stratum servers get the same shape from fixed thresholds: the SRI pool's
//! vardiff acts on a 100% error after 15 seconds but on a 15% error only
//! after five minutes, and ckpool leaves the difficulty alone while the share
//! rate is inside a hysteresis band and reconsiders it only every 72 shares
//! or four minutes. Two further guards bound what one change can do: a
//! deadband ([`VardiffConfig::deadband`]) under which a significant but small
//! error is not worth a change, and a cap on the step
//! ([`VardiffConfig::max_step`]).
//!
//! A looser significance ([`VardiffConfig::fine_significance`]) applies once
//! [`VardiffConfig::fine_min_shares`] shares were expected since the last
//! change. The strict level has to be strict because the difficulty is
//! checked every few seconds and every look is another chance for luck to
//! pass it; on its own it would leave a miner 20% off target for hours. With
//! forty expected shares behind it a move is both well founded and accurate.

use std::time::{Duration, Instant};

/// Vardiff tuning.
#[derive(Debug, Clone)]
pub struct VardiffConfig {
    /// Desired time between shares.
    pub target_interval: Duration,
    /// How unlikely, for a miner exactly on target, the shares since the last
    /// change must be before the difficulty moves. One-sided, per direction.
    /// Strict, because the difficulty is checked every few seconds and every
    /// look is another chance for luck to pass it.
    pub significance: f64,
    /// A looser level that also moves the difficulty once
    /// [`VardiffConfig::fine_min_shares`] were expected since the last change:
    /// by then the shares pin the rate down well enough that a move lands
    /// close to the target.
    pub fine_significance: f64,
    /// Share rates within this factor of the target, either way, are left
    /// alone however long they have been observed.
    pub deadband: f64,
    /// Largest factor one retarget may move the difficulty, up or down.
    pub max_step: u64,
    /// How many shares must have been expected since the last change before
    /// [`VardiffConfig::fine_significance`] applies.
    pub fine_min_shares: f64,
}

impl Default for VardiffConfig {
    fn default() -> Self {
        Self { target_interval: Duration::from_secs(30), significance: 1e-5, fine_significance: 1e-3, deadband: 1.15, max_step: 8, fine_min_shares: 40.0 }
    }
}

/// Largest difficulty a miner may suggest.
pub const MAX_SUGGESTED_DIFFICULTY: u64 = 1 << 48;

/// One connection's vardiff state.
#[derive(Debug, Clone)]
pub struct Vardiff {
    config: VardiffConfig,
    difficulty: u64,
    floor: u64,
    /// When the difficulty last changed (or the miner connected).
    since: Instant,
    /// Shares accepted since then, each weighted by the difficulty it was
    /// judged at over the current difficulty: a share judged at the old
    /// difficulty after a change still counts for the work it proves.
    shares: f64,
}

impl Vardiff {
    pub fn new(config: VardiffConfig, initial: u64, now: Instant) -> Self {
        let initial = initial.max(1);
        Self { config, difficulty: initial, floor: 1, since: now, shares: 0.0 }
    }

    pub fn difficulty(&self) -> u64 {
        self.difficulty
    }

    /// Count an accepted share judged at `judged_at`.
    pub fn record_share(&mut self, judged_at: u64) {
        self.shares += judged_at.max(1) as f64 / self.difficulty as f64;
    }

    /// A miner's `suggest_difficulty`: clamp it to `[1, 2^48]`, adopt it now
    /// and keep it as the floor vardiff will not go below. Returns the
    /// difficulty adopted.
    pub fn suggest(&mut self, suggested: u64, now: Instant) -> u64 {
        let d = suggested.clamp(1, MAX_SUGGESTED_DIFFICULTY);
        self.floor = d;
        self.set(d, now);
        d
    }

    fn set(&mut self, difficulty: u64, now: Instant) {
        self.difficulty = difficulty;
        self.since = now;
        self.shares = 0.0;
    }

    /// Reconsider the difficulty. Cheap; call it every few seconds. `ceiling`
    /// is the network difficulty: a share target harder than the block target
    /// means nothing. Returns the new difficulty when it changed.
    pub fn retarget(&mut self, now: Instant, ceiling: u64) -> Option<u64> {
        let elapsed = now.saturating_duration_since(self.since).as_secs_f64();
        let expected = elapsed / self.config.target_interval.as_secs_f64();
        if expected <= 0.0 {
            return None;
        }
        // Shares per target interval: above one, the difficulty is too low.
        let ratio = self.shares / expected;
        // Rounded towards "on target", so rounding never manufactures evidence.
        let (fast, slow) = (self.shares.floor() as u64, self.shares.ceil() as u64);
        let off_at = |alpha: f64| {
            poisson_at_least(fast, expected) <= alpha || poisson_at_most(slow, expected) <= alpha
        };
        let strong = off_at(self.config.significance);
        let established =
            expected >= self.config.fine_min_shares && off_at(self.config.fine_significance);
        if !strong && !established {
            return None;
        }
        let band = self.config.deadband.max(1.0);
        if ratio > 1.0 / band && ratio < band {
            return None;
        }
        let step = self.config.max_step.max(1) as f64;
        let factor = ratio.clamp(1.0 / step, step);
        let current = self.difficulty;
        let proposed = (current as f64 * factor).round();
        let proposed = if proposed >= u64::MAX as f64 { u64::MAX } else { proposed as u64 };
        let next = proposed.max(1).max(self.floor).min(ceiling.max(1));
        // Either way the evidence has been acted on; start counting afresh.
        self.set(next, now);
        (next != current).then_some(next)
    }
}

/// `P(N <= k)` for `N ~ Poisson(lambda)`.
fn poisson_at_most(k: u64, lambda: f64) -> f64 {
    if lambda > 200.0 || k > 400 {
        // Normal approximation with a continuity correction; accurate to far
        // better than the significance levels used here at these sizes.
        return normal_cdf((k as f64 + 0.5 - lambda) / lambda.sqrt());
    }
    let mut term = (-lambda).exp();
    let mut sum = term;
    for i in 1..=k {
        term *= lambda / i as f64;
        sum += term;
    }
    sum.min(1.0)
}

/// `P(N >= k)` for `N ~ Poisson(lambda)`.
fn poisson_at_least(k: u64, lambda: f64) -> f64 {
    if k == 0 { 1.0 } else { (1.0 - poisson_at_most(k - 1, lambda)).max(0.0) }
}

/// The standard normal CDF, from the Abramowitz and Stegun 7.1.26 `erf`
/// approximation (absolute error below 1.5e-7).
fn normal_cdf(z: f64) -> f64 {
    let x = z.abs() / std::f64::consts::SQRT_2;
    let t = 1.0 / (1.0 + 0.327_591_1 * x);
    let poly = t * (0.254_829_592 + t * (-0.284_496_736 + t * (1.421_413_741 + t * (-1.453_152_027 + t * 1.061_405_429))));
    let erf = 1.0 - poly * (-x * x).exp();
    if z >= 0.0 { 0.5 * (1.0 + erf) } else { 0.5 * (1.0 - erf) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(t0: Instant, s: u64) -> Instant {
        t0 + Duration::from_secs(s)
    }

    fn with_shares(n: u64, difficulty: u64, t0: Instant) -> Vardiff {
        let mut v = Vardiff::new(VardiffConfig::default(), difficulty, t0);
        (0..n).for_each(|_| v.record_share(difficulty));
        v
    }

    #[test]
    fn poisson_tails_match_known_values() {
        // P(N = 0 | 3) = e^-3.
        assert!((poisson_at_most(0, 3.0) - (-3.0f64).exp()).abs() < 1e-12);
        // P(N <= 2 | 3) = e^-3 (1 + 3 + 4.5) = 0.42319...
        assert!((poisson_at_most(2, 3.0) - 0.423_190_081_126_844_4).abs() < 1e-12);
        assert!((poisson_at_least(3, 3.0) - (1.0 - 0.423_190_081_126_844_4)).abs() < 1e-12);
        assert_eq!(poisson_at_least(0, 3.0), 1.0);
        // The normal branch agrees with the exact sum where both apply.
        let exact = poisson_at_most(220, 200.0 - 1e-9);
        let approx = poisson_at_most(220, 200.0 + 1e-9);
        assert!((exact - approx).abs() < 5e-3, "{exact} vs {approx}");
        assert!((normal_cdf(0.0) - 0.5).abs() < 1e-7);
        assert!((normal_cdf(-3.0) - 0.001_349_898).abs() < 2e-7);
    }

    /// The live defect: seven shares in 90 seconds where three were wanted.
    /// The old fixed window more than doubled the difficulty on it; chance
    /// produces it about 3% of the time, so nothing moves.
    #[test]
    fn an_unlucky_window_does_not_move_the_difficulty() {
        let t0 = Instant::now();
        let mut v = with_shares(7, 9_600, t0);
        assert_eq!(v.retarget(secs(t0, 90), u64::MAX), None);
        // Nor does a quiet 90 seconds.
        let mut v = with_shares(0, 9_600, t0);
        assert_eq!(v.retarget(secs(t0, 90), u64::MAX), None);
    }

    /// A miner far off target is corrected as soon as the evidence is in,
    /// not at the end of a fixed window: forty shares in the first twenty
    /// seconds of a connection whose difficulty is far too low.
    #[test]
    fn a_miner_far_off_target_is_corrected_within_seconds() {
        let t0 = Instant::now();
        let mut v = with_shares(40, 1_000, t0);
        assert_eq!(v.retarget(secs(t0, 20), u64::MAX), Some(8_000));
    }

    /// A miner that stops submitting has its difficulty lowered, so a miner
    /// that is still hashing gets shares it can find. At the default
    /// significance that takes a silence of about 11.5 expected shares
    /// (e^-11.5 ≈ 1e-5).
    #[test]
    fn a_silent_miner_has_its_difficulty_lowered() {
        let t0 = Instant::now();
        let mut v = with_shares(0, 10_000, t0);
        assert_eq!(v.retarget(secs(t0, 340), u64::MAX), None);
        assert_eq!(v.retarget(secs(t0, 350), u64::MAX), Some(1_250));
    }

    /// One retarget moves the difficulty by at most `max_step`, however far
    /// off the miner is.
    #[test]
    fn one_retarget_moves_at_most_max_step() {
        let t0 = Instant::now();
        let mut v = with_shares(10_000, 1_000, t0);
        assert_eq!(v.retarget(secs(t0, 90), u64::MAX), Some(8_000));
        let mut v = with_shares(0, 1_000, t0);
        assert_eq!(v.retarget(secs(t0, 3_600), u64::MAX), Some(125));
    }

    /// A small error, however well established, is not worth a change: 2,100
    /// shares in 20 hours where 2,400 were wanted is overwhelming evidence
    /// (z ≈ -6.1) of a rate 12.5% slow, inside the deadband. 1,800, 25% slow,
    /// is outside it.
    #[test]
    fn a_small_established_error_is_left_alone() {
        let t0 = Instant::now();
        let hours = 20 * 3_600;
        let mut v = with_shares(2_100, 1_000, t0);
        assert_eq!(v.retarget(secs(t0, hours), u64::MAX), None);
        let mut v = with_shares(1_800, 1_000, t0);
        assert_eq!(v.retarget(secs(t0, hours), u64::MAX), Some(750));
    }

    /// A moderate error is corrected on the looser significance once forty
    /// shares were expected: 35 in 30 minutes where 60 were wanted
    /// (p ≈ 8e-4). The strict level alone would still be waiting.
    #[test]
    fn an_established_moderate_error_is_corrected() {
        let t0 = Instant::now();
        let mut v = with_shares(35, 1_000, t0);
        assert_eq!(v.retarget(secs(t0, 1_800), u64::MAX), Some(583));
    }

    /// The looser significance needs its evidence: one share in five
    /// minutes where ten were wanted (p ≈ 5e-4) passes it, but ten expected
    /// shares are too few to act on, and the strict level is not met.
    #[test]
    fn the_looser_significance_waits_for_enough_shares() {
        let t0 = Instant::now();
        let mut v = with_shares(1, 1_000, t0);
        assert_eq!(v.retarget(secs(t0, 300), u64::MAX), None);
    }

    #[test]
    fn never_above_the_network_or_below_the_floor() {
        let t0 = Instant::now();
        let mut v = with_shares(100, 1_000, t0);
        assert_eq!(v.retarget(secs(t0, 90), 1_500), Some(1_500));
        let mut v = Vardiff::new(VardiffConfig::default(), 1_000, t0);
        assert_eq!(v.suggest(800, t0), 800);
        assert_eq!(v.retarget(secs(t0, 3_600), u64::MAX), None, "floor holds");
        assert_eq!(v.suggest(u64::MAX, t0), MAX_SUGGESTED_DIFFICULTY);
        assert_eq!(v.suggest(0, t0), 1);
    }

    /// Shares judged at an older difficulty count for the work they prove:
    /// ten shares judged at four times the current difficulty in five
    /// minutes are forty where ten were wanted.
    #[test]
    fn shares_are_weighted_by_the_difficulty_they_were_judged_at() {
        let t0 = Instant::now();
        let mut v = Vardiff::new(VardiffConfig::default(), 1_000, t0);
        (0..10).for_each(|_| v.record_share(4_000));
        assert_eq!(v.retarget(secs(t0, 300), u64::MAX), Some(4_000));
    }

    // ── Simulation ──────────────────────────────────────────────────────

    /// SplitMix64: a small, fixed, seedable generator, so the simulation is
    /// the same on every run and every platform.
    struct Rng(u64);
    impl Rng {
        fn next_f64(&mut self) -> f64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            ((z >> 11) as f64 + 0.5) / (1u64 << 53) as f64
        }
        /// An exponential wait with the given rate.
        fn exp(&mut self, rate: f64) -> f64 {
            -self.next_f64().ln() / rate
        }
    }

    /// How quickly a miner whose shares come ten times too fast must be
    /// within a factor of two of its best difficulty.
    const CONVERGE_FAST_SECS: f64 = 90.0;
    /// The same for shares ten times too rare.
    const CONVERGE_SLOW_SECS: f64 = 40.0 * 60.0;

    /// The session loop's vardiff tick.
    const TICK: f64 = 10.0;

    struct Run {
        /// First time, in seconds, the difficulty was within 2× of optimal.
        converged_secs: Option<f64>,
        /// Largest over smallest difficulty after the settling time.
        band: f64,
        retargets_after_settling: u32,
        /// Mean seconds between shares after the settling time.
        mean_interval: f64,
    }

    /// Simulate a miner at `hashrate` H/s starting at `initial` difficulty for
    /// `hours`, with shares as a Poisson process and a retarget check every
    /// [`TICK`]. Statistics after `settle` seconds describe steady state.
    fn simulate(hashrate: f64, initial: u64, hours: f64, settle: f64, seed: u64) -> Run {
        simulate_with(VardiffConfig::default(), hashrate, initial, hours, settle, seed)
    }

    fn simulate_with(config: VardiffConfig, hashrate: f64, initial: u64, hours: f64, settle: f64, seed: u64) -> Run {
        let t0 = Instant::now();
        let at = |s: f64| t0 + Duration::from_secs_f64(s);
        let optimal = hashrate * 30.0 / 4_294_967_296.0;
        let rate = |d: u64| hashrate / (d as f64 * 4_294_967_296.0);
        let mut rng = Rng(seed);
        let mut v = Vardiff::new(config, initial, t0);
        let end = hours * 3_600.0;
        let mut now = 0.0;
        let mut next_share = rng.exp(rate(v.difficulty()));
        let mut next_tick = TICK;
        let mut converged = None;
        let (mut lo, mut hi) = (u64::MAX, 0u64);
        let (mut shares, mut retargets) = (0u64, 0u32);
        while now < end {
            if next_share < next_tick {
                now = next_share;
                v.record_share(v.difficulty());
                if now >= settle {
                    shares += 1;
                }
                next_share = now + rng.exp(rate(v.difficulty()));
            } else {
                now = next_tick;
                next_tick += TICK;
                if v.retarget(at(now), u64::MAX).is_some() {
                    if now >= settle {
                        retargets += 1;
                    }
                    // Memoryless: redraw at the new difficulty.
                    next_share = now + rng.exp(rate(v.difficulty()));
                }
            }
            let d = v.difficulty() as f64;
            if converged.is_none() && d <= 2.0 * optimal && d >= optimal / 2.0 {
                converged = Some(now);
            }
            if now >= settle {
                lo = lo.min(v.difficulty());
                hi = hi.max(v.difficulty());
            }
        }
        Run {
            converged_secs: converged,
            band: hi as f64 / lo as f64,
            retargets_after_settling: retargets,
            mean_interval: (end - settle) / shares.max(1) as f64,
        }
    }

    /// Six simulated hours at three hashrates, from a difficulty ten times too
    /// high and ten times too low, sixteen seeds each. A miner whose shares
    /// come too fast is within a factor of two of its best difficulty in
    /// [`CONVERGE_FAST_SECS`]; one whose shares are too rare, in
    /// [`CONVERGE_SLOW_SECS`] (its evidence arrives at its slow rate). From
    /// the second hour on the difficulty holds within a factor of two and
    /// changes at most five times, with the mean share interval within 20%
    /// of 30 seconds.
    #[test]
    fn simulated_miners_converge_and_then_hold_steady() {
        let mut failures = Vec::new();
        let mut report = Vec::new();
        for (label, start, limit) in [("10x too high", 10.0f64, CONVERGE_SLOW_SECS), ("10x too low", 0.1, CONVERGE_FAST_SECS)] {
            let (mut converge, mut worst_band, mut worst_interval, mut most_retargets) = (Vec::new(), 1.0f64, 0.0f64, 0u32);
            for hashrate in [100e9, 1.2e12, 100e12] {
                let optimal = hashrate * 30.0 / 4_294_967_296.0;
                let initial = ((optimal * start).round() as u64).max(1);
                for seed in 1..=16u64 {
                    let run = simulate(hashrate, initial, 6.0, 3_600.0, seed * 7_919 + hashrate as u64);
                    let converged = run.converged_secs.unwrap_or(f64::INFINITY);
                    converge.push(converged);
                    worst_band = worst_band.max(run.band);
                    worst_interval = worst_interval.max((run.mean_interval - 30.0).abs());
                    most_retargets = most_retargets.max(run.retargets_after_settling);
                    if converged > limit
                        || run.band > 2.0
                        || (run.mean_interval - 30.0).abs() > 6.0
                        || run.retargets_after_settling > 5
                    {
                        failures.push(format!(
                            "{hashrate:e} H/s, {label}, seed {seed}: converged {converged:.0} s, band x{:.2}, \
                             mean interval {:.1} s, {} retargets",
                            run.band, run.mean_interval, run.retargets_after_settling
                        ));
                    }
                }
            }
            converge.sort_by(f64::total_cmp);
            report.push(format!(
                "{label}: converged median {:.0} s, worst {:.0} s; hours 1-6 band x{worst_band:.2}, \
                 mean interval off by at most {worst_interval:.1} s, at most {most_retargets} retargets",
                converge[converge.len() / 2],
                converge[converge.len() - 1]
            ));
        }
        println!("{}", report.join("\n"));
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
