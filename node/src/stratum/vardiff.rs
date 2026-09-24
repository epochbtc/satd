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
    /// The significance for lowering the difficulty of a miner that has not
    /// had one share accepted since it connected. Its difficulty is only a
    /// guess, so a wrong guess is cheap to correct: a miner that was lowered
    /// too far floods shares and is raised again within a minute. A right
    /// one matters: a slow device at the default difficulty would otherwise
    /// take hours to reach a difficulty at which it can find a share.
    pub first_significance: f64,
}

impl Default for VardiffConfig {
    fn default() -> Self {
        Self {
            target_interval: Duration::from_secs(30),
            significance: 1e-5,
            fine_significance: 1e-3,
            deadband: 1.15,
            max_step: 8,
            fine_min_shares: 40.0,
            first_significance: 1e-2,
        }
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
    /// Whether any share has been accepted since the miner connected.
    ever_accepted: bool,
}

impl Vardiff {
    pub fn new(config: VardiffConfig, initial: u64, now: Instant) -> Self {
        let initial = initial.max(1);
        Self { config, difficulty: initial, floor: 1, since: now, shares: 0.0, ever_accepted: false }
    }

    pub fn difficulty(&self) -> u64 {
        self.difficulty
    }

    /// Count an accepted share judged at `judged_at`.
    pub fn record_share(&mut self, judged_at: u64) {
        self.shares += judged_at.max(1) as f64 / self.difficulty as f64;
        self.ever_accepted = true;
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
        // With no share yet this can only lower the difficulty.
        let first = !self.ever_accepted && off_at(self.config.first_significance);
        if !strong && !established && !first {
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
        // A miner that has submitted: forty shares in twenty seconds raise it.
        let mut v = with_shares(40, 1_000, t0);
        assert_eq!(v.retarget(secs(t0, 20), u64::MAX), Some(8_000));
        // Then silence.
        assert_eq!(v.retarget(secs(t0, 20 + 340), u64::MAX), None);
        assert_eq!(v.retarget(secs(t0, 20 + 350), u64::MAX), Some(1_000));
    }

    /// A miner with no share yet is lowered on much less silence: its
    /// difficulty is a guess. At the default first-share significance that
    /// is about 4.6 expected shares (e^-4.6 ≈ 1e-2), so a device far too
    /// slow for the default difficulty reaches difficulty 1 in minutes.
    #[test]
    fn a_miner_with_no_share_yet_is_lowered_quickly() {
        let t0 = Instant::now();
        let mut v = with_shares(0, 10_000, t0);
        assert_eq!(v.retarget(secs(t0, 130), u64::MAX), None);
        assert_eq!(v.retarget(secs(t0, 140), u64::MAX), Some(1_250));
        let mut t = 140;
        // 1,250 / 8 = 156.25, / 8 = 19.5 → 20, / 8 = 2.5 → 3, then the floor.
        for want in [156, 20, 3, 1] {
            t += 140;
            assert_eq!(v.retarget(secs(t0, t), u64::MAX), Some(want), "at {t} s");
        }
    }

    /// The quick descent is for a miner that has never submitted: after its
    /// first share, a silence is judged at the strict significance.
    #[test]
    fn the_quick_descent_ends_with_the_first_share() {
        let t0 = Instant::now();
        let mut v = with_shares(1, 10_000, t0);
        // One share where 6.7 were expected: p ≈ 0.0098, enough for the
        // first-share significance, nowhere near the strict one.
        assert_eq!(v.retarget(secs(t0, 200), u64::MAX), None);
        // Without the share, the same silence lowers it.
        let mut v = with_shares(0, 10_000, t0);
        assert_eq!(v.retarget(secs(t0, 200), u64::MAX), Some(1_250));
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
    /// high and ten times too low, fifty seeds each (300 runs).
    ///
    /// Every run is within a factor of two of its best difficulty in
    /// [`CONVERGE_FAST_SECS`] when its shares start ten times too fast, and in
    /// [`CONVERGE_SLOW_SECS`] when they start ten times too rare. From the
    /// second hour on, the difficulty of 95% of runs stays within a factor of
    /// two and changes at most four times, with the mean share interval within
    /// 20% of 30 seconds. Checking every ten seconds means a 1-in-100,000 test
    /// is passed by luck now and then, so a few runs make one excursion and
    /// correct it; none moves by more than one step (a factor of eight).
    #[test]
    fn simulated_miners_converge_and_then_hold_steady() {
        let mut failures = Vec::new();
        let mut report = Vec::new();
        let (mut bands, mut retargets, mut intervals) = (Vec::new(), Vec::new(), Vec::new());
        for (label, start, limit) in [("10x too high", 10.0f64, CONVERGE_SLOW_SECS), ("10x too low", 0.1, CONVERGE_FAST_SECS)] {
            let mut converge = Vec::new();
            for hashrate in [100e9, 1.2e12, 100e12] {
                let optimal = hashrate * 30.0 / 4_294_967_296.0;
                let initial = ((optimal * start).round() as u64).max(1);
                for seed in 1..=50u64 {
                    let run = simulate(hashrate, initial, 6.0, 3_600.0, seed * 7_919 + hashrate as u64);
                    let converged = run.converged_secs.unwrap_or(f64::INFINITY);
                    converge.push(converged);
                    bands.push(run.band);
                    retargets.push(run.retargets_after_settling as f64);
                    intervals.push((run.mean_interval - 30.0).abs());
                    if converged > limit || run.band > 8.0 {
                        failures.push(format!(
                            "{hashrate:e} H/s, {label}, seed {seed}: converged {converged:.0} s, band x{:.2}",
                            run.band
                        ));
                    }
                }
            }
            converge.sort_by(f64::total_cmp);
            report.push(format!(
                "{label}: within x2 after median {:.0} s, worst {:.0} s",
                converge[converge.len() / 2],
                converge[converge.len() - 1]
            ));
        }
        let pct = |v: &mut Vec<f64>, p: f64| {
            v.sort_by(f64::total_cmp);
            v[((v.len() - 1) as f64 * p).round() as usize]
        };
        let (band95, band_max) = (pct(&mut bands, 0.95), pct(&mut bands, 1.0));
        let (rt95, rt_max) = (pct(&mut retargets, 0.95), pct(&mut retargets, 1.0));
        let (iv95, iv_max) = (pct(&mut intervals, 0.95), pct(&mut intervals, 1.0));
        report.push(format!(
            "hours 1-6: band p50 x{:.2}, p95 x{band95:.2}, max x{band_max:.2}; changes p95 {rt95}, max {rt_max}; \
             mean interval off by p95 {iv95:.1} s, max {iv_max:.1} s",
            pct(&mut bands, 0.5)
        ));
        println!("{}", report.join("\n"));
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(band95 <= 2.0, "95th-percentile band x{band95:.2}");
        assert!(rt95 <= 4.0, "95th-percentile changes {rt95}");
        assert!(iv95 <= 6.0, "95th-percentile mean-interval error {iv95:.1} s");
    }

    struct Connection {
        /// Seconds from the first connection to the first accepted share.
        first_share_secs: Option<f64>,
        /// Times the idle limit closed the connection.
        drops: u32,
        accepted: u64,
    }

    /// A miner at `hashrate` H/s that connects at `initial` difficulty,
    /// sends nothing but shares, and reconnects one second after being
    /// dropped — at `initial` again, as a real reconnect does. The session is
    /// modelled as the Stratum V1 session runs it: a vardiff check every
    /// [`TICK`], and the idle limit of
    /// [`crate::stratum::miner::miner_idle_timeout`] on the tally's share rate,
    /// counted from the last message the miner sent.
    fn simulate_connection(hashrate: f64, initial: u64, hours: f64, seed: u64) -> Connection {
        use crate::stratum::miner::{MinerTally, miner_idle_timeout};
        let t0 = Instant::now();
        let at = |s: f64| t0 + Duration::from_secs_f64(s);
        let rate = |d: u64| hashrate / (d as f64 * 4_294_967_296.0);
        let mut rng = Rng(seed);
        let end = hours * 3_600.0;
        let mut now = 0.0;
        let (mut first, mut drops, mut accepted) = (None, 0u32, 0u64);
        'connect: while now < end {
            let mut v = Vardiff::new(VardiffConfig::default(), initial, at(now));
            let mut tally = MinerTally::new(at(now));
            let mut last_read = now;
            let mut next_share = now + rng.exp(rate(v.difficulty()));
            let mut next_tick = now + TICK;
            while now < end {
                if next_share < next_tick {
                    now = next_share;
                    tally.accept(at(now), v.difficulty(), v.difficulty() as f64);
                    v.record_share(v.difficulty());
                    last_read = now;
                    accepted += 1;
                    first.get_or_insert(now);
                    next_share = now + rng.exp(rate(v.difficulty()));
                } else {
                    now = next_tick;
                    next_tick += TICK;
                    if v.retarget(at(now), u64::MAX).is_some() {
                        next_share = now + rng.exp(rate(v.difficulty()));
                    }
                    let limit = miner_idle_timeout(tally.share_rate(v.difficulty()));
                    if now - last_read > limit.as_secs_f64() {
                        drops += 1;
                        now += 1.0;
                        continue 'connect;
                    }
                }
            }
        }
        Connection { first_share_secs: first, drops, accepted }
    }

    /// An ESP32-class "lottery" miner at 1 MH/s, connecting at the mainnet
    /// default difficulty of 10,000 without `mining.suggest_difficulty`. At
    /// that difficulty its first share is ten months away. It must be lowered
    /// to difficulty 1 (a share every ~72 minutes) and kept connected there:
    /// before the idle backstop, it was dropped after ten minutes and started
    /// again at 10,000, and never submitted a share.
    #[test]
    fn a_1_mhs_miner_at_the_default_difficulty_gets_shares_and_is_never_dropped() {
        for seed in 1..=16u64 {
            let run = simulate_connection(1e6, 10_000, 48.0, seed * 104_729);
            let first = run.first_share_secs.expect("a first share within 48 hours");
            assert!(first <= 8.0 * 3_600.0, "seed {seed}: first share after {first:.0} s");
            assert_eq!(run.drops, 0, "seed {seed}: dropped");
            assert!(run.accepted >= 20, "seed {seed}: only {} shares in 48 hours", run.accepted);
        }
    }

    /// The same for the classes between: a 7 MH/s device, a 1 GH/s one, a
    /// sub-TH device and a Bitaxe, all from the default difficulty. None is
    /// dropped, and the first share arrives within minutes for all but the
    /// slowest.
    #[test]
    fn miners_from_mhs_to_ths_at_the_default_difficulty_are_never_dropped() {
        for (hashrate, first_within) in [(7e6, 3.0 * 3_600.0), (1e9, 1_200.0), (100e9, 600.0), (1.2e12, 300.0)] {
            for seed in 1..=16u64 {
                let run = simulate_connection(hashrate, 10_000, 24.0, seed * 7_919);
                let first = run.first_share_secs.unwrap_or(f64::INFINITY);
                assert!(first <= first_within, "{hashrate:e} H/s, seed {seed}: first share after {first:.0} s");
                assert_eq!(run.drops, 0, "{hashrate:e} H/s, seed {seed}: dropped {} times", run.drops);
            }
        }
    }

}
