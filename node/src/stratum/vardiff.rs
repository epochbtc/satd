//! Per-connection variable difficulty.
//!
//! Each connection's share difficulty is steered so the miner submits about
//! one share per [`VardiffConfig::target_interval`], whatever its hashrate:
//! often enough to see that it is working, rarely enough not to flood the
//! node.

use std::time::{Duration, Instant};

/// Vardiff tuning.
#[derive(Debug, Clone)]
pub struct VardiffConfig {
    /// Desired time between shares.
    pub target_interval: Duration,
    /// How long shares are counted before the difficulty is reconsidered.
    pub retarget_window: Duration,
    /// Largest factor one retarget may move the difficulty, up or down.
    pub max_step: u64,
}

impl Default for VardiffConfig {
    fn default() -> Self {
        Self {
            target_interval: Duration::from_secs(30),
            retarget_window: Duration::from_secs(90),
            max_step: 4,
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
    window_start: Instant,
    shares: u64,
}

impl Vardiff {
    pub fn new(config: VardiffConfig, initial: u64, now: Instant) -> Self {
        let initial = initial.max(1);
        Self { config, difficulty: initial, floor: 1, window_start: now, shares: 0 }
    }

    pub fn difficulty(&self) -> u64 {
        self.difficulty
    }

    /// Count an accepted share.
    pub fn record_share(&mut self) {
        self.shares += 1;
    }

    /// A miner's `suggest_difficulty`: clamp it to `[1, 2^48]`, adopt it now
    /// and keep it as the floor vardiff will not go below. Returns the
    /// difficulty adopted.
    pub fn suggest(&mut self, suggested: u64, now: Instant) -> u64 {
        let d = suggested.clamp(1, MAX_SUGGESTED_DIFFICULTY);
        self.floor = d;
        self.difficulty = d;
        self.window_start = now;
        self.shares = 0;
        d
    }

    /// Reconsider the difficulty once a full window has passed. `ceiling` is
    /// the network difficulty: a share target harder than the block target
    /// means nothing. Returns the new difficulty when it changed.
    pub fn retarget(&mut self, now: Instant, ceiling: u64) -> Option<u64> {
        let elapsed = now.saturating_duration_since(self.window_start);
        if elapsed < self.config.retarget_window {
            return None;
        }
        let expected = elapsed.as_secs_f64() / self.config.target_interval.as_secs_f64();
        let scale = self.shares as f64 / expected;
        let step = self.config.max_step.max(1);
        let current = self.difficulty;
        let lo = (current / step).max(1);
        let hi = current.saturating_mul(step);
        let proposed = (current as f64 * scale).round();
        let proposed = if proposed >= u64::MAX as f64 { u64::MAX } else { proposed as u64 };
        let mut next = proposed.clamp(lo, hi).max(self.floor);
        next = next.min(ceiling.max(1));
        self.window_start = now;
        self.shares = 0;
        if next != current {
            self.difficulty = next;
            Some(next)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vardiff_scales_within_clamp() {
        let t0 = Instant::now();
        let cfg = VardiffConfig::default();

        // Nothing happens inside the window.
        let mut v = Vardiff::new(cfg.clone(), 1_000, t0);
        v.record_share();
        assert_eq!(v.retarget(t0 + Duration::from_secs(89), u64::MAX), None);

        // 100 shares in 90 s where 3 were wanted: up, but by at most ×4.
        let mut v = Vardiff::new(cfg.clone(), 1_000, t0);
        (0..100).for_each(|_| v.record_share());
        assert_eq!(v.retarget(t0 + Duration::from_secs(90), u64::MAX), Some(4_000));

        // Silence: down by at most ÷4.
        let mut v = Vardiff::new(cfg.clone(), 1_000, t0);
        assert_eq!(v.retarget(t0 + Duration::from_secs(90), u64::MAX), Some(250));

        // Six shares where three were wanted: doubles, unclamped.
        let mut v = Vardiff::new(cfg.clone(), 1_000, t0);
        (0..6).for_each(|_| v.record_share());
        assert_eq!(v.retarget(t0 + Duration::from_secs(90), u64::MAX), Some(2_000));

        // On target: unchanged.
        let mut v = Vardiff::new(cfg.clone(), 1_000, t0);
        (0..3).for_each(|_| v.record_share());
        assert_eq!(v.retarget(t0 + Duration::from_secs(90), u64::MAX), None);

        // Never above the network difficulty, never below the suggested floor.
        let mut v = Vardiff::new(cfg.clone(), 1_000, t0);
        (0..100).for_each(|_| v.record_share());
        assert_eq!(v.retarget(t0 + Duration::from_secs(90), 1_500), Some(1_500));
        let mut v = Vardiff::new(cfg, 1_000, t0);
        assert_eq!(v.suggest(800, t0), 800);
        assert_eq!(v.retarget(t0 + Duration::from_secs(90), u64::MAX), None, "floor holds");
        assert_eq!(v.suggest(u64::MAX, t0), MAX_SUGGESTED_DIFFICULTY);
        assert_eq!(v.suggest(0, t0), 1);
    }
}
