//! Weight-aware IBD ETA estimator.
//!
//! Bitcoin mainnet blocks vary ~50x in processing cost across the chain's
//! history.  A flat "remaining_blocks / current_rate" ETA oscillates wildly
//! because early blocks are trivial while modern blocks are heavy.
//!
//! This module uses a **cost-weight table** — one weight per 1000-block
//! interval — that models relative processing cost.  The estimator
//! calibrates against observed wall-clock time as the sync progresses,
//! producing a stable, converging ETA.
//!
//! ## Formula
//!
//! ```text
//! remaining_weight = Σ weight[i]  for intervals from current_height to target
//! calibration      = mean(observed[i] / weight[i])  over last N intervals
//! eta_secs         = remaining_weight × calibration
//! ```

use std::time::Instant;

/// Number of blocks per weight-table interval.
const INTERVAL: u32 = 1000;

/// Number of recent intervals used to compute the calibration factor.
const CALIBRATION_WINDOW: usize = 10;

// ---------------------------------------------------------------------------
// Mainnet cost-weight table
// ---------------------------------------------------------------------------

/// Relative processing cost for each 1000-block range of Bitcoin mainnet.
/// Index `i` covers heights `[i*1000, (i+1)*1000)`.
///
/// Values capture the dominant cost drivers: block size, transaction count,
/// UTXO set churn, and script complexity.  They reflect the common case of
/// `--assumevalid` enabled (script verification skipped for historical
/// blocks), so the weights primarily model deserialization, UTXO lookups,
/// and I/O cost.
///
/// Precision is not critical — the 50x ratio between genesis-era and modern
/// blocks is what eliminates the oscillation.  The adaptive calibration
/// compensates for hardware differences and any table inaccuracy.
fn mainnet_weight(interval: usize) -> f32 {
    let h = interval as f32;
    match interval {
        // Genesis through early Bitcoin (2009-2012): near-empty blocks
        0..170 => 1.0,
        // Growing adoption (2012-2014): tens to hundreds of txs
        170..250 => lerp(1.0, 5.0, (h - 170.0) / 80.0),
        // Pre-SegWit growth (2014-2016): hundreds to ~2000 txs per block
        250..400 => lerp(5.0, 15.0, (h - 250.0) / 150.0),
        // Peak pre-SegWit (2016-2017): heavy multisig, ~1 MB blocks
        400..480 => lerp(15.0, 25.0, (h - 400.0) / 80.0),
        // SegWit activation and adoption (2017-2019)
        480..550 => lerp(25.0, 35.0, (h - 480.0) / 70.0),
        // Mature SegWit (2019-2021): 1-2 MB effective blocks
        550..680 => lerp(35.0, 40.0, (h - 550.0) / 130.0),
        // Taproot era (2021-2023): growing block sizes
        680..780 => lerp(40.0, 50.0, (h - 680.0) / 100.0),
        // Ordinals / inscriptions (2023-2024): 2-4 MB blocks
        780..840 => lerp(50.0, 60.0, (h - 780.0) / 60.0),
        // Current era (2024+)
        840..1000 => 55.0,
        // Future — assume current-era cost
        _ => 55.0,
    }
}

#[inline]
fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t.clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Estimator
// ---------------------------------------------------------------------------

pub struct IbdEtaEstimator {
    /// Height when this estimator was created (session start).
    start_height: u32,
    /// Wall-clock time when this estimator was created.
    start_time: Instant,
    /// Observed wall-clock seconds for each 1000-block interval.
    /// Indexed by `height / 1000`.  `None` = not yet observed.
    observed: Vec<Option<f64>>,
    /// Whether we're on mainnet (true) or a test network (flat weights).
    mainnet: bool,
}

impl IbdEtaEstimator {
    /// Create a new estimator.
    ///
    /// `start_height`: current tip when IBD begins (0 for fresh sync).
    /// `target_height`: highest known header height.
    /// `mainnet`: true for mainnet, false for signet/testnet/regtest.
    pub fn new(start_height: u32, target_height: u32, mainnet: bool) -> Self {
        let n_intervals = (target_height / INTERVAL + 1) as usize;
        Self {
            start_height,
            start_time: Instant::now(),
            observed: vec![None; n_intervals.max(1)],
            mainnet,
        }
    }

    /// Record the wall-clock time for a completed 1000-block interval.
    ///
    /// `height`: the height just connected (should be a multiple of 1000).
    /// `wall_secs`: seconds it took to process this 1000-block interval.
    pub fn record_interval(&mut self, height: u32, wall_secs: f64) {
        let idx = (height / INTERVAL) as usize;
        if idx < self.observed.len() {
            self.observed[idx] = Some(wall_secs);
        }
    }

    /// Estimate remaining seconds to reach `target_height`.
    ///
    /// Returns `None` if insufficient data (no observed intervals yet).
    pub fn estimate_eta(&self, current_height: u32, target_height: u32) -> Option<u64> {
        if current_height >= target_height {
            return Some(0);
        }

        let current_interval = (current_height / INTERVAL) as usize;
        let target_interval = (target_height / INTERVAL) as usize;

        // Remaining weight (from current position to target)
        let remaining_weight = self.cumulative_weight(current_interval, target_interval);
        if remaining_weight < 0.001 {
            return Some(0);
        }

        // Try calibration from recent observed intervals
        if let Some(cal) = self.calibration_factor(current_interval) {
            return Some((remaining_weight * cal) as u64);
        }

        // Fallback: use total elapsed time and total work done since start
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed < 1.0 {
            return None;
        }
        let start_interval = (self.start_height / INTERVAL) as usize;
        let work_done = self.cumulative_weight(start_interval, current_interval);
        if work_done < 0.001 {
            return None;
        }
        let rate = work_done / elapsed;
        Some((remaining_weight / rate) as u64)
    }

    /// Sum of weights from interval `from` (inclusive) to `to` (exclusive).
    fn cumulative_weight(&self, from: usize, to: usize) -> f64 {
        (from..to).map(|i| f64::from(self.weight(i))).sum()
    }

    /// Weight for a single interval.
    fn weight(&self, interval: usize) -> f32 {
        if self.mainnet {
            mainnet_weight(interval)
        } else {
            1.0
        }
    }

    /// Compute calibration factor from recent observed intervals.
    ///
    /// Returns `Some(seconds_per_weight_unit)` if we have enough data,
    /// `None` otherwise.
    fn calibration_factor(&self, current_interval: usize) -> Option<f64> {
        let mut ratios = Vec::new();

        // Walk backwards from current interval, collecting observed ratios
        let start = current_interval.saturating_sub(CALIBRATION_WINDOW);
        for i in start..current_interval {
            if let Some(obs_secs) = self.observed.get(i).copied().flatten() {
                let w = f64::from(self.weight(i));
                if w > 0.001 {
                    ratios.push(obs_secs / w);
                }
            }
        }

        if ratios.is_empty() {
            return None;
        }

        // Mean of observed ratios = seconds per weight-unit
        let sum: f64 = ratios.iter().sum();
        Some(sum / ratios.len() as f64)
    }
}

/// Format an ETA in seconds to a human-readable string.
pub fn format_eta(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{h}h {m:02}m")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weight_table_monotonic_trend() {
        // Weights should generally increase across Bitcoin history
        let early = mainnet_weight(50);   // height 50k
        let mid = mainnet_weight(350);    // height 350k
        let late = mainnet_weight(800);   // height 800k
        assert!(early < mid, "early={early} should be < mid={mid}");
        assert!(mid < late, "mid={mid} should be < late={late}");
    }

    #[test]
    fn weight_table_ratio() {
        // Modern blocks should be at least 30x heavier than genesis-era
        let genesis = mainnet_weight(10);
        let modern = mainnet_weight(820);
        assert!(modern / genesis >= 30.0,
            "modern/genesis ratio = {}, expected >= 30", modern / genesis);
    }

    #[test]
    fn lerp_basics() {
        assert!((lerp(0.0, 10.0, 0.0) - 0.0).abs() < 0.001);
        assert!((lerp(0.0, 10.0, 0.5) - 5.0).abs() < 0.001);
        assert!((lerp(0.0, 10.0, 1.0) - 10.0).abs() < 0.001);
        // Clamping
        assert!((lerp(0.0, 10.0, -0.5) - 0.0).abs() < 0.001);
        assert!((lerp(0.0, 10.0, 1.5) - 10.0).abs() < 0.001);
    }

    #[test]
    fn cumulative_weight_range() {
        let est = IbdEtaEstimator::new(0, 900_000, true);
        let early = est.cumulative_weight(0, 100);   // 0-100k
        let late = est.cumulative_weight(700, 800);   // 700k-800k
        // Late range should be much heavier
        assert!(late > early * 10.0,
            "late={late}, early={early}, expected late > 10 * early");
    }

    #[test]
    fn eta_with_observations() {
        let mut est = IbdEtaEstimator::new(0, 500_000, true);
        // Simulate processing intervals 0..10 (heights 0-10k)
        // Each taking 0.5 seconds (fast hardware for trivial blocks)
        for i in 0..10 {
            est.record_interval(i * 1000, 0.5);
        }
        // Current height 10k, target 500k
        let eta = est.estimate_eta(10_000, 500_000).unwrap();
        // With calibration factor 0.5s per weight-unit (from trivial blocks),
        // remaining ~4040 weight-units → ~2020s.  The key property: the ETA
        // is MUCH longer than a naive "remaining_blocks / blk_per_sec" would
        // give (490k blocks / 2000 bps ≈ 245s), because the weight table
        // properly accounts for heavier blocks ahead.
        assert!(eta > 1000, "eta={eta}s, expected > 1000 (weight-aware)");
        assert!(eta < 10_000, "eta={eta}s, suspiciously high");
    }

    #[test]
    fn eta_with_heavy_observations() {
        let mut est = IbdEtaEstimator::new(700_000, 900_000, true);
        // Simulate processing at height 700k-710k, heavy blocks: 30 secs each
        for i in 700..710 {
            est.record_interval(i * 1000, 30.0);
        }
        let eta = est.estimate_eta(710_000, 900_000).unwrap();
        // ~190 intervals remaining, at roughly similar weight → ~190 * 30s calibrated
        // Should be in the ballpark of 1-3 hours
        assert!(eta > 3600, "eta={eta}s");
        assert!(eta < 20_000, "eta={eta}s, suspiciously high");
    }

    #[test]
    fn eta_at_target() {
        let est = IbdEtaEstimator::new(0, 900_000, true);
        assert_eq!(est.estimate_eta(900_000, 900_000), Some(0));
        assert_eq!(est.estimate_eta(950_000, 900_000), Some(0));
    }

    #[test]
    fn eta_flat_weights_for_testnet() {
        let mut est = IbdEtaEstimator::new(0, 100_000, false);
        for i in 0..10 {
            est.record_interval(i * 1000, 1.0);
        }
        let eta = est.estimate_eta(10_000, 100_000).unwrap();
        // Flat weights: 90 remaining intervals * 1.0s each = 90s
        assert!((85..=95).contains(&eta), "eta={eta}s, expected ~90");
    }

    #[test]
    fn format_eta_display() {
        assert_eq!(format_eta(45), "45s");
        assert_eq!(format_eta(125), "2m 5s");
        assert_eq!(format_eta(3661), "1h 01m");
        assert_eq!(format_eta(7800), "2h 10m");
    }
}
