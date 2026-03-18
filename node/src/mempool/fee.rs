use std::sync::RwLock;

/// Simple fee rate estimator.
/// Tracks recent block fee rates and returns percentile-based estimates
/// that vary by confirmation target.
pub struct FeeEstimator {
    /// Recent fee rates observed in confirmed blocks (sat/kvB).
    recent_rates: RwLock<Vec<u64>>,
    /// Maximum number of fee rate samples to retain.
    max_samples: usize,
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl FeeEstimator {
    pub fn new() -> Self {
        Self {
            recent_rates: RwLock::new(Vec::new()),
            max_samples: 100_000,
        }
    }

    /// Record fee rates from a confirmed block.
    pub fn record_block(&self, fee_rates: &[u64]) {
        if fee_rates.is_empty() {
            return;
        }
        let mut rates = self.recent_rates.write().unwrap();
        rates.extend_from_slice(fee_rates);
        // Keep only recent samples
        if rates.len() > self.max_samples {
            let drain_to = rates.len() - self.max_samples;
            rates.drain(..drain_to);
        }
    }

    /// Estimate the fee rate (sat/kvB) needed for confirmation within `target` blocks.
    ///
    /// Lower targets return higher percentiles (more aggressive fee).
    /// Returns None if insufficient data.
    pub fn estimate_fee(&self, target: u32) -> Option<u64> {
        let rates = self.recent_rates.read().unwrap();
        if rates.len() < 10 {
            return None;
        }

        let mut sorted = rates.clone();
        sorted.sort();

        // Map target to percentile: lower target = higher fee needed
        let percentile = match target {
            0..=1 => 90,   // next block: 90th percentile
            2..=3 => 75,   // 2-3 blocks: 75th
            4..=6 => 50,   // 4-6 blocks: median
            7..=12 => 25,  // 7-12 blocks: 25th
            _ => 10,       // 13+ blocks: 10th percentile
        };

        let idx = (sorted.len() * percentile / 100).min(sorted.len() - 1);
        Some(sorted[idx])
    }
}
