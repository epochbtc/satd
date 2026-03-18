use std::sync::RwLock;

/// Simple fee rate estimator.
/// Tracks recent block fee rates and returns percentile-based estimates.
pub struct FeeEstimator {
    /// Recent fee rates observed in confirmed blocks (sat/kvB).
    recent_rates: RwLock<Vec<u64>>,
    /// Maximum number of blocks to track.
    max_blocks: usize,
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
            max_blocks: 1000,
        }
    }

    /// Record fee rates from a confirmed block.
    pub fn record_block(&self, fee_rates: Vec<u64>) {
        let mut rates = self.recent_rates.write().unwrap();
        rates.extend(fee_rates);
        // Keep only recent entries
        if rates.len() > self.max_blocks * 100 {
            let drain_to = rates.len() - self.max_blocks * 50;
            rates.drain(..drain_to);
        }
    }

    /// Estimate the fee rate (sat/kvB) needed for confirmation within `target` blocks.
    /// Returns None if insufficient data.
    pub fn estimate_fee(&self, _target: u32) -> Option<u64> {
        let rates = self.recent_rates.read().unwrap();
        if rates.is_empty() {
            return None;
        }

        let mut sorted = rates.clone();
        sorted.sort();

        // Return the median fee rate as a simple estimate
        let median_idx = sorted.len() / 2;
        Some(sorted[median_idx])
    }
}
