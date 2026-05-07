use parking_lot::RwLock;

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
        let mut rates = self.recent_rates.write();
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
        let rates = self.recent_rates.read();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insufficient_data_returns_none() {
        let est = FeeEstimator::new();
        // No data at all
        assert_eq!(est.estimate_fee(1), None);
        // Less than 10 samples
        est.record_block(&[100, 200, 300]);
        assert_eq!(est.estimate_fee(1), None);
        est.record_block(&[400, 500, 600, 700, 800, 900]);
        // Now 9 samples — still not enough
        assert_eq!(est.estimate_fee(1), None);
    }

    #[test]
    fn test_estimate_target_1() {
        let est = FeeEstimator::new();
        let rates: Vec<u64> = (1..=100).collect();
        est.record_block(&rates);
        // target=1 → 90th percentile. sorted=[1..100], idx = 100*90/100 = 90 → sorted[90] = 91
        let fee = est.estimate_fee(1).unwrap();
        assert_eq!(fee, 91);
    }

    #[test]
    fn test_estimate_target_6() {
        let est = FeeEstimator::new();
        let rates: Vec<u64> = (1..=100).collect();
        est.record_block(&rates);
        // target=6 → 50th percentile. idx = 100*50/100 = 50 → sorted[50] = 51
        let fee = est.estimate_fee(6).unwrap();
        assert_eq!(fee, 51);
    }

    #[test]
    fn test_estimate_target_25() {
        let est = FeeEstimator::new();
        let rates: Vec<u64> = (1..=100).collect();
        est.record_block(&rates);
        // target=25 → 10th percentile. idx = 100*10/100 = 10 → sorted[10] = 11
        let fee = est.estimate_fee(25).unwrap();
        assert_eq!(fee, 11);
    }

    #[test]
    fn test_record_empty_block() {
        let est = FeeEstimator::new();
        est.record_block(&[]);
        // Empty block should be a no-op — still no data
        assert_eq!(est.estimate_fee(1), None);
        // Recording actual data after empty block should work fine
        est.record_block(&[100; 10]);
        assert!(est.estimate_fee(1).is_some());
    }

    #[test]
    fn test_multiple_blocks_accumulate() {
        let est = FeeEstimator::new();
        // Record rates across multiple blocks
        est.record_block(&[10, 20, 30]);
        est.record_block(&[40, 50, 60]);
        est.record_block(&[70, 80, 90, 100]);
        // Total = 10 samples, should be enough for estimation
        assert!(est.estimate_fee(1).is_some());
        // Verify accumulation: sorted = [10,20,30,40,50,60,70,80,90,100]
        // target=6 → 50th percentile → idx=10*50/100=5 → sorted[5]=60
        assert_eq!(est.estimate_fee(6).unwrap(), 60);
    }

    #[test]
    fn test_exactly_10_samples() {
        let est = FeeEstimator::new();
        est.record_block(&[5, 15, 25, 35, 45, 55, 65, 75, 85, 95]);
        // Exactly 10 samples — should return Some
        let fee = est.estimate_fee(3).unwrap();
        // target=3 → 75th percentile. idx = 10*75/100 = 7 → sorted[7] = 75
        assert_eq!(fee, 75);
    }

    #[test]
    fn test_all_same_rate() {
        let est = FeeEstimator::new();
        est.record_block(&[42; 50]);
        // All rates identical — any percentile returns 42
        assert_eq!(est.estimate_fee(0).unwrap(), 42);
        assert_eq!(est.estimate_fee(1).unwrap(), 42);
        assert_eq!(est.estimate_fee(6).unwrap(), 42);
        assert_eq!(est.estimate_fee(12).unwrap(), 42);
        assert_eq!(est.estimate_fee(100).unwrap(), 42);
    }
}
