use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use crate::mempool::estimate::{MAX_SIM_DEPTH, MempoolEstimate, estimate_from_mempool};
use crate::mempool::pool::Mempool;

/// TTL for the cached mempool fee simulation. The simulation (a full mempool
/// clone + up to `MAX_SIM_DEPTH` block packs) is identical across surfaces and
/// across closely-spaced requests; caching it bounds how much work an
/// unauthenticated caller on a public surface (Esplora `/fee-estimates`,
/// Electrum `blockchain.estimatefee`) can force, while keeping estimates fresh
/// enough — fees don't move meaningfully within a few seconds.
pub const FEE_SIM_CACHE_TTL: Duration = Duration::from_secs(3);

/// Simple fee rate estimator.
/// Tracks recent block fee rates and returns percentile-based estimates
/// that vary by confirmation target.
pub struct FeeEstimator {
    /// Recent fee rates observed in confirmed blocks (sat/kvB).
    recent_rates: RwLock<Vec<u64>>,
    /// Maximum number of fee rate samples to retain.
    max_samples: usize,
    /// Short-TTL cache of the mempool block simulation, shared across every
    /// fee surface (they all hold the same `Arc<FeeEstimator>`). See
    /// [`FeeEstimator::cached_mempool_estimate`].
    sim_cache: Mutex<Option<(Instant, Arc<MempoolEstimate>)>>,
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
            sim_cache: Mutex::new(None),
        }
    }

    /// The mempool block simulation, memoized with [`FEE_SIM_CACHE_TTL`].
    ///
    /// On a cache miss this clones the entire mempool (`get_all_entries`) and
    /// runs the block packer to `MAX_SIM_DEPTH` — expensive enough that doing
    /// it per request on an unauthenticated endpoint is a DoS amplifier.
    /// Within the TTL, callers share one `Arc<MempoolEstimate>`. The mutex is
    /// held across the rebuild so concurrent callers past expiry queue behind a
    /// single simulation (no thundering herd), mirroring the Electrum fee
    /// histogram cache. The estimate is always built to `MAX_SIM_DEPTH`, which
    /// answers every target identically regardless of how shallow it is.
    pub fn cached_mempool_estimate(&self, mempool: &Mempool) -> Arc<MempoolEstimate> {
        let mut guard = self.sim_cache.lock();
        let now = Instant::now();
        if let Some((stamped, cached)) = guard.as_ref()
            && now.duration_since(*stamped) < FEE_SIM_CACHE_TTL
        {
            return cached.clone();
        }
        let fresh = Arc::new(estimate_from_mempool(
            mempool.get_all_entries(),
            MAX_SIM_DEPTH,
        ));
        *guard = Some((now, fresh.clone()));
        fresh
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
    fn cached_mempool_estimate_is_shared_within_ttl() {
        let est = FeeEstimator::new();
        let mempool = Mempool::new(300_000_000, 1_000);
        let a = est.cached_mempool_estimate(&mempool);
        let b = est.cached_mempool_estimate(&mempool);
        // Second call within the TTL returns the same cached Arc — no
        // re-simulation, no second mempool clone.
        assert!(Arc::ptr_eq(&a, &b), "estimate must be cached within the TTL");
        // And it is a usable (empty-mempool) simulation.
        assert!(a.sim_blocks.iter().all(|blk| blk.tx_count == 0));
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
