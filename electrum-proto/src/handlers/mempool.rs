//! `mempool.*` method handlers.

use parking_lot::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::error::JsonRpcError;
use crate::handlers::blockchain::fee_histogram_buckets;
use crate::state::ElectrumState;

/// Short-TTL cache for the fee histogram.
///
/// Round-1 review M5: each `mempool.get_fee_histogram` call clones
/// every `MempoolEntry` (including the full Transaction blob) before
/// reducing to `(fee_rate, vbytes)` pairs. With a public TCP server
/// and back-to-back wallet polls (~10s cadence in practice), this
/// burns CPU and allocator pressure proportional to mempool size on
/// every connection.
///
/// Mirroring `romanz/electrs`'s short-TTL cache: the first call after
/// expiry rebuilds; subsequent calls within the TTL return the
/// previously-computed JSON. Default TTL = 10 seconds.
pub struct FeeHistogramCache {
    last: Mutex<Option<(Instant, Value)>>,
    ttl: Duration,
}

impl FeeHistogramCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            last: Mutex::new(None),
            ttl,
        }
    }

    /// Return the cached histogram if still within TTL, else call
    /// `build` to produce a fresh one and store it. The mutex
    /// serializes concurrent rebuilds — under load, two requests
    /// past the TTL queue behind a single build, then read the same
    /// fresh value on the wire.
    pub fn get_or_compute<F: FnOnce() -> Value>(&self, build: F) -> Value {
        let mut guard = self.last.lock();
        let now = Instant::now();
        if let Some((stamped, cached)) = guard.as_ref()
            && now.duration_since(*stamped) < self.ttl
        {
            return cached.clone();
        }
        let fresh = build();
        *guard = Some((now, fresh.clone()));
        fresh
    }

    /// Force the next call to rebuild. Exposed for tests; production
    /// callers rely on natural TTL expiry.
    #[cfg(test)]
    pub fn invalidate(&self) {
        *self.last.lock() = None;
    }
}

impl Default for FeeHistogramCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

/// `mempool.get_fee_histogram()` — returns an array of
/// `[fee_per_vbyte, total_vbytes]` pairs in descending fee-rate
/// order. Each row aggregates ~50_000 vbytes of mempool entries by
/// fee rate.
///
/// The result is served from a short-TTL cache
/// ([`FeeHistogramCache`]) to keep wallet polling cheap. The cache
/// lives on [`ElectrumState`] and is shared across connections.
pub fn get_fee_histogram(state: &ElectrumState) -> Result<Value, JsonRpcError> {
    let mempool = state.mempool.clone();
    let value = state
        .fee_histogram_cache
        .get_or_compute(move || compute_fee_histogram(&mempool));
    Ok(value)
}

/// Pure rebuild — drains the mempool snapshot into the histogram
/// JSON. Exposed at module level so the cache (and tests) can
/// invoke the same logic.
pub(crate) fn compute_fee_histogram(mempool: &node::mempool::pool::Mempool) -> Value {
    let entries = mempool.get_all_entries();

    // `MempoolEntry::fee_rate` is sat/kvB (sat per 1000 *virtual* bytes)
    // since PR #355 (`policy::fee_rate_sat_per_kvb`), so sat/vbyte =
    // fee_rate / 1000 (integer divide is fine; clients use the histogram as
    // a fee-rate hint, not for exact accounting). vbyte = ceil(weight / 4)
    // per Bitcoin Core. (The earlier `/250` divisor was for the pre-#355
    // per-weight-unit value and overreported every rate 4×.)
    let pairs: Vec<(u64, u64)> = entries
        .iter()
        .map(|(_txid, entry)| {
            let sats_per_vb = entry.fee_rate / 1000;
            let vbytes = (entry.weight as u64).div_ceil(4);
            (sats_per_vb, vbytes)
        })
        .collect();

    let buckets = fee_histogram_buckets(&pairs);
    serde_json::to_value(&buckets).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_hits_within_ttl() {
        let cache = FeeHistogramCache::new(Duration::from_secs(60));
        let mut count = 0u32;
        let v1 = cache.get_or_compute(|| {
            count += 1;
            serde_json::json!([[100, 50_000]])
        });
        let v2 = cache.get_or_compute(|| {
            count += 1;
            serde_json::json!([[200, 100_000]])
        });
        assert_eq!(count, 1, "second call must hit the cache");
        assert_eq!(v1, v2);
    }

    #[test]
    fn cache_rebuilds_after_invalidate() {
        let cache = FeeHistogramCache::new(Duration::from_secs(60));
        let mut count = 0u32;
        let _ = cache.get_or_compute(|| {
            count += 1;
            serde_json::json!([])
        });
        cache.invalidate();
        let _ = cache.get_or_compute(|| {
            count += 1;
            serde_json::json!([])
        });
        assert_eq!(count, 2);
    }

    #[test]
    fn cache_rebuilds_after_ttl_expiry() {
        // Tiny TTL so we don't sleep long. `get_or_compute` reads the
        // current Instant inside the call, so a second call after a
        // > TTL sleep must rebuild.
        let cache = FeeHistogramCache::new(Duration::from_millis(10));
        let mut count = 0u32;
        let _ = cache.get_or_compute(|| {
            count += 1;
            serde_json::json!([])
        });
        std::thread::sleep(Duration::from_millis(25));
        let _ = cache.get_or_compute(|| {
            count += 1;
            serde_json::json!([])
        });
        assert_eq!(count, 2, "post-expiry call must rebuild");
    }
}
