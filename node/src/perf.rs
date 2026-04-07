//! Lightweight IBD performance instrumentation.
//!
//! Atomic counters accumulate between reporting intervals. The connect loop
//! calls `report()` every 1000 blocks to dump a structured summary. Zero
//! overhead on the hot path — just atomic increments.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// IBD performance counters. Create once, share via Arc or reference.
pub struct IbdPerf {
    // Connect path timing (nanoseconds accumulated)
    pub connect_ns: AtomicU64,
    pub connect_count: AtomicU64,

    // Store path timing
    pub store_ns: AtomicU64,
    pub store_count: AtomicU64,

    // Prefetch hit/miss
    pub prefetch_hits: AtomicU64,
    pub prefetch_misses: AtomicU64,

    // Cache stats
    pub cache_dirty_hits: AtomicU64,
    pub cache_clean_hits: AtomicU64,
    pub cache_store_misses: AtomicU64,

    // Flush stats
    pub flush_ns: AtomicU64,
    pub flush_count: AtomicU64,
    pub flush_coins_written: AtomicU64,
    pub flush_fresh_elided: AtomicU64,

    // Script verification
    pub script_verify_ns: AtomicU64,
    pub script_verify_count: AtomicU64,

    // UTXO batch lookup
    pub utxo_batch_ns: AtomicU64,
    pub utxo_batch_keys: AtomicU64,

    // Speculative verification (pipelined prefetch)
    pub spec_verify_skipped: AtomicU64,
    pub spec_verify_rerun: AtomicU64,

    // Last report time
    last_report: std::sync::Mutex<Instant>,

    // Wall-clock milliseconds of the most recent reporting interval.
    // Set by report(), read by the connect loop for ETA calibration.
    pub last_interval_ms: AtomicU64,
}

impl Default for IbdPerf {
    fn default() -> Self {
        Self::new()
    }
}

impl IbdPerf {
    pub fn new() -> Self {
        Self {
            connect_ns: AtomicU64::new(0),
            connect_count: AtomicU64::new(0),
            store_ns: AtomicU64::new(0),
            store_count: AtomicU64::new(0),
            prefetch_hits: AtomicU64::new(0),
            prefetch_misses: AtomicU64::new(0),
            cache_dirty_hits: AtomicU64::new(0),
            cache_clean_hits: AtomicU64::new(0),
            cache_store_misses: AtomicU64::new(0),
            flush_ns: AtomicU64::new(0),
            flush_count: AtomicU64::new(0),
            flush_coins_written: AtomicU64::new(0),
            flush_fresh_elided: AtomicU64::new(0),
            script_verify_ns: AtomicU64::new(0),
            script_verify_count: AtomicU64::new(0),
            utxo_batch_ns: AtomicU64::new(0),
            utxo_batch_keys: AtomicU64::new(0),
            spec_verify_skipped: AtomicU64::new(0),
            spec_verify_rerun: AtomicU64::new(0),
            last_report: std::sync::Mutex::new(Instant::now()),
            last_interval_ms: AtomicU64::new(0),
        }
    }

    /// Log a structured performance summary and reset counters.
    pub fn report(&self, height: u32) {
        let elapsed = {
            let mut last = self.last_report.lock().unwrap();
            let e = last.elapsed();
            *last = Instant::now();
            e
        };
        let elapsed_ms = elapsed.as_millis().max(1) as u64;
        self.last_interval_ms.store(elapsed_ms, Ordering::Relaxed);

        let connect_count = self.connect_count.swap(0, Ordering::Relaxed);
        let connect_ms = self.connect_ns.swap(0, Ordering::Relaxed) / 1_000_000;
        let store_count = self.store_count.swap(0, Ordering::Relaxed);
        let store_ms = self.store_ns.swap(0, Ordering::Relaxed) / 1_000_000;
        let prefetch_hits = self.prefetch_hits.swap(0, Ordering::Relaxed);
        let prefetch_misses = self.prefetch_misses.swap(0, Ordering::Relaxed);
        let dirty_hits = self.cache_dirty_hits.swap(0, Ordering::Relaxed);
        let clean_hits = self.cache_clean_hits.swap(0, Ordering::Relaxed);
        let store_misses = self.cache_store_misses.swap(0, Ordering::Relaxed);
        let flush_count = self.flush_count.swap(0, Ordering::Relaxed);
        let flush_ms = self.flush_ns.swap(0, Ordering::Relaxed) / 1_000_000;
        let flush_coins = self.flush_coins_written.swap(0, Ordering::Relaxed);
        let flush_elided = self.flush_fresh_elided.swap(0, Ordering::Relaxed);
        let verify_count = self.script_verify_count.swap(0, Ordering::Relaxed);
        let verify_ms = self.script_verify_ns.swap(0, Ordering::Relaxed) / 1_000_000;
        let batch_keys = self.utxo_batch_keys.swap(0, Ordering::Relaxed);
        let batch_ms = self.utxo_batch_ns.swap(0, Ordering::Relaxed) / 1_000_000;
        let spec_skipped = self.spec_verify_skipped.swap(0, Ordering::Relaxed);
        let spec_rerun = self.spec_verify_rerun.swap(0, Ordering::Relaxed);

        let total_lookups = dirty_hits + clean_hits + store_misses;
        let cache_hit_pct = if total_lookups > 0 {
            ((dirty_hits + clean_hits) * 100) / total_lookups
        } else {
            0
        };
        let prefetch_total = prefetch_hits + prefetch_misses;
        let prefetch_hit_pct = if prefetch_total > 0 {
            (prefetch_hits * 100) / prefetch_total
        } else {
            0
        };

        let avg_connect_ms = if connect_count > 0 { connect_ms / connect_count } else { 0 };
        let avg_store_ms = if store_count > 0 { store_ms / store_count } else { 0 };

        tracing::info!(
            height,
            "PERF: {connect_count} blocks in {elapsed_ms}ms | \
             connect: {connect_ms}ms total ({avg_connect_ms}ms/blk) | \
             store: {store_count} in {store_ms}ms ({avg_store_ms}ms/blk) | \
             prefetch: {prefetch_hit_pct}% hit ({prefetch_hits}/{prefetch_total}) | \
             cache: {cache_hit_pct}% hit (dirty={dirty_hits} clean={clean_hits} miss={store_misses}) | \
             utxo_batch: {batch_keys} keys in {batch_ms}ms | \
             verify: {verify_count} txs in {verify_ms}ms | \
             spec: {spec_skipped} skipped, {spec_rerun} rerun | \
             flush: {flush_count}x in {flush_ms}ms ({flush_coins} coins, {flush_elided} elided)"
        );
    }
}

/// Time a block of code and add nanoseconds to an atomic counter.
#[macro_export]
macro_rules! perf_time {
    ($counter:expr, $body:expr) => {{
        let _start = std::time::Instant::now();
        let _result = $body;
        $counter.fetch_add(_start.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
        _result
    }};
}
