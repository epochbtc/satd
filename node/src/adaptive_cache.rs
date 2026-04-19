//! Adaptive dbcache: a background task that resizes the RocksDB block cache
//! and the CoinCache clean-LRU in response to system memory pressure.
//!
//! Policy — executed every `TICK_INTERVAL`:
//!
//! - **IBD active** (headers_tip - tip > 1000): target budget = `0.40 *
//!   MemAvailable`, clamped to [`MIN_BYTES`, `max_bytes`].
//! - **Near tip**: target budget = `0.25 * MemAvailable`, clamped.
//! - **Sharp MemAvailable drop** (>20% since last tick): contract
//!   immediately to 75% of current budget, bypassing the step limit.
//!
//! The budget is split 1/3 RocksDB block cache, 2/3 CoinCache clean-LRU —
//! matching the static `config::dbcache` partition in `satd/src/main.rs`.
//!
//! The controller is a pure no-op on platforms without `/proc/meminfo` —
//! `memstat::meminfo()` returns `None` and we keep the configured static
//! budget.
//!
//! Safety: the resize APIs on `Store` and `CoinCache` are idempotent and
//! thread-safe; there is no durability or consistency concern here.
//! `CoinCache::resize_clean` evicts coldest entries when shrinking, which
//! is the normal LRU behavior.

use std::sync::Arc;
use std::time::Duration;

use crate::chain::state::ChainState;
use crate::memstat::{MemInfo, meminfo};
use crate::storage::Store;

/// Minimum budget — never contract below this regardless of memory pressure.
pub const MIN_BYTES: u64 = 64 * 1024 * 1024;

/// Controller tick period.
pub const TICK_INTERVAL: Duration = Duration::from_secs(30);

/// Approximate bytes per CoinCache clean-LRU entry (Coin + OutPoint + LRU
/// overhead). Used to convert a byte budget into an entry count.
pub const APPROX_BYTES_PER_CLEAN_COIN: usize = 200;

/// Lag (blocks) past which we consider the node "in IBD".
pub const IBD_LAG_THRESHOLD: u32 = 1000;

/// Parameters for one adaptive sizing decision.
#[derive(Debug, Clone, Copy)]
pub struct DecisionInput {
    pub mem: MemInfo,
    pub prev_available_bytes: Option<u64>,
    pub current_budget_bytes: u64,
    pub max_bytes: u64,
    pub is_ibd: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub new_budget_bytes: u64,
    /// RocksDB block cache portion (1/3 of budget).
    pub rocksdb_bytes: u64,
    /// CoinCache clean LRU portion (2/3 of budget).
    pub coincache_bytes: u64,
    /// True if this tick detected a sharp drop in available memory.
    pub contracted: bool,
}

/// Pure decision function (unit-testable). Given the current memory state
/// and the last-known-available, compute the next target budget.
pub fn decide(input: DecisionInput) -> Decision {
    let fraction = if input.is_ibd { 0.40 } else { 0.25 };
    let mut target = (input.mem.available_bytes as f64 * fraction) as u64;
    target = target.clamp(MIN_BYTES, input.max_bytes);

    let mut contracted = false;
    if let Some(prev) = input.prev_available_bytes
        && prev > 0
    {
        let drop_pct = (prev.saturating_sub(input.mem.available_bytes) as f64) / (prev as f64);
        if drop_pct > 0.20 {
            // Sharp contraction: cap target at 75% of current budget.
            let contracted_target = ((input.current_budget_bytes as f64) * 0.75) as u64;
            target = target.min(contracted_target).max(MIN_BYTES);
            contracted = true;
        }
    }

    // 1/3 RocksDB / 2/3 CoinCache split, matching the static partition.
    let rocksdb_bytes = target / 3;
    let coincache_bytes = target - rocksdb_bytes;
    Decision {
        new_budget_bytes: target,
        rocksdb_bytes,
        coincache_bytes,
        contracted,
    }
}

/// Spawn the adaptive-cache task. Returns immediately.
///
/// Cancels cleanly when `shutdown_rx` fires.
pub fn spawn_adaptive_cache(
    chain_state: Arc<ChainState>,
    max_bytes: u64,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(
            max_mb = max_bytes / 1_000_000,
            "Adaptive dbcache controller started"
        );

        // Sanity: on non-Linux we'll get `None` forever. Log once and bail so
        // we don't wake up every 30s doing nothing.
        if meminfo().is_none() {
            tracing::warn!(
                "Adaptive dbcache: /proc/meminfo unavailable. Staying at the \
                 static configured budget; auto-sizing has no effect on this platform."
            );
            return;
        }

        let mut prev_available: Option<u64> = None;
        let mut current_budget = max_bytes;
        let mut interval = tokio::time::interval(TICK_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // First tick fires immediately — skip it so we can establish a baseline.
        interval.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let Some(mem) = meminfo() else {
                        continue;
                    };
                    let tip = chain_state.tip_height();
                    let headers = chain_state.headers_tip_height().max(tip);
                    let is_ibd = headers.saturating_sub(tip) > IBD_LAG_THRESHOLD;

                    let decision = decide(DecisionInput {
                        mem,
                        prev_available_bytes: prev_available,
                        current_budget_bytes: current_budget,
                        max_bytes,
                        is_ibd,
                    });
                    prev_available = Some(mem.available_bytes);

                    // Only log + apply when the budget would actually change.
                    if decision.new_budget_bytes.abs_diff(current_budget) > MIN_BYTES / 4 {
                        tracing::info!(
                            new_mb = decision.new_budget_bytes / 1_000_000,
                            old_mb = current_budget / 1_000_000,
                            rocksdb_mb = decision.rocksdb_bytes / 1_000_000,
                            coincache_mb = decision.coincache_bytes / 1_000_000,
                            mem_available_mb = mem.available_bytes / 1_000_000,
                            is_ibd,
                            contracted = decision.contracted,
                            "Adaptive dbcache resize"
                        );
                        chain_state
                            .store_ref()
                            .resize_block_cache(decision.rocksdb_bytes as usize);
                        chain_state.store_ref().resize_clean(
                            decision.coincache_bytes as usize / APPROX_BYTES_PER_CLEAN_COIN,
                        );
                        current_budget = decision.new_budget_bytes;
                    }
                }
                _ = shutdown_rx.wait_for(|v| *v) => {
                    tracing::info!("Adaptive dbcache controller shutting down");
                    return;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mb(n: u64) -> u64 {
        n * 1_000_000
    }

    #[test]
    fn ibd_targets_40_percent() {
        let d = decide(DecisionInput {
            mem: MemInfo {
                total_bytes: mb(32_000),
                available_bytes: mb(10_000),
            },
            prev_available_bytes: None,
            current_budget_bytes: mb(4_000),
            max_bytes: mb(8_000),
            is_ibd: true,
        });
        // 0.40 * 10_000 MB = 4_000 MB, within max.
        assert_eq!(d.new_budget_bytes, mb(4_000));
        // Split: 1/3 RocksDB (1_333 MB), 2/3 CoinCache.
        assert_eq!(d.rocksdb_bytes, mb(4_000) / 3);
        assert_eq!(d.coincache_bytes, mb(4_000) - mb(4_000) / 3);
        assert!(!d.contracted);
    }

    #[test]
    fn near_tip_targets_25_percent() {
        let d = decide(DecisionInput {
            mem: MemInfo {
                total_bytes: mb(32_000),
                available_bytes: mb(10_000),
            },
            prev_available_bytes: None,
            current_budget_bytes: mb(4_000),
            max_bytes: mb(8_000),
            is_ibd: false,
        });
        assert_eq!(d.new_budget_bytes, mb(2_500));
    }

    #[test]
    fn max_bytes_caps_target() {
        let d = decide(DecisionInput {
            mem: MemInfo {
                total_bytes: mb(128_000),
                available_bytes: mb(100_000),
            },
            prev_available_bytes: None,
            current_budget_bytes: mb(4_000),
            max_bytes: mb(8_000),
            is_ibd: true,
        });
        assert_eq!(d.new_budget_bytes, mb(8_000), "should hit max cap");
    }

    #[test]
    fn min_bytes_floors_target() {
        let d = decide(DecisionInput {
            mem: MemInfo {
                total_bytes: mb(1_000),
                available_bytes: mb(100),
            },
            prev_available_bytes: None,
            current_budget_bytes: MIN_BYTES,
            max_bytes: mb(4_000),
            is_ibd: false,
        });
        // 0.25 * 100 MB = 25 MB, below MIN_BYTES.
        assert_eq!(d.new_budget_bytes, MIN_BYTES);
    }

    #[test]
    fn sharp_drop_triggers_contraction() {
        let d = decide(DecisionInput {
            mem: MemInfo {
                total_bytes: mb(32_000),
                available_bytes: mb(5_000),
            },
            prev_available_bytes: Some(mb(10_000)),
            // 50% drop in available — should contract
            current_budget_bytes: mb(4_000),
            max_bytes: mb(8_000),
            is_ibd: true,
        });
        assert!(d.contracted);
        // Must not exceed 75% of prior budget.
        assert!(d.new_budget_bytes <= mb(3_000));
        // And must not drop below MIN.
        assert!(d.new_budget_bytes >= MIN_BYTES);
    }

    #[test]
    fn small_drop_does_not_trigger_contraction() {
        let d = decide(DecisionInput {
            mem: MemInfo {
                total_bytes: mb(32_000),
                available_bytes: mb(9_500),
            },
            prev_available_bytes: Some(mb(10_000)),
            // 5% drop — under 20% threshold
            current_budget_bytes: mb(4_000),
            max_bytes: mb(8_000),
            is_ibd: true,
        });
        assert!(!d.contracted);
    }
}
