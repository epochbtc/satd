//! Per-principal rate-limit + watch-set-quota traits, and the no-op accounting
//! used by unlimited (operator / loopback) principals.
//!
//! This module defines the *seam* (SATD_AUTH_PLAN.md §7): all enforcement goes
//! through the [`RateLimiter`] / [`QuotaStore`] traits so call sites never
//! hardcode local accounting. The in-process token-bucket / occupancy default
//! implementations — and the wiring that enforces them at each surface — land
//! in a later PR; this PR ships only the traits plus the unlimited no-op so the
//! [`Principal`](crate::Principal) API is stable from the start.

use std::sync::Arc;

/// A parsed `rate_limit = "<n>/s"` policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RatePolicy {
    /// Token-bucket capacity (max burst).
    pub burst: u32,
    /// Sustained refill rate, tokens per second.
    pub per_sec: u32,
}

impl RatePolicy {
    /// Parse the `auth.toml` form `"<n>/s"` (e.g. `"200/s"`). Burst is set equal
    /// to the per-second rate. Returns the original string on failure.
    pub fn parse(s: &str) -> Result<RatePolicy, String> {
        let body = s
            .trim()
            .strip_suffix("/s")
            .ok_or_else(|| s.to_string())?;
        let n: u32 = body.trim().parse().map_err(|_| s.to_string())?;
        if n == 0 {
            return Err(s.to_string());
        }
        Ok(RatePolicy {
            burst: n,
            per_sec: n,
        })
    }
}

/// The outcome of a rate-limit check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateDecision {
    /// Within budget — proceed.
    Allow,
    /// Over budget — shed (HTTP 429 / gRPC `RESOURCE_EXHAUSTED`). Never enqueue
    /// or stall; that would let a consumption surface backpressure the node.
    Throttle {
        /// Suggested `Retry-After`, seconds.
        retry_after_secs: u32,
    },
}

/// Per-principal request rate limiting. The local default is a token bucket; a
/// future Redis-backed limiter is a drop-in (fail-open to local).
pub trait RateLimiter: Send + Sync {
    /// Charge one request against `principal_id`'s bucket under `policy`.
    fn check(&self, principal_id: &str, policy: &RatePolicy) -> RateDecision;
}

/// A watch-set quota was exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaExceeded {
    /// Units currently held by the principal.
    pub current: u64,
    /// Units requested by this acquisition.
    pub requested: u64,
    /// The principal's ceiling.
    pub max: u64,
}

/// Per-principal watch-set occupancy: stateful units (outpoints + scripts) a
/// tenant holds across all its connections. Increment on watch, decrement on
/// release; a local backend reconciles on disconnect for free via the RAII
/// [`WatchLease`].
pub trait QuotaStore: Send + Sync {
    /// Reserve `n` units for `principal_id` if it keeps it at or under `max`.
    fn try_acquire(&self, principal_id: &str, n: u64, max: u64) -> Result<(), QuotaExceeded>;
    /// Return `n` units (called by [`WatchLease::drop`]).
    fn release(&self, principal_id: &str, n: u64);
    /// Units currently held by `principal_id` (diagnostics / tests).
    fn current(&self, principal_id: &str) -> u64;
}

/// RAII handle holding `n` watch units for a principal. Dropping it (connection
/// close, crash unwind) returns the units, giving disconnect reconciliation in
/// the local backend without an explicit cleanup path.
pub struct WatchLease {
    store: Arc<dyn QuotaStore>,
    principal_id: Arc<str>,
    n: u64,
}

impl WatchLease {
    /// Acquire a lease, charging `n` units against `max`.
    pub fn acquire(
        store: Arc<dyn QuotaStore>,
        principal_id: Arc<str>,
        n: u64,
        max: u64,
    ) -> Result<WatchLease, QuotaExceeded> {
        store.try_acquire(&principal_id, n, max)?;
        Ok(WatchLease {
            store,
            principal_id,
            n,
        })
    }

    /// Units this lease holds.
    pub fn units(&self) -> u64 {
        self.n
    }
}

impl Drop for WatchLease {
    fn drop(&mut self) {
        self.store.release(&self.principal_id, self.n);
    }
}

/// A principal's accounting handle: bundles its rate limiter and quota store so
/// the two survive across the principal's multiple connections. Held as an
/// `Arc<dyn Accounting>` on [`Principal`](crate::Principal).
pub trait Accounting: Send + Sync {
    /// The rate limiter for this principal.
    fn rate(&self) -> &dyn RateLimiter;
    /// The watch-set quota store for this principal.
    fn quota(&self) -> Arc<dyn QuotaStore>;
}

/// No-op accounting for unlimited principals (operator, loopback): every rate
/// check allows, every quota acquisition succeeds.
#[derive(Debug, Default)]
pub struct UnlimitedAccounting;

impl RateLimiter for UnlimitedAccounting {
    fn check(&self, _principal_id: &str, _policy: &RatePolicy) -> RateDecision {
        RateDecision::Allow
    }
}

impl QuotaStore for UnlimitedAccounting {
    fn try_acquire(&self, _principal_id: &str, _n: u64, _max: u64) -> Result<(), QuotaExceeded> {
        Ok(())
    }
    fn release(&self, _principal_id: &str, _n: u64) {}
    fn current(&self, _principal_id: &str) -> u64 {
        0
    }
}

impl Accounting for UnlimitedAccounting {
    fn rate(&self) -> &dyn RateLimiter {
        self
    }
    fn quota(&self) -> Arc<dyn QuotaStore> {
        Arc::new(UnlimitedAccounting)
    }
}

/// A shared `Arc<dyn Accounting>` pointing at the unlimited no-op, so every
/// operator/loopback principal reuses one allocation rather than minting a ZST
/// `Arc` each time.
pub(crate) fn unlimited() -> Arc<dyn Accounting> {
    use std::sync::OnceLock;
    static UNLIMITED: OnceLock<Arc<UnlimitedAccounting>> = OnceLock::new();
    UNLIMITED.get_or_init(|| Arc::new(UnlimitedAccounting)).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_policy_parse() {
        assert_eq!(RatePolicy::parse("200/s").unwrap(), RatePolicy { burst: 200, per_sec: 200 });
        assert_eq!(RatePolicy::parse(" 5/s ").unwrap(), RatePolicy { burst: 5, per_sec: 5 });
        assert_eq!(RatePolicy::parse("0/s").unwrap_err(), "0/s");
        assert_eq!(RatePolicy::parse("200").unwrap_err(), "200");
        assert_eq!(RatePolicy::parse("abc/s").unwrap_err(), "abc/s");
    }

    #[test]
    fn unlimited_allows_everything() {
        let acct = unlimited();
        assert_eq!(
            acct.rate().check("anyone", &RatePolicy { burst: 1, per_sec: 1 }),
            RateDecision::Allow
        );
        let q = acct.quota();
        let lease = WatchLease::acquire(q.clone(), Arc::from("anyone"), 1_000_000, 1).unwrap();
        assert_eq!(lease.units(), 1_000_000);
        assert_eq!(q.current("anyone"), 0); // unlimited tracks nothing
    }
}
