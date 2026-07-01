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
    /// **Atomically** swap a reservation: release `release` units and acquire
    /// `acquire`, succeeding only if the post-swap total stays at or under `max`.
    /// This is the primitive an atomic watch-set *replace* needs: releasing the
    /// old reservation and acquiring the new one in one step means there is never
    /// a window where the units are freed but not yet re-held — so a same-size
    /// swap fits at exactly `max` (no transient over-count) and a rejected swap
    /// leaves the reservation **exactly** as it was (no race where a concurrent
    /// stream for the same principal steals the momentarily-freed units).
    ///
    /// The default is the non-atomic release-then-acquire; a real backend MUST
    /// override it with a locked read-modify-write for the guarantee above.
    fn try_replace(
        &self,
        principal_id: &str,
        release: u64,
        acquire: u64,
        max: u64,
    ) -> Result<(), QuotaExceeded> {
        self.release(principal_id, release);
        self.try_acquire(principal_id, acquire, max).inspect_err(|_| {
            // Restore what we released so the failure is a no-op (best effort;
            // the default path is not atomic — override for the real guarantee).
            let _ = self.try_acquire(principal_id, release, u64::MAX);
        })
    }
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

    /// Wrap `n` units the store has **already reserved** (e.g. via
    /// [`QuotaStore::try_replace`]) in a lease, without charging them again. The
    /// returned lease releases `n` on drop, exactly like [`acquire`](Self::acquire).
    /// The caller is responsible for [`defuse`](Self::defuse)ing whatever leases
    /// the reservation replaced, so the units are not double-released.
    pub fn from_reserved(store: Arc<dyn QuotaStore>, principal_id: Arc<str>, n: u64) -> WatchLease {
        WatchLease {
            store,
            principal_id,
            n,
        }
    }

    /// Consume this lease **without** releasing its units — for a lease whose
    /// units were already handed off (e.g. released as part of an atomic
    /// [`QuotaStore::try_replace`]), so its `Drop` must not release them again.
    pub fn defuse(mut self) {
        self.n = 0; // Drop then releases 0 units.
    }

    /// Units this lease holds.
    pub fn units(&self) -> u64 {
        self.n
    }

    /// Split a single unit off this lease into a new one-unit lease over the
    /// same principal, **without charging or releasing any units**. Returns
    /// `None` once this lease holds nothing left to split.
    ///
    /// The two leases together still hold the same total the store charged;
    /// dropping either releases only its own units. This lets an atomic batch
    /// reservation (`acquire(n)` — charged all-or-nothing in one round-trip)
    /// be redistributed into per-item leases, so an individual watch can
    /// return its unit on removal without a second, racy acquire call. Because
    /// no store call is made, the total charged is conserved exactly.
    pub fn split_off_one(&mut self) -> Option<WatchLease> {
        self.split_off(1)
    }

    /// Split `n` units off this lease into a new lease over the same principal,
    /// **without charging or releasing any units** (same conservation property
    /// as [`split_off_one`](Self::split_off_one), generalized to `n`). Returns
    /// `None` if this lease holds fewer than `n` units. Used to carve a
    /// variable-cost per-item lease (e.g. a coarseness-priced prefix watch) out
    /// of one atomic batch reservation.
    pub fn split_off(&mut self, n: u64) -> Option<WatchLease> {
        if n > self.n {
            return None;
        }
        self.n -= n;
        Some(WatchLease {
            store: Arc::clone(&self.store),
            principal_id: Arc::clone(&self.principal_id),
            n,
        })
    }
}

impl std::fmt::Debug for WatchLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `store` is a trait object (not Debug); omit it.
        f.debug_struct("WatchLease")
            .field("principal_id", &self.principal_id)
            .field("n", &self.n)
            .finish()
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

// ----------------------------------------------------------------------------
// In-process default backends. A single `LocalAccounting` is shared by every
// token principal; per-principal state is keyed by `principal_id` inside the
// sharded maps (so a tenant's quota/rate survives across its connections). A
// future Redis-backed backend implements the same traits and drops in
// fail-open; the call sites only ever see the traits.
// ----------------------------------------------------------------------------

use dashmap::DashMap;

/// Real (wall-clock) millisecond clock for the token bucket.
fn system_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone, Copy)]
struct BucketState {
    tokens: f64,
    last_ms: u64,
}

/// In-process token-bucket rate limiter, keyed by principal id.
pub struct LocalRateLimiter {
    buckets: DashMap<String, BucketState>,
    clock: fn() -> u64,
}

impl LocalRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
            clock: system_millis,
        }
    }
    /// Construct with an injected millisecond clock (tests).
    pub fn with_clock(clock: fn() -> u64) -> Self {
        Self {
            buckets: DashMap::new(),
            clock,
        }
    }
}

impl Default for LocalRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter for LocalRateLimiter {
    fn check(&self, principal_id: &str, policy: &RatePolicy) -> RateDecision {
        let now = (self.clock)();
        let mut state = self
            .buckets
            .entry(principal_id.to_string())
            .or_insert(BucketState {
                tokens: policy.burst as f64,
                last_ms: now,
            });
        // Refill proportional to elapsed time, capped at the burst size.
        let elapsed_ms = now.saturating_sub(state.last_ms);
        let refill = (elapsed_ms as f64 / 1000.0) * policy.per_sec as f64;
        state.tokens = (state.tokens + refill).min(policy.burst as f64);
        state.last_ms = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            RateDecision::Allow
        } else {
            // Time until one whole token refills.
            let needed = 1.0 - state.tokens;
            let secs = (needed / policy.per_sec.max(1) as f64).ceil() as u32;
            RateDecision::Throttle {
                retry_after_secs: secs.max(1),
            }
        }
    }
}

/// In-process watch-set occupancy store, keyed by principal id.
#[derive(Default)]
pub struct LocalQuotaStore {
    held: DashMap<String, u64>,
}

impl LocalQuotaStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl QuotaStore for LocalQuotaStore {
    fn try_acquire(&self, principal_id: &str, n: u64, max: u64) -> Result<(), QuotaExceeded> {
        let mut held = self.held.entry(principal_id.to_string()).or_insert(0);
        let current = *held;
        if current.saturating_add(n) > max {
            return Err(QuotaExceeded {
                current,
                requested: n,
                max,
            });
        }
        *held = current + n;
        Ok(())
    }
    fn release(&self, principal_id: &str, n: u64) {
        if let Some(mut held) = self.held.get_mut(principal_id) {
            *held = held.saturating_sub(n);
        }
    }
    fn current(&self, principal_id: &str) -> u64 {
        self.held.get(principal_id).map(|v| *v).unwrap_or(0)
    }
    fn try_replace(
        &self,
        principal_id: &str,
        release: u64,
        acquire: u64,
        max: u64,
    ) -> Result<(), QuotaExceeded> {
        // Under the DashMap entry lock, so the read-modify-write is atomic: no
        // concurrent stream for this principal can observe the released-but-not-
        // reacquired state or steal the units mid-swap.
        let mut held = self.held.entry(principal_id.to_string()).or_insert(0);
        let after_release = held.saturating_sub(release);
        if after_release.saturating_add(acquire) > max {
            return Err(QuotaExceeded {
                current: after_release,
                requested: acquire,
                max,
            });
        }
        *held = after_release + acquire;
        Ok(())
    }
}

/// The default in-process accounting backend: a token-bucket rate limiter plus a
/// watch-set occupancy store, both keyed by principal id. One instance is shared
/// by every token principal.
pub struct LocalAccounting {
    rate: LocalRateLimiter,
    quota: Arc<LocalQuotaStore>,
}

impl LocalAccounting {
    pub fn new() -> Self {
        Self {
            rate: LocalRateLimiter::new(),
            quota: Arc::new(LocalQuotaStore::new()),
        }
    }
    /// Construct with an injected rate-limiter clock (tests).
    pub fn with_clock(clock: fn() -> u64) -> Self {
        Self {
            rate: LocalRateLimiter::with_clock(clock),
            quota: Arc::new(LocalQuotaStore::new()),
        }
    }
}

impl Default for LocalAccounting {
    fn default() -> Self {
        Self::new()
    }
}

impl Accounting for LocalAccounting {
    fn rate(&self) -> &dyn RateLimiter {
        &self.rate
    }
    fn quota(&self) -> Arc<dyn QuotaStore> {
        self.quota.clone()
    }
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

    // A settable clock for the token-bucket tests.
    static CLOCK_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn test_clock() -> u64 {
        CLOCK_MS.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn set_clock(ms: u64) {
        CLOCK_MS.store(ms, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn token_bucket_bursts_then_throttles_then_refills() {
        set_clock(0);
        let rl = LocalRateLimiter::with_clock(test_clock);
        let policy = RatePolicy { burst: 3, per_sec: 1 };
        // Burst of 3 allowed at t=0.
        for _ in 0..3 {
            assert_eq!(rl.check("p", &policy), RateDecision::Allow);
        }
        // 4th is throttled.
        assert!(matches!(
            rl.check("p", &policy),
            RateDecision::Throttle { .. }
        ));
        // After 2s, ~2 tokens refilled.
        set_clock(2000);
        assert_eq!(rl.check("p", &policy), RateDecision::Allow);
        assert_eq!(rl.check("p", &policy), RateDecision::Allow);
        assert!(matches!(
            rl.check("p", &policy),
            RateDecision::Throttle { .. }
        ));
        // A different principal has its own independent bucket.
        assert_eq!(rl.check("other", &policy), RateDecision::Allow);
    }

    #[test]
    fn quota_store_acquires_releases_and_caps() {
        let q: Arc<dyn QuotaStore> = Arc::new(LocalQuotaStore::new());
        // Acquire up to the cap.
        let l1 = WatchLease::acquire(q.clone(), Arc::from("tenant"), 6, 10).unwrap();
        assert_eq!(q.current("tenant"), 6);
        let l2 = WatchLease::acquire(q.clone(), Arc::from("tenant"), 4, 10).unwrap();
        assert_eq!(q.current("tenant"), 10);
        // Over the cap → rejected.
        let err = WatchLease::acquire(q.clone(), Arc::from("tenant"), 1, 10).unwrap_err();
        assert_eq!(err, QuotaExceeded { current: 10, requested: 1, max: 10 });
        // Dropping a lease releases its units (disconnect reconciliation).
        drop(l2);
        assert_eq!(q.current("tenant"), 6);
        drop(l1);
        assert_eq!(q.current("tenant"), 0);
    }

    #[test]
    fn split_off_one_conserves_units_and_releases_per_split() {
        let q: Arc<dyn QuotaStore> = Arc::new(LocalQuotaStore::new());
        // Reserve 3 units atomically, then split into per-item leases.
        let mut batch = WatchLease::acquire(q.clone(), Arc::from("tenant"), 3, 10).unwrap();
        assert_eq!(q.current("tenant"), 3, "batch reservation charges 3 up front");

        let a = batch.split_off_one().unwrap();
        let b = batch.split_off_one().unwrap();
        let c = batch.split_off_one().unwrap();
        // Splitting moves units between leases — it never touches the store.
        assert_eq!(q.current("tenant"), 3, "splitting does not re-charge or release");
        assert_eq!(batch.units(), 0);
        assert!(batch.split_off_one().is_none(), "nothing left to split");

        // Dropping the drained batch releases nothing; each per-item lease frees
        // exactly its one unit.
        drop(batch);
        assert_eq!(q.current("tenant"), 3);
        drop(b);
        assert_eq!(q.current("tenant"), 2, "one per-item lease released one unit");
        drop(a);
        drop(c);
        assert_eq!(q.current("tenant"), 0, "all per-item leases released");
    }

    #[test]
    fn try_replace_is_atomic_and_fits_a_same_size_swap_at_quota() {
        let store = LocalQuotaStore::new();
        store.try_acquire("t", 5, 5).unwrap(); // hold 5 of max 5
        assert_eq!(store.current("t"), 5);

        // A same-size swap fits at exactly the ceiling — the release and acquire
        // are one step, so there is never a 5+5 over-count.
        store.try_replace("t", 5, 5, 5).unwrap();
        assert_eq!(store.current("t"), 5);

        // An over-quota swap (5 - 2 + 4 = 7 > 5) is rejected and changes nothing.
        assert!(store.try_replace("t", 2, 4, 5).is_err());
        assert_eq!(store.current("t"), 5, "a rejected swap leaves the reservation intact");

        // A shrink always fits.
        store.try_replace("t", 5, 2, 5).unwrap();
        assert_eq!(store.current("t"), 2);
    }

    #[test]
    fn from_reserved_lease_releases_on_drop_and_defuse_does_not() {
        let store: Arc<dyn QuotaStore> = Arc::new(LocalQuotaStore::new());
        // Pretend the store already reserved 3 units (e.g. via try_replace).
        store.try_acquire("p", 3, 10).unwrap();
        let lease = WatchLease::from_reserved(store.clone(), Arc::from("p"), 3);
        assert_eq!(store.current("p"), 3);
        drop(lease);
        assert_eq!(store.current("p"), 0, "from_reserved lease releases on drop");

        store.try_acquire("p", 3, 10).unwrap();
        let lease = WatchLease::from_reserved(store.clone(), Arc::from("p"), 3);
        lease.defuse();
        assert_eq!(store.current("p"), 3, "defuse drops without releasing");
    }

    #[test]
    fn local_accounting_bundles_rate_and_quota() {
        let acct = LocalAccounting::new();
        assert_eq!(
            acct.rate().check("p", &RatePolicy { burst: 1, per_sec: 1 }),
            RateDecision::Allow
        );
        let q = acct.quota();
        let _lease = WatchLease::acquire(q.clone(), Arc::from("p"), 5, 5).unwrap();
        assert_eq!(q.current("p"), 5);
    }
}
