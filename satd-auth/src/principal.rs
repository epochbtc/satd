//! An authenticated identity plus what it may do.

use std::fmt;
use std::sync::Arc;

use crate::capability::{Capability, CapabilitySet};
use crate::error::DenyReason;
use crate::quota::{Accounting, QuotaExceeded, RateDecision, RatePolicy, WatchLease, unlimited};

/// What kind of identity authenticated.
#[derive(Clone, Debug)]
pub enum PrincipalKind {
    /// The Core-compatible cookie / userpass / rpcauth operator — full caps.
    Operator,
    /// A `[[token]]` from the auth file.
    Token {
        /// The token's `id` field (for logging/accounting; never the secret).
        id: Arc<str>,
    },
    /// An mTLS client-certificate subject (CN / first DNS-SAN). Phase 3 seam.
    ClientCert {
        /// The certificate subject label.
        subject: Arc<str>,
    },
    /// Unauthenticated loopback trust (default for local-only surfaces).
    Loopback,
}

/// An authenticated principal: an identity, the capabilities it holds, its
/// quota/rate ceilings, and a shared accounting handle. Cheap to clone (a
/// handful of small fields + two `Arc`s).
#[derive(Clone)]
pub struct Principal {
    /// Who this is.
    pub kind: PrincipalKind,
    /// What it may do.
    pub caps: CapabilitySet,
    /// Watch-set ceiling (units). `None` = unlimited (operator).
    pub watch_quota: Option<u64>,
    /// Request rate ceiling. `None` = unlimited (operator).
    pub rate_limit: Option<RatePolicy>,
    /// Per-principal accounting, shared across this identity's connections.
    acct: Arc<dyn Accounting>,
}

impl Principal {
    /// The full-capability operator principal that legacy cookie/userpass/
    /// rpcauth credentials resolve to (SATD_AUTH_PLAN.md §3) — so `bitcoin-cli`,
    /// BTCPay, and NBXplorer keep working with full access when the unified
    /// layer is enabled.
    pub fn operator() -> Principal {
        Principal {
            kind: PrincipalKind::Operator,
            caps: CapabilitySet::ALL,
            watch_quota: None,
            rate_limit: None,
            acct: unlimited(),
        }
    }

    /// An unauthenticated loopback principal with the given capabilities (e.g.
    /// MCP loopback default = `mcp:*`).
    pub fn loopback(caps: CapabilitySet) -> Principal {
        Principal {
            kind: PrincipalKind::Loopback,
            caps,
            watch_quota: None,
            rate_limit: None,
            acct: unlimited(),
        }
    }

    /// A token principal with explicit capabilities, ceilings, and accounting.
    pub fn token(
        id: Arc<str>,
        caps: CapabilitySet,
        watch_quota: Option<u64>,
        rate_limit: Option<RatePolicy>,
        acct: Arc<dyn Accounting>,
    ) -> Principal {
        Principal {
            kind: PrincipalKind::Token { id },
            caps,
            watch_quota,
            rate_limit,
            acct,
        }
    }

    /// A stable identifier for logging and accounting (never a secret):
    /// `"operator"`, the token id, the cert subject, or `"loopback"`.
    pub fn id(&self) -> &str {
        match &self.kind {
            PrincipalKind::Operator => "operator",
            PrincipalKind::Token { id } => id,
            PrincipalKind::ClientCert { subject } => subject,
            PrincipalKind::Loopback => "loopback",
        }
    }

    /// Does this principal hold capability `c`?
    pub fn has(&self, c: Capability) -> bool {
        self.caps.contains(c)
    }

    /// Require capability `c`, returning a [`DenyReason`] naming the missing
    /// capability if absent.
    pub fn require(&self, c: Capability) -> Result<(), DenyReason> {
        if self.has(c) {
            Ok(())
        } else {
            Err(DenyReason(c.as_str()))
        }
    }

    /// This principal's accounting handle (rate limiter + quota store).
    pub fn accounting(&self) -> &Arc<dyn Accounting> {
        &self.acct
    }

    /// Charge one request against this principal's rate limit. Principals with no
    /// `rate_limit` (operator, loopback) always [`Allow`](RateDecision::Allow).
    /// Carriers call this after authentication and shed on
    /// [`Throttle`](RateDecision::Throttle) — never blocking, so a throttled
    /// consumption client can't backpressure the node.
    pub fn check_rate(&self) -> RateDecision {
        match &self.rate_limit {
            Some(policy) => self.acct.rate().check(self.id(), policy),
            None => RateDecision::Allow,
        }
    }

    /// Acquire `n` watch units for a streaming subscription (one scripthash =
    /// one unit; SATD_AUTH_PLAN.md §5). Enforces, in order, the `stream:watch`
    /// capability gate then the principal's `watch_quota` ceiling (`None` =
    /// unlimited, e.g. operator / loopback). On success the returned
    /// [`WatchLease`] holds the units until dropped — embed it in the
    /// subscription's stream so a client disconnect releases the quota
    /// automatically (disconnect reconciliation, no explicit cleanup path).
    ///
    /// This composes *above* the node-wide subscription cap
    /// (`addrindexsubscriptions`): acquire the lease first, then call the global
    /// `SubscriptionRegistry::subscribe`. Either ceiling can reject cleanly;
    /// neither blocks consensus.
    pub fn acquire_watch(&self, n: u64) -> Result<WatchLease, WatchReject> {
        self.require(Capability::StreamWatch)
            .map_err(WatchReject::MissingCapability)?;
        let max = self.watch_quota.unwrap_or(u64::MAX);
        WatchLease::acquire(self.acct.quota(), Arc::from(self.id()), n, max)
            .map_err(WatchReject::QuotaExceeded)
    }
}

/// Why [`Principal::acquire_watch`] refused a streaming subscription.
#[derive(Debug)]
pub enum WatchReject {
    /// The principal lacks the `stream:watch` capability.
    MissingCapability(DenyReason),
    /// The principal's per-tenant watch-set quota is exhausted.
    QuotaExceeded(QuotaExceeded),
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately omits `acct` (a trait object) and never logs secrets.
        f.debug_struct("Principal")
            .field("kind", &self.kind)
            .field("caps", &self.caps)
            .field("watch_quota", &self.watch_quota)
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_has_all_caps() {
        let op = Principal::operator();
        assert_eq!(op.id(), "operator");
        for c in [
            Capability::RpcRead,
            Capability::RpcWrite,
            Capability::EsploraRead,
            Capability::StreamSubscribe,
            Capability::StreamWatch,
            Capability::McpAll,
        ] {
            assert!(op.require(c).is_ok());
        }
    }

    #[test]
    fn token_capability_scoping() {
        let p = Principal::token(
            Arc::from("readonly"),
            CapabilitySet::EMPTY.with(Capability::RpcRead),
            Some(100),
            None,
            crate::quota::unlimited(),
        );
        assert_eq!(p.id(), "readonly");
        assert!(p.require(Capability::RpcRead).is_ok());
        assert_eq!(
            p.require(Capability::RpcWrite).unwrap_err(),
            DenyReason("rpc:write")
        );
    }

    #[test]
    fn acquire_watch_requires_capability() {
        // A token without stream:watch is refused at the capability gate, before
        // any quota accounting.
        let p = Principal::token(
            Arc::from("noscope"),
            CapabilitySet::EMPTY.with(Capability::EsploraRead),
            Some(10),
            None,
            crate::quota::unlimited(),
        );
        assert!(matches!(
            p.acquire_watch(1),
            Err(WatchReject::MissingCapability(DenyReason("stream:watch")))
        ));
    }

    #[test]
    fn acquire_watch_charges_quota_and_releases_on_drop() {
        let acct: Arc<dyn Accounting> = Arc::new(crate::quota::LocalAccounting::new());
        let p = Principal::token(
            Arc::from("tenant"),
            CapabilitySet::EMPTY.with(Capability::StreamWatch),
            Some(2),
            None,
            acct.clone(),
        );
        let quota = acct.quota();
        let l1 = p.acquire_watch(1).expect("first watch within quota");
        let l2 = p.acquire_watch(1).expect("second watch hits the cap exactly");
        assert_eq!(quota.current("tenant"), 2);
        // Third exceeds the watch_quota=2 ceiling.
        assert!(matches!(p.acquire_watch(1), Err(WatchReject::QuotaExceeded(_))));
        // Dropping a lease frees a unit (disconnect reconciliation) → room again.
        drop(l2);
        assert_eq!(quota.current("tenant"), 1);
        let _l3 = p.acquire_watch(1).expect("freed unit allows a new watch");
        drop(l1);
    }

    #[test]
    fn operator_watch_is_unlimited() {
        // Operator has stream:watch (ALL caps) and no quota → always granted,
        // and the unlimited accounting tracks nothing.
        let op = Principal::operator();
        let lease = op.acquire_watch(1_000_000).expect("operator unlimited");
        assert_eq!(lease.units(), 1_000_000);
    }
}
