//! Per-category authorization for the streaming carriers.
//!
//! Most categories carry data that is *about the chain* — blocks, transactions,
//! the mempool — which is public by nature and which `stream:subscribe` exists
//! to hand out. The `status` category is different: it carries data about the
//! **host**, and every other surface keeps that behind `rpc:read`.
//!
//! A `StatusEvent` body reports free bytes on the node's volume, connected peer
//! counts split inbound/outbound, the mempool byte cap with its current
//! occupancy and `mempoolminfee`, tip height, IBD state, and reorg depth with
//! fork heights. Those are the answers to `getblockchaininfo`, `getpeerinfo`,
//! `getmempoolinfo` and `getwarnings`.
//!
//! `satd-auth` separates `rpc:read` from `stream:subscribe` precisely so an
//! operator can issue a streaming token to a wallet backend, an indexer, or a
//! tenant *without* also handing over the node's read RPC. Serving `status` on
//! `stream:subscribe` alone would route around that split rather than extend
//! it: the token would deliver, over the stream, the host telemetry it was
//! issued to withhold. So the bit needs both capabilities.
//!
//! This is not a new capability in the `auth.toml` vocabulary. Adding one would
//! be a Tier 1 surface change, and it is not needed — the data already has an
//! owner in the existing vocabulary, and `status` is new in this release, so no
//! deployed token loses access to something it has today.

/// Whether `principal` may receive the `status` category.
///
/// `None` means the token store is not configured at all, which is the
/// Core-compatible default (loopback trust) and grants everything — this gate
/// only ever narrows a `-authfile` deployment. The operator principal
/// (cookie / userpass / rpcauth) carries `CapabilitySet::ALL` and so passes.
pub(crate) fn may_receive_status(principal: Option<&satd_auth::Principal>) -> bool {
    principal.is_none_or(|p| p.has(satd_auth::Capability::RpcRead))
}

/// Strip `status` from `mask` when `principal` may not receive it.
///
/// Used on the mid-stream control paths (`SetCategories`, `SetWatchSet`), which
/// have no per-message error channel of their own. The handshake paths reject
/// outright instead — see `may_receive_status`'s callers in `grpc`/`ws` — so a
/// client that asks for `status` up front is told plainly rather than left
/// wondering why a category it requested never arrives.
#[cfg_attr(not(feature = "grpc"), allow(dead_code))]
pub(crate) fn strip_unauthorized(principal: Option<&satd_auth::Principal>, mask: u32) -> u32 {
    if may_receive_status(principal) {
        return mask;
    }
    if mask & node::events::CATEGORY_STATUS != 0 {
        tracing::debug!(
            target: "events::auth",
            "dropping the status category from a mid-stream category update: \
             the token lacks rpc:read",
        );
    }
    mask & !node::events::CATEGORY_STATUS
}

#[cfg(test)]
mod tests {
    use super::*;
    use satd_auth::{Capability, CapabilitySet, Principal};

    /// `has()` reads only `caps`, so the principal kind is immaterial here and
    /// `loopback` is the cheapest constructor that takes an explicit set.
    fn principal_with(caps: CapabilitySet) -> Principal {
        Principal::loopback(caps)
    }

    /// The Core-compatible default: no `-authfile`, no token store, nothing to
    /// narrow. This gate must never change behavior for a node that has not
    /// opted into bearer auth.
    #[test]
    fn auth_disabled_receives_status() {
        assert!(may_receive_status(None));
        assert_eq!(
            strip_unauthorized(None, node::events::CATEGORY_STATUS),
            node::events::CATEGORY_STATUS,
        );
    }

    /// The finding: a token issued `stream:subscribe` *in order to* withhold
    /// `getblockchaininfo` / `getpeerinfo` / `getwarnings` must not get the same
    /// telemetry back over the stream.
    #[test]
    fn stream_subscribe_alone_does_not_carry_status() {
        let p = principal_with(CapabilitySet::EMPTY.with(Capability::StreamSubscribe));
        assert!(!may_receive_status(Some(&p)));

        let asked = node::events::CATEGORY_CHAIN | node::events::CATEGORY_STATUS;
        let got = strip_unauthorized(Some(&p), asked);
        assert_eq!(got & node::events::CATEGORY_STATUS, 0, "status is stripped");
        assert_eq!(
            got & node::events::CATEGORY_CHAIN,
            node::events::CATEGORY_CHAIN,
            "and nothing else is",
        );
    }

    #[test]
    fn rpc_read_carries_status() {
        let p = principal_with(
            CapabilitySet::EMPTY
                .with(Capability::StreamSubscribe)
                .with(Capability::RpcRead),
        );
        assert!(may_receive_status(Some(&p)));
        assert_eq!(
            strip_unauthorized(Some(&p), node::events::CATEGORY_STATUS),
            node::events::CATEGORY_STATUS,
        );
    }

    /// The operator principal holds everything, so an operator-authenticated
    /// stream is unaffected.
    #[test]
    fn the_operator_principal_carries_status() {
        let p = principal_with(CapabilitySet::ALL);
        assert!(may_receive_status(Some(&p)));
    }
}
