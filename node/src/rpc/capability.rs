//! Per-method capability enforcement (jsonrpsee RPC-layer middleware).
//!
//! This is the authorization half of the unified-auth JSON-RPC carrier. The
//! HTTP-layer [`AuthLayer`](crate::rpc::auth::AuthLayer) resolves the presented
//! credential to a [`satd_auth::Principal`] and stashes it in the request
//! extensions; this layer reads it back and gates each call on the capability
//! the method requires.
//!
//! It is installed (`set_rpc_middleware`) only when the surface honors bearer
//! tokens (`-rpcauthbearer`). On the default surface every authenticated
//! request is the full-capability operator principal, so the layer would be a
//! no-op and is omitted (zero cost). The policy — which methods are reads vs.
//! writes — is the single classifier in [`crate::rpc::access`], reused from the
//! read-only listener.
//!
//! The gate is **fail-closed**: a request with no principal in its extensions,
//! or whose method is unclassified, requires `rpc:write` (the operator has it;
//! a read-only token does not), so neither a missing principal nor an unknown
//! method can be a capability bypass.

use std::future::Future;

use jsonrpsee::server::middleware::rpc::{Batch, BatchEntry, Notification, RpcServiceT};
use jsonrpsee::server::{BatchResponseBuilder, MethodResponse};
use jsonrpsee::types::{ErrorObjectOwned, Request};
use satd_auth::{Capability, Principal};

use crate::rpc::access::{RpcAccess, classify};

/// JSON-RPC error code for a method the authenticated principal lacks the
/// capability to call. In the implementation-defined server-error range
/// (`-32000..=-32099`), distinct from `-32601 Method not found` and from the
/// read-only listener's `-32001` so a client can tell "forbidden for my token"
/// apart from "does not exist" / "not available on this listener".
pub const CAPABILITY_DENIED_CODE: i32 = -32004;

/// JSON-RPC error code for a batch entry shed by the principal's per-token
/// rate limit. The HTTP layer answers an over-budget *request* with `429`;
/// inside a batch the request was already admitted, so the entry that
/// crosses the budget is answered in-band instead. The `data` field carries
/// `retry_after_secs`, the same figure the HTTP `Retry-After` header carries.
pub const RATE_LIMITED_CODE: i32 = -32005;

/// The response-size bound used by the batch-response builder, matching the
/// [`RPC_MAX_RESPONSE_SIZE`](crate::rpc::RPC_MAX_RESPONSE_SIZE) the inner
/// service enforces on a reply.
const RESPONSE_BODY_LIMIT: usize = crate::rpc::RPC_MAX_RESPONSE_SIZE;

/// The capability a method requires. Read-classified methods need `rpc:read`;
/// mempool-submit methods need `rpc:submit` (which `rpc:write` implies);
/// everything else — control, block-connecting, AND unclassified (unknown)
/// methods — needs `rpc:write`. Fail-closed: an unknown method can never be
/// reached by a read-only or submit-only token.
fn required_capability(method: &str) -> Capability {
    match method {
        // Moving the node clock reaches the future-block check, mempool expiry
        // and block-template timestamps, so it is carved out of `rpc:write`
        // and must be granted on its own. The operator principal (cookie /
        // rpcauth) holds every capability and is unaffected.
        "setmocktime" => Capability::TestClock,
        // `addconnection` dials an address of the caller's choosing and
        // picks the connection's type, which decides whether that peer is
        // asked for transactions and whether it relays addresses. That is
        // reshaping the node's peer set, not an ordinary write, so it gets
        // its own capability the way `setmocktime` does. The operator
        // principal (cookie / rpcauth) holds every capability and is
        // unaffected; the RPC is regtest-only regardless.
        "addconnection" => Capability::TestNet,
        // Writes arbitrary bytes onto a peer connection: the same class of
        // test-only peer control as `addconnection`.
        "sendmsgtopeer" => Capability::TestNet,
        _ => match classify(method) {
            Some(RpcAccess::Read) => Capability::RpcRead,
            // Handing a transaction to the mempool is its own capability so a
            // broadcaster need not hold node control; `rpc:write` implies it
            // (see `CapabilitySet::contains`), so existing write tokens are
            // unaffected.
            Some(RpcAccess::MempoolSubmit) => Capability::RpcSubmit,
            _ => Capability::RpcWrite,
        },
    }
}

fn rate_limited_error(method: &str, retry_after_secs: u32) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        RATE_LIMITED_CODE,
        format!("method '{method}' shed by the token's rate limit"),
        Some(serde_json::json!({ "retry_after_secs": retry_after_secs })),
    )
}

/// Charge a batch entry against the principal's rate limit. The first entry
/// rides on the unit the HTTP layer already charged; every later one costs
/// one. Returns the shed reply's `retry_after_secs` for an entry over budget.
fn charge_batch_entry(principal: Option<&Principal>, index: usize) -> Result<(), u32> {
    if index == 0 {
        return Ok(());
    }
    match principal.map(|p| p.check_rate()) {
        Some(satd_auth::RateDecision::Throttle { retry_after_secs }) => Err(retry_after_secs),
        _ => Ok(()),
    }
}

/// Layer that charges a JSON-RPC batch against the principal's per-token
/// rate limit **per call**, installed only on a bearer-enabled surface.
///
/// The HTTP-layer [`AuthLayer`](crate::rpc::auth::AuthLayer) charges one
/// unit per HTTP request before the body is parsed, so it cannot see how
/// many calls a batch carries; without this a `rate_limit = "1/s"` token
/// could submit thousands of calls per second in one body. This layer sits
/// **outermost** in the RPC middleware chain, because the layers inside it
/// (named-parameter rewrite, active-command tracking, the method filters)
/// each answer a batch by splitting it into single `call`s on the layer
/// beneath, so no inner layer's `batch` ever runs in production. Here the
/// batch is still whole: entry `0` rides on the unit the HTTP layer took,
/// each later entry costs one, and an entry over budget is answered
/// in-band with [`RATE_LIMITED_CODE`] (a notification is dropped). A batch
/// of `n` calls therefore costs exactly `n`, the same as `n` single
/// requests. Single calls and notifications pass through untouched.
#[derive(Clone, Copy, Debug, Default)]
pub struct BatchRateLayer;

impl BatchRateLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> tower::Layer<S> for BatchRateLayer {
    type Service = BatchRateFilter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BatchRateFilter { inner }
    }
}

/// The wrapped service produced by [`BatchRateLayer`].
#[derive(Clone, Debug)]
pub struct BatchRateFilter<S> {
    inner: S,
}

impl<S> RpcServiceT for BatchRateFilter<S>
where
    S: RpcServiceT<
            MethodResponse = MethodResponse,
            BatchResponse = MethodResponse,
            NotificationResponse = MethodResponse,
        > + Send
        + Sync
        + Clone
        + 'static,
{
    type MethodResponse = MethodResponse;
    type BatchResponse = MethodResponse;
    type NotificationResponse = MethodResponse;

    fn call<'a>(&self, req: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        // A single request was charged by the HTTP layer.
        self.inner.call(req)
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        async move {
            let mut builder = BatchResponseBuilder::new_with_limit(RESPONSE_BODY_LIMIT);
            let mut got_notification = false;

            for (index, entry) in batch.into_iter().enumerate() {
                match entry {
                    Ok(BatchEntry::Call(req)) => {
                        let charge = charge_batch_entry(req.extensions.get::<Principal>(), index);
                        let rp = match charge {
                            Ok(()) => inner.call(req).await,
                            Err(retry_after_secs) => {
                                let err = rate_limited_error(req.method_name(), retry_after_secs);
                                MethodResponse::error(req.id.clone(), err)
                                    .with_extensions(req.extensions.clone())
                            }
                        };
                        if let Err(too_big) = builder.append(rp) {
                            return too_big;
                        }
                    }
                    Ok(BatchEntry::Notification(n)) => {
                        got_notification = true;
                        if charge_batch_entry(n.extensions.get::<Principal>(), index).is_ok() {
                            inner.notification(n).await;
                        }
                    }
                    Err(err) => {
                        let (err, id) = err.into_parts();
                        let rp = MethodResponse::error(id, err);
                        if let Err(too_big) = builder.append(rp) {
                            return too_big;
                        }
                    }
                }
            }

            if builder.is_empty() && got_notification {
                MethodResponse::notification()
            } else {
                MethodResponse::from_batch(builder.finish())
            }
        }
    }

    fn notification<'a>(
        &self,
        n: Notification<'a>,
    ) -> impl Future<Output = MethodResponse> + Send + 'a {
        self.inner.notification(n)
    }
}

fn forbidden_error(method: &str, cap: Capability) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        CAPABILITY_DENIED_CODE,
        format!(
            "method '{method}' requires the '{}' capability",
            cap.as_str()
        ),
        None::<()>,
    )
}

/// Layer that gates each call on the principal's capabilities. Apply via
/// `RpcServiceBuilder::new().option_layer(filter)` so a surface that passes
/// `None` stays a zero-cost identity.
#[derive(Clone, Copy, Debug, Default)]
pub struct CapabilityLayer;

impl CapabilityLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> tower::Layer<S> for CapabilityLayer {
    type Service = CapabilityFilter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CapabilityFilter { inner }
    }
}

/// The wrapped service produced by [`CapabilityLayer`].
#[derive(Clone, Debug)]
pub struct CapabilityFilter<S> {
    inner: S,
}

impl<S> RpcServiceT for CapabilityFilter<S>
where
    S: RpcServiceT<
            MethodResponse = MethodResponse,
            BatchResponse = MethodResponse,
            NotificationResponse = MethodResponse,
        > + Send
        + Sync
        + Clone
        + 'static,
{
    type MethodResponse = MethodResponse;
    type BatchResponse = MethodResponse;
    type NotificationResponse = MethodResponse;

    fn call<'a>(&self, req: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        async move {
            let cap = required_capability(req.method_name());
            let allowed = req
                .extensions
                .get::<Principal>()
                .map(|p| p.has(cap))
                .unwrap_or(false);
            if allowed {
                inner.call(req).await
            } else {
                let err = forbidden_error(req.method_name(), cap);
                MethodResponse::error(req.id.clone(), err).with_extensions(req.extensions.clone())
            }
        }
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        // Per-entry gating, mirroring jsonrpsee's own batch loop (and the
        // read-only filter): a batch mixing allowed reads with a forbidden write
        // yields a per-entry error for the forbidden entry rather than failing
        // the whole batch.
        let inner = self.inner.clone();
        async move {
            let mut builder = BatchResponseBuilder::new_with_limit(RESPONSE_BODY_LIMIT);
            let mut got_notification = false;

            for entry in batch.into_iter() {
                match entry {
                    Ok(BatchEntry::Call(req)) => {
                        let cap = required_capability(req.method_name());
                        let allowed = req
                            .extensions
                            .get::<Principal>()
                            .map(|p| p.has(cap))
                            .unwrap_or(false);
                        let rp = if allowed {
                            inner.call(req).await
                        } else {
                            let err = forbidden_error(req.method_name(), cap);
                            MethodResponse::error(req.id.clone(), err)
                                .with_extensions(req.extensions.clone())
                        };
                        if let Err(too_big) = builder.append(rp) {
                            return too_big;
                        }
                    }
                    Ok(BatchEntry::Notification(n)) => {
                        got_notification = true;
                        let cap = required_capability(n.method_name());
                        let allowed = n
                            .extensions
                            .get::<Principal>()
                            .map(|p| p.has(cap))
                            .unwrap_or(false);
                        // Notifications expect no reply; a forbidden one is
                        // silently dropped rather than dispatched.
                        if allowed {
                            inner.notification(n).await;
                        }
                    }
                    Err(err) => {
                        let (err, id) = err.into_parts();
                        let rp = MethodResponse::error(id, err);
                        if let Err(too_big) = builder.append(rp) {
                            return too_big;
                        }
                    }
                }
            }

            if builder.is_empty() && got_notification {
                MethodResponse::notification()
            } else {
                MethodResponse::from_batch(builder.finish())
            }
        }
    }

    fn notification<'a>(
        &self,
        n: Notification<'a>,
    ) -> impl Future<Output = MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        async move {
            let cap = required_capability(n.method_name());
            let allowed = n
                .extensions
                .get::<Principal>()
                .map(|p| p.has(cap))
                .unwrap_or(false);
            if allowed {
                inner.notification(n).await
            } else {
                MethodResponse::notification().with_extensions(n.extensions.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::server::ResponsePayload;
    use jsonrpsee::types::Id;
    use satd_auth::CapabilitySet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct Recorder {
        dispatched: Arc<AtomicUsize>,
    }

    #[allow(clippy::manual_async_fn)]
    impl RpcServiceT for Recorder {
        type MethodResponse = MethodResponse;
        type BatchResponse = MethodResponse;
        type NotificationResponse = MethodResponse;

        fn call<'a>(
            &self,
            req: Request<'a>,
        ) -> impl Future<Output = MethodResponse> + Send + 'a {
            self.dispatched.fetch_add(1, Ordering::SeqCst);
            let id = req.id.clone();
            async move { MethodResponse::response(id, ResponsePayload::success(true), 1024) }
        }

        fn batch<'a>(&self, _batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
            async move { MethodResponse::notification() }
        }

        fn notification<'a>(
            &self,
            _n: Notification<'a>,
        ) -> impl Future<Output = MethodResponse> + Send + 'a {
            self.dispatched.fetch_add(1, Ordering::SeqCst);
            async move { MethodResponse::notification() }
        }
    }

    fn req_with(method: &'static str, principal: Option<Principal>) -> Request<'static> {
        let mut r = Request::owned(method.to_string(), None, Id::Number(1));
        if let Some(p) = principal {
            r.extensions.insert(p);
        }
        r
    }

    fn filter() -> (CapabilityFilter<Recorder>, Arc<AtomicUsize>) {
        let dispatched = Arc::new(AtomicUsize::new(0));
        let svc = CapabilityFilter {
            inner: Recorder {
                dispatched: dispatched.clone(),
            },
        };
        (svc, dispatched)
    }

    fn read_only_token() -> Principal {
        Principal::token(
            Arc::from("ro"),
            CapabilitySet::EMPTY.with(Capability::RpcRead),
            None,
            None,
            // reuse the crate's no-op accounting via an operator clone's handle
            Principal::operator().accounting().clone(),
        )
    }

    #[tokio::test]
    async fn operator_may_call_a_write_method() {
        let (svc, dispatched) = filter();
        let rp = svc
            .call(req_with("sendrawtransaction", Some(Principal::operator())))
            .await;
        assert!(rp.is_success());
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn read_token_may_call_a_read_method() {
        let (svc, dispatched) = filter();
        let rp = svc
            .call(req_with("getblockcount", Some(read_only_token())))
            .await;
        assert!(rp.is_success());
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn read_token_is_forbidden_on_a_write_method() {
        let (svc, dispatched) = filter();
        let rp = svc.call(req_with("stop", Some(read_only_token()))).await;
        assert!(rp.is_error());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        assert!(rp.as_json().get().contains("rpc:write"));
    }

    #[tokio::test]
    async fn read_token_is_forbidden_on_a_submit_method() {
        let (svc, dispatched) = filter();
        let rp = svc
            .call(req_with("sendrawtransaction", Some(read_only_token())))
            .await;
        assert!(rp.is_error());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        // The denial names the capability that would have admitted the call.
        assert!(rp.as_json().get().contains("rpc:submit"), "{}", rp.as_json().get());
    }

    fn submit_token() -> Principal {
        Principal::token(
            Arc::from("sub"),
            CapabilitySet::EMPTY
                .with(Capability::RpcRead)
                .with(Capability::RpcSubmit),
            None,
            None,
            Principal::operator().accounting().clone(),
        )
    }

    /// A submit token broadcasts but cannot control the node; a write token
    /// keeps broadcasting because `rpc:write` implies `rpc:submit`.
    #[tokio::test]
    async fn submit_token_broadcasts_but_cannot_control() {
        for method in ["sendrawtransaction", "submitpackage"] {
            assert_eq!(required_capability(method), Capability::RpcSubmit, "{method}");
            let (svc, dispatched) = filter();
            let rp = svc.call(req_with(method, Some(submit_token()))).await;
            assert!(rp.is_success(), "{method}: {}", rp.as_json().get());
            assert_eq!(dispatched.load(Ordering::SeqCst), 1);
        }
        for method in ["stop", "addnode", "invalidateblock", "totallynewrpc"] {
            let (svc, dispatched) = filter();
            let rp = svc.call(req_with(method, Some(submit_token()))).await;
            assert!(rp.is_error(), "{method} must be denied to a submit token");
            assert_eq!(dispatched.load(Ordering::SeqCst), 0);
            assert!(rp.as_json().get().contains("rpc:write"), "{}", rp.as_json().get());
        }

        let write_token = Principal::token(
            Arc::from("rw"),
            CapabilitySet::EMPTY.with(Capability::RpcWrite),
            None,
            None,
            Principal::operator().accounting().clone(),
        );
        let (svc, dispatched) = filter();
        let rp = svc
            .call(req_with("sendrawtransaction", Some(write_token)))
            .await;
        assert!(rp.is_success(), "{}", rp.as_json().get());
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn missing_principal_is_fail_closed() {
        let (svc, dispatched) = filter();
        // No principal in extensions → treated as lacking every capability.
        let rp = svc.call(req_with("getblockcount", None)).await;
        assert!(rp.is_error());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unknown_method_requires_write() {
        let (svc, dispatched) = filter();
        // A read-only token cannot probe unknown methods.
        let rp = svc
            .call(req_with("totallynewrpc", Some(read_only_token())))
            .await;
        assert!(rp.is_error());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    }

    /// `addconnection` dials an address the caller chooses and picks the
    /// connection's type, so a write token must not reach it — the same
    /// reasoning that carved `setmocktime` out into `test:clock`. Falling
    /// back to `rpc:write` for it, as the classifier did, let any delegated
    /// write token reshape the node's peer set.
    #[test]
    fn the_test_capabilities_are_not_implied_by_write() {
        for (method, cap) in [
            ("setmocktime", Capability::TestClock),
            ("addconnection", Capability::TestNet),
        ] {
            assert_eq!(required_capability(method), cap, "{method}");
            assert_ne!(
                required_capability(method),
                Capability::RpcWrite,
                "{method} must not fall through to rpc:write"
            );
        }
        // The two are distinct: a clock token cannot dial, and vice versa.
        assert_ne!(Capability::TestClock, Capability::TestNet);
        assert_eq!(Capability::TestNet.as_str(), "test:net");
        assert_eq!(Capability::parse("test:net"), Some(Capability::TestNet));
    }

    #[tokio::test]
    async fn a_write_token_is_forbidden_on_addconnection() {
        let write_token = Principal::token(
            Arc::from("rw"),
            CapabilitySet::EMPTY
                .with(Capability::RpcRead)
                .with(Capability::RpcWrite),
            None,
            None,
            Principal::operator().accounting().clone(),
        );
        let (svc, dispatched) = filter();
        let rp = svc
            .call(req_with("addconnection", Some(write_token)))
            .await;
        assert!(rp.is_error());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        assert!(rp.as_json().get().contains("test:net"), "{}", rp.as_json().get());

        // The operator principal still reaches it.
        let (svc, dispatched) = filter();
        let rp = svc
            .call(req_with("addconnection", Some(Principal::operator())))
            .await;
        assert!(rp.is_success());
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    }

    /// A token holding only `rpc:submit` (no `rpc:read`) is the minimal
    /// broadcaster shape: it reaches the submission handlers and nothing
    /// else, and each denial names the capability that would admit the call.
    #[tokio::test]
    async fn submit_only_token_reaches_submit_and_nothing_else() {
        let submit_only = || {
            Principal::token(
                Arc::from("sub-only"),
                CapabilitySet::EMPTY.with(Capability::RpcSubmit),
                None,
                None,
                Principal::operator().accounting().clone(),
            )
        };
        for method in ["sendrawtransaction", "submitpackage"] {
            let (svc, dispatched) = filter();
            let rp = svc.call(req_with(method, Some(submit_only()))).await;
            assert!(rp.is_success(), "{method}: {}", rp.as_json().get());
            assert_eq!(dispatched.load(Ordering::SeqCst), 1);
        }
        let (svc, dispatched) = filter();
        let rp = svc.call(req_with("getblockcount", Some(submit_only()))).await;
        assert!(rp.is_error());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        assert!(rp.as_json().get().contains("rpc:read"), "{}", rp.as_json().get());
        let (svc, dispatched) = filter();
        let rp = svc.call(req_with("stop", Some(submit_only()))).await;
        assert!(rp.is_error());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        assert!(rp.as_json().get().contains("rpc:write"), "{}", rp.as_json().get());
    }

    /// `rpc:write` implies `rpc:submit` and nothing else: a write-only token
    /// is still denied a read method.
    #[tokio::test]
    async fn write_only_token_is_forbidden_on_a_read_method() {
        let write_only = Principal::token(
            Arc::from("rw"),
            CapabilitySet::EMPTY.with(Capability::RpcWrite),
            None,
            None,
            Principal::operator().accounting().clone(),
        );
        let (svc, dispatched) = filter();
        let rp = svc.call(req_with("getblockcount", Some(write_only))).await;
        assert!(rp.is_error());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        assert!(rp.as_json().get().contains("rpc:read"), "{}", rp.as_json().get());
    }

    fn batch_of(reqs: Vec<Request<'static>>) -> Batch<'static> {
        Batch::from(reqs.into_iter().map(|r| Ok(BatchEntry::Call(r))).collect())
    }

    fn batch_replies(rp: &MethodResponse) -> Vec<serde_json::Value> {
        serde_json::from_str(rp.as_json().get()).expect("batch reply is a JSON array")
    }

    /// The batch path gates every entry on its own capability: a submit
    /// token's `[read, submit, control]` batch yields `[result, result,
    /// -32004]`, and only the admitted entries are dispatched.
    #[tokio::test]
    async fn batch_entries_are_gated_individually() {
        let (svc, dispatched) = filter();
        let rp = svc
            .batch(batch_of(vec![
                req_with("getblockcount", Some(submit_token())),
                req_with("sendrawtransaction", Some(submit_token())),
                req_with("stop", Some(submit_token())),
            ]))
            .await;
        let replies = batch_replies(&rp);
        assert_eq!(replies.len(), 3, "{}", rp.as_json().get());
        assert!(replies[0].get("result").is_some(), "{}", replies[0]);
        assert!(replies[1].get("result").is_some(), "{}", replies[1]);
        assert_eq!(replies[2]["error"]["code"], CAPABILITY_DENIED_CODE, "{}", replies[2]);
        assert!(
            replies[2]["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("rpc:write"),
            "{}",
            replies[2]
        );
        assert_eq!(dispatched.load(Ordering::SeqCst), 2);
    }

    /// A batch is charged per entry against the token's rate limit, not once
    /// per HTTP request. The first entry rides on the unit the HTTP layer
    /// charged; every later entry costs one, and the entry that crosses the
    /// budget is answered `-32005` with `retry_after_secs`.
    #[tokio::test]
    async fn batch_entries_are_charged_against_the_rate_limit() {
        use satd_auth::{LocalAccounting, RatePolicy};
        let rate_filter = |dispatched: &Arc<AtomicUsize>| BatchRateFilter {
            inner: Recorder {
                dispatched: dispatched.clone(),
            },
        };
        // burst 2 / 2 per second: the HTTP layer would have taken one; here
        // the bucket starts full, so entries 1 and 2 are admitted and entry 3
        // is shed.
        let acct: Arc<dyn satd_auth::Accounting> = Arc::new(LocalAccounting::new());
        let rl = || {
            Principal::token(
                Arc::from("rl"),
                CapabilitySet::EMPTY.with(Capability::RpcRead),
                None,
                Some(RatePolicy {
                    burst: 2,
                    per_sec: 2,
                }),
                acct.clone(),
            )
        };
        let dispatched = Arc::new(AtomicUsize::new(0));
        let svc = rate_filter(&dispatched);
        let rp = svc
            .batch(batch_of(vec![
                req_with("getblockcount", Some(rl())),
                req_with("getblockcount", Some(rl())),
                req_with("getblockcount", Some(rl())),
                req_with("getblockcount", Some(rl())),
            ]))
            .await;
        let replies = batch_replies(&rp);
        assert_eq!(replies.len(), 4, "{}", rp.as_json().get());
        assert!(replies[0].get("result").is_some(), "entry 0 is free: {}", replies[0]);
        assert!(replies[1].get("result").is_some(), "entry 1 costs one: {}", replies[1]);
        assert!(replies[2].get("result").is_some(), "entry 2 costs one: {}", replies[2]);
        assert_eq!(replies[3]["error"]["code"], RATE_LIMITED_CODE, "{}", replies[3]);
        assert!(
            replies[3]["error"]["data"]["retry_after_secs"].is_u64(),
            "{}",
            replies[3]
        );
        assert_eq!(dispatched.load(Ordering::SeqCst), 3);

        // A single call is not charged here (the HTTP layer did that).
        let dispatched = Arc::new(AtomicUsize::new(0));
        let svc = rate_filter(&dispatched);
        for _ in 0..5 {
            let rp = svc.call(req_with("getblockcount", Some(rl()))).await;
            assert!(rp.is_success(), "{}", rp.as_json().get());
        }
        assert_eq!(dispatched.load(Ordering::SeqCst), 5);

        // Unlimited principals are never shed, however long the batch.
        let dispatched = Arc::new(AtomicUsize::new(0));
        let svc = rate_filter(&dispatched);
        let rp = svc
            .batch(batch_of(
                (0..50)
                    .map(|_| req_with("getblockcount", Some(read_only_token())))
                    .collect(),
            ))
            .await;
        assert!(batch_replies(&rp).iter().all(|r| r.get("result").is_some()));
        assert_eq!(dispatched.load(Ordering::SeqCst), 50);
    }
}
