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

use jsonrpsee::server::middleware::rpc::{Batch, BatchEntry, BatchEntryErr, Notification, RpcServiceT};
use jsonrpsee::server::{BatchResponseBuilder, MethodResponse};
use jsonrpsee::types::{ErrorObjectOwned, Request};
use satd_auth::{Capability, Principal};

use crate::rpc::access::{RpcAccess, classify};
use crate::rpc::auth::{BearerSession, HttpCharged};

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

/// JSON-RPC error code for a frame on an open WebSocket whose bearer token
/// has since been removed from the authfile or has expired (#821). A new
/// request with that token gets HTTP `401`; a frame on a socket opened
/// before has no status line to carry one, so it is answered in-band.
pub const TOKEN_REVOKED_CODE: i32 = -32006;

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
        // Writes an address of the caller's choosing into the address book,
        // which seeds the dial list on the next start: test-only peer
        // control, like the two above.
        "addpeeraddress" => Capability::TestNet,
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

/// Charge one call against the principal's rate limit, unless it rides on a
/// unit the HTTP layer already took. Returns the shed reply's
/// `retry_after_secs` for a call over budget.
fn charge(principal: Option<&Principal>, prepaid: bool) -> Result<(), u32> {
    if prepaid {
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
/// many calls a batch carries, and a WebSocket connection pays it once at
/// the upgrade however many frames follow; without this a
/// `rate_limit = "1/s"` token could submit thousands of calls per second in
/// one body or over one socket. This layer sits
/// **outermost** in the RPC middleware chain, because the layers inside it
/// (named-parameter rewrite, active-command tracking, the method filters)
/// each answer a batch by splitting it into single `call`s on the layer
/// beneath, so no inner layer's `batch` ever runs in production. Here the
/// batch is still whole. A call from an HTTP body carries
/// [`HttpCharged`](crate::rpc::auth::HttpCharged): the first call or
/// notification of that body rides on the unit the HTTP layer took, and
/// every other one costs one, so a batch of `n` costs exactly `n`, the same
/// as `n` single requests. A malformed entry is answered but never charged.
/// A call without the marker -- every frame on a WebSocket -- costs one,
/// single or batched. A call over budget is answered in-band with
/// [`RATE_LIMITED_CODE`]; a notification over budget is dropped.
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
        let inner = self.inner.clone();
        async move {
            let prepaid = req.extensions.get::<HttpCharged>().is_some();
            match charge(req.extensions.get::<Principal>(), prepaid) {
                Ok(()) => inner.call(req).await,
                Err(retry_after_secs) => {
                    let err = rate_limited_error(req.method_name(), retry_after_secs);
                    MethodResponse::error(req.id.clone(), err)
                        .with_extensions(req.extensions.clone())
                }
            }
        }
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        async move {
            let mut builder = BatchResponseBuilder::new_with_limit(RESPONSE_BODY_LIMIT);
            let mut got_notification = false;
            // The HTTP layer's unit covers one call of the body: the first
            // one dispatched, not whatever sits at index 0.
            let mut http_unit_spent = false;
            let mut prepaid = |ext: &jsonrpsee::types::Extensions| {
                if !http_unit_spent && ext.get::<HttpCharged>().is_some() {
                    http_unit_spent = true;
                    true
                } else {
                    false
                }
            };

            for entry in batch.into_iter() {
                match entry {
                    Ok(BatchEntry::Call(req)) => {
                        let free = prepaid(&req.extensions);
                        let charge = charge(req.extensions.get::<Principal>(), free);
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
                        let free = prepaid(&n.extensions);
                        if charge(n.extensions.get::<Principal>(), free).is_ok() {
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
            let prepaid = n.extensions.get::<HttpCharged>().is_some();
            match charge(n.extensions.get::<Principal>(), prepaid) {
                Ok(()) => inner.notification(n).await,
                Err(_) => MethodResponse::notification(),
            }
        }
    }
}

fn token_revoked_error() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        TOKEN_REVOKED_CODE,
        "bearer token revoked or expired",
        None::<()>,
    )
}

/// Layer that resolves a WebSocket's bearer token again for every frame
/// (#821). A call carrying a [`BearerSession`] -- every frame on a socket
/// opened with a token -- has its [`Principal`] replaced by the token's
/// principal as the store has it now, so a SIGHUP edit of its capabilities
/// or rate limit applies too. A token that has been removed or has expired
/// is answered [`TOKEN_REVOKED_CODE`] and its notifications are dropped,
/// before anything is charged or dispatched. Calls without a session (a
/// plain HTTP request, resolved by the HTTP layer moments before, or the
/// operator) pass through untouched.
///
/// It is outermost, ahead of [`BatchRateLayer`], so a frame's rate charge
/// and capability check see the current principal. A batch is one frame:
/// its token is resolved once, for all its entries.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokenRecheckLayer;

impl TokenRecheckLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> tower::Layer<S> for TokenRecheckLayer {
    type Service = TokenRecheck<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TokenRecheck { inner }
    }
}

/// The wrapped service produced by [`TokenRecheckLayer`].
#[derive(Clone, Debug)]
pub struct TokenRecheck<S> {
    inner: S,
}

/// The current principal for a call's session, `Ok(None)` for a call with
/// no session, `Err` for a session whose token no longer resolves.
fn recheck(ext: &jsonrpsee::types::Extensions) -> Result<Option<Principal>, ()> {
    match ext.get::<BearerSession>() {
        None => Ok(None),
        Some(session) => session.current().map(Some).ok_or(()),
    }
}

impl<S> RpcServiceT for TokenRecheck<S>
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

    fn call<'a>(&self, mut req: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        async move {
            match recheck(&req.extensions) {
                Ok(None) => inner.call(req).await,
                Ok(Some(p)) => {
                    req.extensions.insert(p);
                    inner.call(req).await
                }
                Err(()) => MethodResponse::error(req.id.clone(), token_revoked_error())
                    .with_extensions(req.extensions.clone()),
            }
        }
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        async move {
            // One frame, one resolution: the first entry that carries a
            // session decides for all of them (they share the upgrade's
            // extensions).
            let mut verdict: Option<Result<Option<Principal>, ()>> = None;
            let mut dropped = false;
            let mut entries = Vec::with_capacity(batch.len());
            for entry in batch.into_iter() {
                let entry = match entry {
                    Ok(mut e) => {
                        let v = verdict.get_or_insert_with(|| recheck(e.extensions())).clone();
                        match (v, &mut e) {
                            (Ok(None), _) => Ok(e),
                            (Ok(Some(p)), _) => {
                                e.extensions_mut().insert(p);
                                Ok(e)
                            }
                            (Err(()), BatchEntry::Call(req)) => Err(
                                BatchEntryErr::new(
                                    req.id.clone().into_owned(),
                                    token_revoked_error(),
                                ),
                            ),
                            // A notification gets no reply; one on a revoked
                            // token is dropped.
                            (Err(()), BatchEntry::Notification(_)) => {
                                dropped = true;
                                continue;
                            }
                        }
                    }
                    Err(err) => Err(err),
                };
                entries.push(entry);
            }
            // Nothing left because every entry was a dropped notification:
            // no reply, as for a batch of notifications. An empty batch as
            // sent goes on, to be answered `-32600` beneath.
            if entries.is_empty() && dropped {
                return MethodResponse::notification();
            }
            inner.batch(Batch::from(entries)).await
        }
    }

    fn notification<'a>(
        &self,
        mut n: Notification<'a>,
    ) -> impl Future<Output = MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        async move {
            match recheck(&n.extensions) {
                Ok(None) => inner.notification(n).await,
                Ok(Some(p)) => {
                    n.extensions.insert(p);
                    inner.notification(n).await
                }
                Err(()) => MethodResponse::notification(),
            }
        }
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
            ("addpeeraddress", Capability::TestNet),
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

    /// `addpeeraddress` writes an address of the caller's choosing into
    /// the book the node dials from, so it takes `test:net` too.
    #[tokio::test]
    async fn a_write_token_is_forbidden_on_addpeeraddress() {
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
        let rp = svc.call(req_with("addpeeraddress", Some(write_token))).await;
        assert!(rp.is_error());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        assert!(rp.as_json().get().contains("test:net"), "{}", rp.as_json().get());

        let net_token = Principal::token(
            Arc::from("net"),
            CapabilitySet::EMPTY.with(Capability::TestNet),
            None,
            None,
            Principal::operator().accounting().clone(),
        );
        let (svc, dispatched) = filter();
        let rp = svc.call(req_with("addpeeraddress", Some(net_token))).await;
        assert!(rp.is_success(), "{}", rp.as_json().get());
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
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

    /// A call as parsed from an HTTP body, whose unit the HTTP layer took.
    fn http(mut r: Request<'static>) -> Request<'static> {
        r.extensions.insert(HttpCharged);
        r
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
                http(req_with("getblockcount", Some(rl()))),
                http(req_with("getblockcount", Some(rl()))),
                http(req_with("getblockcount", Some(rl()))),
                http(req_with("getblockcount", Some(rl()))),
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

        // A single call from an HTTP body is not charged here (the HTTP
        // layer did that).
        let dispatched = Arc::new(AtomicUsize::new(0));
        let svc = rate_filter(&dispatched);
        for _ in 0..5 {
            let rp = svc.call(http(req_with("getblockcount", Some(rl())))).await;
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

    /// Notifications in a batch are charged like calls. jsonrpsee copies the
    /// HTTP request's extensions -- the principal included -- onto every
    /// batch entry, notifications as well as calls, so a notification over
    /// budget is dropped rather than dispatched. (On satd's listeners a
    /// client's notification never reaches this arm at all: the compat layer
    /// gives every id-less request a synthetic id, so it arrives as a call;
    /// `test_rpc_bearer_batch_notifications_are_charged` covers that path.)
    #[tokio::test]
    async fn batch_notifications_are_charged_against_the_rate_limit() {
        use satd_auth::{LocalAccounting, RatePolicy};
        let acct: Arc<dyn satd_auth::Accounting> = Arc::new(LocalAccounting::new());
        let rl = || {
            Principal::token(
                Arc::from("rl"),
                CapabilitySet::EMPTY.with(Capability::RpcSubmit),
                None,
                Some(RatePolicy {
                    burst: 2,
                    per_sec: 2,
                }),
                acct.clone(),
            )
        };
        let notif = |p: Principal| {
            let mut n = Notification::new("sendrawtransaction".into(), None);
            n.extensions.insert(p);
            n.extensions.insert(HttpCharged);
            Ok(BatchEntry::Notification(n))
        };
        let dispatched = Arc::new(AtomicUsize::new(0));
        let svc = BatchRateFilter {
            inner: Recorder {
                dispatched: dispatched.clone(),
            },
        };
        // Entry 0 is free and the bucket (2) covers entries 1 and 2; the
        // other seven are over budget.
        let rp = svc
            .batch(Batch::from((0..10).map(|_| notif(rl())).collect::<Vec<_>>()))
            .await;
        assert!(rp.is_notification(), "an all-notification batch has no reply");
        assert_eq!(dispatched.load(Ordering::SeqCst), 3);
    }

    fn rate_limited(acct: &Arc<dyn satd_auth::Accounting>) -> Principal {
        Principal::token(
            Arc::from("rl"),
            CapabilitySet::EMPTY.with(Capability::RpcSubmit),
            None,
            Some(satd_auth::RatePolicy {
                burst: 2,
                per_sec: 2,
            }),
            acct.clone(),
        )
    }

    /// A WebSocket frame carries the upgrade request's principal but not
    /// [`HttpCharged`]: the upgrade paid once, the frames did not. Every
    /// frame -- single call, notification, or batch entry, the first one
    /// included -- costs one.
    #[tokio::test]
    async fn websocket_frames_are_charged_against_the_rate_limit() {
        let acct: Arc<dyn satd_auth::Accounting> =
            Arc::new(satd_auth::LocalAccounting::new());
        let dispatched = Arc::new(AtomicUsize::new(0));
        let svc = BatchRateFilter {
            inner: Recorder {
                dispatched: dispatched.clone(),
            },
        };

        let mut shed = 0;
        for _ in 0..5 {
            let rp = svc.call(req_with("sendrawtransaction", Some(rate_limited(&acct)))).await;
            if !rp.is_success() {
                let reply: serde_json::Value = serde_json::from_str(rp.as_json().get()).unwrap();
                assert_eq!(reply["error"]["code"], RATE_LIMITED_CODE, "{reply}");
                shed += 1;
            }
        }
        assert_eq!(dispatched.load(Ordering::SeqCst), 2, "burst 2 admits two frames");
        assert_eq!(shed, 3);

        // The bucket is empty: a notification frame is dropped, and a batch
        // frame's first entry is charged like the rest.
        let mut n = Notification::new("sendrawtransaction".into(), None);
        n.extensions.insert(rate_limited(&acct));
        svc.notification(n).await;
        let rp = svc
            .batch(batch_of(vec![req_with("sendrawtransaction", Some(rate_limited(&acct)))]))
            .await;
        assert_eq!(batch_replies(&rp)[0]["error"]["code"], RATE_LIMITED_CODE);
        assert_eq!(dispatched.load(Ordering::SeqCst), 2);
    }

    /// The HTTP layer's unit pays for the first call a body dispatches, not
    /// for whatever sits at index 0: a malformed entry there is answered
    /// without spending it, so the call after it is still free.
    #[tokio::test]
    async fn a_malformed_first_entry_does_not_spend_the_http_unit() {
        use jsonrpsee::server::middleware::rpc::BatchEntryErr;
        let acct: Arc<dyn satd_auth::Accounting> =
            Arc::new(satd_auth::LocalAccounting::new());
        // Drain the bucket so any charge at all would shed the call.
        let p = rate_limited(&acct);
        while matches!(p.check_rate(), satd_auth::RateDecision::Allow) {}

        let dispatched = Arc::new(AtomicUsize::new(0));
        let svc = BatchRateFilter {
            inner: Recorder {
                dispatched: dispatched.clone(),
            },
        };
        let junk = BatchEntryErr::new(
            Id::Null,
            jsonrpsee::types::ErrorObject::owned(-32600, "Invalid request", None::<()>),
        );
        let rp = svc
            .batch(Batch::from(vec![
                Err(junk),
                Ok(BatchEntry::Call(http(req_with("getblockcount", Some(rate_limited(&acct)))))),
            ]))
            .await;
        let replies = batch_replies(&rp);
        assert_eq!(replies[0]["error"]["code"], -32600, "{}", replies[0]);
        assert!(replies[1].get("result").is_some(), "the call is prepaid: {}", replies[1]);
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    }

    /// An authfile holding one token, `ws-tok`, with `rpc:read` and the
    /// given extra lines.
    fn write_ws_authfile(dir: &std::path::Path, extra: &str) -> std::path::PathBuf {
        use std::io::Write as _;
        let path = dir.join("auth.toml");
        let body = format!(
            "version = 1\n[[token]]\nid = \"ws\"\nhash = \"sha256:{}\"\ncapabilities = [\"rpc:read\"]\n{extra}",
            hex::encode(satd_auth::token_digest("ws-tok"))
        );
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    /// A frame as jsonrpsee hands it over on a WebSocket: the upgrade's
    /// principal (here a stale operator one, to show it is replaced) and
    /// the session.
    fn ws_frame(method: &'static str, session: &BearerSession) -> Request<'static> {
        let mut r = req_with(method, Some(Principal::operator()));
        r.extensions.insert(session.clone());
        r
    }

    /// #821: every frame on a WebSocket resolves its token against the
    /// store as it is now. The frame's principal is the token's current
    /// one (a stale operator principal does not reach `sendrawtransaction`
    /// on a read token); after a reload drops the token, or once it has
    /// expired, calls are answered `-32006` and nothing is dispatched.
    ///
    /// Perturbation: without the layer's recheck the frames keep the
    /// upgrade's principal, so `sendrawtransaction` and the post-revocation
    /// calls are dispatched.
    #[tokio::test]
    async fn websocket_frames_are_rechecked_against_the_token_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_ws_authfile(dir.path(), "");
        let store = Arc::new(satd_auth::TokenStore::load(&path).unwrap());
        let session = BearerSession::new(store.clone(), satd_auth::token_digest("ws-tok"));
        let dispatched = Arc::new(AtomicUsize::new(0));
        let svc = TokenRecheck {
            inner: BatchRateFilter {
                inner: CapabilityFilter { inner: Recorder { dispatched: dispatched.clone() } },
            },
        };

        let rp = svc.call(ws_frame("getblockcount", &session)).await;
        assert!(rp.is_success(), "{}", rp.as_json().get());
        let rp = svc.call(ws_frame("sendrawtransaction", &session)).await;
        assert!(rp.as_json().get().contains("-32004"), "the token's own caps apply: {}", rp.as_json().get());
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);

        // Expired: the reload keeps the token but its `expires` has passed.
        write_ws_authfile(dir.path(), "expires = 1\n");
        store.reload().unwrap();
        let rp = svc.call(ws_frame("getblockcount", &session)).await;
        assert!(rp.as_json().get().contains("-32006"), "expired: {}", rp.as_json().get());

        // Valid again, then removed.
        write_ws_authfile(dir.path(), "");
        store.reload().unwrap();
        assert!(svc.call(ws_frame("getblockcount", &session)).await.is_success());
        assert_eq!(dispatched.load(Ordering::SeqCst), 2);
        std::fs::write(&path, "version = 1\n").unwrap();
        store.reload().unwrap();
        let rp = svc.call(ws_frame("getblockcount", &session)).await;
        assert!(rp.as_json().get().contains("-32006"), "revoked: {}", rp.as_json().get());

        // A batch frame: every call refused, the notification dropped.
        let mut note = jsonrpsee::types::Notification::new("getblockcount".into(), None);
        note.extensions.insert(session.clone());
        let rp = svc
            .batch(Batch::from(vec![
                Ok(BatchEntry::Call(ws_frame("getblockcount", &session))),
                Ok(BatchEntry::Notification(note)),
                Ok(BatchEntry::Call(ws_frame("getbestblockhash", &session))),
            ]))
            .await;
        let replies = batch_replies(&rp);
        assert_eq!(replies.len(), 2, "{replies:?}");
        for r in &replies {
            assert_eq!(r["error"]["code"], TOKEN_REVOKED_CODE, "{r}");
        }
        assert_eq!(dispatched.load(Ordering::SeqCst), 2, "nothing dispatched after revocation");
    }

    /// An empty batch (`[]`) is still answered `-32600` by the layers
    /// beneath; only a batch emptied by dropping a revoked token's
    /// notifications gets no reply.
    #[tokio::test]
    async fn an_empty_batch_is_still_invalid_behind_the_recheck() {
        let dispatched = Arc::new(AtomicUsize::new(0));
        let svc = TokenRecheck { inner: BatchRateFilter { inner: Recorder { dispatched: dispatched.clone() } } };
        let rp = svc.batch(Batch::from(vec![])).await;
        assert!(rp.as_json().get().contains("-32600"), "{}", rp.as_json().get());

        let dir = tempfile::tempdir().unwrap();
        let path = write_ws_authfile(dir.path(), "");
        let store = Arc::new(satd_auth::TokenStore::load(&path).unwrap());
        let session = BearerSession::new(store.clone(), satd_auth::token_digest("ws-tok"));
        std::fs::write(&path, "version = 1\n").unwrap();
        store.reload().unwrap();
        let mut note = jsonrpsee::types::Notification::new("getblockcount".into(), None);
        note.extensions.insert(session);
        let rp = svc.batch(Batch::from(vec![Ok(BatchEntry::Notification(note))])).await;
        assert!(rp.is_notification(), "no reply: {}", rp.as_json().get());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    }

    /// A call with no session -- a plain HTTP request, or the operator --
    /// passes the recheck untouched.
    #[tokio::test]
    async fn calls_without_a_session_pass_the_recheck() {
        let dispatched = Arc::new(AtomicUsize::new(0));
        let svc = TokenRecheck { inner: Recorder { dispatched: dispatched.clone() } };
        assert!(svc.call(req_with("getblockcount", Some(Principal::operator()))).await.is_success());
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    }
}
