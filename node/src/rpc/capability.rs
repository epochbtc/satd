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

/// Mirror of jsonrpsee's default `max_response_body_size` (10 MiB); used by the
/// batch-response builder, matching what the inner service enforces.
const RESPONSE_BODY_LIMIT: usize = 10 * 1024 * 1024;

/// The capability a method requires. Read-classified methods need `rpc:read`;
/// everything else — mempool-submit, control, block-connecting, AND unclassified
/// (unknown) methods — needs `rpc:write`. Fail-closed: an unknown method can
/// never be reached by a read-only token.
fn required_capability(method: &str) -> Capability {
    match classify(method) {
        Some(RpcAccess::Read) => Capability::RpcRead,
        _ => Capability::RpcWrite,
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
        let rp = svc
            .call(req_with("sendrawtransaction", Some(read_only_token())))
            .await;
        assert!(rp.is_error());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        assert!(rp.as_json().get().contains("rpc:write"));
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
}
