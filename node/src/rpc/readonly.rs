//! Read-only RPC listener method filter (jsonrpsee RPC-layer middleware).
//!
//! This is the enforcement half of the opt-in read-only JSON-RPC listener.
//! It sits as an RPC-layer middleware (`set_rpc_middleware`) on the
//! read-only surfaces only — the default full read/write listener does not
//! carry it. By the time a request reaches this layer jsonrpsee has already
//! parsed the method name and split batches into per-entry calls, so the
//! filter is a thin method-name gate rather than a body-parsing HTTP layer.
//!
//! The policy lives in [`crate::rpc::access`]; this module is purely the
//! mechanism. A request whose method is not [read-only-allowed] is answered
//! with a JSON-RPC error (code [`READONLY_REJECT_CODE`]) instead of being
//! dispatched, so a block-connecting or control method can never execute on
//! the API runtime via this listener. The gate is **fail-closed**: an
//! unclassified method is rejected.
//!
//! [read-only-allowed]: crate::rpc::access::readonly_listener_allows

use std::future::Future;

use jsonrpsee::server::middleware::rpc::{Batch, BatchEntry, Notification, RpcServiceT};
use jsonrpsee::server::{BatchResponseBuilder, MethodResponse};
use jsonrpsee::types::{ErrorObjectOwned, Request};

use crate::rpc::access::readonly_listener_allows;

/// JSON-RPC error code returned for a method that exists on the node but is
/// not exposed on the read-only listener. Sits in the JSON-RPC
/// implementation-defined server-error range (`-32000..=-32099`), distinct
/// from `-32601 Method not found` so a client can tell "this method does not
/// exist" from "this method is not available *here*".
pub const READONLY_REJECT_CODE: i32 = -32001;

/// Mirror of jsonrpsee's default `max_response_body_size` (10 MiB). The
/// read-only surfaces build their `ServerConfig` without overriding it, so
/// the batch-response builder below uses the same bound the inner service
/// enforces. If a read-only surface ever overrides the response size, thread
/// that value through instead of this constant.
const RESPONSE_BODY_LIMIT: usize = 10 * 1024 * 1024;

fn rejected_error(method: &str) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        READONLY_REJECT_CODE,
        format!("method '{method}' is not available on the read-only RPC listener"),
        None::<()>,
    )
}

/// Layer that wraps an RPC service so only read-only-allowed methods are
/// dispatched. Apply via `RpcServiceBuilder::new().option_layer(filter)` so
/// the read/write listener (which passes `None`) stays a zero-cost identity.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReadOnlyLayer;

impl ReadOnlyLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> tower::Layer<S> for ReadOnlyLayer {
    type Service = ReadOnlyFilter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ReadOnlyFilter { inner }
    }
}

/// The wrapped service produced by [`ReadOnlyLayer`].
#[derive(Clone, Debug)]
pub struct ReadOnlyFilter<S> {
    inner: S,
}

impl<S> RpcServiceT for ReadOnlyFilter<S>
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
            if readonly_listener_allows(req.method_name()) {
                inner.call(req).await
            } else {
                let err = rejected_error(req.method_name());
                MethodResponse::error(req.id.clone(), err).with_extensions(req.extensions.clone())
            }
        }
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        // Mirror jsonrpsee's own `RpcService::batch` loop so per-entry
        // semantics are preserved: each call gets its own result (or
        // rejection) and notifications produce no response. A batch mixing
        // allowed reads with a rejected write yields per-entry errors for
        // the rejected entries rather than failing the whole batch.
        let inner = self.inner.clone();
        async move {
            let mut builder = BatchResponseBuilder::new_with_limit(RESPONSE_BODY_LIMIT);
            let mut got_notification = false;

            for entry in batch.into_iter() {
                match entry {
                    Ok(BatchEntry::Call(req)) => {
                        let rp = if readonly_listener_allows(req.method_name()) {
                            inner.call(req).await
                        } else {
                            let err = rejected_error(req.method_name());
                            MethodResponse::error(req.id.clone(), err)
                                .with_extensions(req.extensions.clone())
                        };
                        if let Err(too_big) = builder.append(rp) {
                            return too_big;
                        }
                    }
                    Ok(BatchEntry::Notification(n)) => {
                        got_notification = true;
                        // Notifications expect no reply; a disallowed one is
                        // silently dropped rather than forwarded.
                        if readonly_listener_allows(n.method_name()) {
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
            if readonly_listener_allows(n.method_name()) {
                inner.notification(n).await
            } else {
                // No response for a notification; preserve extensions so
                // transport-level headers still propagate.
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Minimal inner service: records how many times a method was actually
    /// dispatched, and echoes a success response.
    #[derive(Clone)]
    struct Recorder {
        dispatched: Arc<AtomicUsize>,
    }

    // The trait methods return `impl Future + Send + 'a` (RPITIT with an
    // explicit Send bound), which `async fn` can't express, so the
    // `manual_async_fn` lint doesn't apply here.
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

        fn batch<'a>(
            &self,
            _batch: Batch<'a>,
        ) -> impl Future<Output = MethodResponse> + Send + 'a {
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

    fn req(method: &'static str) -> Request<'static> {
        Request::owned(method.to_string(), None, Id::Number(1))
    }

    fn filter() -> (ReadOnlyFilter<Recorder>, Arc<AtomicUsize>) {
        let dispatched = Arc::new(AtomicUsize::new(0));
        let svc = ReadOnlyFilter {
            inner: Recorder {
                dispatched: dispatched.clone(),
            },
        };
        (svc, dispatched)
    }

    #[tokio::test]
    async fn allowed_read_is_dispatched() {
        let (svc, dispatched) = filter();
        let rp = svc.call(req("getblockcount")).await;
        assert!(rp.is_success());
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mempool_submit_is_dispatched() {
        let (svc, dispatched) = filter();
        let rp = svc.call(req("sendrawtransaction")).await;
        assert!(rp.is_success());
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn block_connecting_is_rejected_not_dispatched() {
        let (svc, dispatched) = filter();
        let rp = svc.call(req("submitblock")).await;
        assert!(rp.is_error());
        // The inner service was never reached.
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
        assert!(rp.as_json().get().contains("read-only RPC listener"));
    }

    #[tokio::test]
    async fn control_is_rejected_not_dispatched() {
        let (svc, dispatched) = filter();
        let rp = svc.call(req("stop")).await;
        assert!(rp.is_error());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unknown_method_is_rejected_fail_closed() {
        let (svc, dispatched) = filter();
        let rp = svc.call(req("totallynewrpc")).await;
        assert!(rp.is_error());
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    }
}
