//! Bitcoin Core `-28 RPC in warmup` semantics for the startup RPC listener.
//!
//! While a Bitcoin Core node is still coming up it answers *every* RPC with
//! `-28` and a human-readable status line ("Loading block index...", "Verifying
//! blocks...", ...). That code is a contract, not a nicety: it is how a client
//! learns "the node is alive, ask again shortly" as distinct from "this node
//! cannot do what you asked". Core's own tooling polls on it, `bitcoin-cli`
//! prints a warmup-specific message for it, and Core's functional-test
//! framework retries only on `-28` and `-342` -- any other error is fatal.
//!
//! satd's startup listener serves exactly one method, `getstartupinfo`, and
//! left everything else to jsonrpsee's default `-32601 Method not found`. A
//! Core-compatible client polling `getblockcount` during startup therefore got
//! a hard "no such method" from a node that does, in fact, have that method a
//! moment later. This layer restores Core's answer: anything other than the
//! methods the startup listener really serves is answered `-28`, carrying the
//! live progress message so the reply is genuinely informative.
//!
//! It is installed only on the startup listener, which is torn down when the
//! full RPC server takes over the port. On every other surface the layer is
//! `None` and costs nothing.

use std::future::Future;
use std::sync::Arc;

use jsonrpsee::server::middleware::rpc::{Batch, BatchEntry, Notification, RpcServiceT};
use jsonrpsee::server::{BatchResponseBuilder, MethodResponse};
use jsonrpsee::types::{ErrorObjectOwned, Request};

use crate::rpc::readonly::RESPONSE_BODY_LIMIT;

/// Bitcoin Core's `RPC_IN_WARMUP`. Clients treat it as "retry shortly".
pub const RPC_IN_WARMUP: i32 = -28;

/// Methods the startup listener genuinely serves. Everything else is still
/// warming up as far as a caller is concerned.
const STARTUP_METHODS: &[&str] = &["getstartupinfo"];

/// Source of the human-readable status that accompanies the `-28`.
pub trait WarmupStatus: Send + Sync + 'static {
    fn message(&self) -> String;
}

fn warmup_error(status: &dyn WarmupStatus) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(RPC_IN_WARMUP, status.message(), None::<()>)
}

/// Layer answering `-28` for any method the startup listener does not serve.
///
/// Apply via `RpcServiceBuilder::new().option_layer(warmup)`; `None` on every
/// surface but the startup listener.
#[derive(Clone)]
pub struct WarmupLayer {
    status: Arc<dyn WarmupStatus>,
}

impl WarmupLayer {
    pub fn new(status: Arc<dyn WarmupStatus>) -> Self {
        Self { status }
    }
}

impl<S> tower::Layer<S> for WarmupLayer {
    type Service = WarmupFilter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WarmupFilter {
            inner,
            status: self.status.clone(),
        }
    }
}

/// The wrapped service produced by [`WarmupLayer`].
#[derive(Clone)]
pub struct WarmupFilter<S> {
    inner: S,
    status: Arc<dyn WarmupStatus>,
}

fn is_startup_method(method: &str) -> bool {
    STARTUP_METHODS.contains(&method)
}

impl<S> RpcServiceT for WarmupFilter<S>
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
        let status = self.status.clone();
        async move {
            if is_startup_method(req.method_name()) {
                inner.call(req).await
            } else {
                let err = warmup_error(status.as_ref());
                MethodResponse::error(req.id.clone(), err).with_extensions(req.extensions.clone())
            }
        }
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        // Per-entry semantics, matching jsonrpsee's own batch loop: a batch
        // mixing `getstartupinfo` with ordinary methods answers each entry on
        // its own terms rather than failing wholesale.
        let inner = self.inner.clone();
        let status = self.status.clone();
        async move {
            let mut builder = BatchResponseBuilder::new_with_limit(RESPONSE_BODY_LIMIT);
            let mut got_notification = false;

            for entry in batch.into_iter() {
                match entry {
                    Ok(BatchEntry::Call(req)) => {
                        let rp = if is_startup_method(req.method_name()) {
                            inner.call(req).await
                        } else {
                            let err = warmup_error(status.as_ref());
                            MethodResponse::error(req.id.clone(), err)
                                .with_extensions(req.extensions.clone())
                        };
                        if let Err(too_big) = builder.append(rp) {
                            return too_big;
                        }
                    }
                    Ok(BatchEntry::Notification(n)) => {
                        got_notification = true;
                        if is_startup_method(n.method_name()) {
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
            if is_startup_method(n.method_name()) {
                inner.notification(n).await
            } else {
                // A notification expects no reply, so there is nowhere to put
                // the -28; dropping it matches how the read-only filter treats
                // a disallowed notification.
                MethodResponse::notification()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedStatus(&'static str);
    impl WarmupStatus for FixedStatus {
        fn message(&self) -> String {
            self.0.to_string()
        }
    }

    /// The startup listener's own method must still work -- the point is to
    /// report progress, not to black-hole the surface.
    #[test]
    fn startup_method_is_served() {
        assert!(is_startup_method("getstartupinfo"));
    }

    /// Every ordinary RPC is "warming up", not "not found". A Core client
    /// distinguishes the two and only retries on the former.
    #[test]
    fn ordinary_methods_are_warmup() {
        for method in ["getblockcount", "getblockchaininfo", "stop", "getpeerinfo"] {
            assert!(!is_startup_method(method), "{method}");
        }
    }

    /// The code is Core's `-28` and the message carries the live status, so a
    /// polling client can show the operator what the node is doing.
    #[test]
    fn error_is_core_warmup_code_with_status() {
        let err = warmup_error(&FixedStatus("Loading block index..."));
        assert_eq!(err.code(), -28);
        assert_eq!(err.message(), "Loading block index...");
    }
}
