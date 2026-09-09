//! In-flight RPC tracking, behind `getrpcinfo`'s `active_commands`.
//!
//! Bitcoin Core keeps a `g_rpc_server_info.active_commands` list: every
//! executing request is inserted on entry and removed on completion, and
//! `getrpcinfo` renders it as `[{"method", "duration"}]` with the duration in
//! microseconds. It is what an operator reaches for when the node is
//! unresponsive and the question is *which* call is holding it.
//!
//! satd answered with a constant `[]`, which reads as "nothing is running" —
//! the opposite of the answer, and a worse failure than an absent field
//! because it looks like a measurement.
//!
//! This is a sibling of the other `RpcServiceT` layers
//! ([`crate::rpc::readonly`], [`crate::rpc::capability`],
//! [`crate::rpc::warmup`]): it wraps the service, records the method and its
//! start instant for as long as the inner future is running, and drops the
//! entry when it resolves. The registry is process-wide, so a call arriving
//! on one listener is visible to `getrpcinfo` on another — which is the whole
//! point, since the stuck call and the diagnosis rarely share a connection.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use jsonrpsee::server::middleware::rpc::{Batch, BatchEntry, Notification, RpcServiceT};
use jsonrpsee::server::{BatchResponseBuilder, MethodResponse};
use jsonrpsee::types::Request;
use parking_lot::Mutex;

/// One executing request.
#[derive(Clone, Debug)]
pub struct ActiveCommand {
    pub method: String,
    pub started: Instant,
}

/// Process-wide registry of in-flight requests, keyed by a monotonic token so
/// two concurrent calls to the same method are distinct entries.
static ACTIVE: Mutex<Vec<(u64, ActiveCommand)>> = Mutex::new(Vec::new());
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(0);

/// Guard: the entry lives exactly as long as this value. Held across the
/// inner future, so a request that panics or is cancelled mid-flight still
/// leaves the registry clean — a leaked entry would make `getrpcinfo` report
/// a call that finished long ago as still running.
struct ActiveGuard(u64);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let mut active = ACTIVE.lock();
        if let Some(i) = active.iter().position(|(t, _)| *t == self.0) {
            active.remove(i);
        }
    }
}

fn enter(method: &str) -> ActiveGuard {
    let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
    ACTIVE.lock().push((
        token,
        ActiveCommand {
            method: method.to_string(),
            started: Instant::now(),
        },
    ));
    ActiveGuard(token)
}

/// Every request currently executing, oldest first.
///
/// Includes the `getrpcinfo` call doing the asking — Core's does too, and its
/// `interface_rpc.py` asserts on exactly that (`len(active_commands) == 1`
/// with `method == "getrpcinfo"` on an otherwise idle node).
pub fn snapshot() -> Vec<ActiveCommand> {
    let active = ACTIVE.lock();
    let mut out: Vec<ActiveCommand> = active.iter().map(|(_, c)| c.clone()).collect();
    out.sort_by_key(|c| c.started);
    out
}

/// `getrpcinfo`'s `active_commands` array: `[{"method", "duration"}]`, the
/// duration in microseconds as Core reports it.
pub fn as_json() -> serde_json::Value {
    let now = Instant::now();
    serde_json::Value::Array(
        snapshot()
            .into_iter()
            .map(|c| {
                serde_json::json!({
                    "method": c.method,
                    "duration": now.saturating_duration_since(c.started).as_micros() as u64,
                })
            })
            .collect(),
    )
}

/// Layer that records each executing request for the life of its call.
#[derive(Clone, Copy, Debug, Default)]
pub struct ActiveCommandsLayer;

impl ActiveCommandsLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> tower::Layer<S> for ActiveCommandsLayer {
    type Service = ActiveCommandsTracker<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ActiveCommandsTracker { inner }
    }
}

/// The wrapped service produced by [`ActiveCommandsLayer`].
#[derive(Clone, Debug)]
pub struct ActiveCommandsTracker<S> {
    inner: S,
}

impl<S> RpcServiceT for ActiveCommandsTracker<S>
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
            let _guard = enter(req.method_name());
            inner.call(req).await
        }
    }

    fn batch<'a>(&self, batch: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        // Core tracks per *command*, not per HTTP request, so a batch shows
        // each member as it runs rather than one entry for the whole body.
        let inner = self.inner.clone();
        async move {
            let mut builder = BatchResponseBuilder::new_with_limit(
                crate::rpc::readonly::RESPONSE_BODY_LIMIT,
            );
            let mut got_notification = false;
            for entry in batch.into_iter() {
                match entry {
                    Ok(BatchEntry::Call(req)) => {
                        let rp = {
                            let _guard = enter(req.method_name());
                            inner.call(req).await
                        };
                        if let Err(too_big) = builder.append(rp) {
                            return too_big;
                        }
                    }
                    Ok(BatchEntry::Notification(n)) => {
                        got_notification = true;
                        let _guard = enter(n.method_name());
                        inner.notification(n).await;
                    }
                    Err(err) => {
                        let (err, id) = err.into_parts();
                        if let Err(too_big) = builder.append(MethodResponse::error(id, err)) {
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
            let _guard = enter(n.method_name());
            inner.notification(n).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry is process-wide, so these run serially against it.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn an_entry_lives_exactly_as_long_as_its_guard() {
        let _s = SERIAL.lock();
        assert!(snapshot().is_empty(), "clean start");
        let g = enter("getblockcount");
        let snap = snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].method, "getblockcount");
        drop(g);
        assert!(snapshot().is_empty(), "the guard removes its own entry");
    }

    /// Two concurrent calls to the same method are two entries: keying on the
    /// method name alone would collapse them, and "one slow getblock" is a
    /// different diagnosis from "forty".
    #[test]
    fn concurrent_calls_to_one_method_are_separate_entries() {
        let _s = SERIAL.lock();
        let a = enter("getblock");
        let b = enter("getblock");
        assert_eq!(snapshot().len(), 2);
        drop(a);
        assert_eq!(snapshot().len(), 1, "dropping one leaves the other");
        drop(b);
        assert!(snapshot().is_empty());
    }

    /// Entries come out oldest first, and the JSON carries Core's two keys
    /// with the duration in microseconds.
    #[test]
    fn the_json_is_cores_shape_oldest_first() {
        let _s = SERIAL.lock();
        let older = enter("verifychain");
        std::thread::sleep(std::time::Duration::from_millis(5));
        let newer = enter("getblockcount");

        let v = as_json();
        let arr = v.as_array().expect("array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["method"], "verifychain", "oldest first: {v}");
        assert_eq!(arr[1]["method"], "getblockcount", "{v}");
        let older_us = arr[0]["duration"].as_u64().expect("duration is a number");
        let newer_us = arr[1]["duration"].as_u64().unwrap();
        assert!(
            older_us >= newer_us,
            "the older call has run longer: {older_us} vs {newer_us}"
        );
        // Microseconds, not milliseconds: a 5ms-old entry is ~5000.
        assert!(older_us >= 4_000, "duration is in microseconds: {older_us}");

        drop(newer);
        drop(older);
        assert!(as_json().as_array().unwrap().is_empty());
    }
}
