//! RPC admission control — Bitcoin Core `-rpcthreads` / `-rpcworkqueue`.
//!
//! Bitcoin Core services JSON-RPC from a fixed thread pool (`-rpcthreads`,
//! default 16) fronted by a bounded work queue (`-rpcworkqueue`, default
//! 64). When every worker is busy and the queue is full, Core rejects the
//! request with HTTP 503. satd is async rather than thread-per-request, so
//! there is no literal thread pool — but the *observable contract* (bound
//! concurrent work, bound the backlog, shed beyond it) is what integrators
//! and Core-shaped configs depend on, so we honor the two knobs with the
//! closest async equivalent:
//!
//! - `-rpcthreads` → a semaphore of N permits bounding **concurrent
//!   in-flight** method calls.
//! - `-rpcworkqueue` → how many additional requests may **wait** for a
//!   permit before the server sheds load.
//!
//! When `in-flight + waiting` would exceed `rpcthreads + rpcworkqueue`, the
//! request is shed immediately. satd returns **HTTP 429 (Too Many
//! Requests)** with a `Retry-After` header rather than Core's 503: 429 is
//! the semantically correct code for a client-rate/backlog rejection, and
//! the divergence is deliberate and documented (see `config.rs` help text
//! for `--rpcworkqueue`).
//!
//! This is an HTTP-level tower layer, installed **outermost** in the RPC
//! middleware stack (before auth/compat) so the cheap shed decision happens
//! before any per-request work. The `-rpcallowip` check still runs ahead of
//! it on the plain-HTTP path, so source-IP-denied requests (403) never
//! consume an admission slot.
//!
//! A single [`AdmissionState`] is shared (via `Arc`) across every RPC
//! surface — plain-HTTP and TLS — so the cap is one node-wide RPC work
//! budget, not a per-surface or per-connection one.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use jsonrpsee::server::HttpBody;
use tokio::sync::Semaphore;

/// Shared admission budget for the JSON-RPC surfaces.
///
/// `sem` bounds concurrent in-flight calls to `threads`; `outstanding`
/// tracks in-flight + waiting requests and is compared against
/// `max_outstanding` (= `threads + workqueue`) to shed once the backlog is
/// full.
#[derive(Debug)]
pub struct AdmissionState {
    sem: Semaphore,
    outstanding: AtomicUsize,
    max_outstanding: usize,
}

impl AdmissionState {
    /// Build admission state from the Core-compatible knobs. `threads` is
    /// clamped to at least 1 (a zero-thread RPC server can never make
    /// progress); `workqueue` may be 0 (reject as soon as all workers are
    /// busy).
    pub fn new(threads: usize, workqueue: usize) -> Arc<Self> {
        // Clamp to a sane ceiling so a fat-fingered config value can't panic
        // `tokio::sync::Semaphore::new` (which panics above `usize::MAX >> 3`)
        // or overflow `threads + workqueue`. A few thousand concurrent
        // in-flight RPCs already dwarfs any real workload, so the ceiling only
        // ever catches typos / hostile configs, never a legitimate value.
        const MAX: usize = 100_000;
        let threads = threads.clamp(1, MAX);
        let workqueue = workqueue.min(MAX);
        Arc::new(Self {
            sem: Semaphore::new(threads),
            outstanding: AtomicUsize::new(0),
            max_outstanding: threads.saturating_add(workqueue),
        })
    }

    /// Current in-flight + waiting request count. Test/observability hook.
    pub fn outstanding(&self) -> usize {
        self.outstanding.load(Ordering::Acquire)
    }
}

/// Tower layer installing the RPC admission-control shim.
#[derive(Clone)]
pub struct AdmissionLayer {
    state: Arc<AdmissionState>,
}

impl AdmissionLayer {
    pub fn new(state: Arc<AdmissionState>) -> Self {
        Self { state }
    }
}

impl<S> tower::Layer<S> for AdmissionLayer {
    type Service = AdmissionMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AdmissionMiddleware {
            inner,
            state: self.state.clone(),
        }
    }
}

/// RAII release of the backlog reservation taken at the top of
/// [`AdmissionMiddleware::call`]. The reservation MUST be released on every
/// exit path — completion, inner error, future cancellation, panic — so the
/// decrement lives in `Drop` rather than as a trailing statement that
/// cancellation or unwinding would skip. A leaked reservation permanently
/// shrinks effective capacity (every later request sheds with 429 at zero
/// real load) until the process restarts. Mirrors the RAII pattern used by
/// the gRPC `SubscriptionGuard` and the RPC audit guard.
struct OutstandingGuard(Arc<AdmissionState>);

impl Drop for OutstandingGuard {
    fn drop(&mut self) {
        self.0.outstanding.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Tower service that admits, queues, or sheds each RPC request before
/// forwarding it to the inner (auth → compat → jsonrpsee) stack.
#[derive(Clone)]
pub struct AdmissionMiddleware<S> {
    inner: S,
    state: Arc<AdmissionState>,
}

impl<S, B> tower::Service<hyper::Request<B>> for AdmissionMiddleware<S>
where
    S: tower::Service<hyper::Request<B>, Response = hyper::Response<HttpBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // Admission is performed in `call` (the inner service is cloned and
        // driven there, matching the auth/compat layers); readiness is
        // unconditional so the backlog accounting — not tower readiness —
        // is what bounds the queue.
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: hyper::Request<B>) -> Self::Future {
        let state = self.state.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            // Reserve a backlog slot. `outstanding` counts in-flight +
            // waiting; once it would exceed `threads + workqueue` the
            // request is shed with 429 and the reservation is rolled back.
            let admitted = state.outstanding.fetch_add(1, Ordering::AcqRel) + 1;
            if admitted > state.max_outstanding {
                state.outstanding.fetch_sub(1, Ordering::AcqRel);
                return Ok(too_many_requests());
            }

            // From here the reservation is released by RAII on EVERY exit
            // path — normal completion, inner-service error, future
            // cancellation (hyper drops the in-flight service future when a
            // client disconnects mid-request), and panic — exactly like the
            // semaphore permit below. The shed branch above returns before
            // this guard exists, so it rolls the reservation back manually.
            let _outstanding = OutstandingGuard(state.clone());

            // Wait for a worker permit. Holding it across `inner.call`
            // bounds concurrent in-flight calls to `threads`; requests that
            // get here but can't yet acquire a permit are the "queued"
            // ones, bounded above by the `max_outstanding` check. The
            // semaphore is never closed, so `acquire` only ever returns
            // `Ok`; `.ok()` degrades to unbounded rather than panicking in
            // the impossible closed case.
            let _permit = state.sem.acquire().await.ok();
            inner.call(req).await
        })
    }
}

/// `429 Too Many Requests` with `Retry-After: 1` — the shed response when
/// the RPC work queue is full. Intentionally diverges from Core's 503 (see
/// the module docs and `--rpcworkqueue` help text).
fn too_many_requests() -> hyper::Response<HttpBody> {
    hyper::Response::builder()
        .status(hyper::StatusCode::TOO_MANY_REQUESTS)
        .header(hyper::header::RETRY_AFTER, "1")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(HttpBody::from(
            r#"{"result":null,"error":{"code":-32603,"message":"Server busy: RPC work queue full"},"id":null}"#,
        ))
        .expect("static 429 response is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use tower::{Service, ServiceExt};

    /// Inner service that parks each call until the test releases it. The
    /// gate is a **semaphore** (level-triggered), not a `Notify`
    /// (edge-triggered): a call that reaches `acquire().await` *after* the
    /// test adds permits still proceeds, so there is no missed-wakeup race
    /// even under scheduler load.
    #[derive(Clone)]
    struct Parker {
        gate: Arc<Semaphore>,
        active: Arc<AtomicUsize>,
    }

    impl Service<hyper::Request<HttpBody>> for Parker {
        type Response = hyper::Response<HttpBody>;
        type Error = Infallible;
        type Future = std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Self::Response, Infallible>> + Send>,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Infallible>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: hyper::Request<HttpBody>) -> Self::Future {
            let gate = self.gate.clone();
            let active = self.active.clone();
            Box::pin(async move {
                active.fetch_add(1, Ordering::AcqRel);
                // Block until released; the permit is returned immediately
                // (we only need the wakeup), so one `add_permits` unblocks
                // any number of parked calls.
                let _ = gate.acquire().await;
                active.fetch_sub(1, Ordering::AcqRel);
                Ok(hyper::Response::new(HttpBody::from("ok")))
            })
        }
    }

    fn req() -> hyper::Request<HttpBody> {
        hyper::Request::builder()
            .body(HttpBody::from("{}"))
            .unwrap()
    }

    /// Poll `cond` until it holds or the deadline elapses (avoids depending
    /// on a single fixed sleep for tasks to reach a state).
    async fn wait_until(mut cond: impl FnMut() -> bool) {
        for _ in 0..200 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not reached within deadline");
    }

    #[tokio::test]
    async fn sheds_with_429_when_queue_full() {
        // threads=1, workqueue=1 → at most 1 in-flight + 1 waiting = 2
        // admitted; the 3rd concurrent request is shed.
        let state = AdmissionState::new(1, 1);
        let gate = Arc::new(Semaphore::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let inner = Parker {
            gate: gate.clone(),
            active: active.clone(),
        };
        let layer = AdmissionLayer::new(state.clone());
        let svc = tower::layer::Layer::layer(&layer, inner);

        // Fire two requests: one occupies the single worker, the other
        // waits in the queue slot. Both are "outstanding" in the budget.
        let mut s1 = svc.clone();
        let mut s2 = svc.clone();
        let h1 = tokio::spawn(async move { s1.ready().await.unwrap().call(req()).await });
        let h2 = tokio::spawn(async move { s2.ready().await.unwrap().call(req()).await });

        // Wait until both are admitted (one running, one queued).
        wait_until(|| state.outstanding() == 2).await;

        // Third request: queue is full → shed with 429, synchronously.
        let mut s3 = svc.clone();
        let resp = s3.ready().await.unwrap().call(req()).await.unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(hyper::header::RETRY_AFTER));

        // Release the parked work; both originals complete and the budget
        // drains back to zero. `add_permits` is level-triggered so this
        // cannot miss a not-yet-parked waiter.
        gate.add_permits(8);
        let _ = h1.await.unwrap();
        let _ = h2.await.unwrap();
        wait_until(|| state.outstanding() == 0).await;
    }

    #[tokio::test]
    async fn cancelled_request_does_not_leak_outstanding() {
        // A request that is admitted and then has its future dropped mid-
        // flight (the client disconnects and hyper drops the in-flight
        // service future) MUST release its backlog reservation. With a bare
        // trailing `fetch_sub`, the drop would skip it and `outstanding`
        // would leak — the server would eventually shed every request with
        // 429 at zero real load. Here the inner service parks forever (gate
        // never released), so the only way `outstanding` returns to 0 is the
        // RAII guard firing on cancellation.
        let state = AdmissionState::new(1, 1);
        let gate = Arc::new(Semaphore::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let inner = Parker {
            gate,
            active: active.clone(),
        };
        let layer = AdmissionLayer::new(state.clone());
        let svc = tower::layer::Layer::layer(&layer, inner);

        let mut s = svc.clone();
        let h = tokio::spawn(async move { s.ready().await.unwrap().call(req()).await });
        // Admitted and parked inside the inner service.
        wait_until(|| state.outstanding() == 1).await;
        wait_until(|| active.load(Ordering::Acquire) == 1).await;

        // Client disconnect: drop the in-flight future.
        h.abort();

        // The reservation must drain back to zero (panics if it leaks).
        wait_until(|| state.outstanding() == 0).await;
    }

    #[tokio::test]
    async fn oversized_admission_knobs_are_clamped_not_panicking() {
        // A hostile / fat-fingered config must not panic `Semaphore::new`
        // (panics above `usize::MAX >> 3`) or overflow `threads + workqueue`.
        let state = AdmissionState::new(usize::MAX, usize::MAX);
        // Clamped, finite, and still admits at least one request.
        assert!(state.max_outstanding <= 200_000);
        assert!(state.outstanding() == 0);
    }

    #[tokio::test]
    async fn admits_up_to_thread_limit_concurrently() {
        // threads=2 → exactly two calls run inside `inner` at once.
        let state = AdmissionState::new(2, 8);
        let gate = Arc::new(Semaphore::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let inner = Parker {
            gate: gate.clone(),
            active: active.clone(),
        };
        let layer = AdmissionLayer::new(state);
        let svc = tower::layer::Layer::layer(&layer, inner);

        let mut handles = Vec::new();
        for _ in 0..2 {
            let mut s = svc.clone();
            handles.push(tokio::spawn(async move {
                s.ready().await.unwrap().call(req()).await
            }));
        }
        // Both reach the inner service (semaphore admitted 2 at once).
        wait_until(|| active.load(Ordering::Acquire) == 2).await;
        gate.add_permits(8);
        for h in handles {
            let _ = h.await.unwrap();
        }
    }
}
