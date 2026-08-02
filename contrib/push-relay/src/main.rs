//! satd alert webhook → APNs / FCM push relay (reference implementation).
//!
//! ```sh
//! satd-push-relay /etc/satd-push-relay/relay.toml
//! ```
//!
//! # What this is
//!
//! A ~600-line service that receives satd's signed alert webhooks and forwards
//! the ones worth waking someone for as push notifications, using the
//! operator's own Apple/Google credentials.
//!
//! It exists as a **separate process, outside the satd workspace**, so a
//! Bitcoin node never carries a push-provider credential or the JWT/OAuth
//! dependency stack that comes with one. That is a deliberate boundary, not an
//! accident of packaging.
//!
//! # What this is not
//!
//! Reference-grade, and meant to be forked: a wallet vendor wants device
//! registration, per-user routing, and their own retry policy, none of which
//! belong in an example. What is worth copying verbatim is the receive path —
//! verify the raw body in constant time before parsing it, deduplicate on
//! `X-Satd-Delivery`, and acknowledge fast so the node's queue does not back up
//! behind your provider's latency.

mod config;
mod event;
mod push;
mod verify;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use tokio::sync::Mutex;

use config::Config;
use verify::DeliveryDedup;

/// How many recent delivery ids to remember. satd retries with backoff to a
/// 5-minute ceiling, so this needs to cover minutes, not days.
const DEDUP_WINDOW: usize = 4096;

/// Largest body this relay will buffer. An alert envelope is a few hundred
/// bytes; satd caps the `message` and every `details` value, so nothing
/// legitimate approaches this.
///
/// Set explicitly rather than left to axum's implicit 2 MB default. The
/// extractor must buffer the whole body *before* the signature can be checked,
/// so this bound is what an unauthenticated peer can make the process allocate
/// per connection — and being explicit also matters for the audience: a forker
/// who swaps `Bytes` for a streaming extractor silently loses the implicit one.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Deadline on the request once axum is handling it — i.e. from the moment the
/// head has been parsed. Bounds a slow or stalled *body*, and the handler.
///
/// It does NOT cover the header phase: `tower_http`'s layer wraps the axum
/// service, and hyper only invokes that service after it has parsed the request
/// head. See [`HEADER_READ_TIMEOUT`], which is the half that does.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Deadline for a connection to finish sending its request headers.
///
/// This is the slowloris bound, and it has to live at the hyper layer rather
/// than in a tower layer. A peer that opens a connection and dribbles one
/// header byte per minute never completes the head, so hyper never calls the
/// service — meaning neither `REQUEST_TIMEOUT` nor
/// [`MAX_CONCURRENT_REQUESTS`] (also a service-level layer) ever applies. N such
/// connections consume N tasks and N file descriptors indefinitely, and the
/// process runs out of both. Then satd's real deliveries are refused and alerts
/// stop arriving — silently, since the node acknowledges nothing it could not
/// send.
///
/// Body-phase slowloris was already covered; this is the phase that was not.
const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Concurrent in-flight requests. satd delivers serially per hook, so even a
/// dozen hooks never approach this; it exists to bound what an unauthenticated
/// peer can allocate.
const MAX_CONCURRENT_REQUESTS: usize = 64;

/// How long shutdown waits for already-acknowledged pushes to finish.
///
/// Must stay below systemd's `TimeoutStopSec` (90 s by default) so the unit
/// still stops promptly; 15 s covers a provider round-trip with its own
/// timeout applied.
const SHUTDOWN_DRAIN: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    http: reqwest::Client,
    dedup: Arc<Mutex<DeliveryDedup>>,
    /// Pushes that have been acknowledged to satd but not yet delivered to a
    /// provider. Shutdown drains this; see `SHUTDOWN_DRAIN`.
    inflight: Arc<AtomicUsize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let path = std::env::args().nth(1).ok_or_else(|| {
        anyhow::anyhow!("usage: satd-push-relay <relay.toml>")
    })?;
    let cfg = Arc::new(Config::load(std::path::Path::new(&path))?);

    let state = AppState {
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?,
        dedup: Arc::new(Mutex::new(DeliveryDedup::new(DEDUP_WINDOW))),
        inflight: Arc::new(AtomicUsize::new(0)),
        cfg: cfg.clone(),
    };

    let inflight = state.inflight.clone();
    let app = Router::new()
        .route("/hook", post(receive))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            MAX_CONCURRENT_REQUESTS,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    tracing::info!(
        listen = %cfg.listen,
        apns = cfg.apns.is_some(),
        fcm = cfg.fcm.is_some(),
        min_severity = %cfg.min_severity,
        "satd push relay listening on /hook",
    );
    // Hand-rolled accept loop rather than `axum::serve`, for one reason:
    // `axum::serve` exposes no way to set hyper's header-read timeout, and that
    // is the only place the header phase can be bounded (see
    // `HEADER_READ_TIMEOUT`). Everything else — graceful shutdown, per-connection
    // tasks — is what `axum::serve` would have done.
    serve_with_header_timeout(listener, app, HEADER_READ_TIMEOUT, shutdown_signal()).await?;

    // `with_graceful_shutdown` waits for in-flight *requests*, and a push is
    // deliberately not one — it is acknowledged first and delivered on a
    // detached task, so that the node's serial per-hook queue does not sit
    // behind Apple's and Google's latency. Without this drain, returning from
    // `serve` drops the runtime and aborts those tasks at their await points:
    // `systemctl restart` during a critical push means satd already got its
    // 200, the delivery id is in its dedup ring, no retry is coming, and the
    // operator is never paged. That is exactly what the SIGTERM handling is
    // supposed to prevent.
    let deadline = std::time::Instant::now() + SHUTDOWN_DRAIN;
    loop {
        let remaining = inflight.load(Ordering::Acquire);
        if remaining == 0 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                remaining,
                "shutting down with pushes still in flight; satd has already \
                 acknowledged them and will not retry"
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Ok(())
}

/// Serve `app` on `listener` until `shutdown` resolves, with a bound on how long
/// a connection may take to send its request headers.
///
/// Equivalent to `axum::serve(listener, app).with_graceful_shutdown(shutdown)`
/// except for `http1().header_read_timeout(..)`, which `axum::serve` does not
/// expose and which is the only defence against a header-phase slowloris.
async fn serve_with_header_timeout(
    listener: tokio::net::TcpListener,
    app: Router,
    header_timeout: std::time::Duration,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .header_read_timeout(header_timeout)
        // Apple and Google speak to us over HTTP/1.1 here; satd does too. Keep
        // h2 available anyway so the relay is usable behind a proxy that
        // upgrades, and bound its header phase the same way.
        .timer(hyper_util::rt::TokioTimer::new());
    let builder = std::sync::Arc::new(builder);

    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                // A per-connection accept error (fd exhaustion, a peer that
                // vanished mid-handshake) must not take the listener down.
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            },
            _ = shutdown.as_mut() => break,
        };

        let svc = app.clone();
        let builder = builder.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                use tower::ServiceExt as _;
                svc.clone().oneshot(req)
            });
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), svc);
            if let Err(e) = watcher.watch(conn).await {
                tracing::debug!(%peer, error = %e, "connection closed with an error");
            }
        });
    }

    // Same bound the push drain uses: do not let a stuck connection hold
    // shutdown open past what systemd will wait for.
    let _ = tokio::time::timeout(SHUTDOWN_DRAIN, graceful.shutdown()).await;
    Ok(())
}

/// Decrements the in-flight count however the push task ends, including on an
/// early `?`/return inside it.
struct InflightGuard(Arc<AtomicUsize>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Resolve on SIGINT or SIGTERM.
///
/// SIGTERM matters more than SIGINT here: under systemd, `systemctl restart`
/// sends SIGTERM, and a relay that only waits on Ctrl-C is killed outright
/// mid-request — dropping any push it had already acknowledged to satd.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "could not install a SIGTERM handler");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// The receive path. Order matters: verify, then deduplicate, then acknowledge,
/// then do the slow work.
async fn receive(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let header = |name: &str| -> &str {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
    };
    let sig = header("x-satd-signature");
    let timestamp = header("x-satd-timestamp");
    let delivery_id = header("x-satd-delivery");
    let hook_id = header("x-satd-hook");

    // 1. Authenticate the RAW body plus the delivery metadata, before parsing.
    //    A re-serialized body does not verify, and parsing unauthenticated
    //    input is the thing to avoid.
    if !verify::signature_valid(
        &state.cfg.satd_secret,
        timestamp,
        delivery_id,
        hook_id,
        &body,
        sig,
    ) {
        tracing::warn!("rejected a delivery with a bad or missing signature");
        return StatusCode::UNAUTHORIZED;
    }

    // 2. Reject a stale delivery. The signature alone would make a captured
    //    request replayable forever — which matters most for the bodies an
    //    attacker would want to replay: a `cleared` status during a real
    //    incident, or a `raised` one at 3am.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if !verify::timestamp_fresh(timestamp, now, verify::MAX_TIMESTAMP_SKEW_SECS) {
        tracing::warn!(timestamp, "rejected a delivery outside the freshness window");
        return StatusCode::UNAUTHORIZED;
    }

    // 3. Suppress retries of something already acted on. Safe to key on the
    //    delivery id because it is inside the signature: a forged id cannot
    //    reach this point and pre-poison the window against a real alert.
    if !state.dedup.lock().await.insert(delivery_id) {
        tracing::debug!(delivery = delivery_id, "duplicate delivery, already handled");
        return StatusCode::OK;
    }

    let envelope: event::Envelope = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            // Acknowledge anyway: a body this relay cannot parse will not
            // parse on retry either, and refusing it would make satd hammer a
            // dead letter until its queue overflowed.
            tracing::warn!(error = %e, "could not parse a delivery body");
            return StatusCode::OK;
        }
    };

    let Some(notification) = event::to_notification(&envelope, &state.cfg.min_severity) else {
        return StatusCode::OK;
    };

    // 3. Acknowledge before pushing. satd delivers serially per hook, so
    //    holding the response open across two provider round-trips would put
    //    the node's queue behind Apple's and Google's latency.
    // Counted so shutdown can wait for it: the response below tells satd the
    // push is ours, and satd records the delivery id in its dedup ring and
    // never retries it. A push dropped after that point is a page nobody gets.
    state.inflight.fetch_add(1, Ordering::AcqRel);
    tokio::spawn(async move {
        let _guard = InflightGuard(state.inflight.clone());
        if let Some(apns) = &state.cfg.apns
            && let Err(e) = push::send_apns(&state.http, apns, &notification).await
        {
            tracing::error!(error = %e, "APNs push failed");
        }
        if let Some(fcm) = &state.cfg.fcm
            && let Err(e) = push::send_fcm(&state.http, fcm, &notification).await
        {
            tracing::error!(error = %e, "FCM push failed");
        }
    });
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A peer that opens a connection and never finishes its request headers
    /// must be dropped.
    ///
    /// This is the case neither `REQUEST_TIMEOUT` nor `MAX_CONCURRENT_REQUESTS`
    /// can reach: both are tower layers wrapping the axum service, and hyper
    /// only invokes that service once the head is parsed. So a dribbled header
    /// holds a task and a file descriptor while passing through no layer at
    /// all, and enough of them exhaust both — at which point satd's real
    /// deliveries are refused and alerts stop, with the node none the wiser
    /// because it acknowledged nothing it could not send.
    #[tokio::test]
    async fn a_connection_that_never_finishes_its_headers_is_dropped() {
        let app = Router::new().route("/hook", post(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(serve_with_header_timeout(
            listener,
            app,
            std::time::Duration::from_millis(200),
            async {
                let _ = stop_rx.await;
            },
        ));

        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        // A request line and one header, deliberately never terminated by the
        // blank line that ends the head.
        sock.write_all(b"POST /hook HTTP/1.1\r\nHost: x\r\n").await.unwrap();

        // The server must hang up on its own. Read until EOF; if the deadline
        // is not enforced this blocks and the outer timeout fails the test.
        let mut buf = Vec::new();
        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sock.read_to_end(&mut buf),
        )
        .await;
        assert!(
            closed.is_ok(),
            "the server kept a half-sent request open past the header deadline",
        );

        let _ = stop_tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    }

    /// The mirror: a complete request is served normally, so the deadline is
    /// not just closing everything.
    #[tokio::test]
    async fn a_complete_request_is_served() {
        let app = Router::new().route("/hook", post(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(serve_with_header_timeout(
            listener,
            app,
            std::time::Duration::from_millis(200),
            async {
                let _ = stop_rx.await;
            },
        ));

        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"POST /hook HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 15];
        tokio::time::timeout(std::time::Duration::from_secs(5), sock.read_exact(&mut buf))
            .await
            .expect("a complete request must be answered")
            .expect("read the status line");
        assert!(
            String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200"),
            "got: {}",
            String::from_utf8_lossy(&buf),
        );

        let _ = stop_tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    }
}
