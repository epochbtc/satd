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

/// Whole-request deadline, headers included. Without it, `POST /hook` followed
/// by one header byte per minute holds a connection and its task forever.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Concurrent in-flight requests. satd delivers serially per hook, so even a
/// dozen hooks never approach this; it exists to bound what an unauthenticated
/// peer can allocate.
const MAX_CONCURRENT_REQUESTS: usize = 64;

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    http: reqwest::Client,
    dedup: Arc<Mutex<DeliveryDedup>>,
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
        cfg: cfg.clone(),
    };

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
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
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
    tokio::spawn(async move {
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
