//! JSON-over-WebSocket + SSE firehose transport for the streaming API.
//!
//! A dedicated `--streamws` listener (separate port, on the API runtime —
//! never the consensus core) serving the same event schema as the gRPC
//! `NodeEventStream`, hand-mapped to JSON (no grpc-gateway / Go toolchain):
//!
//! - `GET /ws` — a WebSocket: the server streams JSON `NodeEvent`s (live,
//!   category-filtered) and per-subscriber watch matches; the client sends
//!   JSON control messages to manage its watch-set (the JSON mirror of the
//!   gRPC `Watch` bidi stream).
//! - `GET /sse` — a read-only Server-Sent-Events firehose of JSON
//!   `NodeEvent`s, for browser / `curl` consumers (reuses the Esplora SSE
//!   pattern).
//!
//! Auth mirrors the gRPC sink: when a token store is configured, every
//! connection requires `Authorization: Bearer <token>` resolving to a
//! principal with `stream:subscribe`; each watch addition additionally
//! needs `stream:watch` + quota. With no token store (loopback trust) the
//! transport is open, today's events-gRPC behavior.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use node::chain::events::ChainEvent;
use node::events::{
    build_cursor_replay, BlockCursorSource, Cursor, EventPublisher, NodeEventBody, WatchMatch,
    WatchRegistry, MAX_REPLAY_BLOCKS, WATCH_CHANNEL_CAPACITY,
};
use serde::Deserialize;

use crate::watchset::{bounded_txid_depth_pairs, WatchSet};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, watch};
use tokio_stream::wrappers::BroadcastStream;
use tracing::{debug, info, warn};

/// Send a WebSocket Ping at this cadence and reap the connection if no frame
/// (Pong, control, or otherwise) is seen from the client within
/// [`WS_IDLE_TIMEOUT`] — so a dead or half-open peer cannot pin a connection
/// slot, watch-set, and quota indefinitely.
const WS_PING_INTERVAL: Duration = Duration::from_secs(30);
const WS_IDLE_TIMEOUT_SECS: i64 = 90;

/// Operator-configurable streamws limits (`streamwsmax*`). For the connection
/// and subscription caps, `0` ⇒ unlimited.
#[derive(Clone, Copy)]
pub struct WsLimits {
    /// Max concurrent `/ws` + `/sse` connections (`streamwsmaxconns`).
    pub max_conns: usize,
    /// Max watch-set entries per connection (`streamwsmaxsubscriptions`).
    pub max_subscriptions: usize,
    /// Max bytes for a single inbound WS message/frame (`streamwsmaxmessagebytes`).
    pub max_message_bytes: usize,
    /// Script-prefix watch granularity bounds (§7.5).
    pub prefix_min_bits: u8,
    pub prefix_max_bits: u8,
}

/// Construction-time errors for the WS transport.
#[derive(Debug, thiserror::Error)]
pub enum WsStreamError {
    #[error("invalid streamws bind address '{0}': {1}")]
    InvalidBind(String, std::net::AddrParseError),
    #[error(
        "refusing to bind streamws server on non-loopback address {0}: pass \
         --streamws-allow-remote (which requires --streamws-auth) to override"
    )]
    RemoteBindRejected(SocketAddr),
    #[error("failed to bind {0}: {1}")]
    BindFailed(SocketAddr, std::io::Error),
}

/// Shared handler state.
#[derive(Clone)]
struct WsState {
    publisher: Arc<EventPublisher>,
    watch_registry: Arc<WatchRegistry>,
    auth: Option<Arc<satd_auth::TokenStore>>,
    /// Active-chain access for durable `?from_cursor=` replay. `None` ⇒ a
    /// `from_cursor` query is honored as forward-only (no replay), matching the
    /// gRPC no-block-source fallback.
    block_source: Option<Arc<dyn BlockCursorSource>>,
    /// Admission control: bounds concurrent `/ws` + `/sse` connections
    /// (operator-set `streamwsmaxconns`; 0 ⇒ unlimited). A connection holds one
    /// permit for its whole lifetime, released on disconnect.
    conn_sem: Arc<Semaphore>,
    /// Per-connection watch-set entry cap (`streamwsmaxsubscriptions`; 0 ⇒
    /// unlimited). An add at/over the cap is shed without dropping the conn.
    max_subscriptions: usize,
    /// Cap on a single inbound WS message/frame (`streamwsmaxmessagebytes`).
    max_message_bytes: usize,
    /// Script-prefix watch granularity bounds (§7.5).
    prefix_min_bits: u8,
    prefix_max_bits: u8,
}

/// The `--streamws` JSON/WS + SSE transport. Bind early (so a bind failure
/// is reported at startup), then [`WsStreamServer::serve`] on the API
/// runtime.
pub struct WsStreamServer {
    addr: SocketAddr,
    listener: TcpListener,
    state: WsState,
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl WsStreamServer {
    /// Bind the listener. Only loopback is accepted unless `allow_remote`
    /// (which the config layer ties to `--streamws-auth`).
    pub async fn bind(
        bind: &str,
        allow_remote: bool,
        publisher: Arc<EventPublisher>,
        watch_registry: Arc<WatchRegistry>,
        auth: Option<Arc<satd_auth::TokenStore>>,
        block_source: Option<Arc<dyn BlockCursorSource>>,
        limits: WsLimits,
    ) -> Result<Self, WsStreamError> {
        let addr: SocketAddr = bind
            .parse()
            .map_err(|e| WsStreamError::InvalidBind(bind.to_string(), e))?;
        if !allow_remote && !is_loopback(&addr.ip()) {
            return Err(WsStreamError::RemoteBindRejected(addr));
        }
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| WsStreamError::BindFailed(addr, e))?;
        let bound = listener.local_addr().unwrap_or(addr);
        info!(
            target: "events::ws",
            addr = %bound,
            allow_remote,
            authenticated = auth.is_some(),
            "streamws server bound",
        );
        Ok(Self {
            addr: bound,
            listener,
            state: WsState {
                publisher,
                watch_registry,
                auth,
                block_source,
                // 0 ⇒ unlimited (mirrors the events-gRPC cap convention): a
                // near-MAX permit pool never blocks admission.
                conn_sem: Arc::new(Semaphore::new(if limits.max_conns == 0 {
                    Semaphore::MAX_PERMITS
                } else {
                    limits.max_conns
                })),
                max_subscriptions: limits.max_subscriptions,
                // 0 ⇒ unlimited, mirroring the other two caps. Passing 0 straight
                // to axum's max_message_size would instead REJECT every non-empty
                // frame, silently bricking the inbound control channel (adds /
                // removes / set_categories) while the outbound firehose kept
                // running — a confusing footgun. Map 0 → usize::MAX.
                max_message_bytes: if limits.max_message_bytes == 0 {
                    usize::MAX
                } else {
                    limits.max_message_bytes
                },
                prefix_min_bits: limits.prefix_min_bits,
                prefix_max_bits: limits.prefix_max_bits,
            },
        })
    }

    /// Bound address (test/observability helper).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve until `shutdown` flips. Intended to be spawned on the API
    /// runtime.
    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) {
        let app = Router::new()
            .route("/ws", get(ws_upgrade))
            .route("/sse", get(sse_firehose))
            .with_state(self.state);
        info!(target: "events::ws", addr = %self.addr, "streamws server starting");
        let result = axum::serve(self.listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown.changed().await;
            })
            .await;
        if let Err(e) = result {
            warn!(target: "events::ws", error = %e, "streamws server exited with error");
        }
    }
}

/// Authorize a connection: with a token store, require a bearer token
/// holding `stream:subscribe`. Returns the principal (or `None` when auth
/// is disabled) or an HTTP error response.
// The `Err` variant is an axum `Response` (large), but it's the natural
// return for an auth gate and is only built on the rejection path.
#[allow(clippy::result_large_err)]
fn authorize(state: &WsState, headers: &HeaderMap) -> Result<Option<satd_auth::Principal>, Response> {
    let Some(store) = state.auth.as_ref() else {
        return Ok(None); // auth disabled (loopback trust)
    };
    let hdr = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            debug!(target: "events::ws", status = 401, "rejecting streamws connection: missing authorization header");
            (StatusCode::UNAUTHORIZED, "missing authorization header").into_response()
        })?;
    let mut scratch = String::new();
    let principal = match satd_auth::Credential::from_authorization(hdr, &mut scratch) {
        Some(satd_auth::Credential::Bearer { token }) => store.resolve(token, now_unix()),
        _ => None,
    }
    .ok_or_else(|| {
        debug!(target: "events::ws", status = 401, "rejecting streamws connection: invalid or unknown bearer token");
        (StatusCode::UNAUTHORIZED, "invalid or unknown bearer token").into_response()
    })?;
    if !principal.has(satd_auth::Capability::StreamSubscribe) {
        debug!(target: "events::ws", status = 403, "rejecting streamws connection: token lacks stream:subscribe capability");
        return Err((StatusCode::FORBIDDEN, "token lacks stream:subscribe").into_response());
    }
    if let satd_auth::RateDecision::Throttle { .. } = principal.check_rate() {
        debug!(target: "events::ws", status = 429, "rejecting streamws connection: per-principal rate limit exceeded");
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response());
    }
    Ok(Some(principal))
}

#[derive(Deserialize)]
struct FirehoseQuery {
    /// Category bitfield (mempool=1, chain=2, heartbeat=4; 0/absent = all).
    categories: Option<u32>,
    /// Durable replay anchor — the JSON-cursor fields a client persisted from a
    /// prior `NodeEvent`, flattened into query params (curl-friendly; no JS
    /// `Number` precision loss since the URL carries them as text). Replay
    /// engages when `from_height` is present **and** a block source is
    /// configured; otherwise the connection is forward-only. Mirrors the gRPC
    /// `SubscribeRequest.from_cursor`.
    from_height: Option<u32>,
    #[serde(default)]
    from_tx_index: u32,
    #[serde(default)]
    from_mempool_seq: u64,
    #[serde(default)]
    from_instance_id: u64,
}

impl FirehoseQuery {
    /// The durable resume cursor this query requests, if any (`from_height`
    /// present).
    fn cursor(&self) -> Option<Cursor> {
        self.from_height.map(|height| Cursor {
            height,
            tx_index: self.from_tx_index,
            mempool_seq: self.from_mempool_seq,
            instance_id: self.from_instance_id,
        })
    }
}

fn mask_from(categories: Option<u32>) -> u32 {
    // The WS/SSE firehose does not serve the tweaks category this release, so
    // the tweaks bit is stripped from EVERY mask, default or explicit:
    //   - "all" (`0`/absent) maps to the default, which already excludes tweaks,
    //     so a legacy subscriber never begins receiving tweak volume after a node
    //     upgrade.
    //   - an explicit request keeps its other bits but never the tweaks bit — a
    //     WS client that asks for `categories=8` gets an empty stream, not live
    //     `BlockTweaks`. Those are published to the shared broadcast the moment
    //     any gRPC client attaches, so without this strip the WS live filter
    //     would forward them (its replay already returns empty). Tier 1 tweak
    //     consumption is gRPC-only.
    match categories {
        None | Some(0) => node::events::ALL_CATEGORIES_DEFAULT,
        Some(c) => c & !node::events::CATEGORY_TWEAKS,
    }
}

/// Boundary-dedup state for the live filter after a snapshot→live handoff: the
/// confirmed snapshot (height→hash, identity dedup) and the highest replayed
/// mempool seq. Cheap to clone per item (the map sits behind an `Arc`).
#[derive(Clone, Default)]
struct ReplayDedup {
    confirmed: Option<Arc<std::collections::HashMap<u32, bitcoin::BlockHash>>>,
    mempool_through: Option<u64>,
}

impl ReplayDedup {
    /// True if `env` is a snapshot→live boundary duplicate that must be
    /// dropped: a confirmed block byte-identical to the one already replayed at
    /// its height (a reorg replacement has a different hash and is forwarded),
    /// or a mempool event at or below the highest replayed seq.
    fn is_duplicate(&self, env: &node::events::NodeEvent) -> bool {
        if let Some(cd) = &self.confirmed
            && let NodeEventBody::Chain(ChainEvent::BlockConnected { height, hash }) = &env.body
            && cd.get(height) == Some(hash)
        {
            return true;
        }
        if let Some(s) = self.mempool_through
            && matches!(env.body, NodeEventBody::Mempool(_))
            && env.stamp.seq <= s
        {
            return true;
        }
        false
    }

    /// The `(height, mempool_seq)` a `Lagged` notice should resume from before
    /// any live event is delivered: the replay tail (so a client that lags
    /// right after the snapshot resumes after it, not from scratch), else the
    /// request cursor's coordinates.
    fn seed(&self, cursor: Option<Cursor>) -> (u32, u64) {
        let mut h = cursor.map(|c| c.height).unwrap_or(0);
        let mut s = cursor.map(|c| c.mempool_seq).unwrap_or(0);
        if let Some(cd) = &self.confirmed
            && let Some(m) = cd.keys().max()
        {
            h = (*m).max(h);
        }
        if let Some(m) = self.mempool_through {
            s = m.max(s);
        }
        (h, s)
    }
}

/// Build the durable replay (events to emit before live + the live boundary
/// dedup) for a `from_cursor` query, or `(empty, default)` when replay does not
/// engage (no cursor, or no block source). `mask` gates which categories are
/// replayed (mirrors the live category filter).
fn build_replay(
    state: &WsState,
    cursor: Option<Cursor>,
    mask: u32,
) -> (Vec<node::events::NodeEvent>, ReplayDedup) {
    let Some(cursor) = cursor else {
        return (Vec::new(), ReplayDedup::default());
    };
    let Some(src) = state.block_source.as_ref() else {
        debug!(
            target: "events::ws",
            "from_cursor requested but no block source configured; streaming live only",
        );
        return (Vec::new(), ReplayDedup::default());
    };
    // The WS/SSE firehose does not serve the tweaks category (a gRPC-only
    // surface in this release), so it passes no tweak source.
    let r = build_cursor_replay(
        src.as_ref(),
        &state.publisher,
        cursor,
        mask,
        MAX_REPLAY_BLOCKS,
        None,
    );
    let dedup = ReplayDedup {
        confirmed: Some(Arc::new(r.confirmed_dedup)),
        mempool_through: Some(r.mempool_dedup_through),
    };
    (r.events, dedup)
}

/// `GET /sse` — read-only JSON `NodeEvent` firehose, with optional durable
/// `?from_cursor` replay (snapshot→live handoff) before the live tail.
async fn sse_firehose(
    State(state): State<WsState>,
    headers: HeaderMap,
    Query(q): Query<FirehoseQuery>,
) -> Response {
    if let Err(resp) = authorize(&state, &headers) {
        return resp;
    }
    // Admission control: hold a connection permit for the stream's lifetime.
    let Ok(permit) = state.conn_sem.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "streamws connection cap reached",
        )
            .into_response();
    };
    let mask = mask_from(q.categories);
    // Subscribe to the live broadcast FIRST so nothing is missed between the
    // replay snapshot and the live tail (the snapshot→live handoff ordering).
    let rx = state.publisher.subscribe();
    let cursor = q.cursor();
    let (replay_events, dedup) = build_replay(&state, cursor, mask);
    // Track the last-delivered position (seeded from the replay tail) via
    // atomics — an async `filter_map` closure cannot hold `&mut` state across
    // items, so a `Lagged` notice reads the resume cursor from these.
    let (seed_h, seed_s) = dedup.seed(cursor);
    let last_h = Arc::new(AtomicU32::new(seed_h));
    let last_s = Arc::new(AtomicU64::new(seed_s));
    let publisher = state.publisher.clone();
    // Replayed events first (confirmed history + mempool window — already
    // category-gated by the replay builder), then the live stream, filtered by
    // category and boundary-deduped against the snapshot.
    let replay_stream = tokio_stream::iter(replay_events.into_iter().filter_map(|env| {
        serde_json::to_string(&env)
            .ok()
            .map(|s| Ok::<_, std::convert::Infallible>(Event::default().data(s)))
    }));
    let live = BroadcastStream::new(rx).filter_map(move |item| {
        // Keep the permit alive for as long as the SSE stream is held; it is
        // released when the client disconnects and the stream is dropped.
        let _permit = &permit;
        let dedup = dedup.clone();
        let last_h = last_h.clone();
        let last_s = last_s.clone();
        let publisher = publisher.clone();
        async move {
            match item {
                Ok(env) if (env.category_bit() & mask) != 0 && !dedup.is_duplicate(&env) => {
                    last_s.store(env.stamp.seq, Ordering::Relaxed);
                    if let Some(c) = &env.cursor {
                        last_h.store(c.height, Ordering::Relaxed);
                    }
                    Some(Ok::<_, std::convert::Infallible>(
                        Event::default().data(serde_json::to_string(&env).unwrap_or_default()),
                    ))
                }
                // In-band lag notice: tell the client how many events were
                // dropped and the cursor to reconnect from; the stream continues.
                Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                    warn!(target: "events::ws", dropped = n, "streamws SSE subscriber lagged");
                    let resume = publisher.resume_cursor(
                        last_h.load(Ordering::Relaxed),
                        last_s.load(Ordering::Relaxed),
                    );
                    let ev = node::events::lagged_event(&publisher, n, resume);
                    Some(Ok(Event::default().data(serde_json::to_string(&ev).unwrap_or_default())))
                }
                _ => None,
            }
        }
    });
    Sse::new(replay_stream.chain(live))
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

/// `GET /ws` — bidirectional JSON WebSocket, with optional durable
/// `?from_cursor` replay (snapshot→live handoff) before the live tail. The
/// `?categories=` param sets the initial firehose mask; the client can change
/// it later with a `set_categories` control message.
async fn ws_upgrade(
    State(state): State<WsState>,
    headers: HeaderMap,
    Query(q): Query<FirehoseQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let principal = match authorize(&state, &headers) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    // Admission control: hold a connection permit for the connection's
    // lifetime. At cap → 503 before the upgrade.
    let Ok(permit) = state.conn_sem.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "streamws connection cap reached",
        )
            .into_response();
    };
    let initial_mask = mask_from(q.categories);
    let cursor = q.cursor();
    // Bound a single inbound frame/message — control frames are tiny.
    let max_bytes = state.max_message_bytes;
    ws.max_message_size(max_bytes)
        .max_frame_size(max_bytes)
        .on_upgrade(move |socket| ws_conn(socket, state, principal, permit, initial_mask, cursor))
}

async fn ws_conn(
    socket: WebSocket,
    state: WsState,
    principal: Option<satd_auth::Principal>,
    _permit: OwnedSemaphorePermit,
    initial_mask: u32,
    cursor: Option<Cursor>,
) {
    let (mut sender, mut receiver) = socket.split();
    let (handle, mut rx_match) = state.watch_registry.register(WATCH_CHANNEL_CAPACITY);
    let handle = Arc::new(handle);
    let category_mask = Arc::new(AtomicU32::new(initial_mask));
    // Per-stream raw-tx opt-in (SetWatchOptions). Inbound flips it + the
    // registry gate; the outbound encoder reads it to inline raw_tx.
    let include_raw_tx = Arc::new(AtomicBool::new(false));
    // Subscribe to the live broadcast BEFORE building the replay snapshot so no
    // event is missed at the snapshot→live boundary.
    let mut rx_live = state.publisher.subscribe();
    let (replay_events, dedup) = build_replay(&state, cursor, initial_mask);
    // Last-delivered position (seeded from the replay tail), for the in-band
    // `Lagged` notice's resume cursor.
    let (mut last_h, mut last_s) = dedup.seed(cursor);
    // The watch-set (and the per-item quota leases inside it) is owned by the
    // CONNECTION, not the inbound reader (same rule as the gRPC Watch handler):
    // a client that stops sending control frames must not release its quota
    // while its watch-set stays live. Held behind an `Arc` shared with the
    // inbound task; quota is released per-remove, and the remainder when
    // `ws_conn` returns (alongside the `WatchHandle` deregister).
    let watch_set: Arc<std::sync::Mutex<WatchSet>> =
        Arc::new(std::sync::Mutex::new(WatchSet::default()));
    // Liveness: every frame from the client (including Pong) refreshes this;
    // the outbound loop reaps the connection if it goes silent past the idle
    // timeout, so a dead/half-open peer cannot pin a connection slot.
    let last_activity = Arc::new(AtomicI64::new(now_unix()));
    debug!(target: "events::ws", authenticated = principal.is_some(), "streamws connection opened");

    // Inbound control reader: applies watch-set + category changes against the
    // shared connection-scoped watch-set.
    let max_subscriptions = state.max_subscriptions;
    let prefix_bounds = (state.prefix_min_bits, state.prefix_max_bits);
    // Bridge the deterministic result of an atomic SetWatchSet replace (applied
    // by the inbound reader under the watch-set lock) to the outbound loop, which
    // emits the in-band `watch_set_result`.
    let (ws_result_tx, mut ws_result_rx) =
        tokio::sync::mpsc::channel::<crate::watchset::ReplaceOutcome>(32);
    let inbound = {
        let handle = handle.clone();
        let category_mask = category_mask.clone();
        let include_raw_tx = include_raw_tx.clone();
        let watch_set = watch_set.clone();
        let last_activity = last_activity.clone();
        tokio::spawn(async move {
            while let Some(Ok(msg)) = receiver.next().await {
                last_activity.store(now_unix(), Ordering::Relaxed);
                match msg {
                    Message::Text(t) => {
                        // Scope the guard so it drops before the async send below.
                        let outcome = {
                            let mut guard = watch_set.lock().unwrap_or_else(|p| p.into_inner());
                            apply_ws_control(
                                &t,
                                &handle,
                                principal.as_ref(),
                                &category_mask,
                                &include_raw_tx,
                                &mut guard,
                                max_subscriptions,
                                prefix_bounds,
                            )
                        };
                        if let Some(outcome) = outcome {
                            // Outbound gone (tearing down) → nothing to deliver.
                            let _ = ws_result_tx.send(outcome).await;
                        }
                    }
                    Message::Close(_) => break,
                    // Ping is auto-answered by axum; Pong (and any other frame)
                    // already refreshed `last_activity` above.
                    _ => {}
                }
            }
            // The watch-set is NOT dropped here — it belongs to the connection
            // and drops with `watch_set`/`handle` when `ws_conn` returns.
        })
    };

    // Durable replay first (confirmed history + mempool window from
    // `?from_cursor`), before the live tail. Already category-gated by the
    // replay builder; the live stream below boundary-dedups against it.
    let mut replay_aborted = false;
    for env in &replay_events {
        if let Ok(text) = serde_json::to_string(env)
            && sender.send(Message::Text(text.into())).await.is_err()
        {
            replay_aborted = true;
            break;
        }
    }

    // Outbound: live firehose (category-filtered, boundary-deduped) + watch
    // matches as JSON, plus a periodic keepalive Ping that also drives
    // idle-connection reaping.
    let mut ping = tokio::time::interval(WS_PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        // The client vanished mid-replay — skip the live loop, fall to cleanup.
        if replay_aborted {
            break;
        }
        tokio::select! {
            _ = ping.tick() => {
                let idle = now_unix().saturating_sub(last_activity.load(Ordering::Relaxed));
                if idle > WS_IDLE_TIMEOUT_SECS {
                    debug!(target: "events::ws", idle, "streamws connection idle past timeout; closing");
                    break;
                }
                if sender.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            ev = rx_live.recv() => match ev {
                Ok(env) => {
                    if (env.category_bit() & category_mask.load(Ordering::Relaxed)) != 0
                        && !dedup.is_duplicate(&env)
                    {
                        last_s = env.stamp.seq;
                        if let Some(c) = &env.cursor {
                            last_h = c.height;
                        }
                        if let Ok(text) = serde_json::to_string(&env)
                            && sender.send(Message::Text(text.into())).await.is_err()
                        {
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // In-band lag notice: how many events were dropped + the
                    // cursor to reconnect from. The stream then continues live.
                    warn!(target: "events::ws", dropped = n, "streamws subscriber lagged (firehose)");
                    let resume = state.publisher.resume_cursor(last_h, last_s);
                    let ev = node::events::lagged_event(&state.publisher, n, resume);
                    if let Ok(text) = serde_json::to_string(&ev)
                        && sender.send(Message::Text(text.into())).await.is_err()
                    {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            // Deterministic result of an atomic SetWatchSet replace.
            Some(outcome) = ws_result_rx.recv() => {
                let text = watch_set_result_json(&outcome).to_string();
                if sender.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            m = rx_match.recv() => match m {
                Some(wm) => {
                    // Single-shot terminal matches: the registry already evicted
                    // the entry server-side on fire, so handle.remove_* is an
                    // idempotent no-op registry-side — its job here is to drop the
                    // carrier-held quota LEASE. Keyed by the threshold the match carries.
                    match &wm {
                        WatchMatch::TxidDepthReached { txid, depth, .. } => {
                            let mut ws = watch_set.lock().unwrap_or_else(|p| p.into_inner());
                            ws.remove_tx_depths([(*txid, *depth)], |items| {
                                handle.remove_tx_depths(items);
                            });
                        }
                        WatchMatch::TxidFinalized { txid, .. } => {
                            let mut ws = watch_set.lock().unwrap_or_else(|p| p.into_inner());
                            ws.remove_transactions([*txid], |txids| {
                                handle.remove_txids(txids);
                            });
                        }
                        _ => {}
                    }
                    // Attribute a script match to the descriptor(s) whose window
                    // it belongs to (empty for a direct watch).
                    let attribution: Vec<(std::sync::Arc<str>, u32, u32)> = match &wm {
                        WatchMatch::ScriptMatched { scripthash, .. } => {
                            let ws = watch_set.lock().unwrap_or_else(|p| p.into_inner());
                            ws.descriptor_attribution(scripthash).to_vec()
                        }
                        _ => Vec::new(),
                    };
                    let text =
                        watch_match_json(&wm, &attribution, include_raw_tx.load(Ordering::Relaxed))
                            .to_string();
                    if sender.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
        }
    }
    inbound.abort();
    // `handle` + `watch_set` drop here → deregister the watch-set and release
    // the quota together; `_permit` drops too, freeing the connection slot.
    debug!(target: "events::ws", "streamws connection closed");
}

/// JSON control messages a `/ws` client sends to manage its watch-set —
/// the JSON mirror of the gRPC `SubscribeControl` tagged union.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsControl {
    /// Set the live firehose category bitfield (0 = all).
    SetCategories { categories: u32 },
    /// Add outpoints to the watch-set (charges N quota units).
    AddOutpoints { outpoints: Vec<WsOutpoint> },
    /// Remove outpoints from the watch-set.
    RemoveOutpoints { outpoints: Vec<WsOutpoint> },
    /// Add scripthashes (32-byte hex, natural order) to the watch-set.
    /// `min_values` is an optional per-scripthash `min_value` floor (satoshis),
    /// parallel to `scripthashes`; empty = no floors, otherwise its length must
    /// equal `scripthashes`.
    AddScripts {
        scripthashes: Vec<String>,
        #[serde(default)]
        min_values: Vec<u64>,
    },
    /// Remove scripthashes from the watch-set.
    RemoveScripts { scripthashes: Vec<String> },
    /// Add transaction ids (display/reversed hex) to the watch-set. With
    /// `min_depths` empty, registers a lifecycle watch per txid (optionally
    /// self-closing at `auto_close_depth`); with `min_depths` non-empty,
    /// registers a single-shot depth alarm per (txid × depth).
    AddTransactions {
        txids: Vec<String>,
        #[serde(default)]
        min_depths: Vec<u32>,
        #[serde(default)]
        auto_close_depth: u32,
    },
    /// Remove transaction ids from the watch-set. Mirrors AddTransactions:
    /// empty `min_depths` removes the lifecycle watch(es); non-empty removes
    /// those depth alarms.
    RemoveTransactions {
        txids: Vec<String>,
        #[serde(default)]
        min_depths: Vec<u32>,
    },
    /// Expand a descriptor (rust-miniscript) into a script watch-set. The
    /// descriptor → scripthashes membership is retained so the window can be
    /// slid (re-assert reconciles) or removed cleanly.
    AddDescriptor {
        descriptor: String,
        gap_limit: u32,
        /// Window start index (default 0). The client advances this to slide
        /// the derivation window `[start, start+gap_limit)`.
        #[serde(default)]
        start: u32,
    },
    /// Remove a descriptor previously added with `AddDescriptor`, releasing the
    /// scripthashes its window contributed whose last owner this drops.
    RemoveDescriptor { descriptor: String },
    /// Add privacy-preserving script-prefix buckets (§7.5). Charged by
    /// coarseness; `bits` must be within `[streamprefixminbits, streamprefixmaxbits]`.
    AddScriptPrefixes { prefixes: Vec<WsScriptPrefix> },
    /// Remove script-prefix buckets from the watch-set.
    RemoveScriptPrefixes { prefixes: Vec<WsScriptPrefix> },
    /// Atomically REPLACE the whole watch-set with the snapshot carried here
    /// (the JSON mirror of the gRPC `SetWatchSet`). Every field is the full
    /// desired membership of its kind, not a delta. The server reconciles by
    /// effective scripthash coverage and replies with a `watch_set_result`
    /// event (`accepted` with counts, or `rejected` when the target exceeds the
    /// quota — the set is then left unchanged).
    SetWatchSet {
        #[serde(default)]
        categories: u32,
        #[serde(default)]
        scripthashes: Vec<String>,
        #[serde(default)]
        min_values: Vec<u64>,
        #[serde(default)]
        outpoints: Vec<WsOutpoint>,
        #[serde(default)]
        descriptors: Vec<WsDescriptor>,
        #[serde(default)]
        prefixes: Vec<WsScriptPrefix>,
        #[serde(default)]
        lifecycles: Vec<WsLifecycle>,
        #[serde(default)]
        depth_alarms: Vec<WsDepthAlarm>,
    },
    /// Per-stream delivery options (JSON mirror of gRPC `SetWatchOptions`).
    /// `include_raw_tx=true` inlines the full serialized matching tx (hex) on
    /// this stream's `script_matched` events; off by default.
    SetWatchOptions {
        #[serde(default)]
        include_raw_tx: bool,
    },
}

#[derive(Deserialize)]
struct WsDescriptor {
    descriptor: String,
    gap_limit: u32,
    #[serde(default)]
    start: u32,
}

#[derive(Deserialize)]
struct WsLifecycle {
    txid: String,
    #[serde(default)]
    auto_close_depth: u32,
}

#[derive(Deserialize)]
struct WsDepthAlarm {
    txid: String,
    depth: u32,
}

#[derive(Deserialize)]
struct WsScriptPrefix {
    /// Top `ceil(bits/8)` bytes of `sha256(scriptPubKey)`, hex-encoded.
    prefix: String,
    bits: u32,
}

/// Parse a WS prefix (hex + bits) into a validated registry bucket key + its
/// coarseness-priced unit cost; `None` for malformed hex or out-of-range bits.
fn parse_ws_prefix(p: &WsScriptPrefix, k_min: u8, k_max: u8) -> Option<((u8, u32), u64)> {
    let bytes = hex::decode(&p.prefix).ok()?;
    crate::watchset::parse_prefix(&bytes, p.bits, k_min, k_max)
}

#[derive(Deserialize)]
struct WsOutpoint {
    /// Transaction id in the usual display (reversed) hex.
    txid: String,
    vout: u32,
}

fn parse_ws_outpoint(o: &WsOutpoint) -> Option<bitcoin::OutPoint> {
    use std::str::FromStr;
    let txid = bitcoin::Txid::from_str(&o.txid).ok()?;
    Some(bitcoin::OutPoint { txid, vout: o.vout })
}

fn parse_ws_txid(s: &str) -> Option<bitcoin::Txid> {
    use std::str::FromStr;
    bitcoin::Txid::from_str(s).ok()
}

fn parse_ws_scripthash(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut sh = [0u8; 32];
    sh.copy_from_slice(&bytes);
    Some(sh)
}

#[allow(clippy::too_many_arguments)]
fn apply_ws_control(
    text: &str,
    handle: &node::events::WatchHandle,
    principal: Option<&satd_auth::Principal>,
    category_mask: &AtomicU32,
    include_raw_tx: &AtomicBool,
    watch_set: &mut WatchSet,
    max_subscriptions: usize,
    prefix_bounds: (u8, u8),
) -> Option<crate::watchset::ReplaceOutcome> {
    let (prefix_min_bits, prefix_max_bits) = prefix_bounds;
    let ctrl: WsControl = match serde_json::from_str(text) {
        Ok(c) => c,
        Err(e) => {
            warn!(target: "events::ws", error = %e, "ignoring malformed streamws control message");
            return None;
        }
    };

    // SetWatchSet is an atomic replace: build the desired set, reconcile under
    // the lock, and return the outcome so the caller can emit the deterministic
    // `watch_set_result`. Handled before the per-add cap (a replace may shrink)
    // and separate from the incremental match arms.
    if let WsControl::SetWatchSet {
        categories,
        scripthashes,
        min_values,
        outpoints,
        descriptors,
        prefixes,
        lifecycles,
        depth_alarms,
    } = &ctrl
    {
        // STRICT: a replace is a full snapshot, so any unparseable element refuses
        // the whole thing (mirrors the gRPC `desired_from_proto`). Silently
        // dropping a bad item would shrink the desired set and make `replace`
        // unregister still-wanted watches while reporting `Accepted`. Build into a
        // `Result` and turn the first failure into a `Malformed` outcome, leaving
        // the live set untouched (`replace` is never called).
        let desired: Result<crate::watchset::DesiredWatchSet, &'static str> = (|| {
            // `min_values` is empty (no floors) or exactly parallel to
            // `scripthashes`; a non-empty length mismatch is malformed (see the
            // gRPC `desired_from_proto`).
            if !min_values.is_empty() && min_values.len() != scripthashes.len() {
                return Err("min_values length");
            }
            let mut scripts: Vec<([u8; 32], u64)> = Vec::with_capacity(scripthashes.len());
            for (i, s) in scripthashes.iter().enumerate() {
                let sh = parse_ws_scripthash(s).ok_or("scripthash")?;
                scripts.push((sh, min_values.get(i).copied().unwrap_or(0)));
            }
            let mut descs: Vec<(String, crate::watchset::DescriptorWindow)> =
                Vec::with_capacity(descriptors.len());
            for d in descriptors {
                match crate::descriptor::expand_descriptor(&d.descriptor, d.start, d.gap_limit) {
                    Ok(coords) => descs.push((d.descriptor.clone(), coords)),
                    Err(e) => {
                        warn!(target: "events::ws", error = %e, "SetWatchSet: rejecting snapshot for invalid descriptor");
                        return Err("descriptor");
                    }
                }
            }
            let mut ops = Vec::with_capacity(outpoints.len());
            for o in outpoints {
                ops.push(parse_ws_outpoint(o).ok_or("outpoint")?);
            }
            let mut lcs = Vec::with_capacity(lifecycles.len());
            for l in lifecycles {
                let t = parse_ws_txid(&l.txid).ok_or("lifecycle txid")?;
                lcs.push((t, l.auto_close_depth));
            }
            let mut alarms = Vec::with_capacity(depth_alarms.len());
            for a in depth_alarms {
                if a.depth < 1 {
                    return Err("depth alarm depth");
                }
                let t = parse_ws_txid(&a.txid).ok_or("depth alarm txid")?;
                alarms.push((t, a.depth));
            }
            let mut pfx = Vec::with_capacity(prefixes.len());
            for p in prefixes {
                pfx.push(parse_ws_prefix(p, prefix_min_bits, prefix_max_bits).ok_or("prefix")?);
            }
            Ok(crate::watchset::DesiredWatchSet {
                scripts,
                descriptors: descs,
                outpoints: ops,
                lifecycles: lcs,
                depth_alarms: alarms,
                prefixes: pfx,
            })
        })();
        let outcome = match desired {
            Err(_) => crate::watchset::ReplaceOutcome::Malformed,
            Ok(desired) => {
                // Bound the replace by the same per-connection entry cap the
                // incremental adds respect (streamwsmaxsubscriptions).
                let outcome = watch_set.replace(principal, desired, max_subscriptions, handle);
                // The category filter is part of the desired set: apply it only
                // when the replace was accepted, so a rejection leaves the whole
                // set (categories included) unchanged as `watch_set_result`
                // reports.
                if matches!(outcome, crate::watchset::ReplaceOutcome::Accepted { .. }) {
                    let mask = if *categories == 0 {
                        node::events::ALL_CATEGORIES_DEFAULT
                    } else {
                        *categories
                    };
                    // WS/SSE never serves the tweaks firehose (a Subscribe-only
                    // category); strip the bit so a control update cannot opt this
                    // stream into shared-broadcast `BlockTweaks` and bypass the
                    // Subscribe path's index/completeness/dust-limit validation.
                    category_mask.store(mask & !node::events::CATEGORY_TWEAKS, Ordering::Relaxed);
                }
                outcome
            }
        };
        return Some(outcome);
    }
    // Per-connection watch-set entry cap (`streamwsmaxsubscriptions`; 0 ⇒
    // unlimited): once the set is at/over the cap, shed any add (the
    // connection stays up — no per-message ack). Removes and category changes
    // are exempt. A single add may overshoot by one control message's worth of
    // items, itself bounded by the inbound frame cap.
    let is_add = matches!(
        ctrl,
        WsControl::AddOutpoints { .. }
            | WsControl::AddScripts { .. }
            | WsControl::AddDescriptor { .. }
            | WsControl::AddTransactions { .. }
            | WsControl::AddScriptPrefixes { .. }
    );
    if is_add && max_subscriptions != 0 && watch_set.len() >= max_subscriptions {
        warn!(
            target: "events::ws",
            cap = max_subscriptions,
            "streamws watch-set at per-connection cap; shedding add",
        );
        return None;
    }
    match ctrl {
        // Handled and returned above; kept for match exhaustiveness.
        WsControl::SetWatchSet { .. } => {}
        WsControl::SetCategories { categories } => {
            let mask = if categories == 0 {
                node::events::ALL_CATEGORIES_DEFAULT
            } else {
                categories
            };
            // Strip the tweaks bit: WS/SSE never serves the firehose (see the
            // SetWatchSet path above).
            category_mask.store(mask & !node::events::CATEGORY_TWEAKS, Ordering::Relaxed);
        }
        WsControl::SetWatchOptions { include_raw_tx: want } => {
            // Store the encoder-side flag AND toggle the registry gate counter so
            // the matcher serializes only when opted in; both must agree.
            include_raw_tx.store(want, Ordering::Relaxed);
            handle.set_raw_tx(want);
        }
        WsControl::AddOutpoints { outpoints } => {
            watch_set.add_outpoints(
                principal,
                outpoints.iter().filter_map(parse_ws_outpoint),
                |ops| {
                    handle.add_outpoints(ops);
                },
            );
        }
        WsControl::RemoveOutpoints { outpoints } => {
            watch_set.remove_outpoints(
                outpoints.iter().filter_map(parse_ws_outpoint),
                |ops| {
                    handle.remove_outpoints(ops);
                },
            );
        }
        WsControl::AddScripts {
            scripthashes,
            min_values,
        } => {
            // Optional per-script `min_value` floors, parallel to `scripthashes`
            // (mirrors the gRPC AddScripts). A length mismatch is a protocol
            // error — reject the whole add rather than apply the wrong floors.
            if !min_values.is_empty() && min_values.len() != scripthashes.len() {
                warn!(
                    target: "events::ws",
                    min_values = min_values.len(),
                    scripthashes = scripthashes.len(),
                    "streamws AddScripts min_values length mismatch; ignoring add",
                );
            } else {
                let floors: std::collections::HashMap<[u8; 32], u64> = scripthashes
                    .iter()
                    .enumerate()
                    .filter_map(|(i, s)| {
                        parse_ws_scripthash(s)
                            .map(|sh| (sh, min_values.get(i).copied().unwrap_or(0)))
                    })
                    .collect();
                // Apply the parsed floors to a set of scripthashes — used for
                // both net-new and re-asserted scripts (see the gRPC handler for
                // the rationale: re-asserting a held script updates its floor in
                // place without re-charging the watch).
                let apply_floors = |shs: &[[u8; 32]]| {
                    let items: Vec<([u8; 32], u64)> = shs
                        .iter()
                        .map(|sh| (*sh, floors.get(sh).copied().unwrap_or(0)))
                        .collect();
                    handle.add_scripthashes_with_floors(&items);
                };
                watch_set.add_scripts(
                    principal,
                    scripthashes.iter().filter_map(|s| parse_ws_scripthash(s)),
                    "scripts",
                    apply_floors,
                    apply_floors,
                );
            }
        }
        WsControl::RemoveScripts { scripthashes } => {
            watch_set.remove_scripts(
                scripthashes.iter().filter_map(|s| parse_ws_scripthash(s)),
                |shs| {
                    handle.remove_scripthashes(shs);
                },
            );
        }
        WsControl::AddTransactions {
            txids,
            min_depths,
            auto_close_depth,
        } => {
            let parsed: Vec<bitcoin::Txid> = txids.iter().filter_map(|s| parse_ws_txid(s)).collect();
            let depths: Vec<u32> = min_depths.iter().copied().filter(|d| *d >= 1).collect();
            if depths.is_empty() {
                watch_set.add_transactions(principal, parsed, |txids| {
                    handle.add_txids(txids, auto_close_depth);
                });
            } else if let Some(pairs) = bounded_txid_depth_pairs(&parsed, &depths) {
                watch_set.add_tx_depths(principal, pairs, |items| {
                    handle.add_tx_depths(items);
                });
            } else {
                warn!(
                    target: "events::ws",
                    txids = parsed.len(), depths = depths.len(),
                    "add_transactions txid×depth product exceeds cap; rejecting message",
                );
            }
        }
        WsControl::RemoveTransactions { txids, min_depths } => {
            let parsed: Vec<bitcoin::Txid> = txids.iter().filter_map(|s| parse_ws_txid(s)).collect();
            let depths: Vec<u32> = min_depths.iter().copied().filter(|d| *d >= 1).collect();
            if depths.is_empty() {
                watch_set.remove_transactions(parsed, |txids| {
                    handle.remove_txids(txids);
                });
            } else if let Some(pairs) = bounded_txid_depth_pairs(&parsed, &depths) {
                watch_set.remove_tx_depths(pairs, |items| {
                    handle.remove_tx_depths(items);
                });
            } else {
                warn!(
                    target: "events::ws",
                    txids = parsed.len(), depths = depths.len(),
                    "remove_transactions txid×depth product exceeds cap; rejecting message",
                );
            }
        }
        WsControl::AddDescriptor {
            descriptor,
            gap_limit,
            start,
        } => match crate::descriptor::expand_descriptor(&descriptor, start, gap_limit) {
            Ok(scripts) => {
                watch_set.add_descriptor(
                    principal,
                    descriptor.clone(),
                    scripts,
                    |shs| {
                        handle.add_scripthashes(shs);
                    },
                    |shs| {
                        handle.remove_scripthashes(shs);
                    },
                );
            }
            Err(e) => {
                warn!(target: "events::ws", error = %e, "ignoring invalid descriptor");
            }
        },
        WsControl::RemoveDescriptor { descriptor } => {
            watch_set.remove_descriptor(&descriptor, |shs| {
                handle.remove_scripthashes(shs);
            });
        }
        WsControl::AddScriptPrefixes { prefixes } => {
            let items: Vec<((u8, u32), u64)> = prefixes
                .iter()
                .filter_map(|p| parse_ws_prefix(p, prefix_min_bits, prefix_max_bits))
                .collect();
            watch_set.add_prefixes(principal, items, |keys| {
                handle.add_prefixes(keys);
            });
        }
        WsControl::RemoveScriptPrefixes { prefixes } => {
            let keys: Vec<(u8, u32)> = prefixes
                .iter()
                .filter_map(|p| parse_ws_prefix(p, prefix_min_bits, prefix_max_bits).map(|(k, _)| k))
                .collect();
            watch_set.remove_prefixes(keys, |keys| {
                handle.remove_prefixes(keys);
            });
        }
    }
    None
}

/// Hand-rolled JSON for the deterministic result of an atomic `SetWatchSet`
/// replace — the JSON mirror of the `WatchSetResult` node event.
fn watch_set_result_json(outcome: &crate::watchset::ReplaceOutcome) -> serde_json::Value {
    use crate::watchset::ReplaceOutcome;
    let body = match outcome {
        ReplaceOutcome::Accepted { added, removed, unchanged } => json!({
            "category": "watch_set_result",
            "outcome": "accepted",
            "added": added,
            "removed": removed,
            "unchanged": unchanged,
        }),
        ReplaceOutcome::Rejected { required, quota } => json!({
            "category": "watch_set_result",
            "outcome": "rejected",
            "reason": "quota_exceeded",
            "required": required,
            "quota": quota,
        }),
        ReplaceOutcome::CapExceeded { limit, requested } => json!({
            "category": "watch_set_result",
            "outcome": "rejected",
            "reason": "cap_exceeded",
            "required": requested,
            "quota": limit,
        }),
        ReplaceOutcome::Malformed => json!({
            "category": "watch_set_result",
            "outcome": "rejected",
            "reason": "malformed",
            "required": 0,
            "quota": 0,
        }),
    };
    json!({ "schema_version": node::events::SCHEMA_VERSION, "cursor": null, "body": body })
}

/// Hand-rolled JSON for a watch match (the proto has no `serde` derive). The
/// shape mirrors a `NodeEvent`: a `body` tagged by `category`, plus a
/// `cursor` on confirmed matches. `descriptor_matches` is the descriptor
/// attribution for a `ScriptMatched` (empty otherwise / for a direct watch).
fn watch_match_json(
    m: &WatchMatch,
    descriptor_matches: &[(std::sync::Arc<str>, u32, u32)],
    include_raw_tx: bool,
) -> serde_json::Value {
    use bitcoin::hashes::Hash;
    match m {
        WatchMatch::OutpointSpent {
            outpoint,
            spending_txid,
            spending_vin,
            confirmed,
            height,
        } => json!({
            "schema_version": node::events::SCHEMA_VERSION,
            "cursor": height.map(|h| json!({ "height": h, "tx_index": 0, "mempool_seq": 0 })),
            "body": {
                "category": "outpoint_spent",
                "outpoint_txid": hex::encode(outpoint.txid.as_raw_hash().to_byte_array()),
                "outpoint_vout": outpoint.vout,
                "spending_txid": hex::encode(spending_txid.as_raw_hash().to_byte_array()),
                "spending_vin": spending_vin,
                "confirmed": confirmed,
            }
        }),
        WatchMatch::ScriptMatched {
            scripthash,
            txid,
            is_output,
            index,
            confirmed,
            height,
            amount,
            raw_tx,
        } => {
            // Hex of the full tx when this stream opted in (SetWatchOptions) and
            // the match carried it; `null` otherwise. Mirrors the gRPC gate.
            let raw_tx_hex = if include_raw_tx {
                raw_tx.as_ref().map(hex::encode)
            } else {
                None
            };
            json!({
            "schema_version": node::events::SCHEMA_VERSION,
            "cursor": height.map(|h| json!({ "height": h, "tx_index": 0, "mempool_seq": 0 })),
            "body": {
                "category": "script_matched",
                "scripthash": hex::encode(scripthash),
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "is_output": is_output,
                "index": index,
                "confirmed": confirmed,
                // Matched value (sats): funded output value or spent-prevout
                // value. `has_amount = false` marks "not retained at this tier"
                // (mempool spend under `streamprevoutmeta = hash`).
                "amount": amount.unwrap_or(0),
                "has_amount": amount.is_some(),
                // Full serialized tx (hex) when opted in; null otherwise.
                "raw_tx": raw_tx_hex,
                // Empty array for a directly-watched script; one entry per
                // descriptor whose window holds this scripthash.
                "descriptor_matches": descriptor_matches
                    .iter()
                    .map(|(d, branch, index)| json!({
                        "descriptor": d.as_ref(),
                        "branch": branch,
                        "derivation_index": index,
                    }))
                    .collect::<Vec<_>>(),
            }
            })
        }
        WatchMatch::TxidMatched {
            txid,
            confirmed,
            height,
        } => json!({
            "schema_version": node::events::SCHEMA_VERSION,
            "cursor": height.map(|h| json!({ "height": h, "tx_index": 0, "mempool_seq": 0 })),
            "body": {
                "category": "txid_matched",
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "confirmed": confirmed,
            }
        }),
        WatchMatch::TxidReplaced {
            txid,
            replacing_txid,
        } => json!({
            "schema_version": node::events::SCHEMA_VERSION,
            "cursor": serde_json::Value::Null,
            "body": {
                "category": "txid_replaced",
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "replacing_txid": hex::encode(replacing_txid.as_raw_hash().to_byte_array()),
            }
        }),
        WatchMatch::TxidEvicted { txid, reason } => json!({
            "schema_version": node::events::SCHEMA_VERSION,
            "cursor": serde_json::Value::Null,
            "body": {
                "category": "txid_evicted",
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "reason": reason.as_str(),
            }
        }),
        WatchMatch::TxidUnconfirmed { txid, prev_height } => json!({
            "schema_version": node::events::SCHEMA_VERSION,
            "cursor": serde_json::Value::Null,
            "body": {
                "category": "txid_unconfirmed",
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "prev_height": prev_height,
            }
        }),
        WatchMatch::TxidDepthReached {
            txid,
            depth,
            height,
        } => json!({
            "schema_version": node::events::SCHEMA_VERSION,
            "cursor": json!({ "height": height, "tx_index": 0, "mempool_seq": 0 }),
            "body": {
                "category": "txid_depth_reached",
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "depth": depth,
                "height": height,
            }
        }),
        WatchMatch::TxidFinalized {
            txid,
            depth,
            height,
        } => json!({
            "schema_version": node::events::SCHEMA_VERSION,
            "cursor": json!({ "height": height, "tx_index": 0, "mempool_seq": 0 }),
            "body": {
                "category": "txid_finalized",
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "depth": depth,
                "height": height,
            }
        }),
        WatchMatch::PrefixMatched(pm) => {
            let (masked, bits) = pm.prefix;
            let nbytes = (bits as usize).div_ceil(8).min(4);
            json!({
                "schema_version": node::events::SCHEMA_VERSION,
                "cursor": pm.height.map(|h| json!({ "height": h, "tx_index": 0, "mempool_seq": 0 })),
                "body": {
                    "category": "prefix_matched",
                    "prefix": hex::encode(&masked.to_be_bytes()[..nbytes]),
                    "bits": bits,
                    "raw_tx": hex::encode(pm.raw_tx.as_ref()),
                    "confirmed": pm.confirmed,
                    "height": pm.height,
                    "matched_prevouts": pm.matched_prevouts.iter().map(|m| json!({
                        "outpoint_txid": hex::encode(m.outpoint.txid.as_raw_hash().to_byte_array()),
                        "outpoint_vout": m.outpoint.vout,
                        "script_pubkey": hex::encode(m.script_pubkey.as_bytes()),
                        // `amount` is null when the value was not retained
                        // (streamprevoutmeta below `amount`); `has_amount`
                        // mirrors the gRPC SpentPrevout bool so a JSON client can
                        // distinguish "not retained" from a genuine 0-sat prevout
                        // without relying on the null-vs-0 encoding.
                        "amount": m.amount,
                        "has_amount": m.amount.is_some(),
                    })).collect::<Vec<_>>(),
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_defaults_to_all() {
        assert_eq!(mask_from(None), node::events::ALL_CATEGORIES_DEFAULT);
        assert_eq!(mask_from(Some(0)), node::events::ALL_CATEGORIES_DEFAULT);
        assert_eq!(mask_from(Some(2)), 2);
    }

    #[test]
    fn default_mask_excludes_tweaks() {
        // The WS/SSE "all" default must never carry the explicit-only tweaks
        // bit, or a legacy `0`-subscriber would start receiving the tweak
        // firehose the moment a gRPC client attaches (shared broadcast).
        assert_eq!(mask_from(None) & node::events::CATEGORY_TWEAKS, 0);
        assert_eq!(mask_from(Some(0)) & node::events::CATEGORY_TWEAKS, 0);
        // Non-tweak categories are still present in the default.
        assert_ne!(mask_from(None) & node::events::CATEGORY_CHAIN, 0);
        assert_ne!(mask_from(None) & node::events::CATEGORY_MEMPOOL, 0);
    }

    #[test]
    fn parses_scripthash_hex() {
        let hexstr = "ff".repeat(32);
        assert_eq!(parse_ws_scripthash(&hexstr), Some([0xff; 32]));
        assert_eq!(parse_ws_scripthash("ff"), None); // wrong length
        assert_eq!(parse_ws_scripthash("zz".repeat(32).as_str()), None); // not hex
    }

    #[test]
    fn parses_control_json() {
        let c: WsControl =
            serde_json::from_str(r#"{"type":"set_categories","categories":2}"#).unwrap();
        match c {
            WsControl::SetCategories { categories } => assert_eq!(categories, 2),
            _ => panic!("wrong variant"),
        }
        let c: WsControl = serde_json::from_str(
            r#"{"type":"add_outpoints","outpoints":[{"txid":"00","vout":1}]}"#,
        )
        .unwrap();
        assert!(matches!(c, WsControl::AddOutpoints { .. }));

        let c: WsControl =
            serde_json::from_str(r#"{"type":"add_transactions","txids":["aa","bb"]}"#).unwrap();
        match c {
            WsControl::AddTransactions {
                txids,
                min_depths,
                auto_close_depth,
            } => {
                assert_eq!(txids.len(), 2);
                assert!(min_depths.is_empty(), "min_depths defaults empty");
                assert_eq!(auto_close_depth, 0, "auto_close_depth defaults 0");
            }
            _ => panic!("wrong variant"),
        }

        // Depth-alarm form: min_depths drives the depth alarms; auto_close on the
        // lifecycle form.
        let c: WsControl = serde_json::from_str(
            r#"{"type":"add_transactions","txids":["aa"],"min_depths":[1,3]}"#,
        )
        .unwrap();
        match c {
            WsControl::AddTransactions { min_depths, .. } => assert_eq!(min_depths, vec![1, 3]),
            _ => panic!("wrong variant"),
        }
        let c: WsControl = serde_json::from_str(
            r#"{"type":"add_transactions","txids":["aa"],"auto_close_depth":6}"#,
        )
        .unwrap();
        match c {
            WsControl::AddTransactions {
                auto_close_depth, ..
            } => assert_eq!(auto_close_depth, 6),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn per_connection_subscription_cap_sheds_adds() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let mask = AtomicU32::new(u32::MAX);
        let mut ws = WatchSet::default();
        let txid = "00".repeat(32);
        let add = |vout: u32| {
            format!(
                r#"{{"type":"add_outpoints","outpoints":[{{"txid":"{txid}","vout":{vout}}}]}}"#
            )
        };
        // cap = 2, no principal (loopback/unlimited quota).
        apply_ws_control(&add(0), &handle, None, &mask, &AtomicBool::new(false), &mut ws, 2, (8, 32));
        apply_ws_control(&add(1), &handle, None, &mask, &AtomicBool::new(false), &mut ws, 2, (8, 32));
        assert_eq!(ws.len(), 2, "two distinct outpoints registered");
        // At the cap → the next add is shed (connection stays up).
        apply_ws_control(&add(2), &handle, None, &mask, &AtomicBool::new(false), &mut ws, 2, (8, 32));
        assert_eq!(ws.len(), 2, "add at the per-connection cap is shed");
        // A remove frees a slot; a subsequent add then succeeds.
        let rm = format!(
            r#"{{"type":"remove_outpoints","outpoints":[{{"txid":"{txid}","vout":0}}]}}"#
        );
        apply_ws_control(&rm, &handle, None, &mask, &AtomicBool::new(false), &mut ws, 2, (8, 32));
        assert_eq!(ws.len(), 1);
        apply_ws_control(&add(2), &handle, None, &mask, &AtomicBool::new(false), &mut ws, 2, (8, 32));
        assert_eq!(ws.len(), 2, "add succeeds again after a remove frees a slot");
        // cap = 0 ⇒ unlimited: adds are never shed.
        apply_ws_control(&add(3), &handle, None, &mask, &AtomicBool::new(false), &mut ws, 0, (8, 32));
        assert_eq!(ws.len(), 3, "cap 0 disables the per-connection limit");
    }

    #[test]
    fn set_watch_set_applies_categories_only_when_accepted() {
        use satd_auth::{Accounting, Capability, CapabilitySet, LocalAccounting, Principal};
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let acct: Arc<dyn Accounting> = Arc::new(LocalAccounting::new());
        // Quota of 1 unit.
        let p = Principal::token(
            Arc::from("tenant"),
            CapabilitySet::EMPTY.with(Capability::StreamWatch),
            Some(1),
            None,
            acct.clone(),
        );
        let mask = AtomicU32::new(0xF); // a distinctive pre-existing filter
        let mut ws = WatchSet::default();

        // Two scripts need 2 units > quota 1 → the whole replace is rejected, so
        // the category filter must NOT change.
        let ctrl = format!(
            r#"{{"type":"set_watch_set","categories":2,"scripthashes":["{}","{}"]}}"#,
            "11".repeat(32),
            "22".repeat(32),
        );
        let outcome = apply_ws_control(&ctrl, &handle, Some(&p), &mask, &AtomicBool::new(false), &mut ws, 0, (8, 32));
        assert!(
            matches!(outcome, Some(crate::watchset::ReplaceOutcome::Rejected { .. })),
            "over-quota target must be rejected",
        );
        assert_eq!(mask.load(Ordering::Relaxed), 0xF, "rejected replace must not touch categories");
        assert_eq!(ws.len(), 0, "rejected replace registers nothing");

        // A single script fits quota → accepted, and the category filter applies.
        let ok = format!(
            r#"{{"type":"set_watch_set","categories":2,"scripthashes":["{}"]}}"#,
            "11".repeat(32),
        );
        let outcome = apply_ws_control(&ok, &handle, Some(&p), &mask, &AtomicBool::new(false), &mut ws, 0, (8, 32));
        assert!(matches!(outcome, Some(crate::watchset::ReplaceOutcome::Accepted { .. })));
        assert_eq!(mask.load(Ordering::Relaxed), 2, "accepted replace applies its category filter");
    }

    #[test]
    fn set_watch_set_rejects_a_malformed_snapshot_and_keeps_the_live_set() {
        // A full replace is all-or-nothing: one unparseable element must refuse
        // the whole snapshot (Malformed) and leave the already-registered set
        // intact — never silently drop the bad item and unregister live watches.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let mask = AtomicU32::new(0xF);
        let mut ws = WatchSet::default();

        // Establish a live set of two scripts.
        let seed = format!(
            r#"{{"type":"set_watch_set","categories":2,"scripthashes":["{}","{}"]}}"#,
            "aa".repeat(32),
            "bb".repeat(32),
        );
        let outcome = apply_ws_control(&seed, &handle, None, &mask, &AtomicBool::new(false), &mut ws, 0, (8, 32));
        assert!(matches!(outcome, Some(crate::watchset::ReplaceOutcome::Accepted { .. })));
        assert_eq!(ws.len(), 2);
        assert_eq!(mask.load(Ordering::Relaxed), 2);

        // A replace whose second scripthash is malformed (odd length) must be
        // rejected whole — the live two-script set and category filter are kept.
        let bad = format!(
            r#"{{"type":"set_watch_set","categories":8,"scripthashes":["{}","zz"]}}"#,
            "cc".repeat(32),
        );
        let outcome = apply_ws_control(&bad, &handle, None, &mask, &AtomicBool::new(false), &mut ws, 0, (8, 32));
        assert!(
            matches!(outcome, Some(crate::watchset::ReplaceOutcome::Malformed)),
            "a malformed element refuses the whole snapshot",
        );
        assert_eq!(ws.len(), 2, "the live set is untouched by a rejected replace");
        assert_eq!(mask.load(Ordering::Relaxed), 2, "categories are not changed by a rejected replace");
        assert_eq!(watch_set_result_json(&crate::watchset::ReplaceOutcome::Malformed)["body"]["reason"], "malformed");
    }

    #[test]
    fn set_watch_set_is_bounded_by_the_per_connection_entry_cap() {
        // The SetWatchSet path must honor streamwsmaxsubscriptions like the
        // incremental adds — otherwise one frame installs an unbounded set on a
        // no-auth connection. No principal (loopback) → the cap is the only bound.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let mask = AtomicU32::new(0);
        let mut ws = WatchSet::default();

        // cap = 2. A 3-scripthash replace is rejected whole; nothing registers.
        let over = format!(
            r#"{{"type":"set_watch_set","scripthashes":["{}","{}","{}"]}}"#,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
        );
        let outcome = apply_ws_control(&over, &handle, None, &mask, &AtomicBool::new(false), &mut ws, 2, (8, 32));
        assert!(
            matches!(outcome, Some(crate::watchset::ReplaceOutcome::CapExceeded { limit: 2, requested: 3 })),
            "over-cap SetWatchSet must be rejected, got {outcome:?}",
        );
        assert_eq!(ws.len(), 0, "a cap-rejected replace installs nothing");
        assert_eq!(
            watch_set_result_json(&crate::watchset::ReplaceOutcome::CapExceeded { limit: 2, requested: 3 })["body"]["reason"],
            "cap_exceeded",
        );

        // A 2-scripthash replace fits the cap exactly.
        let ok = format!(
            r#"{{"type":"set_watch_set","scripthashes":["{}","{}"]}}"#,
            "11".repeat(32),
            "22".repeat(32),
        );
        let outcome = apply_ws_control(&ok, &handle, None, &mask, &AtomicBool::new(false), &mut ws, 2, (8, 32));
        assert!(matches!(outcome, Some(crate::watchset::ReplaceOutcome::Accepted { .. })));
        assert_eq!(ws.len(), 2);
    }

    #[test]
    fn script_match_json_amount_and_raw_tx_gate() {
        use bitcoin::hashes::Hash;
        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x11; 32]));
        let m = WatchMatch::ScriptMatched {
            scripthash: [0xaa; 32],
            txid,
            is_output: true,
            index: 0,
            confirmed: true,
            height: Some(100),
            amount: Some(50_000),
            raw_tx: Some(std::sync::Arc::from(vec![0xde, 0xad, 0xbe, 0xef])),
        };
        // Value fields are always present; raw_tx only when opted in.
        let off = watch_match_json(&m, &[], false);
        assert_eq!(off["body"]["category"], "script_matched");
        assert_eq!(off["body"]["amount"], 50_000);
        assert_eq!(off["body"]["has_amount"], true);
        assert!(off["body"]["raw_tx"].is_null(), "no opt-in → raw_tx null");

        let on = watch_match_json(&m, &[], true);
        assert_eq!(on["body"]["raw_tx"], "deadbeef", "opt-in → hex of the tx");
    }

    #[test]
    fn txid_match_json_shape() {
        use bitcoin::hashes::Hash;
        let m = WatchMatch::TxidMatched {
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [0xcd; 32],
            )),
            confirmed: true,
            height: Some(202),
        };
        let v = watch_match_json(&m, &[], false);
        assert_eq!(v["body"]["category"], "txid_matched");
        assert_eq!(v["body"]["confirmed"], true);
        assert_eq!(v["body"]["txid"], "cd".repeat(32));
        assert_eq!(v["cursor"]["height"], 202);
    }

    #[test]
    fn lifecycle_and_depth_json_shapes() {
        use bitcoin::hashes::Hash;
        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x11; 32]));
        let rep =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x22; 32]));

        let v = watch_match_json(&WatchMatch::TxidReplaced {
            txid,
            replacing_txid: rep,
        }, &[], false);
        assert_eq!(v["body"]["category"], "txid_replaced");
        assert_eq!(v["body"]["replacing_txid"], "22".repeat(32));
        assert!(v["cursor"].is_null(), "replaced carries no cursor");

        let v = watch_match_json(&WatchMatch::TxidEvicted {
            txid,
            reason: node::mempool::events::EvictReason::BlockConflict,
        }, &[], false);
        assert_eq!(v["body"]["category"], "txid_evicted");
        assert_eq!(v["body"]["reason"], "block_conflict");

        let v = watch_match_json(&WatchMatch::TxidUnconfirmed {
            txid,
            prev_height: 814_000,
        }, &[], false);
        assert_eq!(v["body"]["category"], "txid_unconfirmed");
        assert_eq!(v["body"]["prev_height"], 814_000);

        let v = watch_match_json(&WatchMatch::TxidDepthReached {
            txid,
            depth: 3,
            height: 100,
        }, &[], false);
        assert_eq!(v["body"]["category"], "txid_depth_reached");
        assert_eq!(v["body"]["depth"], 3);
        assert_eq!(v["cursor"]["height"], 100);

        let v = watch_match_json(&WatchMatch::TxidFinalized {
            txid,
            depth: 6,
            height: 100,
        }, &[], false);
        assert_eq!(v["body"]["category"], "txid_finalized");
        assert_eq!(v["body"]["depth"], 6);
        assert_eq!(v["cursor"]["height"], 100);
    }

    #[test]
    fn depth_alarm_add_charges_per_pair_via_control() {
        let reg = std::sync::Arc::new(node::events::WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let mask = AtomicU32::new(u32::MAX);
        let mut ws = WatchSet::default();
        let txid = "11".repeat(32);
        // min_depths [1,3] on one txid → two distinct alarm items.
        let ctrl = format!(
            r#"{{"type":"add_transactions","txids":["{txid}"],"min_depths":[1,3]}}"#
        );
        apply_ws_control(&ctrl, &handle, None, &mask, &AtomicBool::new(false), &mut ws, 0, (8, 32));
        assert_eq!(ws.len(), 2, "(X,1) and (X,3) are two items");
        // Lifecycle add (no depths) is one item.
        let ctrl = format!(r#"{{"type":"add_transactions","txids":["{txid}"]}}"#);
        apply_ws_control(&ctrl, &handle, None, &mask, &AtomicBool::new(false), &mut ws, 0, (8, 32));
        assert_eq!(ws.len(), 3, "lifecycle watch adds one more item");
    }

    #[test]
    fn add_script_prefixes_via_control() {
        let reg = std::sync::Arc::new(node::events::WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let mask = AtomicU32::new(u32::MAX);
        let mut ws = WatchSet::default();
        // A 16-bit prefix (2 bytes hex). No principal ⇒ loopback/unlimited.
        let ctrl = r#"{"type":"add_script_prefixes","prefixes":[{"prefix":"abcd","bits":16}]}"#;
        apply_ws_control(ctrl, &handle, None, &mask, &AtomicBool::new(false), &mut ws, 0, (8, 32));
        assert_eq!(ws.len(), 1, "one prefix bucket registered");
        assert!(reg.has_prefix_watchers());

        // Below-min bits is dropped (filter_map) → nothing registered.
        let bad = r#"{"type":"add_script_prefixes","prefixes":[{"prefix":"ab","bits":4}]}"#;
        apply_ws_control(bad, &handle, None, &mask, &AtomicBool::new(false), &mut ws, 0, (8, 32));
        assert_eq!(ws.len(), 1, "out-of-range bits rejected, set unchanged");

        // Remove releases it.
        let rm = r#"{"type":"remove_script_prefixes","prefixes":[{"prefix":"abcd","bits":16}]}"#;
        apply_ws_control(rm, &handle, None, &mask, &AtomicBool::new(false), &mut ws, 0, (8, 32));
        assert_eq!(ws.len(), 0);
        assert!(!reg.has_prefix_watchers());
    }

    #[test]
    fn prefix_matched_json_shape() {
        use bitcoin::hashes::Hash;
        let op = |b: u8, vout: u32| bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([b; 32]),
            ),
            vout,
        };
        let m = WatchMatch::PrefixMatched(Box::new(node::events::PrefixMatch {
            prefix: (0xabcd_0000, 16),
            raw_tx: vec![0x01, 0x02].into(),
            confirmed: true,
            height: Some(5),
            matched_prevouts: vec![
                // value retained (>= amount tier): amount present, has_amount true
                node::events::SpentPrevoutMeta {
                    outpoint: op(0x11, 0),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
                    amount: Some(0),
                },
                // value NOT retained (hash tier): amount null, has_amount false
                node::events::SpentPrevoutMeta {
                    outpoint: op(0x22, 1),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                    amount: None,
                },
            ],
        }));
        let v = watch_match_json(&m, &[], false);
        assert_eq!(v["body"]["category"], "prefix_matched");
        assert_eq!(v["body"]["bits"], 16);
        assert_eq!(v["body"]["prefix"], "abcd");
        assert_eq!(v["body"]["raw_tx"], "0102");
        assert_eq!(v["body"]["confirmed"], true);
        assert_eq!(v["cursor"]["height"], 5);
        let mp = &v["body"]["matched_prevouts"];
        // Retained 0-sat prevout: amount is the number 0 and has_amount is true —
        // distinguishable from "not retained".
        assert_eq!(mp[0]["amount"], 0);
        assert_eq!(mp[0]["has_amount"], true);
        assert_eq!(mp[0]["script_pubkey"], "51");
        // Unretained prevout: amount is JSON null and has_amount is false.
        assert!(mp[1]["amount"].is_null());
        assert_eq!(mp[1]["has_amount"], false);
        assert_eq!(mp[1]["script_pubkey"], "");
    }

    #[test]
    fn watch_match_json_shape() {
        use bitcoin::hashes::Hash;
        let m = WatchMatch::OutpointSpent {
            outpoint: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]),
                ),
                vout: 3,
            },
            spending_txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xbb; 32]),
            ),
            spending_vin: 0,
            confirmed: true,
            height: Some(101),
        };
        let v = watch_match_json(&m, &[], false);
        assert_eq!(v["body"]["category"], "outpoint_spent");
        assert_eq!(v["body"]["outpoint_vout"], 3);
        assert_eq!(v["body"]["confirmed"], true);
        assert_eq!(v["cursor"]["height"], 101);
    }

    #[test]
    fn firehose_query_builds_cursor_only_when_height_present() {
        let q = FirehoseQuery {
            categories: Some(2),
            from_height: Some(800_000),
            from_tx_index: 4,
            from_mempool_seq: 99,
            from_instance_id: 0xdead_beef,
        };
        assert_eq!(
            q.cursor(),
            Some(Cursor {
                height: 800_000,
                tx_index: 4,
                mempool_seq: 99,
                instance_id: 0xdead_beef,
            })
        );
        let none = FirehoseQuery {
            categories: None,
            from_height: None,
            from_tx_index: 0,
            from_mempool_seq: 0,
            from_instance_id: 0,
        };
        assert!(none.cursor().is_none(), "no from_height ⇒ no replay cursor");
    }

    fn stamp(seq: u64) -> node::events::EdgeStamp {
        node::events::EdgeStamp {
            node_id: [0; 16],
            region: None,
            edge_seen_at_ns: 0,
            edge_wall_ns: 0,
            seq,
        }
    }

    fn block_hash(byte: u8) -> bitcoin::BlockHash {
        use bitcoin::hashes::Hash;
        bitcoin::BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [byte; 32],
        ))
    }

    fn block_ev(height: u32, hash_byte: u8) -> node::events::NodeEvent {
        node::events::NodeEvent::new(
            stamp(0),
            NodeEventBody::Chain(ChainEvent::BlockConnected {
                hash: block_hash(hash_byte),
                height,
            }),
        )
    }

    fn mempool_ev(seq: u64) -> node::events::NodeEvent {
        use bitcoin::hashes::Hash;
        use node::mempool::events::MempoolEvent;
        node::events::NodeEvent::new(
            stamp(seq),
            NodeEventBody::Mempool(MempoolEvent::Enter {
                txid: bitcoin::Txid::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([1; 32]),
                ),
                fee: 1,
                vsize: 1,
                fee_rate_sat_per_kvb: 1,
                time: 1,
            }),
        )
    }

    #[test]
    fn replay_dedup_drops_only_boundary_duplicates() {
        let mut confirmed = std::collections::HashMap::new();
        confirmed.insert(5u32, block_hash(0x55));
        let dedup = ReplayDedup {
            confirmed: Some(Arc::new(confirmed)),
            mempool_through: Some(10),
        };
        // Confirmed: same (height, hash) = replayed duplicate → drop.
        assert!(dedup.is_duplicate(&block_ev(5, 0x55)));
        // Confirmed: same height, DIFFERENT hash (reorg replacement) → keep.
        assert!(!dedup.is_duplicate(&block_ev(5, 0xEE)));
        // Confirmed: a height not in the snapshot → keep.
        assert!(!dedup.is_duplicate(&block_ev(6, 0x66)));
        // Mempool: seq at/below the high-water → drop; above → keep.
        assert!(dedup.is_duplicate(&mempool_ev(10)));
        assert!(dedup.is_duplicate(&mempool_ev(3)));
        assert!(!dedup.is_duplicate(&mempool_ev(11)));
        // No replay engaged → never a duplicate.
        let empty = ReplayDedup::default();
        assert!(!empty.is_duplicate(&block_ev(5, 0x55)));
        assert!(!empty.is_duplicate(&mempool_ev(1)));
    }
}
