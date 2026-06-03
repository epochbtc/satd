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
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
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

use crate::watchset::WatchSet;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, watch};
use tokio_stream::wrappers::BroadcastStream;
use tracing::{debug, info, warn};

/// Max concurrent `streamws` connections (`/ws` + `/sse` combined). Every
/// other remote-facing surface (events-gRPC, Esplora, Electrum) is capped;
/// without this bound a remote-exposed listener could be driven to fd /
/// memory / task exhaustion by opening connections without limit. Excess
/// connections are rejected with 503. (Making this operator-configurable,
/// mirroring `eventsgrpcmaxconns`, is a follow-up.)
const WS_MAX_CONNS: usize = 256;

/// Cap on a single inbound WebSocket message / frame. Control messages are
/// tiny; the axum default (64 MiB) is absurd for this protocol and lets an
/// authenticated peer force large `serde_json` parses.
const WS_MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// Send a WebSocket Ping at this cadence and reap the connection if no frame
/// (Pong, control, or otherwise) is seen from the client within
/// [`WS_IDLE_TIMEOUT`] — so a dead or half-open peer cannot pin a connection
/// slot, watch-set, and quota indefinitely.
const WS_PING_INTERVAL: Duration = Duration::from_secs(30);
const WS_IDLE_TIMEOUT_SECS: i64 = 90;

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
    /// Admission control: bounds concurrent `/ws` + `/sse` connections. A
    /// connection holds one permit for its whole lifetime; the permit is
    /// released on disconnect.
    conn_sem: Arc<Semaphore>,
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
                conn_sem: Arc::new(Semaphore::new(WS_MAX_CONNS)),
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
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing authorization header").into_response())?;
    let mut scratch = String::new();
    let principal = match satd_auth::Credential::from_authorization(hdr, &mut scratch) {
        Some(satd_auth::Credential::Bearer { token }) => store.resolve(token, now_unix()),
        _ => None,
    }
    .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid or unknown bearer token").into_response())?;
    if !principal.has(satd_auth::Capability::StreamSubscribe) {
        return Err((StatusCode::FORBIDDEN, "token lacks stream:subscribe").into_response());
    }
    if let satd_auth::RateDecision::Throttle { .. } = principal.check_rate() {
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
    match categories {
        None | Some(0) => u32::MAX,
        Some(c) => c,
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
    let r = build_cursor_replay(src.as_ref(), &state.publisher, cursor, mask, MAX_REPLAY_BLOCKS);
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
    ws.max_message_size(WS_MAX_MESSAGE_BYTES)
        .max_frame_size(WS_MAX_MESSAGE_BYTES)
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
    let inbound = {
        let handle = handle.clone();
        let category_mask = category_mask.clone();
        let watch_set = watch_set.clone();
        let last_activity = last_activity.clone();
        tokio::spawn(async move {
            while let Some(Ok(msg)) = receiver.next().await {
                last_activity.store(now_unix(), Ordering::Relaxed);
                match msg {
                    Message::Text(t) => {
                        let mut guard = watch_set.lock().unwrap_or_else(|p| p.into_inner());
                        apply_ws_control(
                            &t,
                            &handle,
                            principal.as_ref(),
                            &category_mask,
                            &mut guard,
                        );
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
            m = rx_match.recv() => match m {
                Some(wm) => {
                    let text = watch_match_json(&wm).to_string();
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
    AddScripts { scripthashes: Vec<String> },
    /// Remove scripthashes from the watch-set.
    RemoveScripts { scripthashes: Vec<String> },
    /// Expand a descriptor (rust-miniscript) into a script watch-set.
    AddDescriptor {
        descriptor: String,
        gap_limit: u32,
        /// Window start index (default 0). The client advances this to slide
        /// the derivation window `[start, start+gap_limit)`.
        #[serde(default)]
        start: u32,
    },
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

fn parse_ws_scripthash(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut sh = [0u8; 32];
    sh.copy_from_slice(&bytes);
    Some(sh)
}

fn apply_ws_control(
    text: &str,
    handle: &node::events::WatchHandle,
    principal: Option<&satd_auth::Principal>,
    category_mask: &AtomicU32,
    watch_set: &mut WatchSet,
) {
    let ctrl: WsControl = match serde_json::from_str(text) {
        Ok(c) => c,
        Err(e) => {
            warn!(target: "events::ws", error = %e, "ignoring malformed streamws control message");
            return;
        }
    };
    match ctrl {
        WsControl::SetCategories { categories } => {
            let mask = if categories == 0 { u32::MAX } else { categories };
            category_mask.store(mask, Ordering::Relaxed);
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
        WsControl::AddScripts { scripthashes } => {
            watch_set.add_scripts(
                principal,
                scripthashes.iter().filter_map(|s| parse_ws_scripthash(s)),
                "scripts",
                |shs| {
                    handle.add_scripthashes(shs);
                },
            );
        }
        WsControl::RemoveScripts { scripthashes } => {
            watch_set.remove_scripts(
                scripthashes.iter().filter_map(|s| parse_ws_scripthash(s)),
                |shs| {
                    handle.remove_scripthashes(shs);
                },
            );
        }
        WsControl::AddDescriptor {
            descriptor,
            gap_limit,
            start,
        } => match crate::descriptor::expand_descriptor(&descriptor, start, gap_limit) {
            Ok(scripts) => {
                watch_set.add_scripts(
                    principal,
                    scripts.into_iter().map(|(_, sh)| sh),
                    "descriptor",
                    |shs| {
                        handle.add_scripthashes(shs);
                    },
                );
            }
            Err(e) => {
                warn!(target: "events::ws", error = %e, "ignoring invalid descriptor");
            }
        },
    }
}

/// Hand-rolled JSON for a watch match (the proto has no `serde` derive). The
/// shape mirrors a `NodeEvent`: a `body` tagged by `category`, plus a
/// `cursor` on confirmed matches.
fn watch_match_json(m: &WatchMatch) -> serde_json::Value {
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
        } => json!({
            "schema_version": node::events::SCHEMA_VERSION,
            "cursor": height.map(|h| json!({ "height": h, "tx_index": 0, "mempool_seq": 0 })),
            "body": {
                "category": "script_matched",
                "scripthash": hex::encode(scripthash),
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "is_output": is_output,
                "index": index,
                "confirmed": confirmed,
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_defaults_to_all() {
        assert_eq!(mask_from(None), u32::MAX);
        assert_eq!(mask_from(Some(0)), u32::MAX);
        assert_eq!(mask_from(Some(2)), 2);
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
        let v = watch_match_json(&m);
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
