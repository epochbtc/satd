//! gRPC server-streaming adapter for the satd events bus.
//!
//! Each connecting client opens a `Subscribe` RPC and receives a
//! [`NodeEvent`](node::events::NodeEvent) stream until it disconnects or
//! the daemon shuts down. The sink itself is a single
//! [`tonic`](tonic::transport::Server) bound to a configured address; per-client
//! state (broadcast receiver + filter) lives on the streaming task spawned
//! by tonic for each incoming RPC.
//!
//! Lag handling matches the Esplora SSE pattern — `Lagged` is logged at
//! `warn` level (`target = "events::grpc"`) and the stream continues.
//! Sinks must never panic. Per-client metrics (active subscribers,
//! cumulative lag, dropped count) are deferred to a follow-up.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use async_trait::async_trait;
use bitcoin::BlockHash;
use node::events::{EventSink, NodeEvent, NodeEventBody};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, watch};
use tokio_stream::Stream;
use tokio_stream::wrappers::{BroadcastStream, TcpListenerStream};
use tonic::transport::Server;
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info, warn};

/// Upper bound on the confirmed-block span replayed for a single
/// `from_cursor` subscription. A client resuming from a cursor more than this
/// many blocks behind the tip has its replay window clamped to the most
/// recent `MAX_REPLAY_BLOCKS` (logged); it should full-resync the older
/// history out-of-band rather than stream the whole chain over the event
/// channel. This bounds both the per-subscriber replay work and the
/// boundary-dedup map built from the captured snapshot.
const MAX_REPLAY_BLOCKS: u32 = 10_000;

/// Admission limits for the events gRPC sink. `0` on either field disables
/// that cap. Defaults mirror `satd`'s config defaults (64 / 256).
#[derive(Debug, Clone, Copy)]
pub struct GrpcLimits {
    /// Hard cap on simultaneously-open TCP connections. A connection beyond
    /// the cap is dropped at accept (the client sees a connection reset).
    pub max_conns: usize,
    /// Hard cap on concurrent `Subscribe` streams across all connections. A
    /// `Subscribe` beyond the cap is rejected with `RESOURCE_EXHAUSTED`.
    pub max_subscriptions: usize,
}

impl Default for GrpcLimits {
    fn default() -> Self {
        Self {
            max_conns: 64,
            max_subscriptions: 256,
        }
    }
}

use crate::proto::v1 as pb;
use crate::proto::v1::node_event_stream_server::{
    NodeEventStream, NodeEventStreamServer,
};

/// gRPC adapter errors surfaced at sink construction time.
#[derive(Debug, thiserror::Error)]
pub enum GrpcEventSinkError {
    #[error("invalid bind address '{0}': {1}")]
    InvalidBind(String, std::net::AddrParseError),
    #[error(
        "refusing to bind events gRPC server on non-loopback address {0}: \
         the server is unauthenticated and unencrypted; pass \
         --events-grpc-allow-remote to override after putting it behind a \
         firewall or auth proxy"
    )]
    RemoteBindRejected(SocketAddr),
    #[error("failed to bind {0}: {1}")]
    BindFailed(SocketAddr, std::io::Error),
}

/// gRPC streaming sink. Construct via [`GrpcEventSink::bind`] (async,
/// pre-binds the TCP listener so failure is reported synchronously at
/// startup), then hand it to
/// [`node::events::EventPublisher::attach_sinks`] which spawns the
/// `run` future as a tokio task.
pub struct GrpcEventSink {
    addr: SocketAddr,
    listener: TcpListener,
    publisher: std::sync::Arc<node::events::EventPublisher>,
    limits: GrpcLimits,
    /// Unified-auth bearer-token store, `Some` only when `-eventsgrpcauth` is
    /// set (which requires `authfile`). When present, every `Subscribe` must
    /// carry an `authorization: Bearer <token>` resolving to a principal with
    /// the `stream:subscribe` capability; otherwise the stream is unauthenticated
    /// (loopback-trust), today's behavior.
    auth: Option<std::sync::Arc<satd_auth::TokenStore>>,
    /// Read-only block-index access for durable cursor replay. `Some` when a
    /// chain source is wired (production); `None` disables replay (a
    /// `from_cursor` request then streams live only). Never on the consensus
    /// hot path — replay reads blocks the node already holds.
    block_source: Option<std::sync::Arc<dyn node::events::BlockCursorSource>>,
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Authenticate a gRPC request against the token store: require an
/// `authorization: Bearer <token>` metadata entry resolving to a principal that
/// holds `stream:subscribe`. Returns the principal (for the handler / future
/// per-principal quota) or a gRPC `Status`.
// `Status` is tonic's required error type for an interceptor; it is large but
// not ours to box (the interceptor closure must return `Result<_, Status>`).
#[allow(clippy::result_large_err)]
fn authenticate(
    req: &Request<()>,
    store: &satd_auth::TokenStore,
) -> Result<satd_auth::Principal, Status> {
    let hdr = req
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;
    let mut scratch = String::new();
    let principal = match satd_auth::Credential::from_authorization(hdr, &mut scratch) {
        Some(satd_auth::Credential::Bearer { token }) => store.resolve(token, now_unix()),
        _ => None,
    }
    .ok_or_else(|| Status::unauthenticated("invalid or unknown bearer token"))?;
    if !principal.has(satd_auth::Capability::StreamSubscribe) {
        return Err(Status::permission_denied(
            "token lacks the stream:subscribe capability",
        ));
    }
    Ok(principal)
}

impl GrpcEventSink {
    /// Build a new sink and **bind** the TCP listener immediately, so
    /// any bind failure is reported at startup before the daemon
    /// declares readiness.
    ///
    /// The server is unauthenticated and unencrypted. By default, only
    /// loopback bindings are accepted; pass `allow_remote = true` to
    /// bind a routable address (which the operator should put behind
    /// a firewall, mTLS terminator, or auth proxy).
    ///
    /// The `publisher` handle is needed so each incoming subscriber can
    /// register its own broadcast receiver — sharing the
    /// [`EventSink::run`] receiver across N clients would force each
    /// client to serialize through a single channel.
    pub async fn bind(
        bind: &str,
        allow_remote: bool,
        publisher: std::sync::Arc<node::events::EventPublisher>,
        limits: GrpcLimits,
        auth: Option<std::sync::Arc<satd_auth::TokenStore>>,
        block_source: Option<std::sync::Arc<dyn node::events::BlockCursorSource>>,
    ) -> Result<Self, GrpcEventSinkError> {
        let addr: SocketAddr = bind
            .parse()
            .map_err(|e| GrpcEventSinkError::InvalidBind(bind.to_string(), e))?;
        if !allow_remote && !is_loopback(&addr.ip()) {
            return Err(GrpcEventSinkError::RemoteBindRejected(addr));
        }
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| GrpcEventSinkError::BindFailed(addr, e))?;
        let bound = listener.local_addr().unwrap_or(addr);
        info!(
            target: "events::grpc",
            addr = %bound,
            allow_remote,
            max_conns = limits.max_conns,
            max_subscriptions = limits.max_subscriptions,
            "events gRPC server bound",
        );
        Ok(Self {
            addr: bound,
            listener,
            publisher,
            limits,
            auth,
            block_source,
        })
    }

    /// Address the listener is bound on. Test helper / observability
    /// hook — production callers don't need this.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

#[async_trait]
impl EventSink for GrpcEventSink {
    fn name(&self) -> &'static str {
        "grpc"
    }

    async fn run(
        self: Box<Self>,
        // The "primary" receiver passed by the publisher is unused here:
        // each gRPC client gets its own subscription via `publisher.subscribe()`
        // inside the streaming RPC handler. We drop it immediately so the
        // publisher's broadcast doesn't accumulate buffered events for an
        // unread receiver.
        _events: broadcast::Receiver<NodeEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let svc_impl = NodeEventStreamSvc {
            publisher: self.publisher.clone(),
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: self.limits.max_subscriptions,
            block_source: self.block_source.clone(),
        };
        info!(target: "events::grpc", addr = %self.addr, "events gRPC server starting");
        let shutdown_signal = async move {
            let _ = shutdown.changed().await;
        };
        // The TCP listener was already bound in `bind()` (so any
        // operator-visible bind failure happens at startup, not here).
        // Hand it to tonic via `serve_with_incoming_shutdown`, gating
        // accepted connections through a semaphore so no more than
        // `max_conns` are open at once. Each accepted connection carries an
        // owned permit released when the connection (and thus the wrapping
        // `PermittedTcp`) is dropped. `0` disables the cap.
        let conn_sem = if self.limits.max_conns > 0 {
            Some(Arc::new(Semaphore::new(self.limits.max_conns)))
        } else {
            None
        };
        let max_conns = self.limits.max_conns;
        let incoming = TcpListenerStream::new(self.listener).filter_map(move |res| match res {
            Ok(stream) => match &conn_sem {
                Some(sem) => match sem.clone().try_acquire_owned() {
                    Ok(permit) => Some(Ok(PermittedTcp {
                        inner: stream,
                        _permit: Some(permit),
                    })),
                    Err(_) => {
                        warn!(
                            target: "events::grpc",
                            max_conns,
                            "events gRPC at-capacity rejection (dropping connection)",
                        );
                        None
                    }
                },
                None => Some(Ok(PermittedTcp {
                    inner: stream,
                    _permit: None,
                })),
            },
            Err(e) => Some(Err(e)),
        });
        // When auth is configured, wrap the service in a tonic interceptor that
        // rejects any Subscribe without a valid bearer token holding
        // stream:subscribe (and stashes the principal in the request extensions
        // for the handler / future per-principal quota). The loopback +
        // allow_remote gate in `bind()` stays as a transport pre-check beneath
        // this app-layer auth.
        let result = if let Some(store) = self.auth.clone() {
            let interceptor = move |mut req: Request<()>| -> Result<Request<()>, Status> {
                let principal = authenticate(&req, &store)?;
                // Per-principal rate limit (operator/loopback bypass): shed an
                // over-budget Subscribe with RESOURCE_EXHAUSTED, never block.
                if let satd_auth::RateDecision::Throttle { .. } = principal.check_rate() {
                    return Err(Status::resource_exhausted("rate limit exceeded"));
                }
                req.extensions_mut().insert(principal);
                Ok(req)
            };
            Server::builder()
                .add_service(NodeEventStreamServer::with_interceptor(svc_impl, interceptor))
                .serve_with_incoming_shutdown(incoming, shutdown_signal)
                .await
        } else {
            Server::builder()
                .add_service(NodeEventStreamServer::new(svc_impl))
                .serve_with_incoming_shutdown(incoming, shutdown_signal)
                .await
        };
        if let Err(e) = result {
            warn!(target: "events::grpc", error = %e, "events gRPC server exited with error");
        }
    }
}

struct NodeEventStreamSvc {
    publisher: std::sync::Arc<node::events::EventPublisher>,
    /// Live count of active `Subscribe` streams, shared across all
    /// connections. Bounded by `max_subscriptions` (when non-zero).
    active_subs: Arc<AtomicUsize>,
    /// Hard cap on concurrent `Subscribe` streams. `0` disables the cap.
    max_subscriptions: usize,
    /// Read-only block-index access for durable cursor replay; `None`
    /// disables replay (forward-only).
    block_source: Option<std::sync::Arc<dyn node::events::BlockCursorSource>>,
}

/// RAII guard decrementing the active-subscription counter when a stream is
/// dropped (client disconnect or server shutdown). Held inside the per-
/// subscriber stream closure so its lifetime matches the stream's.
struct SubscriptionGuard(Arc<AtomicUsize>);

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A TCP stream carrying an owned connection-cap permit. Delegates all I/O
/// to the inner `TcpStream`; the permit is released when this is dropped,
/// i.e. when tonic finishes serving the connection. `_permit` is `None`
/// when the connection cap is disabled.
struct PermittedTcp {
    inner: tokio::net::TcpStream,
    _permit: Option<OwnedSemaphorePermit>,
}

impl AsyncRead for PermittedTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PermittedTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl Connected for PermittedTcp {
    type ConnectInfo = <tokio::net::TcpStream as Connected>::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.inner.connect_info()
    }
}

#[async_trait]
impl NodeEventStream for NodeEventStreamSvc {
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<pb::NodeEvent, Status>> + Send + 'static>>;

    async fn subscribe(
        &self,
        request: Request<pb::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let req = request.into_inner();

        // Enforce the global concurrent-subscription cap before attaching a
        // receiver. We reserve a slot up front (fetch_add) and roll back if
        // over the cap, so concurrent `Subscribe` calls can't race past the
        // limit. The reserved slot is released by `SubscriptionGuard` when
        // the returned stream is dropped. `0` disables the cap.
        let sub_guard = if self.max_subscriptions > 0 {
            let active = self.active_subs.fetch_add(1, Ordering::AcqRel) + 1;
            if active > self.max_subscriptions {
                self.active_subs.fetch_sub(1, Ordering::AcqRel);
                warn!(
                    target: "events::grpc",
                    max_subscriptions = self.max_subscriptions,
                    "events gRPC subscription cap reached — rejecting Subscribe",
                );
                return Err(Status::resource_exhausted(
                    "events gRPC concurrent-subscription cap reached",
                ));
            }
            Some(SubscriptionGuard(self.active_subs.clone()))
        } else {
            None
        };

        // 0 means "all categories" — same convention as the in-process
        // `EventSink`. Otherwise it's a bitfield (mempool=1, chain=2,
        // heartbeat=4). Unknown bits are silently ignored: a future
        // server may add new categories without forcing older clients
        // to upgrade. We could `return Err(invalid_argument)` if the
        // mask covers no known bit, but that would also reject the
        // legitimate "subscribe to a category my server doesn't know
        // about yet" case during a rolling upgrade — easier to log
        // and let the stream be empty.
        let category_mask = if req.categories == 0 {
            u32::MAX
        } else {
            req.categories
        };
        let since_seq = req.since_seq.unwrap_or(0);

        // Subscribe to the live broadcast FIRST, before reading the tip for
        // replay. This is the snapshot→live handoff ordering that guarantees
        // no gap: any block connecting while we replay confirmed history is
        // buffered in this receiver and delivered live afterwards. A fresh
        // receiver only sees events emitted after this point, so `since_seq`
        // (a forward-only dedup filter, not durable replay) and the live
        // tail both anchor here.
        let rx = self.publisher.subscribe();

        // Durable cursor replay (snapshot→live handoff). When the client
        // sends `from_cursor` and we have a block source, replay confirmed
        // BlockConnected events from the cursor's next height up to the
        // current tip (the "snapshot"), then chain the live stream. To
        // avoid a duplicate at the boundary, live BlockConnected events at
        // height <= the snapshot tip are dropped (they were just replayed).
        // A `from_cursor` request with no block source falls back to
        // forward-only and logs.
        let replay: Option<(Arc<HashMap<u32, BlockHash>>, Vec<pb::NodeEvent>, u64)> =
            match (req.from_cursor, self.block_source.as_ref()) {
                (Some(cursor), Some(src)) => {
                    let snapshot_tip = src.current_tip_height();
                    let mut start = cursor.height.saturating_add(1);
                    // Bound the confirmed replay span. A cursor far behind the
                    // tip would otherwise stream the entire chain over the
                    // event channel (a DoS amplification) and build an
                    // unbounded boundary-dedup map. Clamp to the most recent
                    // `MAX_REPLAY_BLOCKS`; replayed events carry their height
                    // cursor, so a client can detect the resulting gap (first
                    // replayed height > cursor + 1) and full-resync the rest.
                    if snapshot_tip >= start && snapshot_tip - start + 1 > MAX_REPLAY_BLOCKS {
                        let clamped = snapshot_tip - MAX_REPLAY_BLOCKS + 1;
                        warn!(
                            target: "events::grpc",
                            requested_from = start,
                            clamped_from = clamped,
                            snapshot_tip,
                            "from_cursor replay span exceeds MAX_REPLAY_BLOCKS; \
                             clamping (client should full-resync earlier history)",
                        );
                        start = clamped;
                    }
                    // Capture a CONSISTENT snapshot of the confirmed range as
                    // height→hash (gated on the chain category bit). Replay
                    // emits exactly these hashes (so a reorg during replay
                    // cannot tear the segment), and the live-side boundary
                    // dedup compares against them by identity: a live
                    // BlockConnected whose hash equals the captured hash at
                    // that height is a true duplicate (it connected during the
                    // subscribe→snapshot window) and is dropped, while a reorg
                    // that replaces a block at height <= snapshot_tip yields a
                    // DIFFERENT hash and is forwarded so the client's confirmed
                    // view stays correct.
                    let mut replayed: HashMap<u32, BlockHash> = HashMap::new();
                    if category_mask & 2 != 0 {
                        for h in start..=snapshot_tip {
                            if let Some(hash) = src.block_hash_at(h) {
                                replayed.insert(h, hash);
                            }
                        }
                    }
                    // Best-effort mempool replay from the bounded publisher ring
                    // (the mempool is not durable). Oldest-first; the highest
                    // replayed seq is the live-side dedup boundary. Gated on the
                    // mempool category bit so a chain-only subscription gets no
                    // mempool replay.
                    let mp: Vec<pb::NodeEvent> = if category_mask & 1 != 0 {
                        self.publisher
                            .replay_mempool_since(cursor.mempool_seq)
                            .iter()
                            .map(envelope_to_proto)
                            .collect()
                    } else {
                        Vec::new()
                    };
                    let mp_dedup_through = mp
                        .last()
                        .and_then(|e| e.stamp.as_ref())
                        .map(|s| s.seq)
                        .unwrap_or(0);
                    debug!(
                        target: "events::grpc",
                        from_height = start,
                        snapshot_tip,
                        replayed_blocks = replayed.len(),
                        mempool_replayed = mp.len(),
                        mempool_since = cursor.mempool_seq,
                        "events gRPC durable cursor replay (snapshot→live)",
                    );
                    Some((Arc::new(replayed), mp, mp_dedup_through))
                }
                (Some(_), None) => {
                    warn!(
                        target: "events::grpc",
                        "from_cursor requested but no block source configured; streaming live only",
                    );
                    None
                }
                (None, _) => {
                    debug!(
                        target: "events::grpc",
                        categories = req.categories,
                        since_seq,
                        "events gRPC subscriber attached (forward-only; no replay)",
                    );
                    None
                }
            };
        let replayed_for_live = replay.as_ref().map(|(r, _, _)| r.clone());
        // Live mempool events at or below the highest replayed mempool seq
        // were just replayed from the ring — drop the live copy.
        let drop_mempool_through = replay.as_ref().map(|(_, _, mp_seq)| *mp_seq);
        let edge = *self.publisher.edge();

        // `sub_guard` is moved into the live stream closure so the
        // subscription slot is held for exactly as long as the (combined)
        // stream lives; it is never read, only kept alive (and dropped —
        // decrementing the counter — when the client disconnects or the
        // server shuts down).
        let live = BroadcastStream::new(rx).filter_map(move |item| {
            let _keep_slot = &sub_guard;
            match item {
                Ok(env) => {
                    if (env.category_bit() & category_mask) == 0 {
                        return None;
                    }
                    if since_seq > 0 && env.stamp.seq <= since_seq {
                        return None;
                    }
                    // Boundary dedup (identity-based): drop a live
                    // BlockConnected only if it is byte-identical to the block
                    // already replayed at that height. A reorg replacement at
                    // height <= snapshot_tip has a different hash and is
                    // forwarded, so the client's confirmed view stays correct
                    // across a reorg during the snapshot→live handoff.
                    if let Some(replayed) = &replayed_for_live
                        && let NodeEventBody::Chain(
                            node::chain::events::ChainEvent::BlockConnected { height, hash },
                        ) = &env.body
                        && replayed.get(height) == Some(hash)
                    {
                        return None;
                    }
                    // Boundary dedup (mempool): an event at or below the
                    // highest replayed mempool seq was already replayed from
                    // the ring; drop the live copy.
                    if let Some(s) = drop_mempool_through
                        && matches!(env.body, NodeEventBody::Mempool(_))
                        && env.stamp.seq <= s
                    {
                        return None;
                    }
                    Some(Ok(envelope_to_proto(&env)))
                }
                Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                    warn!(target: "events::grpc", dropped = n, "gRPC subscriber lagged");
                    None
                }
            }
        });

        let stream: Self::SubscribeStream = match replay {
            Some((replayed, mp, _)) => {
                // Confirmed replay first, from the captured consistent snapshot
                // in height order (empty when the chain category was not
                // requested). Each carries its `(height, 0)` cursor and a
                // replay stamp (seq 0 — positioned by the durable cursor, not
                // the volatile per-publisher seq). Then best-effort mempool
                // replay (already proto, seq order), then the live stream.
                let mut pairs: Vec<(u32, BlockHash)> =
                    replayed.iter().map(|(h, hash)| (*h, *hash)).collect();
                pairs.sort_unstable_by_key(|(h, _)| *h);
                let block_replay = tokio_stream::iter(pairs)
                    .map(move |(h, hash)| Ok(replay_event_from_hash(&edge, h, hash)));
                let mp_replay = tokio_stream::iter(mp.into_iter().map(Ok));
                Box::pin(block_replay.chain(mp_replay).chain(live))
            }
            None => Box::pin(live),
        };

        Ok(Response::new(stream))
    }
}

/// Discard `Streaming` from the request, leaving only the unary message
/// — silences an unused-import warning when tonic generates client code.
#[allow(dead_code)]
fn _streaming_marker(_: Streaming<()>) {}

// `tokio_stream::Stream` provides `filter_map`; pull it into scope.
use tokio_stream::StreamExt as _;

fn envelope_to_proto(env: &NodeEvent) -> pb::NodeEvent {
    pb::NodeEvent {
        schema_version: env.schema_version,
        stamp: Some(stamp_to_proto(&env.stamp)),
        cursor: env.cursor.map(cursor_to_proto),
        body: Some(body_to_proto(&env.body)),
    }
}

fn cursor_to_proto(c: node::events::Cursor) -> pb::Cursor {
    pb::Cursor {
        height: c.height,
        tx_index: c.tx_index,
        mempool_seq: c.mempool_seq,
    }
}

/// Wall-clock nanoseconds since the Unix epoch (for replay-event stamps).
fn now_wall_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Build the edge stamp for a synthesized replay event. `seq` is 0 and
/// `edge_seen_at_ns` is 0 — a replayed confirmed event is positioned by its
/// durable `(height, tx_index)` cursor, not the volatile per-publisher seq.
fn replay_stamp(edge: &node::events::EdgeIdentity) -> pb::EdgeStamp {
    pb::EdgeStamp {
        node_id: edge.node_id.to_vec(),
        region: region_to_string(edge.region.as_ref()),
        edge_seen_at_ns: 0,
        edge_wall_ns: now_wall_ns(),
        seq: 0,
    }
}

/// Synthesize a confirmed `BlockConnected` replay event for `height` from a
/// captured snapshot `hash`, carrying its `(height, 0)` cursor.
fn replay_event_from_hash(
    edge: &node::events::EdgeIdentity,
    height: u32,
    hash: BlockHash,
) -> pb::NodeEvent {
    use bitcoin::hashes::Hash;
    pb::NodeEvent {
        schema_version: node::events::SCHEMA_VERSION,
        stamp: Some(replay_stamp(edge)),
        cursor: Some(pb::Cursor {
            height,
            tx_index: 0,
            mempool_seq: 0,
        }),
        body: Some(pb::node_event::Body::Chain(pb::ChainEvent {
            body: Some(pb::chain_event::Body::BlockConnected(pb::BlockConnected {
                hash: hash.as_raw_hash().to_byte_array().to_vec(),
                height,
            })),
        })),
    }
}

fn stamp_to_proto(stamp: &node::events::EdgeStamp) -> pb::EdgeStamp {
    pb::EdgeStamp {
        node_id: stamp.node_id.to_vec(),
        region: region_to_string(stamp.region.as_ref()),
        edge_seen_at_ns: stamp.edge_seen_at_ns,
        edge_wall_ns: stamp.edge_wall_ns,
        seq: stamp.seq,
    }
}

fn region_to_string(region: Option<&[u8; 8]>) -> String {
    match region {
        None => String::new(),
        Some(raw) => {
            let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            std::str::from_utf8(&raw[..end])
                .unwrap_or("")
                .to_string()
        }
    }
}

fn body_to_proto(body: &NodeEventBody) -> pb::node_event::Body {
    use pb::node_event::Body;
    match body {
        NodeEventBody::Mempool(mp) => Body::Mempool(mempool_event_to_proto(mp)),
        NodeEventBody::Chain(ch) => Body::Chain(chain_event_to_proto(ch)),
        NodeEventBody::Heartbeat { uptime_ns } => Body::Heartbeat(pb::Heartbeat {
            uptime_ns: *uptime_ns,
        }),
    }
}

fn mempool_event_to_proto(ev: &node::mempool::events::MempoolEvent) -> pb::MempoolEvent {
    use bitcoin::hashes::Hash;
    use node::mempool::events::{EvictReason as RustReason, MempoolEvent as Mp};
    use pb::mempool_event::Body as MpBody;

    let body = match ev {
        Mp::Enter {
            txid,
            fee,
            vsize,
            fee_rate_sat_per_kvb,
            time,
        } => MpBody::Enter(pb::MempoolEnter {
            txid: txid.as_raw_hash().to_byte_array().to_vec(),
            fee: *fee,
            vsize: *vsize,
            fee_rate_sat_per_kvb: *fee_rate_sat_per_kvb,
            time: *time,
        }),
        Mp::LeaveConfirmed {
            txid,
            block_hash,
            height,
        } => MpBody::LeaveConfirmed(pb::MempoolLeaveConfirmed {
            txid: txid.as_raw_hash().to_byte_array().to_vec(),
            block_hash: block_hash.as_raw_hash().to_byte_array().to_vec(),
            height: *height,
        }),
        Mp::LeaveEvicted { txid, reason } => MpBody::LeaveEvicted(pb::MempoolLeaveEvicted {
            txid: txid.as_raw_hash().to_byte_array().to_vec(),
            reason: match reason {
                RustReason::FullPool => pb::EvictReason::FullPool as i32,
                RustReason::Expiry => pb::EvictReason::Expiry as i32,
                RustReason::BlockConflict => pb::EvictReason::BlockConflict as i32,
            },
        }),
        Mp::LeaveReplaced {
            txid,
            replacing_txid,
        } => MpBody::LeaveReplaced(pb::MempoolLeaveReplaced {
            txid: txid.as_raw_hash().to_byte_array().to_vec(),
            replacing_txid: replacing_txid.as_raw_hash().to_byte_array().to_vec(),
        }),
    };
    pb::MempoolEvent { body: Some(body) }
}

fn chain_event_to_proto(ev: &node::chain::events::ChainEvent) -> pb::ChainEvent {
    use bitcoin::hashes::Hash;
    use node::chain::events::ChainEvent as Ch;
    use pb::chain_event::Body as ChBody;
    let body = match ev {
        Ch::BlockConnected { hash, height } => ChBody::BlockConnected(pb::BlockConnected {
            hash: hash.as_raw_hash().to_byte_array().to_vec(),
            height: *height,
        }),
        Ch::BlockDisconnected { hash, height } => {
            ChBody::BlockDisconnected(pb::BlockDisconnected {
                hash: hash.as_raw_hash().to_byte_array().to_vec(),
                height: *height,
            })
        }
    };
    pb::ChainEvent { body: Some(body) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, Txid};
    use node::chain::events::ChainEvent;
    use node::events::{EdgeIdentity, EventPublisher};
    use node::mempool::events::{EvictReason, MempoolEvent};
    use std::time::Duration;

    fn edge() -> EdgeIdentity {
        EdgeIdentity::new([0x42; 16], Some("us-east1")).unwrap()
    }

    // sha256("grpc-sub-token") and sha256("grpc-nosub-token"), fixed vectors.
    const SUB_TOKEN: &str = "grpc-sub-token";
    const SUB_TOKEN_SHA256: &str =
        "ae5e3c117a11a76ffdbd1ea48b3ab0090d7a236f44aee421cbeb00d9b10bb368";
    const NOSUB_TOKEN: &str = "grpc-nosub-token";
    const NOSUB_TOKEN_SHA256: &str =
        "11185ce0a4d924beea79c1198a388f6f9d75c1e95ff0fc71549ec8d2d28483b3";

    fn auth_store() -> Arc<satd_auth::TokenStore> {
        use std::io::Write;
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let toml = format!(
            "version = 1\n\
             [[token]]\nid=\"sub\"\nhash=\"sha256:{SUB_TOKEN_SHA256}\"\ncapabilities=[\"stream:subscribe\"]\n\
             [[token]]\nid=\"nosub\"\nhash=\"sha256:{NOSUB_TOKEN_SHA256}\"\ncapabilities=[\"rpc:read\"]\n"
        );
        let p = dir.path().join("auth.toml");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Arc::new(satd_auth::TokenStore::load(&p).unwrap())
    }

    fn req_with_auth(value: Option<&str>) -> Request<()> {
        let mut req = Request::new(());
        if let Some(v) = value {
            req.metadata_mut().insert("authorization", v.parse().unwrap());
        }
        req
    }

    #[test]
    fn grpc_auth_accepts_stream_subscribe_token() {
        let store = auth_store();
        let req = req_with_auth(Some(&format!("Bearer {SUB_TOKEN}")));
        let p = authenticate(&req, &store).expect("valid subscribe token");
        assert_eq!(p.id(), "sub");
    }

    #[test]
    fn grpc_auth_rejects_token_without_subscribe_capability() {
        let store = auth_store();
        let req = req_with_auth(Some(&format!("Bearer {NOSUB_TOKEN}")));
        let err = authenticate(&req, &store).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn grpc_auth_rejects_missing_and_unknown() {
        let store = auth_store();
        assert_eq!(
            authenticate(&req_with_auth(None), &store).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            authenticate(&req_with_auth(Some("Bearer nope")), &store)
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        // Basic (non-bearer) is not a valid gRPC credential here.
        assert_eq!(
            authenticate(&req_with_auth(Some("Basic abc")), &store)
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }

    fn enter(byte: u8) -> MempoolEvent {
        MempoolEvent::Enter {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [byte; 32],
            )),
            fee: 100,
            vsize: 250,
            fee_rate_sat_per_kvb: 400,
            time: 1_700_000_000,
        }
    }

    #[test]
    fn convert_mempool_enter_round_trip() {
        let ev = enter(7);
        let pb = mempool_event_to_proto(&ev);
        let body = pb.body.unwrap();
        match body {
            pb::mempool_event::Body::Enter(e) => {
                assert_eq!(e.fee, 100);
                assert_eq!(e.txid.len(), 32);
                assert_eq!(e.txid[0], 7);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn convert_evict_reason_maps_correctly() {
        for (rust, expected) in [
            (EvictReason::FullPool, pb::EvictReason::FullPool),
            (EvictReason::Expiry, pb::EvictReason::Expiry),
            (EvictReason::BlockConflict, pb::EvictReason::BlockConflict),
        ] {
            let ev = MempoolEvent::LeaveEvicted {
                txid: Txid::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]),
                ),
                reason: rust,
            };
            let pb_ev = mempool_event_to_proto(&ev);
            match pb_ev.body.unwrap() {
                pb::mempool_event::Body::LeaveEvicted(e) => {
                    assert_eq!(e.reason, expected as i32);
                }
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn convert_block_connected_includes_hash_and_height() {
        let ev = ChainEvent::BlockConnected {
            hash: BlockHash::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]),
            ),
            height: 42,
        };
        let pb_ev = chain_event_to_proto(&ev);
        match pb_ev.body.unwrap() {
            pb::chain_event::Body::BlockConnected(b) => {
                assert_eq!(b.height, 42);
                assert_eq!(b.hash[0], 0xaa);
                assert_eq!(b.hash.len(), 32);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn bind_rejects_remote_address_by_default() {
        let publisher = EventPublisher::new(edge(), 16);
        match GrpcEventSink::bind("0.0.0.0:0", false, publisher, GrpcLimits::default(), None, None).await {
            Err(GrpcEventSinkError::RemoteBindRejected(_)) => {}
            Ok(_) => panic!("non-loopback bind without allow_remote should fail"),
            Err(e) => panic!("expected RemoteBindRejected, got {e}"),
        }
    }

    #[tokio::test]
    async fn bind_allows_loopback_without_override() {
        let publisher = EventPublisher::new(edge(), 16);
        let sink = GrpcEventSink::bind("127.0.0.1:0", false, publisher, GrpcLimits::default(), None, None)
            .await
            .expect("loopback bind should succeed");
        let addr = sink.local_addr().expect("local_addr");
        assert!(addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn bind_allows_remote_with_allow_flag() {
        let publisher = EventPublisher::new(edge(), 16);
        // 0.0.0.0:0 with allow_remote = true: must succeed (the actual
        // port the OS picks is irrelevant; the test asserts only that
        // the loopback gate is bypassed when the caller opts in).
        let sink = GrpcEventSink::bind("0.0.0.0:0", true, publisher, GrpcLimits::default(), None, None)
            .await
            .expect("explicit remote bind should be allowed");
        let addr = sink.local_addr().unwrap();
        assert!(!addr.ip().is_loopback());
    }

    #[test]
    fn region_serialization_trims_padding() {
        let stamp = node::events::EdgeStamp {
            node_id: [1; 16],
            region: Some(*b"eu-w\0\0\0\0"),
            edge_seen_at_ns: 0,
            edge_wall_ns: 0,
            seq: 1,
        };
        let pb_stamp = stamp_to_proto(&stamp);
        assert_eq!(pb_stamp.region, "eu-w");
    }

    /// End-to-end: spin up a real GrpcEventSink, connect a tonic client,
    /// inject a synthetic chain event via the publisher's bridge, assert
    /// the client receives it with the correct stamp.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_streaming_delivery() {
        // 1. Build publisher + bridges.
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx.clone());

        // 2. Bind directly (the new API picks the actual ephemeral port
        // from the OS, no TOCTOU window).
        let sink = GrpcEventSink::bind("127.0.0.1:0", false, publisher.clone(), GrpcLimits::default(), None, None)
            .await
            .expect("bind");
        let actual = sink.local_addr().unwrap();
        let sinks: Vec<Box<dyn EventSink>> = vec![Box::new(sink)];
        publisher.attach_sinks(sinks, shutdown_rx.clone());

        // 3. Wait briefly for the server to come up, then connect.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut client =
            pb::node_event_stream_client::NodeEventStreamClient::connect(format!(
                "http://{}",
                actual
            ))
            .await
            .expect("connect");

        // 4. Subscribe to all categories.
        let mut stream = client
            .subscribe(pb::SubscribeRequest {
                categories: 0,
                since_seq: None,
                from_cursor: None,
            })
            .await
            .expect("subscribe")
            .into_inner();

        // 5. Inject events.
        tokio::time::sleep(Duration::from_millis(50)).await;
        mp_tx.send(enter(1)).unwrap();
        ch_tx
            .send(ChainEvent::BlockConnected {
                hash: BlockHash::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([2u8; 32]),
                ),
                height: 1,
            })
            .unwrap();

        // 6. Receive both, in order.
        let env1 = tokio::time::timeout(Duration::from_secs(3), stream.message())
            .await
            .expect("timeout waiting for first event")
            .expect("transport error")
            .expect("stream ended");
        let env2 = tokio::time::timeout(Duration::from_secs(3), stream.message())
            .await
            .expect("timeout waiting for second event")
            .expect("transport error")
            .expect("stream ended");

        assert_eq!(env1.schema_version, node::events::SCHEMA_VERSION);
        let stamp1 = env1.stamp.clone().expect("env1 stamp present");
        let stamp2 = env2.stamp.clone().expect("env2 stamp present");
        assert_eq!(stamp1.node_id, [0x42u8; 16].to_vec());
        assert_eq!(stamp1.region, "us-east1");
        // The two bridge tasks publish concurrently; seq ordering between
        // them is non-deterministic, but each is assigned exactly once
        // and they are unique.
        let mut seqs = [stamp1.seq, stamp2.seq];
        seqs.sort();
        assert_eq!(seqs, [1, 2]);

        // We received one mempool body and one chain body, in some order.
        let bodies: Vec<_> = [&env1, &env2].iter().map(|e| e.body.clone()).collect();
        let kinds: Vec<&'static str> = bodies
            .iter()
            .map(|b| match b.as_ref().expect("body present") {
                pb::node_event::Body::Mempool(_) => "mempool",
                pb::node_event::Body::Chain(_) => "chain",
                pb::node_event::Body::Heartbeat(_) => "heartbeat",
            })
            .collect();
        assert!(
            kinds.contains(&"mempool") && kinds.contains(&"chain"),
            "expected one mempool + one chain body, got {kinds:?}",
        );

        // 7. Shutdown.
        let _ = shutdown_tx.send(true);
    }

    /// The concurrent-subscription cap rejects `Subscribe` beyond the limit
    /// with `RESOURCE_EXHAUSTED`, and frees a slot when a stream is dropped.
    #[tokio::test]
    async fn subscription_cap_rejects_when_full() {
        let publisher = EventPublisher::new(edge(), 16);
        let svc = NodeEventStreamSvc {
            publisher,
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 2,
            block_source: None,
        };
        let mk = || {
            Request::new(pb::SubscribeRequest {
                categories: 0,
                since_seq: None,
                from_cursor: None,
            })
        };

        let s1 = svc.subscribe(mk()).await.expect("first subscribe ok");
        let s2 = svc.subscribe(mk()).await.expect("second subscribe ok");
        assert_eq!(svc.active_subs.load(Ordering::Acquire), 2);

        // Third exceeds the cap → RESOURCE_EXHAUSTED, count rolled back.
        // (`Response` wraps a boxed stream that isn't `Debug`, so match
        // rather than `expect_err`.)
        let err = match svc.subscribe(mk()).await {
            Ok(_) => panic!("third subscribe must be rejected"),
            Err(e) => e,
        };
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(svc.active_subs.load(Ordering::Acquire), 2);

        // Dropping a stream frees its slot (the guard decrements on drop),
        // so a fresh subscribe then succeeds.
        drop(s1);
        assert_eq!(svc.active_subs.load(Ordering::Acquire), 1);
        let s3 = svc
            .subscribe(mk())
            .await
            .expect("subscribe ok after a slot frees");
        assert_eq!(svc.active_subs.load(Ordering::Acquire), 2);

        drop(s2);
        drop(s3);
    }

    /// Mock block source: every height up to `tip` resolves to a
    /// deterministic hash (`[height as u8; 32]`); beyond the tip is `None`.
    struct MockBlocks {
        tip: u32,
    }
    impl node::events::BlockCursorSource for MockBlocks {
        fn current_tip_height(&self) -> u32 {
            self.tip
        }
        fn block_hash_at(&self, height: u32) -> Option<BlockHash> {
            if height >= 1 && height <= self.tip {
                Some(BlockHash::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([height as u8; 32]),
                ))
            } else {
                None
            }
        }
    }

    fn chain_height(ev: &pb::NodeEvent) -> Option<u32> {
        match ev.body.as_ref()? {
            pb::node_event::Body::Chain(c) => match c.body.as_ref()? {
                pb::chain_event::Body::BlockConnected(b) => Some(b.height),
                _ => None,
            },
            _ => None,
        }
    }

    fn chain_hash(ev: &pb::NodeEvent) -> Option<Vec<u8>> {
        match ev.body.as_ref()? {
            pb::node_event::Body::Chain(c) => match c.body.as_ref()? {
                pb::chain_event::Body::BlockConnected(b) => Some(b.hash.clone()),
                _ => None,
            },
            _ => None,
        }
    }

    /// `from_cursor` replays confirmed `BlockConnected` history from the
    /// cursor's next height up to the snapshot tip, each stamped with its
    /// `(height, 0)` cursor and a replay seq of 0.
    #[tokio::test]
    async fn cursor_replay_emits_confirmed_history() {
        use tokio_stream::StreamExt as _;
        let publisher = EventPublisher::new(edge(), 64);
        let svc = NodeEventStreamSvc {
            publisher,
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
            block_source: Some(Arc::new(MockBlocks { tip: 5 })),
        };
        // Resume from height 2 → replay 3, 4, 5 (chain category only).
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 2,
                since_seq: None,
                from_cursor: Some(pb::Cursor {
                    height: 2,
                    tx_index: 0,
                    mempool_seq: 0,
                }),
            }))
            .await
            .expect("subscribe");
        let mut stream = resp.into_inner();
        for expected in 3..=5u32 {
            let ev = tokio::time::timeout(Duration::from_secs(1), stream.next())
                .await
                .expect("replay item ready")
                .expect("stream not ended")
                .expect("no status error");
            assert_eq!(chain_height(&ev), Some(expected));
            let cur = ev.cursor.expect("replay event carries a cursor");
            assert_eq!(cur.height, expected);
            assert_eq!(cur.tx_index, 0);
            // Replay events are positioned by the durable cursor, not seq.
            assert_eq!(ev.stamp.as_ref().unwrap().seq, 0);
        }
    }

    /// After replay, the stream joins live; a live block at height <= the
    /// snapshot tip is dropped (already replayed) while a higher block is
    /// delivered — the snapshot→live handoff has no gap and no duplicate.
    #[tokio::test]
    async fn cursor_replay_then_joins_live_without_duplicate() {
        use tokio_stream::StreamExt as _;
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx);

        let svc = NodeEventStreamSvc {
            publisher: publisher.clone(),
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
            block_source: Some(Arc::new(MockBlocks { tip: 5 })),
        };
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 2,
                since_seq: None,
                from_cursor: Some(pb::Cursor {
                    height: 4,
                    tx_index: 0,
                    mempool_seq: 0,
                }),
            }))
            .await
            .expect("subscribe");
        let mut stream = resp.into_inner();

        // Replay covers only height 5 (cursor at 4, tip 5).
        let ev = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("replay ready")
            .unwrap()
            .unwrap();
        assert_eq!(chain_height(&ev), Some(5));

        // Live block at height 5 (<= snapshot tip) must be deduped, and the
        // block at height 6 (> snapshot tip) must come through.
        let mk = |h: u32| ChainEvent::BlockConnected {
            hash: BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [h as u8; 32],
            )),
            height: h,
        };
        ch_tx.send(mk(5)).unwrap(); // duplicate of the replayed tip → dropped
        ch_tx.send(mk(6)).unwrap(); // new → delivered

        let ev = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("live item ready")
            .unwrap()
            .unwrap();
        assert_eq!(
            chain_height(&ev),
            Some(6),
            "the height-5 duplicate must be dropped, leaving height 6",
        );
        let _ = shutdown_tx.send(true);
    }

    /// Regression: a reorg during the snapshot→live handoff that replaces a
    /// block at a height <= the snapshot tip must be DELIVERED (its hash
    /// differs from the replayed block), not silently dropped by the boundary
    /// dedup. The earlier height-based dedup tore the client's confirmed view
    /// by eating the reorg's replacement `BlockConnected` while letting the
    /// disconnect through; identity-based dedup forwards it.
    #[tokio::test]
    async fn reorg_during_handoff_forwards_replacement_block() {
        use tokio_stream::StreamExt as _;
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx);

        let svc = NodeEventStreamSvc {
            publisher: publisher.clone(),
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
            block_source: Some(Arc::new(MockBlocks { tip: 5 })),
        };
        // Resume from height 3 → replay 4, 5 (snapshot hashes [4;32], [5;32]).
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 2,
                since_seq: None,
                from_cursor: Some(pb::Cursor {
                    height: 3,
                    tx_index: 0,
                    mempool_seq: 0,
                }),
            }))
            .await
            .expect("subscribe");
        let mut stream = resp.into_inner();
        for expected in 4..=5u32 {
            let ev = tokio::time::timeout(Duration::from_secs(1), stream.next())
                .await
                .expect("replay ready")
                .unwrap()
                .unwrap();
            assert_eq!(chain_height(&ev), Some(expected));
        }

        // A reorg replaces height 5 with a DIFFERENT block (hash [0xEE;32]).
        // This is height <= snapshot_tip but is not the replayed block, so it
        // must be forwarded, not deduped.
        let reorged5 = ChainEvent::BlockConnected {
            hash: BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [0xEE; 32],
            )),
            height: 5,
        };
        // A true duplicate of the replayed height-5 (same hash) must still be
        // dropped.
        let dup5 = ChainEvent::BlockConnected {
            hash: BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [5u8; 32],
            )),
            height: 5,
        };
        ch_tx.send(dup5).unwrap(); // identical → dropped
        ch_tx.send(reorged5).unwrap(); // reorg replacement → delivered

        let ev = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("live item ready")
            .unwrap()
            .unwrap();
        assert_eq!(chain_height(&ev), Some(5));
        assert_eq!(
            chain_hash(&ev),
            Some([0xEE; 32].to_vec()),
            "the reorg replacement at height 5 must be forwarded, not deduped",
        );
        let _ = shutdown_tx.send(true);
    }

    /// A cursor far behind the tip clamps the replay span to
    /// `MAX_REPLAY_BLOCKS` (the whole chain is never streamed over the event
    /// channel). The replayed window starts at `tip - MAX_REPLAY_BLOCKS + 1`.
    #[tokio::test]
    async fn far_behind_cursor_clamps_replay_span() {
        use tokio_stream::StreamExt as _;
        let tip = MAX_REPLAY_BLOCKS + 100;
        let publisher = EventPublisher::new(edge(), 64);
        let svc = NodeEventStreamSvc {
            publisher,
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
            block_source: Some(Arc::new(MockBlocks { tip })),
        };
        // Resume from height 0 → would replay the whole chain; must clamp.
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 2,
                since_seq: None,
                from_cursor: Some(pb::Cursor {
                    height: 0,
                    tx_index: 0,
                    mempool_seq: 0,
                }),
            }))
            .await
            .expect("subscribe");
        let mut stream = resp.into_inner();
        let first = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("replay ready")
            .unwrap()
            .unwrap();
        assert_eq!(
            chain_height(&first),
            Some(tip - MAX_REPLAY_BLOCKS + 1),
            "replay must start at the clamped window, not height 1",
        );
    }

    /// `from_cursor` with a mempool watermark replays the bounded mempool
    /// window (events with seq > the watermark) before joining live.
    #[tokio::test]
    async fn cursor_replay_includes_mempool_window() {
        use tokio_stream::StreamExt as _;
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(64);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx);

        // Publish 3 mempool events (seqs 1, 2, 3) into the replay ring.
        for i in 1..=3u8 {
            mp_tx.send(enter(i)).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        let svc = NodeEventStreamSvc {
            publisher: publisher.clone(),
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
            // tip 0 → no confirmed replay; isolate the mempool window.
            block_source: Some(Arc::new(MockBlocks { tip: 0 })),
        };
        // Resume from mempool_seq = 1 → replay seqs 2 and 3.
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 1, // mempool only
                since_seq: None,
                from_cursor: Some(pb::Cursor {
                    height: 0,
                    tx_index: 0,
                    mempool_seq: 1,
                }),
            }))
            .await
            .expect("subscribe");
        let mut stream = resp.into_inner();
        let mut seqs = Vec::new();
        for _ in 0..2 {
            let ev = tokio::time::timeout(Duration::from_secs(1), stream.next())
                .await
                .expect("mempool replay item ready")
                .unwrap()
                .unwrap();
            assert!(matches!(
                ev.body.as_ref().unwrap(),
                pb::node_event::Body::Mempool(_)
            ));
            seqs.push(ev.stamp.unwrap().seq);
        }
        assert_eq!(seqs, vec![2, 3], "replays only the post-watermark window");
        let _ = shutdown_tx.send(true);
    }

    /// A `from_cursor` request with no block source falls back to
    /// forward-only (no replay, no error).
    #[tokio::test]
    async fn cursor_without_block_source_is_forward_only() {
        use tokio_stream::StreamExt as _;
        let publisher = EventPublisher::new(edge(), 16);
        let svc = NodeEventStreamSvc {
            publisher,
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
            block_source: None,
        };
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 0,
                since_seq: None,
                from_cursor: Some(pb::Cursor {
                    height: 2,
                    tx_index: 0,
                    mempool_seq: 0,
                }),
            }))
            .await
            .expect("subscribe ok even without a block source");
        let mut stream = resp.into_inner();
        // No replay, no live events → next() times out (stream is pending).
        let pending = tokio::time::timeout(Duration::from_millis(150), stream.next()).await;
        assert!(pending.is_err(), "forward-only stream should have no replay items");
    }

    /// `max_subscriptions = 0` disables the cap entirely.
    #[tokio::test]
    async fn subscription_cap_disabled_when_zero() {
        let publisher = EventPublisher::new(edge(), 16);
        let svc = NodeEventStreamSvc {
            publisher,
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
            block_source: None,
        };
        let mut held = Vec::new();
        for _ in 0..16 {
            held.push(
                svc.subscribe(Request::new(pb::SubscribeRequest {
                    categories: 0,
                    since_seq: None,
                    from_cursor: None,
                }))
                .await
                .expect("uncapped subscribe always ok"),
            );
        }
        // Counter stays at zero when the cap is disabled.
        assert_eq!(svc.active_subs.load(Ordering::Acquire), 0);
    }
}
