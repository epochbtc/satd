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

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use async_trait::async_trait;
use node::events::{EventSink, NodeEvent, NodeEventBody};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, watch};
use tokio_stream::Stream;
use tokio_stream::wrappers::{BroadcastStream, ReceiverStream, TcpListenerStream};
use tonic::transport::Server;
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info, warn};

// The confirmed-block replay span cap is defined once in `node::events`
// (shared by every streaming carrier); re-export the name into scope so the
// handler and tests can refer to it unqualified.
use node::events::MAX_REPLAY_BLOCKS;

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
    /// Minimum allowed bit-length for a script-prefix watch (§7.5).
    pub prefix_min_bits: u8,
    /// Maximum allowed bit-length for a script-prefix watch (§7.5).
    pub prefix_max_bits: u8,
}

impl Default for GrpcLimits {
    fn default() -> Self {
        Self {
            max_conns: 64,
            max_subscriptions: 256,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        }
    }
}

use crate::proto::v1 as pb;
use crate::watchset::{bounded_txid_depth_pairs, WatchSet};
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
    /// Live outpoint/script watch registry backing the bidirectional
    /// `Watch` RPC. `None` disables `Watch` (returns `UNAVAILABLE`).
    watch_registry: Option<std::sync::Arc<node::events::WatchRegistry>>,
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
        .ok_or_else(|| {
            debug!(target: "events::grpc", code = "unauthenticated", "rejecting Subscribe: missing authorization metadata");
            Status::unauthenticated("missing authorization metadata")
        })?;
    let mut scratch = String::new();
    let principal = match satd_auth::Credential::from_authorization(hdr, &mut scratch) {
        Some(satd_auth::Credential::Bearer { token }) => store.resolve(token, now_unix()),
        _ => None,
    }
    .ok_or_else(|| {
        debug!(target: "events::grpc", code = "unauthenticated", "rejecting Subscribe: invalid or unknown bearer token");
        Status::unauthenticated("invalid or unknown bearer token")
    })?;
    if !principal.has(satd_auth::Capability::StreamSubscribe) {
        debug!(target: "events::grpc", code = "permission_denied", "rejecting Subscribe: token lacks stream:subscribe capability");
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
        watch_registry: Option<std::sync::Arc<node::events::WatchRegistry>>,
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
            watch_registry,
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
            watch_registry: self.watch_registry.clone(),
            prefix_min_bits: self.limits.prefix_min_bits,
            prefix_max_bits: self.limits.prefix_max_bits,
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
                    debug!(target: "events::grpc", code = "resource_exhausted", "rejecting Subscribe: per-principal rate limit exceeded");
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
    /// Live watch registry backing the `Watch` RPC; `None` disables it.
    watch_registry: Option<std::sync::Arc<node::events::WatchRegistry>>,
    /// Operator bounds on script-prefix watch granularity (§7.5).
    prefix_min_bits: u8,
    prefix_max_bits: u8,
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
    type WatchStream =
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
        // Capture the requested cursor's coordinates before `from_cursor` is
        // moved into the replay match; they seed the last-delivered position
        // used to fill a `Lagged` notice's resume cursor.
        let from_h = req.from_cursor.as_ref().map(|c| c.height).unwrap_or(0);
        let from_s = req.from_cursor.as_ref().map(|c| c.mempool_seq).unwrap_or(0);
        // Clamp, reorg-safety, instance-epoch handling, and the confirmed +
        // mempool snapshot all live in the shared `build_cursor_replay` helper
        // so every carrier (gRPC here, WS/SSE) behaves identically on the wire.
        let replay: Option<node::events::CursorReplay> =
            match (req.from_cursor, self.block_source.as_ref()) {
                (Some(c), Some(src)) => {
                    let from = node::events::Cursor {
                        height: c.height,
                        tx_index: c.tx_index,
                        mempool_seq: c.mempool_seq,
                        instance_id: c.instance_id,
                    };
                    let r = node::events::build_cursor_replay(
                        src.as_ref(),
                        &self.publisher,
                        from,
                        category_mask,
                        MAX_REPLAY_BLOCKS,
                    );
                    debug!(
                        target: "events::grpc",
                        replayed_events = r.events.len(),
                        confirmed_blocks = r.confirmed_dedup.len(),
                        mempool_dedup_through = r.mempool_dedup_through,
                        "events gRPC durable cursor replay (snapshot→live)",
                    );
                    Some(r)
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
        let replayed_for_live = replay.as_ref().map(|r| Arc::new(r.confirmed_dedup.clone()));
        // Live mempool events at or below the highest replayed mempool seq
        // were just replayed from the ring — drop the live copy.
        let drop_mempool_through = replay.as_ref().map(|r| r.mempool_dedup_through);
        // Last-delivered position, for the `Lagged` notice's resume cursor.
        // Seed from the replay tail (so a client that lags right after the
        // snapshot resumes after it, not from scratch), else the request cursor.
        let lag_publisher = self.publisher.clone();
        let mut last_h = from_h;
        let mut last_s = from_s;
        if let Some(r) = replay.as_ref() {
            if let Some(h) = r.confirmed_dedup.keys().max() {
                last_h = (*h).max(last_h);
            }
            last_s = r.mempool_dedup_through.max(last_s);
        }

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
                    // Advance the last-delivered position so a subsequent lag
                    // resumes the client just after this event.
                    last_s = env.stamp.seq;
                    if let Some(c) = &env.cursor {
                        last_h = c.height;
                    }
                    Some(Ok(envelope_to_proto(&env)))
                }
                Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                    // Tell the client in-band: how many events were dropped and
                    // the cursor to reconnect from to recover them. The stream
                    // then continues live.
                    warn!(target: "events::grpc", dropped = n, "gRPC subscriber lagged");
                    let resume = lag_publisher.resume_cursor(last_h, last_s);
                    let ev = node::events::lagged_event(&lag_publisher, n, resume);
                    Some(Ok(envelope_to_proto(&ev)))
                }
            }
        });

        let stream: Self::SubscribeStream = match replay {
            Some(r) => {
                // Replay events (confirmed BlockConnected in height order, then
                // the best-effort mempool window) are built by the shared
                // helper as `NodeEvent`s; convert each to proto and emit before
                // joining the live stream.
                let replay_events =
                    tokio_stream::iter(r.events.into_iter().map(|e| Ok(envelope_to_proto(&e))));
                Box::pin(replay_events.chain(live))
            }
            None => Box::pin(live),
        };

        Ok(Response::new(stream))
    }

    async fn watch(
        &self,
        request: Request<Streaming<pb::SubscribeControl>>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let registry = self.watch_registry.clone().ok_or_else(|| {
            warn!(target: "events::grpc", code = "unavailable", "rejecting Watch: watch registry not configured on this server");
            Status::unavailable("watch registry not configured on this server")
        })?;

        // Concurrent-subscription cap (shared with Subscribe).
        let sub_guard = if self.max_subscriptions > 0 {
            let active = self.active_subs.fetch_add(1, Ordering::AcqRel) + 1;
            if active > self.max_subscriptions {
                self.active_subs.fetch_sub(1, Ordering::AcqRel);
                warn!(
                    target: "events::grpc",
                    max_subscriptions = self.max_subscriptions,
                    "events gRPC concurrent-subscription cap reached — rejecting Watch",
                );
                return Err(Status::resource_exhausted(
                    "events gRPC concurrent-subscription cap reached",
                ));
            }
            Some(SubscriptionGuard(self.active_subs.clone()))
        } else {
            None
        };

        // Principal for per-add watch quota. Absent when auth is not
        // configured (loopback trust → unlimited watches, today's behavior).
        // When present, the interceptor already verified stream:subscribe;
        // each watch addition additionally requires stream:watch + quota via
        // `acquire_watch`.
        let principal = request.extensions().get::<satd_auth::Principal>().cloned();
        let mut inbound = request.into_inner();

        let (handle, rx_match) = registry.register(node::events::WATCH_CHANNEL_CAPACITY);
        let handle = Arc::new(handle);
        let category_mask = Arc::new(AtomicU32::new(u32::MAX));
        let edge = *self.publisher.edge();
        let rx_live = self.publisher.subscribe();

        // The watch-set (and the per-item quota leases inside it) is owned by
        // the SUBSCRIPTION, not the inbound control reader. gRPC/HTTP-2 lets a
        // client half-close its send side (END_STREAM on the request) while
        // keeping the response stream open; if it lived in the inbound task it
        // would be dropped the moment the control stream closed, releasing the
        // client's quota to zero while its watches stayed live on the outbound
        // stream — letting an authed tenant register an unbounded watch-set at
        // no standing quota cost. Holding it behind an `Arc` shared by both the
        // inbound task and the outbound stream ties the leases' lifetime to the
        // watch-set itself: quota is released per-remove, and the remainder when
        // the subscription is torn down (full disconnect).
        let watch_set: Arc<std::sync::Mutex<WatchSet>> =
            Arc::new(std::sync::Mutex::new(WatchSet::default()));

        // Inbound control reader: applies watch-set mutations + category
        // changes for the life of the stream against the shared subscription-
        // scoped watch-set, and holds a handle clone so the subscription is
        // retained while either side is alive.
        {
            let handle = handle.clone();
            let category_mask = category_mask.clone();
            let watch_set = watch_set.clone();
            let prefix_bounds = (self.prefix_min_bits, self.prefix_max_bits);
            tokio::spawn(async move {
                while let Ok(Some(ctrl)) = inbound.message().await {
                    let mut guard = watch_set.lock().unwrap_or_else(|p| p.into_inner());
                    apply_control(
                        ctrl,
                        &handle,
                        principal.as_ref(),
                        &category_mask,
                        &mut guard,
                        prefix_bounds,
                    );
                }
                // Inbound (control) closed. The watch-set is NOT dropped here —
                // it belongs to the subscription and drops with the outbound
                // stream + WatchHandle when the client fully disconnects.
            });
        }

        // Outbound: live category-filtered firehose merged with the
        // per-subscriber watch matches. Track the last-delivered position to
        // fill an in-band `Lagged` notice. The Watch firehose has no replay, so
        // seed the resume height from the CURRENT chain tip (not 0): a client
        // that lags before any block event is delivered — e.g. one that masks the
        // firehose off and only wants watch matches — would otherwise be handed a
        // resume_cursor of height 0 and re-replay from genesis on reconnect. The
        // mempool watermark still seeds from 0 (no live mempool seen yet).
        let lag_publisher = self.publisher.clone();
        let mut last_h = self
            .block_source
            .as_ref()
            .map(|s| s.current_tip_height())
            .unwrap_or(0);
        let mut last_s = 0u64;
        let live = BroadcastStream::new(rx_live).filter_map(move |item| match item {
            Ok(env) => {
                if (env.category_bit() & category_mask.load(Ordering::Relaxed)) == 0 {
                    return None;
                }
                last_s = env.stamp.seq;
                if let Some(c) = &env.cursor {
                    last_h = c.height;
                }
                Some(Ok(envelope_to_proto(&env)))
            }
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                warn!(target: "events::grpc", dropped = n, "Watch subscriber lagged (firehose)");
                let resume = lag_publisher.resume_cursor(last_h, last_s);
                let ev = node::events::lagged_event(&lag_publisher, n, resume);
                Some(Ok(envelope_to_proto(&ev)))
            }
        });
        // Single-shot terminal matches (depth alarm / lifecycle auto-close): the
        // registry already evicted the entry server-side on fire, so the
        // handle.remove_* below is an idempotent no-op registry-side — its job
        // here is to drop the carrier-held quota LEASE. Keyed by the threshold
        // the match carries.
        let evict_handle = handle.clone();
        let evict_ws = watch_set.clone();
        let matches = ReceiverStream::new(rx_match).map(move |m| {
            use node::events::WatchMatch;
            match &m {
                WatchMatch::TxidDepthReached { txid, depth, .. } => {
                    let mut ws = evict_ws.lock().unwrap_or_else(|p| p.into_inner());
                    ws.remove_tx_depths([(*txid, *depth)], |items| {
                        evict_handle.remove_tx_depths(items);
                    });
                }
                WatchMatch::TxidFinalized { txid, .. } => {
                    let mut ws = evict_ws.lock().unwrap_or_else(|p| p.into_inner());
                    ws.remove_transactions([*txid], |txids| {
                        evict_handle.remove_txids(txids);
                    });
                }
                _ => {}
            }
            Ok(watch_match_to_proto(&edge, &m))
        });

        // Hold `handle` + `sub_guard` alive for the lifetime of the outbound
        // stream (dropped on client disconnect → deregister + free slot).
        let merged = live.merge(matches).map(move |x| {
            let _keep_handle = &handle;
            let _keep_slot = &sub_guard;
            // Keep the watch-set (and its quota leases) alive for the
            // subscription's lifetime; it and the WatchHandle drop together
            // when the client disconnects.
            let _keep_watch_set = &watch_set;
            x
        });

        Ok(Response::new(Box::pin(merged)))
    }
}

/// Apply one `SubscribeControl` to a subscriber's watch-set. Watch additions
/// charge the per-token quota (N items = N units) via the [`WatchSet`], which
/// enforces the `stream:watch` capability, dedups against the live watch-set
/// (cross-message), and mints a per-item lease so a later remove frees exactly
/// that unit. A rejected add is logged and skipped without tearing down the
/// stream.
fn apply_control(
    ctrl: pb::SubscribeControl,
    handle: &node::events::WatchHandle,
    principal: Option<&satd_auth::Principal>,
    category_mask: &AtomicU32,
    watch_set: &mut WatchSet,
    prefix_bounds: (u8, u8),
) {
    use pb::subscribe_control::Msg;
    let (prefix_min_bits, prefix_max_bits) = prefix_bounds;
    match ctrl.msg {
        Some(Msg::AddOutpoints(a)) => {
            watch_set.add_outpoints(
                principal,
                a.outpoints.iter().filter_map(parse_outpoint),
                |ops| {
                    handle.add_outpoints(ops);
                },
            );
        }
        Some(Msg::AddScripts(a)) => {
            // Optional per-script `min_value` floors, parallel to `scripthashes`.
            // A non-empty list must match the scripthash count exactly; a
            // mismatch is a client protocol error — reject the whole add rather
            // than silently apply the wrong (or no) floors.
            if !a.min_values.is_empty() && a.min_values.len() != a.scripthashes.len() {
                warn!(
                    target: "events::grpc",
                    min_values = a.min_values.len(),
                    scripthashes = a.scripthashes.len(),
                    "AddScripts min_values length mismatch; ignoring add",
                );
            } else {
                // scripthash → floor (0 when no min_values given).
                let floors: std::collections::HashMap<[u8; 32], u64> = a
                    .scripthashes
                    .iter()
                    .enumerate()
                    .filter_map(|(i, b)| {
                        parse_scripthash(b).map(|sh| (sh, a.min_values.get(i).copied().unwrap_or(0)))
                    })
                    .collect();
                watch_set.add_scripts(
                    principal,
                    a.scripthashes.iter().filter_map(|b| parse_scripthash(b)),
                    "scripts",
                    |shs| {
                        let items: Vec<([u8; 32], u64)> = shs
                            .iter()
                            .map(|sh| (*sh, floors.get(sh).copied().unwrap_or(0)))
                            .collect();
                        handle.add_scripthashes_with_floors(&items);
                    },
                );
            }
        }
        Some(Msg::RemoveOutpoints(r)) => {
            watch_set.remove_outpoints(r.outpoints.iter().filter_map(parse_outpoint), |ops| {
                handle.remove_outpoints(ops);
            });
        }
        Some(Msg::RemoveScripts(r)) => {
            watch_set.remove_scripts(
                r.scripthashes.iter().filter_map(|b| parse_scripthash(b)),
                |shs| {
                    handle.remove_scripthashes(shs);
                },
            );
        }
        Some(Msg::AddTransactions(a)) => {
            let txids: Vec<bitcoin::Txid> = a.txids.iter().filter_map(|b| parse_txid(b)).collect();
            // Depths >= 1 only; 0 is meaningless as a confirmation threshold.
            let depths: Vec<u32> = a.min_depths.iter().copied().filter(|d| *d >= 1).collect();
            if depths.is_empty() {
                // Lifecycle watch(es); `auto_close_depth` rides on each (0 = off).
                let auto_close = a.auto_close_depth;
                watch_set.add_transactions(principal, txids, |txids| {
                    handle.add_txids(txids, auto_close);
                });
            } else if let Some(pairs) = bounded_txid_depth_pairs(&txids, &depths) {
                // Single-shot depth alarms — one item per (txid × distinct depth).
                watch_set.add_tx_depths(principal, pairs, |items| {
                    handle.add_tx_depths(items);
                });
            } else {
                warn!(
                    target: "events::grpc",
                    txids = txids.len(), depths = depths.len(),
                    "AddTransactions txid×depth product exceeds cap; rejecting message",
                );
            }
        }
        Some(Msg::RemoveTransactions(r)) => {
            let txids: Vec<bitcoin::Txid> = r.txids.iter().filter_map(|b| parse_txid(b)).collect();
            let depths: Vec<u32> = r.min_depths.iter().copied().filter(|d| *d >= 1).collect();
            if depths.is_empty() {
                watch_set.remove_transactions(txids, |txids| {
                    handle.remove_txids(txids);
                });
            } else if let Some(pairs) = bounded_txid_depth_pairs(&txids, &depths) {
                watch_set.remove_tx_depths(pairs, |items| {
                    handle.remove_tx_depths(items);
                });
            } else {
                warn!(
                    target: "events::grpc",
                    txids = txids.len(), depths = depths.len(),
                    "RemoveTransactions txid×depth product exceeds cap; rejecting message",
                );
            }
        }
        Some(Msg::AddDescriptor(d)) => {
            // Expand the descriptor over its [start, start+gap_limit) window and
            // watch it (rust-miniscript). Charges one unit per net-new script.
            // The client advances `start` to slide the window (gap-limit
            // tracking is client-side).
            match crate::descriptor::expand_descriptor(&d.descriptor, d.start, d.gap_limit) {
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
                    warn!(target: "events::grpc", error = %e, "ignoring invalid descriptor");
                }
            }
        }
        Some(Msg::AddScriptPrefixes(a)) => {
            // Validate + price each prefix; malformed or out-of-range buckets are
            // dropped (filter_map) before charging. Coarseness-priced quota.
            let items: Vec<((u8, u32), u64)> = a
                .prefixes
                .iter()
                .filter_map(|p| {
                    crate::watchset::parse_prefix(
                        &p.prefix,
                        p.bits,
                        prefix_min_bits,
                        prefix_max_bits,
                    )
                })
                .collect();
            watch_set.add_prefixes(principal, items, |keys| {
                handle.add_prefixes(keys);
            });
        }
        Some(Msg::RemoveScriptPrefixes(r)) => {
            let keys: Vec<(u8, u32)> = r
                .prefixes
                .iter()
                .filter_map(|p| {
                    crate::watchset::parse_prefix(
                        &p.prefix,
                        p.bits,
                        prefix_min_bits,
                        prefix_max_bits,
                    )
                    .map(|(key, _units)| key)
                })
                .collect();
            watch_set.remove_prefixes(keys, |keys| {
                handle.remove_prefixes(keys);
            });
        }
        Some(Msg::SetCategories(c)) => {
            let mask = if c.categories == 0 {
                u32::MAX
            } else {
                c.categories
            };
            category_mask.store(mask, Ordering::Relaxed);
        }
        Some(Msg::SetCursor(_)) => {
            warn!(
                target: "events::grpc",
                "SetCursor on the Watch stream is not served; use Subscribe(from_cursor) for replay",
            );
        }
        None => {}
    }
}

/// Parse a wire `Outpoint` (raw 32-byte txid + vout). Returns `None` for a
/// malformed txid length.
fn parse_outpoint(op: &pb::Outpoint) -> Option<bitcoin::OutPoint> {
    use bitcoin::hashes::Hash;
    if op.txid.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&op.txid);
    let txid =
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(bytes));
    Some(bitcoin::OutPoint {
        txid,
        vout: op.vout,
    })
}

/// Parse a 32-byte scripthash; `None` for a wrong length.
fn parse_scripthash(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() != 32 {
        return None;
    }
    let mut sh = [0u8; 32];
    sh.copy_from_slice(b);
    Some(sh)
}

/// Parse a raw 32-byte txid; `None` for a wrong length.
fn parse_txid(b: &[u8]) -> Option<bitcoin::Txid> {
    use bitcoin::hashes::Hash;
    if b.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(b);
    Some(bitcoin::Txid::from_raw_hash(
        bitcoin::hashes::sha256d::Hash::from_byte_array(bytes),
    ))
}

/// Convert a per-subscriber [`WatchMatch`](node::events::WatchMatch) into a
/// wire `NodeEvent`. Confirmed matches carry a `(height, 0)` cursor; the
/// stamp seq is 0 (matches are positioned by their identity, not the
/// volatile per-publisher seq).
fn watch_match_to_proto(
    edge: &node::events::EdgeIdentity,
    m: &node::events::WatchMatch,
) -> pb::NodeEvent {
    use bitcoin::hashes::Hash;
    use node::events::WatchMatch;
    let (cursor, body) = match m {
        WatchMatch::OutpointSpent {
            outpoint,
            spending_txid,
            spending_vin,
            confirmed,
            height,
        } => {
            let body = pb::node_event::Body::OutpointSpent(pb::OutpointSpent {
                outpoint_txid: outpoint.txid.as_raw_hash().to_byte_array().to_vec(),
                outpoint_vout: outpoint.vout,
                spending_txid: spending_txid.as_raw_hash().to_byte_array().to_vec(),
                spending_vin: *spending_vin,
                confirmed: *confirmed,
            });
            (cursor_from_height(*height, edge.instance_id), body)
        }
        WatchMatch::ScriptMatched {
            scripthash,
            txid,
            is_output,
            index,
            confirmed,
            height,
        } => {
            let body = pb::node_event::Body::ScriptMatched(pb::ScriptMatched {
                scripthash: scripthash.to_vec(),
                txid: txid.as_raw_hash().to_byte_array().to_vec(),
                is_output: *is_output,
                index: *index,
                confirmed: *confirmed,
            });
            (cursor_from_height(*height, edge.instance_id), body)
        }
        WatchMatch::TxidMatched {
            txid,
            confirmed,
            height,
        } => {
            let body = pb::node_event::Body::TxidMatched(pb::TxidMatched {
                txid: txid.as_raw_hash().to_byte_array().to_vec(),
                confirmed: *confirmed,
                height: height.unwrap_or(0),
            });
            (cursor_from_height(*height, edge.instance_id), body)
        }
        WatchMatch::TxidReplaced {
            txid,
            replacing_txid,
        } => {
            let body = pb::node_event::Body::TxidReplaced(pb::TxidReplaced {
                txid: txid.as_raw_hash().to_byte_array().to_vec(),
                replacing_txid: replacing_txid.as_raw_hash().to_byte_array().to_vec(),
            });
            (None, body)
        }
        WatchMatch::TxidEvicted { txid, reason } => {
            let body = pb::node_event::Body::TxidEvicted(pb::TxidEvicted {
                txid: txid.as_raw_hash().to_byte_array().to_vec(),
                reason: reason.as_str().to_string(),
            });
            (None, body)
        }
        WatchMatch::TxidUnconfirmed { txid, prev_height } => {
            let body = pb::node_event::Body::TxidUnconfirmed(pb::TxidUnconfirmed {
                txid: txid.as_raw_hash().to_byte_array().to_vec(),
                prev_height: *prev_height,
            });
            (None, body)
        }
        WatchMatch::TxidDepthReached {
            txid,
            depth,
            height,
        } => {
            let body = pb::node_event::Body::TxidDepthReached(pb::TxidDepthReached {
                txid: txid.as_raw_hash().to_byte_array().to_vec(),
                depth: *depth,
                height: *height,
            });
            (cursor_from_height(Some(*height), edge.instance_id), body)
        }
        WatchMatch::TxidFinalized {
            txid,
            depth,
            height,
        } => {
            let body = pb::node_event::Body::TxidFinalized(pb::TxidFinalized {
                txid: txid.as_raw_hash().to_byte_array().to_vec(),
                depth: *depth,
                height: *height,
            });
            (cursor_from_height(Some(*height), edge.instance_id), body)
        }
        WatchMatch::PrefixMatched(pm) => {
            let (masked, bits) = pm.prefix;
            let body = pb::node_event::Body::PrefixMatched(pb::PrefixMatched {
                prefix: Some(pb::ScriptPrefix {
                    prefix: prefix_wire_bytes(masked, bits),
                    bits: bits as u32,
                }),
                raw_tx: pm.raw_tx.to_vec(),
                confirmed: pm.confirmed,
                height: pm.height.unwrap_or(0),
                matched_prevouts: pm
                    .matched_prevouts
                    .iter()
                    .map(|(op, spk)| pb::SpentPrevout {
                        outpoint_txid: op.txid.as_raw_hash().to_byte_array().to_vec(),
                        outpoint_vout: op.vout,
                        script_pubkey: spk.to_bytes(),
                    })
                    .collect(),
            });
            (cursor_from_height(pm.height, edge.instance_id), body)
        }
    };
    pb::NodeEvent {
        schema_version: node::events::SCHEMA_VERSION,
        stamp: Some(replay_stamp(edge)),
        cursor,
        body: Some(body),
    }
}

fn cursor_from_height(height: Option<u32>, instance_id: u64) -> Option<pb::Cursor> {
    height.map(|h| pb::Cursor {
        height: h,
        tx_index: 0,
        mempool_seq: 0,
        instance_id,
    })
}

/// Render a bucket key back to wire form: the top `ceil(bits/8)` big-endian
/// bytes of the masked `u32` (low bits beyond `bits` are already zero). Inverse
/// of [`node::events::prefix_bucket_key`].
fn prefix_wire_bytes(masked: u32, bits: u8) -> Vec<u8> {
    let nbytes = (bits as usize).div_ceil(8);
    masked.to_be_bytes()[..nbytes.min(4)].to_vec()
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
        instance_id: c.instance_id,
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
        NodeEventBody::Lagged {
            dropped_count,
            resume_cursor,
        } => Body::Lagged(pb::Lagged {
            dropped_count: *dropped_count,
            resume_cursor: Some(cursor_to_proto(*resume_cursor)),
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
        Ch::Reorg {
            from_height,
            old_tip,
            to_height,
            new_tip,
        } => ChBody::Reorg(pb::Reorg {
            from_height: *from_height,
            old_tip: old_tip.as_raw_hash().to_byte_array().to_vec(),
            to_height: *to_height,
            new_tip: new_tip.as_raw_hash().to_byte_array().to_vec(),
        }),
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

    #[test]
    fn lifecycle_and_depth_watch_match_to_proto() {
        use bitcoin::hashes::Hash;
        use node::events::WatchMatch;
        let e = edge();
        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x11; 32]));
        let rep =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x22; 32]));

        let ev = watch_match_to_proto(
            &e,
            &WatchMatch::TxidReplaced {
                txid,
                replacing_txid: rep,
            },
        );
        match ev.body.unwrap() {
            pb::node_event::Body::TxidReplaced(r) => {
                assert_eq!(r.replacing_txid, [0x22; 32].to_vec());
            }
            other => panic!("wrong body: {other:?}"),
        }
        assert!(ev.cursor.is_none(), "replaced has no cursor");

        let ev = watch_match_to_proto(
            &e,
            &WatchMatch::TxidEvicted {
                txid,
                reason: node::mempool::events::EvictReason::Expiry,
            },
        );
        match ev.body.unwrap() {
            pb::node_event::Body::TxidEvicted(r) => assert_eq!(r.reason, "expiry"),
            other => panic!("wrong body: {other:?}"),
        }

        let ev = watch_match_to_proto(
            &e,
            &WatchMatch::TxidDepthReached {
                txid,
                depth: 3,
                height: 100,
            },
        );
        match ev.body.unwrap() {
            pb::node_event::Body::TxidDepthReached(r) => {
                assert_eq!(r.depth, 3);
                assert_eq!(r.height, 100);
            }
            other => panic!("wrong body: {other:?}"),
        }
        assert_eq!(ev.cursor.unwrap().height, 100, "depth match carries a cursor");

        let ev = watch_match_to_proto(
            &e,
            &WatchMatch::TxidFinalized {
                txid,
                depth: 6,
                height: 100,
            },
        );
        match ev.body.unwrap() {
            pb::node_event::Body::TxidFinalized(r) => assert_eq!(r.depth, 6),
            other => panic!("wrong body: {other:?}"),
        }
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
        match GrpcEventSink::bind("0.0.0.0:0", false, publisher, GrpcLimits::default(), None, None, None).await {
            Err(GrpcEventSinkError::RemoteBindRejected(_)) => {}
            Ok(_) => panic!("non-loopback bind without allow_remote should fail"),
            Err(e) => panic!("expected RemoteBindRejected, got {e}"),
        }
    }

    #[tokio::test]
    async fn bind_allows_loopback_without_override() {
        let publisher = EventPublisher::new(edge(), 16);
        let sink = GrpcEventSink::bind("127.0.0.1:0", false, publisher, GrpcLimits::default(), None, None, None)
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
        let sink = GrpcEventSink::bind("0.0.0.0:0", true, publisher, GrpcLimits::default(), None, None, None)
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
        let sink = GrpcEventSink::bind("127.0.0.1:0", false, publisher.clone(), GrpcLimits::default(), None, None, None)
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
                pb::node_event::Body::OutpointSpent(_) => "outpoint_spent",
                pb::node_event::Body::ScriptMatched(_) => "script_matched",
                pb::node_event::Body::DescriptorNeedsAddresses(_) => "descriptor_needs_addresses",
                pb::node_event::Body::Lagged(_) => "lagged",
                pb::node_event::Body::TxidMatched(_) => "txid_matched",
                pb::node_event::Body::TxidReplaced(_) => "txid_replaced",
                pb::node_event::Body::TxidEvicted(_) => "txid_evicted",
                pb::node_event::Body::TxidUnconfirmed(_) => "txid_unconfirmed",
                pb::node_event::Body::TxidDepthReached(_) => "txid_depth_reached",
                pb::node_event::Body::TxidFinalized(_) => "txid_finalized",
                pb::node_event::Body::PrefixMatched(_) => "prefix_matched",
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
            watch_registry: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
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
        fn active_chain_range(&self, from: u32, to: u32) -> Vec<(u32, BlockHash)> {
            let hi = to.min(self.tip);
            let lo = from.max(1);
            (lo..=hi)
                .map(|h| {
                    (
                        h,
                        BlockHash::from_raw_hash(
                            bitcoin::hashes::sha256d::Hash::from_byte_array([h as u8; 32]),
                        ),
                    )
                })
                .collect()
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
            watch_registry: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
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
                    // Chain-only / no-source replay: the mempool epoch token
                    // is immaterial here (see the dedicated instance-mismatch
                    // tests below for the mempool-side behavior).
                    instance_id: 0,
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
            watch_registry: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 2,
                since_seq: None,
                from_cursor: Some(pb::Cursor {
                    height: 4,
                    tx_index: 0,
                    mempool_seq: 0,
                    // Chain-only / no-source replay: the mempool epoch token
                    // is immaterial here (see the dedicated instance-mismatch
                    // tests below for the mempool-side behavior).
                    instance_id: 0,
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
            watch_registry: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
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
                    // Chain-only / no-source replay: the mempool epoch token
                    // is immaterial here (see the dedicated instance-mismatch
                    // tests below for the mempool-side behavior).
                    instance_id: 0,
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
            watch_registry: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
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
                    // Chain-only / no-source replay: the mempool epoch token
                    // is immaterial here (see the dedicated instance-mismatch
                    // tests below for the mempool-side behavior).
                    instance_id: 0,
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
            watch_registry: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        // Resume from mempool_seq = 1 on the SAME instance → replay seqs 2, 3.
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 1, // mempool only
                since_seq: None,
                from_cursor: Some(pb::Cursor {
                    height: 0,
                    tx_index: 0,
                    mempool_seq: 1,
                    instance_id: publisher.instance_id(),
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

    /// A `from_cursor` whose `instance_id` differs from the live publisher
    /// (the daemon restarted since the cursor was issued) discards the stale
    /// `mempool_seq` and replays the FULL retained mempool window — it must
    /// not trust a watermark indexing a dead `seq` space.
    #[tokio::test]
    async fn cursor_instance_mismatch_replays_full_mempool_window() {
        use tokio_stream::StreamExt as _;
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(64);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx);

        for i in 1..=3u8 {
            mp_tx.send(enter(i)).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        let svc = NodeEventStreamSvc {
            publisher: publisher.clone(),
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
            block_source: Some(Arc::new(MockBlocks { tip: 0 })),
            watch_registry: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        // Same mempool_seq=1 as the same-instance test, but a STALE instance
        // → epoch mismatch → discard the watermark → replay seqs 1, 2, 3.
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 1,
                since_seq: None,
                from_cursor: Some(pb::Cursor {
                    height: 0,
                    tx_index: 0,
                    mempool_seq: 1,
                    instance_id: publisher.instance_id().wrapping_add(1),
                }),
            }))
            .await
            .expect("subscribe");
        let mut stream = resp.into_inner();
        let mut seqs = Vec::new();
        for _ in 0..3 {
            let ev = tokio::time::timeout(Duration::from_secs(1), stream.next())
                .await
                .expect("mempool replay item ready")
                .unwrap()
                .unwrap();
            seqs.push(ev.stamp.unwrap().seq);
        }
        assert_eq!(
            seqs,
            vec![1, 2, 3],
            "instance mismatch must ignore the stale watermark and replay the full window",
        );
        let _ = shutdown_tx.send(true);
    }

    /// An instance mismatch resets only the MEMPOOL side; durable confirmed
    /// `(height)` replay is instance-independent and proceeds unchanged.
    #[tokio::test]
    async fn cursor_instance_mismatch_leaves_confirmed_replay_intact() {
        use tokio_stream::StreamExt as _;
        let publisher = EventPublisher::new(edge(), 64);
        let stale = publisher.instance_id().wrapping_add(1);
        let svc = NodeEventStreamSvc {
            publisher,
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
            block_source: Some(Arc::new(MockBlocks { tip: 5 })),
            watch_registry: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        // Stale instance_id, chain category → confirmed replay 3, 4, 5 anyway.
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 2,
                since_seq: None,
                from_cursor: Some(pb::Cursor {
                    height: 2,
                    tx_index: 0,
                    mempool_seq: 0,
                    instance_id: stale,
                }),
            }))
            .await
            .expect("subscribe");
        let mut stream = resp.into_inner();
        for expected in 3..=5u32 {
            let ev = tokio::time::timeout(Duration::from_secs(1), stream.next())
                .await
                .expect("replay item ready")
                .unwrap()
                .unwrap();
            assert_eq!(chain_height(&ev), Some(expected));
        }
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
            watch_registry: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 0,
                since_seq: None,
                from_cursor: Some(pb::Cursor {
                    height: 2,
                    tx_index: 0,
                    mempool_seq: 0,
                    // Chain-only / no-source replay: the mempool epoch token
                    // is immaterial here (see the dedicated instance-mismatch
                    // tests below for the mempool-side behavior).
                    instance_id: 0,
                }),
            }))
            .await
            .expect("subscribe ok even without a block source");
        let mut stream = resp.into_inner();
        // No replay, no live events → next() times out (stream is pending).
        let pending = tokio::time::timeout(Duration::from_millis(150), stream.next()).await;
        assert!(pending.is_err(), "forward-only stream should have no replay items");
    }

    /// When the subscriber falls behind the broadcast, the server emits an
    /// in-band `Lagged` notice (dropped count + a resume cursor stamped with
    /// the live instance) instead of silently dropping, and the stream
    /// continues.
    #[tokio::test]
    async fn lagged_emits_in_band_resume_cursor() {
        use tokio_stream::StreamExt as _;
        // Tiny broadcast capacity so a burst overflows the subscriber's queue.
        let publisher = EventPublisher::new(edge(), 4);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(128);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let svc = NodeEventStreamSvc {
            publisher: publisher.clone(),
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
            block_source: None,
            watch_registry: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        // Open the subscription first (its receiver is now live), then flood the
        // publisher far past the broadcast capacity before the stream is polled.
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 0,
                since_seq: None,
                from_cursor: None,
            }))
            .await
            .expect("subscribe");
        let mut stream = resp.into_inner();
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx);
        tokio::task::yield_now().await;
        for i in 0..100u8 {
            mp_tx.send(enter(i)).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Some events may arrive before the lag; scan for the in-band notice.
        let mut saw_lagged = false;
        for _ in 0..20 {
            let ev = tokio::time::timeout(Duration::from_secs(1), stream.next())
                .await
                .expect("item ready")
                .expect("stream open")
                .expect("ok");
            if let Some(pb::node_event::Body::Lagged(l)) = ev.body.as_ref() {
                assert!(l.dropped_count > 0, "dropped_count must be non-zero");
                let resume = l.resume_cursor.as_ref().expect("resume cursor present");
                assert_eq!(
                    resume.instance_id,
                    publisher.instance_id(),
                    "resume cursor carries the live instance",
                );
                saw_lagged = true;
                break;
            }
        }
        assert!(saw_lagged, "expected an in-band Lagged notice after overflow");
        let _ = shutdown_tx.send(true);
    }

    fn op_proto(byte: u8, vout: u32) -> pb::Outpoint {
        use bitcoin::hashes::Hash;
        pb::Outpoint {
            txid: bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32])
                .to_byte_array()
                .to_vec(),
            vout,
        }
    }

    /// `apply_control(AddOutpoints)` with no principal (auth disabled) adds
    /// the watch (loopback trust → unlimited).
    #[test]
    fn apply_control_no_auth_adds_outpoint() {
        let reg = Arc::new(node::events::WatchRegistry::new());
        let (handle, _rx) = reg.register(node::events::WATCH_CHANNEL_CAPACITY);
        let mask = AtomicU32::new(u32::MAX);
        let mut leases = WatchSet::default();
        apply_control(
            pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::AddOutpoints(pb::AddOutpoints {
                    outpoints: vec![op_proto(0xcd, 2)],
                })),
            },
            &handle,
            None,
            &mask,
            &mut leases,
            (8, 32),
        );
        assert!(reg.has_watchers());
    }

    /// A principal that holds `stream:subscribe` but not `stream:watch` is
    /// rejected by the quota gate: the watch is NOT added and no lease is
    /// taken — without tearing down the stream.
    #[test]
    fn apply_control_quota_rejects_without_stream_watch() {
        let store = auth_store(); // "sub" token has stream:subscribe only
        let principal = store
            .resolve(SUB_TOKEN, now_unix())
            .expect("resolve sub token");
        let reg = Arc::new(node::events::WatchRegistry::new());
        let (handle, _rx) = reg.register(node::events::WATCH_CHANNEL_CAPACITY);
        let mask = AtomicU32::new(u32::MAX);
        let mut leases = WatchSet::default();
        apply_control(
            pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::AddOutpoints(pb::AddOutpoints {
                    outpoints: vec![op_proto(0xab, 0)],
                })),
            },
            &handle,
            Some(&principal),
            &mask,
            &mut leases,
            (8, 32),
        );
        assert!(
            !reg.has_watchers(),
            "add must be rejected without stream:watch"
        );
        assert_eq!(leases.len(), 0, "no item added on a rejected add");
    }

    /// Regression (HIGH): watch-quota leases must be owned by the
    /// SUBSCRIPTION, not the inbound control reader. A client can half-close
    /// its control stream (END_STREAM) while keeping the response stream open;
    /// if the leases were dropped when the inbound task ended, the client's
    /// quota would be released while its watches stayed live — letting it
    /// register an unbounded watch-set at zero standing quota cost. This
    /// mirrors the handler's wiring: the lease vec is held behind an `Arc`
    /// shared by the inbound task and the outbound stream, so the quota is
    /// released only when the subscription itself is torn down.
    #[test]
    fn watch_quota_held_until_subscription_ends_not_on_control_half_close() {
        use satd_auth::{Accounting, Capability, CapabilitySet, LocalAccounting, Principal};
        let acct: Arc<dyn Accounting> = Arc::new(LocalAccounting::new());
        let principal = Principal::token(
            Arc::from("tenant"),
            CapabilitySet::EMPTY.with(Capability::StreamWatch),
            Some(2),
            None,
            acct.clone(),
        );
        let quota = acct.quota();

        let reg = Arc::new(node::events::WatchRegistry::new());
        let (handle, _rx) = reg.register(node::events::WATCH_CHANNEL_CAPACITY);
        let mask = AtomicU32::new(u32::MAX);

        // The subscription-scoped lease vec (held by the outbound stream).
        let leases: Arc<std::sync::Mutex<WatchSet>> =
            Arc::new(std::sync::Mutex::new(WatchSet::default()));
        // The inbound control reader holds a clone and charges quota into it.
        let inbound = leases.clone();
        {
            let mut guard = inbound.lock().unwrap();
            apply_control(
                pb::SubscribeControl {
                    msg: Some(pb::subscribe_control::Msg::AddOutpoints(pb::AddOutpoints {
                        outpoints: vec![op_proto(0x01, 0), op_proto(0x02, 0)],
                    })),
                },
                &handle,
                Some(&principal),
                &mask,
                &mut guard,
                (8, 32),
            );
        }
        assert_eq!(quota.current("tenant"), 2, "two watches charged 2 units");

        // Control stream half-closes → the inbound task ends and drops ITS
        // clone of the lease vec. Quota must NOT be released: the watches are
        // still live on the outbound stream.
        drop(inbound);
        assert_eq!(
            quota.current("tenant"),
            2,
            "half-closing the control stream must NOT release the watch quota",
        );

        // Subscription ends (client fully disconnects) → outbound drops the
        // last lease-vec reference, releasing the quota.
        drop(leases);
        assert_eq!(
            quota.current("tenant"),
            0,
            "full disconnect releases the watch quota",
        );
    }

    /// A single `AddOutpoints` message that repeats an entry is charged once
    /// per DISTINCT item, not per raw entry — the registry dedups on insert,
    /// so charging the raw count would overcharge the token's quota.
    #[test]
    fn duplicate_entries_in_one_add_charge_once() {
        use satd_auth::{Accounting, Capability, CapabilitySet, LocalAccounting, Principal};
        let acct: Arc<dyn Accounting> = Arc::new(LocalAccounting::new());
        let principal = Principal::token(
            Arc::from("tenant"),
            CapabilitySet::EMPTY.with(Capability::StreamWatch),
            Some(5),
            None,
            acct.clone(),
        );
        let reg = Arc::new(node::events::WatchRegistry::new());
        let (handle, _rx) = reg.register(node::events::WATCH_CHANNEL_CAPACITY);
        let mask = AtomicU32::new(u32::MAX);
        let mut leases = WatchSet::default();
        apply_control(
            pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::AddOutpoints(pb::AddOutpoints {
                    // Same outpoint three times → one distinct unit.
                    outpoints: vec![op_proto(0x07, 3), op_proto(0x07, 3), op_proto(0x07, 3)],
                })),
            },
            &handle,
            Some(&principal),
            &mask,
            &mut leases,
            (8, 32),
        );
        assert_eq!(
            acct.quota().current("tenant"),
            1,
            "a 3x-repeated entry charges a single distinct unit",
        );
    }

    /// Through the wire path (`apply_control`): a `RemoveOutpoints` releases
    /// exactly the removed item's quota unit (C1), and re-asserting a still-held
    /// outpoint in a later message is not double-charged (C2).
    #[test]
    fn apply_control_remove_releases_quota_and_cross_message_dedup() {
        use satd_auth::{Accounting, Capability, CapabilitySet, LocalAccounting, Principal};
        let acct: Arc<dyn Accounting> = Arc::new(LocalAccounting::new());
        let principal = Principal::token(
            Arc::from("tenant"),
            CapabilitySet::EMPTY.with(Capability::StreamWatch),
            Some(10),
            None,
            acct.clone(),
        );
        let q = acct.quota();
        let reg = Arc::new(node::events::WatchRegistry::new());
        let (handle, _rx) = reg.register(node::events::WATCH_CHANNEL_CAPACITY);
        let mask = AtomicU32::new(u32::MAX);
        let mut leases = WatchSet::default();

        let add = |ops: Vec<pb::Outpoint>| pb::SubscribeControl {
            msg: Some(pb::subscribe_control::Msg::AddOutpoints(pb::AddOutpoints {
                outpoints: ops,
            })),
        };

        // Add three distinct outpoints → 3 units.
        apply_control(
            add(vec![op_proto(1, 0), op_proto(2, 0), op_proto(3, 0)]),
            &handle,
            Some(&principal),
            &mask,
            &mut leases,
            (8, 32),
        );
        assert_eq!(q.current("tenant"), 3);

        // Re-assert op(1) in a SEPARATE message + add a new op(4): only op(4) is
        // net-new → charged once more (cross-message dedup).
        apply_control(
            add(vec![op_proto(1, 0), op_proto(4, 0)]),
            &handle,
            Some(&principal),
            &mask,
            &mut leases,
            (8, 32),
        );
        assert_eq!(q.current("tenant"), 4, "re-asserted op(1) not double-charged");

        // Remove op(2) → exactly one unit released (per-remove release).
        apply_control(
            pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::RemoveOutpoints(pb::RemoveOutpoints {
                    outpoints: vec![op_proto(2, 0)],
                })),
            },
            &handle,
            Some(&principal),
            &mask,
            &mut leases,
            (8, 32),
        );
        assert_eq!(q.current("tenant"), 3, "removing one watch frees one unit");
    }

    /// `apply_control(AddDescriptor)` expands the descriptor and registers
    /// the derived script window (no auth → unlimited).
    #[test]
    fn apply_control_add_descriptor_registers_window() {
        let reg = Arc::new(node::events::WatchRegistry::new());
        let (handle, _rx) = reg.register(node::events::WATCH_CHANNEL_CAPACITY);
        let mask = AtomicU32::new(u32::MAX);
        let mut leases = WatchSet::default();
        apply_control(
            pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::AddDescriptor(pb::AddDescriptor {
                    descriptor: "wpkh(xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/0/*)".into(),
                    gap_limit: 4,
                    start: 0,
                })),
            },
            &handle,
            None,
            &mask,
            &mut leases,
            (8, 32),
        );
        assert!(reg.has_watchers(), "descriptor expansion should register a watch-set");
    }

    /// End-to-end bidi `Watch`: a client adds an outpoint to its watch-set
    /// and receives the `OutpointSpent` event when the matcher reports a
    /// spend.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watch_delivers_outpoint_match() {
        use bitcoin::hashes::Hash;
        let publisher = EventPublisher::new(edge(), 64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let registry = Arc::new(node::events::WatchRegistry::new());
        let sink = GrpcEventSink::bind(
            "127.0.0.1:0",
            false,
            publisher.clone(),
            GrpcLimits::default(),
            None,
            None,
            Some(registry.clone()),
        )
        .await
        .expect("bind");
        let actual = sink.local_addr().unwrap();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client =
            pb::node_event_stream_client::NodeEventStreamClient::connect(format!(
                "http://{actual}"
            ))
            .await
            .expect("connect");

        let op = bitcoin::OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xcd; 32])),
            vout: 1,
        };
        let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel::<pb::SubscribeControl>(4);
        ctrl_tx
            .send(pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::AddOutpoints(pb::AddOutpoints {
                    outpoints: vec![op_proto(0xcd, 1)],
                })),
            })
            .await
            .unwrap();
        let mut stream = client
            .watch(ReceiverStream::new(ctrl_rx))
            .await
            .expect("watch")
            .into_inner();

        // Wait until the server applied the AddOutpoints control.
        let mut registered = false;
        for _ in 0..100 {
            if registry.has_watchers() {
                registered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(registered, "server should register the watch");

        // Simulate the matcher reporting a mempool spend of the watched
        // outpoint (in production `run_watch_matcher` calls this).
        let spend = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: op,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        registry.scan_mempool_tx(&spend);

        let ev = tokio::time::timeout(Duration::from_secs(3), stream.message())
            .await
            .expect("timeout")
            .expect("transport")
            .expect("stream ended");
        match ev.body.expect("body") {
            pb::node_event::Body::OutpointSpent(o) => {
                assert_eq!(o.outpoint_vout, 1);
                assert!(!o.confirmed, "mempool match is unconfirmed");
                assert_eq!(o.outpoint_txid.len(), 32);
            }
            other => panic!("expected OutpointSpent, got {other:?}"),
        }

        drop(ctrl_tx);
        let _ = shutdown_tx.send(true);
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
            watch_registry: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
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
