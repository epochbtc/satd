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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use async_trait::async_trait;
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

        // `since_seq` is a forward-only filter, NOT a replay hint. We
        // create a fresh broadcast::Receiver here, which only sees
        // events emitted strictly after this point — there is no
        // history rewind. We then drop everything with seq <= since_seq
        // before sending, so a client that briefly disconnects can
        // suppress already-seen duplicates if its old `seq` is still
        // close to the current one. Anything older has already passed
        // the publisher's broadcast window and cannot be recovered
        // through this RPC; clients needing durable replay should
        // consume from a broker upstream of this sink.
        let rx = self.publisher.subscribe();
        debug!(
            target: "events::grpc",
            categories = req.categories,
            since_seq,
            "events gRPC subscriber attached (forward-only; no replay)",
        );

        // `sub_guard` is moved into the stream closure so the subscription
        // slot is held for exactly as long as the stream lives; it is never
        // read, only kept alive (and dropped — decrementing the counter —
        // when the client disconnects or the server shuts down).
        let stream = BroadcastStream::new(rx).filter_map(move |item| {
            let _keep_slot = &sub_guard;
            match item {
                Ok(env) => {
                    if (env.category_bit() & category_mask) == 0 {
                        return None;
                    }
                    if since_seq > 0 && env.stamp.seq <= since_seq {
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

        Ok(Response::new(Box::pin(stream)))
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
        body: Some(body_to_proto(&env.body)),
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
        match GrpcEventSink::bind("0.0.0.0:0", false, publisher, GrpcLimits::default(), None).await {
            Err(GrpcEventSinkError::RemoteBindRejected(_)) => {}
            Ok(_) => panic!("non-loopback bind without allow_remote should fail"),
            Err(e) => panic!("expected RemoteBindRejected, got {e}"),
        }
    }

    #[tokio::test]
    async fn bind_allows_loopback_without_override() {
        let publisher = EventPublisher::new(edge(), 16);
        let sink = GrpcEventSink::bind("127.0.0.1:0", false, publisher, GrpcLimits::default(), None)
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
        let sink = GrpcEventSink::bind("0.0.0.0:0", true, publisher, GrpcLimits::default(), None)
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
        let sink = GrpcEventSink::bind("127.0.0.1:0", false, publisher.clone(), GrpcLimits::default(), None)
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
        };
        let mk = || {
            Request::new(pb::SubscribeRequest {
                categories: 0,
                since_seq: None,
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

    /// `max_subscriptions = 0` disables the cap entirely.
    #[tokio::test]
    async fn subscription_cap_disabled_when_zero() {
        let publisher = EventPublisher::new(edge(), 16);
        let svc = NodeEventStreamSvc {
            publisher,
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
        };
        let mut held = Vec::new();
        for _ in 0..16 {
            held.push(
                svc.subscribe(Request::new(pb::SubscribeRequest {
                    categories: 0,
                    since_seq: None,
                }))
                .await
                .expect("uncapped subscribe always ok"),
            );
        }
        // Counter stays at zero when the cap is disabled.
        assert_eq!(svc.active_subs.load(Ordering::Acquire), 0);
    }
}
