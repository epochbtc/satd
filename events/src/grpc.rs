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
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use async_trait::async_trait;
use node::events::{EventSink, NodeEvent, NodeEventBody};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc, watch};
use tokio_rustls::server::TlsStream;
use tokio_stream::Stream;
use tokio_stream::wrappers::{BroadcastStream, ReceiverStream, TcpListenerStream};
use tonic::transport::Server;
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info, warn};

/// HTTP/2 server keepalive: PING idle connections at this interval and reap any
/// that fail to respond within [`GRPC_KEEPALIVE_TIMEOUT`]. Without this, a dead
/// or half-open client (request stream still open, response abandoned) can pin a
/// `Watch` subscription's `WatchHandle` + quota leases indefinitely. Mirrors the
/// WS transport's ping/idle-timeout (`ws.rs`).
const GRPC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const GRPC_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// Aborts the wrapped task on drop. Ties the inbound control reader's lifetime to
/// the outbound subscription task: when the subscription tears down, the inbound
/// task is aborted rather than left parked on `message().await` holding a
/// `WatchHandle` clone (and, through it, the subscription's quota leases).
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

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
    #[error("events gRPC mTLS enabled without a client CA bundle (set the mTLS client CA)")]
    MtlsWithoutCa,
    #[error("failed to build events gRPC TLS acceptor: {0}")]
    TlsBuild(tls_config::TlsConfigError),
}

/// TLS parameters for the events gRPC listener, mirroring the RPC / Electrum /
/// Esplora surfaces (same `tls-config` plumbing). When passed to
/// [`GrpcEventSink::bind`], the bound listener terminates TLS in-process; the
/// acceptor is built — and the cert / key / CA validated — at bind time, so a
/// misconfiguration fails at startup rather than per-connection later.
#[derive(Debug, Clone)]
pub struct GrpcTlsParams {
    /// Server leaf certificate chain (PEM).
    pub cert_path: PathBuf,
    /// Server private key (PEM).
    pub key_path: PathBuf,
    /// Require and verify client certificates (mutual TLS).
    pub mtls_enabled: bool,
    /// CA bundle verifying client certs; required when `mtls_enabled`.
    pub mtls_client_ca: Option<PathBuf>,
    /// CN / DNS-SAN allowlist applied after a successful mTLS handshake; empty
    /// means "any cert the CA signed" (see [`tls_config::ClientAllowList`]).
    /// Only consulted when `mtls_enabled`.
    pub mtls_client_allow: Vec<String>,
    /// Per-connection TLS handshake timeout.
    pub handshake_timeout: Duration,
}

/// Built TLS runtime stored on the sink after [`GrpcEventSink::bind`]: a cheap-
/// to-clone acceptor plus the post-handshake mTLS allowlist gate.
struct TlsRuntime {
    acceptor: tokio_rustls::TlsAcceptor,
    allow: tls_config::ClientAllowList,
    mtls_enabled: bool,
    handshake_timeout: Duration,
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
    /// Full block-body + undo access for bounded historical rescan
    /// (`RescanBlocks` on the `Watch` stream). `Some` when a chain source is
    /// wired (production); `None` disables rescan (a `RescanBlocks` is then
    /// rejected `NO_SOURCE`). Like `block_source`, never on the consensus hot
    /// path — it reads blocks the node already holds.
    scan_source: Option<std::sync::Arc<dyn node::events::BlockScanSource>>,
    /// Live outpoint/script watch registry backing the bidirectional
    /// `Watch` RPC. `None` disables `Watch` (returns `UNAVAILABLE`).
    watch_registry: Option<std::sync::Arc<node::events::WatchRegistry>>,
    /// Silent-payment tweak index read handle for the `tweaks` firehose
    /// category. `Some` when `silentpaymentindex=1`; `None` disables the
    /// category (a `tweaks` subscription is rejected in-band). Backs
    /// index-point-lookup cursor replay and the deep-replay-exemption
    /// completeness gate. Read-only; never on the consensus hot path.
    tweak_source: Option<std::sync::Arc<dyn node::index::silent_payments::SpIndex>>,
    /// In-process TLS termination, `Some` when an events-gRPC TLS cert/key are
    /// configured. When present, each accepted connection is TLS-handshaked
    /// (and mTLS-verified) before tonic serves it.
    tls: Option<TlsRuntime>,
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
    /// By default the server is unencrypted and only loopback bindings are
    /// accepted; pass `allow_remote = true` to bind a routable address (which
    /// the operator should put behind a firewall, TLS terminator, or auth
    /// proxy). Pass `tls = Some(..)` to terminate TLS (and optionally mTLS)
    /// in-process — the acceptor is built here so a bad cert/key/CA fails at
    /// startup.
    ///
    /// The `publisher` handle is needed so each incoming subscriber can
    /// register its own broadcast receiver — sharing the
    /// [`EventSink::run`] receiver across N clients would force each
    /// client to serialize through a single channel.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind(
        bind: &str,
        allow_remote: bool,
        publisher: std::sync::Arc<node::events::EventPublisher>,
        limits: GrpcLimits,
        auth: Option<std::sync::Arc<satd_auth::TokenStore>>,
        block_source: Option<std::sync::Arc<dyn node::events::BlockCursorSource>>,
        scan_source: Option<std::sync::Arc<dyn node::events::BlockScanSource>>,
        watch_registry: Option<std::sync::Arc<node::events::WatchRegistry>>,
        tweak_source: Option<std::sync::Arc<dyn node::index::silent_payments::SpIndex>>,
        tls: Option<GrpcTlsParams>,
    ) -> Result<Self, GrpcEventSinkError> {
        let addr: SocketAddr = bind
            .parse()
            .map_err(|e| GrpcEventSinkError::InvalidBind(bind.to_string(), e))?;
        if !allow_remote && !is_loopback(&addr.ip()) {
            return Err(GrpcEventSinkError::RemoteBindRejected(addr));
        }
        // Build the TLS acceptor up front so a misconfigured cert/key/CA is a
        // startup error, not a per-connection surprise.
        let tls = match tls {
            Some(params) => {
                let policy = if params.mtls_enabled {
                    let ca = params
                        .mtls_client_ca
                        .as_ref()
                        .ok_or(GrpcEventSinkError::MtlsWithoutCa)?;
                    tls_config::ClientAuthPolicy::Required { ca_path: ca.clone() }
                } else {
                    tls_config::ClientAuthPolicy::Disabled
                };
                let acceptor =
                    tls_config::build_acceptor(&params.cert_path, &params.key_path, &policy)
                        .map_err(GrpcEventSinkError::TlsBuild)?;
                Some(TlsRuntime {
                    acceptor,
                    allow: tls_config::ClientAllowList::new(params.mtls_client_allow),
                    mtls_enabled: params.mtls_enabled,
                    handshake_timeout: params.handshake_timeout,
                })
            }
            None => None,
        };
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| GrpcEventSinkError::BindFailed(addr, e))?;
        let bound = listener.local_addr().unwrap_or(addr);
        info!(
            target: "events::grpc",
            addr = %bound,
            allow_remote,
            tls = tls.is_some(),
            mtls = tls.as_ref().map(|t| t.mtls_enabled).unwrap_or(false),
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
            scan_source,
            watch_registry,
            tweak_source,
            tls,
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
            scan_source: self.scan_source.clone(),
            watch_registry: self.watch_registry.clone(),
            tweak_source: self.tweak_source.clone(),
            prefix_min_bits: self.limits.prefix_min_bits,
            prefix_max_bits: self.limits.prefix_max_bits,
        };
        info!(target: "events::grpc", addr = %self.addr, "events gRPC server starting");
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
        let listener = self.listener;
        // Tracks the detached TLS accept-loop task so `run` can abort it on
        // return (see the backstop after `serve`). `None` on the plaintext path,
        // where tonic owns the listener and stops accepting on shutdown.
        let mut tls_accept: Option<tokio::task::JoinHandle<()>> = None;
        // Unify the plaintext and TLS paths behind one `EventsConn` incoming
        // stream so the serve block below is transport-agnostic.
        let incoming: Pin<Box<dyn Stream<Item = Result<EventsConn, std::io::Error>> + Send>> =
            if let Some(tls) = self.tls {
                // TLS: terminate each accepted connection in its own task so a
                // slow or stalled handshake can't wedge `accept` for everyone,
                // then forward completed (and mTLS-verified) streams to tonic
                // over a bounded channel. The connection-cap permit is acquired
                // at accept and rides the connection to release on drop.
                let (tx, rx) = mpsc::channel::<Result<EventsConn, std::io::Error>>(16);
                let tls = Arc::new(tls);
                let mut shutdown_accept = shutdown.clone();
                tls_accept = Some(tokio::spawn(async move {
                    let mut tcp = TcpListenerStream::new(listener);
                    loop {
                        // Stop accepting promptly on shutdown so this detached
                        // task can't outlive `run`. (The plaintext path's
                        // listener is owned by tonic and stops on shutdown; this
                        // one needs an explicit signal — without it the loop would
                        // busy-accept forever after graceful shutdown.)
                        let res = tokio::select! {
                            biased;
                            _ = shutdown_accept.changed() => break,
                            next = tcp.next() => match next {
                                Some(r) => r,
                                None => break,
                            },
                        };
                        let stream = match res {
                            Ok(s) => s,
                            Err(e) => {
                                // Don't tight-loop on a persistent accept error
                                // (e.g. EMFILE fd exhaustion): log and briefly
                                // back off. The plaintext path surfaces accept
                                // errors to tonic; here we keep the loop alive but
                                // visible rather than spinning a core silently.
                                debug!(
                                    target: "events::grpc",
                                    error = %e,
                                    "events gRPC TCP accept error (backing off)",
                                );
                                tokio::time::sleep(Duration::from_millis(5)).await;
                                continue;
                            }
                        };
                        let permit = match &conn_sem {
                            Some(sem) => match sem.clone().try_acquire_owned() {
                                Ok(p) => Some(p),
                                Err(_) => {
                                    warn!(
                                        target: "events::grpc",
                                        max_conns,
                                        "events gRPC at-capacity rejection (dropping connection)",
                                    );
                                    continue;
                                }
                            },
                            None => None,
                        };
                        let peer = stream.peer_addr().ok();
                        let tls = tls.clone();
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let tls_stream = match tokio::time::timeout(
                                tls.handshake_timeout,
                                tls.acceptor.accept(stream),
                            )
                            .await
                            {
                                Ok(Ok(s)) => s,
                                Ok(Err(e)) => {
                                    debug!(
                                        target: "events::grpc",
                                        peer = ?peer,
                                        error = %e,
                                        "events gRPC TLS handshake failed",
                                    );
                                    return;
                                }
                                Err(_) => {
                                    warn!(
                                        target: "events::grpc",
                                        peer = ?peer,
                                        timeout_secs = tls.handshake_timeout.as_secs(),
                                        "events gRPC TLS handshake timed out — dropping connection",
                                    );
                                    return;
                                }
                            };
                            // mTLS post-handshake hooks (audit log + CN/SAN
                            // allowlist) only run when mTLS is enabled — without a
                            // client cert there is nothing to check.
                            if tls.mtls_enabled {
                                let (_, server_conn) = tls_stream.get_ref();
                                // Audit every accepted mTLS client — including a
                                // CA-signed cert with no usable CN/DNS-SAN, which
                                // would otherwise be accepted with no log line.
                                let subject = tls_config::peer_subject_label(server_conn)
                                    .unwrap_or_else(|| "<unknown>".to_string());
                                info!(
                                    target: "events::grpc",
                                    peer = ?peer,
                                    subject = %subject,
                                    "events gRPC mTLS client accepted",
                                );
                                if let Err(rej) =
                                    tls_config::check_peer_allowed(server_conn, &tls.allow)
                                {
                                    warn!(
                                        target: "events::grpc",
                                        peer = ?peer,
                                        subject = %rej.subject_label,
                                        "events gRPC mTLS client rejected by allowlist",
                                    );
                                    return;
                                }
                            }
                            // Receiver gone (server shutting down) → drop the
                            // stream; the permit releases with it.
                            let _ = tx
                                .send(Ok(EventsConn::Tls(Box::new(PermittedTls {
                                    inner: tls_stream,
                                    _permit: permit,
                                }))))
                                .await;
                        });
                    }
                }));
                Box::pin(ReceiverStream::new(rx))
            } else {
                Box::pin(TcpListenerStream::new(listener).filter_map(move |res| match res {
                    Ok(stream) => match &conn_sem {
                        Some(sem) => match sem.clone().try_acquire_owned() {
                            Ok(permit) => Some(Ok(EventsConn::Plain(PermittedTcp {
                                inner: stream,
                                _permit: Some(permit),
                            }))),
                            Err(_) => {
                                warn!(
                                    target: "events::grpc",
                                    max_conns,
                                    "events gRPC at-capacity rejection (dropping connection)",
                                );
                                None
                            }
                        },
                        None => Some(Ok(EventsConn::Plain(PermittedTcp {
                            inner: stream,
                            _permit: None,
                        }))),
                    },
                    Err(e) => Some(Err(e)),
                }))
            };
        // When auth is configured, wrap the service in a tonic interceptor that
        // rejects any Subscribe without a valid bearer token holding
        // stream:subscribe (and stashes the principal in the request extensions
        // for the handler / future per-principal quota). The loopback +
        // allow_remote gate in `bind()` stays as a transport pre-check beneath
        // this app-layer auth.
        let shutdown_signal = async move {
            let _ = shutdown.changed().await;
        };
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
                .http2_keepalive_interval(Some(GRPC_KEEPALIVE_INTERVAL))
                .http2_keepalive_timeout(Some(GRPC_KEEPALIVE_TIMEOUT))
                .add_service(NodeEventStreamServer::with_interceptor(svc_impl, interceptor))
                .serve_with_incoming_shutdown(incoming, shutdown_signal)
                .await
        } else {
            Server::builder()
                .http2_keepalive_interval(Some(GRPC_KEEPALIVE_INTERVAL))
                .http2_keepalive_timeout(Some(GRPC_KEEPALIVE_TIMEOUT))
                .add_service(NodeEventStreamServer::new(svc_impl))
                .serve_with_incoming_shutdown(incoming, shutdown_signal)
                .await
        };
        if let Err(e) = result {
            warn!(target: "events::grpc", error = %e, "events gRPC server exited with error");
        }
        // Backstop: tear down the detached TLS accept loop when `run` returns for
        // any reason. The `select!` above already breaks it on graceful shutdown;
        // this also covers a serve error where the shutdown watch never fires.
        // A no-op on the plaintext path (`tls_accept` is `None`).
        if let Some(handle) = tls_accept {
            handle.abort();
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
    /// Full block-body + undo access for bounded historical rescan; `None`
    /// disables rescan (`RescanBlocks` → `NO_SOURCE`).
    scan_source: Option<std::sync::Arc<dyn node::events::BlockScanSource>>,
    /// Live watch registry backing the `Watch` RPC; `None` disables it.
    watch_registry: Option<std::sync::Arc<node::events::WatchRegistry>>,
    /// Silent-payment tweak index read handle for the `tweaks` firehose
    /// category; `None` disables it (a `tweaks` subscription is rejected).
    tweak_source: Option<std::sync::Arc<dyn node::index::silent_payments::SpIndex>>,
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

/// A TLS-terminated connection carrying an owned connection-cap permit.
/// Delegates I/O to the inner `TlsStream`; the permit releases when this is
/// dropped (tonic finished serving). `Connected` reports the underlying TCP
/// peer so tonic's `remote_addr` works exactly as on the plaintext path.
struct PermittedTls {
    inner: TlsStream<tokio::net::TcpStream>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl AsyncRead for PermittedTls {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PermittedTls {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
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

impl Connected for PermittedTls {
    type ConnectInfo = <tokio::net::TcpStream as Connected>::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        // `get_ref().0` is the inner `TcpStream`; reuse tonic's TCP connect-info.
        self.inner.get_ref().0.connect_info()
    }
}

/// A connection handed to tonic's `serve_with_incoming`: either a plaintext TCP
/// stream or a TLS-terminated one. Delegates I/O to the active variant; both
/// report the peer TCP `ConnectInfo`.
enum EventsConn {
    Plain(PermittedTcp),
    // Boxed: `TlsStream` is large, so an unboxed variant would bloat every
    // `EventsConn` (clippy::large_enum_variant).
    Tls(Box<PermittedTls>),
}

impl AsyncRead for EventsConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            EventsConn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            EventsConn::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for EventsConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            EventsConn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            EventsConn::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            EventsConn::Plain(s) => Pin::new(s).poll_flush(cx),
            EventsConn::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            EventsConn::Plain(s) => Pin::new(s).poll_shutdown(cx),
            EventsConn::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            EventsConn::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            EventsConn::Tls(s) => Pin::new(s.as_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            EventsConn::Plain(s) => s.is_write_vectored(),
            EventsConn::Tls(s) => s.is_write_vectored(),
        }
    }
}

impl Connected for EventsConn {
    type ConnectInfo = <tokio::net::TcpStream as Connected>::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        match self {
            EventsConn::Plain(s) => s.connect_info(),
            EventsConn::Tls(s) => s.connect_info(),
        }
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
        // heartbeat=4, tweaks=8). Unknown bits are silently ignored: a future
        // server may add new categories without forcing older clients
        // to upgrade. We could `return Err(invalid_argument)` if the
        // mask covers no known bit, but that would also reject the
        // legitimate "subscribe to a category my server doesn't know
        // about yet" case during a rolling upgrade — easier to log
        // and let the stream be empty. `tweaks` is excluded from the "all"
        // default (see `ALL_CATEGORIES_DEFAULT`): a legacy `0`-subscriber must
        // never begin receiving tweak volume after a node upgrade.
        let category_mask = if req.categories == 0 {
            node::events::ALL_CATEGORIES_DEFAULT
        } else {
            req.categories
        };
        let since_seq = req.since_seq.unwrap_or(0);

        // Silent-payment `tweaks` category (bit 8) is explicit-request only and
        // requires the tweak index. Reject in-band before attaching a receiver:
        //   * index disabled  → the category cannot be served at all;
        //   * replay requested (`from_cursor`) against an incomplete index →
        //     historical tweaks below the backfill frontier are missing, and
        //     silently serving a clamped window would make a light client miss
        //     payments. Refuse until the index is complete.
        // `tweak_source` is threaded to the replay builder only when the client
        // actually asked for tweaks.
        let wants_tweaks = category_mask & node::events::CATEGORY_TWEAKS != 0;
        let tweak_source = if wants_tweaks {
            self.tweak_source.clone()
        } else {
            None
        };
        if wants_tweaks {
            match &tweak_source {
                None => {
                    debug!(target: "events::grpc", code = "failed_precondition", "rejecting Subscribe: tweaks category requires silentpaymentindex=1");
                    return Err(Status::failed_precondition(
                        "the tweaks category requires silentpaymentindex=1",
                    ));
                }
                Some(sp) if req.from_cursor.is_some() && !sp.is_complete() => {
                    debug!(target: "events::grpc", code = "failed_precondition", "rejecting Subscribe: tweak replay requested while index still backfilling");
                    return Err(Status::failed_precondition(
                        "silent payment index is still backfilling; tweak replay is \
                         unavailable until it is complete",
                    ));
                }
                Some(_) => {}
            }
        }
        // Keep the tweak-subscriber count raised for the stream's lifetime so
        // the chain bridge emits live `BlockTweaks` while we are listening.
        // Held (never read) inside the live stream closure, dropped on
        // disconnect. Per-subscription tweak filters: `dust_limit` drops
        // entries below a value floor; `tweaks_only` strips txid/max_value.
        let tweak_sub_guard = wants_tweaks.then(|| self.publisher.tweak_subscriber_guard());
        let tweak_dust_limit = req.tweak_dust_limit.unwrap_or(0);
        let tweaks_only = req.tweaks_only.unwrap_or(false);

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
                        tweak_source.as_deref(),
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
            // A deep tweaks-only cold-sync streams `[start, end]` through a
            // separate stream that bypasses the live closure below, so `last_h`
            // would otherwise still point at the request cursor for the whole
            // multi-minute read. Seed it to the deep tail: if the client lags
            // right after the cold-sync (the slow-phone case this feature is
            // built for), the `Lagged` resume cursor then points at `end`, not
            // ~taproot activation — resuming from activation would re-run the
            // entire ~240k-block cold-sync and can livelock.
            if let Some((_, end)) = r.deep_tweak_range {
                last_h = end.max(last_h);
            }
        }

        // `sub_guard` is moved into the live stream closure so the
        // subscription slot is held for exactly as long as the (combined)
        // stream lives; it is never read, only kept alive (and dropped —
        // decrementing the counter — when the client disconnects or the
        // server shuts down).
        let live = BroadcastStream::new(rx).filter_map(move |item| {
            let _keep_slot = &sub_guard;
            // Held for the stream's lifetime so the chain bridge keeps emitting
            // live tweak events while this subscriber is attached.
            let _keep_tweak_slot = &tweak_sub_guard;
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
                    Some(Ok(envelope_to_proto_sp(&env, tweak_dust_limit, tweaks_only)))
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
                let replay_events = tokio_stream::iter(
                    r.events
                        .into_iter()
                        .map(move |e| Ok(envelope_to_proto_sp(&e, tweak_dust_limit, tweaks_only))),
                );
                // A tweaks-only deep-replay exemption defers its (possibly
                // whole-taproot-era) span to here rather than materializing it
                // in the builder. Page it lazily off the index with
                // backpressure so peak memory is bounded and no async worker is
                // ever blocked on the multi-minute read.
                //
                // A block that connects in the race window between `rx =
                // subscribe()` and the snapshot tip is both read by the deep
                // pager (height <= snapshot_tip) and buffered live, so its
                // `BlockTweaks` can be delivered twice at the seam (bounded to
                // the 1-2 blocks in that window). This duplicate is deliberate:
                // it is the safe failure mode. A blanket "drop live tweaks at
                // height <= snapshot_tip" would instead lose a block's tweaks if
                // a reorg replaced it mid-cold-sync (the live re-emit carries the
                // post-reorg tweaks the already-passed pager did not). Scanning
                // clients re-derive candidates idempotently, so a repeated
                // BlockTweaks costs a re-scan, never a wrong result.
                match (r.deep_tweak_range, tweak_source) {
                    (Some((start, end)), Some(sp)) => {
                        let deep = deep_tweak_replay_stream(
                            sp,
                            self.publisher.clone(),
                            start,
                            end,
                            tweak_dust_limit,
                            tweaks_only,
                        );
                        Box::pin(replay_events.chain(deep).chain(live))
                    }
                    _ => Box::pin(replay_events.chain(live)),
                }
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
        // Excludes the explicit-only `tweaks` bit from the "all" default, so a
        // `Watch` subscriber never receives `BlockTweaks` unless it asks (the
        // tweak firehose is a `Subscribe`-side category).
        let category_mask = Arc::new(AtomicU32::new(node::events::ALL_CATEGORIES_DEFAULT));
        // Per-stream raw-tx opt-in (SetWatchOptions). The inbound reader flips
        // it (and the registry gate counter); the outbound encoder reads it to
        // decide whether to inline raw_tx on this connection's ScriptMatched.
        let include_raw_tx = Arc::new(AtomicBool::new(false));
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

        // Mid-stream re-anchor channel (§7.3.1): a `SetCursor` on the inbound
        // control stream hands its cursor to the outbound task, which drains a
        // confirmed-history replay ahead of the live tail.
        let (reanchor_tx, reanchor_rx) = tokio::sync::mpsc::channel::<node::events::Cursor>(1);

        // "A re-anchor is in flight" — set by the inbound reader when it queues a
        // cursor, cleared by the outbound task only after the replay has fully
        // drained. The capacity-1 channel alone does NOT bound this: `recv()`
        // empties it at the *start* of the drain, so a `SetCursor` arriving
        // during a long replay would be queued and serviced late rather than
        // rejected. This flag spans the whole in-flight window (queue → drain →
        // done), so a concurrent `SetCursor` is rejected `ConcurrentReanchor`
        // for the entire duration, bounding outstanding replay work to one.
        let reanchor_in_flight = Arc::new(AtomicBool::new(false));

        // Re-anchor rejection channel (#439): a `SetCursor` the inbound reader
        // declines (rate-limited, an empty cursor, or a re-anchor already in
        // flight) hands its reason to the outbound task, which renders a
        // deterministic `SetCursorResult::Rejected` in-band so the client can
        // tell "ignored" from "accepted, replaying". The outbound task owns the
        // accurate `current_head` (last position it delivered), so the reason is
        // routed there rather than emitted from inbound.
        //
        // The contract is "exactly one SetCursorResult per actionable SetCursor",
        // so this MUST NOT silently drop. The outbound task only services this
        // channel between drains (a long replay holds it off), so under a burst
        // of declined SetCursors it can fill. Inbound therefore *blocks* on a
        // full channel (`send().await`, not `try_send`): the surplus backpressures
        // the client's control stream (h2 flow control) until the outbound task
        // catches up, rather than being shed. A rejection is lost only if the
        // outbound task is already gone (client disconnected) — nothing to
        // deliver to. The buffer (32) absorbs normal bursts before backpressure.
        let (reject_tx, reject_rx) =
            tokio::sync::mpsc::channel::<node::events::CursorRejectReason>(32);

        // Deterministic result of an atomic SetWatchSet replace, handed from the
        // inbound reader (which applies it under the watch-set lock) to the
        // outbound task (which emits the in-band WatchSetResult). Same bridge
        // shape as the SetCursor rejection channel.
        let (ws_result_tx, mut ws_result_rx) =
            tokio::sync::mpsc::channel::<crate::watchset::ReplaceOutcome>(32);

        // Bounded historical rescan (§6.1): a `RescanBlocks` on the inbound
        // control stream hands its (from, to) range to the outbound task, which
        // runs the watch-set matcher over the range and drains the matches ahead
        // of resuming live. Same bridge shape as the SetCursor re-anchor.
        let (rescan_tx, rescan_rx) = tokio::sync::mpsc::channel::<(u32, u32)>(1);
        // "A rescan is in flight" — set by the inbound reader when it queues a
        // range, cleared by the outbound task once the scan fully drains. Spans
        // queue→drain so a concurrent RescanBlocks is rejected for the whole
        // window (the capacity-1 channel alone does not — recv empties it at the
        // start of the drain). Independent of the re-anchor in-flight slot: a
        // rescan is a side query and may run alongside a re-anchor.
        let rescan_in_flight = Arc::new(AtomicBool::new(false));
        // Rescan rejection channel: a `RescanBlocks` the inbound reader declines
        // (rate-limited, or a rescan already in flight) hands its reason to the
        // outbound task for a deterministic `RescanResult{Rejected}`. Same
        // backpressure contract as the SetCursor reject channel (blocks on full,
        // never drops — "exactly one RescanResult per actionable RescanBlocks").
        let (rescan_reject_tx, rescan_reject_rx) =
            tokio::sync::mpsc::channel::<node::events::RescanRejectReason>(32);

        // Inbound control reader: applies watch-set mutations + category
        // changes for the life of the stream against the shared subscription-
        // scoped watch-set, and holds a handle clone so the subscription is
        // retained while either side is alive.
        let inbound_task = {
            let handle = handle.clone();
            let category_mask = category_mask.clone();
            let include_raw_tx = include_raw_tx.clone();
            let watch_set = watch_set.clone();
            let reanchor_in_flight = reanchor_in_flight.clone();
            let prefix_bounds = (self.prefix_min_bits, self.prefix_max_bits);
            let ws_result_tx = ws_result_tx;
            let rescan_in_flight = rescan_in_flight.clone();
            let rescan_tx = rescan_tx;
            let rescan_reject_tx = rescan_reject_tx;
            tokio::spawn(async move {
                use node::events::CursorRejectReason;
                use node::events::RescanRejectReason;
                // Hand a deterministic rejection to the outbound task. BLOCKS when
                // the channel is full (backpressuring the client's control stream)
                // rather than dropping — a silently-lost rejection is the exact bug
                // this path exists to kill. An `Err` means the outbound task is
                // gone (stream tearing down); there is nothing to deliver, so it is
                // ignored. (`async` closures are unstable, so this is a small
                // async fn over a borrowed sender.)
                async fn reject(
                    tx: &tokio::sync::mpsc::Sender<CursorRejectReason>,
                    reason: CursorRejectReason,
                ) {
                    let _ = tx.send(reason).await;
                }
                // Rescan twin of `reject`: hand a deterministic rescan rejection
                // to the outbound task, blocking on a full channel (backpressure)
                // rather than dropping. `Err` = outbound gone; ignored.
                async fn rescan_reject(
                    tx: &tokio::sync::mpsc::Sender<RescanRejectReason>,
                    reason: RescanRejectReason,
                ) {
                    let _ = tx.send(reason).await;
                }
                while let Ok(Some(ctrl)) = inbound.message().await {
                    // `SetCursor` is a mid-stream re-anchor, not a watch-set
                    // mutation: forward its cursor to the outbound task (or a
                    // rejection reason if it cannot be admitted) instead of
                    // applying it.
                    if let Some(pb::subscribe_control::Msg::SetCursor(sc)) = &ctrl.msg {
                        let Some(c) = &sc.cursor else {
                            // Malformed empty SetCursor: spends no rate token, but
                            // the client still gets a deterministic rejection.
                            reject(&reject_tx, CursorRejectReason::EmptyCursor).await;
                            continue;
                        };
                        // A re-anchor drives a confirmed-history replay (up to
                        // MAX_REPLAY_BLOCKS block-index reads + event synthesis).
                        // The capacity-1 channel bounds only *concurrent*
                        // re-anchors; rate-limit per-principal here so a client
                        // cannot fire back-to-back SetCursors in a tight loop and
                        // pin a worker re-walking the block index. Operator/
                        // loopback/no-policy principals bypass (check_rate →
                        // Allow), same posture as Subscribe establishment and
                        // watch-set adds. Charged only when there is an actionable
                        // cursor.
                        if let Some(p) = principal.as_ref()
                            && let satd_auth::RateDecision::Throttle { retry_after_secs } =
                                p.check_rate()
                        {
                            debug!(
                                target: "events::grpc",
                                retry_after_secs,
                                "rejecting mid-stream SetCursor re-anchor: per-principal rate limit exceeded",
                            );
                            reject(&reject_tx, CursorRejectReason::RateLimited).await;
                            continue;
                        }
                        let cur = node::events::Cursor {
                            height: c.height,
                            tx_index: c.tx_index,
                            mempool_seq: c.mempool_seq,
                            instance_id: c.instance_id,
                        };
                        // Claim the single in-flight slot. `swap` returning `true`
                        // means a re-anchor is already in flight (queued OR
                        // actively draining) → reject ConcurrentReanchor. This
                        // covers the whole drain, which the capacity-1 channel
                        // alone does not (recv empties it before the drain). The
                        // outbound task clears the flag once the replay completes.
                        if reanchor_in_flight.swap(true, Ordering::AcqRel) {
                            reject(&reject_tx, CursorRejectReason::ConcurrentReanchor).await;
                            continue;
                        }
                        // We own the slot, so the capacity-1 channel is empty: a
                        // send error here can only be `Closed` (outbound gone,
                        // stream tearing down). Release the slot in that case.
                        if reanchor_tx.try_send(cur).is_err() {
                            reanchor_in_flight.store(false, Ordering::Release);
                        }
                        continue;
                    }
                    // SetWatchSet is an atomic replace whose deterministic
                    // WatchSetResult must reach the outbound task; apply it under
                    // the lock, then forward the outcome (mirrors SetCursor). The
                    // guard is scoped so it drops before the `.await` below.
                    if let Some(pb::subscribe_control::Msg::SetWatchSet(s)) = &ctrl.msg {
                        let outcome = match desired_from_proto(s, prefix_bounds) {
                            // A malformed element refuses the whole snapshot before
                            // the lock is ever taken — the live set is untouched.
                            Err(_) => crate::watchset::ReplaceOutcome::Malformed,
                            Ok(desired) => {
                                let mut guard = watch_set.lock().unwrap_or_else(|p| p.into_inner());
                                // gRPC entry-caps neither incremental adds nor a
                                // replace (quota is its bound) → max_items = 0.
                                let outcome = guard.replace(principal.as_ref(), desired, 0, &*handle);
                                // The category filter is part of the desired set, so
                                // apply it only when the replace was accepted — a
                                // rejection leaves the whole set (categories
                                // included) unchanged, as WatchSetRejected promises.
                                if matches!(outcome, crate::watchset::ReplaceOutcome::Accepted { .. }) {
                                    let mask = if s.categories == 0 {
                                        node::events::ALL_CATEGORIES_DEFAULT
                                    } else {
                                        s.categories
                                    };
                                    category_mask.store(mask, Ordering::Relaxed);
                                }
                                outcome
                            }
                        };
                        // Outbound gone (stream tearing down) → nothing to deliver.
                        let _ = ws_result_tx.send(outcome).await;
                        continue;
                    }
                    // RescanBlocks is a bounded historical rescan (a side query),
                    // not a watch-set mutation: forward its range to the outbound
                    // task (which owns the scan source + this connection's watch-
                    // set) or a rejection reason. Range validation/clamping is
                    // done there; here we enforce only the rate limit and the
                    // single-in-flight guard, exactly like SetCursor.
                    if let Some(pb::subscribe_control::Msg::RescanBlocks(rb)) = &ctrl.msg {
                        // A rescan drives up to MAX_RESCAN_BLOCKS block-body+undo
                        // reads and a matcher pass — heavier than a re-anchor.
                        // Rate-limit per principal (operator/loopback bypass).
                        if let Some(p) = principal.as_ref()
                            && let satd_auth::RateDecision::Throttle { retry_after_secs } =
                                p.check_rate()
                        {
                            debug!(
                                target: "events::grpc",
                                retry_after_secs,
                                "rejecting RescanBlocks: per-principal rate limit exceeded",
                            );
                            rescan_reject(&rescan_reject_tx, RescanRejectReason::RateLimited).await;
                            continue;
                        }
                        // Claim the single in-flight slot (queued OR draining) →
                        // else reject ConcurrentRescan. Cleared by the outbound
                        // task once the scan drains.
                        if rescan_in_flight.swap(true, Ordering::AcqRel) {
                            rescan_reject(&rescan_reject_tx, RescanRejectReason::ConcurrentRescan)
                                .await;
                            continue;
                        }
                        // We own the slot, so the capacity-1 channel is empty: a
                        // send error can only be `Closed` (outbound gone). Release
                        // the slot in that case.
                        if rescan_tx.try_send((rb.from_height, rb.to_height)).is_err() {
                            rescan_in_flight.store(false, Ordering::Release);
                        }
                        continue;
                    }
                    let mut guard = watch_set.lock().unwrap_or_else(|p| p.into_inner());
                    apply_control(
                        ctrl,
                        &handle,
                        principal.as_ref(),
                        &category_mask,
                        &include_raw_tx,
                        &mut guard,
                        prefix_bounds,
                    );
                }
                // Inbound (control) closed. The watch-set is NOT dropped here —
                // it belongs to the subscription and drops with the outbound
                // stream + WatchHandle when the client fully disconnects.
            })
        };

        // Outbound: a single task selects over the live firehose, the
        // per-subscriber match channel, and mid-stream re-anchor requests,
        // forwarding into a bounded `mpsc` that backs the response stream. A
        // dedicated task (rather than `merge`d streams) is what lets a re-anchor
        // drain its replay batch *fully and in order* before the live tail
        // resumes (§7.3.1) — a plain `merge` would interleave past and present.
        let (tx_out, rx_out) = tokio::sync::mpsc::channel::<Result<pb::NodeEvent, Status>>(
            node::events::WATCH_CHANNEL_CAPACITY,
        );
        let publisher = self.publisher.clone();
        let block_source = self.block_source.clone();
        // Rescan (§6.1) needs full block bodies + undo (`scan_source`), the
        // shared registry (to snapshot THIS connection's watch-set into an
        // isolated ephemeral registry), and the handle (for its subscriber id).
        let scan_source = self.scan_source.clone();
        let rescan_registry = registry.clone();
        let rescan_handle = handle.clone();
        // Resume-cursor seed: the Watch firehose has no establishment replay, so
        // seed the resume height from the CURRENT chain tip (not 0) — a client
        // that lags before any block event (e.g. one watching only matches with
        // the firehose masked off) would otherwise be handed height 0 and
        // re-replay from genesis. The mempool watermark seeds from 0.
        let mut last_h = block_source
            .as_ref()
            .map(|s| s.current_tip_height())
            .unwrap_or(0);
        let mut last_s = 0u64;
        let mut rx_live = rx_live;
        let mut rx_match = rx_match;
        let mut reanchor_rx = reanchor_rx;
        let mut reject_rx = reject_rx;
        let mut rescan_rx = rescan_rx;
        let mut rescan_reject_rx = rescan_reject_rx;
        tokio::spawn(async move {
            use node::events::WatchMatch;
            // Keep the subscription alive for the task's lifetime: the
            // `WatchHandle` (deregisters on drop), the concurrency slot, and the
            // watch-set with its quota leases all drop together when the client
            // disconnects (the task ends when `tx_out` send fails).
            let _keep_slot = sub_guard;
            // Tie the inbound control reader to this task: when the subscription
            // ends (any exit path below), abort the inbound task so it cannot
            // linger on `message().await` holding its `WatchHandle` clone and the
            // shared watch-set after the outbound side is gone. (A clean
            // half-close already ends inbound via `message()` → `Ok(None)`; this
            // covers the case where the outbound side terminates first.)
            let _abort_inbound = AbortOnDrop(inbound_task);
            loop {
                tokio::select! {
                    biased;
                    // Client gone: the response `ReceiverStream` (rx_out) was
                    // dropped. The send-error checks below only fire when an event
                    // arrives to send, so on an IDLE node a disconnect would
                    // otherwise leave this task parked on the channels — pinning
                    // the concurrency slot, WatchHandle, and quota leases (and the
                    // inbound task) until the next event. Detecting the closed
                    // sender here releases them promptly. Checked first so a
                    // disconnect wins over draining work for a client that is gone.
                    _ = tx_out.closed() => break,
                    // Mid-stream re-anchor: drain the replay batch to completion,
                    // in height order, BEFORE servicing live/match again.
                    Some(cur) = reanchor_rx.recv() => {
                        // `reanchor_in_flight` was set by the inbound reader when
                        // it queued this cursor; it stays set across the whole
                        // drain (so concurrent SetCursors are rejected) and is
                        // cleared on every exit from this arm below. The `return`
                        // paths end the task (and abort inbound), so the flag is
                        // moot there.
                        let Some(src) = block_source.as_ref() else {
                            // No block source → re-anchor cannot replay. Tell the
                            // client deterministically (#439) instead of silently
                            // no-op'ing; the live stream is unchanged.
                            reanchor_in_flight.store(false, Ordering::Release);
                            let head = publisher.resume_cursor(last_h, last_s);
                            let ev = node::events::cursor_rejected_event(
                                &publisher,
                                node::events::CursorRejectReason::NoSource,
                                head,
                            );
                            if tx_out.send(Ok(envelope_to_proto(&ev))).await.is_err() {
                                return;
                            }
                            continue;
                        };
                        let mask = category_mask.load(Ordering::Relaxed);
                        let replay = node::events::build_cursor_replay(
                            src.as_ref(),
                            &publisher,
                            cur,
                            mask,
                            MAX_REPLAY_BLOCKS,
                            // The `Watch` re-anchor does not serve the tweaks
                            // firehose (a `Subscribe`-side category).
                            None,
                        );
                        // Ack the re-anchor in-band, ahead of the replay batch, so
                        // the client knows replay is now running (and from where —
                        // `clamped` flags a truncated lower end). (#439)
                        let ack = node::events::cursor_accepted_event(
                            &publisher,
                            cur,
                            replay.clamped,
                            replay.earliest_replayed,
                        );
                        if tx_out.send(Ok(envelope_to_proto(&ack))).await.is_err() {
                            return;
                        }
                        debug!(
                            target: "events::grpc",
                            replayed_events = replay.events.len(),
                            "events gRPC Watch mid-stream re-anchor (drain→resume)",
                        );
                        for ev in &replay.events {
                            if let Some(c) = &ev.cursor {
                                last_h = c.height;
                            }
                            last_s = last_s.max(ev.stamp.seq);
                            if tx_out.send(Ok(envelope_to_proto(ev))).await.is_err() {
                                return;
                            }
                        }
                        // Replay fully drained → admit the next re-anchor.
                        reanchor_in_flight.store(false, Ordering::Release);
                    }
                    // A re-anchor the inbound reader declined (rate-limited, empty
                    // cursor, or concurrent): emit a deterministic rejection with
                    // the subscriber's current head. The live stream is unchanged.
                    Some(reason) = reject_rx.recv() => {
                        let head = publisher.resume_cursor(last_h, last_s);
                        let ev = node::events::cursor_rejected_event(&publisher, reason, head);
                        if tx_out.send(Ok(envelope_to_proto(&ev))).await.is_err() {
                            return;
                        }
                    }
                    // Deterministic result of an atomic SetWatchSet replace applied
                    // by the inbound reader: emit the in-band WatchSetResult.
                    Some(outcome) = ws_result_rx.recv() => {
                        let ev = watch_set_result_to_proto(&edge, &outcome);
                        if tx_out.send(Ok(ev)).await.is_err() {
                            return;
                        }
                    }
                    // Bounded historical rescan (§6.1): scan THIS connection's
                    // watch-set over [from,to] and drain the confirmed matches in
                    // height order, bracketed by a RescanResult ack and a terminal
                    // RescanComplete. A side query — it does NOT advance the
                    // durable forward cursor (last_h/last_s untouched), and it may
                    // run alongside a re-anchor. `rescan_in_flight` (set by inbound)
                    // is cleared on every exit path from this arm.
                    Some((req_from, req_to)) = rescan_rx.recv() => {
                        let Some(src) = scan_source.as_ref() else {
                            rescan_in_flight.store(false, Ordering::Release);
                            let ev = rescan_rejected_event(
                                &edge, node::events::RescanRejectReason::NoSource, 0,
                            );
                            if tx_out.send(Ok(ev)).await.is_err() { return; }
                            continue;
                        };
                        let tip = src.current_tip_height();
                        // Snapshot this connection's watch-set into an isolated,
                        // single-subscriber registry — no cross-connection leakage,
                        // no drop-on-lag. `None` ⇒ empty watch-set.
                        let Some(ephemeral) =
                            rescan_registry.clone_for_rescan(rescan_handle.sub_id())
                        else {
                            rescan_in_flight.store(false, Ordering::Release);
                            let ev = rescan_rejected_event(
                                &edge, node::events::RescanRejectReason::EmptyWatchSet, tip,
                            );
                            if tx_out.send(Ok(ev)).await.is_err() { return; }
                            continue;
                        };
                        let plan = match node::events::plan_rescan(src.as_ref(), req_from, req_to) {
                            Ok(p) => p,
                            Err(reason) => {
                                rescan_in_flight.store(false, Ordering::Release);
                                let ev = rescan_rejected_event(&edge, reason, tip);
                                if tx_out.send(Ok(ev)).await.is_err() { return; }
                                continue;
                            }
                        };
                        // Ack in-band ahead of the matches (mirrors CursorAccepted).
                        let ack = rescan_accepted_event(&edge, plan.from, plan.to, plan.clamped);
                        if tx_out.send(Ok(ack)).await.is_err() { return; }
                        // Undo is fetched only when an input-side script/prefix
                        // match could need it (spent-prevout scriptPubKeys).
                        let need_undo =
                            ephemeral.has_script_watchers() || ephemeral.has_prefix_watchers();
                        let mut matches: u64 = 0;
                        // Reorg-safe (height,hash) resolution first (an active-chain
                        // index walk) — run on the blocking pool like the per-block
                        // reads below, not inline on the async worker.
                        let range = {
                            let src = src.clone();
                            let (from, to) = (plan.from, plan.to);
                            match tokio::task::spawn_blocking(move || {
                                src.active_chain_range(from, to)
                            })
                            .await
                            {
                                Ok(r) => r,
                                // Join error ⇒ the runtime is shutting down (or the
                                // closure panicked); end the task. The in-flight slot
                                // is moot once the task dies.
                                Err(_) => return,
                            }
                        };
                        // Drain the range one block at a time. Each block's body+undo
                        // read (a ≤4 MB flat-file read + full deserialize) AND the
                        // matcher pass run on the blocking pool, NOT inline on the
                        // async worker: a sparse watch-set over the full
                        // MAX_RESCAN_BLOCKS span would otherwise pin one scarce
                        // API-runtime worker for the whole scan with no yield (a
                        // match — the only inline await — is rare). `spawn_blocking`
                        // offloads the I/O and yields between blocks; `is_closed`
                        // gives cheap cooperative cancellation when the client hangs
                        // up mid-scan (the match send is the only other cancel point
                        // and never fires on a match-less range).
                        for (h, hash) in range {
                            if tx_out.is_closed() {
                                return;
                            }
                            let src = src.clone();
                            let eph = ephemeral.clone();
                            let collected = match tokio::task::spawn_blocking(move || {
                                src.block_body(&hash).map(|block| {
                                    let undo =
                                        if need_undo { src.block_undo(&hash) } else { None };
                                    eph.scan_block_collect(&block, h, undo.as_ref())
                                })
                            })
                            .await
                            {
                                Ok(Some(v)) => v, // body held → matches (possibly empty)
                                Ok(None) => continue, // body not held locally → skip height
                                Err(_) => break, // join error (shutdown/panic): stop draining
                            };
                            for m in collected {
                                matches += 1;
                                // Rescan does not attribute descriptor matches (the
                                // ephemeral registry holds raw scripthashes, not the
                                // descriptor→script membership the live path keeps).
                                let ev = watch_match_to_proto(
                                    &edge,
                                    &m,
                                    Vec::new(),
                                    include_raw_tx.load(Ordering::Relaxed),
                                );
                                if tx_out.send(Ok(ev)).await.is_err() { return; }
                            }
                        }
                        debug!(
                            target: "events::grpc",
                            from = plan.from, to = plan.to, matches,
                            "events gRPC Watch bounded historical rescan drained",
                        );
                        let done = rescan_complete_event(&edge, plan.from, plan.to, matches);
                        if tx_out.send(Ok(done)).await.is_err() { return; }
                        rescan_in_flight.store(false, Ordering::Release);
                    }
                    // A rescan the inbound reader declined (rate-limited or already
                    // in flight): deterministic rejection. Live stream unchanged.
                    Some(reason) = rescan_reject_rx.recv() => {
                        let tip = scan_source
                            .as_ref()
                            .map(|s| s.current_tip_height())
                            .unwrap_or(0);
                        let ev = rescan_rejected_event(&edge, reason, tip);
                        if tx_out.send(Ok(ev)).await.is_err() { return; }
                    }
                    live = rx_live.recv() => match live {
                        Ok(env) => {
                            if (env.category_bit() & category_mask.load(Ordering::Relaxed)) == 0 {
                                continue;
                            }
                            last_s = env.stamp.seq;
                            if let Some(c) = &env.cursor {
                                last_h = c.height;
                            }
                            if tx_out.send(Ok(envelope_to_proto(&env))).await.is_err() {
                                return;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!(target: "events::grpc", dropped = n, "Watch subscriber lagged (firehose)");
                            let resume = publisher.resume_cursor(last_h, last_s);
                            let ev = node::events::lagged_event(&publisher, n, resume);
                            if tx_out.send(Ok(envelope_to_proto(&ev))).await.is_err() {
                                return;
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                    m = rx_match.recv() => match m {
                        Some(m) => {
                            // Single-shot terminal matches (depth alarm / lifecycle
                            // auto-close): the registry already evicted the entry
                            // server-side on fire, so handle.remove_* is an
                            // idempotent no-op there — its job here is to drop the
                            // carrier-held quota LEASE.
                            match &m {
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
                            // Attribute a script match back to the descriptor(s)
                            // whose window it belongs to (empty for a direct
                            // watch), looked up from this connection's watch-set.
                            let descriptor_matches = match &m {
                                WatchMatch::ScriptMatched { scripthash, .. } => {
                                    let ws = watch_set.lock().unwrap_or_else(|p| p.into_inner());
                                    ws.descriptor_attribution(scripthash)
                                        .iter()
                                        .map(|(d, branch, index)| pb::DescriptorMatch {
                                            descriptor: d.to_string(),
                                            branch: *branch,
                                            derivation_index: *index,
                                        })
                                        .collect()
                                }
                                _ => Vec::new(),
                            };
                            if tx_out
                                .send(Ok(watch_match_to_proto(
                                    &edge,
                                    &m,
                                    descriptor_matches,
                                    include_raw_tx.load(Ordering::Relaxed),
                                )))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        None => break,
                    },
                    else => break,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx_out))))
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
    include_raw_tx: &AtomicBool,
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
                // Apply the parsed floors to a set of scripthashes. Used for
                // both net-new scripts and re-asserted ones: `add_scripthashes_with_floors`
                // bumps the registry refcount only for genuinely new entries and
                // otherwise just updates the floor in place, so re-asserting a
                // held script to change its `min_value` is honored without
                // double-counting the watch.
                let apply_floors = |shs: &[[u8; 32]]| {
                    let items: Vec<([u8; 32], u64)> = shs
                        .iter()
                        .map(|sh| (*sh, floors.get(sh).copied().unwrap_or(0)))
                        .collect();
                    handle.add_scripthashes_with_floors(&items);
                };
                watch_set.add_scripts(
                    principal,
                    a.scripthashes.iter().filter_map(|b| parse_scripthash(b)),
                    "scripts",
                    apply_floors,
                    apply_floors,
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
            // watch it (rust-miniscript), retaining the descriptor → scripthashes
            // membership so it can be slid or removed cleanly. Charges one unit
            // per net-new script. The client advances `start` to slide the window
            // (gap-limit tracking is client-side); re-asserting reconciles.
            match crate::descriptor::expand_descriptor(&d.descriptor, d.start, d.gap_limit) {
                Ok(scripts) => {
                    watch_set.add_descriptor(
                        principal,
                        d.descriptor.clone(),
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
                    warn!(target: "events::grpc", error = %e, "ignoring invalid descriptor");
                }
            }
        }
        Some(Msg::RemoveDescriptor(r)) => {
            // Drop a previously-added descriptor, releasing the scripthashes its
            // window contributed whose last owner this removes.
            watch_set.remove_descriptor(&r.descriptor, |shs| {
                handle.remove_scripthashes(shs);
            });
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
                node::events::ALL_CATEGORIES_DEFAULT
            } else {
                c.categories
            };
            category_mask.store(mask, Ordering::Relaxed);
        }
        Some(Msg::SetWatchOptions(o)) => {
            // Per-stream raw-tx inlining. Store the encoder-side flag AND toggle
            // the registry gate (the matcher serializes only when some subscriber
            // opted in); both must agree so an opted-in stream both serializes
            // and emits. `set_raw_tx` is idempotent, so a repeated value no-ops.
            include_raw_tx.store(o.include_raw_tx, Ordering::Relaxed);
            handle.set_raw_tx(o.include_raw_tx);
        }
        Some(Msg::SetCursor(_)) => {
            // Unreachable in practice: the Watch inbound loop intercepts
            // SetCursor (a mid-stream re-anchor, §7.3.1) before calling
            // apply_control. Kept as a defensive arm for any other caller.
            debug!(
                target: "events::grpc",
                "SetCursor reached apply_control unexpectedly; ignoring (handled as re-anchor upstream)",
            );
        }
        Some(Msg::SetWatchSet(_)) => {
            // Like SetCursor: the inbound loop intercepts SetWatchSet (an atomic
            // replace whose deterministic WatchSetResult must reach the outbound
            // task) before calling apply_control. Defensive arm for other callers.
            debug!(
                target: "events::grpc",
                "SetWatchSet reached apply_control unexpectedly; ignoring (handled as atomic replace upstream)",
            );
        }
        Some(Msg::RescanBlocks(_)) => {
            // Like SetCursor/SetWatchSet: the inbound loop intercepts
            // RescanBlocks (a bounded historical rescan, §6.1) before calling
            // apply_control. Defensive arm for other callers.
            debug!(
                target: "events::grpc",
                "RescanBlocks reached apply_control unexpectedly; ignoring (handled as rescan upstream)",
            );
        }
        Some(Msg::AddSilentPayments(_)) | Some(Msg::RemoveSilentPayments(_)) => {
            // BIP 352 scan-key watch (§4). PR 4 reserves the schema slot; the
            // registry lease map + matcher wiring land in PR 6. No client in
            // this version sends these, so ignore rather than mis-handle — the
            // real add/remove/quota handling replaces this arm in PR 6.
            debug!(
                target: "events::grpc",
                "silent-payment watch control received but the matcher is not yet wired (PR 6); ignoring",
            );
        }
        None => {}
    }
}

/// Build a [`DesiredWatchSet`] from a `SetWatchSet` snapshot: expand each
/// descriptor over its window and parse the concrete kinds. `prefix_bounds`
/// prices the prefix buckets.
///
/// STRICT: a `SetWatchSet` is a full replacement, so any element that fails to
/// parse or expand fails the whole build (`Err`). Silently dropping a bad item —
/// as the incremental `Add*` best-effort paths do — would shrink the desired set
/// and make [`replace`](crate::watchset::WatchSet::replace) unregister
/// previously-live watches while still reporting `Accepted`. All-or-nothing: the
/// caller turns `Err` into a `WatchSetRejected{MALFORMED}` and leaves the live
/// set untouched.
fn desired_from_proto(
    s: &pb::SetWatchSet,
    prefix_bounds: (u8, u8),
) -> Result<crate::watchset::DesiredWatchSet, &'static str> {
    let (prefix_min_bits, prefix_max_bits) = prefix_bounds;
    // `min_values` is either empty (no floors) or exactly parallel to
    // `scripthashes`. A non-empty length mismatch is malformed: `get(i)` would
    // otherwise silently clear floors (too few) or ignore them (too many),
    // changing filters the client did not ask to change.
    if !s.min_values.is_empty() && s.min_values.len() != s.scripthashes.len() {
        return Err("min_values length");
    }
    let mut scripts: Vec<([u8; 32], u64)> = Vec::with_capacity(s.scripthashes.len());
    for (i, b) in s.scripthashes.iter().enumerate() {
        let sh = parse_scripthash(b).ok_or("scripthash")?;
        scripts.push((sh, s.min_values.get(i).copied().unwrap_or(0)));
    }
    let mut descriptors: Vec<(String, crate::watchset::DescriptorWindow)> =
        Vec::with_capacity(s.descriptors.len());
    for d in &s.descriptors {
        match crate::descriptor::expand_descriptor(&d.descriptor, d.start, d.gap_limit) {
            Ok(coords) => descriptors.push((d.descriptor.clone(), coords)),
            Err(e) => {
                warn!(target: "events::grpc", error = %e, "SetWatchSet: rejecting snapshot for invalid descriptor");
                return Err("descriptor");
            }
        }
    }
    let mut outpoints = Vec::with_capacity(s.outpoints.len());
    for op in &s.outpoints {
        outpoints.push(parse_outpoint(op).ok_or("outpoint")?);
    }
    let mut lifecycles = Vec::with_capacity(s.lifecycles.len());
    for l in &s.lifecycles {
        let t = parse_txid(&l.txid).ok_or("lifecycle txid")?;
        lifecycles.push((t, l.auto_close_depth));
    }
    let mut depth_alarms = Vec::with_capacity(s.depth_alarms.len());
    for a in &s.depth_alarms {
        if a.depth < 1 {
            return Err("depth alarm depth");
        }
        let t = parse_txid(&a.txid).ok_or("depth alarm txid")?;
        depth_alarms.push((t, a.depth));
    }
    let mut prefixes = Vec::with_capacity(s.prefixes.len());
    for p in &s.prefixes {
        let parsed = crate::watchset::parse_prefix(&p.prefix, p.bits, prefix_min_bits, prefix_max_bits)
            .ok_or("prefix")?;
        prefixes.push(parsed);
    }
    Ok(crate::watchset::DesiredWatchSet {
        scripts,
        descriptors,
        outpoints,
        lifecycles,
        depth_alarms,
        prefixes,
    })
}

/// Render a [`ReplaceOutcome`] as the in-band `WatchSetResult` node event.
fn watch_set_result_to_proto(
    edge: &node::events::EdgeIdentity,
    outcome: &crate::watchset::ReplaceOutcome,
) -> pb::NodeEvent {
    use crate::watchset::ReplaceOutcome;
    let outcome = match outcome {
        ReplaceOutcome::Accepted { added, removed, unchanged } => {
            pb::watch_set_result::Outcome::Accepted(pb::WatchSetAccepted {
                added: *added,
                removed: *removed,
                unchanged: *unchanged,
            })
        }
        ReplaceOutcome::Rejected { required, quota } => {
            pb::watch_set_result::Outcome::Rejected(pb::WatchSetRejected {
                reason: pb::watch_set_rejected::Reason::QuotaExceeded as i32,
                required: *required,
                quota: *quota,
            })
        }
        ReplaceOutcome::CapExceeded { limit, requested } => {
            pb::watch_set_result::Outcome::Rejected(pb::WatchSetRejected {
                reason: pb::watch_set_rejected::Reason::CapExceeded as i32,
                required: *requested,
                quota: *limit,
            })
        }
        ReplaceOutcome::Malformed => {
            pb::watch_set_result::Outcome::Rejected(pb::WatchSetRejected {
                reason: pb::watch_set_rejected::Reason::Malformed as i32,
                required: 0,
                quota: 0,
            })
        }
    };
    pb::NodeEvent {
        schema_version: node::events::SCHEMA_VERSION,
        stamp: Some(replay_stamp(edge)),
        cursor: None,
        body: Some(pb::node_event::Body::SetWatchSetResult(pb::WatchSetResult {
            outcome: Some(outcome),
        })),
    }
}

/// Build the in-band `RescanResult{Accepted}` node event — the ack emitted
/// ahead of a bounded historical rescan's matches (§6.1). Carries no cursor: a
/// rescan is a side query and does not advance the durable forward cursor.
fn rescan_accepted_event(
    edge: &node::events::EdgeIdentity,
    from_height: u32,
    to_height: u32,
    clamped: bool,
) -> pb::NodeEvent {
    pb::NodeEvent {
        schema_version: node::events::SCHEMA_VERSION,
        stamp: Some(replay_stamp(edge)),
        cursor: None,
        body: Some(pb::node_event::Body::RescanResult(pb::RescanResult {
            outcome: Some(pb::rescan_result::Outcome::Accepted(pb::RescanAccepted {
                from_height,
                to_height,
                clamped,
            })),
        })),
    }
}

/// Build the in-band `RescanResult{Rejected}` node event for a refused rescan.
fn rescan_rejected_event(
    edge: &node::events::EdgeIdentity,
    reason: node::events::RescanRejectReason,
    tip_height: u32,
) -> pb::NodeEvent {
    use node::events::RescanRejectReason as R;
    let reason = match reason {
        R::RateLimited => pb::rescan_rejected::Reason::RateLimited,
        R::ConcurrentRescan => pb::rescan_rejected::Reason::ConcurrentRescan,
        R::InvalidRange => pb::rescan_rejected::Reason::InvalidRange,
        R::RangeTooLarge => pb::rescan_rejected::Reason::RangeTooLarge,
        R::NoSource => pb::rescan_rejected::Reason::NoSource,
        R::EmptyWatchSet => pb::rescan_rejected::Reason::EmptyWatchSet,
    };
    pb::NodeEvent {
        schema_version: node::events::SCHEMA_VERSION,
        stamp: Some(replay_stamp(edge)),
        cursor: None,
        body: Some(pb::node_event::Body::RescanResult(pb::RescanResult {
            outcome: Some(pb::rescan_result::Outcome::Rejected(pb::RescanRejected {
                reason: reason as i32,
                tip_height,
            })),
        })),
    }
}

/// Build the terminal `RescanComplete` node event — the rescan range is fully
/// scanned and every match delivered; the stream resumes its prior live position.
fn rescan_complete_event(
    edge: &node::events::EdgeIdentity,
    from_height: u32,
    to_height: u32,
    matches: u64,
) -> pb::NodeEvent {
    pb::NodeEvent {
        schema_version: node::events::SCHEMA_VERSION,
        stamp: Some(replay_stamp(edge)),
        cursor: None,
        body: Some(pb::node_event::Body::RescanComplete(pb::RescanComplete {
            from_height,
            to_height,
            matches,
        })),
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
    descriptor_matches: Vec<pb::DescriptorMatch>,
    include_raw_tx: bool,
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
            amount,
            raw_tx,
        } => {
            // raw_tx is carried on the match only when some subscriber opted in;
            // put it on THIS connection's wire only if this connection did.
            let raw_tx = match (include_raw_tx, raw_tx) {
                (true, Some(bytes)) => bytes.to_vec(),
                _ => Vec::new(),
            };
            let body = pb::node_event::Body::ScriptMatched(pb::ScriptMatched {
                scripthash: scripthash.to_vec(),
                txid: txid.as_raw_hash().to_byte_array().to_vec(),
                is_output: *is_output,
                index: *index,
                confirmed: *confirmed,
                descriptor_matches,
                amount: amount.unwrap_or(0),
                has_amount: amount.is_some(),
                raw_tx,
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
                    .map(|m| pb::SpentPrevout {
                        outpoint_txid: m.outpoint.txid.as_raw_hash().to_byte_array().to_vec(),
                        outpoint_vout: m.outpoint.vout,
                        script_pubkey: m.script_pubkey.to_bytes(),
                        amount: m.amount.unwrap_or(0),
                        has_amount: m.amount.is_some(),
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

/// Convert an envelope to proto, applying the subscription's per-subscription
/// `tweaks` filters (`dust_limit`, `tweaks_only`) to a [`BlockTweaks`] body.
/// Every other body is identical to [`envelope_to_proto`].
fn envelope_to_proto_sp(env: &NodeEvent, dust_limit: u64, tweaks_only: bool) -> pb::NodeEvent {
    match &env.body {
        NodeEventBody::BlockTweaks(bt) => pb::NodeEvent {
            schema_version: env.schema_version,
            stamp: Some(stamp_to_proto(&env.stamp)),
            cursor: env.cursor.map(cursor_to_proto),
            body: Some(pb::node_event::Body::BlockTweaks(block_tweaks_to_proto(
                bt, dust_limit, tweaks_only,
            ))),
        },
        _ => envelope_to_proto(env),
    }
}

/// Rows read per `spawn_blocking` hop in the lazy deep-replay pager. Bounds both
/// how long a blocking thread is held and how much is buffered at once.
const DEEP_TWEAK_REPLAY_CHUNK: u32 = 32;

/// Lazily page a tweaks-only deep-replay span `[start, end]` off the silent-
/// payment index, for the `build_cursor_replay` deep exemption (a complete-index
/// cold-sync waives the block clamp). The span can cover the entire taproot era,
/// so instead of materializing it, we read it in bounded [`DEEP_TWEAK_REPLAY_CHUNK`]
/// chunks inside `spawn_blocking` (never on an async worker) and push each block
/// through a small bounded channel. Backpressure on that channel paces the read
/// to the client's consumption, so peak memory is O(chunk) rather than O(chain).
///
/// The range handed here is already clamped to `[activation, tip]` (the builder
/// raises the lower end to taproot activation), so every height MUST carry a row
/// in a complete index. A `NotFound` is therefore NOT a benign below-activation
/// absence — it is a genuine hole (a concurrent backfill/reorg punched it while
/// the completeness marker stayed set), so it is surfaced in-band and ends the
/// stream, exactly like a storage/decode error. A silent skip would be a
/// client-undetectable gap in an unclamped cold-sync, the one failure a scanning
/// client cannot recover from. The client then resyncs from its last durable
/// cursor.
fn deep_tweak_replay_stream(
    sp: std::sync::Arc<dyn node::index::silent_payments::SpIndex>,
    publisher: std::sync::Arc<node::events::EventPublisher>,
    start: u32,
    end: u32,
    dust_limit: u64,
    tweaks_only: bool,
) -> ReceiverStream<Result<pb::NodeEvent, Status>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<pb::NodeEvent, Status>>(4);
    tokio::spawn(async move {
        let mut h = start;
        'outer: while h <= end {
            let chunk_end = h.saturating_add(DEEP_TWEAK_REPLAY_CHUNK - 1).min(end);
            let sp_chunk = sp.clone();
            let pub_chunk = publisher.clone();
            // Read + render one bounded chunk off the async runtime.
            let rendered = tokio::task::spawn_blocking(move || {
                let mut out: Vec<Result<pb::NodeEvent, Status>> = Vec::new();
                for hh in h..=chunk_end {
                    match sp_chunk.tweaks_at(hh) {
                        Ok(row) => {
                            let env = node::events::make_block_tweaks_event(&pub_chunk, hh, row);
                            out.push(Ok(envelope_to_proto_sp(&env, dust_limit, tweaks_only)));
                        }
                        // Range is clamped to `[activation, tip]`, so a missing
                        // row here is a hole, not a below-activation absence.
                        Err(node::index::silent_payments::SpIndexError::NotFound(_)) => {
                            out.push(Err(Status::internal(format!(
                                "silent-payment tweak index hole at height {hh} during unclamped \
                                 cold-sync: index reported complete but the row is missing \
                                 (concurrent backfill/reorg?); resync from your last cursor"
                            ))));
                            break;
                        }
                        Err(e) => {
                            out.push(Err(Status::internal(format!(
                                "silent-payment tweak read failed at height {hh}: {e}"
                            ))));
                            break;
                        }
                    }
                }
                out
            })
            .await;
            let rendered = match rendered {
                Ok(v) => v,
                // The blocking task panicked or was cancelled; end the stream.
                Err(_) => break,
            };
            for item in rendered {
                let stop_after = item.is_err();
                if tx.send(item).await.is_err() {
                    // Client disconnected — stop reading.
                    break 'outer;
                }
                if stop_after {
                    break 'outer;
                }
            }
            h = chunk_end + 1;
        }
    });
    ReceiverStream::new(rx)
}

/// Map a [`BlockTweaks`] to its proto form under a subscription's filters.
/// `dust_limit` drops entries whose `max_value` is below the floor (setting
/// `filtered`); `tweaks_only` strips `txid`/`max_value`, leaving the 33-byte
/// tweak alone. Hashes use internal byte order, matching the other bodies.
fn block_tweaks_to_proto(
    bt: &node::events::BlockTweaks,
    dust_limit: u64,
    tweaks_only: bool,
) -> pb::BlockTweaks {
    use bitcoin::hashes::Hash;
    let mut filtered = false;
    let entries = bt
        .entries
        .iter()
        .filter(|e| {
            let keep = dust_limit == 0 || e.max_value >= dust_limit;
            if !keep {
                filtered = true;
            }
            keep
        })
        .map(|e| pb::TweakEntry {
            tweak: e.tweak.serialize().to_vec(),
            txid: if tweaks_only {
                Vec::new()
            } else {
                e.txid.as_raw_hash().to_byte_array().to_vec()
            },
            max_value: if tweaks_only { 0 } else { e.max_value },
        })
        .collect();
    pb::BlockTweaks {
        block_hash: bt.block_hash.as_raw_hash().to_byte_array().to_vec(),
        height: bt.height,
        entries,
        filtered,
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
        // Unfiltered mapping (no dust limit, full entries) — the `Subscribe`
        // path applies per-subscription filters via `block_tweaks_to_proto`;
        // this covers any other conversion site for exhaustiveness.
        NodeEventBody::BlockTweaks(bt) => Body::BlockTweaks(block_tweaks_to_proto(bt, 0, false)),
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
        NodeEventBody::SetCursorResult(outcome) => {
            Body::SetCursorResult(set_cursor_result_to_proto(outcome))
        }
    }
}

fn set_cursor_result_to_proto(outcome: &node::events::SetCursorOutcome) -> pb::SetCursorResult {
    use node::events::{CursorRejectReason as R, SetCursorOutcome as O};
    use pb::set_cursor_result::Outcome;
    let outcome = match outcome {
        O::Accepted {
            from,
            clamped,
            earliest_replayed,
        } => Outcome::Accepted(pb::CursorAccepted {
            from: Some(cursor_to_proto(*from)),
            clamped: *clamped,
            earliest_replayed: *earliest_replayed,
        }),
        O::Rejected {
            reason,
            current_head,
        } => {
            let reason = match reason {
                R::RateLimited => pb::cursor_rejected::Reason::RateLimited,
                R::ConcurrentReanchor => pb::cursor_rejected::Reason::ConcurrentReanchor,
                R::EmptyCursor => pb::cursor_rejected::Reason::EmptyCursor,
                R::NoSource => pb::cursor_rejected::Reason::NoSource,
            };
            Outcome::Rejected(pb::CursorRejected {
                reason: reason as i32,
                current_head: Some(cursor_to_proto(*current_head)),
            })
        }
    };
    pb::SetCursorResult {
        outcome: Some(outcome),
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
                RustReason::Policy => pb::EvictReason::Policy as i32,
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

    fn test_pubkey(byte: u8) -> bitcoin::secp256k1::PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
    }

    fn sample_block_tweaks() -> node::events::BlockTweaks {
        node::events::BlockTweaks {
            block_hash: BlockHash::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([9u8; 32]),
            ),
            height: 100,
            entries: vec![
                node::events::SpTweakEntry {
                    tweak: test_pubkey(1),
                    txid: Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]),
                    ),
                    max_value: 1_000,
                },
                node::events::SpTweakEntry {
                    tweak: test_pubkey(2),
                    txid: Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([2u8; 32]),
                    ),
                    max_value: 50_000,
                },
            ],
        }
    }

    #[test]
    fn block_tweaks_to_proto_unfiltered() {
        let pb = block_tweaks_to_proto(&sample_block_tweaks(), 0, false);
        assert_eq!(pb.height, 100);
        assert!(!pb.filtered, "no dust limit ⇒ not filtered");
        assert_eq!(pb.entries.len(), 2);
        assert_eq!(pb.entries[0].tweak.len(), 33, "33-byte compressed tweak");
        assert_eq!(pb.entries[0].txid.len(), 32, "txid present");
        assert_eq!(pb.entries[0].max_value, 1_000);
    }

    #[test]
    fn block_tweaks_to_proto_dust_limit_sets_filtered() {
        // A floor above the smaller entry drops it and flags `filtered`.
        let pb = block_tweaks_to_proto(&sample_block_tweaks(), 10_000, false);
        assert_eq!(pb.entries.len(), 1, "sub-floor entry dropped");
        assert_eq!(pb.entries[0].max_value, 50_000);
        assert!(pb.filtered, "a dust limit dropped an entry");
    }

    #[test]
    fn block_tweaks_to_proto_tweaks_only_strips_fields() {
        let pb = block_tweaks_to_proto(&sample_block_tweaks(), 0, true);
        assert_eq!(pb.entries.len(), 2);
        for e in &pb.entries {
            assert_eq!(e.tweak.len(), 33, "tweak always present");
            assert!(e.txid.is_empty(), "txid stripped under tweaks_only");
            assert_eq!(e.max_value, 0, "max_value stripped under tweaks_only");
        }
        assert!(!pb.filtered, "tweaks_only alone is not a dust filter");
    }

    #[test]
    fn desired_from_proto_is_strict_all_or_nothing() {
        // A full replace must reject the whole snapshot if any element is
        // unparseable — never silently drop it (which would shrink the set and
        // unregister live watches while replace() still reports Accepted).
        let ok = pb::SetWatchSet {
            scripthashes: vec![vec![0x11; 32], vec![0x22; 32]],
            ..Default::default()
        };
        let d = desired_from_proto(&ok, (8, 32)).expect("all-valid snapshot builds");
        assert_eq!(d.scripts.len(), 2);

        // One malformed scripthash (wrong length) fails the whole build.
        let bad_sh = pb::SetWatchSet {
            scripthashes: vec![vec![0x11; 32], vec![0x22; 31]],
            ..Default::default()
        };
        assert!(desired_from_proto(&bad_sh, (8, 32)).is_err(), "bad scripthash rejects snapshot");

        // A malformed outpoint (bad txid length) fails too.
        let bad_op = pb::SetWatchSet {
            outpoints: vec![pb::Outpoint { txid: vec![0u8; 31], vout: 0 }],
            ..Default::default()
        };
        assert!(desired_from_proto(&bad_op, (8, 32)).is_err(), "bad outpoint rejects snapshot");

        // A depth alarm with depth 0 is invalid.
        let bad_depth = pb::SetWatchSet {
            depth_alarms: vec![pb::WatchDepthAlarm { txid: vec![0x33; 32], depth: 0 }],
            ..Default::default()
        };
        assert!(desired_from_proto(&bad_depth, (8, 32)).is_err(), "depth 0 rejects snapshot");

        // Non-empty min_values must be exactly parallel to scripthashes: too few
        // (would silently clear floors) and too many (silently ignored) are both
        // malformed. Empty is fine (no floors).
        let too_few = pb::SetWatchSet {
            scripthashes: vec![vec![0x11; 32], vec![0x22; 32]],
            min_values: vec![5],
            ..Default::default()
        };
        assert!(desired_from_proto(&too_few, (8, 32)).is_err(), "too few floors rejects snapshot");
        let too_many = pb::SetWatchSet {
            scripthashes: vec![vec![0x11; 32]],
            min_values: vec![5, 6],
            ..Default::default()
        };
        assert!(desired_from_proto(&too_many, (8, 32)).is_err(), "too many floors rejects snapshot");
        let parallel = pb::SetWatchSet {
            scripthashes: vec![vec![0x11; 32], vec![0x22; 32]],
            min_values: vec![5, 6],
            ..Default::default()
        };
        let d = desired_from_proto(&parallel, (8, 32)).expect("parallel floors build");
        assert_eq!(d.scripts, vec![([0x11; 32], 5), ([0x22; 32], 6)]);
    }

    #[test]
    fn malformed_outcome_maps_to_rejected_malformed() {
        let ev = watch_set_result_to_proto(&edge(), &crate::watchset::ReplaceOutcome::Malformed);
        let Some(pb::node_event::Body::SetWatchSetResult(r)) = ev.body else {
            panic!("expected a WatchSetResult body");
        };
        let Some(pb::watch_set_result::Outcome::Rejected(rj)) = r.outcome else {
            panic!("Malformed maps to a Rejected outcome");
        };
        assert_eq!(rj.reason, pb::watch_set_rejected::Reason::Malformed as i32);
        assert_eq!(rj.required, 0);
        assert_eq!(rj.quota, 0);
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
            Vec::new(),
            false,
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
            Vec::new(),
            false,
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
            Vec::new(),
            false,
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
            Vec::new(),
            false,
        );
        match ev.body.unwrap() {
            pb::node_event::Body::TxidFinalized(r) => assert_eq!(r.depth, 6),
            other => panic!("wrong body: {other:?}"),
        }
    }

    #[test]
    fn script_match_carries_descriptor_attribution() {
        use bitcoin::hashes::Hash;
        use node::events::WatchMatch;
        let e = edge();
        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x11; 32]));
        let ev = watch_match_to_proto(
            &e,
            &WatchMatch::ScriptMatched {
                scripthash: [0xaa; 32],
                txid,
                is_output: true,
                index: 0,
                confirmed: true,
                height: Some(100),
                amount: Some(50_000),
                raw_tx: None,
            },
            vec![pb::DescriptorMatch {
                descriptor: "wpkh(xpub)".into(),
                branch: 1,
                derivation_index: 7,
            }],
            false,
        );
        match ev.body.unwrap() {
            pb::node_event::Body::ScriptMatched(s) => {
                assert_eq!(s.descriptor_matches.len(), 1);
                assert_eq!(s.descriptor_matches[0].descriptor, "wpkh(xpub)");
                assert_eq!(s.descriptor_matches[0].branch, 1);
                assert_eq!(s.descriptor_matches[0].derivation_index, 7);
                // matched value rides the event in-band (#456)
                assert!(s.has_amount);
                assert_eq!(s.amount, 50_000);
                // raw_tx omitted unless the connection opted in.
                assert!(s.raw_tx.is_empty(), "no opt-in → empty raw_tx");
            }
            other => panic!("wrong body: {other:?}"),
        }
    }

    #[test]
    fn script_match_raw_tx_gated_by_include_flag() {
        use bitcoin::hashes::Hash;
        use node::events::WatchMatch;
        let e = edge();
        let txid =
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x11; 32]));
        let bytes: std::sync::Arc<[u8]> = std::sync::Arc::from(vec![0xde, 0xad, 0xbe, 0xef]);
        let m = WatchMatch::ScriptMatched {
            scripthash: [0xaa; 32],
            txid,
            is_output: true,
            index: 0,
            confirmed: true,
            height: Some(100),
            amount: Some(1),
            raw_tx: Some(bytes.clone()),
        };
        let raw_of = |ev: pb::NodeEvent| match ev.body.unwrap() {
            pb::node_event::Body::ScriptMatched(s) => s.raw_tx,
            other => panic!("wrong body: {other:?}"),
        };
        // Opted in AND the match carries it → bytes on the wire.
        assert_eq!(raw_of(watch_match_to_proto(&e, &m, Vec::new(), true)), vec![0xde, 0xad, 0xbe, 0xef]);
        // Not opted in → dropped even though the match carries it.
        assert!(raw_of(watch_match_to_proto(&e, &m, Vec::new(), false)).is_empty());
        // Opted in but the match has no raw_tx (nobody triggered serialization)
        // → still empty, no panic.
        let m_none = WatchMatch::ScriptMatched {
            scripthash: [0xaa; 32],
            txid,
            is_output: true,
            index: 0,
            confirmed: true,
            height: Some(100),
            amount: Some(1),
            raw_tx: None,
        };
        assert!(raw_of(watch_match_to_proto(&e, &m_none, Vec::new(), true)).is_empty());
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
            (EvictReason::Policy, pb::EvictReason::Policy),
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
        match GrpcEventSink::bind("0.0.0.0:0", false, publisher, GrpcLimits::default(), None, None, None, None, None, None).await {
            Err(GrpcEventSinkError::RemoteBindRejected(_)) => {}
            Ok(_) => panic!("non-loopback bind without allow_remote should fail"),
            Err(e) => panic!("expected RemoteBindRejected, got {e}"),
        }
    }

    #[tokio::test]
    async fn bind_allows_loopback_without_override() {
        let publisher = EventPublisher::new(edge(), 16);
        let sink = GrpcEventSink::bind("127.0.0.1:0", false, publisher, GrpcLimits::default(), None, None, None, None, None, None)
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
        let sink = GrpcEventSink::bind("0.0.0.0:0", true, publisher, GrpcLimits::default(), None, None, None, None, None, None)
            .await
            .expect("explicit remote bind should be allowed");
        let addr = sink.local_addr().unwrap();
        assert!(!addr.ip().is_loopback());
    }

    /// Write a throwaway self-signed cert/key to temp files and return the
    /// paths plus the cert (DER) so a test client can trust it.
    fn self_signed_to_files(
        dir: &std::path::Path,
    ) -> (std::path::PathBuf, std::path::PathBuf, rcgen::CertifiedKey) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, ck.cert.pem()).unwrap();
        std::fs::write(&key_path, ck.key_pair.serialize_pem()).unwrap();
        (cert_path, key_path, ck)
    }

    /// A TLS-configured events listener actually terminates TLS: a client that
    /// trusts the server cert completes the handshake against the bound port,
    /// exercising the acceptor + `EventsConn` driver end to end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bind_with_tls_terminates_client_handshake() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path, ck) = self_signed_to_files(dir.path());

        let publisher = EventPublisher::new(edge(), 16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let sink = GrpcEventSink::bind(
            "127.0.0.1:0",
            false,
            publisher.clone(),
            GrpcLimits::default(),
            None,
            None,
            None,
            None,
            None,
            Some(GrpcTlsParams {
                cert_path,
                key_path,
                mtls_enabled: false,
                mtls_client_ca: None,
                mtls_client_allow: vec![],
                handshake_timeout: Duration::from_secs(5),
            }),
        )
        .await
        .expect("TLS bind should succeed");
        let addr = sink.local_addr().unwrap();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Client trusts the self-signed leaf, then handshakes. Success proves
        // the events port speaks TLS (the rustls provider here is `ring`, the
        // single workspace-wide provider — no aws-lc-rs, no dual-provider panic).
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(ck.cert.der().clone()).unwrap();
        let client_cfg = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp connect");
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let handshake = connector.connect(name, tcp).await;
        assert!(
            handshake.is_ok(),
            "TLS handshake against the events listener failed: {:?}",
            handshake.err(),
        );

        let _ = shutdown_tx.send(true);
    }

    /// mTLS without a client CA bundle is a hard bind-time error, not a
    /// per-connection surprise.
    #[tokio::test]
    async fn bind_mtls_without_ca_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path, _ck) = self_signed_to_files(dir.path());
        let publisher = EventPublisher::new(edge(), 16);
        match GrpcEventSink::bind(
            "127.0.0.1:0",
            false,
            publisher,
            GrpcLimits::default(),
            None,
            None,
            None,
            None,
            None,
            Some(GrpcTlsParams {
                cert_path,
                key_path,
                mtls_enabled: true,
                mtls_client_ca: None,
                mtls_client_allow: vec![],
                handshake_timeout: Duration::from_secs(5),
            }),
        )
        .await
        {
            Err(GrpcEventSinkError::MtlsWithoutCa) => {}
            Ok(_) => panic!("mTLS without a CA must fail at bind"),
            Err(e) => panic!("expected MtlsWithoutCa, got {e}"),
        }
    }

    /// A malformed cert/key fails when the acceptor is built — at bind time.
    #[tokio::test]
    async fn bind_tls_bad_cert_fails() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, b"not a pem certificate").unwrap();
        std::fs::write(&key_path, b"not a pem key").unwrap();
        let publisher = EventPublisher::new(edge(), 16);
        match GrpcEventSink::bind(
            "127.0.0.1:0",
            false,
            publisher,
            GrpcLimits::default(),
            None,
            None,
            None,
            None,
            None,
            Some(GrpcTlsParams {
                cert_path,
                key_path,
                mtls_enabled: false,
                mtls_client_ca: None,
                mtls_client_allow: vec![],
                handshake_timeout: Duration::from_secs(5),
            }),
        )
        .await
        {
            Err(GrpcEventSinkError::TlsBuild(_)) => {}
            Ok(_) => panic!("a malformed cert must fail at bind"),
            Err(e) => panic!("expected TlsBuild, got {e}"),
        }
    }

    /// The events TLS acceptor registers its leaf cert/key in the shared
    /// `tls-config` reload registry, so SIGUSR1 (`reload_all_certs`) hot-reloads
    /// it alongside the RPC / Electrum / Esplora surfaces — no per-surface
    /// wiring. Guards against a future refactor to `with_single_cert`, which
    /// would silently drop the events surface from SIGUSR1 reload.
    #[tokio::test]
    async fn bind_with_tls_registers_for_sigusr1_reload() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path, _ck) = self_signed_to_files(dir.path());
        // The registry is process-global and append-only, so other tests can
        // only push the count higher — `> before` is race-safe.
        let before = tls_config::registered_cert_count();
        let publisher = EventPublisher::new(edge(), 16);
        let _sink = GrpcEventSink::bind(
            "127.0.0.1:0",
            false,
            publisher,
            GrpcLimits::default(),
            None,
            None,
            None,
            None,
            None,
            Some(GrpcTlsParams {
                cert_path,
                key_path,
                mtls_enabled: false,
                mtls_client_ca: None,
                mtls_client_allow: vec![],
                handshake_timeout: Duration::from_secs(5),
            }),
        )
        .await
        .expect("TLS bind should succeed");
        assert!(
            tls_config::registered_cert_count() > before,
            "events TLS bind must register a reloadable cert/key for SIGUSR1",
        );
    }

    /// A failed TLS handshake must release the connection-cap permit. With
    /// `max_conns = 1`, a garbage (non-TLS) connection that fails the handshake
    /// must not permanently hold the single permit — a subsequent well-formed
    /// TLS client must still be able to connect. Guards the handshake-task error
    /// paths (bad ClientHello / timeout / allowlist-reject) against a permit leak
    /// that would wedge the listener at capacity after a single failed probe.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls_handshake_failure_releases_connection_permit() {
        use tokio::io::AsyncWriteExt;
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path, ck) = self_signed_to_files(dir.path());

        let publisher = EventPublisher::new(edge(), 16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let limits = GrpcLimits { max_conns: 1, ..GrpcLimits::default() };
        let sink = GrpcEventSink::bind(
            "127.0.0.1:0",
            false,
            publisher.clone(),
            limits,
            None,
            None,
            None,
            None,
            None,
            Some(GrpcTlsParams {
                cert_path,
                key_path,
                mtls_enabled: false,
                mtls_client_ca: None,
                mtls_client_allow: vec![],
                handshake_timeout: Duration::from_secs(5),
            }),
        )
        .await
        .expect("TLS bind should succeed");
        let addr = sink.local_addr().unwrap();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Failed handshake: connect and send non-TLS garbage, then close. rustls
        // rejects the ClientHello, the handshake task returns, and its permit
        // must release.
        {
            let mut bad = tokio::net::TcpStream::connect(addr).await.expect("tcp connect");
            let _ = bad.write_all(b"this is not a tls clienthello\r\n\r\n").await;
            let _ = bad.shutdown().await;
        }

        // The good client must be able to connect. Retry briefly to absorb the
        // async permit release without a fixed-time flake; if the permit leaked,
        // every attempt fails (cap = 1 held forever) and the assert trips.
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(ck.cert.der().clone()).unwrap();
        let client_cfg = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut connected = false;
        for _ in 0..50 {
            let tcp = match tokio::net::TcpStream::connect(addr).await {
                Ok(t) => t,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
            };
            if connector.connect(name.clone(), tcp).await.is_ok() {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            connected,
            "a good TLS client could not connect after a failed handshake — \
             the connection-cap permit was likely leaked on the error path",
        );

        let _ = shutdown_tx.send(true);
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
        let sink = GrpcEventSink::bind("127.0.0.1:0", false, publisher.clone(), GrpcLimits::default(), None, None, None, None, None, None)
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
                tweak_dust_limit: None,
                tweaks_only: None,
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
                pb::node_event::Body::Lagged(_) => "lagged",
                pb::node_event::Body::TxidMatched(_) => "txid_matched",
                pb::node_event::Body::TxidReplaced(_) => "txid_replaced",
                pb::node_event::Body::TxidEvicted(_) => "txid_evicted",
                pb::node_event::Body::TxidUnconfirmed(_) => "txid_unconfirmed",
                pb::node_event::Body::TxidDepthReached(_) => "txid_depth_reached",
                pb::node_event::Body::TxidFinalized(_) => "txid_finalized",
                pb::node_event::Body::PrefixMatched(_) => "prefix_matched",
                pb::node_event::Body::SetCursorResult(_) => "set_cursor_result",
                pb::node_event::Body::SetWatchSetResult(_) => "set_watch_set_result",
                pb::node_event::Body::RescanResult(_) => "rescan_result",
                pb::node_event::Body::RescanComplete(_) => "rescan_complete",
                pb::node_event::Body::BlockTweaks(_) => "block_tweaks",
                pb::node_event::Body::SilentPaymentMatched(_) => "silent_payment_matched",
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
            scan_source: None,
            watch_registry: None,
            tweak_source: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        let mk = || {
            Request::new(pb::SubscribeRequest {
                categories: 0,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
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

    /// A mock silent-payment index: a row per height in `[1, tip]` whose block
    /// hash matches the `[h; 32]` convention `MockBlocks`/`ch_tx` use, so the
    /// live-emit and replay hash-match guards accept it.
    struct MockSp {
        tip: u32,
        complete: bool,
    }
    impl node::index::silent_payments::SpIndex for MockSp {
        fn tweaks_at(
            &self,
            height: u32,
        ) -> Result<
            node::index::silent_payments::SpBlockRow,
            node::index::silent_payments::SpIndexError,
        > {
            if height == 0 || height > self.tip {
                return Err(node::index::silent_payments::SpIndexError::NotFound(height));
            }
            Ok(node::index::silent_payments::SpBlockRow {
                block_hash: BlockHash::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([height as u8; 32]),
                ),
                entries: vec![],
            })
        }
        fn is_complete(&self) -> bool {
            self.complete
        }
        fn activation_height(&self) -> u32 {
            // This mock carries a row for every height in `[1, tip]`.
            1
        }
    }

    fn tweaks_height(ev: &pb::NodeEvent) -> Option<u32> {
        match ev.body.as_ref()? {
            pb::node_event::Body::BlockTweaks(bt) => Some(bt.height),
            _ => None,
        }
    }

    /// A block source whose FIRST `active_chain_range` call blocks until the test
    /// releases it, so a re-anchor drain can be held mid-flight deterministically.
    /// It signals `entered` (async-awaitable) once that drain reaches replay, then
    /// parks on `release` (a blocking channel) until the test sends. Subsequent
    /// calls (later re-anchors) pass through immediately, so a test that fires a
    /// burst of follow-on re-anchors does not deadlock on a single-use gate.
    struct GatedBlocks {
        tip: u32,
        entered: Arc<tokio::sync::Notify>,
        released: AtomicBool,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl node::events::BlockCursorSource for GatedBlocks {
        fn current_tip_height(&self) -> u32 {
            self.tip
        }
        fn active_chain_range(&self, from: u32, to: u32) -> Vec<(u32, BlockHash)> {
            // Only the first drain is gated; later ones pass straight through.
            if !self.released.swap(true, Ordering::AcqRel) {
                self.entered.notify_one();
                let _ = self.release.lock().unwrap().recv();
            }
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

    fn set_cursor_ctrl(height: u32) -> pb::SubscribeControl {
        pb::SubscribeControl {
            msg: Some(pb::subscribe_control::Msg::SetCursor(pb::SetCursor {
                cursor: Some(pb::Cursor {
                    height,
                    tx_index: 0,
                    mempool_seq: 0,
                    instance_id: 0,
                }),
            })),
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
            scan_source: None,
            watch_registry: None,
            tweak_source: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        // Resume from height 2 → replay 3, 4, 5 (chain category only).
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 2,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
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
            scan_source: None,
            watch_registry: None,
            tweak_source: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 2,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
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
            scan_source: None,
            watch_registry: None,
            tweak_source: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        // Resume from height 3 → replay 4, 5 (snapshot hashes [4;32], [5;32]).
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 2,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
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

    /// A `tweaks` subscription against a node with the index disabled
    /// (`tweak_source = None`) is rejected in-band with FAILED_PRECONDITION,
    /// before any receiver is attached.
    #[tokio::test]
    async fn tweaks_subscription_rejected_when_index_disabled() {
        let publisher = EventPublisher::new(edge(), 16);
        let svc = NodeEventStreamSvc {
            publisher,
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
            block_source: None,
            scan_source: None,
            watch_registry: None,
            tweak_source: None, // index disabled
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        let res = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: node::events::CATEGORY_TWEAKS,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
                from_cursor: None,
            }))
            .await;
        match res {
            Ok(_) => panic!("tweaks with disabled index must be rejected"),
            Err(status) => assert_eq!(status.code(), tonic::Code::FailedPrecondition),
        }
    }

    /// The explicit-bit contract (design §3.5 acceptance): a `categories = 0`
    /// ("all") subscriber receives chain events but NOT `BlockTweaks`, while a
    /// `categories = 8` subscriber does. Also exercises the live-emit path: the
    /// chain bridge emits a tweak event per connected block only because a tweak
    /// subscriber is attached.
    #[tokio::test]
    async fn tweaks_explicit_bit_gates_delivery() {
        use tokio_stream::StreamExt as _;
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let sp: Arc<dyn node::index::silent_payments::SpIndex> =
            Arc::new(MockSp { tip: 100, complete: true });
        publisher.spawn_bridges_with_sp(
            mp_tx.subscribe(),
            ch_tx.subscribe(),
            Some(sp.clone()),
            shutdown_rx,
        );

        let mk_svc = || NodeEventStreamSvc {
            publisher: publisher.clone(),
            active_subs: Arc::new(AtomicUsize::new(0)),
            max_subscriptions: 0,
            block_source: Some(Arc::new(MockBlocks { tip: 0 })),
            scan_source: None,
            watch_registry: None,
            tweak_source: Some(sp.clone()),
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };

        // Subscriber A: categories = 0 ("all") — must NOT receive tweaks.
        let mut all = mk_svc()
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 0,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
                from_cursor: None,
            }))
            .await
            .expect("subscribe all")
            .into_inner();
        // Subscriber B: categories = 8 — must receive tweaks. Attaching it
        // raises the tweak-subscriber count so the bridge emits live.
        let mut tweaks = mk_svc()
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: node::events::CATEGORY_TWEAKS,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
                from_cursor: None,
            }))
            .await
            .expect("subscribe tweaks")
            .into_inner();

        // Give both subscribers time to attach (so the tweak-subscriber count is
        // raised before the block connects).
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mk = |h: u32| ChainEvent::BlockConnected {
            hash: BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [h as u8; 32],
            )),
            height: h,
        };
        ch_tx.send(mk(7)).unwrap();

        // Subscriber B is tweaks-only (categories = 8), so it filters out the
        // chain event and its first delivered item is the BlockTweaks at h=7.
        let ev = tokio::time::timeout(Duration::from_secs(2), tweaks.next())
            .await
            .expect("tweaks ready")
            .unwrap()
            .unwrap();
        assert_eq!(tweaks_height(&ev), Some(7), "categories=8 receives BlockTweaks");

        // Subscriber A: receives the chain event but NOT the tweak event. Its
        // next delivered item must be the next block's chain event, never the
        // tweak at h=7.
        let ev = tokio::time::timeout(Duration::from_secs(2), all.next())
            .await
            .expect("chain ready for all")
            .unwrap()
            .unwrap();
        assert_eq!(chain_height(&ev), Some(7));
        ch_tx.send(mk(8)).unwrap();
        let ev = tokio::time::timeout(Duration::from_secs(2), all.next())
            .await
            .expect("next chain for all")
            .unwrap()
            .unwrap();
        assert_eq!(
            chain_height(&ev),
            Some(8),
            "categories=0 must skip the h=7 tweak and see the h=8 chain event next",
        );
        assert!(tweaks_height(&ev).is_none());
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
            scan_source: None,
            watch_registry: None,
            tweak_source: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        // Resume from height 0 → would replay the whole chain; must clamp.
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 2,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
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
            scan_source: None,
            watch_registry: None,
            tweak_source: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        // Resume from mempool_seq = 1 on the SAME instance → replay seqs 2, 3.
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 1, // mempool only
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
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
            scan_source: None,
            watch_registry: None,
            tweak_source: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        // Same mempool_seq=1 as the same-instance test, but a STALE instance
        // → epoch mismatch → discard the watermark → replay seqs 1, 2, 3.
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 1,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
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
            scan_source: None,
            watch_registry: None,
            tweak_source: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        // Stale instance_id, chain category → confirmed replay 3, 4, 5 anyway.
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 2,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
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
            scan_source: None,
            watch_registry: None,
            tweak_source: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 0,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
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
            scan_source: None,
            watch_registry: None,
            tweak_source: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        // Open the subscription first (its receiver is now live), then flood the
        // publisher far past the broadcast capacity before the stream is polled.
        let resp = svc
            .subscribe(Request::new(pb::SubscribeRequest {
                categories: 0,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
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
            &mask, &AtomicBool::new(false),
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
            &mask, &AtomicBool::new(false),
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
                &mask, &AtomicBool::new(false),
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
            &mask, &AtomicBool::new(false),
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
            &mask, &AtomicBool::new(false),
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
            &mask, &AtomicBool::new(false),
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
            &mask, &AtomicBool::new(false),
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
            &mask, &AtomicBool::new(false),
            &mut leases,
            (8, 32),
        );
        assert!(reg.has_watchers(), "descriptor expansion should register a watch-set");
    }

    /// `apply_control(RemoveDescriptor)` drops the window a prior AddDescriptor
    /// registered, leaving no watchers (no auth → unlimited).
    #[test]
    fn apply_control_remove_descriptor_drops_the_window() {
        const DESC: &str = "wpkh(xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/0/*)";
        let reg = Arc::new(node::events::WatchRegistry::new());
        let (handle, _rx) = reg.register(node::events::WATCH_CHANNEL_CAPACITY);
        let mask = AtomicU32::new(u32::MAX);
        let mut leases = WatchSet::default();
        let add = |leases: &mut WatchSet| {
            apply_control(
                pb::SubscribeControl {
                    msg: Some(pb::subscribe_control::Msg::AddDescriptor(pb::AddDescriptor {
                        descriptor: DESC.into(),
                        gap_limit: 4,
                        start: 0,
                    })),
                },
                &handle,
                None,
                &mask, &AtomicBool::new(false),
                leases,
                (8, 32),
            );
        };
        add(&mut leases);
        assert!(reg.has_watchers(), "precondition: the window is registered");
        assert_eq!(leases.len(), 4);

        apply_control(
            pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::RemoveDescriptor(pb::RemoveDescriptor {
                    descriptor: DESC.into(),
                })),
            },
            &handle,
            None,
            &mask, &AtomicBool::new(false),
            &mut leases,
            (8, 32),
        );
        assert_eq!(leases.len(), 0, "removing the descriptor drops its whole window");
        assert!(!reg.has_watchers(), "no watchers remain after RemoveDescriptor");
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
            None,
            Some(registry.clone()),
            None,
            None,
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

    /// Mid-stream `SetCursor` re-anchors the firehose: it drains the confirmed
    /// replay `(cursor.height, tip]` in height order, and the watch-set survives
    /// the re-anchor (a subsequent match still fires).
    #[tokio::test]
    async fn watch_set_cursor_re_anchors_confirmed_history() {
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
            Some(Arc::new(MockBlocks { tip: 5 })),
            None,
            Some(registry.clone()),
            None,
            None,
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
        // Register a watch up front so we can prove it survives the re-anchor.
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

        // Wait until the AddOutpoints control is applied.
        for _ in 0..100 {
            if registry.has_watchers() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(registry.has_watchers(), "watch registered");

        // Re-anchor from height 2 → drain confirmed history 3, 4, 5 in order.
        ctrl_tx
            .send(pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::SetCursor(pb::SetCursor {
                    cursor: Some(pb::Cursor {
                        height: 2,
                        tx_index: 0,
                        mempool_seq: 0,
                        instance_id: 0,
                    }),
                })),
            })
            .await
            .unwrap();

        // The re-anchor is acked in-band ahead of the replay batch (#439).
        let ack = tokio::time::timeout(Duration::from_secs(3), stream.message())
            .await
            .expect("timeout")
            .expect("transport")
            .expect("stream ended");
        let Some(pb::node_event::Body::SetCursorResult(r)) = ack.body else {
            panic!("expected SetCursorResult ack first, got {:?}", ack.body);
        };
        let Some(pb::set_cursor_result::Outcome::Accepted(a)) = r.outcome else {
            panic!("expected CursorAccepted, got {:?}", r.outcome);
        };
        assert!(!a.clamped, "in-window cursor is not clamped");
        assert_eq!(a.earliest_replayed, 3, "replay starts at cursor.height + 1");

        for expected_h in [3u32, 4, 5] {
            let ev = tokio::time::timeout(Duration::from_secs(3), stream.message())
                .await
                .expect("timeout")
                .expect("transport")
                .expect("stream ended");
            assert_eq!(
                chain_height(&ev),
                Some(expected_h),
                "re-anchor replays confirmed blocks in height order"
            );
        }

        // The watch-set survived the re-anchor: a match still fires.
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
        assert!(
            matches!(ev.body, Some(pb::node_event::Body::OutpointSpent(_))),
            "watch-set preserved across re-anchor → match still delivered"
        );

        drop(ctrl_tx);
        let _ = shutdown_tx.send(true);
    }

    /// A deterministic rate limiter for the SetCursor re-anchor test: Allow the
    /// first `allow_first` checks, Throttle every check after that. Counting (not
    /// wall-clock) so the assertion cannot flake on token-bucket refill timing.
    struct CountingRate {
        allow_first: usize,
        calls: Arc<std::sync::Mutex<usize>>,
    }
    impl satd_auth::RateLimiter for CountingRate {
        fn check(&self, _id: &str, _policy: &satd_auth::RatePolicy) -> satd_auth::RateDecision {
            let mut c = self.calls.lock().unwrap();
            *c += 1;
            if *c <= self.allow_first {
                satd_auth::RateDecision::Allow
            } else {
                satd_auth::RateDecision::Throttle { retry_after_secs: 1 }
            }
        }
    }
    /// Custom rate limiter over a real local quota store (so watch-set adds still
    /// charge/acquire normally).
    struct CountingAcct {
        rate: CountingRate,
        quota: Arc<dyn satd_auth::QuotaStore>,
    }
    impl satd_auth::Accounting for CountingAcct {
        fn rate(&self) -> &dyn satd_auth::RateLimiter {
            &self.rate
        }
        fn quota(&self) -> Arc<dyn satd_auth::QuotaStore> {
            self.quota.clone()
        }
    }

    /// A mid-stream `SetCursor` re-anchor is charged against the connection's
    /// per-principal rate limit: once the bucket is spent, the re-anchor is
    /// dropped rather than driving another confirmed-history replay. Proven over
    /// the real authenticated gRPC wire path: establishment + the watch-add spend
    /// the budget, so the subsequent `SetCursor` is throttled and produces no
    /// replay — a watch match still arrives, which would be preceded by replayed
    /// blocks if the re-anchor had fired.
    #[tokio::test]
    async fn watch_set_cursor_re_anchor_is_rate_limited() {
        use bitcoin::hashes::Hash;
        use std::io::Write;
        // plaintext "grpc-ratelimit-token" → this sha256.
        const TOKEN: &str = "grpc-ratelimit-token";
        const TOKEN_SHA256: &str =
            "d8d38e15dcb3f77263eaa46a3436d532fae469482c6d6ea6764405289d45b2a2";

        // Allow establishment (#1) + the AddOutpoints watch-add (#2); throttle the
        // SetCursor (#3) and anything after.
        let calls = Arc::new(std::sync::Mutex::new(0usize));
        let local: Arc<dyn satd_auth::Accounting> = Arc::new(satd_auth::LocalAccounting::new());
        let acct: Arc<dyn satd_auth::Accounting> = Arc::new(CountingAcct {
            rate: CountingRate {
                allow_first: 2,
                calls: calls.clone(),
            },
            quota: local.quota(),
        });
        let dir = tempfile::tempdir().unwrap();
        let toml = format!(
            "version = 1\n\
             [[token]]\nid=\"rl\"\nhash=\"sha256:{TOKEN_SHA256}\"\n\
             capabilities=[\"stream:subscribe\",\"stream:watch\"]\n\
             watch_quota=100\nrate_limit=\"100/s\"\n"
        );
        let path = dir.path().join("auth.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store =
            Arc::new(satd_auth::TokenStore::load(&path).unwrap().with_accounting(acct));

        let publisher = EventPublisher::new(edge(), 64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let registry = Arc::new(node::events::WatchRegistry::new());
        let sink = GrpcEventSink::bind(
            "127.0.0.1:0",
            false,
            publisher.clone(),
            GrpcLimits::default(),
            Some(store),
            Some(Arc::new(MockBlocks { tip: 5 })),
            None,
            Some(registry.clone()),
            None,
            None,
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
        let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel::<pb::SubscribeControl>(8);
        // Register a watch up front (charges rate check #2 + one quota unit).
        ctrl_tx
            .send(pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::AddOutpoints(pb::AddOutpoints {
                    outpoints: vec![op_proto(0xcd, 1)],
                })),
            })
            .await
            .unwrap();
        // Authenticated Watch request (establishment charges rate check #1).
        let mut req = tonic::Request::new(ReceiverStream::new(ctrl_rx));
        req.metadata_mut()
            .insert("authorization", format!("Bearer {TOKEN}").parse().unwrap());
        let mut stream = client.watch(req).await.expect("watch").into_inner();

        for _ in 0..100 {
            if registry.has_watchers() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(registry.has_watchers(), "watch registered (establishment + add allowed)");

        // SetCursor: rate check #3 → throttled → rejected (no replay). Were it
        // served it would replay confirmed blocks 3, 4, 5.
        ctrl_tx
            .send(pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::SetCursor(pb::SetCursor {
                    cursor: Some(pb::Cursor {
                        height: 2,
                        tx_index: 0,
                        mempool_seq: 0,
                        instance_id: 0,
                    }),
                })),
            })
            .await
            .unwrap();

        // Give the inbound task time to process (and, in a regression, re-anchor)
        // the SetCursor before we trigger the sentinel match. With the rate-limit
        // in place the SetCursor is rejected (no replay), but it now emits a
        // deterministic CursorRejected (#439) ahead of the sentinel match.
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Sentinel: a mempool spend of the watched outpoint → OutpointSpent. The
        // outbound select is biased toward re-anchors, so if the throttled
        // SetCursor had instead been served, replayed blocks would arrive BEFORE
        // this match.
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

        // First: the deterministic rejection (rate-limited), not a replayed block.
        let ev = tokio::time::timeout(Duration::from_secs(3), stream.message())
            .await
            .expect("timeout")
            .expect("transport")
            .expect("stream ended");
        let Some(pb::node_event::Body::SetCursorResult(r)) = ev.body else {
            panic!("expected a CursorRejected, not a replayed block (got {:?})", ev.body);
        };
        let Some(pb::set_cursor_result::Outcome::Rejected(rj)) = r.outcome else {
            panic!("expected CursorRejected, got {:?}", r.outcome);
        };
        assert_eq!(
            rj.reason,
            pb::cursor_rejected::Reason::RateLimited as i32,
            "throttled SetCursor is rejected with RATE_LIMITED",
        );

        // Then the live match: no replayed blocks came between.
        let ev = tokio::time::timeout(Duration::from_secs(3), stream.message())
            .await
            .expect("timeout")
            .expect("transport")
            .expect("stream ended");
        assert!(
            matches!(ev.body, Some(pb::node_event::Body::OutpointSpent(_))),
            "rate-limited SetCursor produced no replay: after the rejection the next \
             event is the live match, not a replayed block (got {:?})",
            ev.body,
        );
        assert!(
            *calls.lock().unwrap() >= 3,
            "establishment + watch-add + the throttled SetCursor each hit the limiter",
        );

        drop(ctrl_tx);
        let _ = shutdown_tx.send(true);
    }

    /// A `SetCursor` that arrives while a previous re-anchor is **actively
    /// draining** (not merely queued) must be rejected `ConcurrentReanchor`, not
    /// queued and serviced late. The capacity-1 channel alone does not cover
    /// this — `recv()` empties it before the drain — so the in-flight flag does.
    /// We hold the first drain open with a gated block source, fire the second
    /// SetCursor mid-drain, then release and assert the stream order:
    /// Accepted(#1) → replayed blocks → Rejected(ConcurrentReanchor)(#2).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn watch_set_cursor_concurrent_during_drain_is_rejected() {
        let publisher = EventPublisher::new(edge(), 64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let registry = Arc::new(node::events::WatchRegistry::new());
        let entered = Arc::new(tokio::sync::Notify::new());
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let blocks = GatedBlocks {
            tip: 5,
            entered: entered.clone(),
            released: AtomicBool::new(false),
            release: std::sync::Mutex::new(release_rx),
        };
        let sink = GrpcEventSink::bind(
            "127.0.0.1:0",
            false,
            publisher.clone(),
            GrpcLimits::default(),
            None,
            Some(Arc::new(blocks)),
            None,
            Some(registry.clone()),
            None,
            None,
        )
        .await
        .expect("bind");
        let actual = sink.local_addr().unwrap();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client =
            pb::node_event_stream_client::NodeEventStreamClient::connect(format!("http://{actual}"))
                .await
                .expect("connect");
        let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel::<pb::SubscribeControl>(4);
        let mut stream = client
            .watch(ReceiverStream::new(ctrl_rx))
            .await
            .expect("watch")
            .into_inner();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // SetCursor #1 (height 2): the outbound task enters the replay and parks
        // in the gated block source. The in-flight flag is now set.
        ctrl_tx.send(set_cursor_ctrl(2)).await.unwrap();
        entered.notified().await;

        // SetCursor #2 (height 4) arrives while #1 is mid-drain → ConcurrentReanchor.
        ctrl_tx.send(set_cursor_ctrl(4)).await.unwrap();
        // Let the inbound reader process #2 before we release the drain.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Release #1's drain.
        release_tx.send(()).unwrap();

        macro_rules! next {
            () => {
                tokio::time::timeout(Duration::from_secs(3), stream.message())
                    .await
                    .expect("timeout")
                    .expect("transport")
                    .expect("stream ended")
            };
        }

        // #1 accepted, ahead of its replay.
        let ack = next!();
        let Some(pb::node_event::Body::SetCursorResult(r)) = ack.body else {
            panic!("expected SetCursorResult ack, got {:?}", ack.body);
        };
        assert!(
            matches!(r.outcome, Some(pb::set_cursor_result::Outcome::Accepted(_))),
            "first result is Accepted for SetCursor #1",
        );
        // #1 replays confirmed 3, 4, 5.
        for expected_h in [3u32, 4, 5] {
            let ev = next!();
            assert_eq!(chain_height(&ev), Some(expected_h));
        }
        // #2, fired mid-drain, is rejected ConcurrentReanchor (not queued/serviced).
        let rej = next!();
        let Some(pb::node_event::Body::SetCursorResult(r)) = rej.body else {
            panic!("expected SetCursorResult rejection, got {:?}", rej.body);
        };
        let Some(pb::set_cursor_result::Outcome::Rejected(rj)) = r.outcome else {
            panic!("expected CursorRejected, got {:?}", r.outcome);
        };
        assert_eq!(
            rj.reason,
            pb::cursor_rejected::Reason::ConcurrentReanchor as i32,
            "a SetCursor during an active drain is rejected ConcurrentReanchor",
        );

        drop(ctrl_tx);
        let _ = shutdown_tx.send(true);
    }

    /// A burst of declined SetCursors during a single (held-open) drain — more
    /// than the rejection channel can buffer — must ALL be rejected, none
    /// silently dropped. Inbound backpressures (blocking send) instead of
    /// shedding once the buffer fills, so every SetCursor still yields exactly
    /// one CursorRejected. This is the contract the #439 fix exists to keep.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn watch_set_cursor_burst_is_not_silently_dropped() {
        // Well above the reject channel buffer (32) so the surplus must
        // backpressure rather than drop.
        const BURST: usize = 64;

        let publisher = EventPublisher::new(edge(), 64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let registry = Arc::new(node::events::WatchRegistry::new());
        let entered = Arc::new(tokio::sync::Notify::new());
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let blocks = GatedBlocks {
            tip: 5,
            entered: entered.clone(),
            released: AtomicBool::new(false),
            release: std::sync::Mutex::new(release_rx),
        };
        let sink = GrpcEventSink::bind(
            "127.0.0.1:0",
            false,
            publisher.clone(),
            GrpcLimits::default(),
            None,
            Some(Arc::new(blocks)),
            None,
            Some(registry.clone()),
            None,
            None,
        )
        .await
        .expect("bind");
        let actual = sink.local_addr().unwrap();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client =
            pb::node_event_stream_client::NodeEventStreamClient::connect(format!("http://{actual}"))
                .await
                .expect("connect");
        let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel::<pb::SubscribeControl>(4);
        let mut stream = client
            .watch(ReceiverStream::new(ctrl_rx))
            .await
            .expect("watch")
            .into_inner();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // #1 enters the gated drain (flag set, drain parked).
        ctrl_tx.send(set_cursor_ctrl(2)).await.unwrap();
        entered.notified().await;

        // Fire BURST more SetCursors mid-drain from a task (they backpressure
        // once the buffer fills; the task blocks, never drops).
        let sender = ctrl_tx.clone();
        let pump = tokio::spawn(async move {
            for _ in 0..BURST {
                if sender.send(set_cursor_ctrl(4)).await.is_err() {
                    break;
                }
            }
        });
        // Give inbound time to fill the buffer and block on the surplus.
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Release the drain; everything now flows.
        release_tx.send(()).unwrap();

        // Every SetCursor — the initial #1 plus all BURST burst ones — must yield
        // exactly one SetCursorResult (Accepted or Rejected). We assert the TOTAL
        // count, not the mix: once #1's drain finishes the in-flight flag clears,
        // so some later burst cursors become fresh Accepted re-anchors rather than
        // ConcurrentReanchor — but NONE may be silently dropped. Replayed blocks
        // (from the accepted re-anchors) are ignored.
        macro_rules! next {
            () => {
                tokio::time::timeout(Duration::from_secs(5), stream.message())
                    .await
                    .expect("timeout (a SetCursor result was dropped)")
                    .expect("transport")
                    .expect("stream ended")
            };
        }
        let want = BURST + 1; // #1 + the burst
        let mut results = 0usize;
        while results < want {
            let ev = next!();
            match ev.body {
                Some(pb::node_event::Body::SetCursorResult(r)) => {
                    assert!(r.outcome.is_some(), "every result carries an outcome");
                    results += 1;
                }
                // Replayed blocks from accepted re-anchors — ignore.
                Some(pb::node_event::Body::Chain(_)) => {}
                other => panic!("unexpected body during burst drain: {other:?}"),
            }
        }
        assert_eq!(
            results, want,
            "every SetCursor (initial + burst) yielded exactly one result; none dropped",
        );

        pump.await.unwrap();
        drop(ctrl_tx);
        let _ = shutdown_tx.send(true);
    }

    /// When the client disconnects while the node is IDLE (no live events, no
    /// matches, no re-anchor), the outbound task must still tear down promptly and
    /// release the subscription — it cannot park on the event channels until the
    /// next event. Proven by watching the registration drop after the client drops
    /// the stream with nothing ever published. Without the `tx_out.closed()` branch
    /// the outbound task would stay parked holding its `WatchHandle`, so the watch
    /// would remain registered.
    #[tokio::test]
    async fn watch_outbound_exits_on_client_disconnect_while_idle() {
        let publisher = EventPublisher::new(edge(), 64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let registry = Arc::new(node::events::WatchRegistry::new());
        let sink = GrpcEventSink::bind(
            "127.0.0.1:0",
            false,
            publisher.clone(),
            GrpcLimits::default(),
            None,
            None, // no block source: a re-anchor can't wake the loop either
            None,
            Some(registry.clone()),
            None,
            None,
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
        let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel::<pb::SubscribeControl>(4);
        ctrl_tx
            .send(pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::AddOutpoints(pb::AddOutpoints {
                    outpoints: vec![op_proto(0xab, 0)],
                })),
            })
            .await
            .unwrap();
        let stream = client
            .watch(ReceiverStream::new(ctrl_rx))
            .await
            .expect("watch")
            .into_inner();

        for _ in 0..100 {
            if registry.has_watchers() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(registry.has_watchers(), "watch registered");

        // Client disconnects — drop the response stream (and the rest) with NO
        // event ever published, so only the closed-sender signal can wake the
        // outbound task.
        drop(stream);
        drop(ctrl_tx);
        drop(client);

        let mut released = false;
        for _ in 0..150 {
            if !registry.has_watchers() {
                released = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            released,
            "outbound task released the subscription after an idle disconnect",
        );
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
            scan_source: None,
            watch_registry: None,
            tweak_source: None,
            prefix_min_bits: 8,
            prefix_max_bits: 32,
        };
        let mut held = Vec::new();
        for _ in 0..16 {
            held.push(
                svc.subscribe(Request::new(pb::SubscribeRequest {
                    categories: 0,
                    since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
                    from_cursor: None,
                }))
                .await
                .expect("uncapped subscribe always ok"),
            );
        }
        // Counter stays at zero when the cap is disabled.
        assert_eq!(svc.active_subs.load(Ordering::Acquire), 0);
    }

    /// A `BlockScanSource` holding real blocks keyed by height — the block-body +
    /// undo source a bounded historical rescan reads.
    struct MockScanBlocks {
        tip: u32,
        blocks: std::collections::HashMap<u32, bitcoin::Block>,
    }

    impl node::events::BlockCursorSource for MockScanBlocks {
        fn current_tip_height(&self) -> u32 {
            self.tip
        }
        fn active_chain_range(&self, from: u32, to: u32) -> Vec<(u32, BlockHash)> {
            let hi = to.min(self.tip);
            let lo = from.max(1);
            (lo..=hi)
                .filter_map(|h| self.blocks.get(&h).map(|b| (h, b.block_hash())))
                .collect()
        }
    }

    impl node::events::BlockScanSource for MockScanBlocks {
        fn block_body(&self, hash: &BlockHash) -> Option<bitcoin::Block> {
            self.blocks.values().find(|b| b.block_hash() == *hash).cloned()
        }
        fn block_undo(&self, _hash: &BlockHash) -> Option<node::storage::undo::UndoData> {
            None
        }
    }

    /// End-to-end: a `RescanBlocks` over the Watch stream scans this connection's
    /// watch-set against historical blocks and returns the matches in-band,
    /// bracketed by `RescanResult{Accepted}` and `RescanComplete`.
    #[tokio::test]
    async fn watch_rescan_delivers_historical_matches() {
        use bitcoin::hashes::Hash;
        let publisher = EventPublisher::new(edge(), 64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let registry = Arc::new(node::events::WatchRegistry::new());

        // A block at height 3 spending the watched outpoint.
        let op = bitcoin::OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0xcd; 32])),
            vout: 1,
        };
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
        let block3 = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0),
                nonce: 3,
            },
            txdata: vec![spend],
        };
        let mut blocks = std::collections::HashMap::new();
        blocks.insert(3u32, block3);
        let scan_source: Arc<dyn node::events::BlockScanSource> =
            Arc::new(MockScanBlocks { tip: 5, blocks });

        let sink = GrpcEventSink::bind(
            "127.0.0.1:0",
            false,
            publisher.clone(),
            GrpcLimits::default(),
            None,
            None,
            Some(scan_source),
            Some(registry.clone()),
            None,
            None,
        )
        .await
        .expect("bind");
        let actual = sink.local_addr().unwrap();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client =
            pb::node_event_stream_client::NodeEventStreamClient::connect(format!("http://{actual}"))
                .await
                .expect("connect");

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

        // Wait until the watch is registered, then request the rescan.
        for _ in 0..100 {
            if registry.has_watchers() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(registry.has_watchers(), "watch should register");
        ctrl_tx
            .send(pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::RescanBlocks(pb::RescanBlocks {
                    from_height: 1,
                    to_height: 5,
                })),
            })
            .await
            .unwrap();

        // Read until RescanComplete, asserting the ack + match arrive in order.
        // (Heartbeats from the live firehose may interleave before the rescan
        // arm is selected; skip them.)
        let mut saw_accept = false;
        let mut saw_match = false;
        let mut saw_complete = false;
        for _ in 0..50 {
            let ev = tokio::time::timeout(Duration::from_secs(3), stream.message())
                .await
                .expect("timeout")
                .expect("transport")
                .expect("stream ended");
            match ev.body.expect("body") {
                pb::node_event::Body::RescanResult(r) => match r.outcome.expect("outcome") {
                    pb::rescan_result::Outcome::Accepted(a) => {
                        assert_eq!((a.from_height, a.to_height), (1, 5));
                        assert!(!a.clamped, "to=5 == tip, no clamp");
                        assert!(!saw_match && !saw_complete, "ack precedes matches");
                        saw_accept = true;
                    }
                    pb::rescan_result::Outcome::Rejected(rj) => {
                        panic!("unexpected rescan rejection: reason={}", rj.reason)
                    }
                },
                pb::node_event::Body::OutpointSpent(o) => {
                    assert_eq!(o.outpoint_vout, 1);
                    assert!(o.confirmed, "historical rescan match is confirmed");
                    saw_match = true;
                }
                pb::node_event::Body::RescanComplete(c) => {
                    assert_eq!((c.from_height, c.to_height, c.matches), (1, 5, 1));
                    saw_complete = true;
                    break;
                }
                pb::node_event::Body::Heartbeat(_) => {} // live firehose; ignore
                other => panic!("unexpected event during rescan: {other:?}"),
            }
        }
        assert!(saw_accept, "RescanResult{{Accepted}} delivered");
        assert!(saw_match, "OutpointSpent match delivered");
        assert!(saw_complete, "RescanComplete delivered");

        drop(ctrl_tx);
        let _ = shutdown_tx.send(true);
    }

    /// A `RescanBlocks` with no scan source configured is deterministically
    /// rejected `NO_SOURCE`.
    #[tokio::test]
    async fn watch_rescan_without_scan_source_is_rejected() {
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
            None, // no scan source
            Some(registry.clone()),
            None,
            None,
        )
        .await
        .expect("bind");
        let actual = sink.local_addr().unwrap();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client =
            pb::node_event_stream_client::NodeEventStreamClient::connect(format!("http://{actual}"))
                .await
                .expect("connect");
        let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel::<pb::SubscribeControl>(4);
        // Watch something so the rescan isn't rejected EMPTY_WATCH_SET first.
        ctrl_tx
            .send(pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::AddOutpoints(pb::AddOutpoints {
                    outpoints: vec![op_proto(0x01, 0)],
                })),
            })
            .await
            .unwrap();
        ctrl_tx
            .send(pb::SubscribeControl {
                msg: Some(pb::subscribe_control::Msg::RescanBlocks(pb::RescanBlocks {
                    from_height: 1,
                    to_height: 3,
                })),
            })
            .await
            .unwrap();
        let mut stream = client
            .watch(ReceiverStream::new(ctrl_rx))
            .await
            .expect("watch")
            .into_inner();

        for _ in 0..50 {
            let ev = tokio::time::timeout(Duration::from_secs(3), stream.message())
                .await
                .expect("timeout")
                .expect("transport")
                .expect("stream ended");
            if let pb::node_event::Body::RescanResult(r) = ev.body.expect("body") {
                match r.outcome.expect("outcome") {
                    pb::rescan_result::Outcome::Rejected(rj) => {
                        assert_eq!(rj.reason, pb::rescan_rejected::Reason::NoSource as i32);
                        drop(ctrl_tx);
                        let _ = shutdown_tx.send(true);
                        return;
                    }
                    pb::rescan_result::Outcome::Accepted(_) => {
                        panic!("expected NO_SOURCE rejection, got acceptance")
                    }
                }
            }
        }
        panic!("no RescanResult received");
    }
}
