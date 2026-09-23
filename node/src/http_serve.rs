//! Capped, idle-timed HTTP listeners.
//!
//! Every HTTP surface satd serves itself — JSON-RPC, Esplora, streamws —
//! runs its own accept loop instead of a framework's, for two properties
//! a framework's loop does not give:
//!
//! - **A socket cap taken at accept.** A permit from a semaphore sized to
//!   the surface's `max_sockets` is acquired before the TLS handshake and
//!   before any HTTP is parsed, and lives as long as the connection. Every
//!   open socket counts, an idle keep-alive one included, so a client that
//!   opens connections and never closes them runs into the cap instead of
//!   the process's file-descriptor limit. Per-request concurrency limits
//!   (`ConcurrencyLimitLayer`, jsonrpsee's `max_connections`) bound work
//!   in flight, not sockets, and never see a connection that sends
//!   nothing.
//! - **An idle timeout.** hyper closes a keep-alive connection whose next
//!   request head does not arrive within `idle_timeout`, which needs a
//!   timer on the connection builder. `axum::serve` builds hyper without
//!   one, and hyper then discards its own default, so a connection served
//!   that way stays open for as long as the client keeps the socket.
//!
//! [`serve_http_listener`] is the accept loop; [`serve_http_connection`]
//! serves one connection and is shared with the JSON-RPC listeners, which
//! keep their own loops for the per-connection source-IP decision and the
//! jsonrpsee service stack.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio_rustls::TlsAcceptor;

use crate::warn_budget::WarnBudget;

/// TLS termination for a listener: the acceptor, the handshake budget, and
/// the mTLS post-handshake checks.
pub struct TlsTransport {
    pub acceptor: TlsAcceptor,
    /// A client that has not finished its handshake within this is dropped,
    /// so a half-open client cannot hold a permit indefinitely.
    pub handshake_timeout: Duration,
    /// When true the acceptor was built with `ClientAuthPolicy::Required`;
    /// the accepted client is logged and checked against `allow`. Without
    /// an mTLS handshake there is no peer certificate, so the allowlist is
    /// not consulted (a non-empty one would reject every connection).
    pub mtls_enabled: bool,
    pub allow: tls_config::ClientAllowList,
}

/// How a listener terminates its connections.
pub enum Transport {
    Plain,
    Tls(TlsTransport),
}

/// A cap on open sockets, counted at accept.
///
/// Cloning shares the cap: listeners handed clones of one `SocketCap` draw
/// from the same pool, which is how Esplora's plain and TLS listeners are held
/// to one `-esploramaxsockets` between them rather than one each.
#[derive(Clone, Debug)]
pub struct SocketCap {
    permits: Arc<Semaphore>,
    max: usize,
}

impl SocketCap {
    /// `max` open sockets, clamped to [`CAP_CEILING`]; `0` is unlimited.
    pub fn new(max: usize) -> Self {
        let max = clamp_cap(max);
        Self {
            permits: Arc::new(Semaphore::new(if max == 0 { Semaphore::MAX_PERMITS } else { max })),
            max,
        }
    }
}

/// The largest connection cap satd builds. tokio's `Semaphore::new` panics
/// above `Semaphore::MAX_PERMITS` (`usize::MAX >> 3`), and every cap option
/// accepts any `usize`, so an unclamped typo would panic satd at boot. No
/// host holds this many sockets open on one surface, so the ceiling only
/// catches mistakes.
pub const CAP_CEILING: usize = 100_000;

/// `max` clamped to [`CAP_CEILING`]. `0` stays `0`, so a surface that reads
/// `0` as unlimited still does.
pub fn clamp_cap(max: usize) -> usize {
    max.min(CAP_CEILING)
}

/// A listener's socket cap and idle budget. Cloning shares the socket cap
/// (see [`SocketCap`]).
#[derive(Clone, Debug)]
pub struct ListenerLimits {
    /// Open sockets, counted at accept.
    pub sockets: SocketCap,
    /// How long a keep-alive connection may sit between requests before it
    /// is closed. `None` leaves an idle connection open until the client
    /// closes it, which with a cap means an idle client keeps its slot.
    pub idle_timeout: Option<Duration>,
}

/// Accept connections on `listener` until `shutdown` flips, serving each
/// with `service` under `limits`. Returns when the accept loop stops; the
/// connections in flight are told to shut down gracefully and finish on
/// their own tasks.
///
/// `surface` names the listener in log lines. `service` is typically an
/// `axum::Router`; anything that serves a hyper request works.
pub async fn serve_http_listener<S, B>(
    surface: &'static str,
    listener: TcpListener,
    transport: Transport,
    service: S,
    limits: ListenerLimits,
    mut shutdown: watch::Receiver<bool>,
) where
    S: tower::Service<hyper::Request<hyper::body::Incoming>, Response = hyper::Response<B>>
        + Clone
        + Send
        + 'static,
    S::Error: Into<tower::BoxError>,
    S::Future: Send,
    B: hyper::body::Body<Data = hyper::body::Bytes> + Send + 'static,
    B::Error: Into<tower::BoxError>,
{
    let cap = limits.sockets.permits.clone();
    let transport = Arc::new(transport);
    // One budget per listener, so a flood on one surface does not silence
    // another's report.
    let at_capacity = Arc::new(WarnBudget::new(5, Duration::from_secs(60)));
    loop {
        let (stream, peer) = tokio::select! {
            res = listener.accept() => match res {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(surface, error = %e, "accept error");
                    // Brief sleep on a transient error (EMFILE, ECONNABORTED)
                    // so the loop does not spin.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };
        // The permit is taken before the handshake and before any HTTP is
        // parsed. At capacity the socket is closed (the client sees EOF, or
        // a reset if it had already sent data) rather than queued: queuing
        // would let a flood hold memory.
        let permit = match cap.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                if let Some(suppressed) = at_capacity.tick() {
                    tracing::warn!(
                        surface,
                        peer = %peer,
                        suppressed,
                        "at-capacity rejection ({} max sockets)",
                        limits.sockets.max,
                    );
                }
                drop(stream);
                continue;
            }
        };
        let service = service.clone();
        let transport = transport.clone();
        let mut conn_shutdown = shutdown.clone();
        // The permit rides with the socket (see `Permitted`), through the
        // handshake, the HTTP connection, and any upgrade that outlives it.
        let stream = Permitted::new(stream, permit);
        tokio::spawn(async move {
            let stopped = async move {
                let _ = conn_shutdown.changed().await;
            };
            match &*transport {
                Transport::Plain => {
                    if let Err(e) =
                        serve_http_connection(stream, service, stopped, limits.idle_timeout).await
                    {
                        tracing::debug!(surface, peer = %peer, error = %e, "connection ended");
                    }
                }
                Transport::Tls(tls) => {
                    // The handshake runs on this task, not the accept loop,
                    // so a slow client stalls only itself.
                    let Some(tls_stream) = tls_accept(surface, tls, stream, peer).await else {
                        return;
                    };
                    if let Err(e) =
                        serve_http_connection(tls_stream, service, stopped, limits.idle_timeout)
                            .await
                    {
                        tracing::debug!(surface, peer = %peer, error = %e, "TLS connection ended");
                    }
                }
            }
        });
    }
}

/// Complete a TLS handshake under the transport's budget and apply the mTLS
/// checks. `None` means the connection was dropped (already logged).
async fn tls_accept(
    surface: &'static str,
    tls: &TlsTransport,
    stream: Permitted<TcpStream>,
    peer: std::net::SocketAddr,
) -> Option<tokio_rustls::server::TlsStream<Permitted<TcpStream>>> {
    let tls_stream =
        match tokio::time::timeout(tls.handshake_timeout, tls.acceptor.accept(stream)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!(surface, peer = %peer, error = %e, "TLS handshake failed");
                return None;
            }
            Err(_) => {
                tracing::warn!(
                    surface,
                    peer = %peer,
                    timeout_secs = tls.handshake_timeout.as_secs(),
                    "TLS handshake timed out — closing connection",
                );
                return None;
            }
        };
    if tls.mtls_enabled {
        let (_, server_conn) = tls_stream.get_ref();
        if let Some(subject) = tls_config::peer_subject_label(server_conn) {
            tracing::info!(surface, peer = %peer, subject = %subject, "mTLS client accepted");
        }
        if let Err(rej) = tls_config::check_peer_allowed(server_conn, &tls.allow) {
            tracing::warn!(
                surface,
                peer = %peer,
                subject = %rej.subject_label,
                "mTLS client rejected by allowlist",
            );
            return None;
        }
    }
    Some(tls_stream)
}

/// Serve a single HTTP connection under an optional per-request timeout.
///
/// This is the plain-HTTP equivalent of jsonrpsee's
/// `serve_with_graceful_shutdown`, with one addition: when
/// `header_read_timeout` is `Some`, the underlying hyper HTTP/1.1 builder is
/// configured with a matching `header_read_timeout` (plus the required
/// timer), so a client that opens a TCP connection but never completes a
/// request head — including the head of the *next* request on an idle
/// keep-alive connection — gets disconnected rather than holding a connection
/// slot forever.
///
/// It serves HTTP/1.1 only. hyper-util's auto builder, which also serves
/// HTTP/2, first sniffs the connection for the HTTP/2 preface and only then
/// arms HTTP/1's header timer, so a client that sent one byte of the preface
/// (`P`) and stopped sat in the sniff with no deadline; and an HTTP/2
/// connection has no idle timeout at all, only a ping liveness check any
/// client answers. None of these listeners offers HTTP/2 over TLS (ALPN), so
/// only a client that assumed it unasked could reach that path.
///
/// The other half of Bitcoin Core's `-rpcservertimeout` is the request body,
/// which hyper cannot time out; that budget is applied where satd reads the
/// body, in [`crate::rpc::compat::JsonRpcCompatLayer`].
pub async fn serve_http_connection<S, B, I>(
    io: I,
    service: S,
    stopped: impl std::future::Future<Output = ()>,
    header_read_timeout: Option<Duration>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    // Generic over the transport so the TLS surface gets the same timeouts
    // as the plain one. It used to be `TcpStream`-only, which is why
    // `spawn_tls_surface` fell back to jsonrpsee's helper — and so ignored
    // `-rpcservertimeout` entirely.
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: tower::Service<
            hyper::Request<hyper::body::Incoming>,
            Response = hyper::Response<B>,
        > + Clone
        + Send
        + 'static,
    S::Error: Into<tower::BoxError>,
    S::Future: Send,
    B: hyper::body::Body<Data = hyper::body::Bytes> + Send + 'static,
    B::Error: Into<tower::BoxError>,
{
    let service = hyper_util::service::TowerToHyperService::new(service);
    let io = hyper_util::rt::TokioIo::new(io);

    let mut builder = hyper::server::conn::http1::Builder::new();
    builder.keep_alive(true);
    if let Some(timeout) = header_read_timeout {
        // hyper's timer is armed each time a request head is awaited, the
        // first one included, so this covers a connection that sends
        // nothing, a request head that stalls part-way, and the idle gap
        // before the next request on a keep-alive connection. It stops once
        // the head is complete: the body phase is bounded in the compat
        // layer instead, because that is where satd reads the body and
        // hyper offers no body-read timeout.
        builder
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(timeout);
    }
    let conn = builder.serve_connection(io, service).with_upgrades();

    tokio::pin!(stopped, conn);

    let result = tokio::select! {
        result = &mut conn => result,
        () = stopped => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    };
    Ok(result?)
}


/// A socket that carries its listener's connection-cap permit.
///
/// The permit has to live exactly as long as the socket, and the only thing
/// that does is the IO object itself. A task that holds the permit while it
/// awaits hyper's connection future is not enough: that future completes when
/// hyper hands the socket to an HTTP upgrade (a WebSocket), and the socket
/// lives on inside `hyper::upgrade::Upgraded`. Hyper moves the IO into
/// `Upgraded`, so a permit stored here goes with it and returns to the pool
/// when the upgraded socket is finally dropped.
pub struct Permitted<I> {
    inner: I,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl<I> Permitted<I> {
    pub fn new(inner: I, permit: tokio::sync::OwnedSemaphorePermit) -> Self {
        Self {
            inner,
            _permit: permit,
        }
    }
}

impl<I: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Permitted<I> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<I: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Permitted<I> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Send one `GET /ping` on `stream` and return the response, or `None`
    /// if the server closed the connection instead of answering.
    async fn ping(stream: &mut TcpStream) -> Option<String> {
        if stream
            .write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .is_err()
        {
            return None;
        }
        let mut buf = [0u8; 1024];
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => Some(String::from_utf8_lossy(&buf[..n]).to_string()),
            _ => None,
        }
    }

    async fn start(limits: ListenerLimits) -> (std::net::SocketAddr, watch::Sender<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let (sd_tx, sd_rx) = watch::channel(false);
        tokio::spawn(serve_http_listener("test", listener, Transport::Plain, router, limits, sd_rx));
        (addr, sd_tx)
    }

    /// The socket cap counts established idle connections: with the cap
    /// full of keep-alive connections that have each served a request, the
    /// next socket is dropped at accept, and closing one admits the next.
    #[tokio::test]
    async fn socket_cap_counts_idle_keepalive_connections() {
        let (addr, sd_tx) = start(ListenerLimits {
            sockets: SocketCap::new(2),
            idle_timeout: None,
        })
        .await;
        let mut c1 = TcpStream::connect(addr).await.unwrap();
        assert!(ping(&mut c1).await.unwrap().starts_with("HTTP/1.1 200"));
        let mut c2 = TcpStream::connect(addr).await.unwrap();
        assert!(ping(&mut c2).await.unwrap().starts_with("HTTP/1.1 200"));

        // The kernel completes the third TCP handshake from the backlog; the
        // accept loop then drops it, so the request gets no answer.
        let mut c3 = TcpStream::connect(addr).await.unwrap();
        assert!(ping(&mut c3).await.is_none(), "third socket must be dropped at capacity");

        drop(c1);
        let mut admitted = false;
        for _ in 0..100 {
            let mut c = TcpStream::connect(addr).await.unwrap();
            if ping(&mut c).await.is_some_and(|r| r.starts_with("HTTP/1.1 200")) {
                admitted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(admitted, "closing a connection must release its slot");
        let _ = sd_tx.send(true);
    }

    /// Listeners handed clones of one `ListenerLimits` share its socket cap
    /// -- Esplora's plain and TLS listeners are held to one
    /// `-esploramaxsockets` between them, not one each.
    #[test]
    fn an_oversized_socket_cap_is_clamped_not_panicking() {
        // Every cap option accepts any usize; `Semaphore::new` panics above
        // `usize::MAX >> 3`, so a typo must be clamped before it gets there.
        let cap = SocketCap::new(usize::MAX);
        assert_eq!(cap.max, CAP_CEILING);
        assert_eq!(cap.permits.available_permits(), CAP_CEILING);
        assert_eq!(clamp_cap(0), 0, "0 stays unlimited");
        assert_eq!(clamp_cap(7), 7);
    }

    #[tokio::test]
    async fn cloned_limits_share_one_socket_cap() {
        let limits = ListenerLimits {
            sockets: SocketCap::new(1),
            idle_timeout: None,
        };
        let (a, sd_a) = start(limits.clone()).await;
        let (b, sd_b) = start(limits).await;

        let mut on_a = TcpStream::connect(a).await.unwrap();
        assert!(ping(&mut on_a).await.unwrap().starts_with("HTTP/1.1 200"));
        let mut on_b = TcpStream::connect(b).await.unwrap();
        assert!(
            ping(&mut on_b).await.is_none(),
            "the one shared slot is held on the other listener"
        );

        drop(on_a);
        let mut admitted = false;
        for _ in 0..100 {
            let mut c = TcpStream::connect(b).await.unwrap();
            if ping(&mut c).await.is_some_and(|r| r.starts_with("HTTP/1.1 200")) {
                admitted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(admitted, "a slot freed on one listener serves the other");
        let _ = sd_a.send(true);
        let _ = sd_b.send(true);
    }

    /// A keep-alive connection that sends nothing for `idle_timeout` is
    /// closed by the server, which is what frees a slot held by a client
    /// that never hangs up.
    #[tokio::test]
    async fn idle_keepalive_connection_is_closed_after_the_timeout() {
        let (addr, sd_tx) = start(ListenerLimits {
            sockets: SocketCap::new(0),
            idle_timeout: Some(Duration::from_millis(200)),
        })
        .await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        assert!(ping(&mut c).await.unwrap().starts_with("HTTP/1.1 200"));
        tokio::time::sleep(Duration::from_millis(600)).await;
        let mut buf = [0u8; 16];
        let closed = matches!(
            tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        assert!(closed, "an idle keep-alive connection must be closed after the timeout");

        // Without a timeout the same connection stays open.
        let (addr, sd_tx2) = start(ListenerLimits {
            sockets: SocketCap::new(0),
            idle_timeout: None,
        })
        .await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        assert!(ping(&mut c).await.unwrap().starts_with("HTTP/1.1 200"));
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(ping(&mut c).await.unwrap().starts_with("HTTP/1.1 200"));
        let _ = sd_tx.send(true);
        let _ = sd_tx2.send(true);
    }

    /// A socket that never sends a byte is closed on the same budget, so a
    /// client that only opens sockets cannot hold slots.
    #[tokio::test]
    async fn silent_connection_is_closed_after_the_timeout() {
        let (addr, sd_tx) = start(ListenerLimits {
            sockets: SocketCap::new(0),
            idle_timeout: Some(Duration::from_millis(200)),
        })
        .await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 16];
        let closed = matches!(
            tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        assert!(closed, "a silent connection must be closed after the timeout");
        let _ = sd_tx.send(true);
    }

    /// Send `bytes`, then nothing: the connection must be closed within the
    /// 200 ms budget rather than held.
    async fn closed_after_sending(bytes: &[u8]) -> bool {
        let (addr, sd_tx) = start(ListenerLimits {
            sockets: SocketCap::new(0),
            idle_timeout: Some(Duration::from_millis(200)),
        })
        .await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(bytes).await.unwrap();
        let mut buf = [0u8; 256];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let closed = loop {
            match tokio::time::timeout_at(deadline, c.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break true,
                Ok(Ok(_)) => continue,
                Err(_) => break false,
            }
        };
        let _ = sd_tx.send(true);
        closed
    }

    /// One byte that could begin the HTTP/2 preface buys no time: the
    /// budget covers a request head from its first byte to its last.
    #[tokio::test]
    async fn a_partial_http2_preface_is_closed_after_the_timeout() {
        assert!(closed_after_sending(b"P").await, "a lone `P` held its slot");
        assert!(
            closed_after_sending(b"PRI * HTTP/2.0").await,
            "a partial preface held its slot"
        );
    }

    /// These listeners serve HTTP/1.1 only, so an HTTP/2 client that skips
    /// negotiation gets no HTTP/2 connection, and with it no way around the
    /// idle budget.
    #[tokio::test]
    async fn an_http2_preface_is_not_served_as_http2() {
        assert!(
            closed_after_sending(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await,
            "a full HTTP/2 preface was kept open"
        );
    }

    /// A router whose `/upgrade` answers 101 and then streams ten ticks, 100
    /// ms apart, on the upgraded socket while keeping a read outstanding, as a
    /// WebSocket server does.
    fn upgrade_router() -> Router {
        Router::new().route(
            "/upgrade",
            get(|mut req: axum::extract::Request| async move {
                let on_upgrade = hyper::upgrade::on(&mut req);
                tokio::spawn(async move {
                    let mut io = hyper_util::rt::TokioIo::new(on_upgrade.await.expect("upgrade"));
                    let mut ticks = ticker(10, Duration::from_millis(100));
                    let mut buf = [0u8; 64];
                    // Keep a read outstanding the whole time, as a WebSocket
                    // server does to receive frames and pongs: a deadline
                    // still armed on the upgraded socket would fire here and
                    // end the connection.
                    loop {
                        tokio::select! {
                            t = ticks.recv() => match t {
                                Some(t) => if io.write_all(&t).await.is_err() { return },
                                None => return,
                            },
                            r = io.read(&mut buf) => if !matches!(r, Ok(n) if n > 0) { return },
                        }
                    }
                });
                axum::response::Response::builder()
                    .status(101)
                    .header("connection", "upgrade")
                    .header("upgrade", "satd-test")
                    .body(axum::body::Body::empty())
                    .unwrap()
            }),
        )
    }

    async fn upgrade(c: &mut TcpStream) {
        c.write_all(
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\nUpgrade: satd-test\r\n\r\n",
        )
        .await
        .unwrap();
    }

    /// The socket cap counts an upgraded connection for as long as the
    /// socket lives. Hyper's connection future completes when it hands the
    /// socket to the upgrade, so a permit tied to that future would go back
    /// to the pool while the WebSocket stays open -- and `-streamwsmaxsockets`
    /// would bound only sockets that have not upgraded yet.
    #[tokio::test]
    async fn socket_cap_counts_upgraded_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        tokio::spawn(serve_http_listener(
            "test",
            listener,
            Transport::Plain,
            upgrade_router(),
            ListenerLimits {
                sockets: SocketCap::new(1),
                idle_timeout: None,
            },
            sd_rx,
        ));

        let mut ws = TcpStream::connect(addr).await.unwrap();
        upgrade(&mut ws).await;
        // Two ticks: the upgrade has completed and the socket is live.
        read_ticks(&mut ws, 2).await;

        let mut c = TcpStream::connect(addr).await.unwrap();
        upgrade(&mut c).await;
        let mut buf = [0u8; 64];
        let refused = matches!(
            tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        assert!(refused, "the upgraded socket must still hold the only slot");

        // The upgraded socket closing returns its slot.
        drop(ws);
        let mut admitted = false;
        for _ in 0..100 {
            let mut c = TcpStream::connect(addr).await.unwrap();
            upgrade(&mut c).await;
            let mut buf = [0u8; 64];
            if matches!(
                tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await,
                Ok(Ok(n)) if n > 0
            ) {
                admitted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(admitted, "closing the upgraded socket must release its slot");
        let _ = sd_tx.send(true);
    }

    /// Server-written ticks, one every `every`, `n` in all: the shape of an
    /// SSE feed or a WebSocket the client only reads.
    fn ticker(n: usize, every: Duration) -> tokio::sync::mpsc::Receiver<bytes::Bytes> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            for i in 0..n {
                tokio::time::sleep(every).await;
                if tx.send(bytes::Bytes::from(format!("tick {i}\n"))).await.is_err() {
                    return;
                }
            }
        });
        rx
    }

    struct TickBody(tokio::sync::mpsc::Receiver<bytes::Bytes>);

    impl hyper::body::Body for TickBody {
        type Data = bytes::Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            self.0.poll_recv(cx).map(|t| t.map(|b| Ok(hyper::body::Frame::data(b))))
        }
    }

    /// Read from `c` until `want` ticks have arrived, failing if the server
    /// closes the connection first. Returns everything read.
    async fn read_ticks(c: &mut TcpStream, want: usize) -> String {
        let mut got = String::new();
        let mut buf = [0u8; 1024];
        while got.matches("tick ").count() < want {
            let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
                .await
                .expect("a tick within 5s")
                .expect("read");
            assert!(n > 0, "server closed the connection after: {got:?}");
            got.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        got
    }

    /// The idle budget guards the wait for a request head and nothing after
    /// it. A connection upgraded by its first request (a WebSocket) on which
    /// only the server writes outlives the budget many times over, with a
    /// read held outstanding the whole time.
    #[tokio::test]
    async fn an_upgraded_connection_the_client_only_reads_is_not_timed_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = upgrade_router();
        let (sd_tx, sd_rx) = watch::channel(false);
        tokio::spawn(serve_http_listener(
            "test",
            listener,
            Transport::Plain,
            router,
            ListenerLimits {
                sockets: SocketCap::new(0),
                idle_timeout: Some(Duration::from_millis(200)),
            },
            sd_rx,
        ));

        let mut c = TcpStream::connect(addr).await.unwrap();
        upgrade(&mut c).await;
        // Ten ticks 100 ms apart: a second of server-only traffic against a
        // 200 ms budget.
        let got = read_ticks(&mut c, 10).await;
        assert!(got.starts_with("HTTP/1.1 101"), "{got:?}");
        let _ = sd_tx.send(true);
    }

    /// The same for a long-lived streaming response (an SSE feed): once the
    /// request has arrived, a response the server keeps writing is not cut
    /// off by the idle budget, however long it runs.
    #[tokio::test]
    async fn a_streaming_response_outlives_the_idle_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route(
            "/stream",
            get(|| async {
                axum::body::Body::new(TickBody(ticker(10, Duration::from_millis(100))))
            }),
        );
        let (sd_tx, sd_rx) = watch::channel(false);
        tokio::spawn(serve_http_listener(
            "test",
            listener,
            Transport::Plain,
            router,
            ListenerLimits {
                sockets: SocketCap::new(0),
                idle_timeout: Some(Duration::from_millis(200)),
            },
            sd_rx,
        ));

        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let got = read_ticks(&mut c, 10).await;
        assert!(got.starts_with("HTTP/1.1 200"), "{got:?}");
        let _ = sd_tx.send(true);
    }

    /// Shutdown stops the accept loop and closes idle connections.
    #[tokio::test]
    async fn shutdown_closes_idle_connections() {
        let (addr, sd_tx) = start(ListenerLimits {
            sockets: SocketCap::new(0),
            idle_timeout: None,
        })
        .await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        assert!(ping(&mut c).await.unwrap().starts_with("HTTP/1.1 200"));
        let _ = sd_tx.send(true);
        let mut buf = [0u8; 16];
        let closed = matches!(
            tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        assert!(closed, "shutdown must close an idle connection");
    }
}
