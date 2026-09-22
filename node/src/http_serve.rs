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

/// A listener's socket cap and idle budget.
#[derive(Clone, Copy, Debug)]
pub struct ListenerLimits {
    /// Open sockets, counted at accept. `0` is unlimited.
    pub max_sockets: usize,
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
    let cap = Arc::new(Semaphore::new(if limits.max_sockets == 0 {
        Semaphore::MAX_PERMITS
    } else {
        limits.max_sockets
    }));
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
        // parsed. At capacity the socket is dropped (the client sees a TCP
        // reset) rather than queued: queuing would let a flood hold memory.
        let permit = match cap.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                if let Some(suppressed) = at_capacity.tick() {
                    tracing::warn!(
                        surface,
                        peer = %peer,
                        suppressed,
                        "at-capacity rejection ({} max sockets)",
                        limits.max_sockets,
                    );
                }
                drop(stream);
                continue;
            }
        };
        let service = service.clone();
        let transport = transport.clone();
        let mut conn_shutdown = shutdown.clone();
        tokio::spawn(async move {
            // Held until this task ends, which is when the connection ends.
            let _permit = permit;
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
    stream: TcpStream,
    peer: std::net::SocketAddr,
) -> Option<tokio_rustls::server::TlsStream<TcpStream>> {
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
/// slot forever. HTTP/2 gets the same budget as a keep-alive ping deadline.
/// The same budget bounds the wait for the connection's very first byte,
/// which hyper's timer does not cover (see [`FirstByteDeadline`]).
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
    // hyper-util's auto builder sniffs the protocol version before HTTP/1's
    // header timer is armed, so a socket that never sends a byte would sit
    // in that sniff forever, holding its connection slot. The first byte
    // gets the same budget as a request head.
    let io = hyper_util::rt::TokioIo::new(FirstByteDeadline {
        inner: io,
        deadline: header_read_timeout.map(|t| Box::pin(tokio::time::sleep(t))),
    });

    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    if let Some(timeout) = header_read_timeout {
        // hyper's timer is armed each time a request head is awaited, so this
        // covers both the first head and the idle gap before the next request
        // on a keep-alive connection. It stops once the head is complete: the
        // body phase is bounded in the compat layer instead, because that is
        // where satd reads the body and hyper offers no body-read timeout.
        builder
            .http1()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(timeout)
            // A keep-alive connection that goes quiet is closed on the same
            // budget, which is what an operator setting this expects.
            .keep_alive(true);
        builder
            .http2()
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(Some(timeout))
            .keep_alive_timeout(timeout);
    }
    let conn = builder.serve_connection_with_upgrades(io, service);

    tokio::pin!(stopped, conn);

    tokio::select! {
        result = &mut conn => result,
        () = stopped => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    }
}


/// A transport whose first byte must arrive within a deadline; after it
/// has, reads are passed through untouched. Writes always pass through.
struct FirstByteDeadline<I> {
    inner: I,
    /// `None` once the first byte has arrived (or when no budget applies).
    deadline: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

impl<I: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for FirstByteDeadline<I> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::future::Future;
        if let Some(sleep) = self.deadline.as_mut()
            && sleep.as_mut().poll(cx).is_ready()
        {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no request arrived within the idle budget",
            )));
        }
        let before = buf.filled().len();
        let res = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(res, std::task::Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.deadline = None;
        }
        res
    }
}

impl<I: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for FirstByteDeadline<I> {
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
            max_sockets: 2,
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

    /// A keep-alive connection that sends nothing for `idle_timeout` is
    /// closed by the server, which is what frees a slot held by a client
    /// that never hangs up.
    #[tokio::test]
    async fn idle_keepalive_connection_is_closed_after_the_timeout() {
        let (addr, sd_tx) = start(ListenerLimits {
            max_sockets: 0,
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
            max_sockets: 0,
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
            max_sockets: 0,
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

    /// The first-byte deadline guards the wait for a request and nothing
    /// after it. A connection upgraded by its first request (a WebSocket)
    /// on which only the server writes outlives the idle budget many times
    /// over: the upgrade request is read through the deadline wrapper -- the
    /// version sniff reads it from the socket, not from some other buffer --
    /// so its first byte disarms the deadline for good.
    #[tokio::test]
    async fn an_upgraded_connection_the_client_only_reads_is_not_timed_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route(
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
        );
        let (sd_tx, sd_rx) = watch::channel(false);
        tokio::spawn(serve_http_listener(
            "test",
            listener,
            Transport::Plain,
            router,
            ListenerLimits {
                max_sockets: 0,
                idle_timeout: Some(Duration::from_millis(200)),
            },
            sd_rx,
        ));

        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\nUpgrade: satd-test\r\n\r\n",
        )
        .await
        .unwrap();
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
                max_sockets: 0,
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
            max_sockets: 0,
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
