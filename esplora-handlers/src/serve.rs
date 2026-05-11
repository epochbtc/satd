//! TLS-aware listener for the Esplora HTTP server.
//!
//! Wraps a [`tokio::net::TcpListener`] + [`tokio_rustls::TlsAcceptor`]
//! and implements [`axum::serve::Listener`] so the same
//! `axum::serve(listener, router)` call serves either transport. We
//! retry on accept errors and on handshake failures (logged at
//! `debug` for handshake errors, `warn` for accept errors) because
//! the [`axum::serve::Listener`] contract is "yields the next ready
//! connection", not "yields a `Result`".
//!
//! The handshake is bounded by `handshake_timeout` so a half-open
//! client can't pin the accept loop indefinitely; on timeout the
//! socket is dropped and we move on. Mirrors the Electrum-server
//! handshake-timeout guard.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// Listener that completes the TLS handshake before returning each
/// connection. Yields the inner peer [`SocketAddr`] so downstream
/// middleware (request tracing, rate limiting) sees the real client
/// IP rather than the TLS terminator's loopback address.
pub struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
    handshake_timeout: Duration,
}

impl TlsListener {
    pub fn new(inner: TcpListener, acceptor: TlsAcceptor, handshake_timeout: Duration) -> Self {
        Self {
            inner,
            acceptor,
            handshake_timeout,
        }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, peer) = match self.inner.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "Esplora TLS accept error");
                    // Mirror axum's built-in TcpListener accept retry:
                    // brief sleep on transient errors so an EMFILE
                    // storm doesn't busy-loop.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            match tokio::time::timeout(self.handshake_timeout, self.acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => return (tls_stream, peer),
                Ok(Err(e)) => {
                    tracing::debug!(peer = %peer, error = %e, "Esplora TLS handshake failed");
                    continue;
                }
                Err(_elapsed) => {
                    tracing::warn!(
                        peer = %peer,
                        timeout_secs = self.handshake_timeout.as_secs(),
                        "Esplora TLS handshake timed out — closing connection",
                    );
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_config::build_acceptor;
    use axum::Router;
    use axum::routing::get;
    use std::io::Write;
    use tokio::sync::watch;

    fn write_pem(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::File::create(&p)
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        p
    }

    /// End-to-end test that proves the `TlsListener` + `axum::serve`
    /// pairing serves real HTTPS requests. Uses a self-signed cert
    /// minted in-test and a reqwest client that trusts that root.
    /// Mirrors the Electrum-server `tls_round_trips_a_request` test
    /// so future readers see the same shape on both surfaces.
    #[tokio::test]
    async fn tls_listener_serves_https_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let acceptor = build_acceptor(&cert_path, &key_path).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = tcp.local_addr().unwrap();
        let listener = TlsListener::new(tcp, acceptor, Duration::from_secs(5));

        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let (sd_tx, mut sd_rx) = watch::channel(false);
        let serve = tokio::spawn(async move {
            let s = axum::serve(listener, router).with_graceful_shutdown(async move {
                let _ = sd_rx.changed().await;
            });
            let _ = s.await;
        });

        // Build a reqwest client that trusts our self-signed cert.
        // `add_root_certificate` is the right knob here — disabling
        // cert validation entirely would make this test pass against
        // any wrong cert, which defeats its purpose.
        let cert_pem = cert.cert.pem();
        let root = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(root)
            .build()
            .unwrap();
        let url = format!("https://localhost:{}/ping", local.port());
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "pong");

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
    }

    /// A bare TCP connection (no TLS handshake) should be dropped
    /// after the handshake timeout. The listener must keep accepting
    /// — a half-open client can't wedge the accept loop.
    #[tokio::test]
    async fn tls_listener_drops_bare_tcp_after_handshake_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let acceptor = build_acceptor(&cert_path, &key_path).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = tcp.local_addr().unwrap();
        // Short timeout — keep the test fast.
        let listener = TlsListener::new(tcp, acceptor, Duration::from_millis(200));

        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let (sd_tx, mut sd_rx) = watch::channel(false);
        let serve = tokio::spawn(async move {
            let s = axum::serve(listener, router).with_graceful_shutdown(async move {
                let _ = sd_rx.changed().await;
            });
            let _ = s.await;
        });

        // Connect plain TCP and write nothing. Server should time
        // out the handshake and move on. After the timeout window,
        // a real HTTPS request must still succeed (proves the accept
        // loop survived the bogus client).
        let _bogus = tokio::net::TcpStream::connect(local).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let cert_pem = cert.cert.pem();
        let root = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(root)
            .build()
            .unwrap();
        let url = format!("https://localhost:{}/ping", local.port());
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
    }
}
