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
///
/// When `mtls_enabled` is `true` the acceptor was built with
/// `ClientAuthPolicy::Required` and the rustls verifier rejects any
/// client without a CA-signed cert at handshake time. After the
/// handshake the listener additionally applies `allow` (case-
/// insensitive CN / DNS-SAN check); an `is_empty()` allowlist makes
/// the check a no-op so the CA bundle remains the only gate. Both
/// reject paths drop the connection silently and continue accepting.
pub struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
    handshake_timeout: Duration,
    mtls_enabled: bool,
    allow: tls_config::ClientAllowList,
}

impl TlsListener {
    /// Backwards-compatible constructor — plain TLS (no mTLS). Kept so
    /// existing call sites (tests, downstream embedders) don't break.
    pub fn new(inner: TcpListener, acceptor: TlsAcceptor, handshake_timeout: Duration) -> Self {
        Self::new_with_mtls(
            inner,
            acceptor,
            handshake_timeout,
            false,
            tls_config::ClientAllowList::default(),
        )
    }

    /// Construct a listener that also enforces the mTLS allowlist
    /// after a successful handshake. `mtls_enabled` controls only the
    /// audit-log "client accepted" line (rustls is what actually
    /// enforces the handshake gate); the allowlist is applied
    /// regardless and short-circuits when empty.
    pub fn new_with_mtls(
        inner: TcpListener,
        acceptor: TlsAcceptor,
        handshake_timeout: Duration,
        mtls_enabled: bool,
        allow: tls_config::ClientAllowList,
    ) -> Self {
        Self {
            inner,
            acceptor,
            handshake_timeout,
            mtls_enabled,
            allow,
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
            let tls_stream = match tokio::time::timeout(
                self.handshake_timeout,
                self.acceptor.accept(stream),
            )
            .await
            {
                Ok(Ok(s)) => s,
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
            };
            // mTLS post-handshake checks. The audit log fires for any
            // mTLS-enabled accept; the allowlist check is an additional
            // narrowing applied even when mTLS is "off" (it's a no-op
            // with the default empty list, so the plain-TLS path stays
            // untouched).
            let (_, server_conn) = tls_stream.get_ref();
            if self.mtls_enabled
                && let Some(subject) = tls_config::peer_subject_label(server_conn)
            {
                tracing::info!(
                    peer = %peer,
                    subject = %subject,
                    "Esplora mTLS client accepted",
                );
            }
            if let Err(rej) = tls_config::check_peer_allowed(server_conn, &self.allow) {
                tracing::warn!(
                    peer = %peer,
                    subject = %rej.subject_label,
                    "Esplora mTLS client rejected by allowlist",
                );
                continue;
            }
            return (tls_stream, peer);
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_config::{ClientAuthPolicy, build_acceptor};
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
        let acceptor = build_acceptor(&cert_path, &key_path, &ClientAuthPolicy::Disabled).unwrap();
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
        let acceptor = build_acceptor(&cert_path, &key_path, &ClientAuthPolicy::Disabled).unwrap();
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

    /// Helper: mint a CA + a leaf signed by it. Matches the Electrum
    /// test helper so reviewers can recognize the pattern. The CA's
    /// `is_ca` + `KeyCertSign` is what lets it issue further leaves.
    fn mint_ca_and_leaf(
        leaf_dns: &str,
        leaf_cn: &str,
    ) -> (
        rcgen::Certificate,
        rcgen::KeyPair,
        rcgen::Certificate,
        rcgen::KeyPair,
    ) {
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-ca");
        let ca_kp = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();

        let mut leaf_params = rcgen::CertificateParams::new(vec![leaf_dns.to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, leaf_cn);
        let leaf_kp = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_kp, &ca_cert, &ca_kp).unwrap();
        (ca_cert, ca_kp, leaf_cert, leaf_kp)
    }

    /// mTLS happy path: server requires CA-signed client cert; client
    /// presents a valid leaf via reqwest `Identity`. The HTTPS request
    /// round-trips end to end.
    #[tokio::test]
    async fn mtls_round_trip_with_valid_client_cert() {
        let dir = tempfile::tempdir().unwrap();
        let (ca_cert, ca_kp, server_cert, server_kp) = mint_ca_and_leaf("localhost", "server");
        let mut client_params =
            rcgen::CertificateParams::new(vec!["alice.test".to_string()]).unwrap();
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "alice");
        let client_kp = rcgen::KeyPair::generate().unwrap();
        let client_cert = client_params
            .signed_by(&client_kp, &ca_cert, &ca_kp)
            .unwrap();

        let cert_path = write_pem(dir.path(), "server.pem", &server_cert.pem());
        let key_path = write_pem(dir.path(), "server.key.pem", &server_kp.serialize_pem());
        let ca_path = write_pem(dir.path(), "ca.pem", &ca_cert.pem());
        let acceptor = build_acceptor(
            &cert_path,
            &key_path,
            &ClientAuthPolicy::Required {
                ca_path: ca_path.clone(),
            },
        )
        .unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = tcp.local_addr().unwrap();
        let listener = TlsListener::new_with_mtls(
            tcp,
            acceptor,
            Duration::from_secs(5),
            true,
            tls_config::ClientAllowList::default(),
        );

        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let (sd_tx, mut sd_rx) = watch::channel(false);
        let serve = tokio::spawn(async move {
            let s = axum::serve(listener, router).with_graceful_shutdown(async move {
                let _ = sd_rx.changed().await;
            });
            let _ = s.await;
        });

        let mut id_pem = client_cert.pem();
        id_pem.push_str(&client_kp.serialize_pem());
        let identity = reqwest::Identity::from_pem(id_pem.as_bytes()).unwrap();
        let root = reqwest::Certificate::from_pem(ca_cert.pem().as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            // Workspace feature unification can pull in both
            // native-tls and rustls-tls. Force rustls here because
            // `Identity::from_pem` is rustls-only — without this the
            // client backend defaults to native-tls and the identity
            // is rejected with "incompatible TLS identity type".
            .use_rustls_tls()
            .add_root_certificate(root)
            .identity(identity)
            .build()
            .unwrap();
        let url = format!("https://localhost:{}/ping", local.port());
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "pong");

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
    }

    /// mTLS rejection: server requires client cert; client presents
    /// none. The server-side verifier refuses the handshake; reqwest
    /// surfaces a connection-level error rather than a JSON response.
    #[tokio::test]
    async fn mtls_rejects_request_without_client_cert() {
        let dir = tempfile::tempdir().unwrap();
        let (ca_cert, _ca_kp, server_cert, server_kp) = mint_ca_and_leaf("localhost", "server");
        let cert_path = write_pem(dir.path(), "server.pem", &server_cert.pem());
        let key_path = write_pem(dir.path(), "server.key.pem", &server_kp.serialize_pem());
        let ca_path = write_pem(dir.path(), "ca.pem", &ca_cert.pem());
        let acceptor = build_acceptor(
            &cert_path,
            &key_path,
            &ClientAuthPolicy::Required { ca_path },
        )
        .unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = tcp.local_addr().unwrap();
        let listener = TlsListener::new_with_mtls(
            tcp,
            acceptor,
            Duration::from_secs(5),
            true,
            tls_config::ClientAllowList::default(),
        );

        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let (sd_tx, mut sd_rx) = watch::channel(false);
        let serve = tokio::spawn(async move {
            let s = axum::serve(listener, router).with_graceful_shutdown(async move {
                let _ = sd_rx.changed().await;
            });
            let _ = s.await;
        });

        let root = reqwest::Certificate::from_pem(ca_cert.pem().as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            // Force rustls for backend consistency with the other
            // mTLS tests — see the use_rustls_tls comment above.
            .use_rustls_tls()
            .add_root_certificate(root)
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let url = format!("https://localhost:{}/ping", local.port());
        let result = client.get(&url).send().await;
        assert!(
            result.is_err(),
            "mTLS-required server should refuse client with no cert; got: {result:?}",
        );

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
    }

    /// Allowlist happy path: matching CN passes the post-handshake
    /// check, HTTPS request succeeds.
    #[tokio::test]
    async fn mtls_allowlist_accepts_matching_cn() {
        let dir = tempfile::tempdir().unwrap();
        let (ca_cert, ca_kp, server_cert, server_kp) = mint_ca_and_leaf("localhost", "server");
        let mut client_params =
            rcgen::CertificateParams::new(vec!["alice.test".to_string()]).unwrap();
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "alice");
        let client_kp = rcgen::KeyPair::generate().unwrap();
        let client_cert = client_params
            .signed_by(&client_kp, &ca_cert, &ca_kp)
            .unwrap();

        let cert_path = write_pem(dir.path(), "server.pem", &server_cert.pem());
        let key_path = write_pem(dir.path(), "server.key.pem", &server_kp.serialize_pem());
        let ca_path = write_pem(dir.path(), "ca.pem", &ca_cert.pem());
        let acceptor = build_acceptor(
            &cert_path,
            &key_path,
            &ClientAuthPolicy::Required { ca_path },
        )
        .unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = tcp.local_addr().unwrap();
        let allow = tls_config::ClientAllowList::new(vec![
            "alice".to_string(),
            "bob".to_string(),
        ]);
        let listener =
            TlsListener::new_with_mtls(tcp, acceptor, Duration::from_secs(5), true, allow);

        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let (sd_tx, mut sd_rx) = watch::channel(false);
        let serve = tokio::spawn(async move {
            let s = axum::serve(listener, router).with_graceful_shutdown(async move {
                let _ = sd_rx.changed().await;
            });
            let _ = s.await;
        });

        let mut id_pem = client_cert.pem();
        id_pem.push_str(&client_kp.serialize_pem());
        let identity = reqwest::Identity::from_pem(id_pem.as_bytes()).unwrap();
        let root = reqwest::Certificate::from_pem(ca_cert.pem().as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            // Workspace feature unification can pull in both
            // native-tls and rustls-tls. Force rustls here because
            // `Identity::from_pem` is rustls-only — without this the
            // client backend defaults to native-tls and the identity
            // is rejected with "incompatible TLS identity type".
            .use_rustls_tls()
            .add_root_certificate(root)
            .identity(identity)
            .build()
            .unwrap();
        let url = format!("https://localhost:{}/ping", local.port());
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
    }

    /// Allowlist rejection: handshake succeeds (CA-signed), but
    /// CN/SAN aren't in the allowlist. The listener drops the
    /// connection before yielding it to axum; reqwest gets a
    /// connection-level error (timeout / reset) rather than HTTP.
    #[tokio::test]
    async fn mtls_allowlist_drops_unlisted_principal() {
        let dir = tempfile::tempdir().unwrap();
        let (ca_cert, ca_kp, server_cert, server_kp) = mint_ca_and_leaf("localhost", "server");
        let mut client_params =
            rcgen::CertificateParams::new(vec!["mallory.test".to_string()]).unwrap();
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "mallory");
        let client_kp = rcgen::KeyPair::generate().unwrap();
        let client_cert = client_params
            .signed_by(&client_kp, &ca_cert, &ca_kp)
            .unwrap();

        let cert_path = write_pem(dir.path(), "server.pem", &server_cert.pem());
        let key_path = write_pem(dir.path(), "server.key.pem", &server_kp.serialize_pem());
        let ca_path = write_pem(dir.path(), "ca.pem", &ca_cert.pem());
        let acceptor = build_acceptor(
            &cert_path,
            &key_path,
            &ClientAuthPolicy::Required { ca_path },
        )
        .unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = tcp.local_addr().unwrap();
        let allow = tls_config::ClientAllowList::new(vec![
            "alice".to_string(),
            "bob".to_string(),
        ]);
        let listener =
            TlsListener::new_with_mtls(tcp, acceptor, Duration::from_secs(5), true, allow);

        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let (sd_tx, mut sd_rx) = watch::channel(false);
        let serve = tokio::spawn(async move {
            let s = axum::serve(listener, router).with_graceful_shutdown(async move {
                let _ = sd_rx.changed().await;
            });
            let _ = s.await;
        });

        let mut id_pem = client_cert.pem();
        id_pem.push_str(&client_kp.serialize_pem());
        let identity = reqwest::Identity::from_pem(id_pem.as_bytes()).unwrap();
        let root = reqwest::Certificate::from_pem(ca_cert.pem().as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            // Workspace feature unification can pull in both
            // native-tls and rustls-tls. Force rustls here because
            // `Identity::from_pem` is rustls-only — without this the
            // client backend defaults to native-tls and the identity
            // is rejected with "incompatible TLS identity type".
            .use_rustls_tls()
            .add_root_certificate(root)
            .identity(identity)
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let url = format!("https://localhost:{}/ping", local.port());
        let result = client.get(&url).send().await;
        assert!(
            result.is_err(),
            "allowlist should drop unlisted principal; got: {result:?}",
        );

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
    }
}
