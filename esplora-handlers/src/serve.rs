//! The Esplora listeners: plain HTTP and TLS, both served through
//! [`node::http_serve`], which caps open sockets at accept and closes a
//! keep-alive connection that goes idle.
//!
//! Esplora used to be served by `axum::serve`, which bounds nothing at the
//! socket level: `--esploramaxconns` is a per-request concurrency limit
//! and the SSE cap counts streams, so a client that opened connections and
//! never closed them was limited only by the process's file-descriptor
//! table — and `axum::serve` builds hyper without a timer, so an idle
//! keep-alive connection was never closed. The TLS handshake also ran
//! inline in the accept loop, so one slow client stalled every other
//! connection for the handshake budget. The shared loop takes a permit per
//! socket, runs each handshake on the connection's own task, and applies
//! `--esplorarequesttimeout` as the idle budget.

use std::time::Duration;

use axum::Router;
use node::http_serve::{ListenerLimits, TlsTransport, Transport, serve_http_listener};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

/// Serve `router` on the plain listener until `shutdown` flips.
pub async fn serve_plain(
    listener: TcpListener,
    router: Router,
    limits: ListenerLimits,
    shutdown: watch::Receiver<bool>,
) {
    serve_http_listener("esplora", listener, Transport::Plain, router, limits, shutdown).await
}

/// Serve `router` on the TLS listener until `shutdown` flips.
///
/// When `mtls_enabled` is `true` the acceptor was built with
/// `ClientAuthPolicy::Required`, so rustls refuses any client without a
/// CA-signed certificate at handshake time; after the handshake the client
/// is logged and checked against `allow` (case-insensitive CN / DNS-SAN),
/// which short-circuits when empty so the CA bundle stays the only gate.
#[allow(clippy::too_many_arguments)]
pub async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    handshake_timeout: Duration,
    mtls_enabled: bool,
    allow: tls_config::ClientAllowList,
    router: Router,
    limits: ListenerLimits,
    shutdown: watch::Receiver<bool>,
) {
    let transport = Transport::Tls(TlsTransport {
        acceptor,
        handshake_timeout,
        mtls_enabled,
        allow,
    });
    serve_http_listener("esplora-tls", listener, transport, router, limits, shutdown).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::io::Write;
    use tls_config::{ClientAuthPolicy, build_acceptor};

    fn no_limits() -> ListenerLimits {
        ListenerLimits {
            sockets: node::http_serve::SocketCap::new(0),
            idle_timeout: None,
        }
    }

    fn write_pem(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::File::create(&p)
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        p
    }

    fn ping_router() -> Router {
        Router::new().route("/ping", get(|| async { "pong" }))
    }

    /// End-to-end: the TLS listener serves real HTTPS requests. Uses a
    /// self-signed cert minted in-test and a reqwest client that trusts
    /// that root. Mirrors the Electrum-server `tls_round_trips_a_request`
    /// test so future readers see the same shape on both surfaces.
    #[tokio::test]
    async fn tls_listener_serves_https_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let acceptor = build_acceptor(&cert_path, &key_path, &ClientAuthPolicy::Disabled).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = tcp.local_addr().unwrap();

        let (sd_tx, sd_rx) = watch::channel(false);
        let serve = tokio::spawn(serve_tls(
            tcp,
            acceptor,
            Duration::from_secs(5),
            false,
            tls_config::ClientAllowList::default(),
            ping_router(),
            no_limits(),
            sd_rx,
        ));

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

    /// A bare TCP connection (no TLS handshake) is dropped after the
    /// handshake timeout, and — because each handshake runs on its own
    /// task — a real HTTPS request succeeds *during* the bogus client's
    /// handshake window, not just after it.
    #[tokio::test]
    async fn tls_listener_drops_bare_tcp_after_handshake_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let acceptor = build_acceptor(&cert_path, &key_path, &ClientAuthPolicy::Disabled).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = tcp.local_addr().unwrap();

        let (sd_tx, sd_rx) = watch::channel(false);
        let serve = tokio::spawn(serve_tls(
            tcp,
            acceptor,
            Duration::from_secs(2),
            false,
            tls_config::ClientAllowList::default(),
            ping_router(),
            no_limits(),
            sd_rx,
        ));

        // Connect plain TCP and write nothing. The accept loop must not
        // wait on that handshake: a real request goes through at once.
        let mut bogus = tokio::net::TcpStream::connect(local).await.unwrap();
        let cert_pem = cert.cert.pem();
        let root = reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(root)
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        let url = format!("https://localhost:{}/ping", local.port());
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200);

        // After the budget the silent client is gone: its socket reads EOF.
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 8];
        let closed = matches!(
            tokio::time::timeout(Duration::from_secs(5), bogus.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        assert!(closed, "silent client must be dropped after the handshake timeout");

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

    /// An mTLS server (CA-signed client certs required, optional allowlist)
    /// bound on a free port, plus a client leaf with the given CN.
    struct MtlsFixture {
        local: std::net::SocketAddr,
        ca_pem: String,
        client_identity_pem: String,
        sd_tx: watch::Sender<bool>,
        serve: tokio::task::JoinHandle<()>,
    }

    async fn mtls_server(client_cn: &str, allow: Vec<String>) -> MtlsFixture {
        let dir = tempfile::tempdir().unwrap();
        let (ca_cert, ca_kp, server_cert, server_kp) = mint_ca_and_leaf("localhost", "server");
        let mut client_params =
            rcgen::CertificateParams::new(vec![format!("{client_cn}.test")]).unwrap();
        client_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, client_cn);
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
        let (sd_tx, sd_rx) = watch::channel(false);
        let serve = tokio::spawn(serve_tls(
            tcp,
            acceptor,
            Duration::from_secs(5),
            true,
            tls_config::ClientAllowList::new(allow),
            ping_router(),
            no_limits(),
            sd_rx,
        ));
        // The tempdir may go; the acceptor has read the PEM files already.
        let mut client_identity_pem = client_cert.pem();
        client_identity_pem.push_str(&client_kp.serialize_pem());
        MtlsFixture {
            local,
            ca_pem: ca_cert.pem(),
            client_identity_pem,
            sd_tx,
            serve,
        }
    }

    impl MtlsFixture {
        /// A reqwest client trusting the CA, presenting the client leaf
        /// when `with_identity`.
        fn client(&self, with_identity: bool) -> reqwest::Client {
            let root = reqwest::Certificate::from_pem(self.ca_pem.as_bytes()).unwrap();
            // Workspace feature unification can pull in both native-tls and
            // rustls-tls. Force rustls because `Identity::from_pem` is
            // rustls-only — without this the client backend defaults to
            // native-tls and the identity is rejected with "incompatible
            // TLS identity type".
            let mut b = reqwest::Client::builder()
                .use_rustls_tls()
                .add_root_certificate(root)
                .timeout(Duration::from_secs(2));
            if with_identity {
                let identity =
                    reqwest::Identity::from_pem(self.client_identity_pem.as_bytes()).unwrap();
                b = b.identity(identity);
            }
            b.build().unwrap()
        }

        fn url(&self) -> String {
            format!("https://localhost:{}/ping", self.local.port())
        }

        async fn stop(self) {
            self.sd_tx.send(true).unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(2), self.serve).await;
        }
    }

    /// mTLS happy path: server requires CA-signed client cert; client
    /// presents a valid leaf. The HTTPS request round-trips end to end.
    #[tokio::test]
    async fn mtls_round_trip_with_valid_client_cert() {
        let f = mtls_server("alice", vec![]).await;
        let resp = f.client(true).get(f.url()).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "pong");
        f.stop().await;
    }

    /// mTLS rejection: server requires a client cert; client presents
    /// none. The server-side verifier refuses the handshake; reqwest
    /// surfaces a connection-level error rather than a JSON response.
    #[tokio::test]
    async fn mtls_rejects_request_without_client_cert() {
        let f = mtls_server("alice", vec![]).await;
        let result = f.client(false).get(f.url()).send().await;
        assert!(
            result.is_err(),
            "mTLS-required server should refuse client with no cert; got: {result:?}",
        );
        f.stop().await;
    }

    /// Allowlist happy path: matching CN passes the post-handshake
    /// check, HTTPS request succeeds.
    #[tokio::test]
    async fn mtls_allowlist_accepts_matching_cn() {
        let f = mtls_server("alice", vec!["alice".to_string(), "bob".to_string()]).await;
        let resp = f.client(true).get(f.url()).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        f.stop().await;
    }

    /// Allowlist rejection: handshake succeeds (CA-signed), but CN/SAN
    /// aren't in the allowlist. The connection is dropped before any HTTP
    /// is served; reqwest gets a connection-level error (reset / EOF).
    #[tokio::test]
    async fn mtls_allowlist_drops_unlisted_principal() {
        let f = mtls_server("mallory", vec!["alice".to_string(), "bob".to_string()]).await;
        let result = f.client(true).get(f.url()).send().await;
        assert!(
            result.is_err(),
            "allowlist should drop unlisted principal; got: {result:?}",
        );
        f.stop().await;
    }

    /// The socket cap counts TLS connections that completed their
    /// handshake and sit idle: the next one is dropped at accept.
    #[tokio::test]
    async fn tls_socket_cap_counts_idle_connections() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let acceptor = build_acceptor(&cert_path, &key_path, &ClientAuthPolicy::Disabled).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = tcp.local_addr().unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let serve = tokio::spawn(serve_tls(
            tcp,
            acceptor,
            Duration::from_secs(5),
            false,
            tls_config::ClientAllowList::default(),
            ping_router(),
            ListenerLimits {
                sockets: node::http_serve::SocketCap::new(2),
                idle_timeout: None,
            },
            sd_rx,
        ));

        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let connect = || async {
            let tcp = tokio::net::TcpStream::connect(local).await.unwrap();
            let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
            tokio::time::timeout(Duration::from_secs(5), connector.connect(name, tcp))
                .await
                .expect("handshake within 5s")
        };
        // Two connections each serve a request and then sit idle.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut held = Vec::new();
        for _ in 0..2 {
            let mut s = connect().await.expect("connection within the cap");
            s.write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            let mut buf = [0u8; 512];
            let n = s.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
            held.push(s);
        }
        // The third is dropped at accept: its handshake fails on a closed
        // socket rather than timing out.
        match connect().await {
            Ok(_) => panic!("third connection must be refused at the socket cap"),
            Err(e) => assert_ne!(e.kind(), std::io::ErrorKind::TimedOut, "{e}"),
        }
        // Closing one admits the next.
        drop(held.pop());
        let mut admitted = false;
        for _ in 0..100 {
            if connect().await.is_ok() {
                admitted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(admitted, "closing a connection must release its slot");

        sd_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
    }
}
