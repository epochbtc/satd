//! The HTTP listeners budget the "TLS handshake timed out" warning: the first
//! five a minute per listener are logged and the rest counted, as the
//! at-capacity refusals are. Unbudgeted, a client opening sockets and
//! sending nothing drove one line per socket, about 34 a second on Esplora
//! with its defaults.
//!
//! Its own test binary because the log capture needs a process-wide
//! subscriber (see `Logs`). The accept-error budget has a binary of its
//! own, `accept_error_budget.rs`, because it lowers the process's
//! file-descriptor limit.

use std::time::Duration;

use node::http_serve::{ListenerLimits, SocketCap, TlsTransport, Transport, serve_http_listener};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

thread_local! {
    static THREAD_LOGS: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

struct ThreadLogs;

impl std::io::Write for ThreadLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        THREAD_LOGS.with(|l| l.borrow_mut().extend_from_slice(buf));
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One process-wide subscriber writing into a per-thread buffer, never a
/// scoped `set_default`: whether a `warn!` is evaluated at all is decided by
/// tracing's process-wide callsite interest, which a scoped subscriber on
/// any thread moves. Each `#[tokio::test]` runs on its own thread with a
/// current-thread runtime, so the buffer is the test's own, and the
/// listener's tasks write into it too.
struct Logs;

impl Logs {
    fn capture() -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            use tracing_subscriber::layer::SubscriberExt as _;
            use tracing_subscriber::util::SubscriberInitExt as _;
            let _ = tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(|| ThreadLogs),
                )
                .with(tracing_subscriber::filter::LevelFilter::TRACE)
                .try_init();
        });
        THREAD_LOGS.with(|l| l.borrow_mut().clear());
        Logs
    }

    fn count(&self, needle: &str) -> usize {
        THREAD_LOGS.with(|l| String::from_utf8_lossy(&l.borrow()).matches(needle).count())
    }
}

fn limits() -> ListenerLimits {
    ListenerLimits {
        sockets: SocketCap::new(0),
        idle_timeout: None,
        write_timeout: None,
    }
}

/// A TLS listener with a 50 ms handshake budget, on its own port.
async fn tls_listener(dir: &std::path::Path) -> (std::net::SocketAddr, watch::Sender<bool>) {
    let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let acceptor =
        tls_config::build_acceptor(&cert_path, &key_path, &tls_config::ClientAuthPolicy::Disabled)
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (sd_tx, sd_rx) = watch::channel(false);
    let transport = Transport::Tls(TlsTransport {
        acceptor,
        handshake_timeout: Duration::from_millis(50),
        mtls_enabled: false,
        allow: tls_config::ClientAllowList::default(),
    });
    let router = axum::Router::new();
    tokio::spawn(serve_http_listener("test-tls", listener, transport, router, limits(), sd_rx));
    (addr, sd_tx)
}

/// Open `n` sockets that never start a handshake and wait for the listener
/// to drop each.
async fn silent_sockets(addr: std::net::SocketAddr, n: usize) {
    let mut socks = Vec::new();
    for _ in 0..n {
        socks.push(TcpStream::connect(addr).await.unwrap());
    }
    for mut s in socks {
        let mut buf = [0u8; 8];
        let closed = matches!(
            tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        assert!(closed, "a silent socket must be dropped after the handshake budget");
    }
}

const TIMED_OUT: &str = "TLS handshake timed out";

#[tokio::test]
async fn tls_handshake_timeouts_are_budgeted_per_listener() {
    let logs = Logs::capture();
    let dir = tempfile::tempdir().unwrap();

    let (a, sd_a) = tls_listener(dir.path()).await;
    silent_sockets(a, 12).await;
    assert_eq!(logs.count(TIMED_OUT), 5, "twelve timeouts, five lines");

    // A second listener has its own budget: the first listener's flood
    // does not silence it.
    let (b, sd_b) = tls_listener(dir.path()).await;
    silent_sockets(b, 1).await;
    assert_eq!(logs.count(TIMED_OUT), 6, "the other listener still reports");

    let _ = sd_a.send(true);
    let _ = sd_b.send(true);
}
