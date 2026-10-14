//! A JSON-RPC request with a credential that does not authenticate is answered
//! as Bitcoin Core answers it (`HTTPReq_JSONRPC`, src/httprpc.cpp): a warning
//! naming the peer, a 250 ms pause, then `401`. A request with no credential
//! at all gets its `401` at once, as in Core.
//!
//! Its own test binary because the log capture needs a process-wide
//! subscriber: see `Logs`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use node::rpc::auth::{AuthLayer, RpcAuth, RpcPeerAddr};
use tower::{Layer as _, Service as _};

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
/// current-thread runtime, so the buffer is the test's own.
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

    fn text(&self) -> String {
        THREAD_LOGS.with(|l| String::from_utf8(l.borrow().clone()).unwrap())
    }
}

const PEER: &str = "192.0.2.7:51234";

/// The auth layer over a method layer that answers `200` to anything that
/// reaches it.
fn service() -> impl tower::Service<
    hyper::Request<String>,
    Response = hyper::Response<jsonrpsee::server::HttpBody>,
    Error = Infallible,
> {
    let auth = Arc::new(RpcAuth::from_user_pass("alice".into(), "secret".into()));
    AuthLayer::new(auth, None).layer(tower::service_fn(|_req: hyper::Request<String>| async {
        Ok::<_, Infallible>(hyper::Response::new(jsonrpsee::server::HttpBody::from("ok")))
    }))
}

/// A request from [`PEER`], as the RPC listeners hand it to the middleware.
fn request(userpass: Option<&str>) -> hyper::Request<String> {
    let mut b = hyper::Request::builder().method("POST").uri("/");
    if let Some(up) = userpass {
        b = b.header("authorization", format!("Basic {}", B64.encode(up)));
    }
    let mut req = b.body(String::new()).unwrap();
    req.extensions_mut().insert(RpcPeerAddr(PEER.parse::<SocketAddr>().unwrap()));
    req
}

const CORE_LINE: &str = "ThreadRPCServer incorrect password attempt from 192.0.2.7:51234";

#[tokio::test(start_paused = true)]
async fn a_wrong_password_is_logged_and_answered_after_250_ms() {
    let logs = Logs::capture();
    let mut svc = service();

    for bad in ["alice:wrong", "mallory:secret", "no-colon"] {
        let start = tokio::time::Instant::now();
        let resp = svc.call(request(Some(bad))).await.unwrap();
        assert_eq!(resp.status(), 401, "{bad}");
        assert!(
            start.elapsed() >= Duration::from_millis(250),
            "{bad}: answered after {:?}",
            start.elapsed()
        );
    }
    let text = logs.text();
    assert_eq!(text.matches(CORE_LINE).count(), 3, "{text}");
    assert!(text.lines().all(|l| !l.contains(CORE_LINE) || l.contains("WARN")), "{text}");
}

#[tokio::test(start_paused = true)]
async fn no_credential_is_refused_at_once_and_a_right_one_passes() {
    let logs = Logs::capture();
    let mut svc = service();

    let start = tokio::time::Instant::now();
    let resp = svc.call(request(None)).await.unwrap();
    assert_eq!(resp.status(), 401);
    let resp = svc.call(request(Some("alice:secret"))).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(start.elapsed(), Duration::ZERO, "neither request waits");
    assert!(!logs.text().contains("incorrect password"), "{}", logs.text());
}
