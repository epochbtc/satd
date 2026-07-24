//! Alert webhook dispatcher E2E: a real `satd` POSTing to a real socket.
//!
//! The dispatcher's rules (matching, signing, retry classification) are
//! unit-tested in `satd-alert`. What only an end-to-end test can establish is
//! that a condition detected inside the daemon reaches an external HTTP
//! receiver with the right bytes and headers, that a failing receiver is
//! retried rather than dropped, and that a permanently-broken one cannot wedge
//! the queue behind it.
//!
//! The receiver is a raw TCP listener rather than an HTTP framework: the tests
//! need to script exact status codes per request and hold a connection open
//! without responding, which is easier to do with 20 lines of socket code than
//! to coax out of a server library.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::common::StreamingNode;

/// One captured POST.
#[derive(Debug, Clone)]
pub struct Received {
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl Received {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).expect("webhook body is JSON")
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
            .unwrap_or_default()
    }

    /// Verify `X-Satd-Signature` over the raw body, exactly as a third-party
    /// receiver would.
    fn signature_valid(&self, secret: &str) -> bool {
        self.header("x-satd-signature") == satd_alert::sign_body(secret, self.body.as_bytes())
    }
}

/// How the mock receiver answers the next request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Behavior {
    Ok,
    /// Respond with this status for the first `n` requests, then 200.
    FailFirst(u16, usize),
}

struct Inner {
    behavior: Behavior,
    seen: usize,
    received: Vec<Received>,
}

/// A scriptable HTTP receiver on loopback.
pub struct MockReceiver {
    port: u16,
    inner: Arc<Mutex<Inner>>,
}

impl MockReceiver {
    async fn start(behavior: Behavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let inner = Arc::new(Mutex::new(Inner {
            behavior,
            seen: 0,
            received: Vec::new(),
        }));
        let task_inner = inner.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let inner = task_inner.clone();
                tokio::spawn(async move {
                    let Some(req) = read_request(&mut sock).await else {
                        return;
                    };
                    let status = {
                        let mut g = inner.lock().await;
                        g.seen += 1;
                        let status = match g.behavior {
                            Behavior::Ok => 200,
                            Behavior::FailFirst(code, n) if g.seen <= n => code,
                            Behavior::FailFirst(..) => 200,
                        };
                        // Only a request the receiver actually accepted counts
                        // as received; a 503'd attempt is a retry, not a
                        // delivery.
                        if status == 200 {
                            g.received.push(req);
                        }
                        status
                    };
                    let reason = if status == 200 { "OK" } else { "Error" };
                    let _ = sock
                        .write_all(
                            format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                .as_bytes(),
                        )
                        .await;
                    let _ = sock.flush().await;
                });
            }
        });
        Self { port, inner }
    }

    pub async fn ok() -> Self {
        Self::start(Behavior::Ok).await
    }

    /// Reject the first `n` requests with `code`, then accept.
    pub async fn failing_first(code: u16, n: usize) -> Self {
        Self::start(Behavior::FailFirst(code, n)).await
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/hook", self.port)
    }

    /// Wait for a delivery matching `pred`, up to `secs`.
    async fn wait_for(
        &self,
        secs: u64,
        pred: impl Fn(&Received) -> bool,
    ) -> Received {
        let deadline = std::time::Instant::now() + Duration::from_secs(secs);
        loop {
            if let Some(r) = self
                .inner
                .lock()
                .await
                .received
                .iter()
                .find(|r| pred(r))
                .cloned()
            {
                return r;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for a matching webhook delivery; got: {:?}",
                self.inner.blocking_lock_bodies()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn attempts(&self) -> usize {
        self.inner.lock().await.seen
    }
}

trait BodiesForPanic {
    fn blocking_lock_bodies(&self) -> Vec<String>;
}

impl BodiesForPanic for Mutex<Inner> {
    fn blocking_lock_bodies(&self) -> Vec<String> {
        self.try_lock()
            .map(|g| g.received.iter().map(|r| r.body.clone()).collect())
            .unwrap_or_default()
    }
}

/// Read one HTTP request (headers + Content-Length body) off a socket.
async fn read_request(sock: &mut tokio::net::TcpStream) -> Option<Received> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    // Headers first.
    let head_end = loop {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut headers = HashMap::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    Some(Received {
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

const SECRET: &str = "an-operator-chosen-signing-secret";

/// Start a node whose `alertfile=` points at a one-hook file delivering
/// `categories` to `receiver`.
///
/// The alertfile *path* is restart-only (the `authfile` model — the dispatcher
/// binds to a path at startup), so it must be on the command line rather than
/// SIGHUP'd in. The file lives in its own temp dir, which the returned guard
/// keeps alive for the test's duration.
async fn node_with_hook(
    receiver: &MockReceiver,
    id: &str,
    categories: &str,
    extra: Vec<String>,
) -> (StreamingNode, tempfile::TempDir) {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("alertfile.toml");
    std::fs::write(
        &path,
        format!(
            r#"version = 1
[[webhook]]
id = "{id}"
url = "{}"
secret = "{SECRET}"
categories = [{categories}]
"#,
            receiver.url()
        ),
    )
    .expect("write alertfile");
    // The dispatcher refuses a group/world-readable file; it holds the signing
    // secret.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut args = vec![format!("--alertfile={}", path.display())];
    args.extend(extra);
    let sn = crate::streaming::start_streaming_owned(args).await;
    (sn, dir)
}

// ===========================================================================

/// A detected condition reaches the receiver as a correctly-signed POST whose
/// body is the same JSON a streaming subscriber would have received.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_delivers_a_signed_status_event() {
    let receiver = MockReceiver::ok().await;
    let (sn, _dir) = node_with_hook(&receiver, "ops", "\"status\"", vec![]).await;

    // Raise `disk_low` *after* the dispatcher is attached, by moving the
    // threshold live rather than starting with it tripped: a status event is
    // not replayable, so a condition raised during startup would never reach a
    // hook that had not finished subscribing.
    crate::streaming::sighup_with_conf(&sn, "alertdiskfreemb=17592186044416\n").await;

    let got = receiver
        .wait_for(60, |r| r.json()["body"]["category"] == "status")
        .await;

    assert!(
        got.signature_valid(SECRET),
        "X-Satd-Signature must verify over the raw body",
    );
    assert_eq!(got.header("x-satd-hook"), "ops");
    assert_eq!(got.header("x-satd-webhook-version"), "1");
    assert_eq!(got.header("x-satd-attempt"), "1");
    assert!(
        !got.header("x-satd-delivery").is_empty(),
        "an idempotency key is always present",
    );
    assert_eq!(got.header("content-type"), "application/json");

    let body = got.json();
    assert_eq!(body["body"]["kind"], "disk_low", "body: {body}");
    assert_eq!(body["body"]["state"], "raised");
    // The same envelope a WS subscriber sees — schema version and stamp too.
    assert_eq!(body["schema_version"], 1);
    assert!(body["stamp"]["seq"].is_number());
}

/// A receiver that is down comes back to find the event still waiting: the
/// dispatcher retries with backoff instead of dropping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_retries_until_the_receiver_recovers() {
    // 503 the first two attempts, then accept. Backoff is 1s then 2s, so the
    // delivery lands a few seconds in.
    let receiver = MockReceiver::failing_first(503, 2).await;
    let (sn, _dir) = node_with_hook(&receiver, "flaky", "\"chain\"", vec![]).await;

    crate::streaming::mine_n(&sn, 1).await;
    let got = receiver
        .wait_for(60, |r| r.json()["body"]["category"] == "chain")
        .await;
    assert!(got.signature_valid(SECRET));
    // The attempt counter proves this was a retry rather than a fresh event —
    // and it is what lets a receiver tell the two apart without keeping state.
    let attempt: u32 = got.header("x-satd-attempt").parse().unwrap_or(0);
    assert!(attempt >= 3, "expected the 3rd attempt to succeed, got {attempt}");
    assert!(receiver.attempts().await >= 3);
}

/// A receiver that permanently rejects one event must not pin the queue: the
/// event is skipped and later events still arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_permanent_rejection_does_not_wedge_the_queue() {
    // 404 the first request only. If a permanent 4xx were retried forever the
    // second event would never be delivered.
    let receiver = MockReceiver::failing_first(404, 1).await;
    let (sn, _dir) = node_with_hook(&receiver, "chain", "\"chain\"", vec![]).await;

    crate::streaming::mine_n(&sn, 2).await;
    let got = receiver
        .wait_for(60, |r| r.json()["body"]["category"] == "chain")
        .await;
    assert_eq!(got.json()["body"]["kind"], "block_connected");
    assert!(got.signature_valid(SECRET));
    // Exactly one rejection, and it did not stall what followed.
    assert!(receiver.attempts().await >= 2);
}
