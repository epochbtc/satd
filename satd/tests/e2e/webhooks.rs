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

    /// Verify `X-Satd-Signature` exactly as a third-party receiver would.
    ///
    /// v2: the HMAC covers the timestamp, the delivery id, the hook id, and the
    /// body — not the body alone. Signing only the body would leave the
    /// delivery id unauthenticated, and since the contract tells receivers to
    /// deduplicate on that header, anyone holding one captured delivery could
    /// replay it under forged ids and pre-empt the genuine alerts.
    ///
    /// The comparison is constant-time. It is not a real secret-dependent
    /// branch here — the node is the signer — but this helper is the most
    /// likely thing someone copies when writing a receiver against satd, and
    /// the spec requires constant-time comparison.
    fn signature_valid(&self, secret: &str) -> bool {
        use subtle::ConstantTimeEq as _;
        let Ok(ts) = self.header("x-satd-timestamp").parse::<u64>() else {
            return false;
        };
        let expected = satd_alert::sign_v2(
            secret,
            ts,
            self.header("x-satd-delivery"),
            self.header("x-satd-hook"),
            self.body.as_bytes(),
        );
        let got = self.header("x-satd-signature");
        got.len() == expected.len()
            && got.as_bytes().ct_eq(expected.as_bytes()).into()
    }
}

/// How the mock receiver answers the next request.
#[derive(Clone, PartialEq, Eq)]
enum Behavior {
    Ok,
    /// Respond with this status for the first `n` requests, then 200.
    FailFirst(u16, usize),
    /// Answer every request with `302 Location: <url>`.
    Redirect(String),
    /// Permanently reject (404) any `block_connected` at one of these heights,
    /// accept everything else. Keyed on content rather than request ordinal so
    /// the script does not depend on how many events a block produces.
    RejectHeights(Vec<u64>),
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
                    let (status, location) = {
                        let mut g = inner.lock().await;
                        g.seen += 1;
                        let (status, location) = match &g.behavior {
                            Behavior::Ok => (200, None),
                            Behavior::FailFirst(code, n) if g.seen <= *n => (*code, None),
                            Behavior::FailFirst(..) => (200, None),
                            Behavior::Redirect(to) => (302, Some(to.clone())),
                            Behavior::RejectHeights(hs) => {
                                let h = req.json()["body"]["height"].as_u64();
                                match h {
                                    Some(h) if hs.contains(&h) => (404, None),
                                    _ => (200, None),
                                }
                            }
                        };
                        // Only a request the receiver actually accepted counts
                        // as received; a 503'd attempt is a retry, not a
                        // delivery.
                        if status == 200 {
                            g.received.push(req);
                        }
                        (status, location)
                    };
                    let reason = if status == 200 { "OK" } else { "Error" };
                    let loc = location
                        .map(|l| format!("Location: {l}\r\n"))
                        .unwrap_or_default();
                    let _ = sock
                        .write_all(
                            format!("HTTP/1.1 {status} {reason}\r\n{loc}Content-Length: 0\r\nConnection: close\r\n\r\n")
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

    /// Answer every request with a 302 pointing at `to`.
    pub async fn redirecting_to(to: String) -> Self {
        Self::start(Behavior::Redirect(to)).await
    }

    /// Permanently reject `block_connected` at these heights; accept the rest.
    pub async fn rejecting_heights(heights: Vec<u64>) -> Self {
        Self::start(Behavior::RejectHeights(heights)).await
    }

    /// Heights of every accepted `block_connected` delivery, in arrival order.
    async fn accepted_heights(&self) -> Vec<u64> {
        self.inner
            .lock()
            .await
            .received
            .iter()
            .filter(|r| r.json()["body"]["kind"] == "block_connected")
            .filter_map(|r| r.json()["body"]["height"].as_u64())
            .collect()
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

    /// Every accepted delivery, in arrival order.
    async fn all(&self) -> Vec<Received> {
        self.inner.lock().await.received.clone()
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

/// Write (or rewrite) the alertfile for a test node.
///
/// `nudge` exists so a test can produce a *materially different* file: the
/// dispatcher deliberately treats a SIGHUP that did not change the alertfile as
/// a no-op, so a test that needs a fresh generation — and therefore a fresh
/// catch-up from the persisted cursor — has to actually change something. It
/// sets `allow_insecure_http`, which parses under every category and is a
/// no-op for the loopback URLs these tests use, so it changes the parsed hook
/// without changing behavior.
fn write_alertfile(
    dir: &tempfile::TempDir,
    receiver: &MockReceiver,
    id: &str,
    categories: &str,
    nudge: bool,
) {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.path().join("alertfile.toml");
    let hb = if nudge { "allow_insecure_http = true\n" } else { "" };
    std::fs::write(
        &path,
        format!(
            r#"version = 1
[[webhook]]
id = "{id}"
url = "{}"
secret = "{SECRET}"
categories = [{categories}]
{hb}"#,
            receiver.url()
        ),
    )
    .expect("write alertfile");
    // The dispatcher refuses a group/world-readable file; it holds the signing
    // secret.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

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
    let dir = tempfile::tempdir().expect("tempdir");
    write_alertfile(&dir, receiver, id, categories, false);
    let path = dir.path().join("alertfile.toml");

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
        "X-Satd-Signature must verify over the v2 signing string",
    );
    assert_eq!(got.header("x-satd-hook"), "ops");
    assert_eq!(got.header("x-satd-webhook-version"), "2");
    assert_eq!(got.header("x-satd-attempt"), "1");
    assert!(
        !got.header("x-satd-delivery").is_empty(),
        "an idempotency key is always present",
    );
    // The timestamp is part of the signed material, so a receiver can bound
    // replay of a captured delivery.
    let ts: u64 = got
        .header("x-satd-timestamp")
        .parse()
        .expect("X-Satd-Timestamp is present and numeric");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(now.abs_diff(ts) < 300, "timestamp should be recent, got {ts} vs {now}");
    // Tampering with any signed field must invalidate the signature. The
    // delivery id is the one that matters most: the contract tells receivers to
    // deduplicate on it, so if it were unsigned an attacker holding one valid
    // delivery could pre-poison a receiver's dedup cache against future alerts.
    let mut forged = got.clone();
    forged
        .headers
        .insert("x-satd-delivery".into(), format!("{}-forged", got.header("x-satd-delivery")));
    assert!(
        !forged.signature_valid(SECRET),
        "the delivery id must be covered by the signature",
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

/// A permanently-rejected event still advances the hook's resume cursor.
///
/// Otherwise a receiver that hard-rejects one body shape turns every reload and
/// every restart into a rebuild of the same refused span — the events are lost
/// either way, and the only question is whether the hook makes progress past
/// them. Here blocks 2 and 3 are 404'd; the reload that follows re-runs catch-up
/// from the stored cursor, and must not replay them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_permanent_rejection_advances_the_cursor() {
    let receiver = MockReceiver::rejecting_heights(vec![2, 3]).await;
    let (sn, _dir) = node_with_hook(&receiver, "chain", "\"chain\"", vec![]).await;

    crate::streaming::mine_n(&sn, 3).await;
    // Block 1 is accepted; 2 and 3 are refused. Wait for the last one to have
    // been attempted, so the cursor writes have happened.
    receiver
        .wait_for(60, |r| r.json()["body"]["height"] == 1)
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let before = receiver.attempts().await;
    assert!(before >= 3, "expected all three blocks attempted, got {before}");

    // A SIGHUP retires the generation and starts a new one, which re-runs
    // catch-up from the persisted cursor.
    //
    // The alertfile must actually change: an unchanged one is deliberately a
    // no-op, because retiring a generation destroys its queued deliveries and a
    // status event has no replay to recover it. Without a real edit here this
    // test would pass without ever re-running catch-up — the exact thing it
    // exists to check.
    write_alertfile(&_dir, &receiver, "chain", "\"chain\"", true);
    crate::streaming::sighup_with_conf(&sn, "").await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Counting *attempts*, not accepted deliveries: a replayed block would be
    // refused again and so would never show up as accepted. What matters is
    // whether the request was made at all.
    assert_eq!(
        receiver.attempts().await,
        before,
        "a refused span must not be rebuilt and re-sent on reload",
    );
    let heights = receiver.accepted_heights().await;
    assert_eq!(heights, vec![1], "only block 1 was ever accepted; got {heights:?}");

    // The hook is not wedged: the next block still arrives.
    crate::streaming::mine_n(&sn, 1).await;
    receiver
        .wait_for(60, |r| r.json()["body"]["height"] == 4)
        .await;
}

/// A redirect is never followed: the signed body does not go to a host the
/// alertfile never named.
///
/// The configured URL is validated once, at load. If a 302 moved the request,
/// that check would be advisory only — and the interesting destinations are the
/// ones an operator cannot see from the outside: a cloud metadata endpoint, an
/// RFC1918 admin port, the node's own RPC. Here the redirect target is a second
/// mock receiver, which must never be touched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_does_not_follow_redirects() {
    let elsewhere = MockReceiver::ok().await;
    let receiver = MockReceiver::redirecting_to(elsewhere.url()).await;
    let (sn, _dir) = node_with_hook(&receiver, "redirector", "\"chain\"", vec![]).await;

    crate::streaming::mine_n(&sn, 2).await;
    // Give the dispatcher room to deliver, retry, and give up.
    tokio::time::sleep(Duration::from_secs(5)).await;

    assert!(
        receiver.attempts().await >= 1,
        "the configured endpoint should have been contacted",
    );
    assert_eq!(
        elsewhere.attempts().await,
        0,
        "the redirect target must never receive the signed body",
    );
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

/// A restart-style catch-up must not hand every replayed block the same
/// idempotency key.
///
/// Replayed envelopes are synthesized by the replay builder, which stamps every
/// one of them `seq: 0`. Minting the delivery id from that stamp gave a node
/// that had been down for N blocks N deliveries sharing one
/// `X-Satd-Delivery` — so a receiver following the contract ("deduplicate on
/// it") keeps the first and silently discards the rest. Catch-up exists
/// precisely to close that gap, so the bug quietly reduced it to delivering one
/// block per outage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catch_up_replay_gives_every_event_a_distinct_delivery_id() {
    let receiver = MockReceiver::start(Behavior::Ok).await;
    let (sn, dir) = node_with_hook(&receiver, "chain", "\"chain\"", vec![]).await;

    // Establish a cursor: one block delivered and acked.
    crate::streaming::mine_n(&sn, 1).await;
    receiver
        .wait_for(60, |r| r.json()["body"]["height"] == 1)
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Simulate the outage: retire the dispatcher by pointing the hook at a
    // black hole, mine past it, then point it back. The blocks mined while the
    // hook was dead are exactly the span catch-up must replay.
    // Always-500 stands in for "the receiver is down": nothing is ever acked,
    // so the shared cursor stays at block 1 and the blocks mined below are the
    // span catch-up has to replay.
    let sink = MockReceiver::start(Behavior::FailFirst(500, usize::MAX)).await;
    write_alertfile(&dir, &sink, "chain", "\"chain\"", false);
    crate::streaming::sighup_with_conf(&sn, "").await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    crate::streaming::mine_n(&sn, 4).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let before = receiver.all().await.len();
    write_alertfile(&dir, &receiver, "chain", "\"chain\"", false);
    crate::streaming::sighup_with_conf(&sn, "").await;

    // Wait for the replayed span to arrive.
    receiver
        .wait_for(60, |r| r.json()["body"]["height"] == 5)
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let replayed: Vec<String> = receiver
        .all()
        .await
        .into_iter()
        .skip(before)
        .map(|r| r.header("x-satd-delivery").to_string())
        .collect();
    assert!(
        replayed.len() >= 3,
        "expected a multi-block replay, got {replayed:?}"
    );
    let unique: std::collections::HashSet<&String> = replayed.iter().collect();
    assert_eq!(
        unique.len(),
        replayed.len(),
        "replayed events shared an idempotency key; a conforming receiver \
         would drop all but one: {replayed:?}"
    );
}
