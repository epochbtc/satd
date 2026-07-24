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
    /// Answer with `code` for any `block_connected` at one of these heights,
    /// 200 for everything else. Unlike `RejectHeights` the status is the
    /// caller's, so a 5xx leaves the delivery in retry and the hook's resume
    /// marker parked — which is what an endpoint outage looks like from the
    /// node's side.
    FailHeights(Vec<u64>, u16),
    /// Permanently reject (404) any `block_connected` at one of these heights,
    /// accept everything else. Keyed on content rather than request ordinal so
    /// the script does not depend on how many events a block produces.
    RejectHeights(Vec<u64>),
}

struct Inner {
    behavior: Behavior,
    seen: usize,
    received: Vec<Received>,
    /// Every request, accepted or refused — what `received` deliberately is not.
    attempted: Vec<Received>,
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
            attempted: Vec::new(),
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
                            Behavior::FailHeights(hs, code) => {
                                let h = req.json()["body"]["height"].as_u64();
                                match h {
                                    Some(h) if hs.contains(&h) => (*code, None),
                                    _ => (200, None),
                                }
                            }
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
                        // delivery. Every attempt is kept separately, so a test
                        // can assert on what changes (and what must not) across
                        // the retries of one event.
                        g.attempted.push(req.clone());
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

    /// Answer `code` for `block_connected` at these heights, 200 otherwise.
    pub async fn failing_heights(heights: Vec<u64>, code: u16) -> Self {
        Self::start(Behavior::FailHeights(heights, code)).await
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

    /// Whether any accepted delivery matches `pred`.
    async fn saw_any(&self, pred: impl Fn(&Received) -> bool) -> bool {
        self.inner.lock().await.received.iter().any(pred)
    }

    async fn attempts(&self) -> usize {
        self.inner.lock().await.seen
    }

    /// Every request the receiver saw, accepted or not, in arrival order.
    async fn all_attempts(&self) -> Vec<Received> {
        self.inner.lock().await.attempted.clone()
    }

    /// Every accepted delivery, in arrival order.
    ///
    /// Unused on this branch — the dispatcher tests assert on *attempts*, since
    /// a refused delivery is still evidence of what was sent. The watch-hook
    /// tests stacked above do use it, and each branch is linted on its own.
    #[allow(dead_code)]
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

/// Write a two-hook alertfile. `cats_b` is the only thing callers vary between
/// two writes, so hook `a`'s stanza stays byte-identical across a reload.
fn write_two_hook_alertfile(
    dir: &tempfile::TempDir,
    a: (&MockReceiver, &str, &str),
    b: (&MockReceiver, &str, &str),
) {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.path().join("alertfile.toml");
    let stanza = |(r, id, cats): (&MockReceiver, &str, &str)| {
        format!(
            "\n[[webhook]]\nid = \"{id}\"\nurl = \"{}\"\nsecret = \"{SECRET}\"\n\
             categories = [{cats}]\n",
            r.url()
        )
    };
    std::fs::write(
        &path,
        format!("version = 1\n{}{}", stanza(a), stanza(b)),
    )
    .expect("write alertfile");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Convert an RPC display txid to the internal (consensus) byte order the
/// streaming/webhook surface renders.
fn internal_txid(display: &str) -> String {
    let mut b = hex::decode(display).expect("hex txid");
    b.reverse();
    hex::encode(b)
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

    // Drive `disk_low` to a known-cleared state first, so the raise below is
    // guaranteed to be an edge.
    //
    // At the 10 GiB default this test otherwise depends on the host's free
    // space: on a machine under the floor the condition is already raised
    // before the dispatcher attaches, the raise SIGHUP hits `raise_if_new`'s
    // no-op, and the whole v2-signature guard dies as a bare 60 s timeout with
    // nothing to say why. A 1 MiB floor is below any filesystem that can hold a
    // datadir, so this clears on every host. It has to go through the conf file
    // rather than the command line — a CLI value wins over the conf, so a CLI
    // threshold would make every later SIGHUP retune a no-op.
    crate::streaming::sighup_with_conf(&sn, "alertdiskfreemb=1\n").await;

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

    // One event is signed exactly once, and every attempt carries that same
    // signature, timestamp, and delivery id — only `X-Satd-Attempt` varies.
    //
    // This is the invariant, not an implementation detail. Re-signing per
    // attempt would refresh `X-Satd-Timestamp`, which is what makes a delivery
    // age out of the receiver's freshness window while it is still being
    // retried — deliberate, since a 20-minute-old alert is not worth acting on.
    // Asserting only on the accepted attempt (as this test used to) passes just
    // as happily with the signing moved inside the retry loop.
    let attempts = receiver.all_attempts().await;
    let chain: Vec<_> = attempts
        .iter()
        .filter(|r| r.json()["body"]["category"] == "chain")
        .collect();
    assert!(chain.len() >= 3, "expected 3 attempts at one event, got {}", chain.len());
    let first = chain[0];
    for (i, r) in chain.iter().enumerate() {
        assert_eq!(
            r.header("x-satd-timestamp"),
            first.header("x-satd-timestamp"),
            "attempt {} re-stamped the timestamp; the event must be signed once",
            i + 1
        );
        assert_eq!(r.header("x-satd-signature"), first.header("x-satd-signature"));
        assert_eq!(r.header("x-satd-delivery"), first.header("x-satd-delivery"));
        assert_eq!(r.body, first.body);
    }
    // ...and the attempt counter is the one thing that does move.
    assert_ne!(chain[0].header("x-satd-attempt"), chain[2].header("x-satd-attempt"));
}

/// A SIGHUP that did not touch the alertfile must not destroy a queued status
/// event.
///
/// `reload_from_sighup` calls `AlertReloader::apply()` on *every* SIGHUP,
/// whatever key the operator actually edited, and retiring a generation drops
/// everything queued in it. For chain events that is survivable — the cursor
/// did not advance, so the next generation's catch-up re-queues them. A status
/// event has no replay by design, and the detectors are edge-triggered against
/// a `HealthState` that outlives the reload, so a `disk_low` sitting in retry
/// backoff when the operator SIGHUPs to change `maxconnections` would be
/// dropped, never replayed, and never re-raised. The page simply never arrives.
///
/// The receiver 503s the first two attempts, so the event is provably still
/// in the dispatcher — mid-backoff — when the unrelated SIGHUP lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unrelated_sighup_does_not_destroy_a_queued_status_event() {
    // Refuse the first four attempts. Backoff is 1s, 2s, 4s, 8s, so the event
    // stays in the dispatcher for ~15s — a wide window for the unrelated reload
    // below to land inside. Too few refusals and the delivery could succeed
    // before the SIGHUP, leaving the test green without ever exercising the
    // reload path.
    let receiver = MockReceiver::failing_first(503, 4).await;
    let (sn, _dir) = node_with_hook(&receiver, "pager", "\"status\"", vec![]).await;

    // Known-cleared first, so the raise is an edge on any host (see
    // `webhook_delivers_a_signed_status_event` for why this goes through the
    // conf file rather than the command line).
    crate::streaming::sighup_with_conf(&sn, "alertdiskfreemb=1\n").await;

    // Raise `disk_low`. The detectors re-evaluate on a 15s poll, so the raise
    // does not follow the SIGHUP immediately — wait for the delivery to have
    // been attempted rather than assuming a fixed delay.
    crate::streaming::sighup_with_conf(&sn, "alertdiskfreemb=17592186044416\n").await;
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    while receiver.attempts().await == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the status event was never attempted; the raise did not reach the hook"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Now an unrelated reload, while that delivery is still being retried. The
    // alertfile is untouched; only a daemon key changes. The threshold is
    // carried over so the condition stays raised — a cleared-and-re-raised
    // alert would produce a *new* event and mask the loss of the old one.
    crate::streaming::sighup_with_conf(
        &sn,
        "alertdiskfreemb=17592186044416\nmaxconnections=42\n",
    )
    .await;

    // The original event must still land.
    let got = receiver
        .wait_for(60, |r| r.json()["body"]["category"] == "status")
        .await;
    assert_eq!(got.json()["body"]["kind"], "disk_low");
    assert!(got.signature_valid(SECRET));
}

/// Editing one hook must not destroy a *different* hook's queued event.
///
/// The companion to `an_unrelated_sighup_does_not_destroy_a_queued_status_event`,
/// and the harder half. That one is protected by the unchanged-file early
/// return in `apply`; here the alertfile genuinely changes, so the reload runs
/// the whole handover. A reload that rebuilt every delivery task would take
/// `pager`'s in-flight `disk_low` down with it even though the operator only
/// touched `ops` — and a status event has no replay, so it is lost outright and
/// the edge-triggered detector never raises it again.
///
/// `pager` 503s the first four attempts, so the event is provably still in its
/// queue, mid-backoff, when the reload lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn editing_one_hook_does_not_destroy_another_hooks_queued_event() {
    let pager = MockReceiver::failing_first(503, 4).await;
    let ops = MockReceiver::ok().await;

    let dir = tempfile::tempdir().expect("tempdir");
    write_two_hook_alertfile(
        &dir,
        (&pager, "pager", "\"status\""),
        (&ops, "ops", "\"status\""),
    );
    let path = dir.path().join("alertfile.toml");
    let sn =
        crate::streaming::start_streaming_owned(vec![format!("--alertfile={}", path.display())])
            .await;

    // Known-cleared, then raised, so the detector fires an edge on any host.
    crate::streaming::sighup_with_conf(&sn, "alertdiskfreemb=1\n").await;
    crate::streaming::sighup_with_conf(&sn, "alertdiskfreemb=17592186044416\n").await;

    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    while pager.attempts().await == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the status event was never attempted; the raise did not reach the hook"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Edit `ops` only. `pager`'s stanza is byte-identical, so its delivery task
    // — and the `disk_low` still in its queue — must survive.
    write_two_hook_alertfile(
        &dir,
        (&pager, "pager", "\"status\""),
        (&ops, "ops", "\"status\", \"chain\""),
    );
    crate::streaming::sighup_with_conf(&sn, "alertdiskfreemb=17592186044416\n").await;

    let got = pager
        .wait_for(60, |r| r.json()["body"]["category"] == "status")
        .await;
    assert_eq!(got.json()["body"]["kind"], "disk_low");
    assert!(got.signature_valid(SECRET));
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
    let block_attempts = |rs: Vec<Received>| -> Vec<u64> {
        rs.iter()
            .filter(|r| r.json()["body"]["kind"] == "block_connected")
            .filter_map(|r| r.json()["body"]["height"].as_u64())
            .collect()
    };
    let before = block_attempts(receiver.all_attempts().await);
    assert_eq!(before, vec![1, 2, 3], "expected all three blocks attempted once");

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
    //
    // Scoped to `block_connected` rather than a raw request count, because a
    // permanent rejection now also emits a `lagged` notice — the receiver is
    // told which events it lost, since the cursor advancing past them means it
    // can never fetch them later. A raw count would fold that in and read as a
    // replayed block.
    assert_eq!(
        block_attempts(receiver.all_attempts().await),
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

    // ...and the refusal was announced rather than silent. A gap notice is
    // emitted ahead of the next event for the hook, so this is asserted after
    // block 4 rather than immediately after the rejections.
    //
    // It matters here more than on any other drop path: the cursor advances
    // past a permanently-rejected event, so unlike a queue overflow the
    // receiver cannot go back for it. Being told is all it gets.
    // Summed across notices rather than read off the first one. The gap
    // accounting also flushes on a timer, so whether the two refusals coalesce
    // into a single notice of 2 or arrive as two notices of 1 depends only on
    // which side of a tick they land on — a race this test has no reason to
    // pin down. Only the total is meaningful.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let attempts = receiver.all_attempts().await;
        let lagged: Vec<_> = attempts
            .iter()
            .filter(|r| r.json()["body"]["category"] == "lagged")
            .collect();
        let total: u64 = lagged
            .iter()
            .filter_map(|r| r.json()["body"]["dropped_count"].as_u64())
            .sum();
        if total >= 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "both refused blocks should be counted; got {total} across {} notice(s): {:?}",
            lagged.len(),
            lagged.iter().map(|r| r.body.clone()).collect::<Vec<_>>(),
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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

/// A span missed while the hook was dead is announced, not replayed.
///
/// Webhooks are realtime (design D6): the durable cursor is a resume marker,
/// not a replay log. On restart the dispatcher compares it against the tip and
/// emits one `Lagged` naming what was missed; the events themselves are gone,
/// and a receiver that needs them fetches them over the streaming API from the
/// advertised `resume_cursor`.
///
/// This replaces a test of the old catch-up replay. That replay was built up to
/// 10,000 blocks into a queue holding 1,024, so any outage long enough to
/// matter had its "guaranteed" recovery converted straight back into an
/// overflow gap — and its per-height delivery ids collided between a block and
/// its post-reorg replacement, so a conforming receiver dropped the
/// replacement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missed_span_is_announced_as_a_gap_and_never_replayed() {
    // 503 blocks 2..=5 so they stay in retry and never advance the marker.
    // Everything else — block 1, and the gap notice itself — is accepted.
    let receiver = MockReceiver::failing_heights(vec![2, 3, 4, 5], 503).await;
    let (sn, dir) = node_with_hook(&receiver, "chain", "\"chain\"", vec![]).await;

    // Establish a marker: one block delivered and acked.
    crate::streaming::mine_n(&sn, 1).await;
    receiver
        .wait_for(60, |r| r.json()["body"]["height"] == 1)
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The outage. These four are queued and retrying; none is acked, so the
    // marker stays at 1 while the tip moves to 5.
    crate::streaming::mine_n(&sn, 4).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    let missed = |r: &Received| (2..=5).contains(&r.json()["body"]["height"].as_u64().unwrap_or(0));
    let attempts_before = receiver.all_attempts().await.iter().filter(|r| missed(r)).count();
    assert!(attempts_before > 0, "the outage span should have been attempted at least once");

    // Retire the generation with a same-URL alertfile edit — the same code path
    // a restart takes. The queued, still-retrying blocks go with it, which is
    // exactly why the receiver has to be told.
    write_alertfile(&dir, &receiver, "chain", "\"chain\"", true);
    crate::streaming::sighup_with_conf(&sn, "").await;

    let lagged = receiver
        .wait_for(60, |r| r.json()["body"]["category"] == "lagged")
        .await;
    assert!(
        lagged.json()["body"]["dropped_count"].as_u64().unwrap_or(0) >= 4,
        "the whole missed span must be counted; got {}",
        lagged.body,
    );
    // The anchor points at or before the last block the receiver actually got,
    // never past the hole it is announcing.
    assert!(
        lagged.json()["body"]["resume_cursor"]["height"].as_u64().unwrap_or(u64::MAX) <= 1,
        "resume anchor is past the gap it announces; got {}",
        lagged.body,
    );
    tokio::time::sleep(Duration::from_secs(3)).await;

    // ...and nothing from the missed span was re-sent.
    let attempts_after = receiver.all_attempts().await.iter().filter(|r| missed(r)).count();
    assert_eq!(
        attempts_after, attempts_before,
        "the missed span was replayed; a gap notice replaces it, it does not precede it"
    );

    // The hook is live: the next block still arrives.
    crate::streaming::mine_n(&sn, 1).await;
    receiver
        .wait_for(60, |r| r.json()["body"]["height"] == 6)
        .await;
}

/// A hook with a `[webhook.watch]` script entry receives a signed
/// `script_matched` when a transaction pays that script — the whole watch path:
/// alertfile parse, registry registration, per-hook routing, and the shared
/// envelope-shaped JSON the WebSocket carrier also emits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_watch_set_delivers_a_script_match() {
    use std::os::unix::fs::PermissionsExt as _;

    let receiver = MockReceiver::ok().await;

    // The destination is known before the node starts, so its scripthash can go
    // into the alertfile — which must exist at startup (the path is
    // restart-only).
    let dest_seed = 0x5au8;
    let dest_spk = crate::common::DeterministicWallet::from_secret([dest_seed; 32])
        .address
        .script_pubkey();
    let scripthash = crate::common::scripthash_hex(&dest_spk);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("alertfile.toml");
    std::fs::write(
        &path,
        format!(
            r#"version = 1
[[webhook]]
id = "deposits"
url = "{}"
secret = "{SECRET}"
categories = ["chain"]
[webhook.watch]
scripts = ["{scripthash}"]
"#,
            receiver.url()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let sn =
        crate::streaming::start_streaming_owned(vec![format!("--alertfile={}", path.display())])
            .await;
    let wallet = crate::common::DeterministicWallet::from_secret([0x11u8; 32]);
    {
        let rpc = sn.node.rpc_handle();
        let addr = wallet.address.to_string();
        tokio::task::spawn_blocking(move || rpc.mine(101, &addr))
            .await
            .unwrap();
    }

    // Pay the watched script.
    let (txid, _) = crate::streaming::broadcast_spend(&sn, &wallet, dest_seed, 1_000).await;

    // Mempool match first (unconfirmed), then the confirmed re-emit.
    let got = receiver
        .wait_for(45, |r| r.json()["body"]["category"] == "script_matched")
        .await;
    assert!(got.signature_valid(SECRET), "watch matches are signed too");
    assert_eq!(got.header("x-satd-hook"), "deposits");
    let body = got.json();
    assert_eq!(body["body"]["scripthash"], scripthash, "body: {body}");
    // Hashes on this surface are internal (consensus) byte order, unreversed —
    // the streaming API's convention, not the JSON-RPC display order the
    // `sendrawtransaction` reply uses.
    assert_eq!(body["body"]["txid"], internal_txid(&txid), "body: {body}");
    assert_eq!(body["body"]["is_output"], true);

    crate::streaming::mine_n(&sn, 1).await;
    let confirmed = receiver
        .wait_for(45, |r| {
            r.json()["body"]["category"] == "script_matched"
                && r.json()["body"]["confirmed"] == true
        })
        .await;
    assert_eq!(confirmed.json()["body"]["txid"], internal_txid(&txid));
}

/// A hook that watches nothing must not receive another hook's matches: the
/// registry holds one union subscriber, so routing back to the owning hook is
/// the dispatcher's job and a bug there would leak one operator's deposit
/// activity into an unrelated endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_watch_matches_are_routed_only_to_the_owning_hook() {
    use std::os::unix::fs::PermissionsExt as _;

    let watcher = MockReceiver::ok().await;
    let bystander = MockReceiver::ok().await;

    let dest_seed = 0x5bu8;
    let dest_spk = crate::common::DeterministicWallet::from_secret([dest_seed; 32])
        .address
        .script_pubkey();
    let scripthash = crate::common::scripthash_hex(&dest_spk);

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("alertfile.toml");
    std::fs::write(
        &path,
        format!(
            r#"version = 1
[[webhook]]
id = "watcher"
url = "{}"
secret = "{SECRET}"
categories = ["chain"]
[webhook.watch]
scripts = ["{scripthash}"]

[[webhook]]
id = "bystander"
url = "{}"
secret = "{SECRET}"
categories = ["chain"]
"#,
            watcher.url(),
            bystander.url()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let sn =
        crate::streaming::start_streaming_owned(vec![format!("--alertfile={}", path.display())])
            .await;
    let wallet = crate::common::DeterministicWallet::from_secret([0x11u8; 32]);
    {
        let rpc = sn.node.rpc_handle();
        let addr = wallet.address.to_string();
        tokio::task::spawn_blocking(move || rpc.mine(101, &addr))
            .await
            .unwrap();
    }
    crate::streaming::broadcast_spend(&sn, &wallet, dest_seed, 1_000).await;
    crate::streaming::mine_n(&sn, 1).await;

    // The watcher gets the match...
    watcher
        .wait_for(45, |r| r.json()["body"]["category"] == "script_matched")
        .await;
    // ...and the bystander gets the block it subscribed to, but no match.
    bystander
        .wait_for(45, |r| r.json()["body"]["category"] == "chain")
        .await;
    assert!(
        !bystander.saw_any(|r| r.json()["body"]["category"] == "script_matched").await,
        "a hook with no watch-set must never receive another hook's matches",
    );
}
