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
    /// 200 for everything else. Keyed on content rather than request ordinal so
    /// a script does not depend on how many events a block produces; a 5xx
    /// leaves the delivery in retry, which is what an endpoint outage looks
    /// like from the node's side.
    FailHeights(Vec<u64>, u16),
    /// Accept the connection, read the request, and never answer. The worst
    /// case for a dispatcher: not a refused connection it can fail fast on, but
    /// an open socket that consumes the full per-attempt timeout every time.
    BlackHole,
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
                            // 0 is the sentinel for "never answer".
                            Behavior::BlackHole => (0, None),
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
                    if status == 0 {
                        // Hold the connection open forever; the client times out.
                        std::future::pending::<()>().await;
                        return;
                    }
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

    /// Accept connections and never respond.
    pub async fn black_hole() -> Self {
        Self::start(Behavior::BlackHole).await
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

/// A hook that was not running does not go back for what it missed.
///
/// This is the whole durability contract, asserted from the outside. Webhooks
/// are best-effort (design D6): there is no cursor, no replay and no gap
/// notice. A hook that comes back resumes at the live head, and the events that
/// happened while it was down are simply not delivered.
///
/// The assertion is deliberately that the node does *not* do something. Earlier
/// revisions delivered the missed span, then announced it — each of which cost
/// a durable keyspace, a `Store` trait extension across four backends, a GC
/// pass and a synthesized delivery-id space, to serve a use case the streaming
/// API already serves properly with real cursors and backpressure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hook_that_was_down_resumes_at_the_live_head() {
    // 503 blocks 2..=5 so they stay queued and un-acked when the hook is
    // retired. Everything else is accepted.
    let receiver = MockReceiver::failing_heights(vec![2, 3, 4, 5], 503).await;
    let (sn, dir) = node_with_hook(&receiver, "chain", "\"chain\"", vec![]).await;

    crate::streaming::mine_n(&sn, 1).await;
    receiver
        .wait_for(60, |r| r.json()["body"]["height"] == 1)
        .await;

    // The outage: four blocks queued and retrying, none acked.
    crate::streaming::mine_n(&sn, 4).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    let missed = |r: &Received| (2..=5).contains(&r.json()["body"]["height"].as_u64().unwrap_or(0));
    let before = receiver.all_attempts().await.iter().filter(|r| missed(r)).count();
    assert!(before > 0, "the outage span should have been attempted at least once");

    // Retire the generation with a same-URL alertfile edit — the same code path
    // a restart takes. The queued blocks go with it.
    write_alertfile(&dir, &receiver, "chain", "\"chain\"", true);
    crate::streaming::sighup_with_conf(&sn, "").await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Nothing from the missed span comes back...
    let after = receiver.all_attempts().await.iter().filter(|r| missed(r)).count();
    assert_eq!(
        after, before,
        "the missed span was re-sent; a best-effort hook resumes at the head and \
         does not carry history across a reload"
    );

    // ...and no in-band notice is synthesized about it either.
    assert!(
        !receiver
            .all_attempts()
            .await
            .iter()
            .any(|r| r.json()["body"]["category"] == "lagged"),
        "a lagged body was delivered; gap accounting was removed with the cursor"
    );

    // The hook is live: the next block still arrives.
    crate::streaming::mine_n(&sn, 1).await;
    receiver
        .wait_for(60, |r| r.json()["body"]["height"] == 6)
        .await;
}

/// **Release criterion: a stalled webhook endpoint cannot affect consensus.**
///
/// The isolation is structural — deliveries run on the API runtime, the fan-in
/// only ever `try_send`s into a bounded queue — so this test demonstrates the
/// property rather than establishing it: with a receiver that accepts TCP and
/// never answers (the worst case: every attempt burns the full 10s timeout),
/// block connection must proceed at the same rate as with no hook at all.
///
/// The assertion is deliberately a wide bound rather than a tight ratio: this
/// runs on shared CI hardware where a strict comparison of two wall-clock
/// measurements would flake. A regression that coupled delivery to block
/// connection would not be marginal — it would serialize every block behind a
/// 10-second timeout, blowing past this bound by orders of magnitude.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_endpoint_does_not_slow_block_connection() {
    const BLOCKS: u32 = 20;

    // Baseline: no webhook configured at all.
    let plain = crate::streaming::start_streaming_async(vec![]).await;
    let t0 = std::time::Instant::now();
    crate::streaming::mine_n(&plain, BLOCKS).await;
    let baseline = t0.elapsed();

    // Same work, with every event going to a receiver that never answers.
    let receiver = MockReceiver::black_hole().await;
    let (stalled, _dir) = node_with_hook(&receiver, "blackhole", "\"chain\"", vec![]).await;
    let t0 = std::time::Instant::now();
    crate::streaming::mine_n(&stalled, BLOCKS).await;
    let with_stalled_hook = t0.elapsed();

    println!(
        "block-connect wall time for {BLOCKS} blocks: baseline {baseline:?}, \
         with a stalled webhook {with_stalled_hook:?}",
    );

    // If delivery were coupled to block connection, each block would wait out
    // the 10s per-attempt timeout — 200s for this run. A generous ceiling still
    // catches that by two orders of magnitude.
    let ceiling = (baseline * 4).max(Duration::from_secs(20));
    assert!(
        with_stalled_hook < ceiling,
        "a stalled webhook endpoint slowed block connection: {with_stalled_hook:?} \
         vs a {ceiling:?} ceiling (baseline {baseline:?})",
    );

    // And the node is still healthy afterwards — the tip really did advance.
    let rpc = stalled.node.rpc_handle();
    let height = tokio::task::spawn_blocking(move || rpc.call("getblockcount", vec![]))
        .await
        .unwrap()
        .unwrap()["result"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        height >= u64::from(BLOCKS),
        "tip should have advanced to at least {BLOCKS}, got {height}",
    );
}
