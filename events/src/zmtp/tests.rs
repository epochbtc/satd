//! Tests for the ZMTP PUB server. Clients are the `zeromq` crate's
//! `SubSocket` where it suffices, and a hand-driven raw peer for protocol
//! edge cases and for subscribers that must not read.

use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use zeromq::{Socket, SocketRecv, SubSocket};

use super::ZmtpPub;

const TIMEOUT: Duration = Duration::from_secs(20);

/// Poll `cond` until it holds, or fail the test naming `what`.
async fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn msg(topic: &str, body: impl Into<Bytes>, seq: u32) -> [Bytes; 3] {
    [
        Bytes::copy_from_slice(topic.as_bytes()),
        body.into(),
        Bytes::copy_from_slice(&seq.to_le_bytes()),
    ]
}

async fn zsub(endpoint: &str, topics: &[&str]) -> SubSocket {
    let mut s = SubSocket::new();
    tokio::time::timeout(TIMEOUT, s.connect(endpoint))
        .await
        .expect("connect timed out")
        .expect("connect");
    for t in topics {
        s.subscribe(t).await.expect("subscribe");
    }
    s
}

async fn zrecv(s: &mut SubSocket) -> Vec<Bytes> {
    tokio::time::timeout(TIMEOUT, s.recv())
        .await
        .expect("recv timed out")
        .expect("recv")
        .into_vec()
}

fn topic_of(m: &[Bytes]) -> &[u8] {
    &m[0]
}

// ---- raw peer ---------------------------------------------------------------

fn greeting(major: u8, minor: u8, mechanism: &[u8]) -> [u8; 64] {
    let mut g = [0u8; 64];
    g[0] = 0xFF;
    g[9] = 0x7F;
    g[10] = major;
    g[11] = minor;
    g[12..12 + mechanism.len()].copy_from_slice(mechanism);
    g
}

fn command(name: &str, data: &[u8]) -> Vec<u8> {
    let mut body = vec![name.len() as u8];
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(data);
    frame(0x04, &body)
}

fn ready(socket_type: &str) -> Vec<u8> {
    let mut data = vec![11];
    data.extend_from_slice(b"Socket-Type");
    data.extend_from_slice(&(socket_type.len() as u32).to_be_bytes());
    data.extend_from_slice(socket_type.as_bytes());
    command("READY", &data)
}

fn frame(flags: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if body.len() > 255 {
        out.push(flags | 0x02);
        out.extend_from_slice(&(body.len() as u64).to_be_bytes());
    } else {
        out.push(flags);
        out.push(body.len() as u8);
    }
    out.extend_from_slice(body);
    out
}

/// A ZMTP 3.0 subscription message for `prefix`.
fn subscription(on: bool, prefix: &[u8]) -> Vec<u8> {
    let mut body = vec![u8::from(on)];
    body.extend_from_slice(prefix);
    frame(0, &body)
}

async fn raw_handshake<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, minor: u8) {
    s.write_all(&greeting(3, minor, b"NULL")).await.unwrap();
    let mut theirs = [0u8; 64];
    s.read_exact(&mut theirs).await.unwrap();
    assert_eq!(theirs, super::codec::GREETING);
    s.write_all(&ready("SUB")).await.unwrap();
    let (flags, body) = read_raw_frame(s).await;
    assert_eq!(flags, 0x04, "server READY is a command");
    assert_eq!(&body[..6], b"\x05READY");
}

async fn read_raw_frame<S: AsyncRead + Unpin>(s: &mut S) -> (u8, Vec<u8>) {
    tokio::time::timeout(TIMEOUT, async {
        let flags = s.read_u8().await.unwrap();
        let len = if flags & 0x02 != 0 {
            s.read_u64().await.unwrap() as usize
        } else {
            s.read_u8().await.unwrap() as usize
        };
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).await.unwrap();
        (flags, body)
    })
    .await
    .expect("raw frame timed out")
}

async fn raw_message<S: AsyncRead + Unpin>(s: &mut S) -> Vec<(u8, Vec<u8>)> {
    let mut parts = Vec::new();
    loop {
        let (flags, body) = read_raw_frame(s).await;
        let more = flags & 0x01 != 0;
        parts.push((flags, body));
        if !more {
            return parts;
        }
    }
}

fn tcp_addr(endpoint: &str) -> String {
    let rest = endpoint.strip_prefix("tcp://").unwrap();
    rest.replace("0.0.0.0", "127.0.0.1")
}

async fn raw_sub(endpoint: &str, prefixes: &[&[u8]]) -> TcpStream {
    let mut s = TcpStream::connect(tcp_addr(endpoint)).await.unwrap();
    raw_handshake(&mut s, 0).await;
    for p in prefixes {
        s.write_all(&subscription(true, p)).await.unwrap();
    }
    s
}

/// True once the server has closed the connection (EOF or reset).
async fn closed_by_server<S: AsyncRead + Unpin>(s: &mut S) -> bool {
    let mut buf = [0u8; 4096];
    let res = tokio::time::timeout(TIMEOUT, async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    res.is_ok()
}

async fn bind_local(hwm: usize) -> ZmtpPub {
    ZmtpPub::bind("tcp://127.0.0.1:0", hwm).await.unwrap()
}

// ---- tests ------------------------------------------------------------------

#[tokio::test]
async fn zmtp_sub_receives_three_frames() {
    let pubs = bind_local(1000).await;
    let mut sub = zsub(&pubs.local_endpoint(), &["hashblock"]).await;
    wait_until("subscription", || pubs.has_subscriber(b"hashblock")).await;

    pubs.publish(msg("hashblock", vec![0xAB; 32], 0));
    let got = zrecv(&mut sub).await;
    assert_eq!(got.len(), 3);
    assert_eq!(&got[0][..], b"hashblock");
    assert_eq!(&got[1][..], &[0xAB; 32][..]);
    assert_eq!(&got[2][..], &0u32.to_le_bytes()[..]);
    assert_eq!(pubs.subscriber_count(), 1);
    assert_eq!(pubs.dropped_total(), 0);
}

#[tokio::test]
async fn zmtp_prefix_filtering() {
    let pubs = bind_local(1000).await;
    let mut sub = zsub(&pubs.local_endpoint(), &["hash"]).await;
    wait_until("subscription", || pubs.has_subscriber(b"hashtx")).await;

    for (i, t) in ["rawtx", "hashtx", "rawblock", "hashblock", "sequence", "hashend"]
        .iter()
        .enumerate()
    {
        pubs.publish(msg(t, vec![i as u8], i as u32));
    }
    for want in ["hashtx", "hashblock", "hashend"] {
        assert_eq!(topic_of(&zrecv(&mut sub).await), want.as_bytes());
    }

    // Unsubscribe moves delivery to the new prefix only.
    sub.unsubscribe("hash").await.unwrap();
    sub.subscribe("raw").await.unwrap();
    wait_until("resubscription", || {
        !pubs.has_subscriber(b"hashtx") && pubs.has_subscriber(b"rawtx")
    })
    .await;
    pubs.publish(msg("hashtx", vec![1], 0));
    pubs.publish(msg("rawtx", vec![2], 0));
    assert_eq!(topic_of(&zrecv(&mut sub).await), b"rawtx");

    // Two matching prefixes still deliver a message once.
    sub.subscribe("").await.unwrap();
    wait_until("catch-all", || pubs.has_subscriber(b"zzz")).await;
    pubs.publish(msg("rawblock", vec![3], 0));
    pubs.publish(msg("zzz", vec![4], 0));
    assert_eq!(topic_of(&zrecv(&mut sub).await), b"rawblock");
    assert_eq!(topic_of(&zrecv(&mut sub).await), b"zzz");
}

#[tokio::test]
async fn zmtp_duplicate_subscription_is_counted() {
    let pubs = bind_local(1000).await;
    let mut s = raw_sub(&pubs.local_endpoint(), &[b"a", b"a"]).await;
    // Cancel once, then a marker subscription: once the marker is in, the
    // cancel before it has been applied.
    s.write_all(&subscription(false, b"a")).await.unwrap();
    s.write_all(&subscription(true, b"m1")).await.unwrap();
    wait_until("marker 1", || pubs.has_subscriber(b"m1")).await;
    assert!(pubs.has_subscriber(b"abc"), "one cancel of a doubled prefix keeps it");

    pubs.publish(msg("abc", vec![1], 0));
    let parts = raw_message(&mut s).await;
    assert_eq!(parts[0].1, b"abc");

    s.write_all(&subscription(false, b"a")).await.unwrap();
    s.write_all(&subscription(true, b"m2")).await.unwrap();
    wait_until("marker 2", || pubs.has_subscriber(b"m2")).await;
    assert!(!pubs.has_subscriber(b"abc"), "the second cancel removes it");
}

#[tokio::test]
async fn zmtp_large_message_delivered_without_followup_send() {
    let pubs = bind_local(1000).await;
    let mut sub = zsub(&pubs.local_endpoint(), &["rawblock"]).await;
    wait_until("subscription", || pubs.has_subscriber(b"rawblock")).await;

    let body: Vec<u8> = (0..8 << 20).map(|i: u32| (i % 251) as u8).collect();
    pubs.publish(msg("rawblock", body.clone(), 7));
    // Nothing else is published: the whole message must arrive on its own.
    let got = zrecv(&mut sub).await;
    assert_eq!(&got[0][..], b"rawblock");
    assert_eq!(got[1].len(), body.len());
    assert!(got[1][..] == body[..], "8 MiB body arrived intact");
    assert_eq!(&got[2][..], &7u32.to_le_bytes()[..]);
}

/// A subscriber that completes the handshake and subscribes, then never
/// reads, with a small receive buffer so the server's writes stall early.
async fn stalled_sub(endpoint: &str) -> TcpStream {
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.set_recv_buffer_size(4096).unwrap();
    let mut s = sock.connect(tcp_addr(endpoint).parse().unwrap()).await.unwrap();
    raw_handshake(&mut s, 0).await;
    s.write_all(&subscription(true, b"")).await.unwrap();
    s
}

#[tokio::test]
async fn zmtp_hwm_drops_never_blocks() {
    let pubs = bind_local(4).await;
    let _stalled = stalled_sub(&pubs.local_endpoint()).await;
    wait_until("subscription", || pubs.has_subscriber(b"x")).await;

    let body = Bytes::from(vec![0x5A; 1 << 20]);
    let started = Instant::now();
    for i in 0..200 {
        pubs.publish(msg("x", body.clone(), i));
    }
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(2), "publish blocked: {elapsed:?} for 200 messages");

    let depths = pubs.queue_depths();
    assert_eq!(depths.len(), 1);
    assert!(depths[0].0 <= 4, "queue holds at most the HWM: {depths:?}");
    // At most the 4 queued, one in the writer's hands and the few MiB the
    // kernel buffers can have left; everything else was dropped.
    let dropped = pubs.dropped_total();
    assert!(dropped >= 150, "only {dropped} of 200 dropped");
    assert!(dropped < 200);
}

#[tokio::test]
async fn zmtp_byte_cap() {
    // Unbounded HWM, so the byte cap is the only limit.
    let cap = 4 << 20;
    let pubs = ZmtpPub::bind_with_cap("tcp://127.0.0.1:0", 0, cap).await.unwrap();
    let _stalled = stalled_sub(&pubs.local_endpoint()).await;
    wait_until("subscription", || pubs.has_subscriber(b"x")).await;

    let body = Bytes::from(vec![0x33; 512 << 10]);
    for i in 0..100 {
        pubs.publish(msg("x", body.clone(), i));
    }
    let depths = pubs.queue_depths();
    assert!(depths[0].1 <= cap, "unwritten bytes stay under the cap: {depths:?}");
    let dropped = pubs.dropped_total();
    assert!(dropped >= 50, "only {dropped} of 100 dropped at a 4 MiB cap");

    // An idle subscriber takes a message bigger than the cap.
    let small = ZmtpPub::bind_with_cap("tcp://127.0.0.1:0", 0, 1024).await.unwrap();
    let mut sub = zsub(&small.local_endpoint(), &[""]).await;
    wait_until("subscription", || small.has_subscriber(b"big")).await;
    small.publish(msg("big", vec![1u8; 64 << 10], 0));
    assert_eq!(zrecv(&mut sub).await[1].len(), 64 << 10);
    assert_eq!(small.dropped_total(), 0);
}

#[tokio::test]
async fn zmtp_multiple_subscribers_and_disconnect() {
    let pubs = bind_local(1000).await;
    let mut a = zsub(&pubs.local_endpoint(), &[""]).await;
    let mut b = zsub(&pubs.local_endpoint(), &[""]).await;
    wait_until("two subscriptions", || pubs.subscribers_matching(b"t") == 2).await;

    pubs.publish(msg("t", vec![1], 0));
    assert_eq!(&zrecv(&mut a).await[1][..], &[1]);
    assert_eq!(&zrecv(&mut b).await[1][..], &[1]);

    drop(a);
    wait_until("disconnect noticed", || pubs.subscriber_count() == 1).await;
    pubs.publish(msg("t", vec![2], 1));
    assert_eq!(&zrecv(&mut b).await[1][..], &[2]);
    assert_eq!(pubs.dropped_total(), 0);
}

#[tokio::test]
async fn zmtp_ipc_endpoint_and_stale_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pub.sock");
    // A socket file left behind by an earlier run.
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    assert!(path.exists());

    let endpoint = format!("ipc://{}", path.display());
    let pubs = ZmtpPub::bind(&endpoint, 1000).await.expect("stale socket is replaced");
    assert_eq!(pubs.local_endpoint(), endpoint);
    let mut sub = zsub(&endpoint, &["rawtx"]).await;
    wait_until("subscription", || pubs.has_subscriber(b"rawtx")).await;
    pubs.publish(msg("rawtx", vec![9; 300], 0));
    assert_eq!(&zrecv(&mut sub).await[1][..], &[9; 300][..]);
    drop(sub);
    drop(pubs);
    assert!(!path.exists(), "the socket file is removed with the socket");

    // A regular file is never deleted.
    let file = dir.path().join("not-a-socket");
    std::fs::write(&file, b"keep me").unwrap();
    let err = ZmtpPub::bind(&format!("ipc://{}", file.display()), 1000).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists, "{err}");
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
}

#[tokio::test]
async fn zmtp_tcp_star_and_ipv6() {
    let star = ZmtpPub::bind("tcp://*:0", 1000).await.unwrap();
    assert!(star.local_endpoint().starts_with("tcp://0.0.0.0:"), "{}", star.local_endpoint());
    let mut s = raw_sub(&star.local_endpoint(), &[b""]).await;
    wait_until("subscription", || star.has_subscriber(b"t")).await;
    star.publish(msg("t", vec![1], 0));
    assert_eq!(raw_message(&mut s).await[1].1, vec![1]);

    let wildcard_port = ZmtpPub::bind("tcp://127.0.0.1:*", 1000).await.unwrap();
    assert!(!wildcard_port.local_endpoint().ends_with(":0"));

    let named = ZmtpPub::bind("tcp://localhost:0", 1000).await.unwrap();
    assert!(named.local_endpoint().starts_with("tcp://127.0.0.1:"), "{}", named.local_endpoint());

    for bad in ["inproc://x", "tcp://127.0.0.1", "tcp://127.0.0.1:99999", "tcp://:1", "ipc://*", "ipc://"] {
        assert!(ZmtpPub::bind(bad, 1000).await.is_err(), "{bad} should not bind");
    }

    if std::net::TcpListener::bind("[::1]:0").is_err() {
        eprintln!("IPv6 loopback unavailable; skipping the IPv6 half");
        return;
    }
    let v6 = ZmtpPub::bind("tcp://[::1]:0", 1000).await.unwrap();
    let ep = v6.local_endpoint();
    assert!(ep.starts_with("tcp://[::1]:"), "{ep}");
    let mut s = TcpStream::connect(ep.strip_prefix("tcp://").unwrap()).await.unwrap();
    raw_handshake(&mut s, 0).await;
    s.write_all(&subscription(true, b"")).await.unwrap();
    wait_until("v6 subscription", || v6.has_subscriber(b"t")).await;
    v6.publish(msg("t", vec![6], 0));
    assert_eq!(raw_message(&mut s).await[1].1, vec![6]);
}

#[tokio::test]
async fn zmtp_keepalive_set() {
    let pubs = bind_local(1000).await;
    let _s = raw_sub(&pubs.local_endpoint(), &[b""]).await;
    wait_until("subscriber", || pubs.subscriber_count() == 1).await;
    assert_eq!(pubs.keepalive_set_count(), 1, "the accepted socket has SO_KEEPALIVE");
}

#[tokio::test]
async fn zmtp_long_frames() {
    let pubs = bind_local(1000).await;
    let mut s = raw_sub(&pubs.local_endpoint(), &[b""]).await;
    wait_until("subscription", || pubs.has_subscriber(b"t")).await;

    for len in [0usize, 1, 255, 256, 70_000] {
        let body: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
        pubs.publish(msg("rawtx", body.clone(), len as u32));
        let parts = raw_message(&mut s).await;
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], (0x01, b"rawtx".to_vec()), "topic: short frame, MORE");
        let want_flags = if len > 255 { 0x03 } else { 0x01 };
        assert_eq!(parts[1].0, want_flags, "body of {len} bytes");
        assert_eq!(parts[1].1, body);
        assert_eq!(parts[2], (0x00, (len as u32).to_le_bytes().to_vec()), "last frame");
    }
}

#[tokio::test]
async fn zmtp_rejects_bad_peer() {
    let pubs = bind_local(1000).await;
    let addr = tcp_addr(&pubs.local_endpoint());

    // Not a ZMTP signature.
    let mut s = TcpStream::connect(&addr).await.unwrap();
    s.write_all(&[0u8; 64]).await.unwrap();
    assert!(closed_by_server(&mut s).await, "bad signature");

    // ZMTP 2.x.
    let mut s = TcpStream::connect(&addr).await.unwrap();
    s.write_all(&greeting(2, 0, b"NULL")).await.unwrap();
    assert!(closed_by_server(&mut s).await, "old version");

    // A security mechanism other than NULL.
    let mut s = TcpStream::connect(&addr).await.unwrap();
    s.write_all(&greeting(3, 0, b"PLAIN")).await.unwrap();
    assert!(closed_by_server(&mut s).await, "PLAIN mechanism");

    // A PUB peer.
    let mut s = TcpStream::connect(&addr).await.unwrap();
    s.write_all(&greeting(3, 0, b"NULL")).await.unwrap();
    let mut g = [0u8; 64];
    s.read_exact(&mut g).await.unwrap();
    s.write_all(&ready("PUB")).await.unwrap();
    assert!(closed_by_server(&mut s).await, "PUB peer");

    // A message instead of READY.
    let mut s = TcpStream::connect(&addr).await.unwrap();
    s.write_all(&greeting(3, 0, b"NULL")).await.unwrap();
    s.write_all(&subscription(true, b"")).await.unwrap();
    assert!(closed_by_server(&mut s).await, "message before READY");

    // An oversized frame after the handshake.
    let mut s = raw_sub(&pubs.local_endpoint(), &[]).await;
    wait_until("registered", || pubs.subscriber_count() == 1).await;
    let mut huge = vec![0x02];
    huge.extend_from_slice(&(2u64 << 20).to_be_bytes());
    s.write_all(&huge).await.unwrap();
    assert!(closed_by_server(&mut s).await, "oversized frame");
    wait_until("removed", || pubs.subscriber_count() == 0).await;

    // Reserved flag bits.
    let mut s = raw_sub(&pubs.local_endpoint(), &[]).await;
    s.write_all(&[0x80, 0]).await.unwrap();
    assert!(closed_by_server(&mut s).await, "reserved flags");

    // The server is unaffected.
    let mut sub = zsub(&pubs.local_endpoint(), &["ok"]).await;
    wait_until("good subscriber", || pubs.has_subscriber(b"ok")).await;
    pubs.publish(msg("ok", vec![1], 0));
    assert_eq!(topic_of(&zrecv(&mut sub).await), b"ok");
    wait_until("only the good subscriber", || pubs.subscriber_count() == 1).await;
}

#[tokio::test]
async fn zmtp_zmtp31_subscribe_command() {
    let pubs = bind_local(1000).await;
    let mut s = TcpStream::connect(tcp_addr(&pubs.local_endpoint())).await.unwrap();
    raw_handshake(&mut s, 1).await;

    s.write_all(&command("SUBSCRIBE", b"hash")).await.unwrap();
    wait_until("SUBSCRIBE applied", || pubs.has_subscriber(b"hashtx")).await;
    pubs.publish(msg("hashtx", vec![1; 32], 0));
    assert_eq!(raw_message(&mut s).await[0].1, b"hashtx");

    s.write_all(&command("CANCEL", b"hash")).await.unwrap();
    s.write_all(&command("SUBSCRIBE", b"zz")).await.unwrap();
    wait_until("CANCEL applied", || {
        !pubs.has_subscriber(b"hashtx") && pubs.has_subscriber(b"zz")
    })
    .await;
    pubs.publish(msg("hashtx", vec![2; 32], 1));
    pubs.publish(msg("zz", vec![3], 2));
    assert_eq!(raw_message(&mut s).await[0].1, b"zz");

    // PING (TTL, then context) is answered with a PONG echoing the context.
    s.write_all(&command("PING", b"\x00\x00ctx")).await.unwrap();
    let (flags, body) = read_raw_frame(&mut s).await;
    assert_eq!(flags, 0x04);
    assert_eq!(body, b"\x04PONGctx");
}

#[tokio::test]
async fn zmtp_publish_without_subscribers_is_free() {
    let pubs = bind_local(1).await;
    for i in 0..10 {
        pubs.publish(msg("t", vec![0; 1024], i));
    }
    assert_eq!(pubs.dropped_total(), 0, "nobody to drop for");
    assert_eq!(pubs.subscriber_count(), 0);
}
