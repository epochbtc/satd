//! The crawl (`-crawl`) against running regtest nodes: a small cluster of
//! real satd nodes and scripted peers on loopback, crawled to completion and
//! the book checked exactly; the book and its timers across a restart; the
//! address book's file unchanged by a crawl; and no session before the node
//! leaves initial block download. A regtest book admits loopback addresses
//! (mainnet, testnet4 and signet never do), and every address here is one,
//! so nothing is dialled off the host.

mod common;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use common::{TestNode, test_timeout};
use node::net::crawlbook::{BookParams, CrawlAddr, CrawlBook, GetaddrResult, CRAWL_FILE};
use node::net::peer::PeerAddr;
use serde_json::json;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// A scripted v1-only peer: Core's shape when dialled, or btcd's, and its
/// answer to `getaddr`.
#[derive(Clone)]
struct Shape {
    user_agent: &'static str,
    negotiation: Vec<NetworkMessage>,
    after_verack: Vec<NetworkMessage>,
    answer: Vec<u16>,
}

fn core(answer: Vec<u16>) -> Shape {
    Shape {
        user_agent: "/Satoshi:32.1.0/",
        negotiation: vec![NetworkMessage::WtxidRelay, NetworkMessage::SendAddrV2],
        after_verack: vec![NetworkMessage::Ping(7)],
        answer,
    }
}

fn btcd(answer: Vec<u16>) -> Shape {
    Shape {
        user_agent: "/btcwire:0.5.0/btcd:0.27.0/",
        negotiation: vec![NetworkMessage::SendAddrV2],
        after_verack: vec![],
        answer,
    }
}

fn send(stream: &mut TcpStream, msg: NetworkMessage) -> io::Result<()> {
    stream.write_all(&serialize(&RawNetworkMessage::new(Magic::REGTEST, msg)))
}

fn recv(stream: &mut TcpStream) -> io::Result<NetworkMessage> {
    let mut header = [0u8; 24];
    stream.read_exact(&mut header)?;
    if header[..4] != Magic::REGTEST.to_bytes() {
        // A v2 handshake: a v1-only peer hangs up.
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not v1"));
    }
    let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    let mut buf = header.to_vec();
    buf.resize(24 + len, 0);
    stream.read_exact(&mut buf[24..])?;
    let raw: RawNetworkMessage = deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(raw.into_payload())
}

fn loopback_entry(port: u16) -> AddrV2Message {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
    AddrV2Message {
        time: now - 60,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        addr: AddrV2::Ipv4(Ipv4Addr::LOCALHOST),
        port,
    }
}

fn serve(mut stream: TcpStream, shape: &Shape) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    loop {
        match recv(&mut stream)? {
            NetworkMessage::Version(_) => {
                let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
                let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
                send(
                    &mut stream,
                    NetworkMessage::Version(VersionMessage {
                        version: 70016,
                        services,
                        timestamp: 1_790_000_000,
                        receiver: Address::new(&zero, ServiceFlags::NONE),
                        sender: Address::new(&zero, services),
                        nonce: rand::random(),
                        user_agent: shape.user_agent.into(),
                        start_height: 0,
                        relay: true,
                    }),
                )?;
                for m in &shape.negotiation {
                    send(&mut stream, m.clone())?;
                }
                send(&mut stream, NetworkMessage::Verack)?;
            }
            NetworkMessage::Verack => {
                for m in &shape.after_verack {
                    send(&mut stream, m.clone())?;
                }
            }
            NetworkMessage::GetAddr => {
                let entries = shape.answer.iter().map(|p| loopback_entry(*p)).collect();
                send(&mut stream, NetworkMessage::AddrV2(entries))?;
            }
            NetworkMessage::Ping(n) => send(&mut stream, NetworkMessage::Pong(n))?,
            NetworkMessage::GetHeaders(_) => send(&mut stream, NetworkMessage::Headers(vec![]))?,
            NetworkMessage::GetData(inv) => send(&mut stream, NetworkMessage::NotFound(inv))?,
            _ => {}
        }
    }
}

/// A scripted peer on a port of its own, and how many connections it took.
fn scripted(listener: TcpListener, shape: Shape) -> Arc<AtomicUsize> {
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = accepts.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            let shape = shape.clone();
            std::thread::spawn(move || {
                let _ = serve(stream, &shape);
            });
        }
    });
    accepts
}

fn bind() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// A port nothing listens on.
fn closed_port() -> u16 {
    bind().1
}

const ADDR: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

fn peer(port: u16) -> PeerAddr {
    PeerAddr::Socket(SocketAddr::from(([127, 0, 0, 1], port)))
}

/// Sessions to `port` the node has logged as done.
fn sessions_done(node: &TestNode, port: u16) -> usize {
    let log = std::fs::read_to_string(&node.stderr_log).unwrap_or_default();
    let addr = format!("addr=127.0.0.1:{port}");
    log.lines().filter(|l| l.contains("crawl session done") && l.contains(&addr)).count()
}

fn wait_for(what: &str, secs: u64, f: impl Fn() -> bool) {
    let deadline = Instant::now() + test_timeout(secs);
    while Instant::now() < deadline {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(f(), "timed out waiting for {what}");
}

fn read_book(node: &TestNode) -> CrawlBook {
    let path = node.datadir.join("regtest").join(CRAWL_FILE);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    CrawlBook::load(&path, Magic::REGTEST.to_bytes(), now, BookParams::for_network(bitcoin::Network::Regtest)).unwrap()
}

/// A cluster crawled to completion: the crawler starts from one scripted
/// Core peer, which names two real satd nodes, a scripted btcd peer and an
/// address nobody listens on; the btcd peer names the dead address again.
/// The book must hold exactly those five, four reached: the scripted peers
/// over v1 after a refused v2 attempt, the satd nodes over v2 and then v1
/// on the v1 recheck, none v2-only. No crawl connection is ever a peer of
/// the crawler, and the survey reports itself superseded. Across a restart
/// the book and its timers are kept: nothing is due, so nothing changes.
#[test]
fn a_regtest_cluster_is_crawled_to_completion() {
    let mut x = TestNode::start(&[]);
    let mut y = TestNode::start(&[]);
    let (xp, yp) = (x.p2p_port.unwrap(), y.p2p_port.unwrap());
    let dead = closed_port();
    let (l2, s2) = bind();
    let s2_accepts = scripted(l2, btcd(vec![yp, dead]));
    let (l1, s1) = bind();
    let s1_accepts = scripted(l1, core(vec![xp, s2, dead]));
    let args = [
        "--maxconnections=0".to_string(),
        "--crawl=1".to_string(),
        format!("--crawlseed=127.0.0.1:{s1}"),
        "--loglevel=debug".to_string(),
    ];
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut c = TestNode::start(&args);
    c.rpc_ok("generatetoaddress", vec![json!(1), json!(ADDR)]);

    let done = |c: &TestNode| {
        sessions_done(c, s1) >= 1
            && sessions_done(c, s2) >= 1
            && sessions_done(c, dead) >= 1
            && sessions_done(c, xp) >= 2
            && sessions_done(c, yp) >= 2
    };
    let deadline = Instant::now() + test_timeout(420);
    while !done(&c) {
        assert!(Instant::now() < deadline, "the crawl did not complete");
        assert_eq!(c.rpc_ok("getconnectioncount", vec![]), 0, "no crawl connection is a peer");
        assert_eq!(c.rpc_ok("getpeerinfo", vec![]), json!([]));
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(s1_accepts.load(Ordering::SeqCst) >= 2 && s2_accepts.load(Ordering::SeqCst) >= 2, "v2, then v1");
    let survey = c.rpc_ok("getpeersurvey", vec![]);
    assert_eq!(survey["superseded_by_crawl"], true, "{survey}");
    c.stop();

    let book = read_book(&c);
    assert_eq!(book.len(), 5, "{:?}", book.rows().map(|(a, _)| a.clone()).collect::<Vec<_>>());
    let counts = book.counts();
    assert_eq!((counts.learned[0], counts.reached[0]), (5, 4), "ipv4: learned, reached");
    assert_eq!(&counts.learned[1..], &[0; 4]);
    let entry = |port| book.get(&CrawlAddr::Peer(peer(port))).unwrap_or_else(|| panic!("{port} in the book"));
    for (port, entries) in [(s1, 3), (s2, 2)] {
        let e = entry(port);
        assert_eq!((e.v2_ok, e.v1_ok, e.v2_only), (Some(false), Some(true), false), "scripted {port}");
        let obs = e.observation.as_ref().unwrap();
        assert!(matches!(obs.getaddr, Some(GetaddrResult::Answered { entries: n, .. }) if n == entries), "{obs:?}");
        assert!(obs.probes.any());
    }
    assert_eq!(entry(s1).observation.as_ref().unwrap().user_agent, "/Satoshi:32.1.0/");
    for port in [xp, yp] {
        let e = entry(port);
        assert_eq!((e.v2_ok, e.v1_ok, e.v2_only), (Some(true), Some(true), false), "satd {port}");
        assert!(e.last_v1_check.is_some() && e.last_discovery.is_some());
        let obs = e.observation.as_ref().unwrap();
        assert!(obs.user_agent.starts_with("/satd:"), "{obs:?}");
        assert!(obs.getaddr.is_some(), "the discovery's getaddr is kept");
    }
    let d = entry(dead);
    assert_eq!((d.last_success, d.failures, d.source_count()), (None, 1, 2), "named by both scripted peers");
    assert!(d.retry_at.is_some());

    // The book and its timers survive a restart: nothing is due, so the
    // restarted crawl changes nothing.
    c.restart_preserving_datadir(&args);
    wait_for("the book loaded", 30, || {
        std::fs::read_to_string(&c.stderr_log).unwrap_or_default().contains("Crawl started")
    });
    std::thread::sleep(Duration::from_secs(5));
    c.stop();
    let again = read_book(&c);
    assert_eq!(again.len(), book.len());
    for (addr, e) in book.rows() {
        assert_eq!(again.get(addr), Some(e), "{addr:?}");
    }
    x.stop();
    y.stop();
}

/// The crawl reads the address book and never writes it: `peers.dat` is
/// the same bytes before and after a crawl of the address in it and of the
/// addresses that peer names. The node is out of initial block download
/// and has no automatic connection of its own (`-maxconnections=0`), so
/// only the crawl dials.
#[test]
fn peers_dat_is_unchanged_by_a_crawl() {
    let dead = closed_port();
    let (l, port) = bind();
    let accepts = scripted(l, core(vec![dead, closed_port()]));
    let mut node = TestNode::start(&["--maxconnections=0"]);
    node.rpc_ok("generatetoaddress", vec![json!(1), json!(ADDR)]);
    let r = node.rpc_ok("addpeeraddress", vec![json!("127.0.0.1"), json!(port)]);
    assert_eq!(r["success"], true, "{r}");
    node.stop();
    let peers = node.datadir.join("regtest").join("peers.dat");
    let before = std::fs::read(&peers).unwrap();
    assert_eq!(accepts.load(Ordering::SeqCst), 0, "fixture: the node dials nothing itself");

    node.restart_preserving_datadir(&["--maxconnections=0", "--crawl=1", "--loglevel=debug"]);
    wait_for("the crawl of the book's address and its answer", 120, || {
        sessions_done(&node, port) >= 1 && sessions_done(&node, dead) >= 1
    });
    node.stop();
    assert!(accepts.load(Ordering::SeqCst) >= 1);
    assert_eq!(read_book(&node).len(), 3, "the address, and the two it named");
    assert_eq!(std::fs::read(&peers).unwrap(), before, "peers.dat byte for byte");
}

/// No session starts while the node is in initial block download; the
/// crawl starts once it leaves. The seed is `-crawlseed`, which the node's
/// own dialer never uses, so every connection is the crawl's.
#[test]
fn nothing_is_dialled_in_initial_block_download() {
    let (l, port) = bind();
    let accepts = scripted(l, core(vec![closed_port(), closed_port()]));
    let seed = format!("--crawlseed=127.0.0.1:{port}");
    let mut node = TestNode::start(&["--maxconnections=0", "--crawl=1", &seed, "--loglevel=info"]);
    std::thread::sleep(test_timeout(12));
    assert_eq!(accepts.load(Ordering::SeqCst), 0, "no session in initial block download");
    let log = std::fs::read_to_string(&node.stderr_log).unwrap_or_default();
    assert!(log.contains("The crawl waits for the node to leave initial block download"), "{log}");
    assert!(log.contains("Crawl enabled: it will dial tens of thousands of addresses"), "the startup warning");
    node.rpc_ok("generatetoaddress", vec![json!(1), json!(ADDR)]);
    wait_for("the first crawl session", 60, || accepts.load(Ordering::SeqCst) >= 1);
    node.stop();
}
