//! The crawl (`-crawl`) against running regtest nodes: a small cluster of
//! real satd nodes and scripted peers on loopback, crawled to completion and
//! the book checked exactly; the book and its timers across a restart; the
//! address book's file unchanged by a crawl; no session before the node
//! leaves initial block download; and what `getcrawlinfo`, `getcrawlnodes`,
//! the metrics and the status page report of it; and a fake node and a
//! closed-early one counted apart, and a closed-early one retried until it
//! settles. A regtest book admits loopback addresses
//! (mainnet, testnet4 and signet never do), and every address here is one,
//! so nothing is dialled off the host.

mod common;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use common::{TestNode, find_available_port, test_timeout};
use node::net::crawlbook::{BookParams, CRAWL_FILE, CrawlAddr, CrawlBook, GetaddrResult};
use node::net::peer::PeerAddr;
use serde_json::json;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// A scripted v1-only peer: Core's shape when dialled, or btcd's, and its
/// answer to `getaddr`: each port, and whether it is advertised with
/// `NODE_P2P_V2`.
#[derive(Clone)]
struct Shape {
    user_agent: &'static str,
    negotiation: Vec<NetworkMessage>,
    after_verack: Vec<NetworkMessage>,
    answer: Vec<(u16, bool)>,
    /// Close the connection on the dialler's `verack`, once
    /// `after_verack` is sent.
    close_after_verack: bool,
    /// On the first this many connections, close on the dialler's `verack`
    /// with nothing after it, as a node with full inbound slots evicts a
    /// new connection.
    evict_first: usize,
}

fn core(answer: Vec<(u16, bool)>) -> Shape {
    Shape {
        user_agent: "/Satoshi:32.1.0/",
        negotiation: vec![NetworkMessage::WtxidRelay, NetworkMessage::SendAddrV2],
        after_verack: vec![NetworkMessage::Ping(7)],
        answer,
        close_after_verack: false,
        evict_first: 0,
    }
}

/// Core with its inbound slots full: it completes the handshake, then
/// evicts the new connection before sending anything more.
fn evicting_core() -> Shape {
    Shape {
        after_verack: vec![],
        close_after_verack: true,
        ..core(vec![])
    }
}

/// An impostor claiming Core 25.0: `version` and `verack`, nothing
/// between them and nothing after, the connection held open.
fn fake_core() -> Shape {
    Shape {
        user_agent: "/Satoshi:25.0.0/",
        negotiation: vec![],
        after_verack: vec![],
        ..core(vec![])
    }
}

fn btcd(answer: Vec<(u16, bool)>) -> Shape {
    Shape {
        user_agent: "/btcwire:0.5.0/btcd:0.27.0/",
        negotiation: vec![NetworkMessage::SendAddrV2],
        after_verack: vec![],
        answer,
        close_after_verack: false,
        evict_first: 0,
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
    let raw: RawNetworkMessage =
        deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(raw.into_payload())
}

fn loopback_entry(port: u16, v2: bool) -> AddrV2Message {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    AddrV2Message {
        time: now - 60,
        services: if v2 {
            services | ServiceFlags::P2P_V2
        } else {
            services
        },
        addr: AddrV2::Ipv4(Ipv4Addr::LOCALHOST),
        port,
    }
}

fn serve(mut stream: TcpStream, shape: &Shape, connection: usize) -> io::Result<()> {
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
                if connection < shape.evict_first {
                    return Ok(());
                }
                for m in &shape.after_verack {
                    send(&mut stream, m.clone())?;
                }
                if shape.close_after_verack {
                    return Ok(());
                }
            }
            NetworkMessage::GetAddr => {
                let entries = shape
                    .answer
                    .iter()
                    .map(|(p, v2)| loopback_entry(*p, *v2))
                    .collect();
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
            let connection = counter.fetch_add(1, Ordering::SeqCst);
            let shape = shape.clone();
            std::thread::spawn(move || {
                let _ = serve(stream, &shape, connection);
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
    log.lines()
        .filter(|l| l.contains("crawl session done") && l.contains(&addr))
        .count()
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    CrawlBook::load(
        &path,
        Magic::REGTEST.to_bytes(),
        now,
        BookParams::for_network(bitcoin::Network::Regtest),
    )
    .unwrap()
}

/// A cluster crawled to completion: the crawler starts from one scripted
/// Core peer, which names two real satd nodes, a scripted btcd peer and an
/// address nobody listens on; the btcd peer names the dead address again.
/// The answers advertise the satd nodes with `NODE_P2P_V2` and the others
/// without. The book must hold exactly those five, four reached: the
/// scripted peers (the seed, which carries no services, and btcd) over v1
/// alone with no v2 attempt, the satd nodes over v2 and then v1 on the v1
/// recheck, none v2-only. No crawl connection is ever a peer of
/// the crawler, and the survey reports itself superseded. Across a restart
/// the book and its timers are kept: nothing is due, so nothing changes.
///
/// `getcrawlinfo` counts the cluster exactly, `getcrawlnodes` lists it, and
/// neither `getcrawlinfo`, the metrics nor the status page names an
/// address.
#[test]
fn a_regtest_cluster_is_crawled_to_completion() {
    let mut x = TestNode::start(&[]);
    let mut y = TestNode::start(&[]);
    let (xp, yp) = (x.p2p_port.unwrap(), y.p2p_port.unwrap());
    let dead = closed_port();
    let (l2, s2) = bind();
    let s2_accepts = scripted(l2, btcd(vec![(yp, true), (dead, false)]));
    let (l1, s1) = bind();
    let s1_accepts = scripted(l1, core(vec![(xp, true), (s2, false), (dead, false)]));
    let metrics_port = find_available_port();
    let args = [
        "--maxconnections=0".to_string(),
        "--crawl=1".to_string(),
        format!("--crawlseed=127.0.0.1:{s1}"),
        "--loglevel=debug".to_string(),
        format!("--metricsport={metrics_port}"),
        "--statuspage=1".to_string(),
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
        assert_eq!(
            c.rpc_ok("getconnectioncount", vec![]),
            0,
            "no crawl connection is a peer"
        );
        assert_eq!(c.rpc_ok("getpeerinfo", vec![]), json!([]));
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(
        (
            s1_accepts.load(Ordering::SeqCst),
            s2_accepts.load(Ordering::SeqCst)
        ),
        (1, 1),
        "v1 alone, no v2 attempt"
    );
    let survey = c.rpc_ok("getpeersurvey", vec![]);
    assert_eq!(survey["superseded_by_crawl"], true, "{survey}");
    check_reports(&c, metrics_port, &[s1, s2, dead, xp, yp]);
    c.stop();

    // The hourly snapshot: written when the crawl started, with the book's
    // file permissions.
    let snaps = c.datadir.join("regtest").join("crawl");
    let files = node::net::crawlsnapshot::list_snapshots(&snaps).unwrap();
    assert_eq!(files.len(), 1, "one this hour: {files:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let snap = snaps.join(node::net::crawlsnapshot::snapshot_file_name(files[0]));
        assert_eq!(
            mode(&snap),
            mode(&c.datadir.join("regtest").join(CRAWL_FILE))
        );
        assert_eq!(
            mode(&snap) & 0o077,
            0o077 & mode(&c.datadir.join("regtest")) & 0o666
        );
    }

    let book = read_book(&c);
    assert_eq!(
        book.len(),
        5,
        "{:?}",
        book.rows().map(|(a, _)| a.clone()).collect::<Vec<_>>()
    );
    let counts = book.counts();
    assert_eq!(
        (counts.learned[0], counts.reached[0]),
        (5, 4),
        "ipv4: learned, reached"
    );
    assert_eq!(&counts.learned[1..], &[0; 4]);
    let entry = |port| {
        book.get(&CrawlAddr::Peer(peer(port)))
            .unwrap_or_else(|| panic!("{port} in the book"))
    };
    for (port, entries) in [(s1, 3), (s2, 2)] {
        let e = entry(port);
        assert_eq!(
            (e.v2_ok, e.v1_ok, e.v2_only),
            (None, Some(true), false),
            "scripted {port}"
        );
        let obs = e.observation.as_ref().unwrap();
        assert!(
            matches!(obs.getaddr, Some(GetaddrResult::Answered { entries: n, .. }) if n == entries),
            "{obs:?}"
        );
        assert!(obs.probes.any());
    }
    assert_eq!(
        entry(s1).observation.as_ref().unwrap().user_agent,
        "/Satoshi:32.1.0/"
    );
    for port in [xp, yp] {
        let e = entry(port);
        assert_eq!(
            (e.v2_ok, e.v1_ok, e.v2_only),
            (Some(true), Some(true), false),
            "satd {port}"
        );
        assert!(e.last_v1_check.is_some() && e.last_discovery.is_some());
        let obs = e.observation.as_ref().unwrap();
        assert!(obs.user_agent.starts_with("/satd:"), "{obs:?}");
        assert!(obs.getaddr.is_some(), "the discovery's getaddr is kept");
    }
    let d = entry(dead);
    assert_eq!(
        (d.last_success, d.failures, d.source_count()),
        (None, 1, 2),
        "named by both scripted peers"
    );
    assert!(d.retry_at.is_some());

    // The book and its timers survive a restart: nothing is due, so the
    // restarted crawl changes nothing.
    c.restart_preserving_datadir(&args);
    wait_for("the book loaded", 30, || {
        std::fs::read_to_string(&c.stderr_log)
            .unwrap_or_default()
            .contains("Crawl started")
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

/// What the RPCs, the metrics and the status page say of the crawled
/// cluster: five addresses on IPv4, four reachable (the scripted peers over
/// v1 with v2 never tried, the satd nodes over both), and no address anywhere but in
/// `getcrawlnodes`.
fn check_reports(c: &TestNode, metrics_port: u16, ports: &[u16]) {
    let info = c.rpc_ok("getcrawlinfo", vec![]);
    assert_eq!(info["enabled"], true, "{info}");
    assert_eq!(info["state"], "running", "{info}");
    assert_eq!(info["held_by"], json!([]));
    assert_eq!(info["peersurvey_superseded"], false);
    assert_eq!(
        info["limits"]["networks"],
        json!(["ipv4", "ipv6"]),
        "no proxy, so no onion"
    );
    assert_eq!(info["book"]["entries"], 5, "{info}");
    assert_eq!(info["book"]["learned"]["ipv4"], 5);
    assert_eq!(info["book"]["ever_reached"]["ipv4"], 4);
    assert_eq!(
        info["reachable"],
        json!({ "total": 4, "ipv4": 4, "ipv6": 0, "onion": 0 }),
        "{info}"
    );
    assert_eq!(info["transport"]["v1_v2_untried"]["count"], 2, "{info}");
    assert_eq!(info["transport"]["v1_only"]["count"], 0, "{info}");
    assert_eq!(info["transport"]["v2_and_v1"]["count"], 2, "{info}");
    assert_eq!(info["transport"]["v2_only"]["count"], 0);
    // Every reachable address in exactly one of the family (or unknown),
    // claimed, fake and closed-early tallies; which family the classifier
    // gives a crawl session's transcript is its own test's.
    let sum = |key: &str| {
        info[key]
            .as_object()
            .unwrap()
            .values()
            .map(|f| f["count"].as_u64().unwrap())
            .sum::<u64>()
    };
    let counted = sum("families")
        + sum("claimed")
        + sum("fake")
        + info["closed_early"]["count"].as_u64().unwrap();
    assert_eq!(counted, 4, "{info}");
    assert!(info["sessions"]["reached"].as_u64().unwrap() >= 6);
    assert!(info["totals"]["totalbytesrecv"].as_u64().unwrap() > 0);
    let text = info.to_string();
    assert!(
        !text.contains("127.0.0.1") && !text.contains("Satoshi"),
        "counts only: {text}"
    );

    let rows = c.rpc_ok("getcrawlnodes", vec![]);
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 5);
    for port in ports {
        let addr = format!("127.0.0.1:{port}");
        let row = rows
            .iter()
            .find(|r| r["addr"] == addr)
            .unwrap_or_else(|| panic!("{addr} in {rows:?}"));
        assert!(
            row.get("observation").is_none(),
            "no observation without verbose"
        );
    }
    let verbose = c
        .rpc_call_with_named_params("getcrawlnodes", json!({ "verbose": true }))
        .unwrap();
    let rows = verbose["result"]
        .as_array()
        .unwrap_or_else(|| panic!("{verbose}"));
    let s1 = rows
        .iter()
        .find(|r| r["addr"] == format!("127.0.0.1:{}", ports[0]))
        .unwrap();
    assert_eq!(s1["observation"]["subver"], "/Satoshi:32.1.0/");
    assert_eq!(s1["observation"]["getaddr"]["entries"], 3);
    let help = c.rpc_ok("help", vec![]);
    let help = help.as_str().unwrap();
    assert!(
        help.contains("getcrawlinfo")
            && help.contains("getcrawlnodes")
            && help.contains("dumpcrawlsnapshot")
    );

    // The export: keyed by default, no address and no crawled port in it,
    // under a key created 0600 on first use; raw only when asked.
    let keyed = c.rpc_ok("dumpcrawlsnapshot", vec![]);
    assert_eq!(keyed["total_nodes"], 4, "{keyed}");
    assert_eq!(keyed["latest_height"], 1);
    let text = keyed.to_string();
    assert!(!text.contains("127.0.0.1"), "keyed: {text}");
    for port in ports {
        assert!(
            !text.contains(&format!(":{port}")),
            "keyed: no crawled port in {text}"
        );
    }
    for (id, node) in keyed["nodes"].as_object().unwrap() {
        assert_eq!(id.len(), 32, "{id}");
        assert_eq!(node.as_array().unwrap().len(), 14);
    }
    let key = c.datadir.join("regtest").join("crawlexport.key");
    assert_eq!(std::fs::read(&key).unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let raw = c
        .rpc_call_with_named_params("dumpcrawlsnapshot", json!({ "raw": true }))
        .unwrap();
    let raw = &raw["result"];
    assert_eq!(raw["total_nodes"], 4, "{raw}");
    assert!(
        raw["nodes"]
            .get(format!("127.0.0.1:{}", ports[0]))
            .is_some(),
        "raw: {raw}"
    );

    let base = format!("http://127.0.0.1:{metrics_port}");
    let body = reqwest::blocking::get(format!("{base}/metrics"))
        .unwrap()
        .text()
        .unwrap();
    for line in [
        "satd_crawl_enabled 1",
        "satd_crawl_running 1",
        "satd_crawl_book_entries{network=\"ipv4\"} 5",
        "satd_crawl_reachable{network=\"ipv4\"} 4",
        "satd_crawl_transport{class=\"v1_v2_untried\"} 2",
        "satd_crawl_transport{class=\"v1_only\"} 0",
    ] {
        assert!(body.lines().any(|l| l == line), "missing `{line}`");
    }
    assert!(!body.contains("127.0.0.1"), "no address in the metrics");
    let status: serde_json::Value = reqwest::blocking::get(format!("{base}/status.json"))
        .unwrap()
        .json()
        .unwrap();
    let crawl = &status["snapshot"]["crawl"];
    assert_eq!(crawl["state"], "running", "{status}");
    assert_eq!(crawl["book_entries"], 5);
    assert_eq!(crawl["reachable_ipv4"], 4);
    assert_eq!(crawl["v1_v2_untried"], 2);
    assert_eq!(crawl["v1_only"], 0);
    let page = reqwest::blocking::get(format!("{base}/status"))
        .unwrap()
        .text()
        .unwrap();
    for text in [status.to_string(), page] {
        assert!(!text.contains("127.0.0.1"), "no address on the status page");
        for port in ports {
            assert!(
                !text.contains(&format!(":{port}")),
                "no crawled port on the status page"
            );
        }
    }
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
    let accepts = scripted(l, core(vec![(dead, false), (closed_port(), false)]));
    let mut node = TestNode::start(&["--maxconnections=0"]);
    node.rpc_ok("generatetoaddress", vec![json!(1), json!(ADDR)]);
    let r = node.rpc_ok("addpeeraddress", vec![json!("127.0.0.1"), json!(port)]);
    assert_eq!(r["success"], true, "{r}");
    node.stop();
    let peers = node.datadir.join("regtest").join("peers.dat");
    let before = std::fs::read(&peers).unwrap();
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "fixture: the node dials nothing itself"
    );

    node.restart_preserving_datadir(&["--maxconnections=0", "--crawl=1", "--loglevel=debug"]);
    wait_for(
        "the crawl of the book's address and its answer",
        120,
        || sessions_done(&node, port) >= 1 && sessions_done(&node, dead) >= 1,
    );
    node.stop();
    assert!(accepts.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        read_book(&node).len(),
        3,
        "the address, and the two it named"
    );
    assert_eq!(
        std::fs::read(&peers).unwrap(),
        before,
        "peers.dat byte for byte"
    );
}

/// No session starts while the node is in initial block download; the
/// crawl starts once it leaves. The seed is `-crawlseed`, which the node's
/// own dialer never uses, so every connection is the crawl's.
#[test]
fn nothing_is_dialled_in_initial_block_download() {
    let (l, port) = bind();
    let accepts = scripted(
        l,
        core(vec![(closed_port(), false), (closed_port(), false)]),
    );
    let seed = format!("--crawlseed=127.0.0.1:{port}");
    let mut node = TestNode::start(&["--maxconnections=0", "--crawl=1", &seed, "--loglevel=info"]);
    std::thread::sleep(test_timeout(12));
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "no session in initial block download"
    );
    let log = std::fs::read_to_string(&node.stderr_log).unwrap_or_default();
    assert!(
        log.contains("The crawl waits for the node to leave initial block download"),
        "{log}"
    );
    assert!(
        log.contains("Crawl enabled: it will dial tens of thousands of addresses"),
        "the startup warning"
    );
    let info = node.rpc_ok("getcrawlinfo", vec![]);
    assert_eq!(
        (info["state"].clone(), info["held_by"].clone()),
        (json!("held"), json!(["initial_block_download"]))
    );
    assert_eq!(info["started"], false);
    node.rpc_ok("generatetoaddress", vec![json!(1), json!(ADDR)]);
    wait_for("the first crawl session", 60, || {
        accepts.load(Ordering::SeqCst) >= 1
    });
    let info = node.rpc_ok("getcrawlinfo", vec![]);
    assert_eq!(
        (info["state"].clone(), info["held_by"].clone()),
        (json!("running"), json!([]))
    );
    assert_eq!(info["started"], true);
    node.stop();
}

/// A node that claims Core and sends only `version` and `verack`, holding
/// the connection open and silent through the passive wait, is fake; one
/// that closes the connection straight after the handshake is closed
/// early. Both are reachable and counted by network and transport, and
/// each is counted on its own tally, in no family, claim or unknown:
/// `getcrawlinfo`, `getcrawlnodes`, the keyed export and the metrics say
/// so, and the book keeps the verdicts across a restart.
#[test]
fn the_crawl_counts_fake_and_closed_early_apart() {
    let (lf, fake) = bind();
    scripted(lf, fake_core());
    let (le, early) = bind();
    scripted(le, evicting_core());
    let metrics_port = find_available_port();
    let args = [
        "--maxconnections=0".to_string(),
        "--crawl=1".to_string(),
        format!("--crawlseed=127.0.0.1:{fake}"),
        format!("--crawlseed=127.0.0.1:{early}"),
        "--loglevel=debug".to_string(),
        format!("--metricsport={metrics_port}"),
    ];
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut c = TestNode::start(&args);
    c.rpc_ok("generatetoaddress", vec![json!(1), json!(ADDR)]);
    // The fake's discovery session waits out its getaddr and probes.
    wait_for("both sessions", 300, || {
        sessions_done(&c, fake) >= 1 && sessions_done(&c, early) >= 1
    });

    wait_for("the aggregate", 10, || {
        c.rpc_ok("getcrawlinfo", vec![])["reachable"]["total"] == 2
    });
    let info = c.rpc_ok("getcrawlinfo", vec![]);
    let check_info = |info: &serde_json::Value| {
        assert_eq!(
            info["reachable"],
            json!({ "total": 2, "ipv4": 2, "ipv6": 0, "onion": 0 }),
            "both reachable: {info}"
        );
        assert_eq!(info["transport"]["v1_v2_untried"]["count"], 2, "{info}");
        assert_eq!(
            info["fake"]["core"],
            json!({ "count": 1, "share": 0.5 }),
            "{info}"
        );
        assert_eq!(
            info["closed_early"],
            json!({ "count": 1, "share": 0.5 }),
            "{info}"
        );
        assert_eq!(info["families"]["core"]["count"], 0, "{info}");
        assert_eq!(info["families"]["unknown"]["count"], 0, "{info}");
        assert_eq!(info["claimed"]["core"]["count"], 0, "{info}");
        assert_eq!(info["mismatches"], 0);
    };
    check_info(&info);
    assert!(!info.to_string().contains("Satoshi"), "counts only");

    let verbose = c
        .rpc_call_with_named_params("getcrawlnodes", json!({ "verbose": true }))
        .unwrap();
    let rows = verbose["result"]
        .as_array()
        .unwrap_or_else(|| panic!("{verbose}"));
    let row = |port: u16| {
        rows.iter()
            .find(|r| r["addr"] == format!("127.0.0.1:{port}"))
            .expect("a row")
    };
    let f = row(fake);
    assert_eq!(f["fingerprint"], "fake/core", "{f}");
    assert_eq!(f["family"], serde_json::Value::Null);
    assert_eq!(f["reachable"], true);
    assert_eq!(f["observation"]["claimed"], "core");
    assert_eq!(f["observation"]["subver"], "/Satoshi:25.0.0/");
    let e = row(early);
    assert_eq!(e["fingerprint"], "closed-early", "{e}");
    assert_eq!(e["family"], serde_json::Value::Null);
    assert_eq!(
        (e["reachable"].clone(), e["transport"].clone()),
        (json!(true), json!("v1_v2_untried"))
    );
    assert_eq!(e["observation"]["claimed"], "core");
    assert_eq!(e["observation"]["subver"], "/Satoshi:32.1.0/");
    assert_eq!(e["observation"]["version"], 70016);
    assert_eq!(
        e["observation"]["getaddr"],
        serde_json::Value::Null,
        "closed: no getaddr"
    );

    let keyed = c.rpc_ok("dumpcrawlsnapshot", vec![]);
    let text = keyed.to_string();
    assert!(
        !text.contains("127.0.0.1")
            && !text.contains(&format!(":{fake}"))
            && !text.contains(&format!(":{early}"))
    );
    let mut fingerprints: Vec<String> = keyed["nodes"]
        .as_object()
        .unwrap()
        .values()
        .map(|n| n[13]["fingerprint"].as_str().unwrap().to_string())
        .collect();
    fingerprints.sort();
    assert_eq!(fingerprints, ["closed-early", "fake/core"], "{keyed}");

    let body = reqwest::blocking::get(format!("http://127.0.0.1:{metrics_port}/metrics"))
        .unwrap()
        .text()
        .unwrap();
    for line in [
        "satd_crawl_reachable{network=\"ipv4\"} 2",
        "satd_crawl_fake{family=\"core\"} 1",
        "satd_crawl_closed_early 1",
        "satd_crawl_family{family=\"core\"} 0",
        "satd_crawl_family{family=\"unknown\"} 0",
        "satd_crawl_claimed{family=\"core\"} 0",
    ] {
        assert!(body.lines().any(|l| l == line), "missing `{line}`");
    }
    c.stop();

    // The verdicts survive a restart: nothing is due, so the book stands.
    let book = read_book(&c);
    let verdict = |b: &CrawlBook, port: u16| {
        b.get(&CrawlAddr::Peer(peer(port)))
            .unwrap()
            .observation
            .as_ref()
            .unwrap()
            .verdict
    };
    assert_eq!(
        verdict(&book, early),
        node::net::survey::Verdict::ClosedEarly
    );
    assert_eq!(
        verdict(&book, fake),
        node::net::survey::Verdict::Fake(node::net::fingerprint::Family::Core)
    );
    c.restart_preserving_datadir(&args);
    check_info(&c.rpc_ok("getcrawlinfo", vec![]));
    c.stop();
}

/// The `getcrawlnodes` row of the address on `port`.
fn crawl_row(node: &TestNode, port: u16) -> Option<serde_json::Value> {
    let rows = node.rpc_ok("getcrawlnodes", vec![]);
    rows.as_array()?
        .iter()
        .find(|r| r["addr"] == format!("127.0.0.1:{port}"))
        .cloned()
}

/// A node that closes the first two crawl sessions straight after the
/// handshake (a Core node with its inbound slots full), and has room on
/// the third. The node's clock is mocked and frozen, so nothing falls due
/// on its own: each session after the first is the closed-early retry,
/// dialled once the clock is stepped to its due time (15 min, then 30 min,
/// each spread by a fifth), well inside the two-hour liveness window. The
/// third session settles: the address is Core and the schedule is cleared.
#[test]
fn a_closed_early_address_is_retried_until_it_settles() {
    let (l, port) = bind();
    let accepts = scripted(
        l,
        Shape {
            evict_first: 2,
            ..core(vec![])
        },
    );
    let metrics_port = find_available_port();
    let args = [
        "--maxconnections=0".to_string(),
        "--crawl=1".to_string(),
        format!("--crawlseed=127.0.0.1:{port}"),
        "--loglevel=debug".to_string(),
        format!("--metricsport={metrics_port}"),
    ];
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut c = TestNode::start(&args);
    // Frozen before the crawl leaves initial block download, so every
    // session is timed by it.
    let mut now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    c.rpc_ok("setmocktime", vec![json!(now)]);
    c.rpc_ok("generatetoaddress", vec![json!(1), json!(ADDR)]);

    for (n, wait) in [(1u64, 900u64), (2, 1_800)] {
        wait_for("a closed-early session", 300, || {
            sessions_done(&c, port) >= n as usize
        });
        wait_for("its row", 10, || {
            crawl_row(&c, port).is_some_and(|r| r["retry"]["count"] == n)
        });
        let row = crawl_row(&c, port).unwrap();
        assert_eq!(row["fingerprint"], "closed-early", "{row}");
        let due = row["retry"]["next_due"].as_u64().unwrap();
        assert!(
            (now + wait * 4 / 5..=now + wait * 6 / 5).contains(&due),
            "retry {n} due in {} s: {row}",
            due as i64 - now as i64
        );
        wait_for("the aggregate", 15, || {
            c.rpc_ok("getcrawlinfo", vec![])["retries"]["pending"] == 1
        });
        let body = reqwest::blocking::get(format!("http://127.0.0.1:{metrics_port}/metrics"))
            .unwrap()
            .text()
            .unwrap();
        assert!(
            body.lines()
                .any(|l| l == "satd_crawl_closed_early_retries 1"),
            "{body}"
        );
        // Not before its time.
        std::thread::sleep(Duration::from_secs(3));
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            n as usize,
            "nothing is due before the retry"
        );
        c.rpc_ok("setmocktime", vec![json!(due)]);
        now = due;
    }
    wait_for("the third session", 300, || sessions_done(&c, port) >= 3);
    wait_for("its row", 10, || {
        crawl_row(&c, port).is_some_and(|r| r["fingerprint"] != "closed-early")
    });
    let row = crawl_row(&c, port).unwrap();
    // A liveness session sends no getaddr: Core is observed or only claimed.
    assert!(
        row["fingerprint"].as_str().unwrap().starts_with("core/"),
        "{row}"
    );
    assert!(row.get("retry").is_none(), "settled: no retry: {row}");
    assert_eq!(accepts.load(Ordering::SeqCst), 3);
    wait_for("the aggregate", 15, || {
        c.rpc_ok("getcrawlinfo", vec![])["retries"]["pending"] == 0
    });
    let info = c.rpc_ok("getcrawlinfo", vec![]);
    assert_eq!(
        info["retries"],
        json!({ "pending": 0, "exhausted": 0 }),
        "{info}"
    );
    assert_eq!(info["closed_early"]["count"], 0, "{info}");
    let core = info["families"]["core"]["count"].as_u64().unwrap()
        + info["claimed"]["core"]["count"].as_u64().unwrap();
    assert_eq!(core, 1, "{info}");
    c.stop();
}

/// The committed country file the node tests write and check
/// (`node::net::country`): documentation ranges only, so a loopback peer
/// has no country in it.
fn country_fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/country-test.mmdb")
}

/// With `-countryfile`, `getcrawlinfo` counts the reachable nodes per
/// country: the scripted loopback peer is in no country of the file, so it
/// is `unknown`, and the totals add up to the reachable count. Without the
/// option, `countries` is null (checked on the same node after a restart),
/// and a relative path is read from the data directory.
#[test]
fn getcrawlinfo_counts_countries_with_a_country_file() {
    let (l, port) = bind();
    let _accepts = scripted(l, core(vec![]));
    let seed = format!("--crawlseed=127.0.0.1:{port}");
    let country = format!("--countryfile={}", country_fixture().display());
    let mut node = TestNode::start(&[
        "--maxconnections=0",
        "--crawl=1",
        &seed,
        &country,
        "--loglevel=debug",
    ]);
    node.rpc_ok("generatetoaddress", vec![json!(1), json!(ADDR)]);
    // The discovery session waits out its getaddr and probes.
    wait_for("the seed's session", 300, || {
        sessions_done(&node, port) >= 1
    });
    wait_for("the aggregate", 10, || {
        node.rpc_ok("getcrawlinfo", vec![])["reachable"]["total"] == 1
    });
    let info = node.rpc_ok("getcrawlinfo", vec![]);
    assert_eq!(
        info["countries"],
        json!({
            "unknown": {"count": 1, "share": 1.0},
            "other": {"count": 0, "share": 0.0},
            "onion": {"count": 0, "share": 0.0},
        }),
        "{info}"
    );
    let raw = node.rpc_ok("dumpcrawlsnapshot", vec![json!(true)]);
    assert_eq!(
        raw["satd"]["countries"],
        json!({"unknown": 1, "other": 0, "onion": 0}),
        "{raw}"
    );
    node.stop();

    std::fs::copy(country_fixture(), node.datadir.join("country.mmdb")).unwrap();
    node.restart_preserving_datadir(&[
        "--maxconnections=0",
        "--crawl=1",
        &seed,
        "--countryfile=country.mmdb",
    ]);
    assert!(
        node.rpc_ok("getcrawlinfo", vec![])["countries"].is_object(),
        "read from the data directory"
    );
    node.stop();

    node.restart_preserving_datadir(&["--maxconnections=0", "--crawl=1", &seed]);
    let info = node.rpc_ok("getcrawlinfo", vec![]);
    assert!(info["countries"].is_null(), "{info}");
    node.stop();
}

/// A country file that is not a MaxMind DB fails startup, naming the file,
/// as a bad asmap does, before the node finishes loading; a missing one
/// fails it too. A node still running after the timeout is killed and
/// fails the test.
#[test]
fn a_bad_country_file_fails_startup() {
    use std::process::{Command, Stdio};
    let dir = common::fresh_test_datadir("satd-bad-countryfile");
    std::fs::write(dir.join("country.mmdb"), b"not a MaxMind DB").unwrap();
    let out_path = dir.join("startup.log");
    let run = |file: &str| {
        // Its log and its errors in one file: the log goes to stdout.
        let out = std::fs::File::create(&out_path).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_satd"))
            .arg("--regtest")
            .arg(format!("--datadir={}", dir.display()))
            .arg(format!("--rpcport={}", find_available_port()))
            .arg(format!("--port={}", find_available_port()))
            .arg(format!("--countryfile={file}"))
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .expect("spawn satd");
        let deadline = Instant::now() + test_timeout(60);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        (status, std::fs::read_to_string(&out_path).unwrap())
    };
    let (bad, bad_err) = run("country.mmdb");
    let (missing, missing_err) = run("missing.mmdb");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        bad.is_some_and(|s| !s.success()),
        "a bad file must fail startup: {bad:?} {bad_err}"
    );
    assert!(
        bad_err.contains("Error loading the country file") && bad_err.contains("country.mmdb"),
        "{bad_err}"
    );
    assert!(
        !bad_err.contains("Done loading"),
        "it fails before the node has loaded: {bad_err}"
    );
    assert!(
        missing.is_some_and(|s| !s.success()),
        "a missing file must fail startup: {missing:?}"
    );
    assert!(
        missing_err.contains("country file not found"),
        "{missing_err}"
    );
}

/// A no-authentication SOCKS5 proxy on loopback that relays CONNECTs to
/// IPv4 and IPv6 addresses, recording each target asked for, or with
/// `refuse` answers every CONNECT with reply 0x05.
fn socks_proxy(refuse: bool) -> (u16, Arc<std::sync::Mutex<Vec<SocketAddr>>>) {
    let (listener, port) = bind();
    let asked: Arc<std::sync::Mutex<Vec<SocketAddr>>> = Default::default();
    let seen = asked.clone();
    std::thread::spawn(move || {
        for mut sock in listener.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || -> io::Result<()> {
                let mut head = [0u8; 2];
                sock.read_exact(&mut head)?;
                let mut methods = vec![0u8; head[1] as usize];
                sock.read_exact(&mut methods)?;
                sock.write_all(&[0x05, 0x00])?;
                let mut req = [0u8; 4];
                sock.read_exact(&mut req)?;
                let ip = match req[3] {
                    0x01 => {
                        let mut a = [0u8; 4];
                        sock.read_exact(&mut a)?;
                        std::net::IpAddr::from(a)
                    }
                    0x04 => {
                        let mut a = [0u8; 16];
                        sock.read_exact(&mut a)?;
                        std::net::IpAddr::from(a)
                    }
                    _ => return Ok(()),
                };
                let mut port = [0u8; 2];
                sock.read_exact(&mut port)?;
                let target = SocketAddr::new(ip, u16::from_be_bytes(port));
                seen.lock().unwrap().push(target);
                let reply = |code: u8| [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
                let out = match (refuse, TcpStream::connect(target)) {
                    (false, Ok(out)) => out,
                    _ => return sock.write_all(&reply(0x05)),
                };
                sock.write_all(&reply(0x00))?;
                let (mut a_in, mut b_out) = (sock.try_clone()?, out.try_clone()?);
                let (mut b_in, mut a_out) = (out, sock);
                std::thread::spawn(move || {
                    let _ = io::copy(&mut a_in, &mut b_out);
                    let _ = b_out.shutdown(std::net::Shutdown::Write);
                });
                let _ = io::copy(&mut b_in, &mut a_out);
                let _ = a_out.shutdown(std::net::Shutdown::Write);
                Ok(())
            });
        }
    });
    (port, asked)
}

/// `-crawlproxy`: the crawl's clearnet dials go through it and reach a
/// real regtest node, even under `-proxy`, which is never asked for one.
/// `getcrawlinfo` says a crawl proxy is set, with no failure, and never
/// names it; the startup warning says the dials leave through the proxy.
#[test]
fn the_crawl_dials_clearnet_through_the_crawl_proxy() {
    let mut x = TestNode::start(&[]);
    let xp = x.p2p_port.unwrap();
    let (crawl_proxy, crawl_asked) = socks_proxy(false);
    let (tor_proxy, tor_asked) = socks_proxy(true);
    let args = [
        "--maxconnections=0".to_string(),
        "--crawl=1".to_string(),
        format!("--crawlseed=127.0.0.1:{xp}"),
        format!("--crawlproxy=127.0.0.1:{crawl_proxy}"),
        format!("--proxy=127.0.0.1:{tor_proxy}"),
        "--loglevel=debug".to_string(),
    ];
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut c = TestNode::start(&args);
    c.rpc_ok("generatetoaddress", vec![json!(1), json!(ADDR)]);
    wait_for("a session to the node", 300, || sessions_done(&c, xp) >= 1);
    let target = SocketAddr::from(([127, 0, 0, 1], xp));
    assert!(
        crawl_asked.lock().unwrap().contains(&target),
        "the crawl proxy was asked for the node"
    );
    assert!(tor_asked.lock().unwrap().is_empty(), "-proxy never was");
    wait_for("the aggregate", 10, || {
        c.rpc_ok("getcrawlinfo", vec![])["reachable"]["total"] == 1
    });
    let info = c.rpc_ok("getcrawlinfo", vec![]);
    assert_eq!(info["proxy"], json!({ "set": true, "failures": 0 }), "{info}");
    assert!(
        info["limits"]["networks"]
            .as_array()
            .unwrap()
            .contains(&json!("ipv4")),
        "{info}"
    );
    let text = info.to_string();
    assert!(
        !text.contains(&format!("127.0.0.1:{crawl_proxy}")),
        "no proxy address in getcrawlinfo: {text}"
    );
    let log = std::fs::read_to_string(&c.stderr_log).unwrap_or_default();
    assert!(
        log.contains("leave through the crawl proxy (-crawlproxy)"),
        "the startup warning"
    );
    c.stop();
    x.stop();
}
