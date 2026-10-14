//! Addresses a peer hands a regtest node, and the manual connections it
//! opens with its automatic outbound slots full: Bitcoin Core's address rate
//! limit (`net_processing.cpp` `ProcessAddrs`) and its separate limits for
//! manual connections (`net.cpp` `ThreadOpenAddedConnections`, `rpc/net.cpp`
//! `addnode`), exercised over raw connections.

mod common;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use common::{TestNode, find_available_port, poll_until, test_timeout};
use serde_json::json;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

const ADDR: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

/// A raw peer, read on the test's own thread.
struct Peer {
    stream: TcpStream,
}

impl Peer {
    /// Connect to `port` and complete the handshake.
    fn connect(port: u16) -> Self {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let stream = loop {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                Ok(s) => break s,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => panic!("connect to {addr}: {e}"),
            }
        };
        Self::handshake(stream).expect("handshake with the node")
    }

    /// Accept the connection the node dials to `listener` within `timeout`.
    fn accept(listener: &TcpListener, timeout: Duration) -> Option<Self> {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + timeout;
        let stream = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(_) => return None,
            }
        };
        stream.set_nonblocking(false).unwrap();
        Some(Self::handshake(stream).expect("handshake with the dialling node"))
    }

    fn handshake(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut peer = Peer { stream };
        peer.send(NetworkMessage::Version(version()));
        let (mut got_version, mut got_verack) = (false, false);
        while !(got_version && got_verack) {
            match peer.recv(Duration::from_secs(30))? {
                NetworkMessage::Version(_) => {
                    got_version = true;
                    peer.send(NetworkMessage::Verack);
                }
                NetworkMessage::Verack => got_verack = true,
                _ => {}
            }
        }
        Ok(peer)
    }

    fn send(&mut self, msg: NetworkMessage) {
        let _ = self.stream.write_all(&serialize(&RawNetworkMessage::new(Magic::REGTEST, msg)));
    }

    fn recv(&mut self, timeout: Duration) -> io::Result<NetworkMessage> {
        self.stream.set_read_timeout(Some(timeout)).unwrap();
        let mut header = [0u8; 24];
        self.stream.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut buf = header.to_vec();
        buf.resize(24 + len, 0);
        self.stream.read_exact(&mut buf[24..])?;
        let raw: RawNetworkMessage =
            deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(raw.into_payload())
    }

    /// Answer pings until the node sends a message `pred` accepts.
    fn recv_until(&mut self, timeout: Duration, pred: impl Fn(&NetworkMessage) -> bool) -> Option<NetworkMessage> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
            match self.recv(left) {
                Ok(NetworkMessage::Ping(n)) => self.send(NetworkMessage::Pong(n)),
                Ok(m) if pred(&m) => return Some(m),
                Ok(_) => {}
                Err(_) => return None,
            }
        }
    }

    /// Send `msg` and wait until the node has handled it: the node handles
    /// one peer's messages in order, so the `pong` to a `ping` sent after it
    /// comes once `msg` is done.
    fn send_and_sync(&mut self, msg: NetworkMessage) {
        self.send(msg);
        let nonce = rand_nonce();
        self.send(NetworkMessage::Ping(nonce));
        assert!(
            self.recv_until(test_timeout(30), |m| matches!(m, NetworkMessage::Pong(n) if *n == nonce))
                .is_some(),
            "the node answers the ping"
        );
    }
}

fn version() -> VersionMessage {
    let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
    VersionMessage {
        version: 70016,
        services,
        timestamp: 1_760_000_000,
        receiver: Address::new(&zero, ServiceFlags::NONE),
        sender: Address::new(&zero, services),
        nonce: rand_nonce(),
        user_agent: "/p2p-addr-dials-test/".into(),
        start_height: 0,
        relay: true,
    }
}

/// A distinct nonce per call, so the node's self-connection check never
/// mistakes one raw peer for another.
fn rand_nonce() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    h.finish()
}

/// An `addr` of `n` full-node addresses, each in a /16 of its own (so the
/// address book's per-group limit does not apply), from first octet `base`.
fn addr_msg(base: u8, n: usize) -> NetworkMessage {
    let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    NetworkMessage::Addr(
        (0..n)
            .map(|i| {
                let a = SocketAddr::from(([base + (i / 250) as u8, (i % 250) as u8, 7, 7], 8333));
                (1_760_000_000, Address::new(&a, services))
            })
            .collect(),
    )
}

/// The one `getpeerinfo` entry for a peer that reached the node on `port`.
fn peer_on(node: &TestNode, port: u16) -> serde_json::Value {
    let suffix = format!(":{port}");
    let peers: Vec<serde_json::Value> = node
        .rpc_ok("getpeerinfo", vec![])
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["addrbind"].as_str().is_some_and(|b| b.ends_with(&suffix)))
        .cloned()
        .collect();
    assert_eq!(peers.len(), 1, "one peer on {port}: {peers:?}");
    peers[0].clone()
}

fn addr_counts(node: &TestNode, port: u16) -> (u64, u64) {
    let p = peer_on(node, port);
    (p["addr_processed"].as_u64().unwrap(), p["addr_rate_limited"].as_u64().unwrap())
}

/// The addresses `addr_msg` announced that the address book holds (the
/// book also holds the outbound peers the node connected to).
fn book_size(node: &TestNode) -> usize {
    node.rpc_ok("getnodeaddresses", vec![json!(0)])
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["address"].as_str().is_some_and(|a| a.ends_with(".7.7")))
        .count()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Core meters the addresses each peer announces with a token bucket: one
/// token to start, then 0.1 a second, and a peer with the `addr` permission
/// is not metered (`ProcessAddrs`; Core's `p2p_addr_relay.py`
/// `rate_limit_tests` makes the same steps). satd took every entry of every
/// message and reported both `getpeerinfo` counters as 0.
#[test]
fn a_peers_addresses_are_rate_limited_unless_it_has_the_addr_permission() {
    let p2p = find_available_port();
    let exempt_port = find_available_port();
    let node = TestNode::start(&[
        &format!("--port={p2p}"),
        &format!("--bind=127.0.0.1:{p2p}"),
        &format!("--whitebind=addr@127.0.0.1:{exempt_port}"),
    ]);
    let start = now_secs() - 1000;
    node.rpc_ok("setmocktime", vec![json!(start)]);

    let mut limited = Peer::connect(p2p);
    limited.send_and_sync(addr_msg(1, 1000));
    assert_eq!(addr_counts(&node, p2p), (1, 999), "one token: one address");
    assert_eq!(book_size(&node), 1);

    // A hundred seconds earn ten more.
    node.rpc_ok("setmocktime", vec![json!(start + 100)]);
    limited.send_and_sync(addr_msg(20, 1000));
    assert_eq!(addr_counts(&node, p2p), (11, 1989));
    assert_eq!(book_size(&node), 11);

    let mut exempt = Peer::connect(exempt_port);
    exempt.send_and_sync(addr_msg(40, 1000));
    assert_eq!(addr_counts(&node, exempt_port), (1000, 0), "the addr permission takes them all");
    assert_eq!(book_size(&node), 1011);
}

/// Core adds a thousand tokens when it sends a peer `getaddr`, so the
/// answer is taken whole. An addr-fetch connection exists for that answer.
#[test]
fn an_addr_fetch_peers_answer_is_taken_whole() {
    let node = TestNode::start(&["--v2transport=0"]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap().to_string();
    node.rpc_ok("addconnection", vec![json!(target), json!("addr-fetch"), json!(false)]);
    let mut peer = Peer::accept(&listener, test_timeout(30)).expect("the node dials the addr-fetch peer");
    assert!(
        peer.recv_until(test_timeout(30), |m| matches!(m, NetworkMessage::GetAddr)).is_some(),
        "the node asks for addresses"
    );
    peer.send(addr_msg(1, 600));
    poll_until(|| book_size(&node) == 600, test_timeout(30), "all 600 addresses are learned");
}

/// Core counts manual connections apart from the automatic outbound target:
/// `addnode onetry` takes no grant at all, and added nodes have their own
/// limit of eight (`semAddnode`), redialled every minute however many
/// automatic peers there are. satd counted manual connections against the
/// automatic target, so once it was full `onetry` failed with "max outbound
/// connections reached" and an added node whose first dial failed was never
/// dialled again; an `onetry` to a connected peer failed with "already
/// connected", where Core answers null.
#[test]
fn manual_connections_are_outside_the_automatic_outbound_target() {
    // `-maxconnections=3` caps the automatic target at three.
    let mut node = TestNode::start(&["--v2transport=0", "--maxconnections=3"]);
    // Out of IBD: the target is 64 there.
    node.mine_blocks(1, ADDR);

    let mut automatic = Vec::new();
    for _ in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        node.rpc_ok("addconnection", vec![json!(target), json!("outbound-full-relay"), json!(false)]);
        automatic.push(Peer::accept(&listener, test_timeout(30)).expect("an automatic peer"));
    }
    let outbound = |node: &TestNode| {
        node.rpc_ok("getpeerinfo", vec![])
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["inbound"] == json!(false))
            .map(|p| (p["addr"].as_str().unwrap().to_string(), p["connection_type"].as_str().unwrap().to_string()))
            .collect::<Vec<_>>()
    };
    poll_until(|| outbound(&node).len() == 3, test_timeout(20), "three automatic peers");

    // `onetry`, with the automatic slots full.
    let one = TcpListener::bind("127.0.0.1:0").unwrap();
    let one_addr = one.local_addr().unwrap().to_string();
    let out = node.rpc_call_with_params("addnode", vec![json!(one_addr), json!("onetry")]).unwrap();
    assert!(out["error"].is_null(), "onetry is outside the automatic target: {out}");
    let _one = Peer::accept(&one, test_timeout(30)).expect("the onetry dial");
    poll_until(
        || outbound(&node).contains(&(one_addr.clone(), "manual".to_string())),
        test_timeout(20),
        "the onetry peer is a manual connection",
    );
    // And again, to the connected peer: null, as in Core.
    let out = node.rpc_call_with_params("addnode", vec![json!(one_addr), json!("onetry")]).unwrap();
    assert!(out["error"].is_null(), "onetry to a connected peer answers null: {out}");
    assert_eq!(out["result"], json!(null));

    // An added node whose first dial fails is dialled again.
    let port = find_available_port();
    let added = format!("127.0.0.1:{port}");
    node.rpc_ok("addnode", vec![json!(added), json!("add")]);
    std::thread::sleep(Duration::from_secs(1));
    let listener = TcpListener::bind(&added).unwrap();
    let _added = Peer::accept(&listener, test_timeout(40)).expect("the added node is dialled again");
    poll_until(
        || outbound(&node).contains(&(added.clone(), "manual".to_string())),
        test_timeout(20),
        "the added node is a manual connection",
    );
    assert_eq!(outbound(&node).len(), 5, "three automatic peers and two manual ones");
    node.stop();
}
