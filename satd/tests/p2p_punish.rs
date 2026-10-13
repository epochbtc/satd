//! What a regtest node does with a peer that misbehaves, by where the peer
//! connected from: Bitcoin Core's `MaybeDiscourageAndDisconnect`
//! (`net_processing.cpp`), exercised over raw connections.

mod common;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use bitcoin::BlockHash;
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
    /// Connect to `port` and complete the handshake, or report why not.
    fn connect(port: u16) -> io::Result<Self> {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let stream = loop {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                Ok(s) => break s,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => return Err(e),
            }
        };
        Self::handshake(stream)
    }

    /// Accept the connection the node dials to `listener`: an outbound peer
    /// of the node.
    fn accept(listener: &TcpListener) -> Self {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let stream = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(e) => panic!("the node never dialled us: {e}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        Self::handshake(stream).expect("handshake with the dialling node")
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
        // The node may close the socket part way through.
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

    /// Answer pings until the node sends a message `pred` accepts; `None` if
    /// the connection ends or nothing arrives in time.
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

    /// The node closes the connection within `timeout`.
    fn closed_within(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            match self.recv(left) {
                Ok(NetworkMessage::Ping(n)) => self.send(NetworkMessage::Pong(n)),
                Ok(_) => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return false,
                Err(_) => return true,
            }
        }
    }

    /// The node still serves this peer: a `getdata` sent now, after whatever
    /// was sent before it, is answered with the block. The node handles one
    /// peer's messages in order, so the answer also shows that nothing sent
    /// earlier ended the connection.
    fn served(&mut self, block: BlockHash) -> bool {
        self.send(NetworkMessage::GetData(vec![Inventory::WitnessBlock(block)]));
        self.recv_until(Duration::from_secs(30), |m| matches!(m, NetworkMessage::Block(b) if b.block_hash() == block))
            .is_some()
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
        user_agent: "/p2p-punish-test/".into(),
        start_height: 0,
        relay: true,
    }
}

/// A distinct version nonce per connection, so the node's self-connection
/// check never mistakes one raw peer for another.
fn rand_nonce() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    h.finish()
}

fn best_hash(node: &TestNode) -> BlockHash {
    node.rpc_ok("getbestblockhash", vec![]).as_str().unwrap().parse().unwrap()
}

/// `getblocktxn` for an index past the end of `block`: Core's
/// "getblocktxn with out-of-bounds tx indices", `Misbehaving`.
fn out_of_range_getblocktxn(block: BlockHash) -> NetworkMessage {
    NetworkMessage::GetBlockTxn(bitcoin::p2p::message_compact_blocks::GetBlockTxn {
        txs_request: bitcoin::bip152::BlockTransactionsRequest { block_hash: block, indexes: vec![5] },
    })
}

fn banned(node: &TestNode) -> Vec<serde_json::Value> {
    node.rpc_ok("listbanned", vec![]).as_array().unwrap().clone()
}

/// `getpeerinfo` entries for peers that reached the node on `port`.
fn peers_on(node: &TestNode, port: u16) -> Vec<serde_json::Value> {
    let suffix = format!(":{port}");
    node.rpc_ok("getpeerinfo", vec![])
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["addrbind"].as_str().is_some_and(|b| b.ends_with(&suffix)))
        .cloned()
        .collect()
}

/// Core disconnects a misbehaving peer on a local address without punishing
/// the address, since that would punish every peer on it. Every inbound
/// onion peer arrives from the address Tor dialled from, 127.0.0.1 here, as
/// does every local integration. satd banned 127.0.0.1 for `-bantime`, so one
/// such peer shut every other one out until the ban expired, across restarts.
///
/// Each listener in turn: the peer misbehaves and is disconnected, nothing
/// is banned, and a second peer on the same listener is let in and served.
#[test]
fn a_misbehaving_onion_or_local_peer_is_disconnected_without_a_ban() {
    let p2p = find_available_port();
    let onion = find_available_port();
    let mut node = TestNode::start(&[
        &format!("--port={p2p}"),
        &format!("--bind=127.0.0.1:{p2p}"),
        &format!("--bind=127.0.0.1:{onion}=onion"),
    ]);
    node.mine_blocks(1, ADDR);
    let tip = best_hash(&node);

    for (listener, port, network) in [("onion", onion, "onion"), ("clearnet", p2p, "not_publicly_routable")] {
        let mut peer = Peer::connect(port).unwrap_or_else(|e| panic!("{listener}: first peer: {e}"));
        poll_until(|| peers_on(&node, port).len() == 1, test_timeout(20), "the peer is listed");
        // Core's `ConnectedThroughNetwork`: an inbound onion peer is on the
        // onion network whatever its socket address.
        assert_eq!(peers_on(&node, port)[0]["network"], json!(network), "{listener}: getpeerinfo.network");

        peer.send(out_of_range_getblocktxn(tip));
        assert!(peer.closed_within(test_timeout(30)), "{listener}: the misbehaving peer is disconnected");
        assert_eq!(banned(&node), Vec::<serde_json::Value>::new(), "{listener}: nothing is banned");

        let mut next = Peer::connect(port)
            .unwrap_or_else(|e| panic!("{listener}: a second peer on the same listener is refused: {e}"));
        assert!(next.served(tip), "{listener}: the second peer is served");
    }
    node.stop();
}

/// Core never punishes a manual connection (`addnode`, `-addnode`,
/// `-connect`): it stays connected and its address is not punished. satd
/// banned it like any other peer, and the redial loop then skipped the
/// banned address, so a `-connect` node could be left with no peers.
#[test]
fn a_misbehaving_manual_peer_stays_connected() {
    let mut node = TestNode::start(&["--v2transport=0"]);
    node.mine_blocks(1, ADDR);
    let tip = best_hash(&node);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap().to_string();
    node.rpc_ok("addnode", vec![json!(target), json!("onetry")]);
    let mut peer = Peer::accept(&listener);
    poll_until(
        || {
            node.rpc_ok("getpeerinfo", vec![])
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["addr"] == json!(target) && p["connection_type"] == json!("manual"))
        },
        test_timeout(20),
        "the manual peer is listed",
    );

    peer.send(out_of_range_getblocktxn(tip));
    assert!(peer.served(tip), "the manual peer is still connected and served");
    assert_eq!(banned(&node), Vec::<serde_json::Value>::new(), "nothing is banned");
    node.stop();
}
