//! A node that catches up through its parallel block download announces the
//! tip it reaches, as Bitcoin Core announces each new tip (`UpdatedBlockTip`),
//! exercised over a raw connection that, like Core, never polls for headers.

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
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const ADDR: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

/// A raw peer, read on the test's own thread. It answers pings and sends
/// nothing else, so whatever it learns, the node told it unasked.
struct Peer {
    stream: TcpStream,
}

impl Peer {
    fn connect(port: u16) -> Self {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let stream = loop {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                Ok(s) => break s,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => panic!("connect to the node: {e}"),
            }
        };
        stream.set_nodelay(true).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut peer = Peer { stream };
        peer.send(NetworkMessage::Version(version()));
        let (mut got_version, mut got_verack) = (false, false);
        while !(got_version && got_verack) {
            match peer.recv(Duration::from_secs(30)).expect("handshake") {
                NetworkMessage::Version(_) => {
                    got_version = true;
                    peer.send(NetworkMessage::Verack);
                }
                NetworkMessage::Verack => got_verack = true,
                _ => {}
            }
        }
        peer
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

    /// Whether the node announces `block`, by `inv`, `headers` or
    /// `cmpctblock`, within `timeout`.
    fn hears_of(&mut self, block: BlockHash, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            match self.recv(left) {
                Ok(NetworkMessage::Ping(n)) => self.send(NetworkMessage::Pong(n)),
                Ok(NetworkMessage::Inv(inv)) if inv.contains(&Inventory::Block(block)) => return true,
                Ok(NetworkMessage::Headers(h)) if h.iter().any(|h| h.block_hash() == block) => return true,
                Ok(NetworkMessage::CmpctBlock(c)) if c.compact_block.header.block_hash() == block => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
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
        nonce: 0x5a7d_a110_0ce5_0001,
        user_agent: "/p2p-announce-test/".into(),
        start_height: 0,
        relay: true,
    }
}

fn best_hash(node: &TestNode) -> BlockHash {
    node.rpc_ok("getbestblockhash", vec![]).as_str().unwrap().parse().unwrap()
}

/// Blocks connected by the catch-up emit no chain event, so the announcement
/// task never heard of them: a peer that learns of blocks only from this
/// node, and does not poll for headers as Core does not, stayed at the
/// height it had when the catch-up began until another block was found.
#[test]
fn a_catch_up_announces_the_tip_it_reaches() {
    let port_a = find_available_port();
    let node_a = TestNode::start(&[&format!("--port={port_a}")]);
    node_a.rpc_ok("generatetoaddress", vec![json!(200), json!(ADDR)]);
    let tip = best_hash(&node_a);

    let port_b = find_available_port();
    let node_b = TestNode::start(&[&format!("--port={port_b}")]);
    let mut peer = Peer::connect(port_b);

    // 200 blocks behind: B catches up by the parallel download.
    node_b.rpc_ok("addnode", vec![json!(format!("127.0.0.1:{port_a}")), json!("onetry")]);
    poll_until(|| best_hash(&node_b) == tip, test_timeout(180), "B did not catch up to A");

    assert!(
        peer.hears_of(tip, test_timeout(30)),
        "B never announced the tip its catch-up reached"
    );
}
