//! The initial-block-download scheduler against a live regtest node, over a
//! raw peer connection that the test controls.

mod common;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use common::TestNode;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const ADDR: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

/// A raw inbound peer, read on the test's own thread.
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
                Err(e) => panic!("connect to {addr}: {e}"),
            }
        };
        stream.set_nodelay(true).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut peer = Peer { stream };
        peer.send(NetworkMessage::Version(version()));
        let mut got_version = false;
        loop {
            match peer.recv(Duration::from_secs(30)) {
                Ok(NetworkMessage::Version(_)) => got_version = true,
                Ok(NetworkMessage::Verack) if got_version => break,
                Ok(_) => {}
                Err(e) => panic!("handshake: {e}"),
            }
        }
        peer.send(NetworkMessage::Verack);
        peer
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

    /// Read, answering pings, until the node closes the connection or
    /// `timeout` passes. Returns when it closed, measured from the call.
    fn closed_within(&mut self, timeout: Duration) -> Option<Duration> {
        let start = Instant::now();
        let deadline = start + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            match self.recv(left) {
                Ok(NetworkMessage::Ping(n)) => self.send(NetworkMessage::Pong(n)),
                Ok(_) => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return None,
                Err(_) => return Some(start.elapsed()),
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
        nonce: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64,
        user_agent: "/p2p-ibd-test/".into(),
        start_height: 60,
        relay: true,
    }
}

/// #972: a peer that is asked for blocks during initial block download and
/// sends none is disconnected once the stall timeout (15s) passes, as Core
/// disconnects a peer stalling block download. satd only took the blocks
/// back: the peer stayed connected and was handed the same heights again on
/// the same tick, until the silent-peer check dropped it about a minute
/// later.
#[test]
fn a_peer_stalling_block_download_is_disconnected() {
    // The chain the stalling peer claims to have: real headers, mined by a
    // second node, far enough ahead to start initial block download.
    let mut source = TestNode::start(&[]);
    source.mine_blocks(60, ADDR);
    let headers: Vec<bitcoin::block::Header> = (1..=60)
        .map(|h| {
            let hash = source.rpc_ok("getblockhash", vec![serde_json::json!(h)]);
            let hex = source.rpc_ok("getblockheader", vec![hash, serde_json::json!(false)]);
            deserialize(&hex::decode(hex.as_str().unwrap()).unwrap()).unwrap()
        })
        .collect();

    let node = TestNode::start(&["--loglevel=info"]);
    let mut peer = Peer::connect(node.p2p_port.unwrap());
    peer.send(NetworkMessage::Headers(headers));

    // The node asks the peer for blocks, which it never sends.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
        match peer.recv(left) {
            Ok(NetworkMessage::GetData(inv))
                if inv.iter().any(|i| matches!(i, Inventory::WitnessBlock(_) | Inventory::Block(_))) =>
            {
                break;
            }
            Ok(NetworkMessage::Ping(n)) => peer.send(NetworkMessage::Pong(n)),
            Ok(_) => {}
            Err(e) => panic!("the node never asked the peer for blocks: {e}"),
        }
    }

    // 15s of stall timeout plus the 2s scheduler tick, with room for a slow
    // runner; the silent-peer path took about a minute.
    let closed = peer.closed_within(Duration::from_secs(35));
    let log = std::fs::read_to_string(&node.stderr_log).unwrap_or_default();
    assert!(closed.is_some(), "the stalling peer is still connected 35s after its getdata; log:\n{log}");
    assert!(
        log.contains("IBD: peer is stalling block download, disconnecting"),
        "the peer was disconnected, but not for stalling; log:\n{log}"
    );
}
