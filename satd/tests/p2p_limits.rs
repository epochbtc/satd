//! Bitcoin Core's limits on what one P2P message may carry, and its send
//! buffer, exercised against a live regtest node over raw connections.

mod common;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::{CommandString, NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use bitcoin::BlockHash;
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
        self.send_raw(&serialize(&RawNetworkMessage::new(Magic::REGTEST, msg)));
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        // The node may close the socket part way through.
        let _ = self.stream.write_all(bytes);
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
    fn recv_until(&mut self, timeout: Duration, pred: impl Fn(&NetworkMessage) -> bool) -> NetworkMessage {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
            match self.recv(left) {
                Ok(NetworkMessage::Ping(n)) => self.send(NetworkMessage::Pong(n)),
                Ok(m) if pred(&m) => return m,
                Ok(_) => {}
                Err(e) => panic!("waiting for a message: {e}"),
            }
        }
    }

    /// The connection is still up: a ping gets its pong.
    fn alive(&mut self) -> bool {
        self.send(NetworkMessage::Ping(0x1234));
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
            match self.recv(left) {
                Ok(NetworkMessage::Pong(0x1234)) => return true,
                Ok(NetworkMessage::Ping(n)) => self.send(NetworkMessage::Pong(n)),
                Ok(_) => {}
                Err(_) => return false,
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
                Ok(_) => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return false,
                Err(_) => return true,
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
        nonce: rand_nonce(),
        user_agent: "/p2p-limits-test/".into(),
        start_height: 0,
        relay: true,
    }
}

fn rand_nonce() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
}

fn unknown(len: usize) -> NetworkMessage {
    NetworkMessage::Unknown { command: CommandString::try_from_static("bigmsg").unwrap(), payload: vec![0x5a; len] }
}

/// Core's `MAX_PROTOCOL_MESSAGE_LENGTH`: a message of 4,000,000 bytes is
/// taken (and, of an unknown type, ignored); one byte more and the node
/// drops the connection. satd took frames up to 32 MiB.
#[test]
fn a_frame_over_four_million_bytes_ends_the_connection() {
    let mut node = TestNode::start(&[]);
    let port = node.p2p_port.unwrap();

    let mut peer = Peer::connect(port);
    peer.send(unknown(4_000_000));
    assert!(peer.alive(), "a 4,000,000-byte message is within the limit");

    let mut peer = Peer::connect(port);
    peer.send(unknown(4_000_001));
    assert!(peer.closed_within(Duration::from_secs(30)), "a 4,000,001-byte message ends the connection");
    node.stop();
}

/// Core's `MAX_INV_SZ`: an `inv` of 50,000 entries is fine, one of 50,001 is
/// misbehaviour and the peer is dropped.
#[test]
fn an_inv_over_max_inv_sz_ends_the_connection() {
    let mut node = TestNode::start(&[]);
    let port = node.p2p_port.unwrap();
    let entry = Inventory::Unknown { inv_type: 99, hash: [7u8; 32] };

    let mut peer = Peer::connect(port);
    peer.send(NetworkMessage::Inv(vec![entry; 50_000]));
    assert!(peer.alive(), "50,000 entries are within the limit");
    // Misbehaviour ends the connection (a peer on 127.0.0.1 is disconnected,
    // not banned), so the refusal goes last.
    peer.send(NetworkMessage::Inv(vec![entry; 50_001]));
    assert!(peer.closed_within(Duration::from_secs(30)), "50,001 entries end the connection");
    node.stop();
}

/// One `getdata` for more data than the socket and the peer's queue can
/// hold is served in full and in order, as the peer reads (Core keeps the
/// unserved rest in `m_getdata_requests`). satd queued blocks with a
/// `try_send` that dropped whatever did not fit, so a peer that read a
/// little late never got the rest of its request.
#[test]
fn a_large_getdata_is_served_in_full_as_the_peer_reads() {
    let mut node = TestNode::start(&[]);
    let port = node.p2p_port.unwrap();
    const N: u64 = 100;
    node.mine_blocks(N, ADDR);
    let hashes: Vec<BlockHash> = (1..=N)
        .map(|h| {
            let hex = node.rpc_ok("getblockhash", vec![serde_json::json!(h)]);
            let mut bytes = hex::decode(hex.as_str().unwrap()).unwrap();
            bytes.reverse();
            BlockHash::from_byte_array(bytes.try_into().unwrap())
        })
        .collect();
    // A full-size request, each block asked for many times over: about
    // 12 MB of blocks, more than loopback socket buffers take.
    let asked: Vec<BlockHash> = hashes.iter().copied().cycle().take(50_000).collect();

    let mut peer = Peer::connect(port);
    peer.send(NetworkMessage::GetData(asked.iter().map(|h| Inventory::WitnessBlock(*h)).collect()));
    // Read nothing for a while: the node fills the socket and its queue, and
    // must hold the rest of the request rather than drop it.
    std::thread::sleep(Duration::from_secs(3));
    let mut got = Vec::with_capacity(asked.len());
    while got.len() < asked.len() {
        match peer.recv_until(Duration::from_secs(60), |m| {
            matches!(m, NetworkMessage::Block(_) | NetworkMessage::NotFound(_))
        }) {
            NetworkMessage::Block(b) => got.push(b.block_hash()),
            other => panic!("after {} blocks: {other:?}", got.len()),
        }
    }
    assert!(got == asked, "every block, in the order asked");
    assert!(peer.alive());
    node.stop();
}
