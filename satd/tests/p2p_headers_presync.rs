//! Headers presync (#1132) against a live regtest node, over a raw peer
//! connection the test controls: a header chain is stored only once it has
//! shown the anti-DoS work threshold, as Core's `HeadersSyncState` and
//! `TryLowWorkHeadersSync` decide.

mod common;

use bitcoin::block::{Header, Version};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use bitcoin::{BlockHash, CompactTarget, Network, TxMerkleNode};
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
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(e) => panic!("connect to {addr}: {e}"),
            }
        };
        stream.set_nodelay(true).unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
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
        let _ = self
            .stream
            .write_all(&serialize(&RawNetworkMessage::new(Magic::REGTEST, msg)));
    }

    fn recv(&mut self, timeout: Duration) -> io::Result<NetworkMessage> {
        self.stream.set_read_timeout(Some(timeout)).unwrap();
        let mut header = [0u8; 24];
        self.stream.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut buf = header.to_vec();
        buf.resize(24 + len, 0);
        self.stream.read_exact(&mut buf[24..])?;
        let raw: RawNetworkMessage = deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(raw.into_payload())
    }

    /// Serve `chain` (built on genesis) to every `getheaders` the node sends,
    /// 2000 headers at a time from the first locator hash the chain holds, as
    /// Core's `ProcessGetHeaders` does, until `done` holds or `timeout`
    /// passes. Returns the number of `getheaders` answered.
    fn serve_headers(
        &mut self,
        chain: &[Header],
        timeout: Duration,
        mut done: impl FnMut() -> bool,
    ) -> usize {
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let deadline = Instant::now() + timeout;
        let mut answered = 0;
        while Instant::now() < deadline {
            if done() {
                return answered;
            }
            match self.recv(Duration::from_millis(200)) {
                Ok(NetworkMessage::GetHeaders(gh)) => {
                    let start = gh
                        .locator_hashes
                        .iter()
                        .find_map(|h| {
                            if *h == genesis {
                                return Some(0);
                            }
                            chain
                                .iter()
                                .position(|c| c.block_hash() == *h)
                                .map(|i| i + 1)
                        })
                        .unwrap_or(0);
                    let reply = chain[start..chain.len().min(start + 2000)].to_vec();
                    self.send(NetworkMessage::Headers(reply));
                    answered += 1;
                }
                Ok(NetworkMessage::Ping(n)) => self.send(NetworkMessage::Pong(n)),
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => panic!("the node closed the connection: {e}"),
            }
        }
        answered
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
        nonce: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
        user_agent: "/p2p-headers-presync-test/".into(),
        start_height: 0,
        relay: true,
    }
}

/// `n` regtest headers on `prev`, one second apart from `time`.
fn headers_on(prev: BlockHash, n: usize, time: u32, tag: u8) -> Vec<Header> {
    let mut parent = prev;
    (0..n)
        .map(|i| {
            let mut h = Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: parent,
                merkle_root: TxMerkleNode::from_byte_array([tag; 32]),
                time: time + i as u32,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            while h.validate_pow(h.target()).is_err() {
                h.nonce += 1;
            }
            parent = h.block_hash();
            h
        })
        .collect()
}

fn genesis_chain(n: usize, tag: u8) -> Vec<Header> {
    let genesis = bitcoin::constants::genesis_block(Network::Regtest);
    headers_on(genesis.block_hash(), n, genesis.header.time + 1, tag)
}

fn header_count(node: &TestNode) -> u64 {
    node.rpc_ok("getblockchaininfo", vec![])["headers"]
        .as_u64()
        .unwrap()
}

fn presynced(node: &TestNode) -> i64 {
    node.rpc_ok("getpeerinfo", vec![])[0]["presynced_headers"]
        .as_i64()
        .unwrap()
}

/// A peer serving a chain of 6,000 headers, whose work (about 12,000 on
/// regtest) never reaches `-minimumchainwork=0x10000`: the node runs a
/// presync with it, reports its height in `getpeerinfo`, and stores none of
/// the headers. Without presync every one of them is indexed.
#[test]
fn a_low_work_header_chain_is_not_stored() {
    let chain = genesis_chain(6000, 1);
    let node = TestNode::start(&["--minimumchainwork=0x10000"]);
    let mut peer = Peer::connect(node.p2p_port.unwrap());

    peer.serve_headers(&chain, Duration::from_secs(60), || presynced(&node) == 4000);
    assert_eq!(presynced(&node), 4000, "a presync is in progress");
    assert_eq!(
        header_count(&node),
        0,
        "no header was stored during presync"
    );

    // The rest of the chain, then the empty answer that ends it.
    peer.serve_headers(&chain, Duration::from_secs(60), || presynced(&node) == -1);
    assert_eq!(
        presynced(&node),
        -1,
        "the presync ended with the peer's chain"
    );
    assert_eq!(header_count(&node), 0);
    let tips = node.rpc_ok("getchaintips", vec![]);
    assert_eq!(tips.as_array().unwrap().len(), 1, "only genesis: {tips}");
}

/// A chain of 10,000 headers passes `-minimumchainwork=0x3000` (about
/// 6,100 regtest headers) in presync; the node downloads it again, checks
/// it against its commitments, and stores all of it.
#[test]
fn a_chain_with_enough_work_is_stored_after_its_redownload() {
    let chain = genesis_chain(10_000, 2);
    let node = TestNode::start(&["--minimumchainwork=0x3000"]);
    let mut peer = Peer::connect(node.p2p_port.unwrap());
    let answered = peer.serve_headers(&chain, Duration::from_secs(120), || {
        header_count(&node) == 10_000
    });
    assert_eq!(header_count(&node), 10_000, "the chain was not stored");
    // Five messages for each pass, and the empty answer to the last
    // getheaders at most.
    assert!(
        answered >= 10,
        "the chain was stored without a redownload ({answered} getheaders)"
    );
}

/// The threshold follows the tip: a fork that leaves the active chain less
/// than 144 blocks below the tip is stored even with less work, as Core's
/// `GetAntiDoSWorkThreshold` allows; one that leaves it deeper, with less
/// work, is ignored, and leaves no tip behind.
#[test]
fn a_fork_near_the_tip_is_stored_and_a_deep_low_work_one_is_not() {
    let mut node = TestNode::start(&[]);
    node.mine_blocks(300, ADDR);
    let block_at = |h: u64| -> (BlockHash, u32) {
        let hash: BlockHash = node
            .rpc_ok("getblockhash", vec![h.into()])
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let header = node.rpc_ok("getblockheader", vec![hash.to_string().into()]);
        (hash, header["time"].as_u64().unwrap() as u32)
    };
    let mut peer = Peer::connect(node.p2p_port.unwrap());

    // The deep fork first: headers are handled in the order they arrive,
    // so once the near fork shows up the deep one has been judged.
    let (deep, deep_time) = block_at(100);
    let deep_fork = headers_on(deep, 20, deep_time + 1, 4);
    peer.send(NetworkMessage::Headers(deep_fork.clone()));
    let (near, near_time) = block_at(250);
    let near_fork = headers_on(near, 20, near_time + 1, 3);
    peer.send(NetworkMessage::Headers(near_fork.clone()));
    // A ping after both: its pong comes once they are handled.
    peer.send(NetworkMessage::Ping(7));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match peer.recv(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
        ) {
            Ok(NetworkMessage::Pong(7)) => break,
            Ok(NetworkMessage::Ping(n)) => peer.send(NetworkMessage::Pong(n)),
            Ok(_) => {}
            Err(e) => panic!("no pong: {e}"),
        }
    }
    let has = |h: &Header| {
        node.rpc_call_with_params("getblockheader", vec![h.block_hash().to_string().into()])
            .unwrap()
            .get("error")
            .is_none_or(|e| e.is_null())
    };
    let wait = Instant::now() + Duration::from_secs(10);
    while !has(near_fork.last().unwrap()) && Instant::now() < wait {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        has(near_fork.last().unwrap()),
        "the fork near the tip was not stored"
    );
    assert!(!has(&deep_fork[0]), "the deep low-work fork was stored");
    let tips = node.rpc_ok("getchaintips", vec![]);
    assert_eq!(
        tips.as_array().unwrap().len(),
        2,
        "the active tip and the near fork: {tips}"
    );
}

/// #1122, Core's header-download timeout over P2P. Header sync runs with one
/// peer; a second peer is not asked while the first holds the slot, however
/// long it stays silent, until the sync peer's timeout (15 minutes plus 1 ms
/// per expected header) passes. The peers here are `noban`, so the silent
/// one only loses the slot, as in Core, and header sync starts again with
/// one of the two (Core may pick the noban peer again).
#[test]
fn a_silent_sync_peer_is_replaced_after_the_header_download_timeout() {
    let node = TestNode::start(&["--whitelist=noban@127.0.0.1"]);
    let port = node.p2p_port.unwrap();
    let mut silent = Peer::connect(port);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match silent.recv(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
        ) {
            Ok(NetworkMessage::GetHeaders(_)) => break,
            Ok(NetworkMessage::Ping(n)) => silent.send(NetworkMessage::Pong(n)),
            Ok(_) => {}
            Err(e) => panic!("the first peer was never asked for headers: {e}"),
        }
    }
    let mut other = Peer::connect(port);
    let asked = |peer: &mut Peer, within: Duration| {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            match peer.recv(Duration::from_millis(200)) {
                Ok(NetworkMessage::GetHeaders(_)) => return true,
                Ok(NetworkMessage::Ping(n)) => peer.send(NetworkMessage::Pong(n)),
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => panic!("the node closed the connection: {e}"),
            }
        }
        false
    };
    // Longer than the 10 s stall probe that used to ask another peer.
    assert!(
        !asked(&mut other, Duration::from_secs(15)),
        "the second peer was asked while the sync peer held the slot"
    );

    // Past the timeout: the regtest genesis is from 2011, so about 15 years
    // of ten-minute headers are expected, 1 ms each on top of 15 minutes.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    node.rpc_ok("setmocktime", vec![serde_json::json!(now + 3600)]);
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut restarted = false;
    while !restarted && Instant::now() < deadline {
        restarted = asked(&mut other, Duration::from_millis(500))
            || asked(&mut silent, Duration::from_millis(500));
    }
    assert!(
        restarted,
        "the header sync did not start again after the timeout"
    );
}
