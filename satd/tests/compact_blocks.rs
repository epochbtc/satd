//! BIP 152 compact block relay, exercised against a live regtest node over
//! raw P2P connections.
//!
//! The raw peer here reads everything the node sends onto a channel instead
//! of discarding it, so a test can assert on what the node *answers* — a
//! `getblocktxn`, a `getdata`, a `blocktxn`, a full `block` — and on what it
//! declines to send.

mod common;

use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn};
use bitcoin::{Block, BlockHash, Transaction};
use common::{DeterministicWallet, TestNode, poll_until, test_timeout};
use serde_json::json;
use std::time::Duration;

use p2p::RawPeer;

mod p2p {
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::{Address, Magic, ServiceFlags};
    use std::io::{self, Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const HEADER_SIZE: usize = 24;
    const MAX_PAYLOAD_SIZE: usize = 32 * 1024 * 1024;

    /// A raw P2P peer connected inbound to a regtest node. Everything the
    /// node sends lands on `inbox`; pings are answered so the link stays up.
    pub struct RawPeer {
        writer: Arc<Mutex<TcpStream>>,
        inbox: Receiver<NetworkMessage>,
        closed: Arc<std::sync::atomic::AtomicBool>,
        /// Everything the node sent before its `verack`.
        pub early: Vec<NetworkMessage>,
    }

    impl RawPeer {
        /// Connect and complete the version handshake.
        pub fn connect(p2p_port: u16) -> Self {
            let addr: SocketAddr = format!("127.0.0.1:{p2p_port}").parse().unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            let stream = loop {
                match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                    Ok(s) => break s,
                    Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(100))
                    }
                    Err(e) => panic!("P2P connect to {addr} failed: {e}"),
                }
            };
            Self::handshake(stream)
        }

        /// Accept the connection a node dials to `listener` (e.g. after
        /// `addconnection`) and complete the handshake: an outbound peer of
        /// the node.
        pub fn accept(listener: &std::net::TcpListener) -> Self {
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
            Self::handshake(stream)
        }

        fn handshake(stream: TcpStream) -> Self {
            stream.set_nodelay(true).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut reader = stream.try_clone().unwrap();
            let writer = Arc::new(Mutex::new(stream));
            let (tx, inbox) = channel();
            let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));

            let peer = RawPeer { writer: writer.clone(), inbox, closed: closed.clone(), early: Vec::new() };
            peer.send(NetworkMessage::Version(our_version()));

            std::thread::spawn(move || {
                loop {
                    match recv_msg(&mut reader) {
                        Ok(NetworkMessage::Ping(n)) => {
                            let raw = RawNetworkMessage::new(Magic::REGTEST, NetworkMessage::Pong(n));
                            let _ = writer.lock().unwrap().write_all(&serialize(&raw));
                        }
                        Ok(NetworkMessage::Version(_)) => {
                            let raw = RawNetworkMessage::new(Magic::REGTEST, NetworkMessage::Verack);
                            let _ = writer.lock().unwrap().write_all(&serialize(&raw));
                        }
                        Ok(msg) => {
                            if tx.send(msg).is_err() {
                                break;
                            }
                        }
                        Err(_) => {
                            closed.store(true, std::sync::atomic::Ordering::SeqCst);
                            break;
                        }
                    }
                }
            });

            let mut peer = peer;
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match peer.inbox.recv_timeout(left) {
                    Ok(NetworkMessage::Verack) => break,
                    Ok(m) => peer.early.push(m),
                    Err(_) => panic!("handshake: no verack from the node"),
                }
            }
            // Speak BIP 152 version 2, low-bandwidth, as a Core peer does.
            peer.send(NetworkMessage::SendCmpct(
                bitcoin::p2p::message_compact_blocks::SendCmpct { send_compact: false, version: 2 },
            ));
            peer
        }

        pub fn send(&self, msg: NetworkMessage) {
            let raw = RawNetworkMessage::new(Magic::REGTEST, msg);
            let _ = self.writer.lock().unwrap().write_all(&serialize(&raw));
        }

        /// The first message matching `pred` within `timeout`; everything
        /// before it is discarded.
        pub fn recv_until(
            &mut self,
            pred: impl Fn(&NetworkMessage) -> bool,
            timeout: Duration,
        ) -> Option<NetworkMessage> {
            let deadline = Instant::now() + timeout;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match self.inbox.recv_timeout(left) {
                    Ok(m) if pred(&m) => return Some(m),
                    Ok(_) => continue,
                    Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {
                        return None;
                    }
                }
            }
        }

        /// Every message that arrives within `window`.
        pub fn collect_for(&mut self, window: Duration) -> Vec<NetworkMessage> {
            let deadline = Instant::now() + window;
            let mut out = Vec::new();
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match self.inbox.recv_timeout(left) {
                    Ok(m) => out.push(m),
                    Err(_) => return out,
                }
            }
        }

        /// Whether the node has closed the connection.
        pub fn is_closed(&self) -> bool {
            self.closed.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Wait up to `timeout` for the node to close the connection.
        pub fn wait_closed(&mut self, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if self.is_closed() {
                    return true;
                }
                let _ = self.collect_for(Duration::from_millis(50));
            }
            self.is_closed()
        }
    }

    fn our_version() -> VersionMessage {
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
        VersionMessage {
            version: 70016,
            services,
            // satd keeps no per-peer clock offset; any plausible time will do.
            timestamp: 1_760_000_000,
            receiver: Address::new(&zero, ServiceFlags::NONE),
            sender: Address::new(&zero, services),
            nonce: rand_nonce(),
            user_agent: "/satd-compact-test:0.1/".into(),
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

    fn recv_msg(stream: &mut TcpStream) -> io::Result<NetworkMessage> {
        let mut header = [0u8; HEADER_SIZE];
        stream.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        if len > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "payload too large"));
        }
        let mut buf = Vec::with_capacity(HEADER_SIZE + len);
        buf.extend_from_slice(&header);
        buf.resize(HEADER_SIZE + len, 0);
        stream.read_exact(&mut buf[HEADER_SIZE..])?;
        deserialize::<RawNetworkMessage>(&buf)
            .map(|raw| raw.payload().clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Chain helpers
// ---------------------------------------------------------------------------

fn best_hash(node: &TestNode) -> BlockHash {
    node.rpc_ok("getbestblockhash", vec![]).as_str().unwrap().parse().unwrap()
}

fn height(node: &TestNode) -> u32 {
    node.rpc_ok("getblockcount", vec![]).as_u64().unwrap() as u32
}

fn block_at(node: &TestNode, hash: &BlockHash) -> Block {
    let hex = node.rpc_ok("getblock", vec![json!(hash.to_string()), json!(0)]);
    deserialize(&hex::decode(hex.as_str().unwrap()).unwrap()).unwrap()
}

fn peer_count(node: &TestNode) -> usize {
    node.rpc_ok("getpeerinfo", vec![]).as_array().unwrap().len()
}

fn banned_count(node: &TestNode) -> usize {
    node.rpc_ok("listbanned", vec![]).as_array().unwrap().len()
}

/// A regtest block on `prev`. With `valid_pow`, the header is ground under
/// the regtest target; without, it is ground to *miss* it. A witness
/// commitment is added whenever a transaction carries a witness.
fn build_block(prev: &Block, height: u32, extra: Vec<Transaction>, valid_pow: bool, salt: u32) -> Block {
    let subsidy = (50u64 * 100_000_000) >> (height / 150).min(63);
    let has_witness = extra.iter().any(|tx| tx.input.iter().any(|i| !i.witness.is_empty()));
    let script_sig = bitcoin::script::Builder::new()
        .push_int(height as i64)
        .push_int(salt as i64)
        .push_opcode(bitcoin::opcodes::OP_FALSE)
        .into_script();
    let mut coinbase = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig,
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(subsidy),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    if has_witness {
        coinbase.input[0].witness = bitcoin::Witness::from_slice(&[[0u8; 32]]);
    }
    let mut txdata = vec![coinbase];
    txdata.extend(extra);
    let mut block = Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: prev.block_hash(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: prev.header.time + 1,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    if has_witness {
        let root = block.witness_root().expect("witness root");
        let commitment = Block::compute_witness_commitment(&root, &[0u8; 32]);
        let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        script.extend_from_slice(commitment.as_byte_array());
        block.txdata[0].output.push(bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(script),
        });
    }
    block.header.merkle_root = block.compute_merkle_root().expect("non-empty block");
    let target = block.header.target();
    loop {
        let ok = block.header.validate_pow(target).is_ok();
        if ok == valid_pow {
            return block;
        }
        block.header.nonce += 1;
    }
}

/// A random-looking transaction nobody has: one input from a made-up
/// outpoint, one output.
fn unknown_tx(seed: u32) -> Transaction {
    let mut txid = [0u8; 32];
    txid[..4].copy_from_slice(&seed.to_le_bytes());
    txid[4] = 0xc3;
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array(txid),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1_000 + u64::from(seed)),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    }
}

fn cmpct(compact: HeaderAndShortIds) -> NetworkMessage {
    NetworkMessage::CmpctBlock(CmpctBlock { compact_block: compact })
}

fn is_getblocktxn_for(hash: BlockHash) -> impl Fn(&NetworkMessage) -> bool {
    move |m| matches!(m, NetworkMessage::GetBlockTxn(g) if g.txs_request.block_hash == hash)
}

fn is_getdata_for(hash: BlockHash) -> impl Fn(&NetworkMessage) -> bool {
    move |m| {
        matches!(m, NetworkMessage::GetData(inv)
            if inv.iter().any(|i| matches!(i, Inventory::WitnessBlock(h) | Inventory::Block(h) if *h == hash)))
    }
}

/// A node with `blocks` blocks mined, so it is past IBD.
fn started_node(blocks: u64) -> (TestNode, DeterministicWallet) {
    let node = TestNode::start(&[]);
    let wallet = DeterministicWallet::from_secret([0x5c; 32]);
    node.rpc_ok(
        "generatetoaddress",
        vec![json!(blocks), json!(wallet.address.to_string())],
    );
    (node, wallet)
}

/// Have `peer` deliver a fresh block that becomes the node's tip, which is
/// what earns a peer high-bandwidth compact relay: afterwards the node has
/// sent it `sendcmpct(1)` and accepts `cmpctblock`s it pushes.
fn promote(node: &TestNode, peer: &mut RawPeer) {
    static SALT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(50_000);
    let salt = SALT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tip = block_at(node, &best_hash(node));
    let b = build_block(&tip, height(node) + 1, vec![], true, salt);
    peer.send(NetworkMessage::Headers(vec![b.header]));
    peer.send(NetworkMessage::Block(b));
    let got = peer.recv_until(
        |m| matches!(m, NetworkMessage::SendCmpct(s) if s.send_compact),
        test_timeout(20),
    );
    assert!(got.is_some(), "a peer that delivers the tip must be promoted to high-bandwidth");
}

// ---------------------------------------------------------------------------
// Receive-side hardening
// ---------------------------------------------------------------------------

/// A `cmpctblock` whose header does not meet the proof-of-work target must be
/// dropped before any reconstruction: no `getblocktxn`, no pending state, and
/// no penalty (compact blocks are pushed, not requested). The node used to
/// reconstruct every one — reading the whole mempool, requesting every
/// missing transaction and parking the partial block forever.
#[test]
fn cmpctblock_with_bad_pow_is_ignored_without_state_or_ban() {
    let (node, _) = started_node(1);
    let port = node.p2p_port.unwrap();
    let mut peer = RawPeer::connect(port);
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");

    let tip = block_at(&node, &best_hash(&node));
    for i in 0..200u32 {
        let bad = build_block(&tip, 2, vec![], false, i);
        let mut compact = HeaderAndShortIds::from_block(&bad, u64::from(i), 2, &[]).unwrap();
        compact.short_ids = (0..1_000u32)
            .map(|j| {
                let b = (i * 7919 + j).to_le_bytes();
                ShortId::from([b[0], b[1], b[2], b[3], 0x5a, 0xa5])
            })
            .collect();
        peer.send(cmpct(compact));
    }

    let answered = peer.recv_until(|m| matches!(m, NetworkMessage::GetBlockTxn(_)), Duration::from_secs(3));
    assert!(answered.is_none(), "a bad-PoW compact block must not be reconstructed: {answered:?}");
    assert!(!peer.is_closed(), "an invalid pushed header is not misbehaviour");
    assert_eq!(peer_count(&node), 1);
    assert_eq!(banned_count(&node), 0);

    // The same peer still delivers a good block.
    let good = build_block(&tip, 2, vec![], true, 9_999);
    peer.send(NetworkMessage::Headers(vec![good.header]));
    peer.send(NetworkMessage::Block(good.clone()));
    poll_until(
        || best_hash(&node) == good.block_hash(),
        test_timeout(20),
        "a valid block from the same peer must connect",
    );
}

/// A fully reconstructed compact block that fails its merkle check may be an
/// honest block whose short ID collided with a mempool transaction. Core
/// fetches the full block from the same peer and does not penalise it; satd
/// used to ban the relayer at 100 points.
#[test]
fn cmpctblock_that_fails_merkle_check_is_refetched_in_full_without_ban() {
    let (node, wallet) = started_node(101);
    let dest = DeterministicWallet::from_secret([0x5d; 32]);

    // T: in the node's mempool. T': a different spend of the same coinbase,
    // which the node has never seen, mined into block B.
    let (t_hex, _) = common::build_signed_p2wpkh_spend_from_block1_coinbase(
        &node, &wallet, dest.address.script_pubkey(), 1_000,
    );
    let (t2_hex, _) = common::build_signed_p2wpkh_spend_from_block1_coinbase(
        &node, &wallet, dest.address.script_pubkey(), 2_000,
    );
    let t: Transaction = deserialize(&hex::decode(&t_hex).unwrap()).unwrap();
    let t2: Transaction = deserialize(&hex::decode(&t2_hex).unwrap()).unwrap();
    node.rpc_ok("sendrawtransaction", vec![json!(t_hex)]);

    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    promote(&node, &mut peer);

    let tip = block_at(&node, &best_hash(&node));
    let b = build_block(&tip, height(&node) + 1, vec![t2.clone()], true, 1);
    let hash = b.block_hash();
    let mut compact = HeaderAndShortIds::from_block(&b, 0x1234, 2, &[]).unwrap();
    // Simulate a collision: announce T' under T's short ID, so the node fills
    // the slot with T and the merkle root no longer matches.
    let keys = ShortId::calculate_siphash_keys(&compact.header, compact.nonce);
    compact.short_ids[0] = ShortId::with_siphash_keys(&t.compute_wtxid().to_raw_hash(), keys);
    peer.send(cmpct(compact));

    let got = peer.recv_until(is_getdata_for(hash), Duration::from_secs(15));
    assert!(got.is_some(), "the node must fall back to fetching the full block");
    assert!(!peer.is_closed(), "the relayer must not be disconnected");
    assert_eq!(banned_count(&node), 0, "the relayer must not be banned");

    peer.send(NetworkMessage::Block(b));
    poll_until(|| best_hash(&node) == hash, test_timeout(20), "the full block must connect");
}

/// Build a block of `n` transactions the node has never seen on the current
/// tip, and its compact form (coinbase prefilled only).
fn partial_block(node: &TestNode, n: u32, salt: u32) -> (Block, HeaderAndShortIds) {
    let tip = block_at(node, &best_hash(node));
    let txs = (0..n).map(|i| unknown_tx(salt * 1000 + i)).collect();
    // Unknown inputs never validate, which is fine: these tests stop at
    // reconstruction and never need the block to connect.
    let b = build_block(&tip, height(node) + 1, txs, true, salt);
    let compact = HeaderAndShortIds::from_block(&b, u64::from(salt), 2, &[]).unwrap();
    (b, compact)
}

/// A `cmpctblock` whose parent is known only as a header is not
/// reconstructed: satd connects a block as it arrives, and this one would
/// start a reorg that cannot finish. A fresh node following a peer that
/// mines quickly sees exactly this. The chain is fetched in order instead,
/// and the block still connects.
#[test]
fn cmpctblock_on_a_header_only_parent_is_fetched_in_order() {
    let (node, _) = started_node(1);
    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    // Only a high-bandwidth peer's push reaches reconstruction at all.
    promote(&node, &mut peer);

    let tip = block_at(&node, &best_hash(&node));
    let h = height(&node);
    let b2 = build_block(&tip, h + 1, vec![], true, 21);
    let b3 = build_block(&b2, h + 2, vec![unknown_tx(3_000)], true, 22);
    peer.send(NetworkMessage::Headers(vec![b2.header]));
    std::thread::sleep(Duration::from_millis(500));
    let compact = HeaderAndShortIds::from_block(&b3, 7, 2, &[]).unwrap();
    peer.send(cmpct(compact));

    let asked = peer.recv_until(is_getblocktxn_for(b3.block_hash()), Duration::from_secs(5));
    assert!(asked.is_none(), "a block on a header-only parent must not be reconstructed: {asked:?}");
    assert_eq!(banned_count(&node), 0);

    peer.send(NetworkMessage::Block(b2.clone()));
    poll_until(|| best_hash(&node) == b2.block_hash(), test_timeout(20), "the parent must connect");
    assert!(!peer.is_closed());
}

/// A `blocktxn` completes only the reconstruction the *sending* peer has
/// open. Core ignores one "for block we weren't expecting"; satd used to
/// complete any peer's pending block with any peer's reply.
#[test]
fn blocktxn_for_an_unrequested_block_is_ignored() {
    let (node, wallet) = started_node(101);
    // A block that will connect: one spend the node has never seen.
    let dest = DeterministicWallet::from_secret([0x5e; 32]);
    let (tx_hex, _) = common::build_signed_p2wpkh_spend_from_block1_coinbase(
        &node, &wallet, dest.address.script_pubkey(), 1_000,
    );
    let tx: Transaction = deserialize(&hex::decode(&tx_hex).unwrap()).unwrap();

    let mut x = RawPeer::connect(node.p2p_port.unwrap());
    let mut y = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 2, test_timeout(20), "peers must connect");
    promote(&node, &mut x);

    let tip = block_at(&node, &best_hash(&node));
    let b = build_block(&tip, height(&node) + 1, vec![tx.clone()], true, 3);
    let hash = b.block_hash();
    let compact = HeaderAndShortIds::from_block(&b, 77, 2, &[]).unwrap();

    x.send(cmpct(compact));
    let req = x.recv_until(is_getblocktxn_for(hash), Duration::from_secs(15));
    assert!(req.is_some(), "the node must ask X for the missing transaction");

    let reply = || NetworkMessage::BlockTxn(BlockTxn {
        transactions: BlockTransactions { block_hash: hash, transactions: vec![tx.clone()] },
    });
    // Y never received a getblocktxn for this block.
    y.send(reply());
    std::thread::sleep(Duration::from_secs(3));
    assert_ne!(best_hash(&node), hash, "Y's unrequested blocktxn must not complete X's block");
    assert!(!y.is_closed(), "an unexpected blocktxn is ignored, not punished");

    x.send(reply());
    poll_until(|| best_hash(&node) == hash, test_timeout(20), "X's own reply completes the block");
    let _ = y.collect_for(Duration::from_millis(10));
}

/// A `blocktxn` that does not answer the request — one transaction short —
/// is Core's `READ_STATUS_INVALID`: misbehaviour. satd used to log it and
/// leave the block stranded.
#[test]
fn blocktxn_with_wrong_count_is_penalised() {
    let (node, _) = started_node(1);
    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    promote(&node, &mut peer);

    let (b, compact) = partial_block(&node, 2, 4);
    let hash = b.block_hash();
    peer.send(cmpct(compact));
    let req = peer.recv_until(is_getblocktxn_for(hash), Duration::from_secs(15));
    assert!(req.is_some(), "the node must request the two missing transactions");

    peer.send(NetworkMessage::BlockTxn(BlockTxn {
        transactions: BlockTransactions { block_hash: hash, transactions: vec![b.txdata[1].clone()] },
    }));
    assert!(peer.wait_closed(Duration::from_secs(15)), "a mismatched blocktxn must disconnect the peer");
    poll_until(|| banned_count(&node) == 1, test_timeout(10), "and ban it");
}

fn getblocktxn(hash: BlockHash, indexes: Vec<u64>) -> NetworkMessage {
    NetworkMessage::GetBlockTxn(GetBlockTxn {
        txs_request: BlockTransactionsRequest { block_hash: hash, indexes },
    })
}

/// Core serves `blocktxn` only for the last `MAX_BLOCKTXN_DEPTH` (10) blocks;
/// anything deeper gets the full block, so a peer cannot turn small requests
/// into disk reads for a few bytes of reply.
#[test]
fn getblocktxn_beyond_depth_ten_gets_a_full_block() {
    let (node, _) = started_node(30);
    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");

    let hash_at = |h: u32| -> BlockHash {
        node.rpc_ok("getblockhash", vec![json!(h)]).as_str().unwrap().parse().unwrap()
    };

    // Depth 10 (height 20 under a tip of 30): still a blocktxn.
    let shallow = hash_at(20);
    peer.send(getblocktxn(shallow, vec![0]));
    let got = peer.recv_until(
        |m| matches!(m, NetworkMessage::BlockTxn(_) | NetworkMessage::Block(_)),
        Duration::from_secs(15),
    );
    assert!(
        matches!(&got, Some(NetworkMessage::BlockTxn(t)) if t.transactions.block_hash == shallow),
        "a block 10 deep is served as blocktxn: {got:?}"
    );

    // Depth 15: the full block.
    let deep = hash_at(15);
    peer.send(getblocktxn(deep, vec![0]));
    let got = peer.recv_until(
        |m| matches!(m, NetworkMessage::BlockTxn(_) | NetworkMessage::Block(_)),
        Duration::from_secs(15),
    );
    assert!(
        matches!(&got, Some(NetworkMessage::Block(b)) if b.block_hash() == deep),
        "a block 15 deep is served in full: {got:?}"
    );
}

/// An index past the end of the block is misbehaviour (Core:
/// "getblocktxn with out-of-bounds tx indices").
#[test]
fn getblocktxn_out_of_range_index_is_penalised() {
    let (node, _) = started_node(3);
    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    // Every regtest block mined by `generatetoaddress` on an empty mempool
    // holds only its coinbase.
    peer.send(getblocktxn(best_hash(&node), vec![5]));
    assert!(peer.wait_closed(Duration::from_secs(15)), "an out-of-range getblocktxn must disconnect");
    poll_until(|| banned_count(&node) == 1, test_timeout(10), "and ban the peer");
}

/// Core allows at most three peers to hold a partial reconstruction of the
/// same block (`MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK`). A fourth peer's
/// `cmpctblock` for it is not reconstructed.
#[test]
fn a_second_compact_peer_for_the_same_hash_is_capped_at_three() {
    let (node, _) = started_node(1);
    let port = node.p2p_port.unwrap();
    let mut peers: Vec<RawPeer> = (0..4).map(|_| RawPeer::connect(port)).collect();
    poll_until(|| peer_count(&node) == 4, test_timeout(20), "peers must connect");

    let (b, compact) = partial_block(&node, 3, 5);
    let hash = b.block_hash();
    // Only three peers can be high-bandwidth, so the four take the other road
    // past the unsolicited-push gate: the node asks each of them for the
    // block after the header is announced.
    peers[0].send(NetworkMessage::Headers(vec![b.header]));
    for (i, p) in peers.iter_mut().enumerate() {
        assert!(
            p.recv_until(is_getdata_for(hash), test_timeout(20)).is_some(),
            "the node must request the block from peer {i}"
        );
    }
    for p in &peers {
        p.send(cmpct(compact.clone()));
        // Keep the arrival order deterministic.
        std::thread::sleep(Duration::from_millis(200));
    }
    let asked = peers
        .iter_mut()
        .map(|p| p.recv_until(is_getblocktxn_for(hash), Duration::from_secs(5)).is_some())
        .filter(|asked| *asked)
        .count();
    assert_eq!(asked, 3, "exactly three peers may reconstruct one block at once");
}

// ---------------------------------------------------------------------------
// Reconstruction statistics and the extra-transaction cache
// ---------------------------------------------------------------------------

fn metrics_body(port: u16) -> String {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{port}/metrics");
    let deadline = std::time::Instant::now() + test_timeout(20);
    loop {
        if let Ok(r) = client.get(&url).send()
            && let Ok(body) = r.text()
        {
            return body;
        }
        assert!(std::time::Instant::now() < deadline, "metrics endpoint never answered");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The value of one sample, e.g. `metric(&body, "satd_x_total{a=\"b\"}")`.
fn metric(body: &str, series: &str) -> Option<u64> {
    body.lines()
        .find_map(|l| l.strip_prefix(series).and_then(|rest| rest.trim().parse().ok()))
}

/// A node with a metrics port and `blocks` mined.
fn node_with_metrics(blocks: u64, extra_args: &[&str]) -> (TestNode, DeterministicWallet, u16) {
    let metrics_port = common::find_available_port();
    let mut args = vec![format!("--metricsport={metrics_port}")];
    args.extend(extra_args.iter().map(|a| a.to_string()));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let node = TestNode::start(&args);
    let wallet = DeterministicWallet::from_secret([0x5c; 32]);
    node.rpc_ok("generatetoaddress", vec![json!(blocks), json!(wallet.address.to_string())]);
    (node, wallet, metrics_port)
}

/// Send `block` as a coinbase-only `cmpctblock` and report whether the node
/// had to ask for anything before the block connected.
fn relay_compact(node: &TestNode, peer: &mut RawPeer, block: &Block) -> bool {
    let hash = block.block_hash();
    peer.send(cmpct(HeaderAndShortIds::from_block(block, 0xfeed, 2, &[]).unwrap()));
    let mut asked = false;
    let deadline = std::time::Instant::now() + test_timeout(20);
    while best_hash(node) != hash {
        assert!(std::time::Instant::now() < deadline, "block {hash} never connected");
        for m in peer.collect_for(Duration::from_millis(200)) {
            if let NetworkMessage::GetBlockTxn(g) = m
                && g.txs_request.block_hash == hash
            {
                asked = true;
                let txs = g
                    .txs_request
                    .indexes
                    .iter()
                    .map(|i| block.txdata[*i as usize].clone())
                    .collect();
                peer.send(NetworkMessage::BlockTxn(BlockTxn {
                    transactions: BlockTransactions { block_hash: hash, transactions: txs },
                }));
            }
        }
    }
    asked
}

/// A transaction an RBF replacement pushed out of the mempool is kept, so a
/// block from a miner who never saw the replacement still reconstructs
/// without a round trip — and with the cache sized to zero, it does not.
#[test]
fn compact_block_reconstructs_from_the_extra_pool_after_rbf() {
    for (extra_args, expect_round_trip) in [(&[][..], false), (&["--blockreconstructionextratxn=0"][..], true)] {
        let (node, wallet, metrics_port) = node_with_metrics(101, extra_args);
        let dest = DeterministicWallet::from_secret([0x60; 32]);
        let (t1_hex, _) = common::build_signed_p2wpkh_spend_seq(
            &node, &wallet, dest.address.script_pubkey(), 1_000, 0xffff_fffd,
        );
        let (t2_hex, _) = common::build_signed_p2wpkh_spend_seq(
            &node, &wallet, dest.address.script_pubkey(), 5_000, 0xffff_fffd,
        );
        node.rpc_ok("sendrawtransaction", vec![json!(t1_hex)]);
        node.rpc_ok("sendrawtransaction", vec![json!(t2_hex)]);
        let t1: Transaction = deserialize(&hex::decode(&t1_hex).unwrap()).unwrap();

        let mut peer = RawPeer::connect(node.p2p_port.unwrap());
        poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
        promote(&node, &mut peer);
        let tip = block_at(&node, &best_hash(&node));
        let b = build_block(&tip, height(&node) + 1, vec![t1], true, 6);

        let asked = relay_compact(&node, &mut peer, &b);
        assert_eq!(asked, expect_round_trip, "extra args {extra_args:?}");

        let body = metrics_body(metrics_port);
        let extra = metric(&body, "satd_net_compact_block_txs_total{source=\"extra\"}");
        let direct = metric(&body, "satd_net_compact_block_reconstructions_total{outcome=\"direct\"}");
        let round_trip = metric(&body, "satd_net_compact_block_reconstructions_total{outcome=\"round_trip\"}");
        if expect_round_trip {
            assert_eq!((extra, direct, round_trip), (Some(0), Some(0), Some(1)), "{extra_args:?}");
            assert_eq!(
                metric(&body, "satd_net_compact_block_txs_total{source=\"requested\"}"),
                Some(1)
            );
            assert!(metric(&body, "satd_net_compact_block_fetched_bytes_total").unwrap() > 0);
        } else {
            assert_eq!((extra, direct, round_trip), (Some(1), Some(1), Some(0)), "{extra_args:?}");
        }
    }
}

/// A relayed transaction the mempool refuses on policy — here, no fee — is
/// kept for reconstruction too (Core's first-time-reject insertion).
#[test]
fn a_policy_refused_relayed_tx_is_kept_for_reconstruction() {
    let (node, wallet, metrics_port) = node_with_metrics(101, &[]);
    let dest = DeterministicWallet::from_secret([0x61; 32]);
    let (free_hex, free_txid) = common::build_signed_p2wpkh_spend_from_block1_coinbase(
        &node, &wallet, dest.address.script_pubkey(), 0,
    );
    let free: Transaction = deserialize(&hex::decode(&free_hex).unwrap()).unwrap();

    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    peer.send(NetworkMessage::Tx(free.clone()));
    std::thread::sleep(Duration::from_secs(2));
    let in_pool = node.rpc_ok("getrawmempool", vec![]);
    assert!(
        !in_pool.as_array().unwrap().iter().any(|t| t == &json!(free_txid)),
        "the zero-fee transaction must be refused"
    );
    assert!(!peer.is_closed(), "a policy refusal is not misbehaviour");

    promote(&node, &mut peer);
    let tip = block_at(&node, &best_hash(&node));
    let b = build_block(&tip, height(&node) + 1, vec![free], true, 7);
    assert!(!relay_compact(&node, &mut peer, &b), "the refused tx must fill its slot");
    let body = metrics_body(metrics_port);
    assert_eq!(metric(&body, "satd_net_compact_block_txs_total{source=\"extra\"}"), Some(1));
}

/// `getpeerinfo` reports the peer's high-bandwidth request. It was hardcoded
/// `false`.
#[test]
fn getpeerinfo_reports_bip152_high_bandwidth_state() {
    use bitcoin::p2p::message_compact_blocks::SendCmpct;
    let (node, _) = started_node(1);
    let peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    let hb_from = || node.rpc_ok("getpeerinfo", vec![])[0]["bip152_hb_from"].clone();
    assert_eq!(hb_from(), json!(false));
    peer.send(NetworkMessage::SendCmpct(SendCmpct { send_compact: true, version: 2 }));
    poll_until(|| hb_from() == json!(true), test_timeout(20), "bip152_hb_from must turn true");
    peer.send(NetworkMessage::SendCmpct(SendCmpct { send_compact: false, version: 2 }));
    poll_until(|| hb_from() == json!(false), test_timeout(20), "and back to false");
}

// ---------------------------------------------------------------------------
// High-bandwidth peer selection
// ---------------------------------------------------------------------------

fn sendcmpct_hb(m: &NetworkMessage) -> Option<bool> {
    match m {
        NetworkMessage::SendCmpct(s) if s.version == 2 => Some(s.send_compact),
        _ => None,
    }
}

/// `bip152_hb_to` for each peer, in `getpeerinfo` order keyed by the peer's
/// local port (the raw peers' only distinguishing feature).
fn hb_to_by_port(node: &TestNode) -> std::collections::HashMap<u16, bool> {
    node.rpc_ok("getpeerinfo", vec![])
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let addr: std::net::SocketAddr = p["addr"].as_str().unwrap().parse().unwrap();
            (addr.port(), p["bip152_hb_to"].as_bool().unwrap())
        })
        .collect()
}

/// Core sends `sendcmpct(0, 2)` when a connection comes up and selects
/// high-bandwidth peers later; satd used to ask every peer for
/// high-bandwidth announcements.
#[test]
fn sendcmpct_is_low_bandwidth_at_handshake() {
    let (node, _) = started_node(1);
    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    let first = peer
        .early
        .iter()
        .find_map(sendcmpct_hb)
        .or_else(|| {
            peer.recv_until(|m| sendcmpct_hb(m).is_some(), test_timeout(20))
                .and_then(|m| sendcmpct_hb(&m))
        });
    assert_eq!(first, Some(false), "the first sendcmpct must be low-bandwidth version 2");
    assert_eq!(node.rpc_ok("getpeerinfo", vec![])[0]["bip152_hb_to"], json!(false));
}

/// A peer that delivers a block that becomes the tip is asked for
/// high-bandwidth announcements: `p2p_compactblocks_hb.py`'s assertion.
#[test]
fn a_peer_that_delivers_our_tip_is_promoted_to_high_bandwidth() {
    let (node, _) = started_node(1);
    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    // Delivered by hand rather than through `promote`, which discards what
    // arrives before the `sendcmpct` -- where an echo would be.
    let tip = block_at(&node, &best_hash(&node));
    let b = build_block(&tip, height(&node) + 1, vec![], true, 4_242);
    let delivered = b.block_hash();
    peer.send(NetworkMessage::Headers(vec![b.header]));
    peer.send(NetworkMessage::Block(b));
    poll_until(
        || node.rpc_ok("getpeerinfo", vec![])[0]["bip152_hb_to"] == json!(true),
        test_timeout(20),
        "getpeerinfo must report the selection",
    );
    let seen = peer.collect_for(Duration::from_secs(2));
    assert!(
        seen.iter().any(|m| sendcmpct_hb(m) == Some(true)),
        "a peer that delivers the tip must be promoted to high-bandwidth: {seen:?}"
    );
    // The block the peer delivered is not announced back to it.
    let echoed = seen.into_iter().find(|m| match m {
        NetworkMessage::Inv(inv) => inv.iter().any(|i| matches!(i, Inventory::Block(h) if *h == delivered)),
        NetworkMessage::Headers(hs) => hs.iter().any(|h| h.block_hash() == delivered),
        NetworkMessage::CmpctBlock(c) => c.compact_block.header.block_hash() == delivered,
        _ => false,
    });
    assert!(echoed.is_none(), "the node announced a block back to its source: {echoed:?}");
}

/// BIP 152: at most three high-bandwidth peers. A fourth promotion demotes
/// the least recently useful one with `sendcmpct(0)`.
#[test]
fn at_most_three_peers_are_high_bandwidth_and_the_oldest_is_demoted() {
    let (node, _) = started_node(1);
    let port = node.p2p_port.unwrap();
    let mut peers: Vec<RawPeer> = (0..4).map(|_| RawPeer::connect(port)).collect();
    poll_until(|| peer_count(&node) == 4, test_timeout(20), "peers must connect");
    for p in peers.iter_mut() {
        promote(&node, p);
    }
    let demoted = peers[0].recv_until(|m| sendcmpct_hb(m) == Some(false), test_timeout(20));
    assert!(demoted.is_some(), "the first peer must be demoted when the fourth is promoted");
    for (i, p) in peers.iter_mut().enumerate().skip(1) {
        assert!(
            p.recv_until(|m| sendcmpct_hb(m) == Some(false), Duration::from_millis(500)).is_none(),
            "peer {i} must stay high-bandwidth"
        );
    }
    poll_until(
        || hb_to_by_port(&node).values().filter(|hb| **hb).count() == 3,
        test_timeout(20),
        "exactly three peers are high-bandwidth",
    );
}

/// Core keeps at least one outbound peer among the high-bandwidth three: an
/// inbound promotion demotes an inbound peer instead of the last outbound.
#[test]
fn an_inbound_promotion_never_evicts_the_last_outbound_hb_peer() {
    let (node, _) = started_node(1);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let out = node
        .rpc_call_with_params(
            "addconnection",
            vec![json!(listener.local_addr().unwrap().to_string()), json!("outbound-full-relay"), json!(false)],
        )
        .unwrap();
    assert!(out["error"].is_null(), "addconnection: {out}");
    let mut outbound = RawPeer::accept(&listener);
    let port = node.p2p_port.unwrap();
    let mut inbound: Vec<RawPeer> = (0..3).map(|_| RawPeer::connect(port)).collect();
    poll_until(|| peer_count(&node) == 4, test_timeout(20), "peers must connect");

    // Selection order: outbound, inbound 0, inbound 1 — the outbound peer is
    // the oldest and would be the one to go.
    promote(&node, &mut outbound);
    promote(&node, &mut inbound[0]);
    promote(&node, &mut inbound[1]);
    promote(&node, &mut inbound[2]);

    let demoted = inbound[0].recv_until(|m| sendcmpct_hb(m) == Some(false), test_timeout(20));
    assert!(demoted.is_some(), "the oldest inbound peer is demoted");
    assert!(
        outbound.recv_until(|m| sendcmpct_hb(m) == Some(false), Duration::from_secs(1)).is_none(),
        "the only outbound high-bandwidth peer must not be demoted"
    );
    let info = node.rpc_ok("getpeerinfo", vec![]);
    let out_peer = info.as_array().unwrap().iter().find(|p| p["inbound"] == json!(false)).unwrap();
    assert_eq!(out_peer["bip152_hb_to"], json!(true));
}

// ---------------------------------------------------------------------------
// Sending: announcements and MSG_CMPCT_BLOCK
// ---------------------------------------------------------------------------

/// The `cmpctblock` BIP 152 specifies for `block` under `nonce`: header,
/// coinbase prefilled, a siphash short ID for every other transaction.
fn expected_compact(block: &Block, nonce: u64) -> HeaderAndShortIds {
    HeaderAndShortIds::from_block(block, nonce, 2, &[]).unwrap()
}

fn is_cmpctblock_for(hash: BlockHash) -> impl Fn(&NetworkMessage) -> bool {
    move |m| matches!(m, NetworkMessage::CmpctBlock(c) if c.compact_block.header.block_hash() == hash)
}

/// A peer that sent `sendcmpct(1, 2)` receives a newly mined block as a
/// `cmpctblock` — with the coinbase prefilled and a correct short ID for
/// every other transaction (`test_compactblock_construction`) — while a
/// peer that did not gets a header or inv.
#[test]
fn a_high_bandwidth_peer_receives_new_blocks_as_cmpctblock() {
    use bitcoin::p2p::message_compact_blocks::SendCmpct;
    let (node, wallet) = started_node(101);
    let dest = DeterministicWallet::from_secret([0x62; 32]);
    let (tx_hex, _) = common::build_signed_p2wpkh_spend_from_block1_coinbase(
        &node, &wallet, dest.address.script_pubkey(), 1_000,
    );
    node.rpc_ok("sendrawtransaction", vec![json!(tx_hex)]);

    let port = node.p2p_port.unwrap();
    let mut hb = RawPeer::connect(port);
    let mut lb = RawPeer::connect(port);
    poll_until(|| peer_count(&node) == 2, test_timeout(20), "peers must connect");
    hb.send(NetworkMessage::SendCmpct(SendCmpct { send_compact: true, version: 2 }));
    poll_until(
        || node.rpc_ok("getpeerinfo", vec![]).as_array().unwrap().iter().any(|p| p["bip152_hb_from"] == json!(true)),
        test_timeout(20),
        "the node must record the high-bandwidth request",
    );

    let mined = node.rpc_ok("generatetoaddress", vec![json!(1), json!(wallet.address.to_string())]);
    let hash: BlockHash = mined[0].as_str().unwrap().parse().unwrap();
    let block = block_at(&node, &hash);
    assert_eq!(block.txdata.len(), 2, "the block carries the mempool transaction");

    let got = hb.recv_until(is_cmpctblock_for(hash), test_timeout(20));
    let Some(NetworkMessage::CmpctBlock(c)) = got else {
        panic!("the high-bandwidth peer must receive a cmpctblock");
    };
    assert_eq!(c.compact_block, expected_compact(&block, c.compact_block.nonce));
    let again = hb.collect_for(Duration::from_secs(2));
    let repeat = again.iter().find(|m| match m {
        NetworkMessage::Inv(inv) => inv.iter().any(|i| matches!(i, Inventory::Block(h) if *h == hash)),
        NetworkMessage::Headers(hs) => hs.iter().any(|h| h.block_hash() == hash),
        m => is_cmpctblock_for(hash)(m),
    });
    assert!(
        repeat.is_none(),
        "the block is announced once — before connecting it, not again after: {repeat:?}"
    );

    let lb_msgs = lb.collect_for(Duration::from_secs(2));
    assert!(
        !lb_msgs.iter().any(is_cmpctblock_for(hash)),
        "a low-bandwidth peer must not be pushed a cmpctblock"
    );
    assert!(
        lb_msgs.iter().any(|m| matches!(m, NetworkMessage::Inv(_) | NetworkMessage::Headers(_))),
        "a low-bandwidth peer still hears about the block: {lb_msgs:?}"
    );
}

/// `MSG_CMPCT_BLOCK` within five blocks of the tip is answered with a
/// `cmpctblock`; deeper, with the full block (Core `MAX_CMPCTBLOCK_DEPTH`).
#[test]
fn msg_cmpct_block_getdata_is_answered_by_depth() {
    let (node, _) = started_node(20);
    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    let hash_at = |h: u32| -> BlockHash {
        node.rpc_ok("getblockhash", vec![json!(h)]).as_str().unwrap().parse().unwrap()
    };
    let answer = |peer: &mut RawPeer, hash: BlockHash| {
        peer.send(NetworkMessage::GetData(vec![Inventory::CompactBlock(hash)]));
        peer.recv_until(
            |m| matches!(m, NetworkMessage::CmpctBlock(_) | NetworkMessage::Block(_)),
            test_timeout(20),
        )
    };

    for h in [20u32, 15] {
        let hash = hash_at(h);
        match answer(&mut peer, hash) {
            Some(NetworkMessage::CmpctBlock(c)) => {
                let block = block_at(&node, &hash);
                assert_eq!(c.compact_block, expected_compact(&block, c.compact_block.nonce), "height {h}");
            }
            other => panic!("height {h} (depth {}) must be a cmpctblock, got {other:?}", 20 - h),
        }
    }
    let deep = hash_at(14);
    assert!(
        matches!(answer(&mut peer, deep), Some(NetworkMessage::Block(b)) if b.block_hash() == deep),
        "depth 6 must be a full block"
    );
    let body = node.rpc_ok("getpeerinfo", vec![]);
    assert!(body[0]["bytessent_per_msg"]["cmpctblock"].as_u64().unwrap_or(0) > 0);
}

/// Two satd nodes: once B has taken a block from A, B selects A for
/// high-bandwidth relay, and A's next block reaches B as a `cmpctblock`
/// rather than a `block`.
#[test]
fn two_satd_nodes_relay_a_block_as_cmpctblock() {
    let p2p_port_a = common::find_available_port();
    let node_a = TestNode::start(&[&format!("--port={p2p_port_a}")]);
    let node_b = TestNode::start(&[&format!("--connect=127.0.0.1:{p2p_port_a}")]);
    poll_until(|| peer_count(&node_a) >= 1 && peer_count(&node_b) >= 1, test_timeout(20), "nodes must connect");
    let addr = DeterministicWallet::from_secret([0x63; 32]).address.to_string();

    let per_msg = |node: &TestNode, dir: &str, msg: &str| -> u64 {
        node.rpc_ok("getpeerinfo", vec![])[0][dir][msg].as_u64().unwrap_or(0)
    };

    node_a.rpc_ok("generatetoaddress", vec![json!(1), json!(addr)]);
    poll_until(|| height(&node_b) == 1, test_timeout(20), "B must take A's first block");
    poll_until(
        || node_a.rpc_ok("getpeerinfo", vec![])[0]["bip152_hb_from"] == json!(true),
        test_timeout(20),
        "B must select A for high-bandwidth relay",
    );
    assert_eq!(node_b.rpc_ok("getpeerinfo", vec![])[0]["bip152_hb_to"], json!(true));

    let blocks_before = per_msg(&node_b, "bytesrecv_per_msg", "block");
    node_a.rpc_ok("generatetoaddress", vec![json!(1), json!(addr)]);
    poll_until(|| best_hash(&node_b) == best_hash(&node_a), test_timeout(20), "B must follow A");
    assert!(per_msg(&node_b, "bytesrecv_per_msg", "cmpctblock") > 0, "the block must arrive as a cmpctblock");
    assert_eq!(
        per_msg(&node_b, "bytesrecv_per_msg", "block"),
        blocks_before,
        "no full block may be needed"
    );
}

/// Core's `NewPoWValidBlock`: a block that extends the tip is announced to
/// high-bandwidth peers once it has passed proof of work and `check_block`,
/// before its transactions are validated against the UTXO set. The proof is
/// a block that never connects — it spends a coin that does not exist — and
/// still reaches the peer. A post-connect announcement could not send it.
#[test]
fn a_block_is_announced_to_high_bandwidth_peers_before_it_is_connected() {
    use bitcoin::p2p::message_compact_blocks::SendCmpct;
    let (node, _) = started_node(5);
    let mut hb = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    hb.send(NetworkMessage::SendCmpct(SendCmpct { send_compact: true, version: 2 }));
    poll_until(
        || node.rpc_ok("getpeerinfo", vec![])[0]["bip152_hb_from"] == json!(true),
        test_timeout(20),
        "the node must record the high-bandwidth request",
    );

    let tip_before = best_hash(&node);
    let tip = block_at(&node, &tip_before);
    let bad = build_block(&tip, height(&node) + 1, vec![unknown_tx(1)], true, 8);
    let hash = bad.block_hash();
    let hex = hex::encode(bitcoin::consensus::serialize(&bad));
    let submitted = node.rpc_call_with_params("submitblock", vec![json!(hex)]).unwrap();
    assert!(!submitted["result"].is_null(), "submitblock must reject the block: {submitted}");

    let got = hb.recv_until(is_cmpctblock_for(hash), test_timeout(20));
    assert!(got.is_some(), "the block must be announced before connection is attempted");
    assert_eq!(best_hash(&node), tip_before, "and it must not have connected");
}

/// A peer we did not select for high-bandwidth relay, pushing a `cmpctblock`
/// for a block we never asked it for, gets it treated as a header
/// announcement: the header is taken and the block fetched the ordinary
/// way, with no reconstruction (Core `fRevertToHeaderProcessing`; #32606).
#[test]
fn unsolicited_cmpctblock_from_a_low_bandwidth_peer_is_a_header_announcement() {
    let (node, _) = started_node(1);
    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");

    let (b, compact) = partial_block(&node, 2, 9);
    let hash = b.block_hash();
    peer.send(cmpct(compact));
    let msgs = peer.collect_for(Duration::from_secs(3));
    assert!(
        !msgs.iter().any(is_getblocktxn_for(hash)),
        "an unsolicited push from a low-bandwidth peer must not be reconstructed"
    );
    assert!(msgs.iter().any(is_getdata_for(hash)), "the block is fetched in full instead: {msgs:?}");
    let header = node.rpc_call_with_params("getblockheader", vec![json!(hash.to_string())]).unwrap();
    assert!(header["error"].is_null(), "the header must have been accepted: {header}");
}

// ---------------------------------------------------------------------------
// Outbound prefill (-cmpctblockprefill)
// ---------------------------------------------------------------------------

fn metric_or_zero(port: u16, series: &str) -> u64 {
    metric(&metrics_body(port), series).unwrap_or(0)
}

/// Core #35558: a block announced with the transactions the sender lacked
/// prefilled reconstructs on a peer that lacks them too, without a
/// `getblocktxn` round trip. Node A takes a block carrying X straight from a
/// raw peer, so X was never in A's mempool, and announces it to node B, which
/// has never seen X either. With prefill on, B rebuilds it directly; with it
/// off, B has to ask. Both halves run here so the difference is the flag.
#[test]
fn prefilled_cmpctblock_reconstructs_without_a_round_trip() {
    for (prefill, expect_round_trip) in [(true, false), (false, true)] {
        let p2p_port_a = common::find_available_port();
        let mut args_a = vec![format!("--port={p2p_port_a}")];
        if prefill {
            args_a.push("--cmpctblockprefill=1".to_string());
        }
        let args_a: Vec<&str> = args_a.iter().map(String::as_str).collect();
        let node_a = TestNode::start(&args_a);
        let wallet = DeterministicWallet::from_secret([0x64; 32]);
        node_a.rpc_ok("generatetoaddress", vec![json!(101), json!(wallet.address.to_string())]);

        let metrics_b = common::find_available_port();
        let node_b = TestNode::start(&[
            &format!("--connect=127.0.0.1:{p2p_port_a}"),
            &format!("--metricsport={metrics_b}"),
        ]);
        poll_until(|| height(&node_b) == 101, test_timeout(60), "B must sync A's chain");
        // One block delivered by A makes B select A for high-bandwidth relay.
        node_a.rpc_ok("generatetoaddress", vec![json!(1), json!(wallet.address.to_string())]);
        poll_until(|| best_hash(&node_b) == best_hash(&node_a), test_timeout(20), "B must follow A");
        poll_until(
            || node_a.rpc_ok("getpeerinfo", vec![])[0]["bip152_hb_from"] == json!(true),
            test_timeout(20),
            "B must select A for high-bandwidth relay",
        );

        let dest = DeterministicWallet::from_secret([0x65; 32]);
        let (x_hex, _) = common::build_signed_p2wpkh_spend_from_block1_coinbase(
            &node_a, &wallet, dest.address.script_pubkey(), 1_000,
        );
        let x: Transaction = deserialize(&hex::decode(&x_hex).unwrap()).unwrap();

        let direct = "satd_net_compact_block_reconstructions_total{outcome=\"direct\"}";
        let round_trip = "satd_net_compact_block_reconstructions_total{outcome=\"round_trip\"}";
        let prefilled = "satd_net_compact_block_txs_total{source=\"prefilled\"}";
        let before = [direct, round_trip, prefilled].map(|s| metric_or_zero(metrics_b, s));

        let p = RawPeer::connect(node_a.p2p_port.unwrap());
        poll_until(|| peer_count(&node_a) == 2, test_timeout(20), "the raw peer must connect to A");
        let tip = block_at(&node_a, &best_hash(&node_a));
        let block = build_block(&tip, height(&node_a) + 1, vec![x], true, 64);
        let hash = block.block_hash();
        p.send(NetworkMessage::Headers(vec![block.header]));
        p.send(NetworkMessage::Block(block));
        poll_until(|| best_hash(&node_a) == hash, test_timeout(20), "A must connect the block");
        poll_until(|| best_hash(&node_b) == hash, test_timeout(20), "B must follow A");

        let after = [direct, round_trip, prefilled].map(|s| metric_or_zero(metrics_b, s));
        let delta: Vec<u64> = after.iter().zip(before).map(|(a, b)| a - b).collect();
        if expect_round_trip {
            assert_eq!(delta, vec![0, 1, 1], "prefill off: coinbase only, and B must ask for X");
        } else {
            assert_eq!(delta, vec![1, 0, 2], "prefill on: X arrives prefilled and B needs nothing");
        }
    }
}

/// A transaction nobody has, about `bytes` long.
fn bulky_unknown_tx(seed: u32, bytes: usize) -> Transaction {
    let mut tx = unknown_tx(seed);
    tx.output[0].script_pubkey = bitcoin::ScriptBuf::from_bytes(vec![0x6a; bytes.saturating_sub(60)]);
    tx
}

/// The prefill stays inside `-cmpctblockprefillbytes`: of five transactions
/// the node lacks, only as many as fit go prefilled, and the rest as short
/// IDs.
#[test]
fn prefill_never_exceeds_its_budget() {
    use bitcoin::p2p::message_compact_blocks::SendCmpct;
    let budget = 4_000usize;
    let node = TestNode::start(&["--cmpctblockprefill=1", &format!("--cmpctblockprefillbytes={budget}")]);
    let wallet = DeterministicWallet::from_secret([0x66; 32]);
    node.rpc_ok("generatetoaddress", vec![json!(5), json!(wallet.address.to_string())]);
    let mut hb = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    hb.send(NetworkMessage::SendCmpct(SendCmpct { send_compact: true, version: 2 }));
    poll_until(
        || node.rpc_ok("getpeerinfo", vec![])[0]["bip152_hb_from"] == json!(true),
        test_timeout(20),
        "the node must record the high-bandwidth request",
    );

    let tip = block_at(&node, &best_hash(&node));
    let txs: Vec<Transaction> = (0..5).map(|i| bulky_unknown_tx(700 + i, 1_500)).collect();
    let block = build_block(&tip, height(&node) + 1, txs, true, 66);
    let hash = block.block_hash();
    // It spends coins that do not exist, so it never connects; it is still
    // announced, which is all this test needs.
    let hex = hex::encode(bitcoin::consensus::serialize(&block));
    let _ = node.rpc_call_with_params("submitblock", vec![json!(hex)]).unwrap();

    let Some(NetworkMessage::CmpctBlock(c)) = hb.recv_until(is_cmpctblock_for(hash), test_timeout(20)) else {
        panic!("the block must be announced");
    };
    let prefilled = &c.compact_block.prefilled_txs;
    let used: usize = prefilled.iter().skip(1).map(|p| p.tx.total_size()).sum();
    assert!(used <= budget, "{used} bytes prefilled against a {budget}-byte budget");
    assert_eq!(prefilled.len(), 1 + budget / 1_500, "as many as fit, beyond the coinbase");
    assert_eq!(prefilled.len() + c.compact_block.short_ids.len(), 6, "the rest go as short IDs");
}

/// Which transactions a node lacked can only be read off the mempool before
/// the block connects; afterwards the mempool no longer holds any of them.
/// A `cmpctblock` first built after connection -- here, a `MSG_CMPCT_BLOCK`
/// getdata for a block the tip cache has moved past -- goes out with the
/// coinbase only, not with every transaction the node in fact had.
#[test]
fn a_cmpctblock_built_after_connection_is_not_prefilled() {
    let node = TestNode::start(&["--cmpctblockprefill=1"]);
    let wallet = DeterministicWallet::from_secret([0x67; 32]);
    node.rpc_ok("generatetoaddress", vec![json!(101), json!(wallet.address.to_string())]);
    let dest = DeterministicWallet::from_secret([0x68; 32]);
    let (tx_hex, _) = common::build_signed_p2wpkh_spend_from_block1_coinbase(
        &node, &wallet, dest.address.script_pubkey(), 1_000,
    );
    node.rpc_ok("sendrawtransaction", vec![json!(tx_hex)]);
    let mined = node.rpc_ok("generatetoaddress", vec![json!(1), json!(wallet.address.to_string())]);
    let hash: BlockHash = mined[0].as_str().unwrap().parse().unwrap();
    assert_eq!(block_at(&node, &hash).txdata.len(), 2, "the block must carry the mempool transaction");
    node.rpc_ok("generatetoaddress", vec![json!(1), json!(wallet.address.to_string())]);

    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    peer.send(NetworkMessage::GetData(vec![Inventory::CompactBlock(hash)]));
    match peer.recv_until(|m| matches!(m, NetworkMessage::CmpctBlock(_) | NetworkMessage::Block(_)), test_timeout(20)) {
        Some(NetworkMessage::CmpctBlock(c)) => {
            assert_eq!(c.compact_block.prefilled_txs.len(), 1, "coinbase only");
            assert_eq!(c.compact_block.short_ids.len(), 1);
        }
        other => panic!("expected a cmpctblock, got {other:?}"),
    }
}

/// A peer that announces with `cmpctblock` is a block-download source.
///
/// This is not bookkeeping. The parallel download scheduler will not assign a
/// peer heights above what the node believes that peer holds, and the node
/// learns what a peer holds from Core's `UpdateBlockAvailability`. A
/// high-bandwidth peer announces new blocks with `cmpctblock` **instead of**
/// `headers` (BIP 152), so if that path does not record availability the node
/// ends up knowing the headers, raising its download target, and asking
/// nobody for the blocks — it wedges behind its only peer rather than syncing
/// slowly.
///
/// The shape is the one a node following a peer that mines faster than it can
/// fetch runs into: announcements arrive ahead of data, every block after the
/// first lands on a header-only parent and is left to the scheduler, and the
/// scheduler takes over once headers are more than 24 ahead of the tip.
#[test]
fn a_cmpctblock_announcement_makes_the_peer_a_download_source() {
    // Enough announcements to cross the scheduler's creation threshold
    // (`headers_tip > tip + 24`): below it the steady-state path fetches the
    // chain and the scheduler, where the belief about the peer is consulted,
    // never runs.
    const ANNOUNCED: u32 = 30;

    let (node, _) = started_node(1);
    let mut peer = RawPeer::connect(node.p2p_port.unwrap());
    poll_until(|| peer_count(&node) == 1, test_timeout(20), "peer must connect");
    // Only a high-bandwidth peer's pushes reach the compact path at all, and
    // promotion is also the last thing to teach the node this peer's height
    // through a `headers` message. Everything after it is compact, which is
    // the point: the peer's version message claimed height 0.
    promote(&node, &mut peer);

    let tip = block_at(&node, &best_hash(&node));
    let h = height(&node);

    // The first announcement carries a transaction the node has never seen,
    // so reconstruction needs a `getblocktxn`. Leaving that unanswered is
    // what keeps its data behind its header — and every later block then
    // lands on a header-only parent.
    let first = build_block(&tip, h + 1, vec![unknown_tx(9_100)], true, 91);
    peer.send(cmpct(HeaderAndShortIds::from_block(&first, 91, 2, &[]).unwrap()));
    assert!(
        peer.recv_until(is_getblocktxn_for(first.block_hash()), test_timeout(20)).is_some(),
        "the node should try to reconstruct the first announcement"
    );

    let mut parent = first.clone();
    for i in 1..ANNOUNCED {
        let next = build_block(&parent, h + 1 + i, vec![], true, 9_200 + i);
        peer.send(cmpct(HeaderAndShortIds::from_block(&next, u64::from(9_200 + i), 2, &[]).unwrap()));
        parent = next;
    }

    // The node now knows headers well past its tip and has data for none of
    // them. This peer announced every one of those headers and nothing else
    // has spoken to the node, so it is the only source there is.
    let asked = peer.recv_until(is_getdata_for(first.block_hash()), test_timeout(60));
    assert!(
        asked.is_some(),
        "the node knows {ANNOUNCED} headers past its tip, has no data for them, and the \
         peer that announced them is its only source; asking nobody is a wedge, not a delay"
    );
}
