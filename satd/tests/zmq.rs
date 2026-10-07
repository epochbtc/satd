//! Bitcoin Core-compatible ZMQ notifications (`-zmqpub*`), end to end: a real
//! satd, a real ZMQ subscriber (the `zeromq` crate, an implementation
//! independent of satd's publisher), and Core's message formats checked byte
//! for byte.

mod common;

use std::time::{Duration, Instant};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::{Block, BlockHash, Transaction};
use common::{
    DeterministicWallet, TestNode, build_signed_p2wpkh_spend_from_block1_coinbase,
    build_signed_p2wpkh_spend_seq, find_available_port, test_timeout,
};
use serde_json::json;
use zeromq::{Socket, SocketRecv};

const TOPICS: [&str; 5] = ["hashblock", "hashtx", "rawblock", "rawtx", "sequence"];

/// One received message: topic, body, and the notifier's counter.
#[derive(Debug, Clone)]
struct Msg {
    topic: String,
    body: Vec<u8>,
    seq: u32,
}

impl Msg {
    /// The body as a display-order hash, for `hashblock` / `hashtx`.
    fn hash_hex(&self) -> String {
        assert_eq!(self.body.len(), 32, "{self:?}");
        hex::encode(&self.body)
    }

    /// `sequence`: (display-order hash, label, mempool sequence).
    fn sequence(&self) -> (String, char, Option<u64>) {
        assert_eq!(self.topic, "sequence");
        let hash = hex::encode(&self.body[..32]);
        let label = self.body[32] as char;
        let mempool_sequence = match self.body.len() {
            33 => None,
            41 => Some(u64::from_le_bytes(self.body[33..41].try_into().unwrap())),
            n => panic!("sequence body of {n} bytes"),
        };
        (hash, label, mempool_sequence)
    }
}

/// A ZMQ SUB socket driven from the synchronous test thread.
struct Sub {
    rt: tokio::runtime::Runtime,
    socket: zeromq::SubSocket,
}

impl Sub {
    fn connect(endpoint: &str, topics: &[&str]) -> Self {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let mut socket = zeromq::SubSocket::new();
        rt.block_on(async {
            socket.connect(endpoint).await.expect("connect");
            for t in topics {
                socket.subscribe(t).await.expect("subscribe");
            }
        });
        Sub { rt, socket }
    }

    fn recv(&mut self, timeout: Duration) -> Option<Msg> {
        let socket = &mut self.socket;
        let msg = self.rt.block_on(async { tokio::time::timeout(timeout, socket.recv()).await }).ok()?;
        let msg = msg.expect("recv");
        let frames: Vec<Vec<u8>> = msg.into_vec().into_iter().map(|b| b.to_vec()).collect();
        assert_eq!(frames.len(), 3, "a Core ZMQ message has three frames: {frames:?}");
        Some(Msg {
            topic: String::from_utf8(frames[0].clone()).expect("ascii topic"),
            body: frames[1].clone(),
            seq: u32::from_le_bytes(frames[2].as_slice().try_into().expect("4-byte counter")),
        })
    }

    /// Exactly `n` messages, failing the test if they do not arrive in time.
    fn take(&mut self, n: usize) -> Vec<Msg> {
        let deadline = Instant::now() + test_timeout(30);
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.recv(left) {
                Some(m) => out.push(m),
                None => panic!("expected {n} messages, got {}: {out:#?}", out.len()),
            }
        }
        out
    }

    /// Whatever arrives until the socket has been quiet for `quiet`.
    fn drain(&mut self, quiet: Duration) -> Vec<Msg> {
        let mut out = Vec::new();
        while let Some(m) = self.recv(quiet) {
            out.push(m);
        }
        out
    }
}

fn wallet() -> DeterministicWallet {
    DeterministicWallet::from_secret([0x5a; 32])
}

fn tcp(port: u16) -> String {
    format!("tcp://127.0.0.1:{port}")
}

fn mine(node: &TestNode, n: u64, addr: &str) -> Vec<String> {
    node.rpc_ok("generatetoaddress", vec![json!(n), json!(addr)])
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap().to_string())
        .collect()
}

fn block_at(node: &TestNode, hash: &str) -> Block {
    let hex = node.rpc_ok("getblock", vec![json!(hash), json!(0)]);
    deserialize(&hex::decode(hex.as_str().unwrap()).unwrap()).unwrap()
}

fn mempool_sequence(node: &TestNode) -> u64 {
    node.rpc_ok("getrawmempool", vec![json!(false), json!(true)])["mempool_sequence"]
        .as_u64()
        .unwrap()
}

/// Core's functional-test "sync up": a subscriber's subscription reaches the
/// publisher asynchronously, so mine blocks until every subscriber has seen
/// one, then drain what is left. Every topic publishes for every block (the
/// coinbase rides `hashtx`/`rawtx`), so any message proves the subscription.
/// Returns the hashes of the blocks it mined.
fn sync_up(node: &TestNode, subs: &mut [&mut Sub], addr: &str) -> Vec<String> {
    let mut mined = Vec::new();
    let deadline = Instant::now() + test_timeout(60);
    let mut ready = vec![false; subs.len()];
    while !ready.iter().all(|r| *r) {
        assert!(Instant::now() < deadline, "subscribers never received a message");
        mined.extend(mine(node, 1, addr));
        for (i, sub) in subs.iter_mut().enumerate() {
            if !ready[i] && sub.recv(Duration::from_secs(1)).is_some() {
                ready[i] = true;
            }
        }
    }
    for sub in subs.iter_mut() {
        sub.drain(Duration::from_millis(500));
    }
    mined
}

/// The five topics on one address: per block, Core's messages in Core's
/// order, with Core's bodies, each topic counting from 0.
#[test]
fn zmq_basic_topics_shared_socket() {
    let port = find_available_port();
    let args: Vec<String> = TOPICS.iter().map(|t| format!("--zmqpub{t}={}", tcp(port))).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut node = TestNode::start(&args);
    let addr = wallet().address.to_string();

    let mut sub = Sub::connect(&tcp(port), &[""]);
    let synced = sync_up(&node, &mut [&mut sub], &addr);

    let hashes = mine(&node, 3, &addr);
    let msgs = sub.take(3 * 5);
    for (i, hash) in hashes.iter().enumerate() {
        let block = block_at(&node, hash);
        let coinbase = &block.txdata[0];
        let m = &msgs[i * 5..i * 5 + 5];
        let topics: Vec<&str> = m.iter().map(|m| m.topic.as_str()).collect();
        assert_eq!(topics, ["hashtx", "rawtx", "sequence", "hashblock", "rawblock"], "block {i}");
        assert_eq!(m[0].hash_hex(), coinbase.compute_txid().to_string());
        let rawtx: Transaction = deserialize(&m[1].body).expect("rawtx deserializes");
        assert_eq!(rawtx.compute_txid(), coinbase.compute_txid());
        assert_eq!(m[1].body, serialize(coinbase), "rawtx is the witness serialization");
        assert_eq!(m[2].sequence(), (hash.clone(), 'C', None));
        assert_eq!(m[3].hash_hex(), *hash);
        let rawblock: Block = deserialize(&m[4].body).expect("rawblock deserializes");
        assert_eq!(rawblock.block_hash().to_string(), *hash);
        assert_eq!(m[4].body, serialize(&block));
        // Each notifier counts its own messages from 0, one per block so far
        // (the sync-up blocks included).
        let expected = (synced.len() + i) as u32;
        assert!(m.iter().all(|m| m.seq == expected), "block {i}: {m:?}");
    }
    assert!(sub.drain(Duration::from_millis(500)).is_empty());
    node.stop();
}

/// Umbrel's layout: one address per topic. Each socket carries only its own
/// topic, and counts it independently.
#[test]
fn zmq_per_topic_sockets() {
    let ports: Vec<u16> = TOPICS.iter().map(|_| find_available_port()).collect();
    let args: Vec<String> =
        TOPICS.iter().zip(&ports).map(|(t, p)| format!("--zmqpub{t}={}", tcp(*p))).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut node = TestNode::start(&args);
    let addr = wallet().address.to_string();

    let mut subs: Vec<Sub> = ports.iter().map(|p| Sub::connect(&tcp(*p), &[""])).collect();
    {
        let mut refs: Vec<&mut Sub> = subs.iter_mut().collect();
        sync_up(&node, &mut refs, &addr);
    }
    mine(&node, 2, &addr);
    for (topic, sub) in TOPICS.iter().zip(subs.iter_mut()) {
        let m = sub.take(2);
        assert!(m.iter().all(|m| m.topic == *topic), "{topic} socket: {m:?}");
        assert_eq!(m[1].seq, m[0].seq + 1, "{topic} counter");
        assert!(sub.drain(Duration::from_millis(300)).is_empty(), "{topic}: one per block");
    }
    node.stop();
}

/// A node publishing every topic on one address, with block 1's coinbase
/// mature (spendable by [`wallet`]) and a subscriber synced to it.
fn mempool_fixture() -> (TestNode, Sub, DeterministicWallet) {
    let port = find_available_port();
    let args: Vec<String> = TOPICS.iter().map(|t| format!("--zmqpub{t}={}", tcp(port))).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let node = TestNode::start(&args);
    let w = wallet();
    let addr = w.address.to_string();
    mine(&node, 101, &addr);
    let mut sub = Sub::connect(&tcp(port), &[""]);
    sync_up(&node, &mut [&mut sub], &addr);
    (node, sub, w)
}

fn send(node: &TestNode, raw_hex: &str) -> String {
    node.rpc_ok("sendrawtransaction", vec![json!(raw_hex)]).as_str().unwrap().to_string()
}

/// A mempool admission: `hashtx`, `rawtx` (the witness serialization, so it
/// hashes to the wtxid), and `sequence A` carrying the sequence number the
/// admission took, which is what `getrawmempool(false, true)` reported just
/// before it.
#[test]
fn zmq_mempool_accept() {
    let (mut node, mut sub, w) = mempool_fixture();
    let before = mempool_sequence(&node);
    let (raw, txid) =
        build_signed_p2wpkh_spend_from_block1_coinbase(&node, &w, w.address.script_pubkey(), 1_000);
    assert_eq!(send(&node, &raw), txid);

    let m = sub.take(3);
    let topics: Vec<&str> = m.iter().map(|m| m.topic.as_str()).collect();
    assert_eq!(topics, ["hashtx", "rawtx", "sequence"]);
    assert_eq!(m[0].hash_hex(), txid);
    assert_eq!(m[1].body, hex::decode(&raw).unwrap());
    let tx: Transaction = deserialize(&m[1].body).unwrap();
    assert_eq!(
        sha256d::Hash::hash(&m[1].body).to_byte_array(),
        tx.compute_wtxid().to_byte_array(),
        "rawtx carries the witness"
    );
    assert_eq!(m[2].sequence(), (txid, 'A', Some(before)));
    assert_eq!(mempool_sequence(&node), before + 1);
    node.stop();
}

/// A transaction replaced straight after admission still reaches `rawtx`
/// (the event carries it, so the publisher does not depend on finding it in
/// the mempool), and its replacement is a `sequence R` numbered between the
/// two admissions.
#[test]
fn zmq_rawtx_for_replaced_tx() {
    let (mut node, mut sub, w) = mempool_fixture();
    let before = mempool_sequence(&node);
    let spk = w.address.script_pubkey();
    let (raw1, txid1) = build_signed_p2wpkh_spend_seq(&node, &w, spk.clone(), 1_000, 0xffff_fffd);
    let (raw2, txid2) = build_signed_p2wpkh_spend_seq(&node, &w, spk, 50_000, 0xffff_fffd);
    send(&node, &raw1);
    send(&node, &raw2);

    let m = sub.take(7);
    let got: Vec<(&str, Vec<u8>)> = m.iter().map(|m| (m.topic.as_str(), m.body.clone())).collect();
    assert_eq!(got[1], ("rawtx", hex::decode(&raw1).unwrap()));
    assert_eq!(m[2].sequence(), (txid1.clone(), 'A', Some(before)));
    assert_eq!(m[3].sequence(), (txid1, 'R', Some(before + 1)));
    assert_eq!(m[4].hash_hex(), txid2);
    assert_eq!(got[5], ("rawtx", hex::decode(&raw2).unwrap()));
    assert_eq!(m[6].sequence(), (txid2, 'A', Some(before + 2)));
    node.stop();
}

/// Mining a mempool transaction publishes it again, among the block's
/// messages, as Core does; leaving the mempool by inclusion publishes no
/// `sequence R`.
#[test]
fn zmq_block_republishes_mempool_txs() {
    let (mut node, mut sub, w) = mempool_fixture();
    let (raw, txid) =
        build_signed_p2wpkh_spend_from_block1_coinbase(&node, &w, w.address.script_pubkey(), 1_000);
    send(&node, &raw);
    sub.take(3);

    let hash = mine(&node, 1, &w.address.to_string()).remove(0);
    let block = block_at(&node, &hash);
    assert_eq!(block.txdata.len(), 2, "fixture: the block mines the transaction");
    let m = sub.take(7);
    let topics: Vec<&str> = m.iter().map(|m| m.topic.as_str()).collect();
    assert_eq!(topics, ["hashtx", "rawtx", "hashtx", "rawtx", "sequence", "hashblock", "rawblock"]);
    assert_eq!(m[2].hash_hex(), txid);
    assert_eq!(m[3].body, hex::decode(&raw).unwrap());
    assert_eq!(m[4].sequence(), (hash.clone(), 'C', None));
    assert!(sub.drain(Duration::from_millis(500)).is_empty(), "no R for a mined transaction");
    node.stop();
}

/// A regtest block on `prev`, ground under the regtest target. Transactions
/// in `extra` must carry no witness: the coinbase has no commitment.
fn build_block(prev: BlockHash, height: u32, time: u32, extra: Vec<Transaction>) -> Block {
    let subsidy = (50u64 * 100_000_000) >> (height / 150).min(63);
    let coinbase = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: bitcoin::script::Builder::new()
                .push_int(height as i64)
                .push_int(time as i64)
                .push_opcode(bitcoin::opcodes::OP_FALSE)
                .into_script(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(subsidy),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    let mut txdata = vec![coinbase];
    txdata.extend(extra);
    let mut block = Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block.compute_merkle_root().expect("non-empty block");
    let target = block.header.target();
    while block.header.validate_pow(target).is_err() {
        block.header.nonce += 1;
    }
    block
}

fn submit(node: &TestNode, method: &str, bytes: Vec<u8>) {
    let r = node.rpc_call_with_params(method, vec![json!(hex::encode(bytes))]).expect("rpc");
    assert!(r["error"].is_null(), "{method}: {r}");
}

fn template_time(node: &TestNode) -> u32 {
    node.rpc_ok("getblocktemplate", vec![])["curtime"].as_u64().unwrap() as u32
}

/// A reorg publishes `D` for each disconnected block newest first, `C` for
/// each connected block oldest first, and one `hashblock` / `rawblock`: for
/// the new tip only, as Core announces a tip change once.
#[test]
fn zmq_reorg_single_tip_update() {
    let port = find_available_port();
    let args: Vec<String> = TOPICS.iter().map(|t| format!("--zmqpub{t}={}", tcp(port))).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut node = TestNode::start(&args);
    let addr = wallet().address.to_string();
    let mut sub = Sub::connect(&tcp(port), &[""]);
    sync_up(&node, &mut [&mut sub], &addr);

    let old = mine(&node, 2, &addr);
    sub.take(10);
    let fork: BlockHash = node.rpc_ok("getblockhash", vec![json!(node.rpc_ok("getblockcount", vec![]).as_u64().unwrap() - 2)])
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let fork_height = node.rpc_ok("getblockcount", vec![]).as_u64().unwrap() as u32 - 2;
    let time = template_time(&node);
    let b1 = build_block(fork, fork_height + 1, time + 1, vec![]);
    let b2 = build_block(b1.block_hash(), fork_height + 2, time + 2, vec![]);
    let b3 = build_block(b2.block_hash(), fork_height + 3, time + 3, vec![]);
    for b in [&b1, &b2] {
        submit(&node, "submitblock", serialize(b));
    }
    assert_eq!(node.rpc_ok("getbestblockhash", vec![]).as_str().unwrap(), old[1], "fixture: no reorg yet");
    submit(&node, "submitblock", serialize(&b3));
    assert_eq!(node.rpc_ok("getbestblockhash", vec![]).as_str().unwrap(), b3.block_hash().to_string());

    let m = sub.take(17);
    let seq: Vec<(String, char)> = m
        .iter()
        .filter(|m| m.topic == "sequence")
        .map(|m| {
            let (h, l, _) = m.sequence();
            (h, l)
        })
        .collect();
    assert_eq!(
        seq,
        vec![
            (old[1].clone(), 'D'),
            (old[0].clone(), 'D'),
            (b1.block_hash().to_string(), 'C'),
            (b2.block_hash().to_string(), 'C'),
            (b3.block_hash().to_string(), 'C'),
        ]
    );
    let tips: Vec<String> = m.iter().filter(|m| m.topic == "hashblock").map(Msg::hash_hex).collect();
    assert_eq!(tips, vec![b3.block_hash().to_string()], "one tip update, for the new tip");
    let raw: Vec<&Msg> = m.iter().filter(|m| m.topic == "rawblock").collect();
    assert_eq!(raw.len(), 1);
    assert_eq!(raw[0].body, serialize(&b3));
    assert_eq!(m.last().unwrap().topic, "rawblock");
    assert!(sub.drain(Duration::from_millis(500)).is_empty());
    node.stop();
}

/// `invalidateblock` disconnects without connecting anything: `D`, the
/// mempool re-admitting the block's transaction, and no `hashblock`, since
/// Core announces no tip update for a pure disconnect. The next block is an
/// ordinary tip update again.
#[test]
fn zmq_invalidate_no_hashblock() {
    let (mut node, mut sub, w) = mempool_fixture();
    let addr = w.address.to_string();
    let (raw, txid) =
        build_signed_p2wpkh_spend_from_block1_coinbase(&node, &w, w.address.script_pubkey(), 1_000);
    send(&node, &raw);
    sub.take(3);
    let hash = mine(&node, 1, &addr).remove(0);
    sub.take(7);

    let before = mempool_sequence(&node);
    node.rpc_ok("invalidateblock", vec![json!(hash)]);
    // Block-derived: the block's two transactions, then D. Mempool-derived:
    // the re-admitted transaction. No order is promised between the groups.
    let m = sub.take(8);
    assert!(m.iter().all(|m| m.topic != "hashblock" && m.topic != "rawblock"), "{m:#?}");
    let seq: Vec<(String, char, Option<u64>)> =
        m.iter().filter(|m| m.topic == "sequence").map(Msg::sequence).collect();
    assert_eq!(seq.len(), 2);
    assert!(seq.contains(&(hash.clone(), 'D', None)), "{seq:?}");
    assert!(seq.contains(&(txid.clone(), 'A', Some(before))), "{seq:?}");
    assert_eq!(m.iter().filter(|m| m.topic == "hashtx" && m.hash_hex() == txid).count(), 2);

    // Another address, or the template rebuilds the invalidated block.
    let other = DeterministicWallet::from_secret([0x5b; 32]).address.to_string();
    let next = mine(&node, 1, &other).remove(0);
    let m = sub.take(7);
    let tips: Vec<String> = m.iter().filter(|m| m.topic == "hashblock").map(Msg::hash_hex).collect();
    assert_eq!(tips, vec![next], "the block after an invalidation is announced");
    node.stop();
}

/// Core publishes no `hashblock` / `rawblock` during initial block download.
/// A fresh regtest node's tip is the 2011 genesis block, and blocks stamped
/// near it keep it in IBD: they get their `sequence C`, not a tip update.
/// The first block stamped now ends IBD and is announced.
#[test]
fn zmq_ibd_suppresses_tip_update() {
    let port = find_available_port();
    let mut node = TestNode::start(&[
        &format!("--zmqpubhashblock={}", tcp(port)),
        &format!("--zmqpubsequence={}", tcp(port)),
    ]);
    let mut sub = Sub::connect(&tcp(port), &[""]);
    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
    let mut prev = genesis.block_hash();
    let mut height = 0;
    // Sync up on old blocks: each gives exactly one `sequence C`.
    let deadline = Instant::now() + test_timeout(60);
    loop {
        assert!(Instant::now() < deadline, "subscriber never received a message");
        height += 1;
        let b = build_block(prev, height, genesis.header.time + height, vec![]);
        prev = b.block_hash();
        submit(&node, "submitblock", serialize(&b));
        if sub.recv(Duration::from_secs(1)).is_some() {
            break;
        }
    }
    sub.drain(Duration::from_millis(500));

    let old = build_block(prev, height + 1, genesis.header.time + height + 1, vec![]);
    submit(&node, "submitblock", serialize(&old));
    let m = sub.take(1);
    assert_eq!(m[0].sequence(), (old.block_hash().to_string(), 'C', None));
    assert!(sub.drain(Duration::from_millis(500)).is_empty(), "no tip update in IBD");

    let now = mine(&node, 1, &wallet().address.to_string()).remove(0);
    let m = sub.take(2);
    assert_eq!(m[0].sequence(), (now.clone(), 'C', None));
    assert_eq!((m[1].topic.as_str(), m[1].hash_hex()), ("hashblock", now));
    node.stop();
}

/// `getzmqnotifications`: Core's shape, in Core's notifier order, with a
/// `unix:` address reported as `ipc://` and each topic's HWM.
#[test]
fn zmq_getzmqnotifications_shape() {
    let (p1, p2) = (find_available_port(), find_available_port());
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("hb.sock");
    let mut node = TestNode::start(&[
        &format!("--zmqpubsequence={}", tcp(p1)),
        &format!("--zmqpubrawtx={}", tcp(p1)),
        &format!("--zmqpubhashblock={}", tcp(p2)),
        &format!("--zmqpubhashblock=unix:{}", sock.display()),
        "--zmqpubrawtxhwm=5",
        "--zmqpubhashblockhwm=0",
    ]);
    assert_eq!(
        node.rpc_ok("getzmqnotifications", vec![]),
        json!([
            {"type": "pubhashblock", "address": tcp(p2), "hwm": 0},
            {"type": "pubhashblock", "address": format!("ipc://{}", sock.display()), "hwm": 0},
            {"type": "pubrawtx", "address": tcp(p1), "hwm": 5},
            {"type": "pubsequence", "address": tcp(p1), "hwm": 1000},
        ])
    );
    let help = node.rpc_ok("help", vec![]);
    assert!(help.as_str().unwrap().contains("== Zmq ==\ngetzmqnotifications"), "{help}");
    node.stop();
}

/// An address that cannot be bound turns ZMQ off and leaves the node
/// running, as in Core.
#[test]
fn zmq_bad_endpoint_is_non_fatal() {
    let mut node = TestNode::start(&["--zmqpubrawtx=foo", "--zmqpubhashtx=bar"]);
    assert_eq!(node.rpc_ok("getzmqnotifications", vec![]), json!([]));
    assert!(node.rpc_ok("getblockcount", vec![]).is_u64(), "the node is up");
    node.stop();
}

/// An address with one colon and no valid port refuses to start, with
/// Core's message.
#[test]
fn zmq_port_validation_error_text() {
    let dir = common::fresh_test_datadir("satd-zmq-port");
    let (status, stderr) =
        common::run_satd_until_exit(&dir, &["--zmqpubrawtx=127.0.0.1:notaport"], test_timeout(60));
    assert!(!status.success());
    assert!(
        stderr.contains("Invalid port specified in -zmqpubrawtx: '127.0.0.1:notaport'"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A block near the weight limit arrives on `rawblock` complete, with no
/// later message to push it out (the stuck-tail failure of a PUB socket that
/// flushes only on its next send, which would deliver a block one block
/// late).
#[test]
fn zmq_large_block_rawblock_prompt() {
    let port = find_available_port();
    let mut node = TestNode::start(&[&format!("--zmqpubrawblock={}", tcp(port))]);
    // Coinbases anyone can spend with an empty scriptSig: a transaction with
    // no witness, so the block needs no witness commitment.
    let mined: Vec<String> = node
        .rpc_ok("generatetodescriptor", vec![json!(101), json!("raw(51)")])
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap().to_string())
        .collect();
    let mut sub = Sub::connect(&tcp(port), &["rawblock"]);
    sync_up(&node, &mut [&mut sub], &wallet().address.to_string());

    let funding = block_at(&node, &mined[0]).txdata[0].clone();
    // 95 outputs of a 10 000-byte script that runs no opcode costing a
    // sigop: about 950 kB, so 3.8M of the 4M weight units.
    let big_script = {
        let mut s = vec![0x6a];
        s.extend(std::iter::repeat_n(0x00, 9_999));
        bitcoin::ScriptBuf::from_bytes(s)
    };
    let spend = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint { txid: funding.compute_txid(), vout: 0 },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: (0..95)
            .map(|_| bitcoin::TxOut { value: bitcoin::Amount::ZERO, script_pubkey: big_script.clone() })
            .collect(),
    };
    let tip: BlockHash = node.rpc_ok("getbestblockhash", vec![]).as_str().unwrap().parse().unwrap();
    let height = node.rpc_ok("getblockcount", vec![]).as_u64().unwrap() as u32;
    let big = build_block(tip, height + 1, template_time(&node), vec![spend]);
    let bytes = serialize(&big);
    assert!(big.weight().to_wu() > 3_700_000, "fixture: {} WU", big.weight().to_wu());
    submit(&node, "submitblock", bytes.clone());
    assert_eq!(node.rpc_ok("getbestblockhash", vec![]).as_str().unwrap(), big.block_hash().to_string());

    let m = sub.take(1);
    assert_eq!(m[0].body.len(), bytes.len());
    assert!(m[0].body == bytes, "rawblock is the block's serialization");
    node.stop();
}

/// Without `-zmqpub*` nothing is bound and nothing is reported.
#[test]
fn zmq_unconfigured_is_inert() {
    let metrics = find_available_port();
    let mut node = TestNode::start(&[&format!("--metricsport={metrics}")]);
    assert_eq!(node.rpc_ok("getzmqnotifications", vec![]), json!([]));
    let page = reqwest::blocking::get(format!("http://127.0.0.1:{metrics}/metrics"))
        .unwrap()
        .text()
        .unwrap();
    assert!(!page.contains("satd_zmq_"), "no ZMQ metrics without a publisher");
    node.stop();
}

/// The publisher's metrics, while it runs.
#[test]
fn zmq_metrics_count_messages_and_subscribers() {
    let (port, metrics) = (find_available_port(), find_available_port());
    let mut node = TestNode::start(&[
        &format!("--zmqpubhashblock={}", tcp(port)),
        &format!("--metricsport={metrics}"),
    ]);
    let mut sub = Sub::connect(&tcp(port), &["hashblock"]);
    let mined = sync_up(&node, &mut [&mut sub], &wallet().address.to_string());
    let page = reqwest::blocking::get(format!("http://127.0.0.1:{metrics}/metrics"))
        .unwrap()
        .text()
        .unwrap();
    assert!(
        page.contains(&format!("satd_zmq_messages_total{{topic=\"hashblock\"}} {}", mined.len())),
        "{page}"
    );
    assert!(page.contains("satd_zmq_subscribers 1"), "{page}");
    node.stop();
}

/// A block that arrives before its parent is connected later by the
/// stored-tail drain, which reports it as a chain event (#900), so it is
/// announced on `hashblock` like any other new tip.
#[test]
fn zmq_stored_tail_block_published() {
    let port = find_available_port();
    let mut node = TestNode::start(&[&format!("--zmqpubhashblock={}", tcp(port))]);
    let mut sub = Sub::connect(&tcp(port), &["hashblock"]);
    sync_up(&node, &mut [&mut sub], &wallet().address.to_string());

    let tip: BlockHash = node.rpc_ok("getbestblockhash", vec![]).as_str().unwrap().parse().unwrap();
    let height = node.rpc_ok("getblockcount", vec![]).as_u64().unwrap() as u32;
    let time = template_time(&node);
    let parent = build_block(tip, height + 1, time, vec![]);
    let child = build_block(parent.block_hash(), height + 2, time + 1, vec![]);
    submit(&node, "submitheader", serialize(&parent.header));
    submit(&node, "submitheader", serialize(&child.header));
    submit(&node, "submitblock", serialize(&child));
    assert_eq!(node.rpc_ok("getblockcount", vec![]).as_u64().unwrap() as u32, height, "fixture: the child waits");
    submit(&node, "submitblock", serialize(&parent));

    let m = sub.take(2);
    let tips: Vec<String> = m.iter().map(Msg::hash_hex).collect();
    assert_eq!(tips, vec![parent.block_hash().to_string(), child.block_hash().to_string()]);
    node.stop();
}
