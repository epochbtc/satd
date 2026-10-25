//! The NAP aggregator on regtest: two publishers and one aggregator, and a
//! misbehaving publisher reached only through a pull connection.
//!
//! Publisher A and publisher B serve attestations for three coins; the
//! aggregator C pulls them over its connections to both. The test then
//! covers:
//! - supersession across publishers: B serves a newer attestation for a coin
//!   that A attested;
//! - a withdrawn value: an empty value supersedes the earlier one;
//! - an anchor reorg: invalidating the newer anchor brings the older
//!   attestations back, and reconsidering it restores the newer;
//! - a spent coin, which drops out at the next block;
//! - a fake publisher the aggregator learns of only from an `addr` message.
//!   C reaches it over a `nap-pull` connection, which carries nothing but
//!   the pull. Its forged attestation is misbehaviour: C disconnects it,
//!   and keeps nothing it served.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bitcoin::consensus::encode;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::address::Address as P2pAddress;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, Witness};
use serde_json::{Value, json};

use common::{
    DeterministicWallet, TestNode, build_signed_p2wpkh_spend_of_coinbase, coinbase_txid_at, poll_until,
    test_timeout,
};

const BURN: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
/// `nap::COINBASE_MATURITY` + `nap::ANCHOR_DEPTH`.
const ATTESTABLE_AFTER: u64 = 100 + 6;
const NODE_NAP: u64 = 1 << 30;

fn burn() -> ScriptBuf {
    BURN.parse::<bitcoin::Address<_>>().unwrap().assume_checked().script_pubkey()
}

fn wallet() -> DeterministicWallet {
    DeterministicWallet::from_secret([1; 32])
}

/// A BIP 322 simple signature by the wallet's P2WPKH key over `message`.
fn sign(message: &str) -> String {
    let w = wallet();
    let spk = w.address.script_pubkey();
    let pk = bitcoin::CompressedPublicKey::from_slice(&w.pk.to_bytes()).unwrap();
    let spend = node::bip322::to_spend(&spk, message.as_bytes());
    let tx = node::bip322::to_sign(spend.compute_txid(), Witness::new());
    let sighash =
        SighashCache::new(&tx).p2wpkh_signature_hash(0, &spk, Amount::ZERO, EcdsaSighashType::All).unwrap();
    let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &w.sk);
    let sig = bitcoin::ecdsa::Signature { signature: sig, sighash_type: EcdsaSighashType::All };
    let wit = Witness::p2wpkh(&sig, &pk.0);
    format!("smp{}", base64::engine::general_purpose::STANDARD.encode(bitcoin::consensus::serialize(&wit)))
}

/// The coinbase output of the block at `height`, as `"<txid>:0"`.
fn coin(node: &TestNode, height: u64) -> String {
    format!("{}:0", coinbase_txid_at(node, height))
}

/// Attest `key` = `value` for `outpoint` on publisher `node`.
fn attest(node: &TestNode, outpoint: &str, key: &str, value: &str) {
    let draft = node.rpc_ok("createnapattestation", vec![json!(outpoint), json!(key), json!(value)]);
    let message = draft["message"].as_str().unwrap();
    node.rpc_ok("submitnapattestation", vec![json!(message), json!(sign(message))]);
}

fn height(node: &TestNode) -> u64 {
    node.rpc_ok("getblockcount", vec![]).as_u64().unwrap()
}

fn p2p(node: &TestNode) -> String {
    format!("127.0.0.1:{}", node.p2p_port.expect("tracked port"))
}

fn synced(nodes: &[&TestNode]) {
    poll_until(
        || {
            let tips: Vec<Value> = nodes.iter().map(|n| n.rpc_ok("getbestblockhash", vec![])).collect();
            tips.windows(2).all(|w| w[0] == w[1])
        },
        test_timeout(60),
        "nodes to agree on the tip",
    );
}

fn aggregate(node: &TestNode) -> Value {
    node.rpc_ok("listnapaggregate", vec![])
}

/// What counts for `outpoint` and `key` at the aggregator: the value and the
/// peer it came from.
fn counted(node: &TestNode, outpoint: &str, key: &str) -> Option<(String, String)> {
    aggregate(node)["attestations"].as_array().unwrap().iter().find_map(|a| {
        (a["outpoint"] == outpoint && a["key"] == key)
            .then(|| (a["value"].as_str().unwrap().to_owned(), a["source"].as_str().unwrap().to_owned()))
    })
}

fn wait_counted(node: &TestNode, outpoint: &str, key: &str, value: &str, what: &str) {
    poll_until(
        || counted(node, outpoint, key).is_some_and(|(v, _)| v == value),
        test_timeout(120),
        what,
    );
}

/// Drop the aggregator's connection to `peer` and open it again, which
/// pulls `peer` at once.
fn reconnect(c: &TestNode, peer: &TestNode) {
    let _ = c.rpc_call_with_params("disconnectnode", vec![json!(p2p(peer))]);
    poll_until(
        || {
            let peers = c.rpc_ok("getpeerinfo", vec![]);
            !peers.as_array().unwrap().iter().any(|p| p["addr"] == p2p(peer).as_str())
        },
        test_timeout(30),
        "the connection to close",
    );
    c.rpc_ok("addnode", vec![json!(p2p(peer)), json!("onetry")]);
}

#[test]
fn nap_aggregator_collects_supersedes_withdraws_reorgs_spends_and_punishes() {
    let mut a = TestNode::start(&["--nap=1", "--v2transport=0"]);
    let b = TestNode::start(&["--nap=1", "--v2transport=0"]);
    let c = TestNode::start(&["--napaggregator=1", "--v2transport=0"]);
    let w = wallet();

    // Coins at heights 1 to 4, the last attestable at the tip.
    a.mine_blocks(4, &w.address.to_string());
    a.mine_blocks(ATTESTABLE_AFTER, BURN);
    b.rpc_ok("addnode", vec![json!(p2p(&a)), json!("onetry")]);
    synced(&[&a, &b]);
    let (coin1, coin2, coin3) = (coin(&a, 1), coin(&a, 2), coin(&a, 3));

    attest(&a, &coin1, "k", "yes");
    attest(&a, &coin2, "k", "yes");
    attest(&b, &coin3, "k", "yes");

    // C syncs from both, then pulls both: at connect, or at the collection
    // tick if it connected while still syncing.
    c.rpc_ok("addnode", vec![json!(p2p(&a)), json!("onetry")]);
    c.rpc_ok("addnode", vec![json!(p2p(&b)), json!("onetry")]);
    synced(&[&a, &b, &c]);
    wait_counted(&c, &coin1, "k", "yes", "coin 1 from A");
    wait_counted(&c, &coin2, "k", "yes", "coin 2 from A");
    wait_counted(&c, &coin3, "k", "yes", "coin 3 from B");
    assert_eq!(counted(&c, &coin1, "k").unwrap().1, p2p(&a));
    assert_eq!(counted(&c, &coin3, "k").unwrap().1, p2p(&b));

    // Supersession across publishers: B serves a newer attestation for the
    // coin A attested.
    a.mine_blocks(1, BURN);
    synced(&[&a, &b, &c]);
    let newer_anchor = height(&a) - 6;
    attest(&b, &coin1, "k", "no");
    reconnect(&c, &b);
    wait_counted(&c, &coin1, "k", "no", "B's newer attestation for coin 1");
    assert_eq!(counted(&c, &coin1, "k").unwrap().1, p2p(&b));

    // A withdrawal: an empty value supersedes coin 2's.
    a.mine_blocks(1, BURN);
    synced(&[&a, &b, &c]);
    attest(&a, &coin2, "k", "");
    reconnect(&c, &a);
    wait_counted(&c, &coin2, "k", "", "coin 2's withdrawal");

    // An anchor reorg at the aggregator: without the block the newer
    // attestations anchor to, the older ones count again.
    let anchor: BlockHash = c.rpc_ok("getblockhash", vec![json!(newer_anchor)]).as_str().unwrap().parse().unwrap();
    c.rpc_ok("invalidateblock", vec![json!(anchor.to_string())]);
    wait_counted(&c, &coin1, "k", "yes", "coin 1's older attestation, after the reorg");
    wait_counted(&c, &coin2, "k", "yes", "coin 2's older value, after the reorg");
    c.rpc_ok("reconsiderblock", vec![json!(anchor.to_string())]);
    synced(&[&a, &b, &c]);
    wait_counted(&c, &coin1, "k", "no", "coin 1's newer attestation, back with its anchor");
    wait_counted(&c, &coin2, "k", "", "coin 2's withdrawal, back with its anchor");

    // A spent coin drops out at the next block.
    let (raw, _) = build_signed_p2wpkh_spend_of_coinbase(&a, &w, 3, burn(), 1_000);
    a.rpc_ok("sendrawtransaction", vec![json!(raw)]);
    a.mine_blocks(1, BURN);
    synced(&[&a, &b, &c]);
    poll_until(|| counted(&c, &coin3, "k").is_none(), test_timeout(60), "coin 3 to drop out once spent");

    // A misbehaving publisher, reached only through a pull connection.
    let anchor_height = height(&c) as u32 - 6;
    let anchor: BlockHash =
        c.rpc_ok("getblockhash", vec![json!(anchor_height)]).as_str().unwrap().parse().unwrap();
    let coin4: OutPoint = coin(&a, 4).parse().unwrap();
    let forged = forged_page(coin4, anchor_height, anchor);
    let fake = FakePublisher::start(forged);
    fake.announce_to(c.p2p_port.unwrap());
    poll_until(|| fake.closed(), test_timeout(180), "the aggregator to pull the fake publisher and drop it");
    // The handshake, keep-alive and the pull: nothing else.
    let seen = fake.pull_connection().unwrap();
    let allowed = ["version", "verack", "wtxidrelay", "sendaddrv2", "ping", "pong", "getnapatt"];
    assert!(seen.iter().all(|m| allowed.contains(&m.as_str())), "a pull connection carried more: {seen:?}");
    let agg = aggregate(&c);
    assert_eq!(agg["misbehaving"], 1, "{agg}");
    assert!(counted(&c, &coin4.to_string(), "forged").is_none());
    // What was held stays held.
    assert_eq!(counted(&c, &coin1, "k").unwrap().0, "no");

    a.stop();
}

/// An error's code from an RPC that must fail.
fn refused(node: &TestNode, method: &str, params: Vec<Value>) -> i64 {
    let resp = node.rpc_call_with_params(method, params).unwrap();
    resp["error"]["code"].as_i64().unwrap_or_else(|| panic!("{method} succeeded: {resp}"))
}

#[test]
fn nap_report_replays_byte_for_byte_from_an_exported_snapshot() {
    let mut a = TestNode::start(&["--nap=1", "--v2transport=0"]);
    let c = TestNode::start(&["--napaggregator=1", "--v2transport=0"]);
    let w = wallet();
    a.mine_blocks(3, &w.address.to_string());
    a.mine_blocks(ATTESTABLE_AFTER, BURN);
    let (coin1, coin2, coin3) = (coin(&a, 1), coin(&a, 2), coin(&a, 3));
    attest(&a, &coin1, "k", "yes");
    attest(&a, &coin2, "k", "no");
    attest(&a, &coin3, "k", "");

    c.rpc_ok("addnode", vec![json!(p2p(&a)), json!("onetry")]);
    synced(&[&a, &c]);
    wait_counted(&c, &coin1, "k", "yes", "coin 1");
    wait_counted(&c, &coin2, "k", "no", "coin 2");
    wait_counted(&c, &coin3, "k", "", "coin 3's withdrawal");

    let live = c.rpc_ok("getnapreport", vec![]);
    assert_eq!(live["height"], height(&c));
    assert_eq!(live["counting"], 3);
    let k = &live["keys"][0];
    assert_eq!(k["key"], "k");
    // Regtest's early coinbases hold 50 BTC each.
    assert_eq!(k["weight_sat"], 10_000_000_000u64);
    assert_eq!(k["withdrawn"], json!({ "weight_sat": 5_000_000_000u64, "outpoints": 1 }));
    assert_eq!(k["values"][0]["share_ppm"], 500_000);

    let export = c.rpc_ok("exportnapsnapshot", vec![json!("nap-snapshot.dat")]);
    assert_eq!(export["digest"], live["digest"]);
    assert_eq!(export["attestations"], 3);
    let path = export["path"].as_str().unwrap().to_owned();
    assert!(path.ends_with("nap-snapshot.dat") && std::path::Path::new(&path).is_absolute(), "{path}");
    assert_eq!(refused(&c, "exportnapsnapshot", vec![json!(path)]), -8, "an existing file is not overwritten");

    // The replay, at the same tip, on the aggregator and on a node that
    // aggregates nothing: the same bytes.
    let replayed = c.rpc_ok("replaynapsnapshot", vec![json!(path)]);
    let elsewhere = a.rpc_ok("replaynapsnapshot", vec![json!(path)]);
    let bytes = serde_json::to_string(&live).unwrap();
    assert_eq!(serde_json::to_string(&replayed).unwrap(), bytes);
    assert_eq!(serde_json::to_string(&elsewhere).unwrap(), bytes);

    // Without the aggregator, only a snapshot can be reported on.
    assert_eq!(refused(&a, "getnapreport", vec![]), -1);
    assert_eq!(refused(&a, "exportnapsnapshot", vec![json!("x.dat")]), -1);
    assert_eq!(refused(&a, "replaynapsnapshot", vec![json!("no-such-file.dat")]), -8);

    // The live report, asked again, is the one computed; a new block makes
    // a new one.
    assert_eq!(c.rpc_ok("getnapreport", vec![]), live);
    a.mine_blocks(1, BURN);
    synced(&[&a, &c]);
    let next = c.rpc_ok("getnapreport", vec![]);
    assert_eq!(next["height"], height(&c));
    assert_ne!(next["hash"], live["hash"]);

    a.stop();
}

/// A `napatt` with one attestation for `outpoint` whose signature signs
/// another message: well formed, on a real coin, and false.
fn forged_page(outpoint: OutPoint, anchor_height: u32, anchor: BlockHash) -> Vec<u8> {
    let other = node::nap::message::render(&outpoint, "forged", "no", anchor_height, &anchor);
    let sig = sign(&other);
    let witness: Witness = encode::deserialize(
        &base64::engine::general_purpose::STANDARD.decode(sig.trim_start_matches("smp")).unwrap(),
    )
    .unwrap();
    let att = node::nap::Attestation::new(
        outpoint,
        "forged".into(),
        "yes".into(),
        anchor_height,
        anchor,
        node::nap::NapSignature::Simple(witness),
    )
    .unwrap();
    node::nap::p2p::NapAtt { attestations: vec![att], next_cursor: None }.to_bytes()
}

/// A P2P peer in the test process that announces itself as a NAP publisher
/// in an `addr` message, then serves `page` to whoever pulls from it on its
/// listening port, recording the commands each connection there receives.
///
/// It advertises `NODE_NAP` without `NODE_NETWORK`: an ordinary outbound
/// connection drops it in the handshake for lacking the services it wants,
/// while a pull connection, which needs no blocks, goes on.
struct FakePublisher {
    listener_port: u16,
    /// The commands each accepted connection received, in order.
    connections: std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>>,
    /// A connection that was asked for the pull has closed.
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

fn services() -> ServiceFlags {
    ServiceFlags::WITNESS | ServiceFlags::from(NODE_NAP)
}

fn send(stream: &mut TcpStream, msg: NetworkMessage) {
    let raw = RawNetworkMessage::new(Magic::REGTEST, msg);
    let _ = stream.write_all(&encode::serialize(&raw));
}

/// The next message, or `None` once the peer hangs up.
fn recv(stream: &mut TcpStream) -> Option<NetworkMessage> {
    let mut header = [0u8; 24];
    stream.read_exact(&mut header).ok()?;
    let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).ok()?;
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(&payload);
    let raw: RawNetworkMessage = encode::deserialize(&bytes).ok()?;
    Some(raw.payload().clone())
}

/// A message's command, an unknown one's included.
fn command(msg: &NetworkMessage) -> String {
    match msg {
        NetworkMessage::Unknown { command, .. } => command.to_string(),
        other => other.cmd().to_string(),
    }
}

fn version(services: ServiceFlags) -> NetworkMessage {
    let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    NetworkMessage::Version(VersionMessage {
        version: 70016,
        services,
        timestamp: now.as_secs() as i64,
        receiver: P2pAddress::new(&zero, ServiceFlags::NONE),
        sender: P2pAddress::new(&zero, services),
        nonce: now.as_nanos() as u64 ^ 0x5eed_5eed,
        user_agent: "/fake-nap-publisher/".into(),
        start_height: 0,
        relay: false,
    })
}

impl FakePublisher {
    fn start(page: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listener_port = listener.local_addr().unwrap().port();
        let connections = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<String>>::new()));
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (log, done) = (connections.clone(), closed.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (log, done, page) = (log.clone(), done.clone(), page.clone());
                std::thread::spawn(move || {
                    stream.set_read_timeout(Some(Duration::from_secs(300))).unwrap();
                    let n = {
                        let mut l = log.lock().unwrap();
                        l.push(Vec::new());
                        l.len() - 1
                    };
                    let mut pulled = false;
                    let mut answered = false;
                    while let Some(msg) = recv(&mut stream) {
                        log.lock().unwrap()[n].push(command(&msg));
                        match msg {
                            NetworkMessage::Version(_) if !answered => {
                                answered = true;
                                send(&mut stream, version(services()));
                                send(&mut stream, NetworkMessage::Verack);
                            }
                            NetworkMessage::Ping(x) => send(&mut stream, NetworkMessage::Pong(x)),
                            NetworkMessage::Unknown { command, .. } if command.as_ref() == "getnapatt" => {
                                pulled = true;
                                send(
                                    &mut stream,
                                    NetworkMessage::Unknown {
                                        command: "napatt".to_string().try_into().unwrap(),
                                        payload: page.clone(),
                                    },
                                );
                            }
                            _ => {}
                        }
                    }
                    if pulled {
                        done.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });
        FakePublisher { listener_port, connections, closed }
    }

    /// Connect to the node at `port` as an ordinary peer that does not
    /// publish, and announce the listening port as a NAP publisher's address.
    fn announce_to(&self, port: u16) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        send(&mut stream, version(ServiceFlags::NETWORK | ServiceFlags::WITNESS));
        let (mut version_in, mut verack_in) = (false, false);
        while !(version_in && verack_in) {
            match recv(&mut stream).expect("handshake") {
                NetworkMessage::Version(_) => {
                    version_in = true;
                    send(&mut stream, NetworkMessage::Verack);
                }
                NetworkMessage::Verack => verack_in = true,
                _ => {}
            }
        }
        let me: SocketAddr = format!("127.0.0.1:{}", self.listener_port).parse().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        send(&mut stream, NetworkMessage::Addr(vec![(now, P2pAddress::new(&me, services()))]));
        // Stay up, answering pings, so the address is taken in.
        std::thread::spawn(move || {
            while let Some(msg) = recv(&mut stream) {
                if let NetworkMessage::Ping(n) = msg {
                    send(&mut stream, NetworkMessage::Pong(n));
                }
            }
        });
    }

    /// The commands the connection asked for the pull received.
    fn pull_connection(&self) -> Option<Vec<String>> {
        self.connections.lock().unwrap().iter().find(|c| c.iter().any(|m| m == "getnapatt")).cloned()
    }

    fn closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Coins for the budget measurement: one transaction spending the coinbase
/// at `height` into `count` P2WPKH outputs for the wallet.
fn fan_out(node: &TestNode, height: u64, count: usize) -> String {
    use bitcoin::{Sequence, Transaction, TxIn, TxOut, absolute::LockTime};
    let w = wallet();
    let txid: bitcoin::Txid = coinbase_txid_at(node, height).parse().unwrap();
    // Regtest's subsidy before the first halving, less a fee of about
    // 2.5 sat/vB on a transaction of this many outputs.
    let total: u64 = 50 * 100_000_000 - 100 * count as u64;
    let each = total / count as u64;
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: (0..count)
            .map(|_| TxOut { value: Amount::from_sat(each), script_pubkey: w.address.script_pubkey() })
            .collect(),
    };
    let sighash = SighashCache::new(&tx)
        .p2wpkh_signature_hash(0, &w.address.script_pubkey(), Amount::from_sat(50 * 100_000_000), EcdsaSighashType::All)
        .unwrap();
    let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &w.sk);
    let sig = bitcoin::ecdsa::Signature { signature: sig, sighash_type: EcdsaSighashType::All };
    let pk = bitcoin::CompressedPublicKey::from_slice(&w.pk.to_bytes()).unwrap();
    tx.input[0].witness = Witness::p2wpkh(&sig, &pk.0);
    node.rpc_ok("sendrawtransaction", vec![json!(hex::encode(encode::serialize(&tx)))]);
    tx.compute_txid().to_string()
}

/// N9 budget measurement, not a check: a publisher serving
/// `NAP_BUDGET_COINS` attestations (default 12,000, more than two pulls'
/// worth of the per-pull verification budget) and an aggregator pulling
/// them from scratch under the default budgets. It prints how long the
/// publisher took to take them, the set's growth over time with the pull
/// counters, the bytes the pull moved, and the cost of a report, an export
/// and a replay. Run with
/// `cargo test -p satd --release --test nap_aggregator nap_budget -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement; run by hand"]
fn nap_budget_measurement() {
    const PER_TX: usize = 2_500;
    let n: usize = std::env::var("NAP_BUDGET_COINS").ok().and_then(|v| v.parse().ok()).unwrap_or(12_000);
    let txs = n.div_ceil(PER_TX);
    assert!(txs < 40, "the fan-out spends coinbases from below the first halving");
    let mut a = TestNode::start(&["--nap=1", "--v2transport=0"]);
    let w = wallet();
    a.mine_blocks(txs as u64, &w.address.to_string());
    a.mine_blocks(100, BURN);
    let mut outpoints = Vec::with_capacity(n);
    for t in 0..txs {
        let count = PER_TX.min(n - t * PER_TX);
        let txid = fan_out(&a, t as u64 + 1, count);
        outpoints.extend((0..count).map(|v| format!("{txid}:{v}")));
    }
    // The coins confirm and are six blocks old at an anchor six deep, with
    // a block to spare.
    a.mine_blocks(14, BURN);

    let start = std::time::Instant::now();
    for (i, op) in outpoints.iter().enumerate() {
        attest(&a, op, "budget", if i % 3 == 0 { "no" } else { "yes" });
    }
    let submit = start.elapsed();
    println!("publisher: {n} attestations created and submitted in {submit:.1?} ({:.0}/s)", n as f64 / submit.as_secs_f64());

    let c = TestNode::start(&["--napaggregator=1", "--v2transport=0"]);
    c.rpc_ok("addnode", vec![json!(p2p(&a)), json!("onetry")]);
    synced(&[&a, &c]);
    let start = std::time::Instant::now();
    let mut last = None;
    println!("{:>8} {:>8} {:>9} {:>6} {:>6}", "secs", "held", "deferred", "pulls", "pages");
    loop {
        let agg = aggregate(&c);
        let row = (
            agg["held"].as_u64().unwrap(),
            agg["deferred"].as_u64().unwrap(),
            agg["pulls"]["completed"].as_u64().unwrap(),
            agg["pulls"]["pages"].as_u64().unwrap(),
        );
        if last != Some(row) {
            println!("{:>8.1} {:>8} {:>9} {:>6} {:>6}", start.elapsed().as_secs_f64(), row.0, row.1, row.2, row.3);
            last = Some(row);
        }
        if row.0 as usize >= n || start.elapsed() > Duration::from_secs(3 * 60 * 60) {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let fill = start.elapsed();
    println!("aggregator: {} of {n} held after {fill:.1?}", last.unwrap().0);
    let peer = |node: &TestNode, other: &TestNode| -> Value {
        let peers = node.rpc_ok("getpeerinfo", vec![]);
        let port = other.p2p_port.unwrap().to_string();
        peers
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["addr"].as_str().unwrap().ends_with(&port) || p["addrbind"].as_str().is_some_and(|b| b.ends_with(&port)))
            .cloned()
            .unwrap_or(Value::Null)
    };
    println!("aggregator received per message: {}", peer(&c, &a)["bytesrecv_per_msg"]);
    let served = a.rpc_ok("getpeerinfo", vec![]);
    for p in served.as_array().unwrap() {
        println!("publisher sent to {} per message: {}", p["addr"], p["bytessent_per_msg"]);
    }

    let start = std::time::Instant::now();
    let report = c.rpc_ok("getnapreport", vec![]);
    let first = start.elapsed();
    let start = std::time::Instant::now();
    c.rpc_ok("getnapreport", vec![]);
    let cached = start.elapsed();
    println!(
        "report: {} counting, {} bytes of JSON, first {first:.1?}, cached {cached:.1?}",
        report["counting"],
        serde_json::to_string(&report).unwrap().len()
    );
    let start = std::time::Instant::now();
    let export = c.rpc_ok("exportnapsnapshot", vec![json!("budget.dat")]);
    let exported = start.elapsed();
    let path = export["path"].as_str().unwrap().to_owned();
    let size = std::fs::metadata(&path).unwrap().len();
    println!("export: {size} bytes ({:.0} per attestation) in {exported:.1?}", size as f64 / n as f64);
    let start = std::time::Instant::now();
    let replayed = a.rpc_ok("replaynapsnapshot", vec![json!(path)]);
    println!("replay on the publisher: {:.1?}, same report: {}", start.elapsed(), replayed == report);
    a.stop();
}
