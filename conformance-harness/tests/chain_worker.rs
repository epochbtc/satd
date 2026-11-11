//! The chain operations through the harness binary, as the runner drives it.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

const REGTEST_GENESIS: &str = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

/// Send `requests` in order and return the responses.
fn run(requests: &[Value]) -> Vec<Value> {
    run_in(requests, &std::env::temp_dir())
}

/// [`run`], with the harness's temporary directories under `tmp`.
fn run_in(requests: &[Value], tmp: &std::path::Path) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_satd-conformance-harness"))
        .env("TMPDIR", tmp)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start the harness");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut out = Vec::new();
    for (id, req) in requests.iter().enumerate() {
        let mut req = req.clone();
        req["id"] = json!(id);
        writeln!(stdin, "{req}").unwrap();
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        out.push(serde_json::from_str(&line).unwrap());
    }
    drop(stdin);
    assert!(child.wait().unwrap().success());
    out
}

/// Every reset starts a fresh chain, and two resets in one run can carry
/// different activation heights: the overrides are set once per process, so
/// the second would be refused if both chains shared one.
#[test]
fn each_reset_gets_a_fresh_chain_with_its_own_options() {
    let reset = |segwit: u32| {
        json!({"op": "chain_reset", "network": "regtest", "options": {"testactivationheight": {"segwit": segwit}}})
    };
    let out = run(&[
        json!({"op": "chain_tip"}),
        reset(120),
        json!({"op": "chain_tip"}),
        json!({"op": "utxo_hash"}),
        reset(432),
        json!({"op": "chain_tips"}),
    ]);
    assert_eq!(out[0]["ok"], json!(false), "no chain before the first reset");
    assert_eq!(out[1]["genesis"], json!(REGTEST_GENESIS), "{}", out[1]);
    assert_eq!(out[2]["tip"], json!(REGTEST_GENESIS));
    assert_eq!(out[2]["height"], json!(0));
    assert_eq!(out[3]["txouts"], json!(0), "the genesis coinbase is not a coin");
    assert_eq!(out[4]["ok"], json!(true), "the second reset is refused: {}", out[4]);
    assert_eq!(out[5]["tips"], json!([{"hash": REGTEST_GENESIS, "height": 0, "status": "active"}]));
}

/// An option satd does not have is reported as unsupported, not ignored.
/// `-test=bip94`, which satd has, starts a regtest chain.
#[test]
fn an_option_satd_lacks_is_unsupported() {
    let out = run(&[json!({"op": "chain_reset", "network": "regtest", "options": {"test": ["addrman"]}})]);
    assert_eq!(out[0]["ok"], json!(false));
    assert_eq!(out[0]["error"], json!("unsupported_op"), "{}", out[0]);
    let out = run(&[json!({"op": "chain_reset", "network": "regtest", "options": {"test": ["bip94"]}})]);
    assert_eq!(out[0]["ok"], json!(true), "{}", out[0]);
}

/// A worker removes its data directory when the next reset replaces it and
/// when the run ends, rather than being killed with it in place.
#[test]
fn workers_remove_their_data_directories() {
    let tmp = tempfile::tempdir().unwrap();
    let reset = json!({"op": "chain_reset", "network": "regtest"});
    let out = run_in(&[reset.clone(), reset], tmp.path());
    assert!(out.iter().all(|r| r["ok"] == json!(true)), "{out:?}");
    let left: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();
    assert!(left.is_empty(), "left behind: {left:?}");
}

/// `index` is the refused header's position in the request. A header the
/// node already knows is skipped without being counted by `accept_headers`,
/// so it must still count here.
#[test]
fn the_refused_header_index_counts_known_headers() {
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
    let mut bad = Header {
        version: Version::from_consensus(4),
        prev_blockhash: genesis.block_hash(),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: genesis.time + 1,
        bits: genesis.bits,
        nonce: 0,
    };
    // A nonce whose hash misses the target: `high-hash`.
    while bad.target().is_met_by(bad.block_hash()) {
        bad.nonce += 1;
    }
    let hex = |h: &Header| hex::encode(bitcoin::consensus::serialize(h));
    let out = run(&[
        json!({"op": "chain_reset", "network": "regtest"}),
        json!({"op": "chain_process_headers", "headers": [hex(&genesis), hex(&bad)], "now": genesis.time + 10}),
    ]);
    assert_eq!(out[1]["result"], json!("invalid"), "{}", out[1]);
    assert_eq!(out[1]["index"], json!(1), "{}", out[1]);
}
