//! The chain operations through the harness binary, as the runner drives it.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

const REGTEST_GENESIS: &str = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

/// Send `requests` in order and return the responses.
fn run(requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_satd-conformance-harness"))
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
#[test]
fn an_option_satd_lacks_is_unsupported() {
    let out = run(&[json!({"op": "chain_reset", "network": "regtest", "options": {"test": ["bip94"]}})]);
    assert_eq!(out[0]["ok"], json!(false));
    assert_eq!(out[0]["error"], json!("unsupported_op"), "{}", out[0]);
}
