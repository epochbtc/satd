//! `-bytespersigop` reaches the mempool: `testmempoolaccept` reports Core's
//! sigop-adjusted `vsize` for a spend dense in signature checks.

mod common;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use common::TestNode;
use serde_json::json;

/// `OP_0 OP_IF OP_1 OP_CHECKMULTISIG×198 OP_ENDIF OP_1`: spendable with no
/// signature, and 3941 sigops by Core's count, so 19705 vbytes at the
/// default 20 bytes per sigop.
fn heavy_script() -> ScriptBuf {
    let mut s = vec![0x00, 0x63, 0x51];
    s.extend(std::iter::repeat_n(0xae, 198));
    s.extend([0x68, 0x51]);
    ScriptBuf::from_bytes(s)
}

/// A spend of a mature coinbase paid to the heavy script, and its vsize by
/// weight alone.
fn heavy_spend(node: &TestNode) -> (String, u64) {
    let script = heavy_script();
    let address = Address::p2wsh(&script, Network::Regtest).to_string();
    let hashes = node.rpc_ok("generatetoaddress", vec![json!(1), json!(address)]);
    let block = node.rpc_ok("getblock", vec![hashes[0].clone(), json!(2)]);
    let coinbase = &block["tx"][0];
    // Mature it.
    node.rpc_ok("generatetoaddress", vec![json!(100), json!("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")]);

    let value = Amount::from_btc(coinbase["vout"][0]["value"].as_f64().unwrap()).unwrap();
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(coinbase["txid"].as_str().unwrap().parse().unwrap(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[script.as_bytes()]),
        }],
        output: vec![TxOut {
            value: value - Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes([&[0x00, 0x14][..], &[7; 20]].concat()),
        }],
    };
    (serialize_hex(&tx), tx.weight().to_wu().div_ceil(4))
}

fn accepted_vsize(node: &TestNode, hex: &str) -> u64 {
    let r = node.rpc_ok("testmempoolaccept", vec![json!([hex])]);
    assert_eq!(r[0]["allowed"], json!(true), "{r}");
    r[0]["vsize"].as_u64().unwrap()
}

#[test]
fn the_vsize_is_sigop_adjusted_by_the_configured_bytes_per_sigop() {
    let mut node = TestNode::start(&[]);
    let (hex, by_weight) = heavy_spend(&node);
    assert_eq!(accepted_vsize(&node, &hex), 19_705, "3941 sigops at 20 bytes each");
    assert!(by_weight < 1_000);
    node.stop();

    let mut node = TestNode::start(&["--bytespersigop=0"]);
    let (hex, by_weight) = heavy_spend(&node);
    assert_eq!(accepted_vsize(&node, &hex), by_weight, "no sigop charge");
    node.stop();
}

/// Core v32.1 reports both sizes beside `vsize`: `vsize_adjusted`, the
/// sigop-adjusted size `vsize` already is, and `vsize_bip141`, the size by
/// weight alone (`entryToJSON`, `testmempoolaccept`, `submitpackage` and
/// `getrawtransaction` in src/rpc/{mempool,rawtransaction}.cpp).
#[test]
fn every_mempool_rpc_reports_vsize_bip141_and_vsize_adjusted() {
    let mut node = TestNode::start(&[]);
    let (hex, by_weight) = heavy_spend(&node);
    assert!(by_weight < 1_000);
    let sizes = |v: &serde_json::Value| (v["vsize"].clone(), v["vsize_adjusted"].clone(), v["vsize_bip141"].clone());
    let want = (json!(19_705), json!(19_705), json!(by_weight));

    let r = node.rpc_ok("testmempoolaccept", vec![json!([hex])]);
    assert_eq!(sizes(&r[0]), want, "testmempoolaccept: {r}");

    let r = node.rpc_ok("submitpackage", vec![json!([hex])]);
    let result = r["tx-results"].as_object().unwrap().values().next().unwrap().clone();
    assert_eq!(sizes(&result), want, "submitpackage: {r}");
    let txid = result["txid"].clone();

    let entry = node.rpc_ok("getmempoolentry", vec![txid.clone()]);
    assert_eq!(sizes(&entry), want, "getmempoolentry: {entry}");
    let pool = node.rpc_ok("getrawmempool", vec![json!(true)]);
    assert_eq!(sizes(&pool[txid.as_str().unwrap()]), want, "getrawmempool: {pool}");

    // `getrawtransaction` adds only `vsize_adjusted`, and only while the
    // transaction is in the mempool; its `vsize` is the BIP 141 one.
    for verbosity in [1, 2] {
        let tx = node.rpc_ok("getrawtransaction", vec![txid.clone(), json!(verbosity)]);
        assert_eq!(sizes(&tx), (json!(by_weight), json!(19_705), serde_json::Value::Null), "{tx}");
    }
    let hashes = node.rpc_ok("generatetoaddress", vec![json!(1), json!("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")]);
    let tx = node.rpc_ok("getrawtransaction", vec![txid, json!(1), hashes[0].clone()]);
    assert!(tx.get("vsize_adjusted").is_none(), "confirmed: {tx}");
    node.stop();
}
