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
