//! Electrum chain-tip stamps: the answers of the chain-reading methods name
//! the block they were read at in `chain_tip` / `chain_tip_height`, on every
//! connection, as rbitcoin's do. `server.version` also accepts rbitcoin's
//! `1.4.2-asof`.

use bitcoin::hashes::{Hash as _, sha256};
use serde_json::json;

use super::{E2eNode, RawElectrum, electrum_e2e_args};
use crate::common::DeterministicWallet;

fn mine(e2e: &E2eNode, n: u64, wallet: &DeterministicWallet) {
    e2e.node.rpc_ok(
        "generatetoaddress",
        vec![json!(n), json!(wallet.address.to_string())],
    );
}

fn best(e2e: &E2eNode) -> String {
    e2e.node
        .rpc_ok("getbestblockhash", vec![])
        .as_str()
        .expect("hash string")
        .to_string()
}

/// The Electrum scripthash of `wallet`'s script: sha256, byte-reversed hex.
fn scripthash(wallet: &DeterministicWallet) -> String {
    let mut h = sha256::Hash::hash(wallet.address.script_pubkey().as_bytes()).to_byte_array();
    h.reverse();
    hex::encode(h)
}

fn call(cli: &mut RawElectrum, id: u64, method: &str, params: serde_json::Value) -> serde_json::Value {
    cli.send(&json!({"id": id, "method": method, "params": params}).to_string());
    let v = cli.recv();
    assert_eq!(v["id"], id, "{v}");
    v
}

#[test]
fn test_e2e_electrum_answers_name_the_tip_they_were_read_at() {
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let w = DeterministicWallet::from_secret([0x41; 32]);
    mine(&e2e, 3, &w);
    let tip = best(&e2e);
    let sh = scripthash(&w);
    let port = e2e.electrum_port.expect("electrum port");

    // A standard 1.4 client gets the stamps too.
    let mut plain = RawElectrum::connect(port);
    let v = call(&mut plain, 1, "server.version", json!(["test", "1.4"]));
    assert_eq!(v["result"][1], "1.4");
    let v = call(&mut plain, 2, "blockchain.scripthash.get_history", json!([sh]));
    assert_eq!(v["result"].as_array().map(Vec::len), Some(3), "{v}");
    assert_eq!(v["chain_tip"], tip);
    let v = call(&mut plain, 3, "server.features", json!([]));
    assert_eq!(v["result"]["chain_tip"], true);
    assert!(v.get("chain_tip").is_none(), "server.features is not stamped: {v}");

    // rbitcoin's dialect negotiates, and every stamped method names the tip.
    let mut cli = RawElectrum::connect(port);
    let v = call(&mut cli, 1, "server.version", json!(["test", "1.4.2-asof"]));
    assert_eq!(v["result"][1], "1.4.2-asof");
    for (id, method) in [
        (2, "blockchain.scripthash.get_history"),
        (3, "blockchain.scripthash.get_balance"),
        (4, "blockchain.scripthash.listunspent"),
    ] {
        let v = call(&mut cli, id, method, json!([sh]));
        assert!(v.get("error").is_none(), "{method}: {v}");
        assert_eq!(v["chain_tip"], tip, "{method}");
        assert_eq!(v["chain_tip_height"], 3, "{method}");
    }
    let coinbase = call(&mut cli, 5, "blockchain.transaction.id_from_pos", json!([3, 0]));
    assert_eq!(coinbase["chain_tip"], tip);
    let txid = coinbase["result"].as_str().expect("txid").to_string();
    let v = call(&mut cli, 6, "blockchain.transaction.get_merkle", json!([txid]));
    assert_eq!(v["result"]["block_height"], 3);
    assert_eq!(v["chain_tip_height"], 3);
    let v = call(&mut cli, 7, "blockchain.transaction.get", json!([txid, true]));
    assert_eq!(v["result"]["confirmations"], 1);
    assert_eq!(v["chain_tip"], tip);

    // The next block moves the stamp with it.
    mine(&e2e, 1, &w);
    let v = call(&mut cli, 8, "blockchain.scripthash.get_balance", json!([sh]));
    assert_eq!(v["chain_tip"], best(&e2e));
    assert_eq!(v["chain_tip_height"], 4);
    e2e.node.stop();
}
