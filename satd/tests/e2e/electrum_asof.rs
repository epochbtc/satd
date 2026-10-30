//! Electrum chain-tip stamps: the answers of the chain-reading methods name
//! the block they were read at in `chain_tip` / `chain_tip_height`, on every
//! connection, as rbitcoin's do. `server.version` also accepts rbitcoin's
//! `1.4.2-asof`. A trailing `asof:<blockhash>` argument answers as of a
//! block still on the best chain.

use bitcoin::hashes::{Hash as _, sha256};
use serde_json::json;

use super::{E2eNode, RawElectrum, electrum_e2e_args};
use crate::common::{self, DeterministicWallet, build_signed_p2wpkh_spend_of_coinbase};

fn mine(e2e: &E2eNode, n: u64, wallet: &DeterministicWallet) {
    e2e.node.rpc_ok(
        "generatetoaddress",
        vec![json!(n), json!(wallet.address.to_string())],
    );
}

fn hash_at(e2e: &E2eNode, height: u64) -> String {
    e2e.node
        .rpc_ok("getblockhash", vec![json!(height)])
        .as_str()
        .expect("hash string")
        .to_string()
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
    scripthash_of(&wallet.address.script_pubkey())
}

fn scripthash_of(script: &bitcoin::Script) -> String {
    let mut h = sha256::Hash::hash(script.as_bytes()).to_byte_array();
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

/// The chain: `w` mines 102 blocks, so its coinbase at height 1 is mature;
/// block 103 holds `spend`, which pays that coinbase to `dest`. As of block
/// 102 the coinbase is unspent and `dest` has no history. The client never
/// negotiates `1.4.2-asof`: sending `asof:` is the opt-in.
#[test]
fn test_e2e_electrum_trailing_asof_answers_as_of_an_ancestor() {
    use std::str::FromStr;

    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let w = DeterministicWallet::from_secret([0x42; 32]);
    let dest = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("address")
        .assume_checked();
    mine(&e2e, 102, &w);
    let h102 = hash_at(&e2e, 102);
    let (raw, spend) =
        build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &w, 1, dest.script_pubkey(), 1_000);
    let mut cli = RawElectrum::connect(e2e.electrum_port.expect("electrum port"));
    let v = call(&mut cli, 1, "server.version", json!(["test", "1.4"]));
    assert_eq!(v["result"][1], "1.4");
    let v = call(&mut cli, 2, "blockchain.transaction.broadcast", json!([raw]));
    assert_eq!(v["result"], spend.as_str(), "{v}");
    mine(&e2e, 1, &w);
    let coinbase1 = common::coinbase_txid_at(&e2e.node, 1);
    let tag = format!("asof:{h102}");
    let (sh_w, sh_dest) = (scripthash(&w), scripthash_of(&dest.script_pubkey()));

    // `w`'s UTXOs: the height-1 coinbase as of 102, gone live.
    let utxos = |v: &serde_json::Value| -> Vec<String> {
        v["result"]
            .as_array()
            .unwrap_or_else(|| panic!("{v}"))
            .iter()
            .map(|u| u["tx_hash"].as_str().unwrap().to_string())
            .collect()
    };
    let live = call(&mut cli, 3, "blockchain.scripthash.listunspent", json!([sh_w]));
    let then = call(&mut cli, 4, "blockchain.scripthash.listunspent", json!([sh_w, tag]));
    assert!(!utxos(&live).contains(&coinbase1));
    assert!(utxos(&then).contains(&coinbase1));
    assert_eq!(utxos(&then).len(), 102, "one coinbase per block 1..=102");
    assert_eq!(then["chain_tip"], h102);
    assert_eq!(then["chain_tip_height"], 102);

    // `dest`: one transaction live, none as of 102; no balance then.
    let v = call(&mut cli, 5, "blockchain.scripthash.get_history", json!([sh_dest]));
    assert_eq!(v["result"].as_array().map(Vec::len), Some(1), "{v}");
    let v = call(&mut cli, 6, "blockchain.scripthash.get_history", json!([sh_dest, tag]));
    assert_eq!(v["result"], json!([]), "{v}");
    let v = call(&mut cli, 7, "blockchain.scripthash.get_balance", json!([sh_dest, tag]));
    assert_eq!(v["result"], json!({"confirmed": 0, "unconfirmed": 0}), "{v}");

    // The spend: confirmed at 103, not found as of 102.
    let v = call(&mut cli, 8, "blockchain.transaction.get", json!([spend, true]));
    assert_eq!(v["result"]["confirmations"], 1, "{v}");
    let v = call(&mut cli, 9, "blockchain.transaction.get", json!([spend, true, tag]));
    assert!(v.get("error").is_some(), "{v}");

    // Not on the best chain, or on a method that does not take it: an error.
    let unknown = format!("asof:{}", "00".repeat(32));
    let v = call(&mut cli, 10, "blockchain.scripthash.get_balance", json!([sh_w, unknown]));
    assert_eq!(v["error"]["message"], "asof not on chain", "{v}");
    let v = call(&mut cli, 11, "blockchain.scripthash.get_mempool", json!([sh_w, tag]));
    assert!(v.get("error").is_some(), "{v}");
    // A transaction only in the mempool: found live, not as of any block.
    let (raw, pending) =
        build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &w, 2, dest.script_pubkey(), 1_000);
    let v = call(&mut cli, 13, "blockchain.transaction.broadcast", json!([raw]));
    assert_eq!(v["result"], pending.as_str(), "{v}");
    let v = call(&mut cli, 14, "blockchain.transaction.get", json!([pending]));
    assert!(v["result"].is_string(), "{v}");
    let now = format!("asof:{}", best(&e2e));
    let v = call(&mut cli, 15, "blockchain.transaction.get", json!([pending, now]));
    assert!(v.get("error").is_some(), "the mempool is not part of an asof answer: {v}");

    let v = call(&mut cli, 12, "server.features", json!([]));
    assert_eq!(v["result"]["asof"], true);
    assert_eq!(v["result"]["asof_protocol"], "1.4.2-asof");
    e2e.node.stop();
}
