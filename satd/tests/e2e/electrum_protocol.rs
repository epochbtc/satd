//! Electrum protocol 1.6 against a real node, through `electrum-client`,
//! which offers 1.4 to 1.6 and so negotiates 1.6.

use bitcoin::hashes::Hash as _;
use electrum_client::ElectrumApi;
use serde_json::json;

use super::electrum_status::{send, sign_p2wpkh_spend};
use super::{E2eNode, RawElectrum, electrum_e2e_args, electrum_url_for};
use crate::common::{DeterministicWallet, build_signed_p2wpkh_spend_of_coinbase, e2e_test_timeout};

const COINBASE_SAT: u64 = 50 * 100_000_000;

fn mine_to(e2e: &E2eNode, n: u64, address: &bitcoin::Address) {
    e2e.node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![json!(n), json!(address.to_string())],
        )
        .expect("generatetoaddress");
}

fn in_mempool(e2e: &E2eNode, txid: &str) -> bool {
    let pool = e2e.node.rpc_call_with_params("getrawmempool", vec![]).expect("getrawmempool");
    pool["result"].as_array().is_some_and(|a| a.iter().any(|t| t == txid))
}

/// A zero-fee parent and a child paying for both: the parent alone is below
/// the minimum feerate and refused, by the node and by Electrum's single
/// broadcast; as a package (`submitpackage`) both are admitted. Before 1.6
/// satd submitted package members one by one, which refused the parent.
/// `verbose=true` answers with `submitpackage`'s own JSON.
#[test]
fn test_e2e_electrum_broadcast_package_carries_a_parent_below_the_floor() {
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum connect");
    let wallet = DeterministicWallet::from_secret([0x22u8; 32]);
    let spk = wallet.address.script_pubkey();
    mine_to(&e2e, 101, &wallet.address);

    let package = |height: u64| {
        let (parent, parent_txid) =
            build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &wallet, height, spk.clone(), 0);
        let parent_txid: bitcoin::Txid = parent_txid.parse().expect("txid");
        let child = sign_p2wpkh_spend(
            &wallet,
            bitcoin::OutPoint { txid: parent_txid, vout: 0 },
            COINBASE_SAT,
            spk.clone(),
            50_000,
        );
        (parent, parent_txid.to_string(), child)
    };

    // Non-verbose, through the client.
    let (parent, parent_txid, child) = package(1);
    let alone = e2e
        .node
        .rpc_call_with_params("sendrawtransaction", vec![json!(parent)])
        .expect("sendrawtransaction");
    assert!(alone["error"].is_object(), "a zero-fee parent alone is refused: {alone}");
    let parent_bytes = hex::decode(&parent).unwrap();
    assert!(
        client.transaction_broadcast_raw(&parent_bytes).is_err(),
        "Electrum's single broadcast refuses it too"
    );
    let res = client
        .transaction_broadcast_package_raw(&[parent_bytes, hex::decode(&child).unwrap()])
        .expect("broadcast_package");
    assert!(res.success, "the package is accepted: {:?}", res.errors);
    assert!(res.errors.is_empty(), "{:?}", res.errors);
    assert!(in_mempool(&e2e, &parent_txid), "the parent is in the mempool");

    // Verbose, raw: the `submitpackage` answer.
    let (parent, parent_txid, child) = package(2);
    let mut cli = RawElectrum::connect(e2e.electrum_port.expect("electrum port"));
    cli.send(r#"{"id":1,"method":"server.version","params":["test",["1.4","1.6"]]}"#);
    assert_eq!(cli.recv()["result"][1], "1.6");
    cli.send(
        &json!({"id": 2, "method": "blockchain.transaction.broadcast_package",
                "params": [[parent, child], true]})
        .to_string(),
    );
    let verbose = cli.recv();
    let result = &verbose["result"];
    assert_eq!(result["package_msg"], "success", "{verbose}");
    assert_eq!(result["tx-results"].as_object().map(|m| m.len()), Some(2), "{verbose}");
    assert_eq!(result["replaced-transactions"], json!([]), "{verbose}");
    assert!(in_mempool(&e2e, &parent_txid));

    e2e.node.stop();
}

/// `get_mempool` lists the mempool in the order 1.6 mandates, `(-height,
/// tx_hash)`: height 0 before -1, then the txid as displayed. The status and
/// `get_history` order are checked in `electrum_status`.
#[test]
fn test_e2e_electrum_get_mempool_is_in_canonical_order() {
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let script = wallet.address.script_pubkey();
    mine_to(&e2e, 101, &wallet.address);

    let fee = 1_000u64;
    let (raw_a, _) = build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &wallet, 1, script.clone(), fee);
    let txid_a = send(&e2e, &raw_a);
    let raw_b = sign_p2wpkh_spend(
        &wallet,
        bitcoin::OutPoint { txid: txid_a, vout: 0 },
        COINBASE_SAT - fee,
        script.clone(),
        fee,
    );
    let txid_b = send(&e2e, &raw_b);
    let (raw_c, _) = build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &wallet, 2, script.clone(), fee);
    let txid_c = send(&e2e, &raw_c);

    let mut sh = bitcoin::hashes::sha256::Hash::hash(script.as_bytes()).to_byte_array();
    sh.reverse();
    let mut cli = RawElectrum::connect(e2e.electrum_port.expect("electrum port"));
    cli.send(r#"{"id":1,"method":"server.version","params":["test",["1.4","1.6"]]}"#);
    assert_eq!(cli.recv()["result"][1], "1.6");
    let deadline = std::time::Instant::now() + e2e_test_timeout(20);
    let rows = loop {
        cli.send(
            &json!({"id": 2, "method": "blockchain.scripthash.get_mempool",
                    "params": [hex::encode(sh)]})
            .to_string(),
        );
        let resp = cli.recv();
        let rows = resp["result"].as_array().cloned().unwrap_or_default();
        if rows.len() == 3 {
            break rows;
        }
        assert!(std::time::Instant::now() < deadline, "mempool never held all three: {resp}");
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    let got: Vec<(i64, String)> = rows
        .iter()
        .map(|r| (r["height"].as_i64().unwrap(), r["tx_hash"].as_str().unwrap().to_string()))
        .collect();
    let mut zero = [txid_a.to_string(), txid_c.to_string()];
    zero.sort();
    assert_eq!(
        got,
        vec![(0, zero[0].clone()), (0, zero[1].clone()), (-1, txid_b.to_string())],
        "(-height, tx_hash) order"
    );

    e2e.node.stop();
}
