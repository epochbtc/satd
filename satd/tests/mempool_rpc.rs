//! Mempool RPCs against a live regtest node, checked against Bitcoin Core:
//! `sendrawtransaction`'s limits and its "already confirmed" answer
//! (src/rpc/mempool.cpp, src/node/transaction.cpp), `gettxout` with
//! `include_mempool` (src/rpc/blockchain.cpp), and the `getmempoolinfo` /
//! `getmempoolentry` fields (`MempoolInfoToJSON`, `entryToJSON`).

mod common;

use common::{
    build_signed_p2tr_keypath_spend, build_signed_p2wpkh_spend_from_block1_coinbase,
    block1_coinbase_txid, p2tr_keypath_output, poll_until, test_timeout, DeterministicWallet,
    TestNode,
};
use serde_json::{json, Value};
use std::str::FromStr;

/// The `error` of a call the node is expected to refuse, as `(code, message)`.
fn refused(node: &TestNode, method: &str, params: Vec<Value>) -> (i64, String) {
    let resp = node.rpc_call_with_params(method, params.clone()).expect("node reachable");
    let err = &resp["error"];
    assert!(!err.is_null(), "{method}{params:?} must be refused; got {resp}");
    (
        err["code"].as_i64().expect("error code"),
        err["message"].as_str().expect("error message").to_string(),
    )
}

/// A node with 101 blocks mined to `wallet`, so block 1's coinbase is
/// spendable, and with its mempool load finished.
fn funded_node(extra_args: &[&str], wallet: &DeterministicWallet) -> TestNode {
    let mut node = TestNode::start(extra_args);
    node.mine_blocks(101, &wallet.address.to_string());
    // Core's functional tests wait on the same flag before using the pool.
    poll_until(
        || node.rpc_ok("getmempoolinfo", vec![])["loaded"] == json!(true),
        test_timeout(30),
        "getmempoolinfo.loaded never became true",
    );
    node
}

/// Spend block 1's coinbase to a fresh taproot key, paying `fee`. Returns
/// `(raw hex, txid, the key, the output script)`.
fn spend_coinbase_to_taproot(
    node: &TestNode,
    wallet: &DeterministicWallet,
    fee: u64,
) -> (String, String, bitcoin::secp256k1::Keypair, bitcoin::ScriptBuf) {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (kp, spk) = p2tr_keypath_output(&secp, [0x3c; 32]);
    let (hex, txid) = build_signed_p2wpkh_spend_from_block1_coinbase(node, wallet, spk.clone(), fee);
    (hex, txid, kp, spk)
}

#[test]
fn mempool_rpcs_match_core() {
    let wallet = DeterministicWallet::from_secret([0x5a; 32]);
    let mut node = funded_node(&[], &wallet);
    let (hex, txid, _kp, _spk) = spend_coinbase_to_taproot(&node, &wallet, 10_000);

    // --- sendrawtransaction reads `maxfeerate` and `maxburnamount` as Core
    // does (`ParseFeeRate`, `AmountFromValue`). Each of these used to be
    // accepted, with the limit silently dropped or replaced.
    assert_eq!(
        refused(&node, "sendrawtransaction", vec![json!(hex), json!(-1)]),
        (-3, "Amount out of range".to_string())
    );
    assert_eq!(
        refused(&node, "sendrawtransaction", vec![json!(hex), json!("abc")]),
        (-3, "Invalid amount".to_string())
    );
    assert_eq!(
        refused(&node, "sendrawtransaction", vec![json!(hex), json!(1)]),
        (-8, "Fee rates larger than or equal to 1BTC/kvB are not accepted".to_string())
    );
    assert_eq!(
        refused(&node, "sendrawtransaction", vec![json!(hex), json!(0.1), json!(-1)]),
        (-3, "Amount out of range".to_string())
    );
    // A rate the transaction exceeds (10,000 sat on ~110 vB).
    assert_eq!(
        refused(&node, "sendrawtransaction", vec![json!(hex), json!("0.0001")]),
        (-25, "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)".to_string())
    );
    assert!(node.rpc_ok("getrawmempool", vec![]).as_array().unwrap().is_empty());
    // A well-formed limit, given as a string as Core allows.
    let sent = node.rpc_ok("sendrawtransaction", vec![json!(hex), json!("0.10")]);
    assert_eq!(sent, json!(txid));

    // --- getmempoolentry / getmempoolinfo.
    let tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&hex::decode(&hex).unwrap()).unwrap();
    let vsize = tx.weight().to_wu().div_ceil(4);
    let entry = node.rpc_ok("getmempoolentry", vec![json!(txid)]);
    assert_eq!(entry["vsize"], json!(vsize), "{entry}");
    // Core's `entryHeight`: the tip when it entered.
    assert_eq!(entry["height"], json!(101), "{entry}");
    let info = node.rpc_ok("getmempoolinfo", vec![]);
    assert_eq!(info["loaded"], json!(true), "{info}");
    assert_eq!(info["bytes"], json!(vsize), "{info}");
    assert_eq!(info["total_fee"].as_f64(), Some(0.0001), "{info}");

    // --- gettxout sees the mempool by default (`include_mempool=true`).
    let cb_txid = block1_coinbase_txid(&node);
    assert_eq!(
        node.rpc_ok("gettxout", vec![json!(cb_txid), json!(0)]),
        Value::Null,
        "an output the mempool spends is not reported"
    );
    assert!(
        node.rpc_ok("gettxout", vec![json!(cb_txid), json!(0), json!(false)]).is_object(),
        "without the mempool the coin is still there"
    );
    let unconfirmed = node.rpc_ok("gettxout", vec![json!(txid), json!(0)]);
    assert_eq!(unconfirmed["confirmations"], json!(0), "{unconfirmed}");
    assert_eq!(unconfirmed["coinbase"], json!(false), "{unconfirmed}");
    assert_eq!(
        node.rpc_ok("gettxout", vec![json!(txid), json!(0), json!(false)]),
        Value::Null
    );

    // --- Already confirmed: Core answers -27 from the UTXO set, with no
    // txindex.
    node.mine_blocks(1, &wallet.address.to_string());
    assert_eq!(
        refused(&node, "sendrawtransaction", vec![json!(hex)]),
        (-27, "Transaction outputs already in utxo set".to_string())
    );
    node.stop();
}

#[test]
fn sendrawtransaction_of_a_spent_confirmed_transaction_is_missing_inputs() {
    // With every output spent, Core no longer finds the transaction in the
    // UTXO set and judges it as new: its inputs are gone (-25). The txindex
    // still knows it, which is why the answer must not come from there.
    let wallet = DeterministicWallet::from_secret([0x5b; 32]);
    let mut node = funded_node(&["-txindex=1"], &wallet);
    let (hex, txid, kp, spk) = spend_coinbase_to_taproot(&node, &wallet, 10_000);
    node.rpc_ok("sendrawtransaction", vec![json!(hex)]);

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let value = 50 * 100_000_000 - 10_000;
    let (child_hex, _) = build_signed_p2tr_keypath_spend(
        &secp,
        &kp,
        bitcoin::OutPoint { txid: bitcoin::Txid::from_str(&txid).unwrap(), vout: 0 },
        spk,
        value,
        wallet.address.script_pubkey(),
        10_000,
    );
    node.rpc_ok("sendrawtransaction", vec![json!(child_hex)]);
    node.mine_blocks(1, &wallet.address.to_string());
    assert!(node.rpc_ok("getrawmempool", vec![]).as_array().unwrap().is_empty());

    let (code, message) = refused(&node, "sendrawtransaction", vec![json!(hex)]);
    assert_eq!(code, -25, "{message}");
    assert!(message.contains("bad-txns-inputs-missingorspent"), "{message}");
    node.stop();
}

/// `gettxspendingprevout` under `-txospenderindex`, through the case Core's
/// `rpc_gettxspendingprevout.py` ends on: a spender in a block is found with
/// its block, and once `invalidateblock` disconnects that block and a
/// replacement evicts the spender, the output reads unspent at once. Core's
/// index would still name the spender until the next block (CORE_DIFFERENCES.md).
#[test]
fn gettxspendingprevout_reads_the_mempool_then_the_chain() {
    let wallet = DeterministicWallet::from_secret([0x5c; 32]);
    let mut node = funded_node(&["-txospenderindex"], &wallet);
    poll_until(
        || node.rpc_ok("getindexinfo", vec![])["txospenderindex"]["synced"] == json!(true),
        test_timeout(30),
        "txospenderindex never synced",
    );
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (parent_hex, parent, kp, spk) = spend_coinbase_to_taproot(&node, &wallet, 10_000);
    let (child_hex, child) = build_signed_p2tr_keypath_spend(
        &secp,
        &kp,
        bitcoin::OutPoint { txid: bitcoin::Txid::from_str(&parent).unwrap(), vout: 0 },
        spk,
        50 * 100_000_000 - 10_000,
        wallet.address.script_pubkey(),
        10_000,
    );
    let coinbase_out = json!({"txid": block1_coinbase_txid(&node), "vout": 0});
    let parent_out = json!({"txid": parent, "vout": 0});
    let ask = |node: &TestNode, outputs: Value, options: Value| {
        node.rpc_ok("gettxspendingprevout", vec![outputs, options])
    };

    node.rpc_ok("sendrawtransaction", vec![json!(parent_hex)]);
    node.rpc_ok("sendrawtransaction", vec![json!(child_hex)]);
    assert_eq!(
        ask(&node, json!([parent_out]), json!({})),
        json!([{"txid": parent, "vout": 0, "spendingtxid": child}]),
        "the mempool spender"
    );

    node.mine_blocks(1, &wallet.address.to_string());
    let block = node.rpc_ok("getbestblockhash", vec![]);
    assert_eq!(
        ask(&node, json!([parent_out]), json!({"return_spending_tx": true})),
        json!([{"txid": parent, "vout": 0, "spendingtxid": child, "blockhash": block, "spendingtx": child_hex}]),
        "the confirmed spender, its block and itself"
    );
    assert_eq!(ask(&node, json!([parent_out]), json!({"mempool_only": true})), json!([parent_out]));

    node.rpc_ok("invalidateblock", vec![block]);
    let (_, other_spk) = p2tr_keypath_output(&secp, [0x3d; 32]);
    let (replacement_hex, replacement) =
        build_signed_p2wpkh_spend_from_block1_coinbase(&node, &wallet, other_spk, 30_000);
    node.rpc_ok("sendrawtransaction", vec![json!(replacement_hex)]);
    assert_eq!(
        ask(&node, json!([coinbase_out, parent_out]), json!({})),
        json!([
            {"txid": coinbase_out["txid"], "vout": 0, "spendingtxid": replacement},
            parent_out,
        ]),
        "the disconnected spender is gone from the index"
    );
}

/// A reorg that returns a transaction whose spenders are already in the
/// mempool joins them into one cluster, and Core trims one past the cluster
/// limits (`UpdateTransactionsFromBlock`). Here a parent is mined, three
/// spenders chain off it in the mempool at `-limitclustercount=3`, and
/// `invalidateblock` returns the parent: a cluster of four, cut back to
/// three by dropping the last spender.
#[test]
fn a_reorg_trims_the_cluster_its_returned_parent_grows_past_the_limit() {
    let wallet = DeterministicWallet::from_secret([0x5d; 32]);
    let mut node = funded_node(&["-limitclustercount=3"], &wallet);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (parent_hex, parent, kp, spk) = spend_coinbase_to_taproot(&node, &wallet, 10_000);
    node.rpc_ok("sendrawtransaction", vec![json!(parent_hex)]);
    node.mine_blocks(1, &wallet.address.to_string());
    let block = node.rpc_ok("getbestblockhash", vec![]);

    let mut spenders = Vec::new();
    let mut prevout = bitcoin::OutPoint { txid: bitcoin::Txid::from_str(&parent).unwrap(), vout: 0 };
    let mut value = 50 * 100_000_000 - 10_000;
    for _ in 0..3 {
        let (hex, txid) = build_signed_p2tr_keypath_spend(&secp, &kp, prevout, spk.clone(), value, spk.clone(), 10_000);
        node.rpc_ok("sendrawtransaction", vec![json!(hex)]);
        prevout = bitcoin::OutPoint { txid: bitcoin::Txid::from_str(&txid).unwrap(), vout: 0 };
        value -= 10_000;
        spenders.push(txid);
    }

    node.rpc_ok("invalidateblock", vec![block]);
    let mut pool: Vec<String> = serde_json::from_value(node.rpc_ok("getrawmempool", vec![])).unwrap();
    pool.sort();
    let mut expected = vec![parent, spenders[0].clone(), spenders[1].clone()];
    expected.sort();
    assert_eq!(pool, expected, "the last spender is trimmed");

    node.stop();
}

/// While a reorg is offered back, a returned transaction's cluster does not
/// yet reach the mempool transactions already spending an earlier returned
/// one: Core links those only once every disconnected transaction is
/// offered. Here a mined parent has a high-fee child in its block and a
/// cheap two-transaction chain in the mempool off another output, at
/// `-limitclustercount=3`. Counting the chain refused the child; Core keeps
/// it, and the trim drops the chain's tail instead.
#[test]
fn a_reorg_keeps_a_returned_child_over_cheaper_mempool_spenders() {
    let wallet = DeterministicWallet::from_secret([0x5e; 32]);
    let mut node = funded_node(&["-limitclustercount=3"], &wallet);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (kp, spk) = p2tr_keypath_output(&secp, [0x3e; 32]);
    let half = 2_499_990_000u64;
    let outputs = vec![
        bitcoin::TxOut { value: bitcoin::Amount::from_sat(half), script_pubkey: spk.clone() },
        bitcoin::TxOut { value: bitcoin::Amount::from_sat(half), script_pubkey: spk.clone() },
    ];
    let (parent_hex, parent) = common::build_signed_p2wpkh_spend_to_outputs(&node, &wallet, outputs);
    let parent_out = |vout| bitcoin::OutPoint { txid: bitcoin::Txid::from_str(&parent).unwrap(), vout };
    let (child_hex, child) =
        build_signed_p2tr_keypath_spend(&secp, &kp, parent_out(0), spk.clone(), half, spk.clone(), 100_000);
    node.rpc_ok("sendrawtransaction", vec![json!(parent_hex)]);
    node.rpc_ok("sendrawtransaction", vec![json!(child_hex)]);
    node.mine_blocks(1, &wallet.address.to_string());
    let block = node.rpc_ok("getbestblockhash", vec![]);

    let (a_hex, a) = build_signed_p2tr_keypath_spend(&secp, &kp, parent_out(1), spk.clone(), half, spk.clone(), 1_000);
    let a_out = bitcoin::OutPoint { txid: bitcoin::Txid::from_str(&a).unwrap(), vout: 0 };
    let (b_hex, _b) = build_signed_p2tr_keypath_spend(&secp, &kp, a_out, spk.clone(), half - 1_000, spk.clone(), 1_000);
    node.rpc_ok("sendrawtransaction", vec![json!(a_hex)]);
    node.rpc_ok("sendrawtransaction", vec![json!(b_hex)]);

    node.rpc_ok("invalidateblock", vec![block]);
    let mut pool: Vec<String> = serde_json::from_value(node.rpc_ok("getrawmempool", vec![])).unwrap();
    pool.sort();
    let mut expected = vec![parent, child, a];
    expected.sort();
    assert_eq!(pool, expected, "the child comes back; the chain's tail is trimmed");

    node.stop();
}
