//! Mempool RPCs against a live regtest node, checked against Bitcoin Core:
//! `sendrawtransaction`'s limits and its "already confirmed" answer
//! (src/rpc/mempool.cpp, src/node/transaction.cpp), `gettxout` with
//! `include_mempool` (src/rpc/blockchain.cpp), and the `getmempoolinfo` /
//! `getmempoolentry` fields (`MempoolInfoToJSON`, `entryToJSON`).

mod common;

use common::{
    build_signed_p2tr_keypath_spend, build_signed_p2wpkh_spend_from_block1_coinbase,
    build_signed_p2wpkh_spend_of_coinbase,
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

/// Core v31's chunk fields, as a client that sets fees by the chunk a
/// transaction is mined in reads them (`entryToJSON`: `chunkweight` and
/// `fees.chunk`): on `getmempoolentry` and on every verbose mempool view.
/// A child paying 10 000 sat for a parent paying 200 shares its chunk.
#[test]
fn mempool_entries_carry_their_chunk() {
    let wallet = DeterministicWallet::from_secret([0x5e; 32]);
    let mut node = funded_node(&[], &wallet);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (parent_hex, parent, kp, spk) = spend_coinbase_to_taproot(&node, &wallet, 200);
    let (child_hex, child) = build_signed_p2tr_keypath_spend(
        &secp,
        &kp,
        bitcoin::OutPoint { txid: bitcoin::Txid::from_str(&parent).unwrap(), vout: 0 },
        spk,
        50 * 100_000_000 - 200,
        wallet.address.script_pubkey(),
        10_000,
    );
    node.rpc_ok("sendrawtransaction", vec![json!(parent_hex)]);
    node.rpc_ok("sendrawtransaction", vec![json!(child_hex)]);
    let weight = |hex: &str| {
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&hex::decode(hex).unwrap()).unwrap();
        tx.weight().to_wu()
    };
    let chunk_weight = weight(&parent_hex) + weight(&child_hex);
    let check = |entry: &Value, view: &str| {
        assert_eq!(entry["chunkweight"], json!(chunk_weight), "{view}: {entry}");
        assert_eq!(entry["fees"]["chunk"].to_string(), "0.00010200", "{view}: {entry}");
    };

    for txid in [&parent, &child] {
        check(&node.rpc_ok("getmempoolentry", vec![json!(txid)]), "getmempoolentry");
    }
    let verbose = node.rpc_ok("getrawmempool", vec![json!(true)]);
    for txid in [&parent, &child] {
        check(&verbose[txid.as_str()], "getrawmempool true");
    }
    check(&node.rpc_ok("getmempoolancestors", vec![json!(child), json!(true)])[parent.as_str()], "getmempoolancestors true");
    check(&node.rpc_ok("getmempooldescendants", vec![json!(parent), json!(true)])[child.as_str()], "getmempooldescendants true");
    node.stop();
}

/// `getmempoolcluster` and `getmempoolfeeratediagram` over a CPFP pair whose
/// parent is then prioritised below zero, in Core v32.1's shape
/// (`clusterToJSON`, `getmempoolfeeratediagram`, src/rpc/mempool.cpp): one
/// chunk, parent first, its fee the signed sum of modified fees, and the
/// diagram from zero to that chunk.
#[test]
fn the_cluster_rpcs_answer_as_core_does() {
    let wallet = DeterministicWallet::from_secret([0x5f; 32]);
    let mut node = funded_node(&[], &wallet);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (parent_hex, parent, kp, spk) = spend_coinbase_to_taproot(&node, &wallet, 200);
    let (child_hex, child) = build_signed_p2tr_keypath_spend(
        &secp,
        &kp,
        bitcoin::OutPoint { txid: bitcoin::Txid::from_str(&parent).unwrap(), vout: 0 },
        spk,
        50 * 100_000_000 - 200,
        wallet.address.script_pubkey(),
        10_000,
    );
    node.rpc_ok("sendrawtransaction", vec![json!(parent_hex)]);
    node.rpc_ok("sendrawtransaction", vec![json!(child_hex)]);
    let weight = |hex: &str| {
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&hex::decode(hex).unwrap()).unwrap();
        tx.weight().to_wu()
    };
    let w = weight(&parent_hex) + weight(&child_hex);
    let cluster = |fee: &str| {
        json!({
            "clusterweight": w,
            "txcount": 2,
            "chunks": [{ "chunkfee": serde_json::Value::from_str(fee).unwrap(), "chunkweight": w, "txs": [&parent, &child] }],
        })
    };
    for txid in [&parent, &child] {
        assert_eq!(node.rpc_ok("getmempoolcluster", vec![json!(txid)]), cluster("0.00010200"));
    }
    let diagram = node.rpc_ok("getmempoolfeeratediagram", vec![]);
    let points: Vec<(u64, String)> =
        diagram.as_array().unwrap().iter().map(|p| (p["weight"].as_u64().unwrap(), p["fee"].to_string())).collect();
    assert_eq!(points, [(0, "0.00000000".to_string()), (w, "0.00010200".to_string())]);

    node.rpc_ok("prioritisetransaction", vec![json!(parent), json!(0), json!(-20_000)]);
    assert_eq!(node.rpc_ok("getmempoolcluster", vec![json!(child)]), cluster("-0.00009800"));
    let diagram = node.rpc_ok("getmempoolfeeratediagram", vec![]);
    assert_eq!(diagram[1]["fee"].to_string(), "-0.00009800", "{diagram}");

    // Named parameters, and Core's errors.
    let named = node.rpc_call_with_named_params("getmempoolcluster", json!({ "txid": parent })).unwrap();
    assert_eq!(named["result"]["txcount"], json!(2), "{named}");
    assert_eq!(
        refused(&node, "getmempoolcluster", vec![json!("00".repeat(32))]),
        (-5, "Transaction not in mempool".to_string())
    );
    assert_eq!(
        refused(&node, "getmempoolcluster", vec![json!("zz")]),
        (-8, "txid must be of length 64 (not 2, for 'zz')".to_string())
    );
    node.stop();
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
    // The configured limits are what `getmempoolinfo` reports (Core v31),
    // the size in virtual bytes.
    let info = node.rpc_ok("getmempoolinfo", vec![]);
    assert_eq!(info["limitclustercount"], json!(3), "{info}");
    assert_eq!(info["limitclustersize"], json!(101_000), "{info}");
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

/// `version | 00 00 | lock_time` decodes, as Core's `DecodeHexTx` decodes
/// it, to a transaction with no inputs, and each submission RPC refuses it
/// as `bad-txns-vin-empty`, not "TX decode failed" (#1242). The answers are a
/// Core v32.1 regtest node's.
#[test]
fn a_transaction_with_no_inputs_is_refused_as_core_refuses_it() {
    const EMPTY: &str = "02000000000000000000";
    let node = TestNode::start(&[]);
    assert_eq!(
        refused(&node, "sendrawtransaction", vec![json!(EMPTY)]),
        (-26, "bad-txns-vin-empty".to_string())
    );
    let tma = node.rpc_ok("testmempoolaccept", vec![json!([EMPTY])]);
    assert_eq!(tma[0]["allowed"], json!(false), "{tma}");
    assert_eq!(tma[0]["reject-reason"], json!("bad-txns-vin-empty"), "{tma}");
    let decoded = node.rpc_ok("decoderawtransaction", vec![json!(EMPTY)]);
    assert_eq!(decoded["txid"], json!("4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a"));
    assert_eq!(decoded["vin"], json!([]));

    // `generateblock` takes it into the block, which fails `CheckBlock`.
    // Core: -25 "TestBlockValidity failed: bad-txns-vin-empty, Transaction
    // check failed (tx hash ...)".
    let output = node.rpc_ok("getdescriptorinfo", vec![json!("raw(51)")])["descriptor"].clone();
    let (code, message) = refused(&node, "generateblock", vec![output, json!([EMPTY])]);
    assert_eq!(code, -25, "{message}");
    assert!(message.starts_with("TestBlockValidity failed: bad-txns-vin-empty"), "{message}");

    // A witness flag with no inputs: Core refuses the bytes.
    assert_eq!(
        refused(&node, "sendrawtransaction", vec![json!("020000000001000000000000")]).0,
        -22
    );
}

/// The rest of Core's answers for a transaction with no inputs (Core v31.1
/// regtest; the code paths are v32.1's):
/// - `decoderawtransaction` measures it without the marker and flag, and its
///   wtxid is its txid, which `testmempoolaccept` prints and `submitpackage`
///   keys `tx-results` by;
/// - `submitpackage` refuses it as `conflict-in-package` (`IsConsistentPackage`),
///   as does a multi-transaction `testmempoolaccept`;
/// - the submission RPCs read only the extended form (`DecodeHexTx`'s
///   defaults), so `createrawtransaction`'s answer with no inputs and an
///   output is a decode failure there, with Core's message, while
///   `decoderawtransaction` reads it back.
#[test]
fn a_transaction_with_no_inputs_gets_cores_sizes_ids_and_messages() {
    const EMPTY: &str = "02000000000000000000";
    const EMPTY_TXID: &str = "4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a";
    // The same with lock time 1.
    const EMPTY2: &str = "02000000000001000000";
    const EMPTY2_TXID: &str = "d877b150e2f2cb183f38643fca5169da842be9c8fb841570d6fdf496bd56e829";
    let node = TestNode::start(&[]);

    let decoded = node.rpc_ok("decoderawtransaction", vec![json!(EMPTY)]);
    assert_eq!(decoded["hash"], json!(EMPTY_TXID), "{decoded}");
    assert_eq!((&decoded["size"], &decoded["vsize"], &decoded["weight"]), (&json!(10), &json!(10), &json!(40)));

    let tma = node.rpc_ok("testmempoolaccept", vec![json!([EMPTY])]);
    assert_eq!(tma[0]["wtxid"], json!(EMPTY_TXID), "{tma}");
    let tma = node.rpc_ok("testmempoolaccept", vec![json!([EMPTY, EMPTY2])]);
    assert_eq!(
        tma,
        json!([
            {"txid": EMPTY_TXID, "wtxid": EMPTY_TXID, "package-error": "conflict-in-package"},
            {"txid": EMPTY2_TXID, "wtxid": EMPTY2_TXID, "package-error": "conflict-in-package"},
        ])
    );

    let sp = node.rpc_ok("submitpackage", vec![json!([EMPTY])]);
    assert_eq!(
        sp,
        json!({
            "package_msg": "conflict-in-package",
            "tx-results": {EMPTY_TXID: {"txid": EMPTY_TXID, "error": "package-not-validated"}},
            "replaced-transactions": [],
        })
    );

    let data = node.rpc_ok("createrawtransaction", vec![json!([]), json!([{"data": "00"}])]);
    let data = data.as_str().expect("hex").to_string();
    assert_eq!(data, "0200000000010000000000000000036a010000000000");
    let decoded = node.rpc_ok("decoderawtransaction", vec![json!(data)]);
    assert_eq!(decoded["vout"][0]["scriptPubKey"]["hex"], json!("6a0100"), "{decoded}");
    let at_least_one = "Make sure the tx has at least one input.";
    assert_eq!(
        refused(&node, "sendrawtransaction", vec![json!(data)]),
        (-22, format!("TX decode failed. {at_least_one}"))
    );
    for method in ["testmempoolaccept", "submitpackage"] {
        assert_eq!(
            refused(&node, method, vec![json!([data])]),
            (-22, format!("TX decode failed: {data} {at_least_one}")),
            "{method}"
        );
    }
    let output = node.rpc_ok("getdescriptorinfo", vec![json!("raw(51)")])["descriptor"].clone();
    assert_eq!(
        refused(&node, "generateblock", vec![output, json!([data])]),
        (-22, format!("Transaction decode failed for {data}. {at_least_one}"))
    );
}

/// `tx` with its first input repeated: one outpoint spent twice.
fn with_duplicated_input(hex: &str) -> (String, String, String) {
    let mut tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&hex::decode(hex).unwrap()).unwrap();
    tx.input.push(tx.input[0].clone());
    (
        hex::encode(bitcoin::consensus::serialize(&tx)),
        tx.compute_txid().to_string(),
        node::validation::decode::wtxid(&tx).to_string(),
    )
}

/// A package member spending one outpoint twice itself, answered as Core
/// answers it (v31.1 regtest; the code paths are v32.1's). Core's
/// `IsConsistentPackage` (`src/policy/packages.cpp`) adds a member's inputs
/// as one batch and compares only across members, so the package is well
/// formed; the member then fails `CheckTransaction` with
/// `bad-txns-inputs-duplicate`. A multi-transaction `testmempoolaccept`
/// reports it on that member and leaves the rest with only their ids;
/// `submitpackage` answers `transaction failed`, keeps the parent it accepted
/// on its own, and gives the member its error.
///
/// Two members spending one outpoint stay `conflict-in-package`.
#[test]
fn a_member_spending_one_outpoint_twice_is_refused_as_core_refuses_it() {
    let wallet = DeterministicWallet::from_secret([0x5b; 32]);
    let mut node = funded_node(&[], &wallet);
    // Blocks 2 and 3's coinbases mature too.
    node.mine_blocks(2, &wallet.address.to_string());
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (parent, parent_txid, kp, spk) = spend_coinbase_to_taproot(&node, &wallet, 10_000);
    let parent_tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&hex::decode(&parent).unwrap()).unwrap();
    let parent_wtxid = node::validation::decode::wtxid(&parent_tx).to_string();
    let parent_value = parent_tx.output[0].value.to_sat();
    let parent_out = bitcoin::OutPoint::new(bitcoin::Txid::from_str(&parent_txid).unwrap(), 0);
    let (child, _) =
        build_signed_p2tr_keypath_spend(&secp, &kp, parent_out, spk.clone(), parent_value, spk.clone(), 10_000);
    let (dup_child, dup_child_txid, dup_child_wtxid) = with_duplicated_input(&child);

    // Two transactions, unrelated to the parent: `dup` spends block 2's
    // coinbase twice, `other` spends block 3's.
    let (spends_2, _) = build_signed_p2wpkh_spend_of_coinbase(&node, &wallet, 2, spk.clone(), 10_000);
    let (dup, dup_txid, dup_wtxid) = with_duplicated_input(&spends_2);
    let (other, other_txid) = build_signed_p2wpkh_spend_of_coinbase(&node, &wallet, 3, spk.clone(), 10_000);
    let other_wtxid = {
        let tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&other).unwrap()).unwrap();
        node::validation::decode::wtxid(&tx).to_string()
    };
    let refusal = |txid: &str, wtxid: &str| {
        json!({
            "txid": txid,
            "wtxid": wtxid,
            "allowed": false,
            "reject-reason": "bad-txns-inputs-duplicate",
            "reject-details": "bad-txns-inputs-duplicate",
        })
    };
    let ids = |txid: &str, wtxid: &str| json!({"txid": txid, "wtxid": wtxid});

    // Alone, as before.
    assert_eq!(
        node.rpc_ok("testmempoolaccept", vec![json!([dup])]),
        json!([refusal(&dup_txid, &dup_wtxid)])
    );
    // In a package, wherever it stands, and whether or not the other member
    // is its parent.
    assert_eq!(
        node.rpc_ok("testmempoolaccept", vec![json!([parent, dup_child])]),
        json!([ids(&parent_txid, &parent_wtxid), refusal(&dup_child_txid, &dup_child_wtxid)])
    );
    assert_eq!(
        node.rpc_ok("testmempoolaccept", vec![json!([dup, other])]),
        json!([refusal(&dup_txid, &dup_wtxid), ids(&other_txid, &other_wtxid)])
    );
    assert_eq!(
        node.rpc_ok("testmempoolaccept", vec![json!([other, dup])]),
        json!([ids(&other_txid, &other_wtxid), refusal(&dup_txid, &dup_wtxid)])
    );

    // `submitpackage` of the member alone.
    assert_eq!(
        node.rpc_ok("submitpackage", vec![json!([dup])]),
        json!({
            "package_msg": "transaction failed",
            "tx-results": {dup_wtxid.clone(): {"txid": dup_txid, "error": "bad-txns-inputs-duplicate"}},
            "replaced-transactions": [],
        })
    );

    // Two members spending one outpoint: still a package conflict, judged
    // before any member.
    let (spends_3_again, spends_3_again_txid) =
        build_signed_p2wpkh_spend_of_coinbase(&node, &wallet, 3, spk.clone(), 20_000);
    let spends_3_again_wtxid = {
        let tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&hex::decode(&spends_3_again).unwrap()).unwrap();
        node::validation::decode::wtxid(&tx).to_string()
    };
    let conflict = |txid: &str, wtxid: &str| {
        json!({"txid": txid, "wtxid": wtxid, "package-error": "conflict-in-package"})
    };
    assert_eq!(
        node.rpc_ok("testmempoolaccept", vec![json!([other, spends_3_again])]),
        json!([conflict(&other_txid, &other_wtxid), conflict(&spends_3_again_txid, &spends_3_again_wtxid)])
    );

    // `submitpackage` of the parent and the child: the parent goes in on its
    // own, the child carries its error.
    let sp = node.rpc_ok("submitpackage", vec![json!([parent, dup_child])]);
    assert_eq!(sp["package_msg"], json!("transaction failed"), "{sp}");
    assert_eq!(sp["replaced-transactions"], json!([]), "{sp}");
    let results = sp["tx-results"].as_object().expect("tx-results");
    assert_eq!(results.len(), 2, "{sp}");
    assert_eq!(
        results[&dup_child_wtxid],
        json!({"txid": dup_child_txid, "error": "bad-txns-inputs-duplicate"}),
        "{sp}"
    );
    let accepted = &results[&parent_wtxid];
    assert_eq!(accepted["txid"], json!(parent_txid), "{sp}");
    assert!(accepted.get("error").is_none(), "{sp}");
    assert_eq!(accepted["vsize"], json!(parent_tx.weight().to_wu().div_ceil(4)), "{sp}");
    assert_eq!(accepted["fees"]["base"].as_f64(), Some(0.0001), "{sp}");
    assert_eq!(accepted["fees"]["effective-includes"], json!([parent_wtxid]), "{sp}");
    assert_eq!(node.rpc_ok("getrawmempool", vec![]), json!([parent_txid]));
}
