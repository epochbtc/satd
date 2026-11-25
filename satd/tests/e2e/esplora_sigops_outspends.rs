//! Esplora `sigops` in the transaction JSON and `GET /txs/outspends`, as
//! rbitcoin's Esplora serves them.
//!
//! The chain: `w` mines 101 blocks. `fund` spends block 1's coinbase to a
//! P2PKH, a P2SH 1-of-2 multisig, a P2TR and a P2WPKH output, and confirms
//! in block 102. Three transactions then spend the first three outputs and
//! a fourth spends block 2's coinbase; they sit in the mempool, then confirm
//! in block 103.
//!
//! Every expected sigop cost is worked out here from Bitcoin Core's rules:
//! a legacy sigop (an `OP_CHECKSIG` in a scriptSig or an output script)
//! costs 4, a sigop of a P2SH redeem script 4, a P2WPKH input 1, a taproot
//! spend nothing.

use std::str::FromStr;

use bitcoin::hashes::Hash as _;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use serde_json::{Value, json};

use super::{E2eNode, EsploraClient, esplora_e2e_args, esplora_for, esplora_get_json};
use crate::common::{
    self, DeterministicWallet, build_signed_p2tr_keypath_spend,
    build_signed_p2wpkh_spend_of_coinbase, build_signed_p2wpkh_spend_to_outputs,
};

const TIP: &str = "x-bitcoin-chain-tip";
const COIN: u64 = 100_000_000;
const FEE: u64 = 10_000;

fn mine(e2e: &E2eNode, n: u64, wallet: &DeterministicWallet) {
    e2e.node.rpc_ok(
        "generatetoaddress",
        vec![json!(n), json!(wallet.address.to_string())],
    );
}

fn block_hash_at(e2e: &E2eNode, height: u64) -> String {
    e2e.node
        .rpc_ok("getblockhash", vec![json!(height)])
        .as_str()
        .expect("hash string")
        .to_string()
}

/// GET `path`: status, the chain-tip header, and the body.
fn get(esplora: &EsploraClient, path: &str) -> (u16, Option<String>, String) {
    let resp = esplora.get(path);
    let status = resp.status().as_u16();
    let tip = resp
        .headers()
        .get(TIP)
        .map(|v| v.to_str().expect("ascii header").to_string());
    (status, tip, resp.text().expect("body utf8"))
}

fn broadcast(esplora: &EsploraClient, raw: &str) {
    let r = esplora.post_tx(raw);
    assert_eq!(r.status(), 200, "broadcast: {}", r.text().unwrap_or_default());
}

fn push(bytes: &[u8]) -> PushBytesBuf {
    PushBytesBuf::try_from(bytes.to_vec()).expect("a push")
}

/// A one-input transaction spending `prevout`, paying `value` to `dest`.
fn unsigned(prevout: OutPoint, value: u64, dest: ScriptBuf) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(value), script_pubkey: dest }],
    }
}

/// A SIGHASH_ALL signature of `tx`'s only input under the pre-segwit rules,
/// for `script_code` (the spent script, or the P2SH redeem script).
fn legacy_signature(tx: &Transaction, script_code: &bitcoin::Script, sk: &SecretKey) -> PushBytesBuf {
    let sighash = SighashCache::new(tx)
        .legacy_signature_hash(0, script_code, EcdsaSighashType::All.to_u32())
        .expect("legacy sighash");
    let msg = Message::from_digest(sighash.to_byte_array());
    let mut sig = Secp256k1::new().sign_ecdsa(&msg, sk).serialize_der().to_vec();
    sig.push(EcdsaSighashType::All as u8);
    push(&sig)
}

fn raw(tx: &Transaction) -> String {
    hex::encode(bitcoin::consensus::serialize(tx))
}

/// The `sigops` of every transaction object in a JSON list, by txid.
fn sigops_by_txid(list: &Value) -> std::collections::HashMap<String, Value> {
    list.as_array()
        .expect("a list of transactions")
        .iter()
        .map(|tx| (tx["txid"].as_str().expect("txid").to_string(), tx["sigops"].clone()))
        .collect()
}

#[test]
fn test_e2e_esplora_sigops_and_txs_outspends() {
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let secp = Secp256k1::new();
    let w = DeterministicWallet::from_secret([0x51u8; 32]);
    let other = DeterministicWallet::from_secret([0x52u8; 32]);
    mine(&e2e, 101, &w);

    let dest = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("address")
        .assume_checked();
    let p2pkh = ScriptBuf::new_p2pkh(&w.pk.pubkey_hash());
    let redeem = Builder::new()
        .push_int(1)
        .push_key(&w.pk)
        .push_key(&other.pk)
        .push_int(2)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
        .into_script();
    let p2sh = ScriptBuf::new_p2sh(&redeem.script_hash());
    let (taproot_key, p2tr) = common::p2tr_keypath_output(&secp, [0x53u8; 32]);

    // `fund`: block 1's coinbase to one output of each kind.
    let change = 50 * COIN - 3 * COIN - FEE;
    let (fund_raw, fund) = build_signed_p2wpkh_spend_to_outputs(
        &e2e.node,
        &w,
        vec![
            TxOut { value: Amount::from_sat(COIN), script_pubkey: p2pkh.clone() },
            TxOut { value: Amount::from_sat(COIN), script_pubkey: p2sh.clone() },
            TxOut { value: Amount::from_sat(COIN), script_pubkey: p2tr.clone() },
            TxOut { value: Amount::from_sat(change), script_pubkey: dest.script_pubkey() },
        ],
    );
    broadcast(&esplora, &fund_raw);
    let fund_txid = Txid::from_str(&fund).expect("txid");
    let coinbase1 = common::coinbase_txid_at(&e2e.node, 1);

    // In the mempool: a P2WPKH input (1) and a P2PKH output (4).
    let tx = esplora_get_json(&esplora, &format!("/tx/{fund}"));
    assert_eq!(tx["status"]["confirmed"], false);
    assert_eq!(tx["sigops"], 5, "{tx}");
    mine(&e2e, 1, &w);
    let h102 = block_hash_at(&e2e, 102);
    let tx = esplora_get_json(&esplora, &format!("/tx/{fund}"));
    assert_eq!(tx["status"]["block_height"], 102);
    assert_eq!(tx["sigops"], 5, "confirmed, the same cost: {tx}");

    // Legacy P2PKH spend paying a P2PKH output: the scriptSig only pushes,
    // the output holds one OP_CHECKSIG. 4.
    let mut spend_p2pkh = unsigned(OutPoint { txid: fund_txid, vout: 0 }, COIN - FEE, p2pkh.clone());
    let sig = legacy_signature(&spend_p2pkh, &p2pkh, &w.sk);
    spend_p2pkh.input[0].script_sig = Builder::new().push_slice(sig).push_key(&w.pk).into_script();

    // P2SH 1-of-2 multisig spend paying P2WPKH: the redeem script's two
    // keys at 4 each. 8.
    let mut spend_p2sh =
        unsigned(OutPoint { txid: fund_txid, vout: 1 }, COIN - FEE, dest.script_pubkey());
    let sig = legacy_signature(&spend_p2sh, &redeem, &w.sk);
    spend_p2sh.input[0].script_sig = Builder::new()
        .push_opcode(bitcoin::opcodes::OP_FALSE)
        .push_slice(sig)
        .push_slice(push(redeem.as_bytes()))
        .into_script();

    // Taproot key-path spend paying P2WPKH. 0.
    let (spend_p2tr_raw, spend_p2tr) = build_signed_p2tr_keypath_spend(
        &secp,
        &taproot_key,
        OutPoint { txid: fund_txid, vout: 2 },
        p2tr,
        COIN,
        dest.script_pubkey(),
        FEE,
    );

    // P2WPKH spend (block 2's coinbase) paying P2WPKH. 1.
    let (spend_p2wpkh_raw, spend_p2wpkh) =
        build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &w, 2, dest.script_pubkey(), FEE);

    let spend_p2pkh_txid = spend_p2pkh.compute_txid().to_string();
    let spend_p2sh_txid = spend_p2sh.compute_txid().to_string();
    for raw_tx in [&raw(&spend_p2pkh), &raw(&spend_p2sh), &spend_p2tr_raw, &spend_p2wpkh_raw] {
        broadcast(&esplora, raw_tx);
    }
    let expected: Vec<(&str, u64)> = vec![
        (&spend_p2pkh_txid, 4),
        (&spend_p2sh_txid, 8),
        (&spend_p2tr, 0),
        (&spend_p2wpkh, 1),
    ];

    // Unconfirmed: `/tx/:txid` and the address's mempool list.
    for (txid, sigops) in &expected {
        let tx = esplora_get_json(&esplora, &format!("/tx/{txid}"));
        assert_eq!(tx["status"]["confirmed"], false);
        assert_eq!(tx["sigops"], json!(sigops), "unconfirmed {txid}: {tx}");
    }
    let listed = sigops_by_txid(&esplora_get_json(&esplora, &format!("/address/{dest}/txs/mempool")));
    assert_eq!(listed.len(), 3, "the three spends paying `dest`");
    for (txid, sigops) in &expected[1..] {
        assert_eq!(listed[*txid], json!(sigops), "mempool list, {txid}");
    }

    // ── `/txs/outspends` with the spends in the mempool ──
    let unknown = "ff".repeat(32);
    let single = |txid: &str| esplora_get_json(&esplora, &format!("/tx/{txid}/outspends"));
    let fund_spends = single(&fund);
    let unconfirmed = |txid: &str| json!({"spent": true, "txid": txid, "vin": 0, "status": {"confirmed": false}});
    assert_eq!(
        fund_spends,
        json!([
            unconfirmed(&spend_p2pkh_txid),
            unconfirmed(&spend_p2sh_txid),
            unconfirmed(&spend_p2tr),
            {"spent": false},
        ])
    );
    let coinbase1_spends = single(&coinbase1);
    assert_eq!(coinbase1_spends[0]["txid"], json!(fund));
    assert_eq!(coinbase1_spends[0]["status"]["block_hash"], json!(h102));

    // Request order, a txid twice, one unknown, one not a txid.
    let path = format!("/txs/outspends?txids={coinbase1},{fund},{unknown},zz,{coinbase1}");
    let (status, tip, body) = get(&esplora, &path);
    assert_eq!(status, 200, "{body}");
    assert_eq!(tip.as_deref(), Some(h102.as_str()), "stamped with the tip it was read at");
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("JSON"),
        json!([coinbase1_spends, fund_spends, [], [], coinbase1_spends])
    );
    // A transaction only in the mempool has outputs too.
    assert_eq!(
        esplora_get_json(&esplora, &format!("/txs/outspends?txids={spend_p2tr}")),
        json!([[{"spent": false}]])
    );

    // As of block 102 the mempool is left out: `fund`'s outputs are unspent,
    // and a transaction only in the mempool is unknown (404 on its own).
    let asof = esplora_get_json(
        &esplora,
        &format!("/txs/outspends?txids={fund},{spend_p2tr}&asof={h102}"),
    );
    let unspent = json!({"spent": false});
    assert_eq!(asof, json!([[unspent, unspent, unspent, unspent], []]));
    assert_eq!(asof[0], esplora_get_json(&esplora, &format!("/tx/{fund}/outspends?asof={h102}")));
    assert_eq!(get(&esplora, &format!("/tx/{spend_p2tr}/outspends?asof={h102}")).0, 404);

    // The refusals.
    for path in ["/txs/outspends", "/txs/outspends?txids="] {
        let (status, _, body) = get(&esplora, path);
        assert_eq!((status, body.as_str()), (400, "No txids specified"), "{path}");
    }
    let list = |n: usize| vec![fund.as_str(); n].join(",");
    let fifty = esplora_get_json(&esplora, &format!("/txs/outspends?txids={}", list(50)));
    assert_eq!(fifty.as_array().expect("an array").len(), 50);
    assert!(fifty.as_array().unwrap().iter().all(|row| *row == fund_spends));
    let (status, _, body) = get(&esplora, &format!("/txs/outspends?txids={}", list(51)));
    assert_eq!((status, body.as_str()), (400, "Too many txids requested"));

    // ── Block 103 confirms the four spends ──
    mine(&e2e, 1, &w);
    let h103 = block_hash_at(&e2e, 103);
    for (txid, sigops) in &expected {
        let tx = esplora_get_json(&esplora, &format!("/tx/{txid}"));
        assert_eq!(tx["status"]["block_height"], 103);
        assert_eq!(tx["sigops"], json!(sigops), "confirmed {txid}: {tx}");
    }
    // The block's list: the coinbase (a P2WPKH output and the witness
    // commitment, no sigop) and the four spends.
    let listed = sigops_by_txid(&esplora_get_json(&esplora, &format!("/block/{h103}/txs")));
    assert_eq!(listed.len(), 5);
    assert_eq!(listed[&common::coinbase_txid_at(&e2e.node, 103)], json!(0));
    for (txid, sigops) in &expected {
        assert_eq!(listed[*txid], json!(sigops), "block list, {txid}");
    }
    // The address's confirmed list.
    let listed = sigops_by_txid(&esplora_get_json(&esplora, &format!("/address/{dest}/txs/chain")));
    assert_eq!(listed.len(), 4, "`fund` and the three spends paying `dest`");
    assert_eq!(listed[&fund], json!(5));
    for (txid, sigops) in &expected[1..] {
        assert_eq!(listed[*txid], json!(sigops), "address list, {txid}");
    }

    // The spends are confirmed now, and the batch still equals the single
    // route; as of block 102 nothing changed.
    let confirmed = |txid: &str| {
        let status = esplora_get_json(&esplora, &format!("/tx/{txid}/status"));
        assert_eq!(status["block_hash"], json!(h103));
        json!({"spent": true, "txid": txid, "vin": 0, "status": status})
    };
    let fund_spends = json!([
        confirmed(&spend_p2pkh_txid),
        confirmed(&spend_p2sh_txid),
        confirmed(&spend_p2tr),
        {"spent": false},
    ]);
    assert_eq!(single(&fund), fund_spends);
    let (status, tip, body) = get(&esplora, &format!("/txs/outspends?txids={fund},{spend_p2tr}"));
    assert_eq!(status, 200, "{body}");
    assert_eq!(tip.as_deref(), Some(h103.as_str()));
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("JSON"),
        json!([fund_spends, [{"spent": false}]])
    );
    let (status, tip, body) = get(&esplora, &format!("/txs/outspends?txids={fund}&asof={h102}"));
    assert_eq!(status, 200, "{body}");
    assert_eq!(tip.as_deref(), Some(h102.as_str()), "stamped with the asof block");
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("JSON"),
        json!([[unspent, unspent, unspent, unspent]])
    );

    e2e.node.stop();
}
