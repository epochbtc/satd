//! The NAP publisher over JSON-RPC on regtest: every signer class the
//! design names, a restart, a spent coin and a reorganised anchor.
//!
//! Six coinbases pay six script types. Once they are `MIN_COIN_AGE` blocks
//! below the anchor, each is attested: P2WPKH (unprefixed simple), P2TR key
//! path and script path, P2WSH 2-of-2 (`smp`), P2SH-P2WPKH (`ful`) and P2PKH
//! (legacy, signed by the node's own `signmessagewithprivkey`). The test
//! signs BIP 322 itself, over `node::bip322`'s virtual transactions.

mod common;

use base64::Engine as _;
use bitcoin::hashes::Hash as _;
use bitcoin::key::{Keypair, TapTweak as _};
use bitcoin::opcodes::all::*;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, PrivateKey, ScriptBuf, Transaction, TxOut,
    Witness,
};
use common::{
    DeterministicWallet, TestNode, build_signed_p2wpkh_spend_of_coinbase, coinbase_txid_at,
    find_available_port, fresh_test_datadir, poll_until, test_timeout,
};
use serde_json::{Value, json};

const BURN: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
/// `nap::MIN_COIN_AGE` + `nap::ANCHOR_DEPTH`: a coin is attestable this many
/// blocks after it confirms.
const ATTESTABLE_AFTER: u64 = 4_032 + 6;

fn secret(n: u8) -> SecretKey {
    SecretKey::from_slice(&[n; 32]).unwrap()
}

fn compressed(sk: &SecretKey) -> CompressedPublicKey {
    CompressedPublicKey(sk.public_key(&Secp256k1::new()))
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// BIP 322's default `to_sign` for `message` against `spk`.
fn to_sign(spk: &ScriptBuf, message: &str) -> Transaction {
    let spend = node::bip322::to_spend(spk, message.as_bytes());
    node::bip322::to_sign(spend.compute_txid(), Witness::new())
}

fn ecdsa(sighash: [u8; 32], sk: &SecretKey) -> bitcoin::ecdsa::Signature {
    let signature = Secp256k1::new().sign_ecdsa(&Message::from_digest(sighash), sk);
    bitcoin::ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All }
}

fn schnorr(sighash: [u8; 32], keypair: &Keypair) -> bitcoin::taproot::Signature {
    let signature = Secp256k1::new().sign_schnorr_no_aux_rand(&Message::from_digest(sighash), keypair);
    bitcoin::taproot::Signature { signature, sighash_type: TapSighashType::Default }
}

/// Signs a message text, given the node (for `signmessagewithprivkey`).
type Sign = Box<dyn Fn(&TestNode, &str) -> String>;

/// A coin's owner: its address and how it signs a message.
struct Holder {
    name: &'static str,
    address: Address,
    formats: Value,
    sign: Sign,
}

fn holders() -> Vec<Holder> {
    let secp = Secp256k1::new();
    let net = Network::Regtest;
    let mut out = Vec::new();

    // P2WPKH, unprefixed simple, as most deployed wallets emit it.
    let sk = secret(1);
    let pk = compressed(&sk);
    let address = Address::p2wpkh(&pk, net);
    let spk = address.script_pubkey();
    out.push(Holder {
        name: "p2wpkh",
        address,
        formats: json!(["simple", "full"]),
        sign: Box::new(move |_, message| {
            let tx = to_sign(&spk, message);
            let sighash = SighashCache::new(&tx)
                .p2wpkh_signature_hash(0, &spk, Amount::ZERO, EcdsaSighashType::All)
                .unwrap();
            let w = Witness::p2wpkh(&ecdsa(sighash.to_byte_array(), &sk), &pk.0);
            b64(&bitcoin::consensus::serialize(&w))
        }),
    });

    // P2TR key path, `smp`.
    let keypair = Keypair::from_secret_key(&secp, &secret(2));
    let address = Address::p2tr(&secp, keypair.x_only_public_key().0, None, net);
    let spk = address.script_pubkey();
    out.push(Holder {
        name: "p2tr key path",
        address,
        formats: json!(["simple", "full"]),
        sign: Box::new(move |_, message| {
            let tx = to_sign(&spk, message);
            let prevout = [TxOut { value: Amount::ZERO, script_pubkey: spk.clone() }];
            let sighash = SighashCache::new(&tx)
                .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevout), TapSighashType::Default)
                .unwrap();
            let tweaked = keypair.tap_tweak(&Secp256k1::new(), None).to_keypair();
            let w = Witness::p2tr_key_spend(&schnorr(sighash.to_byte_array(), &tweaked));
            format!("smp{}", b64(&bitcoin::consensus::serialize(&w)))
        }),
    });

    // P2TR script path, `<key> OP_CHECKSIG` under another internal key.
    let leaf_key = Keypair::from_secret_key(&secp, &secret(3));
    let leaf = Builder::new()
        .push_x_only_key(&leaf_key.x_only_public_key().0)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let internal = Keypair::from_secret_key(&secp, &secret(4)).x_only_public_key().0;
    let info = TaprootBuilder::new().add_leaf(0, leaf.clone()).unwrap().finalize(&secp, internal).unwrap();
    let control = info.control_block(&(leaf.clone(), LeafVersion::TapScript)).unwrap();
    let address = Address::p2tr_tweaked(info.output_key(), net);
    let spk = address.script_pubkey();
    out.push(Holder {
        name: "p2tr script path",
        address,
        formats: json!(["simple", "full"]),
        sign: Box::new(move |_, message| {
            let tx = to_sign(&spk, message);
            let prevout = [TxOut { value: Amount::ZERO, script_pubkey: spk.clone() }];
            let sighash = SighashCache::new(&tx)
                .taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(&prevout),
                    TapLeafHash::from_script(&leaf, LeafVersion::TapScript),
                    TapSighashType::Default,
                )
                .unwrap();
            let mut w = Witness::new();
            w.push(schnorr(sighash.to_byte_array(), &leaf_key).to_vec());
            w.push(leaf.as_bytes());
            w.push(control.serialize());
            format!("smp{}", b64(&bitcoin::consensus::serialize(&w)))
        }),
    });

    // P2WSH 2-of-2, `smp`.
    let (sk1, sk2) = (secret(5), secret(6));
    let ws = Builder::new()
        .push_opcode(OP_PUSHNUM_2)
        .push_key(&compressed(&sk1).into())
        .push_key(&compressed(&sk2).into())
        .push_opcode(OP_PUSHNUM_2)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();
    let address = Address::p2wsh(&ws, net);
    let spk = address.script_pubkey();
    out.push(Holder {
        name: "p2wsh 2-of-2",
        address,
        formats: json!(["simple", "full"]),
        sign: Box::new(move |_, message| {
            let tx = to_sign(&spk, message);
            let sighash = SighashCache::new(&tx)
                .p2wsh_signature_hash(0, &ws, Amount::ZERO, EcdsaSighashType::All)
                .unwrap()
                .to_byte_array();
            let mut w = Witness::new();
            w.push([]);
            w.push(ecdsa(sighash, &sk1).to_vec());
            w.push(ecdsa(sighash, &sk2).to_vec());
            w.push(ws.as_bytes());
            format!("smp{}", b64(&bitcoin::consensus::serialize(&w)))
        }),
    });

    // P2SH-P2WPKH, which only the full format covers (D13).
    let sk = secret(7);
    let pk = compressed(&sk);
    let address = Address::p2shwpkh(&pk, net);
    let spk = address.script_pubkey();
    let redeem = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    out.push(Holder {
        name: "p2sh-p2wpkh",
        address,
        formats: json!(["full"]),
        sign: Box::new(move |_, message| {
            let mut tx = to_sign(&spk, message);
            let push = PushBytesBuf::try_from(redeem.to_bytes()).unwrap();
            tx.input[0].script_sig = Builder::new().push_slice(push).into_script();
            let sighash = SighashCache::new(&tx)
                .p2wpkh_signature_hash(0, &redeem, Amount::ZERO, EcdsaSighashType::All)
                .unwrap();
            tx.input[0].witness = Witness::p2wpkh(&ecdsa(sighash.to_byte_array(), &sk), &pk.0);
            format!("ful{}", b64(&bitcoin::consensus::serialize(&tx)))
        }),
    });

    // P2PKH, legacy: Core's message signing, which satd answers itself.
    let key = PrivateKey::new(secret(8), net);
    let address = Address::p2pkh(key.public_key(&secp), net);
    out.push(Holder {
        name: "p2pkh",
        address,
        formats: json!(["legacy", "full"]),
        sign: Box::new(move |node, message| {
            node.rpc_ok("signmessagewithprivkey", vec![json!(key.to_wif()), json!(message)])
                .as_str()
                .unwrap()
                .to_string()
        }),
    });
    out
}

fn list(node: &TestNode) -> Vec<Value> {
    node.rpc_ok("listnapattestations", vec![]).as_array().unwrap().clone()
}

fn error_of(r: Value) -> (i64, String) {
    (r["error"]["code"].as_i64().unwrap(), r["error"]["message"].as_str().unwrap().to_string())
}

#[test]
fn nap_publisher_signs_restarts_spends_and_reorgs() {
    let rpcport = find_available_port();
    let datadir = fresh_test_datadir("satd-nap-publisher");
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--nap=1"]);

    let holders = holders();
    for h in &holders {
        node.mine_blocks(1, &h.address.to_string());
    }
    // Coin `i` confirmed at height `i + 1`; the last is attestable once the
    // tip is `ATTESTABLE_AFTER` above it.
    node.mine_blocks(ATTESTABLE_AFTER, BURN);
    let outpoints: Vec<String> =
        (1..=holders.len() as u64).map(|h| format!("{}:0", coinbase_txid_at(&node, h))).collect();

    // Not yet old enough: one block short, at the anchor.
    let young = node.rpc_call_with_params(
        "createnapattestation",
        vec![json!(format!("{}:0", coinbase_txid_at(&node, 7))), json!("k"), json!("v")],
    );
    let (code, msg) = error_of(young.unwrap());
    assert_eq!(code, -26);
    assert!(msg.contains("coin-too-young"), "{msg}");

    for (h, op) in holders.iter().zip(&outpoints) {
        let draft = node.rpc_ok("createnapattestation", vec![json!(op), json!("bip_xyz.support"), json!("yes")]);
        assert_eq!(draft["address"], json!(h.address.to_string()), "{}", h.name);
        assert_eq!(draft["formats"], h.formats, "{}", h.name);
        assert_eq!(draft["warnings"], json!([]), "{}", h.name);
        let message = draft["message"].as_str().unwrap();
        let signature = (h.sign)(&node, message);

        // A signature over other text is refused, naming the rule.
        let other = message.replace("value: yes", "value: no");
        let r = node.rpc_call_with_params("submitnapattestation", vec![json!(other), json!(signature)]).unwrap();
        let (code, msg) = error_of(r);
        assert_eq!(code, -26, "{}", h.name);
        assert!(msg.contains("signature-invalid"), "{}: {msg}", h.name);

        let stored = node.rpc_ok("submitnapattestation", vec![json!(message), json!(signature)]);
        assert_eq!(stored["status"], "valid", "{}: {stored}", h.name);
        assert_eq!(stored["outpoint"], json!(op));
        assert_eq!(stored["amount"].as_f64(), Some(50.0), "{}", h.name);
        assert_eq!(stored["replaced"], Value::Null);
    }
    let before = list(&node);
    assert_eq!(before.len(), holders.len());
    assert!(before.iter().all(|a| a["status"] == "valid"), "{before:?}");
    let formats: Vec<&str> = before.iter().map(|a| a["format"].as_str().unwrap()).collect();
    for f in ["simple", "full", "legacy"] {
        assert!(formats.contains(&f), "{formats:?}");
    }

    // The store survives a restart.
    node.stop();
    let mut node = TestNode::start_with_datadir(&datadir, rpcport, &["--nap=1"]);
    assert_eq!(list(&node), before);

    // Spending a coin drops its attestation.
    let wallet = DeterministicWallet::from_secret([1; 32]);
    assert_eq!(wallet.address, holders[0].address);
    let (raw, _) = build_signed_p2wpkh_spend_of_coinbase(&node, &wallet, 1, wallet.address.script_pubkey(), 1_000);
    node.rpc_ok("sendrawtransaction", vec![json!(raw)]);
    node.mine_blocks(1, BURN);
    poll_until(|| list(&node).len() == holders.len() - 1, test_timeout(60), "the spent coin's attestation is dropped");
    assert!(list(&node).iter().all(|a| a["outpoint"] != json!(outpoints[0])));

    // Removing one stops publishing it.
    let removed = node.rpc_ok("removenapattestation", vec![json!(outpoints[5]), json!("bip_xyz.support")]);
    let p2pkh = before.iter().find(|a| a["outpoint"] == json!(outpoints[5])).unwrap();
    assert_eq!(p2pkh["format"], "legacy");
    assert_eq!(removed["id"], p2pkh["id"]);
    let r = node.rpc_call_with_params("removenapattestation", vec![json!(outpoints[5]), json!("bip_xyz.support")]);
    assert_eq!(error_of(r.unwrap()).0, -8);
    assert_eq!(list(&node).len(), holders.len() - 2);

    // A reorg that replaces the anchor block: every attestation loses its
    // anchor, stays stored, and the operator is warned.
    let anchor = before[1]["anchor_hash"].as_str().unwrap().to_string();
    node.rpc_ok("invalidateblock", vec![json!(anchor)]);
    node.mine_blocks(12, &holders[1].address.to_string());
    poll_until(
        || list(&node).iter().all(|a| a["status"] == "anchor-not-on-chain"),
        test_timeout(60),
        "every attestation lost its anchor",
    );
    assert_eq!(list(&node).len(), holders.len() - 2);
    poll_until(
        || {
            std::fs::read_to_string(&node.stderr_log)
                .is_ok_and(|log| log.contains("a reorg removed the anchor block of a published attestation"))
        },
        test_timeout(60),
        "the operator is warned about the lost anchor",
    );
    node.stop();
    let _ = std::fs::remove_dir_all(&datadir);
}

/// Without `-nap=1` the NAP RPCs exist but refuse, and nothing is stored.
#[test]
fn nap_rpcs_need_the_flag() {
    let mut node = TestNode::start(&[]);
    let r = node.rpc_call_with_params("listnapattestations", vec![]).unwrap();
    let (code, msg) = error_of(r);
    assert_eq!(code, -1);
    assert!(msg.contains("NAP is disabled"), "{msg}");
    assert!(!node.datadir.join("regtest").join("nap").exists());
    node.stop();
}
