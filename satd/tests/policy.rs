//! End-to-end regtest tests for the transaction-filtering / quarantine policy
//! engine (the `satd-policy` crate, design §1–§10).
//!
//! These exercise the engine through a *live* satd node — the layers below the
//! `satd-policy` unit tests, which only ever see a synthetic `TxView`:
//!
//! * **Layer A — `policytest` dry-run verdict matrix.** Load the documented §17
//!   cookbook and assert the decisive rule / verdict / placement scope for a
//!   crafted matching transaction (and a non-matching control) per rule. This
//!   pins the published cookbook to actual engine behaviour: if the DSL or its
//!   semantics drift, these break. `policytest` skips standardness, so it can
//!   evaluate transactions a relay node would reject for other reasons.
//! * **Layer B — single-node submission semantics.** The §6.1 local-submission
//!   refusal, the `allowquarantined` override, and two-class mempool visibility
//!   (a quarantined tx is invisible to `getrawmempool` but present via
//!   `getquarantineentry`).
//! * **Layer C — multi-node gossip + scope re-relay.** A spam tx submitted to a
//!   policy-free node A, gossiped to a policy-bearing node B: acting in A,
//!   quarantined-and-hidden in B. Plus the `relay`/`template` scope distinction
//!   verified by whether B re-gossips onward to a third node C.
//!
//! Crafted transactions spend matured regtest coinbases (the warmup mines 110
//! blocks to a deterministic wallet, so coinbases 1..=10 are spendable 50-BTC
//! P2WPKH outputs). Policy-bearing nodes that need to admit otherwise-non-
//! standard spam (oversized OP_RETURN, dust storms, big witnesses) run with
//! `--acceptnonstdtxn` so the *policy* — not standard relay — is what holds the
//! transaction; inscriptions and runestones are standard and need no relaxation.

mod common;

use common::{find_available_port, get_rpc_u64, poll_until, test_timeout, DeterministicWallet, TestNode};

use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all as op;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Cookbook policies (verbatim from the Operator Manual §17 / satd-policy
// integration tests). Kept as source strings so a drift in the published
// cookbook surfaces here.
// ---------------------------------------------------------------------------

/// The full documented cookbook **without** the `allow own-submissions` rule.
/// `policytest` hardcodes `tx.source == rpc`, so an allow-on-source rule would
/// short-circuit every dry-run to `allow`; the allow rule is exercised on its
/// own through the gossip path (Layer C), where the source actually differs.
const COOKBOOK_NO_ALLOW: &str = r#"version 1

quarantine ordinals on relay,template
    when any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))

quarantine atomicals
    when any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x61746f6d))))

quarantine runes
    when any outputs (out.script.contains_ops(script(OP_RETURN OP_PUSHNUM_13 *)))

quarantine stamps-baremultisig when any outputs (out.script_type == bare_multisig)

quarantine cheap-bulk-opreturn
    when any outputs (out.script_type == op_return and out.op_return_size > 83)
         and tx.fee_rate < node.min_relay_fee * 3

quarantine dust-storm
    when count outputs (out.is_dust and out.script_type != p2a) >= 5

quarantine no-mine-big-witness on template when tx.total_witness_size > 100kb
"#;

/// The full cookbook including the `allow own-submissions` exception first.
/// Used by the gossip layer where `tx.source` actually distinguishes a local
/// RPC submission (allowed) from a peer-relayed one (filtered).
const COOKBOOK_FULL: &str = r#"version 1

allow own-submissions when tx.source == rpc or tx.source == mcp

quarantine runes
    when any outputs (out.script.contains_ops(script(OP_RETURN OP_PUSHNUM_13 *)))
"#;

/// A single relay-scoped runes rule: a relay-withheld quarantine refuses local
/// submission (§6.1) and is not re-gossiped onward.
const RUNES_RELAY_ONLY: &str = "version 1\nquarantine runes on relay when any outputs (out.script.contains_ops(script(OP_RETURN OP_PUSHNUM_13 *)))\n";

/// A single template-scoped runes rule: still relays (so it re-gossips and does
/// not refuse local submission) but is withheld from block templates.
const RUNES_TEMPLATE_ONLY: &str = "version 1\nquarantine runes on template when any outputs (out.script.contains_ops(script(OP_RETURN OP_PUSHNUM_13 *)))\n";

/// Regtest coinbase subsidy for blocks 1..=150 (no halving before 150): 50 BTC.
const CB_VALUE_SAT: u64 = 50 * 100_000_000;

// ---------------------------------------------------------------------------
// Policy-file fixture
// ---------------------------------------------------------------------------

/// A policy file written to a temp dir, kept alive so the path stays valid for
/// the node's lifetime. `--policyfile` requires an absolute path; `tempfile`
/// gives one.
struct PolicyFile {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn write_policy(src: &str) -> PolicyFile {
    use std::io::Write as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.policy");
    let mut f = std::fs::File::create(&path).expect("create policy file");
    f.write_all(src.as_bytes()).expect("write policy file");
    PolicyFile { _dir: dir, path }
}

// ---------------------------------------------------------------------------
// Node bootstrap + funding
// ---------------------------------------------------------------------------

/// A deterministic regtest wallet whose address received the warmup coinbases.
/// Fixed secret so the matured coinbases are reproducible across runs.
fn test_wallet() -> DeterministicWallet {
    DeterministicWallet::from_secret([7u8; 32])
}

/// Start a regtest node, optionally loading `policy_src`, and mine 110 blocks to
/// the deterministic wallet so coinbases 1..=10 are mature (COINBASE_MATURITY =
/// 100). Returns the node and the wallet. Extra args are appended verbatim.
fn start_funded(policy_src: Option<&str>, extra_args: &[&str]) -> (TestNode, DeterministicWallet, Option<PolicyFile>) {
    let wallet = test_wallet();
    let policy = policy_src.map(write_policy);
    let mut args: Vec<String> = Vec::new();
    if let Some(pf) = &policy {
        args.push(format!("--policyfile={}", pf.path.display()));
    }
    for a in extra_args {
        args.push((*a).to_string());
    }
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let node = TestNode::start(&arg_refs);
    mine_to(&node, 110, &wallet);
    (node, wallet, policy)
}

/// Mine `n` blocks to the wallet's address.
fn mine_to(node: &TestNode, n: u32, wallet: &DeterministicWallet) {
    node.rpc_call_with_params(
        "generatetoaddress",
        vec![json!(n), json!(wallet.address.to_string())],
    )
    .expect("generatetoaddress");
}

/// The txid of the coinbase mined into block `height` (output 0 pays the wallet).
fn coinbase_txid_at(node: &TestNode, height: u64) -> bitcoin::Txid {
    let hash = node
        .rpc_call_with_params("getblockhash", vec![json!(height)])
        .expect("getblockhash")["result"]
        .as_str()
        .expect("block hash")
        .to_string();
    let txid = node
        .rpc_call_with_params("getblock", vec![json!(hash), json!(1)])
        .expect("getblock")["result"]["tx"][0]
        .as_str()
        .expect("coinbase txid")
        .to_string();
    bitcoin::Txid::from_str(&txid).expect("txid parse")
}

/// Build + sign a P2WPKH spend of the coinbase at `cb_height` paying `outputs`,
/// with `fee_sat` left to fee (the remainder returns to the wallet as P2WPKH
/// change unless it would be zero). Returns `(raw_hex, txid_hex)`.
fn build_spend(
    node: &TestNode,
    wallet: &DeterministicWallet,
    cb_height: u64,
    mut outputs: Vec<TxOut>,
    fee_sat: u64,
) -> (String, String) {
    use bitcoin::hashes::Hash as _;
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};

    let cb_txid = coinbase_txid_at(node, cb_height);
    let spent: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
    let change = CB_VALUE_SAT
        .checked_sub(spent + fee_sat)
        .expect("outputs + fee exceed coinbase value");
    if change > 0 {
        outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: wallet.address.script_pubkey(),
        });
    }

    let mut spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cb_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    };

    let secp = Secp256k1::new();
    let src_script = wallet.address.script_pubkey();
    let mut cache = SighashCache::new(&spend);
    let sighash = cache
        .p2wpkh_signature_hash(0, &src_script, Amount::from_sat(CB_VALUE_SAT), EcdsaSighashType::All)
        .expect("sighash");
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &wallet.sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(wallet.pk.to_bytes());
    spend.input[0].witness = witness;

    let raw_hex = hex::encode(bitcoin::consensus::serialize(&spend));
    let txid_hex = spend.compute_txid().to_string();
    (raw_hex, txid_hex)
}

// ---------------------------------------------------------------------------
// Output / script constructors
// ---------------------------------------------------------------------------

/// An OP_RETURN output carrying `payload_len` bytes (value 0).
fn op_return_output(payload_len: usize) -> TxOut {
    let pb = PushBytesBuf::try_from(vec![0x2au8; payload_len]).expect("push bytes");
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(pb),
    }
}

/// A runestone-style OP_RETURN: `OP_RETURN OP_PUSHNUM_13 <push>`.
fn runestone_output() -> TxOut {
    let pb = PushBytesBuf::try_from(vec![0x01u8, 0x02, 0x03, 0x04]).expect("push bytes");
    let script = Builder::new()
        .push_opcode(op::OP_RETURN)
        .push_opcode(op::OP_PUSHNUM_13)
        .push_slice(pb)
        .into_script();
    TxOut {
        value: Amount::ZERO,
        script_pubkey: script,
    }
}

/// A bare 1-of-1 multisig output (`OP_1 <pubkey> OP_1 OP_CHECKMULTISIG`).
fn bare_multisig_output(wallet: &DeterministicWallet, value_sat: u64) -> TxOut {
    let script = Builder::new()
        .push_int(1)
        .push_key(&wallet.pk)
        .push_int(1)
        .push_opcode(op::OP_CHECKMULTISIG)
        .into_script();
    TxOut {
        value: Amount::from_sat(value_sat),
        script_pubkey: script,
    }
}

/// A dust P2WPKH output (1 sat — well below the dust threshold).
fn dust_output(wallet: &DeterministicWallet) -> TxOut {
    TxOut {
        value: Amount::from_sat(1),
        script_pubkey: wallet.address.script_pubkey(),
    }
}

/// A normal non-matching P2WPKH payment output.
fn payment_output(wallet: &DeterministicWallet, value_sat: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(value_sat),
        script_pubkey: wallet.address.script_pubkey(),
    }
}

// ---------------------------------------------------------------------------
// RPC helpers
// ---------------------------------------------------------------------------

/// Run `policytest` against the loaded ruleset and return the `result` object.
fn policytest(node: &TestNode, raw_hex: &str) -> Value {
    let resp = node
        .rpc_call_with_params("policytest", vec![json!(raw_hex)])
        .expect("policytest rpc");
    assert!(
        resp.get("error").map(|e| e.is_null()).unwrap_or(true),
        "policytest returned error: {resp}"
    );
    resp["result"].clone()
}

/// Assert a `policytest` result quarantines under `rule` with the given scope.
fn assert_quarantined(res: &Value, rule: &str, relay: bool, template: bool) {
    assert_eq!(res["verdict"], json!("quarantine"), "verdict for {rule}: {res}");
    assert_eq!(res["decisive_rule"], json!(rule), "decisive rule: {res}");
    assert_eq!(res["placement"]["class"], json!("quarantine"), "class: {res}");
    assert_eq!(
        res["placement"]["scope"]["relay"],
        json!(relay),
        "relay scope for {rule}: {res}"
    );
    assert_eq!(
        res["placement"]["scope"]["template"],
        json!(template),
        "template scope for {rule}: {res}"
    );
}

// ===========================================================================
// Layer A — policytest dry-run verdict matrix
// ===========================================================================

#[test]
fn layer_a_runes_quarantined() {
    let (mut node, wallet, _pf) = start_funded(Some(COOKBOOK_NO_ALLOW), &[]);
    let (raw, _txid) = build_spend(&node, &wallet, 1, vec![runestone_output()], 1_000);
    let res = policytest(&node, &raw);
    // Default scope (no `on` clause) withholds both relay and template.
    assert_quarantined(&res, "runes", true, true);
    node.stop();
}

#[test]
fn layer_a_bare_multisig_quarantined() {
    let (mut node, wallet, _pf) = start_funded(Some(COOKBOOK_NO_ALLOW), &[]);
    let (raw, _txid) = build_spend(
        &node,
        &wallet,
        1,
        vec![bare_multisig_output(&wallet, 100_000)],
        1_000,
    );
    let res = policytest(&node, &raw);
    assert_quarantined(&res, "stamps-baremultisig", true, true);
    node.stop();
}

#[test]
fn layer_a_cheap_bulk_opreturn_quarantined_but_high_fee_passes() {
    let (mut node, wallet, _pf) = start_funded(Some(COOKBOOK_NO_ALLOW), &[]);

    // Matching: 84-byte OP_RETURN payload (> 83) at a low fee (< min_relay*3).
    let (raw_low, _) = build_spend(&node, &wallet, 1, vec![op_return_output(84)], 200);
    let res = policytest(&node, &raw_low);
    assert_quarantined(&res, "cheap-bulk-opreturn", true, true);

    // Control: same oversized OP_RETURN but a high fee ⇒ the `and fee_rate <`
    // clause fails ⇒ no rule matches ⇒ pass.
    let (raw_high, _) = build_spend(&node, &wallet, 2, vec![op_return_output(84)], 1_000_000);
    let res = policytest(&node, &raw_high);
    assert_eq!(res["verdict"], json!("pass"), "high-fee bulk OP_RETURN: {res}");
    assert_eq!(res["placement"]["class"], json!("acting"));

    node.stop();
}

#[test]
fn layer_a_dust_storm_quarantined() {
    let (mut node, wallet, _pf) = start_funded(Some(COOKBOOK_NO_ALLOW), &[]);
    let outputs: Vec<TxOut> = (0..5).map(|_| dust_output(&wallet)).collect();
    let (raw, _txid) = build_spend(&node, &wallet, 1, outputs, 1_000);
    let res = policytest(&node, &raw);
    assert_quarantined(&res, "dust-storm", true, true);

    // Control: only 4 dust outputs ⇒ count < 5 ⇒ pass.
    let four: Vec<TxOut> = (0..4).map(|_| dust_output(&wallet)).collect();
    let (raw4, _) = build_spend(&node, &wallet, 2, four, 1_000);
    let res = policytest(&node, &raw4);
    assert_eq!(res["verdict"], json!("pass"), "4-dust control: {res}");

    node.stop();
}

#[test]
fn layer_a_plain_payment_passes() {
    let (mut node, wallet, _pf) = start_funded(Some(COOKBOOK_NO_ALLOW), &[]);
    let (raw, _txid) = build_spend(&node, &wallet, 1, vec![payment_output(&wallet, 1_000_000)], 1_000);
    let res = policytest(&node, &raw);
    assert_eq!(res["verdict"], json!("pass"), "plain payment: {res}");
    assert_eq!(res["placement"]["class"], json!("acting"));
    node.stop();
}

#[test]
fn layer_a_unloaded_node_reports_not_loaded() {
    let (mut node, wallet, _pf) = start_funded(None, &[]);
    let (raw, _txid) = build_spend(&node, &wallet, 1, vec![payment_output(&wallet, 1_000_000)], 1_000);
    let res = policytest(&node, &raw);
    assert_eq!(res["loaded"], json!(false), "no policy loaded: {res}");
    node.stop();
}

// ---------------------------------------------------------------------------
// Taproot inscription (commit→reveal) construction
// ---------------------------------------------------------------------------

/// Inscription-envelope tapleaf, matching the engine's `ord_leaf` test vector:
/// `<32B x-only pubkey> OP_CHECKSIG OP_FALSE OP_IF push(marker) push("text/plain")
/// OP_ENDIF`. `marker` is the self-identifying protocol tag the cookbook keys on
/// (`b"ord"` → `0x6f7264`, `b"atom"` → `0x61746f6d`).
fn inscription_leaf(insc_xonly: &bitcoin::XOnlyPublicKey, marker: &[u8]) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(insc_xonly)
        .push_opcode(op::OP_CHECKSIG)
        .push_opcode(op::OP_PUSHBYTES_0) // OP_FALSE / OP_0
        .push_opcode(op::OP_IF)
        .push_slice(PushBytesBuf::try_from(marker.to_vec()).expect("marker push"))
        .push_slice(PushBytesBuf::try_from(b"text/plain".to_vec()).expect("mime push"))
        .push_opcode(op::OP_ENDIF)
        .into_script()
}

/// Build a real commit→reveal inscription pair. The commit funds a P2TR output
/// committing to the inscription tapleaf (from the coinbase at `cb_height`); the
/// reveal is a script-path spend whose witness exposes the tapleaf, so the
/// engine sees the envelope in `in.leaf_script`. Returns
/// `(commit_raw, commit_txid, reveal_raw, reveal_txid)`. The caller must mine
/// the commit before evaluating/submitting the reveal so its prevout resolves.
fn build_inscription_pair(
    node: &TestNode,
    wallet: &DeterministicWallet,
    cb_height: u64,
    marker: &[u8],
) -> (String, String, String, String) {
    use bitcoin::hashes::Hash as _;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};

    let secp = Secp256k1::new();
    let insc_kp = Keypair::from_seckey_slice(&secp, &[9u8; 32]).expect("inscription key");
    let insc_xonly = insc_kp.x_only_public_key().0;
    let internal_kp = Keypair::from_seckey_slice(&secp, &[11u8; 32]).expect("internal key");
    let internal_xonly = internal_kp.x_only_public_key().0;

    let leaf = inscription_leaf(&insc_xonly, marker);
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .expect("add leaf")
        .finalize(&secp, internal_xonly)
        .expect("finalize taproot");
    let p2tr_spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

    // Commit: a single P2TR output (vout 0) plus wallet change (vout 1).
    let commit_value: u64 = 10_000_000;
    let p2tr_out = TxOut {
        value: Amount::from_sat(commit_value),
        script_pubkey: p2tr_spk.clone(),
    };
    let (commit_raw, commit_txid_hex) = build_spend(node, wallet, cb_height, vec![p2tr_out], 1_000);
    let commit_txid = bitcoin::Txid::from_str(&commit_txid_hex).expect("commit txid");

    // Reveal: script-path spend of the commit's P2TR output.
    let prevout = TxOut {
        value: Amount::from_sat(commit_value),
        script_pubkey: p2tr_spk,
    };
    let reveal_fee: u64 = 5_000;
    let mut reveal = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: commit_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![payment_output(wallet, commit_value - reveal_fee)],
    };

    let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
    let sighash = SighashCache::new(&reveal)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .expect("taproot sighash");
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &insc_kp);
    let control_block = spend_info
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .expect("control block");

    let mut witness = Witness::new();
    witness.push(sig.as_ref()); // 64-byte schnorr (SIGHASH_DEFAULT: no type byte)
    witness.push(leaf.as_bytes());
    witness.push(control_block.serialize());
    reveal.input[0].witness = witness;

    let reveal_raw = hex::encode(bitcoin::consensus::serialize(&reveal));
    let reveal_txid = reveal.compute_txid().to_string();
    (commit_raw, commit_txid_hex, reveal_raw, reveal_txid)
}

/// Submit a raw tx and assert it was accepted, returning the txid.
fn send_ok(node: &TestNode, raw: &str) -> String {
    let resp = node
        .rpc_call_with_params("sendrawtransaction", vec![json!(raw)])
        .expect("sendrawtransaction rpc");
    assert!(
        resp.get("error").map(|e| e.is_null()).unwrap_or(true),
        "sendrawtransaction rejected: {resp}"
    );
    resp["result"].as_str().expect("txid").to_string()
}

/// True if `txid` is present in the node's acting mempool (`getrawmempool`).
fn mempool_has(node: &TestNode, txid: &str) -> bool {
    node.rpc_call("getrawmempool")
        .ok()
        .and_then(|r| r["result"].as_array().cloned())
        .map(|a| a.iter().any(|v| v.as_str() == Some(txid)))
        .unwrap_or(false)
}

/// True if `txid` is held in the node's quarantine class (`getquarantineentry`).
fn quarantine_has(node: &TestNode, txid: &str) -> bool {
    node.rpc_call_with_params("getquarantineentry", vec![json!(txid)])
        .ok()
        .map(|r| r["error"].is_null() && r["result"]["txid"] == json!(txid))
        .unwrap_or(false)
}

#[test]
fn layer_a_ordinals_quarantined() {
    let (mut node, wallet, _pf) = start_funded(Some(COOKBOOK_NO_ALLOW), &[]);
    let (commit_raw, _ctxid, reveal_raw, _rtxid) =
        build_inscription_pair(&node, &wallet, 1, b"ord");
    // Mine the commit so the reveal's prevout resolves for policytest.
    send_ok(&node, &commit_raw);
    mine_to(&node, 1, &wallet);
    let res = policytest(&node, &reveal_raw);
    assert_quarantined(&res, "ordinals", true, true);
    node.stop();
}

#[test]
fn layer_a_atomicals_quarantined() {
    let (mut node, wallet, _pf) = start_funded(Some(COOKBOOK_NO_ALLOW), &[]);
    let (commit_raw, _ctxid, reveal_raw, _rtxid) =
        build_inscription_pair(&node, &wallet, 1, b"atom");
    send_ok(&node, &commit_raw);
    mine_to(&node, 1, &wallet);
    let res = policytest(&node, &reveal_raw);
    assert_quarantined(&res, "atomicals", true, true);
    node.stop();
}

// ===========================================================================
// Layer B — single-node submission semantics
// ===========================================================================

#[test]
fn layer_b_local_submission_refused_for_relay_quarantine() {
    let (mut node, wallet, _pf) = start_funded(Some(COOKBOOK_NO_ALLOW), &[]);
    let (raw, _txid) = build_spend(&node, &wallet, 1, vec![runestone_output()], 1_000);
    let resp = node
        .rpc_call_with_params("sendrawtransaction", vec![json!(raw)])
        .expect("sendrawtransaction rpc");
    let err = &resp["error"];
    assert!(!err.is_null(), "expected §6.1 refusal, got: {resp}");
    assert_eq!(err["code"], json!(-25), "refusal code: {resp}");
    let blob = err.to_string();
    assert!(
        blob.contains("txn-policy-quarantined"),
        "refusal message: {blob}"
    );
    assert!(blob.contains("runes"), "refusal names the rule: {blob}");
    node.stop();
}

#[test]
fn layer_b_allowquarantined_holds_and_is_two_class_invisible() {
    let (mut node, wallet, _pf) = start_funded(Some(COOKBOOK_NO_ALLOW), &[]);
    let (raw, txid) = build_spend(&node, &wallet, 1, vec![runestone_output()], 1_000);

    // allowquarantined=true (2nd positional) ⇒ held instead of refused.
    let resp = node
        .rpc_call_with_params("sendrawtransaction", vec![json!(raw), json!(true)])
        .expect("sendrawtransaction rpc");
    assert!(resp["error"].is_null(), "allowquarantined should accept: {resp}");
    assert_eq!(resp["result"], json!(txid));

    // Invisible to standard surfaces.
    assert!(!mempool_has(&node, &txid), "quarantined tx leaked into getrawmempool");
    let mi = node.rpc_call("getmempoolinfo").expect("getmempoolinfo");
    assert_eq!(mi["result"]["size"], json!(0), "acting mempool not empty: {mi}");

    // Visible via the quarantine surface, with the rule + scope.
    let qe = node
        .rpc_call_with_params("getquarantineentry", vec![json!(txid)])
        .expect("getquarantineentry");
    assert!(qe["error"].is_null(), "getquarantineentry errored: {qe}");
    assert_eq!(qe["result"]["rule"], json!("runes"));
    assert_eq!(qe["result"]["scope"]["relay"], json!(true));

    // And in the paged listing.
    let list = node
        .rpc_call_with_params("listquarantine", vec![])
        .expect("listquarantine");
    let arr = list["result"].as_array().expect("array");
    assert!(
        arr.iter().any(|e| e["txid"] == json!(txid)),
        "txid missing from listquarantine: {list}"
    );
    node.stop();
}

#[test]
fn layer_b_template_only_local_submission_not_refused() {
    let (mut node, wallet, _pf) = start_funded(Some(RUNES_TEMPLATE_ONLY), &[]);
    let (raw, txid) = build_spend(&node, &wallet, 1, vec![runestone_output()], 1_000);

    // A template-only quarantine still relays, so §6.1 does not refuse it.
    let resp = node
        .rpc_call_with_params("sendrawtransaction", vec![json!(raw)])
        .expect("sendrawtransaction rpc");
    assert!(
        resp["error"].is_null(),
        "template-only must not refuse local submission: {resp}"
    );

    let qe = node
        .rpc_call_with_params("getquarantineentry", vec![json!(txid)])
        .expect("getquarantineentry");
    assert!(qe["error"].is_null(), "expected quarantine entry: {qe}");
    assert_eq!(qe["result"]["scope"]["template"], json!(true));
    assert_eq!(qe["result"]["scope"]["relay"], json!(false));
    node.stop();
}

// ===========================================================================
// Layer C — multi-node gossip + scope re-relay
// ===========================================================================

/// Wait for a node to reach at least `height`.
fn wait_height(node: &TestNode, height: u64, what: &str) {
    poll_until(
        || get_rpc_u64(node, "getblockcount").unwrap_or(0) >= height,
        test_timeout(60),
        what,
    );
}

#[test]
fn layer_c_gossiped_spam_is_quarantined_on_policy_node() {
    let wallet = test_wallet();
    let p2p_a = find_available_port();
    let mut node_a = TestNode::start(&[&format!("--port={}", p2p_a)]);
    let pf = write_policy(COOKBOOK_NO_ALLOW);
    let mut node_b = TestNode::start(&[
        &format!("--connect=127.0.0.1:{}", p2p_a),
        &format!("--policyfile={}", pf.path.display()),
        "--acceptnonstdtxn",
    ]);

    poll_until(
        || get_rpc_u64(&node_a, "getconnectioncount").unwrap_or(0) >= 1,
        test_timeout(30),
        "A and B did not connect",
    );

    // A mines; B syncs the chain (block relay is unaffected by tx policy).
    mine_to(&node_a, 110, &wallet);
    wait_height(&node_b, 110, "B did not sync to A");

    // Spam submitted to the policy-free node A ⇒ acting there.
    let (raw, txid) = build_spend(&node_a, &wallet, 1, vec![runestone_output()], 1_000);
    send_ok(&node_a, &raw);
    poll_until(|| mempool_has(&node_a, &txid), test_timeout(20), "tx not acting on A");

    // Gossiped to B, the policy node ⇒ quarantined, hidden from standard surfaces.
    poll_until(
        || quarantine_has(&node_b, &txid),
        test_timeout(30),
        "tx not quarantined on B",
    );
    assert!(!mempool_has(&node_b, &txid), "quarantined tx leaked into B getrawmempool");

    node_a.stop();
    node_b.stop();
}

#[test]
fn layer_c_allow_own_submission_but_quarantine_when_gossiped() {
    let wallet = test_wallet();
    let p2p_a = find_available_port();
    let mut node_a = TestNode::start(&[&format!("--port={}", p2p_a)]);
    let pf = write_policy(COOKBOOK_FULL);
    let mut node_b = TestNode::start(&[
        &format!("--connect=127.0.0.1:{}", p2p_a),
        &format!("--policyfile={}", pf.path.display()),
        "--acceptnonstdtxn",
    ]);
    poll_until(
        || get_rpc_u64(&node_a, "getconnectioncount").unwrap_or(0) >= 1,
        test_timeout(30),
        "A and B did not connect",
    );
    mine_to(&node_a, 110, &wallet);
    wait_height(&node_b, 110, "B did not sync to A");

    // (1) Runestone submitted *directly* to B over RPC ⇒ `allow own-submissions`
    // matches (source == rpc) ⇒ acting on B.
    let (raw1, txid1) = build_spend(&node_b, &wallet, 1, vec![runestone_output()], 1_000);
    send_ok(&node_b, &raw1);
    poll_until(|| mempool_has(&node_b, &txid1), test_timeout(20), "own submission not acting on B");
    assert!(!quarantine_has(&node_b, &txid1), "own submission wrongly quarantined");

    // (2) An identical-shape runestone submitted to A and *gossiped* to B
    // arrives with source == p2p ⇒ the allow rule does not match ⇒ quarantined.
    let (raw2, txid2) = build_spend(&node_a, &wallet, 2, vec![runestone_output()], 1_000);
    send_ok(&node_a, &raw2);
    poll_until(
        || quarantine_has(&node_b, &txid2),
        test_timeout(30),
        "gossiped runestone not quarantined on B",
    );
    assert!(!mempool_has(&node_b, &txid2), "gossiped runestone leaked into B mempool");

    node_a.stop();
    node_b.stop();
}

/// Three-node line A → B → C built with the `addnode` RPC (so the policy node B
/// keeps listening for C; Core's `-connect` would disable inbound). Returns the
/// three nodes after they are all connected and synced to `height`, with the
/// policy `policy_src` loaded on B. A and C run no policy.
fn three_node_line(policy_src: &str, height: u64) -> (TestNode, TestNode, TestNode, DeterministicWallet, PolicyFile) {
    let wallet = test_wallet();
    let p2p_a = find_available_port();
    let p2p_c = find_available_port();
    let node_a = TestNode::start(&[&format!("--port={}", p2p_a)]);
    let node_c = TestNode::start(&[&format!("--port={}", p2p_c)]);
    let pf = write_policy(policy_src);
    let node_b = TestNode::start(&[
        &format!("--policyfile={}", pf.path.display()),
        "--acceptnonstdtxn",
    ]);
    // B dials out to both A and C; B keeps listening (no -connect).
    node_b
        .rpc_call_with_params("addnode", vec![json!(format!("127.0.0.1:{}", p2p_a)), json!("add")])
        .expect("addnode A");
    node_b
        .rpc_call_with_params("addnode", vec![json!(format!("127.0.0.1:{}", p2p_c)), json!("add")])
        .expect("addnode C");
    poll_until(
        || get_rpc_u64(&node_b, "getconnectioncount").unwrap_or(0) >= 2,
        test_timeout(40),
        "B did not connect to both A and C",
    );

    mine_to(&node_a, height as u32, &wallet);
    wait_height(&node_b, height, "B did not sync");
    wait_height(&node_c, height, "C did not sync via B");
    (node_a, node_b, node_c, wallet, pf)
}

#[test]
fn layer_c_relay_scope_is_not_re_gossiped() {
    let (mut node_a, mut node_b, mut node_c, wallet, _pf) =
        three_node_line(RUNES_RELAY_ONLY, 110);

    let (raw, txid) = build_spend(&node_a, &wallet, 1, vec![runestone_output()], 1_000);
    send_ok(&node_a, &raw);

    // B quarantines it relay-withheld — wait on that as the positive signal that
    // B has fully processed the tx and made its relay decision.
    poll_until(
        || quarantine_has(&node_b, &txid),
        test_timeout(30),
        "tx not quarantined on B",
    );

    // A relay-withheld tx is never announced onward: C must not see it. B's relay
    // decision is made at admission, so by the time it is quarantined the (non-)
    // announcement has already happened; a short grace covers in-flight delivery.
    std::thread::sleep(test_timeout(5));
    assert!(
        !mempool_has(&node_c, &txid),
        "relay-withheld tx was re-gossiped to C"
    );
    assert!(!quarantine_has(&node_c, &txid), "C has no policy yet holds it");

    node_a.stop();
    node_b.stop();
    node_c.stop();
}

#[test]
fn layer_c_template_scope_still_re_gossips() {
    let (mut node_a, mut node_b, mut node_c, wallet, _pf) =
        three_node_line(RUNES_TEMPLATE_ONLY, 110);

    let (raw, txid) = build_spend(&node_a, &wallet, 1, vec![runestone_output()], 1_000);
    send_ok(&node_a, &raw);

    // Template-only withholding still relays, so B forwards to C, where (no
    // policy) it lands acting.
    poll_until(
        || mempool_has(&node_c, &txid),
        test_timeout(40),
        "template-scoped tx was not re-gossiped to C",
    );
    // On B itself it is quarantined (template-withheld), not acting.
    assert!(quarantine_has(&node_b, &txid), "tx should be quarantined on B");
    assert!(!mempool_has(&node_b, &txid), "template-withheld tx acting on B");

    node_a.stop();
    node_b.stop();
    node_c.stop();
}
