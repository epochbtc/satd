//! The passthrough proof: a BIP 375 PSBT survives every PSBT RPC.
//!
//! satd does not have to understand a field to be obliged to carry it. A PSBT
//! passes through several parties in turn, and a node that quietly drops an
//! unfamiliar pair breaks the next party's work in a way nobody notices until
//! the money has moved. Each test here feeds a surface a real BIP 375 vector
//! with extra unknown pairs planted in all three kinds of map, and demands
//! that every pair the surface had no reason to touch comes back with the
//! same bytes, in the same relative order.
//!
//! `utxoupdatepsbt` needs a UTXO set and so is proven in the regtest suite
//! instead; it is the one surface whose passthrough test cannot run here.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use node::rpc::psbt;
use satd_psbt::raw::{RawMap, RawPair, RawPsbt};
use satd_psbt::{keys, testing};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Vectors and planted unknowns
// ---------------------------------------------------------------------------

fn vectors(group: &str) -> Vec<(String, Vec<u8>)> {
    let doc: Value = serde_json::from_str(testing::BIP375_VECTORS).expect("vectors parse");
    doc[group]
        .as_array()
        .expect("a vector array")
        .iter()
        .map(|v| {
            (
                v["description"].as_str().unwrap_or_default().to_string(),
                B64.decode(v["psbt"].as_str().expect("base64")).expect("base64"),
            )
        })
        .collect()
}

fn bip370_valid() -> Vec<(String, Vec<u8>)> {
    let doc: Value = serde_json::from_str(testing::BIP370_VECTORS).expect("vectors parse");
    doc["valid"]
        .as_array()
        .expect("a vector array")
        .iter()
        .map(|v| {
            (
                v["description"].as_str().unwrap_or_default().to_string(),
                B64.decode(v["psbt"].as_str().expect("base64")).expect("base64"),
            )
        })
        .collect()
}

/// A key type no BIP has defined, so no code has an excuse to touch it.
const UNKNOWN_TYPE: u64 = 0x7a;

fn plant_unknowns(raw: &mut RawPsbt) {
    raw.global
        .set(RawPair::new(UNKNOWN_TYPE, b"global".to_vec(), b"g-value".to_vec()));
    for (i, map) in raw.inputs.iter_mut().enumerate() {
        map.set(RawPair::new(
            UNKNOWN_TYPE,
            format!("in{i}").into_bytes(),
            format!("i-value-{i}").into_bytes(),
        ));
    }
    for (i, map) in raw.outputs.iter_mut().enumerate() {
        map.set(RawPair::new(
            UNKNOWN_TYPE,
            format!("out{i}").into_bytes(),
            format!("o-value-{i}").into_bytes(),
        ));
    }
}

/// A BIP 375 vector with unknown pairs planted in every map.
fn seeded(description_prefix: &str) -> (String, RawPsbt) {
    let (description, bytes) = vectors("valid")
        .into_iter()
        .find(|(d, _)| d.starts_with(description_prefix))
        .unwrap_or_else(|| panic!("no vector starting {description_prefix:?}"));
    let mut raw = RawPsbt::parse(&bytes).expect("the vector parses");
    plant_unknowns(&mut raw);
    (description, raw)
}

fn to_b64(raw: &RawPsbt) -> String {
    B64.encode(raw.serialize())
}

fn from_b64(s: &str) -> RawPsbt {
    RawPsbt::parse(&B64.decode(s).expect("base64")).expect("the answer parses")
}

// ---------------------------------------------------------------------------
// The checker
// ---------------------------------------------------------------------------

/// Every pair `before` has that `after` should still have, byte for byte and
/// in the same relative order. Returns a description of each loss; an empty
/// vector means nothing was dropped, changed or moved.
fn losses(before: &RawPsbt, after: &RawPsbt, may_change: &[u64]) -> Vec<String> {
    losses_opt(before, after, may_change, true)
}

/// The same, without the ordering demand. Used for the documents a combiner
/// merges *into* a base: two documents cannot both keep their ordering, and
/// BIP 174 asks for neither. Values and presence still must hold.
fn losses_values(before: &RawPsbt, after: &RawPsbt, may_change: &[u64]) -> Vec<String> {
    losses_opt(before, after, may_change, false)
}

fn losses_opt(before: &RawPsbt, after: &RawPsbt, may_change: &[u64], order: bool) -> Vec<String> {
    let mut out = Vec::new();
    check_map("global map", &before.global, &after.global, may_change, order, &mut out);
    for (i, map) in before.inputs.iter().enumerate() {
        match after.inputs.get(i) {
            Some(a) => check_map(&format!("input {i}"), map, a, may_change, order, &mut out),
            None => out.push(format!("input {i}: gone entirely")),
        }
    }
    for (i, map) in before.outputs.iter().enumerate() {
        match after.outputs.get(i) {
            Some(a) => check_map(&format!("output {i}"), map, a, may_change, order, &mut out),
            None => out.push(format!("output {i}: gone entirely")),
        }
    }
    out
}

fn check_map(
    label: &str,
    before: &RawMap,
    after: &RawMap,
    may_change: &[u64],
    order: bool,
    out: &mut Vec<String>,
) {
    let kept: Vec<&RawPair> = before
        .pairs()
        .iter()
        .filter(|p| !may_change.contains(&p.key_type))
        .collect();

    for p in &kept {
        match after.get(p.key_type, &p.key_data) {
            Some(v) if v == p.value.as_slice() => {}
            Some(_) => out.push(format!("{label}: the value of {:#x} changed", p.key_type)),
            None => out.push(format!("{label}: {:#x} was dropped", p.key_type)),
        }
    }

    let positions: Vec<usize> = kept
        .iter()
        .filter_map(|p| {
            after
                .pairs()
                .iter()
                .position(|q| q.key_type == p.key_type && q.key_data == p.key_data)
        })
        .collect();
    if order && positions.windows(2).any(|w| w[0] >= w[1]) {
        out.push(format!("{label}: the relative order of its pairs changed"));
    }
}

/// The meta-test the other tests rest on: a checker that never fails is worth
/// nothing. `serialize_lossy` writes a PSBT with every unknown and BIP 375
/// pair dropped — the shape of codec this stack exists to avoid — and every
/// checker below must notice.
#[test]
fn the_loss_checker_notices_a_lossy_codec() {
    let (description, raw) = seeded("can finalize: two inputs single-signer using global");
    let lossy = RawPsbt::parse(&testing::serialize_lossy(&raw)).expect("still a PSBT");
    let found = losses(&raw, &lossy, &[]);
    assert!(
        !found.is_empty(),
        "{description}: a codec that strips unknown and BIP 375 pairs must be detected"
    );
    assert!(
        found.iter().any(|l| l.contains(&format!("{UNKNOWN_TYPE:#x}"))),
        "the planted unknown pairs should be among the losses: {found:?}"
    );
    assert!(
        found
            .iter()
            .any(|l| l.contains(&format!("{:#x}", keys::global::SP_ECDH_SHARE))),
        "the global ECDH share should be among the losses: {found:?}"
    );
}

// ---------------------------------------------------------------------------
// Surface by surface
// ---------------------------------------------------------------------------

/// `decodepsbt` emits no PSBT, so the passthrough assertion is that every BIP
/// 375 field and every unknown pair reaches the JSON with the right bytes.
#[test]
fn bip375_survives_decodepsbt() {
    let (description, raw) = seeded("can finalize: two inputs single-signer using per-input");
    let out = psbt::decode_psbt(&to_b64(&raw))
        .unwrap_or_else(|e| panic!("{description}: decodepsbt failed: {e:?}"));

    assert_eq!(out["psbt_version"], 2);
    assert_eq!(out["input_count"], raw.inputs.len());
    assert_eq!(out["output_count"], raw.outputs.len());

    // Unknown pairs, keyed by the hex of the whole key.
    assert_eq!(
        out["unknown"]["7a676c6f62616c"],
        Value::String(hex::encode("g-value")),
        "the global unknown pair is missing from the JSON: {out}"
    );
    for i in 0..raw.inputs.len() {
        let key = hex::encode(format!("\x7ain{i}").as_bytes());
        assert_eq!(
            out["inputs"][i]["unknown"][&key],
            Value::String(hex::encode(format!("i-value-{i}"))),
            "input {i}'s unknown pair is missing: {out}"
        );
    }
    for i in 0..raw.outputs.len() {
        let key = hex::encode(format!("\x7aout{i}").as_bytes());
        assert_eq!(
            out["outputs"][i]["unknown"][&key],
            Value::String(hex::encode(format!("o-value-{i}"))),
            "output {i}'s unknown pair is missing: {out}"
        );
    }

    // Every per-input ECDH share and proof, with its scan key.
    for (i, map) in raw.inputs.iter().enumerate() {
        for (scan_key, share) in map.get_all(keys::input::SP_ECDH_SHARE) {
            let rows = out["inputs"][i]["sp_shares"]
                .as_array()
                .unwrap_or_else(|| panic!("input {i} has no sp_shares: {out}"));
            let row = rows
                .iter()
                .find(|r| r["scan_key"] == hex::encode(scan_key))
                .unwrap_or_else(|| panic!("input {i} lost the share for a scan key: {out}"));
            assert_eq!(row["ecdh_share"], hex::encode(share));
            assert_eq!(
                row["dleq_proof"],
                hex::encode(map.get(keys::input::SP_DLEQ, scan_key).expect("a proof"))
            );
        }
    }

    // And every silent payment output's code.
    for (i, map) in raw.outputs.iter().enumerate() {
        let Some(info) = map.get_single(keys::output::SP_V0_INFO) else {
            continue;
        };
        assert_eq!(out["outputs"][i]["silent_payment"]["scan_key"], hex::encode(&info[..33]));
        assert_eq!(out["outputs"][i]["silent_payment"]["spend_key"], hex::encode(&info[33..]));
    }
}

/// Every vector, valid and invalid alike, must decode rather than be refused.
/// Refusing a structurally wrong PSBT here would take away the only tool an
/// operator has for finding out what is wrong with it.
#[test]
fn every_bip375_vector_decodes() {
    for group in ["valid", "invalid"] {
        for (description, bytes) in vectors(group) {
            let out = psbt::decode_psbt(&B64.encode(&bytes))
                .unwrap_or_else(|e| panic!("{group} {description}: {e:?}"));
            assert_eq!(out["psbt_version"], 2, "{description}");
        }
    }
}

/// `analyzepsbt` emits no PSBT either. What it must do is answer at all, say
/// the silent payments have not been verified, and never point past the
/// Signer while an output script is still uncomputed.
#[test]
fn bip375_survives_analyzepsbt() {
    let mut in_progress = 0usize;
    for group in ["valid", "invalid"] {
        for (description, bytes) in vectors(group) {
            let raw = RawPsbt::parse(&bytes).expect("parses");
            let out = psbt::analyze_psbt(&B64.encode(&bytes))
                .unwrap_or_else(|e| panic!("{description}: {e:?}"));

            let has_sp = raw
                .outputs
                .iter()
                .any(|o| o.contains_type(keys::output::SP_V0_INFO));
            if has_sp {
                assert_eq!(
                    out["silent_payments"]["verified"],
                    Value::Bool(false),
                    "{description}: a client must be able to tell \"not checked\" from \"fine\""
                );
            }

            let awaiting = raw.outputs.iter().any(|o| {
                o.contains_type(keys::output::SP_V0_INFO)
                    && o.get_single(keys::output::SCRIPT).is_none_or(|s| s.is_empty())
            });
            if awaiting {
                in_progress += 1;
                assert!(
                    out["next"] == "signer" || out["next"] == "updater",
                    "{description}: next was {} while an output script is uncomputed",
                    out["next"]
                );
            }
        }
    }
    assert!(in_progress > 0, "some vectors should still be awaiting a script");
}

#[test]
fn bip375_survives_combinepsbt() {
    let (description, raw) = seeded("can finalize: two inputs / two sp outputs with mixed");

    // Split the per-input shares across two halves, the way two signers
    // would, and combine them back.
    let mut left = raw.clone();
    let mut right = raw.clone();
    for map in &mut left.inputs {
        map.remove_type(keys::input::SP_ECDH_SHARE);
        map.remove_type(keys::input::SP_DLEQ);
    }
    right.global.remove_type(keys::global::SP_ECDH_SHARE);
    right.global.remove_type(keys::global::SP_DLEQ);

    let out = psbt::combine_psbt(&[to_b64(&left), to_b64(&right)])
        .unwrap_or_else(|e| panic!("{description}: combinepsbt failed: {e:?}"));
    let combined = from_b64(out.as_str().expect("a base64 PSBT"));

    // The first document is the base the merge builds on, so its pairs keep
    // their bytes *and* their positions. The second contributes what the base
    // lacks; its own ordering cannot survive a merge and BIP 174 does not ask
    // it to, so only its bytes are demanded. Between them the two halves hold
    // every pair of the original vector, so nothing goes unchecked.
    let found = losses(&left, &combined, &[]);
    assert!(found.is_empty(), "{description}: base half: {found:?}");
    let found = losses_values(&right, &combined, &[]);
    assert!(found.is_empty(), "{description}: merged half: {found:?}");
    let found = losses_values(&raw, &combined, &[]);
    assert!(
        found.is_empty(),
        "{description}: the combination lost pairs the halves had between them: {found:?}"
    );
}

/// Core's version 0 combiner keeps whichever value it saw first where a key is
/// present in both with different values. For an ECDH share that decides where
/// the money goes, so satd refuses and says which field.
#[test]
fn combinepsbt_refuses_a_conflicting_ecdh_share() {
    let (_, raw) = seeded("can finalize: two inputs single-signer using global");
    let mut tampered = raw.clone();
    let scan_key = raw
        .global
        .get_all(keys::global::SP_ECDH_SHARE)
        .next()
        .map(|(k, _)| k.to_vec())
        .expect("the vector has a global share");
    tampered.global.set(RawPair::new(
        keys::global::SP_ECDH_SHARE,
        scan_key,
        vec![0x02; 33],
    ));

    let err = psbt::combine_psbt(&[to_b64(&raw), to_b64(&tampered)])
        .expect_err("a conflicting share must be refused");
    assert_eq!(err.0, -22);
    assert!(
        err.1.contains("PSBT_GLOBAL_SP_ECDH_SHARE"),
        "the message should name the field, got: {}",
        err.1
    );
}

#[test]
fn combinepsbt_refuses_a_mix_of_versions() {
    let (_, v2) = seeded("can finalize: one P2PKH input");
    let v0 = v0_psbt();
    let err = psbt::combine_psbt(&[to_b64(&v2), v0]).expect_err("mixed versions must be refused");
    assert!(err.1.contains("version"), "got: {}", err.1);
}

#[test]
fn combinepsbt_refuses_two_different_transactions() {
    let (_, a) = seeded("can finalize: one P2PKH input");
    let (_, b) = seeded("can finalize: two inputs single-signer using global");
    let err = psbt::combine_psbt(&[to_b64(&a), to_b64(&b)])
        .expect_err("two different transactions must be refused");
    assert!(
        err.1.contains("different transaction"),
        "got: {}",
        err.1
    );
}

/// `joinpsbts` adds inputs and outputs, which changes the silent payment
/// shared secret and every script derived from it. A PSBT that has already
/// committed to that secret must be refused by name.
#[test]
fn bip375_survives_joinpsbts() {
    // Two in-progress PSBTs: no computed scripts, no global share, both
    // modifiable. This is the shape a coordinator actually joins.
    let a = joinable();
    let mut b = joinable();
    // Give the second one distinguishable unknowns.
    b.global
        .set(RawPair::new(UNKNOWN_TYPE, b"global".to_vec(), b"g-value".to_vec()));

    let out = psbt::join_psbts(&[to_b64(&a), to_b64(&b)])
        .unwrap_or_else(|e| panic!("joinpsbts failed: {e:?}"));
    let joined = from_b64(out.as_str().expect("a base64 PSBT"));

    assert_eq!(joined.inputs.len(), a.inputs.len() + b.inputs.len());
    assert_eq!(joined.outputs.len(), a.outputs.len() + b.outputs.len());

    // The first PSBT's maps keep their place and their bytes.
    let head = RawPsbt {
        global: joined.global.clone(),
        inputs: joined.inputs[..a.inputs.len()].to_vec(),
        outputs: joined.outputs[..a.outputs.len()].to_vec(),
    };
    let found = losses(
        &a,
        &head,
        // The counts are the one thing joining is supposed to change.
        &[keys::global::INPUT_COUNT, keys::global::OUTPUT_COUNT],
    );
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn joinpsbts_refuses_a_psbt_whose_sp_script_is_computed() {
    let (_, computed) = seeded("can finalize: one P2PKH input");
    let joinable = joinable();
    let err = psbt::join_psbts(&[to_b64(&joinable), to_b64(&computed)])
        .expect_err("a computed silent payment script must be refused");
    assert!(
        err.1.contains("already") && err.1.contains("computed"),
        "got: {}",
        err.1
    );
}

#[test]
fn joinpsbts_refuses_a_psbt_with_a_global_share() {
    let mut with_global = joinable();
    with_global.global.set(RawPair::new(
        keys::global::SP_ECDH_SHARE,
        vec![0x02; 33],
        vec![0x03; 33],
    ));
    with_global.global.set(RawPair::new(
        keys::global::SP_DLEQ,
        vec![0x02; 33],
        vec![0x00; 64],
    ));
    let err = psbt::join_psbts(&[to_b64(&joinable()), to_b64(&with_global)])
        .expect_err("a global share must be refused");
    assert!(err.1.contains("global ECDH share"), "got: {}", err.1);
}

/// `finalizepsbt` on a version 2 PSBT that has nothing to do with silent
/// payments: the version 0 finaliser does the work and everything else is
/// carried across untouched.
#[test]
fn bip375_survives_finalizepsbt() {
    // A BIP 370 vector, so there are no silent payment outputs to refuse.
    let (description, bytes) = bip370_valid()
        .into_iter()
        .find(|(d, _)| d.starts_with("1 input, 2 output updated PSBTv2, with all PSBTv2 fields"))
        .expect("the vector is in the file");
    let mut raw = RawPsbt::parse(&bytes).expect("parses");
    plant_unknowns(&mut raw);

    let out = psbt::finalize_psbt(&to_b64(&raw), false)
        .unwrap_or_else(|e| panic!("{description}: finalizepsbt failed: {e:?}"));
    let after = from_b64(out["psbt"].as_str().expect("a base64 PSBT"));

    // A Finalizer is allowed to clear the interim per-input fields and write
    // the final ones. Everything else must survive.
    let may_change = [
        keys::input::PARTIAL_SIG,
        keys::input::REDEEM_SCRIPT,
        keys::input::WITNESS_SCRIPT,
        keys::input::BIP32_DERIVATION,
        keys::input::TAP_KEY_SIG,
        keys::input::TAP_SCRIPT_SIG,
        keys::input::TAP_BIP32_DERIVATION,
        keys::input::TAP_INTERNAL_KEY,
        keys::input::TAP_MERKLE_ROOT,
    ];
    let found = losses(&raw, &after, &may_change);
    assert!(found.is_empty(), "{description}: {found:?}");
}

/// Until satd can recompute and check a silent payment output script, it must
/// not extract a transaction carrying one. Refusing is the safe floor.
#[test]
fn finalizepsbt_refuses_silent_payment_outputs_for_now() {
    let (_, raw) = seeded("can finalize: one P2PKH input");
    for extract in [true, false] {
        let err = psbt::finalize_psbt(&to_b64(&raw), extract)
            .expect_err("a silent payment PSBT must not be finalized yet");
        assert_eq!(err.0, -22);
        assert_eq!(
            err.1,
            "silent payment outputs cannot be finalized by this version"
        );
    }
}

/// The version 0 path must be exactly where it was. Its error text included:
/// a client that matches on "PSBT decode failed" keeps matching.
#[test]
fn version_0_errors_are_unchanged() {
    assert_eq!(
        psbt::decode_psbt("not base64 at all !!"),
        Err((-22, "PSBT base64 decode failed".to_string()))
    );
    assert_eq!(
        psbt::decode_psbt(&B64.encode(b"definitely not a psbt")),
        Err((-22, "PSBT decode failed".to_string()))
    );
    // A PSBT that declares version 2 gets the reason appended, which is new
    // surface and so cannot break a version 0 client.
    let mut truncated = satd_psbt::keys::MAGIC.to_vec();
    truncated.extend_from_slice(&[0x01, 0xfb, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00]);
    let err = psbt::decode_psbt(&B64.encode(&truncated)).expect_err("incomplete");
    assert_eq!(err.0, -22);
    assert!(err.1.starts_with("PSBT decode failed: "), "got: {}", err.1);
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A version 2 PSBT with a silent payment output, no computed script, no
/// global share, and both modifiable bits set: what a Constructor hands to a
/// coordinator.
fn joinable() -> RawPsbt {
    let (_, bytes) = vectors("valid")
        .into_iter()
        .find(|(d, _)| d.starts_with("in progress: one P2TR input / one sp output"))
        .expect("the vector is in the file");
    let mut raw = RawPsbt::parse(&bytes).expect("parses");
    raw.global.set(RawPair::new(
        keys::global::TX_MODIFIABLE,
        Vec::new(),
        vec![keys::modifiable::INPUTS | keys::modifiable::OUTPUTS],
    ));
    plant_unknowns(&mut raw);
    raw
}

fn v0_psbt() -> String {
    use bitcoin::hashes::Hash;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        absolute::LockTime, transaction::Version,
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([9u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_hex("0014c430f64c4756da310dbd1a085572ef299926272c")
                .unwrap(),
        }],
    };
    B64.encode(bitcoin::Psbt::from_unsigned_tx(tx).unwrap().serialize())
}
