//! A snapshot of what the version 0 PSBT RPCs answer.
//!
//! Adding version 2 must not move the version 0 path by one byte. The way to
//! know that is not to read the diff, it is to record what the methods
//! answered before the change and keep comparing. This fixture was generated
//! against master before the version dispatch existed, and reproduced
//! byte-for-byte afterwards; it must stay green for the rest of the silent
//! payment stack.
//!
//! Regenerate deliberately, never reflexively:
//!
//! ```sh
//! SATD_UPDATE_SNAPSHOT=1 cargo test -p node --test psbt_v0_snapshot
//! ```
//!
//! A change to this file is a change to what every existing PSBT client sees,
//! and belongs in a pull request that says so.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime, transaction::Version,
};
use node::rpc::psbt;
use serde_json::{Value, json};

const SNAPSHOT: &str = include_str!("snapshots/psbt_v0.json");

#[test]
fn version_0_psbt_rpcs_answer_exactly_what_they_did_before() {
    let actual = take_snapshot();
    let rendered = serde_json::to_string_pretty(&actual).expect("serializes") + "\n";

    if std::env::var("SATD_UPDATE_SNAPSHOT").is_ok() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots/psbt_v0.json");
        std::fs::write(path, &rendered).expect("writes the snapshot");
        return;
    }

    let expected: Value = serde_json::from_str(SNAPSHOT).expect("the snapshot parses");
    if actual != expected {
        // Show the first key that differs rather than two walls of JSON.
        let (a, e) = (
            actual.as_object().expect("an object"),
            expected.as_object().expect("an object"),
        );
        for (k, v) in a {
            match e.get(k) {
                Some(ev) if ev == v => {}
                Some(ev) => panic!(
                    "the version 0 path moved.\ncase: {k}\nbefore: {ev}\nafter:  {v}\n\n\
                     If this is intended, regenerate with SATD_UPDATE_SNAPSHOT=1 and say so \
                     in the pull request: it is a change every existing PSBT client sees."
                ),
                None => panic!("the snapshot has no case named {k}; regenerate it"),
            }
        }
        for k in e.keys() {
            assert!(a.contains_key(k), "case {k} disappeared from the snapshot");
        }
        panic!("the snapshot differs but no single case does; regenerate it");
    }
}

/// Every version 0 answer, keyed by case name. Errors are recorded too: their
/// codes and text are part of the contract.
fn take_snapshot() -> Value {
    let mut out = serde_json::Map::new();
    let mut record = |name: &str, r: Result<Value, (i32, String)>| {
        out.insert(
            name.to_string(),
            match r {
                Ok(v) => json!({ "ok": v }),
                Err((code, msg)) => json!({ "error": { "code": code, "message": msg } }),
            },
        );
    };

    for (name, b64) in fixtures() {
        record(&format!("decodepsbt/{name}"), psbt::decode_psbt(&b64));
        record(&format!("analyzepsbt/{name}"), psbt::analyze_psbt(&b64));
        record(
            &format!("finalizepsbt-extract/{name}"),
            psbt::finalize_psbt(&b64, true),
        );
        record(
            &format!("finalizepsbt-keep/{name}"),
            psbt::finalize_psbt(&b64, false),
        );
        record(
            &format!("combinepsbt-self/{name}"),
            psbt::combine_psbt(&[b64.clone(), b64.clone()]),
        );
        record(
            &format!("joinpsbts-self/{name}"),
            psbt::join_psbts(&[b64.clone(), b64.clone()]),
        );
    }

    // createpsbt and converttopsbt take no PSBT, so they get their own cases.
    record(
        "createpsbt/one-in-one-out",
        psbt::create_psbt(
            &[json!({ "txid": Txid::from_byte_array([7u8; 32]).to_string(), "vout": 1 })],
            &json!({ "bcrt1qcsc0vnz82md33pk7351p2h9au5ejvfevzfnp5r": 0.001 }),
            None,
            Network::Regtest,
        ),
    );
    record(
        "createpsbt/bad-address",
        psbt::create_psbt(
            &[json!({ "txid": Txid::from_byte_array([7u8; 32]).to_string(), "vout": 1 })],
            &json!({ "not an address": 0.001 }),
            None,
            Network::Regtest,
        ),
    );
    let raw_tx = hex::encode(bitcoin::consensus::serialize(&unsigned_tx()));
    record("converttopsbt/unsigned", psbt::convert_to_psbt(&raw_tx, false, None));
    record("converttopsbt/not-hex", psbt::convert_to_psbt("zz", false, None));

    // Error paths shared by every method that takes a PSBT.
    record("decodepsbt/not-base64", psbt::decode_psbt("!!!"));
    record(
        "decodepsbt/not-a-psbt",
        psbt::decode_psbt(&B64.encode(b"nope")),
    );
    record("combinepsbt/empty", psbt::combine_psbt(&[]));
    record("joinpsbts/empty", psbt::join_psbts(&[]));

    Value::Object(out)
}

fn unsigned_tx() -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([7u8; 32]),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::from_hex("0014c430f64c4756da310dbd1a085572ef299926272c")
                .unwrap(),
        }],
    }
}

/// The shapes a version 0 PSBT passes through: newly created, updated with a
/// previous output, signed, already finalised, and carrying pairs satd does
/// not know.
fn fixtures() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bare = bitcoin::Psbt::from_unsigned_tx(unsigned_tx()).expect("an unsigned tx");
    out.push(("bare".to_string(), B64.encode(bare.serialize())));

    let mut updated = bare.clone();
    updated.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::from_hex("00142269acb34a645bd3496bbbf50bbb81c9063f4f94").unwrap(),
    });
    out.push(("updated".to_string(), B64.encode(updated.serialize())));

    let mut signed = updated.clone();
    let pubkey: bitcoin::PublicKey =
        "02c817bb7521afc35ea96f3bfb270e6eb50ddffa5560627b961fec00f2996508bf"
            .parse()
            .expect("a public key");
    let sig_bytes = hex::decode(
        "304402201705fcda06266edb32b1698677b37f67bb6e45d492ebfce656a880ee7f138eb602203dcde\
         3239dd90636af64fb2412ca41e397c958a030777cff9c8940b9c777d74c01",
    )
    .expect("hex");
    let sig = bitcoin::ecdsa::Signature::from_slice(&sig_bytes).expect("a signature");
    signed.inputs[0].partial_sigs.insert(pubkey, sig);
    signed.inputs[0].sighash_type = Some(bitcoin::EcdsaSighashType::All.into());
    out.push(("signed".to_string(), B64.encode(signed.serialize())));

    let mut finalized = updated.clone();
    let mut witness = Witness::new();
    witness.push(sig.serialize());
    witness.push(pubkey.to_bytes());
    finalized.inputs[0].final_script_witness = Some(witness);
    out.push(("finalized".to_string(), B64.encode(finalized.serialize())));

    let mut with_unknowns = signed.clone();
    let key = bitcoin::psbt::raw::Key {
        type_value: 0x7a,
        key: b"satd".to_vec(),
    };
    with_unknowns.unknown.insert(key.clone(), b"global".to_vec());
    with_unknowns.inputs[0].unknown.insert(key.clone(), b"input".to_vec());
    with_unknowns.outputs[0].unknown.insert(key, b"output".to_vec());
    out.push((
        "with-unknowns".to_string(),
        B64.encode(with_unknowns.serialize()),
    ));

    out
}
