//! rbitcoin's script corpus (`test-data/rbitcoin_script_corpus.json`, see
//! `rbitcoin_script_corpus.md` for its source, license and per-row
//! predicates). Each row is in Core's `script_tests.json` form, and rbitcoin
//! checks every row against Bitcoin Core v31.1 `VerifyScript`. It pins limits
//! Core's own file leaves unstated: script and element sizes, the opcode and
//! stack limits in every signature version, OP_SUCCESS and OP_VERIF in
//! executed and unexecuted branches, locktime edges, and SIGHASH_SINGLE past
//! the last output.
//!
//! The corpus records accept or reject (`OK` / `ERR`), not error names, so
//! only the verdict is compared. Where a row's flags are all ones
//! libbitcoinconsensus takes, it is run there too.
//!
//! Two departures from Core's dialect are handled here: the `OP_CLTV` and
//! `OP_CSV` opcode aliases, and an optional `spend` object that sets the
//! spending transaction's `locktime`, `sequence`, `version` and `n_outputs`.

mod helpers;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use consensus::flags;
use consensus::sighash::TxSignatureChecker;
use consensus::verify::verify_script;
use helpers::{parse_flags, parse_script, parse_witness_row, TAPROOT_OUTPUT_MARKER};
use serde_json::Value;

/// The flags libbitcoinconsensus accepts.
const CPP_FLAGS: u32 = flags::VERIFY_P2SH
    | flags::VERIFY_DERSIG
    | flags::VERIFY_NULLDUMMY
    | flags::VERIFY_CHECKLOCKTIMEVERIFY
    | flags::VERIFY_CHECKSEQUENCEVERIFY
    | flags::VERIFY_WITNESS
    | flags::VERIFY_TAPROOT;

/// Core's `BuildCreditingTransaction`.
fn crediting_tx(script_pubkey: &[u8], value: u64) -> Transaction {
    Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut { value: Amount::from_sat(value), script_pubkey: ScriptBuf::from_bytes(script_pubkey.to_vec()) }],
    }
}

/// Core's `BuildSpendingTransaction`, then the row's `spend` overrides.
fn spending_tx(script_sig: &[u8], witness: &[Vec<u8>], credit: &Transaction, spend: Option<&Value>, id: &str) -> Transaction {
    let mut tx = Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array(credit.compute_txid().to_byte_array()), vout: 0 },
            script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(witness),
        }],
        output: vec![TxOut { value: credit.output[0].value, script_pubkey: ScriptBuf::new() }],
    };
    for (key, v) in spend.and_then(Value::as_object).into_iter().flatten() {
        let v = v.as_u64().unwrap_or_else(|| panic!("{id}: spend.{key} is not a number"));
        match key.as_str() {
            "locktime" => tx.lock_time = LockTime::from_consensus(v as u32),
            "sequence" => tx.input[0].sequence = Sequence(v as u32),
            "version" => tx.version = Version(v as u32 as i32),
            "n_outputs" => tx.output.truncate(v as usize),
            other => panic!("{id}: unknown spend field {other}"),
        }
    }
    tx
}

#[test]
fn rbitcoin_script_corpus() {
    let data = include_str!("../test-data/rbitcoin_script_corpus.json")
        .replace("OP_CLTV", "CHECKLOCKTIMEVERIFY")
        .replace("OP_CSV", "CHECKSEQUENCEVERIFY");
    let rows: Vec<Value> = serde_json::from_str(&data).unwrap();
    let (mut checked, mut cpp_checked) = (0, 0);
    let mut wrong = Vec::new();

    for r in &rows {
        let id = r["id"].as_str().unwrap();
        let row = r["row"].as_array().unwrap();
        // [scriptSig, scriptPubKey, flags, result], or with a leading
        // witness array whose last element is the amount in BTC.
        let mut taproot_output = None;
        let (witness, fields, amount) = if let Some(w) = row[0].as_array() {
            let amount = (w.last().and_then(Value::as_f64).unwrap() * 100_000_000.0).round() as u64;
            let parsed = parse_witness_row(&w[..w.len() - 1]);
            taproot_output = parsed.taproot_output;
            (parsed.stack, &row[1..], amount)
        } else {
            (Vec::new(), &row[..], 0)
        };
        let field = |i: usize| fields[i].as_str().unwrap();
        let script_sig = parse_script(field(0));
        let script_pubkey = if field(1) == TAPROOT_OUTPUT_MARKER {
            taproot_output.take().unwrap_or_else(|| panic!("{id}: no tapscript leaf for the output"))
        } else {
            parse_script(field(1))
        };
        let mut script_flags = parse_flags(field(2));
        // As Core's harness: CLEANSTACK implies P2SH and WITNESS.
        if script_flags & flags::VERIFY_CLEANSTACK != 0 {
            script_flags |= flags::VERIFY_P2SH | flags::VERIFY_WITNESS;
        }
        let expect_ok = match field(3) {
            "OK" => true,
            "ERR" => false,
            other => panic!("{id}: result {other}"),
        };

        let credit = crediting_tx(&script_pubkey, amount);
        let spend = spending_tx(&script_sig, &witness, &credit, r.get("spend"), id);
        let prevouts = [credit.output[0].clone()];
        let checker = TxSignatureChecker::new(&spend, 0, credit.output[0].value, &prevouts);
        let rust_ok = verify_script(&script_sig, &script_pubkey, &witness, script_flags, &checker).is_ok();
        checked += 1;
        if rust_ok != expect_ok {
            wrong.push(format!("{id}: expected {}, the engine {}", field(3), if rust_ok { "accepts" } else { "rejects" }));
        }

        if script_flags & !CPP_FLAGS == 0 {
            let mut bytes = Vec::new();
            spend.consensus_encode(&mut bytes).unwrap();
            let utxos = [bitcoinconsensus::Utxo {
                script_pubkey: script_pubkey.as_ptr(),
                script_pubkey_len: script_pubkey.len() as u32,
                value: amount as i64,
            }];
            let cpp_ok =
                bitcoinconsensus::verify_with_flags(&script_pubkey, amount, &bytes, Some(&utxos), 0, script_flags).is_ok();
            cpp_checked += 1;
            if cpp_ok != expect_ok {
                wrong.push(format!("{id}: expected {}, libbitcoinconsensus {}", field(3), if cpp_ok { "accepts" } else { "rejects" }));
            }
        }
    }

    eprintln!("rbitcoin corpus: {checked} rows, {cpp_checked} also run by libbitcoinconsensus");
    assert!(wrong.is_empty(), "{} rows disagree:\n{}", wrong.len(), wrong.join("\n"));
    assert_eq!(checked, 448, "every row runs");
}
