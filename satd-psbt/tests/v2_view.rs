//! The typed view: lock-time determination, the unsigned transaction, the
//! unique identifier, and the hand-back to `bitcoin::Psbt`.

mod common;

use satd_psbt::raw::RawPsbt;
use satd_psbt::{PsbtError, V2View};

/// BIP 370 ships ten lock-time determination cases with the answer written
/// out. Nine have one, and the tenth is the case where no lock time satisfies
/// every input.
#[test]
fn locktime_determination_vectors() {
    let mut with_answer = 0usize;
    let mut impossible = 0usize;
    for v in common::bip370_locktime() {
        let raw = RawPsbt::parse(&v.psbt)
            .unwrap_or_else(|e| panic!("{}: should parse: {e}", v.description));
        let view = V2View::new(&raw).expect("a version 2 PSBT");
        match v.locktime.expect("a locktime vector states its answer") {
            Some(expected) => {
                with_answer += 1;
                let got = view
                    .lock_time()
                    .unwrap_or_else(|e| panic!("{}: {e}", v.description));
                assert_eq!(
                    got.to_consensus_u32(),
                    expected,
                    "{}: wrong lock time",
                    v.description
                );
            }
            None => {
                impossible += 1;
                match view.lock_time() {
                    Err(PsbtError::ConflictingLockTimes(_, _)) => {}
                    other => panic!("{}: expected a conflict, got {other:?}", v.description),
                }
            }
        }
    }
    assert_eq!(with_answer, 9);
    assert_eq!(impossible, 1);
}

/// A height lock time wins a tie, so that two signers cannot commit to
/// different transactions.
#[test]
fn a_height_locktime_wins_a_tie() {
    let v = common::bip370_locktime()
        .into_iter()
        .find(|v| {
            v.description.contains("Input 1 has PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 10000 and")
                && v.description.contains("Input 2 has PSBT_IN_REQUIRED_HEIGHT_LOCKTIME of 9000")
        })
        .expect("the tie-break vector is in the file");
    let raw = RawPsbt::parse(&v.psbt).expect("parses");
    let view = V2View::new(&raw).unwrap();
    assert_eq!(view.lock_time().unwrap().to_consensus_u32(), 10_000);
}

/// A PSBT whose outputs all have scripts describes a transaction. One still
/// waiting on a silent payment script does not, and must say so by name
/// rather than inventing an empty script.
#[test]
fn unsigned_tx_needs_every_output_script() {
    let mut finished = 0usize;
    let mut in_progress = 0usize;
    for v in common::bip375_valid() {
        let raw = RawPsbt::parse(&v.psbt).expect("parses");
        let view = V2View::new(&raw).unwrap();
        let all_scripts = view.outputs().all(|o| {
            o.script()
                .map(|s| s.is_some_and(|s| !s.is_empty()))
                .unwrap_or(false)
        });
        match view.unsigned_tx() {
            Ok(tx) => {
                assert!(all_scripts, "{}: built a tx with a missing script", v.description);
                assert_eq!(tx.input.len(), view.input_count());
                assert_eq!(tx.output.len(), view.output_count());
                finished += 1;
            }
            Err(PsbtError::OutputScriptNotComputed(i)) => {
                assert!(!all_scripts, "{}: refused output {i} that had a script", v.description);
                in_progress += 1;
            }
            Err(e) => panic!("{}: {e}", v.description),
        }
    }
    assert!(finished > 0 && in_progress > 0, "both shapes should be covered");
}

/// The unique identifier ignores sequence numbers, so an Updater bumping one
/// does not make two halves of the same PSBT look like different PSBTs; and
/// it stands a silent payment code in for a script that does not exist yet,
/// so the two halves agree before the script is computed.
#[test]
fn unique_id_ignores_sequences_and_survives_an_absent_script() {
    use satd_psbt::keys;
    use satd_psbt::raw::RawPair;

    for v in common::bip375_valid() {
        let raw = RawPsbt::parse(&v.psbt).expect("parses");
        let before = V2View::new(&raw).unwrap().unique_id();
        let before = match before {
            Ok(id) => id,
            // A PSBT with a conflicting lock time has no unique id either way.
            Err(_) => continue,
        };

        let mut bumped = raw.clone();
        for input in &mut bumped.inputs {
            input.set(RawPair::new(
                keys::input::SEQUENCE,
                Vec::new(),
                0xfffffffdu32.to_le_bytes().to_vec(),
            ));
        }
        let after = V2View::new(&bumped).unwrap().unique_id().expect("still computable");
        assert_eq!(before, after, "{}: a sequence change moved the id", v.description);
    }
}

/// Computing a silent payment output's script must not change the PSBT's
/// identity: the two sides of a `combinepsbt` may be at different stages.
#[test]
fn unique_id_is_unchanged_by_computing_an_sp_script() {
    use satd_psbt::keys;
    use satd_psbt::raw::RawPair;

    let v = common::bip375_valid()
        .into_iter()
        .find(|v| v.description.starts_with("in progress: one P2TR input / one sp output"))
        .expect("the vector is in the file");
    let raw = RawPsbt::parse(&v.psbt).expect("parses");
    let before = V2View::new(&raw).unwrap().unique_id().expect("computable");

    let mut filled = raw.clone();
    let script = hex_bytes("51200000000000000000000000000000000000000000000000000000000000000001");
    for out in &mut filled.outputs {
        if out.contains_type(keys::output::SP_V0_INFO) {
            out.set(RawPair::new(keys::output::SCRIPT, Vec::new(), script.clone()));
        }
    }
    let after = V2View::new(&filled).unwrap().unique_id().expect("computable");
    assert_eq!(before, after, "the identifier must ignore the computed script");
}

/// `to_v0` is how the version 0 finaliser gets to keep doing its job. The
/// version 2 and BIP 375 fields have no version 0 encoding and do not
/// survive; everything else does.
#[test]
fn to_v0_hands_back_a_psbt_the_v0_parser_accepts() {
    let mut converted = 0usize;
    for v in common::bip375_valid() {
        let raw = RawPsbt::parse(&v.psbt).expect("parses");
        let view = V2View::new(&raw).unwrap();
        let v0 = match view.to_v0() {
            Ok(psbt) => psbt,
            Err(PsbtError::OutputScriptNotComputed(_)) => continue,
            Err(e) => panic!("{}: {e}", v.description),
        };
        converted += 1;

        let tx = view.unsigned_tx().expect("every script is present");
        assert_eq!(v0.unsigned_tx, tx, "{}", v.description);
        assert_eq!(v0.inputs.len(), view.input_count());
        assert_eq!(v0.outputs.len(), view.output_count());

        // Per-input material survives.
        for (i, input) in v0.inputs.iter().enumerate() {
            let src = view.input(i).unwrap();
            assert_eq!(
                input.witness_utxo.is_some(),
                src.witness_utxo().unwrap().is_some(),
                "{}: input {i} witness utxo",
                v.description
            );
            assert_eq!(
                input.bip32_derivation.len(),
                src.bip32_derivations().count(),
                "{}: input {i} derivations",
                v.description
            );
            assert_eq!(
                input.partial_sigs.len(),
                src.partial_sigs().count(),
                "{}: input {i} signatures",
                v.description
            );
        }

        // And it round-trips through the version 0 serialiser.
        assert!(bitcoin::Psbt::deserialize(&v0.serialize()).is_ok());
    }
    assert!(converted > 0, "some vectors should be convertible");
}

#[test]
fn a_version_0_psbt_is_not_a_v2_view() {
    let raw = RawPsbt::parse(&v0_bytes()).expect("parses");
    assert!(matches!(
        V2View::new(&raw),
        Err(PsbtError::UnsupportedVersion(0))
    ));
}

fn v0_bytes() -> Vec<u8> {
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
                txid: Txid::from_byte_array([3u8; 32]),
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
    bitcoin::Psbt::from_unsigned_tx(tx).unwrap().serialize()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
