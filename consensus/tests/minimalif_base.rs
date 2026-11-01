//! `VERIFY_MINIMALIF_BASE`, satd's BIP 322 extension flag: MINIMALIF for
//! base scripts, opt-in through `verify_script` only.

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use consensus::checker::NoopChecker;
use consensus::error::ScriptError;
use consensus::flags::{self, ALL_FLAGS, VERIFY_MINIMALIF, VERIFY_MINIMALIF_BASE};
use consensus::verify::verify_script;
use consensus::{Error, PrecomputedTransactionData, verify, verify_transaction};

/// `OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF`: true for a true argument.
const IF_SCRIPT: &[u8] = &[0x63, 0x51, 0x67, 0x00, 0x68];
/// `OP_NOTIF OP_1 OP_ELSE OP_0 OP_ENDIF`: true for a false argument.
const NOTIF_SCRIPT: &[u8] = &[0x64, 0x51, 0x67, 0x00, 0x68];

fn push(item: &[u8]) -> Vec<u8> {
    let mut v = vec![item.len() as u8];
    v.extend_from_slice(item);
    v
}

/// P2SH scriptSig: the IF argument's (minimal) push, then the redeem script.
fn p2sh(arg_push: &[u8], redeem: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut sig = arg_push.to_vec();
    sig.extend(push(redeem));
    let spk = ScriptBuf::new_p2sh(&ScriptBuf::from_bytes(redeem.to_vec()).script_hash());
    (sig, spk.into_bytes())
}

fn run(script_sig: &[u8], spk: &[u8], flags: u32) -> Result<(), ScriptError> {
    verify_script(script_sig, spk, &[], flags, &NoopChecker)
}

#[test]
fn non_minimal_if_argument_fails_only_under_the_extension() {
    for redeem in [IF_SCRIPT, NOTIF_SCRIPT] {
        // OP_2 pushes 0x02, which is true, and a direct push of one 0x00 byte
        // is false. Both pushes are minimal (MINIMALDATA passes), but
        // neither value is a minimal IF argument.
        let arg: Vec<u8> = if redeem == IF_SCRIPT { vec![0x52] } else { push(&[0x00]) };
        let arg = arg.as_slice();

        let (bare_sig, bare_spk) = (arg.to_vec(), redeem.to_vec());
        let (p2sh_sig, p2sh_spk) = p2sh(arg, redeem);
        for (sig, spk) in [(&bare_sig, &bare_spk), (&p2sh_sig, &p2sh_spk)] {
            // Every Core flag, MINIMALIF included: base scripts are exempt.
            assert_eq!(run(sig, spk, ALL_FLAGS), Ok(()));
            assert_eq!(
                run(sig, spk, ALL_FLAGS | VERIFY_MINIMALIF_BASE),
                Err(ScriptError::MinimalIf)
            );
        }

        // A minimal argument passes either way: OP_1, or OP_0 (empty).
        let minimal: &[u8] = if redeem == IF_SCRIPT { &[0x51] } else { &[0x00] };
        let (sig, spk) = p2sh(minimal, redeem);
        assert_eq!(run(&sig, &spk, ALL_FLAGS | VERIFY_MINIMALIF_BASE), Ok(()));
    }
}

#[test]
fn extension_leaves_witness_v0_to_minimalif() {
    // P2WSH of IF_SCRIPT with a non-minimal argument: MINIMALIF decides,
    // the extension flag changes nothing.
    let witness_script = IF_SCRIPT.to_vec();
    let spk = ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(witness_script.clone()).wscript_hash());
    let witness = vec![vec![0x02], witness_script];
    let base = ALL_FLAGS & !VERIFY_MINIMALIF;
    for ext in [0, VERIFY_MINIMALIF_BASE] {
        assert_eq!(verify_script(&[], spk.as_bytes(), &witness, base | ext, &NoopChecker), Ok(()));
        assert_eq!(
            verify_script(&[], spk.as_bytes(), &witness, base | VERIFY_MINIMALIF | ext, &NoopChecker),
            Err(ScriptError::MinimalIf)
        );
    }
}

#[test]
fn libconsensus_entry_points_refuse_the_extension() {
    assert!(!flags::valid_flags(VERIFY_MINIMALIF_BASE));
    assert_eq!(ALL_FLAGS & VERIFY_MINIMALIF_BASE, 0);

    let credit = Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(IF_SCRIPT.to_vec()) }],
    };
    let spend = Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: credit.compute_txid(), vout: 0 },
            script_sig: ScriptBuf::from_bytes(vec![0x51]),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![],
    };
    let precomputed = PrecomputedTransactionData::new(&spend, &credit.output).unwrap();
    assert_eq!(
        verify(Script::from_bytes(IF_SCRIPT), Amount::ZERO, &spend, 0, VERIFY_MINIMALIF_BASE, &precomputed),
        Err(Error::ErrInvalidFlags)
    );
    assert_eq!(
        verify_transaction(&spend, &credit.output, VERIFY_MINIMALIF_BASE),
        Err((0, Error::ErrInvalidFlags))
    );
    // The same spend with Core's flags is fine: the refusal is the flag's.
    assert_eq!(verify_transaction(&spend, &credit.output, ALL_FLAGS & !flags::VERIFY_TAPROOT), Ok(()));
}
