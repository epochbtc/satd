//! BIP 322 generic signed messages: construction, decoding and verification.
//!
//! A BIP 322 signature proves that whoever can spend a scriptPubKey (the
//! *challenge*) signed a message. The prover spends a virtual output: a
//! `to_spend` transaction pays the challenge from a fake input committing to
//! the message hash, and `to_sign` spends it to a lone `OP_RETURN`. The
//! signature is `to_sign`'s witness stack (*simple*, prefix `smp`) or the
//! whole `to_sign` (*full*, prefix `ful`). *Legacy* is Bitcoin Core's
//! `signmessage` format, P2PKH only; it lives in [`crate::rpc::signmessage`].
//!
//! Verification runs satd's own script interpreter (the `consensus` crate),
//! so every script it can validate verifies here: Taproot script paths,
//! timelocks and arbitrary witness scripts included. The order and the three
//! outcomes are the BIP's ("Verification Process"):
//!
//! 1. Basic validation: the structure of `to_sign`.
//! 2. Required rules, under [`REQUIRED_FLAGS`] plus SIGHASH_ALL (or
//!    SIGHASH_DEFAULT for Taproot) and no `OP_CODESEPARATOR`. A failure is
//!    [`Verification::Invalid`].
//! 3. Upgradeable rules: `to_sign` version 0 or 2, then the same scripts
//!    under [`UPGRADEABLE_FLAGS`] as well. A failure only here is
//!    [`Verification::Inconclusive`].
//! 4. Otherwise [`Verification::Valid`], "valid at time T and age S": the
//!    caller decides what `to_sign`'s locktime and input sequence mean.
//!
//! Proof-of-funds (`pof`) signatures are not supported: they prove other
//! UTXOs through a PSBT, which needs a UTXO view this module does not have.

pub mod psbt;

use std::cell::Cell;

use bitcoin::hashes::{Hash as _, HashEngine as _, sha256};
use bitcoin::script::Instruction;
use bitcoin::{
    Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime, opcodes, transaction::Version,
};
use consensus::checker::{ExecData, SigVersion, SignatureChecker};
use consensus::error::ScriptError;
use consensus::flags::*;
use consensus::scriptnum::ScriptNum;
use consensus::sighash::TxSignatureChecker;

/// The BIP 340 tag of the message hash.
pub const MESSAGE_TAG: &[u8] = b"BIP0322-signed-message";

/// The BIP's required rules, as interpreter flags: every consensus rule plus
/// LOW_S, STRICTENC, NULLFAIL, MINIMALDATA, CLEANSTACK and MINIMALIF (for
/// base scripts too, through satd's [`VERIFY_MINIMALIF_BASE`]).
/// CONST_SCRIPTCODE forbids `OP_CODESEPARATOR` and FindAndDelete in base
/// scripts; [`forbid_codeseparator`] covers witness scripts.
pub const REQUIRED_FLAGS: u32 = VERIFY_P2SH
    | VERIFY_STRICTENC
    | VERIFY_DERSIG
    | VERIFY_LOW_S
    | VERIFY_NULLDUMMY
    | VERIFY_MINIMALDATA
    | VERIFY_CLEANSTACK
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_MINIMALIF
    | VERIFY_NULLFAIL
    | VERIFY_CONST_SCRIPTCODE
    | VERIFY_TAPROOT
    | VERIFY_MINIMALIF_BASE;

/// The BIP's upgradeable rules: NOPs reserved for upgrades, and witness
/// versions, Taproot leaf versions, `OP_SUCCESS` opcodes and public key
/// types not yet defined.
pub const UPGRADEABLE_FLAGS: u32 = VERIFY_DISCOURAGE_UPGRADABLE_NOPS
    | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
    | VERIFY_DISCOURAGE_OP_SUCCESS
    | VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE;

/// A decoded BIP 322 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    /// `smp`: the witness stack of a default `to_sign`.
    Simple(Witness),
    /// `ful`: the whole `to_sign` transaction.
    Full(Transaction),
}

/// A signature string, decoded by its prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// An unprefixed string for a P2PKH challenge: Core's compact signature.
    Legacy(Vec<u8>),
    Bip322(Proof),
}

/// Why a signature string did not decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("signature is not valid base64")]
    Base64,
    #[error("proof-of-funds (pof) signatures are not supported")]
    ProofOfFunds,
    #[error("simple signature is not a witness stack: {0}")]
    Simple(String),
    #[error("full signature is not a transaction: {0}")]
    Full(String),
}

/// The outcome of verifying a BIP 322 proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// Valid at time `lock_time` and age `sequence` (input 0's), as `to_sign`
    /// carries them. A simple proof has all three fields zero.
    Valid { version: i32, lock_time: u32, sequence: u32 },
    /// Valid only under rules this verifier treats as upgradeable.
    Inconclusive(String),
    Invalid(String),
}

/// BIP 340 tagged hash of `message` under [`MESSAGE_TAG`].
pub fn message_hash(message: &[u8]) -> [u8; 32] {
    let tag = sha256::Hash::hash(MESSAGE_TAG);
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_byte_array());
    engine.input(tag.as_byte_array());
    engine.input(message);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// The virtual transaction paying `challenge`, committing to `message`.
pub fn to_spend(challenge: &Script, message: &[u8]) -> Transaction {
    let mut script_sig = vec![opcodes::OP_0.to_u8(), 32];
    script_sig.extend_from_slice(&message_hash(message));
    Transaction {
        version: Version(0),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0xFFFF_FFFF },
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence(0),
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::ZERO, script_pubkey: challenge.to_owned() }],
    }
}

/// The default `to_sign` for `to_spend`, with `witness` as its signature:
/// what a simple signature stands for.
pub fn to_sign(to_spend_txid: Txid, witness: Witness) -> Transaction {
    Transaction {
        version: Version(0),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: to_spend_txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0),
            witness,
        }],
        output: vec![op_return_output()],
    }
}

fn op_return_output() -> TxOut {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(vec![opcodes::all::OP_RETURN.to_u8()]),
    }
}

/// Decode a signature string for `challenge`.
///
/// `smp` and `ful` decode as the BIP says. `pof` is refused. An unprefixed
/// string, which most wallets made before the BIP was finalized still emit,
/// is Core's legacy format for a P2PKH challenge and a simple signature for
/// anything else, as the BIP allows ("a verifier might assume the simple
/// variant in the absence of a prefix").
///
/// Base64 is decoded as strictly as Core decodes it: wallets emit canonical
/// base64, and the BIP's negative vectors include non-canonical padding.
pub fn decode(signature: &str, challenge: &Script) -> Result<Signature, DecodeError> {
    let b64 = |s: &str| crate::rpc::signmessage::decode_base64(s).ok_or(DecodeError::Base64);
    let simple = |bytes: Vec<u8>| {
        bitcoin::consensus::deserialize::<Witness>(&bytes)
            .map(|w| Signature::Bip322(Proof::Simple(w)))
            .map_err(|e| DecodeError::Simple(e.to_string()))
    };
    if let Some(rest) = signature.strip_prefix("smp") {
        simple(b64(rest)?)
    } else if let Some(rest) = signature.strip_prefix("ful") {
        bitcoin::consensus::deserialize::<Transaction>(&b64(rest)?)
            .map(|tx| Signature::Bip322(Proof::Full(tx)))
            .map_err(|e| DecodeError::Full(e.to_string()))
    } else if signature.starts_with("pof") {
        Err(DecodeError::ProofOfFunds)
    } else if challenge.is_p2pkh() {
        Ok(Signature::Legacy(b64(signature)?))
    } else {
        simple(b64(signature)?)
    }
}

/// Verify `proof` of `message` against `challenge`.
pub fn verify(challenge: &Script, message: &[u8], proof: &Proof) -> Verification {
    let to_spend = to_spend(challenge, message);
    let to_spend_txid = to_spend.compute_txid();

    // 1. Basic validation.
    let to_sign = match proof {
        Proof::Simple(witness) => {
            if !challenge.is_witness_program() {
                return Verification::Invalid(
                    "a simple signature is only for a native segwit output".into(),
                );
            }
            to_sign(to_spend_txid, witness.clone())
        }
        Proof::Full(tx) => {
            if let Err(reason) = check_full_structure(tx, to_spend_txid) {
                return Verification::Invalid(reason.into());
            }
            tx.clone()
        }
    };
    let input = &to_sign.input[0];
    let witness: Vec<Vec<u8>> = input.witness.iter().map(<[u8]>::to_vec).collect();
    let prevouts = [to_spend.output[0].clone()];

    // 2. Required rules.
    if let Err(reason) = forbid_codeseparator(challenge, &input.script_sig, &witness) {
        return Verification::Invalid(reason.into());
    }
    let run = |flags: u32| {
        let checker = Bip322Checker {
            inner: TxSignatureChecker::new(&to_sign, 0, Amount::ZERO, &prevouts),
            bad_sighash: Cell::new(false),
        };
        let result = consensus::verify::verify_script(
            input.script_sig.as_bytes(),
            challenge.as_bytes(),
            &witness,
            flags,
            &checker,
        );
        (result, checker.bad_sighash.get())
    };
    match run(REQUIRED_FLAGS) {
        (Ok(()), _) => {}
        (Err(_), true) => {
            return Verification::Invalid(
                "a signature uses a sighash type other than SIGHASH_ALL (or SIGHASH_DEFAULT for Taproot)"
                    .into(),
            );
        }
        (Err(e), false) => return Verification::Invalid(script_reason(e)),
    }

    // 3. Upgradeable rules.
    if !matches!(to_sign.version, Version(0) | Version(2)) {
        return Verification::Inconclusive(format!(
            "to_sign version {} is neither 0 nor 2",
            to_sign.version.0
        ));
    }
    if let (Err(e), _) = run(REQUIRED_FLAGS | UPGRADEABLE_FLAGS) {
        return Verification::Inconclusive(script_reason(e));
    }

    Verification::Valid {
        version: to_sign.version.0,
        lock_time: to_sign.lock_time.to_consensus_u32(),
        sequence: input.sequence.0,
    }
}

fn script_reason(e: ScriptError) -> String {
    format!("script verification failed: {}", e.as_str())
}

/// The BIP's structure rules for a full `to_sign`: one input, spending
/// `to_spend:0`, and one output, a zero-value `OP_RETURN`. More inputs make
/// it a proof of funds, which needs the `pof` encoding.
fn check_full_structure(tx: &Transaction, to_spend_txid: Txid) -> Result<(), &'static str> {
    if tx.input.len() != 1 {
        return Err("a full signature's to_sign must have exactly one input");
    }
    if tx.input[0].previous_output != (OutPoint { txid: to_spend_txid, vout: 0 }) {
        return Err("to_sign does not spend to_spend for this message and address");
    }
    if tx.output.len() != 1 || tx.output[0] != op_return_output() {
        return Err("to_sign must have exactly one output, a zero-value OP_RETURN");
    }
    Ok(())
}

/// The BIP forbids `OP_CODESEPARATOR` everywhere. CONST_SCRIPTCODE already
/// refuses it in base scripts (bare and P2SH redeem scripts), as Core does.
/// Witness v0 scripts and tapscript leaves allow it by consensus, so this
/// scans the script a witness spend will run, as CONST_SCRIPTCODE scans a base
/// script: every opcode, executed or not.
///
/// A script that does not parse is left to the interpreter, which fails it
/// when it reaches the bad push.
fn forbid_codeseparator(
    challenge: &Script,
    script_sig: &Script,
    witness: &[Vec<u8>],
) -> Result<(), &'static str> {
    // P2SH-wrapped segwit: the program is the scriptSig's last push.
    let program = if challenge.is_p2sh() {
        match script_sig.instructions().last() {
            Some(Ok(Instruction::PushBytes(p))) => ScriptBuf::from_bytes(p.as_bytes().to_vec()),
            _ => return Ok(()),
        }
    } else {
        challenge.to_owned()
    };
    let script = if program.is_p2wsh() {
        witness.last()
    } else if program.is_p2tr() && !challenge.is_p2sh() {
        // BIP 341: drop an annex, then a script-path spend is
        // [..args, leaf script, control block]. Only leaf version 0xc0 is
        // tapscript; any other is upgradeable and the interpreter says so.
        let mut stack = witness;
        if stack.len() >= 2 && stack.last().is_some_and(|a| a.first() == Some(&0x50)) {
            stack = &stack[..stack.len() - 1];
        }
        match stack {
            [.., leaf, control] if control.first().is_some_and(|c| c & 0xfe == 0xc0) => Some(leaf),
            _ => None,
        }
    } else {
        None
    };
    let Some(script) = script else { return Ok(()) };
    for ins in Script::from_bytes(script).instructions() {
        match ins {
            Ok(Instruction::Op(op)) if op == opcodes::all::OP_CODESEPARATOR => {
                return Err("OP_CODESEPARATOR is forbidden in a BIP 322 proof");
            }
            Ok(_) => {}
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

/// The transaction checker, refusing every sighash type but SIGHASH_ALL,
/// and SIGHASH_DEFAULT for Schnorr. A refused signature fails to verify, so
/// the script fails (under NULLFAIL, or as a failed Schnorr signature); the
/// flag lets [`verify`] say why.
struct Bip322Checker<'a> {
    inner: TxSignatureChecker<'a>,
    bad_sighash: Cell<bool>,
}

impl SignatureChecker for Bip322Checker<'_> {
    fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sig_version: SigVersion,
    ) -> bool {
        if let Some(&hash_type) = sig.last()
            && hash_type != 0x01
        {
            self.bad_sighash.set(true);
            return false;
        }
        self.inner.check_ecdsa_signature(sig, pubkey, script_code, sig_version)
    }

    fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        sig_version: SigVersion,
        exec_data: &ExecData,
    ) -> Result<bool, ScriptError> {
        // 64 bytes is SIGHASH_DEFAULT. A 65th byte of 0x00 is invalid by
        // consensus, which the inner checker reports.
        if sig.len() == 65 && sig[64] != 0x01 && sig[64] != 0x00 {
            self.bad_sighash.set(true);
            return Ok(false);
        }
        self.inner.check_schnorr_signature(sig, pubkey, sig_version, exec_data)
    }

    fn check_lock_time(&self, lock_time: &ScriptNum) -> bool {
        self.inner.check_lock_time(lock_time)
    }

    fn check_sequence(&self, sequence: &ScriptNum) -> bool {
        self.inner.check_sequence(sequence)
    }
}

#[cfg(test)]
mod tests;
