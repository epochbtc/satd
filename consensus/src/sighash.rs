//! Transaction signature checker — adapts bitcoin::sighash::SighashCache for
//! use with our SignatureChecker trait.
#![allow(clippy::nonminimal_bool)]

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, sha256d, Hash, HashEngine};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::secp256k1::{self, Message, Secp256k1, VerifyOnly};
use bitcoin::{Amount, Script, ScriptBuf, Sequence, Transaction, TxOut};
use std::cell::{OnceCell, RefCell};
use std::rc::Rc;
use std::sync::OnceLock;

use crate::checker::{ExecData, SignatureChecker, SigVersion};
use crate::error::ScriptError;
use crate::scriptnum::ScriptNum;

const LOCKTIME_THRESHOLD: u32 = 500_000_000;
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;

/// Process-global verification-only secp256k1 context.
///
/// Creating a `Secp256k1` context is expensive — it allocates the ecmult_gen
/// precomputation table and runs `context_randomize` for side-channel
/// protection. Previously we did this on every `TxSignatureChecker::new()`,
/// which cost ~40% of total verify time on signature-heavy workloads
/// (profiled via consensus/benches/p2sh.rs). Bitcoin Core allocates its
/// context once at process startup and reuses it; we now do the same.
///
/// `VerifyOnly` omits the ecmult_gen tables (which are only needed for
/// signing and ECDH), making the one-time allocation cheaper than `All`.
fn secp_ctx() -> &'static Secp256k1<VerifyOnly> {
    static CTX: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::verification_only)
}

/// Per-transaction sighash state, shared by every input's checker.
///
/// `SighashCache` lazily populates the legacy and BIP143 per-tx hashes
/// (`hashPrevouts`, `hashSequence`, `hashOutputs`). The BIP341 per-tx hashes
/// live beside it in `taproot`, filled on the first Schnorr check: they are
/// identical across all inputs of a transaction, as Core's
/// `PrecomputedTransactionData`.
pub struct TxSighashCache<'a> {
    pub legacy: SighashCache<&'a Transaction>,
    taproot: Option<TaprootTxHashes>,
}

impl<'a> TxSighashCache<'a> {
    pub fn new(tx: &'a Transaction) -> Self {
        Self { legacy: SighashCache::new(tx), taproot: None }
    }
}

/// `RefCell` gives us interior mutability so `check_*` methods can keep their
/// `&self` trait signature while the cache's encode helpers require
/// `&mut self`. `Rc` lets a higher-level batch verify share a single cache
/// across per-input `TxSignatureChecker`s.
pub type SharedSighashCache<'a> = Rc<RefCell<TxSighashCache<'a>>>;

/// BIP 341's single-SHA256 per-transaction hashes.
#[derive(Clone, Copy)]
struct TaprootTxHashes {
    prevouts: [u8; 32],
    amounts: [u8; 32],
    script_pubkeys: [u8; 32],
    sequences: [u8; 32],
    outputs: [u8; 32],
}

impl TaprootTxHashes {
    fn compute(tx: &Transaction, spent: &[TxOut]) -> Self {
        let mut prevouts = sha256::Hash::engine();
        let mut sequences = sha256::Hash::engine();
        for input in &tx.input {
            input.previous_output.consensus_encode(&mut prevouts).expect("engines do not fail");
            input.sequence.consensus_encode(&mut sequences).expect("engines do not fail");
        }
        let mut amounts = sha256::Hash::engine();
        let mut script_pubkeys = sha256::Hash::engine();
        for out in spent {
            out.value.consensus_encode(&mut amounts).expect("engines do not fail");
            out.script_pubkey.consensus_encode(&mut script_pubkeys).expect("engines do not fail");
        }
        let mut outputs = sha256::Hash::engine();
        for out in &tx.output {
            out.consensus_encode(&mut outputs).expect("engines do not fail");
        }
        let done = |e: sha256::HashEngine| sha256::Hash::from_engine(e).to_byte_array();
        Self {
            prevouts: done(prevouts),
            amounts: done(amounts),
            script_pubkeys: done(script_pubkeys),
            sequences: done(sequences),
            outputs: done(outputs),
        }
    }
}

/// A signature checker backed by an actual transaction, delegating sighash
/// computation to `bitcoin::sighash::SighashCache`.
pub struct TxSignatureChecker<'a> {
    tx: &'a Transaction,
    input_index: usize,
    amount: Amount,
    prev_outputs: &'a [TxOut],
    cache: SharedSighashCache<'a>,
    /// BIP 341 `sha_single_output` for this input, hashed on first use.
    single_output_hash: OnceCell<Option<[u8; 32]>>,
}

impl<'a> TxSignatureChecker<'a> {
    /// Single-input constructor: builds its own sighash cache.  Use this when
    /// verifying a single input in isolation (e.g. via `verify_with_flags`).
    pub fn new(
        tx: &'a Transaction,
        input_index: usize,
        amount: Amount,
        prev_outputs: &'a [TxOut],
    ) -> Self {
        Self::with_cache(
            tx,
            input_index,
            amount,
            prev_outputs,
            Rc::new(RefCell::new(TxSighashCache::new(tx))),
        )
    }

    /// Shared-cache constructor: reuses an existing sighash cache across
    /// multiple per-input checkers.  Use this inside `verify_transaction`
    /// so the expensive `hashPrevouts` / `hashSequence` / `hashOutputs`
    /// computations happen once per tx, not once per input.
    pub fn with_cache(
        tx: &'a Transaction,
        input_index: usize,
        amount: Amount,
        prev_outputs: &'a [TxOut],
        cache: SharedSighashCache<'a>,
    ) -> Self {
        Self {
            tx,
            input_index,
            amount,
            prev_outputs,
            cache,
            single_output_hash: OnceCell::new(),
        }
    }

    /// Core's `SignatureHashSchnorr` (src/script/interpreter.cpp): the BIP 341
    /// signature message, from hashes computed once per transaction (the
    /// shared cache), once per input (the annex and tapleaf hashes in
    /// `exec_data`, and the SIGHASH_SINGLE output here), never per check.
    /// `None` where Core returns false: an undefined hash type, spent outputs
    /// missing, or SIGHASH_SINGLE with no output at this input's index.
    fn taproot_sighash(&self, hash_type: u8, sig_version: SigVersion, exec_data: &ExecData) -> Option<[u8; 32]> {
        if !(hash_type <= 0x03 || (0x81..=0x83).contains(&hash_type)) {
            return None;
        }
        if self.prev_outputs.len() != self.tx.input.len() {
            return None;
        }
        let output_type = if hash_type == 0x00 { 0x01 } else { hash_type & 0x03 };
        let anyone_can_pay = hash_type & 0x80 != 0;
        let tx_hashes = {
            let mut cache = self.cache.borrow_mut();
            *cache.taproot.get_or_insert_with(|| TaprootTxHashes::compute(self.tx, self.prev_outputs))
        };

        let mut e = bitcoin::TapSighash::engine();
        let ok = "engines do not fail";
        e.input(&[0x00, hash_type]); // epoch, hash type
        self.tx.version.consensus_encode(&mut e).expect(ok);
        self.tx.lock_time.consensus_encode(&mut e).expect(ok);
        if !anyone_can_pay {
            e.input(&tx_hashes.prevouts);
            e.input(&tx_hashes.amounts);
            e.input(&tx_hashes.script_pubkeys);
            e.input(&tx_hashes.sequences);
        }
        if output_type == 0x01 {
            e.input(&tx_hashes.outputs);
        }
        let ext_flag: u8 = if sig_version == SigVersion::Tapscript { 1 } else { 0 };
        e.input(&[(ext_flag << 1) | u8::from(exec_data.annex_present)]);
        if anyone_can_pay {
            let input = &self.tx.input[self.input_index];
            input.previous_output.consensus_encode(&mut e).expect(ok);
            self.prev_outputs[self.input_index].consensus_encode(&mut e).expect(ok);
            input.sequence.consensus_encode(&mut e).expect(ok);
        } else {
            (self.input_index as u32).consensus_encode(&mut e).expect(ok);
        }
        if exec_data.annex_present {
            e.input(&exec_data.annex_hash);
        }
        if output_type == 0x03 {
            let single = self.single_output_hash.get_or_init(|| {
                self.tx.output.get(self.input_index).map(|out| {
                    let mut h = sha256::Hash::engine();
                    out.consensus_encode(&mut h).expect(ok);
                    sha256::Hash::from_engine(h).to_byte_array()
                })
            });
            e.input(&(*single)?);
        }
        if sig_version == SigVersion::Tapscript {
            e.input(&exec_data.tapleaf_hash);
            e.input(&[0x00]); // key_version
            exec_data.codeseparator_pos.consensus_encode(&mut e).expect(ok);
        }
        Some(bitcoin::TapSighash::from_engine(e).to_byte_array())
    }
}

impl SignatureChecker for TxSignatureChecker<'_> {
    fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        pubkey_bytes: &[u8],
        script_code: &[u8],
        sig_version: SigVersion,
    ) -> bool {
        // Parse pubkey using secp256k1 directly (not bitcoin::PublicKey)
        // because bitcoin::PublicKey rejects hybrid keys (0x06/0x07 prefix)
        // which are valid for consensus.
        let pubkey = match secp256k1::PublicKey::from_slice(pubkey_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        if sig.is_empty() {
            return false;
        }

        // Last byte is hashtype
        let hash_type_byte = sig[sig.len() - 1];
        let sig_bytes = &sig[..sig.len() - 1];

        // Parse DER signature using lax parser (consensus-compatible).
        // Bitcoin Core uses secp256k1_ecdsa_signature_parse_der_lax for
        // verification, which accepts slightly non-canonical DER encodings.
        let mut ecdsa_sig = match secp256k1::ecdsa::Signature::from_der_lax(sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // Normalize to low-S form before verification. Bitcoin Core's
        // CPubKey::Verify calls secp256k1_ecdsa_signature_normalize before
        // secp256k1_ecdsa_verify. Without this, high-S signatures fail.
        ecdsa_sig.normalize_s();

        // Compute sighash
        let sighash_type = EcdsaSighashType::from_consensus(hash_type_byte as u32);

        let script_code_obj = Script::from_bytes(script_code);

        let sighash = match sig_version {
            SigVersion::WitnessV0 => {
                // BIP143 segwit v0 sighash.
                //
                // Write the signing data to a buffer so we can replace the
                // trailing 4-byte hash-type field with the RAW hash-type
                // byte from the signature.  The bitcoin crate normalises
                // non-standard bytes (e.g. 0x65 → All → 0x01) via
                // EcdsaSighashType, but Bitcoin Core hashes the original
                // byte.  Intermediate fields (hashPrevouts, hashSequence,
                // hashOutputs) are unaffected because the ACP / SINGLE /
                // NONE routing is identical after normalisation.
                let mut cache = self.cache.borrow_mut();
                let mut buf = Vec::with_capacity(256);
                match cache.legacy.segwit_v0_encode_signing_data_to(
                    &mut buf,
                    self.input_index,
                    script_code_obj,
                    self.amount,
                    sighash_type,
                ) {
                    Ok(()) => {}
                    Err(_) => return false,
                }
                // Overwrite the last 4 bytes with the raw hash type.
                let len = buf.len();
                buf[len - 4..].copy_from_slice(&(hash_type_byte as u32).to_le_bytes());
                sha256d::Hash::hash(&buf).to_byte_array()
            }
            SigVersion::Base => {
                // Legacy sighash
                let cache = self.cache.borrow();
                // Remove OP_CODESEPARATOR from script_code for legacy
                let script_code_buf = remove_codeseparators(script_code);
                match cache.legacy.legacy_signature_hash(
                    self.input_index,
                    &script_code_buf,
                    hash_type_byte as u32,
                ) {
                    Ok(h) => h.to_byte_array(),
                    Err(_) => return false,
                }
            }
            _ => return false,
        };

        let msg = Message::from_digest(sighash);

        secp_ctx()
            .verify_ecdsa(&msg, &ecdsa_sig, &pubkey)
            .is_ok()
    }

    fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey_bytes: &[u8],
        sig_version: SigVersion,
        exec_data: &ExecData,
    ) -> Result<bool, ScriptError> {
        assert!(sig_version == SigVersion::Taproot || sig_version == SigVersion::Tapscript);
        assert!(pubkey_bytes.len() == 32);

        if sig.len() != 64 && sig.len() != 65 {
            return Err(ScriptError::SchnorrSigSize);
        }

        let xonly =
            secp256k1::XOnlyPublicKey::from_slice(pubkey_bytes).map_err(|_| ScriptError::SchnorrSig)?;

        let mut hash_type_byte: u8 = 0x00; // SIGHASH_DEFAULT
        let sig_data = if sig.len() == 65 {
            hash_type_byte = sig[64];
            if hash_type_byte == 0x00 {
                // Explicit DEFAULT byte is not allowed
                return Err(ScriptError::SchnorrSigHashtype);
            }
            &sig[..64]
        } else {
            sig
        };

        let schnorr_sig = secp256k1::schnorr::Signature::from_slice(sig_data)
            .map_err(|_| ScriptError::SchnorrSig)?;

        let sighash = self
            .taproot_sighash(hash_type_byte, sig_version, exec_data)
            .ok_or(ScriptError::SchnorrSigHashtype)?;

        let msg = Message::from_digest(sighash);
        match secp_ctx().verify_schnorr(&schnorr_sig, &msg, &xonly) {
            Ok(()) => Ok(true),
            Err(_) => Err(ScriptError::SchnorrSig),
        }
    }

    fn check_lock_time(&self, lock_time: &ScriptNum) -> bool {
        let tx_locktime = self.tx.lock_time.to_consensus_u32();
        let n = lock_time.value();

        // Both must be same type (block height vs timestamp)
        if !((tx_locktime < LOCKTIME_THRESHOLD && n < LOCKTIME_THRESHOLD as i64)
            || (tx_locktime >= LOCKTIME_THRESHOLD && n >= LOCKTIME_THRESHOLD as i64))
        {
            return false;
        }

        if n > tx_locktime as i64 {
            return false;
        }

        // nSequence must not be SEQUENCE_FINAL
        if self.tx.input[self.input_index].sequence == Sequence::MAX {
            return false;
        }

        true
    }

    fn check_sequence(&self, sequence: &ScriptNum) -> bool {
        let tx_sequence = self.tx.input[self.input_index].sequence.0;

        // Tx version must be >= 2 for BIP68.
        // Bitcoin Core uses uint32_t for version, so the comparison is unsigned.
        if (self.tx.version.0 as u32) < 2 {
            return false;
        }

        // Tx sequence must not have disable flag
        if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return false;
        }

        let mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK;
        let tx_masked = (tx_sequence & mask) as i64;
        let n_masked = sequence.value() & mask as i64;

        // Both must be same type
        if !((tx_masked < SEQUENCE_LOCKTIME_TYPE_FLAG as i64
            && n_masked < SEQUENCE_LOCKTIME_TYPE_FLAG as i64)
            || (tx_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG as i64
                && n_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG as i64))
        {
            return false;
        }

        if n_masked > tx_masked {
            return false;
        }

        true
    }
}

/// Remove OP_CODESEPARATOR (0xab) opcodes from a script for legacy sighash.
fn remove_codeseparators(script: &[u8]) -> ScriptBuf {
    let mut result = Vec::with_capacity(script.len());
    let mut pc = 0;
    while pc < script.len() {
        let opcode = script[pc];
        if opcode == 0xab {
            pc += 1;
            continue;
        }
        let start = pc;
        pc += 1;
        if opcode <= 75 {
            pc += opcode as usize;
        } else if opcode == 0x4c && pc < script.len() {
            let n = script[pc] as usize;
            pc += 1 + n;
        } else if opcode == 0x4d && pc + 1 < script.len() {
            let n = script[pc] as usize | ((script[pc + 1] as usize) << 8);
            pc += 2 + n;
        } else if opcode == 0x4e && pc + 3 < script.len() {
            let n = script[pc] as usize
                | ((script[pc + 1] as usize) << 8)
                | ((script[pc + 2] as usize) << 16)
                | ((script[pc + 3] as usize) << 24);
            pc += 4 + n;
        }
        let end = pc.min(script.len());
        result.extend_from_slice(&script[start..end]);
    }
    ScriptBuf::from_bytes(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_codeseparators_keeps_push_data() {
        // Each push form carries three 0xab bytes as data, then an
        // OP_CODESEPARATOR follows. Only the opcode is removed.
        let pushes: [&[u8]; 4] = [
            &[0x03],
            &[0x4c, 0x03],
            &[0x4d, 0x03, 0x00],
            &[0x4e, 0x03, 0x00, 0x00, 0x00],
        ];
        for push in pushes {
            let mut script = push.to_vec();
            script.extend([0xab; 4]);
            let got = remove_codeseparators(&script);
            assert_eq!(got.as_bytes(), &script[..script.len() - 1], "push {push:02x?}");
        }
    }
}
