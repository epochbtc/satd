//! Transaction signature checker — adapts bitcoin::sighash::SighashCache for
//! use with our SignatureChecker trait.
#![allow(clippy::nonminimal_bool)]

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::sighash::{self, EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::secp256k1::{self, Message, Secp256k1, VerifyOnly};
use bitcoin::{Amount, Script, ScriptBuf, Sequence, Transaction, TxOut};
use std::cell::RefCell;
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

/// Shared `SighashCache` container. `SighashCache` lazily populates per-tx
/// hashes (`hashPrevouts`, `hashSequence`, `hashOutputs`) which are identical
/// across all inputs of a transaction — so one cache per tx is correct and
/// optimal.  `RefCell` gives us interior mutability so `check_*` methods can
/// keep their `&self` trait signature while the cache's encode helpers
/// require `&mut self`.  `Rc` lets a higher-level batch verify share a single
/// cache across per-input `TxSignatureChecker`s.
pub type SharedSighashCache<'a> = Rc<RefCell<SighashCache<&'a Transaction>>>;

/// A signature checker backed by an actual transaction, delegating sighash
/// computation to `bitcoin::sighash::SighashCache`.
pub struct TxSignatureChecker<'a> {
    tx: &'a Transaction,
    input_index: usize,
    amount: Amount,
    prev_outputs: &'a [TxOut],
    cache: SharedSighashCache<'a>,
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
            Rc::new(RefCell::new(SighashCache::new(tx))),
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
        }
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
                match cache.segwit_v0_encode_signing_data_to(
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
                match cache.legacy_signature_hash(
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

        // Compute taproot sighash
        let tap_sighash_type =
            TapSighashType::from_consensus_u8(hash_type_byte).map_err(|_| ScriptError::SchnorrSigHashtype)?;

        let mut cache = self.cache.borrow_mut();
        let prevouts = Prevouts::All(self.prev_outputs);

        // Build annex from ExecData if present
        let annex_data: Option<Vec<u8>> = if exec_data.annex_init && exec_data.annex_present {
            // We need the original annex bytes for sighash computation.
            // ExecData only stores the hash. We need the raw annex from the witness.
            // For now, reconstruct from the transaction's witness data.
            let witness = &self.tx.input[self.input_index].witness;
            let wit_items: Vec<&[u8]> = witness.iter().collect();
            if wit_items.len() >= 2 {
                let last = wit_items[wit_items.len() - 1];
                if !last.is_empty() && last[0] == 0x50 {
                    Some(last.to_vec())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let annex = annex_data
            .as_deref()
            .and_then(|bytes| sighash::Annex::new(bytes).ok());

        let sighash = match sig_version {
            SigVersion::Taproot => {
                // Key-path spending: no leaf hash or codeseparator
                let mut engine = bitcoin::TapSighash::engine();
                cache
                    .taproot_encode_signing_data_to(
                        &mut engine,
                        self.input_index,
                        &prevouts,
                        annex,
                        None, // no leaf hash for key-path
                        tap_sighash_type,
                    )
                    .map_err(|_| ScriptError::SchnorrSigHashtype)?;
                bitcoin::TapSighash::from_engine(engine)
            }
            SigVersion::Tapscript => {
                // Script-path spending: include leaf hash and codeseparator position
                let leaf_hash = bitcoin::TapLeafHash::from_byte_array(exec_data.tapleaf_hash);
                let codesep_pos = exec_data.codeseparator_pos;
                let mut engine = bitcoin::TapSighash::engine();
                cache
                    .taproot_encode_signing_data_to(
                        &mut engine,
                        self.input_index,
                        &prevouts,
                        annex,
                        Some((leaf_hash, codesep_pos)),
                        tap_sighash_type,
                    )
                    .map_err(|_| ScriptError::SchnorrSigHashtype)?;
                bitcoin::TapSighash::from_engine(engine)
            }
            _ => unreachable!(),
        };

        let msg = Message::from_digest(sighash.to_byte_array());
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
