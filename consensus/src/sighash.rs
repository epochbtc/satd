//! Transaction signature checker — adapts bitcoin::sighash::SighashCache for
//! use with our SignatureChecker trait.
#![allow(clippy::nonminimal_bool)]

use bitcoin::hashes::Hash;
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::secp256k1::{self, Message, Secp256k1};
use bitcoin::{Amount, Script, ScriptBuf, Sequence, Transaction, TxOut};

use crate::checker::{ExecData, SignatureChecker, SigVersion};
use crate::error::ScriptError;
use crate::scriptnum::ScriptNum;

const LOCKTIME_THRESHOLD: u32 = 500_000_000;
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;


/// A signature checker backed by an actual transaction, delegating sighash
/// computation to `bitcoin::sighash::SighashCache`.
pub struct TxSignatureChecker<'a> {
    tx: &'a Transaction,
    input_index: usize,
    amount: Amount,
    prev_outputs: &'a [TxOut],
    secp: Secp256k1<secp256k1::All>,
}

impl<'a> TxSignatureChecker<'a> {
    pub fn new(
        tx: &'a Transaction,
        input_index: usize,
        amount: Amount,
        prev_outputs: &'a [TxOut],
    ) -> Self {
        Self {
            tx,
            input_index,
            amount,
            prev_outputs,
            secp: Secp256k1::new(),
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
        let sighash_type = match EcdsaSighashType::from_consensus(hash_type_byte as u32) {
            sht => sht,
        };

        let script_code_obj = Script::from_bytes(script_code);

        let sighash = match sig_version {
            SigVersion::WitnessV0 => {
                // BIP143 segwit v0 sighash
                let mut cache = SighashCache::new(self.tx);
                match cache.p2wsh_signature_hash(
                    self.input_index,
                    script_code_obj,
                    self.amount,
                    sighash_type,
                ) {
                    Ok(h) => h.to_byte_array(),
                    Err(_) => return false,
                }
            }
            SigVersion::Base => {
                // Legacy sighash
                let cache = SighashCache::new(self.tx);
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

        let msg = match Message::from_digest(sighash) {
            msg => msg,
        };

        self.secp
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

        let mut cache = SighashCache::new(self.tx);
        let prevouts = Prevouts::All(self.prev_outputs);

        let sighash = match sig_version {
            SigVersion::Taproot => {
                // Key-path spending
                cache
                    .taproot_key_spend_signature_hash(self.input_index, &prevouts, tap_sighash_type)
                    .map_err(|_| ScriptError::SchnorrSigHashtype)?
            }
            SigVersion::Tapscript => {
                // Script-path spending
                let leaf_hash = bitcoin::TapLeafHash::from_byte_array(exec_data.tapleaf_hash);
                cache
                    .taproot_script_spend_signature_hash(
                        self.input_index,
                        &prevouts,
                        leaf_hash,
                        tap_sighash_type,
                    )
                    .map_err(|_| ScriptError::SchnorrSigHashtype)?
            }
            _ => unreachable!(),
        };

        let msg = Message::from_digest(sighash.to_byte_array());
        match self.secp.verify_schnorr(&schnorr_sig, &msg, &xonly) {
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
