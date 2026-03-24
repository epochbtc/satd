use crate::error::ScriptError;
use crate::scriptnum::ScriptNum;

/// Signature version indicating which script rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigVersion {
    /// Bare scripts and BIP16 P2SH-wrapped redeemscripts.
    Base,
    /// Witness v0 (P2WPKH and P2WSH); see BIP 141.
    WitnessV0,
    /// Witness v1 with 32-byte program, key path spending; see BIP 341.
    Taproot,
    /// Witness v1 with 32-byte program, script path spending, leaf version 0xc0; see BIP 342.
    Tapscript,
}

/// Execution data accumulated during tapscript evaluation.
pub struct ExecData {
    pub tapleaf_hash_init: bool,
    pub tapleaf_hash: [u8; 32],

    pub codeseparator_pos_init: bool,
    pub codeseparator_pos: u32,

    pub annex_init: bool,
    pub annex_present: bool,
    pub annex_hash: [u8; 32],

    pub validation_weight_left_init: bool,
    pub validation_weight_left: i64,
}

impl ExecData {
    pub fn new() -> Self {
        Self {
            tapleaf_hash_init: false,
            tapleaf_hash: [0; 32],
            codeseparator_pos_init: false,
            codeseparator_pos: 0xFFFFFFFF,
            annex_init: false,
            annex_present: false,
            annex_hash: [0; 32],
            validation_weight_left_init: false,
            validation_weight_left: 0,
        }
    }
}

impl Default for ExecData {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for signature checking, matching Bitcoin Core's BaseSignatureChecker.
///
/// All methods return false by default (matching the C++ base class).
pub trait SignatureChecker {
    /// Check an ECDSA signature against a public key and script code.
    fn check_ecdsa_signature(
        &self,
        _sig: &[u8],
        _pubkey: &[u8],
        _script_code: &[u8],
        _sig_version: SigVersion,
    ) -> bool {
        false
    }

    /// Check a Schnorr signature (taproot/tapscript).
    fn check_schnorr_signature(
        &self,
        _sig: &[u8],
        _pubkey: &[u8],
        _sig_version: SigVersion,
        _exec_data: &ExecData,
    ) -> Result<bool, ScriptError> {
        Ok(false)
    }

    /// Check nLockTime against the transaction.
    fn check_lock_time(&self, _lock_time: &ScriptNum) -> bool {
        false
    }

    /// Check nSequence against the transaction input.
    fn check_sequence(&self, _sequence: &ScriptNum) -> bool {
        false
    }
}

/// A no-op signature checker that always returns false.
/// Used for testing non-signature opcodes.
pub struct NoopChecker;
impl SignatureChecker for NoopChecker {}
