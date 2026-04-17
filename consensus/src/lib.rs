#![allow(clippy::collapsible_if, clippy::needless_return, clippy::manual_range_contains)]
//! Pure Rust Bitcoin script verification engine.
//!
//! A drop-in replacement for the `bitcoinconsensus` crate's C++ FFI, implementing
//! the Bitcoin Script interpreter in idiomatic Rust. Designed to produce
//! identical results to Bitcoin Core's libbitcoinconsensus for all transactions.
//!
//! # Public API
//!
//! The public API matches `bitcoinconsensus` exactly:
//! - [`verify`] / [`verify_with_flags`] — verify a single input
//! - [`Utxo`] — spent output data for taproot
//! - [`Error`] — coarse verification error
//! - `VERIFY_*` flag constants

pub mod checker;
pub mod condition;
pub mod encoding;
pub mod error;
pub mod eval;
pub mod flags;
pub mod scriptnum;
pub mod sighash;
pub mod stack;
pub mod verify;
pub mod witness;

// Re-export flag constants at crate root for API compatibility
pub use flags::{
    VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_DERSIG, VERIFY_NONE,
    VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
};

use std::os::raw::{c_uchar, c_uint};

/// Spent output data for taproot signature hash computation.
/// Layout matches `bitcoinconsensus::Utxo`.
#[repr(C)]
pub struct Utxo {
    pub script_pubkey: *const c_uchar,
    pub script_pubkey_len: c_uint,
    pub value: i64,
}

/// Coarse error type matching `bitcoinconsensus::Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    ErrScript,
    ErrTxIndex,
    ErrTxSizeMismatch,
    ErrTxDeserialize,
    ErrAmountRequired,
    ErrInvalidFlags,
    ErrSpentOutputsRequired,
    ErrSpentOutputsMismatch,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ErrScript => write!(f, "script verification failed"),
            Self::ErrTxIndex => write!(f, "invalid input index"),
            Self::ErrTxSizeMismatch => write!(f, "tx size mismatch"),
            Self::ErrTxDeserialize => write!(f, "tx deserialization failed"),
            Self::ErrAmountRequired => write!(f, "amount required for witness"),
            Self::ErrInvalidFlags => write!(f, "invalid flags"),
            Self::ErrSpentOutputsRequired => write!(f, "spent outputs required for taproot"),
            Self::ErrSpentOutputsMismatch => write!(f, "spent outputs count mismatch"),
        }
    }
}

impl std::error::Error for Error {}

/// Verify a single transaction input with automatic flag selection.
///
/// If `spent_outputs` is provided, taproot verification is enabled.
pub fn verify(
    spent_output_script: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
) -> Result<(), Error> {
    let flag_set = if spent_outputs.is_some() {
        flags::VERIFY_ALL_PRE_TAPROOT | flags::VERIFY_TAPROOT
    } else {
        flags::VERIFY_ALL_PRE_TAPROOT
    };
    verify_with_flags(
        spent_output_script,
        amount,
        spending_transaction,
        spent_outputs,
        input_index,
        flag_set,
    )
}

/// Verify a single transaction input with explicit flag selection.
///
/// This is the main entry point, matching `bitcoinconsensus::verify_with_flags()`.
pub fn verify_with_flags(
    spent_output_script: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
    flag_set: u32,
) -> Result<(), Error> {
    // Validate flags
    if !flags::valid_flags(flag_set) {
        return Err(Error::ErrInvalidFlags);
    }

    // Taproot requires spent outputs
    if flags::has_flag(flag_set, flags::VERIFY_TAPROOT) && spent_outputs.is_none() {
        return Err(Error::ErrSpentOutputsRequired);
    }

    // Deserialize transaction
    let tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(spending_transaction).map_err(|_| Error::ErrTxDeserialize)?;

    // Validate input index
    if input_index >= tx.input.len() {
        return Err(Error::ErrTxIndex);
    }

    // Validate spent outputs count
    if let Some(utxos) = spent_outputs {
        if utxos.len() != tx.input.len() {
            return Err(Error::ErrSpentOutputsMismatch);
        }
    }

    // Build prev_outputs only when taproot is active — BIP341 sighash is the
    // only code path that reads `self.prev_outputs` in `TxSignatureChecker`.
    // For legacy / segwit-v0 verifies, we can pass an empty slice and skip
    // the N× allocation that was building one TxOut per input.
    let prev_outputs: Vec<bitcoin::TxOut> = if flags::has_flag(flag_set, flags::VERIFY_TAPROOT) {
        // Taproot requires a matching prev_output per input.
        let utxos = spent_outputs.expect("VERIFY_TAPROOT requires spent_outputs (enforced above)");
        utxos
            .iter()
            .map(|u| {
                let script_bytes = unsafe {
                    std::slice::from_raw_parts(u.script_pubkey, u.script_pubkey_len as usize)
                };
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(u.value as u64),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(script_bytes.to_vec()),
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    // Build checker
    let tx_checker = sighash::TxSignatureChecker::new(
        &tx,
        input_index,
        bitcoin::Amount::from_sat(amount),
        &prev_outputs,
    );

    // Get witness
    let witness_stack: Vec<Vec<u8>> = tx.input[input_index]
        .witness
        .iter()
        .map(|w| w.to_vec())
        .collect();

    // Get scriptSig
    let script_sig = tx.input[input_index].script_sig.as_bytes();

    // Call VerifyScript
    verify::verify_script(
        script_sig,
        spent_output_script,
        &witness_stack,
        flag_set,
        &tx_checker,
    )
    .map_err(|_| Error::ErrScript)
}

/// Verify every input of a transaction in one batch.
///
/// Preferred over looping over `verify_with_flags` because it:
/// - Accepts an already-decoded `Transaction` (avoids N× re-deserialization
///   when verifying an N-input tx).
/// - Shares a single `SighashCache` across all inputs — BIP143 and BIP341
///   hash `hashPrevouts` / `hashSequence` / `hashOutputs` are tx-wide and
///   otherwise recomputed per input.
///
/// Returns `Ok(())` if every input verifies.  On failure returns the zero-
/// based index of the first failing input along with the error.
///
/// `prev_outputs` must have one entry per `tx.input`, in the same order.
pub fn verify_transaction(
    tx: &bitcoin::Transaction,
    prev_outputs: &[bitcoin::TxOut],
    flag_set: u32,
) -> Result<(), (usize, Error)> {
    use std::cell::RefCell;
    use std::rc::Rc;

    if !flags::valid_flags(flag_set) {
        return Err((0, Error::ErrInvalidFlags));
    }
    if prev_outputs.len() != tx.input.len() {
        return Err((0, Error::ErrSpentOutputsMismatch));
    }
    if flags::has_flag(flag_set, flags::VERIFY_TAPROOT) && prev_outputs.is_empty() {
        return Err((0, Error::ErrSpentOutputsRequired));
    }

    // One SighashCache for the whole tx — the key optimisation of this API.
    let cache = Rc::new(RefCell::new(bitcoin::sighash::SighashCache::new(tx)));

    // TxSignatureChecker only reads prev_outputs in the BIP341 taproot path.
    // For non-taproot verifies we can pass an empty slice to skip the
    // unnecessary indirection.
    let checker_prevs: &[bitcoin::TxOut] = if flags::has_flag(flag_set, flags::VERIFY_TAPROOT) {
        prev_outputs
    } else {
        &[]
    };

    for (i, input) in tx.input.iter().enumerate() {
        let prev = &prev_outputs[i];
        let tx_checker = sighash::TxSignatureChecker::with_cache(
            tx,
            i,
            prev.value,
            checker_prevs,
            Rc::clone(&cache),
        );

        let witness_stack: Vec<Vec<u8>> = input.witness.iter().map(|w| w.to_vec()).collect();
        let script_sig = input.script_sig.as_bytes();
        let spent_output_script = prev.script_pubkey.as_bytes();

        verify::verify_script(
            script_sig,
            spent_output_script,
            &witness_stack,
            flag_set,
            &tx_checker,
        )
        .map_err(|_| (i, Error::ErrScript))?;
    }

    Ok(())
}
