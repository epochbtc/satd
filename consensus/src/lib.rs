#![allow(clippy::collapsible_if, clippy::needless_return, clippy::manual_range_contains)]
//! Pure Rust Bitcoin script verification engine.
//!
//! Bitcoin Script's interpreter in Rust, built to give the same verdicts as
//! Bitcoin Core's.
//!
//! # Public API
//!
//! The entry points follow libbitcoinkernel's script verification, which is
//! how Core's own `CheckInputScripts` works:
//! - [`PrecomputedTransactionData`]: the per-transaction signature hash
//!   state, built once for a transaction and shared by all its inputs
//! - [`verify()`]: verify one input against it
//! - [`verify_transaction`]: every input of a transaction, in order
//! - [`Error`]: why verification failed, naming the script error
//! - `VERIFY_*` flag constants
//!
//! [`verify::verify_script`] and [`sighash::TxSignatureChecker`] stay public
//! for callers that need the interpreter itself.

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

use bitcoin::{Amount, Script, Transaction, TxOut};
use std::cell::RefCell;
use std::rc::Rc;

/// Why verification failed.
///
/// libbitcoinkernel reports a script failure as a bare
/// `btck_ScriptVerifyStatus` with no reason: the specific `ScriptError_t`
/// never crosses its C API. This engine computes the specific error, so it
/// reports it. Bitcoin Core names the script error in
/// `mempool-script-verify-flag-failed (...)` and every test that reads a
/// rejection reads that name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The script failed, and this is why.
    ErrScript(error::ScriptError),
    /// The input index is past the transaction's last input.
    ErrTxIndex,
    /// A flag bit outside [`flags::ALL_FLAGS`].
    ErrInvalidFlags,
    /// `VERIFY_TAPROOT` with no spent outputs: BIP 341 signature hashes
    /// commit to all of them.
    ErrSpentOutputsRequired,
    /// Spent outputs given, but not one per input.
    ErrSpentOutputsMismatch,
    /// The precomputed data was built for a different transaction than the
    /// one passed to [`verify()`].
    ErrTxMismatch,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Core's `ScriptErrorString`, which is what a rejection reason
            // quotes.
            Self::ErrScript(e) => write!(f, "{}", e.as_str()),
            Self::ErrTxIndex => write!(f, "invalid input index"),
            Self::ErrInvalidFlags => write!(f, "invalid flags"),
            Self::ErrSpentOutputsRequired => write!(f, "spent outputs required for taproot"),
            Self::ErrSpentOutputsMismatch => write!(f, "spent outputs count mismatch"),
            Self::ErrTxMismatch => write!(f, "precomputed data is for another transaction"),
        }
    }
}

impl std::error::Error for Error {}

/// A transaction's signature hash state, shared by all its inputs: Core's
/// `PrecomputedTransactionData`, and libbitcoinkernel's
/// `btck_PrecomputedTransactionData`.
///
/// The BIP 143 hashes (`hashPrevouts`, `hashSequence`, `hashOutputs`) and the
/// BIP 341 ones (prevouts, amounts, scripts, sequences, outputs) are the same
/// for every input of a transaction. Built once and passed to [`verify()`] for
/// each input, they are computed once per transaction instead of once per
/// input. Each is computed on first use.
pub struct PrecomputedTransactionData<'a> {
    tx: &'a Transaction,
    spent_outputs: &'a [TxOut],
    cache: sighash::SharedSighashCache<'a>,
}

impl<'a> PrecomputedTransactionData<'a> {
    /// `spent_outputs` is the output each input spends, in input order, or
    /// empty. It may be empty only when `VERIFY_TAPROOT` will not be set:
    /// legacy and BIP 143 signature hashes read only the input's own amount,
    /// which [`verify()`] takes. As in libbitcoinkernel, a non-empty list must
    /// have one entry per input.
    pub fn new(tx: &'a Transaction, spent_outputs: &'a [TxOut]) -> Result<Self, Error> {
        if !spent_outputs.is_empty() && spent_outputs.len() != tx.input.len() {
            return Err(Error::ErrSpentOutputsMismatch);
        }
        Ok(Self {
            tx,
            spent_outputs,
            cache: Rc::new(RefCell::new(sighash::TxSighashCache::new(tx))),
        })
    }
}

/// Verify that input `input_index` of `tx` spends `script_pubkey`, worth
/// `amount`, under `flag_set`: libbitcoinkernel's
/// `btck_script_pubkey_verify`.
///
/// `precomputed` must have been built for this `tx`.
pub fn verify(
    script_pubkey: &Script,
    amount: Amount,
    tx: &Transaction,
    input_index: usize,
    flag_set: u32,
    precomputed: &PrecomputedTransactionData<'_>,
) -> Result<(), Error> {
    if !flags::valid_flags(flag_set) {
        return Err(Error::ErrInvalidFlags);
    }
    if input_index >= tx.input.len() {
        return Err(Error::ErrTxIndex);
    }
    if !std::ptr::eq(tx, precomputed.tx) {
        return Err(Error::ErrTxMismatch);
    }
    if flags::has_flag(flag_set, flags::VERIFY_TAPROOT) && precomputed.spent_outputs.is_empty() {
        return Err(Error::ErrSpentOutputsRequired);
    }

    // The same transaction (checked above), at the lifetime the shared
    // cache holds.
    let tx = precomputed.tx;
    let tx_checker = sighash::TxSignatureChecker::with_cache(
        tx,
        input_index,
        amount,
        precomputed.spent_outputs,
        Rc::clone(&precomputed.cache),
    );
    let input = &tx.input[input_index];
    let witness_stack: Vec<Vec<u8>> = input.witness.iter().map(|w| w.to_vec()).collect();
    verify::verify_script(
        input.script_sig.as_bytes(),
        script_pubkey.as_bytes(),
        &witness_stack,
        flag_set,
        &tx_checker,
    )
    .map_err(Error::ErrScript)
}

/// Verify every input of a transaction, in order, against one
/// [`PrecomputedTransactionData`].
///
/// Returns `Ok(())` if every input verifies. On failure returns the zero-
/// based index of the first failing input along with the error. Errors that
/// concern the whole call (flags, the spent-output count) report input 0.
///
/// `prev_outputs` must have one entry per `tx.input`, in the same order.
pub fn verify_transaction(
    tx: &Transaction,
    prev_outputs: &[TxOut],
    flag_set: u32,
) -> Result<(), (usize, Error)> {
    if !flags::valid_flags(flag_set) {
        return Err((0, Error::ErrInvalidFlags));
    }
    if prev_outputs.len() != tx.input.len() {
        return Err((0, Error::ErrSpentOutputsMismatch));
    }
    // Only reachable with no inputs, where no input's check would say it.
    if flags::has_flag(flag_set, flags::VERIFY_TAPROOT) && prev_outputs.is_empty() {
        return Err((0, Error::ErrSpentOutputsRequired));
    }
    let precomputed = PrecomputedTransactionData::new(tx, prev_outputs).map_err(|e| (0, e))?;
    for (i, prev) in prev_outputs.iter().enumerate() {
        verify(&prev.script_pubkey, prev.value, tx, i, flag_set, &precomputed).map_err(|e| (i, e))?;
    }
    Ok(())
}
