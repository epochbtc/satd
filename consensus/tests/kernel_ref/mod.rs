//! Bitcoin Core's script interpreter, through libbitcoinkernel, behind the
//! single-input call shape these tests were written against
//! (`bitcoinconsensus::verify_with_flags`). It is the reference engine the
//! Rust interpreter is compared with.
//!
//! The checks before the script runs (flag bits, input index, the
//! transaction's encoding, the spent-output count) follow
//! libbitcoinconsensus's order and error names, so a test that reads them
//! sees what it saw before.
#![allow(dead_code, unused_imports)]

use bitcoinkernel::{KernelError, PrecomputedTransactionData, ScriptPubkey, ScriptVerifyError};

pub use bitcoinkernel::{
    VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_DERSIG, VERIFY_NULLDUMMY,
    VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
};

/// A spent output: the libbitcoinconsensus layout the tests already build.
#[repr(C)]
pub struct Utxo {
    pub script_pubkey: *const u8,
    pub script_pubkey_len: u32,
    pub value: i64,
}

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    ERR_SCRIPT,
    ERR_TX_INDEX,
    ERR_TX_SIZE_MISMATCH,
    ERR_TX_DESERIALIZE,
    ERR_INVALID_FLAGS,
    ERR_SPENT_OUTPUTS_REQUIRED,
    ERR_SPENT_OUTPUTS_MISMATCH,
}

pub fn verify_with_flags(
    spent_output_script: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
    flags: u32,
) -> Result<(), Error> {
    if flags & !bitcoinkernel::VERIFY_ALL != 0 {
        return Err(Error::ERR_INVALID_FLAGS);
    }
    let (tx, used): (bitcoin::Transaction, usize) =
        bitcoin::consensus::deserialize_partial(spending_transaction)
            .map_err(|_| Error::ERR_TX_DESERIALIZE)?;
    if used != spending_transaction.len() {
        return Err(Error::ERR_TX_SIZE_MISMATCH);
    }
    if input_index >= tx.input.len() {
        return Err(Error::ERR_TX_INDEX);
    }
    let spent: Vec<bitcoinkernel::TxOut> = match spent_outputs {
        Some(utxos) => {
            if utxos.len() != tx.input.len() {
                return Err(Error::ERR_SPENT_OUTPUTS_MISMATCH);
            }
            utxos
                .iter()
                .map(|u| {
                    // SAFETY: each `Utxo` points into a buffer the caller
                    // keeps alive for the call, as libbitcoinconsensus
                    // required.
                    let spk = unsafe {
                        std::slice::from_raw_parts(u.script_pubkey, u.script_pubkey_len as usize)
                    };
                    bitcoinkernel::TxOut::new(&ScriptPubkey::new(spk).unwrap(), u.value)
                })
                .collect()
        }
        None if flags & VERIFY_TAPROOT != 0 => return Err(Error::ERR_SPENT_OUTPUTS_REQUIRED),
        None => Vec::new(),
    };

    let ktx = bitcoinkernel::Transaction::new(spending_transaction)
        .map_err(|_| Error::ERR_TX_DESERIALIZE)?;
    let txdata = PrecomputedTransactionData::new(&ktx, &spent)
        .map_err(|_| Error::ERR_SPENT_OUTPUTS_MISMATCH)?;
    let spk = ScriptPubkey::new(spent_output_script).map_err(|_| Error::ERR_SCRIPT)?;
    bitcoinkernel::verify(&spk, Some(amount as i64), &ktx, input_index, Some(flags), &txdata)
        .map_err(|e| match e {
            KernelError::ScriptVerify(ScriptVerifyError::InvalidFlags)
            | KernelError::ScriptVerify(ScriptVerifyError::InvalidFlagsCombination) => {
                Error::ERR_INVALID_FLAGS
            }
            KernelError::ScriptVerify(ScriptVerifyError::SpentOutputsRequired) => {
                Error::ERR_SPENT_OUTPUTS_REQUIRED
            }
            KernelError::ScriptVerify(ScriptVerifyError::TxInputIndex) => Error::ERR_TX_INDEX,
            _ => Error::ERR_SCRIPT,
        })
}
