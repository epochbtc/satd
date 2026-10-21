//! BIP 322 signing through a PSBT ("PSBT-based signing"): the creator and
//! finalizer roles.
//!
//! Hardware signers and multisig coordinators sign BIP 322 the way they sign
//! a transaction. The creator hands them `to_sign` as a version 0 PSBT, with
//! `to_spend` as input 0's UTXO and the message in the global field
//! [`PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE`], which a signer that knows the
//! field shows as a message to sign rather than a payment. Signers add
//! partial signatures; the coordinator (or the signer's wallet) adds what a
//! script needs to be satisfied, such as a witness script or a tap leaf.
//! [`finalize`] then builds the witness and returns the proof, simple when
//! `to_sign` is the default one and the challenge is native segwit, full
//! otherwise.
//!
//! Single-key inputs finalize through satd's own PSBT finalizer, the one
//! `finalizepsbt` uses. Everything else (multisig, tapscript leaves, other
//! scripts miniscript can satisfy) goes through rust-miniscript's. A script
//! neither satisfies needs a `ful` signature built by the holder's own tools.

use bitcoin::psbt::{Psbt, raw};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Script, ScriptBuf, Witness};
use miniscript::psbt::PsbtExt as _;

use super::{Proof, to_sign, to_spend};

/// BIP 322's global PSBT field: no key data, the UTF-8 message as the value.
pub const PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE: u8 = 0x09;

/// The magic bytes every serialized PSBT starts with.
const PSBT_MAGIC: &[u8] = b"psbt\xff";

/// A finalized BIP 322 PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finalized {
    /// The message the PSBT carries in [`PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE`].
    pub message: Vec<u8>,
    /// The scriptPubKey input 0 spends: the address the proof is for.
    pub challenge: ScriptBuf,
    pub proof: Proof,
}

/// Why a PSBT is not a finalizable BIP 322 PSBT.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PsbtError {
    #[error("the PSBT does not decode as a version 0 PSBT: {0}")]
    Decode(String),
    #[error("the PSBT carries no message (BIP 322 global field 0x09), so it is not a BIP 322 PSBT")]
    NoMessage,
    #[error(
        "the PSBT has {0} inputs; proof-of-funds PSBTs, with inputs beyond the first, are not accepted"
    )]
    ExtraInputs(usize),
    #[error("the PSBT's input has neither witness_utxo nor non_witness_utxo")]
    NoUtxo,
    #[error("the PSBT's input does not spend to_spend for its message and scriptPubKey: {0}")]
    NotToSpend(&'static str),
    #[error("the PSBT's transaction must have one output, of zero value, paying a bare OP_RETURN")]
    NotOpReturn,
    #[error("the PSBT is not fully signed: {0}")]
    Incomplete(String),
}

/// The `to_sign` PSBT for `message` against `challenge`, as BIP 322's
/// creator builds it: version 0, input 0 carrying both `to_spend` and its
/// output, and the message in field 0x09.
pub fn create(challenge: &Script, message: &[u8]) -> Psbt {
    let spend = to_spend(challenge, message);
    let unsigned = to_sign(spend.compute_txid(), Witness::new());
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("to_sign carries no signatures");
    psbt.inputs[0].witness_utxo = Some(spend.output[0].clone());
    psbt.inputs[0].non_witness_utxo = Some(spend);
    psbt.unknown.insert(message_key(), message.to_vec());
    psbt
}

fn message_key() -> raw::Key {
    raw::Key { type_value: PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE, key: Vec::new() }
}

/// Whether `bytes` are a serialized PSBT rather than a signature: no
/// signature string decodes to bytes starting with the PSBT magic (a
/// witness stack of 0x70 items whose first is 0x73 bytes long would, and
/// no signer emits one).
pub fn is_psbt(bytes: &[u8]) -> bool {
    bytes.starts_with(PSBT_MAGIC)
}

/// A BIP 322 PSBT that passed [`parse`]'s checks, signed or not.
#[derive(Debug, Clone)]
pub struct Signed {
    /// The message the PSBT carries in [`PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE`].
    pub message: Vec<u8>,
    /// The scriptPubKey input 0 spends: the address the proof is for.
    pub challenge: ScriptBuf,
    psbt: Psbt,
}

/// Parse and finalize a signed BIP 322 PSBT: [`parse`], then
/// [`Signed::finalize`].
pub fn finalize(bytes: &[u8]) -> Result<Finalized, PsbtError> {
    let signed = parse(bytes)?;
    let (message, challenge) = (signed.message.clone(), signed.challenge.clone());
    Ok(Finalized { message, challenge, proof: signed.finalize()? })
}

/// Decode a BIP 322 PSBT and check its structure.
///
/// The checks are the BIP's signer checks: the message field is set, input
/// 0 spends `to_spend:0` for that message and the scriptPubKey its UTXO
/// field names, and the one output is a zero-value bare `OP_RETURN`. Any
/// UTXO field present must be `to_spend`'s. A PSBT with more inputs is
/// proof of funds, which is refused.
pub fn parse(bytes: &[u8]) -> Result<Signed, PsbtError> {
    let psbt = Psbt::deserialize(bytes).map_err(|e| PsbtError::Decode(e.to_string()))?;
    let message = psbt.unknown.get(&message_key()).cloned().ok_or(PsbtError::NoMessage)?;
    if psbt.inputs.len() != 1 {
        return Err(PsbtError::ExtraInputs(psbt.inputs.len()));
    }
    let input = &psbt.inputs[0];
    let challenge = match (&input.witness_utxo, &input.non_witness_utxo) {
        (Some(utxo), _) => utxo.script_pubkey.clone(),
        (None, Some(tx)) => match tx.output.first() {
            Some(out) => out.script_pubkey.clone(),
            None => return Err(PsbtError::NotToSpend("non_witness_utxo has no outputs")),
        },
        (None, None) => return Err(PsbtError::NoUtxo),
    };
    let spend = to_spend(&challenge, &message);
    let spend_txid = spend.compute_txid();
    let prevout = psbt.unsigned_tx.input[0].previous_output;
    if prevout.txid != spend_txid || prevout.vout != 0 {
        return Err(PsbtError::NotToSpend("its prevout is not to_spend:0"));
    }
    if input.witness_utxo.as_ref().is_some_and(|u| *u != spend.output[0]) {
        return Err(PsbtError::NotToSpend("witness_utxo is not to_spend's output"));
    }
    if input.non_witness_utxo.as_ref().is_some_and(|tx| *tx != spend) {
        return Err(PsbtError::NotToSpend("non_witness_utxo is not to_spend"));
    }
    let outputs = &psbt.unsigned_tx.output;
    if outputs.len() != 1 || *outputs != to_sign(spend_txid, Witness::new()).output {
        return Err(PsbtError::NotOpReturn);
    }
    Ok(Signed { message, challenge, psbt })
}

impl Signed {
    /// Build input 0's witness (and scriptSig) from the signatures and
    /// scripts the PSBT carries, and return the proof: simple when
    /// `to_sign` is the default one and the challenge is native segwit,
    /// full otherwise. The proof is not verified here.
    pub fn finalize(self) -> Result<Proof, PsbtError> {
        let Signed { challenge, mut psbt, .. } = self;
        let spend_txid = psbt.unsigned_tx.input[0].previous_output.txid;
        crate::rpc::psbt::try_finalize_input(&mut psbt.inputs[0]);
        if !is_final(&psbt.inputs[0]) {
            psbt.finalize_inp_mut(&Secp256k1::verification_only(), 0)
                .map_err(|e| PsbtError::Incomplete(e.to_string()))?;
        }
        let input = &psbt.inputs[0];
        let mut tx = psbt.unsigned_tx.clone();
        tx.input[0].script_sig = input.final_script_sig.clone().unwrap_or_default();
        tx.input[0].witness = input.final_script_witness.clone().unwrap_or_default();

        let native_segwit = challenge.is_p2wpkh() || challenge.is_p2wsh() || challenge.is_p2tr();
        Ok(if native_segwit && tx == to_sign(spend_txid, tx.input[0].witness.clone()) {
            Proof::Simple(tx.input[0].witness.clone())
        } else {
            Proof::Full(tx)
        })
    }
}

fn is_final(input: &bitcoin::psbt::Input) -> bool {
    input.final_script_sig.is_some() || input.final_script_witness.is_some()
}

#[cfg(test)]
mod tests;
