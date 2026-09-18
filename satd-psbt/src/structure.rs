//! BIP 370 and BIP 375 structural validation.
//!
//! This is BIP 375's first check ("PSBT Structure"), plus the required-field
//! rules BIP 370 states for version 2. It is deliberately separate from
//! parsing: the raw layer carries a malformed field through untouched so that
//! `decodepsbt` can show an operator exactly what is wrong with their PSBT,
//! and this is the function that says what that is.

use bitcoin::secp256k1::PublicKey;

use crate::error::PsbtError;
use crate::keys;
use crate::raw::{PsbtVersion, RawMap, RawPsbt};
use crate::v2::V2View;

/// Check a version 2 PSBT's structure. Version 0 PSBTs are not this crate's
/// business and are accepted without comment.
pub fn validate_structure(raw: &RawPsbt) -> Result<(), PsbtError> {
    if raw.version()? == PsbtVersion::V0 {
        return Ok(());
    }
    let view = V2View::new(raw)?;

    // BIP 370 required fields. `tx_version` and the per-input outpoint fields
    // have no default, so a PSBT without them describes no transaction.
    view.tx_version()?;
    for input in view.inputs() {
        input.previous_txid()?;
        input.output_index()?;
        // Reading these validates their ranges (BIP 370: a time lock time is
        // at least 500000000, a height lock time is below it and non-zero).
        input.time_locktime()?;
        input.height_locktime()?;
    }
    for output in view.outputs() {
        output.amount()?;
    }

    // BIP 375 §"PSBT Structure".
    for output in view.outputs() {
        let has_script = output
            .map()
            .get_single(keys::output::SCRIPT)
            .is_some_and(|s| !s.is_empty());
        let has_info = output.map().contains_type(keys::output::SP_V0_INFO);
        let has_label = output.map().contains_type(keys::output::SP_V0_LABEL);

        if !has_script && !has_info {
            return Err(PsbtError::structure(format!(
                "output {} has neither PSBT_OUT_SCRIPT nor PSBT_OUT_SP_V0_INFO",
                output.index()
            )));
        }
        if has_label && !has_info {
            return Err(PsbtError::structure(format!(
                "output {} has PSBT_OUT_SP_V0_LABEL but no PSBT_OUT_SP_V0_INFO",
                output.index()
            )));
        }
        // Validates the 66-byte length and both points.
        output.sp_v0_info()?;
        output.sp_v0_label()?;
    }

    // Lengths and point validity of every share and proof, global and per
    // input; then that each share has a proof under the same scan key.
    check_shares_and_proofs(
        &raw.global,
        keys::global::SP_ECDH_SHARE,
        keys::global::SP_DLEQ,
        "global",
    )?;
    for share in view.sp_ecdh_shares()? {
        PublicKey::from_slice(&share.share).map_err(|_| {
            PsbtError::structure("a global PSBT_GLOBAL_SP_ECDH_SHARE is not a valid point")
        })?;
    }
    view.sp_dleq_proofs()?;

    for input in view.inputs() {
        let label = format!("input {}", input.index());
        check_shares_and_proofs(
            input.map(),
            keys::input::SP_ECDH_SHARE,
            keys::input::SP_DLEQ,
            &label,
        )?;
        for share in input.sp_ecdh_shares()? {
            PublicKey::from_slice(&share.share).map_err(|_| {
                PsbtError::structure(format!(
                    "{label}: PSBT_IN_SP_ECDH_SHARE is not a valid point"
                ))
            })?;
        }
        input.sp_dleq_proofs()?;
    }

    // Once a silent payment output's script has been computed, the
    // transaction it was computed from is fixed: any further input or output
    // would change the shared secret and the script with it.
    let any_sp_script = view.outputs().any(|o| {
        o.map().contains_type(keys::output::SP_V0_INFO)
            && o.map()
                .get_single(keys::output::SCRIPT)
                .is_some_and(|s| !s.is_empty())
    });
    if any_sp_script && view.tx_modifiable()? != 0 {
        return Err(PsbtError::structure(
            "a silent payment output has PSBT_OUT_SCRIPT but PSBT_GLOBAL_TX_MODIFIABLE is not zero",
        ));
    }

    Ok(())
}

/// Every ECDH share must have a DLEQ proof under the same scan key, and every
/// proof a share. A share without a proof is an unverifiable claim about
/// where money is going; a proof without a share proves nothing.
fn check_shares_and_proofs(
    map: &RawMap,
    share_type: u64,
    proof_type: u64,
    label: &str,
) -> Result<(), PsbtError> {
    for (scan_key, _) in map.get_all(share_type) {
        if !map.contains(proof_type, scan_key) {
            return Err(PsbtError::structure(format!(
                "{label}: an ECDH share has no DLEQ proof for the same scan key"
            )));
        }
    }
    for (scan_key, _) in map.get_all(proof_type) {
        if !map.contains(share_type, scan_key) {
            return Err(PsbtError::structure(format!(
                "{label}: a DLEQ proof has no ECDH share for the same scan key"
            )));
        }
    }
    Ok(())
}
