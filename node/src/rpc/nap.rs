//! The NAP publisher RPCs, satd's own: `createnapattestation`,
//! `submitnapattestation`, `listnapattestations` and
//! `removenapattestation`. All four answer an error unless the node runs
//! with `-nap=1`.

use std::str::FromStr as _;

use bitcoin::{OutPoint, ScriptBuf};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{Value, json};

use crate::chain::state::ChainState;
use crate::nap::publisher::{Published, encode_signature};
use crate::nap::{NapSignature, PublishError, Publisher};
use crate::rpc::amounts::{annotate_units, default_unit, format_amount};
use crate::rpc::error::RpcError;

/// The publisher, or the error every NAP RPC answers without `-nap=1`.
pub fn enabled(nap: Option<&Publisher>) -> Result<&Publisher, ErrorObjectOwned> {
    nap.ok_or_else(|| {
        RpcError::new(-1, "network.disabled", "NAP is disabled")
            .with_suggestion("Start satd with -nap=1 to publish attestations.")
            .into_error_object()
    })
}

/// `"<txid>:<vout>"`, as `createnapattestation` and `removenapattestation`
/// take it.
pub fn parse_outpoint(s: &str) -> Result<OutPoint, ErrorObjectOwned> {
    OutPoint::from_str(s).map_err(|_| {
        RpcError::new(-8, "rpc.input.parse", format!("outpoint must be \"<txid>:<vout>\", not \"{s}\""))
            .into_error_object()
    })
}

/// A publisher refusal as an RPC error. A rejection is -26, as Core reports
/// a transaction that fails verification, and names its rule in the message
/// and, with extended errors, in `data.debug.rule`.
pub fn error(e: PublishError) -> ErrorObjectOwned {
    let (code, category) = match &e {
        PublishError::Format(_) => (-8, "rpc.input.parse"),
        PublishError::NotFound => (-8, "storage.not_found"),
        PublishError::ChainTooShort | PublishError::Busy => (-1, "node.initializing"),
        PublishError::Io(_) => (-1, "storage.io"),
        PublishError::Rejected(_)
        | PublishError::Superseded { .. }
        | PublishError::KeyLimit
        | PublishError::StoreFull { .. } => {
            (-26, "nap.rejected")
        }
    };
    let message = match code {
        -26 => format!("rejected ({}): {e}", e.rule()),
        _ => e.to_string(),
    };
    RpcError::new(code, category, message).with_debug(json!({ "rule": e.rule() })).into_error_object()
}

fn format_name(signature: &NapSignature) -> &'static str {
    match signature {
        NapSignature::Simple(_) => "simple",
        NapSignature::Full(_) => "full",
        NapSignature::Legacy(_) => "legacy",
    }
}

/// The signature formats a coin's script takes (D13, D9).
fn formats_for(script: &ScriptBuf) -> Vec<&'static str> {
    if script.is_witness_program() {
        vec!["simple", "full"]
    } else if script.is_p2pkh() {
        vec!["legacy", "full"]
    } else {
        vec!["full"]
    }
}

/// `createnapattestation "outpoint" "key" "value"`.
pub fn create(
    nap: &Publisher,
    chain: &ChainState,
    outpoint: &str,
    key: &str,
    value: &str,
) -> Result<Value, ErrorObjectOwned> {
    let outpoint = parse_outpoint(outpoint)?;
    let draft = nap.create(chain, outpoint, key, value).map_err(error)?;
    let unit = default_unit();
    let mut out = json!({
        "message": draft.message,
        "outpoint": outpoint.to_string(),
        "key": key,
        "value": value,
        "anchor_height": draft.anchor_height,
        "anchor_hash": draft.anchor_hash.to_string(),
        "amount": format_amount(draft.coin.value.to_sat(), unit),
        "formats": formats_for(&draft.coin.script_pubkey),
        "warnings": draft.warnings,
    });
    if let Ok(address) = bitcoin::Address::from_script(&draft.coin.script_pubkey, chain.network) {
        out["address"] = json!(address.to_string());
    }
    annotate_units(&mut out, unit);
    Ok(out)
}

/// `submitnapattestation "message" "signature"`.
pub fn submit(
    nap: &Publisher,
    chain: &ChainState,
    message: &str,
    signature: &str,
) -> Result<Value, ErrorObjectOwned> {
    let (published, replaced) = nap.submit(chain, message, signature).map_err(error)?;
    let mut out = describe(&published);
    out["replaced"] = json!(replaced.map(|id| id.to_string()));
    Ok(out)
}

/// `listnapattestations`.
pub fn list(nap: &Publisher, chain: &ChainState) -> Value {
    Value::Array(nap.list(chain).iter().map(describe).collect())
}

/// `removenapattestation "outpoint" "key"`.
pub fn remove(nap: &Publisher, outpoint: &str, key: &str) -> Result<Value, ErrorObjectOwned> {
    let outpoint = parse_outpoint(outpoint)?;
    let att = nap.remove(outpoint, key).map_err(error)?;
    Ok(json!({ "id": att.id().to_string() }))
}

/// One stored attestation as the RPCs report it.
fn describe(p: &Published) -> Value {
    let att = &p.attestation;
    let unit = default_unit();
    let mut out = json!({
        "id": att.id().to_string(),
        "outpoint": att.outpoint().to_string(),
        "key": att.key(),
        "value": att.value(),
        "anchor_height": att.anchor_height(),
        "anchor_hash": att.anchor_hash().to_string(),
        "format": format_name(att.signature()),
        "signature": encode_signature(att.signature()),
        "message": att.message(),
    });
    match &p.status {
        Some(Ok(amount)) => {
            out["status"] = json!("valid");
            out["amount"] = format_amount(amount.to_sat(), unit);
        }
        Some(Err(r)) => {
            out["status"] = json!(r.rule());
            out["reason"] = json!(r.to_string());
        }
        None => {
            out["status"] = json!("unknown");
            out["reason"] = json!("not judged yet: the chain tip kept changing; ask again");
        }
    }
    annotate_units(&mut out, unit);
    out
}
