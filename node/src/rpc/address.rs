//! Operator-facing RPC handlers for the address-history index.
//!
//! Three minimal RPCs cover the M3 surface: `getaddressbalance`,
//! `getaddresshistory`, `getaddressutxos`. Inputs accept either an
//! address string (parsed against the active network) or a
//! 32-byte hex scripthash (`{"scripthash": "<hex>"}` form). Output
//! shapes follow the `ADDRESS_INDEX.md` operator-RPC sketch.
//!
//! These are operator tools, not protocol surfaces — Electrum /
//! Esplora handlers in later milestones build on the same trait but
//! with their own request/response shapes.

use std::sync::Arc;

use bitcoin::Network;
use serde_json::{Value, json};

use crate::index::address::{AddressIndex, IndexError, Scripthash, scripthash_of};

/// Resolve a request parameter into a `Scripthash`. Accepts:
///
/// 1. A bare base58/bech32 address string (`"bcrt1..."`, `"1..."`, …).
///    Parsed against the active network — wrong-network rejected.
/// 2. An object form `{"scripthash": "<64 hex chars>"}` — bypasses the
///    address parser. Used by tooling that already holds the hash.
/// 3. An object form `{"address": "<addr>"}` — equivalent to (1).
pub fn parse_scripthash_param(param: &Value, network: Network) -> Result<Scripthash, String> {
    match param {
        Value::String(s) => parse_address(s, network),
        Value::Object(map) => {
            if let Some(Value::String(hex_sh)) = map.get("scripthash") {
                parse_hex_scripthash(hex_sh)
            } else if let Some(Value::String(addr)) = map.get("address") {
                parse_address(addr, network)
            } else {
                Err("expected {\"address\": \"...\"} or {\"scripthash\": \"<hex>\"}".to_string())
            }
        }
        _ => Err(
            "expected an address string or {address|scripthash} object".to_string(),
        ),
    }
}

fn parse_address(s: &str, network: Network) -> Result<Scripthash, String> {
    let unchecked: bitcoin::Address<bitcoin::address::NetworkUnchecked> = s
        .parse()
        .map_err(|e| format!("invalid address '{}': {}", s, e))?;
    let address = unchecked
        .require_network(network)
        .map_err(|e| format!("address '{}' not valid for network: {}", s, e))?;
    Ok(scripthash_of(&address.script_pubkey()))
}

fn parse_hex_scripthash(hex_sh: &str) -> Result<Scripthash, String> {
    let bytes = hex::decode(hex_sh).map_err(|e| format!("invalid scripthash hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "scripthash must be 32 bytes (64 hex chars); got {}",
            bytes.len()
        ));
    }
    let mut sh = [0u8; 32];
    sh.copy_from_slice(&bytes);
    Ok(sh)
}

/// `getaddressbalance` → `{ "confirmed": <sat>, "unconfirmed": <sat> }`.
/// The unconfirmed delta is signed (M4 fills it in); for now it is
/// always 0 and serialized as integer.
pub fn get_address_balance(
    index: &Arc<dyn AddressIndex>,
    param: &Value,
    network: Network,
) -> Result<Value, (i32, String)> {
    let sh = parse_scripthash_param(param, network).map_err(|e| (-8, e))?;
    let (confirmed, unconfirmed) = index.balance(&sh).map_err(index_error_to_rpc)?;
    Ok(json!({
        "confirmed": confirmed,
        "unconfirmed": unconfirmed,
    }))
}

/// `getaddresshistory` → array of `{type, height, txid, ...}` objects,
/// in `(height, txid)` ascending order. `type` is `"funding"` or
/// `"spending"`. Funding rows include `vout` and `amount_sat`; spending
/// rows include `vin` and `prev_txid`/`prev_vout`.
pub fn get_address_history(
    index: &Arc<dyn AddressIndex>,
    param: &Value,
    network: Network,
) -> Result<Value, (i32, String)> {
    let sh = parse_scripthash_param(param, network).map_err(|e| (-8, e))?;
    let entries = index.confirmed_history(&sh).map_err(index_error_to_rpc)?;

    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let v = match e {
            crate::index::address::HistoryEntry::Funding {
                height,
                txid,
                vout,
                amount_sat,
            } => json!({
                "type": "funding",
                "height": height,
                "txid": txid.to_string(),
                "vout": vout,
                "amount_sat": amount_sat,
            }),
            crate::index::address::HistoryEntry::Spending {
                height,
                txid,
                vin,
                prev_outpoint,
            } => json!({
                "type": "spending",
                "height": height,
                "txid": txid.to_string(),
                "vin": vin,
                "prev_txid": prev_outpoint.txid.to_string(),
                "prev_vout": prev_outpoint.vout,
            }),
        };
        out.push(v);
    }
    Ok(Value::Array(out))
}

/// `getaddressutxos` → array of `{txid, vout, height, amount_sat}`.
pub fn get_address_utxos(
    index: &Arc<dyn AddressIndex>,
    param: &Value,
    network: Network,
) -> Result<Value, (i32, String)> {
    let sh = parse_scripthash_param(param, network).map_err(|e| (-8, e))?;
    let utxos = index.utxos(&sh).map_err(index_error_to_rpc)?;

    let out: Vec<Value> = utxos
        .into_iter()
        .map(|u| {
            json!({
                "txid": u.txid.to_string(),
                "vout": u.vout,
                "height": u.height,
                "amount_sat": u.amount_sat,
            })
        })
        .collect();
    Ok(Value::Array(out))
}

fn index_error_to_rpc(e: IndexError) -> (i32, String) {
    match e {
        // Use Core's "method not found / not enabled" error code so
        // tooling can detect a disabled-index server cleanly.
        IndexError::Disabled => (-32601, e.to_string()),
        // Distinct application error code for "the index is enabled
        // but its on-disk data is incomplete". -32605 is unused by
        // Core; clients can detect and prompt the operator to
        // reindex (round-3 H2).
        IndexError::Incomplete => (-32605, e.to_string()),
        IndexError::Storage(_) => (-32603, e.to_string()),
    }
}
