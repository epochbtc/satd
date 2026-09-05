use serde_json::{json, Value};

use crate::rpc::address_decode::{decode_destination, Decoded};

/// `validateaddress` — Core's `src/rpc/output_script.cpp`.
///
/// `network` is not decoration: Core's `DecodeDestination` is network-scoped,
/// and satd used to parse `NetworkUnchecked` and call `assume_checked()`, so
/// it reported a mainnet address as valid on regtest.
///
/// A string that does not decode carries Core's `error` and, for a Bech32
/// checksum failure, the `error_locations` its error locator attributes.
pub fn validate_address(address: &str, network: bitcoin::Network) -> Value {
    match decode_destination(address, network) {
        Decoded::Valid(addr) => {
            let script = addr.script_pubkey();
            let script_type = if script.is_p2pkh() {
                "pubkeyhash"
            } else if script.is_p2sh() {
                "scripthash"
            } else if script.is_p2wpkh() {
                "witness_v0_keyhash"
            } else if script.is_p2wsh() {
                "witness_v0_scripthash"
            } else if script.is_p2tr() {
                "witness_v1_taproot"
            } else if script.witness_version().is_some() {
                "witness_unknown"
            } else {
                "nonstandard"
            };

            let witness_version = script.witness_version().map(|v| v.to_num());
            let mut out = json!({
                "isvalid": true,
                // Core re-encodes the decoded destination rather than echoing
                // the input, so a mixed-case Bech32 address comes back
                // normalised.
                "address": addr.to_string(),
                "scriptPubKey": hex::encode(script.as_bytes()),
                "isscript": script.is_p2sh() || script.is_p2wsh(),
                "iswitness": witness_version.is_some(),
                "witness_version": witness_version.map_or(-1i64, i64::from),
                "type": script_type,
            });
            // Core's `DescribeAddress` emits `witness_program` for a witness
            // destination only.
            if witness_version.is_some() {
                out["witness_program"] = json!(hex::encode(&script.as_bytes()[2..]));
            }
            out
        }
        Decoded::Invalid { error, locations } => json!({
            "isvalid": false,
            // Core pushes `error_locations` first and `error` second; key
            // order is not significant to any client, but the fields are:
            // both are always present on a failure, `error_locations` empty
            // when nothing could be attributed.
            "error_locations": locations,
            "error": error,
        }),
    }
}
