use serde_json::{json, Value};

/// `validateaddress` — check if an address is valid and return info.
pub fn validate_address(address: &str) -> Value {
    match address.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>() {
        Ok(addr) => {
            let script = addr.assume_checked().script_pubkey();
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
            } else {
                "nonstandard"
            };

            let is_witness = script.is_p2wpkh() || script.is_p2wsh() || script.is_p2tr();

            json!({
                "isvalid": true,
                "address": address,
                "scriptPubKey": hex::encode(script.as_bytes()),
                "isscript": script.is_p2sh() || script.is_p2wsh(),
                "iswitness": is_witness,
                "witness_version": if script.is_p2tr() { 1 } else if is_witness { 0 } else { -1 },
                "type": script_type,
            })
        }
        Err(_) => {
            json!({
                "isvalid": false,
            })
        }
    }
}
