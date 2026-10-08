//! The `vin[].witness` field is left out for an input without a witness.

use super::*;

fn vin(witness: Vec<String>) -> VinJson {
    VinJson {
        txid: "00".repeat(32),
        vout: 0,
        prevout: None,
        scriptsig: String::new(),
        scriptsig_asm: String::new(),
        witness,
        is_coinbase: false,
        sequence: 0xffff_ffff,
    }
}

#[test]
fn vin_without_a_witness_has_no_witness_key() {
    let v = serde_json::to_value(vin(Vec::new())).unwrap();
    assert!(
        v.get("witness").is_none(),
        "an input without a witness must not serialize `witness`: {v}"
    );
    // The other keys are all still there.
    for key in [
        "txid",
        "vout",
        "prevout",
        "scriptsig",
        "scriptsig_asm",
        "is_coinbase",
        "sequence",
    ] {
        assert!(v.get(key).is_some(), "missing {key}: {v}");
    }
}

#[test]
fn vin_with_a_witness_lists_it() {
    let v = serde_json::to_value(vin(vec!["30440220".to_string(), "02aa".to_string()])).unwrap();
    assert_eq!(v["witness"], serde_json::json!(["30440220", "02aa"]));
}
