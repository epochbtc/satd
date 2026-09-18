//! Loading the vendored BIP vectors.
//!
//! Included by each integration test binary separately, so any one of them
//! uses only part of this file.
#![allow(dead_code)]

use base64::Engine as _;
use serde_json::Value;

pub const BIP375: &str = include_str!("../vectors/bip375_test_vectors.json");
pub const BIP370: &str = include_str!("../vectors/bip370_test_vectors.json");

pub struct Vector {
    pub description: String,
    pub psbt: Vec<u8>,
    pub base64: String,
    /// BIP 375's per-vector override of the four-check sequence.
    pub checks: Option<Vec<String>>,
    /// BIP 370's lock-time group: the expected lock time, or `None` where the
    /// BIP says none can be computed.
    pub locktime: Option<Option<u32>>,
}

fn load(json: &str, group: &str) -> Vec<Vector> {
    let doc: Value = serde_json::from_str(json).expect("the vector file parses");
    doc[group]
        .as_array()
        .unwrap_or_else(|| panic!("the vector file has a {group} array"))
        .iter()
        .map(|v| {
            let b64 = v["psbt"].as_str().expect("a base64 psbt").to_string();
            Vector {
                description: v["description"].as_str().unwrap_or_default().to_string(),
                psbt: base64::engine::general_purpose::STANDARD
                    .decode(&b64)
                    .expect("the vector's psbt is base64"),
                base64: b64,
                checks: v["checks"].as_array().map(|a| {
                    a.iter()
                        .filter_map(|c| c.as_str().map(String::from))
                        .collect()
                }),
                locktime: v
                    .as_object()
                    .filter(|o| o.contains_key("locktime"))
                    .map(|o| o["locktime"].as_u64().map(|n| n as u32)),
            }
        })
        .collect()
}

pub fn bip375_invalid() -> Vec<Vector> {
    load(BIP375, "invalid")
}

pub fn bip375_valid() -> Vec<Vector> {
    load(BIP375, "valid")
}

pub fn bip375_all() -> Vec<Vector> {
    let mut v = bip375_invalid();
    v.extend(bip375_valid());
    v
}

pub fn bip370_invalid() -> Vec<Vector> {
    load(BIP370, "invalid")
}

pub fn bip370_valid() -> Vec<Vector> {
    load(BIP370, "valid")
}

pub fn bip370_locktime() -> Vec<Vector> {
    load(BIP370, "locktime")
}

impl Vector {
    /// Whether the reference runner would apply a named check to this vector.
    pub fn runs(&self, check: &str) -> bool {
        match &self.checks {
            None => true,
            Some(list) => list.iter().any(|c| c == check),
        }
    }
}
