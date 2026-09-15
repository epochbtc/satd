//! Stratum V1: line-delimited JSON-RPC.
//!
//! This module is the wire format — parsing requests, shaping responses and
//! notifications. [`session`] is the per-connection state machine.

pub mod session;

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use serde_json::{Value, json};

use super::template::ActiveTemplate;

/// Longest request line accepted. A miner's messages are a few hundred
/// bytes; anything near this is not a miner.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// Bytes of extranonce the server assigns per connection (extranonce1).
pub const EXTRANONCE1_LEN: usize = 4;
/// Bytes of extranonce the miner rolls (extranonce2).
pub const EXTRANONCE2_LEN: usize = 4;

/// The version bits a miner may roll (BIP 310 / BIP 320).
pub const VERSION_ROLLING_MASK: u32 = 0x1fff_e000;

/// A parsed request.
#[derive(Debug)]
pub struct Request {
    pub id: Value,
    pub method: String,
    pub params: Vec<Value>,
}

/// Parse one request line. `None` when the line is not a JSON object with a
/// string `method`; a missing or non-array `params` reads as empty.
pub fn parse_request(line: &str) -> Option<Request> {
    let v: Value = serde_json::from_str(line).ok()?;
    let obj = v.as_object()?;
    let method = obj.get("method")?.as_str()?.to_string();
    let id = obj.get("id").cloned().unwrap_or(Value::Null);
    let params = match obj.get("params") {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    };
    Some(Request { id, method, params })
}

/// A Stratum V1 error: `[code, message, null]` on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StratumError {
    Other,
    UnknownMethod,
    JobNotFound,
    Duplicate,
    LowDifficulty,
    Unauthorized,
    NotSubscribed,
    InvalidParams,
    InvalidTime,
}

impl StratumError {
    pub fn code(self) -> i64 {
        match self {
            Self::Other | Self::UnknownMethod | Self::InvalidParams | Self::InvalidTime => 20,
            Self::JobNotFound => 21,
            Self::Duplicate => 22,
            Self::LowDifficulty => 23,
            Self::Unauthorized => 24,
            Self::NotSubscribed => 25,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Other => "Other/Unknown",
            Self::UnknownMethod => "Unknown method",
            Self::JobNotFound => "Job not found",
            Self::Duplicate => "Duplicate share",
            Self::LowDifficulty => "Low difficulty share",
            Self::Unauthorized => "Unauthorized worker",
            Self::NotSubscribed => "Not subscribed",
            Self::InvalidParams => "Invalid parameters",
            Self::InvalidTime => "Invalid ntime",
        }
    }
}

/// A successful response line.
pub fn response(id: &Value, result: Value) -> String {
    json!({ "id": id, "result": result, "error": null }).to_string()
}

/// An error response line, with an optional message overriding the default.
pub fn error_response(id: &Value, err: StratumError, detail: Option<&str>) -> String {
    json!({
        "id": id,
        "result": null,
        "error": [err.code(), detail.unwrap_or(err.message()), null],
    })
    .to_string()
}

/// A server-initiated notification line.
pub fn notification(method: &str, params: Value) -> String {
    json!({ "id": null, "method": method, "params": params }).to_string()
}

/// The previous block hash as Stratum V1 carries it: the header's byte
/// order, with each 4-byte word reversed.
///
/// Miners read the value as eight big-endian 32-bit words and store them
/// little-endian, which recovers the header bytes. Written out: the
/// display-order hash, reversed word by word — so a mainnet prevhash ends in
/// `00000000`.
pub fn stratum_prevhash(hash: &BlockHash) -> String {
    let mut bytes = hash.to_byte_array();
    for word in bytes.chunks_exact_mut(4) {
        word.reverse();
    }
    hex::encode(bytes)
}

/// `mining.notify` parameters for a job.
pub fn notify_params(job: &ActiveTemplate, clean_jobs: bool) -> Value {
    let work = &job.work;
    json!([
        format!("{:x}", job.job_id),
        stratum_prevhash(&work.prev_hash),
        hex::encode(&job.coinbase_prefix),
        hex::encode(&job.coinbase_suffix),
        work.merkle_branch.iter().map(hex::encode).collect::<Vec<_>>(),
        format!("{:08x}", work.version as u32),
        format!("{:08x}", work.bits.to_consensus()),
        format!("{:08x}", work.cur_time),
        clean_jobs,
    ])
}

/// Parse a hex-encoded big-endian `u32` as miners send `ntime`, `nonce` and
/// version bits. Accepts an optional `0x` and fewer than eight digits.
pub fn parse_hex_u32(v: &Value) -> Option<u32> {
    let s = v.as_str()?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() || s.len() > 8 {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

/// Parse a pool difficulty as miners send it: a JSON number or a numeric
/// string. Fractions round down; anything below one reads as one.
pub fn parse_difficulty(v: &Value) -> Option<u64> {
    let f = match v {
        Value::Number(n) => n.as_f64()?,
        Value::String(s) => s.parse::<f64>().ok()?,
        _ => return None,
    };
    if !f.is_finite() || f < 0.0 {
        return None;
    }
    Some(if f >= u64::MAX as f64 { u64::MAX } else { (f as u64).max(1) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::{Header, Version};
    use bitcoin::pow::CompactTarget;
    use std::str::FromStr;

    /// Mainnet block 1, rebuilt from the fields a miner receives. The swap is
    /// applied the way miners undo it: hex-decode, then reverse each word.
    #[test]
    fn notify_prevhash_word_swap_matches_known_vector() {
        let genesis = BlockHash::from_str(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .unwrap();
        let wire = stratum_prevhash(&genesis);
        assert_eq!(wire, "0a8ce26f72b3f1b646a2a6c14ff763ae65831e939c085ae10019d66800000000");

        let mut bytes: [u8; 32] = hex::decode(&wire).unwrap().try_into().unwrap();
        for word in bytes.chunks_exact_mut(4) {
            word.reverse();
        }
        let header = Header {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::from_byte_array(bytes),
            merkle_root: bitcoin::TxMerkleNode::from_str(
                "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
            )
            .unwrap(),
            time: 1_231_469_665,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 2_573_394_689,
        };
        assert_eq!(
            header.block_hash().to_string(),
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
        );
    }

    #[test]
    fn request_and_value_parsing() {
        let r = parse_request(r#"{"id":3,"method":"mining.submit","params":["w","1"]}"#).unwrap();
        assert_eq!(r.id, json!(3));
        assert_eq!(r.method, "mining.submit");
        assert_eq!(r.params.len(), 2);
        assert!(parse_request("[1,2]").is_none());
        assert!(parse_request(r#"{"id":1}"#).is_none());
        assert_eq!(parse_request(r#"{"method":"mining.ping"}"#).unwrap().params.len(), 0);

        assert_eq!(parse_hex_u32(&json!("1d00ffff")), Some(0x1d00ffff));
        assert_eq!(parse_hex_u32(&json!("0x0a")), Some(10));
        assert_eq!(parse_hex_u32(&json!("123456789")), None);
        assert_eq!(parse_hex_u32(&json!(5)), None);

        assert_eq!(parse_difficulty(&json!(512)), Some(512));
        assert_eq!(parse_difficulty(&json!(0.5)), Some(1));
        assert_eq!(parse_difficulty(&json!("1000")), Some(1000));
        assert_eq!(parse_difficulty(&json!(-1)), None);

        let err = error_response(&json!(9), StratumError::LowDifficulty, None);
        let v: Value = serde_json::from_str(&err).unwrap();
        assert_eq!(v["error"], json!([23, "Low difficulty share", null]));
    }
}
