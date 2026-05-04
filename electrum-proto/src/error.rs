//! JSON-RPC error model used by every method handler.
//!
//! [`JsonRpcError`] is the wire-shape Electrum clients expect:
//! `{ "code": <int>, "message": <string> }`. Codes follow the
//! JSON-RPC 2.0 spec for the well-known errors and the
//! `electrumx`/`electrs` convention for protocol-specific cases (e.g.
//! `1: invalid request`, `2: history too large`, `4: bad scripthash`).
//! Internal errors ride code `-32603` as the spec dictates.

use serde::{Deserialize, Serialize};

/// Wire-format error per JSON-RPC 2.0 §5.1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

impl JsonRpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn parse_error(message: impl Into<String>) -> Self {
        Self::new(-32700, message)
    }
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(-32600, message)
    }
    pub fn method_not_found(method: &str) -> Self {
        Self::new(-32601, format!("method not found: {method}"))
    }
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(-32602, message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(-32603, message)
    }

    /// Index disabled — surfaces an `--addressindex=0` runtime gate to
    /// the client as a recognisable error rather than an empty result.
    pub fn index_disabled() -> Self {
        Self::new(
            1,
            "address index is disabled — restart the node with --addressindex=1",
        )
    }

    /// History (or listunspent) result would exceed the per-request
    /// cap. Mirrors electrs's "history too large" sentinel; clients
    /// should retry with a narrower scripthash or fall back to
    /// pagination via blockchain.scripthash.history (not supported in
    /// v1 but still the actionable advice).
    pub fn history_too_large(limit: usize) -> Self {
        Self::new(2, format!("history too large (cap = {limit} entries)"))
    }

    /// Subscription cap reached for the connection or server.
    pub fn subscription_cap(limit: usize) -> Self {
        Self::new(3, format!("subscription cap reached ({limit})"))
    }

    /// Convert a `node_index::IndexError` into the appropriate wire
    /// error.
    pub fn from_index(err: node_index::IndexError) -> Self {
        match err {
            node_index::IndexError::Disabled => Self::index_disabled(),
            node_index::IndexError::Incomplete => {
                Self::internal("address index is incomplete — restart with --reindex-chainstate")
            }
            node_index::IndexError::Storage(s) => Self::internal(format!("storage: {s}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_code() {
        assert_eq!(JsonRpcError::parse_error("nope").code, -32700);
    }

    #[test]
    fn method_not_found_includes_name() {
        let e = JsonRpcError::method_not_found("foo.bar");
        assert!(e.message.contains("foo.bar"));
        assert_eq!(e.code, -32601);
    }

    #[test]
    fn from_index_disabled_maps_to_protocol_code() {
        let e = JsonRpcError::from_index(node_index::IndexError::Disabled);
        assert_eq!(e.code, 1);
    }

    #[test]
    fn from_index_storage_maps_to_internal() {
        let e = JsonRpcError::from_index(node_index::IndexError::Storage("disk full".into()));
        assert_eq!(e.code, -32603);
        assert!(e.message.contains("disk full"));
    }
}
