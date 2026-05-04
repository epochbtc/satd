//! JSON-RPC error model used by every method handler.
//!
//! [`JsonRpcError`] is the wire-shape Electrum clients expect:
//! `{ "code": <int>, "message": <string> }`.
//!
//! ## Wire-message convention (mirrors `romanz/electrs` v0.11.1)
//!
//! Standard JSON-RPC errors carry **fixed** wire messages — electrs's
//! `RpcError::Standard(_)` arm produces `"parse error"`, `"invalid
//! request"`, `"method not found"`, `"invalid params"` regardless of
//! the underlying detail. We mirror that so client-side message
//! comparisons interoperate. Dynamic detail (the bad value, the parse
//! reason) is logged via `tracing::warn!` for operator debugging but
//! never goes on the wire.
//!
//! Protocol-level errors that DO carry detail on the wire:
//! - [`bad_request`] (code `1`) — handler-returned validation /
//!   not-found errors. Mirrors electrs's `RpcError::BadRequest` —
//!   the message is whatever the handler stringified.
//! - [`history_too_large`] / [`subscription_cap`] — code `2` /
//!   server-side caps; messages include the limit.
//! - [`unavailable_index`] / [`internal`] — code `-32603`. Fixed
//!   wire string `"unavailable index"` for index-disabled,
//!   electrs-style; `internal` is `"internal error"` for unexpected
//!   server faults.

use serde::{Deserialize, Serialize};

/// Fixed wire messages — must match `romanz/electrs` v0.11.1
/// `src/electrum.rs::RpcError::to_value` exactly.
pub const PARSE_ERROR_MSG: &str = "parse error";
pub const INVALID_REQUEST_MSG: &str = "invalid request";
pub const METHOD_NOT_FOUND_MSG: &str = "method not found";
pub const INVALID_PARAMS_MSG: &str = "invalid params";
pub const UNAVAILABLE_INDEX_MSG: &str = "unavailable index";

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

    /// JSON-RPC parse error (`-32700`). Wire message is the fixed
    /// `"parse error"` string; `detail` is logged at warn level for
    /// operator debugging only.
    pub fn parse_error(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        if !detail.is_empty() {
            tracing::warn!(target = "electrum::rpc", detail = %detail, "parse error");
        }
        Self::new(-32700, PARSE_ERROR_MSG)
    }

    /// JSON-RPC invalid request (`-32600`). Fixed wire message; detail
    /// is logged.
    pub fn invalid_request(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        if !detail.is_empty() {
            tracing::warn!(target = "electrum::rpc", detail = %detail, "invalid request");
        }
        Self::new(-32600, INVALID_REQUEST_MSG)
    }

    /// JSON-RPC method not found (`-32601`). Fixed wire message; the
    /// method name is logged but not exposed (electrs does the same).
    pub fn method_not_found(method: &str) -> Self {
        tracing::warn!(target = "electrum::rpc", method, "method not found");
        Self::new(-32601, METHOD_NOT_FOUND_MSG)
    }

    /// JSON-RPC invalid params (`-32602`). Fixed wire message; detail
    /// is logged. Use this for argument-shape errors (wrong arity, bad
    /// type, hex parse failure on a positional arg). For semantic
    /// "value not found" / handler-validation errors prefer
    /// [`bad_request`] which carries detail on the wire.
    pub fn invalid_params(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        if !detail.is_empty() {
            tracing::warn!(target = "electrum::rpc", detail = %detail, "invalid params");
        }
        Self::new(-32602, INVALID_PARAMS_MSG)
    }

    /// Internal server error (`-32603`). Fixed wire message
    /// `"internal error"`; detail logged.
    pub fn internal(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        if !detail.is_empty() {
            tracing::warn!(target = "electrum::rpc", detail = %detail, "internal error");
        }
        Self::new(-32603, "internal error")
    }

    /// Index disabled — surfaces an `--addressindex=0` runtime gate to
    /// the client. Mirrors electrs's `UnavailableIndex` wire shape
    /// (code `-32603`, message `"unavailable index"`).
    pub fn unavailable_index() -> Self {
        Self::new(-32603, UNAVAILABLE_INDEX_MSG)
    }

    /// Handler-returned validation / not-found error (code `1`).
    /// Mirrors electrs's `RpcError::BadRequest(err)` — the message is
    /// whatever the handler stringified (kept on the wire so wallets
    /// can surface it to users).
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(1, message)
    }

    /// History (or listunspent) result would exceed the per-request
    /// cap. Code `2` (DaemonError-style — semantic limit, dynamic
    /// message).
    pub fn history_too_large(limit: usize) -> Self {
        Self::new(2, format!("history too large (cap = {limit} entries)"))
    }

    /// Subscription cap reached for the connection or server.
    pub fn subscription_cap(limit: usize) -> Self {
        Self::new(3, format!("subscription cap reached ({limit})"))
    }

    /// Convert a `node_index::IndexError` into the appropriate wire
    /// error. `Disabled` → `unavailable_index` (matches electrs);
    /// `Incomplete` / `Storage` → internal.
    pub fn from_index(err: node_index::IndexError) -> Self {
        match err {
            node_index::IndexError::Disabled => Self::unavailable_index(),
            node_index::IndexError::Incomplete => {
                Self::internal("address index is incomplete — restart with --reindex-chainstate")
            }
            node_index::IndexError::Storage(s) => Self::internal(format!("storage: {s}")),
        }
    }

    /// Backward-compat shim for the old `index_disabled` constructor.
    /// Equivalent to [`unavailable_index`](Self::unavailable_index).
    #[deprecated(note = "use `unavailable_index` to match electrs's wire message")]
    pub fn index_disabled() -> Self {
        Self::unavailable_index()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_uses_fixed_wire_message() {
        let e = JsonRpcError::parse_error("bad json: trailing comma at line 3");
        assert_eq!(e.code, -32700);
        assert_eq!(e.message, PARSE_ERROR_MSG);
    }

    #[test]
    fn invalid_params_drops_detail_to_match_electrs() {
        let e = JsonRpcError::invalid_params("scripthash must be 64 hex chars");
        assert_eq!(e.code, -32602);
        assert_eq!(e.message, INVALID_PARAMS_MSG);
    }

    #[test]
    fn method_not_found_omits_method_name_to_match_electrs() {
        // electrs returns the fixed string "method not found" — no
        // method name. We log the name but don't expose it on the wire.
        let e = JsonRpcError::method_not_found("foo.bar");
        assert_eq!(e.code, -32601);
        assert_eq!(e.message, METHOD_NOT_FOUND_MSG);
        assert!(!e.message.contains("foo.bar"));
    }

    #[test]
    fn bad_request_keeps_dynamic_detail_on_wire() {
        let e = JsonRpcError::bad_request("tx not found: deadbeef");
        assert_eq!(e.code, 1);
        assert_eq!(e.message, "tx not found: deadbeef");
    }

    #[test]
    fn from_index_disabled_maps_to_unavailable_index() {
        let e = JsonRpcError::from_index(node_index::IndexError::Disabled);
        assert_eq!(e.code, -32603);
        assert_eq!(e.message, UNAVAILABLE_INDEX_MSG);
    }

    #[test]
    fn from_index_storage_maps_to_internal() {
        let e = JsonRpcError::from_index(node_index::IndexError::Storage("disk full".into()));
        assert_eq!(e.code, -32603);
        // Internal carries the fixed wire message; detail is logged.
        assert_eq!(e.message, "internal error");
    }
}
