//! Structured RPC error responses — opt-in extension over Bitcoin Core's
//! `{code, message}` error shape.
//!
//! # Wire compatibility
//!
//! JSON-RPC 2.0 permits an arbitrary `data` field on errors. Bitcoin Core
//! itself uses it occasionally (e.g. `testmempoolaccept` returns detail).
//! That means adding a structured `data` object is within spec.
//!
//! **However**, strict-typed client deserializers can reject unknown `data`
//! payloads. To stay byte-identical to Core for `bitcoin-cli` / BTCPay /
//! Electrum personal servers / etc., the structured extension is **opt-in
//! per server** via `--rpc-extended-errors`. When disabled (the default),
//! `RpcError::into_error_object` emits exactly `{code, message}` — the same
//! output we produced before this module existed.
//!
//! Per-request HTTP-header override (`X-Satd-Extended-Errors: 1`) is a
//! planned follow-up. The server-wide default covers the common
//! deployment pattern (satd driven only by satd-aware tooling).
//!
//! # Category taxonomy
//!
//! Categories are stable strings suitable for dashboards and alert rules.
//! Once published in a release, a category name must not change its
//! meaning — only new names can be added. See category() docs below.

use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};

/// Server-wide extended-errors switch. Set once at server start.
static EXTENDED_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable structured error payloads server-wide. Call at server start.
pub fn set_extended_enabled(enabled: bool) {
    EXTENDED_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn extended_enabled() -> bool {
    EXTENDED_ENABLED.load(Ordering::Relaxed)
}

/// A structured RPC error. When rendered to a jsonrpsee `ErrorObjectOwned`:
/// - With extended-errors disabled (default): emits only `code` + `message`
///   (byte-identical to Bitcoin Core).
/// - With extended-errors enabled: also populates `data` with
///   `category`, `suggestion`, and `debug` when present.
#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    /// Stable dashboard-friendly taxonomy. Examples:
    /// - `mempool.policy.feerate`, `mempool.policy.size`, `mempool.policy.rbf`
    /// - `mempool.conflicts`, `mempool.missing_inputs`
    /// - `validation.consensus`, `validation.witness`, `validation.sighash`
    /// - `rpc.input.parse`, `rpc.input.missing`, `rpc.input.range`
    /// - `storage.not_found`, `storage.pruned`
    /// - `network.peer_not_found`, `network.disabled`
    /// - `node.shutting_down`, `node.initializing`
    pub category: &'static str,
    /// Operator-facing remediation hint. Should be concrete and actionable.
    pub suggestion: Option<String>,
    /// Arbitrary structured debug data (field positions, computed values, etc.).
    pub debug: Option<Value>,
}

impl RpcError {
    pub fn new(code: i32, category: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            category,
            suggestion: None,
            debug: None,
        }
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    pub fn with_debug(mut self, debug: Value) -> Self {
        self.debug = Some(debug);
        self
    }

    /// Convert to the jsonrpsee error type that handlers return.
    ///
    /// When extended errors are disabled (default), emits only the
    /// Core-compatible `{code, message}` — `data` is `None`. When enabled,
    /// `data` carries the category + suggestion + debug payload.
    pub fn into_error_object(self) -> ErrorObjectOwned {
        if extended_enabled() {
            let mut data = serde_json::Map::new();
            data.insert("category".into(), Value::String(self.category.into()));
            if let Some(s) = self.suggestion {
                data.insert("suggestion".into(), Value::String(s));
            }
            if let Some(d) = self.debug {
                data.insert("debug".into(), d);
            }
            ErrorObjectOwned::owned(self.code, self.message, Some(json!(data)))
        } else {
            ErrorObjectOwned::owned(self.code, self.message, None::<()>)
        }
    }
}

impl From<RpcError> for ErrorObjectOwned {
    fn from(e: RpcError) -> Self {
        e.into_error_object()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The global EXTENDED_ENABLED is shared process-wide; cargo test runs
    // cases in parallel by default. One combined test function flips the
    // flag sequentially, eliminating the race entirely.
    #[test]
    fn error_object_shape_matches_mode() {
        // Default (extended off): Core-compatible {code, message} only.
        set_extended_enabled(false);
        let obj = RpcError::new(-25, "mempool.policy.feerate", "fee too low")
            .with_suggestion("raise --minrelaytxfee")
            .with_debug(json!({"feerate": 0.7}))
            .into_error_object();
        assert_eq!(obj.code(), -25);
        assert_eq!(obj.message(), "fee too low");
        assert!(
            obj.data().is_none(),
            "default mode must emit no data: {:?}",
            obj.data()
        );

        // Extended on: data payload carries category/suggestion/debug.
        set_extended_enabled(true);
        let obj = RpcError::new(-25, "mempool.policy.feerate", "fee too low")
            .with_suggestion("raise --minrelaytxfee")
            .with_debug(json!({"feerate": 0.7}))
            .into_error_object();
        let data = obj.data().expect("data populated when extended");
        let v: Value = serde_json::from_str(data.get()).unwrap();
        assert_eq!(v["category"], "mempool.policy.feerate");
        assert_eq!(v["suggestion"], "raise --minrelaytxfee");
        assert_eq!(v["debug"]["feerate"], 0.7);

        // Extended on, no optional fields: category is required, others omitted.
        let obj = RpcError::new(-5, "storage.not_found", "block not found").into_error_object();
        let data = obj.data().expect("data populated when extended");
        let v: Value = serde_json::from_str(data.get()).unwrap();
        assert_eq!(v["category"], "storage.not_found");
        assert!(v.get("suggestion").is_none());
        assert!(v.get("debug").is_none());

        // Leave the flag off so other tests in the crate see defaults.
        set_extended_enabled(false);
    }
}
