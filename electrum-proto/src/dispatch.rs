//! JSON-RPC 2.0 Request / Response types and method-name dispatch.
//!
//! Wire framing (newline-delimited or otherwise) is the transport
//! layer's concern (PR-3). This module turns a parsed [`Request`] into
//! a [`Response`] by routing on `method` and invoking the appropriate
//! handler from [`crate::handlers`].

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::JsonRpcError;
use crate::extras::ElectrumExtras;
use crate::handlers;
use crate::state::ElectrumState;
use crate::status::compute_status_hash;
use crate::subscribe::{HeadersSource, Subscriptions};
use crate::types::ScripthashHex;

/// Inbound JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    /// Notifications (no `id`) are valid JSON-RPC; for Electrum we don't
    /// receive any in normal flow but accept them gracefully (the
    /// response is suppressed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl Request {
    /// Parse a single JSON-RPC request from a UTF-8 string. Wraps the
    /// underlying serde error as a JSON-RPC parse error so the
    /// transport can shape a consistent error response.
    pub fn parse(s: &str) -> Result<Self, JsonRpcError> {
        serde_json::from_str(s).map_err(|e| JsonRpcError::parse_error(format!("bad json: {e}")))
    }
}

/// Outbound JSON-RPC 2.0 response. Exactly one of `result` / `error`
/// is populated; the response always carries `jsonrpc: "2.0"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl Response {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, err: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(err),
        }
    }
}

/// Synthesize a server-pushed notification (no `id`). Used by
/// subscription paths in PR-4 to push `blockchain.scripthash.subscribe`
/// / `blockchain.headers.subscribe` updates to clients.
#[derive(Debug, Clone, Serialize)]
pub struct Notification {
    pub jsonrpc: &'static str,
    pub method: String,
    pub params: Value,
}

impl Notification {
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            method: method.into(),
            params,
        }
    }
}

/// Route a parsed [`Request`] to its handler and produce a
/// [`Response`]. Errors raised by handlers are converted to
/// [`Response::error`]; an unknown method returns
/// `method_not_found`.
///
/// Notifications (requests with no `id`) still get dispatched — the
/// transport drops the synthesized response — but we always return
/// one here so the caller has uniform success / failure visibility
/// for logging and metrics.
pub fn dispatch(state: &ElectrumState, req: Request) -> Response {
    let id = req.id.clone().unwrap_or(Value::Null);
    let params = req.params.unwrap_or(Value::Array(Vec::new()));
    let outcome: Result<Value, JsonRpcError> = match req.method.as_str() {
        // server.*
        "server.version" => handlers::server_methods::version(state, params),
        "server.ping" => handlers::server_methods::ping(),
        "server.banner" => handlers::server_methods::banner(state),
        "server.donation_address" => handlers::server_methods::donation_address(state),
        "server.features" => handlers::server_methods::features(state),
        "server.peers.subscribe" => handlers::server_methods::peers_subscribe(),

        // blockchain.headers.*
        "blockchain.headers.subscribe" => handlers::blockchain::headers_subscribe(state),
        "blockchain.headers.get" => handlers::blockchain::headers_get(state, params),

        // blockchain.block.*
        "blockchain.block.header" => handlers::blockchain::block_header(state, params),
        "blockchain.block.headers" => handlers::blockchain::block_headers(state, params),

        // blockchain.scripthash.*
        "blockchain.scripthash.get_history" => {
            handlers::blockchain::scripthash_get_history(state, params)
        }
        "blockchain.scripthash.get_balance" => {
            handlers::blockchain::scripthash_get_balance(state, params)
        }
        "blockchain.scripthash.listunspent" => {
            handlers::blockchain::scripthash_listunspent(state, params)
        }
        "blockchain.scripthash.get_mempool" => {
            handlers::blockchain::scripthash_get_mempool(state, params)
        }
        "blockchain.scripthash.get_first_use" => {
            handlers::blockchain::scripthash_get_first_use(state, params)
        }
        "blockchain.scripthash.subscribe" => {
            // Synchronous initial-status response only. The
            // subscription state machine + push-notifications side
            // lands in PR-4; PR-2's surface is the get-current-status
            // half (which clients also use for one-shot polling when
            // they don't keep the connection open).
            handlers::blockchain::scripthash_subscribe(state, params)
        }
        "blockchain.scripthash.unsubscribe" => {
            // Returns true unconditionally for unknown scripthashes
            // — matches electrs and works for both subscribed and
            // never-subscribed inputs. PR-4 wires the actual
            // per-connection cleanup.
            handlers::blockchain::scripthash_unsubscribe(state, params)
        }

        // blockchain.transaction.*
        "blockchain.transaction.get" => handlers::blockchain::transaction_get(state, params),
        "blockchain.transaction.get_merkle" => {
            handlers::blockchain::transaction_get_merkle(state, params)
        }
        "blockchain.transaction.broadcast" => {
            handlers::blockchain::transaction_broadcast(state, params)
        }
        "blockchain.transaction.id_from_pos" => {
            handlers::blockchain::transaction_id_from_pos(state, params)
        }

        // fees
        "blockchain.estimatefee" => handlers::blockchain::estimatefee(state, params),
        "blockchain.relayfee" => handlers::blockchain::relayfee(state),

        // mempool.*
        "mempool.get_fee_histogram" => handlers::mempool::get_fee_histogram(state),

        unknown => Err(JsonRpcError::method_not_found(unknown)),
    };

    match outcome {
        Ok(result) => Response::success(id, result),
        Err(err) => Response::error(id, err),
    }
}

/// Subscription-aware dispatch. Handles
/// `blockchain.scripthash.subscribe` / `unsubscribe` and
/// `blockchain.headers.subscribe` by registering / cancelling against
/// the per-connection [`Subscriptions`] AND computing the synchronous
/// initial response. All other methods fall through to
/// [`dispatch`].
///
/// `headers_source` is the `ChainState` (or test fake) the headers
/// subscription will read `ChainEvent`s from. It's plumbed in as a
/// trait object so the connection layer can swap the concrete source
/// without coupling this module to `ChainState`.
pub fn dispatch_with_subscriptions(
    state: &ElectrumState,
    subs: &mut Subscriptions,
    headers_source: &dyn HeadersSource,
    extras: Arc<dyn ElectrumExtras>,
    req: Request,
) -> Response {
    let id = req.id.clone().unwrap_or(Value::Null);
    let outcome: Result<Value, JsonRpcError> = match req.method.as_str() {
        "blockchain.scripthash.subscribe" => handle_scripthash_subscribe(state, subs, &req),
        "blockchain.scripthash.unsubscribe" => handle_scripthash_unsubscribe(subs, &req),
        "blockchain.headers.subscribe" => {
            handle_headers_subscribe(state, subs, headers_source, extras, &req)
        }
        _ => return dispatch(state, req),
    };
    match outcome {
        Ok(result) => Response::success(id, result),
        Err(err) => Response::error(id, err),
    }
}

fn handle_scripthash_subscribe(
    state: &ElectrumState,
    subs: &mut Subscriptions,
    req: &Request,
) -> Result<Value, JsonRpcError> {
    let params = req.params.clone().unwrap_or(Value::Array(Vec::new()));
    let arr = require_array_range(&params, 1, 1, "blockchain.scripthash.subscribe")?;
    let s = arr[0]
        .as_str()
        .ok_or_else(|| JsonRpcError::invalid_params("scripthash must be a string"))?;
    let bytes =
        hex::decode(s).map_err(|e| JsonRpcError::invalid_params(format!("bad scripthash: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsonRpcError::invalid_params(
            "scripthash must be 64 hex chars (32 bytes)",
        ));
    }
    let mut sh = [0u8; 32];
    sh.copy_from_slice(&bytes);

    // Register first so the connection captures any update that happens
    // between this point and the synchronous status read below. The
    // initial status read MAY be slightly stale relative to the next
    // notification — that's fine: clients dedup on status hash, and an
    // extra notification with an unchanged hash is suppressed by
    // `SubscriptionRegistry::maybe_notify`.
    subs.add_scripthash(sh, state.address_index.as_ref())?;

    let h = compute_status_hash(state.address_index.as_ref(), ScripthashHex(sh))
        .map_err(JsonRpcError::from_index)?;
    Ok(match crate::status::status_hash_to_json(h) {
        Some(s) => Value::String(s),
        None => Value::Null,
    })
}

fn handle_scripthash_unsubscribe(
    subs: &mut Subscriptions,
    req: &Request,
) -> Result<Value, JsonRpcError> {
    let params = req.params.clone().unwrap_or(Value::Array(Vec::new()));
    let arr = require_array_range(&params, 1, 1, "blockchain.scripthash.unsubscribe")?;
    let s = arr[0]
        .as_str()
        .ok_or_else(|| JsonRpcError::invalid_params("scripthash must be a string"))?;
    let bytes =
        hex::decode(s).map_err(|e| JsonRpcError::invalid_params(format!("bad scripthash: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsonRpcError::invalid_params(
            "scripthash must be 64 hex chars (32 bytes)",
        ));
    }
    let mut sh = [0u8; 32];
    sh.copy_from_slice(&bytes);
    let _ = subs.remove_scripthash(&sh);
    // Per Electrum spec, return true regardless of whether a
    // subscription existed.
    Ok(Value::Bool(true))
}

fn handle_headers_subscribe(
    state: &ElectrumState,
    subs: &mut Subscriptions,
    headers_source: &dyn HeadersSource,
    extras: Arc<dyn ElectrumExtras>,
    _req: &Request,
) -> Result<Value, JsonRpcError> {
    subs.add_headers(headers_source, extras.clone())?;
    let (height, header) = state.electrum_extras.tip();
    Ok(serde_json::json!({
        "height": height,
        "hex": hex::encode(bitcoin::consensus::encode::serialize(&header)),
    }))
}

// ── Param parsing helpers ──────────────────────────────────────────

/// Parse `params` as a positional array of length exactly `n`.
pub(crate) fn require_array(
    params: &Value,
    n: usize,
    method: &str,
) -> Result<Vec<Value>, JsonRpcError> {
    match params {
        Value::Array(a) if a.len() == n => Ok(a.clone()),
        Value::Array(a) => Err(JsonRpcError::invalid_params(format!(
            "{method} expects {n} positional argument(s), got {}",
            a.len()
        ))),
        _ => Err(JsonRpcError::invalid_params(format!(
            "{method} expects an array of params"
        ))),
    }
}

/// Parse `params` as a positional array of length `min..=max`.
pub(crate) fn require_array_range(
    params: &Value,
    min: usize,
    max: usize,
    method: &str,
) -> Result<Vec<Value>, JsonRpcError> {
    match params {
        Value::Array(a) if (min..=max).contains(&a.len()) => Ok(a.clone()),
        Value::Array(a) => Err(JsonRpcError::invalid_params(format!(
            "{method} expects {min}..={max} positional argument(s), got {}",
            a.len()
        ))),
        _ => Err(JsonRpcError::invalid_params(format!(
            "{method} expects an array of params"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_well_formed_request() {
        let s = r#"{"jsonrpc":"2.0","id":1,"method":"server.ping","params":[]}"#;
        let req = Request::parse(s).unwrap();
        assert_eq!(req.method, "server.ping");
        assert_eq!(req.id, Some(Value::from(1)));
    }

    #[test]
    fn parse_bad_json_yields_parse_error() {
        let err = Request::parse("not json").unwrap_err();
        assert_eq!(err.code, -32700);
    }

    #[test]
    fn response_success_serializes_with_result_only() {
        let resp = Response::success(Value::from(7), Value::from("ok"));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\":\"ok\""));
        assert!(!json.contains("\"error\""));
        assert!(json.contains("\"id\":7"));
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
    }

    #[test]
    fn response_error_serializes_with_error_only() {
        let resp = Response::error(Value::from(7), JsonRpcError::method_not_found("foo"));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"error\""));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn notification_has_no_id_field() {
        let n = Notification::new("blockchain.headers.subscribe", Value::Null);
        let json = serde_json::to_string(&n).unwrap();
        assert!(!json.contains("\"id\""));
        assert!(json.contains("\"method\":\"blockchain.headers.subscribe\""));
    }

    #[test]
    fn require_array_arity_check() {
        let p = serde_json::json!([1, 2, 3]);
        assert!(require_array(&p, 3, "x").is_ok());
        assert!(require_array(&p, 2, "x").is_err());
    }

    #[test]
    fn require_array_rejects_object_params() {
        let p = serde_json::json!({"k":1});
        assert!(require_array(&p, 0, "x").is_err());
    }
}
