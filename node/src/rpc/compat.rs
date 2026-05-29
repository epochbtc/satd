//! Bitcoin Core JSON-RPC compatibility shim.
//!
//! Bitcoin Core's JSON-RPC server speaks JSON-RPC 1.0/1.1 semantics: a
//! request object may carry `"jsonrpc":"1.0"`, `"jsonrpc":"1.1"`, or no
//! `jsonrpc` member at all. `jsonrpsee` — satd's RPC engine — strictly
//! requires `"jsonrpc":"2.0"` and rejects anything else during request
//! parsing with `-32600 Invalid request`, before any RPC-level
//! middleware can see it.
//!
//! Every Core-ecosystem client built on the canonical libraries sends
//! the 1.0 form. NBitcoin (and therefore NBXplorer and BTCPayServer)
//! sends `"jsonrpc":"1.0"`; `python-bitcoinrpc`, many shell scripts, and
//! older tooling omit the member entirely. Against an unpatched
//! jsonrpsee, *every* call from those clients fails — which is exactly
//! the failure the NBXplorer compatibility canary surfaced (the indexer
//! could open a P2P connection but every `getblockchaininfo` RPC came
//! back `Invalid request`, so it never synced).
//!
//! This HTTP-level tower layer runs *before* jsonrpsee parses the body.
//! It buffers the request body, and for each JSON-RPC request object
//! (single or batched) that carries a `"method"`, forces
//! `"jsonrpc":"2.0"` so jsonrpsee accepts it. Bodies that are not valid
//! JSON, or are empty, are forwarded untouched so jsonrpsee still emits
//! the correct `-32700` / parse errors. The normalization only ever
//! *adds or rewrites* the protocol-version tag; method, params, and id
//! are preserved byte-for-byte in meaning, so the Core contract is
//! unchanged. Responses are left in jsonrpsee's 2.0 shape, which the
//! Core client libraries parse (they read `result`/`error`/`id` and do
//! not validate the response `jsonrpc` member).
//!
//! Matching Core's leniency here is a Tier 1 compatibility obligation
//! (CLI/RPC wire shape) — see `STABILITY_POLICY.md`.

use http_body_util::{BodyExt, Limited};
use jsonrpsee::server::{HttpBody, HttpRequest, HttpResponse};

/// jsonrpsee's default `max_request_body_size` (10 MiB). The shim must
/// not buffer more than the engine would itself accept. The cap is
/// enforced *while* reading the body (via `http_body_util::Limited`,
/// plus a `Content-Length` pre-check), never after a full
/// `collect()` — otherwise this middleware would itself be a memory-DoS
/// vector, allocating the entire (authenticated or not) request body
/// before the limit could reject it. An over-limit request is answered
/// with `413 Payload Too Large`, the same outcome jsonrpsee gives for a
/// request exceeding its own `max_request_body_size`.
const MAX_NORMALIZE_BODY: usize = 10 * 1024 * 1024;

/// Rewrite a JSON-RPC request body so Core-style (`1.0` / `1.1` /
/// absent) `jsonrpc` members become `2.0`. Returns `None` when the body
/// is unchanged or cannot/should not be rewritten (not JSON, empty, no
/// request object needing a fix), so the caller forwards the original
/// bytes verbatim.
fn normalize_jsonrpc_version(body: &[u8]) -> Option<Vec<u8>> {
    // The body is already size-bounded by the caller (Content-Length
    // pre-check + `Limited` read), so this only guards the empty case;
    // the length check is kept as defense-in-depth.
    if body.is_empty() || body.len() > MAX_NORMALIZE_BODY {
        return None;
    }
    let mut value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let changed = match &mut value {
        serde_json::Value::Object(_) => fix_request_object(&mut value),
        serde_json::Value::Array(items) => {
            // Batch request: fix each element independently. `any` is not
            // short-circuiting here because we must visit every element.
            let mut any = false;
            for item in items.iter_mut() {
                any |= fix_request_object(item);
            }
            any
        }
        _ => false,
    };
    if !changed {
        return None;
    }
    serde_json::to_vec(&value).ok()
}

/// If `value` is a JSON-RPC *request* object (has a `"method"` member),
/// ensure its `"jsonrpc"` member is exactly `"2.0"`. Returns whether a
/// change was made. Non-objects and objects without `"method"` (e.g. a
/// response echoed back, or junk) are left untouched.
fn fix_request_object(value: &mut serde_json::Value) -> bool {
    let serde_json::Value::Object(map) = value else {
        return false;
    };
    if !map.contains_key("method") {
        return false;
    }
    let already_2_0 = map
        .get("jsonrpc")
        .and_then(|v| v.as_str())
        .map(|s| s == "2.0")
        .unwrap_or(false);
    if already_2_0 {
        return false;
    }
    map.insert(
        "jsonrpc".to_string(),
        serde_json::Value::String("2.0".to_string()),
    );
    true
}

/// Tower layer installing the JSON-RPC version-compatibility shim.
#[derive(Clone, Default)]
pub struct JsonRpcCompatLayer;

impl JsonRpcCompatLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> tower::Layer<S> for JsonRpcCompatLayer {
    type Service = JsonRpcCompatMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JsonRpcCompatMiddleware { inner }
    }
}

/// Tower service that normalizes the `jsonrpc` member of incoming
/// request bodies before forwarding to the inner jsonrpsee service.
#[derive(Clone)]
pub struct JsonRpcCompatMiddleware<S> {
    inner: S,
}

impl<S> tower::Service<HttpRequest<hyper::body::Incoming>> for JsonRpcCompatMiddleware<S>
where
    S: tower::Service<HttpRequest<HttpBody>, Response = HttpResponse<HttpBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // The inner service is cloned per-call (it is `Clone` and cheap);
        // readiness is driven on that clone inside the future, matching
        // the pattern jsonrpsee's own tower stack uses.
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: HttpRequest<hyper::body::Incoming>) -> Self::Future {
        // Clone the inner service into the future, matching jsonrpsee's
        // own tower pattern (the cloned service is the one polled to
        // completion; `self.inner` stays ready for the next call).
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();

            // Reject before reading a byte if the declared length already
            // exceeds the cap. Covers the common DoS shape (a client
            // advertising a huge `Content-Length`) without allocating.
            if let Some(len) = parts
                .headers
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<usize>().ok())
                && len > MAX_NORMALIZE_BODY
            {
                return Ok(payload_too_large());
            }

            // Bound the actual read: `Limited` returns an error once more
            // than `MAX_NORMALIZE_BODY` bytes arrive, so a chunked /
            // length-omitting body cannot force unbounded allocation
            // either. On the length-limit error answer 413; any other
            // (transport) error yields an empty body so the inner service
            // produces a normal parse/te error rather than this layer
            // panicking.
            let collected = match Limited::new(body, MAX_NORMALIZE_BODY).collect().await {
                Ok(buf) => buf.to_bytes(),
                Err(e) if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() => {
                    return Ok(payload_too_large());
                }
                Err(_) => bytes::Bytes::new(),
            };

            let new_body = match normalize_jsonrpc_version(&collected) {
                Some(rewritten) => HttpBody::from(rewritten),
                None => HttpBody::from(collected.to_vec()),
            };

            let new_req = HttpRequest::from_parts(parts, new_body);
            inner.call(new_req).await
        })
    }
}

/// `413 Payload Too Large` — the response for a request body exceeding
/// [`MAX_NORMALIZE_BODY`], matching jsonrpsee's own oversized-request
/// outcome.
fn payload_too_large() -> HttpResponse<HttpBody> {
    hyper::Response::builder()
        .status(hyper::StatusCode::PAYLOAD_TOO_LARGE)
        .body(HttpBody::from("Payload Too Large"))
        .expect("static 413 response is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &str) -> Option<serde_json::Value> {
        normalize_jsonrpc_version(s.as_bytes()).map(|b| serde_json::from_slice(&b).unwrap())
    }

    #[test]
    fn rewrites_jsonrpc_1_0() {
        let out = norm(r#"{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}"#)
            .expect("should rewrite");
        assert_eq!(out["jsonrpc"], "2.0");
        assert_eq!(out["method"], "getblockchaininfo");
        assert_eq!(out["id"], 1);
        assert!(out["params"].is_array());
    }

    #[test]
    fn adds_missing_jsonrpc() {
        let out = norm(r#"{"id":7,"method":"getblockcount","params":[]}"#).expect("should rewrite");
        assert_eq!(out["jsonrpc"], "2.0");
        assert_eq!(out["id"], 7);
    }

    #[test]
    fn rewrites_jsonrpc_1_1() {
        let out = norm(r#"{"jsonrpc":"1.1","id":"x","method":"ping"}"#).expect("should rewrite");
        assert_eq!(out["jsonrpc"], "2.0");
    }

    #[test]
    fn leaves_2_0_untouched() {
        // Already 2.0 → no rewrite needed → None (forward verbatim).
        assert!(norm(r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#).is_none());
    }

    #[test]
    fn batch_request_all_elements_fixed() {
        let out = norm(
            r#"[{"id":1,"method":"getblockcount"},{"jsonrpc":"1.0","id":2,"method":"getbestblockhash"}]"#,
        )
        .expect("should rewrite");
        assert_eq!(out[0]["jsonrpc"], "2.0");
        assert_eq!(out[1]["jsonrpc"], "2.0");
        assert_eq!(out[0]["method"], "getblockcount");
    }

    #[test]
    fn batch_already_2_0_untouched() {
        assert!(
            norm(r#"[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","id":2,"method":"b"}]"#)
                .is_none()
        );
    }

    #[test]
    fn non_request_object_untouched() {
        // No "method" member: not a request we should rewrite.
        assert!(norm(r#"{"jsonrpc":"1.0","id":1,"result":42}"#).is_none());
    }

    #[test]
    fn invalid_json_forwarded_verbatim() {
        // Not JSON → None → caller forwards original bytes → jsonrpsee
        // returns its own -32700 parse error.
        assert!(norm("this is not json").is_none());
        assert!(norm("").is_none());
    }

    #[test]
    fn preserves_string_id_and_params() {
        let out = norm(
            r#"{"jsonrpc":"1.0","id":"abc","method":"getblock","params":["deadbeef",2]}"#,
        )
        .expect("should rewrite");
        assert_eq!(out["id"], "abc");
        assert_eq!(out["params"][0], "deadbeef");
        assert_eq!(out["params"][1], 2);
    }
}
