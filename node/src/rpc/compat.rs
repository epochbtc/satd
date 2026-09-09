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
//! unchanged.
//!
//! Responses are normalized to Core's JSON-RPC 1.0 shape: the `jsonrpc`
//! member is stripped, success responses gain `"error":null`, and error
//! responses gain `"result":null` — matching what Core-derived clients
//! expect (they read `result`/`error`/`id` and check `error` for null).
//!
//! Non-POST requests to paths other than `/` return `404 Not Found`,
//! matching Core's libevent-based httpserver. Excessively long URIs
//! (> 8192 bytes, Core's `MAX_HEADERS_SIZE`) return `400 Bad Request`.
//!
//! Matching Core's leniency here is a Tier 1 compatibility obligation
//! (CLI/RPC wire shape) — see `STABILITY_POLICY.md`.

use http_body_util::{BodyExt, Limited};
use jsonrpsee::server::{HttpBody, HttpRequest, HttpResponse};

/// Maximum request body size the compat shim will buffer for JSON-RPC
/// version normalization: the same
/// [`RPC_MAX_BODY_SIZE`](crate::rpc::RPC_MAX_BODY_SIZE) the engine is
/// configured with, so the shim never rejects a request the engine would
/// accept and never buffers one it would not.
///
/// The cap is enforced *while* reading the body (via
/// `http_body_util::Limited`, plus a `Content-Length` pre-check), never
/// after a full `collect()` — otherwise this middleware would itself be a
/// memory-DoS vector, allocating the entire (authenticated or not) request
/// body before the limit could reject it. An over-limit request is
/// answered with `413 Payload Too Large`, the same outcome jsonrpsee gives
/// for a request exceeding its own `max_request_body_size`.
const MAX_NORMALIZE_BODY: usize = crate::rpc::RPC_MAX_BODY_SIZE;

/// Bitcoin Core's libevent `MAX_HEADERS_SIZE` — URIs longer than this
/// produce `400 Bad Request`.
const MAX_URI_LENGTH: usize = 8192;

/// Rewrite a JSON-RPC request body so Core-style (`1.0` / `1.1` /
/// absent) `jsonrpc` members become `2.0`. Returns `None` when the body
/// is unchanged or cannot/should not be rewritten (not JSON, empty, no
/// request object needing a fix), so the caller forwards the original
/// bytes verbatim.
/// What the request rewrite decided, beyond the bytes: which synthetic ids
/// belong to notifications, and whether *every* request in the body was one.
#[derive(Default)]
pub(crate) struct RequestPlan {
    pub(crate) body: Option<Vec<u8>>,
    pub(crate) notification_ids: Vec<String>,
    pub(crate) all_notifications: bool,
}

#[cfg(test)]
fn normalize_jsonrpc_version(body: &[u8]) -> Option<Vec<u8>> {
    plan_request(body).body
}

/// [`normalize_jsonrpc_version`] plus the notification bookkeeping.
pub(crate) fn plan_request(body: &[u8]) -> RequestPlan {
    // The body is already size-bounded by the caller (Content-Length
    // pre-check + `Limited` read), so this only guards the empty case;
    // the length check is kept as defense-in-depth.
    if body.is_empty() || body.len() > MAX_NORMALIZE_BODY {
        return RequestPlan::default();
    }
    // Each request object is read as a list of *raw* member text, not as a
    // fully-parsed `Value`. That is the difference between rewriting the
    // protocol tag and rewriting the request: a `Value` round-trip
    // renormalises every member, and in particular `serde_json::Map` silently
    // collapses duplicate keys -- so `{"a":1,"a":2}` inside `params` reached
    // the handler as `{"a":2}`. Bitcoin Core keeps duplicates
    // (`UniValue::pushKVEnd`) and rejects them by name in
    // `createrawtransaction`; satd's check for exactly that sat downstream of
    // this layer and so could never fire.
    //
    // Keeping every member as `&RawValue` re-emits it byte-for-byte, which is
    // what this module's contract already claimed for `params`.
    if let Ok(mut members) = serde_json::from_slice::<Members>(body) {
        let fix = plan_request_fix(&members, 0);
        if !fix.changed() {
            return RequestPlan::default();
        }
        let mut out = Vec::with_capacity(body.len() + 32);
        write_request_object(&mut out, &mut members, fix);
        return RequestPlan {
            body: Some(out),
            notification_ids: if fix.notification {
                vec![format!("{NOTIFICATION_ID_PREFIX}0")]
            } else {
                Vec::new()
            },
            all_notifications: fix.notification,
        };
    }
    // A batch is read element by element, not as `Vec<Members>`: one element
    // that is not an object (`[{"method":"m"}, 5]`) fails the whole-batch
    // deserialize, and bailing out then left the *other*, well-formed 1.0
    // requests in that batch without their `jsonrpc`/`id` fixup -- so a
    // Core-shaped client's batch stopped working because of a neighbour.
    // Elements that are not request objects are copied through verbatim; it
    // is jsonrpsee's job to reject them, not this layer's.
    if let Ok(elements) = serde_json::from_slice::<Vec<&serde_json::value::RawValue>>(body) {
        let mut parsed: Vec<Option<(Members, RequestFix)>> = Vec::with_capacity(elements.len());
        for (i, raw) in elements.iter().enumerate() {
            match serde_json::from_str::<Members>(raw.get()) {
                Ok(members) => {
                    let fix = plan_request_fix(&members, i as u64);
                    parsed.push(Some((members, fix)));
                }
                Err(_) => parsed.push(None),
            }
        }
        let notification_ids: Vec<String> = parsed
            .iter()
            .filter_map(|p| p.as_ref())
            .filter(|(_, fix)| fix.notification)
            .map(|(_, fix)| format!("{NOTIFICATION_ID_PREFIX}{}", fix.synthetic_id))
            .collect();
        // Core answers a batch of nothing but notifications with 204 and no
        // body, exactly as it answers a single one.
        let all_notifications = !elements.is_empty()
            && parsed
                .iter()
                .all(|p| p.as_ref().is_some_and(|(_, fix)| fix.notification));
        if !parsed
            .iter()
            .any(|p| p.as_ref().is_some_and(|(_, fix)| fix.changed()))
        {
            return RequestPlan::default();
        }
        let mut out = Vec::with_capacity(body.len() + 32 * elements.len().max(1));
        out.push(b'[');
        for (i, (raw, slot)) in elements.iter().zip(parsed.iter_mut()).enumerate() {
            if i > 0 {
                out.push(b',');
            }
            match slot {
                Some((members, fix)) => write_request_object(&mut out, members, *fix),
                None => out.extend_from_slice(raw.get().as_bytes()),
            }
        }
        out.push(b']');
        return RequestPlan {
            body: Some(out),
            notification_ids,
            all_notifications,
        };
    }
    RequestPlan::default()
}

/// One request object's members, in source order, each still raw text.
///
/// A hand-written `Deserialize` rather than a `Map`: `serde_json::Map` only
/// holds `Value`, and collapsing to `Value` is precisely what this must not
/// do. Visiting the map directly keeps every member's bytes and every
/// repetition of a key.
struct Members<'a>(Vec<(String, &'a serde_json::value::RawValue)>);

impl<'a> Members<'a> {
    fn iter(&self) -> std::slice::Iter<'_, (String, &'a serde_json::value::RawValue)> {
        self.0.iter()
    }
}

impl<'de: 'a, 'a> serde::Deserialize<'de> for Members<'a> {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Members<'de>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a JSON-RPC request object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    let raw: &serde_json::value::RawValue = map.next_value()?;
                    out.push((key, raw));
                }
                Ok(Members(out))
            }
        }
        de.deserialize_map(V)
    }
}

/// What [`normalize_jsonrpc_version`] has to change about one request object.
#[derive(Clone, Copy)]
struct RequestFix {
    set_jsonrpc: bool,
    add_id: bool,
    /// A JSON-RPC 2.0 request with no `id`: the method runs and no response
    /// is sent.
    notification: bool,
    /// Distinguishes one notification's synthetic id from another's within a
    /// batch. Meaningless unless `notification`.
    synthetic_id: u64,
}

impl RequestFix {
    const NONE: Self = Self {
        set_jsonrpc: false,
        add_id: false,
        notification: false,
        synthetic_id: 0,
    };

    fn changed(&self) -> bool {
        self.set_jsonrpc || self.add_id
    }
}

/// The prefix of the synthetic `id` given to a 2.0 notification.
///
/// A notification carries no `id`, but jsonrpsee will not run a request
/// without one, so this layer supplies one — and then has to recognise the
/// reply in order to drop it. A `null` id is not enough: two notifications in
/// one batch would both come back as `null` and be indistinguishable. The NUL
/// byte cannot appear in a JSON string a client wrote without escaping, and
/// nothing in satd emits one, so a value starting with it is unambiguously
/// this layer's own.
const NOTIFICATION_ID_PREFIX: &str = "\u{0}satd-notification-";

/// The prefix of the synthetic `id` given to a **1.0** request that carried
/// no `id` member.
///
/// Core parses `id` as `std::optional`: absent means absent, and
/// `JSONRPCReplyObj` pushes `id` only when it has a value
/// (`rpc/request.cpp`, `rpc/protocol.cpp`). So a 1.0 request without an id is
/// answered with **no `id` member at all**, while one that sent `"id": null`
/// is answered `"id": null`. Those two look identical in the reply, so the
/// difference has to be carried from the request — hence a sentinel here too,
/// stripped from the response rather than the whole reply being dropped.
const ABSENT_ID_PREFIX: &str = "\u{0}satd-absent-id-";

/// If `members` is a JSON-RPC *request* object (it has a `"method"` member),
/// decide whether its `"jsonrpc"` member needs forcing to `2.0` and whether an
/// `"id"` must be added. Without an `id`, jsonrpsee treats the request as a
/// 2.0 notification and returns no response; Core always responds, `id` or not.
fn plan_request_fix(members: &Members<'_>, synthetic_id: u64) -> RequestFix {
    let has = |name: &str| members.iter().any(|(k, _)| k == name);
    if !has("method") {
        return RequestFix::NONE;
    }
    // The *last* `jsonrpc` member decides, because that is the one jsonrpsee
    // will see: it parses into a `Map`, where a repeated key keeps the last
    // value. Reading the first meant `{"jsonrpc":"2.0","jsonrpc":"1.0",...}`
    // was judged already-2.0 and forwarded unchanged, and jsonrpsee then
    // rejected the request this layer exists to make it accept. A rewrite
    // rewrites every occurrence, so the duplicates collapse consistently.
    let already_2_0 = members
        .iter()
        .rfind(|(k, _)| k == "jsonrpc")
        .is_some_and(|(_, v)| v.get().trim() == "\"2.0\"");
    // A JSON-RPC 2.0 request with **no** `id` member is a notification: the
    // method runs and no response is sent (HTTP 204, and no entry in a batch).
    // An explicit `"id": null` is not a notification — it is an id, and Core
    // echoes it.
    //
    // This layer used to inject `"id": null` into every request that lacked
    // one, so jsonrpsee never saw a notification and satd always answered.
    let notification = already_2_0 && !has("id");
    RequestFix {
        set_jsonrpc: !already_2_0,
        add_id: !has("id"),
        notification,
        synthetic_id,
    }
}

/// Re-emit one request object, applying `fix`. Every member other than
/// `jsonrpc` is copied out verbatim, so `params` reaches jsonrpsee exactly as
/// the client wrote it -- duplicate keys, number spellings and all.
fn write_request_object(out: &mut Vec<u8>, members: &mut Members<'_>, fix: RequestFix) {
    out.push(b'{');
    let mut wrote_any = false;
    let mut wrote_jsonrpc = false;
    for (key, raw) in members.iter() {
        if wrote_any {
            out.push(b',');
        }
        wrote_any = true;
        // `to_vec` on a `String` emits a correctly-escaped JSON string.
        out.extend_from_slice(&serde_json::to_vec(key).expect("a String is serialisable"));
        out.push(b':');
        if key == "jsonrpc" && fix.set_jsonrpc {
            out.extend_from_slice(b"\"2.0\"");
            wrote_jsonrpc = true;
        } else {
            out.extend_from_slice(raw.get().as_bytes());
        }
    }
    if fix.set_jsonrpc && !wrote_jsonrpc {
        if wrote_any {
            out.push(b',');
        }
        wrote_any = true;
        out.extend_from_slice(b"\"jsonrpc\":\"2.0\"");
    }
    if fix.add_id {
        if wrote_any {
            out.push(b',');
        }
        let prefix = if fix.notification {
            NOTIFICATION_ID_PREFIX
        } else {
            ABSENT_ID_PREFIX
        };
        let id = format!("{prefix}{}", fix.synthetic_id);
        out.extend_from_slice(b"\"id\":");
        out.extend_from_slice(&serde_json::to_vec(&id).expect("a String is serialisable"));
    }
    out.push(b'}');
}

/// Rewrite a JSON response's `Content-Type` to Core's exact spelling.
///
/// Bitcoin Core answers every RPC with literally `application/json`. jsonrpsee
/// answers with `application/json; charset=utf-8`. The parameter is redundant
/// -- RFC 8259 fixes JSON's encoding as UTF-8 -- but Core-derived clients
/// compare the header for equality rather than parsing the media type, so the
/// suffix reads to them as a non-JSON response. Core's own functional-test
/// client is one of these: it rejects every satd reply with
/// `-342 non-JSON HTTP response`, having never looked at the perfectly valid
/// JSON body.
///
/// Only a body that already claims to be JSON is rewritten, so an error
/// response from another layer keeps whatever type it set.
fn normalize_response_content_type(headers: &mut hyper::HeaderMap) {
    let is_json = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .map(str::trim)
                .is_some_and(|media| media.eq_ignore_ascii_case("application/json"))
        });
    if is_json {
        headers.insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
    }
}

/// Whether the *request* explicitly spoke JSON-RPC 2.0.
///
/// The response normalization below rewrites replies into Core's 1.0 shape.
/// That is right for Core-derived clients, which is what the compatibility
/// surface exists for — but it must not be applied to a client that asked for
/// 2.0. A 2.0 response is defined by its `jsonrpc` member, and 2.0 forbids
/// carrying `result` and `error` together; handing a 2.0 client the 1.0 shape
/// breaks strict parsers, jsonrpsee's own `http-client` (which this workspace
/// ships and tests against) among them.
///
/// A batch counts as 2.0 only when *every* request object in it declares 2.0;
/// a mixed batch is treated as Core-shaped, which is the conservative choice
/// because Core is the only thing that sends one.
fn request_declared_2_0(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    fn is_2_0(v: &serde_json::Value) -> Option<bool> {
        let obj = v.as_object()?;
        // Only request objects carry a verdict; anything else abstains.
        obj.get("method")?;
        Some(obj.get("jsonrpc").and_then(|j| j.as_str()) == Some("2.0"))
    }
    match &value {
        serde_json::Value::Array(items) => {
            let mut saw_request = false;
            for item in items {
                match is_2_0(item) {
                    Some(true) => saw_request = true,
                    Some(false) => return false,
                    None => {}
                }
            }
            saw_request
        }
        other => is_2_0(other).unwrap_or(false),
    }
}

/// Normalize a JSON-RPC response body for Core compatibility.
///
/// jsonrpsee (JSON-RPC 2.0) omits `"error"` from success responses and
/// always includes `"jsonrpc":"2.0"`. Core (JSON-RPC 1.0) always includes
/// `"error":null` on success. Clients like Core's functional test suite
/// assert `"error":null` is present in the byte stream.
///
/// Key ordering matters: Core emits `result`, `error`, then `id`
/// (UniValue preserves insertion order). serde_json's `Map` is backed
/// by `BTreeMap` (alphabetical), so we reconstruct the output with
/// Core's key order by writing directly rather than re-serializing the
/// mutated map.
fn normalize_response_body_bytes(body: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        return body.to_vec();
    }

    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.to_vec();
    };

    match &value {
        serde_json::Value::Object(_) => {
            if let Some(out) = rewrite_response_object(&value) {
                return out;
            }
            body.to_vec()
        }
        serde_json::Value::Array(items) => {
            // Batch response: rewrite each element.
            let mut any = false;
            let mut parts: Vec<Vec<u8>> = Vec::with_capacity(items.len());
            for item in items {
                if let Some(rewritten) = rewrite_response_object(item) {
                    parts.push(rewritten.strip_suffix(b"\n").unwrap_or(&rewritten).to_vec());
                    any = true;
                } else if let Ok(bytes) = serde_json::to_vec(item) {
                    parts.push(bytes);
                }
            }
            if any {
                let mut out = b"[".to_vec();
                for (i, p) in parts.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(p);
                }
                out.push(b']');
                out.push(b'\n');
                return out;
            }
            body.to_vec()
        }
        _ => body.to_vec(),
    }
}

/// Rewrite a single JSON-RPC 2.0 response object to Core's 1.0 format.
///
/// Returns `Some(bytes)` when the object was rewritten, `None` when it
/// should be forwarded verbatim. The output uses Core's field order:
/// `result`, `error`, then `id` (only when non-null).
fn rewrite_response_object(value: &serde_json::Value) -> Option<Vec<u8>> {
    let serde_json::Value::Object(map) = value else {
        return None;
    };
    if !map.contains_key("result") && !map.contains_key("error") {
        return None;
    }

    // Extract the three fields we care about.
    let result = map.get("result").cloned();
    let error = map.get("error").cloned();
    let id = map.get("id").cloned();

    // Determine the Core-compatible values.
    let result_val = result.unwrap_or(serde_json::Value::Null);
    let error_val = error.unwrap_or(serde_json::Value::Null);

    // Build output with Core's key order: result, error, id.
    // `id` is omitted when null (request had no id — we added a
    // synthetic null to satisfy jsonrpsee's 2.0 requirement).
    let result_json = serde_json::to_string(&result_val).ok()?;
    let error_json = serde_json::to_string(&error_val).ok()?;

    // Core echoes the `id` it was given, `null` included, and omits the
    // member entirely when the request carried none (`JSONRPCReplyObj` pushes
    // `id` only `if (id.has_value())`). satd used to omit every null id,
    // which lost the difference between `"id": null` and no id — different
    // requests with different replies. The synthetic id this layer added for
    // jsonrpsee's benefit is what distinguishes them, and it is dropped here.
    let synthetic = id
        .as_ref()
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.starts_with(ABSENT_ID_PREFIX) || s.starts_with(NOTIFICATION_ID_PREFIX));
    let mut out = format!("{{\"result\":{result_json},\"error\":{error_json}");
    if !synthetic {
        let id_json = serde_json::to_string(&id.unwrap_or(serde_json::Value::Null)).ok()?;
        out.push_str(&format!(",\"id\":{id_json}"));
    }
    out.push('}');
    out.push('\n');
    Some(out.into_bytes())
}

/// Tower layer for the Core-compatible parts of the HTTP surface that can be
/// decided from the request *head* alone.
///
/// This is deliberately a separate layer from [`JsonRpcCompatLayer`]. Core's
/// libevent httpserver answers a bad path or an over-long URI without
/// authenticating, and `interface_http.py` checks that — so these checks have
/// to sit outside the auth layer. Reading the request *body* must not:
/// buffering and JSON-parsing megabytes for an unauthenticated caller is a
/// memory-amplification surface on a port that is frequently exposed, and it
/// is why the auth layer used to be outermost. Splitting the two gets both
/// properties: Core's unauthenticated 400/404, and no pre-auth body handling.
#[derive(Clone, Default)]
pub struct CoreHttpPreludeLayer;

impl CoreHttpPreludeLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> tower::Layer<S> for CoreHttpPreludeLayer {
    type Service = CoreHttpPrelude<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CoreHttpPrelude { inner }
    }
}

/// Tower service applying Core's head-only HTTP behaviour.
#[derive(Clone)]
pub struct CoreHttpPrelude<S> {
    inner: S,
}

impl<S, B> tower::Service<HttpRequest<B>> for CoreHttpPrelude<S>
where
    S: tower::Service<HttpRequest<B>, Response = HttpResponse<HttpBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
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
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: HttpRequest<B>) -> Self::Future {
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let (mut parts, body) = req.into_parts();

            // Bitcoin Core's libevent httpserver rejects excessively long
            // URIs (> MAX_HEADERS_SIZE = 8192) with 400 Bad Request, and any
            // non-root path with 404 Not Found (there is no REST surface on
            // the RPC port). jsonrpsee returns 405 Method Not Allowed for
            // non-POST requests, which breaks `interface_http.py`.
            let uri_len =
                parts.uri.path().len() + parts.uri.query().map_or(0, |q| q.len() + 1);
            if uri_len > MAX_URI_LENGTH {
                return Ok(bad_request());
            }
            if parts.uri.path() != "/" {
                return Ok(not_found());
            }

            // Core does not require a Content-Type header on RPC requests;
            // jsonrpsee does (`application/json`). Add a default when the
            // client omitted it, matching Core's leniency.
            if !parts.headers.contains_key(hyper::header::CONTENT_TYPE) {
                parts.headers.insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
            }

            inner.call(HttpRequest::from_parts(parts, body)).await
        })
    }
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
            let (mut parts, body) = req.into_parts();

            // Core does not require a Content-Type header on RPC requests;
            // jsonrpsee does (`application/json`). Add a default when the
            // client omitted it, matching Core's leniency.
            if !parts.headers.contains_key(hyper::header::CONTENT_TYPE) {
                parts.headers.insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
            }

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

            // Decide the response shape from what the client actually spoke,
            // before the request is rewritten to 2.0 for jsonrpsee's benefit.
            let client_spoke_2_0 = request_declared_2_0(&collected);

            let plan = plan_request(&collected);
            let new_body = match &plan.body {
                Some(rewritten) => HttpBody::from(rewritten.clone()),
                None => HttpBody::from(collected.to_vec()),
            };

            let new_req = HttpRequest::from_parts(parts, new_body);
            let resp = inner.call(new_req).await?;
            let (mut head, body) = resp.into_parts();
            normalize_response_content_type(&mut head.headers);

            let resp_bytes = match BodyExt::collect(body).await {
                Ok(b) => b.to_bytes(),
                Err(_) => bytes::Bytes::new(),
            };

            // Every request in the body was a 2.0 notification: the methods
            // ran, and Core answers with `204 No Content` and no body at all.
            if plan.all_notifications {
                return Ok(no_content());
            }

            // A batch with some notifications in it: their replies exist only
            // because jsonrpsee needed an id to run them, so drop them.
            let resp_bytes = if plan.notification_ids.is_empty() {
                resp_bytes
            } else {
                bytes::Bytes::from(drop_notification_replies(
                    &resp_bytes,
                    &plan.notification_ids,
                ))
            };

            // Core's HTTP status follows the JSON-RPC error code
            // (`httprpc.cpp`): a parse error is 500, an invalid request 400,
            // and an unknown method 404. jsonrpsee answers 200 for all three,
            // so a client that switches on the status — Core's own
            // `interface_rpc.py` does — could not tell them apart.
            //
            // But only for a **legacy** (1.0/1.1) request. Core catches
            // errors for a 2.0 request and returns them inside an HTTP 200
            // (`catch_errors{jreq.m_json_version == JSONRPCVersion::V2}`);
            // `JSONErrorReply`, which does the mapping, opens with
            // `Assume(jreq.m_json_version != JSONRPCVersion::V2)`. Mapping it
            // for 2.0 as well is worse than cosmetic: Core's own authproxy
            // raises `-342 non-200 HTTP status code` for a 2.0 reply with a
            // non-200 status *before* it looks at the error object, so the
            // real error code never reaches the caller.
            if let Some(status) = core_http_status(&resp_bytes, client_spoke_2_0) {
                head.status = status;
            }

            // Core-shaped request in, Core-shaped response out. A client that
            // asked for 2.0 gets jsonrpsee's 2.0 reply untouched.
            let out_body = if client_spoke_2_0 {
                resp_bytes.to_vec()
            } else if resp_bytes.len() > MAX_NORMALIZE_BODY {
                // Normalisation DOM-parses the body to touch three top-level
                // keys, which costs several times its size again. A reply
                // over the cap — a verbosity-2 `getblock` of a full block is
                // the realistic one — is forwarded in jsonrpsee's shape
                // instead. Truncating or refusing it would be worse: the
                // answer is correct JSON, only its envelope is 2.0.
                tracing::debug!(
                    target: "rpc::compat",
                    bytes = resp_bytes.len(),
                    "response too large to normalise to JSON-RPC 1.0; forwarding as 2.0"
                );
                resp_bytes.to_vec()
            } else {
                normalize_response_body_bytes(&resp_bytes)
            };
            Ok(HttpResponse::from_parts(head, HttpBody::from(out_body)))
        })
    }
}

/// `204 No Content` — Core's answer to a request body containing nothing but
/// JSON-RPC 2.0 notifications.
fn no_content() -> HttpResponse<HttpBody> {
    hyper::Response::builder()
        .status(hyper::StatusCode::NO_CONTENT)
        .body(HttpBody::from(""))
        .expect("static 204 response is always valid")
}

/// Remove the replies jsonrpsee produced for notifications, identified by the
/// synthetic ids this layer gave them.
///
/// Only a batch reaches this: a lone notification is answered 204 before it.
fn drop_notification_replies(body: &[u8], notification_ids: &[String]) -> Vec<u8> {
    let Ok(serde_json::Value::Array(items)) =
        serde_json::from_slice::<serde_json::Value>(body)
    else {
        return body.to_vec();
    };
    let kept: Vec<&serde_json::Value> = items
        .iter()
        .filter(|item| {
            item.get("id")
                .and_then(|v| v.as_str())
                .is_none_or(|id| !notification_ids.iter().any(|n| n == id))
        })
        .collect();
    serde_json::to_vec(&kept).unwrap_or_else(|_| body.to_vec())
}

/// Core's HTTP status for a JSON-RPC error code (`httprpc.cpp`
/// `HTTPReq_JSONRPC`). `None` leaves the status alone.
///
/// `client_spoke_2_0` is not decoration. Core maps the status only for a
/// **legacy** request: `JSONRPCExec` is called with
/// `catch_errors{jreq.m_json_version == JSONRPCVersion::V2}`, so a 2.0 error
/// is caught and returned inside an HTTP 200, and `JSONErrorReply` — the only
/// place the mapping lives — opens with
/// `Assume(jreq.m_json_version != JSONRPCVersion::V2)`.
///
/// Mapping it for 2.0 too is not merely cosmetic. Core's own `authproxy`
/// raises `-342 non-200 HTTP status code` for a 2.0 reply whose status is not
/// 200, *before* it reads the error object — so the real code never reaches
/// the caller and `assert_raises_rpc_error(-32601, ...)` cannot match.
fn core_http_status(body: &[u8], client_spoke_2_0: bool) -> Option<hyper::StatusCode> {
    if client_spoke_2_0 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    // A batch keeps 200 whatever its members say; Core only maps the status
    // for a single request.
    let code = value.get("error")?.get("code")?.as_i64()?;
    match code {
        -32700 => Some(hyper::StatusCode::INTERNAL_SERVER_ERROR),
        -32600 => Some(hyper::StatusCode::BAD_REQUEST),
        -32601 => Some(hyper::StatusCode::NOT_FOUND),
        _ => None,
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

/// `404 Not Found` — for non-root paths on the RPC port, matching
/// Bitcoin Core's libevent-based httpserver.
fn not_found() -> HttpResponse<HttpBody> {
    hyper::Response::builder()
        .status(hyper::StatusCode::NOT_FOUND)
        .body(HttpBody::from("Not Found"))
        .expect("static 404 response is always valid")
}

/// `400 Bad Request` — for excessively long URIs.
fn bad_request() -> HttpResponse<HttpBody> {
    hyper::Response::builder()
        .status(hyper::StatusCode::BAD_REQUEST)
        .body(HttpBody::from("Bad Request"))
        .expect("static 400 response is always valid")
}

#[cfg(test)]
mod tests {

    /// Bitcoin Core sends exactly `application/json`, and Core-derived clients
    /// compare the header for equality. jsonrpsee's
    /// `application/json; charset=utf-8` made every reply look non-JSON to
    /// them -- Core's own test client rejects it with -342 without reading the
    /// body. Deleting the rewrite in `normalize_response_content_type` fails
    /// this test.
    #[test]
    fn json_content_type_matches_core_exactly() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json; charset=utf-8"),
        );
        super::normalize_response_content_type(&mut headers);
        assert_eq!(headers[hyper::header::CONTENT_TYPE], "application/json");
    }

    /// Already-correct headers must survive untouched, and the match is on the
    /// media type only, so casing in the parameter cannot defeat it.
    #[test]
    fn json_content_type_is_idempotent_and_case_insensitive() {
        for start in ["application/json", "Application/JSON; charset=UTF-8"] {
            let mut headers = hyper::HeaderMap::new();
            headers.insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_str(start).unwrap(),
            );
            super::normalize_response_content_type(&mut headers);
            assert_eq!(headers[hyper::header::CONTENT_TYPE], "application/json", "from {start}");
        }
    }

    /// A non-JSON response keeps its own type: this layer normalizes JSON
    /// replies, it does not relabel everything as JSON.
    #[test]
    fn non_json_content_type_is_left_alone() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        super::normalize_response_content_type(&mut headers);
        assert_eq!(headers[hyper::header::CONTENT_TYPE], "text/plain; charset=utf-8");

        // A response with no Content-Type at all must not gain one.
        let mut empty = hyper::HeaderMap::new();
        super::normalize_response_content_type(&mut empty);
        assert!(empty.get(hyper::header::CONTENT_TYPE).is_none());
    }
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

    /// The layer's contract is that it rewrites the protocol tag and nothing
    /// else. Round-tripping the body through `serde_json::Value` broke that
    /// silently: `Map` collapses duplicate keys, so a `params` object written
    /// `{"a":1,"a":2}` reached the handler as `{"a":2}`. Core keeps duplicates
    /// and `createrawtransaction` rejects them by name — a check that sat
    /// downstream of this layer and could never fire.
    #[test]
    fn params_are_preserved_byte_for_byte() {
        let body = br#"{"jsonrpc":"1.0","id":"t","method":"createrawtransaction","params":[[],{"a":0.01,"a":0.02}]}"#;
        let out = normalize_jsonrpc_version(body).expect("should rewrite 1.0 -> 2.0");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#""jsonrpc":"2.0""#), "{text}");
        assert!(
            text.contains(r#""params":[[],{"a":0.01,"a":0.02}]"#),
            "duplicate keys must survive: {text}"
        );

        // Number spellings survive too — a `Value` round-trip renormalises
        // them, and amounts are parsed from their literal text.
        let body = br#"{"method":"createrawtransaction","params":[[],{"a":1.10,"b":1e2}]}"#;
        let out = normalize_jsonrpc_version(body).expect("should add jsonrpc + id");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#"{"a":1.10,"b":1e2}"#), "{text}");
        // The id this layer supplies for jsonrpsee's benefit is a sentinel it
        // strips from the reply, not a literal null — see
        // `an_absent_id_and_an_explicit_null_id_are_different`.
        assert!(text.contains("satd-absent-id-"), "{text}");

        // ...and in a batch.
        let body = br#"[{"method":"m","params":[{"a":1,"a":2}]},{"jsonrpc":"2.0","id":1,"method":"n","params":[]}]"#;
        let out = normalize_jsonrpc_version(body).expect("first element needs fixing");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#"{"a":1,"a":2}"#), "{text}");
    }

    /// A member this layer does not know about must be carried through
    /// unchanged rather than dropped.
    #[test]
    fn unknown_members_survive() {
        let body = br#"{"jsonrpc":"1.0","id":7,"method":"m","params":[],"extra":{"x":[1,2]}}"#;
        let out = normalize_jsonrpc_version(body).expect("should rewrite");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#""extra":{"x":[1,2]}"#), "{text}");
        assert!(text.contains(r#""id":7"#), "{text}");
        // Still exactly one `id` and one `jsonrpc`.
        assert_eq!(text.matches(r#""id":"#).count(), 1, "{text}");
        assert_eq!(text.matches(r#""jsonrpc":"#).count(), 1, "{text}");
        // And the result parses.
        let _: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    }

    #[test]
    fn leaves_2_0_untouched() {
        // Already 2.0 with id → no rewrite needed → None (forward verbatim).
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

    #[test]
    fn no_id_request_gets_id_added() {
        // jsonrpsee will not run a request without an `id`, so this layer
        // supplies one — a sentinel it can recognise and strip from the
        // reply, since Core answers a request that carried no id with no `id`
        // member at all.
        let out = norm(r#"{"method": "getbestblockhash"}"#).expect("should rewrite");
        assert_eq!(out["jsonrpc"], "2.0");
        assert!(
            out["id"].as_str().is_some_and(|s| s.starts_with(ABSENT_ID_PREFIX)),
            "{out}"
        );
        assert_eq!(out["method"], "getbestblockhash");
    }

    #[test]
    fn response_success_gets_error_null_in_core_order() {
        let input = br#"{"jsonrpc":"2.0","result":"abc","id":1}"#;
        let out = normalize_response_body_bytes(input);
        // Core field order: result, error, id.
        assert_eq!(
            out,
            br#"{"result":"abc","error":null,"id":1}
"#
        );
    }

    #[test]
    fn response_error_gets_result_null_in_core_order() {
        let input = br#"{"jsonrpc":"2.0","error":{"code":-28,"message":"loading"},"id":1}"#;
        let out = normalize_response_body_bytes(input);
        assert_eq!(
            out,
            br#"{"result":null,"error":{"code":-28,"message":"loading"},"id":1}
"#
        );
    }

    /// Core parses `id` as an `optional` and pushes it into the reply only
    /// when the request carried one (`rpc/request.cpp`, `JSONRPCReplyObj`).
    /// So "no id" and `"id": null` are different requests with different
    /// replies — and satd used to answer both the same way, omitting every
    /// null id.
    #[test]
    fn an_absent_id_and_an_explicit_null_id_are_different() {
        // The synthetic id this layer gives a request that carried none: the
        // reply drops the member entirely.
        let synthetic = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "result": "ok",
            "id": format!("{ABSENT_ID_PREFIX}0"),
        }))
        .unwrap();
        assert_eq!(
            normalize_response_body_bytes(&synthetic),
            br#"{"result":"ok","error":null}
"#
        );

        // An id the client actually wrote — even `null` — is echoed.
        let input = br#"{"jsonrpc":"2.0","result":"ok","id":null}"#;
        assert_eq!(
            normalize_response_body_bytes(input),
            br#"{"result":"ok","error":null,"id":null}
"#
        );
    }

    /// A JSON-RPC 2.0 request with no `id` is a notification: the method
    /// runs, and nothing comes back. satd injected `"id": null` into every
    /// request that lacked one, so jsonrpsee never saw a notification and the
    /// node always answered.
    #[test]
    fn a_2_0_request_without_an_id_is_a_notification() {
        let plan = plan_request(br#"{"jsonrpc":"2.0","method":"getblockcount","params":[]}"#);
        assert!(plan.all_notifications, "a lone 2.0 request with no id");
        assert_eq!(plan.notification_ids.len(), 1);
        // …and it still reaches jsonrpsee with an id, or the method would not
        // run at all.
        let body: serde_json::Value =
            serde_json::from_slice(&plan.body.expect("rewritten")).expect("valid JSON");
        assert_eq!(body["id"], serde_json::json!(plan.notification_ids[0]));

        // A 1.0 request without an id is *not* a notification: only 2.0 has
        // them. It is answered, with no `id` member.
        let plan = plan_request(br#"{"jsonrpc":"1.0","method":"getblockcount","params":[]}"#);
        assert!(!plan.all_notifications);
        assert!(plan.notification_ids.is_empty());

        // Neither is an explicit null id.
        let plan =
            plan_request(br#"{"jsonrpc":"2.0","id":null,"method":"getblockcount","params":[]}"#);
        assert!(!plan.all_notifications);
        assert!(plan.notification_ids.is_empty());
    }

    /// In a batch, a notification produces no entry — but its neighbours do.
    #[test]
    fn a_notification_in_a_batch_leaves_no_entry() {
        let plan = plan_request(
            br#"[{"jsonrpc":"2.0","method":"a"},{"jsonrpc":"2.0","id":7,"method":"b"}]"#,
        );
        assert!(!plan.all_notifications, "one member has an id");
        assert_eq!(plan.notification_ids.len(), 1);

        let reply = serde_json::to_vec(&serde_json::json!([
            { "jsonrpc": "2.0", "result": 1, "id": plan.notification_ids[0] },
            { "jsonrpc": "2.0", "result": 2, "id": 7 },
        ]))
        .unwrap();
        let kept = drop_notification_replies(&reply, &plan.notification_ids);
        let kept: serde_json::Value = serde_json::from_slice(&kept).unwrap();
        let kept = kept.as_array().expect("array");
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(kept[0]["id"], serde_json::json!(7));

        // A batch of nothing but notifications is answered 204 whole.
        let plan =
            plan_request(br#"[{"jsonrpc":"2.0","method":"a"},{"jsonrpc":"2.0","method":"b"}]"#);
        assert!(plan.all_notifications);
        assert_eq!(plan.notification_ids.len(), 2);
        assert_ne!(
            plan.notification_ids[0], plan.notification_ids[1],
            "two notifications in one batch need distinguishable ids"
        );
    }

    /// Core's HTTP status follows the JSON-RPC error code
    /// (`httprpc.cpp`): a parse error is 500, an invalid request 400, an
    /// unknown method 404. jsonrpsee answers 200 to all three.
    #[test]
    fn the_http_status_follows_cores_mapping() {
        for (code, want) in [
            (-32700, hyper::StatusCode::INTERNAL_SERVER_ERROR),
            (-32600, hyper::StatusCode::BAD_REQUEST),
            (-32601, hyper::StatusCode::NOT_FOUND),
        ] {
            let body = format!(r#"{{"error":{{"code":{code},"message":"x"}},"id":1}}"#);
            assert_eq!(
                core_http_status(body.as_bytes(), false),
                Some(want),
                "code {code}"
            );
            // The same error answering a *2.0* request keeps 200: Core
            // catches it and replies 200, and its own authproxy turns any
            // non-200 on a 2.0 reply into `-342` before it ever reads the
            // code. `rpc_generate.py` and `wallet_disable.py` both assert on
            // -32601 through that path.
            assert_eq!(
                core_http_status(body.as_bytes(), true),
                None,
                "code {code} on a 2.0 request must stay 200"
            );
        }
        // An application error keeps 200, as Core does.
        let body = br#"{"error":{"code":-8,"message":"x"},"id":1}"#;
        assert_eq!(core_http_status(body, false), None);
        // …and so does a success, and a batch.
        assert_eq!(core_http_status(br#"{"result":1,"id":1}"#, false), None);
        assert_eq!(
            core_http_status(br#"[{"error":{"code":-32601,"message":"x"},"id":1}]"#, false),
            None
        );
    }

    #[test]
    fn response_shape_follows_the_request_version() {
        // Core-shaped requests: no `jsonrpc` member, or 1.0/1.1.
        for body in [
            br#"{"method":"getblockcount","params":[],"id":1}"#.as_slice(),
            br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}"#.as_slice(),
            br#"{"jsonrpc":"1.1","method":"getblockcount","params":[],"id":1}"#.as_slice(),
        ] {
            assert!(
                !request_declared_2_0(body),
                "Core-shaped request must get the 1.0 response shape: {}",
                String::from_utf8_lossy(body)
            );
        }

        // A client that explicitly speaks 2.0 must not have its response
        // rewritten — 2.0 forbids `result` and `error` together and requires
        // the `jsonrpc` member that the rewrite strips.
        assert!(request_declared_2_0(
            br#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}"#
        ));

        // Batches: all-2.0 is 2.0; anything else is Core-shaped.
        assert!(request_declared_2_0(
            br#"[{"jsonrpc":"2.0","method":"a","id":1},{"jsonrpc":"2.0","method":"b","id":2}]"#
        ));
        assert!(!request_declared_2_0(
            br#"[{"jsonrpc":"2.0","method":"a","id":1},{"method":"b","id":2}]"#
        ));

        // Junk abstains rather than claiming 2.0, so the compatibility
        // rewrite stays the default for anything we cannot read.
        assert!(!request_declared_2_0(b"not json"));
        assert!(!request_declared_2_0(b""));
        assert!(!request_declared_2_0(br#"{"jsonrpc":"2.0","id":1}"#));
    }

    /// A repeated `jsonrpc` member is decided by its *last* value, because a
    /// `Map` keeps the last -- so that is what jsonrpsee will act on. Reading
    /// the first judged this body already-2.0 and forwarded it verbatim, and
    /// jsonrpsee then rejected the `"1.0"` it actually saw.
    #[test]
    fn the_last_jsonrpc_member_decides_the_rewrite() {
        let body = br#"{"jsonrpc":"2.0","jsonrpc":"1.0","method":"getblockcount","id":1}"#;
        let out = super::normalize_jsonrpc_version(body).expect("must rewrite");
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains(r#""1.0""#), "the 1.0 must not survive: {text}");
        assert_eq!(text.matches(r#""jsonrpc":"2.0""#).count(), 2, "{text}");
    }

    /// One unreadable element must not cost the rest of the batch its fixup.
    /// `Vec<Members>` failed whole-batch on a non-object element, so the
    /// Core-shaped requests beside it were forwarded without `jsonrpc`/`id`
    /// and answered as 2.0 notifications -- i.e. not answered at all.
    #[test]
    fn a_junk_batch_element_does_not_strand_its_neighbours() {
        let body = br#"[{"method":"getblockcount","id":1},5]"#;
        let out = super::normalize_jsonrpc_version(body).expect("must rewrite");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#""jsonrpc":"2.0""#), "{text}");
        assert!(text.ends_with(",5]"), "the junk element is copied through: {text}");
    }

    /// The whole point of the raw-member rewrite: `params` reaches jsonrpsee
    /// byte-for-byte, duplicate keys included.
    #[test]
    fn duplicate_params_keys_survive_the_rewrite() {
        let body = br#"{"method":"createrawtransaction","params":[[],{"a":1,"a":2}]}"#;
        let out = super::normalize_jsonrpc_version(body).expect("must rewrite");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(r#"{"a":1,"a":2}"#), "{text}");
    }

}
