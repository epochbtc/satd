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
fn normalize_jsonrpc_version(body: &[u8]) -> Option<Vec<u8>> {
    // The body is already size-bounded by the caller (Content-Length
    // pre-check + `Limited` read), so this only guards the empty case;
    // the length check is kept as defense-in-depth.
    if body.is_empty() || body.len() > MAX_NORMALIZE_BODY {
        return None;
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
        let fix = plan_request_fix(&members);
        if !fix.changed() {
            return None;
        }
        let mut out = Vec::with_capacity(body.len() + 32);
        write_request_object(&mut out, &mut members, fix);
        return Some(out);
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
        for raw in &elements {
            match serde_json::from_str::<Members>(raw.get()) {
                Ok(members) => {
                    let fix = plan_request_fix(&members);
                    parsed.push(Some((members, fix)));
                }
                Err(_) => parsed.push(None),
            }
        }
        if !parsed
            .iter()
            .any(|p| p.as_ref().is_some_and(|(_, fix)| fix.changed()))
        {
            return None;
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
        return Some(out);
    }
    None
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
}

impl RequestFix {
    const NONE: Self = Self {
        set_jsonrpc: false,
        add_id: false,
    };

    fn changed(&self) -> bool {
        self.set_jsonrpc || self.add_id
    }
}

/// If `members` is a JSON-RPC *request* object (it has a `"method"` member),
/// decide whether its `"jsonrpc"` member needs forcing to `2.0` and whether an
/// `"id"` must be added. Without an `id`, jsonrpsee treats the request as a
/// 2.0 notification and returns no response; Core always responds, `id` or not.
fn plan_request_fix(members: &Members<'_>) -> RequestFix {
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
    RequestFix {
        set_jsonrpc: !already_2_0,
        add_id: !has("id"),
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
        out.extend_from_slice(b"\"id\":null");
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

    let mut out = format!("{{\"result\":{result_json},\"error\":{error_json}");
    if let Some(id_val) = &id
        && !id_val.is_null()
    {
        let id_json = serde_json::to_string(id_val).ok()?;
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

            let new_body = match normalize_jsonrpc_version(&collected) {
                Some(rewritten) => HttpBody::from(rewritten),
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
            // Core-shaped request in, Core-shaped response out. A client that
            // asked for 2.0 gets jsonrpsee's 2.0 reply untouched.
            let out_body = if client_spoke_2_0 {
                resp_bytes.to_vec()
            } else {
                normalize_response_body_bytes(&resp_bytes)
            };
            Ok(HttpResponse::from_parts(head, HttpBody::from(out_body)))
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
        assert!(text.contains(r#""id":null"#), "{text}");

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
        let out = norm(r#"{"method": "getbestblockhash"}"#).expect("should rewrite");
        assert_eq!(out["jsonrpc"], "2.0");
        assert_eq!(out["id"], serde_json::Value::Null);
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

    #[test]
    fn response_with_null_id_omits_id() {
        // A request we added synthetic `id:null` to gets the id stripped
        // from the response, matching Core's "no id in request → no id
        // in response" behaviour.
        let input = br#"{"jsonrpc":"2.0","result":"ok","id":null}"#;
        let out = normalize_response_body_bytes(input);
        assert_eq!(out, br#"{"result":"ok","error":null}
"#);
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
