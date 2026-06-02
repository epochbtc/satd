//! JSON-over-WebSocket + SSE firehose transport for the streaming API.
//!
//! A dedicated `--streamws` listener (separate port, on the API runtime —
//! never the consensus core) serving the same event schema as the gRPC
//! `NodeEventStream`, hand-mapped to JSON (no grpc-gateway / Go toolchain):
//!
//! - `GET /ws` — a WebSocket: the server streams JSON `NodeEvent`s (live,
//!   category-filtered) and per-subscriber watch matches; the client sends
//!   JSON control messages to manage its watch-set (the JSON mirror of the
//!   gRPC `Watch` bidi stream).
//! - `GET /sse` — a read-only Server-Sent-Events firehose of JSON
//!   `NodeEvent`s, for browser / `curl` consumers (reuses the Esplora SSE
//!   pattern).
//!
//! Auth mirrors the gRPC sink: when a token store is configured, every
//! connection requires `Authorization: Bearer <token>` resolving to a
//! principal with `stream:subscribe`; each watch addition additionally
//! needs `stream:watch` + quota. With no token store (loopback trust) the
//! transport is open, today's events-gRPC behavior.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use node::events::{EventPublisher, WatchMatch, WatchRegistry, WATCH_CHANNEL_CAPACITY};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, watch};
use tokio_stream::wrappers::BroadcastStream;
use tracing::{debug, info, warn};

/// Construction-time errors for the WS transport.
#[derive(Debug, thiserror::Error)]
pub enum WsStreamError {
    #[error("invalid streamws bind address '{0}': {1}")]
    InvalidBind(String, std::net::AddrParseError),
    #[error(
        "refusing to bind streamws server on non-loopback address {0}: pass \
         --streamws-allow-remote (which requires --streamws-auth) to override"
    )]
    RemoteBindRejected(SocketAddr),
    #[error("failed to bind {0}: {1}")]
    BindFailed(SocketAddr, std::io::Error),
}

/// Shared handler state.
#[derive(Clone)]
struct WsState {
    publisher: Arc<EventPublisher>,
    watch_registry: Arc<WatchRegistry>,
    auth: Option<Arc<satd_auth::TokenStore>>,
}

/// The `--streamws` JSON/WS + SSE transport. Bind early (so a bind failure
/// is reported at startup), then [`WsStreamServer::serve`] on the API
/// runtime.
pub struct WsStreamServer {
    addr: SocketAddr,
    listener: TcpListener,
    state: WsState,
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl WsStreamServer {
    /// Bind the listener. Only loopback is accepted unless `allow_remote`
    /// (which the config layer ties to `--streamws-auth`).
    pub async fn bind(
        bind: &str,
        allow_remote: bool,
        publisher: Arc<EventPublisher>,
        watch_registry: Arc<WatchRegistry>,
        auth: Option<Arc<satd_auth::TokenStore>>,
    ) -> Result<Self, WsStreamError> {
        let addr: SocketAddr = bind
            .parse()
            .map_err(|e| WsStreamError::InvalidBind(bind.to_string(), e))?;
        if !allow_remote && !is_loopback(&addr.ip()) {
            return Err(WsStreamError::RemoteBindRejected(addr));
        }
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| WsStreamError::BindFailed(addr, e))?;
        let bound = listener.local_addr().unwrap_or(addr);
        info!(
            target: "events::ws",
            addr = %bound,
            allow_remote,
            authenticated = auth.is_some(),
            "streamws server bound",
        );
        Ok(Self {
            addr: bound,
            listener,
            state: WsState {
                publisher,
                watch_registry,
                auth,
            },
        })
    }

    /// Bound address (test/observability helper).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve until `shutdown` flips. Intended to be spawned on the API
    /// runtime.
    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) {
        let app = Router::new()
            .route("/ws", get(ws_upgrade))
            .route("/sse", get(sse_firehose))
            .with_state(self.state);
        info!(target: "events::ws", addr = %self.addr, "streamws server starting");
        let result = axum::serve(self.listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown.changed().await;
            })
            .await;
        if let Err(e) = result {
            warn!(target: "events::ws", error = %e, "streamws server exited with error");
        }
    }
}

/// Authorize a connection: with a token store, require a bearer token
/// holding `stream:subscribe`. Returns the principal (or `None` when auth
/// is disabled) or an HTTP error response.
// The `Err` variant is an axum `Response` (large), but it's the natural
// return for an auth gate and is only built on the rejection path.
#[allow(clippy::result_large_err)]
fn authorize(state: &WsState, headers: &HeaderMap) -> Result<Option<satd_auth::Principal>, Response> {
    let Some(store) = state.auth.as_ref() else {
        return Ok(None); // auth disabled (loopback trust)
    };
    let hdr = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing authorization header").into_response())?;
    let mut scratch = String::new();
    let principal = match satd_auth::Credential::from_authorization(hdr, &mut scratch) {
        Some(satd_auth::Credential::Bearer { token }) => store.resolve(token, now_unix()),
        _ => None,
    }
    .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid or unknown bearer token").into_response())?;
    if !principal.has(satd_auth::Capability::StreamSubscribe) {
        return Err((StatusCode::FORBIDDEN, "token lacks stream:subscribe").into_response());
    }
    if let satd_auth::RateDecision::Throttle { .. } = principal.check_rate() {
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response());
    }
    Ok(Some(principal))
}

#[derive(Deserialize)]
struct CategoryQuery {
    /// Category bitfield (mempool=1, chain=2, heartbeat=4; 0/absent = all).
    categories: Option<u32>,
}

fn mask_from(categories: Option<u32>) -> u32 {
    match categories {
        None | Some(0) => u32::MAX,
        Some(c) => c,
    }
}

/// `GET /sse` — read-only JSON `NodeEvent` firehose.
async fn sse_firehose(
    State(state): State<WsState>,
    headers: HeaderMap,
    Query(q): Query<CategoryQuery>,
) -> Response {
    if let Err(resp) = authorize(&state, &headers) {
        return resp;
    }
    let mask = mask_from(q.categories);
    let rx = state.publisher.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |item| async move {
        match item {
            Ok(env) if (env.category_bit() & mask) != 0 => Some(Ok::<_, std::convert::Infallible>(
                Event::default().data(serde_json::to_string(&env).unwrap_or_default()),
            )),
            _ => None,
        }
    });
    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

/// `GET /ws` — bidirectional JSON WebSocket.
async fn ws_upgrade(
    State(state): State<WsState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let principal = match authorize(&state, &headers) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    ws.on_upgrade(move |socket| ws_conn(socket, state, principal))
}

async fn ws_conn(socket: WebSocket, state: WsState, principal: Option<satd_auth::Principal>) {
    let (mut sender, mut receiver) = socket.split();
    let (handle, mut rx_match) = state.watch_registry.register(WATCH_CHANNEL_CAPACITY);
    let handle = Arc::new(handle);
    let category_mask = Arc::new(AtomicU32::new(u32::MAX));
    let mut rx_live = state.publisher.subscribe();
    debug!(target: "events::ws", authenticated = principal.is_some(), "streamws connection opened");

    // Inbound control reader: applies watch-set + category changes and holds
    // the quota leases (released when this task ends = on disconnect).
    let inbound = {
        let handle = handle.clone();
        let category_mask = category_mask.clone();
        tokio::spawn(async move {
            let mut leases: Vec<satd_auth::WatchLease> = Vec::new();
            while let Some(Ok(msg)) = receiver.next().await {
                match msg {
                    Message::Text(t) => {
                        apply_ws_control(&t, &handle, principal.as_ref(), &category_mask, &mut leases)
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            drop(leases);
        })
    };

    // Outbound: live firehose (category-filtered) + watch matches as JSON.
    loop {
        tokio::select! {
            ev = rx_live.recv() => match ev {
                Ok(env) => {
                    if (env.category_bit() & category_mask.load(Ordering::Relaxed)) != 0
                        && let Ok(text) = serde_json::to_string(&env)
                        && sender.send(Message::Text(text.into())).await.is_err()
                    {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(target: "events::ws", dropped = n, "streamws subscriber lagged (firehose)");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            m = rx_match.recv() => match m {
                Some(wm) => {
                    let text = watch_match_json(&wm).to_string();
                    if sender.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
        }
    }
    inbound.abort();
    // `handle` drops here → deregister the watch-set.
    debug!(target: "events::ws", "streamws connection closed");
}

/// JSON control messages a `/ws` client sends to manage its watch-set —
/// the JSON mirror of the gRPC `SubscribeControl` tagged union.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsControl {
    /// Set the live firehose category bitfield (0 = all).
    SetCategories { categories: u32 },
    /// Add outpoints to the watch-set (charges N quota units).
    AddOutpoints { outpoints: Vec<WsOutpoint> },
    /// Remove outpoints from the watch-set.
    RemoveOutpoints { outpoints: Vec<WsOutpoint> },
    /// Add scripthashes (32-byte hex, natural order) to the watch-set.
    AddScripts { scripthashes: Vec<String> },
    /// Remove scripthashes from the watch-set.
    RemoveScripts { scripthashes: Vec<String> },
}

#[derive(Deserialize)]
struct WsOutpoint {
    /// Transaction id in the usual display (reversed) hex.
    txid: String,
    vout: u32,
}

fn parse_ws_outpoint(o: &WsOutpoint) -> Option<bitcoin::OutPoint> {
    use std::str::FromStr;
    let txid = bitcoin::Txid::from_str(&o.txid).ok()?;
    Some(bitcoin::OutPoint { txid, vout: o.vout })
}

fn parse_ws_scripthash(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut sh = [0u8; 32];
    sh.copy_from_slice(&bytes);
    Some(sh)
}

fn apply_ws_control(
    text: &str,
    handle: &node::events::WatchHandle,
    principal: Option<&satd_auth::Principal>,
    category_mask: &AtomicU32,
    leases: &mut Vec<satd_auth::WatchLease>,
) {
    let ctrl: WsControl = match serde_json::from_str(text) {
        Ok(c) => c,
        Err(e) => {
            warn!(target: "events::ws", error = %e, "ignoring malformed streamws control message");
            return;
        }
    };
    match ctrl {
        WsControl::SetCategories { categories } => {
            let mask = if categories == 0 { u32::MAX } else { categories };
            category_mask.store(mask, Ordering::Relaxed);
        }
        WsControl::AddOutpoints { outpoints } => {
            let ops: Vec<bitcoin::OutPoint> =
                outpoints.iter().filter_map(parse_ws_outpoint).collect();
            if !ops.is_empty() {
                charge_and_add(principal, leases, ops.len(), "outpoints", || {
                    handle.add_outpoints(&ops);
                });
            }
        }
        WsControl::RemoveOutpoints { outpoints } => {
            let ops: Vec<bitcoin::OutPoint> =
                outpoints.iter().filter_map(parse_ws_outpoint).collect();
            handle.remove_outpoints(&ops);
        }
        WsControl::AddScripts { scripthashes } => {
            let shs: Vec<[u8; 32]> = scripthashes
                .iter()
                .filter_map(|s| parse_ws_scripthash(s))
                .collect();
            if !shs.is_empty() {
                charge_and_add(principal, leases, shs.len(), "scripts", || {
                    handle.add_scripthashes(&shs);
                });
            }
        }
        WsControl::RemoveScripts { scripthashes } => {
            let shs: Vec<[u8; 32]> = scripthashes
                .iter()
                .filter_map(|s| parse_ws_scripthash(s))
                .collect();
            handle.remove_scripthashes(&shs);
        }
    }
}

/// Charge `n` watch-quota units, then `add` on success. No principal (auth
/// disabled) → unlimited (loopback trust).
fn charge_and_add<F: FnOnce()>(
    principal: Option<&satd_auth::Principal>,
    leases: &mut Vec<satd_auth::WatchLease>,
    n: usize,
    kind: &'static str,
    add: F,
) {
    match principal {
        Some(p) => match p.acquire_watch(n as u64) {
            Ok(lease) => {
                add();
                leases.push(lease);
            }
            Err(reject) => {
                warn!(target: "events::ws", kind, reject = ?reject, "watch add rejected (capability or quota)");
            }
        },
        None => add(),
    }
}

/// Hand-rolled JSON for a watch match (the proto has no `serde` derive). The
/// shape mirrors a `NodeEvent`: a `body` tagged by `category`, plus a
/// `cursor` on confirmed matches.
fn watch_match_json(m: &WatchMatch) -> serde_json::Value {
    use bitcoin::hashes::Hash;
    match m {
        WatchMatch::OutpointSpent {
            outpoint,
            spending_txid,
            spending_vin,
            confirmed,
            height,
        } => json!({
            "schema_version": node::events::SCHEMA_VERSION,
            "cursor": height.map(|h| json!({ "height": h, "tx_index": 0, "mempool_seq": 0 })),
            "body": {
                "category": "outpoint_spent",
                "outpoint_txid": hex::encode(outpoint.txid.as_raw_hash().to_byte_array()),
                "outpoint_vout": outpoint.vout,
                "spending_txid": hex::encode(spending_txid.as_raw_hash().to_byte_array()),
                "spending_vin": spending_vin,
                "confirmed": confirmed,
            }
        }),
        WatchMatch::ScriptMatched {
            scripthash,
            txid,
            is_output,
            index,
            confirmed,
            height,
        } => json!({
            "schema_version": node::events::SCHEMA_VERSION,
            "cursor": height.map(|h| json!({ "height": h, "tx_index": 0, "mempool_seq": 0 })),
            "body": {
                "category": "script_matched",
                "scripthash": hex::encode(scripthash),
                "txid": hex::encode(txid.as_raw_hash().to_byte_array()),
                "is_output": is_output,
                "index": index,
                "confirmed": confirmed,
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_defaults_to_all() {
        assert_eq!(mask_from(None), u32::MAX);
        assert_eq!(mask_from(Some(0)), u32::MAX);
        assert_eq!(mask_from(Some(2)), 2);
    }

    #[test]
    fn parses_scripthash_hex() {
        let hexstr = "ff".repeat(32);
        assert_eq!(parse_ws_scripthash(&hexstr), Some([0xff; 32]));
        assert_eq!(parse_ws_scripthash("ff"), None); // wrong length
        assert_eq!(parse_ws_scripthash("zz".repeat(32).as_str()), None); // not hex
    }

    #[test]
    fn parses_control_json() {
        let c: WsControl =
            serde_json::from_str(r#"{"type":"set_categories","categories":2}"#).unwrap();
        match c {
            WsControl::SetCategories { categories } => assert_eq!(categories, 2),
            _ => panic!("wrong variant"),
        }
        let c: WsControl = serde_json::from_str(
            r#"{"type":"add_outpoints","outpoints":[{"txid":"00","vout":1}]}"#,
        )
        .unwrap();
        assert!(matches!(c, WsControl::AddOutpoints { .. }));
    }

    #[test]
    fn watch_match_json_shape() {
        use bitcoin::hashes::Hash;
        let m = WatchMatch::OutpointSpent {
            outpoint: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]),
                ),
                vout: 3,
            },
            spending_txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xbb; 32]),
            ),
            spending_vin: 0,
            confirmed: true,
            height: Some(101),
        };
        let v = watch_match_json(&m);
        assert_eq!(v["body"]["category"], "outpoint_spent");
        assert_eq!(v["body"]["outpoint_vout"], 3);
        assert_eq!(v["body"]["confirmed"], true);
        assert_eq!(v["cursor"]["height"], 101);
    }
}
