//! Server-Sent Events handlers (Esplora plan PR 9).
//!
//! Three SSE streams:
//!
//! - `GET /blocks/sse`         → one `block` event per chain-tip
//!   `BlockConnected`. Body: JSON `{hash, height}`.
//! - `GET /address/:addr/sse`  → one `status` event per status-hash
//!   change for the address. Body: JSON `{address, status_hash}`.
//! - `GET /scripthash/:hash/sse` → parallel scripthash variant. Body
//!   shape is identical to `/address/:addr/sse` —
//!   `{address, status_hash}`, where the `address` field carries the
//!   scripthash hex. The field name is stable across both routes so
//!   client tooling can dispatch on a single key.
//!
//! Each stream emits a heartbeat comment every 25 seconds so idle
//! connections survive intermediate proxy timeouts (Caddy's default
//! is 30s; nginx's default is 60s).
//!
//! Subscribers that lag the broadcast channel see the stream skip
//! ahead — the broadcast guarantees no panic, only that *some* events
//! between subscriptions may have been dropped. Clients are expected
//! to re-fetch via the standard endpoints (`/address/:addr` or
//! `/blocks/tip`) on reconnect / lag.
//!
//! Per-address subscriptions consume from the same
//! `SubscriptionRegistry` capped by `--addrindexsubscriptions=N`; an
//! over-cap subscribe attempt returns 503 (`SubscribeError::CapReached`).
//!
//! Open-stream count is capped by `--esplorasseconns` (defaults to
//! `--esploramaxconns`). Each handler acquires an
//! `OwnedSemaphorePermit` and embeds it in the response stream so the
//! permit lives until client disconnect. Tower's
//! `ConcurrencyLimitLayer` does not bound stream lifetime — only
//! request handling — so without this separate cap an attacker could
//! pin SSE sockets indefinitely (review M2).

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Network};
use futures_util::stream::{Stream, StreamExt};
use node::chain::events::ChainEvent;
use node_index::{Scripthash, SubscribeError, scripthash_of};
use serde::Serialize;
use tokio::sync::OwnedSemaphorePermit;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};

use crate::error::{EsploraError, EsploraResult};
use crate::state::EsploraState;

/// Heartbeat interval — sent as a `:keep-alive` SSE comment so idle
/// connections survive proxy timeouts. 25s is comfortably under the
/// 30s default Caddy timeout.
const HEARTBEAT: Duration = Duration::from_secs(25);

// ── JSON shapes ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct BlockEventJson {
    pub hash: String,
    pub height: u32,
}

#[derive(Debug, Serialize)]
pub struct AddressStatusEventJson {
    /// Literal input string. For `/address/:addr/sse` this is the
    /// address; for `/scripthash/:hash/sse` it is the scripthash hex.
    /// Field name kept stable across both routes so client tooling can
    /// dispatch on it identically.
    pub address: String,
    /// Hex-encoded 32-byte Electrum-compatible status hash.
    pub status_hash: String,
}

// ── Block SSE ──────────────────────────────────────────────────────

pub async fn blocks_sse(
    State(state): State<EsploraState>,
) -> EsploraResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    // Acquire an SSE permit BEFORE wiring the broadcast receiver so a
    // saturated cap rejects with 503 cheaply (review M2). Permit is
    // moved into the stream below; it drops when the stream drops.
    let permit = acquire_sse_permit(&state)?;
    let rx = state
        .chain
        .subscribe_chain_events()
        .ok_or(EsploraError::ServiceUnavailable)?;
    // Wrap broadcast Receiver as a Stream; map each event into an SSE
    // payload, filter out disconnects (we only emit on connect), and
    // skip lag errors (clients re-fetch on reconnect).
    let stream = BroadcastStream::new(rx).filter_map(|item| async move {
        match item {
            Ok(ChainEvent::BlockConnected { hash, height }) => {
                let payload = BlockEventJson {
                    hash: hash.to_string(),
                    height,
                };
                Some(Ok(Event::default()
                    .event("block")
                    .data(serde_json::to_string(&payload).unwrap_or_default())))
            }
            Ok(ChainEvent::BlockDisconnected { .. }) => None,
            Err(BroadcastStreamRecvError::Lagged(_)) => None,
        }
    });
    let stream = with_permit(stream, permit);
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(HEARTBEAT)))
}

// ── Address / scripthash SSE ───────────────────────────────────────

pub async fn address_sse(
    State(state): State<EsploraState>,
    Path(addr): Path<String>,
) -> EsploraResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let sh = parse_address(&addr, state.network)?;
    let permit = acquire_sse_permit(&state)?;
    let rx = state.address_index.subscribe(sh).map_err(map_subscribe_err)?;
    Ok(build_status_sse(rx, addr, permit))
}

pub async fn scripthash_sse(
    State(state): State<EsploraState>,
    Path(hash): Path<String>,
) -> EsploraResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let sh = parse_scripthash(&hash)?;
    let permit = acquire_sse_permit(&state)?;
    let rx = state.address_index.subscribe(sh).map_err(map_subscribe_err)?;
    Ok(build_status_sse(rx, hash, permit))
}

/// Wrap a per-scripthash `StatusUpdate` receiver into an SSE stream.
/// `label` is the literal user-supplied identifier (address or
/// scripthash hex) — included in each event payload as `address` so
/// client tooling can dispatch on a single field across both routes.
/// `permit` lives until the stream is dropped, releasing the SSE cap
/// slot exactly when the client disconnects.
fn build_status_sse(
    rx: tokio::sync::broadcast::Receiver<node_index::StatusUpdate>,
    label: String,
    permit: OwnedSemaphorePermit,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(rx).filter_map(move |item| {
        let label = label.clone();
        async move {
            match item {
                Ok(update) => {
                    let payload = AddressStatusEventJson {
                        address: label,
                        status_hash: hex::encode(update.status_hash),
                    };
                    Some(Ok(Event::default()
                        .event("status")
                        .data(serde_json::to_string(&payload).unwrap_or_default())))
                }
                Err(BroadcastStreamRecvError::Lagged(_)) => None,
            }
        }
    });
    let stream = with_permit(stream, permit);
    Sse::new(stream).keep_alive(KeepAlive::new().interval(HEARTBEAT))
}

/// Try to grab one SSE permit. `cap = 0` disables the cap (returns a
/// permit from a sized-1 semaphore that's then immediately released —
/// equivalent to "no cap", since we never actually hold permits in
/// the cap=0 case). Returns 503 when the cap is saturated.
fn acquire_sse_permit(state: &EsploraState) -> EsploraResult<OwnedSemaphorePermit> {
    state
        .sse_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| EsploraError::ServiceUnavailable)
}

/// Glue an `OwnedSemaphorePermit` to the lifetime of a stream.
/// `futures_util::StreamExt::map` consumes the permit by moving it
/// into the per-item closure, but each item's closure runs and drops
/// before the next event arrives — so a `move` capture wouldn't keep
/// the permit alive across events. We instead wrap the stream in a
/// dedicated `PermitStream` whose `Drop` releases the permit when the
/// outer `Sse` body is dropped (i.e., on client disconnect).
fn with_permit<S>(stream: S, permit: OwnedSemaphorePermit) -> impl Stream<Item = S::Item>
where
    S: Stream + Send + 'static,
{
    PermitStream {
        inner: Box::pin(stream),
        _permit: permit,
    }
}

#[pin_project::pin_project]
struct PermitStream<S> {
    #[pin]
    inner: std::pin::Pin<Box<S>>,
    _permit: OwnedSemaphorePermit,
}

impl<S: Stream> Stream for PermitStream<S> {
    type Item = S::Item;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.project().inner.as_mut().poll_next(cx)
    }
}

// ── Parsing ────────────────────────────────────────────────────────

fn parse_address(s: &str, network: Network) -> EsploraResult<Scripthash> {
    let unchecked: Address<NetworkUnchecked> = s
        .parse()
        .map_err(|e| EsploraError::BadRequest(format!("bad address '{s}': {e}")))?;
    let address = unchecked
        .require_network(network)
        .map_err(|e| {
            EsploraError::BadRequest(format!("address '{s}' not valid for network: {e}"))
        })?;
    Ok(scripthash_of(&address.script_pubkey()))
}

fn parse_scripthash(s: &str) -> EsploraResult<Scripthash> {
    let bytes = hex::decode(s)
        .map_err(|e| EsploraError::BadRequest(format!("bad scripthash hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(EsploraError::BadRequest(format!(
            "scripthash must be 32 bytes (64 hex chars); got {}",
            bytes.len()
        )));
    }
    let mut sh = [0u8; 32];
    sh.copy_from_slice(&bytes);
    Ok(sh)
}

fn map_subscribe_err(e: SubscribeError) -> EsploraError {
    match e {
        // The configured subscription cap is full. 503 mirrors the
        // disabled-index path so tooling can treat both as transient.
        SubscribeError::CapReached(_) => EsploraError::ServiceUnavailable,
    }
}
