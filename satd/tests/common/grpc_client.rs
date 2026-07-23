//! Real gRPC client for the streaming Consumption-API E2E suite.
//!
//! Connects a `tonic` client to a `satd` spawned by [`crate::common`]'s
//! `TestNode`, over the daemon's `--events-grpc-bind` listener — unlike the
//! in-process `end_to_end_streaming_delivery` test in `events/src/grpc.rs`,
//! which hand-builds a `GrpcEventSink` and never spawns the binary. The proto
//! types come from the same generated module the server uses
//! (`satd_events::proto::v1`), so a wire-shape drift is a compile error here.

#![allow(dead_code)]
// Re-exports + helpers consumed incrementally across the streaming E2E phases;
// the Phase 0/1 smoke tests use only a subset, so silence unused-import noise
// here rather than gating each export on the phase that first uses it.
#![allow(unused_imports)]

use satd_events::proto::v1 as pb;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Request, Status, Streaming};

pub use pb::node_event::Body;
/// The `SubscribeControl.msg` oneof, re-exported under an ergonomic name.
pub use pb::subscribe_control::Msg as Control;
pub use pb::{Cursor, NodeEvent, SubscribeControl, SubscribeRequest};

/// Injects an `authorization: Bearer <token>` header on every request when a
/// token is configured. A named interceptor (rather than a closure) so the
/// client's concrete type is nameable in [`GrpcStreamClient`].
#[derive(Clone)]
pub struct AuthInterceptor {
    token: Option<String>,
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        if let Some(t) = &self.token {
            let value = format!("Bearer {t}");
            req.metadata_mut().insert(
                "authorization",
                value.parse().expect("ascii bearer header"),
            );
        }
        Ok(req)
    }
}

type Inner = pb::node_event_stream_client::NodeEventStreamClient<
    InterceptedService<Channel, AuthInterceptor>,
>;

pub struct GrpcStreamClient {
    inner: Inner,
}

impl GrpcStreamClient {
    /// Connect to a loopback gRPC events listener (no auth).
    pub async fn connect(port: u16) -> Self {
        Self::connect_inner(port, None).await
    }

    /// Connect presenting a bearer token (for `--events-grpc-auth` nodes).
    pub async fn connect_with_token(port: u16, token: &str) -> Self {
        Self::connect_inner(port, Some(token.to_string())).await
    }

    /// Like [`Self::connect_with_token`] but returns the transport error
    /// instead of panicking — used by the auth-rejection tests, where the
    /// server is expected to refuse the stream.
    pub async fn try_connect_with_token(
        port: u16,
        token: Option<&str>,
    ) -> Result<Self, tonic::transport::Error> {
        let endpoint = format!("http://127.0.0.1:{port}");
        let channel = Channel::from_shared(endpoint).expect("uri").connect().await?;
        let interceptor = AuthInterceptor {
            token: token.map(|t| t.to_string()),
        };
        Ok(Self {
            inner: pb::node_event_stream_client::NodeEventStreamClient::with_interceptor(
                channel,
                interceptor,
            ),
        })
    }

    /// Connect with a deliberately tiny HTTP/2 flow-control window, so a
    /// non-reading client makes the server block (and its broadcast receiver
    /// lag) after only a few buffered events. Loopback socket buffers are
    /// megabytes, so without this a flood drains without ever lagging — this
    /// is what makes the in-band `Lagged` test deterministic.
    pub async fn connect_lagprone(port: u16) -> Self {
        let endpoint = Channel::from_shared(format!("http://127.0.0.1:{port}"))
            .expect("uri")
            .initial_stream_window_size(Some(2048))
            .initial_connection_window_size(Some(2048));
        let channel = endpoint.connect().await.expect("lagprone connect");
        Self {
            inner: pb::node_event_stream_client::NodeEventStreamClient::with_interceptor(
                channel,
                AuthInterceptor { token: None },
            ),
        }
    }

    async fn connect_inner(port: u16, token: Option<String>) -> Self {
        let endpoint = format!("http://127.0.0.1:{port}");
        // The listener is already bound by the time the harness reads its port
        // back from `getserverstatus`, but allow a brief retry for the HTTP/2
        // handshake to settle.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let channel = loop {
            match Channel::from_shared(endpoint.clone())
                .expect("uri")
                .connect()
                .await
            {
                Ok(c) => break c,
                Err(e) => {
                    if std::time::Instant::now() >= deadline {
                        panic!("gRPC connect to {endpoint} failed: {e}");
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        };
        Self {
            inner: pb::node_event_stream_client::NodeEventStreamClient::with_interceptor(
                channel,
                AuthInterceptor { token },
            ),
        }
    }

    /// Open a server-streaming `Subscribe` firehose. `categories` is the
    /// bitfield (0 = all). `from_cursor` requests durable replay.
    pub async fn subscribe(
        &mut self,
        categories: u32,
        from_cursor: Option<Cursor>,
    ) -> Streaming<NodeEvent> {
        self.inner
            .subscribe(SubscribeRequest {
                categories,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
                mempool_tweaks: None,
                tweak_outputs: None,
                from_cursor,
            })
            .await
            .expect("subscribe")
            .into_inner()
    }

    /// Like [`Self::subscribe`] but returns the auth/transport error instead
    /// of panicking — used by the auth-rejection tests, where the server
    /// rejects the stream with `Unauthenticated`/`PermissionDenied`.
    pub async fn try_subscribe(
        &mut self,
        categories: u32,
    ) -> Result<Streaming<NodeEvent>, Status> {
        let resp = self
            .inner
            .subscribe(SubscribeRequest {
                categories,
                since_seq: None,
                tweak_dust_limit: None,
                tweaks_only: None,
                mempool_tweaks: None,
                tweak_outputs: None,
                from_cursor: None,
            })
            .await?;
        Ok(resp.into_inner())
    }

    /// Open the bidirectional `Watch` stream. Returns a control sender (send
    /// `SubscribeControl` messages to mutate the live watch-set) and the
    /// inbound event/match stream. The `initial` controls are sent before the
    /// stream is opened.
    pub async fn watch(
        &mut self,
        initial: Vec<SubscribeControl>,
    ) -> (mpsc::Sender<SubscribeControl>, Streaming<NodeEvent>) {
        let (tx, rx) = mpsc::channel(16);
        for c in initial {
            tx.send(c).await.expect("send initial control");
        }
        let stream = self
            .inner
            .watch(Request::new(ReceiverStream::new(rx)))
            .await
            .expect("watch")
            .into_inner();
        (tx, stream)
    }
}

// --- SubscribeControl builders (gRPC wire-correct) -------------------------
//
// gRPC control parsing reads txid/outpoint as 32 RAW bytes in *internal*
// order (`Txid::from_raw_hash(from_byte_array(bytes))`), whereas RPC returns
// display (reversed) hex — so these builders reverse a display-hex txid into
// internal bytes. Scripthashes and prefixes are natural-order `sha256(spk)`
// bytes (no reversal). The WS JSON path differs (it parses display-hex txid
// strings); see `ws_client` / the WS tests.

fn txid_internal_bytes(display_hex: &str) -> Vec<u8> {
    let mut b = hex::decode(display_hex).expect("txid hex");
    b.reverse();
    b
}

/// `AddOutpoints` for `(display_txid, vout)` pairs.
pub fn add_outpoints(items: &[(&str, u32)]) -> SubscribeControl {
    SubscribeControl {
        msg: Some(Control::AddOutpoints(pb::AddOutpoints {
            outpoints: items
                .iter()
                .map(|(txid, vout)| pb::Outpoint {
                    txid: txid_internal_bytes(txid),
                    vout: *vout,
                })
                .collect(),
        })),
    }
}

/// `RemoveOutpoints` for `(display_txid, vout)` pairs.
pub fn remove_outpoints(items: &[(&str, u32)]) -> SubscribeControl {
    SubscribeControl {
        msg: Some(Control::RemoveOutpoints(pb::RemoveOutpoints {
            outpoints: items
                .iter()
                .map(|(txid, vout)| pb::Outpoint {
                    txid: txid_internal_bytes(txid),
                    vout: *vout,
                })
                .collect(),
        })),
    }
}

/// `AddScripts` for natural-order `sha256(spk)` scripthash hex strings.
pub fn add_scripts(scripthash_hex: &[&str]) -> SubscribeControl {
    SubscribeControl {
        msg: Some(Control::AddScripts(pb::AddScripts {
            scripthashes: scripthash_hex
                .iter()
                .map(|h| hex::decode(h).expect("scripthash hex"))
                .collect(),
            min_values: Vec::new(),
        })),
    }
}

/// `AddScripts` carrying a per-scripthash `min_value` floor (satoshis). `floors`
/// is parallel to `scripthash_hex` (index `i` is the floor for scripthash `i`);
/// a floor of `0` means "deliver every match". Re-sending an already-watched
/// scripthash updates its floor in place (the `reassert` metadata-refresh path).
pub fn add_scripts_with_floors(scripthash_hex: &[&str], floors: &[u64]) -> SubscribeControl {
    assert_eq!(
        scripthash_hex.len(),
        floors.len(),
        "min_values must be parallel to scripthashes"
    );
    SubscribeControl {
        msg: Some(Control::AddScripts(pb::AddScripts {
            scripthashes: scripthash_hex
                .iter()
                .map(|h| hex::decode(h).expect("scripthash hex"))
                .collect(),
            min_values: floors.to_vec(),
        })),
    }
}

/// `AddTransactions` for display-hex txids. `min_depths` empty ⇒ lifecycle
/// watch (optionally self-closing at `auto_close_depth`); non-empty ⇒ depth
/// alarms.
pub fn add_transactions(
    display_txids: &[&str],
    min_depths: Vec<u32>,
    auto_close_depth: u32,
) -> SubscribeControl {
    SubscribeControl {
        msg: Some(Control::AddTransactions(pb::AddTransactions {
            txids: display_txids.iter().map(|t| txid_internal_bytes(t)).collect(),
            min_depths,
            auto_close_depth,
        })),
    }
}

/// `AddScriptPrefixes` for a single byte-aligned prefix (natural-order top
/// bytes hex + bit length).
pub fn add_script_prefixes(prefix_hex: &str, bits: u32) -> SubscribeControl {
    SubscribeControl {
        msg: Some(Control::AddScriptPrefixes(pb::AddScriptPrefixes {
            prefixes: vec![pb::ScriptPrefix {
                prefix: hex::decode(prefix_hex).expect("prefix hex"),
                bits,
            }],
        })),
    }
}

/// Await the next event on a stream, panicking on timeout / stream close.
pub async fn next_event(stream: &mut Streaming<NodeEvent>, secs: u64) -> NodeEvent {
    tokio::time::timeout(Duration::from_secs(secs), stream.message())
        .await
        .expect("timed out waiting for gRPC event")
        .expect("gRPC stream error")
        .expect("gRPC stream closed unexpectedly")
}

/// Await the next event, returning `None` on timeout or clean close. For
/// negative assertions ("no match should arrive").
pub async fn next_event_opt(stream: &mut Streaming<NodeEvent>, secs: u64) -> Option<NodeEvent> {
    match tokio::time::timeout(Duration::from_secs(secs), stream.message()).await {
        Ok(Ok(ev)) => ev,
        _ => None,
    }
}

/// Await the next event whose body matches `pred` (skipping heartbeats and any
/// other interleaved firehose traffic), up to `secs` total.
pub async fn next_event_matching(
    stream: &mut Streaming<NodeEvent>,
    secs: u64,
    pred: impl Fn(&Body) -> bool,
) -> NodeEvent {
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for matching event");
        let ev = tokio::time::timeout(remaining, stream.message())
            .await
            .expect("timed out waiting for matching event")
            .expect("gRPC stream error")
            .expect("gRPC stream closed unexpectedly");
        if let Some(body) = &ev.body
            && pred(body)
        {
            return ev;
        }
    }
}
