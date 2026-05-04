//! gRPC server-streaming adapter for the satd events bus.
//!
//! Each connecting client opens a `Subscribe` RPC and receives a
//! [`NodeEvent`](node::events::NodeEvent) stream until it disconnects or
//! the daemon shuts down. The sink itself is a single
//! [`tonic`](tonic::transport::Server) bound to a configured address; per-client
//! state (broadcast receiver + filter) lives on the streaming task spawned
//! by tonic for each incoming RPC.
//!
//! Lag handling matches the Esplora SSE pattern — `Lagged` is logged at
//! `warn` level (`target = "events::grpc"`) and the stream continues.
//! Sinks must never panic. Per-client metrics (active subscribers,
//! cumulative lag, dropped count) are deferred to a follow-up.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use async_trait::async_trait;
use node::events::{EventSink, NodeEvent, NodeEventBody};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, watch};
use tokio_stream::Stream;
use tokio_stream::wrappers::{BroadcastStream, TcpListenerStream};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info, warn};

use crate::proto::v1 as pb;
use crate::proto::v1::node_event_stream_server::{
    NodeEventStream, NodeEventStreamServer,
};

/// gRPC adapter errors surfaced at sink construction time.
#[derive(Debug, thiserror::Error)]
pub enum GrpcEventSinkError {
    #[error("invalid bind address '{0}': {1}")]
    InvalidBind(String, std::net::AddrParseError),
    #[error(
        "refusing to bind events gRPC server on non-loopback address {0}: \
         the server is unauthenticated and unencrypted; pass \
         --events-grpc-allow-remote to override after putting it behind a \
         firewall or auth proxy"
    )]
    RemoteBindRejected(SocketAddr),
    #[error("failed to bind {0}: {1}")]
    BindFailed(SocketAddr, std::io::Error),
}

/// gRPC streaming sink. Construct via [`GrpcEventSink::bind`] (async,
/// pre-binds the TCP listener so failure is reported synchronously at
/// startup), then hand it to
/// [`node::events::EventPublisher::attach_sinks`] which spawns the
/// `run` future as a tokio task.
pub struct GrpcEventSink {
    addr: SocketAddr,
    listener: TcpListener,
    publisher: std::sync::Arc<node::events::EventPublisher>,
}

impl GrpcEventSink {
    /// Build a new sink and **bind** the TCP listener immediately, so
    /// any bind failure is reported at startup before the daemon
    /// declares readiness.
    ///
    /// The server is unauthenticated and unencrypted. By default, only
    /// loopback bindings are accepted; pass `allow_remote = true` to
    /// bind a routable address (which the operator should put behind
    /// a firewall, mTLS terminator, or auth proxy).
    ///
    /// The `publisher` handle is needed so each incoming subscriber can
    /// register its own broadcast receiver — sharing the
    /// [`EventSink::run`] receiver across N clients would force each
    /// client to serialize through a single channel.
    pub async fn bind(
        bind: &str,
        allow_remote: bool,
        publisher: std::sync::Arc<node::events::EventPublisher>,
    ) -> Result<Self, GrpcEventSinkError> {
        let addr: SocketAddr = bind
            .parse()
            .map_err(|e| GrpcEventSinkError::InvalidBind(bind.to_string(), e))?;
        if !allow_remote && !is_loopback(&addr.ip()) {
            return Err(GrpcEventSinkError::RemoteBindRejected(addr));
        }
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| GrpcEventSinkError::BindFailed(addr, e))?;
        let bound = listener.local_addr().unwrap_or(addr);
        info!(
            target: "events::grpc",
            addr = %bound,
            allow_remote,
            "events gRPC server bound",
        );
        Ok(Self {
            addr: bound,
            listener,
            publisher,
        })
    }

    /// Address the listener is bound on. Test helper / observability
    /// hook — production callers don't need this.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

#[async_trait]
impl EventSink for GrpcEventSink {
    fn name(&self) -> &'static str {
        "grpc"
    }

    async fn run(
        self: Box<Self>,
        // The "primary" receiver passed by the publisher is unused here:
        // each gRPC client gets its own subscription via `publisher.subscribe()`
        // inside the streaming RPC handler. We drop it immediately so the
        // publisher's broadcast doesn't accumulate buffered events for an
        // unread receiver.
        _events: broadcast::Receiver<NodeEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let svc = NodeEventStreamServer::new(NodeEventStreamSvc {
            publisher: self.publisher.clone(),
        });
        info!(target: "events::grpc", addr = %self.addr, "events gRPC server starting");
        let shutdown_signal = async move {
            let _ = shutdown.changed().await;
        };
        // The TCP listener was already bound in `bind()` (so any
        // operator-visible bind failure happens at startup, not here).
        // Hand it to tonic via `serve_with_incoming_shutdown`.
        let incoming = TcpListenerStream::new(self.listener);
        if let Err(e) = Server::builder()
            .add_service(svc)
            .serve_with_incoming_shutdown(incoming, shutdown_signal)
            .await
        {
            warn!(target: "events::grpc", error = %e, "events gRPC server exited with error");
        }
    }
}

struct NodeEventStreamSvc {
    publisher: std::sync::Arc<node::events::EventPublisher>,
}

#[async_trait]
impl NodeEventStream for NodeEventStreamSvc {
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<pb::NodeEvent, Status>> + Send + 'static>>;

    async fn subscribe(
        &self,
        request: Request<pb::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let req = request.into_inner();
        // 0 means "all categories" — same convention as the in-process
        // `EventSink`. Otherwise it's a bitfield (mempool=1, chain=2,
        // heartbeat=4). Unknown bits are silently ignored: a future
        // server may add new categories without forcing older clients
        // to upgrade. We could `return Err(invalid_argument)` if the
        // mask covers no known bit, but that would also reject the
        // legitimate "subscribe to a category my server doesn't know
        // about yet" case during a rolling upgrade — easier to log
        // and let the stream be empty.
        let category_mask = if req.categories == 0 {
            u32::MAX
        } else {
            req.categories
        };
        let since_seq = req.since_seq.unwrap_or(0);

        // `since_seq` is a forward-only filter, NOT a replay hint. We
        // create a fresh broadcast::Receiver here, which only sees
        // events emitted strictly after this point — there is no
        // history rewind. We then drop everything with seq <= since_seq
        // before sending, so a client that briefly disconnects can
        // suppress already-seen duplicates if its old `seq` is still
        // close to the current one. Anything older has already passed
        // the publisher's broadcast window and cannot be recovered
        // through this RPC; clients needing durable replay should
        // consume from a broker upstream of this sink.
        let rx = self.publisher.subscribe();
        debug!(
            target: "events::grpc",
            categories = req.categories,
            since_seq,
            "events gRPC subscriber attached (forward-only; no replay)",
        );

        let stream = BroadcastStream::new(rx).filter_map(move |item| match item {
            Ok(env) => {
                if (env.category_bit() & category_mask) == 0 {
                    return None;
                }
                if since_seq > 0 && env.stamp.seq <= since_seq {
                    return None;
                }
                Some(Ok(envelope_to_proto(&env)))
            }
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                warn!(target: "events::grpc", dropped = n, "gRPC subscriber lagged");
                None
            }
        });

        Ok(Response::new(Box::pin(stream)))
    }
}

/// Discard `Streaming` from the request, leaving only the unary message
/// — silences an unused-import warning when tonic generates client code.
#[allow(dead_code)]
fn _streaming_marker(_: Streaming<()>) {}

// `tokio_stream::Stream` provides `filter_map`; pull it into scope.
use tokio_stream::StreamExt as _;

fn envelope_to_proto(env: &NodeEvent) -> pb::NodeEvent {
    pb::NodeEvent {
        schema_version: env.schema_version,
        stamp: Some(stamp_to_proto(&env.stamp)),
        body: Some(body_to_proto(&env.body)),
    }
}

fn stamp_to_proto(stamp: &node::events::EdgeStamp) -> pb::EdgeStamp {
    pb::EdgeStamp {
        node_id: stamp.node_id.to_vec(),
        region: region_to_string(stamp.region.as_ref()),
        edge_seen_at_ns: stamp.edge_seen_at_ns,
        edge_wall_ns: stamp.edge_wall_ns,
        seq: stamp.seq,
    }
}

fn region_to_string(region: Option<&[u8; 8]>) -> String {
    match region {
        None => String::new(),
        Some(raw) => {
            let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            std::str::from_utf8(&raw[..end])
                .unwrap_or("")
                .to_string()
        }
    }
}

fn body_to_proto(body: &NodeEventBody) -> pb::node_event::Body {
    use pb::node_event::Body;
    match body {
        NodeEventBody::Mempool(mp) => Body::Mempool(mempool_event_to_proto(mp)),
        NodeEventBody::Chain(ch) => Body::Chain(chain_event_to_proto(ch)),
        NodeEventBody::Heartbeat { uptime_ns } => Body::Heartbeat(pb::Heartbeat {
            uptime_ns: *uptime_ns,
        }),
    }
}

fn mempool_event_to_proto(ev: &node::mempool::events::MempoolEvent) -> pb::MempoolEvent {
    use bitcoin::hashes::Hash;
    use node::mempool::events::{EvictReason as RustReason, MempoolEvent as Mp};
    use pb::mempool_event::Body as MpBody;

    let body = match ev {
        Mp::Enter {
            txid,
            fee,
            vsize,
            fee_rate_sat_per_kvb,
            time,
        } => MpBody::Enter(pb::MempoolEnter {
            txid: txid.as_raw_hash().to_byte_array().to_vec(),
            fee: *fee,
            vsize: *vsize,
            fee_rate_sat_per_kvb: *fee_rate_sat_per_kvb,
            time: *time,
        }),
        Mp::LeaveConfirmed {
            txid,
            block_hash,
            height,
        } => MpBody::LeaveConfirmed(pb::MempoolLeaveConfirmed {
            txid: txid.as_raw_hash().to_byte_array().to_vec(),
            block_hash: block_hash.as_raw_hash().to_byte_array().to_vec(),
            height: *height,
        }),
        Mp::LeaveEvicted { txid, reason } => MpBody::LeaveEvicted(pb::MempoolLeaveEvicted {
            txid: txid.as_raw_hash().to_byte_array().to_vec(),
            reason: match reason {
                RustReason::FullPool => pb::EvictReason::FullPool as i32,
                RustReason::Expiry => pb::EvictReason::Expiry as i32,
                RustReason::BlockConflict => pb::EvictReason::BlockConflict as i32,
            },
        }),
        Mp::LeaveReplaced {
            txid,
            replacing_txid,
        } => MpBody::LeaveReplaced(pb::MempoolLeaveReplaced {
            txid: txid.as_raw_hash().to_byte_array().to_vec(),
            replacing_txid: replacing_txid.as_raw_hash().to_byte_array().to_vec(),
        }),
    };
    pb::MempoolEvent { body: Some(body) }
}

fn chain_event_to_proto(ev: &node::chain::events::ChainEvent) -> pb::ChainEvent {
    use bitcoin::hashes::Hash;
    use node::chain::events::ChainEvent as Ch;
    use pb::chain_event::Body as ChBody;
    let body = match ev {
        Ch::BlockConnected { hash, height } => ChBody::BlockConnected(pb::BlockConnected {
            hash: hash.as_raw_hash().to_byte_array().to_vec(),
            height: *height,
        }),
        Ch::BlockDisconnected { hash, height } => {
            ChBody::BlockDisconnected(pb::BlockDisconnected {
                hash: hash.as_raw_hash().to_byte_array().to_vec(),
                height: *height,
            })
        }
    };
    pb::ChainEvent { body: Some(body) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, Txid};
    use node::chain::events::ChainEvent;
    use node::events::{EdgeIdentity, EventPublisher};
    use node::mempool::events::{EvictReason, MempoolEvent};
    use std::time::Duration;

    fn edge() -> EdgeIdentity {
        EdgeIdentity::new([0x42; 16], Some("us-east1")).unwrap()
    }

    fn enter(byte: u8) -> MempoolEvent {
        MempoolEvent::Enter {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [byte; 32],
            )),
            fee: 100,
            vsize: 250,
            fee_rate_sat_per_kvb: 400,
            time: 1_700_000_000,
        }
    }

    #[test]
    fn convert_mempool_enter_round_trip() {
        let ev = enter(7);
        let pb = mempool_event_to_proto(&ev);
        let body = pb.body.unwrap();
        match body {
            pb::mempool_event::Body::Enter(e) => {
                assert_eq!(e.fee, 100);
                assert_eq!(e.txid.len(), 32);
                assert_eq!(e.txid[0], 7);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn convert_evict_reason_maps_correctly() {
        for (rust, expected) in [
            (EvictReason::FullPool, pb::EvictReason::FullPool),
            (EvictReason::Expiry, pb::EvictReason::Expiry),
            (EvictReason::BlockConflict, pb::EvictReason::BlockConflict),
        ] {
            let ev = MempoolEvent::LeaveEvicted {
                txid: Txid::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]),
                ),
                reason: rust,
            };
            let pb_ev = mempool_event_to_proto(&ev);
            match pb_ev.body.unwrap() {
                pb::mempool_event::Body::LeaveEvicted(e) => {
                    assert_eq!(e.reason, expected as i32);
                }
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn convert_block_connected_includes_hash_and_height() {
        let ev = ChainEvent::BlockConnected {
            hash: BlockHash::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]),
            ),
            height: 42,
        };
        let pb_ev = chain_event_to_proto(&ev);
        match pb_ev.body.unwrap() {
            pb::chain_event::Body::BlockConnected(b) => {
                assert_eq!(b.height, 42);
                assert_eq!(b.hash[0], 0xaa);
                assert_eq!(b.hash.len(), 32);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn bind_rejects_remote_address_by_default() {
        let publisher = EventPublisher::new(edge(), 16);
        match GrpcEventSink::bind("0.0.0.0:0", false, publisher).await {
            Err(GrpcEventSinkError::RemoteBindRejected(_)) => {}
            Ok(_) => panic!("non-loopback bind without allow_remote should fail"),
            Err(e) => panic!("expected RemoteBindRejected, got {e}"),
        }
    }

    #[tokio::test]
    async fn bind_allows_loopback_without_override() {
        let publisher = EventPublisher::new(edge(), 16);
        let sink = GrpcEventSink::bind("127.0.0.1:0", false, publisher)
            .await
            .expect("loopback bind should succeed");
        let addr = sink.local_addr().expect("local_addr");
        assert!(addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn bind_allows_remote_with_allow_flag() {
        let publisher = EventPublisher::new(edge(), 16);
        // 0.0.0.0:0 with allow_remote = true: must succeed (the actual
        // port the OS picks is irrelevant; the test asserts only that
        // the loopback gate is bypassed when the caller opts in).
        let sink = GrpcEventSink::bind("0.0.0.0:0", true, publisher)
            .await
            .expect("explicit remote bind should be allowed");
        let addr = sink.local_addr().unwrap();
        assert!(!addr.ip().is_loopback());
    }

    #[test]
    fn region_serialization_trims_padding() {
        let stamp = node::events::EdgeStamp {
            node_id: [1; 16],
            region: Some(*b"eu-w\0\0\0\0"),
            edge_seen_at_ns: 0,
            edge_wall_ns: 0,
            seq: 1,
        };
        let pb_stamp = stamp_to_proto(&stamp);
        assert_eq!(pb_stamp.region, "eu-w");
    }

    /// End-to-end: spin up a real GrpcEventSink, connect a tonic client,
    /// inject a synthetic chain event via the publisher's bridge, assert
    /// the client receives it with the correct stamp.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_streaming_delivery() {
        // 1. Build publisher + bridges.
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx.clone());

        // 2. Bind directly (the new API picks the actual ephemeral port
        // from the OS, no TOCTOU window).
        let sink = GrpcEventSink::bind("127.0.0.1:0", false, publisher.clone())
            .await
            .expect("bind");
        let actual = sink.local_addr().unwrap();
        let sinks: Vec<Box<dyn EventSink>> = vec![Box::new(sink)];
        publisher.attach_sinks(sinks, shutdown_rx.clone());

        // 3. Wait briefly for the server to come up, then connect.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut client =
            pb::node_event_stream_client::NodeEventStreamClient::connect(format!(
                "http://{}",
                actual
            ))
            .await
            .expect("connect");

        // 4. Subscribe to all categories.
        let mut stream = client
            .subscribe(pb::SubscribeRequest {
                categories: 0,
                since_seq: None,
            })
            .await
            .expect("subscribe")
            .into_inner();

        // 5. Inject events.
        tokio::time::sleep(Duration::from_millis(50)).await;
        mp_tx.send(enter(1)).unwrap();
        ch_tx
            .send(ChainEvent::BlockConnected {
                hash: BlockHash::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([2u8; 32]),
                ),
                height: 1,
            })
            .unwrap();

        // 6. Receive both, in order.
        let env1 = tokio::time::timeout(Duration::from_secs(3), stream.message())
            .await
            .expect("timeout waiting for first event")
            .expect("transport error")
            .expect("stream ended");
        let env2 = tokio::time::timeout(Duration::from_secs(3), stream.message())
            .await
            .expect("timeout waiting for second event")
            .expect("transport error")
            .expect("stream ended");

        assert_eq!(env1.schema_version, node::events::SCHEMA_VERSION);
        let stamp1 = env1.stamp.clone().expect("env1 stamp present");
        let stamp2 = env2.stamp.clone().expect("env2 stamp present");
        assert_eq!(stamp1.node_id, [0x42u8; 16].to_vec());
        assert_eq!(stamp1.region, "us-east1");
        // The two bridge tasks publish concurrently; seq ordering between
        // them is non-deterministic, but each is assigned exactly once
        // and they are unique.
        let mut seqs = [stamp1.seq, stamp2.seq];
        seqs.sort();
        assert_eq!(seqs, [1, 2]);

        // We received one mempool body and one chain body, in some order.
        let bodies: Vec<_> = [&env1, &env2].iter().map(|e| e.body.clone()).collect();
        let kinds: Vec<&'static str> = bodies
            .iter()
            .map(|b| match b.as_ref().expect("body present") {
                pb::node_event::Body::Mempool(_) => "mempool",
                pb::node_event::Body::Chain(_) => "chain",
                pb::node_event::Body::Heartbeat(_) => "heartbeat",
            })
            .collect();
        assert!(
            kinds.contains(&"mempool") && kinds.contains(&"chain"),
            "expected one mempool + one chain body, got {kinds:?}",
        );

        // 7. Shutdown.
        let _ = shutdown_tx.send(true);
    }
}
