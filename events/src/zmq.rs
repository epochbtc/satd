//! ZMQ PUB-socket adapter for the satd events bus.
//!
//! Designed for two complementary use cases:
//!
//! 1. **Bitcoin Core compatibility.** The `hashtx` and `hashblock`
//!    topics emit raw 32-byte hashes followed by a little-endian u32
//!    sequence — the same wire format Bitcoin Core's
//!    `-zmqpubhashtx` / `-zmqpubhashblock` produce. Existing Core
//!    tooling (block-explorer indexers, watchtower scripts) connects
//!    unchanged.
//!
//! 2. **Native consumers.** New topics (`mpevict`, `mpreplace`,
//!    `mpconfirm`, `nodeevent`) emit JSON payloads that include the
//!    full envelope or per-event metadata that Core does not provide.
//!
//! All topics are multiplexed onto a single PUB socket. Subscribers
//! filter via standard ZMQ topic prefixes.
//!
//! Sequence semantics: Bitcoin Core assigns a per-topic LE u32 counter
//! that wraps modulo 2^32. We do the same so the wire is byte-identical
//! to Core for the compat topics. Lag handling matches the in-process
//! sink contract — `RecvError::Lagged` is logged and the loop continues.

use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use bitcoin::hashes::Hash;
use node::events::{EventSink, NodeEvent, NodeEventBody};
use node::mempool::events::MempoolEvent;
use node::chain::events::ChainEvent;
use tokio::sync::{broadcast, watch};
use tracing::{debug, error, info, warn};
use zeromq::{Socket, SocketSend, ZmqMessage};

/// Topic prefixes. Stable wire identifiers — operators configure
/// subscribers via these strings, so don't rename them without bumping
/// the schema version and documenting the migration.
pub mod topics {
    /// Core-compatible. Payload = 32-byte raw txid. Seq tag = u32 LE.
    pub const HASHTX: &str = "hashtx";
    /// Core-compatible. Payload = 32-byte raw block hash. Seq tag = u32 LE.
    pub const HASHBLOCK: &str = "hashblock";
    /// New. Payload = JSON-serialized `MempoolEvent::LeaveEvicted` body
    /// (txid + reason). Seq tag = u32 LE.
    pub const MPEVICT: &str = "mpevict";
    /// New. Payload = JSON-serialized `MempoolEvent::LeaveReplaced`
    /// body (txid + replacing_txid). Seq tag = u32 LE.
    pub const MPREPLACE: &str = "mpreplace";
    /// New. Payload = JSON-serialized `MempoolEvent::LeaveConfirmed`
    /// body (txid + block_hash + height). Seq tag = u32 LE.
    pub const MPCONFIRM: &str = "mpconfirm";
    /// New, catch-all. Payload = JSON-serialized full `NodeEvent`
    /// envelope. Seq tag = u32 LE.
    pub const NODEEVENT: &str = "nodeevent";
}

/// Operator-facing ZMQ adapter errors.
#[derive(Debug, thiserror::Error)]
pub enum ZmqEventSinkError {
    #[error("ZMQ bind failed for '{0}': {1}")]
    Bind(String, String),
}

/// Per-topic enable flags. `None` = sink defaults (all enabled).
#[derive(Debug, Clone, Default)]
pub struct ZmqTopicConfig {
    pub hashtx: Option<bool>,
    pub hashblock: Option<bool>,
    pub mpevict: Option<bool>,
    pub mpreplace: Option<bool>,
    pub mpconfirm: Option<bool>,
    pub nodeevent: Option<bool>,
}

impl ZmqTopicConfig {
    fn enabled(opt: Option<bool>) -> bool {
        opt.unwrap_or(true)
    }
}

/// PUB-socket events sink. Built once and handed to
/// [`node::events::EventPublisher::attach_sinks`].
pub struct ZmqEventSink {
    bind: String,
    topics: ZmqTopicConfig,
}

impl ZmqEventSink {
    /// Construct a new sink. `bind` is a ZMQ endpoint string
    /// (e.g. `tcp://0.0.0.0:28332`). The socket is not bound yet —
    /// binding happens inside [`EventSink::run`] so any failure is
    /// reported once the daemon's tokio runtime is up.
    pub fn new(bind: impl Into<String>, topics: ZmqTopicConfig) -> Self {
        Self {
            bind: bind.into(),
            topics,
        }
    }
}

#[async_trait]
impl EventSink for ZmqEventSink {
    fn name(&self) -> &'static str {
        "zmq"
    }

    async fn run(
        self: Box<Self>,
        mut events: broadcast::Receiver<NodeEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut socket = zeromq::PubSocket::new();
        if let Err(e) = socket.bind(&self.bind).await {
            error!(
                target: "events::zmq",
                bind = %self.bind,
                error = %e,
                "events ZMQ sink failed to bind",
            );
            return;
        }
        info!(target: "events::zmq", bind = %self.bind, "events ZMQ sink bound");

        let counters = TopicCounters::default();

        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                res = events.recv() => match res {
                    Ok(env) => {
                        if let Err(e) = publish(&mut socket, &env, &self.topics, &counters).await {
                            warn!(target: "events::zmq", error = %e, "events ZMQ publish failed");
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(target: "events::zmq", dropped = n, "ZMQ sink lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            }
        }
        debug!(target: "events::zmq", "events ZMQ sink shutting down");
    }
}

#[derive(Default)]
struct TopicCounters {
    hashtx: AtomicU32,
    hashblock: AtomicU32,
    mpevict: AtomicU32,
    mpreplace: AtomicU32,
    mpconfirm: AtomicU32,
    nodeevent: AtomicU32,
}

impl TopicCounters {
    fn next(&self, counter: &AtomicU32) -> u32 {
        // Match Bitcoin Core: the published seq is the value AFTER
        // increment-modulo-2^32, starting at 1 for the first message.
        // `fetch_add` returns the previous value; we publish that+1.
        counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
    }
}

async fn publish(
    socket: &mut zeromq::PubSocket,
    env: &NodeEvent,
    topics: &ZmqTopicConfig,
    counters: &TopicCounters,
) -> Result<(), zeromq::ZmqError> {
    // Catch-all envelope topic (always emitted unless disabled).
    if ZmqTopicConfig::enabled(topics.nodeevent) {
        let payload = serde_json::to_vec(env).unwrap_or_default();
        let seq = counters.next(&counters.nodeevent);
        send(socket, topics::NODEEVENT, payload, seq).await?;
    }

    // Per-event-type topics.
    match &env.body {
        NodeEventBody::Mempool(MempoolEvent::Enter { txid, .. }) => {
            if ZmqTopicConfig::enabled(topics.hashtx) {
                let payload = txid.as_raw_hash().to_byte_array().to_vec();
                let seq = counters.next(&counters.hashtx);
                send(socket, topics::HASHTX, payload, seq).await?;
            }
        }
        NodeEventBody::Mempool(ev @ MempoolEvent::LeaveEvicted { .. }) => {
            if ZmqTopicConfig::enabled(topics.mpevict) {
                let payload = serde_json::to_vec(ev).unwrap_or_default();
                let seq = counters.next(&counters.mpevict);
                send(socket, topics::MPEVICT, payload, seq).await?;
            }
        }
        NodeEventBody::Mempool(ev @ MempoolEvent::LeaveReplaced { .. }) => {
            if ZmqTopicConfig::enabled(topics.mpreplace) {
                let payload = serde_json::to_vec(ev).unwrap_or_default();
                let seq = counters.next(&counters.mpreplace);
                send(socket, topics::MPREPLACE, payload, seq).await?;
            }
        }
        NodeEventBody::Mempool(ev @ MempoolEvent::LeaveConfirmed { .. }) => {
            if ZmqTopicConfig::enabled(topics.mpconfirm) {
                let payload = serde_json::to_vec(ev).unwrap_or_default();
                let seq = counters.next(&counters.mpconfirm);
                send(socket, topics::MPCONFIRM, payload, seq).await?;
            }
        }
        NodeEventBody::Chain(ChainEvent::BlockConnected { hash, .. }) => {
            if ZmqTopicConfig::enabled(topics.hashblock) {
                let payload = hash.as_raw_hash().to_byte_array().to_vec();
                let seq = counters.next(&counters.hashblock);
                send(socket, topics::HASHBLOCK, payload, seq).await?;
            }
        }
        NodeEventBody::Chain(ChainEvent::BlockDisconnected { .. }) => {
            // Bitcoin Core does not emit a hashblock for disconnect —
            // operators detect reorgs via the higher-level reorg
            // webhook or by observing block-height regressions in
            // their indexer. The full envelope is still available on
            // `nodeevent` if the consumer needs it.
        }
        NodeEventBody::Heartbeat { .. } => {
            // Heartbeats only flow through `nodeevent`. The Core-compat
            // topics deliberately ignore them.
        }
    }
    Ok(())
}

async fn send(
    socket: &mut zeromq::PubSocket,
    topic: &str,
    payload: Vec<u8>,
    seq: u32,
) -> Result<(), zeromq::ZmqError> {
    // Three-frame multipart wire format matching Bitcoin Core:
    //   frame 0 = topic bytes
    //   frame 1 = payload
    //   frame 2 = u32 sequence (little-endian)
    let mut msg = ZmqMessage::from(topic.as_bytes().to_vec());
    msg.push_back(payload.into());
    msg.push_back(seq.to_le_bytes().to_vec().into());
    socket.send(msg).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, Txid};
    use node::events::{EdgeIdentity, EventPublisher};
    use std::time::Duration;
    use zeromq::{Socket, SocketRecv as _, SubSocket};

    fn edge() -> EdgeIdentity {
        EdgeIdentity::new([0xab; 16], None).unwrap()
    }

    fn enter_event(byte: u8) -> MempoolEvent {
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

    /// Pick an ephemeral TCP port via a throwaway bind, then drop it.
    /// Tiny TOCTOU window before the ZMQ bind, but reliable on
    /// loopback for tests.
    async fn ephemeral_endpoint() -> (String, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        (format!("tcp://127.0.0.1:{port}"), port)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hashtx_frame_matches_core_wire_format() {
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        publisher.spawn_bridges(
            mp_tx.subscribe(),
            ch_tx.subscribe(),
            shutdown_rx.clone(),
        );

        let (endpoint, _port) = ephemeral_endpoint().await;
        let sink = ZmqEventSink::new(endpoint.clone(), ZmqTopicConfig::default());
        let sinks: Vec<Box<dyn EventSink>> = vec![Box::new(sink)];
        publisher.attach_sinks(sinks, shutdown_rx.clone());

        // Wait for sink to bind, then connect a SUB.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let mut sub = SubSocket::new();
        sub.connect(&endpoint).await.expect("sub connect");
        sub.subscribe(topics::HASHTX).await.expect("subscribe");
        // SUB joins are racy; give the cluster a moment to propagate.
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Inject an Enter event.
        mp_tx.send(enter_event(0xcd)).unwrap();

        // Receive (with timeout).
        let msg = tokio::time::timeout(Duration::from_secs(3), sub.recv())
            .await
            .expect("timed out waiting for hashtx")
            .expect("recv");
        let frames: Vec<_> = msg.into_vec().into_iter().map(|b| b.to_vec()).collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], topics::HASHTX.as_bytes());
        assert_eq!(frames[1].len(), 32);
        assert_eq!(frames[1][0], 0xcd);
        assert_eq!(frames[2].len(), 4);
        // First seq is 1 (Core convention).
        let seq = u32::from_le_bytes(frames[2].as_slice().try_into().unwrap());
        assert_eq!(seq, 1);

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hashblock_frame_emits_on_block_connect() {
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        publisher.spawn_bridges(
            mp_tx.subscribe(),
            ch_tx.subscribe(),
            shutdown_rx.clone(),
        );

        let (endpoint, _) = ephemeral_endpoint().await;
        let sink = ZmqEventSink::new(endpoint.clone(), ZmqTopicConfig::default());
        publisher.attach_sinks(
            vec![Box::new(sink) as Box<dyn EventSink>],
            shutdown_rx.clone(),
        );
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut sub = SubSocket::new();
        sub.connect(&endpoint).await.expect("sub connect");
        sub.subscribe(topics::HASHBLOCK).await.expect("subscribe");
        tokio::time::sleep(Duration::from_millis(150)).await;

        ch_tx
            .send(ChainEvent::BlockConnected {
                hash: BlockHash::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([0xee; 32]),
                ),
                height: 42,
            })
            .unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(3), sub.recv())
            .await
            .expect("hashblock timeout")
            .expect("recv");
        let frames: Vec<_> = msg.into_vec().into_iter().map(|b| b.to_vec()).collect();
        assert_eq!(frames[0], topics::HASHBLOCK.as_bytes());
        assert_eq!(frames[1][0], 0xee);
        assert_eq!(frames[1].len(), 32);

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mpevict_frame_carries_reason_json() {
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        publisher.spawn_bridges(
            mp_tx.subscribe(),
            ch_tx.subscribe(),
            shutdown_rx.clone(),
        );

        let (endpoint, _) = ephemeral_endpoint().await;
        let sink = ZmqEventSink::new(endpoint.clone(), ZmqTopicConfig::default());
        publisher.attach_sinks(
            vec![Box::new(sink) as Box<dyn EventSink>],
            shutdown_rx.clone(),
        );
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut sub = SubSocket::new();
        sub.connect(&endpoint).await.expect("sub connect");
        sub.subscribe(topics::MPEVICT).await.expect("subscribe");
        tokio::time::sleep(Duration::from_millis(150)).await;

        mp_tx
            .send(MempoolEvent::LeaveEvicted {
                txid: Txid::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]),
                ),
                reason: node::mempool::events::EvictReason::FullPool,
            })
            .unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(3), sub.recv())
            .await
            .expect("mpevict timeout")
            .expect("recv");
        let frames: Vec<_> = msg.into_vec().into_iter().map(|b| b.to_vec()).collect();
        assert_eq!(frames[0], topics::MPEVICT.as_bytes());
        let parsed: serde_json::Value = serde_json::from_slice(&frames[1]).unwrap();
        assert_eq!(parsed["kind"], "leave_evicted");
        assert_eq!(parsed["reason"], "full_pool");

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nodeevent_topic_carries_full_envelope() {
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        publisher.spawn_bridges(
            mp_tx.subscribe(),
            ch_tx.subscribe(),
            shutdown_rx.clone(),
        );

        let (endpoint, _) = ephemeral_endpoint().await;
        let sink = ZmqEventSink::new(endpoint.clone(), ZmqTopicConfig::default());
        publisher.attach_sinks(
            vec![Box::new(sink) as Box<dyn EventSink>],
            shutdown_rx.clone(),
        );
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut sub = SubSocket::new();
        sub.connect(&endpoint).await.expect("sub connect");
        sub.subscribe(topics::NODEEVENT).await.expect("subscribe");
        tokio::time::sleep(Duration::from_millis(150)).await;

        mp_tx.send(enter_event(0x55)).unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(3), sub.recv())
            .await
            .expect("nodeevent timeout")
            .expect("recv");
        let frames: Vec<_> = msg.into_vec().into_iter().map(|b| b.to_vec()).collect();
        assert_eq!(frames[0], topics::NODEEVENT.as_bytes());
        let parsed: serde_json::Value = serde_json::from_slice(&frames[1]).unwrap();
        assert_eq!(parsed["schema_version"], node::events::SCHEMA_VERSION);
        assert_eq!(parsed["body"]["category"], "mempool");
        assert_eq!(parsed["body"]["kind"], "enter");

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disabled_topic_is_skipped() {
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        publisher.spawn_bridges(
            mp_tx.subscribe(),
            ch_tx.subscribe(),
            shutdown_rx.clone(),
        );

        let (endpoint, _) = ephemeral_endpoint().await;
        // Disable hashtx; nodeevent stays on.
        let sink = ZmqEventSink::new(
            endpoint.clone(),
            ZmqTopicConfig {
                hashtx: Some(false),
                ..ZmqTopicConfig::default()
            },
        );
        publisher.attach_sinks(
            vec![Box::new(sink) as Box<dyn EventSink>],
            shutdown_rx.clone(),
        );
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut sub = SubSocket::new();
        sub.connect(&endpoint).await.expect("sub connect");
        sub.subscribe("").await.expect("subscribe all");
        tokio::time::sleep(Duration::from_millis(150)).await;

        mp_tx.send(enter_event(1)).unwrap();

        // We should receive only nodeevent (not hashtx).
        let msg = tokio::time::timeout(Duration::from_secs(3), sub.recv())
            .await
            .expect("recv timeout")
            .expect("recv");
        let frames: Vec<_> = msg.into_vec().into_iter().map(|b| b.to_vec()).collect();
        assert_eq!(frames[0], topics::NODEEVENT.as_bytes());

        // No second message within a short window.
        let second =
            tokio::time::timeout(Duration::from_millis(300), sub.recv()).await;
        assert!(second.is_err(), "should not receive hashtx when disabled");

        let _ = shutdown_tx.send(true);
    }
}
