//! ZMQ PUB-socket adapter for the satd events bus.
//!
//! Designed for two complementary use cases:
//!
//! 1. **Bitcoin Core compatibility.** The `hashtx` and `hashblock`
//!    topics emit the **reversed** 32-byte hash (RPC display order)
//!    followed by a little-endian u32 sequence — the same wire format
//!    Bitcoin Core's `-zmqpubhashtx` / `-zmqpubhashblock` produce.
//!    Existing Core tooling (block-explorer indexers, watchtower
//!    scripts) connects unchanged.
//!
//! 2. **Native consumers.** New topics (`mpevict`, `mpreplace`,
//!    `mpconfirm`, `nodeevent`) emit JSON payloads that include the
//!    full envelope or per-event metadata that Core does not provide.
//!
//! All topics are multiplexed onto a single PUB socket. Subscribers
//! filter via standard ZMQ topic prefixes.
//!
//! Wire format (matches Bitcoin Core's `zmqpub*` exactly for the compat
//! topics):
//! - Frame 0: ASCII topic name (e.g. `b"hashtx"`).
//! - Frame 1: payload bytes — for `hashtx` / `hashblock`, the 32-byte
//!   hash in **RPC display order** (reverse of internal byte order).
//!   For new topics, JSON.
//! - Frame 2: per-topic monotonic sequence as little-endian `u32`. The
//!   first message on each topic carries seq `0`; the counter wraps
//!   modulo 2^32. (Core publishes the *current* counter value and
//!   increments after send, so seq starts at 0; we replicate that.)
//!
//! Backpressure: the underlying `zeromq` PUB socket discards messages
//! to subscribers whose receive queue is full (standard PUB/SUB
//! behavior). The current adapter does NOT expose a high-water-mark
//! knob; satd cannot observe per-subscriber drops. Local lag from the
//! in-process broadcast (`RecvError::Lagged`) is logged. Future work:
//! HWM configuration plus per-topic sent/dropped counters.

use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use bitcoin::hashes::Hash;
use node::events::{EventSink, NodeEvent, NodeEventBody};
use node::mempool::events::MempoolEvent;
use node::chain::events::ChainEvent;
use tokio::sync::{broadcast, watch};
use tracing::{debug, info, warn};
use zeromq::{Socket, SocketSend, ZmqMessage};

/// Topic prefixes. Stable wire identifiers — operators configure
/// subscribers via these strings, so don't rename them without bumping
/// the schema version and documenting the migration.
pub mod topics {
    /// Core-compatible. Payload = 32-byte txid in **RPC display order**
    /// (the internal byte order reversed — same on-the-wire shape as
    /// Bitcoin Core's `-zmqpubhashtx`). Seq tag = u32 LE.
    pub const HASHTX: &str = "hashtx";
    /// Core-compatible. Payload = 32-byte block hash in **RPC display
    /// order** (the internal byte order reversed — same on-the-wire
    /// shape as Bitcoin Core's `-zmqpubhashblock`). Seq tag = u32 LE.
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

/// Reverse a 32-byte hash from internal byte order to Bitcoin Core's
/// RPC/display order. Used for the Core-compatible `hashtx` and
/// `hashblock` topics so existing Core ZMQ tooling sees identical
/// frames.
fn reverse_32(bytes: [u8; 32]) -> [u8; 32] {
    let mut out = bytes;
    out.reverse();
    out
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

/// PUB-socket events sink. Built and **bound** via
/// [`ZmqEventSink::bind`], then handed to
/// [`node::events::EventPublisher::attach_sinks`].
pub struct ZmqEventSink {
    endpoint: String,
    socket: zeromq::PubSocket,
    topics: ZmqTopicConfig,
}

impl ZmqEventSink {
    /// Build a new sink and bind the PUB socket immediately. Any bind
    /// failure surfaces here at startup, before the daemon declares
    /// readiness — operators get a clear error rather than a silently
    /// dead sink.
    ///
    /// `endpoint` is a ZMQ transport string (`tcp://host:port`,
    /// `ipc:///path`, etc.). `topics` controls which per-topic frames
    /// the sink emits.
    pub async fn bind(
        endpoint: impl Into<String>,
        topics: ZmqTopicConfig,
    ) -> Result<Self, ZmqEventSinkError> {
        let endpoint = endpoint.into();
        let mut socket = zeromq::PubSocket::new();
        socket
            .bind(&endpoint)
            .await
            .map_err(|e| ZmqEventSinkError::Bind(endpoint.clone(), e.to_string()))?;
        Ok(Self {
            endpoint,
            socket,
            topics,
        })
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
        let Self {
            endpoint,
            mut socket,
            topics,
        } = *self;
        info!(target: "events::zmq", bind = %endpoint, "events ZMQ sink running");

        let counters = TopicCounters::default();

        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                res = events.recv() => match res {
                    Ok(env) => {
                        if let Err(e) = publish(&mut socket, &env, &topics, &counters).await {
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
    /// Match Bitcoin Core: publish the *current* counter value, then
    /// increment for next time. First message on each topic carries
    /// `seq = 0`; counter wraps modulo 2^32. `fetch_add(1)` returns the
    /// pre-increment value, which is exactly what Core writes on the
    /// wire.
    fn next(&self, counter: &AtomicU32) -> u32 {
        counter.fetch_add(1, Ordering::Relaxed)
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
        match serde_json::to_vec(env) {
            Ok(payload) => {
                let seq = counters.next(&counters.nodeevent);
                send(socket, topics::NODEEVENT, payload, seq).await?;
            }
            Err(e) => {
                warn!(
                    target: "events::zmq",
                    topic = topics::NODEEVENT,
                    error = %e,
                    "skipping nodeevent frame: serialization failed",
                );
            }
        }
    }

    // Per-event-type topics.
    match &env.body {
        NodeEventBody::Mempool(MempoolEvent::Enter { txid, .. }) => {
            if ZmqTopicConfig::enabled(topics.hashtx) {
                // Core wire format: 32-byte hash in RPC display order
                // (reverse of internal byte order).
                let payload = reverse_32(txid.as_raw_hash().to_byte_array()).to_vec();
                let seq = counters.next(&counters.hashtx);
                send(socket, topics::HASHTX, payload, seq).await?;
            }
        }
        NodeEventBody::Mempool(ev @ MempoolEvent::LeaveEvicted { .. }) => {
            if ZmqTopicConfig::enabled(topics.mpevict) {
                publish_json(socket, topics::MPEVICT, ev, &counters.mpevict, counters)
                    .await?;
            }
        }
        NodeEventBody::Mempool(ev @ MempoolEvent::LeaveReplaced { .. }) => {
            if ZmqTopicConfig::enabled(topics.mpreplace) {
                publish_json(
                    socket,
                    topics::MPREPLACE,
                    ev,
                    &counters.mpreplace,
                    counters,
                )
                .await?;
            }
        }
        NodeEventBody::Mempool(ev @ MempoolEvent::LeaveConfirmed { .. }) => {
            if ZmqTopicConfig::enabled(topics.mpconfirm) {
                publish_json(
                    socket,
                    topics::MPCONFIRM,
                    ev,
                    &counters.mpconfirm,
                    counters,
                )
                .await?;
            }
        }
        NodeEventBody::Chain(ChainEvent::BlockConnected { hash, .. }) => {
            if ZmqTopicConfig::enabled(topics.hashblock) {
                // Core wire format: 32-byte hash in RPC display order.
                let payload = reverse_32(hash.as_raw_hash().to_byte_array()).to_vec();
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

async fn publish_json<T: serde::Serialize>(
    socket: &mut zeromq::PubSocket,
    topic: &'static str,
    payload: &T,
    counter: &AtomicU32,
    counters: &TopicCounters,
) -> Result<(), zeromq::ZmqError> {
    match serde_json::to_vec(payload) {
        Ok(bytes) => {
            let seq = counters.next(counter);
            send(socket, topic, bytes, seq).await
        }
        Err(e) => {
            warn!(
                target: "events::zmq",
                topic,
                error = %e,
                "skipping frame: serialization failed",
            );
            Ok(())
        }
    }
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

    /// 32-byte non-palindromic pattern: each byte is its 1-based index.
    /// `[0x01, 0x02, ..., 0x20]`. Reversing yields `[0x20, 0x1f, ..., 0x01]`
    /// — so a wire-format check that asserts `frames[1][0] == 0x20`
    /// catches both "no reversal" and "wrong reversal" mistakes.
    fn ramped_bytes() -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = (i as u8) + 1;
        }
        b
    }

    fn enter_event_with_hash(bytes: [u8; 32]) -> MempoolEvent {
        MempoolEvent::Enter {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                bytes,
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

    /// Build, bind, and attach a sink with the given topic config.
    /// Returns the publisher senders for direct event injection.
    async fn spin_up_sink(
        endpoint: String,
        topics: ZmqTopicConfig,
        publisher: std::sync::Arc<EventPublisher>,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        let sink = ZmqEventSink::bind(endpoint, topics).await.expect("bind");
        publisher.attach_sinks(
            vec![Box::new(sink) as Box<dyn EventSink>],
            shutdown_rx,
        );
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
        spin_up_sink(
            endpoint.clone(),
            ZmqTopicConfig::default(),
            publisher.clone(),
            shutdown_rx.clone(),
        )
        .await;

        let mut sub = SubSocket::new();
        sub.connect(&endpoint).await.expect("sub connect");
        sub.subscribe(topics::HASHTX).await.expect("subscribe");
        // SUB joins are racy; give the cluster a moment to propagate.
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Inject an Enter event with a non-palindromic 32-byte hash so
        // the test catches "no reversal" and "wrong reversal" mistakes.
        let raw = ramped_bytes();
        mp_tx.send(enter_event_with_hash(raw)).unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(3), sub.recv())
            .await
            .expect("timed out waiting for hashtx")
            .expect("recv");
        let frames: Vec<_> = msg.into_vec().into_iter().map(|b| b.to_vec()).collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0], topics::HASHTX.as_bytes());
        assert_eq!(frames[1].len(), 32);
        // Core wire = reversed (RPC display) order. raw is [01..20];
        // reversed is [20..01], so the first byte must be 0x20.
        let mut expected = raw;
        expected.reverse();
        assert_eq!(
            frames[1].as_slice(),
            &expected[..],
            "hashtx payload must be reversed (Bitcoin Core RPC display order)",
        );
        assert_eq!(frames[2].len(), 4);
        // First seq on a topic is 0 (Core publishes pre-increment).
        let seq = u32::from_le_bytes(frames[2].as_slice().try_into().unwrap());
        assert_eq!(seq, 0, "first hashtx seq must be 0 (Core convention)");

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hashtx_seq_increments_per_message() {
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
        spin_up_sink(
            endpoint.clone(),
            ZmqTopicConfig::default(),
            publisher.clone(),
            shutdown_rx.clone(),
        )
        .await;

        let mut sub = SubSocket::new();
        sub.connect(&endpoint).await.expect("sub connect");
        sub.subscribe(topics::HASHTX).await.expect("subscribe");
        tokio::time::sleep(Duration::from_millis(150)).await;

        for i in 1..=3u8 {
            mp_tx.send(enter_event(i)).unwrap();
        }

        let mut seqs = Vec::new();
        for _ in 0..3 {
            let msg = tokio::time::timeout(Duration::from_secs(3), sub.recv())
                .await
                .expect("recv timeout")
                .expect("recv");
            let frames: Vec<_> = msg.into_vec().into_iter().map(|b| b.to_vec()).collect();
            seqs.push(u32::from_le_bytes(
                frames[2].as_slice().try_into().unwrap(),
            ));
        }
        assert_eq!(seqs, vec![0u32, 1, 2]);

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hashblock_frame_emits_reversed_hash_on_block_connect() {
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
        spin_up_sink(
            endpoint.clone(),
            ZmqTopicConfig::default(),
            publisher.clone(),
            shutdown_rx.clone(),
        )
        .await;

        let mut sub = SubSocket::new();
        sub.connect(&endpoint).await.expect("sub connect");
        sub.subscribe(topics::HASHBLOCK).await.expect("subscribe");
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Non-palindromic ramp so byte-order regressions are visible.
        let raw = ramped_bytes();
        ch_tx
            .send(ChainEvent::BlockConnected {
                hash: BlockHash::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_byte_array(raw),
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
        let mut expected = raw;
        expected.reverse();
        assert_eq!(
            frames[1].as_slice(),
            &expected[..],
            "hashblock payload must be reversed (Bitcoin Core RPC display order)",
        );
        assert_eq!(frames[1].len(), 32);
        let seq = u32::from_le_bytes(frames[2].as_slice().try_into().unwrap());
        assert_eq!(seq, 0, "first hashblock seq must be 0 (Core convention)");

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
        spin_up_sink(
            endpoint.clone(),
            ZmqTopicConfig::default(),
            publisher.clone(),
            shutdown_rx.clone(),
        )
        .await;

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
        spin_up_sink(
            endpoint.clone(),
            ZmqTopicConfig::default(),
            publisher.clone(),
            shutdown_rx.clone(),
        )
        .await;

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
        // EdgeStamp serializes node_id as 32-char hex, region as
        // trimmed string. (Custom Serialize impl, fixed in PR-1
        // review fixes.)
        let stamp = &parsed["stamp"];
        let node_hex = stamp["node_id"].as_str().expect("node_id is a string");
        assert_eq!(node_hex.len(), 32);
        assert!(node_hex.chars().all(|c| c.is_ascii_hexdigit()));
        // edge() in this test sets region=None.
        assert!(stamp["region"].is_null());

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
        spin_up_sink(
            endpoint.clone(),
            ZmqTopicConfig {
                hashtx: Some(false),
                ..ZmqTopicConfig::default()
            },
            publisher.clone(),
            shutdown_rx.clone(),
        )
        .await;

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
