//! Bitcoin Core-compatible ZMQ notifications (`-zmqpub*`).
//!
//! A compatibility projection of the event bus for software written against
//! Bitcoin Core: LND, Umbrel's Bitcoin apps, pool software and anything else
//! that subscribes to Core's `hashblock`, `hashtx`, `rawblock`, `rawtx` and
//! `sequence` topics. Each message is byte-for-byte what Core publishes:
//!
//! - frame 0: the topic;
//! - frame 1: the body — a hash in display (reversed) byte order, a
//!   transaction or block in its witness serialization, or a `sequence`
//!   record;
//! - frame 2: the notifier's message counter as a little-endian `u32`,
//!   starting at 0 and wrapping.
//!
//! Each event produces the messages Core's `CZMQNotificationInterface`
//! produces for it, in Core's order within the event:
//!
//! | Event | Messages |
//! |---|---|
//! | block connected | per transaction `hashtx`, `rawtx`; then `sequence C`; then, if the block is the new tip and the node is not in initial block download, `hashblock`, `rawblock` |
//! | block disconnected | per transaction `hashtx`, `rawtx`; then `sequence D` |
//! | mempool accept | `hashtx`, `rawtx`, `sequence A` |
//! | mempool removal other than by a block | `sequence R` |
//!
//! What it does not reproduce is Core's total order *across* events: block
//! and mempool events reach the bus on two paths, so a block's messages and
//! a mempool transaction's may interleave differently than Core would put
//! them. Within each group the order is the node's. The Operator Manual's
//! streaming chapter states the guarantee; `CORE_DIFFERENCES.md` lists every
//! deviation.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, Transaction, Txid};
use bytes::Bytes;
use node::chain::events::ChainEvent;
use node::chain::state::ChainState;
use node::events::core_zmq::{CoreZmqNotifier, CoreZmqSocketStats, CoreZmqStatus, CoreZmqTopic};
use node::events::{EventSink, NodeEvent, NodeEventBody};
use node::mempool::events::MempoolEvent;
use node::mempool::pool::Mempool;
use tokio::sync::{broadcast, watch};
use tracing::{debug, info, warn};

use crate::zmtp::ZmtpPub;

/// What the publisher reads from the chain.
pub trait CoreZmqChain: Send + Sync + 'static {
    /// A stored block, connected or recently disconnected.
    fn block(&self, hash: &BlockHash) -> Option<Block>;
    /// How many transactions a block has, from its index entry, without
    /// reading the block.
    fn tx_count(&self, hash: &BlockHash) -> Option<usize>;
    /// Whether the node is in initial block download, when Core publishes no
    /// `hashblock` / `rawblock`.
    fn in_initial_block_download(&self) -> bool;
}

impl CoreZmqChain for ChainState {
    fn block(&self, hash: &BlockHash) -> Option<Block> {
        self.get_block(hash)
    }

    fn tx_count(&self, hash: &BlockHash) -> Option<usize> {
        self.get_block_index(hash).map(|e| e.num_tx as usize).filter(|n| *n > 0)
    }

    fn in_initial_block_download(&self) -> bool {
        self.is_initial_block_download()
    }
}

/// What the publisher reads from the mempool: an admitted transaction whose
/// event did not carry it.
pub trait CoreZmqMempool: Send + Sync + 'static {
    fn transaction(&self, txid: &Txid) -> Option<Transaction>;
}

impl CoreZmqMempool for Mempool {
    fn transaction(&self, txid: &Txid) -> Option<Transaction> {
        self.get(txid).map(|e| e.tx)
    }
}

/// A `-zmqpub*` address that could not be bound.
#[derive(Debug, thiserror::Error)]
#[error("cannot bind -{option}={address}: {source}")]
pub struct CoreZmqBindError {
    pub option: &'static str,
    pub address: String,
    #[source]
    pub source: io::Error,
}

impl CoreZmqSocketStats for ZmtpPub {
    fn subscriber_count(&self) -> usize {
        ZmtpPub::subscriber_count(self)
    }

    fn dropped_total(&self) -> u64 {
        ZmtpPub::dropped_total(self)
    }
}

/// One notifier: a topic on one of the sockets, with its own counter.
struct Notifier {
    topic: CoreZmqTopic,
    socket: usize,
    /// The next message's counter value (frame 2).
    seq: u32,
}

/// The Core-compatible ZMQ publisher. Built bound by [`CoreZmqSink::bind`],
/// then handed to [`node::events::EventPublisher::attach_sinks`].
pub struct CoreZmqSink {
    sockets: Vec<Arc<ZmtpPub>>,
    notifiers: Vec<Notifier>,
    status: Arc<CoreZmqStatus>,
    chain: Arc<dyn CoreZmqChain>,
    mempool: Arc<dyn CoreZmqMempool>,
    /// The tip a reorg is heading for, and its height, from the `Reorg`
    /// marker that opens the reorg's events. The side blocks it connects on
    /// the way publish no `hashblock`: Core announces only the reorg's final
    /// tip.
    pending_reorg: Option<(BlockHash, u32)>,
}

impl CoreZmqSink {
    /// Bind one socket per distinct address and build the publisher.
    ///
    /// `notifiers` must be in Core's notifier order (topics alphabetically,
    /// then option order). Notifiers with the same address share a socket,
    /// whose high-water mark is the first such notifier's, as in Core.
    /// Fails on the first address that does not bind; the caller then runs
    /// with ZMQ off, as Core does.
    pub async fn bind(
        notifiers: Vec<CoreZmqNotifier>,
        chain: Arc<dyn CoreZmqChain>,
        mempool: Arc<dyn CoreZmqMempool>,
    ) -> Result<Self, CoreZmqBindError> {
        let mut by_address: HashMap<String, usize> = HashMap::new();
        let mut sockets: Vec<Arc<ZmtpPub>> = Vec::new();
        let mut table = Vec::with_capacity(notifiers.len());
        for n in &notifiers {
            let socket = match by_address.get(&n.address) {
                Some(&i) => i,
                None => {
                    let hwm = usize::try_from(n.hwm).unwrap_or(0);
                    let bound = ZmtpPub::bind(&n.address, hwm).await.map_err(|source| {
                        CoreZmqBindError {
                            option: n.topic.option(),
                            address: n.address.clone(),
                            source,
                        }
                    })?;
                    sockets.push(Arc::new(bound));
                    by_address.insert(n.address.clone(), sockets.len() - 1);
                    sockets.len() - 1
                }
            };
            table.push(Notifier { topic: n.topic, socket, seq: 0 });
        }
        let stats = sockets
            .iter()
            .map(|s| {
                let s: Arc<dyn CoreZmqSocketStats> = s.clone();
                Arc::downgrade(&s)
            })
            .collect();
        Ok(Self {
            sockets,
            notifiers: table,
            status: Arc::new(CoreZmqStatus::new(notifiers, stats)),
            chain,
            mempool,
            pending_reorg: None,
        })
    }

    /// The publisher's state, for `getzmqnotifications` and `/metrics`.
    pub fn status(&self) -> Arc<CoreZmqStatus> {
        self.status.clone()
    }

    /// Each socket's bound endpoint, with an OS-assigned port resolved.
    pub fn local_endpoints(&self) -> Vec<String> {
        self.sockets.iter().map(|s| s.local_endpoint()).collect()
    }

    fn has(&self, topic: CoreZmqTopic) -> bool {
        self.notifiers.iter().any(|n| n.topic == topic)
    }

    /// Whether any subscriber would receive a message on `topic` now. When
    /// none would, a message's body is not built — but its notifiers'
    /// counters still advance, as a libzmq PUB socket's sender counts what
    /// it drops.
    fn listening(&self, topic: CoreZmqTopic) -> bool {
        self.notifiers.iter().any(|n| {
            n.topic == topic && self.sockets[n.socket].has_subscriber(topic.name().as_bytes())
        })
    }

    /// Send one message on every notifier of `topic`, in notifier order:
    /// `body` when it was built, otherwise only the counter moves.
    fn publish(&mut self, topic: CoreZmqTopic, body: Option<&Bytes>) {
        let topic_frame = Bytes::from_static(topic.name().as_bytes());
        for n in self.notifiers.iter_mut().filter(|n| n.topic == topic) {
            if let Some(body) = body {
                let seq = Bytes::copy_from_slice(&n.seq.to_le_bytes());
                self.sockets[n.socket].publish([topic_frame.clone(), body.clone(), seq]);
            }
            n.seq = n.seq.wrapping_add(1);
            self.status.record_message(topic);
        }
    }

    /// Build a message's body only if anyone will receive it.
    fn body(&self, topic: CoreZmqTopic, build: impl FnOnce() -> Bytes) -> Option<Bytes> {
        self.listening(topic).then(build)
    }

    async fn on_event(&mut self, body: &NodeEventBody) {
        match body {
            NodeEventBody::Mempool(MempoolEvent::Enter { txid, raw_tx, mempool_sequence, .. }) => {
                self.tx_added(txid, raw_tx.as_deref(), *mempool_sequence);
            }
            NodeEventBody::Mempool(
                MempoolEvent::LeaveEvicted { txid, mempool_sequence, .. }
                | MempoolEvent::LeaveReplaced { txid, mempool_sequence, .. },
            ) => {
                if self.has(CoreZmqTopic::Sequence) {
                    let body = self.body(CoreZmqTopic::Sequence, || {
                        sequence_body(txid.as_byte_array(), b'R', Some(*mempool_sequence))
                    });
                    self.publish(CoreZmqTopic::Sequence, body.as_ref());
                }
            }
            // Core is silent on a removal by block inclusion: the block's own
            // messages carry the transaction.
            NodeEventBody::Mempool(MempoolEvent::LeaveConfirmed { .. }) => {}
            NodeEventBody::Chain(ChainEvent::Reorg { new_tip, to_height, .. }) => {
                self.pending_reorg = Some((*new_tip, *to_height));
            }
            NodeEventBody::Chain(ChainEvent::BlockDisconnected { hash, .. }) => {
                self.block_disconnected(*hash).await;
            }
            NodeEventBody::Chain(ChainEvent::BlockConnected { hash, height }) => {
                self.block_connected(*hash, *height).await;
            }
            _ => {}
        }
    }

    fn tx_added(&mut self, txid: &Txid, raw_tx: Option<&Transaction>, mempool_sequence: u64) {
        if self.has(CoreZmqTopic::HashTx) {
            let body = self.body(CoreZmqTopic::HashTx, || reversed(txid.as_byte_array()));
            self.publish(CoreZmqTopic::HashTx, body.as_ref());
        }
        if self.has(CoreZmqTopic::RawTx) {
            let body = if self.listening(CoreZmqTopic::RawTx) {
                let bytes = match raw_tx {
                    Some(tx) => Some(bitcoin::consensus::serialize(tx)),
                    None => self.mempool.transaction(txid).map(|tx| bitcoin::consensus::serialize(&tx)),
                };
                if bytes.is_none() {
                    // The event did not carry the transaction and it has
                    // already left the mempool. Only possible if the
                    // publisher runs without `Mempool::set_emit_raw_tx`.
                    self.status.record_rawtx_unavailable();
                    debug!(target: "events::zmq::core", %txid, "rawtx skipped: transaction no longer available");
                }
                bytes.map(Bytes::from)
            } else {
                None
            };
            self.publish(CoreZmqTopic::RawTx, body.as_ref());
        }
        if self.has(CoreZmqTopic::Sequence) {
            let body = self.body(CoreZmqTopic::Sequence, || {
                sequence_body(txid.as_byte_array(), b'A', Some(mempool_sequence))
            });
            self.publish(CoreZmqTopic::Sequence, body.as_ref());
        }
    }

    /// Read a block for its messages. `None`, counted and logged, when it
    /// cannot be read: pruned away, or unreadable.
    async fn read_block(&self, hash: BlockHash) -> Option<Block> {
        let chain = self.chain.clone();
        let block = match tokio::task::spawn_blocking(move || chain.block(&hash)).await {
            Ok(b) => b,
            Err(e) => {
                warn!(target: "events::zmq::core", %hash, error = %e, "block read task failed");
                None
            }
        };
        if block.is_none() {
            self.status.record_block_read_failure();
            warn!(
                target: "events::zmq::core",
                %hash,
                "block not readable; its hashtx, rawtx and rawblock messages are skipped",
            );
        }
        block
    }

    /// The per-transaction `hashtx` / `rawtx` messages of a connected or
    /// disconnected block. Without the block (nobody listening, or it could
    /// not be read) the counters still advance by its transaction count, so
    /// a subscriber sees the gap.
    fn block_txs(&mut self, hash: BlockHash, block: Option<&Block>) {
        let hashtx = self.listening(CoreZmqTopic::HashTx);
        let rawtx = self.listening(CoreZmqTopic::RawTx);
        match block {
            Some(block) => {
                for tx in &block.txdata {
                    if self.has(CoreZmqTopic::HashTx) {
                        let body = hashtx.then(|| reversed(tx.compute_txid().as_byte_array()));
                        self.publish(CoreZmqTopic::HashTx, body.as_ref());
                    }
                    if self.has(CoreZmqTopic::RawTx) {
                        let body = rawtx.then(|| Bytes::from(bitcoin::consensus::serialize(tx)));
                        self.publish(CoreZmqTopic::RawTx, body.as_ref());
                    }
                }
            }
            None => {
                let n = self.chain.tx_count(&hash).unwrap_or(0);
                for _ in 0..n {
                    for topic in [CoreZmqTopic::HashTx, CoreZmqTopic::RawTx] {
                        if self.has(topic) {
                            self.publish(topic, None);
                        }
                    }
                }
            }
        }
    }

    async fn block_disconnected(&mut self, hash: BlockHash) {
        if self.has(CoreZmqTopic::HashTx) || self.has(CoreZmqTopic::RawTx) {
            let block = if self.listening(CoreZmqTopic::HashTx) || self.listening(CoreZmqTopic::RawTx) {
                self.read_block(hash).await
            } else {
                None
            };
            self.block_txs(hash, block.as_ref());
        }
        if self.has(CoreZmqTopic::Sequence) {
            let body = self.body(CoreZmqTopic::Sequence, || sequence_body(hash.as_byte_array(), b'D', None));
            self.publish(CoreZmqTopic::Sequence, body.as_ref());
        }
    }

    /// Whether a connected block is a tip update Core would announce on
    /// `hashblock` / `rawblock`.
    fn is_tip_update(&mut self, hash: BlockHash, height: u32) -> bool {
        if let Some((tip, tip_height)) = self.pending_reorg {
            if hash == tip {
                self.pending_reorg = None;
            } else if height <= tip_height {
                // A side block the reorg connects on its way to `tip`.
                return false;
            } else {
                // Above the reorg's target, so the reorg is over without a
                // block connected at it: `invalidateblock` disconnects back to
                // the fork point and stops there. This is a new block.
                self.pending_reorg = None;
            }
        }
        !self.chain.in_initial_block_download()
    }

    async fn block_connected(&mut self, hash: BlockHash, height: u32) {
        let tip_update = self.is_tip_update(hash, height);
        let want_txs = self.listening(CoreZmqTopic::HashTx) || self.listening(CoreZmqTopic::RawTx);
        let want_raw = tip_update && self.listening(CoreZmqTopic::RawBlock);
        let block = if want_txs || want_raw { self.read_block(hash).await } else { None };
        if self.has(CoreZmqTopic::HashTx) || self.has(CoreZmqTopic::RawTx) {
            self.block_txs(hash, block.as_ref().filter(|_| want_txs));
        }
        if self.has(CoreZmqTopic::Sequence) {
            let body = self.body(CoreZmqTopic::Sequence, || sequence_body(hash.as_byte_array(), b'C', None));
            self.publish(CoreZmqTopic::Sequence, body.as_ref());
        }
        if tip_update {
            if self.has(CoreZmqTopic::HashBlock) {
                let body = self.body(CoreZmqTopic::HashBlock, || reversed(hash.as_byte_array()));
                self.publish(CoreZmqTopic::HashBlock, body.as_ref());
            }
            if self.has(CoreZmqTopic::RawBlock) {
                let body = block
                    .as_ref()
                    .filter(|_| want_raw)
                    .map(|b| Bytes::from(bitcoin::consensus::serialize(b)));
                self.publish(CoreZmqTopic::RawBlock, body.as_ref());
            }
        }
    }

    /// The publisher's own receiver fell behind and the bus dropped `n`
    /// events for it. Every notifier skips a counter value so its
    /// subscribers see a gap.
    fn lagged(&mut self, n: u64) {
        for notifier in &mut self.notifiers {
            notifier.seq = notifier.seq.wrapping_add(1);
        }
        self.status.record_events_lagged(n);
        warn!(
            target: "events::zmq::core",
            dropped = n,
            "Core ZMQ publisher fell behind the event bus; subscribers will see a sequence gap",
        );
    }
}

/// A hash in Core's display byte order, as `hashblock` / `hashtx` carry it.
fn reversed(hash: &[u8; 32]) -> Bytes {
    let mut b = *hash;
    b.reverse();
    Bytes::copy_from_slice(&b)
}

/// A `sequence` body: the reversed hash, the label, and for `A`/`R` the
/// mempool sequence number as a little-endian `u64`.
fn sequence_body(hash: &[u8; 32], label: u8, mempool_sequence: Option<u64>) -> Bytes {
    let mut b = Vec::with_capacity(41);
    b.extend(hash.iter().rev());
    b.push(label);
    if let Some(s) = mempool_sequence {
        b.extend_from_slice(&s.to_le_bytes());
    }
    Bytes::from(b)
}

#[async_trait]
impl EventSink for CoreZmqSink {
    fn name(&self) -> &'static str {
        "core-zmq"
    }

    async fn run(
        mut self: Box<Self>,
        mut events: broadcast::Receiver<NodeEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        info!(
            target: "events::zmq::core",
            endpoints = ?self.local_endpoints(),
            notifiers = self.notifiers.len(),
            "Core ZMQ publisher running",
        );
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                res = events.recv() => match res {
                    Ok(env) => self.on_event(&env.body).await,
                    Err(broadcast::error::RecvError::Lagged(n)) => self.lagged(n),
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            }
        }
        debug!(target: "events::zmq::core", "Core ZMQ publisher stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use zeromq::{Socket, SocketRecv, SubSocket};

    const TIMEOUT: Duration = Duration::from_secs(20);

    #[derive(Default)]
    struct FakeChain {
        blocks: Mutex<HashMap<BlockHash, Block>>,
        ibd: AtomicBool,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl CoreZmqChain for FakeChain {
        fn block(&self, hash: &BlockHash) -> Option<Block> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.blocks.lock().unwrap().get(hash).cloned()
        }
        fn tx_count(&self, hash: &BlockHash) -> Option<usize> {
            self.blocks.lock().unwrap().get(hash).map(|b| b.txdata.len())
        }
        fn in_initial_block_download(&self) -> bool {
            self.ibd.load(Ordering::Relaxed)
        }
    }

    #[derive(Default)]
    struct FakeMempool(Mutex<HashMap<Txid, Transaction>>);

    impl CoreZmqMempool for FakeMempool {
        fn transaction(&self, txid: &Txid) -> Option<Transaction> {
            self.0.lock().unwrap().get(txid).cloned()
        }
    }

    /// A distinct transaction per `tag`.
    fn tx(tag: u8) -> Transaction {
        let mut tx = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).txdata[0].clone();
        tx.input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0x01, tag]);
        tx
    }

    /// A distinct block per `tag`, with `n_tx` transactions. Its proof of
    /// work is irrelevant here.
    fn block(tag: u8, n_tx: u8) -> Block {
        let mut b = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        b.header.nonce = u32::from(tag);
        b.txdata = (0..n_tx).map(|i| tx(tag.wrapping_mul(16).wrapping_add(i))).collect();
        b
    }

    fn all_topics(address: &str) -> Vec<CoreZmqNotifier> {
        CoreZmqTopic::ALL
            .iter()
            .map(|t| CoreZmqNotifier { topic: *t, address: address.into(), hwm: 1000 })
            .collect()
    }

    struct Rig {
        sink: CoreZmqSink,
        chain: Arc<FakeChain>,
        mempool: Arc<FakeMempool>,
    }

    impl Rig {
        async fn new(notifiers: Vec<CoreZmqNotifier>) -> Self {
            let chain = Arc::new(FakeChain::default());
            let mempool = Arc::new(FakeMempool::default());
            let sink = CoreZmqSink::bind(notifiers, chain.clone(), mempool.clone()).await.expect("bind");
            Rig { sink, chain, mempool }
        }

        fn add_block(&self, b: &Block) -> BlockHash {
            let hash = b.block_hash();
            self.chain.blocks.lock().unwrap().insert(hash, b.clone());
            hash
        }

        /// A subscriber to `topics` on socket `i`, connected and registered
        /// for every topic before this returns.
        async fn sub(&self, i: usize, topics: &[&str]) -> SubSocket {
            let mut s = SubSocket::new();
            s.connect(&self.sink.sockets[i].local_endpoint()).await.expect("connect");
            for t in topics {
                s.subscribe(t).await.expect("subscribe");
            }
            let deadline = Instant::now() + TIMEOUT;
            let probe: Vec<&str> = if topics == [""] { vec!["hashblock"] } else { topics.to_vec() };
            while !probe.iter().all(|t| self.sink.sockets[i].has_subscriber(t.as_bytes())) {
                assert!(Instant::now() < deadline, "subscription never registered");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            s
        }

        async fn chain(&mut self, ev: ChainEvent) {
            self.sink.on_event(&NodeEventBody::Chain(ev)).await;
        }

        async fn mempool(&mut self, ev: MempoolEvent) {
            self.sink.on_event(&NodeEventBody::Mempool(ev)).await;
        }
    }

    /// (topic, body, counter).
    async fn recv(s: &mut SubSocket) -> (String, Vec<u8>, u32) {
        let m = tokio::time::timeout(TIMEOUT, s.recv()).await.expect("recv timed out").expect("recv");
        let f = m.into_vec();
        assert_eq!(f.len(), 3);
        (
            String::from_utf8(f[0].to_vec()).unwrap(),
            f[1].to_vec(),
            u32::from_le_bytes(f[2].as_ref().try_into().unwrap()),
        )
    }

    async fn recv_n(s: &mut SubSocket, n: usize) -> Vec<(String, Vec<u8>, u32)> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(recv(s).await);
        }
        out
    }

    /// Nothing more arrives within a short wait.
    async fn assert_quiet(s: &mut SubSocket) {
        if let Ok(m) = tokio::time::timeout(Duration::from_millis(300), s.recv()).await {
            panic!("unexpected message: {:?}", m.map(|m| m.into_vec()));
        }
    }

    fn rev(h: &[u8; 32]) -> Vec<u8> {
        h.iter().rev().copied().collect()
    }

    fn topics(m: &[(String, Vec<u8>, u32)]) -> Vec<&str> {
        m.iter().map(|(t, _, _)| t.as_str()).collect()
    }

    fn enter(t: &Transaction, raw: bool, mempool_sequence: u64) -> MempoolEvent {
        MempoolEvent::Enter {
            txid: t.compute_txid(),
            fee: 0,
            vsize: 0,
            fee_rate_sat_per_kvb: 0,
            time: 0,
            mempool_sequence,
            raw_tx: raw.then(|| Arc::new(t.clone())),
        }
    }

    /// A mempool admission is `hashtx`, `rawtx`, `sequence A` with Core's
    /// bodies; a removal is `sequence R`; a confirmation is silent.
    #[tokio::test]
    async fn mempool_events_map_to_cores_messages() {
        let mut rig = Rig::new(all_topics("tcp://127.0.0.1:0")).await;
        let mut sub = rig.sub(0, &[""]).await;
        let t = tx(1);
        let txid = t.compute_txid();

        rig.mempool(enter(&t, true, 7)).await;
        let m = recv_n(&mut sub, 3).await;
        assert_eq!(topics(&m), ["hashtx", "rawtx", "sequence"]);
        assert_eq!(m[0].1, rev(txid.as_byte_array()));
        assert_eq!(m[1].1, bitcoin::consensus::serialize(&t));
        let mut a = rev(txid.as_byte_array());
        a.push(b'A');
        a.extend_from_slice(&7u64.to_le_bytes());
        assert_eq!(m[2].1, a);
        assert!(m.iter().all(|(_, _, seq)| *seq == 0));

        rig.mempool(MempoolEvent::LeaveConfirmed {
            txid,
            block_hash: BlockHash::all_zeros(),
            height: 1,
            mempool_sequence: 8,
        })
        .await;
        rig.mempool(MempoolEvent::LeaveReplaced { txid, replacing_txid: txid, mempool_sequence: 9 }).await;
        let (topic, body, seq) = recv(&mut sub).await;
        let mut r = rev(txid.as_byte_array());
        r.push(b'R');
        r.extend_from_slice(&9u64.to_le_bytes());
        assert_eq!((topic.as_str(), body, seq), ("sequence", r, 1), "LeaveConfirmed publishes nothing");
        assert_quiet(&mut sub).await;
    }

    /// Without the transaction on the event, `rawtx` reads the mempool; if
    /// it is gone from there too the message is skipped, counted, and its
    /// counter value spent, so a subscriber sees the gap.
    #[tokio::test]
    async fn rawtx_falls_back_to_the_mempool_then_leaves_a_gap() {
        let notifiers =
            vec![CoreZmqNotifier { topic: CoreZmqTopic::RawTx, address: "tcp://127.0.0.1:0".into(), hwm: 0 }];
        let mut rig = Rig::new(notifiers).await;
        let mut sub = rig.sub(0, &["rawtx"]).await;
        let (a, b, c) = (tx(1), tx(2), tx(3));
        rig.mempool.0.lock().unwrap().insert(a.compute_txid(), a.clone());

        rig.mempool(enter(&a, false, 1)).await;
        rig.mempool(enter(&b, false, 2)).await;
        rig.mempool(enter(&c, true, 3)).await;
        let m = recv_n(&mut sub, 2).await;
        assert_eq!((m[0].1.clone(), m[0].2), (bitcoin::consensus::serialize(&a), 0));
        assert_eq!((m[1].1.clone(), m[1].2), (bitcoin::consensus::serialize(&c), 2));
        assert_eq!(rig.sink.status.rawtx_unavailable_total(), 1);
    }

    /// A connected block: its transactions, `C`, then the tip update. A
    /// disconnected block: its transactions, then `D`, and no tip update.
    #[tokio::test]
    async fn block_events_map_to_cores_messages() {
        let mut rig = Rig::new(all_topics("tcp://127.0.0.1:0")).await;
        let mut sub = rig.sub(0, &[""]).await;
        let b = block(1, 2);
        let hash = rig.add_block(&b);

        rig.chain(ChainEvent::BlockConnected { hash, height: 1 }).await;
        let m = recv_n(&mut sub, 7).await;
        assert_eq!(topics(&m), ["hashtx", "rawtx", "hashtx", "rawtx", "sequence", "hashblock", "rawblock"]);
        assert_eq!(m[2].1, rev(b.txdata[1].compute_txid().as_byte_array()));
        assert_eq!(m[3].1, bitcoin::consensus::serialize(&b.txdata[1]));
        let mut c = rev(hash.as_byte_array());
        c.push(b'C');
        assert_eq!(m[4].1, c);
        assert_eq!(m[5].1, rev(hash.as_byte_array()));
        assert_eq!(m[6].1, bitcoin::consensus::serialize(&b));
        let seqs: Vec<u32> = m.iter().map(|x| x.2).collect();
        assert_eq!(seqs, [0, 0, 1, 1, 0, 0, 0], "each notifier counts its own messages");

        rig.chain(ChainEvent::BlockDisconnected { hash, height: 1 }).await;
        let m = recv_n(&mut sub, 5).await;
        assert_eq!(topics(&m), ["hashtx", "rawtx", "hashtx", "rawtx", "sequence"]);
        let mut d = rev(hash.as_byte_array());
        d.push(b'D');
        assert_eq!(m[4].1, d);
        assert_quiet(&mut sub).await;
    }

    fn hashblocks(m: &[(String, Vec<u8>, u32)]) -> Vec<Vec<u8>> {
        m.iter().filter(|(t, _, _)| t == "hashblock").map(|(_, b, _)| b.clone()).collect()
    }

    /// A reorg's side blocks connect without a tip update; only the block
    /// the `Reorg` marker names is announced.
    #[tokio::test]
    async fn reorg_announces_only_the_new_tip() {
        let notifiers = vec![
            CoreZmqNotifier { topic: CoreZmqTopic::HashBlock, address: "tcp://127.0.0.1:0".into(), hwm: 0 },
            CoreZmqNotifier { topic: CoreZmqTopic::Sequence, address: "tcp://127.0.0.1:0".into(), hwm: 0 },
        ];
        let mut rig = Rig::new(notifiers).await;
        let mut sub = rig.sub(0, &[""]).await;
        let (a1, a2) = (rig.add_block(&block(1, 1)), rig.add_block(&block(2, 1)));
        let (b1, b2, b3) = (rig.add_block(&block(3, 1)), rig.add_block(&block(4, 1)), rig.add_block(&block(5, 1)));

        rig.chain(ChainEvent::Reorg { from_height: 2, old_tip: a2, to_height: 3, new_tip: b3 }).await;
        rig.chain(ChainEvent::BlockDisconnected { hash: a2, height: 2 }).await;
        rig.chain(ChainEvent::BlockDisconnected { hash: a1, height: 1 }).await;
        rig.chain(ChainEvent::BlockConnected { hash: b1, height: 1 }).await;
        rig.chain(ChainEvent::BlockConnected { hash: b2, height: 2 }).await;
        rig.chain(ChainEvent::BlockConnected { hash: b3, height: 3 }).await;
        let m = recv_n(&mut sub, 6).await;
        assert_eq!(topics(&m), ["sequence", "sequence", "sequence", "sequence", "sequence", "hashblock"]);
        assert_eq!(hashblocks(&m), [rev(b3.as_byte_array())]);

        // The reorg is over: the next block is an ordinary tip update.
        let b4 = rig.add_block(&block(6, 1));
        rig.chain(ChainEvent::BlockConnected { hash: b4, height: 4 }).await;
        let m = recv_n(&mut sub, 2).await;
        assert_eq!(hashblocks(&m), [rev(b4.as_byte_array())]);
    }

    /// `invalidateblock` emits a `Reorg` marker naming the fork point as the
    /// new tip and connects nothing. No block ever matches that tip, so the
    /// pending reorg must end with the next block above it, which is an
    /// ordinary tip update. Holding out for a match would mute `hashblock`
    /// from then on.
    #[tokio::test]
    async fn a_disconnect_only_reorg_does_not_mute_later_blocks() {
        let notifiers =
            vec![CoreZmqNotifier { topic: CoreZmqTopic::HashBlock, address: "tcp://127.0.0.1:0".into(), hwm: 0 }];
        let mut rig = Rig::new(notifiers).await;
        let mut sub = rig.sub(0, &["hashblock"]).await;
        let (parent, invalid) = (rig.add_block(&block(1, 1)), rig.add_block(&block(2, 1)));

        rig.chain(ChainEvent::Reorg { from_height: 2, old_tip: invalid, to_height: 1, new_tip: parent }).await;
        rig.chain(ChainEvent::BlockDisconnected { hash: invalid, height: 2 }).await;
        let next = rig.add_block(&block(3, 1));
        rig.chain(ChainEvent::BlockConnected { hash: next, height: 2 }).await;
        let m = recv_n(&mut sub, 1).await;
        assert_eq!(hashblocks(&m), [rev(next.as_byte_array())]);
        assert_quiet(&mut sub).await;
    }

    /// In initial block download Core publishes no tip update.
    #[tokio::test]
    async fn no_tip_update_in_initial_block_download() {
        let mut rig = Rig::new(all_topics("tcp://127.0.0.1:0")).await;
        let mut sub = rig.sub(0, &["hashblock", "rawblock", "sequence"]).await;
        rig.chain.ibd.store(true, Ordering::Relaxed);
        let hash = rig.add_block(&block(1, 1));
        rig.chain(ChainEvent::BlockConnected { hash, height: 1 }).await;
        let m = recv_n(&mut sub, 1).await;
        assert_eq!(topics(&m), ["sequence"]);
        assert_quiet(&mut sub).await;
    }

    /// Messages nobody is subscribed to are not built, but they are counted,
    /// a block's per-transaction ones included: a subscriber that arrives
    /// later sees the counter where Core's would be.
    #[tokio::test]
    async fn unheard_messages_still_advance_the_counter() {
        let notifiers =
            vec![CoreZmqNotifier { topic: CoreZmqTopic::HashTx, address: "tcp://127.0.0.1:0".into(), hwm: 0 }];
        let mut rig = Rig::new(notifiers).await;
        rig.mempool(enter(&tx(1), false, 1)).await;
        let hash = rig.add_block(&block(1, 3));
        rig.chain(ChainEvent::BlockConnected { hash, height: 1 }).await;
        assert_eq!(rig.chain.reads.load(Ordering::Relaxed), 0, "an unheard block is not read");

        let mut sub = rig.sub(0, &["hashtx"]).await;
        rig.mempool(enter(&tx(2), false, 2)).await;
        let (_, _, seq) = recv(&mut sub).await;
        assert_eq!(seq, 4, "one admission and three block transactions came before");
        assert_eq!(rig.sink.status.messages_total(CoreZmqTopic::HashTx), 5);
    }

    /// The publisher's own lag spends a counter value on every notifier, so
    /// the gap shows.
    #[tokio::test]
    async fn own_lag_shows_as_a_counter_gap() {
        let mut rig = Rig::new(all_topics("tcp://127.0.0.1:0")).await;
        let mut sub = rig.sub(0, &["sequence"]).await;
        let t = tx(1);
        rig.mempool(MempoolEvent::LeaveEvicted {
            txid: t.compute_txid(),
            reason: node::mempool::events::EvictReason::Expiry,
            mempool_sequence: 1,
        })
        .await;
        rig.sink.lagged(40);
        rig.mempool(MempoolEvent::LeaveEvicted {
            txid: t.compute_txid(),
            reason: node::mempool::events::EvictReason::Expiry,
            mempool_sequence: 2,
        })
        .await;
        let m = recv_n(&mut sub, 2).await;
        assert_eq!((m[0].2, m[1].2), (0, 2));
        assert_eq!(rig.sink.status.events_lagged_total(), 40);
    }

    /// Notifiers on one address share one socket; distinct addresses get
    /// their own.
    #[tokio::test]
    async fn notifiers_on_one_address_share_a_socket() {
        let dir = tempfile::tempdir().unwrap();
        let ipc = format!("ipc://{}", dir.path().join("z.sock").display());
        let mut notifiers = all_topics(&ipc);
        notifiers.push(CoreZmqNotifier { topic: CoreZmqTopic::Sequence, address: "tcp://127.0.0.1:0".into(), hwm: 5 });
        let rig = Rig::new(notifiers).await;
        assert_eq!(rig.sink.local_endpoints().len(), 2);
        assert_eq!(rig.sink.status.notifiers().len(), 6);
    }

    /// A bind failure names the option and the address, for Core's log line.
    #[tokio::test]
    async fn bind_failure_names_the_option() {
        let notifiers = vec![
            CoreZmqNotifier { topic: CoreZmqTopic::HashTx, address: "tcp://127.0.0.1:0".into(), hwm: 0 },
            CoreZmqNotifier { topic: CoreZmqTopic::RawTx, address: "foo".into(), hwm: 0 },
        ];
        let err = CoreZmqSink::bind(notifiers, Arc::new(FakeChain::default()), Arc::new(FakeMempool::default()))
            .await
            .err()
            .expect("an address that is not one fails");
        assert_eq!((err.option, err.address.as_str()), ("zmqpubrawtx", "foo"));
    }
}
