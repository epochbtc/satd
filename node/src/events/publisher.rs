//! [`EventPublisher`] — the daemon-level service that fans the existing
//! internal `MempoolEvent` / `ChainEvent` broadcasts into the unified,
//! edge-stamped [`super::NodeEvent`] envelope, then supervises the sink
//! tasks that ferry those envelopes onto external transports.
//!
//! Constructed once at startup, threaded through `main.rs`. The
//! existing internal consumers (Esplora SSE, address-index notifier,
//! `subscribemempool` JSON-RPC, reorg-webhook dispatcher) keep
//! subscribing to the raw broadcasts directly — this service only
//! handles the new external-transport pipeline.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bitcoin::Txid;
use node_sp_index::{SpIndex, TweakEntry};
use tokio::sync::{broadcast, watch};
use tokio::time::{Duration, MissedTickBehavior, interval};
use tracing::{debug, info, warn};

use crate::chain::events::ChainEvent;
use crate::mempool::events::MempoolEvent;

use super::envelope::{
    BlockTweaks, Cursor, EdgeIdentity, EdgeStamp, NodeEvent, NodeEventBody, SpTweakEntry,
};

/// Read handle for the mempool's admission-cached silent-payment tweaks, keyed
/// by txid. Implemented by [`crate::mempool::pool::Mempool`]; the mempool bridge
/// consults it on each `Enter` when a `mempool_tweaks` subscriber is listening,
/// mirroring how the chain bridge reads [`SpIndex`] for confirmed `BlockTweaks`.
/// Returns `None` when the entry is gone (raced eviction/RBF) or was admitted
/// while the tweak gate was cold — both benign, best-effort skips.
pub trait MempoolTweakSource: Send + Sync {
    fn cached_tweak(&self, txid: &Txid) -> Option<TweakEntry>;
}
use super::sink::EventSink;

/// Capacity of the envelope broadcast channel. Sized 4× the existing
/// mempool channel: envelopes are heavier than raw events and adapters
/// can run slower than internal consumers, so a deeper buffer absorbs
/// transient bursts without forcing `Lagged` errors at every adapter
/// simultaneously.
pub const ENVELOPE_BROADCAST_CAPACITY: usize = 4096;

/// Depth of the best-effort mempool replay ring. Holds the most recent
/// published envelopes so a reconnecting client with a `from_cursor`
/// mempool watermark can replay mempool transitions it missed within a
/// bounded window, then join live. The mempool is not durable, so this is
/// explicitly lossy: a cursor older than the oldest retained entry simply
/// resumes from the window's start. Confirmed-side replay does NOT use
/// this ring — it reads the durable block index (see
/// [`super::BlockCursorSource`]).
pub const REPLAY_RING_CAPACITY: usize = 1024;

/// Resolve a buffer-capacity knob, applying a test-only environment
/// override when present. The override exists so the streaming E2E suite
/// can shrink the broadcast buffer / replay ring to force a deterministic
/// `Lagged` (and a bounded replay window) without flooding tens of
/// thousands of events over a real socket. Mirrors the
/// `SATD_BACKFILL_DEBUG_DELAY_MS` test-knob pattern: parsed, bounds-checked
/// (1..=65536), and silently ignored on a malformed value, so production —
/// which never sets these vars — always gets `default`.
fn capacity_override(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|c| *c > 0 && *c <= 65536)
        .unwrap_or(default)
}

/// Heartbeat cadence. One per second is enough for end-to-end pipeline
/// latency probes; the bandwidth cost is trivial (a single envelope
/// per second). Subscribers that don't want heartbeats filter via the
/// gRPC `categories` bitfield or the ZMQ topic selection.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

/// Daemon-level event-bus publisher. Built once at startup; all sink
/// adapters share the same instance.
pub struct EventPublisher {
    out: broadcast::Sender<NodeEvent>,
    edge: EdgeIdentity,
    seq: AtomicU64,
    started_monotonic: Instant,
    /// Bounded ring of the most recent published envelopes, for
    /// best-effort mempool cursor replay. Short critical section (one
    /// push + bounded pop per publish); no `.await` is held across the
    /// lock, so a `std::sync::Mutex` is appropriate.
    replay_ring: Mutex<VecDeque<NodeEvent>>,
    /// Effective replay-ring capacity (normally [`REPLAY_RING_CAPACITY`],
    /// shrinkable via the test-only env knob). Stored per-instance because
    /// `publish`'s pop bound must match the capacity the ring was built
    /// with.
    replay_ring_cap: usize,
    /// Live count of streaming subscribers on the `tweaks` (silent-payment)
    /// category. The chain bridge only does the per-block `sp_tweaks` lookup
    /// and `BlockTweaks` emit when this is non-zero — a node with the index
    /// enabled but no tweak subscribers pays nothing on the bus. Carriers
    /// hold a [`TweakSubscriberGuard`] for a tweak subscription's lifetime.
    tweak_subscribers: Arc<AtomicUsize>,
    /// Live count of subscribers that additionally requested `mempool_tweaks`
    /// (Tier 1.5). The mempool bridge only looks up an admitted tx's cached
    /// tweak and emits a `MempoolTweak` when this is non-zero. Shared with the
    /// mempool's second admission gate (via [`Self::mempool_tweaks_gate`]) so a
    /// firehose subscriber's presence is what makes admission compute the tweak.
    /// Carriers hold a [`MempoolTweakSubscriberGuard`] for the subscription's
    /// lifetime.
    mempool_tweak_subscribers: Arc<AtomicUsize>,
}

/// RAII counter for an active `tweaks`-category subscription. Increments the
/// publisher's tweak-subscriber count on construction and decrements it on
/// drop, so the chain bridge's live-emit gate reflects real demand.
pub struct TweakSubscriberGuard {
    count: Arc<AtomicUsize>,
}

impl Drop for TweakSubscriberGuard {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// RAII counter for an active `mempool_tweaks` subscription. Raises the
/// publisher's mempool-tweak-subscriber count (which doubles as the mempool's
/// second admission gate) for as long as it is held.
pub struct MempoolTweakSubscriberGuard {
    count: Arc<AtomicUsize>,
}

impl Drop for MempoolTweakSubscriberGuard {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}

impl EventPublisher {
    /// Build a new publisher. `capacity` is the broadcast buffer size;
    /// pass [`ENVELOPE_BROADCAST_CAPACITY`] for the default.
    pub fn new(edge: EdgeIdentity, capacity: usize) -> Arc<Self> {
        let capacity = capacity_override("SATD_EVENT_BROADCAST_CAPACITY", capacity);
        let replay_ring_cap =
            capacity_override("SATD_EVENT_REPLAY_RING_CAPACITY", REPLAY_RING_CAPACITY);
        let (out, _rx) = broadcast::channel(capacity);
        Arc::new(Self {
            out,
            edge,
            seq: AtomicU64::new(0),
            started_monotonic: Instant::now(),
            replay_ring: Mutex::new(VecDeque::with_capacity(replay_ring_cap)),
            replay_ring_cap,
            tweak_subscribers: Arc::new(AtomicUsize::new(0)),
            mempool_tweak_subscribers: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Register an active `tweaks`-category subscription. The returned guard
    /// keeps the tweak-subscriber count raised for as long as it is held; drop
    /// it when the subscription ends. While at least one guard is live and a
    /// tweak source is wired, the chain bridge emits `BlockTweaks` per block.
    pub fn tweak_subscriber_guard(&self) -> TweakSubscriberGuard {
        self.tweak_subscribers.fetch_add(1, Ordering::Relaxed);
        TweakSubscriberGuard {
            count: self.tweak_subscribers.clone(),
        }
    }

    /// Whether any `tweaks`-category subscriber is currently attached.
    pub fn has_tweak_subscribers(&self) -> bool {
        self.tweak_subscribers.load(Ordering::Relaxed) > 0
    }

    /// Register an active `mempool_tweaks` subscription. The returned guard keeps
    /// the mempool-tweak-subscriber count raised until dropped; while any guard
    /// is live and a mempool tweak source is wired, the mempool bridge emits a
    /// `MempoolTweak` at each SP-eligible admission.
    pub fn mempool_tweak_subscriber_guard(&self) -> MempoolTweakSubscriberGuard {
        self.mempool_tweak_subscribers.fetch_add(1, Ordering::Relaxed);
        MempoolTweakSubscriberGuard {
            count: self.mempool_tweak_subscribers.clone(),
        }
    }

    /// Whether any `mempool_tweaks` subscriber is currently attached.
    pub fn has_mempool_tweak_subscribers(&self) -> bool {
        self.mempool_tweak_subscribers.load(Ordering::Relaxed) > 0
    }

    /// The mempool-tweak-subscriber counter, shared with the mempool as its
    /// second admission gate (`Mempool::set_mempool_tweaks_gate`). While it reads
    /// `> 0`, admission computes and caches the tweak even with no Tier-2 SP
    /// scan-key watch live, so the firehose has something to emit.
    pub fn mempool_tweaks_gate(&self) -> Arc<AtomicUsize> {
        self.mempool_tweak_subscribers.clone()
    }

    /// Subscribe to the envelope stream. Each call returns a fresh
    /// receiver. Sinks normally subscribe once via
    /// [`EventPublisher::attach_sinks`]; tests subscribe directly.
    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.out.subscribe()
    }

    /// Edge identity stamped on every envelope.
    pub fn edge(&self) -> &EdgeIdentity {
        &self.edge
    }

    /// This publisher's per-process epoch nonce. A reconnecting client's
    /// `from_cursor.instance_id` is compared against this; a mismatch
    /// means the daemon restarted since the cursor was issued, so its
    /// `mempool_seq` watermark must be discarded (see [`EdgeIdentity`]).
    pub fn instance_id(&self) -> u64 {
        self.edge.instance_id
    }

    /// Build a resume [`Cursor`] at `(height, mempool_seq)` stamped with this
    /// publisher's `instance_id` — used by carriers to fill a `Lagged` notice's
    /// `resume_cursor` from the last position they delivered.
    pub fn resume_cursor(&self, height: u32, mempool_seq: u64) -> Cursor {
        Cursor {
            height,
            tx_index: 0,
            mempool_seq,
            instance_id: self.edge.instance_id,
        }
    }

    /// Number of envelopes published since startup. Useful for tests.
    pub fn published(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }

    /// Build a stamp for a new envelope. Increments the per-publisher
    /// monotonic sequence and samples both clocks at the bridge instant.
    /// `edge_seen_at_ns` is monotonic since publisher start;
    /// `edge_wall_ns` is `SystemTime::now()` so it tracks NTP /
    /// administrator-driven adjustments — accept that it may step
    /// backwards or forwards under those, and use it for cross-node
    /// correlation rather than ordering on a single node.
    fn stamp(&self) -> EdgeStamp {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let monotonic_elapsed = self.started_monotonic.elapsed().as_nanos() as u64;
        // SystemTime is a VDSO call on Linux x86_64 (~50ns) — fine to
        // resample per event. Pre-1970 clocks fall back to 0; that is
        // pathological in practice but keeps the type total.
        let edge_wall_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        EdgeStamp {
            node_id: self.edge.node_id,
            region: self.edge.region,
            edge_seen_at_ns: monotonic_elapsed,
            edge_wall_ns,
            seq,
        }
    }

    /// Build an envelope and best-effort publish it. Drops silently
    /// when there are zero subscribers (which is the steady-state when
    /// no external sinks are configured); sink-side `Lagged` errors are
    /// the sink's problem, not ours.
    fn publish(&self, body: NodeEventBody) {
        let stamp = self.stamp();
        // Stamp a durable resume cursor on confirmed-side bodies (a
        // connected block), so a reconnecting client can persist it and
        // resume via `SubscribeRequest.from_cursor`. `stamp.seq` doubles
        // as the best-effort mempool high-water mark; the per-process
        // `instance_id` lets a reconnecting client detect a restart and
        // discard a stale mempool watermark.
        let cursor = body.derive_cursor(self.edge.instance_id, stamp.seq);
        let env = NodeEvent::with_cursor(stamp, cursor, body);
        // Record into the bounded replay ring before broadcasting, so a
        // reconnecting client can replay recent mempool transitions it
        // missed (best-effort, bounded window). Lock poisoning would only
        // happen if a holder panicked mid-update; recover the guard rather
        // than propagate a panic into the publish path.
        //
        // `BlockTweaks` is deliberately excluded: it is replayed from the
        // durable index by height (never from this ring), and a busy chain's
        // tweak volume would otherwise evict the mempool transitions the ring
        // exists to retain. `MempoolTweak` is excluded too: it is ephemeral and
        // best-effort (no durable cursor), so it is never replayed — a client
        // that missed an admission catches the payment at confirmation.
        if !matches!(
            env.body,
            NodeEventBody::BlockTweaks(_) | NodeEventBody::MempoolTweak(_)
        ) {
            let mut ring = self
                .replay_ring
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if ring.len() == self.replay_ring_cap {
                ring.pop_front();
            }
            ring.push_back(env.clone());
        }
        // `send` returns `Err(SendError)` only when there are no active
        // receivers. That's the no-sinks-configured case — silent drop
        // is correct.
        let _ = self.out.send(env);
    }

    /// Best-effort replay of mempool-category envelopes published after
    /// `after_seq`, oldest-first, from the bounded replay ring. Used by a
    /// streaming subscriber resuming from a `from_cursor` mempool
    /// watermark: confirmed history comes from the durable block index,
    /// mempool history (which is not durable) from this lossy window. A
    /// watermark older than the ring's oldest retained entry simply
    /// resumes from the window's start.
    pub fn replay_mempool_since(&self, after_seq: u64) -> Vec<NodeEvent> {
        let ring = self
            .replay_ring
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        ring.iter()
            .filter(|e| {
                e.stamp.seq > after_seq && matches!(e.body, NodeEventBody::Mempool(_))
            })
            .cloned()
            .collect()
    }

    /// Spawn the bridge tasks with no silent-payment tweak emit (the common
    /// case for callers that do not serve the `tweaks` category — including
    /// the unit/integration tests). Delegates to [`Self::spawn_bridges_with_sp`].
    pub fn spawn_bridges(
        self: &Arc<Self>,
        mempool_rx: broadcast::Receiver<MempoolEvent>,
        chain_rx: broadcast::Receiver<ChainEvent>,
        shutdown: watch::Receiver<bool>,
    ) {
        self.spawn_bridges_with_sp(mempool_rx, chain_rx, None, None, shutdown);
    }

    /// Spawn the bridge tasks: one for the mempool broadcast and one
    /// for the chain broadcast. Each task runs until the broadcast
    /// sender is closed or `shutdown` flips to `true`.
    ///
    /// `tweak_source` is the silent-payment index read handle (present only
    /// when `silentpaymentindex=1`); `tweak_subscribers` is the live count of
    /// `tweaks`-category streaming subscribers, incremented by the carrier. On
    /// each connected block the chain bridge emits a `BlockTweaks` envelope
    /// **only** when the index is enabled and that count is non-zero — a node
    /// with the index on but no tweak subscribers pays nothing on the bus.
    pub fn spawn_bridges_with_sp(
        self: &Arc<Self>,
        mempool_rx: broadcast::Receiver<MempoolEvent>,
        chain_rx: broadcast::Receiver<ChainEvent>,
        tweak_source: Option<Arc<dyn SpIndex>>,
        mempool_tweak_source: Option<Arc<dyn MempoolTweakSource>>,
        shutdown: watch::Receiver<bool>,
    ) {
        // Mempool bridge.
        {
            let publisher = self.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                bridge_mempool(publisher, mempool_rx, mempool_tweak_source, shutdown).await;
            });
        }
        // Chain bridge.
        {
            let publisher = self.clone();
            tokio::spawn(async move {
                bridge_chain(publisher, chain_rx, tweak_source, shutdown).await;
            });
        }
    }

    /// Spawn the heartbeat task at the given cadence. Heartbeats
    /// traverse the same envelope path as real events so downstream
    /// consumers can probe end-to-end latency without an out-of-band
    /// channel. Production callers should pass [`HEARTBEAT_INTERVAL`].
    pub fn spawn_heartbeat(
        self: &Arc<Self>,
        interval: Duration,
        shutdown: watch::Receiver<bool>,
    ) {
        let publisher = self.clone();
        tokio::spawn(async move {
            heartbeat_loop(publisher, interval, shutdown).await;
        });
    }

    /// Spawn one task per sink. Each sink receives a fresh broadcast
    /// receiver and a clone of the shutdown watch. Returns the number
    /// of tasks spawned (handy for startup logs and tests).
    pub fn attach_sinks(
        self: &Arc<Self>,
        sinks: Vec<Box<dyn EventSink>>,
        shutdown: watch::Receiver<bool>,
    ) -> usize {
        let mut count = 0;
        for sink in sinks {
            let name = sink.name();
            let rx = self.out.subscribe();
            let shutdown = shutdown.clone();
            info!(target: "events", sink = %name, "events sink starting");
            tokio::spawn(async move {
                sink.run(rx, shutdown).await;
                info!(target: "events", sink = %name, "events sink stopped");
            });
            count += 1;
        }
        count
    }
}

async fn bridge_mempool(
    publisher: Arc<EventPublisher>,
    mut rx: broadcast::Receiver<MempoolEvent>,
    mempool_tweak_source: Option<Arc<dyn MempoolTweakSource>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            res = rx.recv() => match res {
                Ok(ev) => {
                    // On admission, follow the mempool event with the tx's cached
                    // public tweak (Tier 1.5) — but only when a `mempool_tweaks`
                    // subscriber is listening and the source is wired. The txid is
                    // captured before `ev` moves into `publish`. Symmetric to the
                    // chain bridge's `BlockTweaks` emit: the source (here the
                    // mempool) is consulted by key; a `None` means the entry is
                    // gone (raced eviction/RBF) or was admitted gate-cold — a
                    // benign, best-effort skip.
                    let admitted =
                        matches!(ev, MempoolEvent::Enter { .. }).then(|| *ev.txid());
                    publisher.publish(NodeEventBody::Mempool(ev));
                    if let Some(txid) = admitted
                        && let Some(src) = mempool_tweak_source.as_deref()
                        && publisher.has_mempool_tweak_subscribers()
                        && let Some(tweak) = src.cached_tweak(&txid)
                    {
                        publisher.publish(NodeEventBody::MempoolTweak(
                            SpTweakEntry::from_tweak_entry(&tweak),
                        ));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(target: "events", dropped = n, "mempool bridge lagged");
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
        }
    }
}

async fn bridge_chain(
    publisher: Arc<EventPublisher>,
    mut rx: broadcast::Receiver<ChainEvent>,
    tweak_source: Option<Arc<dyn SpIndex>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            res = rx.recv() => match res {
                Ok(ev) => {
                    // Emit the chain event first, then — when the index is on
                    // and a `tweaks` subscriber is listening — the same
                    // block's public tweak data as a trailing event at the
                    // same height. The row was committed atomically with the
                    // block in `connect_block`, so a point lookup by height
                    // returns the just-connected block's row. We guard on the
                    // row's embedded block hash (self-authenticating, §3.2):
                    // if it does not match the connected hash, a reorg has
                    // already advanced the height slot, and the correct
                    // `BlockTweaks` will be emitted when that block's own
                    // `BlockConnected` is bridged — skipping here avoids a
                    // duplicate/mislabeled early emit.
                    let connected = match &ev {
                        ChainEvent::BlockConnected { height, hash } => Some((*height, *hash)),
                        _ => None,
                    };
                    publisher.publish(NodeEventBody::Chain(ev));
                    if let Some((height, hash)) = connected
                        && let Some(src) = tweak_source.as_deref()
                        && publisher.has_tweak_subscribers()
                    {
                        match src.tweaks_at(height) {
                            Ok(row) if row.block_hash == hash => {
                                publisher.publish(NodeEventBody::BlockTweaks(
                                    BlockTweaks::from_row(height, &row),
                                ));
                            }
                            Ok(_) => {
                                debug!(
                                    target: "events",
                                    height,
                                    "sp_tweaks row hash mismatch on connect (reorg race); \
                                     deferring BlockTweaks emit",
                                );
                            }
                            // Below taproot activation no row exists (benign, and
                            // the common case for a pre-activation connect). A miss
                            // at/above activation on a just-committed block is
                            // unexpected but bounded — the live tweaks subscriber
                            // misses this block and recovers it on its next
                            // from_cursor replay/reconnect. Never a silent skip.
                            Err(node_sp_index::SpIndexError::NotFound(_)) => {
                                if height >= src.activation_height() {
                                    debug!(
                                        target: "events",
                                        height,
                                        "sp_tweaks row absent on connect at/above activation; \
                                         live BlockTweaks skipped (client replay will recover)",
                                    );
                                }
                            }
                            // A transient storage/decode fault reading the
                            // just-committed row would otherwise vanish silently,
                            // leaving a live tweaks subscriber with an (h-1, h+1)
                            // cursor jump it cannot detect until it reconnects.
                            // Surface it so a degraded index is observable.
                            Err(e) => {
                                warn!(
                                    target: "events",
                                    height,
                                    error = %e,
                                    "sp_tweaks read failed on connect; live BlockTweaks skipped \
                                     for this block (a tweaks subscriber must resync from its \
                                     cursor to recover it)",
                                );
                            }
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(target: "events", dropped = n, "chain bridge lagged");
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
        }
    }
}

async fn heartbeat_loop(
    publisher: Arc<EventPublisher>,
    period: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = interval(period);
    // Skip missed ticks on resume — a stalled task should not emit a
    // backlog of stale heartbeats. Drop the immediate tick at t=0 so the
    // first heartbeat is one full interval after start (matches typical
    // Prometheus-style cadence and avoids skewing latency measurements).
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = ticker.tick() => {
                let uptime_ns = publisher.started_monotonic.elapsed().as_nanos() as u64;
                publisher.publish(NodeEventBody::Heartbeat { uptime_ns });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::sink::testing::CaptureSink;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, Txid};
    use std::time::Duration;

    fn edge() -> EdgeIdentity {
        EdgeIdentity::new([0xab; 16], Some("us-east1")).unwrap()
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

    fn block_event(byte: u8, height: u32) -> ChainEvent {
        ChainEvent::BlockConnected {
            hash: BlockHash::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]),
            ),
            height,
        }
    }

    /// A `TweakEntry` whose txid matches `enter_event(byte)`, so a fake source
    /// can answer the bridge's lookup for that admission.
    fn tweak_entry(byte: u8) -> TweakEntry {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x33; 32]).unwrap());
        let txid =
            Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]));
        TweakEntry {
            txid,
            tweak: pk,
            max_taproot_value: bitcoin::Amount::from_sat(50_000),
            taproot_outputs: vec![node_sp_index::TaprootOutput {
                vout: 0,
                output_key: [byte; 32],
                value: bitcoin::Amount::from_sat(50_000),
            }],
        }
    }

    /// Mempool-tweak source that answers only for `byte`'s txid (mirrors an
    /// entry that cached a tweak at admission). `None` for anything else.
    struct FakeTweakSource {
        byte: u8,
    }
    impl MempoolTweakSource for FakeTweakSource {
        fn cached_tweak(&self, txid: &Txid) -> Option<TweakEntry> {
            let want =
                Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([self.byte; 32]));
            (txid == &want).then(|| tweak_entry(self.byte))
        }
    }

    #[tokio::test]
    async fn bridge_converts_mempool_event_with_stamp() {
        let publisher = EventPublisher::new(edge(), 16);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let sink = CaptureSink::new();
        let received = sink.received.clone();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx);

        // Yield so the sink subscriber registers before we publish.
        tokio::task::yield_now().await;

        mp_tx.send(enter_event(1)).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let envs = received.lock().clone();
        assert_eq!(envs.len(), 1);
        assert!(matches!(
            envs[0].body,
            NodeEventBody::Mempool(MempoolEvent::Enter { .. })
        ));
        assert_eq!(envs[0].stamp.node_id, [0xab; 16]);
        assert_eq!(envs[0].stamp.seq, 1);

        let _ = shutdown_tx.send(true);
    }

    #[test]
    fn mempool_tweak_guard_gates_and_shares_counter() {
        let publisher = EventPublisher::new(edge(), 16);
        assert!(!publisher.has_mempool_tweak_subscribers());
        // The gate accessor shares the same atomic the guard raises.
        let gate = publisher.mempool_tweaks_gate();
        assert_eq!(gate.load(Ordering::Relaxed), 0);
        {
            let _g = publisher.mempool_tweak_subscriber_guard();
            assert!(publisher.has_mempool_tweak_subscribers());
            assert_eq!(gate.load(Ordering::Relaxed), 1);
        }
        // Dropped guard decrements both views.
        assert!(!publisher.has_mempool_tweak_subscribers());
        assert_eq!(gate.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn bridge_emits_mempool_tweak_when_subscribed() {
        let publisher = EventPublisher::new(edge(), 16);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let sink = CaptureSink::new();
        let received = sink.received.clone();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        // A live mempool_tweaks subscription + a source that has the cached tweak.
        let _guard = publisher.mempool_tweak_subscriber_guard();
        let src: Arc<dyn MempoolTweakSource> = Arc::new(FakeTweakSource { byte: 1 });
        publisher.spawn_bridges_with_sp(
            mp_tx.subscribe(),
            ch_tx.subscribe(),
            None,
            Some(src),
            shutdown_rx,
        );
        tokio::task::yield_now().await;

        mp_tx.send(enter_event(1)).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let envs = received.lock().clone();
        // The Enter, then its MempoolTweak (in that order).
        assert_eq!(envs.len(), 2, "Enter + MempoolTweak");
        assert!(matches!(
            envs[0].body,
            NodeEventBody::Mempool(MempoolEvent::Enter { .. })
        ));
        match &envs[1].body {
            NodeEventBody::MempoolTweak(e) => {
                assert_eq!(e.max_value, 50_000);
                assert_eq!(
                    e.txid,
                    Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([1; 32]))
                );
                // The mempool tweak carries the tx's taproot outputs end-to-end
                // (source → cache → publish), so a client confirms the match at
                // admission without fetching the tx.
                assert_eq!(e.taproot_outputs.len(), 1);
                assert_eq!(e.taproot_outputs[0].output_key, [1; 32]);
            }
            other => panic!("expected MempoolTweak, got {other:?}"),
        }
        // Ephemeral: the tweak carries no durable cursor and is not in the
        // mempool replay window; only the Enter is replayable.
        assert!(envs[1].cursor.is_none(), "MempoolTweak has no cursor");
        assert_eq!(
            publisher.replay_mempool_since(0).len(),
            1,
            "replay ring holds the Enter but not the MempoolTweak",
        );

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn bridge_no_mempool_tweak_without_subscriber_or_cache() {
        // (a) subscriber present but source has no cached tweak → no emit.
        // (b) source has the tweak but no subscriber → no emit.
        for (with_sub, byte) in [(true, 9u8), (false, 1u8)] {
            let publisher = EventPublisher::new(edge(), 16);
            let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
            let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);

            let sink = CaptureSink::new();
            let received = sink.received.clone();
            publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
            let guard = with_sub.then(|| publisher.mempool_tweak_subscriber_guard());
            // Source only answers for txid byte 1; case (a) sends Enter(1) but
            // the source is byte 9 (miss), case (b) matches but no subscriber.
            let src: Arc<dyn MempoolTweakSource> = Arc::new(FakeTweakSource { byte });
            publisher.spawn_bridges_with_sp(
                mp_tx.subscribe(),
                ch_tx.subscribe(),
                None,
                Some(src),
                shutdown_rx,
            );
            tokio::task::yield_now().await;

            mp_tx.send(enter_event(1)).unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;

            let envs = received.lock().clone();
            assert_eq!(envs.len(), 1, "only the Enter, no MempoolTweak");
            assert!(matches!(
                envs[0].body,
                NodeEventBody::Mempool(MempoolEvent::Enter { .. })
            ));
            drop(guard);
            let _ = shutdown_tx.send(true);
        }
    }

    #[tokio::test]
    async fn seq_is_monotonic_across_mixed_streams() {
        let publisher = EventPublisher::new(edge(), 64);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(64);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let sink = CaptureSink::new();
        let received = sink.received.clone();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx);
        tokio::task::yield_now().await;

        // Interleave 5 mempool + 5 chain events.
        for i in 0..5 {
            mp_tx.send(enter_event(i as u8)).unwrap();
            ch_tx.send(block_event(i as u8 + 100, i as u32)).unwrap();
        }
        // Allow both bridges to drain.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let envs = received.lock().clone();
        assert_eq!(envs.len(), 10);
        let seqs: Vec<u64> = envs.iter().map(|e| e.stamp.seq).collect();
        let mut sorted = seqs.clone();
        sorted.sort();
        // Each seq must be unique and span exactly 1..=10.
        assert_eq!(sorted, (1..=10).collect::<Vec<u64>>());

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn heartbeat_fires_at_configured_cadence() {
        // Real wall clock with a tiny test cadence. `start_paused` is
        // brittle here because broadcast subscriber registration is
        // also driven by the runtime, and the timer-vs-subscriber race
        // is hard to settle deterministically under paused time.
        let publisher = EventPublisher::new(edge(), 16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let sink = CaptureSink::new();
        let received = sink.received.clone();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());

        let cadence = Duration::from_millis(20);
        publisher.spawn_heartbeat(cadence, shutdown_rx);

        // Wait for ~5 heartbeat intervals to elapse.
        tokio::time::sleep(cadence * 5 + Duration::from_millis(30)).await;

        let envs = received.lock().clone();
        let heartbeats: Vec<_> = envs
            .iter()
            .filter(|e| matches!(e.body, NodeEventBody::Heartbeat { .. }))
            .collect();
        assert!(
            heartbeats.len() >= 3,
            "expected ≥3 heartbeats, got {}",
            heartbeats.len()
        );

        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn shutdown_signal_stops_bridges_and_sinks() {
        let publisher = EventPublisher::new(edge(), 16);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let sink = CaptureSink::new();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx.clone());
        publisher.spawn_heartbeat(Duration::from_millis(50), shutdown_rx);

        // Send shutdown immediately. Without a timeout this would hang
        // if the bridges or sink ignored the watch.
        shutdown_tx.send(true).unwrap();

        // All spawned tasks should observe the watch and exit; we
        // verify by ensuring the publisher's broadcast receiver count
        // returns to 0 within a bounded window.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if publisher.out.receiver_count() == 0 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("subscribers should detach after shutdown");
    }

    #[tokio::test]
    async fn slow_sink_lags_without_panic() {
        // Tiny channel forces RecvError::Lagged when a sink falls behind.
        let publisher = EventPublisher::new(edge(), 4);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(64);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let sink = CaptureSink::new();
        let lag = sink.lag_total.clone();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx);
        tokio::task::yield_now().await;

        // Burst far past the channel capacity. The publisher's broadcast
        // is the bounded channel here; bridges run fast, sink gets
        // dropped events and reports them via the lag counter.
        for i in 0..200u8 {
            mp_tx.send(enter_event(i)).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        // We should have observed lag at least once. The exact count
        // depends on scheduler timing; the contract is "non-zero, no
        // panic, sink keeps running".
        assert!(lag.load(Ordering::Relaxed) > 0);
        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn edge_wall_ns_advances_with_real_time() {
        // Two events separated by a real sleep should have edge_wall_ns
        // values whose delta is at least ~10ms — confirming we resample
        // SystemTime per event rather than computing from a frozen
        // start anchor.
        let publisher = EventPublisher::new(edge(), 16);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let sink = CaptureSink::new();
        let received = sink.received.clone();
        publisher.attach_sinks(vec![Box::new(sink)], shutdown_rx.clone());
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx);
        tokio::task::yield_now().await;

        mp_tx.send(enter_event(1)).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        mp_tx.send(enter_event(2)).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let envs = received.lock().clone();
        assert_eq!(envs.len(), 2);
        let delta = envs[1].stamp.edge_wall_ns.saturating_sub(envs[0].stamp.edge_wall_ns);
        assert!(
            delta > 10_000_000,
            "edge_wall_ns delta should reflect real elapsed time (got {} ns)",
            delta,
        );
        let _ = shutdown_tx.send(true);
    }

    #[tokio::test]
    async fn no_subscribers_no_panic() {
        // Publishing without any sinks attached must not panic.
        let publisher = EventPublisher::new(edge(), 4);
        let (mp_tx, _) = broadcast::channel::<MempoolEvent>(16);
        let (ch_tx, _) = broadcast::channel::<ChainEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        publisher.spawn_bridges(mp_tx.subscribe(), ch_tx.subscribe(), shutdown_rx);

        for i in 0..5u8 {
            mp_tx.send(enter_event(i)).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = shutdown_tx.send(true);
    }
}
