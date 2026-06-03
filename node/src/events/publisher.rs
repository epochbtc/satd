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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{broadcast, watch};
use tokio::time::{Duration, MissedTickBehavior, interval};
use tracing::{info, warn};

use crate::chain::events::ChainEvent;
use crate::mempool::events::MempoolEvent;

use super::envelope::{EdgeIdentity, EdgeStamp, NodeEvent, NodeEventBody};
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
}

impl EventPublisher {
    /// Build a new publisher. `capacity` is the broadcast buffer size;
    /// pass [`ENVELOPE_BROADCAST_CAPACITY`] for the default.
    pub fn new(edge: EdgeIdentity, capacity: usize) -> Arc<Self> {
        let (out, _rx) = broadcast::channel(capacity);
        Arc::new(Self {
            out,
            edge,
            seq: AtomicU64::new(0),
            started_monotonic: Instant::now(),
            replay_ring: Mutex::new(VecDeque::with_capacity(REPLAY_RING_CAPACITY)),
        })
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
        {
            let mut ring = self
                .replay_ring
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if ring.len() == REPLAY_RING_CAPACITY {
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

    /// Spawn the bridge tasks: one for the mempool broadcast and one
    /// for the chain broadcast. Each task runs until the broadcast
    /// sender is closed or `shutdown` flips to `true`.
    pub fn spawn_bridges(
        self: &Arc<Self>,
        mempool_rx: broadcast::Receiver<MempoolEvent>,
        chain_rx: broadcast::Receiver<ChainEvent>,
        shutdown: watch::Receiver<bool>,
    ) {
        // Mempool bridge.
        {
            let publisher = self.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                bridge_mempool(publisher, mempool_rx, shutdown).await;
            });
        }
        // Chain bridge.
        {
            let publisher = self.clone();
            tokio::spawn(async move {
                bridge_chain(publisher, chain_rx, shutdown).await;
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
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            res = rx.recv() => match res {
                Ok(ev) => publisher.publish(NodeEventBody::Mempool(ev)),
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
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            res = rx.recv() => match res {
                Ok(ev) => publisher.publish(NodeEventBody::Chain(ev)),
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
