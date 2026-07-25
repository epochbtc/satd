//! The alert webhook dispatcher.
//!
//! One fan-in task reads the event bus; one delivery task per configured hook
//! owns an outbound HTTP client and a bounded queue. `satd-alert` holds the
//! rules (what matches, how it is signed, when to retry); everything here is
//! the plumbing that runs them against a real socket.
//!
//! # Invariants
//!
//! **Nothing blocks consensus.** The fan-in `try_send`s into bounded queues and
//! drops on overflow; the delivery tasks run on the isolated API runtime. There
//! is no path from a slow endpoint back to block connection — the isolation is
//! structural, not a timeout budget. (The dispatcher this replaces ran its
//! outbound HTTP on the consensus runtime.)
//!
//! **A gap is never silent.** Both drop paths — a full hook queue and a lagged
//! broadcast receiver — set the hook's gap flag. Before its next delivery the
//! hook emits a synthesized `Lagged` body carrying the number of events lost
//! and the cursor to resume from, so a receiver that cares can go fetch the
//! span it missed.
//!
//! **Delivery is serial and ordered per hook.** One request in flight at a
//! time, so a receiver observes events in the order the node produced them and
//! a retry cannot be overtaken by the event behind it.
//!
//! **A dead endpoint degrades only itself.** Retries back off to a five-minute
//! ceiling and never give up on a transient failure, but a permanent 4xx skips
//! the event rather than pinning the head of the queue — a receiver returning
//! 404 forever must not convert every subsequent event into an overflow drop.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use node::events::{Cursor, EventPublisher, NodeEvent, NodeEventBody};
use node::metrics::{HookCounters, WebhookMetrics};
use node::storage::Store;
use satd_alert::{AlertFile, Hook, HOOK_QUEUE_CAPACITY};
use tokio::sync::{mpsc, watch};

/// Hook id the legacy `reorgwebhook=` alias reports under, in metric labels and
/// the `X-Satd-Hook` header. Namespaced so it can never collide with an
/// operator-chosen alertfile id (`-` is allowed in ids, but this exact string
/// is documented as reserved).
pub const LEGACY_REORG_HOOK_ID: &str = "reorg-legacy";

/// Per-attempt HTTP timeout. Matches the shipped reorg webhook.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How far back a hook's startup catch-up may replay. Shares the streaming
/// API's clamp so a webhook receiver and a streaming client see the same
/// "resync below this height yourself" boundary.
const MAX_CATCHUP_BLOCKS: u32 = node::events::MAX_REPLAY_BLOCKS;

/// How often a pending gap notice is flushed when no event is driving the hook.
const GAP_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Numbers synthesized deliveries — catch-up replay events and gap notices.
///
/// Process-wide rather than per-generation, for the same reason the watch
/// counter is: a SIGHUP reload keeps the same `instance_id`, so a per-generation
/// counter would restart at zero and re-mint ids the receiver has already seen.
static SYNTH_DELIVERY_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Composite stop signal: the process-wide shutdown, plus a per-generation
/// channel the SIGHUP reload flips to retire the previous dispatcher.
///
/// Two channels rather than one because a reload must stop *this* generation's
/// tasks without touching the global signal every other subsystem watches.
#[derive(Clone)]
pub struct Stop {
    global: watch::Receiver<bool>,
    generation: watch::Receiver<bool>,
}

impl Stop {
    fn stopped(&self) -> bool {
        *self.global.borrow() || *self.generation.borrow()
    }

    /// Resolve once either channel signals. Cancel-safe: `changed()` only
    /// marks a value seen when it completes, and the loop re-checks both
    /// borrows, so being dropped inside a `select!` loses nothing.
    async fn wait(&mut self) {
        loop {
            if self.stopped() {
                return;
            }
            tokio::select! {
                _ = self.global.changed() => {}
                _ = self.generation.changed() => {}
            }
        }
    }
}

/// What a hook's delivery task receives.
enum Delivery {
    /// An event to deliver, pre-rendered to the exact bytes that will be
    /// signed and sent. Rendering happens once in the fan-in rather than per
    /// hook so a body is never serialized differently for two receivers.
    Event {
        body: Arc<Vec<u8>>,
        delivery_id: String,
        /// Cursor to persist once the receiver acks, if this event carries one.
        cursor: Option<Cursor>,
    },
}

struct HookChannel {
    id: String,
    hook: Hook,
    tx: mpsc::Sender<Delivery>,
    counters: Arc<HookCounters>,
    /// Set when an event was dropped for this hook; cleared when the resulting
    /// `Lagged` notice has been queued.
    gap: Arc<GapState>,
    /// Whether the "delivery task is gone" warning has already been logged for
    /// this generation. Per-generation on purpose: a reload should re-report a
    /// genuinely dead hook once, not stay quiet because a retired generation
    /// already said so.
    reported_closed: std::sync::atomic::AtomicBool,
}

/// Accumulated drop state for one hook.
#[derive(Default)]
struct GapState {
    dropped: std::sync::atomic::AtomicU64,
    /// Position of the last event successfully queued before the gap — the
    /// anchor a receiver resumes from.
    resume_height: std::sync::atomic::AtomicU32,
}

/// Per-hook gap state, keyed by hook id, living as long as the process.
///
/// Deliberately not per-generation. A reload retires the generation that
/// accumulated a drop count, and per-generation state would take the pending
/// `Lagged` notice down with it — the receiver would never learn about a hole
/// that satd had already recorded. `HookCounters` is process-lived for the same
/// reason; this is the half that was missed.
static GAP_STATE: std::sync::LazyLock<
    parking_lot::Mutex<std::collections::HashMap<String, Arc<GapState>>>,
> = std::sync::LazyLock::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

fn gap_state_for(id: &str) -> Arc<GapState> {
    let mut map = GAP_STATE.lock();
    Arc::clone(map.entry(id.to_string()).or_default())
}

/// Whether this node has ever been observed out of initial block download.
///
/// `is_initial_block_download()` is a function of the tip header's age, not of
/// whether a sync is in progress: a node whose tip stops advancing crosses back
/// into "IBD" 24 hours later. Without this latch the alert path would go dark
/// during exactly the incident it exists to report — a stalled tip — and, worse,
/// resume by advancing the durable cursor across everything it suppressed.
/// Once a node has been caught up, it is never "syncing" again for the
/// dispatcher's purposes.
static LEFT_IBD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Spawn the dispatcher for a parsed alertfile.
///
/// Must be called from within the API runtime — every task spawned here does
/// outbound HTTP, which is exactly what must never share the consensus runtime.
/// Returns `None` when the file configures no hooks, so a node with an empty
/// alertfile starts no tasks at all.
fn spawn_with_metrics(
    file: &AlertFile,
    publisher: Arc<EventPublisher>,
    store: Arc<dyn Store>,
    block_source: Option<Arc<dyn node::events::BlockCursorSource>>,
    metrics: Arc<WebhookMetrics>,
    stop: Stop,
) {
    if file.hooks.is_empty() {
        return;
    }
    let mut hooks = Vec::new();
    for hook in &file.hooks {
        let (tx, rx) = mpsc::channel::<Delivery>(HOOK_QUEUE_CAPACITY);
        let counters = metrics.hook(&hook.id);
        let gap = gap_state_for(&hook.id);
        tokio::spawn(deliver_loop(
            hook.clone(),
            rx,
            counters.clone(),
            gap.clone(),
            store.clone(),
            stop.clone(),
        ));
        hooks.push(HookChannel {
            id: hook.id.clone(),
            hook: hook.clone(),
            tx,
            counters,
            gap,
            reported_closed: std::sync::atomic::AtomicBool::new(false),
        });
    }
    tokio::spawn(fan_in(hooks, publisher, store, block_source, stop));
}

/// Fan-in: one broadcast receiver, filtered and enqueued per hook.
async fn fan_in(
    hooks: Vec<HookChannel>,
    publisher: Arc<EventPublisher>,
    store: Arc<dyn Store>,
    block_source: Option<Arc<dyn node::events::BlockCursorSource>>,
    mut stop: Stop,
) {
    // Subscribe BEFORE the catch-up replay, so an event published while the
    // replay is being built is buffered rather than lost in the seam.
    let mut rx = publisher.subscribe();

    // Per-hook snapshot→live boundary dedup, exactly as the gRPC and WS
    // carriers keep. A block connecting between `subscribe()` and the tip
    // snapshot taken inside `catch_up` is *both* buffered on the broadcast and
    // inside the replayed span, so without this it is delivered twice — and
    // because the replayed copy is re-synthesized with its own delivery id, the
    // two carry different idempotency keys and a conforming receiver cannot
    // collapse them. A duplicate deposit alert is exactly the failure the
    // idempotency contract exists to prevent.
    let mut dedup: Vec<std::collections::HashMap<u32, bitcoin::BlockHash>> =
        Vec::with_capacity(hooks.len());
    for hook in &hooks {
        dedup.push(catch_up(hook, &publisher, store.as_ref(), block_source.as_deref()).await);
    }

    // Per-hook heartbeat downsampling state (D11): last forwarded instant.
    let mut last_heartbeat: Vec<Option<std::time::Instant>> = vec![None; hooks.len()];

    tracing::info!(
        target: "alert",
        hooks = hooks.len(),
        "alert webhook dispatcher started",
    );

    // A gap notice is otherwise only emitted ahead of the *next* event for that
    // hook, so a hook whose traffic stops right after a drop holds it
    // indefinitely — and traffic stopping is correlated with the drop, not
    // independent of it. The one message that must not wait is the one saying
    // data was lost.
    let mut gap_flush = tokio::time::interval(GAP_FLUSH_INTERVAL);
    gap_flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = stop.wait() => break,
            _ = gap_flush.tick() => {
                for hook in &hooks {
                    flush_gap(hook, &publisher);
                }
            }
            recv = rx.recv() => match recv {
                Ok(env) => {
                    // Suppress the firehose during initial block download.
                    //
                    // The dispatcher is started long before P2P, so without
                    // this a brand-new node with an alertfile POSTs its entire
                    // sync — one `block_connected` per historical block, plus a
                    // watch-match per historical transaction touching a watched
                    // script, for as long as IBD takes. That is the opposite of
                    // what the manual promises, and the failure mode is a
                    // multi-day firehose at the receiver rather than anything
                    // that looks like a bug locally.
                    //
                    // Latched (see `LEFT_IBD`), because the predicate is the
                    // tip's age rather than a sync flag. Once latched the
                    // `block_source` call is skipped entirely, which also keeps
                    // a per-event RocksDB block-index lookup off this task.
                    //
                    // Status and heartbeat events are exempt. "This node is
                    // unhealthy" is exactly as true during IBD, and the
                    // detectors already suppress the conditions that are
                    // meaningless while syncing. A heartbeat is a dead-man's
                    // switch: suppressing it during a multi-day sync makes an
                    // external watchdog declare a healthy node dead, which
                    // inverts the signal it exists to carry.
                    let syncing = !LEFT_IBD.load(Ordering::Relaxed) && {
                        let in_ibd = block_source
                            .as_deref()
                            .is_some_and(|s| s.in_initial_block_download());
                        if !in_ibd {
                            LEFT_IBD.store(true, Ordering::Relaxed);
                        }
                        in_ibd
                    };
                    let exempt = matches!(
                        env.body,
                        NodeEventBody::Status(_) | NodeEventBody::Heartbeat { .. }
                    );
                    // Decide who wants this *before* rendering it. Serializing
                    // first meant a `BlockTweaks` envelope — hundreds of KB of
                    // per-block silent-payment rows — was rendered in full and
                    // then discarded, since tweaks are refused at parse and can
                    // never be in any hook's mask.
                    let wanted: Vec<usize> = hooks
                        .iter()
                        .enumerate()
                        .filter(|(i, hook)| accepts(&hook.hook, &env, &mut last_heartbeat[*i]))
                        .map(|(i, _)| i)
                        .collect();
                    if wanted.is_empty() {
                        continue;
                    }
                    if syncing && !exempt {
                        // Record the suppression as a gap rather than dropping
                        // it silently. A silent skip would leave no counter
                        // moved and no `lagged` body emitted, and the first
                        // post-IBD delivery would then advance the durable
                        // cursor straight across everything suppressed — making
                        // the span unrecoverable on the next restart while the
                        // module claims at-least-once. Counting it means the
                        // receiver is told, and the resume anchor still points
                        // before the hole.
                        for i in wanted {
                            hooks[i].gap.dropped.fetch_add(1, Ordering::Relaxed);
                            hooks[i].counters.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        continue;
                    }
                    // Render once for every hook: the body a receiver verifies
                    // must be the bytes a WS subscriber would have seen, and
                    // rendering per hook risks two receivers disagreeing.
                    let Ok(bytes) = serde_json::to_vec(&env) else {
                        tracing::warn!(target: "alert", "skipping event: serialization failed");
                        continue;
                    };
                    let body = Arc::new(bytes);
                    let delivery_id = satd_alert::delivery_id(
                        &hex::encode(env.stamp.node_id),
                        publisher.instance_id(),
                        env.stamp.seq,
                    );
                    for i in wanted {
                        let hook = &hooks[i];
                        // A live block identical to one already replayed for
                        // this hook. A reorg replacement at the same height has
                        // a different hash and is forwarded, which is why the
                        // check is on the hash and not the height alone.
                        if !dedup[i].is_empty()
                            && let NodeEventBody::Chain(
                                node::chain::events::ChainEvent::BlockConnected { height, hash },
                            ) = &env.body
                            && dedup[i].get(height) == Some(hash)
                        {
                            dedup[i].remove(height);
                            continue;
                        }
                        enqueue(hook, &publisher, Delivery::Event {
                            body: body.clone(),
                            delivery_id: delivery_id.clone(),
                            cursor: env.cursor,
                        }, env.cursor);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // The dispatcher itself fell behind the bus. Every hook
                    // missed the same span, so every hook is told.
                    tracing::warn!(target: "alert", dropped = n, "alert dispatcher lagged the event bus");
                    for hook in &hooks {
                        hook.gap.dropped.fetch_add(n, Ordering::Relaxed);
                        hook.counters.dropped.fetch_add(n, Ordering::Relaxed);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
        }
    }
    tracing::info!(target: "alert", "alert webhook dispatcher stopped");
}

/// Queue an event for one hook, converting an overflow into a recorded gap.
///
/// Returns whether the event was queued. Callers that need a count must use
/// this rather than diffing `counters.dropped`: those counters are process-lived
/// and shared across generations, so a retired generation still shedding events
/// perturbs the delta — which, on a subtraction, underflowed.
fn enqueue(
    hook: &HookChannel,
    publisher: &EventPublisher,
    item: Delivery,
    cursor: Option<Cursor>,
) -> bool {
    // Emit the pending gap notice ahead of the event that follows it, so the
    // receiver learns about the hole before it sees the data after it.
    flush_gap(hook, publisher);
    match hook.tx.try_send(item) {
        Ok(()) => {
            hook.counters
                .queue_depth
                .store(queue_depth(&hook.tx) as u64, Ordering::Relaxed);
            if let Some(c) = cursor {
                hook.gap.resume_height.store(c.height, Ordering::Relaxed);
            }
            true
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            // A receiver that cannot keep up degrades to "you missed N" rather
            // than back-pressuring the bus.
            hook.gap.dropped.fetch_add(1, Ordering::Relaxed);
            hook.counters.dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // The delivery task is gone: it failed to build its HTTP client, or
            // it panicked. Silently ignoring this makes the hook look perfectly
            // healthy on `/metrics` — `dropped_total` flat, `queue_depth` flat,
            // no `Lagged` ever synthesized — while it delivers nothing at all,
            // forever. Count it like any other loss so the existing
            // "no successful delivery in N minutes" rule fires.
            hook.gap.dropped.fetch_add(1, Ordering::Relaxed);
            hook.counters.dropped.fetch_add(1, Ordering::Relaxed);
            // Logged once per hook, not once per event. This arm is reached on
            // every event once a delivery task is gone — including for a
            // generation being retired by a reload, where it is expected — and
            // an unrated line here is thousands per second on a busy mempool,
            // filling the very disk `disk_low` is watching.
            if !hook.reported_closed.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    target: "alert",
                    hook = %hook.id,
                    "hook delivery task is gone; events for this hook are being dropped",
                );
            }
            false
        }
    }
}

/// If events were dropped for this hook, queue a `Lagged` notice describing the
/// gap. Best-effort: if the queue is still full the notice waits for the next
/// opportunity, and the drop count keeps accumulating in the meantime.
fn flush_gap(hook: &HookChannel, publisher: &EventPublisher) {
    let dropped = hook.gap.dropped.swap(0, Ordering::Relaxed);
    if dropped == 0 {
        return;
    }
    let resume = publisher.resume_cursor(hook.gap.resume_height.load(Ordering::Relaxed), 0);
    let env = node::events::lagged_event(publisher, dropped, resume);
    let Ok(bytes) = serde_json::to_vec(&env) else {
        return;
    };
    let item = Delivery::Event {
        body: Arc::new(bytes),
        // Synthesized envelope: `stamp.seq` is 0 for every one of these, so it
        // gets an id from the replay space instead. Without this every gap
        // notice in the process would carry the same idempotency key and a
        // conforming receiver would discard all but the first — "a gap is never
        // silent" would hold exactly once.
        delivery_id: satd_alert::replay_delivery_id(
            &hex::encode(env.stamp.node_id),
            publisher.instance_id(),
            SYNTH_DELIVERY_SEQ.fetch_add(1, Ordering::Relaxed).wrapping_add(1),
        ),
        cursor: None,
    };
    if hook.tx.try_send(item).is_err() {
        // Still full — put the count back so the notice is not lost.
        hook.gap.dropped.fetch_add(dropped, Ordering::Relaxed);
    }
}

fn queue_depth(tx: &mpsc::Sender<Delivery>) -> usize {
    HOOK_QUEUE_CAPACITY.saturating_sub(tx.capacity())
}

/// Whether a hook wants this event, applying category, kind, severity, and
/// heartbeat-downsampling filters in that order.
fn accepts(hook: &Hook, env: &NodeEvent, last_heartbeat: &mut Option<std::time::Instant>) -> bool {
    match &env.body {
        NodeEventBody::Status(s) => hook.filter.accepts_status(s.kind, s.severity),
        NodeEventBody::Heartbeat { .. } => {
            let Some(interval) = hook.heartbeat_interval_secs else {
                return false;
            };
            if !hook.filter.categories.contains(node::events::CATEGORY_HEARTBEAT) {
                return false;
            }
            // The bus beats at 1 Hz; a dead-man's-switch receiver wants one
            // ping per interval, not sixty.
            let now = std::time::Instant::now();
            let due = last_heartbeat
                .map(|t| now.duration_since(t).as_secs() >= interval)
                .unwrap_or(true);
            if due {
                *last_heartbeat = Some(now);
            }
            due
        }
        // A lag notice is a control signal: it reaches every hook regardless of
        // filter, exactly as it reaches every streaming subscriber.
        NodeEventBody::Lagged { .. } => true,
        other => {
            // Tweaks are refused at parse (never in a hook's mask), and the
            // remaining bodies map to their category bit.
            let bit = match other {
                NodeEventBody::Mempool(_) => node::events::CATEGORY_MEMPOOL,
                NodeEventBody::Chain(_) => node::events::CATEGORY_CHAIN,
                _ => return false,
            };
            hook.filter.categories.contains(bit)
        }
    }
}

/// Replay the confirmed events a hook missed while the daemon was down.
///
/// Only the chain category has durable history to replay; status is re-raised
/// by the detectors instead, and mempool events are ephemeral by construction.
/// A cursor older than the clamp yields a leading `Lagged` notice — the same
/// deterministic "resync below this height yourself" signal a streaming client
/// gets.
async fn catch_up(
    hook: &HookChannel,
    publisher: &EventPublisher,
    store: &dyn Store,
    block_source: Option<&dyn node::events::BlockCursorSource>,
) -> std::collections::HashMap<u32, bitcoin::BlockHash> {
    if !hook
        .hook
        .filter
        .categories
        .contains(node::events::CATEGORY_CHAIN)
    {
        return Default::default();
    }
    let Some(src) = block_source else {
        return Default::default();
    };
    let Some(cursor) = read_cursor(store, &hook.hook) else {
        // A hook that has never delivered starts at the live head rather than
        // replaying history nobody asked for.
        return Default::default();
    };
    // Seed the gap anchor from the durable cursor before any replay is queued.
    // `resume_height` is otherwise only set by a successful enqueue, so a hook
    // that lags before its first one — a fresh generation whose catch-up burst
    // overflows immediately — would emit a `Lagged` advertising height 0, which
    // reads as "resume from genesis" rather than "resume from where you were".
    hook.gap
        .resume_height
        .store(cursor.height, Ordering::Relaxed);

    let replay = node::events::build_cursor_replay(
        src,
        publisher,
        cursor,
        node::events::CATEGORY_CHAIN,
        MAX_CATCHUP_BLOCKS,
        None,
    );
    if replay.clamped {
        // Replay begins at `cursor.height + 1`, so the number of blocks skipped
        // is the distance to the first one actually replayed, not to the cursor
        // itself — the latter counts the already-delivered block at the cursor.
        let dropped =
            u64::from(replay.earliest_replayed.saturating_sub(cursor.height.saturating_add(1)));
        hook.gap.dropped.fetch_add(dropped, Ordering::Relaxed);
        hook.counters.dropped.fetch_add(dropped, Ordering::Relaxed);
        hook.gap.resume_height.store(cursor.height, Ordering::Relaxed);
        tracing::warn!(
            target: "alert",
            hook = %hook.id,
            from = cursor.height,
            earliest = replay.earliest_replayed,
            "webhook catch-up clamped; receiver must resync the older span itself",
        );
    }
    let count = replay.events.len();
    let mut queued = 0u64;
    let mut overflowed = 0u64;
    let mut queued_heights: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for env in replay.events {
        let height = match &env.body {
            NodeEventBody::Chain(node::chain::events::ChainEvent::BlockConnected {
                height,
                ..
            }) => Some(*height),
            _ => None,
        };
        let Ok(bytes) = serde_json::to_vec(&env) else {
            continue;
        };
        let cursor = env.cursor;
        // Every replayed envelope is stamped `seq: 0`, so minting from it would
        // give a node that was down for 100 blocks 100 deliveries sharing one
        // idempotency key — the whole point of catch-up defeated silently.
        //
        // A replayed block takes an id derived from its height rather than a
        // process counter. This is the one event the design really can deliver
        // twice (a restart, or a reload whose generations overlap), and every
        // counter-minted id embeds a per-process random `instance_id`, so the
        // duplicate would arrive under a fresh id and "deduplicate on
        // X-Satd-Delivery" would be unimplementable for the only case that
        // needs it. Non-block replays keep the counter — they carry no durable
        // position to key on.
        let delivery_id = match height {
            Some(h) => satd_alert::block_delivery_id(&hex::encode(env.stamp.node_id), h),
            None => satd_alert::replay_delivery_id(
                &hex::encode(env.stamp.node_id),
                publisher.instance_id(),
                SYNTH_DELIVERY_SEQ.fetch_add(1, Ordering::Relaxed).wrapping_add(1),
            ),
        };
        if enqueue(
            hook,
            publisher,
            Delivery::Event {
                body: Arc::new(bytes),
                delivery_id,
                cursor,
            },
            cursor,
        ) {
            queued += 1;
            if let Some(h) = height {
                queued_heights.insert(h);
            }
        } else {
            overflowed += 1;
        }
    }
    if count > 0 {
        // Report what was *queued*, not what was built. The 10k-block replay
        // clamp warns loudly, but the hook queue holds 1024 — and for any
        // realistic outage the queue is the binding limit, since 1024 blocks is
        // about a week and 10k is about ten. Overflow inside this loop is
        // counted but was otherwise unlogged, so the success line reported the
        // pre-truncation figure and read as if everything had been recovered.
        if overflowed > 0 {
            tracing::warn!(
                target: "alert",
                hook = %hook.id,
                built = count,
                dropped = overflowed,
                "webhook catch-up exceeded the hook queue; the excess is lost \
                 and reported to the receiver as a gap",
            );
        }
        tracing::info!(
            target: "alert",
            hook = %hook.id,
            events = queued,
            from = cursor.height,
            "webhook catch-up queued events missed while the daemon was down",
        );
    }
    // Only suppress the live copy of a block this hook actually received. The
    // replay builds up to 10,000 events into a queue that holds 1024, so on a
    // long outage most of the tail overflows — and the tail is exactly the span
    // still buffered on the broadcast, i.e. the blocks whose live copies are
    // about to arrive. Keeping a dropped block in the dedup map suppresses that
    // live copy too, dropping the same block twice.
    let mut dedup = replay.confirmed_dedup;
    dedup.retain(|height, _| queued_heights.contains(height));
    dedup
}

fn read_cursor(store: &dyn Store, hook: &Hook) -> Option<Cursor> {
    let raw = store.read_alert_cursor(&hook.cursor_key())?;
    decode_cursor(&raw)
}

/// Cursors are stored as a fixed 24-byte little-endian record rather than JSON:
/// the format is written and read only here, and a fixed layout cannot acquire
/// a parse failure mode as the `Cursor` type grows fields.
fn encode_cursor(c: &Cursor) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[0..4].copy_from_slice(&c.height.to_le_bytes());
    out[4..8].copy_from_slice(&c.tx_index.to_le_bytes());
    out[8..16].copy_from_slice(&c.mempool_seq.to_le_bytes());
    out[16..24].copy_from_slice(&c.instance_id.to_le_bytes());
    out
}

fn decode_cursor(raw: &[u8]) -> Option<Cursor> {
    if raw.len() != 24 {
        return None;
    }
    Some(Cursor {
        height: u32::from_le_bytes(raw[0..4].try_into().ok()?),
        tx_index: u32::from_le_bytes(raw[4..8].try_into().ok()?),
        mempool_seq: u64::from_le_bytes(raw[8..16].try_into().ok()?),
        instance_id: u64::from_le_bytes(raw[16..24].try_into().ok()?),
    })
}

/// The HTTP client every webhook delivery goes through.
///
/// Redirects are **not** followed. The alertfile URL is validated once, at load
/// (scheme, and a warning for a non-loopback plaintext target), and a followed
/// redirect would silently move the request — body, `X-Satd-Signature`, and the
/// hook's identity — to a host that never passed that check. The interesting
/// destinations are exactly the ones an operator cannot see: a cloud metadata
/// endpoint, an RFC1918 admin port, the node's own RPC. HTTPS does not help;
/// a 302 to `http://169.254.169.254/` is a perfectly valid response.
///
/// A receiver that wants to move must publish a stable final URL and have the
/// operator update the alertfile. A 3xx classifies as a permanent drop, so the
/// misconfiguration shows up in the logs rather than as silent non-delivery.
fn webhook_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

/// Persist a hook's resume position, at most once per block height.
///
/// The cursor is a resume hint, not a ledger: one RocksDB write per delivered
/// event would be pure write amplification for a value only read at startup.
fn persist_cursor(
    hook: &Hook,
    store: &dyn Store,
    cursor: Option<Cursor>,
    persisted_height: &mut Option<u32>,
) {
    let Some(c) = cursor else { return };
    if *persisted_height == Some(c.height) {
        return;
    }
    // Never move a hook's durable cursor backwards.
    //
    // `persisted_height` is this task's own view and starts empty for a fresh
    // generation, so it cannot see what a *retired* generation is still doing.
    // A reload spawns the new generation before signalling the old one to stop,
    // and an in-flight POST is not inside the stop `select!` — so a delivery
    // retired mid-request can land up to `REQUEST_TIMEOUT` later and write a
    // cursor the new generation has already advanced past. Rewinding it means
    // the next restart replays a span the receiver already acked.
    if let Some(existing) = store
        .read_alert_cursor(&hook.cursor_key())
        .and_then(|raw| decode_cursor(&raw))
        && existing.height > c.height
    {
        *persisted_height = Some(existing.height);
        return;
    }
    match store.write_alert_cursor(&hook.cursor_key(), &encode_cursor(&c)) {
        Ok(()) => *persisted_height = Some(c.height),
        Err(e) => {
            tracing::warn!(target: "alert", hook = %hook.id, error = %e, "failed to persist webhook cursor")
        }
    }
}

/// One hook's delivery loop: serial, in-order, retrying with backoff.
async fn deliver_loop(
    hook: Hook,
    mut rx: mpsc::Receiver<Delivery>,
    counters: Arc<HookCounters>,
    gap: Arc<GapState>,
    store: Arc<dyn Store>,
    mut stop: Stop,
) {
    let client = match webhook_client() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(target: "alert", hook = %hook.id, error = %e, "failed to build webhook HTTP client; this hook will not deliver");
            return;
        }
    };
    // Only persist a cursor when it actually moves forward a block: the cursor
    // is a resume hint, not a ledger, and one RocksDB write per delivered event
    // would be pure write amplification.
    let mut persisted_height: Option<u32> = None;

    loop {
        let item = tokio::select! {
            _ = stop.wait() => return,
            item = rx.recv() => match item {
                Some(i) => i,
                None => return,
            },
        };
        let Delivery::Event {
            body,
            delivery_id,
            cursor,
        } = item;

        counters
            .queue_depth
            .store(rx.len() as u64, Ordering::Relaxed);

        // Signed once, outside the retry loop, and reused for every attempt:
        // the signature must be stable across retries of one event (the
        // attempt counter rides in a header, deliberately not in the body or
        // the signed material), and the timestamp records when satd *signed*
        // this delivery, not when it last retried it. A receiver enforcing a
        // freshness window therefore sees a delivery age out if it is still
        // being retried after the window, which is the intended behavior: a
        // 20-minute-old "disk is filling" alert is not worth acting on.
        let signed_at = unix_secs();
        let signature =
            satd_alert::sign_v2(&hook.secret, signed_at, &delivery_id, &hook.id, &body);
        let mut attempt: u32 = 0;
        loop {
            attempt = attempt.saturating_add(1);
            let result = client
                .post(&hook.url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(satd_alert::SIGNATURE_HEADER, &signature)
                .header(satd_alert::TIMESTAMP_HEADER, signed_at.to_string())
                .header(satd_alert::DELIVERY_HEADER, &delivery_id)
                .header(satd_alert::HOOK_HEADER, &hook.id)
                .header(satd_alert::ATTEMPT_HEADER, attempt.to_string())
                .header(satd_alert::WEBHOOK_VERSION_HEADER, satd_alert::WEBHOOK_VERSION)
                .body(body.as_ref().clone())
                .send()
                .await;
            let status = match &result {
                Ok(r) => Some(r.status().as_u16()),
                Err(_) => None,
            };
            match satd_alert::classify_response(status) {
                satd_alert::Disposition::Delivered => {
                    counters.delivered.fetch_add(1, Ordering::Relaxed);
                    counters
                        .last_success_unix
                        .store(unix_secs(), Ordering::Relaxed);
                    persist_cursor(&hook, store.as_ref(), cursor, &mut persisted_height);
                    break;
                }
                satd_alert::Disposition::Drop => {
                    counters.failed_attempts.fetch_add(1, Ordering::Relaxed);
                    counters.dropped.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        target: "alert",
                        hook = %hook.id,
                        status = ?status,
                        delivery = %delivery_id,
                        "webhook receiver rejected the delivery permanently; skipping this event",
                    );
                    // Record it as a gap, so the receiver is told in-band.
                    //
                    // This is the one drop path that did not, and it is the one
                    // most likely to fire on a routine misconfiguration: a 3xx
                    // (an `http://` URL behind a proxy that redirects to HTTPS)
                    // and a 401 (a rotated secret, or a delivery that aged past
                    // the receiver's freshness window while being retried) are
                    // both permanent by this classification. Without a `lagged`
                    // body the receiver has no way to learn which events it
                    // lost, and — because the cursor advances below — no way to
                    // recover them after the misconfiguration is fixed.
                    gap.dropped.fetch_add(1, Ordering::Relaxed);
                    // Advance the cursor anyway. A permanent rejection is the
                    // receiver's decision about this event, and it will decide
                    // the same way next time — leaving the cursor parked would
                    // make every restart rebuild and re-queue the same span
                    // against an endpoint that has already refused it, forever.
                    // The event is lost either way; the difference is whether
                    // the hook makes progress past it. The drop is counted
                    // (`satd_alertwebhook_dropped_total`), logged, and now
                    // announced to the receiver, so the loss is visible on both
                    // ends rather than silent.
                    persist_cursor(&hook, store.as_ref(), cursor, &mut persisted_height);
                    break;
                }
                satd_alert::Disposition::Retry => {
                    counters.failed_attempts.fetch_add(1, Ordering::Relaxed);
                    match &result {
                        Ok(r) => tracing::warn!(target: "alert", hook = %hook.id, status = %r.status(), attempt, "webhook delivery failed; retrying"),
                        Err(e) => tracing::warn!(target: "alert", hook = %hook.id, error = %e, attempt, "webhook request failed; retrying"),
                    }
                    let delay = satd_alert::retry::jitter(
                        satd_alert::retry_delay(attempt),
                        rand::random::<u64>(),
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = stop.wait() => return,
                    }
                }
            }
        }
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Owns the running dispatcher generation and re-spawns it on SIGHUP.
///
/// `alertfile=` follows the `authfile=` model: the *path* is restart-only, the
/// *contents* are re-read on every SIGHUP even when no `bitcoin.conf` key
/// changed — editing a hook in place is the whole point. A parse or permission
/// error keeps the last-good dispatcher running, because the failure mode of
/// "your alerting silently stopped after a typo" is worse than the failure mode
/// of "your edit did not take effect and the log says why".
pub struct AlertReloader {
    path: std::path::PathBuf,
    /// The API runtime. The reload runs on the consensus runtime's signal loop,
    /// so the new generation's tasks must be spawned onto the API runtime
    /// explicitly rather than inherited from the caller.
    api_handle: tokio::runtime::Handle,
    publisher: Arc<EventPublisher>,
    store: Arc<dyn Store>,
    block_source: Option<Arc<dyn node::events::BlockCursorSource>>,
    metrics: Arc<WebhookMetrics>,
    global_stop: watch::Receiver<bool>,
    /// Stop signal for the generation currently running, if any.
    current: parking_lot::Mutex<Option<watch::Sender<bool>>>,
    /// The last successfully-applied alertfile, so a SIGHUP that did not change
    /// it can be a no-op instead of destroying in-flight deliveries.
    last_applied: parking_lot::Mutex<Option<AlertFile>>,
}

impl AlertReloader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: std::path::PathBuf,
        api_handle: tokio::runtime::Handle,
        publisher: Arc<EventPublisher>,
        store: Arc<dyn Store>,
        block_source: Option<Arc<dyn node::events::BlockCursorSource>>,
        metrics: Arc<WebhookMetrics>,
        global_stop: watch::Receiver<bool>,
    ) -> Self {
        Self {
            path,
            api_handle,
            publisher,
            store,
            block_source,
            metrics,
            global_stop,
            current: parking_lot::Mutex::new(None),
            last_applied: parking_lot::Mutex::new(None),
        }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Load the alertfile and start a dispatcher generation, replacing any
    /// generation already running.
    ///
    /// Returns the hook count on success. On failure the previous generation is
    /// left untouched and the error is returned for the caller to log with the
    /// right severity (fatal at startup, warn-and-continue on reload).
    pub fn apply(&self) -> Result<usize, satd_alert::AlertFileError> {
        let file = AlertFile::load(&self.path)?;
        let ids: Vec<String> = file.hooks.iter().map(|h| h.id.clone()).collect();

        // A SIGHUP that did not change the alertfile must not disturb the
        // dispatcher. `reload_from_sighup` calls this on *every* SIGHUP,
        // whatever key the operator actually edited, and retiring a generation
        // destroys its queued deliveries. For chain events that is recoverable
        // — the cursor did not advance, so the next generation's catch-up
        // re-queues them — but a status event has no replay by design, and the
        // detectors are edge-triggered against a `HealthState` that outlives
        // the reload. So a `disk_low` sitting in retry backoff when the
        // operator SIGHUPs to change `maxconnections` would be dropped, never
        // replayed, and never re-raised: the page simply never arrives.
        //
        // Comparing the parsed file rather than the file bytes means
        // reformatting or a comment edit is also a no-op.
        {
            let last = self.last_applied.lock();
            if last.as_ref() == Some(&file) {
                tracing::debug!(
                    target: "alert",
                    "alertfile unchanged; keeping the running dispatcher generation",
                );
                return Ok(file.hooks.len());
            }
        }

        // Retire the previous generation only once the new file has parsed, so
        // a bad edit never leaves the node with no dispatcher at all.
        let (gen_tx, gen_rx) = watch::channel(false);
        let stop = Stop {
            global: self.global_stop.clone(),
            generation: gen_rx,
        };
        let publisher = self.publisher.clone();
        let store = self.store.clone();
        let block_source = self.block_source.clone();
        let metrics = self.metrics.clone();
        let hook_count = file.hooks.len();
        {
            let _guard = self.api_handle.enter();
            spawn_with_metrics(&file, publisher, store, block_source, metrics, stop);
        }
        if let Some(old) = self.current.lock().replace(gen_tx) {
            // Draining is deliberate rather than graceful: the retired
            // generation's queued events are dropped. A reload is an operator
            // changing where alerts go, and delivering the backlog to the *old*
            // endpoint after they redirected it is not what they asked for.
            let _ = old.send(true);
        }
        // Stop exporting counters for hooks that are no longer configured,
        // rather than freezing their series at the last value forever.
        //
        // The legacy reorg alias is preserved explicitly: it registers its
        // counters outside the alertfile, so retaining only alertfile ids would
        // evict them the first time `apply` runs — and it runs at startup —
        // leaving the still-running legacy dispatcher incrementing a snapshot
        // nothing renders. Reorg-webhook delivery would become permanently
        // unobservable, and only on nodes that configure both.
        let mut keep = ids;
        keep.push(LEGACY_REORG_HOOK_ID.to_string());
        self.metrics.retain(&keep);

        // Drop the durable cursor of any hook this reload removed. Hook ids are
        // short and reused — `pager`, `alerts`, `ops` — so leaving the key
        // behind means a later hook that happens to reuse the id inherits a
        // stale resume position and greets a brand-new endpoint with the whole
        // replay window of its predecessor's history.
        //
        // Reconciled against what is actually stored rather than against the
        // previous generation. A reload-time diff cannot see the ordinary case:
        // an operator who removes a hook by editing the file and *restarting*
        // leaves no previous generation to compare against, so the cursor
        // survived forever. Enumerating the keyspace also cleans up whatever
        // earlier versions left behind.
        let live: std::collections::HashSet<Vec<u8>> = file
            .hooks
            .iter()
            .map(|h| h.cursor_key())
            .chain(std::iter::once(
                format!("alertwebhook.cursor.{LEGACY_REORG_HOOK_ID}").into_bytes(),
            ))
            .collect();
        match self.store.list_alert_cursor_keys() {
            Ok(stored) => {
                for key in stored.into_iter().filter(|k| !live.contains(k)) {
                    let label = String::from_utf8_lossy(&key).to_string();
                    match self.store.delete_alert_cursor(&key) {
                        Ok(()) => tracing::info!(
                            target: "alert",
                            key = %label,
                            "no hook owns this resume cursor; dropped it",
                        ),
                        Err(e) => tracing::warn!(
                            target: "alert",
                            key = %label,
                            error = %e,
                            "failed to drop an orphaned resume cursor",
                        ),
                    }
                }
            }
            Err(e) => tracing::warn!(
                target: "alert",
                error = %e,
                "could not enumerate stored resume cursors; orphans were not reclaimed",
            ),
        }
        *self.last_applied.lock() = Some(file);
        Ok(hook_count)
    }
}

/// Deliver legacy `reorgwebhook=` records.
///
/// Absorbed into this module so it shares the API runtime and the HTTP client
/// shape, but **the body stays the shipped `ReorgRecord` JSON, byte for byte**.
/// A `ChainEvent::Reorg` envelope does not carry `depth`, `fork_height`, or the
/// disconnected/reconnected hash lists, so switching this hook to the envelope
/// schema would silently break every deployed receiver. Operators who want the
/// envelope shape configure a new-style hook with `categories = ["chain"]`.
pub async fn legacy_reorg_dispatcher(
    webhook: crate::reload::SharedWebhook,
    mut rx: mpsc::Receiver<node::chain::reorg_log::ReorgRecord>,
    counters: Arc<HookCounters>,
) {
    let client = match webhook_client() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(target: "alert", error = %e, "failed to build reorg webhook HTTP client");
            return;
        }
    };
    tracing::info!(target: "alert", "reorg webhook dispatcher started (legacy alias)");
    while let Some(record) = rx.recv().await {
        // Re-read the live target per record so a SIGHUP that changes or
        // removes the URL takes effect without a restart. The guard is dropped
        // before any await.
        let Some(target) = webhook.read().clone() else {
            continue;
        };
        let Ok(body) = serde_json::to_vec(&record) else {
            tracing::warn!(target: "alert", "failed to serialize reorg record for webhook");
            continue;
        };
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let mut req = client
                .post(&target.url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(satd_alert::ATTEMPT_HEADER, attempt.to_string())
                .header(satd_alert::HOOK_HEADER, LEGACY_REORG_HOOK_ID)
                // v1, frozen: this surface shipped with a body-only signature,
                // no delivery id, and a `ReorgRecord` body. Deployed receivers
                // verify exactly that, so it does not move to the v2 contract;
                // the version header is how a receiver tells them apart.
                .header(
                    satd_alert::WEBHOOK_VERSION_HEADER,
                    satd_alert::LEGACY_WEBHOOK_VERSION,
                );
            if let Some(secret) = &target.secret {
                req = req.header(satd_alert::SIGNATURE_HEADER, satd_alert::sign_body(secret, &body));
            }
            let result = req.body(body.clone()).send().await;
            let status = match &result {
                Ok(r) => Some(r.status().as_u16()),
                Err(_) => None,
            };
            match satd_alert::classify_response(status) {
                satd_alert::Disposition::Delivered => {
                    counters.delivered.fetch_add(1, Ordering::Relaxed);
                    counters.last_success_unix.store(unix_secs(), Ordering::Relaxed);
                    break;
                }
                d => {
                    counters.failed_attempts.fetch_add(1, Ordering::Relaxed);
                    match &result {
                        Ok(r) => tracing::warn!(target: "alert", status = %r.status(), attempt, "reorg webhook returned non-2xx"),
                        Err(e) => tracing::warn!(target: "alert", error = %e, attempt, "reorg webhook request failed"),
                    }
                    // Bounded retries, matching the shipped behavior: the legacy
                    // hook has no queue to fall behind on, so a failing endpoint
                    // is given three tries and the record is dropped.
                    //
                    // Deliberately NOT keyed on `Disposition` the way alertfile
                    // hooks are. The shipped dispatcher retried *any* non-2xx
                    // three times, so classifying 4xx as a one-shot drop here
                    // would quietly change behavior on a flag operators already
                    // depend on. (The redirect change is not reverted: the
                    // shipped client followed 30x, and that is an SSRF vector
                    // for a signed request, so 3xx now fails — documented as a
                    // breaking change in the release notes.)
                    let _ = d;
                    if attempt >= 3 {
                        counters.dropped.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(
                        200u64 * (1 << (attempt - 1)),
                    ))
                    .await;
                }
            }
        }
    }
    tracing::info!(target: "alert", "reorg webhook dispatcher stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use node::events::{StatusEvent, StatusKind, StatusSeverity};

    fn hook_from(toml: &str) -> Hook {
        AlertFile::parse(std::path::Path::new("/test"), toml)
            .expect("valid alertfile")
            .hooks
            .remove(0)
    }

    fn status_env(kind: StatusKind, severity: StatusSeverity) -> NodeEvent {
        let mut ev = StatusEvent::raised(StatusKind::TipStall, "x");
        ev.kind = kind;
        ev.severity = severity;
        NodeEvent::new(
            node::events::EdgeStamp {
                node_id: [7; 16],
                region: None,
                edge_seen_at_ns: 0,
                edge_wall_ns: 0,
                seq: 1,
            },
            NodeEventBody::Status(ev),
        )
    }

    const STATUS_HOOK: &str = r#"
version = 1
[[webhook]]
id = "ops"
url = "https://x.example/h"
secret = "s"
categories = ["status"]
min_severity = "warning"
"#;

    #[test]
    fn cursor_round_trips_through_its_fixed_encoding() {
        let c = Cursor {
            height: 812_345,
            tx_index: 7,
            mempool_seq: 0xDEAD_BEEF_CAFE,
            instance_id: 0x0102_0304_0506_0708,
        };
        assert_eq!(decode_cursor(&encode_cursor(&c)), Some(c));
    }

    #[test]
    fn a_truncated_or_garbage_cursor_is_ignored_not_misread() {
        // A corrupt cursor must degrade to "start at the live head", never to a
        // wrong height that would replay or skip history.
        assert_eq!(decode_cursor(&[]), None);
        assert_eq!(decode_cursor(&[0u8; 23]), None);
        assert_eq!(decode_cursor(&[0u8; 25]), None);
    }

    #[test]
    fn status_filter_is_applied_per_hook() {
        let hook = hook_from(STATUS_HOOK);
        let mut hb = None;
        assert!(accepts(
            &hook,
            &status_env(StatusKind::DiskLow, StatusSeverity::Critical),
            &mut hb
        ));
        // Below the severity floor.
        assert!(!accepts(
            &hook,
            &status_env(StatusKind::IbdComplete, StatusSeverity::Info),
            &mut hb
        ));
    }

    #[test]
    fn a_status_only_hook_does_not_receive_chain_events() {
        let hook = hook_from(STATUS_HOOK);
        let env = NodeEvent::new(
            node::events::EdgeStamp {
                node_id: [7; 16],
                region: None,
                edge_seen_at_ns: 0,
                edge_wall_ns: 0,
                seq: 1,
            },
            NodeEventBody::Chain(node::chain::events::ChainEvent::BlockConnected {
                hash: bitcoin::BlockHash::from_raw_hash(
                    bitcoin::hashes::Hash::from_byte_array([3u8; 32]),
                ),
                height: 5,
            }),
        );
        let mut hb = None;
        assert!(!accepts(&hook, &env, &mut hb));
    }

    #[test]
    fn lag_notices_bypass_every_filter() {
        // A receiver must learn it missed events even if the events it missed
        // were in a category it does not subscribe to — otherwise its cursor
        // silently diverges.
        let hook = hook_from(STATUS_HOOK);
        let env = NodeEvent::new(
            node::events::EdgeStamp {
                node_id: [7; 16],
                region: None,
                edge_seen_at_ns: 0,
                edge_wall_ns: 0,
                seq: 1,
            },
            NodeEventBody::Lagged {
                dropped_count: 3,
                resume_cursor: Cursor {
                    height: 1,
                    tx_index: 0,
                    mempool_seq: 0,
                    instance_id: 1,
                },
            },
        );
        let mut hb = None;
        assert!(accepts(&hook, &env, &mut hb));
    }

    #[test]
    fn heartbeats_are_downsampled_to_the_configured_interval() {
        let hook = hook_from(
            r#"
version = 1
[[webhook]]
id = "deadman"
url = "https://x.example/h"
secret = "s"
categories = ["heartbeat"]
heartbeat_interval_secs = 3600
"#,
        );
        let env = NodeEvent::new(
            node::events::EdgeStamp {
                node_id: [7; 16],
                region: None,
                edge_seen_at_ns: 0,
                edge_wall_ns: 0,
                seq: 1,
            },
            NodeEventBody::Heartbeat { uptime_ns: 1 },
        );
        let mut hb = None;
        // The bus beats at 1 Hz; the first one goes through and the rest of the
        // hour's worth do not.
        assert!(accepts(&hook, &env, &mut hb));
        for _ in 0..100 {
            assert!(!accepts(&hook, &env, &mut hb));
        }
    }

    #[test]
    fn a_hook_without_the_heartbeat_interval_gets_no_heartbeats() {
        let hook = hook_from(STATUS_HOOK);
        let env = NodeEvent::new(
            node::events::EdgeStamp {
                node_id: [7; 16],
                region: None,
                edge_seen_at_ns: 0,
                edge_wall_ns: 0,
                seq: 1,
            },
            NodeEventBody::Heartbeat { uptime_ns: 1 },
        );
        let mut hb = None;
        assert!(!accepts(&hook, &env, &mut hb));
    }
}
