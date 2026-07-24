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

/// Monotonic counter naming watch-match deliveries.
///
/// Watch matches arrive on a per-subscriber channel rather than the shared
/// event bus, so there is no `EdgeStamp.seq` to identify them with. They need an
/// id of their own because the contract makes `X-Satd-Delivery` the receiver's
/// idempotency key — the reference push relay dedupes on it, and so will anyone
/// following the spec. Reading the bus counter instead would give every match
/// between two bus publishes the *same* id, and that id would also collide with
/// the bus event that last advanced it: distinct deposit alerts, silently
/// deduplicated away by a correct receiver.
///
/// Process-wide rather than per-dispatcher-generation: a SIGHUP reload keeps
/// the same `instance_id`, so a per-generation counter would restart at 1 and
/// re-mint ids a receiver has already seen.
static WATCH_DELIVERY_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Per-attempt HTTP timeout. Matches the shipped reorg webhook.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How often a pending gap notice is flushed when no event is driving the hook.
const GAP_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Numbers synthesized deliveries — catch-up replay events and gap notices.
///
/// Process-wide rather than per-generation, for the same reason the watch
/// counter is: a SIGHUP reload keeps the same `instance_id`, so a per-generation
/// counter would restart at zero and re-mint ids the receiver has already seen.
static SYNTH_DELIVERY_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Composite stop signal: the process-wide shutdown, plus a narrower channel
/// the SIGHUP reload flips to retire one task.
///
/// Two channels rather than one because a reload must stop *some* of the
/// dispatcher's tasks without touching the global signal every other subsystem
/// watches. The scope of `local` differs by task on purpose: a fan-in is
/// retired per *generation*, because every reload rebuilds the hook list it
/// iterates; a delivery task is retired per *hook*, because a reload that
/// leaves a hook's stanza untouched must leave its queue alone (see
/// `AlertReloader::apply`).
#[derive(Clone)]
pub struct Stop {
    global: watch::Receiver<bool>,
    local: watch::Receiver<bool>,
}

impl Stop {
    fn stopped(&self) -> bool {
        *self.global.borrow() || *self.local.borrow()
    }

    /// Resolve once either channel signals. Cancel-safe: `changed()` only
    /// marks a value seen when it completes, and the loop re-checks both
    /// borrows, so being dropped inside a `select!` loses nothing.
    ///
    /// A dropped sender counts as stopped. `changed()` returns `Err` forever
    /// once the sender is gone, so ignoring it would spin this loop at 100%
    /// CPU — and the reading is right anyway: nothing that could retire this
    /// task still exists.
    async fn wait(&mut self) {
        loop {
            if self.stopped() {
                return;
            }
            tokio::select! {
                r = self.global.changed() => if r.is_err() { return },
                r = self.local.changed() => if r.is_err() { return },
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
        /// How many lost events this delivery announces, if it is a `Lagged`
        /// notice. The count travels *with* the delivery rather than being
        /// retired when the notice is queued: a queued notice can still be
        /// destroyed — by a reload retiring the generation, or by a permanent
        /// rejection — and the one message that must not be lost is the one
        /// saying data was lost. Anything that fails to deliver hands the
        /// weight back to `GapState`.
        gap_weight: u64,
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
    /// Whether this hook's delivery task was started by the same `apply` that
    /// built this channel, and so should be told what it missed while nothing
    /// was delivering for it.
    ///
    /// False for a hook carried across a reload. Its queue survived, so the
    /// span between its durable cursor and the tip is not a hole — it is a
    /// backlog about to be delivered, and announcing it as a gap tells the
    /// receiver to go rescan a range it is about to be sent anyway.
    fresh: bool,
}

/// Accumulated drop state for one hook.
#[derive(Default)]
struct GapState {
    dropped: std::sync::atomic::AtomicU64,
    /// Position of the last event successfully queued before the gap — the
    /// anchor a receiver resumes from.
    resume_height: std::sync::atomic::AtomicU32,
}

/// Process-lived dispatcher state that must outlive any single generation.
///
/// A reload retires the generation that accumulated a drop count, and
/// per-generation state would take the pending `Lagged` notice down with it —
/// the receiver would never learn about a hole satd had already recorded.
/// `HookCounters` is process-lived for the same reason.
///
/// Injected rather than reached for as a `static` so a test can hand in a fresh
/// one. With a bare static the first test to latch `left_ibd` makes every later
/// test of the gate vacuous, non-deterministically, since they share a process.
#[derive(Default)]
struct DispatcherState {
    /// Whether this node has ever been observed out of initial block download.
    ///
    /// `is_initial_block_download()` is the tip header's age, not a sync flag,
    /// so a node whose tip stops advancing crosses back into "IBD" a day later.
    /// This keeps a flapping predicate from re-suppressing a caught-up node.
    ///
    /// It is deliberately not load-bearing. The latch lives in this process, so
    /// a node restarted while already wedged never observes a non-IBD tip and
    /// never arms it — and an earlier version of this gate went permanently
    /// silent in exactly that case. What makes that harmless now is the *scope*
    /// of the gate: only chain events are suppressed, and chain events are by
    /// definition not arriving on a node whose tip has stopped.
    left_ibd: std::sync::atomic::AtomicBool,
    gaps: parking_lot::Mutex<std::collections::HashMap<String, Arc<GapState>>>,
}

impl DispatcherState {
    fn gap_for(&self, id: &str) -> Arc<GapState> {
        Arc::clone(self.gaps.lock().entry(id.to_string()).or_default())
    }

    /// Drop gap state for hooks no longer named in the alertfile.
    ///
    /// The mirror of `metrics.retain` and the cursor GC, which already run on
    /// reload. Hook ids are short and reused — `pager`, `ops`, `alerts` — so a
    /// re-added id would otherwise inherit its predecessor's pending drop count
    /// and resume anchor, and announce a hole to a brand-new endpoint that
    /// never had one.
    fn retain_gaps(&self, keep: &std::collections::HashSet<String>) {
        self.gaps.lock().retain(|id, _| keep.contains(id));
    }
}

/// The process-wide instance. Tests construct their own.
static DISPATCHER_STATE: std::sync::LazyLock<Arc<DispatcherState>> =
    std::sync::LazyLock::new(|| Arc::new(DispatcherState::default()));

/// A delivery task the reloader keeps alive across reloads.
///
/// Held by `AlertReloader` rather than by the fan-in, so a reload can decide
/// per hook whether to keep the task — and its queue of pending deliveries —
/// or retire it.
struct RunningHook {
    /// The stanza this task was started for. A reload reuses the task when the
    /// new stanza compares equal, and retires it when it does not.
    config: Hook,
    tx: mpsc::Sender<Delivery>,
    counters: Arc<HookCounters>,
    gap: Arc<GapState>,
    /// Retires this hook's delivery task alone.
    stop: watch::Sender<bool>,
}

/// Start one hook's delivery task.
///
/// Must be called from within the API runtime — the task does outbound HTTP,
/// which is exactly what must never share the consensus runtime.
fn start_hook(
    hook: &Hook,
    metrics: &WebhookMetrics,
    state: &DispatcherState,
    store: Arc<dyn Store>,
    global_stop: watch::Receiver<bool>,
) -> RunningHook {
    let (tx, rx) = mpsc::channel::<Delivery>(HOOK_QUEUE_CAPACITY);
    let (stop_tx, stop_rx) = watch::channel(false);
    let counters = metrics.hook(&hook.id);
    let gap = state.gap_for(&hook.id);
    tokio::spawn(deliver_loop(
        hook.clone(),
        rx,
        counters.clone(),
        gap.clone(),
        store,
        Stop {
            global: global_stop,
            local: stop_rx,
        },
    ));
    RunningHook {
        config: hook.clone(),
        tx,
        counters,
        gap,
        stop: stop_tx,
    }
}

/// Fan-in: one broadcast receiver, filtered and enqueued per hook.
///
/// The bus receiver is created by the caller, not here. When it is created
/// relative to retiring the previous generation is the whole handover protocol;
/// see `AlertReloader::apply`.
#[allow(clippy::too_many_arguments)]
async fn fan_in(
    hooks: Vec<HookChannel>,
    mut rx: tokio::sync::broadcast::Receiver<NodeEvent>,
    publisher: Arc<EventPublisher>,
    store: Arc<dyn Store>,
    block_source: Option<Arc<dyn node::events::BlockCursorSource>>,
    watch_registry: Arc<node::events::WatchRegistry>,
    state: Arc<DispatcherState>,
    mut stop: Stop,
) {
    // Register the union of every hook's watch-set as ONE registry subscriber.
    // Matches arrive on a per-subscriber channel (they never ride the shared
    // bus), and each is routed back to the hooks that asked for it. The handle
    // is held for the generation's lifetime — dropping it deregisters, which is
    // exactly what a reload wants.
    let (watch_handle, mut watch_rx) = register_watch_sets(&watch_registry, &hooks);

    // Announce whatever each hook missed while the daemon was down. Nothing is
    // replayed — there is no snapshot-to-live seam to dedupe, because there is
    // no snapshot.
    for hook in hooks.iter().filter(|h| h.fresh) {
        announce_gap(hook, store.as_ref(), block_source.as_deref()).await;
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
            m = watch_rx.recv() => match m {
                Some(m) => {
                    let json = node::events::watch_match_json(&m, &[], false);
                    let Ok(bytes) = serde_json::to_vec(&json) else { continue };
                    let body = Arc::new(bytes);
                    // One id per match, shared by every hook that wants it —
                    // the same rule the bus path follows, so "one event, one
                    // idempotency key" holds on both. Minted lazily so a match
                    // no hook subscribes to costs nothing.
                    let mut delivery_id: Option<String> = None;
                    for hook in &hooks {
                        // Route by what the hook actually watches. The registry
                        // knows only the union, so a match for hook A must not
                        // be delivered to hook B that never asked for it.
                        if !hook_watches_match(&hook.hook, &m) {
                            continue;
                        }
                        let id = delivery_id.get_or_insert_with(|| {
                            let seq = WATCH_DELIVERY_SEQ
                                .fetch_add(1, Ordering::Relaxed)
                                .wrapping_add(1);
                            satd_alert::watch_delivery_id(
                                &hex::encode(publisher.edge().node_id),
                                publisher.instance_id(),
                                seq,
                            )
                        });
                        enqueue(hook, &publisher, Delivery::Event {
                            body: body.clone(),
                            delivery_id: id.clone(),
                            // Watch matches are per-subscriber and carry no
                            // durable cursor of their own; the hook's resume
                            // position advances on the confirmed chain events
                            // it also receives.
                            cursor: None,
                            gap_weight: 0,
                        }, None);
                    }
                }
                None => {
                    // Break, matching the bus arm. A closed mpsc returns `None`
                    // immediately and forever, so falling through would spin
                    // this loop at 100% CPU with a warn per iteration.
                    // Unreachable today — `watch_handle` is held for the whole
                    // loop and is the only thing that drops the sender — but
                    // the asymmetry with the bus arm is a trap for whoever adds
                    // registry-side subscriber pruning later.
                    tracing::warn!(target: "alert", "watch match channel closed");
                    break;
                }
            },
            recv = rx.recv() => match recv {
                Ok(env) => {
                    // Suppress the block firehose during initial block
                    // download.
                    //
                    // The dispatcher starts long before P2P, so without this a
                    // brand-new node with an alertfile POSTs its entire sync —
                    // one `block_connected` per historical block, for as long as
                    // IBD takes. The failure mode is a multi-day firehose at the
                    // receiver rather than anything that looks like a bug
                    // locally.
                    //
                    // Scoped to chain events, and that scope is what makes the
                    // gate safe. `is_initial_block_download()` is the tip
                    // header's age, not a sync flag, so a node that is fully
                    // caught up and then *stops* reads as "syncing" a day later
                    // — and a node restarted while already wedged reads that way
                    // from its first event, with no chance to latch. An earlier
                    // version gated everything on that predicate and so went
                    // totally dark on a stalled node: no status, no mempool, and
                    // watch matches destroyed outright since they have no replay
                    // to recover them. The one thing a stalled node is *not*
                    // producing is chain events, so suppressing only those costs
                    // nothing in that state and still stops the firehose in the
                    // state it was written for.
                    //
                    // Status and heartbeat therefore always pass, which they
                    // must: "this node is unhealthy" is exactly as true during
                    // IBD, and a heartbeat is a dead-man's switch — suppressing
                    // it during a multi-day sync makes an external watchdog
                    // declare a healthy node dead.
                    let suppressible = matches!(env.body, NodeEventBody::Chain(_));
                    let syncing = suppressible
                        && !state.left_ibd.load(Ordering::Relaxed)
                        && {
                            let in_ibd = block_source
                                .as_deref()
                                .is_some_and(|s| s.in_initial_block_download());
                            if !in_ibd {
                                state.left_ibd.store(true, Ordering::Relaxed);
                            }
                            in_ibd
                        };
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
                    if syncing {
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
                        enqueue(hook, &publisher, Delivery::Event {
                            body: body.clone(),
                            delivery_id: delivery_id.clone(),
                            cursor: env.cursor,
                            gap_weight: 0,
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
    drop(watch_handle);
    tracing::info!(target: "alert", "alert webhook dispatcher stopped");
}

/// Register every hook's watch-set into one registry subscriber and return the
/// handle plus the match channel.
///
/// One subscriber rather than one per hook: the matcher's cost is per watched
/// entry per transaction, and registering the same script twice would double it
/// for no benefit. Routing back to individual hooks is a cheap set membership
/// test on the delivery side.
fn register_watch_sets(
    registry: &Arc<node::events::WatchRegistry>,
    hooks: &[HookChannel],
) -> (
    node::events::WatchHandle,
    tokio::sync::mpsc::Receiver<node::events::WatchMatch>,
) {
    let (handle, rx) = registry.register(node::events::WATCH_CHANNEL_CAPACITY);
    let mut scripts = 0usize;
    let mut outpoints = 0usize;
    let mut txids = 0usize;
    let mut sp = 0usize;
    for hook in hooks {
        let w = &hook.hook.watch;
        if !w.scripthashes.is_empty() {
            scripts += handle.add_scripthashes(&w.scripthashes);
        }
        if !w.outpoints.is_empty() {
            outpoints += handle.add_outpoints(&w.outpoints);
        }
        if !w.txids.is_empty() {
            // No auto-close: a webhook watch is a standing operator
            // configuration, not a one-shot wait for a payment to confirm.
            txids += handle.add_txids(&w.txids, 0);
        }
        if !w.silent_payments.is_empty() {
            sp += handle.add_silent_payments(&w.silent_payments);
        }
    }
    if scripts + outpoints + txids + sp > 0 {
        tracing::info!(
            target: "alert",
            scripts,
            outpoints,
            txids,
            silent_payments = sp,
            "registered webhook watch-sets",
        );
    }
    (handle, rx)
}

/// Whether this hook's own watch-set produced `m`.
fn hook_watches_match(hook: &Hook, m: &node::events::WatchMatch) -> bool {
    use node::events::WatchMatch as W;
    let w = &hook.watch;
    match m {
        W::OutpointSpent { outpoint, .. } => w.outpoints.contains(outpoint),
        W::ScriptMatched { scripthash, .. } => w.scripthashes.iter().any(|s| s == scripthash),
        W::TxidMatched { txid, .. }
        | W::TxidReplaced { txid, .. }
        | W::TxidEvicted { txid, .. }
        | W::TxidUnconfirmed { txid, .. }
        | W::TxidDepthReached { txid, .. }
        | W::TxidFinalized { txid, .. } => w.txids.contains(txid),
        W::SilentPaymentMatched { scan_pubkey, .. } => w
            .silent_payments
            .iter()
            .any(|t| t.scan_pubkey() == *scan_pubkey),
        // Prefix watches are not configurable from an alertfile (they exist to
        // give a remote client plausible deniability, which is meaningless for
        // an operator watching their own node), so no hook can own one.
        W::PrefixMatched { .. } => false,
    }
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
        gap_weight: dropped,
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
/// Tell a hook what it missed while the daemon was down, without replaying it.
///
/// Webhooks are realtime (design D6): an event is delivered live or not at all.
/// The durable cursor is a resume *marker*, not a replay log — read once here,
/// compared against the tip, reported as a single `Lagged`, then advanced past
/// the span so a restart does not announce it twice.
///
/// This used to rebuild the missed span from the block index and re-deliver it.
/// That duplicated the streaming API, which does resumable consumption properly
/// — real cursors, backpressure, a bounded `RescanBlocks` — and did it worse:
/// the replay was built up to `MAX_REPLAY_BLOCKS` into a queue holding 1024, so
/// any outage long enough to matter had its "guaranteed" catch-up converted
/// straight back into an overflow gap. It also minted per-height delivery ids,
/// which collided between a block and its post-reorg replacement, so a
/// conforming receiver discarded the replacement.
async fn announce_gap(
    hook: &HookChannel,
    store: &dyn Store,
    block_source: Option<&dyn node::events::BlockCursorSource>,
) {
    let Some(src) = block_source else {
        return;
    };
    let tip = src.current_tip_height();
    let Some(cursor) = read_cursor(store, &hook.hook) else {
        // No stored marker: this hook is forward-only from now. Anchor the
        // resume height at the live tip anyway. It is otherwise only set by a
        // successful enqueue, so a hook that lags before its first one — or one
        // that never carries a cursor at all, like a status-only or watch-only
        // hook — would emit a `Lagged` advertising height 0. A receiver reading
        // that as "resume from genesis" would resync the whole chain over
        // having missed nothing.
        hook.gap.resume_height.store(tip, Ordering::Relaxed);
        return;
    };
    hook.gap.resume_height.store(cursor.height, Ordering::Relaxed);
    let missed = u64::from(tip.saturating_sub(cursor.height));
    if missed == 0 {
        return;
    }
    hook.gap.dropped.fetch_add(missed, Ordering::Relaxed);
    tracing::info!(
        target: "alert",
        hook = %hook.id,
        from = cursor.height,
        tip,
        missed,
        "webhook missed a span while the daemon was down; announcing it as a gap",
    );
    // Advance the marker past the announced span. Without this a restart before
    // the next delivery re-announces the same gap, and on a quiet chain that
    // repeats on every restart.
    let advanced = Cursor { height: tip, ..cursor };
    if let Err(e) = store.write_alert_cursor(&hook.hook.cursor_key(), &encode_cursor(&advanced)) {
        tracing::warn!(
            target: "alert",
            hook = %hook.id,
            error = %e,
            "failed to advance the webhook resume marker past an announced gap",
        );
    }
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

/// Hand back the gap weight of every delivery this loop will never send.
///
/// Retiring a generation drops its queue, and `flush_gap` has already zeroed
/// `GapState` on the assumption the queued notice would go out. Without this,
/// a reload silently destroys the record of a hole — and the process-lived
/// `GapState` that exists precisely to survive a reload reads zero afterwards.
fn drain_owed(rx: &mut mpsc::Receiver<Delivery>, gap: &GapState) {
    let mut owed = 0u64;
    while let Ok(Delivery::Event { gap_weight, .. }) = rx.try_recv() {
        owed = owed.saturating_add(gap_weight);
    }
    if owed > 0 {
        gap.dropped.fetch_add(owed, Ordering::Relaxed);
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
            _ = stop.wait() => return drain_owed(&mut rx, &gap),
            item = rx.recv() => match item {
                Some(i) => i,
                None => return drain_owed(&mut rx, &gap),
            },
        };
        let Delivery::Event {
            body,
            delivery_id,
            cursor,
            gap_weight,
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
                    //
                    // `gap_weight` is what this delivery was itself announcing:
                    // rejecting a `Lagged` that carried 500 must not shrink the
                    // count to 1. Under a receiver that rejects every request —
                    // a proxy 302ing the lot — a collapsing count would grind
                    // gap accounting down to 1 on every cycle indefinitely.
                    gap.dropped
                        .fetch_add(gap_weight.saturating_add(1), Ordering::Relaxed);
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
                        // Retired mid-backoff. This delivery is already out of
                        // the queue, so `drain_owed` cannot see it — hand its
                        // weight back explicitly before dropping it.
                        _ = stop.wait() => {
                            if gap_weight > 0 {
                                gap.dropped.fetch_add(gap_weight, Ordering::Relaxed);
                            }
                            return drain_owed(&mut rx, &gap);
                        }
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
    /// Watch registry the dispatcher registers each generation's union
    /// watch-set into.
    watch_registry: Arc<node::events::WatchRegistry>,
    /// Whether `silentpaymentindex=1`. Silent-payment watch entries are refused
    /// without it (see `apply`).
    sp_index_enabled: bool,
    metrics: Arc<WebhookMetrics>,
    global_stop: watch::Receiver<bool>,
    /// Everything a handover has to hand over.
    running: parking_lot::Mutex<Running>,
    /// The last successfully-applied alertfile, so a SIGHUP that did not change
    /// it can be a no-op instead of destroying in-flight deliveries.
    last_applied: parking_lot::Mutex<Option<AlertFile>>,
}

/// The live dispatcher, as much of it as a reload has to reason about.
///
/// Under one lock because the handover in `apply` is a sequence over these
/// fields whose *order* is the correctness argument; splitting them would turn
/// that order into an unstated convention between independent critical
/// sections.
#[derive(Default)]
struct Running {
    /// Retires the fan-in of the generation currently running.
    fan_in_stop: Option<watch::Sender<bool>>,
    /// Live delivery tasks by hook id, carried across reloads.
    hooks: std::collections::HashMap<String, RunningHook>,
}

impl AlertReloader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: std::path::PathBuf,
        api_handle: tokio::runtime::Handle,
        publisher: Arc<EventPublisher>,
        store: Arc<dyn Store>,
        block_source: Option<Arc<dyn node::events::BlockCursorSource>>,
        watch_registry: Arc<node::events::WatchRegistry>,
        sp_index_enabled: bool,
        metrics: Arc<WebhookMetrics>,
        global_stop: watch::Receiver<bool>,
    ) -> Self {
        Self {
            path,
            api_handle,
            publisher,
            store,
            block_source,
            watch_registry,
            sp_index_enabled,
            metrics,
            global_stop,
            running: parking_lot::Mutex::new(Running::default()),
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

        // Silent-payment watch entries are refused without the tweak index.
        // Live matching would work either way (the matcher recomputes from the
        // block), but the index is what lets a hook's confirmed SP matches be
        // caught up after a restart — and an alerting rule whose durability
        // silently depends on an unrelated flag is worse than one that refuses
        // to start.
        if !self.sp_index_enabled
            && let Some(hook) = file
                .hooks
                .iter()
                .find(|h| !h.watch.silent_payments.is_empty())
        {
            return Err(satd_alert::AlertFileError::Invalid {
                path: self.path.clone(),
                message: format!(
                    "webhook `{}` watches silent payments, which requires silentpaymentindex=1",
                    hook.id
                ),
            });
        }

        let ids: Vec<String> = file.hooks.iter().map(|h| h.id.clone()).collect();

        // A SIGHUP that did not change the alertfile is a no-op.
        // `reload_from_sighup` calls this on *every* SIGHUP, whatever key the
        // operator actually edited, so without this an unrelated
        // `maxconnections` edit would churn the whole dispatcher.
        //
        // Belt and braces rather than the only defence: the handover below
        // carries each hook's delivery task across a reload when that hook's
        // stanza is unchanged, so even a real edit leaves the untouched hooks'
        // queues and retry backoff intact.
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

        let hook_count = file.hooks.len();

        // ---- Handover ----------------------------------------------------
        //
        // Subscribe the incoming generation to the bus here, synchronously,
        // before anything is retired — and hand the receiver to the task rather
        // than letting it subscribe for itself.
        //
        // A `broadcast::Receiver` only sees what is published after it is
        // created. Subscribing inside the spawned fan-in means the subscription
        // does not exist until the executor first polls that task, so every
        // event published between retiring the outgoing generation and that
        // first poll reaches nobody. Not delayed: gone. Status events have no
        // replay by design and the detectors that raise them are edge-triggered
        // against a `HealthState` that outlives the reload, so a `disk_low`
        // that lands in the window is never re-raised and the page never
        // arrives. The window is short but it is scheduler latency, which is
        // longest exactly when the node is loaded enough to be raising alerts.
        //
        // Holding both subscriptions open for a moment is the safe direction: a
        // bus delivery id is `node-instance-<the event's own seq>`, so the two
        // generations mint the *same* id for the same event and a receiver
        // deduplicating on `X-Satd-Delivery`, as the contract instructs,
        // collapses them.
        let bus_rx = self.publisher.subscribe();

        let mut running = self.running.lock();

        // Reconcile the delivery tasks. A hook whose stanza is unchanged keeps
        // the task it already has, queue and retry backoff included — a reload
        // is an operator editing one stanza, and it must not destroy pending
        // deliveries for every *other* hook in the file. A status event has no
        // replay behind it, so one sitting in backoff for an untouched hook is
        // lost outright. Only hooks actually edited or removed are retired.
        let mut next_hooks: std::collections::HashMap<String, RunningHook> =
            std::collections::HashMap::with_capacity(file.hooks.len());
        let mut channels: Vec<HookChannel> = Vec::with_capacity(file.hooks.len());
        {
            let _guard = self.api_handle.enter();
            for hook in &file.hooks {
                let kept = match running.hooks.remove(&hook.id) {
                    Some(r) if r.config == *hook => Some(r),
                    Some(edited) => {
                        // This one's queue is dropped on purpose: the operator
                        // changed where or how it delivers, and flushing the
                        // backlog to the superseded endpoint is not what they
                        // asked for. `deliver_loop` hands the undelivered count
                        // back to the process-lived `GapState` on its way out,
                        // so the hole is announced rather than swallowed.
                        let _ = edited.stop.send(true);
                        None
                    }
                    None => None,
                };
                let fresh = kept.is_none();
                let running_hook = kept.unwrap_or_else(|| {
                    start_hook(
                        hook,
                        &self.metrics,
                        &DISPATCHER_STATE,
                        self.store.clone(),
                        self.global_stop.clone(),
                    )
                });
                channels.push(HookChannel {
                    id: hook.id.clone(),
                    hook: hook.clone(),
                    tx: running_hook.tx.clone(),
                    counters: running_hook.counters.clone(),
                    gap: running_hook.gap.clone(),
                    reported_closed: std::sync::atomic::AtomicBool::new(false),
                    fresh,
                });
                next_hooks.insert(hook.id.clone(), running_hook);
            }
            // Whatever is left was removed from the file.
            for (_, gone) in running.hooks.drain() {
                let _ = gone.stop.send(true);
            }
        }
        running.hooks = next_hooks;

        // Retire the outgoing fan-in. Its queued deliveries are not lost with
        // it: the queues belong to the delivery tasks, which this handover has
        // already decided the fate of, one hook at a time.
        if let Some(old) = running.fan_in_stop.take() {
            let _ = old.send(true);
        }

        if channels.is_empty() {
            // An alertfile with no hooks runs no tasks at all.
            drop(bus_rx);
        } else {
            let (gen_tx, gen_rx) = watch::channel(false);
            {
                let _guard = self.api_handle.enter();
                tokio::spawn(fan_in(
                    channels,
                    bus_rx,
                    self.publisher.clone(),
                    self.store.clone(),
                    self.block_source.clone(),
                    self.watch_registry.clone(),
                    Arc::clone(&DISPATCHER_STATE),
                    Stop {
                        global: self.global_stop.clone(),
                        local: gen_rx,
                    },
                ));
            }
            running.fan_in_stop = Some(gen_tx);
        }
        drop(running);
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

        // Reclaim gap state for the same set. `metrics.retain` and the cursor
        // GC below both prune on hook removal; the process-lived gap map has to
        // prune with them, or a re-added id inherits its predecessor's pending
        // drop count and resume anchor and announces a hole its new endpoint
        // never had.
        DISPATCHER_STATE.retain_gaps(&keep.iter().cloned().collect());

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

    fn test_pubkey(byte: u8) -> bitcoin::secp256k1::PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap(),
        )
    }

    fn sp_hook_toml(id: &str) -> String {
        let spend = test_pubkey(0x43);
        format!(
            r#"version = 1
[[webhook]]
id = "{id}"
url = "https://x.example/h"
secret = "s"
categories = ["chain"]
[[webhook.watch.silent_payments]]
scan_key = "{}"
spend_pubkey = "{}"
"#,
            hex::encode([0x42u8; 32]),
            hex::encode(spend.serialize()),
        )
    }

    #[test]
    fn watch_matches_route_only_to_the_hook_that_asked() {
        // One registry subscriber holds the union of every hook's watch-set, so
        // routing back to the owning hook is this module's job — a bug here
        // leaks one operator's deposit activity into an unrelated endpoint.
        let watcher = hook_from(
            r#"
version = 1
[[webhook]]
id = "watcher"
url = "https://x.example/h"
secret = "s"
categories = ["chain"]
[webhook.watch]
scripts = ["1111111111111111111111111111111111111111111111111111111111111111"]
"#,
        );
        let bystander = hook_from(STATUS_HOOK);
        let m = node::events::WatchMatch::ScriptMatched {
            scripthash: [0x11; 32],
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([9u8; 32])),
            is_output: true,
            index: 0,
            confirmed: false,
            height: None,
            amount: None,
            raw_tx: None,
        };
        assert!(hook_watches_match(&watcher, &m));
        assert!(!hook_watches_match(&bystander, &m));

        // A different script is not this hook's match either.
        let other = node::events::WatchMatch::ScriptMatched {
            scripthash: [0x22; 32],
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([9u8; 32])),
            is_output: true,
            index: 0,
            confirmed: false,
            height: None,
            amount: None,
            raw_tx: None,
        };
        assert!(!hook_watches_match(&watcher, &other));
    }

    #[test]
    fn silent_payment_matches_route_by_scan_identity() {
        let hook = hook_from(&sp_hook_toml("wallet"));
        let mine = hook.watch.silent_payments[0].scan_pubkey();
        let m = |scan_pubkey: [u8; 33]| node::events::WatchMatch::SilentPaymentMatched {
            scan_pubkey,
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([9u8; 32])),
            vout: 0,
            output_pubkey: test_pubkey(0x45).x_only_public_key().0,
            amount: 1_000,
            tweak: test_pubkey(0x44),
            k: 0,
            label: None,
            confirmed: true,
            height: Some(10),
            raw_tx: None,
        };
        assert!(hook_watches_match(&hook, &m(mine)));
        // A match for someone else's scan key must not be delivered here.
        assert!(!hook_watches_match(&hook, &m([0x00; 33])));
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

    // === Handover ==========================================================

    /// A reloader over a one-line alertfile in `dir`, plus the publisher it
    /// dispatches from.
    ///
    /// The URL is a discard port on loopback: these tests are about what the
    /// reloader does to its own tasks, not about delivery, and nothing here
    /// waits on a response.
    fn handover_fixture(dir: &std::path::Path) -> (AlertReloader, Arc<EventPublisher>) {
        let publisher = EventPublisher::new(
            node::events::EdgeIdentity::new([9; 16], None).expect("edge identity"),
            64,
        );
        let (_tx, global_stop) = watch::channel(false);
        // `_tx` must outlive the reloader or every `Stop` reads "sender gone"
        // and the tasks retire themselves immediately. Leak it: the fixture
        // owns nothing else that could hold it for the test's duration.
        std::mem::forget(_tx);
        let reloader = AlertReloader::new(
            dir.join("alertfile.toml"),
            tokio::runtime::Handle::current(),
            publisher.clone(),
            Arc::new(node::storage::db::InMemoryStore::new()),
            None,
            Arc::new(node::events::WatchRegistry::new()),
            false,
            Arc::new(WebhookMetrics::new()),
            global_stop,
        );
        (reloader, publisher)
    }

    fn write_hooks(dir: &std::path::Path, stanzas: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join("alertfile.toml");
        std::fs::write(&path, format!("version = 1\n{stanzas}")).expect("write alertfile");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn stanza(id: &str, categories: &str) -> String {
        format!(
            "\n[[webhook]]\nid = \"{id}\"\nurl = \"http://127.0.0.1:9/{id}\"\n\
             secret = \"{}\"\ncategories = [{categories}]\n",
            "s".repeat(32)
        )
    }

    /// `apply` must take the incoming generation's bus subscription itself,
    /// not leave it to the task it spawns.
    ///
    /// A `broadcast::Receiver` only sees what is published after it is created.
    /// If the fan-in subscribes for itself, the subscription does not exist
    /// until the executor first polls it — and every event published between
    /// retiring the outgoing generation and that first poll reaches nobody.
    /// A status event lost there is lost for good: there is no replay, and the
    /// detectors are edge-triggered against a `HealthState` that outlives the
    /// reload, so the condition is never re-raised.
    ///
    /// This is a single-threaded runtime and nothing is awaited across the
    /// second `apply`, so no spawned task has run: the subscriber count is
    /// exactly what `apply` did synchronously. Deferring the subscription to
    /// the task leaves it at 1 and fails here.
    #[tokio::test(flavor = "current_thread")]
    async fn a_reload_subscribes_the_incoming_generation_before_retiring_the_old_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_hooks(dir.path(), &stanza("pager", "\"status\""));
        let (reloader, publisher) = handover_fixture(dir.path());

        reloader.apply().expect("first apply");
        // Let generation one's fan-in reach its select loop.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            publisher.subscriber_count(),
            1,
            "one generation running should mean exactly one bus subscriber"
        );

        write_hooks(
            dir.path(),
            &format!(
                "{}{}",
                stanza("pager", "\"status\""),
                stanza("ops", "\"chain\"")
            ),
        );
        reloader.apply().expect("second apply");

        assert_eq!(
            publisher.subscriber_count(),
            2,
            "apply() must subscribe the incoming generation itself; deferring it \
             to the spawned task leaves the bus unsubscribed for as long as the \
             executor takes to poll, and events published in that window are gone"
        );
    }

    /// Editing one hook must not destroy another hook's pending deliveries.
    ///
    /// A reload used to retire the whole generation, taking every hook's queue
    /// and retry backoff with it. For chain events that is survivable — the
    /// durable cursor did not advance. A status event has no replay by design,
    /// so one sitting in backoff for a hook the operator never touched is
    /// simply lost, and the edge-triggered detector will not raise it again.
    ///
    /// Identity of the `mpsc::Sender` is the observable: a carried-over hook
    /// keeps the same channel, and therefore the same queue.
    #[tokio::test(flavor = "current_thread")]
    async fn a_reload_carries_over_the_delivery_task_of_an_untouched_hook() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_hooks(dir.path(), &stanza("pager", "\"status\""));
        let (reloader, _publisher) = handover_fixture(dir.path());

        reloader.apply().expect("first apply");
        let before = reloader
            .running
            .lock()
            .hooks
            .get("pager")
            .map(|h| h.tx.clone())
            .expect("pager is running");

        // Add an unrelated second hook. `pager`'s stanza is byte-identical.
        write_hooks(
            dir.path(),
            &format!(
                "{}{}",
                stanza("pager", "\"status\""),
                stanza("ops", "\"chain\"")
            ),
        );
        reloader.apply().expect("second apply");

        let after = reloader
            .running
            .lock()
            .hooks
            .get("pager")
            .map(|h| h.tx.clone())
            .expect("pager is still running");
        assert!(
            before.same_channel(&after),
            "an untouched hook must keep its delivery task across a reload; a \
             fresh channel means its queued deliveries were destroyed"
        );
        assert!(
            !before.is_closed(),
            "the carried-over hook's delivery task must still be running"
        );
    }

    /// The mirror: a hook the operator *did* edit is retired, so the new
    /// endpoint does not inherit a backlog addressed to the old one.
    #[tokio::test(flavor = "current_thread")]
    async fn a_reload_retires_the_delivery_task_of_an_edited_hook() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_hooks(dir.path(), &stanza("pager", "\"status\""));
        let (reloader, _publisher) = handover_fixture(dir.path());

        reloader.apply().expect("first apply");
        let before = reloader.running.lock().hooks["pager"].tx.clone();

        write_hooks(dir.path(), &stanza("pager", "\"status\", \"chain\""));
        reloader.apply().expect("second apply");

        let after = reloader.running.lock().hooks["pager"].tx.clone();
        assert!(
            !before.same_channel(&after),
            "an edited hook must get a fresh delivery task"
        );
    }
}
