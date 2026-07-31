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
//! **Best-effort, and deliberately so.** Nothing is persisted and nothing is
//! replayed. A full hook queue or a lagged broadcast receiver drops events,
//! moves `satd_alertwebhook_dropped_total`, and logs; a restart resumes at the
//! live head. Anything that needs to know what it missed wants the Streaming
//! Consumption API, which is the canonical integration surface and has real
//! cursors, backpressure and a bounded `RescanBlocks`. Adding durability here
//! would be a worse reimplementation of that one surface over.
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

use node::events::{EventPublisher, NodeEvent, NodeEventBody};
use node::metrics::{HookCounters, WebhookMetrics};
use satd_alert::{AlertFile, Hook, HOOK_QUEUE_CAPACITY};
use tokio::sync::{mpsc, watch};

/// Hook id the legacy `reorgwebhook=` alias reports under, in metric labels and
/// the `X-Satd-Hook` header. Namespaced so it can never collide with an
/// operator-chosen alertfile id (`-` is allowed in ids, but this exact string
/// is documented as reserved).
pub const LEGACY_REORG_HOOK_ID: &str = "reorg-legacy";

/// Per-attempt HTTP timeout. Matches the shipped reorg webhook.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
    },
}

struct HookChannel {
    id: String,
    hook: Hook,
    tx: mpsc::Sender<Delivery>,
    counters: Arc<HookCounters>,
    /// Whether the "delivery task is gone" warning has already been logged for
    /// this generation. Per-generation on purpose: a reload should re-report a
    /// genuinely dead hook once, not stay quiet because a retired generation
    /// already said so.
    reported_closed: std::sync::atomic::AtomicBool,
}

/// Process-lived dispatcher state that must outlive any single generation.
///
/// A reload retires the generation that accumulated a drop count, and
/// `HookCounters` is process-lived so a reload does not reset an operator's
/// counters.
///
/// Held in a process `static` (`DISPATCHER_STATE`). Note the consequence for
/// testing: `left_ibd` is a latch, so the first test in a process to set it
/// makes every later test of the IBD gate vacuous, non-deterministically. The
/// gate is covered end-to-end rather than by unit tests for that reason; a unit
/// test of it would need this state threaded through `AlertReloader::new`.
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
    global_stop: watch::Receiver<bool>,
) -> RunningHook {
    let (tx, rx) = mpsc::channel::<Delivery>(HOOK_QUEUE_CAPACITY);
    let (stop_tx, stop_rx) = watch::channel(false);
    let counters = metrics.hook(&hook.id);
    tokio::spawn(deliver_loop(
        hook.clone(),
        rx,
        counters.clone(),
        Stop {
            global: global_stop,
            local: stop_rx,
        },
    ));
    RunningHook {
        config: hook.clone(),
        tx,
        counters,
        stop: stop_tx,
    }
}

/// Fan-in: one broadcast receiver, filtered and enqueued per hook.
///
/// The bus receiver is created by the caller, not here. When it is created
/// relative to retiring the previous generation is the whole handover protocol;
/// see `AlertReloader::apply`.
async fn fan_in(
    hooks: Vec<HookChannel>,
    mut rx: tokio::sync::broadcast::Receiver<NodeEvent>,
    publisher: Arc<EventPublisher>,
    block_source: Option<Arc<dyn node::events::BlockCursorSource>>,
    state: Arc<DispatcherState>,
    mut stop: Stop,
) {
    // Per-hook heartbeat downsampling state (D11): last forwarded instant.
    let mut last_heartbeat: Vec<Option<std::time::Instant>> = vec![None; hooks.len()];

    tracing::info!(
        target: "alert",
        hooks = hooks.len(),
        "alert webhook dispatcher started",
    );

    loop {
        tokio::select! {
            _ = stop.wait() => break,
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
                        // Counted rather than skipped silently, so an operator
                        // can see on `/metrics` that the sync suppressed
                        // deliveries rather than the hook being broken.
                        for i in wanted {
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
                        enqueue(hook, Delivery::Event {
                            body: body.clone(),
                            delivery_id: delivery_id.clone(),
                        });
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // The dispatcher itself fell behind the bus. Best-effort
                    // means those events are simply gone: the counter and this
                    // line are the whole record.
                    tracing::warn!(target: "alert", dropped = n, "alert dispatcher lagged the event bus");
                    for hook in &hooks {
                        hook.counters.dropped.fetch_add(n, Ordering::Relaxed);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
        }
    }
    tracing::info!(target: "alert", "alert webhook dispatcher stopped");
}

/// Queue an event for one hook.
///
/// Returns whether the event was queued. An overflow drops the event and moves
/// `satd_alertwebhook_dropped_total`; nothing is held for later and nothing is
/// synthesized into the stream. Webhooks are best-effort by design — a consumer
/// that needs to know what it missed wants the streaming API, which has real
/// cursors and backpressure.
fn enqueue(hook: &HookChannel, item: Delivery) -> bool {
    match hook.tx.try_send(item) {
        Ok(()) => {
            hook.counters
                .queue_depth
                .store(queue_depth(&hook.tx) as u64, Ordering::Relaxed);
            true
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            // A receiver that cannot keep up loses events rather than
            // back-pressuring the bus. Consensus is never the thing that waits.
            hook.counters.dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // The delivery task is gone: it failed to build its HTTP client, or
            // it panicked. Silently ignoring this makes the hook look perfectly
            // healthy on `/metrics` — `dropped_total` flat, `queue_depth` flat
            // — while it delivers nothing at all, forever. Count it like any
            // other loss so the existing "no successful delivery in N minutes"
            // rule fires.
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
        // A `Lagged` body is built per-connection by the streaming carriers and
        // is never published to the shared bus, so the dispatcher cannot see
        // one. Treated as any other unsubscribed body rather than special-cased
        // into a path that no event takes.
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

/// One hook's delivery loop: serial, in-order, retrying with backoff.
async fn deliver_loop(
    hook: Hook,
    mut rx: mpsc::Receiver<Delivery>,
    counters: Arc<HookCounters>,
    mut stop: Stop,
) {
    let client = match webhook_client() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(target: "alert", hook = %hook.id, error = %e, "failed to build webhook HTTP client; this hook will not deliver");
            return;
        }
    };

    loop {
        let item = tokio::select! {
            _ = stop.wait() => return,
            item = rx.recv() => match item {
                Some(i) => i,
                None => return,
            },
        };
        let Delivery::Event { body, delivery_id } = item;

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
                    break;
                }
                satd_alert::Disposition::Retry => {
                    counters.failed_attempts.fetch_add(1, Ordering::Relaxed);
                    // A builder error is not transient. reqwest defers URL
                    // parsing into the builder, so a URL that satisfies the
                    // alertfile's checks but that the WHATWG parser rejects
                    // fails here with no status — which `classify_response`
                    // reads as a transient network problem. `validate_url`
                    // parses at load precisely so this cannot happen, but if
                    // one ever slips through, retrying it every five minutes
                    // forever would pin the head of a serial queue and drop
                    // every real alert behind it.
                    if result.as_ref().err().is_some_and(reqwest::Error::is_builder) {
                        counters.dropped.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(
                            target: "alert",
                            hook = %hook.id,
                            "webhook url cannot be resolved; dropping this event (fix the \
                             alertfile — retrying cannot help)",
                        );
                        break;
                    }
                    // Stop once the delivery is older than the freshness window
                    // the contract publishes. `signed_at` is fixed for the life
                    // of the event, so past this age a conforming receiver is
                    // required to refuse every remaining attempt. Continuing
                    // would be guaranteed-futile work — and if the rejection
                    // arrives as a 503 from a gateway rather than a 4xx, the
                    // event would never reach `Drop` and would pin the queue
                    // permanently.
                    if unix_secs().saturating_sub(signed_at) > satd_alert::MAX_TIMESTAMP_SKEW_SECS {
                        counters.dropped.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            target: "alert",
                            hook = %hook.id,
                            delivery = %delivery_id,
                            attempt,
                            "webhook delivery aged past the freshness window; giving up on it",
                        );
                        break;
                    }
                    match result {
                        Ok(r) => tracing::warn!(target: "alert", hook = %hook.id, status = %r.status(), attempt, "webhook delivery failed; retrying"),
                        // `without_url` because a webhook URL is frequently the
                        // credential itself (Slack, Discord, PagerDuty) and may
                        // carry userinfo; reqwest's `Display` appends it
                        // verbatim to transport and timeout errors, so the
                        // plain form writes that credential to the log on every
                        // endpoint blip.
                        Err(e) => {
                            let e = e.without_url();
                            tracing::warn!(target: "alert", hook = %hook.id, error = %e, attempt, "webhook request failed; retrying");
                        }
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
    block_source: Option<Arc<dyn node::events::BlockCursorSource>>,
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
        block_source: Option<Arc<dyn node::events::BlockCursorSource>>,
        metrics: Arc<WebhookMetrics>,
        global_stop: watch::Receiver<bool>,
    ) -> Self {
        Self {
            path,
            api_handle,
            publisher,
            block_source,
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
                        // asked for. Nothing is announced — webhooks are
                        // best-effort, and the loss shows up only on
                        // `satd_alertwebhook_dropped_total`.
                        let _ = edited.stop.send(true);
                        None
                    }
                    None => None,
                };
                let running_hook = kept.unwrap_or_else(|| {
                    start_hook(hook, &self.metrics, self.global_stop.clone())
                });
                channels.push(HookChannel {
                    id: hook.id.clone(),
                    hook: hook.clone(),
                    tx: running_hook.tx.clone(),
                    counters: running_hook.counters.clone(),
                    reported_closed: std::sync::atomic::AtomicBool::new(false),
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
                    self.block_source.clone(),
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
                    // Consumes `result` (nothing below reads it) so the error
                    // can be stripped of its URL before it is formatted.
                    match result {
                        Ok(r) => tracing::warn!(target: "alert", status = %r.status(), attempt, "reorg webhook returned non-2xx"),
                        // `without_url` for the same reason the alertfile
                        // dispatcher applies it: a webhook URL is frequently
                        // the credential itself (Slack, Discord, PagerDuty)
                        // and may carry userinfo, and reqwest's `Display`
                        // appends it verbatim to transport and timeout errors.
                        Err(e) => {
                            let e = e.without_url();
                            tracing::warn!(target: "alert", error = %e, attempt, "reorg webhook request failed")
                        }
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

    /// The alertfile parser reserves this id so an operator hook cannot
    /// collide with the built-in `reorgwebhook=` dispatcher. The two constants
    /// live in different crates — `satd-alert` cannot depend on this binary —
    /// so nothing but this assertion keeps them in step. If they drift, the
    /// reservation silently protects the wrong string and both hooks share one
    /// set of metrics counters again.
    #[test]
    fn the_reserved_hook_id_matches_the_one_the_parser_refuses() {
        assert_eq!(LEGACY_REORG_HOOK_ID, satd_alert::RESERVED_LEGACY_REORG_ID);
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
            None,
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
