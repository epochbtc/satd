//! Generic active-warnings surface for node operational issues.
//!
//! Any time the node emits `tracing::error!` or `tracing::warn!` for a
//! *real operational problem* (not normal-flow logging), it also calls
//! `NodeWarnings::record(...)` with a stable id. The warning stays
//! active — and visible to operators via `getwarnings`, `getblockchaininfo`
//! and the TUI red/yellow modal — until the underlying condition
//! resolves and the call site calls `NodeWarnings::clear(id)`.
//!
//! Repeat events with the same id increment `count` and update
//! `last_seen` but do not duplicate entries. This keeps the surface
//! small and signal-dense: N identical retry failures show up as one
//! row with count=N, not N separate rows.
//!
//! Warnings are deliberately not persisted. They represent *current*
//! state; on restart, conditions get re-detected and re-recorded.
//! History-style events (reorgs, fee-estimate windows, etc.) have
//! their own persistent logs.
//!
//! Every emitted warning indicates a bug that should be fixed. The
//! TUI displays warnings in a blocking modal precisely because they
//! are not meant to be a normal part of the operator's experience.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as _;

/// Severity of a node warning. `Error` is for conditions that block
/// progress or indicate data inconsistency; `Warn` is for conditions
/// worth operator attention but not immediately blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warn,
}

impl Severity {
    fn as_str(&self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warn => "warn",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Warning {
    /// Stable category identifier — callers use this to clear. E.g.
    /// `connect.inputs_missing`, `storage.flush_failed`.
    pub id: String,
    pub severity: Severity,
    /// Human-readable description. Can be overwritten on re-record to
    /// reflect updated context (e.g. retry count).
    pub message: String,
    pub first_seen_unix_secs: u64,
    pub last_seen_unix_secs: u64,
    /// Number of times this id has been recorded since first_seen.
    pub count: u64,
    /// Structured context — height/hash/peer_id/etc. For operator
    /// diagnostics. `serde_json::Value::Null` is fine if no context.
    #[serde(default)]
    pub context: serde_json::Value,
}

/// In-process active-warnings set keyed by stable id. Safe to share
/// across threads via `Arc`.
#[derive(Debug)]
pub struct NodeWarnings {
    active: Mutex<HashMap<String, Warning>>,
    /// Optional sink for the Bitcoin Core `-alertnotify` shell hook. When
    /// set (by the daemon at startup, only if `-alertnotify` is configured),
    /// a formatted message is sent on the *first* occurrence of each warning
    /// id — not on repeats, which only bump the count. `None` when no hook
    /// is configured, so the common path stays a cheap lock + drop.
    alert_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<String>>>,
    /// Per-id rate-limit state for [`notify_event`](Self::notify_event). See
    /// `EVENT_HOOK_MIN_INTERVAL`.
    event_rate: Mutex<HashMap<String, EventRate>>,
}

/// Per-id state for the edge-event rate limit.
#[derive(Debug)]
struct EventRate {
    /// When the current window opened, i.e. when this id last paged for the
    /// first time in a window. An escalation inside the window deliberately
    /// does **not** move it, so a rising sequence cannot extend the window
    /// indefinitely and page per occurrence after all.
    window_started: std::time::Instant,
    /// How many occurrences have been withheld since `window_started`.
    withheld: u64,
    /// The worst withheld occurrence, held so that closing the window pages
    /// the most serious thing that happened rather than a bare count.
    worst_withheld: Option<Withheld>,
    /// The highest magnitude that has already paged in this window — the bar an
    /// occurrence must clear to count as an escalation.
    paged_magnitude: u64,
    /// Whether the one escalation this window permits has already fired.
    escalated: bool,
}

/// An occurrence held back by the rate limit, kept whole rather than reduced to
/// a tally so the operator is eventually paged about the event itself.
#[derive(Debug)]
struct Withheld {
    severity: Severity,
    message: String,
    magnitude: u64,
}

/// Minimum interval between `-alertnotify` execs for the same **edge-event**
/// id.
///
/// Edge events fire per occurrence by design — three reorgs are three things
/// that happened, and deduping them by id would lose information an operator
/// wants, which is why [`notify_event`](NodeWarnings::notify_event) exists
/// separately from [`record`](NodeWarnings::record). But each message queues an
/// exec on an **unbounded** channel that the notifier task drains one at a
/// time (`spawn_alert_notifier` awaits each `sh -c` before taking the next
/// message). So a burst of at-threshold reorgs — a scripted
/// `invalidateblock`/`reconsiderblock` loop, or a thin-hashrate chain having a
/// rough time — does not spawn N processes at once; it grows the queue without
/// bound and pushes the hook arbitrarily far behind real time, until the
/// operator is being paged about a reorg from twenty minutes ago. Both halves
/// of that are the defect: unbounded memory, and an alerting path whose latency
/// is set by the worst burst it has ever seen (#497).
///
/// A rate limit rather than dedup keeps the semantics: nothing is collapsed
/// into "same as before". Occurrences during the window are counted, the worst
/// of them is held and paged when the window closes, and a strictly worse
/// occurrence escalates immediately (once per window). One minute is well below
/// any human response time to a paging hook, and the full-fidelity record is
/// unaffected — the subsystem's own log and the `status` event on the streaming
/// API still carry every occurrence.
const EVENT_HOOK_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Cap on the number of distinct active warning ids.
///
/// Most ids are fixed strings, but some embed an identifier — a corrupt block's
/// warning is `blockdata.corrupt.<hash>`, one per damaged block — and nothing
/// ever clears those. A storage fault that damaged thousands of blocks would
/// put thousands of rows into `getwarnings` and `getblockchaininfo`, fire
/// `-alertnotify` once per row, and fill the TUI's blocking modal with a list
/// no operator can read. Past the cap, a new id is folded into a single
/// [`OVERFLOW_WARNING_ID`] entry instead: every already-active id keeps
/// updating, the operator still learns that more went wrong and how much more,
/// and the node log — which is not capped — still carries each one in full.
///
/// The overflow row is itself an id, so the set holds at most
/// `MAX_ACTIVE_WARNINGS + 1` entries.
const MAX_ACTIVE_WARNINGS: usize = 256;

/// The id that absorbs new warnings once the registry is at
/// [`MAX_ACTIVE_WARNINGS`].
const OVERFLOW_WARNING_ID: &str = "warnings.truncated";

/// The connector has exhausted its retries on a block and cannot extend the
/// chain. Shared so the site that raises it and the readiness probe that
/// reads it cannot drift apart — a typo in either would silently turn the
/// probe off, which is the failure mode it was added to fix.
pub const CONNECT_PERSISTENT_FAILURE: &str = "connect.persistent_failure";

impl NodeWarnings {
    pub fn new() -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
            alert_tx: Mutex::new(None),
            event_rate: Mutex::new(HashMap::new()),
        }
    }

    /// Install the `-alertnotify` sink. The daemon calls this once at
    /// startup when the operator configured `-alertnotify`; the receiving
    /// task runs the shell command per message. Idempotent (last writer
    /// wins).
    pub fn set_alert_notifier(&self, tx: tokio::sync::mpsc::UnboundedSender<String>) {
        *self.alert_tx.lock() = Some(tx);
    }

    /// Record a warning. If `id` is already active, increment count
    /// and refresh `last_seen`, `severity`, `message`, `context`.
    ///
    /// `-alertnotify` fires only the first time an id becomes active. For a
    /// standing condition that is what you want; for a one-shot event that will
    /// never be cleared use [`notify_event`](Self::notify_event).
    pub fn record(
        &self,
        id: &str,
        severity: Severity,
        message: impl Into<String>,
        context: serde_json::Value,
    ) {
        self.record_inner(id, severity, message, context);
    }

    /// Fire `-alertnotify` for a **one-shot event**, without recording a
    /// standing warning.
    ///
    /// This is the right call for something that *happened* rather than
    /// something that *is*: a deep reorg, for instance. Such an event has no
    /// resolved state, so nothing would ever call [`clear`](Self::clear) for
    /// it — and an entry that never clears is exactly what this registry must
    /// not accumulate. It would pin `getwarnings`, keep
    /// [`has_errors`](Self::has_errors) true for the life of the process, and
    /// hold the TUI's blocking modal open forever. On signet and testnet4,
    /// where reorgs several blocks deep are routine, the first one would do
    /// that permanently.
    ///
    /// Each occurrence is a distinct event rather than a restatement of a
    /// standing condition, so occurrences are never *collapsed* — but the shell
    /// hook is rate-limited per id by `EVENT_HOOK_MIN_INTERVAL` (#497). Within
    /// a window:
    ///
    /// * `magnitude` ranks how bad *this* occurrence is on a per-id scale —
    ///   reorg depth, for the one caller that has one. An occurrence strictly
    ///   worse than anything already paged in the window escalates through
    ///   immediately, once per window. Without that, a depth-3 reorg arriving
    ///   first would claim the window and a depth-200 reorg a second later
    ///   would be discarded to a `+= 1` counter — so an exchange that halts
    ///   deposits from `-alertnotify` would get the benign page and never the
    ///   serious one, which is the opposite of what a rate limit is for. Pass
    ///   `0` when the id has no meaningful scale; every occurrence then ranks
    ///   equal and the limiter degrades to plain rate limiting.
    /// * Everything else is withheld, but withheld *whole*: the worst one is
    ///   kept and paged when the window closes, carrying the count of the
    ///   others. A burst therefore reads as a burst, and the page describes the
    ///   most serious thing in it.
    ///
    /// A closed window is drained by the next occurrence of the same id, or by
    /// [`flush_due_events`](Self::flush_due_events) when there isn't one.
    ///
    /// The rate limit applies only to this shell hook. The durable,
    /// full-fidelity record of what happened is the subsystem's own log
    /// (`ReorgLog` for reorgs) and the `status` event on the streaming API,
    /// neither of which this touches.
    pub fn notify_event(
        &self,
        id: &str,
        severity: Severity,
        message: impl Into<String>,
        magnitude: u64,
    ) {
        let message: String = message.into();
        let now = std::time::Instant::now();
        // Decide under the rate-limit lock, then send outside it.
        let outgoing = {
            let mut rate = self.event_rate.lock();
            match rate.get_mut(id) {
                None => {
                    rate.insert(id.to_string(), EventRate::opened(now, magnitude));
                    Some(format_event(severity, id, &message, 0, 0))
                }
                Some(state) => {
                    let window_age = now.duration_since(state.window_started);
                    if window_age >= EVENT_HOOK_MIN_INTERVAL {
                        // The window has closed. Fold this occurrence in with
                        // whatever was withheld and page the worst of the lot,
                        // so the exec reports the most serious thing that
                        // happened rather than whichever arrived first.
                        state.withhold(severity, &message, magnitude);
                        state
                            .close_window(now, window_age)
                            .map(|(worst, others, secs)| {
                                format_event(worst.severity, id, &worst.message, others, secs)
                            })
                    } else if magnitude > state.paged_magnitude && !state.escalated {
                        state.escalated = true;
                        state.paged_magnitude = magnitude;
                        Some(format_event(severity, id, &message, 0, 0))
                    } else {
                        state.withhold(severity, &message, magnitude);
                        None
                    }
                }
            }
        };

        if let Some(msg) = outgoing {
            self.send_alert(msg);
        }
    }

    /// Page anything the edge-event rate limiter is still holding whose window
    /// has closed.
    ///
    /// Withheld occurrences are otherwise drained only by the *next* occurrence
    /// of the same id — and a burst followed by quiet has no next occurrence,
    /// so the worst of the burst would sit in memory unreported for as long as
    /// the chain behaved itself, which is precisely when the operator would
    /// most want to have heard about it. The health detector calls this from
    /// its poll tick, making the drain a function of time rather than of
    /// traffic.
    ///
    /// Cheap and safe to call on a timer: an id with nothing withheld costs a
    /// comparison and is left untouched, window and all.
    pub fn flush_due_events(&self) {
        let now = std::time::Instant::now();
        let mut outgoing = Vec::new();
        {
            let mut rate = self.event_rate.lock();
            for (id, state) in rate.iter_mut() {
                let window_age = now.duration_since(state.window_started);
                if window_age < EVENT_HOOK_MIN_INTERVAL {
                    continue;
                }
                if let Some((worst, others, secs)) = state.close_window(now, window_age) {
                    outgoing.push(format_event(worst.severity, id, &worst.message, others, secs));
                }
            }
        }
        for msg in outgoing {
            self.send_alert(msg);
        }
    }

    /// Best-effort send to the `-alertnotify` sink. Non-blocking; a dropped
    /// receiver (hook task gone) just no-ops.
    fn send_alert(&self, msg: String) {
        let guard = self.alert_tx.lock();
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(msg);
        }
    }

    fn record_inner(
        &self,
        id: &str,
        severity: Severity,
        message: impl Into<String>,
        context: serde_json::Value,
    ) {
        let now = unix_secs();
        let message: String = message.into();
        let is_new;
        {
            let mut active = self.active.lock();
            is_new = !active.contains_key(id);
            // Past the cap, a new id is folded into one overflow row rather
            // than growing the set without bound. Ids that are already active
            // fall through and keep updating, so an established condition is
            // never displaced by a flood of new ones.
            if is_new && active.len() >= MAX_ACTIVE_WARNINGS {
                let overflow_is_new = !active.contains_key(OVERFLOW_WARNING_ID);
                active
                    .entry(OVERFLOW_WARNING_ID.to_string())
                    .and_modify(|w| {
                        w.last_seen_unix_secs = now;
                        w.count += 1;
                        w.context = serde_json::json!({ "most_recent_dropped_id": id });
                    })
                    .or_insert_with(|| Warning {
                        id: OVERFLOW_WARNING_ID.to_string(),
                        // Error, not Warn: needing more than
                        // MAX_ACTIVE_WARNINGS distinct un-cleared warnings is
                        // itself a condition to go look at, whatever the
                        // severity of the individual ones being folded in.
                        severity: Severity::Error,
                        message: format!(
                            "the active-warnings set hit its cap of {MAX_ACTIVE_WARNINGS}; \
                             further distinct ids are counted here rather than listed — the \
                             node log carries every one in full"
                        ),
                        first_seen_unix_secs: now,
                        last_seen_unix_secs: now,
                        count: 1,
                        context: serde_json::json!({ "most_recent_dropped_id": id }),
                    });
                drop(active);
                if overflow_is_new {
                    self.send_alert(format!(
                        "[{}] {}: the active-warnings set hit its cap of {}",
                        Severity::Error.as_str(),
                        OVERFLOW_WARNING_ID,
                        MAX_ACTIVE_WARNINGS
                    ));
                }
                return;
            }
            active
                .entry(id.to_string())
                .and_modify(|w| {
                    w.severity = severity;
                    w.message = message.clone();
                    w.context = context.clone();
                    w.last_seen_unix_secs = now;
                    w.count += 1;
                })
                .or_insert_with(|| Warning {
                    id: id.to_string(),
                    severity,
                    message: message.clone(),
                    first_seen_unix_secs: now,
                    last_seen_unix_secs: now,
                    count: 1,
                    context,
                });
        }
        // Fire the `-alertnotify` hook once per new warning id (Core fires on
        // each `DoWarning`; deduping by id avoids flooding the hook with
        // identical repeats).
        if is_new {
            self.send_alert(format!("[{}] {}: {}", severity.as_str(), id, message));
        }
    }

    /// Push an event id's rate-limit window into the past so the next
    /// `notify_event` for it is allowed through, and so `flush_due_events`
    /// sees it as due.
    ///
    /// Test-only. The window is measured with `Instant`, which cannot be
    /// faked, and sleeping for the real interval would put a minute of wall
    /// clock into the suite for every case.
    #[cfg(test)]
    fn rewind_event_window_for_test(&self, id: &str) {
        if let Some(state) = self.event_rate.lock().get_mut(id) {
            state.window_started -= EVENT_HOOK_MIN_INTERVAL + std::time::Duration::from_secs(1);
        }
    }

    /// Clear a warning by id. No-op if not present.
    pub fn clear(&self, id: &str) {
        let mut active = self.active.lock();
        active.remove(id);
    }

    /// Active warnings, sorted `Error` first then by first_seen asc.
    pub fn list(&self) -> Vec<Warning> {
        let active = self.active.lock();
        let mut out: Vec<Warning> = active.values().cloned().collect();
        out.sort_by(|a, b| {
            // Error < Warn, i.e. Error first.
            match (a.severity, b.severity) {
                (Severity::Error, Severity::Warn) => std::cmp::Ordering::Less,
                (Severity::Warn, Severity::Error) => std::cmp::Ordering::Greater,
                _ => a.first_seen_unix_secs.cmp(&b.first_seen_unix_secs),
            }
        });
        out
    }

    /// True if at least one `Error`-severity warning is active.
    pub fn has_errors(&self) -> bool {
        self.active
            .lock()
            
            .values()
            .any(|w| w.severity == Severity::Error)
    }

    /// Core-compat helper: a single `warnings` string per active entry.
    /// Used for `getblockchaininfo.warnings` array.
    pub fn as_strings(&self) -> Vec<String> {
        self.list()
            .into_iter()
            .map(|w| format!("[{}] {}: {} (×{})", w.severity.as_str(), w.id, w.message, w.count))
            .collect()
    }

    #[cfg(test)]
    pub fn count(&self) -> usize {
        self.active.lock().len()
    }
}

impl EventRate {
    /// A fresh window, opened by an occurrence that has just paged.
    fn opened(now: std::time::Instant, magnitude: u64) -> Self {
        Self {
            window_started: now,
            withheld: 0,
            worst_withheld: None,
            paged_magnitude: magnitude,
            escalated: false,
        }
    }

    /// Hold an occurrence back, keeping it if it is the worst seen this window.
    ///
    /// `>=` rather than `>` so that among equally-bad occurrences the most
    /// recent is the one reported: they rank the same, and the newer one is the
    /// more useful thing to hand an operator.
    fn withhold(&mut self, severity: Severity, message: &str, magnitude: u64) {
        self.withheld += 1;
        if self.worst_withheld.as_ref().is_none_or(|w| magnitude >= w.magnitude) {
            self.worst_withheld = Some(Withheld {
                severity,
                message: message.to_string(),
                magnitude,
            });
        }
    }

    /// Close the window and open the next one, returning the occurrence to page,
    /// how many others it stands in for, and how long the closed window ran.
    ///
    /// `None` when nothing was withheld — and in that case the state is left
    /// entirely alone, so an idle id is not repeatedly "closed" by the flush
    /// timer and its next occurrence still pages immediately.
    fn close_window(
        &mut self,
        now: std::time::Instant,
        window_age: std::time::Duration,
    ) -> Option<(Withheld, u64, u64)> {
        let worst = self.worst_withheld.take()?;
        // The reported count excludes the one being paged: it *is* one of the
        // withheld occurrences, not an extra on top of them.
        let others = self.withheld.saturating_sub(1);
        self.window_started = now;
        self.withheld = 0;
        self.escalated = false;
        self.paged_magnitude = worst.magnitude;
        Some((worst, others, window_age.as_secs()))
    }
}

/// Render one `-alertnotify` line, optionally accounting for occurrences the
/// window withheld.
fn format_event(
    severity: Severity,
    id: &str,
    message: &str,
    withheld_others: u64,
    window_secs: u64,
) -> String {
    let mut msg = format!("[{}] {}: {}", severity.as_str(), id, message);
    if withheld_others > 0 {
        // Square brackets and a real elapsed time, both deliberately.
        //
        // `-alertnotify` substitution replaces shell metacharacters with
        // spaces, and `(`, `)` and `|` are on that list — so the obvious
        // "(N further occurrence(s))" reached the operator's hook as
        // "N further occurrence s ". Brackets, commas and digits survive it.
        //
        // And the window is reported as measured, not as configured: a burst
        // drained by the flush timer or by an occurrence minutes later did not
        // happen "in the previous 60s", and a page that misdates itself is
        // worse than one that says nothing about timing.
        let _ = write!(msg, " [{withheld_others} more in the previous {window_secs}s]");
    }
    msg
}

impl Default for NodeWarnings {
    fn default() -> Self {
        Self::new()
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn record_and_clear_roundtrip() {
        let w = NodeWarnings::new();
        assert_eq!(w.count(), 0);
        w.record("foo.bar", Severity::Error, "oops", json!({"h": 1}));
        assert_eq!(w.count(), 1);
        assert!(w.has_errors());

        w.clear("foo.bar");
        assert_eq!(w.count(), 0);
        assert!(!w.has_errors());
    }

    #[test]
    fn record_same_id_increments_count_without_duplicate() {
        let w = NodeWarnings::new();
        for i in 0..5 {
            w.record(
                "retry.thing",
                Severity::Warn,
                format!("retry {i}"),
                json!({"i": i}),
            );
        }
        assert_eq!(w.count(), 1);
        let list = w.list();
        assert_eq!(list[0].count, 5);
        assert_eq!(list[0].message, "retry 4"); // latest message wins
        assert_eq!(list[0].context["i"], 4);
    }

    #[test]
    fn list_orders_errors_first() {
        let w = NodeWarnings::new();
        // Warn recorded first chronologically.
        w.record("warn.early", Severity::Warn, "warn", json!(null));
        std::thread::sleep(std::time::Duration::from_millis(10));
        w.record("err.late", Severity::Error, "err", json!(null));
        let list = w.list();
        assert_eq!(list[0].id, "err.late");
        assert_eq!(list[1].id, "warn.early");
    }

    #[test]
    fn as_strings_is_core_compatible() {
        let w = NodeWarnings::new();
        w.record("connect.missing", Severity::Error, "block 945989 won't connect", json!({"h": 945989}));
        let strings = w.as_strings();
        assert_eq!(strings.len(), 1);
        assert!(strings[0].contains("error"));
        assert!(strings[0].contains("connect.missing"));
        assert!(strings[0].contains("block 945989 won't connect"));
        assert!(strings[0].contains("×1"));
    }

    #[test]
    fn has_errors_ignores_warn_only() {
        let w = NodeWarnings::new();
        w.record("just.warn", Severity::Warn, "meh", json!(null));
        assert!(!w.has_errors());
        w.record("real.err", Severity::Error, "bad", json!(null));
        assert!(w.has_errors());
    }

    #[test]
    fn clear_missing_is_noop() {
        let w = NodeWarnings::new();
        w.clear("never.recorded"); // no panic
    }

    #[test]
    fn alert_notifier_fires_once_per_new_id() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        // First occurrence fires; the message carries severity + id + text.
        w.record("disk.full", Severity::Error, "out of space", json!(null));
        let msg = rx.try_recv().expect("first record should fire alertnotify");
        assert!(msg.contains("error"));
        assert!(msg.contains("disk.full"));
        assert!(msg.contains("out of space"));

        // Repeats of the same id only bump the count — they do NOT re-fire,
        // so the hook isn't flooded by an N-times-recorded condition.
        w.record("disk.full", Severity::Error, "still out of space", json!(null));
        assert!(rx.try_recv().is_err(), "repeat of same id must not re-fire");

        // A new id fires again.
        w.record("peer.stall", Severity::Warn, "no progress", json!(null));
        let msg2 = rx.try_recv().expect("new id should fire");
        assert!(msg2.contains("peer.stall"));
    }

    /// A one-shot event pages, but must not become a standing warning.
    ///
    /// Nothing ever clears an event that has no resolved state, so recording
    /// one would pin `getwarnings`, keep `has_errors()` true for the life of
    /// the process, and hold the TUI's blocking modal open — permanently, from
    /// the first deep reorg, on chains where those are routine.
    #[test]
    fn notify_event_fires_the_hook_without_recording_a_warning() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        w.notify_event("alert.deep_reorg", Severity::Error, "reorg rolled back 4 blocks", 4);

        let msg = rx.try_recv().expect("a one-shot event must still page");
        assert!(msg.contains("alert.deep_reorg"), "{msg}");
        assert_eq!(w.count(), 0, "it must not become a standing warning");
        assert!(!w.has_errors(), "and must not wedge has_errors()");
        assert!(w.as_strings().is_empty(), "nor appear in getwarnings");
    }

    /// A burst of equally-bad occurrences pages once and holds the rest, rather
    /// than queueing a shell exec per occurrence on an unbounded channel (#497).
    ///
    /// This replaces an earlier test asserting that *every* occurrence pages.
    /// That was the behaviour the issue was filed about: unlike `record`, which
    /// dedupes by id, `notify_event` had no floor at all, so a scripted
    /// `invalidateblock`/`reconsiderblock` loop or a thin-hashrate chain having
    /// a rough patch queued one exec per reorg on a channel the notifier task
    /// drains one at a time.
    #[test]
    fn a_burst_of_events_pages_once_and_holds_the_rest() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        // Equal magnitude throughout: nothing here escalates, so the floor is
        // the only thing being exercised.
        for i in 0..5 {
            w.notify_event("alert.deep_reorg", Severity::Error, format!("reorg {i}"), 6);
        }

        let first = rx.try_recv().expect("the first occurrence must page");
        assert!(first.contains("reorg 0"), "{first}");
        assert!(
            rx.try_recv().is_err(),
            "the rest of the burst must not each queue a hook"
        );
        assert_eq!(w.count(), 0, "still not a standing warning");
    }

    /// **The worst occurrence in a window must reach the operator.**
    ///
    /// A rate limiter that keeps whichever event arrived first, and discards the
    /// rest to a counter, inverts what a paging hook is for: a depth-3 reorg
    /// claims the window, a depth-200 reorg a second later becomes `+= 1`, and
    /// an exchange that halts deposits on `-alertnotify` is paged about the
    /// benign one and never told about the serious one.
    ///
    /// Something strictly worse than anything already paged escalates through
    /// immediately.
    #[test]
    fn a_worse_occurrence_escalates_through_the_window() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        w.notify_event("alert.deep_reorg", Severity::Error, "rolled back 3 blocks", 3);
        let benign = rx.try_recv().expect("the first occurrence pages");
        assert!(benign.contains("3 blocks"), "{benign}");

        // Well inside the window, and far worse.
        w.notify_event("alert.deep_reorg", Severity::Error, "rolled back 200 blocks", 200);
        let serious = rx
            .try_recv()
            .expect("a strictly worse occurrence must not wait out the window");
        assert!(serious.contains("200 blocks"), "{serious}");
    }

    /// Escalation is capped at one per window, so a monotonically rising
    /// sequence — which is exactly what a scripted `invalidateblock` walk
    /// produces — cannot page per occurrence and defeat the floor.
    #[test]
    fn escalation_is_capped_at_one_per_window() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        for depth in 1..=20 {
            w.notify_event("alert.deep_reorg", Severity::Error, format!("depth {depth}"), depth);
        }

        let first = rx.try_recv().expect("first pages");
        assert!(first.contains("depth 1"), "{first}");
        let escalation = rx.try_recv().expect("the first escalation pages");
        assert!(escalation.contains("depth 2"), "{escalation}");
        assert!(
            rx.try_recv().is_err(),
            "a rising sequence must still be floored at two execs per window"
        );

        // The rest are held, not dropped: closing the window pages the worst of
        // them, which is the deepest reorg, not the next one in sequence.
        w.rewind_event_window_for_test("alert.deep_reorg");
        w.flush_due_events();
        let held = rx.try_recv().expect("the held remainder must be reported");
        assert!(held.contains("depth 20"), "the worst held one, not the first: {held}");
    }

    /// Nothing is *lost*: once the window closes, the next occurrence pages,
    /// reports the worst thing the window held, and says how many others it
    /// stands in for. Suppressing silently would turn a burst into something
    /// that looks like one isolated event.
    #[test]
    fn the_next_event_after_the_window_reports_the_worst_of_what_was_held() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        w.notify_event("alert.deep_reorg", Severity::Error, "reorg 0", 9);
        let _ = rx.try_recv().expect("first pages");
        // All below the paged magnitude, so none of them escalate; the middle
        // one is the worst of the held set.
        for (i, depth) in [(1, 4), (2, 8), (3, 5)] {
            w.notify_event("alert.deep_reorg", Severity::Error, format!("reorg {i}"), depth);
        }
        assert!(rx.try_recv().is_err(), "held inside the window");

        w.rewind_event_window_for_test("alert.deep_reorg");
        w.notify_event("alert.deep_reorg", Severity::Error, "reorg 4", 1);

        let msg = rx.try_recv().expect("must page again after the window");
        assert!(
            msg.contains("reorg 2"),
            "the worst held occurrence must be the one reported, not the newest \
             arrival and not the first: {msg}"
        );
        assert!(
            msg.contains("3 more in the previous"),
            "the message must account for the rest of the burst: {msg}"
        );

        // And the counter resets, so the next window starts clean.
        w.rewind_event_window_for_test("alert.deep_reorg");
        w.notify_event("alert.deep_reorg", Severity::Error, "reorg 5", 1);
        let msg = rx.try_recv().expect("pages");
        assert!(!msg.contains("more in the previous"), "counter must reset: {msg}");
    }

    /// A burst that simply *stops* must still be reported. Draining only on the
    /// next occurrence of the same id means quiet — the state an operator is
    /// least likely to go looking at — is where the worst event gets stranded.
    #[test]
    fn a_burst_followed_by_quiet_is_flushed_by_the_timer() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        w.notify_event("alert.deep_reorg", Severity::Error, "reorg 0", 2);
        let _ = rx.try_recv().expect("first pages");
        w.notify_event("alert.deep_reorg", Severity::Error, "reorg 1", 1);
        w.notify_event("alert.deep_reorg", Severity::Error, "reorg 2", 1);

        // Nothing further ever arrives for this id.
        w.flush_due_events();
        assert!(rx.try_recv().is_err(), "not due yet — the window is still open");

        w.rewind_event_window_for_test("alert.deep_reorg");
        w.flush_due_events();
        let msg = rx.try_recv().expect("the held burst must page once the window closes");
        assert!(msg.contains("reorg"), "{msg}");
        assert!(msg.contains("1 more in the previous"), "{msg}");

        // Idempotent: a second tick with nothing held sends nothing, and does
        // not reopen or re-close anything.
        w.flush_due_events();
        w.rewind_event_window_for_test("alert.deep_reorg");
        w.flush_due_events();
        assert!(rx.try_recv().is_err(), "an idle id must not page on every tick");
    }

    /// The window is reported as measured, not as configured. A page that
    /// misdates the burst it is summarising is worse than one that says nothing
    /// about timing at all.
    #[test]
    fn the_reported_window_is_the_elapsed_one_not_the_configured_one() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        w.notify_event("alert.deep_reorg", Severity::Error, "reorg 0", 1);
        let _ = rx.try_recv().expect("first pages");
        w.notify_event("alert.deep_reorg", Severity::Error, "reorg 1", 1);
        w.notify_event("alert.deep_reorg", Severity::Error, "reorg 2", 1);

        // `rewind_event_window_for_test` backdates by the interval plus a
        // second, so the window as measured is 61s — not the configured 60.
        w.rewind_event_window_for_test("alert.deep_reorg");
        w.flush_due_events();
        let msg = rx.try_recv().expect("pages");
        assert!(
            msg.contains("in the previous 61s"),
            "the elapsed window, not the constant: {msg}"
        );
    }

    /// The message has to survive `-alertnotify` substitution, which replaces
    /// shell metacharacters — `(`, `)` and `|` among them — with spaces. The
    /// first cut of this suffix read "3 further occurrence(s)" and reached the
    /// operator's hook as "3 further occurrence s ".
    #[test]
    fn the_suffix_survives_alertnotify_shell_sanitisation() {
        // Same character class `satd::notifyhooks::sanitize_subst` replaces.
        const METACHARS: [char; 15] = [
            '`', '$', ';', '&', '|', '<', '>', '(', ')', '\\', '\'', '"', '\n', '\r', '\0',
        ];
        let rendered = format_event(Severity::Error, "alert.deep_reorg", "rolled back 9", 3, 74);
        let suffix = rendered
            .split_once("rolled back 9")
            .expect("the message body is present")
            .1;
        assert_eq!(suffix, " [3 more in the previous 74s]", "{rendered}");
        for c in METACHARS {
            assert!(
                !suffix.contains(c),
                "the hook rewrites {c:?} to a space, mangling the suffix: {suffix:?}"
            );
        }
    }

    /// The limit is per id, so one noisy event cannot mute a different one.
    #[test]
    fn the_rate_limit_is_per_event_id() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        w.notify_event("alert.deep_reorg", Severity::Error, "reorg", 5);
        w.notify_event("alert.deep_reorg", Severity::Error, "reorg again", 5);
        w.notify_event("alert.other_thing", Severity::Warn, "unrelated", 0);

        let a = rx.try_recv().expect("first id pages");
        assert!(a.contains("alert.deep_reorg"), "{a}");
        let b = rx.try_recv().expect("a different id must page independently");
        assert!(b.contains("alert.other_thing"), "{b}");
        assert!(rx.try_recv().is_err());
    }

    /// An id with no meaningful magnitude scale passes 0 for every occurrence,
    /// where nothing can ever be "strictly worse" and the limiter is a plain
    /// one-per-window floor.
    #[test]
    fn a_scaleless_id_degrades_to_plain_rate_limiting() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        for i in 0..10 {
            w.notify_event("alert.other_thing", Severity::Warn, format!("thing {i}"), 0);
        }
        let first = rx.try_recv().expect("first pages");
        assert!(first.contains("thing 0"), "{first}");
        assert!(rx.try_recv().is_err(), "no magnitude means no escalation path");
    }

    /// Ids that embed an identifier — `blockdata.corrupt.<hash>` is one per
    /// damaged block, and nothing ever clears them — must not be able to grow
    /// the registry without bound. A storage fault across thousands of blocks
    /// would otherwise fill `getwarnings`, queue an `-alertnotify` exec per row,
    /// and leave the TUI's blocking modal holding a list nobody can read.
    #[test]
    fn the_registry_caps_distinct_ids_and_counts_the_overflow() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        for i in 0..MAX_ACTIVE_WARNINGS {
            w.record(&format!("blockdata.corrupt.{i}"), Severity::Error, "bad", json!(null));
        }
        assert_eq!(w.count(), MAX_ACTIVE_WARNINGS);
        while rx.try_recv().is_ok() {}

        for i in MAX_ACTIVE_WARNINGS..MAX_ACTIVE_WARNINGS + 50 {
            w.record(&format!("blockdata.corrupt.{i}"), Severity::Error, "bad", json!(null));
        }
        assert_eq!(
            w.count(),
            MAX_ACTIVE_WARNINGS + 1,
            "the overflow row is the only thing added past the cap"
        );

        let overflow = w
            .list()
            .into_iter()
            .find(|entry| entry.id == OVERFLOW_WARNING_ID)
            .expect("the overflow row exists");
        assert_eq!(overflow.count, 50, "every dropped id is counted");
        assert_eq!(
            overflow.context["most_recent_dropped_id"],
            format!("blockdata.corrupt.{}", MAX_ACTIVE_WARNINGS + 49)
        );

        // One page for the overflow condition, not one per dropped id.
        let paged: Vec<String> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(paged.len(), 1, "{paged:?}");
        assert!(paged[0].contains(OVERFLOW_WARNING_ID), "{}", paged[0]);
    }

    /// The cap must not displace a condition that is already being tracked: an
    /// established warning still updates, and clearing one frees the slot.
    #[test]
    fn an_already_active_id_still_updates_past_the_cap() {
        let w = NodeWarnings::new();
        w.record("storage.flush_failed", Severity::Error, "first", json!(null));
        for i in 0..MAX_ACTIVE_WARNINGS + 20 {
            w.record(&format!("blockdata.corrupt.{i}"), Severity::Error, "bad", json!(null));
        }
        w.record("storage.flush_failed", Severity::Error, "still failing", json!(null));

        let tracked = w
            .list()
            .into_iter()
            .find(|entry| entry.id == "storage.flush_failed")
            .expect("an established id is never displaced");
        assert_eq!(tracked.count, 2);
        assert_eq!(tracked.message, "still failing");
    }

    #[test]
    fn record_without_alert_notifier_is_fine() {
        // The common path: no -alertnotify configured, no sink installed.
        let w = NodeWarnings::new();
        w.record("x.y", Severity::Warn, "z", json!(null));
        assert_eq!(w.count(), 1);
    }
}
