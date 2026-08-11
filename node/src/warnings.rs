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
    /// Per-id rate-limit state for [`notify_event`](Self::notify_event):
    /// when the last exec fired, and how many occurrences have been suppressed
    /// since. See `EVENT_HOOK_MIN_INTERVAL`.
    event_rate: Mutex<HashMap<String, EventRate>>,
}

#[derive(Debug)]
struct EventRate {
    last_fired: std::time::Instant,
    suppressed: u64,
}

/// Minimum interval between `-alertnotify` execs for the same **edge-event**
/// id.
///
/// Edge events fire per occurrence by design — three reorgs are three things
/// that happened, and deduping them by id would lose information an operator
/// wants, which is why [`notify_event`](NodeWarnings::notify_event) exists
/// separately from [`record`](NodeWarnings::record). But each message spawns a
/// shell command over an unbounded channel, so "per occurrence" with no floor
/// means a burst of at-threshold reorgs — a scripted
/// `invalidateblock`/`reconsiderblock` loop, or a thin-hashrate chain having a
/// rough time — queues one process spawn each, unboundedly (#497).
///
/// A rate limit rather than dedup keeps the semantics: nothing is collapsed,
/// occurrences during the window are *counted* and reported on the next exec,
/// so the operator learns both that it happened again and how often. One
/// minute is well below any human response time to a paging hook, and the
/// full-fidelity record is unaffected — the subsystem's own log and the
/// `status` event on the streaming API still carry every occurrence.
const EVENT_HOOK_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

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
    /// hook is rate-limited per id by `EVENT_HOOK_MIN_INTERVAL`, and
    /// occurrences inside that window are counted and reported on the next
    /// exec. Without a floor, a burst of at-threshold reorgs would queue one
    /// process spawn each on an unbounded channel (#497).
    ///
    /// The rate limit applies only to this shell hook. The durable,
    /// full-fidelity record of what happened is the subsystem's own log
    /// (`ReorgLog` for reorgs) and the `status` event on the streaming API,
    /// neither of which this touches.
    pub fn notify_event(&self, id: &str, severity: Severity, message: impl Into<String>) {
        // Decide under the rate-limit lock, then send outside it.
        let suppressed_before = {
            let now = std::time::Instant::now();
            let mut rate = self.event_rate.lock();
            match rate.get_mut(id) {
                Some(state) if now.duration_since(state.last_fired) < EVENT_HOOK_MIN_INTERVAL => {
                    state.suppressed += 1;
                    return;
                }
                Some(state) => {
                    let n = state.suppressed;
                    state.last_fired = now;
                    state.suppressed = 0;
                    n
                }
                None => {
                    rate.insert(
                        id.to_string(),
                        EventRate {
                            last_fired: now,
                            suppressed: 0,
                        },
                    );
                    0
                }
            }
        };

        let guard = self.alert_tx.lock();
        if let Some(tx) = guard.as_ref() {
            let mut msg = format!("[{}] {}: {}", severity.as_str(), id, message.into());
            if suppressed_before > 0 {
                // Say what the window hid, so a burst is visibly a burst
                // rather than looking like a single isolated event.
                let _ = write!(
                    msg,
                    " ({suppressed_before} further occurrence(s) in the previous {}s)",
                    EVENT_HOOK_MIN_INTERVAL.as_secs()
                );
            }
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
        // identical repeats). The send is non-blocking and best-effort: a
        // dropped receiver (hook task gone) just no-ops.
        if is_new {
            let guard = self.alert_tx.lock();
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(format!("[{}] {}: {}", severity.as_str(), id, message));
            }
        }
    }

    /// Push an event id's rate-limit window into the past so the next
    /// `notify_event` for it is allowed through.
    ///
    /// Test-only. The window is measured with `Instant`, which cannot be
    /// faked, and sleeping for the real interval would put a minute of wall
    /// clock into the suite for every case.
    #[cfg(test)]
    fn rewind_event_window_for_test(&self, id: &str) {
        if let Some(state) = self.event_rate.lock().get_mut(id) {
            state.last_fired -= EVENT_HOOK_MIN_INTERVAL + std::time::Duration::from_secs(1);
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

        w.notify_event("alert.deep_reorg", Severity::Error, "reorg rolled back 4 blocks");

        let msg = rx.try_recv().expect("a one-shot event must still page");
        assert!(msg.contains("alert.deep_reorg"), "{msg}");
        assert_eq!(w.count(), 0, "it must not become a standing warning");
        assert!(!w.has_errors(), "and must not wedge has_errors()");
        assert!(w.as_strings().is_empty(), "nor appear in getwarnings");
    }

    /// A burst pages once and counts the rest, rather than spawning a shell
    /// command per occurrence on an unbounded channel (#497).
    ///
    /// This replaces an earlier test asserting that *every* occurrence pages.
    /// That was the behaviour the issue was filed about: unlike `record`, which
    /// dedupes by id, `notify_event` had no floor at all, so a scripted
    /// `invalidateblock`/`reconsiderblock` loop or a thin-hashrate chain having
    /// a rough patch queued one process spawn per reorg.
    #[test]
    fn a_burst_of_events_pages_once_and_counts_the_rest() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        for i in 0..5 {
            w.notify_event("alert.deep_reorg", Severity::Error, format!("reorg {i}"));
        }

        let first = rx.try_recv().expect("the first occurrence must page");
        assert!(first.contains("reorg 0"), "{first}");
        assert!(
            rx.try_recv().is_err(),
            "the rest of the burst must not each spawn a hook"
        );
        assert_eq!(w.count(), 0, "still not a standing warning");
    }

    /// Nothing is *lost*: once the window passes, the next occurrence pages and
    /// says how many it stood in for. Suppressing silently would turn a burst
    /// into something that looks like one isolated event.
    #[test]
    fn the_next_event_after_the_window_reports_what_was_suppressed() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        w.notify_event("alert.deep_reorg", Severity::Error, "reorg 0");
        let _ = rx.try_recv().expect("first pages");
        for i in 1..4 {
            w.notify_event("alert.deep_reorg", Severity::Error, format!("reorg {i}"));
        }
        assert!(rx.try_recv().is_err(), "suppressed inside the window");

        w.rewind_event_window_for_test("alert.deep_reorg");
        w.notify_event("alert.deep_reorg", Severity::Error, "reorg 4");

        let msg = rx.try_recv().expect("must page again after the window");
        assert!(msg.contains("reorg 4"), "{msg}");
        assert!(
            msg.contains("3 further occurrence(s)"),
            "the message must account for the suppressed burst: {msg}"
        );

        // And the counter resets, so the next window starts clean.
        w.rewind_event_window_for_test("alert.deep_reorg");
        w.notify_event("alert.deep_reorg", Severity::Error, "reorg 5");
        let msg = rx.try_recv().expect("pages");
        assert!(!msg.contains("further occurrence"), "counter must reset: {msg}");
    }

    /// The limit is per id, so one noisy event cannot mute a different one.
    #[test]
    fn the_rate_limit_is_per_event_id() {
        let w = NodeWarnings::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        w.set_alert_notifier(tx);

        w.notify_event("alert.deep_reorg", Severity::Error, "reorg");
        w.notify_event("alert.deep_reorg", Severity::Error, "reorg again");
        w.notify_event("alert.other_thing", Severity::Warn, "unrelated");

        let a = rx.try_recv().expect("first id pages");
        assert!(a.contains("alert.deep_reorg"), "{a}");
        let b = rx.try_recv().expect("a different id must page independently");
        assert!(b.contains("alert.other_thing"), "{b}");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn record_without_alert_notifier_is_fine() {
        // The common path: no -alertnotify configured, no sink installed.
        let w = NodeWarnings::new();
        w.record("x.y", Severity::Warn, "z", json!(null));
        assert_eq!(w.count(), 1);
    }
}
