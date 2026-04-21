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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

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
}

impl NodeWarnings {
    pub fn new() -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Record a warning. If `id` is already active, increment count
    /// and refresh `last_seen`, `severity`, `message`, `context`.
    pub fn record(
        &self,
        id: &str,
        severity: Severity,
        message: impl Into<String>,
        context: serde_json::Value,
    ) {
        let now = unix_secs();
        let message: String = message.into();
        let mut active = self.active.lock().unwrap();
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
                message,
                first_seen_unix_secs: now,
                last_seen_unix_secs: now,
                count: 1,
                context,
            });
    }

    /// Clear a warning by id. No-op if not present.
    pub fn clear(&self, id: &str) {
        let mut active = self.active.lock().unwrap();
        active.remove(id);
    }

    /// Active warnings, sorted `Error` first then by first_seen asc.
    pub fn list(&self) -> Vec<Warning> {
        let active = self.active.lock().unwrap();
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
            .unwrap()
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
        self.active.lock().unwrap().len()
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
}
