//! Node-health status events (`status` category, bit
//! [`CATEGORY_STATUS`](super::CATEGORY_STATUS)).
//!
//! A [`StatusEvent`] is the daemon reporting a condition about *itself* —
//! stalled tip, low disk, congested mempool, peer starvation — rather than
//! about the chain or the mempool's contents. They are the substrate for
//! operator alerting: the same event feeds the streaming carriers, the
//! `-alertnotify` shell hook (via the warnings registry), and the webhook
//! dispatcher, so those three can never disagree about node state.
//!
//! Firing semantics are **level-triggered**: a standing condition emits
//! exactly one [`StatusState::Raised`] on entry and exactly one
//! [`StatusState::Cleared`] on recovery, with hysteresis between the two
//! thresholds so a value hovering at the line does not flap. Observations with
//! no "recovered" state (IBD finishing, a deep reorg landing) are
//! [`StatusState::Edge`] and never produce a clear.
//!
//! Status events carry no durable cursor and are not retained in the replay
//! ring: they are not replayable. Durability comes from re-evaluation instead
//! — detectors re-examine every condition at startup and re-raise the ones
//! still standing, which is what makes health alerting at-least-once across a
//! restart without any replay machinery. A condition that both raised and
//! fully cleared while a consumer was away is stale by definition and is not
//! reconstructed.

use std::collections::BTreeMap;

use serde::Serialize;

/// Which health condition a [`StatusEvent`] describes.
///
/// Additive: consumers switch on the kind and **must** tolerate an
/// unrecognized one (a newer node talking to an older client during a rolling
/// upgrade) — `message` and `severity` stay meaningful in that case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusKind {
    /// Initial block download finished (edge, at most once per process).
    IbdComplete,
    /// No block connected for longer than the configured window, while not in
    /// IBD. Clears when the next block connects.
    TipStall,
    /// Free space on the data (or blocks) directory fell below the configured
    /// floor. Clears with hysteresis above it.
    DiskLow,
    /// Mempool occupancy crossed the configured percentage of its byte cap.
    MempoolCongested,
    /// Connected-peer count sat below the configured floor for the hold time.
    PeerFloor,
    /// A reorg at least `alertreorgdepth` blocks deep was applied (edge).
    DeepReorg,
}

impl StatusKind {
    /// The snake_case wire name, also used as the stable
    /// [`NodeWarnings`](crate::warnings::NodeWarnings) id suffix
    /// (`alert.<name>`) and the `satd_alert_active{kind=...}` label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            StatusKind::IbdComplete => "ibd_complete",
            StatusKind::TipStall => "tip_stall",
            StatusKind::DiskLow => "disk_low",
            StatusKind::MempoolCongested => "mempool_congested",
            StatusKind::PeerFloor => "peer_floor",
            StatusKind::DeepReorg => "deep_reorg",
        }
    }

    /// Every kind, for config validation and metric pre-registration.
    pub const ALL: [StatusKind; 6] = [
        StatusKind::IbdComplete,
        StatusKind::TipStall,
        StatusKind::DiskLow,
        StatusKind::MempoolCongested,
        StatusKind::PeerFloor,
        StatusKind::DeepReorg,
    ];

    /// Parse a wire name (the inverse of [`as_str`](Self::as_str)). Used by
    /// the alertfile's per-hook `kinds` filter, which rejects unknown names
    /// rather than silently matching nothing.
    pub fn from_str_exact(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// Whether this kind is a one-shot observation (no `cleared` will follow).
    pub const fn is_edge(self) -> bool {
        matches!(self, StatusKind::IbdComplete | StatusKind::DeepReorg)
    }

    /// The severity a detector reports this kind at. Fixed per kind in v1 (a
    /// hook filters with `min_severity`, it does not reassign severities).
    pub const fn severity(self) -> StatusSeverity {
        match self {
            StatusKind::IbdComplete => StatusSeverity::Info,
            StatusKind::TipStall | StatusKind::DiskLow | StatusKind::DeepReorg => {
                StatusSeverity::Critical
            }
            StatusKind::MempoolCongested | StatusKind::PeerFloor => StatusSeverity::Warning,
        }
    }

    /// The stable [`NodeWarnings`](crate::warnings::NodeWarnings) id for this
    /// kind, so `getwarnings` / `-alertnotify` and the status stream agree.
    pub fn warning_id(self) -> String {
        format!("alert.{}", self.as_str())
    }
}

/// Level-triggered lifecycle of a condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusState {
    /// Condition entered; stands until a matching [`Cleared`](Self::Cleared).
    Raised,
    /// Condition recovered.
    Cleared,
    /// One-shot observation; no clear will follow.
    Edge,
}

/// How loud a condition is. Ordered, so a hook's `min_severity` filter is a
/// simple comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusSeverity {
    Info,
    Warning,
    Critical,
}

impl StatusSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            StatusSeverity::Info => "info",
            StatusSeverity::Warning => "warning",
            StatusSeverity::Critical => "critical",
        }
    }

    /// Parse a wire name; used by the alertfile's `min_severity` key, which
    /// rejects unknown names.
    pub fn from_str_exact(s: &str) -> Option<Self> {
        match s {
            "info" => Some(StatusSeverity::Info),
            "warning" => Some(StatusSeverity::Warning),
            "critical" => Some(StatusSeverity::Critical),
            _ => None,
        }
    }
}

/// One node-health observation, carried by
/// [`NodeEventBody::Status`](super::NodeEventBody::Status).
///
/// Serializes flat under the envelope's `category` tag:
/// ```json
/// {"category":"status","kind":"tip_stall","state":"raised",
///  "severity":"critical","message":"no block connected for 3612s",
///  "details":{"seconds_since_block":"3612","threshold_seconds":"3600"}}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusEvent {
    pub kind: StatusKind,
    pub state: StatusState,
    pub severity: StatusSeverity,
    /// Human-readable one-liner. Safe to log or page on, **not** to parse:
    /// machine consumers switch on `kind` and read `details`.
    pub message: String,
    /// Kind-specific structured fields as decimal strings. A `BTreeMap` (not a
    /// `HashMap`) so the rendered JSON has a deterministic key order — the
    /// webhook body is HMAC-signed, and golden signature vectors would be
    /// unreproducible under map-iteration order.
    pub details: BTreeMap<String, String>,
}

impl StatusEvent {
    /// Build an event, taking the severity from the kind and the state from
    /// whether the kind is an edge observation.
    fn build(kind: StatusKind, state: StatusState, message: impl Into<String>) -> Self {
        Self {
            kind,
            state,
            severity: kind.severity(),
            message: message.into(),
            details: BTreeMap::new(),
        }
    }

    /// A condition entering. Panics in debug builds for edge kinds, which have
    /// no standing state — use [`edge`](Self::edge) for those.
    pub fn raised(kind: StatusKind, message: impl Into<String>) -> Self {
        debug_assert!(!kind.is_edge(), "{} is an edge kind", kind.as_str());
        Self::build(kind, StatusState::Raised, message)
    }

    /// A condition recovering.
    pub fn cleared(kind: StatusKind, message: impl Into<String>) -> Self {
        debug_assert!(!kind.is_edge(), "{} is an edge kind", kind.as_str());
        Self::build(kind, StatusState::Cleared, message)
    }

    /// A one-shot observation.
    pub fn edge(kind: StatusKind, message: impl Into<String>) -> Self {
        debug_assert!(kind.is_edge(), "{} is not an edge kind", kind.as_str());
        Self::build(kind, StatusState::Edge, message)
    }

    /// Attach a structured detail field (builder style). Values are rendered
    /// as decimal strings by the caller so the map stays additive forever.
    #[must_use]
    pub fn with_detail(mut self, key: &str, value: impl ToString) -> Self {
        self.details.insert(key.to_string(), value.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_names_round_trip() {
        for k in StatusKind::ALL {
            assert_eq!(StatusKind::from_str_exact(k.as_str()), Some(k));
        }
        assert_eq!(StatusKind::from_str_exact("no_such_kind"), None);
    }

    #[test]
    fn severity_names_round_trip() {
        for s in [
            StatusSeverity::Info,
            StatusSeverity::Warning,
            StatusSeverity::Critical,
        ] {
            assert_eq!(StatusSeverity::from_str_exact(s.as_str()), Some(s));
        }
        assert_eq!(StatusSeverity::from_str_exact("fatal"), None);
    }

    #[test]
    fn severity_is_ordered_for_min_severity_filters() {
        assert!(StatusSeverity::Critical > StatusSeverity::Warning);
        assert!(StatusSeverity::Warning > StatusSeverity::Info);
    }

    #[test]
    fn warning_ids_are_namespaced() {
        assert_eq!(StatusKind::DiskLow.warning_id(), "alert.disk_low");
    }

    #[test]
    fn edge_kinds_have_no_clear() {
        assert!(StatusKind::IbdComplete.is_edge());
        assert!(StatusKind::DeepReorg.is_edge());
        assert!(!StatusKind::TipStall.is_edge());
    }

    #[test]
    fn details_serialize_in_deterministic_order() {
        // The webhook body is HMAC-signed; a non-deterministic key order would
        // make golden signature vectors unreproducible.
        let ev = StatusEvent::raised(StatusKind::DiskLow, "low")
            .with_detail("z_last", 1)
            .with_detail("a_first", 2)
            .with_detail("m_middle", 3);
        let json = serde_json::to_string(&ev.details).unwrap();
        assert_eq!(json, r#"{"a_first":"2","m_middle":"3","z_last":"1"}"#);
    }

    #[test]
    fn serde_shape_is_flat_snake_case() {
        let ev = StatusEvent::raised(StatusKind::TipStall, "no block connected for 3612s")
            .with_detail("seconds_since_block", 3612u64);
        let json = serde_json::to_string(&ev).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"tip_stall","state":"raised","severity":"critical","message":"no block connected for 3612s","details":{"seconds_since_block":"3612"}}"#
        );
    }
}
