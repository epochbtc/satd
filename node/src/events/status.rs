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
    /// No block connected for longer than the configured window. Clears when
    /// the next block connects.
    ///
    /// Deliberately *not* suppressed during initial block download:
    /// `is_initial_block_download()` compares the tip header's timestamp
    /// against the wall clock rather than tracking sync progress, so a node
    /// that was caught up and then wedged re-enters it exactly when the
    /// operator most needs paging. A node that is genuinely syncing connects
    /// blocks continuously and never crosses the threshold on its own.
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
    ///
    /// Kept exhaustive by the compile-time guard below the impl block. A kind
    /// missing from here compiles clean and fails only at runtime, invisibly:
    /// `from_str_exact` scans `ALL`, so the alertfile would reject
    /// `kinds = ["the_new_kind"]` as unknown even though the streaming docs
    /// list it, and the metric would never be pre-registered.
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

/// Compile-time guard that [`StatusKind::ALL`] lists every variant.
///
/// Adding a variant makes this `match` non-exhaustive and fails the build here,
/// pointing at the array that needs updating — rather than shipping a kind that
/// the alertfile parser rejects and the metrics registry never sees.
const _: () = {
    const fn every_variant_is_in_all(k: StatusKind) -> usize {
        match k {
            StatusKind::IbdComplete => 0,
            StatusKind::TipStall => 1,
            StatusKind::DiskLow => 2,
            StatusKind::MempoolCongested => 3,
            StatusKind::PeerFloor => 4,
            StatusKind::DeepReorg => 5,
        }
    }
    // Also pins the array's length to the variant count.
    assert!(StatusKind::ALL.len() == every_variant_is_in_all(StatusKind::DeepReorg) + 1);
};

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
    /// Kind-specific structured fields, as strings.
    ///
    /// Mostly decimal numbers, but **not** universally: a `cleared` event can
    /// carry a `reason` token (`detector_disabled`, `mempool_cap_zero`). A
    /// consumer must not parse the map uniformly as integers.
    ///
    /// A `BTreeMap` (not a `HashMap`) so the rendered JSON has a deterministic
    /// key order — the webhook body is HMAC-signed, and golden signature
    /// vectors would be unreproducible under map-iteration order.
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
            message: truncate(&message.into(), MAX_MESSAGE_LEN),
            details: BTreeMap::new(),
        }
    }

    /// A condition entering.
    ///
    /// An edge kind has no standing state, so it is coerced to
    /// [`StatusState::Edge`] rather than shipping a `raised` a consumer would
    /// wait forever to see cleared. These constructors are total on purpose:
    /// the kind is a runtime parameter at both call sites in `health.rs`, so a
    /// mismatch is reachable, and a `debug_assert!` would let a release build
    /// emit the malformed event silently — leaving `satd_alert_active{kind=…}`
    /// stuck at 1 and a receiver waiting on a `cleared` that cannot come.
    pub fn raised(kind: StatusKind, message: impl Into<String>) -> Self {
        Self::build(kind, Self::state_for(kind, StatusState::Raised), message)
    }

    /// A condition recovering. Coerced to [`StatusState::Edge`] for edge kinds,
    /// which never clear — see [`raised`](Self::raised).
    pub fn cleared(kind: StatusKind, message: impl Into<String>) -> Self {
        Self::build(kind, Self::state_for(kind, StatusState::Cleared), message)
    }

    /// The state an event of this kind may actually carry.
    fn state_for(kind: StatusKind, requested: StatusState) -> StatusState {
        if kind.is_edge() {
            StatusState::Edge
        } else if requested == StatusState::Edge {
            // A standing kind cannot be an edge; `raised` is the honest
            // reading of "this just happened" for one.
            StatusState::Raised
        } else {
            requested
        }
    }

    /// A one-shot observation.
    pub fn edge(kind: StatusKind, message: impl Into<String>) -> Self {
        Self::build(kind, Self::state_for(kind, StatusState::Edge), message)
    }

    /// Attach a structured detail field (builder style). Values are stringified
    /// by the caller so the map stays additive forever.
    ///
    /// Both key and value are truncated to [`MAX_DETAIL_LEN`]. Every producer
    /// is in-tree today and emits short tokens, but this body rides a 4096-slot
    /// broadcast to every subscriber *and* goes inside an HMAC-signed webhook
    /// payload, so the first detector to interpolate peer-supplied text (a user
    /// agent, a reject reason) should not be able to size either.
    #[must_use]
    pub fn with_detail(mut self, key: &str, value: impl ToString) -> Self {
        self.details
            .insert(truncate(key, MAX_DETAIL_LEN), truncate(&value.to_string(), MAX_DETAIL_LEN));
        self
    }
}

/// Cap on any single `details` key or value.
pub const MAX_DETAIL_LEN: usize = 256;

/// Cap on the human-readable `message`.
pub const MAX_MESSAGE_LEN: usize = 1024;

/// Truncate on a UTF-8 boundary (slicing mid-codepoint would panic).
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
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
