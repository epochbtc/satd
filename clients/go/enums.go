package satdevents

import "strconv"

// The wire enums, as int32-backed Go types.
//
// Every one of them is OPEN: a newer node may report a value this build
// predates. Go's numeric enum carries that value through unchanged, so an
// unrecognized code keeps its number (rather than collapsing into the zero
// value) and Known reports false. That is a real distinction to preserve -
// "the producer did not set this field" (the zero value, Unspecified) and "the
// producer set something I do not recognize" are different facts, and folding
// them together is how a reason added by a newer node gets reported as
// unspecified.
//
// A consumer must tolerate an unrecognized value: switch on the ones you know
// and handle the rest generically.

// EvictReason says why a transaction left the mempool by policy.
type EvictReason int32

// Eviction reasons.
const (
	// EvictUnspecified is proto3's zero value: the producer set no reason.
	EvictUnspecified EvictReason = 0
	// EvictFullPool - the pool hit its byte budget.
	EvictFullPool EvictReason = 1
	// EvictExpiry - mempool expiry.
	EvictExpiry EvictReason = 2
	// EvictBlockConflict - a connected block conflicts with it.
	EvictBlockConflict EvictReason = 3
	// EvictPolicy - evicted from the quarantine class on a fee-rate byte-budget
	// overflow.
	EvictPolicy EvictReason = 4
)

// Known reports whether this build recognizes the reason.
func (r EvictReason) Known() bool { return r >= EvictUnspecified && r <= EvictPolicy }

func (r EvictReason) String() string {
	switch r {
	case EvictUnspecified:
		return "unspecified"
	case EvictFullPool:
		return "full_pool"
	case EvictExpiry:
		return "expiry"
	case EvictBlockConflict:
		return "block_conflict"
	case EvictPolicy:
		return "policy"
	default:
		return "unknown(" + strconv.FormatInt(int64(r), 10) + ")"
	}
}

// StatusKind says which node-health condition a [Status] event describes.
//
// Open by design: a newer node may report a kind this build predates. The
// event's Severity and Message stay meaningful in that case, so a generic
// "log it and page on critical" handler keeps working across upgrades.
type StatusKind int32

// Health conditions.
const (
	// StatusKindUnspecified is proto3's zero value: the producer set no kind.
	StatusKindUnspecified StatusKind = 0
	// StatusKindIBDComplete - initial block download finished (one-shot).
	StatusKindIBDComplete StatusKind = 1
	// StatusKindTipStall - no block connected inside the configured window.
	//
	// Not suppressed during initial block download: the node's IBD predicate is
	// the tip header's age, not a sync flag, so a node that was caught up and
	// then wedged re-enters it exactly when you want to hear about it. A
	// genuinely syncing node connects blocks and never crosses the threshold.
	StatusKindTipStall StatusKind = 2
	// StatusKindDiskLow - free space on the watched directory fell below the
	// configured floor.
	StatusKindDiskLow StatusKind = 3
	// StatusKindMempoolCongested - mempool occupancy crossed the configured
	// share of its byte cap.
	StatusKindMempoolCongested StatusKind = 4
	// StatusKindPeerFloor - connected peers stayed below the configured floor.
	StatusKindPeerFloor StatusKind = 5
	// StatusKindDeepReorg - a reorg at least the configured depth landed
	// (one-shot).
	StatusKindDeepReorg StatusKind = 6
)

// Known reports whether this build recognizes the kind.
func (k StatusKind) Known() bool { return k >= StatusKindUnspecified && k <= StatusKindDeepReorg }

func (k StatusKind) String() string {
	switch k {
	case StatusKindUnspecified:
		return "unspecified"
	case StatusKindIBDComplete:
		return "ibd_complete"
	case StatusKindTipStall:
		return "tip_stall"
	case StatusKindDiskLow:
		return "disk_low"
	case StatusKindMempoolCongested:
		return "mempool_congested"
	case StatusKindPeerFloor:
		return "peer_floor"
	case StatusKindDeepReorg:
		return "deep_reorg"
	default:
		return "unknown(" + strconv.FormatInt(int64(k), 10) + ")"
	}
}

// StatusState is the level-triggered lifecycle of a health condition.
type StatusState int32

// Condition lifecycle.
const (
	// StatusStateUnspecified is proto3's zero value: the producer set no state.
	//
	// A consumer tracking standing conditions cannot infer a lifecycle from
	// this - it is neither a raise nor a clear - so treat it as unusable and say
	// so, rather than dropping it silently. Dropping it is how a condition whose
	// CLEAR arrived unset stays standing forever.
	StatusStateUnspecified StatusState = 0
	// StatusStateRaised - the condition was entered; it stands until a matching
	// Cleared.
	StatusStateRaised StatusState = 1
	// StatusStateCleared - the condition recovered.
	StatusStateCleared StatusState = 2
	// StatusStateEdge - a one-shot observation; no Cleared will follow.
	StatusStateEdge StatusState = 3
)

// Known reports whether this build recognizes the state.
func (s StatusState) Known() bool { return s >= StatusStateUnspecified && s <= StatusStateEdge }

func (s StatusState) String() string {
	switch s {
	case StatusStateUnspecified:
		return "unspecified"
	case StatusStateRaised:
		return "raised"
	case StatusStateCleared:
		return "cleared"
	case StatusStateEdge:
		return "edge"
	default:
		return "unknown(" + strconv.FormatInt(int64(s), 10) + ")"
	}
}

// StatusSeverity is how loud a health condition is.
//
// Filter with [StatusSeverity.AtLeast], not with a raw comparison: the ordering
// is by severity RANK, which is
//
//	Unspecified < Info < Warning < Critical < unrecognized
//
// An unrecognized severity ranking above Critical is deliberate - a level this
// build cannot name is not one to quietly filter out, so an additive taxonomy
// change fails loud rather than silent. Unspecified is the opposite case: it is
// proto3's zero value, what an absent field decodes to, an absence of
// information rather than a loud condition, so it ranks lowest and a severity
// floor never promotes it.
//
// satd itself never emits a zero severity - its own enum has three variants and
// the encoder writes one of them explicitly - so Unspecified is defence against
// a third-party producer, an in-path relay that re-encodes the event, or a
// future schema. If you do see it and need a level, Kind is the recovery: in v1
// severity is a fixed function of the condition.
type StatusSeverity int32

// Severity levels.
const (
	// SeverityUnspecified is proto3's zero value: the producer set no severity.
	// Ranks below Info.
	SeverityUnspecified StatusSeverity = 0
	// SeverityInfo - worth knowing, not worth waking anyone (IBD completing).
	SeverityInfo StatusSeverity = 1
	// SeverityWarning - degraded but functioning (peer starvation, a congested
	// mempool).
	SeverityWarning StatusSeverity = 2
	// SeverityCritical - the node is not doing its job, or is about to stop (a
	// stalled tip, a filling disk, a deep reorg).
	SeverityCritical StatusSeverity = 3
)

// Known reports whether this build recognizes the severity.
func (s StatusSeverity) Known() bool {
	return s >= SeverityUnspecified && s <= SeverityCritical
}

// Rank is the severity's sort key: 0 for Unspecified through 3 for Critical,
// and 4 for anything this build does not recognize.
//
// Rank exists because the raw numeric value is not the ordering: a severity
// code this build cannot name must outrank Critical (fail loud), which a
// numeric compare would get wrong for any value below 1.
func (s StatusSeverity) Rank() int {
	if s.Known() {
		return int(s)
	}
	return 4
}

// AtLeast reports whether s is at least as loud as floor, by [StatusSeverity.Rank].
// This is the filter idiom:
//
//	if ev.Severity.AtLeast(satdevents.SeverityWarning) { page(ev) }
func (s StatusSeverity) AtLeast(floor StatusSeverity) bool { return s.Rank() >= floor.Rank() }

// Compare orders two severities by rank, breaking ties between two distinct
// unrecognized codes by their numeric value so the order stays total (usable
// for sorting).
func (s StatusSeverity) Compare(other StatusSeverity) int {
	if r, o := s.Rank(), other.Rank(); r != o {
		if r < o {
			return -1
		}
		return 1
	}
	switch {
	case s < other:
		return -1
	case s > other:
		return 1
	default:
		return 0
	}
}

func (s StatusSeverity) String() string {
	switch s {
	case SeverityUnspecified:
		return "unspecified"
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown(" + strconv.FormatInt(int64(s), 10) + ")"
	}
}

// CursorRejectReason says why a mid-stream re-anchor was declined (see
// [CursorRejected]).
type CursorRejectReason int32

// Re-anchor reject reasons.
const (
	// CursorRejectUnspecified is proto3's zero value.
	CursorRejectUnspecified CursorRejectReason = 0
	// CursorRejectRateLimited - per-principal re-anchor rate limit exceeded;
	// retry after a backoff.
	CursorRejectRateLimited CursorRejectReason = 1
	// CursorRejectConcurrentReanchor - another re-anchor is already draining
	// (only one runs at a time); retry once it completes.
	CursorRejectConcurrentReanchor CursorRejectReason = 2
	// CursorRejectEmptyCursor - the request carried no cursor (client bug).
	CursorRejectEmptyCursor CursorRejectReason = 3
	// CursorRejectNoSource - the server has no block source to replay from.
	CursorRejectNoSource CursorRejectReason = 4
)

// Known reports whether this build recognizes the reason.
func (r CursorRejectReason) Known() bool {
	return r >= CursorRejectUnspecified && r <= CursorRejectNoSource
}

// Transient reports whether the reject is worth retrying in place (rate limit,
// concurrent re-anchor) rather than escalating to a full resnapshot. This is
// the classification [ResilientWatch] drives its in-place retry off.
func (r CursorRejectReason) Transient() bool {
	return r == CursorRejectRateLimited || r == CursorRejectConcurrentReanchor
}

func (r CursorRejectReason) String() string {
	switch r {
	case CursorRejectUnspecified:
		return "unspecified"
	case CursorRejectRateLimited:
		return "rate_limited"
	case CursorRejectConcurrentReanchor:
		return "concurrent_reanchor"
	case CursorRejectEmptyCursor:
		return "empty_cursor"
	case CursorRejectNoSource:
		return "no_source"
	default:
		return "unknown(" + strconv.FormatInt(int64(r), 10) + ")"
	}
}

// WatchSetRejectReason says why an atomic watch-set replace was declined (see
// [WatchSetRejected]).
type WatchSetRejectReason int32

// Watch-set replace reject reasons.
const (
	// WatchSetRejectUnspecified is proto3's zero value.
	WatchSetRejectUnspecified WatchSetRejectReason = 0
	// WatchSetRejectQuotaExceeded - the target set's total unit cost exceeds the
	// principal's quota (Required units vs the Quota ceiling). Transient: a
	// smaller set fits.
	WatchSetRejectQuotaExceeded WatchSetRejectReason = 1
	// WatchSetRejectMalformed - the server could not parse or expand an element
	// of the snapshot. A full replace is all-or-nothing, so the whole snapshot
	// was refused. A client bug: retrying the same set will not help.
	WatchSetRejectMalformed WatchSetRejectReason = 2
	// WatchSetRejectCapExceeded - the target's watch-set ENTRY count exceeds the
	// per-connection cap (streamwsmaxsubscriptions). Distinct from quota: this
	// bound applies even to a no-auth connection with no quota, and counts
	// entries (a prefix is one) not units. Shed entries and retry.
	WatchSetRejectCapExceeded WatchSetRejectReason = 3
)

// Known reports whether this build recognizes the reason.
func (r WatchSetRejectReason) Known() bool {
	return r >= WatchSetRejectUnspecified && r <= WatchSetRejectCapExceeded
}

func (r WatchSetRejectReason) String() string {
	switch r {
	case WatchSetRejectUnspecified:
		return "unspecified"
	case WatchSetRejectQuotaExceeded:
		return "quota_exceeded"
	case WatchSetRejectMalformed:
		return "malformed"
	case WatchSetRejectCapExceeded:
		return "cap_exceeded"
	default:
		return "unknown(" + strconv.FormatInt(int64(r), 10) + ")"
	}
}

// RescanRejectReason says why a bounded historical rescan was declined (see
// [RescanRejected]).
type RescanRejectReason int32

// Rescan reject reasons.
const (
	// RescanRejectUnspecified is proto3's zero value.
	RescanRejectUnspecified RescanRejectReason = 0
	// RescanRejectRateLimited - per-principal rescan rate limit exceeded; retry
	// after a backoff.
	RescanRejectRateLimited RescanRejectReason = 1
	// RescanRejectConcurrentRescan - another rescan is already draining on this
	// connection; retry once it completes.
	RescanRejectConcurrentRescan RescanRejectReason = 2
	// RescanRejectInvalidRange - ToHeight < FromHeight, or the range lies
	// entirely above the tip.
	RescanRejectInvalidRange RescanRejectReason = 3
	// RescanRejectRangeTooLarge - the (clamped) span exceeds the server cap;
	// page the range into smaller rescans.
	RescanRejectRangeTooLarge RescanRejectReason = 4
	// RescanRejectNoSource - the server has no block-scan source (no local block
	// bodies or undo data).
	RescanRejectNoSource RescanRejectReason = 5
	// RescanRejectEmptyWatchSet - the connection watches nothing, so a rescan
	// could match nothing. Register a watch-set first.
	RescanRejectEmptyWatchSet RescanRejectReason = 6
)

// Known reports whether this build recognizes the reason.
func (r RescanRejectReason) Known() bool {
	return r >= RescanRejectUnspecified && r <= RescanRejectEmptyWatchSet
}

func (r RescanRejectReason) String() string {
	switch r {
	case RescanRejectUnspecified:
		return "unspecified"
	case RescanRejectRateLimited:
		return "rate_limited"
	case RescanRejectConcurrentRescan:
		return "concurrent_rescan"
	case RescanRejectInvalidRange:
		return "invalid_range"
	case RescanRejectRangeTooLarge:
		return "range_too_large"
	case RescanRejectNoSource:
		return "no_source"
	case RescanRejectEmptyWatchSet:
		return "empty_watch_set"
	default:
		return "unknown(" + strconv.FormatInt(int64(r), 10) + ")"
	}
}
