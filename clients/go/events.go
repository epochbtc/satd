package satdevents

import (
	"github.com/epochbtc/satd/clients/go/eventspb"
)

// Event is one typed streaming event - the Go mirror of the wire
// NodeEvent.body tagged union. It is a sealed interface (the marker method is
// unexported), so the set of implementations is exactly the types in this file
// and a type switch is the way to consume it:
//
//	for {
//	    ev, err := stream.Recv()
//	    if err != nil { ... }
//	    switch e := ev.(type) {
//	    case *satdevents.BlockConnected:
//	        log.Printf("block %d %s", e.Height, satdevents.DisplayHex(e.Hash))
//	    case *satdevents.ScriptMatched:
//	        ...
//	    }
//	}
//
// A body this build does not recognize (a newer server arm), or an event with
// no body set, decodes to [*UnknownEvent]. Well-behaved consumers ignore it -
// the wire schema is additive, so a default branch is not an error path.
//
// Hashes and txids are raw bytes in internal (consensus) byte order. See
// [DisplayHex].
type Event interface {
	isEvent()
}

// Cursor is a durable resume position.
//
// Confirmed-side cursors are (Height, TxIndex) - per-transaction, so a client
// can resume mid-block after a disconnect. MempoolSeq is a best-effort
// high-water mark for the mempool side (advisory; it resets on daemon restart).
// InstanceID is the issuing publisher's per-process epoch nonce: on a
// from-cursor resume the server discards MempoolSeq when it differs from the
// live instance, while confirmed replay is instance-independent.
//
// Persist the value from [Stream.Cursor] and present it again as
// [SubscribeOptions.FromCursor] to resume. It is a plain comparable value type,
// so it copies and compares with ==.
type Cursor struct {
	// Height is the block height of the last delivered confirmed item.
	Height uint32
	// TxIndex is the index within that block of the last delivered transaction.
	TxIndex uint32
	// MempoolSeq is the best-effort mempool high-water mark (advisory).
	MempoolSeq uint64
	// InstanceID is the publisher's per-process epoch nonce.
	InstanceID uint64
}

func cursorFromProto(c *eventspb.Cursor) *Cursor {
	if c == nil {
		return nil
	}
	return &Cursor{
		Height:     c.GetHeight(),
		TxIndex:    c.GetTxIndex(),
		MempoolSeq: c.GetMempoolSeq(),
		InstanceID: c.GetInstanceId(),
	}
}

func (c Cursor) toProto() *eventspb.Cursor {
	return &eventspb.Cursor{
		Height:     c.Height,
		TxIndex:    c.TxIndex,
		MempoolSeq: c.MempoolSeq,
		InstanceId: c.InstanceID,
	}
}

// Outpoint is a transaction output reference (txid:vout), raw bytes.
type Outpoint struct {
	// Txid is 32 raw bytes in internal byte order (see [DisplayHex]).
	Txid []byte
	// Vout is the output index.
	Vout uint32
}

// DescriptorMatch is descriptor attribution for a [ScriptMatched]: which
// descriptor watch a matched scripthash belongs to, and the exact coordinate
// the server derived it at.
type DescriptorMatch struct {
	// Descriptor is the descriptor string the watch was registered with.
	Descriptor string
	// Branch is the 0-based BIP-389 multipath branch the matched script came
	// from (<0;1> means external = 0, change = 1; always 0 for a single-path
	// descriptor).
	Branch uint32
	// DerivationIndex is the absolute derivation index of the matched script -
	// ready to use, no gap-limit arithmetic. (Branch, DerivationIndex) is
	// exactly what the server derived, correct for fixed and multipath
	// descriptors alike; the server tracks no derivation progress, so advancing
	// your gap limit remains your concern.
	DerivationIndex uint32
}

// ScriptPrefix is a k-bit prefix of sha256(scriptPubKey).
type ScriptPrefix struct {
	// Prefix is the top ceil(Bits/8) bytes, big-endian.
	Prefix []byte
	// Bits is the prefix length in bits.
	Bits uint32
}

// TaprootOutput is one of a transaction's taproot outputs - a silent-payment
// scan candidate. Carried in [TweakEntry.TaprootOutputs] so a client can
// confirm a derived output key against the actual on-chain output without
// fetching the transaction.
type TaprootOutput struct {
	// Vout is the output index within the transaction.
	Vout uint32
	// OutputPubkey is the 32-byte x-only taproot output key in internal
	// (consensus) byte order - the raw scriptPubKey push, unreversed. Compare it
	// directly against a derived key with no byte flip.
	OutputPubkey []byte
	// Value is the output value in satoshis.
	Value uint64
}

// TweakEntry is one transaction's public silent-payment tweak.
type TweakEntry struct {
	// Tweak is the 33-byte compressed public tweak T = input_hash * A for the
	// transaction. Always present - this is what a client feeds its own b_scan
	// into to scan the transaction's outputs locally.
	Tweak []byte
	// Txid is the transaction's id (internal byte order). Empty when the
	// subscription set TweaksOnly (the compact, tweak-alone form).
	Txid []byte
	// MaxValue is the largest taproot output value in the transaction, in
	// satoshis - a cap on what a payment here could be worth, for client-side
	// dust triage. Zero under TweaksOnly.
	MaxValue uint64
	// TaprootOutputs are the transaction's taproot outputs (the scan
	// candidates). Always populated on a [MempoolTweak] - the whole point of
	// Tier 1.5, since there is no block to fetch to recover them. On a
	// [BlockTweaks] entry it is present only when the subscription set
	// TweakOutputs; empty otherwise (the confirmed block is the fallback).
	TaprootOutputs []TaprootOutput
}

// SpentPrevout is a spent prevout that matched a prefix bucket (the spend side
// of a [PrefixMatched]).
type SpentPrevout struct {
	// Outpoint is the consumed outpoint.
	Outpoint Outpoint
	// ScriptPubkey is the script it paid. Empty when the server did not retain
	// it (a mempool spend below the `full` retention tier) - resolve the
	// outpoint yourself in that case.
	ScriptPubkey []byte
	// Amount is the prevout value in satoshis, or nil when not retained
	// (distinct from a genuine 0-value prevout, which is a non-nil zero).
	Amount *uint64
}

// ---- mempool ---------------------------------------------------------------

// MempoolEnter reports a transaction entering the mempool.
type MempoolEnter struct {
	// Txid is the transaction id.
	Txid []byte
	// Fee is the fee in satoshis.
	Fee uint64
	// Vsize is the virtual size in vbytes.
	Vsize uint64
	// FeeRateSatPerKvB is the fee rate in sat/kvB.
	FeeRateSatPerKvB uint64
	// Time is the admission time, seconds since the Unix epoch.
	Time uint64
}

// MempoolLeaveConfirmed reports a mempool transaction confirmed in a block.
type MempoolLeaveConfirmed struct {
	// Txid is the transaction id.
	Txid []byte
	// BlockHash is the confirming block hash.
	BlockHash []byte
	// Height is the confirming block height.
	Height uint32
}

// MempoolLeaveEvicted reports a mempool transaction evicted by policy.
type MempoolLeaveEvicted struct {
	// Txid is the transaction id.
	Txid []byte
	// Reason is why it was evicted.
	Reason EvictReason
}

// MempoolLeaveReplaced reports a mempool transaction replaced (RBF).
type MempoolLeaveReplaced struct {
	// Txid is the replaced transaction id.
	Txid []byte
	// ReplacingTxid is the incoming transaction that evicted it.
	ReplacingTxid []byte
}

// ---- chain -----------------------------------------------------------------

// BlockConnected reports a block connected to the active chain.
type BlockConnected struct {
	// Hash is the block hash.
	Hash []byte
	// Height is the block height.
	Height uint32
}

// BlockDisconnected reports a block disconnected (a reorg).
type BlockDisconnected struct {
	// Hash is the block hash.
	Hash []byte
	// Height is the block height.
	Height uint32
}

// Reorg is the first-class reorg marker, emitted once before the per-block
// disconnect/connect sequence. In-process ground truth: a ZMQ or header
// sidecar can only infer a reorg.
type Reorg struct {
	// FromHeight is the height of the abandoned tip.
	FromHeight uint32
	// OldTip is the hash of the abandoned tip.
	OldTip []byte
	// ToHeight is the height of the new active tip.
	ToHeight uint32
	// NewTip is the hash of the new active tip.
	NewTip []byte
}

// Heartbeat is a periodic synthetic event for end-to-end latency probes.
type Heartbeat struct {
	// UptimeNs is the publisher's uptime in nanoseconds.
	UptimeNs uint64
}

// Status is a node-health condition the daemon detected about ITSELF - a
// stalled tip, a filling disk, peer starvation. It arrives only for a
// subscription that set [CategoryStatus], which is deliberately not part of the
// 0 ("all") default.
//
// Standing conditions are level-triggered: exactly one [StatusStateRaised] on
// entry and one [StatusStateCleared] on recovery, with hysteresis so a value
// hovering at the threshold does not flap. Observations with no recovered state
// (IBD finishing, a deep reorg landing) are [StatusStateEdge].
//
// # Not replayable, and the gap is not observable
//
// A status event carries no cursor, so a from-cursor resume never yields one;
// the node re-raises standing conditions after a restart instead. A client that
// connects AFTER a condition was raised will not see it until the condition
// changes. This is not something the reconnect layer can paper over:
// [ResilientSubscription] hides reconnects by design, and its one synthetic
// notice ([ReplayGap]) is cursor-anchored, which status has no part in. So a
// drop during which one condition raised and another cleared leaves a client's
// picture silently wrong, with nothing to key recovery off.
//
// Treat this stream as the low-latency edge signal and getwarnings over
// JSON-RPC as the AUTHORITY on what is wrong right now: poll it on a slow timer
// as well as consuming this, and a missed transition self-corrects at the next
// poll instead of persisting for the life of the process. Seeding once on
// connect is not enough, because reconnects after that are invisible to you.
type Status struct {
	// Kind is which condition this describes.
	Kind StatusKind
	// State is whether it was entered, recovered, or is a one-shot observation.
	State StatusState
	// Severity is how loud it is. Filter with [StatusSeverity.AtLeast].
	Severity StatusSeverity
	// Message is a human-readable one-liner. Log it or page on it; do not parse
	// it - machine consumers switch on Kind and read Details.
	Message string
	// Details are kind-specific structured fields, as strings.
	//
	// Mostly decimal numbers (free bytes and the threshold, seconds since the
	// last block, a reorg's depth and fork height) but NOT uniformly - a cleared
	// event can carry a reason token such as detector_disabled or
	// mempool_cap_zero. Parse per key, not with one integer parse over the map.
	//
	// The watched path is deliberately absent: it reaches every status
	// subscriber and every webhook receiver, and an absolute datadir path
	// usually names the account the node runs under.
	//
	// Tolerate unknown keys and absent optional ones.
	Details map[string]string
}

// ---- watch matches ---------------------------------------------------------

// OutpointSpent reports that a watched outpoint was spent.
type OutpointSpent struct {
	// Outpoint is the spent outpoint.
	Outpoint Outpoint
	// SpendingTxid is the spending transaction id.
	SpendingTxid []byte
	// SpendingVin is the spending input index.
	SpendingVin uint32
	// Confirmed is false when seen only in the mempool.
	Confirmed bool
}

// ScriptMatched reports that a watched script was matched by a transaction, on
// either side: funding (an output pays the script) or spending (an input spends
// an output that paid it).
type ScriptMatched struct {
	// Scripthash is the matched sha256(scriptPubKey).
	Scripthash []byte
	// Txid is the matching transaction id.
	Txid []byte
	// IsOutput is true for a funding (output) match, false for spending (input).
	IsOutput bool
	// Index is the vout when IsOutput, else the vin.
	Index uint32
	// Confirmed is false when seen only in the mempool.
	Confirmed bool
	// Amount is the matched value in satoshis: the funded output value when
	// IsOutput, or the spent-prevout value otherwise. Non-nil on the funding
	// side and for confirmed spends; non-nil for mempool spends when the node
	// retained the prevout value (streamprevoutmeta >= amount, the default),
	// else nil (hash tier). Non-nil lets a consumer skip the enrichment
	// getrawtransaction for the common single-coin case.
	Amount *uint64
	// RawTx is the full consensus-serialized matching transaction, present only
	// when this stream opted in via SetWatchOptions with IncludeRawTx; nil
	// otherwise.
	RawTx []byte
	// Descriptors is descriptor attribution: the descriptor watch(es) this
	// scripthash belongs to, if it was registered via AddDescriptor. Empty for a
	// directly-watched script.
	Descriptors []DescriptorMatch
}

// TxidMatched reports that a watched txid appeared in the mempool or a
// connected block.
type TxidMatched struct {
	// Txid is the transaction id.
	Txid []byte
	// Confirmed is false when seen only in the mempool.
	Confirmed bool
	// Height is the block height when confirmed; 0 in the mempool.
	Height uint32
}

// TxidReplaced reports that a watched transaction was replaced in the mempool
// by a conflicting RBF candidate.
type TxidReplaced struct {
	// Txid is the replaced transaction id.
	Txid []byte
	// ReplacingTxid is the incoming transaction that evicted it.
	ReplacingTxid []byte
}

// TxidEvicted reports that a watched transaction left the mempool by policy
// (not confirmation, not RBF).
type TxidEvicted struct {
	// Txid is the transaction id.
	Txid []byte
	// Reason is a free-text token: "full_pool", "expiry", "block_conflict", or
	// "policy".
	Reason string
}

// TxidUnconfirmed reports that a watched transaction's confirming block was
// rolled back by a reorg (it is back in flight).
type TxidUnconfirmed struct {
	// Txid is the transaction id.
	Txid []byte
	// PrevHeight is the height it had been confirmed at, now disconnected.
	PrevHeight uint32
}

// TxidDepthReached reports that a depth alarm fired: the watched transaction
// reached the requested confirmation depth. Single-shot - the alarm self-evicts
// after this.
type TxidDepthReached struct {
	// Txid is the transaction id.
	Txid []byte
	// Depth is the confirmations reached (>= the requested depth).
	Depth uint32
	// Height is the active-chain height where the transaction is confirmed.
	Height uint32
}

// TxidFinalized reports that a lifecycle watch's auto-close depth was reached:
// a terminal notice, and the lifecycle watch has self-evicted (its quota unit
// is released).
type TxidFinalized struct {
	// Txid is the transaction id.
	Txid []byte
	// Depth is the confirmations reached (>= the auto-close depth).
	Depth uint32
	// Height is the active-chain height where the transaction is confirmed.
	Height uint32
}

// PrefixMatched reports a transaction that fell inside a watched script-prefix
// bucket. It carries the FULL serialized transaction so the client filters the
// bucket against its real scripts locally - no precise follow-up fetch that
// would re-leak the exact interest. See [PrefixWatcher.Filter].
type PrefixMatched struct {
	// Prefix is the registered bucket that fired.
	Prefix ScriptPrefix
	// RawTx is the consensus-serialized matching transaction.
	RawTx []byte
	// Confirmed is false for a mempool match, true for a connected block.
	Confirmed bool
	// Height is the block height when confirmed; 0 in the mempool.
	Height uint32
	// MatchedPrevouts is the spend side: the matched prevout(s) for inputs whose
	// prevout script fell in the bucket. Empty for a pure funding match.
	MatchedPrevouts []SpentPrevout
}

// SilentPaymentMatched reports that a BIP 352 silent payment paid a registered
// scan key - the Tier 2 (scan-key watch) match, delivered on the Watch stream
// to a connection that registered the target. The node ran the ECDH; Tweak and
// K let the wallet re-derive the output key - and, with its b_spend, the
// spending key - OFFLINE.
type SilentPaymentMatched struct {
	// ScanPubkey is the registered target's identity b_scan*G (33 bytes) this
	// output paid - it echoes which of your scan keys matched, never the secret.
	ScanPubkey []byte
	// Txid is the paying transaction's id (internal byte order).
	Txid []byte
	// Vout is the matched output's index.
	Vout uint32
	// OutputPubkey is the matched taproot output key (32-byte x-only).
	OutputPubkey []byte
	// Amount is the output value in satoshis.
	Amount uint64
	// Tweak is the transaction's 33-byte public tweak T. With K, re-derive the
	// full output key offline: P_k = B_spend + hash(b_scan*T || k)*G.
	Tweak []byte
	// K is the BIP 352 output counter for this match.
	K uint32
	// Label is the matched label integer when the output paid a registered label
	// (change is commonly label 0); nil for an unlabeled match.
	Label *uint32
	// Confirmed is true once seen in a connected block; false while only in the
	// mempool (re-emitted true on confirmation).
	Confirmed bool
	// Height is the confirming block height; nil while unconfirmed.
	Height *uint32
	// RawTx is the full serialized transaction, only when this connection opted
	// in via SetWatchOptions with IncludeRawTx; nil otherwise.
	RawTx []byte
}

// ---- silent-payment firehose ------------------------------------------------

// BlockTweaks carries one connected block's silent-payment tweaks - the Tier 1
// (client-side scan, zero-custody) firehose payload. It arrives only for a
// subscription that set [CategoryTweaks]. For each entry, a client computes
// T * b_scan with its own scan secret and derives the candidate output key(s),
// so the scan key never leaves the device.
type BlockTweaks struct {
	// BlockHash is the block these tweaks describe (internal byte order).
	BlockHash []byte
	// Height is the block's height.
	Height uint32
	// Entries is one entry per silent-payment-eligible transaction in the block.
	Entries []TweakEntry
	// Filtered is true when a TweakDustLimit or TweaksOnly filter dropped or
	// trimmed entries in this block - so an empty Entries may mean "filtered
	// out", not "none present".
	Filtered bool
}

// MempoolTweak carries one accepted-but-unconfirmed transaction's
// silent-payment tweak - the Tier 1.5 (mempool-time, zero-custody) firehose
// payload. It arrives only for a subscription that set [CategoryTweaks] AND
// [SubscribeOptions.MempoolTweaks]. Scan it exactly like a [BlockTweaks] entry.
//
// Ephemeral and best-effort: not replayable, no retraction on RBF or eviction.
// Dedup by Entry.Txid (always present here) against the confirmed [BlockTweaks].
type MempoolTweak struct {
	// Entry is the admitted transaction's tweak. Always full (Txid present) -
	// TweaksOnly does not apply to mempool tweaks.
	Entry TweakEntry
}

// ---- in-band control results ------------------------------------------------

// Lagged is the in-band slow-consumer lag notice: the server dropped events for
// this subscriber because it could not keep up with the broadcast, and the
// stream then continues live.
//
// Not an error. Reconnect (Subscribe) or re-anchor (Watch) with ResumeCursor to
// durably replay the dropped events. [ResilientSubscription] does this for you
// by default; see [LagPolicy].
type Lagged struct {
	// DroppedCount is the number of events skipped between the last delivered
	// event and this notice.
	DroppedCount uint64
	// ResumeCursor is the position of the last event the server delivered before
	// the gap - the anchor to recover it.
	ResumeCursor *Cursor
}

// ReplayGap is SDK-SYNTHESIZED - not a wire event. [ResilientSubscription]
// emits it when a durable replay was clamped by the server to the most recent
// MAX_REPLAY_BLOCKS (10,000) blocks, so the confirmed history in
// (ResumeHeight, FirstHeight) was skipped.
//
// The live stream continues correctly from FirstHeight; the gap is
// unrecoverable via this stream, so full-resync the skipped range from another
// source (for example the getblock JSON-RPC). Emitted once per resume,
// immediately before the first replayed block.
type ReplayGap struct {
	// ResumeHeight is the height the resume cursor expected next
	// (cursor.Height + 1).
	ResumeHeight uint32
	// FirstHeight is the first height the server actually delivered
	// (> ResumeHeight).
	FirstHeight uint32
}

// CursorAccepted reports that a mid-stream re-anchor was ADMITTED.
// Confirmed-history replay follows this event (in height order) before the live
// tail resumes.
//
// When Clamped is true the requested cursor predated the server's replay
// window: replay still runs, but only from EarliestReplayed, so full-resync
// history below it from another source. This is the deterministic "accepted,
// replaying from X" signal.
type CursorAccepted struct {
	// From is the cursor the server anchored to.
	From *Cursor
	// Clamped is true when the replay window truncated the lower end of the gap.
	Clamped bool
	// EarliestReplayed is the first height the server will replay.
	EarliestReplayed uint32
}

// CursorRejected reports that a mid-stream re-anchor was NOT admitted. The live
// stream is unchanged (still emitting from its prior position). Decide whether
// to retry, back off, or escalate to a full resnapshot based on Reason;
// CurrentHead is where the server is now.
type CursorRejected struct {
	// Reason is why the re-anchor was declined.
	Reason CursorRejectReason
	// CurrentHead is the server's current resume position.
	CurrentHead *Cursor
}

// WatchSetReplaced reports that an atomic watch-set replace was applied. The
// live watch-set now equals the reloaded truth; the counts are the server's
// authoritative diff by EFFECTIVE coverage (an item covered by both the old and
// new set - even via a different mechanism - counts as unchanged, never
// gapped).
type WatchSetReplaced struct {
	// Added is the count of items newly watched.
	Added uint32
	// Removed is the count of items released.
	Removed uint32
	// Unchanged is the count of items in both sets (kept without
	// re-registration).
	Unchanged uint32
}

// WatchSetRejected reports that an atomic watch-set replace was REJECTED; the
// live watch-set is UNCHANGED (the prior set is still in effect).
//
// Reason says which ceiling refused it, and Required/Quota are in the matching
// unit: for [WatchSetRejectQuotaExceeded], Required units against the Quota
// ceiling; for [WatchSetRejectCapExceeded], Required entries against the
// per-connection entry cap; for [WatchSetRejectMalformed] both are 0 and
// retrying the same set will not help.
//
// In every case the client's mirror still reflects the (unapplied) reloaded
// set, so a consumer that ignores this keeps an over-claiming mirror; react by
// reloading a set the server accepts.
type WatchSetRejected struct {
	// Reason is why the replace was refused.
	Reason WatchSetRejectReason
	// Required is what the rejected target needs: units or entries, per Reason;
	// 0 for a malformed snapshot.
	Required uint64
	// Quota is the ceiling that refused it: the unit quota or the entry cap, per
	// Reason; 0 for a malformed snapshot.
	Quota uint64
}

// RescanAccepted reports that a bounded historical rescan was ADMITTED.
// Confirmed watch-matches for the scanned range follow this event (in height
// order), terminated by a [RescanComplete].
//
// FromHeight/ToHeight are the range the server will ACTUALLY scan: Clamped is
// true when the requested bounds were narrowed to what the node holds. A rescan
// is a side query - it does not advance the durable cursor, and its match
// events carry no resume cursor.
type RescanAccepted struct {
	// FromHeight is the first height that will be scanned (post-clamp).
	FromHeight uint32
	// ToHeight is the last height that will be scanned (post-clamp).
	ToHeight uint32
	// Clamped is true when the requested range was narrowed.
	Clamped bool
}

// RescanRejected reports that a bounded historical rescan was NOT admitted; no
// matches follow and the live stream is unchanged. TipHeight is the server's
// current tip so a client can re-scope the range and retry.
type RescanRejected struct {
	// Reason is why the rescan was declined.
	Reason RescanRejectReason
	// TipHeight is the server's current active-chain tip height.
	TipHeight uint32
}

// RescanComplete is the terminal marker for a bounded historical rescan: the
// range has been fully scanned and every match delivered. After this the stream
// resumes its prior live position.
type RescanComplete struct {
	// FromHeight is the scanned range's lower bound (post-clamp), echoing
	// [RescanAccepted].
	FromHeight uint32
	// ToHeight is the scanned range's upper bound (post-clamp).
	ToHeight uint32
	// Matches is the number of match events emitted for this rescan (0 when the
	// range held none).
	Matches uint64
}

// UnknownEvent is a body this client build does not recognize (a newer server
// arm), or an event whose body was not set. Well-behaved consumers ignore it.
type UnknownEvent struct{}

func (*MempoolEnter) isEvent()          {}
func (*MempoolLeaveConfirmed) isEvent() {}
func (*MempoolLeaveEvicted) isEvent()   {}
func (*MempoolLeaveReplaced) isEvent()  {}
func (*BlockConnected) isEvent()        {}
func (*BlockDisconnected) isEvent()     {}
func (*Reorg) isEvent()                 {}
func (*Heartbeat) isEvent()             {}
func (*Status) isEvent()                {}
func (*OutpointSpent) isEvent()         {}
func (*ScriptMatched) isEvent()         {}
func (*TxidMatched) isEvent()           {}
func (*TxidReplaced) isEvent()          {}
func (*TxidEvicted) isEvent()           {}
func (*TxidUnconfirmed) isEvent()       {}
func (*TxidDepthReached) isEvent()      {}
func (*TxidFinalized) isEvent()         {}
func (*PrefixMatched) isEvent()         {}
func (*SilentPaymentMatched) isEvent()  {}
func (*BlockTweaks) isEvent()           {}
func (*MempoolTweak) isEvent()          {}
func (*Lagged) isEvent()                {}
func (*ReplayGap) isEvent()             {}
func (*CursorAccepted) isEvent()        {}
func (*CursorRejected) isEvent()        {}
func (*WatchSetReplaced) isEvent()      {}
func (*WatchSetRejected) isEvent()      {}
func (*RescanAccepted) isEvent()        {}
func (*RescanRejected) isEvent()        {}
func (*RescanComplete) isEvent()        {}
func (*UnknownEvent) isEvent()          {}

// unknownEvent is the shared instance the decoder returns; UnknownEvent carries
// no data, so there is nothing to allocate per occurrence.
var unknownEvent = &UnknownEvent{}

// decodeEvent maps a wire NodeEvent onto the typed [Event] model.
//
// Every oneof arm of NodeEvent.body must be covered; the exhaustiveness test in
// events_exhaustive_test.go walks the descriptor and fails if one is not, so a
// proto addition that lands without Go support fails that PR rather than a
// later release.
func decodeEvent(ev *eventspb.NodeEvent) Event {
	switch body := ev.GetBody().(type) {
	case *eventspb.NodeEvent_Mempool:
		return decodeMempool(body.Mempool)
	case *eventspb.NodeEvent_Chain:
		return decodeChain(body.Chain)
	case *eventspb.NodeEvent_Heartbeat:
		return &Heartbeat{UptimeNs: body.Heartbeat.GetUptimeNs()}
	case *eventspb.NodeEvent_Status:
		s := body.Status
		details := s.GetDetails()
		if details == nil {
			details = map[string]string{}
		}
		return &Status{
			Kind:     StatusKind(s.GetKind()),
			State:    StatusState(s.GetState()),
			Severity: StatusSeverity(s.GetSeverity()),
			Message:  s.GetMessage(),
			Details:  details,
		}
	case *eventspb.NodeEvent_OutpointSpent:
		o := body.OutpointSpent
		return &OutpointSpent{
			Outpoint:     Outpoint{Txid: o.GetOutpointTxid(), Vout: o.GetOutpointVout()},
			SpendingTxid: o.GetSpendingTxid(),
			SpendingVin:  o.GetSpendingVin(),
			Confirmed:    o.GetConfirmed(),
		}
	case *eventspb.NodeEvent_ScriptMatched:
		s := body.ScriptMatched
		out := &ScriptMatched{
			Scripthash: s.GetScripthash(),
			Txid:       s.GetTxid(),
			IsOutput:   s.GetIsOutput(),
			Index:      s.GetIndex(),
			Confirmed:  s.GetConfirmed(),
			Amount:     optUint64(s.GetHasAmount(), s.GetAmount()),
			RawTx:      nonEmpty(s.GetRawTx()),
		}
		for _, d := range s.GetDescriptorMatches() {
			out.Descriptors = append(out.Descriptors, DescriptorMatch{
				Descriptor:      d.GetDescriptor_(),
				Branch:          d.GetBranch(),
				DerivationIndex: d.GetDerivationIndex(),
			})
		}
		return out
	case *eventspb.NodeEvent_TxidMatched:
		t := body.TxidMatched
		return &TxidMatched{Txid: t.GetTxid(), Confirmed: t.GetConfirmed(), Height: t.GetHeight()}
	case *eventspb.NodeEvent_TxidReplaced:
		t := body.TxidReplaced
		return &TxidReplaced{Txid: t.GetTxid(), ReplacingTxid: t.GetReplacingTxid()}
	case *eventspb.NodeEvent_TxidEvicted:
		t := body.TxidEvicted
		return &TxidEvicted{Txid: t.GetTxid(), Reason: t.GetReason()}
	case *eventspb.NodeEvent_TxidUnconfirmed:
		t := body.TxidUnconfirmed
		return &TxidUnconfirmed{Txid: t.GetTxid(), PrevHeight: t.GetPrevHeight()}
	case *eventspb.NodeEvent_TxidDepthReached:
		t := body.TxidDepthReached
		return &TxidDepthReached{Txid: t.GetTxid(), Depth: t.GetDepth(), Height: t.GetHeight()}
	case *eventspb.NodeEvent_TxidFinalized:
		t := body.TxidFinalized
		return &TxidFinalized{Txid: t.GetTxid(), Depth: t.GetDepth(), Height: t.GetHeight()}
	case *eventspb.NodeEvent_PrefixMatched:
		p := body.PrefixMatched
		// A PrefixMatched without its bucket is a degenerate message the local
		// re-filter cannot use (bits 0 matches nothing meaningfully); surface it
		// as unknown rather than a structurally-valid-looking zero.
		if p.GetPrefix() == nil {
			return unknownEvent
		}
		out := &PrefixMatched{
			Prefix:    ScriptPrefix{Prefix: p.GetPrefix().GetPrefix(), Bits: p.GetPrefix().GetBits()},
			RawTx:     p.GetRawTx(),
			Confirmed: p.GetConfirmed(),
			Height:    p.GetHeight(),
		}
		for _, sp := range p.GetMatchedPrevouts() {
			out.MatchedPrevouts = append(out.MatchedPrevouts, SpentPrevout{
				Outpoint:     Outpoint{Txid: sp.GetOutpointTxid(), Vout: sp.GetOutpointVout()},
				ScriptPubkey: sp.GetScriptPubkey(),
				Amount:       optUint64(sp.GetHasAmount(), sp.GetAmount()),
			})
		}
		return out
	case *eventspb.NodeEvent_SilentPaymentMatched:
		s := body.SilentPaymentMatched
		out := &SilentPaymentMatched{
			ScanPubkey:   s.GetScanPubkey(),
			Txid:         s.GetTxid(),
			Vout:         s.GetVout(),
			OutputPubkey: s.GetOutputPubkey(),
			Amount:       s.GetAmount(),
			Tweak:        s.GetTweak(),
			K:            s.GetK(),
			Confirmed:    s.GetConfirmed(),
			RawTx:        nonEmpty(s.GetRawTx()),
		}
		if s.GetHasLabel() {
			l := s.GetLabel()
			out.Label = &l
		}
		// Height is 0 on the wire while unconfirmed; surface that as absent.
		if s.GetConfirmed() {
			h := s.GetHeight()
			out.Height = &h
		}
		return out
	case *eventspb.NodeEvent_BlockTweaks:
		b := body.BlockTweaks
		out := &BlockTweaks{
			BlockHash: b.GetBlockHash(),
			Height:    b.GetHeight(),
			Filtered:  b.GetFiltered(),
		}
		for _, e := range b.GetEntries() {
			out.Entries = append(out.Entries, tweakEntryFromProto(e))
		}
		return out
	case *eventspb.NodeEvent_MempoolTweak:
		// A well-formed MempoolTweak always carries its entry; an absent one
		// (malformed wire) degrades to an empty entry rather than dropping the
		// event.
		return &MempoolTweak{Entry: tweakEntryFromProto(body.MempoolTweak.GetEntry())}
	case *eventspb.NodeEvent_Lagged:
		l := body.Lagged
		return &Lagged{
			DroppedCount: l.GetDroppedCount(),
			ResumeCursor: cursorFromProto(l.GetResumeCursor()),
		}
	case *eventspb.NodeEvent_SetCursorResult:
		switch outcome := body.SetCursorResult.GetOutcome().(type) {
		case *eventspb.SetCursorResult_Accepted:
			a := outcome.Accepted
			return &CursorAccepted{
				From:             cursorFromProto(a.GetFrom()),
				Clamped:          a.GetClamped(),
				EarliestReplayed: a.GetEarliestReplayed(),
			}
		case *eventspb.SetCursorResult_Rejected:
			r := outcome.Rejected
			return &CursorRejected{
				Reason:      CursorRejectReason(r.GetReason()),
				CurrentHead: cursorFromProto(r.GetCurrentHead()),
			}
		default:
			// A result frame with no outcome set is a degenerate message.
			return unknownEvent
		}
	case *eventspb.NodeEvent_SetWatchSetResult:
		switch outcome := body.SetWatchSetResult.GetOutcome().(type) {
		case *eventspb.WatchSetResult_Accepted:
			a := outcome.Accepted
			return &WatchSetReplaced{
				Added:     a.GetAdded(),
				Removed:   a.GetRemoved(),
				Unchanged: a.GetUnchanged(),
			}
		case *eventspb.WatchSetResult_Rejected:
			r := outcome.Rejected
			return &WatchSetRejected{
				Reason:   WatchSetRejectReason(r.GetReason()),
				Required: r.GetRequired(),
				Quota:    r.GetQuota(),
			}
		default:
			return unknownEvent
		}
	case *eventspb.NodeEvent_RescanResult:
		switch outcome := body.RescanResult.GetOutcome().(type) {
		case *eventspb.RescanResult_Accepted:
			a := outcome.Accepted
			return &RescanAccepted{
				FromHeight: a.GetFromHeight(),
				ToHeight:   a.GetToHeight(),
				Clamped:    a.GetClamped(),
			}
		case *eventspb.RescanResult_Rejected:
			r := outcome.Rejected
			return &RescanRejected{
				Reason:    RescanRejectReason(r.GetReason()),
				TipHeight: r.GetTipHeight(),
			}
		default:
			return unknownEvent
		}
	case *eventspb.NodeEvent_RescanComplete:
		c := body.RescanComplete
		return &RescanComplete{
			FromHeight: c.GetFromHeight(),
			ToHeight:   c.GetToHeight(),
			Matches:    c.GetMatches(),
		}
	default:
		// Forward-compatible catch-all: a body a newer proto adds, or no body.
		return unknownEvent
	}
}

func decodeMempool(m *eventspb.MempoolEvent) Event {
	switch body := m.GetBody().(type) {
	case *eventspb.MempoolEvent_Enter:
		e := body.Enter
		return &MempoolEnter{
			Txid:             e.GetTxid(),
			Fee:              e.GetFee(),
			Vsize:            e.GetVsize(),
			FeeRateSatPerKvB: e.GetFeeRateSatPerKvb(),
			Time:             e.GetTime(),
		}
	case *eventspb.MempoolEvent_LeaveConfirmed:
		e := body.LeaveConfirmed
		return &MempoolLeaveConfirmed{
			Txid:      e.GetTxid(),
			BlockHash: e.GetBlockHash(),
			Height:    e.GetHeight(),
		}
	case *eventspb.MempoolEvent_LeaveEvicted:
		e := body.LeaveEvicted
		// Decode from the raw enum value, not a helper that would collapse an
		// unrecognized code into the zero variant: "the producer set no reason"
		// and "a newer node set a reason I don't know" are different facts.
		return &MempoolLeaveEvicted{Txid: e.GetTxid(), Reason: EvictReason(e.GetReason())}
	case *eventspb.MempoolEvent_LeaveReplaced:
		e := body.LeaveReplaced
		return &MempoolLeaveReplaced{Txid: e.GetTxid(), ReplacingTxid: e.GetReplacingTxid()}
	default:
		return unknownEvent
	}
}

func decodeChain(c *eventspb.ChainEvent) Event {
	switch body := c.GetBody().(type) {
	case *eventspb.ChainEvent_BlockConnected:
		b := body.BlockConnected
		return &BlockConnected{Hash: b.GetHash(), Height: b.GetHeight()}
	case *eventspb.ChainEvent_BlockDisconnected:
		b := body.BlockDisconnected
		return &BlockDisconnected{Hash: b.GetHash(), Height: b.GetHeight()}
	case *eventspb.ChainEvent_Reorg:
		r := body.Reorg
		return &Reorg{
			FromHeight: r.GetFromHeight(),
			OldTip:     r.GetOldTip(),
			ToHeight:   r.GetToHeight(),
			NewTip:     r.GetNewTip(),
		}
	default:
		return unknownEvent
	}
}

func tweakEntryFromProto(e *eventspb.TweakEntry) TweakEntry {
	out := TweakEntry{
		Tweak:    e.GetTweak(),
		Txid:     e.GetTxid(),
		MaxValue: e.GetMaxValue(),
	}
	for _, t := range e.GetTaprootOutputs() {
		out.TaprootOutputs = append(out.TaprootOutputs, TaprootOutput{
			Vout:         t.GetVout(),
			OutputPubkey: t.GetOutputPubkey(),
			Value:        t.GetValue(),
		})
	}
	return out
}

// optUint64 turns the wire's (has_x, x) pair into an optional: nil when the
// producer did not retain the value, a non-nil zero for a genuine zero.
func optUint64(has bool, v uint64) *uint64 {
	if !has {
		return nil
	}
	return &v
}

// nonEmpty maps an empty wire bytes field to nil, so "absent" and "present but
// empty" do not both read as a zero-length slice at the call site.
func nonEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
