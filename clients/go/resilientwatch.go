package satdevents

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

// WatchSetLoader rebuilds the canonical watch-set from an integrator's durable
// source-of-truth.
//
// It is handed a fresh, empty [WatchSet] to declare into - typically by querying
// a database, a config file, or an upstream service, with its own I/O between
// calls - and returns once the set is complete. Only the Add*/Set* methods make
// sense here: the set starts empty, so a removal has nothing to act on.
//
// See [ResilientWatchConfig.WatchSetLoader] for when it runs and what a failure
// means.
type WatchSetLoader func(ctx context.Context, set *WatchSet) error

// ResilientWatchConfig configures [Client.ResilientWatch]. The zero value is
// valid: default backoff, no persistence, no loader.
type ResilientWatchConfig struct {
	// Backoff is the reconnect (and re-anchor-retry) schedule. The zero value
	// uses [DefaultBackoff].
	Backoff Backoff
	// CursorStore persists the resume cursor across reconnects and restarts. nil
	// means [NoopCursorStore].
	CursorStore CursorStore
	// FromCursor seeds the first connect's resume anchor, used only when the
	// store holds nothing.
	FromCursor *Cursor
	// WatchSetLoader, when set, is the canonical source of the watch-set.
	//
	// Without a loader, [ResilientWatch] re-registers its in-memory mirror of the
	// Add*/Remove* calls made through it. That is correct when the watch-set is
	// built once at startup and never drifts, but the mirror is empty after a
	// process restart and goes stale if the truth changes while the stream is
	// down. With a loader, the mirror becomes a CACHE of the external truth:
	//
	//   - The loader runs once after every successful (re)connect, BEFORE any
	//     event is pumped, so the first events after a reconnect already land on
	//     a fully populated subscription.
	//   - On return, the loaded set REPLACES the mirror. In-process Add*/Remove*
	//     calls still mutate the mirror and go out live, but the next reconnect
	//     re-derives the set from the loader - so the integrator's truth, not the
	//     accumulated in-process edits, is the record across reconnects.
	//   - A loader error is treated as TRANSIENT: it is backed off and retried on
	//     the next connect rather than surfaced. A momentary failure of the
	//     integrator's truth must not kill a consumer whose contract is
	//     at-least-once. A permanently failing loader is indistinguishable from a
	//     transient one and so retries forever; set [Backoff.MaxRetries] if you
	//     need it to surface a terminal error instead.
	//
	// The resume cursor is independent of the watch-set: it still comes from
	// CursorStore / FromCursor, and the re-anchor runs after the loaded set is
	// registered.
	WatchSetLoader WatchSetLoader
}

func (c ResilientWatchConfig) store() CursorStore {
	if c.CursorStore == nil {
		return NoopCursorStore{}
	}
	return c.CursorStore
}

func (c ResilientWatchConfig) backoff() Backoff {
	if c.Backoff.Initial == 0 && c.Backoff.Max == 0 && c.Backoff.Multiplier == 0 {
		b := DefaultBackoff()
		b.MaxRetries = c.Backoff.MaxRetries
		return b
	}
	return c.Backoff
}

// ReloadSummary is what an explicit [ResilientWatch.Reload] changed.
//
// The counts are advisory: the server's [WatchSetReplaced] carries the
// authoritative numbers by effective coverage (a scripthash already covered by a
// descriptor, say, is not charged twice). These are computed client-side from
// the mirror so a caller can see the shape of a reload without waiting for the
// ack, and because Unchanged is not derivable from the ack at all.
type ReloadSummary struct {
	// Added counts items new or changed - a changed floor, a slid descriptor
	// window, a different auto-close depth, refreshed labels.
	Added int
	// Removed counts items present before and absent from the reloaded set.
	Removed int
	// Unchanged counts items present and identical in both.
	Unchanged int
	// Applied reports whether the reloaded set went out on the live stream now.
	// When false the stream was down (or died mid-reload) and the mirror still
	// holds the reloaded set, so the pending reconnect registers it from the
	// same loader - nothing is lost, it just lands later.
	Applied bool
}

// ErrNoLoader is returned by [ResilientWatch.Reload] when no
// [ResilientWatchConfig.WatchSetLoader] was configured - there is nothing to
// reload from.
var ErrNoLoader = errors.New("satdevents: reload requires a WatchSetLoader")

// ResilientWatch is a [Client.Watch] stream that reconnects, re-registers its
// watch-set, and re-anchors its cursor on the consumer's behalf.
//
// Construct it with [Client.ResilientWatch]. Register interest with the Add*/
// Remove* methods - each mutates a client-side mirror of the registered set AND
// goes out on the live stream - and drive it by calling
// [ResilientWatch.Next] in a loop. Close it when done.
//
// # What survives a reconnect
//
// The mirror is replayed onto every fresh stream before events flow: scripts,
// outpoints, lifecycles, depth alarms, descriptors, prefixes, silent-payment
// targets, the category filter, and the raw-tx opt-in. Silent-payment scan keys
// are re-disclosed on each connect and never persisted server-side, which is the
// custody model the design calls for. One-shot watches the server auto-evicts
// when they fire (a depth alarm that reached its depth, a finalized lifecycle)
// are pruned from the mirror as those events arrive, so a reconnect does not
// re-register a completed watch and burn quota on it.
//
// # What a reconnect does NOT backfill
//
// A reconnect re-anchors the cursor, so the CHAIN event stream (blocks
// connected and disconnected) is continuous across the gap. Watch MATCHES are
// not: the node's cursor replay synthesizes events from its block index and
// deliberately does not re-run the watch matcher over the replayed range, which
// would need full block bodies and undo data. A payment to a watched script that
// confirms while the stream is down therefore produces no [ScriptMatched] when
// the stream comes back.
//
// Reproducing confirmed matches over a range is what [ResilientWatch.Rescan] is
// for. A consumer that must not miss a match across an outage should note the
// height it was last caught up to - [ResilientWatch.ResumeCursor] gives it - and
// issue a Rescan over the gap after reconnecting. This is the same behavior the
// Rust SDK has; it is spelled out here because nothing about the reconnect
// suggests it.
//
// # Cancel safety
//
// As with [ResilientSubscription], the reconnect state machine runs on its own
// goroutine and hands events over an unbuffered channel, so Next is cancel-safe
// by construction: cancelling it cannot consume an event. The transient-reject
// retry lives entirely on that goroutine, so there is no charged-but-unsent
// retry for a cancelled caller to strand - the Rust SDK needs an explicit
// state machine for this only because its next() is a cancellable future.
type ResilientWatch struct {
	client *Client
	config ResilientWatchConfig

	events chan delivery
	cancel context.CancelFunc
	done   chan struct{}

	// replayMu orders a caller edit against a reconnect's watch-set replay.
	//
	// Without it, an edit landing between the replay's snapshot and the handle
	// install saw handle == nil, took the "the mirror carries it onto the next
	// stream" path, and was carried onto a stream whose snapshot had ALREADY
	// been taken - so it reached the server on no stream at all. Ordering the
	// two makes an edit either wholly before the snapshot (and thus in it) or
	// wholly after the install (and thus sent live).
	//
	// Always taken BEFORE mu. Next and Commit deliberately do not take it, so a
	// slow replay cannot stall event delivery or cancellation.
	replayMu sync.Mutex

	// mu guards the mirror, the live handle, and the cursor bookkeeping. Caller
	// methods hold it across the wire send that accompanies a mirror mutation, so
	// the mirror and the stream can never disagree about the order edits were
	// applied in.
	mu     sync.Mutex
	mirror *WatchSet
	handle *WatchHandle
	// resume is the confirmed high-water: the anchor a (re)connect re-anchors to.
	resume *Cursor
	// desired is the cursor most recently requested via SetCursor or a
	// connect-time re-anchor, re-sent if a transient reject asks us to retry.
	desired *Cursor
	// commitNext / commitNextGen / committed / pending mirror the commit-on-poll
	// bookkeeping in ResilientSubscription; see Next there.
	commitNext    *Cursor
	commitNextGen uint64
	gen           uint64
	committed     *Cursor
	pending       *delivery
	seeded        bool
	// reanchorAttempts counts consecutive transient re-anchor rejections, driving
	// the in-place retry backoff.
	reanchorAttempts uint32
	// reloadRollback is the mirror as it stood before an in-flight Reload's
	// SetWatchSet, restored if the node rejects it. Nil when none is in flight.
	reloadRollback *WatchSet
	// reanchorPending is true from the moment a SetCursor goes out until the node
	// answers it. While it is set, arriving events must NOT advance resume: the
	// node subscribes the live bus when the stream opens and applies the inbound
	// SetCursor asynchronously, so live tip events legitimately arrive first.
	// Letting one of those move the high-water pushed resume PAST the range the
	// re-anchor was about to replay, and a drop in that window then skipped the
	// range for good, with no ReplayGap to show for it.
	reanchorPending bool

	closeOnce sync.Once
}

// ResilientWatch opens a reconnect-and-replay-aware watch stream.
//
// ctx governs the whole subscription: cancelling it (or calling Close) stops the
// reconnect loop and releases the stream.
func (c *Client) ResilientWatch(ctx context.Context, config ResilientWatchConfig) *ResilientWatch {
	pumpCtx, cancel := context.WithCancel(ctx)
	w := &ResilientWatch{
		client: c,
		config: config,
		mirror: NewWatchSet(),
		events: make(chan delivery),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go w.pump(pumpCtx)
	return w
}

// Next yields the next event, reconnecting, re-registering the watch-set, and
// re-anchoring underneath as needed.
//
// It returns an error only when reconnect retries are exhausted (see
// [Backoff.MaxRetries]), on a non-retryable failure, when ctx is done, or when
// the watch is closed - which surfaces as [io.EOF]. The deterministic in-band
// results ([CursorAccepted], a terminal [CursorRejected], [WatchSetReplaced],
// [WatchSetRejected]) are handed to the caller; only a transient re-anchor
// reject is absorbed and retried internally.
func (w *ResilientWatch) Next(ctx context.Context) (Event, error) {
	w.mu.Lock()
	item := w.pending
	w.pending = nil
	w.mu.Unlock()

	if item == nil {
		select {
		case v, ok := <-w.events:
			if !ok {
				return nil, io.EOF
			}
			item = &v
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Commit-on-poll: arriving here acks the previous event. See
	// [ResilientSubscription.Next] for why the flush and the arm both live on
	// this side of the handoff.
	if err := w.commitDue(ctx); err != nil {
		w.mu.Lock()
		w.pending = item
		w.mu.Unlock()
		return nil, err
	}
	w.mu.Lock()
	w.commitNext, w.commitNextGen = copyCursor(item.cursor), item.gen
	w.mu.Unlock()
	return item.ev, item.err
}

// ResumeCursor is the cursor the next reconnect would re-anchor to.
func (w *ResilientWatch) ResumeCursor() *Cursor {
	w.mu.Lock()
	defer w.mu.Unlock()
	return copyCursor(w.resume)
}

// Commit persists the most-recently-delivered event's cursor now rather than
// waiting for the implicit ack on the next [ResilientWatch.Next]. Call it before
// a clean shutdown. Idempotent.
func (w *ResilientWatch) Commit(ctx context.Context) error { return w.commitDue(ctx) }

// Close stops the reconnect loop and releases the stream. Next returns [io.EOF]
// afterwards. Safe to call more than once.
func (w *ResilientWatch) Close() error {
	w.closeOnce.Do(func() {
		w.cancel()
		<-w.done
	})
	return nil
}

// WatchSetLen is how many items the mirror currently holds - what a reconnect
// would re-register. Useful for a quota gauge or a log line.
func (w *ResilientWatch) WatchSetLen() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.mirror.Len()
}

// --- registering interest ----------------------------------------------------
//
// Each method mutates the mirror and, when connected, sends the matching control
// message. A send failure that means "the stream is gone" is NOT surfaced: the
// edit is safe in the mirror and replays on the reconnect, which is the whole
// point of the wrapper. Any other error is returned.

// AddScripts watches scripthashes (each sha256(scriptPubKey)), optionally with a
// per-script minimum-value floor.
func (w *ResilientWatch) AddScripts(ctx context.Context, items ...ScriptWatch) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.AddScripts(ctx, items) },
		func(m *WatchSet) { m.AddScripts(items...) })
}

// RemoveScripts stops watching scripthashes.
func (w *ResilientWatch) RemoveScripts(ctx context.Context, hashes ...[32]byte) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.RemoveScripts(ctx, hashes) },
		func(m *WatchSet) { m.removeScripts(hashes...) })
}

// AddOutpoints watches specific outpoints for their spend.
func (w *ResilientWatch) AddOutpoints(ctx context.Context, outpoints ...OutpointRef) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.AddOutpoints(ctx, outpoints) },
		func(m *WatchSet) { m.AddOutpoints(outpoints...) })
}

// RemoveOutpoints stops watching outpoints.
func (w *ResilientWatch) RemoveOutpoints(ctx context.Context, outpoints ...OutpointRef) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.RemoveOutpoints(ctx, outpoints) },
		func(m *WatchSet) { m.removeOutpoints(outpoints...) })
}

// AddTxLifecycle follows txids through mempool acceptance, replacement,
// eviction, confirmation, and finality.
func (w *ResilientWatch) AddTxLifecycle(ctx context.Context, autoClose AutoClose, txids ...[32]byte) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.AddTxLifecycle(ctx, txids, autoClose) },
		func(m *WatchSet) { m.AddTxLifecycle(autoClose, txids...) })
}

// RemoveTxLifecycle stops following txids.
func (w *ResilientWatch) RemoveTxLifecycle(ctx context.Context, txids ...[32]byte) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.RemoveTxLifecycle(ctx, txids) },
		func(m *WatchSet) { m.removeTxLifecycle(txids...) })
}

// AddDepthAlarms arms single-shot alarms over the cross product of txids and
// depths. Depths below 1 are dropped.
func (w *ResilientWatch) AddDepthAlarms(ctx context.Context, txids [][32]byte, depths []uint32) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.AddDepthAlarms(ctx, txids, depths) },
		func(m *WatchSet) { m.AddDepthAlarms(txids, depths) })
}

// RemoveDepthAlarms disarms alarms over the cross product of txids and depths.
func (w *ResilientWatch) RemoveDepthAlarms(ctx context.Context, txids [][32]byte, depths []uint32) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.RemoveDepthAlarms(ctx, txids, depths) },
		func(m *WatchSet) { m.removeDepthAlarms(txids, validDepths(depths)) })
}

// AddDescriptor watches a public output descriptor over a (gapLimit, start)
// window. Re-asserting the same descriptor slides the window.
func (w *ResilientWatch) AddDescriptor(ctx context.Context, descriptor string, gapLimit, start uint32) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.AddDescriptor(ctx, descriptor, gapLimit, start) },
		func(m *WatchSet) { m.AddDescriptor(descriptor, gapLimit, start) })
}

// RemoveDescriptor stops watching a descriptor.
func (w *ResilientWatch) RemoveDescriptor(ctx context.Context, descriptor string) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.RemoveDescriptor(ctx, descriptor) },
		func(m *WatchSet) { m.removeDescriptor(descriptor) })
}

// AddScriptPrefixes watches script-prefix buckets. Each is validated
// client-side, so an invalid (prefix, bits) is rejected before it touches the
// mirror or the wire.
func (w *ResilientWatch) AddScriptPrefixes(ctx context.Context, prefixes ...ScriptPrefix) error {
	if _, err := validatePrefixes(prefixes); err != nil {
		return err
	}
	return w.edit(ctx, func(h *WatchHandle) error { return h.AddScriptPrefixes(ctx, prefixes) },
		func(m *WatchSet) { m.AddScriptPrefixes(prefixes...) })
}

// RemoveScriptPrefixes stops watching prefix buckets.
func (w *ResilientWatch) RemoveScriptPrefixes(ctx context.Context, prefixes ...ScriptPrefix) error {
	if _, err := validatePrefixes(prefixes); err != nil {
		return err
	}
	return w.edit(ctx, func(h *WatchHandle) error { return h.RemoveScriptPrefixes(ctx, prefixes) },
		func(m *WatchSet) { m.removeScriptPrefixes(prefixes...) })
}

// AddSilentPayments installs BIP 352 scan-key targets.
//
// Each target is validated and keyed by its identity b_scan*G, so a re-register
// of the same scan key refreshes its labels rather than duplicating it. The scan
// secret is re-disclosed on every reconnect and never persisted by the node.
func (w *ResilientWatch) AddSilentPayments(ctx context.Context, targets ...SilentPaymentTarget) error {
	// Validate (and derive the identity key) before anything is mutated or sent,
	// so a malformed target is a clean client-side error rather than a silent
	// server-side skip.
	//
	// The cap is checked against the LIVE mirror, not against this batch. It
	// used to be staged in a fresh set, so sixteen calls of one target each all
	// passed, the mirror's own error was discarded, and the over-cap set only
	// failed on the next reconnect - where the server sheds the whole message
	// and every silent-payment watch silently disappears.
	return w.editErr(ctx, func(h *WatchHandle) error { return h.AddSilentPayments(ctx, targets) },
		func(m *WatchSet) error { return m.AddSilentPayments(targets...) })
}

// RemoveSilentPayments removes scan-key targets by their identity b_scan*G.
func (w *ResilientWatch) RemoveSilentPayments(ctx context.Context, scanPubkeys ...[33]byte) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.RemoveSilentPayments(ctx, scanPubkeys) },
		func(m *WatchSet) { m.removeSilentPayments(scanPubkeys...) })
}

// SetCategories sets the live category filter. It is replayed first on every
// reconnect, so it is in effect before any match flows.
func (w *ResilientWatch) SetCategories(ctx context.Context, categories uint32) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.SetCategories(ctx, categories) },
		func(m *WatchSet) { m.SetCategories(categories) })
}

// SetWatchOptions toggles the raw-transaction opt-in on matches. It is replayed
// on reconnect, so the opt-in survives a stream tear-down.
func (w *ResilientWatch) SetWatchOptions(ctx context.Context, includeRawTx bool) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.SetWatchOptions(ctx, includeRawTx) },
		func(m *WatchSet) { m.SetWatchOptions(includeRawTx) })
}

// SetCursor re-anchors the stream, asking the node to replay from cursor.
//
// The result arrives in-band as a [CursorAccepted] (watch its Clamped field) or
// a [CursorRejected]. A transient rejection - rate limited, or a concurrent
// re-anchor - is retried internally with backoff and never reaches the caller;
// a terminal one does.
//
// Unlike a watch-set edit, a re-anchor requested while the stream is down is NOT
// deferred to the reconnect: the reconnect re-anchors from the confirmed
// high-water instead, which cannot skip anything but also will not honour a
// request to go further back. Re-issue it after the stream is up if you need an
// earlier anchor. (The Rust SDK behaves identically.)
func (w *ResilientWatch) SetCursor(ctx context.Context, cursor Cursor) error {
	c := cursor
	return w.edit(ctx, func(h *WatchHandle) error { return h.SetCursor(ctx, c) },
		func(*WatchSet) {
			w.desired = &c
			// Hold the high-water still until the node answers, so an event
			// racing the ack cannot move it past the requested anchor.
			w.reanchorPending = true
			// A fresh explicit re-anchor supersedes any in-flight transient-reject
			// retry, so it starts the retry budget over rather than inheriting the
			// previous anchor's exhausted one.
			w.reanchorAttempts = 0
		})
}

// Rescan asks the node to replay a bounded historical range against the current
// watch-set. The result arrives in-band as [RescanAccepted] / [RescanRejected]
// and a terminating [RescanComplete].
//
// A rescan touches no resilient state - it is a side query, orthogonal to the
// watch-set mirror and the resume cursor - so it is neither replayed on
// reconnect nor retried. If the stream drops mid-rescan, re-issue it. With the
// stream down this is a no-op.
func (w *ResilientWatch) Rescan(ctx context.Context, fromHeight, toHeight uint32) error {
	return w.edit(ctx, func(h *WatchHandle) error { return h.Rescan(ctx, fromHeight, toHeight) },
		func(*WatchSet) {})
}

// Reload rebuilds the watch-set from the configured [WatchSetLoader] and applies
// it as a single atomic replacement.
//
// The whole desired membership goes out as one SetWatchSet, which the node
// reconciles under its own lock - there is no client-computed sequence of
// Add*/Remove* messages whose ordering could strand coverage or double-charge a
// quota mid-swap. The deterministic result arrives in-band on
// [ResilientWatch.Next] as [WatchSetReplaced] or [WatchSetRejected].
//
// If the stream is down, the reloaded set still becomes the mirror and is
// registered by the pending reconnect; the returned summary reports
// Applied=false. A loader error is surfaced here rather than retried, because an
// explicit reload is the caller's call to make.
func (w *ResilientWatch) Reload(ctx context.Context) (ReloadSummary, error) {
	loader := w.config.WatchSetLoader
	if loader == nil {
		return ReloadSummary{}, ErrNoLoader
	}
	loaded := NewWatchSet()
	if err := loader(ctx, loaded); err != nil {
		return ReloadSummary{}, wrapError(KindWatchSetLoader, err, "watch-set loader: %s", err)
	}
	snapshot, err := loaded.toProto()
	if err != nil {
		return ReloadSummary{}, err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	counts := w.mirror.reconcileTo(loaded)
	// The raw-tx opt-in is NOT part of SetWatchSet, so reconcile it separately -
	// and in both directions. On the reconnect path a fresh stream starts with it
	// off and controlMessages re-asserts it, but here the stream is live: if the
	// reloaded truth drops an opt-in the stream still has, it has to be turned
	// off explicitly or the node keeps serializing full transactions until some
	// incidental reconnect.
	oldRawTx := w.mirror.includeRawTx != nil && *w.mirror.includeRawTx
	newRawTx := loaded.includeRawTx != nil && *loaded.includeRawTx

	applied := false
	if h := w.handle; h != nil {
		err := h.SendControl(ctx, &eventspb.SubscribeControl{
			Msg: &eventspb.SubscribeControl_SetWatchSet{SetWatchSet: snapshot},
		})
		if err == nil && oldRawTx != newRawTx {
			err = h.SetWatchOptions(ctx, newRawTx)
		}
		switch {
		case err == nil:
			applied = true
		case errors.Is(err, ErrControlClosed):
			w.teardownLocked()
		default:
			// The SetWatchSet itself may already have landed - only the
			// follow-up options toggle failed. Adopt the mirror before
			// returning, or the server holds the new set while the mirror holds
			// the old one and the next reconnect replays the stale set, undoing
			// the reload with no error anywhere.
			w.mirror = loaded.clone()
			return ReloadSummary{}, err
		}
	}

	// The reloaded set becomes the mirror either way: a deferred reload is
	// rebuilt from the same loader on the next reconnect. Copied for the same
	// reason as the connect-time adopt.
	//
	// Keep the outgoing set so a WatchSetRejected can put it back: the node
	// leaves its live set UNTOUCHED on rejection, so adopting unconditionally
	// left the mirror describing a set the server never had - every item the
	// reload added silently unmatched, every item it removed still matching.
	if applied {
		w.reloadRollback = w.mirror.clone()
	}
	w.mirror = loaded.clone()

	return ReloadSummary{
		Added:     counts.added,
		Removed:   counts.removed,
		Unchanged: counts.unchanged,
		Applied:   applied,
	}, nil
}

// --- internals ---------------------------------------------------------------

// edit applies a mirror mutation and its live control message atomically with
// respect to other edits.
func (w *ResilientWatch) edit(ctx context.Context, send func(*WatchHandle) error, mutate func(*WatchSet)) error {
	return w.editErr(ctx, send, func(m *WatchSet) error { mutate(m); return nil })
}

// editErr is edit for a mutation that can be refused. The check runs against the
// LIVE mirror under the lock, so a bound is enforced against everything already
// registered rather than against the batch in hand.
func (w *ResilientWatch) editErr(ctx context.Context, send func(*WatchHandle) error, mutate func(*WatchSet) error) error {
	// Ordered against a reconnect replay before touching any state.
	w.replayMu.Lock()
	defer w.replayMu.Unlock()

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := mutate(w.mirror); err != nil {
		return err
	}
	h := w.handle
	if h == nil {
		// Disconnected: the mirror carries the edit onto the next stream.
		return nil
	}
	err := send(h)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrControlClosed):
		// The stream died under us. The edit is safe in the mirror and replays on
		// the reconnect, so this is not the caller's problem.
		w.teardownLocked()
		return nil
	default:
		return err
	}
}

func (w *ResilientWatch) teardownLocked() {
	w.handle = nil
}

func (w *ResilientWatch) commitDue(ctx context.Context) error {
	w.mu.Lock()
	armed := w.commitNext
	gen := w.commitNextGen
	if armed == nil || gen != w.gen ||
		(w.committed != nil && *w.committed == *armed) {
		w.commitNext = nil
		w.mu.Unlock()
		return nil
	}
	c := *armed
	w.mu.Unlock()

	if err := w.config.store().Store(ctx, c); err != nil {
		// The arm stays armed on failure - see the note in
		// ResilientSubscription.commitDue for why clearing it here silently
		// broke at-least-once.
		return err
	}
	w.mu.Lock()
	if w.commitNext != nil && w.commitNextGen == gen && *w.commitNext == c {
		w.commitNext = nil
	}
	w.committed = &c
	w.mu.Unlock()
	return nil
}

// pump is the reconnect state machine: connect, replay the watch-set, re-anchor,
// then pump events until the stream fails.
func (w *ResilientWatch) pump(ctx context.Context) {
	defer close(w.done)
	defer close(w.events)

	backoff := w.config.backoff()

	// Each attempt's Watch stream gets its own cancellable context, cancelled
	// the moment the attempt is abandoned. Without it every failed connect -
	// a loader error, a rejected control, a failed re-anchor - orphaned a LIVE
	// server-side Watch stream holding a subscription slot and its watch quota.
	// A loader whose durable truth is briefly unreachable is documented as
	// retrying forever, which turned a transient outage into hundreds of
	// leaked subscriptions and eventually locked every client off the node.
	var streamCancel context.CancelFunc
	dropStream := func() {
		if streamCancel != nil {
			streamCancel()
			streamCancel = nil
		}
	}
	defer dropStream()

	var (
		stream    *Stream
		attempts  uint32
		lastError error
	)

	for {
		if ctx.Err() != nil {
			return
		}
		if stream == nil {
			if attempts > 0 {
				if backoff.MaxRetries > 0 && attempts > backoff.MaxRetries {
					w.deliver(ctx, delivery{err: orControlClosed(lastError)})
					return
				}
				if !sleepCtx(ctx, backoff.DelayFor(attempts-1)) {
					return
				}
			}
			streamCtx, cancel := context.WithCancel(ctx)
			st, err := w.connectOnce(streamCtx)
			if err != nil {
				cancel()
				if !reconnectable(err) || ctx.Err() != nil {
					w.deliver(ctx, delivery{err: err})
					return
				}
				attempts++
				lastError = err
				continue
			}
			streamCancel = cancel
			stream = st
		}

		ev, err := stream.Recv()
		if err != nil {
			stream = nil
			dropStream()
			w.mu.Lock()
			w.teardownLocked()
			w.mu.Unlock()
			if err == io.EOF {
				attempts++
				continue
			}
			if Retryable(err) && ctx.Err() == nil {
				attempts++
				lastError = err
				continue
			}
			if ctx.Err() != nil {
				return
			}
			w.deliver(ctx, delivery{err: err})
			return
		}

		attempts, lastError = 0, nil
		handled, err := w.handleEvent(ctx, ev, stream.Cursor(), backoff)
		if err != nil {
			w.deliver(ctx, delivery{err: err})
			return
		}
		if handled {
			// Absorbed internally (a transient re-anchor retry): keep pumping.
			continue
		}
		if !w.deliverEvent(ctx, ev) {
			return
		}
	}
}

// handleEvent advances the high-water, prunes one-shot watches the node has
// auto-evicted, and absorbs a transient re-anchor rejection. It reports whether
// the event was handled internally (and so must not reach the caller).
func (w *ResilientWatch) handleEvent(ctx context.Context, ev Event, cur *Cursor, backoff Backoff) (bool, error) {
	w.mu.Lock()
	// The high-water only ever moves FORWARD, and never while a re-anchor is
	// outstanding. Two distinct bugs lived in the unconditional assignment this
	// replaces:
	//
	//   - A Rescan's matches are stamped with historical cursors, so they
	//     dragged resume backwards into the scanned range. A reconnect then
	//     re-anchored there, the node clamped the over-long replay, and the
	//     SDK reported a ReplayGap - which the docs tell operators means data
	//     was permanently lost, triggering a resync that was never needed.
	//   - Live events racing an unacked SetCursor pushed resume past the gap
	//     the re-anchor existed to close. See reanchorPending.
	if cur != nil && !w.reanchorPending && cursorForward(w.resume, cur) {
		w.resume = cur
	}

	// One-shot watches the node evicts when their terminal event fires: prune the
	// mirror to match. Otherwise a reconnect re-registers an already-fired watch,
	// which duplicates the terminal notification and burns watch quota on a
	// completed txid. The node reports the REQUESTED threshold as depth (the
	// alarm's identity), so that is the exact key to drop.
	switch e := ev.(type) {
	case *TxidDepthReached:
		if t, ok := txid32(e.Txid); ok {
			w.mirror.removeDepthAlarms([][32]byte{t}, []uint32{e.Depth})
		}
	case *TxidFinalized:
		if t, ok := txid32(e.Txid); ok {
			w.mirror.removeTxLifecycle(t)
		}
	}
	w.mu.Unlock()

	switch e := ev.(type) {
	case *WatchSetReplaced:
		// The node adopted the reloaded set; the mirror already matches it.
		w.mu.Lock()
		w.reloadRollback = nil
		w.mu.Unlock()
	case *WatchSetRejected:
		// The node kept its previous set, so the mirror must go back to
		// describing that set - otherwise every reconnect replays a set the
		// server refused and the divergence becomes permanent.
		w.mu.Lock()
		if w.reloadRollback != nil {
			w.mirror = w.reloadRollback
			w.reloadRollback = nil
		}
		w.mu.Unlock()
	case *CursorRejected:
		if e.Reason == CursorRejectRateLimited || e.Reason == CursorRejectConcurrentReanchor {
			return w.retryReanchor(ctx, backoff)
		}
		// Terminal rejection: the node will not re-anchor, so stop holding the
		// high-water back or it would never advance again.
		w.mu.Lock()
		w.reanchorPending = false
		w.mu.Unlock()
	case *CursorAccepted:
		// The node has committed to replaying from this anchor. Adopt it as the
		// resume point NOW, not once the first replayed event advances the
		// high-water: if the stream drops between the ack and that first event,
		// the reconnect re-anchors from resume, and leaving it at the stale
		// high-water would silently skip the catch-up window the caller asked for.
		w.mu.Lock()
		if e.From != nil {
			c := *e.From
			w.resume, w.desired = &c, &c
			// Supersede any cursor armed before this re-anchor. Without the
			// bump the guard in commitDue was inert (gen was never incremented
			// anywhere in this type), so a BACKWARD re-anchor still committed
			// the older, higher cursor - and a crash in that window skipped
			// exactly the range the caller had asked to replay.
			w.gen++
			w.commitNext = nil
		}
		w.reanchorPending = false
		w.reanchorAttempts = 0
		w.mu.Unlock()
	}
	return false, nil
}

// retryReanchor backs off and re-sends the outstanding re-anchor in place.
//
// Running on the pump goroutine means the retry budget cannot be charged without
// the re-send following: there is no cancellable caller future to strand it.
// Exhausting the budget surfaces the rejection so the caller can escalate rather
// than spinning forever.
func (w *ResilientWatch) retryReanchor(ctx context.Context, backoff Backoff) (bool, error) {
	w.mu.Lock()
	attempt := w.reanchorAttempts
	if backoff.MaxRetries > 0 && attempt >= backoff.MaxRetries {
		w.reanchorAttempts = 0
		w.mu.Unlock()
		return false, nil // surface the rejection
	}
	w.reanchorAttempts = attempt + 1
	w.mu.Unlock()

	if !sleepCtx(ctx, backoff.DelayFor(attempt)) {
		return true, nil
	}

	w.mu.Lock()
	h, desired := w.handle, copyCursor(w.desired)
	w.mu.Unlock()
	if h == nil || desired == nil {
		return true, nil
	}
	if err := h.SetCursor(ctx, *desired); err != nil {
		if errors.Is(err, ErrControlClosed) {
			w.mu.Lock()
			w.teardownLocked()
			w.mu.Unlock()
			return true, nil
		}
		return true, err
	}
	return true, nil
}

// connectOnce opens a fresh Watch stream, runs the loader if configured,
// re-registers the mirrored watch-set, and re-anchors to the resume cursor.
//
// A control-send failure here means the new stream is already unusable, so it is
// returned for the pump to back off and retry rather than surfaced.
func (w *ResilientWatch) connectOnce(ctx context.Context) (*Stream, error) {
	if err := w.seedResume(ctx); err != nil {
		return nil, err
	}
	// Order this whole sequence - loader, snapshot, replay, install - against
	// caller edits. See replayMu.
	w.replayMu.Lock()
	defer w.replayMu.Unlock()

	h, stream, err := w.client.Watch(ctx)
	if err != nil {
		return nil, err
	}

	// A configured loader is canonical: rebuild from the integrator's truth into
	// a fresh set and adopt it, before anything is registered and before any
	// event is pumped.
	if loader := w.config.WatchSetLoader; loader != nil {
		loaded := NewWatchSet()
		if err := loader(ctx, loaded); err != nil {
			return nil, wrapError(KindWatchSetLoader, err, "watch-set loader: %s", err)
		}
		// Adopt a copy: the loader is user code and is free to keep the set it was
		// handed. A retained reference mutated later would otherwise silently
		// corrupt the mirror between reconnects.
		w.mu.Lock()
		w.mirror = loaded.clone()
		w.mu.Unlock()
	}

	w.mu.Lock()
	msgs, err := w.mirror.controlMessages()
	resume := copyCursor(w.resume)
	w.mu.Unlock()
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if err := h.SendControl(ctx, m); err != nil {
			return nil, err
		}
	}
	if resume != nil {
		if err := h.SetCursor(ctx, *resume); err != nil {
			return nil, err
		}
	}

	w.mu.Lock()
	w.handle = h
	w.desired = resume
	// A re-anchor is outstanding until the node answers it; hold the high-water
	// still until then so a live event racing the ack cannot skip the replay
	// range. With no anchor to send there is nothing to wait for.
	w.reanchorPending = resume != nil
	w.reanchorAttempts = 0
	w.mu.Unlock()
	return stream, nil
}

// cursorForward reports whether b is at or beyond a, so the resume high-water
// can be advanced monotonically.
//
// A differing InstanceID means the node restarted and its cursor space is new,
// so the previous ordering carries no meaning and b is adopted.
func cursorForward(a, b *Cursor) bool {
	if a == nil || b == nil {
		return b != nil
	}
	if a.InstanceID != b.InstanceID {
		return true
	}
	if b.Height != a.Height {
		return b.Height > a.Height
	}
	if b.TxIndex != a.TxIndex {
		return b.TxIndex > a.TxIndex
	}
	return b.MempoolSeq >= a.MempoolSeq
}

// seedResume establishes the anchor on the first connect: the in-memory
// high-water, else the persisted cursor, else the configured FromCursor. A
// cursor read back from the store is already durable, so it also seeds committed
// and the first post-restart commit of an unchanged anchor is elided.
func (w *ResilientWatch) seedResume(ctx context.Context) error {
	w.mu.Lock()
	seeded := w.seeded
	w.mu.Unlock()
	if seeded {
		return nil
	}
	loaded, err := w.config.store().Load(ctx)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.seeded {
		if loaded != nil {
			if w.committed == nil {
				c := *loaded
				w.committed = &c
			}
			if w.resume == nil {
				w.resume = loaded
			}
		} else if w.resume == nil && w.config.FromCursor != nil {
			c := *w.config.FromCursor
			w.resume = &c
		}
		w.seeded = true
	}
	return nil
}

// txid32 narrows a wire txid to the fixed-size mirror key, ignoring a
// wrong-length one rather than panicking: a malformed txid means the pruning is
// skipped, which at worst re-registers a fired watch - never a crash.
func txid32(b []byte) ([32]byte, bool) {
	var out [32]byte
	if len(b) != 32 {
		return out, false
	}
	copy(out[:], b)
	return out, true
}

func (w *ResilientWatch) deliverEvent(ctx context.Context, ev Event) bool {
	w.mu.Lock()
	cur, gen := copyCursor(w.resume), w.gen
	w.mu.Unlock()
	return w.deliver(ctx, delivery{ev: ev, cursor: cur, gen: gen})
}

func (w *ResilientWatch) deliver(ctx context.Context, item delivery) bool {
	select {
	case w.events <- item:
		return true
	case <-ctx.Done():
		return false
	}
}

// reconnectable extends the transport-retryable set with the two failures that
// are specific to (re)establishing a watch stream: a control-send that found the
// stream already closed, and a watch-set loader that could not reach its
// source-of-truth. Neither is the caller's problem - both are retried on the
// next connect.
func reconnectable(err error) bool {
	return Retryable(err) || errors.Is(err, ErrControlClosed) || errors.Is(err, ErrWatchSetLoaderFailed)
}
