package satdevents

import (
	"context"
	"io"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

// MaxPrefixBits is the widest meaningful script-prefix width.
//
// The server buckets on the top 32 bits of sha256(scriptPubKey) - its mask
// saturates there - so a wider registration can never be more selective and is
// silently dropped server-side (the control path has no per-message ack). The
// SDK rejects it client-side rather than let a caller believe a watch was
// installed. A server may further LOWER the ceiling via streamprefixmaxbits;
// that bound is not advertised over the wire, so an over-precise (but <= 32)
// prefix can still be dropped silently, with no client-side signal.
const MaxPrefixBits = 32

// AutoClose is a transaction lifecycle watch's auto-close depth.
//
// [AutoCloseNever] (0) keeps the watch until it is removed. A depth >= 1
// self-evicts the watch and emits [TxidFinalized] once the transaction is that
// many confirmations deep - a free modifier that costs no extra quota.
type AutoClose uint32

// AutoCloseNever keeps a lifecycle watch until it is removed explicitly.
const AutoCloseNever AutoClose = 0

// AutoCloseAtDepth self-evicts the lifecycle watch (and emits [TxidFinalized])
// once the transaction is depth confirmations deep.
func AutoCloseAtDepth(depth uint32) AutoClose { return AutoClose(depth) }

// ScriptWatch is one script registration: the scripthash to watch, with an
// optional per-script value floor.
type ScriptWatch struct {
	// Scripthash is sha256(scriptPubKey) - see [ScripthashOf].
	Scripthash [32]byte
	// MinValue suppresses matches below this floor in satoshis (the funded
	// output value for a funding match, the spent-prevout value for a spend).
	// nil delivers every match. Re-asserting a watched scripthash updates its
	// floor.
	MinValue *uint64
}

// OutpointRef is a transaction output reference for a watch registration.
type OutpointRef struct {
	// Txid is the 32-byte transaction id in internal byte order (see
	// [TxidFromDisplayHex] to convert one from JSON-RPC).
	Txid [32]byte
	// Vout is the output index.
	Vout uint32
}

// WatchHandle sends control messages on a bidirectional Watch stream.
//
// Typed helpers build the right control message for each watch kind;
// [WatchHandle.SendControl] remains for raw access to anything not yet wrapped.
// Empty inputs are no-ops - nothing is sent.
//
// It is safe for concurrent use: sends are serialized internally (a gRPC stream
// permits only one Send at a time). Close it, or cancel the context the stream
// was opened with, to tear the stream down.
type WatchHandle struct {
	stream eventspb.NodeEventStream_WatchClient
	// sendLock is a context-aware mutex: a buffered channel of capacity one, so
	// a caller blocked behind another send still honors its own cancellation.
	sendLock chan struct{}
}

// Watch opens a bidirectional watch stream, returning a [WatchHandle] to
// register interest and a [Stream] of matches interleaved with the
// category-filtered firehose.
//
// The watch-set is per-CONNECTION: the server holds no principal-keyed state,
// so when this stream drops its watch-set and quota leases are torn down with
// it and a fresh stream starts blank. [Client.ResilientWatch] exists for that
// reason - it mirrors every registration and replays it on reconnect.
//
// Adding watches requires the stream:watch capability when the server enforces
// auth. Cancelling ctx terminates the stream.
func (c *Client) Watch(ctx context.Context) (*WatchHandle, *Stream, error) {
	sc, err := c.rpc.Watch(c.authed(ctx))
	if err != nil {
		return nil, nil, fromStatus(err)
	}
	h := &WatchHandle{stream: sc, sendLock: make(chan struct{}, 1)}
	return h, &Stream{recv: sc.Recv}, nil
}

// Close stops sending on the watch stream. The server tears the stream (and its
// watch-set) down; already-sent registrations stay in effect until it does.
// Receiving continues until the server closes its half.
func (h *WatchHandle) Close() error {
	if err := h.stream.CloseSend(); err != nil {
		return fromStatus(err)
	}
	return nil
}

// SendControl sends a raw control message - the escape hatch for anything the
// typed helpers do not cover.
func (h *WatchHandle) SendControl(ctx context.Context, ctrl *eventspb.SubscribeControl) error {
	// Checked before the select: with the lock free, select would otherwise pick
	// either ready case at random and an already-cancelled context could still
	// put a message on the wire.
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case h.sendLock <- struct{}{}:
		defer func() { <-h.sendLock }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := h.stream.Send(ctrl); err != nil {
		// grpc-go reports a stream that has already failed as io.EOF from Send,
		// with the real status surfacing on Recv. Map it to the SDK's
		// control-closed class so a caller (and the resilience layer) can tell
		// "the stream is gone, re-register on a new one" from a genuine
		// argument or permission failure.
		if err == io.EOF {
			return &Error{Kind: KindControlClosed, err: err}
		}
		return fromStatus(err)
	}
	return nil
}

// AddScripts adds script watches (each keyed on sha256(scriptPubKey)), with an
// optional per-script value floor. Charges one watch-quota unit per scripthash.
func (h *WatchHandle) AddScripts(ctx context.Context, items []ScriptWatch) error {
	if len(items) == 0 {
		return nil
	}
	add := &eventspb.AddScripts{Scripthashes: make([][]byte, 0, len(items))}
	floored := false
	for _, it := range items {
		add.Scripthashes = append(add.Scripthashes, append([]byte(nil), it.Scripthash[:]...))
		if it.MinValue != nil {
			floored = true
		}
	}
	// min_values is empty when no script carries a floor; otherwise it must be
	// parallel to scripthashes, with 0 (deliver-all) for the unfloored entries.
	if floored {
		add.MinValues = make([]uint64, 0, len(items))
		for _, it := range items {
			var v uint64
			if it.MinValue != nil {
				v = *it.MinValue
			}
			add.MinValues = append(add.MinValues, v)
		}
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddScripts{AddScripts: add}})
}

// RemoveScripts removes script watches, releasing their quota.
func (h *WatchHandle) RemoveScripts(ctx context.Context, scripthashes [][32]byte) error {
	if len(scripthashes) == 0 {
		return nil
	}
	msg := &eventspb.RemoveScripts{Scripthashes: make([][]byte, 0, len(scripthashes))}
	for _, s := range scripthashes {
		msg.Scripthashes = append(msg.Scripthashes, append([]byte(nil), s[:]...))
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_RemoveScripts{RemoveScripts: msg}})
}

// AddOutpoints watches outpoints for their spend. Charges one unit each.
func (h *WatchHandle) AddOutpoints(ctx context.Context, outpoints []OutpointRef) error {
	if len(outpoints) == 0 {
		return nil
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddOutpoints{
		AddOutpoints: &eventspb.AddOutpoints{Outpoints: outpointsToProto(outpoints)},
	}})
}

// RemoveOutpoints stops watching outpoints, releasing their quota.
func (h *WatchHandle) RemoveOutpoints(ctx context.Context, outpoints []OutpointRef) error {
	if len(outpoints) == 0 {
		return nil
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_RemoveOutpoints{
		RemoveOutpoints: &eventspb.RemoveOutpoints{Outpoints: outpointsToProto(outpoints)},
	}})
}

func outpointsToProto(in []OutpointRef) []*eventspb.Outpoint {
	out := make([]*eventspb.Outpoint, 0, len(in))
	for _, op := range in {
		out = append(out, &eventspb.Outpoint{
			Txid: append([]byte(nil), op.Txid[:]...),
			Vout: op.Vout,
		})
	}
	return out
}

// AddTxLifecycle adds persistent lifecycle watches on transactions: seen ->
// confirmed -> replaced / evicted / unconfirmed. autoClose optionally
// self-evicts the watch once the transaction is buried. Charges one unit per
// txid.
func (h *WatchHandle) AddTxLifecycle(ctx context.Context, txids [][32]byte, autoClose AutoClose) error {
	if len(txids) == 0 {
		return nil
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddTransactions{
		AddTransactions: &eventspb.AddTransactions{
			Txids: txidsToProto(txids),
			// An EMPTY min_depths is what selects the lifecycle primitive; the
			// server dispatches on that field, not on a flag.
			MinDepths:      nil,
			AutoCloseDepth: uint32(autoClose),
		},
	}})
}

// RemoveTxLifecycle removes lifecycle watches.
func (h *WatchHandle) RemoveTxLifecycle(ctx context.Context, txids [][32]byte) error {
	if len(txids) == 0 {
		return nil
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_RemoveTransactions{
		RemoveTransactions: &eventspb.RemoveTransactions{Txids: txidsToProto(txids), MinDepths: nil},
	}})
}

// AddDepthAlarms arms single-shot depth alarms over the CROSS PRODUCT of txids
// and depths: each transaction fires [TxidDepthReached] once it is depth
// confirmations deep, then the alarm self-evicts. Charges one unit per
// (txid, depth).
//
// Depths must be >= 1; smaller ones are dropped. If that leaves no valid depths
// (or there are no txids) this is a no-op - importantly it does NOT send an
// empty min_depths, which the server would reinterpret as a LIFECYCLE add.
func (h *WatchHandle) AddDepthAlarms(ctx context.Context, txids [][32]byte, depths []uint32) error {
	valid := validDepths(depths)
	if len(txids) == 0 || len(valid) == 0 {
		return nil
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddTransactions{
		AddTransactions: &eventspb.AddTransactions{
			Txids:          txidsToProto(txids),
			MinDepths:      valid,
			AutoCloseDepth: 0,
		},
	}})
}

// RemoveDepthAlarms removes depth alarms over the cross product of txids and
// depths. As with [WatchHandle.AddDepthAlarms], an all-invalid or empty call is
// a no-op and never sends an empty min_depths (which would target lifecycle
// watches instead).
func (h *WatchHandle) RemoveDepthAlarms(ctx context.Context, txids [][32]byte, depths []uint32) error {
	valid := validDepths(depths)
	if len(txids) == 0 || len(valid) == 0 {
		return nil
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_RemoveTransactions{
		RemoveTransactions: &eventspb.RemoveTransactions{
			Txids:     txidsToProto(txids),
			MinDepths: valid,
		},
	}})
}

func validDepths(depths []uint32) []uint32 {
	var out []uint32
	for _, d := range depths {
		if d >= 1 {
			out = append(out, d)
		}
	}
	return out
}

func txidsToProto(txids [][32]byte) [][]byte {
	out := make([][]byte, 0, len(txids))
	for _, t := range txids {
		out = append(out, append([]byte(nil), t[:]...))
	}
	return out
}

// AddDescriptor expands a public output descriptor into a script watch-set over
// the window [start, start+gapLimit).
//
// The server retains the descriptor-to-scripthashes membership, so the CLIENT
// owns gap-limit advancement: re-send with an advanced start to slide the
// window (the server reconciles it - scripts that left are released, scripts
// that entered are added), and drop the whole window with
// [WatchHandle.RemoveDescriptor]. Charges one unit per net-new derived script.
func (h *WatchHandle) AddDescriptor(ctx context.Context, descriptor string, gapLimit, start uint32) error {
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddDescriptor{
		AddDescriptor: &eventspb.AddDescriptor{
			Descriptor_: descriptor,
			GapLimit:    gapLimit,
			Start:       start,
		},
	}})
}

// RemoveDescriptor removes a descriptor added with
// [WatchHandle.AddDescriptor], releasing every scripthash its window
// contributed whose last owner this drops. A scripthash the descriptor shares
// with a direct AddScripts or another descriptor stays watched. descriptor must
// byte-match the string it was added with; removing an unknown one is a no-op.
func (h *WatchHandle) RemoveDescriptor(ctx context.Context, descriptor string) error {
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_RemoveDescriptor{
		RemoveDescriptor: &eventspb.RemoveDescriptor{Descriptor_: descriptor},
	}})
}

// AddScriptPrefixes adds privacy-preserving script-prefix buckets: each is a
// Bits-bit prefix of sha256(scriptPubKey), carried as its top ceil(Bits/8)
// bytes. The server delivers every transaction in the 2^-Bits bucket and the
// client filters locally (see [PrefixWatcher]), so the server learns only the
// bucket. Charged by coarseness - a smaller Bits costs more.
//
// Bits must be in [1, MaxPrefixBits] and Prefix exactly ceil(Bits/8) bytes;
// both are checked before anything reaches the wire. Prefix is normalized to
// its bucket (bits past Bits zeroed) to match how the node keys it.
//
// The NODE enforces its own floor, streamprefixminbits (default 8), and drops a
// narrower bucket SILENTLY - no error, no rejection event. Registering below the
// node's floor therefore looks exactly like "nobody has paid you yet". The
// floor is server configuration the client cannot see, so this cannot be
// checked here; if you register narrow buckets, confirm the node's setting.
func (h *WatchHandle) AddScriptPrefixes(ctx context.Context, prefixes []ScriptPrefix) error {
	validated, err := validatePrefixes(prefixes)
	if err != nil || len(validated) == 0 {
		return err
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddScriptPrefixes{
		AddScriptPrefixes: &eventspb.AddScriptPrefixes{Prefixes: validated},
	}})
}

// RemoveScriptPrefixes removes prefix buckets, releasing their quota.
func (h *WatchHandle) RemoveScriptPrefixes(ctx context.Context, prefixes []ScriptPrefix) error {
	validated, err := validatePrefixes(prefixes)
	if err != nil || len(validated) == 0 {
		return err
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_RemoveScriptPrefixes{
		RemoveScriptPrefixes: &eventspb.RemoveScriptPrefixes{Prefixes: validated},
	}})
}

// validatePrefixes checks a whole batch up front, so one bad entry rejects the
// call rather than sending a partially-valid registration.
func validatePrefixes(prefixes []ScriptPrefix) ([]*eventspb.ScriptPrefix, error) {
	out := make([]*eventspb.ScriptPrefix, 0, len(prefixes))
	for _, p := range prefixes {
		v, err := validatePrefix(p)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func validatePrefix(p ScriptPrefix) (*eventspb.ScriptPrefix, error) {
	if p.Bits < 1 || p.Bits > MaxPrefixBits {
		return nil, newError(KindInvalidArgument,
			"prefix bits %d out of range 1..=%d", p.Bits, MaxPrefixBits)
	}
	want := int((p.Bits + 7) / 8)
	if len(p.Prefix) != want {
		return nil, newError(KindInvalidArgument,
			"prefix for %d bits must be %d bytes, got %d", p.Bits, want, len(p.Prefix))
	}
	// NORMALIZE to the bucket the server will key on. The node masks every bit
	// past Bits before bucketing, so an unmasked prefix registers under one key
	// and is mirrored locally under another - a later Remove built with
	// [PrefixOf] then drops the server's bucket while the mirror keeps its
	// entry, and the SDK reports a bucket as watched that receives nothing.
	//
	// It also matters for privacy: the sub-Bits remainder is the part the
	// anonymity-set argument assumes was never sent, and a hand-built
	// ScriptPrefix would have put it on the wire verbatim.
	return &eventspb.ScriptPrefix{
		Prefix: maskPrefix(p.Prefix, p.Bits),
		Bits:   p.Bits,
	}, nil
}

// AddSilentPayments registers BIP 352 scan-key watch targets (Tier 2). The node
// runs the ECDH match server-side and pushes a [SilentPaymentMatched] for every
// output paying one of them. Up to [MaxSPTargetsPerConnection] per connection;
// each charges one watch-quota unit. Re-registering an existing target (same
// b_scan*G) refreshes its labels.
//
// Each target's ScanSecret and SpendPubkey are validated as curve values before
// anything is sent (see [SilentPaymentTarget.Validate]), so a malformed target
// is a deterministic error here rather than a silent server-side skip that
// would return success while installing no watch.
//
// The scan secret is a watch credential disclosed to the node - see
// [SilentPaymentTarget].
func (h *WatchHandle) AddSilentPayments(ctx context.Context, targets []SilentPaymentTarget) error {
	if len(targets) == 0 {
		return nil
	}
	out := make([]*eventspb.SilentPaymentTarget, 0, len(targets))
	for i := range targets {
		if _, err := targets[i].Validate(); err != nil {
			return err
		}
		out = append(out, targets[i].toProto())
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddSilentPayments{
		AddSilentPayments: &eventspb.AddSilentPayments{Targets: out},
	}})
}

// RemoveSilentPayments removes scan-key targets by their identity b_scan*G
// (33-byte compressed, from [SilentPaymentTarget.ScanPubkey]), releasing quota.
func (h *WatchHandle) RemoveSilentPayments(ctx context.Context, scanPubkeys [][33]byte) error {
	if len(scanPubkeys) == 0 {
		return nil
	}
	keys := make([][]byte, 0, len(scanPubkeys))
	for _, k := range scanPubkeys {
		keys = append(keys, append([]byte(nil), k[:]...))
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_RemoveSilentPayments{
		RemoveSilentPayments: &eventspb.RemoveSilentPayments{ScanPubkeys: keys},
	}})
}

// SetCategories adjusts the live firehose category bitfield (see
// [CategoryAll]). It applies immediately and does not affect the watch-set.
func (h *WatchHandle) SetCategories(ctx context.Context, categories uint32) error {
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_SetCategories{
		SetCategories: &eventspb.SetCategories{Categories: categories},
	}})
}

// SetWatchOptions sets per-stream delivery options. With includeRawTx, later
// [ScriptMatched] on this stream carry the full serialized matching
// transaction; false restores the default. Applies immediately, does not affect
// the watch-set, and is bandwidth-heavy - the Amount field already covers the
// common case.
//
// When driving a [ResilientWatch], prefer its own SetWatchOptions so the opt-in
// is re-applied across reconnects.
func (h *WatchHandle) SetWatchOptions(ctx context.Context, includeRawTx bool) error {
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_SetWatchOptions{
		SetWatchOptions: &eventspb.SetWatchOptions{IncludeRawTx: includeRawTx},
	}})
}

// SetCursor requests a mid-stream re-anchor: replay confirmed history forward
// from cursor, then resume live, without tearing down the watch-set.
// Rate-limited per principal; only one re-anchor drains at a time.
//
// A nil error means the request reached the control stream - NOT that the
// re-anchor ran. The outcome arrives IN-BAND on the event stream as exactly one
// of [CursorAccepted] (admitted; replay follows - watch Clamped) or
// [CursorRejected] (declined; the live stream is unchanged). A consumer that
// needs at-least-once delivery drives its catch-up off those events, not off
// this return.
func (h *WatchHandle) SetCursor(ctx context.Context, cursor Cursor) error {
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_SetCursor{
		SetCursor: &eventspb.SetCursor{Cursor: cursor.toProto()},
	}})
}

// SetWatchSet atomically REPLACES the whole watch-set with this snapshot: each
// field is the full desired membership, not a delta. The server reconciles it
// under its own lock, by effective coverage, so there is no client-computed
// add/remove ordering to strand coverage or over-charge at quota.
//
// As with SetCursor the outcome is in-band: exactly one [WatchSetReplaced] or
// [WatchSetRejected]. This is the primitive [ResilientWatch.Reload] is built on.
func (h *WatchHandle) SetWatchSet(ctx context.Context, snapshot *WatchSet) error {
	if snapshot == nil {
		return newError(KindInvalidArgument, "SetWatchSet requires a snapshot")
	}
	msg, err := snapshot.toProto()
	if err != nil {
		return err
	}
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_SetWatchSet{SetWatchSet: msg}})
}

// Rescan requests a bounded historical rescan of the current watch-set over the
// INCLUSIVE height range [fromHeight, toHeight].
//
// A side query: it does not move the durable cursor and runs independently of
// the live tail or any in-flight re-anchor. The server span-caps the range and
// admits one rescan at a time. The outcome arrives in-band as [RescanAccepted]
// (then confirmed matches in height order, terminated by [RescanComplete]) or
// [RescanRejected].
func (h *WatchHandle) Rescan(ctx context.Context, fromHeight, toHeight uint32) error {
	return h.SendControl(ctx, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_RescanBlocks{
		RescanBlocks: &eventspb.RescanBlocks{FromHeight: fromHeight, ToHeight: toHeight},
	}})
}
