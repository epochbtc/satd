package satdevents

import (
	"crypto/sha256"
	"sort"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

// ScripthashOf returns sha256(scriptPubKey) - the 32-byte value the server keys
// script watches on, and the identity a [ScriptMatched] reports.
//
// It takes raw scriptPubKey bytes rather than a typed script so the SDK does
// not force a Bitcoin library on consumers; get the bytes from whatever library
// (or RPC field) you already use.
func ScripthashOf(scriptPubKey []byte) [32]byte { return sha256.Sum256(scriptPubKey) }

// WatchSet is a complete watch-set snapshot: the full desired membership of
// every watch kind, not a delta.
//
// Build one and hand it to [WatchHandle.SetWatchSet] for an atomic replace, or
// declare one from a [WatchSetLoader] so a [ResilientWatch] can rebuild the
// canonical set from your durable source-of-truth on every reconnect.
//
// The Add methods are declarative and additive; re-asserting a key overwrites
// it, exactly as the server reconciles. There are deliberately no Remove
// methods: a snapshot describes what SHOULD be watched, and anything absent is
// removed by construction.
//
// The zero value is an empty, usable set.
type WatchSet struct {
	// scripts maps a scripthash to its optional min-value floor.
	scripts map[[32]byte]*uint64
	// outpoints is the set of watched (txid, vout) pairs.
	outpoints map[OutpointRef]struct{}
	// lifecycles maps a txid to its auto-close policy.
	lifecycles map[[32]byte]AutoClose
	// depthAlarms is the set of (txid, depth) alarms.
	depthAlarms map[depthAlarm]struct{}
	// descriptors maps a descriptor string to its latest window.
	descriptors map[string]descriptorWindow
	// prefixes is the set of registered buckets, keyed by (bits, prefix hex) so
	// the byte slice does not have to be a map key.
	prefixes map[prefixKey]ScriptPrefix
	// silentPayments maps a target's identity b_scan*G to the target.
	silentPayments map[[33]byte]SilentPaymentTarget
	// categories is the live firehose filter, when the caller set one.
	categories *uint32
	// includeRawTx is the raw-tx opt-in, when the caller set one.
	includeRawTx *bool
}

type depthAlarm struct {
	txid  [32]byte
	depth uint32
}

type descriptorWindow struct {
	gapLimit uint32
	start    uint32
}

type prefixKey struct {
	bits   uint32
	prefix string
}

// NewWatchSet returns an empty watch-set.
func NewWatchSet() *WatchSet { return &WatchSet{} }

// AddScripts declares script watches with optional per-script value floors.
func (w *WatchSet) AddScripts(items ...ScriptWatch) *WatchSet {
	if w.scripts == nil {
		w.scripts = map[[32]byte]*uint64{}
	}
	for _, it := range items {
		var floor *uint64
		if it.MinValue != nil {
			v := *it.MinValue
			floor = &v
		}
		w.scripts[it.Scripthash] = floor
	}
	return w
}

// AddOutpoints declares outpoint watches.
func (w *WatchSet) AddOutpoints(outpoints ...OutpointRef) *WatchSet {
	if w.outpoints == nil {
		w.outpoints = map[OutpointRef]struct{}{}
	}
	for _, op := range outpoints {
		w.outpoints[op] = struct{}{}
	}
	return w
}

// AddTxLifecycle declares lifecycle watches on transactions.
func (w *WatchSet) AddTxLifecycle(autoClose AutoClose, txids ...[32]byte) *WatchSet {
	if w.lifecycles == nil {
		w.lifecycles = map[[32]byte]AutoClose{}
	}
	for _, t := range txids {
		w.lifecycles[t] = autoClose
	}
	return w
}

// AddDepthAlarms declares single-shot depth alarms over the cross product of
// txids and depths. Depths below 1 are dropped, matching
// [WatchHandle.AddDepthAlarms].
func (w *WatchSet) AddDepthAlarms(txids [][32]byte, depths []uint32) *WatchSet {
	valid := validDepths(depths)
	if len(txids) == 0 || len(valid) == 0 {
		return w
	}
	if w.depthAlarms == nil {
		w.depthAlarms = map[depthAlarm]struct{}{}
	}
	for _, t := range txids {
		for _, d := range valid {
			w.depthAlarms[depthAlarm{txid: t, depth: d}] = struct{}{}
		}
	}
	return w
}

// AddDescriptor declares a descriptor's watch window. The latest window per
// descriptor string wins.
func (w *WatchSet) AddDescriptor(descriptor string, gapLimit, start uint32) *WatchSet {
	if w.descriptors == nil {
		w.descriptors = map[string]descriptorWindow{}
	}
	w.descriptors[descriptor] = descriptorWindow{gapLimit: gapLimit, start: start}
	return w
}

// AddScriptPrefixes declares script-prefix buckets. Validation happens when the
// set is rendered ([WatchHandle.SetWatchSet]), so a builder chain stays
// error-free; an invalid (Prefix, Bits) pair surfaces there.
func (w *WatchSet) AddScriptPrefixes(prefixes ...ScriptPrefix) *WatchSet {
	if w.prefixes == nil {
		w.prefixes = map[prefixKey]ScriptPrefix{}
	}
	for _, p := range prefixes {
		w.prefixes[prefixKey{bits: p.Bits, prefix: string(p.Prefix)}] = ScriptPrefix{
			Prefix: append([]byte(nil), p.Prefix...),
			Bits:   p.Bits,
		}
	}
	return w
}

// AddSilentPayments declares BIP 352 scan-key targets, keyed by their identity
// b_scan*G. Each target is validated here (rather than at render time) because
// deriving that identity is what validates it.
func (w *WatchSet) AddSilentPayments(targets ...SilentPaymentTarget) error {
	if w.silentPayments == nil {
		w.silentPayments = map[[33]byte]SilentPaymentTarget{}
	}
	for i := range targets {
		id, err := targets[i].Validate()
		if err != nil {
			return err
		}
		// Last-wins on a repeated identity, matching the server's reconcile.
		w.silentPayments[id] = targets[i].clone()
	}
	if len(w.silentPayments) > MaxSPTargetsPerConnection {
		return newError(KindInvalidArgument,
			"silent-payment target cap exceeded: %d > %d",
			len(w.silentPayments), MaxSPTargetsPerConnection)
	}
	return nil
}

// SetCategories declares the live firehose category filter.
func (w *WatchSet) SetCategories(categories uint32) *WatchSet {
	v := categories
	w.categories = &v
	return w
}

// SetWatchOptions declares the raw-tx opt-in. A snapshot that wants raw_tx on
// [ScriptMatched] must re-declare it on every rebuild, exactly like
// [WatchSet.SetCategories] - the snapshot is canonical.
func (w *WatchSet) SetWatchOptions(includeRawTx bool) *WatchSet {
	v := includeRawTx
	w.includeRawTx = &v
	return w
}

// Len is the number of watch ENTRIES in the set - the unit the per-connection
// cap (streamwsmaxsubscriptions) counts, and what a
// [WatchSetRejectCapExceeded] reports.
func (w *WatchSet) Len() int {
	return len(w.scripts) + len(w.outpoints) + len(w.lifecycles) +
		len(w.depthAlarms) + len(w.descriptors) + len(w.prefixes) + len(w.silentPayments)
}

// toProto renders the snapshot into the wire SetWatchSet message.
//
// Every repeated field is emitted in a deterministic order (sorted by key)
// rather than Go's randomized map order. That is not cosmetic: the differential
// parity harness compares the Go and Rust SDKs' wire output, and the Rust
// mirror renders from ordered maps.
func (w *WatchSet) toProto() (*eventspb.SetWatchSet, error) {
	out := &eventspb.SetWatchSet{}
	if w.categories != nil {
		out.Categories = *w.categories
	}

	for _, h := range sortedScripthashes(w.scripts) {
		out.Scripthashes = append(out.Scripthashes, append([]byte(nil), h[:]...))
	}
	// min_values is parallel to scripthashes, or empty when no script is
	// floored - the same rule AddScripts follows.
	floored := false
	for _, f := range w.scripts {
		if f != nil {
			floored = true
			break
		}
	}
	if floored {
		for _, h := range sortedScripthashes(w.scripts) {
			var v uint64
			if f := w.scripts[h]; f != nil {
				v = *f
			}
			out.MinValues = append(out.MinValues, v)
		}
	}

	ops := make([]OutpointRef, 0, len(w.outpoints))
	for op := range w.outpoints {
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool {
		if c := compareBytes(ops[i].Txid[:], ops[j].Txid[:]); c != 0 {
			return c < 0
		}
		return ops[i].Vout < ops[j].Vout
	})
	out.Outpoints = outpointsToProto(ops)

	for _, t := range sortedLifecycleTxids(w.lifecycles) {
		out.Lifecycles = append(out.Lifecycles, &eventspb.WatchLifecycle{
			Txid:           append([]byte(nil), t[:]...),
			AutoCloseDepth: uint32(w.lifecycles[t]),
		})
	}

	alarms := make([]depthAlarm, 0, len(w.depthAlarms))
	for a := range w.depthAlarms {
		alarms = append(alarms, a)
	}
	sort.Slice(alarms, func(i, j int) bool {
		if c := compareBytes(alarms[i].txid[:], alarms[j].txid[:]); c != 0 {
			return c < 0
		}
		return alarms[i].depth < alarms[j].depth
	})
	for _, a := range alarms {
		out.DepthAlarms = append(out.DepthAlarms, &eventspb.WatchDepthAlarm{
			Txid:  append([]byte(nil), a.txid[:]...),
			Depth: a.depth,
		})
	}

	descs := make([]string, 0, len(w.descriptors))
	for d := range w.descriptors {
		descs = append(descs, d)
	}
	sort.Strings(descs)
	for _, d := range descs {
		win := w.descriptors[d]
		out.Descriptors = append(out.Descriptors, &eventspb.AddDescriptor{
			Descriptor_: d,
			GapLimit:    win.gapLimit,
			Start:       win.start,
		})
	}

	for _, p := range sortedPrefixes(w.prefixes) {
		v, err := validatePrefix(p)
		if err != nil {
			return nil, err
		}
		out.Prefixes = append(out.Prefixes, v)
	}

	for _, id := range sortedScanPubkeys(w.silentPayments) {
		t := w.silentPayments[id]
		out.SilentPayments = append(out.SilentPayments, t.toProto())
	}

	return out, nil
}

func sortedScripthashes(m map[[32]byte]*uint64) [][32]byte {
	out := make([][32]byte, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return compareBytes(out[i][:], out[j][:]) < 0 })
	return out
}

func sortedLifecycleTxids(m map[[32]byte]AutoClose) [][32]byte {
	out := make([][32]byte, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return compareBytes(out[i][:], out[j][:]) < 0 })
	return out
}

func sortedScanPubkeys(m map[[33]byte]SilentPaymentTarget) [][33]byte {
	out := make([][33]byte, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return compareBytes(out[i][:], out[j][:]) < 0 })
	return out
}

func sortedPrefixes(m map[prefixKey]ScriptPrefix) []ScriptPrefix {
	out := make([]ScriptPrefix, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bits != out[j].Bits {
			return out[i].Bits < out[j].Bits
		}
		return compareBytes(out[i].Prefix, out[j].Prefix) < 0
	})
	return out
}

func compareBytes(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}
