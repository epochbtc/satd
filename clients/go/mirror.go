package satdevents

import (
	"sort"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

// This file gives [WatchSet] the operations [ResilientWatch] needs of it as a
// client-side MIRROR of what is registered on a stream: the removals that
// balance the public Add* methods, a rendering back into the control messages
// that reconstruct the set on a fresh stream, and a diff against a target set.
//
// The mirror keeps each kind as its NET set (adds minus removes), keyed so a
// re-assertion overwrites rather than duplicates - the server's own semantics.

func (w *WatchSet) removeScripts(hashes ...[32]byte) {
	for _, h := range hashes {
		delete(w.scripts, h)
	}
}

func (w *WatchSet) removeOutpoints(outpoints ...OutpointRef) {
	for _, op := range outpoints {
		delete(w.outpoints, op)
	}
}

func (w *WatchSet) removeTxLifecycle(txids ...[32]byte) {
	for _, t := range txids {
		delete(w.lifecycles, t)
	}
}

func (w *WatchSet) removeDepthAlarms(txids [][32]byte, depths []uint32) {
	for _, t := range txids {
		for _, d := range depths {
			delete(w.depthAlarms, depthAlarm{txid: t, depth: d})
		}
	}
}

func (w *WatchSet) removeDescriptor(descriptor string) {
	delete(w.descriptors, descriptor)
}

func (w *WatchSet) removeScriptPrefixes(prefixes ...ScriptPrefix) {
	for _, p := range prefixes {
		delete(w.prefixes, prefixKey{bits: p.Bits, prefix: string(p.Prefix)})
	}
}

func (w *WatchSet) removeSilentPayments(scanPubkeys ...[33]byte) {
	for _, k := range scanPubkeys {
		delete(w.silentPayments, k)
	}
}

// clone is a deep copy, so a mirror can be swapped without the old one aliasing
// the new one's maps.
func (w *WatchSet) clone() *WatchSet {
	out := NewWatchSet()
	if len(w.scripts) > 0 {
		out.scripts = make(map[[32]byte]*uint64, len(w.scripts))
		for k, v := range w.scripts {
			if v == nil {
				out.scripts[k] = nil
				continue
			}
			f := *v
			out.scripts[k] = &f
		}
	}
	if len(w.outpoints) > 0 {
		out.outpoints = make(map[OutpointRef]struct{}, len(w.outpoints))
		for k := range w.outpoints {
			out.outpoints[k] = struct{}{}
		}
	}
	if len(w.lifecycles) > 0 {
		out.lifecycles = make(map[[32]byte]AutoClose, len(w.lifecycles))
		for k, v := range w.lifecycles {
			out.lifecycles[k] = v
		}
	}
	if len(w.depthAlarms) > 0 {
		out.depthAlarms = make(map[depthAlarm]struct{}, len(w.depthAlarms))
		for k := range w.depthAlarms {
			out.depthAlarms[k] = struct{}{}
		}
	}
	if len(w.descriptors) > 0 {
		out.descriptors = make(map[string]descriptorWindow, len(w.descriptors))
		for k, v := range w.descriptors {
			out.descriptors[k] = v
		}
	}
	if len(w.prefixes) > 0 {
		out.prefixes = make(map[prefixKey]ScriptPrefix, len(w.prefixes))
		for k, v := range w.prefixes {
			p := v
			p.Prefix = append([]byte(nil), v.Prefix...)
			out.prefixes[k] = p
		}
	}
	if len(w.silentPayments) > 0 {
		out.silentPayments = make(map[[33]byte]SilentPaymentTarget, len(w.silentPayments))
		for k, v := range w.silentPayments {
			out.silentPayments[k] = v.clone()
		}
	}
	if w.categories != nil {
		c := *w.categories
		out.categories = &c
	}
	if w.includeRawTx != nil {
		r := *w.includeRawTx
		out.includeRawTx = &r
	}
	return out
}

// controlMessages renders the net watch-set into the control messages that
// reconstruct it on a fresh stream.
//
// The category filter goes first, so it is in effect before any match flows,
// followed by the raw-tx opt-in for the same reason: replayed and live
// ScriptMatched must carry raw_tx exactly as they did before the reconnect. The
// rest are grouped into the wire shapes the [WatchHandle] helpers emit -
// notably lifecycles grouped by auto-close depth with EMPTY min_depths, and
// depth alarms grouped per txid with NON-empty min_depths, because that field is
// what the server dispatches the two apart on.
//
// Ordering within each kind is by sorted key rather than Go's randomized map
// order, so a replay is byte-identical run to run (and diffable against the Rust
// mirror, which renders from ordered maps).
func (w *WatchSet) controlMessages() ([]*eventspb.SubscribeControl, error) {
	var out []*eventspb.SubscribeControl

	if w.categories != nil {
		out = append(out, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_SetCategories{
			SetCategories: &eventspb.SetCategories{Categories: *w.categories},
		}})
	}
	if w.includeRawTx != nil {
		out = append(out, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_SetWatchOptions{
			SetWatchOptions: &eventspb.SetWatchOptions{IncludeRawTx: *w.includeRawTx},
		}})
	}

	if len(w.scripts) > 0 {
		hashes := sortedScripthashes(w.scripts)
		msg := &eventspb.AddScripts{}
		for _, h := range hashes {
			msg.Scripthashes = append(msg.Scripthashes, append([]byte(nil), h[:]...))
		}
		if anyFloored(w.scripts) {
			for _, h := range hashes {
				var v uint64
				if f := w.scripts[h]; f != nil {
					v = *f
				}
				msg.MinValues = append(msg.MinValues, v)
			}
		}
		out = append(out, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddScripts{AddScripts: msg}})
	}

	if len(w.outpoints) > 0 {
		out = append(out, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddOutpoints{
			AddOutpoints: &eventspb.AddOutpoints{Outpoints: outpointsToProto(sortedOutpoints(w.outpoints))},
		}})
	}

	// Lifecycles, grouped by auto-close depth so each depth is one message.
	if len(w.lifecycles) > 0 {
		byDepth := map[uint32][][]byte{}
		for _, t := range sortedLifecycleTxids(w.lifecycles) {
			d := uint32(w.lifecycles[t])
			byDepth[d] = append(byDepth[d], append([]byte(nil), t[:]...))
		}
		for _, d := range sortedUint32Keys(byDepth) {
			out = append(out, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddTransactions{
				AddTransactions: &eventspb.AddTransactions{
					Txids:          byDepth[d],
					AutoCloseDepth: d,
				},
			}})
		}
	}

	// Depth alarms, grouped per txid - min_depths non-empty is what marks them.
	for _, g := range groupAlarmsByTxid(w.depthAlarms) {
		out = append(out, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddTransactions{
			AddTransactions: &eventspb.AddTransactions{
				Txids:     [][]byte{append([]byte(nil), g.txid[:]...)},
				MinDepths: g.depths,
			},
		}})
	}

	for _, d := range sortedDescriptorKeys(w.descriptors) {
		win := w.descriptors[d]
		out = append(out, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddDescriptor{
			AddDescriptor: &eventspb.AddDescriptor{
				Descriptor_: d,
				GapLimit:    win.gapLimit,
				Start:       win.start,
			},
		}})
	}

	if len(w.prefixes) > 0 {
		msg := &eventspb.AddScriptPrefixes{}
		for _, p := range sortedPrefixes(w.prefixes) {
			v, err := validatePrefix(p)
			if err != nil {
				return nil, err
			}
			msg.Prefixes = append(msg.Prefixes, v)
		}
		out = append(out, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddScriptPrefixes{AddScriptPrefixes: msg}})
	}

	if len(w.silentPayments) > 0 {
		msg := &eventspb.AddSilentPayments{}
		for _, id := range sortedScanPubkeys(w.silentPayments) {
			t := w.silentPayments[id]
			msg.Targets = append(msg.Targets, t.toProto())
		}
		out = append(out, &eventspb.SubscribeControl{Msg: &eventspb.SubscribeControl_AddSilentPayments{AddSilentPayments: msg}})
	}

	return out, nil
}

// reloadCounts is the item accounting from a [WatchSet.reconcileTo] diff.
type reloadCounts struct {
	added     int
	removed   int
	unchanged int
}

// reconcileTo counts what would change to turn w (the currently registered net
// set) into target.
//
// [ResilientWatch.Reload] sends the target as one atomic SetWatchSet and lets
// the server reconcile it under its own lock, so these counts are advisory - the
// server's WatchSetAccepted carries the authoritative numbers by effective
// coverage. They are computed here so a caller can see the shape of a reload
// (how much churn) without waiting for the ack, and because "unchanged" is not
// derivable from the ack alone.
//
// An item counts as unchanged only if it is present in both AND identical: a
// changed min-value floor, a slid descriptor window, a different auto-close
// depth, or refreshed silent-payment labels all count as added, because each
// re-asserts on the wire.
func (w *WatchSet) reconcileTo(target *WatchSet) reloadCounts {
	var c reloadCounts

	for h, floor := range target.scripts {
		if cur, ok := w.scripts[h]; ok && sameFloor(cur, floor) {
			c.unchanged++
		} else {
			c.added++
		}
	}
	for h := range w.scripts {
		if _, ok := target.scripts[h]; !ok {
			c.removed++
		}
	}

	for op := range target.outpoints {
		if _, ok := w.outpoints[op]; ok {
			c.unchanged++
		} else {
			c.added++
		}
	}
	for op := range w.outpoints {
		if _, ok := target.outpoints[op]; !ok {
			c.removed++
		}
	}

	for t, ac := range target.lifecycles {
		if cur, ok := w.lifecycles[t]; ok && cur == ac {
			c.unchanged++
		} else {
			c.added++
		}
	}
	for t := range w.lifecycles {
		if _, ok := target.lifecycles[t]; !ok {
			c.removed++
		}
	}

	for a := range target.depthAlarms {
		if _, ok := w.depthAlarms[a]; ok {
			c.unchanged++
		} else {
			c.added++
		}
	}
	for a := range w.depthAlarms {
		if _, ok := target.depthAlarms[a]; !ok {
			c.removed++
		}
	}

	for d, win := range target.descriptors {
		if cur, ok := w.descriptors[d]; ok && cur == win {
			c.unchanged++
		} else {
			c.added++
		}
	}
	for d := range w.descriptors {
		if _, ok := target.descriptors[d]; !ok {
			c.removed++
		}
	}

	for k := range target.prefixes {
		if _, ok := w.prefixes[k]; ok {
			c.unchanged++
		} else {
			c.added++
		}
	}
	for k := range w.prefixes {
		if _, ok := target.prefixes[k]; !ok {
			c.removed++
		}
	}

	for id, t := range target.silentPayments {
		if cur, ok := w.silentPayments[id]; ok && cur.sameWatch(&t) {
			c.unchanged++
		} else {
			c.added++
		}
	}
	for id := range w.silentPayments {
		if _, ok := target.silentPayments[id]; !ok {
			c.removed++
		}
	}

	return c
}

func anyFloored(scripts map[[32]byte]*uint64) bool {
	for _, f := range scripts {
		if f != nil {
			return true
		}
	}
	return false
}

func sameFloor(a, b *uint64) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}

func sortedOutpoints(m map[OutpointRef]struct{}) []OutpointRef {
	out := make([]OutpointRef, 0, len(m))
	for op := range m {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := compareBytes(out[i].Txid[:], out[j].Txid[:]); c != 0 {
			return c < 0
		}
		return out[i].Vout < out[j].Vout
	})
	return out
}

func sortedDescriptorKeys(m map[string]descriptorWindow) []string {
	out := make([]string, 0, len(m))
	for d := range m {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func sortedUint32Keys[V any](m map[uint32]V) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// alarmGroup is one txid's depth alarms, ready for a single AddTransactions.
type alarmGroup struct {
	txid   [32]byte
	depths []uint32
}

func groupAlarmsByTxid(m map[depthAlarm]struct{}) []alarmGroup {
	byTxid := map[[32]byte][]uint32{}
	for a := range m {
		byTxid[a.txid] = append(byTxid[a.txid], a.depth)
	}
	out := make([]alarmGroup, 0, len(byTxid))
	for t, depths := range byTxid {
		sort.Slice(depths, func(i, j int) bool { return depths[i] < depths[j] })
		out = append(out, alarmGroup{txid: t, depths: depths})
	}
	sort.Slice(out, func(i, j int) bool { return compareBytes(out[i].txid[:], out[j].txid[:]) < 0 })
	return out
}
