package satdevents

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

// kindsOf names each control message in order, which is what the replay
// assertions are really about: shape and sequence, not payload bytes.
func kindsOf(t *testing.T, msgs []*eventspb.SubscribeControl) []string {
	t.Helper()
	out := make([]string, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, reflect.TypeOf(m.Msg).Elem().Name())
	}
	return out
}

func mustControlMessages(t *testing.T, ws *WatchSet) []*eventspb.SubscribeControl {
	t.Helper()
	msgs, err := ws.controlMessages()
	if err != nil {
		t.Fatalf("controlMessages: %v", err)
	}
	return msgs
}

// TestControlMessagesReplayEveryKind: a reconnect replay must reconstruct the
// whole watch-set, with the filter and the raw-tx opt-in leading so they are in
// effect before any match flows.
func TestControlMessagesReplayEveryKind(t *testing.T) {
	floor := uint64(5000)
	ws := NewWatchSet().
		SetCategories(CategoryChain).
		SetWatchOptions(true).
		AddScripts(ScriptWatch{Scripthash: [32]byte{1}, MinValue: &floor}).
		AddOutpoints(OutpointRef{Txid: [32]byte{2}, Vout: 1}).
		AddTxLifecycle(AutoCloseAtDepth(6), [32]byte{3}).
		AddDepthAlarms([][32]byte{{4}}, []uint32{1, 3}).
		AddDescriptor("wpkh(xpub)", 20, 0).
		AddScriptPrefixes(ScriptPrefix{Prefix: []byte{0xab}, Bits: 8})

	got := kindsOf(t, mustControlMessages(t, ws))
	want := []string{
		"SubscribeControl_SetCategories",
		"SubscribeControl_SetWatchOptions",
		"SubscribeControl_AddScripts",
		"SubscribeControl_AddOutpoints",
		"SubscribeControl_AddTransactions", // lifecycle
		"SubscribeControl_AddTransactions", // depth alarms
		"SubscribeControl_AddDescriptor",
		"SubscribeControl_AddScriptPrefixes",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("replay = %v\nwant %v", got, want)
	}
}

// TestReplayDistinguishesLifecyclesFromDepthAlarms pins the one-message-two-
// meanings hazard: both are AddTransactions, and the server tells them apart
// ONLY by whether min_depths is empty. Getting this backwards on a replay would
// silently convert every lifecycle watch into a depth alarm.
func TestReplayDistinguishesLifecyclesFromDepthAlarms(t *testing.T) {
	ws := NewWatchSet().
		AddTxLifecycle(AutoCloseAtDepth(6), [32]byte{0xaa}).
		AddDepthAlarms([][32]byte{{0xbb}}, []uint32{2})

	var lifecycle, alarm *eventspb.AddTransactions
	for _, m := range mustControlMessages(t, ws) {
		at, ok := m.Msg.(*eventspb.SubscribeControl_AddTransactions)
		if !ok {
			continue
		}
		if len(at.AddTransactions.GetMinDepths()) == 0 {
			lifecycle = at.AddTransactions
		} else {
			alarm = at.AddTransactions
		}
	}
	if lifecycle == nil || alarm == nil {
		t.Fatal("the replay did not produce both an empty and a non-empty min_depths message")
	}
	if lifecycle.GetAutoCloseDepth() != 6 {
		t.Errorf("lifecycle auto_close_depth = %d, want 6", lifecycle.GetAutoCloseDepth())
	}
	if got := lifecycle.GetTxids(); len(got) != 1 || got[0][0] != 0xaa {
		t.Errorf("lifecycle carries the wrong txid: %x", got)
	}
	if got := alarm.GetMinDepths(); !reflect.DeepEqual(got, []uint32{2}) {
		t.Errorf("alarm min_depths = %v, want [2]", got)
	}
	if alarm.GetAutoCloseDepth() != 0 {
		t.Errorf("a depth alarm must not carry an auto-close depth, got %d", alarm.GetAutoCloseDepth())
	}
}

// TestReplayGroupsLifecyclesByDepthAndAlarmsByTxid: the grouping is what keeps a
// large watch-set from becoming one control message per item.
func TestReplayGroupsLifecyclesByDepthAndAlarmsByTxid(t *testing.T) {
	ws := NewWatchSet().
		AddTxLifecycle(AutoCloseAtDepth(6), [32]byte{1}, [32]byte{2}).
		AddTxLifecycle(AutoCloseNever, [32]byte{3}).
		AddDepthAlarms([][32]byte{{9}}, []uint32{1, 2, 3})

	var groups []*eventspb.AddTransactions
	for _, m := range mustControlMessages(t, ws) {
		if at, ok := m.Msg.(*eventspb.SubscribeControl_AddTransactions); ok {
			groups = append(groups, at.AddTransactions)
		}
	}
	// Two lifecycle depths + one alarm txid = 3 messages, not 6 items.
	if len(groups) != 3 {
		t.Fatalf("%d AddTransactions messages, want 3 (two lifecycle depths, one alarm txid)", len(groups))
	}
	for _, g := range groups {
		if len(g.GetMinDepths()) > 0 {
			if len(g.GetTxids()) != 1 || len(g.GetMinDepths()) != 3 {
				t.Errorf("alarms not grouped per txid: %d txids, %d depths",
					len(g.GetTxids()), len(g.GetMinDepths()))
			}
			continue
		}
		if g.GetAutoCloseDepth() == 6 && len(g.GetTxids()) != 2 {
			t.Errorf("depth-6 lifecycles not grouped: %d txids", len(g.GetTxids()))
		}
	}
}

// TestReplayMinValuesStayParallel: min_values is either empty or exactly as long
// as scripthashes. A ragged pair would misalign every floor.
func TestReplayMinValuesStayParallel(t *testing.T) {
	floor := uint64(1234)
	withFloor := NewWatchSet().AddScripts(
		ScriptWatch{Scripthash: [32]byte{1}, MinValue: &floor},
		ScriptWatch{Scripthash: [32]byte{2}}, // unfloored
	)
	msgs := mustControlMessages(t, withFloor)
	add := msgs[0].Msg.(*eventspb.SubscribeControl_AddScripts).AddScripts
	if len(add.GetMinValues()) != len(add.GetScripthashes()) {
		t.Fatalf("min_values has %d entries for %d scripthashes",
			len(add.GetMinValues()), len(add.GetScripthashes()))
	}
	// Sorted by scripthash, so {1} comes first and carries the floor.
	if add.GetMinValues()[0] != 1234 || add.GetMinValues()[1] != 0 {
		t.Errorf("floors landed on the wrong scripts: %v", add.GetMinValues())
	}

	none := NewWatchSet().AddScripts(ScriptWatch{Scripthash: [32]byte{1}})
	add = mustControlMessages(t, none)[0].Msg.(*eventspb.SubscribeControl_AddScripts).AddScripts
	if len(add.GetMinValues()) != 0 {
		t.Errorf("an unfloored set sent min_values %v, want empty", add.GetMinValues())
	}
}

// TestReplayIsDeterministic: the same set must render identically every time.
// Go randomizes map iteration, so without explicit sorting this would be a
// coin flip - and the parity harness diffs this output against the Rust SDK's.
func TestReplayIsDeterministic(t *testing.T) {
	build := func() *WatchSet {
		ws := NewWatchSet()
		for i := byte(0); i < 20; i++ {
			ws.AddScripts(ScriptWatch{Scripthash: [32]byte{i}})
			ws.AddOutpoints(OutpointRef{Txid: [32]byte{i}, Vout: uint32(i)})
			ws.AddDescriptor(string(rune('a'+i))+"desc", 20, 0)
			ws.AddDepthAlarms([][32]byte{{i}}, []uint32{1, 2})
		}
		return ws
	}
	first := mustControlMessages(t, build())
	for i := 0; i < 20; i++ {
		got := mustControlMessages(t, build())
		if len(got) != len(first) {
			t.Fatalf("run %d produced %d messages, first run produced %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].String() != first[j].String() {
				t.Fatalf("run %d message %d differs:\n got %s\nwant %s", i, j, got[j], first[j])
			}
		}
	}
}

func TestEmptyMirrorReplaysNothing(t *testing.T) {
	if msgs := mustControlMessages(t, NewWatchSet()); len(msgs) != 0 {
		t.Errorf("an empty mirror rendered %d message(s): %v", len(msgs), kindsOf(t, msgs))
	}
}

// TestRemovalsBalanceTheAdds: the mirror is a NET set, so a removal must leave
// nothing behind for the replay to re-register.
func TestRemovalsBalanceTheAdds(t *testing.T) {
	floor := uint64(1)
	sp := SilentPaymentTarget{ScanSecret: secretOf(0x07), SpendPubkey: generatorPubkey()}
	id, err := sp.Validate()
	if err != nil {
		t.Fatal(err)
	}

	ws := NewWatchSet().
		AddScripts(ScriptWatch{Scripthash: [32]byte{1}, MinValue: &floor}).
		AddOutpoints(OutpointRef{Txid: [32]byte{2}, Vout: 3}).
		AddTxLifecycle(AutoCloseAtDepth(6), [32]byte{4}).
		AddDepthAlarms([][32]byte{{5}}, []uint32{2}).
		AddDescriptor("wpkh(xpub)", 20, 0).
		AddScriptPrefixes(ScriptPrefix{Prefix: []byte{0xff}, Bits: 8})
	if err := ws.AddSilentPayments(sp); err != nil {
		t.Fatal(err)
	}
	if ws.Len() != 7 {
		t.Fatalf("Len = %d, want 7", ws.Len())
	}

	ws.removeScripts([32]byte{1})
	ws.removeOutpoints(OutpointRef{Txid: [32]byte{2}, Vout: 3})
	ws.removeTxLifecycle([32]byte{4})
	ws.removeDepthAlarms([][32]byte{{5}}, []uint32{2})
	ws.removeDescriptor("wpkh(xpub)")
	ws.removeScriptPrefixes(ScriptPrefix{Prefix: []byte{0xff}, Bits: 8})
	ws.removeSilentPayments(id)

	if ws.Len() != 0 {
		t.Errorf("Len = %d after removing everything", ws.Len())
	}
	if msgs := mustControlMessages(t, ws); len(msgs) != 0 {
		t.Errorf("a fully-drained mirror still replays %v", kindsOf(t, msgs))
	}
}

// TestRemoveDepthAlarmsOnlyDropsTheNamedPairs: alarms are keyed by (txid,
// depth), so removing one depth must not disarm the others on the same txid.
func TestRemoveDepthAlarmsOnlyDropsTheNamedPairs(t *testing.T) {
	ws := NewWatchSet().AddDepthAlarms([][32]byte{{1}, {2}}, []uint32{1, 6})
	if ws.Len() != 4 {
		t.Fatalf("Len = %d, want the 2x2 cross product", ws.Len())
	}
	ws.removeDepthAlarms([][32]byte{{1}}, []uint32{6})
	if ws.Len() != 3 {
		t.Fatalf("Len = %d after removing one pair, want 3", ws.Len())
	}
	if _, gone := ws.depthAlarms[depthAlarm{txid: [32]byte{1}, depth: 6}]; gone {
		t.Error("the named pair survived")
	}
	if _, ok := ws.depthAlarms[depthAlarm{txid: [32]byte{1}, depth: 1}]; !ok {
		t.Error("removing (tx1, 6) also disarmed (tx1, 1)")
	}
}

func TestReconcileCounts(t *testing.T) {
	floorA := uint64(100)
	floorB := uint64(200)

	current := NewWatchSet().
		AddScripts(
			ScriptWatch{Scripthash: [32]byte{1}},                    // survives unchanged
			ScriptWatch{Scripthash: [32]byte{2}, MinValue: &floorA}, // floor changes
			ScriptWatch{Scripthash: [32]byte{3}},                    // removed
		).
		AddDescriptor("keep", 20, 0).
		AddDescriptor("slide", 20, 0).
		AddOutpoints(OutpointRef{Txid: [32]byte{9}, Vout: 0})

	target := NewWatchSet().
		AddScripts(
			ScriptWatch{Scripthash: [32]byte{1}},
			ScriptWatch{Scripthash: [32]byte{2}, MinValue: &floorB},
			ScriptWatch{Scripthash: [32]byte{4}}, // new
		).
		AddDescriptor("keep", 20, 0).
		AddDescriptor("slide", 20, 40) // window slid
		// the outpoint is gone

	got := current.reconcileTo(target)
	want := reloadCounts{
		// added: script{2} (new floor), script{4} (new), descriptor "slide"
		added: 3,
		// removed: script{3}, the outpoint
		removed: 2,
		// unchanged: script{1}, descriptor "keep"
		unchanged: 2,
	}
	if got != want {
		t.Errorf("counts = %+v, want %+v", got, want)
	}
}

// TestReconcileTreatsAChangedFloorAsAdded: a re-asserted floor really does go
// back on the wire, so counting it as unchanged would under-report the churn.
func TestReconcileTreatsAChangedFloorAsAdded(t *testing.T) {
	a, b := uint64(1), uint64(2)
	cur := NewWatchSet().AddScripts(ScriptWatch{Scripthash: [32]byte{1}, MinValue: &a})
	same := NewWatchSet().AddScripts(ScriptWatch{Scripthash: [32]byte{1}, MinValue: &a})
	diff := NewWatchSet().AddScripts(ScriptWatch{Scripthash: [32]byte{1}, MinValue: &b})
	unfloored := NewWatchSet().AddScripts(ScriptWatch{Scripthash: [32]byte{1}})

	if got := cur.reconcileTo(same); got.unchanged != 1 || got.added != 0 {
		t.Errorf("identical floors counted as %+v", got)
	}
	if got := cur.reconcileTo(diff); got.added != 1 || got.unchanged != 0 {
		t.Errorf("a changed floor counted as %+v", got)
	}
	// Dropping a floor is also a real change: the server would keep the old one.
	if got := cur.reconcileTo(unfloored); got.added != 1 || got.unchanged != 0 {
		t.Errorf("a dropped floor counted as %+v", got)
	}
}

func TestCloneIsDeep(t *testing.T) {
	floor := uint64(5)
	ws := NewWatchSet().
		AddScripts(ScriptWatch{Scripthash: [32]byte{1}, MinValue: &floor}).
		AddScriptPrefixes(ScriptPrefix{Prefix: []byte{0xaa}, Bits: 8}).
		SetCategories(CategoryChain).
		SetWatchOptions(true)

	c := ws.clone()
	// Mutating the original must not reach the copy - the loader keeps a
	// reference to the set it was handed, so this is the property that stops an
	// integrator's later edit from corrupting the adopted mirror.
	ws.removeScripts([32]byte{1})
	ws.AddScripts(ScriptWatch{Scripthash: [32]byte{99}})
	ws.SetCategories(CategoryMempool)
	floor = 999

	if c.Len() != 2 {
		t.Errorf("clone Len = %d, want 2", c.Len())
	}
	if _, ok := c.scripts[[32]byte{1}]; !ok {
		t.Error("the clone lost a script the original removed")
	}
	if _, ok := c.scripts[[32]byte{99}]; ok {
		t.Error("the clone gained a script added to the original")
	}
	if f := c.scripts[[32]byte{1}]; f == nil || *f != 5 {
		t.Errorf("the clone's floor aliased the original's: %v", f)
	}
	if c.categories == nil || *c.categories != CategoryChain {
		t.Errorf("the clone's categories followed the original: %v", c.categories)
	}
}

// generatorPubkey is the secp256k1 generator in compressed form - a real curve
// point, so validation accepts it as a spend key.
func generatorPubkey() [33]byte {
	raw, err := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	if err != nil {
		panic(err)
	}
	var out [33]byte
	copy(out[:], raw)
	return out
}
