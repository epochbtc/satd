//go:build e2e

package e2e

import (
	"context"
	"testing"

	satdevents "github.com/epochbtc/satd/clients/go"
)

// matured boots a node with a spendable block-1 coinbase and returns it with
// that coinbase's display-order txid.
func matured(t *testing.T) (*node, string) {
	t.Helper()
	n := startNode(t)
	n.mine(101, walletA)
	return n, n.coinbaseTxid(1)
}

// watchStream opens a Watch stream that is torn down with the test.
func watchStream(t *testing.T, n *node) (context.Context, *satdevents.WatchHandle, *satdevents.Stream) {
	t.Helper()
	client := n.dial(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout(120))
	t.Cleanup(cancel)
	h, s, err := client.Watch(ctx)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return ctx, h, s
}

// TestWatchScriptsMatchesFundingBothSides proves the script watch end to end:
// the mempool match, then the confirmed re-emission, with the real value.
func TestWatchScriptsMatchesFundingBothSides(t *testing.T) {
	n, cb := matured(t)
	ctx, h, stream := watchStream(t, n)

	if err := h.AddScripts(ctx, []satdevents.ScriptWatch{
		{Scripthash: walletB.scripthash()},
	}); err != nil {
		t.Fatalf("add scripts: %v", err)
	}

	spendTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)

	mempool := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		m, ok := ev.(*satdevents.ScriptMatched)
		return ok && satdevents.DisplayHex(m.Txid) == spendTxid && !m.Confirmed
	}).(*satdevents.ScriptMatched)

	if !mempool.IsOutput {
		t.Error("expected the funding (output) side")
	}
	if got := satdevents.DisplayHexUnreversed(mempool.Scripthash); got !=
		satdevents.DisplayHexUnreversed(hashSlice(walletB.scripthash())) {
		t.Errorf("scripthash = %s, want the watched one", got)
	}
	// Amount is what lets a consumer skip an enrichment getrawtransaction; a nil
	// here would mean the SDK dropped the has_amount/amount pair.
	if mempool.Amount == nil {
		t.Fatal("funding match carried no amount")
	}
	if *mempool.Amount != 4999900000 {
		t.Errorf("amount = %d sat, want 49.999 BTC", *mempool.Amount)
	}
	// raw_tx is off by default - it is bandwidth-heavy and opt-in per stream.
	if mempool.RawTx != nil {
		t.Error("raw_tx arrived without the opt-in")
	}

	n.mine(1, walletC)
	confirmed := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		m, ok := ev.(*satdevents.ScriptMatched)
		return ok && satdevents.DisplayHex(m.Txid) == spendTxid && m.Confirmed
	}).(*satdevents.ScriptMatched)
	if confirmed.Amount == nil || *confirmed.Amount != 4999900000 {
		t.Errorf("confirmed amount = %v", confirmed.Amount)
	}
}

// TestWatchScriptsHonorsTheMinValueFloor: a floor above the payment must
// suppress the match. Without this the parallel min_values encoding could be
// wrong in either direction and every other script test would still pass.
func TestWatchScriptsHonorsTheMinValueFloor(t *testing.T) {
	n, cb := matured(t)
	ctx, h, stream := watchStream(t, n)

	// The spend below pays ~49.999 BTC; floor the watch above it.
	floor := uint64(5000000000)
	if err := h.AddScripts(ctx, []satdevents.ScriptWatch{
		{Scripthash: walletB.scripthash(), MinValue: &floor},
	}); err != nil {
		t.Fatalf("add scripts: %v", err)
	}
	// A second, unfloored watch on the change-free filler wallet gives the test
	// a positive control that the stream is live and past the spend.
	if err := h.AddScripts(ctx, []satdevents.ScriptWatch{
		{Scripthash: walletC.scripthash()},
	}); err != nil {
		t.Fatalf("add control script: %v", err)
	}

	spendTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)
	n.mine(1, walletC) // pays walletC, so the control watch fires

	// The coinbase paying walletC proves the stream reached this block.
	recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		m, ok := ev.(*satdevents.ScriptMatched)
		return ok && m.Confirmed && bytesEq(m.Scripthash, hashSlice(walletC.scripthash()))
	})

	// Anything already queued would have been delivered before that.
	for _, ev := range collect(t, stream, 4, 3) {
		if m, ok := ev.(*satdevents.ScriptMatched); ok &&
			satdevents.DisplayHex(m.Txid) == spendTxid &&
			bytesEq(m.Scripthash, hashSlice(walletB.scripthash())) {
			t.Errorf("a match below the min_value floor was delivered: %d sat", derefAmount(m.Amount))
		}
	}
}

// TestWatchOutpointsReportsTheSpend covers the outpoint watch: the spend of a
// specific coin, attributed to the spending input.
func TestWatchOutpointsReportsTheSpend(t *testing.T) {
	n, cb := matured(t)
	ctx, h, stream := watchStream(t, n)

	txid, err := satdevents.TxidFromDisplayHex(cb)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.AddOutpoints(ctx, []satdevents.OutpointRef{{Txid: txid, Vout: 0}}); err != nil {
		t.Fatalf("add outpoints: %v", err)
	}

	spendTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)

	spent := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		s, ok := ev.(*satdevents.OutpointSpent)
		return ok && satdevents.DisplayHex(s.SpendingTxid) == spendTxid
	}).(*satdevents.OutpointSpent)

	if satdevents.DisplayHex(spent.Outpoint.Txid) != cb || spent.Outpoint.Vout != 0 {
		t.Errorf("spent outpoint = %s:%d, want %s:0",
			satdevents.DisplayHex(spent.Outpoint.Txid), spent.Outpoint.Vout, cb)
	}
	if spent.SpendingVin != 0 {
		t.Errorf("spending vin = %d, want 0", spent.SpendingVin)
	}
	if spent.Confirmed {
		t.Error("the mempool spend should arrive unconfirmed first")
	}
}

// TestWatchTxLifecycleNarratesSeenThenConfirmed covers the lifecycle primitive
// (empty min_depths) and its auto-close terminal notice.
func TestWatchTxLifecycleNarratesSeenThenConfirmed(t *testing.T) {
	n, cb := matured(t)
	ctx, h, stream := watchStream(t, n)

	// The txid is known before broadcast: build and sign first, register, then
	// send. (n.spend does all three, so instead watch after broadcast and rely
	// on the confirmed leg - the mempool leg may already have passed.)
	spendTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)
	txid, err := satdevents.TxidFromDisplayHex(spendTxid)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.AddTxLifecycle(ctx, [][32]byte{txid}, satdevents.AutoCloseAtDepth(2)); err != nil {
		t.Fatalf("add lifecycle: %v", err)
	}

	height := n.blockCount() + 1
	n.mine(1, walletC)

	matched := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		m, ok := ev.(*satdevents.TxidMatched)
		return ok && satdevents.DisplayHex(m.Txid) == spendTxid && m.Confirmed
	}).(*satdevents.TxidMatched)
	if matched.Height != height {
		t.Errorf("confirmed height = %d, want %d", matched.Height, height)
	}

	// Two confirmations deep, the auto-close fires and the watch self-evicts.
	n.mine(1, walletC)
	final := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		f, ok := ev.(*satdevents.TxidFinalized)
		return ok && satdevents.DisplayHex(f.Txid) == spendTxid
	}).(*satdevents.TxidFinalized)
	if final.Depth < 2 {
		t.Errorf("finalized at depth %d, want >= the auto-close depth 2", final.Depth)
	}
	if final.Height != height {
		t.Errorf("finalized height = %d, want the confirming height %d", final.Height, height)
	}
}

// TestWatchDepthAlarmFires covers the other primitive on the same wire message:
// a non-empty min_depths registers a single-shot alarm, not a lifecycle watch.
func TestWatchDepthAlarmFires(t *testing.T) {
	n, cb := matured(t)
	ctx, h, stream := watchStream(t, n)

	spendTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)
	txid, err := satdevents.TxidFromDisplayHex(spendTxid)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.AddDepthAlarms(ctx, [][32]byte{txid}, []uint32{3}); err != nil {
		t.Fatalf("add depth alarm: %v", err)
	}

	height := n.blockCount() + 1
	n.mine(3, walletC)

	alarm := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		a, ok := ev.(*satdevents.TxidDepthReached)
		return ok && satdevents.DisplayHex(a.Txid) == spendTxid
	}).(*satdevents.TxidDepthReached)
	if alarm.Depth < 3 {
		t.Errorf("depth = %d, want >= the requested 3", alarm.Depth)
	}
	if alarm.Height != height {
		t.Errorf("height = %d, want the confirming height %d", alarm.Height, height)
	}
}

// TestWatchDescriptorAttributesTheMatch covers descriptor expansion AND the
// attribution a wallet needs: which descriptor, which branch, which index.
func TestWatchDescriptorAttributesTheMatch(t *testing.T) {
	n, cb := matured(t)
	ctx, h, stream := watchStream(t, n)

	// A fixed (non-ranged) descriptor over walletB's public key expands to
	// exactly walletB's P2WPKH script.
	descriptor := "wpkh(" + walletB.pubkey + ")"
	if err := h.AddDescriptor(ctx, descriptor, 1, 0); err != nil {
		t.Fatalf("add descriptor: %v", err)
	}

	spendTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)

	m := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		sm, ok := ev.(*satdevents.ScriptMatched)
		return ok && satdevents.DisplayHex(sm.Txid) == spendTxid
	}).(*satdevents.ScriptMatched)

	if len(m.Descriptors) != 1 {
		t.Fatalf("descriptor attribution = %v, want exactly one entry", m.Descriptors)
	}
	if m.Descriptors[0].Descriptor != descriptor {
		t.Errorf("attributed to %q, want %q", m.Descriptors[0].Descriptor, descriptor)
	}
	if m.Descriptors[0].Branch != 0 {
		t.Errorf("branch = %d, want 0 for a single-path descriptor", m.Descriptors[0].Branch)
	}
	if m.Descriptors[0].DerivationIndex != 0 {
		t.Errorf("derivation index = %d, want 0", m.Descriptors[0].DerivationIndex)
	}
}

// TestWatchOptionsIncludeRawTx: the opt-in must actually change what arrives.
func TestWatchOptionsIncludeRawTx(t *testing.T) {
	n, cb := matured(t)
	ctx, h, stream := watchStream(t, n)

	if err := h.SetWatchOptions(ctx, true); err != nil {
		t.Fatalf("set watch options: %v", err)
	}
	if err := h.AddScripts(ctx, []satdevents.ScriptWatch{
		{Scripthash: walletB.scripthash()},
	}); err != nil {
		t.Fatalf("add scripts: %v", err)
	}

	spendTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)
	m := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		sm, ok := ev.(*satdevents.ScriptMatched)
		return ok && satdevents.DisplayHex(sm.Txid) == spendTxid
	}).(*satdevents.ScriptMatched)

	if len(m.RawTx) == 0 {
		t.Fatal("include_raw_tx was set but no raw transaction arrived")
	}
	// The inlined bytes must be the real transaction, not a placeholder.
	var raw string
	n.mustCall("getrawtransaction", []any{spendTxid}, &raw)
	if got := satdevents.DisplayHexUnreversed(m.RawTx); got != raw {
		t.Errorf("inlined raw_tx does not match getrawtransaction:\n got %s\nwant %s", got, raw)
	}
}

// TestWatchSetReplacesAtomically covers the SetWatchSet primitive and its
// in-band deterministic result - the ack ResilientWatch.Reload drives off.
func TestWatchSetReplacesAtomically(t *testing.T) {
	n, cb := matured(t)
	ctx, h, stream := watchStream(t, n)

	txid, err := satdevents.TxidFromDisplayHex(cb)
	if err != nil {
		t.Fatal(err)
	}
	ws := satdevents.NewWatchSet().
		SetCategories(satdevents.CategoryChain).
		AddScripts(satdevents.ScriptWatch{Scripthash: walletB.scripthash()}).
		AddOutpoints(satdevents.OutpointRef{Txid: txid, Vout: 0})
	if err := h.SetWatchSet(ctx, ws); err != nil {
		t.Fatalf("set watch set: %v", err)
	}

	replaced := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.WatchSetReplaced)
		return ok
	}).(*satdevents.WatchSetReplaced)
	if replaced.Added != 2 {
		t.Errorf("added = %d, want the 2 entries in the snapshot", replaced.Added)
	}

	// The replaced set is live: the spend hits both the script and the outpoint.
	spendTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)
	recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		s, ok := ev.(*satdevents.OutpointSpent)
		return ok && satdevents.DisplayHex(s.SpendingTxid) == spendTxid
	})

	// Now replace with a set that drops both: the counts report the removal, and
	// nothing further matches.
	if err := h.SetWatchSet(ctx, satdevents.NewWatchSet().
		AddScripts(satdevents.ScriptWatch{Scripthash: walletC.scripthash()})); err != nil {
		t.Fatalf("second set watch set: %v", err)
	}
	second := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.WatchSetReplaced)
		return ok
	}).(*satdevents.WatchSetReplaced)
	if second.Removed != 2 || second.Added != 1 {
		t.Errorf("second replace: added %d removed %d, want 1 and 2",
			second.Added, second.Removed)
	}
}

// TestWatchSetInstallsSilentPaymentTargets is how the SP registration is
// verified without constructing a BIP 352 payment: SetWatchSet is the one
// control message with a deterministic ack, and its Added count includes the
// scan-key targets - so an accepted replace proves the server parsed and
// installed the target this SDK built.
func TestWatchSetInstallsSilentPaymentTargets(t *testing.T) {
	n := startNode(t)
	ctx, h, stream := watchStream(t, n)

	target := satdevents.SilentPaymentTarget{
		ScanSecret:  secretBytes(0x11),
		SpendPubkey: pubkeyBytes(t, walletB.pubkey),
		Labels:      []uint32{0},
	}
	ws := satdevents.NewWatchSet()
	if err := ws.AddSilentPayments(target); err != nil {
		t.Fatalf("declaring the target: %v", err)
	}
	if err := h.SetWatchSet(ctx, ws); err != nil {
		t.Fatalf("set watch set: %v", err)
	}

	ev := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		switch ev.(type) {
		case *satdevents.WatchSetReplaced, *satdevents.WatchSetRejected:
			return true
		}
		return false
	})
	switch r := ev.(type) {
	case *satdevents.WatchSetReplaced:
		if r.Added != 1 {
			t.Errorf("added = %d, want the one scan-key target", r.Added)
		}
	case *satdevents.WatchSetRejected:
		t.Fatalf("the server rejected the scan-key target: reason %s required %d quota %d",
			r.Reason, r.Required, r.Quota)
	}

	// The direct registration path must be accepted too (it has no ack, so this
	// asserts only that the SDK sends something the server does not kill the
	// stream over).
	if err := h.AddSilentPayments(ctx, []satdevents.SilentPaymentTarget{target}); err != nil {
		t.Fatalf("add silent payments: %v", err)
	}
	n.mine(1, walletC)
	recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.BlockConnected)
		return ok
	})
}

// TestWatchSetRejectionIsSurfaced: a malformed element must refuse the WHOLE
// snapshot in-band, leaving the prior set in effect, rather than silently
// shrinking the live watch-set.
func TestWatchSetRejectionIsSurfaced(t *testing.T) {
	n := startNode(t)
	ctx, h, stream := watchStream(t, n)

	// A descriptor the server cannot parse. The SDK does not validate descriptor
	// syntax (rust-miniscript is the authority), so this reaches the wire.
	ws := satdevents.NewWatchSet().AddDescriptor("this is not a descriptor", 5, 0)
	if err := h.SetWatchSet(ctx, ws); err != nil {
		t.Fatalf("set watch set: %v", err)
	}
	rejected := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.WatchSetRejected)
		return ok
	}).(*satdevents.WatchSetRejected)
	if rejected.Reason != satdevents.WatchSetRejectMalformed {
		t.Errorf("reason = %s, want malformed", rejected.Reason)
	}
	if rejected.Required != 0 || rejected.Quota != 0 {
		t.Errorf("a malformed rejection carries no counts, got %d/%d",
			rejected.Required, rejected.Quota)
	}
}

// TestSetCursorIsAckedInBand covers the deterministic re-anchor result the
// resilience layer is built on.
func TestSetCursorIsAckedInBand(t *testing.T) {
	n := startNode(t)
	ctx, h, stream := watchStream(t, n)

	if err := h.SetCategories(ctx, satdevents.CategoryChain); err != nil {
		t.Fatal(err)
	}
	first := mineUntilSeen(t, n, stream, walletC, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.BlockConnected)
		return ok
	}).(*satdevents.BlockConnected)
	anchor := stream.Cursor()
	if anchor == nil {
		t.Fatal("no cursor to re-anchor from")
	}

	mined := n.mine(2, walletC)
	if err := h.SetCursor(ctx, *anchor); err != nil {
		t.Fatalf("set cursor: %v", err)
	}

	accepted := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.CursorAccepted)
		return ok
	}).(*satdevents.CursorAccepted)
	if accepted.From == nil || accepted.From.Height != anchor.Height {
		t.Errorf("anchored to %+v, want height %d", accepted.From, anchor.Height)
	}
	if accepted.Clamped {
		t.Error("a fresh regtest chain cannot exceed the replay window")
	}
	if accepted.EarliestReplayed != first.Height+1 {
		t.Errorf("earliest replayed = %d, want %d", accepted.EarliestReplayed, first.Height+1)
	}

	// Replay follows the ack, in height order.
	for i, want := range mined {
		got := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
			b, ok := ev.(*satdevents.BlockConnected)
			return ok && b.Height > first.Height
		}).(*satdevents.BlockConnected)
		if satdevents.DisplayHex(got.Hash) != want {
			t.Fatalf("replayed block %d = %s, want %s", i, satdevents.DisplayHex(got.Hash), want)
		}
	}
}

// TestRescanIsBoundedAndTerminated covers the bounded historical rescan: the
// ack echoes the post-clamp range, matches follow, and a terminal marker closes
// it out.
func TestRescanIsBoundedAndTerminated(t *testing.T) {
	n, cb := matured(t)
	// Confirm a payment to walletB so there is something in history to find.
	spendTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)
	spendHeight := n.blockCount() + 1
	n.mine(1, walletC)

	ctx, h, stream := watchStream(t, n)
	if err := h.AddScripts(ctx, []satdevents.ScriptWatch{
		{Scripthash: walletB.scripthash()},
	}); err != nil {
		t.Fatal(err)
	}

	tip := n.blockCount()
	// Ask for more than exists, so the clamp is exercised too.
	if err := h.Rescan(ctx, 1, tip+1000); err != nil {
		t.Fatalf("rescan: %v", err)
	}

	accepted := recvMatching(t, stream, 60, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.RescanAccepted)
		return ok
	}).(*satdevents.RescanAccepted)
	if !accepted.Clamped {
		t.Error("a range past the tip must report clamped")
	}
	if accepted.ToHeight != tip {
		t.Errorf("clamped to %d, want the tip %d", accepted.ToHeight, tip)
	}

	match := recvMatching(t, stream, 60, func(ev satdevents.Event) bool {
		m, ok := ev.(*satdevents.ScriptMatched)
		return ok && satdevents.DisplayHex(m.Txid) == spendTxid
	}).(*satdevents.ScriptMatched)
	if !match.Confirmed {
		t.Error("a rescan delivers confirmed matches")
	}

	done := recvMatching(t, stream, 60, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.RescanComplete)
		return ok
	}).(*satdevents.RescanComplete)
	if done.ToHeight != tip || done.FromHeight != accepted.FromHeight {
		t.Errorf("complete range = [%d, %d], want [%d, %d]",
			done.FromHeight, done.ToHeight, accepted.FromHeight, tip)
	}
	if done.Matches == 0 {
		t.Error("the rescan found the payment but reported 0 matches")
	}
	_ = spendHeight
}

// TestRescanWithNoWatchSetIsRejected: the server refuses a rescan that could
// match nothing, and the SDK surfaces the typed reason.
func TestRescanWithNoWatchSetIsRejected(t *testing.T) {
	n := startNode(t)
	n.mine(3, walletC)
	ctx, h, stream := watchStream(t, n)

	if err := h.Rescan(ctx, 1, 2); err != nil {
		t.Fatalf("rescan: %v", err)
	}
	rejected := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.RescanRejected)
		return ok
	}).(*satdevents.RescanRejected)
	if rejected.Reason != satdevents.RescanRejectEmptyWatchSet {
		t.Errorf("reason = %s, want empty_watch_set", rejected.Reason)
	}
	if rejected.TipHeight == 0 {
		t.Error("the rejection should carry the server's tip so a client can re-scope")
	}
}

// ---- helpers ----------------------------------------------------------------

func hashSlice(h [32]byte) []byte { return h[:] }

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func derefAmount(a *uint64) uint64 {
	if a == nil {
		return 0
	}
	return *a
}

func secretBytes(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func pubkeyBytes(t *testing.T, hexKey string) [33]byte {
	t.Helper()
	var out [33]byte
	raw := mustHex(hexKey)
	if len(raw) != 33 {
		t.Fatalf("public key %s is %d bytes, want 33", hexKey, len(raw))
	}
	copy(out[:], raw)
	return out
}
