//go:build e2e

package e2e

import (
	"bytes"
	"testing"

	satdevents "github.com/epochbtc/satd/clients/go"
)

// TestE2EPrefixWatchRoundTrip is the whole prefix-privacy loop against a real
// node: register a bucket derived from a script the node is never told, receive
// the coarse deliveries, and re-filter them locally back down to the true match.
func TestE2EPrefixWatchRoundTrip(t *testing.T) {
	n, cb := matured(t)
	ctx, h, stream := watchStream(t, n)

	// The node only ever learns the bucket. It is never sent walletB's script.
	watcher := satdevents.NewPrefixWatcherWithScripts(walletB.spk)
	prefixes := watcher.Prefixes(16)
	if len(prefixes) != 1 {
		t.Fatalf("one script produced %d buckets", len(prefixes))
	}
	if err := h.AddScriptPrefixes(ctx, prefixes); err != nil {
		t.Fatalf("add prefixes: %v", err)
	}

	// A prefix delivery carries the full transaction inline, so the SDK can
	// filter locally without a precise follow-up fetch that would re-leak the
	// script.
	spendTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)
	n.mine(1, walletA)

	match := recvMatching(t, stream, 60, func(ev satdevents.Event) bool {
		m, ok := ev.(*satdevents.PrefixMatched)
		if !ok {
			return false
		}
		hits, err := watcher.Filter(m)
		return err == nil && satdevents.DisplayHex(hits.Txid[:]) == spendTxid
	}).(*satdevents.PrefixMatched)

	// The delivered bucket must be the one registered, not the exact script.
	if !bytes.Equal(match.Prefix.Prefix, prefixes[0].Prefix) || match.Prefix.Bits != 16 {
		t.Errorf("delivered bucket = %x/%d, want %x/16",
			match.Prefix.Prefix, match.Prefix.Bits, prefixes[0].Prefix)
	}

	hits, err := watcher.Filter(match)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if !hits.IsMatch() {
		t.Fatal("the local re-filter found no match in a delivery for our own script")
	}
	if len(hits.Funding) != 1 {
		t.Fatalf("%d funding hit(s), want 1", len(hits.Funding))
	}
	f := hits.Funding[0]
	if f.Scripthash != walletB.scripthash() {
		t.Errorf("matched scripthash = %x, want wallet B's", f.Scripthash)
	}
	if !bytes.Equal(f.ScriptPubKey, walletB.spk) {
		t.Errorf("matched scriptPubKey = %x, want %x", f.ScriptPubKey, walletB.spk)
	}
	if f.Value != 4999900000 {
		t.Errorf("value = %d sat, want 49.999 BTC", f.Value)
	}
	// The txid the SDK recomputed from the raw bytes must be the node's own.
	if got := satdevents.DisplayHex(hits.Txid[:]); got != spendTxid {
		t.Errorf("recomputed txid = %s, want %s", got, spendTxid)
	}
}

// TestE2EPrefixDeliveriesIncludeDecoys is the privacy property in practice: a
// bucket delivers transactions that are not ours, and only the local filter
// tells them apart.
//
// The decoy is made deterministic by registering the bucket that covers wallet
// C's script while the local watcher holds only wallet B's. That is exactly what
// a shared bucket looks like from the node's side - it cannot tell which script
// in the bucket we actually care about - without depending on two scripts
// happening to collide.
func TestE2EPrefixDeliveriesIncludeDecoys(t *testing.T) {
	n, cb := matured(t)
	ctx, h, stream := watchStream(t, n)

	watcher := satdevents.NewPrefixWatcherWithScripts(walletB.spk)
	decoyBucket := satdevents.PrefixOf(walletC.spk, 16)
	if err := h.AddScriptPrefixes(ctx, []satdevents.ScriptPrefix{decoyBucket}); err != nil {
		t.Fatalf("add prefixes: %v", err)
	}

	// Pay wallet C: guaranteed to land in the registered bucket, and guaranteed
	// not to be ours.
	decoyTxid := n.spend(cb, 0, walletA, walletC, 49.999, 0xffffffff)
	n.mine(1, walletA)

	match := recvMatching(t, stream, 60, func(ev satdevents.Event) bool {
		m, ok := ev.(*satdevents.PrefixMatched)
		if !ok {
			return false
		}
		hits, err := watcher.Filter(m)
		return err == nil && satdevents.DisplayHex(hits.Txid[:]) == decoyTxid
	}).(*satdevents.PrefixMatched)

	hits, err := watcher.Filter(match)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	// Delivered because it shares the registered bucket - but it pays wallet C,
	// so the local filter must report no match. Reporting one would mean the SDK
	// trusts the bucket instead of the script, which defeats the entire feature.
	if hits.IsMatch() {
		t.Fatalf("a payment to another wallet was reported as our match: %+v", hits.Funding)
	}
	if hits.HasUnresolved() {
		t.Errorf("a confirmed funding-only delivery reported unresolved prevouts: %v",
			hits.Unresolved)
	}
	// The node was told the bucket, and the delivery echoes only that.
	if !bytes.Equal(match.Prefix.Prefix, decoyBucket.Prefix) {
		t.Errorf("delivered bucket = %x, want the registered %x",
			match.Prefix.Prefix, decoyBucket.Prefix)
	}
}

// TestE2EPrefixMatchesTheSpendSide: the bucket fires on a spent prevout's script
// too, and the filter must attribute it to the right input.
func TestE2EPrefixMatchesTheSpendSide(t *testing.T) {
	n, cb := matured(t)

	// Fund wallet B first, so there is a wallet-B coin to spend later.
	fundTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)
	n.mine(1, walletA)

	ctx, h, stream := watchStream(t, n)
	watcher := satdevents.NewPrefixWatcherWithScripts(walletB.spk)
	if err := h.AddScriptPrefixes(ctx, watcher.Prefixes(16)); err != nil {
		t.Fatalf("add prefixes: %v", err)
	}

	// Now spend wallet B's coin away. The prevout's script is wallet B's, so the
	// bucket fires on the spend side.
	spendTxid := n.spend(fundTxid, 0, walletB, walletC, 49.998, 0xffffffff)
	n.mine(1, walletA)

	match := recvMatching(t, stream, 60, func(ev satdevents.Event) bool {
		m, ok := ev.(*satdevents.PrefixMatched)
		if !ok {
			return false
		}
		hits, err := watcher.Filter(m)
		return err == nil && satdevents.DisplayHex(hits.Txid[:]) == spendTxid && len(hits.Spending) > 0
	}).(*satdevents.PrefixMatched)

	hits, err := watcher.Filter(match)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if len(hits.Spending) != 1 {
		t.Fatalf("%d spending hit(s), want 1 (unresolved: %d)",
			len(hits.Spending), len(hits.Unresolved))
	}
	s := hits.Spending[0]
	if s.Scripthash != walletB.scripthash() {
		t.Errorf("spending scripthash = %x, want wallet B's", s.Scripthash)
	}
	if s.Vin == nil {
		t.Fatal("the spending input was not located in the delivered transaction")
	}
	if *s.Vin != 0 {
		t.Errorf("vin = %d, want 0", *s.Vin)
	}
	if got := satdevents.DisplayHex(s.Outpoint.Txid); got != fundTxid {
		t.Errorf("spent outpoint txid = %s, want the funding tx %s", got, fundTxid)
	}
	if s.Amount == nil || *s.Amount != 4999900000 {
		t.Errorf("spent amount = %v, want 49.999 BTC", s.Amount)
	}
}
