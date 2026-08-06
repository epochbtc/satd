//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	satdevents "github.com/epochbtc/satd/clients/go"
)

// coinbaseSource hands out distinct mature walletA coinbases to spend from.
//
// Script matches come from spends, not from coinbase payouts, so every test
// here that needs to "pay" a watched script does it by spending one of these.
type coinbaseSource struct {
	n    *node
	next int
}

func newCoinbaseSource(t *testing.T, n *node) *coinbaseSource {
	t.Helper()
	// 140 blocks leaves ~40 mature coinbases, far more than any test here uses,
	// and every later block matures another.
	n.mine(140, walletA)
	return &coinbaseSource{n: n, next: 1}
}

// take returns the next unspent mature coinbase's display-order txid.
func (c *coinbaseSource) take(t *testing.T) string {
	t.Helper()
	txid := c.n.coinbaseTxid(c.next)
	c.next++
	return txid
}

// payTo spends a fresh coinbase to dest and confirms it, returning the txid.
func (c *coinbaseSource) payTo(t *testing.T, dest wallet) string {
	t.Helper()
	txid := c.n.spend(c.take(t), 0, walletA, dest, 49.999, 0xffffffff)
	c.n.mine(1, walletA)
	return txid
}

// awaitRW drives the watch until pred matches, ignoring everything else.
func awaitRW(t *testing.T, w *satdevents.ResilientWatch, secs float64,
	pred func(satdevents.Event) bool) satdevents.Event {
	t.Helper()
	deadline := time.Now().Add(timeout(secs))
	counts := map[string]int{}
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		ev, err := w.Next(ctx)
		cancel()
		if err != nil {
			t.Fatalf("resilient watch Next (saw %v): %v", counts, err)
		}
		if pred(ev) {
			return ev
		}
		counts[eventName(ev)]++
	}
	t.Fatalf("no matching event within %s; saw %v", timeout(secs), counts)
	return nil
}

func eventName(ev satdevents.Event) string {
	switch ev.(type) {
	case *satdevents.BlockConnected:
		return "BlockConnected"
	case *satdevents.ScriptMatched:
		return "ScriptMatched"
	case *satdevents.CursorAccepted:
		return "CursorAccepted"
	case *satdevents.WatchSetReplaced:
		return "WatchSetReplaced"
	case *satdevents.Heartbeat:
		return "Heartbeat"
	case *satdevents.TxidDepthReached:
		return "TxidDepthReached"
	default:
		return "other"
	}
}

// matchesWallet reports whether a ScriptMatched is for this wallet's script.
func matchesWallet(m *satdevents.ScriptMatched, w wallet) bool {
	sh := w.scripthash()
	return bytes.Equal(m.Scripthash, sh[:])
}

// primeRW gets the watch connected and its registration acknowledged in fact,
// by re-registering and paying the script until a match comes back.
//
// ResilientWatch connects on a background goroutine and Watch control messages
// have no per-message ack, so "register, then act" races the connect: a payment
// made in that window is simply not on the stream. Retrying with a fresh
// payment each round closes the window from the client side.
func primeRW(t *testing.T, src *coinbaseSource, w *satdevents.ResilientWatch, target wallet) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(timeout(90))
	for time.Now().Before(deadline) {
		if err := w.AddScripts(ctx, satdevents.ScriptWatch{Scripthash: target.scripthash()}); err != nil {
			t.Fatalf("add scripts: %v", err)
		}
		src.payTo(t, target)

		short, cancel := context.WithTimeout(context.Background(), timeout(5))
		for {
			ev, err := w.Next(short)
			if err != nil {
				break // deadline for this round; register and pay again
			}
			if m, ok := ev.(*satdevents.ScriptMatched); ok && matchesWallet(m, target) {
				cancel()
				return
			}
		}
		cancel()
	}
	t.Fatal("the watch never produced a match while priming")
}

// TestE2EResilientWatchReRegistersAcrossAReconnect is the contract end to end: a
// watch registered before the transport broke still matches after it comes back,
// with no caller involvement.
func TestE2EResilientWatchReRegistersAcrossAReconnect(t *testing.T) {
	n := startNode(t)
	src := newCoinbaseSource(t, n)
	proxy := startProxy(t, n.grpcTarget())
	client, err := satdevents.Dial(context.Background(), proxy.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	w := client.ResilientWatch(context.Background(), satdevents.ResilientWatchConfig{
		Backoff: satdevents.Backoff{
			Initial: 50 * time.Millisecond, Max: time.Second, Multiplier: 2,
		},
	})
	defer func() { _ = w.Close() }()

	primeRW(t, src, w, walletB)

	// Cut the transport. The watch-set now exists only client-side.
	proxy.cutAll()

	// Wait for the reconnect's re-anchor to be acknowledged before paying. A
	// payment that lands while the node is still draining the replay produces no
	// match - the cursor replay does not run the watch matcher (see the
	// ResilientWatch docs and TestE2EMissedMatchesNeedARescan below), so paying
	// first would be testing that gap rather than the re-registration.
	awaitRW(t, w, 60, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.CursorAccepted)
		return ok
	})

	// Pay the watched script. The reconnect must have re-registered it, or this
	// match never arrives.
	txid := src.payTo(t, walletB)

	match := awaitRW(t, w, 120, func(ev satdevents.Event) bool {
		m, ok := ev.(*satdevents.ScriptMatched)
		return ok && matchesWallet(m, walletB) && satdevents.DisplayHex(m.Txid) == txid
	}).(*satdevents.ScriptMatched)
	if !matchesWallet(match, walletB) {
		t.Errorf("matched the wrong script: %x", match.Scripthash)
	}
	if proxy.dialCount() < 2 {
		t.Errorf("the proxy saw %d connection(s); no reconnect happened", proxy.dialCount())
	}
}

// TestE2EWatchSetLoaderRebuildsFromTruthOnReconnect: the loader is the canonical
// source, so a watch added to the integrator's truth while the stream was down
// is live the moment it comes back - even though nothing in-process ever
// registered it.
func TestE2EWatchSetLoaderRebuildsFromTruthOnReconnect(t *testing.T) {
	n := startNode(t)
	src := newCoinbaseSource(t, n)
	proxy := startProxy(t, n.grpcTarget())
	client, err := satdevents.Dial(context.Background(), proxy.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	// The "durable truth": wallet B to start with.
	var mu sync.Mutex
	truth := []wallet{walletB}
	loads := 0

	w := client.ResilientWatch(context.Background(), satdevents.ResilientWatchConfig{
		Backoff: satdevents.Backoff{
			Initial: 50 * time.Millisecond, Max: time.Second, Multiplier: 2,
		},
		WatchSetLoader: func(_ context.Context, set *satdevents.WatchSet) error {
			mu.Lock()
			defer mu.Unlock()
			loads++
			for _, wal := range truth {
				set.AddScripts(satdevents.ScriptWatch{Scripthash: wal.scripthash()})
			}
			return nil
		},
	})
	defer func() { _ = w.Close() }()

	// Confirm the first load really is registered.
	deadline := time.Now().Add(timeout(90))
	registered := false
	for !registered && time.Now().Before(deadline) {
		txid := src.payTo(t, walletB)
		short, cancel := context.WithTimeout(context.Background(), timeout(5))
		for {
			ev, err := w.Next(short)
			if err != nil {
				break
			}
			if m, ok := ev.(*satdevents.ScriptMatched); ok && satdevents.DisplayHex(m.Txid) == txid {
				registered = true
				break
			}
		}
		cancel()
	}
	if !registered {
		t.Fatal("the loader's initial watch-set never matched")
	}

	// The truth gains wallet C while the stream is down. No in-process call
	// registers it - only the loader knows about it.
	mu.Lock()
	truth = append(truth, walletC)
	before := loads
	mu.Unlock()
	proxy.cutAll()

	awaitRW(t, w, 60, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.CursorAccepted)
		return ok
	})
	txid := src.payTo(t, walletC)
	awaitRW(t, w, 120, func(ev satdevents.Event) bool {
		m, ok := ev.(*satdevents.ScriptMatched)
		return ok && matchesWallet(m, walletC) && satdevents.DisplayHex(m.Txid) == txid
	})

	mu.Lock()
	after := loads
	mu.Unlock()
	if after <= before {
		t.Errorf("the loader ran %d times before the reconnect and %d after; "+
			"it must run on every connect", before, after)
	}
}

// TestE2EReloadAppliesTheNewTruthAtomically: an explicit reload swaps the whole
// watch-set on the live stream, and the node acknowledges it in band.
func TestE2EReloadAppliesTheNewTruthAtomically(t *testing.T) {
	n := startNode(t)
	src := newCoinbaseSource(t, n)
	client := n.dial(t)

	var mu sync.Mutex
	truth := []wallet{walletB}

	w := client.ResilientWatch(context.Background(), satdevents.ResilientWatchConfig{
		WatchSetLoader: func(_ context.Context, set *satdevents.WatchSet) error {
			mu.Lock()
			defer mu.Unlock()
			for _, wal := range truth {
				set.AddScripts(satdevents.ScriptWatch{Scripthash: wal.scripthash()})
			}
			return nil
		},
	})
	defer func() { _ = w.Close() }()

	// Confirm the first load is live before swapping it.
	deadline := time.Now().Add(timeout(90))
	registered := false
	for !registered && time.Now().Before(deadline) {
		txid := src.payTo(t, walletB)
		short, cancel := context.WithTimeout(context.Background(), timeout(5))
		for {
			ev, err := w.Next(short)
			if err != nil {
				break
			}
			if m, ok := ev.(*satdevents.ScriptMatched); ok && satdevents.DisplayHex(m.Txid) == txid {
				registered = true
				break
			}
		}
		cancel()
	}
	if !registered {
		t.Fatal("the loader's initial watch-set never matched")
	}

	// Swap the truth entirely: B out, C in.
	mu.Lock()
	truth = []wallet{walletC}
	mu.Unlock()

	summary, err := w.Reload(context.Background())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !summary.Applied {
		t.Fatal("the reload was not applied to the live stream")
	}
	if summary.Added != 1 || summary.Removed != 1 {
		t.Errorf("client-side summary = %+v, want one added and one removed", summary)
	}

	// The node's own counts are authoritative (by effective coverage), so they
	// are asserted separately from the advisory client-side ones.
	acc := awaitRW(t, w, 60, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.WatchSetReplaced)
		return ok
	}).(*satdevents.WatchSetReplaced)
	if acc.Added != 1 || acc.Removed != 1 {
		t.Errorf("the node reported %+v, want one added and one removed", acc)
	}

	// The new watch is live...
	txid := src.payTo(t, walletC)
	awaitRW(t, w, 60, func(ev satdevents.Event) bool {
		m, ok := ev.(*satdevents.ScriptMatched)
		return ok && satdevents.DisplayHex(m.Txid) == txid
	})

	// ...and the old one is genuinely gone, not merely unmentioned: a payment to
	// B must produce nothing.
	dropped := src.payTo(t, walletB)
	ctx, cancel := context.WithTimeout(context.Background(), timeout(15))
	defer cancel()
	for {
		ev, err := w.Next(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return // the replaced watch stayed replaced
			}
			t.Fatalf("Next: %v", err)
		}
		if m, ok := ev.(*satdevents.ScriptMatched); ok && satdevents.DisplayHex(m.Txid) == dropped {
			t.Fatal("the reload left the old watch registered")
		}
	}
}

// TestE2EResilientWatchResumesAcrossARestart: the cursor is persisted, so a
// consumer that dies and comes back against a restarted node gets the matches it
// missed rather than starting forward-only.
func TestE2EResilientWatchResumesAcrossARestart(t *testing.T) {
	n := startNode(t)
	src := newCoinbaseSource(t, n)
	cursorPath := t.TempDir() + "/cursor"

	newWatch := func(client *satdevents.Client) *satdevents.ResilientWatch {
		return client.ResilientWatch(context.Background(), satdevents.ResilientWatchConfig{
			CursorStore: satdevents.NewFileCursorStore(cursorPath),
			WatchSetLoader: func(_ context.Context, set *satdevents.WatchSet) error {
				set.AddScripts(satdevents.ScriptWatch{Scripthash: walletB.scripthash()})
				return nil
			},
		})
	}

	client := n.dial(t)
	w := newWatch(client)

	// Establish a confirmed match, so the resume anchor is real.
	deadline := time.Now().Add(timeout(90))
	registered := false
	for !registered && time.Now().Before(deadline) {
		txid := src.payTo(t, walletB)
		short, cancel := context.WithTimeout(context.Background(), timeout(5))
		for {
			ev, err := w.Next(short)
			if err != nil {
				break
			}
			if m, ok := ev.(*satdevents.ScriptMatched); ok &&
				satdevents.DisplayHex(m.Txid) == txid && m.Confirmed {
				registered = true
				break
			}
		}
		cancel()
	}
	if !registered {
		t.Fatal("no confirmed match before the restart")
	}
	if err := w.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	anchor := w.ResumeCursor()
	if anchor == nil {
		t.Fatal("no resume cursor was established")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// Three payments to the watched script land while the consumer is down.
	gapFrom := n.blockCount() + 1
	missed := map[string]bool{}
	for i := 0; i < 3; i++ {
		missed[src.payTo(t, walletB)] = true
	}
	gapTo := n.blockCount()
	n.restart()

	client2 := n.dial(t)
	w2 := newWatch(client2)
	defer func() { _ = w2.Close() }()

	// The reconnect re-anchors the cursor, so the chain stream is continuous -
	// but it does NOT replay watch matches, which is what Rescan is for. Wait
	// until the resumed stream is caught up, then rescan the gap.
	awaitRW(t, w2, 120, func(ev satdevents.Event) bool {
		b, ok := ev.(*satdevents.BlockConnected)
		return ok && b.Height >= gapTo
	})
	if err := w2.Rescan(context.Background(), gapFrom, gapTo); err != nil {
		t.Fatalf("rescan: %v", err)
	}

	// Every payment made during the downtime has to come back.
	seen := map[string]bool{}
	deadline = time.Now().Add(timeout(120))
	for len(seen) < len(missed) && time.Now().Before(deadline) {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		ev, err := w2.Next(ctx)
		cancel()
		if err != nil {
			t.Fatalf("Next after the rescan (saw %d of %d missed matches): %v",
				len(seen), len(missed), err)
		}
		switch e := ev.(type) {
		case *satdevents.ScriptMatched:
			if id := satdevents.DisplayHex(e.Txid); missed[id] {
				seen[id] = true
			}
		case *satdevents.RescanRejected:
			t.Fatalf("the gap rescan was rejected: %s", e.Reason)
		}
	}
	if len(seen) < len(missed) {
		t.Errorf("the rescan over %d..%d recovered %d of the %d matches missed "+
			"while down (anchor %+v)", gapFrom, gapTo, len(seen), len(missed), anchor)
	}
}

// TestE2EMissedMatchesNeedARescan pins the boundary the ResilientWatch docs draw:
// a reconnect re-anchors the CHAIN stream but does not replay watch MATCHES, so
// a confirmed payment made while the stream was down is not delivered on its own.
//
// This is deliberate node behavior - the cursor replay synthesizes events from
// the block index and never runs the watch matcher - and a consumer that assumed
// otherwise would silently miss payments. Asserting it here means the day it
// changes, the docs get updated with it.
func TestE2EMissedMatchesNeedARescan(t *testing.T) {
	n := startNode(t)
	src := newCoinbaseSource(t, n)
	proxy := startProxy(t, n.grpcTarget())
	client, err := satdevents.Dial(context.Background(), proxy.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	// A long backoff keeps the consumer down while the payment confirms.
	w := client.ResilientWatch(context.Background(), satdevents.ResilientWatchConfig{
		Backoff: satdevents.Backoff{
			Initial: 5 * time.Second, Max: 5 * time.Second, Multiplier: 1,
		},
	})
	defer func() { _ = w.Close() }()

	primeRW(t, src, w, walletB)

	proxy.cutAll()
	gapFrom := n.blockCount() + 1
	missedTxid := src.payTo(t, walletB)
	gapTo := n.blockCount()

	// Let the reconnect happen and settle.
	awaitRW(t, w, 120, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.CursorAccepted)
		return ok
	})

	// The missed match does not arrive by itself.
	ctx, cancel := context.WithTimeout(context.Background(), timeout(20))
	for {
		ev, err := w.Next(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				break // as documented
			}
			cancel()
			t.Fatalf("Next: %v", err)
		}
		if m, ok := ev.(*satdevents.ScriptMatched); ok && satdevents.DisplayHex(m.Txid) == missedTxid {
			cancel()
			t.Fatal("the reconnect replayed a watch match - the docs saying it does " +
				"not are now wrong, and the Rescan guidance is unnecessary")
		}
	}
	cancel()

	// A rescan over the gap recovers it, which is the documented remedy.
	if err := w.Rescan(context.Background(), gapFrom, gapTo); err != nil {
		t.Fatalf("rescan: %v", err)
	}
	awaitRW(t, w, 60, func(ev satdevents.Event) bool {
		m, ok := ev.(*satdevents.ScriptMatched)
		return ok && satdevents.DisplayHex(m.Txid) == missedTxid
	})
}

// TestE2EFiredDepthAlarmIsNotReArmed: the node self-evicts a fired one-shot
// alarm. Re-registering it on reconnect would duplicate the terminal notice and
// burn watch quota on a completed txid.
func TestE2EFiredDepthAlarmIsNotReArmed(t *testing.T) {
	n := startNode(t)
	src := newCoinbaseSource(t, n)
	proxy := startProxy(t, n.grpcTarget())
	client, err := satdevents.Dial(context.Background(), proxy.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	w := client.ResilientWatch(context.Background(), satdevents.ResilientWatchConfig{
		Backoff: satdevents.Backoff{
			Initial: 50 * time.Millisecond, Max: time.Second, Multiplier: 2,
		},
	})
	defer func() { _ = w.Close() }()

	primeRW(t, src, w, walletB)

	// Arm an alarm on a fresh transaction. Priming proved the stream is live, so
	// this registration does not race the connect.
	txid := n.spend(src.take(t), 0, walletA, walletB, 49.999, 0xffffffff)
	raw, err := satdevents.TxidFromDisplayHex(txid)
	if err != nil {
		t.Fatalf("parsing txid: %v", err)
	}
	if err := w.AddDepthAlarms(context.Background(), [][32]byte{raw}, []uint32{1}); err != nil {
		t.Fatalf("arming: %v", err)
	}
	before := w.WatchSetLen()
	n.mine(2, walletA)

	awaitRW(t, w, 60, func(ev satdevents.Event) bool {
		d, ok := ev.(*satdevents.TxidDepthReached)
		return ok && satdevents.DisplayHex(d.Txid) == txid
	})

	// The fired alarm is pruned from the mirror.
	deadline := time.Now().Add(timeout(45))
	for w.WatchSetLen() >= before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := w.WatchSetLen(); got >= before {
		t.Fatalf("watch-set still holds %d items (was %d); the fired alarm was not pruned",
			got, before)
	}

	// After a reconnect it must not fire a second time.
	proxy.cutAll()
	n.mine(3, walletA)

	ctx, cancel := context.WithTimeout(context.Background(), timeout(20))
	defer cancel()
	for {
		ev, err := w.Next(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return // nothing re-fired, which is the contract
			}
			t.Fatalf("Next: %v", err)
		}
		if d, ok := ev.(*satdevents.TxidDepthReached); ok && satdevents.DisplayHex(d.Txid) == txid {
			t.Fatal("the fired alarm was re-armed on reconnect and fired again")
		}
	}
}
