//go:build e2e

package e2e

import (
	"io"
	"testing"
	"time"

	satdevents "github.com/epochbtc/satd/clients/go"
)

// TestSubscribeDeliversBlockConnected is the smoke test for the whole path:
// Dial, Subscribe, and a typed event out of a real node over a real socket.
func TestSubscribeDeliversBlockConnected(t *testing.T) {
	n := startNode(t)
	client := n.dial(t)

	stream, err := client.Subscribe(ctxWithTimeout(t, 60),
		satdevents.SubscribeOptions{Categories: satdevents.CategoryChain})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	before := n.blockCount()
	hashes := n.mine(1, walletC)

	ev := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.BlockConnected)
		return ok
	}).(*satdevents.BlockConnected)

	if ev.Height != before+1 {
		t.Errorf("height = %d, want %d", ev.Height, before+1)
	}
	// The wire carries the hash in internal byte order; DisplayHex is what makes
	// it comparable against JSON-RPC. Getting this wrong is the single most
	// common integration bug against this API, so assert it directly.
	if got := satdevents.DisplayHex(ev.Hash); got != hashes[0] {
		t.Errorf("hash = %s, want the generatetoaddress hash %s", got, hashes[0])
	}
}

// TestSubscribeDeliversMempoolLifecycle proves the mempool category end to end:
// a broadcast produces MempoolEnter with real fee/vsize, and mining it produces
// MempoolLeaveConfirmed at the confirming height.
func TestSubscribeDeliversMempoolLifecycle(t *testing.T) {
	n := startNode(t)
	// 101 blocks so block 1's coinbase is mature and spendable.
	n.mine(101, walletA)
	cb := n.coinbaseTxid(1)

	client := n.dial(t)
	stream, err := client.Subscribe(ctxWithTimeout(t, 120),
		satdevents.SubscribeOptions{Categories: satdevents.CategoryMempool})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	spendTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)

	enter := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		e, ok := ev.(*satdevents.MempoolEnter)
		return ok && satdevents.DisplayHex(e.Txid) == spendTxid
	}).(*satdevents.MempoolEnter)

	if enter.Fee == 0 {
		t.Error("fee = 0, want the real fee the spend paid")
	}
	if enter.Vsize == 0 {
		t.Error("vsize = 0, want the real virtual size")
	}
	if enter.FeeRateSatPerKvB == 0 {
		t.Error("fee rate = 0, want sat/kvB")
	}
	if enter.Time == 0 {
		t.Error("admission time = 0")
	}

	height := n.blockCount() + 1
	blocks := n.mine(1, walletC)

	confirmed := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		e, ok := ev.(*satdevents.MempoolLeaveConfirmed)
		return ok && satdevents.DisplayHex(e.Txid) == spendTxid
	}).(*satdevents.MempoolLeaveConfirmed)

	if confirmed.Height != height {
		t.Errorf("confirmed height = %d, want %d", confirmed.Height, height)
	}
	if got := satdevents.DisplayHex(confirmed.BlockHash); got != blocks[0] {
		t.Errorf("confirming block = %s, want %s", got, blocks[0])
	}
}

// TestCategoryFilterExcludesOtherCategories: a chain-only subscription must not
// receive mempool bodies. Without this the category bitfield could be ignored
// entirely and every other test would still pass.
func TestCategoryFilterExcludesOtherCategories(t *testing.T) {
	n := startNode(t)
	n.mine(101, walletA)
	cb := n.coinbaseTxid(1)

	client := n.dial(t)
	stream, err := client.Subscribe(ctxWithTimeout(t, 120),
		satdevents.SubscribeOptions{Categories: satdevents.CategoryChain})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	spendTxid := n.spend(cb, 0, walletA, walletB, 49.999, 0xffffffff)
	n.mine(1, walletC)

	// The block connect proves the stream is live and past the broadcast, so a
	// mempool body would have arrived by now if the filter were ignored.
	events := collect(t, stream, 8, 8)
	sawBlock := false
	for _, ev := range events {
		switch e := ev.(type) {
		case *satdevents.BlockConnected:
			sawBlock = true
		case *satdevents.MempoolEnter:
			if satdevents.DisplayHex(e.Txid) == spendTxid {
				t.Errorf("a chain-only subscription received MempoolEnter for %s", spendTxid)
			}
		case *satdevents.MempoolLeaveConfirmed:
			t.Errorf("a chain-only subscription received MempoolLeaveConfirmed")
		}
	}
	if !sawBlock {
		t.Fatal("no BlockConnected arrived; the subscription was not live")
	}
}

// TestSubscribeCapturesTheDurableCursorAndResumes covers the replay contract
// that every resilient consumer rests on: the cursor a stream hands out really
// does resume history from that point on a fresh subscription.
func TestSubscribeCapturesTheDurableCursorAndResumes(t *testing.T) {
	n := startNode(t)
	client := n.dial(t)

	stream, err := client.Subscribe(ctxWithTimeout(t, 60),
		satdevents.SubscribeOptions{Categories: satdevents.CategoryChain})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	n.mine(1, walletC)
	first := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.BlockConnected)
		return ok
	}).(*satdevents.BlockConnected)

	cursor := stream.Cursor()
	if cursor == nil {
		t.Fatal("a confirmed event left no durable cursor")
	}
	if cursor.Height != first.Height {
		t.Errorf("cursor height = %d, want %d", cursor.Height, first.Height)
	}

	// Mine past the cursor with the stream closed, then resume from it: the
	// blocks mined in between must be replayed.
	mined := n.mine(3, walletC)

	resumed, err := client.Subscribe(ctxWithTimeout(t, 60), satdevents.SubscribeOptions{
		Categories: satdevents.CategoryChain,
		FromCursor: cursor,
	})
	if err != nil {
		t.Fatalf("resume subscribe: %v", err)
	}

	for i, want := range mined {
		got := recvMatching(t, resumed, 30, func(ev satdevents.Event) bool {
			_, ok := ev.(*satdevents.BlockConnected)
			return ok
		}).(*satdevents.BlockConnected)
		if h := satdevents.DisplayHex(got.Hash); h != want {
			t.Fatalf("replayed block %d = %s, want %s", i, h, want)
		}
		if got.Height != first.Height+uint32(i)+1 {
			t.Errorf("replayed height = %d, want %d", got.Height, first.Height+uint32(i)+1)
		}
	}
}

// TestHeartbeatsArriveOnlyWhenRequested pins the second half of the category
// contract - a bit that is not set must not deliver - and that a heartbeat
// carries a real uptime.
func TestHeartbeatsArriveOnlyWhenRequested(t *testing.T) {
	n := startNode(t) // the publisher heartbeats every 1s in every build
	client := n.dial(t)

	beats, err := client.Subscribe(ctxWithTimeout(t, 60),
		satdevents.SubscribeOptions{Categories: satdevents.CategoryHeartbeat})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	first := recvMatching(t, beats, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.Heartbeat)
		return ok
	}).(*satdevents.Heartbeat)
	second := recvMatching(t, beats, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.Heartbeat)
		return ok
	}).(*satdevents.Heartbeat)

	if first.UptimeNs == 0 {
		t.Error("uptime = 0; the heartbeat carries no payload")
	}
	// Uptime must advance between beats - a count alone would pass even if the
	// server sent the same frame twice.
	if second.UptimeNs <= first.UptimeNs {
		t.Errorf("uptime did not advance: %d then %d", first.UptimeNs, second.UptimeNs)
	}

	// A chain-only subscription must see none.
	chain, err := client.Subscribe(ctxWithTimeout(t, 30),
		satdevents.SubscribeOptions{Categories: satdevents.CategoryChain})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	for _, ev := range collect(t, chain, 3, 4) {
		if _, ok := ev.(*satdevents.Heartbeat); ok {
			t.Error("a chain-only subscription received a heartbeat")
		}
	}
}

// TestReorgIsReportedAsAFirstClassEvent: invalidateblock rolls the tip back, and
// the stream must narrate it - the Reorg marker plus the per-block disconnect -
// rather than leaving a consumer to infer it from a height going backwards.
func TestReorgIsReportedAsAFirstClassEvent(t *testing.T) {
	n := startNode(t)
	n.mine(3, walletC)

	client := n.dial(t)
	stream, err := client.Subscribe(ctxWithTimeout(t, 60),
		satdevents.SubscribeOptions{Categories: satdevents.CategoryChain})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	tipHeight := n.blockCount()
	var tipHash string
	n.mustCall("getblockhash", []any{int(tipHeight)}, &tipHash)
	n.mustCall("invalidateblock", []any{tipHash}, nil)

	disconnected := recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.BlockDisconnected)
		return ok
	}).(*satdevents.BlockDisconnected)

	if disconnected.Height != tipHeight {
		t.Errorf("disconnected height = %d, want the invalidated tip %d",
			disconnected.Height, tipHeight)
	}
	if got := satdevents.DisplayHex(disconnected.Hash); got != tipHash {
		t.Errorf("disconnected hash = %s, want %s", got, tipHash)
	}
}

// TestSubscribeSurfacesAServerClose: when the node goes away, Recv must report
// it rather than block forever. The resilience layer (PR 4) is built on exactly
// this signal.
func TestSubscribeSurfacesAServerClose(t *testing.T) {
	n := startNode(t)
	client := n.dial(t)
	stream, err := client.Subscribe(ctxWithTimeout(t, 60),
		satdevents.SubscribeOptions{Categories: satdevents.CategoryChain})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	n.mine(1, walletC)
	recvMatching(t, stream, 30, func(ev satdevents.Event) bool {
		_, ok := ev.(*satdevents.BlockConnected)
		return ok
	})

	n.kill()

	done := make(chan error, 1)
	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case err := <-done:
		if err == io.EOF {
			return // a clean close is a legitimate outcome
		}
		// Otherwise it must be a typed, retryable transport error - that is what
		// tells the resilience layer to reconnect rather than give up.
		if !satdevents.Retryable(err) {
			t.Errorf("a dead node produced %v, which is not retryable", err)
		}
	case <-time.After(timeout(30)):
		t.Fatal("Recv did not return after the node died")
	}
}
