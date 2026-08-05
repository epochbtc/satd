package satdevents

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

// watchLeg is one server-side Watch connection: it records every control message
// the client sends and can push events back. `controls` is closed when the
// client's send side goes away.
type watchLeg struct {
	mu       sync.Mutex
	received []*eventspb.SubscribeControl
	ready    chan struct{}
	closed   bool
}

func (l *watchLeg) record(msg *eventspb.SubscribeControl) {
	l.mu.Lock()
	l.received = append(l.received, msg)
	l.mu.Unlock()
}

func (l *watchLeg) controls() []*eventspb.SubscribeControl {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*eventspb.SubscribeControl(nil), l.received...)
}

// scriptedWatch answers each Watch with the next leg of a script.
type scriptedWatch struct {
	eventspb.UnimplementedNodeEventStreamServer

	mu    sync.Mutex
	legs  []func(l *watchLeg, srv eventspb.NodeEventStream_WatchServer) error
	seen  []*watchLeg
	calls int
}

func (s *scriptedWatch) Watch(srv eventspb.NodeEventStream_WatchServer) error {
	leg := &watchLeg{ready: make(chan struct{})}
	s.mu.Lock()
	s.seen = append(s.seen, leg)
	i := s.calls
	s.calls++
	var run func(*watchLeg, eventspb.NodeEventStream_WatchServer) error
	if i < len(s.legs) {
		run = s.legs[i]
	}
	s.mu.Unlock()

	// Recv on its own goroutine so a leg can push events while controls arrive.
	go func() {
		for {
			msg, err := srv.Recv()
			if err != nil {
				leg.mu.Lock()
				leg.closed = true
				leg.mu.Unlock()
				return
			}
			leg.record(msg)
		}
	}()

	if run != nil {
		return run(leg, srv)
	}
	<-srv.Context().Done()
	return nil
}

func (s *scriptedWatch) leg(i int) *watchLeg {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i >= len(s.seen) {
		return nil
	}
	return s.seen[i]
}

func (s *scriptedWatch) legCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func startScriptedWatch(t *testing.T, legs ...func(*watchLeg, eventspb.NodeEventStream_WatchServer) error) (*Client, *scriptedWatch) {
	t.Helper()
	srv := &scriptedWatch{legs: legs}
	return startServer(t, srv), srv
}

// parkLeg keeps a connection open until the client goes away.
func parkLeg(_ *watchLeg, srv eventspb.NodeEventStream_WatchServer) error {
	<-srv.Context().Done()
	return nil
}

// waitLegControls blocks until leg i has recorded n controls.
func waitLegControls(t *testing.T, s *scriptedWatch, i, n int) []*eventspb.SubscribeControl {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if leg := s.leg(i); leg != nil {
			if got := leg.controls(); len(got) >= n {
				return got
			}
		}
		time.Sleep(time.Millisecond)
	}
	var got int
	if leg := s.leg(i); leg != nil {
		got = len(leg.controls())
	}
	t.Fatalf("leg %d recorded %d of %d control messages", i, got, n)
	return nil
}

func controlKinds(msgs []*eventspb.SubscribeControl) []string {
	out := make([]string, 0, len(msgs))
	for _, m := range msgs {
		switch m.Msg.(type) {
		case *eventspb.SubscribeControl_SetCategories:
			out = append(out, "SetCategories")
		case *eventspb.SubscribeControl_SetWatchOptions:
			out = append(out, "SetWatchOptions")
		case *eventspb.SubscribeControl_AddScripts:
			out = append(out, "AddScripts")
		case *eventspb.SubscribeControl_RemoveScripts:
			out = append(out, "RemoveScripts")
		case *eventspb.SubscribeControl_AddOutpoints:
			out = append(out, "AddOutpoints")
		case *eventspb.SubscribeControl_AddTransactions:
			out = append(out, "AddTransactions")
		case *eventspb.SubscribeControl_AddDescriptor:
			out = append(out, "AddDescriptor")
		case *eventspb.SubscribeControl_AddScriptPrefixes:
			out = append(out, "AddScriptPrefixes")
		case *eventspb.SubscribeControl_AddSilentPayments:
			out = append(out, "AddSilentPayments")
		case *eventspb.SubscribeControl_SetCursor:
			out = append(out, "SetCursor")
		case *eventspb.SubscribeControl_SetWatchSet:
			out = append(out, "SetWatchSet")
		case *eventspb.SubscribeControl_RescanBlocks:
			out = append(out, "RescanBlocks")
		default:
			out = append(out, "other")
		}
	}
	return out
}

// waitLive blocks until the wrapper has actually connected, by driving a control
// that reaches the server and touches no resilient state.
//
// ResilientWatch connects on a background goroutine, so an edit made before then
// lands in the mirror only and is not observable server-side until the replay -
// a test that assumes its first edit went live is racing the connect. Rescan is
// the right probe: unlike every Add*/Set*, it leaves the mirror alone, so the
// replay assertions stay clean. It returns the number of controls to skip.
func waitLive(t *testing.T, w *ResilientWatch, s *scriptedWatch, leg int) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if l := s.leg(leg); l != nil {
			if n := len(l.controls()); n > 0 {
				return n
			}
		}
		_ = w.Rescan(context.Background(), 0, 0)
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the watch never connected to leg %d", leg)
	return 0
}

func nextWatch(t *testing.T, w *ResilientWatch) Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev, err := w.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return ev
}

// TestResilientWatchReRegistersTheWatchSetOnReconnect is the whole point of the
// wrapper: the second connection must be handed the same watch-set the caller
// registered on the first, without the caller doing anything.
func TestResilientWatchReRegistersTheWatchSetOnReconnect(t *testing.T) {
	client, srv := startScriptedWatch(t,
		func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
			// Let the caller register, then drop the connection.
			time.Sleep(150 * time.Millisecond)
			return nil
		},
		parkLeg,
	)
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		Backoff: Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond, Multiplier: 2},
	})
	defer func() { _ = w.Close() }()

	ctx := context.Background()
	floor := uint64(5000)
	if err := w.SetCategories(ctx, CategoryChain); err != nil {
		t.Fatal(err)
	}
	if err := w.AddScripts(ctx, ScriptWatch{Scripthash: [32]byte{1}, MinValue: &floor}); err != nil {
		t.Fatal(err)
	}
	if err := w.AddTxLifecycle(ctx, AutoCloseAtDepth(6), [32]byte{2}); err != nil {
		t.Fatal(err)
	}
	waitLegControls(t, srv, 0, 3)

	// The second leg gets the whole set replayed, in the canonical order, with no
	// further caller action.
	got := controlKinds(waitLegControls(t, srv, 1, 3))
	want := []string{"SetCategories", "AddScripts", "AddTransactions"}
	if len(got) < len(want) {
		t.Fatalf("replay = %v, want at least %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("replay = %v, want %v", got, want)
		}
	}
}

// TestResilientWatchRemovalsDoNotReplay: an item removed while connected must
// not come back on the next connection.
func TestResilientWatchRemovalsDoNotReplay(t *testing.T) {
	client, srv := startScriptedWatch(t,
		func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
			time.Sleep(150 * time.Millisecond)
			return nil
		},
		parkLeg,
	)
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		Backoff: Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond, Multiplier: 2},
	})
	defer func() { _ = w.Close() }()

	ctx := context.Background()
	skip := waitLive(t, w, srv, 0)
	if err := w.AddScripts(ctx, ScriptWatch{Scripthash: [32]byte{1}}, ScriptWatch{Scripthash: [32]byte{2}}); err != nil {
		t.Fatal(err)
	}
	if err := w.RemoveScripts(ctx, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if got := controlKinds(waitLegControls(t, srv, 0, skip+2))[skip:]; got[0] != "AddScripts" || got[1] != "RemoveScripts" {
		t.Fatalf("live edits went out as %v", got)
	}

	replay := waitLegControls(t, srv, 1, 1)
	add, ok := replay[0].Msg.(*eventspb.SubscribeControl_AddScripts)
	if !ok {
		t.Fatalf("first replayed message is %v, want AddScripts", controlKinds(replay))
	}
	if n := len(add.AddScripts.GetScripthashes()); n != 1 {
		t.Fatalf("replayed %d scripts, want only the surviving one", n)
	}
	if add.AddScripts.GetScripthashes()[0][0] != 2 {
		t.Errorf("the removed script came back: %x", add.AddScripts.GetScripthashes()[0])
	}
}

// TestEditsWhileDisconnectedLandOnTheNextConnection: the wrapper is not a
// pass-through - an edit made while the stream is down must not be lost, and
// must not error at the caller either.
func TestEditsWhileDisconnectedLandOnTheNextConnection(t *testing.T) {
	release := make(chan struct{})
	client, srv := startScriptedWatch(t,
		func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
			return nil // dies immediately
		},
		func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
			<-release
			<-s.Context().Done()
			return nil
		},
	)
	// A long backoff keeps the wrapper disconnected while the edit is made.
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		Backoff: Backoff{Initial: 300 * time.Millisecond, Max: time.Second, Multiplier: 2},
	})
	defer func() { _ = w.Close() }()

	// Wait for the first leg to die.
	deadline := time.Now().Add(5 * time.Second)
	for srv.legCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	// Edit during the backoff window: no error, and nothing on the wire yet.
	if err := w.AddScripts(context.Background(), ScriptWatch{Scripthash: [32]byte{9}}); err != nil {
		t.Fatalf("an edit while disconnected must not fail the caller: %v", err)
	}
	close(release)

	replay := waitLegControls(t, srv, 1, 1)
	add, ok := replay[0].Msg.(*eventspb.SubscribeControl_AddScripts)
	if !ok {
		t.Fatalf("first replayed message is %v, want AddScripts", controlKinds(replay))
	}
	if add.AddScripts.GetScripthashes()[0][0] != 9 {
		t.Errorf("the offline edit did not reach the new stream: %x", add.AddScripts.GetScripthashes())
	}
}

// TestReconnectReAnchorsToTheResumeCursor: after a drop, the fresh stream must
// be told where to resume, or the events between the two connections are lost.
func TestReconnectReAnchorsToTheResumeCursor(t *testing.T) {
	client, srv := startScriptedWatch(t,
		func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
			if err := s.Send(blockEvent(42)); err != nil {
				return err
			}
			time.Sleep(100 * time.Millisecond)
			return nil
		},
		parkLeg,
	)
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		Backoff: Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond, Multiplier: 2},
	})
	defer func() { _ = w.Close() }()

	if b, ok := nextWatch(t, w).(*BlockConnected); !ok || b.Height != 42 {
		t.Fatalf("first event = %v", b)
	}

	replay := waitLegControls(t, srv, 1, 1)
	last := replay[len(replay)-1]
	sc, ok := last.Msg.(*eventspb.SubscribeControl_SetCursor)
	if !ok {
		t.Fatalf("the reconnect sent %v, with no SetCursor", controlKinds(replay))
	}
	if h := sc.SetCursor.GetCursor().GetHeight(); h != 42 {
		t.Errorf("re-anchored at height %d, want the last delivered 42", h)
	}
}

// TestTransientReanchorRejectIsRetriedInternally: a rate-limited re-anchor is
// the node saying "ask again", not a caller-facing failure.
func TestTransientReanchorRejectIsRetriedInternally(t *testing.T) {
	client, srv := startScriptedWatch(t, func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
		// Wait for a SetCursor, reject it transiently once, then let the retry
		// succeed. Counted by kind, because the test's connect probe sends its own
		// unrelated controls first.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if countKind(l.controls(), "SetCursor") >= 1 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if err := s.Send(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetCursorResult{
			SetCursorResult: &eventspb.SetCursorResult{
				Outcome: &eventspb.SetCursorResult_Rejected{Rejected: &eventspb.CursorRejected{
					Reason: eventspb.CursorRejected_RATE_LIMITED,
				}},
			},
		}}); err != nil {
			return err
		}
		// The retry arrives as a second SetCursor; ack it.
		for time.Now().Before(deadline) {
			if countKind(l.controls(), "SetCursor") >= 2 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if err := s.Send(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetCursorResult{
			SetCursorResult: &eventspb.SetCursorResult{
				Outcome: &eventspb.SetCursorResult_Accepted{Accepted: &eventspb.CursorAccepted{
					From: &eventspb.Cursor{Height: 100},
				}},
			},
		}}); err != nil {
			return err
		}
		<-s.Context().Done()
		return nil
	})
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		Backoff: Backoff{Initial: time.Millisecond, Max: 10 * time.Millisecond, Multiplier: 2},
	})
	defer func() { _ = w.Close() }()

	skip := waitLive(t, w, srv, 0)
	if err := w.SetCursor(context.Background(), Cursor{Height: 100}); err != nil {
		t.Fatal(err)
	}

	// The caller sees the eventual acceptance and never the transient rejection.
	ev := nextWatch(t, w)
	acc, ok := ev.(*CursorAccepted)
	if !ok {
		t.Fatalf("got %T, want *CursorAccepted - the transient reject reached the caller", ev)
	}
	if acc.From == nil || acc.From.Height != 100 {
		t.Errorf("accepted anchor = %v", acc.From)
	}
	// Two SetCursor messages: the original and the internal retry.
	got := controlKinds(waitLegControls(t, srv, 0, skip+2))[skip:]
	if len(got) < 2 || got[0] != "SetCursor" || got[1] != "SetCursor" {
		t.Errorf("controls = %v, want the original SetCursor plus a retry", got)
	}
}

// TestTerminalReanchorRejectReachesTheCaller: unlike a transient one, a cursor
// the node will never accept has to surface, or the caller waits forever for a
// replay that is not coming.
func TestTerminalReanchorRejectReachesTheCaller(t *testing.T) {
	client, _ := startScriptedWatch(t, func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && len(l.controls()) == 0 {
			time.Sleep(time.Millisecond)
		}
		if err := s.Send(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetCursorResult{
			SetCursorResult: &eventspb.SetCursorResult{
				Outcome: &eventspb.SetCursorResult_Rejected{Rejected: &eventspb.CursorRejected{
					Reason: eventspb.CursorRejected_NO_SOURCE,
				}},
			},
		}}); err != nil {
			return err
		}
		<-s.Context().Done()
		return nil
	})
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{})
	defer func() { _ = w.Close() }()

	if err := w.SetCursor(context.Background(), Cursor{Height: 5}); err != nil {
		t.Fatal(err)
	}
	ev := nextWatch(t, w)
	rej, ok := ev.(*CursorRejected)
	if !ok {
		t.Fatalf("got %T, want *CursorRejected", ev)
	}
	if rej.Reason != CursorRejectNoSource {
		t.Errorf("reason = %s", rej.Reason)
	}
}

// TestCursorAcceptedIsAdoptedAsTheResumeAnchor: the node has committed to
// replaying from the accepted anchor. If the stream drops before the first
// replayed event, the reconnect must ask for that anchor - not the stale
// high-water, which would silently skip the requested catch-up window.
func TestCursorAcceptedIsAdoptedAsTheResumeAnchor(t *testing.T) {
	client, srv := startScriptedWatch(t,
		func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
			// Advance the high-water to 10, then accept a re-anchor to 3 and die
			// before replaying anything.
			if err := s.Send(blockEvent(10)); err != nil {
				return err
			}
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) && len(l.controls()) == 0 {
				time.Sleep(time.Millisecond)
			}
			if err := s.Send(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_SetCursorResult{
				SetCursorResult: &eventspb.SetCursorResult{
					Outcome: &eventspb.SetCursorResult_Accepted{Accepted: &eventspb.CursorAccepted{
						From: &eventspb.Cursor{Height: 3},
					}},
				},
			}}); err != nil {
				return err
			}
			time.Sleep(100 * time.Millisecond)
			return nil
		},
		parkLeg,
	)
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		Backoff: Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond, Multiplier: 2},
	})
	defer func() { _ = w.Close() }()

	if b, ok := nextWatch(t, w).(*BlockConnected); !ok || b.Height != 10 {
		t.Fatalf("first event = %v", b)
	}
	if err := w.SetCursor(context.Background(), Cursor{Height: 3}); err != nil {
		t.Fatal(err)
	}
	if acc, ok := nextWatch(t, w).(*CursorAccepted); !ok || acc.From.Height != 3 {
		t.Fatalf("expected the acceptance of the re-anchor, got %v", acc)
	}

	replay := waitLegControls(t, srv, 1, 1)
	sc, ok := replay[len(replay)-1].Msg.(*eventspb.SubscribeControl_SetCursor)
	if !ok {
		t.Fatalf("the reconnect sent %v, with no SetCursor", controlKinds(replay))
	}
	if h := sc.SetCursor.GetCursor().GetHeight(); h != 3 {
		t.Errorf("reconnect anchored at %d, want the accepted 3 - the catch-up window was skipped", h)
	}
}

// TestFiredOneShotWatchesArePrunedFromTheMirror: a depth alarm that fired and a
// finalized lifecycle are gone server-side. Re-registering them on reconnect
// would duplicate the terminal notification and burn quota on a done txid.
func TestFiredOneShotWatchesArePrunedFromTheMirror(t *testing.T) {
	alarmTx := [32]byte{0xa1}
	lifeTx := [32]byte{0xb2}
	client, srv := startScriptedWatch(t,
		func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) && len(l.controls()) < 2 {
				time.Sleep(time.Millisecond)
			}
			if err := s.Send(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_TxidDepthReached{
				TxidDepthReached: &eventspb.TxidDepthReached{
					Txid: append([]byte(nil), alarmTx[:]...), Depth: 3, Height: 100,
				},
			}}); err != nil {
				return err
			}
			if err := s.Send(&eventspb.NodeEvent{Body: &eventspb.NodeEvent_TxidFinalized{
				TxidFinalized: &eventspb.TxidFinalized{
					Txid: append([]byte(nil), lifeTx[:]...), Depth: 6, Height: 100,
				},
			}}); err != nil {
				return err
			}
			time.Sleep(150 * time.Millisecond)
			return nil
		},
		parkLeg,
	)
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		Backoff: Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond, Multiplier: 2},
	})
	defer func() { _ = w.Close() }()

	ctx := context.Background()
	if err := w.AddDepthAlarms(ctx, [][32]byte{alarmTx}, []uint32{3, 9}); err != nil {
		t.Fatal(err)
	}
	if err := w.AddTxLifecycle(ctx, AutoCloseAtDepth(6), lifeTx); err != nil {
		t.Fatal(err)
	}
	if got := w.WatchSetLen(); got != 3 {
		t.Fatalf("watch-set holds %d items, want 2 alarms + 1 lifecycle", got)
	}

	// Drain both terminal events.
	for i := 0; i < 2; i++ {
		nextWatch(t, w)
	}
	// The fired alarm and the finalized lifecycle are gone; the un-fired alarm
	// at depth 9 survives.
	deadline := time.Now().Add(5 * time.Second)
	for w.WatchSetLen() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := w.WatchSetLen(); got != 1 {
		t.Fatalf("watch-set holds %d items after both terminals, want only the depth-9 alarm", got)
	}

	replay := waitLegControls(t, srv, 1, 1)
	for _, m := range replay {
		at, ok := m.Msg.(*eventspb.SubscribeControl_AddTransactions)
		if !ok {
			continue
		}
		if len(at.AddTransactions.GetMinDepths()) == 0 {
			t.Error("a finalized lifecycle was re-registered on reconnect")
			continue
		}
		for _, d := range at.AddTransactions.GetMinDepths() {
			if d == 3 {
				t.Error("a fired depth alarm was re-armed on reconnect")
			}
		}
	}
}

// TestWatchSetLoaderIsCanonicalOnEveryConnect: with a loader configured, the
// registered set comes from the integrator's truth, not from the accumulated
// in-process edits.
func TestWatchSetLoaderIsCanonicalOnEveryConnect(t *testing.T) {
	client, srv := startScriptedWatch(t,
		func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
			time.Sleep(150 * time.Millisecond)
			return nil
		},
		parkLeg,
	)

	var mu sync.Mutex
	truth := [32]byte{0x11}
	loads := 0
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		Backoff: Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond, Multiplier: 2},
		WatchSetLoader: func(_ context.Context, set *WatchSet) error {
			mu.Lock()
			defer mu.Unlock()
			loads++
			set.AddScripts(ScriptWatch{Scripthash: truth})
			return nil
		},
	})
	defer func() { _ = w.Close() }()

	first := waitLegControls(t, srv, 0, 1)
	add := first[0].Msg.(*eventspb.SubscribeControl_AddScripts).AddScripts
	if add.GetScripthashes()[0][0] != 0x11 {
		t.Fatalf("first connect registered %x, want the loader's set", add.GetScripthashes()[0])
	}

	// The truth moves while the stream is down. The reconnect must pick up the
	// NEW value - this is the drift the loader exists to close.
	mu.Lock()
	truth = [32]byte{0x22}
	mu.Unlock()

	replay := waitLegControls(t, srv, 1, 1)
	add = replay[0].Msg.(*eventspb.SubscribeControl_AddScripts).AddScripts
	if add.GetScripthashes()[0][0] != 0x22 {
		t.Errorf("reconnect registered %x, want the updated truth 0x22", add.GetScripthashes()[0])
	}
	mu.Lock()
	n := loads
	mu.Unlock()
	if n < 2 {
		t.Errorf("the loader ran %d time(s); it must run on every connect", n)
	}
}

// TestLoaderFailureIsTransient: an integrator's truth being briefly unreachable
// must not kill a consumer whose contract is at-least-once.
func TestLoaderFailureIsTransient(t *testing.T) {
	client, srv := startScriptedWatch(t, parkLeg, parkLeg, parkLeg)

	var mu sync.Mutex
	attempts := 0
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		Backoff: Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond, Multiplier: 2},
		WatchSetLoader: func(_ context.Context, set *WatchSet) error {
			mu.Lock()
			defer mu.Unlock()
			attempts++
			if attempts < 3 {
				return errors.New("database unavailable")
			}
			set.AddScripts(ScriptWatch{Scripthash: [32]byte{7}})
			return nil
		},
	})
	defer func() { _ = w.Close() }()

	// The failures are retried on fresh connections until one succeeds.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := attempts
		mu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	got := waitLegControls(t, srv, srv.legCount()-1, 1)
	add, ok := got[0].Msg.(*eventspb.SubscribeControl_AddScripts)
	if !ok {
		t.Fatalf("controls = %v, want the eventually-loaded set", controlKinds(got))
	}
	if add.AddScripts.GetScripthashes()[0][0] != 7 {
		t.Errorf("registered %x after the loader recovered", add.AddScripts.GetScripthashes()[0])
	}
}

// TestPermanentLoaderFailureSurfacesUnderARetryBudget: retrying forever is the
// documented default, but a MaxRetries budget must convert it to a real error
// rather than a consumer that silently never yields.
func TestPermanentLoaderFailureSurfacesUnderARetryBudget(t *testing.T) {
	client, _ := startScriptedWatch(t, parkLeg, parkLeg, parkLeg, parkLeg, parkLeg, parkLeg)
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		Backoff: Backoff{
			Initial: time.Millisecond, Max: 2 * time.Millisecond, Multiplier: 2, MaxRetries: 2,
		},
		WatchSetLoader: func(context.Context, *WatchSet) error {
			return errors.New("config typo")
		},
	})
	defer func() { _ = w.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := w.Next(ctx)
	if err == nil {
		t.Fatal("a permanently failing loader never surfaced")
	}
	if !errors.Is(err, ErrWatchSetLoaderFailed) {
		t.Errorf("got %v, want the loader failure", err)
	}
}

func TestReloadWithoutALoaderIsAnError(t *testing.T) {
	client, _ := startScriptedWatch(t, parkLeg)
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{})
	defer func() { _ = w.Close() }()

	if _, err := w.Reload(context.Background()); !errors.Is(err, ErrNoLoader) {
		t.Errorf("got %v, want ErrNoLoader", err)
	}
}

// TestReloadSendsOneAtomicSetWatchSet: the reload does NOT compute a client-side
// Add*/Remove* sequence - it hands the node the whole desired membership and
// lets it reconcile under its own lock.
func TestReloadSendsOneAtomicSetWatchSet(t *testing.T) {
	client, srv := startScriptedWatch(t, parkLeg)

	var mu sync.Mutex
	set := []byte{0x11}
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		WatchSetLoader: func(_ context.Context, ws *WatchSet) error {
			mu.Lock()
			defer mu.Unlock()
			for _, b := range set {
				ws.AddScripts(ScriptWatch{Scripthash: [32]byte{b}})
			}
			return nil
		},
	})
	defer func() { _ = w.Close() }()

	waitLegControls(t, srv, 0, 1) // the connect-time load
	before := len(srv.leg(0).controls())

	mu.Lock()
	set = []byte{0x22, 0x33} // one dropped, two new
	mu.Unlock()

	summary, err := w.Reload(context.Background())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !summary.Applied {
		t.Error("the reload was not applied on a live stream")
	}
	if summary.Added != 2 || summary.Removed != 1 || summary.Unchanged != 0 {
		t.Errorf("summary = %+v, want 2 added / 1 removed / 0 unchanged", summary)
	}

	got := controlKinds(waitLegControls(t, srv, 0, before+1))[before:]
	if len(got) != 1 || got[0] != "SetWatchSet" {
		t.Errorf("reload sent %v, want exactly one SetWatchSet", got)
	}
}

// TestReloadWhileDisconnectedDefersToTheReconnect: the mirror still adopts the
// reloaded set, so nothing is lost - it just lands on the next connection.
func TestReloadWhileDisconnectedDefersToTheReconnect(t *testing.T) {
	release := make(chan struct{})
	client, srv := startScriptedWatch(t,
		func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error { return nil },
		func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
			<-release
			<-s.Context().Done()
			return nil
		},
	)

	var mu sync.Mutex
	targets := []byte{0x44}
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		Backoff: Backoff{Initial: 300 * time.Millisecond, Max: time.Second, Multiplier: 2},
		WatchSetLoader: func(_ context.Context, ws *WatchSet) error {
			mu.Lock()
			defer mu.Unlock()
			for _, b := range targets {
				ws.AddScripts(ScriptWatch{Scripthash: [32]byte{b}})
			}
			return nil
		},
	})
	defer func() { _ = w.Close() }()

	deadline := time.Now().Add(5 * time.Second)
	for srv.legCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	// The truth grows while the stream is down.
	mu.Lock()
	targets = []byte{0x44, 0x55, 0x66}
	mu.Unlock()

	summary, err := w.Reload(context.Background())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if summary.Applied {
		t.Error("a reload with no live stream reported Applied")
	}
	// The mirror adopts the reloaded set even though nothing went out, which is
	// what makes the summary meaningful and what the pending reconnect registers.
	if got := w.WatchSetLen(); got != 3 {
		t.Errorf("watch-set holds %d items after the deferred reload, want the 3 loaded", got)
	}
	close(release)

	replay := waitLegControls(t, srv, 1, 1)
	add, ok := replay[0].Msg.(*eventspb.SubscribeControl_AddScripts)
	if !ok {
		t.Fatalf("controls = %v", controlKinds(replay))
	}
	if n := len(add.AddScripts.GetScripthashes()); n != 3 {
		t.Fatalf("the reconnect registered %d script(s), want the 3 from the reloaded truth", n)
	}
}

// TestReloadTurnsOffARawTxOptInTheStreamStillHas: SetWatchSet does not carry the
// raw-tx opt-in, so dropping it from the truth has to be sent explicitly or the
// node keeps serializing full transactions.
func TestReloadTurnsOffARawTxOptInTheStreamStillHas(t *testing.T) {
	client, srv := startScriptedWatch(t, parkLeg)

	var mu sync.Mutex
	rawTx := true
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		WatchSetLoader: func(_ context.Context, ws *WatchSet) error {
			mu.Lock()
			defer mu.Unlock()
			ws.AddScripts(ScriptWatch{Scripthash: [32]byte{1}})
			ws.SetWatchOptions(rawTx)
			return nil
		},
	})
	defer func() { _ = w.Close() }()

	waitLegControls(t, srv, 0, 2)
	before := len(srv.leg(0).controls())

	mu.Lock()
	rawTx = false
	mu.Unlock()
	if _, err := w.Reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}

	got := controlKinds(waitLegControls(t, srv, 0, before+2))[before:]
	if len(got) < 2 || got[0] != "SetWatchSet" || got[1] != "SetWatchOptions" {
		t.Fatalf("reload sent %v, want SetWatchSet then an explicit SetWatchOptions", got)
	}
	msgs := srv.leg(0).controls()
	opts := msgs[before+1].Msg.(*eventspb.SubscribeControl_SetWatchOptions).SetWatchOptions
	if opts.GetIncludeRawTx() {
		t.Error("the raw-tx opt-in was left on after the truth dropped it")
	}
}

// TestReloadDoesNotResendAnUnchangedRawTxOptIn keeps the opposite honest: a
// reload that does not touch the opt-in must not chatter.
func TestReloadDoesNotResendAnUnchangedRawTxOptIn(t *testing.T) {
	client, srv := startScriptedWatch(t, parkLeg)
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{
		WatchSetLoader: func(_ context.Context, ws *WatchSet) error {
			ws.AddScripts(ScriptWatch{Scripthash: [32]byte{1}})
			ws.SetWatchOptions(true)
			return nil
		},
	})
	defer func() { _ = w.Close() }()

	waitLegControls(t, srv, 0, 2)
	before := len(srv.leg(0).controls())
	if _, err := w.Reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := controlKinds(waitLegControls(t, srv, 0, before+1))[before:]
	if len(got) != 1 || got[0] != "SetWatchSet" {
		t.Errorf("reload sent %v, want only the SetWatchSet", got)
	}
}

// TestResilientWatchSeedsFromTheCursorStore: a restart resumes where the last
// process left off.
func TestResilientWatchSeedsFromTheCursorStore(t *testing.T) {
	client, srv := startScriptedWatch(t, parkLeg)
	store := &recordingStore{loaded: &Cursor{Height: 77, TxIndex: 2}}
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{CursorStore: store})
	defer func() { _ = w.Close() }()

	got := waitLegControls(t, srv, 0, 1)
	sc, ok := got[0].Msg.(*eventspb.SubscribeControl_SetCursor)
	if !ok {
		t.Fatalf("first control = %v, want SetCursor", controlKinds(got))
	}
	if c := sc.SetCursor.GetCursor(); c.GetHeight() != 77 || c.GetTxIndex() != 2 {
		t.Errorf("anchored at %v, want the persisted cursor", c)
	}
}

func TestResilientWatchCommitsOnPoll(t *testing.T) {
	client, _ := startScriptedWatch(t, func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
		for h := uint32(10); h <= 12; h++ {
			if err := s.Send(blockEvent(h)); err != nil {
				return err
			}
		}
		<-s.Context().Done()
		return nil
	})
	store := &recordingStore{}
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{CursorStore: store})
	defer func() { _ = w.Close() }()

	if b := nextWatch(t, w).(*BlockConnected); b.Height != 10 {
		t.Fatalf("height = %d", b.Height)
	}
	if c := store.last(); c != nil {
		t.Errorf("committed %v before the caller acked the first event", c)
	}
	if b := nextWatch(t, w).(*BlockConnected); b.Height != 11 {
		t.Fatalf("height = %d", b.Height)
	}
	waitFor(t, func() bool { c := store.last(); return c != nil && c.Height == 10 })

	if err := w.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := store.last(); c == nil || c.Height != 11 {
		t.Errorf("after Commit the store holds %v, want height 11", c)
	}
}

func TestResilientWatchCloseEndsIt(t *testing.T) {
	client, _ := startScriptedWatch(t, parkLeg)
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := w.Next(ctx); err != io.EOF {
		t.Errorf("Next after Close = %v, want io.EOF", err)
	}
}

// TestResilientWatchNextIsCancelSafe mirrors the subscription's property: a
// cancelled Next must not swallow the event that was in flight.
func TestResilientWatchNextIsCancelSafe(t *testing.T) {
	const total = 40
	client, _ := startScriptedWatch(t, func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
		for h := uint32(10); h < 10+total; h++ {
			if err := s.Send(blockEvent(h)); err != nil {
				return err
			}
		}
		<-s.Context().Done()
		return nil
	})
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{})
	defer func() { _ = w.Close() }()

	if b := nextWatch(t, w).(*BlockConnected); b.Height != 10 {
		t.Fatalf("height = %d", b.Height)
	}

	var (
		got       []uint32
		cancelled int
	)
	for i := 0; i < 20*total && len(got) < total-1; i++ {
		time.Sleep(200 * time.Microsecond)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ev, err := w.Next(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Next: %v", err)
			}
			cancelled++
			continue
		}
		got = append(got, ev.(*BlockConnected).Height)
	}
	if cancelled == 0 {
		t.Skip("never won the cancellation race; nothing was perturbed")
	}
	for len(got) < total-1 {
		got = append(got, nextWatch(t, w).(*BlockConnected).Height)
	}
	for i := range got {
		if want := uint32(11 + i); got[i] != want {
			t.Fatalf("event %d = height %d, want %d - %d cancelled call(s) lost an event",
				i, got[i], want, cancelled)
		}
	}
}

// TestConcurrentEditsAndPollingAreSafe is a race-detector exercise: a consumer
// that drives Next on one goroutine while registering watches on another must
// not corrupt the mirror.
func TestConcurrentEditsAndPollingAreSafe(t *testing.T) {
	client, _ := startScriptedWatch(t, func(l *watchLeg, s eventspb.NodeEventStream_WatchServer) error {
		for h := uint32(0); h < 200; h++ {
			if err := s.Send(blockEvent(h)); err != nil {
				return err
			}
		}
		<-s.Context().Done()
		return nil
	})
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{})
	defer func() { _ = w.Close() }()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			select {
			case <-stop:
				return
			default:
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := w.Next(ctx)
			cancel()
			if err != nil {
				return
			}
		}
	}()

	ctx := context.Background()
	for i := 0; i < 100; i++ {
		h := [32]byte{byte(i)}
		if err := w.AddScripts(ctx, ScriptWatch{Scripthash: h}); err != nil {
			t.Errorf("add: %v", err)
			break
		}
		if err := w.RemoveScripts(ctx, h); err != nil {
			t.Errorf("remove: %v", err)
			break
		}
		_ = w.WatchSetLen()
	}
	close(stop)
	wg.Wait()

	if got := w.WatchSetLen(); got != 0 {
		t.Errorf("watch-set holds %d items after equal adds and removes", got)
	}
}

// countKind is how many of msgs are of the named control kind.
func countKind(msgs []*eventspb.SubscribeControl, kind string) int {
	n := 0
	for _, k := range controlKinds(msgs) {
		if k == kind {
			n++
		}
	}
	return n
}
