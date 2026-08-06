package satdevents

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

func TestBackoffGrowsAndClamps(t *testing.T) {
	b := Backoff{
		Initial:    100 * time.Millisecond,
		Max:        1 * time.Second,
		Multiplier: 2.0,
	}
	want := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
		time.Second, // clamped
		time.Second,
	}
	for i, w := range want {
		if got := b.DelayFor(uint32(i)); got != w {
			t.Errorf("DelayFor(%d) = %s, want %s", i, got, w)
		}
	}
	// A huge attempt count must clamp, not overflow to a negative or zero delay
	// (which would turn a backoff into a reconnect storm).
	for _, attempt := range []uint32{64, 1000, 1 << 20, ^uint32(0)} {
		if got := b.DelayFor(attempt); got != time.Second {
			t.Errorf("DelayFor(%d) = %s, want the 1s ceiling", attempt, got)
		}
	}
	// The zero value is usable rather than a zero-delay spin.
	if got := (Backoff{}).DelayFor(0); got != DefaultBackoff().Initial {
		t.Errorf("zero-value DelayFor(0) = %s, want the default initial", got)
	}
}

func TestFileCursorStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cursor")
	store := NewFileCursorStore(path)
	ctx := context.Background()

	// A missing file is "no cursor yet", not an error - a fresh consumer must
	// start clean rather than crash.
	got, err := store.Load(ctx)
	if err != nil || got != nil {
		t.Fatalf("Load on a missing file = (%v, %v), want (nil, nil)", got, err)
	}

	want := Cursor{Height: 812345, TxIndex: 7, MempoolSeq: 99, InstanceID: 12345678901234567}
	if err := store.Store(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err = store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got != want {
		t.Errorf("round trip = %v, want %v", got, want)
	}

	// The on-disk format is the Rust SDK's, byte for byte, so the two can share
	// a cursor file.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "812345 7 99 12345678901234567\n" {
		t.Errorf("on-disk form = %q", string(raw))
	}

	// No temp file survives a successful write.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("temp file %s was left behind", e.Name())
		}
	}
}

func TestFileCursorStoreRejectsCorruptContent(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"truncated":         "1 2 3\n",
		"empty":             "",
		"not a number":      "1 2 3 x\n",
		"height out of u32": "4294967296 0 0 0\n",
		// The load-bearing one: parsed at 64 bits and truncated, this would
		// resume from height 0 instead of erroring - silently replaying the
		// entire chain, or skipping it.
		"height wraps u32": "4294967297 0 0 0\n",
	}
	for name, content := range cases {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewFileCursorStore(path).Load(context.Background()); !errors.Is(err, ErrDecode) {
			t.Errorf("%s: got %v, want ErrDecode", name, err)
		}
	}
}

// TestFileCursorStoreSurvivesConcurrentWriters: two subscriptions can share one
// cursor path, and a temp-file collision would make one rename a foreign or
// partial file.
func TestFileCursorStoreSurvivesConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared")
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := NewFileCursorStore(path)
			for j := 0; j < 20; j++ {
				if err := store.Store(ctx, Cursor{Height: uint32(i*100 + j)}); err != nil {
					t.Errorf("store: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	// Whatever landed last, it must be a whole, parseable cursor - never torn.
	if _, err := NewFileCursorStore(path).Load(ctx); err != nil {
		t.Errorf("the file was left unreadable: %v", err)
	}
}

// ---- scripted server for the reconnect state machine -----------------------

// scriptedServer answers each Subscribe with the next leg of a script,
// recording the request so a test can assert on the replay anchor the SDK sent.
type scriptedServer struct {
	eventspb.UnimplementedNodeEventStreamServer

	mu       sync.Mutex
	requests []*eventspb.SubscribeRequest
	legs     []func(srv eventspb.NodeEventStream_SubscribeServer) error
	calls    int
}

func (s *scriptedServer) Subscribe(req *eventspb.SubscribeRequest, srv eventspb.NodeEventStream_SubscribeServer) error {
	s.mu.Lock()
	s.requests = append(s.requests, req)
	i := s.calls
	s.calls++
	s.mu.Unlock()

	if i < len(s.legs) {
		return s.legs[i](srv)
	}
	// Past the script, park until the client goes away rather than spinning the
	// reconnect loop against a server that closes instantly.
	<-srv.Context().Done()
	return nil
}

func (s *scriptedServer) request(i int) *eventspb.SubscribeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i >= len(s.requests) {
		return nil
	}
	return s.requests[i]
}

func (s *scriptedServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func startScripted(t *testing.T, legs ...func(srv eventspb.NodeEventStream_SubscribeServer) error) (*Client, *scriptedServer) {
	t.Helper()
	srv := &scriptedServer{legs: legs}
	client := startServer(t, srv)
	return client, srv
}

// blockEvent is a confirmed BlockConnected carrying its durable cursor.
func blockEvent(height uint32) *eventspb.NodeEvent {
	return &eventspb.NodeEvent{
		Cursor: &eventspb.Cursor{Height: height},
		Body: &eventspb.NodeEvent_Chain{Chain: &eventspb.ChainEvent{
			Body: &eventspb.ChainEvent_BlockConnected{
				BlockConnected: &eventspb.BlockConnected{Height: height},
			},
		}},
	}
}

func laggedEvent(dropped uint64, resume *eventspb.Cursor) *eventspb.NodeEvent {
	return &eventspb.NodeEvent{Body: &eventspb.NodeEvent_Lagged{
		Lagged: &eventspb.Lagged{DroppedCount: dropped, ResumeCursor: resume},
	}}
}

// sendAll pushes events and then returns, which closes the stream cleanly.
func sendAll(events ...*eventspb.NodeEvent) func(eventspb.NodeEventStream_SubscribeServer) error {
	return func(srv eventspb.NodeEventStream_SubscribeServer) error {
		for _, ev := range events {
			if err := srv.Send(ev); err != nil {
				return err
			}
		}
		return nil
	}
}

// nextBlock drives sub until a BlockConnected arrives, failing on anything else.
func nextBlock(t *testing.T, sub *ResilientSubscription) *BlockConnected {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev, err := sub.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	b, ok := ev.(*BlockConnected)
	if !ok {
		t.Fatalf("got %T, want *BlockConnected", ev)
	}
	return b
}

// TestResilientSubscribeReconnectsAndReplaysFromTheCursor is the core contract:
// a server close is invisible to the caller, and the reconnect asks to replay
// from the last confirmed cursor rather than starting forward-only.
func TestResilientSubscribeReconnectsAndReplaysFromTheCursor(t *testing.T) {
	client, srv := startScripted(t,
		sendAll(blockEvent(10), blockEvent(11)),
		sendAll(blockEvent(12)),
	)
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{},
		ResilientConfig{Backoff: Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond, Multiplier: 2}})
	defer func() { _ = sub.Close() }()

	for _, want := range []uint32{10, 11, 12} {
		if got := nextBlock(t, sub).Height; got != want {
			t.Fatalf("height = %d, want %d", got, want)
		}
	}

	if first := srv.request(0); first.GetFromCursor() != nil {
		t.Errorf("the first subscribe carried a cursor: %v", first.GetFromCursor())
	}
	second := srv.request(1)
	if second == nil || second.GetFromCursor() == nil {
		t.Fatal("the reconnect did not carry a replay anchor")
	}
	if h := second.GetFromCursor().GetHeight(); h != 11 {
		t.Errorf("reconnect anchored at height %d, want the last delivered 11", h)
	}
}

// TestResilientSubscribeCommitsOnPoll pins the at-least-once discipline: the
// store must not advance past an event the caller has not yet come back from.
func TestResilientSubscribeCommitsOnPoll(t *testing.T) {
	client, _ := startScripted(t, func(srv eventspb.NodeEventStream_SubscribeServer) error {
		for h := uint32(10); h <= 12; h++ {
			if err := srv.Send(blockEvent(h)); err != nil {
				return err
			}
		}
		<-srv.Context().Done()
		return nil
	})
	store := &recordingStore{}
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{},
		ResilientConfig{CursorStore: store})
	defer func() { _ = sub.Close() }()

	// After the FIRST event, nothing is committed: the caller has not
	// acknowledged it by asking for another.
	if got := nextBlock(t, sub).Height; got != 10 {
		t.Fatalf("height = %d", got)
	}
	if last := store.last(); last != nil {
		t.Errorf("committed %v before the caller acked the first event", last)
	}

	// Asking for the second commits the first, and so on - always one behind.
	if got := nextBlock(t, sub).Height; got != 11 {
		t.Fatalf("height = %d", got)
	}
	waitFor(t, func() bool { c := store.last(); return c != nil && c.Height == 10 })

	if got := nextBlock(t, sub).Height; got != 12 {
		t.Fatalf("height = %d", got)
	}
	waitFor(t, func() bool { c := store.last(); return c != nil && c.Height == 11 })

	// An explicit Commit flushes the last one, which is what a clean shutdown
	// needs so the final processed event is not replayed.
	if err := sub.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := store.last(); c == nil || c.Height != 12 {
		t.Errorf("after Commit the store holds %v, want height 12", c)
	}
}

// TestResilientSubscribeSeedsFromTheStore covers the restart path: a persisted
// cursor becomes the first connect's replay anchor, and is not rewritten
// redundantly.
func TestResilientSubscribeSeedsFromTheStore(t *testing.T) {
	client, srv := startScripted(t, func(srv eventspb.NodeEventStream_SubscribeServer) error {
		// The anchor block itself is replayed first (inclusive replay), then the
		// ones after it.
		for _, h := range []uint32{42, 43, 44} {
			if err := srv.Send(blockEvent(h)); err != nil {
				return err
			}
		}
		<-srv.Context().Done()
		return nil
	})
	store := &recordingStore{loaded: &Cursor{Height: 42}}
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{},
		ResilientConfig{CursorStore: store})
	defer func() { _ = sub.Close() }()

	for _, want := range []uint32{42, 43, 44} {
		if got := nextBlock(t, sub).Height; got != want {
			t.Fatalf("height = %d, want %d", got, want)
		}
	}
	req := srv.request(0)
	if req.GetFromCursor().GetHeight() != 42 {
		t.Errorf("first subscribe anchored at %v, want the persisted cursor", req.GetFromCursor())
	}

	// Polling for 43 acked 42 - but 42 is exactly what was loaded, so it is
	// already durable and rewriting it is a wasted disk write on every replayed
	// event. By the time 44 arrives, 42's commit has either happened or been
	// elided, so this is not racing the pump.
	waitFor(t, func() bool { c := store.last(); return c != nil && c.Height == 43 })
	for _, c := range store.all() {
		if c.Height == 42 {
			t.Errorf("the just-loaded cursor was written back redundantly")
		}
	}
}

// TestReplayGapIsSynthesizedWhenTheServerClamps: a server that truncates the
// replay window must not look like a contiguous stream. The gap is
// unrecoverable through this stream, so the consumer has to be told.
func TestReplayGapIsSynthesizedWhenTheServerClamps(t *testing.T) {
	client, _ := startScripted(t,
		sendAll(blockEvent(10)),
		// The reconnect asks to replay from 11, but the server starts at 500 -
		// the window clamped away everything between.
		func(srv eventspb.NodeEventStream_SubscribeServer) error {
			if err := srv.Send(blockEvent(500)); err != nil {
				return err
			}
			<-srv.Context().Done()
			return nil
		},
	)
	store := &recordingStore{}
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{},
		ResilientConfig{
			CursorStore: store,
			Backoff:     Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond, Multiplier: 2},
		})
	defer func() { _ = sub.Close() }()

	if got := nextBlock(t, sub).Height; got != 10 {
		t.Fatalf("height = %d", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev, err := sub.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	gap, ok := ev.(*ReplayGap)
	if !ok {
		t.Fatalf("got %T, want the synthesized *ReplayGap", ev)
	}
	if gap.ResumeHeight != 11 || gap.FirstHeight != 500 {
		t.Errorf("gap = (%d, %d), want (11, 500)", gap.ResumeHeight, gap.FirstHeight)
	}

	// The gap notice must NOT advance the durable anchor past the skipped
	// range - the block that triggered it is delivered next and commits then.
	if c := store.last(); c != nil && c.Height >= 500 {
		t.Errorf("the gap notice committed %v, skipping the unread range", c)
	}
	if got := nextBlock(t, sub).Height; got != 500 {
		t.Errorf("the triggering block was not delivered after the gap: %d", got)
	}
}

func TestLagPolicyAutoResumeReanchorsSilently(t *testing.T) {
	client, srv := startScripted(t,
		sendAll(blockEvent(10), laggedEvent(500, &eventspb.Cursor{Height: 42})),
		sendAll(blockEvent(43)),
	)
	store := &recordingStore{}
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{},
		ResilientConfig{
			CursorStore: store,
			Backoff:     Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond, Multiplier: 2},
		})
	defer func() { _ = sub.Close() }()

	if got := nextBlock(t, sub).Height; got != 10 {
		t.Fatalf("height = %d", got)
	}
	// The lag notice is consumed internally; the caller only sees the events
	// after the re-anchor.
	if got := nextBlock(t, sub).Height; got != 43 {
		t.Fatalf("height = %d, want the post-reanchor block", got)
	}
	req := srv.request(1)
	if req.GetFromCursor().GetHeight() != 42 {
		t.Errorf("re-anchored at %v, want the notice's resume cursor (42)", req.GetFromCursor())
	}
	// The lag re-anchor moves the in-memory resume point, and the STORE follows
	// commit-on-poll like everything else. It must never be written from the
	// pump: the node's resume_cursor is the last position it delivered - the
	// event the caller is still holding - so persisting it there let a crash
	// mid-processing skip that event for good.
	// (The re-anchor itself is already proven by the FromCursor check above.)
	if c := store.last(); c != nil && c.Height == 42 {
		t.Error("the pump persisted the lag anchor directly, so an unacked event can be skipped")
	}
}

// TestLagAutoResumeDoesNotOutrunTheCaller is the regression proof for that:
// the caller takes an event, the pump sees a lag notice anchored AT that event,
// and the store must still not hold it until the caller polls again.
func TestLagAutoResumeDoesNotOutrunTheCaller(t *testing.T) {
	client, _ := startScripted(t,
		sendAll(blockEvent(10), laggedEvent(500, &eventspb.Cursor{Height: 10})),
		sendAll(blockEvent(11)),
	)
	store := &recordingStore{}
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{},
		ResilientConfig{
			CursorStore: store,
			Backoff:     Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond, Multiplier: 2},
		})
	defer func() { _ = sub.Close() }()

	// Block 10 is now in the caller's hands and NOT acked. The pump goes on to
	// read the lag notice, whose resume cursor is block 10's own position.
	if got := nextBlock(t, sub).Height; got != 10 {
		t.Fatalf("height = %d", got)
	}
	// Give the pump time to process the lag notice and reconnect.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r := sub.ResumeCursor(); r != nil && r.Height == 10 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if c := store.last(); c != nil && c.Height >= 10 {
		t.Fatalf("store holds %v while block 10 is still unacked: a crash here loses it", c)
	}
	// Polling again is the ack, and only now may the store advance.
	if got := nextBlock(t, sub).Height; got != 11 {
		t.Fatalf("height = %d", got)
	}
	if c := store.last(); c == nil || c.Height != 10 {
		t.Errorf("after the ack the store holds %v, want block 10", c)
	}
}

func TestLagPolicySurfaceHandsTheNoticeToTheCaller(t *testing.T) {
	client, _ := startScripted(t, func(srv eventspb.NodeEventStream_SubscribeServer) error {
		if err := srv.Send(laggedEvent(7, &eventspb.Cursor{Height: 42})); err != nil {
			return err
		}
		if err := srv.Send(blockEvent(43)); err != nil {
			return err
		}
		<-srv.Context().Done()
		return nil
	})
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{},
		ResilientConfig{LagPolicy: LagSurface})
	defer func() { _ = sub.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev, err := sub.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lag, ok := ev.(*Lagged)
	if !ok {
		t.Fatalf("got %T, want *Lagged", ev)
	}
	if lag.DroppedCount != 7 || lag.ResumeCursor == nil || lag.ResumeCursor.Height != 42 {
		t.Errorf("lag notice = %+v", lag)
	}
	// The loop keeps running on the same connection afterwards.
	if got := nextBlock(t, sub).Height; got != 43 {
		t.Errorf("height = %d", got)
	}
}

// TestNonRetryableErrorsAreSurfacedImmediately: a permission failure must not
// be retried forever behind the caller's back.
func TestNonRetryableErrorsAreSurfacedImmediately(t *testing.T) {
	client, srv := startScripted(t, func(eventspb.NodeEventStream_SubscribeServer) error {
		return status.Error(codes.PermissionDenied, "stream:subscribe required")
	})
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{}, ResilientConfig{})
	defer func() { _ = sub.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := sub.Next(ctx); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("got %v, want ErrPermissionDenied", err)
	}
	if n := srv.requestCount(); n != 1 {
		t.Errorf("%d subscribe attempts, want exactly 1 - a permission error is permanent", n)
	}
}

// TestMaxRetriesIsHonored: a flapping server must eventually surface an error
// rather than reconnecting silently forever.
func TestMaxRetriesIsHonored(t *testing.T) {
	legs := make([]func(eventspb.NodeEventStream_SubscribeServer) error, 10)
	for i := range legs {
		legs[i] = func(eventspb.NodeEventStream_SubscribeServer) error {
			return status.Error(codes.Unavailable, "node restarting")
		}
	}
	client, srv := startScripted(t, legs...)

	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{},
		ResilientConfig{Backoff: Backoff{
			Initial: time.Millisecond, Max: 2 * time.Millisecond, Multiplier: 2, MaxRetries: 3,
		}})
	defer func() { _ = sub.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := sub.Next(ctx)
	if err == nil {
		t.Fatal("the retry budget ran out but Next succeeded")
	}
	if !errors.Is(err, ErrTransport) {
		t.Errorf("got %v, want the last transport error", err)
	}
	// The initial connect is not counted against the budget, so the bound is
	// 1 + MaxRetries attempts.
	if n := srv.requestCount(); n > 5 {
		t.Errorf("%d attempts for MaxRetries=3, want no more than 4", n)
	}
}

// TestNextIsCancelSafe is the load-bearing concurrency property: cancelling a
// Next - losing a select race to a command channel, say - must not consume the
// event that was in flight.
func TestNextIsCancelSafe(t *testing.T) {
	const total = 40
	client, _ := startScripted(t, func(srv eventspb.NodeEventStream_SubscribeServer) error {
		for h := uint32(10); h < 10+total; h++ {
			if err := srv.Send(blockEvent(h)); err != nil {
				return err
			}
		}
		<-srv.Context().Done()
		return nil
	})
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{}, ResilientConfig{})
	defer func() { _ = sub.Close() }()

	// Take the first event normally. That proves the pump is running, and it
	// then parks trying to hand over the next one - which is the state the
	// cancellation has to race against. A cancelled call made while nothing is
	// being offered asserts nothing, so every iteration below yields first to let
	// the pump get back to its park.
	if got := nextBlock(t, sub).Height; got != 10 {
		t.Fatalf("height = %d", got)
	}

	// Hammer Next with an already-cancelled context while the pump is parked on
	// the handoff. Go picks randomly among ready select cases, so each call is a
	// genuine race: some cancel, some win the event. Either is fine - what must
	// never happen is an event disappearing into a cancelled call. Forty events
	// means forty parked races, so "the cancel branch never won while an event
	// was in flight" is not a way for this to pass vacuously.
	var (
		got       []uint32
		cancelled int
	)
	for i := 0; i < 20*total && len(got) < total-1; i++ {
		time.Sleep(200 * time.Microsecond)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ev, err := sub.Next(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Next: %v", err)
			}
			cancelled++
			continue
		}
		b, ok := ev.(*BlockConnected)
		if !ok {
			t.Fatalf("got %T, want *BlockConnected", ev)
		}
		got = append(got, b.Height)
	}
	if cancelled == 0 {
		t.Skip("never won the cancellation race; nothing was perturbed")
	}
	// Drain whatever the cancelled calls did not pick up. A cancelled call that
	// swallowed an event shows up either as a wrong height here or as this
	// blocking until the deadline.
	for len(got) < total-1 {
		got = append(got, nextBlock(t, sub).Height)
	}
	for i := range got {
		if want := uint32(11 + i); got[i] != want {
			t.Fatalf("event %d = height %d, want %d - %d cancelled call(s) lost an event",
				i, got[i], want, cancelled)
		}
	}
}

func TestCloseEndsTheSubscription(t *testing.T) {
	client, _ := startScripted(t, func(srv eventspb.NodeEventStream_SubscribeServer) error {
		<-srv.Context().Done()
		return nil
	})
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{}, ResilientConfig{})
	if err := sub.Close(); err != nil {
		t.Fatal(err)
	}
	// Idempotent.
	if err := sub.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := sub.Next(ctx); err != io.EOF {
		t.Errorf("Next after Close = %v, want io.EOF", err)
	}
}

func TestCursorStoreFailureIsSurfaced(t *testing.T) {
	client, _ := startScripted(t, func(srv eventspb.NodeEventStream_SubscribeServer) error {
		for h := uint32(10); h <= 12; h++ {
			if err := srv.Send(blockEvent(h)); err != nil {
				return err
			}
		}
		<-srv.Context().Done()
		return nil
	})
	store := &recordingStore{storeErr: errors.New("disk full")}
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{},
		ResilientConfig{CursorStore: store})
	defer func() { _ = sub.Close() }()

	// The first event is delivered; the failure surfaces when its commit runs,
	// which is on the poll for the second.
	if got := nextBlock(t, sub).Height; got != 10 {
		t.Fatalf("height = %d", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ev, err := sub.Next(ctx)
	if err == nil {
		t.Fatalf("a failing cursor store was swallowed (got %T); a crash would "+
			"resume from a stale anchor", ev)
	}
	if !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("got %v, want the store failure", err)
	}

	// The event whose commit failed must not have been eaten by the error: once
	// the store recovers, it is still delivered, in order.
	store.mu.Lock()
	store.storeErr = nil
	store.mu.Unlock()
	for _, want := range []uint32{11, 12} {
		if got := nextBlock(t, sub).Height; got != want {
			t.Fatalf("height = %d, want %d - the store failure consumed an event", got, want)
		}
	}
}

// ---- helpers ---------------------------------------------------------------

// recordingStore is an in-memory [CursorStore] that records every write.
type recordingStore struct {
	mu       sync.Mutex
	loaded   *Cursor
	saved    []Cursor
	storeErr error
}

func (s *recordingStore) Load(context.Context) (*Cursor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded == nil {
		return nil, nil
	}
	c := *s.loaded
	return &c, nil
}

func (s *recordingStore) Store(_ context.Context, c Cursor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.storeErr != nil {
		return s.storeErr
	}
	s.saved = append(s.saved, c)
	return nil
}

func (s *recordingStore) last() *Cursor {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.saved) == 0 {
		return nil
	}
	c := s.saved[len(s.saved)-1]
	return &c
}

func (s *recordingStore) all() []Cursor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Cursor(nil), s.saved...)
}

// waitFor spins until cond holds, so a test never races the pump's commit.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition never became true")
}

// TestCommitRetryAfterStoreFailureActuallyWrites pins the arm-retention rule in
// commitDue. Clearing the armed cursor before the store write meant a retried
// Commit found nothing armed and returned nil - a FALSE durability ack. The
// caller shuts down believing its position is safe; the next start finds an
// empty store, begins forward-only, and never delivers what happened in
// between. That is a lost event, not a replayed one.
func TestCommitRetryAfterStoreFailureActuallyWrites(t *testing.T) {
	client, _ := startScripted(t, sendAll(blockEvent(10), blockEvent(11)))
	store := &recordingStore{}
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{},
		ResilientConfig{CursorStore: store})
	defer func() { _ = sub.Close() }()

	if got := nextBlock(t, sub).Height; got != 10 {
		t.Fatalf("height = %d", got)
	}

	// Arm block 10, then fail the write the caller asked for.
	store.mu.Lock()
	store.storeErr = errors.New("disk full")
	store.mu.Unlock()
	if err := sub.Commit(context.Background()); err == nil {
		t.Fatal("Commit reported success while the store was failing")
	}

	// The store recovers. The retry must WRITE, not report a no-op success.
	store.mu.Lock()
	store.storeErr = nil
	store.mu.Unlock()
	if err := sub.Commit(context.Background()); err != nil {
		t.Fatalf("Commit after recovery: %v", err)
	}
	if c := store.last(); c == nil || c.Height != 10 {
		t.Fatalf("store holds %v after a retried Commit, want block 10", c)
	}
}
