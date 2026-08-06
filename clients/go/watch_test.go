package satdevents

import (
	"context"
	"errors"
	"net"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

// fakeServer is a minimal in-process NodeEventStream that records the control
// messages a Watch stream sends and can push events back.
//
// The control path has no per-message ack on the wire, so a real node cannot
// tell us what it received - the only way to assert the SDK builds the right
// message for each watch kind is to be the server.
type fakeServer struct {
	eventspb.UnimplementedNodeEventStreamServer

	mu       sync.Mutex
	received []*eventspb.SubscribeControl
	// push, when set, is called once the client's control stream closes, so a
	// test can drive events back. Most tests only assert on control messages.
	push func(srv eventspb.NodeEventStream_WatchServer) error
}

func (f *fakeServer) Watch(srv eventspb.NodeEventStream_WatchServer) error {
	for {
		msg, err := srv.Recv()
		if err != nil {
			if f.push != nil {
				return f.push(srv)
			}
			return nil
		}
		f.mu.Lock()
		f.received = append(f.received, msg)
		f.mu.Unlock()
	}
}

func (f *fakeServer) controls() []*eventspb.SubscribeControl {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*eventspb.SubscribeControl(nil), f.received...)
}

// startFake wires a Client to an in-process server over bufconn - no ports, no
// node.
func startFake(t *testing.T) (*Client, *fakeServer) {
	t.Helper()
	fake := &fakeServer{}
	return startServer(t, fake), fake
}

// startServer wires a Client to impl over bufconn.
func startServer(t *testing.T, impl eventspb.NodeEventStreamServer) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	eventspb.RegisterNodeEventStreamServer(srv, impl)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
	)
	if err != nil {
		t.Fatalf("dialing the fake: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &Client{conn: conn, rpc: eventspb.NewNodeEventStreamClient(conn)}
}

// waitForControls blocks until the fake has seen n control messages, so an
// assertion never races the server's Recv loop.
func waitForControls(t *testing.T, f *fakeServer, n int) []*eventspb.SubscribeControl {
	t.Helper()
	for i := 0; i < 500; i++ {
		if got := f.controls(); len(got) >= n {
			return got
		}
		// bufconn delivery is fast; a short yield beats a fixed sleep.
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("only %d of %d control messages arrived", len(f.controls()), n)
	return nil
}

func TestWatchControlMessagesPerKind(t *testing.T) {
	client, fake := startFake(t)
	ctx := context.Background()
	h, _, err := client.Watch(ctx)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}

	txA := [32]byte{0x0a}
	txB := [32]byte{0x0b}
	floor := uint64(5000)

	if err := h.AddScripts(ctx, []ScriptWatch{
		{Scripthash: [32]byte{1}, MinValue: &floor},
		{Scripthash: [32]byte{2}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.AddOutpoints(ctx, []OutpointRef{{Txid: txA, Vout: 3}}); err != nil {
		t.Fatal(err)
	}
	if err := h.AddTxLifecycle(ctx, [][32]byte{txA}, AutoCloseAtDepth(6)); err != nil {
		t.Fatal(err)
	}
	if err := h.AddDepthAlarms(ctx, [][32]byte{txA, txB}, []uint32{3, 6}); err != nil {
		t.Fatal(err)
	}
	if err := h.AddDescriptor(ctx, "wpkh(xpub.../<0;1>/*)", 20, 40); err != nil {
		t.Fatal(err)
	}
	if err := h.AddScriptPrefixes(ctx, []ScriptPrefix{{Prefix: []byte{0xab, 0xcd}, Bits: 16}}); err != nil {
		t.Fatal(err)
	}
	if err := h.SetCategories(ctx, CategoryChain|CategoryMempool); err != nil {
		t.Fatal(err)
	}
	if err := h.SetWatchOptions(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := h.SetCursor(ctx, Cursor{Height: 9, TxIndex: 1, MempoolSeq: 2, InstanceID: 3}); err != nil {
		t.Fatal(err)
	}
	if err := h.Rescan(ctx, 100, 200); err != nil {
		t.Fatal(err)
	}

	got := waitForControls(t, fake, 10)

	// AddScripts: a mixed batch must send min_values parallel to scripthashes,
	// with 0 standing in for the unfloored entry - a shorter vector would
	// silently mis-assign floors server-side.
	add := got[0].GetAddScripts()
	if add == nil {
		t.Fatalf("first control was %T, want AddScripts", got[0].GetMsg())
	}
	if len(add.GetScripthashes()) != 2 {
		t.Errorf("scripthashes = %d, want 2", len(add.GetScripthashes()))
	}
	if !reflect.DeepEqual(add.GetMinValues(), []uint64{5000, 0}) {
		t.Errorf("min_values = %v, want [5000 0]", add.GetMinValues())
	}

	if op := got[1].GetAddOutpoints().GetOutpoints(); len(op) != 1 ||
		op[0].GetVout() != 3 || !bytesEqual(op[0].GetTxid(), txA[:]) {
		t.Errorf("AddOutpoints = %v", op)
	}

	// Lifecycle vs depth alarms are ONE wire message dispatched on min_depths:
	// empty selects the lifecycle primitive, non-empty the alarm. Confusing the
	// two registers the wrong kind of watch entirely.
	life := got[2].GetAddTransactions()
	if len(life.GetMinDepths()) != 0 {
		t.Errorf("lifecycle add carried min_depths %v, which selects depth alarms", life.GetMinDepths())
	}
	if life.GetAutoCloseDepth() != 6 {
		t.Errorf("auto_close_depth = %d, want 6", life.GetAutoCloseDepth())
	}

	alarm := got[3].GetAddTransactions()
	if !reflect.DeepEqual(alarm.GetMinDepths(), []uint32{3, 6}) {
		t.Errorf("min_depths = %v, want [3 6] (the server takes the cross product)", alarm.GetMinDepths())
	}
	if len(alarm.GetTxids()) != 2 {
		t.Errorf("txids = %d, want 2", len(alarm.GetTxids()))
	}
	if alarm.GetAutoCloseDepth() != 0 {
		t.Errorf("a depth alarm must not carry an auto-close depth")
	}

	desc := got[4].GetAddDescriptor()
	if desc.GetDescriptor_() != "wpkh(xpub.../<0;1>/*)" || desc.GetGapLimit() != 20 || desc.GetStart() != 40 {
		t.Errorf("AddDescriptor = %+v", desc)
	}

	if pfx := got[5].GetAddScriptPrefixes().GetPrefixes(); len(pfx) != 1 ||
		pfx[0].GetBits() != 16 || !bytesEqual(pfx[0].GetPrefix(), []byte{0xab, 0xcd}) {
		t.Errorf("AddScriptPrefixes = %v", pfx)
	}

	if c := got[6].GetSetCategories().GetCategories(); c != CategoryChain|CategoryMempool {
		t.Errorf("categories = %d", c)
	}
	if !got[7].GetSetWatchOptions().GetIncludeRawTx() {
		t.Error("SetWatchOptions did not set include_raw_tx")
	}
	if c := got[8].GetSetCursor().GetCursor(); c.GetHeight() != 9 || c.GetTxIndex() != 1 ||
		c.GetMempoolSeq() != 2 || c.GetInstanceId() != 3 {
		t.Errorf("SetCursor = %+v", c)
	}
	if r := got[9].GetRescanBlocks(); r.GetFromHeight() != 100 || r.GetToHeight() != 200 {
		t.Errorf("Rescan = %+v", r)
	}
}

func TestWatchRemovalsMirrorTheirAdds(t *testing.T) {
	client, fake := startFake(t)
	ctx := context.Background()
	h, _, err := client.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx := [32]byte{0x0c}

	if err := h.RemoveScripts(ctx, [][32]byte{{1}}); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveOutpoints(ctx, []OutpointRef{{Txid: tx, Vout: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveTxLifecycle(ctx, [][32]byte{tx}); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveDepthAlarms(ctx, [][32]byte{tx}, []uint32{6}); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveDescriptor(ctx, "wpkh(x)"); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveScriptPrefixes(ctx, []ScriptPrefix{{Prefix: []byte{0x01}, Bits: 8}}); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveSilentPayments(ctx, [][33]byte{{0x02}}); err != nil {
		t.Fatal(err)
	}

	got := waitForControls(t, fake, 7)
	if got[0].GetRemoveScripts() == nil {
		t.Error("RemoveScripts did not send its message")
	}
	if got[1].GetRemoveOutpoints() == nil {
		t.Error("RemoveOutpoints did not send its message")
	}
	// The same min_depths dispatch as the adds: a lifecycle removal must not
	// carry depths, or it would target alarms instead.
	if d := got[2].GetRemoveTransactions().GetMinDepths(); len(d) != 0 {
		t.Errorf("lifecycle removal carried min_depths %v", d)
	}
	if d := got[3].GetRemoveTransactions().GetMinDepths(); !reflect.DeepEqual(d, []uint32{6}) {
		t.Errorf("depth-alarm removal min_depths = %v, want [6]", d)
	}
	if got[4].GetRemoveDescriptor().GetDescriptor_() != "wpkh(x)" {
		t.Error("RemoveDescriptor did not carry the descriptor string")
	}
	if got[5].GetRemoveScriptPrefixes() == nil {
		t.Error("RemoveScriptPrefixes did not send its message")
	}
	if got[6].GetRemoveSilentPayments() == nil {
		t.Error("RemoveSilentPayments did not send its message")
	}
}

// TestEmptyRegistrationsSendNothing pins the no-op contract. The depth-alarm
// case is the load-bearing one: an all-invalid call must NOT send an empty
// min_depths, which the server would reinterpret as a LIFECYCLE add - silently
// registering a different, quota-charging watch than the caller asked for.
func TestEmptyRegistrationsSendNothing(t *testing.T) {
	client, fake := startFake(t)
	ctx := context.Background()
	h, _, err := client.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}

	for _, call := range []func() error{
		func() error { return h.AddScripts(ctx, nil) },
		func() error { return h.RemoveScripts(ctx, nil) },
		func() error { return h.AddOutpoints(ctx, nil) },
		func() error { return h.RemoveOutpoints(ctx, nil) },
		func() error { return h.AddTxLifecycle(ctx, nil, AutoCloseNever) },
		func() error { return h.RemoveTxLifecycle(ctx, nil) },
		func() error { return h.AddDepthAlarms(ctx, [][32]byte{{1}}, nil) },
		func() error { return h.AddDepthAlarms(ctx, nil, []uint32{3}) },
		// depths below 1 are dropped; nothing valid is left.
		func() error { return h.AddDepthAlarms(ctx, [][32]byte{{1}}, []uint32{0}) },
		func() error { return h.RemoveDepthAlarms(ctx, [][32]byte{{1}}, []uint32{0}) },
		func() error { return h.AddScriptPrefixes(ctx, nil) },
		func() error { return h.AddSilentPayments(ctx, nil) },
		func() error { return h.RemoveSilentPayments(ctx, nil) },
	} {
		if err := call(); err != nil {
			t.Fatalf("a no-op registration errored: %v", err)
		}
	}

	// Send one real message and wait for it: once the server has that, anything
	// sent before it would already have arrived.
	if err := h.SetCategories(ctx, CategoryChain); err != nil {
		t.Fatal(err)
	}
	got := waitForControls(t, fake, 1)
	if len(got) != 1 || got[0].GetSetCategories() == nil {
		t.Fatalf("expected only the SetCategories message, got %d controls", len(got))
	}
}

func TestPrefixValidationRejectsBadWidths(t *testing.T) {
	client, fake := startFake(t)
	ctx := context.Background()
	h, _, err := client.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}

	bad := []ScriptPrefix{
		{Prefix: []byte{0xab}, Bits: 16},    // 16 bits needs 2 bytes
		{Prefix: nil, Bits: 0},              // below the range
		{Prefix: make([]byte, 5), Bits: 33}, // above the server's 32-bit ceiling
		{Prefix: []byte{1, 2, 3}, Bits: 32}, // 32 bits needs 4 bytes
	}
	for _, p := range bad {
		if err := h.AddScriptPrefixes(ctx, []ScriptPrefix{p}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("prefix %+v: got %v, want ErrInvalidArgument", p, err)
		}
	}

	// One bad entry rejects the whole batch rather than sending a partial
	// registration the caller did not ask for.
	err = h.AddScriptPrefixes(ctx, []ScriptPrefix{
		{Prefix: []byte{0xab, 0xcd}, Bits: 16},
		{Prefix: []byte{0xff}, Bits: 16},
	})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("a batch with one bad entry: got %v, want ErrInvalidArgument", err)
	}

	// Valid boundaries do go out.
	if err := h.AddScriptPrefixes(ctx, []ScriptPrefix{
		{Prefix: []byte{0xde, 0xad, 0xbe, 0xef}, Bits: 32},
		{Prefix: []byte{0x80}, Bits: 1},
	}); err != nil {
		t.Fatalf("valid prefixes rejected: %v", err)
	}
	got := waitForControls(t, fake, 1)
	if len(got) != 1 {
		t.Fatalf("got %d controls, want only the valid batch", len(got))
	}
	if p := got[0].GetAddScriptPrefixes().GetPrefixes(); len(p) != 2 {
		t.Errorf("prefixes = %d, want 2", len(p))
	}
}

func TestSetWatchSetRendersTheWholeSnapshot(t *testing.T) {
	client, fake := startFake(t)
	ctx := context.Background()
	h, _, err := client.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}

	floor := uint64(1000)
	ws := NewWatchSet().
		SetCategories(CategoryChain).
		AddScripts(ScriptWatch{Scripthash: [32]byte{2}, MinValue: &floor}, ScriptWatch{Scripthash: [32]byte{1}}).
		AddOutpoints(OutpointRef{Txid: [32]byte{9}, Vout: 1}).
		AddTxLifecycle(AutoCloseAtDepth(6), [32]byte{3}).
		AddDepthAlarms([][32]byte{{4}}, []uint32{2, 0}).
		AddDescriptor("wpkh(x)", 20, 0).
		AddScriptPrefixes(ScriptPrefix{Prefix: []byte{0xaa, 0xbb}, Bits: 16})

	if err := h.SetWatchSet(ctx, ws); err != nil {
		t.Fatal(err)
	}
	got := waitForControls(t, fake, 1)
	snap := got[0].GetSetWatchSet()
	if snap == nil {
		t.Fatalf("got %T, want SetWatchSet", got[0].GetMsg())
	}
	if snap.GetCategories() != CategoryChain {
		t.Errorf("categories = %d", snap.GetCategories())
	}
	// Deterministic ordering, not Go's randomized map order: the parity harness
	// diffs this against the Rust mirror, which renders from ordered maps.
	if len(snap.GetScripthashes()) != 2 || snap.GetScripthashes()[0][0] != 1 {
		t.Errorf("scripthashes not sorted: %v", snap.GetScripthashes())
	}
	if !reflect.DeepEqual(snap.GetMinValues(), []uint64{0, 1000}) {
		t.Errorf("min_values = %v, want [0 1000] parallel to the sorted hashes", snap.GetMinValues())
	}
	if len(snap.GetOutpoints()) != 1 || len(snap.GetDescriptors()) != 1 || len(snap.GetPrefixes()) != 1 {
		t.Errorf("snapshot lost a kind: %+v", snap)
	}
	if l := snap.GetLifecycles(); len(l) != 1 || l[0].GetAutoCloseDepth() != 6 {
		t.Errorf("lifecycles = %v", l)
	}
	// Depth 0 was dropped, so only the single valid alarm survives.
	if a := snap.GetDepthAlarms(); len(a) != 1 || a[0].GetDepth() != 2 {
		t.Errorf("depth_alarms = %v, want the one valid alarm", a)
	}
	// 2 scripts + 1 outpoint + 1 lifecycle + 1 surviving alarm + 1 descriptor +
	// 1 prefix: the unit the per-connection entry cap counts.
	if ws.Len() != 7 {
		t.Errorf("Len() = %d, want 7 entries", ws.Len())
	}
}

func TestSetWatchSetRejectsAnInvalidPrefix(t *testing.T) {
	client, _ := startFake(t)
	ctx := context.Background()
	h, _, err := client.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ws := NewWatchSet().AddScriptPrefixes(ScriptPrefix{Prefix: []byte{0x01}, Bits: 16})
	if err := h.SetWatchSet(ctx, ws); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("got %v, want ErrInvalidArgument", err)
	}
	if err := h.SetWatchSet(ctx, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("a nil snapshot: got %v, want ErrInvalidArgument", err)
	}
}

// TestSendOnATornDownStreamIsControlClosed: the resilience layer keys its
// "re-register on a fresh stream" behavior off this class, so a dead stream must
// not surface as a generic transport error.
func TestSendOnATornDownStreamIsControlClosed(t *testing.T) {
	client, _ := startFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	h, _, err := client.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()

	// The cancellation propagates asynchronously; retry until the stream reports
	// itself gone rather than sleeping a fixed interval.
	for i := 0; i < 500; i++ {
		err = h.SetCategories(context.Background(), CategoryChain)
		if err != nil {
			break
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	if err == nil {
		t.Fatal("sending on a cancelled stream eventually has to fail")
	}
	if !errors.Is(err, ErrControlClosed) && !errors.Is(err, ErrTransport) {
		t.Errorf("got %v, want ErrControlClosed (or a transport error)", err)
	}
}

func TestSendHonorsContextCancellation(t *testing.T) {
	client, _ := startFake(t)
	h, _, err := client.Watch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.SetCategories(ctx, CategoryChain); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want context.Canceled", err)
	}
}

func bytesEqual(a, b []byte) bool {
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
