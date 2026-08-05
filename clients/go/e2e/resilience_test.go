//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	satdevents "github.com/epochbtc/satd/clients/go"
)

// dialLagProne opens a client whose HTTP/2 flow-control windows are pinned to
// the 64 KiB floor grpc-go allows. Setting them explicitly also disables the
// dynamic BDP window growth, which would otherwise expand the window until an
// unread client could absorb far more than the node's shrunk broadcast buffer -
// and no Lagged would ever be produced. The Rust E2E forces lag the same way.
func dialLagProne(t *testing.T, n *node) *satdevents.Client {
	t.Helper()
	c, err := satdevents.Dial(context.Background(), n.grpcTarget(),
		satdevents.WithGRPCDialOption(
			grpc.WithInitialWindowSize(65536),
			grpc.WithInitialConnWindowSize(65536),
		))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// nextResilient drives sub until an event arrives, failing on error.
func nextResilient(t *testing.T, sub *satdevents.ResilientSubscription, secs float64) satdevents.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout(secs))
	defer cancel()
	ev, err := sub.Next(ctx)
	if err != nil {
		t.Fatalf("resilient Next: %v", err)
	}
	return ev
}

// awaitLive reads one event to prove the subscription is actually registered
// server-side. ResilientSubscribe connects on a background goroutine, so mining
// immediately after it returns can race the subscribe and produce blocks the
// stream never sees - with nothing persisted yet, there is no cursor to replay
// them from either, and the test hangs. Heartbeats arrive every second, so this
// costs at most about a second.
func awaitLive(t *testing.T, sub *satdevents.ResilientSubscription) {
	t.Helper()
	nextResilient(t, sub, 30)
}

// blocksUntil drives sub collecting BlockConnected heights until want is seen,
// returning them in order. Anything else on the stream is ignored.
func blocksUntil(t *testing.T, sub *satdevents.ResilientSubscription, want uint32, secs float64) []uint32 {
	t.Helper()
	var heights []uint32
	deadline := time.Now().Add(timeout(secs))
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout(secs))
		ev, err := sub.Next(ctx)
		cancel()
		if err != nil {
			t.Fatalf("resilient Next (saw %v): %v", heights, err)
		}
		b, ok := ev.(*satdevents.BlockConnected)
		if !ok {
			continue
		}
		heights = append(heights, b.Height)
		if b.Height >= want {
			return heights
		}
	}
	t.Fatalf("never reached height %d; saw %v", want, heights)
	return nil
}

// TestE2EResilientResumesAcrossAProcessRestart is the durability contract end
// to end: a consumer that persists its cursor and dies picks up where it left
// off against a restarted node, with no block missed and none skipped.
//
// The restart is the real thing - satd exits and comes back on the same datadir
// with a fresh publisher instance id - so this also covers the SDK not being
// confused by the instance id changing under it.
func TestE2EResilientResumesAcrossAProcessRestart(t *testing.T) {
	n := startNode(t)
	cursorPath := filepath.Join(t.TempDir(), "cursor")
	store := satdevents.NewFileCursorStore(cursorPath)

	client := n.dial(t)
	sub := client.ResilientSubscribe(context.Background(),
		satdevents.SubscribeOptions{},
		satdevents.ResilientConfig{CursorStore: store})
	awaitLive(t, sub)

	n.mine(3, walletA)
	first := blocksUntil(t, sub, n.blockCount(), 60)
	last := first[len(first)-1]

	// Commit explicitly, the way a clean shutdown would, then stop consuming.
	if err := sub.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := sub.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got, err := satdevents.NewFileCursorStore(cursorPath).Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	} else if got == nil || got.Height != last {
		t.Fatalf("persisted cursor = %v, want height %d", got, last)
	}

	// Blocks that land while the consumer is down must not be lost.
	n.mine(4, walletA)
	n.restart()
	tip := n.blockCount()

	// A brand-new client and subscription, sharing only the cursor file.
	client2 := n.dial(t)
	sub2 := client2.ResilientSubscribe(context.Background(),
		satdevents.SubscribeOptions{},
		satdevents.ResilientConfig{CursorStore: satdevents.NewFileCursorStore(cursorPath)})
	defer func() { _ = sub2.Close() }()

	resumed := blocksUntil(t, sub2, tip, 90)
	if len(resumed) == 0 {
		t.Fatal("the resumed subscription delivered nothing")
	}
	// Replay is inclusive of the anchor at worst, so the first block back is
	// either the committed one or the one after it - never further ahead, which
	// would mean the downtime blocks were silently skipped.
	if resumed[0] > last+1 {
		t.Errorf("resumed at height %d after committing %d - blocks %d..%d were skipped",
			resumed[0], last, last+1, resumed[0]-1)
	}
	for i := 1; i < len(resumed); i++ {
		if resumed[i] != resumed[i-1]+1 {
			t.Errorf("gap in the resumed stream: %d then %d", resumed[i-1], resumed[i])
		}
	}
	if resumed[len(resumed)-1] != tip {
		t.Errorf("resumed stream ended at %d, want the tip %d", resumed[len(resumed)-1], tip)
	}
}

// TestE2EResilientReconnectsThroughADroppedConnection: the transport dies under
// the subscription and the consumer never notices - it keeps calling Next and
// keeps getting every block, in order.
//
// The node is reached through an in-test TCP proxy so the connection can be cut
// without stopping satd. A node restart moves the streaming port, which a fixed
// dial target could not follow; this isolates "the socket broke" from "the node
// went away".
func TestE2EResilientReconnectsThroughADroppedConnection(t *testing.T) {
	n := startNode(t)
	proxy := startProxy(t, n.grpcTarget())

	client, err := satdevents.Dial(context.Background(), proxy.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	sub := client.ResilientSubscribe(context.Background(),
		satdevents.SubscribeOptions{},
		satdevents.ResilientConfig{Backoff: satdevents.Backoff{
			Initial:    50 * time.Millisecond,
			Max:        time.Second,
			Multiplier: 2,
		}})
	defer func() { _ = sub.Close() }()

	awaitLive(t, sub)
	n.mine(2, walletA)
	before := blocksUntil(t, sub, n.blockCount(), 60)
	last := before[len(before)-1]

	// Cut every proxied connection, then keep the chain moving.
	proxy.cutAll()
	n.mine(3, walletA)
	tip := n.blockCount()

	after := blocksUntil(t, sub, tip, 90)
	if len(after) == 0 {
		t.Fatal("nothing arrived after the connection was cut")
	}
	if after[0] > last+1 {
		t.Errorf("resumed at %d after %d - blocks %d..%d were dropped by the reconnect",
			after[0], last, last+1, after[0]-1)
	}
	for i := 1; i < len(after); i++ {
		if after[i] != after[i-1]+1 {
			t.Errorf("gap after the reconnect: %d then %d", after[i-1], after[i])
		}
	}
	if proxy.dialCount() < 2 {
		t.Errorf("the proxy saw %d connection(s); the SDK never actually reconnected",
			proxy.dialCount())
	}
}

// TestE2ELagAutoResumeRecoversASlowConsumer: a consumer that stops reading long
// enough for the node's broadcast buffer to overflow gets re-anchored
// transparently and carries on, rather than seeing a Lagged or a hole.
//
// The node runs with a deliberately tiny broadcast buffer (a supported test
// knob) so a handful of events overflows it instead of tens of thousands.
func TestE2ELagAutoResumeRecoversASlowConsumer(t *testing.T) {
	n := startNodeEnv(t, []string{"SATD_EVENT_BROADCAST_CAPACITY=2"})
	client := dialLagProne(t, n)

	sub := client.ResilientSubscribe(context.Background(),
		satdevents.SubscribeOptions{},
		satdevents.ResilientConfig{
			LagPolicy: satdevents.LagAutoResume,
			Backoff: satdevents.Backoff{
				Initial: 50 * time.Millisecond, Max: time.Second, Multiplier: 2,
			},
		})
	defer func() { _ = sub.Close() }()

	// Establish the stream, then stop reading. The pump parks on the handoff, so
	// it stops draining the socket and the node's per-subscriber buffer fills.
	awaitLive(t, sub)
	n.mine(1, walletA)
	first := blocksUntil(t, sub, n.blockCount(), 60)[0] + 1

	time.Sleep(timeout(1))
	n.mine(1200, walletA)
	tip := n.blockCount()
	time.Sleep(timeout(2))

	// Under LagAutoResume the caller must never be handed a Lagged, and - the
	// part that matters - must still see EVERY block. A lag that was not
	// recovered from shows up as a hole in the heights, since the dropped events
	// are exactly the ones the node could not buffer. That the burst really does
	// overflow the node's buffer is pinned by the sibling LagSurface test, which
	// runs the same node config and the same burst.
	seen := map[uint32]bool{}
	deadline := time.Now().Add(timeout(120))
	var lastSeen uint32
	for time.Now().Before(deadline) && lastSeen < tip {
		ev := nextResilient(t, sub, 60)
		if _, isLag := ev.(*satdevents.Lagged); isLag {
			t.Fatal("LagAutoResume surfaced a Lagged to the caller")
		}
		if b, ok := ev.(*satdevents.BlockConnected); ok {
			seen[b.Height] = true
			lastSeen = b.Height
		}
	}
	if lastSeen != tip {
		t.Fatalf("recovered only to height %d, want the tip %d", lastSeen, tip)
	}
	var missing []uint32
	for h := first; h <= tip; h++ {
		if !seen[h] {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		show := missing
		if len(show) > 10 {
			show = show[:10]
		}
		t.Errorf("%d block(s) lost to the lag, e.g. %v - the re-anchor did not "+
			"replay what the node dropped", len(missing), show)
	}
}

// TestE2ELagSurfaceHandsTheNoticeToTheCaller is the other half of the policy:
// with LagSurface the consumer sees the notice itself and decides what to do.
func TestE2ELagSurfaceHandsTheNoticeToTheCaller(t *testing.T) {
	n := startNodeEnv(t, []string{"SATD_EVENT_BROADCAST_CAPACITY=2"})
	client := dialLagProne(t, n)

	sub := client.ResilientSubscribe(context.Background(),
		satdevents.SubscribeOptions{},
		satdevents.ResilientConfig{LagPolicy: satdevents.LagSurface})
	defer func() { _ = sub.Close() }()

	awaitLive(t, sub)
	n.mine(1, walletA)
	blocksUntil(t, sub, n.blockCount(), 60)

	time.Sleep(timeout(1))
	n.mine(1200, walletA)
	time.Sleep(timeout(2))

	deadline := time.Now().Add(timeout(120))
	for time.Now().Before(deadline) {
		ev := nextResilient(t, sub, 60)
		lag, ok := ev.(*satdevents.Lagged)
		if !ok {
			continue
		}
		if lag.DroppedCount == 0 {
			t.Errorf("Lagged reported 0 dropped events")
		}
		if lag.ResumeCursor == nil {
			t.Error("Lagged carried no resume cursor, so the caller cannot re-anchor")
		}
		return
	}
	t.Fatal("no Lagged surfaced under LagSurface despite a 2-event node buffer")
}

// TestE2EResilientSurfacesAPermanentFailure: a node that goes away for good
// must not leave the consumer reconnecting in silence forever when a retry
// budget was set.
func TestE2EResilientSurfacesAPermanentFailure(t *testing.T) {
	n := startNode(t)
	client := n.dial(t)
	sub := client.ResilientSubscribe(context.Background(), satdevents.SubscribeOptions{},
		satdevents.ResilientConfig{Backoff: satdevents.Backoff{
			Initial: 20 * time.Millisecond, Max: 100 * time.Millisecond,
			Multiplier: 2, MaxRetries: 3,
		}})
	defer func() { _ = sub.Close() }()

	// Drain whatever is flowing (heartbeats at worst) so the stream is live.
	nextResilient(t, sub, 30)
	n.kill()

	ctx, cancel := context.WithTimeout(context.Background(), timeout(60))
	defer cancel()
	for {
		_, err := sub.Next(ctx)
		if err == nil {
			continue
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("the retry budget never ran out; Next hung until the deadline")
		}
		if err == io.EOF {
			t.Fatal("the subscription closed itself instead of surfacing the failure")
		}
		return // a real error reached the caller, which is the contract
	}
}

// ---- TCP proxy --------------------------------------------------------------

// tcpProxy forwards to a fixed backend and can drop every live connection on
// demand, which is how these tests break the transport without stopping satd.
type tcpProxy struct {
	listener net.Listener

	mu    sync.Mutex
	conns []net.Conn
	dials int
}

func startProxy(t *testing.T, backend string) *tcpProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &tcpProxy{listener: l}
	t.Cleanup(func() {
		_ = l.Close()
		p.cutAll()
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", backend)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, up)
			p.dials++
			p.mu.Unlock()
			go func() { _, _ = io.Copy(up, c) }()
			go func() { _, _ = io.Copy(c, up) }()
		}
	}()
	return p
}

func (p *tcpProxy) addr() string {
	return fmt.Sprintf("127.0.0.1:%d", p.listener.Addr().(*net.TCPAddr).Port)
}

// cutAll closes every connection the proxy has relayed, in both directions.
func (p *tcpProxy) cutAll() {
	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// dialCount is how many client connections the proxy has accepted; more than
// one means the SDK really did re-dial.
func (p *tcpProxy) dialCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dials
}
