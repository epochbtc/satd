package satdevents

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

func mustVersion(t *testing.T, s string) version {
	t.Helper()
	v, ok := parseVersion(s)
	if !ok {
		t.Fatalf("parseVersion(%q) failed", s)
	}
	return v
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]version{
		"0.6.0":       {0, 6},
		"0.6.0-pre":   {0, 6},
		"1.0":         {1, 0},
		"0.6":         {0, 6},
		"0.6.0+build": {0, 6},
		"0.12.3-rc.1": {0, 12},
	} {
		if got, ok := parseVersion(in); !ok || got != want {
			t.Errorf("parseVersion(%q) = %v, %v; want %v", in, got, ok, want)
		}
	}
	for _, in := range []string{"garbage", "", "1", "0.x.0", "0.6.x", "0.6.0.1", "-1.2.0"} {
		if got, ok := parseVersion(in); ok {
			t.Errorf("parseVersion(%q) = %v, want a failure", in, got)
		}
	}
}

// TestClassifyMatchesThePolicyTable is the worked-example table from the
// policy, row by row. The Rust SDK's classify_matches_the_policy_table pins the
// same rows.
func TestClassifyMatchesThePolicyTable(t *testing.T) {
	const missing = "<missing>"
	rows := []struct {
		sdk, header string
		want        compat
	}{
		{"0.6.0", "0.6.0", compatOK},
		{"0.6.0", "0.6.0-pre", compatOK},
		{"0.6.0-pre", "0.7.3", compatOK},
		{"0.6.0", "1.0.0", compatOK},
		{"0.6.0-pre", "0.5.2", compatOneBehind},
		{"0.6.0", missing, compatOneBehind},
		{"0.7.0", "0.5.2", compatTooOld},
		{"0.7.0", missing, compatTooOld},
		{"1.1.0", "0.9.0", compatTooOld},
		{"0.6.0", "garbage", compatOneBehind},
		{"1.0.0", "0.9.9", compatTooOld},
	}
	for _, r := range rows {
		md := metadata.MD{}
		if r.header != missing {
			md.Set(versionHeader, r.header)
		}
		_, node := nodeVersionFromMD(md)
		if got := classify(mustVersion(t, r.sdk), node); got != r.want {
			t.Errorf("sdk %s, node header %s: got %d, want %d", r.sdk, r.header, got, r.want)
		}
	}
}

func TestSchemaFromMD(t *testing.T) {
	for header, want := range map[string]uint32{"": 1, "1": 1, "2": 2, "one": 0} {
		md := metadata.MD{}
		if header != "" {
			md.Set(schemaHeader, header)
		}
		if got := schemaFromMD(md); got != want {
			t.Errorf("schema header %q: got %d, want %d", header, got, want)
		}
	}
}

func TestNodeVersionFromMDKeepsTheRawHeader(t *testing.T) {
	if raw, v := nodeVersionFromMD(metadata.MD{}); raw != "" || v != headerlessNode {
		t.Errorf("missing: %q %v", raw, v)
	}
	if raw, v := nodeVersionFromMD(metadata.Pairs(versionHeader, "garbage")); raw != "garbage" || v != headerlessNode {
		t.Errorf("garbage: %q %v", raw, v)
	}
	if raw, v := nodeVersionFromMD(metadata.Pairs(versionHeader, "0.7.1")); raw != "0.7.1" || v != (version{0, 7}) {
		t.Errorf("0.7.1: %q %v", raw, v)
	}
}

// --- the check, through a fake node ------------------------------------------

// versionFake is a node stand-in for the version check: every stream stays
// open, optionally after one heartbeat with a chosen schema_version.
type versionFake struct {
	eventspb.UnimplementedNodeEventStreamServer

	headers     atomic.Pointer[nodeHeaders]
	eventSchema uint32 // 0: send no event
	opens       atomic.Int32
}

func newVersionFake(h nodeHeaders) *versionFake {
	f := &versionFake{}
	f.headers.Store(&h)
	return f
}

func (f *versionFake) current() nodeHeaders { return *f.headers.Load() }

func (f *versionFake) serve(ctx context.Context, send func(*eventspb.NodeEvent) error) error {
	f.opens.Add(1)
	if f.eventSchema != 0 {
		err := send(&eventspb.NodeEvent{
			SchemaVersion: f.eventSchema,
			Body:          &eventspb.NodeEvent_Heartbeat{Heartbeat: &eventspb.Heartbeat{UptimeNs: 1}},
		})
		if err != nil {
			return err
		}
	}
	<-ctx.Done()
	return nil
}

func (f *versionFake) Subscribe(_ *eventspb.SubscribeRequest, srv eventspb.NodeEventStream_SubscribeServer) error {
	return f.serve(srv.Context(), srv.Send)
}

func (f *versionFake) Watch(srv eventspb.NodeEventStream_WatchServer) error {
	return f.serve(srv.Context(), srv.Send)
}

func startVersionFake(t *testing.T, f *versionFake, opts ...Option) *Client {
	t.Helper()
	return startServerAs(t, f, f.current, opts...)
}

// logBuffer collects slog output; safe for the concurrent writes gRPC may cause.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) warnings() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, line := range strings.Split(b.buf.String(), "\n") {
		if strings.Contains(line, "level=WARN") {
			out = append(out, line)
		}
	}
	return out
}

func newLogger() (*slog.Logger, *logBuffer) {
	buf := &logBuffer{}
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

func sdkVersion(t *testing.T) version { return mustVersion(t, Version) }

// minorsBehind is a node version n minor versions behind this build's SDK,
// derived so the tests keep meaning the same thing after every version bump.
func minorsBehind(t *testing.T, n uint64) (string, bool) {
	v := sdkVersion(t)
	if v.minor < n {
		return "", false
	}
	return fmt.Sprintf("%d.%d.0", v.major, v.minor-n), true
}

// tooOld is a node version the SDK refuses: two minors behind, or failing that
// a major behind.
func tooOld(t *testing.T) string {
	if s, ok := minorsBehind(t, 2); ok {
		return s
	}
	return fmt.Sprintf("%d.9.0", sdkVersion(t).major-1)
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestSameVersionNodeOpensSilently(t *testing.T) {
	logger, logs := newLogger()
	client := startVersionFake(t, newVersionFake(sameVersionNode()), WithLogger(logger))
	ctx := testCtx(t)
	if _, err := client.Subscribe(ctx, SubscribeOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.Watch(ctx); err != nil {
		t.Fatal(err)
	}
	if w := logs.warnings(); len(w) != 0 {
		t.Errorf("unexpected warnings: %q", w)
	}
}

func TestNewerNodeOpensSilently(t *testing.T) {
	logger, logs := newLogger()
	v := sdkVersion(t)
	client := startVersionFake(t,
		newVersionFake(nodeHeaders{version: fmt.Sprintf("%d.%d.0", v.major, v.minor+3), schema: "1"}),
		WithLogger(logger))
	if _, err := client.Subscribe(testCtx(t), SubscribeOptions{}); err != nil {
		t.Fatal(err)
	}
	if w := logs.warnings(); len(w) != 0 {
		t.Errorf("unexpected warnings: %q", w)
	}
}

// TestHeaderlessNodeIsTreatedAs05: a node that sends no headers is taken to be
// 0.5; what that means depends on this build's version, so the expectation is
// derived from the rule.
func TestHeaderlessNodeIsTreatedAs05(t *testing.T) {
	logger, _ := newLogger()
	client := startVersionFake(t, newVersionFake(nodeHeaders{}), WithLogger(logger))
	_, err := client.Subscribe(testCtx(t), SubscribeOptions{})
	if classify(sdkVersion(t), headerlessNode) == compatTooOld {
		if !errors.Is(err, ErrNodeTooOld) {
			t.Fatalf("got %v, want ErrNodeTooOld", err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	if got := client.NodeVersion(); got != "" {
		t.Errorf("NodeVersion() = %q for a headerless node", got)
	}
}

func TestTwoMinorsBehindIsRefused(t *testing.T) {
	old := tooOld(t)
	fake := newVersionFake(nodeHeaders{version: old, schema: "1"})
	client := startVersionFake(t, fake)
	ctx := testCtx(t)

	_, err := client.Subscribe(ctx, SubscribeOptions{})
	if !errors.Is(err, ErrNodeTooOld) {
		t.Fatalf("Subscribe: got %v, want ErrNodeTooOld", err)
	}
	var serr *Error
	if !errors.As(err, &serr) || serr.NodeVersion != old {
		t.Errorf("error does not carry the node version %q: %#v", old, serr)
	}
	if !strings.Contains(err.Error(), old) || !strings.Contains(err.Error(), Version) {
		t.Errorf("message does not name both versions: %v", err)
	}
	if Retryable(err) {
		t.Error("ErrNodeTooOld must not be retryable")
	}

	if _, _, err := client.Watch(ctx); !errors.Is(err, ErrNodeTooOld) {
		t.Fatalf("Watch: got %v, want ErrNodeTooOld", err)
	}
}

func TestAllowOldNodeDowngradesTheRefusalToAWarning(t *testing.T) {
	logger, logs := newLogger()
	client := startVersionFake(t, newVersionFake(nodeHeaders{version: tooOld(t), schema: "1"}),
		WithAllowOldNode(), WithLogger(logger))
	if _, err := client.Subscribe(testCtx(t), SubscribeOptions{}); err != nil {
		t.Fatal(err)
	}
	if w := logs.warnings(); len(w) != 1 {
		t.Errorf("warnings = %q, want exactly one", w)
	}
}

func TestSchemaHeaderMismatchIsRefusedEvenWithAllowOldNode(t *testing.T) {
	client := startVersionFake(t, newVersionFake(nodeHeaders{version: Version, schema: "2"}),
		WithAllowOldNode())
	ctx := testCtx(t)
	_, err := client.Subscribe(ctx, SubscribeOptions{})
	if !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("Subscribe: got %v, want ErrSchemaMismatch", err)
	}
	var serr *Error
	if !errors.As(err, &serr) || serr.NodeSchema != 2 {
		t.Errorf("error does not carry the node schema: %#v", serr)
	}
	if Retryable(err) {
		t.Error("ErrSchemaMismatch must not be retryable")
	}
	if _, _, err := client.Watch(ctx); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("Watch: got %v, want ErrSchemaMismatch", err)
	}
}

// TestFirstEventSchemaMismatchIsRefused: a node that predates the headers still
// stamps schema_version on every event; the first one is checked.
func TestFirstEventSchemaMismatchIsRefused(t *testing.T) {
	fake := newVersionFake(sameVersionNode())
	fake.eventSchema = 2
	client := startVersionFake(t, fake)
	ctx := testCtx(t)
	stream, err := client.Subscribe(ctx, SubscribeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("got %v, want ErrSchemaMismatch", err)
	}

	// The matching schema passes through as an ordinary event.
	fake = newVersionFake(sameVersionNode())
	fake.eventSchema = 1
	client = startVersionFake(t, fake)
	_, stream, err = client.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ev.(*Heartbeat); !ok {
		t.Fatalf("got %T, want *Heartbeat", ev)
	}
}

func TestOneBehindWarnsOncePerNodeVersion(t *testing.T) {
	// At a .0 minor there is no one-behind in the same major; the downgraded
	// refusal logs the same warning.
	behind, ok := minorsBehind(t, 1)
	opts := []Option{}
	if !ok {
		behind = tooOld(t)
		opts = append(opts, WithAllowOldNode())
	}
	logger, logs := newLogger()
	fake := newVersionFake(nodeHeaders{version: behind, schema: "1"})
	client := startVersionFake(t, fake, append(opts, WithLogger(logger))...)
	ctx := testCtx(t)

	for i := 0; i < 2; i++ {
		if _, err := client.Subscribe(ctx, SubscribeOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := client.Watch(ctx); err != nil {
		t.Fatal(err)
	}
	w := logs.warnings()
	if len(w) != 1 {
		t.Fatalf("warnings = %q, want exactly one", w)
	}
	for _, want := range []string{
		"node_version=" + behind,
		"sdk_version=" + Version,
		"is older than this SDK",
	} {
		if !strings.Contains(w[0], want) {
			t.Errorf("warning %q lacks %q", w[0], want)
		}
	}

	// The node changes version (a rolling downgrade, say): warn again, once.
	fake.headers.Store(&nodeHeaders{version: behind + "-other", schema: "1"})
	for i := 0; i < 2; i++ {
		if _, err := client.Subscribe(ctx, SubscribeOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if w := logs.warnings(); len(w) != 2 {
		t.Errorf("warnings = %q, want two", w)
	}
}

// lockProbe is a slog.Handler that records, for each record, whether the
// client's compat lock was free.
type lockProbe struct {
	client **Client
	mu     sync.Mutex
	free   []bool
}

func (h *lockProbe) Enabled(context.Context, slog.Level) bool { return true }
func (h *lockProbe) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *lockProbe) WithGroup(string) slog.Handler            { return h }
func (h *lockProbe) Handle(context.Context, slog.Record) error {
	c := *h.client
	free := c.compatMu.TryLock()
	if free {
		c.compatMu.Unlock()
	}
	h.mu.Lock()
	h.free = append(h.free, free)
	h.mu.Unlock()
	return nil
}

// TestWarningIsLoggedWithoutHoldingTheCompatLock: the handler behind WithLogger
// is user code. One that calls NodeVersion from inside Handle would deadlock if
// the warning were logged under the lock, and a slow one would stall every
// stream open.
func TestWarningIsLoggedWithoutHoldingTheCompatLock(t *testing.T) {
	behind, ok := minorsBehind(t, 1)
	opts := []Option{}
	if !ok {
		behind = tooOld(t)
		opts = append(opts, WithAllowOldNode())
	}
	var client *Client
	probe := &lockProbe{client: &client}
	client = startVersionFake(t, newVersionFake(nodeHeaders{version: behind, schema: "1"}),
		append(opts, WithLogger(slog.New(probe)))...)
	if _, err := client.Subscribe(testCtx(t), SubscribeOptions{}); err != nil {
		t.Fatal(err)
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if len(probe.free) == 0 {
		t.Fatal("the warning was not logged")
	}
	for _, free := range probe.free {
		if !free {
			t.Fatalf("a record was logged under the compat lock: %v", probe.free)
		}
	}
}

func TestNodeVersionIsRecordedOnceAStreamOpens(t *testing.T) {
	client := startVersionFake(t, newVersionFake(sameVersionNode()))
	if got := client.NodeVersion(); got != "" {
		t.Fatalf("NodeVersion() = %q before any stream", got)
	}
	if _, err := client.Subscribe(testCtx(t), SubscribeOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := client.NodeVersion(); got != Version {
		t.Errorf("NodeVersion() = %q, want %q", got, Version)
	}
}

func TestResilientSubscribeSurfacesNodeTooOldWithoutRetrying(t *testing.T) {
	fake := newVersionFake(nodeHeaders{version: tooOld(t), schema: "1"})
	client := startVersionFake(t, fake)
	sub := client.ResilientSubscribe(context.Background(), SubscribeOptions{}, ResilientConfig{})
	defer func() { _ = sub.Close() }()
	if _, err := sub.Next(testCtx(t)); !errors.Is(err, ErrNodeTooOld) {
		t.Fatalf("got %v, want ErrNodeTooOld", err)
	}
	if n := fake.opens.Load(); n != 1 {
		t.Errorf("%d subscribe attempts, want exactly 1", n)
	}
}

func TestResilientWatchSurfacesNodeTooOldWithoutRetrying(t *testing.T) {
	fake := newVersionFake(nodeHeaders{version: tooOld(t), schema: "1"})
	client := startVersionFake(t, fake)
	w := client.ResilientWatch(context.Background(), ResilientWatchConfig{})
	defer func() { _ = w.Close() }()
	if _, err := w.Next(testCtx(t)); !errors.Is(err, ErrNodeTooOld) {
		t.Fatalf("got %v, want ErrNodeTooOld", err)
	}
	if n := fake.opens.Load(); n != 1 {
		t.Errorf("%d watch attempts, want exactly 1", n)
	}
}
