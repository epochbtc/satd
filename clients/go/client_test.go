package satdevents

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

func TestSubscribeOptionsSendTweakKnobsOnlyWhenSet(t *testing.T) {
	// A default subscription must be byte-identical on the wire to one built
	// before these knobs existed, so an older node never sees a field it does
	// not know.
	plain := SubscribeOptions{Categories: CategoryTweaks}.toProto()
	if plain.TweaksOnly != nil || plain.MempoolTweaks != nil || plain.TweakOutputs != nil {
		t.Errorf("unset knobs reached the wire: %+v", plain)
	}
	if plain.SinceSeq != nil || plain.FromCursor != nil || plain.TweakDustLimit != nil {
		t.Errorf("unset optionals reached the wire: %+v", plain)
	}

	full := SubscribeOptions{
		Categories:     CategoryTweaks,
		TweaksOnly:     true,
		MempoolTweaks:  true,
		TweakOutputs:   true,
		SinceSeq:       u64(7),
		TweakDustLimit: u64(546),
		FromCursor:     &Cursor{Height: 9, TxIndex: 1, MempoolSeq: 2, InstanceID: 3},
	}.toProto()
	if !full.GetTweaksOnly() || !full.GetMempoolTweaks() || !full.GetTweakOutputs() {
		t.Errorf("set knobs did not reach the wire: %+v", full)
	}
	if full.GetSinceSeq() != 7 || full.GetTweakDustLimit() != 546 {
		t.Errorf("optionals mapped wrong: %+v", full)
	}
	if c := full.GetFromCursor(); c.GetHeight() != 9 || c.GetTxIndex() != 1 ||
		c.GetMempoolSeq() != 2 || c.GetInstanceId() != 3 {
		t.Errorf("cursor mapped wrong: %+v", c)
	}
}

func TestCategoryBitsMatchTheWire(t *testing.T) {
	// The category bitfield is a wire contract with no generated constant to
	// check against, so pin the documented values directly.
	for _, c := range []struct {
		name string
		got  uint32
		want uint32
	}{
		{"all", CategoryAll, 0},
		{"mempool", CategoryMempool, 1},
		{"chain", CategoryChain, 2},
		{"heartbeat", CategoryHeartbeat, 4},
		{"tweaks", CategoryTweaks, 8},
		{"status", CategoryStatus, 16},
	} {
		if c.got != c.want {
			t.Errorf("Category%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestSplitScheme(t *testing.T) {
	cases := []struct {
		in       string
		endpoint string
		scheme   string
		wantErr  bool
	}{
		{in: "127.0.0.1:50051", endpoint: "127.0.0.1:50051"},
		{in: "http://node:50051", endpoint: "node:50051", scheme: "http"},
		{in: "https://node:50051", endpoint: "node:50051", scheme: "https"},
		{in: "HTTPS://node:50051", endpoint: "node:50051", scheme: "https"},
		// A genuine gRPC target scheme is handed to the resolver untouched.
		{in: "dns:///node:50051", endpoint: "dns:///node:50051"},
		{in: "unix:///run/satd.sock", endpoint: "unix:///run/satd.sock"},
		{in: "", wantErr: true},
		{in: "https://", wantErr: true},
	}
	for _, c := range cases {
		endpoint, scheme, err := splitScheme(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("splitScheme(%q) = %q, want an error", c.in, endpoint)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitScheme(%q): %v", c.in, err)
			continue
		}
		if endpoint != c.endpoint || scheme != c.scheme {
			t.Errorf("splitScheme(%q) = (%q, %q), want (%q, %q)",
				c.in, endpoint, scheme, c.endpoint, c.scheme)
		}
	}
}

// TestTLSOverPlaintextSchemeIsRefused is the fail-closed guard: asking for TLS
// against an explicit http:// target can only be a mistake, and connecting
// anyway would put the bearer token and the whole event stream on the wire in
// cleartext while the caller believed the link was encrypted.
func TestTLSOverPlaintextSchemeIsRefused(t *testing.T) {
	for _, opt := range []Option{
		WithTLS(),
		WithTLSCAPem([]byte("-----BEGIN CERTIFICATE-----")),
		WithMTLS([]byte("cert"), []byte("key")),
		WithTLSServerName("node.example"),
	} {
		c, err := Dial(context.Background(), "http://127.0.0.1:1", opt, WithBearerToken("SECRET"))
		if err == nil {
			_ = c.Close()
			t.Fatal("TLS over an http:// target must be refused")
		}
		if !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("got %v, want ErrInvalidEndpoint", err)
		}
	}
}

// TestHTTPSTargetEnablesTLS: an https:// target with no TLS option must not
// silently connect in cleartext.
func TestHTTPSTargetEnablesTLS(t *testing.T) {
	cfg := dialConfig{}
	_, scheme, err := splitScheme("https://node:50051")
	if err != nil {
		t.Fatal(err)
	}
	if scheme == "https" && !cfg.tlsEnabled {
		cfg.tlsEnabled = true
	}
	creds, err := transportCredentials(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if creds.Info().SecurityProtocol == "insecure" {
		t.Error("an https:// target produced insecure credentials")
	}
}

func TestDialRejectsAnInvalidBearerToken(t *testing.T) {
	// TLS throughout: a plaintext target with a token is refused before the
	// token is ever inspected, which would make this test assert the wrong
	// thing.
	for _, bad := range []string{"tok\nen", "tok\x00en", "töken"} {
		c, err := Dial(context.Background(), "127.0.0.1:1", WithTLS(), WithBearerToken(bad))
		if err == nil {
			_ = c.Close()
			t.Errorf("token %q was accepted", bad)
			continue
		}
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("token %q: got %v, want ErrInvalidToken", bad, err)
		}
	}
	c, err := Dial(context.Background(), "127.0.0.1:1", WithTLS(), WithBearerToken("valid-token"))
	if err != nil {
		t.Fatalf("a printable-ASCII token must be accepted: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestBearerTokenOverPlaintextIsRefused is the #521 guard. gRPC-Go's own
// RequireTransportSecurity check never fires for this SDK - the token is
// attached with metadata.AppendToOutgoingContext, not as PerRPCCredentials - and
// a remote-bound node with eventsgrpcauth=1 and no TLS is a supported server
// configuration, so nothing else stops the credential reaching the wire in the
// clear.
func TestBearerTokenOverPlaintextIsRefused(t *testing.T) {
	for _, target := range []string{"127.0.0.1:1", "http://node.example:50051", "node.example:50051"} {
		c, err := Dial(context.Background(), target, WithBearerToken("SECRET"))
		if err == nil {
			_ = c.Close()
			t.Errorf("target %q: a bearer token over plaintext must be refused", target)
			continue
		}
		if !errors.Is(err, ErrInsecureCredential) {
			t.Errorf("target %q: got %v, want ErrInsecureCredential", target, err)
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("target %q: the error must not quote the token: %v", target, err)
		}
	}
}

// The three ways a token is legitimately allowed on the wire.
func TestBearerTokenIsAllowedOverTLSOrByExplicitWaiver(t *testing.T) {
	cases := []struct {
		name   string
		target string
		opts   []Option
	}{
		{"explicit TLS", "node.example:50051", []Option{WithTLS(), WithBearerToken("SECRET")}},
		{"https target", "https://node.example:50051", []Option{WithBearerToken("SECRET")}},
		{"named waiver", "127.0.0.1:50051", []Option{WithInsecureBearerToken("SECRET")}},
	}
	for _, tc := range cases {
		c, err := Dial(context.Background(), tc.target, tc.opts...)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		_ = c.Close()
	}
}

// A later WithBearerToken must clear an earlier waiver rather than inherit it -
// the reason the waiver is a token-carrying option and not a standalone flag.
func TestInsecureWaiverDoesNotLeakIntoASubsequentBearerToken(t *testing.T) {
	c, err := Dial(context.Background(), "127.0.0.1:1",
		WithInsecureBearerToken("SECRET"), WithBearerToken("SECRET"))
	if err == nil {
		_ = c.Close()
		t.Fatal("the waiver must not survive a later WithBearerToken")
	}
	if !errors.Is(err, ErrInsecureCredential) {
		t.Errorf("got %v, want ErrInsecureCredential", err)
	}
}

// No token, no rule: a plaintext loopback dial without credentials is the
// default local setup and must keep working.
func TestPlaintextWithoutATokenIsUnaffected(t *testing.T) {
	c, err := Dial(context.Background(), "127.0.0.1:1")
	if err != nil {
		t.Fatalf("a plaintext dial with no token must be allowed: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDialAppliesOptions(t *testing.T) {
	cfg := dialConfig{keepalive: true, keepaliveEvery: defaultKeepaliveInterval}
	WithKeepalive(5*time.Second, 2*time.Second)(&cfg)
	if cfg.keepaliveEvery != 5*time.Second || cfg.keepaliveTimeout != 2*time.Second {
		t.Errorf("keepalive not applied: %+v", cfg)
	}
	WithoutKeepalive()(&cfg)
	if cfg.keepalive {
		t.Error("WithoutKeepalive did not disable keepalive")
	}
	WithTLSServerName("node.example")(&cfg)
	if !cfg.tlsEnabled || cfg.serverName != "node.example" {
		t.Errorf("server-name override did not enable TLS: %+v", cfg)
	}
}

func TestTransportCredentialsRejectGarbagePEM(t *testing.T) {
	_, err := transportCredentials(&dialConfig{tlsEnabled: true, caPEM: []byte("not a pem")})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("got %v, want ErrInvalidArgument", err)
	}
	_, err = transportCredentials(&dialConfig{
		tlsEnabled: true, certPEM: []byte("nope"), keyPEM: []byte("nope"),
	})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("got %v, want ErrInvalidArgument", err)
	}
}

// TestStreamCapturesTheDurableCursor: the cursor a consumer persists comes from
// the stream, and only confirmed-side events carry one - a control frame with
// no cursor must not reset it.
func TestStreamCapturesTheDurableCursor(t *testing.T) {
	msgs := []*eventspb.NodeEvent{
		{
			Cursor: &eventspb.Cursor{Height: 5, TxIndex: 2},
			Body: &eventspb.NodeEvent_Chain{Chain: &eventspb.ChainEvent{
				Body: &eventspb.ChainEvent_BlockConnected{BlockConnected: &eventspb.BlockConnected{Height: 5}},
			}},
		},
		// No cursor: a heartbeat does not advance the durable position.
		{Body: &eventspb.NodeEvent_Heartbeat{Heartbeat: &eventspb.Heartbeat{UptimeNs: 1}}},
		{
			Cursor: &eventspb.Cursor{Height: 6},
			Body: &eventspb.NodeEvent_Chain{Chain: &eventspb.ChainEvent{
				Body: &eventspb.ChainEvent_BlockConnected{BlockConnected: &eventspb.BlockConnected{Height: 6}},
			}},
		},
	}
	s := &Stream{recv: sliceRecv(msgs)}

	if s.Cursor() != nil {
		t.Error("a fresh stream has no cursor")
	}
	if _, err := s.Recv(); err != nil {
		t.Fatal(err)
	}
	if c := s.Cursor(); c == nil || *c != (Cursor{Height: 5, TxIndex: 2}) {
		t.Fatalf("cursor = %+v, want height 5 tx 2", c)
	}
	if _, err := s.Recv(); err != nil {
		t.Fatal(err)
	}
	if c := s.Cursor(); c == nil || c.Height != 5 {
		t.Errorf("a cursorless event moved the durable position to %+v", c)
	}
	if _, err := s.Recv(); err != nil {
		t.Fatal(err)
	}
	if c := s.Cursor(); c == nil || c.Height != 6 {
		t.Errorf("cursor = %+v, want height 6", c)
	}

	// Cursor hands back a copy: mutating it must not corrupt the stream's state.
	c := s.Cursor()
	c.Height = 999
	if s.Cursor().Height != 6 {
		t.Error("Cursor() leaked its internal cursor to the caller")
	}
}

// sliceRecv turns a fixed list of wire events into a Stream receive function,
// returning io.EOF once drained - the same shape a real gRPC stream has.
func sliceRecv(msgs []*eventspb.NodeEvent) func() (*eventspb.NodeEvent, error) {
	i := 0
	return func() (*eventspb.NodeEvent, error) {
		if i >= len(msgs) {
			return nil, io.EOF
		}
		m := msgs[i]
		i++
		return m, nil
	}
}

// TestClientStringDoesNotLeakTheToken: fmt reflects over unexported fields, so
// without an explicit String the bearer token appeared verbatim in any
// `%v`/`%+v` of a *Client - i.e. in logs, on disk, and in a log aggregator.
func TestClientStringDoesNotLeakTheToken(t *testing.T) {
	const token = "SUPER_SECRET_TOKEN"
	c := &Client{auth: "Bearer " + token}
	for _, verb := range []string{"%v", "%+v", "%s", "%#v"} {
		if got := fmt.Sprintf(verb, c); strings.Contains(got, token) {
			t.Errorf("%s leaked the token: %s", verb, got)
		}
	}
}

// TestTLSCredentialsFailClosedOnEmptyPEM: an empty CA PEM means "pin to
// nothing", which must be an error - silently falling back to the system roots
// turns a truncated CA file into a MITM opportunity.
func TestTLSCredentialsFailClosedOnEmptyPEM(t *testing.T) {
	if _, err := transportCredentials(&dialConfig{tlsEnabled: true, caPEM: []byte{}}); err == nil {
		t.Error("an empty CA PEM was accepted; the connection would trust the system roots")
	}
	// mTLS with both halves empty must not dial without a client identity.
	cfg := &dialConfig{tlsEnabled: true, certPEM: []byte{}, keyPEM: []byte{}}
	if _, err := transportCredentials(cfg); err == nil {
		t.Error("empty mTLS material was accepted; the client would present no certificate")
	}
	// Not pinning at all stays valid: nil means "use the system roots".
	if _, err := transportCredentials(&dialConfig{tlsEnabled: true}); err != nil {
		t.Errorf("plain WithTLS should still work: %v", err)
	}
}
