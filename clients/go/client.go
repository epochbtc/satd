package satdevents

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/epochbtc/satd/clients/go/eventspb"
)

// Category bits for [SubscribeOptions.Categories]. Combine with |.
//
// [CategoryAll] (0, the default) means "all categories" - EXCEPT
// [CategoryTweaks] and [CategoryStatus], which are explicit-request only and
// are NOT part of that expansion, so an existing 0-subscriber never starts
// receiving tweak volume or a new event type after a node upgrade.
const (
	// CategoryAll is the server default: every category except the
	// explicit-request-only ones.
	CategoryAll uint32 = 0
	// CategoryMempool selects mempool events.
	CategoryMempool uint32 = 1
	// CategoryChain selects block connect/disconnect/reorg events.
	CategoryChain uint32 = 2
	// CategoryHeartbeat selects heartbeats.
	CategoryHeartbeat uint32 = 4
	// CategoryTweaks selects BIP 352 silent-payment per-block tweaks (Tier 1
	// client-side scan). Not part of CategoryAll: a subscription must request it
	// explicitly. Requires the node's tweak index (silentpaymentindex=1); a
	// tweaks subscription against a node with it disabled is refused in-band.
	CategoryTweaks uint32 = 8
	// CategoryStatus selects node-health conditions ([Status]). Like
	// CategoryTweaks it is not part of CategoryAll, so a client written against
	// an older node never starts receiving a body it has no parser for. Unlike
	// CategoryTweaks there is no index prerequisite: any node serves it.
	CategoryStatus uint32 = 16
)

const (
	// MaxSPLabelsPerTarget is the server-enforced cap on the number of DISTINCT
	// labels one scan-key target may carry. The server rejects an over-label
	// target; enforcing the same bound client-side turns that into a
	// deterministic error at the call site instead of a silent skip.
	MaxSPLabelsPerTarget = 16
	// MaxSPTargetsPerConnection is the server-enforced cap on scan-key targets
	// per connection. The server silently sheds an over-cap add; a stateful
	// [ResilientWatch] enforces this bound before recording or sending, so it
	// never mirrors and replays a target the server dropped.
	MaxSPTargetsPerConnection = 16
)

// defaultKeepaliveInterval and defaultKeepaliveTimeout match the server's own
// HTTP/2 keepalive settings.
const (
	defaultKeepaliveInterval = 30 * time.Second
	defaultKeepaliveTimeout  = 20 * time.Second
)

// Client is a connected client for the satd satd.events.v1 streaming API.
//
// It is safe for concurrent use: each Subscribe or Watch call opens an
// independent stream over the shared connection. Close it when done.
type Client struct {
	conn *grpc.ClientConn
	rpc  eventspb.NodeEventStreamClient
	// auth is the pre-rendered "Bearer <token>" header value, empty when no
	// token was configured. Held rather than logged - never put it in a String
	// or error message.
	auth string
}

type dialConfig struct {
	token string

	tlsEnabled bool
	caPEM      []byte
	certPEM    []byte
	keyPEM     []byte
	serverName string

	keepalive        bool
	keepaliveEvery   time.Duration
	keepaliveTimeout time.Duration

	extra []grpc.DialOption
}

// Option configures [Dial].
type Option func(*dialConfig)

// WithBearerToken attaches a bearer token, sent as `authorization: Bearer
// <token>` metadata on every RPC.
//
// The token is only honored when the server enforces auth (-eventsgrpcauth); a
// no-auth (loopback-trust) server ignores it. Over a plaintext endpoint the
// token travels in cleartext - enable TLS ([WithTLS] or [WithTLSCAPem]) so the
// connection is encrypted, or restrict bearer auth to loopback or a
// TLS-terminating proxy.
func WithBearerToken(token string) Option {
	return func(c *dialConfig) { c.token = token }
}

// WithTLS enables TLS for the connection, trusting the host's system root CAs
// (for a server with a publicly-trusted certificate). For a private or
// self-signed CA - the usual case for a satd node serving its own certificate -
// use [WithTLSCAPem] instead.
func WithTLS() Option {
	return func(c *dialConfig) { c.tlsEnabled = true }
}

// WithTLSCAPem enables TLS and verifies the server certificate against the PEM
// CA (or self-signed leaf) in pem - the usual choice for a satd node serving
// its own certificate. It replaces the system roots for this connection.
func WithTLSCAPem(pem []byte) Option {
	return func(c *dialConfig) {
		c.tlsEnabled = true
		c.caPEM = pem
	}
}

// WithMTLS enables mutual TLS: present this PEM client certificate and private
// key to a server configured for mTLS (-eventsgrpcmtls).
//
// Combine it with [WithTLSCAPem] to pin the server's CA - without that, the
// SERVER certificate is verified against the system roots, so a self-signed
// satd node (the usual mTLS case) fails the handshake.
func WithMTLS(certPEM, keyPEM []byte) Option {
	return func(c *dialConfig) {
		c.tlsEnabled = true
		c.certPEM = certPEM
		c.keyPEM = keyPEM
	}
}

// WithTLSServerName overrides the certificate name verified during the TLS
// handshake (and sent as SNI). Use it when the endpoint host differs from the
// certificate subject - connecting by IP, or through a proxy. It enables TLS if
// not already enabled.
func WithTLSServerName(name string) Option {
	return func(c *dialConfig) {
		c.tlsEnabled = true
		c.serverName = name
	}
}

// WithKeepalive sets the client-side HTTP/2 keepalive ping interval and timeout,
// overriding the defaults (30s / 20s, matching the server).
func WithKeepalive(interval, timeout time.Duration) Option {
	return func(c *dialConfig) {
		c.keepalive = true
		c.keepaliveEvery = interval
		c.keepaliveTimeout = timeout
	}
}

// WithoutKeepalive disables the client-side HTTP/2 keepalive that [Dial]
// enables by default. Use it when an intermediary is strict about ping
// frequency; the cost is that a silently dead connection is detected only when
// the transport's own timeouts fire.
func WithoutKeepalive() Option {
	return func(c *dialConfig) { c.keepalive = false }
}

// WithGRPCDialOption passes raw grpc-go dial options through - the escape hatch
// for anything this SDK does not wrap (a custom resolver, interceptors,
// message-size limits, a proxy dialer). They are applied last, so they override
// the SDK's own options where they overlap.
func WithGRPCDialOption(opts ...grpc.DialOption) Option {
	return func(c *dialConfig) { c.extra = append(c.extra, opts...) }
}

// Dial connects to a satd node's gRPC streaming endpoint.
//
// target is a gRPC target: usually `host:port`, optionally with an `http://` or
// `https://` scheme (which this SDK strips, for symmetry with the Rust client
// and with the -eventsgrpcbind flag's documentation). An `https://` scheme
// enables TLS with the system roots if no TLS option was given.
//
// Requesting TLS against an explicit `http://` target is refused rather than
// silently downgraded: that combination can only be a mistake, and connecting
// in cleartext would leak the bearer token and the whole event stream while the
// caller believed the link was encrypted.
//
// Dial does not block on the connection coming up; gRPC connects lazily and the
// first Subscribe or Watch surfaces a connection failure. Pass
// [grpc.WithBlock] via [WithGRPCDialOption] if you want the old blocking
// behavior.
func Dial(ctx context.Context, target string, opts ...Option) (*Client, error) {
	cfg := dialConfig{
		keepalive:        true,
		keepaliveEvery:   defaultKeepaliveInterval,
		keepaliveTimeout: defaultKeepaliveTimeout,
	}
	for _, o := range opts {
		o(&cfg)
	}

	endpoint, scheme, err := splitScheme(target)
	if err != nil {
		return nil, err
	}
	switch {
	case scheme == "http" && cfg.tlsEnabled:
		return nil, newError(KindInvalidEndpoint,
			"TLS was requested but the target scheme is http:// - refusing to connect in "+
				"cleartext; drop the scheme or use https://")
	case scheme == "https" && !cfg.tlsEnabled:
		// An https target with no TLS option means TLS with the system roots.
		cfg.tlsEnabled = true
	}

	creds, err := transportCredentials(&cfg)
	if err != nil {
		return nil, err
	}

	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if cfg.keepalive {
		dialOpts = append(dialOpts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                cfg.keepaliveEvery,
			Timeout:             cfg.keepaliveTimeout,
			PermitWithoutStream: true,
		}))
	}
	dialOpts = append(dialOpts, cfg.extra...)

	conn, err := grpc.NewClient(endpoint, dialOpts...)
	if err != nil {
		return nil, wrapError(KindConnect, err, "%s", err)
	}
	c := &Client{conn: conn, rpc: eventspb.NewNodeEventStreamClient(conn)}
	if cfg.token != "" {
		if !validHeaderValue(cfg.token) {
			_ = conn.Close()
			return nil, newError(KindInvalidToken, "bearer token is not a valid header value")
		}
		c.auth = "Bearer " + cfg.token
	}
	return c, nil
}

// Close releases the underlying connection. Streams opened from this client
// fail after it returns.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// Conn exposes the underlying gRPC connection, for callers that need to inspect
// its state or share it. The Client owns it: do not close it directly.
func (c *Client) Conn() *grpc.ClientConn { return c.conn }

// authed attaches the configured bearer credential to an outgoing context.
func (c *Client) authed(ctx context.Context) context.Context {
	if c.auth == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", c.auth)
}

// SubscribeOptions are the filter and replay knobs for a [Client.Subscribe]
// firehose. The zero value is a valid "everything, from now" subscription.
type SubscribeOptions struct {
	// Categories is the category bitfield; 0 means all. See [CategoryAll].
	Categories uint32
	// FromCursor is a durable replay anchor. When set, the server replays
	// confirmed history forward from this cursor, then joins live with no gap or
	// duplicate at the boundary.
	FromCursor *Cursor
	// SinceSeq is a forward-only dedup filter: drop events with seq <=
	// SinceSeq. Use it after a brief reconnect within the broadcast window - not
	// for durable replay, which is FromCursor's job.
	SinceSeq *uint64
	// TweakDustLimit drops [TweakEntry] whose MaxValue is below this floor
	// (satoshis) and flags the block Filtered. Only meaningful with
	// [CategoryTweaks]; nil keeps every tweak.
	TweakDustLimit *uint64
	// TweaksOnly requests the compact tweak form: entries carry only the 33-byte
	// tweak (no txid or max value), the minimal payload a client-side ECDH scan
	// needs. Only meaningful with [CategoryTweaks], and it does not apply to
	// [MempoolTweak] (whose txid is needed for confirm-time dedup).
	TweaksOnly bool
	// MempoolTweaks additionally streams a [MempoolTweak] at each SP-eligible
	// transaction's admission, for mempool-latency detection without uploading a
	// scan key. A modifier on [CategoryTweaks] - the server rejects it if that
	// bit is not set. Ephemeral and best-effort: mempool tweaks are not
	// replayable, so a missed admission is caught at confirmation via
	// [BlockTweaks].
	MempoolTweaks bool
	// TweakOutputs includes each transaction's taproot outputs on every
	// [BlockTweaks] entry, so a match is confirmed against the on-chain output
	// without fetching the block. False keeps the confirmed firehose lean. A
	// modifier on [CategoryTweaks]; the server also rejects it if the node has
	// no block source. A [MempoolTweak] carries its outputs regardless.
	TweakOutputs bool
}

func (o SubscribeOptions) toProto() *eventspb.SubscribeRequest {
	req := &eventspb.SubscribeRequest{Categories: o.Categories}
	if o.FromCursor != nil {
		req.FromCursor = o.FromCursor.toProto()
	}
	if o.SinceSeq != nil {
		v := *o.SinceSeq
		req.SinceSeq = &v
	}
	if o.TweakDustLimit != nil {
		v := *o.TweakDustLimit
		req.TweakDustLimit = &v
	}
	// Send each flag only when set, so a default subscription is byte-identical
	// to one built before these knobs existed.
	if o.TweaksOnly {
		t := true
		req.TweaksOnly = &t
	}
	if o.MempoolTweaks {
		t := true
		req.MempoolTweaks = &t
	}
	if o.TweakOutputs {
		t := true
		req.TweakOutputs = &t
	}
	return req
}

// Stream is a live stream of typed [Event]s, shared by Subscribe and Watch.
//
// As confirmed events flow, the stream captures their durable [Cursor];
// [Stream.Cursor] returns the latest, which a consumer persists and presents as
// [SubscribeOptions.FromCursor] to resume.
//
// A Stream is NOT safe for concurrent Recv calls - drive it from one goroutine,
// as the underlying gRPC stream requires.
type Stream struct {
	recv       func() (*eventspb.NodeEvent, error)
	lastCursor *Cursor
}

// Recv returns the next event. It returns [io.EOF] when the server closes the
// stream cleanly, and an [*Error] otherwise.
func (s *Stream) Recv() (Event, error) {
	msg, err := s.recv()
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fromStatus(err)
	}
	if c := cursorFromProto(msg.GetCursor()); c != nil {
		s.lastCursor = c
	}
	return decodeEvent(msg), nil
}

// Cursor returns the most recent durable cursor seen on this stream, or nil if
// none has arrived. Persist it to resume after a disconnect.
func (s *Stream) Cursor() *Cursor {
	if s.lastCursor == nil {
		return nil
	}
	c := *s.lastCursor
	return &c
}

// Subscribe opens a server-streaming firehose. It requires the
// stream:subscribe capability when the server enforces auth.
//
// The returned [Stream] stops at the first transport error or server close; for
// automatic reconnect, cursor persistence, and lag recovery use
// [Client.ResilientSubscribe].
//
// Cancelling ctx terminates the stream.
func (c *Client) Subscribe(ctx context.Context, opts SubscribeOptions) (*Stream, error) {
	sc, err := c.rpc.Subscribe(c.authed(ctx), opts.toProto())
	if err != nil {
		return nil, fromStatus(err)
	}
	return &Stream{recv: sc.Recv}, nil
}

// splitScheme accepts a bare gRPC target or one carrying an http:// or https://
// scheme, returning the target with the scheme removed plus the scheme itself
// ("" when there was none).
//
// gRPC targets are not URLs, and grpc-go picks its transport credentials from
// the dial options rather than from the target - so unlike the Rust client
// there is no way for a scheme-less target to silently downgrade a TLS
// connection to cleartext. What is still worth refusing is an explicit
// http:// alongside TLS options, which [Dial] does.
func splitScheme(target string) (endpoint, scheme string, err error) {
	i := strings.Index(target, "://")
	if i < 0 {
		if target == "" {
			return "", "", newError(KindInvalidEndpoint, "target is empty")
		}
		return target, "", nil
	}
	scheme = strings.ToLower(target[:i])
	endpoint = target[i+3:]
	switch scheme {
	case "http", "https":
	default:
		// Anything else is a genuine gRPC target scheme (dns:, unix:,
		// passthrough:) or a typo; hand it back untouched and let grpc-go's
		// resolver registry decide.
		return target, "", nil
	}
	if endpoint == "" {
		return "", "", newError(KindInvalidEndpoint, "target %q has no host", target)
	}
	return endpoint, scheme, nil
}

func transportCredentials(cfg *dialConfig) (credentials.TransportCredentials, error) {
	if !cfg.tlsEnabled {
		return insecure.NewCredentials(), nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.serverName != "" {
		tlsCfg.ServerName = cfg.serverName
	}
	if len(cfg.caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.caPEM) {
			return nil, newError(KindInvalidArgument, "no certificate found in the supplied CA PEM")
		}
		tlsCfg.RootCAs = pool
	}
	if len(cfg.certPEM) > 0 || len(cfg.keyPEM) > 0 {
		cert, err := tls.X509KeyPair(cfg.certPEM, cfg.keyPEM)
		if err != nil {
			return nil, wrapError(KindInvalidArgument, err, "client identity: %s", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return credentials.NewTLS(tlsCfg), nil
}

// validHeaderValue reports whether s can be sent as an HTTP/2 header value.
// gRPC metadata is ASCII for a non "-bin" key; a token carrying a control
// character or a non-ASCII byte would be rejected (or, worse, mangled) at the
// transport, so reject it at the call site with a clear error instead.
func validHeaderValue(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
