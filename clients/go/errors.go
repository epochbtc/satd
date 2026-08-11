package satdevents

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorKind classifies an [Error]. Each kind has a matching sentinel (ErrX)
// that [errors.Is] recognizes, so a caller can branch on the class without
// unwrapping to the concrete type.
type ErrorKind int

// The error classes the SDK produces. A slow-consumer lag notice is
// deliberately NOT one of them: it is a normal [Lagged] event, recoverable and
// carrying a resume cursor. These are conditions that stop forward progress on
// a call.
const (
	// KindTransport is an unclassified transport or RPC status from the server.
	KindTransport ErrorKind = iota
	// KindConnect is a failure to establish the underlying transport.
	KindConnect
	// KindInvalidEndpoint is an endpoint string that could not be used.
	KindInvalidEndpoint
	// KindInvalidToken is a bearer token that is not a valid header value.
	KindInvalidToken
	// KindUnauthenticated is gRPC UNAUTHENTICATED: the token was missing,
	// malformed, or rejected. Fixable by presenting a valid token, but not by a
	// blind retry - so it is reported non-retryable.
	KindUnauthenticated
	// KindPermissionDenied is gRPC PERMISSION_DENIED: authenticated but lacking
	// the required capability (stream:subscribe to open, stream:watch to add
	// watches). A permanent configuration error.
	KindPermissionDenied
	// KindQuotaExhausted is gRPC RESOURCE_EXHAUSTED: the subscription cap, a
	// per-principal rate limit, or the per-token watch quota. The first two are
	// transient; a genuinely full watch quota is not. Inspect Status's message
	// to distinguish.
	KindQuotaExhausted
	// KindRateLimited is reserved for explicit rate-limit signaling in the
	// resilience layer. The current server does not return a status for an
	// over-rate SetCursor re-anchor - it drops it silently - so this is not
	// produced yet.
	KindRateLimited
	// KindReplayUnavailable is reserved. A from_cursor replay against a server
	// with no block source is a silent server-side fallback to forward-only, so
	// this is not produced from the wire; the resilience layer detects the
	// degraded case from the event stream instead.
	KindReplayUnavailable
	// KindPrefixBitsOutOfRange is a prefix watch rejected because Bits is
	// outside the server's configured [streamprefixminbits, streamprefixmaxbits]
	// range. Reserved: the server does not advertise that range over the wire,
	// so the SDK cannot currently produce it.
	KindPrefixBitsOutOfRange
	// KindInvalidArgument is a client-side argument rejected before the wire.
	KindInvalidArgument
	// KindDecode is a received message (or a persisted cursor) that could not be
	// decoded into a typed value.
	KindDecode
	// KindControlClosed is a control-channel send after the watch stream was
	// torn down.
	KindControlClosed
	// KindWatchSetLoader is a user-supplied watch-set loader that failed while
	// rebuilding the watch-set on (re)connect. [ResilientWatch] treats it as a
	// transient reconnect-level condition rather than surfacing it, so a
	// momentary failure of the integrator's source-of-truth does not crash the
	// consumer.
	KindWatchSetLoader
	// KindInsecureCredential is a bearer token configured against a connection
	// with no transport encryption. [Dial] refuses rather than putting the
	// credential on the wire in the clear; use TLS, or [WithInsecureBearerToken]
	// to accept the risk explicitly.
	KindInsecureCredential
)

// Sentinels for [errors.Is]. `errors.Is(err, ErrUnauthenticated)` is true for
// any [Error] whose Kind is KindUnauthenticated.
var (
	ErrTransport            = errors.New("satdevents: rpc error")
	ErrConnect              = errors.New("satdevents: connect error")
	ErrInvalidEndpoint      = errors.New("satdevents: invalid endpoint")
	ErrInvalidToken         = errors.New("satdevents: invalid bearer token")
	ErrUnauthenticated      = errors.New("satdevents: unauthenticated")
	ErrPermissionDenied     = errors.New("satdevents: permission denied")
	ErrQuotaExhausted       = errors.New("satdevents: resource exhausted")
	ErrRateLimited          = errors.New("satdevents: rate limited")
	ErrReplayUnavailable    = errors.New("satdevents: cursor replay unavailable")
	ErrPrefixBitsOutOfRange = errors.New("satdevents: prefix bits out of server range")
	ErrInvalidArgument      = errors.New("satdevents: invalid argument")
	ErrDecode               = errors.New("satdevents: decode error")
	ErrControlClosed        = errors.New("satdevents: control channel closed")
	ErrWatchSetLoaderFailed = errors.New("satdevents: watch-set loader failed")
	ErrInsecureCredential   = errors.New("satdevents: insecure credential")
)

// sentinelsByKind maps each class to its sentinel, for Error's Is and Error
// methods. Kept as one table so a new kind cannot ship without its sentinel.
var sentinelsByKind = map[ErrorKind]error{
	KindTransport:            ErrTransport,
	KindConnect:              ErrConnect,
	KindInvalidEndpoint:      ErrInvalidEndpoint,
	KindInvalidToken:         ErrInvalidToken,
	KindUnauthenticated:      ErrUnauthenticated,
	KindPermissionDenied:     ErrPermissionDenied,
	KindQuotaExhausted:       ErrQuotaExhausted,
	KindRateLimited:          ErrRateLimited,
	KindReplayUnavailable:    ErrReplayUnavailable,
	KindPrefixBitsOutOfRange: ErrPrefixBitsOutOfRange,
	KindInvalidArgument:      ErrInvalidArgument,
	KindDecode:               ErrDecode,
	KindControlClosed:        ErrControlClosed,
	KindWatchSetLoader:       ErrWatchSetLoaderFailed,
	KindInsecureCredential:   ErrInsecureCredential,
}

// Error is the SDK's error type. Match its class with [errors.Is] against a
// sentinel, or pull out the details with [errors.As]:
//
//	var serr *satdevents.Error
//	if errors.As(err, &serr) && serr.Status != nil {
//	    log.Print(serr.Status.Code(), serr.Status.Message())
//	}
type Error struct {
	// Kind is the error class.
	Kind ErrorKind
	// Message is the human-readable detail.
	Message string
	// Status is the gRPC status this error was classified from, when it came
	// from the wire; nil otherwise. The server's message and details survive
	// classification here.
	Status *status.Status
	// RetryAfter is the suggested backoff before retrying, when known. Only
	// meaningful for KindRateLimited.
	RetryAfter time.Duration
	// Bits, MinBits, and MaxBits carry the rejected prefix width and the
	// server's accepted range. Only meaningful for KindPrefixBitsOutOfRange.
	Bits, MinBits, MaxBits uint32

	err error
}

func (e *Error) Error() string {
	if e.Message == "" {
		return sentinelFor(e.Kind).Error()
	}
	return sentinelFor(e.Kind).Error() + ": " + e.Message
}

// Unwrap exposes the underlying cause (a gRPC status error, a transport error,
// or an integrator's loader error), so [errors.As] reaches it.
func (e *Error) Unwrap() error { return e.err }

// Is makes every Error match its class sentinel.
func (e *Error) Is(target error) bool { return target == sentinelFor(e.Kind) }

// Retryable reports whether retrying the operation (after a backoff) could
// plausibly succeed.
//
// True for transport failures gRPC marks transient (UNAVAILABLE,
// DEADLINE_EXCEEDED, ABORTED, CANCELED, RESOURCE_EXHAUSTED), for connection
// failures, and for the reserved rate-limit class. False for permanent
// conditions - bad endpoint or token, PERMISSION_DENIED, client-side argument
// errors. Unauthenticated is reported non-retryable on purpose: a blind retry
// with the same token will not help; re-auth and reconnect deliberately.
func (e *Error) Retryable() bool {
	switch e.Kind {
	case KindConnect, KindRateLimited, KindQuotaExhausted:
		return true
	case KindTransport:
		if e.Status == nil {
			return false
		}
		switch e.Status.Code() {
		case codes.Unavailable, codes.DeadlineExceeded, codes.Aborted,
			codes.Canceled, codes.ResourceExhausted:
			return true
		}
		return false
	default:
		return false
	}
}

// Retryable reports whether err is an SDK error worth retrying after a backoff.
// A non-SDK error (including a context cancellation) is not retryable.
func Retryable(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Retryable()
	}
	return false
}

func sentinelFor(k ErrorKind) error {
	if s, ok := sentinelsByKind[k]; ok {
		return s
	}
	return ErrTransport
}

func newError(kind ErrorKind, format string, args ...any) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

func wrapError(kind ErrorKind, cause error, format string, args ...any) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...), err: cause}
}

// fromStatus classifies a gRPC error, keeping the original status so its
// message and details are preserved. A context cancellation surfaces as a
// Canceled transport error, which Retryable treats as transient - callers that
// cancel deliberately check ctx.Err() rather than the classification.
func fromStatus(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return wrapError(KindTransport, err, "%s", err.Error())
	}
	kind := KindTransport
	switch st.Code() {
	case codes.Unauthenticated:
		kind = KindUnauthenticated
	case codes.PermissionDenied:
		kind = KindPermissionDenied
	case codes.ResourceExhausted:
		kind = KindQuotaExhausted
	}
	return &Error{Kind: kind, Message: st.Message(), Status: st, err: err}
}
