package satdevents

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStatusClassification(t *testing.T) {
	cases := []struct {
		code     codes.Code
		wantKind ErrorKind
		sentinel error
	}{
		{codes.Unauthenticated, KindUnauthenticated, ErrUnauthenticated},
		{codes.PermissionDenied, KindPermissionDenied, ErrPermissionDenied},
		{codes.ResourceExhausted, KindQuotaExhausted, ErrQuotaExhausted},
		{codes.Unavailable, KindTransport, ErrTransport},
		{codes.Internal, KindTransport, ErrTransport},
	}
	for _, c := range cases {
		err := fromStatus(status.Error(c.code, "server said so"))
		var se *Error
		if !errors.As(err, &se) {
			t.Fatalf("%s did not classify to *Error: %v", c.code, err)
		}
		if se.Kind != c.wantKind {
			t.Errorf("%s classified to kind %d, want %d", c.code, se.Kind, c.wantKind)
		}
		if !errors.Is(err, c.sentinel) {
			t.Errorf("%s does not match its sentinel", c.code)
		}
		// The server's own message must survive classification - it is often the
		// only way to tell a transient quota bounce from a full watch quota.
		if se.Status == nil || se.Status.Message() != "server said so" {
			t.Errorf("%s lost the server status", c.code)
		}
		if se.Error() == "" {
			t.Errorf("%s produced an empty error string", c.code)
		}
	}
}

func TestRetryableClassification(t *testing.T) {
	retryable := []error{
		fromStatus(status.Error(codes.Unavailable, "")),
		fromStatus(status.Error(codes.DeadlineExceeded, "")),
		fromStatus(status.Error(codes.Aborted, "")),
		fromStatus(status.Error(codes.Canceled, "")),
		fromStatus(status.Error(codes.ResourceExhausted, "")),
		&Error{Kind: KindConnect},
		&Error{Kind: KindRateLimited},
	}
	for _, err := range retryable {
		if !Retryable(err) {
			t.Errorf("%v should be retryable", err)
		}
	}

	permanent := []error{
		// A blind retry with the same token will not help; re-auth deliberately.
		fromStatus(status.Error(codes.Unauthenticated, "")),
		fromStatus(status.Error(codes.PermissionDenied, "")),
		fromStatus(status.Error(codes.InvalidArgument, "")),
		&Error{Kind: KindInvalidEndpoint},
		&Error{Kind: KindInvalidToken},
		&Error{Kind: KindInvalidArgument},
		&Error{Kind: KindDecode},
		&Error{Kind: KindControlClosed},
		&Error{Kind: KindWatchSetLoader},
		// A plain non-SDK error is not something to retry blindly either.
		errors.New("some caller error"),
	}
	for _, err := range permanent {
		if Retryable(err) {
			t.Errorf("%v should not be retryable", err)
		}
	}
}

func TestEveryKindHasASentinel(t *testing.T) {
	// The Error and Is methods both go through the sentinel table; a kind added
	// without one would silently render as a transport error.
	for k := KindTransport; k <= KindWatchSetLoader; k++ {
		if _, ok := sentinelsByKind[k]; !ok {
			t.Errorf("ErrorKind %d has no sentinel", k)
		}
	}
	// Distinct kinds must not share a sentinel, or errors.Is would conflate them.
	seen := map[error]ErrorKind{}
	for k, s := range sentinelsByKind {
		if prev, dup := seen[s]; dup {
			t.Errorf("kinds %d and %d share the sentinel %v", prev, k, s)
		}
		seen[s] = k
	}
}

func TestErrorUnwrapsToTheCause(t *testing.T) {
	cause := errors.New("underlying")
	err := wrapError(KindWatchSetLoader, cause, "loader: %s", cause)
	if !errors.Is(err, cause) {
		t.Error("the cause is not reachable through Unwrap")
	}
	if !errors.Is(err, ErrWatchSetLoaderFailed) {
		t.Error("the class sentinel does not match")
	}
	if got := err.Error(); got != "satdevents: watch-set loader failed: loader: underlying" {
		t.Errorf("Error() = %q", got)
	}
	// A kind with no detail still renders its class rather than an empty string.
	if got := (&Error{Kind: KindControlClosed}).Error(); got != ErrControlClosed.Error() {
		t.Errorf("bare Error() = %q", got)
	}
}

func TestErrorsIsDoesNotCrossClasses(t *testing.T) {
	err := newError(KindQuotaExhausted, "over quota")
	if errors.Is(err, ErrPermissionDenied) {
		t.Error("a quota error must not match the permission sentinel")
	}
	if !errors.Is(err, ErrQuotaExhausted) {
		t.Error("a quota error must match its own sentinel")
	}
}

func TestNonStatusErrorStillClassifies(t *testing.T) {
	// status.FromError treats a plain error as codes.Unknown; either way the
	// SDK must return a typed *Error rather than passing the raw error through.
	err := fromStatus(fmt.Errorf("socket closed"))
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("got %T, want *Error", err)
	}
	if se.Retryable() {
		t.Error("an unclassifiable error should not be reported retryable")
	}
}
