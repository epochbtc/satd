package satdevents

import (
	"context"
	"io"
	"math"
	"sync"
	"time"
)

// LagPolicy is what the resilience loop does with a [Lagged] notice.
type LagPolicy int

const (
	// LagAutoResume transparently reconnects from the notice's ResumeCursor and
	// rejoins live; the [Lagged] event is not surfaced. The default.
	LagAutoResume LagPolicy = iota
	// LagSurface hands the [Lagged] event to the caller unchanged and keeps
	// running on the same connection. The caller decides whether to keep
	// consuming or to re-anchor.
	LagSurface
)

// Backoff is the exponential reconnect schedule. Delays grow
// Initial * Multiplier^attempt, capped at Max.
//
// No jitter is applied: a single client reconnecting to a single node needs
// none, and the Rust SDK behaves identically. Add jitter externally if you are
// fanning many clients at one server.
type Backoff struct {
	// Initial is the delay before the first retry.
	Initial time.Duration
	// Max is the upper bound on any single delay.
	Max time.Duration
	// Multiplier is the per-attempt growth factor.
	Multiplier float64
	// MaxRetries gives up after this many CONSECUTIVE reconnect attempts produce
	// no event, surfacing the last error from Next. The initial connect is not
	// counted, and a connection that delivers any event resets the count. Zero
	// retries forever.
	MaxRetries uint32
}

// DefaultBackoff is 500ms doubling to a 30s ceiling, retrying forever.
func DefaultBackoff() Backoff {
	return Backoff{
		Initial:    500 * time.Millisecond,
		Max:        30 * time.Second,
		Multiplier: 2.0,
	}
}

// DelayFor is the delay before retry attempt (0-based: attempt 0 is the first
// retry).
func (b Backoff) DelayFor(attempt uint32) time.Duration {
	initial, max := b.Initial, b.Max
	if initial <= 0 {
		initial = DefaultBackoff().Initial
	}
	if max <= 0 {
		max = DefaultBackoff().Max
	}
	mult := b.Multiplier
	if mult <= 0 {
		mult = DefaultBackoff().Multiplier
	}
	// Clamp the exponent before scaling: 64 doublings already dwarf any sane
	// ceiling, and an unclamped Pow overflows to +Inf.
	exp := float64(attempt)
	if exp > 64 {
		exp = 64
	}
	scaled := initial.Seconds() * math.Pow(mult, exp)
	if !(scaled >= 0) || math.IsInf(scaled, 0) {
		return max
	}
	d := time.Duration(scaled * float64(time.Second))
	if d > max || d <= 0 {
		return max
	}
	return d
}

// ResilientConfig bundles the resilience knobs for
// [Client.ResilientSubscribe]. The zero value is valid: default backoff,
// [LagAutoResume], and no persistence.
type ResilientConfig struct {
	// Backoff is the reconnect schedule. The zero value uses [DefaultBackoff].
	Backoff Backoff
	// LagPolicy is what to do with [Lagged] notices.
	LagPolicy LagPolicy
	// CursorStore is where the resume cursor is persisted. nil means
	// [NoopCursorStore] - reconnects still resume from the in-memory cursor, but
	// a restart starts forward-only.
	CursorStore CursorStore
}

func (c ResilientConfig) store() CursorStore {
	if c.CursorStore == nil {
		return NoopCursorStore{}
	}
	return c.CursorStore
}

func (c ResilientConfig) backoff() Backoff {
	if c.Backoff.Initial == 0 && c.Backoff.Max == 0 && c.Backoff.Multiplier == 0 {
		b := DefaultBackoff()
		b.MaxRetries = c.Backoff.MaxRetries
		return b
	}
	return c.Backoff
}

// delivery is one item handed from the pump goroutine to Next.
//
// cursor is the resume high-water as of this item, captured by the pump at
// send time. It travels with the item rather than being read back off the
// subscription, so what Next arms for commit is exactly what belonged to the
// event it handed out, with no window for the pump to move on underneath.
type delivery struct {
	ev     Event
	err    error
	cursor *Cursor
	// gen is the anchor generation this item was produced under. An out-of-band
	// re-anchor (a lag recovery) bumps it, which invalidates anything the caller
	// armed from the superseded generation.
	gen uint64
}

// ResilientSubscription is a firehose that reconnects, replays from a persisted
// cursor, and recovers from lag on the consumer's behalf.
//
// Construct it with [Client.ResilientSubscribe] and drive it by calling
// [ResilientSubscription.Next] in a loop. Close it when done.
//
// # Cancel safety
//
// The reconnect state machine runs on its own goroutine and hands events over
// an UNBUFFERED channel, so it is never more than one event ahead of the
// caller. Next is therefore cancel-safe by construction: returning on
// ctx.Done() cannot consume an event, because a handoff only completes when the
// caller actually receives it. Cancel Next freely - in a select against a
// command channel, say - and call it again.
//
// This is the Go equivalent of the Rust SDK's explicit cancel-safe state
// machine; the language does the work here because a gRPC Recv cannot be
// abandoned mid-flight without losing the message.
type ResilientSubscription struct {
	client *Client
	base   SubscribeOptions
	config ResilientConfig

	events chan delivery
	cancel context.CancelFunc
	done   chan struct{}

	// mu guards the cursor bookkeeping, which both the pump and a caller's
	// Commit / ResumeCursor touch.
	mu sync.Mutex
	// resume is the anchor the next (re)connect uses: the most recent confirmed
	// cursor, seeded from the store or the caller's base options.
	resume *Cursor
	// commitNext is the high-water armed for the commit-on-poll write, and
	// commitNextGen the generation it came from.
	commitNext    *Cursor
	commitNextGen uint64
	// gen increments on every out-of-band re-anchor. The pump and the caller's
	// Next run concurrently, so the pump cannot simply clear an armed cursor -
	// the caller may not have armed it yet. Stamping generations lets the stale
	// arm be recognized and dropped whenever it does land.
	gen uint64
	// committed is the cursor last written, to skip redundant writes (a run of
	// mempool events does not move the confirmed high-water).
	committed *Cursor
	// pending holds an item received from the pump that Next could not return
	// because the commit it triggered failed. Without it, a store error would
	// eat the event that was already off the channel.
	pending *delivery

	closeOnce sync.Once
}

// ResilientSubscribe opens a reconnect-and-replay-aware firehose.
//
// Unlike [Client.Subscribe], the returned subscription reconnects with backoff,
// persists and replays the resume cursor through the configured [CursorStore],
// recovers from [Lagged] per the [LagPolicy], and surfaces replay-truncation
// gaps as a synthesized [ReplayGap].
//
// ctx governs the whole subscription: cancelling it (or calling Close) stops
// the pump and releases the stream. Unlike the Rust SDK, which connects lazily
// on the first next(), the pump starts here - it will be parked on the handoff
// until the first Next in any case.
func (c *Client) ResilientSubscribe(ctx context.Context, opts SubscribeOptions, config ResilientConfig) *ResilientSubscription {
	pumpCtx, cancel := context.WithCancel(ctx)
	s := &ResilientSubscription{
		client: c,
		base:   opts,
		config: config,
		events: make(chan delivery),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go s.pump(pumpCtx)
	return s
}

// Next yields the next event, reconnecting and replaying underneath as needed.
//
// It returns an error only when reconnect retries are exhausted (see
// [Backoff.MaxRetries]), on a non-retryable failure (a bad endpoint or token,
// PERMISSION_DENIED, a failed cursor write), when ctx is done, or when the
// subscription is closed - which surfaces as [io.EOF].
func (s *ResilientSubscription) Next(ctx context.Context) (Event, error) {
	s.mu.Lock()
	item := s.pending
	s.pending = nil
	s.mu.Unlock()

	if item == nil {
		select {
		case v, ok := <-s.events:
			if !ok {
				return nil, io.EOF
			}
			item = &v
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Getting here is the caller's ack of the PREVIOUS event, so its armed
	// cursor commits now - commit-on-poll. Doing it here rather than on the pump
	// goroutine also makes it ordered against the caller: by the time Next
	// returns, the event it hands back is armed, so an immediately following
	// Commit checkpoints that event and not the one before it.
	if err := s.commitDue(ctx); err != nil {
		// Hold the event back rather than losing it to a store failure.
		s.mu.Lock()
		s.pending = item
		s.mu.Unlock()
		return nil, err
	}

	s.mu.Lock()
	s.commitNext, s.commitNextGen = copyCursor(item.cursor), item.gen
	s.mu.Unlock()
	return item.ev, item.err
}

// ResumeCursor is the cursor the next reconnect would use. It advances as
// confirmed events arrive; useful for diagnostics or an external checkpoint.
func (s *ResilientSubscription) ResumeCursor() *Cursor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyCursor(s.resume)
}

// Commit persists the most-recently-delivered event's cursor now, rather than
// waiting for the implicit ack on the next [ResilientSubscription.Next].
//
// Call it before a clean shutdown so the last event you durably processed is
// not replayed on the next start. Idempotent - a no-op when nothing new is
// armed or the store already holds the armed cursor.
func (s *ResilientSubscription) Commit(ctx context.Context) error {
	return s.commitDue(ctx)
}

// Close stops the reconnect loop and releases the stream. Next returns
// [io.EOF] afterwards. It is safe to call more than once.
func (s *ResilientSubscription) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		<-s.done
	})
	return nil
}

// commitDue is the single point on the delivery path where the store advances:
// it persists the armed high-water (the previously delivered event's) if it
// differs from what the store already holds.
func (s *ResilientSubscription) commitDue(ctx context.Context) error {
	s.mu.Lock()
	armed := s.commitNext
	if armed == nil || s.commitNextGen != s.gen ||
		(s.committed != nil && *s.committed == *armed) {
		s.commitNext = nil
		s.mu.Unlock()
		return nil
	}
	s.commitNext = nil
	c := *armed
	s.mu.Unlock()

	if err := s.config.store().Store(ctx, c); err != nil {
		return err
	}
	s.mu.Lock()
	s.committed = &c
	s.mu.Unlock()
	return nil
}

// pump is the reconnect state machine. It owns the connection and hands each
// event to Next over an unbuffered channel, so it never runs more than one
// event ahead of the caller.
func (s *ResilientSubscription) pump(ctx context.Context) {
	defer close(s.done)
	defer close(s.events)

	backoff := s.config.backoff()
	var (
		stream *Stream
		// attempts counts consecutive reconnects that have produced NO event.
		// It resets the moment a connection delivers one ("made progress"), and
		// increments whenever a connection fails to establish or ends without
		// progress - so a server that accepts a subscribe and immediately closes
		// it cannot induce a no-delay reconnect storm.
		attempts  uint32
		lastError error
		// expectFirstHeight is cursor.Height+1 captured at the last (re)connect:
		// the height the first replayed confirmed event should carry if the
		// replay was not clamped. Cleared once that seam has been checked.
		expectFirstHeight *uint32
	)

	for {
		if ctx.Err() != nil {
			return
		}
		if stream == nil {
			if attempts > 0 {
				if backoff.MaxRetries > 0 && attempts > backoff.MaxRetries {
					s.deliver(ctx, delivery{err: orControlClosed(lastError)})
					return
				}
				if !sleepCtx(ctx, backoff.DelayFor(attempts-1)) {
					return
				}
			}
			st, expect, err := s.connectOnce(ctx)
			if err != nil {
				if !Retryable(err) || ctx.Err() != nil {
					s.deliver(ctx, delivery{err: err})
					return
				}
				attempts++
				lastError = err
				continue
			}
			stream, expectFirstHeight = st, expect
		}

		ev, err := stream.Recv()
		if err != nil {
			stream = nil
			if err == io.EOF {
				// The server closed cleanly; reconnect from the resume anchor,
				// backing off since this connection yielded nothing new.
				attempts++
				continue
			}
			if Retryable(err) && ctx.Err() == nil {
				attempts++
				lastError = err
				continue
			}
			if ctx.Err() != nil {
				return
			}
			s.deliver(ctx, delivery{err: err})
			return
		}

		attempts, lastError = 0, nil
		cur := stream.Cursor()

		// Replay-truncation check, only on the first confirmed-height event
		// after a resume. A BlockConnected whose height exceeds the expected
		// next height means the server clamped the replay window to its most
		// recent MAX_REPLAY_BLOCKS; the gap is unrecoverable via this stream.
		//
		// Detection depends on the server replaying confirmed history as
		// BlockConnected in height order ahead of the live tail, which is what
		// its cursor-replay builder synthesizes.
		if expectFirstHeight != nil {
			if block, ok := ev.(*BlockConnected); ok {
				expect := *expectFirstHeight
				expectFirstHeight = nil
				if block.Height > expect {
					// The gap notice goes first, and it commits only the pre-gap
					// anchor: the triggering block's own cursor is armed when the
					// block itself is delivered, so the store never runs ahead.
					if !s.deliverEvent(ctx, &ReplayGap{ResumeHeight: expect, FirstHeight: block.Height}) {
						return
					}
				}
			}
		}

		if lag, ok := ev.(*Lagged); ok && s.config.LagPolicy == LagAutoResume {
			// Re-anchor from the notice's cursor, then reconnect. A lag
			// re-anchor is a recovery point the server handed us, not
			// caller-delivered data, so persist it immediately (superseding any
			// deferred commit): a crash then resumes from the same place the
			// live re-anchor would.
			if lag.ResumeCursor != nil {
				c := *lag.ResumeCursor
				s.mu.Lock()
				s.resume = &c
				s.commitNext = nil
				// Supersede anything armed from before this re-anchor, including
				// an arm the caller has not performed yet.
				s.gen++
				s.mu.Unlock()
				if err := s.config.store().Store(ctx, c); err != nil {
					s.deliver(ctx, delivery{err: err})
					return
				}
				s.mu.Lock()
				s.committed = &c
				s.mu.Unlock()
			}
			stream = nil
			continue
		}

		// Advance the in-memory high-water, then hand the event over. The
		// advance happens AFTER the gap check above, so a clamped replay does
		// not move the anchor past the skipped range.
		if cur != nil {
			s.mu.Lock()
			s.resume = cur
			s.mu.Unlock()
		}
		if !s.deliverEvent(ctx, ev) {
			return
		}
	}
}

// deliverEvent hands one event to the caller, tagged with the resume high-water
// it belongs to. The commit of that high-water happens in [Next], on the poll
// after this one - see the commit-on-poll note there.
func (s *ResilientSubscription) deliverEvent(ctx context.Context, ev Event) bool {
	s.mu.Lock()
	cur, gen := copyCursor(s.resume), s.gen
	s.mu.Unlock()
	return s.deliver(ctx, delivery{ev: ev, cursor: cur, gen: gen})
}

// deliver blocks until the caller receives the item or the subscription is
// stopped. It reports whether the handoff completed.
func (s *ResilientSubscription) deliver(ctx context.Context, item delivery) bool {
	select {
	case s.events <- item:
		return true
	case <-ctx.Done():
		return false
	}
}

// connectOnce opens one subscription from the current resume anchor, returning
// the stream and the replay-seam height to check (nil when no replay was
// requested).
func (s *ResilientSubscription) connectOnce(ctx context.Context) (*Stream, *uint32, error) {
	if err := s.seedResume(ctx); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	resume := copyCursor(s.resume)
	s.mu.Unlock()

	opts := s.base
	opts.FromCursor = resume
	stream, err := s.client.Subscribe(ctx, opts)
	if err != nil {
		return nil, nil, err
	}
	var expect *uint32
	if resume != nil {
		h := resume.Height + 1
		expect = &h
	}
	return stream, expect, nil
}

// seedResume establishes the anchor on the first connect: the in-memory
// high-water, else the persisted cursor, else the caller's base FromCursor.
//
// A cursor read back from the store is by definition already durably
// committed, so it also seeds `committed` - that way the write-elision
// recognizes it and the first post-restart commit of an unchanged anchor is a
// no-op rather than a redundant write.
func (s *ResilientSubscription) seedResume(ctx context.Context) error {
	s.mu.Lock()
	seeded := s.resume != nil
	s.mu.Unlock()
	if seeded {
		return nil
	}
	loaded, err := s.config.store().Load(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.resume != nil {
		return nil
	}
	if loaded != nil {
		if s.committed == nil {
			c := *loaded
			s.committed = &c
		}
		s.resume = loaded
	} else if s.base.FromCursor != nil {
		c := *s.base.FromCursor
		s.resume = &c
	}
	return nil
}

// sleepCtx waits for d, reporting false if the context ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func copyCursor(c *Cursor) *Cursor {
	if c == nil {
		return nil
	}
	v := *c
	return &v
}

// orControlClosed is the error surfaced when the retry budget runs out with no
// recorded cause.
func orControlClosed(err error) error {
	if err != nil {
		return err
	}
	return &Error{Kind: KindControlClosed}
}
