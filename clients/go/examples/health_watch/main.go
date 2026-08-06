// Command health_watch watches a node's own health and reacts to it — the
// shape of a real alerting integration.
//
//	go run ./health_watch -endpoint 127.0.0.1:50051 [-token TOKEN]
//
// Five things worth copying:
//
//  1. Ask for the category explicitly. CategoryStatus is not part of the 0
//     ("all") default, so a client that does not request it receives nothing —
//     which is the point: an older client never starts receiving a body it
//     cannot parse after the node is upgraded. The node also requires the token
//     to hold rpc:read for this category, since the bodies carry host telemetry
//     that is capability-gated elsewhere.
//  2. Reconnect. This uses ResilientSubscribe, not Subscribe. A plain
//     subscription surfaces any transient stream error to the caller, and the
//     obvious log.Fatal on it ends the process — precisely when the node
//     restarting is what produced the error, which is also when it re-raises
//     every standing condition. An unsupervised copy of that shape is silently
//     off from its first blip onward.
//  3. Put a deadline on silence. Heartbeats are subscribed AND enforced with a
//     timeout. Subscribing to them and then ignoring them proves nothing: if
//     the node process is alive but its publisher is wedged, gRPC keepalive
//     still answers, Next blocks forever, and "no output" reads as "nothing is
//     wrong".
//  4. Track raise/clear pairs, don't count events. A standing condition fires
//     once when entered and once when it recovers. Holding the active set gives
//     you "what is wrong right now"; counting alerts gives you a number that
//     only ever grows.
//  5. Tolerate unknown kinds. New conditions ship additively, so a kind this
//     build predates arrives with Known() false. Severity and Message stay
//     meaningful, so route on those.
//
// # What this client cannot know
//
// Status events are NOT replayable. There is no cursor for them, so a client
// that connects after a condition was raised never learns about it, and the
// resilient subscription hides reconnects — meaning a drop during which
// tip_stall raised and disk_low cleared leaves the set below silently wrong,
// with no synthetic notice to key off (ReplayGap is cursor-anchored, and status
// carries no cursor).
//
// So the set below is labelled for what it is: what THIS CONNECTION has
// observed, not the node's true state. `getwarnings` over JSON-RPC is the
// authoritative answer to "what is wrong right now". A production integration
// should poll it on a slow timer (once a minute, say) and treat this stream as
// the low-latency edge signal on top — which is also what makes a missed
// transition self-correcting rather than permanent. This example prints the
// observed set rather than pretending to be complete; it does not poll, because
// that would need an RPC client and this file is about the stream.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	satdevents "github.com/epochbtc/satd/clients/go"
)

// silenceDeadline is how long the stream may stay silent before we treat it as
// broken.
//
// The node's heartbeat interval is well under this, so several missed pings in
// a row are needed to trip it — tight enough to catch a wedged publisher, loose
// enough not to fire on ordinary scheduling jitter.
const silenceDeadline = 90 * time.Second

func main() {
	endpoint := flag.String("endpoint", "127.0.0.1:50051", "satd gRPC endpoint")
	token := flag.String("token", "", "bearer token; the status category needs rpc:read")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var opts []satdevents.Option
	if *token != "" {
		opts = append(opts, satdevents.WithBearerToken(*token))
	}
	client, err := satdevents.Dial(ctx, *endpoint, opts...)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	sub := client.ResilientSubscribe(ctx, satdevents.SubscribeOptions{
		// CategoryHeartbeat as well as CategoryStatus, deliberately.
		//
		// Unknown category bits are ignored by design, so CategoryStatus alone
		// against a pre-0.5.0 node is accepted and then matches nothing — an
		// open connection that stays silent forever, indistinguishable from a
		// healthy node. That is failing open in the one direction alerting must
		// not. Subscribing to heartbeats makes silence a signal, and the
		// deadline below is what actually reads it.
		Categories: satdevents.CategoryStatus | satdevents.CategoryHeartbeat,
	}, satdevents.ResilientConfig{})
	defer func() { _ = sub.Close() }()

	fmt.Println("watching node health (heartbeats confirm the stream is live)")

	// Conditions this connection has seen raised and not yet seen cleared.
	// Deliberately NOT called "the node's active conditions" — see the package
	// docs: without replay this can only ever be a partial view.
	observed := map[string]struct{}{}

	for {
		// Next is cancel-safe, so a per-call deadline cannot swallow an event:
		// the handoff is unbuffered and only completes when we receive.
		callCtx, cancel := context.WithTimeout(ctx, silenceDeadline)
		ev, err := sub.Next(callCtx)
		cancel()

		if err != nil {
			if ctx.Err() != nil {
				return // Ctrl-C, not a fault.
			}
			if errors.Is(err, context.DeadlineExceeded) {
				// No event of any kind — not even a heartbeat — for the whole
				// window. Something between the node's publisher and this
				// process is stuck. Exiting non-zero is the right move for an
				// example: a supervisor restarts it, and a monitored process
				// that dies is far louder than one that sits quiet.
				log.Fatalf("no events for %s — the stream is silent, which is not "+
					"the same as the node being healthy", silenceDeadline)
			}
			// The stream failed in a way even the resilient layer would not
			// retry. Surface it; do not treat it as end-of-stream.
			log.Fatalf("stream failed: %v", err)
		}

		// Everything that is not a status body (heartbeats, a lag notice, a
		// body this build does not know) is ignored — tolerating what you did
		// not ask for is the forward-compatible default. The heartbeat's job is
		// done by arriving at all.
		s, ok := ev.(*satdevents.Status)
		if !ok {
			continue
		}

		name := s.Kind.String()
		switch s.State {
		case satdevents.StatusStateRaised:
			observed[name] = struct{}{}
		case satdevents.StatusStateCleared:
			delete(observed, name)
		case satdevents.StatusStateEdge:
			// A one-shot observation: it happened, there is nothing to clear.
		case satdevents.StatusStateUnspecified:
			// The producer did not set a state. This is the dangerous one to
			// swallow: if the event that arrived unset was a CLEAR, dropping it
			// silently leaves the condition standing in `observed` for the life
			// of the process, long after it recovered. We cannot infer which it
			// was, so say so loudly and let the operator reconcile against
			// getwarnings rather than trusting the set below.
			log.Printf("  !! %s arrived with no state — cannot tell raise from clear; "+
				"the standing set below may now be wrong", name)
		default:
			// A state this build predates. Do not guess at its lifecycle.
		}

		fmt.Printf("[%s] %s %s: %s  %s\n",
			route(s.Severity), name, s.State, s.Message, details(s.Details))

		if len(observed) == 0 {
			// NOT "all clear": this client may simply never have been told.
			// getwarnings is the surface that can answer that.
			fmt.Println("       → nothing standing that this client has observed")
		} else {
			fmt.Printf("       → standing (observed): %s\n", strings.Join(sortedKeys(observed), ", "))
		}
	}
}

// route picks a destination from severity rather than from kind, so a condition
// this build does not recognize still reaches the right place.
func route(sev satdevents.StatusSeverity) string {
	switch sev {
	case satdevents.SeverityUnspecified:
		// The producer never set a severity. Log it — the kind and message are
		// still meaningful — but do not page: an absent field is not a critical
		// condition, and treating it as one pages on every partial or buggy
		// producer.
		return "info"
	case satdevents.SeverityInfo:
		return "info"
	case satdevents.SeverityWarning:
		return "warn"
	case satdevents.SeverityCritical:
		return "PAGE"
	default:
		// An unrecognized severity pages deliberately: a condition we cannot
		// name is not one to quietly downgrade.
		return "PAGE"
	}
}

func details(d map[string]string) string {
	if len(d) == 0 {
		return ""
	}
	parts := make([]string, 0, len(d))
	for _, k := range sortedKeys(d) {
		parts = append(parts, fmt.Sprintf("%s=%s", k, d[k]))
	}
	return strings.Join(parts, " ")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
