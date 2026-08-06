// Command resilient_tail is a durable firehose: it reconnects with backoff,
// persists the resume cursor to a file, and recovers from lag automatically. It
// survives both transient disconnects and a full process restart — on launch
// the cursor file replays whatever was missed.
//
//	go run ./resilient_tail -endpoint 127.0.0.1:50051 -cursor /tmp/satd.cursor
//
// This is the shape to copy for anything long-running. firehose_tail is
// shorter, but its first transport hiccup ends the process.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	satdevents "github.com/epochbtc/satd/clients/go"
)

func main() {
	endpoint := flag.String("endpoint", "127.0.0.1:50051", "satd gRPC endpoint")
	cursorPath := flag.String("cursor", "/tmp/satd.cursor", "file to persist the resume cursor in")
	token := flag.String("token", "", "bearer token, if the node requires one")
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

	// A file-backed cursor store is the one setting worth having by default: a
	// restart then resumes from the persisted height instead of forward-only,
	// silently skipping everything that happened while the process was down.
	sub := client.ResilientSubscribe(ctx,
		satdevents.SubscribeOptions{
			Categories: satdevents.CategoryMempool | satdevents.CategoryChain,
		},
		satdevents.ResilientConfig{
			CursorStore: satdevents.NewFileCursorStore(*cursorPath),
		})
	defer func() { _ = sub.Close() }()

	// Next reconnects and replays underneath. It returns an error only for a
	// permanent failure (bad endpoint or token) or exhausted retries — not for
	// an ordinary disconnect.
	for {
		ev, err := sub.Next(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Fatalf("fatal: %v", err)
		}

		switch e := ev.(type) {
		case *satdevents.ReplayGap:
			// Delivery is at-least-once EXCEPT here. The persisted cursor fell
			// out of the server's replay window, so blocks in the open interval
			// below were never delivered and never will be. Anything that must
			// not miss a payment has to full-resync that range from another
			// source; logging it and moving on quietly loses transactions.
			log.Printf("WARNING: replay clamped — blocks (%d, %d) skipped; "+
				"full-resync them from another source", e.ResumeHeight, e.FirstHeight)
		case *satdevents.Lagged:
			// The server dropped events because this consumer fell behind. The
			// resilience layer re-anchors from ResumeCursor on its own; this is
			// a signal that the consumer loop is too slow, not a fault to act on.
			log.Printf("lagged: %d event(s) dropped", e.DroppedCount)
		case *satdevents.BlockConnected:
			fmt.Printf("block %d %s\n", e.Height, satdevents.DisplayHex(e.Hash))
		case *satdevents.MempoolEnter:
			fmt.Printf("mempool enter %s fee=%d\n", satdevents.DisplayHex(e.Txid), e.Fee)
		default:
			fmt.Printf("event %T\n", ev)
		}
	}
}
