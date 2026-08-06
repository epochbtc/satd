// Command resilient_watch is a reconnect-and-replay-aware Watch: a
// durable-truth watch-set loader rebuilds the canonical set from an external
// store on every (re)connect, Reload realigns a live stream with that truth on
// demand, and the resume cursor survives both transient disconnects and a full
// process restart.
//
//	go run ./resilient_watch -endpoint 127.0.0.1:50051 \
//	    -cursor /tmp/satd-watch.cursor -script <hex scriptPubKey>
//
// The watch-set is per-CONNECTION — the server keys no state to the principal —
// so a dropped stream loses it entirely. That is what the loader is for: it
// makes the integrator's own durable store the record, rather than the
// in-process history of Add/Remove calls, which is empty after a restart.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"

	satdevents "github.com/epochbtc/satd/clients/go"
)

// watchedScripts stands in for a durable source of truth — a database, a config
// file, an upstream service. A real integrator would query it with real I/O
// inside the loader; the mutex here is only because this toy lives in memory.
type watchedScripts struct {
	mu           sync.Mutex
	scripthashes [][32]byte
}

func (w *watchedScripts) snapshot() [][32]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][32]byte(nil), w.scripthashes...)
}

func (w *watchedScripts) insert(h [32]byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.scripthashes = append(w.scripthashes, h)
}

func main() {
	endpoint := flag.String("endpoint", "127.0.0.1:50051", "satd gRPC endpoint")
	cursorPath := flag.String("cursor", "/tmp/satd-watch.cursor", "file to persist the resume cursor in")
	scriptHex := flag.String("script", "", "hex scriptPubKey to watch (required)")
	flag.Parse()

	if *scriptHex == "" {
		log.Fatal("-script is required (hex scriptPubKey)")
	}
	script, err := hex.DecodeString(*scriptHex)
	if err != nil {
		log.Fatalf("script: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Seed the truth. A real integrator's store already holds whatever it
	// persisted before this process started.
	truth := &watchedScripts{}
	truth.insert(satdevents.ScripthashOf(script))

	client, err := satdevents.Dial(ctx, *endpoint)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	watch := client.ResilientWatch(ctx, satdevents.ResilientWatchConfig{
		CursorStore: satdevents.NewFileCursorStore(*cursorPath),
		// Runs on every (re)connect, before any event is pumped, so the mirror
		// can never go stale after a restart or an outage.
		WatchSetLoader: func(ctx context.Context, set *satdevents.WatchSet) error {
			for _, h := range truth.snapshot() {
				set.AddScripts(satdevents.ScriptWatch{Scripthash: h})
			}
			return nil
		},
	})
	defer func() { _ = watch.Close() }()

	// New addresses (from a wallet's own key derivation, say) go into the truth
	// and are picked up with Reload rather than a live AddScripts, so a later
	// reconnect's loader agrees with what this process registered.
	added := false
	for {
		ev, err := watch.Next(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Fatalf("fatal: %v", err)
		}

		switch e := ev.(type) {
		case *satdevents.ScriptMatched:
			side := "spending"
			if e.IsOutput {
				side = "funding"
			}
			where := "mempool"
			if e.Confirmed {
				where = "confirmed"
			}
			fmt.Printf("watch hit tx=%s %s (%s)\n", satdevents.DisplayHex(e.Txid), side, where)

			if !added {
				added = true
				truth.insert([32]byte{0x22})
				summary, err := watch.Reload(ctx)
				if err != nil {
					log.Fatalf("reload: %v", err)
				}
				fmt.Printf("reload: +%d -%d =%d applied=%v\n",
					summary.Added, summary.Removed, summary.Unchanged, summary.Applied)
			}

		case *satdevents.ReplayGap:
			// The one event that is NOT at-least-once: the server could not
			// replay this range, so these blocks were never delivered and never
			// will be. Everything else the SDK redelivers on reconnect; this
			// has to be repaired from the caller's own chain access.
			//
			// A durable watcher that logs this and moves on has silently lost
			// every match in [From, To) — which for a deposit watcher means
			// credited funds that were never credited.
			log.Printf("REPLAY GAP %d..%d: rescan this range or resync from your "+
				"own chain source; these matches will not be redelivered",
				e.ResumeHeight, e.FirstHeight)

		case *satdevents.CursorRejected:
			// The persisted cursor is outside what this node can replay (a
			// stale store, or a node whose retention window moved past it). A
			// real integrator clears the store and resnapshots from scratch
			// here rather than continuing from an anchor the server refused.
			log.Printf("re-anchor rejected: %s (server head height=%d)",
				e.Reason, headHeight(e.CurrentHead))
		}
	}
}

func headHeight(c *satdevents.Cursor) uint32 {
	if c == nil {
		return 0
	}
	return c.Height
}
