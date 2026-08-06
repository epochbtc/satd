// Command prefix_privacy runs a privacy-preserving prefix watch: it registers a
// coarse bits-wide bucket of sha256(scriptPubKey) — so the node learns only the
// bucket, never the script — and then re-filters the decoy-laden deliveries
// down to true matches locally.
//
//	go run ./prefix_privacy -endpoint 127.0.0.1:50051 -bits 16 \
//	    -script <hex scriptPubKey> [-script ...]
//
// The trade is explicit: a bits-wide bucket delivers roughly every transaction
// in 2^-bits of the chain's traffic, and the client discards the ones that are
// not its own. Narrower buckets cost more bandwidth and more watch quota, and
// buy more privacy.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	satdevents "github.com/epochbtc/satd/clients/go"
)

// scriptFlag collects repeated -script hex arguments.
type scriptFlag [][]byte

func (f *scriptFlag) String() string { return fmt.Sprintf("%d script(s)", len(*f)) }

func (f *scriptFlag) Set(s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return errors.New("empty script")
	}
	*f = append(*f, b)
	return nil
}

func main() {
	endpoint := flag.String("endpoint", "127.0.0.1:50051", "satd gRPC endpoint")
	bits := flag.Uint("bits", 16, "bucket width in bits; smaller hides more and costs more")
	var scripts scriptFlag
	flag.Var(&scripts, "script", "hex scriptPubKey to watch (repeatable)")
	flag.Parse()

	if len(scripts) == 0 {
		log.Fatal("at least one -script is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// The real scripts stay in this process; only buckets go to the node.
	watcher := satdevents.NewPrefixWatcherWithScripts(scripts...)
	prefixes := watcher.Prefixes(uint32(*bits))

	client, err := satdevents.Dial(ctx, *endpoint)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	handle, stream, err := client.Watch(ctx)
	if err != nil {
		log.Fatalf("watch: %v", err)
	}
	defer func() { _ = handle.Close() }()

	if err := handle.AddScriptPrefixes(ctx, prefixes); err != nil {
		log.Fatalf("add prefixes: %v", err)
	}
	// Distinct scripts sharing a bucket collapse into one registration, which
	// is the point — the node cannot tell how many scripts a bucket covers.
	fmt.Printf("watching %d script(s) as %d bucket(s) at %d bits\n",
		watcher.Len(), len(prefixes), *bits)

	for {
		ev, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return
			}
			log.Fatalf("recv: %v", err)
		}

		m, ok := ev.(*satdevents.PrefixMatched)
		if !ok {
			continue
		}

		// The bucket fired. Decode the delivered transaction and re-filter it
		// against the real scripts.
		hits, err := watcher.Filter(m)
		if err != nil {
			log.Printf("filter: %v", err)
			continue
		}
		for _, f := range hits.Funding {
			fmt.Printf("funding hit tx=%s vout=%d value=%d\n",
				satdevents.DisplayHex(hits.Txid[:]), f.Vout, f.Value)
		}
		for _, s := range hits.Spending {
			fmt.Printf("spend hit tx=%s outpoint=%s:%d\n",
				satdevents.DisplayHex(hits.Txid[:]),
				satdevents.DisplayHex(s.Outpoint.Txid), s.Outpoint.Vout)
		}
		if hits.HasUnresolved() {
			// The server did not retain these prevout scripts (a mempool
			// delivery below the `full` prevout-metadata tier). They are
			// UNKNOWN, not misses: resolve the outpoints yourself before
			// concluding the transaction does not touch you.
			fmt.Printf("%d prevout(s) need local resolution\n", len(hits.Unresolved))
		}
		// Anything else is a decoy from the bucket — silently ignored. That is
		// the bandwidth cost of the privacy.
	}
}
