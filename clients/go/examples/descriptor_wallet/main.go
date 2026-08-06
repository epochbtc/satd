// Command descriptor_wallet watches a wallet by output descriptor: the node
// expands [start, start+gap) into a script watch-set, and this client advances
// the gap-limit window as funding approaches its high end.
//
//	go run ./descriptor_wallet -endpoint 127.0.0.1:50051 \
//	    -descriptor 'wpkh([deadbeef/84h/0h/0h]xpub6.../0/*)' -gap-limit 20
//
// Gap-limit advancement is the WALLET's job, not the node's: the server retains
// descriptor-to-scripthash membership but tracks no derivation progress, and it
// never pushes a "you are running out of addresses" nudge. Re-sending the
// descriptor with a higher start slides the window, and the server reconciles
// it — scripts that left are released, scripts that entered are added.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	satdevents "github.com/epochbtc/satd/clients/go"
)

func main() {
	endpoint := flag.String("endpoint", "127.0.0.1:50051", "satd gRPC endpoint")
	descriptor := flag.String("descriptor", "", "ranged output descriptor (required)")
	gapLimit := flag.Uint("gap-limit", 20, "window width to keep watched")
	start := flag.Uint("start", 0, "first derivation index of the window")
	flag.Parse()

	if *descriptor == "" {
		log.Fatal("-descriptor is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

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

	window := uint32(*start)
	gap := uint32(*gapLimit)
	if err := handle.AddDescriptor(ctx, *descriptor, gap, window); err != nil {
		log.Fatalf("add descriptor: %v", err)
	}
	fmt.Printf("watching %s over [%d, %d)\n", *descriptor, window, window+gap)

	for {
		ev, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return
			}
			log.Fatalf("recv: %v", err)
		}

		e, ok := ev.(*satdevents.ScriptMatched)
		if !ok {
			continue
		}

		side := "spending"
		if e.IsOutput {
			side = "funding"
		}
		where := "mempool"
		if e.Confirmed {
			where = "confirmed"
		}
		// Attribution gives the exact (branch, derivation index) the server
		// derived the matched script at, so there is no need to re-expand the
		// descriptor or keep a reverse scripthash index locally.
		for _, d := range e.Descriptors {
			fmt.Printf("descriptor hit tx=%s %s idx=%d branch=%d derivation=%d (%s)\n",
				satdevents.DisplayHex(e.Txid), side, e.Index, d.Branch, d.DerivationIndex, where)

			// Only FUNDING (output-side) hits consume addresses — never a
			// spend, which pays out of an index already in use. Advance once a
			// funding hit lands in the top half of the window, so unused
			// addresses stay covered well before anyone pays one.
			//
			// Re-anchoring at the hit drops the indices below it. That is right
			// for a wallet that hands out addresses in order (they are spent
			// for), and wrong for one that does not — such a wallet should
			// widen the window rather than slide it.
			if e.IsOutput && d.DerivationIndex+gap/2 >= window+gap {
				window = d.DerivationIndex + 1
				if err := handle.AddDescriptor(ctx, *descriptor, gap, window); err != nil {
					log.Fatalf("advance window: %v", err)
				}
				fmt.Printf("  → window advanced to [%d, %d)\n", window, window+gap)
			}
		}
	}
}
