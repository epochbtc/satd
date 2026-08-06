// Command firehose_tail tails the firehose: connect, subscribe to mempool +
// chain, print each event.
//
//	go run ./firehose_tail -endpoint 127.0.0.1:50051 [-token TOKEN]
//
// This is the smallest useful shape. It is also the one to grow out of quickly:
// a plain Subscribe surfaces the first transport hiccup to the caller and stops.
// See resilient_tail for the version that reconnects and resumes.
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
	token := flag.String("token", "", "bearer token, if the node requires one")
	flag.Parse()

	// Ctrl-C cancels the context, which tears the stream down and returns from
	// Recv — rather than killing the process mid-event.
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

	stream, err := client.Subscribe(ctx, satdevents.SubscribeOptions{
		Categories: satdevents.CategoryMempool | satdevents.CategoryChain,
	})
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return
			}
			log.Fatalf("recv: %v", err)
		}

		switch e := ev.(type) {
		case *satdevents.MempoolEnter:
			// DisplayHex, not raw bytes: the wire carries txids in internal
			// order, and a txid printed unreversed will not match anything you
			// look up in an explorer or over JSON-RPC.
			fmt.Printf("mempool enter %s fee=%d vsize=%d\n",
				satdevents.DisplayHex(e.Txid), e.Fee, e.Vsize)
		case *satdevents.BlockConnected:
			fmt.Printf("block %d %s\n", e.Height, satdevents.DisplayHex(e.Hash))
		case *satdevents.Reorg:
			fmt.Printf("reorg %d -> %d\n", e.FromHeight, e.ToHeight)
		default:
			// The cursor advances on confirmed events — persist it to resume.
			if c := stream.Cursor(); c != nil {
				fmt.Printf("event %T (cursor height=%d)\n", ev, c.Height)
			} else {
				fmt.Printf("event %T\n", ev)
			}
		}
	}
}
