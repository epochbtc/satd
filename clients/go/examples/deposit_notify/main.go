// Command deposit_notify is the README quickstart, verbatim and compiled: watch
// an address, get told the moment a payment shows up in the mempool and again
// when it confirms.
//
//	go run ./deposit_notify -endpoint 127.0.0.1:50051 -script <hex scriptPubKey>
//
// It lives here rather than only in the README so CI compiles it. The most
// copied snippet in the repository is the one that must not rot.
//
// Two things it deliberately does NOT do, both a few lines away in
// resilient_watch: it does not reconnect, and it does not persist a resume
// cursor — so a restart silently skips whatever arrived while it was down. Copy
// this to see the shape; copy that one to run it.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	satdevents "github.com/epochbtc/satd/clients/go"
)

func main() {
	endpoint := flag.String("endpoint", "127.0.0.1:50051", "satd gRPC endpoint")
	scriptHex := flag.String("script", "", "hex scriptPubKey of the address to watch (required)")
	flag.Parse()

	if *scriptHex == "" {
		log.Fatal("-script is required (the address's scriptPubKey, hex)")
	}
	script, err := hex.DecodeString(*scriptHex)
	if err != nil {
		log.Fatalf("script: %v", err)
	}

	ctx := context.Background()

	client, err := satdevents.Dial(ctx, *endpoint)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	handle, stream, err := client.Watch(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = handle.Close() }()

	// The server keys watches on sha256(scriptPubKey), so hand it the script
	// bytes from whatever Bitcoin library or RPC field you already have — the
	// SDK does not make you adopt one.
	err = handle.AddScripts(ctx, []satdevents.ScriptWatch{
		{Scripthash: satdevents.ScripthashOf(script)},
	})
	if err != nil {
		log.Fatal(err)
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			log.Fatal(err)
		}
		if m, ok := ev.(*satdevents.ScriptMatched); ok && m.IsOutput {
			state := "in the mempool"
			if m.Confirmed {
				state = "confirmed"
			}
			// DisplayHex, not raw bytes: the wire carries txids in internal
			// order, and an unreversed one matches nothing you look up.
			fmt.Printf("paid: tx %s output %d, %s\n",
				satdevents.DisplayHex(m.Txid), m.Index, state)
		}
	}
}
