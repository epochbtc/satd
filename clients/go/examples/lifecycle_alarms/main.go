// Command lifecycle_alarms tracks a transaction's lifecycle
// (seen -> confirmed -> replaced / evicted) and arms depth alarms that fire
// once at given confirmation depths.
//
//	go run ./lifecycle_alarms -endpoint 127.0.0.1:50051 -txid <txid>
//
// The lifecycle watch is registered with an auto-close depth, so it self-evicts
// (emitting TxidFinalized) once the transaction is buried that deep — a free
// modifier that costs no extra watch quota and saves an explicit removal.
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
	txidHex := flag.String("txid", "", "txid to track, in display order (required)")
	finalDepth := flag.Uint("final-depth", 6, "auto-close the lifecycle watch at this depth")
	flag.Parse()

	if *txidHex == "" {
		log.Fatal("-txid is required")
	}
	txid, err := satdevents.TxidFromDisplayHex(*txidHex)
	if err != nil {
		log.Fatalf("txid: %v", err)
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

	// Lifecycle watch that self-evicts (emitting TxidFinalized) at -final-depth.
	if err := handle.AddTxLifecycle(ctx, [][32]byte{txid},
		satdevents.AutoCloseAtDepth(uint32(*finalDepth))); err != nil {
		log.Fatalf("add lifecycle: %v", err)
	}
	// Single-shot alarms at 1 and 3 confirmations. Depth alarms are the cross
	// product of txids and depths, and each pair costs one quota unit.
	if err := handle.AddDepthAlarms(ctx, [][32]byte{txid}, []uint32{1, 3}); err != nil {
		log.Fatalf("add depth alarms: %v", err)
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return
			}
			log.Fatalf("recv: %v", err)
		}

		switch e := ev.(type) {
		case *satdevents.TxidMatched:
			where := "mempool"
			if e.Confirmed {
				where = "confirmed"
			}
			fmt.Printf("seen (%s) at height %d\n", where, e.Height)
		case *satdevents.TxidDepthReached:
			fmt.Printf("depth alarm: %d confs at height %d\n", e.Depth, e.Height)
		case *satdevents.TxidUnconfirmed:
			// A reorg took the confirming block back out. The transaction is
			// unconfirmed again; earlier depth alarms do NOT re-arm.
			fmt.Printf("unconfirmed again (was at height %d)\n", e.PrevHeight)
		case *satdevents.TxidReplaced:
			fmt.Printf("replaced by %s\n", satdevents.DisplayHex(e.ReplacingTxid))
		case *satdevents.TxidEvicted:
			fmt.Printf("evicted: %s\n", e.Reason)
		case *satdevents.TxidFinalized:
			fmt.Printf("finalized at %d confs — watch auto-closed\n", e.Depth)
			return
		}
	}
}
