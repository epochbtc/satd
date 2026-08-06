// Command watch_outpoints watches specific outpoints (txid:vout) for their
// spend, on a bidirectional Watch stream. It prints an OutpointSpent as each
// lands in the mempool and again when it confirms.
//
//	go run ./watch_outpoints -endpoint 127.0.0.1:50051 \
//	    -outpoint <txid>:0 -outpoint <txid>:1
//
// txids are given in the usual explorer / JSON-RPC display order; the SDK
// converts to the internal order the wire uses.
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
	"strconv"
	"strings"

	satdevents "github.com/epochbtc/satd/clients/go"
)

// outpointFlag collects repeated -outpoint txid:vout arguments.
type outpointFlag []satdevents.OutpointRef

func (f *outpointFlag) String() string { return fmt.Sprintf("%d outpoint(s)", len(*f)) }

func (f *outpointFlag) Set(s string) error {
	txidHex, voutStr, ok := strings.Cut(s, ":")
	if !ok {
		return fmt.Errorf("want txid:vout, got %q", s)
	}
	txid, err := satdevents.TxidFromDisplayHex(txidHex)
	if err != nil {
		return err
	}
	vout, err := strconv.ParseUint(voutStr, 10, 32)
	if err != nil {
		return fmt.Errorf("vout %q: %w", voutStr, err)
	}
	*f = append(*f, satdevents.OutpointRef{Txid: txid, Vout: uint32(vout)})
	return nil
}

func main() {
	endpoint := flag.String("endpoint", "127.0.0.1:50051", "satd gRPC endpoint")
	var outpoints outpointFlag
	flag.Var(&outpoints, "outpoint", "outpoint to watch as txid:vout (repeatable)")
	flag.Parse()

	if len(outpoints) == 0 {
		log.Fatal("at least one -outpoint is required")
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
	// The handle stays alive for the life of the stream; closing it (or
	// cancelling ctx) tears the stream and its watch-set down.
	defer func() { _ = handle.Close() }()

	if err := handle.AddOutpoints(ctx, outpoints); err != nil {
		log.Fatalf("add outpoints: %v", err)
	}
	fmt.Printf("watching %d outpoint(s)\n", len(outpoints))

	for {
		ev, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return
			}
			log.Fatalf("recv: %v", err)
		}
		if e, ok := ev.(*satdevents.OutpointSpent); ok {
			where := "mempool"
			if e.Confirmed {
				where = "confirmed"
			}
			fmt.Printf("outpoint %s:%d spent by %s vin=%d (%s)\n",
				satdevents.DisplayHex(e.Outpoint.Txid), e.Outpoint.Vout,
				satdevents.DisplayHex(e.SpendingTxid), e.SpendingVin, where)
		}
	}
}
