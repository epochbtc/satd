// Command sp_wallet is the BIP 352 silent-payments SCAN-KEY WATCH (Tier 2,
// convenience) mode.
//
//	go run ./sp_wallet -endpoint 127.0.0.1:50051 \
//	    -scan-secret <32-byte hex> -spend-secret <32-byte hex>
//
// Register a (scan secret b_scan, spend pubkey B_spend) target on a Watch
// stream; the node runs the ECDH match and pushes a SilentPaymentMatched for
// every output paying you. From each match's public tweak T and counter k this
// example re-derives the output's full spending key offline — the node never
// holds spend authority.
//
// Understand the trade before using this mode: b_scan is DISCLOSED to the node.
// It is a watch credential, not a spend key, so the operator learns which
// outputs are yours but can never spend them. The zero-custody alternative,
// where b_scan never leaves the device, is sp_light_scan.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	"github.com/btcsuite/btcd/btcec/v2"
	satdevents "github.com/epochbtc/satd/clients/go"
	"github.com/epochbtc/satd/clients/go/examples/internal/bip352"
)

func main() {
	endpoint := flag.String("endpoint", "127.0.0.1:50051", "satd gRPC endpoint")
	scanHex := flag.String("scan-secret", "", "32-byte hex scan secret b_scan (required)")
	spendHex := flag.String("spend-secret", "", "32-byte hex spend secret b_spend (required)")
	label := flag.Int("label", 0, "receiver label to also watch for; negative for none")
	flag.Parse()

	if *scanHex == "" || *spendHex == "" {
		log.Fatal("-scan-secret and -spend-secret are required")
	}
	scanSecret, err := privKeyFromHex(*scanHex)
	if err != nil {
		log.Fatalf("scan secret: %v", err)
	}
	spendSecret, err := privKeyFromHex(*spendHex)
	if err != nil {
		log.Fatalf("spend secret: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	target := satdevents.SilentPaymentTarget{
		ScanSecret:  scanSecret.Key.Bytes(),
		SpendPubkey: [33]byte(spendSecret.PubKey().SerializeCompressed()),
	}
	if *label >= 0 {
		// Label 0 is where BIP 352 puts your own change, so a wallet that omits
		// it sees payments it receives but not the change it sends itself.
		target.Labels = []uint32{uint32(*label)}
	}
	// Validate before dialing: a malformed target is rejected server-side by
	// silently installing no watch, which looks exactly like "nobody has paid
	// you yet".
	scanPubkey, err := target.Validate()
	if err != nil {
		log.Fatalf("target: %v", err)
	}
	fmt.Printf("watching scan key %s\n", satdevents.DisplayHexUnreversed(scanPubkey[:]))

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

	if err := handle.AddSilentPayments(ctx, []satdevents.SilentPaymentTarget{target}); err != nil {
		log.Fatalf("add silent payments: %v", err)
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return
			}
			log.Fatalf("recv: %v", err)
		}

		m, ok := ev.(*satdevents.SilentPaymentMatched)
		if !ok {
			continue
		}

		// Re-derive the full spending key offline from T, k, and — for a
		// labelled/change output — the label the node reported.
		c, err := bip352.DeriveFor(scanSecret, spendSecret, m.Tweak, m.K, m.Label)
		if err != nil {
			log.Printf("derive: %v", err)
			continue
		}
		// Self-check: the derived key's public key must be the matched output
		// key. A MISMATCH here is the label bug — deriving without the label
		// tweak yields a plausible key that does not control the output, so the
		// change would be silently unspendable.
		verdict := "MISMATCH"
		if bytes.Equal(c.OutputKey[:], m.OutputPubkey) {
			verdict = "verified"
		}

		where := "mempool"
		if m.Confirmed {
			where = "confirmed"
		}
		fmt.Printf("paid %d sat at %s:%d (%s) — spend key %s [%s]\n",
			m.Amount, satdevents.DisplayHex(m.Txid), m.Vout, where,
			satdevents.DisplayHexUnreversed(c.SpendKey[:]), verdict)
	}
}

func privKeyFromHex(s string) (*btcec.PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	priv, _ := btcec.PrivKeyFromBytes(b)
	return priv, nil
}
