// Command sp_light_scan is the BIP 352 silent-payments CLIENT-SIDE SCAN
// (Tier 1, zero-custody) mode — the recommended one.
//
//	go run ./sp_light_scan -endpoint 127.0.0.1:50051 \
//	    -scan-secret <32-byte hex> -spend-secret <32-byte hex>
//
// Subscribe to the tweaks firehose and do the ECDH locally: for each block the
// node sends only the public tweak T of every silent-payment-eligible
// transaction, and this client derives its own candidate output keys — so the
// SCAN KEY NEVER LEAVES THE DEVICE. Contrast sp_wallet, where you hand the node
// b_scan and it matches for you.
//
// For each tweak and output counter k the scanner derives the unlabelled
// candidate and, for each label the receiver uses (include 0 to catch your own
// change), the labelled candidate. A candidate is yours iff its taproot output
// actually appears in the transaction. When the event carries the transaction's
// taproot outputs the match is confirmed IN-BAND, with no getblock or
// getrawtransaction round-trip; otherwise the candidate key is printed for the
// wallet to look up against the block from its own chain access.
//
// The tweaks category requires the node's tweak index (silentpaymentindex=1)
// and is not part of the default category set — request it explicitly.
//
// This example also sets MempoolTweaks (Tier 1.5), so it scans each payment at
// mempool admission as well as at confirmation — mempool-latency detection with
// the scan key still on the device. A mempool tweak ALWAYS carries its taproot
// outputs (there is no block to fall back to, and fetching an unconfirmed
// transaction races eviction); TweakOutputs asks for them on the confirmed side
// too, so both paths confirm in-band. A mempool hit and its later confirmed hit
// share a txid, so a real scanner dedups on it.
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
	probeK := flag.Uint("probe-k", 2, "how many output counters k to probe per transaction")
	label := flag.Int("label", 0, "receiver label to also scan for; negative for none")
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
	var labels []uint32
	if *label >= 0 {
		labels = []uint32{uint32(*label)}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client, err := satdevents.Dial(ctx, *endpoint)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	stream, err := client.Subscribe(ctx, satdevents.SubscribeOptions{
		// ONLY the tweaks category, explicitly — it is not in the default set.
		Categories: satdevents.CategoryTweaks,
		// Scan at mempool admission too (Tier 1.5).
		MempoolTweaks: true,
		// Ask confirmed entries to carry their taproot outputs, so the block
		// path can also confirm a match without fetching anything. Drop this
		// and BlockTweaks arrives lean, falling back to the candidate-key path.
		TweakOutputs: true,
	})
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}

	scanner := &scanner{
		scan:   scanSecret,
		spend:  spendSecret,
		probeK: uint32(*probeK),
		labels: labels,
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
		case *satdevents.BlockTweaks:
			// Confirmed: one entry per silent-payment-eligible transaction in
			// the connected block.
			for i := range e.Entries {
				scanner.scanEntry(&e.Entries[i], fmt.Sprintf("block %d", e.Height))
			}
			if e.Filtered && len(e.Entries) == 0 {
				// An empty Entries here means "filtered out", NOT "none
				// present" — a dust limit or tweaks-only filter dropped them.
				fmt.Printf("block %d: entries filtered out by a subscription filter\n", e.Height)
			}
		case *satdevents.MempoolTweak:
			scanner.scanEntry(&e.Entry, "mempool")
		}
	}
}

type scanner struct {
	scan, spend *btcec.PrivateKey
	probeK      uint32
	labels      []uint32
}

// scanEntry runs the client-side scan over one tweak entry. The cryptography is
// identical for the confirmed and mempool paths; only the log prefix differs.
func (s *scanner) scanEntry(entry *satdevents.TweakEntry, where string) {
	// A real scanner stops probing once a k misses, since outputs are numbered
	// consecutively; this one probes a fixed few to keep the loop obvious.
	for k := uint32(0); k < s.probeK; k++ {
		candidates, err := bip352.Derive(s.scan, s.spend, entry.Tweak, k, s.labels)
		if err != nil {
			log.Printf("derive k=%d: %v", k, err)
			continue
		}

		for _, c := range candidates {
			lbl := ""
			if c.Label != nil {
				lbl = fmt.Sprintf(" label=%d", *c.Label)
			}

			if out := findOutput(entry.TaprootOutputs, c.OutputKey); out != nil {
				fmt.Printf("%s tx %s k=%d%s: MATCH — vout=%d value=%d sat is yours (spend key %s)\n",
					where, satdevents.DisplayHex(entry.Txid), k, lbl,
					out.Vout, out.Value, satdevents.DisplayHexUnreversed(c.SpendKey[:]))
				continue
			}
			if len(entry.TaprootOutputs) == 0 {
				// A lean BlockTweaks with TweakOutputs off. Fall back to the
				// candidate key for the wallet to look up against the block
				// from its own chain access.
				fmt.Printf("%s tx %s k=%d%s: candidate output key %s — confirm against the block\n",
					where, satdevents.DisplayHex(entry.Txid), k, lbl,
					satdevents.DisplayHexUnreversed(c.OutputKey[:]))
			}
			// Otherwise the outputs are present and this candidate is not among
			// them: not ours at this k.
		}
	}
}

func findOutput(outs []satdevents.TaprootOutput, key [32]byte) *satdevents.TaprootOutput {
	for i := range outs {
		if bytes.Equal(outs[i].OutputPubkey, key[:]) {
			return &outs[i]
		}
	}
	return nil
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
