// Command sp_light_scan is the BIP 352 silent-payments CLIENT-SIDE SCAN
// (Tier 1, zero-custody) mode — the recommended one.
//
//	export SATD_SP_SCAN_SECRET=<32-byte hex> SATD_SP_SPEND_SECRET=<32-byte hex>
//	go run ./sp_light_scan -endpoint 127.0.0.1:50051 \
//	    -cursor /tmp/satd-sp.cursor -from-height 709632
//
// The secrets are read from the environment rather than from flags: a flag value
// is world-readable in /proc/<pid>/cmdline and shows up in `ps` and in shell
// history. Flags still work, with a warning.
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
//
// RESUME IS DURABLE, and the SDK owns the hard part. The scan runs under
// ResilientSubscribe with a file-backed cursor store, which persists each block's
// cursor COMMIT-ON-POLL: the write happens when this loop comes back for the next
// event — that is, only once the block it belongs to has been scanned. A crash
// mid-block replays that block instead of skipping it. Getting this backwards is
// how a scanner silently loses a payment: persist the cursor of an event you have
// not finished processing and a restart resumes past it. (The opposite slip —
// persisting one event BEHIND — only costs a rescan, and is a real bug in a
// shipped wallet: cake-tech/cake_wallet#3574.) Do not hand-roll it.
//
// COLD SYNC: -from-height is where the scan begins when the cursor file is empty
// — taproot activation (709632 on mainnet) for a fresh wallet, which the server
// replays in one unclamped, backpressured subscription. Once the file holds a
// cursor it wins, so the flag seeds the first run only and is harmless to leave
// in place.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/btcsuite/btcd/btcec/v2"
	satdevents "github.com/epochbtc/satd/clients/go"
	"github.com/epochbtc/satd/clients/go/examples/internal/bip352"
	"github.com/epochbtc/satd/clients/go/examples/internal/secret"
)

func main() {
	endpoint := flag.String("endpoint", "127.0.0.1:50051", "satd gRPC endpoint")
	cursorPath := flag.String("cursor", "/tmp/satd-sp.cursor", "file to persist the resume cursor in")
	fromHeight := flag.Uint("from-height", 0, "first height to scan on a cold start (0 = live only)")
	scanHex := flag.String("scan-secret", "", "32-byte hex scan secret b_scan; prefer $SATD_SP_SCAN_SECRET")
	spendHex := flag.String("spend-secret", "", "32-byte hex spend secret b_spend; prefer $SATD_SP_SPEND_SECRET")
	probeK := flag.Uint("probe-k", 2, "how many output counters k to probe per transaction")
	label := flag.Int("label", 0, "receiver label to also scan for; negative for none")
	flag.Parse()

	// Secrets come from the environment by default: a flag value is visible in
	// `ps` and /proc/<pid>/cmdline. See the internal/secret package.
	scanText, err := secret.FromEnvOrFlag("SATD_SP_SCAN_SECRET", *scanHex, "-scan-secret")
	if err != nil {
		log.Fatalf("scan secret: %v", err)
	}
	spendText, err := secret.FromEnvOrFlag("SATD_SP_SPEND_SECRET", *spendHex, "-spend-secret")
	if err != nil {
		log.Fatalf("spend secret: %v", err)
	}
	scanSecret, err := privKeyFromHex(scanText)
	if err != nil {
		log.Fatalf("scan secret: %v", err)
	}
	spendSecret, err := privKeyFromHex(spendText)
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

	opts := satdevents.SubscribeOptions{
		// ONLY the tweaks category, explicitly — it is not in the default set.
		Categories: satdevents.CategoryTweaks,
		// Scan at mempool admission too (Tier 1.5).
		MempoolTweaks: true,
		// Ask confirmed entries to carry their taproot outputs, so the block
		// path can also confirm a match without fetching anything. Drop this
		// and BlockTweaks arrives lean, falling back to the candidate-key path.
		TweakOutputs: true,
	}
	if *fromHeight > 0 {
		// A cursor names the last height already DONE, so anchoring at h-1
		// makes h itself the first block replayed: -from-height 709632 scans
		// block 709632 rather than skipping it. Seed only — the persisted
		// cursor wins whenever the store has one.
		opts.FromCursor = &satdevents.Cursor{Height: uint32(*fromHeight) - 1}
	}

	// The file-backed store is what makes a restart resume instead of rescanning
	// from scratch, and commit-on-poll is what makes it resume SAFELY.
	sub := client.ResilientSubscribe(ctx, opts, satdevents.ResilientConfig{
		CursorStore: satdevents.NewFileCursorStore(*cursorPath),
	})
	defer func() { _ = sub.Close() }()

	scanner := &scanner{
		scan:   scanSecret,
		spend:  spendSecret,
		probeK: uint32(*probeK),
		labels: labels,
	}

	// Next reconnects and replays underneath, and commits the previous event's
	// cursor on the way in. It returns an error only on a permanent failure.
	for {
		ev, err := sub.Next(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
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
		case *satdevents.ReplayGap:
			// Tweak replay is unclamped, so a scanner should never see this. If
			// it ever does, blocks went unscanned — for a wallet that is missed
			// money, not a warning. Stop rather than carry a hole in the history.
			log.Fatalf("replay gap: blocks (%d, %d) were never scanned; rescan that "+
				"range before trusting this wallet's balance", e.ResumeHeight, e.FirstHeight)
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
				// c.SpendKey — the private scalar controlling this output — is
				// deliberately not printed. Hand it to your signer, never to a
				// log; stdout here is journald or a log aggregator in any real
				// deployment. The output key is public and identifies the coin.
				fmt.Printf("%s tx %s k=%d%s: MATCH — vout=%d value=%d sat is yours (output key %s)\n",
					where, satdevents.DisplayHex(entry.Txid), k, lbl,
					out.Vout, out.Value, satdevents.DisplayHexUnreversed(c.OutputKey[:]))
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
