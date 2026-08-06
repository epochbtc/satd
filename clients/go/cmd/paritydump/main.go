// Command paritydump drives the Go SDK against a live satd node and writes
// every received event as one canonical JSON line.
//
// It exists only for the differential parity harness. A Rust twin
// (satd/tests/e2e/parity.rs) drives satd-events-client through the same watch
// spec against the same node, and the harness diffs the two dumps line by line.
// Anything the two SDKs disagree about - a variant one of them cannot decode, a
// field typed differently, an off-by-one height - shows up as a diff and fails
// the PR. That is the whole point: "parity" is otherwise a claim nobody checks.
//
// Determinism is the design constraint, not ergonomics. See render.go for the
// canonical-JSON rules and the fields deliberately dropped.
//
// Usage:
//
//	paritydump -endpoint host:port -spec watch.json -until-height 120 \
//	    -ready-file /path/ready -out dump.jsonl
//
// The dumper writes -ready-file once its watch set is registered and the node
// has acknowledged it. The scenario driver must wait for BOTH dumpers' ready
// files before it mines or spends anything; otherwise one client subscribes
// mid-scenario and the diff is a race, not a finding.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	satdevents "github.com/epochbtc/satd/clients/go"
)

func main() {
	var (
		endpoint    = flag.String("endpoint", "", "gRPC endpoint, host:port (required)")
		specPath    = flag.String("spec", "", "path to the JSON watch spec (required)")
		outPath     = flag.String("out", "", "output path for JSON lines; empty writes stdout")
		readyPath   = flag.String("ready-file", "", "file to create once the watch set is live")
		untilHeight = flag.Uint("until-height", 0, "stop after a BlockConnected at or above this height")
		untilEvents = flag.Uint("until-events", 0, "stop after this many rendered events")
		timeout     = flag.Duration("timeout", 5*time.Minute, "overall deadline")
		token       = flag.String("token", "", "bearer token, if the node requires one")
	)
	flag.Parse()

	if *endpoint == "" || *specPath == "" {
		fmt.Fprintln(os.Stderr, "both -endpoint and -spec are required")
		flag.Usage()
		os.Exit(2)
	}
	if *untilHeight == 0 && *untilEvents == 0 {
		fmt.Fprintln(os.Stderr, "one of -until-height or -until-events is required: "+
			"without a sentinel the two dumps stop at different points and every diff is spurious")
		os.Exit(2)
	}

	if err := run(*endpoint, *specPath, *outPath, *readyPath,
		uint32(*untilHeight), int(*untilEvents), *timeout, *token); err != nil {
		fmt.Fprintf(os.Stderr, "paritydump: %v\n", err)
		os.Exit(1)
	}
}

func run(endpoint, specPath, outPath, readyPath string,
	untilHeight uint32, untilEvents int, timeout time.Duration, token string) error {

	sp, err := loadSpec(specPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var opts []satdevents.Option
	if token != "" {
		opts = append(opts, satdevents.WithBearerToken(token))
	}
	client, err := satdevents.Dial(ctx, endpoint, opts...)
	if err != nil {
		return fmt.Errorf("dial %s: %w", endpoint, err)
	}
	defer func() { _ = client.Close() }()

	handle, stream, err := client.Watch(ctx)
	if err != nil {
		return fmt.Errorf("watch: %w", err)
	}
	defer func() { _ = handle.Close() }()

	if err := sp.apply(ctx, handle); err != nil {
		return fmt.Errorf("apply spec: %w", err)
	}

	out := io.Writer(os.Stdout)
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		out = f
	}
	w := bufio.NewWriter(out)
	defer func() { _ = w.Flush() }()

	// Lines are buffered and sorted rather than streamed, because arrival order
	// is not a parity property.
	//
	// Two independent connections are served by independent tasks, so the node
	// legitimately interleaves a watch match against a chain event differently
	// for each. Comparing arrival order would make the harness fail on server
	// scheduling and say nothing about the SDKs. Sorting on the cursor - the
	// node's own total order over confirmed events - with the rendered line
	// itself as the tie-break gives a key derived entirely from content.
	//
	// The cost is explicit: this harness proves the two SDKs see the same events
	// with the same field values, NOT that they see them in the same order.
	var lines []sortableLine

	// Readiness barrier: one deliberately invalid rescan.
	//
	// A ready file written at connect time would let the driver start mining
	// while registration was still in flight, and the events racing that window
	// would land in one dump and not the other. Counting registration acks does
	// not work either - not every control emits one, so the count is a guess
	// that hangs when it is wrong.
	//
	// An inverted range (from > to) is rejected by the node with exactly one
	// RescanRejected and no side effects. Because gRPC preserves order on a
	// stream, everything the earlier controls provoked has already been
	// delivered by the time that reply lands. One control, one reply, no
	// counting.
	if err := handle.Rescan(ctx, 1, 0); err != nil {
		return fmt.Errorf("readiness probe: %w", err)
	}
	ready := false

	count := 0
	for {
		ev, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return flush(w, lines)
			}
			return fmt.Errorf("recv after %d event(s): %w", count, err)
		}

		if !ready {
			switch ev.(type) {
			case *satdevents.RescanRejected, *satdevents.RescanAccepted:
				ready = true
				if readyPath != "" {
					if err := writeReady(readyPath); err != nil {
						return err
					}
				}
			}
			// Everything before the barrier is registration handshake, not
			// scenario output. Dropping it keeps the diff about the node's
			// events rather than about how each SDK sequences its own setup.
			continue
		}

		if _, isBeat := ev.(*satdevents.Heartbeat); isBeat {
			// Timer-driven; see render.go.
			continue
		}

		encoded, err := json.Marshal(render(ev))
		if err != nil {
			return err
		}
		lines = append(lines, sortableLine{key: cursorKey(stream.Cursor()), line: string(encoded)})
		count++

		if bc, ok := ev.(*satdevents.BlockConnected); ok &&
			untilHeight != 0 && bc.Height >= untilHeight {
			return flush(w, lines)
		}
		if untilEvents != 0 && count >= untilEvents {
			return flush(w, lines)
		}
	}
}

// sortableLine is a rendered event plus the cursor it arrived under.
type sortableLine struct {
	key  [3]uint64
	line string
}

// cursorKey is the node's total order over confirmed events. A nil cursor sorts
// first, which is where the pre-cursor events genuinely belong.
func cursorKey(c *satdevents.Cursor) [3]uint64 {
	if c == nil {
		return [3]uint64{}
	}
	return [3]uint64{uint64(c.Height), uint64(c.TxIndex), c.MempoolSeq}
}

func flush(w *bufio.Writer, lines []sortableLine) error {
	sort.SliceStable(lines, func(i, j int) bool {
		if lines[i].key != lines[j].key {
			return lines[i].key[0] < lines[j].key[0] ||
				(lines[i].key[0] == lines[j].key[0] &&
					(lines[i].key[1] < lines[j].key[1] ||
						(lines[i].key[1] == lines[j].key[1] && lines[i].key[2] < lines[j].key[2])))
		}
		return lines[i].line < lines[j].line
	})
	for _, l := range lines {
		if _, err := w.WriteString(l.line + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

// writeReady creates the readiness file atomically, so a driver polling for it
// can never observe a half-written path.
func writeReady(path string) error {
	f, err := os.CreateTemp(dirOf(path), ".ready.*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
