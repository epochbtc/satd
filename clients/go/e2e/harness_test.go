//go:build e2e

// Package e2e drives the Go SDK against a real satd regtest node over a real
// gRPC socket.
//
// It is an independent module (see go.mod) so its test-only dependencies never
// reach the published SDK's graph, and it is behind the `e2e` build tag so a
// plain `go test ./...` in clients/go never tries to boot a node.
//
// Run it against a built satd binary:
//
//	SATD_BIN=../../../target/debug/satd go test -tags e2e ./...
//
// The sibling Rust suite (satd/tests/e2e/sdk.rs) proves the same recipes for
// the Rust SDK; PR 7 of this stack adds a differential harness that runs both
// against one node and diffs their view of the same events.
package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	satdevents "github.com/epochbtc/satd/clients/go"
)

// Regtest keys the harness mines to and spends from. Each is
// (WIF, P2WPKH address, scriptPubKey) for the private key that is one byte
// repeated 32 times - the same construction the Rust E2E suite's
// DeterministicWallet uses, so a scenario reads the same across both suites.
type wallet struct {
	wif     string
	address string
	// pubkey is the compressed public key, hex - the form a fixed wpkh()
	// descriptor takes.
	pubkey string
	spk    []byte
}

var (
	// walletA (key 0x11...) receives the mined coinbases and funds spends.
	walletA = wallet{
		wif:     "cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw",
		address: "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw",
		pubkey:  "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
		spk:     mustHex("0014fc7250a211deddc70ee5a2738de5f07817351cef"),
	}
	// walletB (key 0x22...) is the spend destination - the address a watch-set
	// test registers to see a funding match.
	walletB = wallet{
		wif:     "cNj3zTdrLAMQtUhdFPPVJtRY7a3TdUF38ShW5MrJkVh1CVaeuEGU",
		address: "bcrt1q2vfxp232rx0z9rzn0hay9jptagk8c86ddphpjv",
		pubkey:  "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
		spk:     mustHex("0014531260aa2a199e228c537dfa42c82bea2c7c1f4d"),
	}
	// walletC (key 0x99...) absorbs filler blocks so they never touch the
	// scripts a test is watching.
	walletC = wallet{
		wif:     "cSjHC4wLYdiLsnaFWMaAwuGVq78u24maQT4EGe1geTB8rpGvbmqX",
		address: "bcrt1q6tvhjq0thwhe0wl8c7kyrjjhsfzd259z3jpr9l",
		pubkey:  "028985087b1818714f67e494a076ca0284c060fabc5d2ba66885b4ac60f801d3f5",
		spk:     mustHex("0014d2d97901ebbbaf97bbe7c7ac41ca578244d550a2"),
	}
)

// scripthash is sha256(scriptPubKey) - the value the server keys script
// watches on.
func (w wallet) scripthash() [32]byte { return sha256.Sum256(w.spk) }

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// timeoutMult scales every deadline in this suite, mirroring the Rust harness's
// SATD_E2E_TIMEOUT_MULT. A hosted CI runner under load takes far longer than a
// dev machine, and a fixed deadline there is a flake generator.
func timeoutMult() float64 {
	for _, k := range []string{"SATD_E2E_TIMEOUT_MULT", "SATD_TEST_TIMEOUT_MULT"} {
		if v := os.Getenv(k); v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f < 100 {
				return f
			}
		}
	}
	return 1
}

func timeout(seconds float64) time.Duration {
	return time.Duration(seconds * timeoutMult() * float64(time.Second))
}

// Two kinds of deadline live in this suite, and they want opposite treatment.
// Conflating them is how a flake fix turns into a slow suite, or into a weaker
// assertion that still looks green.
//
// A POSITIVE WAIT — recvMatching, awaitRW, a poll loop — returns the instant its
// condition holds. Its deadline is paid only when the test is about to fail
// anyway, so a generous one costs nothing on the happy path and buys headroom on
// a loaded runner. These are 60s here (180s at the CI multiplier). Widen freely.
//
// A NEGATIVE WINDOW — collect, or a context deadline used to prove nothing
// arrives — is paid in full on EVERY run, because "nothing happened" can only be
// established by waiting. Widening one slows every green run to buy confidence
// in a claim that is already anchored: each is preceded by a positive wait that
// proves the stream is live and past the point of interest, so anything wrongly
// delivered would already have arrived. Leave them small, and if one flakes,
// strengthen the barrier ahead of it rather than inflating the window.

// node is a running satd regtest daemon with the gRPC streaming listener up.
type node struct {
	t        *testing.T
	cmd      *exec.Cmd
	datadir  string
	rpcPort  int
	grpcPort int
	cookie   string
	stderr   string
	// env is extra KEY=VALUE entries for the satd process, preserved across a
	// restart so a test knob (a shrunk event buffer, say) survives it.
	env []string
}

// satdBinary locates the satd binary under test. CI points SATD_BIN at the
// binary the Rust E2E step just built; locally the workspace debug build is the
// obvious default.
func satdBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SATD_BIN"); p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("SATD_BIN=%s is not usable: %v", p, err)
		}
		return p
	}
	// clients/go/e2e -> repo root.
	def, err := filepath.Abs("../../../target/debug/satd")
	if err != nil {
		t.Fatalf("resolving the default satd path: %v", err)
	}
	if _, err := os.Stat(def); err != nil {
		t.Skipf("no satd binary at %s and SATD_BIN is unset; "+
			"build one with `cargo build -p satd --bin satd` or set SATD_BIN", def)
	}
	return def
}

// freePort asks the OS for an unused TCP port. There is an inherent race
// between closing the listener and satd binding it, which is why startNode
// retries the whole spawn rather than trusting one allocation.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocating a port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

var nodeSeq atomic.Uint64

// startNode boots a regtest satd with the gRPC streaming listener on an
// OS-assigned port and waits until both the JSON-RPC and the listener are up.
//
// extraArgs are appended after the harness's own flags, so a test can override
// any of them.
func startNode(t *testing.T, extraArgs ...string) *node {
	t.Helper()
	return startNodeEnv(t, nil, extraArgs...)
}

// startNodeEnv is startNode with extra KEY=VALUE environment entries, for the
// node-side test knobs (SATD_EVENT_BROADCAST_CAPACITY and friends).
func startNodeEnv(t *testing.T, env []string, extraArgs ...string) *node {
	t.Helper()
	bin := satdBinary(t)

	// A satd that never answers RPC has almost always crashed on startup (a
	// port race, a datadir lock) rather than being slow, so retry the spawn on
	// a fresh port/datadir instead of polling a corpse until the deadline.
	const attempts = 3
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		n, err := tryStartNode(t, bin, env, extraArgs)
		if err == nil {
			return n
		}
		lastErr = err
		t.Logf("satd startup failed (attempt %d/%d): %v", attempt, attempts, err)
	}
	t.Fatalf("satd failed to start after %d attempts: %v", attempts, lastErr)
	return nil
}

func tryStartNode(t *testing.T, bin string, env []string, extraArgs []string) (*node, error) {
	t.Helper()
	rpcPort := freePort(t)
	p2pPort := freePort(t)
	datadir := filepath.Join(t.TempDir(), fmt.Sprintf("satd-%d-%d", rpcPort, nodeSeq.Add(1)))
	if err := os.MkdirAll(datadir, 0o755); err != nil {
		return nil, err
	}

	args := []string{
		"--regtest",
		"--datadir=" + datadir,
		fmt.Sprintf("--rpcport=%d", rpcPort),
		fmt.Sprintf("--port=%d", p2pPort),
		// Bind the streaming listener on an OS-assigned port and read it back
		// from getserverstatus: picking a port up front and binding it later is
		// a TOCTOU race under parallel tests.
		"--events-grpc-bind=127.0.0.1:0",
		// The Esplora server binds a fixed port and would collide across nodes.
		"--esplora=0",
		"--loglevel=error",
	}
	args = append(args, extraArgs...)

	stderrPath := filepath.Join(datadir, "satd.stderr")
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = stderrFile.Close() }()

	cmd := exec.Command(bin, args...)
	cmd.Stdout = nil
	cmd.Stderr = stderrFile
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	n := &node{t: t, cmd: cmd, datadir: datadir, rpcPort: rpcPort, stderr: stderrPath, env: env}
	if err := n.waitReady(); err != nil {
		n.kill()
		return nil, fmt.Errorf("%w%s", err, n.stderrTail())
	}
	t.Cleanup(n.kill)
	return n, nil
}

// waitReady polls until the JSON-RPC answers and the gRPC listener reports a
// bound address. satd starts the JSON-RPC server before the optional listeners
// bind, so RPC readiness alone does not imply the streaming port is up.
func (n *node) waitReady() error {
	deadline := time.Now().Add(timeout(120))
	cookiePath := filepath.Join(n.datadir, "regtest", ".cookie")
	var lastErr error
	for time.Now().Before(deadline) {
		if n.cmd.ProcessState != nil {
			return fmt.Errorf("satd exited before its RPC came up")
		}
		// Re-read the cookie every poll rather than caching the first one seen.
		// After a restart the old file is still on disk for a moment, so caching
		// pins a credential satd has already replaced and every later call comes
		// back Unauthorized - which reads as "the node never came up".
		raw, err := os.ReadFile(cookiePath)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		n.cookie = strings.TrimSpace(string(raw))
		var info struct {
			Chain string `json:"chain"`
		}
		if err := n.call("getblockchaininfo", nil, &info); err != nil || info.Chain == "" {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		port, err := n.grpcBoundPort()
		if err == nil && port != 0 {
			n.grpcPort = port
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("satd did not become ready within %s (last error: %v)",
		timeout(120), lastErr)
}

// grpcBoundPort reads the runtime-bound streaming port out of getserverstatus.
func (n *node) grpcBoundPort() (int, error) {
	var status map[string]json.RawMessage
	if err := n.call("getserverstatus", nil, &status); err != nil {
		return 0, err
	}
	raw, ok := status["events_grpc"]
	if !ok {
		// Older field spellings would show up here as a hard failure rather than
		// a silent zero, which is what we want: the port is not optional.
		return 0, fmt.Errorf("getserverstatus has no events_grpc section: %v", keys(status))
	}
	var section struct {
		Bind string `json:"bind"`
	}
	if err := json.Unmarshal(raw, &section); err != nil {
		return 0, err
	}
	if section.Bind == "" {
		return 0, fmt.Errorf("events_grpc listener has not bound yet")
	}
	_, portStr, err := net.SplitHostPort(section.Bind)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(portStr)
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// call issues a JSON-RPC request against the node, decoding `result` into out.
func (n *node) call(method string, params []any, out any) error {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/", n.rpcPort), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization",
		"Basic "+base64.StdEncoding.EncodeToString([]byte(n.cookie)))
	client := &http.Client{Timeout: timeout(30)}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("%s: decoding the response: %w", method, err)
	}
	if envelope.Error != nil {
		return fmt.Errorf("%s: rpc error %d: %s", method, envelope.Error.Code, envelope.Error.Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, out)
}

// mustCall fails the test on any RPC error.
func (n *node) mustCall(method string, params []any, out any) {
	n.t.Helper()
	if err := n.call(method, params, out); err != nil {
		n.t.Fatalf("%v%s", err, n.stderrTail())
	}
}

// mine generates n blocks to w's address and returns their hashes.
func (n *node) mine(count int, w wallet) []string {
	n.t.Helper()
	var hashes []string
	n.mustCall("generatetoaddress", []any{count, w.address}, &hashes)
	return hashes
}

// blockCount is the active-chain height.
func (n *node) blockCount() uint32 {
	n.t.Helper()
	var h uint32
	n.mustCall("getblockcount", nil, &h)
	return h
}

// coinbaseTxid returns the (display-order) coinbase txid of the block at
// height.
func (n *node) coinbaseTxid(height int) string {
	n.t.Helper()
	var hash string
	n.mustCall("getblockhash", []any{height}, &hash)
	var block struct {
		Tx []string `json:"tx"`
	}
	n.mustCall("getblock", []any{hash}, &block)
	if len(block.Tx) == 0 {
		n.t.Fatalf("block %d has no transactions", height)
	}
	return block.Tx[0]
}

// spend builds, signs, and broadcasts a spend of fromTxid:vout to dest,
// returning the broadcast transaction's display-order txid.
//
// Everything goes through the node's own createrawtransaction /
// signrawtransactionwithkey RPCs, so this suite needs no Bitcoin library in Go -
// which is the point: the SDK does not force one on consumers, and its tests
// should not quietly depend on one either.
func (n *node) spend(fromTxid string, vout int, key wallet, dest wallet, amountBTC float64, sequence uint32) string {
	n.t.Helper()
	input := map[string]any{"txid": fromTxid, "vout": vout, "sequence": sequence}
	outputs := map[string]any{dest.address: amountBTC}

	var rawUnsigned string
	n.mustCall("createrawtransaction", []any{[]any{input}, outputs}, &rawUnsigned)

	var signed struct {
		Hex      string            `json:"hex"`
		Complete bool              `json:"complete"`
		Errors   []json.RawMessage `json:"errors"`
	}
	n.mustCall("signrawtransactionwithkey", []any{rawUnsigned, []string{key.wif}}, &signed)
	if !signed.Complete {
		n.t.Fatalf("signing did not complete: %v", signed.Errors)
	}

	var txid string
	n.mustCall("sendrawtransaction", []any{signed.Hex}, &txid)
	return txid
}

// grpcTarget is the address the SDK dials.
func (n *node) grpcTarget() string {
	return fmt.Sprintf("127.0.0.1:%d", n.grpcPort)
}

// dial opens an SDK client against this node, closed at test end.
func (n *node) dial(t *testing.T, opts ...satdevents.Option) *satdevents.Client {
	t.Helper()
	c, err := satdevents.Dial(context.Background(), n.grpcTarget(), opts...)
	if err != nil {
		t.Fatalf("dialing %s: %v", n.grpcTarget(), err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// restart stops and re-spawns satd on the same datadir, preserving the durable
// chain, and re-discovers the streaming port (which changes, as does the
// publisher's per-process instance id).
func (n *node) restart() {
	n.t.Helper()
	bin := satdBinary(n.t)
	n.kill()

	args := []string{
		"--regtest",
		"--datadir=" + n.datadir,
		fmt.Sprintf("--rpcport=%d", n.rpcPort),
		fmt.Sprintf("--port=%d", freePort(n.t)),
		"--events-grpc-bind=127.0.0.1:0",
		"--esplora=0",
		"--loglevel=error",
	}
	// Append rather than truncate: the pre-restart output is often what explains
	// a node that does not come back.
	stderrFile, err := os.OpenFile(n.stderr, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		n.t.Fatalf("reopening the stderr log: %v", err)
	}
	defer func() { _ = stderrFile.Close() }()

	cmd := exec.Command(bin, args...)
	cmd.Stderr = stderrFile
	if len(n.env) > 0 {
		cmd.Env = append(os.Environ(), n.env...)
	}
	if err := cmd.Start(); err != nil {
		n.t.Fatalf("restarting satd: %v", err)
	}
	n.cmd = cmd
	n.grpcPort = 0
	n.cookie = ""
	if err := n.waitReady(); err != nil {
		n.t.Fatalf("satd did not come back up: %v%s", err, n.stderrTail())
	}
}

func (n *node) kill() {
	if n.cmd == nil || n.cmd.Process == nil {
		return
	}
	_ = n.cmd.Process.Kill()
	_, _ = n.cmd.Process.Wait()
}

// stderrTail returns the last few lines of the node's stderr, so a failure
// carries satd's own error (a bind conflict, a panic) instead of an opaque
// timeout.
func (n *node) stderrTail() string {
	raw, err := os.ReadFile(n.stderr)
	if err != nil || len(raw) == 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
	return "\n--- satd stderr ---\n" + strings.Join(lines, "\n")
}

// ---- stream helpers ---------------------------------------------------------

// recvMatching drains the stream until pred accepts an event or the deadline
// passes, and fails the test if it passes.
//
// Recv is driven on a goroutine because a gRPC stream's Recv does not observe a
// deadline set after the call started; the goroutine parks on the socket and
// the context times out here. It reports through the channel rather than
// calling t.Fatal itself - t.Fatal from a non-test goroutine does not stop the
// test, which is exactly how a suite goes vacuously green.
func recvMatching(t *testing.T, s *satdevents.Stream, secs float64, pred func(satdevents.Event) bool) satdevents.Event {
	t.Helper()
	type result struct {
		ev  satdevents.Event
		err error
	}
	out := make(chan result, 1)
	go func() {
		for {
			ev, err := s.Recv()
			if err != nil {
				out <- result{err: err}
				return
			}
			if pred(ev) {
				out <- result{ev: ev}
				return
			}
		}
	}()
	select {
	case r := <-out:
		if r.err != nil {
			t.Fatalf("stream error while waiting for a matching event: %v", r.err)
		}
		return r.ev
	case <-time.After(timeout(secs)):
		t.Fatalf("no matching event within %s", timeout(secs))
		return nil
	}
}

// mineUntilSeen mines blocks until pred matches on the stream.
//
// Watch control messages have no per-message ack, so SetCategories (or
// AddScripts, or any other registration) returning means only that the frame was
// written - the node may not have applied it yet, and a block mined inside that
// window never reaches the stream. Retrying the trigger is the only way to close
// that window from the client side. One reader goroutine drives the whole wait,
// so a retry cannot race a previous attempt for the same event.
func mineUntilSeen(t *testing.T, n *node, s *satdevents.Stream, w wallet, secs float64,
	pred func(satdevents.Event) bool) satdevents.Event {
	t.Helper()
	type result struct {
		ev  satdevents.Event
		err error
	}
	out := make(chan result, 1)
	go func() {
		for {
			ev, err := s.Recv()
			if err != nil {
				out <- result{err: err}
				return
			}
			if pred(ev) {
				out <- result{ev: ev}
				return
			}
		}
	}()

	deadline := time.Now().Add(timeout(secs))
	for {
		n.mine(1, w)
		select {
		case r := <-out:
			if r.err != nil {
				t.Fatalf("stream error while waiting for a matching event: %v", r.err)
			}
			return r.ev
		case <-time.After(timeout(2)):
		}
		if time.Now().After(deadline) {
			t.Fatalf("no matching event within %s, despite mining throughout", timeout(secs))
			return nil
		}
	}
}

// collect drains up to n events (or until the deadline), returning what
// arrived. Unlike recvMatching it never fails the test on a short read - the
// caller asserts on the collection.
func collect(t *testing.T, s *satdevents.Stream, n int, secs float64) []satdevents.Event {
	t.Helper()
	out := make(chan satdevents.Event, n)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < n; i++ {
			ev, err := s.Recv()
			if err != nil {
				return
			}
			out <- ev
		}
	}()
	select {
	case <-done:
	case <-time.After(timeout(secs)):
	}
	close(out)
	var got []satdevents.Event
	for ev := range out {
		got = append(got, ev)
	}
	return got
}

// ctxWithTimeout is the standard scaled context for a streaming call.
func ctxWithTimeout(t *testing.T, secs float64) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), timeout(secs))
	t.Cleanup(cancel)
	return ctx
}
