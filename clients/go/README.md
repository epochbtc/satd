# satd Go SDK (`satdevents`)

Go client for the satd **Streaming Consumption API** (`satd.events.v1`): a live
gRPC feed of mempool, chain, and watch-match events from a satd node, with
durable cursors so a consumer resumes exactly where it left off.

```sh
go get github.com/epochbtc/satd/clients/go
```

```go
import satdevents "github.com/epochbtc/satd/clients/go"
```

Requires only Go — no Rust toolchain, no `protoc`; the protobuf bindings are
committed. The only dependencies are gRPC and protobuf.

## Quickstart: tell me when a deposit arrives

The common case. Watch an address, get told the moment a payment shows up in
the mempool and again when it confirms.

```go
ctx := context.Background()

client, err := satdevents.Dial(ctx, "127.0.0.1:50051")
if err != nil {
	log.Fatal(err)
}
defer func() { _ = client.Close() }()

handle, stream, err := client.Watch(ctx)
if err != nil {
	log.Fatal(err)
}
defer func() { _ = handle.Close() }()

// The server keys watches on sha256(scriptPubKey), so hand it the script bytes
// from whatever Bitcoin library or RPC field you already have — the SDK does
// not make you adopt one.
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
		fmt.Printf("paid: tx %s output %d, %s\n",
			satdevents.DisplayHex(m.Txid), m.Index, state)
	}
}
```

That is the whole integration. This snippet is the body of
[`examples/deposit_notify`](examples/deposit_notify), which CI compiles — the
most-copied code in this repository is the code that must not rot:

```sh
go run ./deposit_notify -endpoint 127.0.0.1:50051 -script 0014…
```

Two things it is missing before production, both a few lines away: it does not
reconnect, and it does not persist a resume cursor — so a restart silently skips
whatever arrived while it was down. Use `ResilientWatch` (see
[`examples/resilient_watch`](examples/resilient_watch)) for anything long-lived.

## Byte order — read this first

Every txid and block hash on this API is in **internal (consensus) byte order**,
not the reversed order block explorers and `getrawtransaction` show. This is the
single most common integration bug against this API: a txid compared against
JSON-RPC output silently never matches.

```go
satdevents.DisplayHex(ev.Txid)          // explorer / JSON-RPC order
satdevents.TxidFromDisplayHex(s)        // the inverse, for feeding a txid in
satdevents.DisplayHexUnreversed(pubkey) // pubkeys, tweaks, scripts — NOT reversed
```

Do **not** apply `DisplayHex` to a public key, tweak, or scriptPubKey. Those are
raw bytes; reversing them produces a plausible-looking string that is wrong.

Nor to a **scripthash**, even though it is 32 bytes and looks like a txid.
Electrum reverses scripthashes; this API does not, and neither does
`ScripthashOf`. Mixing the two gives a key that silently matches nothing.

## Choosing a surface

| You want | Use | Reconnects |
|---|---|---|
| Everything happening on the node | `Subscribe` | no |
| …and to survive restarts and blips | `ResilientSubscribe` | yes |
| Only events touching your scripts / txids / outpoints | `Watch` | no |
| …and to survive restarts and blips | `ResilientWatch` | yes |

The watch-set is **per-connection**: the server holds no principal-keyed state,
so a dropped stream takes the whole watch-set with it. `ResilientWatch` exists
for exactly that — it mirrors every registration and replays it on reconnect,
and with a `WatchSetLoader` it rebuilds the set from your own durable store
instead of from in-process history (which is empty after a restart).

## Delivery guarantees

Cursors are committed **on poll**: a delivered event's cursor is persisted only
once you come back for the next one. A crash mid-processing therefore replays
that event — **at-least-once, not at-most-once**. Dedup on your side if you need
exactly-once.

The one exception is `ReplayGap`. It means the persisted cursor fell outside the
server's replay window, so the named block range was never delivered and never
will be. Handle it; logging it and moving on loses transactions.

## Examples

Each is a runnable program in [`examples/`](examples/) — `go run ./firehose_tail
-endpoint 127.0.0.1:50051`, and so on.

| Example | What it shows |
|---|---|
| `deposit_notify` | the quickstart above, compiled |
| `firehose_tail` | the minimum: connect, subscribe, print |
| `resilient_tail` | reconnect + a file-backed cursor; the shape to copy |
| `watch_outpoints` | watch outpoints for their spend |
| `descriptor_wallet` | watch a wallet by descriptor, advance the gap limit |
| `lifecycle_alarms` | track a tx seen → confirmed → replaced, with depth alarms |
| `resilient_watch` | a watch-set rebuilt from your durable truth on every reconnect |
| `health_watch` | node-health alerting, including why silence must be a deadline |
| `prefix_privacy` | register a coarse bucket, filter locally; the node never sees your scripts |
| `sp_wallet` | BIP 352 scan-key watch (Tier 2) — node matches, you derive the spend key |
| `sp_light_scan` | BIP 352 client-side scan (Tier 1) — the scan key never leaves the device |
| `tls_tail` | TLS, pinning a self-signed node CA |
| `mtls_tail` | mutual TLS against `eventsgrpcmtls=1` |

The examples are their own Go module, so nothing they need — including the
secp256k1 library the two silent-payment examples use — reaches the dependency
graph of an application that imports the SDK.

## Compatibility

The SDK tracks the additive `satd.events.v1` wire schema, not the node's release
cadence: **a node and SDK do not need matching versions.** New event kinds and
optional fields are added without breaking existing consumers — an event this
build predates decodes to `UnknownEvent` rather than an error, and unknown enum
values are preserved with `Known() == false` so `Severity` and `Message` stay
usable.

Releases are tagged `clients/go/vX.Y.Z`, independently of the node's `vX.Y.Z`.
The module stays within v0/v1: Go's semantic import versioning makes `v2+` a
breaking import-path change, so the bar for v1 is "we can live with this API".

## Layout

| Path | What |
|---|---|
| `.` | the `satdevents` package — the public SDK |
| `eventspb/` | generated `satd.events.v1` bindings (committed; regenerate with `./gen.sh`) |
| `examples/` | runnable programs, one per usage shape (own module) |
| `e2e/` | end-to-end tests against a live regtest node, build tag `e2e` (own module) |
| `cmd/paritydump/` | the Go half of the differential parity harness — see below |
| `tools/` | pinned code generators and linters (own module) |

## Development

```sh
./lint.sh          # gofmt, vet, staticcheck, errcheck — SDK, examples, and e2e
./gen.sh           # regenerate eventspb/ from the proto
go test ./...      # unit tests
```

Every satd PR runs the SDK's unit tests, builds the examples, and runs the Go
E2E suite against the same freshly built `satd` binary the Rust E2E suite uses.
On top of that, a **differential parity harness** (`cmd/paritydump` plus
`satd/tests/e2e/parity.rs`) drives this SDK and the Rust `satd-events-client`
through an identical watch spec against one node and diffs their rendered
events. That is what keeps "parity with the Rust SDK" from being a claim nobody
checks — the two must agree event for event, field for field.

CI re-runs `gen.sh` and fails on a diff, so the committed bindings cannot drift
from `satd-events-proto/proto/satd/events/v1/events.proto`.

## See also

- **Wire protocol:** [`docs/api/streaming.md`](../../docs/api/streaming.md)
- **Operator Manual:** <https://epochbtc.github.io/satd/>
- **Rust SDK:** [`satd-events-client`](../../satd-events-client)
