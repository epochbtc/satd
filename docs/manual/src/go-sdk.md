# Go SDK (`satdevents`)

`satdevents` is the Go client for the [Streaming Consumption
API](streaming.md). It is a full-parity sibling of the [Rust
SDK](rust-sdk.md) — same surface, same guarantees, expressed in Go idiom rather
than transliterated from Rust.

It lives in the satd repository at `clients/go/`, as an independently versioned
Go module:

```sh
go get github.com/epochbtc/satd/clients/go
```

```go
import satdevents "github.com/epochbtc/satd/clients/go"
```

Only Go is needed — no Rust toolchain, no `protoc`. The protobuf bindings are
committed, and CI regenerates them on every PR and fails on a diff, so they
cannot drift from the `.proto`.

> **Note.** [Getting Started: Consuming Events](streaming-tutorial.md) walks the
> whole sequence — connect, firehose, durable watch, prefix privacy — one step
> at a time. It is written against the Rust SDK, but the sequence and the
> concepts are identical here; the mapping table below is the translation key.

## Module layout & dependencies

The published SDK's dependency graph is **gRPC and protobuf, and nothing else**.
That is a deliberate constraint, not an accident of being small: a client
library that drags a Bitcoin stack or a secp256k1 implementation into every
consumer forces version bumps on applications that already have their own. So:

- Script and txid parameters are `[]byte` and `[32]byte` with helpers, never
  library-specific types. Bring whatever Bitcoin library you already use, or
  none.
- Silent-payment scan-key validation is an in-tree on-curve check rather than a
  curve dependency.
- Code generators, linters, the E2E suite, and the examples each live in their
  own nested module, so what they need never reaches a consumer.

| Path | What |
|---|---|
| `clients/go/` | the `satdevents` package |
| `clients/go/eventspb/` | generated `satd.events.v1` bindings, exported for cases a typed helper does not cover |
| `clients/go/examples/` | thirteen runnable programs (own module) |
| `clients/go/e2e/` | live-node end-to-end tests, build tag `e2e` (own module) |
| `clients/go/tools/` | pinned generators and linters (own module) |

The `go` directive tracks one release behind the latest stable Go, covering
Go's two-release support window.

## Rust → Go mapping

Where the two languages' idioms diverge, the Go shape wins. Nothing is dropped;
this table is the translation key.

| Rust SDK | Go SDK | Why |
|---|---|---|
| `StreamClient::builder(..).bearer_token(..).connect()` | `Dial(ctx, target, WithBearerToken(..))` | functional options are Go's builder |
| `enum Event` | sealed `Event` interface + type switch | a sealed interface is Go's closed union; the marker method is unexported, so the implementation set is fixed |
| `Event::Unknown` | `*UnknownEvent` | same forward-compatibility contract |
| `#[non_exhaustive]` enums | `Known() bool` on each enum type | Go has no exhaustiveness check, so the "is this value from a newer node?" question is a method |
| `Option<T>` fields | pointer fields (`*uint64`) | absent stays distinguishable from zero |
| cancel-safe futures | `ctx` on every blocking call | see [cancel safety](#cancel-safety) |
| `AutoClose::{Never, AtDepth(n)}` | `AutoCloseNever`, `AutoCloseAtDepth(n)` | a `uint32` newtype, zero meaning never |
| `StreamError::is_retryable()` | `Retryable(err)`, `errors.Is(err, ErrX)` | Go error idiom, one sentinel per class |

## Connecting

```go
client, err := satdevents.Dial(ctx, "node:50051",
    satdevents.WithBearerToken(token), // sent as `authorization: Bearer …`
)
defer client.Close()
```

`Dial` accepts `host:port`, optionally with an `http://` or `https://` scheme
(stripped, for symmetry with the Rust client and the `-eventsgrpcbind`
documentation). It does not block on the connection coming up — gRPC connects
lazily, and the first `Subscribe` or `Watch` surfaces a connection failure.

Keepalive matching the server (30s/20s) is on by default; `WithoutKeepalive`
and `WithKeepalive` override it.

The bearer token is honored only when the server enforces auth
(`-eventsgrpcauth`). Over a plaintext connection it travels in cleartext —
enable TLS, restrict bearer auth to loopback, or front the node with a
TLS-terminating proxy.

## TLS / mTLS

```go
// Pin a satd node's own (self-signed) CA — the usual case.
client, err := satdevents.Dial(ctx, "node.example:50051",
    satdevents.WithTLSCAPem(caPEM),
    satdevents.WithBearerToken(token),
)

// Publicly trusted certificate: the system roots.
client, err := satdevents.Dial(ctx, "node.example:50051", satdevents.WithTLS())

// Mutual TLS, against a node with `eventsgrpcmtls=1`.
client, err := satdevents.Dial(ctx, "node.example:50051",
    satdevents.WithTLSCAPem(caPEM),
    satdevents.WithMTLS(certPEM, keyPEM),
)
```

`WithTLSServerName` overrides the verified name, for dialing by IP or through a
tunnel.

Requesting TLS against an explicit `http://` target is **refused, not silently
downgraded**. That combination can only be a mistake, and connecting in
cleartext would leak the token and the whole event stream while the caller
believed the link was encrypted.

## Firehose: `Subscribe`

```go
stream, err := client.Subscribe(ctx, satdevents.SubscribeOptions{
    Categories: satdevents.CategoryMempool | satdevents.CategoryChain,
})

for {
    ev, err := stream.Recv()
    if err != nil {
        if errors.Is(err, io.EOF) { break }
        return err
    }
    switch e := ev.(type) {
    case *satdevents.BlockConnected:
        log.Printf("block %d %s", e.Height, satdevents.DisplayHex(e.Hash))
    case *satdevents.MempoolEnter:
        log.Printf("tx %s fee=%d", satdevents.DisplayHex(e.Txid), e.Fee)
    }
}
```

`CategoryAll` (zero, the default) means every category **except**
`CategoryTweaks` and `CategoryStatus`, which are explicit-request only. That
exclusion is what keeps a client written against an older node from suddenly
receiving a body it has no parser for after the node is upgraded — so if you
want status or tweak events, ask for them by name.

`stream.Cursor()` returns the latest durable resume position. Persist it to
resume later.

## Durable firehose: `ResilientSubscribe`

```go
sub := client.ResilientSubscribe(ctx,
    satdevents.SubscribeOptions{Categories: satdevents.CategoryChain},
    satdevents.ResilientConfig{
        CursorStore: satdevents.NewFileCursorStore("/var/lib/app/satd.cursor"),
    })
defer sub.Close()

for {
    ev, err := sub.Next(ctx)   // reconnects and replays underneath
    if err != nil { return err }
    // ...
}
```

`Next` returns an error only on a permanent failure (bad endpoint or token,
`PERMISSION_DENIED`, a failed cursor write), when retries are exhausted, or when
`ctx` is done. An ordinary disconnect is not an error — it is handled.

The zero `ResilientConfig` is valid: default backoff (500 ms doubling to a 30 s
ceiling, retrying forever), auto-resume on lag, and **no persistence**. Set a
`CursorStore`; without one, a restart resumes forward-only and silently skips
everything that happened while the process was down.

`CursorStore` is an interface — `FileCursorStore` is provided, and a database
or key-value implementation is a two-method type.

## Watches: `Watch`

```go
handle, stream, err := client.Watch(ctx)
defer handle.Close()

err = handle.AddScripts(ctx, []satdevents.ScriptWatch{
    {Scripthash: satdevents.ScripthashOf(scriptPubKey)},
})
err = handle.AddOutpoints(ctx, []satdevents.OutpointRef{{Txid: txid, Vout: 0}})
err = handle.AddTxLifecycle(ctx, [][32]byte{txid}, satdevents.AutoCloseAtDepth(6))
err = handle.AddDepthAlarms(ctx, [][32]byte{txid}, []uint32{1, 3})
err = handle.AddDescriptor(ctx, descriptor, 20 /*gap*/, 0 /*start*/)
err = handle.AddSilentPayments(ctx, []satdevents.SilentPaymentTarget{target})
err = handle.AddScriptPrefixes(ctx, watcher.Prefixes(16))
```

The `WatchHandle` is safe for concurrent use — sends are serialized internally,
since a gRPC stream permits only one send at a time. Every `Add` has a matching
`Remove`, and `SendControl` is the escape hatch for anything the typed helpers
do not wrap yet.

The watch-set is **per-connection**. The server holds no principal-keyed state,
so when the stream drops, the watch-set and its quota leases go with it and a
fresh stream starts blank. That is why the durable variant below exists.

Some registrations are outcome-in-band rather than outcome-on-return:
`SetCursor` and `SetWatchSet` return nil once the request reaches the control
stream, and the actual outcome arrives on the event stream as exactly one
`CursorAccepted`/`CursorRejected` or `WatchSetReplaced`/`WatchSetRejected`.
Drive catch-up off those events, not off the return value.

## Durable watch: `ResilientWatch`

```go
watch := client.ResilientWatch(ctx, satdevents.ResilientWatchConfig{
    CursorStore: satdevents.NewFileCursorStore("/var/lib/app/watch.cursor"),
    WatchSetLoader: func(ctx context.Context, set *satdevents.WatchSet) error {
        rows, err := db.WatchedScripts(ctx)   // your durable truth
        if err != nil { return err }
        for _, r := range rows {
            set.AddScripts(satdevents.ScriptWatch{Scripthash: r.Scripthash})
        }
        return nil
    },
})
defer watch.Close()

for {
    ev, err := watch.Next(ctx)
    if err != nil { return err }
    // ...
}
```

Without a loader, `ResilientWatch` re-registers its in-memory mirror of the
`Add`/`Remove` calls made through it. That is correct for a watch-set built once
at startup — but the mirror is empty after a process restart, and goes stale if
the truth changes while the stream is down.

With a loader, the mirror becomes a **cache of your truth**:

- the loader runs after every successful (re)connect, *before* any event is
  pumped, so the first events after a reconnect already land on a fully
  populated subscription;
- the loaded set replaces the mirror, so the next reconnect re-derives from the
  loader rather than from accumulated in-process edits;
- a loader error is **transient** — backed off and retried on the next connect,
  not surfaced. A momentary outage of your database must not kill a consumer
  whose contract is at-least-once. A permanently broken loader is
  indistinguishable from a transient one and retries forever; set
  `Backoff.MaxRetries` if you need a terminal error instead.

`Reload(ctx)` realigns a live stream with the loader's truth on demand, and
returns a `ReloadSummary` (`Added`, `Removed`, `Unchanged`, `Applied`). Use it
after adding an address, so a later reconnect's loader agrees with what this
process registered.

## Cancel safety

`ResilientSubscription.Next` and `ResilientWatch.Next` take a `ctx`, and
cancelling it never consumes an event. (`Stream.Recv` on the non-resilient
surfaces takes no `ctx`; it is unblocked by cancelling the context passed to
`Subscribe`/`Watch`, and that surfaces as a gRPC `CANCELED` status rather than
`context.Canceled` — check `ctx.Err()`, not `errors.Is(err, context.Canceled)`.)

The reconnect state machine runs on its own goroutine and hands events over an
**unbuffered** channel, so it is never more than one event ahead of the caller.
Returning on `ctx.Done()` therefore cannot drop an event in flight: the handoff
only completes when the caller actually receives. Cancel `Next` freely — in a
`select` against a command channel, or under a per-call deadline — and call it
again.

This is the Go equivalent of the Rust SDK's explicit cancel-safe state machine.
The language does the work here, because a gRPC `Recv` cannot be abandoned
mid-flight without losing the message.

## Prefix watches (privacy-preserving)

Register a coarse `bits`-wide bucket of `sha256(scriptPubKey)`; the node learns
only the bucket and delivers everything in it, and the client filters locally.

```go
watcher := satdevents.NewPrefixWatcherWithScripts(script1, script2)
err = handle.AddScriptPrefixes(ctx, watcher.Prefixes(16))

// on each *satdevents.PrefixMatched:
hits, err := watcher.Filter(m)
for _, f := range hits.Funding { /* f.Vout, f.Value */ }
for _, s := range hits.Spending { /* s.Outpoint */ }
if hits.HasUnresolved() {
    // The server did not retain these prevout scripts. They are UNKNOWN, not
    // misses — resolve the outpoints yourself before concluding otherwise.
}
```

Distinct scripts sharing a bucket collapse into a single registration, which is
the point: the node cannot tell how many of your scripts a bucket covers. Bits
below the bucket width are masked before deduplicating, so a coarse bucket
really does collapse — at 1 bit, any number of scripts registers at most two
buckets. `MaxPrefixBits` (32) is where the server's mask saturates; a wider
registration cannot be more selective and is rejected client-side rather than
silently dropped by the server.

A server may lower the ceiling further via `streamprefixmaxbits`. That bound is
not advertised over the wire, so an over-precise (but ≤ 32) prefix can still be
dropped server-side with no client-side signal.

## Errors

Every SDK error is an `*Error` carrying a `Kind`, and each kind has a sentinel
that `errors.Is` matches:

```go
if errors.Is(err, satdevents.ErrPermissionDenied) { /* fix the token's caps */ }
if satdevents.Retryable(err) { /* back off and retry */ }

var serr *satdevents.Error
if errors.As(err, &serr) && serr.Status != nil {
    log.Print(serr.Status.Code(), serr.Status.Message())  // server detail survives
}
```

A `Lagged` notice is deliberately **not** an error: it is a normal, recoverable
event carrying a resume cursor. `ErrUnauthenticated` is reported non-retryable
on purpose — a blind retry with the same token will not help.

## Delivery guarantees

Cursors commit **on poll**: a delivered event's cursor is persisted only once
the caller comes back for the following event, which is an implicit ack. The
store therefore never advances past an event you have not received, so a crash
mid-processing replays that event. This is **at-least-once, not at-most-once**;
dedup on your side, keyed by what you process, if you need exactly-once.

The exception is `ReplayGap`. It means the persisted cursor fell outside the
server's replay window: the blocks it names were never delivered and never will
be. Full-resync that range from another source — logging it and moving on loses
transactions.

## Stability & versioning

The SDK tracks the additive `satd.events.v1` wire schema, not the node's release
cadence, and **a node and SDK do not need matching versions**. An event kind
this build predates decodes to `*UnknownEvent`; an unknown enum value is
preserved with `Known() == false`, so a `Status` from a newer node still routes
correctly on `Severity` and `Message`.

Releases are tagged `clients/go/vX.Y.Z`, independently of the node. Because
there is no `go.mod` at the repository root, the node's own `vX.Y.Z` tags do not
collide, and the module proxy serves consumers a zip of the module subtree only
— importing this SDK does not pull the Rust tree.

The module stays within v0/v1: Go's semantic import versioning makes `v2+` a
breaking import-path change (`.../go/v2`), so the bar for declaring v1 is "we
can live with this API".

## How parity is verified

The Go SDK is not a best-effort port kept in sync by hand. Every satd PR runs:

1. the Go unit tests, including a protobuf-reflection test that fails when a new
   event variant is added to the `.proto` without a Go decoder;
2. a build of all thirteen examples, so a renamed method cannot rot in a file
   whose whole job is to be copied;
3. the Go E2E suite against the same freshly built `satd` binary the Rust E2E
   suite uses;
4. a **differential parity harness** — one node, two clients, byte-identical
   watch spec. The Go SDK and the Rust `satd-events-client` each render every
   event they receive to canonical JSON, and the two dumps are diffed line by
   line. A field one SDK decodes differently, or a variant one of them cannot
   decode at all, fails the PR.

The harness normalizes exactly two things, and no more: it drops the publisher's
per-process `instance_id` (which differs per connection by definition), and it
sorts by cursor rather than arrival order (two connections are served by
independent tasks, so interleaving is server scheduling, not a parity property).
It therefore proves the two SDKs see the same events with the same field values
— not that they see them in the same order.

## Examples

Thirteen runnable programs live in
[`clients/go/examples/`](https://github.com/epochbtc/satd/tree/master/clients/go/examples),
one per usage shape:

```sh
cd clients/go/examples
go run ./firehose_tail   -endpoint 127.0.0.1:50051
go run ./resilient_tail  -endpoint 127.0.0.1:50051 -cursor /tmp/satd.cursor
go run ./health_watch    -endpoint 127.0.0.1:50051
go run ./tls_tail        -endpoint node.example:50051 -ca ./node-ca.pem
```

| Example | What it shows |
|---|---|
| `deposit_notify` | the smallest useful integration: tell me when this address is paid |
| `firehose_tail` | the minimum: connect, subscribe, print |
| `resilient_tail` | reconnect + file-backed cursor; the shape to copy |
| `watch_outpoints` | watch outpoints for their spend |
| `descriptor_wallet` | watch by descriptor, advance the gap limit |
| `lifecycle_alarms` | seen → confirmed → replaced, with depth alarms |
| `resilient_watch` | watch-set rebuilt from a durable truth on every reconnect |
| `health_watch` | node-health alerting, and why silence needs a deadline |
| `prefix_privacy` | coarse buckets registered, real filtering done locally |
| `sp_wallet` | BIP 352 scan-key watch (Tier 2) |
| `sp_light_scan` | BIP 352 client-side scan (Tier 1), scan key never leaves the device |
| `tls_tail` | TLS with a pinned self-signed node CA |
| `mtls_tail` | mutual TLS against `eventsgrpcmtls=1` |

`health_watch` is the alerting shape worth reading in full: it subscribes to
heartbeats *and enforces a deadline on them*, because a wedged publisher on a
live connection produces silence, and silence otherwise reads as "nothing is
wrong". It also documents what a status stream structurally cannot tell you —
status events are not replayable, so `getwarnings` over JSON-RPC remains the
authoritative answer to "what is wrong right now".
