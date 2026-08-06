# satd Go SDK (`satdevents`)

Go client for the satd **Streaming Consumption API** (`satd.events.v1`): a live
gRPC feed of mempool, chain, and watch-match events from a satd node, with
durable cursors so a consumer resumes exactly where it left off.

```
go get github.com/epochbtc/satd/clients/go
```

```go
import satdevents "github.com/epochbtc/satd/clients/go"
```

Requires only Go — no Rust toolchain, no `protoc`; the protobuf bindings are
committed.

## Byte order — read this first

Every txid and block hash on this API is in **internal (consensus) byte
order**, not the reversed order block explorers and `getrawtransaction` show.
Convert only when displaying or comparing against JSON-RPC:

```go
fmt.Println(satdevents.DisplayHex(ev.Txid)) // explorer / JSON-RPC order
```

Do **not** apply it to a public key or tweak — those are raw bytes and are not
reversed.

## Status

Under construction; see `SATD_GO_SDK_PLAN.md` in the monorepo for the parity
inventory this is being built against. The wire contract itself is documented in
[`docs/api/streaming.md`](../../docs/api/streaming.md).

## Layout

| Path | What |
|---|---|
| `.` | the `satdevents` package — the public SDK |
| `eventspb/` | generated `satd.events.v1` bindings (committed; regenerate with `./gen.sh`) |
| `tools/` | pinned code generators and linters, in their own module so they stay out of the SDK's dependency graph |
| `examples/` | runnable programs, one per usage shape |
| `e2e/` | end-to-end tests against a live regtest node (build tag `e2e`) |

## Regenerating the bindings

```sh
./gen.sh
```

CI re-runs it and fails on a diff, so the committed bindings cannot drift from
`satd-events-proto/proto/satd/events/v1/events.proto`.
