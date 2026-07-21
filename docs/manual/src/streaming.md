# Streaming Consumption API

The Streaming Consumption API is satd's push-based surface for downstream
consumers: wallets, Lightning nodes, exchanges, watchtowers, explorers, and
other L2 projects. It pairs a real-time **event firehose** of blocks and mempool
transitions with live, **cursor-resumable watch subscriptions** keyed on
outpoints, scripts, descriptors, and transaction ids.

The incumbent ways to consume a node all leave the same gaps: descriptor
lifecycle, outpoint-level subscriptions, and cursor-based event replay.
Consumers end up rebuilding each of these themselves. satd serves all three
natively and in-process, as consensus ground truth, with no reconstruction from
a ZMQ side channel.

This chapter is the integrator guide. The authoritative wire-level protocol
specification (the `satd.events.v1` protobuf, frame formats, and cursor
semantics) is
[`docs/api/streaming.md`](https://github.com/epochbtc/satd/blob/master/docs/api/streaming.md).
For a step-by-step onramp before this reference, start with
[Getting Started: Consuming Events](streaming-tutorial.md).

## The base primitive: outpoint subscription

Outpoint subscription is the base primitive. Lightning channel-close detection,
watchtower triggers, exchange deposit confirmation, and theft monitoring all
reduce to one request: report when this outpoint is spent. Address watching is
outpoint watching with a derivation rule on top. The API builds down to
outpoints, and layers script, descriptor, and transaction-id watches over the
same matcher.

## Transports

One schema serves three transports. The `satd.events.v1` protobuf definition is
the source of truth.

1. **gRPC** (`satd.events.v1`, tonic). The primary transport for programmatic
   consumers. It offers a server-streaming `Subscribe` (the firehose) and a
   bidirectional `Watch` (the firehose plus a managed watch-set).
2. **JSON over WebSocket** (`GET /ws`). A hand-mapped JSON rendering of the
   same tagged unions, with a client-to-server control channel that mirrors
   `Watch`.
3. **Server-Sent Events** (`GET /sse`). A read-only JSON firehose with no
   control channel, for browser and `curl` consumers.

A Core-compatible ZMQ PUB sink remains for legacy parity. It carries the
firehose bodies only, not per-subscriber watch matches, and uses Core's
per-topic sequence numbers.

WebSocket and SSE bind a dedicated `--streamws` port; they do not upgrade on
the Core-compatible JSON-RPC port. The stream stays a distinct service on a
distinct port. Every streaming listener (`--streamws` and the gRPC
`NodeEventStream`) runs on the isolated API tokio runtime (`--api-threads`),
never on the core block-connecting runtime. A flood of streaming clients
therefore cannot contend with the threads that connect blocks and accept
mempool transactions. See [API Scaling & Runtimes](api-scaling.md) for the
runtime split, the admission caps, and how to scale beyond one node.

## Subscriptions and watch-sets

The gRPC service offers the server-streaming `Subscribe` (the firehose, with
cursor replay) and a bidirectional `Watch`. The client-to-server `Watch`
messages are a tagged union: `SetCursor`, `SetCategories`, `Add`/`Remove` for
scripts, outpoints, transactions, script prefixes, and descriptors, and
`SetWatchSet`. `SetWatchSet` is an atomic whole-set replace: the client sends
the complete desired watch-set in one message, and the server reconciles it
under its lock by effective coverage, replying with a deterministic
`WatchSetResult`. New subscription kinds can be added without protocol
breakage.

Match events delivered on the per-subscriber `Watch` channel include:

- `OutpointSpent`. An outpoint was spent, in the mempool or in a connected
  block.
- `ScriptMatched`. A script was funded or spent (both sides). For a
  descriptor-derived script it carries `descriptor_matches`: which descriptor
  matched, and the exact `(branch, derivation_index)` the script was derived
  at. The field is empty for a directly watched script. A multi-descriptor
  consumer can route a hit without keeping its own reverse index. The event
  also carries the matched value (`amount`/`has_amount`, at parity with
  `SpentPrevout`), so an exact-script consumer can skip the per-match
  `getrawtransaction` enrichment call. With `SetWatchOptions{include_raw_tx}`
  set (per connection, off by default) it also carries the full
  consensus-serialized matching transaction in `raw_tx`.
- `TxidMatched` / `TxidReplaced` / `TxidEvicted` / `TxidUnconfirmed` /
  `TxidDepthReached` / `TxidFinalized`. Transaction lifecycle and
  confirmation-depth alarms.
- `PrefixMatched`. A privacy-preserving script-prefix match.
- `SilentPaymentMatched`. A BIP 352 silent payment paid one of your registered
  scan keys. See the scan-key watch below.

The matcher is decoupled from the consensus path. A dedicated task subscribes
to the existing chain and mempool broadcasts, re-reads blocks and accepted
transactions the node already holds, scans the watch-set, and delivers matches.
A node with no subscribers pays nothing; a lock-free `has_watchers()` gate
skips the work. A slow client's matches are dropped with notice. The matcher
never stalls and never blocks consensus.

### Descriptor convenience layer

`AddDescriptor` takes a public-key-only descriptor that rust-miniscript can
parse, plus a `gap_limit` window. The server expands the descriptor over
`[start, start + gap_limit)`, derives the watch scripts, and registers them
with the matcher.

A BIP-389 multipath descriptor (`.../<0;1>/*`, the canonical export form of
Core, Sparrow, and BDK wallets) is split into its branches, and each branch is
expanded over the same window. The descriptor therefore yields up to
`branches × gap_limit` scripts and costs that many watch units. The branch
count is capped at 2; more branches are rejected.

Expansion is bounded per branch: `MAX_DESCRIPTOR_WINDOW = 1000`, so a 2-branch
descriptor yields at most 2000 scripts. Any secret-bearing descriptor is
rejected at the type level. No signing material can be submitted, and the node
stays keyless.

The server retains the descriptor-to-scripthash membership for the connection,
so a window can be slid or dropped cleanly. Re-sending `AddDescriptor` with an
advanced `start` reconciles the slid window server-side: scripts that leave the
window are released, and scripts that enter it are added. `RemoveDescriptor`
drops the whole window. A scripthash shared with a direct add or with another
descriptor is held until its last owner is removed.

A connection may retain up to 256 distinct descriptors
(`MAX_DESCRIPTORS_PER_CONNECTION`). At the cap, drop a descriptor with
`RemoveDescriptor` before adding a new one. Re-asserting an existing descriptor
to slide its window is always allowed.

Gap-limit advancement stays a client concern. The server manages the window it
is told to manage; it does not track derivation progress and does not prompt
the client to extend. The client decides when to advance `start` or send
`RemoveDescriptor`.

### Silent-payment scan-key watch (BIP 352, Tier 2)

For clients that would rather not run a per-block scan themselves, `Watch` accepts
BIP 352 **scan-key targets**. `AddSilentPayments` (or an atomic
`SetWatchSet.silent_payments` replace) registers up to 16 targets per connection
(`MAX_SP_TARGETS_PER_CONNECTION`); each is a `(scan_secret b_scan, spend_pubkey
B_spend)` pair plus optional label integers. The node then matches every
silent-payment output that pays a registered target and emits a
`SilentPaymentMatched` carrying the output key and value, the transaction's public
tweak `T`, and the output counter `k` — enough for the wallet to re-derive the
full output key, and therefore its spending key, **offline** from its own
`b_scan`. Targets are removed by their identity `b_scan·G` (`RemoveSilentPayments`),
which the client derives locally; each costs one watch-quota unit. Matching
recomputes from the block and its undo data with the same kernel the index uses,
so it needs **no** `silentpaymentindex` and does zero extra work on a block when
no target is registered.

A fresh wallet cold-syncs its history by registering its scan key and then
issuing a bounded `RescanBlocks` over the taproot-activation-to-tip window. That
rescan produces exactly the confirmed matches the live path would; when
`silentpaymentindex` is enabled and fully synced it also runs faster, reading
each block's tweaks from the index instead of recomputing them (verified per
block against the stored row's block hash, falling back to recompute on any
mismatch). The index only changes rescan speed, never which payments are found.

A match fires in two phases, like the `ScriptMatched` watch. When a paying
transaction is accepted into the mempool the node emits the match with
`confirmed = false`; when it later lands in a block it re-emits the same match
with `confirmed = true` and a resume cursor. The unconfirmed phase is
best-effort: a scan key registered *after* a transaction was already admitted
matches it only once it confirms, and a replaced or evicted transaction never
reaches the confirmed re-emit. Mempool matching needs each spent prevout's script
to classify inputs, which the default event path does not retain — so while any
scan key is registered the node keeps those scripts on each mempool entry (paid
for by that watch), and drops back to retaining nothing the moment the last scan
key goes away.

> **Operator-trust trade.** A scan key lets the node run the ECDH match, so the
> operator — and anyone who compromises the node — learns *which* outputs are
> yours. It is **not** a spending key: `B_spend`'s private half never leaves the
> client, so no party but you can ever spend them. The node treats the secret
> accordingly: scan secrets live in memory for the connection's lifetime only,
> are wrapped in a zeroize-on-drop buffer, and are never written to disk, a
> cursor, a status RPC, or a log line. A routable events bind still requires auth
> or mTLS, the same as every other watch kind. The zero-custody alternative is
> Tier 1 client-side scanning (see the streaming API reference), where the scan
> key never leaves the device.

## Cursors & replay

Reconnect-with-cursor is the one replay mechanism for every subscription type.
It subsumes Electrum's subscribe-then-get-history sequence and Esplora's
per-address pagination.

- Confirmed-side replay is exact. The cursor is `(height, tx_index)`, and
  replay reads straight from the block index with no extra log.
- Mempool-side replay is best-effort within a bounded in-memory window, because
  the mempool is not durable. Only the high-water `seq` is persisted.
- A process restart is detected through `Cursor.instance_id`. The per-publisher
  `seq` resets on restart; it is the mempool-side watermark only, never a
  durable confirmed-side cursor.

Reorgs are not a separate event type. `ChainEvent` carries a `Reorg` marker,
followed by the per-block disconnect and connect sequence.

## Authentication & quotas

The streaming API adds no new authentication surface. It reuses the unified
auth layer; see [Authentication & Authorization](authentication.md) for the
details. With no token store configured, the transports are open under
loopback trust, matching the existing events-gRPC behavior. A remote bind
requires a token store (`-streamwsauth` / `-eventsgrpcauth`, backed by
`-authfile`).

| Action | Capability | Quota |
|---|---|---|
| Open a stream; receive the firehose | `stream:subscribe` | none |
| `AddScripts` / `AddOutpoints` / `AddTransactions` / `AddDescriptor` | `stream:watch` | per-token watch quota plus per-add rate limit |
| `Remove*` | none | releases each item's unit immediately |

The quota unit is one watched item; N items cost N units. Each item holds an
RAII `WatchLease`, so `Remove*` returns its unit immediately, and a long-lived
client can rotate a sliding watch-set without exhausting quota. Over-quota adds
are rejected (`RESOURCE_EXHAUSTED` on gRPC, `429` on WebSocket) without tearing
down the subscription.

## Transport encryption (events gRPC TLS / mTLS)

Bearer auth controls who may subscribe. Over a plaintext `http://` bind, the
token and the event stream still travel in the clear. The events gRPC listener
can terminate TLS in-process, sharing the same certificate and mTLS plumbing as
the RPC, Electrum, and Esplora surfaces.

Set a certificate and key to upgrade the existing `eventsgrpcbind` listener to
TLS. There is no separate plaintext-plus-TLS bind:

```ini
eventsgrpcbind = 0.0.0.0:50051
eventsgrpctlscert = /etc/satd/events-cert.pem
eventsgrpctlskey  = /etc/satd/events-key.pem
```

With mutual TLS, every client must present a certificate signed by a CA you
control. Add the CA bundle and, optionally, an allowlist of accepted
certificate subjects (CN or DNS-SAN). An empty allowlist accepts any
certificate the CA signed:

```ini
eventsgrpcmtls          = 1
eventsgrpcmtlsclientca  = /etc/satd/clients-ca.pem
eventsgrpcmtlsclientallow = alice,bob       # optional
```

A remote bind must be authenticated: `eventsgrpcallowremote` requires either
bearer auth (`eventsgrpcauth`) or mTLS (`eventsgrpcmtls`). mTLS satisfies the
requirement on its own, since every client must present a CA-signed
certificate. satd checks the certificate, key, and CA at startup, so a
misconfiguration fails startup immediately instead of failing per-connection.
The handshake timeout (`eventsgrpctlshandshaketimeout`, default 30s) bounds
slow or probing clients. Certificates hot-reload from the same paths on
`SIGUSR1`, like the other TLS surfaces. TLS uses the workspace `ring` provider
exclusively.

If a TLS-terminating reverse proxy fronts the node, keep the loopback bind and
leave these options unset.

## Operator limits

Every remote-facing streaming surface is bounded, so it cannot be driven to
file-descriptor, memory, or task exhaustion. All of these options are
restart-classified; `0` means unlimited.

| Key | Default | Bounds |
|---|---|---|
| `streamwsmaxconns` | 256 | concurrent `/ws` + `/sse` connections |
| `streamwsmaxsubscriptions` | 256 | watch-set size per WS connection |
| `streamwsmaxmessagebytes` | 262144 | a single inbound WS control frame |
| `eventsgrpcmaxconns` | 64 | concurrent gRPC streams |
| `eventsgrpcmaxsubscriptions` | 256 | watch-set size per gRPC stream |
| `streammaxresyncblocks` | 10000 | blocks the matcher will rescan after a lag, bounding catch-up |

Admission shedding runs before authentication and request-body buffering. A
connection flood, authenticated or not, is bounded before it does any work.

## Consensus-safety invariants

These guarantees are structural, not policy:

- The event bus is publish-only out of `connect_block` and `accept_tx`. The
  matcher only reads data the node already holds. It adds no code to the
  consensus path and takes no lock on it.
- A slow client never backpressures the publisher. Degradation is
  drop-with-notice: the `broadcast` send is non-blocking and lossy, and
  per-subscriber delivery uses a non-blocking `try_send`.
- Streaming listeners run on the API runtime only, never on the core
  block-connecting runtime.
