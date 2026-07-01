# Streaming Consumption API

The Streaming Consumption API is satd's push-based surface for downstream
consumers — wallets, Lightning nodes, exchanges, watchtowers, explorers, and
other L2 projects. It pairs a real-time **event firehose** (blocks and mempool
transitions) with live, **cursor-resumable watch subscriptions** keyed on
outpoints, scripts, descriptors, and transaction ids.

It exists because the incumbent ways to consume a node each leave the same three
gaps — **descriptor lifecycle**, **outpoint-level subscriptions**, and
**cursor-based event replay** — that every serious consumer ends up reinventing.
satd serves all three natively, in-process, as consensus ground truth rather
than reconstructed from a ZMQ side-channel.

This chapter is the integrator guide. The authoritative, wire-level protocol
specification — the `satd.events.v1` protobuf, frame formats, and cursor
semantics — is
[`docs/api/streaming.md`](https://github.com/epochbtc/satd/blob/master/docs/api/streaming.md).

## The base primitive: outpoint subscription

The key generalization is that **outpoint subscription is the base primitive.**
Lightning channel-close detection, watchtower triggers, exchange deposit
confirmation, and theft monitoring all reduce to "tell me when this outpoint is
spent." Address-watching is outpoint-watching with a derivation rule layered on
top. The API builds down to outpoints and layers scripts, descriptors, and
transaction-id watches on as conveniences over the same matcher.

## Transports

One schema (the `satd.events.v1` protobuf definition is the source of truth),
three transports:

1. **gRPC native** (`satd.events.v1`, tonic) — the primary transport for
   programmatic consumers. A server-streaming `Subscribe` (firehose) and a
   bidirectional `Watch` (firehose + managed watch-set).
2. **JSON-over-WebSocket** (`GET /ws`) — a hand-mapped JSON rendering of the
   same tagged-unions, with a client→server control channel mirroring `Watch`.
3. **Server-Sent Events** (`GET /sse`) — a read-only JSON firehose (no control
   channel) for browser / `curl` consumers.

A Core-compatible **ZMQ PUB** sink remains for legacy parity; it carries the
firehose bodies only (not per-subscriber watch matches) and uses Core's
per-topic sequence numbers.

WebSocket and SSE bind a **dedicated `--streamws` port** rather than upgrading on
the Core-compat JSON-RPC port — keeping the differentiated stream a distinct
service on a distinct port. Every streaming listener (`--streamws` and the gRPC
`NodeEventStream`) **runs on the isolated API tokio runtime** (`--api-threads`),
never the core block-connecting runtime: a flood of streaming clients can never
contend with the threads that connect blocks and accept mempool transactions. See
[API Scaling & Runtimes](api-scaling.md) for the runtime split, the admission
caps, and how to scale beyond one node.

## Subscriptions and watch-sets

The gRPC service offers the server-streaming `Subscribe` (the firehose, with
cursor replay) plus a **bidirectional** `Watch` whose client→server messages are
a tagged union — `SetCursor`, `SetCategories`, `Add`/`Remove` for scripts,
outpoints, transactions, script-prefixes, and descriptors, and `SetWatchSet` (an
atomic whole-set replace: send the complete desired watch-set in one message and
the server reconciles it under its lock by effective coverage, replying with a
deterministic `WatchSetResult`). New subscription kinds slot in additively
without protocol breakage.

Match events delivered on the per-subscriber `Watch` channel include:

- `OutpointSpent` — an outpoint was spent (in mempool or a connected block).
- `ScriptMatched` — a script was funded or spent (both sides). For a
  descriptor-derived script it carries `descriptor_matches`: which descriptor +
  the exact `(branch, derivation_index)` it was derived at (empty for a
  directly-watched script), so a multi-descriptor consumer can route a hit
  without its own reverse index.
- `TxidMatched` / `TxidReplaced` / `TxidEvicted` / `TxidUnconfirmed` /
  `TxidDepthReached` / `TxidFinalized` — transaction lifecycle and
  confirmation-depth alarms.
- `PrefixMatched` — a privacy-preserving script-prefix match.

The matcher is **decoupled from the consensus path**: a dedicated task subscribes
to the existing chain/mempool broadcasts and *re-reads* blocks and accepted
transactions the node already holds, then scans the watch-set and delivers
matches. A node with no subscribers pays nothing (gated behind a lock-free
`has_watchers()` check), and a slow client's matches are dropped-with-notice,
never stalling the matcher or blocking consensus.

### Descriptor convenience layer

`AddDescriptor` takes a rust-miniscript-parseable, **public-key-only** descriptor
plus a `gap_limit` window; the server expands it over `[start, start +
gap_limit)`, derives the watch scripts, and registers them with the matcher.
A BIP-389 multipath descriptor (`.../<0;1>/*`, the canonical export form of
Core/Sparrow/BDK wallets) is split into its branches and each branch is expanded
over the same window, so it yields up to `branches × gap_limit` scripts (and
costs that many watch units); the branch count is capped at 2 — more is rejected.
Expansion is bounded per branch (`MAX_DESCRIPTOR_WINDOW = 1000`, so at most 2000
scripts for a 2-branch descriptor) and rejects any secret-bearing descriptor at
the type level, so no signing material can ever be submitted — the node stays
keyless. The server retains the descriptor → scripthashes membership for the
connection, so a window can be slid or dropped cleanly: re-sending `AddDescriptor`
with an advanced `start` reconciles the slid window server-side (scripts leaving
the window are released, scripts entering are added), and `RemoveDescriptor` drops
the whole window. A scripthash shared with a direct add or another descriptor is
held until its **last** owner goes. A connection may retain up to 256 distinct
descriptors (`MAX_DESCRIPTORS_PER_CONNECTION`); at the cap, drop one with
`RemoveDescriptor` before adding a new one (re-asserting an existing descriptor
to slide its window is always allowed). Gap-limit advancement stays a client concern
by design: the server manages the window it is told to, but never tracks
derivation progress or nudges the client to extend — the client decides when to
advance `start` (or `RemoveDescriptor`).

## Cursors & replay

Reconnect-with-cursor is the single highest-value primitive — the *one* replay
mechanism for every subscription type, subsuming Electrum's subscribe-then-
get-history dance and Esplora's per-address pagination.

- **Confirmed-side replay** is exact: the cursor is `(height, tx_index)` and
  replay runs straight from the block index, no extra log.
- **Mempool-side replay** is best-effort within a bounded in-memory window
  (the mempool isn't durable); only the high-water `seq` is persisted.
- Process restart is detected through `Cursor.instance_id`; the per-publisher
  `seq` resets on restart and is the mempool-side watermark only, never a durable
  confirmed-side cursor.

Reorgs are not a separate event type: they are carried on `ChainEvent` as a
first-class `Reorg` marker followed by the per-block disconnect/connect sequence.

## Authentication & quotas

The streaming API adds **no new auth surface** — it reuses the unified auth layer
wholesale (full details in [Authentication & Authorization](authentication.md)).
With no token store configured the transports are open (loopback-trust, matching
the existing events-gRPC behavior); a **remote bind requires a token store**
(`-streamwsauth`/`-eventsgrpcauth` → `-authfile`).

| Action | Capability | Quota |
|---|---|---|
| Open a stream; receive the firehose | `stream:subscribe` | — |
| `AddScripts` / `AddOutpoints` / `AddTransactions` / `AddDescriptor` | `stream:watch` | per-token watch quota + per-add rate limit |
| `Remove*` | — | releases each item's unit immediately |

The quota unit is **one watched item** (N items = N units); each item holds an
RAII `WatchLease` so `Remove*` returns its unit immediately, making long-lived
clients that rotate a sliding watch-set viable without exhausting quota.
Over-quota adds are rejected cleanly (`RESOURCE_EXHAUSTED` on gRPC / `429` on WS)
without tearing down the subscription.

## Transport encryption (events gRPC TLS / mTLS)

Bearer auth protects *who* may subscribe, but over a plaintext `http://` bind the
token — and the event stream — travel in the clear. The events gRPC listener can
terminate **TLS in-process**, sharing the same certificate / mTLS plumbing as the
RPC, Electrum, and Esplora surfaces. Set a cert + key and the existing
`eventsgrpcbind` listener is upgraded to TLS (there is no separate plaintext + TLS
bind):

```ini
eventsgrpcbind = 0.0.0.0:50051
eventsgrpctlscert = /etc/satd/events-cert.pem
eventsgrpctlskey  = /etc/satd/events-key.pem
```

For **mutual TLS** — clients must present a certificate signed by a CA you control
— add the CA bundle and, optionally, an allowlist of accepted certificate
subjects (CN / DNS-SAN; empty means "any cert the CA signed"):

```ini
eventsgrpcmtls          = 1
eventsgrpcmtlsclientca  = /etc/satd/clients-ca.pem
eventsgrpcmtlsclientallow = alice,bob       # optional
```

A **remote bind must be authenticated**: `eventsgrpcallowremote` requires either
bearer auth (`eventsgrpcauth`) *or* mTLS (`eventsgrpcmtls`) — mTLS satisfies the
requirement on its own, since every client must present a CA-signed certificate.
The cert/key/CA are validated at startup, so a misconfiguration fails the daemon
immediately rather than per-connection. The handshake timeout
(`eventsgrpctlshandshaketimeout`, default 30s) bounds slow or probing clients.
Certificates hot-reload from the same paths on `SIGUSR1`, like the other TLS
surfaces. TLS uses the workspace `ring` provider exclusively. If you instead
front the node with a TLS-terminating reverse proxy, keep the loopback bind and
leave these unset.

## Operator limits

Every remote-facing streaming surface is bounded so it cannot be driven to
fd / memory / task exhaustion. All are restart-classified config; `0` means
unlimited.

| Key | Default | Bounds |
|---|---|---|
| `streamwsmaxconns` | 256 | concurrent `/ws` + `/sse` connections |
| `streamwsmaxsubscriptions` | 256 | watch-set size per WS connection |
| `streamwsmaxmessagebytes` | 262144 | a single inbound WS control frame |
| `eventsgrpcmaxconns` | 64 | concurrent gRPC streams |
| `eventsgrpcmaxsubscriptions` | 256 | watch-set size per gRPC stream |
| `streammaxresyncblocks` | 10000 | blocks the matcher will rescan after a lag, bounding catch-up |

Admission shedding runs ahead of authentication and request-body buffering, so a
connection flood — authenticated or not — is bounded before it does work.

## Consensus-safety invariants

These are structural guarantees, not policies:

- The event bus is **publish-only** out of `connect_block` / `accept_tx`; the
  matcher only *reads* data the node already holds and adds no code to, and takes
  no lock on, the consensus path.
- A slow client **never backpressures** the publisher — degradation is
  drop-with-notice (`broadcast` send is non-blocking and lossy; per-subscriber
  delivery is non-blocking `try_send`).
- Streaming listeners run on the **API runtime only**, never the core
  block-connecting runtime.
