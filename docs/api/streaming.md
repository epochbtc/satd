# satd Streaming Consumption API — Protocol Spec (DRAFT / WIP)

> **Status: DRAFT — pre-implementation, pre-consumer-feedback.**
> This document captures the *current design intent* for the Streaming
> Consumption API described in [`ROADMAP.md` → "Streaming Consumption
> API"](../../ROADMAP.md). It is deliberately a work-in-progress: the wire
> shapes below are a starting point to be iterated against a real anchor
> consumer (per ROADMAP: *"prove the shape with one anchor consumer before
> spec-and-evangelize"*). Nothing here is a stability commitment yet. Field
> numbers, message names, and error codes WILL change before any `v1` freeze.
>
> The eventual goal is an **open, transport-agnostic protocol** that a bitcoind
> sidecar (or another node) could also serve, with satd as the reference native
> implementation — but that standardization is a later governance step. For now
> this spec is satd-internal-for-now: a consolidation contract, not a public
> commitment.

## 1. Purpose & scope

Existing node-consumption APIs (Core JSON-RPC + ZMQ, Electrum, Esplora) each
leave the same three gaps: **descriptor lifecycle**, **outpoint-level
subscriptions**, and **cursor-based event replay**. Every serious consumer —
wallets, Lightning nodes, exchanges, watchtowers, explorers, L2s — reinvents
them on top. This API serves all three natively.

The key generalization: **outpoint subscription is the base primitive.** Channel-
close detection, watchtower triggers, deposit confirmation, and theft monitoring
all reduce to "tell me when this outpoint is spent." Address-watching is
outpoint-watching with a derivation rule layered on top. We build down to
outpoints and layer descriptors on as a convenience.

**Out of scope** (unchanged from ROADMAP): mining ops (`getblocktemplate` /
`submitblock` — Stratum is the venue), wallet key management / signing (the node
stays keyless), and any consensus / block-production knobs.

## 2. Relationship to what already exists

This is a **consolidation effort, not a greenfield build.** satd already has:

| Substrate | Crate / module | Role here |
|---|---|---|
| `NodeEvent` envelope (schema v1, edge-stamped, monotonic `seq`) | `node::events` | The wire event type; extended additively below |
| Broadcast firehose (`broadcast::Sender<NodeEvent>`, cap 4096) | `node::events::publisher` | Live event source |
| gRPC `NodeEventStream.Subscribe` (server-streaming) | `events::grpc` (`satd.events.v1`) | Upgraded to bidi (§6) |
| Core-compatible ZMQ PUB | `events::zmq` | Unchanged; legacy sink |
| Electrum per-scripthash registry, status-hash | `electrum-proto` | Pattern reused; not the new surface |
| Esplora REST + SSE (`PermitStream` / `WatchLease` RAII) | `esplora-handlers` | SSE firehose pattern reused (§5) |
| `SpendIndex` (outpoint → spending input, persistent backfill cursor) | `node-index::spend_*` | Query side; the *live* notifier (§7) is the new half |
| BIP158 compact-filter index | `node-filter-index` | Unaffected |
| Unified auth (`stream:subscribe` / `stream:watch` caps + per-token watch quota) | `satd-auth` | Fully reused; no new auth surface (§9) |

The substrate is ~60–70% of the work. This spec defines the **remaining delta**:
durable replay cursors, a live outpoint/script notifier with a bidi control
channel, the JSON/WebSocket transport, and a descriptor convenience layer.

## 3. Transports

One schema (the proto is the source of truth), two transports:

1. **gRPC native** (`satd.events.v1`, tonic) — the bidi `NodeEventStream`
   service (§6). Primary transport for programmatic consumers.
2. **JSON-over-WebSocket** — a hand-rolled JSON mapping of the same proto
   `oneof` tagged-unions, served on a **dedicated `--streamws` listener**. We
   deliberately **do not** use grpc-gateway/REST transcoding (it drags a Go
   toolchain into a build that already fights bindgen / libclang / musl-static).

A **read-only SSE firehose** variant (no client→server control) is also offered
for browser / `curl` consumers, reusing the existing
`esplora-handlers::sse` `PermitStream` / `WatchLease` pattern verbatim.

### 3.1 Listener placement *(decided)*

The `--streamws` listener is a **dedicated port** (not an upgrade on the
Core-compat JSON-RPC port). Two reasons: it keeps the differentiated stream a
"distinct service on a distinct port" (avoiding the *compatibility trap* where
integrators reach for the Core-shaped surfaces and never touch the stream), and
it isolates failure/blast-radius from the RPC listener.

The `--streamws` listener **runs on the API tokio runtime only** — the isolated
read-surface runtime (`--api-threads`), never the core block-connecting runtime.
This is a hard placement rule: it composes with the API-runtime-split
architecture so a flood of streaming clients cannot contend with the threads that
connect blocks and accept mempool transactions. (gRPC `NodeEventStream` likewise
binds on the API runtime.)

## 4. Schema versioning

`NodeEvent.schema_version` is currently `1`. Per the `node::events::schema`
evolution policy, **adding variants and fields is not a major bump** — every
addition in this spec is additive, so `schema_version` stays `1`. A rename or
removal would force a major bump; we avoid those pre-freeze by only adding.

Unknown `oneof` arms / fields MUST be ignored by older readers (forward-compat
for rolling upgrades), exactly as the existing `categories` bitfield already
tolerates unknown bits.

## 5. Event envelope (additions)

```proto
message NodeEvent {
  uint32    schema_version = 1;
  EdgeStamp stamp          = 2;
  Cursor    cursor         = 3;   // NEW — set on confirmed-side bodies (§6)
  oneof body {
    MempoolEvent  mempool      = 10;  // existing
    ChainEvent    chain        = 11;  // existing
    Heartbeat     heartbeat    = 12;  // existing
    OutpointSpent outpoint_spent = 13; // NEW (§7)
    ScriptMatched script_matched = 14; // NEW (§7)
    Reorg         reorg          = 15; // NEW (§8) — first-class, not inferred
  }
}
```

`EdgeStamp` is unchanged (node_id, region, edge_seen_at_ns, edge_wall_ns, `seq`).
`seq` remains **per-publisher and resets on restart** — it is the mempool-side
replay watermark only, never a durable confirmed-side cursor (§6.2).

## 6. Cursors & replay

The single highest-value item: an operator chooses satd over Core RPC + ZMQ
because reconnect-with-cursor is the *one* replay primitive for every
subscription type — subsuming Electrum's subscribe-then-get-history dance and
Esplora's per-address pagination.

### 6.1 Cursor type *(per-tx granularity, decided)*

```proto
message Cursor {
  uint32 height      = 1;  // confirmed: block height of the last delivered item
  uint32 tx_index    = 2;  // confirmed: index within that block of the last delivered tx
  uint64 mempool_seq = 3;  // best-effort mempool high-water (advisory; resets on restart)
}
```

Confirmed-side cursors are durable `(height, tx_index)` — **per-transaction**,
not per-block. Per-tx granularity lets a client resume *mid-block* after a
disconnect, which matters for large blocks; it is nearly free because replay
already indexes into `block.transactions[]`. A client persists the `cursor` from
the last `NodeEvent` it durably processed and presents it on reconnect.

### 6.2 Replay semantics

A client resumes by sending a cursor (§6.3 `SetCursor`). The server:

1. **Confirmed replay** — walks the block index forward from the cursor:
   `get_block_hash_by_height(h)` → `get_block(hash)` →
   `block.transactions[tx_index+1 ..]`, continuing `height → tip`, emitting only
   transactions that match the subscription watch-set (§7). No extra log or index
   is needed — the block store *is* the durable event source.
2. **Snapshot → live handoff** — before replay begins, the server captures the
   current live tip + `seq` watermark. It replays confirmed history up to that
   watermark, then seamlessly drains the live broadcast from the captured point.
   This avoids both gaps and duplicates at the live boundary.
3. **Mempool replay** — best-effort only. The mempool is not durable; the server
   replays from its bounded in-memory ring (the existing
   `mempool::pool` `event_ring`, cap 50) for entries with `seq > mempool_seq`,
   then joins live. A client must treat mempool replay as lossy.

### 6.3 Reorg during replay

If the block hash at `cursor.height` no longer matches what the client last saw
(detectable because the client holds the prior tip hash, and/or the server
emits a `Reorg`, §8), the cursor is **stale**. The server re-anchors: it emits a
`Reorg` describing the fork point, then replays forward from the new common
ancestor. Clients MUST be prepared to receive `BlockDisconnected` / `Reorg`
during replay and roll back their own state accordingly.

## 7. Watch-set subscriptions (the live notifier)

satd has `SpendIndex` (a *query* index) and the Electrum scripthash registry (a
*push* for scripthashes), but no live **outpoint** subscription. This section
adds an outpoint-keyed and script-keyed matcher consulted in the connect /
mempool-accept path, plus a bidi control channel to manage the watch-set on a
live connection.

### 7.1 The matcher (`WatchRegistry`)

A new in-memory registry keyed by `OutPoint` and by `Scripthash`. It is consulted
**inside `connect_block` / `accept_tx`**, where the full transactions are already
in hand, and emits match events. Critically it is **publish/read-only**: the
matcher reads transactions the node already holds and never blocks, locks, or
backpressures the connect path (§10). A slow client lags → drops; it can never
stall block connection.

The current event bus (`ChainEvent::BlockConnected { hash, height }`) is too
coarse to drive this — it carries no per-tx detail. So the matcher runs at the
connect site with the block's transactions, rather than re-deriving matches from
the coarse broadcast event.

### 7.2 Match events

```proto
message OutpointSpent {
  bytes  outpoint_txid = 1;
  uint32 outpoint_vout = 2;
  bytes  spending_txid = 3;
  uint32 spending_vin  = 4;
  bool   confirmed     = 5;   // false = observed in mempool, not yet in a block
}

message ScriptMatched {       // address-watching = outpoint-watching + a derivation rule
  bytes  scripthash = 1;
  bytes  txid       = 2;
  bool   is_output  = 3;      // true = funding (output pays the script), false = spending
  uint32 index      = 4;      // vout if is_output else vin
  bool   confirmed  = 5;
}
```

`AddTransactions` (§7.3) emits the existing `MempoolEvent` / `ChainEvent` bodies
for the watched txids (confirmation tracking) — no new body type needed there.

### 7.3 Bidi control channel *(decided: bidi, tagged-union)*

The gRPC `Subscribe` is lifted from a one-way server stream + category bitfield
to a **bidirectional** stream whose client→server messages are a tagged union:

```proto
service NodeEventStream {
  // was: rpc Subscribe(SubscribeRequest) returns (stream NodeEvent);
  rpc Subscribe(stream SubscribeControl) returns (stream NodeEvent);
}

message SubscribeControl {
  oneof msg {
    SetCursor       set_cursor       = 1;  // §6 resume; supersedes the since_seq punt
    SetCategories   set_categories   = 2;  // firehose category filter (mempool/chain/heartbeat)
    AddScripts      add_scripts      = 3;
    RemoveScripts   remove_scripts   = 4;
    AddOutpoints    add_outpoints    = 5;
    RemoveOutpoints remove_outpoints = 6;
    AddTransactions add_transactions = 7;
    // AddDescriptor (§11) slots in here later without protocol breakage
  }
}

message AddScripts       { repeated bytes scripthashes = 1; }
message RemoveScripts    { repeated bytes scripthashes = 1; }
message AddOutpoints     { repeated Outpoint outpoints = 1; }
message RemoveOutpoints  { repeated Outpoint outpoints = 1; }
message AddTransactions  { repeated bytes txids = 1; }
message Outpoint         { bytes txid = 1; uint32 vout = 2; }
```

A tagged union (not a BIP37-style bloom filter) is what lets new watch kinds slot
in without protocol breakage — the design choice that avoids btcd's BIP37
dead-end. Each arm mirrors the `oneof` style already used in `NodeEvent`.

The legacy server-streaming firehose (categories + `since_seq`) remains available
as a degenerate case: a client that sends only `SetCategories` and never a watch
add gets exactly today's behavior.

## 8. Reorg events

Reorgs become **first-class**, emitted in-process as consensus ground truth — a
bitcoind sidecar structurally cannot do this (ZMQ has no reorg semantics; a
sidecar can only *infer* a reorg by diffing headers).

```proto
message Reorg {
  uint32 from_height = 1;  bytes old_tip = 2;  // tip being abandoned
  uint32 to_height   = 3;  bytes new_tip = 4;  // new active tip
}
```

`Reorg` is emitted around the existing `BlockDisconnected` → `BlockConnected`
sequence the connect path already produces during a reorg, giving clients an
explicit fork-point marker rather than forcing them to reconstruct one.

## 9. Auth, capabilities & quotas

Fully reused from the unified auth layer (`satd-auth`); this API adds **no new
auth surface**.

| Action | Required capability | Quota |
|---|---|---|
| Open `Subscribe`; receive firehose (categories) | `stream:subscribe` | — |
| `AddScripts` / `AddOutpoints` / `AddTransactions` | `stream:watch` | per-token watch quota |
| `Remove*` | — | releases the lease |

Each watch *item* acquires a `WatchLease` (the RAII type from the watch-quota
work) via `Principal::acquire_watch(n)`, gated on `stream:watch` and the
per-token quota. The lease is held for the lifetime of the subscription and
released on `Remove*` or disconnect (RAII drop = reconciliation, same as the
Esplora SSE path).

### 9.1 Quota unit *(decided: N items = N units)*

A watch quota unit is **one watched item**. An `AddOutpoints` carrying N
outpoints consumes **N units**, not 1; likewise `AddScripts` with N scripthashes
consumes N. This matches the quota's intent (bound the *work* a tenant pins on
the node) rather than the message count. Over-quota adds are rejected cleanly
(`RESOURCE_EXHAUSTED` on gRPC / `429` on WS) without tearing down the
subscription; the client may retry after releasing items.

## 10. Consensus-safety invariants (non-negotiable)

satd's first value is being a correct Core-compatible node. The streaming API
MUST NOT compromise that:

- **The event bus is publish-only out of `connect_block` / `accept_tx`.** The
  `WatchRegistry` matcher (§7.1) only *reads* transactions the node already
  holds. It never locks, blocks, or backpressures the connect / mempool-accept
  path.
- **A slow client never backpressures the publisher.** Degrade by drop-with-
  notice: the existing `BroadcastStreamRecvError::Lagged` → log → continue
  behavior is correct and must be preserved as load grows. This is a *safety*
  property, not just UX.
- **Watch/quota state is lock-light** (DashMap / atomics), off the consensus
  hot path.
- **Listeners run on the API runtime only** (§3.1) — never the core
  block-connecting runtime.

## 11. Descriptor convenience layer (sequenced last)

Pure library work on top of the §7 script primitive — no consensus path, lowest
risk, built last.

```proto
message AddDescriptor {              // new SubscribeControl arm
  string descriptor = 1;             // rust-miniscript parseable
  uint32 gap_limit  = 2;
}

message DescriptorNeedsAddresses {   // new NodeEvent body: server→client side-channel
  string descriptor = 1;
  uint32 next_index = 2;             // "expand the watch window to at least here"
}
```

The server expands the descriptor via rust-miniscript → derives watch scripts →
registers them with the §7 `WatchRegistry`. Gap-limit rotation advances the
derivation window as matches land, emitting `DescriptorNeedsAddresses` when the
client should extend. This is the address-watching-as-outpoint-watching
convenience the base primitive was designed to support.

## 12. Proposed implementation sequence

| # | Surface | Net-new vs reuse | Consensus risk |
|---|---|---|---|
| 1 | `Cursor` type + confirmed `(height, tx_index)` replay iterator + snapshot→live handoff | net-new stream machinery | low (read-only) |
| 2 | Mempool best-effort replay (high-water `seq` over existing ring) | mostly reuse | none |
| 3 | `WatchRegistry` + match events in connect / mempool path | net-new matcher | **highest** (touches connect path; must prove no backpressure) |
| 4 | Bidi `Subscribe` + `SubscribeControl` tagged-union + watch-lease wiring | reuses `WatchLease` | low |
| 5 | First-class `Reorg` event | net-new (today inferred) | low |
| 6 | JSON/WS transport (`--streamws`, API runtime) + SSE firehose | reuses `sse.rs` pattern | none |
| 7 | Descriptor layer | pure library | none |

`1→2` gate `3`; `3→4` gate `5–6`; `7` last.

## 13. Open questions (to iterate with consumer feedback)

- **Anchor consumer.** Which downstream integrator co-designs the surface before
  any `v1` freeze? The wire shapes above are a starting point, not a commitment.
- **Standardization path.** Whether/when to lift this into an open, BIP-style,
  transport-agnostic spec with a second implementation (the sidecar hedge) — a
  governance lift deferred until the shape is proven.
- **WS framing details.** Exact JSON envelope for the `oneof` mapping, error
  object shape, and SSE event-type names — to be pinned during §6 implementation.
- **Cursor opacity.** Whether to expose `(height, tx_index)` as structured fields
  (current design, debuggable) or an opaque base64 token (future-proof against
  cursor-format changes). Leaning structured for the draft; revisit at freeze.
- **Descriptor expansion bounds.** Max gap-limit / max derived watch-set per
  token, and how it interacts with the §9.1 per-item quota.

---

*This is a living draft. Update it alongside the implementation PRs (§12) and
revise the wire shapes as the anchor consumer's feedback lands. Cross-reference:
[`ROADMAP.md`](../../ROADMAP.md) (strategic framing),
[`docs/api/esplora.md`](./esplora.md) (the surface this consolidates beyond).*
