# satd Streaming Consumption API — Protocol Spec

A push-based consumption surface for downstream indexers, wallets, Lightning
nodes, exchanges, watchtowers, and explorers: a real-time event firehose plus
live, cursor-resumable watch subscriptions, served over gRPC, WebSocket/SSE, and
(for legacy parity) ZMQ. One schema — the protobuf definition in `satd.events.v1`
is the source of truth — mapped to JSON for the WebSocket transport.

The surface is strictly **publish/read-only and decoupled from consensus**: it
consumes the node's existing chain/mempool broadcasts and re-reads blocks the node
already holds, never touching the block-connection or mempool-acceptance path
(§10). All wire additions are additive — the schema stays `v1`.

## 1. Purpose & scope

Existing node-consumption APIs (Core JSON-RPC + ZMQ, Electrum, Esplora) each leave
the same three gaps: **descriptor lifecycle**, **outpoint-level subscriptions**,
and **cursor-based event replay**. Every serious consumer reinvents them on top.
This API serves all three natively.

The key generalization: **outpoint subscription is the base primitive.**
Channel-close detection, watchtower triggers, deposit confirmation, and theft
monitoring all reduce to "tell me when this outpoint is spent." Address-watching is
outpoint-watching with a derivation rule layered on top. We build down to outpoints
and layer scripts, descriptors, and transaction-id watches on as conveniences over
the same matcher.

**Out of scope:** mining operations (`getblocktemplate` / `submitblock` — Stratum
is the venue), wallet key management and signing (the node stays keyless), and any
consensus or block-production knobs.

## 2. Relationship to existing surfaces

This is a **consolidation of existing substrate, not a greenfield build.** satd
already provides:

| Substrate | Crate / module | Role here |
|---|---|---|
| `NodeEvent` envelope (schema v1, edge-stamped, monotonic `seq`) | `node::events` | The wire event type, extended additively below |
| Broadcast firehose (`broadcast::Sender<NodeEvent>`, cap 4096) | `node::events::publisher` | Live event source |
| gRPC `NodeEventStream` (`satd.events.v1`) | `events::grpc` | The native transport (§3, §7.3) |
| Core-compatible ZMQ PUB | `events::zmq` | Legacy sink, carried unchanged |
| Electrum per-scripthash registry, status-hash | `electrum-proto` | Pattern reused; not the new surface |
| Esplora REST + SSE (`PermitStream` / `WatchLease` RAII) | `esplora-handlers` | SSE firehose pattern reused (§3) |
| `SpendIndex` (outpoint → spending input, persistent) | `node-index::spend_*` | The *query* side; the *live* notifier (§7) is the other half |
| Unified auth (`stream:subscribe` / `stream:watch` + per-token quota) | `satd-auth` | Reused wholesale; no new auth surface (§9) |

The delta this spec defines is the **live notifier**: durable replay cursors, an
outpoint/script/txid matcher with a bidirectional control channel, the JSON/
WebSocket transport, transaction-lifecycle and confirmation-depth watches, and a
descriptor convenience layer.

## 3. Transports

One schema, three transports:

1. **gRPC native** (`satd.events.v1`, tonic) — the primary transport for
   programmatic consumers. A server-streaming `Subscribe` (firehose) and a
   bidirectional `Watch` (firehose + managed watch-set, §7.3).
2. **JSON-over-WebSocket** (`GET /ws`) — a hand-mapped JSON rendering of the same
   proto tagged-unions, with a client→server control channel mirroring `Watch`.
3. **Server-Sent Events** (`GET /sse`) — a read-only JSON firehose (no control
   channel) for browser / `curl` consumers, reusing the Esplora SSE pattern.

The JSON transports deliberately **do not** use grpc-gateway/REST transcoding: it
would drag a Go toolchain into a build that already contends with bindgen /
libclang / musl-static. Hand-mapping a stable, narrow `oneof` surface is cheaper
than owning that toolchain.

A Core-compatible **ZMQ PUB** sink remains for legacy parity. It carries the
firehose bodies only — not the per-subscriber watch matches — and uses Core's
per-topic sequence numbers; gaps are detected the Core way (sequence jumps), so it
does not carry the in-band lag signal (§6.4).

### 3.1 Listener placement

WS/SSE bind a **dedicated `--streamws` port**, not an upgrade on the Core-compat
JSON-RPC port. This keeps the differentiated stream a distinct service on a
distinct port — avoiding the *compatibility trap* where integrators reach for the
Core-shaped surfaces and never discover the stream — and isolates its blast radius
from the RPC listener.

Every streaming listener — `--streamws` and the gRPC `NodeEventStream` — **runs on
the isolated API tokio runtime** (`--api-threads`), never the core block-connecting
runtime. This is a hard placement rule that composes with the API-runtime split: a
flood of streaming clients cannot contend with the threads that connect blocks and
accept mempool transactions.

## 4. Schema versioning

`NodeEvent.schema_version` is `1`. Per the `node::events::schema` evolution policy,
**adding `oneof` variants and fields is not a major bump** — every addition here is
additive, so `schema_version` stays `1`. A rename or removal would force a major
bump; those are avoided pre-freeze.

Unknown `oneof` arms and fields MUST be ignored by older readers (forward-compat
for rolling upgrades), exactly as the existing `categories` bitfield already
tolerates unknown bits.

## 5. Event envelope

```proto
message NodeEvent {
  uint32    schema_version = 1;
  EdgeStamp stamp          = 2;
  Cursor    cursor         = 3;   // set on confirmed-side bodies (§6)
  oneof body {
    MempoolEvent  mempool        = 10;  // accept / confirm / evict / replace
    ChainEvent    chain          = 11;  // connect / disconnect / reorg marker (§8)
    Heartbeat     heartbeat      = 12;
    OutpointSpent outpoint_spent = 13;  // watch match (§7.2)
    ScriptMatched script_matched = 14;  // watch match (§7.2)
    DescriptorNeedsAddresses descriptor_needs_addresses = 15;  // reserved, never emitted (§11)
    Lagged        lagged         = 16;  // in-band lag notice (§6.4)
    TxidMatched   txid_matched   = 17;  // txid lifecycle: seen / confirmed (§7.4)
    TxidReplaced  txid_replaced  = 18;  // txid lifecycle: RBF-replaced (§7.4)
    TxidEvicted   txid_evicted   = 19;  // txid lifecycle: policy eviction (§7.4)
    TxidUnconfirmed txid_unconfirmed = 20;  // txid lifecycle: reorg rollback (§7.4)
    TxidDepthReached txid_depth_reached = 21;  // depth alarm, single-shot (§7.4)
    TxidFinalized txid_finalized = 22;  // lifecycle auto-close, terminal (§7.4)
  }
}
```

`EdgeStamp` carries `node_id`, `region`, `edge_seen_at_ns`, `edge_wall_ns`, and a
per-publisher `seq`. `seq` **resets on process restart**: it is the mempool-side
replay watermark only, never a durable confirmed-side cursor. Restart is detected
through `Cursor.instance_id` (§6.1).

Reorgs are **not** a separate top-level body: they are carried on `ChainEvent`
(`chain = 11`) as a first-class `Reorg` marker followed by the per-block
disconnect/connect sequence (§8). Watch matches (13/14, 17–22) flow on the
per-subscriber `Watch` channel, not the firehose, and are never bridged to ZMQ.

## 6. Cursors & replay

Reconnect-with-cursor is the single highest-value primitive: it is the *one* replay
mechanism for every subscription type, subsuming Electrum's subscribe-then-
get-history dance and Esplora's per-address pagination. A consumer chooses satd
over Core RPC + ZMQ for exactly this.

### 6.1 Cursor type

```proto
message Cursor {
  uint32 height      = 1;  // confirmed: block height of the last delivered item
  uint32 tx_index    = 2;  // confirmed: index within that block (reserved; see below)
  uint64 mempool_seq = 3;  // best-effort mempool high-water (advisory; resets on restart)
  uint64 instance_id = 4;  // per-process restart epoch; JSON-encoded as a decimal string
}
```

A client persists the `cursor` from the last `NodeEvent` it durably processed and
presents it on reconnect to resume.

**Granularity.** `(height, tx_index)` is designed for per-transaction resume so a
client could resume *mid-block* after a disconnect. Today resume is **block-
granular**: `tx_index` is reserved and always `0`, because the only confirmed-side
event is one `BlockConnected` per block. The field is a deliberate forward-
compatible reservation — per-tx resume activates if and when per-tx confirmed
events are introduced — not an oversight. There is no consumer driving per-tx
granularity yet, so it is intentionally unbuilt rather than speculatively shipped.

**Restart epoch.** `instance_id` is a **per-process** random `u64` minted once at
startup — deliberately *not* the persisted-stable `node_id`, which cannot
distinguish a same-node restart. When a resume cursor's `instance_id` differs from
the live publisher's, the daemon has restarted and the mempool `seq` space has
reset; the server resets the mempool watermark (replaying the full ring) while
confirmed/height replay stays durable. On the JSON transports it is serialized as a
decimal **string** so a 64-bit value survives a JavaScript `Number` (53-bit
mantissa); the structured fields (`height`, `tx_index`) are small and stay numeric.

### 6.2 Replay semantics

On resume the server:

1. **Confirmed replay** — resolves the active-chain hash at each height in
   `(cursor.height, tip]` and re-reads each block, emitting the confirmed events.
   The block store *is* the durable event source; no extra log or index is needed.
   Crucially, the hash at each height is found by **walking `prev_blockhash` back
   from the tip** (`active_chain_range`, O(span)), *not* by the best-known-at-height
   index (`get_block_hash_by_height`). That index is last-writer-wins and a
   header-first or side-chain `store_block` can clobber it — using it would risk
   replaying a side-chain block as confirmed. The span is capped (`MAX_REPLAY_BLOCKS`,
   10 000) on every carrier; a client behind the cap backfills the older tail with a
   second `from_cursor` request.
2. **Snapshot → live handoff** — before replay the server captures the current tip
   and `seq` watermark, replays confirmed history up to it, then drains the live
   broadcast from the captured point. The live receiver is subscribed *before* the
   snapshot, so nothing in the gap is lost.
3. **Mempool replay** — best-effort only. The mempool is not durable; the server
   replays from its bounded in-memory ring for entries with `seq > mempool_seq`,
   then joins live. Clients treat mempool replay as lossy by contract.

### 6.3 Reorg at the replay boundary

The handoff de-duplicates **confirmed events by `(height, hash)` identity** and
mempool events by `seq` high-water. Keying confirmed dedup on the *hash*, not the
height alone, is what makes a reorg at the seam correct: a replacement block has a
different hash at the same height, so it is **forwarded** rather than suppressed as
a duplicate. A client that holds the prior tip hash (and/or receives a `Reorg`,
§8) detects a stale cursor and rolls its own state back; the server emits the
`Reorg` and replays forward from the new common ancestor. Clients MUST be prepared
to receive `BlockDisconnected` / `Reorg` during replay.

### 6.4 In-band lag signal

A subscriber that falls behind the bounded broadcast buffer would otherwise
silently lose events. Instead, every carrier (gRPC `Subscribe` + `Watch`, WS, SSE)
emits an in-band `Lagged`:

```proto
message Lagged { uint64 dropped_count = 1; Cursor resume_cursor = 2; }
```

The notice **bypasses the category filter** (its `category_bit` is `u32::MAX`), so
a `SetCategories` mask cannot accidentally suppress the one message a lagging client
most needs. `resume_cursor` is the last-delivered position (seeded from the replay
tail, or the current chain tip on the replay-less `Watch` firehose), so the client
re-issues `Subscribe(from_cursor)` to backfill the gap.

This preserves the core safety property — the server stays **drop-on-lag and never
backpressures the publisher** (§10) — while removing its sharp edge: the client is
told, in-band, exactly where to resume. The cost is that recovery is the client's
responsibility, which is the right place for it (only the client knows its own
durability needs). ZMQ keeps Core's behavior and does not carry `Lagged`.

## 7. Watch-set subscriptions

satd has `SpendIndex` (a *query* index) and the Electrum scripthash registry (a
*push* for scripthashes), but no live **outpoint** subscription. This section adds
an outpoint-, script-, and txid-keyed matcher plus a bidirectional control channel
to manage a watch-set on a live connection.

### 7.1 The matcher

A `WatchRegistry` holds per-subscriber watch-sets behind O(1) inverted indexes
(`by_outpoint`, `by_scripthash`, `by_txid`). It is **decoupled from the consensus
path, not inline in it**: a dedicated `run_watch_matcher` task subscribes to the
existing chain/mempool broadcasts and *re-reads* each connected block
(`ChainState::get_block`) and each accepted tx (`Mempool::get`) once the node
already holds them, then scans the watch-set and delivers matches.

This decoupling is the central design tradeoff. The alternative — matching inside
`connect_block` / `accept_tx` — would be marginally cheaper but would add code to
the consensus hot path. Re-reading off the hot path costs one extra block read per
connected block (and gates it behind a lock-free `has_watchers()` check, so a node
with no subscribers pays nothing), in exchange for **zero edits to the accept
path** and a hard guarantee that no consumer can ever block consensus. The one
cost it introduces is that a matcher whose broadcast receiver lags would skip
blocks; the matcher closes that hole by rescanning the missed window on `Lagged`
(reading blocks the node already holds), bounded by `streammaxresyncblocks`
(default 10 000) so catch-up can never monopolize the API runtime. Delivery to each
subscriber is non-blocking `try_send`: a slow client's channel fills and matches
are dropped-with-notice, never stalling the matcher.

### 7.2 Match events

```proto
message OutpointSpent {
  bytes  outpoint_txid = 1;
  uint32 outpoint_vout = 2;
  bytes  spending_txid = 3;
  uint32 spending_vin  = 4;
  bool   confirmed     = 5;   // false = observed in mempool, not yet in a block
}

message ScriptMatched {
  bytes  scripthash = 1;
  bytes  txid       = 2;
  bool   is_output  = 3;      // true = funding (an output pays the script); false = spending
  uint32 index      = 4;      // vout if is_output else vin
  bool   confirmed  = 5;
}
```

`OutpointSpent` covers spend detection in both the mempool and connected blocks.
`ScriptMatched` covers **both sides** of a script: funding (`is_output = true`) and
spending (`is_output = false`). Input-side script matching is the subtle case — the
spending transaction does not carry the prevout's `scriptPubKey` — so for a
connected block it is recovered from the block's **undo data**
(`Store::get_undo` → `spent_coins[i].script_pubkey`, the i-th non-coinbase input's
prevout). This is a single cached point-get per block, paid only when a script is
actually watched. Unconfirmed spends are tracked by watching the funding
**outpoint**, which `OutpointSpent` detects in the mempool.

### 7.3 Bidirectional control channel

The gRPC service offers the unchanged server-streaming `Subscribe` (the firehose)
plus a **bidirectional** `Watch` whose client→server messages are a tagged union:

```proto
service NodeEventStream {
  rpc Subscribe(SubscribeRequest)        returns (stream NodeEvent);  // firehose; from_cursor replay
  rpc Watch(stream SubscribeControl)     returns (stream NodeEvent);  // firehose + managed watch-set
}

message SubscribeControl {
  oneof msg {
    SetCursor          set_cursor          = 1;  // resume anchor (see below)
    SetCategories      set_categories      = 2;  // firehose category filter (mempool/chain/heartbeat)
    AddScripts         add_scripts         = 3;
    RemoveScripts      remove_scripts      = 4;
    AddOutpoints       add_outpoints       = 5;
    RemoveOutpoints    remove_outpoints    = 6;
    AddDescriptor      add_descriptor      = 7;  // §11
    AddTransactions    add_transactions    = 8;  // txid lifecycle + depth (§7.4)
    RemoveTransactions remove_transactions = 9;
  }
}
```

A tagged union — not a BIP37-style bloom filter — is what lets new watch kinds slot
in without protocol breakage, the design choice that avoids btcd's BIP37 dead-end.
The WS control channel is the JSON mirror of this union.

**Resume semantics.** Durable replay (§6.2) is offered at stream **establishment**:
`Subscribe(from_cursor)` on gRPC, and `?from_cursor=` at WS/SSE connect. Mid-stream
`SetCursor` on the bidi `Watch` is a **documented no-op** — splicing a historical
replay into a stream that is already live is ill-defined (it would interleave past
and present); a client that needs to re-anchor reconnects with `from_cursor`
instead. A client that sends only `SetCategories` and no watch-add gets exactly the
legacy firehose behavior.

### 7.4 Transaction lifecycle & confirmation-depth watches

`AddTransactions` registers, over the same `by_txid` index, **two decoupled
primitives** selected by `min_depths`:

```proto
message AddTransactions    { repeated bytes txids = 1; repeated uint32 min_depths = 2; uint32 auto_close_depth = 3; }
message RemoveTransactions { repeated bytes txids = 1; repeated uint32 min_depths = 2; }

message TxidMatched     { bytes txid = 1; bool confirmed = 2; uint32 height = 3; }
message TxidReplaced    { bytes txid = 1; bytes replacing_txid = 2; }        // RBF
message TxidEvicted     { bytes txid = 1; string reason = 2; }               // full_pool | expiry | block_conflict
message TxidUnconfirmed { bytes txid = 1; uint32 prev_height = 2; }          // reorg rollback
message TxidDepthReached{ bytes txid = 1; uint32 depth = 2; uint32 height = 3; }  // single-shot alarm
message TxidFinalized   { bytes txid = 1; uint32 depth = 2; uint32 height = 3; }  // lifecycle auto-close
```

- **Lifecycle watch** (`min_depths` empty) — one persistent watch per txid that
  narrates the transaction's full lifecycle: **seen** (mempool) → **confirmed**
  (block) via `TxidMatched`, then `TxidReplaced` (RBF, carrying the replacing
  txid), `TxidEvicted` (mempool policy), and `TxidUnconfirmed` (a reorg rolled back
  its confirming block). An optional `auto_close_depth ≥ 1` makes the watch emit a
  terminal `TxidFinalized` and self-evict once the tx is that many confirmations
  deep.
- **Depth alarm** (`min_depths` non-empty) — single-shot triggers keyed
  `(txid, depth)`: `TxidDepthReached` fires the moment the tx reaches `depth`
  confirmations, then self-evicts. `min_depths` is a list, so one message arms
  several thresholds (e.g. `[1, 6]`); each `(txid, depth)` pair is an independent
  watch item.

The two are orthogonal: a depth alarm needs no lifecycle watch, and a lifecycle
watch implies no alarm. `auto_close_depth` exists because **no lifecycle state is
truly terminal** — a reorg un-confirms a confirmed tx, a re-broadcast revives an
evicted one, a replacing tx can itself be reorged out — so a watch cannot safely
self-clean on "confirmed" or "evicted." The only sound server-side self-clean is a
depth the *client* nominates as its finality horizon, past which it accepts that
reorgs are no longer interesting; below that depth, un-confirmations still fire.

**Reorg safety.** Depth tracking anchors on the confirming `(height, hash)` and
re-checks it against the active chain on every block (the same tip-walk as replay,
§6.2, never the pollutable height index). A confirming block reorged off the active
chain reverts the entry, which re-arms if the tx reappears. A tx already buried when
the watch is registered is resolved best-effort via the txindex (and otherwise arms
on its next observed confirmation). `TxidUnconfirmed` is best-effort: it requires
re-reading the disconnected block, so it is skipped if that block has been pruned —
the depth anchor's revert remains reliable regardless.

**Single-shot eviction** is registry-authoritative: a fired alarm or auto-close is
torn down server-side immediately, so it cannot re-fire even if its txid reappears
in a later block, and its accounting is freed regardless of whether the terminal
match reached a lagging client. The carrier then releases the quota lease on
forwarding the match. The residual tradeoff: a terminal match dropped to a full
channel holds that one quota unit until the connection closes — bounded by the
connection lifetime and the per-token quota.

Because `AddTransactions` carries two repeated lists, the server bounds the
`txids × min_depths` cross-product before allocating it: a malformed or oversized
control message is rejected, never amplified into a large allocation.

## 8. Reorg events

Reorgs are **first-class**, emitted in-process as consensus ground truth — a
bitcoind sidecar structurally cannot do this (ZMQ has no reorg semantics; a sidecar
can only infer a reorg by diffing headers).

```proto
message Reorg {
  uint32 from_height = 1;  bytes old_tip = 2;  // tip being abandoned
  uint32 to_height   = 3;  bytes new_tip = 4;  // new active tip
}
```

The `Reorg` marker is emitted around the existing `BlockDisconnected` →
`BlockConnected` sequence the connect path already produces during a reorg, giving
clients an explicit fork-point marker rather than forcing them to reconstruct one
from a stream of disconnects.

## 9. Auth, capabilities & quotas

Reused wholesale from the unified auth layer (`satd-auth`); this API adds **no new
auth surface**. With no token store configured the transports are open
(loopback-trust, matching today's events-gRPC behavior); a remote bind requires a
token store.

| Action | Capability | Quota |
|---|---|---|
| Open a stream; receive the firehose (categories) | `stream:subscribe` | — |
| `AddScripts` / `AddOutpoints` / `AddTransactions` / `AddDescriptor` | `stream:watch` | per-token watch quota + per-add rate limit |
| `Remove*` | — | releases each item's unit immediately |

**Quota unit (N items = N units).** A unit is one watched *item*: an `AddOutpoints`
of N outpoints consumes N units, an `AddScripts` of N scripthashes consumes N, and
a depth alarm consumes one unit per `(txid, depth)` pair. A lifecycle watch's
`auto_close_depth` rides free (it is not a separate item). This bounds the *work* a
tenant pins on the node, not the message count. Over-quota adds are rejected
cleanly (`RESOURCE_EXHAUSTED` on gRPC / `429` on WS) without tearing down the
subscription.

**Lease lifecycle.** Each item holds a `WatchLease` (RAII) tracked **per item** in
a subscription-scoped `WatchSet`. So `Remove*` returns that item's unit
immediately, which is what makes a long-lived client that rotates a watch-set
(e.g. a sliding descriptor window, §11) viable without monotonically exhausting its
quota. Dedup is **cross-message**: re-asserting an item the subscription already
holds is charged once. The `WatchSet` is scoped to the *subscription*, not the
control stream, so an HTTP/2 half-close (client closing its send side while keeping
the response open) cannot release quota while watches stay live. A **per-add rate
limit** bounds the rate of effective (net-new) adds via the per-principal token
bucket, shedding over-budget adds without dropping the connection — a connected
client must not be able to spam adds bounded only by steady-state quota.

## 10. Consensus-safety invariants (non-negotiable)

satd's first value is being a correct Core-compatible node; the streaming API must
not compromise that. These are structural guarantees, not policies:

- **The event bus is publish-only out of `connect_block` / `accept_tx`.** The
  matcher (§7.1) only *reads* data the node already holds; it adds no code to, and
  takes no lock on, the consensus path.
- **A slow client never backpressures the publisher.** Degradation is drop-with-
  notice (§6.4): `broadcast` `send` is non-blocking and lossy, and per-subscriber
  delivery is non-blocking `try_send`. This is a *safety* property, not just UX.
- **Watch/quota state is lock-light** (inverted-index maps gated by lock-free
  watcher counts; atomics), off the consensus hot path.
- **Listeners run on the API runtime only** (§3.1), never the core block-connecting
  runtime.

## 11. Descriptor convenience layer

Pure library work on top of the §7 script primitive — no consensus path, lowest
risk.

```proto
message AddDescriptor {
  string descriptor = 1;   // rust-miniscript parseable, public-key-only
  uint32 gap_limit  = 2;   // window size; capped at MAX_DESCRIPTOR_WINDOW (1000)
  uint32 start      = 3;   // window start index (default 0)
}
```

The server expands the descriptor via rust-miniscript over the window
`[start, start + gap_limit)`, derives the watch scripts, and registers them with
the §7 matcher — the address-watching-as-outpoint-watching convenience the base
primitive was designed for. Expansion is bounded (`MAX_DESCRIPTOR_WINDOW`, a DoS
limit) and rejects hardened-wildcard and any secret-bearing descriptor at the type
level (`Descriptor<DescriptorPublicKey>`), so no signing material can be submitted.

**Gap-limit tracking is a client concern, by design.** An earlier approach had the
server track derivation progress and push a `DescriptorNeedsAddresses` side-channel
to tell the client to extend its window. We rejected it: the client knows its own
address-generation policy and is better placed to decide when to advance. So the
server stays **stateless** — it watches the fixed window it was asked for — and the
client drives a sliding window by issuing a fresh `AddDescriptor` with an advanced
`start` as funding approaches the window's high end, `Remove*`-ing the trailing
scripts (cheap thanks to per-remove release, §9). The `DescriptorNeedsAddresses`
body (field 15) is reserved for wire-compat but is never emitted.

## 12. Operator limits

Every remote-facing surface is bounded so it cannot be driven to fd / memory / task
exhaustion, mirroring the rest of the node's admission controls. All are
`restart!`-classified config; `0` means unlimited:

| Key | Default | Bounds |
|---|---|---|
| `streamwsmaxconns` | 256 | concurrent `/ws` + `/sse` connections |
| `streamwsmaxsubscriptions` | 256 | watch-set size per WS connection |
| `streamwsmaxmessagebytes` | 262144 | a single inbound WS control frame |
| `eventsgrpcmaxconns` | 64 | concurrent gRPC streams |
| `eventsgrpcmaxsubscriptions` | 256 | watch-set size per gRPC stream |

Admission shedding runs ahead of authentication and request-body buffering, so a
connection flood — authenticated or not — is bounded before it does work.

## 13. Open questions

These are genuine open design points, deferred until a real consumer's feedback can
settle them ahead of any `v1` freeze:

- **Anchor consumer.** Which downstream integrator co-designs the surface before a
  `v1` freeze. The wire shapes here are a working contract, not yet a commitment.
- **Standardization path.** Whether and when to lift this into an open, BIP-style,
  transport-agnostic spec with a second implementation (e.g. a bitcoind sidecar) —
  a governance step deferred until the shape is proven.
- **Cursor opacity.** Whether to keep `(height, tx_index, mempool_seq,
  instance_id)` as structured, debuggable fields (current design) or move to an
  opaque token that is future-proof against cursor-format changes.
- **Descriptor expansion bounds.** The right max gap-limit / max derived watch-set
  per token, and how it composes with the §9 per-item quota.

---

*Cross-reference: [`ROADMAP.md`](../../ROADMAP.md) (strategic framing),
[`docs/api/esplora.md`](./esplora.md) (the surface this consolidates beyond),
[`CHANGELOG.md`](../../CHANGELOG.md) (user-facing summary).*
