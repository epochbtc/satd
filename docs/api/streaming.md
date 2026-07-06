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
    PrefixMatched prefix_matched = 23;  // privacy-preserving prefix watch (§7.5)
    SetCursorResult set_cursor_result = 24;  // deterministic re-anchor ack/reject (§7.3.1)
    WatchSetResult set_watch_set_result = 25;  // deterministic atomic-replace ack/reject (§11.2)
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
  repeated DescriptorMatch descriptor_matches = 6;  // descriptor attribution (§11.1); empty for a direct watch
  uint64 amount     = 7;      // matched value; funded output or spent-prevout, per streamprevoutmeta tier
  bool   has_amount = 8;      // distinguishes a genuine 0-value match from "not retained at this tier"
  bytes  raw_tx     = 9;      // full matching tx, inline; only when this stream opted in (SetWatchOptions)
}

// Per-stream delivery options (SubscribeControl.set_watch_options). Off by
// default — raw_tx inlining is bandwidth-heavy.
message SetWatchOptions { bool include_raw_tx = 1; }

message DescriptorMatch {
  string descriptor       = 1;   // the descriptor string the client registered
  uint32 branch           = 2;   // 0-based BIP-389 multipath branch (external=0, change=1; 0 if single-path)
  uint32 derivation_index = 3;   // absolute derivation index of the matched script
}

// AddScripts carries an optional per-scripthash min_value floor (§7.2.1).
message AddScripts { repeated bytes scripthashes = 1; repeated uint64 min_values = 2; }
```

`OutpointSpent` covers spend detection in both the mempool and connected blocks.
`ScriptMatched` covers **both sides** of a script: funding (`is_output = true`) and
spending (`is_output = false`). Input-side script matching is the subtle case — the
spending transaction does not carry the prevout's `scriptPubKey` — so for a
connected block it is recovered from the block's **undo data**
(`Store::get_undo` → `spent_coins[i].script_pubkey`, the i-th non-coinbase input's
prevout). This is a single cached point-get per block, paid only when a script is
actually watched. The **mempool** input side is its unconfirmed twin: the spending
tx still carries no prevout `scriptPubKey`, so it is recovered from the prevout
scripthashes the mempool entry retains at admission (where the prevouts were already
resolved for validation), yielding `ScriptMatched{is_output = false, confirmed =
false}` without re-resolving anything off the hot path. Watching the funding
**outpoint** also surfaces the spend (via `OutpointSpent`); the script path means a
script watcher need not separately enumerate its outpoints to see unconfirmed spends.

`ScriptMatched.amount`/`has_amount` carry the matched value in-band at wire
parity with `SpentPrevout` (§7.6.1) — always present on the funding side and
for confirmed spends, present for mempool spends under `streamprevoutmeta >=
amount` (the default) — so an exact-script consumer can skip the per-match
`getrawtransaction` enrichment call and the cross-node "not found" mempool
race it can hit. `raw_tx` goes further: the full consensus-serialized
matching transaction, inlined only for a connection that has sent
`SetWatchOptions{include_raw_tx = true}` (off by default; the matcher only
pays the serialization cost when at least one connection has opted in, and
the bytes are cached and shared across matches on the same transaction).

#### 7.2.1 Per-script `min_value` floor

`AddScripts` accepts an optional `min_values` list, parallel to `scripthashes`: a
per-script floor in satoshis below which matches are suppressed **server-side**, so
a watcher that only cares about economically significant activity is not woken by
dust. An empty `min_values` means no floors; a non-empty list MUST have the same
length as `scripthashes` (a mismatch rejects the whole add — never silently
unfiltered). Re-asserting a watched scripthash updates its floor in place (it is
not a new quota item).

The floor is **symmetric** with the two sides of `ScriptMatched`, gating on the
value of the coin the script controls in that match:

- **Funding** (`is_output = true`): the matched output's value.
- **Spending** (`is_output = false`): the **spent prevout's** value — the input
  carries no value, so it is recovered the same way the prevout `scriptPubKey` is.
  For a **confirmed** block that is the undo data (`spent_coins[i].value`, free
  alongside the script); for the **mempool** it is the prevout value retained at
  admission (`streamprevoutmeta ≥ amount`, §12.1) — the default.

On a node configured `streamprevoutmeta = hash` the mempool spend side has no
value to test, so a floored script's **unconfirmed-spend** matches **fail closed**
(suppressed) rather than being delivered unfiltered — a `min_value` watcher is
never handed a possibly-dust unconfirmed spend it asked to be spared. The floor is
still enforced normally on that script's funding and confirmed-block-input sides;
only the mempool spend preview is withheld until the operator retains amounts.
(Non-floored watches on the same node are unaffected.)

The value itself never enters the wire event — the floor is purely a delivery
filter. The floor on the **output** and **confirmed-input** sides costs nothing
(both values are already in hand); only the mempool-input side depends on the
retention tier.

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
    AddTransactions      add_transactions      = 8;  // txid lifecycle + depth (§7.4)
    RemoveTransactions   remove_transactions   = 9;
    AddScriptPrefixes    add_script_prefixes   = 10; // privacy-preserving prefix watch (§7.5)
    RemoveScriptPrefixes remove_script_prefixes = 11;
    RemoveDescriptor     remove_descriptor     = 12; // drop a descriptor window (§11)
    SetWatchSet          set_watch_set         = 13; // atomic whole-set replace (see below)
    RescanBlocks         rescan_blocks         = 14; // bounded historical rescan (§7.6)
    SetWatchOptions      set_watch_options     = 15; // per-stream delivery opt-ins, e.g. raw_tx (§7.2)
  }
}
```

A tagged union — not a BIP37-style bloom filter — is what lets new watch kinds slot
in without protocol breakage, the design choice that avoids btcd's BIP37 dead-end.
The WS control channel is the JSON mirror of this union.

**Resume semantics.** Durable replay (§6.2) is offered at stream **establishment**:
`Subscribe(from_cursor)` on gRPC, and `?from_cursor=` at WS/SSE connect. A client
that sends only `SetCategories` and no watch-add gets exactly the legacy firehose
behavior.

Mid-stream `SetCursor` on the bidirectional gRPC `Watch` **re-anchors** the
firehose (§7.3.1); WS/SSE clients, which have no mid-stream control channel,
re-anchor by reconnecting with `?from_cursor=`.

#### 7.3.1 Mid-stream re-anchor

`SetCursor(cursor)` on a live `Watch` replays the confirmed history the client
asks to revisit, then resumes the live tail — without tearing down the watch-set.
It is an **ordered drain-replay-resume**, not an interleave:

1. The server runs the same `build_cursor_replay` snapshot→live handoff used at
   establishment (§6.2) for `(cursor.height, current_tip]`.
2. The replayed confirmed events are emitted **in height order, ahead of any
   further live events** — the re-anchor batch is drained to completion before the
   live tail resumes. Live events that accumulate during the drain follow and may
   duplicate the tail of the replay; the client de-duplicates by `(height, hash)`
   exactly as at the establishment seam (§6.3), so the stream is at-least-once with
   idempotent confirmed application.
3. The **watch-set and its quota leases are preserved** across the re-anchor —
   the reason to re-anchor in place rather than reconnect with `from_cursor`, which
   would force a full re-add (+ re-auth + quota rebuild) of a possibly-large
   watch-set. A long-lived `Watch` with thousands of registered scripts/outpoints
   re-anchors its replay position without rebuilding its watch-set.

**Not replayed:** historical watch *matches*. Watch matches are per-subscriber and
not durable (they are never part of cursor replay, nor bridged to ZMQ). A
re-anchor replays the firehose/confirmed history only; the client reconstructs any
historical matches it needs from the replayed blocks against its own watch-set, and
receives live matches going forward. Replay work is bounded two ways: concurrent
re-anchors are capped at one in flight per stream, and each actionable re-anchor is
charged against the connection's per-principal rate limit — the same token bucket as
watch-set adds — so back-to-back `SetCursor`s in a tight loop are throttled rather
than allowed to re-walk the block index unboundedly. (Operator/loopback principals
bypass the rate limit, as elsewhere.)

##### Deterministic outcome (`SetCursorResult`)

Every actionable `SetCursor` produces exactly one in-band `SetCursorResult`
`NodeEvent` on the stream, so a client can distinguish "accepted, replaying from
X" from "ignored, still live from the old position" without inferring it from the
event flow:

```proto
message SetCursorResult {
  oneof outcome {
    CursorAccepted accepted = 1;
    CursorRejected rejected = 2;
  }
}
message CursorAccepted { Cursor from = 1; bool clamped = 2; uint32 earliest_replayed = 3; }
message CursorRejected {
  enum Reason { REASON_UNSPECIFIED = 0; RATE_LIMITED = 1; CONCURRENT_REANCHOR = 2; EMPTY_CURSOR = 3; NO_SOURCE = 4; }
  Reason reason = 1; Cursor current_head = 2;
}
```

- **`CursorAccepted`** is emitted **ahead of the replay batch**: replay is now
  running. When the requested cursor predates the replay window
  (`MAX_REPLAY_BLOCKS = 10 000` confirmed blocks) the lower end is **clamped** —
  `clamped = true` and `earliest_replayed` is the first height that will actually
  be replayed; the client must full-resync the skipped range below it from another
  source (e.g. RPC `getblock`).
- **`CursorRejected`** means the re-anchor did **not** run and the live stream is
  unchanged: `RATE_LIMITED` (per-principal limit), `CONCURRENT_REANCHOR` (a drain
  already in flight), `EMPTY_CURSOR` (no cursor in the request), or `NO_SOURCE`
  (server has no `block_source`). `current_head` is the server's present resume
  position, so the client can retry, back off, or escalate to a full resnapshot.

A consumer with an at-least-once delivery contract should drive its catch-up
state machine off these results rather than treating the `SetCursor` send as
success. WS/SSE clients have no mid-stream control channel and so never see a
`SetCursorResult` — they re-anchor by reconnecting with `?from_cursor=`.

### 7.4 Transaction lifecycle & confirmation-depth watches

`AddTransactions` registers, over the same `by_txid` index, **two decoupled
primitives** selected by `min_depths`:

```proto
message AddTransactions    { repeated bytes txids = 1; repeated uint32 min_depths = 2; uint32 auto_close_depth = 3; }
message RemoveTransactions { repeated bytes txids = 1; repeated uint32 min_depths = 2; }

message TxidMatched     { bytes txid = 1; bool confirmed = 2; uint32 height = 3; }
message TxidReplaced    { bytes txid = 1; bytes replacing_txid = 2; }        // RBF
message TxidEvicted     { bytes txid = 1; string reason = 2; }               // full_pool | expiry | block_conflict | policy
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

### 7.5 Privacy-preserving prefix subscriptions

The §7.2–7.4 watches are precise: the server learns the exact scripts, outpoints,
and txids a client cares about. The firehose (§5) is the privacy ceiling — the
server learns nothing — but a client that wants only its own activity pays full
chain+mempool bandwidth for it. `AddScriptPrefixes` is the tunable middle. A client
registers a **k-bit prefix** of `sha256(scriptPubKey)` instead of a full 32-byte
scripthash, and the server delivers every transaction whose script falls in that
2⁻ᵏ **bucket**; the client filters the bucket against its real scripts locally. The
server's knowledge is bounded at "this client watches bucket *p*" — it never learns
which script within the bucket is the real target, because it delivers the whole
bucket and the discrimination happens client-side.

This is the **push dual of BIP 158** (which satd already computes and serves as a
block-filter index): the same idea — coarse, deterministic membership the client
tests itself — pushed rather than pulled. The push form is *more* naturally private
here, for two reasons. First, there is **no fetch step**: a BIP 158 client that
matches a filter must fetch the full block, and that fetch leaks which block it
cared about (mitigated only by fetching blocks from a *different* server); a prefix
subscriber receives the matching transactions inline, so there is no second request
to correlate. Second, it **covers the mempool**, which block filters structurally
cannot.

**Membership is BIP 158-parity** — output scripts *and* spent-prevout scripts — so a
single bucket catches both funding and spending of a script, exactly as §7.2's
`ScriptMatched` does for exact scripts. It reuses the same resolution machinery: the
output side is the scripthash `scan_tx` already computes; the **confirmed** input
side is the prevout script `scan_block_spent_scripts` already recovers from a block's
undo data; the **mempool** input side is resolved from the prevout scripthashes the
mempool entry retains at admission (the prevouts are already resolved there for
validation). That retained-hash mempool-spend path is shared with the exact-script
watch (§7.2) — the prefix watch is what *motivated* it, because the alternative
unconfirmed-spend signal, an outpoint watch, is a fallback a privacy client *cannot*
use without naming the very outpoints it is hiding. Each resolved scripthash is
truncated to the registered prefix lengths
and looked up in a parallel `by_prefix` index (keyed `(bits, prefix)`, gated by a
lock-free `has_prefix_watchers()` like every other watch kind). The per-output cost
is O(distinct prefix lengths in use) — a `BTreeSet` of active `k` values, typically
one or two — independent of subscriber count.

```proto
message ScriptPrefix         { bytes prefix = 1; uint32 bits = 2; }  // k bits, left-aligned in ceil(k/8) bytes
message AddScriptPrefixes    { repeated ScriptPrefix prefixes = 1; }  // control field 10
message RemoveScriptPrefixes { repeated ScriptPrefix prefixes = 1; }  // control field 11

message PrefixMatched {                       // body field 23
  ScriptPrefix prefix           = 1;
  bytes        raw_tx           = 2;          // the full matching tx, inline — no precise follow-up fetch
  bool         confirmed        = 3;
  uint32       height           = 4;
  repeated SpentPrevout matched_prevouts = 5; // spend side (see SpentPrevout); empty on a pure funding match
}
// script_pubkey/amount carriage depends on the retention tier (§12.1): confirmed
// spends always carry both (from undo); mempool spends carry the script only
// under `full` and the value only under `>= amount`. `has_amount` disambiguates a
// genuine 0-sat prevout from "value not retained".
message SpentPrevout {
  bytes  outpoint_txid = 1; uint32 outpoint_vout = 2;
  bytes  script_pubkey = 3;  // empty when not retained
  uint64 amount = 4; bool has_amount = 5;
}
```

On the WS/SSE JSON surface each `matched_prevouts` entry mirrors this exactly:
`script_pubkey` is a (possibly empty) hex string, `amount` is a number or `null`
when the value was not retained, and `has_amount` is the explicit boolean — so a
JSON client need not infer retention from the `null`-vs-`0` encoding.

**Delivery is self-contained, deliberately.** `PrefixMatched` carries the full
`raw_tx`, not a txid — a txid would force the client to fetch the transaction
precisely, re-leaking the exact interest the bucket was hiding. For a **confirmed**
spend it also carries the matched prevout scripts (and values) in
`matched_prevouts` (recovered from undo data), so the client can confirm "this is a
spend of one of my outputs" without resolving any outpoint itself. For a
**mempool** spend, how much it can confirm from the event alone depends on the
operator's `streamprevoutmeta` (§12.1): under `full` the real prevout `scriptPubKey`
is carried (the chainstate-less / privacy client's case — confirm locally, no
outpoint resolution, no re-leak); under the default `amount` the value is carried
but the script is empty; under `hash` neither is, and the client confirms the match
against its own UTXO set. Because a bucket is
a 2⁻ᵏ slice of uniform scripthash space, inline full-tx delivery is cheap: even a
coarse k=8 bucket (anonymity set ≈ 256×) is a low-single-digit transactions per
block plus a trickle from the mempool.

**Granularity is operator-bounded** by `streamprefixminbits` / `streamprefixmaxbits`.
The maximum (most precise) bound matters most: without it a client could register a
near-full-length prefix and rebuild the leaking exact watch with extra steps, so
`bits` is capped well short of a single script. The minimum bounds the bandwidth and
quota a single bucket can pull. A client's choice of `k` is itself metadata, so a
future refinement is to advertise a small fixed *menu* of allowed lengths rather
than a free range, making buckets uniform across clients (privacy by uniformity, the
property that makes BIP 158 filters identical for everyone) — see §13.

**Quota is priced by coarseness.** A coarse prefix is both more private and more
expensive to serve (a bigger bucket is more delivered traffic), so a prefix item
costs units scaling inversely with `k` rather than a flat one unit (§9) — the
bandwidth cost of privacy is surfaced directly in the quota rather than hidden, and
a client cannot cheaply pin a near-half-chain bucket under a single "watch."

**Privacy properties, stated honestly.** The server learns the *set of buckets* a
client subscribes to, and nothing finer; within a bucket the real target is
indistinguishable from its 2ᵏ⁻ᵇⁱᵗ cover, and there is no fetch step to narrow it.
Two residuals are the client's to manage, not the server's: a wallet that registers
many *precise* prefixes leaks a coarse silhouette of itself (prefer few coarse
buckets over many fine ones), and a *stable* prefix per target is
intersection-resistant — repeated matches only re-assert "watches bucket *p*" —
whereas a prefix that varies per query can be intersected back down. The firehose
remains the only zero-disclosure option; this is the knob between it and the exact
watches, not a replacement for either.

### 7.6 Bounded historical rescan (`RescanBlocks`)

`SetCursor` replay (§6.2) is forward-from-cursor and synthesizes `BlockConnected`
events, but it does **not** replay watch *matches* — the client reconstructs them
from the replayed blocks against its own watch-set, and the window is capped at
`MAX_REPLAY_BLOCKS`. `RescanBlocks` is the **pull dual**: the server runs the
matcher over a caller-specified historical range and returns the matches directly.

```proto
message RescanBlocks {          // SubscribeControl.rescan_blocks = 14
  uint32 from_height = 1;       // inclusive
  uint32 to_height   = 2;       // inclusive, >= from_height
}
```

Semantics:

1. **Scans this connection's watch-set only.** The rescan runs against a snapshot
   of the requesting subscription's watch-set in an isolated, single-subscriber
   matcher — it can never deliver to another connection. It reproduces the four
   confirmed match bodies a live block scan would (`ScriptMatched` output- and
   input-side, `OutpointSpent`, `TxidMatched`, `PrefixMatched`, all
   `confirmed=true`), in height order. Depth alarms and txid-lifecycle
   transitions are **not** reproduced — those are forward-looking/stateful and
   have no meaning over a closed historical range.
2. **Deterministic, in-band ack** (mirrors `SetCursorResult`). Exactly one
   `RescanResult` precedes any matches:

   ```proto
   message RescanResult { oneof outcome {
       RescanAccepted accepted = 1;   // from/to (post-clamp) + clamped flag
       RescanRejected rejected = 2;   // reason + tip_height
   } }
   ```

   The range is clamped to the current tip (`clamped` set when the requested
   `to_height` exceeded it); an inverted range, a range wholly above the tip, or a
   span exceeding `MAX_RESCAN_BLOCKS` (= `MAX_REPLAY_BLOCKS`, 10 000) is rejected
   whole (`INVALID_RANGE` / `RANGE_TOO_LARGE`). Other reasons: `NO_SOURCE` (no
   local block bodies/undo), `EMPTY_WATCH_SET`, `RATE_LIMITED`, `CONCURRENT_RESCAN`.
3. **Terminal marker.** After the last match the server emits
   `RescanComplete{from_height, to_height, matches}`, so the client knows the range
   is fully drained and how many matches it produced. The stream then resumes its
   prior live position.
4. **A side query.** A rescan does **not** advance the durable forward cursor, and
   its match events carry no resume cursor. It is rate-limited per principal, admits
   one rescan in flight at a time (a second → `CONCURRENT_RESCAN`), and runs
   independently of any in-flight `SetCursor` re-anchor.
5. **Off the consensus hot path.** Like replay, the rescan reads blocks (and undo
   data, only when a script/prefix is watched) the node already holds; it never
   blocks or backpressures block connection.

This closes the streaming-watch-set cold-sync / beyond-`MAX_REPLAY_BLOCKS` recovery
gap without the client walking blocks itself. (BIP157 P2P still covers bulk
trustless filter-based sync; this is the server-side push-model equivalent for the
watch-set path.) SDK: `ResilientWatch::rescan(from, to)` — the ack, matches, and
`RescanComplete` arrive in-band on `next()`.

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
| `AddScriptPrefixes` (§7.5) | `stream:watch` | same quota, but **priced by coarseness** (see below) |
| `Remove*` | — | releases each item's unit immediately |

**Quota unit (N items = N units).** A unit is one watched *item*: an `AddOutpoints`
of N outpoints consumes N units, an `AddScripts` of N scripthashes consumes N, and
a depth alarm consumes one unit per `(txid, depth)` pair. A lifecycle watch's
`auto_close_depth` rides free (it is not a separate item). The one exception is a
prefix watch (§7.5), which is priced by coarseness — units scale inversely with
`bits` (a coarser bucket delivers more traffic) rather than a flat one unit — so the
quota reflects served bandwidth, not item count, for the one watch kind whose cost
is not one-item-one-match. This bounds the *work* a tenant pins on the node, not the
message count. Over-quota adds are rejected
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

message RemoveDescriptor {
  string descriptor = 1;   // byte-matches the AddDescriptor string
}
```

The server expands the descriptor via rust-miniscript over the window
`[start, start + gap_limit)`, derives the watch scripts, registers them with
the §7 matcher, and **retains the descriptor → derived-scripthashes membership**
for the connection — the address-watching-as-outpoint-watching convenience the
base primitive was designed for. A BIP-389 multipath descriptor (`.../<0;1>/*`) is
split into its branches and each branch expanded over the same window, so it
yields up to `branches × gap_limit` scripts and costs that many watch units; the
branch count is capped at 2 (`MAX_DESCRIPTOR_BRANCHES`) — more is rejected before
the split. Expansion is bounded per branch (`MAX_DESCRIPTOR_WINDOW`, a DoS limit,
so ≤ 2000 scripts for a 2-branch descriptor) and rejects hardened-wildcard and any
secret-bearing descriptor at the type level (`Descriptor<DescriptorPublicKey>`),
so no signing material can be submitted.

Each derived scripthash carries an **owner count** — the number of sources
(a direct `AddScripts` and/or one or more descriptors) that currently watch it.
A script's quota unit and matcher registration are released only when its **last**
owner goes, so a scripthash shared by two descriptors, or by a descriptor and a
direct add, is never dropped while any source still wants it.

The number of distinct descriptors a single connection may retain is capped
(`MAX_DESCRIPTORS_PER_CONNECTION = 256`). The cap exists because a descriptor
whose window expands entirely to already-watched scripts charges no quota unit
(nothing is net-new) yet still costs a retained membership entry, so without it a
client could grow that map without bound, invisibly to the watch quota and the
per-connection watch-set cap. A connection at the cap must `RemoveDescriptor`
before adding a new descriptor; re-asserting (sliding) an already-retained
descriptor never counts against it.

`RemoveDescriptor` drops a descriptor's whole window: every scripthash it
contributed whose last owner this removes is released (membership is retained
precisely so the server knows which those are — it does not re-derive). Removing
an unknown descriptor is a no-op. Re-sending `AddDescriptor` for the same
descriptor string with an advanced `start` **reconciles the slid window
server-side**: scripts that left the window are released (subject to the same
last-owner rule), scripts that entered are added, all-or-nothing on quota — the
client no longer has to `Remove*` the trailing scripts by hand.

**Gap-limit tracking is still a client concern, by design.** Retaining membership
lets the server *manage* a window (slide, remove); it does **not** make the server
track derivation *progress*. An earlier approach had the server follow how far the
client had derived and push a `DescriptorNeedsAddresses` side-channel telling it to
extend the window. We rejected that and it stays rejected: the server never tracks
how far the client has advanced, never decides when to slide, and emits no
unsolicited nudge. The client owns address-generation policy and drives the window
by advancing `start` (or dropping it with `RemoveDescriptor`); the server only
expands, watches, reconciles, and releases. The `DescriptorNeedsAddresses` body
(field 15) is reserved for wire-compat but is never emitted.

### 11.1 Match attribution

A `ScriptMatched` for a descriptor-derived script carries
`descriptor_matches` — the descriptor(s) whose window currently contains that
scripthash, each with the exact `(branch, derivation_index)` the server derived
it at. This saves a descriptor consumer from maintaining its own reverse
`scripthash → descriptor` index (the work it offloaded to the server by sending a
descriptor in the first place): a deposit hit can be routed to the right account
directly. It is empty for a directly-watched (`AddScripts`) script, and carries
more than one entry when the script falls in more than one descriptor's window
(overlap). The server keeps a per-connection reverse index over the retained
membership (§11) to attach it.

`branch` is the 0-based BIP-389 multipath branch (`<0;1>` → external = 0,
change = 1; always 0 for a single-path descriptor) and `derivation_index` is the
absolute index — together the coordinate the server actually derived the script
at, ready to use with **no `gap_limit` arithmetic**. This is correct for every
descriptor shape, including fixed (non-wildcard) and multipath descriptors where
a positional offset could not be reversed. Attribution stays consistent with the
gap-limit-is-a-client-concern principle (§11): it is **reactive** (emitted only on
a match, never an unsolicited "derive more" nudge) and the server still tracks no
derivation *progress* — it reports only where a matched script sits, never
advancing a gap limit on the client's behalf.

### 11.2 Atomic whole-set replace (`SetWatchSet`)

`SetWatchSet` carries the **complete desired watch-set** — scripts (+floors),
outpoints, txid lifecycles, depth alarms, descriptors (+windows), prefixes, and
the category filter — in one message, and asks the server to *become* it:

```protobuf
message SetWatchSet {
  uint32 categories                   = 1;  // 0 = all
  repeated bytes scripthashes         = 2;
  repeated uint64 min_values          = 3;  // parallel to scripthashes (empty = no floors)
  repeated Outpoint outpoints         = 4;
  repeated AddDescriptor descriptors  = 5;  // expanded over each window, as AddDescriptor
  repeated ScriptPrefix prefixes      = 6;
  repeated WatchLifecycle lifecycles  = 7;  // { txid, auto_close_depth }
  repeated WatchDepthAlarm depth_alarms = 8; // { txid, depth }
}
```

The server reconciles it **under the watch-set lock, by effective scripthash
coverage** (descriptors expanded): items in both the old and new set keep their
registration and quota lease untouched — including a scripthash whose *mechanism*
changes across the replace (a direct add becoming descriptor-covered, or vice
versa), which a client-side `Add*`/`Remove*` diff cannot see and would briefly
unwatch. Departed items are released; net-new items are charged. The replace is
**all-or-nothing on the whole target** for three independent reasons:

- **Quota** — if the target's total unit cost exceeds the principal's quota the
  watch-set is left **unchanged** (`reason = QUOTA_EXCEEDED`, `required` = units
  needed, `quota` = the unit ceiling).
- **Entry cap** — the replace is bounded by the same per-connection watch-set
  **entry** cap as the incremental adds on that carrier (WebSocket
  `streamwsmaxsubscriptions`; a prefix counts as one entry). A target with more
  entries than the cap is refused whole (`reason = CAP_EXCEEDED`, `required` =
  entry count, `quota` = the cap). This bound applies even to a **loopback/no-auth
  connection**, which has no quota — so one `SetWatchSet` frame can never install
  more than the cap. (gRPC entry-caps neither its incremental adds nor a replace;
  quota is its bound.)
- **Malformed input** — because a `SetWatchSet` is a *full snapshot*, any element
  the server cannot parse or expand (a bad scripthash, outpoint, txid, descriptor,
  or prefix — or a `min_values` length that does not match `scripthashes`) refuses
  the **whole** snapshot (`reason = MALFORMED`, `required`/`quota` = 0) and leaves
  the live set unchanged. It is *not* silently dropped — dropping one item would
  shrink the snapshot and unwatch still-wanted scripts while reporting success.
  (This is the one place the incremental `Add*` paths differ: those are
  best-effort and skip an unparseable item, since they only *grow* the set.)

Unlike the incremental adds, a replace does **not** charge the per-add rate
limiter: it is the watch-set re-establishment primitive (reconnect / SDK reload),
and rate-limiting it would let a reconnect storm block clients from restoring
their watches. Steady-state size stays bounded by quota and the entry cap above.

The outcome is deterministic and in-band (mirrors `SetCursorResult`):

```protobuf
message WatchSetResult {
  oneof outcome { WatchSetAccepted accepted = 1; WatchSetRejected rejected = 2; }
}
message WatchSetAccepted { uint32 added = 1; uint32 removed = 2; uint32 unchanged = 3; }
message WatchSetRejected {
  enum Reason { REASON_UNSPECIFIED = 0; QUOTA_EXCEEDED = 1; MALFORMED = 2; CAP_EXCEEDED = 3; }
  Reason reason = 1; uint64 required = 2; uint64 quota = 3;
}
```

This is the primitive an SDK reload/realign uses: one round-trip, gap-free,
quota-correct even for a same-size swap at exactly the quota ceiling — never a
client-computed delta whose ordering can strand coverage (send `Remove*` first
and an at-quota client is briefly unwatched; send `Add*` first and the over-quota
adds are silently dropped). On WebSocket the same operation is
`{"type":"set_watch_set", ...}` and the result a `{"category":"watch_set_result",
"outcome":"accepted"|"rejected", ...}` event.

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

### 12.1 Mempool spend-side prevout retention

The matcher's **mempool** spend-side path (§7.2, §7.5) needs prevout data the
spending input does not carry. Whatever it needs must be captured at admission —
`prev_outputs` is resolved for validation and then dropped, so there is no
off-hot-path way to recover it later. `streamprevoutmeta` tunes how much is kept
per mempool input, trading memory for matcher capability:

| Value | Per-input cost | Enables |
|---|---|---|
| `hash` | scripthash only (32 B) | exact-script + prefix **bucket** matching; client resolves outpoints itself |
| `amount` *(default)* | + prevout value (8 B) | a mempool-input `min_value` floor on spend-side script matches |
| `full` | + full prevout `scriptPubKey` (variable, one heap allocation) | a chainstate-less client confirming a mempool prefix spend without resolving any outpoint |

Retention is paid for **every** mempool entry regardless of subscribers (it
happens at admission), so the default is the cheapest tier that makes `min_value`
work out of the box; `full` is opt-in because it both costs the most and widens
the data the node holds in memory. Unlike the §12 caps this is a live-reloadable
mempool-policy key (SIGHUP): a change governs subsequent admissions, while entries
already pooled keep whatever they were admitted with (mempool matching is
best-effort by contract, §6.2). The confirmed-block spend side is unaffected — it
always recovers full script and value from undo data (§7.2).

**Memory accounting.** Retained prevout metadata is held *alongside* each mempool
entry and is **not** counted against `maxmempool` (which bounds only serialized
transaction weight). Budget for it separately. The worst case is bounded by the
mempool's input count: roughly `entries × inputs_per_entry × per_input_cost`,
where `per_input_cost` is 32 B (`hash`), 40 B (`amount`), or 32 B + the prevout
script length (`full`, typically ~34 B for witness outputs, but attacker-
influenceable up to the standardness script-size limit). For a full default-size
mempool this is sub-1% of the mempool's own footprint under `hash`/`amount`; under
`full` size it as `maxmempool` plus that per-input script overhead, and prefer a
lower tier on memory-constrained nodes that do not need chainstate-less spend
confirmation.

## 13. Open questions

These are genuine open design points, deferred until a real consumer's feedback can
settle them ahead of any `v1` freeze:

- **Anchor consumer.** Which downstream integrator co-designs the surface before a
  `v1` freeze. The wire shapes here are a working contract, not yet a commitment.
- **Stability commitment.** When to freeze the wire surface as a committed `v1` for
  satd consumers. This API is a deliberate satd differentiator — a native,
  in-process consensus stream (first-class reorgs, cursor-resumable matches, mempool
  coverage) that an out-of-process sidecar over Core's ZMQ structurally cannot match
  (§8). The goal is a stable *satd* contract that pulls integrators onto the node
  itself, not a lowest-common-denominator cross-node specification that would
  commoditize the advantage away. Any broader standardization is a downstream
  governance question, explicitly not a design goal for this surface.
- **Cursor opacity.** Whether to keep `(height, tx_index, mempool_seq,
  instance_id)` as structured, debuggable fields (current design) or move to an
  opaque token that is future-proof against cursor-format changes.
- **Descriptor expansion bounds.** The right max gap-limit / max derived watch-set
  per token, and how it composes with the §9 per-item quota.
- **Prefix-watch granularity (§7.5).** Whether to expose `bits` as a free range
  within `[streamprefixminbits, streamprefixmaxbits]` (current design) or a small
  fixed *menu* of allowed lengths — the menu makes buckets uniform across clients
  (so the choice of `k` is not itself a fingerprint) at the cost of client
  flexibility. Also: whether mempool spend-side matching (which costs one retained
  scripthash per mempool-entry input) is worth its memory on nodes with no prefix
  subscribers, or should be gated behind a "prefix subscriptions enabled" flag.

---

*Cross-reference: [`ROADMAP.md`](../../ROADMAP.md) (strategic framing),
[Esplora REST API](../manual/src/esplora.md) (the surface this consolidates beyond),
[`CHANGELOG.md`](../../CHANGELOG.md) (user-facing summary).*
