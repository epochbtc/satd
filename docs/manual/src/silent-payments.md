# Silent Payments (BIP 352)

A [BIP 352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
silent-payment address (`sp1…`) is a reusable, static address that produces a
unique, unlinkable taproot output on chain for every payment it receives.
Nothing on chain connects two payments to the same address, and nothing
identifies an output as a silent payment at all. The cost of that privacy falls
on the receiver: finding your own payments means running an ECDH computation
against candidate transactions, because there is no address string to look up.

satd implements the receive side: a tweak index, a streaming tweak firehose
with cursor replay, mempool-time detection, and an optional server-side
scan-key matcher, with typed support in both SDKs. The matching kernel is
tested for parity against the BIP 352 reference vectors. Everything is opt-in;
a node that enables none of it behaves exactly as before.

This chapter is the integrator guide: what each consumption mode gives you, how
to pick one, and how to operate the index behind them. The wire-level contract
lives in the
[streaming API specification](https://github.com/epochbtc/satd/blob/master/docs/api/streaming.md)
(§7.7).

## In the node, not beside it

Silent-payment support follows the same one-process, one-store model as satd's
Electrum and Esplora surfaces: the tweak index is written inside block
connection, atomically with the chainstate, and the serving and matching layers
read it in-process from the same RocksDB store the node validates against.
There is no companion indexer to keep in sync and no window where an external
index's view lags the node across a reorg — rows are removed in the same batch
that disconnects the block, and tweak events carry the block's own hash so a
client re-anchors from the `(block_hash, height)` it already holds.

For context: Bitcoin Core has no silent-payment support in any released
version as of this writing (August 2026), so receiving against a stock node
means running a separate tweak-indexing daemon and serving layer beside it,
each with its own sync state and reorg handling. satd's index produces the
same per-block public tweak data such stacks do, served over the streaming API
and a JSON-RPC method instead of a sidecar's own protocol.

The trade-off, as with every satd index, is local disk — measured in
[Disk Footprint & Indices](disk-footprint.md).

## Choosing a tier

Three consumption modes ride on the streaming surface. They differ in who runs
the ECDH scan, and therefore in who ever sees your scan key.

| | Tier 1 — client-side scan | Tier 1.5 — mempool tweaks | Tier 2 — scan-key watch |
|---|---|---|---|
| Who computes | your wallet | your wallet | the node |
| Scan key leaves the device | never | never | disclosed to the node |
| Requires `silentpaymentindex=1` | yes | yes | no (accelerates rescan only) |
| Detection latency | block | mempool admission | mempool admission |
| History / cold-sync | unclamped cursor replay | none (best-effort, live only) | `RescanBlocks` |
| Transport | gRPC `Subscribe` | gRPC `Subscribe` | gRPC `Watch` (mirrored on WebSocket) |
| Typical consumer | wallets, batch scanners | payment-notification clients | thin clients, phones |

**Tier 1 is the recommended, zero-custody mode.** The node streams each block's
public tweak data (`BlockTweaks`, category bit 8 — explicitly requested, never
part of the `categories = 0` default); the wallet runs one ECDH per tweak
locally. The scan key never leaves the device, and the node learns nothing
about which outputs are yours. Because every stored row embeds the hash of the
block it describes, tweaks-only replay is exempt from the usual
`MAX_REPLAY_BLOCKS` clamp: a fresh wallet cold-syncs the entire taproot era in
one `from_cursor` subscription, paged and backpressured server-side.

**Tier 1.5 is Tier 1 at mempool latency.** Setting `mempool_tweaks = true`
alongside bit 8 additionally delivers a `MempoolTweak` at each eligible
transaction's admission — the same 33-byte tweak its later `BlockTweaks` entry
will carry, plus the transaction's taproot outputs so a match is confirmed
in-band without a `getrawtransaction` race. It is best-effort like the mempool
itself: no durable cursor, no replay, no retraction on RBF (dedup by `txid`;
the confirmed record at connect stays authoritative). A payment missed while
offline is simply caught at confirmation.

**Tier 2 moves the scan to the node.** Register up to 16
`(scan_secret, spend_pubkey)` targets per connection and the node emits a
`SilentPaymentMatched` for every output paying you — at mempool admission with
`confirmed = false`, then again at confirmation with `confirmed = true` and a
resume cursor. Each match carries the transaction's public tweak `T` and output
counter `k`, which is exactly enough for the wallet to re-derive the output's
full spending key offline from its own `b_scan` and `b_spend`. This mode works
on any satd node: matching recomputes from the block and its undo data with the
same kernel the index uses, so it needs no `silentpaymentindex` and costs the
node nothing while no target is registered.

The trust trade is explicit: a scan key lets the node — and anyone who
compromises it — learn *which* outputs are yours. It is not a spending key;
`b_spend`'s private half never leaves the client, so no one else can ever spend
them. The node treats the secret accordingly: scan secrets live in memory for
the connection's lifetime only, wrapped in a zeroize-on-drop buffer, never
written to disk, a cursor, a status RPC, or a log line. Both SDKs refuse to
send one over a plaintext transport that carries a bearer token, and a routable
events bind requires auth or mTLS like every other watch kind. Pointing a thin
client at *your own* node keeps the disclosure inside your trust boundary;
pointing it at someone else's node is a choice to extend that boundary to them.

## The tweak index

Tier 1 and 1.5 serve from the `sp_tweaks` index: one row per block from taproot
activation upward (height 709,632 on mainnet — earlier blocks cannot carry
silent payments), holding the public tweak `T = input_hash · A` for every
eligible transaction. Rows are written inside block connection, removed on
disconnect, and rebuilt by `-reindex-chainstate`. A row is present even for a
block with no eligible transactions, so row presence distinguishes "indexed,
none" from "not indexed", and every row embeds its block's hash, so readers
authenticate it without trusting the height-to-hash index.

Enable it with:

```ini
# bitcoin.conf — default off, restart to change
silentpaymentindex=1
```

A node that syncs from genesis with the flag set builds the index inline. To
add it to an existing datadir, run the deferred backfill:

```sh
sat-cli backfillindex silentpayment
```

The backfill walks from taproot activation to the snapshot height pinned at
start, resumes across daemon restarts, and answers to the generic index
controls (`pauseindex` / `resumeindex` / `cancelindex silentpayment`). It
refuses to start with less than 6 GiB of free disk. Progress is visible three
ways, all reporting the same walk-relative ratio:

- `getindexinfo` → the `silentpayments` section: `enabled`, `synced`, and a
  `backfill` object with `state`, `cursor_height`, `snapshot_height`,
  `progress_ratio`, and `estimated_remaining_seconds`. Use the reported
  `progress_ratio`, not `cursor_height / snapshot_height` — the latter measures
  from genesis and overstates a mainnet backfill from its first block.
- [`sat-tui`](tui.md) → the services row's `sp-idx` column.
- Prometheus → the `satd_spindex_*` family; see
  [Observability & Metrics](observability.md).

Until the backfill completes, the tweak-serving surfaces refuse rather than
return a partial result: a `from_cursor` tweak replay is rejected in-band so a
light client can never silently miss payments below the backfill frontier.

What it costs, measured on a synced mainnet node (August 2026): **~13 GB** for
the full taproot era, growing **~1 GB/year** at the recent eligible-transaction
rate, with a mainnet backfill taking **6 h 46 m**. The full accounting,
including the estimator's stint semantics and the row format, is in
[Disk Footprint & Indices](disk-footprint.md).

## Serving tweaks (Tier 1 on the wire)

With the index enabled and synced, a gRPC `Subscribe` with category bit 8
streams one `BlockTweaks` per connected block, shaped by four per-subscription
knobs:

- `tweak_dust_limit` — drop entries whose largest eligible output is below the
  floor (in sats). At 546 sat this trims roughly 10% of mainnet entries.
- `tweaks_only` — strip `txid` and `max_value`, leaving the 33-byte tweak
  alone: the leanest form for bulk cold-sync.
- `mempool_tweaks` — additionally stream `MempoolTweak` at admission
  (Tier 1.5).
- `tweak_outputs` — include each entry's taproot outputs, re-derived at serve
  time, so matches confirm in-band. Off by default because it makes replay read
  each block; `MempoolTweak` always carries its outputs regardless.

The firehose serves on gRPC only in this release — the WebSocket/SSE transports
do not carry the tweaks category. For scripts and integrators not on an SDK,
`getsilentpaymentblockdata "blockhash" ( verbosity dust_limit )` returns the
same per-block bytes over JSON-RPC; see
[JSON-RPC Extensions](json-rpc-extensions.md).

## Walkthrough: a zero-custody light wallet (Tier 1)

The shipped SDK examples are the reference implementations —
[`sp_light_scan.rs`](https://github.com/epochbtc/satd/blob/master/satd-events-client/examples/sp_light_scan.rs)
(Rust) and
[`sp_light_scan`](https://github.com/epochbtc/satd/blob/master/clients/go/examples/sp_light_scan)
(Go) — each a complete scanner in one file: subscribe, ECDH, label handling,
in-band output confirmation, and a restart-durable resume cursor. The shape, in
Rust:

```rust,ignore
let opts = SubscribeOptions {
    categories: Categories::TWEAKS,   // bit 8 — never implied by "all"
    mempool_tweaks: true,             // Tier 1.5: detect at admission
    tweak_outputs: true,              // confirm matches in-band
    // Cold-start anchor, used only when the cursor file is empty. A cursor
    // names the last height already done, so `activation - 1` scans the
    // activation block itself.
    from_cursor: Some(Cursor { height: 709_631, ..Default::default() }),
    ..Default::default()
};
let mut sub = client.resilient_subscribe(
    opts,
    ResilientConfig::new().cursor_store(Arc::new(FileCursorStore::new(path))),
);
loop {
    // Propagate, never `while let Ok(..)`: `next()` returns `Err` on every
    // PERMANENT failure — a corrupt cursor file, a rejected subscribe (an index
    // still backfilling answers `FAILED_PRECONDITION`), retries exhausted.
    // Swallowing that exits the loop silently and the wallet reports a zero
    // balance it never actually scanned for.
    let event = sub.next().await?;
    // scan, then poll again — the next poll commits this event's cursor
}
```

For each `TweakEntry`, the wallet computes locally, per BIP 352:

```text
ecdh  = b_scan · T                                  // one point multiply per entry
t_k   = hash("BIP0352/SharedSecret", ecdh ‖ k)      // k = 0, 1, … per candidate output
P_k   = B_spend + t_k · G                           // expected output key
```

and compares `P_k`'s x-only form against the transaction's taproot outputs —
carried in the event itself under `tweak_outputs`, so no follow-up RPC is
needed. A payment to a labeled address (BIP 352 §5) shifts `P_k` by the label
tweak; scan with each of your labels, and include label `0` even if you issue
none, because label `0` is how your own change comes back. On a match, the
spending key is `b_spend + t_k` (plus the label tweak if any) — derived
entirely on the device.

Cold-sync is the same subscription with a `from_cursor` at taproot activation;
the replay is unclamped, index-backed, and ends in-band on any storage error
rather than skipping a height.

The resume anchor to persist is the cursor of the last event you have **finished
scanning**, not the last one delivered — a cursor written ahead of the work it
stands for turns a crash into a silently skipped block, and for a scanner a
skipped block is a missed payment. Both SDKs get this right for you: a
`ResilientSubscription` with a `CursorStore` commits **on poll**, writing an
event's cursor only when you come back for the next one, so an interrupted scan
replays its last block instead of stepping over it. Use that rather than
hand-rolling persistence around the raw stream; both reference examples do
([`sp_light_scan.rs`](https://github.com/epochbtc/satd/blob/master/satd-events-client/examples/sp_light_scan.rs),
[`sp_light_scan`](https://github.com/epochbtc/satd/blob/master/clients/go/examples/sp_light_scan)).
The mirror-image slip — persisting the *previous* event's cursor — costs only a
repeated scan, and has shipped in a production wallet
([cake_wallet#3574](https://github.com/cake-tech/cake_wallet/issues/3574)).

## Walkthrough: a thin client with a registered scan key (Tier 2)

The reference implementations are
[`sp_wallet.rs`](https://github.com/epochbtc/satd/blob/master/satd-events-client/examples/sp_wallet.rs)
and
[`sp_wallet`](https://github.com/epochbtc/satd/blob/master/clients/go/examples/sp_wallet).
The shape, in Go:

```go
target := satdevents.SilentPaymentTarget{
    ScanSecret:  bScan,          // disclosed to the node: a watch credential, not a spend key
    SpendPubkey: spendPubkey,    // public half only; b_spend never leaves the client
    Labels:      []uint32{0},    // label 0 catches your own change
}
handle.AddSilentPayments(ctx, []satdevents.SilentPaymentTarget{target})
```

From here the node does the scanning. Each `SilentPaymentMatched` arrives twice
— once at mempool admission (`confirmed = false`, best-effort) and once at
confirmation (`confirmed = true`, with a resume cursor) — and carries the
output key and value plus the public tweak `T` and counter `k`, from which the
client re-derives the full spending key offline exactly as in Tier 1. Targets
are removed by their identity `b_scan · G`, which the client derives locally;
each target costs one watch-quota unit.

A fresh wallet cold-syncs by registering its targets and issuing a
`RescanBlocks` over the taproot-activation-to-tip window. The rescan produces
exactly the matches the live path would have; on a node whose tweak index is
enabled and complete it also runs faster, reading each block's tweaks from the
index (verified per block against the stored row's embedded hash) instead of
recomputing them. The index changes rescan speed, never results.

Both SDKs' `ResilientWatch` re-registers scan-key targets automatically on
reconnect, so a dropped connection never silently stops the watch; see the
[Rust SDK](rust-sdk.md) and [Go SDK](go-sdk.md) chapters for the
reconnect-and-resume contract and the TLS posture around scan secrets.
