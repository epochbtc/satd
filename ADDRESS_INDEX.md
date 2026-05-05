# Address-history index — design

Locked design for the address-history index that backs satd's native Electrum and Esplora subsystems (per `ECOSYSTEM.md` §4 / §4a). The index is the load-bearing prerequisite for both protocols and for any future Silent Payments work.

**Status (2026-05): shipped.** The full live-index path (M1–M6) and the deferred-backfill machinery (M7) have landed. Lookup paths live in `node-index/`, the connect/disconnect-block integration in `node/src/index/address/`, and the deferred backfill in `node/src/index/address/backfill.rs` + `runner.rs`. The Esplora REST server (`esplora-handlers`) and Electrum protocol server (`electrum-proto`) ride on top via the `AddressIndex` and `SpendIndex` traits.

This document is the spec. Where the implementation deviated, the section calls it out.

---

## Goals

- Look up confirmed transaction history for a `scriptPubKey` (`scripthash` keyed) — funding outputs and spending inputs, in height-order.
- Look up unconfirmed (mempool) history for the same scripthash.
- Compute current confirmed balance, mempool delta, and live UTXO set per scripthash.
- Support subscription / notification for scripthash status changes (Electrum protocol requires it).
- All of the above with **atomic reorg consistency** vs. the chainstate — no window where a protocol handler can observe an index out of sync with the tip.
- Single RocksDB instance shared with chainstate. No separate process, no IPC, no parallel block re-scanning.

## Non-goals

- Not a full transaction-by-txid lookup. `tx_index` already exists for that (CF `tx_index`, see `node/src/storage/rocksdb_store.rs:19`).
- Not a balance accumulator (precomputed running totals per scripthash). Balance is computed on demand from the index. Accumulators add reorg-undo complexity for marginal lookup speedup; revisit if benchmarks justify it.
- Not a Silent Payments index. SP rides on the same scan-every-output infrastructure but stores ECDH-tweak keys, not scripthashes. Future, separate CF, sibling design doc.
- Not multi-process. The index lives in satd's RocksDB; future companion binaries (`sat-electrum`, `sat-esplora` per `ECOSYSTEM.md` §4) open the datadir in RocksDB secondary mode, not write to it.

## Decisions

| Question | Decision |
|---|---|
| Scripthash key width | Full 32 bytes (no truncation, no resolution CF) |
| Default behavior when feature compiled in | On by default; opt out via `-noindex=address` |
| IBD strategy | Index during IBD; no separate backfill phase |
| Shadow validation | Skip — vendored upstream protocol code makes equivalence the test |
| Storage process | Same RocksDB instance, same `WriteBatch` as `connect_block` / `disconnect_block` |
| Mempool variant | In-memory parallel index, separate from on-disk |

---

## Schema

### Scripthash

`scripthash = sha256(scriptPubKey)` — full 32 bytes, big-endian throughout. Matches the modern Electrum protocol convention. We do not implement the legacy `hash160` variant.

### Column families

Two new CFs, added to the existing six in `node/src/storage/rocksdb_store.rs:15-20`:

```
addr_funding   key: scripthash[32] || height_be[4] || txid[32] || vout_be[4]    (72 bytes)
               value: amount_sat_be[8]                                          (8 bytes)

addr_spending  key: scripthash[32] || height_be[4] || txid[32] || vin_be[4]     (72 bytes)
               value: prev_outpoint_txid[32] || prev_outpoint_vout_be[4]        (36 bytes)
```

CF naming follows the existing convention (`block_index`, `coins`, `tx_index`, …). Constants `CF_ADDR_FUNDING` and `CF_ADDR_SPENDING` are added alongside the others.

### Why this layout

- **Prefix scan over `scripthash[32]`** — the dominant query pattern. Sorted iteration is RocksDB-native; bloom filters and the block cache work as expected.
- **`height_be` next** so iteration returns history in height-order without a sort step. Same for mempool variant (synthetic `height = u32::MAX`).
- **Self-describing keys** — full txid in the key means no collision-resolution CF, no `addr_txids` row, and a delete path that needs no auxiliary lookup.
- **`addr_funding` value carries amount** so `balance(scripthash)` is a single CF iteration, not a join with the UTXO set.
- **`addr_spending` value carries `prev_outpoint`** so we can resolve "what funding entry does this row spend" without re-reading the tx body.

### Why two CFs and not one

Two CFs lets us iterate just-funding or just-spending rows independently. Electrum's `blockchain.scripthash.get_balance` wants funding sums; the merged view is computed by the protocol layer, not by RocksDB. Single-CF with a `kind` byte is also workable but loses the iteration-discrimination property and complicates compaction tuning.

### Disk overhead

| Source | Approx size at mainnet tip (~Apr 2026, ~945k blocks) |
|---|---|
| Funding rows | ~1.4B × 80 B ≈ 110 GB |
| Spending rows | ~1.4B × 108 B ≈ 150 GB |
| **Total raw** | **~260 GB** |
| After RocksDB compression (LZ4 / Zstd) | ~120-180 GB estimated |

Substantially larger than electrs's ~50-80 GB (electrs uses 8-byte truncated scripthash + 4-byte truncated txid). The simplification trade.

Pi 5 implication: a 1 TB SSD comfortably holds chain (~700 GB) + address index (~150 GB). 512 GB is tight and operators should consider `-noindex=address`.

---

## Integration with `connect_block` / `disconnect_block`

### `StoreBatch` extension

Two new fields in `StoreBatch` (`node/src/storage/mod.rs:27`):

```rust
pub struct StoreBatch {
    // ... existing fields ...
    pub addr_funding_puts: Vec<AddrFundingRow>,
    pub addr_spending_puts: Vec<AddrSpendingRow>,
    pub addr_funding_removes: Vec<AddrFundingKey>,    // for disconnect
    pub addr_spending_removes: Vec<AddrSpendingKey>,  // for disconnect
}
```

`StoreBatch::merge` extends to merge them. `RocksDBStore::write_batch` writes them to their CFs in the same `rocksdb::WriteBatch` as the existing fields, preserving the atomic-per-block-connection guarantee.

### `connect_block` integration

`connect_block` (`node/src/chain/connect.rs:145`) already iterates every output and every input. Two integration points:

```rust
// at the per-output emit-coin point (after the existing batch.coin_puts.push):
if address_index_enabled {
    let scripthash = sha256(&txout.script_pubkey);
    batch.addr_funding_puts.push(AddrFundingRow {
        scripthash,
        height,
        txid,
        vout,
        amount_sat: txout.value.to_sat(),
    });
}

// at the per-input spend-coin point (after the existing batch.coin_removes.push):
if address_index_enabled {
    let prev_coin = /* already resolved for spend-check */;
    let scripthash = sha256(&prev_coin.txout.script_pubkey);
    batch.addr_spending_puts.push(AddrSpendingRow {
        scripthash,
        height,
        txid,
        vin,
        prev_outpoint: input.previous_output,
    });
}
```

Both points already have the `script_pubkey` in hand — output trivially, input via the already-resolved `prev_coin` for the existing spend-check. **No additional disk reads.** The cost is the per-row hash and the batch grow.

### `disconnect_block` integration

`disconnect_block` (`node/src/chain/disconnect.rs`) reads the block's `UndoData` and reverses each spend / output. Same shape:

- For each restored output: emit `addr_funding_removes` for its key.
- For each removed coinbase / non-coinbase output: same.
- For each "un-spend" from undo data: emit `addr_spending_removes`.

Because the keys carry full `(scripthash, height, txid, vout/vin)`, each remove is point-deterministic. No range deletes, no scan-then-delete.

### `WriteMode::BulkLoad` interaction

The existing `WriteMode::BulkLoad` (`node/src/storage/mod.rs:65`) disables the WAL during IBD for a 20-50% write-I/O reduction. The address-index CFs honor the same mode — they're just additional rows in the same `rocksdb::WriteBatch`. No special handling.

`Store::flush()` already exists to bound replay work in BulkLoad mode; it flushes all CFs.

---

## IBD strategy

### Index during IBD, default-on, opt-out flag

When `electrum` or `esplora` features are compiled in, the address index is built incrementally during IBD by the existing `connect_block` flow. By tip, the index is at the tip.

The opt-out flag is `-noindex=address` (Bitcoin-Core-compatible negation syntax; mirrors `-noprune`). When set:

- `connect_block` skips the per-output / per-input scripthash work.
- The `addr_funding` and `addr_spending` CFs remain present but empty.
- Electrum / Esplora endpoints return an explicit error (`"address index disabled on this node"`) rather than empty results.

### IBD overhead estimate

Per-block work added: ~`(num_outputs + num_inputs) × sha256` plus the batch entries. At typical mainnet block density (~3000 inputs+outputs), that's ~3000 SHA-256 hashes per block. Negligible CPU cost (~1ms on Pi 5) vs. ~50-200ms script verification per block.

The disk-write overhead is the dominant cost — roughly +30-60% bytes-per-block written. Expected IBD wall-time impact on Pi 5: 10-25%. Will benchmark before declaring victory.

### No separate backfill phase as default

Rejected as the default path: Bitcoin Core's `-reindex-chainstate` pattern where index becomes available only after a long post-IBD walk. Reasons:
- Doubles wall-clock time before protocols become useful.
- Requires re-reading every block from flat files — IO-heavy on Pi.
- Adds a "backfill in progress" state to operate / monitor.
- Index-during-IBD pays the cost once, in the same pass as block validation.

The one place backfill **does** matter is AssumeUTXO bootstrap, where pre-snapshot history is missing by construction. That case is handled by an opt-in deferred backfill — see [Deferred backfill (AssumeUTXO mitigation)](#deferred-backfill-assumeutxo-mitigation) below.

---

## Mempool variant

### In-memory, separate from on-disk

The mempool address index lives in RAM, not RocksDB. It's volatile and rapidly mutated; persisting it would be pure cost.

```rust
struct MempoolAddrIndex {
    by_scripthash: HashMap<[u8; 32], HashSet<Txid>>,
    by_txid: HashMap<Txid, Vec<[u8; 32]>>,  // for O(1) eviction
}
```

### Updates

- **`add_tx(tx)`**: hash every output's `scriptPubKey`, hash every input's previous output's `scriptPubKey` (already resolved during mempool acceptance), insert into both maps.
- **`remove_tx(txid)`**: look up `by_txid`, remove this txid from each scripthash's set, remove the `by_txid` entry.
- **RBF replacement**: `remove_tx(old)` + `add_tx(new)`, ordered.
- **Block confirmation**: `remove_tx(txid)` for each txid in the connected block. The on-disk `connect_block` integration writes the confirmed entries; the mempool index sheds them in lock-step.
- **Reorg disconnection**: `add_tx(txid)` for each tx whose block was disconnected back into the mempool. Confirmed entries vanish from disk via `disconnect_block`'s remove path.

### Memory cost

Bounded by `maxmempool` (default 300 MB). Index overhead ≈ scripthash count × (32 + small set). Empirically ~10-15% of mempool size in RAM. For default settings, ~30-45 MB. Acceptable.

---

## Deferred backfill (AssumeUTXO mitigation)

AssumeUTXO bootstrap (`-assumeutxo=<height>`) skips IBD validation up to the snapshot height. The index-during-IBD strategy populates rows only for blocks the node validates — so a node that bootstrapped via AssumeUTXO has an index that covers heights `> snapshot_height` and a hole below it. Wallets scanning from a pre-snapshot birthday see incomplete history.

The v1 mitigation: an **opt-in deferred backfill** that the operator triggers when convenient. The node remains usable with partial history during the backfill, which runs in background as a tokio task. This is the standard pattern (Bitcoin Core uses it for `tx_index` and `blockfilter_index`).

### Trigger model

- **Startup flag**: `-backfillindex=address` — starts the backfill on next launch. Compatible with Bitcoin Core's `-reindex` / `-reindex-chainstate` style.
- **Runtime RPC**: `backfillindex "address"` — starts the backfill in background; returns immediately.
- **Idempotent**: triggering while a backfill is already running is a no-op.

### The technical challenge: resolving spent prev_outputs

`addr_funding` rows are easy — every output's scriptPubKey is in its own block. `addr_spending` rows are hard: each input's spent scriptPubKey lives in an *earlier* block, and AssumeUTXO didn't leave us a historical UTXO state to consult.

**Approach: two-pass walk with a temporary CF.**

```
Pass 1 (genesis → snapshot_height):
  for each block:
    for each tx, for each output:
      write addr_funding row
      write to temp CF: outpoint(txid, vout) → scripthash

Pass 2 (genesis → snapshot_height):
  for each block:
    for each tx, for each non-coinbase input:
      lookup scripthash in temp CF using input.previous_output
      write addr_spending row
  drop temp CF
```

Sequential reads + sequential writes per pass. RocksDB-friendly, no random IO into flat files.

### Cost estimate

- **Disk**: temp CF holds ~1.4B entries × ~40 B ≈ 56 GB during backfill, freed at end. Combined peak on a Pi 5: chain (~700 GB) + index (~150 GB) + temp (~56 GB) ≈ 906 GB. 1 TB SSD is workable; 512 GB requires the operator to wait until they've expanded storage.
- **Time**: ~2× a normal IBD walk (two passes). Pi 5 from cold disk cache: 1.5-3 days. With existing prefetch + parallel hashing infrastructure, likely closer to 1.5.
- **CPU / IO during backfill**: bounded — runs at lower priority than live block processing. Operators can `pauseindex address` if they need bandwidth.

### Concurrency with live chain

Disjoint write ranges, no conflict:
- Backfill writes only to `addr_funding` / `addr_spending` rows at heights ≤ snapshot.
- Live `connect_block` writes to those CFs at heights > current_tip (always > snapshot since we're past it).
- RocksDB MVCC handles concurrent readers; protocol handlers querying during backfill see whatever rows exist and learn from `getindexinfo` that the index is incomplete.

### Resumability + crash safety

- Per-pass cursor in `metadata` CF: `addrindex.backfill.pass`, `addrindex.backfill.cursor_height`.
- Each batch of K blocks (e.g. K=1000) writes its rows + advances the cursor in a single `WriteBatch`. WAL ensures atomicity.
- On restart: read cursor, resume. If pass=1 was complete and pass=2 hadn't started, advance to pass=2.
- On crash mid-batch: WAL replay rewinds to the last committed cursor; worst-case re-do K blocks of work.

### Status reporting

Mirror Bitcoin Core's `getindexinfo` shape:

```json
{
  "address": {
    "synced": false,
    "best_block_height": 945123,
    "backfill": {
      "active": true,
      "pass": 1,
      "cursor_height": 412567,
      "snapshot_height": 945000,
      "estimated_remaining_seconds": 86400
    }
  }
}
```

Estimate from blocks-per-minute over a sliding window. Logged hourly to journal so operators can see progress in `journalctl`.

### Pause / resume / cancel

- `pauseindex "address"` — sets a flag the backfill polls between batches; flushes cursor; exits cleanly.
- `resumeindex "address"` — re-launches from cursor.
- `cancelindex "address"` — pauses + drops temp CF + clears cursor. Backfill state gone; user re-triggers from scratch later.

Useful ops scenarios: "I need IO bandwidth, pause" / "I'm low on disk, cancel and reschedule when I've added storage."

### Operator user story

For the AssumeUTXO operator path:

1. Run satd with `-assumeutxo=N`. IBD completes in hours instead of days.
2. Address index covers heights `> N` only. Electrum / Esplora endpoints work for recent activity. Wallets with post-N birthdays sync fully; wallets with earlier birthdays get a clear "history incomplete below height N" signal from `getindexinfo`.
3. When ready, run `backfillindex address`. Takes ~1.5-3 days on a Pi 5. During that time the node serves correctly with partial history.
4. On completion, `getindexinfo` reports `synced: true` and full pre-N history is available.

This is honest, opt-in, and doesn't gate node usability behind a multi-day operation.

### Future: targeted backfill

A separate flavor — `backfillindex "address" --scripthashes=<file>` — that walks blocks once but only writes rows for scripts in a watch set. ~10-100× faster for users who know their addresses upfront (most wallets do, via xpub derivation). Deferred to v1.x: makes "point my new wallet at this node, scan from birthday" a one-shot operation rather than a multi-day rebuild.

---

## Trait surface

What `electrum-proto` and `esplora-handlers` need from `node-index`:

```rust
pub trait AddressIndex: Send + Sync {
    /// Confirmed history in height-ascending order.
    fn confirmed_history(&self, scripthash: &[u8; 32]) -> Result<Vec<HistoryEntry>>;

    /// Mempool history (unordered; protocol layer sorts as needed).
    fn mempool_history(&self, scripthash: &[u8; 32]) -> Vec<MempoolHistoryEntry>;

    /// (confirmed_balance, mempool_delta) where mempool_delta is signed.
    fn balance(&self, scripthash: &[u8; 32]) -> Result<(u64, i64)>;

    /// Current UTXO set for this scripthash. Computed by joining
    /// addr_funding rows against the live UTXO `coins` CF.
    fn utxos(&self, scripthash: &[u8; 32]) -> Result<Vec<Utxo>>;

    /// Subscribe to status changes. Returns a tokio broadcast receiver.
    /// Status = sha256 of the concatenated history-as-string per Electrum spec.
    fn subscribe(&self, scripthash: [u8; 32]) -> broadcast::Receiver<StatusUpdate>;
}
```

The trait is small enough that vendored Electrum protocol code (per `ECOSYSTEM.md` §4a) can be adapted to call it with mechanical edits.

### Subscription / notification model

`tokio::sync::broadcast` channel per subscribed scripthash, lazily created. Producer side: a single notifier task receives `BlockConnected` / `BlockDisconnected` / `MempoolDelta` events from the chain + mempool, computes affected scripthashes from the event payload, and fans out `StatusUpdate` messages.

Capacity bounds matter:
- Per-channel buffer: 32 messages (configurable). Slow consumers see `RecvError::Lagged` and resync via fresh `confirmed_history` query.
- Max active subscriptions: bounded by `-electrumsubscriptions=N` (default 10000). Mobile wallets typically subscribe to ~20-200 scripthashes; cap is generous but finite.

Memory cost: a subscription is essentially a `HashMap` entry + a broadcast `Sender`. ~200 B × N. At 10000 subs ≈ 2 MB.

---

## Implementation milestones

All milestones below have shipped. Kept for historical reference; each was its own PR.

### M1 — Schema + storage primitives — SHIPPED

- Add `CF_ADDR_FUNDING`, `CF_ADDR_SPENDING` constants and CF descriptors to `RocksDBStore`.
- Define `AddrFundingRow`, `AddrFundingKey`, `AddrSpendingRow`, `AddrSpendingKey` types with serde (key encoding/decoding).
- Extend `StoreBatch` with the four new vectors. Implement merge.
- Extend `RocksDBStore::write_batch` to write to the new CFs.
- Unit tests for round-trip encoding, key sort order, CF iteration.

### M2 — `connect_block` / `disconnect_block` integration — SHIPPED

- Wire the two integration points in `connect.rs` (per-output, per-input).
- Wire the `disconnect_block` inverse path.
- Feature-flag gate: only compile the integration code under `#[cfg(feature = "address_index")]`.
- Runtime opt-out flag: `-noindex=address` short-circuits the integration even when compiled in.
- Reorg correctness tests in `regtest.rs`: connect → disconnect → reconnect, verify CF state matches expected at each step.

### M3 — Lookup methods + `AddressIndex` trait — SHIPPED

- Implement `confirmed_history`, `balance`, `utxos` against the CFs.
- Implement the trait on the `node-index` library crate.
- Integration tests against a regtest node: send tx, mine, query, verify.

### M4 — Mempool variant — SHIPPED

- `MempoolAddrIndex` struct + integration with existing `Mempool::add_tx` / `remove_tx`.
- Block-confirmation lock-step (`connect_block` shedding mempool entries).
- Reorg-disconnection re-add path.
- `mempool_history` trait method.
- RBF replacement tests.

### M5 — Subscription / notification — SHIPPED

- Notifier task fed by chain + mempool events.
- Per-scripthash `tokio::broadcast` channel pool.
- `subscribe` trait method.
- Bounded subscription count + lagged-receiver semantics.
- Tests: subscribe, mine block, receive status update.

### M6 — Bench + tune — SHIPPED

- IBD overhead measurement on Pi 5 (4 GB and 8 GB).
- Write amplification analysis (RocksDB stats).
- dbcache impact under address-index workload.
- Compaction tuning (which CF should merge-on-write vs. point-lookup-tuned).
- Documentation: tuning recommendations land in `OPERATOR_ERGONOMICS.md`.

### M7 — Deferred backfill — SHIPPED

- Backfill task: two-pass walk with temporary CF (`backfill_outpoint_to_scripthash`).
- Per-pass cursor in metadata CF; resumable across restarts.
- `-backfillindex=address` startup flag; `backfillindex "address"` RPC.
- `pauseindex` / `resumeindex` / `cancelindex` RPCs.
- `getindexinfo` RPC reporting backfill progress.
- Concurrency with live chain (disjoint height ranges; smoke test under regtest).
- Crash-safety test: kill -9 mid-backfill, restart, verify resume completes correctly.
- AssumeUTXO interaction smoke test: bootstrap via AssumeUTXO at height N, run backfill, verify final index state matches a from-genesis-validated reference.

All seven milestones shipped. The deferred backfill (M7) is the recommended path for AssumeUTXO operators and for datadirs synced before the index landed.

---

## Testing strategy

### No shadow validation

Unlike the chainstate (which has 945k blocks of C++ Bitcoin Core shadow validation as ground truth), the address-history index has no canonical reference implementation in Bitcoin Core to compare against. Building a bespoke shadow that runs electrs against the same blocks and diffs row-for-row is possible but expensive (different key encoding, different CF layout, multi-day backfills) for a class of bugs that is mostly mechanical.

Instead:
- **Unit tests** over CF encoding, key sort order, batch merge.
- **Integration tests** in `regtest.rs` using satd's existing mining + transaction harness:
  - Send N txs to varied scripthashes; mine; verify history matches expectations.
  - Reorg correctness: connect → disconnect → reconnect, verify final state == "as if disconnect-reconnect never happened."
  - RBF in mempool: verify mempool_history shows the latest tx, not the replaced one.
  - Subscription: subscribe → mempool tx → block confirms → expect two status updates.
- **Vendored upstream protocol code** for Electrum: equivalence with romanz/electrs's protocol-level test fixtures comes for free from the vendoring. The bug surface where we diverge from electrs is in our index reads, which are covered by the integration tests above.

### What we explicitly check for

- Reorg correctness across single-block, multi-block, and orphan reorgs.
- Mempool/disk lock-step at block confirmation and disconnection.
- Shutdown safety: index writes survive `SIGTERM` because they ride the existing `WriteBatch` durability.
- Restart equivalence: a node that disabled the index, then re-enabled it on a clean datadir, must reach the same on-disk index state as a node that had it enabled throughout (validated by re-syncing one and comparing).

---

## Future / open questions

### Signed index snapshots (v2 / v3)

The deferred backfill (above) covers the AssumeUTXO mitigation in v1, but pays the full ~1.5-3 day Pi cost when triggered. The long-term answer is to ship signed `addr_funding.sst` + `addr_spending.sst` files alongside the AssumeUTXO snapshot itself, so an operator who trusts the snapshot signature can `unzip` themselves directly to a complete index. Largest engineering effort (signing infrastructure, key policy, distribution CDN, snapshot update cadence, schema-version compatibility) for the smallest user-visible cost. Defer to v2 / v3 once the v1 backfill path proves out and operator demand justifies it.

### Silent Payments index

SP indexing scans every output's ECDH-tweak rather than its scripthash. Same scan-every-output infrastructure; different hash function; different key. Lives in a third CF (`sp_outputs`?) with the same `connect_block` / `disconnect_block` integration shape. Sibling design doc when SP becomes a milestone.

### Balance accumulators

Pre-computed running totals per scripthash would speed `balance(scripthash)` from O(history) to O(1). Cost: extra row per scripthash, extra reorg-undo bookkeeping. Defer until benchmarks show `balance` is a bottleneck under realistic Electrum subscription load.

### Compact filter precomputation

If we also ship BIP 157/158 (per `ECOSYSTEM.md` §3 ranked-leverage list), the same connect-block walk could populate compact filter buckets in the same pass. Worth designing in mind during M2 even though filters are a separate workstream.

---

## Rejected alternatives

- **Truncated 8-byte scripthash + collision-resolution CF.** ~40% less disk; adds a third CF and a per-lookup join. Simplicity wins; we can revisit if disk pressure becomes the dominant Pi complaint.
- **Single CF with a `kind` byte discriminator** (funding-vs-spending in one CF). Loses the iterate-funding-only and iterate-spending-only patterns; complicates compaction tuning. Small win not worth the loss.
- **Per-scripthash precomputed balance accumulator** (above).
- **Async write path** (index writes happen out-of-band of `connect_block`). Defeats the atomic-reorg-consistency promise and reintroduces the "index lags chainstate" race that we're explicitly avoiding by going native in the first place.
- **Separate index process with RocksDB secondary mode.** Defers to v2 per `ECOSYSTEM.md` §4 — single binary first, split later if operational data demands it.
- **Forced backfill on AssumeUTXO load.** Defeats the AssumeUTXO time saving by adding hours-to-days at the worst possible moment (first-launch, before the operator has any useful index either way). Replaced by opt-in deferred backfill — see [Deferred backfill (AssumeUTXO mitigation)](#deferred-backfill-assumeutxo-mitigation).
- **Single-pass backfill via flat-file random reads.** Resolves spent prev_outputs by reading funding txs from flat files on demand. Simpler conceptually; catastrophic IO profile on Pi (random reads dominate). Two-pass with temp CF wins.
- **Backfill that also populates `tx_index` as a side effect.** Persistent tx_index has its own value but should be its own opt-in feature, not coupled to the address index. Keep concerns separable.
- **Bundled electrs as the index.** Architecturally rejected in `ECOSYSTEM.md` §4 — doesn't share chainstate, parallel block scanning, reorg race window. Doesn't earn the headline.
