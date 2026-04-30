# Address-history index — design

Locked design for the address-history index that backs satd's native Electrum and Esplora subsystems (per `ECOSYSTEM.md` §4 / §4a). The index is the load-bearing prerequisite for both protocols and for any future Silent Payments work.

This document predates implementation. Once code lands, treat it as the spec; deviations get discussed and the doc gets updated.

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

### No separate backfill phase

Rejected: Bitcoin Core's `-reindex-chainstate` pattern where index becomes available only after a long post-IBD walk. Reasons:
- Doubles wall-clock time before protocols become useful.
- Requires re-reading every block from flat files — IO-heavy on Pi.
- Adds a "backfill in progress" state to operate / monitor.
- Index-during-IBD pays the cost once, in the same pass as block validation.

The one place backfill **does** matter: AssumeUTXO. See [Future / open questions](#future--open-questions).

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

Suggested ordering, ~3-5 weeks total. Each step is its own PR.

### M1 — Schema + storage primitives (~3-5 days)

- Add `CF_ADDR_FUNDING`, `CF_ADDR_SPENDING` constants and CF descriptors to `RocksDBStore`.
- Define `AddrFundingRow`, `AddrFundingKey`, `AddrSpendingRow`, `AddrSpendingKey` types with serde (key encoding/decoding).
- Extend `StoreBatch` with the four new vectors. Implement merge.
- Extend `RocksDBStore::write_batch` to write to the new CFs.
- Unit tests for round-trip encoding, key sort order, CF iteration.

### M2 — `connect_block` / `disconnect_block` integration (~1 week)

- Wire the two integration points in `connect.rs` (per-output, per-input).
- Wire the `disconnect_block` inverse path.
- Feature-flag gate: only compile the integration code under `#[cfg(feature = "address_index")]`.
- Runtime opt-out flag: `-noindex=address` short-circuits the integration even when compiled in.
- Reorg correctness tests in `regtest.rs`: connect → disconnect → reconnect, verify CF state matches expected at each step.

### M3 — Lookup methods + `AddressIndex` trait (~3-5 days)

- Implement `confirmed_history`, `balance`, `utxos` against the CFs.
- Implement the trait on the `node-index` library crate.
- Integration tests against a regtest node: send tx, mine, query, verify.

### M4 — Mempool variant (~1 week)

- `MempoolAddrIndex` struct + integration with existing `Mempool::add_tx` / `remove_tx`.
- Block-confirmation lock-step (`connect_block` shedding mempool entries).
- Reorg-disconnection re-add path.
- `mempool_history` trait method.
- RBF replacement tests.

### M5 — Subscription / notification (~3-5 days)

- Notifier task fed by chain + mempool events.
- Per-scripthash `tokio::broadcast` channel pool.
- `subscribe` trait method.
- Bounded subscription count + lagged-receiver semantics.
- Tests: subscribe, mine block, receive status update.

### M6 — Bench + tune (~1 week)

- IBD overhead measurement on Pi 5 (4 GB and 8 GB).
- Write amplification analysis (RocksDB stats).
- dbcache impact under address-index workload.
- Compaction tuning (which CF should merge-on-write vs. point-lookup-tuned).
- Documentation: tuning recommendations land in `OPERATOR_ERGONOMICS.md`.

Total elapsed: ~3-5 weeks of focused work. M1-M3 are sequential; M4 can run partially in parallel with M3; M5-M6 are after the index is correct.

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

### AssumeUTXO interaction

Snapshot bootstrap (`-assumeutxo=<height>`) skips IBD validation up to the snapshot height. The address index has no equivalent "trust this snapshot" path — pre-snapshot history is missing.

Three options, none free:

1. **Backfill on AssumeUTXO load**: walk every block from genesis to snapshot-height, build the index. Defeats the AssumeUTXO time saving; adds hours-to-days on Pi.
2. **Truncated index**: index only covers post-snapshot blocks. Document clearly: "address index reflects blocks since snapshot height N." Acceptable for many wallets (they have a birthday); breaks others (legacy address recovery).
3. **Signed index snapshot**: ship a signed `addr_funding.sst` + `addr_spending.sst` alongside the AssumeUTXO snapshot. Largest engineering effort; smallest user-visible cost.

Initial v1 ships with option 2. Option 3 is the right long-term answer.

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
- **Bundled electrs as the index.** Architecturally rejected in `ECOSYSTEM.md` §4 — doesn't share chainstate, parallel block scanning, reorg race window. Doesn't earn the headline.
