# Disk Footprint & Indices

A fully-indexed satd node (`-txindex=1 -addressindex=1 -blockfilterindex=basic`)
uses more disk for its indices than a `bitcoind + electrs/Fulcrum + esplora`
stack uses in total. This is by design. This chapter explains where the bytes go
and what they pay for.

If you only need a validating node, none of this applies. A consensus-only satd
(`-txindex=0 -addressindex=0`, filters off) has a chainstate comparable to
Core's and carries none of the index column families below.

## Where the bytes go

satd keeps everything in one RocksDB with multiple column families (CFs). The
indices are append-mostly: rows are added as blocks connect and removed only on
disconnect during a reorg, so no tombstone debt accumulates over time. The
figures below describe a fully-indexed mainnet node in mid-2026; your numbers
will track the chain's growth.

| Column family | Role | Keyed by | Row size | Approx. on disk |
|---|---|---|---|---|
| `addr_funding_v2` | every output paying a script | `scripthash[16] ‖ height ‖ txid ‖ vout` | 64 B | ~200 GB |
| `tx_index` | txid → containing block | `txid[32]` | 64 B | ~140 GB |
| `addr_spending_v2` | every input spending a script | `scripthash[16] ‖ height ‖ txid ‖ vin` | 92 B | ~140 GB |
| `outpoint_spend` | UTXO → the input that spent it | `prev_txid[32] ‖ vout` | 76 B | ~100 GB |
| `block_filter` / `_header` | BIP 158 compact filters | `type ‖ height` | ~30 KB / 37 B | ~30 GB |
| `coins` | the live UTXO set | `txid[32] ‖ vout` | ~28 B varint | ~tens of MB |
| `undo` | per-block disconnect data | `block_hash[32]` | ~28 B / input | small (rolling) |

The three address/txid indices plus `outpoint_spend` are the bulk. The UTXO set
itself (`coins`) is small: it lives mostly in the in-memory coin cache and
serializes to a few tens of MB on disk.

> **Note.** During a `-reindex` or `-reindex-chainstate`, RocksDB compaction
> falls behind the write rate, so `tx_index` in particular can read much larger
> than its settled size (uncompacted L0 SSTs, bloom filters, and index blocks).
> Measure the per-CF footprint after the node has idled and background
> compaction has drained; see [Compaction](#compaction).

## Why it is larger than `bitcoind + electrs + esplora`

Three structural reasons.

### 1. satd stores the spend graph in both directions

Every spend writes two rows:

- `addr_spending_v2`, keyed by script (`scripthash ‖ height ‖ …`). It answers
  "show me everything address A spent."
- `outpoint_spend`, keyed by outpoint (`prev_txid ‖ vout`). It answers "what
  input spent this UTXO" in a single keyed read.

electrs and Fulcrum keep one spend representation and derive the other
direction on demand. satd spends the disk to keep both materialized, so both
queries are O(1). This duplication is internal and intentional, and it is the
largest source of the overage.

### 2. satd indexes a superset of what any one external tool does

The often-quoted "30–180 GB" figure is the electrs/Fulcrum address index alone.
satd's address index alone (`addr_funding` + `addr_spending`) already exceeds
that range. satd also carries a Core-style `tx_index`, an `outpoint_spend`
reverse index, and BIP 158 filters in the same database, because one binary
serves Electrum, Esplora, `getrawtransaction`, and compact-filter clients. So
compare satd's indices to electrs plus Core's `txindex` plus a spend index plus
a filter index, fused into one store.

### 3. satd trades pointer compactness for self-containment

`tx_index` stores the full 32-byte block hash as its value, where Core's
`txindex` stores an on-disk position (`CDiskTxPos`) of about 12 bytes. That
costs about 20 extra bytes per transaction, roughly 24 GB across the chain, and
one extra indirection on read. In exchange, the index is independent of
block-file layout and survives block-file re-packing. satd's keys are also
fixed-width binary tuned for prefix seeks rather than byte-minimal, which costs
a little space and speeds up range scans.

### What satd already does to keep the footprint down

The schema is close to the smallest encoding of what it indexes:

- **16-byte scripthash prefix, not 32.** Address rows key on the first half of
  `sha256(scriptPubKey)`, which halves the dominant field of every address row.
  Collisions are extremely unlikely and are resolved against the full script on
  read.
- **Varint-packed UTXOs.** The `coins` CF uses a compact varint encoding,
  about 28 B typical against about 43 B for a naive struct.
- **Fixed-width keys, no delimiters.** Heights are big-endian, so range scans
  return rows in chain order with no secondary sort.

The size is `row_count × ~70 B`, and `row_count` is every output and every
spend in Bitcoin's history. The footprint is data, not per-row overhead.

## What the disk buys you

| Property | satd (shared store) | `bitcoind + electrs/Fulcrum` |
|---|---|---|
| Index vs. tip consistency | Always atomic: the index update is in the same `WriteBatch` as the block | Index lags the node; reorg-window races are possible |
| Build cost | Index built inside `connect_block` validation | Second process re-scans every block to build a parallel DB |
| Lookup path | O(1) keyed read, in-process function call | Cross-process RPC plus the indexer's own lookup |
| Spend-by-outpoint | O(1) (`outpoint_spend`) | Often derived or scanned |
| Operational surface | One process, one config, one backup, one reindex | Two or more processes to wire, monitor, and keep in lockstep |
| TLS / auth | Native on every surface | Usually a separate reverse proxy |
| Disk | Larger in aggregate | Smaller per tool, but you run several |

The disk pays for consistency and a single process to operate. A read on any
surface (Electrum, Esplora, JSON-RPC) can never observe an index out of sync
with the chain tip, because there is no second copy to fall behind. To scale
read throughput, run more nodes rather than more index processes; see
[API Scaling & Runtimes](api-scaling.md).

## Choosing what to index

The indices are opt-in per surface. Match the disk to what you serve:

| You want… | Flags | Heavy CFs pulled in |
|---|---|---|
| Validating node only | (defaults; indices off) | none |
| `getrawtransaction <txid>` anywhere | `-txindex=1` | `tx_index` |
| Electrum / Esplora address history | `-addressindex=1` (implies `-txindex=1` for Electrum) | `addr_funding_v2`, `addr_spending_v2`, `outpoint_spend`, `tx_index` |
| BIP 157/158 light-client service | `-blockfilterindex=basic -peerblockfilters=1` | `block_filter`, `block_filter_header` |

When a surface is off, its CF is never written and the disk is never spent.

## Compaction

RocksDB background compaction runs continuously. satd's bulk-load reindex mode
does not disable it; only the WAL is disabled. When reindex writes stop, the
background jobs drain the L0 backlog on their own, with no manual step. satd
also force-compacts the `coins` CF on a timer (`compaction_interval_secs`,
default 30 min, L0-triggered). There is no satd-level forced full compaction of
the large index CFs; they rely on RocksDB auto-compaction.

The index CFs are append-mostly, with little deletion outside reorgs. Expect
compaction to reclaim the reindex-era L0 and overlap debt: a moderate drop, not
a collapse, because most of the footprint is index data. satd logs a per-CF
pending-compaction-bytes diagnostic every `compaction_diag_interval_secs`
(default 60 s). Let those settle toward zero before taking a size measurement.
