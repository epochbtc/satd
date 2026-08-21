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
disconnect during a reorg, so no tombstone debt accumulates over time.

The on-disk column is measured, not estimated. It comes from the per-CF SST
totals of one fully-indexed mainnet node in August 2026, at height 963,000 with
`txindex`, `addressindex` and `silentpaymentindex` all on. Your numbers track
the chain's growth.

| Column family | Role | Keyed by | Row size | Approx. on disk |
|---|---|---|---|---|
| `addr_spending_v2` | every input spending a script | `scripthash[16] ‖ height ‖ txid ‖ vin` | 92 B | ~256 GB |
| `outpoint_spend` | UTXO → the input that spent it | `prev_txid[32] ‖ vout` | 76 B | ~186 GB |
| `addr_funding_v2` | every output paying a script | `scripthash[16] ‖ height ‖ txid ‖ vout` | 64 B | ~178 GB |
| `tx_index` | txid → containing block | `txid[32]` | 64 B | ~79 GB |
| `undo` | per-block disconnect data | `block_hash[32]` | ~28 B / input | ~74 GB |
| `sp_tweaks` | BIP 352 tweaks, one row per block from taproot activation | `height` | 73 B/eligible tx | ~13 GB |
| `coins` | the live UTXO set | `txid[32] ‖ vout` | ~28 B varint | ~10 GB |
| `block_index` | header and status per block | `block_hash[32]` | ~100 B | ~120 MB |
| `block_filter` / `_header` | BIP 158 compact filters | `type ‖ height` | ~30 KB / 37 B | ~30 GB (estimate) |

The three address/txid indices plus `outpoint_spend` are the bulk. Two rows
often surprise operators. `undo` is not a rolling window: satd keeps the
disconnect data for every block, so it grows with the chain. `coins` is the
live UTXO set, which is served from the in-memory coin cache but still
serializes to several GB.

The filter row is the one figure here that is still an estimate. The measured
node does not run `blockfilterindex`.

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
| BIP 352 silent-payment scanning or serving | `-silentpaymentindex=1` | `sp_tweaks` |

When a surface is off, its CF is never written and the disk is never spent.

## Silent-payment index

`sp_tweaks` holds one BIP 352 public tweak per eligible transaction, grouped
into one row per block. The `silentpaymentindex` option enables it, and it is
off by default. Two surfaces read it: the streaming `tweaks` firehose and
index-accelerated scan-key-watch rescans (see
[Streaming Consumption API](streaming.md)).

The index starts at taproot activation, not at genesis, because pre-taproot
blocks carry no silent payments. Each indexed block writes a row even with no
eligible transaction, so an empty row means "indexed, none" rather than "not
indexed". Every row embeds the hash of the block it describes, so a reader
authenticates it without the height-to-hash index.

A node that syncs from genesis with the option set builds the index inline. To
add the index to an existing datadir, run a backfill:

```sh
sat-cli backfillindex silentpayment
```

The backfill walks from taproot activation to the snapshot height it pinned at
start, and resumes across a restart. `getindexinfo` reports a `silentpayments`
section with the synced flag and the backfill progress, including a
`backfill.progress_ratio` field. Progress is measured across that walked span,
not from genesis, so it starts near zero rather than near the fraction of the
chain that predates taproot — use the reported ratio rather than dividing
`cursor_height` by `snapshot_height`, which measures from genesis.

`estimated_remaining_seconds` is reported only while a backfill is both enabled
and running. A paused, cancelled, failed or disabled cursor reports `0` — its
progress is frozen while elapsed wall-clock keeps growing, so any estimate
derived from it would grow without bound for as long as the node stays up.

The estimate is measured over the current *stint* — the uninterrupted span
since the running backfill last started walking blocks. It is not an average
over the life of the job. Two consequences worth knowing:

- Time the backfill was not working is never counted. Pause it for two days and
  resume, or stop the daemon for a week and restart, and the estimate reflects
  the throughput it is achieving now, not the idle time in between.
- The estimate is unavailable for the first few seconds after a start, a
  resume, or a daemon restart, and reads `0` until the new stint has measured
  something. `0` here means "no estimate yet", not "nearly done"; the `state`
  and `cursor_height` fields are the ones to watch during that window.

This applies to all three backfills (`address`, `basic block filter index`,
`silentpayments`) — they share one estimator.

Until a backfill completes, the tweak-serving surfaces refuse a request rather
than return a partial result.

### Size and backfill time

The figures here are measurements from a synced mainnet node, taken in August
2026 over heights 709,632 to 962,151. That span is 252,520 blocks, holding
187,015,795 tweak entries.

| Measure | Value |
|---|---|
| Row content, full taproot era | ~13 GB |
| Mean eligible transactions per block, whole era | ~740 |
| Mean eligible transactions per block, recent blocks | ~260 |
| Mean row | ~54 KB |
| Growth at the recent rate | ~1 GB/year |
| Backfill wall-clock for 252,520 blocks | 6 h 46 m (~10 blocks/s) |

A transaction is eligible when it pays a taproot output and has at least one
input whose public key the protocol can recover. Recoverable inputs are P2PKH,
P2WPKH, P2SH-P2WPKH and key-path P2TR. A transaction funded only by P2WSH,
bare multisig or script-path P2TR pays taproot and indexes nothing. Measured
against the index, about 98% of taproot-paying transactions across the era are
eligible.

The era mean is far above the recent rate. Blocks from the 2023 and 2024
inscription period average about a thousand eligible transactions, and the
busiest carry several thousand. A return to that transaction pattern raises the
growth rate again.

The backfill ran while the node stayed at the tip and served its other
surfaces. It is bound by CPU rather than by disk. The walk does one elliptic
curve multiplication per eligible transaction. Its measured throughput tracks
the eligible-transaction count, not the block size, and roughly 70% of that
6 h 46 m was per-transaction work.

> **Note.** A datadir where a backfill was interrupted and restarted can read
> larger than the figure above until compaction reclaims the superseded rows.
> The node measured here read about 15 GB for a 13 GB index for that reason.

> **Note.** A `tweak_dust_limit` on a subscription drops entries whose largest
> taproot output is below the limit. It filters less than its name suggests. At
> 330 sat, the dust threshold for a taproot output, it removes nothing
> measurable. At 546 sat it removes about 10%, and at 0.001 BTC about two
> thirds. The limit reduces the bandwidth a subscription uses. It does not
> reduce the index on disk.

## Repairing lost block data

Block bodies live in the flat files under `blocks/` (`blk*.dat`), not in
RocksDB. The `block_index` entry for a block records which file and offset its
record starts at. Those are two independently buffered write streams, so it is
possible — after a kernel panic or power loss, never after a clean shutdown or
a plain process crash — to end up with an index entry that survived while the
block bytes it points at did not.

The symptom is a single block that behaves as if it were pruned on a node that
is not pruning:

```console
$ sat-cli getblock 000000000000000000000b951399b504a52a3fdfa1d33bcde59ac6c019c4af1c 0
error code: -5: Block data not available
```

`getblockheader` still works and shows the block connected with a normal
confirmation count, because consensus never re-reads the body: the UTXO delta
was applied when the block connected. Nothing surfaces the hole until something
walks history — an index backfill fails at that height, or a peer's request for
the block cannot be served.

Fetch a fresh copy of just that block from a peer:

```sh
sat-cli getblockfrompeer <blockhash>          # satd picks a peer
sat-cli getblockfrompeer <blockhash> <peer_id>  # or name one from `getpeerinfo`
```

The call returns as soon as the request is sent; the repair happens when the
block arrives. Re-run `getblock` to confirm, and check the log for
`Repaired block data from a peer-supplied copy`.

The supplied block is authenticated before anything is written. Its hash must
match a header already in the index — which is what carries the proof-of-work
and difficulty checks made when that header was accepted — and its transactions
must match the merkle root that hash commits to. Witnesses need their own
chain, because the merkle root commits only to txids: when the coinbase carries
a BIP 141 commitment it must hold exactly one 32-byte witness item and the
commitment must verify; otherwise no transaction may carry witness data at all.
Together those pin every byte, so a peer can only return the genuine block or
be rejected. A peer whose reply fails is banned.

The same test decides whether there is anything to repair. A stored copy is
left alone only if it is the *canonical* block, not merely one that parses —
witness bytes are outside everything the block hash commits to, so a copy can
deserialize and hash correctly while still carrying a padded, truncated or
stripped witness. `getblockfrompeer` will replace such a copy; `getblock` on it
succeeds, so nothing else would ever surface it.

Blocks that are pruned or marked invalid are refused: those states are
deliberate, and repopulating them would contradict the decision that produced
them. A block you hold only the header for is not repaired either — it is
downloaded through the normal path, which applies the checkpoint and signet
checks and connects it.

To find holes ahead of time rather than discovering them through a failed
backfill, use the block-file audit:

```sh
sat-cli debug blockfile-audit
```

It reports `unresolved_entries` for index entries whose record falls past the
end of its file, in one pass over the file metadata — as opposed to
`getblockstats` across every height, which reads and deserializes every block
body on the chain and cannot distinguish a data hole from an unknown block
(both return `-5`).

> **Note.** satd fsyncs a block's record before its index entry is committed on
> every write path, so the window above is closed for blocks written by current
> versions. Datadirs that predate this may still carry a hole from an earlier
> crash; nothing audits or migrates them on upgrade.

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
