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

| Column family | Role | Keyed by | Row size | Before | After (projected) |
|---|---|---|---|---|---|
| `addr_spending_v3` | every input spending a script | `scripthash[16] ‖ txseq[5] ‖ vin[3]` | 32 B (was 92) | ~256 GB | ~89 GB |
| `spent` | UTXO → the input that spent it | `funding_txseq[5] ‖ vout[3]` | 16 B (was 76) | ~186 GB | ~39 GB |
| `addr_funding_v3` | every output paying a script | `scripthash[16] ‖ txseq[5] ‖ vout[3]` | 32 B (was 64) | ~178 GB | ~89 GB |
| `tx_loc` + `txseq_txid` | txid ↔ transaction ordinal | `txid[32]` / `txseq[5]` | 37 B each (was 64, one way) | ~79 GB | ~91 GB |
| `txseq_block` | first ordinal of a block → height | `txseq[5]` | 9 B | — | ~10 MB |
| `undo` | per-block disconnect data | `block_hash[32]` | ~33 B / input | ~74 GB | ~87 GB |
| `sp_tweaks` | BIP 352 tweaks, one row per block from taproot activation | `height` | 73 B/eligible tx | ~13 GB | ~13 GB |
| `coins` | the live UTXO set | `txid[32] ‖ vout` | ~29 B varint | ~10 GB | ~10 GB |
| `block_index` | header and status per block | `block_hash[32]` | ~100 B | ~120 MB | ~120 MB |
| `block_filter` / `_header` | BIP 158 compact filters | `type ‖ height` | ~30 KB / 37 B | ~30 GB | ~30 GB |
| **total** | | | | **~826 GB** | **~449 GB** |

**Read the two columns differently.** *Before* is measured: the per-CF SST
totals of one fully-indexed mainnet node in August 2026, at height 963,000
with `txindex`, `addressindex` and `silentpaymentindex` all on. *After* is
a projection — the measured figure scaled by the change in row width — for
the chainstate schema that keys every index on a transaction ordinal. It
has not yet been re-measured on a synced node; when it is, this table gets
real numbers and this paragraph goes away.

The projection is conservative. Both columns are post-compression (LZ4 at
L2–L5, Zstd at the bottom), and the dense ascending ordinals that replaced
the 32-byte hashes compress considerably better than the hashes did — a
hash is incompressible by construction — so the measured after-figure
should land at or below the projection rather than above it.

Two rows in the after column go *up*, and both are deliberate. `undo`
gains five bytes per spend and `coins` about one per coin, because a coin
now carries the ordinal of the transaction that created it. That is what
lets `connect_block` key a spend row without a lookup: paying ~15 GB
across the two smallest families takes ~150 GB off the two largest. The
transaction index also goes up, because it is now two families instead of
one — that reverse map is what every other index drops its txid copies
*for*.

Two rows often surprise operators. `undo` is not a rolling window: satd
keeps the disconnect data for every block, so it grows with the chain.
`coins` is the live UTXO set, which is served from the in-memory coin
cache but still serializes to several GB.

The filter row is the one figure here that was always an estimate. The
measured node does not run `blockfilterindex`.

> **Note.** During a `-reindex` or `-reindex-chainstate`, RocksDB compaction
> falls behind the write rate, so the transaction index in particular can read much larger
> than its settled size (uncompacted L0 SSTs, bloom filters, and index blocks).
> Measure the per-CF footprint after the node has idled and background
> compaction has drained; see [Compaction](#compaction).

To take the same measurement on your own node, ask it:

```
sat-cli debug storage-footprint
```

It reports, per column family, the on-disk SST bytes, an estimate of the live
key count, their quotient (the effective post-compression cost of one row), and
the bytes RocksDB still owes to compaction. The RPC behind it is
`getstoragefootprint`; it reads RocksDB properties and LSM metadata only, with
no iteration, so it is safe on a live node under IBD — unlike
`getblockfileaudit`. Column families the running binary did not create — the
filter indexes on a node without `-blockfilterindex`, the backfill temp CF on a
node that never backfilled — are absent from the list rather than reported as
zero. Take the measurement after compaction has drained; see
[Compaction](#compaction).

## Why it is larger than `bitcoind + electrs + esplora`

Three structural reasons.

### 1. satd stores the spend graph in both directions

Every spend writes two rows:

- `addr_spending_v3`, keyed by script (`scripthash ‖ txseq ‖ vin`). It answers
  "show me everything address A spent."
- `spent`, keyed by the spent output's funding transaction and vout. It
  answers "what input spent this UTXO" in a single keyed read.

electrs and Fulcrum keep one spend representation and derive the other
direction on demand. satd spends the disk to keep both materialized, so both
queries are O(1). This duplication is internal and intentional, and it is the
largest source of the overage.

### 2. satd indexes a superset of what any one external tool does

The often-quoted "30–180 GB" figure is the electrs/Fulcrum address index alone.
satd's address index alone (`addr_funding_v3` + `addr_spending_v3`) already
exceeds that range. satd also carries a transaction index, a `spent`
reverse index, and BIP 158 filters in the same database, because one binary
serves Electrum, Esplora, `getrawtransaction`, and compact-filter clients. So
compare satd's indices to electrs plus Core's `txindex` plus a spend index plus
a filter index, fused into one store.

### 3. satd keys on transaction ordinals

Every index used to key on a 32-byte txid. A txid is a hash: incompressible,
and written once per index that mentions the transaction. On a fully indexed
node that repetition was the single largest line in the chainstate — the same
identifiers stored five to seven times over.

An **ordinal** replaces it. Transactions are numbered in chain order from the
genesis coinbase at 0, so the transaction at position *i* of a block takes
`nchaintx(parent) + i` — the cumulative count satd already keeps per block for
`getchaintxstats`. Nothing new has to be counted. Five bytes hold 2^40 of
them, about 880 times the chain's current transaction count, and the encoding
is big-endian, so the byte order of a key is the order the transactions were
mined.

Two column families hold the mapping: `tx_loc` from txid to ordinal, and
`txseq_txid` back. The reverse map is the part that makes the rest work — a
row keys on an ordinal, and the storage layer resolves it to a txid, in one
batched lookup per scan, before the row leaves. A third, `txseq_block`, is one
small row per block that turns an ordinal back into a height. Because an
ordinal names the position inside the block as well as the block,
`getrawtransaction` also indexes straight into the block's transaction list
instead of reading the block and comparing every txid in it.

The ordinal is a storage encoding, not a new public identifier. Nothing on any
wire changes.

Against Core, the comparison is with `CDiskTxPos` — an on-disk position of
about 12 bytes, compact but tied to the block-file layout. satd's 5-byte
ordinal is smaller and stays independent of that layout, so a block-file
re-pack does not invalidate the index.

The design is borrowed. [rbitcoin](https://github.com/reardencode/rbitcoin)
stores the chain as a decomposed relational archive — separate bodies for
outputs, input witnesses and spend annotations, with a dense 32-byte-per-
transaction txid sidefile — and numbers everything by position rather than by
hash. satd keeps Core-compatible flat block files and a UTXO set, so the two
designs are not interchangeable, but the observation that the hashes are the
footprint, and that one dense sidefile can carry them for every index at once,
is rbitcoin's.

satd's keys are otherwise fixed-width binary tuned for prefix seeks rather
than byte-minimal, which costs a little space and speeds up range scans.

### What satd already does to keep the footprint down

The schema is close to the smallest encoding of what it indexes:

- **16-byte scripthash prefix, not 32.** Address rows key on the first half of
  `sha256(scriptPubKey)`, which halves the dominant field of every address row.
  Collisions are extremely unlikely and are resolved against the full script on
  read.
- **Varint-packed UTXOs.** The `coins` CF uses a compact varint encoding,
  about 28 B typical against about 43 B for a naive struct.
- **Fixed-width keys, no delimiters.** Ordinals are big-endian, so range
  scans return rows in chain order with no secondary sort.
- **One copy of each transaction identifier.** Index rows name transactions by
  a 5-byte ordinal; the 32-byte txid lives once, in `txseq_txid`.

The size is `row_count × ~32 B`, and `row_count` is every output and every
spend in Bitcoin's history. The footprint is data, not per-row overhead.

## What the disk buys you

| Property | satd (shared store) | `bitcoind + electrs/Fulcrum` |
|---|---|---|
| Index vs. tip consistency | Always atomic: the index update is in the same `WriteBatch` as the block | Index lags the node; reorg-window races are possible |
| Build cost | Index built inside `connect_block` validation | Second process re-scans every block to build a parallel DB |
| Lookup path | O(1) keyed read, in-process function call | Cross-process RPC plus the indexer's own lookup |
| Spend-by-outpoint | O(1) (`spent`) | Often derived or scanned |
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
| `getrawtransaction <txid>` anywhere | `-txindex=1` | `tx_loc`, `txseq_txid`, `txseq_block` |
| Electrum / Esplora address history | `-addressindex=1` (implies `-txindex=1` for Electrum) | `addr_funding_v3`, `addr_spending_v3`, `spent`, `tx_loc`, `txseq_txid`, `txseq_block` |
| BIP 157/158 light-client service | `-blockfilterindex=basic -peerblockfilters=1` | `block_filter`, `block_filter_header` |
| BIP 352 silent-payment scanning or serving | `-silentpaymentindex=1` | `sp_tweaks` |

When a surface is off, its CF is never written and the disk is never spent.

## Silent-payment index

`sp_tweaks` holds one BIP 352 public tweak per eligible transaction, grouped
into one row per block. The `silentpaymentindex` option enables it, and it is
off by default. Two surfaces read it: the streaming `tweaks` firehose and
index-accelerated scan-key-watch rescans; the integrator guide for both is
[Silent Payments (BIP 352)](silent-payments.md).

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
start, and resumes across a restart. `getsatdindexinfo` reports a `silentpayments`
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

## OP_RETURN data pruning

> **Undoing it means downloading the stripped blocks again.**
>
> - Turning `pruneopreturn` off restores nothing. `restoreopreturns` downloads
>   every stripped block again from peers (see
>   [Restoring stripped blocks](#restoring-stripped-blocks));
>   `getblockfrompeer` brings back one.
> - Once anything is stripped, satd 0.6.x and earlier refuse to open the
>   datadir (RocksDB reports `Column families not opened: opreturn_strip`), so
>   there is no rollback to them. This is deliberate: they would misread the
>   zeroed data.
> - The node stops serving old blocks to peers, like a pruned node.

**What it costs the network.** A stripping node is no longer an archive peer.
It drops `NODE_NETWORK` and advertises only `NODE_NETWORK_LIMITED`, so new
nodes cannot sync the chain from it. It serves only the last 288 blocks: a
peer asking for an older one is disconnected, as Core does for a pruned node,
and a `noban` peer asking for a stripped block gets `notfound`. Headers and
BIP 157 filters are still served for the whole chain. It stays limited for as
long as any stripped block exists, so turning the option off does not by
itself bring `NODE_NETWORK` back; restoring every stripped block does (see
[Restoring stripped blocks](#restoring-stripped-blocks)). An operator who wants to help the
network with initial block download should leave the option off.

`pruneopreturnpeers=intact` serves the blocks the node still holds intact at
any depth (and advertises `NODE_INTACT_BLOCKS`, experimental service bit 28),
but Bitcoin Core and most other nodes do not ask a limited peer for old
blocks, so it mainly helps `getblockfrompeer` callers and nodes such as
rbitcoin that do.

### How it works

With `pruneopreturn=N`, a background worker walks the active chain below
`tip − N − 2`. In each block it zeroes the payload of every non-coinbase
OP_RETURN output whose scriptPubKey is at least `pruneopreturnsize` bytes long
(default 4096), keeping the leading `OP_RETURN` byte and every length, and
punches the zeroed range out of the block file (`fallocate(PUNCH_HOLE)` on
Linux, `F_PUNCHHOLE` on macOS). No offset moves. Before it touches a byte it
stores the block's original txids and a hash of its zeroed form, so every
surface still names each transaction by its real txid, and `-reindex` and
`-reindex-chainstate` replay the block from that record.

```ini
pruneopreturn=4320       # about 30 days; 52560 is about a year; 1 or all = 288
pruneopreturnsize=10KiB  # 10k is 10,000 bytes, 10KiB is 10,240
```

The worker runs only on a quiet node: never during initial block download, a
reindex or an AssumeUTXO background validation. Blocks are fully validated
whatever the setting; only what is kept on disk afterwards changes. It works
alongside `prune`, the indexes, Esplora and Electrum.

**Filesystem support.** The blocks directory's filesystem must support hole
punching (ext4, XFS, btrfs, ZFS, tmpfs, APFS). satd probes it at startup and
refuses to start, naming the error, when it does not.

### What it saves

Hole punching frees only the whole filesystem blocks inside each payload,
usually 4 KiB.

| scriptPubKey size | freed on a 4 KiB-block filesystem |
|---|---|
| ≤ 83 B (Runes, Omni, OpenTimestamps, most of today's) | 0 |
| 210 B (median of today's >83 B outputs) | 0 |
| 4 KiB | 0 to 4 KiB depending on alignment, average ~0.5 KiB |
| 10 KiB | ~6 KiB on average |
| 100 KB (Core v30 standard maximum) | ~96 KB |

Today's chain gives back almost nothing: most OP_RETURN outputs are far
smaller than a filesystem block. The option bounds what large data-carrier
outputs cost if their use grows. A threshold below one filesystem block is
accepted, with a startup note: such outputs free little or no disk, and each
stripped transaction costs about 100 bytes of index.

This removes the data from the node's block files; it is not a secure erase, and copies, snapshots, backups and the last 288 blocks keep the original bytes.

### What you lose

Every other surface keeps working ([Esplora](esplora.md), [Electrum](electrum.md),
the [JSON-RPC extensions](json-rpc-extensions.md#opreturn-pruned-blocks),
streaming).

1. **An archival peer**, as above.
2. **The raw bytes of stripped transactions**, on every surface: `getblock` at
   verbosity 0 (Core's `Block not available (pruned data)`, which LND's
   pruned-node fallback recognizes), `getrawtransaction` hex, Esplora `/raw`
   and `/hex`, Electrum `blockchain.transaction.get` without `verbose`, and
   `raw_tx` in streaming rescans. Their JSON views still work, with each
   stripped script shown as a bare `OP_RETURN` and its original size.
3. **Watches on OP_RETURN script content** cannot match a stripped output in a
   rescan. Live matching, as blocks connect, is unaffected.
4. **Deep reorgs.** A reorg or `invalidateblock` that would disconnect a
   stripped block fails with an error naming it; nothing changes.
5. **Script re-verification on reindex.** The input scripts of stripped
   transactions are not verified again on `-reindex`; they were when the
   block first connected. Everything else is.
6. **The `blk*.dat` files.** Tools that parse them directly see zeroed
   payloads. Copying them with tools that are not sparse-aware (plain `cp`
   without `--sparse=always`, `rsync` without `-S`) fills the holes back in on
   the copy.

### Restoring stripped blocks

To make a stripping node a full archive peer again, remove the three
`pruneopreturn*` options and restart with:

```ini
restoreopreturns=1
```

The node then downloads every stripped block again, as a small initial block
download, and writes each back in place over its stripped copy: the record
goes, the raw block is served again, and the punched space is allocated
again.

- It asks only connected peers that keep every block (`NODE_NETWORK` with
  `NODE_WITNESS`), never a limited peer, which may have stripped the same
  block. While it waits for one, its outbound connections keep looking for
  such peers.
- It asks each peer for at most 16 blocks at a time, and works on at most
  1024 at once. A peer that does not answer within 15 seconds has its
  requests moved to another peer; one that answers `notfound` is not asked
  for that block again.
- It runs only once the tip is caught up, and pauses while the node is
  behind. The node is not in initial block download meanwhile: relay, the
  mempool, mining and the indexes carry on as normal.
- Before each 1024 blocks it checks the blocks volume for room for what the
  holes still lack, plus 1 GiB, and waits (checking every minute) when there
  is not.
- It downloads about the total size of the stripped blocks, which
  `getopreturnpruneinfo` reports when the download starts. On a pruning node it
  restores the newest blocks first.
- A restart carries on where it stopped.

`restoreopreturns` cannot be combined with `pruneopreturn`,
`pruneopreturnsize` or `pruneopreturnpeers`, at any value: satd refuses to
start, naming both. On a node with nothing stripped it does nothing, so it can
stay set.

Once the last stripped block is restored the node is a full node again,
within a minute and without a restart. It advertises `NODE_NETWORK` to every
peer that connects from then on; peers already connected keep the services
they saw when they connected. The strip records' column family is removed
from the datadir with the last record, and the log says that
`restoreopreturns` can be removed. Restarted without it, the node runs as an
ordinary unpruned satd.

`getblockfrompeer <blockhash> <peer_id>` restores a single stripped block the
same way. The worker strips it again on a later pass if the option is still
on. Restoring the last stripped block by hand, with the option off, also makes
the node a full node again.

### Watching it

`getopreturnpruneinfo` reports the configuration, the worker's state
(`running`, `ibd`, `reindex`, `background_validation` or `off`; under
`restoreopreturns`, `restoring`, `waiting_for_peers`, `waiting_for_disk`,
`waiting_for_tip` or `restored`), how far its scan has reached, and what is
stripped:

- `blocks`, `transactions`, `outputs` and `bytes_zeroed`, added up from the
  strip records;
- `bytes_freed_estimate`, the whole filesystem blocks every span is sure to
  contain: a cautious minimum;
- `blocks_dir_apparent_bytes` and `blocks_dir_allocated_bytes`, a stat of the
  block files (cached for a minute). Their difference is the measurement of
  what the holes save;
- under `restoreopreturns`, `restore`: `total_blocks` when the pass started,
  `remaining_blocks`, `restored_blocks`, `bytes_downloaded`,
  `remaining_bytes`, `in_flight`, `peers` (the connected peers it can ask),
  `progress_ratio` and `estimated_remaining_seconds`. `sat-tui` shows it in
  its services row ([TUI](tui.md)).
  A log line every 1000 blocks restored gives the rate and an estimate of the
  time left.

`getblockchaininfo` carries the same totals under `opreturn_prune`, only on a
node that strips or holds stripped blocks. Its `pruned` field still means
`-prune` only. Prometheus gets `satd_opreturn_strip_examined_height`,
`satd_opreturn_stripped_bytes_total` and `satd_opreturn_stripped_blocks_total`,
and under `restoreopreturns` `satd_opreturn_restore_remaining_blocks`,
`satd_opreturn_restore_restored_blocks_total` and
`satd_opreturn_restore_downloaded_bytes_total`.

`size_on_disk` does not move: it counts the files' apparent size, as Core's
does. Holes do not show in `getblockfileaudit` either, whose referenced bytes
are apparent bytes.

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

A block the node has stored but not yet connected needs none of this. When
the connector reaches one whose record is gone, it asks a peer for the block
itself on the same route, logging
`Stored block has no readable record; fetching it again from a peer`, and
connects the copy. That matters on a pruned node, where `getblockfrompeer`
refuses any block above the tip, as Core's does. Before 0.6.0, pruning could
delete a file that still held such blocks, and the node stopped for good on
the first one.

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

## Upgrading to chainstate schema 7

The chainstate is versioned, and a satd that cannot read an older layout
refuses to open the datadir rather than misinterpret its rows. The refusal
names the remedy:

```
Chainstate schema version mismatch: DB has v6, binary expects v7.
Run with --reindex-chainstate to rebuild from existing block files.
```

`-reindex-chainstate` discards the RocksDB chainstate and replays the block
files into a new one, rebuilding every enabled index inline as it goes. The
block files themselves are never touched, so nothing is downloaded again,
and because the old column families are dropped before the replay starts the
datadir never grows beyond its current size during the rebuild. It is a
single pass over the chain; budget roughly what an `-assumevalid` sync of the
same chain costs on your hardware.

With `upgradechainstate=1` in the configuration, satd runs that rebuild by
itself on the first start, and restarts it if it is interrupted; the app-store
packages and the reference stack set it. See "Upgrading the chainstate
unprompted" in [Initial Block Download & Fast Sync](ibd.md).

A rebuild that is refused before it starts (a pruned node, the replay's
coverage check) leaves the chainstate as it was: the previous release can
still open the datadir. Once the rebuild has started there is no way back but another
rebuild: 0.5.x refuses a schema 7 chainstate as this release refuses theirs.

Two cases need more than that:

- **Pruned nodes.** The replay needs every block, and a pruned node does not
  have them. Such a node has to resync; `-upgradechainstate` says so and
  refuses rather than starting a rebuild it cannot finish.
- **AssumeUTXO nodes.** Unchanged from before: run `backfillindex address`
  once background validation has reached the snapshot base, as the
  snapshot's own coins carry no history behind them.

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
`sat-cli debug storage-footprint` reports the same number per family as
`pending_MB`, so you can check whether the backlog has drained without waiting
for the next diagnostic line.
