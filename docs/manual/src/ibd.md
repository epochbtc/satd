# Initial Block Download & Fast Sync

This chapter covers getting a satd node to the chain tip: **AssumeUTXO** fast
sync, the script-verification skip knobs (`assumevalid`), satd's **dual-engine
shadow verification**, and the IBD performance/storage tuning flags — with the
points that **differ from Bitcoin Core** called out throughout.

For the exhaustive per-key table (defaults, reload disposition, Core-vs-satd) see
the [Configuration Flag Reference](config-reference.md); this chapter is the
how-and-why.

## How satd syncs: the IBD pipeline

satd does not download and verify blocks one-at-a-time in lockstep. IBD is a
**pipeline** that keeps the network, disk, and CPU all busy at once:

- **Swarm-style block download.** Like BitTorrent, satd fetches blocks **in
  parallel from many peers** rather than serially from one, so download
  throughput scales with peer bandwidth instead of a single peer's round-trip.
  `-maxahead` bounds how far ahead of the connect tip the swarm may stage blocks.
- **Background prefetch workers.** `-prefetchworkers` threads pre-read blocks from
  the flat files (without holding the chainstate lock), deserialize them, compute
  txids, run the context-free transaction checks, and **speculatively resolve
  (cache-warm) each block's UTXO inputs** — all *off* the connect thread, so when
  the connect thread reaches a block its inputs are already hot in cache.
- **Speculative script verification.** Ahead of connection, prefetch workers
  pre-verify scripts; verified transactions are marked so the connect thread
  doesn't re-verify them. (In `assumevalid` mode this lets the connect step skip
  straight to applying UTXO changes for the trusted range.)
- **Asynchronous shadow verification.** The second consensus engine (see below)
  runs on its own worker pool, never on the connect path, so dual-engine
  cross-checking adds essentially no wall-clock cost.

The net effect: network I/O, block pre-processing, script verification, and
chainstate writes overlap instead of serializing.

## AssumeUTXO fast sync

AssumeUTXO lets a node become usable in **minutes instead of days** by loading a
UTXO-set snapshot at a recent height, serving wallets/queries from it immediately,
and validating the historical chain (genesis → snapshot) in the **background**.
satd's implementation is Bitcoin Core-compatible and **fully shipped**.

### Loading a snapshot

- **`loadtxoutset <path>`** (RPC) — load a UTXO snapshot file. satd splits into
  **two chainstates**: the **snapshot chainstate** becomes the active tip
  (wallets, Esplora, Electrum, RPC all serve from it right away), while a
  **background chainstate** validates from genesis up to the snapshot's anchor.
  When background validation completes, the snapshot is marked validated and the
  node is a normal fully-validated node.
- **`--fast-start=<url|path>`** (startup flag) — the one-flag UX: satd downloads
  the snapshot (or reads a local file), waits for header sync to reach the
  snapshot's anchor, and calls `loadtxoutset` automatically — no manual step.
  Remote sources **must be `https://`** (plain `http://` is refused; TLS certs are
  validated). Pair with **`--fast-start-sha256=<hex>`** to pin the download's
  digest. Download progress renders in the pre-RPC startup TUI gauge.
- **`getchainstates`** (RPC, Core 27+ compatible) — observe progress: a node with
  no snapshot reports a single fully-validated chainstate; after `loadtxoutset` it
  reports a second (background) chainstate, and the snapshot entry carries
  `snapshot_blockhash` + `validated: false` until background validation finishes.
- **`dumptxoutset <path>`** (RPC) — emit a Bitcoin Core-compatible UTXO snapshot
  from your own node.

### Trust model

The snapshot file is verified against satd's **hardcoded anchor hash** at load, so
a tampered or wrong-height snapshot is rejected regardless of where it came from.
satd deliberately **hosts no snapshots and does no P2P snapshot fetch** — the
operator names a trusted `https://` source (or a file). The historical chain is
*still fully validated* in the background; AssumeUTXO shortens time-to-usable, it
does not skip validation permanently.

> **Difference from Bitcoin Core.** The RPCs (`loadtxoutset`, `getchainstates`,
> `dumptxoutset`) and the two-chainstate model match Core. The **`--fast-start`**
> one-flag download-verify-load UX (and `--fast-start-sha256`) is a satd
> extension; Core requires a manual `loadtxoutset` against a file you fetched
> yourself.

## Script-verification skip: `assumevalid`

`-assumevalid` controls how much script verification IBD performs. satd accepts
three forms — and the third is a satd extension:

| Value | Meaning | Compat |
|---|---|---|
| `-assumevalid=<blockhash>` | Skip script checks **at or below** that block (the hash must be in the block index first). A sensible per-network default ships in the binary (e.g. mainnet height 840,000), exactly like Core. | Core |
| `-assumevalid=0` | **Verify everything** — no skipping. | Core |
| `-assumevalid=all` | Skip script checks for blocks **older than a cutoff age**, fully verifying recent and new blocks. The cutoff is **`-assumevalidage`** (default 86400 s / 24 h). | **satd extension** |

> **Difference from Bitcoin Core.** Core's `-assumevalid` is a block hash (or `0`).
> satd adds the **`all`** keyword plus **`-assumevalidage`**, so you can say "trust
> the deep chain, verify the last day" without pinning a specific hash — useful for
> recurring fast re-syncs. `assumevalid` skipping is independent of AssumeUTXO
> (which is about the UTXO set, not script checks), though they compose.

## Consensus engine & shadow verification

satd ships **two independent script-verification engines** — the C++
`libbitcoinconsensus` FFI and a from-scratch Rust verifier — and can run them
together, cross-checking every script. This has **no equivalent in Bitcoin Core**.

**Read the name as "which engine is the shadow."** In `<engine>-shadow`, the
named engine is the **shadow** (the non-authoritative cross-checker); the *other*
engine is **primary/authoritative** — its verdict is what the node actually acts
on, and the shadow only re-checks in the background and logs any disagreement. So,
counter-intuitively at first:

- **`rust-shadow`** → the **Rust** engine is the shadow → **C++ is primary.**
- **`cpp-shadow`** → the **C++** engine is the shadow → **Rust is primary.**

`-consensus=<mode>`:

| Mode | Primary (authoritative) | Shadow (cross-check) |
|---|---|---|
| `rust-shadow` *(default)* | **C++** `libbitcoinconsensus` | Rust (logs mismatches) |
| `cpp-shadow` | **Rust** | C++ (logs mismatches) |
| `cpp` | C++ `libbitcoinconsensus` | — (single engine) |
| `rust` | Rust — single engine, **no cross-check** | — (single engine) |

The Rust engine is no toy: it **passes Bitcoin Core's script test suite** and has
been **shadow-validated against `libbitcoinconsensus` across the entire mainnet
chain (genesis → ~945k) with zero divergence**. It is also **typically faster
than the C++ FFI** — it avoids the per-call FFI marshaling overhead and uses a
process-global, verification-only cached `secp256k1` context, which is why
`cpp-shadow` (Rust authoritative, C++ shadow) is the high-performance pairing.

Given all that, why is `rust-shadow` (C++ authoritative) still the default? Pure
conservatism: keeping a second, independently-written engine as the authoritative
check is satd's core safety property, and C++ `libbitcoinconsensus` is the most
battle-tested implementation in existence. The plan is to promote Rust to primary
as it accrues more authoritative-in-production mileage — `cpp-shadow` is exactly
that step. The single-engine `rust` mode is the one to be cautious with: not
because the engine is unproven, but because running *either* engine alone forgoes
the dual-engine cross-check that is satd's core safety property. satd prints a
caution at startup when you select the single-engine `rust` mode.

The shadow engine runs on a **bounded background worker pool**, so it consumes
spare CPU without slowing block connection — shadow verification is essentially
free in wall-clock terms. Two knobs tune it:

- **`-shadowworkers=<n>`** (default 4) — background shadow-verification threads.
- **`-shadowqueuesize=<n>`** (default 4194304) — shadow work-queue capacity. When
  the queue is full, shadow work is **dropped** (the authoritative engine still
  verifies every script — correctness is never affected) and an aggregated WARN is
  emitted at most once per 5 s.

> **Difference from Bitcoin Core.** Core has a single C++ engine and no shadow
> mode. satd's default cross-checks two engines at runtime; `-consensus`,
> `-shadowworkers`, and `-shadowqueuesize` are all satd-specific.

## IBD performance & storage tuning

These bound or accelerate IBD. The full defaults/semantics are in the
[Configuration Flag Reference](config-reference.md); the Core-relevant notes:

| Flag | Default | Notes |
|---|---|---|
| `-dbcache=<MB\|auto>` | 450 | Write-cache size. **`auto`** (satd) spawns a controller that resizes RocksDB block cache + CoinCache against `/proc/meminfo` pressure — Core's `-dbcache` is a static number only. |
| `-par=<n>` | — | Script-verification threads. **Accepted for Core compatibility but a no-op** in satd (the shadow pool / connect path manage their own parallelism). |
| `-prefetchworkers=<n>` | CPU cores | *(satd)* IBD block-prefetch worker threads. |
| `-maxahead=<n\|N%\|all>` | 50000 | *(satd)* how many blocks IBD may stage ahead of the connect tip. |
| `-storageprofile=<ssd\|hdd>` | ssd | *(satd)* RocksDB tuning class for the storage medium. |
| `-maxopenfiles=<n>` | 2048 | *(satd)* RocksDB `max_open_files` cap (`-1` = unlimited). |
| `-rocksdbbackgroundjobs` / `-rocksdbsubcompactions` / `-rocksdbwalmb` | from profile | *(satd)* advanced RocksDB overrides. |
| `-compactionl0at=<n>` / `-ibdl0pauseat=<n>` | 16 / 64 | *(satd)* force chainstate compaction at N L0 SST files; pause the IBD connector at N L0 files to let compaction catch up. |
| `-compactionintervalsecs` / `-compactiondiagintervalsecs` | 1800 / 60 | *(satd)* periodic forced-compaction and pending-compaction diagnostics (`0` disables). |
| `-stallwatchdogsecs` / `-stallabortsecs` | 300 / 300 | *(satd)* if the tip doesn't advance for N seconds, dump forensics, then abort after a further grace period — turns a silent IBD wedge into a loud, debuggable failure. |

`-dbcache` / `-prune` / `-txindex` / `-assumevalid` / `-reindex` keep Core's
names and meanings; the rest of the table is satd-specific tuning that Core has no
equivalent for.

## Reindexing

- **`-reindex`** — rebuild **both** the block index and the chainstate from the
  block files on disk (Core-compatible).
- **`-reindex-chainstate`** — rebuild only the UTXO set / chainstate from the
  existing block files, preserving the flat block files (Core-compatible). Faster
  than a full `-reindex` when only the chainstate is suspect.

A reindex on a synced mainnet node runs for hours; the shipped `systemd` unit
handles this without tripping the start timeout (see [Packaging](packaging.md) →
"Reindex resilience").

## Differences from Bitcoin Core at a glance

- **`assumevalid=all` + `assumevalidage`** — verify-recent-only mode (Core: hash or `0`).
- **Dual-engine shadow verification** (`-consensus`, `-shadowworkers`, `-shadowqueuesize`) — default cross-checks C++ and Rust engines; Core has one engine.
- **`--fast-start` / `--fast-start-sha256`** — one-flag AssumeUTXO download-verify-load (Core: manual `loadtxoutset`).
- **`-dbcache=auto`** — adaptive cache sizing (Core: static).
- **satd-only IBD/storage knobs** — `-prefetchworkers`, `-maxahead`, `-storageprofile`, `-maxopenfiles`, the `-rocksdb*` and `-compaction*` family, `-ibdl0pauseat`, and the stall watchdog.
- **`-par` is a no-op** (accepted for config compatibility).
