# Initial Block Download & Fast Sync

This chapter covers getting a satd node to the chain tip: AssumeUTXO fast sync,
the `assumevalid` script-verification skip options, dual-engine shadow
verification, and the IBD performance and storage tuning flags. Points that
differ from Bitcoin Core are called out throughout.

For the per-key table of defaults, reload disposition, and Core-vs-satd status,
see the [Configuration Flag Reference](config-reference.md). This chapter
explains how the pieces work and when to use them.

## How satd syncs: the IBD pipeline

satd does not download and verify blocks one at a time in lockstep. IBD is a
pipeline that keeps the network, the disk, and the CPU busy at the same time.

- **Parallel block download.** satd fetches blocks from many peers at once, the
  way BitTorrent downloads pieces from a swarm. Download throughput scales with
  aggregate peer bandwidth instead of one peer's round-trip time. `-maxahead`
  bounds how far ahead of the connect tip downloaded blocks may be staged.
- **Background prefetch workers.** `-prefetchworkers` threads pre-read blocks
  from the flat files without holding the chainstate lock. They deserialize
  each block, compute txids, run the context-free transaction validation, and
  resolve the block's UTXO inputs into the coin cache. All of this happens off
  the connect thread. When the connect thread reaches a block, its inputs are
  already cached.
- **Speculative script verification.** Prefetch workers verify scripts ahead of
  connection and mark the transactions they verified. The connect thread does
  not verify them again. In `assumevalid` mode, the connect step can then go
  straight to applying UTXO changes for the trusted range.
- **Asynchronous shadow verification.** The second consensus engine (see below)
  runs on its own worker pool, never on the connect path. It adds almost no
  wall-clock cost.

Network I/O, block pre-processing, script verification, and chainstate writes
overlap instead of running one after another.

## AssumeUTXO fast sync

AssumeUTXO makes a node usable in minutes instead of days. The node loads a
UTXO-set snapshot at a recent height and serves wallets and queries from it
immediately. It validates the historical chain from genesis to the snapshot in
the background. satd's implementation is shipped and Bitcoin Core-compatible.

### Loading a snapshot

- **`loadtxoutset <path>`** (RPC) loads a UTXO snapshot file. The node then
  holds two chainstates. The snapshot chainstate becomes the active tip;
  wallets, Esplora, Electrum, and RPC serve from it immediately. A background
  chainstate validates from genesis up to the snapshot's anchor. When
  background validation completes, the snapshot is marked validated and the
  node is a normal fully-validated node.
- **`--fast-start=<url|path>`** (startup flag) automates the sequence. satd
  downloads the snapshot (or reads a local file), waits for header sync to
  reach the snapshot's anchor, and calls `loadtxoutset` itself. Remote sources
  must be `https://`; plain `http://` is refused, and TLS certificates are
  verified. Use `--fast-start-sha256=<hex>` to pin the download's digest.
  Download progress appears in the pre-RPC startup TUI gauge.
- **`getchainstates`** (RPC, Core 27+ compatible) reports progress. A node with
  no snapshot reports a single fully-validated chainstate. After `loadtxoutset`
  it reports a second, background chainstate, and the snapshot entry carries
  `snapshot_blockhash` and `validated: false` until background validation
  finishes.
- **`dumptxoutset <path>`** (RPC) writes a Bitcoin Core-compatible UTXO
  snapshot from your own node.

### Trust model

At load, satd verifies the snapshot file against a hardcoded anchor hash. A
tampered or wrong-height snapshot is rejected no matter where it came from.
satd hosts no snapshots and does no P2P snapshot fetch; the operator names a
trusted `https://` source or a local file. The historical chain is still fully
validated in the background. AssumeUTXO shortens the time to a usable node; it
does not skip validation.

> **Difference from Bitcoin Core.** The RPCs (`loadtxoutset`, `getchainstates`,
> `dumptxoutset`) and the two-chainstate model match Core. The `--fast-start`
> download-verify-load flag and `--fast-start-sha256` are satd extensions. Core
> requires a manual `loadtxoutset` against a file you fetched yourself.

## Script-verification skip: `assumevalid`

`-assumevalid` controls how much script verification IBD performs. satd
accepts three forms. The third is a satd extension.

| Value | Meaning | Compat |
|---|---|---|
| `-assumevalid=<blockhash>` | Skip script verification at or below that block. The hash must already be in the block index. A per-network default ships in the binary (for example, mainnet height 840,000), as in Core. | Core |
| `-assumevalid=0` | Verify everything; no skipping. | Core |
| `-assumevalid=all` | Skip script verification for blocks older than a cutoff age; verify recent and new blocks in full. The cutoff is `-assumevalidage` (default 86400 s, 24 h). | satd extension |

> **Difference from Bitcoin Core.** Core's `-assumevalid` takes a block hash or
> `0`. satd adds the `all` keyword and `-assumevalidage`, which trust the deep
> chain and verify the last day without pinning a hash. This suits recurring
> fast re-syncs. `assumevalid` is independent of AssumeUTXO, which concerns the
> UTXO set rather than script verification; the two compose.

## Consensus engine & shadow verification

satd ships two independent script-verification engines: the C++
`libbitcoinconsensus` FFI and a from-scratch Rust verifier. It can run both
together and verify every script twice. Bitcoin Core has no equivalent.

Read a mode name as "which engine is the shadow". In `<engine>-shadow`, the
named engine is the shadow, the non-authoritative one. The other engine is
primary; its verdict is what the node acts on. The shadow re-verifies in the
background and logs any disagreement. So:

- `rust-shadow`: the Rust engine is the shadow; C++ is primary.
- `cpp-shadow`: the C++ engine is the shadow; Rust is primary.

`-consensus=<mode>`:

| Mode | Primary (authoritative) | Shadow |
|---|---|---|
| `rust-shadow` (default) | C++ `libbitcoinconsensus` | Rust (logs mismatches) |
| `cpp-shadow` | Rust | C++ (logs mismatches) |
| `cpp` | C++ `libbitcoinconsensus` | none (single engine) |
| `rust` | Rust | none (single engine) |

The Rust engine passes Bitcoin Core's script test suite. Shadow verification
against `libbitcoinconsensus` across the whole mainnet chain, genesis to about
height 945,000, found zero divergence. The Rust engine is also usually faster
than the C++ FFI: it avoids per-call FFI marshaling and uses a process-global,
verification-only cached `secp256k1` context. `cpp-shadow` (Rust primary, C++
shadow) is therefore the high-performance pairing.

`rust-shadow` (C++ primary) stays the default out of conservatism. Running two
independently written engines against each other is satd's core safety
property, and `libbitcoinconsensus` is the most widely deployed implementation.
The plan is to promote the Rust engine to primary as it accumulates production
mileage; `cpp-shadow` is that step. Treat the single-engine `rust` mode with
care. The engine itself is proven, but either single-engine mode gives up the
dual-engine cross-verification. satd prints a caution at startup when the
single-engine `rust` mode is selected.

The shadow engine runs on a bounded background worker pool, so it consumes
spare CPU without slowing block connection. Two flags tune it:

- `-shadowworkers=<n>` (default 4): background shadow-verification threads.
- `-shadowqueuesize=<n>` (default 4194304): shadow work-queue capacity. When
  the queue is full, shadow work is dropped, and an aggregated WARN is logged
  at most once per 5 s. The primary engine still verifies every script, so
  correctness is unaffected.

> **Difference from Bitcoin Core.** Core has a single C++ engine and no shadow
> mode. satd's default runs both engines at once. `-consensus`,
> `-shadowworkers`, and `-shadowqueuesize` are satd-specific.

## IBD performance & storage tuning

These flags bound or accelerate IBD. Full defaults and semantics are in the
[Configuration Flag Reference](config-reference.md).

| Flag | Default | Notes |
|---|---|---|
| `-dbcache=<MB\|auto>` | 450 | Write-cache size. `auto` (satd) starts a controller that resizes the RocksDB block cache and CoinCache against `/proc/meminfo` pressure. Core's `-dbcache` is a static number only. |
| `-par=<n>` | unset | Script-verification threads (Core name). satd's connect path manages its own parallelism, so `-par` does not size it directly. When `-shadowworkers` is unset, a positive `-par` value is used as the shadow-verification worker count; otherwise the default of 4 applies. |
| `-prefetchworkers=<n>` | CPU cores | (satd) IBD block-prefetch worker threads. |
| `-maxahead=<n\|N%\|all>` | 50000 | (satd) How many blocks IBD may stage ahead of the connect tip. |
| `-storageprofile=<ssd\|hdd>` | ssd | (satd) RocksDB tuning class for the storage medium. |
| `-maxopenfiles=<n>` | 2048 | (satd) RocksDB `max_open_files` cap (`-1` = unlimited). |
| `-rocksdbbackgroundjobs` / `-rocksdbsubcompactions` / `-rocksdbwalmb` | from profile | (satd) Advanced RocksDB overrides. |
| `-compactionl0at=<n>` / `-ibdl0pauseat=<n>` | 16 / 64 | (satd) Force chainstate compaction at N L0 SST files; pause the IBD connector at N L0 files so compaction can catch up. |
| `-compactionintervalsecs` / `-compactiondiagintervalsecs` | 1800 / 60 | (satd) Periodic forced compaction and pending-compaction diagnostics (`0` disables). |
| `-stallwatchdogsecs` / `-stallabortsecs` | 300 / 300 | (satd) If the tip does not advance for N seconds, dump forensics, then abort after a further grace period. A silent IBD wedge becomes a loud, debuggable failure. |

`-dbcache`, `-prune`, `-txindex`, `-assumevalid`, and `-reindex` keep Core's
names and meanings. The rest of the table is satd-specific tuning with no Core
equivalent.

## Reindexing

- `-reindex` rebuilds both the block index and the chainstate from the block
  files on disk (Core-compatible).
- `-reindex-chainstate` rebuilds only the chainstate (the UTXO set) from the
  existing block files, and preserves the flat block files (Core-compatible).
  It is faster than a full `-reindex` when only the chainstate is suspect.

A reindex on a synced mainnet node runs for hours. The shipped `systemd` unit
handles this without tripping the start timeout; see "Reindex resilience" in
[Packaging](packaging.md).

## Differences from Bitcoin Core at a glance

- `assumevalid=all` with `assumevalidage`: verify-recent-only mode. Core takes
  a hash or `0`.
- Dual-engine shadow verification (`-consensus`, `-shadowworkers`,
  `-shadowqueuesize`): the default runs the C++ and Rust engines together.
  Core has one engine.
- `--fast-start` / `--fast-start-sha256`: one-flag AssumeUTXO
  download-verify-load. Core requires a manual `loadtxoutset`.
- `-dbcache=auto`: adaptive cache sizing. Core's is static.
- satd-only IBD and storage options: `-prefetchworkers`, `-maxahead`,
  `-storageprofile`, `-maxopenfiles`, the `-rocksdb*` and `-compaction*`
  families, `-ibdl0pauseat`, and the stall watchdog.
- `-par` is accepted for config compatibility. It does not size the connect
  path, but a positive value feeds `-shadowworkers` when that flag is unset.
