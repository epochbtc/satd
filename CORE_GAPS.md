# satd: Gap Analysis vs Bitcoin Core

This document catalogs known gaps between satd and Bitcoin Core, prioritized by
severity. Wallet functionality is intentionally omitted (out of scope — Epoch
uses external wallets).

Last updated: 2026-05-05

---

## P0 — Consensus-Critical

These gaps mean satd may accept invalid blocks or reject valid ones on mainnet
or testnet. Must be fixed before any non-regtest use.

### 1. ~~No witness commitment in mined blocks~~ — FIXED

Coinbase now includes BIP 141 witness commitment output when the block contains
SegWit transactions. `compute_witness_root()` uses wtxids correctly.

### 2. ~~No witness commitment verification for received blocks~~ — FIXED

`check_witness_commitment()` in `validation/block.rs` validates the commitment
hash against the wtxid merkle root and coinbase witness nonce.

### 3. ~~No locktime validation~~ — FIXED

`connect_block()` validates absolute locktimes using Median Time Past per BIP 113
for time-based locktimes, and block height for height-based locktimes.

### 4. ~~No BIP 68 relative locktime (sequence locks)~~ — FIXED

`connect_block()` implements BIP 68 for tx version >= 2: parses disable bit,
time/height flag, and validates against MTP delta or height delta respectively.

### 5. ~~No taproot verification~~ — FIXED

`VERIFY_TAPROOT` flag is included in the bitcoinconsensus verification flags.
All taproot key-path and script-path spends are validated.

### 6. ~~No BIP 34 coinbase height verification~~ — FIXED

`decode_coinbase_height()` in `chain/connect.rs` decodes OP_0, OP_1..OP_16,
and data-push encodings. Block connection verifies the encoded height matches.

---

## P1 — Reliability / Correctness

These gaps cause incorrect behavior under specific conditions (reorgs, network
partitions, edge-case transactions). Won't affect basic regtest usage but will
cause failures in adversarial or production environments.

### 7. ~~Non-atomic reorgs~~ — FIXED

`perform_reorg()` now accumulates all disconnect batches into a single combined
batch and performs one atomic `write_batch()` call.

### 8. ~~Height index not cleaned on disconnect~~ — FIXED

`disconnect_block()` now adds `height_hash_removes` entries to clean the
height→hash mapping on block disconnect.

### 9. ~~No compact block relay (BIP 152)~~ — FIXED

`SendCmpct`, `CmpctBlock`, `GetBlockTxn`, and `BlockTxn` messages are handled.
`compact.rs` implements reconstruction from mempool and pending-block tracking.

### 10. ~~P2P has no timeouts or peer banning~~ — FIXED

Ban scoring implemented with `BAN_THRESHOLD` (100 points). Address-level ban
persistence (24h). 600-second idle timeout. Exponential reconnect backoff.
Split read/write connection to prevent stream misalignment.

### 11. ~~P2P sync has no state machine or IBD detection~~ — FIXED

`is_ibd()` method compares tip height against `headers_tip`. During IBD,
transaction relay is skipped, preventing false-positive peer bans. Block
requests use a 512-block lookahead window with 128-block batches.

### 12. ~~Mempool has no RBF (Replace-By-Fee)~~ — FIXED

Opt-in RBF (BIP 125) and full RBF are both implemented. Configurable via
`-mempoolfullrbf` (default: true, matching Bitcoin Core v28+). Replacement
requires higher absolute fee plus incremental relay fee per weight unit.

### 13. ~~Mempool has no CPFP (Child-Pays-For-Parent)~~ — FIXED

Mempool inputs can reference unconfirmed parent outputs. Full transitive
ancestor set tracking with configurable `-limitancestorcount` (default: 25).

### 14. ~~Fee estimation is not wired~~ — FIXED

`record_block_fees()` is called from `block_processor()` after every successful
block connection. Extracts per-tx fee rates and feeds them to `FeeEstimator`
via `record_block()`. `estimatesmartfee` returns target-aware percentiles.

---

## P2 — Operational / Completeness

Missing features that affect deployment and administration. Not consensus-
critical but expected by operators and tooling.

### 15. ~~No pruning (-prune)~~ — FIXED

`-prune=<MB>` flag enables automatic deletion of old blk*.dat files once the
chain tip is deep enough. Pruned blocks return appropriate errors from RPCs.
`BlockStatus::Pruned` tracks entries whose flat file data has been deleted.

### 16. ~~No transaction index (-txindex)~~ — FIXED

`-txindex` flag enables txid→block_hash lookup stored in RocksDB (CF
`tx_index`). `getrawtransaction` works without a `blockhash` parameter when
txindex is enabled.

### 17. ~~No reindex support (-reindex, -reindex-chainstate)~~ — FIXED

`-reindex-chainstate` clears UTXO/undo/txindex tables and replays all blocks from
flat files using the intact block index. `-reindex` clears everything, scans blk*.dat
files, discovers chain topology via BFS from genesis, and reconnects all blocks.

### 18. ~~No checkpoint validation~~ — FIXED

Hardcoded checkpoints for signet at key heights. During IBD, blocks at checkpoint
heights must match the expected hash or be rejected. Mainnet/testnet checkpoints
can be added from Bitcoin Core's source.

### 19. ~~Missing ~80% of Bitcoin Core config flags~~ — FIXED

44 flags now supported (was 27). Newly added: `-maxconnections`, `-bind`,
`-timeout`, `-addnode`, `-dns`, `-bantime`, `-blockmaxweight`, `-blockmintxfee`,
`-pid`. No-op compatibility flags accepted silently: `-server`, `-daemon`,
`-dbcache`, `-par`. Remaining unsupported flags require new subsystems
(`-proxy`/SOCKS5, `-zmqpub*`/ZMQ, `-rest`/REST API, `-whitelist`) and are
documented as out of scope for Phase 1.

### 20. ~~No mempool policy enforcement~~ — FIXED

Implemented:
- Dust output checks (configurable via `-dustrelayfee`, 0 = disable)
- OP_RETURN data size limits (configurable via `-datacarrier`, `-datacarriersize`)
- Maximum ancestor/descendant count limits (`-limitancestorcount`, `-limitdescendantcount`)
- Mempool expiration (configurable via `-mempoolexpiry`)
- Low-fee eviction when mempool is full (evicts lowest fee-rate entries)
- Standard script type enforcement: rejects non-standard output scripts (P2PKH,
  P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN accepted; bare multisig configurable)

### 21. ~~Missing P2P message types~~ — FIXED (intentional exclusions)

19 of ~20 message types are now handled: `Ping`, `Pong`, `Inv`, `Headers`,
`Block`, `Tx`, `GetHeaders`, `GetData`, `SendHeaders`, `SendCmpct`,
`CmpctBlock`, `GetBlockTxn`, `BlockTxn`, `FeeFilter`, `Addr`, `AddrV2`,
`SendAddrV2`, `NotFound`, `GetAddr`.

Intentionally excluded (same rationale as legacy wallet exclusion):

- `FilterLoad` / `FilterAdd` / `FilterClear` / `MerkleBlock` — BIP 37 bloom
  filters. Deprecated in Bitcoin Core (disabled by default since v0.19, 2019).
  Known privacy leak and DoS vector. No modern wallet uses them.
- `MemPool` — rarely used, mostly by bloom filter clients.

### 22. ~~Incomplete getblocktemplate (BIP 22/23)~~ — FIXED

All BIP 22/23 fields now present: `longpollid`, `expires`, and
`default_witness_commitment` (computed from template transaction wtxids).

### 23. ~~Missing RPCs~~ — FIXED

77 of ~77 non-wallet Bitcoin Core RPCs are implemented.

- ~~`prioritisetransaction`~~ — FIXED: adjusts fee delta for mining priority
- ~~`signrawtransactionwithkey`~~ — FIXED: P2PKH, P2WPKH, P2SH-P2WPKH, P2TR key-path signing
- ~~`combinepsbt` / `finalizepsbt` / `utxoupdatepsbt`~~ — FIXED (were already implemented)
- ~~`disconnectnode`~~ — FIXED (was already implemented, not documented)

### 24. ~~Checksum handling~~ — FIXED

Handled by the `bitcoin` crate's `deserialize` — invalid checksums in P2P
messages are rejected during deserialization.

---

## Additional Completions (not in original gap list)

### A1. ~~Storage backend migration~~ — DONE

The original Phase 1 plan started on a pure-Rust embedded KV store; the
chainstate is now on **RocksDB** (`rocksdb = 0.24`, zstd + lz4 compression
enabled). RAII write-mode guard with fail-closed durability transitions
(PR #56), jemalloc on the daemon, and the BulkLoad / Durable WAL flip
during IBD live in `node/src/storage/rocksdb_store.rs`. No `redb`
runtime dependency remains; legacy `chainstate.redb` paths are detected
on startup and the daemon refuses to start with a migration message
(`satd/src/main.rs:156`).

### A2. ~~Address-history index~~ — DONE

`node-index` crate provides per-scripthash funding + spending CFs over
the same RocksDB instance, updated atomically with `connect_block` /
`disconnect_block`. Powers the native Esplora REST and Electrum protocol
servers. Mempool variant in-memory; subscription registry per-scripthash;
deferred AssumeUTXO backfill via `backfillindex address`. See
`ADDRESS_INDEX.md`.

### A3. ~~Esplora REST server~~ — DONE

`esplora-handlers` crate; on by default on `127.0.0.1:3000`; wire-shape
parity with blockstream.info / mempool.space within the implemented
endpoint set. Cookie + userpass auth; CORS; SSE live updates. Esplora
requires `--addressindex=1` and `--txindex=1` (auto-enforced). See
`docs/api/esplora.md`.

### A4. ~~Electrum protocol server~~ — DONE

`electrum-proto` crate; vendored protocol code from `romanz/electrs`
(MIT) over our own `AddressIndex` trait. Plain TCP + optional TLS;
JSON-RPC batches; full v1.4.5 method set. `--electrum=1` enables;
loopback default. See `OPERATOR_ERGONOMICS.md`.

### A5. ~~BIP 157/158 compact block filters~~ — DONE

`node-filter-index` crate (BIP 158 codec) + `node/src/index/filter`
(emission, backfill, P2P service). Atomic `connect_block` /
`disconnect_block` writes; chained filter headers; deferred backfill
via `backfillindex blockfilter`. P2P service advertises
`NODE_COMPACT_FILTERS` (bit 6) via `--peerblockfilters=1` and answers
`getcfilters` / `getcfheaders` / `getcfcheckpt`.

### A6. ~~Mempool subscription stream~~ — DONE

`subscribemempool` JSON-RPC WS subscription emitting `enter` /
`leave_confirmed` / `leave_evicted` (with `reason: full_pool | expiry`)
/ `leave_replaced` (with `replacing_txid`). Bulk `getmempoolentry`,
`getmempoolhistory` ring buffer.

### A7. ~~Persistent reorg log + webhook~~ — DONE

JSONL append-only log at `$datadir/reorg.log`; in-memory 256-record
ring; `getreorghistory` RPC; optional `--reorg-webhook=<url>` HTTP POST
with `--reorg-webhook-secret=<secret>` HMAC-SHA256 signature.

### A8. ~~Ops-surface endpoints~~ — DONE

Prometheus `/metrics`, `/healthz`, `/readyz` on `--metricsbind`. Stable
metric schema (see `node/src/metrics.rs`). Structured-JSON tracing
spans (`--log-format=json`). `--profile=<preset>` config presets +
`getconfig` RPC.

### A9. ~~Events bus (gRPC + ZMQ frames)~~ — DONE

`satd-events` crate with gRPC server and ZMQ publisher sinks for
chain + mempool envelopes. Edge-identity + heartbeat. Distinct from
Bitcoin Core's `-zmqpub*` topic-pub model (we ship a structured event
envelope, not raw block / tx topics).

### A10. ~~MCP server~~ — DONE

`satd-mcp` crate exposes ops-surface RPCs as Model Context Protocol
tools. stdio transport (`--mcp-stdio`) + streamable-HTTP transport
(`--mcp-port`).

---

## Summary

| Priority | Total | Fixed | Partial | Open | Description |
|----------|-------|-------|---------|------|-------------|
| **P0** | 6 | 6 | 0 | 0 | All consensus-critical gaps closed |
| **P1** | 8 | 8 | 0 | 0 | All reliability gaps closed |
| **P2** | 11 | 11 | 0 | 0 | All gaps closed |
| **Beyond Core** | 10 | 10 | 0 | 0 | satd-specific surfaces |
| **Total** | 35 | 35 | 0 | 0 | |

All 25 original gaps remain resolved; A1–A10 are surfaces beyond Core
parity that satd ships natively. satd serves wallets and operator tooling
out of one binary that Core requires `bitcoind + electrs + esplora +
prometheus-exporter + nginx` to cover.

Intentional exclusions: legacy (BDB) wallet, BIP 37 bloom filters,
SOCKS5 proxy, Bitcoin Core-style `-zmqpub*` raw-topic publication
(satd ships a structured event envelope via `satd-events` instead).
