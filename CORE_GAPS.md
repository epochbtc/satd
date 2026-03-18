# satd: Gap Analysis vs Bitcoin Core

This document catalogs known gaps between satd and Bitcoin Core, prioritized by
severity. Wallet functionality is intentionally omitted (out of scope — Epoch
uses external wallets).

Last updated: 2026-03-18

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

### 12. Mempool has no RBF (Replace-By-Fee)

**File:** `node/src/mempool/pool.rs`

When a transaction's input conflicts with an existing mempool entry, it is
rejected with `ConflictingSpend`. BIP 125 (opt-in RBF) and full RBF are not
implemented. There is no fee comparison or replacement logic.

### 13. Mempool has no CPFP (Child-Pays-For-Parent)

**File:** `node/src/mempool/pool.rs`

Inputs referencing unconfirmed transactions (outputs from other mempool entries)
are rejected with `MissingInputs`. There is no ancestor/descendant tracking or
package fee rate computation.

### 14. Fee estimation is not wired

**File:** `node/src/mempool/fee.rs`

`FeeEstimator` struct exists with a percentile-based implementation, but
`record_block()` is never called from the block connection path. The RPC
`estimatesmartfee` falls back to a hardcoded 1 sat/vB default.

---

## P2 — Operational / Completeness

Missing features that affect deployment and administration. Not consensus-
critical but expected by operators and tooling.

### 15. No pruning (-prune)

Full blockchain must be stored. No flat file deletion for old blocks, no
automatic disk space management.

### 16. No transaction index (-txindex)

`getrawtransaction` requires a `blockhash` parameter for confirmed transactions.
Without `-txindex`, there is no txid→block reverse lookup.

### 17. No reindex support (-reindex, -reindex-chainstate)

If RocksDB becomes corrupted, the node cannot rebuild from flat files. Must
delete the chainstate directory and resync from peers.

### 18. No checkpoint validation

No hardcoded checkpoints for known block hashes at specific heights. Speeds up
IBD and protects against long-range attacks.

### 19. Missing ~80% of Bitcoin Core config flags

Only basic flags are supported: `-regtest`, `-testnet`, `-signet`, `-datadir`,
`-rpcport`, `-rpcuser`, `-rpcpassword`, `-listen`, `-port`, `-connect`,
`-assumevalid`. Missing: `-proxy`, `-maxconnections`, `-dbcache`, `-debug`,
`-pid`, and ~70 others.

### 20. No mempool policy enforcement

**File:** `node/src/mempool/pool.rs`

Missing:
- Dust output checks (outputs below relay dust threshold)
- Standard script type enforcement (non-standard scripts accepted)
- OP_RETURN data size limits
- Maximum ancestor/descendant count limits
- Mempool expiration (entries persist forever until confirmed or conflicted)
- Low-fee eviction (when full, new txs are rejected instead of evicting lowest-fee)

### 21. Missing P2P message types

13 of ~20 message types are handled: `Ping`, `Pong`, `Inv`, `Headers`,
`Block`, `Tx`, `GetHeaders`, `GetData`, `SendHeaders`, `SendCmpct`,
`CmpctBlock`, `GetBlockTxn`, `BlockTxn`. Not handled:

- `Addr` / `AddrV2` (peer discovery)
- `MemPool` (mempool sync)
- `FeeFilter` (min fee relay)
- `NotFound` (missing data notification)
- `FilterLoad` / `FilterAdd` / `FilterClear` (bloom filters)

### 22. Incomplete getblocktemplate (BIP 22/23)

**File:** `node/src/rpc/mining.rs`

Missing fields: `longpollid`, `expires`, `rules`, `vbavailable`, `vbrequired`,
`capabilities`, `default_witness_commitment`. Sufficient for basic regtest
mining but not compatible with production mining software.

### 23. Missing RPCs

~26 of ~150 Bitcoin Core RPCs are implemented. Notable missing RPCs beyond wallet:

- `testmempoolaccept` — dry-run tx validation
- `getmempoolentry` — single mempool tx details
- `getmempoolancestors` / `getmempooldescendants` — dependency queries
- `getmininginfo` — mining status
- `prioritisetransaction` — fee bumping for miners
- `createrawtransaction` / `combinerawtransaction` — tx construction
- `signrawtransactionwithkey` — signing without wallet
- `decodescript` — script analysis
- `getblockstats` — per-block statistics
- `getchaintips` — fork information
- `waitforblock` / `waitforblockheight` — long-polling
- `verifychain` — check chain database integrity

---

## Summary

| Priority | Total | Fixed | Open | Description |
|----------|-------|-------|------|-------------|
| **P0** | 6 | 6 | 0 | All consensus-critical gaps closed |
| **P1** | 8 | 5 | 3 | RBF, CPFP, fee estimation remain |
| **P2** | 11 | 0 | 11 | Operational: pruning, txindex, config, policy, RPCs |
| **Total** | 25 | 11 | 14 | |

All P0 consensus issues are resolved. satd is safe for signet/testnet IBD and
block validation. The remaining P1 items (mempool improvements) are needed for
production relay and mining. P2 items are operational polish for drop-in
Bitcoin Core compatibility.
