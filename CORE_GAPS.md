# btcd: Gap Analysis vs Bitcoin Core

This document catalogs known gaps between btcd and Bitcoin Core, prioritized by
severity. Wallet functionality is intentionally omitted (out of scope — Epoch
uses external wallets).

Last updated after M6 completion.

---

## P0 — Consensus-Critical

These gaps mean btcd may accept invalid blocks or reject valid ones on mainnet
or testnet. Must be fixed before any non-regtest use.

### 1. No witness commitment in mined blocks

**File:** `node/src/mining/miner.rs:108-133`

`build_coinbase()` creates a single output paying the miner. BIP 141 requires a
second OP_RETURN output containing the witness commitment hash
(`SHA256(SHA256(witness_root || witness_nonce))`). Without it, any block
containing SegWit transactions is invalid.

Additionally, `compute_merkle_root()` (line 136) uses `compute_txid()` (txids)
rather than wtxids. The header merkle root correctly uses txids, but the witness
root (for the commitment) must use wtxids — and this second root is never
computed.

**Impact:** Cannot mine valid blocks containing witness transactions.

### 2. No witness commitment verification for received blocks

**File:** `node/src/validation/block.rs:8-47`

`check_block()` validates the merkle root and coinbase structure but never checks
the witness commitment. BIP 141 mandates that blocks with any witness transaction
must include a valid commitment in the coinbase. btcd accepts blocks without one.

**Impact:** Will accept invalid blocks from peers that omit or forge the witness
commitment.

### 3. No locktime validation

**Files:** `node/src/chain/connect.rs`, `node/src/validation/tx.rs`

No code checks that `tx.lock_time <= block.header.time` (or block height for
height-based locktimes) for transactions included in a block. Transactions with
future locktimes are accepted unconditionally.

BIP 113 further requires using Median Time Past instead of block timestamp for
locktime comparison — also missing.

**Impact:** Transactions that should be time-locked can be mined prematurely.

### 4. No BIP 68 relative locktime (sequence locks)

**Files:** `node/src/chain/connect.rs`, `node/src/validation/tx.rs`

BIP 68 redefines the transaction `nSequence` field for non-coinbase inputs. If
bit 31 is unset, the sequence value encodes a relative locktime (either
block-height-based or time-based). btcd never interprets sequence values beyond
the coinbase scriptSig length check.

BIP 112 (OP_CHECKSEQUENCEVERIFY) is passed to bitcoinconsensus as a flag, so
the *script opcode* is verified, but the underlying consensus rule that enforces
the actual locktime constraint is not implemented in btcd's block connection
logic.

**Impact:** Transactions violating relative locktime can be included in blocks.

### 5. No taproot verification

**File:** `node/src/validation/script.rs:36-41`

The bitcoinconsensus flags are hardcoded to pre-taproot:
```
VERIFY_P2SH | VERIFY_DERSIG | VERIFY_CHECKLOCKTIMEVERIFY |
VERIFY_CHECKSEQUENCEVERIFY | VERIFY_WITNESS | VERIFY_NULLDUMMY
```

bitcoinconsensus 0.106 (Bitcoin Core 26.0) supports taproot, but the
`VERIFY_TAPROOT` flag is not included. Taproot key-path and script-path spends
are not validated.

**Impact:** Taproot signatures are not verified. Invalid taproot spends will be
accepted. Valid P2TR transactions work only because they pass the witness check
without taproot-specific validation.

### 6. No BIP 34 coinbase height verification

**File:** `node/src/validation/tx.rs:44-49`

`check_transaction()` verifies the coinbase scriptSig is 2–100 bytes long, but
never decodes or checks that the encoded height matches the block height. The
miner correctly *encodes* height (miner.rs:110), but the validator doesn't
verify it.

**Impact:** Blocks with incorrect height in the coinbase are accepted.

---

## P1 — Reliability / Correctness

These gaps cause incorrect behavior under specific conditions (reorgs, network
partitions, edge-case transactions). Won't affect basic regtest usage but will
cause failures in adversarial or production environments.

### 7. Non-atomic reorgs

**File:** `node/src/chain/state.rs:312-347`

`perform_reorg()` calls `store.write_batch()` once per disconnected block in a
loop. If the process crashes mid-reorg (after disconnecting 3 of 5 blocks), the
chain state is left in an inconsistent partially-rewound state.

Bitcoin Core uses a single atomic write for the entire disconnect+reconnect
sequence.

**Fix:** Accumulate all disconnect batches into one, or use a write-ahead log.

### 8. Height index not cleaned on disconnect

**File:** `node/src/chain/disconnect.rs:9-39`

`disconnect_block()` restores spent UTXOs and updates the tip, but does NOT
remove or update `height_hash_puts`. After disconnecting block at height N, the
height→hash index still points to the old (now-disconnected) block hash.

Subsequent `getblockhash(N)` calls will return the disconnected block's hash
instead of the replacement.

### 9. No compact block relay (BIP 152)

**File:** `node/src/net/manager.rs:206-208`

All non-handled message types, including `CmpctBlock`, `GetBlockTxn`, and
`BlockTxn`, are silently ignored. There is zero BIP 152 implementation.

Compact blocks reduce block propagation latency from ~seconds to ~milliseconds
by transmitting short transaction IDs instead of full transactions. This is
critical for efficient P2P operation, especially at fast block times (Phase 2).

### 10. P2P has no timeouts or peer banning

**File:** `node/src/net/manager.rs`, `node/src/net/peer.rs`

- `ban_score` field exists in `PeerInfo` (peer.rs:37) but is never incremented or
  checked. Misbehaving peers are never disconnected.
- No read/write timeouts on peer connections. A stalled peer blocks its read task
  forever.
- No `sendheaders` negotiation confirmation tracking.
- No ping/pong timeout (peer liveness detection).

**Impact:** A single misbehaving or stalled peer can consume a connection slot
indefinitely.

### 11. P2P sync has no state machine or IBD detection

**File:** `node/src/net/manager.rs:340-370`

`request_missing_blocks()` does a naive linear scan from height 0 to tip+2000,
requesting up to 16 blocks at a time. There is no:

- Initial Block Download (IBD) detection or progress tracking
- Download pipeline (should request from multiple peers in parallel)
- Stall detection (no timeout if blocks never arrive)
- Block request deduplication across peers
- Orphan block handling

**Impact:** Syncing from a peer with thousands of blocks is extremely slow and
fragile.

### 12. Mempool has no RBF (Replace-By-Fee)

**File:** `node/src/mempool/pool.rs:107-109`

When a transaction's input conflicts with an existing mempool entry, it is
rejected with `ConflictingSpend`. BIP 125 (opt-in RBF) and full RBF are not
implemented. There is no fee comparison or replacement logic.

### 13. Mempool has no CPFP (Child-Pays-For-Parent)

**File:** `node/src/mempool/pool.rs:127-130`

Inputs referencing unconfirmed transactions (outputs from other mempool entries)
are rejected with `MissingInputs`. There is no ancestor/descendant tracking or
package fee rate computation.

### 14. Fee estimation is a stub

**File:** `node/src/rpc/server.rs` (estimatesmartfee registration)

Returns a hardcoded `0.00001000` BTC/kvB regardless of input. The
`FeeEstimator` struct exists (`mempool/fee.rs`) but is never wired into the
block connection or RPC path.

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

Only basic flags are supported: `-regtest`, `-testnet`, `-datadir`, `-rpcport`,
`-rpcuser`, `-rpcpassword`, `-listen`, `-port`, `-connect`. Missing: `-proxy`,
`-maxconnections`, `-dbcache`, `-assumevalid`, `-debug`, `-pid`, and ~70 others.

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

**File:** `node/src/net/manager.rs:183-210`

Only 7 of ~20 message types are handled: `Ping`, `Inv`, `Headers`, `Block`,
`Tx`, `GetHeaders`, `GetData`. Silently ignored:

- `Pong` (ping response tracking)
- `Addr` / `AddrV2` (peer discovery)
- `MemPool` (mempool sync)
- `FeeFilter` (min fee relay)
- `SendCmpct` (compact block negotiation)
- `CmpctBlock` / `GetBlockTxn` / `BlockTxn` (BIP 152)
- `NotFound` (missing data notification)
- `Reject` (error reporting)
- `FilterLoad` / `FilterAdd` / `FilterClear` (bloom filters)

### 22. Incomplete getblocktemplate (BIP 22/23)

**File:** `node/src/rpc/mining.rs:61-95`

Missing fields: `longpollid`, `expires`, `rules`, `vbavailable`, `vbrequired`,
`capabilities`, `default_witness_commitment`. Sufficient for basic regtest
mining but not compatible with production mining software.

### 23. Missing RPCs

24 of ~150 Bitcoin Core RPCs are implemented. Notable missing RPCs beyond wallet:

- `verifychain` — check chain database integrity
- `getmempoolentry` — single mempool tx details
- `getmempoolancestors` / `getmempooldescendants` — dependency queries
- `testmempoolaccept` — dry-run tx validation
- `getmininginfo` — mining status
- `prioritisetransaction` — fee bumping for miners
- `createrawtransaction` / `combinerawtransaction` — tx construction
- `signrawtransactionwithkey` — signing without wallet
- `decodescript` — script analysis
- `getblockstats` — per-block statistics
- `getchaintips` — fork information
- `waitforblock` / `waitforblockheight` — long-polling

### 24. P2P checksum not explicitly validated

**File:** `node/src/net/connection.rs:38-77`

The 4-byte checksum in the P2P message header (bytes 20–24) is not explicitly
extracted and validated. The `bitcoin::consensus::deserialize` call on
`RawNetworkMessage` handles this internally, but an explicit check before full
deserialization would reject invalid messages faster and avoid unnecessary work.

### 25. No graceful P2P shutdown

The `PeerManager` event loop runs until the channel closes, but there is no
explicit shutdown signal. Peer connections are not cleanly closed on node
shutdown — they are dropped when the process exits.

---

## Summary

| Priority | Count | Description |
|----------|-------|-------------|
| **P0** | 6 | Consensus-critical: witness, locktime, sequence locks, taproot |
| **P1** | 8 | Reliability: reorg atomicity, P2P robustness, RBF/CPFP, fee estimation |
| **P2** | 11 | Operational: pruning, txindex, config, policy, RPC coverage |
| **Total** | 25 | |

The P0 issues must be resolved before any non-regtest deployment. P1 issues
should be resolved before connecting to untrusted peers. P2 issues are
operational improvements that can be addressed incrementally.
