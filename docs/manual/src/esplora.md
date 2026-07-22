# satd Esplora REST API

satd ships a native Esplora-compatible REST server, enabled by default and
listening on `127.0.0.1:3000`. Wire shapes match upstream
[blockstream/esplora](https://github.com/Blockstream/esplora) and
[mempool.space](https://github.com/mempool/mempool) byte-for-byte within the
endpoint set listed below.

Like the Electrum server, the Esplora server is a query layer over satd's own
chainstate and shared address-history index. There is no separate indexer
process (electrs, esplora-electrs, Fulcrum) beside the node with its own copy
of the data. One RocksDB store backs the node and every API surface, updated
atomically inside the node's `connect_block` and `disconnect_block` path. A
read can never observe an index out of sync with the tip. The combined index is
larger on disk than a standalone electrs or Fulcrum index: the trade is disk
for consistency and single-process operation. See
[Disk Footprint & Indices](disk-footprint.md) for the accounting.

This chapter covers what is implemented today. The implementation lives in the
`esplora-handlers/` workspace crate. Routes are registered in
`esplora-handlers/src/router.rs`, and shape parity is locked behind the canary
CI requirement in `STABILITY_POLICY.md`.

Last verified against routes: 2026-05-05.

> **Note.** The Esplora surface defaults to unauthenticated loopback. For Basic
> auth (`--esploraauth`) or capability-scoped bearer tokens
> (`--esploraauthbearer`, `esplora:read`), see
> [Authentication & Authorization](authentication.md).

## Configuration

| Flag | Default | Notes |
|---|---|---|
| `--esplora=<bool>` | `1` | Disable with `--esplora=0`. Disabling stops the listener; address-index data is still maintained for RPC consumers. |
| `--esplorabind=<addr:port>` | `127.0.0.1:3000` | Bind address. Read the [Auth](#auth) section before binding to a non-loopback address such as `0.0.0.0:3000`. |
| `--esploraprefix=<path>` | `/` | Mount under a path (for example `/api`) for blockstream.info-style deployments. Must start with `/`. |
| `--esploraauth=<scheme>` | `none` | One of `none`, `cookie`, `userpass`. `none` runs the listener unauthenticated. `cookie` reuses the JSON-RPC cookie file. `userpass` requires `--esplorauserpass=user:pass`. |
| `--esplorauserpass=<user:pass>` | (none) | Static credentials, used only when `--esploraauth=userpass`. |
| `--esploracookiefile=<path>` | (auto) | Override the cookie-file path when `--esploraauth=cookie`. The default is the same `.cookie` file the JSON-RPC server uses. |
| `--esploracors=<origin>` | (none) | Repeat for multiple origins. Use `*` for any origin. |
| `--esplorarequesttimeout=<seconds>` | `30` | Per-request timeout. |
| `--esploramaxconns=<n>` | `256` | Cap on concurrent in-flight requests. `0` disables the cap. Does not bound long-lived SSE streams; see [Live updates](#live-updates-server-sent-events). |
| `--esplorasseconns=<n>` | same as `--esploramaxconns` | Hard cap on simultaneously open SSE streams (`/blocks/sse`, `/address/:addr/sse`, `/scripthash/:hash/sse`). Each open stream holds a permit until the client disconnects; over-cap connections receive 503. `0` disables the cap. |

`POST /tx` has a fixed 1 MiB body limit at the route layer. A witness-heavy
400 KB raw transaction hex-encodes to about 800 KB, so 1 MiB leaves margin and
stays well under any consensus block limit. There is no flag to change this.

Esplora requires `--addressindex=1` (auto-enabled if not set; see the
address-index docs) and `--txindex=1` (auto-enabled by the reconciliation in
`satd/src/config.rs`). Both flags are on by default.

## Endpoints

### Chain

| Method | URL | Returns |
|---|---|---|
| GET | `/blocks/tip/hash` | `text/plain`: current best-chain tip hash (display hex, 64 chars). |
| GET | `/blocks/tip/height` | `text/plain`: current tip height. |
| GET | `/blocks` | JSON array of up to 10 most-recent block summaries, descending. |
| GET | `/blocks/:start_height` | JSON array of up to 10 summaries ending at `start_height` inclusive, descending. |
| GET | `/block-height/:height` | `text/plain`: block hash at the active-chain `height`, or 404. |

### Block

| Method | URL | Returns |
|---|---|---|
| GET | `/block/:hash` | JSON: `{id, height, version, timestamp, mediantime, tx_count, size, weight, merkle_root, previousblockhash, nonce, bits, difficulty}`. |
| GET | `/block/:hash/header` | `text/plain`: 80-byte serialized header, hex-encoded. |
| GET | `/block/:hash/raw` | `application/octet-stream`: raw block bytes. |
| GET | `/block/:hash/status` | JSON: `{in_best_chain, height?, next_best?}`. |
| GET | `/block/:hash/txs` | JSON: first 25 txs in full Esplora shape (`{txid, version, locktime, vin, vout, size, weight, fee, status}`). |
| GET | `/block/:hash/txs/:start_index` | JSON: 25 txs starting at `start_index`. Empty array past the end. |
| GET | `/block/:hash/txid/:index` | `text/plain`: txid at the given block-tx index. |
| GET | `/block/:hash/txids` | JSON: array of every txid in the block. |

### Transaction

| Method | URL | Returns |
|---|---|---|
| GET | `/tx/:txid` | JSON: full tx (`vin`/`vout`/`status`/`fee`). 404 if unknown. |
| GET | `/tx/:txid/status` | JSON: `{confirmed, block_height?, block_hash?, block_time?}`. |
| GET | `/tx/:txid/hex` | `text/plain`: hex-encoded serialized tx. |
| GET | `/tx/:txid/raw` | `application/octet-stream`: raw tx bytes. |
| POST | `/tx` | Body: hex-encoded tx. Returns the txid as plain text on accept. Bad hex or a mempool reject returns 400. |
| GET | `/tx/:txid/outspend/:vout` | JSON: `{spent, txid?, vin?, status?}`. |
| GET | `/tx/:txid/outspends` | JSON: array of outspends, one per output, vout-ordered. |
| GET | `/tx/:txid/merkle-proof` | JSON: `{block_height, merkle: [hex...], pos}`. |
| GET | `/tx/:txid/merkleblock-proof` | `text/plain`: hex-encoded P2P MerkleBlock for the given tx. |

### Address & Scripthash

The address-string and scripthash endpoint families share handlers; only the
parser differs. A scripthash is the 32-byte sha256 of the scriptPubKey,
hex-encoded in natural byte order. It is not reversed; Esplora's scripthash
format differs from Electrum's.

| Method | URL | Returns |
|---|---|---|
| GET | `/address/:address` <br> `/scripthash/:hash` | JSON: `{address, chain_stats, mempool_stats}`. Each `*_stats` block: `{tx_count, funded_txo_count, funded_txo_sum, spent_txo_count, spent_txo_sum}`. |
| GET | `/address/:address/txs` <br> `/scripthash/:hash/txs` | JSON: up to 50 mempool txs followed by first 25 confirmed (newest first). |
| GET | `/address/:address/txs/chain` <br> `/scripthash/:hash/txs/chain` | JSON: 25 confirmed txs, newest first. |
| GET | `/address/:address/txs/chain/:last_seen_txid` <br> `/scripthash/:hash/txs/chain/:last_seen_txid` | JSON: next 25 confirmed txs strictly older than `last_seen_txid`. Unknown cursor returns an empty array, not 404. |
| GET | `/address/:address/txs/mempool` <br> `/scripthash/:hash/txs/mempool` | JSON: up to 50 mempool txs. No paging. |
| GET | `/address/:address/utxo` <br> `/scripthash/:hash/utxo` | JSON: live UTXOs (confirmed + mempool funding) with `{txid, vout, value, status}`. |

Wrong-network addresses return 400, as do malformed addresses and bad
scripthash hex (non-hex characters or wrong length).

### Mempool & Fee

| Method | URL | Returns |
|---|---|---|
| GET | `/mempool` | JSON: `{count, vsize, total_fee, fee_histogram}`. `fee_histogram` is `[[feerate_sat_vb, vsize], …]` descending by feerate. |
| GET | `/mempool/txids` | JSON: array of every mempool txid. |
| GET | `/mempool/recent` | JSON: up to 10 newest mempool txs by admission timestamp; each `{txid, fee, vsize, value}`. |
| GET | `/fee-estimates` | JSON: object mapping confirmation target (string) to feerate (sat/vB, float). Standard targets: 1..25, 144, 504, 1008. Floor 1.0 sat/vB. |

### Root

| Method | URL | Returns |
|---|---|---|
| GET | `/` | JSON: `{chain_tip: {hash, height}, mempool_count}`. Small summary for status pings. |

### Live updates (Server-Sent Events)

| Method | URL | Stream |
|---|---|---|
| GET | `/blocks/sse` | One `block` event per `BlockConnected`. Body: `{hash, height}`. |
| GET | `/address/:addr/sse` | One `status` event per status-hash change for the address. Body: `{address, status_hash}`. |
| GET | `/scripthash/:hash/sse` | Parallel scripthash variant. The `address` field carries the scripthash hex. |

Connections receive a `:keep-alive` heartbeat every 25 seconds, so idle streams
survive intermediate proxy timeouts (Caddy defaults to 30 s, nginx to 60 s).

Per-scripthash subscriptions consume from the registry capped by
`--addrindexsubscriptions=N` (default 10000). Over-cap subscribe attempts
return 503.

Total open SSE streams across all three endpoints are capped by
`--esplorasseconns=N`, which defaults to the `--esploramaxconns` value. Each
stream holds a permit until the client disconnects. This cap is distinct from
the request-handling cap, which does not bound long-lived streaming bodies.
Over-cap connections receive 503 immediately at the SSE entry point.

A subscriber that lags the broadcast channel skips ahead: the broadcast never
panics but can drop intermediate events. On reconnect, refresh state through
the standard endpoints (`/address/:addr` or `/blocks/tip/{hash,height}`).

## Wire-shape gotchas

- **Hex byte order.** Block hashes, txids, and merkle siblings are hex-encoded
  in display (reversed) byte order, the same as Bitcoin Core's `getblockhash`
  and `getrawtransaction`. Scripthash hex is the natural byte order of
  `sha256(scriptPubKey)`, not reversed; this differs from Electrum's wire
  format.
- **Pagination cursors.** `/address/:addr/txs/chain/:last_seen_txid` starts the
  next page strictly after the cursor in the descending list. An unknown cursor
  returns an empty array, so clients with stale state get `[]` rather than 404.
- **Combined `/txs`.** Returns up to 50 mempool transactions followed by the
  first 25 confirmed, in that order. Mempool entries appear in the index's
  HashSet iteration order, not strictly time-ordered.
- **`fee` field on tx JSON.** `null` when at least one prevout cannot be
  resolved (for example, txindex disabled or the previous tx pruned). `Some(0)`
  for coinbase. Otherwise `sum_inputs - sum_outputs`.
- **Mempool UTXOs in `/utxo`.** Outputs created by mempool transactions appear
  with `status.confirmed: false` and no block fields. Outputs spent in the
  mempool are excluded.
- **Confirmation status on outspends.** Confirmed spends carry a full `status`
  with `block_height`, `block_hash`, and `block_time`. Mempool spends carry
  `status: { confirmed: false }`.

## Auth

> **Warning.** The default auth mode is `none`. Loopback-only deployments
> (`--esplorabind=127.0.0.1:3000`) are usually fine. Set an auth mode
> explicitly before binding to a non-loopback address such as `0.0.0.0:3000`.
> `POST /tx` is a broadcast endpoint, and an unauthenticated public listener
> accepts any transaction submission.

Three auth modes are available via `--esploraauth=<mode>`:

1. **`none`** (default): no authentication. The listener accepts every
   request.
2. **`cookie`**: reuses the same `.cookie` file the JSON-RPC server creates.
   Clients pass it via HTTP Basic Auth as `__cookie__:<token>`, the form
   Bitcoin Core-compatible tooling generates. Use
   `--esploracookiefile=<path>` to override the cookie path.

   ```sh
   satd --esplora=1 --esploraauth=cookie
   ```

3. **`userpass`**: static credentials supplied via
   `--esplorauserpass=<user>:<pass>`. The comparison is constant-time, and the
   HTTP scheme is case-insensitive.

   ```sh
   satd --esplora=1 --esploraauth=userpass --esplorauserpass=admin:hunter2
   ```

In `cookie` and `userpass` modes, satd refuses to start if the auth source
cannot be established (unreadable cookie file, or `--esplorauserpass` missing).

## CORS

`--esploracors=<origin>` enables CORS for the listed origins; `*` allows any
origin. Allowed methods: `GET` and `POST`. Allowed headers: `Content-Type` and
`Authorization`. CORS does not bypass authentication; it only admits
cross-origin browser requests.

## Bench harness

`scripts/run-esplora-bench.sh` starts a regtest node, mines warmup blocks, then
drives `ESPLORA_BENCH_REQS` requests (default 200) against each implemented
endpoint. It reports p50, p90, and p99 latency per endpoint. See the script
header for the environment variables. It is not a CI gate; use it as a local
regression check.

## Compatibility statement

The implemented endpoints aim for byte-for-byte parity with upstream
blockstream.info and mempool.space within these constraints:

- **Standard scripts only.** `scriptpubkey_type` strings cover `p2pk`, `p2pkh`,
  `p2sh`, `v0_p2wpkh`, `v0_p2wsh`, `v1_p2tr`, `op_return`, `multisig`, and
  `unknown`, matching upstream. Non-standard scripts serialize with
  `scriptpubkey_address: null`.
- **Mempool ordering.** `/address/:addr/txs/mempool` returns entries in HashSet
  iteration order, not strictly time-ordered. Upstream's contract is "up to
  50" with no order specified.
- **Fee histogram bucketing** uses fixed boundaries spanning realistic mainnet
  fee regimes: 1, 2, 3, 5, 8, 10, 15, 20, 30, 50, 75, 100, 150, 200, 300, 500,
  1000 sat/vB.
- **WebSocket** subscriptions are not implemented; SSE is the supported
  live-updates transport. Most consumers (BDK, the mempool.space SDK) accept
  SSE as a drop-in replacement.
- **High-history scripts.** The address-history endpoints (`/address/:addr`,
  `/address/:addr/txs/chain[/:cursor]`, `/address/:addr/utxo`, and the
  scripthash variants) load the full confirmed-history row set for the
  scripthash on every request and sort it in memory. For typical wallet-sized
  scripts this takes under a millisecond. For high-activity scripts (exchange
  hot wallets, mining pools, popular donation addresses) a request can cost
  multi-MB allocations and sub-second latency. `--esploramaxconns` and
  `--esplorarequesttimeout` bound the damage. For a public deployment that
  serves such scripts, put the listener behind a per-IP rate limiter at the
  reverse proxy. Cursor-paginated index reads are tracked as future work.
- **Address prefix search** (`/address-prefix/:prefix`) is not implemented; it
  would require a separate prefix index.
