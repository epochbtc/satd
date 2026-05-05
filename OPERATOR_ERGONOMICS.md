# satd: Operator Ergonomics & Differentiation

This document catalogs Bitcoin Core ergonomic pain points that satd can address,
mapped against what satd already has. It is a product-research artifact meant to
feed milestone planning, not a commitment to any specific scope.

Last updated: 2026-05-05

---

## Scope

Bitcoin Core is the reference implementation and is excellent at consensus,
reproducible builds, and protocol correctness. satd should not try to
differentiate there. Where satd *can* win is in the surfaces operators and
integrators actually touch: CLI, TUI, RPC ergonomics, observability, fee
estimation, error messages, and wallet-integration surfaces.

All pain-point citations below reference Core GitHub issues, Bitcoin Optech,
PR Review Club sessions, and operator-community tooling that exists *because*
Core doesn't ship the feature. See the References section at the end.

---

## What satd already does well

These are current differentiators. They should be kept and polished — not
rebuilt or redesigned without explicit reason.

- **Ratatui TUI with IBD bitmap visualization** (`sat-tui`). Shows per-block
  progress, per-peer stats, in-flight/pending counts. Core has no equivalent.
- **Cookie auth by default** with auto-generated `.cookie` in datadir.
- **Native Tor v3** via control port (`ADD_ONION`/`DEL_ONION`); hardcoded
  .onion seeds; no separate torification daemon.
- **`getibdprogress` RPC** with bitmap + per-peer tracking — richer than
  Core's `verificationprogress` scalar.
- **Parallel IBD with prefetch + speculative verification** — cross-block
  pipeline that is unique to satd (Core parallelizes *within* a block via
  `CCheckQueue` but not across blocks).
- **RocksDB storage** with RAII write-mode guard and fail-closed durability
  transitions (PR #56).
- **Rust consensus engine at parity with C++ libbitcoinconsensus** (PR #55,
  cached secp256k1 context). Can run as primary or shadow, dispatch in either
  direction symmetrically.

---

## Tier 1 — high impact, natural fits

These are small-to-medium efforts that each remove a well-known Core friction
and are visible in the first 10 minutes of operator use. Each ships cleanly as
its own PR. This is the recommended starter pack.

### 1. First-class `/metrics` Prometheus endpoint ✅ SHIPPED

**Status:** Landed — `--metricsbind=<addr:port>` enables the HTTP server
exposing `GET /metrics` (Prometheus text format), `GET /healthz`, and
`GET /readyz`. Unauthenticated by design; bind to loopback or behind a
reverse proxy. Stable schema documented in `node/src/metrics.rs`.
`/readyz` reports green when within `READY_LAG_BLOCKS` of the highest
seen header.

**Pain:** Monitoring Core requires third-party exporters — `jvstein/bitcoin-prometheus-exporter`
(Python RPC polling), `0xB10C/bitcoind-observer` (requires USDT+eBPF), and
homegrown shell scripts. Each has different metric names and coverage gaps.

### 2. Structured CLI subcommands ✅ SHIPPED

**Status:** Landed — `sat-cli` now has structured subcommands
(`chain`, `mempool`, `peer`, `node`, `fee`, `tx`, `psbt`, etc.) with
pretty-printed output by default and `-o json|yaml|raw` as escape
hatch. Legacy raw-method form (`sat-cli getblockchaininfo`) still
works via clap's `external_subcommand` so existing scripts and
muscle memory keep working.

**Pain:** `sat-cli` was originally a raw RPC wrapper.
`bitcoin-core-config-generator` and similar wrappers exist because the
raw Bitcoin Core CLI is hostile.
([jlopp/bitcoin-core-config-generator](https://github.com/jlopp/bitcoin-core-config-generator))

### 3. Satoshis-as-integers by default ✅ SHIPPED

**Status:** Landed — per-request `amounts=sats|btc` parameter on
amount-returning RPCs and a server default selectable via
`AmountUnit::set_default` at startup. Per-request opt-in remains
backward-compatible: BTC-as-doubles is the wire default to preserve
parity with Bitcoin Core, callers opt into `"amounts": "sats"` per
request and can verify via the `"units": "sats"` field in the
response. `node/src/rpc/amounts.rs` is the canonical surface.

**Pain (historical):** Bitcoin Core issue [#3249](https://github.com/bitcoin/bitcoin/issues/3249)
("RPC option to report bitcoins in satoshi units") has been open
since 2013. All Core amount fields are JSON doubles (IEEE 754); the
Bitcoin Wiki has a dedicated warning page
([Proper Money Handling (JSON-RPC)](https://en.bitcoin.it/wiki/Proper_Money_Handling_(JSON-RPC))).

### 4. Mempool-based smart fee estimation ✅ SHIPPED

**Status:** Landed — new `estimatefees` RPC plus `estimatesmartfee` with
optional `mode` param (`historical` default, `mempool`, `blend`). Never
errors; falls back to min-relay floor with `confidence: low`. Core-compat
response shape preserved on `estimatesmartfee`.

**Pain:** Core's `estimatesmartfee` is history-based — it cannot react to
sudden congestion until blocks confirm at the new rate. BTCPay switched to
mempool.space; Strike uses a blended approach. ([Bitcoin Optech — Fee estimation](https://bitcoinops.org/en/topics/fee-estimation/),
[Mempool-based fee estimation on Delving Bitcoin](https://delvingbitcoin.org/t/mempool-based-fee-estimation-on-bitcoin-core/703))

satd has percentile-based today; that's historical-block data, same failure
mode as Core.

**Proposal:**
- Simulate the next N block templates from current mempool (greedy feerate
  packing with CPFP-aware sorting).
- Expose percentile estimates per target (`P50`, `P90` of what fits in block 1, 3, 6, 24).
- Always return *something* with a `confidence: low|medium|high` field —
  never error out like Core's "Insufficient data or no feerate found"
  ([#11500](https://github.com/bitcoin/bitcoin/issues/11500)).
- Expose the underlying histogram so callers can roll their own strategy.

**Effort:** M. Block-template simulation is code we already have for mining
(`getblocktemplate`); wire it into fee estimation as a forward-looking source.

### 5. Structured error responses ✅ SHIPPED

**Status:** Landed — `node/src/rpc/error.rs` defines a stable
`category` string per error site, optional `suggestion` for actionable
fix advice, and an optional `debug` object. Per-request opt-in via the
existing structured-error escape hatch keeps Core-compat clients on
the historical Core-shaped error response. The category schema is
covered by `STABILITY_POLICY.md` Tier 2 ("category names, once
published, must not change meaning — only new names can be added").

**Pain (historical):** Core error messages are famously cryptic.
"Insufficient funds" even when balance exceeds the send amount
(because fee isn't accounted for,
[#18](https://github.com/bitcoin/bitcoin/issues/18)).
`importdescriptors` errors don't point at the parse location
([Sparrow #1575](https://github.com/sparrowwallet/sparrow/issues/1575)).
"Bitcoin Core is shutting down…" indefinite hangs
([#27848](https://github.com/bitcoin/bitcoin/issues/27848)).

---

## Tier 2 — meaningful wins, more work

### 6. PSBT signing (stdin-keyed, no stored keys)

**Pain:** satd today has all the non-signing PSBT ops (create, decode, analyze,
combine, finalize, join, utxoupdate). Signing is missing because satd is
keyless by design. But CLAUDE.md explicitly states PSBTs are in scope — and
signing-without-key-storage is the modern flow Sparrow/Specter/Nunchuk use.

**Proposal:**
- `signpsbtwithkey`: WIF or xpriv provided on stdin, never stored, zeroed after use.
- External-signer dispatch protocol: stdin/stdout JSON frames so hardware
  wallets / SSS / airgap signers can plug in without satd knowing their
  implementation.
- Miniscript-aware signing (BIP 388 wallet policies) — descriptor language +
  "what role am I, what's missing, what should I do next" output modeled on
  Sparrow's UX, not Core's `decodepsbt` raw dump.

**Effort:** M-L. The crypto is `bitcoin` crate code we already depend on. The
UX design for the external-signer protocol is the main work.

### 7. Structured JSON logging ✅ SHIPPED

**Status:** Landed — `--log-format=json|text` flag, default `text`.
tracing-subscriber JSON formatter. Trace-id spans on
`connect_preprocessed_block`, `connect_stored_block`, `accept_block`, and
`perform_reorg`. Stable field shape: `timestamp`, `level`, `target`,
`fields.message`, with `span.trace_id` for validation events.

**Pain:** Core's `debug.log` is a text firehose with category prefixes but no
machine-parseable structure. Every operator who wants log-based alerting
writes a regex parser.

**Proposal:** `--log-format=json|text` (default text for humans, json for
production). Stable field schema: `ts`, `level`, `component`, `msg`, `trace_id`,
plus component-specific fields. Per-component log level via existing
`RUST_LOG`. Trace IDs on block validation pipeline so you can follow one block
through prefetch → connect → flush.

**Effort:** S. `tracing-subscriber` has a JSON formatter. The work is picking
field names we'll commit to.

### 8. First-class REST/gRPC with OpenAPI ✅ PARTIALLY SHIPPED (Esplora)

**Status:** Native Esplora-compatible REST server landed. On by default
on `127.0.0.1:3000`; **auth defaults to `none`** (loopback-only
deployments are fine; non-loopback exposure must explicitly set
`--esploraauth=cookie` or `--esploraauth=userpass --esplorauserpass=...`).
CORS, request-timeout, and concurrency-limit knobs are available;
`POST /tx` carries a hard-wired 1 MiB body cap. Wire-shape parity with
[blockstream.info](https://github.com/Blockstream/esplora) /
[mempool.space](https://github.com/mempool/mempool) for the implemented
endpoint set: chain, block, tx, address/scripthash (info, txs paginated,
mempool txs, utxo), outspends + merkle proofs, mempool + fee + root,
and Server-Sent Events live updates for new blocks + per-address /
per-scripthash status changes. See
[docs/api/esplora.md](docs/api/esplora.md) for the full endpoint list,
configuration table, gotchas, and bench harness
(`scripts/run-esplora-bench.sh`). WebSocket transport is not
implemented; SSE covers all known consumers (BDK, mempool.space SDK).

**Pain (historical):** Core's REST interface is "experimental",
unauthenticated, loopback-only, and covers a subset of blockchain
RPCs. No wallet, no network. Every third-party explorer
(btc-rpc-explorer, mempool.space) exists partially because Core REST
isn't fit for purpose.

**Deployment notes:**
- Always behind a TLS terminator for public exposure (TLS handled by
  `caddy` / `nginx`; satd does not terminate TLS itself).
- **Public exposure requires explicitly enabling auth.** Default is
  `--esploraauth=none`. For non-loopback binds, run with
  `--esploraauth=cookie` (reuses the daemon `.cookie` file) or
  `--esploraauth=userpass --esplorauserpass=<user>:<pass>`.
- For mempool.space-style mounts, set `--esploraprefix=/api`.
- For browser consumers, set `--esploracors=<origin>` (or `*`).

**Future:** OpenAPI spec generation from the handler types, optional
gRPC surface, PSBT-aware tx submission.

**Effort:** Esplora layer is now L+ shipped over PRs 1–9; PRs 1–7
landed, 8 (this PR) and 9 (live updates) follow.

### 9. `--profile` presets ✅ SHIPPED

**Status:** Landed — `--profile=<name>` flag with presets `archival`,
`pruned-home`, `mining`, `regtest-dev`, `signet-watchtower`. CLI flags
override profile values. New `getconfig` RPC + `sat-cli node config`
show the effective post-merge configuration with secrets redacted.

**Pain:** Core has a large flag space and no profile concept.
`jlopp/bitcoin-core-config-generator` exists because operators can't navigate
the flag matrix themselves.

**Proposal:** Bundled profiles:
- `--profile=archival` — `--txindex`, large dbcache, no prune
- `--profile=pruned-home` — `--prune=10000`, moderate dbcache, fewer peers
- `--profile=mining` — higher connection limits, priority mempool tuning
- `--profile=regtest-dev` — everything permissive, fast mining
- `--profile=signet-watchtower` — signet, low resource, high relay

Plus `sat-cli node config --effective` to print the merged bitcoin.conf +
profile + CLI configuration.

**Effort:** S. Mostly flag-bundling.

### 10. AssumeUTXO `--fast-start`

**Pain:** Core shipped AssumeUTXO in v28 but it's invisible to most users.
You have to find a snapshot URL, verify the hash, call `loadtxoutset`.
[Start9Labs/bitcoin-core-startos#167](https://github.com/Start9Labs/bitcoin-core-startos/issues/167)
shows even packaged distros are still working on exposing it.

**Proposal:** `--fast-start` downloads a signed snapshot from a hardcoded
mirror, verifies against a binary-embedded hash (updated per release),
applies it, falls back to full IBD gracefully on any failure. Progress UI
in TUI. New operators reach near-tip in minutes, not days.

**Effort:** M. Snapshot generation + verification pipeline + mirror infra.

### 11. Operator-focused mempool APIs ✅ SHIPPED

**Status:** Landed — bulk `getmempoolentry` (array of txids → map of
verbose entries or null), `getmempoolhistory [since_secs]` ring of
periodic snapshots with feerate histogram, and `subscribemempool` WS
subscription emitting `enter` / `leave_confirmed` / `leave_evicted`
(reason: `full_pool` | `expiry`) / `leave_replaced` (with
`replacing_txid`). `getmempoolentry` also now populates
`spentby` (direct children) and `descendantcount` /
`descendantsize` / `descendantfees` — Core-compat schema. The same
PR backfilled MCP tools for every shipped ergonomics endpoint
(`get_config`, `get_reorg_history`, `get_metrics_snapshot`,
`get_health`, `get_readiness`, `get_mempool_entries_bulk`,
`get_mempool_history`, `subscribe_mempool_snapshot`).

**Pain:** `getmempoolentry` is per-tx only (no bulk). `getrawmempool` is
point-in-time (no history). No streaming diff API — you poll or rebuild
state from ZMQ per-tx events.

**Proposal:**
- Bulk `getmempoolentry [txid1, txid2, ...]` → array.
- Ring-buffered `getmempoolhistory --minutes=60` with histogram snapshots.
- Streaming `subscribemempool` (WS or NDJSON): events
  `enter`, `leave-confirmed`, `leave-evicted`, `leave-replaced`, with the
  replacing txid. Clean semantics out of the box.

**Effort:** M. The streaming endpoint is the bulk of the work.

### 12. Persistent reorg log + webhook ✅ SHIPPED

**Status:** Landed — JSONL append-only reorg log at
`$datadir/reorg.log` with an in-memory 256-record ring. New
`getreorghistory [since_secs]` RPC + `sat-cli node reorgs` subcommand.
Optional `--reorg-webhook=<url>` dispatches each record via HTTP POST;
optional `--reorg-webhook-secret=<secret>` adds HMAC-SHA256
`X-Satd-Signature: sha256=...` for integrity.

**Pain:** `getchaintips` shows current known tips only. Reorgs that happened
yesterday are gone. Exchanges and custodians all log reorgs externally.

**Proposal:** Persistent reorg log: `{ts, depth, old_tip, new_tip, disconnected_blocks, reconnected_blocks}`.
`getreorghistory --since=24h`. Configurable webhook on reorg-detected.
Tag re-entered mempool txs with their origin block (per [reorg handling
discussion](https://github.com/bitcoin/bitcoin/blob/master/doc/design/)).

**Effort:** S-M.

---

## Tier 3 — attractive but heavier lifts

### 13. Built-in address/scripthash index + Electrum protocol server ✅ SHIPPED

**Status:** All three originally-scoped phases have landed. Phase A
(address/scripthash index) is `node-index` + `node/src/index/address`;
Phase B (Electrum protocol server) is `electrum-proto`; Phase C (BIP
157/158 filter server) is `node-filter-index` + `node/src/index/filter`.
See the [Compact block filter index](#compact-block-filter-index-bip-157--158)
and [Electrum/electrs Integration](#electrumelectrs-integration) sections
below for operator quick-starts. Original Tier-3 planning analysis is
retained in the "Electrum/electrs Integration" section under
"Original analysis (kept for reference)".

### 14. Config hot reload on SIGHUP

**Pain:** [bitcoin/bitcoin#1158](https://github.com/bitcoin/bitcoin/issues/1158)
is open since 2012 — "Reload bitcoin.conf without restarting the program."

**Proposal:** SIGHUP reloads safely-reloadable knobs (log levels, ban policy,
max connections, fee settings). Document unambiguously which options are
reloadable and which need restart.

**Effort:** M. The hard part is classifying options.

### 15. Built-in alerting hooks

**Pain:** No built-in alert on disk-filling, all-peers-disconnected, reorg-
deeper-than-N, stalled-tip. Operators bolt on external monitoring.

**Proposal:** Alert rules in config:

```toml
[alert.disk_low]
condition = "disk_free_gb < 20"
action    = "webhook:https://my-pager.example/alert"

[alert.reorg_deep]
condition = "reorg_depth >= 6"
action    = "exec:/usr/local/bin/on-reorg.sh"
```

Ship example rules for the common cases.

**Effort:** M.

### 16. CPFP helper RPC

**Pain:** Core's `bumpfee` only works sender-side on RBF-signalled txs.
Receiver has no tooling. CPFP construction is DIY.

**Proposal:** `createcpfp <incoming-txid> <target-feerate> [--destination=addr]` —
constructs a child tx that fee-bumps an unconfirmed incoming payment.
First-class RBFR semantics where policy allows ([Peter Todd — One-Shot RBFR](https://petertodd.org/2024/one-shot-replace-by-fee-rate)).

**Effort:** M. Requires some wallet-adjacent machinery (destination selection)
but stays keyless — output is an unsigned PSBT.

### 17. Online consistent chainstate snapshot

**Pain:** To move a synced node to new hardware you stop the daemon and rsync.
No online consistent snapshot (no `pg_basebackup` equivalent).

**Proposal:** `sat-cli node snapshot export --to=/path/snapshot.tar`
produces a restartable tarball while the node keeps running. Streaming
restore. Internally: RocksDB checkpoints + WAL tail.

**Effort:** L. RocksDB checkpointing is the enabling primitive; the hard part
is ensuring flat-file block storage snapshots consistently.

### 18. Silent payments index + BIP158 block filter server

**Pain:** Silent payments receive requires full-block scanning without an
index ([bitcoin/bitcoin#28241](https://github.com/bitcoin/bitcoin/pull/28241)).
BIP157/158 is the modern light-client protocol but Core's implementation is
limited.

**Proposal:** Opt-in SP index with incremental maintenance. BIP157 server
over P2P for light clients. Pairs naturally with the address index work.

**Effort:** L.

**Status (2026-05): BIP 157/158 has landed.** Silent Payments deferred —
see `bip157-158-compact-filters.md` for the implementation plan.

---

## Compact block filter index (BIP 157 / 158)

> *Note: BIP 158 is the compact-block-filter format (GCS-encoded
> `(scriptPubKey)` set per block); BIP 157 is the P2P service that
> serves filters and chained filter headers (`getcfilters` /
> `getcfheaders` / `getcfcheckpt`). Together they let mobile and
> embedded wallets like Zeus, Blixt, and Mutiny scan privately
> without maintaining a per-scripthash subscription on a remote
> server.*

**Status (2026-05): shipped.** satd builds the BIP 158 SCRIPT_FILTER
(filter type `0x00`, the only type the spec defines today) atomically
inside the existing `connect_block` / `disconnect_block` write batch,
and answers BIP 157 P2P requests when the operator opts in.

### Operator quick-start

```sh
# Build the filter index (no P2P advertisement)
satd --blockfilterindex=basic

# Same, plus advertise NODE_COMPACT_FILTERS and answer P2P queries
satd --blockfilterindex=basic --peerblockfilters=1

# Bitcoin Core spelling also accepted:
#   --blockfilterindex=basic    # alias for --blockfilterindex=1
#   -noindex=blockfilter        # alias for --blockfilterindex=0
```

### Flags

| Flag | Default | Notes |
|---|---|---|
| `--blockfilterindex=<0\|1\|basic>` | `0` | Builds the index; one filter blob (~30 KB) + 32-byte chained header per connected block. |
| `--peerblockfilters=<bool>` | `0` | Advertises `NODE_COMPACT_FILTERS` (bit 6) at the version handshake and serves `getcfilters` / `getcfheaders` / `getcfcheckpt`. Implies `--blockfilterindex=basic`. |

### Verification

```sh
satd-cli getindexinfo
# {
#   "address": { ... },
#   "basic block filter index": {
#     "synced": true,
#     "best_block_height": 947910
#   }
# }

satd-cli getserverstatus
# { "blockfilterindex": { "enabled": true, "complete": true }, ... }

satd-cli getblockfilter <blockhash>
# { "filter": "<hex>", "header": "<hex>" }
```

### Tor deployment

The BIP 157 service is the natural pairing for a Tor-only node:
mobile wallets connect over `.onion`, work through CGNAT, and never
leak the operator's home IP. Combine with `--listenonion` /
`--onlynet=onion` and use the standard P2P port:

```sh
satd \
    --blockfilterindex=basic --peerblockfilters=1 \
    --listenonion --onlynet=onion \
    --torcontrol=127.0.0.1:9051
```

The mobile wallet `addpeer`s your node's `.onion`; embedded-Neutrino
clients (Zeus-embedded, Blixt) discover your peer via service-flag
filtering on connect.

### Backfilling pre-existing datadirs

Datadirs that were synced before the BIP 158 filter index landed (or
that previously ran with `--blockfilterindex=0`) start with the
completeness marker `false`. `getblockfilter` errors with "block
filter index is not synced" and the BIP 157 P2P arms silent-drop.

To retroactively populate the index without a full chain rebuild:

1. Restart with `--blockfilterindex=basic`.
2. Trigger the deferred backfill:

   ```sh
   sat-cli backfillindex blockfilter
   ```

3. Monitor progress:

   ```sh
   sat-cli getindexinfo
   # → result["basic block filter index"]["backfill"]["state"] / cursor_height /
   #   snapshot_height / estimated_remaining_seconds
   ```

   Operator controls: `pauseindex blockfilter`, `resumeindex
   blockfilter`, `cancelindex blockfilter`. The cursor is persisted
   atomically with each filter row so a kill -9 mid-flight resumes
   cleanly on the next start.

The backfill is a single-pass walk over `(block, undo)` per height,
which means it requires the on-disk undo data the connect-block path
already wrote. After completion, a tail catch-up phase rewrites any
filter headers the live `connect_block` emitted above
`snapshot_height` so the BIP 157 chain is intact at completion.

### Caveats

- **Pruning** is not yet implemented (see `CORE_GAPS.md`). Once it
  lands, the filter index will survive pruning by construction
  (filters are independent of full block bodies) — but a pruned
  datadir cannot retroactively backfill (the runner reads each
  block's persisted undo data, which `--prune` discards).
- **`--reindex-chainstate`** is still available as a heavier last-
  resort remediation if undo data is corrupt or unavailable. Prefer
  `backfillindex blockfilter` for the common upgrade path.

---

## Electrum/electrs Integration

> *Note for posterity: the "Electrum protocol" referenced here is the wire
> protocol spoken by the Electrum desktop wallet and compatible servers
> (electrs, Fulcrum, ElectrumX). Not to be confused with the Electrum wallet
> itself.*

**Status (2026-05): Phase A and Phase B have landed.** satd's
`--addressindex=1` (default on; see `ADDRESS_INDEX.md`) provides Phase A;
the native Electrum protocol server in the `electrum-proto` crate
provides Phase B. Operators enable it via `--electrum=1`, optional TLS
via `--electrumtlsbind` + `--electrumtlscert`/`--electrumtlskey`.

### Operator quick-start

```sh
# Plain TCP, loopback only (recommended; expose via Tor)
satd --electrum=1 --electrumbind=127.0.0.1:50001

# Plain TCP + TLS
satd --electrum=1 \
     --electrumbind=127.0.0.1:50001 \
     --electrumtlsbind=127.0.0.1:50002 \
     --electrumtlscert=/etc/satd/electrum.crt \
     --electrumtlskey=/etc/satd/electrum.key
```

`--electrum=1` requires `--addressindex=1` (auto-enforced) and a
complete `--txindex` (auto-enabled when not explicitly disabled).
A datadir previously synced with `--txindex=0` requires
`--reindex-chainstate` before Electrum can serve confirmed-tx and
merkle-proof endpoints.

Defaults:
- `--electrumbind` = `127.0.0.1:50001` (loopback). Expose via a
  Tor hidden service rather than directly on the LAN/internet —
  same deployment story as `bitcoind` for self-custody distros.
- `--electrummaxconns` = 64 (total simultaneous connections).
- `--electrummaxsubsperconn` = 100 (per-connection scripthash
  subscription cap).
- `--electrumrequesttimeout` = 30 seconds. Wraps the dispatch path
  (read → handler → write) and the TLS handshake; a slow client
  can't pin a connection slot past this deadline.
- `--electrummaxbatchrequests` = 16 (max requests per JSON-RPC
  batch line; mirrors `romanz/electrs`).
- `--electrummaxbroadcastpackagetxs` = 25 (max txs per
  `blockchain.transaction.broadcast_package`; mirrors Bitcoin
  Core's `MAX_PACKAGE_COUNT`).
- `--electrumfeehistogramttl` = 10 seconds. TTL for the
  `mempool.get_fee_histogram` cache. The first call after expiry
  rebuilds from the live mempool snapshot; subsequent calls within
  the window return the cached JSON. Lower for fresher data at
  higher CPU cost.

Bitcoin-conf aliases mirror the CLI flags: `electrum`,
`electrumbind`, `electrumtlsbind`, `electrumtlscert`,
`electrumtlskey`, `electrummaxconns`, `electrummaxsubsperconn`,
`electrumrequesttimeout`, `electrummaxbatchrequests`,
`electrummaxbroadcastpackagetxs`, `electrumfeehistogramttl`,
`electrumbanner`.

### What's implemented

The v1 method set (per `ECOSYSTEM.md` §4a):

- `server.{version, banner, ping, donation_address, features, peers.subscribe}`
  — `peers.subscribe` returns `[]` (we are not part of the Electrum
  server peer mesh).
- `blockchain.headers.{subscribe, get}`, `blockchain.block.{header, headers}`.
- `blockchain.scripthash.{get_history, get_balance, listunspent,
  get_mempool, get_first_use, subscribe, unsubscribe}`.
- `blockchain.transaction.{get, get_merkle, broadcast,
  broadcast_package, id_from_pos}`.
  `transaction.get` returns the raw hex by default; `verbose=true`
  returns Bitcoin Core's `getrawtransaction <txid> 1` JSON shape
  (txid/hash/version/size/vsize/weight/locktime, vin with coinbase
  variant + scriptSig + txinwitness, vout with value/n/scriptPubKey,
  hex, and blockhash/confirmations/time/blocktime when confirmed).
- `blockchain.estimatefee`, `blockchain.relayfee` (BTC/kB on the
  wire, converted from satd's internal sat-per-1000-WU unit).
- `mempool.get_fee_histogram` (50,000-vbyte buckets, descending sat/vbyte).
- JSON-RPC batch requests (`[req, req, ...]`) are accepted up to
  `--electrummaxbatchrequests`. Notifications inside a batch have
  their responses suppressed per JSON-RPC §6.

`blockchain.block.header` and `blockchain.block.headers` accept the
`cp_height` argument for protocol compatibility but reject any
nonzero value with a `bad_request` error — checkpoint proofs are
not yet implemented, and silently returning the proof-less response
would be a wallet-compat hazard.

Server-pushed notifications (`blockchain.scripthash.subscribe` and
`blockchain.headers.subscribe`) are delivered on the same connection
as the response, with the per-connection mpsc fan-in providing
backpressure when a client is slow.

### Original analysis (kept for reference)

This was the single highest-leverage Tier-3 item and deserves dedicated
analysis. Short answer: **yes, and I think it's a major differentiator** —
but it should be opt-in and carefully scoped.

### What electrs provides today

- **scripthash index**: SHA256(scriptPubKey) → list of (height, txid, position).
- **Electrum JSON-RPC server** over TCP/TLS (typically ports 50001/50002).
- **Protocol methods**: `blockchain.scripthash.get_history`, `.get_balance`,
  `.listunspent`, `.subscribe`; `blockchain.transaction.get`, `.get_merkle`;
  `blockchain.estimatefee`; `mempool.get_fee_histogram`; `server.version`,
  `server.features`.
- **Mempool tracking** for address-level subscription updates.
- **Block filter serving** in newer versions (Fulcrum more so than electrs).

### Why it matters for operators

Sparrow, Electrum, Blue Wallet, Nunchuk, Keeper, and most modern Bitcoin
wallets speak the Electrum protocol to "connect to your own node." Every
sovereignty-oriented node distro (Umbrel, Start9, MyNode, RaspiBlitz) bundles
electrs or Fulcrum alongside Core specifically because Core doesn't serve
wallets itself. Without this, satd is a node you can run but can't easily
**use** — operators have to bolt on electrs and manage two services.

### Tradeoffs

**Cost:**
- Storage: ~40–60 GB for the scripthash index at current chain size (~950k
  blocks). Grows roughly linearly.
- CPU: ~5–15% IBD overhead for incremental indexing during block connect.
- Memory: modest — the hot-path cache is working-set-sized.
- Code complexity: significant — Electrum protocol has quirks (version
  negotiation, TLS cert management, subscription backpressure, long-lived
  TCP connections, connection limits).
- Maintenance: the protocol evolves; electrs and Fulcrum have different
  interpretations of edge cases.

**Benefit:**
- Single binary, single lifecycle, single log stream, single metrics
  endpoint. The *real* operator win is eliminating the "bitcoind + electrs +
  nginx" stack, not the Electrum protocol itself.
- Shared RocksDB avoids double-indexing (electrs currently duplicates block
  data).
- Wallets work against a fresh `satd --fast-start` in minutes, not days.
- Native TUI visibility of Electrum subscriptions — operators can see who's
  connected and what they're watching.

### Recommended implementation path

**Phase A — address index as internal infrastructure.**
- Add a RocksDB column family `addr_index`: `scripthash → CompactHistory`.
- Populate on block connect, unindex on disconnect. Prune with block pruning.
- Expose via native RPC first: `getaddresshistory`, `getaddressbalance`,
  `getaddressutxos`. This gives us the data layer with no protocol surface.
- Gate behind `--index=address` flag (opt-in). Default off to respect
  storage-constrained operators.

**Phase B — Electrum protocol server.**
- TCP (50001) and TLS (50002) listener behind `--electrum-port=...`.
- Implement the core `blockchain.scripthash.*` and `blockchain.transaction.*`
  methods on top of Phase A.
- Mempool subscription tracking on top of existing mempool events.
- Connection limits, rate limits, subscription caps as config.
- Reference Fulcrum's C++ implementation for test vectors and edge cases
  (it's the more-maintained successor to electrs).

**Phase C — BIP157/158 block filter server.**
- Compact block filter index (scriptPubKey hashing into GCS filter).
- Serve over P2P (`getcfilters`, `getcfheaders`).
- This is the modern alternative to Electrum protocol — much simpler wire
  format, trust-minimized for light clients, complementary rather than
  competitive.

**Phase D — integration polish.**
- `sat-cli wallet connect` prints `electrum://...` / `bitcoin://...` URIs
  wallets can consume directly.
- TUI panel: active Electrum connections, subscription count, history
  queries/sec.
- Prometheus metrics: `satd_electrum_connections`, `satd_electrum_rpc_latency`,
  `satd_addr_index_bytes`.

### Scope boundary — what we should *not* build

- Not a full block explorer. mempool.space is its own layer.
- Not time-series analytics on address activity. That's a separate database.
- Not a REST/gRPC address API before we ship the native RPC + Electrum
  protocol — scope creep.

### Risk

Bitcoin Core has explicitly stayed out of address-indexing land for scaling
reasons. If satd grows to many operators, the address index becomes a
meaningful per-node cost. Mitigations: keep it strictly opt-in; document the
disk cost up front; consider "recent-only" modes (last N blocks) for
lightweight use cases.

### Effort estimate

3 milestones end-to-end:
- **M+1**: address index + native RPC surface (Phase A).
- **M+2**: Electrum protocol server (Phase B).
- **M+3**: BIP157/158 filter server + integration polish (Phases C+D).

This is a significant commitment. The payoff is that satd becomes a
"one-binary Bitcoin node you can actually use with a wallet" — which is what
every operator-focused Bitcoin distro has been trying to stitch together
for years.

---

## Constrained-environment features (Umbrel / Raspberry Pi / home-node)

Home-node distros — Umbrel, Start9, MyNode, RaspiBlitz, Nodl — run on ARM
hardware with 4–8 GB RAM, 1–2 TB external SSDs, passive cooling, residential
ISPs (often with data caps and CGNAT), and frequently alongside a Lightning
implementation, BTCPay, electrs, mempool.space, and other services competing
for the same resources. This is arguably satd's most natural user base
because it's where Core's one-size-fits-all tuning hurts the most.

### Tier 1 — high-leverage constrained-environment wins

#### C1. Resource budget caps (`--max-cpu`, `--max-memory`, `--max-disk-growth-per-day`)

**Pain:** Core has dbcache, prune, and connection limits — but no unified
"don't exceed X" guarantee. On shared hardware (satd + LND + BTCPay on one
Pi), the node can starve its neighbors during IBD or a mempool storm.

**Proposal:** Hard caps enforced at the scheduler layer:
- `--max-cpu=50%` — cgroup-style throttle (native Linux cgroup v2 when
  available, soft thread-count limit otherwise).
- `--max-memory=3GB` — strict memory ceiling covering coin cache + mempool
  + RocksDB block cache. Shrink caches proactively before OOM.
- `--max-disk-growth-per-day=5GB` — if about to exceed, prune aggressively
  or pause non-critical indexes.
- TUI shows current usage vs. budget per resource.

**Why this matters:** Operators on Umbrel today can't reliably co-locate
services because each one assumes it owns the box.

#### C2. Adaptive dbcache sizing

**Pain:** Core's `-dbcache` is a static value. Too small → slow IBD; too
large → indefinite shutdown ([#31534](https://github.com/bitcoin/bitcoin/pull/31534)),
OOM on memory pressure, or starves co-located services. Operators guess.

**Proposal:** `--dbcache=auto` reads free memory from the system, starts at
a conservative fraction (say 40% of free), and adjusts every N minutes.
During IBD: expand. Near tip: contract. When another process demands memory
(via cgroup events or `/proc/meminfo`): contract immediately. Periodic
background flush capped at `--max-shutdown-flush-time=30s` so shutdown is
bounded regardless of cache size.

#### C3. Warm restart (no rescan on normal shutdown)

**Pain:** On many Pi deployments, Core rescans a chunk of recent blocks
after reboot because shutdown wasn't clean or flush was interrupted. On slow
hardware this is 10–30 minutes of unavailability per restart.

**Proposal:** Atomic shutdown protocol: fsync the coin cache, write a
sealed-shutdown marker, unlink on next startup. If the marker is present,
skip rescan entirely and resume from persisted tip. We have most of this
already via the `BulkLoadGuard` and `flush_durable()` work — formalize it as
an "clean shutdown" guarantee with TUI confirmation.

#### C4. AssumeUTXO `--fast-start` (doubly important here)

On a Pi 4, IBD from genesis at full speed takes multiple days even with
every optimization in place. `--fast-start` is the difference between "set
it up tonight, use it tomorrow" and "let it run for a week." Already in
Tier 2 above (#10); calling it out here as a constrained-environment
priority.

#### C5. Split data locations — chainstate on fast device, blocks elsewhere

**Pain:** Umbrel users have 1 TB SSDs; Pi users often have a single
external drive. Block storage (650 GB+) dominates. But chainstate (5–10 GB)
is the hot path. Running both on the same slow external USB spinning disk
is needlessly slow.

**Proposal:** Separate `--blocksdir`, `--chainstatedir`, `--indexdir` flags
so operators can put chainstate on a small NVMe (Pi 5 supports this) and
blocks on a slow large HDD. Core supports `-blocksdir` but the UX is
undocumented and the split between chainstate and indexes is fuzzy.
Validate location health on startup (is chainstate on a fast device?).

### Tier 2 — meaningful constrained-environment wins

#### C6. Bandwidth caps + "data cap" awareness

**Pain:** Residential ISPs with monthly caps (1 TB typical in US). A Core
node in steady state can easily push 300 GB/month serving blocks/txs.
Operators disable peers or firewall-off.

**Proposal:**
- `--max-upload-per-month=500GB` — cumulative counter persisted across
  restarts; stops serving blocks (not txs) when threshold reached; resumes
  at month boundary.
- `--max-upload-rate=5Mbps` and `--max-download-rate=50Mbps` — token bucket
  at the socket layer.
- TUI shows monthly usage, cap status, days remaining.
- Configurable "upload-only at night" window for operators with metered
  daytime bandwidth.

#### C7. Tor-only mode (proper first-class support)

**Pain:** Many home-node operators run Tor-only for privacy. Current satd
already has Tor v3 — but there's no clean "Tor-only, no clearnet, ever"
mode. Requires careful firewall setup.

**Proposal:** `--tor-only` flag that:
- Disables IPv4/IPv6 listeners entirely.
- Rejects manual `--addnode` for non-.onion peers.
- Uses only .onion seeds for discovery.
- Verifies Tor control-port reachability on startup and fails fast if not.
- Documents NAT/firewall implications clearly.

#### C8. CGNAT / no-listen awareness

**Pain:** Many residential ISPs put users behind CGNAT — they can't receive
inbound connections at all. Core tries to listen anyway and spams logs.
Operators don't realize why they have no inbound peers.

**Proposal:** Detect no-inbound state (no peer reached us in N minutes,
listen socket unreachable externally). Surface as a first-class warning in
TUI: "This node has no inbound connectivity — likely CGNAT. Set `--listen=0`
or enable Tor hidden service for inbound peers."

#### C9. UPnP / NAT-PMP with explicit opt-in

**Pain:** Core deprecated UPnP for security reasons. Home users now
manually configure port forwarding — which most don't know how to do.

**Proposal:** Opt-in UPnP (`--upnp=on`) with explicit security warnings and
auto-disable if the router doesn't confirm the mapping within a timeout.
NAT-PMP as an alternative for routers that prefer it. Both off by default.

#### C10. Thermal throttling awareness

**Pain:** Pi 4 without active cooling throttles CPU at 80°C, which silently
halves IBD throughput. Operators don't always notice until they compare
against community benchmarks.

**Proposal:** Poll `/sys/class/thermal/thermal_zone*/temp` on Linux. If
throttling is occurring (temp > threshold or `cpufreq` shows degraded
state), log a clear warning once per minute and expose as a Prometheus
metric. TUI: red thermometer icon. Don't attempt to manage cooling — just
surface the fact.

#### C11. Pruned + address index compatibility

**Pain:** If we ship the address index (§13), ensuring it works with
pruning is critical for Pi operators. Core's indexes are historically
prune-hostile ([#12651](https://github.com/bitcoin/bitcoin/issues/12651),
[#21726](https://bitcoincore.reviews/21726)).

**Proposal:** Address index stores only what's derivable from current UTXO
set + recent-N blocks of history. Serve what we have; return a structured
"pruned, data unavailable from block X to Y" error for queries outside the
window. Let the operator configure the window.

### Tier 3 — nice-to-have optimizations

#### C12. Block storage compression (zstd)

**Pain:** ~650 GB of flat-file block storage on a 1 TB drive is tight.

**Proposal:** Optional per-file zstd compression (`--blocks-compression=zstd`).
Expected ~25–30% savings. Decompression cost is small relative to disk I/O
on slow external drives.

**Risk:** Write amplification, recovery complexity. Ship only after
benchmarking.

#### C13. SD-card-friendly write discipline

**Pain:** Some Pi deployments boot from SD card. Write amplification kills
SD cards in months.

**Proposal:** `--sdcard-safe` mode: rate-limit RocksDB compactions, batch
log writes, warn if OS appears to be on removable media (check
`/sys/block/*/queue/rotational` and `/sys/block/*/removable`). Documented
guidance.

#### C14. Low-power / battery-aware operation

**Pain:** Solar/battery-powered node operators (there are a few) want to
pause non-critical work when on battery.

**Proposal:** `--on-battery-action=pause-sync|throttle|continue`. Poll
`/sys/class/power_supply/*/status` on Linux. Niche but delightful for the
users who need it.

#### C15. Rootless / unprivileged operation by default

**Pain:** Some Core features (UPnP with privileged sockets, capability
requirements for Tor binding) force operators to run as root or grant
capabilities. Umbrel/Start9 mostly work around this but not universally.

**Proposal:** satd runs unprivileged by default. Document the full set of
privileges actually required (none for the common path) so distro packagers
can ship with minimal surface.

#### C16. `satd init` config wizard

**Pain:** First-run config on a Pi is frustrating. `bitcoin.conf` examples
are generic.

**Proposal:** `satd init --profile=pi5-umbrel` generates a tuned conf based
on detected hardware (memory, cores, disk type). Interactive mode asks 5
questions ("how much disk can I use?", "do you have other services on this
box?", "do you have a monthly data cap?") and writes the conf.

#### C17. Container / distro health endpoints

**Pain:** Running satd under Docker (Umbrel-style) needs proper
liveness/readiness probes. Core's `getblockchaininfo` over RPC works but
requires auth and is expensive.

**Proposal:** Unauthenticated `/healthz` and `/readyz` HTTP endpoints on
the metrics port. `/healthz` = process alive. `/readyz` = RPC answering
+ within N blocks of expected tip. Simple enough for Kubernetes /
Docker Compose / systemd to consume.

### Recommended constrained-environment starter pack

If I were picking a focused milestone for the Pi / Umbrel user:

1. **C3 Warm restart guarantee** — the single biggest UX win on slow
   hardware.
2. **C2 Adaptive dbcache** — eliminates the most common operator pitfall.
3. **C1 Resource budget caps** — makes co-location with LND/BTCPay
   tractable.
4. **C6 Bandwidth caps** — unlocks deployment behind data-capped ISPs.
5. **C17 Container health endpoints** — ship day-one, unblocks Umbrel/Start9
   packaging.

Each is independently shippable; C1–C3 share some scheduler infrastructure
and could land as a single milestone.

---

## Pain points Core has fixed or where we shouldn't differentiate

Be honest about these — don't spend effort chasing.

- **Consensus correctness and compatibility.** Core is the reference. Match
  exactly.
- **Deterministic/Guix builds.** Core's current Guix pipeline is solid.
- **ZMQ notifications.** They work. Limitations are scope, not quality.
- **Cookie auth for local use.** `~/.bitcoin/.cookie` is fine once you know
  about it. Keep compatibility.
- **Script verification correctness.** `libbitcoinconsensus` is battle-tested;
  our Rust verifier matches it.
- **Auto-update.** Core refuses for good supply-chain reasons. Ship an update
  *notifier* only (off by default, opt-in).
- **IBD stalling logic.** Core v25 made the stall-detection adaptive; mostly
  fixed.
- **Full-RBF semantics.** Clarified in Core v28+; match the consensus.

---

## Recommended first moves — historical, all shipped

The 2026-04 starter pack landed in full and the address-index follow-on
shipped on top:

1. ~~**#1 Prometheus `/metrics`**~~ — shipped (`--metricsbind`).
2. ~~**#3 Satoshis-as-integers**~~ — shipped (per-request `amounts=sats`).
3. ~~**#2 Structured CLI subcommands**~~ — shipped (`sat-cli chain info`, `node status`, etc.).
4. ~~**#5 Structured error responses**~~ — shipped (`category` / `suggestion` / `debug`).
5. ~~**#13 address index + Electrum protocol server**~~ — shipped (Phase A in `node-index`, Phase B in `electrum-proto`, plus Phase C BIP 157/158 in `node-filter-index`).

Open Tier 1 / Tier 2 items remaining for the next operator-facing pack:

- **#6 PSBT signing** (stdin-keyed, no stored keys) — keyless flow that satd is uniquely positioned to ship cleanly.
- **#10 AssumeUTXO `--fast-start`** — one-flag UX with embedded snapshot hash; the snapshot-validation pipeline already exists.
- **#14 Config hot reload on SIGHUP** — small but distinctive vs. Core.
- **#15 Built-in alerting hooks** — pairs naturally with the persistent reorg-log webhook that already shipped.

---

## References

### Bitcoin Core issues & PRs

- [#3249 — RPC option to report bitcoins in satoshi units](https://github.com/bitcoin/bitcoin/issues/3249) (open since 2013)
- [#1158 — Reload bitcoin.conf without restarting](https://github.com/bitcoin/bitcoin/issues/1158) (open since 2012)
- [#11500 — estimatesmartfee insufficient data error](https://github.com/bitcoin/bitcoin/issues/11500)
- [#10436 — Disconnected clients fill rpcworkqueue](https://github.com/bitcoin/bitcoin/issues/10436)
- [#16642 — ThreadDNSAddressSeed hangs on shutdown](https://github.com/bitcoin/bitcoin/issues/16642)
- [#17145 — GUI event loop should be block free](https://github.com/bitcoin/bitcoin/issues/17145)
- [#20160 — Proposed Timeline for Legacy Wallet and BDB removal](https://github.com/bitcoin/bitcoin/issues/20160)
- [#23727 — Make rescans faster](https://github.com/bitcoin/bitcoin/issues/23727)
- [#25800 — IBD stalls permanently with v23](https://github.com/bitcoin/bitcoin/issues/25800)
- [#27848 — Indefinite shutting down](https://github.com/bitcoin/bitcoin/issues/27848)
- [#27827 — Silent Payments send and receive](https://github.com/bitcoin/bitcoin/pull/27827)
- [#28241 — Dedicated silent payments index](https://github.com/bitcoin/bitcoin/pull/28241)
- [#29348 — v26 shuts down without warning](https://github.com/bitcoin/bitcoin/issues/29348)
- [#31534 — Warn on shutdown for big UTXO flushes](https://github.com/bitcoin/bitcoin/pull/31534)
- [#32955 — v29 enters IBD when only 600 blocks behind](https://github.com/bitcoin/bitcoin/issues/32955)
- [#33468 — sqlite legacy descriptor wallet migration fails](https://github.com/bitcoin/bitcoin/issues/33468)
- [gui#804 — UI unresponsive while syncing](https://github.com/bitcoin-core/gui/issues/804)

### Specifications & docs

- [Bitcoin Core PSBT docs](https://github.com/bitcoin/bitcoin/blob/master/doc/psbt.md)
- [Bitcoin Core REST interface docs](https://github.com/bitcoin/bitcoin/blob/master/doc/REST-interface.md)
- [Bitcoin Core zmq docs](https://github.com/bitcoin/bitcoin/blob/master/doc/zmq.md)
- [AssumeUTXO design doc](https://github.com/bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md)
- [BIP 157/158 — Compact Block Filters](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)
- [BIP 352 — Silent Payments](https://bips.dev/352/)
- [BIP 388 — Wallet Policies](https://en.bitcoin.it/wiki/BIP_0388)
- [Proper Money Handling (JSON-RPC) — Bitcoin Wiki](https://en.bitcoin.it/wiki/Proper_Money_Handling_(JSON-RPC))

### Bitcoin Optech

- [Fee estimation topic](https://bitcoinops.org/en/topics/fee-estimation/)
- [Replace-by-fee](https://bitcoinops.org/en/topics/replace-by-fee/)
- [Transaction pinning](https://bitcoinops.org/en/topics/transaction-pinning/)
- [Miniscript](https://bitcoinops.org/en/topics/miniscript/)
- [Silent payments](https://bitcoinops.org/en/topics/silent-payments/)
- [AssumeUTXO](https://bitcoinops.org/en/topics/assumeutxo/)
- [Output script descriptors](https://bitcoinops.org/en/topics/output-script-descriptors/)
- [Newsletter #334 — 2024 Year-in-Review](https://bitcoinops.org/en/newsletters/2024/12/20/)

### Research & commentary

- [Delving Bitcoin — Mempool-based fee estimation](https://delvingbitcoin.org/t/mempool-based-fee-estimation-on-bitcoin-core/703)
- [Transaction Fee Estimation in the Bitcoin System (arXiv 2024)](https://arxiv.org/html/2405.15293v1)
- [Strike — Blended Bitcoin Fee Estimations](https://strike.me/en/blog/blended-bitcoin-fee-estimations/)
- [Peter Todd — One-Shot Replace-by-Fee-Rate](https://petertodd.org/2024/one-shot-replace-by-fee-rate)
- [Lopp — Revisiting Bitcoin Network Bandwidth Issues](https://blog.lopp.net/revisiting-bitcoin-network-bandwidth-issues/)
- [Lopp — Effects of DBcache Size on Sync Speed](https://blog.lopp.net/effects-dbcache-size-bitcoin-node-sync-speed/)
- [Lopp — Boost Your Bitcoin Node Sync With UTXO Snapshots](https://blog.lopp.net/bitcoin-node-sync-with-utxo-snapshots/)
- [Protos — No auto-update in Bitcoin Core](https://protos.com/no-auto-update-in-bitcoin-core-means-13-of-nodes-could-crash/)
- [Bitcoin Core PR Review Club — Fast rescan with BIP157](https://bitcoincore.reviews/15845)

### Ecosystem tools that exist *because* Core lacks something

- [mempool/mempool](https://github.com/mempool/mempool) — mempool visualization & time-series
- [janoside/btc-rpc-explorer](https://github.com/janoside/btc-rpc-explorer) — explorer on top of Core RPC
- [cculianu/Fulcrum](https://github.com/cculianu/Fulcrum) — successor to electrs
- [romanz/electrs](https://github.com/romanz/electrs) — original Rust Electrum server
- [jvstein/bitcoin-prometheus-exporter](https://github.com/jvstein/bitcoin-prometheus-exporter)
- [0xB10C/bitcoind-observer](https://github.com/0xb10c/bitcoind-observer)
- [jlopp/bitcoin-core-config-generator](https://github.com/jlopp/bitcoin-core-config-generator)
- [jlopp/bitcoin-core-rpc-auth-generator](https://github.com/jlopp/bitcoin-core-rpc-auth-generator)
- [Sparrow Wallet](https://sparrowwallet.com/) — PSBT UX done right
