# satd vs. Bitcoin Core — Intentional Differences

satd is a **fully compatible, independent implementation of the Bitcoin
protocol** in Rust. Consensus rules, P2P wire format, JSON-RPC method
shapes, CLI flags, and `bitcoin.conf` syntax are kept compatible with
Bitcoin Core so that existing operators, integrators, and downstream
infrastructure (BTCPayServer, NBXplorer, Sparrow, Umbrel, Start9,
mempool.space SDK, BDK) work without code changes.

**Compatibility target: Bitcoin Core v30 — drop in your `bitcoin.conf`.**
The aim is that an existing Core `bitcoin.conf` starts satd unedited.
Commonly-used options are honored (names/semantics pinned to v30);
recognized-but-unsupported v30 options are **skipped with a startup warning**
rather than aborting, so the long tail doesn't block a drop-in; only a small
set whose silent omission would mislead about security/exposure/privacy stays
fatal; and unknown keys are rejected as typos. Nothing a config asks for is
ever *silently* ignored. satd makes no compatibility commitment for options
introduced in later Core releases (e.g. the v31 cluster-mempool knobs).

Within that compatibility envelope, satd intentionally goes further on
**features, ergonomics, and operator flexibility**. This document
catalogs those deviations: what we ship that Core doesn't, what we
intentionally don't ship, and where our default behavior differs.

The compatibility contract itself — what is Tier 1 / Tier 2 / Tier 3,
how deprecations are staged, what migration invariants apply — lives
in `STABILITY_POLICY.md`.

Last updated: 2026-06-01.

---

## Compatibility envelope

These surfaces match Bitcoin Core. We treat any user-visible deviation
as a bug unless explicitly enumerated below.

- **Consensus rules** — full P0 parity; script evaluation is mainnet
  shadow-validated against `libbitcoinconsensus` from genesis through
  ~945k blocks (zero divergence). The block-acceptance pipeline around
  scripts is held to Core by a differential test battery: static fixtures
  ported from Core's own block-acceptance tests, plus a generative fuzzer
  that dual-submits adversarial blocks to `satd` and a live `bitcoind` and
  asserts identical accept/reject. Soft-forks through Taproot (BIPs 141,
  143, 152, 155, 158, 340, 341, 342, 345) are active. Locktime, BIP 68
  sequence locks, BIP 34 coinbase height enforcement, witness commitment
  validation, and median-time-past semantics all match.
- **P2P wire** — standard `NetworkMessage` types via the `bitcoin`
  crate; BIP 152 compact blocks, BIP 155 addrv2, BIP 157/158 compact
  filters, BIP 339 wtxid relay, BIP 324 v2 encrypted transport
  (`-v2transport`, on by default).
- **JSON-RPC method shapes** — 80 Core-named methods, response field
  names + types preserved by default. RPC extensions are **opt-in per
  request** (the `amounts=sats` and structured-error patterns below)
  rather than unconditional schema additions. Like Core, the server
  accepts JSON-RPC **1.0 / 1.1 / 2.0** request envelopes (and a missing
  `jsonrpc` member), since the canonical Core client libraries —
  NBitcoin/NBXplorer/BTCPayServer, `python-bitcoinrpc` — send the 1.0
  form; responses use the JSON-RPC 2.0 shape.
- **CLI flag names + defaults** — `-regtest`, `-datadir`, `-rpcport`,
  `-rpcuser`, `-rpcpassword`, `-prune`, `-txindex`, `-reindex`,
  `-reindex-chainstate`, `-assumevalid`, `-mempoolfullrbf`, `-maxmempool`,
  `-minrelaytxfee`, `-dustrelayfee`, `-datacarrier`, `-datacarriersize`,
  `-limitancestorcount`, `-limitdescendantcount`, `-mempoolexpiry`,
  `-permitbaremultisig`, etc.
- **`bitcoin.conf` / `satd.conf`** — accepted in either filename;
  Core's section + key syntax preserved.
- **Cookie auth** — `~/.bitcoin/.cookie` (or `$datadir/.cookie`) with
  the same `__cookie__:<token>` Basic Auth contract Core-compatible
  tooling generates.

---

## Architectural differences

These are implementation choices below the wire-compatible surface.
They have operator-visible second-order effects (storage layout, build
artifacts, signing stack) but no protocol consequences.

| Surface | Bitcoin Core | satd |
|---|---|---|
| **Implementation language** | C++ | Rust (edition 2024) |
| **Script verification** | `libbitcoinconsensus` (C++) | `bitcoinconsensus` FFI primary + native Rust verifier as parity-validated shadow |
| **Storage backend** | LevelDB (chainstate, indices) + flat block files | RocksDB (chainstate + all indices, single instance, zstd + lz4) + flat block files; jemalloc allocator |
| **Async runtime** | `boost::asio` + `std::thread` mix | `tokio` for all I/O |
| **JSON-RPC server** | bespoke HTTP / SSL stack | `jsonrpsee` over `tower` middleware (with native TLS support) |
| **Reproducible builds** | Guix | Nix flake (Guix may follow if a downstream packager needs it) |
| **Release signing** | GPG (PGP) | minisign (artifacts) + cosign keyless (containers) + SSH sigs (git tags). No GPG. |
| **Peer address store** | `peers.dat` (Core bucketed addrman serialization) | `peers.dat` with a satd-native versioned format (magic `SADR`) — **not** byte-compatible with Core's file |
| **Log destination** | `debug.log` file in the datadir (plus optional console); internal rotation; `SIGHUP` reopens the file | **stdout only**; no `debug.log`. Rotation/retention is delegated to systemd-journald or the container runtime. `SIGHUP` is therefore free for config reload (see Operator-facing additions). |

**On `peers.dat` compatibility.** satd persists its address manager to
`peers.dat` (same filename), but the on-disk format is satd-native and
not interchangeable with Core's. The two daemons will not read each
other's `peers.dat`; satd silently discards an unrecognized file and
rebuilds its address set from DNS seeds / `-seednode`. Operators
migrating a datadir should let satd regenerate `peers.dat` rather than
expect Core's peer set to carry over.

**Why one RocksDB instance.** Core uses LevelDB and bundles indices
(`-txindex`, `-blockfilterindex`, `-coinstatsindex`) as separate
LevelDB databases. satd uses one RocksDB with multiple column families
(`block_index`, `coins`, `tx_index`, `addr_funding_v2`,
`addr_spending_v2`, `block_filters`, `block_filter_headers`,
`cf_meta`, `outpoint_spend`, `undo`, `tip`, `height_hash`). Index updates ride the same
`WriteBatch` as the connect-block / disconnect-block path, so
protocol handlers cannot observe an index out of sync with the tip.
This is the architectural foundation for native Esplora and Electrum
without the second-copy, parallel-rescan, reorg-race costs of the
`bitcoind + electrs` two-process world. A fully-indexed satd
(`-txindex -addressindex -blockfilterindex`) uses more disk in aggregate
than `bitcoind + electrs + esplora` summed, because one store serves all
those surfaces and materializes the spend graph in both directions; the
trade is disk for tip-consistent, single-process operation. The byte-level
accounting and the trade-offs are documented in the Operator Manual's
[Disk Footprint & Indices](https://epochbtc.github.io/satd/disk-footprint.html)
chapter.

---

## Native protocol surfaces (Core requires bundled side-cars)

The biggest set of intentional differences. Bitcoin Core operators
typically run a stack: `bitcoind + electrs/Fulcrum + esplora +
prometheus-exporter + custom-zmq-consumer + nginx` (for TLS). satd ships those
surfaces in-tree, sharing chainstate, with **native TLS support** for Electrum, Esplora, and JSON-RPC.

### Esplora REST server (`esplora-handlers`)

Native handlers for the Esplora wire format consumed by BDK, Mutiny,
mempool.space SDK, and the blockstream.info / mempool.space public
APIs. On by default on `127.0.0.1:3000`. Optional TLS via `--esploratlsbind`.

- Wire-shape parity with `blockstream.info` / `mempool.space` for the
  implemented endpoint set: chain, block, tx, address/scripthash,
  outspends, merkle proofs, mempool + fee, root.
- Server-Sent Events live updates (`/blocks/sse`, `/address/:addr/sse`,
  `/scripthash/:hash/sse`).
- Cookie + userpass auth modes (default unauthenticated on loopback;
  non-loopback exposure must explicitly set auth).
- CORS, request-timeout, concurrency caps, hard-wired 1 MiB body cap on
  `POST /tx`.
- See `docs/manual/src/esplora.md` for the endpoint reference.

### Electrum protocol server (`electrum-proto`)

Native v1.4.5 protocol server vendored from `romanz/electrs` (MIT
attribution preserved in `electrum-proto/vendor/electrs.MIT`) adapted
to call our `AddressIndex` trait against the shared RocksDB. Plain
TCP loopback default; optional TLS via `--electrumtlsbind`.

- `server.{version, banner, ping, donation_address, features, peers.subscribe}`.
- `blockchain.headers.{subscribe, get}`, `blockchain.block.{header, headers}`.
- `blockchain.scripthash.{get_history, get_balance, listunspent,
  get_mempool, get_first_use, subscribe, unsubscribe}`.
- `blockchain.transaction.{get, get_merkle, broadcast,
  broadcast_package, id_from_pos}`.
- `blockchain.estimatefee`, `blockchain.relayfee`,
  `mempool.get_fee_histogram`.
- JSON-RPC batch requests up to `--electrummaxbatchrequests`.
- Server-pushed notifications on the same TCP connection (no separate
  notification socket).

Unlocks BlueWallet, Sparrow, Nunchuk, Electrum desktop, hardware-wallet
coordinators in one move. Bitcoin Core operators typically deploy
`electrs` or `Fulcrum` as a separate process that re-indexes the chain;
satd makes that a runtime flag.

### Address-history index (`node-index`)

Per-scripthash funding + spending history over the shared RocksDB.
Atomic with `connect_block` / `disconnect_block`. Default-on
(`--addressindex=1`); auto-required by Esplora and Electrum. Mempool
variant in-memory; subscription registry per-scripthash; deferred
AssumeUTXO backfill via `backfillindex address`. Two RocksDB column
families (`addr_funding_v2`, `addr_spending_v2`) keyed by
`(scripthash_prefix[16], height_be[4], txid[32], vout/vin_be[4])`.
Source lives in `node-index/` and `node/src/index/address/`.

Bitcoin Core deliberately stays out of address-indexing for scaling
reasons. satd accepts the disk cost (~120-180 GB compressed at mainnet
tip) as a documented trade and lets operators opt out
(`--addressindex=0`) on storage-constrained boxes.

### BIP 157/158 compact block filters (`node-filter-index`)

Index + P2P service. Builds the BIP 158 SCRIPT_FILTER (filter type
`0x00`) atomically inside the same write batch as the chainstate, and
answers BIP 157 P2P queries when `--peerblockfilters=1`. Advertises
`NODE_COMPACT_FILTERS` (bit 6) at the version handshake. Deferred
backfill via `backfillindex blockfilter` for datadirs synced before the
index landed.

Bitcoin Core implements BIP 157/158 indexing but the P2P serving arm is
limited; satd's is the modern light-client path for Zeus-embedded,
Blixt, and Mutiny.

### BIP 352 silent-payment tweak index (`node-sp-index`)

Index (`--silentpaymentindex=1`, default off, always compiled) that
computes one public tweak per eligible transaction (`T = input_hash · A`)
and stores it, with the transaction's largest taproot output value, in a
per-block row committed atomically with the chainstate. Each row embeds
the hash of the block it describes, so a served row is self-authenticating.
Deferred backfill via `backfillindex silentpayment` for datadirs synced
before the index landed.

Two consumption modes on the streaming API (see the wire spec in
`docs/api/streaming.md`): a **client-side scan** firehose (`tweaks`
category, bit 8 — explicit-request only, never in the `categories = 0`
default) that streams each block's tweak data for local one-ECDH-per-tx
scanning (the scan key never leaves the device), and a JSON-RPC fallback
`getsilentpaymentblockdata "blockhash" ( verbosity dust_limit )` serving
the same bytes for scripts and integrators. Tweaks-only replay cold-syncs
from taproot activation in one subscription (exempt from the replay clamp
because rows are self-authenticating and the exemption is gated on index
completeness).

Bitcoin Core has no silent-payment index; wallets must scan blocks
themselves. satd moves the tweak computation server-side while keeping
scanning (and thus the scan key) on the client.

### Mempool subscription stream

`subscribemempool` JSON-RPC WS subscription emitting structured events:

- `enter` — new tx admitted.
- `leave_confirmed` — tx confirmed in a block.
- `leave_evicted` — `reason: full_pool | expiry`.
- `leave_replaced` — with `replacing_txid`.

Bulk `getmempoolentry` (array → map of verbose entries), ring-buffered
`getmempoolhistory [since_secs]` with feerate histogram snapshots.

Bitcoin Core requires polling `getrawmempool` or rebuilding state from
ZMQ per-tx events. satd's stream has explicit eviction reasons and RBF
replacement linkage.

### Transaction-filtering / quarantine policy (`satd-policy`)

An optional, total, statically-cost-bounded policy language
(`policyfile=<path>`) that *quarantines* transaction shapes — withholding
them from relay and/or block templates — without ever changing what the node
accepts as valid; consensus is untouched by construction. Live `SIGHUP`
reload (last-good-wins, lossless re-placement). A strict-by-default
Lightning-enforcement danger gate refuses a rule that would withhold relay
for L2 enforcement traffic (BOLT-3 commitment/justice/HTLC, taproot spends);
opt out with
`allowdangerousfilters=1`. Offline `sat-cli policylint` catches a dangerous
rule before it is ever loaded (exit 3). Observability is additive and
disjoint from the standard surfaces: `getpolicyinfo`, `getquarantineinfo`,
`listquarantine`, `getquarantineentry`, `policytest`, matching MCP tools, and
`satd_policy_*` Prometheus metrics — every standard mempool surface
(`getrawmempool`, Electrum, Esplora, the standard MCP mempool tools) stays
acting-class-only and byte-identical whether or not anything is quarantined.

Bitcoin Core's relay policy is a fixed C++ decision tree
(`-minrelaytxfee`/`-datacarriersize`/etc.) with no way for an operator to
express an arbitrary shape-based withholding rule without a source patch.
No Bitcoin Core equivalent.

### Persistent reorg log + webhook

JSONL append-only log at `$datadir/reorg.log` with an in-memory
256-record ring. `getreorghistory [since_secs]` RPC. Optional
`--reorg-webhook=<url>` HTTP POST with `--reorg-webhook-secret=<secret>`
HMAC-SHA256 `X-Satd-Signature: sha256=...` for integrity.

Bitcoin Core's `getchaintips` reflects current known tips only;
yesterday's reorgs are gone. Exchanges and custodians log reorgs
externally. satd does it natively.

### Operator HTTP endpoints (`/metrics`, `/healthz`, `/readyz`)

Single `--metricsbind=<addr:port>` enables a Prometheus text-format
metrics endpoint plus liveness and readiness probes. Stable metric
schema documented in `node/src/metrics.rs`. Unauthenticated by design
(loopback or behind a reverse proxy).

Bitcoin Core requires third-party exporters
(`jvstein/bitcoin-prometheus-exporter`, `0xB10C/bitcoind-observer`);
each has different metric names and coverage gaps.

### Events bus (`satd-events`)

gRPC server + ZMQ publisher sinks for chain + mempool envelopes. Edge
identity (node ID + region) and heartbeat included in every envelope.

Bitcoin Core ships `-zmqpub*` raw-topic publication (one ZMQ topic per
event type, raw bytes). satd ships a structured event envelope instead,
designed for operator pipelines that want to consume across many nodes
with consistent shape and provenance. Core's per-topic ZMQ model is
**intentionally not** implemented — see "Intentional exclusions" below.

### MCP server (`satd-mcp`)

Model Context Protocol tools over the ops-surface RPCs, served over a
streamable-HTTP(S) transport (`--mcpport`, with native TLS/mTLS via
`--mcpcert`/`--mcpkey`/`--mcpmtls`). Lets agentic / LLM consumers call
`get_health`, `get_reorg_history`, `subscribe_mempool_snapshot`, etc.
without re-implementing JSON-RPC auth.

No Bitcoin Core equivalent.

### Ratatui TUI (`sat-tui`)

Live ops TUI: IBD bitmap with per-block progress, per-peer stats,
in-flight / pending counts, service-status row, RPC explorer.
`getibdprogress` RPC is the underlying data source — richer than Core's
scalar `verificationprogress`.

No Bitcoin Core equivalent.

---

## Operator-facing additions (within Core compatibility)

These ride on top of Core-shape behavior. The Core-shape default is
preserved; the satd extension is opt-in per request or per flag.

- **`-v2only`** — refuse peers that do not speak the BIP 324 v2 encrypted
  transport. Core's `-v2transport` (offer/accept v2, fall back to v1) is
  supported and on by default; `-v2only` is a satd-specific privacy lever
  that drops inbound v1 peers at detection and never downgrades outbound
  connections to v1. Off by default: as of 2026 most surveillance and
  DoS nodes do not speak v2, so `-v2only` sheds essentially all of that
  traffic without banlists — at the cost of also dropping honest peers
  that have not yet upgraded, so it stays opt-in until v2 adoption is
  high. `getpeerinfo.transport_protocol_type` reports `v1`/`v2` per peer.

- **`--profile=<preset>`** — bundled config presets (`archival`,
  `pruned-home`, `mining`, `regtest-dev`, `signet-watchtower`). CLI
  flags override profile values. `getconfig` RPC + `sat-cli node config`
  show the effective post-merge configuration with secrets redacted.

- **Structured CLI subcommands** (`sat-cli`) — `chain info`,
  `chain tips`, `mempool top`, `peer list`, `peer ban`, `fee estimate`,
  `tx decode`, `psbt analyze`, `node status`, `node logs`, `node reorgs`,
  etc. Pretty-printed by default, `-o json|yaml|raw` as escape hatch.
  Legacy raw-method form (`sat-cli getblockchaininfo`) still works via
  clap's `external_subcommand`.

- **Satoshis-as-integers** — per-request `amounts=sats|btc`. Default
  wire format remains BTC-as-doubles for Core compat; callers opt into
  `"amounts": "sats"` per request and verify via the `"units": "sats"`
  field in the response. Closes Core's
  [#3249](https://github.com/bitcoin/bitcoin/issues/3249) (open since
  2013).

- **Structured RPC errors** — opt-in `category` / `suggestion` /
  `debug` fields on JSON-RPC error payloads (`node/src/rpc/error.rs`).
  Default error shape stays Core-compat. Category schema is
  `STABILITY_POLICY.md` Tier 2.

- **`estimatefees` mempool-aware mode** — alongside the historical
  Core-shape `estimatesmartfee` (preserved unchanged), the
  `estimatefees` RPC simulates next-N block templates from the current
  mempool with CPFP-aware sorting, and never errors — always returns a
  `confidence: low|medium|high` field. Closes Core's
  [#11500](https://github.com/bitcoin/bitcoin/issues/11500).

- **Structured-JSON logs** — `--log-format=json|text`. Default text for
  humans, json for production. Stable field schema, trace IDs on the
  block-validation pipeline.

- **`SIGHUP` reloads config (does not reopen a log file).** Bitcoin Core
  treats `SIGHUP` as "reopen `debug.log`" for logrotate. satd has no
  `debug.log` (it logs to stdout — see the **Log destination** row in
  Architectural differences), so `SIGHUP` is repurposed for **live config
  reload**: edit `bitcoin.conf` and `kill -HUP <pid>` (or
  `systemctl reload satd`) to re-read the file and apply the hot-reloadable
  subset of settings without a restart. CLI flags stay authoritative across
  reloads (only the file is re-read). Hot-reloadable settings include log
  verbosity (`-debug`/`-debugexclude`), connection knobs
  (`-timeout`/`-blocksonly`/`-maxuploadtarget`/`-v2transport`/`-v2only`/`-externalip`/`-whitelist`),
  the RPC-behavior switches (`-rpcextendederrors`/`-rpcdefaultunits`), mempool
  and relay policy (`-minrelaytxfee`/`-maxmempool`/`-dustrelayfee`/`-datacarrier(size)`/`-mempoolfullrbf`/`-limit{ancestor,descendant}count`/`-mempoolexpiry`/`-permitbaremultisig`),
  and the peer-limit knobs (`-maxconnections`/`-maxinboundperip`/`-bantime`).
  Settings wired into long-lived state at startup (network, datadir, ports,
  binds, `-dbcache`, indices, TLS, seeds, Tor) are reported in the log as
  "restart required" and never silently ignored. A reload that fails to parse
  (e.g. a typo, which is rejected at load) is logged and the running config is
  kept — the daemon never crashes on a bad reload. The
  authoritative per-key list is in the operator manual (`docs/manual/src/configuration.md`).

- **`SIGUSR1` reloads TLS certificates in place.** Bitcoin Core has no
  `SIGUSR1` handler and no native TLS (its JSON-RPC is HTTP-only, fronted by a
  TLS-terminating sidecar). satd terminates TLS natively on the RPC, Esplora,
  and Electrum surfaces, so `kill -USR1 <pid>` re-reads each surface's leaf
  cert/key from its **already-configured** path and swaps it into the live
  listener — new handshakes use the new cert, in-flight connections keep
  theirs, and the socket never rebinds. Built for short-TTL auto-rotated certs
  (cert-manager / ACME / Vault). The cert/key **paths** and the mTLS **CA**
  remain restart-only. A failed reload keeps the previous, still-valid cert.
  Kept separate from `SIGHUP` so frequent automated cert rotation doesn't
  re-read `bitcoin.conf` or run the config diff/apply machinery. See the
  operator manual (`docs/manual/src/configuration.md`).

- **`getibdprogress`** — IBD bitmap + per-peer tracking; richer than
  Core's `verificationprogress` scalar.

- **Native Tor v3** — `ADD_ONION` / `DEL_ONION` via control port, with
  `PROTOCOLINFO`-negotiated auth (SAFECOOKIE by default, password, or null) and
  hardcoded `.onion` seeds. No external torification daemon.

- **Parallel IBD with prefetch + speculative verification** —
  cross-block pipeline. Core parallelizes within a block via
  `CCheckQueue` but not across blocks.

---

## Intentional exclusions

These surfaces will not ship. Each is a deliberate scope decision.

- **Legacy (BDB) wallet, WIF-keyed wallet RPCs, descriptor-wallet GUI.**
  Out of scope by project charter — satd assumes external wallets
  (Sparrow, Nunchuk, hardware wallets) and exposes PSBT construction,
  decoding, analysis, combining, finalizing, joining, `utxoupdatepsbt`,
  and `signrawtransactionwithkey`. PSBT *signing* is offered too, but
  deliberately **client-side** via `sat-cli signpsbtwithkey`: the key is
  read from stdin and signed locally so it never traverses RPC or lands
  in the keyless daemon. Core's v30 removal of
  `addmultisigaddress`, `dumpprivkey`, `dumpwallet`, the `import*`
  family, `sethdseed`, `upgradewallet`, etc. is a surface satd never
  exposed.

- **BIP 37 bloom filters** (`FilterLoad` / `FilterAdd` / `FilterClear`
  / `MerkleBlock`). Deprecated and off-by-default in Core since v0.19
  (2019). Known privacy leak and DoS vector. No modern wallet uses
  them. BIP 157/158 compact filters are the modern replacement and
  ship natively.

- **`MemPool` P2P message.** Rarely used; mostly by bloom filter
  clients.

- **Bitcoin Core-style `-zmqpub*` raw topic publication.** Core's
  per-topic ZMQ model (one topic per event type, raw bytes) is replaced
  by the structured event envelope on `satd-events` (gRPC + ZMQ frames
  with edge identity + heartbeat). Migration path for Core operators
  consuming `-zmqpubrawblock` etc. is documented in the events crate
  README.

- **GPG release signing.** See `STABILITY_POLICY.md` — minisign +
  cosign keyless + SSH sigs, no GPG even as fallback.

---

## Behavioral defaults that intentionally differ

Both behaviors sit inside the Core compatibility envelope, but the satd
default differs from the Core default. Operators who need Core's
default behavior set the corresponding flag.

| Default | Bitcoin Core | satd | Reasoning |
|---|---|---|---|
| Esplora REST listener | not present | on (loopback, unauth) | satd ships native Esplora; loopback default keeps the auth-defaults choice safe. Disable with `--esplora=0`. |
| Address index | not present | on (`--addressindex=1`) | Required by Esplora and Electrum. Opt out with `--addressindex=0` on storage-constrained nodes. |
| `/metrics` HTTP server | not present | off | Off by default; enable with `--metricsbind=<addr:port>`. |
| Electrum server | not present | off | Off by default; enable with `--electrum=1`. |
| Block-filter index | off | off | Matches Core; enable with `--blockfilterindex=basic`. |
| `--peerblockfilters` | off | off | Matches Core; opt in to advertise `NODE_COMPACT_FILTERS`. |
| `--mempoolfullrbf` | on (Core v28+) | on | Matches Core post-v28. |
| `--listenonion` | on (no-op without Tor) | off (on if `-torcontrol` set) | Core defaults it on, but it's a silent no-op unless a Tor control port is reachable; satd defaults it off to avoid dialing the control port on every boot. When on, satd creates a v3 hidden service via `-torcontrol` (default `127.0.0.1:9051`). An explicit `-torcontrol` implies `-listenonion=1`; `-listenonion=0` forces it off. |

---

## Migration for Core operators

A Core datadir is **not** byte-compatible with satd (different storage
backend), but your `bitcoin.conf` and CLI flags drop in: satd reads Core's
config surface, honors the commonly-used options, and **skips any option it
doesn't implement with a startup warning** rather than refusing to start (a
few security/exposure/privacy-sensitive keys are the exception and fail with
guidance — see the [Configuration Flag Reference](docs/manual/src/config-reference.md)).
So the same `bitcoin.conf` starts satd; review the skip warnings on first boot
to see which lines had no effect. The intended migration is:

1. Stop `bitcoind`. Keep the flat-file `blocks/` directory if you want
   to skip re-downloading the chain (satd reuses the same flat-file
   layout).
2. Move the Core `chainstate/`, `indexes/`, and `wallets/` directories
   aside (satd doesn't read them).
3. Start satd with the same `bitcoin.conf`. `-reindex-chainstate`
   replays the flat files into the RocksDB chainstate.
4. Optional: `backfillindex address` and `backfillindex blockfilter` to
   populate the satd-specific indices from disk.

Backfills run concurrently with live block validation, so the node
serves correctly with partial history while they progress. End-to-end
migration timings on representative hardware are not yet benchmarked;
this section will be updated when measurements are available.

---

## References

- `STABILITY_POLICY.md` — Tier 1 / 2 / 3 stability contract.
- Operator manual (`docs/manual/`) — operator flag matrix, tuning, the native
  protocol-surface architecture, and packaging.
- `ROADMAP.md` — unshipped operator features and the ecosystem / mobile strategy.
- `docs/manual/src/esplora.md` — Esplora REST endpoint reference.
