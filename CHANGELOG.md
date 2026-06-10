# Changelog

A terse index of satd releases. **Full, explanatory release notes live in
[`docs/release-notes/`](docs/release-notes/)** — one file per release; this
file points there for detail and keeps only a short list of unreleased changes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
satd follows [semantic versioning](https://semver.org/spec/v2.0.0.html) for its
Tier 1 public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per [`STABILITY_POLICY.md`](STABILITY_POLICY.md).

## [Unreleased] → 0.3.0

In-progress; full detail tracked in
[`docs/release-notes/0.3.0-pre.md`](docs/release-notes/0.3.0-pre.md).

- **Networking** — locally-submitted transactions now reliably propagate.
  Every broadcast surface (`sendrawtransaction`, MCP `send_transaction`,
  Esplora `POST /tx`, Electrum `transaction.broadcast`/`broadcast_package`)
  announces the tx to peers through one shared path (resubmitting an
  already-in-mempool tx succeeds and re-relays, Core semantics), and a new
  rebroadcast loop re-announces unconfirmed local txs — on a timer and to
  newly-connected outbound peers — until enough peer IPs fetch them (via
  `getdata`) or they leave the mempool, so a tx submitted with no peers
  connected is no longer stranded. The pending set persists across restarts
  (`mempool.dat` v2). Tx announcements now honor a peer's BIP 37 `fRelay`
  (blocksonly peers are never sent tx invs). `getmempoolinfo.unbroadcastcount`
  and the per-entry `unbroadcast` flag now report real values. New knobs
  (SIGHUP-reloadable): `rebroadcastinterval` (default `0` = auto, randomized
  10–15 min) and `broadcastconfirmpeers` (default `1`).

- **Storage (CRITICAL)** — fixed silent UTXO/index data loss after IBD or
  reindex: `flush_durable()` flushed only RocksDB's (empty) default column
  family, so WAL-disabled (BulkLoad) writes could evaporate on the next
  restart — losing a connected block's coins/txindex/undo wholesale and
  wedging the node with `bad-txns-inputs-missingorspent`. Durable flushes now
  cover every column family; `SplitStore` flushes both halves; leaving
  BulkLoad mode flushes durably by construction; a reindex whose exit flush
  fails now reports failure instead of success; small catch-ups
  (<10,000 blocks behind) keep the WAL on; and flat-file block data is now
  fsync'd before any durable checkpoint that references it (Core's
  `FlushBlockFile` ordering), closing a power-loss window where the block
  index could point at truncated files.
- **Tooling** — new offline `satd-chainstate-repair` binary: surgically
  re-applies a single block's lost connect delta (the damage left by the
  BulkLoad durability bug above) on a stopped node, instead of a multi-day
  reindex. Dry-run by default, verifies the damage matches the lost-delta
  signature before writing, takes a RocksDB checkpoint backup, and never
  moves the tip.
- **Consensus** — six block-level rules brought to Bitcoin Core parity (sigop
  cost, BIP30, future-timestamp, block-version gate, merkle-mutation
  /CVE-2012-2459, per-tx weight cap); reject-reason strings aligned; on-receipt
  mutated-block gate. Differential matrix now 32/32 exact vs Core.
- **Policy/mining** — two internal defaults aligned to Bitcoin Core v30: the RBF
  incremental relay fee (1000 → 100 sat/kvB) and the coinbase weight reserve
  used for block templates and fee estimation (4000 → 8000 WU).
- **Policy (fee rate)** — fee rates are now computed per **virtual byte**
  (sat/kvB), not per weight unit. Several hot paths — the min-relay-fee check,
  the RBF incremental fee, fee estimation/histogram, `getblockstats`, and the
  peer `feefilter` — divided the fee by weight (~4× vsize), so satd's effective
  relay floor was ~4 sat/vB instead of Bitcoin Core's 1 sat/vB and it **rejected
  standard 1–4 sat/vB transactions** the rest of the network relays (and under-
  reported fee rates ~4× in RPC). All sites now divide by virtual size, matching
  Core's `CFeeRate`. (Found dogfooding signet: a 412-sat / 277-vbyte tx paying
  1487 sat/kvB was wrongly rejected as "min relay fee not met. 371 < 1000".)
- **Consensus (CRITICAL, non-mainnet)** — softfork activation heights for
  script verification are now **per-network**. Both script engines previously
  applied Bitcoin **mainnet** buried heights on every chain, so on signet /
  testnet4 / regtest (tips far below mainnet's segwit height 481,824) the
  WITNESS/TAPROOT/DERSIG/CLTV/CSV flags were never enforced — making P2WPKH,
  P2WSH, and P2TR outputs **anyone-can-spend** on those networks (an unsigned
  segwit spend was accepted into the signet mempool; Core rejects it). Signet,
  testnet4, and regtest now enforce all softforks from genesis and testnet3
  uses its own buried heights, matching Bitcoin Core's `chainparams.cpp`.
  Block sigop-cost accounting's P2SH gate is per-network for the same reason.
  Mainnet behavior is unchanged (already cross-validated genesis→tip).
- **Reliability** — fixed a block-index corruption where a competing fork
  announced below the active tip could clobber the active-chain `height→hash`
  map, making `--reindex-chainstate` abort at `bad-cb-height` and loop. Header
  acceptance and block storage now only touch the index above the active tip.
  New `-checkblockindex` flag (default on for regtest/CI) runs a structural
  block-index audit at startup and after a reindex; fail-closed.
- **Consensus (testnet difficulty)** — the testnet/testnet4 20-minute
  min-difficulty walk-back now follows **parent pointers** (`prev_blockhash`),
  matching Bitcoin Core's `pprev` walk, instead of the active-chain `height→hash`
  index. The height index can have gaps (reorg artifacts / the corruption class
  above); a single gap made the walk-back stop early and return powlimit,
  rejecting a valid real-difficulty block as `bad-diffbits` and wedging header
  sync. Parent pointers are always present for any ancestor held, so difficulty
  is now immune to height-index gaps. (Observed live: a testnet4 node stuck at a
  height whose next real-difficulty block sat just past a one-block index gap.)
  Difficulty computation across all networks now also fails **closed**: a
  missing retarget-period seed or an unresolvable walk-back ancestor rejects the
  block as `bad-diffbits` instead of substituting a wrong (too-easy) value.
- **Reliability (P2P)** — stopped charging ban score for *policy* transaction
  rejections (min-relay-fee, dust, mempool-full, RBF, conflicts, non-standard).
  Only consensus-invalid txs (bad script / outputs-exceed-inputs) are now scored,
  matching Bitcoin Core. On low-fee networks (e.g. testnet4's sub-min-relay-fee
  tx soup) the old behavior banned honest peers one `+1` at a time until the
  whole reachable peer set was gone and the node could no longer sync.
- **Reliability (reindex UX)** — fixed `--reindex` progress and ETA on nodes
  whose block files hold duplicate/orphan records (e.g. competing forks stored
  during a sync wedge): the connect target is now the real genesis-reachable
  tip height rather than the raw on-disk record count, so the progress bar
  reaches 100% and the ETA no longer projects past the true finish.
- **Reliability (sync)** — fixed a wedge where a competing same-height fork at
  the IBD connect frontier looped forever on `bad-prevblk`. The height-indexed
  download scheduler counted that height as "stored" (so never fetched the
  competing parent block) yet stayed active, which suppressed the steady-state
  fork-aware block pull. Now the linear scheduler is not (re)created while the
  connect frontier is fork-blocked (`frontier_connects_to_tip`) — the
  reorg-capable steady-state path moves the tip onto the better chain first,
  then bulk IBD resumes (self-correcting at any fork depth). An already-running
  wedge is broken too: a persistent `bad-prevblk` (specifically) with a
  higher-work competing chain tears down the stalled scheduler and hands off to
  the steady-state reorg path. Non-`bad-prevblk` failures stay fail-closed.
- **TUI / logging** — the daemon startup log now reports the real build version
  (from the crate version) instead of a hardcoded `v0.1.0`. The `sat-tui` header
  shows **both** the connected daemon's version (from `getnetworkinfo`) and the
  TUI binary's own version (`srv vX · tui vY`), so a version mismatch between
  client and node is visible at a glance.
- **RPC** — `invalidateblock` / `reconsiderblock` implemented (crash-safe,
  AssumeUTXO-aware); `getblock` serves invalidated blocks.
- **P2P observability & control** — un-stubbed the peer activity counters:
  `getpeerinfo` now reports real `bytessent`/`bytesrecv`/`lastsend`/`lastrecv`
  and `getnettotals` real `totalbytessent`/`totalbytesrecv` (with matching
  `satd_net_bytes_sent_total`/`satd_net_bytes_recv_total` Prometheus counters),
  counted on the wire for both v1 and v2 transports. `setnetworkactive` is now
  a real toggle (pauses inbound accepts + outbound dials and disconnects
  peers), reflected in `getnetworkinfo.networkactive`, with a matching
  `-networkactive` startup flag. The native Prometheus listener
  (`-metricsport`) remains the recommended path for monitoring.
- **Policy** — `-acceptnonstdtxn` honored: relay/accept non-standard
  transactions (bypasses the standardness relay checks; consensus rules still
  apply). Default off, matching Core.
- **Mempool fix** — corrected an off-by-one in the mempool's coinbase-maturity
  check: a tx is spent at `tip+1`, so a coinbase at exactly 100 confirmations is
  now accepted (matching consensus / Bitcoin Core's `CheckTxInputs` and satd's
  own connect-time check). Previously the mempool was one block stricter and
  rejected a valid spend as `bad-txns-premature-spend-of-coinbase`.
- **Auth** — opt-in capability-scoped bearer-token layer (`-authfile`) across
  JSON-RPC, Esplora, events gRPC, and MCP, with per-token rate limits and
  watch-set quotas. Default credential behavior unchanged.
- **MCP** — native TLS/mTLS for the HTTP server via
  `-mcpcert`/`-mcpkey`/`-mcpmtls`; a remote bind requires TLS so the bearer token
  is never sent in cleartext. The stdio transport (`-mcpstdio`) is removed; MCP
  is HTTP(S)-only.
- **MCP (fix)** — fixed a panic that reset *every* MCP HTTP connection before a
  response (`header_read_timeout` was set on the hyper server without a timer,
  so hyper panicked as soon as it armed the timer). The MCP server now serves
  requests instead of dropping the connection.
- **Tor** — control-port auth is negotiated via `PROTOCOLINFO` and now supports
  **SAFECOOKIE**, so `-listenonion` works against a stock Tor
  (`CookieAuthentication 1`) with no `HashedControlPassword`. Falls back to
  password (`-torpassword`) or null; the server's cookie proof is verified.
  The `addnode` RPC now accepts `.onion` peers (e.g.
  `addnode "<base32>.onion:8333" add`), matching Bitcoin Core — onion peers were
  previously addable only via the `-addnode` config. Onion dials are also given
  a 20s timeout floor (Core's `SOCKS5_RECV_TIMEOUT`) independent of `-timeout`,
  so the Tor rendezvous can complete on first connection instead of being cut
  off by the 5s clearnet socket-connect budget. A `-listenonion` node now
  **advertises its own hidden service** to addrv2-capable peers (BIP 155 TorV3,
  both proactively after the handshake and in `getaddr` responses) and surfaces
  it in `getnetworkinfo.localaddresses` — so the network can discover and dial
  it inbound, where before the service was reachable only by peers handed the
  address out of band. As a prerequisite, satd now records a peer's
  `sendaddrv2` during the handshake (it was previously dropped, so satd never
  sent addrv2 to anyone); the onion network's `getnetworkinfo` `reachable` flag
  now reflects whether an onion-routing proxy is configured. New
  **`-proxyrandomize`** (default on, matching Core) gives each outbound
  connection fresh random SOCKS5 credentials so Tor isolates every peer on its
  own circuit — previously all connections shared circuits, letting a single
  guard/exit correlate the whole peer set. `getnetworkinfo` now reports the
  configured `proxy` and an honest `proxy_randomize_credentials` per network.
- **Networking** — DNS seed lists resynced to Bitcoin Core v28.0 per network
  (purely additive; new `test_core_parity_seeds_present` golden membership check
  guards Core parity).
- **API scaling** — per-surface admission control (honors `-rpcthreads` /
  `-rpcworkqueue`); isolated bounded runtime for read/streaming surfaces
  (`--api-threads`); opt-in read-only JSON-RPC listener (`-rpcreadonlybind`).
- **Streaming Consumption API** — push-based event firehose + live
  subscriptions over gRPC / WebSocket+SSE / ZMQ, with durable reorg-safe cursor
  replay; decoupled from consensus. Opt-in, wire schema `v1`.
- **Operator** — `SIGHUP` live config reload; `SIGUSR1` in-place TLS-cert
  reload.
- **Client compatibility** (surfaced by the third-party canary fleet) —
  JSON-RPC 1.0/1.1 accepted; `getpeerinfo` gains `timeoffset`/`inflight`;
  loopback exempt from `-maxinboundperip`; new-tip block announcement (BIP 130);
  `getdata MSG_CMPCT_BLOCK` served; `sendrawtransaction` txs relayed; BTC
  amounts emitted with fixed 8 decimals; Esplora coinbase `vin` carries
  `txid`/`vout`/`prevout`; synced node adopts a competing chain from an inbound
  peer.
- **Config compatibility (drop-in `bitcoin.conf`)** — an existing Bitcoin Core
  `bitcoin.conf` now drops in and starts satd unedited. Supported flags are
  honored (semantics pinned to Core v30); recognized-but-unsupported Core v30
  options are **skipped with a startup warning** (naming the satd equivalent
  where one exists) instead of aborting; a small set whose silent omission would
  mislead about security/exposure/privacy (`i2psam`, `rpcwhitelist`, …) stays
  fatal with guidance; and keys that are neither satd nor known-Core-v30 options
  are rejected as typos (so a fat-fingered `rpcusser=` can't disable auth).
  Nothing a config asks for is ever *silently* ignored. Newly honored Core
  logging knobs `-logtimestamps` / `-logthreadnames` / `-logsourcelocations`,
  and the hyphenated `reindex-chainstate` config-file spelling is accepted.
  More previously-skipped Core v30 keys are now honored: `-loglevel`
  (global or `category:level` verbosity), `-checkpoints=0` (disable built-in
  checkpoint validation), `-whitelistrelay` / `-whitelistforcerelay` (default
  relay permissions for whitelisted peers), `-allowignoredconf` (suppress
  ignored-`includeconf` warnings), and the `*notify` shell-hook family —
  `-blocknotify` (`%s`→block hash, per new best block), `-alertnotify`
  (`%s`→warning text, per new node warning), `-startupnotify` (once after
  startup) and `-shutdownnotify` (once at graceful shutdown). These hooks are
  provided for Core compatibility only; each logs a startup warning steering
  integrators to the Streaming Consumption API (the supported, reorg-safe,
  replayable integration path). The bare network selectors `testnet=1` /
  `testnet4=1` / `signet=1` / `regtest=1` in `bitcoin.conf` are now honored as
  chain selectors (matching Core); previously satd consulted only `chain=` and
  the CLI flags, silently treating such a config as **mainnet**. Conflicting
  selectors in a file (e.g. `signet=1` + `testnet4=1`, or `chain=` disagreeing
  with a bare selector) are now a startup error rather than a silent pick.
- **Monitoring** — daemon-side startup/reindex timing on `getstartupinfo`;
  `sat-tui` distinguishes an unreadable RPC cookie from rejected credentials.
- **Testing / CI** — block-consensus differential matrix (Phase B); live
  differential vs `bitcoind` + in-process fuzzer (Phase C); third-party canary
  fleet (BDK, Core interop, LND Neutrino, Electrum, CLN, NBXplorer, BTCPay) now
  required status checks.
- **Documentation** — operator docs consolidated into an mdbook **Operator
  Manual** (`docs/manual/`, published to GitHub Pages), folding in
  `OPERATOR_ERGONOMICS.md`, `docs/PACKAGING.md`, `docs/TUI.md`, the Esplora REST
  and Electrum protocol references, the native-protocol-surface architecture
  rationale, a streaming-API
  integrator guide, a complete **Configuration Flag Reference** (every key:
  default, reload disposition, Core-compatible vs satd extension), an
  **Authentication & Authorization** chapter (the unified bearer-token layer and
  how it contrasts with Core cookie/`rpcuser`/`rpcauth`), an **MCP Server**
  chapter, an **API Scaling & Runtimes** chapter (the core/API two-runtime
  split, admission-control tuning knobs, and horizontal-scaling guidance), and an
  **Initial Block Download & Fast Sync** chapter (AssumeUTXO / `loadtxoutset` /
  `--fast-start`, `assumevalid=all`, dual-engine shadow verification, the
  swarm-download / prefetch / speculative-verify pipeline, and IBD/storage tuning
  knobs — with Core differences called out). Unshipped ecosystem/mobile strategy
  moved to `ROADMAP.md` (tagged by
  likelihood).

## Releases

| Version | Date | Notes |
|---|---|---|
| [0.2.1](docs/release-notes/0.2.1.md) | 2026-05-29 | Packaging only — ship `sat-tui` in tarballs (no code change from 0.2.0). |
| [0.2.0](docs/release-notes/0.2.0.md) | 2026-05-27 | BIP 324 v2 transport, native TLS, client-side PSBT signing, Core CLI/config-compat gap closed, AssumeUTXO fast-start. **Breaking storage cleanup** — see notes. |
| [0.1.0](docs/release-notes/0.1.0.md) | 2026-05-08 | First public release: mainnet-validated node, native Esplora/Electrum/cfilters, Core-compatible RPC/CLI, signed reproducible builds. |

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.2.1...HEAD
