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

- **Consensus** — six block-level rules brought to Bitcoin Core parity (sigop
  cost, BIP30, future-timestamp, block-version gate, merkle-mutation
  /CVE-2012-2459, per-tx weight cap); reject-reason strings aligned; on-receipt
  mutated-block gate. Differential matrix now 32/32 exact vs Core.
- **Policy/mining** — two internal defaults aligned to Bitcoin Core v30: the RBF
  incremental relay fee (1000 → 100 sat/kvB) and the coinbase weight reserve
  used for block templates and fee estimation (4000 → 8000 WU).
- **Reliability** — fixed a block-index corruption where a competing fork
  announced below the active tip could clobber the active-chain `height→hash`
  map, making `--reindex-chainstate` abort at `bad-cb-height` and loop. Header
  acceptance and block storage now only touch the index above the active tip.
  New `-checkblockindex` flag (default on for regtest/CI) runs a structural
  block-index audit at startup and after a reindex; fail-closed.
- **RPC** — `invalidateblock` / `reconsiderblock` implemented (crash-safe,
  AssumeUTXO-aware); `getblock` serves invalidated blocks.
- **Auth** — opt-in capability-scoped bearer-token layer (`-authfile`) across
  JSON-RPC, Esplora, events gRPC, and MCP, with per-token rate limits and
  watch-set quotas. Default credential behavior unchanged.
- **MCP** — native TLS/mTLS for the HTTP server via
  `-mcpcert`/`-mcpkey`/`-mcpmtls`; a remote bind requires TLS so the bearer token
  is never sent in cleartext. The stdio transport (`-mcpstdio`) is removed; MCP
  is HTTP(S)-only.
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
