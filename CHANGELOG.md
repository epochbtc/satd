# Changelog

A terse index of satd releases. **Full, explanatory release notes live in
[`docs/release-notes/`](docs/release-notes/)** — one file per release; this
file points there for detail and keeps only a short list of unreleased changes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
satd follows [semantic versioning](https://semver.org/spec/v2.0.0.html) for its
Tier 1 public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per [`STABILITY_POLICY.md`](STABILITY_POLICY.md).

## [Unreleased]

Bound for **0.5.2**, a patch release on the 0.5.x line. This is an index: every
item below is (or will be) written up in full in the in-development
[`docs/release-notes/0.5.2-pre.md`](docs/release-notes/0.5.2-pre.md).

### Changed

- **Breaking:** `getdeploymentinfo` reports the buried deployments under
  Bitcoin Core's names — `dersig` is now `bip66` and `cltv` is now `bip65`
  (#666). It also honours the `blockhash` argument instead of ignoring it.

### Added

- `validateaddress` reports *why* an address is invalid: Core's `error`
  string plus `error_locations` for a Bech32 checksum failure.
- `dumptxoutset` accepts Core's `type` argument (every Core-shaped call was
  previously a parse error), and resolves a relative `path` against the
  network data directory as Core does rather than the working directory.

### Fixed

- `validateaddress` reported an address from another network as valid — it
  never checked the network at all.

- JSON-RPC: a mistyped argument no longer discards every argument after it.
  `generateblock` with a bad `transactions` silently ignored `submit=false`
  and mined a block. Wrong-typed arguments now return Core's `-3`
  `Wrong type passed:` error naming each one (#672).
- `sat-cli -named`: an argument with no `=` was silently dropped; it is now
  sent as a positional argument in Core's reserved `args` slot (#672).

## Releases

| Version | Date | Notes |
|---|---|---|
| [0.5.1](docs/release-notes/0.5.1.md) | 2026-09-04 | A Bitcoin Core compatibility release. satd now runs **Core's own functional test suite**, unmodified and pinned to a Core release, with all 264 test files inventoried as run-or-skip-with-a-reason; the set gates every pull request and found twelve defects in shipped behaviour — an RPC `Content-Type` Core-derived clients reject outright, a startup listener answering "no such method" where Core answers "warming up", a `bitcoin.conf` fee-rate value silently discarded, a panic on any unparseable `-bind` (and no IPv6 bind at all), mempool chain limits enforcing a limit Core v31 no longer has, and an oversized locator banning the peer where Core only disconnects. The mempool event broadcast now holds a whole block's confirmations — its 1024-slot ring was smaller than a single mainnet block, so every subscriber silently lost roughly 37% of each block's burst (#682). Silent payments reach wallets that exist today via `blockchain.tweaks.subscribe` on the Electrum server, plus `tweak_unspent_only` cut-through and spendable silent-payment outputs (#609). **Breaking:** `getindexinfo` is now Core's method — satd's richer view moved to `getsatdindexinfo`; `uacomment` is now validated and an unparseable `minrelaytxfee`/`dustrelayfee` now stops the node. Drop-in binary upgrade, no reindex. |
| [0.5.0](docs/release-notes/0.5.0.md) | 2026-08-25 | The wallet-backend release — **BIP 352 silent payments, receive-side, end to end**: an opt-in tweak index (`silentpaymentindex=1`), a streaming tweak firehose with taproot-era cold-sync and mempool-time tweaks, and a server-side scan-key watch (confirmed + unconfirmed) with index-accelerated rescan, proven against the BIP 352 reference vectors. Adds a first-party Go SDK (`satdevents`) in full parity with the Rust SDK, node-health alerting (six detectors reported via status events, Prometheus, and webhooks), three BIP 141 witness rules at exact Core parity, chain-integrity fixes (tip standing on never-connected blocks, reorg/connector races, MTP from displaced branches, a block/index durability hole plus `getblockfrompeer` repair), Core v28+ obfuscated block-file reading, and measured index footprints in the manual. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.4.0](docs/release-notes/0.4.0.md) | 2026-07-06 | Two major additions: an opt-in transaction-filtering/quarantine policy language (`policyfile=`, with a strict-by-default Lightning-enforcement danger gate) and a substantially matured Streaming Consumption API — a published Rust SDK (`satd-events-client`), events gRPC TLS/mTLS, bounded historical rescan, resilient reconnect-and-replay watches (durable-truth loader + atomic reload), descriptor match attribution, and in-band `ScriptMatched` value/raw-tx enrichment. Also fixes a `getrawmempool` verbose O(N²) blowup, ships profilable release binaries, and makes a P2P listener bind failure fatal at startup instead of silently degrading. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.3.2](docs/release-notes/0.3.2.md) | 2026-06-24 | Consensus fix on the 0.3.x line — median-time-past now walks the candidate block's own ancestors instead of the active-chain height index, fixing a fork-handling bug that could permanently stall a node behind the tip (canonical successor blocks rejected `time-too-old`). Surfaced on testnet4's min-difficulty timestamp sawtooth. No breaking changes; defaults stay Bitcoin Core-compatible. |
| [0.3.1](docs/release-notes/0.3.1.md) | 2026-06-15 | Maintenance release on the 0.3.x line — all bug fixes and tooling, no breaking changes. Fee estimation reworked and unified across every surface (monotone tiers; **corrected a 4× over-report on Esplora/Electrum fee rates**, a regression since 0.3.0); `getrawmempool` verbose no longer O(N²); profilable release binaries (frame pointers + a signed per-target debuginfo sidecar); and the MCP `get_metrics_snapshot` tool now reports real address-index state. Defaults stay Bitcoin Core-compatible. |
| [0.3.0](docs/release-notes/0.3.0.md) | 2026-06-10 | Consensus hardening — per-network softfork-activation heights (critical, non-mainnet), six block-level rules brought to Core parity, a live Core block-acceptance differential + fuzzer — and **critical storage-durability fixes** (silent UTXO/index loss after IBD/reindex, plus an offline `satd-chainstate-repair` tool). Adds `invalidateblock`/`reconsiderblock`, reliable local-tx broadcast + durable rebroadcast, opt-in bearer auth, API-surface scaling, a push-based Streaming Consumption API, drop-in `bitcoin.conf` compatibility, and canary-fleet client-compat fixes. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.2.1](docs/release-notes/0.2.1.md) | 2026-05-29 | Packaging only — ship `sat-tui` in tarballs (no code change from 0.2.0). |
| [0.2.0](docs/release-notes/0.2.0.md) | 2026-05-27 | BIP 324 v2 transport, native TLS, client-side PSBT signing, Core CLI/config-compat gap closed, AssumeUTXO fast-start. **Breaking storage cleanup** — see notes. |
| [0.1.0](docs/release-notes/0.1.0.md) | 2026-05-08 | First public release: mainnet-validated node, native Esplora/Electrum/cfilters, Core-compatible RPC/CLI, signed reproducible builds. |

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.5.1...HEAD
