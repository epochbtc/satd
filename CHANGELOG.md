# Changelog

A terse index of satd releases. **Full, explanatory release notes live in
[`docs/release-notes/`](docs/release-notes/)** — one file per release; this
file points there for detail and keeps only a short list of unreleased changes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
satd follows [semantic versioning](https://semver.org/spec/v2.0.0.html) for its
Tier 1 public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per [`STABILITY_POLICY.md`](STABILITY_POLICY.md).

## [Unreleased]

- **Transaction-filtering policy (opt-in).** A total, statically-cost-bounded
  policy language (`policyfile=`) that *quarantines* transaction shapes —
  withholding them from relay and/or block templates — without ever changing
  what the node accepts as valid (consensus is untouched). Quarantine-only: no
  `reject`. Standard mempool surfaces stay acting-class-only and byte-identical
  whether or not anything is quarantined; the quarantine view is exposed solely
  through dedicated surfaces — `getpolicyinfo`, `getquarantineinfo` (with
  foregone-fees + confirmed-anyway), `listquarantine`, `getquarantineentry`,
  `policytest`, matching MCP tools, and `satd_policy_*` Prometheus metrics. Live
  `SIGHUP` reload (last-good-wins, lossless re-placement). A **strict-by-default
  Lightning-enforcement danger gate** refuses a policy whose rule would withhold
  relay for L2 enforcement traffic (BOLT-3 commitment/justice/HTLC, taproot
  spends); opt out with `allowdangerousfilters=1`. Offline `sat-cli policylint`
  (exit 3 on a dangerous rule). New Operator Manual chapter plus a contributor
  [design doc](satd-policy/DESIGN.md). See the
  [release notes](docs/release-notes/0.4.0-pre.md).
- **`getrawmempool` verbose no longer O(N²).** Verbose mempool views
  (`getrawmempool true`, `getmempooldescendants`, `getmempoolentry`) computed
  each transaction's ancestor/descendant rollups by scanning the whole mempool
  per traversal hop and re-hashing each tx's txid every hop — so a client
  polling verbose mempool on a timer (e.g. the `sat-tui` mempool pane) could
  peg a CPU core, worsening as the mempool grew. Descendant traversal now
  follows the existing spend index (O(descendants) per hop, not a full-mempool
  scan) and the Txid/OutPoint maps use a fast hasher, so per-call and
  chain-shaped lookups are linear. (The aggregate `getrawmempool true` dump
  over a very wide cluster is still superlinear until per-transaction
  descendant limits are enforced — tracked as follow-up.) Output is identical.
  See the [release notes](docs/release-notes/0.4.0-pre.md).
- **Profilable release binaries.** Release builds now ship with frame pointers
  + line-table debug info; the binary stays stripped (same download size) and
  the debug info is published as a separate per-target `*-debuginfo.tar.zst`
  sidecar, so production nodes can be profiled with `perf -g` and symbolized
  against the exact running binary. See the
  [release notes](docs/release-notes/0.4.0-pre.md).
- **Fee estimation reworked.** Fixed inverted smart-fee tiers (now monotone:
  `High ≥ Medium ≥ Low ≥ economy`); unified `estimatefees`,
  `estimatesmartfee`, the TUI, the MCP `estimate_fee` tool, Esplora
  `/fee-estimates`, and Electrum `blockchain.estimatefee` on one shared
  estimator so they agree; made the per-block floor robust to a single cheap
  tail transaction; and cache the mempool simulation behind the public fee
  endpoints. **Corrected a 4× fee over-report** (regression since 0.3.0) on
  Esplora `/fee-estimates` + `/mempool` fee rates and Electrum
  `estimatefee`/`relayfee`/`get_fee_histogram` — see the
  [release notes](docs/release-notes/0.4.0-pre.md) for the upgrade note.

## Releases

| Version | Date | Notes |
|---|---|---|
| [0.3.0](docs/release-notes/0.3.0.md) | 2026-06-10 | Consensus hardening — per-network softfork-activation heights (critical, non-mainnet), six block-level rules brought to Core parity, a live Core block-acceptance differential + fuzzer — and **critical storage-durability fixes** (silent UTXO/index loss after IBD/reindex, plus an offline `satd-chainstate-repair` tool). Adds `invalidateblock`/`reconsiderblock`, reliable local-tx broadcast + durable rebroadcast, opt-in bearer auth, API-surface scaling, a push-based Streaming Consumption API, drop-in `bitcoin.conf` compatibility, and canary-fleet client-compat fixes. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.2.1](docs/release-notes/0.2.1.md) | 2026-05-29 | Packaging only — ship `sat-tui` in tarballs (no code change from 0.2.0). |
| [0.2.0](docs/release-notes/0.2.0.md) | 2026-05-27 | BIP 324 v2 transport, native TLS, client-side PSBT signing, Core CLI/config-compat gap closed, AssumeUTXO fast-start. **Breaking storage cleanup** — see notes. |
| [0.1.0](docs/release-notes/0.1.0.md) | 2026-05-08 | First public release: mainnet-validated node, native Esplora/Electrum/cfilters, Core-compatible RPC/CLI, signed reproducible builds. |

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.3.0...HEAD
