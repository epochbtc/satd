# Changelog

A terse index of satd releases. **Full, explanatory release notes live in
[`docs/release-notes/`](docs/release-notes/)** — one file per release; this
file points there for detail and keeps only a short list of unreleased changes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
satd follows [semantic versioning](https://semver.org/spec/v2.0.0.html) for its
Tier 1 public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per [`STABILITY_POLICY.md`](STABILITY_POLICY.md).

## [Unreleased]

- **Events gRPC TLS / mTLS.** The events gRPC streaming listener can now
  terminate TLS (and mutual TLS) in-process, sharing the cert / mTLS-allowlist
  plumbing of the RPC / Electrum / Esplora surfaces. Setting `eventsgrpctlscert`
  + `eventsgrpctlskey` upgrades the existing `eventsgrpcbind` to TLS;
  `eventsgrpcmtls` (+ `eventsgrpcmtlsclientca`, optional `eventsgrpcmtlsclientallow`)
  requires client certificates. A remote bind is now satisfied by mTLS as well as
  bearer auth. New flags: `eventsgrpctlscert`, `eventsgrpctlskey`,
  `eventsgrpcmtls`, `eventsgrpcmtlsclientca`, `eventsgrpcmtlsclientallow`,
  `eventsgrpctlshandshaketimeout`.
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
- **Streaming API: mid-stream `SetCursor` re-anchor on gRPC `Watch`.** A
  `SetCursor` on a live bidi `Watch` now replays confirmed history
  `(cursor.height, tip]` in order ahead of the live tail (drain-replay-resume),
  preserving the watch-set + quota leases — previously a documented no-op. Lets a
  long-lived `Watch` re-anchor its replay position without rebuilding a large
  watch-set. See the [release notes](docs/release-notes/0.4.0-pre.md).
- **Streaming API: prefix mempool spend-side prevout carriage (`full` tier).**
  Under `streamprevoutmeta = full`, a mempool `PrefixMatched` now carries the real
  spent-prevout `scriptPubKey` (and, from `amount`, its value) so a chainstate-less
  privacy client can confirm a bucket spend locally without resolving the outpoint.
  `SpentPrevout` gains `amount`/`has_amount`. See the
  [release notes](docs/release-notes/0.4.0-pre.md).
- **Streaming API: per-script `min_value` filter on `AddScripts`.** A watch can
  attach a per-scripthash satoshi floor (`min_values`, parallel to
  `scripthashes`); matches below it are suppressed server-side. Symmetric across
  funding (output value) and spending (spent-prevout value). Also corrects the
  stale `ScriptMatched.is_output` proto comment (input-side matching has shipped
  since the prefix/exact spend-side work). See the
  [release notes](docs/release-notes/0.4.0-pre.md).
- **Streaming API: `streamprevoutmeta` mempool prevout retention (default
  `amount`).** New mempool-policy key tuning how much spent-prevout metadata the
  streaming watch matcher retains per mempool input (`hash` | `amount` | `full`)
  — the foundation for mempool-input `min_value` filtering and chainstate-less
  prefix-spend confirmation. SIGHUP-reloadable.
  See the [release notes](docs/release-notes/0.4.0-pre.md).
- **Rust SDK for the Streaming API (`satd-events-client`).** A new published
  async client crate that absorbs the tonic boilerplate every consumer
  otherwise hand-writes: typed `Event` enum, per-call auth metadata, cursor
  capture/persistence, reconnect-with-backoff, `Lagged` auto-resume,
  replay-truncation detection, and the privacy-preserving prefix-watch local
  re-filter (`PrefixWatcher`, behind the default-on `bitcoin` feature).
  Native **TLS / mTLS** (default-on `tls` feature, `ring` provider):
  `tls()` / `tls_ca_pem()` / `tls_client_identity()` / `tls_domain()` on the
  builder encrypt the transport so the bearer token is never sent in cleartext.
  Wire types are extracted into a shared `satd-events-proto` crate so the client
  pulls no server/`node` dependencies. New Operator Manual chapter + runnable
  examples. See the [release notes](docs/release-notes/0.4.0-pre.md).
- **P2P listener bind failure is now fatal at startup.** With `-listen=1` (the
  default) or `-whitebind`, a failure to bind the P2P port — almost always a
  second satd instance on the same datadir/port, or a port already in use — was
  logged on a detached task while the daemon otherwise reported a clean start
  and ran with **no inbound P2P listener** (silently unreachable). The bind now
  happens synchronously before the accept loop starts and a failure aborts
  startup with a clear message, matching the existing RPC/Esplora listeners.
  See the [release notes](docs/release-notes/0.4.0-pre.md).

## Releases

| Version | Date | Notes |
|---|---|---|
| [0.3.1](docs/release-notes/0.3.1.md) | 2026-06-15 | Maintenance release on the 0.3.x line — all bug fixes and tooling, no breaking changes. Fee estimation reworked and unified across every surface (monotone tiers; **corrected a 4× over-report on Esplora/Electrum fee rates**, a regression since 0.3.0); `getrawmempool` verbose no longer O(N²); profilable release binaries (frame pointers + a signed per-target debuginfo sidecar); and the MCP `get_metrics_snapshot` tool now reports real address-index state. Defaults stay Bitcoin Core-compatible. |
| [0.3.0](docs/release-notes/0.3.0.md) | 2026-06-10 | Consensus hardening — per-network softfork-activation heights (critical, non-mainnet), six block-level rules brought to Core parity, a live Core block-acceptance differential + fuzzer — and **critical storage-durability fixes** (silent UTXO/index loss after IBD/reindex, plus an offline `satd-chainstate-repair` tool). Adds `invalidateblock`/`reconsiderblock`, reliable local-tx broadcast + durable rebroadcast, opt-in bearer auth, API-surface scaling, a push-based Streaming Consumption API, drop-in `bitcoin.conf` compatibility, and canary-fleet client-compat fixes. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.2.1](docs/release-notes/0.2.1.md) | 2026-05-29 | Packaging only — ship `sat-tui` in tarballs (no code change from 0.2.0). |
| [0.2.0](docs/release-notes/0.2.0.md) | 2026-05-27 | BIP 324 v2 transport, native TLS, client-side PSBT signing, Core CLI/config-compat gap closed, AssumeUTXO fast-start. **Breaking storage cleanup** — see notes. |
| [0.1.0](docs/release-notes/0.1.0.md) | 2026-05-08 | First public release: mainnet-validated node, native Esplora/Electrum/cfilters, Core-compatible RPC/CLI, signed reproducible builds. |

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.3.1...HEAD
