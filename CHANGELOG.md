# Changelog

A terse index of satd releases. **Full, explanatory release notes live in
[`docs/release-notes/`](docs/release-notes/)** — one file per release; this
file points there for detail and keeps only a short list of unreleased changes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
satd follows [semantic versioning](https://semver.org/spec/v2.0.0.html) for its
Tier 1 public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per [`STABILITY_POLICY.md`](STABILITY_POLICY.md).

## [Unreleased]

- Silent payments (BIP 352): new workspace-internal `node-sp-index` crate — the
  shared BIP 352 kernel (input extraction, public tweak `T = input_hash · A`,
  scan loop) plus the `sp_tweaks` row/key codec, backfill cursor, read trait,
  and config. Validated against the BIP 352 v1.1.0 test vectors. Foundation
  only; not yet wired into the daemon.
- Silent payments (BIP 352): index write path. New `silentpaymentindex=1`
  runtime flag (default off, always compiled) makes `connect_block` stamp one
  self-authenticating tweak row per block at/above taproot activation (present
  even when empty), committed atomically with the chainstate; reorg disconnects
  remove it. `-reindex-chainstate` rebuilds it. New `satd_spindex_rows_total` /
  `satd_spindex_row_removes_total` metrics. Off ⇒ defaults byte-identical to
  0.4.0. Serving surfaces land in a later change.
- Silent payments (BIP 352): deferred backfill for enabling the index on an
  existing datadir. `backfillindex silentpayment` walks every block from taproot
  activation to the tip (undo-based, anchored, resumable across restart) and
  stamps a completeness marker; `pauseindex`/`resumeindex`/`cancelindex
  silentpayment` control it. `getindexinfo` gains a `silentpayments` section
  (synced + backfill progress) and a `satd_spindex_backfill_progress_ratio`
  gauge is exported. Until a backfill completes (or the sync ran from genesis
  with the index on), the index reports not-synced so tweak-serving surfaces
  refuse rather than return holes.
- Silent payments (BIP 352): streaming-API wire schema (`satd-events-proto`) for
  both consumption modes. Tier 1 adds a `tweaks` firehose category (bit 8 —
  explicit-request only, not part of the `categories=0` default) with per-block
  `BlockTweaks`/`TweakEntry` bodies and `tweak_dust_limit`/`tweaks_only`
  subscription knobs; Tier 2 adds a scan-key watch kind
  (`AddSilentPayments`/`RemoveSilentPayments`, `SetWatchSet.silent_payments`) and
  a `SilentPaymentMatched` body. Additive — the schema version does not bump and
  existing subscribers are unaffected. Emit, serving, and matching land in
  later changes; this is the schema pass both SDKs build on.
- Silent payments (BIP 352): Tier 1 serving. The node now emits a `BlockTweaks`
  event per connected block on the gRPC `Subscribe` firehose (only while a
  `tweaks` subscriber is attached) and replays it by index on `from_cursor`
  resume — a tweaks-only subscription cold-syncs from taproot activation in one
  subscription, exempt from the replay clamp because rows are self-authenticating
  and the exemption is gated on index completeness; a mixed-category subscription
  keeps the clamp. Per-subscription `tweak_dust_limit`/`tweaks_only` filters
  apply on live and replayed events. A `tweaks` subscription against a disabled
  or still-backfilling index is rejected in-band. New read-only JSON-RPC
  `getsilentpaymentblockdata "blockhash" ( verbosity dust_limit )` serves the
  same bytes as a fallback. WS/SSE and the typed SDK helpers land later.
- Silent payments (BIP 352): Tier 2 scan-key watch (confirmed path). A `Watch`
  client can register scan credentials (`AddSilentPayments` /
  `SetWatchSet.silent_payments`; up to 16/connection) and the node matches
  BIP 352 payments server-side, emitting a `SilentPaymentMatched` per matched
  output as blocks connect — including the public tweak `T` and output counter
  `k` so a light client re-derives the output key offline. Matching recomputes
  from the block + undo data (works with the index off) and does zero extra work
  when no target is registered. Scan secrets are held in-memory per connection,
  wrapped in a zeroize-on-drop buffer, and never persisted or logged. Mirrored on
  the WS/SSE surface. The typed SDK helpers land later.
- Silent payments (BIP 352): Tier 2 scan-key watch — mempool (unconfirmed)
  matching. A registered SP watch now also matches payments in accepted-but-
  unconfirmed transactions, emitting `SilentPaymentMatched` with
  `confirmed = false`; the block-connect scan re-emits the same match
  `confirmed = true` when it confirms (mirroring `ScriptMatched` mempool
  semantics). To classify inputs the mempool matcher needs the resolved prevout
  scripts, so while any SP watch is live the mempool retains them on each entry
  (a shared gate — the same counter the watch registry maintains); with no SP
  watch registered nothing extra is retained and the mempool event path is
  byte-identical to before. Best-effort like every mempool watch: a target
  registered after a tx was admitted matches it only once it confirms.

## Releases

| Version | Date | Notes |
|---|---|---|
| [0.4.0](docs/release-notes/0.4.0.md) | 2026-07-06 | Two major additions: an opt-in transaction-filtering/quarantine policy language (`policyfile=`, with a strict-by-default Lightning-enforcement danger gate) and a substantially matured Streaming Consumption API — a published Rust SDK (`satd-events-client`), events gRPC TLS/mTLS, bounded historical rescan, resilient reconnect-and-replay watches (durable-truth loader + atomic reload), descriptor match attribution, and in-band `ScriptMatched` value/raw-tx enrichment. Also fixes a `getrawmempool` verbose O(N²) blowup, ships profilable release binaries, and makes a P2P listener bind failure fatal at startup instead of silently degrading. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.3.2](docs/release-notes/0.3.2.md) | 2026-06-24 | Consensus fix on the 0.3.x line — median-time-past now walks the candidate block's own ancestors instead of the active-chain height index, fixing a fork-handling bug that could permanently stall a node behind the tip (canonical successor blocks rejected `time-too-old`). Surfaced on testnet4's min-difficulty timestamp sawtooth. No breaking changes; defaults stay Bitcoin Core-compatible. |
| [0.3.1](docs/release-notes/0.3.1.md) | 2026-06-15 | Maintenance release on the 0.3.x line — all bug fixes and tooling, no breaking changes. Fee estimation reworked and unified across every surface (monotone tiers; **corrected a 4× over-report on Esplora/Electrum fee rates**, a regression since 0.3.0); `getrawmempool` verbose no longer O(N²); profilable release binaries (frame pointers + a signed per-target debuginfo sidecar); and the MCP `get_metrics_snapshot` tool now reports real address-index state. Defaults stay Bitcoin Core-compatible. |
| [0.3.0](docs/release-notes/0.3.0.md) | 2026-06-10 | Consensus hardening — per-network softfork-activation heights (critical, non-mainnet), six block-level rules brought to Core parity, a live Core block-acceptance differential + fuzzer — and **critical storage-durability fixes** (silent UTXO/index loss after IBD/reindex, plus an offline `satd-chainstate-repair` tool). Adds `invalidateblock`/`reconsiderblock`, reliable local-tx broadcast + durable rebroadcast, opt-in bearer auth, API-surface scaling, a push-based Streaming Consumption API, drop-in `bitcoin.conf` compatibility, and canary-fleet client-compat fixes. New surfaces are opt-in — defaults stay Bitcoin Core-compatible. |
| [0.2.1](docs/release-notes/0.2.1.md) | 2026-05-29 | Packaging only — ship `sat-tui` in tarballs (no code change from 0.2.0). |
| [0.2.0](docs/release-notes/0.2.0.md) | 2026-05-27 | BIP 324 v2 transport, native TLS, client-side PSBT signing, Core CLI/config-compat gap closed, AssumeUTXO fast-start. **Breaking storage cleanup** — see notes. |
| [0.1.0](docs/release-notes/0.1.0.md) | 2026-05-08 | First public release: mainnet-validated node, native Esplora/Electrum/cfilters, Core-compatible RPC/CLI, signed reproducible builds. |

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.4.0...HEAD
