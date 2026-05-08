# Changelog

All notable changes to satd are documented here. Format is loosely based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); satd follows
[semantic versioning](https://semver.org/spec/v2.0.0.html) for its Tier 1
public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per `STABILITY_POLICY.md`.

## [Unreleased]

## [0.1.0] — 2026-05-08

First public release. Pre-1.0 in semver terms; the Tier 1 surfaces listed
below are governed by `STABILITY_POLICY.md` from this tag forward.

### Consensus and chain

- Bitcoin Core-compatible JSON-RPC across chain, mempool, mining, indexes,
  PSBT, and ops surfaces.
- `bitcoinconsensus` FFI as primary script verifier with a parity-validated
  native Rust verifier as a shadow on every block sync.
- Full mainnet sync from genesis through tip with no consensus divergence.
- Pruning, AssumeUTXO, txindex, reindex, and reindex-chainstate.
- Full P2P including BIP 152 compact blocks, BIP 155 addrv2, ban scoring,
  Tor v3 (`ADD_ONION` / `DEL_ONION`).
- Mempool with full RBF / opt-in BIP 125, CPFP ancestor tracking, and
  configurable policy (`-dustrelayfee`, `-datacarrier`, `-limitancestorcount`,
  `-mempoolexpiry`, `-permitbaremultisig`).

### Native protocol surfaces

- **Esplora REST** (`esplora-handlers`) — wire-shape parity with
  blockstream.info / mempool.space for the implemented endpoint set. On by
  default on loopback. See `docs/api/esplora.md`.
- **Electrum protocol server** (`electrum-proto`) — TCP + optional TLS,
  protocol version 1.4.5. Vendored protocol code from `romanz/electrs` (MIT,
  attribution preserved) layered over the address-history index.
- **Address-history index** (`node-index`) — single RocksDB instance shared
  with chainstate, atomic with `connect_block` / `disconnect_block`. Powers
  Esplora and Electrum.
- **BIP 157/158 compact block filters** (`node-filter-index`) — index plus
  P2P service (`getcfilters` / `getcfheaders` / `getcfcheckpt`) for
  embedded-Neutrino mobile wallets.

### Operator ergonomics

- `/healthz`, `/readyz`, `/metrics` (Prometheus) on `--metricsport`.
- Mempool subscription stream via `subscribemempool` JSON-RPC WS.
- Persistent reorg log at `$datadir/reorg.log` plus optional webhook.
- Structured JSON logging via `tracing-subscriber`.
- `sat-tui` startup progress panel with per-phase ETA and rate.
- MCP server for AI-assisted operations.

### Packaging

- Multi-arch Docker images (`linux/amd64`, `linux/arm64`) on GHCR.
- Signed release tarballs for `x86_64-unknown-linux-gnu` and
  `aarch64-unknown-linux-gnu`.
- Three-surface release signing: minisign for tarballs, cosign keyless for
  containers, SSH signatures on git tags. No GPG.
- Nix flake reproducible build with two-runner byte-identical CI verification.
- CycloneDX 1.5 SBOMs per binary plus `cargo-deny` supply-chain gate at PR
  time and tag time.
- `Type=notify` systemd unit with reindex-resilient `EXTEND_TIMEOUT_USEC`
  heartbeat, OpenRC and runit equivalents.
- `docs/PACKAGING.md` as the authoritative downstream-packager reference.

### Documentation

- `CORE_DIFFERENCES.md` — catalog of intentional deviations from Bitcoin Core.
- `OPERATOR_ERGONOMICS.md` — full flag matrix and tuning guide.
- `STABILITY_POLICY.md` — tiered stability contract with the deprecation
  policy and canary-CI commitments.
- `SECURITY.md` — disclosure address, signing key matrix, threat-model notes.
- `ECOSYSTEM.md` — packaging and protocol-surface strategy.

### Known deferred items

Tracked in `ECOSYSTEM.md` and `docs/PACKAGING.md` for the v0.1.x line:

- macOS Apple Silicon tarballs (re-enable after the public flip; hosted Apple
  Silicon runners bill at 20× the linux rate).
- musl-linux tarballs (`rocksdb-sys` + musl wants a dedicated cross
  toolchain).
- `cargo-auditable` to embed the dependency manifest in the binary.
- `WatchdogSec=` runtime liveness in the systemd unit (needs per-subsystem
  health criteria).
- `satd@.service` template unit for per-network instances; the drop-in
  pattern is documented in `docs/PACKAGING.md` as the workaround.
- Signed AssumeUTXO snapshot distribution and `--fast-start` UX.

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/epochbtc/satd/releases/tag/v0.1.0
