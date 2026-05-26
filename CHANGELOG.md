# Changelog

All notable changes to satd are documented here. Format is loosely based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); satd follows
[semantic versioning](https://semver.org/spec/v2.0.0.html) for its Tier 1
public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per `STABILITY_POLICY.md`.

## [Unreleased]

### Native protocol surfaces

- **Native TLS Support:** Direct TLS termination for JSON-RPC, Electrum, and Esplora servers via `--rpctlsbind`, `--electrumtlsbind`, and `--esploratlsbind`. Eliminates the need for a TLS-terminating sidecar.

### Configuration and CLI compatibility

- **Bitcoin Core CLI/config-compatibility gap closed.** Every recognized
  `bitcoin.conf` key is now either honored or recognize-rejected with a
  clear message — no silent accept-and-ignore. Newly implemented:
  `-includeconf` chained config files (main file read first, included
  files appended; single-valued keys resolve first-wins, matching Core's
  `reverse_precedence`); comprehensive `-no<option>` boolean negation
  across all boolean flags; `-signetchallenge` custom signet with
  opt-in BIP 325 block-solution validation; `-testnet4` chain params
  including BIP 94 (timewarp guard + first-block-seeded retarget);
  `-blocksonly`; `-externalip`; `-whitelist` / `-whitebind` peer
  permissions (NoBan + Relay/ForceRelay acted on); `-maxuploadtarget`
  (meters block-serving bytes); persistent address manager
  (`peers.dat`, satd-native format — see `CORE_DIFFERENCES.md`); `-asmap`
  ASN-based bucketing (Core `util/asmap.cpp` port); `-forcednsseed` and
  `-fixedseeds`. `-includeconf` on the command line is now a hard error,
  matching Core.

### AssumeUTXO

- **`loadtxoutset` / `getchainstates` RPCs** plus two-chainstate
  (background) sync. satd loads Bitcoin Core's published UTXO snapshot
  files directly; the anchor table is copied verbatim from Core's
  `m_assumeutxo_data`. Refuses to load under pruning. Signed snapshot
  distribution and a `--fast-start` UX remain deferred.

### Packaging

- **musl-linux static tarballs** (`x86_64`/`aarch64-unknown-linux-musl`,
  built via `cargo-zigbuild`) and **macOS Apple Silicon tarballs**
  (`aarch64-apple-darwin`) now ship in the release matrix.
- **systemd `WatchdogSec=` liveness** wired into both `satd.service` and
  the new **`satd@.service`** template unit for per-network instances.

### Storage

- **Breaking — storage format cleanup.** Undo entries are now v1-only
  on disk (8-byte magic + 1-byte version + compact-coin stream);
  address-history rows live exclusively in the `addr_funding_v2` /
  `addr_spending_v2` column families (16-byte scripthash-prefix keys).
  The dual-read fallbacks, the legacy v1 address CFs, and the offline
  migrators (`--migrate-undo`, `--migrate-addr-index`) introduced
  post-0.1.0 are all removed. Any chainstate written by an earlier
  post-0.1.0 build that did not run both migrators must be rebuilt
  with `--reindex-chainstate`. The `_v2` naming is preserved as a
  fossilized marker — these are now the only address-history CFs.

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

Tracked in `ECOSYSTEM.md` and `docs/PACKAGING.md` for the v0.1.x line.
(macOS Apple Silicon tarballs, musl-linux tarballs, systemd
`WatchdogSec=`, and the `satd@.service` template all shipped post-0.1.0
— see the `[Unreleased]` section above.)

- `cargo-auditable` to embed the dependency manifest in the binary.
- Signed AssumeUTXO snapshot distribution and `--fast-start` UX.

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/epochbtc/satd/releases/tag/v0.1.0
