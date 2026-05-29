# Changelog

All notable changes to satd are documented here. Format is loosely based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); satd follows
[semantic versioning](https://semver.org/spec/v2.0.0.html) for its Tier 1
public surfaces (RPC method shape, CLI flags, `bitcoin.conf` syntax, file
layout) per `STABILITY_POLICY.md`.

## [Unreleased]

## [0.2.1] — 2026-05-29

### Packaging

- **`sat-tui` is now included in the release tarballs.** The terminal
  dashboard (`sat-tui`) ships in `bin/` of every `satd-<version>-<target>.tar.zst`
  alongside `satd` and `sat-cli`, with a CycloneDX SBOM
  (`sat-tui-v<version>.cdx.json`) and a minisign signature like the other
  artifacts. It was a workspace member but was never built or staged into the
  tarball through 0.2.0, so operators who installed from a release archive had
  no TUI. No code changed from 0.2.0 — this release exists solely to package
  the binary.

## [0.2.0] — 2026-05-27

### Network

- **BIP 324 v2 encrypted transport** (`-v2transport`, on by default, matching Bitcoin Core). satd offers/accepts the ElligatorSwift + ChaCha20-Poly1305 v2 handshake on inbound and outbound connections, transparently falling back to plaintext v1 for legacy peers. The satd-specific **`-v2only`** flag (off by default) refuses non-v2 peers as an anti-surveillance lever. `getpeerinfo` reports `transport_protocol_type`; a `satd_peer_connections_v2` Prometheus gauge counts v2 peers. Built on the rust-bitcoin `bip324` crate.

### Wallet / signing

- **`sat-cli signpsbtwithkey` — client-side PSBT signing.** Signs a base64 PSBT locally using a private key (WIF or xpriv) read from **stdin**; the key is never sent over JSON-RPC, keeping the daemon keyless. On an interactive terminal the key is read with a no-echo prompt; when piped, newline-separated keys are accepted. Key material is best-effort erased after use. Signs p2pkh, p2wpkh, p2sh-wrapped-p2wpkh, and p2tr key-path inputs (populating `partial_sigs` / `tap_key_sig`); the signed PSBT is emitted on stdout to feed into the existing `finalizepsbt` RPC. Exits `0` when fully signed, `2` when partial (PSBT still emitted, unsigned inputs reported on stderr). Intended workflow: `createpsbt` → `utxoupdatepsbt` → `signpsbtwithkey` → `finalizepsbt` → `sendrawtransaction`. For an xpriv, standard BIP 44/49/84/86 child keys are derived client-side (account 0, receive + change, over a `--gap`-bounded scan, default 100) and matched against the input scripts, so an xpriv signs PSBTs that carry no derivation metadata — including satd's own `createpsbt` output; PSBTs that *do* carry `bip32_derivation` also sign on their declared paths.

- **`sat-cli signpsbtwithsigner` — external-signer dispatch (HWI / Bitcoin-Core compatible).** Signs a base64 PSBT by spawning an external signer command (`--signer "<cmd>"`, e.g. the `hwi` tool or any conforming script) locally; the key lives in that process and is never sent over RPC, keeping the daemon keyless. Speaks Core's `doc/external-signer.md` arg-based contract: runs `<signer> enumerate` to discover the device fingerprint (auto-selected when exactly one is present, or chosen with `--fingerprint`), then `<signer> --fingerprint=<fp> --chain <net> signtx <psbt>` (chain derived from `--regtest`/`--testnet`), parsing `{"psbt"}` / `{"error"}`. The signed PSBT is emitted on stdout for `finalizepsbt`; same `0`/`2`/`1` exit scheme as `signpsbtwithkey`. Note: a hardware device only signs inputs carrying its own `bip32_derivation`, so it acts on properly-formed PSBTs (from a wallet that knows the device xpub), not satd's bare `createpsbt` output. Scope: `enumerate` + `signtx` (`displayaddress`/`getdescriptors` not yet wired).

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
- **JSON-RPC server CLI flags.** `-rpcbind=<addr>[:port]` (repeatable),
  `-rpcallowip=<subnet>` allow-list, `-rpcauth=<user>:<salt>$<hash>`
  HMAC credentials, and the `-rpccookiefile` / `-rpccookieperms` cookie
  controls, all matching Bitcoin Core.
- **`-chain=<name>` unified network selector** (Core's single-flag form),
  mutually exclusive with `-regtest` / `-testnet` / `-testnet4` / `-signet`;
  a `[signet]` config section; `-blocksdir` for a separate blocks directory;
  `-signetseednode`; and `-timeout=<ms>` peer-connection timeout. `sat-cli`
  gains `-rpcwait` to block until the daemon's RPC is reachable.
- **`-persistmempool`** — the mempool is saved to `mempool.dat` on clean
  shutdown and reloaded (each tx re-validated against the chainstate) at
  startup. The flag, filename, and behavior match Bitcoin Core, but the
  on-disk format is satd-native and **not** byte-compatible with Core's
  `mempool.dat` (like `peers.dat` — see `CORE_DIFFERENCES.md`).
- **`-listenonion`** Tor hidden-service wiring is honored end-to-end.

### RPC compatibility

- **`getchaintxstats` now reports Core-faithful cumulative statistics.**
  `txcount` is the cumulative chain-wide transaction total through the
  window's final block (previously it duplicated the window count), and
  the optional second `blockhash` argument — which selects the block that
  *ends* the window (default = chain tip) — is now honored (previously
  silently ignored). The cumulative count is maintained in a new
  additive `chain_tx` column family, seeded at the AssumeUTXO anchor and
  backfilled at startup on upgraded datadirs with no reindex. Field
  optionality matches Core exactly: `txcount` is omitted when the final
  block's count is unknown (e.g. a pre-snapshot block on an AssumeUTXO
  node still validating in the background), `window_tx_count` is the
  difference of the two endpoint counts and is omitted unless both are
  known, and `txrate` is omitted unless `window_tx_count` exists and the
  interval is positive. The window interval is measured between the
  endpoints' median-time-past values (BIP 113), as in Core. Active-chain
  membership for an explicit `blockhash` is resolved authoritatively
  (rejecting side-chain blocks with "Block is not in main chain").

### AssumeUTXO

- **`loadtxoutset` / `getchainstates` RPCs** plus two-chainstate
  (background) sync. satd loads Bitcoin Core's published UTXO snapshot
  files directly; the anchor table is copied verbatim from Core's
  `m_assumeutxo_data`. Refuses to load under pruning. Note: While AssumeUTXO is fully compatible with commonly-distributed snapshots, satd does not create or distribute these snapshots. Users must find their own source for trusted snapshots.
- **`dumptxoutset` RPC** — exports a byte-compatible UTXO snapshot at the
  current tip, loadable into either Core or satd via `loadtxoutset`. The
  returned `txoutset_hash` is Core's `hash_serialized_3` UTXO-set hash
  (not the file digest), so it can be checked against a height's
  `hash_serialized` in Core's `m_assumeutxo_data`. Finalize is atomic and
  refuses to clobber an existing file.
- **UTXO-set hash parity with Core.** Provably-unspendable outputs are
  now excluded from the UTXO set, so `gettxoutsetinfo` and `dumptxoutset`
  produce the same `hash_serialized_3` as Bitcoin Core at a given height —
  required for AssumeUTXO snapshots to cross-validate against Core anchors.
- **`--fast-start=<url>` one-flag startup UX.** Downloads a UTXO snapshot
  at startup (from an `https://` URL or a local file path), waits for
  header sync to reach the snapshot's anchor, and loads it automatically
  — no manual `loadtxoutset`. Remote sources **must** be `https://`
  (plain `http://` is refused at config time; TLS certificates are
  validated), and the snapshot is verified against satd's hardcoded
  anchor hash at load, so a tampered or wrong file is rejected regardless
  of its source. The download is resumable and its progress renders in
  the pre-RPC startup TUI gauge (like a reindex); the genesis→snapshot
  background re-validation shows in `getchainstates`. Incompatible with
  `-prune`. On a node that already has chainstate the flag is a no-op, so
  it is safe to leave in a systemd unit. satd never fetches snapshots
  over P2P and hosts none — the operator names a trusted source. The
  download is length-checked against the server's `Content-Length`, and an
  optional `--fast-start-sha256=<hex>` fails fast if the file doesn't match
  an operator-supplied digest (opt-in; the anchor-hash check at load is the
  authoritative gate regardless).

### Performance

- **Pipelined `-reindex-chainstate`.** Rebuilding the UTXO set from
  on-disk blocks now uses the same parallel block-processing pipeline as
  initial block download instead of a serial pass, substantially reducing
  reindex-chainstate wall-clock time on multi-core hosts.

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
`WatchdogSec=`, the `satd@.service` template, and the AssumeUTXO
`--fast-start` UX all shipped post-0.1.0 — see the `[Unreleased]`
section above.)

- `cargo-auditable` to embed the dependency manifest in the binary.

[Unreleased]: https://github.com/epochbtc/satd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/epochbtc/satd/releases/tag/v0.1.0
