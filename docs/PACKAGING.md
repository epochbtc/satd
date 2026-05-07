# Packaging satd

This document is the authoritative reference for downstream packagers
(Umbrel, Start9, RaspiBlitz, MyNode, BTCPay, Debian/Fedora/Alpine,
Homebrew, Nix). It describes file layout, signals, ports, config
surface, runtime model, and the contract satd offers a packager.

The user-facing operator guide is [`OPERATOR_ERGONOMICS.md`](../OPERATOR_ERGONOMICS.md).
The deviation catalog vs. Bitcoin Core is in
[`CORE_DIFFERENCES.md`](../CORE_DIFFERENCES.md). The strategic
direction for packaging is in [`ECOSYSTEM.md`](../ECOSYSTEM.md) §2.

## Document status

This is **PACKAGING.md v1**. It covers what shipped today: the
container, systemd unit, on-disk layout, operational surface, release
pipeline, signing across all three surfaces, and reproducible build
via Nix. Sections marked **(future)** describe contracts that future
PRs will fulfil — SBOM generation, `Type=notify` systemd, OpenRC /
runit equivalents. They are listed here so packagers can see the
full intended shape and plan against it.

Updated: 2026-05-07.

## Binaries

satd ships two binaries:

| Binary | Purpose |
|---|---|
| `satd` | Daemon. Long-running process; opens RocksDB, runs P2P + RPC + optional protocol surfaces. |
| `sat-cli` | JSON-RPC CLI client. Bitcoin Core-compatible flag shape (`-rpcuser`, `-rpcpassword`, `-rpccookiefile`, network selectors). |

A third binary, `sat-tui`, is a curses-style operator dashboard. It is
optional; packagers who don't want it can skip it.

There are deliberately **no separate `sat-electrum` / `sat-esplora`
companion binaries**. Both protocols are subsystems of `satd` itself,
gated by runtime flags (`--electrum=1`, `--esplora=1`). One process,
one RocksDB, one log stream, one PID. This is a load-bearing design
choice — see `ECOSYSTEM.md` §4a.

## File layout

```
$DATADIR/                         # default: $HOME/.bitcoin (Core-compat)
└── <network>/                    # one of: <empty for mainnet>, testnet3, signet, regtest
    ├── blocks/
    │   ├── blk00000.dat          # flat-file block storage (state)
    │   ├── blk00001.dat
    │   └── ...
    ├── chainstate/               # RocksDB instance (state)
    │   ├── *.sst                 # SST files — the bulk of disk usage
    │   ├── CURRENT, MANIFEST-*   # RocksDB metadata
    │   └── ...
    ├── .cookie                   # RPC cookie auth (auto-generated, mode 0600)
    ├── mempool_history.log       # rolling mempool snapshot (state, derived-OK)
    ├── reorg.log                 # persistent reorg ledger (state, append-only)
    ├── debug.log                 # rotating diagnostic log (derived)
    ├── bitcoin.conf              # optional config file (Core-compat name)
    └── satd.conf                 # alternative config name (also accepted)
```

**State** — must be backed up to preserve consensus history:
`blocks/`, `chainstate/`, `reorg.log`. These are load-bearing.

**Derived / safe to nuke** — regenerate from `blocks/` via
`--reindex` or `--reindex-chainstate`: everything inside
`chainstate/` (the RocksDB instance), `mempool_history.log`,
`debug.log`, and the various `*.complete` index marker files inside
`chainstate/`.

**Single-instance RocksDB.** Unlike Bitcoin Core, satd does not
maintain separate LevelDB databases for the txindex, address index,
or BIP 158 filter index. They are column families inside the one
RocksDB instance, written atomically with each `connect_block`
batch. This means:

- Backup is simpler (one directory).
- Index updates can never be visible without the corresponding tip
  update — the whole `WriteBatch` either commits or it doesn't.
- An `--reindex-chainstate` rebuilds everything in chainstate
  (UTXO + indexes) but preserves the flat files.

## Process model

- One process. PID file is whatever the supervisor records; satd
  does not write its own PID file by default.
- `tokio` async runtime; many tasks but a fixed-size worker pool.
- `rayon` for script verification (CPU-bound parallelism).
- File descriptors: RocksDB keeps many SST files mmapped; budget
  `LimitNOFILE=65536` minimum. The systemd unit and the Docker
  image both pre-set this.

## Signals

| Signal | Behaviour |
|---|---|
| `SIGTERM` | Clean shutdown. Flush RocksDB, fsync undo files, drain mempool snapshot, close listeners. May take **up to 10 minutes** under heavy IBD load — most shutdowns are sub-second. |
| `SIGINT` | Identical to SIGTERM. |
| `SIGHUP` | Currently ignored (no log-reopen on signal yet — see `--logrotate=size` for size-based rotation). |
| `SIGKILL` | RocksDB recovers via WAL replay on next start. Avoid; one botched shutdown = one corrupted chainstate is the failure mode to design against. |

Container supervisors should set a **stop grace period of at least 10
minutes** (`--stop-timeout=600` for `docker run`, `terminationGracePeriodSeconds: 600`
for Kubernetes). The systemd unit ships `TimeoutStopSec=10min` for the
same reason.

## Network ports (defaults)

| Service | Mainnet | Testnet | Signet | Regtest |
|---|---|---|---|---|
| P2P | 8333 | 18333 | 38333 | 18444 |
| JSON-RPC | 8332 | 18332 | 38332 | 18443 |
| Esplora REST (`--esplora`) | configurable, e.g. 3000 | — | — | — |
| Electrum (`--electrum`) | configurable, e.g. 50001 | — | — | — |
| Metrics + health (`--metricsport`) | configurable, e.g. 9332 | — | — | — |

The default RPC bind is loopback. Esplora, Electrum, and the metrics
endpoint are **off by default**; turn them on per-deployment.

## Health and readiness

When `--metricsport=<port>` is configured, satd exposes three
unauthenticated HTTP endpoints on that port (default bind 127.0.0.1):

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | Process is alive and the event loop is responsive. Cheap. |
| `GET /readyz` | RocksDB is open, headers are syncing, peers > 0. Returns 503 during IBD. |
| `GET /metrics` | Prometheus exposition format. |

These are the right surfaces to wire to a Docker `HEALTHCHECK`,
Kubernetes liveness/readiness probes, or a systemd `ExecStartPost=`
poll. Both `Type=notify` (planned, requires `sd_notify` wiring) and
poll-based readiness work.

## Configuration

Two files are accepted, both with Bitcoin Core's `key=value` /
`[network]` syntax:

- `bitcoin.conf` — Core-compat name. Same shape, same precedence.
- `satd.conf` — preferred when running side-by-side with a Core
  install; identical syntax.

Resolution order: `--conf=<path>` if given, else `<datadir>/bitcoin.conf`,
else `<datadir>/satd.conf`. CLI flags always win over file values.

The full flag matrix is in `OPERATOR_ERGONOMICS.md`. The
container ships a sensible mainnet-loopback default; everything is
overridable via `-e SATD_*` … see "Container" below.

## Container

The repository ships a multi-stage `Dockerfile` at the repo root.
Build:

```sh
docker build -t satd:dev .
```

Properties of the image:

- Base: `debian:bookworm-slim`.
- Runtime user: `satd` (UID/GID **2121**, deliberately non-1000 to
  avoid bind-mount UID clash with the host operator user).
- PID 1: `tini`, so SIGTERM forwards to satd cleanly.
- Datadir: `/var/lib/satd`. Marked as a `VOLUME`.
- Exposed ports: `8333` (P2P), `8332` (RPC). Other ports are
  off by default; map them with `-p` per deployment.

Example mainnet run with persistent state, RPC on loopback,
metrics on loopback:

```sh
docker volume create satd-data
docker run -d --name satd \
  --restart unless-stopped \
  --stop-timeout 600 \
  -v satd-data:/var/lib/satd \
  -p 8333:8333 \
  -p 127.0.0.1:8332:8332 \
  -p 127.0.0.1:9332:9332 \
  satd:dev \
    --rpcbind=0.0.0.0 --rpcallowip=127.0.0.0/8 \
    --metricsport=9332 --metricsbind=0.0.0.0
```

CLI:

```sh
docker exec satd sat-cli getblockchaininfo
```

**Multi-arch images.** Tag-triggered releases publish `linux/amd64`
and `linux/arm64` to `ghcr.io/epochbtc/satd` via the workflow at
`.github/workflows/release.yml`. Tags follow `docker/metadata-action`
defaults: `<MAJOR>.<MINOR>.<PATCH>`, `<MAJOR>.<MINOR>`, and `latest`
on every release.

```sh
docker pull ghcr.io/epochbtc/satd:0.1.0
docker pull ghcr.io/epochbtc/satd:latest
```

Signing of these images (cosign keyless OIDC, attested to Rekor) ships
in PR-3 of the packaging stack.

## systemd

The repository ships `contrib/systemd/satd.service`. Install:

```sh
sudo install -Dm644 contrib/systemd/satd.service /etc/systemd/system/satd.service
sudo install -Dm755 target/release/satd /usr/local/bin/satd
sudo install -Dm755 target/release/sat-cli /usr/local/bin/sat-cli
sudo useradd --system --home /var/lib/satd --shell /usr/sbin/nologin satd
sudo systemctl daemon-reload
sudo systemctl enable --now satd
```

The unit ships with restrictive hardening (read-only /, private /tmp,
syscall filter, no new privileges). A packager who needs to relax any
of those — for example to write to a non-`/var/lib/satd` datadir —
should override via a drop-in:

```ini
# /etc/systemd/system/satd.service.d/datadir.conf
[Service]
ExecStart=
ExecStart=/usr/local/bin/satd --datadir=/srv/bitcoin
ReadWritePaths=
ReadWritePaths=/srv/bitcoin
```

The unit is currently `Type=simple`; it will move to `Type=notify`
once `sd_notify(READY=1)` lands. See
`contrib/systemd/README.md` for context.

OpenRC and runit equivalents will land in a follow-up PR.

## Resource budget

Mainnet, fresh IBD, no optional indexes:

| Resource | Pi 5 (8 GB) target | Server target |
|---|---|---|
| Disk (chainstate + blocks) | ~700 GB at 2026-05 tip | same |
| RAM peak during IBD | ~3 GB | unbounded by `dbcache` |
| RAM steady-state | ~1.5 GB | ~2 GB |
| CPU during IBD | 4 cores ≈ saturated | scales with cores |
| Network during IBD | 50–200 Mbps | network-bound |

Optional indexes (`--txindex`, `--addressindex`, `--blockfilterindex`)
each add disk and a one-time backfill cost. Turning them on after the
fact runs an online backfill — there is no "stop, reindex from scratch"
ceremony; see `node/src/index/<index>/backfill.rs` for the cursors.

## Pruning

`--prune=<MiB>` works the same shape as Bitcoin Core. Minimum 550 MiB.

Indexes that scan historical blocks (`--txindex`, `--addressindex`,
`--blockfilterindex`) require unpruned blocks. satd refuses to start
with a conflicting combination — same shape as Core.

## Reproducible build via Nix

The repo ships a Nix flake at `flake.nix` that produces deterministic
`satd` and `sat-cli` binaries on `x86_64-linux` and `aarch64-linux`.

Quickstart for a packager who already has Nix with flakes enabled:

```sh
# Build (produces ./result/bin/{satd, sat-cli})
nix build .#satd

# Hash the built binaries
sha256sum result/bin/satd result/bin/sat-cli

# Drop into a dev shell with the full toolchain (clang, libclang,
# cmake, openssl, rustc, cargo, rustfmt, clippy, cargo-watch,
# cargo-nextest)
nix develop
```

The toolchain pin (`rust-toolchain.toml` at the repo root) is the
single source of truth — both rustup and the flake read it.

### What "reproducible" means in v1

- **Two `nix build` invocations** of the same commit on two hosts
  produce byte-identical `result/bin/satd`. CI proves this on every
  PR that touches `flake.nix` / `flake.lock` / `rust-toolchain.toml` /
  `Cargo.lock` via `.github/workflows/nix.yml` (a two-runner pair
  build + a third compare job that asserts SHA256 equality).
- **Local repro** is one command: `contrib/repro/diff-build.sh
  /path/to/clone-A /path/to/clone-B`. Runs `nix build` in each, hashes
  the outputs, and falls back to `diffoscope` when they diverge.
- **Out of scope for v1**: matching the rustup-stable tarball binary
  (the one `.github/workflows/release.yml` ships) byte-for-byte. That
  requires aligning linker / debug-info / build-id behaviour between
  two different build drivers; tractable but a separate PR.

### Determinism hazards addressed

| Hazard | How the flake handles it |
|---|---|
| `rocksdb-sys` bindgen output | `LIBCLANG_PATH` set to the pinned libclang; bindgen output is deterministic for a fixed libclang version. |
| RocksDB vendored C++ build | `PORTABLE=1` + `ROCKSDB_DISABLE_AVX2=1` so the build doesn't tune for the runner's CPU; matches what the release-tarball workflow already produces (rustup-stable defaults to generic x86_64-v1). |
| `cc-rs` C/C++ compiles (secp256k1, bitcoinconsensus) | Compiler version pinned via nixpkgs; `SOURCE_DATE_EPOCH` respected by cc-rs for any timestamped output. |
| `OUT_DIR` paths in generated code | crane builds inside a content-addressed `/build/source`; paths are stable across hosts. |
| Linker build-id | `RUSTFLAGS=-C link-arg=-Wl,--build-id=none` drops the per-build random ID. |
| Cargo `--release` profile | `CARGO_PROFILE_RELEASE_STRIP=symbols` strips deterministically inside the derivation. |
| `tonic_build` / proto generation | `events/proto/*.proto` files included in the source filter; protoc is vendored via `protoc-bin-vendored` so no host protoc dep. |

### Gating policy

The `Nix` workflow is **advisory-only** in v1 — not a required check
on `master`. After ~10 green PRs the maintainer should promote it
to required. The `Release` workflow does **not** depend on it; tag-
time releases continue to ship rustup-stable tarballs and the Nix
build is a separate verification surface.

### `flake.lock`

The first PR that lands the flake intentionally **does not commit
`flake.lock`** because the maintainer who lands it does not have Nix
on their workstation. The CI workflow is gated to `workflow_dispatch`
+ relevant-paths PR triggers; the first run by a Nix-capable
maintainer (or via `workflow_dispatch` from a CI runner) will
generate the lock, after which it should be committed and the PR
description updated. Subsequent PRs run against the committed lock.

Renovate (or a manual cadence) bumps the lock weekly. Bumps that
change `flake.lock` re-trigger the repro check; if reproducibility
breaks under a new input revision, the bump is reverted and the
hazard is investigated.

### What's intentionally not in this flake

- macOS reproducibility (`aarch64-darwin`) — deferred until the
  repo flips public; macOS builds in the release workflow are
  also currently disabled for the same reason.
- musl targets — same `rocksdb-sys + musl` cross-toolchain reason
  the release workflow defers them.
- A NixOS module / Home Manager output — packagers should write
  their own service definitions; the contract this doc describes
  is the input.
- A maintainer-owned binary cache (Cachix) — adds a key-custody
  surface we're not taking on yet. The CI uses the ephemeral
  `magic-nix-cache` action for speedup only.

Bitcoin Core uses Guix; satd targets Nix as the primary reproducible
build because the workspace is pure-Cargo and Nix integration is
substantially shorter to specify. A Guix manifest may follow if a
downstream packager needs it.

## Release artifacts

Tag-triggered (`v*`) releases produce, per tag, via
`.github/workflows/release.yml` running on hosted GitHub runners:

- `satd-<version>-<target>.tar.zst` for the targets currently shipped:
  - `x86_64-unknown-linux-gnu`
  - `aarch64-unknown-linux-gnu`

  **macOS Apple Silicon (`aarch64-apple-darwin`) is temporarily
  disabled** while the repo is private. Hosted Apple Silicon runners
  bill at 20× the linux-2-core rate, which is uneconomical on the
  current Team plan. The matrix entry is commented out (not removed)
  in `.github/workflows/release.yml`; it will be re-enabled when the
  repo flips to public, at which point hosted Actions minutes are
  free. Until then, macOS users can `cargo install --git` or
  cross-build from any host.

  `x86_64-apple-darwin` is also not built — macos-13 is being
  deprecated by GitHub and Apple Silicon is the targeted macOS
  surface. Operators who need x86_64 darwin can cross-compile from
  an arm64 darwin host (`cargo build --release --target=x86_64-apple-darwin`).

  Each tarball contains stripped `satd` + `sat-cli` binaries and the
  authoritative reference docs (`README.md`, `PACKAGING.md`,
  `CORE_DIFFERENCES.md`, `STABILITY_POLICY.md`), plus a `MANIFEST` file
  pinning the build commit, target triple, Rust toolchain version, and
  build timestamp.

- A per-tarball `*.sha256` file alongside each artifact, plus an
  aggregate `SHA256SUMS` in the release.

- A multi-arch container at `ghcr.io/epochbtc/satd:<version>` covering
  `linux/amd64` + `linux/arm64`.

The workflow currently runs on tag pushes only. PR-trigger dry-runs
and `workflow_dispatch` were removed during the private-repo phase
to conserve hosted-runner minutes; they will be re-enabled when the
repo flips to public (Actions minutes are free for public repos).
Until then, release-workflow / Dockerfile / Cargo-lock breakage
first manifests at tag time rather than on the PR that introduced
it — fix forward by reverting or patching, then re-tag.

### Signed releases

Three independent signing surfaces. Verifier commands and key custody
details live in [`SECURITY.md`](../SECURITY.md).

- **Tarballs — minisign Ed25519.** Each `.tar.zst` ships with a
  detached `.minisig`. Pubkeys (primary + cold spare) in `SECURITY.md`.
  Maintainer signs offline with passphrases gated by 1Password +
  YubiKey 2FA — the signing key is never present in CI. Maintainer
  runbook: `contrib/release/sign-tarballs.sh <tag>`.
- **Container image — cosign keyless OIDC.** No signing key in
  custody. The merge-manifest CI job mints a short-lived cert from
  GitHub Actions OIDC and the attestation is logged to Rekor.
  Verify with:

  ```sh
  cosign verify ghcr.io/epochbtc/satd:<version> \
    --certificate-identity-regexp \
      'https://github.com/epochbtc/satd/.github/workflows/release.yml@refs/tags/v.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

- **Git tags — SSH signatures.** Annotated tags are signed by the
  maintainer's SSH key. Source-of-truth for the trusted pubkey set is
  `https://github.com/bkeroack.keys` (delegating to GitHub avoids a
  stale pinned file as machines rotate). Verify with the bundled
  helper:

  ```sh
  contrib/release/verify-tag.sh v0.1.0
  ```

### Coming in later PRs

- **musl-linux tarballs.** Targets `x86_64-unknown-linux-musl` and
  `aarch64-unknown-linux-musl`. Deferred to a follow-up because
  `rocksdb-sys` + musl wants a dedicated cross toolchain and the
  v0.1.0 priority is gnu-linux + macOS, both of which downstream
  package managers handle natively.
- **`cyclonedx`-format SBOM** attached to each release — PR-5.
- **`Type=notify` systemd unit upgrade** + OpenRC / runit equivalents
  — PR-6.

## Stability contract

Shipped surfaces (RPC method shapes, CLI flag shape, `bitcoin.conf`
syntax, file layout described above) are governed by
`STABILITY_POLICY.md`. Tier 1 (Core-compat) is the strongest: a
breaking change requires a deliberate, scoped proposal with a
demonstrated migration story for downstreams.

## Packaging contacts

If you are packaging satd for an ecosystem (Umbrel, Start9, Debian,
Nix, Homebrew, etc.) and need a contract change, file an issue tagged
`packaging` against the `epochbtc/satd` repo. We treat packaging
breakage as a P1.

---

## Versioning

This document is versioned alongside satd. Changes that shift the
contract (file layout, signals, default ports) are called out in the
release notes for the version that ships them.

| Version | Notable changes |
|---|---|
| 0.1.0 (current) | Initial PACKAGING.md. Dockerfile + systemd unit shipped. Tag-triggered release workflow on hosted runners produces tarballs (gnu-linux + Apple Silicon) and a multi-arch GHCR image. Signing across all three surfaces (minisign tarballs, cosign keyless image, SSH-signed tags) shipped. Nix flake (`flake.nix`) shipped for reproducible builds with two-runner CI verification (`x86_64-linux`, `aarch64-linux`); SBOM generation pending. |
