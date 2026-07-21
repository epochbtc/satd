# Packaging satd

This document is the authoritative reference for downstream packagers
(Umbrel, Start9, RaspiBlitz, MyNode, BTCPay, Debian/Fedora/Alpine,
Homebrew, Nix). It describes file layout, signals, ports, config
surface, runtime model, and the contract satd offers a packager.

The user-facing operator surfaces are documented elsewhere in this
manual. See [Observability & Metrics](observability.md) and
[Configuration, Tuning & Reload](configuration.md). The catalog of
intentional deviations from Bitcoin Core is
[`CORE_DIFFERENCES.md`](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md).
Ecosystem and packaging work that has not shipped is tracked in
[`ROADMAP.md`](https://github.com/epochbtc/satd/blob/master/ROADMAP.md).

## Document status

This is PACKAGING.md v1. It covers the surfaces shipped today: the
container image, the `Type=notify` systemd unit, the OpenRC and runit
equivalents, the on-disk layout, the operational surface, the release
pipeline, signing on all three surfaces, the reproducible build via
Nix, CycloneDX SBOMs per binary, and the `cargo-deny` supply-chain
gate.

Updated: 2026-05-07.

## Binaries

satd ships two binaries:

| Binary | Purpose |
|---|---|
| `satd` | The node. A long-running process that opens RocksDB and runs P2P, RPC, and the optional protocol surfaces. |
| `sat-cli` | JSON-RPC command-line client. Takes Bitcoin Core-compatible flags (`-rpcuser`, `-rpcpassword`, `-rpccookiefile`, network selectors). |

A third binary, `sat-tui`, is a curses-style operator dashboard. It is
optional; packagers can omit it.

There are no separate `sat-electrum` or `sat-esplora` companion
binaries. Both protocols are subsystems of satd, enabled with the
`--electrum=1` and `--esplora=1` flags. satd runs as one process with
one RocksDB instance, one log stream, and one PID. [Disk Footprint &
Indices](disk-footprint.md) covers the disk cost of the shared store.

## File layout

```
$DATADIR/                         # default: $HOME/.bitcoin (Core-compat)
└── <network>/                    # one of: <empty for mainnet>, testnet3, signet, regtest
    ├── blocks/
    │   ├── blk00000.dat          # flat-file block storage (state)
    │   ├── blk00001.dat
    │   └── ...
    ├── chainstate/               # RocksDB instance (state)
    │   ├── *.sst                 # SST files (the bulk of disk usage)
    │   ├── CURRENT, MANIFEST-*   # RocksDB metadata
    │   └── ...
    ├── .cookie                   # RPC cookie auth (auto-generated, mode 0600)
    ├── mempool_history.log       # rolling mempool snapshot (state, derived-OK)
    ├── reorg.log                 # persistent reorg ledger (state, append-only)
    ├── bitcoin.conf              # optional config file (Core-compat name)
    └── satd.conf                 # alternative config name (also accepted)
```

Three paths hold state and must be backed up to preserve consensus
history: `blocks/`, `chainstate/`, and `reorg.log`.

The derived files are safe to delete. Everything inside `chainstate/`
(the RocksDB instance), `mempool_history.log`, and the `*.complete`
index marker files inside `chainstate/` regenerate from `blocks/` with
`--reindex` or `--reindex-chainstate`. There is no `debug.log`: satd
logs to stdout.

> **Difference from Bitcoin Core.** satd does not keep separate
> databases for the txindex, address index, or BIP 158 filter index.
> They are column families inside the one RocksDB instance, written
> atomically with each `connect_block` batch.

Consequences of the single instance:

- Backup is one directory.
- An index update is never visible without the matching tip update.
  The whole `WriteBatch` commits, or none of it does.
- `--reindex-chainstate` rebuilds everything in chainstate (UTXO set
  and indexes) and preserves the flat files.

## Process model

- One process. The PID file is whatever the supervisor records; satd
  does not write its own PID file by default.
- `tokio` async runtime; many tasks on a fixed-size worker pool.
- `rayon` for script verification (CPU-bound parallelism).
- RocksDB keeps many SST files mmapped. Budget `LimitNOFILE=65536` at
  minimum. The systemd unit and the Docker image both pre-set this.

## Signals

| Signal | Behaviour |
|---|---|
| `SIGTERM` | Clean shutdown. Flushes RocksDB, fsyncs undo files, drains the mempool snapshot, closes listeners. Can take up to 10 minutes under heavy IBD load; most shutdowns finish in under a second. |
| `SIGINT` | Identical to `SIGTERM`. |
| `SIGHUP` | Live config reload. Re-reads `bitcoin.conf` and applies the hot-reloadable subset without dropping the P2P swarm or flushing chainstate. See [Configuration, Tuning & Reload](configuration.md#live-config-reload-sighup). |
| `SIGUSR1` | Live TLS certificate reload. Re-reads the configured TLS leaf cert and key from disk and swaps them in atomically on every TLS surface, without a restart or dropped connections. |
| `SIGKILL` | Not clean. RocksDB recovers via WAL replay on the next start. Avoid it; have the supervisor send `SIGTERM` and wait. |

> **Difference from Bitcoin Core.** Core reopens `debug.log` on
> `SIGHUP`. satd logs to stdout and repurposes `SIGHUP` for config
> reload.

Give the container supervisor a stop grace period of at least 10
minutes: `--stop-timeout=600` for `docker run`,
`terminationGracePeriodSeconds: 600` on Kubernetes. The systemd unit
ships `TimeoutStopSec=10min` for the same reason.

## Network ports (defaults)

| Service | Mainnet | Testnet | Signet | Regtest |
|---|---|---|---|---|
| P2P | 8333 | 18333 | 38333 | 18444 |
| JSON-RPC | 8332 | 18332 | 38332 | 18443 |

Esplora REST (`--esplora`), Electrum (`--electrum`), and the metrics
and health endpoint (`--metricsport`) have no per-network default
port. Each is off by default on every network. Pick a port per
deployment, for example 3000 for Esplora, 50001 for Electrum, and
9332 for metrics.

The default RPC bind is loopback.

## Health and readiness

When `--metricsport=<port>` is configured, satd exposes three
unauthenticated HTTP endpoints on that port (default bind 127.0.0.1):

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | The process is alive and the event loop responds. Cheap. |
| `GET /readyz` | RocksDB is open, headers are syncing, and peer count is above zero. Returns 503 during IBD. |
| `GET /metrics` | Prometheus exposition format. |

Wire these endpoints to a Docker `HEALTHCHECK`, Kubernetes liveness
and readiness probes, or a systemd `ExecStartPost=` poll. The shipped
`Type=notify` unit (see the systemd section) signals startup with
`sd_notify(READY=1)`. Supervisors without notify support can poll
`/readyz` instead.

## Configuration

Two files are accepted, both in Bitcoin Core's `key=value` /
`[network]` syntax:

- `bitcoin.conf`: the Core-compatible name. Same shape, same
  precedence.
- `satd.conf`: identical syntax. Preferred when running next to a
  Core install.

Resolution order: `--conf=<path>` if given, else
`<datadir>/bitcoin.conf`, else `<datadir>/satd.conf`. Command-line
flags always win over file values.

The full option matrix is in [Configuration, Tuning &
Reload](configuration.md). The container ships a mainnet-loopback
default; every value can be overridden with `-e SATD_*` environment
variables. See the Container section.

## Container

The repository ships a multi-stage `Dockerfile` at the repo root.
Build:

```sh
docker build -t satd:dev .
```

Properties of the image:

- Base: `debian:bookworm-slim`.
- Runtime user: `satd`, UID/GID 2121. A non-1000 UID avoids a
  bind-mount clash with the usual host operator UID.
- PID 1: `tini`, so SIGTERM forwards to satd cleanly.
- Datadir: `/var/lib/satd`, declared as a `VOLUME`.
- Exposed ports: `8333` (P2P) and `8332` (RPC). Map other ports with
  `-p` per deployment.

An example mainnet run with persistent state, RPC on loopback, and
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

Tag-triggered releases publish `linux/amd64` and `linux/arm64` images
to `ghcr.io/epochbtc/satd` via the workflow at
`.github/workflows/release.yml`. Tags follow `docker/metadata-action`
defaults: `<MAJOR>.<MINOR>.<PATCH>`, `<MAJOR>.<MINOR>`, and `latest`
on every release.

```sh
docker pull ghcr.io/epochbtc/satd:0.1.0
docker pull ghcr.io/epochbtc/satd:latest
```

The images are signed with cosign keyless OIDC and attested to the
Rekor transparency log. The verifier command is under Signed releases
below.

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

The unit ships restrictive hardening: read-only root, private `/tmp`,
a syscall filter, and no new privileges. To relax any of these, for
example to write to a datadir outside `/var/lib/satd`, use a drop-in:

```ini
# /etc/systemd/system/satd.service.d/datadir.conf
[Service]
ExecStart=
ExecStart=/usr/local/bin/satd --datadir=/srv/bitcoin
ReadWritePaths=
ReadWritePaths=/srv/bitcoin
```

The unit is `Type=notify`. satd calls `sd_notify(READY=1)` after every
listener is bound: RPC, P2P, and the optional Esplora, Electrum, MCP,
and events surfaces. Units that depend on satd, such as a Tor onion
service pointing at the RPC port or a monitoring agent, start once the
listeners exist instead of racing the bind sequence.

### Reindex resilience

`--reindex-chainstate` on a fully-synced mainnet node runs for hours.
satd handles this without help from the operator:

- The unit sets a finite `TimeoutStartSec=3min`, not `infinity`. That
  is long enough for the first heartbeat, at 30 s, to land and push
  the deadline out. It is short enough that a wedge before the first
  heartbeat is killed in bounded time. `EXTEND_TIMEOUT_USEC` only
  works against a finite `TimeoutStartSec`; an infinite startup
  timeout would let a wedged process hang before `READY=1`.
- Every 30 s during the pre-bind phase, satd emits
  `sd_notify(EXTEND_TIMEOUT_USEC=120000000, STATUS=...)`.
  `EXTEND_TIMEOUT_USEC` resets systemd's internal kill deadline. The
  `STATUS` line shows the live phase and progress in
  `systemctl status satd`.
- The heartbeat doubles as the liveness check. If satd sends nothing
  for more than 120 s, systemd kills the unit and the on-failure
  restart loop takes over.

```sh
$ systemctl status satd
● satd.service - Bitcoin full node
     Loaded: loaded (/etc/systemd/system/satd.service; enabled)
     Active: activating (start) since Wed 2026-05-07 18:44:19 UTC
     Status: "Replaying blocks (350000/800000, 43%)"
   Main PID: 12345 (satd)
```

Bitcoin Core's `bitcoind.service` has behaved the same way since v22.

### Running multiple networks side by side

There is no `satd@.service` template unit yet. To run signet,
regtest, and mainnet on the same host, copy the unit under different
names and add per-instance drop-ins:

```sh
# Mainnet: the default unit installed above (satd.service).

# Signet on the same host:
sudo cp contrib/systemd/satd.service \
        /etc/systemd/system/satd-signet.service

# /etc/systemd/system/satd-signet.service.d/instance.conf
sudo install -Dm644 /dev/stdin \
        /etc/systemd/system/satd-signet.service.d/instance.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/local/bin/satd --signet --datadir=/var/lib/satd-signet
StateDirectory=
StateDirectory=satd-signet
ReadWritePaths=
ReadWritePaths=/var/lib/satd-signet
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now satd-signet
```

Use the same pattern for `--regtest`. Give each instance its own
datadir and its own RPC port (`--rpcport=<n>` in the drop-in). Each
instance can have its own `satd-<network>` user or share the `satd`
user.

A native `satd@.service` template unit (`systemctl start satd@signet`)
is a candidate for v0.1.x if the drop-in pattern proves insufficient.

## OpenRC

For Alpine, Gentoo with the `openrc` profile, Artix, and other
OpenRC distributions, the repository ships
`contrib/openrc/init.d/satd`.

```sh
sudo install -Dm755 contrib/openrc/init.d/satd /etc/init.d/satd
sudo install -Dm755 target/release/satd /usr/local/bin/satd
sudo install -Dm755 target/release/sat-cli /usr/local/bin/sat-cli
sudo adduser -S -H -h /var/lib/satd -s /sbin/nologin satd
sudo install -d -m 0750 -o satd -g satd /var/lib/satd
sudo rc-update add satd default
sudo rc-service satd start
```

OpenRC has no notify protocol. It marks the service started once satd
backgrounds via `start-stop-daemon`, so reindex never contends with a
startup timeout. The service reads as `running` for the whole
reindex.

Set per-instance options in `/etc/conf.d/satd`:

```sh
# /etc/conf.d/satd
satd_args="--prune=550 --txindex=0"
```

## runit

For Void Linux, Artix-runit, and any s6-rc-compatible setup, the
repository ships `contrib/runit/satd/run` and a log helper at
`contrib/runit/satd/log/run`.

```sh
sudo install -Dm755 contrib/runit/satd/run     /etc/sv/satd/run
sudo install -Dm755 contrib/runit/satd/log/run /etc/sv/satd/log/run
sudo install -Dm755 target/release/satd        /usr/local/bin/satd
sudo install -Dm755 target/release/sat-cli     /usr/local/bin/sat-cli
sudo useradd --system --home /var/lib/satd --shell /sbin/nologin satd
sudo install -d -m 0750 -o satd -g satd /var/lib/satd
sudo ln -s /etc/sv/satd /var/service/satd
```

runit supervises foreground processes, so satd never daemonizes.
There is no readiness gate and no startup timeout; reindex runs as
long as it needs to.

## Resource budget

Mainnet, fresh IBD, no optional indexes:

| Resource | Pi 5 (8 GB) target | Server target |
|---|---|---|
| Disk (chainstate + blocks) | ~700 GB at 2026-05 tip | same |
| RAM peak during IBD | ~3 GB | unbounded by `dbcache` |
| RAM steady-state | ~1.5 GB | ~2 GB |
| CPU during IBD | 4 cores ≈ saturated | scales with cores |
| Network during IBD | 50–200 Mbps | network-bound |

Each optional index (`--txindex`, `--addressindex`,
`--blockfilterindex`) adds disk and a one-time backfill cost.
Enabling an index on a synced node runs an online backfill; there is
no stop-and-reindex step. The backfill cursors are in
`node/src/index/<index>/backfill.rs`.

## Pruning

`--prune=<MiB>` has the same shape as in Bitcoin Core. The minimum is
550 MiB.

Indexes that scan historical blocks (`--txindex`, `--addressindex`,
`--blockfilterindex`) require unpruned blocks. satd refuses to start
with a conflicting combination, as Core does.

## Reproducible build via Nix

The repository ships a Nix flake at `flake.nix`. It produces
deterministic `satd` and `sat-cli` binaries on `x86_64-linux` and
`aarch64-linux`.

Quickstart, for a packager who already has Nix with flakes enabled:

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

The toolchain pin at `rust-toolchain.toml` is authoritative. Both
rustup and the flake read it; there is no second place to update.

### What "reproducible" means in v1

- Two `nix build` invocations of the same commit on two hosts produce
  a byte-identical `result/bin/satd`. CI proves this on every PR that
  touches `flake.nix`, `flake.lock`, `rust-toolchain.toml`, or
  `Cargo.lock`, via `.github/workflows/nix.yml`: a two-runner pair
  build plus a compare job that asserts SHA256 equality.
- Local reproduction is one command: `contrib/repro/diff-build.sh
  /path/to/clone-A /path/to/clone-B`. It runs `nix build` in each
  clone, hashes the outputs, and falls back to `diffoscope` when they
  diverge.
- Out of scope for v1: matching the rustup-stable tarball binary (the
  one `.github/workflows/release.yml` ships) byte for byte. That
  requires aligning linker, debug-info, and build-id behaviour across
  two different build drivers. It is tractable, but it is a separate
  PR.

### Determinism hazards addressed

| Hazard | How the flake handles it |
|---|---|
| `rocksdb-sys` bindgen output | `rustPlatform.bindgenHook` sets up libclang + the stdenv's system include paths so bindgen's translation-unit parse is reproducible. Output is deterministic for a fixed libclang version. |
| RocksDB native code | The flake links nixpkgs's pre-built `rocksdb` (via `ROCKSDB_LIB_DIR` / `ROCKSDB_INCLUDE_DIR`) instead of the C++ tree vendored by librocksdb-sys. nixpkgs builds rocksdb portably, without `-march=native`, so CPU variance across runners does not affect the output. The trade-off is a minor version mismatch between librocksdb-sys's pinned 10.4.2 and whatever nixpkgs ships; bindings are regenerated either way, and major API drift would surface as a compile error. |
| `cc-rs` C/C++ compiles (secp256k1, bitcoinconsensus) | Compiler version pinned via nixpkgs; `SOURCE_DATE_EPOCH` respected by cc-rs for any timestamped output. |
| `OUT_DIR` paths in generated code | crane builds inside a content-addressed `/build/source`; paths are stable across hosts. |
| Linker build-id | `RUSTFLAGS=-C link-arg=-Wl,--build-id=none` drops the per-build random ID. |
| Cargo `--release` profile | `CARGO_PROFILE_RELEASE_STRIP=symbols` strips deterministically inside the derivation. |
| `tonic_build` / proto generation | `events/proto/*.proto` files included in the source filter; protoc is vendored via `protoc-bin-vendored` so no host protoc dep. |

### Gating policy

The `Nix` workflow runs on tag pushes (`v*`), on `workflow_dispatch`,
and on PRs that change flake-specific files: the flake itself,
`rust-toolchain.toml`, the workflow, and the repro helper under
`contrib/repro/`. It does not trigger on `Cargo.lock` or `Cargo.toml`
edits. Every dependency bump touches those files, and the runs would
burn hosted-runner minutes for little signal.

The Nix and Release workflows fire in parallel at tag-cut time and do
not gate each other. If the Nix side fails, the released tarball
cannot claim Nix-rebuilt provenance for that tag, and the fix goes
out forward.

Reconsider the trigger scope and a hard Release-gates-on-Nix
dependency once the repo flips public and Actions minutes are free.

### `flake.lock`

The first PR that lands the flake does not commit `flake.lock`,
because the maintainer who lands it does not have Nix on their
workstation. The CI workflow is gated to `workflow_dispatch`, to
flake-touching PRs, and to tag pushes. The first `workflow_dispatch`
run by a Nix-capable maintainer, or from a CI runner, generates the
lock. Commit the lock at that point and update the PR description.
Subsequent PRs run against the committed lock.

Renovate, or a manual cadence, bumps the lock weekly. A bump that
changes `flake.lock` re-triggers the repro check. If reproducibility
breaks under a new input revision, revert the bump and investigate
the hazard.

### What's intentionally not in this flake

- macOS reproducibility (`aarch64-darwin`): deferred. The release
  workflow ships an Apple Silicon tarball, but the flake does not yet
  verify it reproducibly.
- musl reproducibility: deferred for `rocksdb-sys` and musl
  cross-toolchain reasons. The release workflow ships both musl
  tarballs; the flake covers only the glibc Linux targets.
- A NixOS module or Home Manager output: packagers write their own
  service definitions, with the contract in this document as the
  input.
- A maintainer-owned binary cache (Cachix): it adds a key-custody
  surface not yet taken on. CI uses the ephemeral `magic-nix-cache`
  action for speed only.

Bitcoin Core uses Guix. satd targets Nix as the primary reproducible
build because the workspace is pure Cargo and a Nix integration is
much shorter to specify. A Guix manifest may follow if a downstream
packager needs it.

## Release artifacts

Tag-triggered (`v*`) releases run `.github/workflows/release.yml` on
hosted GitHub runners and produce, per tag:

- `satd-<version>-<target>.tar.zst` for the targets currently shipped:
  - `x86_64-unknown-linux-gnu`
  - `aarch64-unknown-linux-gnu`
  - `x86_64-unknown-linux-musl` (statically-linked musl)
  - `aarch64-unknown-linux-musl` (statically-linked musl)
  - `aarch64-apple-darwin` (macOS Apple Silicon)

  `x86_64-apple-darwin` is not built in the standard release matrix.
  GitHub is deprecating macos-13 runners, and Apple Silicon is the
  targeted macOS surface. To get an x86_64 darwin build, cross-compile
  from an arm64 darwin host
  (`cargo build --release --target=x86_64-apple-darwin`).

  Each tarball contains stripped `satd` and `sat-cli` binaries, the
  authoritative reference docs (`README.md`, `PACKAGING.md`,
  `CORE_DIFFERENCES.md`, `STABILITY_POLICY.md`), and a `MANIFEST` file
  pinning the build commit, target triple, Rust toolchain version, and
  build timestamp.

- A per-tarball `*.sha256` file alongside each artifact, plus an
  aggregate `SHA256SUMS` covering the tarballs and the SBOMs.

- A multi-arch container at `ghcr.io/epochbtc/satd:<version>` covering
  `linux/amd64` and `linux/arm64`.

- CycloneDX 1.5 JSON SBOMs for each shipped binary:
  - `satd-v<version>.cdx.json`
  - `sat-cli-v<version>.cdx.json`

  Each ships with a `*.sha256` next to it (already in `SHA256SUMS`)
  and a `*.minisig` produced by the same maintainer-side
  `contrib/release/sign-tarballs.sh` flow that signs the tarballs.

The release workflow triggers on tag pushes (`v*`) and on
`workflow_dispatch`, and builds the binary, container, and SBOM
artifacts in parallel.

### Signed releases

satd signs three independent surfaces. Verifier commands and key
custody details live in
[`SECURITY.md`](https://github.com/epochbtc/satd/blob/master/SECURITY.md).

- **Tarballs (minisign Ed25519).** Each `.tar.zst` ships with a
  detached `.minisig`. The public keys, primary and cold spare, are
  in `SECURITY.md`. The maintainer signs offline; the passphrases sit
  behind 1Password with YubiKey 2FA, and the signing key is never
  present in CI. The maintainer runbook is
  `contrib/release/sign-tarballs.sh <tag>`.
- **Container image (cosign keyless OIDC).** No signing key in
  custody. The merge-manifest CI job mints a short-lived certificate
  from GitHub Actions OIDC, and the attestation is logged to Rekor.
  Verify with:

  ```sh
  cosign verify ghcr.io/epochbtc/satd:<version> \
    --certificate-identity-regexp \
      'https://github.com/epochbtc/satd/.github/workflows/release.yml@refs/tags/v.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

- **Git tags (SSH signatures).** Annotated tags are signed with the
  maintainer's SSH key. The source of truth for the trusted pubkey
  set is `https://github.com/bkeroack.keys`; delegating to GitHub
  avoids a stale pinned file as machines rotate. Verify with the
  bundled helper:

  ```sh
  contrib/release/verify-tag.sh v0.1.0
  ```

### Software Bill of Materials

Each release ships a CycloneDX 1.5 JSON SBOM per binary:

```sh
# Authenticate the SBOM (same key + recipe as the tarballs)
minisign -Vm satd-v0.1.0.cdx.json \
  -P RWQeP6MczCgPh6tU03GEMm4HsnGbXte3VT2Bc52TBSR7Q+X7WnL5vfQ3

# Enumerate dependencies: name, version, license
jq -r '.components[] | "\(.name) \(.version) \(.licenses[0].license.id // .licenses[0].license.name // "?")"' \
  satd-v0.1.0.cdx.json | sort
```

The SBOM is generated from the same `Cargo.lock` that produced the
released binary. The `cargo cyclonedx` invocation lives in the `sbom`
job in `.github/workflows/release.yml`. The dependency graph is
identical across the gnu-linux release targets currently shipped
(`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`), so a
single SBOM per binary covers both tarballs.

musl and macOS targets can resolve different platform-specific
dependencies, for example `libc` shim crates or `security-framework`
on darwin. A release that adds them needs the workflow to emit a
per-target SBOM, and the artifact filenames gain a target-triple
suffix. Track this when re-enabling the deferred targets in the
release matrix.

### Supply-chain policy

`deny.toml` at the repo root encodes the supply-chain policy enforced
by [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny):

- **Advisories.** Every RustSec advisory against any dependency in
  the workspace fails CI by default. Exceptions are documented in
  `[advisories.ignore]` with a `reason` field naming the rationale.
- **Licenses.** Permissive only: the MIT / Apache-2.0 / BSD / ISC /
  Unicode / CC0 / Zlib / Unlicense / MPL-2.0 family. GPL-* and
  AGPL-* are denied implicitly.
- **Bans.** Wildcard versions on crates.io dependencies are denied.
  Workspace-internal `path = "../foo"` dependencies are allowed via
  `allow-wildcard-paths`, since every workspace crate is
  `publish = false`.
- **Sources.** Only `https://github.com/rust-lang/crates.io-index`.
  Git dependencies require an explicit allowlist entry.

The policy runs as a hard gate in two places:

- `.github/workflows/deny.yml`, on every PR that touches
  `Cargo.toml`, `Cargo.lock`, `deny.toml`, or the workflow itself.
- The `supply-chain-gate` job inside
  `.github/workflows/release.yml`. Every release artifact (tarballs,
  SBOMs, container) `needs:` it, so a new RustSec advisory that lands
  during a quiet period between merges cannot ship in a release.

### Known deferred items

- `cargo-auditable`: embed the dependency manifest in the compiled
  binaries for better runtime supply-chain verification.

## Stability contract

The shipped surfaces (RPC method shapes, CLI flag shape,
`bitcoin.conf` syntax, the file layout described above) are governed
by `STABILITY_POLICY.md`. Tier 1, the Core-compatible surface, is the
strongest: a breaking change requires a scoped proposal with a
demonstrated migration story for downstreams.

## Packaging contacts

To request a contract change for an ecosystem package (Umbrel,
Start9, Debian, Nix, Homebrew, and so on), file an issue tagged
`packaging` against the `epochbtc/satd` repo. Packaging breakage is
treated as a P1.

---

## Versioning

This document is versioned alongside satd. Changes that shift the
contract (file layout, signals, default ports) are called out in the
release notes for the version that ships them.

| Version | Notable changes |
|---|---|
| 0.1.0 (current) | Initial PACKAGING.md. Dockerfile + systemd unit shipped. Tag-triggered release workflow on hosted runners produces tarballs (gnu-linux + Apple Silicon) and a multi-arch GHCR image. Signing across all three surfaces (minisign tarballs, cosign keyless image, SSH-signed tags) shipped. Nix flake (`flake.nix`) shipped for reproducible builds with two-runner CI verification (`x86_64-linux`, `aarch64-linux`). CycloneDX 1.5 SBOMs per binary + `cargo-deny` supply-chain gate (PR-time on dep-graph PRs, hard gate at tag time) shipped. systemd unit upgraded to `Type=notify` with sd_notify heartbeats so `--reindex-chainstate` does not trip `TimeoutStartSec`; OpenRC and runit unit equivalents shipped. |
