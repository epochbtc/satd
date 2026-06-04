# Reproducible build helpers

Tools for verifying the satd flake produces deterministic binaries.

| Script | Audience | Purpose |
|---|---|---|
| `diff-build.sh <A> <B>` | Maintainer / packager | Build the flake against two clean checkouts and assert byte-identical binaries. Falls back to `diffoscope` when hashes diverge (if installed). |

The full reproducibility story — flake design, determinism hazards
addressed, gating policy — lives in
[`docs/manual/src/packaging.md`](../../docs/manual/src/packaging.md) §"Reproducible build via Nix".

CI runs an equivalent two-runner check on every PR that touches
`flake.nix`, `flake.lock`, `rust-toolchain.toml`, or `Cargo.lock`;
see [`.github/workflows/nix.yml`](../../.github/workflows/nix.yml).
