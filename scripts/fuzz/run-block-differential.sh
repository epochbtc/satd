#!/bin/bash
# Block-acceptance differential fuzz — run the in-process consensus fuzzer with
# a live Bitcoin Core oracle. Needs a nightly toolchain, cargo-fuzz, and Docker.
#
#   MAX_TOTAL_TIME=300 scripts/fuzz/run-block-differential.sh
#
# The fuzz target (fuzz/fuzz_targets/block_differential.rs) spawns a resident
# regtest bitcoind (lncm/bitcoind:v27.0) named `satd-fuzz-core`; this script
# tears it down on exit. A discovered divergence is written to
# fuzz/artifacts/block_differential/ AND its block hex is printed to stderr,
# so the run log alone is enough to reproduce.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-300}"
# Pinned nightly, not floating: an upstream rustc regression must not red this
# job (see the FUZZ_NIGHTLY comment in
# .github/workflows/core_block_differential_fuzz.yml). Keep this default in
# sync with that workflow so a local run reproduces CI exactly; override with
# FUZZ_NIGHTLY=nightly to test a newer toolchain before bumping both.
FUZZ_NIGHTLY="${FUZZ_NIGHTLY:-nightly-2026-07-22}"

cleanup() { docker rm -f satd-fuzz-core >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Seed the corpus (idempotent) using the same builders as the target.
( cd "$REPO_ROOT/fuzz" && cargo "+$FUZZ_NIGHTLY" run --release --bin gen_corpus -- corpus/block_differential )

# Fuzz. cargo-fuzz resolves ./fuzz/ relative to the repo root.
cd "$REPO_ROOT"
cargo "+$FUZZ_NIGHTLY" fuzz run block_differential -- -max_total_time="$MAX_TOTAL_TIME"
