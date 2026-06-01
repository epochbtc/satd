#!/bin/bash
# Phase C Layer 2 — run the in-process consensus fuzzer with a live Bitcoin
# Core oracle. Needs a nightly toolchain, cargo-fuzz, and Docker.
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

cleanup() { docker rm -f satd-fuzz-core >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Seed the corpus (idempotent) using the same builders as the target.
( cd "$REPO_ROOT/fuzz" && cargo +nightly run --release --bin gen_corpus -- corpus/block_differential )

# Fuzz. cargo-fuzz resolves ./fuzz/ relative to the repo root.
cd "$REPO_ROOT"
cargo +nightly fuzz run block_differential -- -max_total_time="$MAX_TOTAL_TIME"
