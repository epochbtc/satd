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
# Pinned nightly, not floating: cargo-fuzz needs nightly, but this job exists
# to find consensus divergence, not to track rustc. A floating `nightly` makes
# any upstream regression red the job — nightly-2026-07-24 (rustc 89c61a754)
# ICEs in rustc_codegen_ssa building `tokio` in release mode, which broke every
# run until this pin.
#
# THIS LINE IS THE SINGLE SOURCE OF TRUTH for the pinned toolchain.
# `.github/workflows/core_block_differential_fuzz.yml` parses it out of this
# file rather than declaring its own copy: when the two were kept in sync by
# comment, a drift would have sent the on-call a reproducer that runs on a
# different toolchain than the job that failed. Keep the assignment on one
# line, in this exact `FUZZ_NIGHTLY="${FUZZ_NIGHTLY:-...}"` form — the
# workflow's parser matches it, and fails the job if it stops matching.
#
# Bump deliberately, after checking the new toolchain builds this script
# locally; override with FUZZ_NIGHTLY=nightly to try a newer one first.
FUZZ_NIGHTLY="${FUZZ_NIGHTLY:-nightly-2026-07-22}"

cleanup() { docker rm -f satd-fuzz-core >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Seed the corpus (idempotent) using the same builders as the target.
( cd "$REPO_ROOT/fuzz" && cargo "+$FUZZ_NIGHTLY" run --release --bin gen_corpus -- corpus/block_differential )

# Fuzz. cargo-fuzz resolves ./fuzz/ relative to the repo root.
cd "$REPO_ROOT"
cargo "+$FUZZ_NIGHTLY" fuzz run block_differential -- -max_total_time="$MAX_TOTAL_TIME"
