#!/bin/bash
# Run every self-contained fuzz target in fuzz/ for a fixed time each. Needs a
# nightly toolchain and cargo-fuzz; no Docker.
#
#   SECONDS_PER_TARGET=60 scripts/fuzz/run-standalone-targets.sh
#   SECONDS_PER_TARGET=60 scripts/fuzz/run-standalone-targets.sh psbt_raw
#
# With no arguments the targets come from `cargo fuzz list`, minus the ones in
# ORACLE_TARGETS, which need a live bitcoind and have a job of their own
# (.github/workflows/core_block_differential_fuzz.yml). Listing rather than
# naming them is the point: a target added to fuzz/Cargo.toml is fuzzed the
# next night without anyone remembering to wire it in. Three of the first four
# targets were compiled by CI and never run, because only the one with a job
# was ever run.
#
# Every target runs even when an earlier one fails, so one crash does not hide
# another. A crash, timeout or OOM input lands in fuzz/artifacts/<target>/.
# The script exits non-zero if any target failed or ran zero inputs, and when
# GITHUB_STEP_SUMMARY is set it writes a per-target table there.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SECONDS_PER_TARGET="${SECONDS_PER_TARGET:-600}"

# Targets that need an external oracle and run elsewhere.
ORACLE_TARGETS=(block_differential)

# The pinned nightly lives in run-block-differential.sh, so both fuzz jobs and
# every reproducer they hand out use one toolchain. Parsed with the same
# pattern the block-differential workflow uses; a FUZZ_NIGHTLY in the
# environment overrides it.
if [ -z "${FUZZ_NIGHTLY:-}" ]; then
    FUZZ_NIGHTLY=$(sed -n 's/^FUZZ_NIGHTLY="${FUZZ_NIGHTLY:-\(.*\)}"$/\1/p' \
        "$SCRIPT_DIR/run-block-differential.sh")
    if [ -z "$FUZZ_NIGHTLY" ]; then
        echo "error: could not parse the FUZZ_NIGHTLY pin from run-block-differential.sh" >&2
        exit 1
    fi
fi
if [ "${1:-}" = "--print-toolchain" ]; then
    echo "$FUZZ_NIGHTLY"
    exit 0
fi

cd "$REPO_ROOT"

if [ "$#" -gt 0 ]; then
    targets=("$@")
else
    targets=()
    while IFS= read -r t; do
        skip=0
        for o in "${ORACLE_TARGETS[@]}"; do [ "$t" = "$o" ] && skip=1; done
        [ "$skip" = 1 ] || targets+=("$t")
    done < <(cargo "+$FUZZ_NIGHTLY" fuzz list)
fi
if [ "${#targets[@]}" -eq 0 ]; then
    echo "error: no fuzz targets to run" >&2
    exit 1
fi
echo "Fuzzing ${#targets[@]} target(s) for ${SECONDS_PER_TARGET}s each on $FUZZ_NIGHTLY: ${targets[*]}"

# Build every target once, so a compile error fails here, before any fuzzing,
# rather than as a confusing per-target failure.
for t in "${targets[@]}"; do
    cargo "+$FUZZ_NIGHTLY" fuzz build "$t"
done

log_dir="$(mktemp -d)"
trap 'rm -rf "$log_dir"' EXIT
failed=()
rows=()
for t in "${targets[@]}"; do
    echo "::group::fuzz $t"
    log="$log_dir/$t.log"
    set +e
    cargo "+$FUZZ_NIGHTLY" fuzz run "$t" -- -max_total_time="$SECONDS_PER_TARGET" 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
    set -e
    echo "::endgroup::"
    # libFuzzer's closing line: "Done 123456 runs in 600 second(s)".
    runs=$(sed -n 's/^Done \([0-9]*\) runs in .*/\1/p' "$log" | tail -1)
    if [ "$rc" -ne 0 ]; then
        failed+=("$t")
        result="FAILED (exit $rc)"
    elif [ -z "$runs" ] || [ "$runs" -eq 0 ]; then
        # A run that exits 0 without executing an input proves nothing.
        failed+=("$t")
        result="FAILED (no inputs executed)"
    else
        result="ok"
    fi
    rows+=("| \`$t\` | ${runs:-0} | $result |")
done

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### Fuzz targets (${SECONDS_PER_TARGET}s each, $FUZZ_NIGHTLY)"
        echo
        echo "| Target | Inputs run | Result |"
        echo "|---|---:|---|"
        printf '%s\n' "${rows[@]}"
    } >> "$GITHUB_STEP_SUMMARY"
fi
printf '%s\n' "${rows[@]}"

if [ "${#failed[@]}" -gt 0 ]; then
    echo "error: fuzz target(s) failed: ${failed[*]}" >&2
    exit 1
fi
