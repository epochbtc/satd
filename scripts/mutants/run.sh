#!/bin/bash
# Mutation testing with cargo-mutants, in one of two scopes.
#
#   scripts/mutants/run.sh diff <diff-file>   # mutants on the lines a diff changed
#   scripts/mutants/run.sh nightly [k/n]      # one shard of the consensus-critical code
#
# A mutant is a small deliberate break (`<` for `<=`, a function body replaced
# by a default value). cargo-mutants builds each one and runs the tests of the
# crate it is in; a mutant those tests still pass is "missed". See
# scripts/mutants/report.py for how to read the result.
#
# `diff` is for a pull request: it tests only mutants on lines the diff touches,
# which asks whether the tests a change came with notice the change breaking.
#
# `nightly` walks NIGHTLY_GLOBS, too large for one night, in shards: tonight's
# shard is the day number modulo the shard count, so consecutive nights cover
# different slices and the whole scope comes round every n nights. The shard
# count follows the size of the scope (NIGHTLY_SHARD_SIZE mutants each).
#
# Both stop at BUDGET_MINUTES and report what they finished; the order is
# shuffled, so a run cut short is a sample of its scope rather than its first
# files. Exit status is 0 whenever the run itself worked, missed mutants or not:
# they are findings for a person to judge, not a test failure. A build error in
# the unmutated tree, or cargo-mutants failing, exits non-zero.
#
# Env: BUDGET_MINUTES (default 120), MUTANTS_OUT (default target/mutants-run),
# TEST_TIMEOUT / BUILD_TIMEOUT in seconds, GITHUB_STEP_SUMMARY when set.
# Runs cargo-mutants with --in-place: it edits and restores the checkout it is
# run from, so use a clean tree, not one with work in progress.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUDGET_MINUTES="${BUDGET_MINUTES:-120}"
MUTANTS_OUT="${MUTANTS_OUT:-$REPO_ROOT/target/mutants-run}"
# The baseline (unmutated) run is skipped, since CI's test jobs already run
# the tree, so cargo-mutants cannot size these from it. `node`'s own tests take
# about a minute on a fast machine; a hosted runner is several times slower.
TEST_TIMEOUT="${TEST_TIMEOUT:-900}"
BUILD_TIMEOUT="${BUILD_TIMEOUT:-1800}"
NIGHTLY_SHARD_SIZE="${NIGHTLY_SHARD_SIZE:-150}"

# The consensus-critical scope of the nightly run: script and transaction
# evaluation, block validation and connection, chain state, and the mempool.
NIGHTLY_GLOBS=(
    'consensus/src/**'
    'node/src/validation/**'
    'node/src/chain/**'
    'node/src/mempool/**'
)

usage() { sed -n '2,6p' "$0" >&2; exit 64; }

mode="${1:-}"
scope_args=()
note=""
case "$mode" in
    diff)
        diff_file="${2:-}"
        [ -f "$diff_file" ] || usage
        scope_args=(--in-diff "$diff_file")
        note="Mutants on the lines this change touched."
        ;;
    nightly)
        file_args=()
        for g in "${NIGHTLY_GLOBS[@]}"; do file_args+=(--file "$g"); done
        cd "$REPO_ROOT"
        total=$(cargo mutants --list "${file_args[@]}" | wc -l)
        if [ -n "${2:-}" ]; then
            shard="$2"
        else
            shards=$(( (total + NIGHTLY_SHARD_SIZE - 1) / NIGHTLY_SHARD_SIZE ))
            [ "$shards" -ge 1 ] || shards=1
            shard="$(( $(date -u +%s) / 86400 % shards ))/$shards"
        fi
        scope_args=("${file_args[@]}" --shard "$shard" --sharding round-robin)
        note="Shard $shard of the consensus-critical scope ($total mutants: ${NIGHTLY_GLOBS[*]})."
        ;;
    *) usage ;;
esac

cd "$REPO_ROOT"
listed=$(cargo mutants --list "${scope_args[@]}" | wc -l)
echo "$note $listed mutant(s) in scope; budget ${BUDGET_MINUTES} min."

# Markdown for the run summary, or the terminal outside Actions.
emit() { if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat >> "$GITHUB_STEP_SUMMARY"; else cat; fi; }
if [ "$listed" -eq 0 ]; then
    printf '### Mutation testing\n\n%s\n\nNo mutants in scope: nothing to test.\n' "$note" | emit
    exit 0
fi

rm -rf "$MUTANTS_OUT"
set +e
# SIGINT, not the default TERM: cargo-mutants stops at the interrupt and keeps
# outcomes.json for the mutants it finished.
timeout -s INT "${BUDGET_MINUTES}m" cargo mutants \
    "${scope_args[@]}" \
    --in-place --baseline=skip --shuffle \
    --timeout "$TEST_TIMEOUT" --build-timeout "$BUILD_TIMEOUT" \
    --output "$MUTANTS_OUT"
rc=$?
set -e

# cargo-mutants: 0 all caught, 2 some missed, 3 some timed out. 124 is our
# budget running out. Anything else means the run itself failed.
case "$rc" in
    0|2|3) ;;
    124) note="$note Stopped at the ${BUDGET_MINUTES}-minute budget." ;;
    *)
        echo "error: cargo mutants exited $rc" >&2
        exit "$rc"
        ;;
esac

outcomes="$MUTANTS_OUT/mutants.out/outcomes.json"
if [ ! -f "$outcomes" ]; then
    # The budget can run out before the first mutant finishes building.
    printf '### Mutation testing\n\n%s\n\nNo mutant finished inside the budget.\n' "$note" | emit
    echo "error: no mutant finished inside ${BUDGET_MINUTES} minutes" >&2
    exit 1
fi
args=("$outcomes" --listed "$listed" --note "$note" --annotate)
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && args+=(--summary "$GITHUB_STEP_SUMMARY")
python3 "$SCRIPT_DIR/report.py" "${args[@]}"
