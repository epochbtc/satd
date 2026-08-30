#!/usr/bin/env bash
#
# Tests for check_results.py.
#
# The checker is what stops a green CI run from claiming a test ran when it
# did not. Each case below is a way a run could lie about its run-set: a test
# the framework skipped at runtime, a test missing from the results entirely,
# a results file that never appeared. Each must be rejected -- and an honest
# all-passed run must still be accepted.
#
# Run directly; no arguments. Exits non-zero on the first unmet expectation.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="$HERE/../check_results.py"

WORK="$(mktemp -d -t satd-results-test-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0

# expect <accept|reject> <name> <run-set...> <<< results csv
expect() {
    local want="$1" name="$2"
    shift 2
    local csv="$WORK/results.csv"
    cat > "$csv"
    local out rc
    out="$("$CHECKER" "$csv" "$@" 2>&1)"
    rc=$?
    if [[ "$want" == accept && $rc -ne 0 ]]; then
        echo "FAIL: $name -- expected accept, got exit $rc:"
        echo "$out" | sed 's/^/      /'
        FAILURES=$((FAILURES + 1))
    elif [[ "$want" == reject && $rc -eq 0 ]]; then
        echo "FAIL: $name -- expected reject, got exit 0"
        FAILURES=$((FAILURES + 1))
    else
        echo "ok:   $name"
    fi
}

expect accept "every run-set test passed" alpha.py beta.py <<'EOF'
test,status,duration(seconds)
alpha.py,Passed,3
beta.py,Passed,4
ALL,Passed,7
EOF

expect reject "a run-set test skipped at runtime" alpha.py beta.py <<'EOF'
test,status,duration(seconds)
alpha.py,Passed,3
beta.py,Skipped,0
ALL,Passed,3
EOF

expect reject "a run-set test missing from the results" alpha.py beta.py <<'EOF'
test,status,duration(seconds)
alpha.py,Passed,3
ALL,Passed,3
EOF

expect accept "a test reported under its per-variant names is present" alpha.py <<'EOF'
test,status,duration(seconds)
alpha.py --v1transport,Passed,3
alpha.py --v2transport,Passed,3
ALL,Passed,6
EOF

expect reject "a variant suffix does not excuse an absent test" alpha.py beta.py <<'EOF'
test,status,duration(seconds)
alpha.py --v1transport,Passed,3
ALL,Passed,3
EOF

expect reject "a runtime-skipped variant is still a runtime skip" alpha.py <<'EOF'
test,status,duration(seconds)
alpha.py --v1transport,Skipped,0
ALL,Passed,0
EOF

expect accept "a failing test is the runner's own exit code to report" alpha.py <<'EOF'
test,status,duration(seconds)
alpha.py,Failed,3
ALL,Failed,3
EOF

# A results file that never appeared: the runner died before writing one.
if "$CHECKER" "$WORK/does-not-exist.csv" alpha.py >/dev/null 2>&1; then
    echo "FAIL: a missing results file was accepted"
    FAILURES=$((FAILURES + 1))
else
    echo "ok:   a missing results file is rejected"
fi

if [[ $FAILURES -eq 0 ]]; then
    echo "all results-checker tests passed"
    exit 0
fi
echo "$FAILURES failure(s)"
exit 1
