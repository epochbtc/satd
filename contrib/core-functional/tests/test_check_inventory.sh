#!/usr/bin/env bash
#
# Tests for check_inventory.py.
#
# The checker is what stops the scoreboard drifting from reality, so each case
# below is a way the inventory could lie: a test file with no row, a row for a
# file that no longer exists, a skip with no reason or a reason outside the
# taxonomy, an open-ended skip with nothing tracking it. Each must be rejected.
#
# Run directly; no arguments. Exits non-zero on the first unmet expectation.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="$HERE/../check_inventory.py"

WORK="$(mktemp -d -t satd-inventory-test-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cp "$CHECKER" "$WORK/check_inventory.py"
cat > "$WORK/PIN" <<'EOF'
CORE_TAG=vTEST
CORE_COMMIT=0000000000000000000000000000000000000000
EOF
printf 'alpha.py\nbeta.py\n' > "$WORK/vTEST-tests.txt"

FAILURES=0

# expect <accept|reject> <name> <<< inventory body
expect() {
    local want="$1" name="$2"
    local inv="$WORK/inv.toml"
    cat > "$inv"
    local out
    out="$("$WORK/check_inventory.py" --inventory "$inv" 2>&1)"
    local rc=$?
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

expect accept "a complete, valid inventory" <<'EOF'
[[test]]
file = "alpha.py"
status = "run"

[[test]]
file = "beta.py"
status = "skip"
reason = "no-wallet"
EOF

expect reject "a test file with no row" <<'EOF'
[[test]]
file = "alpha.py"
status = "run"
EOF

expect reject "a row for a file not in the pinned list" <<'EOF'
[[test]]
file = "alpha.py"
status = "run"

[[test]]
file = "beta.py"
status = "run"

[[test]]
file = "gamma.py"
status = "run"
EOF

expect reject "a duplicate row" <<'EOF'
[[test]]
file = "alpha.py"
status = "run"

[[test]]
file = "alpha.py"
status = "run"

[[test]]
file = "beta.py"
status = "run"
EOF

expect reject "a skip with no reason" <<'EOF'
[[test]]
file = "alpha.py"
status = "run"

[[test]]
file = "beta.py"
status = "skip"
EOF

expect reject 'reason = "unknown"' <<'EOF'
[[test]]
file = "alpha.py"
status = "run"

[[test]]
file = "beta.py"
status = "skip"
reason = "unknown"
EOF

expect reject "a reason outside the taxonomy" <<'EOF'
[[test]]
file = "alpha.py"
status = "run"

[[test]]
file = "beta.py"
status = "skip"
reason = "it-is-annoying"
EOF

expect reject "an open-ended skip with no follow-up note" <<'EOF'
[[test]]
file = "alpha.py"
status = "run"

[[test]]
file = "beta.py"
status = "skip"
reason = "rpc-missing"
EOF

expect accept "an open-ended skip that names its follow-up" <<'EOF'
[[test]]
file = "alpha.py"
status = "run"

[[test]]
file = "beta.py"
status = "skip"
reason = "rpc-missing"
note = "needs getdescriptorinfo; tracked in #1234"
EOF

expect reject "an unknown status" <<'EOF'
[[test]]
file = "alpha.py"
status = "maybe"

[[test]]
file = "beta.py"
status = "run"
EOF

expect reject "a run row carrying a skip reason" <<'EOF'
[[test]]
file = "alpha.py"
status = "run"
reason = "no-wallet"

[[test]]
file = "beta.py"
status = "run"
EOF

# --print-run-set drives run.sh, so it must emit exactly the run rows.
cat > "$WORK/inv.toml" <<'EOF'
[[test]]
file = "alpha.py"
status = "run"

[[test]]
file = "beta.py"
status = "skip"
reason = "no-wallet"
EOF
got="$("$WORK/check_inventory.py" --inventory "$WORK/inv.toml" --print-run-set)"
if [[ "$got" == "alpha.py" ]]; then
    echo "ok:   --print-run-set emits only run rows"
else
    echo "FAIL: --print-run-set emitted: $got"
    FAILURES=$((FAILURES + 1))
fi

if [[ $FAILURES -eq 0 ]]; then
    echo "all checker tests passed"
    exit 0
fi
echo "$FAILURES failure(s)"
exit 1
