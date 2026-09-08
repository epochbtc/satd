#!/usr/bin/env bash
#
# Tests for the bitcoind shim's process arrangement.
#
# The shim tees satd's stdout into debug.log from a forked child, and nothing
# synchronises that child with satd's exit -- the framework waits on satd's pid
# and reads the stdout file immediately afterwards. That is safe only for a
# node that keeps running. An invocation that prints one thing and exits must
# therefore bypass the tee entirely, which is what these cases pin: the
# print-and-exit flags leave no debug.log behind and still deliver every byte
# to stdout, while an ordinary node start still gets its debug.log.
#
# Run directly; no arguments. Exits non-zero on the first unmet expectation.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIM="$HERE/../shims/bitcoind"

WORK="$(mktemp -d -t satd-shim-test-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# A stand-in for satd. Prints a marker to stdout and exits, which is exactly
# the shape that loses the tee race.
FAKE="$WORK/fake-satd"
cat > "$FAKE" <<'EOF'
#!/usr/bin/env bash
echo "MARKER $*"
EOF
chmod +x "$FAKE"

# A stand-in that lingers, so the ordinary path has something to tee.
LINGER="$WORK/linger-satd"
cat > "$LINGER" <<'EOF'
#!/usr/bin/env bash
echo "MARKER $*"
sleep 0.5
EOF
chmod +x "$LINGER"

FAILURES=0

fail() {
    echo "FAIL: $1"
    shift
    for line in "$@"; do echo "      $line"; done
    FAILURES=$((FAILURES + 1))
}

# exits_immediately <name> <flag>
#
# The flag must reach satd unaltered, its output must arrive on stdout, and no
# debug.log may be created -- the last of those is what proves the tee was
# skipped rather than merely having won the race this time.
exits_immediately() {
    local name="$1" flag="$2"
    local datadir="$WORK/$name"
    mkdir -p "$datadir"
    local out
    out="$(SATD_BIN="$FAKE" "$SHIM" "-datadir=$datadir" -regtest "$flag" 2>/dev/null)"
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        fail "$name: shim exited $rc"
        return
    fi
    if [[ "$out" != *"MARKER"*"$flag"* ]]; then
        fail "$name: stdout did not carry the node's output" "got: $out"
        return
    fi
    if [[ -e "$datadir/regtest/debug.log" ]]; then
        fail "$name: a debug.log was created, so the tee ran for a process that exits immediately"
        return
    fi
    echo "ok:   $name execs straight through"
}

exits_immediately "dash-h" "-h"
exits_immediately "dash-help" "-help"
exits_immediately "dash-question" "-?"
exits_immediately "dash-version" "-version"
exits_immediately "ddash-help" "--help"
exits_immediately "ddash-version" "--version"

# The ordinary path is unchanged: a node start is still teed into debug.log.
node_start_is_teed() {
    local datadir="$WORK/node"
    mkdir -p "$datadir"
    local out
    out="$(SATD_BIN="$LINGER" "$SHIM" "-datadir=$datadir" -regtest 2>/dev/null)"
    if [[ "$out" != *"MARKER"* ]]; then
        fail "node start: stdout did not carry the node's output" "got: $out"
        return
    fi
    if [[ ! -s "$datadir/regtest/debug.log" ]]; then
        fail "node start: no debug.log was written"
        return
    fi
    if ! grep -q MARKER "$datadir/regtest/debug.log"; then
        fail "node start: debug.log does not contain the node's output"
        return
    fi
    echo "ok:   an ordinary node start is still teed to debug.log"
}

node_start_is_teed

# A modifier that merely contains a print-and-exit name must not be mistaken
# for one: Core's -help-debug changes the help text, it does not print it.
not_a_print_and_exit() {
    local datadir="$WORK/helpdebug"
    mkdir -p "$datadir"
    SATD_BIN="$LINGER" "$SHIM" "-datadir=$datadir" -regtest -help-debug=0 >/dev/null 2>&1
    if [[ ! -s "$datadir/regtest/debug.log" ]]; then
        fail "-help-debug: took the print-and-exit path"
        return
    fi
    echo "ok:   -help-debug is not treated as print-and-exit"
}

not_a_print_and_exit

if [[ $FAILURES -ne 0 ]]; then
    echo "$FAILURES failure(s)"
    exit 1
fi
echo "all shim cases passed"
