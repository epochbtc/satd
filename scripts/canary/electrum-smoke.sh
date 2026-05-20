#!/bin/bash
# Electrum protocol canary — drives the wire protocol with raw `nc`,
# zero client-library dependencies. Verifies that satd speaks the
# Electrum line-delimited JSON-RPC protocol correctly enough for
# real Electrum clients (Sparrow, BlueWallet, electrum-client crate)
# to interoperate.
#
# Coverage:
#   server.version          — handshake
#   server.banner
#   blockchain.headers.subscribe
#   blockchain.estimatefee
#   blockchain.relayfee
#
# This complements (does not replace) tests/e2e.rs's Electrum suite,
# which uses the `electrum-client` Rust crate (same library BDK
# consumes) for deeper protocol checks. This shell smoke catches
# wire-format breaks at a lower level — if `nc | jq` can't parse our
# response, no real client will either.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"

ELECTRUM_DATADIR="$(mktemp -d -t satd-canary-electrum.XXXXXX)"
boot_satd "$ELECTRUM_DATADIR" 18200 --electrum=1 --addressindex=1

# Helper: send a JSON-RPC frame on a one-shot TCP connection, read the
# response, parse with jq. Electrum's framing is `<JSON>\n`; we use
# `printf` + `nc -q 1 -w 5` to send + close + read with a 5s budget.
electrum_call() {
    local method="$1"
    local params="$2"
    local id="${3:-1}"
    local request
    request=$(jq -cn --arg m "$method" --argjson p "$params" --argjson i "$id" \
        '{jsonrpc: "2.0", id: $i, method: $m, params: $p}')
    # `nc -q 1` exits 1s after the remote closes; `-w 5` is total
    # connection timeout. The trailing newline terminates the Electrum
    # JSON-RPC frame.
    printf '%s\n' "$request" | nc -q 1 -w 5 127.0.0.1 "$ELECTRUM_PORT"
}

# Helper: assert a JSON path matches an expected condition.
expect_jq() {
    local body="$1"
    local jq_expr="$2"
    local label="$3"
    if ! jq -e "$jq_expr" <<< "$body" > /dev/null; then
        echo "electrum: jq check failed: $label" >&2
        echo "  body: $body" >&2
        echo "  expr: $jq_expr" >&2
        return 1
    fi
}

# --- server.version handshake ---
# Electrum servers MUST accept v1.4 from clients. Response shape is
# [server_software_version, protocol_version_negotiated].
RESP=$(electrum_call "server.version" '["satd-canary", "1.4"]')
expect_jq "$RESP" '.id == 1' "server.version response id"
expect_jq "$RESP" '.result | type == "array"' "server.version result is array"
expect_jq "$RESP" '.result | length == 2' "server.version result has 2 elements"
expect_jq "$RESP" '.result[0] | type == "string"' "server_software is string"
expect_jq "$RESP" '.result[1] | type == "string"' "protocol_version is string"
echo "ok: server.version handshake"

# --- server.banner — any string return is fine ---
RESP=$(electrum_call "server.banner" '[]')
expect_jq "$RESP" '.result | type == "string"' "banner is string"
echo "ok: server.banner"

# --- blockchain.headers.subscribe — returns {height, hex} of tip ---
# Mine a block first so tip is non-genesis (makes the assertion stronger).
# Deterministic P2WPKH from secret [0x11; 32] — matches the
# DeterministicWallet helper in satd/tests/e2e.rs.
ADDR="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"
sat_cli generatetoaddress 1 "$ADDR" > /dev/null

RESP=$(electrum_call "blockchain.headers.subscribe" '[]')
expect_jq "$RESP" '.result.height >= 1' "tip height >= 1"
expect_jq "$RESP" '.result.hex | test("^[0-9a-f]+$")' "tip header is hex"
expect_jq "$RESP" '.result.hex | length == 160' "header is exactly 80 bytes (160 hex chars)"
echo "ok: blockchain.headers.subscribe"

# --- blockchain.estimatefee — sat/kvB at confirmation target ---
RESP=$(electrum_call "blockchain.estimatefee" '[6]')
# satd's estimatefee never errors; returns -1 if no estimate yet (regtest,
# no fee data). Either a number or -1 is acceptable.
expect_jq "$RESP" '.result | type == "number"' "estimatefee is number"
echo "ok: blockchain.estimatefee"

# --- blockchain.relayfee — min relay rate ---
RESP=$(electrum_call "blockchain.relayfee" '[]')
expect_jq "$RESP" '.result | type == "number"' "relayfee is number"
expect_jq "$RESP" '.result >= 0' "relayfee non-negative"
echo "ok: blockchain.relayfee"

echo "electrum canary: PASS"
