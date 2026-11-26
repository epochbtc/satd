#!/bin/bash
# rbitcoin-space canary: the explorer's own regtest tooling, unmodified,
# against satd.
#
# rbitcoin-space (github.com/smolcars/rbitcoin-space) is a block explorer
# written for an rbitcoin backend. satd aims to be a drop-in backend for it, so
# this runs the explorer's `dev/regtest/regtest.py` at the tag pinned in PINS:
#
#   scenario  105 blocks at fixed times; P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2A
#             and OP_RETURN outputs; a P2SH + P2A spend; a payment, an RBF
#             pair and a CPFP pair left in the mempool; then the explorer's
#             own checks of the mempool, Esplora address history and Electrum
#             scripthash history
#   rbf, cpfp, mine, send
#   hostile   OP_RETURN text (several OP_RETURN outputs in one transaction),
#             inscriptions and a tagged coinbase
#   tagged    empty blocks built by hand and sent with `submitblock`
#
# regtest.py starts its node with `docker compose`; a stand-in `docker` on
# PATH answers those calls from a satd booted here instead, so the script runs
# exactly as upstream ships it. The explorer server itself is not built: the
# point is the node's answers, which these checks read over RPC, Esplora and
# Electrum the same way the explorer does.
#
# Env overrides: SATD_BIN (the satd to test; default target/release, then
# target/debug), RBITCOIN_SPACE_DIR (an existing checkout at the pinned
# commit, skips the clone).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=PINS
source "$SCRIPT_DIR/PINS"

WORK="$(mktemp -d -t satd-canary-explorer.XXXXXX)"
DATADIR="$WORK/satd"
PORT_BASE=18700
RPC_PORT=$PORT_BASE
P2P_PORT=$((PORT_BASE + 1))
ESPLORA_PORT=$((PORT_BASE + 2))
ELECTRUM_PORT=$((PORT_BASE + 3))

if [[ -n "${SATD_BIN:-}" ]]; then
    :
elif [[ -x "target/release/satd" ]]; then
    SATD_BIN="$PWD/target/release/satd"
elif [[ -x "target/debug/satd" ]]; then
    SATD_BIN="$PWD/target/debug/satd"
else
    echo "explorer canary: no satd binary in target/release or target/debug" >&2
    exit 1
fi

# --- the explorer, at the pinned tag ----------------------------------------
EXPLORER="${RBITCOIN_SPACE_DIR:-$WORK/rbitcoin-space}"
if [[ -z "${RBITCOIN_SPACE_DIR:-}" ]]; then
    git init -q "$EXPLORER"
    git -C "$EXPLORER" fetch -q --depth 1 https://github.com/smolcars/rbitcoin-space.git \
        "refs/tags/$RBITCOIN_SPACE_VERSION:refs/tags/$RBITCOIN_SPACE_VERSION"
    git -C "$EXPLORER" checkout -q "$RBITCOIN_SPACE_VERSION"
fi
got="$(git -C "$EXPLORER" rev-parse HEAD)"
if [[ "$got" != "$RBITCOIN_SPACE_COMMIT" ]]; then
    echo "explorer canary: $RBITCOIN_SPACE_VERSION is $got, PINS says $RBITCOIN_SPACE_COMMIT" >&2
    exit 1
fi
REGTEST_PY="$EXPLORER/dev/regtest/regtest.py"

# --- the stand-in docker ----------------------------------------------------
# regtest.py calls `docker compose -f <file> -p <project> <verb> ...`. Each
# verb maps onto the satd below; anything else fails loudly, so an upstream
# change to how the script drives its node shows up as a red canary rather
# than a silent skip. The container-side ports are rbitcoin's (compose.yml).
mkdir -p "$WORK/bin"
cat > "$WORK/bin/docker" <<'STANDIN'
#!/bin/bash
set -euo pipefail
pidfile="$DROPIN_WORK/satd.pid"
running() { [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; }
start() {
    mkdir -p "$DROPIN_DATADIR"
    "$DROPIN_SATD" --regtest --datadir="$DROPIN_DATADIR" \
        --rpcport="$DROPIN_RPC" --rpcbind="127.0.0.1:$DROPIN_RPC" --rpcallowip=127.0.0.1 \
        --rpcuser=regtest --rpcpassword=regtest \
        --port="$DROPIN_P2P" --listen=0 \
        --txindex=1 --addressindex=1 \
        --esplora=1 --esplorabind="127.0.0.1:$DROPIN_ESPLORA" \
        --electrum=1 --electrumbind="127.0.0.1:$DROPIN_ELECTRUM" \
        --maxtipage=1000000000 \
        >> "$DROPIN_WORK/satd.log" 2>&1 &
    echo $! > "$pidfile"
}
stop() {
    running || return 0
    local pid; pid="$(cat "$pidfile")"
    kill -TERM "$pid"
    for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.5; done
    kill -KILL "$pid" 2>/dev/null || true
}
[[ "${1:-}" == compose ]] || { echo "docker stand-in: only 'compose' is handled: $*" >&2; exit 1; }
shift
while [[ $# -gt 0 && "$1" == -* ]]; do shift 2; done   # -f <file> -p <project>
verb="${1:-}"; shift || true
case "$verb" in
    ps)   running && echo satd || true ;;
    port)
        case "${2:-}" in
            18443) echo "127.0.0.1:$DROPIN_RPC" ;;
            3000)  echo "127.0.0.1:$DROPIN_ESPLORA" ;;
            50001) echo "127.0.0.1:$DROPIN_ELECTRUM" ;;
            *) echo "docker stand-in: unknown port $*" >&2; exit 1 ;;
        esac ;;
    up)   running || start ;;
    stop) stop ;;
    down) stop; rm -rf "$DROPIN_DATADIR" ;;
    logs) tail -40 "$DROPIN_WORK/satd.log" 2>/dev/null || true ;;
    *) echo "docker stand-in: unhandled verb '$verb'" >&2; exit 1 ;;
esac
STANDIN
chmod +x "$WORK/bin/docker"

export DROPIN_WORK="$WORK" DROPIN_DATADIR="$DATADIR" DROPIN_SATD="$SATD_BIN" \
    DROPIN_RPC="$RPC_PORT" DROPIN_P2P="$P2P_PORT" DROPIN_ESPLORA="$ESPLORA_PORT" \
    DROPIN_ELECTRUM="$ELECTRUM_PORT"
export PATH="$WORK/bin:$PATH"
export REGTEST_PROJECT=satd-canary

cleanup() { docker compose stop >/dev/null 2>&1 || true; }
trap cleanup EXIT

run() {
    echo "--- regtest.py $*" >&2
    python3 -I "$REGTEST_PY" "$@"
}

echo "explorer canary: rbitcoin-space $RBITCOIN_SPACE_VERSION ($RBITCOIN_SPACE_COMMIT), satd $SATD_BIN"
run scenario > "$WORK/manifest.json"
python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])); assert m["tip"]["height"]==110, m["tip"]; print("manifest: tip", m["tip"]["height"], "txs", len(m["txs"]))' "$WORK/manifest.json"
run rbf
run cpfp
run mine 1
run send bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw 10000
run hostile
run tagged satd-canary
run tagged satd-canary-sv2 --extranonce 20
run mine 1
echo "explorer canary: PASS"
