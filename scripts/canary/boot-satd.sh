#!/bin/bash
# Shared boot helper for the canary CI jobs.
#
# Usage:
#   source scripts/canary/boot-satd.sh
#   boot_satd "<datadir>" "<port_base>" [extra args...]
#   ... canary work ...
#   stop_satd
#
# port_base is the starting port — RPC binds to $port_base, P2P to
# $port_base+1, Esplora to $port_base+2, Electrum to $port_base+3.
# The canaries each pick a different port_base so they could run on
# the same host without colliding (currently they don't — each job
# is a fresh runner).
#
# Cookie auth: written to "$datadir/regtest/.cookie" by satd; readable
# back by `sat-cli --datadir=$datadir --regtest`.

set -euo pipefail

SATD_PID=""
SATD_DATADIR=""
SATD_LOG=""
RPC_PORT=""
ESPLORA_PORT=""
ELECTRUM_PORT=""

boot_satd() {
    SATD_DATADIR="$1"
    local port_base="$2"
    shift 2

    RPC_PORT=$port_base
    local p2p_port=$((port_base + 1))
    ESPLORA_PORT=$((port_base + 2))
    ELECTRUM_PORT=$((port_base + 3))

    mkdir -p "$SATD_DATADIR"
    SATD_LOG="$SATD_DATADIR/satd.log"

    # Find the binary. Prefer release build (CI uses release) but fall
    # back to debug for local-dev use of the same scripts.
    local satd_bin
    if [[ -x "target/release/satd" ]]; then
        satd_bin="target/release/satd"
    elif [[ -x "target/debug/satd" ]]; then
        satd_bin="target/debug/satd"
    else
        echo "boot_satd: no satd binary found in target/release or target/debug" >&2
        return 1
    fi

    "$satd_bin" \
        --regtest \
        --datadir="$SATD_DATADIR" \
        --rpcport="$RPC_PORT" \
        --port="$p2p_port" \
        --esplorabind="127.0.0.1:$ESPLORA_PORT" \
        --electrumbind="127.0.0.1:$ELECTRUM_PORT" \
        "$@" \
        > "$SATD_LOG" 2>&1 &
    SATD_PID=$!

    # Poll until the RPC binds — getblockchaininfo returns 200 once
    # the chainstate is loaded. 60s budget is conservative for regtest
    # (typical ~1s) but covers a slow CI runner under load.
    local deadline=$(($(date +%s) + 60))
    while [[ $(date +%s) -lt $deadline ]]; do
        if sat_cli getblockchaininfo > /dev/null 2>&1; then
            echo "satd ready on rpcport=$RPC_PORT pid=$SATD_PID datadir=$SATD_DATADIR"
            return 0
        fi
        if ! kill -0 "$SATD_PID" 2>/dev/null; then
            echo "boot_satd: satd exited before ready" >&2
            tail -50 "$SATD_LOG" >&2 || true
            return 1
        fi
        sleep 1
    done
    echo "boot_satd: satd did not bind RPC within 60s" >&2
    tail -50 "$SATD_LOG" >&2 || true
    return 1
}

# sat-cli wrapper that authenticates via either cookie (default) or
# basic auth when SATD_RPCUSER / SATD_RPCPASSWORD are exported by the
# caller. Cookie auth is auto-discovered from --datadir; basic auth
# requires the explicit --rpcuser / --rpcpassword pair, otherwise sat-
# cli won't find a cookie (satd doesn't write one when basic-auth
# creds are configured) and every call fails with 401.
sat_cli() {
    local satd_bin_dir
    if [[ -x "target/release/sat-cli" ]]; then
        satd_bin_dir="target/release"
    else
        satd_bin_dir="target/debug"
    fi
    local auth_args=()
    if [[ -n "${SATD_RPCUSER:-}" ]] && [[ -n "${SATD_RPCPASSWORD:-}" ]]; then
        auth_args=(
            --rpcuser="$SATD_RPCUSER"
            --rpcpassword="$SATD_RPCPASSWORD"
        )
    fi
    "$satd_bin_dir/sat-cli" \
        --regtest \
        --datadir="$SATD_DATADIR" \
        --rpcport="$RPC_PORT" \
        "${auth_args[@]}" \
        "$@"
}

stop_satd() {
    if [[ -n "$SATD_PID" ]] && kill -0 "$SATD_PID" 2>/dev/null; then
        kill -TERM "$SATD_PID" 2>/dev/null || true
        # Wait up to 30s for graceful flush. RocksDB shutdown is fast
        # on a regtest dataset, but the harness uses --max-shutdown-secs
        # default which gives the daemon up to a couple of minutes.
        local deadline=$(($(date +%s) + 30))
        while [[ $(date +%s) -lt $deadline ]] && kill -0 "$SATD_PID" 2>/dev/null; do
            sleep 1
        done
        if kill -0 "$SATD_PID" 2>/dev/null; then
            echo "stop_satd: SIGTERM didn't take effect within 30s, escalating to SIGKILL" >&2
            kill -KILL "$SATD_PID" 2>/dev/null || true
        fi
    fi
}

# Always stop on script exit — failure or success.
trap 'stop_satd' EXIT
