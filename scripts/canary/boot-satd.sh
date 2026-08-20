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

# SATD_CANARY_FEATURES=on additionally enables satd's 0.5.0 opt-in surfaces
# (silent-payment index, events gRPC, streaming WebSocket, alert webhooks) on
# every node this helper boots. The point is to prove the downstream clients
# are unaffected by turning them on, so the profile is fixed here rather than
# passed per job: "0.5.0 features enabled" has to mean one definite thing for
# a green run to be evidence of anything. Default is off, which reproduces the
# stock defaults byte for byte.

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

    # The 0.5.0 opt-in surfaces, when this run is exercising them. Only
    # options no canary already passes appear here: clap rejects a repeated
    # value flag, so a profile that overlapped a job's own arguments would
    # fail to boot rather than run with both.
    #
    # The two streaming listeners bind port 0 on purpose. Nothing connects to
    # them; what is under test is whether a node that is indexing tweaks,
    # publishing to two carriers and dispatching webhooks still serves Esplora,
    # Electrum, RPC and P2P exactly as a stock node does.
    local feature_args=()
    if [[ "${SATD_CANARY_FEATURES:-off}" == "on" ]]; then
        local alertfile="$SATD_DATADIR/alerts.toml"
        cat > "$alertfile" <<'ALERTS'
version = 1

[[webhook]]
id = "canary"
# Discard port: the dispatcher runs, signs and attempts delivery, and every
# attempt fails fast. A node whose alerting is wedged still has to serve.
url = "http://127.0.0.1:9/canary"
secret = "canary-canary-canary-canary-canary-canary"
categories = ["chain", "status"]
ALERTS
        chmod 600 "$alertfile"
        feature_args=(
            --silentpaymentindex=1
            --events-grpc-bind=127.0.0.1:0
            --streamws=127.0.0.1:0
            --alertfile="$alertfile"
        )
        echo "boot_satd: 0.5.0 feature profile ON: ${feature_args[*]}"
    fi

    "$satd_bin" \
        --regtest \
        --datadir="$SATD_DATADIR" \
        --rpcport="$RPC_PORT" \
        --port="$p2p_port" \
        --esplorabind="127.0.0.1:$ESPLORA_PORT" \
        --electrumbind="127.0.0.1:$ELECTRUM_PORT" \
        ${feature_args[@]+"${feature_args[@]}"} \
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
