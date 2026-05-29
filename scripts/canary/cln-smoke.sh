#!/bin/bash
# Core Lightning (CLN) canary — runs a real CLN node (lightningd) with
# satd as its Bitcoin backend over JSON-RPC, and verifies the Lightning-
# node-on-satd path works.
#
# CLN's `bcli` plugin drives the chain backend purely over Bitcoin Core
# JSON-RPC (no ZMQ), exercising a specific, strict slice of the RPC
# surface that nothing else here covers in the same way:
#   getchaininfo  (→ getblockchaininfo: chain/blocks/headers/ibd shape)
#   getrawblockbyheight (→ getblockhash + getblock verbosity 0 raw hex)
#   getutxout     (→ gettxout: scriptPubKey/amount or null)
#   estimatefees  (→ estimatesmartfee)
#   sendrawtransaction
# A format mismatch in any of these stalls CLN at startup — so a clean
# `getinfo` + funded wallet is a strong "Lightning runs on satd" signal.
#
# Coverage:
#   - CLN starts, its bcli syncs against satd, and `getinfo` reports
#     `blockheight` == satd's tip (proves getchaininfo + getrawblockbyheight).
#   - A CLN wallet address is funded + matured; `listfunds` shows the
#     output (proves getutxout + CLN's block scan over satd RPC).
#
# `--offline` keeps CLN from doing any Lightning P2P (we only test the
# chain backend). Pin: elementsproject/lightningd:v24.11.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"

CLN_IMAGE="elementsproject/lightningd:v24.11"
CLN_CONTAINER="satd-canary-cln-$$"
CLN_DIR="/root/.lightning"

RPCUSER="canary"
RPCPASSWORD="$(head -c 16 /dev/urandom | xxd -p)"
export SATD_RPCUSER="$RPCUSER"
export SATD_RPCPASSWORD="$RPCPASSWORD"

cln() {
    docker exec "$CLN_CONTAINER" lightning-cli --regtest --lightning-dir="$CLN_DIR" "$@"
}

pull_with_retries() {
    local image="$1"
    for attempt in 1 2 3; do
        if docker pull "$image"; then return 0; fi
        if [[ $attempt -eq 3 ]]; then echo "docker pull $image failed 3 times" >&2; return 1; fi
        echo "docker pull $image attempt $attempt failed; retrying in $((attempt * 2))s..."
        sleep $((attempt * 2))
    done
}

cleanup() {
    docker rm -f "$CLN_CONTAINER" >/dev/null 2>&1 || true
    stop_satd
}
trap cleanup EXIT

pull_with_retries "$CLN_IMAGE"

# ── Boot satd (basic-auth RPC; CLN's bcli needs rpcuser/rpcpassword) ──
CLN_DATADIR="$(mktemp -d -t satd-canary-cln.XXXXXX)"
# port_base 19000 → RPC 19000, P2P 19001, Esplora 19002, Electrum 19003.
boot_satd "$CLN_DATADIR" 19000 \
    --rpcuser="$RPCUSER" \
    --rpcpassword="$RPCPASSWORD" \
    --txindex \
    --server

SATD_MINE_ADDR="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"
# A starting chain so CLN's getrawblockbyheight scan has blocks to read.
sat_cli generatetoaddress 10 "$SATD_MINE_ADDR" >/dev/null
echo "satd mined to height $(sat_cli getblockcount)"

# ── Boot CLN, backed by satd's RPC ──
docker run -d --name "$CLN_CONTAINER" --network=host --entrypoint lightningd \
    "$CLN_IMAGE" \
    --regtest --lightning-dir="$CLN_DIR" --offline \
    --bitcoin-rpcconnect=127.0.0.1 --bitcoin-rpcport="$RPC_PORT" \
    --bitcoin-rpcuser="$RPCUSER" --bitcoin-rpcpassword="$RPCPASSWORD" \
    --bitcoin-rpcclienttimeout=60 --log-level=info >/dev/null

# ── 1. CLN syncs against satd and getinfo reports the tip ──
TIP="$(sat_cli getblockcount)"
echo "waiting for CLN to sync against satd (tip $TIP)..."
deadline=$(($(date +%s) + 120))
while [[ $(date +%s) -lt $deadline ]]; do
    if info="$(cln getinfo 2>/dev/null)"; then
        h="$(jq -r '.blockheight // 0' <<<"$info")"
        if [[ "$h" == "$TIP" ]]; then
            echo "ok: CLN synced via satd RPC, blockheight=$h (version $(jq -r '.version' <<<"$info"))"
            break
        fi
    fi
    if ! docker ps --format '{{.Names}}' | grep -q "^$CLN_CONTAINER\$"; then
        echo "cln: container exited unexpectedly" >&2
        docker logs "$CLN_CONTAINER" 2>&1 | tail -40 >&2 || true
        exit 1
    fi
    sleep 2
done
info="$(cln getinfo 2>/dev/null || echo '{}')"
if [[ "$(jq -r '.blockheight // 0' <<<"$info")" != "$TIP" ]]; then
    echo "cln: did not sync to satd tip $TIP" >&2
    jq '{blockheight, warning_bitcoind_sync, warning_lightningd_sync}' <<<"$info" >&2 || true
    docker logs "$CLN_CONTAINER" 2>&1 | tail -50 >&2 || true
    exit 1
fi

# ── 2. Fund a CLN wallet address, mature it, verify listfunds ──
CLN_ADDR="$(cln newaddr bech32 2>/dev/null | jq -r '.bech32 // .address // .p2tr')"
[[ -n "$CLN_ADDR" && "$CLN_ADDR" != "null" ]] || { echo "cln: could not get a wallet address" >&2; exit 1; }
echo "funding CLN address $CLN_ADDR (mine 1, then mature)..."
sat_cli generatetoaddress 1 "$CLN_ADDR" >/dev/null
sat_cli generatetoaddress 110 "$SATD_MINE_ADDR" >/dev/null
NEW_TIP="$(sat_cli getblockcount)"

deadline=$(($(date +%s) + 120))
while [[ $(date +%s) -lt $deadline ]]; do
    funds="$(cln listfunds 2>/dev/null || echo '{}')"
    n="$(jq -r '.outputs | length' <<<"$funds" 2>/dev/null || echo 0)"
    h="$(cln getinfo 2>/dev/null | jq -r '.blockheight // 0')"
    if [[ "$h" == "$NEW_TIP" && "$n" -ge 1 ]]; then
        total="$(jq -r '[.outputs[].amount_msat] | add' <<<"$funds")"
        echo "ok: CLN scanned the funding block over satd RPC and credited its wallet ($n output(s), $total msat)"
        echo "cln canary: PASS"
        exit 0
    fi
    sleep 2
done

echo "cln: wallet did not reflect funds at tip $NEW_TIP" >&2
cln getinfo 2>/dev/null | jq '{blockheight}' >&2 || true
cln listfunds >&2 || true
docker logs "$CLN_CONTAINER" 2>&1 | tail -60 >&2 || true
exit 1
