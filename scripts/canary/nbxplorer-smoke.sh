#!/bin/bash
# NBXplorer canary — runs the real NBXplorer Docker container against
# a satd regtest backend and verifies it reaches synchronization +
# tracks new blocks.
#
# This is the FIRST canary that exercises a real third-party
# downstream (not just an in-tree library against in-tree code).
# NBXplorer is the indexer underneath BTCPayServer, so green here is a
# strong signal that BTCPay sits cleanly on top of satd's JSON-RPC.
#
# Coverage:
#   GET /v1/cryptos/btc/status     — IsFullySynched, sync height
#   Mine, poll, verify NBXplorer follows
#
# Pin: nicolasdorier/nbxplorer:2.5.21 (Docker Hub tag). Bumping the
# pin is a deliberate maintenance step — pin updates land in a
# follow-up PR after verifying the new image still works.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"

NBXPLORER_IMAGE="nicolasdorier/nbxplorer:2.5.21"
NBXPLORER_CONTAINER="satd-canary-nbxplorer-$$"
NBXPLORER_PORT=18204

# NBXplorer authenticates with rpcuser/rpcpassword (cookie auth would
# require shared filesystem access).
NBX_DATADIR="$(mktemp -d -t satd-canary-nbxplorer.XXXXXX)"
RPCUSER="canary"
RPCPASSWORD="$(head -c 16 /dev/urandom | xxd -p)"

# satd's RPC binds to 127.0.0.1 by default and has no --rpcbind /
# --rpcallowip CLI flags today (a Core-compat gap to be filed as a
# separate follow-up). The workaround for the canary is to run the
# NBXplorer container on the host's network namespace via
# `docker run --network=host`, so 127.0.0.1 inside the container
# resolves to the runner's loopback — which is where satd actually
# binds.
boot_satd "$NBX_DATADIR" 18300 \
    --rpcuser="$RPCUSER" \
    --rpcpassword="$RPCPASSWORD" \
    --txindex \
    --server

# Cleanup of NBXplorer container too — boot-satd.sh's EXIT trap only
# stops satd. Compose a combined trap.
cleanup_nbxplorer() {
    docker rm -f "$NBXPLORER_CONTAINER" >/dev/null 2>&1 || true
}
trap 'cleanup_nbxplorer; stop_satd' EXIT

# Pull the image with 3 retries (network flake mitigation per the
# canary-gating posture in STABILITY_POLICY.md).
for attempt in 1 2 3; do
    if docker pull "$NBXPLORER_IMAGE"; then
        break
    fi
    if [[ $attempt -eq 3 ]]; then
        echo "nbxplorer: docker pull failed 3 times" >&2
        exit 1
    fi
    echo "nbxplorer: docker pull attempt $attempt failed; retrying in ${attempt}s..."
    sleep $((attempt * 2))
done

# Run NBXplorer on the host's network namespace so it can reach satd
# at 127.0.0.1. NBXplorer's regtest support uses
# `NBXPLORER_NETWORK=regtest` + Bitcoin RPC connection settings; with
# --network=host the container's API listens on $NBXPLORER_PORT
# directly on the host (no -p mapping needed).
# `NBXPLORER_NOAUTH=1` disables NBXplorer's own client auth — this is
# a localhost-only canary, the NBXplorer API surface never leaves the
# runner.
docker run -d \
    --name "$NBXPLORER_CONTAINER" \
    --network=host \
    -e "NBXPLORER_NETWORK=regtest" \
    -e "NBXPLORER_BIND=127.0.0.1:$NBXPLORER_PORT" \
    -e "NBXPLORER_CHAINS=btc" \
    -e "NBXPLORER_BTCRPCURL=http://127.0.0.1:$RPC_PORT" \
    -e "NBXPLORER_BTCRPCUSER=$RPCUSER" \
    -e "NBXPLORER_BTCRPCPASSWORD=$RPCPASSWORD" \
    -e "NBXPLORER_BTCNODEENDPOINT=127.0.0.1:$((RPC_PORT + 1))" \
    -e "NBXPLORER_NOAUTH=1" \
    "$NBXPLORER_IMAGE"

# Poll NBXplorer status with a 5-minute budget. Regtest sync of an
# empty chain is fast (~1s) but the container needs ~30-60s to come
# up cold; the budget covers worst-case CI scheduling.
NBX_BASE="http://127.0.0.1:$NBXPLORER_PORT"
deadline=$(($(date +%s) + 300))
echo "Waiting for NBXplorer to come up..."
while [[ $(date +%s) -lt $deadline ]]; do
    if status=$(curl -sf --max-time 10 "$NBX_BASE/v1/cryptos/btc/status"); then
        if jq -e '.bitcoinStatus.headers >= 0' <<< "$status" > /dev/null; then
            echo "NBXplorer is up:"
            jq '.' <<< "$status"
            break
        fi
    fi
    if ! docker ps --format '{{.Names}}' | grep -q "^$NBXPLORER_CONTAINER\$"; then
        echo "nbxplorer: container exited unexpectedly" >&2
        docker logs "$NBXPLORER_CONTAINER" 2>&1 | tail -50 >&2 || true
        exit 1
    fi
    sleep 5
done

if [[ $(date +%s) -ge $deadline ]]; then
    echo "nbxplorer: did not reach ready state within 5 minutes" >&2
    docker logs "$NBXPLORER_CONTAINER" 2>&1 | tail -50 >&2 || true
    exit 1
fi

# Mine 10 blocks and verify NBXplorer follows. IsFullySynched ==
# true and headers == blocks count is the contract.
# Deterministic P2WPKH from secret [0x11; 32].
ADDR="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"
sat_cli generatetoaddress 10 "$ADDR" > /dev/null

deadline=$(($(date +%s) + 60))
while [[ $(date +%s) -lt $deadline ]]; do
    status=$(curl -sf --max-time 10 "$NBX_BASE/v1/cryptos/btc/status")
    if jq -e '.isFullySynched == true and .chainHeight == 10' <<< "$status" > /dev/null; then
        echo "ok: NBXplorer synced to height 10:"
        jq '.' <<< "$status"
        echo "nbxplorer canary: PASS"
        exit 0
    fi
    sleep 3
done

echo "nbxplorer: did not sync to height 10 within 60s after mining" >&2
echo "last status:"
curl -sf --max-time 10 "$NBX_BASE/v1/cryptos/btc/status" | jq '.' || true
echo "satd log tail:"
tail -50 "$SATD_LOG" || true
docker logs "$NBXPLORER_CONTAINER" 2>&1 | tail -50 >&2 || true
exit 1
