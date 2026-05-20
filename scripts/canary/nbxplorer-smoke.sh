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

# NBXplorer 2.5+ requires PostgreSQL (the SQLite mode was removed
# upstream). We boot a throwaway postgres alongside the NBXplorer
# container; both share the host's network namespace so they reach
# each other via 127.0.0.1.
POSTGRES_IMAGE="postgres:16-alpine"
POSTGRES_CONTAINER="satd-canary-nbxplorer-pg-$$"
POSTGRES_PORT=18205
POSTGRES_PASSWORD="$(head -c 16 /dev/urandom | xxd -p)"

# NBXplorer authenticates with rpcuser/rpcpassword (cookie auth would
# require shared filesystem access).
NBX_DATADIR="$(mktemp -d -t satd-canary-nbxplorer.XXXXXX)"
RPCUSER="canary"
RPCPASSWORD="$(head -c 16 /dev/urandom | xxd -p)"

# Export for boot-satd.sh's sat_cli helper. Without these, sat-cli
# falls back to cookie discovery from $SATD_DATADIR — but satd does
# not write a cookie when rpcuser/rpcpassword are configured, so the
# readiness probe would hang the full 60s budget on 401.
export SATD_RPCUSER="$RPCUSER"
export SATD_RPCPASSWORD="$RPCPASSWORD"

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

# Cleanup of Postgres + NBXplorer containers — boot-satd.sh's EXIT
# trap only stops satd. Compose a combined trap.
cleanup_containers() {
    docker rm -f "$NBXPLORER_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$POSTGRES_CONTAINER" >/dev/null 2>&1 || true
}
trap 'cleanup_containers; stop_satd' EXIT

# Helper: docker-pull with 3 retries.
pull_with_retries() {
    local image="$1"
    for attempt in 1 2 3; do
        if docker pull "$image"; then
            return 0
        fi
        if [[ $attempt -eq 3 ]]; then
            echo "docker pull $image failed 3 times" >&2
            return 1
        fi
        echo "docker pull $image attempt $attempt failed; retrying in ${attempt}s..."
        sleep $((attempt * 2))
    done
}

pull_with_retries "$POSTGRES_IMAGE"
pull_with_retries "$NBXPLORER_IMAGE"

# Boot Postgres. NBXplorer connects over TCP rather than via the
# socket since --network=host means all containers share the host
# loopback. Use a non-default port (18205) so we don't fight with a
# real postgres install on a dev machine.
docker run -d \
    --name "$POSTGRES_CONTAINER" \
    --network=host \
    -e "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" \
    -e "POSTGRES_DB=nbxplorer" \
    -e "PGPORT=$POSTGRES_PORT" \
    "$POSTGRES_IMAGE"

# Wait for Postgres to accept connections. Alpine postgres takes
# ~5-10s cold to initdb. Use docker exec rather than pg_isready on
# the host because the host runner may not have a postgres client.
echo "Waiting for Postgres to accept connections..."
pg_deadline=$(($(date +%s) + 60))
while [[ $(date +%s) -lt $pg_deadline ]]; do
    if docker exec "$POSTGRES_CONTAINER" pg_isready -h 127.0.0.1 -p "$POSTGRES_PORT" >/dev/null 2>&1; then
        echo "Postgres is ready."
        break
    fi
    if ! docker ps --format '{{.Names}}' | grep -q "^$POSTGRES_CONTAINER\$"; then
        echo "postgres: container exited unexpectedly" >&2
        docker logs "$POSTGRES_CONTAINER" 2>&1 | tail -30 >&2 || true
        exit 1
    fi
    sleep 2
done

# Run NBXplorer on the host's network namespace so it can reach
# satd at 127.0.0.1 and Postgres at 127.0.0.1:$POSTGRES_PORT.
# `NBXPLORER_NOAUTH=1` disables NBXplorer's own client auth — this is
# a localhost-only canary, the NBXplorer API surface never leaves
# the runner.
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
    -e "NBXPLORER_POSTGRES=Host=127.0.0.1;Port=$POSTGRES_PORT;Database=nbxplorer;Username=postgres;Password=$POSTGRES_PASSWORD" \
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
        docker logs "$NBXPLORER_CONTAINER" 2>&1 | tail -80 >&2 || true
        echo "--- postgres logs ---" >&2
        docker logs "$POSTGRES_CONTAINER" 2>&1 | tail -20 >&2 || true
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
