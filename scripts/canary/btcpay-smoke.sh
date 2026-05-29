#!/bin/bash
# BTCPayServer canary — boots the full BTCPay stack (satd + NBXplorer +
# Postgres + BTCPayServer) and verifies BTCPay comes up healthy and
# reports its BTC chain synchronized against a satd backend.
#
# This sits one layer above the NBXplorer canary: BTCPayServer uses
# NBXplorer as its indexer, which in turn talks to satd over JSON-RPC
# and P2P. Green here means the whole self-custody-merchant stack runs
# on satd unmodified — the headline "drop-in Bitcoin Core replacement"
# claim, end to end.
#
# Contract:
#   GET /api/v1/health        -> 200, {"synchronized": true}
# `/api/v1/health` is unauthenticated and reflects whether BTCPay's
# NBXplorer-backed BTC chain is fully synced, so it exercises the full
# satd -> NBXplorer -> BTCPay path without needing an API key.
#
# Pins: btcpayserver/btcpayserver:2.3.9, nicolasdorier/nbxplorer:2.5.21,
# postgres:16-alpine. Pin bumps are deliberate maintenance steps in a
# follow-up PR after verifying the new images still work.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"

NBXPLORER_IMAGE="nicolasdorier/nbxplorer:2.5.21"
BTCPAY_IMAGE="btcpayserver/btcpayserver:2.3.9"
POSTGRES_IMAGE="postgres:16-alpine"

SUFFIX="$$"
PG_CONTAINER="satd-canary-btcpay-pg-$SUFFIX"
NBX_CONTAINER="satd-canary-btcpay-nbx-$SUFFIX"
BTCPAY_CONTAINER="satd-canary-btcpay-$SUFFIX"

PG_PORT=18705
NBX_PORT=18704
BTCPAY_PORT=18703

POSTGRES_PASSWORD="$(head -c 16 /dev/urandom | xxd -p)"
RPCUSER="canary"
RPCPASSWORD="$(head -c 16 /dev/urandom | xxd -p)"
BTCPAY_DATADIR="$(mktemp -d -t satd-canary-btcpay.XXXXXX)"

# Export for boot-satd.sh's sat_cli helper (basic-auth path).
export SATD_RPCUSER="$RPCUSER"
export SATD_RPCPASSWORD="$RPCPASSWORD"

# satd binds RPC to 127.0.0.1 with no CLI rpcbind/rpcallowip flags, so
# every container runs on the host network namespace (see the NBXplorer
# canary for the rationale).
boot_satd "$BTCPAY_DATADIR" 18800 \
    --rpcuser="$RPCUSER" \
    --rpcpassword="$RPCPASSWORD" \
    --txindex \
    --server

cleanup_containers() {
    docker rm -f "$BTCPAY_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$NBX_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
}
trap 'cleanup_containers; stop_satd' EXIT

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
        echo "docker pull $image attempt $attempt failed; retrying in $((attempt * 2))s..."
        sleep $((attempt * 2))
    done
}

pull_with_retries "$POSTGRES_IMAGE"
pull_with_retries "$NBXPLORER_IMAGE"
pull_with_retries "$BTCPAY_IMAGE"

# --- Postgres (one instance, separate DBs for NBXplorer and BTCPay) ---
docker run -d \
    --name "$PG_CONTAINER" \
    --network=host \
    -e "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" \
    -e "POSTGRES_DB=nbxplorer" \
    -e "PGPORT=$PG_PORT" \
    "$POSTGRES_IMAGE"

echo "Waiting for Postgres to accept connections..."
pg_deadline=$(($(date +%s) + 60))
while [[ $(date +%s) -lt $pg_deadline ]]; do
    if docker exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -p "$PG_PORT" >/dev/null 2>&1; then
        echo "Postgres is ready."
        break
    fi
    if ! docker ps --format '{{.Names}}' | grep -q "^$PG_CONTAINER\$"; then
        echo "postgres: container exited unexpectedly" >&2
        docker logs "$PG_CONTAINER" 2>&1 | tail -30 >&2 || true
        exit 1
    fi
    sleep 2
done
# BTCPay uses its own database in the same Postgres server.
docker exec "$PG_CONTAINER" psql -U postgres -h 127.0.0.1 -p "$PG_PORT" -c "CREATE DATABASE btcpay;" >/dev/null 2>&1 || true

# --- NBXplorer (NOWARMUP: satd is keyless, see nbxplorer-smoke.sh) ---
docker run -d \
    --name "$NBX_CONTAINER" \
    --network=host \
    -e "NBXPLORER_NETWORK=regtest" \
    -e "NBXPLORER_BIND=127.0.0.1:$NBX_PORT" \
    -e "NBXPLORER_CHAINS=btc" \
    -e "NBXPLORER_BTCRPCURL=http://127.0.0.1:$RPC_PORT" \
    -e "NBXPLORER_BTCRPCUSER=$RPCUSER" \
    -e "NBXPLORER_BTCRPCPASSWORD=$RPCPASSWORD" \
    -e "NBXPLORER_BTCNODEENDPOINT=127.0.0.1:$((RPC_PORT + 1))" \
    -e "NBXPLORER_POSTGRES=Host=127.0.0.1;Port=$PG_PORT;Database=nbxplorer;Username=postgres;Password=$POSTGRES_PASSWORD" \
    -e "NBXPLORER_NOAUTH=1" \
    -e "NBXPLORER_NOWARMUP=1" \
    "$NBXPLORER_IMAGE"

NBX_BASE="http://127.0.0.1:$NBX_PORT"
echo "Waiting for NBXplorer to come up..."
deadline=$(($(date +%s) + 300))
while [[ $(date +%s) -lt $deadline ]]; do
    if curl -sf --max-time 10 "$NBX_BASE/v1/cryptos/btc/status" >/dev/null 2>&1; then
        echo "NBXplorer is up."
        break
    fi
    if ! docker ps --format '{{.Names}}' | grep -q "^$NBX_CONTAINER\$"; then
        echo "nbxplorer: container exited unexpectedly" >&2
        docker logs "$NBX_CONTAINER" 2>&1 | tail -60 >&2 || true
        exit 1
    fi
    sleep 5
done

# Mine 10 blocks so the chain is past genesis before BTCPay starts
# (BTCPay/NBXplorer are happier with a non-trivial chain, and this
# mirrors the NBXplorer canary). Deterministic P2WPKH from [0x11; 32].
ADDR="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"
sat_cli generatetoaddress 10 "$ADDR" >/dev/null

# --- BTCPayServer ---
# BTCPay talks to NBXplorer (not satd directly). NBXplorer runs with
# NOAUTH, so no explorer cookie is needed. Lightning is left
# unconfigured (on-chain only).
docker run -d \
    --name "$BTCPAY_CONTAINER" \
    --network=host \
    -e "BTCPAY_NETWORK=regtest" \
    -e "BTCPAY_BIND=127.0.0.1:$BTCPAY_PORT" \
    -e "BTCPAY_ROOTPATH=/" \
    -e "BTCPAY_CHAINS=btc" \
    -e "BTCPAY_BTCEXPLORERURL=$NBX_BASE/" \
    -e "BTCPAY_POSTGRES=Host=127.0.0.1;Port=$PG_PORT;Database=btcpay;Username=postgres;Password=$POSTGRES_PASSWORD" \
    -e "BTCPAY_EXPLORERPOSTGRES=Host=127.0.0.1;Port=$PG_PORT;Database=nbxplorer;Username=postgres;Password=$POSTGRES_PASSWORD" \
    "$BTCPAY_IMAGE"

BTCPAY_BASE="http://127.0.0.1:$BTCPAY_PORT"
echo "Waiting for BTCPayServer to report healthy + synchronized (up to 6 min)..."
deadline=$(($(date +%s) + 360))
while [[ $(date +%s) -lt $deadline ]]; do
    if health=$(curl -sf --max-time 10 "$BTCPAY_BASE/api/v1/health" 2>/dev/null); then
        if jq -e '.synchronized == true' <<< "$health" > /dev/null 2>&1; then
            echo "ok: BTCPayServer healthy + synchronized on satd backend:"
            jq '.' <<< "$health"
            echo "btcpay canary: PASS"
            exit 0
        fi
        echo "  BTCPay health: $health (waiting for synchronized)"
    fi
    if ! docker ps --format '{{.Names}}' | grep -q "^$BTCPAY_CONTAINER\$"; then
        echo "btcpay: container exited unexpectedly" >&2
        docker logs "$BTCPAY_CONTAINER" 2>&1 | tail -80 >&2 || true
        exit 1
    fi
    sleep 5
done

echo "btcpay: did not reach healthy+synchronized within 6 minutes" >&2
echo "--- BTCPay logs ---" >&2
docker logs "$BTCPAY_CONTAINER" 2>&1 | tail -80 >&2 || true
echo "--- NBXplorer status ---" >&2
curl -sf --max-time 10 "$NBX_BASE/v1/cryptos/btc/status" | jq '.' >&2 || true
echo "--- satd log tail ---" >&2
tail -50 "$SATD_LOG" >&2 || true
exit 1
