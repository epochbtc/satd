#!/usr/bin/env bash
# Launch satd on mainnet with local Bitcoin Core + DNS-seeded external peers.
set -euo pipefail

# Paths and ports are overridable so this script carries no assumption about
# any particular host's layout: export SATD/DATADIR/RPCPORT/P2PPORT to match
# your own, or drop them in an env file and source it before running.
SATD="${SATD:-$HOME/.local/bin/satd}"
DATADIR="${DATADIR:-$HOME/.satd-mainnet}"
RPCPORT="${RPCPORT:-8332}"
P2PPORT="${P2PPORT:-8333}"
MAINNET_P2P_PORT=8333
DNS_SEEDS=(
    "seed.bitcoin.sipa.be"
    "dnsseed.bluematt.me"
    "seed.bitcoinstats.com"
    "seed.bitcoin.jonasschnelli.ch"
)

CONNECT_ARGS=()

# Always connect to local Bitcoin Core if it's listening
if ss -tln | grep -q ":${MAINNET_P2P_PORT} "; then
    CONNECT_ARGS+=(--connect "127.0.0.1:${MAINNET_P2P_PORT}")
fi

# Resolve DNS seeds
for seed in "${DNS_SEEDS[@]}"; do
    mapfile -t PEERS < <(dig +short "$seed" 2>/dev/null | head -10)
    for ip in "${PEERS[@]}"; do
        [[ -n "$ip" ]] && CONNECT_ARGS+=(--connect "${ip}:${MAINNET_P2P_PORT}")
    done
done

echo "Starting satd mainnet sync with ${#CONNECT_ARGS[@]} peer addresses"

exec "$SATD" \
    --datadir="$DATADIR" \
    --rpcport="$RPCPORT" \
    --port="$P2PPORT" \
    --txindex \
    --addressindex=1 \
    --esplora=0 \
    --electrum=0 \
    --dbcache=8000 \
    --maxahead=all \
    --consensus=cpp-shadow \
    --shadowworkers=8 \
    --assumevalid=0 \
    "${CONNECT_ARGS[@]}"
