#!/usr/bin/env bash
# Launch satd on mainnet with local Bitcoin Core + DNS-seeded external peers.
set -euo pipefail

SATD="$HOME/.local/bin/satd"
DATADIR="/opt/satd-mainnet"
RPCPORT=18880
P2PPORT=18881
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
    --assumevalid=all \
    "${CONNECT_ARGS[@]}"
