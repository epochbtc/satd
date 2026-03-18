#!/usr/bin/env bash
# Launch satd on signet with local Bitcoin Core + DNS-seeded external peers.
# Used by the satd-signet systemd unit.

set -euo pipefail

SATD="/home/bk/devel/epoch/satd/target/release/satd"
DATADIR="/home/bk/.satd"
RPCPORT=38342
P2PPORT=38343
SIGNET_DNS_SEED="seed.signet.bitcoin.sprovoost.nl"
SIGNET_P2P_PORT=38333

CONNECT_ARGS=()

# Always connect to local Bitcoin Core if it's listening
if ss -tln | grep -q ":${SIGNET_P2P_PORT} "; then
    CONNECT_ARGS+=(--connect "127.0.0.1:${SIGNET_P2P_PORT}")
fi

# Resolve DNS seed and add up to 8 external peers
mapfile -t PEERS < <(dig +short "$SIGNET_DNS_SEED" 2>/dev/null | head -8)
for ip in "${PEERS[@]}"; do
    [[ -n "$ip" ]] && CONNECT_ARGS+=(--connect "${ip}:${SIGNET_P2P_PORT}")
done

if [[ ${#CONNECT_ARGS[@]} -eq 0 ]]; then
    echo "WARNING: no peers found (no local Core, DNS resolution failed)" >&2
fi

exec "$SATD" \
    --signet \
    --datadir="$DATADIR" \
    --rpcport="$RPCPORT" \
    --port="$P2PPORT" \
    "${CONNECT_ARGS[@]}"
