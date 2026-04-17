#!/usr/bin/env bash
# Partial-IBD benchmark: fresh sync from genesis to a target height,
# running satd with --consensus=cpp-shadow (Rust authoritative).
#
# Uses a dedicated datadir (/satd/bench-run) and alternate RPC/P2P ports
# so it doesn't collide with the production satd-mainnet service.
#
# Prereq: systemctl --user stop satd-mainnet  (frees CPU/mem/peers)
# Stop the bench: Ctrl+C, or the watcher (`scripts/watch-ibd-bench.sh`)
# kills it once TARGET_HEIGHT is reached.

set -euo pipefail

SATD="$HOME/.local/bin/satd"
DATADIR="/satd/bench-run"
RPCPORT=18890
P2PPORT=18891
MAINNET_P2P_PORT=8333
LOG_FILE="${DATADIR}/satd-bench.log"

DNS_SEEDS=(
    "seed.bitcoin.sipa.be"
    "dnsseed.bluematt.me"
    "seed.bitcoinstats.com"
    "seed.bitcoin.jonasschnelli.ch"
)

CONNECT_ARGS=()

# Always connect to local Bitcoin Core if present.
if ss -tln | grep -q ":${MAINNET_P2P_PORT} "; then
    CONNECT_ARGS+=(--connect "127.0.0.1:${MAINNET_P2P_PORT}")
fi

# DNS-seeded external peers.
for seed in "${DNS_SEEDS[@]}"; do
    mapfile -t PEERS < <(dig +short "$seed" 2>/dev/null | head -10)
    for ip in "${PEERS[@]}"; do
        [[ -n "$ip" ]] && CONNECT_ARGS+=(--connect "${ip}:${MAINNET_P2P_PORT}")
    done
done

mkdir -p "$DATADIR"

echo "Starting IBD benchmark"
echo "  datadir:   $DATADIR"
echo "  rpc port:  $RPCPORT"
echo "  p2p port:  $P2PPORT"
echo "  consensus: cpp-shadow (rust authoritative)"
echo "  peers:     ${#CONNECT_ARGS[@]} addresses"
echo "  log:       $LOG_FILE"

START_EPOCH=$(date +%s)
echo "$START_EPOCH" > "$DATADIR/start_epoch"

exec "$SATD" \
    --datadir="$DATADIR" \
    --rpcport="$RPCPORT" \
    --port="$P2PPORT" \
    --txindex \
    --dbcache=8000 \
    --maxahead=all \
    --consensus=cpp-shadow \
    --shadowworkers=8 \
    --assumevalid=0 \
    "${CONNECT_ARGS[@]}" 2>&1 | tee "$LOG_FILE"
