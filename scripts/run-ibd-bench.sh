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
DATADIR="${IBD_BENCH_DATADIR:-/satd/bench-run}"
RPCPORT="${IBD_BENCH_RPCPORT:-18890}"
P2PPORT="${IBD_BENCH_P2PPORT:-18891}"
CONSENSUS="${IBD_BENCH_CONSENSUS:-cpp-shadow}"
ASSUMEVALID="${IBD_BENCH_ASSUMEVALID:-0}"
SHADOW_WORKERS="${IBD_BENCH_SHADOW_WORKERS:-8}"
# P2P ports of local peers we should force-connect to. 8333 = Bitcoin Core.
# (The satd-mainnet service at 18881 was tried too, but when it's running its
# own IBD catchup it competes for CPU and skews the bench — skip it.)
LOCAL_PEER_PORTS=(8333)
MAINNET_P2P_PORT=8333
LOG_FILE="${DATADIR}/satd-bench.log"

DNS_SEEDS=(
    "seed.bitcoin.sipa.be"
    "dnsseed.bluematt.me"
    "seed.bitcoinstats.com"
    "seed.bitcoin.jonasschnelli.ch"
)

CONNECT_ARGS=()

# Always connect to local peers (Bitcoin Core + satd-mainnet service) if
# they are listening — LAN-localhost gives the bench maximum download
# throughput and also exercises the synced satd node's inbound-serve path.
for port in "${LOCAL_PEER_PORTS[@]}"; do
    if ss -tln | grep -qE "(:|\.)${port}\b"; then
        CONNECT_ARGS+=(--connect "127.0.0.1:${port}")
    fi
done

# DNS-seeded external peers (real mainnet port).
for seed in "${DNS_SEEDS[@]}"; do
    mapfile -t PEERS < <(dig +short "$seed" 2>/dev/null | head -10)
    for ip in "${PEERS[@]}"; do
        [[ -n "$ip" ]] && CONNECT_ARGS+=(--connect "${ip}:${MAINNET_P2P_PORT}")
    done
done

mkdir -p "$DATADIR"

echo "Starting IBD benchmark"
echo "  datadir:        $DATADIR"
echo "  rpc port:       $RPCPORT"
echo "  p2p port:       $P2PPORT"
echo "  consensus:      $CONSENSUS"
echo "  assumevalid:    $ASSUMEVALID"
echo "  shadow workers: $SHADOW_WORKERS"
echo "  peers:          ${#CONNECT_ARGS[@]} addresses"
echo "  log:            $LOG_FILE"

START_EPOCH=$(date +%s)
echo "$START_EPOCH" > "$DATADIR/start_epoch"

# Optional extra args injected by wrapper scripts (e.g.
# `run-ibd-bench-with-addrindex.sh` adds `--addressindex=0|1`).
EXTRA_ARGS=()
if [[ -n "${IBD_BENCH_EXTRA_ARGS:-}" ]]; then
    # shellcheck disable=SC2206  # intentional word-splitting
    EXTRA_ARGS=( ${IBD_BENCH_EXTRA_ARGS} )
fi

exec "$SATD" \
    --datadir="$DATADIR" \
    --rpcport="$RPCPORT" \
    --port="$P2PPORT" \
    --txindex \
    --dbcache=8000 \
    --maxahead=all \
    --consensus="$CONSENSUS" \
    --shadowworkers="$SHADOW_WORKERS" \
    --assumevalid="$ASSUMEVALID" \
    "${EXTRA_ARGS[@]}" \
    "${CONNECT_ARGS[@]}" 2>&1 | tee "$LOG_FILE"
