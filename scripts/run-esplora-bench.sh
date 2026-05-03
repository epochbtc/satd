#!/usr/bin/env bash
# Esplora REST endpoint micro-benchmark.
#
# Spins up a satd regtest node, mines warmup blocks, then drives a
# fixed number of GET requests against each implemented endpoint. For
# each endpoint emits p50, p90, p99 latency in ms.
#
# Usage:
#   ./scripts/run-esplora-bench.sh                 # default 200 reqs / endpoint
#   ESPLORA_BENCH_REQS=1000 ./scripts/run-esplora-bench.sh
#   ESPLORA_BENCH_BIND=127.0.0.1:9000 ./scripts/run-esplora-bench.sh
#
# Requires: cargo (release build of satd), curl, python3.
#
# This is an operator/ops harness — not a CI gate. Numbers vary
# meaningfully run-to-run depending on system load, dbcache warmth,
# and mempool population. Treat the output as a regression check
# (>2× degradation between runs is suspicious), not an absolute SLA.

set -euo pipefail

REQS="${ESPLORA_BENCH_REQS:-200}"
WARMUP_BLOCKS="${ESPLORA_BENCH_WARMUP:-200}"
BIND="${ESPLORA_BENCH_BIND:-127.0.0.1:0}"
DATADIR="${ESPLORA_BENCH_DATADIR:-$(mktemp -d -t satd-esplora-bench-XXXXXX)}"
SATD_BIN="${ESPLORA_BENCH_SATD:-./target/release/satd}"

# Build release binary if missing.
if [ ! -x "$SATD_BIN" ]; then
    echo "[bench] Building release satd…"
    cargo build --release --bin satd
fi

# Pick a free port if 0 was passed.
HOST="${BIND%:*}"
PORT="${BIND##*:}"
if [ "$PORT" = "0" ]; then
    PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')"
fi
ESPLORA_BIND="${HOST}:${PORT}"

# Random RPC port.
RPC_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')"
P2P_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')"

echo "[bench] Datadir   : $DATADIR"
echo "[bench] Esplora   : http://$ESPLORA_BIND"
echo "[bench] RPC port  : $RPC_PORT"
echo "[bench] P2P port  : $P2P_PORT"

# Start satd in background.
"$SATD_BIN" --regtest \
    --datadir="$DATADIR" \
    --rpcport="$RPC_PORT" \
    --port="$P2P_PORT" \
    --esplora=1 \
    --esplorabind="$ESPLORA_BIND" \
    > "$DATADIR/satd.log" 2>&1 &
SATD_PID=$!
trap 'kill "$SATD_PID" 2>/dev/null || true; wait "$SATD_PID" 2>/dev/null || true' EXIT

# Wait for the listener.
echo -n "[bench] Waiting for esplora listener…"
for _ in $(seq 1 60); do
    if curl -sf "http://$ESPLORA_BIND/blocks/tip/height" >/dev/null 2>&1; then
        echo " ready"
        break
    fi
    echo -n "."
    sleep 0.5
done

# Mine warmup blocks. Use the canonical zero-hash regtest address —
# its scripthash receives every coinbase, so address endpoints have
# rich data to query against.
ADDR="bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202"
COOKIE_PATH="$DATADIR/regtest/.cookie"
echo "[bench] Mining $WARMUP_BLOCKS warmup blocks to $ADDR…"
curl -sf -u "$(cat "$COOKIE_PATH")" --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"bench\",\"method\":\"generatetoaddress\",\"params\":[$WARMUP_BLOCKS, \"$ADDR\"]}" -H 'Content-Type: text/plain;' "http://127.0.0.1:$RPC_PORT/" >/dev/null

# Endpoint list. Each entry is a URL path. The scripthash is computed
# at runtime against the regtest address above so the bench data is
# representative of a real query workload.
SCRIPTHASH="$(python3 - <<EOF
import hashlib, sys
# bcrt1q…dku202 is the all-zeros 20-byte witness program: P2WPKH.
# scriptPubKey: 0x00 0x14 || 20 bytes of zero.
spk = bytes.fromhex("0014" + "00" * 20)
print(hashlib.sha256(spk).hexdigest())
EOF
)"
TIP_HASH="$(curl -sf "http://$ESPLORA_BIND/blocks/tip/hash")"
TIP_HEIGHT="$(curl -sf "http://$ESPLORA_BIND/blocks/tip/height")"
COINBASE_TXID="$(curl -sf "http://$ESPLORA_BIND/block/$TIP_HASH/txids" | python3 -c 'import json, sys; print(json.load(sys.stdin)[0])')"

ENDPOINTS=(
    "/blocks/tip/height"
    "/blocks/tip/hash"
    "/blocks"
    "/block-height/$TIP_HEIGHT"
    "/block/$TIP_HASH"
    "/block/$TIP_HASH/header"
    "/block/$TIP_HASH/status"
    "/block/$TIP_HASH/txids"
    "/block/$TIP_HASH/txs"
    "/tx/$COINBASE_TXID"
    "/tx/$COINBASE_TXID/status"
    "/tx/$COINBASE_TXID/hex"
    "/tx/$COINBASE_TXID/outspend/0"
    "/tx/$COINBASE_TXID/outspends"
    "/tx/$COINBASE_TXID/merkle-proof"
    "/tx/$COINBASE_TXID/merkleblock-proof"
    "/address/$ADDR"
    "/address/$ADDR/txs/chain"
    "/address/$ADDR/utxo"
    "/scripthash/$SCRIPTHASH"
    "/scripthash/$SCRIPTHASH/utxo"
    "/mempool"
    "/mempool/txids"
    "/mempool/recent"
    "/fee-estimates"
    "/"
)

# Compute percentiles via python (portable; awk asort is gawk-only and
# not available in mawk / busybox). Reads numbers (ms) one per line,
# emits p50 p90 p99 space-separated.
percentiles() {
    python3 -c '
import sys
xs = sorted(float(line) for line in sys.stdin if line.strip())
def pick(p):
    if not xs:
        return 0.0
    idx = min(len(xs) - 1, int(round(len(xs) * p / 100.0 + 0.5)) - 1)
    return xs[max(0, idx)]
print(f"{pick(50):.2f} {pick(90):.2f} {pick(99):.2f}")
'
}

printf "\n[bench] Running %d requests per endpoint…\n\n" "$REQS"
printf "%-50s %8s %8s %8s\n" "ENDPOINT" "p50_ms" "p90_ms" "p99_ms"
printf -- "----------------------------------------------------------------------------\n"

for path in "${ENDPOINTS[@]}"; do
    url="http://$ESPLORA_BIND$path"
    # Run the requests, collecting latency in milliseconds.
    samples="$(
        for _ in $(seq 1 "$REQS"); do
            curl -sf -o /dev/null -w '%{time_total}\n' "$url"
        done | python3 -c '
import sys
for line in sys.stdin:
    line = line.strip()
    if line:
        print(f"{float(line)*1000:.3f}")
'
    )"
    read -r p50 p90 p99 < <(echo "$samples" | percentiles)
    printf "%-50s %8s %8s %8s\n" "$path" "$p50" "$p90" "$p99"
done

echo
echo "[bench] Done. Datadir kept at: $DATADIR"
echo "[bench] To clean up: rm -rf $DATADIR"
