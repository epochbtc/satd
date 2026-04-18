#!/usr/bin/env bash
# Watch the IBD benchmark, print checkpoint timings, and stop it once
# the target height is reached.
#
# Usage: scripts/watch-ibd-bench.sh [TARGET_HEIGHT]    (default 500000)

set -euo pipefail

TARGET_HEIGHT="${1:-500000}"
DATADIR="${IBD_BENCH_DATADIR:-/satd/bench-run}"
RPCPORT="${IBD_BENCH_RPCPORT:-18890}"
COOKIE_PATH="$DATADIR/.cookie"

# Wait for cookie
while [[ ! -f "$COOKIE_PATH" ]]; do
    sleep 2
done

START_EPOCH=$(cat "$DATADIR/start_epoch" 2>/dev/null || date +%s)

declare -A CHECKPOINT_TIMES=(
    [100000]=0 [200000]=0 [300000]=0 [400000]=0 [500000]=0
    [600000]=0 [700000]=0 [800000]=0 [900000]=0
)

get_height() {
    local cookie
    cookie=$(cat "$COOKIE_PATH" 2>/dev/null)
    [[ -z "$cookie" ]] && echo 0 && return
    curl -s --user "$cookie" -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
        "http://127.0.0.1:${RPCPORT}/" 2>/dev/null \
        | python3 -c "import json,sys; r=json.load(sys.stdin).get('result',{}); print(r.get('blocks',0))" 2>/dev/null \
        || echo 0
}

echo "Watching bench-run, target height $TARGET_HEIGHT"
echo "Start epoch: $START_EPOCH ($(date -d @"$START_EPOCH"))"

while true; do
    H=$(get_height)
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_EPOCH))

    # Record milestones
    for CP in 100000 200000 300000 400000 500000 600000 700000 800000 900000; do
        if [[ $H -ge $CP && ${CHECKPOINT_TIMES[$CP]} -eq 0 ]]; then
            CHECKPOINT_TIMES[$CP]=$ELAPSED
            RATE=$(awk -v h="$CP" -v e="$ELAPSED" 'BEGIN{if(e>0) print int(h/e); else print 0}')
            echo "[$(date +%H:%M:%S)] CHECKPOINT h=$CP elapsed=${ELAPSED}s rate=${RATE} blk/s"
        fi
    done

    # Done?
    if [[ $H -ge $TARGET_HEIGHT ]]; then
        echo "[$(date +%H:%M:%S)] REACHED target height $TARGET_HEIGHT at $H (elapsed ${ELAPSED}s)"
        echo "Stopping satd…"
        pkill -TERM -f "satd.*$DATADIR" || true
        sleep 3
        echo "=== Summary ==="
        for CP in 100000 200000 300000 400000 500000 600000 700000 800000 900000; do
            T=${CHECKPOINT_TIMES[$CP]}
            if [[ $T -gt 0 ]]; then
                RATE=$(awk -v h="$CP" -v t="$T" 'BEGIN{print int(h/t)}')
                printf "  h=%7d  elapsed=%6ds  rate=%4d blk/s\n" "$CP" "$T" "$RATE"
            fi
        done
        exit 0
    fi

    if (( NOW % 30 == 0 )); then
        echo "[$(date +%H:%M:%S)] h=$H elapsed=${ELAPSED}s"
    fi
    sleep 10
done
