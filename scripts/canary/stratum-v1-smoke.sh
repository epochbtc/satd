#!/bin/bash
# Stratum V1 canary: a real third-party CPU miner (cpuminer, the one SRI's
# integration tests drive) mines against satd's Stratum V1 server on regtest.
#
# Coverage:
#   - mining.subscribe / mining.authorize with an address.worker username
#   - mining.notify as a real miner reads it: split coinbase, merkle branch,
#     word-swapped prevhash, version, nbits, ntime
#   - mining.submit judged as a share and as a block, and the block connects
#   - the found block's coinbase pays the miner's address
#   - a tip change the miner did not cause reaches it as new work
#
# Speed: satd's V1 share difficulty is at least 1, so cpuminer submits only
# hashes at difficulty 1 (about 2^32 hashes each), even though every such hash
# is a regtest block. On a hosted runner that is about a minute per block, so
# the canary waits for one and allows ten.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"
# shellcheck source=stratum-common.sh
source "$SCRIPT_DIR/stratum-common.sh"

WORK="$(mktemp -d /tmp/satd-canary-stratum-v1.XXXXXX)"
MINERD_PID=""

cleanup() {
    if [[ -n "$MINERD_PID" ]]; then kill "$MINERD_PID" 2>/dev/null || true; fi
    stop_satd
}
trap cleanup EXIT

echo "fetching cpuminer $CPUMINER_VERSION..."
curl -fsSL --retry 3 -o "$WORK/cpuminer.tar.gz" \
    "https://github.com/stratum-mining/cpuminer/releases/download/v${CPUMINER_VERSION}/pooler-cpuminer-${CPUMINER_VERSION}-linux-x86_64.tar.gz"
echo "$CPUMINER_SHA256  $WORK/cpuminer.tar.gz" | sha256sum -c -
tar -xzf "$WORK/cpuminer.tar.gz" -C "$WORK" minerd

# shellcheck disable=SC2046 # word splitting is the point
boot_satd "$WORK" 18950 $(stratum_satd_args)
sat_cli generatetoaddress 1 "$STRATUM_PAYOUT_ADDR" >/dev/null
V1="$(stratum_listener v1)"
echo "Stratum V1 listening on $V1"

"$WORK/minerd" -a sha256d -t "$(nproc)" --no-getwork --retry-pause 1 \
    -o "stratum+tcp://$V1" -u "$STRATUM_PAYOUT_ADDR.canary" -p x \
    > "$WORK/minerd.log" 2>&1 &
MINERD_PID=$!

# ── 1. The miner authorizes and gets work ──
wait_stratum '.connections >= 1 and .channels >= 1' 30 "cpuminer to authorize"
echo "ok: cpuminer authorized"

# ── 2. It finds a block that connects and pays the miner ──
START_HEIGHT="$(sat_cli getblockcount)"
wait_stratum '.blocks_found >= 1' 600 "cpuminer to find a block"
[[ "$(sat_cli getblockcount)" -gt "$START_HEIGHT" ]] || { echo "the found block did not raise the tip" >&2; exit 1; }
assert_last_block_pays_payout
sat_cli getstratuminfo | jq -e '.shares.accepted >= 1 and .shares.rejected == 0' >/dev/null \
    || { echo "unexpected share counters:" >&2; sat_cli getstratuminfo | jq .shares >&2; exit 1; }
grep -q "accepted: 1/1" "$WORK/minerd.log" || { echo "cpuminer did not report an accepted share" >&2; tail -20 "$WORK/minerd.log" >&2; exit 1; }
echo "ok: cpuminer found block $(sat_cli getblockcount) and satd counted it"

# ── 3. A tip it did not mine reaches it as new work ──
restarts="$(grep -c "Stratum requested work restart" "$WORK/minerd.log" || true)"
sat_cli generatetoaddress 1 "$STRATUM_PAYOUT_ADDR" >/dev/null
deadline=$(($(date +%s) + 30))
while [[ $(date +%s) -lt $deadline ]]; do
    now="$(grep -c "Stratum requested work restart" "$WORK/minerd.log" || true)"
    [[ "$now" -gt "$restarts" ]] && break
    sleep 1
done
[[ "$now" -gt "$restarts" ]] || { echo "cpuminer was not sent new work after a tip change" >&2; tail -20 "$WORK/minerd.log" >&2; exit 1; }
echo "ok: a new tip reached cpuminer as new work"

echo "stratum v1 canary: PASS"
