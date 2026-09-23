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
#   - Bitcoin Core, peered over P2P, accepts every block the miner found and
#     decodes its coinbase as paying the miner
#   - a full block: Core's wallet fills the mempool past a block's capacity,
#     and the next block found through Stratum is full and Core accepts it
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
    stop_core_peer
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
V1="$(stratum_listener v1)"
echo "Stratum V1 listening on $V1"

# Bitcoin Core, peered with satd, mines coins for its wallet: the chain the
# miner builds on, and the funds that fill the mempool in step 4.
start_core_peer "satd-canary-stratum-v1-core-$$" 18955 18951
core_peer_cli createwallet canary >/dev/null
CORE_ADDR="$(core_peer_cli getnewaddress)"
core_peer_cli generatetoaddress 250 "$CORE_ADDR" >/dev/null
deadline=$(($(date +%s) + 60))
until [[ "$(sat_cli getblockcount)" == "$(core_peer_cli getblockcount)" ]]; do
    [[ $(date +%s) -lt $deadline ]] || { echo "satd did not sync Core's chain" >&2; exit 1; }
    sleep 1
done

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

# ── 3. Bitcoin Core accepts what the miner found ──
assert_core_accepted_all_found

# ── 4. A full block ──
# Core's wallet sends 150 transactions of 250 outputs each (about 34,000 WU
# apiece, 5 MWU in all), which satd receives over P2P: more than a block.
echo "filling the mempool from Core's wallet..."
docker exec "$CORE_PEER_CONTAINER" sh -c '
    cli() { bitcoin-cli -regtest -rpcport='"$CORE_PEER_RPC_PORT"' -rpcuser='"$CORE_PEER_RPCUSER"' -rpcpassword='"$CORE_PEER_RPCPASSWORD"' -rpcwallet=canary "$@"; }
    outs="{"
    for i in $(seq 1 250); do outs="$outs\"$(cli getnewaddress)\":0.001,"; done
    outs="${outs%,}}"
    for i in $(seq 1 150); do cli sendmany "" "$outs" >/dev/null || exit 1; done
'
deadline=$(($(date +%s) + 120))
until [[ "$(sat_cli getmempoolinfo | jq .size)" -ge 150 ]]; do
    [[ $(date +%s) -lt $deadline ]] || { echo "Core's transactions did not reach satd's mempool ($(sat_cli getmempoolinfo | jq .size) of 150)" >&2; exit 1; }
    sleep 1
done
echo "ok: satd's mempool holds $(sat_cli getmempoolinfo | jq .size) transactions, $(sat_cli getmempoolinfo | jq .bytes) bytes"
# A new tip that leaves the mempool alone, so the next job is built from it.
sat_cli generateblock "$STRATUM_PAYOUT_ADDR" '[]' >/dev/null
FILLED_AT="$(sat_cli getblockcount)"
found_before="$(stratum_found_hashes | wc -l)"
deadline=$(($(date +%s) + 600))
FULL=""
while [[ $(date +%s) -lt $deadline ]]; do
    while read -r hash; do
        h="$(sat_cli getblockheader "$hash" | jq .height)"
        if [[ "$h" -gt "$FILLED_AT" ]]; then FULL="$hash"; break; fi
    done < <(stratum_found_hashes | tail -n +"$((found_before + 1))")
    [[ -n "$FULL" ]] && break
    sleep 2
done
[[ -n "$FULL" ]] || { echo "cpuminer found no block on the filled mempool" >&2; exit 1; }
weight="$(sat_cli getblock "$FULL" | jq .weight)"
txs="$(sat_cli getblock "$FULL" | jq '.tx | length')"
[[ "$weight" -gt 3900000 ]] || { echo "block $FULL on a full mempool weighs only $weight WU ($txs txs)" >&2; exit 1; }
echo "ok: cpuminer found full block $FULL: $weight WU, $txs transactions"
assert_core_accepted "$FULL"
core_follows_satd 60

echo "stratum v1 canary: PASS"
