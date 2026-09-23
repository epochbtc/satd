#!/bin/bash
# Stratum V2 Job Declaration canary: SRI's Job Declaration client chooses the
# block's transactions and satd, as pool and Job Declaration server on one
# listener, checks and mines them.
#
#   mining_device ──SV2──▶ SRI JD client ──SV2 mining──▶ satd
#                              │        └─Job Declaration─▶ satd
#                              └─IPC templates─▶ Bitcoin Core ◀─P2P─ satd
#
# Coverage:
#   - AllocateMiningJobToken, DeclareMiningJob (with a real transaction in the
#     declared list) and SetCustomMiningJob on an extended channel, as SRI's
#     client sends them
#   - the declared job is mined, the block connects, and it contains the
#     transaction Core's template chose and satd's mempool holds
#   - the coinbase pays the address the token was issued for
#
# Bitcoin Core is peered with satd over P2P, so the two share a chain and a
# mempool: Core mines its wallet's coins and satd syncs them, and a transaction
# Core's wallet sends reaches satd's mempool, where the declaration check
# requires it to be.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"
# shellcheck source=stratum-common.sh
source "$SCRIPT_DIR/stratum-common.sh"

require_mining_device
WORK="$(mktemp -d /tmp/satd-canary-stratum-jd.XXXXXX)"
CORE_CONTAINER="satd-canary-jd-core-$$"
JDC_CONTAINER="satd-canary-jd-client-$$"
CORE_RPC_PORT=18991
JDC_PORT=18992
DEVICE_PID=""
# SRI's published example keys for the JD client's own downstream listener.
JDC_PUBLIC_KEY="9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
JDC_SECRET_KEY="mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"

core_cli() {
    docker exec "$CORE_CONTAINER" bitcoin-cli -regtest -datadir=/data -rpcport="$CORE_RPC_PORT" "$@"
}

cleanup() {
    if [[ -n "$DEVICE_PID" ]]; then kill "$DEVICE_PID" 2>/dev/null || true; fi
    docker logs "$JDC_CONTAINER" > "$WORK/jd-client.log" 2>&1 || true
    docker rm -f "$JDC_CONTAINER" "$CORE_CONTAINER" >/dev/null 2>&1 || true
    stop_satd
}
trap cleanup EXIT

pull_with_retries "$CORE_IMAGE"
pull_with_retries "$SRI_JD_CLIENT_IMAGE"

# shellcheck disable=SC2046 # word splitting is the point
boot_satd "$WORK/satd" 18970 $(stratum_satd_args)
SATD_P2P_PORT=18971
V2="$(stratum_listener v2)"
KEY="$(stratum_authority_base58)"
sat_cli getstratuminfo | jq -e '.job_declaration == true' >/dev/null \
    || { echo "satd is not serving Job Declaration" >&2; exit 1; }
echo "Stratum V2 with Job Declaration on $V2"

# ── Bitcoin Core: peered with satd, serving templates over IPC ──
mkdir -p "$WORK/core"
chmod 777 "$WORK/core"
# `bitcoin -m node` is the multiprocess node, which serves IPC; the image's
# entrypoint would start plain bitcoind. By name, not path: the image's
# install directory carries the version, and moves with every pin bump.
docker run -d --name "$CORE_CONTAINER" --network=host -v "$WORK/core:/data" \
    --entrypoint bitcoin "$CORE_IMAGE" \
    -m node -regtest -datadir=/data -server -ipcbind=unix \
    -connect="127.0.0.1:$SATD_P2P_PORT" -listen=0 -rpcport="$CORE_RPC_PORT" \
    -fallbackfee=0.0001 >/dev/null
deadline=$(($(date +%s) + 60))
until core_cli getblockchaininfo >/dev/null 2>&1; do
    [[ $(date +%s) -lt $deadline ]] || { echo "Core RPC never came up" >&2; docker logs "$CORE_CONTAINER" | tail -20 >&2; exit 1; }
    sleep 1
done
core_cli createwallet canary >/dev/null
CORE_ADDR="$(core_cli getnewaddress)"

# Core mines coins for its wallet, and satd follows its chain.
core_cli generatetoaddress 101 "$CORE_ADDR" >/dev/null
deadline=$(($(date +%s) + 60))
until [[ "$(sat_cli getblockcount)" == "$(core_cli getblockcount)" ]]; do
    [[ $(date +%s) -lt $deadline ]] || { echo "satd did not sync Core's chain" >&2; exit 1; }
    sleep 1
done

# A transaction in both mempools, for the JD client to declare.
TXID="$(core_cli -rpcwallet=canary sendtoaddress "$STRATUM_PAYOUT_ADDR" 1.0)"
deadline=$(($(date +%s) + 60))
until sat_cli getrawmempool | jq -e --arg t "$TXID" 'index($t) != null' >/dev/null; do
    [[ $(date +%s) -lt $deadline ]] || { echo "Core's transaction never reached satd's mempool" >&2; exit 1; }
    sleep 1
done
echo "ok: transaction $TXID is in both mempools"

# ── The JD client ──
cat > "$WORK/jdc-config.toml" <<TOML
listening_address = "127.0.0.1:$JDC_PORT"
max_supported_version = 2
min_supported_version = 2
authority_public_key = "$JDC_PUBLIC_KEY"
authority_secret_key = "$JDC_SECRET_KEY"
cert_validity_sec = 3600
shares_per_minute = 6.0
share_batch_size = 10
mode = "FULLTEMPLATE"
jdc_signature = "satd-canary"
coinbase_reward_script = "addr($STRATUM_PAYOUT_ADDR)"
supported_extensions = []

[[upstreams]]
authority_pubkey = "$KEY"
pool_address = "${V2%:*}"
pool_port = ${V2##*:}
jds_address = "${V2%:*}"
jds_port = ${V2##*:}
user_identity = "$STRATUM_PAYOUT_ADDR"

[template_provider_type.BitcoinCoreIpc]
version = 31
network = "regtest"
data_dir = "/data"
fee_threshold = 0
min_interval = 1
TOML
docker run -d --name "$JDC_CONTAINER" --network=host \
    -v "$WORK/jdc-config.toml:/app/jdc-config.toml:ro" -v "$WORK/core:/data" \
    "$SRI_JD_CLIENT_IMAGE" >/dev/null

# ── A miner behind it ──
# Throttled for the same reasons as in stratum-v2-smoke.sh. The JD client sets
# the device's share target from the hashrate the device advertises, which it
# measures unthrottled; advertising a millionth of it keeps the target within
# reach of the throttled device.
sleep 5
"$SRI_MINING_DEVICE" --address-pool "127.0.0.1:$JDC_PORT" --pubkey-pool "$JDC_PUBLIC_KEY" \
    --id-user "$STRATUM_PAYOUT_ADDR" --cores 1 --nonces-per-call 1 --handicap 500000 \
    --nominal-hashrate-multiplier 0.000001 \
    > "$WORK/mining-device.log" 2>&1 &
DEVICE_PID=$!

# ── The declared transaction is mined through satd ──
deadline=$(($(date +%s) + 180))
MINED=""
while [[ $(date +%s) -lt $deadline ]]; do
    if ! sat_cli getrawmempool | jq -e --arg t "$TXID" 'index($t) != null' >/dev/null; then
        MINED="$(sat_cli getrawtransaction "$TXID" true 2>/dev/null | jq -r '.blockhash // empty' || true)"
        [[ -n "$MINED" ]] && break
    fi
    sleep 2
done
if [[ -z "$MINED" ]]; then
    echo "the declared transaction was not mined" >&2
    sat_cli getstratuminfo >&2 || true
    docker logs "$JDC_CONTAINER" 2>&1 | tail -40 >&2
    grep -i "stratum" "$SATD_LOG" | tail -20 >&2
    exit 1
fi
grep -q "Stratum V2 mining job declared" "$SATD_LOG" \
    || { echo "the block was not mined through a declared job" >&2; exit 1; }
grep -q "Stratum V2 custom mining job set" "$SATD_LOG" \
    || { echo "no custom mining job was set" >&2; exit 1; }
sat_cli getstratuminfo | jq -e '.blocks_found >= 1' >/dev/null \
    || { echo "satd did not count the block" >&2; exit 1; }
PAID="$(sat_cli getblock "$MINED" 2 | jq -r --arg a "$STRATUM_PAYOUT_ADDR" \
    '[.tx[0].vout[] | select(.scriptPubKey.address == $a and .value > 0)] | length')"
[[ "$PAID" -ge 1 ]] || { echo "block $MINED does not pay $STRATUM_PAYOUT_ADDR" >&2; exit 1; }
echo "ok: the declared job's block $MINED mined $TXID and pays $STRATUM_PAYOUT_ADDR"

# ── Bitcoin Core accepts it ──
# The block was built from a coinbase the JD client declared, so Core's
# verdict is the one that matters: a coinbase satd's checks passed and the
# network refuses would be a block lost.
assert_core_accepted "$MINED" core_cli
core_follows_satd 60 core_cli

echo "stratum job declaration canary: PASS"
