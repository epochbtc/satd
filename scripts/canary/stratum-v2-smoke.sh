#!/bin/bash
# Stratum V2 canary: SRI's Stratum V2 CPU miner (the Stratum V2 Reference
# Implementation's mining_device) mines against satd's Stratum V2 listener on
# regtest, with the server's authority key pinned.
#
# Coverage:
#   - the Noise NX handshake, authenticated against the pinned authority key,
#     and refused when the miner pins a different key
#   - SetupConnection and a standard channel (OpenStandardMiningChannel)
#   - NewMiningJob as a future job, activated by SetNewPrevHash
#   - SubmitSharesStandard judged as a block, and the block connects
#   - block after block: the job for each tip reaches a miner that is
#     submitting continuously (on regtest every share is a block)
#   - the found blocks' coinbase pays the channel's user identity
#
# SRI publishes no image for mining_device; the workflow builds it from the
# pinned sv2-apps tag and passes its path as SRI_MINING_DEVICE.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"
# shellcheck source=stratum-common.sh
source "$SCRIPT_DIR/stratum-common.sh"

require_mining_device
WORK="$(mktemp -d /tmp/satd-canary-stratum-v2.XXXXXX)"
DEVICE_PID=""

cleanup() {
    if [[ -n "$DEVICE_PID" ]]; then kill "$DEVICE_PID" 2>/dev/null || true; fi
    stop_satd
}
trap cleanup EXIT

# shellcheck disable=SC2046 # word splitting is the point
boot_satd "$WORK" 18960 $(stratum_satd_args)
sat_cli generatetoaddress 1 "$STRATUM_PAYOUT_ADDR" >/dev/null
V2="$(stratum_listener v2)"
KEY="$(stratum_authority_base58)"
[[ -n "$KEY" ]] || { echo "satd logged no authority key" >&2; exit 1; }
echo "Stratum V2 listening on $V2, authority key $KEY"

# ── 1. A miner pinning some other key never gets a channel ──
# SRI's own example authority key: valid, and not this server's.
WRONG_KEY="9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
timeout 15 "$SRI_MINING_DEVICE" --address-pool "$V2" --pubkey-pool "$WRONG_KEY" \
    --id-user "$STRATUM_PAYOUT_ADDR" --cores 1 > "$WORK/wrong-key.log" 2>&1 || true
if grep -q "channel opened" "$WORK/wrong-key.log" \
    || ! sat_cli getstratuminfo | jq -e '.channels == 0 and .shares.accepted == 0' >/dev/null; then
    echo "a miner pinning the wrong authority key got work" >&2
    tail -20 "$WORK/wrong-key.log" >&2
    exit 1
fi
echo "ok: a miner pinning another key was refused"

# ── 2. The real key: a standard channel, work, and block after block ──
START_HEIGHT="$(sat_cli getblockcount)"
# Throttled to about two hashes a second. On regtest every other hash is a
# block, and mining_device stamps a job's headers once, a minute ahead of the
# clock; at full speed it mines blocks faster than a second apart, median time
# past overtakes that stamp, and every header after is refused as invalid by
# consensus. Unthrottled, it also queues millions of shares for a job before it
# switches to the next, and sends them all.
"$SRI_MINING_DEVICE" --address-pool "$V2" --pubkey-pool "$KEY" \
    --id-user "$STRATUM_PAYOUT_ADDR" --id-device satd-canary \
    --cores 1 --nonces-per-call 1 --handicap 500000 \
    > "$WORK/mining-device.log" 2>&1 &
DEVICE_PID=$!

wait_stratum '.channels >= 1' 60 "mining_device to open a channel"
echo "ok: mining_device opened a standard channel"
wait_stratum '.blocks_found >= 3' 120 "mining_device to find three blocks"
[[ "$(sat_cli getblockcount)" -ge $((START_HEIGHT + 3)) ]] \
    || { echo "blocks were found but the tip did not move by three" >&2; exit 1; }
assert_last_block_pays_payout
prevhashes="$(grep -c "Received SetNewPrevHash" "$WORK/mining-device.log" || true)"
[[ "$prevhashes" -ge 3 ]] \
    || { echo "mining_device saw only $prevhashes SetNewPrevHash messages" >&2; exit 1; }
sat_cli getstratuminfo | jq -e '.shares.rejected == 0' >/dev/null \
    || { echo "shares were rejected:" >&2; sat_cli getstratuminfo | jq .shares >&2; grep -o 'reason="[a-z-]*"' "$SATD_LOG" | sort | uniq -c >&2; exit 1; }
echo "ok: mining_device found $(sat_cli getstratuminfo | jq .blocks_found) blocks across $prevhashes tips"

echo "stratum v2 canary: PASS"
