#!/bin/bash
# Shared helpers for the Stratum canaries. Source after boot-satd.sh.

# The miners the Stratum canaries run (cpuminer, SRI's JD client and the
# sv2-apps tag mining_device is built from) are pinned in PINS.
# shellcheck source=PINS
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/PINS"

# A valid regtest P2WPKH the miners are paid to (secret [0x11; 32]); shared
# with the other canaries.
STRATUM_PAYOUT_ADDR="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"

# The satd flags that turn the Stratum server on, unless the fleet's feature
# profile already did (clap refuses a repeated flag). Either way the listeners
# bind port 0 and are read back from getstratuminfo.
stratum_satd_args() {
    if [[ "${SATD_CANARY_FEATURES:-off}" != "on" ]]; then
        echo --stratum=1 --stratumbind=127.0.0.1:0 --stratumv2bind=127.0.0.1:0 --stratumv2jd=1
    fi
}

# The bound address of a listener: v1, v1_tls or v2.
stratum_listener() {
    sat_cli getstratuminfo | jq -er --arg l "$1" '.listeners[$l]'
}

# The authority key in the base58check form Stratum V2 clients are configured
# with, as satd logs it at startup.
stratum_authority_base58() {
    grep -o 'authority_pubkey_base58=[1-9A-HJ-NP-Za-km-z]*' "$SATD_LOG" | head -1 | cut -d= -f2
}

# Poll `getstratuminfo` until the jq filter holds, or fail after $2 seconds.
wait_stratum() {
    local filter="$1" budget="$2" what="$3"
    local deadline=$(($(date +%s) + budget))
    while [[ $(date +%s) -lt $deadline ]]; do
        if sat_cli getstratuminfo | jq -e "$filter" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    echo "timed out after ${budget}s waiting for: $what" >&2
    sat_cli getstratuminfo >&2 || true
    return 1
}

# Assert the last block found through the server pays STRATUM_PAYOUT_ADDR.
assert_last_block_pays_payout() {
    local hash
    hash="$(sat_cli getstratuminfo | jq -er '.last_block.hash')"
    local paid
    paid="$(sat_cli getblock "$hash" 2 | jq -r --arg a "$STRATUM_PAYOUT_ADDR" \
        '[.tx[0].vout[] | select(.scriptPubKey.address == $a and .value > 0)] | length')"
    if [[ "$paid" -lt 1 ]]; then
        echo "block $hash does not pay $STRATUM_PAYOUT_ADDR:" >&2
        sat_cli getblock "$hash" 2 | jq '.tx[0].vout' >&2
        return 1
    fi
    echo "ok: block $hash pays $STRATUM_PAYOUT_ADDR"
}

pull_with_retries() {
    local image="$1"
    for attempt in 1 2 3; do
        if docker pull "$image"; then return 0; fi
        if [[ $attempt -eq 3 ]]; then echo "docker pull $image failed 3 times" >&2; return 1; fi
        sleep $((attempt * 2))
    done
}

require_mining_device() {
    if [[ -z "${SRI_MINING_DEVICE:-}" || ! -x "$SRI_MINING_DEVICE" ]]; then
        echo "SRI_MINING_DEVICE must name SRI's mining_device binary (sv2-apps $SRI_TAG, integration-tests)" >&2
        return 1
    fi
}
