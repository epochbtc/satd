#!/bin/bash
# Shared helpers for the Stratum canaries. Source after boot-satd.sh.

# Pins for the miners the Stratum canaries run.
#   cpuminer: the Stratum V1 CPU miner SRI's own integration tests drive, as
#   the prebuilt release of github.com/stratum-mining/cpuminer.
CPUMINER_VERSION=2.5.1
CPUMINER_SHA256=5fc7219fbb72dad32d64f11cd579383e53d8872f95309594fad2a07554a541f7

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

# Stratum V2 Reference Implementation (SRI), github.com/stratum-mining/sv2-apps.
#   mining_device: SRI's Stratum V2 CPU miner, built from source at this tag
#   by the workflow (it has no published image) and passed in as
#   SRI_MINING_DEVICE.
SRI_TAG=v0.7.0
SRI_COMMIT=d7d556d1a3c7e1c26dfccd076b491a38c038a5e0
SRI_JD_CLIENT_IMAGE=stratumv2/jd_client_sv2:v0.7.0@sha256:485853aa8e58bc75c2cef2fb45f537880b047e3b3c4eac352ca8576d07415f2b
# Bitcoin Core, the JD client's template source over IPC.
STRATUM_CORE_IMAGE=bitcoin/bitcoin:31.1@sha256:da25cedc66b1daefff9f412ee196c901a899c3fa68a33b20849c3e08b5c40d63

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
