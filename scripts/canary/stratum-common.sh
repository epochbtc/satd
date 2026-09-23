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

# ── A Bitcoin Core peer, the judge of every block the Stratum server finds ──
#
# A block satd accepts is only worth anything if the network accepts it too.
# The canaries peer a Bitcoin Core node (CORE_IMAGE in PINS) with satd over
# P2P and require every Stratum-found block to be on Core's active chain.

CORE_PEER_CONTAINER=""
CORE_PEER_RPC_PORT=""
CORE_PEER_RPCUSER="canary"
CORE_PEER_RPCPASSWORD="canary"

core_peer_cli() {
    docker exec "$CORE_PEER_CONTAINER" bitcoin-cli -regtest -rpcport="$CORE_PEER_RPC_PORT" \
        -rpcuser="$CORE_PEER_RPCUSER" -rpcpassword="$CORE_PEER_RPCPASSWORD" "$@"
}

# start_core_peer <container name> <rpc port> <satd p2p port>
start_core_peer() {
    CORE_PEER_CONTAINER="$1"
    CORE_PEER_RPC_PORT="$2"
    pull_with_retries "$CORE_IMAGE"
    docker run -d --name "$CORE_PEER_CONTAINER" --network=host "$CORE_IMAGE" \
        -regtest -server -listen=0 -connect="127.0.0.1:$3" -rpcport="$CORE_PEER_RPC_PORT" \
        -rpcuser="$CORE_PEER_RPCUSER" -rpcpassword="$CORE_PEER_RPCPASSWORD" -rpcallowip=127.0.0.1 \
        -fallbackfee=0.0001 >/dev/null
    local deadline=$(($(date +%s) + 60))
    until core_peer_cli getblockchaininfo >/dev/null 2>&1; do
        [[ $(date +%s) -lt $deadline ]] || { echo "Bitcoin Core RPC never came up" >&2; docker logs "$CORE_PEER_CONTAINER" 2>&1 | tail -20 >&2; return 1; }
        sleep 1
    done
    deadline=$(($(date +%s) + 60))
    until [[ "$(core_peer_cli getconnectioncount)" -ge 1 ]]; do
        [[ $(date +%s) -lt $deadline ]] || { echo "Bitcoin Core never connected to satd" >&2; return 1; }
        sleep 1
    done
    echo "Bitcoin Core $(core_peer_cli getnetworkinfo | jq -r .subversion) peered with satd"
}

stop_core_peer() {
    if [[ -n "$CORE_PEER_CONTAINER" ]]; then
        docker logs "$CORE_PEER_CONTAINER" > "${WORK:-/tmp}/core.log" 2>&1 || true
        docker rm -f "$CORE_PEER_CONTAINER" >/dev/null 2>&1 || true
    fi
}

# Every block satd logged as found through Stratum, oldest first.
stratum_found_hashes() {
    grep 'Stratum miner found a block' "$SATD_LOG" | grep -o 'hash=[0-9a-f]\{64\}' | cut -d= -f2
}

# core_follows_satd <budget secs> [cli function]: Core's best block must
# reach satd's within the budget.
core_follows_satd() {
    local budget="$1" cli="${2:-core_peer_cli}"
    local deadline=$(($(date +%s) + budget)) best
    while [[ $(date +%s) -lt $deadline ]]; do
        best="$(sat_cli getbestblockhash)"
        [[ "$("$cli" getbestblockhash 2>/dev/null)" == "$best" ]] && return 0
        sleep 1
    done
    echo "Bitcoin Core did not reach satd's tip $best (Core is at $("$cli" getbestblockhash 2>/dev/null))" >&2
    return 1
}

# assert_core_accepted <hash> [cli function]: the block is on Bitcoin Core's
# active chain, and by Core's own decoding its coinbase pays the payout
# address. A block only satd accepted would be orphaned: nothing else here
# can tell.
assert_core_accepted() {
    local hash="$1" cli="${2:-core_peer_cli}"
    local deadline=$(($(date +%s) + 60)) confirmations="-1"
    while [[ $(date +%s) -lt $deadline ]]; do
        confirmations="$("$cli" getblockheader "$hash" 2>/dev/null | jq -r '.confirmations // -1')"
        [[ "$confirmations" -ge 1 ]] && break
        sleep 1
    done
    if [[ "$confirmations" -lt 1 ]]; then
        echo "Bitcoin Core does not have Stratum-found block $hash on its active chain (confirmations=$confirmations)" >&2
        "$cli" getchaintips >&2 || true
        return 1
    fi
    local paid
    paid="$("$cli" getblock "$hash" 2 | jq -r --arg a "$STRATUM_PAYOUT_ADDR" \
        '[.tx[0].vout[] | select(.scriptPubKey.address == $a and .value > 0)] | length')"
    [[ "$paid" -ge 1 ]] || { echo "by Bitcoin Core's decoding, block $hash does not pay $STRATUM_PAYOUT_ADDR" >&2; return 1; }
    echo "ok: Bitcoin Core accepted Stratum-found block $hash, paying $STRATUM_PAYOUT_ADDR"
}

# Every block found so far must be on Core's chain, and Core at satd's tip.
assert_core_accepted_all_found() {
    local cli="${1:-core_peer_cli}" n=0 hash
    while read -r hash; do
        assert_core_accepted "$hash" "$cli"
        n=$((n + 1))
    done < <(stratum_found_hashes)
    [[ "$n" -ge 1 ]] || { echo "satd logged no Stratum-found block" >&2; return 1; }
    core_follows_satd 60 "$cli"
    echo "ok: Bitcoin Core accepted all $n Stratum-found blocks and is at satd's tip"
}
