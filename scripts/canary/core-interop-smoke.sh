#!/bin/bash
# Bitcoin Core P2P interop canary — peers satd with a real `bitcoind`
# (Bitcoin Core) regtest node and verifies they interoperate at the P2P
# layer in BOTH directions. This is the only canary that tests satd
# against the reference implementation itself, rather than via a
# downstream's tolerance — so it catches consensus/relay/wire drift
# vs. Core directly.
#
# Coverage:
#   - handshake + peer identity (each sees the other's user agent)
#   - BIP324 v2 encrypted transport negotiation (both default v2 on)
#   - block download satd <- Core (satd syncs Core's chain over P2P)
#   - block download Core <- satd (Core syncs satd-mined blocks)
#   - tx relay satd <- Core (Core-originated tx reaches satd mempool)
#   - tx relay Core <- satd (satd-broadcast tx reaches Core mempool)
#
# satd uses Bitcoin Core's regtest network magic, so the two peer
# directly with no shim. Core runs on the host network namespace (like
# the other container canaries) so satd reaches it at 127.0.0.1.
#
# Pin: lncm/bitcoind:v27.0. Bumping the pin is a deliberate maintenance
# step in a follow-up PR after re-verifying interop holds — especially
# across a Core major (consensus/relay/transport changes land there).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"

CORE_IMAGE="lncm/bitcoind:v27.0"
CORE_CONTAINER="satd-canary-core-$$"
CORE_RPC_PORT=18510
CORE_P2P_PORT=18511
CORE_RPCUSER="canary"
CORE_RPCPASSWORD="$(head -c 16 /dev/urandom | xxd -p)"

# A valid regtest P2WPKH satd can mine to (satd is keyless; it just
# needs a destination). Deterministic from secret [0x11; 32]; shared
# with the other canaries.
SATD_MINE_ADDR="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"

pull_with_retries() {
    local image="$1"
    for attempt in 1 2 3; do
        if docker pull "$image"; then return 0; fi
        if [[ $attempt -eq 3 ]]; then echo "docker pull $image failed 3 times" >&2; return 1; fi
        echo "docker pull $image attempt $attempt failed; retrying in $((attempt * 2))s..."
        sleep $((attempt * 2))
    done
}

core_cli() {
    docker exec "$CORE_CONTAINER" bitcoin-cli \
        -regtest -rpcport="$CORE_RPC_PORT" \
        -rpcuser="$CORE_RPCUSER" -rpcpassword="$CORE_RPCPASSWORD" "$@"
}

cleanup() {
    docker rm -f "$CORE_CONTAINER" >/dev/null 2>&1 || true
    stop_satd
}
trap cleanup EXIT

pull_with_retries "$CORE_IMAGE"

# ── Boot Bitcoin Core ──
docker run -d --name "$CORE_CONTAINER" --network=host "$CORE_IMAGE" \
    -regtest -server -listen=1 \
    -port="$CORE_P2P_PORT" -rpcport="$CORE_RPC_PORT" \
    -rpcuser="$CORE_RPCUSER" -rpcpassword="$CORE_RPCPASSWORD" -rpcallowip=127.0.0.1 \
    -fallbackfee=0.0001 -txindex=1 -v2transport=1 >/dev/null

echo "waiting for Bitcoin Core RPC..."
core_deadline=$(($(date +%s) + 60))
while [[ $(date +%s) -lt $core_deadline ]]; do
    if core_cli getblockchaininfo >/dev/null 2>&1; then echo "Bitcoin Core ready."; break; fi
    if ! docker ps --format '{{.Names}}' | grep -q "^$CORE_CONTAINER\$"; then
        echo "core: container exited unexpectedly" >&2
        docker logs "$CORE_CONTAINER" 2>&1 | tail -30 >&2 || true
        exit 1
    fi
    sleep 1
done
core_cli getblockchaininfo >/dev/null 2>&1 || { echo "core: RPC never came up" >&2; exit 1; }

# Core needs a wallet to build txs (no default wallet since v0.21).
core_cli createwallet canary >/dev/null 2>&1 || core_cli loadwallet canary >/dev/null 2>&1 || true
CORE_ADDR="$(core_cli getnewaddress)"

# Mine an initial chain on Core (101 → one mature coinbase to spend).
core_cli generatetoaddress 101 "$CORE_ADDR" >/dev/null
echo "Core mined to height $(core_cli getblockcount)"

# ── Boot satd, connected to Core over P2P ──
CORE_DATADIR="$(mktemp -d -t satd-canary-core.XXXXXX)"
# port_base 18500 → RPC 18500, P2P 18501, Esplora 18502, Electrum 18503.
boot_satd "$CORE_DATADIR" 18500 \
    --listen=1 \
    --connect="127.0.0.1:$CORE_P2P_PORT" \
    --txindex \
    --server

# ── Helper: wait until `sat_cli getblockcount` == target ──
wait_satd_height() {
    local target="$1" deadline=$(($(date +%s) + 90))
    while [[ $(date +%s) -lt $deadline ]]; do
        local h
        h="$(sat_cli getblockcount 2>/dev/null || echo -1)"
        if [[ "$h" == "$target" ]]; then return 0; fi
        sleep 1
    done
    echo "satd did not reach height $target (stuck at $(sat_cli getblockcount 2>/dev/null))" >&2
    return 1
}
wait_core_height() {
    local target="$1" deadline=$(($(date +%s) + 90))
    while [[ $(date +%s) -lt $deadline ]]; do
        local h
        h="$(core_cli getblockcount 2>/dev/null || echo -1)"
        if [[ "$h" == "$target" ]]; then return 0; fi
        sleep 1
    done
    echo "Core did not reach height $target (stuck at $(core_cli getblockcount 2>/dev/null))" >&2
    return 1
}
assert_same_tip() {
    local label="$1"
    local sh ch
    sh="$(sat_cli getbestblockhash)"
    ch="$(core_cli getbestblockhash)"
    if [[ "$sh" != "$ch" ]]; then
        echo "$label: tip mismatch — satd=$sh core=$ch" >&2
        return 1
    fi
    echo "ok: $label — both at $sh"
}

# ── 1. Peer identity + transport ──
echo "verifying peer handshake..."
peer_deadline=$(($(date +%s) + 60))
while [[ $(date +%s) -lt $peer_deadline ]]; do
    n="$(sat_cli getpeerinfo 2>/dev/null | jq 'length' 2>/dev/null || echo 0)"
    [[ "$n" -ge 1 ]] && break
    sleep 1
done
peers="$(sat_cli getpeerinfo)"
[[ "$(jq 'length' <<<"$peers")" -ge 1 ]] || { echo "satd has no peers — handshake failed" >&2; echo "$peers" >&2; exit 1; }
core_subver="$(jq -r '.[0].subver' <<<"$peers")"
transport="$(jq -r '.[0].transport_protocol_type // "unknown"' <<<"$peers")"
echo "ok: satd peered with Core (subver=$core_subver transport=$transport)"
case "$core_subver" in
    *Satoshi*) ;;
    *) echo "peer user agent is not Bitcoin Core ($core_subver)" >&2; exit 1 ;;
esac
# Both default BIP324 v2 on; satd dials out offering v2 and Core v27
# supports it, so the link must negotiate v2 (not silently fall to v1).
if [[ "$transport" != "v2" ]]; then
    echo "expected BIP324 v2 transport with Core v27, got '$transport'" >&2
    exit 1
fi
echo "ok: BIP324 v2 encrypted transport negotiated with Bitcoin Core"

# ── 2. Block download satd <- Core ──
echo "verifying satd syncs Core's chain..."
wait_satd_height 101
assert_same_tip "block sync satd<-Core (initial 101)"

# Ongoing relay: extend Core, satd must follow.
core_cli generatetoaddress 5 "$CORE_ADDR" >/dev/null
wait_satd_height 106
assert_same_tip "block relay satd<-Core (tip announce)"

# ── 3. Block download Core <- satd ──
echo "verifying Core syncs satd-mined blocks..."
sat_cli generatetoaddress 3 "$SATD_MINE_ADDR" >/dev/null
wait_core_height 109
assert_same_tip "block sync Core<-satd"

# ── 4. Tx relay satd <- Core ──
echo "verifying tx relay satd<-Core..."
core_txid="$(core_cli sendtoaddress "$CORE_ADDR" 1.0)"
relay_deadline=$(($(date +%s) + 30))
while [[ $(date +%s) -lt $relay_deadline ]]; do
    if sat_cli getrawmempool | jq -e --arg t "$core_txid" 'index($t) != null' >/dev/null 2>&1; then
        echo "ok: Core-originated tx $core_txid relayed into satd mempool"
        break
    fi
    sleep 1
done
sat_cli getrawmempool | jq -e --arg t "$core_txid" 'index($t) != null' >/dev/null 2>&1 \
    || { echo "Core tx never reached satd mempool" >&2; exit 1; }

# ── 5. Tx relay Core <- satd ──
# Build + sign a tx in Core's wallet but DON'T broadcast it there;
# broadcast it through satd and verify it propagates back to Core. This
# exercises satd's accept + relay-to-peer path in the Core<-satd direction.
echo "verifying tx relay Core<-satd..."
funded="$(core_cli -named createrawtransaction inputs='[]' outputs="{\"$CORE_ADDR\":0.5}")"
fund_res="$(core_cli -named fundrawtransaction hexstring="$funded")"
raw_hex="$(jq -r '.hex' <<<"$fund_res")"
signed="$(core_cli -named signrawtransactionwithwallet hexstring="$raw_hex" | jq -r '.hex')"
satd_relayed_txid="$(sat_cli sendrawtransaction "$signed")"
relay_deadline=$(($(date +%s) + 30))
while [[ $(date +%s) -lt $relay_deadline ]]; do
    if core_cli getrawmempool | jq -e --arg t "$satd_relayed_txid" 'index($t) != null' >/dev/null 2>&1; then
        echo "ok: satd-broadcast tx $satd_relayed_txid relayed into Core mempool"
        break
    fi
    sleep 1
done
core_cli getrawmempool | jq -e --arg t "$satd_relayed_txid" 'index($t) != null' >/dev/null 2>&1 \
    || { echo "satd-broadcast tx never reached Core mempool" >&2; exit 1; }

echo "core interop canary: PASS"
