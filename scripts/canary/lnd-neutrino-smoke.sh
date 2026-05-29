#!/bin/bash
# LND Neutrino canary — runs a real LND node as a BIP 157/158 light
# client (Neutrino) backed by satd over P2P, and verifies the full
# light-client path works end to end.
#
# This is distinct from the NBXplorer canary (which downloads *every*
# block over P2P as a full-node client) and from the Core interop canary
# (full-node ↔ full-node): Neutrino is the dominant Lightning light-
# client backend, and it exercises a path nothing else does — satd
# serving BIP 158 compact block filters + filter headers over P2P
# (`getcfilters` / `getcfheaders` / `getcfcheckpt`, advertised via
# `NODE_COMPACT_FILTERS` with `--peerblockfilters=1`). LND fetches
# filter headers, then filters, and only downloads the full blocks whose
# filters match a watched script.
#
# Coverage:
#   - LND connects to satd, recognises NODE_COMPACT_FILTERS, syncs the
#     header + filter-header chain, and reports `synced_to_chain: true`
#     at satd's tip.
#   - Funding an LND wallet address and mining to it: satd's cfilter for
#     the funding block matches → LND downloads exactly that block →
#     credits its wallet. Proves the filter-match → targeted-block-
#     download → wallet-credit path, not just header sync.
#
# Pin: lightninglabs/lnd:v0.18.5-beta. Pin bumps are deliberate
# follow-up-PR maintenance after re-verifying interop holds.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"

LND_IMAGE="lightninglabs/lnd:v0.18.5-beta"
LND_CONTAINER="satd-canary-lnd-$$"
LND_RPC_PORT=18610
LND_P2P_PORT=18612

pull_with_retries() {
    local image="$1"
    for attempt in 1 2 3; do
        if docker pull "$image"; then return 0; fi
        if [[ $attempt -eq 3 ]]; then echo "docker pull $image failed 3 times" >&2; return 1; fi
        echo "docker pull $image attempt $attempt failed; retrying in $((attempt * 2))s..."
        sleep $((attempt * 2))
    done
}

lncli() {
    docker exec "$LND_CONTAINER" lncli \
        --network=regtest --no-macaroons --rpcserver="127.0.0.1:$LND_RPC_PORT" "$@"
}

cleanup() {
    docker rm -f "$LND_CONTAINER" >/dev/null 2>&1 || true
    stop_satd
}
trap cleanup EXIT

pull_with_retries "$LND_IMAGE"

# ── Boot satd: P2P listening + BIP158 filters served over P2P ──
# `--peerblockfilters=1` advertises NODE_COMPACT_FILTERS and answers
# getcfilters/getcfheaders/getcfcheckpt; it implies --blockfilterindex=basic.
LND_DATADIR="$(mktemp -d -t satd-canary-lnd.XXXXXX)"
# port_base 18600 → RPC 18600, P2P 18601, Esplora 18602, Electrum 18603.
boot_satd "$LND_DATADIR" 18600 \
    --listen=1 \
    --peerblockfilters=1 \
    --server

SATD_P2P_PORT=$((18600 + 1))

# Mine a starting chain so LND has headers + filters to sync.
SATD_MINE_ADDR="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"
sat_cli generatetoaddress 10 "$SATD_MINE_ADDR" >/dev/null
echo "satd mined to height $(sat_cli getblockcount)"

# ── Boot LND in Neutrino mode, pointed only at satd ──
docker run -d --name "$LND_CONTAINER" --network=host "$LND_IMAGE" \
    --bitcoin.active --bitcoin.regtest --bitcoin.node=neutrino \
    --neutrino.connect="127.0.0.1:$SATD_P2P_PORT" \
    --nobootstrap --noseedbackup --no-macaroons \
    --norest \
    --rpclisten="127.0.0.1:$LND_RPC_PORT" \
    --listen="127.0.0.1:$LND_P2P_PORT" \
    --debuglevel=info >/dev/null

# ── Wait for LND RPC + wallet (auto-created via --noseedbackup) ──
echo "waiting for LND to come up..."
lnd_deadline=$(($(date +%s) + 120))
while [[ $(date +%s) -lt $lnd_deadline ]]; do
    if lncli getinfo >/dev/null 2>&1; then echo "LND RPC ready."; break; fi
    if ! docker ps --format '{{.Names}}' | grep -q "^$LND_CONTAINER\$"; then
        echo "lnd: container exited unexpectedly" >&2
        docker logs "$LND_CONTAINER" 2>&1 | tail -40 >&2 || true
        exit 1
    fi
    sleep 2
done
lncli getinfo >/dev/null 2>&1 || { echo "lnd: RPC never came up" >&2; docker logs "$LND_CONTAINER" 2>&1 | tail -40 >&2; exit 1; }

# ── 1. LND syncs to satd's tip over the light-client path ──
TIP="$(sat_cli getblockcount)"
echo "waiting for LND to sync to satd tip ($TIP) via Neutrino..."
sync_deadline=$(($(date +%s) + 120))
while [[ $(date +%s) -lt $sync_deadline ]]; do
    info="$(lncli getinfo 2>/dev/null || echo '{}')"
    synced="$(jq -r '.synced_to_chain // false' <<<"$info")"
    height="$(jq -r '.block_height // 0' <<<"$info")"
    if [[ "$synced" == "true" && "$height" == "$TIP" ]]; then
        echo "ok: LND synced_to_chain=true at height $height (peer count: $(jq -r '.num_peers' <<<"$info"))"
        break
    fi
    sleep 2
done
info="$(lncli getinfo)"
if [[ "$(jq -r '.synced_to_chain' <<<"$info")" != "true" || "$(jq -r '.block_height' <<<"$info")" != "$TIP" ]]; then
    echo "lnd: did not sync to satd tip $TIP" >&2
    jq '{synced_to_chain, block_height, num_peers}' <<<"$info" >&2
    docker logs "$LND_CONTAINER" 2>&1 | tail -50 >&2 || true
    exit 1
fi

# ── 2. Filter-match → selective block-download → wallet-credit ──
# Mine exactly ONE block to an LND wallet address, then mine the rest to
# a non-LND address. This is the real Neutrino test: only the single
# funding block's BIP158 filter matches LND's watched script, so LND must
# fetch *that one block* over P2P (and skip downloading the other ~110,
# syncing them by filter header alone). The funding coinbase matures 100
# blocks later, giving a non-zero confirmed balance. Mining the bulk to a
# non-LND address keeps LND's block downloads to one (fast) instead of
# 100+ (which would both be slow and fail to prove selective fetch).
LND_ADDR="$(lncli newaddress p2wkh | jq -r '.address')"
echo "funding LND address $LND_ADDR with ONE block, then maturing it..."
sat_cli generatetoaddress 1 "$LND_ADDR" >/dev/null
sat_cli generatetoaddress 110 "$SATD_MINE_ADDR" >/dev/null
NEW_TIP="$(sat_cli getblockcount)"

bal_deadline=$(($(date +%s) + 120))
while [[ $(date +%s) -lt $bal_deadline ]]; do
    info="$(lncli getinfo 2>/dev/null || echo '{}')"
    bal="$(lncli walletbalance 2>/dev/null || echo '{}')"
    height="$(jq -r '.block_height // 0' <<<"$info")"
    confirmed="$(jq -r '.confirmed_balance // 0' <<<"$bal")"
    if [[ "$height" == "$NEW_TIP" && "$confirmed" -gt 0 ]]; then
        echo "ok: LND followed to height $height and credited a filter-matched coinbase (confirmed_balance=$confirmed sat)"
        echo "lnd neutrino canary: PASS"
        exit 0
    fi
    sleep 2
done

echo "lnd: wallet did not reflect filter-matched funds at tip $NEW_TIP" >&2
lncli getinfo | jq '{synced_to_chain, block_height}' >&2 || true
lncli walletbalance >&2 || true
docker logs "$LND_CONTAINER" 2>&1 | tail -60 >&2 || true
exit 1
