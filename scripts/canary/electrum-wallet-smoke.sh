#!/bin/bash
# Electrum reference-wallet canary — runs the actual Electrum wallet
# (spesmilo/electrum, the canonical client millions of users run) headless
# against satd's Electrum server, and verifies a real wallet workflow that
# includes SPV.
#
# This is distinct from the BDK canary (which drives the Electrum surface
# via the `electrum-client` library) and the electrum-smoke wire canary
# (raw `nc`): the reference wallet does **SPV** — it syncs and verifies the
# header chain (`blockchain.block.headers`) and checks **merkle proofs**
# (`blockchain.transaction.get_merkle`) for every wallet tx. That
# verification path is exactly what a light wallet relies on and what the
# library-level checks don't fully exercise.
#
# Electrum is not published as a usable PyPI wheel and its tarball needs a
# matching libsecp256k1; the self-contained AppImage bundles its own Python
# + libsecp256k1, so we run that (extracted, no FUSE needed) inside a thin
# Debian container on the host network.
#
# Coverage:
#   - Electrum connects to satd as its only server (`--oneserver`), syncs +
#     SPV-verifies the header chain, reports `connected` at satd's tip.
#   - A wallet address is funded (mine 1 block to it) and matured: Electrum
#     detects it via scripthash subscription, pulls history, verifies the
#     merkle proof, and reports a confirmed balance.
#
# Pin: electrum 4.5.8 (download.electrum.org AppImage). Pin bumps are
# deliberate follow-up-PR maintenance.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"

ELECTRUM_VERSION="4.5.8"
ELECTRUM_IMAGE="debian:bookworm-slim"
ELECTRUM_CONTAINER="satd-canary-electrum-wallet-$$"
APPRUN="/opt/electrum/squashfs-root/AppRun"

# Electrum CLI against the regtest daemon inside the container.
el() {
    docker exec "$ELECTRUM_CONTAINER" "$APPRUN" --regtest "$@"
}

cleanup() {
    docker rm -f "$ELECTRUM_CONTAINER" >/dev/null 2>&1 || true
    stop_satd
}
trap cleanup EXIT

# ── Boot satd with the Electrum server ──
EL_DATADIR="$(mktemp -d -t satd-canary-electrum-wallet.XXXXXX)"
# port_base 18900 → RPC 18900, P2P 18901, Esplora 18902, Electrum 18903.
boot_satd "$EL_DATADIR" 18900 \
    --electrum=1 \
    --addressindex=1 \
    --txindex \
    --server

SATD_ELECTRUM_PORT=$((18900 + 3))
SATD_MINE_ADDR="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"

# Mine a starting chain so Electrum has headers to sync + verify.
sat_cli generatetoaddress 10 "$SATD_MINE_ADDR" >/dev/null
echo "satd mined to height $(sat_cli getblockcount)"

# ── Start the Electrum container + fetch the AppImage ──
docker run -d --name "$ELECTRUM_CONTAINER" --network=host --entrypoint sh \
    "$ELECTRUM_IMAGE" -c 'sleep 1800' >/dev/null

echo "installing Electrum $ELECTRUM_VERSION (AppImage) in the container..."
docker exec "$ELECTRUM_CONTAINER" sh -c '
    set -e
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq curl ca-certificates >/dev/null 2>&1
    mkdir -p /opt/electrum && cd /opt/electrum
    curl -fsSL -o e.AppImage "https://download.electrum.org/'"$ELECTRUM_VERSION"'/electrum-'"$ELECTRUM_VERSION"'-x86_64.AppImage"
    chmod +x e.AppImage
    ./e.AppImage --appimage-extract >/dev/null 2>&1
' || { echo "electrum: AppImage install failed" >&2; exit 1; }

# ── Start the Electrum daemon + wallet ──
# Sequencing matters: `setconfig` needs a running daemon, but a daemon
# started without a server never connects. So: start the daemon, point it
# at satd as its ONLY server over plaintext TCP (":t"), create the wallet,
# then RESTART the daemon so it actually dials the configured server.
echo "starting Electrum daemon + wallet..."
el daemon -d >/dev/null 2>&1 || true
sleep 3
el setconfig oneserver true >/dev/null 2>&1 || true
el setconfig server "127.0.0.1:$SATD_ELECTRUM_PORT:t" >/dev/null 2>&1 || true
el create >/dev/null 2>&1 || true
el stop >/dev/null 2>&1 || true
sleep 2
el daemon -d >/dev/null 2>&1 || true
sleep 3
el load_wallet >/dev/null 2>&1 || true

# ── 1. Electrum connects to satd and SPV-syncs the header chain ──
TIP="$(sat_cli getblockcount)"
echo "waiting for Electrum to connect + sync to satd tip ($TIP)..."
conn_deadline=$(($(date +%s) + 90))
while [[ $(date +%s) -lt $conn_deadline ]]; do
    info="$(el getinfo 2>/dev/null || echo '{}')"
    connected="$(jq -r '.connected // false' <<<"$info" 2>/dev/null || echo false)"
    sh="$(jq -r '.server_height // 0' <<<"$info" 2>/dev/null || echo 0)"
    if [[ "$connected" == "true" && "$sh" == "$TIP" ]]; then
        echo "ok: Electrum connected to satd, server_height=$sh"
        break
    fi
    sleep 2
done
info="$(el getinfo 2>/dev/null || echo '{}')"
if [[ "$(jq -r '.connected // false' <<<"$info")" != "true" ]]; then
    echo "electrum: never connected to satd" >&2
    echo "$info" >&2
    docker logs "$ELECTRUM_CONTAINER" 2>&1 | tail -30 >&2 || true
    exit 1
fi

# ── 2. Fund a wallet address, mature it, verify SPV-confirmed balance ──
EL_ADDR="$(el getunusedaddress 2>/dev/null | tr -d '"')"
[[ -n "$EL_ADDR" ]] || { echo "electrum: could not get a wallet address" >&2; exit 1; }
echo "funding Electrum address $EL_ADDR with ONE block, then maturing it..."
sat_cli generatetoaddress 1 "$EL_ADDR" >/dev/null
sat_cli generatetoaddress 110 "$SATD_MINE_ADDR" >/dev/null
NEW_TIP="$(sat_cli getblockcount)"

bal_deadline=$(($(date +%s) + 90))
while [[ $(date +%s) -lt $bal_deadline ]]; do
    bal="$(el getbalance 2>/dev/null || echo '{}')"
    confirmed="$(jq -r '.confirmed // "0"' <<<"$bal" 2>/dev/null || echo 0)"
    # Electrum reports BTC strings; treat any non-zero confirmed as success.
    if [[ -n "$confirmed" && "$confirmed" != "0" && "$confirmed" != "0.0" ]]; then
        echo "ok: Electrum SPV-verified a confirmed balance of $confirmed BTC"
        echo "electrum wallet canary: PASS"
        exit 0
    fi
    sleep 2
done

echo "electrum: wallet did not report an SPV-confirmed balance at tip $NEW_TIP" >&2
el getbalance >&2 || true
el getinfo 2>/dev/null | jq '{connected, server_height, blockchain_height}' >&2 || true
exit 1
