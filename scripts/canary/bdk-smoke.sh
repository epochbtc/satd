#!/bin/bash
# BDK descriptor-wallet canary — drives satd's Electrum + Esplora
# surfaces with the Bitcoin Dev Kit (bdk_wallet + bdk_electrum +
# bdk_esplora), the canonical real-world consumer of both APIs.
#
# Where the wire-shape canaries (esplora-smoke.sh / electrum-smoke.sh)
# poke individual endpoints with curl/nc, this runs a *real wallet
# workflow* end to end: gap-limit full_scan over BOTH surfaces with the
# same descriptor, coinbase-maturity accounting, a signed spend
# broadcast through Esplora and observed over Electrum, and a
# cross-surface balance agreement check. If satd's surfaces drift from
# what a descriptor wallet actually needs (heights, coinbase flags,
# address pagination, mempool visibility, broadcast), this goes red.
#
# The harness lives in scripts/canary/bdk-canary/ as a STANDALONE cargo
# project (its own workspace + lockfile) so the heavy BDK dependency
# tree never enters satd's own build, and so it resolves exactly like a
# real downstream would.
#
# Pins: bdk_wallet 2.x / bdk_electrum 0.23 / bdk_esplora 0.22 (see the
# crate's Cargo.toml). Pin bumps are deliberate maintenance steps in a
# follow-up PR after re-verifying the canary passes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=boot-satd.sh
source "$SCRIPT_DIR/boot-satd.sh"

CANARY_DIR="$SCRIPT_DIR/bdk-canary"
CANARY_BIN="$CANARY_DIR/target/release/bdk-canary"

# Basic-auth creds for both sat-cli (boot helper) and the bitcoincore-rpc
# client inside the harness (which uses RPC only to mine).
RPCUSER="canary"
RPCPASSWORD="$(head -c 16 /dev/urandom | xxd -p)"
export SATD_RPCUSER="$RPCUSER"
export SATD_RPCPASSWORD="$RPCPASSWORD"

# Build the standalone harness first (fail fast before booting satd).
echo "building bdk-canary harness (standalone crate)..."
cargo build --release --manifest-path "$CANARY_DIR/Cargo.toml"

BDK_DATADIR="$(mktemp -d -t satd-canary-bdk.XXXXXX)"
# port_base 18400 → RPC 18400, P2P 18401, Esplora 18402, Electrum 18403.
# Electrum needs txindex (it serves arbitrary transactions); both
# surfaces need addressindex for scripthash/address history.
boot_satd "$BDK_DATADIR" 18400 \
    --rpcuser="$RPCUSER" \
    --rpcpassword="$RPCPASSWORD" \
    --esplora=1 \
    --electrum=1 \
    --addressindex=1 \
    --txindex=1 \
    --server

echo "running BDK descriptor-wallet canary against satd surfaces..."
BDK_ELECTRUM_URL="tcp://127.0.0.1:$ELECTRUM_PORT" \
BDK_ESPLORA_URL="http://127.0.0.1:$ESPLORA_PORT" \
BDK_RPC_URL="http://127.0.0.1:$RPC_PORT" \
BDK_RPC_USER="$RPCUSER" \
BDK_RPC_PASS="$RPCPASSWORD" \
    "$CANARY_BIN"

echo "bdk canary: PASS"
