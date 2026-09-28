#!/usr/bin/env bash
# Nightly three-implementation Warnet rig: Bitcoin Core, satd and rbitcoin in
# one network, checked against each other.
#
# Deploys a ring of one tank each with Warnet's stock bitcoincore Helm chart,
# mines on the Bitcoin Core tank with a keyless scenario, and runs
# contrib/warnet/scenarios/consensus_diff.py: relay, compact blocks, reorgs
# and a valid non-standard block must leave all three on the same tip. A
# divergence logs `tip mismatch` and every tank's height and tip.
#
#   scripts/canary/warnet-3impl.sh
#
# Needs what warnet-smoke.sh needs, plus rbitcoin's Warnet lab image
# (RBITCOIN_WARNET_IMAGE, default rbitcoin-warnet:ci) built at the pinned
# commit by scripts/canary/warnet/build-rbitcoin.sh. rbitcoin's image is a
# lab artefact of that project, pinned by commit like every other downstream
# here, and this rig is nightly rather than PR-gating because of it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/canary/PINS
. "$REPO_ROOT/scripts/canary/PINS"
# shellcheck source=scripts/canary/warnet/lib.sh
. "$REPO_ROOT/scripts/canary/warnet/lib.sh"

SATD_WARNET_IMAGE="${SATD_WARNET_IMAGE:-satd-warnet:ci}"
RBITCOIN_WARNET_IMAGE="${RBITCOIN_WARNET_IMAGE:-rbitcoin-warnet:ci}"
# Warnet's chart renders only X.Y[.Z][-suffix] tags. These are never pulled.
SATD_TANK_TAG="${SATD_TANK_TAG:-0.0.0-canary}"
RBITCOIN_TANK_TAG="${RBITCOIN_TANK_TAG:-0.0.0-canary}"
REORGS="${REORGS:-5}"

require_tools warnet kubectl kind helm docker python3
trap collect_logs EXIT

load_pinned_image "$WARNET_CORE_IMAGE"
load_pinned_image "$WARNET_COMMANDER_IMAGE"
load_local_image "$SATD_WARNET_IMAGE" "satd-warnet:$SATD_TANK_TAG"
load_local_image "$RBITCOIN_WARNET_IMAGE" "rbitcoin-warnet:$RBITCOIN_TANK_TAG"

net="$(render_network "$REPO_ROOT/scripts/canary/warnet/networks/3impl" \
    "CORE_REPO=$(image_repo "$WARNET_CORE_IMAGE")" "CORE_TAG=$(image_tag "$WARNET_CORE_IMAGE")" \
    "SATD_REPO=satd-warnet" "SATD_TAG=$SATD_TANK_TAG" \
    "RBITCOIN_REPO=rbitcoin-warnet" "RBITCOIN_TAG=$RBITCOIN_TANK_TAG")"
scen="$(scenarios_dir)"

# rbitcoin reports the peer it dials for `addnode` as outbound-full-relay, not
# manual, so Warnet's "Network connected" (which counts manual peers) never
# prints for its tank. Wait for every tank to have a peer, and for the manual
# peers of the tanks whose addnode peers are manual, then check them.
deploy_and_wait_peers "$net" tank-0000=1 tank-0001=1
assert_peers tank-0000 1
assert_peers tank-0001 1
assert_v2_only tank-0002

run_scenario "$scen/consensus_diff.py" --miner tank-0000 --timeout 180 --reorgs "$REORGS"

log "all three implementations followed every step"
