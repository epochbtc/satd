#!/usr/bin/env bash
# Warnet canary: satd tanks in a Warnet network beside Bitcoin Core tanks.
#
# Deploys a ring alternating Bitcoin Core and satd with Warnet's stock
# bitcoincore Helm chart and the contrib/warnet lab image, then drives it with
# Warnet's own tooling: keyless mining and a transaction flood through satd
# tanks, Warnet's reconnaissance and P2P-interface scenarios, and a
# cross-implementation consensus check. Green means Warnet can run satd.
#
#   scripts/canary/warnet-smoke.sh
#
# Needs a kind cluster (KIND_CLUSTER, default warnet) as the current kubectl
# context; warnet, kubectl, kind, helm and docker on PATH; and the lab image
# (SATD_WARNET_IMAGE, default satd-warnet:ci), built with
#   docker build --build-arg SATD_IMAGE=<satd image> -t satd-warnet:ci contrib/warnet
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/canary/PINS
. "$REPO_ROOT/scripts/canary/PINS"
# shellcheck source=scripts/canary/warnet/lib.sh
. "$REPO_ROOT/scripts/canary/warnet/lib.sh"

SATD_WARNET_IMAGE="${SATD_WARNET_IMAGE:-satd-warnet:ci}"
# The chart renders only X.Y[.Z][-suffix] tags; this one is never pulled.
SATD_TANK_TAG="${SATD_TANK_TAG:-0.0.0-canary}"

require_tools warnet kubectl kind helm docker python3
trap collect_logs EXIT

log "cluster $KIND_CLUSTER; kubectl context $(kubectl config current-context)"
load_pinned_image "$WARNET_CORE_IMAGE"
load_pinned_image "$WARNET_COMMANDER_IMAGE"
load_local_image "$SATD_WARNET_IMAGE" "satd-warnet:$SATD_TANK_TAG"

net="$(render_network "$REPO_ROOT/scripts/canary/warnet/networks/core-satd" \
    "CORE_REPO=$(image_repo "$WARNET_CORE_IMAGE")" "CORE_TAG=$(image_tag "$WARNET_CORE_IMAGE")" \
    "SATD_REPO=satd-warnet" "SATD_TAG=$SATD_TANK_TAG")"
scen="$(scenarios_dir)"

deploy_and_wait "$net"

# Mining through a satd tank: MiniWallet's generatetodescriptor + scantxoutset.
run_scenario "$scen/keyless_miner.py" --tank tank-0001 --blocks 110
wait_same_height 110

# satd tanks dial their addnode peer by service name, as a manual peer, and
# every link runs v2 transport (Bitcoin Core 27.0+ defaults to it, as satd does).
assert_peers tank-0001 1
assert_peers tank-0003 1

# Warnet's own scenarios. p2p_interface speaks to nodes[0] from the test
# framework's P2PInterface; reconnaissance crawls every tank over P2P.
run_scenario "$scen/reconnaissance.py"
run_scenario "$scen/test_scenarios/p2p_interface.py" --source_dir="$scen"

# A transaction flood sent through the other satd tank, confirmed everywhere.
before="$(tank_rpc tank-0000 getblockcount)"
run_scenario "$scen/keyless_tx_flood.py" --tank tank-0003 --txs 40
wait_same_height "$((before + 2))"

# Relay, compact blocks and a valid non-standard block, checked on every tank.
# No reorg rounds: satd can stay a block behind after a reorg whose blocks
# arrive tip-first (#856); the nightly rig runs them.
run_scenario "$scen/consensus_diff.py" --miner tank-0000 --timeout 120 --reorgs 0

log "all checks passed"
