#!/usr/bin/env bash
# compose-test.sh — run two tanks of the Warnet lab image the way Warnet's
# stock bitcoincore chart runs them, and prove the chart's assumptions hold.
#
#   contrib/warnet/tests/compose-test.sh
#   SATD_WARNET_IMAGE=satd-warnet:dev contrib/warnet/tests/compose-test.sh
#
# tank0.conf and tank1.conf are the chart's rendered bitcoin.conf, byte for
# byte (regenerate them with render-confs.sh). Each check below is one thing
# the chart does without asking:
#
#   - starts the container with no arguments        -> satd comes up at all
#   - writes every stock Bitcoin Core key            -> none of them is fatal
#   - probes liveness with `pidof bitcoind`          -> the probe matches
#   - execs `bitcoin-cli` for `warnet bitcoin rpc`   -> it authenticates from
#     bitcoin.conf, since satd writes no cookie when rpcuser+rpcpassword are set
#   - peers tanks with `addnode=<service name>`      -> the name resolves, the
#     peer is dialled as a manual connection, and blocks relay across it
#
# Requires docker with compose v2 and python3.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${SATD_WARNET_IMAGE:-satd-warnet:local}"
PROJECT="${COMPOSE_PROJECT:-satd-warnet-test-$$}"
WAIT_SECS="${WAIT_SECS:-90}"
# A fixed regtest address with no key behind it; blocks mined to it are never spent.
MINE_TO="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"

for c in docker python3; do
    command -v "$c" > /dev/null 2>&1 || { echo "compose-test.sh: missing $c" >&2; exit 2; }
done
docker compose version > /dev/null 2>&1 || { echo "compose-test.sh: needs docker compose v2" >&2; exit 2; }
docker image inspect "$IMAGE" > /dev/null 2>&1 || {
    echo "compose-test.sh: image $IMAGE not found; build it with" >&2
    echo "  docker build -t $IMAGE contrib/warnet" >&2
    exit 2
}

export SATD_WARNET_IMAGE="$IMAGE"
compose() { docker compose -p "$PROJECT" -f "$HERE/compose.yml" "$@"; }
cli() { local t="$1"; shift; compose exec -T "$t" bitcoin-cli "$@"; }

fail=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=1; }
dump_and_die() {
    printf '  FAIL  %s\n' "$1"
    echo "--- logs ---"
    compose logs --no-color 2>&1 | tail -n 80 || true
    exit 1
}
cleanup() { compose down -v -t 5 > /dev/null 2>&1 || true; }
trap cleanup EXIT

# wait_for <description> <command...>: retry until the command succeeds.
wait_for() {
    local what="$1"; shift
    local deadline=$((SECONDS + WAIT_SECS))
    until "$@" > /dev/null 2>&1; do
        [ "$SECONDS" -lt "$deadline" ] || dump_and_die "$what (gave up after ${WAIT_SECS}s)"
        sleep 1
    done
    ok "$what"
}

height_is() { [ "$(cli "$1" getblockcount 2>/dev/null | tr -d '\r')" = "$2" ]; }

one_manual_peer() {
    cli "$1" getpeerinfo | python3 -c '
import json, sys
peers = json.load(sys.stdin)
manual = [p for p in peers if p.get("connection_type") == "manual" and p.get("addr")]
sys.exit(0 if len(manual) == 1 else 1)'
}

echo "== tank0 starts on the chart's bitcoin.conf =="
compose up -d tank0 > /dev/null 2>&1
wait_for "bitcoin-cli in tank0 authenticates from bitcoin.conf and answers" height_is tank0 0

echo "== liveness probe =="
if compose exec -T tank0 pidof bitcoind > /dev/null; then
    ok "pidof bitcoind finds the node (the chart's liveness probe)"
else
    bad "pidof bitcoind finds nothing; the chart would restart the pod forever"
fi

echo "== stock Bitcoin Core keys are skipped, never fatal =="
logs0="$(compose logs --no-color tank0 2>&1)"
if grep -q "ignoring unsupported Bitcoin Core option 'rest'" <<< "$logs0"; then
    ok "rest= is skipped with a warning"
else
    bad "no warning for rest=; is the fixture the chart's render?"
fi
if grep -qi 'error reading configuration\|unsupported.*refus\|fatal' <<< "$logs0"; then
    bad "the startup log reports a configuration error"
else
    ok "no configuration error in the startup log"
fi

echo "== bitcoin-cli adapter =="
if cli tank0 -generate 1 > /dev/null 2>&1; then
    bad "-generate was accepted; it needs a wallet"
else
    ok "-generate is refused (satd has no wallet)"
fi

echo "== tank1 peers with tank0 by service name =="
compose up -d tank1 > /dev/null 2>&1
wait_for "tank1 answers" height_is tank1 0
cli tank0 generatetoaddress 1 "$MINE_TO" > /dev/null
wait_for "tank1 syncs the block tank0 mined" height_is tank1 1
wait_for "tank1 has exactly one manual peer (addnode=tank0 resolved and dialled)" one_manual_peer tank1

if [ "$fail" -ne 0 ]; then
    echo "compose-test.sh: FAILED"
    compose logs --no-color 2>&1 | tail -n 80 || true
    exit 1
fi
echo "compose-test.sh: all checks passed"
