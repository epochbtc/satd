# shellcheck shell=bash
# Shared helpers for the Warnet canaries (warnet-smoke.sh, warnet-3impl.sh).
# Source after `set -euo pipefail` and after sourcing scripts/canary/PINS.
#
# The caller sets:
#   KIND_CLUSTER   kind cluster name (default: warnet)
#   ARTIFACT_DIR   where logs are collected (default: ./warnet-logs)
#   WAIT_DEPLOY    seconds to wait for "Network connected" (default: 600)
#   WAIT_SCENARIO  seconds to wait for one scenario (default: 600)

KIND_CLUSTER="${KIND_CLUSTER:-warnet}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$PWD/warnet-logs}"
WAIT_DEPLOY="${WAIT_DEPLOY:-600}"
WAIT_SCENARIO="${WAIT_SCENARIO:-600}"
WARNET_WORK="$(mktemp -d)"
mkdir -p "$ARTIFACT_DIR"

log() { printf '[warnet-canary] %s\n' "$*"; }
die() { printf '[warnet-canary] FAIL: %s\n' "$*" >&2; exit 1; }

require_tools() {
    local missing=()
    for c in "$@"; do command -v "$c" > /dev/null 2>&1 || missing+=("$c"); done
    [ "${#missing[@]}" -eq 0 ] || die "missing tools: ${missing[*]}"
}

# `repo:tag@sha256:...` -> repo, tag
image_repo() { local r="${1%%@*}"; printf '%s' "${r%:*}"; }
image_tag()  { local r="${1%%@*}"; printf '%s' "${r##*:}"; }

# Pull a pinned `repo:tag@sha256:...` by digest, tag it `repo:tag` (the name
# a chart uses) and load it into the cluster. With the image present the
# cluster pulls nothing, so a re-pushed upstream tag cannot change the run.
load_pinned_image() {
    local ref="$1" name
    name="$(image_repo "$ref"):$(image_tag "$ref")"
    docker pull -q "$(image_repo "$ref")@${ref##*@}" > /dev/null
    docker tag "$(image_repo "$ref")@${ref##*@}" "$name"
    kind load docker-image "$name" --name "$KIND_CLUSTER" > /dev/null
    log "loaded $name (${ref##*@})"
}

# Load a locally built image under a tag Warnet's chart will render:
# the chart only accepts tags shaped like X.Y[.Z][-suffix].
load_local_image() {
    local src="$1" dst="$2"
    docker image inspect "$src" > /dev/null 2>&1 || die "image $src not found; build it first"
    docker tag "$src" "$dst"
    kind load docker-image "$dst" --name "$KIND_CLUSTER" > /dev/null
    log "loaded $dst (from $src)"
}

# render_network <template dir> KEY=value... -> prints the rendered dir.
# Replaces @KEY@ in every file.
render_network() {
    local src="$1"; shift
    local dst
    dst="$WARNET_WORK/networks/$(basename "$src")"
    mkdir -p "$dst"
    cp "$src"/*.yaml "$dst/"
    local kv
    for kv in "$@"; do
        sed -i "s|@${kv%%=*}@|${kv#*=}|g" "$dst"/*.yaml
    done
    if grep -q '@[A-Z_]*@' "$dst"/*.yaml; then
        grep -n '@[A-Z_]*@' "$dst"/*.yaml >&2
        die "unrendered placeholders in $src"
    fi
    printf '%s' "$dst"
}

# A Warnet project's scenarios directory: Warnet's own scenarios and
# frameworks, plus satd's keyless scenarios. `warnet run` uploads only the
# scenario's directory, so they have to sit together.
scenarios_dir() {
    local dst="$WARNET_WORK/scenarios" src
    if [ ! -d "$dst" ]; then
        src="$(python3 -c 'from warnet.constants import SCENARIOS_DIR; print(SCENARIOS_DIR)')"
        cp -r "$src" "$dst"
        cp "$REPO_ROOT"/contrib/warnet/scenarios/*.py "$dst/"
    fi
    printf '%s' "$dst"
}

tank_rpc() { local t="$1"; shift; warnet bitcoin rpc "$t" "$@" | tr -d '\r'; }

tanks() { kubectl get pods -l mission=tank -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort; }

deploy_and_wait() {
    local net="$1" deadline status
    log "deploying $net"
    warnet deploy "$net" > "$ARTIFACT_DIR/deploy.log" 2>&1 || { cat "$ARTIFACT_DIR/deploy.log"; die "warnet deploy failed"; }
    deadline=$((SECONDS + WAIT_DEPLOY))
    while :; do
        status="$(warnet status 2>&1 || true)"
        if grep -q 'Network connected' <<< "$status"; then
            log "network connected: $(tanks | tr '\n' ' ')"
            return 0
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            printf '%s\n' "$status" > "$ARTIFACT_DIR/status-timeout.txt"
            kubectl get pods -A -o wide || true
            die "network not connected after ${WAIT_DEPLOY}s (warnet status saved)"
        fi
        sleep 5
    done
}

# start_scenario <file> [args...]: `warnet run` and print the new commander pod.
start_scenario() {
    local file="$1"; shift
    local before pod name
    name="$(basename "$file" .py)"
    before="$(kubectl get pods -l mission=commander -o name | sort)"
    warnet run "$file" "$@" >> "$ARTIFACT_DIR/run-$name.log" 2>&1 || { cat "$ARTIFACT_DIR/run-$name.log" >&2; die "warnet run $name failed to start"; }
    pod="$(comm -13 <(printf '%s\n' "$before") <(kubectl get pods -l mission=commander -o name | sort) | head -n1)"
    [ -n "$pod" ] || die "no commander pod appeared for $name"
    printf '%s' "$pod"
}

# wait_started <pod>: true once the pod has left Pending. `warnet run` reports
# the scenario upload as successful even when its exec into the init container
# failed, and the pod then waits for the archive forever.
wait_started() {
    local pod="$1" deadline=$((SECONDS + 180))
    while [ "$SECONDS" -lt "$deadline" ]; do
        [ "$(kubectl get "$pod" -o jsonpath='{.status.phase}')" != Pending ] && return 0
        sleep 5
    done
    return 1
}

# run_scenario <file> [args...]: run a scenario to completion and fail unless
# its pod Succeeded. Polls the pod rather than using --debug, which streams
# logs but loses the exit status. A commander that never starts is an
# infrastructure fault, not a scenario result: it is retried once.
run_scenario() {
    local file="$1"; shift
    local pod phase deadline name attempt
    name="$(basename "$file" .py)"
    log "scenario $name $*"
    for attempt in 1 2; do
        pod="$(start_scenario "$file" "$@")"
        wait_started "$pod" && break
        kubectl describe "$pod" > "$ARTIFACT_DIR/stuck-$name-$attempt.txt" 2>&1 || true
        helm uninstall "${pod#pod/}" > /dev/null 2>&1 || true
        [ "$attempt" = 1 ] || die "scenario $name: commander never started (see stuck-$name-*.txt)"
        log "scenario $name: commander stuck before start; retrying once"
    done
    deadline=$((SECONDS + WAIT_SCENARIO))
    while :; do
        phase="$(kubectl get "$pod" -o jsonpath='{.status.phase}')"
        case "$phase" in Succeeded|Failed) break ;; esac
        [ "$SECONDS" -lt "$deadline" ] || { phase="Timeout"; break; }
        sleep 5
    done
    kubectl logs "$pod" -c commander > "$ARTIFACT_DIR/scenario-$name.log" 2>&1 || true
    if [ "$phase" != Succeeded ]; then
        tail -n 60 "$ARTIFACT_DIR/scenario-$name.log" >&2
        die "scenario $name: $phase"
    fi
    log "scenario $name: Succeeded"
    # A commander run is a Helm release named after its pod.
    helm uninstall "${pod#pod/}" > /dev/null 2>&1 || true
}

# deploy_and_wait_peers <network dir>: deploy, then wait until every tank has
# at least one peer. For networks with a tank whose addnode peers are not
# reported as `manual`, where Warnet's own "Network connected" never prints.
deploy_and_wait_peers() {
    local net="$1" deadline t n ok
    log "deploying $net"
    warnet deploy "$net" > "$ARTIFACT_DIR/deploy.log" 2>&1 || { cat "$ARTIFACT_DIR/deploy.log"; die "warnet deploy failed"; }
    deadline=$((SECONDS + WAIT_DEPLOY))
    while :; do
        ok=1
        for t in $(tanks); do
            n="$(tank_rpc "$t" getconnectioncount 2>/dev/null || echo 0)"
            [ "${n:-0}" -ge 1 ] 2>/dev/null || ok=0
        done
        if [ "$ok" = 1 ] && [ -n "$(tanks)" ]; then
            log "every tank has a peer: $(tanks | tr '\n' ' ')"
            return 0
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            warnet status > "$ARTIFACT_DIR/status-timeout.txt" 2>&1 || true
            kubectl get pods -A -o wide || true
            die "some tank has no peer after ${WAIT_DEPLOY}s"
        fi
        sleep 5
    done
}

# wait_same_height <min> [timeout]: poll until every tank reports the same
# height, at least <min>. Blocks take a moment to cross the ring, so a single
# read right after mining would fail on ordinary relay latency; a tank still
# apart after the timeout is stuck, not slow.
wait_same_height() {
    local min="$1" timeout="${2:-120}" deadline t h first same
    deadline=$((SECONDS + timeout))
    while :; do
        same=1; first=""
        for t in $(tanks); do
            h="$(tank_rpc "$t" getblockcount 2>/dev/null || echo -1)"
            [ -z "$first" ] && first="$h"
            { [ "$h" = "$first" ] && [ "$h" -ge "$min" ]; } 2>/dev/null || same=0
        done
        [ "$same" = 1 ] && [ -n "$first" ] && break
        if [ "$SECONDS" -ge "$deadline" ]; then
            for t in $(tanks); do log "  $t height $(tank_rpc "$t" getblockcount 2>/dev/null || echo unreachable)"; done
            die "tanks did not converge on one height of at least $min within ${timeout}s"
        fi
        sleep 2
    done
    log "every tank at height $first"
}

# Every peer of <tank> speaks v2 transport, and at least <n> are manual.
assert_peers() {
    local tank="$1" n="$2"
    tank_rpc "$tank" getpeerinfo | python3 -c '
import json, sys
tank, want = sys.argv[1], int(sys.argv[2])
peers = json.load(sys.stdin)
for p in peers:
    print("  %s peer %s %s %s %s" % (tank, p.get("addr"), p.get("connection_type"),
                                     p.get("transport_protocol_type"), p.get("subver")))
manual = [p for p in peers if p.get("connection_type") == "manual"]
v1 = [p for p in peers if p.get("transport_protocol_type") != "v2"]
if len(manual) < want:
    sys.exit(f"{tank}: {len(manual)} manual peers, expected at least {want}")
if v1:
    sys.exit(f"{tank}: {len(v1)} peers not on v2 transport")
' "$tank" "$n"
}

# Every peer of <tank> speaks v2 transport, whatever its connection type.
assert_v2_only() { assert_peers "$1" 0; }

collect_logs() {
    local t
    for t in $(tanks 2>/dev/null); do
        kubectl logs "$t" --all-containers > "$ARTIFACT_DIR/tank-$t.log" 2>&1 || true
    done
    kubectl get pods -A -o wide > "$ARTIFACT_DIR/pods.txt" 2>&1 || true
    warnet status > "$ARTIFACT_DIR/status.txt" 2>&1 || true
    log "logs in $ARTIFACT_DIR"
}
