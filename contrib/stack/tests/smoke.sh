#!/bin/bash
# smoke.sh — bring the reference stack up on regtest and prove every surface
# it advertises actually answers.
#
#   contrib/stack/tests/smoke.sh                     # satd core only
#   contrib/stack/tests/smoke.sh --with lightning    # + LND (Neutrino)
#   contrib/stack/tests/smoke.sh --with proxy
#   SATD_IMAGE=satd:dev contrib/stack/tests/smoke.sh # test a local build
#
# The point of this test is the TLS half. satd's own test suite already
# proves the RPC, Electrum and Esplora protocols; what is unproven until
# something connects from outside the container is whether the certificate
# this stack generates is one a client will actually accept — right SANs,
# right chain, right key, on the right listener. So every probe here goes
# over TLS from the host, verifying against the generated CA with
# `-verify_return_error`, and a probe that would pass without verification
# is not a probe.
#
# Requires: docker (with compose v2), openssl, curl and python3. On macOS,
# also GNU coreutils (`brew install coreutils`) and a real OpenSSL
# (`brew install openssl@3`) — see the preflight below.

set -euo pipefail

# --- preflight --------------------------------------------------------------
# Named up front rather than discovered two hundred lines in. A missing
# `timeout` used to surface as an Electrum probe that simply never returned.
missing=()
for c in docker openssl curl python3 awk sed grep cut head tr od dirname; do
    command -v "$c" > /dev/null 2>&1 || missing+=("$c")
done

# `timeout` and `sha256sum` are GNU; macOS ships neither. Homebrew's
# coreutils installs them g-prefixed, and `shasum` is in the base system, so
# resolve rather than require — this script is the same test either way.
if command -v timeout > /dev/null 2>&1; then TIMEOUT=(timeout)
elif command -v gtimeout > /dev/null 2>&1; then TIMEOUT=(gtimeout)
else missing+=("timeout (macOS: brew install coreutils)"); TIMEOUT=(); fi

if command -v sha256sum > /dev/null 2>&1; then SHA256=(sha256sum)
elif command -v gsha256sum > /dev/null 2>&1; then SHA256=(gsha256sum)
elif command -v shasum > /dev/null 2>&1; then SHA256=(shasum -a 256)
else missing+=("sha256sum"); SHA256=(); fi

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "smoke.sh: missing required tools:" >&2
    printf '  %s\n' "${missing[@]}" >&2
    exit 2
fi

# LibreSSL is what /usr/bin/openssl is on macOS, and it is not a drop-in for
# what the TLS probes below do: `-verify_return_error` with `-quiet` is the
# whole point of this test, and a probe that silently stops verifying is
# worse than no probe. Say so rather than emit passes that mean less than
# they read.
if openssl version 2>/dev/null | grep -qi libressl; then
    echo "smoke.sh: $(openssl version) is not supported — the TLS probes need OpenSSL." >&2
    echo "  macOS: brew install openssl@3, then put its bin directory first on PATH." >&2
    exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="$(cd "$HERE/.." && pwd)"

OVERLAYS=()
KEEP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --with) OVERLAYS+=("$2"); shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "smoke.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

# A distinct project name and a distinct port block, so this can run beside
# a real stack (or a second copy of itself) without fighting over either.
PROJECT="satd-smoke-$$"
PORT_BASE="${SATD_SMOKE_PORT_BASE:-21400}"
export SATD_RPC_TLS_PORT=$((PORT_BASE + 0))
export SATD_ELECTRUM_TLS_PORT=$((PORT_BASE + 1))
export SATD_ESPLORA_TLS_PORT=$((PORT_BASE + 2))
export SATD_P2P_PORT=18444
export PROXY_RTL_PORT=$((PORT_BASE + 3))
export PROXY_MINT_PORT=$((PORT_BASE + 4))
export PROXY_METRICS_PORT=$((PORT_BASE + 5))
export LND_P2P_PORT=$((PORT_BASE + 6))
export LND_REST_PORT=$((PORT_BASE + 7))
export PROXY_BTCPAY_PORT=$((PORT_BASE + 8))
# Required by compose.lightning.yml, and asserted on below: RTL falls back to
# the literal password "password" if this does not reach it.
export RTL_PASSWORD="smoke-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export NETWORK=regtest
export SATD_IMAGE="${SATD_IMAGE:-ghcr.io/epochbtc/satd:latest}"
export SATD_TLS_HOSTNAME=satd
export SATD_STACK_SUBNET="${SATD_STACK_SUBNET:-10.77.0.0/24}"

COMPOSE_ARGS=(-p "$PROJECT" -f "$STACK_DIR/compose.yml")
for overlay in ${OVERLAYS[@]+"${OVERLAYS[@]}"}; do
    f="$STACK_DIR/compose.$overlay.yml"
    [[ -f "$f" ]] || { echo "smoke.sh: no such overlay: $f" >&2; exit 2; }
    COMPOSE_ARGS+=(-f "$f")
done

compose() { docker compose "${COMPOSE_ARGS[@]}" "$@"; }

WORK="$(mktemp -d)"
cleanup() {
    report_incomplete
    if [[ "$KEEP" == 1 ]]; then
        echo "smoke.sh: --keep given; leaving project $PROJECT running"
    else
        compose down -v --remove-orphans > /dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# Any exit before the summary is a bug in this script, not a clean result.
# Without this, an `set -e` trip in the middle reads as a passing run.
COMPLETED=0
report_incomplete() {
    [[ "$COMPLETED" == 1 ]] || echo "smoke.sh: exited before finishing its checks" >&2
}

FAILURES=0
pass() { echo "ok   — $1"; }
fail() { echo "FAIL — $1"; [[ $# -lt 2 ]] || sed 's/^/       /' <<< "$2"; FAILURES=$((FAILURES + 1)); }

echo "smoke.sh: project=$PROJECT image=$SATD_IMAGE overlays=${OVERLAYS[*]:-none}"
compose up -d --quiet-pull

# --- readiness --------------------------------------------------------------
echo "smoke.sh: waiting for satd to report ready..."
deadline=$(($(date +%s) + 300))
ready=0
while [[ $(date +%s) -lt $deadline ]]; do
    status="$(compose ps --format json satd 2>/dev/null | python3 -c \
        'import sys,json
raw = sys.stdin.read().strip()
if raw:
    for line in raw.splitlines():
        d = json.loads(line)
        print(d.get("Health") or d.get("State") or "")
' 2>/dev/null || true)"
    status="$(awk 'NR==1' <<< "$status")"
    if [[ "$status" == "healthy" ]]; then ready=1; break; fi
    if [[ "$status" == "exited" ]]; then break; fi
    sleep 3
done
if [[ "$ready" == 1 ]]; then
    pass "satd reaches the healthy state"
else
    fail "satd reaches the healthy state" "$(compose logs --no-color --tail 60 satd 2>&1)"
    COMPLETED=1
    echo "$FAILURES failure(s)" >&2
    exit 1
fi

# --- the init container did its job ----------------------------------------
CA="$WORK/ca.crt"
if compose exec -T satd cat /var/lib/satd/tls/ca.crt > "$CA" 2>/dev/null && [[ -s "$CA" ]]; then
    pass "the generated CA is readable from the data volume"
else
    fail "the generated CA is readable from the data volume"
fi

if compose exec -T satd cat /var/lib/satd/bitcoin.conf > "$WORK/conf" 2>/dev/null; then
    if grep -q '@[A-Z_]\+@' "$WORK/conf"; then
        fail "the rendered config has no unsubstituted placeholders" "$(grep '@[A-Z_]\+@' "$WORK/conf")"
    else
        pass "the rendered config has no unsubstituted placeholders"
    fi
    grep -q '^txindex=1' "$WORK/conf" && pass "txindex is on" || fail "txindex is on"
    grep -q '^peerblockfilters=1' "$WORK/conf" && pass "BIP158 filters are served" || fail "BIP158 filters are served"
    grep -q '^prune=0' "$WORK/conf" && pass "pruning is off" || fail "pruning is off"
else
    fail "bitcoin.conf was rendered"
fi

# --- sat-cli inside the container ------------------------------------------
if compose exec -T satd sat-cli -regtest -datadir=/var/lib/satd -rpcport=8332 getblockchaininfo > "$WORK/chaininfo" 2>&1; then
    pass "sat-cli authenticates over the plain loopback listener"
else
    fail "sat-cli authenticates over the plain loopback listener" "$(cat "$WORK/chaininfo")"
fi

# The stable cookie symlink is what every overlay authenticates through.
if compose exec -T satd test -r /var/lib/satd/rpc-cookie 2>/dev/null; then
    pass "rpc-cookie resolves to a readable cookie"
else
    fail "rpc-cookie resolves to a readable cookie"
fi

# --- TLS probes from the host ----------------------------------------------
# `-verify_return_error` turns a verification failure into a non-zero exit
# instead of a warning buried in the handshake transcript.
tls_handshake() {
    local port="$1" servername="$2"
    openssl s_client -connect "127.0.0.1:$port" -servername "$servername" \
        -CAfile "$CA" -verify_return_error -brief < /dev/null 2>&1
}

for probe in "RPC:$SATD_RPC_TLS_PORT" "Electrum:$SATD_ELECTRUM_TLS_PORT" "Esplora:$SATD_ESPLORA_TLS_PORT"; do
    name="${probe%%:*}"; port="${probe##*:}"
    out="$(tls_handshake "$port" localhost || true)"
    if grep -q "Verification: OK" <<< "$out"; then
        pass "$name TLS listener presents a certificate the CA verifies"
    else
        fail "$name TLS listener presents a certificate the CA verifies" "$out"
    fi
done

# Negative control. Without the CA the same handshake must fail, or the
# checks above prove only that something is listening.
out="$(openssl s_client -connect "127.0.0.1:$SATD_RPC_TLS_PORT" -servername localhost \
        -verify_return_error -brief < /dev/null 2>&1 || true)"
if grep -q "Verification: OK" <<< "$out"; then
    fail "an untrusted client is rejected" "handshake succeeded without the CA"
else
    pass "an untrusted client is rejected"
fi

# --- RPC over TLS, end to end ----------------------------------------------
COOKIE="$(compose exec -T satd cat /var/lib/satd/regtest/.cookie 2>/dev/null || true)"
if [[ -n "$COOKIE" ]]; then
    code="$(curl -sS --cacert "$CA" --resolve "localhost:$SATD_RPC_TLS_PORT:127.0.0.1" \
        -u "$COOKIE" -o "$WORK/rpc.json" -w '%{http_code}' \
        --data '{"jsonrpc":"2.0","id":"smoke","method":"getblockchaininfo","params":[]}' \
        -H 'Content-Type: application/json' \
        "https://localhost:$SATD_RPC_TLS_PORT/" 2>&1 || true)"
    if [[ "$code" == "200" ]] && grep -q '"chain"' "$WORK/rpc.json"; then
        pass "JSON-RPC answers over TLS with cookie auth"
    else
        fail "JSON-RPC answers over TLS with cookie auth" "http $code: $(cat "$WORK/rpc.json" 2>/dev/null)"
    fi
else
    fail "the RPC cookie is readable"
fi

# --- mine, then read the chain back through the client surfaces ------------
ADDR="bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw"
compose exec -T satd sat-cli -regtest -datadir=/var/lib/satd -rpcport=8332 generatetoaddress 5 "$ADDR" > /dev/null 2>&1 || true
# `|| true` matters: under `set -e` a failing command substitution in an
# assignment exits the script, and with stderr discarded it would do so
# without printing anything at all.
HEIGHT="$(compose exec -T satd sat-cli -regtest -datadir=/var/lib/satd -rpcport=8332 getblockcount 2>/dev/null | tr -d '\r\n' || true)"
if [[ "$HEIGHT" == "5" ]]; then
    pass "mined 5 regtest blocks"
else
    fail "mined 5 regtest blocks" "height is '$HEIGHT'"
fi

# Esplora over TLS must agree with the node about the tip. Anything less
# than agreement would also be produced by a stale cache or a wrong network.
esplora_tip="$(curl -sS --cacert "$CA" --resolve "localhost:$SATD_ESPLORA_TLS_PORT:127.0.0.1" \
    "https://localhost:$SATD_ESPLORA_TLS_PORT/api/blocks/tip/height" 2>&1 || true)"
if [[ "$esplora_tip" == "$HEIGHT" ]]; then
    pass "Esplora over TLS reports the node's tip height"
else
    fail "Esplora over TLS reports the node's tip height" "got '$esplora_tip', expected '$HEIGHT'"
fi

# Electrum over TLS: a real protocol exchange, not just a handshake.
# `timeout` is not optional here: s_client holds the connection open after
# its stdin closes and Electrum keeps the session up waiting for the next
# request, so without a bound this probe never returns.
electrum_reply="$(printf '{"jsonrpc":"2.0","id":1,"method":"server.version","params":["smoke","1.4"]}\n' \
    | "${TIMEOUT[@]}" 20 openssl s_client -connect "127.0.0.1:$SATD_ELECTRUM_TLS_PORT" -servername localhost \
        -CAfile "$CA" -verify_return_error -quiet 2>/dev/null | head -1 || true)"
if grep -q '"result"' <<< "$electrum_reply"; then
    pass "Electrum over TLS answers server.version"
else
    fail "Electrum over TLS answers server.version" "got: $electrum_reply"
fi

# --- nothing key-like escaped into the image --------------------------------
# The image is redistributed; the CA key must exist only in the volume.
# Captured rather than piped into `grep -q`. In an `if`, a SIGPIPE-failed
# pipeline reads as false and would take the `pass` branch — turning a real
# leak into a green check, which is the one direction this must never fail.
key_listing="$(compose exec -T satd sh -c 'ls /etc/satd/*.key /usr/local/share/satd/*.key 2>/dev/null' 2>/dev/null || true)"
if [[ -n "$(tr -d '[:space:]' <<< "$key_listing")" ]]; then
    fail "the image carries no private keys" "$key_listing"
else
    pass "the image carries no private keys"
fi

# --- overlays ---------------------------------------------------------------
for overlay in ${OVERLAYS[@]+"${OVERLAYS[@]}"}; do
    case "$overlay" in
        lightning)
            echo "smoke.sh: waiting for LND to sync to satd over Neutrino..."
            lnd_deadline=$(($(date +%s) + 240))
            synced=0
            while [[ $(date +%s) -lt $lnd_deadline ]]; do
                info="$(compose exec -T lnd lncli --network=regtest getinfo 2>/dev/null || echo '{}')"
                if python3 -c "
import json,sys
d=json.loads(sys.argv[1] or '{}')
sys.exit(0 if d.get('synced_to_chain') and d.get('block_height')==$HEIGHT else 1)
" "$info" 2>/dev/null; then synced=1; break; fi
                sleep 5
            done
            if [[ "$synced" == 1 ]]; then
                pass "LND syncs to the node's tip in Neutrino mode"
            else
                fail "LND syncs to the node's tip in Neutrino mode" \
                    "$(compose logs --no-color --tail 40 lnd 2>&1)"
            fi
            ;;
        proxy)
            code="$(curl -sS --cacert "$CA" --resolve "localhost:$PROXY_METRICS_PORT:127.0.0.1" \
                -o /dev/null -w '%{http_code}' \
                "https://localhost:$PROXY_METRICS_PORT/readyz" 2>&1 || true)"
            if [[ "$code" == "200" ]]; then
                pass "the proxy serves /readyz over TLS with the stack certificate"
            else
                fail "the proxy serves /readyz over TLS with the stack certificate" "http $code"
            fi

            # RTL only exists when the Lightning overlay is also up. It is a
            # bundled Tier B app, and the rule is that a bundled app ships
            # only if something checks it actually serves — RTL's config is
            # built from environment variables here, which is exactly the
            # kind of thing that silently produces a container that starts
            # and then 502s.
            if [[ " ${OVERLAYS[*]} " == *" lightning "* ]]; then
                rtl_code=""
                rtl_deadline=$(($(date +%s) + 120))
                while [[ $(date +%s) -lt $rtl_deadline ]]; do
                    rtl_code="$(curl -sS --cacert "$CA" --resolve "localhost:$PROXY_RTL_PORT:127.0.0.1" \
                        -o /dev/null -w '%{http_code}' \
                        "https://localhost:$PROXY_RTL_PORT/" 2>&1 || true)"
                    # 2xx or a redirect to the login page both mean RTL is up.
                    [[ "$rtl_code" =~ ^(200|301|302)$ ]] && break
                    sleep 5
                done
                if [[ "$rtl_code" =~ ^(200|301|302)$ ]]; then
                    pass "Ride The Lightning serves over TLS through the proxy"
                else
                    fail "Ride The Lightning serves over TLS through the proxy" \
                        "http $rtl_code
$(compose logs --no-color --tail 30 rtl 2>&1)"
                fi

                # RTL reads APP_PASSWORD and nothing else. Passing it under
                # any other name leaves the password RTL writes into the
                # config it generates -- the literal string "password" -- in
                # front of LND's admin macaroon, on a port the proxy
                # publishes. Serving a login page is not evidence that the
                # login is ours, so both directions are checked.
                #
                # RTL mounts csurf on every route, so the POST needs the
                # token from a prior GET; without it the answer is 403 and
                # both assertions below would fail for the wrong reason.
                #
                # The API lives under RTL's baseHref, /rtl -- express serves
                # the frontend as a static catch-all, so posting to /api/...
                # returns 200 and index.html no matter what the credentials
                # were. Both directions are asserted precisely because a
                # wrong path answers 200 to anything.
                rtl_curl() { curl -sS --cacert "$CA" \
                    --resolve "localhost:$PROXY_RTL_PORT:127.0.0.1" "$@"; }
                # /rtl/login, not /rtl/: the XSRF-TOKEN cookie is set by the
                # single-page catch-all, and express.static answers /rtl/ with
                # index.html before that middleware ever runs.
                rtl_jar="$WORK/rtl-cookies"
                rtl_curl -c "$rtl_jar" -o /dev/null \
                    "https://localhost:$PROXY_RTL_PORT/rtl/login" || true
                # Netscape jar: name is field 6, value is field 7.
                rtl_xsrf="$(awk '$6=="XSRF-TOKEN"{print $7}' "$rtl_jar" 2>/dev/null || true)"
                rtl_login() {
                    local hash
                    hash="$(printf '%s' "$1" | "${SHA256[@]}" | cut -d' ' -f1)"
                    rtl_curl -b "$rtl_jar" -c "$rtl_jar" \
                        -H "X-XSRF-TOKEN: $rtl_xsrf" \
                        -H 'Content-Type: application/json' \
                        -o /dev/null -w '%{http_code}' \
                        -d "{\"authenticateWith\":\"PASSWORD\",\"authenticationValue\":\"$hash\"}" \
                        "https://localhost:$PROXY_RTL_PORT/rtl/api/authenticate" 2>&1 || true
                }
                if [[ -z "$rtl_xsrf" ]]; then
                    fail "RTL rejects its upstream default password" \
                        "no XSRF-TOKEN cookie from RTL; the login check could not run"
                else
                    default_code="$(rtl_login password)"
                    if [[ "$default_code" == "401" ]]; then
                        pass "RTL rejects its upstream default password"
                    else
                        fail "RTL rejects its upstream default password" \
                            "expected http 401, got $default_code -- APP_PASSWORD did not reach RTL"
                    fi
                    ours_code="$(rtl_login "$RTL_PASSWORD")"
                    if [[ "$ours_code" == "200" ]]; then
                        pass "RTL accepts the password the stack configured"
                    else
                        fail "RTL accepts the password the stack configured" \
                            "expected http 200, got $ours_code"
                    fi
                fi
            fi
            ;;
        *)
            echo "note — no automated checks for the '$overlay' overlay; it came up, which is all this asserts"
            ;;
    esac
done

if [[ $FAILURES -ne 0 ]]; then
    COMPLETED=1
    echo "$FAILURES smoke check(s) failed" >&2
    exit 1
fi
COMPLETED=1
echo "all stack smoke checks passed"
