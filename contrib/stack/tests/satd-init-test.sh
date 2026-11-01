#!/usr/bin/env bash
# satd-init's guarded keys (status page, metrics over TLS, chainstate
# upgrades) and the JSON-RPC allowlist, against stub binaries.
#
# Each must be written for a satd that has the key and not for one that does
# not: satd refuses an unknown config key, so the second case is the
# difference between a missing feature and a node that will not start.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=1; }

# A satd whose --help does, or does not, list the flag.
mkdir -p "$WORK/new" "$WORK/old"
printf '#!/bin/sh\necho "  --statuspage [<BOOL>]  Serve a status page"\necho "  --metricstlsbind <ADDR:PORT>"\necho "  --upgradechainstate [<BOOL>]"\n' > "$WORK/new/satd"
printf '#!/bin/sh\necho "  --metricsport <PORT>"\n' > "$WORK/old/satd"
chmod +x "$WORK/new/satd" "$WORK/old/satd"

render() { # <satd> <datadir> [env...]
    local bin="$1" dir="$2"; shift 2
    env SATD_DATADIR="$dir" SATD_CONF_TEMPLATE="$STACK/satd/satd.conf.tmpl" SATD_MKCA=true \
        NETWORK=regtest SATD_BIN="$bin" "$@" "$STACK/satd/satd-init" > "$dir.log" 2>&1
}

echo "== satd-init: status page =="
render "$WORK/new/satd" "$WORK/a" SATD_STATUSPAGE=1 \
    SATD_STATUS_ADVERTISE="electrum=ssl://node.local:50012 esplora=https://node.local:8431/api?x=*"
conf="$WORK/a/bitcoin.conf"
if grep -qx 'statuspage=1' "$conf"; then ok "writes statuspage=1"; else bad "no statuspage=1"; fi
if grep -qx 'statusadvertise=electrum=ssl://node.local:50012' "$conf" \
    && grep -qx 'statusadvertise=esplora=https://node.local:8431/api?x=\*' "$conf"; then
    ok "writes each statusadvertise, unglobbed"
else
    bad "statusadvertise lines wrong: $(grep statusadvertise "$conf" || true)"
fi

render "$WORK/old/satd" "$WORK/b" SATD_STATUSPAGE=1 SATD_STATUS_ADVERTISE="electrum=ssl://x:1"
if grep -q '^status' "$WORK/b/bitcoin.conf"; then
    bad "wrote status keys for a satd without the page"
else
    ok "writes nothing for a satd without the page"
fi
if grep -q 'has no status page' "$WORK/b.log"; then ok "and says so"; else bad "silently skipped"; fi

render "$WORK/new/satd" "$WORK/c"
if grep -q '^status' "$WORK/c/bitcoin.conf"; then bad "page on without SATD_STATUSPAGE"; else ok "off by default"; fi

echo "== satd-init: metrics over TLS =="
if grep -qx 'metricstlsbind=0.0.0.0:9336' "$WORK/c/bitcoin.conf" \
    && grep -qx "metricstlscert=$WORK/c/tls/fullchain.crt" "$WORK/c/bitcoin.conf" \
    && grep -qx "metricstlskey=$WORK/c/tls/leaf.key" "$WORK/c/bitcoin.conf"; then
    ok "writes the metrics TLS listener for a satd that has it"
else
    bad "metrics TLS lines wrong: $(grep metricstls "$WORK/c/bitcoin.conf" || true)"
fi
if grep -q '^metricstls' "$WORK/b/bitcoin.conf"; then
    bad "wrote metrics TLS keys for a satd without them"
else
    ok "writes nothing for a satd without them"
fi

echo "== satd-init: chainstate upgrades =="
# On by default for a satd that has the key: a package update that changes the
# chainstate format must not need a shell.
if grep -qx 'upgradechainstate=1' "$WORK/c/bitcoin.conf"; then
    ok "writes upgradechainstate=1 for a satd that has it"
else
    bad "no upgradechainstate=1: $(grep upgradechainstate "$WORK/c/bitcoin.conf" || true)"
fi
if grep -q '^upgradechainstate' "$WORK/b/bitcoin.conf"; then
    bad "wrote upgradechainstate for a satd without it"
else
    ok "writes nothing for a satd without it"
fi

echo "== satd-init: JSON-RPC over TLS from the LAN =="
# rpcallowip gates the published TLS listener as well as the plain one, so a
# list naming only the stack subnet refuses every wallet on the LAN before the
# handshake. The appliance boot test sees that as an `unexpected eof`.
render "$WORK/new/satd" "$WORK/d" SATD_STACK_SUBNET=10.99.0.0/24
if grep -q '^rpctlsbind=0\.0\.0\.0:' "$WORK/d/bitcoin.conf" \
    && grep -qx 'rpcallowip=0.0.0.0/0' "$WORK/d/bitcoin.conf"; then
    ok "the TLS listener admits a client outside the stack subnet"
else
    bad "TLS RPC refuses the LAN: $(grep -E '^rpc(allowip|tlsbind)' "$WORK/d/bitcoin.conf" | tr '\n' ' ')"
fi

echo "== satd-init: conf.d/local.conf overrides =="
# satd takes the first value of a repeated config-file key, so an override of
# a key satd-init writes must come before the rendered one (#843), and a
# [section] block must come after every rendered key, or it would swallow them.
mkdir -p "$WORK/e/conf.d"
printf 'port=19444\ndbcache=4000\n[regtest]\nmaxconnections=12\n' > "$WORK/e/conf.d/local.conf"
render "$WORK/new/satd" "$WORK/e"
conf="$WORK/e/bitcoin.conf"
first_port=$(grep -m1 '^port=' "$conf" || true)
if [[ "$first_port" == "port=19444" ]] && [[ $(grep -c '^port=' "$conf") -eq 2 ]]; then
    ok "a local.conf key satd-init also writes comes first"
else
    bad "first port line is '$first_port': $(grep -n '^port=' "$conf" | tr '\n' ' ')"
fi
section_line=$(grep -n '^\[regtest\]' "$conf" | cut -d: -f1)
last_key_line=$(grep -n '^[a-z]' "$conf" | grep -v 'maxconnections=12' | tail -1 | cut -d: -f1)
if [[ -n "$section_line" && "$section_line" -gt "$last_key_line" ]] && [[ $(tail -1 "$conf") == "maxconnections=12" ]]; then
    ok "a local.conf [section] block comes after every rendered key"
else
    bad "section at line ${section_line:-none}, last rendered key at line $last_key_line"
fi
render "$WORK/new/satd" "$WORK/e"
if [[ $(grep -c '^port=19444' "$conf") -eq 1 ]]; then ok "re-running does not duplicate it"; else bad "duplicated on re-run"; fi

echo
[[ "$fail" -eq 0 ]] || { echo "satd-init-test.sh: FAILED"; exit 1; }
echo "satd-init-test.sh: all checks passed"
