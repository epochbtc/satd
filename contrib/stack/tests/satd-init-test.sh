#!/usr/bin/env bash
# satd-init's status-page switch, against stub binaries.
#
# The switch must write the page's keys for a satd that has them and nothing
# for one that does not: satd refuses an unknown config key, so the second
# case is the difference between no page and a node that will not start.
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
printf '#!/bin/sh\necho "  --statuspage [<BOOL>]  Serve a status page"\necho "  --metricstlsbind <ADDR:PORT>"\n' > "$WORK/new/satd"
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

echo
[[ "$fail" -eq 0 ]] || { echo "satd-init-test.sh: FAILED"; exit 1; }
echo "satd-init-test.sh: all checks passed"
