#!/usr/bin/env bash
# The checks read $out* inside eval strings, which shellcheck cannot see.
# shellcheck disable=SC2034
# contract-test.sh — the Warnet lab image's layout contract, checked without
# docker. Warnet's bitcoincore chart assumes Bitcoin Core's image layout; each
# check names the chart behaviour that depends on it. compose-test.sh proves
# the same contract against a running container.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
W="$(cd "$HERE/.." && pwd)"
fail=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

for p in "$W/Dockerfile" "$W/entrypoint.sh" "$W/bitcoin-cli"; do
    [ -e "$p" ] || { echo "contract-test.sh: no such path: $p" >&2; exit 1; }
done

echo "== Dockerfile =="
check "bitcoind is a symlink to satd (liveness probe is pidof bitcoind)" \
    "grep -q 'ln -s /usr/local/bin/satd /usr/local/bin/bitcoind' '$W/Dockerfile'"
check "bitcoin-cli is installed on PATH (warnet bitcoin rpc execs it)" \
    "grep -q 'COPY bitcoin-cli /usr/local/bin/bitcoin-cli' '$W/Dockerfile'"
check "the image runs as root (the chart mounts bitcoin.conf under /root)" \
    "grep -q '^USER root' '$W/Dockerfile'"
check "the datadir is /root/.bitcoin" \
    "grep -q '^ENV BITCOIN_DATA=/root/.bitcoin' '$W/Dockerfile'"
check "the entrypoint needs no arguments (the chart passes none)" \
    "grep -q '^ENTRYPOINT \[\"/entrypoint.sh\"\]' '$W/Dockerfile'"

echo "== entrypoint.sh =="
check "execs through tini, as bitcoind" \
    "grep -q '^exec /usr/bin/tini -- /usr/local/bin/bitcoind \"\$@\"' '$W/entrypoint.sh'"
check "supplies -datadir when none is given" \
    "grep -q 'set -- \"-datadir=\$DATADIR\" \"\$@\"' '$W/entrypoint.sh'"
check "is POSIX sh (the base image has no bash guarantee)" \
    "head -n1 '$W/entrypoint.sh' | grep -q '^#!/bin/sh'"

echo "== bitcoin-cli adapter =="
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# A stub sat-cli that prints one argument per line.
printf '#!/bin/sh\nfor a in "$@"; do printf "%%s\\n" "$a"; done\n' > "$tmp/sat-cli"
chmod +x "$tmp/sat-cli"
cp "$HERE/tank1.conf" "$tmp/bitcoin.conf"
run() { BITCOIN_DATA="$tmp" SAT_CLI="$tmp/sat-cli" sh "$W/bitcoin-cli" "$@"; }

out="$(run getblockcount)"
for want in "-datadir=$tmp" -regtest -rpcport=18443 -rpcuser=user -rpcpassword=gn0cchi getblockcount; do
    check "passes $want from the chart's bitcoin.conf" "grep -qxF -- '$want' <<< \"\$out\""
done
check "the method comes after the adapter's flags" \
    "[ \"\$(printf '%s\n' \"\$out\" | tail -n1)\" = getblockcount ]"

out="$(run -rpcuser=alice -rpcpassword=secret getblockcount)"
check "a command-line -rpcuser wins over the file" "grep -qxF -- -rpcuser=alice <<< \"\$out\" && ! grep -qxF -- -rpcuser=user <<< \"\$out\""
check "a command-line flag is passed once, not repeated (sat-cli refuses repeats)" \
    "[ \"\$(grep -c -- '^-rpcuser=' <<< \"\$out\")\" = 1 ]"
out2="$(run -regtest -datadir="$tmp" getblockcount)"
check "a command-line -regtest or -datadir is not added again" \
    "[ \"\$(grep -cx -- '-regtest' <<< \"\$out2\")\" = 1 ] && [ \"\$(grep -c -- '^-datadir=' <<< \"\$out2\")\" = 1 ]"
out3="$(run getblock -rpcuser=param)"
check "arguments after the method are left alone" \
    "grep -qxF -- -rpcuser=user <<< \"\$out3\" && [ \"\$(printf '%s\\n' \"\$out3\" | tail -n1)\" = -rpcuser=param ]"
check "a command-line -rpcpassword wins over the file" "! grep -qxF -- -rpcpassword=gn0cchi <<< \"\$out\""

printf 'rpcuser=top\n[regtest]\nrpcuser=section\n' > "$tmp/bitcoin.conf"
out="$(run getblockcount)"
check "reads only top-level keys, never a [section] value" \
    "grep -qxF -- -rpcuser=top <<< \"\$out\" && ! grep -q section <<< \"\$out\""
check "no regtest=1 in the file means no -regtest" "! grep -qxF -- -regtest <<< \"\$out\""

rm "$tmp/bitcoin.conf"
check "a missing bitcoin.conf is not an error" "run getblockcount > /dev/null"

if run -generate 1 > /dev/null 2> "$tmp/err"; then
    bad "-generate is refused"
else
    check "-generate is refused, naming the keyless alternative" "grep -q generatetodescriptor '$tmp/err'"
fi

if [ "$fail" -ne 0 ]; then echo "contract-test.sh: FAILED"; exit 1; fi
echo "contract-test.sh: all checks passed"
