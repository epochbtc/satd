#!/usr/bin/env bash
# Static checks on the compose definitions and the appliance CLI.
#
# No docker, no network: these are the invariants that a round of review
# found broken by inspection, and each one is cheap enough to assert on
# every push. Anything needing a running stack belongs in smoke.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$STACK/../.." && pwd)"
APPLIANCE="$ROOT/contrib/appliance"
UMBREL="$ROOT/contrib/packaging/umbrel/satd"

fail=0
ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

echo "== chain selector =="
# satd has bare --signet/--regtest/--testnet4 but no bare --mainnet, so a
# `--${NETWORK}` render exits on an unknown argument for the one network
# most deployments actually want. --chain= takes every name.
for f in "$STACK/compose.yml" "$UMBREL/docker-compose.yml"; do
    n="$(basename "$(dirname "$f")")/$(basename "$f")"
    if grep -qE '^\s+- --\$\{[A-Z_]*NETWORK' "$f"; then
        bad "$n renders a bare --\${NETWORK} flag (no such flag for mainnet)"
    else
        ok "$n does not render a bare --\${NETWORK} flag"
    fi
    check "$n selects the chain with --chain=" \
        "grep -qE '^\s+- --chain=\\\$\{[A-Z_]*NETWORK' '$f'"
done

echo "== RTL credentials =="
# RTL v0.15.x reads APP_PASSWORD and nothing else; with it unset it serves
# the config it generates, whose password is the literal "password", in
# front of LND's admin macaroon.
check "compose.lightning.yml sets APP_PASSWORD" \
    "grep -q 'APP_PASSWORD:' '$STACK/compose.lightning.yml'"
check "compose.lightning.yml does not pass RTL_PASSWORD to the container" \
    "! grep -qE '^\s+RTL_PASSWORD:' '$STACK/compose.lightning.yml'"
check "the RTL password is required, not defaulted" \
    "grep -qE 'APP_PASSWORD: \\\$\{RTL_PASSWORD:\?' '$STACK/compose.lightning.yml'"

echo "== no plaintext web UI on a public interface =="
# A published port also bypasses the appliance's inbound nftables chain, so
# "it is only on the LAN" is the whole exposure. Every host-published port
# must be either loopback-bound or on the allow-list below, which is the
# point: a new public port fails here until someone says why it is safe.
if ! python3 "$HERE/published-ports.py" "$STACK" "$APPLIANCE/files" "$UMBREL"; then
    fail=1
fi

check "the proxy serves BTCPay over TLS" \
    "grep -q 'btcpay:49392' '$STACK/caddy/Caddyfile'"
check "the proxy publishes the BTCPay TLS port" \
    "grep -q 'PROXY_BTCPAY_PORT' '$STACK/compose.proxy.yml'"

echo "== every required secret has a generator =="
# Overlays declare secrets as ${VAR:?...}, which is a hard compose parse
# error rather than an empty string. An overlay the appliance can enable but
# has no branch for cannot be started, stopped, or moved between networks.
CLI="$APPLIANCE/bin/satd-appliance"
for f in "$STACK"/compose.*.yml; do
    overlay="$(basename "$f" | sed 's/^compose\.//; s/\.yml$//')"
    [[ "$overlay" == "yml" || "$overlay" == "proxy" ]] && continue
    while read -r var; do
        if grep -q "^\s*grep -q '\^${var}=' " "$CLI"; then
            ok "$overlay: satd-appliance generates $var"
        else
            bad "$overlay declares \${$var:?} but satd-appliance never generates it"
        fi
    done < <(grep -oE '\$\{[A-Z_]+:\?' "$f" | sed 's/\${//; s/:?//' | sort -u)
done

echo "== the appliance loads secrets where it runs compose =="
# Sourcing at each call site is what went wrong: `set-network` and the
# teardown in `disable` did not, so they failed to parse the overlay files.
check "run_compose sources overlay.env itself" \
    "awk '/^run_compose\(\)/,/^}/' '$CLI' | grep -q 'overlay.env'"
check "disable does not drop the marker after a failed teardown" \
    "! awk '/^cmd_disable\(\)/,/^}/' '$CLI' | grep -q 'run_compose down --remove-orphans || true'"

echo "== the installer creates what it mounts on =="
# rsync excludes the pseudo-filesystems, so the chroot mountpoints do not
# exist on the new root. The first bind mount then fails under `set -e`,
# after the disk is formatted and before GRUB runs.
check "install creates the chroot mountpoints" \
    "awk '/^cmd_install_to_disk\(\)/,/^}/' '$CLI' | grep -q 'mkdir -p \"\$mnt\"/{dev,proc,sys'"
check "install unwinds its mounts on failure" \
    "awk '/^cmd_install_to_disk\(\)/,/^}/' '$CLI' | grep -q 'trap install_cleanup EXIT'"

echo
if [[ "$fail" -ne 0 ]]; then
    echo "compose-test.sh: FAILED"
    exit 1
fi
echo "compose-test.sh: all checks passed"
