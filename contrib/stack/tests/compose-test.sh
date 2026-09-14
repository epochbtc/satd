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
UMBREL="$ROOT/contrib/packaging/umbrel/epochbtc-satd"

fail=0

# Every check below is a grep against a path. A stale path does not announce
# itself: `grep -q` on a missing file just returns non-zero, so the positive
# assertions fail with a message about the compose file's contents and the
# negative ones ("does not contain X") pass, because nothing contains anything.
# This directory was renamed to carry the store prefix and these checks spent
# that time reading a file that was not there.
for p in "$STACK/compose.yml" "$UMBREL/docker-compose.yml" "$APPLIANCE/files"; do
    [ -e "$p" ] || { echo "compose-test.sh: no such path: $p" >&2; exit 1; }
done
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

echo "== Umbrel host ports =="
# One host port space for the whole Umbrel store. The package used to take
# 8333, 50002 and 3001, which Bitcoin Node, Fulcrum and Ride The Lightning
# own, so it could not be installed beside any of them. Each port must be
# mapped 1:1 with satd listening on it: satd advertises its listen port, so a
# remapped P2P port sends peers to whichever node owns the standard one.
if ! python3 "$HERE/umbrel-ports.py" "$UMBREL"; then
    fail=1
fi

echo "== a package that turns on the status page pins a satd that has it =="
# satd-init writes the page's keys only for a satd that lists --statuspage,
# so an older image would not crash-loop, but the app would open onto a 404:
# Umbrel's app_proxy and StartOS's UI interface both point at /status. The
# page first ships in 0.6.0.
#
# Between releases a package pins a master commit's `sha-` image. That commit
# must be in this checkout's history (so, merged), its satd must have the
# flag, and its satd-init the SATD_STATUSPAGE switch, since the packages run
# the image's satd-init. The CI job checks out full history for this.
if python3 - "$UMBREL/docker-compose.yml" "$ROOT/contrib/packaging/startos/startos/main.ts" \
    "$ROOT/contrib/packaging/startos/startos/manifest/index.ts" "$ROOT" <<'PY'
import re, subprocess, sys
umbrel, main_ts, manifest = (open(p).read() for p in sys.argv[1:4])
root = sys.argv[4]
failed = False
def git(*args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)
def tag_of(text):
    m = re.search(r"ghcr\.io/epochbtc/satd:sha-([0-9a-f]{7,40})@sha256:[0-9a-f]{64}", text)
    if m:
        return m.group(1)
    m = re.search(r"ghcr\.io/epochbtc/satd:([0-9]+)\.([0-9]+)\.([0-9]+)@", text)
    return tuple(int(x) for x in m.groups()) if m else None
def dev_pin_problem(short):
    full = git("rev-parse", "--verify", "--quiet", f"{short}^{{commit}}").stdout.strip()
    if not full:
        return f"sha-{short}, which names no commit in this checkout (a shallow clone, or not merged)"
    if git("merge-base", "--is-ancestor", full, "HEAD").returncode != 0:
        return f"sha-{short}, which is not in this branch's history"
    config = git("show", f"{full}:satd/src/config.rs").stdout
    if "pub statuspage:" not in config:
        return f"sha-{short}, which predates the status page"
    # The packages run the satd-init baked into the image, not this tree's,
    # so the image has to carry the switch that turns the page on. Without
    # it satd starts, serves /metrics, and answers 404 on /status.
    init = git("show", f"{full}:contrib/stack/satd/satd-init").stdout
    if "SATD_STATUSPAGE" not in init:
        return f"sha-{short}, whose satd-init cannot turn the status page on"
    return None
for name, enabled, pinned in [
    ("Umbrel", re.search(r'SATD_STATUSPAGE:\s*"1"', umbrel), tag_of(umbrel)),
    ("StartOS", re.search(r"SATD_STATUSPAGE:\s*'1'", main_ts), tag_of(manifest)),
]:
    if not enabled:
        print(f"  ok    {name} does not turn on the status page")
    elif isinstance(pinned, str):
        problem = dev_pin_problem(pinned)
        if problem:
            print(f"  FAIL  {name} turns on the status page but pins {problem}")
            failed = True
        else:
            print(f"  ok    {name} pins master sha-{pinned}, which has the status page")
    elif pinned is None or pinned < (0, 6, 0):
        print(f"  FAIL  {name} turns on the status page but pins satd {pinned}, which predates it (0.6.0)")
        failed = True
    else:
        print(f"  ok    {name} pins satd {'.'.join(map(str, pinned))} for its status page")
sys.exit(1 if failed else 0)
PY
then :; else fail=1; fi

echo "== Umbrel backups leave the chain out, as StartOS's do =="
# Umbrel backs up the whole app data directory unless told otherwise, and the
# package used to say nothing, so a user with backups on backed up the chain.
# The two packages exclude the same set; StartOS's is guarded by its own tests
# against the directory names satd opens.
if python3 - "$UMBREL/umbrel-app.yml" "$ROOT/contrib/packaging/startos/startos/backups.ts" <<'PY'
import re, sys
umbrel = open(sys.argv[1]).read()
block = re.search(r"^backupIgnore:\n((?:  - .*\n)+)", umbrel, re.M)
u = set()
for line in (block.group(1).splitlines() if block else []):
    path = line.strip()[2:].strip()
    if not path.startswith("data/"):
        print(f"  FAIL  backupIgnore {path} is outside data/, the directory mounted at /var/lib/satd")
        sys.exit(1)
    u.add(path[len("data/"):].rstrip("/"))
ts = re.sub(r"//.*", "", open(sys.argv[2]).read())
excl = re.search(r"exclude: \[(.*?)\]", ts, re.S)
s = {e.rstrip("/") for e in re.findall(r"'([^']+)'", excl.group(1))} - {"rpc-cookie"}
if not u:
    print("  FAIL  umbrel-app.yml has no backupIgnore")
    sys.exit(1)
if u != s:
    print(f"  FAIL  Umbrel and StartOS exclude different sets: only Umbrel {sorted(u - s)}, only StartOS {sorted(s - u)}")
    sys.exit(1)
for d in ("blocks", "chainstate", "chainstate_background"):
    if d not in u or "*/" + d not in u:
        print(f"  FAIL  {d} is not excluded at the root and per network")
        sys.exit(1)
print(f"  ok    both packages exclude the same {len(u)} paths, the chain among them")
PY
then :; else fail=1; fi

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
