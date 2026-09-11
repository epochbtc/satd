#!/bin/bash
# preflight.sh — report whether this machine can run the arm64 validation.
#
# Everything the arm64 legs need, checked and named in one pass, because the
# alternative is discovering a missing `tar2sqfs` after a forty-minute image
# build. Prints a line per check and exits non-zero if a hard requirement is
# missing; soft requirements (needed only by a later leg) are reported as
# `warn` and do not fail the run.
#
#   contrib/validation/arm64/preflight.sh
#   contrib/validation/arm64/preflight.sh --leg stack     # only leg 1's needs
set -uo pipefail

LEG=all
while [[ $# -gt 0 ]]; do
    case "$1" in
        --leg) LEG="$2"; shift 2 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "preflight.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

HARD=0
ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; [[ $# -lt 2 ]] || printf '        %s\n' "$2"; HARD=1; }
warn() { printf '  warn  %s\n' "$1"; [[ $# -lt 2 ]] || printf '        %s\n' "$2"; }

have() { command -v "$1" > /dev/null 2>&1; }

echo "== machine =="
uname_m="$(uname -m)"
case "$uname_m" in
    arm64|aarch64) ok "CPU is $uname_m" ;;
    *) bad "CPU is $uname_m, not arm64" \
           "This harness exists to test arm64 natively; on x86_64 everything below would run under emulation and prove nothing about the arch." ;;
esac
printf '  info  %s\n' "$(uname -sr)"

echo
echo "== leg 1: the reference stack =="
if have docker; then
    ok "docker is installed"
    if docker info > /dev/null 2>&1; then
        ok "the docker daemon is reachable"
        srv_arch="$(docker version --format '{{.Server.Arch}}' 2>/dev/null || echo unknown)"
        if [[ "$srv_arch" == "arm64" ]]; then
            ok "the docker server reports arch=arm64"
        else
            bad "the docker server reports arch=$srv_arch" \
                "Containers would run emulated. On Docker Desktop, turn off Rosetta for x86_64/amd64 emulation, or check you are not talking to a remote amd64 daemon."
        fi
        if docker compose version > /dev/null 2>&1; then
            ok "docker compose v2 is available"
        else
            bad "docker compose v2 is not available" "smoke.sh uses \`docker compose\`, not \`docker-compose\`."
        fi
    else
        bad "the docker daemon is not reachable" "Start Docker Desktop and re-run."
    fi
else
    bad "docker is not installed"
fi

# smoke.sh's own requirements. It preflights these itself and will say the
# same things; checking here means one report rather than two.
for c in curl python3 awk sed grep cut head tr od dirname; do
    have "$c" || bad "$c is missing"
done
have curl && ok "curl, python3 and the standard text tools are present"

if have timeout; then ok "timeout is present"
elif have gtimeout; then ok "gtimeout is present (Homebrew coreutils)"
else bad "neither timeout nor gtimeout" "brew install coreutils"; fi

if have sha256sum || have gsha256sum; then ok "sha256sum is present"
elif have shasum; then ok "shasum is present (smoke.sh uses it as sha256sum)"
else bad "no sha256sum and no shasum" "brew install coreutils"; fi

if have openssl; then
    v="$(openssl version 2>/dev/null)"
    if grep -qi libressl <<< "$v"; then
        bad "openssl is $v" \
            "LibreSSL is macOS's /usr/bin/openssl and the TLS probes need real OpenSSL: brew install openssl@3, then put its bin directory first on PATH."
    else
        ok "openssl is $v"
    fi
else
    bad "openssl is missing" "brew install openssl@3"
fi

# Disk. The image build is the expensive part: a cold rocksdb/C++ build plus
# the overlay images.
if have df; then
    avail_kb="$(df -Pk . | awk 'NR==2{print $4}')"
    avail_gb=$((avail_kb / 1024 / 1024))
    if [[ "$avail_gb" -ge 40 ]]; then ok "${avail_gb} GB free on this filesystem"
    else warn "${avail_gb} GB free on this filesystem" "The image build plus the overlay images want roughly 40 GB. Docker Desktop's disk image has its own limit — check Settings > Resources too."; fi
fi

if [[ "$LEG" == "stack" ]]; then
    echo
    [[ "$HARD" == 0 ]] && echo "preflight: ready for leg 1" || echo "preflight: NOT ready — see FAIL lines above"
    exit "$HARD"
fi

echo
echo "== leg 2: packing the StartOS .s9pk =="
if have node; then
    major="$(node --version | sed 's/^v//; s/\..*//')"
    if [[ "$major" -ge 22 ]]; then ok "node $(node --version)"
    else bad "node $(node --version) is too old" "The package's tests are .ts run under \`node --test\`, which needs --experimental-strip-types (22.6+). brew install node@22"; fi
else
    bad "node is not installed" "brew install node@22"
fi
have npm && ok "npm $(npm --version)" || bad "npm is not installed"

if have start-cli; then
    ok "start-cli $(start-cli --version 2>/dev/null | head -1)"
else
    warn "start-cli is not on PATH" \
         "pack-s9pk.sh downloads start-cli_aarch64-macos from Start9Labs/start-technologies (tag start-cli/v2.0.0) if it is absent."
fi

# The one genuine unknown. `start-cli s9pk pack` shells out to tar2sqfs to
# build each layer's squashfs. It is squashfs-tools-ng, NOT the more common
# squashfs-tools/mksquashfs, and whether Homebrew carries it on arm64 macOS
# has not been checked from here — so this is reported, not assumed.
if have tar2sqfs; then
    ok "tar2sqfs is present"
else
    warn "tar2sqfs is not on PATH" \
         "start-cli s9pk pack needs it (squashfs-tools-ng, not squashfs-tools). Try \`brew install squashfs-tools-ng\`; if there is no such formula, see the README's note on packing in a Linux container instead."
fi

echo
if [[ "$HARD" == 0 ]]; then
    echo "preflight: ready"
else
    echo "preflight: NOT ready — see FAIL lines above"
fi
exit "$HARD"
