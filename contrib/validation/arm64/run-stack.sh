#!/bin/bash
# run-stack.sh — leg 1: the reference stack, built and run natively on arm64.
#
# What this is for: every claim the repository makes about the container
# image and the reference stack has been checked on x86_64 only. The arm64
# half of the image is built by CI and has never had a stack stood up on it.
# This is that run.
#
# It builds the image for linux/arm64, proves the binaries inside are
# actually aarch64 rather than emulated x86_64, and then hands the image to
# the existing smoke.sh — twice, core and with the Lightning + proxy
# overlays. smoke.sh is the test; nothing here re-implements it.
#
#   contrib/validation/arm64/run-stack.sh
#   SATD_IMAGE=satd:arm64 contrib/validation/arm64/run-stack.sh --no-build
#
# Evidence lands in contrib/validation/arm64/evidence/ (gitignored). Paste
# summary.txt back when reporting.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
EVIDENCE="$HERE/evidence"
IMAGE="${SATD_IMAGE:-satd:arm64}"
BUILD=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build) BUILD=0; shift ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "run-stack.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$EVIDENCE"
SUMMARY="$EVIDENCE/summary.txt"
: > "$SUMMARY"

FAILURES=0
say()  { echo "$*" | tee -a "$SUMMARY"; }
ok()   { say "ok   — $1"; }
bad()  { say "FAIL — $1"; [[ $# -lt 2 ]] || say "       $2"; FAILURES=$((FAILURES + 1)); }

say "run-stack.sh on $(uname -sm) at $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
say "image: $IMAGE"
say ""

"$HERE/preflight.sh" --leg stack | tee "$EVIDENCE/preflight.txt"
if [[ "${PIPESTATUS[0]}" -ne 0 ]]; then
    say "run-stack.sh: preflight failed; see evidence/preflight.txt"
    exit 1
fi

# --- build ------------------------------------------------------------------
if [[ "$BUILD" == 1 ]]; then
    say ""
    say "building $IMAGE for linux/arm64 (cold rocksdb build: expect 20-60 min)"
    if docker build --platform linux/arm64 -t "$IMAGE" "$ROOT" > "$EVIDENCE/build.log" 2>&1; then
        ok "the image builds for linux/arm64"
    else
        bad "the image builds for linux/arm64" "see evidence/build.log"
        say ""
        say "run-stack.sh: $FAILURES failure(s)"
        exit 1
    fi
fi

# --- the image really is arm64 ----------------------------------------------
# Three separate claims, because the cheap one is the weakest. Docker's own
# metadata can say arm64 for an image whose binaries are amd64 running under
# emulation, so the ELF header is the one that settles it.
arch="$(docker image inspect --format '{{.Architecture}}' "$IMAGE" 2>/dev/null || echo unknown)"
if [[ "$arch" == "arm64" ]]; then
    ok "docker reports the image architecture as arm64"
else
    bad "docker reports the image architecture as arm64" "got: $arch"
fi

# e_machine lives at offset 18 of an ELF header, little-endian. EM_AARCH64 is
# 183 = 0xb7, so an aarch64 binary reads `b7 00` there and an x86-64 one
# reads `3e 00`.
emachine="$(docker run --rm --entrypoint /bin/sh "$IMAGE" -c \
    'od -An -tx1 -j18 -N2 /usr/local/bin/satd' 2>/dev/null | tr -d ' \n' || true)"
case "$emachine" in
    b700) ok "satd's ELF header says EM_AARCH64 (e_machine=0xb7)" ;;
    3e00) bad "satd's ELF header says EM_AARCH64" "got e_machine=0x3e — this is an x86-64 binary" ;;
    *)    bad "satd's ELF header says EM_AARCH64" "could not read e_machine (got '$emachine')" ;;
esac

# macOS ships bash 3.2, where expanding an empty array under `set -u` is an
# error, so every array expansion here uses the ${a[@]+"${a[@]}"} guard the
# rest of contrib/ uses.
for bin in satd sat-cli sat-tui; do
    entry=(--entrypoint "/usr/local/bin/$bin")
    # satd IS the entrypoint; overriding it would change what is tested.
    [[ "$bin" == satd ]] && entry=()
    if out="$(docker run --rm ${entry[@]+"${entry[@]}"} "$IMAGE" --version 2>&1)"; then
        ok "$bin runs: $(head -1 <<< "$out")"
    else
        bad "$bin runs" "$out"
    fi
done

# --- the stack ---------------------------------------------------------------
# smoke.sh is the actual test. Two runs: core, then the overlays, on separate
# port blocks so a leftover from the first cannot be mistaken for the second.
run_smoke() {
    local label="$1" logname="$2" portbase="$3"; shift 3
    say ""
    say "smoke.sh $label"
    if SATD_IMAGE="$IMAGE" SATD_SMOKE_PORT_BASE="$portbase" \
        "$ROOT/contrib/stack/tests/smoke.sh" "$@" > "$EVIDENCE/$logname" 2>&1; then
        grep '^ok   —' "$EVIDENCE/$logname" | tee -a "$SUMMARY" > /dev/null
        ok "smoke.sh $label: $(grep -c '^ok   —' "$EVIDENCE/$logname") checks passed"
    else
        bad "smoke.sh $label" "see evidence/$logname"
        grep -E '^FAIL' "$EVIDENCE/$logname" | tee -a "$SUMMARY" || true
    fi
}

run_smoke "core" "smoke-core.log" 23400
run_smoke "with lightning + proxy" "smoke-overlays.log" 23600 --with lightning --with proxy

say ""
if [[ "$FAILURES" -eq 0 ]]; then
    say "run-stack.sh: leg 1 passed"
else
    say "run-stack.sh: $FAILURES failure(s) — evidence in $EVIDENCE"
fi
exit $(( FAILURES > 0 ))
