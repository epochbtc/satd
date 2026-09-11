#!/bin/bash
# pack-s9pk.sh — leg 2: build the aarch64 StartOS package on this machine.
#
# `start-cli s9pk pack --arch=aarch64` resolves the image pinned in
# startos/manifest/index.ts and embeds its layers, so the .s9pk is
# self-contained and a StartOS server never contacts a registry to install
# it. Packing does not need an arm64 host — it is done here so the artifact
# and the server that installs it come from the same machine, and so a
# failure is attributable.
#
#   contrib/validation/arm64/pack-s9pk.sh
#
# Leaves satd_aarch64.s9pk in contrib/packaging/startos/ (gitignored) and
# records its digest in evidence/s9pk.txt. Leg 3 sideloads that file.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PKG="$ROOT/contrib/packaging/startos"
EVIDENCE="$HERE/evidence"
CLI_TAG="start-cli/v2.0.0"

mkdir -p "$EVIDENCE"
OUT="$EVIDENCE/s9pk.txt"
: > "$OUT"
say() { echo "$*" | tee -a "$OUT"; }

say "pack-s9pk.sh on $(uname -sm) at $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# --- start-cli ---------------------------------------------------------------
# The release carries one static binary per platform. Downloaded into the
# evidence directory rather than anywhere on PATH: this harness should not
# install things system-wide behind your back.
if ! command -v start-cli > /dev/null 2>&1; then
    case "$(uname -s)/$(uname -m)" in
        Darwin/arm64)  asset=start-cli_aarch64-macos ;;
        Darwin/x86_64) asset=start-cli_x86_64-macos ;;
        Linux/aarch64) asset=start-cli_aarch64-linux ;;
        Linux/x86_64)  asset=start-cli_x86_64-linux ;;
        *) say "pack-s9pk.sh: no start-cli asset for $(uname -sm)"; exit 1 ;;
    esac
    say "start-cli is not on PATH; fetching $asset from $CLI_TAG"
    if ! gh release download "$CLI_TAG" --repo Start9Labs/start-technologies \
            --pattern "$asset" --output "$EVIDENCE/start-cli" --clobber; then
        say "pack-s9pk.sh: could not download $asset"
        say "  Fetch it by hand from https://github.com/Start9Labs/start-technologies/releases/tag/${CLI_TAG//\//%2F}"
        exit 1
    fi
    chmod +x "$EVIDENCE/start-cli"
    PATH="$EVIDENCE:$PATH"
    export PATH
fi
say "start-cli: $(start-cli --version 2>&1 | head -1)"

# --- the packaging workspace -------------------------------------------------
# start-cli looks for a .startos/ marker in the directory *containing* the
# package, and holds a per-machine signing key there. `init-workspace` also
# clones the whole start-technologies monorepo beside it, which is not
# wanted — the marker directory and the key are all that is required.
if [[ ! -d "$ROOT/contrib/packaging/.startos" ]]; then
    say "creating the packaging workspace marker at contrib/packaging/.startos"
    mkdir -p "$ROOT/contrib/packaging/.startos"
fi
if [[ ! -f "$HOME/.startos/developer.key.pem" ]]; then
    say "minting a developer signing key (start-cli init-key)"
    start-cli init-key || { say "pack-s9pk.sh: start-cli init-key failed"; exit 1; }
fi

# --- dependencies the SDK's makefile checks for ------------------------------
for c in npm git jq tar2sqfs; do
    if ! command -v "$c" > /dev/null 2>&1; then
        say "pack-s9pk.sh: $c is required and missing"
        [[ "$c" == tar2sqfs ]] && say "  tar2sqfs is squashfs-tools-ng, not squashfs-tools. See this directory's README."
        exit 1
    fi
done

# --- pack --------------------------------------------------------------------
cd "$PKG" || exit 1
say ""
say "running: make arm   (npm ci, tsc, tests, ncc, then pack --arch=aarch64)"
if ! make arm 2>&1 | tee "$EVIDENCE/pack.log"; then
    say "pack-s9pk.sh: make arm failed; see evidence/pack.log"
    exit 1
fi

artifact="$PKG/satd_aarch64.s9pk"
if [[ ! -f "$artifact" ]]; then
    say "pack-s9pk.sh: make arm reported success but $artifact does not exist"
    exit 1
fi

# --- what was produced -------------------------------------------------------
if command -v sha256sum > /dev/null 2>&1; then digest="$(sha256sum "$artifact")"
elif command -v shasum > /dev/null 2>&1; then digest="$(shasum -a 256 "$artifact")"
else digest="(no sha256 tool)"; fi

say ""
say "artifact: $artifact"
say "size:     $(ls -lh "$artifact" | awk '{print $5}')"
say "sha256:   ${digest%% *}"
manifest="$(start-cli s9pk inspect "$artifact" manifest 2>/dev/null)"
if [[ -n "$manifest" ]]; then
    say "arch:     $(jq -r '[.images[].arch // []] | flatten | unique | join(", ")' <<< "$manifest")"
    say "version:  $(jq -r .version <<< "$manifest")"
    say "gitHash:  $(jq -r .gitHash <<< "$manifest")"
fi
say ""
say "pack-s9pk.sh: leg 2 done. Leg 3 sideloads this file onto an aarch64 StartOS server."
