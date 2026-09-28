#!/usr/bin/env bash
# Build rbitcoin's Warnet lab image at the commit pinned in scripts/canary/PINS,
# with the recipe its own repository documents for that image
# (scripts/core-functional/warnet/Dockerfile): a debug build of rbitcoin-node
# inside a Debian bookworm Rust image, a sparse Bitcoin Core checkout for the
# test framework its RPC shim imports, then its Dockerfile.
#
#   scripts/canary/warnet/build-rbitcoin.sh            # -> rbitcoin-warnet:ci
#
# RBITCOIN_SRC (default $HOME/.cache/rbitcoin-src) holds the clone, reused
# between runs; RBITCOIN_WARNET_IMAGE names the result. The base images are
# pulled by digest and tagged with the names rbitcoin's recipe uses, so the
# build does not follow a moving tag.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/canary/PINS
. "$REPO_ROOT/scripts/canary/PINS"
SRC="${RBITCOIN_SRC:-$HOME/.cache/rbitcoin-src}"
OUT="${RBITCOIN_WARNET_IMAGE:-rbitcoin-warnet:ci}"

pinned() { # repo:tag@sha256:... -> pull by digest, tag repo:tag, print repo:tag
    local ref="$1" base="${1%%@*}"
    docker pull -q "${base%:*}@${ref##*@}" > /dev/null
    docker tag "${base%:*}@${ref##*@}" "$base"
    printf '%s' "$base"
}

[ -d "$SRC/.git" ] || git clone --quiet https://github.com/reardencode/rbitcoin "$SRC"
git -C "$SRC" fetch --quiet origin
git -C "$SRC" checkout --quiet --detach "$RBITCOIN_COMMIT"
echo "rbitcoin at $(git -C "$SRC" rev-parse HEAD)"

rust="$(pinned "$RBITCOIN_RUST_IMAGE")"
docker run --rm -v "$SRC":/src -w /src -e CARGO_TARGET_DIR=/src/target/docker \
    -u "$(id -u):$(id -g)" -e CARGO_HOME=/src/target/cargo-home \
    "$rust" cargo build --quiet -p rbitcoin-node
"$SRC/scripts/core-functional/init-submodule.sh"

pinned "$RBITCOIN_BASE_IMAGE" > /dev/null
docker build --quiet -t "$OUT" \
    --build-arg NODE_BIN=target/docker/debug/rbitcoin-node \
    -f "$SRC/scripts/core-functional/warnet/Dockerfile" "$SRC" > /dev/null
echo "built $OUT"
