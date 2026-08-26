#!/usr/bin/env bash
#
# Fetch the pinned Bitcoin Core tree into ./core/ (gitignored).
#
# The harness runs Core's *unmodified* functional tests, so the tests
# themselves are never vendored into this repo -- only the pin (PIN) and the
# expected file list (<tag>-tests.txt) are checked in. That keeps the public
# repo lean and matches the no-submodules convention.
#
# Environment overrides (no path here is specific to any one machine):
#   SATD_CORE_DIR     where to put the tree            (default: <script dir>/core)
#   SATD_CORE_MIRROR  path to a local bitcoin clone to fetch from instead of
#                     the network -- any existing checkout works, e.g.
#                     SATD_CORE_MIRROR="$HOME/devel/bitcoin"
#   SATD_CORE_REMOTE  upstream URL   (default: https://github.com/bitcoin/bitcoin)
#
# Usage: fetch-core.sh [--force]

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="${SATD_CORE_DIR:-$HERE/core}"
REMOTE="${SATD_CORE_REMOTE:-https://github.com/bitcoin/bitcoin}"
FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

# shellcheck source=/dev/null
source "$HERE/PIN"
: "${CORE_TAG:?PIN is missing CORE_TAG}"
: "${CORE_COMMIT:?PIN is missing CORE_COMMIT}"

# Sparse set: the functional suite plus the data files some tests read.
# share/rpcauth is referenced as RPCAUTH= in the generated config.ini; tests
# that build RPC credentials invoke it directly.
SPARSE_PATHS=(test/functional src/test/data share/rpcauth)

have_pin() {
    [[ -f "$CORE_DIR/.satd-core-commit" ]] &&
        [[ "$(cat "$CORE_DIR/.satd-core-commit")" == "$CORE_COMMIT" ]]
}

if have_pin && [[ $FORCE -eq 0 ]]; then
    echo "core tree already at $CORE_TAG ($CORE_COMMIT); nothing to do"
    exit 0
fi

rm -rf "$CORE_DIR"
mkdir -p "$CORE_DIR"

if [[ -n "${SATD_CORE_MIRROR:-}" ]]; then
    echo "fetching Core $CORE_TAG from local mirror $SATD_CORE_MIRROR"
    resolved="$(git -C "$SATD_CORE_MIRROR" rev-parse "$CORE_COMMIT^{commit}")"
    if [[ "$resolved" != "$CORE_COMMIT" ]]; then
        echo "mirror does not contain pinned commit $CORE_COMMIT" >&2
        exit 1
    fi
    git -C "$SATD_CORE_MIRROR" archive "$CORE_COMMIT" -- "${SPARSE_PATHS[@]}" |
        tar -x -C "$CORE_DIR"
else
    echo "fetching Core $CORE_TAG from $REMOTE (shallow, sparse)"
    tmp="$CORE_DIR/.clone"
    git clone --quiet --depth 1 --branch "$CORE_TAG" \
        --filter=blob:none --sparse "$REMOTE" "$tmp"
    resolved="$(git -C "$tmp" rev-parse HEAD)"
    if [[ "$resolved" != "$CORE_COMMIT" ]]; then
        echo "tag $CORE_TAG resolved to $resolved, expected $CORE_COMMIT" >&2
        echo "the tag moved or PIN is stale -- refusing to continue" >&2
        exit 1
    fi
    git -C "$tmp" sparse-checkout set --no-cone "${SPARSE_PATHS[@]}"
    for p in "${SPARSE_PATHS[@]}"; do
        mkdir -p "$CORE_DIR/$(dirname "$p")"
        cp -a "$tmp/$p" "$CORE_DIR/$(dirname "$p")/"
    done
    rm -rf "$tmp"
fi

# The tree keeps Core's own layout: the framework resolves its config file and
# its data files relative to the source root, so `test/functional` and
# `src/test/data` must sit where Core puts them.

echo "$CORE_COMMIT" > "$CORE_DIR/.satd-core-commit"

# The checked-in list is the offline source of truth for the inventory checker;
# verify the fetched tree agrees with it.
if ! "$HERE/check_inventory.py" --check-tree >/dev/null 2>&1; then
    echo "note: fetched tree does not match $CORE_TAG-tests.txt --" \
         "run check_inventory.py for details" >&2
fi

echo "Core $CORE_TAG ready at $CORE_DIR"
