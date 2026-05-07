#!/usr/bin/env bash
# diff-build.sh — local reproducibility helper.
#
# Builds the satd flake against two clean checkouts at the same
# commit, hashes the resulting binaries, and (optionally)
# `diffoscope`s them when the hashes mismatch. Mirrors what the
# `reproducibility` job in `.github/workflows/nix.yml` does, but
# offline so packagers / auditors can verify without trusting CI.
#
# Prereqs:
#   - nix (with flakes enabled)
#   - sha256sum (coreutils)
#   - diffoscope (optional; only used when hashes diverge)
#
# Usage:
#   contrib/repro/diff-build.sh <checkout-A> <checkout-B>
#
# Both checkouts must be at the same commit and have identical
# tracked + untracked state (the script asserts this with
# `git status` on each).
#
# Example — same machine, two worktrees:
#   git worktree add /tmp/satd-a HEAD
#   git worktree add /tmp/satd-b HEAD
#   contrib/repro/diff-build.sh /tmp/satd-a /tmp/satd-b
#
# Example — two machines (run on machine A, copy result/bin/satd to
# machine B, then sha256sum on B and compare manually):
#   nix build .#satd
#   sha256sum result/bin/satd
#
# Exit codes:
#   0 — both binaries are byte-identical
#   1 — mismatch (script prints diffoscope summary if available)
#   64 — usage error
#   65 — environment error (nix missing, etc.)

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <checkout-A> <checkout-B>" >&2
    exit 64
fi

A="$1"
B="$2"

if ! command -v nix >/dev/null 2>&1; then
    echo "error: nix not on PATH; install Nix and enable flakes" >&2
    exit 65
fi

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "error: sha256sum not on PATH" >&2
    exit 65
fi

for dir in "$A" "$B"; do
    if [[ ! -d "$dir" ]]; then
        echo "error: checkout not a directory: $dir" >&2
        exit 64
    fi
    if [[ ! -f "$dir/flake.nix" ]]; then
        echo "error: checkout missing flake.nix: $dir" >&2
        exit 64
    fi
done

# Sanity-check that both trees are at the same commit. A diff in
# tracked content silently breaks the repro story; surface it loudly.
sha_a=$(git -C "$A" rev-parse HEAD)
sha_b=$(git -C "$B" rev-parse HEAD)
if [[ "$sha_a" != "$sha_b" ]]; then
    echo "error: checkouts at different commits:" >&2
    echo "  $A: $sha_a" >&2
    echo "  $B: $sha_b" >&2
    exit 64
fi

# Catch dirty working trees that would silently divergence the build.
for dir in "$A" "$B"; do
    if [[ -n "$(git -C "$dir" status --porcelain)" ]]; then
        echo "error: dirty working tree at $dir" >&2
        echo "       a clean tree is required for a meaningful repro check" >&2
        exit 64
    fi
done

build_one() {
    local dir="$1"
    local label="$2"
    echo ">> Building $label ($dir)"
    (
        cd "$dir"
        # --no-write-lock-file so `nix build` doesn't surprise the
        # checkout with a flake.lock edit.
        nix build .#satd --print-build-logs --no-write-lock-file
    )
}

build_one "$A" "replica-A"
build_one "$B" "replica-B"

ha_satd=$(sha256sum "$A/result/bin/satd"    | awk '{print $1}')
hb_satd=$(sha256sum "$B/result/bin/satd"    | awk '{print $1}')
ha_cli=$( sha256sum "$A/result/bin/sat-cli" | awk '{print $1}')
hb_cli=$( sha256sum "$B/result/bin/sat-cli" | awk '{print $1}')

echo
echo "Binary hashes:"
echo "  satd    A=${ha_satd}"
echo "  satd    B=${hb_satd}"
echo "  sat-cli A=${ha_cli}"
echo "  sat-cli B=${hb_cli}"
echo

fail=0
if [[ "$ha_satd" != "$hb_satd" ]]; then
    echo "MISMATCH: satd"    >&2
    fail=1
fi
if [[ "$ha_cli" != "$hb_cli" ]]; then
    echo "MISMATCH: sat-cli" >&2
    fail=1
fi

if [[ "$fail" -ne 0 ]] && command -v diffoscope >/dev/null 2>&1; then
    echo
    echo ">> Running diffoscope against the divergent binaries"
    diffoscope --max-text-report-size 4096 \
        "$A/result/bin/satd" "$B/result/bin/satd" \
        || true
fi

if [[ "$fail" -eq 0 ]]; then
    echo "OK: both replicas produced byte-identical binaries."
    exit 0
fi

exit 1
