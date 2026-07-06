#!/usr/bin/env bash
# publish-sdk-crates.sh — maintainer-side: publish satd-events-proto and
# satd-events-client to crates.io in dependency order, after the release
# version bump has landed (workspace `version` in the root Cargo.toml, and
# satd-events-client's `satd-events-proto` version requirement, both dropped
# from `-pre`).
#
# satd-events-client depends on satd-events-proto via path+version; proto
# MUST be live on crates.io before client's manifest will resolve there, so
# this always publishes in that order with a wait in between for the index
# to pick up the new version.
#
# Prereqs:
#   - Logged in to crates.io (`cargo login`), or CARGO_REGISTRY_TOKEN set,
#     with publish rights on both crates.
#
# Usage:
#   contrib/release/publish-sdk-crates.sh [--dry-run]
#
# Flags:
#   --dry-run  Verify both crates package cleanly (cargo publish --dry-run)
#              without uploading. Note: proto's dry-run will pass, but
#              client's dry-run cannot fully resolve satd-events-proto
#              until proto is actually live on crates.io — this is the
#              same two-step-order limitation the real publish has.

set -euo pipefail

DRY_RUN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --help|-h)
            sed -n '1,/^set -e/p' "$0" | sed -n '/^# /p' | sed 's/^# \?//'
            exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 64 ;;
    esac
done

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

proto_version=$(cargo pkgid -p satd-events-proto | sed 's/.*[#@]//')

if [[ "$proto_version" == *-pre* ]]; then
    echo "error: satd-events-proto is still at a -pre version ($proto_version)." >&2
    echo "Bump the release version (drop -pre) before publishing." >&2
    exit 1
fi

publish_args=(-p satd-events-proto)
[[ $DRY_RUN -eq 1 ]] && publish_args+=(--dry-run)

echo ">> Publishing satd-events-proto $proto_version"
cargo publish "${publish_args[@]}"

if [[ $DRY_RUN -eq 0 ]]; then
    echo ">> Waiting for satd-events-proto $proto_version to land on the crates.io index"
    for _ in $(seq 1 30); do
        if cargo info "satd-events-proto@=$proto_version" >/dev/null 2>&1; then
            break
        fi
        sleep 10
    done
fi

publish_args=(-p satd-events-client)
[[ $DRY_RUN -eq 1 ]] && publish_args+=(--dry-run)

echo ">> Publishing satd-events-client"
cargo publish "${publish_args[@]}"

echo ">> Done."
