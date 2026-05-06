#!/usr/bin/env bash
# verify-tag.sh — fetch the maintainer's live SSH pubkey set from
# GitHub and verify the given tag against it.
#
# This is the canonical operator-side path. The repo intentionally
# does not pin a static .allowed_signers file; the maintainer's keys
# rotate as machines come and go, so we delegate to whatever
# https://github.com/<maintainer>.keys publishes at verification time.
#
# Usage:
#   contrib/release/verify-tag.sh v0.1.0
#
# Optional env:
#   SATD_GH_USER  maintainer's GitHub handle (default: bkeroack)
#   SATD_EMAIL    principal email used in the allowed-signers grammar
#                 (default: ben@keroack.com)

set -euo pipefail

TAG="${1:-}"
if [[ -z "$TAG" ]]; then
    echo "usage: $0 <git tag>" >&2
    exit 64
fi

GH_USER="${SATD_GH_USER:-bkeroack}"
EMAIL="${SATD_EMAIL:-ben@keroack.com}"
URL="https://github.com/${GH_USER}.keys"

tmp=$(mktemp -t satd-allowed-signers-XXXXXX)
trap 'rm -f "$tmp"' EXIT

echo ">> Fetching ${URL}"
curl --proto '=https' --tlsv1.2 -fsSL "$URL" \
    | awk -v email="$EMAIL" '
        NF >= 2 { print email " namespaces=\"git\" " $0 }
      ' \
    > "$tmp"

if [[ ! -s "$tmp" ]]; then
    echo "Empty keys list from $URL — refusing to verify against an empty allowlist." >&2
    exit 1
fi

key_count=$(wc -l < "$tmp")
echo ">> $key_count key(s) loaded; verifying $TAG"
git -c gpg.ssh.allowedSignersFile="$tmp" verify-tag "$TAG"
echo "   ok"
