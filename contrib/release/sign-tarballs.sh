#!/usr/bin/env bash
# sign-tarballs.sh — maintainer-side: download a release's tarballs,
# sign each with minisign, and upload the .minisig files back.
#
# Prereqs:
#   - minisign installed locally
#   - gh (GitHub CLI) authenticated against epochbtc/satd
#   - SATD_MINISIGN_KEY pointing at the encrypted private key, or the
#     default path below works
#
# Usage:
#   contrib/release/sign-tarballs.sh v0.1.0
#
# Optional env:
#   SATD_MINISIGN_KEY    path to encrypted minisign secret key file
#                        (default: ~/devel/epoch/.keys/satd-primary.key)
#   SATD_MINISIGN_PUBKEY base64 pubkey string for verification round-trip
#                        (default: primary pubkey from SECURITY.md)

set -euo pipefail

TAG="${1:-}"
if [[ -z "$TAG" ]]; then
    echo "usage: $0 <tag>" >&2
    exit 64
fi

KEY="${SATD_MINISIGN_KEY:-${HOME}/devel/epoch/.keys/satd-primary.key}"
PUBKEY="${SATD_MINISIGN_PUBKEY:-RWQeP6MczCgPh6tU03GEMm4HsnGbXte3VT2Bc52TBSR7Q+X7WnL5vfQ3}"

if [[ ! -f "$KEY" ]]; then
    echo "minisign key file not found: $KEY" >&2
    echo "set SATD_MINISIGN_KEY to override the default path" >&2
    exit 1
fi

work=$(mktemp -d -t satd-sign-XXXXXX)
trap 'rm -rf "$work"' EXIT
cd "$work"

echo ">> Downloading release artifacts for $TAG"
gh release download "$TAG" \
    --repo epochbtc/satd \
    --pattern '*.tar.zst' \
    --pattern '*.tar.zst.sha256' \
    --pattern 'SHA256SUMS' \
    --skip-existing

echo ">> Confirming SHA256SUMS"
sha256sum -c SHA256SUMS

echo ">> Signing each tarball"
echo "   passphrase will be requested once; minisign caches in-process"
for f in *.tar.zst; do
    if [[ -f "${f}.minisig" ]]; then
        echo "   skip $f (signature already present)"
        continue
    fi
    minisign -Sm "$f" -s "$KEY"
done

echo ">> Round-trip verifying every signature against the published pubkey"
for f in *.tar.zst; do
    minisign -Vm "$f" -P "$PUBKEY" >/dev/null
    echo "   ok: ${f}.minisig"
done

echo ">> Uploading .minisig files to release $TAG"
gh release upload "$TAG" \
    --repo epochbtc/satd \
    --clobber \
    -- *.minisig

echo
echo "Done. Operators can now verify with:"
echo "  minisign -Vm <tarball> -P '${PUBKEY}'"
