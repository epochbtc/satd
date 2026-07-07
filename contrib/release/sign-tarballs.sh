#!/usr/bin/env bash
# sign-tarballs.sh — maintainer-side: download a release's tarballs +
# CycloneDX SBOMs, sign each with minisign, and upload the .minisig
# files back.
#
# Prereqs:
#   - minisign installed locally
#   - gh (GitHub CLI) authenticated against epochbtc/satd
#   - SATD_MINISIGN_KEY pointing at the encrypted private key, or the
#     default path below works
#
# Usage:
#   contrib/release/sign-tarballs.sh [--dry-run] <tag>
#
# Flags:
#   --dry-run  Sign locally and round-trip verify, but skip the
#              `gh release upload`. Useful before a real release to
#              validate the maintainer's local signing setup.
#
# Optional env:
#   SATD_MINISIGN_KEY    path to encrypted minisign secret key file
#                        (default: ~/devel/epoch/.keys/satd-primary.key)
#   SATD_MINISIGN_PUBKEY base64 pubkey string for verification round-trip
#                        (default: primary pubkey from SECURITY.md)

set -euo pipefail

DRY_RUN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --help|-h)
            sed -n '1,/^set -e/p' "$0" | sed -n '/^# /p' | sed 's/^# \?//'
            exit 0 ;;
        --) shift; break ;;
        -*) echo "unknown flag: $1" >&2; exit 64 ;;
        *) break ;;
    esac
done

TAG="${1:-}"
if [[ -z "$TAG" ]]; then
    echo "usage: $0 [--dry-run] <tag>" >&2
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
trap 'unset -v MINISIGN_PASSPHRASE 2>/dev/null; rm -rf "$work"' EXIT
cd "$work"

echo ">> Downloading release artifacts for $TAG"
# Re-download every time. --skip-existing was considered but rejected:
# if a tarball was tampered with after a previous sign-tarballs run,
# --skip-existing would silently keep the bad copy. The SHA256SUMS
# step below catches that, but only if we actually fetched fresh
# bytes. Tarballs are small; the re-download cost is trivial.
#
# Both tarballs (*.tar.zst) and CycloneDX SBOMs (*.cdx.json) are
# signed with the same minisign primary key. Operators verify both
# with the same recipe (`minisign -Vm <file> -P <pubkey>`).
gh release download "$TAG" \
    --repo epochbtc/satd \
    --pattern '*.tar.zst' \
    --pattern '*.tar.zst.sha256' \
    --pattern '*.cdx.json' \
    --pattern '*.cdx.json.sha256' \
    --pattern 'SHA256SUMS' \
    --clobber

echo ">> Confirming SHA256SUMS"
sha256sum -c SHA256SUMS

# Collect everything we'll sign: tarballs + SBOMs.
shopt -s nullglob
to_sign=( *.tar.zst *.cdx.json )
shopt -u nullglob

if [[ ${#to_sign[@]} -eq 0 ]]; then
    echo "no artifacts found to sign for tag $TAG" >&2
    exit 1
fi

already_signed=()
to_do=()
for f in "${to_sign[@]}"; do
    if [[ -f "${f}.minisig" ]]; then
        already_signed+=("$f")
    else
        to_do+=("$f")
    fi
done

if [[ ${#to_do[@]} -eq 0 ]]; then
    echo ">> All ${#to_sign[@]} artifact(s) already signed, nothing to do"
else
    echo ">> Signing ${#to_do[@]} artifact(s) (${#already_signed[@]} already signed, skipping those)"
    read -rs -p "   minisign passphrase for $KEY (entered once, reused for every artifact): " MINISIGN_PASSPHRASE
    echo
    i=0
    for f in "${to_do[@]}"; do
        i=$((i + 1))
        printf '   [%d/%d] signing %s\n' "$i" "${#to_do[@]}" "$f"
        if ! out=$(printf '%s\n' "$MINISIGN_PASSPHRASE" | minisign -S -s "$KEY" -m "$f" 2>&1); then
            echo "$out" >&2
            echo "signing failed for $f (wrong passphrase?)" >&2
            exit 1
        fi
    done
    unset -v MINISIGN_PASSPHRASE
fi

echo ">> Round-trip verifying every signature against the published pubkey"
for f in "${to_sign[@]}"; do
    minisign -Vm "$f" -P "$PUBKEY" >/dev/null
    echo "   ok: ${f}.minisig"
done

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo
    echo "[dry-run] Skipping upload. Generated signatures:"
    ls -1 *.minisig
    echo "[dry-run] Re-run without --dry-run to publish to the release."
    exit 0
fi

echo ">> Uploading .minisig files to release $TAG"
gh release upload "$TAG" \
    --repo epochbtc/satd \
    --clobber \
    -- *.minisig

echo
echo "Done. Operators can now verify with:"
echo "  minisign -Vm <tarball> -P '${PUBKEY}'"
