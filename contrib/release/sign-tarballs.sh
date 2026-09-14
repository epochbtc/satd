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
#   contrib/release/sign-tarballs.sh --images <dir> [--dry-run] <tag>
#
# Flags:
#   --dry-run  Sign locally and round-trip verify, but skip the
#              `gh release upload`. Useful before a real release to
#              validate the maintainer's local signing setup.
#   --images <dir>
#              Sign the appliance images in <dir> instead of the release's
#              tarballs, and upload each image and its .minisig to the
#              release. Images fit GitHub's 2 GiB per-asset limit with room
#              to spare, and a release has no total-size or bandwidth cap,
#              so they are release assets like everything else rather than
#              being hosted off GitHub. An image already attached by the
#              appliance workflow (same name, same size) is not re-uploaded.
#
# Optional env:
#   SATD_MINISIGN_KEY    path to encrypted minisign secret key file
#                        (default: ~/devel/epoch/.keys/satd-primary.key)
#   SATD_MINISIGN_PUBKEY base64 pubkey string for verification round-trip
#                        (default: primary pubkey from SECURITY.md)

set -euo pipefail

DRY_RUN=0
IMAGES_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --images) IMAGES_DIR="${2:-}"; shift 2 ;;
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

if [[ -n "$IMAGES_DIR" ]]; then
    # --- appliance images -------------------------------------------------
    # Each image is signed in its own right, exactly as a tarball is, because
    # the images are ordinary release assets. This script used to sign a
    # manifest of SHA-256 sums instead, on the stated premise that the images
    # were "several GB each" and so had to be hosted off GitHub. Measured,
    # the core qcow2 is ~612 MB and the desktop qcow2 and OVA ~1.34 GiB each,
    # against a 2 GiB per-asset cap and no cap at all on a release's total
    # size or its download bandwidth. The premise was wrong, so the second
    # verification ritual it forced on operators is gone with it.
    [[ -d "$IMAGES_DIR" ]] || { echo "no such directory: $IMAGES_DIR" >&2; exit 1; }
    IMAGES_DIR="$(cd "$IMAGES_DIR" && pwd)"

    # Only the formats that are actually published. `build.sh` leaves the raw
    # disk in the same directory — 6 or 16 GiB, sparse on disk but its full
    # size on the wire — and a .vmdk is an intermediate that ships inside the
    # .ova. Globbing those in when the files were merely hashed was harmless;
    # now that they are uploaded it would push an asset GitHub refuses.
    shopt -s nullglob
    images=( "$IMAGES_DIR"/*.qcow2 "$IMAGES_DIR"/*.ova "$IMAGES_DIR"/*.iso )
    shopt -u nullglob
    if [[ ${#images[@]} -eq 0 ]]; then
        echo "no appliance images (*.qcow2 / *.ova / *.iso) in $IMAGES_DIR" >&2
        exit 1
    fi

    # GitHub rejects an asset of 2 GiB or more, and it rejects it partway
    # through the batch — after the earlier assets are already attached. Fail
    # before anything is uploaded rather than halfway through.
    limit=$((2 * 1024 * 1024 * 1024))
    oversize=()
    for img in "${images[@]}"; do
        [[ "$(stat -c %s "$img")" -ge "$limit" ]] && oversize+=( "$(basename "$img")" )
    done
    if [[ ${#oversize[@]} -gt 0 ]]; then
        echo "at or over GitHub's 2 GiB per-asset limit:" >&2
        printf '  %s\n' "${oversize[@]}" >&2
        exit 1
    fi

    # Decide what to upload before signing anything, so a mismatch is caught
    # before the passphrase is asked for. Whether an image is already
    # published is judged on content, not size: a same-size, different-content
    # asset would otherwise keep its published bytes and receive a signature
    # computed over the local ones, which then verifies nothing. The sums
    # files the appliance build ships alongside each image carry the published
    # hashes, and are cheap to fetch.
    upload=()
    if [[ "$DRY_RUN" -eq 0 ]]; then
        sumsdir="$work/published-sums"
        mkdir -p "$sumsdir"
        gh release download "$TAG" --repo epochbtc/satd \
            --pattern '*.SHA256SUMS' --dir "$sumsdir" > /dev/null 2>&1 || true
        declare -A published_sha=()
        for f in "$sumsdir"/*.SHA256SUMS; do
            [[ -e "$f" ]] || continue
            while read -r sha sname; do
                [[ -n "$sname" ]] && published_sha["$sname"]="$sha"
            done < "$f"
        done

        declare -A present=()
        while read -r aname; do
            [[ -n "$aname" ]] && present["$aname"]=1
        done < <(gh release view "$TAG" --repo epochbtc/satd \
                     --json assets --jq '.assets[].name')

        for img in "${images[@]}"; do
            name="$(basename "$img")"
            if [[ -z "${present[$name]:-}" ]]; then
                upload+=( "$img" )
                continue
            fi
            remote_sha="${published_sha[$name]:-}"
            local_sha="$(sha256sum "$img" | cut -d' ' -f1)"
            if [[ -z "$remote_sha" ]]; then
                echo "$name is on $TAG but no published SHA256SUMS covers it," >&2
                echo "so the local copy cannot be shown to match it. Download the" >&2
                echo "release copy and sign that instead." >&2
                exit 1
            fi
            if [[ "$remote_sha" != "$local_sha" ]]; then
                echo "$name differs from the copy already on $TAG:" >&2
                echo "  published $remote_sha" >&2
                echo "  local     $local_sha" >&2
                echo "Signing the local bytes would publish a signature the" >&2
                echo "released asset fails. Download the release copy and sign that." >&2
                exit 1
            fi
            echo "   already on the release, contents match: $name"
        done
    fi

    echo ">> Signing ${#images[@]} image(s) — this reads several GB"
    read -rs -p "   minisign passphrase for $KEY: " MINISIGN_PASSPHRASE
    echo
    sigs=()
    for img in "${images[@]}"; do
        name="$(basename "$img")"
        printf '   %s\n' "$name"
        if ! out=$(printf '%s\n' "$MINISIGN_PASSPHRASE" \
                   | minisign -S -s "$KEY" -m "$img" -x "$work/$name.minisig" 2>&1); then
            echo "$out" >&2
            echo "signing failed (wrong passphrase?)" >&2
            exit 1
        fi
        # Verify before it goes anywhere, so a bad signature is caught here
        # rather than by the first operator who tries to check one.
        minisign -Vm "$img" -x "$work/$name.minisig" -P "$PUBKEY" > /dev/null
        sigs+=( "$work/$name.minisig" )
    done
    unset -v MINISIGN_PASSPHRASE
    echo "   ok: ${#sigs[@]} signature(s) verified against the published key"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo
        echo "[dry-run] Skipping upload. Generated:"
        ls -1 "${sigs[@]}"
        exit 0
    fi

    assets=( "${upload[@]}" "${sigs[@]}" )
    echo ">> Uploading ${#upload[@]} image(s) and ${#sigs[@]} signature(s) to release $TAG"
    gh release upload "$TAG" --repo epochbtc/satd --clobber -- "${assets[@]}"

    echo
    echo "Done. Operators verify an image with:"
    echo "  minisign -Vm <image> -P '${PUBKEY}'"
    exit 0
fi

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
