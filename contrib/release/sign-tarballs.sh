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
#                        (default: ~/.minisign/minisign.key, minisign's own default)
#   SATD_MINISIGN_PUBKEY base64 pubkey string for verification round-trip
#                        (default: primary pubkey from SECURITY.md)
#   SATD_SIGN_DIR        working directory for the tarball path
#                        (default: ${XDG_CACHE_HOME:-~/.cache}/satd-sign/<tag>)
#
# Working directory (tarball path):
#   Downloads go to a fixed per-tag directory, created mode 0700, which is
#   kept when a run fails and removed after a successful upload or
#   --dry-run. A rerun after a failure (wrong passphrase, failed upload)
#   reuses the tarballs and SBOMs already there when their SHA-256 matches
#   both the release's fresh SHA256SUMS and the asset digest GitHub reports,
#   and keeps every .minisig that still verifies. The script refuses a
#   directory it does not own, a symlink, or one that group or others can
#   write to, and it uses (and later deletes) only a directory it created
#   itself: an existing directory without its marker file is refused, never
#   chmod'd or removed. --images uses a temporary directory, as before.

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

KEY="${SATD_MINISIGN_KEY:-${HOME}/.minisign/minisign.key}"
PUBKEY="${SATD_MINISIGN_PUBKEY:-RWQeP6MczCgPh6tU03GEMm4HsnGbXte3VT2Bc52TBSR7Q+X7WnL5vfQ3}"

if [[ ! -f "$KEY" ]]; then
    echo "minisign key file not found: $KEY" >&2
    echo "set SATD_MINISIGN_KEY to override the default path" >&2
    exit 1
fi

REPO="epochbtc/satd"

if [[ -n "$IMAGES_DIR" ]]; then
    work=$(mktemp -d -t satd-sign-XXXXXX)
    trap 'unset -v MINISIGN_PASSPHRASE 2>/dev/null; rm -rf "$work"' EXIT
    cd "$work"

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
        gh release download "$TAG" --repo "$REPO" \
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
        done < <(gh release view "$TAG" --repo "$REPO" \
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
    gh release upload "$TAG" --repo "$REPO" --clobber -- "${assets[@]}"

    echo
    echo "Done. Operators verify an image with:"
    echo "  minisign -Vm <image> -P '${PUBKEY}'"
    exit 0
fi

# --- tarballs and SBOMs ----------------------------------------------------
# The tag becomes a path component, so it must not be able to climb out of
# the cache directory.
if [[ ! "$TAG" =~ ^[A-Za-z0-9._+-]+$ || "$TAG" == "." || "$TAG" == ".." ]]; then
    echo "refusing tag with unexpected characters: $TAG" >&2
    exit 64
fi

work="${SATD_SIGN_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/satd-sign/$TAG}"
# "/path/link/" would make every test below look through the symlink.
while [[ "$work" == */ && "$work" != / ]]; do work="${work%/}"; done

# The script deletes this directory after a successful run, so it must only
# ever use one it made. It drops this marker in a directory when it creates
# it; an existing directory without the marker (an operator's own directory
# named by SATD_SIGN_DIR, say) is refused, and is never chmod'd or removed.
MARKER=".sign-tarballs-workdir"

# The default path is predictable, and so is anything an operator points
# SATD_SIGN_DIR at under /tmp. Another local user who pre-creates it could
# swap a tarball between the hash check and the signature. Only a directory
# this user owns, that is not a symlink, and that nobody else can write to is
# used.
check_dir() {
    # $1: the path to test, $2: the name to report it under.
    local owner mode
    owner="$(stat -c %u -- "$1")"
    if [[ "$owner" != "$(id -u)" ]]; then
        echo "refusing $2: owned by uid $owner, not $(id -u)" >&2
        exit 1
    fi
    mode="$(stat -c %a -- "$1")"
    if (( 8#$mode & 8#022 )); then
        echo "refusing $2: mode $mode lets group or others write to it" >&2
        exit 1
    fi
    if [[ ! -f "$1/$MARKER" || -L "$1/$MARKER" ]]; then
        echo "refusing $2: it exists but this script did not create it (no $MARKER)." >&2
        echo "Point SATD_SIGN_DIR at a path that does not exist yet; the script creates it." >&2
        exit 1
    fi
}

if [[ ! -e "$work" && ! -L "$work" ]]; then
    (umask 077 && mkdir -p -- "$(dirname -- "$work")")
    mkdir -m 700 -- "$work"
    : > "$work/$MARKER"
fi
if [[ -L "$work" ]]; then
    echo "refusing $work: is a symlink" >&2
    exit 1
fi
if [[ ! -d "$work" ]]; then
    echo "refusing $work: not a directory" >&2
    exit 1
fi
check_dir "$work" "$work"
expect="$(cd -- "$(dirname -- "$work")" && pwd -P)/$(basename -- "$work")"
expect="${expect#/}"; expect="/$expect"
chmod 700 -- "$work"

# The checks above went by name. If the parent directory is writable by
# someone else, the name can be pointed somewhere else before the cd, so
# check again where the cd actually landed.
cd -- "$work"
if [[ "$(pwd -P)" != "$expect" ]]; then
    echo "refusing $work: it changed between the check and the cd (now $(pwd -P))" >&2
    exit 1
fi
check_dir . "$work"
work="$expect"

finished=0
on_exit() {
    unset -v MINISIGN_PASSPHRASE 2>/dev/null
    if [[ "$finished" -eq 1 ]]; then
        cd / && rm -rf -- "$work"
        echo "Removed working directory $work"
    else
        echo "Kept working directory $work; a rerun reuses what still matches." >&2
    fi
}
trap on_exit EXIT
echo ">> Working directory: $work"

# Both tarballs (*.tar.zst) and CycloneDX SBOMs (*.cdx.json) are signed with
# the same minisign primary key. Operators verify both with the same recipe
# (`minisign -Vm <file> -P <pubkey>`).
#
# The small files (SHA256SUMS and the per-file .sha256) are fetched fresh on
# every run. A tarball or SBOM left by an earlier run is kept only if its
# SHA-256 matches both the fresh SHA256SUMS and the digest GitHub reports for
# the release asset; anything missing or different is downloaded again. A
# file that was replaced on the release, or changed on disk, after an earlier
# run is therefore never signed from the stale copy.
echo ">> Fetching SHA256SUMS and per-file sums for $TAG"
rm -f -- SHA256SUMS ./*.tar.zst.sha256 ./*.cdx.json.sha256
gh release download "$TAG" \
    --repo "$REPO" \
    --pattern 'SHA256SUMS' \
    --pattern '*.tar.zst.sha256' \
    --pattern '*.cdx.json.sha256' \
    --clobber

declare -A sums_sha=()
while read -r sha sname; do
    [[ -n "${sname:-}" ]] && sums_sha["${sname#\*}"]="$sha"
done < SHA256SUMS

# Asset names and digests ("sha256:<hex>", or empty for assets uploaded
# before GitHub recorded digests).
declare -A asset_sha=()
to_sign=()
while IFS=$'\t' read -r aname adigest; do
    case "$aname" in
        *.tar.zst|*.cdx.json) ;;
        *) continue ;;
    esac
    [[ "$aname" == */* ]] && { echo "unexpected asset name: $aname" >&2; exit 1; }
    to_sign+=( "$aname" )
    asset_sha["$aname"]="${adigest#sha256:}"
done < <(gh api "repos/$REPO/releases/tags/$TAG" \
             --jq '.assets[] | [.name, (.digest // "")] | @tsv')

if [[ ${#to_sign[@]} -eq 0 ]]; then
    echo "no artifacts found to sign for tag $TAG" >&2
    exit 1
fi

fetch=()
reused=0
for f in "${to_sign[@]}"; do
    if [[ -f "$f" ]]; then
        have="$(sha256sum -- "$f" | cut -d' ' -f1)"
        if [[ -n "${sums_sha[$f]:-}" && -n "${asset_sha[$f]}" \
              && "$have" == "${sums_sha[$f]}" && "$have" == "${asset_sha[$f]}" ]]; then
            reused=$((reused + 1))
            continue
        fi
        echo "   stale or unverifiable local copy, fetching again: $f"
    fi
    rm -f -- "$f" "$f.minisig"
    fetch+=( "$f" )
done

echo ">> Downloading ${#fetch[@]} artifact(s) for $TAG (${reused} already here and matching)"
if [[ ${#fetch[@]} -gt 0 ]]; then
    patterns=()
    for f in "${fetch[@]}"; do
        # gh takes glob patterns; escape glob characters so each one names
        # exactly one asset.
        patterns+=( --pattern "$(printf '%s' "$f" | sed 's/[][*?\\]/\\&/g')" )
    done
    gh release download "$TAG" --repo "$REPO" "${patterns[@]}" --clobber
fi

echo ">> Confirming SHA256SUMS"
sha256sum -c SHA256SUMS
for f in "${to_sign[@]}"; do
    if [[ -z "${sums_sha[$f]:-}" ]]; then
        echo "$f is on $TAG but SHA256SUMS does not list it" >&2
        exit 1
    fi
    want="${asset_sha[$f]}"
    if [[ -n "$want" && "$(sha256sum -- "$f" | cut -d' ' -f1)" != "$want" ]]; then
        echo "$f does not match the digest GitHub reports for the asset" >&2
        exit 1
    fi
done

# A .minisig left by an earlier run counts only if it verifies against the
# current bytes and the published key. Anything else is removed and signed
# again, so a run that fails partway keeps the signatures it already made.
already_signed=()
to_do=()
for f in "${to_sign[@]}"; do
    if [[ -f "${f}.minisig" ]] && minisign -Vm "$f" -P "$PUBKEY" >/dev/null 2>&1; then
        already_signed+=("$f")
    else
        rm -f -- "${f}.minisig"
        to_do+=("$f")
    fi
done

if [[ ${#to_do[@]} -eq 0 ]]; then
    echo ">> All ${#to_sign[@]} artifact(s) already signed, nothing to sign"
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
sigs=()
for f in "${to_sign[@]}"; do
    minisign -Vm "$f" -P "$PUBKEY" >/dev/null
    echo "   ok: ${f}.minisig"
    sigs+=( "${f}.minisig" )
done

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo
    echo "[dry-run] Skipping upload. Generated signatures:"
    printf '%s\n' "${sigs[@]}"
    echo "[dry-run] Re-run without --dry-run to publish to the release."
    finished=1
    exit 0
fi

echo ">> Uploading .minisig files to release $TAG"
gh release upload "$TAG" \
    --repo "$REPO" \
    --clobber \
    -- "${sigs[@]}"

finished=1
echo
echo "Done. Operators can now verify with:"
echo "  minisign -Vm <tarball> -P '${PUBKEY}'"
