#!/usr/bin/env bash
# sync-store.sh — copy an app-store package into the repository that publishes it.
#
#   contrib/packaging/sync-store.sh umbrel  <clone of epochbtc/umbrel-apps>
#   contrib/packaging/sync-store.sh startos <clone of epochbtc/satd-startos, or its Start9-Community fork>
#
# The packages are developed here, beside satd, and each store consumes them
# from a repository of its own. This is the one step between the two. It
# checks the package is publishable, replaces the destination's copy, and
# stops: it never commits or pushes. Review the diff in the destination and
# push it yourself, or open the pull request against the fork.
#
# A maintainer-run script rather than a workflow on purpose. A workflow here
# would need a token that can write to another repository, and satd is a
# public repository whose workflows run on pull requests.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

die() { echo "sync-store.sh: $*" >&2; exit 1; }
usage() { sed -n '2,5p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }

[[ $# -eq 2 ]] || usage
store="$1"
dest="$2"

command -v rsync >/dev/null || die "needs rsync"
[[ -d "$dest" ]] || die "no such directory: $dest"
git -C "$dest" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || die "$dest is not a git checkout; clone the store repository first"
[[ "$(git -C "$dest" rev-parse --show-toplevel)" == "$(cd "$dest" && pwd -P)" ]] \
    || die "$dest is inside a repository but is not its root"
[[ -z "$(git -C "$dest" status --porcelain)" ]] \
    || die "$dest has uncommitted changes; this replaces its contents, so start clean"

# The copy should name a commit someone can check out, so the satd tree must
# be clean too.
[[ -z "$(git -C "$ROOT" status --porcelain -- contrib/packaging contrib/stack/satd)" ]] \
    || die "contrib/packaging or contrib/stack/satd has uncommitted changes"
satd_commit="$(git -C "$ROOT" rev-parse HEAD)"
satd_describe="$(git -C "$ROOT" describe --tags --always HEAD)"

# `ghcr.io/epochbtc/satd:<tag>@sha256:<64 hex>`, where <tag> must be a release.
check_pin() {
    local where="$1" pin="$2" version="$3"
    [[ "$pin" =~ ^ghcr\.io/epochbtc/satd:([^@]+)@sha256:[0-9a-f]{64}$ ]] \
        || die "$where: image '$pin' is not pinned as ghcr.io/epochbtc/satd:<tag>@sha256:<digest>"
    local tag="${BASH_REMATCH[1]}"
    [[ "$tag" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "$where: image tag '$tag' is not a release; a store package ships released images only"
    [[ "$tag" == "$version" ]] \
        || die "$where: image tag $tag does not match the package version $version; bump both"
    echo "sync-store.sh: $where pins satd $tag by digest"
}

case "$store" in
umbrel)
    src="$HERE/umbrel"
    app="epochbtc-satd"
    version="$(sed -n 's/^version: "\(.*\)"$/\1/p' "$src/$app/umbrel-app.yml")"
    [[ -n "$version" ]] || die "$app/umbrel-app.yml has no quoted version"
    pin="$(sed -n 's/^x-satd-image: &satd-image //p' "$src/$app/docker-compose.yml")"
    check_pin "$app/docker-compose.yml" "$pin" "$version"
    grep -q '^releaseNotes:' "$src/$app/umbrel-app.yml" \
        || die "$app/umbrel-app.yml has no releaseNotes for $version"

    # The store's layout: its manifest at the root, one directory per app.
    # Everything else in the destination is left alone except a previous copy
    # of the app itself, which is replaced whole so a deleted file does not
    # linger.
    cp "$src/umbrel-app-store.yml" "$dest/umbrel-app-store.yml"
    rsync -a --delete "$src/$app/" "$dest/$app/"
    cp "$src/STORE_README.md" "$dest/README.md"
    ;;
startos)
    src="$HERE/startos"
    version="$(sed -n "s/^  version: '\([^:']*\):[0-9]*',$/\1/p" "$src/startos/versions/current.ts")"
    [[ -n "$version" ]] || die "startos/versions/current.ts has no '<upstream>:<revision>' version"
    pin="$(sed -n "s/^ *dockerTag: '\(.*\)',$/\1/p" "$src/startos/manifest/index.ts")"
    check_pin "startos/manifest/index.ts" "$pin" "$version"

    # The package is this directory, at the destination's root. Build output
    # and the per-machine workspace stay behind.
    #
    # The source directories are replaced whole, so a file deleted here does
    # not linger there. Top-level files are copied without deleting anything
    # else: once Start9 forks the repository it is theirs as well, and a fork
    # carries files of its own (agent notes, update guides) that a sync must
    # not remove.
    rsync -a \
        --exclude=/.git --exclude=/startos/ --exclude=/test/ --exclude=/assets/ \
        --exclude=node_modules/ --exclude=javascript/ --exclude=ncc-cache/ \
        --exclude='*.s9pk' --exclude=/.startos/ \
        "$src/" "$dest/"
    for dir in startos test assets; do
        rsync -a --delete --exclude=/upstream/ "$src/$dir/" "$dest/$dir/"
    done

    # Two tests check the package against satd's own files. The one the
    # package cannot work without is vendored, from this same commit; see
    # test/upstream.ts. The storage-layout check stays behind and skips.
    mkdir -p "$dest/test/upstream"
    cp "$ROOT/contrib/stack/satd/satd-init" "$dest/test/upstream/satd-init"
    printf 'Vendored from epochbtc/satd %s (%s) by contrib/packaging/sync-store.sh.\n' \
        "$satd_describe" "$satd_commit" > "$dest/test/upstream/SOURCE"
    ;;
*)
    usage
    ;;
esac

git -C "$dest" add -A
if git -C "$dest" diff --cached --quiet; then
    git -C "$dest" reset -q
    echo "sync-store.sh: $dest already matches satd $satd_describe; nothing to do"
    exit 0
fi
git -C "$dest" diff --cached --check \
    || die "whitespace errors in the synced copy (git diff --check above)"
git -C "$dest" reset -q

echo "sync-store.sh: synced $store from satd $satd_describe ($satd_commit)"
echo
git -C "$dest" status --short
echo
echo "Next, in $dest: review the diff, then commit and push (or open the"
echo "pull request against the fork). Suggested message:"
echo
echo "    satd $version, from epochbtc/satd $satd_describe"
