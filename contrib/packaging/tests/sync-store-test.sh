#!/usr/bin/env bash
# Drive contrib/packaging/sync-store.sh against throwaway repositories.
#
# The script's job is to refuse: a dirty destination, an image that is not a
# release, a tag that disagrees with the package version. Each refusal is
# paired with the sync that must succeed, since a script that refused
# everything would pass every refusal on its own.
#
# It runs against a copy of the packaging tree in a scratch git repository,
# so perturbing a pin never touches the real checkout, which sync-store.sh
# requires to be clean.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=1; }

git_q() { git -c user.email=test@example.invalid -c user.name=test "$@" >/dev/null; }

# A satd-shaped tree holding just what the script reads.
satd="$WORK/satd"
mkdir -p "$satd/contrib/stack/satd"
cp -r "$ROOT/contrib/packaging" "$satd/contrib/"
cp "$ROOT/contrib/stack/satd/satd-init" "$satd/contrib/stack/satd/"
rm -rf "$satd/contrib/packaging/startos/node_modules" "$satd/contrib/packaging/startos/javascript"
git_q -C "$satd" init -q
git_q -C "$satd" add -A
git_q -C "$satd" commit -qm base
sync="$satd/contrib/packaging/sync-store.sh"

new_dest() {
    local d="$WORK/dest-$1"
    rm -rf "$d"
    mkdir -p "$d"
    git_q -C "$d" init -q
    printf 'kept\n' > "$d/UNRELATED"
    git_q -C "$d" add -A
    git_q -C "$d" commit -qm init
    echo "$d"
}

commit_dest() {
    git_q -C "$1" add -A
    git_q -C "$1" commit -qm sync --allow-empty
}

expect_ok() {
    local what="$1"; shift
    if out="$("$@" 2>&1)"; then ok "$what"; else bad "$what"; printf '%s\n' "$out" | sed 's/^/        /'; fi
}
expect_refused() {
    local what="$1" pattern="$2"; shift 2
    if out="$("$@" 2>&1)"; then
        bad "$what (it succeeded)"
    elif grep -q -- "$pattern" <<< "$out"; then
        ok "$what"
    else
        bad "$what (refused for another reason)"; printf '%s\n' "$out" | sed 's/^/        /'
    fi
}

echo "== umbrel =="
d="$(new_dest umbrel)"
expect_ok "syncs into a clean clone" "$sync" umbrel "$d"
for f in umbrel-app-store.yml README.md epochbtc-satd/umbrel-app.yml \
         epochbtc-satd/docker-compose.yml epochbtc-satd/exports.sh epochbtc-satd/data/.gitkeep UNRELATED; do
    if [[ -e "$d/$f" ]]; then ok "the store has $f"; else bad "the store has no $f"; fi
done
if [[ -e "$d/epochbtc-satd/README.md" || -e "$d/STORE_README.md" ]]; then
    bad "development files leaked into the store"
else
    ok "development files stay behind"
fi
commit_dest "$d"
if out="$("$sync" umbrel "$d" 2>&1)" && grep -q "nothing to do" <<< "$out"; then
    ok "a second sync is a no-op"
else
    bad "a second sync is a no-op"; printf '%s\n' "$out" | sed 's/^/        /'
fi
printf 'stale\n' > "$d/epochbtc-satd/stale-file"
commit_dest "$d"
"$sync" umbrel "$d" >/dev/null
if [[ -e "$d/epochbtc-satd/stale-file" ]]; then bad "a file deleted upstream lingers"; else ok "a file deleted upstream is removed"; fi
commit_dest "$d"
printf 'x\n' >> "$d/UNRELATED"
expect_refused "refuses a dirty destination" "uncommitted changes" "$sync" umbrel "$d"
git_q -C "$d" checkout -q -- UNRELATED

compose="$satd/contrib/packaging/umbrel/epochbtc-satd/docker-compose.yml"
orig="$(cat "$compose")"
sed -i 's|ghcr.io/epochbtc/satd:\([0-9.]*\)@|ghcr.io/epochbtc/satd:sha-0000000@|' "$compose"
git_q -C "$satd" commit -qam perturb
expect_refused "refuses a per-commit image" "is not a release" "$sync" umbrel "$d"
printf '%s\n' "$orig" > "$compose"
sed -i 's|ghcr.io/epochbtc/satd:\([0-9.]*\)@|ghcr.io/epochbtc/satd:9.9.9@|' "$compose"
git_q -C "$satd" commit -qam perturb
expect_refused "refuses a tag that disagrees with version" "does not match the package version" "$sync" umbrel "$d"
printf '%s\n' "$orig" > "$compose"
sed -i 's|@sha256:[0-9a-f]*|@sha256:abc|' "$compose"
git_q -C "$satd" commit -qam perturb
expect_refused "refuses an image without a digest" "is not pinned" "$sync" umbrel "$d"
printf '%s\n' "$orig" > "$compose"
git_q -C "$satd" commit -qam restore
printf 'x\n' >> "$compose"
expect_refused "refuses an uncommitted satd tree" "uncommitted changes" "$sync" umbrel "$d"
printf '%s\n' "$orig" > "$compose"

echo "== startos =="
d="$(new_dest startos)"
mkdir -p "$d/startos"
printf 'stale\n' > "$d/startos/stale.ts"
commit_dest "$d"
expect_ok "syncs into a clean clone" "$sync" startos "$d"
if [[ -e "$d/startos/stale.ts" ]]; then bad "a source file deleted upstream lingers"; else ok "a source file deleted upstream is removed"; fi
for f in package.json Makefile instructions.md startos/manifest/index.ts \
         .github/workflows/build.yml test/upstream/satd-init test/upstream/SOURCE UNRELATED; do
    if [[ -e "$d/$f" ]]; then ok "the package repo has $f"; else bad "the package repo has no $f"; fi
done
if cmp -s "$d/test/upstream/satd-init" "$ROOT/contrib/stack/satd/satd-init"; then
    ok "the vendored satd-init is this commit's"
else
    bad "the vendored satd-init differs from this commit's"
fi
commit_dest "$d"
manifest="$satd/contrib/packaging/startos/startos/manifest/index.ts"
orig="$(cat "$manifest")"
sed -i "s|ghcr.io/epochbtc/satd:\([0-9.]*\)@|ghcr.io/epochbtc/satd:9.9.9@|" "$manifest"
git_q -C "$satd" commit -qam perturb
expect_refused "refuses a tag that disagrees with version" "does not match the package version" "$sync" startos "$d"
printf '%s\n' "$orig" > "$manifest"
git_q -C "$satd" commit -qam restore

echo
if [[ "$fail" -ne 0 ]]; then echo "sync-store-test.sh: FAILED"; exit 1; fi
echo "sync-store-test.sh: all checks passed"
