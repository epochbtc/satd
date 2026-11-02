#!/bin/bash
# Tests for contrib/release/sign-tarballs.sh (the tarball path).
#
# `gh` and `minisign` are replaced by stubs on PATH: the stub release is a
# local directory, and the stub signature is the file's SHA-256, so a
# signature made over stale bytes fails verification exactly as a real one
# would. What is under test is the working-directory handling: what a rerun
# after a failure downloads, what it signs again, and which directories it
# refuses to work in.
#
# No network, no key, no passphrase prompt.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../sign-tarballs.sh"
[[ -x "$SCRIPT" ]] || { echo "not executable: $SCRIPT" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'chmod -R u+w "${WORK:?}" 2>/dev/null; rm -rf "${WORK:?}"' EXIT

FAILURES=0
pass() { echo "ok   — $1"; }
fail() { echo "FAIL — $1"; [[ $# -lt 2 ]] || sed 's/^/       /' <<< "$2"; FAILURES=$((FAILURES + 1)); }
assert_eq() {
    if [[ "$2" == "$3" ]]; then pass "$1"
    else fail "$1" "expected: $2
actual:   $3"; fi
}

# --- stubs -------------------------------------------------------------------
BIN="$WORK/bin"
mkdir -p "$BIN"

cat > "$BIN/gh" <<'STUB'
#!/bin/bash
# gh stub: serves $FAKE_RELEASE as the release's assets.
set -euo pipefail
case "$1 $2" in
    "release download")
        shift 3
        dir="."; pats=()
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --pattern) pats+=( "$2" ); shift 2 ;;
                --dir) dir="$2"; shift 2 ;;
                --repo) shift 2 ;;
                *) shift ;;
            esac
        done
        for src in "$FAKE_RELEASE"/*; do
            name="$(basename "$src")"
            for p in "${pats[@]}"; do
                # shellcheck disable=SC2053  # $p is a glob on purpose
                if [[ "$name" == $p ]]; then
                    cp "$src" "$dir/$name"
                    echo "$name" >> "$GH_LOG"
                    break
                fi
            done
        done ;;
    "api repos/"*)
        for src in "$FAKE_RELEASE"/*; do
            printf '%s\tsha256:%s\n' "$(basename "$src")" "$(sha256sum "$src" | cut -d' ' -f1)"
        done ;;
    "release upload")
        [[ -z "${GH_UPLOAD_FAIL:-}" ]] || { echo "upload failed (stub)" >&2; exit 1; }
        echo "upload" >> "$GH_LOG" ;;
    *) echo "gh stub: unhandled: $*" >&2; exit 2 ;;
esac
STUB

cat > "$BIN/minisign" <<'STUB'
#!/bin/bash
# minisign stub: a "signature" is the SHA-256 of the signed bytes, and the
# passphrase is "right".
set -euo pipefail
mode=""; file=""; sig=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -S) mode=sign; shift ;;
        -Vm) mode=verify; file="$2"; shift 2 ;;
        -m) file="$2"; shift 2 ;;
        -x) sig="$2"; shift 2 ;;
        -s|-P) shift 2 ;;
        *) shift ;;
    esac
done
sig="${sig:-$file.minisig}"
sum="$(sha256sum "$file" | cut -d' ' -f1)"
if [[ "$mode" == sign ]]; then
    read -r pass
    [[ "$pass" == right ]] || { echo "Wrong password for that key" >&2; exit 1; }
    echo "sig:$sum" > "$sig"
    basename "$file" >> "$MS_LOG"
else
    [[ -f "$sig" && "$(cat "$sig")" == "sig:$sum" ]] || { echo "Signature verification failed" >&2; exit 1; }
fi
STUB
# chmod stub: the real chmod, and then, when SWAP_DIR names the directory it
# just changed, the swap a local attacker who can write to the parent would
# make between the script's checks and its cd: SWAP_DIR becomes a symlink to
# SWAP_TO.
cat > "$BIN/chmod" <<'STUB'
#!/bin/bash
set -euo pipefail
PATH=/usr/bin:/bin chmod "$@"
if [[ -n "${SWAP_DIR:-}" && "${!#}" == "$SWAP_DIR" ]]; then
    mv "$SWAP_DIR" "$SWAP_DIR.orig"
    ln -s "$SWAP_TO" "$SWAP_DIR"
fi
STUB
chmod +x "$BIN/gh" "$BIN/minisign" "$BIN/chmod"

touch "$WORK/key"
export PATH="$BIN:$PATH" SATD_MINISIGN_KEY="$WORK/key" GH_LOG="$WORK/gh.log" MS_LOG="$WORK/ms.log"

# A release: two tarballs and an SBOM, each with its .sha256, plus SHA256SUMS.
reseal() {
    local rel="${1:?}" f
    rm -f "$rel"/*.sha256 "$rel/SHA256SUMS"
    (cd "$rel" && for f in *.tar.zst *.cdx.json; do sha256sum "$f" > "$f.sha256"; done \
        && cat ./*.sha256 | sort > SHA256SUMS)
}
make_release() {
    local rel="${1:?}"
    mkdir -p "$rel"
    head -c 4096 /dev/urandom > "$rel/satd-9.9.9-x86_64-unknown-linux-gnu.tar.zst"
    head -c 4096 /dev/urandom > "$rel/satd-9.9.9-x86_64-unknown-linux-gnu-debuginfo.tar.zst"
    echo '{"bomFormat":"CycloneDX"}' > "$rel/satd-v9.9.9.cdx.json"
    reseal "$rel"
}
BIG=3

# Runs the script; the first argument is the passphrase fed on stdin.
run() {
    local pass="$1"; shift
    : > "$GH_LOG"; : > "$MS_LOG"
    printf '%s\n' "$pass" | "$SCRIPT" "$@" > "$WORK/out" 2>&1
}
big_fetched() { grep -E '\.(tar\.zst|cdx\.json)$' "$GH_LOG" || true; }
big_downloads() { big_fetched | wc -l | tr -d ' '; }
signed() { wc -l < "$MS_LOG" | tr -d ' '; }

# --- (a) a rerun after a failure downloads nothing big -----------------------
export FAKE_RELEASE="$WORK/release" SATD_SIGN_DIR="$WORK/cache/a"
make_release "$FAKE_RELEASE"

if run wrong v9.9.9; then fail "wrong passphrase fails the run"; else pass "wrong passphrase fails the run"; fi
assert_eq "first run downloads every artifact" "$BIG" "$(big_downloads)"
[[ -d "$SATD_SIGN_DIR" ]] && pass "directory kept after a failed run" || fail "directory kept after a failed run"
assert_eq "directory is 0700" "700" "$(stat -c %a "$SATD_SIGN_DIR")"

if GH_UPLOAD_FAIL=1 run right v9.9.9; then fail "failed upload fails the run"; else pass "failed upload fails the run"; fi
assert_eq "rerun downloads no artifact" "0" "$(big_downloads)"
grep -qx SHA256SUMS "$GH_LOG" && pass "rerun fetches SHA256SUMS fresh" || fail "rerun fetches SHA256SUMS fresh" "$(cat "$GH_LOG")"
assert_eq "rerun signs every artifact" "$BIG" "$(signed)"
assert_eq "signatures kept after a failed upload" "$BIG" "$(find "$SATD_SIGN_DIR" -name '*.minisig' | wc -l | tr -d ' ')"

if run right v9.9.9; then pass "third run succeeds"; else fail "third run succeeds" "$(cat "$WORK/out")"; fi
assert_eq "third run downloads no artifact" "0" "$(big_downloads)"
assert_eq "third run signs nothing (signatures still verify)" "0" "$(signed)"
grep -qx upload "$GH_LOG" && pass "third run uploads" || fail "third run uploads"
[[ ! -e "$SATD_SIGN_DIR" ]] && pass "directory removed after upload" || fail "directory removed after upload"

# A second successful run on the same tag starts over and still works.
if run right v9.9.9; then pass "repeat run on a signed tag succeeds"; else fail "repeat run on a signed tag succeeds" "$(cat "$WORK/out")"; fi
assert_eq "repeat run signs everything again" "$BIG" "$(signed)"

# --- (b) a changed local file, or a replaced asset, is fetched again ---------
export SATD_SIGN_DIR="$WORK/cache/b"
GH_UPLOAD_FAIL=1 run right v9.9.9 || true
victim="satd-9.9.9-x86_64-unknown-linux-gnu.tar.zst"
printf 'tampered' >> "$SATD_SIGN_DIR/$victim"
if GH_UPLOAD_FAIL=1 run right v9.9.9; then fail "run (b1) fails at upload"; else pass "run (b1) fails at upload"; fi
assert_eq "tampered local file is downloaded again" "$victim" "$(big_fetched)"
assert_eq "tampered file is signed again, nothing else" "$victim" "$(cat "$MS_LOG")"
assert_eq "re-downloaded copy matches the release" \
    "$(sha256sum < "$FAKE_RELEASE/$victim")" "$(sha256sum < "$SATD_SIGN_DIR/$victim")"

sbom="satd-v9.9.9.cdx.json"
echo '{"bomFormat":"CycloneDX","replaced":true}' > "$FAKE_RELEASE/$sbom"
reseal "$FAKE_RELEASE"
if run right v9.9.9; then pass "run (b2) succeeds"; else fail "run (b2) succeeds" "$(cat "$WORK/out")"; fi
assert_eq "replaced release asset is downloaded again" "$sbom" "$(big_fetched)"
assert_eq "replaced asset is signed again, nothing else" "$sbom" "$(cat "$MS_LOG")"

# SHA256SUMS and the asset digest are checked independently: a local copy that
# matches a (doctored) SHA256SUMS but not the digest is not kept, and the run
# then fails because the release disagrees with itself.
export SATD_SIGN_DIR="$WORK/cache/b3"
GH_UPLOAD_FAIL=1 run right v9.9.9 || true
printf 'x' >> "$SATD_SIGN_DIR/$victim"
doctored="$(sha256sum "$SATD_SIGN_DIR/$victim" | cut -d' ' -f1)"
sed -i "s/^[0-9a-f]*  $victim\$/$doctored  $victim/" "$FAKE_RELEASE/SHA256SUMS"
if run right v9.9.9; then fail "SHA256SUMS that disagrees with the asset digest fails"; else pass "SHA256SUMS that disagrees with the asset digest fails"; fi
assert_eq "copy matching only SHA256SUMS is downloaded again" "$victim" "$(big_fetched)"
assert_eq "nothing signed when the release disagrees with itself" "0" "$(signed)"
reseal "$FAKE_RELEASE"

# --- --dry-run removes the directory on success -----------------------------
export SATD_SIGN_DIR="$WORK/cache/dry"
if run right --dry-run v9.9.9; then pass "dry run succeeds"; else fail "dry run succeeds" "$(cat "$WORK/out")"; fi
if grep -q upload "$GH_LOG"; then fail "dry run does not upload"; else pass "dry run does not upload"; fi
[[ ! -e "$SATD_SIGN_DIR" ]] && pass "directory removed after a dry run" || fail "directory removed after a dry run"

# --- (c) unsafe directories are refused --------------------------------------
# refused <name> [<message regex>] [script args...]
refused() {
    local name="$1" want="${2:-^refusing}"
    shift 2 2>/dev/null || shift
    if run right "$@" v9.9.9; then fail "$name" "$(cat "$WORK/out")"
    elif ! grep -qE "$want" "$WORK/out"; then fail "$name" "$(cat "$WORK/out")"
    elif [[ -s "$GH_LOG" ]]; then fail "$name (downloaded before refusing)" "$(cat "$GH_LOG")"
    else pass "$name"; fi
}

export SATD_SIGN_DIR="$WORK/cache/open"
mkdir -p "$SATD_SIGN_DIR"; chmod 777 "$SATD_SIGN_DIR"
refused "world-writable directory is refused"
mkdir -p "$SATD_SIGN_DIR"; chmod 770 "$SATD_SIGN_DIR"
refused "group-writable directory is refused"
assert_eq "a refused directory keeps its mode" "770" "$(stat -c %a "$SATD_SIGN_DIR")"

# The symlink's target is a directory an earlier run made, so it passes every
# other check: only the symlink refusal stands between the script and it.
export SATD_SIGN_DIR="$WORK/elsewhere"
run wrong v9.9.9 || true
ln -s "$WORK/elsewhere" "$WORK/cache/link"
export SATD_SIGN_DIR="$WORK/cache/link"
refused "symlinked directory is refused" '^refusing .*: is a symlink$'
export SATD_SIGN_DIR="$WORK/cache/link/"
refused "symlinked directory named with a trailing slash is refused" '^refusing .*: is a symlink$'
export SATD_SIGN_DIR="$WORK/cache/link//"
refused "symlinked directory named with two trailing slashes is refused" '^refusing .*: is a symlink$'

# An operator's own directory is never used, chmod'd or deleted, even on a
# --dry-run, which removes the directory it worked in.
mkdir -p "$WORK/mine"; chmod 755 "$WORK/mine"; echo keep > "$WORK/mine/keep.txt"
export SATD_SIGN_DIR="$WORK/mine"
refused "existing directory the script did not create is refused" 'did not create it' --dry-run
[[ -f "$WORK/mine/keep.txt" ]] && pass "refused directory keeps its contents" || fail "refused directory keeps its contents"
assert_eq "refused directory is not chmod'd" "755" "$(stat -c %a "$WORK/mine")"
mkdir -p "$WORK/mine-empty"; chmod 700 "$WORK/mine-empty"
export SATD_SIGN_DIR="$WORK/mine-empty"
refused "existing empty directory the script did not create is refused" 'did not create it' --dry-run
[[ -d "$WORK/mine-empty" ]] && pass "refused empty directory is not removed" || fail "refused empty directory is not removed"

# The directory is swapped for a symlink between the checks and the cd. The
# target is one an earlier run made, so only the re-check after the cd sees it.
export SATD_SIGN_DIR="$WORK/attacker"
run wrong v9.9.9 || true
export SATD_SIGN_DIR="$WORK/cache/race"
run wrong v9.9.9 || true
SWAP_DIR="$SATD_SIGN_DIR" SWAP_TO="$WORK/attacker" \
    refused "directory swapped before the cd is refused" 'changed between the check and the cd'
unset SWAP_DIR SWAP_TO

if [[ "$(id -u)" -ne 0 ]]; then
    # / exists, is not writable by others, and belongs to root.
    export SATD_SIGN_DIR=/
    refused "directory owned by another user is refused"
else
    echo "skip — directory owned by another user (running as root)"
fi

# The key defaults to minisign's own location, not to any one machine's layout.
mkdir -p "$WORK/home"
if HOME="$WORK/home" SATD_MINISIGN_KEY= run right --dry-run v9.9.9; then
    fail "missing default key fails the run"
elif grep -qx "minisign key file not found: $WORK/home/.minisign/minisign.key" "$WORK/out"; then
    pass "key defaults to ~/.minisign/minisign.key"
else
    fail "key defaults to ~/.minisign/minisign.key" "$(cat "$WORK/out")"
fi

unset SATD_SIGN_DIR
export XDG_CACHE_HOME="$WORK/xdg"
if run right 'v9.9.9/../../x'; then fail "tag with a path separator is refused"
elif grep -q '^refusing tag' "$WORK/out"; then pass "tag with a path separator is refused"
else fail "tag with a path separator is refused" "$(cat "$WORK/out")"; fi

if run right --dry-run v9.9.9; then pass "default directory under XDG_CACHE_HOME works"; else fail "default directory under XDG_CACHE_HOME works" "$(cat "$WORK/out")"; fi
grep -q "Working directory: $WORK/xdg/satd-sign/v9.9.9" "$WORK/out" \
    && pass "default directory is \$XDG_CACHE_HOME/satd-sign/<tag>" \
    || fail "default directory is \$XDG_CACHE_HOME/satd-sign/<tag>" "$(cat "$WORK/out")"

echo
if [[ "$FAILURES" -eq 0 ]]; then echo "all passed"; else echo "$FAILURES failure(s)"; exit 1; fi
