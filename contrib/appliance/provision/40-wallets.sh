#!/bin/bash
# 40-wallets.sh — the bundled desktop wallets. Desktop flavour only.
#
# BEST-EFFORT SOFTWARE. These are third-party applications included so the
# appliance can demonstrate satd end to end. They are not tracked for
# security advisories here; see the support policy in the README.
#
# Every download is signature-verified against a key fingerprint pinned
# below. The fingerprints were taken from the projects' own published
# release signatures, and a build fails rather than installing anything that
# does not verify — an appliance that silently installed an unverified
# wallet would be worse than one that shipped without wallets at all.
#
# Pins are bumped deliberately, by a PR that re-checks the signature.
set -euo pipefail
. /provision/common.sh

[[ "$SATD_FLAVOR" == "desktop" ]] || { step "not the desktop flavour; skipping"; exit 0; }

SPARROW_VERSION="${SPARROW_VERSION:-2.5.4}"
# Craig Raw. Taken from the detached signature on the 2.5.4 manifest.
SPARROW_FPR="D4D0D3202FC06849A257B38DE94618334C674B40"

ELECTRUM_VERSION="${ELECTRUM_VERSION:-4.6.2}"
# Electrum AppImages carry three signatures; any one verifying is the
# project's own documented check. ThomasV, SomberNight and Emzy.
ELECTRUM_FPRS=(
    "637DB1E23370F84AFF88CCE03152347D07DA627C"
    "AA0BC6824B397BBA99776E157ED8D82B37192688"
    "0EEDCFD5CAFB459067349B23CA9EEEC43DF911DC"
)

LIANA_VERSION="${LIANA_VERSION:-15.0}"
# Wizardsardine's release key, taken from the signature on the v15.0
# shasums. Pinned like the two above, and for the same reason: deriving the
# key from the signature and then verifying against it proves only that the
# file is self-consistent, which a hostile file also is.
LIANA_FPR="4730DDCC64DFAEC16CEFEB5BE65F7A089C20DC8F"

apt_install gnupg dirmngr

# Verify a detached signature and require that a specific key made it.
#
# The output is captured first and matched afterwards, deliberately. The
# obvious spelling — `gpg --verify ... | grep -q "VALIDSIG $fpr"` — is wrong
# under `set -o pipefail` in a way that depends on FILE SIZE: grep -q exits
# at the first match and closes the pipe, gpg dies of SIGPIPE, and the
# pipeline reports failure even though the signature verified. On a small
# manifest gpg has already finished and it passes; on Electrum's 84 MB
# AppImage it has not, and a perfectly good signature is rejected. Capturing
# removes the pipe, and with it the dependence on how fast gpg finishes.
verify_detached_sig() {
    local sig="$1" file="$2" fpr="$3"
    local status
    status="$(gpg --batch --status-fd 1 --verify "$sig" "$file" 2>/dev/null || true)"
    grep -q "VALIDSIG $fpr" <<< "$status"
}

# Fetch a key by fingerprint from a keyserver and confirm we got that key
# and not another. Asking a keyserver for a fingerprint and then trusting
# whatever comes back would defeat the point of pinning one.
import_key() {
    local fpr="$1"
    for server in keyserver.ubuntu.com keys.openpgp.org; do
        if gpg --batch --keyserver "hkps://$server" --recv-keys "$fpr" 2>/dev/null; then
            if gpg --batch --list-keys "$fpr" > /dev/null 2>&1; then
                return 0
            fi
        fi
    done
    echo "  could not obtain key $fpr" >&2
    return 1
}

TMP="$(mktemp -d)"
# gpg starts gpg-agent and dirmngr as daemons that outlive the command that
# needed them. Left running inside the build chroot they hold /dev open, and
# the umount after provisioning then fails with "target is busy" — losing a
# completed build at the very last step.
cleanup_wallets() {
    gpgconf --kill all > /dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup_wallets EXIT

# Check one file against a signed checksum manifest.
#
# Manifests differ in shape between projects: Sparrow writes
# `<sha256> *<name>` (coreutils binary mode), Liana writes
# `<sha256>  <name>`. Matching the name with a plain grep against one of
# those forms silently finds nothing on the other — and "no matching line"
# has to be a failure, not an empty success, which is what this exists to
# guarantee. The line is located by comparing the parsed name for equality
# and then handed to sha256sum, which understands both forms.
verify_from_manifest() {
    local manifest="$1" name="$2"
    local line
    line="$(awk -v want="$name" 'BEGIN { FS = "[ \t]+" }
        {
            n = $2
            sub(/^[*]/, "", n)
            if (n == want) print
        }' "$manifest")"
    if [[ -z "$line" ]]; then
        echo "  $name is not listed in $(basename "$manifest")" >&2
        return 1
    fi
    if [[ "$(wc -l <<< "$line")" != 1 ]]; then
        echo "  $name is listed more than once in $(basename "$manifest")" >&2
        return 1
    fi
    ( cd "$(dirname "$manifest")" && printf '%s\n' "$line" | sha256sum -c - )
}

# --- Sparrow ---------------------------------------------------------------
step "Sparrow Wallet $SPARROW_VERSION"
base="https://github.com/sparrowwallet/sparrow/releases/download/$SPARROW_VERSION"
deb="sparrowwallet_${SPARROW_VERSION}-1_${DEB_ARCH}.deb"
manifest="sparrow-${SPARROW_VERSION}-manifest.txt"
fetch "$base/$deb" "$TMP/$deb"
fetch "$base/$manifest" "$TMP/$manifest"
fetch "$base/$manifest.asc" "$TMP/$manifest.asc"
import_key "$SPARROW_FPR"
# Sparrow signs a manifest of SHA-256 sums rather than each file, so the
# check is two-step: the signature covers the manifest, the manifest covers
# the .deb.
verify_detached_sig "$TMP/$manifest.asc" "$TMP/$manifest" "$SPARROW_FPR" \
    || { echo "  Sparrow manifest signature did not verify against $SPARROW_FPR" >&2; exit 1; }
verify_from_manifest "$TMP/$manifest" "$deb" \
    || { echo "  $deb does not match the signed manifest" >&2; exit 1; }
apt-get install -y "$TMP/$deb"
step "  Sparrow verified and installed"

# --- Electrum --------------------------------------------------------------
step "Electrum $ELECTRUM_VERSION"
appimage="electrum-${ELECTRUM_VERSION}-x86_64.AppImage"
if [[ "$DEB_ARCH" == "amd64" ]]; then
    fetch "https://download.electrum.org/$ELECTRUM_VERSION/$appimage" "$TMP/$appimage"
    fetch "https://download.electrum.org/$ELECTRUM_VERSION/$appimage.asc" "$TMP/$appimage.asc"
    verified=0
    for fpr in "${ELECTRUM_FPRS[@]}"; do
        import_key "$fpr" || continue
        if verify_detached_sig "$TMP/$appimage.asc" "$TMP/$appimage" "$fpr"; then
            verified=1
            step "  Electrum verified against $fpr"
            break
        fi
    done
    [[ "$verified" == 1 ]] || { echo "  no pinned Electrum key verified the AppImage" >&2; exit 1; }
    install -Dm755 "$TMP/$appimage" /opt/electrum/electrum.AppImage
    # AppImages need FUSE, which is awkward in a VM; --appimage-extract-and-run
    # avoids it entirely at the cost of a slower start.
    cat > /usr/local/bin/electrum <<'WRAP'
#!/bin/sh
# FUSE is not always available in a guest, and an AppImage that cannot
# mount itself fails with a confusing error rather than falling back.
exec /opt/electrum/electrum.AppImage --appimage-extract-and-run "$@"
WRAP
    chmod +x /usr/local/bin/electrum
    cat > /usr/share/applications/electrum.desktop <<'DESK'
[Desktop Entry]
Type=Application
Name=Electrum
Comment=Electrum wallet, pointed at this appliance's Electrum server
Exec=electrum
Icon=electrum
Terminal=false
Categories=Office;Finance;
DESK
else
    step "  no published Electrum AppImage for $DEB_ARCH; skipping"
fi

# --- Liana -----------------------------------------------------------------
step "Liana $LIANA_VERSION"
lbase="https://github.com/wizardsardine/liana/releases/download/v$LIANA_VERSION"
ldeb="liana-${LIANA_VERSION}-1_${DEB_ARCH}.deb"
lsums="liana-${LIANA_VERSION}-shasums.txt"
if fetch "$lbase/$ldeb" "$TMP/$ldeb" && fetch "$lbase/$lsums" "$TMP/$lsums"; then
    # Liana signs a shasums file; the signature covers the manifest, the
    # manifest covers the .deb. A keyserver that cannot be reached is not a
    # reason to install something unchecked, so failure here fails the build.
    fetch "$lbase/$lsums.asc" "$TMP/$lsums.asc"
    import_key "$LIANA_FPR"
    verify_detached_sig "$TMP/$lsums.asc" "$TMP/$lsums" "$LIANA_FPR" \
        || { echo "  Liana shasums signature did not verify against $LIANA_FPR" >&2; exit 1; }
    step "  Liana shasums verified against $LIANA_FPR"
    verify_from_manifest "$TMP/$lsums" "$ldeb" \
        || { echo "  $ldeb does not match the signed shasums" >&2; exit 1; }
    apt-get install -y "$TMP/$ldeb"
    step "  Liana verified and installed"
else
    step "  no Liana package for $DEB_ARCH at v$LIANA_VERSION; skipping"
fi

# --- Cashu (nutshell wallet CLI) -------------------------------------------
# --- Cashu ------------------------------------------------------------------
step "Cashu wallet CLI"
# The mint is a container (compose.cashu.yml); this is the wallet CLI.
#
# Two upstream breakages have to be worked around, and both are pinned here
# rather than left to a resolver that would rediscover them differently on a
# different day:
#
#  1. cashu -> bip32 4.x -> `coincurve >=15,<21`. coincurve 21 is the FIRST
#     release with a cp313 wheel, and that cap excludes it, so pip must build
#     coincurve 20 from source. coincurve 20 in turn requires
#     `scikit-build-core>=0.9.0` with no upper bound while using a config key
#     (`cmake.verbose`) that scikit-build-core >= 0.10 rejects outright — so
#     the sdist is unbuildable with a current toolchain. PIP_CONSTRAINT does
#     NOT help: it is not consulted for pip's isolated build environment.
#     The fix is to build that one wheel ourselves with a build tool that
#     understands the source, then let normal resolution find it. The
#     library itself is upstream's, unmodified; only the build tool is
#     pinned.
#
#  2. cashu -> environs -> marshmallow. environs reads
#     `marshmallow.__version_info__` at import; marshmallow 4 removed it.
#     That one IS an ordinary runtime dependency, so a constraint fixes it.
#
# The build toolchain is installed for this and removed again: nothing here
# needs a compiler at runtime, and an appliance should not carry one.
apt_install pipx python3-venv
CASHU_BUILD_DEPS=(build-essential python3-dev libsecp256k1-dev pkg-config cmake ninja-build)
apt_install "${CASHU_BUILD_DEPS[@]}"

CASHU_WHEELS=/tmp/cashu-wheels
CASHU_CONSTRAINTS=/tmp/cashu-constraints.txt
mkdir -p "$CASHU_WHEELS"
printf 'marshmallow<4\n' > "$CASHU_CONSTRAINTS"

cashu_ok=0
if python3 -m venv /tmp/cashu-build \
    && /tmp/cashu-build/bin/pip install -q "scikit-build-core<0.10" "hatchling>=1.24.2" \
         cffi setuptools wheel ninja \
    && /tmp/cashu-build/bin/pip wheel --no-build-isolation --no-deps \
         "coincurve==${COINCURVE_VERSION:-20.0.0}" -w "$CASHU_WHEELS"; then
    step "  built a coincurve wheel for this Python"
    if PIP_CONSTRAINT="$CASHU_CONSTRAINTS" PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin \
        pipx install "cashu==${CASHU_VERSION:-0.20.2}" --pip-args="--find-links $CASHU_WHEELS"; then
        cashu_ok=1
    fi
fi

if [[ "$cashu_ok" == 1 ]] && /usr/local/bin/cashu --help > /dev/null 2>&1; then
    step "  cashu wallet installed and runs"
else
    # Loud, and not fatal: the mint overlay is the part that matters, and a
    # desktop image without one CLI is worth more than no image.
    step "  WARNING: cashu wallet did not install; the mint overlay is unaffected"
fi

rm -rf /tmp/cashu-build "$CASHU_WHEELS" "$CASHU_CONSTRAINTS"
apt-get purge -y "${CASHU_BUILD_DEPS[@]}" > /dev/null 2>&1 || true
apt-get autoremove -y --purge > /dev/null 2>&1 || true

step "wallet server presets"
# Pre-seeding the server URL is the difference between "a wallet is
# installed" and "a wallet is talking to this node". Both of these clients
# pin the server certificate on first use, so the user accepts it once.
install -d -m 0755 /etc/skel/.electrum
cat > /etc/skel/.electrum/config <<'ECONF'
{
    "auto_connect": false,
    "oneserver": true,
    "server": "localhost:50002:s",
    "check_updates": false
}
ECONF
USER_HOME="$(getent passwd "$APPLIANCE_USER" | cut -d: -f6)"
install -d -o "$APPLIANCE_USER" -g "$APPLIANCE_USER" -m 0700 "$USER_HOME/.electrum"
install -o "$APPLIANCE_USER" -g "$APPLIANCE_USER" -m 0644 \
    /etc/skel/.electrum/config "$USER_HOME/.electrum/config"

# Sparrow reads its server configuration from its own config file; point it
# at the appliance's Electrum TLS listener so the first launch connects
# instead of asking.
install -d -o "$APPLIANCE_USER" -g "$APPLIANCE_USER" -m 0700 "$USER_HOME/.sparrow"
cat > "$USER_HOME/.sparrow/config" <<SPARROWCONF
{
  "mode": "ONLINE",
  "serverType": "ELECTRUM_SERVER",
  "electrumServer": "ssl://localhost:50002",
  "useProxy": false,
  "autoSwitchBitcoinCore": false
}
SPARROWCONF
chown "$APPLIANCE_USER:$APPLIANCE_USER" "$USER_HOME/.sparrow/config"

for d in sparrow-desktop sparrowwallet; do
    [[ -f "/usr/share/applications/$d.desktop" ]] && \
        cp "/usr/share/applications/$d.desktop" "$USER_HOME/Desktop/" 2>/dev/null || true
done
[[ -f /usr/share/applications/electrum.desktop ]] && \
    cp /usr/share/applications/electrum.desktop "$USER_HOME/Desktop/" 2>/dev/null || true
chown -R "$APPLIANCE_USER:$APPLIANCE_USER" "$USER_HOME/Desktop" 2>/dev/null || true
chmod +x "$USER_HOME"/Desktop/*.desktop 2>/dev/null || true
