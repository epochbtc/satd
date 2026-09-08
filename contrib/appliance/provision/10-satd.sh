#!/bin/bash
# 10-satd.sh — install satd, sat-cli and sat-tui, and its service unit.
#
# Two sources:
#   SATD_SOURCE=release   fetch the signed release tarball and verify it
#                         with the published minisign key (default)
#   SATD_SOURCE=local     install from /provision/satd-bin, which build.sh
#                         populates from a locally built tree
#
# The release path verifies; the local path is for CI runs that test the
# commit under review and for developers building their own image, and it
# says so on the console rather than pretending an unsigned binary was
# checked.
set -euo pipefail
. /provision/common.sh

SATD_SOURCE="${SATD_SOURCE:-release}"
SATD_VERSION="${SATD_VERSION:-}"
# The primary release key, as published in SECURITY.md. Pinned here so the
# image build trusts the same key an operator verifying a tarball by hand
# would use.
SATD_MINISIGN_PUBKEY="${SATD_MINISIGN_PUBKEY:-RWQeP6MczCgPh6tU03GEMm4HsnGbXte3VT2Bc52TBSR7Q+X7WnL5vfQ3}"

case "$DEB_ARCH" in
    amd64) TARBALL_ARCH="x86_64-linux-gnu" ;;
    arm64) TARBALL_ARCH="aarch64-linux-gnu" ;;
esac

step "installing satd from source=$SATD_SOURCE"
install -d -m 0755 /usr/local/bin

if [[ "$SATD_SOURCE" == "release" ]]; then
    [[ -n "$SATD_VERSION" ]] || { echo "SATD_SOURCE=release requires SATD_VERSION" >&2; exit 1; }
    base="https://github.com/epochbtc/satd/releases/download/v${SATD_VERSION}"
    tarball="satd-${SATD_VERSION}-${TARBALL_ARCH}.tar.gz"
    tmp="$(mktemp -d)"
    fetch "$base/$tarball" "$tmp/$tarball"
    fetch "$base/$tarball.minisig" "$tmp/$tarball.minisig"

    # Verify before unpacking, not after. An unpacked archive has already
    # written whatever it wanted to the filesystem.
    step "verifying $tarball against the published minisign key"
    minisign -Vm "$tmp/$tarball" -P "$SATD_MINISIGN_PUBKEY"

    tar -xzf "$tmp/$tarball" -C "$tmp"
    found=0
    for bin in satd sat-cli sat-tui; do
        # `find ... | head -1` would abort here under pipefail whenever find
        # is still walking when head closes the pipe: a size-dependent
        # failure that passes on a small archive and not on a large one.
        matches=()
        mapfile -t matches < <(find "$tmp" -type f -name "$bin" -perm -u+x)
        path="${matches[0]:-}"
        [[ -n "$path" ]] || { echo "$bin missing from $tarball" >&2; exit 1; }
        install -m 0755 "$path" "/usr/local/bin/$bin"
        found=$((found + 1))
    done
    [[ "$found" == 3 ]]
    rm -rf "$tmp"
else
    echo "  NOTE: installing UNSIGNED binaries from a local build."
    echo "  NOTE: images built this way are for testing, not distribution."
    for bin in satd sat-cli sat-tui; do
        src="/provision/satd-bin/$bin"
        [[ -x "$src" ]] || { echo "missing $src" >&2; exit 1; }
        install -m 0755 "$src" "/usr/local/bin/$bin"
    done
    # Recorded in the image so a boot test — and anyone who later wonders
    # where the image came from — can tell a test build from a release one.
    echo "local" > /etc/satd-appliance-source
fi

/usr/local/bin/satd --version
/usr/local/bin/sat-cli --version > /dev/null

step "satd system user and datadir"
if ! getent group satd > /dev/null; then groupadd --system satd; fi
if ! id -u satd > /dev/null 2>&1; then
    useradd --system --gid satd --home-dir /var/lib/satd --shell /usr/sbin/nologin satd
fi
install -d -o satd -g satd -m 0750 /var/lib/satd
# The console user reads the cookie through group membership rather than
# sudo; the shipped unit relaxes the cookie to 0640 on every start for
# exactly this.
usermod -aG satd "$APPLIANCE_USER"

step "systemd unit"
install -Dm644 /provision/files/satd.service /etc/systemd/system/satd.service
# Not enabled here. First boot renders the configuration and issues the
# certificates before anything starts satd; an image that came up with a
# half-configured node would race that.
