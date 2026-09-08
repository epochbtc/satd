# shellcheck shell=bash
# Shared helpers for the provision scripts. Sourced, not executed — the
# directive above tells shellcheck which shell to check against, since
# there is no shebang to infer it from.
#
# Every variable read here is exported by build.sh; the defaults exist so a
# script can be run by hand against a chroot for debugging.

export DEBIAN_FRONTEND=noninteractive

SATD_FLAVOR="${SATD_FLAVOR:-core}"
SATD_NETWORK="${SATD_NETWORK:-signet}"
APPLIANCE_USER="${APPLIANCE_USER:-satd-user}"
APPLIANCE_HOSTNAME="${APPLIANCE_HOSTNAME:-satd}"
DEB_ARCH="${DEB_ARCH:-amd64}"

case "$DEB_ARCH" in
    amd64) GRUB_EFI_ARCH=amd64 ;;
    arm64) GRUB_EFI_ARCH=arm64 ;;
    *) echo "unsupported architecture: $DEB_ARCH" >&2; exit 1 ;;
esac

export SATD_FLAVOR SATD_NETWORK APPLIANCE_USER APPLIANCE_HOSTNAME DEB_ARCH GRUB_EFI_ARCH

step() { echo "  [$(basename "$0")] $*"; }

# apt-get with the flags that matter for a reproducible-ish image: no
# recommends (they pull half a desktop into a headless build), and no
# interactive prompts.
apt_install() {
    apt-get install -y --no-install-recommends "$@"
}

# Fetch a URL to a path, with retries. Every download in this tree is
# verified afterwards — by minisign, by GPG, or by SHA-256 — so this only
# has to be reliable, not trusted.
fetch() {
    local url="$1" out="$2"
    for attempt in 1 2 3; do
        if curl -fsSL --retry 3 --retry-delay 2 -o "$out" "$url"; then
            return 0
        fi
        echo "  fetch attempt $attempt failed: $url" >&2
        sleep $((attempt * 3))
    done
    echo "  giving up on $url" >&2
    return 1
}

# Install a systemd unit from a heredoc and enable it.
install_unit() {
    local name="$1"
    cat > "/etc/systemd/system/$name"
    systemctl enable "$name" > /dev/null
}
