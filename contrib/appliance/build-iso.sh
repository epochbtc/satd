#!/bin/bash
# build-iso.sh — build a live ISO from the same provisioning tree the disk
# image uses.
#
#   sudo contrib/appliance/build-iso.sh --flavor desktop --out out/
#   contrib/appliance/build-iso-in-docker.sh --flavor desktop --out out/
#
# "Try it without installing anything, from a USB stick." The rootfs is
# built exactly as build.sh builds it — same provision/ scripts, same
# packages, same first-boot behaviour — and then squashed and made bootable
# rather than written to a partitioned disk. That sharing is the point:
# two build paths that provisioned differently would drift, and the ISO is
# the one nobody tests as often.
#
# Boots on BIOS and UEFI from the same file. `satd-appliance install-to-disk`
# copies the running live system onto a real disk.
#
# Note on persistence: a live session keeps everything in RAM, so first boot
# runs on every boot and the chain it syncs is lost at power-off. That is
# what live media are; install to disk for anything you want to keep.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# shellcheck source=contrib/appliance/lib.sh
. "$HERE/lib.sh"

FLAVOR=desktop
ARCH=amd64
SUITE=trixie
NETWORK=signet
OUT="$HERE/out"
SATD_SOURCE=local
SATD_BIN="$REPO/target/release"
SATD_VERSION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --flavor) FLAVOR="$2"; shift 2 ;;
        --arch) ARCH="$2"; shift 2 ;;
        --suite) SUITE="$2"; shift 2 ;;
        --network) NETWORK="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --satd-source) SATD_SOURCE="$2"; shift 2 ;;
        --satd-bin) SATD_BIN="$2"; shift 2 ;;
        --satd-version) SATD_VERSION="$2"; shift 2 ;;
        -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "build-iso.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ "$(id -u)" == 0 ]] || { echo "build-iso.sh: needs root" >&2; exit 1; }
for tool in mmdebstrap mksquashfs xorriso grub-mkrescue; do
    command -v "$tool" > /dev/null || { echo "build-iso.sh: missing $tool" >&2; exit 1; }
done

VERSION_TAG="${SATD_VERSION:-$(grep -m1 '^version' "$REPO/Cargo.toml" | cut -d'"' -f2)}"
ISO_NAME="satd-appliance-${VERSION_TAG}-${FLAVOR}-${ARCH}-live"

WORK="$(mktemp -d /var/tmp/satd-iso.XXXXXX)"
ROOTFS="$WORK/rootfs"
ISOTREE="$WORK/iso"
# The status is captured on entry and re-raised at the end. Left to itself a
# trap whose last command fails reports THAT failure — and tearing down a
# chroot fails routinely (already-unmounted paths, a busy /dev) — so the
# builder would write a perfectly good ISO and then exit non-zero, which in
# CI is indistinguishable from a broken build.
cleanup_iso() {
    local status=$?
    # `set +e` first: with errexit still on, any non-zero step in the
    # teardown aborts this function before it reaches the `exit` below, and
    # bash then reports 1 — losing both the success it should have reported
    # and any real failure code it was carrying.
    set +e
    unmount_chroot "$ROOTFS"
    rm -rf "$WORK" 2>/dev/null
    exit "$status"
}
trap cleanup_iso EXIT

say() { echo "==> $*"; }

say "building the root filesystem (the same provisioning tree as build.sh)"
# `--rootfs-only` stops build.sh where it would otherwise partition a disk,
# and hands back the provisioned tree. One provisioning path, two outputs —
# the alternative is a second copy of the same steps that drifts from the
# first.
"$HERE/build.sh" \
    --flavor "$FLAVOR" --arch "$ARCH" --suite "$SUITE" \
    --network "$NETWORK" --satd-source "$SATD_SOURCE" \
    --satd-bin "$SATD_BIN" --satd-version "$VERSION_TAG" \
    --rootfs-only "$ROOTFS"

say "adding the live-boot components"
mount --bind /dev "$ROOTFS/dev"
mount -t proc proc "$ROOTFS/proc"
mount -t sysfs sys "$ROOTFS/sys"

# Provisioning left /etc/resolv.conf as a symlink to systemd-resolved's stub,
# which does not exist inside a chroot — so a plain `cp` onto it refuses to
# write through a dangling symlink. Replace it for the duration of the apt
# work below, then put the symlink back: shipping the build host's
# nameserver in the image is precisely what 00-base.sh made it a symlink to
# avoid.
rm -f "$ROOTFS/etc/resolv.conf"
cp /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
chroot "$ROOTFS" bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update
# live-boot supplies the initramfs hook that finds and mounts the squashfs;
# live-config sets up the live session (autologin, hostname) at boot.
apt-get install -y --no-install-recommends live-boot live-config live-config-systemd
update-initramfs -u -k all
apt-get clean
rm -rf /var/lib/apt/lists/*
'
ln -sf /run/systemd/resolve/stub-resolv.conf "$ROOTFS/etc/resolv.conf"
unmount_chroot "$ROOTFS"

KERNEL="$(basename "$(ls "$ROOTFS"/boot/vmlinuz-* | sort -V | tail -1)")"
INITRD="$(basename "$(ls "$ROOTFS"/boot/initrd.img-* | sort -V | tail -1)")"

say "assembling the ISO tree"
mkdir -p "$ISOTREE/live" "$ISOTREE/boot/grub"
cp "$ROOTFS/boot/$KERNEL" "$ISOTREE/live/vmlinuz"
cp "$ROOTFS/boot/$INITRD" "$ISOTREE/live/initrd.img"

say "squashing the filesystem (this is the slow part)"
# -noappend so a rerun replaces rather than accumulates; xz for size,
# because this file is most of the download.
mksquashfs "$ROOTFS" "$ISOTREE/live/filesystem.squashfs" \
    -noappend -comp xz -e boot -quiet

cat > "$ISOTREE/boot/grub/grub.cfg" <<GRUBCFG
set default=0
set timeout=5

# Serial as well as the display: a headless boot test has no other console.
serial --speed=115200
terminal_input console serial
terminal_output console serial

menuentry "satd appliance (live)" {
    linux /live/vmlinuz boot=live components quiet splash console=tty0 console=ttyS0,115200n8
    initrd /live/initrd.img
}

menuentry "satd appliance (live, verbose)" {
    linux /live/vmlinuz boot=live components console=tty0 console=ttyS0,115200n8
    initrd /live/initrd.img
}
GRUBCFG

mkdir -p "$OUT"
say "making it bootable on BIOS and UEFI"
grub-mkrescue -o "$OUT/$ISO_NAME.iso" "$ISOTREE" \
    -- -volid "SATD_APPLIANCE" 2>&1 | sed 's/^/    /'

( cd "$OUT" && sha256sum "$ISO_NAME.iso" > "$ISO_NAME.iso.sha256" )
say "built:"
ls -lh "$OUT/$ISO_NAME.iso" | sed 's/^/    /'
