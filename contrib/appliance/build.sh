#!/bin/bash
# build.sh — build a bootable satd appliance disk image.
#
#   sudo contrib/appliance/build.sh --flavor core --out out/
#   contrib/appliance/build-in-docker.sh --flavor core --out out/   # no root
#
# Output: a raw image plus qcow2, and for the desktop flavour a VMDK and OVA
# that VirtualBox and VMware import directly.
#
# ## Why this and not Packer
#
# Packer's QEMU builder drives Debian's installer through a preseed inside a
# running VM. That needs KVM to finish in a sensible time, needs a ~700 MB
# installer ISO, and fails in ways that can only be diagnosed by watching a
# VNC console. This builds the filesystem directly with mmdebstrap and
# installs a bootloader onto a loop device: no virtual machine, no KVM, no
# ISO, a few minutes rather than an hour, and every failure is a shell
# command that exited non-zero with its output on stdout. It runs unchanged
# on a GitHub-hosted runner and inside a container.
#
# What it needs: root (for loop devices and chroot) plus mmdebstrap, parted,
# and qemu-img. build-in-docker.sh supplies all of that in a container so
# the host needs none of it.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# shellcheck source=contrib/appliance/lib.sh
. "$HERE/lib.sh"

FLAVOR=core
ARCH=amd64
SUITE=trixie
MIRROR="${DEBIAN_MIRROR:-http://deb.debian.org/debian}"
NETWORK=signet
OUT="$HERE/out"
SIZE=""
SATD_SOURCE=local
SATD_BIN="$REPO/target/release"
SATD_VERSION=""
HOSTNAME_DEFAULT=satd
KEEP_ROOTFS=0
# When set, build.sh stops after provisioning and leaves the finished root
# filesystem at this path instead of writing a disk image. build-iso.sh uses
# it so the ISO is squashed from a tree provisioned by exactly this script,
# rather than by a second copy of the same steps that would drift from it.
ROOTFS_ONLY=""

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --flavor) FLAVOR="$2"; shift 2 ;;
        --arch) ARCH="$2"; shift 2 ;;
        --suite) SUITE="$2"; shift 2 ;;
        --network) NETWORK="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --size) SIZE="$2"; shift 2 ;;
        --satd-source) SATD_SOURCE="$2"; shift 2 ;;
        --satd-bin) SATD_BIN="$2"; shift 2 ;;
        --satd-version) SATD_VERSION="$2"; shift 2 ;;
        --hostname) HOSTNAME_DEFAULT="$2"; shift 2 ;;
        --keep-rootfs) KEEP_ROOTFS=1; shift ;;
        --rootfs-only) ROOTFS_ONLY="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "build.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$FLAVOR" in
    core|desktop) ;;
    *) echo "build.sh: --flavor must be core or desktop" >&2; exit 2 ;;
esac

# The core flavour is a headless node; the desktop one adds XFCE and the
# bundled wallets, which are several GB of packages.
if [[ -z "$SIZE" ]]; then
    [[ "$FLAVOR" == "core" ]] && SIZE=6G || SIZE=16G
fi

[[ "$(id -u)" == 0 ]] || { echo "build.sh: needs root (or use build-in-docker.sh)" >&2; exit 1; }
REQUIRED_TOOLS=(mmdebstrap chroot)
# The disk-image tools are only needed when a disk image is actually built.
[[ -n "$ROOTFS_ONLY" ]] || REQUIRED_TOOLS+=(parted qemu-img losetup mkfs.ext4 mkfs.vfat)
for tool in "${REQUIRED_TOOLS[@]}"; do
    command -v "$tool" > /dev/null || { echo "build.sh: missing $tool" >&2; exit 1; }
done

VERSION_TAG="${SATD_VERSION:-$(grep -m1 '^version' "$REPO/Cargo.toml" | cut -d'"' -f2)}"
IMAGE_NAME="satd-appliance-${VERSION_TAG}-${FLAVOR}-${ARCH}"

WORK="$(mktemp -d /var/tmp/satd-appliance.XXXXXX)"
if [[ -n "$ROOTFS_ONLY" ]]; then
    ROOTFS="$ROOTFS_ONLY"
    mkdir -p "$(dirname "$ROOTFS")"
    rm -rf "$ROOTFS"
else
    ROOTFS="$WORK/rootfs"
fi
RAW="$WORK/$IMAGE_NAME.raw"
LOOP=""

cleanup() {
    set +e
    if [[ -n "$LOOP" ]]; then
        umount -R "$WORK/mnt" 2>/dev/null
        losetup -d "$LOOP" 2>/dev/null
    fi
    umount -R "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" 2>/dev/null
    [[ "$KEEP_ROOTFS" == 1 ]] || rm -rf "$WORK"
    # $ROOTFS is outside $WORK in --rootfs-only mode; the caller owns it.
    [[ "$KEEP_ROOTFS" == 0 ]] || echo "build.sh: --keep-rootfs; work tree at $WORK"
}
trap cleanup EXIT

say() { echo "==> $*"; }

# ---------------------------------------------------------------------------
# 1. Base filesystem
# ---------------------------------------------------------------------------
say "debootstrapping $SUITE/$ARCH"
# --variant=important is the smallest set that still has a working apt and
# systemd; `minbase` omits enough that the provision scripts would spend
# their first minutes reinstalling it.
mmdebstrap \
    --arch="$ARCH" \
    --variant=important \
    --components="main,contrib,non-free-firmware" \
    --include="systemd-sysv,dbus,locales" \
    "$SUITE" "$ROOTFS" "$MIRROR"

# ---------------------------------------------------------------------------
# 2. Stage the provisioning tree and everything it installs
# ---------------------------------------------------------------------------
say "staging the provisioning tree"
mkdir -p "$ROOTFS/provision/files"
cp -a "$HERE/provision/." "$ROOTFS/provision/"

# Files the provision scripts install, gathered here so each script can
# assume a flat /provision/files rather than knowing the repository layout.
cp "$REPO/contrib/stack/tls/mkca.sh"            "$ROOTFS/provision/files/mkca.sh"
cp "$REPO/contrib/stack/satd/satd-init"         "$ROOTFS/provision/files/satd-init"
cp "$REPO/contrib/stack/satd/satd.conf.tmpl"    "$ROOTFS/provision/files/satd.conf.tmpl"
cp "$REPO/contrib/systemd/satd.service"         "$ROOTFS/provision/files/satd.service"
cp "$HERE/bin/satd-appliance"                   "$ROOTFS/provision/files/satd-appliance"
cp "$HERE/firstboot/satd-appliance-firstboot"   "$ROOTFS/provision/files/firstboot"
cp "$HERE/files/configure-network"              "$ROOTFS/provision/files/configure-network"
cp "$HERE/firstboot/satd-appliance-firstboot.service" "$ROOTFS/provision/files/firstboot.service"

# The compose stack, as the appliance runs it: every overlay, plus the
# appliance's replacement for compose.yml.
mkdir -p "$ROOTFS/provision/files/stack"
cp "$REPO"/contrib/stack/compose.*.yml          "$ROOTFS/provision/files/stack/"
rm -f "$ROOTFS/provision/files/stack/compose.yml"
cp -a "$REPO/contrib/stack/caddy"               "$ROOTFS/provision/files/stack/"
cp "$HERE/files/compose.appliance.yml"          "$ROOTFS/provision/files/stack/"

if [[ "$FLAVOR" == "desktop" ]]; then
    cp -a "$HERE/files/desktop/." "$ROOTFS/provision/files/" 2>/dev/null || true
fi

if [[ "$SATD_SOURCE" == "local" ]]; then
    say "staging locally built binaries from $SATD_BIN"
    mkdir -p "$ROOTFS/provision/satd-bin"
    for bin in satd sat-cli sat-tui; do
        [[ -x "$SATD_BIN/$bin" ]] || { echo "build.sh: no $SATD_BIN/$bin — build them first" >&2; exit 1; }
        install -m 0755 "$SATD_BIN/$bin" "$ROOTFS/provision/satd-bin/$bin"
    done
fi

# ---------------------------------------------------------------------------
# 3. Provision, in the chroot
# ---------------------------------------------------------------------------
say "provisioning ($FLAVOR)"
mount --bind /dev "$ROOTFS/dev"
mount -t proc proc "$ROOTFS/proc"
mount -t sysfs sys "$ROOTFS/sys"
# apt needs working DNS inside the chroot. Replaced by a symlink to
# systemd-resolved's stub in 00-base.sh, so the build host's resolver does
# not survive into the image.
cp /etc/resolv.conf "$ROOTFS/etc/resolv.conf"

# `policy-rc.d` returning 101 stops package postinsts from starting daemons
# inside the chroot, where there is no init to start them under.
cat > "$ROOTFS/usr/sbin/policy-rc.d" <<'POLICY'
#!/bin/sh
exit 101
POLICY
chmod +x "$ROOTFS/usr/sbin/policy-rc.d"

SCRIPTS=(00-base.sh 10-satd.sh 20-tls.sh)
[[ "$FLAVOR" == "desktop" ]] && SCRIPTS+=(30-desktop.sh 40-wallets.sh)
SCRIPTS+=(50-containers.sh 60-firstboot.sh 90-cleanup.sh)

for script in "${SCRIPTS[@]}"; do
    say "  $script"
    chroot "$ROOTFS" env \
        SATD_FLAVOR="$FLAVOR" \
        SATD_NETWORK="$NETWORK" \
        DEB_ARCH="$ARCH" \
        APPLIANCE_HOSTNAME="$HOSTNAME_DEFAULT" \
        SATD_SOURCE="$SATD_SOURCE" \
        SATD_VERSION="$VERSION_TAG" \
        /bin/bash "/provision/$script"
done

rm -f "$ROOTFS/usr/sbin/policy-rc.d"

unmount_chroot "$ROOTFS"

if [[ -n "$ROOTFS_ONLY" ]]; then
    say "provisioned root filesystem left at $ROOTFS"
    exit 0
fi

# ---------------------------------------------------------------------------
# 4. Disk image
# ---------------------------------------------------------------------------
say "creating a $SIZE disk"
truncate -s "$SIZE" "$RAW"

# GPT with a BIOS boot partition *and* an ESP. VirtualBox defaults to BIOS
# and most other hypervisors default to UEFI; carrying both means the same
# file boots either way, which is the whole point of shipping one image.
parted -s "$RAW" mklabel gpt
parted -s "$RAW" mkpart bios_grub 1MiB 3MiB
parted -s "$RAW" set 1 bios_grub on
parted -s "$RAW" mkpart ESP fat32 3MiB 515MiB
parted -s "$RAW" set 2 esp on
parted -s "$RAW" mkpart root ext4 515MiB 100%

LOOP="$(losetup --find --show --partscan "$RAW")"

# The kernel scans the partition table and creates the block devices, but
# the /dev nodes for them are made by udev — which is not running inside a
# build container. Without this the loop device exists, its partitions exist
# in sysfs, and `mkfs` fails on a path that is simply absent.
ensure_partition_nodes() {
    local loop="$1"
    local base; base="$(basename "$loop")"
    partprobe "$loop" 2>/dev/null || true
    local sysdir
    for sysdir in /sys/block/"$base"/"$base"p*; do
        [[ -d "$sysdir" ]] || continue
        local node="/dev/$(basename "$sysdir")"
        [[ -b "$node" ]] && continue
        local devnum; devnum="$(cat "$sysdir/dev")"
        mknod "$node" b "${devnum%%:*}" "${devnum##*:}"
        echo "    created $node (${devnum})"
    done
}

for _ in $(seq 1 20); do
    ensure_partition_nodes "$LOOP"
    [[ -b "${LOOP}p3" ]] && break
    sleep 0.5
done
[[ -b "${LOOP}p3" ]] || { echo "build.sh: partition devices never appeared for $LOOP" >&2; exit 1; }

mkfs.vfat -F32 -n ESP "${LOOP}p2" > /dev/null
mkfs.ext4 -q -L satd-root "${LOOP}p3"

mkdir -p "$WORK/mnt"
mount "${LOOP}p3" "$WORK/mnt"
mkdir -p "$WORK/mnt/boot/efi"
mount "${LOOP}p2" "$WORK/mnt/boot/efi"

say "copying the filesystem"
# `-x` keeps the copy on one filesystem, so the bind mounts undone above
# cannot be walked into even if one lingered.
cp -ax "$ROOTFS/." "$WORK/mnt/"

ROOT_UUID="$(blkid -s UUID -o value "${LOOP}p3")"
ESP_UUID="$(blkid -s UUID -o value "${LOOP}p2")"
cat > "$WORK/mnt/etc/fstab" <<FSTAB
# Written by contrib/appliance/build.sh. UUIDs, not device names: the disk
# appears as /dev/sda, /dev/vda or /dev/nvme0n1 depending on the hypervisor.
UUID=$ROOT_UUID  /          ext4  errors=remount-ro  0 1
UUID=$ESP_UUID   /boot/efi  vfat  umask=0077         0 1
FSTAB

say "installing the bootloader"
mount --bind /dev "$WORK/mnt/dev"
mount -t proc proc "$WORK/mnt/proc"
mount -t sysfs sys "$WORK/mnt/sys"

cat > "$WORK/mnt/etc/default/grub" <<'GRUB'
GRUB_DEFAULT=0
# Short but not zero: an operator who needs to reach recovery on a headless
# VM has no other way in.
GRUB_TIMEOUT=3
GRUB_DISTRIBUTOR="satd appliance"
# console= twice: the kernel logs to both the graphical console and the
# serial port, which is the only console a headless boot test has.
GRUB_CMDLINE_LINUX_DEFAULT="console=tty0 console=ttyS0,115200n8"
GRUB_CMDLINE_LINUX=""
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --speed=115200"
GRUB
chroot "$WORK/mnt" grub-install --target=i386-pc --boot-directory=/boot "$LOOP"
chroot "$WORK/mnt" grub-install --target="$( [[ $ARCH == amd64 ]] && echo x86_64 || echo arm64 )-efi" \
    --efi-directory=/boot/efi --boot-directory=/boot --removable --no-nvram
chroot "$WORK/mnt" update-grub 2>&1 | sed 's/^/    /'

# grub-mkconfig derives root= from `grub-probe --target=fs_uuid /`. Inside a
# build container that probe can come back empty, and 10_linux then falls
# back to GRUB_DEVICE — which here is the BUILD HOST's loop device. The
# image boots, the kernel starts, and the initramfs then waits forever for
# a /dev/loopNpM that exists on no machine but the builder.
#
# So the root reference is rewritten to the UUID and then checked. The check
# is the point: this failure is invisible until someone boots the image.
sed -i "s|root=/dev/[^ ]*|root=UUID=$ROOT_UUID|g" "$WORK/mnt/boot/grub/grub.cfg"
if grep -q 'root=/dev/' "$WORK/mnt/boot/grub/grub.cfg"; then
    echo "build.sh: grub.cfg still names a device path for root:" >&2
    grep -n 'root=/dev/' "$WORK/mnt/boot/grub/grub.cfg" >&2
    exit 1
fi
if ! grep -q "root=UUID=$ROOT_UUID" "$WORK/mnt/boot/grub/grub.cfg"; then
    echo "build.sh: grub.cfg does not reference the root filesystem UUID" >&2
    grep -n 'linux\s' "$WORK/mnt/boot/grub/grub.cfg" >&2
    exit 1
fi
say "  root=UUID=$ROOT_UUID"

umount -R "$WORK/mnt/dev" "$WORK/mnt/proc" "$WORK/mnt/sys"
umount -R "$WORK/mnt"
losetup -d "$LOOP"; LOOP=""

# ---------------------------------------------------------------------------
# 5. Output formats
# ---------------------------------------------------------------------------
mkdir -p "$OUT"
say "converting"
qemu-img convert -f raw -O qcow2 -c "$RAW" "$OUT/$IMAGE_NAME.qcow2"
mv "$RAW" "$OUT/$IMAGE_NAME.raw"

if [[ "$FLAVOR" == "desktop" ]]; then
    # VirtualBox and VMware want a stream-optimised VMDK inside an OVA.
    qemu-img convert -f raw -O vmdk -o subformat=streamOptimized \
        "$OUT/$IMAGE_NAME.raw" "$WORK/$IMAGE_NAME.vmdk"
    "$HERE/mkova.sh" \
        --vmdk "$WORK/$IMAGE_NAME.vmdk" \
        --name "$IMAGE_NAME" \
        --out "$OUT/$IMAGE_NAME.ova"
fi

( cd "$OUT" && sha256sum "$IMAGE_NAME".* > "$IMAGE_NAME.SHA256SUMS" )

say "built:"
ls -lh "$OUT/$IMAGE_NAME".* | sed 's/^/    /'
