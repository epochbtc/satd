# shellcheck shell=bash
# Shared helpers for the appliance builders. Sourced by build.sh and
# build-iso.sh, which otherwise would each carry their own copy of the one
# piece of this that is genuinely fiddly: taking a chroot apart again.

# Unmount a chroot's pseudo-filesystems, and mean it.
#
# This is where a finished build is most easily thrown away. Anything a
# package's postinst left running inside the chroot — gpg-agent and dirmngr
# are the usual culprits — holds a mount open, and a bare `umount -R` under
# `set -e` then discards the whole build at the last step. So: stop the
# stragglers, retry, and fall back to a lazy detach, which is safe because
# nothing is written through these mounts afterwards.
unmount_chroot() {
    local root="$1"
    # `fuser -k` is best-effort; the builder container may not have it, and
    # the retry below is the real mechanism.
    if command -v fuser > /dev/null 2>&1; then
        fuser -km "$root/dev" > /dev/null 2>&1 || true
        sleep 1
    fi
    local mp i
    for mp in "$root/dev" "$root/proc" "$root/sys"; do
        mountpoint -q "$mp" 2>/dev/null || continue
        for i in 1 2 3 4 5; do
            umount -R "$mp" 2>/dev/null && break
            sleep 1
        done
        if mountpoint -q "$mp" 2>/dev/null; then
            echo "==>   $mp is still busy; detaching lazily"
            umount -Rl "$mp" 2>/dev/null || true
        fi
    done
}
