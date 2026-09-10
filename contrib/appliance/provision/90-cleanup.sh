#!/bin/bash
# 90-cleanup.sh — strip everything that must not ship, then assert it is gone.
#
# The assertions at the end are the point. This image is downloaded by
# strangers; a private key, a machine-id or a live cookie baked into it
# would be shared by every one of them, and the failure would be silent.
set -euo pipefail
. /provision/common.sh

step "apt caches"
apt-get autoremove -y > /dev/null
apt-get clean
rm -rf /var/lib/apt/lists/*

step "logs and transient state"
find /var/log -type f -exec truncate -s 0 {} \; 2>/dev/null || true
rm -rf /tmp/* /var/tmp/* 2>/dev/null || true
rm -f /root/.bash_history "/home/$APPLIANCE_USER/.bash_history" 2>/dev/null || true

step "machine identity"
# An empty (not missing) /etc/machine-id makes systemd generate a fresh one
# at first boot. A missing file makes some initramfs setups fail instead.
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -sf /etc/machine-id /var/lib/dbus/machine-id

step "host keys"
# sshd is off by default, but if the package pulled keys in, they must not
# be the same on every download.
rm -f /etc/ssh/ssh_host_*

step "provisioning tree"
rm -rf /provision

step "asserting the image carries no secrets"
fail=0
check_absent() {
    local desc="$1"; shift
    local found
    # No `| head`. Under `set -o pipefail` a truncating pipe makes the
    # producer die of SIGPIPE and the assignment fail — which, in the one
    # function whose job is to detect a leak, would abort the script instead
    # of reporting the leak. The listing is trimmed afterwards, in the shell.
    local all
    all="$("$@" 2>/dev/null || true)"
    if [[ -n "$all" ]]; then
        local lines=()
        mapfile -t lines <<< "$all"
        found="$(printf '%s\n' "${lines[@]:0:5}")"
    else
        found=""
    fi
    if [[ -n "$found" ]]; then
        echo "  SECRET LEAK: $desc" >&2
        echo "$found" | sed 's/^/    /' >&2
        fail=1
    else
        echo "  ok: $desc"
    fi
}

check_absent "no TLS private keys" find / -xdev -name '*.key' -path '*satd*'
check_absent "no CA material in the datadir" find /var/lib/satd -mindepth 1
check_absent "no RPC cookie" find / -xdev -name '.cookie'
check_absent "no authfile" find / -xdev -name 'authfile.toml'
check_absent "no MCP token" find / -xdev -name 'mcp-token'
check_absent "no ssh host keys" find /etc/ssh -name 'ssh_host_*'
check_absent "no first-boot marker" find /var/lib/satd-appliance -name 'firstboot-done'
check_absent "no saved initial password" find /var/lib/satd-appliance -name 'initial-password'

# A non-empty machine-id would make every install of this image report the
# same identity to the network.
if [[ -s /etc/machine-id ]]; then
    echo "  SECRET LEAK: /etc/machine-id is not empty" >&2
    fail=1
else
    echo "  ok: machine-id is empty"
fi

# Locked, not blank. `!` in the password field accepts nothing; an empty
# field would let anyone in at the console.
for u in root "$APPLIANCE_USER"; do
    hash="$(awk -F: -v u="$u" '$1==u{print $2}' /etc/shadow)"
    if [[ "$hash" == "!" || "$hash" == "*" || "$hash" == "!"* ]]; then
        echo "  ok: $u has no usable password in the image"
    else
        echo "  SECRET LEAK: $u ships with a password hash ('$hash')" >&2
        fail=1
    fi
done

[[ "$fail" == 0 ]] || { echo "90-cleanup.sh: refusing to finish a leaky image" >&2; exit 1; }

# No free-space zeroing here. This script runs against a debootstrap
# *directory*, not a mounted filesystem image, so writing a zero file would
# fill the build host's disk rather than the appliance's. It would also be
# pointless: build.sh copies this tree into a freshly created ext4, whose
# unallocated blocks are already zero, and qcow2 compression sees them as
# such.
sync

step "done"
