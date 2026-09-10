#!/bin/bash
# 60-firstboot.sh — install the operator CLI and the first-boot unit.
set -euo pipefail
. /provision/common.sh

step "operator CLI"
install -Dm755 /provision/files/satd-appliance /usr/local/bin/satd-appliance

step "shared first-run scripts (the same ones the compose stack uses)"
install -Dm755 /provision/files/satd-init /usr/local/lib/satd-appliance/satd-init
install -Dm644 /provision/files/satd.conf.tmpl /usr/local/lib/satd-appliance/satd.conf.tmpl
install -Dm755 /provision/files/configure-network /usr/local/lib/satd-appliance/configure-network

step "first-boot unit"
install -Dm755 /provision/files/firstboot /usr/local/lib/satd-appliance/firstboot
install -Dm644 /provision/files/firstboot.service \
    /etc/systemd/system/satd-appliance-firstboot.service
systemctl enable satd-appliance-firstboot.service > /dev/null

step "default network"
install -d -m 0755 /var/lib/satd-appliance
echo "$SATD_NETWORK" > /var/lib/satd-appliance/network

step "shell hint on login"
cat > /etc/profile.d/99-satd-appliance.sh <<'PROFILE'
# Printed on interactive login. Short on purpose: the one command that
# answers "what is this box doing" and the one that makes it reachable.
if [ -n "${PS1:-}" ] && [ -z "${SATD_APPLIANCE_MOTD_SHOWN:-}" ]; then
    export SATD_APPLIANCE_MOTD_SHOWN=1
    echo
    echo "satd appliance — try:"
    echo "  satd-appliance status         what the node is doing"
    echo "  sat-tui -rpcport=8332         live dashboard"
    echo "  satd-appliance tls export-ca  the certificate to trust on other machines"
    echo
fi
PROFILE
