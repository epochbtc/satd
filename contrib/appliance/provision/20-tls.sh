#!/bin/bash
# 20-tls.sh — install the certificate tooling and its renewal timer.
#
# No certificate is created here. The CA key is generated on first boot, on
# the machine that will use it: a CA shipped inside a downloadable image
# would be a private key every download shared, which is not a CA at all.
# 90-cleanup.sh asserts none exists, and the boot test asserts one appears.
set -euo pipefail
. /provision/common.sh

step "certificate tooling"
install -Dm755 /provision/files/mkca.sh /usr/local/lib/satd-appliance/mkca.sh

step "renewal timer"
install_unit satd-tls-renew.service <<'UNIT'
[Unit]
Description=Renew the satd appliance TLS certificate when it is near expiry
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
# Re-runs mkca.sh, which is a no-op unless the certificate expires within 30
# days or the machine's names/addresses have changed. Both are worth acting
# on: the second is what happens when DHCP moves the appliance, and a
# certificate that no longer covers the address clients use fails closed.
ExecStart=/usr/local/bin/satd-appliance tls renew --quiet
UNIT

install_unit satd-tls-renew.timer <<'UNIT'
[Unit]
Description=Daily check of the satd appliance TLS certificate

[Timer]
OnCalendar=daily
# The appliance is often off overnight; a missed daily run must happen at
# the next boot rather than wait for the next window.
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
UNIT
