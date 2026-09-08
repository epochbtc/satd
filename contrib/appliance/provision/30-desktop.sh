#!/bin/bash
# 30-desktop.sh — XFCE, a browser that trusts the appliance, and a desktop
# that explains itself. Desktop flavour only.
set -euo pipefail
. /provision/common.sh

step "XFCE and a display manager"
apt_install \
    xfce4 xfce4-terminal xfce4-notifyd \
    lightdm lightdm-gtk-greeter \
    dbus-x11 xdg-utils \
    firefox-esr \
    fonts-dejavu-core \
    qrencode \
    network-manager-gnome \
    mousepad ristretto

step "autologin for the console user"
# Autologin because this is an appliance someone downloads and boots: the
# first thing they should see is the node, not a login prompt for a password
# that first boot has only just generated and printed on the console.
mkdir -p /etc/lightdm/lightdm.conf.d
cat > /etc/lightdm/lightdm.conf.d/50-satd-appliance.conf <<LIGHTDM
[Seat:*]
autologin-user=$APPLIANCE_USER
autologin-user-timeout=0
user-session=xfce
LIGHTDM
# lightdm needs the user in `autologin` for a passwordless session.
groupadd -f autologin
usermod -aG autologin "$APPLIANCE_USER"

step "Firefox trusts the appliance CA"
# Certificates.Install takes an absolute path from Firefox 65 on. The file
# does not exist at build time — first boot creates it — and Firefox reads
# the policy at startup, so by the time a browser runs the CA is there.
install -d -m 0755 /etc/firefox/policies
cat > /etc/firefox/policies/policies.json <<'POLICY'
{
  "policies": {
    "Certificates": {
      "ImportEnterpriseRoots": true,
      "Install": ["/var/lib/satd/tls/ca.crt"]
    },
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DontCheckDefaultBrowser": true,
    "OverrideFirstRunPage": "file:///usr/share/satd-appliance/welcome.html",
    "Homepage": {
      "URL": "file:///usr/share/satd-appliance/welcome.html",
      "StartPage": "homepage"
    }
  }
}
POLICY

step "desktop launchers"
install -d -m 0755 /usr/share/applications
cat > /usr/share/applications/satd-tui.desktop <<'DESK'
[Desktop Entry]
Type=Application
Name=satd dashboard (sat-tui)
Comment=Live view of the node: chain, mempool, peers
Exec=xfce4-terminal --title="satd" --geometry=140x45 --command="sat-tui -rpcport=8332"
Icon=utilities-system-monitor
Terminal=false
Categories=System;Monitor;
DESK

cat > /usr/share/applications/satd-status.desktop <<'DESK'
[Desktop Entry]
Type=Application
Name=Appliance status
Comment=Network, sync progress, enabled services, certificate
Exec=xfce4-terminal --hold --title="satd-appliance status" --command="satd-appliance status"
Icon=dialog-information
Terminal=false
Categories=System;
DESK

cat > /usr/share/applications/satd-readme.desktop <<'DESK'
[Desktop Entry]
Type=Application
Name=Start here
Comment=What this appliance is and what to do with it
Exec=xdg-open /usr/share/satd-appliance/welcome.html
Icon=text-html
Terminal=false
Categories=Documentation;
DESK

step "welcome page"
install -d -m 0755 /usr/share/satd-appliance
install -Dm644 /provision/files/welcome.html /usr/share/satd-appliance/welcome.html

step "desktop shortcuts for the console user"
USER_HOME="$(getent passwd "$APPLIANCE_USER" | cut -d: -f6)"
install -d -o "$APPLIANCE_USER" -g "$APPLIANCE_USER" -m 0755 "$USER_HOME/Desktop"
for d in satd-readme satd-status satd-tui; do
    cp "/usr/share/applications/$d.desktop" "$USER_HOME/Desktop/"
    chmod +x "$USER_HOME/Desktop/$d.desktop"
done
chown -R "$APPLIANCE_USER:$APPLIANCE_USER" "$USER_HOME/Desktop"

step "no screen lock or suspend"
# A node is meant to keep running. A suspended appliance stops syncing and
# looks broken.
mkdir -p /etc/xdg/autostart
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target > /dev/null
