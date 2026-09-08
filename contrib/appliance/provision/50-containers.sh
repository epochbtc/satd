#!/bin/bash
# 50-containers.sh — Docker engine plus the reference stack, staged on disk.
#
# The overlays are not started here and no images are pulled at build time:
# a pulled image would age inside the download and would have to be
# refreshed anyway on first boot. `satd-appliance enable <overlay>` pulls on
# demand.
set -euo pipefail
. /provision/common.sh

step "docker engine from Docker's apt repository"
install -m 0755 -d /etc/apt/keyrings
fetch "https://download.docker.com/linux/debian/gpg" /tmp/docker.asc
gpg --dearmor < /tmp/docker.asc > /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
rm -f /tmp/docker.asc

# `signed-by` pins this repository to that key alone, so it cannot sign for
# anything else in the sources list.
cat > /etc/apt/sources.list.d/docker.list <<LIST
deb [arch=$DEB_ARCH signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian trixie stable
LIST
apt-get update
apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Docker starts on demand. The appliance's own node runs natively under
# systemd, so an install with no overlays enabled has no reason to keep a
# container runtime resident.
systemctl disable docker.service docker.socket > /dev/null 2>&1 || true

usermod -aG docker "$APPLIANCE_USER"

step "staging the reference stack in /opt/satd/stack"
install -d -m 0755 /opt/satd/stack
cp -a /provision/files/stack/. /opt/satd/stack/
