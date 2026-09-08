#!/bin/bash
# 00-base.sh — the base system every flavour shares.
#
# Runs inside the chroot of the image being built. Idempotent: the ISO and
# disk builders both run the whole provision tree, and a rebuild must not
# depend on which scripts ran before.
set -euo pipefail
. /provision/common.sh

# mmdebstrap cleans the package lists as its last act, so the chroot starts
# with no index at all and every apt-get install would fail with "unable to
# locate package".
step "refreshing the package index"
apt-get update

step "base packages"
apt_install \
    ca-certificates curl gnupg openssl \
    systemd-timesyncd systemd-resolved \
    nftables avahi-daemon libnss-mdns \
    sudo less vim-tiny bash-completion \
    jq python3-minimal \
    linux-image-"$DEB_ARCH" \
    initramfs-tools \
    dosfstools e2fsprogs parted cloud-guest-utils \
    qemu-guest-agent \
    minisign

# GRUB is installed to the disk by build.sh, from outside the chroot, so the
# `-bin` packages are what is wanted here: the full grub-pc / grub-efi
# packages run grub-install from their postinst against a device that does
# not exist yet in a chroot.
step "bootloader components"
apt_install grub2-common grub-common grub-pc-bin "grub-efi-${GRUB_EFI_ARCH}-bin"

step "hostname and hosts"
echo "$APPLIANCE_HOSTNAME" > /etc/hostname
cat > /etc/hosts <<HOSTS
127.0.0.1	localhost
127.0.1.1	$APPLIANCE_HOSTNAME
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters
HOSTS

step "networking (DHCP on any wired interface)"
mkdir -p /etc/systemd/network
cat > /etc/systemd/network/20-wired.network <<'NET'
[Match]
Name=en* eth*

[Network]
DHCP=yes
# The appliance is addressed by its mDNS name, so that a DHCP lease change
# does not invalidate the TLS certificate's address SANs.
MulticastDNS=yes

[DHCPv4]
UseDomains=yes
NET
systemctl enable systemd-networkd systemd-resolved systemd-timesyncd avahi-daemon > /dev/null

# systemd-resolved owns /etc/resolv.conf. The symlink is created here rather
# than left to first boot because the build chroot has a real resolv.conf
# copied in, which would otherwise persist into the image as a stale file
# pointing at the build host's nameserver.
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

step "users"
# The password is set at first boot and must be changed at first login;
# shipping a known one would make every downloaded image equally accessible.
if ! id -u "$APPLIANCE_USER" > /dev/null 2>&1; then
    useradd --create-home --shell /bin/bash --groups sudo "$APPLIANCE_USER"
fi
# Locked until first boot generates one. `!` is "no password accepted",
# which is not the same as an empty password.
usermod -p '!' "$APPLIANCE_USER"
usermod -p '!' root

step "firewall (default deny inbound)"
cat > /etc/nftables.conf <<'NFT'
#!/usr/sbin/nft -f
# Default-deny inbound. Only the surfaces the appliance advertises are open,
# and every one of them is either TLS-terminated or Bitcoin P2P.
#
# The plain RPC / Electrum / Esplora / metrics listeners are NOT here on
# purpose: they bind loopback and the container network, and are reachable
# from this machine only.
flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;

		iif "lo" accept
		ct state established,related accept
		ct state invalid drop

		# ICMP, including path-MTU discovery. Dropping it silently
		# breaks large transfers rather than blocking anything.
		ip protocol icmp accept
		ip6 nexthdr icmpv6 accept

		# mDNS: how clients find <hostname>.local, which is the name on
		# the TLS certificate.
		udp dport 5353 accept

		# Bitcoin P2P.
		tcp dport { 8333, 38333, 48333, 18333, 18444 } accept

		# The container overlays talk to a natively-run satd through the
		# docker bridge gateway, which is this host — so their packets
		# arrive on THIS chain, not on `forward`, and the default-drop
		# above would silence them. Restricted to the stack's own subnet:
		# these are the plain RPC, Electrum, Esplora, metrics and ZMQ
		# listeners, and nothing outside the bridge may reach them.
		#
		# Keep the subnet in step with SATD_STACK_SUBNET in
		# contrib/appliance/files/compose.appliance.yml.
		ip saddr 10.77.0.0/24 tcp dport { 8332, 50001, 3000, 9332, 28332 } accept

		# satd's TLS surfaces: JSON-RPC, Electrum, Esplora, MCP.
		tcp dport { 8336, 50002, 3001, 8339 } accept

		# Reverse proxy: web UIs and metrics, TLS with the same cert.
		tcp dport { 443, 8443, 9443 } accept

		# Lightning P2P (LND / CLN), when an overlay is enabled.
		tcp dport { 9735, 9736 } accept

		# SSH is closed. `satd-appliance ssh enable` opens it.
		counter drop
	}

	chain forward {
		# Docker installs its own rules in the ip/ip6 filter tables for
		# container traffic; this inet table's forward chain must not
		# also drop, or published container ports stop working.
		type filter hook forward priority filter; policy accept;
	}

	chain output {
		type filter hook output priority filter; policy accept;
	}
}
NFT
systemctl enable nftables > /dev/null

step "journald size cap"
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/50-appliance.conf <<'JRN'
[Journal]
# A node that runs for months on a 64 GB disk must not fill it with logs.
SystemMaxUse=512M
JRN

step "sshd off by default"
if [[ -f /lib/systemd/system/ssh.service ]]; then
    systemctl disable ssh > /dev/null 2>&1 || true
fi

step "done"
