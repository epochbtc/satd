# satd appliance image

A downloadable virtual machine that boots into a working Bitcoin node with
every satd surface on and TLS everywhere, plus the wallets and Lightning
software people actually point at a node.

The point is not convenience alone. Every third-party application here is a
**compatibility claim** about satd, and one that a CI job re-checks rather
than a sentence in a README.

## Support

**satd in this image is supported** — the same release artifact as the
tarballs and the container image.

**The bundled third-party software is best-effort, for evaluation and
testing, and is not a production deployment.** Its security advisories are
not tracked here in real time, and a critical fix in a bundled component may
not appear in an appliance image until the next scheduled build. For
production, run satd from a release artifact and operate the other
components yourself.

## Flavours

| Flavour | Contents | Disk | Built for |
|---|---|---|---|
| `core` | satd, `sat-cli`, `sat-tui`, MCP, the container overlays staged but idle | 6 GB grown at first boot | headless VMs, mini-PCs, the CI boot gate |
| `desktop` | the above plus XFCE, Firefox, Sparrow, Electrum, Liana | 16 GB grown at first boot | trying it on a laptop |

Both boot on **signet** by default. It is the only network on which the
whole thing is a one-evening exercise: a fully indexed node syncs in well
under an hour, faucets supply coins, and Lightning and ecash work end to end
with no real money. `satd-appliance set-network mainnet` switches, and
refuses below 1.5 TB free.

There is no prune option on any network. Electrum and Esplora both require
`txindex`, and `txindex` excludes pruning, so mainnet here means the full
chain plus every index.

## Building

```sh
# From a local build of satd. No root, no KVM: everything runs in a container.
cargo build --release --bin satd --bin sat-cli --bin sat-tui
contrib/appliance/build-in-docker.sh --flavor core --out contrib/appliance/out

# From a published, signed release instead.
contrib/appliance/build-in-docker.sh --flavor desktop \
    --satd-source release --satd-version 0.5.2 --out out/

# With the tools already on the host.
sudo contrib/appliance/build.sh --flavor core --out out/
```

Output: a raw image and a qcow2, plus a VMDK and OVA for the desktop
flavour, and a `SHA256SUMS`.

### Live ISO

```sh
contrib/appliance/build-iso-in-docker.sh --flavor desktop --out out/
```

"Try it from a USB stick without installing anything." The root filesystem
is built by the same `build.sh` with `--rootfs-only` — same provision
scripts, same packages, same first-boot behaviour — and then squashed and
made bootable rather than written to a partitioned disk. Two build paths
that provisioned differently would drift, and the ISO is the one nobody
tests as often.

A live session keeps everything in RAM, so first boot runs on every boot and
the chain it syncs is lost at power-off. The console password is generated
each time and printed on the login banner, which is where a live user reads
it from.

`satd-appliance install-to-disk /dev/sdX` copies the running system onto a
real disk. It clears the CA, certificate, token and password the live
session generated first, so the installed system creates its own on its own
first boot rather than inheriting credentials that were displayed on a
screen.

### Why not Packer

Packer's QEMU builder drives Debian's installer through a preseed inside a
running VM: it needs KVM to finish in sensible time, needs a ~700 MB
installer ISO, and fails in ways you diagnose by watching a VNC console.
`build.sh` builds the filesystem directly with `mmdebstrap` and installs
GRUB onto a loop device — no VM, no KVM, no ISO, minutes rather than an
hour, and every failure is a shell command that exited non-zero with its
output on stdout. It runs unchanged on a GitHub-hosted runner and inside a
container, which is what made the boot gate below practical.

The provisioning tree in `provision/` is plain, idempotent shell and is
shared by the disk builder and the ISO builder.

## Running

| Hypervisor | File |
|---|---|
| QEMU/KVM, virt-manager, Proxmox, UTM | `.qcow2` |
| VirtualBox, VMware | `.ova` (desktop flavour) |
| bare metal, a spare SSD | `.raw`, written with `dd` |

Minimum: 2 vCPU / 4 GB for signet, 4+ vCPU / 16 GB and a 2 TB disk for a
fully indexed mainnet.

The disk grows to fill whatever it is given on first boot, so attach a large
virtual disk rather than resizing later.

## First boot

Runs once, before satd starts, and creates everything that must be unique
per install — because an image that shipped any of it would be an image
where every download shared it:

1. the root filesystem is grown to the disk;
2. a console password is generated and printed on the console, and must be
   changed at first login;
3. the local CA and the server certificate are issued;
4. the node's configuration is rendered and the MCP bearer token minted;
5. satd starts.

`90-cleanup.sh` asserts at build time that none of those exist in the image
— no keys, no cookie, no token, no machine-id, no usable password hash —
and refuses to finish a build that would ship one.

## Operating

```sh
satd-appliance status                  network, sync progress, overlays, certificate
satd-appliance tls export-ca           the CA to import on other machines
satd-appliance tls renew               reissue after a hostname or address change
sudo satd-appliance set-network mainnet
sudo satd-appliance enable lightning    LND (Neutrino) + Ride The Lightning
sudo satd-appliance enable cashu        a Cashu mint backed by that LND
sudo satd-appliance enable btcpay       BTCPay Server
sudo satd-appliance disable lightning   stop it; its data volumes are kept
satd-appliance logs [satd|<service>]
sudo satd-appliance ssh enable          sshd is off by default
```

satd runs natively under systemd — `systemctl status satd`, `journalctl -u
satd`, `sat-tui` — while the overlays run as containers from
`/opt/satd/stack`, which is `contrib/stack`'s overlay files used unmodified.
`files/compose.appliance.yml` supplies what `compose.yml` would have: the
data volume bound to the real `/var/lib/satd`, and a network whose gateway
is how the containers reach the host's node.

## TLS

One CA per install, one certificate presented by every surface. Export the
CA once and everything is trusted at once:

```sh
satd-appliance tls export-ca > satd-ca.crt
```

- The OS trust store already has it, so `curl` and `sat-cli` on the
  appliance itself need no flags.
- Firefox on the desktop flavour is policy-configured to import it.
- Sparrow, Electrum and Liana pin the server certificate on first use
  instead; accept it once.
- Elsewhere: import `satd-ca.crt`, then use `satd.local` — the name is on
  the certificate and survives a DHCP change, which an address does not.

A daily timer reissues the certificate when fewer than 30 days remain or the
machine's names or addresses have changed. The CA is never rotated
automatically; that would invalidate trust every client has already
established.

The firewall is default-deny inbound. Only Bitcoin P2P, the TLS surfaces,
the proxy ports and mDNS are open. The plain RPC, Electrum, Esplora and
metrics listeners are reachable from the machine and its containers only.

## Testing

```sh
contrib/appliance/tests/boot-test.sh --image out/....qcow2 --in-docker
```

Boots the actual artifact — no test-only build, no injected hooks — and
checks what a person who downloaded it would find. Two channels: the QEMU
guest agent for looking inside (did first boot run, is satd up, were the
certificates created), and forwarded ports for the TLS surfaces, verified
from outside against the CA the guest agent hands out. Checking a
certificate from inside the guest proves much less than connecting to it the
way a client on the network will, and the suite includes the negative
control that the same handshake without the CA must fail.

It uses KVM when there is one and TCG when there is not, so it runs on a
hosted CI runner and on a laptop with no virtualisation.
