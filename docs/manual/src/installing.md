# Installing satd

Pick the one that matches the machine you have:

| You have | Install | Updates |
|---|---|---|
| An Umbrel | the satd [community app store](#umbrel) | Umbrel's app store |
| A StartOS server | the [StartOS package](#startos), sideloaded until Start9 lists it | sideload each version, then StartOS's marketplace |
| A hypervisor, a mini-PC or a spare SSD | the [appliance image](#appliance-image): a bootable VM with satd, wallets and Lightning | boot a newer image |
| Docker | the [container image](#container) | pull a newer tag |
| A Linux or macOS host you manage | a [release tarball](#release-tarball) | replace the binaries |

Every one runs the same signed release. The store packages contain only satd;
the appliance image adds third-party software for evaluation, on a
best-effort basis (see [Appliance & Reference Stack](appliance.md)).

## Umbrel

satd is in its own community app store rather than Umbrel's official one:

1. In umbrelOS, open the **App Store**, then **⋯ → Community App Stores**.
2. Add `https://github.com/epochbtc/umbrel-apps`.
3. Open the **satd** store and install **satd**.

The app takes its own host ports, clear of every other app in the Umbrel store,
so it installs alongside Bitcoin Node, Fulcrum and Ride The Lightning:

| Port | Surface |
|---|---|
| 8430 | the app page, through Umbrel's proxy and login |
| 8431 | Esplora, TLS (from 0.6.0) |
| 8433 | Bitcoin P2P |
| 50012 | Electrum, TLS |
| 8436 | JSON-RPC, TLS |
| 8439 | MCP, TLS and a bearer token |

From 0.6.0, opening the app shows satd's [status page](observability.md#status-page):
sync progress, whether a wallet can connect yet, and the connection strings
to use. The 0.5.2 package opens onto Esplora instead, served through Umbrel's
proxy on 8430, and has no status page.

Point a wallet at `umbrel.local:50012` over SSL. Sparrow and Electrum pin the
certificate on first use; a client that verifies against a CA needs the
install's, and the MCP token lives beside it. The status page never shows
either, since it carries nothing secret, so reading them takes SSH:

```sh
sudo cat ~/umbrel/app-data/epochbtc-satd/data/tls/ca.crt
sudo cat ~/umbrel/app-data/epochbtc-satd/data/secrets/mcp-token
```

See [Trusting it](appliance.md#trusting-it) for importing the CA. Other
apps on the device reach JSON-RPC in plain text on the app network, as
`epochbtc-satd_server_1:8332` with the cookie at `APP_SATD_RPC_COOKIE_FILE`,
which is how they reach Bitcoin Node too.

Earlier builds of the package used 8333, 50002, 3001, 8336 and 8339. A client
configured against those needs the new port.

Umbrel backups leave out the chain and chainstate, which the node downloads
again on its own, and keep the CA and the MCP token.

The package is supported on `x86_64`. It has not been installed on an
`aarch64` Umbrel, since umbrelOS ships `aarch64` only as a Raspberry Pi image.

## StartOS

The package has been submitted to Start9's community registry and is not
listed yet. Until it is, build it from its repository and sideload it:

```sh
git clone https://github.com/epochbtc/satd-startos
cd satd-startos
make x86        # or `make` for x86_64 and aarch64
```

`make` needs Node 22, `start-cli` 2.0, both `squashfs-tools-ng` and
`squashfs-tools`, a container runtime and a packaging workspace; the
repository's `README.md` covers each under **Building**. Then sideload `satd_x86_64.s9pk` (or
`satd_aarch64.s9pk`) from the StartOS web interface's sideload page, or with
`start-cli`:

```sh
start-cli package install -s satd_x86_64.s9pk
```

The package targets StartOS 0.4.0.x and runs on `x86_64` and `aarch64`. Its
**Instructions** tab covers the interfaces, the actions and what the package
does not do. StartOS lists each interface's addresses itself, and exports the
status page as the package's UI from 0.6.0.

Backups leave out the chain, chainstate and the AssumeUTXO background
chainstate, and keep the CA, the MCP token and the configuration, so a restore
comes back with the certificates clients already trust.

## Appliance image

A bootable VM that starts on signet with every satd surface on and TLS
everywhere. `core` is headless, about 600 MB; `desktop` adds XFCE with
Sparrow, Electrum and Liana already pointed at the node, about 1.4 GB. Each
comes for `amd64` and `arm64`; on arm64 the desktop carries Sparrow alone.

Images are attached to the [GitHub release](https://github.com/epochbtc/satd/releases),
alongside the tarballs, from 0.6.0 on, and signed with the same minisign key:

```sh
ver=0.6.0
flavor=core    # or desktop
arch=amd64     # or arm64, for Apple Silicon and arm64 servers
base="https://github.com/epochbtc/satd/releases/download/v$ver"
img="satd-appliance-$ver-$flavor-$arch.qcow2"
curl -fLO "$base/$img"
curl -fLO "$base/$img.minisig"

minisign -Vm "$img" -P RWQeP6MczCgPh6tU03GEMm4HsnGbXte3VT2Bc52TBSR7Q+X7WnL5vfQ3
```

Pick the architecture of the host: under emulation the node syncs slowly
enough to be unpleasant.

| Hypervisor | File |
|---|---|
| QEMU/KVM, virt-manager, Proxmox, UTM | `.qcow2`, as downloaded; it is already compressed |
| VirtualBox, VMware | `.ova` (desktop flavour) |

An arm64 guest is UEFI-only. UTM on macOS handles that; with plain QEMU,
pass `-machine virt` and an `AAVMF_CODE.fd` in pflash.

Give it 2 vCPU and 4 GB of memory for signet, or 4+ vCPU, 16 GB and a 2 TB
disk for a fully indexed mainnet. The root filesystem grows to the disk on
first boot, so attach a large virtual disk from the start.

### First boot

First boot creates everything that must be unique to the install: the
certificate authority and certificate, the MCP token and a console password.
The console shows the login, `satd-user`, and the generated password, which
must be changed at first login.

Then:

```sh
satd-appliance status                      # network, sync progress, overlays, certificate
satd-appliance tls export-ca > satd-ca.crt # import on the machines that connect
sudo satd-appliance set-network mainnet    # refuses below 1.5 TB free
sudo satd-appliance enable lightning       # LND (Neutrino) and Ride The Lightning
sudo satd-appliance ssh enable             # sshd is off by default
```

Once the CA is imported, the status page is at
`https://satd.local:9336/status` from another machine. Wallets connect to
`satd.local`, whose name is on the certificate.

The firewall is default-deny inbound; P2P, the TLS surfaces, the proxy
ports and mDNS are open. [Appliance & Reference Stack](appliance.md) covers
the overlays, TLS and building an image yourself.

## Container

A multi-arch image (`linux/amd64`, `linux/arm64`) is published for every
release at `ghcr.io/epochbtc/satd:<version>`, with `latest` following the
newest stable release. It is signed with cosign; see
[Signed releases](packaging.md#signed-releases).

A signet node, streaming its sync to the terminal:

```sh
docker run --rm -it -v satd-signet:/var/lib/satd \
  ghcr.io/epochbtc/satd:latest --signet --datadir=/var/lib/satd
```

Query it from another terminal (signet RPC is on `38332`, cookie auth):

```sh
docker exec <container> sat-cli \
  --rpcport=38332 --rpccookiefile=/var/lib/satd/signet/.cookie \
  chain info
```

Drop `--rm` and keep the named volume to resume the sync later. For a
long-running deployment, see [Container](packaging.md#container), or the
docker-compose [reference stack](appliance.md#the-reference-stack), which adds
TLS on every surface.

## Release tarball

Each release carries `satd-<version>-<target>.tar.zst` for
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, the statically
linked `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, and
`aarch64-apple-darwin`:

```sh
ver=0.5.2
target=x86_64-unknown-linux-musl
gh release download "v$ver" -R epochbtc/satd --pattern "satd-$ver-$target.tar.zst*"
minisign -Vm "satd-$ver-$target.tar.zst" \
  -P RWQeP6MczCgPh6tU03GEMm4HsnGbXte3VT2Bc52TBSR7Q+X7WnL5vfQ3
tar --zstd -xf "satd-$ver-$target.tar.zst"
```

Without `gh`, download the same files from the
[release page](https://github.com/epochbtc/satd/releases). `SECURITY.md` has
the cold spare key and what to do if a signature fails. To run it as a
service, see [systemd](packaging.md#systemd), [OpenRC](packaging.md#openrc) or
[runit](packaging.md#runit); to build from source, see the
[repository README](https://github.com/epochbtc/satd#building).
