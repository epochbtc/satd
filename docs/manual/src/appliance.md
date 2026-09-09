# Appliance & Reference Stack

satd ships three ways to run it beyond a bare binary: a docker-compose
**reference stack**, a downloadable **appliance image**, and packages for
the **Umbrel** and **StartOS** app stores. They share one configuration and
one certificate scheme, so what you learn from any of them applies to the
others.

| | What it is | Where it lives | Support |
|---|---|---|---|
| Reference stack | compose: satd plus optional third-party overlays | `contrib/stack/` | satd supported; overlays best-effort |
| Appliance image | a bootable VM with satd, wallets and Lightning | `contrib/appliance/` | satd supported; bundled software best-effort |
| Store packages | satd, `sat-cli`, `sat-tui` and MCP only | `contrib/packaging/` | supported |

> **The appliance image and the stack's overlays bundle third-party software
> (wallets, Lightning, ecash, and others) so you can try satd end to end.
> That software is included on a best-effort basis for evaluation and
> testing. It is not a production deployment: we do not track its security
> advisories in real time, and a critical fix in a bundled component may not
> appear in an appliance image until the next scheduled build. satd itself
> in this image is the same supported release as our tarballs and container
> image. For production, run satd from a release artifact or an app store
> package and operate the other components yourself.**
>
> The Umbrel and StartOS packages carry no such notice: they contain only
> satd.

## The reference stack

```sh
cd contrib/stack
cp .env.example .env
docker compose up -d
```

That runs satd on signet with JSON-RPC, Electrum, Esplora and the metrics
endpoint all enabled, each TLS-terminated by a certificate the install
issues for itself on first start.

Overlays add third-party software, combined with repeated `-f`:

```sh
docker compose -f compose.yml -f compose.lightning.yml -f compose.proxy.yml up -d
```

| Overlay | Contents |
|---|---|
| `compose.lightning.yml` | LND in Neutrino mode, Ride The Lightning |
| `compose.cln.yml` | Core Lightning, as an alternative to LND |
| `compose.cashu.yml` | a Nutshell mint backed by that LND |
| `compose.btcpay.yml` | Postgres, NBXplorer, BTCPay Server |
| `compose.proxy.yml` | Caddy, terminating TLS for the web UIs and metrics |

Overlays that need a secret have no default and refuse to start without one,
rather than shipping a value every deployment would share:

```sh
echo "RTL_PASSWORD=$(openssl rand -hex 24)" >> .env
echo "MINT_PRIVATE_KEY=$(openssl rand -hex 32)" >> .env
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" >> .env
echo "ARK_POSTGRES_PASSWORD=$(openssl rand -hex 24)" >> .env
```

`RTL_PASSWORD` is the login for Ride The Lightning, which fronts LND's admin
macaroon. Left unset, RTL generates a configuration whose password is the
literal string `password`, so this one is required rather than defaulted.

`satd-appliance enable <overlay>` generates each of these into
`/var/lib/satd-appliance/overlay.env` on first use, so the appliance needs
none of this by hand.

### Which ports are published

Plain RPC, Electrum, Esplora and metrics listeners bind the compose network
and are **not** published. They exist because the overlay containers cannot
be taught to trust a private CA. What leaves the host is TLS only:

| Published | Surface |
|---|---|
| 8336 | JSON-RPC over TLS |
| 50002 | Electrum over TLS |
| 3001 | Esplora over TLS |
| 8339 | MCP over TLS, when `SATD_MCP=1` |
| 38333 (signet) | Bitcoin P2P |
| 443 / 8443 / 49393 / 9443 | RTL, Cashu mint, BTCPay and metrics, with `compose.proxy.yml` |

BTCPay's own HTTP port binds `127.0.0.1` and RTL and the mint are not
published at all, so the proxy is the only route to a web UI from another
machine. A docker-published port is also not filtered by the appliance's
inbound firewall chain, which is the second reason those bindings matter.

The internal RPC port is 8332 on **every** network so that overlays, the
proxy and the store packages address one fixed port. The cost is that
`sat-cli` inside the container needs `-rpcport=8332` on any network but
mainnet, since it derives its default from the chain:

```sh
docker compose exec satd sat-cli -rpcport=8332 getblockchaininfo
docker compose exec -it satd sat-tui -rpcport=8332
```

### No pruning, anywhere

Electrum and Esplora both require `txindex`, and satd rejects `txindex`
together with `prune`. So every deliverable here runs a fully indexed node.
On mainnet that is the whole chain plus the address, spend and transaction
indices — see [Disk Footprint & Indices](disk-footprint.md), and budget a
2 TB volume. [Initial Block Download & Fast Sync](ibd.md) covers loading an
AssumeUTXO snapshot so the node is usable in hours rather than days.

signet is the default everywhere for this reason: it is the only network on
which the whole stack is a one-evening exercise.

## TLS

`contrib/stack/tls/mkca.sh` is the one certificate script. The compose
stack's `satd-init`, the appliance's first boot, and both store packages run
it, so all four produce the same material and the client instructions are
identical everywhere.

It creates a **CA for that install only**, then issues **one server
certificate** that every satd surface presents. That is why there are two
certificates and not one self-signed: clients import the CA once, and every
later reissue — after a hostname change, a new address, or a year — is
signed by a CA they already trust, with nothing to accept again.

The certificate covers `localhost`, `127.0.0.1`, `::1`, the hostname,
`<hostname>.local`, and the machine's non-bridge addresses. **Prefer the
mDNS name.** A DHCP change invalidates an address in the SAN list; the name
survives it.

Reissue happens automatically when the certificate expires within 30 days or
the machine's names or addresses have changed. The CA is never rotated
automatically — that would invalidate trust every client has established.
Rotating it is a deliberate act: delete the CA files and re-run.

### Trusting it

```sh
# compose
docker compose exec satd cat /var/lib/satd/tls/ca.crt > satd-ca.crt
# appliance
satd-appliance tls export-ca > satd-ca.crt
```

Then:

| Client | How |
|---|---|
| `curl`, python, Go, anything using the OS store | import `satd-ca.crt` into the system trust store |
| `sat-cli` / `sat-tui` | `--rpctls --rpccacert=satd-ca.crt --rpcport=8336` |
| Firefox | already policy-configured on the appliance desktop; elsewhere, import it |
| Sparrow, Electrum, Liana | these pin the server certificate on first use; accept it once |

`-rpccacert` wants the certificate that **issued** the one the server
presents. For a self-signed node certificate that is the certificate itself;
it is not the leaf of a chain, which cannot anchor its own path.

### What TLS does not cover

Bearer tokens from an [`authfile`](authentication.md) still gate MCP,
streaming and Esplora writes; the plain loopback RPC listener is
cookie-authenticated. The local CA authenticates the appliance to clients,
not clients to the appliance — every surface supports mTLS if you turn it
on, but none requires it by default.

The metrics endpoint and the streaming WebSocket have no native TLS. They
stay on loopback or the container network, and `compose.proxy.yml` fronts
them.

## The appliance image

A bootable VM: `core` is headless, `desktop` adds XFCE with Sparrow,
Electrum and Liana already pointed at the node. Each bundled wallet is
installed from its project's own release, with the download checked against
a signature from a pinned key; the build fails rather than installing
anything that does not verify.

```sh
contrib/appliance/build-in-docker.sh --flavor core --out out/
```

No root, no KVM and no Packer: the image is built with `mmdebstrap` and a
GRUB install onto a loop device, which runs in a container and on a hosted
CI runner in minutes. `contrib/appliance/README.md` has the details.

First boot creates everything that must be unique to an install — the disk
size, the console password, the CA and certificate, the MCP token — because
an image that shipped any of those would be an image where every download
shared them. The build asserts none of them exist in the artifact and
refuses to finish otherwise.

Day-to-day operation goes through one command:

```sh
satd-appliance status
satd-appliance tls export-ca
sudo satd-appliance set-network mainnet    # refuses below 1.5 TB free
sudo satd-appliance enable lightning
satd-appliance logs satd
```

satd runs natively under systemd; the overlays run as containers from
`/opt/satd/stack`, which is `contrib/stack`'s overlay files unmodified.

The firewall is default-deny inbound, and `sshd` is off until
`satd-appliance ssh enable`.

## Why LND runs in Neutrino mode

LND's `bitcoind` backend requires Bitcoin Core's raw ZMQ topics
(`zmqpubrawblock` / `zmqpubrawtx`). satd does not implement them and rejects
those settings; see [CORE_DIFFERENCES.md]. Neutrino needs no ZMQ — it pulls
BIP 157/158 filter headers and filters over P2P, which satd serves because
every deliverable here sets `peerblockfilters=1`.

Core Lightning is unaffected: its `bcli` plugin polls JSON-RPC, so it runs
as an ordinary full-node client.

### Ark

`compose.ark.yml` runs an Ark server against satd. **Experimental** — Ark is
young, and every setting in that overlay was established by running the
binary rather than read from a specification, so expect it to need attention
on a version bump.

The chain is:

```
satd  ->  NBXplorer  ->  arkd-wallet  ->  arkd
```

arkd v0.9 splits the wallet into its own service, and that wallet's chain
backend is **NBXplorer** — not Esplora, and not Core's ZMQ. Two things
follow. satd implements no raw ZMQ topics, so a backend that needed them
would have ruled Ark out entirely; and NBXplorer against satd is already a
PR-gating canary in this repository, so the single link in that chain which
touches satd is the link that is continuously tested.

First run is two steps, because arkd will not start without a signer key and
its wallet must then be created and unlocked:

```sh
docker compose -f compose.yml -f compose.ark.yml run --rm ark-init   # prints the key
# add ARKD_SIGNER_KEY=... to .env
docker compose -f compose.yml -f compose.ark.yml up -d
docker compose -f compose.yml -f compose.ark.yml run --rm ark-init   # creates the wallet
```

Both the signer key and the wallet password are generated per install into
the data volume. Neither is shipped.

## What is checked, and how

Each bundled application is a compatibility claim, so each is exercised
rather than asserted:

- `contrib/stack/tests/mkca-test.sh` — the certificate script, including
  that it does *not* reissue a healthy certificate or rotate the CA.
- `contrib/stack/tests/smoke.sh` — the stack on regtest, with every TLS
  listener probed from outside the container against the generated CA, LND
  syncing to the node's tip over Neutrino, and RTL served through the proxy.
- `contrib/appliance/tests/boot-test.sh` — the built image booted under
  QEMU, checked through the guest agent and through forwarded ports.

Every probe that verifies a certificate is paired with the negative control
that the same handshake without the CA must fail. A probe that would pass
unverified proves nothing about the certificate.

[CORE_DIFFERENCES.md]: https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md
