# satd reference stack

A docker-compose stack that runs satd with every client-facing surface on,
TLS everywhere, plus optional overlays for the third-party software people
actually point at a Bitcoin node.

```sh
cp .env.example .env          # edit NETWORK if you want something other than signet
docker compose up -d
docker compose logs -f satd
```

This directory is also the shared substrate for the other two deliverables:
the appliance image runs this stack, and the Umbrel / StartOS packages are
derived from `compose.yml`. The satd service is defined once so that its
configuration cannot drift between them.

## Support

**satd is supported.** The `satd` and `satd-init` services run the same
release artifact as the tarballs and the published container image, and are
covered by the same policy.

**The overlays are best-effort.** They bundle third-party software — LND,
RTL, Nutshell, Core Lightning, NBXplorer, BTCPay — so that satd's
compatibility claims can be exercised end to end rather than asserted. We do
not track their security advisories in real time, and a critical fix in one
of them may not reach a pinned digest here until the next scheduled bump.
Run them for evaluation and testing. For production, operate those
components yourself.

## What you get

| Surface | Reachable at | TLS |
|---|---|---|
| JSON-RPC | `https://<host>:8336` | native, stack certificate |
| Electrum | `ssl://<host>:50002` | native, stack certificate |
| Esplora REST | `https://<host>:3001/api` | native, stack certificate |
| MCP (opt-in) | `https://<host>:8339` | native, plus a bearer token |
| P2P | `<host>:38333` on signet | n/a — Bitcoin P2P, BIP 324 v2 is on |
| metrics / `readyz` | compose network, or `https://<host>:9443` with the proxy overlay | reverse proxy |

Plain listeners exist for RPC, Electrum, Esplora and metrics, but they bind
the compose network only and are never published. They are how the overlay
containers reach satd, since none of them can be taught to trust a private
CA. Nothing unencrypted leaves the host.

## Networks and disk

`NETWORK=signet` by default. signet is the only network on which this whole
stack is a one-evening exercise: a fully indexed node syncs in well under an
hour, faucets supply coins, and Lightning and ecash work end to end with no
real money.

There is no prune option, on any network. Electrum and Esplora both require
`txindex`, and `txindex` cannot coexist with pruning, so a mainnet stack
stores the full chain plus every index. Read
`docs/manual/src/disk-footprint.md` before setting `NETWORK=mainnet`;
budget a 2 TB volume.

For mainnet, `--fast-start` can load a Bitcoin Core AssumeUTXO snapshot so
the node is usable in hours rather than days. See
`docs/manual/src/ibd.md`; satd hosts no snapshots.

## TLS

`satd-init` runs `tls/mkca.sh` on first start. It creates a CA **for this
install only**, then issues one server certificate that every satd surface
presents. Nothing key-like exists in any image; the CA private key is
generated on the machine that will use it and never leaves.

Export the CA once and every surface becomes trusted at once:

```sh
docker compose exec satd cat /var/lib/satd/tls/ca.crt > satd-ca.crt
```

Then:

- `curl --cacert satd-ca.crt https://<host>:3001/api/blocks/tip/height`
- `sat-cli --rpctls --rpccacert=satd-ca.crt --rpcport=8336 -rpcconnect=<host> getblockchaininfo`
- Import `satd-ca.crt` into your OS or browser trust store for the web UIs.
- Sparrow, Electrum and Liana pin the server certificate on first use
  instead; accept it once when connecting to `ssl://<host>:50002`.

The certificate covers `localhost`, `127.0.0.1`, `::1`, the configured
hostname, `<hostname>.local`, and the machine's non-bridge addresses. Prefer
the mDNS name (`<hostname>.local`) on a LAN: it survives a DHCP change,
where an address in the SAN list does not. `mkca.sh` reissues automatically
when the address set changes, on a start where fewer than 30 days remain,
or with `--force`.

`tls/mkca.sh` is also what the appliance image and the app-store packages
run, so all three produce identical material and the client instructions
above are the same everywhere.

## Layout

```
compose.yml              satd + satd-init. Supported.
compose.lightning.yml    LND in Neutrino mode + Ride The Lightning.
compose.cln.yml          Core Lightning, as an alternative to LND.
compose.cashu.yml        Nutshell mint, backed by the LND above.
compose.btcpay.yml       Postgres + NBXplorer + BTCPay Server.
compose.ark.yml          An Ark server (arkd), via NBXplorer. Experimental.
compose.proxy.yml        Caddy, terminating TLS for the web UIs and metrics.
                         443 RTL, 8443 Cashu mint, 49393 BTCPay, 9443 metrics.
                         RTL and the mint are not published at all and BTCPay
                         binds loopback, so these are the only ways to reach a
                         web UI from another machine.
satd/satd.conf.tmpl      The node configuration, with @NAME@ substitutions.
satd/satd-init           Renders it, issues the certificates, mints the MCP token.
tls/mkca.sh              The one CA/certificate script, shared by all three deliverables.
tests/smoke.sh           Brings the stack up on regtest and probes every surface.
tests/mkca-test.sh       Unit tests for the certificate script.
```

Combine overlays by repeating `-f`:

```sh
docker compose -f compose.yml -f compose.lightning.yml -f compose.proxy.yml up -d
```

Some overlays require a secret with no default, and refuse to start without
it rather than shipping one everybody shares:

```sh
echo "RTL_PASSWORD=$(openssl rand -hex 24)" >> .env            # compose.lightning.yml
echo "MINT_PRIVATE_KEY=$(openssl rand -hex 32)" >> .env       # compose.cashu.yml
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)" >> .env      # compose.btcpay.yml
echo "ARK_POSTGRES_PASSWORD=$(openssl rand -hex 24)" >> .env  # compose.ark.yml
```

`RTL_PASSWORD` is the login for Ride The Lightning, which fronts LND's admin
macaroon. RTL has no default worth keeping: with nothing set it generates a
config whose password is the literal string `password`.

## Why LND runs in Neutrino mode

LND's `bitcoind` backend needs Bitcoin Core's raw ZMQ topics
(`zmqpubrawblock` / `zmqpubrawtx`). satd does not implement them — it
rejects those settings outright, and `CORE_DIFFERENCES.md` records that as
deliberate. Neutrino needs no ZMQ: it pulls BIP 157/158 filter headers and
filters over P2P, which satd serves because the stack sets
`peerblockfilters=1`.

Core Lightning is unaffected — its `bcli` plugin polls JSON-RPC — which is
why `compose.cln.yml` runs it as a full-node client.

Ark is unaffected for a third reason: `arkd`'s wallet takes its chain data
from NBXplorer, which speaks satd's JSON-RPC and P2P. See
`compose.ark.yml`.

## Local overrides

`satd-init` rewrites `bitcoin.conf` on every start, so edits to it are lost.
Put additions in `conf.d/local.conf` inside the data volume instead; they
are appended last, and satd takes the last value for a repeated key.

```sh
docker compose exec satd sh -c 'mkdir -p /var/lib/satd/conf.d && \
    printf "dbcache=4000\n" >> /var/lib/satd/conf.d/local.conf'
docker compose restart satd
```

## Using the CLI and the TUI

```sh
docker compose exec satd sat-cli -rpcport=8332 getblockchaininfo
docker compose exec -it satd sat-tui -rpcport=8332
```

`-rpcport=8332` is needed on any network but mainnet: the stack pins the
internal RPC port to 8332 everywhere so that the overlays, the proxy and the
app-store packages address one fixed port, while `sat-cli` derives its
default from the chain.

## Tests

```sh
tests/mkca-test.sh                            # certificate script, no docker needed
tests/smoke.sh                                # regtest bring-up, every TLS surface probed
tests/smoke.sh --with lightning --with proxy  # + LND syncing over Neutrino
SATD_IMAGE=satd:dev tests/smoke.sh            # against a locally built image
```

`smoke.sh` verifies every TLS listener from outside the container against
the generated CA with `-verify_return_error`, and includes the negative
control — the same handshake without the CA must fail — because a probe that
would also pass without verification proves nothing about the certificate.
