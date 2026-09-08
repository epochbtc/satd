# StartOS package — not written yet

A StartOS package is a TypeScript project built with Start9's SDK. The SDK's
API has changed shape across StartOS versions, and a package written against
a guessed API produces something that looks right in review and does not
build.

So this directory holds the requirements rather than a package. Writing it
is mechanical once the target version is fixed:

1. Choose the StartOS version to target, and install that SDK.
2. Copy the structure of `start9labs/bitcoind-startos` at the matching tag —
   satd is a drop-in for Bitcoin Core's RPC, config file and cookie format,
   so that package's shape is the right starting point rather than a blank
   project.
3. Publish from its own repository (`epochbtc/satd-startos`); Start9's
   registry expects one repository per package.

## What the package must declare

**Contents: satd only** — the daemon, `sat-cli`, `sat-tui` and the MCP
server. No Lightning, no BTCPay, no wallets: StartOS users compose those
from their own store, and a package that bundled a second copy of software
the store already offers would be worse than useless.

**Image:** `ghcr.io/epochbtc/satd`, unmodified. It already carries
`satd-init` and `mkca.sh`, so the package's first run is the same one the
reference stack and the appliance perform, and cannot drift from them.

**Interfaces:**

| Interface | Port | Notes |
|---|---|---|
| JSON-RPC | 8332 | plain, internal to the StartOS network, cookie auth |
| JSON-RPC (TLS) | 8336 | LAN-facing |
| Electrum (TLS) | 50002 | LAN-facing; the plain 50001 stays internal |
| Esplora (TLS) | 3001 | LAN-facing, prefix `/api` |
| MCP (TLS) | 8339 | bearer token from the generated authfile |
| P2P | 8333 | mainnet |

**Config options:** the network, and nothing else that changes indexing.
`txindex` and `addressindex` stay forced on — Electrum and Esplora both
require them — and there is therefore no prune option to offer.

**Health check:** `/readyz` on the metrics listener (port 9332, internal).
It reports not-ready until the chainstate is loaded and every listener is
bound, which is what a dependent package needs it to mean. Sync progress
comes from `getblockchaininfo`.

**Backups:** a wallet-less node has no irreplaceable state; exclude the
chain and index directories. Do include `/var/lib/satd/tls` if the
deployment wants its CA to survive a restore — restoring without it means
every client re-imports.

**Actions to expose in the UI:** show the CA certificate (so a user can
import it), show the MCP token and connection snippet, and the Electrum /
Esplora connection strings.

## Open question for the package

The CA and certificate are reissued by `mkca.sh` when they near expiry or
the machine's addresses change. On the appliance a systemd timer runs that
daily. A StartOS package has no equivalent scheduler of its own, so it would
renew on container start — fine for a box that reboots, not fine for one
that runs for a year. Decide whether that is acceptable or whether the
package needs a scheduled action.
