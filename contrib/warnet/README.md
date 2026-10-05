# satd in Warnet

[Warnet](https://github.com/bitcoin-dev-project/warnet) deploys networks of
Bitcoin nodes ("tanks") to Kubernetes with its stock `bitcoincore` Helm chart.
This directory holds a lab image that lets that chart run satd unchanged,
example networks with satd tanks alone and mixed with Bitcoin Core, and
keyless scenarios that drive them.

The image is for test networks. To run a node, use the published
`ghcr.io/epochbtc/satd` image.

## What the image changes

Warnet's chart assumes Bitcoin Core's image layout and cannot override the
container's command. The image adapts satd to it:

| The chart does this | The image provides |
|---|---|
| Probes liveness with `pidof bitcoind` | `bitcoind`, a symlink to `satd` |
| Runs `bitcoin-cli` for `warnet bitcoin rpc` | `bitcoin-cli`, an adapter over `sat-cli` |
| Mounts `bitcoin.conf` at `/root/.bitcoin/` | datadir `/root/.bitcoin`, running as root |
| Starts the container with no arguments | an entrypoint that supplies `-datadir` |

satd reads the chart's `bitcoin.conf` as it is. The Bitcoin Core options it
does not implement, such as `rest`, `zmqpubrawblock` and `debuglogfile`, are
skipped with a warning in the tank's log.

The chart writes `rpcuser` and `rpcpassword`, and satd writes no cookie when
both are set. The `bitcoin-cli` adapter therefore reads `rpcuser`,
`rpcpassword`, `rpcport` and `regtest` from `bitcoin.conf`, as `bitcoin-cli`
does, and passes them to `sat-cli`. It reads top-level keys only, which is
what the chart writes for satd.

## Build and load the image

Warnet renders only image tags shaped like `X.Y[.Z][-suffix]`. Tag the image
`<satd version>-warnet<N>`:

```sh
docker build --build-arg SATD_IMAGE=ghcr.io/epochbtc/satd:0.5.2 \
  -t satd-warnet:0.6.0-warnet0 contrib/warnet
```

`SATD_IMAGE` defaults to `ghcr.io/epochbtc/satd:latest`. Any satd image
works, including one built from this repository with `docker build -t satd:dev .`.

Load the image into the cluster. With [kind](https://kind.sigs.k8s.io/):

```sh
kind load docker-image satd-warnet:0.6.0-warnet0 --name <cluster>
```

The examples set `pullPolicy: Never`, so a tank whose image is missing fails
to start instead of pulling something else. On a cluster that pulls from a
registry, push the image there and change the examples' `image:` to match.

## Example networks

| Network | Tanks |
|---|---|
| `examples/all-satd` | four satd tanks in a ring |
| `examples/core-satd` | a ring alternating Bitcoin Core 27.0 and satd |

```sh
warnet deploy contrib/warnet/examples/core-satd
warnet status                         # waits for "Network connected"
warnet bitcoin rpc tank-0001 getpeerinfo
```

Bitcoin Core 27.0 and later use BIP 324 v2 transport by default, as satd
does, so every link in the mixed ring is v2.

## Scenarios

satd has no wallet. Warnet's stock `miner_std.py`, `tx_flood.py` and
`ln_init.py` call wallet RPCs, so they cannot run against a satd tank. These
scenarios keep the keys in the scenario with the test framework's MiniWallet
instead. They mine with `generatetodescriptor`, find coins with
`scantxoutset` and spend with `sendrawtransaction`, which Bitcoin Core and
satd both provide.

| Scenario | What it does |
|---|---|
| `keyless_miner.py` | Mines a batch of blocks on one tank, and with `--forever` keeps mining |
| `keyless_tx_flood.py` | Sends a stream of transactions through one tank and confirms them |
| `consensus_diff.py` | Mines on one tank and checks every tank follows: relay, compact blocks, reorgs, and a valid block carrying a non-standard transaction |

`warnet run` uploads only the scenario's own directory, and the scenarios
import Warnet's `commander.py` and `test_framework`. Copy them into a Warnet
project's `scenarios/` directory, which `warnet new` and `warnet init` create,
and run them from there:

```sh
cp contrib/warnet/scenarios/*.py <project>/scenarios/
warnet run <project>/scenarios/keyless_miner.py --tank tank-0001 --blocks 110
warnet run <project>/scenarios/keyless_tx_flood.py --tank tank-0003 --txs 40
warnet run <project>/scenarios/consensus_diff.py --miner tank-0000 --reorgs 5
```

Scenario arguments must not contain commas: Warnet passes them to the
commander pod through `helm --set`, which splits values on commas.

## What does not work on satd tanks

- Wallet scenarios: `miner_std.py`, `tx_flood.py`, `ln_init.py`. Use the
  keyless scenarios, or make a Bitcoin Core tank the miner.
- Lightning. LND needs `zmqpubrawblock` and `zmqpubrawtx`, which satd does
  not provide.
- `warnet bitcoin messages`. satd does not write `capturemessages` files.
- `warnet bitcoin debug-log`. satd logs to stdout; use `warnet logs <tank>`.
- `rpcwhitelist`, which a network made with `warnet create` writes for the
  fork-observer user. satd refuses to start with it; remove those lines.

## Tests

`tests/contract-test.sh` checks the image's layout contract without docker.
`tests/compose-test.sh` runs two tanks on the chart's rendered
`bitcoin.conf` with docker compose and checks the same contract against
running containers. `tests/render-confs.sh` regenerates that `bitcoin.conf`
from Warnet's chart after a Warnet upgrade.

```sh
docker build -t satd-warnet:local contrib/warnet
contrib/warnet/tests/contract-test.sh
contrib/warnet/tests/compose-test.sh
```
