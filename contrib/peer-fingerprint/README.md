# Peer fingerprint captures

What each Bitcoin P2P implementation sends during and just after the
handshake, recorded against a local regtest node, as fixtures for satd's
peer fingerprint classifier. Every row of the classifier's table is to be
backed by one of these captures, never by documentation or by memory of how
a client behaves.

- `capture.py` records one connection. It greets the peer as satd 0.7.0
  does in the same direction (the greeting is in its docstring and was
  measured from satd's own fixtures here), records every message for 10 s,
  then runs four probes one at a time: `ping`, `getheaders` from genesis,
  `getdata` for a random txid (`MSG_WITNESS_TX`), and an unknown message type. Over v1 it
  needs nothing beyond Python 3. `--v2` speaks BIP324, using the
  pure-Python implementation in Bitcoin Core's functional test framework
  (`--core-functional` names a Core checkout's `test/functional`).
- `run-captures.py` starts each implementation on regtest with a fresh
  datadir, mines a block where it can so the node is out of initial block
  download, captures it as an outbound peer (we dial it) and as an inbound
  peer (it dials us), records the IBD state its own RPC reports, and stops
  it. `--transport v1,v2` does both transports. Each implementation is
  named by an environment variable; see the script's help.
- `fixtures/` holds one JSON file per implementation, direction and
  transport: `<name>-<version>-<inbound|outbound>[-v2].json`. `connection`
  is from our side: `inbound` means the peer dialed us. When listening, the
  recorder also takes the node's next connection, if it opens one within
  20 s, as `…-s2.json`.

The fixtures hold commands, sizes, timings and decoded fields. They never
hold an address: the version message's address fields and nonce are
dropped, and addr/addrv2 bodies are reduced to a count.

## What was captured

| Implementation | Version | Directions | v2 | Opening messages after `verack` (it dialed us) |
|---|---|---|---|---|
| Bitcoin Core | 31.2 | both | yes, falls back to v1 | `getaddr sendcmpct ping getheaders feefilter` |
| Bitcoin Knots | 29.4.3.knots20260508 | both | yes, falls back to v1 | as Core |
| satd | 0.7.0 | both | yes, falls back to v1 | `sendheaders getheaders sendcmpct feefilter getaddr ping` |
| rbitcoin | 0.8.0 | both | only: refuses v1 both ways | `sendheaders sendcmpct ping feefilter getheaders`, on its second connection |
| Floresta | 0.9.1 | it dials only | yes, falls back to v1 | `getaddr feefilter getheaders` |
| btcd | 0.27.0 | both | no | `getaddr` (no `wtxidrelay`, `sendcmpct`, `feefilter` or `getheaders`) |
| bcoin | 2.2.0 | both | no | `addr sendcmpct getaddr getblocks` (no `wtxidrelay` or `sendaddrv2`) |
| libbitcoin-server | 3.8.0 | both | no | none: drops the connection on `wtxidrelay` |
| bitcoin-seeder | `92d2b46` | it dials only | no | `getaddr`, with `start_height` 350000 |
| bitnodes | `036dc5c` | it dials only | no | `getaddr`, with `relay` 0 and services 0 |

Replies to the recorder's own `getheaders` and `ping` are left out of the
last column. Where those replies fall among a peer's own messages depends
on timing (two captures of satd differ only in that), so a classifier
should compare a peer's own messages and treat replies separately. The messages are the same over v1 and v2 for every
implementation that speaks both.

- **rbitcoin** opens two connections when it dials: a catch-up connection
  that completes the handshake and closes after about 40 ms when there is
  nothing to download, then a second one that follows the tip
  (`rbitcoin-0.8.0-inbound-v2-s2.json`). It refuses a v1 inbound
  connection before sending `version`.
- **libbitcoin-server 3.8.0** sends `version` and `verack`, then stops the
  channel on the `wtxidrelay` that satd (and Core since 0.21) sends before
  `verack`, logging `Invalid wtxidrelay payload`. It never stays connected
  to satd.
- **Probes:** every implementation that stayed connected answered `ping`
  and `getheaders`, except bitcoin-seeder, which answered no probe and
  closed the connection 30 s after it opened. No implementation
  disconnected on a probe. Floresta and bitnodes leave the `getdata` for an
  unknown txid unanswered; the rest send `notfound`. Core 31.2 logs the
  unknown message as `Unknown message type` and nothing else: no
  misbehaviour, no disconnect.

## Limits

- **IBD state.** btcd and bcoin report no IBD field over RPC; their
  fixtures say so and that the tip was mined seconds before. Floresta and
  libbitcoin cannot mine on regtest, and libbitcoin has no RPC that reports
  its state. Crawlers have no chain.
- **Dial-only clients.** Floresta and both crawlers make outbound
  connections only.
- **libbitcoin's sources.** libbitcoin-server 3.8.0 depends on
  `libbitcoin-blockchain`, `-protocol`, `-client` and `-consensus`, which
  are no longer under the `libbitcoin` organisation. Their `v3.8.0` tags
  are in `github.com/evoskuil`, the maintainer's account. It was built in
  an Ubuntu 20.04 container, with its `install.sh` pointed at those
  repositories and tags, Boost 1.73 instead of 1.72 (the libraries require
  it), and `unset WITH_BITCOIN_CONSENSUS` for its `unset -f` bug. `bs`
  cannot choose its listen address, so it runs in a container with only
  its P2P port published to 127.0.0.1.
- **Regtest, one block.** A node on mainnet with a full chain, peers and a
  mempool may announce more. The classifier's thresholds are calibrated on
  a synced mainnet node before they ship.

## Re-running

Build or download each implementation into a scratch directory, then:

```sh
SATD=… SATCLI=… CORE_BIN=…/bin KNOTS_BIN=…/bin BTCD=… BCOIN=… RBITCOIN=… \
FLORESTAD=… LIBBITCOIN_BS=… SEEDER=… BITNODES=… BITNODES_PYTHON=… \
./run-captures.py --workdir /path/to/scratch --out fixtures \
  --transport v1,v2 --core-functional /path/to/bitcoin/test/functional \
  --version satd=0.7.0 --version core=31.2 …
```

Each node runs with `HOME` set to its own scratch directory and binds to
127.0.0.1 (libbitcoin: in a container, see above). btcd creates an empty `~/.btcd` from the passwd entry whatever
its flags say; the script removes it again. When satd's own greeting
changes, capture satd and update `capture.py`'s greeting to match.
