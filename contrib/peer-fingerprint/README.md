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
  `getdata` for a random wtxid, and an unknown message type. No
  dependencies beyond Python 3.
- `run-captures.py` starts each implementation on regtest with a fresh
  datadir, mines a block where it can so the node is out of initial block
  download, captures it as an outbound peer (we dial it) and as an inbound
  peer (it dials us), records the IBD state its own RPC reports, and stops
  it. Each implementation is named by an environment variable; see the
  script's help.
- `fixtures/` holds one JSON file per implementation and direction.
  `connection` is from our side: `inbound` means the peer dialed us.

The fixtures hold commands, sizes, timings and decoded fields. They never
hold an address: the version message's address fields and nonce are
dropped, and addr/addrv2 bodies are reduced to a count.

## What was captured

| Implementation | Version | Directions | Opening messages after `verack` (inbound) |
|---|---|---|---|
| Bitcoin Core | 31.2 | both | `getaddr sendcmpct ping getheaders feefilter` |
| Bitcoin Knots | 29.4.3.knots20260508 | both | as Core |
| satd | 0.7.0 | both | `sendheaders getheaders sendcmpct feefilter getaddr ping` |
| btcd | 0.27.0 | both | `getaddr` (no `wtxidrelay`, `sendcmpct`, `feefilter` or `getheaders`) |
| bcoin | 2.2.0 | both | `addr sendcmpct getaddr getblocks` (no `wtxidrelay` or `sendaddrv2`) |
| rbitcoin | 0.8.0 | both | none: v2 (BIP324) only, see below |
| Floresta | 0.9.1 | inbound only | `getaddr feefilter getheaders` |
| bitcoin-seeder | `92d2b46` | inbound only | `getaddr`, with `start_height` 350000 |
| bitnodes | `036dc5c` | inbound only | `getaddr`, with `relay` 0 and services 0 |

Replies to the recorder's own `getheaders` and `ping` are left out of the
last column. Probes: every implementation answered `ping` and `getheaders`
except bitcoin-seeder, which answered no probe and closed the connection
30 s after it opened, during the last one; no implementation disconnected
on a probe. Floresta and bitnodes leave the
`getdata` for an unknown wtxid unanswered; the rest send `notfound`. Core
31.2 logs the unknown message as `Unknown message type` and nothing else: no
misbehaviour, no disconnect.

## Limits

- **v1 only.** The recorder speaks v1. A peer that opens with v2 is
  recorded as a v2 attempt and closed, and the recorder waits 30 s for a v1
  retry. Core, Knots, satd and Floresta retry over v1. rbitcoin 0.8.0 does
  not, and it also refuses v1 inbound (`peer does not speak BIP324 v2`), so
  its fixtures record only that. Capturing its messages needs a v2
  recorder.
- **IBD state.** btcd and bcoin report no IBD field over RPC; their
  fixtures say so and that the tip was mined seconds before. Floresta
  cannot mine on regtest. Crawlers have no chain.
- **Dial-only clients.** Floresta and both crawlers make outbound
  connections only.
- **libbitcoin is missing.** libbitcoin-server 3.8.0 cannot be built from
  upstream source: three of its dependency repositories
  (`libbitcoin-blockchain`, `libbitcoin-protocol`, `libbitcoin-client`) are
  no longer on GitHub, and the next major version is unreleased.
- **Regtest, one block.** A node on mainnet with a full chain, peers and a
  mempool may announce more. The classifier's thresholds are calibrated on
  a synced mainnet node before they ship.

## Re-running

Build or download each implementation into a scratch directory, then:

```sh
SATD=… SATCLI=… CORE_BIN=…/bin KNOTS_BIN=…/bin BTCD=… BCOIN=… RBITCOIN=… \
FLORESTAD=… SEEDER=… BITNODES=… BITNODES_PYTHON=… \
./run-captures.py --workdir /path/to/scratch --out fixtures \
  --version satd=0.7.0 --version core=31.2 …
```

Each node runs with `HOME` set to its own scratch directory and binds to
127.0.0.1. btcd creates an empty `~/.btcd` from the passwd entry whatever
its flags say; the script removes it again. When satd's own greeting
changes, capture satd and update `capture.py`'s greeting to match.
