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
- `fixtures/crawl/` holds the crawl-shape captures (below):
  `<name>-<version>-outbound-crawl[-v2].json`. They sit in a directory of
  their own so the classifier's fixture tests, which read every
  `fixtures/*.json` and expect a table row for each, do not pick them up.

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

## Crawl-shape captures

`capture.py --crawl` (with `--dial`) greets a node as an optional crawl
mode would: a declared crawler that only asks for addresses. Its `version`
carries protocol 70016, services 0, relay 0, `start_height` the node's real
tip, a random nonce, the dialed address in `addr_recv`, a dummy
`addr_from`, and the user agent `/satd:<version>(crawler)/` (the version
from the workspace `Cargo.toml`). It sends `version` at once and, on the
node's `version`, `wtxidrelay` and `sendaddrv2` when the common version is
70016 or more (as the crawl does: libbitcoin 3.8.0 and bcoin 2.2.0 speak
older versions), then `verack`, and nothing else unsolicited; it answers `ping` and `getheaders` as before. After the
handshake and the 10 s passive window it sends one `getaddr`, waits up to
90 s for the answer (the first `addr`/`addrv2` with more than one entry),
then runs the same four probes.

The `getaddr` answer is kept as summary numbers only (`getaddr` in the
fixture): message kind, entry count, delay from `getaddr`, networks,
service bits, whether the node lists itself, and the age spread of the
entries' `nTime`. With `--v2` the recorder dials v2 first and records the
node's BIP324 transport before any message (`v2_transport`: garbage
length, decoy packets before its version packet, the version packet's
length and contents, decoys afterwards, short vs 12-byte message IDs, and
`v2_id` on each message). When the v2 attempt fails it records how
(`v2_failure`: reset, end of stream or timeout, the time, and how many
bytes came back, never the bytes) and redials over v1, as a crawler falls
back.

`run-captures.py --crawl` runs this against each implementation that
accepts connections. It first seeds the node's address book with 1,000
random routable IPv4 addresses on the regtest port through
`addpeeraddress` (`--seed-addrs`), and starts the node with no outbound
connections of its own (`-connect=0`; rbitcoin, whose `--max-outbound`
must be at least 1, dials only a closed local port), so nothing it was
given is ever dialled. `peer_state.address_book` records how many it
accepted.

| Implementation | Version | v1 | v2 | Opening messages after `verack` | `getaddr` answer (v1 / v2) | v2 transport | Our v2 attempt, if refused |
|---|---|---|---|---|---|---|---|
| Bitcoin Core | 32.1 | yes | yes | `sendcmpct ping feefilter` | `addrv2`, 227 of 990 / 228 of 992, 1 ms / 5 ms | garbage 1729 B, no decoys, empty version packet | n/a |
| Bitcoin Core | 24.0.1 | yes | no | `sendcmpct ping feefilter` | `addrv2`, 227 of 991 / 228 of 992, 1 ms / 119 ms | n/a | closed (end of stream) after 73 ms, 0 bytes back; v1 redial works |
| satd | 0.8.0-pre | yes | yes | `sendcmpct feefilter ping` | `addrv2`, 230 of 1000, 2 ms / 8 ms | garbage 2731 B, no decoys, empty version packet | n/a |
| rbitcoin | 0.8.99 | no | yes | `sendheaders sendcmpct ping` | — / `addrv2`, 230 of 1000, 11 ms | garbage 3570 B, no decoys, empty version packet | n/a |

"227 of 990" is the entry count of the answer out of the addresses the
node accepted. What the table shows:

- **No `getheaders`.** Against the normal outbound shape Core (31.2 in
  the fixtures above, and 32.1 when re-checked) and satd 0.7.0 send
  `getheaders` after `verack`; against services 0 no implementation asks
  for headers. rbitcoin still sends
  `sendheaders`.
- **`notfound` depends on `relay`.** Core (32.1 and 24.0.1) leaves the
  `getdata` probe for an unknown txid unanswered on a connection that set
  relay 0; satd and rbitcoin send `notfound` as they do on a normal one.
  No implementation disconnected on any probe or on `getaddr`.
- **Answer size.** Every answer is 23 % of the address book, as Core's
  `MAX_PCT_ADDR_TO_SEND`, in `addrv2` (all were sent `sendaddrv2`); none
  lists the node itself. In rbitcoin's answer every entry's `nTime` is the
  time of the answer (age 0) and its services are 0x809; in Core's and
  satd's, `nTime` is when the address was added and services are 0x9.
- **v2 transport.** Garbage length is random per connection (BIP324:
  0–4095 bytes), so one capture shows only that a node sends some. No node
  sent decoy packets or a non-empty version packet, and every node used
  the short ID wherever BIP324 defines one (`version`, `verack`,
  `wtxidrelay`, `sendaddrv2` and `sendheaders` have none), so message IDs
  do not tell these implementations apart.
- **rbitcoin refuses v1:** it closes our v1 connection before sending
  anything, as in the outbound fixtures.

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
- **Crawl captures: versions.** The Core, satd and rbitcoin versions are
  the ones that were available (Core 32.1 and 24.0.1, satd at this tree's
  version, an rbitcoin 0.8.99 development build); Knots 29.5.1, btcd
  0.27.0, bcoin 2.2.0 and libbitcoin-server 3.8.0 are their current
  releases. The Core, satd, rbitcoin, Knots and btcd crawl captures were
  taken while the recorder still sent `wtxidrelay` with its `version`;
  all of them speak 70016 or more, where the crawl sends it too.
- **Crawl captures: how v1-only clients refuse v2.** Core 24.0.1 closes
  with nothing sent and btcd resets: a crawler redials those over v1.
  bcoin and libbitcoin send their v1 `version` first, then close on our
  BIP 324 bytes, and bcoin bans the address for them (its log: `Invalid
  magic value`, `Ban threshold exceeded`), so its v1 redial is refused.
- **Crawl captures: btcd, bcoin and libbitcoin address books.** None of
  them can be given addresses over RPC, so their `getaddr` answers are
  empty or absent.
- **Crawl captures: regtest address books.** Each answer comes from about
  1,000 addresses added over RPC seconds before, all IPv4 on one port, so
  the answer's networks, service bits and `nTime` spread say little about a
  mainnet node's. The delay is from `getaddr` to the answer: it rides the
  address trickle (Core: an exponential timer averaging 30 s), and sent
  10 s after the handshake it mostly found the timer already due, so the
  regtest delays are short. A node's own address on 127.0.0.1 is never in
  its address book, so `lists_itself` is false by construction here.
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

The crawl-shape captures:

```sh
SATD=… SATCLI=… CORE_BIN=…/bin RBITCOIN=… \
./run-captures.py --crawl --workdir /path/to/scratch --out fixtures/crawl \
  --transport v1,v2 --core-functional /path/to/bitcoin/test/functional \
  --version satd=0.8.0-pre --version core=32.1 --version rbitcoin=0.8.99
```

and for the other families:

```sh
KNOTS_BIN=…/bin BTCD=… BCOIN=… LIBBITCOIN_BS=… \
./run-captures.py --crawl --workdir /path/to/scratch --out fixtures/crawl \
  --only knots,btcd,bcoin,libbitcoin \
  --transport v1,v2 --core-functional /path/to/bitcoin/test/functional \
  --version knots=29.5.1.knots20260508 --version btcd=0.27.0 \
  --version bcoin=2.2.0 --version libbitcoin=3.8.0
```

bcoin needs its native `bdb` module built (`npm rebuild bdb` after an
install with `--ignore-scripts`).
