# Electrum Protocol Server

satd ships a native **Electrum protocol** server (the `electrum-proto`
crate), serving the JSON-RPC-over-TCP protocol that BlueWallet, Sparrow,
Nunchuk, Electrum, and most hardware-wallet coordinators speak. It is a
query layer over satd's own chainstate and address-history index, not a
separate `electrs` or Fulcrum process with its own copy of the data. satd's
combined index is larger on disk than a standalone electrs/Fulcrum index:
the trade is disk for consistency and single-process operation. See
[Disk Footprint & Indices](disk-footprint.md) for the rationale behind the
native, shared-chainstate design.

The server is off by default. Enable it with `--electrum=1`. It needs
the address index for scripthash history (on by default) and
`--txindex=1` for the confirmed-transaction and merkle-proof methods
(off by default). Startup fails if either index is disabled.

- Protocol version: `1.4`, advertised as both `protocol_min` and
  `protocol_max`. satd serves a single protocol version.
- Transport: line-delimited JSON-RPC over plain TCP (default
  `127.0.0.1:50001`) and/or TLS (default port 50002). Expose the server
  over Tor / `.onion` rather than directly on the LAN.

> **Note.** Electrum is loopback by default. It supports native TLS and
> mutual TLS (`--electrumtlsbind` + `--electrummtls…`). The unified
> bearer-token layer does not gate Electrum; client-certificate principals
> are planned but not yet implemented. See
> [Authentication & Authorization](authentication.md).

## Configuration

| Flag | Default | Notes |
|---|---|---|
| `--electrum=<0\|1>` | `0` | Enable the Electrum server. Requires `--addressindex=1` and `--txindex=1`. |
| `--electrumbind=<addr:port>` | `127.0.0.1:50001` | Plain-TCP listener bind. |
| `--electrumtlsbind=<addr:port>` | none | TLS listener bind (standard port 50002). Requires cert + key. |
| `--electrumtlscert=<path>` | none | PEM TLS certificate. |
| `--electrumtlskey=<path>` | none | PEM TLS private key. |
| `--electrummtls=<0\|1>` | `0` | Require mutual TLS on the TLS listener. |
| `--electrummtlsclientca=<path>` | none | PEM CA bundle to verify client certs when `--electrummtls=1`. |
| `--electrummtlsclientallow=<subj>` | any CA-signed | Allowlist of accepted client-cert CN / DNS-SAN values. |
| `--electrummaxconns=<n>` | `64` | Hard cap on simultaneously-open connections. |
| `--electrummaxsubsperconn=<n>` | `1000` | Per-connection scripthash subscription cap. See [Subscription limits](#subscription-limits) for how it relates to the server-wide `--addrindexsubscriptions`. |
| `--electrumrequesttimeout=<secs>` | `30` | Per-request handler timeout. A request still running after this long is answered with a `request timed out` error and its connection is closed. The handler's work cannot be interrupted, so the connection keeps its `--electrummaxconns` slot until that work ends. |
| `--electrummaxbatchrequests=<n>` | `100` | Max requests per JSON-RPC batch line. Wallets such as Sparrow batch their whole gap-limit window of `scripthash.subscribe` calls at scan time, so a low cap fails the scan. |
| `--electrummaxbroadcastpackagetxs=<n>` | `25` | Max txs per `blockchain.transaction.broadcast_package`. |
| `--electrumfeehistogramttl=<secs>` | `10` | TTL for the `mempool.get_fee_histogram` cache. |
| `--electrumbanner=<text>` | `powered by satd <version>` | Override for `server.banner`. |
| `--electrumservername=<text>` | `satd-electrs-compatible/<version>` | Name reported by `server.version` / `server.features.server_version`. Does not affect the P2P user agent. See [The server name](#the-server-name-and-why-it-says-electrs). |

The server runs on satd's [isolated API runtime](api-scaling.md)
(`--api-threads`), so Electrum load cannot starve block connection. Each
request's handler runs on that runtime's blocking pool rather than on one of
its workers: a request that reads a long history does not hold up other
connections, Esplora, events gRPC or `/metrics`, and the request timeout
answers on time.

### History cap

A scripthash whose history holds more than 200,000 transactions is refused
rather than served. `blockchain.scripthash.get_history`, `get_balance`,
`listunspent` and `subscribe` answer with code `2`, `history too large (cap =
200000 entries)`, as ElectrumX ("history too large") and Fulcrum ("exceeds
max history") refuse the same methods above their `max_history`. For
`get_history` and `subscribe` the cap counts confirmed plus mempool
transactions. The refusal counts the history and stops at the first
transaction past the cap, so it costs a bounded read however long the
history is; a refused `subscribe` is not kept. A subscribed scripthash whose
history grows past the cap gets no further status notifications.
`get_first_use` and `get_mempool` are not capped: they read only the first
block and the mempool. `-addrindexmaxhistory=<n>` sets the cap, for Electrum
and Esplora together; `0` removes it, and a request for a busy scripthash
then reads its whole history again.

## Supported methods

A scripthash is the SHA-256 of an output `scriptPubKey`, reversed (hex),
exactly as in the Electrum protocol.

### Server / session

| Method | Description |
|---|---|
| `server.version` | Negotiate client/server software + protocol version. Also accepts rbitcoin's `1.4.2-asof`; see [Chain-tip stamps](#chain-tip-stamps). |
| `server.ping` | Keepalive; returns null. |
| `server.banner` | Server banner text (configurable via `--electrumbanner`). |
| `server.donation_address` | Configured donation address (empty if unset). |
| `server.features` | Feature/identity dict: genesis hash, `protocol_min`/`protocol_max` (both `1.4`), hosts, `tweaks` (whether `blockchain.tweaks.subscribe` can be served), `chain_tip` (`true`: answers name the tip they were read at), etc. |
| `server.peers.subscribe` | Peer-server discovery list (satd returns an empty set; no peer gossip). |

### Headers & blocks

| Method | Description |
|---|---|
| `blockchain.headers.subscribe` | Subscribe to new-tip notifications; returns the current tip header and pushes on each new block. |
| `blockchain.headers.get` | Fetch a header by height. |
| `blockchain.block.header` | A block header (with an optional merkle proof to a checkpoint). |
| `blockchain.block.headers` | A contiguous range of headers (with optional checkpoint proof). |

### Scripthash (address) queries

| Method | Description |
|---|---|
| `blockchain.scripthash.get_history` | Confirmed + mempool history for a scripthash. |
| `blockchain.scripthash.get_balance` | Confirmed + unconfirmed balance. |
| `blockchain.scripthash.listunspent` | Unspent outputs for a scripthash. |
| `blockchain.scripthash.get_mempool` | Mempool-only history for a scripthash. |
| `blockchain.scripthash.get_first_use` | First block/tx that paid the scripthash (electrs-style extension). |
| `blockchain.scripthash.subscribe` | Subscribe to a scripthash; pushes a new status hash whenever its history changes. |
| `blockchain.scripthash.unsubscribe` | Cancel a scripthash subscription. |

### Transactions

| Method | Description |
|---|---|
| `blockchain.transaction.get` | Raw transaction by txid (verbose decode optional). Needs `--txindex`. |
| `blockchain.transaction.get_merkle` | Merkle inclusion proof for a confirmed tx. Needs `--txindex`. |
| `blockchain.transaction.id_from_pos` | Txid at a `(height, position)`, optionally with a merkle proof. Needs `--txindex`. |
| `blockchain.transaction.broadcast` | Submit a raw transaction to the network. |
| `blockchain.transaction.broadcast_package` | Submit a package of transactions (bounded by `--electrummaxbroadcastpackagetxs`). |

### Fees

| Method | Description |
|---|---|
| `blockchain.estimatefee` | Estimated fee rate (BTC/kB) for a confirmation target. |
| `blockchain.relayfee` | The node's minimum relay fee rate. |
| `mempool.get_fee_histogram` | Mempool fee-rate histogram (cached; TTL `--electrumfeehistogramttl`). |

### Silent payments

| Method | Description |
|---|---|
| `blockchain.tweaks.subscribe` | BIP 352 tweak stream for client-side scanning. Requires `-silentpaymentindex=1`; see below. |

## Chain-tip stamps

The methods that read the chain at one block answer for the tip the
request started at, and name it beside `result`:

```json
{"jsonrpc": "2.0", "id": 7, "result": {"confirmed": 5000, "unconfirmed": 0},
 "chain_tip": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
 "chain_tip_height": 3}
```

They are `blockchain.scripthash.get_history`, `get_balance` and
`listunspent`, and `blockchain.transaction.get`, `get_merkle` and
`id_from_pos`. The members and methods are rbitcoin's (satd adds
`id_from_pos`), and as on rbitcoin every connection gets them. A wallet
that syncs with several requests compares `chain_tip` across them: if it
changed, a block connected or a reorg happened in between, and the answers
do not describe one chain.

- Nothing above the pinned tip counts as confirmed. A transaction that
  confirms while the request runs is listed as the unconfirmed transaction
  it was: `get_history` and `listunspent` give it height `0` (`-1` when it
  spends another transaction that was unconfirmed then) and `get_history`
  its fee when its inputs can be read; `get_balance` counts it in
  `unconfirmed`; `transaction.get` gives it no block, and `get_merkle`
  and `id_from_pos` no proof or position.
- `transaction.get`'s `confirmations` counts to the pinned tip.
- A disconnect while a request runs (a reorg, or `invalidateblock`) runs it
  again at the new tip. One that a disconnect interrupts eight times in a
  row is answered with the error `chain view moved`.
- The mempool part of an answer is read as it is when the request reads it.
- Errors, and every other method, carry no stamp.

`server.version` also accepts rbitcoin's protocol string `1.4.2-asof`, alone
or at either end of a `[min, max]` range, and answers with it, so a client
written for rbitcoin negotiates as it does there. The protocol spoken is
still 1.4, and the stamps do not depend on it.

## Subscriptions

Two long-lived push subscriptions are supported. Only
`blockchain.scripthash.subscribe` is counted against
`--electrummaxsubsperconn`; `blockchain.headers.subscribe` is one per
connection whatever the cap:

- `blockchain.headers.subscribe`: a `blockchain.headers.subscribe`
  notification on every new tip.
- `blockchain.scripthash.subscribe`: a `blockchain.scripthash.subscribe`
  notification carrying the new status hash whenever a watched scripthash's
  history changes, in the mempool or confirmed. The index is updated inside
  the same `connect_block` / `disconnect_block` batch as the chainstate, so
  a subscriber can never observe a status out of sync with the tip.
  The status is the protocol's sha256 over `tx_hash:height:` for each
  history row, in the order `blockchain.scripthash.get_history` returns
  them: confirmed transactions by height and position in the block, then
  mempool transactions, height `0` (all inputs confirmed) before `-1`
  (spends an unconfirmed parent), then by txid as displayed. A client can
  therefore check an announced status by hashing the `get_history` answer
  as received.

Status notifications are computed after every block for every subscribed
scripthash, and after every mempool change for the subscribed scripthashes
it touches, by reading each history from the index. That work runs on the
blocking pool, never on a runtime worker, and block events that arrive while
one pass is running share the next pass.

### Subscription limits

Two caps apply to `blockchain.scripthash.subscribe`:

- `--electrummaxsubsperconn` (default `1000`) bounds one connection.
- `--addrindexsubscriptions` (default `10000`) bounds the distinct
  scripthashes subscribed across the whole server. Esplora's
  `/address/:addr/sse` and `/scripthash/:hash/sse` streams count against it
  too. Once it is full, every further subscribe of a new scripthash is
  refused with `subscribe: subscription cap reached (N scripthashes)`,
  whichever connection asks.

With the defaults, 10 connections at their own cap fill the server-wide
registry while 54 of the 64 connection slots are still free, and satd logs
how many connections fill it at startup. For the per-connection cap to bind
first, set `--addrindexsubscriptions` to at least
`--electrummaxconns` × `--electrummaxsubsperconn` (64,000 with the defaults),
plus room for the Esplora SSE streams you serve. Each subscribed scripthash
costs a notification channel of a few kilobytes and a history read on every
block, so size it to the wallets you serve. `--addrindexsubscriptions` can be
changed with `SIGHUP`; lowering it does not drop existing subscriptions.

`blockchain.tweaks.subscribe` also pushes notifications, but it is a bounded
chunk rather than a standing subscription — it ends itself with
`{"message":"done"}` — so it does not count against the per-connection cap.

A chunk serves at most **1000 heights**, whatever `count` asks for; both known
clients request the entire remaining chain in one call and resubscribe when the
chunk ends, and the de-facto reference server clamps the same way. The cap is
what makes the end marker unambiguous: clients disagree about what `done` means
— Cake reads it as "this chunk ended, ask again from the last height key",
kiss-bdk as "the range I requested was served in full" — and those readings only
agree if the server finishes every range it accepts. satd therefore bounds the
range up front rather than truncating an accepted one. If a chunk does stop
early anyway (a height it cannot read, or the 60-second budget), it ends with
`{"message":"incomplete: …; resume from height <h>"}` instead of `done`, so a
client that reads the sentinel as completion is not told that unserved heights
were scanned and empty.
Only one runs per connection at a time: a second subscribe while one is still
producing is refused rather than replacing it, because notifications the
superseded stream had already queued cannot be recalled and would arrive after
the new stream's first height.

## Serving silent-payment tweaks

`blockchain.tweaks.subscribe` serves the BIP 352 per-transaction tweaks a wallet
needs to scan for silent payments **on the device** — the node never sees a scan
key. It requires the tweak index (`-silentpaymentindex=1`), and refuses in-band
without it, or while the index is still backfilling: a partial index would answer
the heights it has not reached with silence, and a scanning client cannot tell
that from "no payments here". `server.features.tweaks` reports whether this node
can serve it **right now** — index present *and* complete, the same test the
subscribe itself makes — so a client can check before starting a scan rather
than discovering hours of backfill the hard way.

**It is a stream, not a call.** The JSON-RPC `result` carries the **first**
height only; every further height arrives as an unsolicited
`blockchain.tweaks.subscribe` notification, and `{"message":"done"}` ends the
chunk. A client that treats it as an ordinary request/response reads one block
and believes it finished a scan. Params are
`[start_height, count, historical_mode]`, and one height looks like:

```json
{"850000": {"<txid>": {"tweak": "<33-byte hex>",
                       "output_pubkeys": {"<vout>": ["<x-only hex>", 100000]}}}}
```

Carrying each transaction's taproot outputs alongside the tweak is what lets a
client confirm a match without fetching the block — the difference between a
scan that is CPU-bound and one that waits on network round-trips.

`historical_mode` is the same trade the streaming API's `tweak_unspent_only`
makes, in reverse polarity: `false` (what Cake Wallet sends) **cuts through**
coins that are already spent, `true` keeps them. A balance scan wants `false`; a
wallet reconstructing transaction history must pass `true`, because a payment
received and later spent is omitted entirely under cut-through. See
[Silent Payments](silent-payments.md) for the full contract.

Heights below taproot activation are streamed as one notification carrying up to
1024 empty height keys, so a wallet restoring from an old height still sees its
progress marker advance without the server writing ~700k lines. A chunk ends
after 60 seconds of wall clock at a height boundary; clients resubscribe from the
next unscanned height, which is what `done` is for.

### The server name, and why it says `electrs`

satd reports `satd-electrs-compatible/<version>` from `server.version` and
`server.features.server_version`.

Cake Wallet feature-detects by matching on that string rather than on
`server.features`, and will not probe
`blockchain.tweaks.subscribe` at all unless it contains the substring `electrs`
— note `electrs`, not `electrum`; the two read the same to a person and only one
matches. Carrying the token is what makes silent-payment support work out of the
box for those clients.

The name leads with satd's own identity and states a claim about the *protocol*,
in the same way every browser still sends `Mozilla` at the front of its
user-agent long after that stopped saying anything about who wrote the browser.
It is scoped to this surface: peers on the P2P network see satd's own user agent
(`/satd:<version>/`, reported by `getnetworkinfo` as `subversion`), which this
setting cannot change.

Override it if you would rather not advertise the token, or need a different one
for another client:

```ini
electrumservername=satd/0.6.0
```

Keep an override from *beginning* with `electrs`. Several clients test that
prefix rather than searching the whole string: BlueWallet uses it to decide a
server needs request batching disabled, and a name starting with `electrs`
would leave batching off permanently. Leading with `satd-` — identity first,
compatibility token second — is what keeps the default matching Cake's
substring test while matching nobody's prefix test. An empty value
(`electrumservername=`) is ignored with a warning rather than advertising a
nameless server.

Other tweak clients (for example
[kiss-bdk](https://github.com/kkdao/kiss-bdk)) do not need the substring — they
identify the chain from `server.features.genesis_hash`. Nothing else about the
server depends on the name.

Sparrow's silent-payment path is a *different* method
(`blockchain.silentpayments.subscribe`), which uploads a scan key to the server.
satd does not implement it. Sparrow still uses satd as an ordinary Electrum
backend.

## Notes & differences

- `--txindex` is required for `blockchain.transaction.get`, `get_merkle`,
  and `id_from_pos`. `--addressindex` (on by default) backs every
  `scripthash.*` method.
- **History order is unchanged by the ordinal-keyed chainstate.** The
  address index stores rows keyed on a dense transaction ordinal rather
  than a height and txid (see [Disk Footprint](disk-footprint.md)), but
  the store resolves and orders them before they leave it, so
  `get_history`, `listunspent` and `get_balance` return exactly the rows,
  in exactly the order, that they did before. Nothing on the Electrum
  wire carries an ordinal.
- **Histories over the cap are refused**, not truncated: see
  [History cap](#history-cap).
- satd advertises a single protocol version (`protocol_min == protocol_max
  == 1.4`); it does not negotiate a range. The one other string it accepts
  is rbitcoin's `1.4.2-asof` ([Chain-tip stamps](#chain-tip-stamps)).
- `server.peers.subscribe` returns an empty list: satd does not participate
  in Electrum peer gossip.
- The protocol layer is vendored from `romanz/electrs` (MIT; attribution in
  `electrum-proto/vendor/electrs.MIT`) and adapted to satd's `AddressIndex`
  trait over the shared RocksDB.
