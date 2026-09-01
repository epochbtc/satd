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
| `--electrummaxsubsperconn=<n>` | `1000` | Per-connection scripthash subscription cap. |
| `--electrumrequesttimeout=<secs>` | `30` | Per-request handler timeout. |
| `--electrummaxbatchrequests=<n>` | `100` | Max requests per JSON-RPC batch line. Wallets such as Sparrow batch their whole gap-limit window of `scripthash.subscribe` calls at scan time, so a low cap fails the scan. |
| `--electrummaxbroadcastpackagetxs=<n>` | `25` | Max txs per `blockchain.transaction.broadcast_package`. |
| `--electrumfeehistogramttl=<secs>` | `10` | TTL for the `mempool.get_fee_histogram` cache. |
| `--electrumbanner=<text>` | `powered by satd <version>` | Override for `server.banner`. |
| `--electrumservername=<text>` | `satd-electrs-compatible/<version>` | Name reported by `server.version` / `server.features.server_version`. Does not affect the P2P user agent. See [The server name](#the-server-name-and-why-it-says-electrs). |

The server runs on satd's [isolated API runtime](api-scaling.md)
(`--api-threads`), so Electrum load cannot starve block connection.

## Supported methods

A scripthash is the SHA-256 of an output `scriptPubKey`, reversed (hex),
exactly as in the Electrum protocol.

### Server / session

| Method | Description |
|---|---|
| `server.version` | Negotiate client/server software + protocol version. |
| `server.ping` | Keepalive; returns null. |
| `server.banner` | Server banner text (configurable via `--electrumbanner`). |
| `server.donation_address` | Configured donation address (empty if unset). |
| `server.features` | Feature/identity dict: genesis hash, `protocol_min`/`protocol_max` (both `1.4`), hosts, `tweaks` (whether `blockchain.tweaks.subscribe` can be served), etc. |
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

## Subscriptions

Two long-lived push subscriptions are supported, both counted against
`--electrummaxsubsperconn`:

- `blockchain.headers.subscribe`: a `blockchain.headers.subscribe`
  notification on every new tip.
- `blockchain.scripthash.subscribe`: a `blockchain.scripthash.subscribe`
  notification carrying the new status hash whenever a watched scripthash's
  history changes, in the mempool or confirmed. The index is updated inside
  the same `connect_block` / `disconnect_block` batch as the chainstate, so
  a subscriber can never observe a status out of sync with the tip.

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
electrumservername=satd/0.5.1
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
- satd advertises a single protocol version (`protocol_min == protocol_max
  == 1.4`); it does not negotiate a range.
- `server.peers.subscribe` returns an empty list: satd does not participate
  in Electrum peer gossip.
- The protocol layer is vendored from `romanz/electrs` (MIT; attribution in
  `electrum-proto/vendor/electrs.MIT`) and adapted to satd's `AddressIndex`
  trait over the shared RocksDB.
