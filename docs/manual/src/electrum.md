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
| `server.features` | Feature/identity dict: genesis hash, `protocol_min`/`protocol_max` (both `1.4`), hosts, etc. |
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

## Subscriptions

Two push subscriptions are supported, both counted against
`--electrummaxsubsperconn`:

- `blockchain.headers.subscribe`: a `blockchain.headers.subscribe`
  notification on every new tip.
- `blockchain.scripthash.subscribe`: a `blockchain.scripthash.subscribe`
  notification carrying the new status hash whenever a watched scripthash's
  history changes, in the mempool or confirmed. The index is updated inside
  the same `connect_block` / `disconnect_block` batch as the chainstate, so
  a subscriber can never observe a status out of sync with the tip.

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
