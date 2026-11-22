# Peer Behaviour Flags

satd keeps a small record of what each peer does on the wire, judges from it
which implementation the peer runs and whether it behaves like a crawler, a
transaction spy or a peer that lies about its chain, and reports the result.
It only reports: no flag changes how a peer is treated.

## What is judged

Every 5 seconds the node judges each connected peer, and once more when a
peer leaves, so that a peer gone in a few seconds is judged on its whole
session. Two things come out of it.

**A fingerprint.** The commands a peer sends from its `version` through the
end of its connection setup, with its `version` fields (protocol version,
services, `relay`), are compared against a table of the shapes each
implementation was measured to send: Bitcoin Core (Knots and other Core
forks are in the Core family, since they share its networking code), btcd,
bcoin, libbitcoin, Floresta, rbitcoin, satd, and the bitcoin-seeder and
bitnodes crawlers. Every row of the table comes from a capture of that
implementation against a local node, committed with the sources
(`contrib/peer-fingerprint/`). The result is one of:

| Result | Means |
|---|---|
| `known` | The transcript matches one family, and the user agent names that family or none. `confidence` is `high` when the commands alone tell, `low` when another family sends the same commands and the `version` fields told them apart. |
| `unknown` | No row matches, or the transcript is not settled yet (less than 10 seconds connected and still open). A shape no capture shows, such as an older release or Core's block-relay-only and feeler connections, is unknown rather than a guess. |
| `mismatch` | The user agent names one family and the transcript matches another. |

**Flags**, each carried with the numbers that raised it:

| Code | Name | Raised when |
|---|---|---|
| `C` | `crawler` | An inbound peer connected for under 300 s has sent `getaddr` and no `getheaders` or block request, and either its handshake is a known crawler's (`bitnodes`, `bitcoin-seeder`) or its network group has opened at least 3 inbound connections in the last hour. Onion and unroutable peers have no network group to count, so they get `C` only by the crawler handshake. |
| `S` | `spy` | A peer that asked for transaction relay has been sent at least 500 transaction announcements, asked for at least 90% of them, with a 10th-percentile delay of 5 ms or less, announced none itself, asked for no block, and been connected at least 2 hours. |
| `F` | `fingerprint-mismatch` | The fingerprint is a `mismatch`. |
| `A` | `addr-abuse` | More than one `getaddr` in the connection (Core answers one), or more than 1,000 of its addresses dropped by the address rate limit. |
| `H` | `height-lie` | Its `start_height` was at least 6 blocks above the chain it then served in answer to our `getheaders`. |
| `N` | `notfound-pattern` | At least 10 `notfound` for transactions it announced and was asked for, and at least 10% of what it announced. |
| `T` | `stalling` | At least 3 block-download stalls charged to it. |

**The thresholds are provisional.** They are placeholders until they are
calibrated against the distribution measured on a synced mainnet node, and
may change in any release. Flags are recomputed on every pass, so a flag
clears when its shape goes, except where the counters behind it only grow.

## `getpeerbehavior`

`getpeerbehavior [peer_id]` is a satd RPC. With no argument it returns every
peer, ordered by id; with a `peer_id` it returns an array holding that peer,
or error `-8` if no peer has the id. `getpeerinfo` is unchanged. A client
talking to a node without the method gets "Method not found".

```
sat-cli getpeerbehavior 7
```

```json
[
  {
    "id": 7,
    "connection_type": "inbound",
    "session_secs": 4,
    "subver": "/bitcoin-seeder:0.01/",
    "evaluated": true,
    "fingerprint": {
      "result": "known", "family": "bitcoin-seeder", "confidence": "high",
      "settled": true, "handshake": ["version", "verack", "getaddr"]
    },
    "flag_codes": "C",
    "flags": [
      {"code": "C", "name": "crawler",
       "evidence": {"session_secs": 4, "getaddr_in": 1, "headers_req": 0, "blocks_req": 0, "netgroup_seen": 5}}
    ],
    "counters": { "inv_tx_in": 0, "getdata_tx_in": 0, "getaddr_in": 1, "...": "..." }
  }
]
```

| Field | What |
|---|---|
| `id` | The peer id `getpeerinfo` uses. No address is reported. |
| `connection_type` | As `getpeerinfo.connection_type`. |
| `session_secs` | Seconds since the connection opened. |
| `subver` | The user agent, sanitized as `getpeerinfo.subver` is. It is the peer's own text. |
| `evaluated` | Whether the peer has been judged yet; a peer connected in the last 5 seconds may not have been. |
| `fingerprint` | `result` and its fields (above), `settled`, and `handshake`, the commands the fingerprint was judged on. |
| `flag_codes`, `flags` | The flags from the last pass, each with its evidence. |
| `counters` | The raw record: `inv_tx_in`, `getdata_tx_in`, `getdata_latency` (count, `p10_ms`, `median_ms`, and the histogram), `inv_tx_announced_to`, `headers_req`, `blocks_req`, `getaddr_in`, `addr_in`, `addr_out`, `addr_rate_limited`, `notfound_after_inv`, `height_claim_gap`, `stalls`, and the `version` fields. |

It is a read: allowed on the read-only listener, and for a bearer token it
needs `rpc:read`.

## Metrics, status page and log

- `satd_peer_flagged{flag}`: connected peers carrying each flag, one series
  per code, zeros included.
- `satd_peer_fingerprint{family}`: connected peers per observed family
  (a mismatch counts under the family its transcript matched), plus
  `family="unknown"`.
- The [status page](observability.md#status-page) lists the number of
  connected peers carrying each flag, and only the flags some peer carries.
- With `-debug=net`, one line when a peer first gains a flag in a
  connection, with its evidence, fingerprint and quoted user agent.

None of these carries an address, and a user agent appears only escaped.
