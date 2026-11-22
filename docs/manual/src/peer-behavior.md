# Peer Behaviour Flags

satd keeps a small record of what each peer does on the wire, judges from it
which implementation the peer runs and whether it behaves like a crawler, a
transaction spy or a peer that lies about its chain, and reports the result.
By default it only reports: no flag changes how a peer is treated. With
[`-peerflagpolicy=evict`](#soft-enforcement--peerflagpolicy) some flags
decide which inbound peer goes first when an inbound slot is needed, and
nothing else.

An opt-in [network survey](#network-survey) applies the same judgement to
short connections of its own, across the address book.

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
| `alt_slot` | Only for a peer in an [alt-slot](#alt-slots): the `rule` it matched, the `trust` its user agent got, and `fallback`. |
| `counters` | The raw record: `inv_tx_in`, `getdata_tx_in`, `getdata_latency` (count, `p10_ms`, `median_ms`, and the histogram), `inv_tx_announced_to`, `headers_req`, `blocks_req`, `getaddr_in`, `addr_in`, `addr_out`, `addr_rate_limited`, `notfound_after_inv`, `height_claim_gap`, `stalls`, and the `version` fields. |

It is a read: allowed on the read-only listener, and for a bearer token it
needs `rpc:read`.

## In sat-tui

`sat-tui` shows the flags in a column of its peers tables, marks a
mismatched agent with `≠`, opens a detail overlay with the evidence and
counters on `Enter`, filters to flagged peers on `f`, and counts Peer
clients by observed family. See [sat-tui](tui.md#peer-behaviour).

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

## Soft enforcement (`-peerflagpolicy`)

`-peerflagpolicy=observe|evict`, default `observe`.

- **`observe`**: the flags are information only. The inbound eviction is
  Bitcoin Core's, unchanged.
- **`evict`**: an inbound peer flagged `C`, `S` or `F` loses the protection
  Core's eviction gives it (network group, ping time, recent transactions
  and blocks, privacy network, uptime) and is the first evicted when an
  inbound slot is needed. Among several flagged peers, Core's last rule
  picks: the youngest of the network group with the most of them.

`evict` only reorders an eviction that would happen anyway:

- Nothing is disconnected while an inbound slot is free, nor because a
  peer gained a flag. An eviction happens, as in Core, when a new inbound
  connection arrives with every inbound slot taken, or when a
  transaction-relaying inbound peer arrives past the transaction-relay
  share of them.
- Nothing is banned or discouraged; an evicted peer may connect again.
- Peers with the `noban`, `relay` or `forcerelay` permission
  (`-whitelist`, `-whitebind`) are exempt and keep Core's protection.
  `noban` peers are never evicted at all, as in Core.
- Outbound peers, manual connections and alt-slot peers are never touched:
  the surplus outbound eviction after IBD ignores the flags.
- The `A`, `H`, `N` and `T` flags play no part.

An eviction the policy decided is logged (`peer=<id> evicted first under
-peerflagpolicy=evict, flagged <codes>`), and the peer's disconnect reason
is `evicted-flagged`. A node that does not accept inbound connections
(`-listen=0`) never evicts, so the policy has nothing to act on there.

The flag thresholds are provisional (see above), so under `evict` a
threshold change in a later release changes which peers go first. The
policy is read at startup; a reload that changes it reports it as needing
a restart. `getconfig` reports it as `p2p.peer_flag_policy`.

## Network survey

**Off by default.** With `-peersurvey=1` the node surveys the network: which
implementations are reachable, and how many of each. It samples, from the
node's own address book; the [network crawl](crawl.md) (`-crawl`) counts,
and supersedes the survey while it is on.

> **The survey's file holds peer addresses.** `peersurvey.dat` in the data
> directory keeps one record per address the survey reached, and
> `getpeersurvey true` returns them. The file is written with the data
> directory's permissions, execute bits dropped, and nothing serves it but
> the authenticated RPC. **Probing makes survey connections recognisable**:
> no ordinary connection sends an unknown message or asks for a transaction
> that does not exist, so a peer that logs them can tell a satd surveyor
> from an ordinary node, and follow it across address changes. The node's
> own peers are never probed. `-peersurveyprobes=0` turns the probes off.

### What a survey connection does

Every `-peersurveyinterval` seconds (60 by default), if no survey connection
is open, the node draws an address uniformly from its whole address book,
new and tried entries alike, and opens a survey connection to it. Nothing
about the address weighs the draw. It passes over what an automatic dial
passes over: an address the operator named, a banned one, one on a network
the node does not reach, one connected or being dialled, one backing off
after failed dials, and a bad port. It is dialled as any automatic
connection is, so `-onlynet`, `-proxy` and `-onion` apply: a node that only
reaches Tor surveys only over Tor. It tries BIP 324 first under
`-v2transport`, as an ordinary outbound does.

The connection is outside every connection budget: it takes no outbound
slot, at most one is open at a time, and `getpeerinfo` and
`getconnectioncount` leave it out. It does not run under `-connect` or with
networking off.

It sends the same `version` (with `relay` set), `wtxidrelay`, `sendaddrv2`,
`verack`, `sendheaders`, `sendcmpct` and `feefilter` an ordinary full-relay
outbound sends, and answers a `ping`. It sends no `getaddr`, no
`getheaders` and none of the node's addresses. It listens for up to 10
seconds while the peer announces what it supports, until the handshake
transcript the fingerprint is judged on is complete, then sends the probes
and closes. It carries no blocks, transactions or addresses either way.

The address book learns what a feeler would teach it: a completed handshake
moves the address to the tried table, the peer's `version` updates its
services, and a failed dial counts as an attempt. Nothing else.

### Probes

With `-peersurveyprobes=1` (the default with the survey), each survey
connection sends a random subset of these, in random order, after the
listening and before it closes:

| Probe | Sends | Records |
|---|---|---|
| `ping` | `ping` with a random nonce | the `pong`'s round trip, in milliseconds |
| `getheaders` | `getheaders` with the parent of the node's tip as the locator and the tip as the stop; not sent while the node is at genesis, where a peer would answer with 2,000 headers | how many headers come back |
| `getdata` | `getdata` for a random transaction id (by wtxid to a peer that relays by wtxid) | whether `notfound` names it |
| `unknown` | a message of a random type no implementation defines, empty | whether the peer closes the connection over it |

Each was checked against Bitcoin Core v32.1: none raises a misbehaviour
score or costs the connection. Nothing Core punishes is sent (`mempool`
without `NODE_BLOOM`, filter requests to a peer that does not serve them, a
second `getaddr`). Probes are sent on survey connections only, never to the
node's own peers.

### `getpeersurvey`

`getpeersurvey [verbose]` returns the aggregate of what the store holds:

```json
{
  "addresses": 812,
  "families": {
    "core": {"count": 690, "share": 0.8497},
    "btcd": {"count": 9, "share": 0.0111},
    "...": "...",
    "unknown": {"count": 41, "share": 0.0505}
  },
  "mismatches": 3,
  "v2": {"count": 402, "share": 0.495},
  "top_as": [{"asn": 64496, "count": 57}],
  "probed": 405,
  "enabled": true,
  "probes": true,
  "interval": 60,
  "connections": {"completed": 815, "failed": 1311,
                  "last": {"time": 1795000000, "result": "completed"}}
}
```

| Field | What |
|---|---|
| `addresses` | Records in the store: addresses the survey reached in the last 30 days. |
| `families` | Records per observed family (a mismatch counts under the family its handshake matched), with each one's share of `addresses`. |
| `mismatches` | Records whose user agent names one family and handshake matches another. |
| `v2` | Records reached over BIP 324. |
| `top_as` | The ten autonomous systems with the most records. Empty without `-asmap`. |
| `probed` | Records with at least one probe outcome. |
| `enabled`, `probes`, `interval` | The survey's settings. With the survey off, `enabled` is false and every count is zero. |
| `connections` | Survey connections since start: `completed`, and `failed` at the dial or the handshake; `last`, the most recent to end, with its `time` (Unix seconds) and `result` (`completed` or `failed`), null until one ends. |
| `alt_slots` | The [alt-slots](#alt-slots): `configured`, `matched`, `fallback` and `empty`. Reported with the survey off too. |

`getpeersurvey true` adds `peers`, one row per address, most recently seen
first: `addr`, `network`, `fingerprint` (as in `getpeerbehavior`, for
example `core/high`), `family`, `claimed` (the family the user agent names),
`mismatch`, `subver` (sanitized peer text), `version`, `services`, `v2`,
`asn`, `first_seen`, `last_seen` (Unix seconds) and `probes`, each probe
sent with its `result` (`answered`, `silent` or `disconnected`) and, when
answered, its `value`.

The RPC is operator control: it is refused on the read-only listener, and
for a bearer token it needs `rpc:write`.

### The store

`peersurvey.dat` keeps one record per address: the fingerprint, user agent,
protocol version, services, whether it spoke v2, its autonomous system, when
it was first and last seen, and the last probe outcomes. A record not seen
for 30 days is dropped, and past 250,000 records (about 25 MB) the least
recently seen go first. It is written every 10 minutes and at shutdown, and
read at startup; a file that does not read is renamed with a `.bad-<unix time>` suffix, with a warning, and
the survey starts empty.

### Metrics

- `satd_peer_survey_enabled`: 1 while the survey runs.
- `satd_peer_survey_records`, `satd_peer_survey_family{family}`,
  `satd_peer_survey_mismatches` and `satd_peer_survey_v2`: the store's
  counts.
- `satd_peer_survey_connections_total{result}`: `completed` and `failed`
  survey connections.
- `satd_peer_survey_probes_total{probe,outcome}`: probe outcomes.

None carries an address.

## Alt-slots

**Off by default.** `-altslots=N` sets aside N of the full-relay outbound
slots for peers that match the operator's preference rules, for example to
keep connections to implementations other than Core. The rest of the slots
are filled from the address book exactly as without it. Alt-slot peers are
ordinary full-relay connections in every other respect: they relay blocks,
transactions and addresses, and `getpeerinfo` reports them as
`outbound-full-relay`. The two block-relay-only connections are never
alt-slots.

> **The eclipse trade-off.** The peers that match your rules are a far
> smaller pool than the address book. An attacker who runs nodes matching
> them competes for those slots against a few honest nodes instead of
> thousands. With `-altslots` equal to `-maxoutboundfullrelay`, every
> full-relay outbound comes from that small pool, and transaction and
> address relay could be served entirely by the attacker's nodes. The two
> block-relay-only connections stay ordinary and remain the backstop for
> block delivery. What limits it: the network-group rule every outbound
> obeys, flagged and contradicted candidates kept out by default, and
> fingerprints that are harder to fake than user agents. The node logs a
> warning when `-altslots` is above 4. The choice is yours; satd does not
> refuse it.

### Rules

`-altprefer=<rule>`, repeatable; earlier rules have priority. A rule is one
or more terms joined by `+`, all of which must hold, with an optional `@k`
cap on how many slots it may fill:

| Term | Matches |
|---|---|
| `family:<name>` | The family the peer's handshake matched: `core`, `btcd`, `bcoin`, `libbitcoin`, `floresta`, `rbitcoin`, `satd`, `bitcoin-seeder`, `bitnodes`, or `non-core` for any family but Core's. Knots and other Core forks are in Core's family. A peer whose handshake matched nothing matches no `family:` term. |
| `ua:<glob>` | The claimed user agent, `*` and `?` wildcards, case-sensitive, subject to `-altuatrust`. |
| `svc:<name>` | An advertised service: `network`, `bloom`, `witness`, `compact_filters`, `network_limited`, `p2p_v2`, `intact_blocks`, `nap` (`getpeerinfo`'s `servicesnames`, in lower case). |

```
altslots=6
altprefer=family:btcd@2
altprefer=family:floresta+svc:compact_filters@2
altprefer=ua:/Satoshi:*Knots:*@1
altprefer=family:non-core
```

With `-altslots` above 0 and no `-altprefer`, the one rule is
`family:non-core`. An unknown term, family or service is a startup error.

### How far a user agent is trusted

A `ua:` term never rests on the user agent alone. Each candidate is
**verified** (its handshake matched the family its agent names; a Knots
agent with a Core-family handshake is verified), **unverified** (its
handshake matched nothing the table knows, or its agent names no known
family) or **contradicted** (its handshake matched another family; the peer
carries the `F` flag). `-altuatrust`:

- `strict`: `ua:` terms match verified candidates only.
- `consistent` (default): verified and unverified match; verified ones are
  tried first.
- `any`: the agent alone decides, contradicted candidates included. Meant
  for a client the fingerprint table does not know yet. It is the easiest
  rule to game.

Under `strict` and `consistent`, a peer carrying `C`, `S` or `F` never
fills an alt-slot, whatever the rule.

### Filling the slots

Ordinary dials leave the alt-slots empty. Each reconnect pass (every 10
seconds) may dial one **trial**: an address whose survey record matches a
rule with a slot left (with `-peersurvey`; without it, the results of
earlier trials, kept in memory), or else an address-book entry, drawn as
any automatic dial is, whose recorded services can meet such a rule. Once
the trial's handshake has settled (at most about 15 seconds), it takes the
slot under the first rule it matches, with one `net` log line naming the
rule; otherwise it is disconnected (`alt-slot-no-match`), its address is
passed over by trials for 24 hours, and the next trial waits 30 seconds, as
it does when no candidate is found. One trial at a time. Every alt-slot dial obeys the same
network-group rule as every other outbound.

A slot still empty after `-altfillwait` seconds (600) gets an ordinary
**fallback** peer, so the node keeps all its outbounds even when no
matching peer is reachable. Trials go on; when one matches, it takes the
slot and the fallback is disconnected (`alt-slot-fallback-replaced`). A
fallback that turns out to match takes the slot itself.

### The full-relay outbound count

`-maxoutboundfullrelay=<n>` (default 8, Core's
`MAX_OUTBOUND_FULL_RELAY_CONNECTIONS`) sets how many full-relay outbound
peers the node keeps once synced; alt-slots are carved out of it. Core has
no such option. Every extra outbound takes an inbound slot on another
node, and Core holds everyone at 8 partly so the network does not run out
of them:

- above 8: a warning at startup and on reload;
- above 16: a startup error, and a refused reload, unless
  `-enable-dangerously-large-outbound-peer-limit` is also set;
- above 64: always an error, even with the override.

It also sizes the automatic outbound connections (full-relay, 2
block-relay-only, 1 feeler), so the inbound slots are `-maxconnections`
less that. During initial block download the full-relay target stays at
64. `-altslots` above `-maxoutboundfullrelay`, or above `-maxconnections`,
is a startup error.

### Reload

All six options reload on SIGHUP. A value past its limits refuses the
whole reload, with the running values kept. Raising `-altslots` fills the
new slots from the next pass; when every full-relay slot is taken, a match
pushes the count one over and the usual surplus rule then drops an ordinary
peer. Lowering `-altslots`, or a rule change that a peer no longer matches,
turns the peer into an ordinary outbound without disconnecting it
(fallbacks first). Lowering `-maxoutboundfullrelay` sheds the surplus one
peer at a time, as after initial block download, never a peer that holds an
alt-slot by its rules.

### Visibility

- `getpeerbehavior` gives each alt-slot peer
  `"alt_slot": {"rule": "family:btcd@2", "trust": "verified", "fallback": false}`;
  a fallback has `"rule": null, "trust": null, "fallback": true`. A trial
  still being judged has none.
- `getpeersurvey` reports `"alt_slots": {"configured", "matched",
  "fallback", "empty"}`, with the survey on or off.
- `satd_peer_alt_slots{state="matched|fallback|empty"}`, with `-altslots`
  above 0. No addresses.
- `sat-tui` tags alt-slot peers `alt` (`alt*` for a fallback) in the Flags
  column, names the rule and trust in the detail overlay, and Peer clients
  counts them.
