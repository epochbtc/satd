# Network Crawl

**Off by default.** With `-crawl=1` the node walks the reachable Bitcoin
network, the way public node counters do: it starts from seeds, asks each
reachable node for the addresses it knows (`getaddr`), dials what they
name, and records which addresses complete a handshake, over which
transport, and which implementation each one runs. It counts the network
rather than sampling it, which the [network survey](peer-behavior.md#network-survey)
(one connection a minute from the node's own address book) cannot do.

> **Read [Risks to the operator](#risks-to-the-operator) before turning it
> on.** The crawl dials tens of thousands of addresses a day from this
> host's IP address (or `-crawlbind`'s). Other operators' monitors will
> record that address as a crawler, it can end up on ban lists that then
> refuse the node's own connections too, and hosting providers may receive
> abuse reports. **Run it on a dedicated host**, not from home and not from
> the address of a node whose connectivity matters. The node logs this
> once at startup and never refuses to crawl.
>
> **The crawl's book holds raw peer addresses**, including the clearnet IP
> addresses of home nodes, which are personal data in some jurisdictions.
> See [What it stores](#what-it-stores).

## What a crawl does

### Seeding

When the crawl starts, and every hour after, it takes in:

- the DNS seeds for the chain, unless `-dnsseed=0` or `-dns=0`; under a
  proxy nothing is looked up locally and the onion seeds are used, as the
  node's own seeding does;
- the fixed seeds, unless `-fixedseeds=0`;
- a uniform sample of 1,000 entries of the node's address book, read only;
- every `-crawlseed` address;
- every address already in its book.

### Sessions

Each session is one short connection to one address. Three kinds:

| Session | When | What it does |
|---|---|---|
| Discovery | First contact, then once a day per address | The handshake, one `getaddr` with a wait of up to 90 seconds for the answer, then (with `-crawlprobes`) the four survey probes. |
| Liveness | Every `-crawlliveness` seconds (2 hours) after the last handshake | The handshake, then close once it settles (under 15 seconds). |
| v1 recheck | For an address that did BIP 324: on first contact, then weekly | A v1-only handshake, to tell a node that only speaks BIP 324 from one that speaks both. |

`getaddr` is sent once a day because a Bitcoin Core node answers it from a
cache that lives about a day: asking sooner learns nothing new. An address
that completes no handshake is retried after 1 hour, 4 hours, 24 hours, then
daily, and is dropped after 30 days of failures in which no node named it
again.

Every session declares itself as a crawler. Its `version` carries protocol
70016, services 0, `relay` off, the node's real tip height, a fresh random
nonce (never the node's own), a dummy `addr_from`, and the user agent
`/satd:<version>(crawler)/`, with `-crawluacomment` added as a second
comment. Then `wtxidrelay`, `sendaddrv2` and `verack`, and nothing else
unsolicited. The node's own `-uacomment`, listen address, onion and
`-externalip` never appear. A crawl session answers `ping` with `pong`,
gives a `getaddr` sent to it nothing, and ignores everything else.

BIP 324 is tried first. A node that refuses it as a v1-only node does
(closing, or never answering, with nothing sent back) is redialled over v1,
as Bitcoin Core does. A node that did BIP 324 and then fails the v1 recheck
within the liveness window is counted **v2-only**, a class v1-only crawlers
cannot see.

Every message a crawl sends was checked against Bitcoin Core v32.1 for no
misbehaviour score and no disconnect: a correct handshake, one `getaddr`
per connection, the vetted probes, and never an unsolicited `addr`.

### What enters the book

From each `getaddr` answer: at most 1,000 entries are considered (a larger
answer is dropped whole) and at most 500 new addresses admitted. An entry
is ignored when its time is older than `-crawlmaxage` (5 days) or more than
10 minutes ahead, when its address is private, reserved, multicast or
otherwise not public, or when its port is one Bitcoin Core's automatic
dials avoid. A new address is admitted only while the book holds fewer
than one address in its IPv6 `/64`, or fewer than 8 in its IPv4 `/24`. An
address only one node ever named is dialled after the others, so one node
flooding its answers cannot set the crawl's agenda. The book holds at most
250,000 addresses; past that the least recently named or reached go first.

## Options

All are read at startup only (`-crawl` and every `-crawl*` option is
restart-only).

| Option | Default | What |
|---|---|---|
| `-crawl` | off | Turn the crawl on. Supersedes `-peersurvey`. |
| `-crawlconcurrency` | 32 | Clearnet sessions open at once, 1 to 256. |
| `-crawltorconcurrency` | 8 | Onion sessions open at once, 1 to 256. |
| `-crawlrate` | 10 | New sessions a second, all networks, 1 to 100. |
| `-crawlliveness` | 7200 | Seconds between liveness checks of a reachable address; at least 7200. Also the window an address counts as reachable in. |
| `-crawlmaxage` | 432000 | Seconds past which an entry of a `getaddr` answer is ignored; at least 3600. |
| `-crawlnet` | every network the node reaches | `ipv4`, `ipv6`, `onion` (repeatable or comma-separated). Narrows only. `i2p` and `cjdns` are refused. |
| `-crawlbind` | none | The source address of direct crawl dials: at most one IPv4 and one IPv6 (repeatable). |
| `-crawlseed` | none | An IP address or onion to start from, at the network's port unless one is given (repeatable). No names. |
| `-crawluacomment` | none | A comment for the crawler's user agent: `/satd:<version>(crawler; <comment>)/`. Use one that tells other operators who runs the crawl. |
| `-crawlprobes` | on | Send the four [survey probes](peer-behavior.md#probes) on each discovery session. |
| `-crawlexportkeyfile` | `crawlexport.key` | The key a keyed `dumpcrawlsnapshot` computes node IDs under: a 32-byte file, relative paths under the network's data directory. See [Snapshots and export](#snapshots-and-export). |
| `-crawlexportmink` | 10 | In a keyed export, an autonomous system with fewer nodes than this is `"other"`; 1 to 100000. |

The limits hold whatever the options say: no option lifts concurrency past
256 or the rate past 100 a second. On top of them, the crawl never opens
two sessions to one address at a time, nor more than two to one IPv4 `/16`
or IPv6 `/32`. A target sees at most 14 sessions a day at the default
liveness interval. At startup the crawl's sessions are fitted into the
file-descriptor limit after `-maxconnections`: a limit too tight lowers the
crawl's concurrency, with a line in the log, and never `-maxconnections`.
`getcrawlinfo` reports the limits in force.

## How it stays apart from the node

- **Its own connections.** A crawl session is outside every connection
  budget: it takes no connection slot and no grant, and it
  is never in `getpeerinfo`, `getconnectioncount`, `getpeerbehavior`,
  eviction or the behaviour flags. No block, transaction or address is ever
  relayed over it.
- **Its own book.** The crawl reads the address book to seed itself and
  never writes it: no address is added, promoted, or marked tried or
  attempted, and no service is updated. `peers.dat` is the same before and
  after a crawl. What the crawl learns is never relayed, never served on
  `getaddr`, and never given to the node's own dialer, the alt-slots or the
  extra-network peer, so the crawl cannot steer whom the node connects to.
- **Its own traffic counts.** Crawl bytes are counted apart from
  `getnettotals` and `satd_net_bytes_*` (`getcrawlinfo`'s `totals`,
  `satd_crawl_bytes_*`).
- **Its own identity.** A fresh nonce per session, the dummy `addr_from`,
  the crawler user agent; the node's own connections send exactly what they
  sent before.
- **Failure.** A panic in a crawl task stops the crawl, with an error in
  the log; the node keeps running. `getcrawlinfo` then says
  `"state": "stopped"`.
- **When it holds.** No session starts while the node is in initial block
  download (the crawl states a real tip, and initial block download needs
  the bandwidth), under `-connect`, or with networking off.

With the crawl on, the network survey opens no connection: the crawl
measures everything the survey would, from more addresses. `getpeersurvey`
still reports the survey's store and says `"superseded_by_crawl": true`.

## Networks

The crawl dials only what the node's own dialer may: `-onlynet`, `-proxy`,
`-onion` and `-noproxy` apply exactly as they do to the node's
connections, and `-crawlnet` can narrow that further, never widen it.
Clearnet is never crawled through the proxy, since that would put crawl
volume on Tor exit operators. **A Tor-only node crawls onions only**: it
does not dial clearnet for the crawl, because that is the IP address its
operator chose to hide.

Each onion dial gets SOCKS credentials of its own, whatever
`-proxyrandomize` says, so no crawl circuit is shared with another or with
the node's own peers.

I2P and CJDNS addresses that nodes name are recorded and counted as
learned, and never dialled: satd has no transport for either.

### Tuning Tor for a crawl

A Tor daemon that carries onion crawl sessions builds a circuit for every
one. With a `-crawltorconcurrency` above the defaults, raise Tor's limits to
match, or circuits queue and onion sessions time out:

- `MaxClientCircuitsPending` (default 32) above `-crawltorconcurrency`;
- the Tor process's open-file limit (`ulimit -n`, or the service manager's
  file limit), since each session holds a socket on Tor's side too.

A Tor daemon of its own for the crawl keeps its circuit load off the one
the node's own onion connections use.

## What it stores

`crawlbook.dat`, in the network's data directory, holds one entry per
address: when it was learned and last named, how many distinct nodes named
it, the services it was advertised with, its dialling state (attempts,
failures, backoff, the next session of each kind), its transport results
(BIP 324, v1, v2-only), how often and since when it has been reachable, and
what its last completed handshake showed: implementation family, sanitized
user agent, protocol version, services, autonomous system (with `-asmap`),
probe outcomes, height and its gap to the node's tip, clock offset,
handshake round trip, and the size and delay of its `getaddr` answer.

It is written every 10 minutes and at shutdown, and read at startup. A file
that does not read is renamed with a `.bad-<unix time>` suffix, with a
warning, and the crawl starts empty. On mainnet the file is around 25 MB and
the book about 50 MB in memory at its 250,000-entry cap.

**It holds raw IP addresses.** It is written with the data directory's
permissions, execute bits dropped, and only the authenticated RPC reads it
back (`getcrawlnodes`). Retention is bounded: an address that fails for 30
days and that no node names in that time is dropped, and the book's size is
capped.

The hourly snapshots in `crawl/` hold raw IP addresses too; see
[Snapshots and export](#snapshots-and-export).

## Privacy

Nothing leaves the node by default. The data stays in the data directory,
behind the RPC's authentication:

- `getcrawlinfo`, the metrics and the status page carry counts only: never
  an address, never a user agent.
- `getcrawlnodes` returns raw addresses. It is operator control: refused on
  the read-only listener, and a bearer token needs `rpc:write` for it.
- `dumpcrawlsnapshot` exports the reachable set keyed by default: no
  clearnet address and no port number in it. Only `raw=true` gives
  addresses. Both forms are operator control.

Treat `crawlbook.dat`, the snapshots in `crawl/`, `getcrawlnodes` and
`dumpcrawlsnapshot raw=true` output, and any copy of them, as personal data
where clearnet IP addresses of home nodes are.

## Risks to the operator

- **Ban lists.** Crawler addresses end up on published ban lists and in
  operators' own bans. If the crawl shares the node's address, the node's
  own outbound connections to those operators fail too. Use `-crawlbind`
  with a second address, or a dedicated host.
- **Being flagged.** Expected: the crawl declares itself, and monitors that
  watch for many short connections, `getaddr` and no block requests (satd's
  own `C` flag among them) will flag it. An implementation that disconnects
  crawlers shows up as a node the crawl cannot reach; the counts carry that
  bias, as every declared crawler's do.
- **ISP and hosting complaints.** Tens of thousands of outbound connections
  to port 8333 a day can look like scanning to an intrusion detection
  system. Home routers are not at risk at the default concurrency, but
  residential ISPs and hosting providers may send complaints.
- **Bandwidth.** About 1 to 2 GB a day on mainnet: roughly 30 KB per
  `getaddr` answer from each reachable node, plus about 2 KB per liveness
  handshake.
- **Disk and memory.** Bounded as above.

## `getcrawlinfo`

`getcrawlinfo` returns the crawl's state and its aggregate. Counts only.

```json
{
  "enabled": true,
  "state": "running",
  "held_by": [],
  "stopped_by": null,
  "started": true,
  "peersurvey_superseded": false,
  "limits": {"concurrency": 32, "tor_concurrency": 8, "rate": 10,
             "liveness": 7200, "max_age": 432000, "probes": true,
             "networks": ["ipv4", "ipv6", "onion"], "bind": false},
  "book": {"entries": 61234, "max_entries": 250000,
           "learned": {"ipv4": 41000, "ipv6": 9000, "onion": 11000, "i2p": 200, "cjdns": 34},
           "ever_reached": {"ipv4": 14000, "ipv6": 3100, "onion": 6400, "i2p": 0, "cjdns": 0}},
  "reachable": {"total": 21000, "ipv4": 12500, "ipv6": 2600, "onion": 5900},
  "transport": {"v2_and_v1": {"count": 9000, "share": 0.4286},
                "v1_only": {"count": 11500, "share": 0.5476},
                "v2_only": {"count": 40, "share": 0.0019},
                "v2_unconfirmed": {"count": 460, "share": 0.0219},
                "v2_advertised": {"count": 9400, "share": 0.4476}},
  "families": {"core": {"count": 20100, "share": 0.9571}, "...": "...",
               "unknown": {"count": 500, "share": 0.0238}},
  "mismatches": 12,
  "sessions": {"reached": 50213, "unreached": 140022,
               "in_flight": {"clearnet": 31, "tor": 8}},
  "totals": {"totalbytessent": 81234567, "totalbytesrecv": 912345678}
}
```

| Field | What |
|---|---|
| `enabled` | Whether the crawl is on. Off, `state` is `off` and every count is zero. |
| `state` | `running`, `held` (no session may start; `held_by` says why) or `stopped` (after a panic in a crawl task; `stopped_by` is `panic`). |
| `held_by` | Every reason sessions are held: `initial_block_download`, `connect` (`-connect`), `network_inactive` (networking off). |
| `started` | The crawl has left its initial-block-download hold at least once this run. |
| `peersurvey_superseded` | `-peersurvey` was asked for too; the survey opens no connection. |
| `limits` | The limits in force: after the ceilings and the file-descriptor fitting. `networks` are those the crawl dials; `bind` whether `-crawlbind` is set (not the address). |
| `book` | Entries in the book and its cap; entries per network, and those ever reached. I2P and CJDNS are learned only. |
| `reachable` | Addresses whose last completed handshake is within the liveness window, per dialled network. This is the crawl's count of the reachable network. |
| `transport` | The reachable addresses in four classes that add up to `reachable.total`: `v2_and_v1`, `v1_only`, `v2_only` (a v1 attempt failed within the liveness window of a BIP 324 success), `v2_unconfirmed` (BIP 324 worked, v1 not checked yet). `v2_advertised` counts those advertised with `NODE_P2P_V2`. Shares are of `reachable.total`. |
| `families` | The reachable addresses per implementation family their handshake matched (a mismatch counts under the family observed), and `unknown`. |
| `mismatches` | Reachable addresses whose user agent names one family and handshake another. |
| `sessions` | Sessions since start that completed a handshake (`reached`) or did not (`unreached`), and those open now. |
| `totals` | The crawl's own bytes, as `getnettotals` names them; not counted there. |

It is a read: allowed on the read-only listener and to an `rpc:read` token.

## `getcrawlnodes [verbose]`

`getcrawlnodes` returns one row per address in the book, the most recently
reached first. **Its output holds raw peer addresses**: it is refused on
the read-only listener, and for a bearer token it needs `rpc:write`.

Without `verbose`, each row is:

| Field | What |
|---|---|
| `addr` | The address: `ip:port`, `[ipv6]:port`, `<host>.onion:port`, `<base32>.b32.i2p:port`. |
| `network` | `ipv4`, `ipv6`, `onion`, `i2p` or `cjdns`. |
| `reachable` | A handshake within the liveness window. |
| `last_success` | The last completed handshake, Unix seconds; null if never. |
| `transport` | Its transport class, as in `getcrawlinfo`; null if never reached. |
| `family` | The implementation family its last handshake matched; null if none. |

`getcrawlnodes true` adds every field of the entry: `dialable`,
`first_learned`, `last_named`, `sources` (distinct nodes that named it, at
most 16), `advertised_services`, `v2_advertised`, `best_time` (the newest
time any answer gave it), `attempts`, `last_attempt`, `last_discovery`,
`last_v1_check`, `failures`, `failing_since`, `retry_at`, `in_flight`,
`v2_ok`, `v1_ok`, `v2_only`, `reachable_count`, `first_reachable`, and
`observation`, the last completed handshake: `time`, `fingerprint`,
`family`, `claimed`, `mismatch`, `subver` (sanitized peer text), `version`,
`services`, `v2`, `asn`, `height`, `height_gap` (the node's tip less the
peer's height), `chain_check`, `clock_offset` (seconds), `handshake_rtt_ms`,
`getaddr` (`answered` with `entries` and `delay_ms`, or `no_answer`) and
`probes` as in `getpeersurvey`.

## Snapshots and export

A **snapshot** is the crawl's reachable set: every address with a completed
handshake within the liveness window (`-crawlliveness`, 2 hours). It is the
same set `getcrawlinfo` counts under `reachable`.

### Hourly snapshots

Once an hour the crawl writes a snapshot to `crawl/<unix time>.jsonl.gz` in
the network's data directory: gzip-compressed JSON lines, one line per
reachable node, with raw addresses:

```json
{"timestamp": 1790006400, "latest_height": 900002, "addr": "203.0.113.7:8333", "node": [70016, "/Satoshi:32.1.0/", null, 3081, 900000, null, null, null, null, null, null, "AS64496", null, {"network": "ipv4", "...": "..."}]}
```

`node` is the node as a raw `dumpcrawlsnapshot` lists it. Read one with
`zcat crawl/<time>.jsonl.gz`.

Each write prunes the directory: every snapshot of the last 7 days is
kept, of older ones only the first of each UTC day, and none older than 90
days. On mainnet a snapshot is around 1 MB compressed, so about 170 MB of
hourly and 90 MB of daily snapshots. A restart within the hour writes no
second snapshot for it. Files in `crawl/` other than snapshots are left
alone.

**The snapshots hold raw IP addresses.** `crawl/` is created with the data
directory's permissions, and each snapshot is written as `crawlbook.dat` is
(the directory's permissions, execute bits dropped: 0600 under a 0700 data
directory). Nothing reads them back over RPC.

### `dumpcrawlsnapshot [raw]`

`dumpcrawlsnapshot` returns the reachable set now, shaped as a Bitnodes
snapshot, so tools that read those read this:

```json
{
  "timestamp": 1790006412,
  "total_nodes": 21000,
  "latest_height": 900002,
  "nodes": {
    "adccb55f12feb805aab99ac4145f6109": [70016, "/Satoshi:32.1.0/", null, 3081, 900000,
      null, null, null, null, null, null, "AS64496", null,
      {"network": "ipv4", "port": "default", "transport": "v2_and_v1",
       "v2_advertised": true, "family": "core", "confidence": "high",
       "mismatch": false, "chain_check": null, "last_seen": 1790005980}],
    "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion": ["..."]
  },
  "satd": {"export": "keyed", "chain": "main", "liveness": 7200,
           "learned_not_dialled": {"i2p": 200, "cjdns": 34},
           "node_id": "hmac-sha256-128", "asn_min_count": 10}
}
```

| Field | What |
|---|---|
| `timestamp` | When the snapshot was taken, Unix seconds. |
| `total_nodes` | Nodes in `nodes`. |
| `latest_height` | This node's tip height. |
| `nodes` | One entry per reachable node: keyed by node ID (or onion), or with `raw=true` by address. |
| `satd` | `export` (`keyed` or `raw`), `chain`, `liveness` (the window, seconds), `learned_not_dialled` (I2P and CJDNS addresses learned: the crawl never dials them, so they are counts only); keyed, `node_id` (how IDs are made) and `asn_min_count`. |

Each node is Bitnodes' thirteen fields, then a `satd` object:

| # | Bitnodes field | Here |
|---|---|---|
| 0 | protocol version | from its `version` |
| 1 | user agent | sanitized, as `getpeerinfo`'s `subver` |
| 2 | connected since | null: the crawl holds no long-lived connection to measure it |
| 3 | services | from its `version` |
| 4 | height | its `start_height` |
| 5 | hostname | null: no reverse lookup |
| 6–10 | city, country, latitude, longitude, timezone | null: no geolocation |
| 11 | ASN | `AS<n>` from `-asmap`; null without one |
| 12 | organization | null |
| 13 | `satd` | `network` (`ipv4`, `ipv6`, `onion`), `port` (`default` or `other`), `transport` (as in `getcrawlinfo`), `v2_advertised`, `family`, `confidence` (`high` or `low`; null unless the family is known), `mismatch`, `chain_check`, `last_seen` (its last completed handshake) |

**Keyed, the default.** A clearnet node is listed by its node ID:
HMAC-SHA256 under the export key of its address as `ip:port` (an IPv6
address as `[ipv6]:port`, an IPv4-mapped one as IPv4), the first 16 bytes
in hex. 128 bits leave no realistic chance of two nodes sharing an ID over
years of snapshots. The same key gives a node the same ID in every export,
so its history can be followed; without the key, an ID cannot be tested
against a guessed address, as a plain hash could across the whole IPv4
space. And in a keyed export:

- onion addresses are listed as they are (the host, with `:port` added
  only when it is not the network's port, so one onion's two services are
  two nodes), since their operators publish them to be dialled and they say
  nothing about location;
- I2P and CJDNS addresses appear only as counts;
- the port is only `default` or `other`;
- an ASN with fewer than `-crawlexportmink` (10) nodes in the export is
  `"other"`, since a lone node on a small network is otherwise nearly
  identified;
- the user agent and height are given per node.

**The key** is `crawlexport.key` in the network's data directory: 32
random bytes, created with mode 0600 by the first keyed export, and read as
it stands by every export after. `-crawlexportkeyfile` names another file
instead, which satd reads and never creates: a census operator who merges
several crawlers' exports gives them one key that way. satd never rotates
the key. Rotating is replacing the file: IDs from the next export on differ
from all earlier ones, which protects later exports if the key leaked and
breaks the per-node history. **If the key leaks, every ID exported under it
can be reversed**: keep it off any host that publishes the export.

**`raw=true`** lists every node by its address and gives every ASN as it
is. It holds raw IP addresses.

`dumpcrawlsnapshot` is operator control, keyed or raw: refused on the
read-only listener, and a bearer token needs `rpc:write`. A keyed export is
the act of publishing the crawl and creates the key on first use, so a
read-only token gets neither form. With the crawl off, or a key file that
is missing or not 32 bytes, it returns an error.

## Metrics and the status page

- `satd_crawl_enabled`: 1 while the crawl is on; `satd_crawl_running`, 1
  while sessions may start; `satd_crawl_stopped`, 1 after a panic.
- `satd_crawl_book_entries{network}`: the book per network.
- `satd_crawl_reachable{network}`, `satd_crawl_transport{class}`,
  `satd_crawl_v2_advertised`, `satd_crawl_family{family}` and
  `satd_crawl_mismatches`: the reachable addresses, as `getcrawlinfo`
  counts them.
- `satd_crawl_sessions_total{result}` (`reached`, `unreached`) and
  `satd_crawl_sessions_in_flight{network}` (`clearnet`, `tor`).
- `satd_crawl_bytes_sent_total` and `satd_crawl_bytes_recv_total`: the
  crawl's traffic, not in `satd_net_bytes_*`.

The [status page](observability.md#status-page) shows a Crawl card with the crawl on:
its state, the book's size, reachable addresses per network, I2P and CJDNS
learned, and the transport classes. None of these, nor the metrics, carries
an address. The metrics and the status page reuse an aggregate for up to 10
seconds, so a full book is not walked on every scrape; `getcrawlinfo` reuses
one for up to a second, so a client polling it cannot keep the crawl's
sessions waiting on the book.
