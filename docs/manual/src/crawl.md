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
> host's IP address (or `-crawlbind`'s, or with `-crawlproxy` the proxy
> host's). Other operators' monitors will
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

BIP 324 is tried first only to a node known to advertise it
(`NODE_P2P_V2`), as Bitcoin Core does for its own outbound connections:
after a handshake, by the services in the node's own last `version`;
before one, by the services its address was last advertised with in a
`getaddr` answer or the address book. A seed (`-crawlseed`, a fixed seed, a
DNS seed) carries no services, so it is dialled over v1 until a handshake
or an answer naming it says otherwise. Every other address is dialled over
v1, with no BIP 324 bytes sent: some v1-only implementations close on
them, and one bans the dialling address. A node that speaks BIP 324 without
advertising it is therefore counted as v1 (`v1_v2_untried`).

A node dialled over BIP 324 that refuses it as a v1-only node does
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

### How it tells implementations apart

Each session with a completed handshake is judged against the crawl's own
rows, one or two per implementation family, measured by greeting each
client as the crawl does. A row names the traits that set its family
apart, not the whole transcript of one release, and each was checked
against captures of two or more releases:

| Family | Traits | Releases captured |
|---|---|---|
| Bitcoin Core (Knots included) | `wtxidrelay` and `sendaddrv2` before `verack`; then `sendcmpct`, with no `feefilter` or `sendheaders` before its next message | Core 24.0.1, 28.1, 31.1, 32.1; Knots 28.1, 29.5.1 |
| satd | the same negotiation; then `sendcmpct` and `feefilter` before its next message (0.8), or `getheaders` straight after `verack` (0.6, 0.7) | 0.6.3, 0.7.2, the 0.8 development tree |
| rbitcoin | the same negotiation, then `sendheaders`; BIP 324 only | 0.8.0, a 0.8.99 development build, 0.9.2 |
| btcd | `sendaddrv2` with no `wtxidrelay`; v1 only | 0.24.2, 0.25.0, 0.27.0 |
| bcoin | protocol 70015, its own `addr` straight after `verack`; v1 only | 2.0.0, 2.1.2, 2.2.0 |
| libbitcoin | protocol 70013, `relay` off, nothing negotiated, its own `ping` straight after `verack`; v1 only | 3.6.0, 3.8.0 |

A row also holds what none of its captures contradicted: no BIP 324 decoy
packet or version-packet contents, the probe answers (`notfound` for the
unknown transaction from all but Core, which answers it only when its
operator grants the crawler relay; silence for the unknown message; never a
disconnect) and an `addrv2` answer to `getaddr`.

The result is `high` when the session matches one family's row, `low` when
only the `version` fields told two families' rows apart, and a
**mismatch** when the user agent names another family than the one
matched. When no row matches, the family the user agent names is reported
with confidence **`claimed`**: a release whose shape no capture has, or a
node that closed on a probe. A claimed family is never counted as
observed: `getcrawlinfo`, the metrics and the export count it under
`claimed`, apart from both its family and `unknown`. It is never a
mismatch. A user agent that names no family is `unknown`. Every session
no row matched keeps its transcript, `relay` flag, BIP 324 greeting and
`getaddr` message in the book, so a new implementation or release shows
up as many records of one shape before it has a row.

Two kinds of session say nothing about the implementation, and are
counted apart from every family, claim and `unknown`:

- **Closed early.** The peer closed the connection during the passive
  wait, before its handshake transcript settled. The node is reached (it
  sent its `version` and `verack`) and counted as reachable, by network
  and by transport, with what its `version` said, but it has no
  fingerprint. These are mostly ordinary Core nodes with full inbound
  slots: on a new inbound connection Core evicts one, the youngest member
  of its largest network group, and a crawl connection seconds old is
  often that one. On a synced mainnet node, the survey's records showed
  105 such Core nodes. The same address, dialled again, may settle, so it
  is retried (below).
- **Fake.** The user agent names Core, the common protocol version is
  70016 or more, the transcript is exactly `version`, `verack` (no
  negotiation message between them, nothing after), and the passive wait
  ran out with the connection still open. Every Core release since 0.21
  sends `wtxidrelay` and `sendaddrv2` before `verack` at that version and
  a message within the wait, so no Core node produces this session; on a
  synced mainnet node 74 nodes claiming `/Satoshi:25.x/` did. It is
  counted under `fake`, by the family it claims. Only Core has the rule,
  as the survey's, since the evidence is Core's alone.

Neither changes how the crawl dials the node or its transport class: the
session is recorded as any session that completed a handshake is.

A closed-early address with no settled observation is retried: after its
closed-early session a liveness session is due 15 minutes later, and after
each further closed-early session (or a retry that completed no
handshake) the next is due after 30 minutes, 1 hour, 2 hours, then 4 hours
for every later one, each wait moved at random by up to a fifth either way.
A retry only brings the address's next session forward, ahead of its
liveness check (a discovery still comes first once one is due); it goes
through the same limits, network rules and BIP 324 rule as every session.
A failing address's unreachable backoff still comes first. After ten
retries none is scheduled: the address waits for its next ordinary
session, and a closed-early session then does not start the retries over.
The first session that settles (a fingerprint, or fake) clears the
schedule.

A closed-early session never replaces a settled observation. An address
whose last observation has a fingerprint (at any confidence, claimed
included) or is fake keeps that observation whole; the session still
counts as reached and updates the reachability, transport results and
timers, and no retry is scheduled. A fake session still replaces a
classified observation, and a settled session replaces any.

Connected peers and the network survey are judged the same way against
rows of their own, captured against an ordinary node's `version`: a
session no row matches is `claimed` there too (see
[Peer Behaviour Flags](peer-behavior.md#what-is-judged)).

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
| `-crawlbind` | none | The source address of direct crawl dials: at most one IPv4 and one IPv6 (repeatable). Not applied to dials through `-crawlproxy`. |
| `-crawlproxy` | none | A SOCKS5 proxy (no authentication), as an IP address and port, that every IPv4 and IPv6 crawl dial goes through, so they leave from the proxy's host. Clearnet is crawled through it under `-proxy` too; onion dials and the node's own connections never use it. No direct fallback. See [Crawling through a proxy](#crawling-through-a-proxy--crawlproxy). |
| `-crawlseed` | none | An IP address or onion to start from, at the network's port unless one is given (repeatable). No names. |
| `-crawluacomment` | none | A comment for the crawler's user agent: `/satd:<version>(crawler; <comment>)/`. Use one that tells other operators who runs the crawl. |
| `-crawlprobes` | on | Send the four [survey probes](peer-behavior.md#probes) on each discovery session. |
| `-crawlexportkeyfile` | `crawlexport.key` | The key a keyed `dumpcrawlsnapshot` computes node IDs under: a 32-byte file, relative paths under the network's data directory. See [Snapshots and export](#snapshots-and-export). |
| `-crawlexportmink` | 10 | In a keyed export, an autonomous system with fewer nodes than this is `"other"`; 1 to 100000. With `-countryfile`, a country with fewer nodes than this is folded into `other` in the country totals, keyed export or not. |
| `-countryfile` | none | A MaxMind DB (`.mmdb`) country file, for per-country totals in `getcrawlinfo` and the export's summary; relative paths are under the data directory. See [Country totals](#country-totals--countryfile). |

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

`-crawlproxy` changes how clearnet is dialled, never whether: see
[Crawling through a proxy](#crawling-through-a-proxy--crawlproxy).

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

### Crawling through a proxy (`-crawlproxy`)

`-crawlproxy=<ip>:<port>` sends every IPv4 and IPv6 crawl dial through a
SOCKS5 proxy, so the crawl's source address is the proxy host's and the
node stays where it is. The proxy must be one that is not a Tor exit:
`-crawlproxy` at the address of `-proxy` or `-onion` is refused at
startup (compared as addresses, so `[::ffff:127.0.0.1]:9050` matches
`127.0.0.1:9050`, and every loopback address counts as one host, so
`[::1]:9050` matches it too; a `-proxy` or `-onion` given as a host name and port is
resolved once at startup, never on a `SIGHUP` reload, and refused if any
of its addresses matches, and one that does not resolve is not refused on
that basis).

The best setup is a SOCKS5 server on the far host, bound to its
loopback, reached through an SSH tunnel:

```sh
# On the far host: a SOCKS5 server on its loopback only (microsocks, say)
microsocks -i 127.0.0.1 -p 1080
# On the node's host: forward a local port to it
ssh -N -L 127.0.0.1:1081:127.0.0.1:1080 user@crawl-host.example
```

An SSH dynamic forward (`ssh -N -D 127.0.0.1:1081 user@crawl-host.example`)
works too, but OpenSSH answers every CONNECT with success before the far
side has connected. A dead target then looks like a connection that
closed at once, which the crawl's v2-to-v1 redial rule retries over v1,
and refused and unreachable targets cannot be told apart.

```ini
crawl=1
crawlproxy=127.0.0.1:1081
```

- **The proxy host's address is the crawler.** Other operators' monitors
  and ban lists will record that address, and its hosting provider gets
  any abuse reports (see [Risks to the operator](#risks-to-the-operator)).
  The node's own address is not in the crawl's connections.
- **Only the crawl uses it.** The node's peers, `-proxy` and `-onion` are
  unchanged, and onion crawl dials still go through `-onion`/`-proxy` with
  credentials of their own. `-onlynet` and `-crawlnet` still narrow what
  is crawled; with `-crawlproxy` set clearnet is crawled under `-proxy`
  too, since the operator has named a proxy that is not a Tor exit.
- **No fallback.** With the proxy down, a clearnet dial fails and is
  counted as the proxy's failure (`getcrawlinfo`'s `proxy.failures`): it
  is never retried direct and never held against the target, whose
  reachability, retries and liveness stay as they were. The address stays
  due, proxied dials pause for 5 seconds after each failure, and the crawl
  resumes once the proxy answers. The log says so once when the proxy
  fails and once when it answers again.
- **A proxy that greets but reaches nothing** (its host's own uplink
  down) answers every CONNECT with no reply, 0x01, 0x03, 0x04 or 0x06.
  After 200 such dials in a row, with no success and no refusal (0x05)
  between them, the crawl takes the proxy as down, as above; while it is
  down such a dial is the proxy's, and a success or a refusal ends the
  outage. 0x02 (not allowed by ruleset) comes from the proxy's own policy
  without asking the target, so it counts toward the 200 too. At most 199 dials of such an outage are recorded against
  their targets before it is seen.
- **Proxy or target.** A failure to reach the proxy, a failed SOCKS5
  greeting, or a CONNECT the proxy cannot serve (reply 0x07 command not
  supported, 0x08 address type not supported, or an unassigned code) is
  the proxy's. A reply the proxy gives for the target (0x01 general
  failure, 0x02 not allowed by ruleset, 0x03 network unreachable, 0x04
  host unreachable, 0x05 refused, 0x06 TTL expired), no reply in time, or
  the proxy closing instead of replying, is the target's, as a failed
  direct dial is (see the SSH dynamic forward note above). A request the
  proxy does not take in time is the proxy's. A proxy host without IPv6
  answers IPv6 CONNECTs with 0x08 or 0x04: add `-crawlnet=ipv4`.
- `-crawlbind` does not apply to proxied dials, and a proxied session's
  `version` names the dummy address as the receiver, as an onion dial's
  does. DNS seeding is unchanged: under `-proxy` the onion seeds, else a
  local lookup.
- The value is an IP address and port (`127.0.0.1:1081`, `[::1]:1081`),
  never a host name and never an unspecified address (`0.0.0.0`, `[::]`);
  anything else is refused at startup.

## What it stores

`crawlbook.dat`, in the network's data directory, holds one entry per
address: when it was learned and last named, how many distinct nodes named
it, the services it was advertised with, its dialling state (attempts,
failures, backoff, the next session of each kind), its transport results
(BIP 324, v1, v2-only), how often and since when it has been reachable, and
what its last completed handshake showed: implementation family, sanitized
user agent, protocol version, services, autonomous system (with `-asmap`),
probe outcomes, height and its gap to the node's tip, clock offset,
handshake round trip, the size and delay of its `getaddr` answer,
whether the session was fake or closed early and, for a closed-early
address, its retry count and next due time.

It is written every 10 minutes and at shutdown, and read at startup. A file
that does not read is renamed with a `.bad-<unix time>` suffix, with a
warning, and the crawl starts empty. The book is format version 5; a
version 4 book is read whole and keeps everything, each entry with no
retry scheduled (a closed-early address gets one after its next
closed-early session). A file written before the fake and closed-early
verdicts (book version 2 or 3) is read whole, a damaged one
still set aside, and keeps every entry with its reachability, transport
results, sources and timers; each entry's last observation is dropped and
the count logged, since neither version stored whether the peer closed
during the passive wait. Until its next session such an address counts as
reachable with no observation (under `unknown`); every reachable address
has one again within the liveness window. On mainnet the file is around 25 MB and
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

## Country totals (`-countryfile`)

With `-countryfile=<file>`, the crawl counts its reachable nodes per
country: in `getcrawlinfo` (`countries`), in the summary of
`dumpcrawlsnapshot` (`satd.countries`) and in the
`satd_crawl_country{country}` metric. The file is in the MaxMind DB
(`.mmdb`) format. Two free ones carry what it needs:

- DB-IP's **IP to Country Lite**, under the Creative Commons Attribution
  4.0 licence: published counts made with it must credit DB-IP.
- MaxMind's **GeoLite2 Country**, after creating a free account; its
  licence requires replacing the file with a newer release within 30 days
  of one being published.

A city file in the same format works too. satd reads only
`country.iso_code` from a record: never a city, a region or coordinates.

The file is resolved against the data directory as `-asmap` is, read once
at startup into memory, and fatal to startup when it is missing or does
not parse. Update it by replacing the file and restarting. Without
`-countryfile` nothing is looked up, and `countries` is `null` (not an
empty object, which would read as no nodes); the metric is not exported.

The totals' keys:

| Key | What |
|---|---|
| `DE`, `US`, ... | An ISO 3166-1 alpha-2 code, uppercase: the IPv4 and IPv6 nodes the file places there, when there are at least `-crawlexportmink` (10) of them. |
| `other` | Every country with fewer nodes than `-crawlexportmink`, added together. |
| `unknown` | IPv4 and IPv6 nodes the file has no country for. |
| `onion` | Onion nodes: an onion address says nothing about where its node is, so none is given a country. |

`other`, `unknown` and `onion` are always present, zero or not; they are
never folded. Each reachable node is counted once, so the totals add up
to `reachable.total`. The fold is the same in `getcrawlinfo`, the metrics
and both forms of the export.

**No country is given per node**, anywhere: not in `getcrawlnodes`, not in
a node of the export (Bitnodes' country field stays null) and not in the
hourly snapshots. Next to a node's autonomous system, user agent and
services, a country can single out a node in a small one. Nothing finer
than a country is read at all.

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
  "proxy": {"set": false, "failures": 0},
  "book": {"entries": 61234, "max_entries": 250000,
           "learned": {"ipv4": 41000, "ipv6": 9000, "onion": 11000, "i2p": 200, "cjdns": 34},
           "ever_reached": {"ipv4": 14000, "ipv6": 3100, "onion": 6400, "i2p": 0, "cjdns": 0}},
  "reachable": {"total": 21000, "ipv4": 12500, "ipv6": 2600, "onion": 5900},
  "transport": {"v2_and_v1": {"count": 9000, "share": 0.4286},
                "v1_only": {"count": 1500, "share": 0.0714},
                "v1_v2_untried": {"count": 10000, "share": 0.4762},
                "v2_only": {"count": 40, "share": 0.0019},
                "v2_unconfirmed": {"count": 460, "share": 0.0219},
                "v2_advertised": {"count": 9400, "share": 0.4476}},
  "families": {"core": {"count": 20000, "share": 0.9524}, "...": "...",
               "unknown": {"count": 100, "share": 0.0048}},
  "claimed": {"core": {"count": 350, "share": 0.0167}, "...": "..."},
  "fake": {"core": {"count": 140, "share": 0.0067}, "...": "..."},
  "closed_early": {"count": 100, "share": 0.0048},
  "mismatches": 12,
  "retries": {"pending": 60, "exhausted": 14},
  "countries": {"DE": {"count": 4100, "share": 0.1952},
                "US": {"count": 3900, "share": 0.1857}, "...": "...",
                "other": {"count": 310, "share": 0.0148},
                "unknown": {"count": 20, "share": 0.001},
                "onion": {"count": 5900, "share": 0.281}},
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
| `proxy` | `set`: whether `-crawlproxy` is set (never its address). `failures`: the dials it failed since start, the proxy's failures and not the targets' (see [Crawling through a proxy](#crawling-through-a-proxy--crawlproxy)). |
| `book` | Entries in the book and its cap; entries per network, and those ever reached. I2P and CJDNS are learned only. |
| `reachable` | Addresses whose last completed handshake is within the liveness window, per dialled network. This is the crawl's count of the reachable network. |
| `transport` | The reachable addresses in five classes that add up to `reachable.total`: `v2_and_v1`, `v1_only` (v1 worked and the last BIP 324 attempt failed), `v1_v2_untried` (v1 worked and BIP 324 was never tried, the node not advertising it), `v2_only` (a v1 attempt failed within the liveness window of a BIP 324 success), `v2_unconfirmed` (BIP 324 worked, v1 not checked yet). `v2_advertised` counts those whose address was last advertised with `NODE_P2P_V2` (in a `getaddr` answer or the address book), whatever their own `version` said. Shares are of `reachable.total`. |
| `families` | The reachable addresses per implementation family their handshake matched, `high` or `low` (a mismatch counts under the family observed), and `unknown`: no row matched and the user agent names no family. A family's count never includes a claim, a fake or a closed-early address. |
| `claimed` | The reachable addresses no row matched whose user agent names a family (confidence `claimed`), per family. Never in `families`. |
| `fake` | The reachable addresses whose last session was fake (a Core user agent; `version` and `verack` only, silent through the wait), per claimed family. Never in `families` or `claimed`. |
| `closed_early` | The reachable addresses whose peer closed the last session before its handshake settled: no fingerprint, in no family. Each reachable address is counted once among `families`, `claimed`, `fake` and `closed_early`. |
| `mismatches` | Reachable addresses whose user agent names one family and handshake another. |
| `retries` | Addresses in the book, reachable or not, whose last observation is closed early: with a retry scheduled (`pending`), and with none left after ten (`exhausted`). |
| `countries` | With `-countryfile`, the reachable addresses per country, each with its share of `reachable.total`: ISO codes, `other` (countries under `-crawlexportmink`), `unknown` and `onion`. See [Country totals](#country-totals--countryfile). `null` without a country file. |
| `sessions` | Sessions since start that completed a handshake (`reached`) or did not (`unreached`), and those open now. |
| `totals` | The crawl's own bytes, as `getnettotals` names them; not counted there. |

It is a read: allowed on the read-only listener and to an `rpc:read` token.
[sat-tui](tui.md#network-crawl--crawl-detail)'s Chain view draws it as
the Network crawl row.

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
| `family` | The implementation family its last handshake matched; null if none, a claimed, fake or closed-early one included. |
| `fingerprint` | The last handshake's result: `core/high`, `btcd/low`, `core/claimed`, `unknown`, `mismatch(claimed=core,observed=btcd)`, `fake/core` or `closed-early`; null if never reached or not observed since an older book was read. |
| `retry` | A closed-early row only: `count`, the retries scheduled so far, and `next_due`, when the next is due (Unix seconds; null once all ten are spent). |

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
       "v2_advertised": true, "family": "core", "fingerprint": "core/high",
       "confidence": "high", "claimed": "core", "mismatch": false,
       "chain_check": null, "last_seen": 1790005980}],
    "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion": ["..."]
  },
  "satd": {"export": "keyed", "chain": "main", "liveness": 7200,
           "learned_not_dialled": {"i2p": 200, "cjdns": 34},
           "node_id": "hmac-sha256-128", "asn_min_count": 10,
           "countries": {"DE": 4100, "US": 3900, "...": "...", "other": 310,
                         "unknown": 20, "onion": 5900},
           "country_min_count": 10}
}
```

| Field | What |
|---|---|
| `timestamp` | When the snapshot was taken, Unix seconds. |
| `total_nodes` | Nodes in `nodes`. |
| `latest_height` | This node's tip height. |
| `nodes` | One entry per reachable node: keyed by node ID (or onion), or with `raw=true` by address. |
| `satd` | `export` (`keyed` or `raw`), `chain`, `liveness` (the window, seconds), `learned_not_dialled` (I2P and CJDNS addresses learned: the crawl never dials them, so they are counts only); keyed, `node_id` (how IDs are made) and `asn_min_count`; `countries`, the nodes per country under `-countryfile` (null without one; folded below `-crawlexportmink` in both forms, as in `getcrawlinfo`), and with a country file `country_min_count`. |

Each node is Bitnodes' thirteen fields, then a `satd` object:

| # | Bitnodes field | Here |
|---|---|---|
| 0 | protocol version | from its `version` |
| 1 | user agent | sanitized, as `getpeerinfo`'s `subver` |
| 2 | connected since | null: the crawl holds no long-lived connection to measure it |
| 3 | services | from its `version` |
| 4 | height | its `start_height` |
| 5 | hostname | null: no reverse lookup |
| 6–10 | city, country, latitude, longitude, timezone | null: no geolocation per node, `-countryfile` or not |
| 11 | ASN | `AS<n>` from `-asmap`; null without one |
| 12 | organization | null |
| 13 | `satd` | `network` (`ipv4`, `ipv6`, `onion`), `port` (`default` or `other`), `transport` (as in `getcrawlinfo`), `v2_advertised`, `family` (null when claimed, fake or closed early), `fingerprint` (as `getcrawlnodes` gives it: `core/high`, `core/claimed`, `fake/core`, `closed-early`, ...), `confidence` (`high`, `low` or `claimed`; null when unknown, a mismatch, fake or closed early), `claimed` (the family the user agent names, if any), `mismatch`, `chain_check`, `last_seen` (its last completed handshake) |

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
  `satd_crawl_v2_advertised`, `satd_crawl_family{family}`,
  `satd_crawl_claimed{family}`, `satd_crawl_fake{family}`,
  `satd_crawl_closed_early` and `satd_crawl_mismatches`: the reachable
  addresses, as `getcrawlinfo` counts them. Each reachable address is in
  one of the family, claimed, fake and closed-early series only:
  `satd_crawl_family{family="unknown"}` is what none of the others
  names.
- `satd_crawl_closed_early_retries`: the closed-early addresses in the
  book with a retry scheduled.
- `satd_crawl_country{country}`: with `-countryfile` only, the reachable
  addresses per country, under the keys and fold of
  [Country totals](#country-totals--countryfile).
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
