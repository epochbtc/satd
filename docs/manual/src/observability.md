# Observability & Metrics

`satd` ships three observability surfaces: a native terminal dashboard, a
Prometheus endpoint, and structured logs. None of them needs an external
exporter or a log-parsing sidecar.

## Native TUI (`sat-tui`)

`satd` ships with a native Ratatui-based terminal interface that shows node
progress in real time:

*   **IBD bitmap**: block download and verification progress.
*   **Peer stats**: connected peers, their latency, and block delivery rates.
*   **Mempool status**: live mempool depth and fee percentiles.

The full `sat-tui` reference, with every view, panel, field, and keybinding, is
in the [Terminal UI](tui.md) chapter.

## Prometheus Metrics Endpoint

The metrics and health server starts only when a port is set. Use
`--metricsport=<port>` to enable it. `--metricsbind=<addr>` sets the bind
address alone (default `127.0.0.1`) and does not enable the server on its own.
The listener binds `<metricsbind>:<metricsport>`.

The `GET /metrics` endpoint serves native Prometheus metrics covering P2P
traffic, block validation times, mempool depth, and RocksDB performance. P2P
wire volume is exported as the `satd_net_bytes_sent_total` and
`satd_net_bytes_recv_total` counters, and peer count as
`satd_peer_connections`. The `GET /healthz` and `GET /readyz` endpoints exist
for load balancer and orchestrator integration.

See the [Packaging](packaging.md#health-and-readiness) chapter for how to wire
`/healthz` and `/readyz` to Docker `HEALTHCHECK`, Kubernetes probes, or a
systemd `ExecStartPost=` poll.

For dashboards and alerting, scrape `/metrics` rather than polling RPC. The
Bitcoin Core methods `getnettotals` (byte totals) and `getpeerinfo`
(`bytessent`, `bytesrecv`, `lastsend`, `lastrecv`, and the per-message-type
breakdowns `bytessent_per_msg` / `bytesrecv_per_msg`) are populated and
accurate for steady-state traffic, but they exist for Core compatibility. The Prometheus
endpoint is a counter model built for time-series tooling (rates, retention,
labels) and does not consume an RPC worker on every scrape.

> **Note.** The RPC byte counters cover post-handshake traffic only. The
> one-time handshake bytes are not included, so absolute socket totals read
> marginally lower than the kernel's.
>
> The per-message tallies sum to `bytessent` / `bytesrecv` for the same peer
> once a message is fully accounted for. The peer total is bumped before the
> per-type tally, so a `getpeerinfo` that lands mid-message can observe the
> breakdown trailing the total by one message's bytes — during IBD, by as much
> as a block. Treat the equality as a resting invariant, not something to
> alert on. They are on-wire sizes for the transport in use, so the same
> message costs fewer bytes on a BIP 324 v2 link than on v1. Message types satd has no
> variant for, undecodable frames, and v2 decoy packets are all counted under
> `*other*`, matching Core.

### Index readiness

Each DB-backed index exports whether it is switched on, whether it is ready to
serve, and what its deferred backfill is doing. The silent-payment family:

| Metric | Meaning |
|---|---|
| `satd_spindex_enabled` | 1 if the silent-payment tweak index is enabled at runtime |
| `satd_spindex_synced` | 1 if the tweak-serving surfaces will return data — enabled, complete on disk, and no backfill in flight. Matches `getindexinfo`'s `silentpayments.synced` |
| `satd_spindex_backfill_state{state="…"}` | one series per lifecycle state, exactly one of them 1 |
| `satd_spindex_backfill_progress_ratio` | fraction of the deferred backfill walked, over `[taproot activation, snapshot]` |

The address and block-filter indexes export the same readiness shape —
`satd_addrindex_synced` / `satd_addrindex_backfill_state{state="…"}`
(alongside the existing `satd_addrindex_enabled` and row counters), and
`satd_filterindex_enabled` / `satd_filterindex_synced` /
`satd_filterindex_backfill_state{state="…"}`. `synced` matches the
corresponding `getindexinfo` predicate in each case: for the address index it
means the Electrum / Esplora address surfaces will serve; for the filter index
it means BIP 157 peers and `getblockfilter` will be served. A failed or stuck
backfill on any of the three is alertable with the same rules shown below —
substitute the family prefix.

**Do not alert on the progress ratio alone.** `0.0` is not an error signal: it
covers an index that is switched off, one built inline from a genesis sync (which
never needs a backfill and stays at `0.0` while being perfectly complete), a
backfill that has only just started, and one that failed near taproot
activation. Alert on the state series instead, which distinguishes them:

```promql
# The backfill failed.
satd_spindex_backfill_state{state="failed"} == 1
  and ignoring(state) satd_spindex_enabled == 1

# Enabled but never going to become ready on its own: no backfill was ever
# started. This is the state an existing datadir lands in when the index is
# switched on without running `backfillindex silentpayment`.
satd_spindex_backfill_state{state="idle"} == 1
  and ignoring(state) satd_spindex_enabled == 1
  and ignoring(state) satd_spindex_synced == 0

# Running, but not making progress — stuck rather than merely slow.
satd_spindex_backfill_state{state="running"} == 1
  and ignoring(state) satd_spindex_enabled == 1
  and ignoring(state) delta(satd_spindex_backfill_progress_ratio[30m]) == 0
```

Three things worth copying exactly rather than paraphrasing:

- **The `satd_spindex_enabled == 1` guard belongs on every one of them**,
  including the `failed` rule. The state series is derived from the *persisted*
  cursor, which outlives the config: switch `silentpaymentindex` back off after
  a failed backfill and the node keeps exporting
  `satd_spindex_backfill_state{state="failed"} 1` for ever, because the cursor
  stays on disk and is deliberately not auto-resumed. Without the guard that
  pages continuously for an index the operator has turned off.
- **`ignoring(state)` is required.** `and` matches on identical label sets, and
  `satd_spindex_backfill_state{state="running"} == 1` carries a `state` label
  that `satd_spindex_enabled` does not. Plain `and` finds no matching series and
  the rule silently evaluates to nothing, for ever — it will sit at "0 active"
  in the Prometheus UI, which reads as healthy.
- **`delta()`, not `rate()`.** The ratio is a gauge. `rate()` treats the drop
  back to `0.0` when a backfill restarts as a counter reset and compensates for
  it, which is not what you want here.

Give the last two a `for:` of at least an hour in the alert rule. A backfill
that has not committed its first 1000-block batch yet legitimately shows no
progress.

All seven state series are always present, so a rule can reference
`state="failed"` before it has ever fired — the same reason `satd_alert_active`
pre-registers at 0 (see [below](#node-health-alerts)).

## Node-health alerts

Metrics tell you what the node is doing; health alerts tell you when it has
stopped doing it. satd watches six conditions about *itself* and reports each
one through three surfaces at once, so they can never disagree:

*   a `status` event on the [Streaming Consumption API](streaming.md) (category
    bit 16 — see §7.8 of the wire spec),
*   an entry in `getwarnings` (and therefore in `getblockchaininfo.warnings`
    and the TUI), which also fires the Core-compatible `alertnotify` hook,
*   a `satd_alert_active{kind="..."}` gauge on `/metrics`.

**One-shot events are the exception to the middle surface.** `ibd_complete` and
`deep_reorg` describe something that *happened*; there is no state for anything
to later clear. They fire `alertnotify` and emit their `status` event, but they
do **not** create a `getwarnings` entry. An entry nothing clears would sit in
`getblockchaininfo.warnings` for the life of the process and hold the TUI's
warning modal open — which on signet and testnet4, where reorgs several blocks
deep are ordinary, would happen on the first one and never stop. The durable
record of a reorg is the reorg log (`getreorghistory`), not the warnings set.

Because they have no standing condition to dedupe against, one-shot events are
rate-limited on the `alertnotify` hook instead: **one exec per minute per event
id, reporting the worst occurrence in that window.** A run of reorgs otherwise
queues one shell exec each on a channel drained one at a time, which grows
without bound and pushes the hook further and further behind real time. Keeping
the first occurrence and counting the rest would be worse still — a depth-3
reorg would claim the window and a depth-200 reorg a second later would be
reduced to an increment, so a script that halts trading on `alertnotify` would
hear about the harmless one and not the serious one. So:

* the first occurrence pages immediately;
* an occurrence strictly deeper than anything already paged in the window
  escalates through at once, capped at one escalation per window;
* the rest are held, and the worst of them pages when the window closes,
  carrying a count and the window as measured —
  `rolled back 41 blocks [3 more in the previous 74s]`;
* a burst that stops is drained by the detector poll, not left waiting for a
  next occurrence.

None of this touches the `status` event or `getreorghistory`, which carry every
occurrence unthrottled. If you are building on reorg data, read those.

The warnings set itself is capped at **256 distinct ids**, with anything past
the cap counted in a single `warnings.truncated` row. Almost every id is a
fixed string, but a few embed an identifier — a block whose stored data is
unreadable gets one per block — and a storage fault across many blocks would
otherwise fill `getwarnings`, the TUI modal, and the hook. Ids already active
keep updating, and the node log carries every one in full.

| Condition | Severity | Raises when | Clears when |
|---|---|---|---|
| `ibd_complete` | info | initial block download finishes | one-shot |
| `tip_stall` | critical | no block connected for `alerttipstallseconds`, outside IBD | the next block connects, or the threshold no longer considers the tip stalled |
| `disk_low` | critical | free space below `alertdiskfreemb` | free space reaches 1.5× the floor, or the floor is lowered below the current reading |
| `mempool_congested` | warning | mempool at `alertmempoolfullpct` of its cap | occupancy drops below 75 % of the raise line, or the threshold is raised above the current occupancy |
| `peer_floor` | warning | fewer than `alertpeerfloor` peers for 60 s (after a 90 s startup grace) | at or above the floor for 60 s |
| `deep_reorg` | critical | a reorg rolled back ≥ `alertreorgdepth` blocks (default `3` on mainnet, `10` on test networks, off on regtest) | one-shot |

Every standing condition raises **once** on entry and clears **once** on
recovery — you get a pair of events, not a stream of repeats — and the gap
between the raise and clear lines (a ratio, a hold time, or both) means a value
sitting on the threshold does not flap your pager. `ibd_complete` and
`deep_reorg` describe things that happened rather than states that persist, so
they are one-shot: they never clear, and for the same reason they never enter
`getwarnings` at all.

Thresholds are configured with the `alert*` keys in the
[Configuration Reference](config-reference.md#health-alerts); all of them are
hot-reloadable, and setting one to `0` disables that detector. Each event
carries a `details` map with the numbers behind it (free bytes and the floor,
seconds since the last block and the tip height, the reorg's true depth and
fork height, the mempool's current `mempoolminfee`), so an alert is actionable
without a follow-up query. The watched *path* is deliberately not in the event —
it goes to every `status` subscriber and into push-notification bodies, and an
absolute datadir path usually names the account it runs under. The node logs it
instead.

**Retuning a threshold always clears its own alert.** The gap between each raise
and clear line stops a value hovering at the threshold from flapping, but it
would otherwise trap the operator who raises a threshold *because* the alert is
firing: the unchanged reading lands between the new raise line and the new clear
line, where neither fires. So a standing condition also clears when the
threshold moves such that it would no longer raise. Without this,
`mempool_congested` in particular was inescapable — `alertmempoolfullpct` clamps
at 100 and the clear line is 75 % of the raise line, so past 75 % occupancy no
setting could clear it.

`alertreorgdepth` defaults to `3` on mainnet, where a reorg that deep costs real
hashrate and invalidates transactions merchants have started treating as
settled. Signet, testnet and testnet4 default to `10`: those chains are not
economically secured, and reorgs a few blocks deep are an ordinary consequence
of thin, volatile hashrate rather than an incident. Defaulting them to mainnet's
sensitivity would run `-alertnotify` for the network working as designed, and an
alert that fires during normal operation is one you learn to ignore — which
costs you the mainnet alert too. It is raised rather than switched off because
past the 6-confirmation convention a wallet has been told something false, and
that is worth reporting on any chain. Regtest is off entirely; its test suites
reorg deliberately. Set `alertreorgdepth=3` explicitly if you want mainnet
sensitivity on a test network.

`alertpeerfloor` defaults to `3` everywhere except regtest, where it is `0`
(disabled) because running with no peers at all is a regtest node's normal
operating state rather than a fault. Signet keeps the floor: it is a public
network with real peers, and a detector defaulted off is indistinguishable from
a healthy one — `satd_alert_active{kind="peer_floor"}` reads `0` either way. Set
`alertpeerfloor=0` explicitly on a deliberately isolated signet node.

Where the floor is active, a node that has never seen a peer gets a 90 s startup
grace, and the ordinary hold begins when that grace expires or when the first
peer arrives, whichever comes first. The grace defers the start of the hold
rather than shortening it, so a node still dialing out does not page anyone on
the way up.

**Durability.** Health events are not replayable: they carry no resume cursor,
and a `from_cursor` reconnect never yields one. Instead the detectors
re-evaluate from scratch on startup and re-raise anything still standing, so a
consumer that was disconnected across a restart still learns about a live
problem. A condition that both raised and cleared while nothing was listening is
stale by definition and is not reconstructed. For the same reason, a subscriber
that attaches *after* a condition raised will not see it until the condition
changes — check `getwarnings` for current state on connect.

Two of the gauges are useful independently of alerting:
`satd_tip_last_connect_age_seconds` (seconds since the last connected block)
and `satd_disk_free_bytes` (free space on the watched directory). The latter is
omitted rather than reported as zero when the filesystem cannot be
interrogated.

## Alert webhooks

The three surfaces above all require something to be *watching* the node. A
webhook pushes instead: point `alertfile=<path>` at a TOML file and satd POSTs
each matching event to your endpoint.

```toml
version = 1

[[webhook]]
id = "pager"                        # unique; appears in the X-Satd-Hook header and metric labels
url = "https://alerts.example/satd"
secret = "a-long-random-string"     # required — it signs every delivery
categories = ["status"]             # status | chain | mempool | heartbeat
kinds = ["tip_stall", "disk_low"]   # optional, status only
min_severity = "warning"            # optional, status only

[[webhook]]
id = "deadman"
url = "https://hc-ping.example/abc123"
secret = "another-long-random-string"
categories = ["heartbeat"]
heartbeat_interval_secs = 300       # one ping per 5 min, not the bus's 1 Hz
```

The file must be mode `0600` — it holds signing secrets, and satd refuses to
read a group- or world-accessible one. Its **contents** are re-read on every
`SIGHUP`, so hooks can be added, edited, or removed without a restart; the
**path** is fixed at startup. A parse error on reload keeps the last-good hook
set and logs why, because alerting that silently stopped after a typo is the
worse failure.

`categories` is required — a hook without it would receive nothing, which is
never what anyone meant to configure. It selects from the node's firehose:

| Category | Delivers | Rate |
|---|---|---|
| `status` | node-health transitions (the six conditions above) | a handful per week on a healthy node |
| `chain` | every block connect, disconnect, and reorg | one per block |
| `mempool` | every transaction entering or leaving the mempool — **all** of them, not just yours | thousands per minute on mainnet |
| `heartbeat` | liveness pings, downsampled to `heartbeat_interval_secs` | whatever interval you set |

`kinds` and `min_severity` narrow `status` and apply to nothing else; both are
checked after the category, so `kinds` without `"status"` in `categories`
matches nothing. The streaming API's `tweaks` category is **rejected** here
rather than ignored — it is per-block bulk data and an HTTP receiver is the
wrong consumer for it.

`mempool` is almost never the right choice for a webhook: it is the whole
network's traffic, not yours. To be told about *your* transactions, use the
streaming API's `Watch` stream, which matches on scripts, outpoints, txids and
silent-payment scan keys. A webhook hook cannot filter that way and is not
meant to — see [Streaming](streaming.md).

The normative wire contract — every header, the signature scheme with test
vectors, and the exact retry semantics — is
[`docs/api/webhooks.md`](https://github.com/epochbtc/satd/blob/master/docs/api/webhooks.md).
What follows is the working summary.

### What arrives

```http
POST /your/endpoint HTTP/1.1
Content-Type: application/json
X-Satd-Signature: sha256=<hex HMAC-SHA256(secret, canonical string)>
X-Satd-Timestamp: 1753400000
X-Satd-Delivery: <node_id>-<instance_id>-<seq>
X-Satd-Hook: pager
X-Satd-Attempt: 1
X-Satd-Webhook-Version: 2

{"schema_version":1,"stamp":{...},"body":{"category":"status", ...}}
```

The body is **byte-identical** to the JSON a WebSocket subscriber receives for
the same event, so a receiver parses webhook bodies and streaming frames with
one code path. Delivery metadata rides in headers and never in the body — which
is what makes the signature stable across retries.

### Verifying a delivery

The signature covers a **canonical string**, not the bare body — five fields
joined by newlines, with the raw body last:

```
"2" LF <X-Satd-Timestamp> LF <X-Satd-Delivery> LF <X-Satd-Hook> LF <raw body>
```

Signing only the body would leave `X-Satd-Delivery` unauthenticated *and*
predictable, and that header is the one this page tells you to deduplicate on.
One captured `(body, signature)` pair could then be replayed under forged future
delivery ids, poisoning your dedup cache so the real alerts were discarded on
arrival while satd counted them delivered. Binding the id, the hook, and a
timestamp into the signed material closes that.

So a receiver must:

1. Read `X-Satd-Timestamp` and reject anything older than **600 seconds**. This
   is not optional — it is what stops a captured delivery being a permanent
   replay token. A delivery still being retried after the window ages out by
   design; a 20-minute-old "disk is filling" alert is not worth acting on.
2. Rebuild the canonical string above from the raw body, **before parsing it**.
3. Compare the HMAC in constant time.
4. Deduplicate on `X-Satd-Delivery` — stable across retries of one event, and
   unique across restarts, so a retry and a genuine repeat are distinguishable.
5. Reply `2xx` to acknowledge.

> **Upgrading from the pre-release v1 scheme.** Earlier drafts signed the raw
> body alone and sent `X-Satd-Webhook-Version: 1`. The legacy `reorgwebhook=`
> keys still use exactly that, unchanged, and still report version `1` — branch
> on the version header rather than assuming one scheme.

The `X-Satd-Delivery` value is opaque; do not parse it. Deduplicate on the whole
header: it is unique per event and stable across the retries of one delivery, so
the only duplicate you can receive is a retry of something you already saw.

### Delivery behavior

- **Serial and in-order per hook** — one request in flight at a time, so events
  arrive in the order the node produced them.
- **Retried with backoff** on 5xx, 408, 429, timeouts, and connection failures:
  1 s doubling to a 5-minute ceiling — but **not forever**. A delivery is
  abandoned once it ages past the 600 s freshness window it was signed with,
  which lands somewhere around the tenth or eleventh attempt. That is
  deliberate: the signed timestamp is the only staleness signal a receiver
  checks, so a delivery that could no longer pass that check is not worth
  sending. The practical consequence is that a receiver down for longer than
  ten minutes — a relay redeploy, a restart that takes a while — loses the
  events raised during the outage. Alert on
  `satd_alertwebhook_dropped_total` if that matters to you; the detectors
  re-raise standing health conditions, so those recover on their own, but
  chain and mempool events do not.
  Any *other* 4xx is treated as permanent, counted, and skipped — a receiver
  answering 404 forever must not pin the queue and turn every later event into
  a drop. The skip is counted in `satd_alertwebhook_dropped_total` and logged.
- **Redirects are not followed.** A 3xx is a permanent drop. The URL in the
  alertfile is where the signed body goes; following a redirect would move it —
  signature, hook identity and all — to a host you never named, and the useful
  targets for that are exactly the ones you cannot see: a cloud metadata
  endpoint, an RFC1918 admin port, the node's own RPC. If your receiver moves,
  update the alertfile.
- **Bounded queue.** A hook that falls far enough behind drops events. They are
  counted in `satd_alertwebhook_dropped_total` and logged; nothing is held for
  later and nothing is inserted into the stream to tell the receiver.
- **Nothing reaches consensus.** Deliveries run on the isolated API runtime and
  the event fan-in never blocks, so a stalled endpoint cannot affect block
  connection. Measured on a regtest node connecting 20 blocks: 11.23 ms with no
  webhook configured, 11.24 ms with every event going to a receiver that
  accepts the connection and never answers.
- **Best-effort, and that is the whole contract.** Nothing is persisted. A
  webhook fires when something happens and is retried while your endpoint is
  briefly unreachable; that is all it promises. A node that was down did not
  deliver those events and will not go back for them — when it comes up, its
  hooks resume at the live head. Health alerts are the exception, and they get
  it for free: the detectors re-evaluate at startup and re-raise anything still
  true (see **Durability** above), so a standing problem still reaches you.

  If you need guaranteed delivery, resumability across downtime, or history,
  use the [Streaming Consumption API](streaming.md). That is the recommended
  way to integrate with satd and it does all three properly — real cursors,
  backpressure, and a bounded `RescanBlocks`. Webhooks are for automation you
  are happy to miss occasionally: page me, poke a script, ping a dead-man's
  switch.
- **`chain` alerts are suppressed during initial block download.** A node
  syncing from scratch does not POST its entire block history. `status`,
  `heartbeat` **and `mempool`** keep flowing: health alerts stay live because
  "this node is unhealthy" is exactly as true mid-sync, and the heartbeat keeps
  flowing so an external dead-man's switch does not declare a syncing node dead.
  Note the consequence for `mempool` hooks — a mainnet mempool subscription is
  thousands of events a minute, and a multi-day sync does not quiet it. What was
  suppressed is counted in `satd_alertwebhook_dropped_total`. The suppression is
  latched on leaving IBD once, so a node whose tip later goes stale keeps
  alerting — which is the whole point of a stalled-tip alert.

Plaintext `http://` is accepted for loopback and private-network targets. For a
public host, use `https://` or set `allow_insecure_http = true` on the hook.

Per-hook counters are exported: `satd_alertwebhook_delivered_total`,
`_failed_attempts_total`, `_dropped_total` (events lost, not held —
there is no dead-letter queue),
`_queue_depth`, and `_last_success_age_seconds`, all labelled `hook="<id>"`.
Nothing is exported when no hook is configured.

### Writing a receiver

A receiver is an HTTP endpoint that verifies the signature and acts. What it
does with an alert — page someone, open a ticket, forward to a push service, or
just log it — is yours to decide; satd's job ends at the delivery.

Two things are worth getting right, and both are covered with test vectors in
the [webhook reference](https://github.com/epochbtc/satd/blob/master/docs/api/webhooks.md):

1. **Verify `X-Satd-Signature` over the raw body, in constant time, before
   parsing.** Key order and whitespace are part of the signed bytes, so a
   re-serialized body will not verify — and parsing unauthenticated input is
   the thing to avoid.
2. **Deduplicate on `X-Satd-Delivery`.** satd retries, so the same id arrives
   again whenever a response is lost after you already acted on it. The id is
   inside the signature, so a forged one cannot poison your dedup window.

A condition and its later recovery share a `collapse_id`, so a receiver that
surfaces alerts to a human can replace the alert with its recovery rather than
stacking a second message beneath it.

> **Note.** The older `reorgwebhook=` / `reorgwebhooksecret=` keys still work
> and are now served by this dispatcher, with their original `ReorgRecord`
> payload and v1 body-only signature unchanged.
>
> **One behavior did change:** redirects are no longer followed. A receiver
> that answers 301/302 — an `http`→`https` proxy hop, a trailing-slash
> redirect, a load balancer that relocates — used to be chased and now
> classifies as a permanent drop. If your reorg endpoint relies on a redirect,
> point `reorgwebhook=` at the final URL; otherwise every reorg record is
> silently discarded. Everything else about the payload and signature is
> byte-identical, so a receiver on a stable URL needs no edits.
>
> New deployments should prefer an `alertfile` hook with
> `categories = ["chain"]`, which delivers the standard event envelope.

## Structured JSON Logging

`satd` logs to stdout. Use `--log-format=json` to switch from the text format
to structured, machine-parseable JSON in place of a traditional `debug.log`
stream. The JSON output feeds Datadog, ELK, or custom log-alerting pipelines
directly. Trace IDs let an operator follow a single block through prefetch,
connect, and flush.

*   **Flag:** `--log-format=json|text`

## Reorg Notifications

`satd` records every reorg it performs, so exchanges and custodians can read
reorg history from the node instead of reconstructing it externally.

*   **Persistent log.** An append-only JSONL log at
    `$datadir/<network>/reorg.log`, the network-specific datadir subdirectory.
    The log sits directly under `$datadir` only on mainnet. It survives
    restarts and is backed by an in-memory 256-record ring.
*   **Query method.** `getreorghistory [since_secs]` returns recent reorgs.
*   **Webhook.** Use `--reorg-webhook=<url>` to send an HTTP POST on each
    reorg. Set `--reorg-webhook-secret=<secret>` to have satd sign the body
    with HMAC-SHA256 in an `X-Satd-Signature: sha256=...` header, which the
    receiver can use to verify integrity.

> **Difference from Bitcoin Core.** Core's `getchaintips` reflects only the
> currently known tips; a reorg that happened yesterday leaves no record. satd
> persists reorg history natively.
