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
(`bytessent`, `bytesrecv`, `lastsend`, `lastrecv`) are populated and accurate
for steady-state traffic, but they exist for Core compatibility. The Prometheus
endpoint is a counter model built for time-series tooling (rates, retention,
labels) and does not consume an RPC worker on every scrape.

> **Note.** The RPC byte counters cover post-handshake traffic only. The
> one-time handshake bytes are not included, so absolute socket totals read
> marginally lower than the kernel's.

## Node-health alerts

Metrics tell you what the node is doing; health alerts tell you when it has
stopped doing it. satd watches six conditions about *itself* and reports each
one through three surfaces at once, so they can never disagree:

*   a `status` event on the [Streaming Consumption API](streaming.md) (category
    bit 16 — see §7.8 of the wire spec),
*   an entry in `getwarnings` (and therefore in `getblockchaininfo.warnings`
    and the TUI), which also fires the Core-compatible `alertnotify` hook,
*   a `satd_alert_active{kind="..."}` gauge on `/metrics`.

| Condition | Severity | Raises when | Clears when |
|---|---|---|---|
| `ibd_complete` | info | initial block download finishes | one-shot |
| `tip_stall` | critical | no block connected for `alerttipstallseconds`, outside IBD | the next block connects, or the threshold no longer considers the tip stalled |
| `disk_low` | critical | free space below `alertdiskfreemb` | free space reaches 1.5× the floor, or the floor is lowered below the current reading |
| `mempool_congested` | warning | mempool at `alertmempoolfullpct` of its cap | occupancy drops below 75 % of the raise line, or the threshold is raised above the current occupancy |
| `peer_floor` | warning | fewer than `alertpeerfloor` peers for 60 s (after a 90 s startup grace) | at or above the floor for 60 s |
| `deep_reorg` | critical | a reorg rolled back ≥ `alertreorgdepth` blocks | one-shot |

Every standing condition raises **once** on entry and clears **once** on
recovery — you get a pair of events, not a stream of repeats — and the gap
between the raise and clear lines (a ratio, a hold time, or both) means a value
sitting on the threshold does not flap your pager. `ibd_complete` and
`deep_reorg` describe things that happened rather than states that persist, so
they are one-shot and never clear.

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

`alertpeerfloor` defaults to `3` on mainnet and testnet4, and to `0`
(disabled) on regtest and signet, where running with no peers at all is normal
rather than a fault. On the networks where it is active it does not raise until
90 s after startup or the node's first peer, whichever comes first, so a node
that is still dialing out does not page anyone on the way up.

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
