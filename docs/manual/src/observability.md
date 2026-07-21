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
