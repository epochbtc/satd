# Observability & Metrics

`satd` is built to make running a full node transparent. Rather than running
blind or parsing a chatty log file, operators get a native terminal dashboard,
a Prometheus endpoint, and structured logs out of the box.

## Native TUI (`sat-tui`)

`satd` ships with a native Ratatui-based terminal interface. Rather than running
blind or relying on chatty log files, operators can visualize node progress in
real-time.

*   **IBD Bitmap:** Visualizes block download and verification progress.
*   **Peer Stats:** Shows connected peers, their latency, and block delivery rates.
*   **Mempool Status:** Live view of mempool depth and fee percentiles.

The full `sat-tui` reference — every view, panel, field, and keybinding — is in
the [Terminal UI](tui.md) chapter.

## Prometheus Metrics Endpoint

*   **Enable flag:** `--metricsport=<port>` — the metrics/health server starts
    only when a port is set. `--metricsbind=<addr>` sets the bind address alone
    (default `127.0.0.1`); it does **not** enable the server on its own. The
    listener binds `<metricsbind>:<metricsport>`.
*   Exposes a native Prometheus HTTP server at `GET /metrics` providing deep insights into P2P traffic, block validation times, mempool depth, and RocksDB performance. P2P wire volume is exported as the `satd_net_bytes_sent_total` / `satd_net_bytes_recv_total` counters (peer count via `satd_peer_connections`).
*   Includes `GET /healthz` and `GET /readyz` endpoints for load balancer and orchestrator integration.

See the [Packaging](packaging.md#health-and-readiness) chapter for how to wire
`/healthz` and `/readyz` to Docker `HEALTHCHECK`, Kubernetes probes, or a
systemd `ExecStartPost=` poll.

> **Prefer `/metrics` over RPC polling for monitoring.** The Bitcoin Core
> RPCs `getnettotals` (byte totals) and `getpeerinfo`
> (`bytessent`/`bytesrecv`/`lastsend`/`lastrecv`) are populated and accurate
> for steady-state traffic, but they exist for Core compatibility. For
> dashboards and alerting, scrape the native Prometheus endpoint instead: it
> is a counter model purpose-built for time-series tooling (rates, retention,
> labels) and does not consume an RPC worker on every scrape. The RPC byte
> counters cover post-handshake traffic only (the one-time handshake bytes are
> not included), so absolute socket totals will read marginally lower than the
> kernel's.

## Structured JSON Logging

*   **Flag:** `--log-format=json|text`
*   Replaces the traditional `debug.log` text firehose with structured, machine-parseable JSON logs. Perfect for Datadog, ELK, or custom log-alerting pipelines. Trace IDs allow operators to follow a single block through prefetch, connect, and flush.

## Reorg Notifications

Where Bitcoin Core's `getchaintips` reflects only the *currently* known tips —
yesterday's reorgs are gone — satd records every reorg natively, so exchanges
and custodians don't have to reconstruct them externally.

*   **Persistent log.** An append-only JSONL log at `$datadir/<network>/reorg.log`
    (the network-specific datadir subdirectory; directly under `$datadir` only on
    mainnet) survives restarts, backed by an in-memory 256-record ring.
*   **Query RPC.** `getreorghistory [since_secs]` returns recent reorgs.
*   **Webhook.** Optional HTTP POST on each reorg via `--reorg-webhook=<url>`.
    Set `--reorg-webhook-secret=<secret>` to have satd sign the body with
    HMAC-SHA256 in an `X-Satd-Signature: sha256=...` header so the receiver can
    verify integrity.
