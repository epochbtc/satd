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
*   Exposes a native Prometheus HTTP server at `GET /metrics` providing deep insights into P2P traffic, block validation times, mempool depth, and RocksDB performance.
*   Includes `GET /healthz` and `GET /readyz` endpoints for load balancer and orchestrator integration.

See the [Packaging](packaging.md#health-and-readiness) chapter for how to wire
`/healthz` and `/readyz` to Docker `HEALTHCHECK`, Kubernetes probes, or a
systemd `ExecStartPost=` poll.

## Structured JSON Logging

*   **Flag:** `--log-format=json|text`
*   Replaces the traditional `debug.log` text firehose with structured, machine-parseable JSON logs. Perfect for Datadog, ELK, or custom log-alerting pipelines. Trace IDs allow operators to follow a single block through prefetch, connect, and flush.
