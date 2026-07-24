//! Prometheus-format metrics and health endpoints for operator monitoring.
//!
//! Exposes three HTTP endpoints on a separate unauthenticated listener:
//! - `GET /metrics`  — Prometheus text-format metrics (scrape target)
//! - `GET /healthz`  — 200 if the process is up (Docker/k8s liveness)
//! - `GET /readyz`   — 200 when chain is within READY_LAG_BLOCKS of known
//!   headers tip, 503 otherwise (Docker/k8s readiness)
//!
//! The listener is intentionally unauthenticated: these are operator-only
//! signals, and adding auth would break the Prometheus scrape and k8s probe
//! ecosystems. Bind to loopback or a trusted network; firewall externally.
//!
//! Metric schema: `satd_*` prefix, Prometheus conventions (`_bytes` /
//! `_seconds` / `_total` / `_ratio`). The schema is a stability commitment —
//! once emitted, metric names and label dimensions should not change in
//! incompatible ways.

use bitcoin::Network;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Instant;

use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::net::manager::PeerManager;
use crate::storage::Store as _;

/// A node is "ready" when its connected tip is within this many blocks of
/// the best headers tip observed from peers.
pub const READY_LAG_BLOCKS: u32 = 6;

/// Everything the metrics handler needs to render its response.
///
/// Cheap to clone (Arcs all the way down).
#[derive(Clone)]
pub struct MetricsContext {
    pub chain_state: Arc<ChainState>,
    pub mempool: Arc<Mempool>,
    pub peer_manager: Arc<PeerManager>,
    pub network: Network,
    pub start_time: Instant,
    pub version: &'static str,
    /// Subscription registry handle for active-subscribers gauge.
    /// Optional so test backends without a registry still render.
    pub addr_subs:
        Option<Arc<crate::index::address::SubscriptionRegistry>>,
    /// Address-index runtime config — exposed as an `enabled` gauge
    /// so operators can confirm at a glance which DB-backed indexes
    /// are live.
    pub addr_enabled: bool,
    /// Live readings from the health detectors. `None` in test backends and
    /// anywhere the detector task was not spawned, in which case the health
    /// gauges are omitted entirely rather than reported as zeros (a zero
    /// `satd_disk_free_bytes` is exactly the alarm an operator must not be
    /// shown falsely).
    pub health: Option<Arc<crate::health::HealthState>>,
}

impl MetricsContext {
    /// Render the `/metrics` response body in Prometheus text format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        let tip_height = self.chain_state.tip_height();
        let headers_tip = self.chain_state.headers_tip_height().max(tip_height);
        let ibd_active = u64::from(headers_tip.saturating_sub(tip_height) > READY_LAG_BLOCKS);
        let dirty = self.chain_state.cache_dirty_count() as u64;
        let cache_size = self.chain_state.cache_size() as u64;
        let flush_threshold = self.chain_state.flush_threshold() as u64;
        let mempool_info = self.mempool.info();
        let peer_count = self.peer_manager.connection_count() as u64;
        let peer_count_v2 = self.peer_manager.connection_count_v2() as u64;
        let net_totals = self.peer_manager.net_totals();
        let net_bytes_sent = net_totals.bytes_sent();
        let net_bytes_recv = net_totals.bytes_recv();
        let uptime_secs = self.start_time.elapsed().as_secs();
        let network_str = network_label(self.network);
        let (rss_bytes, vm_bytes) = process_memory().unwrap_or((0, 0));

        // Gauges: current chain state.
        metric(
            &mut out,
            "satd_tip_height",
            "Height of the best fully-validated block in the active chain.",
            "gauge",
            &[],
            u64::from(tip_height),
        );
        metric(
            &mut out,
            "satd_headers_tip_height",
            "Height of the best known header (may exceed tip during IBD).",
            "gauge",
            &[],
            u64::from(headers_tip),
        );
        metric(
            &mut out,
            "satd_ibd_active",
            "1 if the node is currently in Initial Block Download, 0 otherwise.",
            "gauge",
            &[],
            ibd_active,
        );
        metric(
            &mut out,
            "satd_coin_cache_dirty_entries",
            "Dirty UTXO cache entries awaiting flush to RocksDB.",
            "gauge",
            &[],
            dirty,
        );
        metric(
            &mut out,
            "satd_coin_cache_total_entries",
            "Total UTXO cache entries (dirty + clean).",
            "gauge",
            &[],
            cache_size,
        );
        metric(
            &mut out,
            "satd_coin_cache_flush_threshold",
            "Dirty-entry count at which the coin cache is flushed.",
            "gauge",
            &[],
            flush_threshold,
        );
        metric(
            &mut out,
            "satd_mempool_transactions",
            "Number of transactions currently in the mempool.",
            "gauge",
            &[],
            mempool_info.size as u64,
        );
        metric(
            &mut out,
            "satd_mempool_bytes",
            "Total serialized size of mempool transactions in bytes.",
            "gauge",
            &[],
            mempool_info.bytes as u64,
        );
        metric(
            &mut out,
            "satd_mempool_max_bytes",
            "Configured mempool capacity in bytes.",
            "gauge",
            &[],
            mempool_info.max_size as u64,
        );
        let orphanage = self.peer_manager.orphanage();
        metric(
            &mut out,
            "satd_orphan_count",
            "Current number of transactions in the orphan pool (missing parents, awaiting reconsideration).",
            "gauge",
            &[],
            orphanage.len() as u64,
        );
        metric(
            &mut out,
            "satd_orphan_bytes",
            "Total serialized size of orphan transactions in bytes.",
            "gauge",
            &[],
            orphanage.bytes() as u64,
        );
        metric(
            &mut out,
            "satd_mempool_min_fee_rate_sat_per_kvb",
            "Minimum relay fee rate in satoshis per kilo-vbyte.",
            "gauge",
            &[],
            mempool_info.min_fee_rate,
        );
        metric(
            &mut out,
            "satd_peer_connections",
            "Number of currently connected P2P peers.",
            "gauge",
            &[],
            peer_count,
        );
        metric(
            &mut out,
            "satd_peer_connections_v2",
            "Number of connected P2P peers using the BIP 324 v2 transport.",
            "gauge",
            &[],
            peer_count_v2,
        );
        metric(
            &mut out,
            "satd_net_bytes_sent_total",
            "Total P2P bytes sent on the wire across all peers (post-handshake).",
            "counter",
            &[],
            net_bytes_sent,
        );
        metric(
            &mut out,
            "satd_net_bytes_recv_total",
            "Total P2P bytes received on the wire across all peers (post-handshake).",
            "counter",
            &[],
            net_bytes_recv,
        );
        metric(
            &mut out,
            "satd_process_uptime_seconds",
            "Process uptime in seconds since startup.",
            "gauge",
            &[],
            uptime_secs,
        );
        if rss_bytes > 0 {
            metric(
                &mut out,
                "satd_process_memory_rss_bytes",
                "Resident set size of the satd process in bytes.",
                "gauge",
                &[],
                rss_bytes,
            );
        }
        if vm_bytes > 0 {
            metric(
                &mut out,
                "satd_process_memory_virtual_bytes",
                "Virtual memory size of the satd process in bytes.",
                "gauge",
                &[],
                vm_bytes,
            );
        }

        // Build info: a constant gauge of 1 with descriptive labels.
        metric(
            &mut out,
            "satd_build_info",
            "Build metadata. Always 1; inspect labels for version and network.",
            "gauge",
            &[("version", self.version), ("network", network_str)],
            1,
        );

        // Address-history index metrics (M6).
        let addr_stats = crate::index::address::stats::snapshot();
        metric(
            &mut out,
            "satd_addrindex_enabled",
            "1 if the address-history index is enabled at runtime, 0 otherwise.",
            "gauge",
            &[],
            u64::from(self.addr_enabled),
        );
        metric(
            &mut out,
            "satd_addrindex_funding_rows_total",
            "Cumulative count of address-history funding rows committed to RocksDB since process start.",
            "counter",
            &[],
            addr_stats.funding_rows,
        );
        metric(
            &mut out,
            "satd_addrindex_spending_rows_total",
            "Cumulative count of address-history spending rows committed to RocksDB since process start.",
            "counter",
            &[],
            addr_stats.spending_rows,
        );
        metric(
            &mut out,
            "satd_addrindex_funding_removes_total",
            "Cumulative count of address-history funding-row removals committed to RocksDB.",
            "counter",
            &[],
            addr_stats.funding_removes,
        );
        metric(
            &mut out,
            "satd_addrindex_spending_removes_total",
            "Cumulative count of address-history spending-row removals committed to RocksDB.",
            "counter",
            &[],
            addr_stats.spending_removes,
        );
        if let Some(subs) = &self.addr_subs {
            metric(
                &mut out,
                "satd_addrindex_subscriptions_active",
                "Currently registered per-scripthash status subscriptions.",
                "gauge",
                &[],
                subs.active_count() as u64,
            );
        }

        // BIP 352 silent-payment tweak index. Row counters are process-
        // wide and count only rows actually committed to RocksDB.
        let sp_stats = crate::index::silent_payments::stats::snapshot();
        metric(
            &mut out,
            "satd_spindex_rows_total",
            "Cumulative count of silent-payment tweak rows committed to RocksDB since process start (one per block at/above taproot activation).",
            "counter",
            &[],
            sp_stats.rows,
        );
        metric(
            &mut out,
            "satd_spindex_row_removes_total",
            "Cumulative count of silent-payment tweak-row removals committed to RocksDB (reorg disconnects).",
            "counter",
            &[],
            sp_stats.row_removes,
        );
        // Deferred-backfill progress ratio (0.0–1.0). Reads the persisted
        // SP-index backfill cursor: 0.0 when idle / not started, 1.0 on
        // completion. A float gauge, so emitted directly rather than via
        // the u64 `metric` helper.
        let sp_backfill_ratio = self
            .chain_state
            .store_ref()
            .read_sp_backfill_cursor()
            .progress_ratio();
        let _ = writeln!(
            out,
            "# HELP satd_spindex_backfill_progress_ratio Fraction of the silent-payment-index deferred backfill completed (0.0 idle/none, 1.0 complete)."
        );
        let _ = writeln!(out, "# TYPE satd_spindex_backfill_progress_ratio gauge");
        let _ = writeln!(out, "satd_spindex_backfill_progress_ratio {sp_backfill_ratio}");

        // Node-health gauges, rendered only when the detector task is running.
        render_health_metrics(&mut out, self.health.as_deref());

        // Transaction-filtering policy metrics (design §10, PR 7c). Extracted to
        // a free function so the I8-invisibility invariant (a node with no
        // non-empty ruleset renders a byte-identical page) is unit-testable
        // without standing up a full MetricsContext.
        render_policy_metrics(&mut out, &self.mempool);

        out
    }

    /// Render the `/readyz` decision: `Ok` if ready, `Err(reason)` otherwise.
    pub fn is_ready(&self) -> Result<(), String> {
        let tip = self.chain_state.tip_height();
        let headers_tip = self.chain_state.headers_tip_height().max(tip);
        let lag = headers_tip.saturating_sub(tip);
        if lag > READY_LAG_BLOCKS {
            Err(format!(
                "chain lag {} blocks exceeds ready threshold {}",
                lag, READY_LAG_BLOCKS
            ))
        } else {
            Ok(())
        }
    }
}

fn metric(
    out: &mut String,
    name: &str,
    help: &str,
    kind: &str,
    labels: &[(&str, &str)],
    value: u64,
) {
    metric_header(out, name, help, kind);
    metric_sample(out, name, labels, value);
}

/// Emit the `# HELP` / `# TYPE` pair for a metric family, once.
///
/// The text format permits **one** such pair per family name. [`metric`] writes
/// a header with every sample, which is correct only for a single-series
/// family; calling it in a loop emits repeated headers, and a strict parser
/// (`promtool check metrics`, and the `expfmt` text parser several collectors
/// and relays use) hard-errors on the second `# HELP` and discards the *entire
/// page* — taking every unrelated satd metric down with it. For a multi-series
/// family call this once, then [`metric_sample`] per series.
fn metric_header(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// Emit one sample of an already-headered metric family.
fn metric_sample(out: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
    if labels.is_empty() {
        let _ = writeln!(out, "{name} {value}");
    } else {
        let mut label_str = String::new();
        for (i, (k, v)) in labels.iter().enumerate() {
            if i > 0 {
                label_str.push(',');
            }
            let _ = write!(label_str, "{k}=\"{}\"", escape_label(v));
        }
        let _ = writeln!(out, "{name}{{{label_str}}} {value}");
    }
}

/// Append the node-health gauges (§A3): tip age, free disk, and one 0/1 series
/// per standing alert condition.
///
/// `satd_alert_active` is pre-registered for *every* kind, including ones that
/// are not currently raised, so an alerting rule can be written against a series
/// that exists from the first scrape — a gauge that only appears once the
/// condition fires is exactly the gauge you cannot alert on. Edge kinds
/// (`ibd_complete`, `deep_reorg`) have no standing state and are omitted: a
/// permanently-zero series would invite a rule that can never fire.
///
/// Renders nothing at all when no detector task is running (`None`), rather
/// than emitting zeros that would read as real readings.
fn render_health_metrics(out: &mut String, health: Option<&crate::health::HealthState>) {
    let Some(health) = health else {
        return;
    };
    metric(
        out,
        "satd_tip_last_connect_age_seconds",
        "Seconds since the last block was connected to the active chain (since process start if none has been).",
        "gauge",
        &[],
        health.last_connect_age_secs(),
    );
    // Omitted rather than zeroed when the filesystem cannot be interrogated.
    if let Some(free) = health.disk_free_bytes() {
        metric(
            out,
            "satd_disk_free_bytes",
            "Free space available to satd on the watched data/blocks directory.",
            "gauge",
            &[],
            free,
        );
    }
    metric_header(
        out,
        "satd_alert_active",
        "1 while a node-health condition is raised, 0 while it is clear.",
        "gauge",
    );
    for kind in crate::events::StatusKind::ALL {
        if kind.is_edge() {
            continue;
        }
        metric_sample(
            out,
            "satd_alert_active",
            &[("kind", kind.as_str())],
            u64::from(health.is_active(kind)),
        );
    }
}

/// Append the transaction-filtering policy metrics to `out` — but ONLY when a
/// non-empty ruleset is active. A node with no policy (or one whose policyfile
/// is just `version 1`) appends nothing, so its `/metrics` page is byte-identical
/// to a build without the engine (I8 invisibility). The `has_policy()` gate is
/// the same `!is_empty()` test the admission hot path uses; gating on
/// `policy_snapshot().is_some()` alone would leak the whole block as zero-valued
/// samples for an empty-but-loaded ruleset.
fn render_policy_metrics(out: &mut String, mempool: &Mempool) {
    let Some(snapshot) = mempool
        .has_policy()
        .then(|| mempool.policy_snapshot())
        .flatten()
    else {
        return;
    };
    let stats = mempool.policy_stats_snapshot();
    let (promoted, demoted, reload_failures) = mempool.policy_transition_totals();
    let template_floor = mempool.min_fee_rate();
    let report = mempool.quarantine_report(template_floor);

    metric(
        out,
        "satd_policy_evaluations_total",
        "Transactions evaluated against the policy ruleset since it loaded.",
        "counter",
        &[],
        stats.evaluations,
    );
    metric(
        out,
        "satd_policy_fuel_exhausted_total",
        "Policy evaluations that hit the fuel backstop (fail-safe full-scope quarantine).",
        "counter",
        &[],
        stats.fuel_exhausted,
    );
    metric(
        out,
        "satd_policy_reload_failures_total",
        "SIGHUP policy reloads that failed to compile (last-good kept).",
        "counter",
        &[],
        reload_failures,
    );
    metric(
        out,
        "satd_policy_promoted_total",
        "Cumulative quarantine->acting moves by the reload re-placement pass.",
        "counter",
        &[],
        promoted,
    );
    metric(
        out,
        "satd_policy_demoted_total",
        "Cumulative acting->quarantine moves by the reload re-placement pass.",
        "counter",
        &[],
        demoted,
    );
    metric(
        out,
        "satd_policy_quarantine_confirmed_total",
        "Quarantined transactions later seen confirmed in a block (confirmed-anyway).",
        "counter",
        &[],
        report.confirmed_anyway,
    );

    // Per-rule match counters. Emit each metric family's HELP/TYPE once, then one
    // labelled sample per rule (multiple HELP/TYPE lines for the same family is
    // invalid Prometheus).
    let _ = writeln!(
        out,
        "# HELP satd_policy_quarantined_total Per-rule count of quarantine matches since load."
    );
    let _ = writeln!(out, "# TYPE satd_policy_quarantined_total counter");
    let _ = writeln!(
        out,
        "# HELP satd_policy_allows_total Per-rule count of allow matches since load."
    );
    let _ = writeln!(out, "# TYPE satd_policy_allows_total counter");
    for r in snapshot.rules() {
        let matched = stats.per_rule.get(&r.name).copied().unwrap_or(0);
        match r.action {
            satd_policy::Action::Quarantine => {
                let _ = writeln!(
                    out,
                    "satd_policy_quarantined_total{{rule=\"{}\",scope=\"{}\"}} {}",
                    escape_label(&r.name),
                    scope_label(r.scope.relay, r.scope.template),
                    matched,
                );
            }
            satd_policy::Action::Allow => {
                let _ = writeln!(
                    out,
                    "satd_policy_allows_total{{rule=\"{}\"}} {}",
                    escape_label(&r.name),
                    matched,
                );
            }
        }
    }

    metric(
        out,
        "satd_policy_quarantine_transactions",
        "Transactions currently held in the quarantine class.",
        "gauge",
        &[],
        report.total_count,
    );
    metric(
        out,
        "satd_policy_quarantine_bytes",
        "Serialized bytes currently held in the quarantine class.",
        "gauge",
        &[],
        report.total_bytes,
    );
    metric(
        out,
        "satd_policy_quarantine_budget_bytes",
        "Configured quarantine-class capacity in bytes.",
        "gauge",
        &[],
        report.budget_bytes,
    );
    metric(
        out,
        "satd_policy_foregone_fees_sat",
        "Sum of fees (sat) of template-withheld quarantined txs above the template floor.",
        "gauge",
        &[],
        report.foregone_fees_sat,
    );
}

fn escape_label(v: &str) -> String {
    let mut s = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            other => s.push(other),
        }
    }
    s
}

fn network_label(n: Network) -> &'static str {
    match n {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

/// Stable label for a quarantine rule's scope (`satd_policy_quarantined_total`).
/// A scope bit set means "withheld from" that path.
fn scope_label(relay: bool, template: bool) -> &'static str {
    match (relay, template) {
        (true, true) => "relay+template",
        (true, false) => "relay",
        (false, true) => "template",
        (false, false) => "none",
    }
}

/// Read RSS and VmSize from `/proc/self/status`. Returns `(rss_bytes, vm_bytes)`
/// or `None` on non-Linux / parse failure.
fn process_memory() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    let mut rss = 0u64;
    let mut vm = 0u64;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            rss = parse_kib_line(rest)?;
        } else if let Some(rest) = line.strip_prefix("VmSize:") {
            vm = parse_kib_line(rest)?;
        }
    }
    Some((rss, vm))
}

fn parse_kib_line(rest: &str) -> Option<u64> {
    let kib: u64 = rest.trim().trim_end_matches(" kB").trim().parse().ok()?;
    Some(kib.saturating_mul(1024))
}

/// Run the metrics HTTP server until the shutdown signal fires.
///
/// Uses plain hyper (already in the dependency tree via jsonrpsee) — no new
/// server framework, no Prometheus client library. The endpoints are:
/// - `GET /metrics`  → 200 `text/plain; version=0.0.4`
/// - `GET /healthz`  → 200 `OK`
/// - `GET /readyz`   → 200 `OK` when ready, 503 when not
/// - anything else   → 404
pub async fn serve_metrics_http(
    ctx: MetricsContext,
    bind_addr: std::net::SocketAddr,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "Metrics/health HTTP server listening");

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            let io = hyper_util::rt::TokioIo::new(stream);
                            let svc = hyper::service::service_fn(move |req| {
                                let ctx = ctx.clone();
                                async move { Ok::<_, std::convert::Infallible>(handle_request(&ctx, req).await) }
                            });
                            if let Err(e) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, svc)
                                .await
                            {
                                tracing::debug!("Metrics HTTP connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Metrics HTTP accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.wait_for(|v| *v) => {
                tracing::info!("Metrics HTTP server shutting down");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_request(
    ctx: &MetricsContext,
    req: hyper::Request<hyper::body::Incoming>,
) -> hyper::Response<String> {
    if req.method() != hyper::Method::GET {
        return plain_response(405, "method not allowed\n");
    }
    match req.uri().path() {
        "/metrics" => {
            let body = ctx.render_prometheus();
            hyper::Response::builder()
                .status(200)
                .header(
                    hyper::header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )
                .body(body)
                .unwrap()
        }
        "/healthz" => plain_response(200, "ok\n"),
        "/readyz" => match ctx.is_ready() {
            Ok(()) => plain_response(200, "ok\n"),
            Err(reason) => plain_response(503, &format!("not ready: {}\n", reason)),
        },
        _ => plain_response(404, "not found\n"),
    }
}

fn plain_response(status: u16, body: &str) -> hyper::Response<String> {
    hyper::Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body.to_string())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_escaping_handles_specials() {
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(escape_label("with \"quote\""), "with \\\"quote\\\"");
        assert_eq!(escape_label("back\\slash"), "back\\\\slash");
        assert_eq!(escape_label("line\nbreak"), "line\\nbreak");
    }

    #[test]
    fn metric_line_format_matches_prometheus_spec() {
        let mut out = String::new();
        metric(&mut out, "foo_bar", "help text", "gauge", &[], 42);
        assert!(out.contains("# HELP foo_bar help text\n"));
        assert!(out.contains("# TYPE foo_bar gauge\n"));
        assert!(out.contains("foo_bar 42\n"));
    }

    #[test]
    fn metric_with_labels_orders_and_quotes() {
        let mut out = String::new();
        metric(
            &mut out,
            "build",
            "info",
            "gauge",
            &[("version", "0.1.0"), ("network", "mainnet")],
            1,
        );
        assert!(out.contains("build{version=\"0.1.0\",network=\"mainnet\"} 1\n"));
    }

    #[test]
    fn network_label_covers_all_mainline_networks() {
        assert_eq!(network_label(Network::Bitcoin), "mainnet");
        assert_eq!(network_label(Network::Testnet), "testnet");
        assert_eq!(network_label(Network::Signet), "signet");
        assert_eq!(network_label(Network::Regtest), "regtest");
    }

    #[test]
    fn parse_kib_line_handles_typical_proc_status() {
        assert_eq!(parse_kib_line("  123456 kB\n"), Some(123_456 * 1024));
        assert_eq!(parse_kib_line("0 kB"), Some(0));
    }

    #[test]
    fn scope_label_covers_every_combination() {
        assert_eq!(scope_label(true, true), "relay+template");
        assert_eq!(scope_label(true, false), "relay");
        assert_eq!(scope_label(false, true), "template");
        assert_eq!(scope_label(false, false), "none");
    }

    #[test]
    fn health_metrics_absent_without_a_detector_task() {
        // Rendering zeros here would show a `satd_disk_free_bytes 0` — the
        // exact alarm an operator must not be given falsely.
        let mut out = String::new();
        render_health_metrics(&mut out, None);
        assert!(out.is_empty(), "no detector ⇒ no health metrics:\n{out}");
    }

    /// Assert a rendered page is valid Prometheus text format on the one rule
    /// that is easy to break and fatal when broken: at most one `# HELP` and
    /// one `# TYPE` per family name.
    ///
    /// Strict parsers (`promtool check metrics`, `expfmt.TextParser`) reject
    /// the whole page on a duplicate, so one careless family takes every other
    /// satd metric down with it. Prometheus's own scrape parser is lenient,
    /// which is exactly why this is worth a test rather than a scrape check.
    fn assert_one_header_per_family(out: &str) {
        use std::collections::HashMap;
        let mut helps: HashMap<&str, usize> = HashMap::new();
        let mut types: HashMap<&str, usize> = HashMap::new();
        for line in out.lines() {
            if let Some(rest) = line.strip_prefix("# HELP ") {
                *helps.entry(rest.split(' ').next().unwrap_or("")).or_default() += 1;
            } else if let Some(rest) = line.strip_prefix("# TYPE ") {
                *types.entry(rest.split(' ').next().unwrap_or("")).or_default() += 1;
            }
        }
        for (name, n) in helps {
            assert_eq!(n, 1, "family {name} has {n} `# HELP` lines:\n{out}");
        }
        for (name, n) in types {
            assert_eq!(n, 1, "family {name} has {n} `# TYPE` lines:\n{out}");
        }
    }

    #[test]
    fn health_metrics_are_valid_exposition_format() {
        // `satd_alert_active` is one family with a series per kind, so the
        // header must be emitted once and the samples must follow it.
        let health = crate::health::HealthState::new();
        health.set_disk_free_for_test(Some(1 << 30));
        let mut out = String::new();
        render_health_metrics(&mut out, Some(&health));
        assert_one_header_per_family(&out);
    }

    #[test]
    fn health_metrics_preregister_every_standing_kind() {
        use crate::events::StatusKind;
        let health = crate::health::HealthState::new();
        let mut out = String::new();
        render_health_metrics(&mut out, Some(&health));

        // The tip-age gauge always renders.
        assert!(out.contains("satd_tip_last_connect_age_seconds 0"), "{out}");
        // Disk is omitted until sampled, rather than reported as zero free.
        assert!(
            !out.contains("satd_disk_free_bytes"),
            "an unsampled disk reading must be omitted, not zeroed:\n{out}"
        );
        // Every standing condition has a series from the first scrape, so an
        // alerting rule can reference one before it ever fires.
        for kind in StatusKind::ALL {
            let want = format!("satd_alert_active{{kind=\"{}\"}} 0", kind.as_str());
            if kind.is_edge() {
                assert!(
                    !out.contains(&format!("kind=\"{}\"", kind.as_str())),
                    "edge kind {kind:?} has no standing state to report:\n{out}"
                );
            } else {
                assert!(out.contains(&want), "missing series {want}:\n{out}");
            }
        }
    }

    #[test]
    fn health_metrics_reflect_a_raised_condition() {
        use crate::events::StatusKind;
        let health = crate::health::HealthState::new();
        let mut out = String::new();
        render_health_metrics(&mut out, Some(&health));
        assert!(out.contains("satd_alert_active{kind=\"disk_low\"} 0"));

        // Simulate the detector raising `disk_low` with a real reading.
        health.set_active_for_test(StatusKind::DiskLow, true);
        health.set_disk_free_for_test(Some(4096));
        let mut out = String::new();
        render_health_metrics(&mut out, Some(&health));
        assert!(out.contains("satd_alert_active{kind=\"disk_low\"} 1"), "{out}");
        assert!(out.contains("satd_disk_free_bytes 4096"), "{out}");
        // Unrelated conditions stay at 0.
        assert!(out.contains("satd_alert_active{kind=\"tip_stall\"} 0"), "{out}");
    }

    #[test]
    fn policy_metrics_invisible_until_nonempty_ruleset() {
        use crate::mempool::pool::Mempool;
        let mp = Mempool::new(300_000_000, 1_000);

        // No policy ⇒ no policy metrics (byte-identical to engine-compiled-out).
        let mut out = String::new();
        render_policy_metrics(&mut out, &mp);
        assert!(out.is_empty(), "no-policy node must emit zero policy metrics");

        // Empty-but-loaded ruleset (`version 1`) is inert (I8): still nothing —
        // this is the deep-review bug (gating on policy_snapshot() leaked it).
        mp.set_policy(std::sync::Arc::new(
            satd_policy::parse_ruleset("version 1").unwrap(),
        ));
        assert!(!mp.has_policy(), "an empty ruleset is inert");
        let mut out2 = String::new();
        render_policy_metrics(&mut out2, &mp);
        assert!(
            out2.is_empty(),
            "empty-but-loaded ruleset must NOT leak the policy block:\n{out2}"
        );

        // A non-empty ruleset DOES emit the block.
        mp.set_policy(std::sync::Arc::new(
            satd_policy::parse_ruleset("version 1\nquarantine spam when tx.version == 2").unwrap(),
        ));
        let mut out3 = String::new();
        render_policy_metrics(&mut out3, &mp);
        assert!(out3.contains("satd_policy_evaluations_total"));
        assert!(out3.contains("satd_policy_quarantined_total{rule=\"spam\",scope=\"relay+template\"}"));
    }
}
