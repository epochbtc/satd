//! Prometheus-format metrics and health endpoints for operator monitoring.
//!
//! Exposes three HTTP endpoints on a separate unauthenticated listener:
//! - `GET /metrics`  — Prometheus text-format metrics (scrape target)
//! - `GET /healthz`  — 200 if the process is up (Docker/k8s liveness)
//! - `GET /readyz`   — 200 when the chain is within READY_LAG_BLOCKS of the
//!   known headers tip and the connector is making progress, 503 otherwise
//!   (Docker/k8s readiness)
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
    /// Silent-payment-index runtime config, exported as an `enabled` gauge for
    /// the same reason as `addr_enabled`: without it, a `0.0` backfill-progress
    /// reading cannot be told apart from the index being switched off.
    pub sp_enabled: bool,
    /// Live readings from the health detectors. `None` in test backends and
    /// anywhere the detector task was not spawned, in which case the health
    /// gauges are omitted entirely rather than reported as zeros (a zero
    /// `satd_disk_free_bytes` is exactly the alarm an operator must not be
    /// shown falsely).
    pub health: Option<Arc<crate::health::HealthState>>,
    /// Per-hook webhook delivery counters. `None` (or empty) when no alertfile
    /// is configured, in which case the block renders nothing at all.
    pub webhooks: Option<Arc<WebhookMetrics>>,
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
        // Deferred-backfill progress ratio (0.0–1.0), read from the persisted
        // SP-index backfill cursor. A float gauge, so emitted directly rather
        // than via the u64 `metric` helper. Measured from taproot activation,
        // the height the walk actually starts at — from genesis it would sit
        // at ~0.74 on mainnet from the first stamped block onward.
        //
        // 0.0 is deliberately not a "nothing is wrong" signal: it covers an
        // idle cursor, a node whose index was built inline from genesis (and
        // is therefore complete without any backfill having run), and a
        // backfill that has only just started. Never alert on it alone — the
        // `satd_spindex_enabled` / `_synced` / `_backfill_state` gauges below
        // are what distinguish those cases.
        // Read the completeness marker BEFORE the cursor snapshot, and the
        // cursor once for both the ratio and the state gauge.
        //
        // The two live in different writes — `mark_silent_payment_index_complete`
        // is a standalone put, the cursor transition is a `WriteBatch` — so a
        // scrape can still land between them. Ordering the marker first bounds
        // which way that can go: `synced` below requires the cursor to be
        // quiescent, so a straddle can only report `synced 0` for an index
        // that just became complete, never `synced 1` for one that is still
        // walking. Under-claiming readiness for one scrape is safe;
        // over-claiming it is what would make an alert miss.
        let sp_complete = self.chain_state.store_ref().silent_payment_index_complete();
        let sp_cursor = self.chain_state.store_ref().read_sp_backfill_cursor();
        let sp_backfill_ratio =
            sp_cursor.progress_ratio(crate::index::silent_payments::walk_start(self.network));
        let _ = writeln!(
            out,
            "# HELP satd_spindex_backfill_progress_ratio Fraction of the silent-payment-index deferred backfill completed, over the walked span [taproot activation, snapshot]. 1.0 means a deferred backfill ran to completion; 0.0 means no backfill progress and does NOT imply the index is incomplete (an index built inline from genesis needs no backfill and stays at 0.0) - read satd_spindex_synced and satd_spindex_backfill_state to tell those apart; do not alert on this gauge alone."
        );
        let _ = writeln!(out, "# TYPE satd_spindex_backfill_progress_ratio gauge");
        let _ = writeln!(out, "satd_spindex_backfill_progress_ratio {sp_backfill_ratio}");

        // The three gauges that make the ratio interpretable (#535).
        //
        // On its own, `satd_spindex_backfill_progress_ratio == 0.0` means five
        // different things: the index is off; it was built inline from a
        // genesis sync and is complete without a backfill ever running; a
        // backfill completed via the below-activation short-circuit; one has
        // just started; or one failed at or near taproot activation. So
        // neither `ratio == 0` nor `ratio < 1` identifies a problem — the
        // first pages on every node with the index disabled, the second on
        // every healthy from-genesis node, forever. There was no expression
        // over the exported set that answered "is the backfill stuck or
        // failed", which is the only question the gauge exists to support.
        //
        // Together these disambiguate all five: `enabled` separates off from
        // on, `synced` separates complete-without-backfill from incomplete,
        // and the state series separates running from failed from idle.
        metric(
            &mut out,
            "satd_spindex_enabled",
            "1 if the silent-payment tweak index is enabled at runtime, 0 otherwise.",
            "gauge",
            &[],
            u64::from(self.sp_enabled),
        );
        // `synced` is the *serving* predicate, not the raw on-disk marker.
        //
        // `ChainState`'s `SpIndex::is_complete()` — the gate the tweak
        // surfaces actually consult — and `getindexinfo`'s
        // `silentpayments.synced` both require enabled AND the marker AND a
        // quiescent cursor, and `is_complete` carries a comment saying it
        // mirrors the status gate "so the serving surface and the
        // `getindexinfo` status can never disagree". Exporting the bare marker
        // here would have made this the third surface that disagrees with the
        // other two: the marker is stamped at open time and outlives a
        // redundant backfill that is mid-walk or failed, so a node refusing to
        // serve tweaks would have reported `satd_spindex_synced 1`. It also
        // reads 1 on a fresh datadir with the index switched off, until the
        // first block connects and clears it.
        let sp_synced = self.sp_enabled
            && sp_complete
            && matches!(
                sp_cursor.state,
                node_sp_index::cursor::BackfillState::Idle
                    | node_sp_index::cursor::BackfillState::Completed
            );
        metric(
            &mut out,
            "satd_spindex_synced",
            "1 if the silent-payment index is enabled, marked complete on disk, and has no backfill in flight — i.e. the tweak-serving surfaces will return data. Matches getindexinfo's silentpayments.synced. A node that built the index inline from a genesis sync reports 1 with a backfill progress ratio of 0.0.",
            "gauge",
            &[],
            u64::from(sp_synced),
        );
        // One series per state, always present — see `BackfillState::ALL`.
        metric_header(
            &mut out,
            "satd_spindex_backfill_state",
            "Current state of the silent-payment-index deferred backfill: exactly one series is 1, the rest are 0.",
            "gauge",
        );
        for state in node_sp_index::cursor::BackfillState::ALL {
            metric_sample(
                &mut out,
                "satd_spindex_backfill_state",
                &[("state", state.label())],
                u64::from(state == sp_cursor.state),
            );
        }

        // Node-health gauges, rendered only when the detector task is running.
        render_health_metrics(&mut out, self.health.as_deref());

        // Webhook delivery counters, rendered only when a hook is configured.
        render_webhook_metrics(&mut out, self.webhooks.as_deref());

        // Transaction-filtering policy metrics (design §10, PR 7c). Extracted to
        // a free function so the I8-invisibility invariant (a node with no
        // non-empty ruleset renders a byte-identical page) is unit-testable
        // without standing up a full MetricsContext.
        render_policy_metrics(&mut out, &self.mempool);

        out
    }

    /// Render the `/readyz` decision: `Ok` if ready, `Err(reason)` otherwise.
    ///
    /// Note this is readiness, not liveness. `/healthz` stays a plain
    /// process-is-up probe on purpose: a restart loop is a worse answer to a
    /// wedged connector than a node that keeps running and says it is not
    /// ready.
    pub fn is_ready(&self) -> Result<(), String> {
        readiness(
            self.chain_state.warnings(),
            self.chain_state.tip_height(),
            self.chain_state.headers_tip_height(),
        )
    }
}

/// The `/readyz` decision, separated from the state it reads so it can be
/// tested without standing up a live node.
fn readiness(
    warnings: &crate::warnings::NodeWarnings,
    tip: u32,
    headers_tip: u32,
) -> Result<(), String> {
    // A connector that has given up cannot extend the chain, and lag alone
    // does not always catch that — a node wedged at its own tip has no lag to
    // show, and one wedged mid-IBD stops advancing the headers tip too once
    // its peers run out of new ones. On the node that produced #567 the
    // condition stood for five and a half hours while every health surface
    // said fine.
    if warnings
        .list()
        .iter()
        .any(|w| w.id == crate::warnings::CONNECT_PERSISTENT_FAILURE)
    {
        return Err("the block connector cannot make progress".to_string());
    }
    let headers_tip = headers_tip.max(tip);
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

/// Per-hook webhook delivery counters, written by the alert dispatcher in the
/// `satd` binary and rendered here.
///
/// Lives in `node` rather than beside the dispatcher because `satd-alert`
/// depends on `node` (for the health taxonomy), so the reverse dependency
/// needed to render them from here would be a cycle.
#[derive(Debug, Default)]
pub struct HookCounters {
    pub delivered: std::sync::atomic::AtomicU64,
    /// Failed *attempts*, not failed events: a single event retried five times
    /// before succeeding contributes five. This is the signal that an endpoint
    /// is flaky even while it is ultimately keeping up.
    pub failed_attempts: std::sync::atomic::AtomicU64,
    /// Events never delivered: queue overflow, broadcast lag, or a permanent
    /// 4xx. The dead-letter count.
    pub dropped: std::sync::atomic::AtomicU64,
    pub queue_depth: std::sync::atomic::AtomicU64,
    /// Unix seconds of the last 2xx, or 0 if there has never been one.
    pub last_success_unix: std::sync::atomic::AtomicU64,
}

/// Registry of per-hook counters, keyed by hook id.
///
/// A `BTreeMap` so `/metrics` renders hooks in a stable order (Prometheus does
/// not care, but a diffable scrape is worth the ordering), behind an `RwLock`
/// because a SIGHUP reload can add or remove hooks while the endpoint is being
/// scraped.
#[derive(Debug, Default)]
pub struct WebhookMetrics {
    hooks: parking_lot::RwLock<std::collections::BTreeMap<String, Arc<HookCounters>>>,
}

impl WebhookMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a hook's counters. Called on hook registration and on
    /// every delivery, so it must not allocate on the hot path — the common
    /// case is a read-lock hit.
    pub fn hook(&self, id: &str) -> Arc<HookCounters> {
        if let Some(c) = self.hooks.read().get(id) {
            return c.clone();
        }
        let mut w = self.hooks.write();
        w.entry(id.to_string()).or_default().clone()
    }

    /// Forget hooks that are no longer configured, so a removed hook's series
    /// stops being exported instead of freezing at its last value forever.
    pub fn retain(&self, ids: &[String]) {
        self.hooks.write().retain(|k, _| ids.iter().any(|i| i == k));
    }

    pub fn is_empty(&self) -> bool {
        self.hooks.read().is_empty()
    }

    fn snapshot(&self) -> Vec<(String, Arc<HookCounters>)> {
        self.hooks
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// Append the webhook dispatcher's per-hook counters — but only when at least
/// one hook is configured, so a node with no alertfile renders a page
/// byte-identical to a build without the dispatcher (the same invisibility
/// property the policy metrics hold).
fn render_webhook_metrics(out: &mut String, metrics: Option<&WebhookMetrics>) {
    use std::sync::atomic::Ordering;
    let Some(metrics) = metrics.filter(|m| !m.is_empty()) else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Family headers once, then one labelled sample per hook. Emitting a
    // header per hook (as a per-sample `metric` call in this loop does) is
    // well-formed with a single webhook configured and invalid with two — the
    // kind of bug that passes every test written against one hook and breaks
    // an operator's whole scrape page the day they add a second.
    let snapshot = metrics.snapshot();
    for (name, help, kind) in [
        (
            "satd_alertwebhook_delivered_total",
            "Webhook events acknowledged (2xx) by the receiver.",
            "counter",
        ),
        (
            "satd_alertwebhook_failed_attempts_total",
            "Webhook delivery attempts that failed (retried or dropped).",
            "counter",
        ),
        (
            "satd_alertwebhook_dropped_total",
            "Webhook events never delivered (queue overflow, broadcast lag, or a permanent 4xx).",
            "counter",
        ),
        (
            "satd_alertwebhook_queue_depth",
            "Events currently queued for this webhook.",
            "gauge",
        ),
        // Age rather than a timestamp: an alerting rule wants "no successful
        // delivery in N minutes", which is awkward to express against an
        // absolute epoch value. 0 before the first success, which reads as
        // "fresh" — so pair it with `delivered_total > 0` in a rule.
        (
            "satd_alertwebhook_last_success_age_seconds",
            "Seconds since this webhook's last acknowledged delivery (0 if none yet).",
            "gauge",
        ),
    ] {
        metric_header(out, name, help, kind);
        for (id, c) in &snapshot {
            let labels = [("hook", id.as_str())];
            let last = c.last_success_unix.load(Ordering::Relaxed);
            let value = match name {
                "satd_alertwebhook_delivered_total" => c.delivered.load(Ordering::Relaxed),
                "satd_alertwebhook_failed_attempts_total" => {
                    c.failed_attempts.load(Ordering::Relaxed)
                }
                "satd_alertwebhook_dropped_total" => c.dropped.load(Ordering::Relaxed),
                "satd_alertwebhook_queue_depth" => c.queue_depth.load(Ordering::Relaxed),
                _ if last == 0 => 0,
                _ => now.saturating_sub(last),
            };
            metric_sample(out, name, &labels, value);
        }
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

    /// A wedged connector must fail readiness even when the chain lag looks
    /// fine. Lag was the only input, and the mainnet node behind #567 sat at
    /// its own tip failing every connect for five and a half hours while
    /// `/readyz` returned 200 throughout.
    #[test]
    fn a_wedged_connector_is_not_ready() {
        let warnings = crate::warnings::NodeWarnings::new();
        assert_eq!(readiness(&warnings, 100, 100), Ok(()));

        warnings.record(
            crate::warnings::CONNECT_PERSISTENT_FAILURE,
            crate::warnings::Severity::Error,
            "cannot connect block 101".to_string(),
            serde_json::Value::Null,
        );
        let reason = readiness(&warnings, 100, 100).expect_err("not ready while wedged");
        assert!(reason.contains("connector"), "reason was: {reason}");

        // And recovers when the connector does.
        warnings.clear(crate::warnings::CONNECT_PERSISTENT_FAILURE);
        assert_eq!(readiness(&warnings, 100, 100), Ok(()));
    }

    /// An unrelated standing warning must not hold readiness down — a probe
    /// that fails on anything in the registry is a probe operators turn off.
    #[test]
    fn an_unrelated_warning_does_not_affect_readiness() {
        let warnings = crate::warnings::NodeWarnings::new();
        warnings.record(
            "storage.flush_coin_cache_failed",
            crate::warnings::Severity::Error,
            "transient".to_string(),
            serde_json::Value::Null,
        );
        assert_eq!(readiness(&warnings, 100, 100), Ok(()));
        assert!(readiness(&warnings, 100, 100 + READY_LAG_BLOCKS + 1).is_err());
    }

    #[test]
    fn metric_line_format_matches_prometheus_spec() {
        let mut out = String::new();
        metric(&mut out, "foo_bar", "help text", "gauge", &[], 42);
        assert!(out.contains("# HELP foo_bar help text\n"));
        assert!(out.contains("# TYPE foo_bar gauge\n"));
        assert!(out.contains("foo_bar 42\n"));
    }

    /// The property that makes the SP backfill alertable (#535): every state
    /// gets a series, and exactly one of them is 1.
    ///
    /// Mirrors the emission in `render_prometheus`, which needs a live
    /// `ChainState` and so cannot be driven from a unit test. What is asserted
    /// here is the part that can silently rot — a missing series reads as
    /// "absent" to Prometheus, and an alert on an absent series never fires.
    #[test]
    fn sp_backfill_state_series_is_exhaustive_and_one_hot() {
        use node_sp_index::cursor::BackfillState;

        // Written out rather than derived from `ALL`, deliberately. A test that
        // both emits and asserts over `ALL` uses the thing under test as its
        // own oracle: drop a state and the test stays green because both sides
        // dropped it together. This list is the independent expectation — the
        // set of series an operator's alerting rules are allowed to depend on.
        const EXPECTED: [&str; 7] = [
            "idle",
            "running",
            "paused",
            "completed",
            "cancelled",
            "rejected",
            "failed",
        ];

        for current in BackfillState::ALL {
            let mut out = String::new();
            metric_header(&mut out, "satd_spindex_backfill_state", "help", "gauge");
            for state in BackfillState::ALL {
                metric_sample(
                    &mut out,
                    "satd_spindex_backfill_state",
                    &[("state", state.label())],
                    u64::from(state == current),
                );
            }

            // Exactly one `# HELP`/`# TYPE` pair: a repeated header makes a
            // strict parser discard the entire page, taking every unrelated
            // satd metric down with it.
            assert_eq!(out.matches("# HELP").count(), 1);
            assert_eq!(out.matches("# TYPE").count(), 1);

            for label in EXPECTED {
                let expected = u64::from(label == current.label());
                let line =
                    format!("satd_spindex_backfill_state{{state=\"{label}\"}} {expected}\n");
                assert!(
                    out.contains(&line),
                    "missing or wrong series for state={label:?} while current is {current:?}:\n{out}"
                );
            }
            assert_eq!(
                out.lines().filter(|l| l.starts_with("satd_")).count(),
                EXPECTED.len(),
                "series count must match the expected state set exactly"
            );
            assert_eq!(
                out.lines().filter(|l| l.ends_with(" 1")).count(),
                1,
                "exactly one series must be hot"
            );
        }
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
    fn webhook_metrics_are_valid_exposition_format_with_several_hooks() {
        // Two hooks, because one hook cannot expose this: a header-per-sample
        // renderer is well-formed with a single series and invalid with two.
        // A strict parser rejects the entire page on the duplicate `# HELP`,
        // so an operator adding a second webhook would lose every metric satd
        // exports, not just these.
        let m = WebhookMetrics::default();
        let _ = m.hook("pager");
        let _ = m.hook("deadman");
        let _ = m.hook("relay");
        let mut out = String::new();
        render_webhook_metrics(&mut out, Some(&m));
        assert_one_header_per_family(&out);
        // And every hook is still represented.
        for id in ["pager", "deadman", "relay"] {
            assert!(
                out.contains(&format!("satd_alertwebhook_delivered_total{{hook=\"{id}\"}}")),
                "missing series for {id}:\n{out}"
            );
        }
    }

    #[test]
    fn webhook_metrics_invisible_until_a_hook_is_configured() {
        use std::sync::atomic::Ordering;
        // No registry, and an empty registry, both render nothing: a node with
        // no alertfile must produce a page byte-identical to one built without
        // the dispatcher.
        let mut out = String::new();
        render_webhook_metrics(&mut out, None);
        assert!(out.is_empty(), "{out}");

        let m = WebhookMetrics::new();
        let mut out = String::new();
        render_webhook_metrics(&mut out, Some(&m));
        assert!(out.is_empty(), "an empty registry must leak nothing:\n{out}");

        // A registered hook exports its counters, labelled by id.
        let c = m.hook("ops");
        c.delivered.store(7, Ordering::Relaxed);
        c.dropped.store(2, Ordering::Relaxed);
        let mut out = String::new();
        render_webhook_metrics(&mut out, Some(&m));
        assert!(out.contains(r#"satd_alertwebhook_delivered_total{hook="ops"} 7"#), "{out}");
        assert!(out.contains(r#"satd_alertwebhook_dropped_total{hook="ops"} 2"#), "{out}");
        assert!(out.contains(r#"satd_alertwebhook_queue_depth{hook="ops"} 0"#), "{out}");
    }

    #[test]
    fn removed_hooks_stop_being_exported() {
        // Otherwise a hook deleted on SIGHUP would keep exporting its last
        // values forever, and an alerting rule on it could never recover.
        let m = WebhookMetrics::new();
        m.hook("old");
        m.hook("new");
        m.retain(&["new".to_string()]);
        let mut out = String::new();
        render_webhook_metrics(&mut out, Some(&m));
        assert!(out.contains(r#"hook="new""#), "{out}");
        assert!(!out.contains(r#"hook="old""#), "{out}");
    }

    #[test]
    fn last_success_age_is_zero_before_the_first_delivery() {
        use std::sync::atomic::Ordering;
        // An age computed from an unset (0) timestamp would render as ~57 years
        // and read as a catastrophic outage on a node that simply has not
        // delivered anything yet.
        let m = WebhookMetrics::new();
        m.hook("ops");
        let mut out = String::new();
        render_webhook_metrics(&mut out, Some(&m));
        assert!(
            out.contains(r#"satd_alertwebhook_last_success_age_seconds{hook="ops"} 0"#),
            "{out}"
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        m.hook("ops")
            .last_success_unix
            .store(now.saturating_sub(30), Ordering::Relaxed);
        let mut out = String::new();
        render_webhook_metrics(&mut out, Some(&m));
        assert!(
            out.contains(r#"satd_alertwebhook_last_success_age_seconds{hook="ops"} 3"#),
            "expected an age around 30s:\n{out}"
        );
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
