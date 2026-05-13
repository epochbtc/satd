use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::collections::{HashMap, VecDeque};

const HISTORY_CAP: usize = 60;

/// Tracks which data groups have been loaded at least once.
#[derive(Debug, Clone, Default)]
pub struct Loaded {
    pub chain_info: bool,
    pub peers: bool,
    pub mempool: bool,
    pub block_stats: bool,
    pub fee_estimates: bool,
    pub utxo: bool,
    pub mining: bool,
    pub tx_stats: bool,
    pub uptime: bool,
    pub ibd_progress: bool,
    pub mempool_dist: bool,
    pub system: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Ibd,
    Steady,
    Mempool,
    Chain,
}

/// One snapshot from getmempoolhistory.
#[derive(Debug, Clone)]
pub struct MempoolSnapshot {
    pub ts_unix_secs: u64,
    pub size: u64,
    pub bytes: u64,
    pub min_fee_rate_sat_per_kvb: u64,
    pub max_fee_rate_sat_per_kvb: u64,
    pub histogram: Vec<HistogramBucket>,
}

#[derive(Debug, Clone)]
pub struct HistogramBucket {
    pub feerate_sat_per_kvb: u64,
    pub weight: u64,
}

/// Top-N mempool entry by ancestor feerate (derived from getrawmempool verbose).
#[derive(Debug, Clone)]
pub struct MempoolTopEntry {
    pub txid: String,
    pub vsize: u64,
    /// sat/vB.
    pub ancestor_feerate: f64,
    pub ancestor_count: u32,
    pub descendant_count: u32,
    pub age_secs: u64,
}

/// One reorg record from getreorghistory.
#[derive(Debug, Clone)]
pub struct ReorgEntry {
    pub ts_unix_secs: u64,
    pub depth: u32,
    pub fork_height: u32,
    pub old_tip: String,
    pub new_tip: String,
    pub disconnected_len: usize,
    pub reconnected_len: usize,
}

/// Active warning surfaced from the node's `getwarnings` RPC.
#[derive(Debug, Clone)]
pub struct NodeWarning {
    pub id: String,
    pub severity: WarningSeverity,
    pub message: String,
    pub first_seen_unix_secs: u64,
    /// Kept for future enrichment; modal currently shows first_seen + count.
    #[allow(dead_code)]
    pub last_seen_unix_secs: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningSeverity {
    Error,
    Warn,
}

/// 4-tier fee summary derived from estimatefees (mempool.space convention).
#[derive(Debug, Clone, Default)]
pub struct FeeSummary {
    /// sat/vB for the 1-block target.
    pub high: Option<f64>,
    /// sat/vB for the 3-block target.
    pub medium: Option<f64>,
    /// sat/vB for the 6-block target.
    pub low: Option<f64>,
    /// sat/vB for economy (min-relay-floor clamp).
    pub none: Option<f64>,
    pub confidence: Option<String>,
    pub mode: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeerDownloadStat {
    pub peer_id: u64,
    pub blocks_received: u64,
    pub assigned: usize,
}

#[derive(Debug, Clone)]
pub struct IbdBitmap {
    pub connect_cursor: u32,
    pub target_height: u32,
    pub bitmap_start: u32,
    pub bitmap: Vec<u8>,
    pub downloaded: usize,
    pub in_flight: usize,
    pub pending: usize,
    pub peer_stats: Vec<PeerDownloadStat>,
}

impl IbdBitmap {
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        if !v.get("active")?.as_bool()? {
            return None;
        }
        let bitmap_b64 = v.get("bitmap")?.as_str()?;
        let bitmap = BASE64.decode(bitmap_b64).ok()?;
        let peer_stats = v.get("peer_download_stats")?
            .as_array()?
            .iter()
            .filter_map(|p| {
                Some(PeerDownloadStat {
                    peer_id: p.get("peer_id")?.as_u64()?,
                    blocks_received: p.get("blocks_received")?.as_u64()?,
                    assigned: p.get("assigned")?.as_u64()? as usize,
                })
            })
            .collect();

        Some(IbdBitmap {
            connect_cursor: v.get("connect_cursor")?.as_u64()? as u32,
            target_height: v.get("target_height")?.as_u64()? as u32,
            bitmap_start: v.get("bitmap_start")?.as_u64()? as u32,
            bitmap,
            downloaded: v.get("downloaded")?.as_u64()? as usize,
            in_flight: v.get("in_flight")?.as_u64()? as usize,
            pending: v.get("pending")?.as_u64()? as usize,
            peer_stats,
        })
    }
}

/// Snapshot of the address-index backfill from `getindexinfo`. Only
/// surfaced in the UI when state is one of `running`, `paused`, or
/// `failed` — `idle`, `completed`, `cancelled`, `rejected` are quiet.
#[derive(Debug, Clone)]
pub struct BackfillProgress {
    /// State label as reported by the daemon: `running` | `paused` |
    /// `completed` | `failed` | `cancelled` | `rejected` | `idle`.
    pub state: String,
    pub pass: u8,
    pub cursor_height: u32,
    pub snapshot_height: u32,
    pub estimated_remaining_seconds: u64,
    /// Populated when state == "failed".
    pub last_error: Option<String>,
}

/// Snapshot of the runtime listener status from `getserverstatus`.
/// Drives the steady-view services row.
///
/// Each listener field is tri-state so the renderer can distinguish
/// "not yet polled / older satd / transient RPC error" from
/// "explicitly not bound." Conflating them silently mislabels a
/// disconnected TUI as "all servers off."
#[derive(Debug, Clone, Default)]
pub struct ServerStatus {
    pub addressindex: ListenerView<AddressIndexStatus>,
    pub esplora: ListenerView<ListenerStatus>,
    pub electrum: ListenerView<ListenerStatus>,
    pub electrum_tls: ListenerView<ListenerStatus>,
}

/// Tri-state view of a listener's runtime status.
///
/// - `Unknown`: getserverstatus has not returned a usable response
///   for this field yet (first poll, transient RPC error, satd build
///   without `getserverstatus`, or a malformed sub-field).
/// - `NotBound`: getserverstatus returned `null` for this listener.
///   The server is not currently bound — either disabled in config
///   or skipped by a runtime gate (e.g. Esplora skipped when
///   `--addressindex=0` is paired with the default `--esplora=1`).
/// - `Bound(t)`: listener is actively serving on the carried address.
#[derive(Debug, Clone, Default)]
pub enum ListenerView<T> {
    #[default]
    Unknown,
    NotBound,
    Bound(T),
}

#[derive(Debug, Clone)]
pub struct AddressIndexStatus {
    pub enabled: bool,
    /// Reflects the on-disk `address_index.complete` marker, which the
    /// Electrum / Esplora servers use as a hard gate. False means a
    /// backfill (or fresh sync) is still required before those servers
    /// can answer history queries safely.
    pub complete: bool,
}

#[derive(Debug, Clone)]
pub struct ListenerStatus {
    pub bind: String,
}

impl ServerStatus {
    pub fn from_json(v: &serde_json::Value) -> Self {
        Self {
            addressindex: parse_addressindex(v.get("addressindex")),
            esplora: parse_listener_view(v.get("esplora")),
            electrum: parse_listener_view(v.get("electrum")),
            electrum_tls: parse_listener_view(v.get("electrum_tls")),
        }
    }
}

fn parse_addressindex(v: Option<&serde_json::Value>) -> ListenerView<AddressIndexStatus> {
    let v = match v {
        Some(v) if !v.is_null() => v,
        _ => return ListenerView::Unknown,
    };
    match (v.get("enabled").and_then(|x| x.as_bool()), v.get("complete").and_then(|x| x.as_bool())) {
        (Some(enabled), Some(complete)) => ListenerView::Bound(AddressIndexStatus { enabled, complete }),
        _ => ListenerView::Unknown,
    }
}

fn parse_listener_view(v: Option<&serde_json::Value>) -> ListenerView<ListenerStatus> {
    let Some(v) = v else { return ListenerView::Unknown };
    if v.is_null() {
        return ListenerView::NotBound;
    }
    match v.get("bind").and_then(|b| b.as_str()) {
        Some(bind) => ListenerView::Bound(ListenerStatus { bind: bind.to_string() }),
        // Object present but no usable bind — treat as unknown rather
        // than guessing at "off."
        None => ListenerView::Unknown,
    }
}

impl BackfillProgress {
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let bf = v.get("address")?.get("backfill")?;
        let state = bf.get("state")?.as_str()?.to_string();
        Some(BackfillProgress {
            state,
            pass: bf.get("pass").and_then(|p| p.as_u64()).unwrap_or(0) as u8,
            cursor_height: bf.get("cursor_height").and_then(|h| h.as_u64()).unwrap_or(0) as u32,
            snapshot_height: bf.get("snapshot_height").and_then(|h| h.as_u64()).unwrap_or(0) as u32,
            estimated_remaining_seconds: bf
                .get("estimated_remaining_seconds")
                .and_then(|s| s.as_u64())
                .unwrap_or(0),
            last_error: bf.get("last_error").and_then(|s| s.as_str()).map(str::to_string),
        })
    }

    /// True only for states that warrant rendering a status row.
    pub fn is_visible(&self) -> bool {
        matches!(self.state.as_str(), "running" | "paused" | "failed")
    }

    /// Progress ratio across both passes (0.0..=1.0).
    pub fn progress_ratio(&self) -> f64 {
        if self.snapshot_height == 0 {
            return 0.0;
        }
        let total = 2u64 * self.snapshot_height as u64;
        let done = match self.pass {
            1 => self.cursor_height as u64,
            2 => self.snapshot_height as u64 + self.cursor_height as u64,
            _ => 0,
        };
        (done as f64 / total as f64).clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone)]
pub struct AppState {
    // From RPCs
    pub chain_name: String,
    pub blocks: u32,
    pub headers: u32,
    /// Highest block height reported by any connected peer (true chain tip).
    pub network_height: u32,
    pub best_block_hash: String,
    pub difficulty: f64,
    pub chain_time: u64,
    pub is_ibd: bool,
    pub verification_progress: f64,
    /// Hex-encoded cumulative chain work (256-bit big-endian).
    pub chainwork_hex: String,

    // Difficulty-epoch anchor — cached header.time at floor(blocks/2016)*2016.
    // Refreshed only when the floor advances (≈ once per fortnight).
    pub epoch_start_height: Option<u32>,
    pub epoch_start_time: Option<u64>,

    pub peers: Vec<serde_json::Value>,
    pub mempool_size: u64,
    pub mempool_bytes: u64,
    pub mempool_min_fee: f64,
    pub connections: usize,

    // Steady-state extras
    pub block_stats_txs: Option<u64>,
    pub block_stats_total_fee: Option<u64>,
    pub block_stats_avg_fee_rate: Option<f64>,
    pub block_stats_size: Option<u64>,
    pub block_stats_weight: Option<u64>,

    pub fees: FeeSummary,
    pub utxo_count: Option<u64>,
    pub utxo_total_amount: Option<f64>,
    pub utxo_age_dist: Option<[u64; 8]>,
    pub network_hash_ps: Option<f64>,
    pub tx_rate: Option<f64>,
    pub uptime_secs: Option<u64>,
    pub last_block_secs_ago: Option<u64>,
    pub mempool_size_dist: Option<[u32; 8]>,

    // System resources
    pub rss_bytes: Option<u64>,
    pub thread_count: Option<u32>,
    pub cache_dirty: Option<u32>,
    pub cache_clean: Option<usize>,
    /// "clean" | "dirty" — from getsysteminfo.last_shutdown (PR #60).
    pub last_shutdown: Option<String>,

    // Reorg history (from getreorghistory)
    pub reorg_history: Vec<ReorgEntry>,

    // Active node warnings (from getwarnings)
    pub warnings: Vec<NodeWarning>,
    /// Per-id dismissal — keys that the operator has acknowledged for
    /// the current session. Cleared when the id clears server-side.
    pub dismissed_warnings: std::collections::HashSet<String>,

    // Mempool-pane data
    pub mempool_history: Vec<MempoolSnapshot>,
    /// False when the node started without a writable history log.
    pub mempool_history_available: bool,
    pub mempool_top: Vec<MempoolTopEntry>,
    pub selected_mempool_row: usize,

    // Computed deltas
    pub blocks_per_sec: f64,
    pub headers_per_sec: f64,
    pub dl_blocks_per_sec: f64,
    pub eta_secs: Option<u64>,

    // History (last 60 samples ~ 90 seconds)
    pub bps_history: VecDeque<f64>,
    pub dl_history: VecDeque<f64>,

    // Per-peer block download rate (peer_id → blk/s)
    pub peer_dl_rates: HashMap<u64, f64>,

    // IBD block map
    pub ibd_bitmap: Option<IbdBitmap>,

    // Address-index backfill — None when no backfill cursor exists or
    // when the response shape couldn't be parsed.
    pub backfill: Option<BackfillProgress>,

    /// Listener and address-index status from `getserverstatus`. Drives
    /// the always-visible services row in the steady view.
    pub server_status: ServerStatus,

    // UI state
    pub mode: ViewMode,
    pub force_mode: Option<ViewMode>,
    pub selected_peer: usize,
    pub show_help: bool,
    pub show_reorgs: bool,

    // Internal tracking
    prev_blocks: u32,
    prev_headers: u32,
    prev_total_downloaded: u64,
    prev_peer_blocks: HashMap<u64, u64>,
    pub connected: bool,
    pub last_poll: Option<std::time::Instant>,
    pub stale: bool,
    pub loaded: Loaded,
    /// Structured startup-progress response from `getstartupinfo`.
    /// `Some` while satd is in pre-RPC startup (opening DB, reindex, etc.);
    /// `None` once the full RPC server is up and `getblockchaininfo` succeeds.
    pub startup_status: Option<StartupStatus>,
    /// Wall-clock time of the first startup-status poll. Used by the
    /// startup panel to compute elapsed / rate / ETA.
    pub startup_started_at: Option<std::time::Instant>,
    /// Per-phase wall-clock anchor — reset on phase transition so rate
    /// and ETA reflect the *current* phase rather than the whole startup.
    pub startup_phase_started_at: Option<std::time::Instant>,
    /// Last-seen phase, used to detect transitions.
    pub startup_phase: String,
    /// Rolling samples of `(t, current)` for rate estimation. Capped
    /// at ~30 entries (~45 s at the 1.5 s poll cadence).
    pub startup_samples: VecDeque<(std::time::Instant, u64)>,

    /// Last RPC failure observed by the poller. `Some` from the first
    /// failed batch until any RPC in a subsequent batch succeeds. The
    /// failure modal reads this to surface hard errors (auth, connect)
    /// prominently — without it the UI silently sits on "Connecting..."
    /// forever.
    pub last_failure: Option<RpcFailureRecord>,
}

/// Categorised RPC failure for modal display. Mirrors `rpc::RpcError`
/// but lives in state so the UI layer doesn't import rpc types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcFailure {
    AuthFailed,
    ConnectionFailed,
    Timeout,
    Other,
}

#[derive(Debug, Clone)]
pub struct RpcFailureRecord {
    pub kind: RpcFailure,
    pub message: String,
    pub first_seen: std::time::Instant,
}

/// Structured startup-progress response from `getstartupinfo`.
#[derive(Debug, Clone, Default)]
pub struct StartupStatus {
    pub phase: String,
    pub message: String,
    pub current: u64,
    pub total: u64,
    /// `Some(h)` when the active phase honors `-stopatheight`: reindex
    /// will halt cleanly at height `h` even if the on-disk block files
    /// extend past it (`total > stop_height`).
    pub stop_height: Option<u64>,
}

impl StartupStatus {
    pub fn from_json(v: &serde_json::Value) -> Self {
        Self {
            phase: v.get("phase").and_then(|s| s.as_str()).unwrap_or("").to_string(),
            message: v.get("status").and_then(|s| s.as_str()).unwrap_or("").to_string(),
            current: v.get("current").and_then(|n| n.as_u64()).unwrap_or(0),
            total: v.get("total").and_then(|n| n.as_u64()).unwrap_or(0),
            stop_height: v.get("stop_height").and_then(|n| n.as_u64()),
        }
    }

    /// Human-readable line: "Replaying blocks (phase 2/2) [reindex_connect]:
    /// 234567/945000 (24.8%)". Kept for tests / fallback callers; the
    /// rich panel renders its own layout.
    #[allow(dead_code)]
    pub fn render(&self) -> String {
        let phase_tag = if self.phase.is_empty() {
            String::new()
        } else {
            format!(" [{}]", self.phase)
        };
        if self.total > 0 {
            let pct = (self.current as f64 / self.total as f64) * 100.0;
            format!(
                "{}{}: {}/{} ({:.1}%)",
                self.message, phase_tag, self.current, self.total, pct
            )
        } else if !self.message.is_empty() {
            format!("{}{}", self.message, phase_tag)
        } else {
            "satd is starting...".to_string()
        }
    }
}

/// Compute log2 of a hex-encoded big-endian integer without materializing it.
/// Returns None for empty/all-zero input.
///
/// Strategy: locate the most-significant non-zero hex digit, take it plus the
/// next ~13 hex digits as a u64 mantissa, then add log2(mantissa) to the bit
/// offset of the consumed prefix. Accuracy is well within 0.001 bits.
pub fn chain_work_bits_from_hex(hex_str: &str) -> Option<f64> {
    let s = hex_str.trim_start_matches('0');
    if s.is_empty() {
        return None;
    }
    // Take up to 14 hex digits (56 bits) for the mantissa — fits in a u64
    // with headroom for the f64 conversion to keep all bits significant.
    let take = s.len().min(14);
    let mantissa_hex = &s[..take];
    let mantissa = u64::from_str_radix(mantissa_hex, 16).ok()?;
    if mantissa == 0 {
        return None;
    }
    // Total bits represented by `s` = (s.len() - 1) full nibbles after the
    // leading nibble + the bit-width of the leading nibble itself.
    // log2(value) = log2(mantissa) + 4 * (s.len() - take)
    let tail_nibbles = (s.len() - take) as f64;
    Some((mantissa as f64).log2() + 4.0 * tail_nibbles)
}

impl AppState {
    pub fn new() -> Self {
        Self {
            chain_name: String::new(),
            blocks: 0,
            headers: 0,
            network_height: 0,
            best_block_hash: String::new(),
            difficulty: 0.0,
            chain_time: 0,
            is_ibd: false,
            verification_progress: 0.0,
            chainwork_hex: String::new(),
            epoch_start_height: None,
            epoch_start_time: None,

            peers: Vec::new(),
            mempool_size: 0,
            mempool_bytes: 0,
            mempool_min_fee: 0.0,
            connections: 0,

            block_stats_txs: None,
            block_stats_total_fee: None,
            block_stats_avg_fee_rate: None,
            block_stats_size: None,
            block_stats_weight: None,

            fees: FeeSummary::default(),
            utxo_count: None,
            utxo_total_amount: None,
            utxo_age_dist: None,
            network_hash_ps: None,
            tx_rate: None,
            uptime_secs: None,
            last_block_secs_ago: None,
            mempool_size_dist: None,

            rss_bytes: None,
            thread_count: None,
            cache_dirty: None,
            cache_clean: None,
            last_shutdown: None,

            reorg_history: Vec::new(),

            warnings: Vec::new(),
            dismissed_warnings: std::collections::HashSet::new(),

            mempool_history: Vec::new(),
            mempool_history_available: true,
            mempool_top: Vec::new(),
            selected_mempool_row: 0,

            blocks_per_sec: 0.0,
            headers_per_sec: 0.0,
            dl_blocks_per_sec: 0.0,
            eta_secs: None,

            bps_history: VecDeque::with_capacity(HISTORY_CAP),
            dl_history: VecDeque::with_capacity(HISTORY_CAP),

            peer_dl_rates: HashMap::new(),

            ibd_bitmap: None,
            backfill: None,
            server_status: ServerStatus::default(),

            mode: ViewMode::Steady,
            force_mode: None,
            selected_peer: 0,
            show_help: false,
            show_reorgs: false,

            prev_blocks: 0,
            prev_headers: 0,
            prev_total_downloaded: 0,
            prev_peer_blocks: HashMap::new(),
            connected: false,
            last_poll: None,
            stale: false,
            loaded: Loaded::default(),
            startup_status: None,
            startup_started_at: None,
            startup_phase_started_at: None,
            startup_phase: String::new(),
            startup_samples: VecDeque::with_capacity(32),
            last_failure: None,
        }
    }

    /// Record an RPC failure observed by the poller. Re-recording the
    /// same kind keeps the original `first_seen` so the failure modal
    /// can display "failing for Ns".
    pub fn record_failure(&mut self, kind: RpcFailure, message: String) {
        match &mut self.last_failure {
            Some(rec) if rec.kind == kind => {
                rec.message = message;
            }
            _ => {
                self.last_failure = Some(RpcFailureRecord {
                    kind,
                    message,
                    first_seen: std::time::Instant::now(),
                });
            }
        }
    }

    /// Clear any tracked failure — called from `mark_poll` when an RPC
    /// succeeds, so the modal dismisses automatically the moment the
    /// connection recovers.
    pub fn clear_failure(&mut self) {
        self.last_failure = None;
    }

    /// Push a fresh startup-progress sample. Resets the rolling window
    /// when the phase changes so per-phase rate stays accurate.
    pub fn update_startup(&mut self, status: StartupStatus) {
        let now = std::time::Instant::now();
        if self.startup_started_at.is_none() {
            self.startup_started_at = Some(now);
        }
        if self.startup_phase != status.phase {
            self.startup_phase = status.phase.clone();
            self.startup_phase_started_at = Some(now);
            self.startup_samples.clear();
        }
        if self.startup_phase_started_at.is_none() {
            self.startup_phase_started_at = Some(now);
        }
        self.startup_samples.push_back((now, status.current));
        while self.startup_samples.len() > 30 {
            self.startup_samples.pop_front();
        }
        self.startup_status = Some(status);
    }

    /// Clear startup tracking — called once the full RPC server replies.
    pub fn clear_startup(&mut self) {
        self.startup_status = None;
        self.startup_started_at = None;
        self.startup_phase_started_at = None;
        self.startup_phase.clear();
        self.startup_samples.clear();
    }

    /// Items per second over the rolling window. `None` if the window is
    /// empty or spans less than 1 second.
    pub fn startup_rate(&self) -> Option<f64> {
        if self.startup_samples.len() < 2 {
            return None;
        }
        let (t0, c0) = self.startup_samples.front().copied()?;
        let (t1, c1) = self.startup_samples.back().copied()?;
        let dt = t1.duration_since(t0).as_secs_f64();
        if dt < 1.0 || c1 <= c0 {
            return None;
        }
        Some((c1 - c0) as f64 / dt)
    }

    /// Estimated seconds remaining for the current phase. Only meaningful
    /// after a few samples — returns `None` until the rolling window has
    /// enough data and `total` is known.
    pub fn startup_eta_secs(&self) -> Option<u64> {
        let status = self.startup_status.as_ref()?;
        if status.total == 0 || status.current >= status.total {
            return None;
        }
        let rate = self.startup_rate()?;
        if rate <= 0.0 {
            return None;
        }
        let remaining = (status.total - status.current) as f64 / rate;
        Some(remaining as u64)
    }

    /// Update from getblockchaininfo response.
    pub fn update_chain_info(&mut self, v: &serde_json::Value) {
        self.loaded.chain_info = true;
        self.chain_name = v.get("chain").and_then(|c| c.as_str()).unwrap_or("").to_string();
        let new_blocks = v.get("blocks").and_then(|b| b.as_u64()).unwrap_or(0) as u32;
        let new_headers = v.get("headers").and_then(|h| h.as_u64()).unwrap_or(0) as u32;
        self.best_block_hash = v.get("bestblockhash").and_then(|h| h.as_str()).unwrap_or("").to_string();
        self.difficulty = v.get("difficulty").and_then(|d| d.as_f64()).unwrap_or(0.0);
        self.chain_time = v.get("time").and_then(|t| t.as_u64()).unwrap_or(0);
        self.is_ibd = v.get("initialblockdownload").and_then(|b| b.as_bool()).unwrap_or(false);
        self.verification_progress = v.get("verificationprogress").and_then(|p| p.as_f64()).unwrap_or(0.0);
        if let Some(s) = v.get("chainwork").and_then(|c| c.as_str()) {
            self.chainwork_hex = s.to_string();
        }

        // Compute deltas
        if let Some(last) = self.last_poll {
            let dt = last.elapsed().as_secs_f64();
            if dt > 0.1 {
                let raw_bps = (new_blocks.saturating_sub(self.prev_blocks)) as f64 / dt;
                let raw_hps = (new_headers.saturating_sub(self.prev_headers)) as f64 / dt;

                // EMA smoothing (alpha=0.2)
                self.blocks_per_sec = 0.2 * raw_bps + 0.8 * self.blocks_per_sec;
                self.headers_per_sec = 0.2 * raw_hps + 0.8 * self.headers_per_sec;

                // History
                self.bps_history.push_back(self.blocks_per_sec);
                if self.bps_history.len() > HISTORY_CAP {
                    self.bps_history.pop_front();
                }

                // ETA — only set here as a fallback when server-side ETA is
                // not available (non-IBD path or stale IBD progress data).
                // During active IBD, update_ibd_progress() provides a
                // weight-aware ETA from the daemon.
                if self.ibd_bitmap.is_none() {
                    let target = self.network_height.max(new_headers);
                    if self.blocks_per_sec > 0.01 && target > new_blocks {
                        self.eta_secs = Some(((target - new_blocks) as f64 / self.blocks_per_sec) as u64);
                    } else {
                        self.eta_secs = None;
                    }
                }
            }
        }

        self.prev_blocks = new_blocks;
        self.prev_headers = new_headers;
        self.blocks = new_blocks;
        self.headers = new_headers;

        // Compute last_block_secs_ago
        if self.chain_time > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.last_block_secs_ago = Some(now.saturating_sub(self.chain_time));
        }

        // Auto-detect mode
        if self.force_mode.is_none() {
            self.mode = if self.is_ibd { ViewMode::Ibd } else { ViewMode::Steady };
        }
    }

    /// Update from getpeerinfo response.
    pub fn update_peers(&mut self, v: &serde_json::Value) {
        self.loaded.peers = true;
        if let Some(arr) = v.as_array() {
            // Track max peer height (true network chain tip)
            let max_height = arr.iter()
                .filter_map(|p| p.get("startingheight").and_then(|h| h.as_u64()))
                .max()
                .unwrap_or(0) as u32;
            if max_height > self.network_height {
                self.network_height = max_height;
            }

            self.peers = arr.clone();
        }
    }

    /// Update from getmempoolinfo response.
    pub fn update_mempool_info(&mut self, v: &serde_json::Value) {
        self.loaded.mempool = true;
        self.mempool_size = v.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
        self.mempool_bytes = v.get("bytes").and_then(|b| b.as_u64()).unwrap_or(0);
        self.mempool_min_fee = v.get("mempoolminfee").and_then(|f| f.as_f64()).unwrap_or(0.0);
    }

    /// Update from getconnectioncount response.
    pub fn update_connections(&mut self, v: &serde_json::Value) {
        self.connections = v.as_u64().unwrap_or(0) as usize;
    }

    /// Update from getibdprogress response.
    pub fn update_ibd_progress(&mut self, v: &serde_json::Value) {
        self.loaded.ibd_progress = true;
        self.ibd_bitmap = IbdBitmap::from_json(v);

        if let Some(ref bm) = self.ibd_bitmap {
            if let Some(last) = self.last_poll {
                let dt = last.elapsed().as_secs_f64();
                if dt > 0.1 {
                    // Connect rate (blocks connected / sec)
                    let cursor = bm.connect_cursor;
                    if cursor > self.prev_blocks {
                        let raw_bps = (cursor - self.prev_blocks) as f64 / dt;
                        self.blocks_per_sec = 0.2 * raw_bps + 0.8 * self.blocks_per_sec;
                        self.bps_history.push_back(self.blocks_per_sec);
                        if self.bps_history.len() > HISTORY_CAP {
                            self.bps_history.pop_front();
                        }
                    }

                    // Download rate (blocks downloaded / sec) from total peer blocks_received
                    let total_dl: u64 = bm.peer_stats.iter().map(|s| s.blocks_received).sum();
                    if self.prev_total_downloaded > 0 {
                        let raw_dl = total_dl.saturating_sub(self.prev_total_downloaded) as f64 / dt;
                        self.dl_blocks_per_sec = 0.2 * raw_dl + 0.8 * self.dl_blocks_per_sec;
                        self.dl_history.push_back(self.dl_blocks_per_sec);
                        if self.dl_history.len() > HISTORY_CAP {
                            self.dl_history.pop_front();
                        }
                    }
                    self.prev_total_downloaded = total_dl;

                    // Per-peer download rates (blk/s)
                    for ps in &bm.peer_stats {
                        let prev = self.prev_peer_blocks.get(&ps.peer_id).copied().unwrap_or(0);
                        if prev > 0 {
                            let raw = ps.blocks_received.saturating_sub(prev) as f64 / dt;
                            let old = self.peer_dl_rates.get(&ps.peer_id).copied().unwrap_or(0.0);
                            self.peer_dl_rates.insert(ps.peer_id, 0.3 * raw + 0.7 * old);
                        }
                        self.prev_peer_blocks.insert(ps.peer_id, ps.blocks_received);
                    }
                }
            }

            // Update block count from cursor (more current than getblockchaininfo)
            let cursor = bm.connect_cursor;
            if cursor > self.blocks {
                self.prev_blocks = cursor;
                self.blocks = cursor;
            }

            // ETA from server-side weight-aware estimator (computed in the
            // daemon's connect loop, exposed via getibdprogress RPC).
            // This accounts for the ~50x cost variation across Bitcoin's
            // history, producing a stable, converging ETA.
            if let Some(eta) = v.get("eta_secs").and_then(|e| e.as_u64()) {
                self.eta_secs = if eta > 0 { Some(eta) } else { None };
            }
        }
    }

    /// Update from getblockstats response.
    pub fn update_block_stats(&mut self, v: &serde_json::Value) {
        self.loaded.block_stats = true;
        self.block_stats_txs = v.get("txs").and_then(|t| t.as_u64());
        self.block_stats_total_fee = v.get("totalfee").and_then(|t| t.as_u64());
        self.block_stats_avg_fee_rate = v.get("avgfeerate").and_then(|f| f.as_f64());
        self.block_stats_size = v.get("total_size").and_then(|s| s.as_u64());
        self.block_stats_weight = v.get("total_weight").and_then(|w| w.as_u64());
    }

    /// Update from estimatefees response (PR #65/#67).
    /// Response shape: { targets: { "1": {feerate, confidence}, "3": ..., "6": ... },
    ///                   economy_feerate, mode, ... }
    /// `feerate` is already in sat/vB when `sat_per_vb: true` or BTC/kvB otherwise.
    /// Map targets onto 4-tier mempool.space labels:
    ///   High = target 1, Medium = target 3, Low = target 6, None = economy.
    pub fn update_fee_estimates(&mut self, v: &serde_json::Value) {
        self.loaded.fee_estimates = true;
        let sat_per_vb = v.get("sat_per_vb").and_then(|b| b.as_bool()).unwrap_or(false);

        let parse_rate = |raw: &serde_json::Value| -> Option<f64> {
            // Values may be strings (new default units=btc path annotates them)
            // or numbers. Accept either.
            let n = raw.as_f64()
                .or_else(|| raw.as_str().and_then(|s| s.parse().ok()))?;
            if sat_per_vb {
                Some(n)
            } else {
                // BTC/kvB → sat/vB
                Some(n * 100_000.0)
            }
        };

        let targets = v.get("targets").and_then(|t| t.as_object());
        let tier = |key: &str| -> (Option<f64>, Option<String>) {
            let obj = targets.and_then(|m| m.get(key)).and_then(|o| o.as_object());
            let feerate = obj.and_then(|o| o.get("feerate")).and_then(parse_rate);
            let conf = obj
                .and_then(|o| o.get("confidence"))
                .and_then(|c| c.as_str())
                .map(|s| s.to_string());
            (feerate, conf)
        };

        let (high, high_conf) = tier("1");
        let (medium, _) = tier("3");
        let (low, _) = tier("6");
        let none = v.get("economy_feerate").and_then(parse_rate);

        self.fees = FeeSummary {
            high,
            medium,
            low,
            none,
            confidence: high_conf,
            mode: v.get("mode").and_then(|m| m.as_str()).map(|s| s.to_string()),
        };
    }

    /// Update from gettxoutsetinfo response.
    pub fn update_utxo_info(&mut self, v: &serde_json::Value) {
        self.loaded.utxo = true;
        self.utxo_count = v.get("txouts").and_then(|t| t.as_u64());
        self.utxo_total_amount = v.get("total_amount").and_then(|a| a.as_f64());
        self.utxo_age_dist = v.get("utxo_age_distribution")
            .and_then(|d| d.get("counts"))
            .and_then(|c| c.as_array())
            .and_then(|arr| {
                if arr.len() == 8 {
                    let mut dist = [0u64; 8];
                    for (i, v) in arr.iter().enumerate() {
                        dist[i] = v.as_u64().unwrap_or(0);
                    }
                    Some(dist)
                } else {
                    None
                }
            });
    }

    /// Update from getmininginfo response.
    pub fn update_mining_info(&mut self, v: &serde_json::Value) {
        self.loaded.mining = true;
        self.network_hash_ps = v.get("networkhashps").and_then(|h| h.as_f64());
    }

    /// Update from getchaintxstats response.
    pub fn update_chain_tx_stats(&mut self, v: &serde_json::Value) {
        self.loaded.tx_stats = true;
        self.tx_rate = v.get("txrate").and_then(|r| r.as_f64());
    }

    /// Update from uptime response.
    pub fn update_uptime(&mut self, v: &serde_json::Value) {
        self.loaded.uptime = true;
        self.uptime_secs = v.as_u64();
    }

    /// Update from `getindexinfo` response.
    pub fn update_index_info(&mut self, v: &serde_json::Value) {
        self.backfill = BackfillProgress::from_json(v);
    }

    /// Update from `getserverstatus` response.
    pub fn update_server_status(&mut self, v: &serde_json::Value) {
        self.server_status = ServerStatus::from_json(v);
    }

    /// Update mempool size distribution + top-N from getrawmempool verbose response.
    pub fn update_mempool_dist(&mut self, v: &serde_json::Value) {
        self.loaded.mempool_dist = true;
        let Some(obj) = v.as_object() else { return };

        // Size distribution (existing vsize-bucket sparkline for steady view).
        let mut dist = [0u32; 8];
        for entry in obj.values() {
            let vsize = entry.get("vsize").and_then(|s| s.as_u64()).unwrap_or(0);
            let bucket = match vsize {
                0..100 => 0,
                100..250 => 1,
                250..500 => 2,
                500..1_000 => 3,
                1_000..5_000 => 4,
                5_000..10_000 => 5,
                10_000..50_000 => 6,
                _ => 7,
            };
            dist[bucket] += 1;
        }
        self.mempool_size_dist = Some(dist);

        // Top-N by ancestor feerate (ancestorfees is in sats, ancestorsize
        // in vbytes → feerate in sat/vB directly).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut entries: Vec<MempoolTopEntry> = obj
            .iter()
            .filter_map(|(txid, e)| {
                let ancestor_fees = e.get("ancestorfees")?.as_u64()?;
                let ancestor_size = e.get("ancestorsize")?.as_u64().unwrap_or(0);
                let vsize = e.get("vsize")?.as_u64().unwrap_or(0);
                let ancestor_feerate = if ancestor_size > 0 {
                    ancestor_fees as f64 / ancestor_size as f64
                } else {
                    0.0
                };
                Some(MempoolTopEntry {
                    txid: txid.clone(),
                    vsize,
                    ancestor_feerate,
                    ancestor_count: e.get("ancestorcount").and_then(|c| c.as_u64()).unwrap_or(1) as u32,
                    descendant_count: e.get("descendantcount").and_then(|c| c.as_u64()).unwrap_or(1) as u32,
                    age_secs: e.get("time")
                        .and_then(|t| t.as_u64())
                        .map(|t| now.saturating_sub(t))
                        .unwrap_or(0),
                })
            })
            .collect();
        // Sort by ancestor feerate descending, tiebreak by smaller vsize.
        entries.sort_by(|a, b| {
            b.ancestor_feerate
                .partial_cmp(&a.ancestor_feerate)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.vsize.cmp(&b.vsize))
        });
        entries.truncate(50);
        self.mempool_top = entries;
        if self.selected_mempool_row >= self.mempool_top.len() {
            self.selected_mempool_row = self.mempool_top.len().saturating_sub(1);
        }
    }

    /// Update from getmempoolhistory: { since_secs, available, snapshots: [...] }.
    pub fn update_mempool_history(&mut self, v: &serde_json::Value) {
        self.mempool_history_available = v
            .get("available")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        let Some(snaps) = v.get("snapshots").and_then(|a| a.as_array()) else {
            return;
        };
        let mut out: Vec<MempoolSnapshot> = snaps
            .iter()
            .filter_map(|s| {
                let histogram: Vec<HistogramBucket> = s
                    .get("histogram")
                    .and_then(|h| h.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|b| {
                                Some(HistogramBucket {
                                    feerate_sat_per_kvb: b.get("feerate_sat_per_kvb")?.as_u64()?,
                                    weight: b.get("weight")?.as_u64()?,
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Some(MempoolSnapshot {
                    ts_unix_secs: s.get("ts_unix_secs")?.as_u64()?,
                    size: s.get("size")?.as_u64()?,
                    bytes: s.get("bytes")?.as_u64()?,
                    min_fee_rate_sat_per_kvb: s.get("min_fee_rate_sat_per_kvb")?.as_u64()?,
                    max_fee_rate_sat_per_kvb: s.get("max_fee_rate_sat_per_kvb")?.as_u64()?,
                    histogram,
                })
            })
            .collect();
        // Oldest-first for sparkline left-to-right.
        out.sort_by_key(|s| s.ts_unix_secs);
        self.mempool_history = out;
    }

    /// Most recent snapshot delta (net tx and byte flow since previous snapshot).
    /// Returns (delta_tx, delta_bytes, interval_secs).
    pub fn latest_mempool_delta(&self) -> Option<(i64, i64, u64)> {
        let n = self.mempool_history.len();
        if n < 2 {
            return None;
        }
        let cur = &self.mempool_history[n - 1];
        let prev = &self.mempool_history[n - 2];
        Some((
            cur.size as i64 - prev.size as i64,
            cur.bytes as i64 - prev.bytes as i64,
            cur.ts_unix_secs.saturating_sub(prev.ts_unix_secs),
        ))
    }

    /// Update from getsysteminfo response.
    pub fn update_system_info(&mut self, v: &serde_json::Value) {
        self.loaded.system = true;
        self.rss_bytes = v.get("rss_bytes").and_then(|r| r.as_u64());
        self.thread_count = v.get("threads").and_then(|t| t.as_u64()).map(|t| t as u32);
        self.cache_dirty = v.get("cache_dirty").and_then(|c| c.as_u64()).map(|c| c as u32);
        self.cache_clean = v.get("cache_clean").and_then(|c| c.as_u64()).map(|c| c as usize);
        self.last_shutdown = v.get("last_shutdown")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string());
    }

    /// Update from getreorghistory response: { since_secs, records: [ReorgRecord, ...] }.
    pub fn update_reorg_history(&mut self, v: &serde_json::Value) {
        let Some(records) = v.get("records").and_then(|r| r.as_array()) else {
            return;
        };
        self.reorg_history = records
            .iter()
            .filter_map(|r| {
                Some(ReorgEntry {
                    ts_unix_secs: r.get("ts_unix_secs")?.as_u64()?,
                    depth: r.get("depth")?.as_u64()? as u32,
                    fork_height: r.get("fork_height")?.as_u64()? as u32,
                    old_tip: r.get("old_tip")?.as_str()?.to_string(),
                    new_tip: r.get("new_tip")?.as_str()?.to_string(),
                    disconnected_len: r.get("disconnected")
                        .and_then(|a| a.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0),
                    reconnected_len: r.get("reconnected")
                        .and_then(|a| a.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0),
                })
            })
            .collect();
        // Most-recent first for display.
        self.reorg_history.sort_by(|a, b| b.ts_unix_secs.cmp(&a.ts_unix_secs));
    }

    /// Cache the difficulty-epoch start anchor (height + header.time).
    /// Caller must have already verified `epoch_height % 2016 == 0`.
    pub fn update_epoch_anchor(&mut self, epoch_height: u32, header: &serde_json::Value) {
        if let Some(t) = header.get("time").and_then(|t| t.as_u64()) {
            self.epoch_start_height = Some(epoch_height);
            self.epoch_start_time = Some(t);
        }
    }

    // ---- Chain & Issuance derivations (pure math) ----

    /// Block subsidy in sats at the current tip (50 BTC halved every 210k).
    /// Saturates to 0 after the 33rd halving.
    pub fn subsidy_sats(&self) -> u64 {
        let halvings = self.blocks / 210_000;
        if halvings >= 64 {
            return 0;
        }
        50_0000_0000u64 >> halvings
    }

    /// Subsidy expected at `tip + 1` — same table, accounting for the case
    /// where the next block is the first of a new halving epoch.
    pub fn next_subsidy_sats(&self) -> u64 {
        let halvings = (self.blocks + 1) / 210_000;
        if halvings >= 64 {
            return 0;
        }
        50_0000_0000u64 >> halvings
    }

    /// Halving epoch index for the current tip (0 = pre-first-halving).
    pub fn subsidy_epoch(&self) -> u32 {
        self.blocks / 210_000
    }

    /// Blocks until the next halving (≥ 1 except in the last epoch).
    pub fn blocks_to_halving(&self) -> u32 {
        210_000 - (self.blocks % 210_000)
    }

    /// Blocks until the next difficulty retarget.
    pub fn blocks_to_retarget(&self) -> u32 {
        2016 - (self.blocks % 2016)
    }

    /// Blocks elapsed in the current difficulty epoch (0..2016).
    pub fn blocks_in_epoch(&self) -> u32 {
        self.blocks % 2016
    }

    /// Average seconds per block within the current difficulty epoch.
    /// Returns None if we don't yet have an anchor or have only just rolled
    /// into a new epoch.
    pub fn epoch_avg_block_secs(&self) -> Option<f64> {
        let start = self.epoch_start_time?;
        let elapsed_blocks = self.blocks_in_epoch();
        if elapsed_blocks == 0 || self.chain_time <= start {
            return None;
        }
        Some((self.chain_time - start) as f64 / elapsed_blocks as f64)
    }

    /// Estimated %-change at next retarget, clamped to ±300%.
    /// Negative = difficulty drops (blocks slower than 10m), positive = up.
    pub fn retarget_change_pct(&self) -> Option<f64> {
        let avg = self.epoch_avg_block_secs()?;
        if avg <= 0.0 {
            return None;
        }
        // Bitcoin Core retargets so the *next* epoch averages 600s/block.
        // %change = 600/avg - 1 (positive when blocks were fast).
        let raw = (600.0 / avg - 1.0) * 100.0;
        Some(raw.clamp(-300.0, 300.0))
    }

    /// Cumulative chain work expressed as bits (≈ log2 of the integer).
    /// Computed in log domain so the 256-bit value never materializes.
    pub fn chain_work_bits(&self) -> Option<f64> {
        chain_work_bits_from_hex(&self.chainwork_hex)
    }

    /// Seconds an attacker at the current network hashrate would need to
    /// reproduce the entire chain work. `chainwork / hashrate`.
    pub fn chain_rewrite_secs(&self) -> Option<f64> {
        let bits = self.chain_work_bits()?;
        let hps = self.network_hash_ps?;
        if hps <= 0.0 {
            return None;
        }
        // 2^bits / hps  =  2^(bits - log2(hps))
        let log_hps = hps.log2();
        Some(2.0_f64.powf(bits - log_hps))
    }

    /// Total issued supply as fraction of 21M (0.0..1.0). Requires UTXO snapshot.
    pub fn supply_pct_issued(&self) -> Option<f64> {
        Some(self.utxo_total_amount? / 21_000_000.0)
    }

    /// Realized annual inflation: subsidy_at_tip × blocks_per_year / supply.
    /// `blocks_per_year` ≈ 144 × 365.25 = 52596.
    pub fn realized_annual_inflation(&self) -> Option<f64> {
        let supply_btc = self.utxo_total_amount?;
        if supply_btc <= 0.0 {
            return None;
        }
        let annual_btc = (self.subsidy_sats() as f64 / 1e8) * 52596.0;
        Some(annual_btc / supply_btc)
    }

    /// Forward annual inflation: subsidy *after* the next halving, applied
    /// against the supply that will exist at that point. Useful as a
    /// "post-halving" preview.
    pub fn forward_annual_inflation(&self) -> Option<f64> {
        let supply_btc = self.utxo_total_amount?;
        if supply_btc <= 0.0 {
            return None;
        }
        let next_halvings = self.subsidy_epoch() + 1;
        if next_halvings >= 64 {
            return Some(0.0);
        }
        let next_subsidy_btc = (50_0000_0000u64 >> next_halvings) as f64 / 1e8;
        // Supply at next halving = current + remaining_subsidy_in_this_epoch.
        let blocks_left = self.blocks_to_halving() as f64;
        let remaining_btc = (self.subsidy_sats() as f64 / 1e8) * blocks_left;
        let supply_at_next = supply_btc + remaining_btc;
        if supply_at_next <= 0.0 {
            return None;
        }
        Some(next_subsidy_btc * 52596.0 / supply_at_next)
    }

    /// Top-N peer subver strings with counts. The `(N+1)`th bucket aggregates
    /// the long tail under "other". Empty subvers are dropped.
    pub fn subver_distribution(&self, top_n: usize) -> Vec<(String, usize)> {
        if self.peers.is_empty() || top_n == 0 {
            return vec![];
        }
        let mut counts: HashMap<String, usize> = HashMap::new();
        for p in &self.peers {
            if let Some(s) = p.get("subver").and_then(|s| s.as_str())
                && !s.is_empty()
            {
                *counts.entry(s.to_string()).or_default() += 1;
            }
        }
        let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        if sorted.len() <= top_n {
            return sorted;
        }
        let (head, tail) = sorted.split_at(top_n);
        let other_total: usize = tail.iter().map(|(_, c)| *c).sum();
        let mut out = head.to_vec();
        if other_total > 0 {
            out.push(("other".to_string(), other_total));
        }
        out
    }

    /// True if we have a healthy, live, steady-state connection.
    pub fn is_healthy(&self) -> bool {
        self.connected && !self.stale && !self.is_ibd
    }

    /// Update from getwarnings: { warnings: [{id,severity,message,...}, ...] }.
    pub fn update_warnings(&mut self, v: &serde_json::Value) {
        let Some(arr) = v.get("warnings").and_then(|a| a.as_array()) else {
            return;
        };
        let parsed: Vec<NodeWarning> = arr
            .iter()
            .filter_map(|w| {
                let severity = match w.get("severity")?.as_str()? {
                    "error" => WarningSeverity::Error,
                    "warn" => WarningSeverity::Warn,
                    _ => return None,
                };
                Some(NodeWarning {
                    id: w.get("id")?.as_str()?.to_string(),
                    severity,
                    message: w.get("message")?.as_str()?.to_string(),
                    first_seen_unix_secs: w.get("first_seen_unix_secs")?.as_u64()?,
                    last_seen_unix_secs: w.get("last_seen_unix_secs")?.as_u64()?,
                    count: w.get("count")?.as_u64()?,
                })
            })
            .collect();
        // Drop dismissals for IDs that no longer appear — once the node
        // clears a warning and it reappears, the operator should see it
        // again.
        let active_ids: std::collections::HashSet<String> =
            parsed.iter().map(|w| w.id.clone()).collect();
        self.dismissed_warnings.retain(|id| active_ids.contains(id));
        self.warnings = parsed;
    }

    /// Warnings the operator hasn't dismissed yet.
    pub fn visible_warnings(&self) -> Vec<&NodeWarning> {
        self.warnings
            .iter()
            .filter(|w| !self.dismissed_warnings.contains(&w.id))
            .collect()
    }

    /// Dismiss all currently-visible warnings for this session.
    pub fn dismiss_visible_warnings(&mut self) {
        for w in &self.warnings {
            self.dismissed_warnings.insert(w.id.clone());
        }
    }

    /// Best known target height: max of headers and peer-reported network height.
    pub fn sync_target(&self) -> u32 {
        self.network_height.max(self.headers)
    }

    /// Mark poll timestamp.
    pub fn mark_poll(&mut self) {
        self.last_poll = Some(std::time::Instant::now());
        self.connected = true;
        self.stale = false;
    }

    /// Toggle force mode.
    pub fn toggle_mode(&mut self, mode: ViewMode) {
        if self.force_mode == Some(mode) {
            self.force_mode = None;
            self.mode = if self.is_ibd { ViewMode::Ibd } else { ViewMode::Steady };
        } else {
            self.force_mode = Some(mode);
            self.mode = mode;
        }
    }

    /// Active view mode (respects force override).
    pub fn active_mode(&self) -> ViewMode {
        self.force_mode.unwrap_or(self.mode)
    }

    /// Check if data is stale (>5s since last poll).
    pub fn check_stale(&mut self) {
        if let Some(last) = self.last_poll {
            self.stale = last.elapsed().as_secs() > 5;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn startup_rate_needs_window_and_progress() {
        let mut st = AppState::new();
        // No samples yet.
        assert!(st.startup_rate().is_none());

        let s = StartupStatus {
            phase: "reindex_connect".into(),
            message: "x".into(),
            current: 100,
            total: 1000,
            stop_height: None,
        };
        st.update_startup(s);
        // Single sample is insufficient.
        assert!(st.startup_rate().is_none());

        // Two samples but inside the same instant — duration < 1 s.
        let s2 = StartupStatus {
            phase: "reindex_connect".into(),
            message: "x".into(),
            current: 110,
            total: 1000,
            stop_height: None,
        };
        st.update_startup(s2);
        // Likely None unless the test scheduler stalled past 1 s; either
        // way, no panic and the API stays well-defined.
        let _ = st.startup_rate();
    }

    #[test]
    fn startup_phase_transition_resets_window() {
        let mut st = AppState::new();
        st.update_startup(StartupStatus {
            phase: "reindex_scan".into(),
            message: "scanning".into(),
            current: 5_000,
            total: 0,
            stop_height: None,
        });
        assert_eq!(st.startup_samples.len(), 1);
        assert_eq!(st.startup_phase, "reindex_scan");

        st.update_startup(StartupStatus {
            phase: "reindex_connect".into(),
            message: "replay".into(),
            current: 1,
            total: 945_000,
            stop_height: None,
        });
        // Phase change clears the rolling window so rate isn't polluted
        // by the (much faster) scan-phase samples.
        assert_eq!(st.startup_samples.len(), 1);
        assert_eq!(st.startup_phase, "reindex_connect");
    }

    #[test]
    fn startup_eta_requires_total_and_rate() {
        let mut st = AppState::new();
        st.update_startup(StartupStatus {
            phase: "reindex_connect".into(),
            message: "replay".into(),
            current: 100,
            total: 0,
            stop_height: None,
        });
        // total=0 → no ETA.
        assert!(st.startup_eta_secs().is_none());
    }

    #[test]
    fn clear_startup_drops_all_tracking() {
        let mut st = AppState::new();
        st.update_startup(StartupStatus {
            phase: "reindex_connect".into(),
            message: "replay".into(),
            current: 100,
            total: 1000,
            stop_height: None,
        });
        st.clear_startup();
        assert!(st.startup_status.is_none());
        assert!(st.startup_started_at.is_none());
        assert!(st.startup_samples.is_empty());
        assert!(st.startup_phase.is_empty());
    }

    #[test]
    fn startup_status_parses_stop_height_when_present() {
        let v = json!({
            "phase": "reindex_chainstate",
            "status": "Replaying UTXO set",
            "current": 12_345,
            "total": 945_000,
            "stop_height": 840_000,
        });
        let s = StartupStatus::from_json(&v);
        assert_eq!(s.stop_height, Some(840_000));
        assert_eq!(s.total, 945_000);
    }

    #[test]
    fn startup_status_omits_stop_height_when_absent_or_null() {
        let v_absent = json!({
            "phase": "reindex_chainstate",
            "status": "Replaying UTXO set",
            "current": 1,
            "total": 100,
        });
        assert_eq!(StartupStatus::from_json(&v_absent).stop_height, None);

        let v_null = json!({
            "phase": "reindex_chainstate",
            "status": "Replaying UTXO set",
            "current": 1,
            "total": 100,
            "stop_height": serde_json::Value::Null,
        });
        assert_eq!(StartupStatus::from_json(&v_null).stop_height, None);
    }

    #[test]
    fn record_failure_then_clear() {
        let mut st = AppState::new();
        assert!(st.last_failure.is_none());

        st.record_failure(RpcFailure::AuthFailed, "401".into());
        let rec = st.last_failure.as_ref().expect("recorded");
        assert_eq!(rec.kind, RpcFailure::AuthFailed);
        assert_eq!(rec.message, "401");
        let first_seen = rec.first_seen;

        // Re-recording the same kind preserves first_seen so the
        // modal can show a stable "failing for Ns" duration.
        st.record_failure(RpcFailure::AuthFailed, "still 401".into());
        let rec = st.last_failure.as_ref().unwrap();
        assert_eq!(rec.first_seen, first_seen);
        assert_eq!(rec.message, "still 401");

        // Recording a different kind resets first_seen.
        st.record_failure(RpcFailure::ConnectionFailed, "econnrefused".into());
        let rec = st.last_failure.as_ref().unwrap();
        assert_eq!(rec.kind, RpcFailure::ConnectionFailed);
        assert!(rec.first_seen >= first_seen);

        st.clear_failure();
        assert!(st.last_failure.is_none());
    }

    #[test]
    fn update_fee_estimates_btc_units() {
        // Default-unit (btc) response: feerate is BTC/kvB as a float.
        let v = json!({
            "targets": {
                "1": {"feerate": 0.00025, "confidence": "high"},
                "3": {"feerate": 0.00018, "confidence": "medium"},
                "6": {"feerate": 0.00010, "confidence": "low"},
            },
            "economy_feerate": 0.00001,
            "mode": "blend",
            "fallback": false,
        });
        let mut st = AppState::new();
        st.update_fee_estimates(&v);
        // BTC/kvB → sat/vB = value * 100_000
        assert_eq!(st.fees.high, Some(25.0));
        assert_eq!(st.fees.medium, Some(18.0));
        assert_eq!(st.fees.low, Some(10.0));
        assert_eq!(st.fees.none, Some(1.0));
        assert_eq!(st.fees.confidence.as_deref(), Some("high"));
        assert_eq!(st.fees.mode.as_deref(), Some("blend"));
        assert!(st.loaded.fee_estimates);
    }

    #[test]
    fn update_fee_estimates_sat_per_vb_units() {
        // --rpcdefaultunits=sats path: feerate is a string integer and
        // sat_per_vb: true is present.
        let v = json!({
            "targets": {
                "1": {"feerate": "25", "confidence": "high"},
                "3": {"feerate": "18", "confidence": "medium"},
                "6": {"feerate": "10", "confidence": "low"},
            },
            "economy_feerate": "1",
            "mode": "mempool",
            "fallback": false,
            "sat_per_vb": true,
        });
        let mut st = AppState::new();
        st.update_fee_estimates(&v);
        assert_eq!(st.fees.high, Some(25.0));
        assert_eq!(st.fees.none, Some(1.0));
        assert_eq!(st.fees.mode.as_deref(), Some("mempool"));
    }

    #[test]
    fn update_fee_estimates_missing_targets_leave_tier_none() {
        // Node returns only a subset of targets (e.g., historical mode miss).
        let v = json!({
            "targets": { "1": {"feerate": 0.00025, "confidence": "medium"} },
            "economy_feerate": 0.00001,
            "mode": "historical",
        });
        let mut st = AppState::new();
        st.update_fee_estimates(&v);
        assert_eq!(st.fees.high, Some(25.0));
        assert_eq!(st.fees.medium, None);
        assert_eq!(st.fees.low, None);
        assert_eq!(st.fees.none, Some(1.0));
    }

    #[test]
    fn update_reorg_history_shape_and_sort() {
        let v = json!({
            "since_secs": 86400,
            "records": [
                {
                    "ts_unix_secs": 1_700_000_000,
                    "depth": 1,
                    "fork_height": 100,
                    "old_tip": "aa",
                    "new_tip": "bb",
                    "disconnected": ["aa"],
                    "reconnected": ["bb"],
                },
                {
                    "ts_unix_secs": 1_700_001_000,
                    "depth": 3,
                    "fork_height": 200,
                    "old_tip": "cc",
                    "new_tip": "dd",
                    "disconnected": ["cc","c2","c3"],
                    "reconnected": ["dd","d2"],
                },
            ],
        });
        let mut st = AppState::new();
        st.update_reorg_history(&v);
        // Most-recent first.
        assert_eq!(st.reorg_history.len(), 2);
        assert_eq!(st.reorg_history[0].depth, 3);
        assert_eq!(st.reorg_history[0].disconnected_len, 3);
        assert_eq!(st.reorg_history[0].reconnected_len, 2);
        assert_eq!(st.reorg_history[1].depth, 1);
    }

    #[test]
    fn update_system_info_last_shutdown() {
        let v = json!({
            "pid": 1,
            "rss_bytes": 1_000,
            "threads": 4,
            "cache_dirty": 0,
            "cache_clean": 0,
            "last_shutdown": "dirty",
        });
        let mut st = AppState::new();
        st.update_system_info(&v);
        assert_eq!(st.last_shutdown.as_deref(), Some("dirty"));
    }

    #[test]
    fn update_mempool_history_parses_and_orders() {
        let v = json!({
            "since_secs": 2400,
            "available": true,
            "snapshots": [
                {
                    "ts_unix_secs": 1_700_000_020,
                    "size": 120,
                    "bytes": 50_000,
                    "min_fee_rate_sat_per_kvb": 1_000,
                    "max_fee_rate_sat_per_kvb": 50_000,
                    "histogram": [
                        {"feerate_sat_per_kvb": 2_000, "weight": 4_000},
                        {"feerate_sat_per_kvb": 10_000, "weight": 2_000},
                    ],
                },
                {
                    "ts_unix_secs": 1_700_000_010,
                    "size": 100,
                    "bytes": 40_000,
                    "min_fee_rate_sat_per_kvb": 1_000,
                    "max_fee_rate_sat_per_kvb": 40_000,
                    "histogram": [],
                },
            ],
        });
        let mut st = AppState::new();
        st.update_mempool_history(&v);
        assert!(st.mempool_history_available);
        assert_eq!(st.mempool_history.len(), 2);
        // Oldest-first after sort so sparkline reads left→right chronologically.
        assert_eq!(st.mempool_history[0].ts_unix_secs, 1_700_000_010);
        assert_eq!(st.mempool_history[1].ts_unix_secs, 1_700_000_020);
        assert_eq!(st.mempool_history[1].histogram.len(), 2);
    }

    #[test]
    fn update_mempool_history_available_false() {
        let v = json!({
            "since_secs": 2400,
            "available": false,
            "snapshots": [],
        });
        let mut st = AppState::new();
        st.update_mempool_history(&v);
        assert!(!st.mempool_history_available);
        assert!(st.mempool_history.is_empty());
    }

    #[test]
    fn latest_mempool_delta_tracks_consecutive_snapshots() {
        let mut st = AppState::new();
        assert!(st.latest_mempool_delta().is_none());
        let v = json!({
            "since_secs": 20,
            "available": true,
            "snapshots": [
                {"ts_unix_secs": 100, "size": 10, "bytes": 5_000,
                 "min_fee_rate_sat_per_kvb": 1_000, "max_fee_rate_sat_per_kvb": 5_000,
                 "histogram": []},
                {"ts_unix_secs": 110, "size": 15, "bytes": 7_500,
                 "min_fee_rate_sat_per_kvb": 1_000, "max_fee_rate_sat_per_kvb": 5_000,
                 "histogram": []},
            ],
        });
        st.update_mempool_history(&v);
        let (dtx, dbytes, secs) = st.latest_mempool_delta().expect("delta");
        assert_eq!(dtx, 5);
        assert_eq!(dbytes, 2_500);
        assert_eq!(secs, 10);
    }

    #[test]
    fn update_mempool_dist_computes_top_n_sorted_by_ancestor_feerate() {
        let v = json!({
            "lowest": {"fees": {"base": 0.00001}, "vsize": 200, "ancestorfees": 2000, "ancestorsize": 200,
                       "ancestorcount": 1, "descendantcount": 1, "time": 1_700_000_000},
            "highest": {"fees": {"base": 0.001}, "vsize": 250, "ancestorfees": 100_000, "ancestorsize": 250,
                        "ancestorcount": 1, "descendantcount": 1, "time": 1_700_000_000},
            "cpfp_child": {"fees": {"base": 0.0001}, "vsize": 300, "ancestorfees": 50_000, "ancestorsize": 500,
                           "ancestorcount": 2, "descendantcount": 1, "time": 1_700_000_000},
        });
        let mut st = AppState::new();
        st.update_mempool_dist(&v);
        assert_eq!(st.mempool_top.len(), 3);
        // 100_000/250 = 400 sat/vB (highest)
        // 50_000/500 = 100 sat/vB
        // 2_000/200 = 10 sat/vB
        assert_eq!(st.mempool_top[0].txid, "highest");
        assert_eq!(st.mempool_top[1].txid, "cpfp_child");
        assert_eq!(st.mempool_top[2].txid, "lowest");
        assert!(st.mempool_top[0].ancestor_feerate > st.mempool_top[1].ancestor_feerate);
    }

    #[test]
    fn update_warnings_parses_severity_and_fields() {
        let v = json!({
            "warnings": [
                {
                    "id": "connect.persistent_failure",
                    "severity": "error",
                    "message": "block 945989 won't connect",
                    "first_seen_unix_secs": 100,
                    "last_seen_unix_secs": 200,
                    "count": 5,
                    "context": {"height": 945989},
                },
                {
                    "id": "storage.flush_slow",
                    "severity": "warn",
                    "message": "flush took 8s",
                    "first_seen_unix_secs": 150,
                    "last_seen_unix_secs": 150,
                    "count": 1,
                    "context": {},
                },
            ],
        });
        let mut st = AppState::new();
        st.update_warnings(&v);
        assert_eq!(st.warnings.len(), 2);
        assert_eq!(st.warnings[0].id, "connect.persistent_failure");
        assert_eq!(st.warnings[0].severity, WarningSeverity::Error);
        assert_eq!(st.warnings[0].count, 5);
        assert_eq!(st.warnings[1].severity, WarningSeverity::Warn);
    }

    #[test]
    fn dismissed_warnings_hidden_until_cleared_or_new() {
        let v = json!({
            "warnings": [{
                "id": "a", "severity": "error", "message": "m",
                "first_seen_unix_secs": 1, "last_seen_unix_secs": 1, "count": 1,
            }],
        });
        let mut st = AppState::new();
        st.update_warnings(&v);
        assert_eq!(st.visible_warnings().len(), 1);

        // Operator acknowledges.
        st.dismiss_visible_warnings();
        assert_eq!(st.visible_warnings().len(), 0);
        assert!(st.dismissed_warnings.contains("a"));

        // Server clears the warning — dismissal also clears so next
        // occurrence of `a` is visible again.
        st.update_warnings(&json!({"warnings": []}));
        assert!(!st.dismissed_warnings.contains("a"));

        // `a` reappears.
        st.update_warnings(&v);
        assert_eq!(st.visible_warnings().len(), 1);
    }

    // ---- Chain & Issuance derivations ----

    #[test]
    fn subsidy_at_known_heights() {
        let mut st = AppState::new();
        st.blocks = 0;
        assert_eq!(st.subsidy_sats(), 50_0000_0000);
        st.blocks = 209_999;
        assert_eq!(st.subsidy_sats(), 50_0000_0000);
        st.blocks = 210_000;
        assert_eq!(st.subsidy_sats(), 25_0000_0000);
        st.blocks = 419_999;
        assert_eq!(st.subsidy_sats(), 25_0000_0000);
        st.blocks = 840_000;
        assert_eq!(st.subsidy_sats(), 3_1250_0000); // 3.125 BTC
        st.blocks = 945_000;
        assert_eq!(st.subsidy_sats(), 3_1250_0000);
    }

    #[test]
    fn next_subsidy_handles_halving_boundary() {
        let mut st = AppState::new();
        st.blocks = 209_999;
        // Tip at 209_999 is still 50; the *next* block (210_000) is the first of epoch 1.
        assert_eq!(st.subsidy_sats(), 50_0000_0000);
        assert_eq!(st.next_subsidy_sats(), 25_0000_0000);
    }

    #[test]
    fn blocks_to_halving_and_retarget() {
        let mut st = AppState::new();
        st.blocks = 0;
        assert_eq!(st.blocks_to_halving(), 210_000);
        assert_eq!(st.blocks_to_retarget(), 2016);

        st.blocks = 209_999;
        assert_eq!(st.blocks_to_halving(), 1);
        st.blocks = 210_000;
        assert_eq!(st.blocks_to_halving(), 210_000);

        st.blocks = 2015;
        assert_eq!(st.blocks_to_retarget(), 1);
        st.blocks = 2016;
        assert_eq!(st.blocks_to_retarget(), 2016);
    }

    #[test]
    fn epoch_avg_block_secs_requires_anchor() {
        let mut st = AppState::new();
        st.blocks = 1_500;
        st.chain_time = 1_700_006_000;
        // No anchor yet.
        assert_eq!(st.epoch_avg_block_secs(), None);
        st.epoch_start_height = Some(0);
        st.epoch_start_time = Some(1_700_000_000);
        // 6000s over 1500 blocks → 4.0s/blk avg.
        let avg = st.epoch_avg_block_secs().expect("avg");
        assert!((avg - 4.0).abs() < 1e-6, "avg = {}", avg);
    }

    #[test]
    fn epoch_avg_returns_none_at_boundary() {
        let mut st = AppState::new();
        st.blocks = 4032; // exact 2016 boundary → blocks_in_epoch == 0
        st.chain_time = 1_700_006_000;
        st.epoch_start_height = Some(4032);
        st.epoch_start_time = Some(1_700_006_000);
        assert_eq!(st.epoch_avg_block_secs(), None);
    }

    #[test]
    fn retarget_change_pct_clamps_extremes() {
        let mut st = AppState::new();
        st.blocks = 1; // fresh epoch, 1 block in
        st.chain_time = 1_700_000_001;
        st.epoch_start_height = Some(0);
        st.epoch_start_time = Some(1_700_000_000);
        // 1s avg → would be huge speedup; clamped to +300%.
        let pct = st.retarget_change_pct().expect("pct");
        assert!((pct - 300.0).abs() < 1e-6, "got {}", pct);

        // 60_000s/blk → very slow → 600/60000 - 1 = -0.99 = -99%.
        // The slow side naturally bounds at -100%, so the clamp never fires
        // in that direction; verify the analytical value rather than the clamp.
        st.chain_time = 1_700_000_000 + 60_000;
        let pct2 = st.retarget_change_pct().expect("pct2");
        assert!((pct2 - (-99.0)).abs() < 0.001, "got {}", pct2);
    }

    #[test]
    fn retarget_change_pct_normal_range() {
        let mut st = AppState::new();
        st.blocks = 1008; // mid-epoch
        st.chain_time = 1_700_000_000 + 1008 * 540; // 9m blocks → faster
        st.epoch_start_height = Some(0);
        st.epoch_start_time = Some(1_700_000_000);
        // avg = 540s → 600/540 - 1 ≈ +11.11%
        let pct = st.retarget_change_pct().expect("pct");
        assert!((pct - 11.111111).abs() < 0.01, "got {}", pct);
    }

    #[test]
    fn chain_work_bits_from_known_hex() {
        // 2^20 = 0x100000 → 20 bits exactly.
        let v = chain_work_bits_from_hex("0000000000000000000000000000000000000000000000000000000000100000")
            .expect("bits");
        assert!((v - 20.0).abs() < 1e-6, "got {}", v);

        // 2^256 - 1 max chainwork ≈ 256 bits.
        let max = chain_work_bits_from_hex(&"f".repeat(64)).expect("bits");
        assert!((max - 256.0).abs() < 0.01, "got {}", max);

        // Empty / all-zero hex → None.
        assert_eq!(chain_work_bits_from_hex(""), None);
        assert_eq!(chain_work_bits_from_hex(&"0".repeat(64)), None);
    }

    #[test]
    fn chain_rewrite_secs_known_inputs() {
        let mut st = AppState::new();
        // chainwork = 2^60, hashrate = 2^30 H/s → rewrite = 2^30 sec.
        st.chainwork_hex = format!("{:0>64}", "1000000000000000"); // 2^60
        st.network_hash_ps = Some((1u64 << 30) as f64);
        let secs = st.chain_rewrite_secs().expect("secs");
        let expected = (1u64 << 30) as f64;
        assert!(
            (secs / expected - 1.0).abs() < 1e-3,
            "got {} expected {}",
            secs,
            expected
        );
    }

    #[test]
    fn supply_pct_and_inflation() {
        let mut st = AppState::new();
        st.blocks = 945_000;
        st.utxo_total_amount = Some(19_712_500.0);
        let pct = st.supply_pct_issued().expect("pct");
        assert!((pct - 0.93869).abs() < 0.001, "got {}", pct);

        // Subsidy at 945k = 3.125 BTC; annual = 3.125 * 52596 ≈ 164_362.5 BTC.
        // realized ≈ 164_362.5 / 19_712_500 ≈ 0.00834 (0.834%).
        let realized = st.realized_annual_inflation().expect("realized");
        assert!((realized - 0.00834).abs() < 0.001, "got {}", realized);

        // Forward: next-epoch subsidy = 1.5625, supply at next ≈ supply + 3.125 * (210000 - 945000%210000).
        let forward = st.forward_annual_inflation().expect("forward");
        assert!(forward < realized, "forward {} should be < realized {}", forward, realized);
        assert!(forward > 0.0);
    }

    #[test]
    fn subver_distribution_top_n_with_other_bucket() {
        let mut st = AppState::new();
        st.peers = vec![
            json!({"subver": "/Satoshi:25.0.0/"}),
            json!({"subver": "/Satoshi:25.0.0/"}),
            json!({"subver": "/Satoshi:25.0.0/"}),
            json!({"subver": "/Satoshi:24.0.1/"}),
            json!({"subver": "/Satoshi:24.0.1/"}),
            json!({"subver": "/knots:24.1.0/"}),
            json!({"subver": "/btcd:0.23.0/"}),
            json!({"subver": "/SuchPeer:1.0/"}),
        ];
        let dist = st.subver_distribution(2);
        // Top-2 keeps Satoshi:25 (3) and Satoshi:24 (2); other bucket folds knots+btcd+SuchPeer (3).
        assert_eq!(dist.len(), 3);
        assert_eq!(dist[0].0, "/Satoshi:25.0.0/");
        assert_eq!(dist[0].1, 3);
        assert_eq!(dist[1].0, "/Satoshi:24.0.1/");
        assert_eq!(dist[1].1, 2);
        assert_eq!(dist[2].0, "other");
        assert_eq!(dist[2].1, 3);

        // Empty subver dropped.
        st.peers.push(json!({"subver": ""}));
        let dist2 = st.subver_distribution(10);
        let total: usize = dist2.iter().map(|(_, c)| c).sum();
        assert_eq!(total, 8); // unchanged — empty was filtered out
    }

    #[test]
    fn subver_distribution_no_peers() {
        let st = AppState::new();
        assert!(st.subver_distribution(5).is_empty());
    }

    #[test]
    fn update_epoch_anchor_caches_height_and_time() {
        let mut st = AppState::new();
        st.blocks = 945_312;
        let header = json!({"time": 1_714_389_222});
        st.update_epoch_anchor(944_352, &header);
        assert_eq!(st.epoch_start_height, Some(944_352));
        assert_eq!(st.epoch_start_time, Some(1_714_389_222));
    }

    #[test]
    fn update_chain_info_captures_chainwork() {
        let v = json!({
            "chain": "main",
            "blocks": 1,
            "headers": 1,
            "bestblockhash": "aa",
            "difficulty": 1.0,
            "time": 0,
            "initialblockdownload": false,
            "verificationprogress": 1.0,
            "chainwork": "0000000000000000000000000000000000000000000000000000000000100000",
        });
        let mut st = AppState::new();
        st.update_chain_info(&v);
        assert_eq!(
            st.chainwork_hex,
            "0000000000000000000000000000000000000000000000000000000000100000"
        );
        assert!((st.chain_work_bits().unwrap() - 20.0).abs() < 1e-6);
    }

    #[test]
    fn health_dot_transitions() {
        let mut st = AppState::new();
        assert!(!st.is_healthy()); // fresh: not connected
        st.connected = true;
        st.is_ibd = true;
        assert!(!st.is_healthy()); // ibd
        st.is_ibd = false;
        st.stale = true;
        assert!(!st.is_healthy()); // stale
        st.stale = false;
        assert!(st.is_healthy());
    }

    #[test]
    fn backfill_progress_parses_running_shape() {
        let v = json!({
            "address": {
                "synced": false,
                "best_block_height": 947_498,
                "backfill": {
                    "active": true,
                    "state": "running",
                    "pass": 1,
                    "cursor_height": 100_000,
                    "snapshot_height": 947_498,
                    "estimated_remaining_seconds": 360,
                }
            }
        });
        let bf = BackfillProgress::from_json(&v).expect("backfill subobject present");
        assert_eq!(bf.state, "running");
        assert_eq!(bf.pass, 1);
        assert_eq!(bf.cursor_height, 100_000);
        assert_eq!(bf.snapshot_height, 947_498);
        assert_eq!(bf.estimated_remaining_seconds, 360);
        assert!(bf.last_error.is_none());
        assert!(bf.is_visible());
        // Pass 1 contributes cursor / (2 * snapshot) ≈ 5.28%
        assert!((bf.progress_ratio() - 100_000.0 / (2.0 * 947_498.0)).abs() < 1e-9);
    }

    #[test]
    fn backfill_progress_visibility_filters_quiet_states() {
        for state in ["idle", "completed", "cancelled", "rejected"] {
            let v = json!({
                "address": { "backfill": { "state": state } }
            });
            let bf = BackfillProgress::from_json(&v).unwrap();
            assert!(!bf.is_visible(), "{state} should not be visible");
        }
        for state in ["running", "paused", "failed"] {
            let v = json!({
                "address": { "backfill": { "state": state } }
            });
            let bf = BackfillProgress::from_json(&v).unwrap();
            assert!(bf.is_visible(), "{state} should be visible");
        }
    }

    #[test]
    fn backfill_progress_pass_two_advances_past_halfway() {
        let v = json!({
            "address": { "backfill": {
                "state": "running",
                "pass": 2,
                "cursor_height": 947_498,
                "snapshot_height": 947_498,
            }}
        });
        let bf = BackfillProgress::from_json(&v).unwrap();
        // End of pass 2 == 100% across both passes.
        assert!((bf.progress_ratio() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn backfill_progress_failed_carries_last_error() {
        let v = json!({
            "address": { "backfill": {
                "state": "failed",
                "pass": 1,
                "cursor_height": 50_000,
                "snapshot_height": 947_498,
                "last_error": "snapshot tip no longer on active chain",
            }}
        });
        let bf = BackfillProgress::from_json(&v).unwrap();
        assert_eq!(bf.last_error.as_deref(), Some("snapshot tip no longer on active chain"));
        assert!(bf.is_visible());
    }

    #[test]
    fn backfill_progress_returns_none_when_no_backfill_subobject() {
        let v = json!({ "address": { "synced": true } });
        assert!(BackfillProgress::from_json(&v).is_none());
    }

    fn unwrap_bound<T: Clone>(v: &ListenerView<T>) -> T {
        match v {
            ListenerView::Bound(t) => t.clone(),
            other => panic!("expected Bound, got {:?}", std::mem::discriminant(other)),
        }
    }

    #[test]
    fn server_status_parses_all_listeners_bound() {
        // New wire shape: each listener is `null` (not bound) or
        // `{bind: "..."}`. addressindex is its own shape.
        let v = json!({
            "addressindex": { "enabled": true, "complete": true },
            "esplora": { "bind": "127.0.0.1:3000" },
            "electrum": { "bind": "127.0.0.1:50001" },
            "electrum_tls": { "bind": "127.0.0.1:50002" },
        });
        let s = ServerStatus::from_json(&v);
        let ai = unwrap_bound(&s.addressindex);
        assert!(ai.enabled);
        assert!(ai.complete);
        assert_eq!(unwrap_bound(&s.esplora).bind, "127.0.0.1:3000");
        assert_eq!(unwrap_bound(&s.electrum).bind, "127.0.0.1:50001");
        assert_eq!(unwrap_bound(&s.electrum_tls).bind, "127.0.0.1:50002");
    }

    #[test]
    fn server_status_listener_null_becomes_not_bound() {
        let v = json!({
            "addressindex": { "enabled": false, "complete": false },
            "esplora": null,
            "electrum": null,
            "electrum_tls": null,
        });
        let s = ServerStatus::from_json(&v);
        assert!(matches!(s.esplora, ListenerView::NotBound));
        assert!(matches!(s.electrum, ListenerView::NotBound));
        assert!(matches!(s.electrum_tls, ListenerView::NotBound));
        let ai = unwrap_bound(&s.addressindex);
        assert!(!ai.enabled);
    }

    #[test]
    fn server_status_missing_field_becomes_unknown() {
        // Round-trip against an older satd that doesn't emit the new
        // top-level keys. Empty object → all Unknown.
        let v = json!({});
        let s = ServerStatus::from_json(&v);
        assert!(matches!(s.addressindex, ListenerView::Unknown));
        assert!(matches!(s.esplora, ListenerView::Unknown));
        assert!(matches!(s.electrum, ListenerView::Unknown));
        assert!(matches!(s.electrum_tls, ListenerView::Unknown));
    }

    #[test]
    fn server_status_default_is_unknown() {
        // The pre-poll default must render as Unknown (dim "-"), not
        // NotBound ("off"). This is the regression PR #127's reviewer
        // flagged.
        let s = ServerStatus::default();
        assert!(matches!(s.addressindex, ListenerView::Unknown));
        assert!(matches!(s.esplora, ListenerView::Unknown));
        assert!(matches!(s.electrum, ListenerView::Unknown));
        assert!(matches!(s.electrum_tls, ListenerView::Unknown));
    }

    #[test]
    fn server_status_partial_addressindex_is_unknown() {
        // Object present but flags missing — older satd that emits a
        // skeleton but not the live fields. Don't guess.
        let v = json!({
            "addressindex": { "enabled": true },
            "esplora": null,
            "electrum": null,
            "electrum_tls": null,
        });
        let s = ServerStatus::from_json(&v);
        assert!(
            matches!(s.addressindex, ListenerView::Unknown),
            "partial addressindex must render as Unknown"
        );
    }
}
