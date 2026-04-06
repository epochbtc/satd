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

    pub fee_estimates: [Option<f64>; 5],
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

    // UI state
    pub mode: ViewMode,
    pub force_mode: Option<ViewMode>,
    pub selected_peer: usize,
    pub show_help: bool,

    // Internal tracking
    prev_blocks: u32,
    prev_headers: u32,
    prev_total_downloaded: u64,
    prev_peer_blocks: HashMap<u64, u64>,
    pub connected: bool,
    pub last_poll: Option<std::time::Instant>,
    pub stale: bool,
    pub loaded: Loaded,
    /// Startup status message from satd (shown while node is loading).
    pub startup_status: Option<String>,
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

            fee_estimates: [None; 5],
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

            blocks_per_sec: 0.0,
            headers_per_sec: 0.0,
            dl_blocks_per_sec: 0.0,
            eta_secs: None,

            bps_history: VecDeque::with_capacity(HISTORY_CAP),
            dl_history: VecDeque::with_capacity(HISTORY_CAP),

            peer_dl_rates: HashMap::new(),

            ibd_bitmap: None,

            mode: ViewMode::Steady,
            force_mode: None,
            selected_peer: 0,
            show_help: false,

            prev_blocks: 0,
            prev_headers: 0,
            prev_total_downloaded: 0,
            prev_peer_blocks: HashMap::new(),
            connected: false,
            last_poll: None,
            stale: false,
            loaded: Loaded::default(),
            startup_status: None,
        }
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

    /// Update from estimatesmartfee responses (5 targets).
    pub fn update_fee_estimates(&mut self, idx: usize, v: &serde_json::Value) {
        self.loaded.fee_estimates = true;
        if idx < 5 {
            // feerate is in BTC/kvB, convert to sat/vB: * 100_000_000 / 1000 = * 100_000
            self.fee_estimates[idx] = v.get("feerate")
                .and_then(|f| f.as_f64())
                .map(|f| f * 100_000.0);
        }
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

    /// Update mempool size distribution from getrawmempool true response.
    pub fn update_mempool_dist(&mut self, v: &serde_json::Value) {
        self.loaded.mempool_dist = true;
        if let Some(obj) = v.as_object() {
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
        }
    }

    /// Update from getsysteminfo response.
    pub fn update_system_info(&mut self, v: &serde_json::Value) {
        self.loaded.system = true;
        self.rss_bytes = v.get("rss_bytes").and_then(|r| r.as_u64());
        self.thread_count = v.get("threads").and_then(|t| t.as_u64()).map(|t| t as u32);
        self.cache_dirty = v.get("cache_dirty").and_then(|c| c.as_u64()).map(|c| c as u32);
        self.cache_clean = v.get("cache_clean").and_then(|c| c.as_u64()).map(|c| c as usize);
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
