use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};
use bitcoin::Network;
use parking_lot::{Condvar, RwLock};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use base64::Engine;

use crate::chain::connect_phase::ConnectPhase;
use crate::chain::state::ChainState;
use crate::mempool::fee::FeeEstimator;
use crate::mempool::orphanage::{AddOutcome, OrphanReject, TxOrphanage};
use crate::mempool::pool::{Mempool, MempoolError};
use crate::net::compact;
use crate::net::connection::{Connection, ConnectionWriter};
use crate::net::ibd::IbdScheduler;
use crate::net::peer::{Direction, PeerAddr, PeerId, PeerInfo, PeerState};
use crate::net::proxy;
use crate::net::sync;

const MAX_OUTBOUND: usize = 8;
const MAX_OUTBOUND_IBD: usize = 64;
const BAN_THRESHOLD: u32 = 100;
/// Hardcoded fallback when callers (tests, the no-config `new` constructor)
/// don't supply a value. Operator-facing path goes through
/// `Config::maxinboundperip` and the `-maxinboundperip` CLI flag.
const DEFAULT_MAX_INBOUND_PER_IP: usize = 3;
/// Default handshake timeout in milliseconds, matching Bitcoin Core's
/// `-timeout` default (5000ms).
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5000;

/// Per-address reconnect backoff state.
struct ReconnectState {
    attempts: u32,
    next_attempt: Instant,
}

impl ReconnectState {
    fn new() -> Self {
        Self {
            attempts: 0,
            next_attempt: Instant::now(),
        }
    }

    /// Backoff delay: 10s, 20s, 40s, 80s, 160s, capped at 300s.
    fn backoff_duration(&self) -> Duration {
        let secs = 10u64.saturating_mul(1u64 << self.attempts.min(5));
        Duration::from_secs(secs.min(300))
    }

    fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.next_attempt = Instant::now() + self.backoff_duration();
    }

    fn reset(&mut self) {
        self.attempts = 0;
        self.next_attempt = Instant::now();
    }
}

/// Event sent from peer tasks to the central manager loop.
pub enum NetEvent {
    PeerConnected {
        id: PeerId,
        addr: SocketAddr,
        version: VersionMessage,
    },
    PeerDisconnected {
        id: PeerId,
    },
    MessageReceived {
        id: PeerId,
        msg: NetworkMessage,
    },
}

/// Handle for sending messages to a specific peer.
struct PeerHandle {
    info: PeerInfo,
    msg_tx: mpsc::Sender<NetworkMessage>,
}

/// Manages all peer connections and routes messages.
pub struct PeerManager {
    peers: RwLock<HashMap<PeerId, PeerHandle>>,
    chain_state: Arc<ChainState>,
    mempool: Arc<Mempool>,
    network: Network,
    next_id: AtomicU64,
    event_tx: mpsc::Sender<NetEvent>,
    event_rx: tokio::sync::Mutex<mpsc::Receiver<NetEvent>>,
    /// Track the highest header height we've stored.
    headers_tip: AtomicU64,
    /// Track blocks currently in-flight (requested but not yet received).
    #[allow(dead_code)]
    in_flight_blocks: RwLock<std::collections::HashSet<bitcoin::BlockHash>>,
    /// Configured outbound peer addresses for auto-reconnect.
    connect_addrs: RwLock<Vec<SocketAddr>>,
    /// Channel to send received blocks to the processing thread.
    block_tx: mpsc::UnboundedSender<bitcoin::Block>,
    /// Pending compact blocks awaiting missing transactions.
    pending_compact: RwLock<HashMap<bitcoin::BlockHash, compact::PendingCompact>>,
    /// Per-address reconnect backoff state.
    reconnect_backoff: RwLock<HashMap<SocketAddr, ReconnectState>>,
    /// Banned addresses with ban expiry time.
    banned_addrs: RwLock<HashMap<SocketAddr, Instant>>,
    /// Fee estimator fed from confirmed blocks (kept alive via Arc, used in block_processor).
    #[allow(dead_code)]
    fee_estimator: Arc<FeeEstimator>,
    /// Shutdown signal.
    shutdown: tokio::sync::watch::Receiver<bool>,
    /// Prune target in MB (0 = disabled).
    #[allow(dead_code)]
    prune_target_mb: u64,
    /// Maximum total connections (default: 125).
    max_connections: usize,
    /// Maximum simultaneous inbound peers from the same source IP
    /// (Core-style flood guard).
    max_inbound_per_ip: usize,
    /// Outbound `connect_outbound` calls that have started but haven't
    /// yet finished registering a peer. Used to dedup concurrent dial
    /// attempts against the same addr (e.g. an addr arriving from
    /// multiple peers' gossip).
    pending_connections: RwLock<HashSet<SocketAddr>>,
    /// Ban duration in seconds (default: 86400).
    ban_duration_secs: u64,
    /// Per-message timeout for the version/verack handshake, in
    /// milliseconds (Bitcoin Core's `-timeout`, default 5000ms). A peer
    /// that doesn't make handshake progress within this window is
    /// dropped. Stored as an atomic so the satd binary can set it from
    /// config after construction (see [`set_connect_timeout_ms`]) without
    /// widening the already-large `with_config` argument list.
    connect_timeout_ms: AtomicU64,
    /// IBD scheduler for parallel block download (shared with connect thread).
    ibd: Arc<parking_lot::RwLock<Option<IbdScheduler>>>,
    /// Signal to wake the connect thread when a block is stored.
    connect_signal: Arc<(parking_lot::Mutex<bool>, Condvar)>,
    /// SOCKS5 proxy for all outbound connections (e.g. "127.0.0.1:9050").
    proxy: Option<String>,
    /// Separate SOCKS5 proxy for .onion connections (defaults to proxy).
    onion_proxy: Option<String>,
    /// Configured outbound .onion and hostname-based peer addresses for auto-reconnect.
    connect_peer_addrs: RwLock<Vec<PeerAddr>>,
    /// Max blocks downloaded ahead of connect cursor during IBD.
    max_ahead: u32,
    /// Latest ETA (seconds) from the weight-aware IBD estimator.
    /// Written by the connect loop, read by the RPC handler.
    ibd_eta_secs: Arc<AtomicU64>,
    /// Orphan transaction pool. Txs with missing parents (from P2P relay)
    /// are deferred here instead of triggering peer bans; reconsidered on
    /// new mempool admission and on block connect.
    orphanage: Arc<TxOrphanage>,
    /// BIP 158 filter index handle. Wired post-construction via
    /// `set_filter_index` (mirrors `ChainState::set_mempool` shape) so
    /// the existing constructor surface stays unchanged. The handler
    /// arms read it for `getcfilters` / `getcfheaders` / `getcfcheckpt`,
    /// and the version handshake ORs `COMPACT_FILTERS` into our
    /// services when both the runtime advertise flag and the index's
    /// `is_complete()` say yes.
    #[cfg(feature = "block-filter-index")]
    filter_index: std::sync::OnceLock<Arc<dyn node_filter_index::FilterIndex>>,
    /// Whether the operator opted into advertising and serving the BIP
    /// 157 P2P service (`--peerblockfilters=1`). Defaults to false; set
    /// alongside `set_filter_index` from the satd binary.
    #[cfg(feature = "block-filter-index")]
    peer_serve_filters: std::sync::atomic::AtomicBool,
}

impl PeerManager {
    pub fn new(
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
        fee_estimator: Arc<FeeEstimator>,
        network: Network,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Arc<Self> {
        let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        Self::with_config(chain_state, mempool, fee_estimator, network, shutdown, 0, 125, DEFAULT_MAX_INBOUND_PER_IP, 86400, None, None, workers, 50_000, 0)
    }

    pub fn with_prune(
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
        fee_estimator: Arc<FeeEstimator>,
        network: Network,
        shutdown: tokio::sync::watch::Receiver<bool>,
        prune_target_mb: u64,
    ) -> Arc<Self> {
        let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        Self::with_config(chain_state, mempool, fee_estimator, network, shutdown, prune_target_mb, 125, DEFAULT_MAX_INBOUND_PER_IP, 86400, None, None, workers, 50_000, 0)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_config(
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
        fee_estimator: Arc<FeeEstimator>,
        network: Network,
        shutdown: tokio::sync::watch::Receiver<bool>,
        prune_target_mb: u64,
        max_connections: usize,
        max_inbound_per_ip: usize,
        ban_duration_secs: u64,
        proxy: Option<String>,
        onion_proxy: Option<String>,
        prefetch_workers: usize,
        max_ahead: u32,
        ibd_l0_pause_at: u32,
    ) -> Arc<Self> {
        let (event_tx, event_rx) = mpsc::channel(4096);
        let (block_tx, block_rx) = mpsc::unbounded_channel();
        let connect_signal = Arc::new((parking_lot::Mutex::new(false), Condvar::new()));

        // Check for IBD resume: if headers are ahead of tip, create scheduler
        let tip_height = chain_state.tip_height();
        let headers_tip_height = chain_state.headers_tip_height();
        let ibd_scheduler = if headers_tip_height > tip_height + 24 {
            let effective_max_ahead = Self::resolve_max_ahead(max_ahead, headers_tip_height, tip_height);
            let mut sched = IbdScheduler::new(headers_tip_height, tip_height, &chain_state, effective_max_ahead);
            // Scan for already-downloaded blocks (crash-resume)
            for h in (tip_height + 1)..=headers_tip_height {
                if let Some(hash) = chain_state.get_block_hash_by_height(h)
                    && chain_state.has_block_data(&hash)
                {
                    sched.mark_downloaded(h);
                }
            }
            let (dl, _inf, pend, _) = sched.progress();
            tracing::info!(
                target_height = headers_tip_height,
                already_downloaded = dl,
                pending = pend,
                "Resuming IBD with parallel scheduler"
            );
            Some(sched)
        } else {
            None
        };
        let ibd = Arc::new(parking_lot::RwLock::new(ibd_scheduler));

        let mgr = Arc::new(Self {
            peers: RwLock::new(HashMap::new()),
            chain_state: chain_state.clone(),
            mempool: mempool.clone(),
            network,
            next_id: AtomicU64::new(1),
            event_tx,
            event_rx: tokio::sync::Mutex::new(event_rx),
            headers_tip: AtomicU64::new(headers_tip_height as u64),
            in_flight_blocks: RwLock::new(std::collections::HashSet::new()),
            connect_addrs: RwLock::new(Vec::new()),
            block_tx,
            pending_compact: RwLock::new(HashMap::new()),
            fee_estimator: fee_estimator.clone(),
            reconnect_backoff: RwLock::new(HashMap::new()),
            banned_addrs: RwLock::new(HashMap::new()),
            shutdown,
            prune_target_mb,
            max_connections,
            max_inbound_per_ip,
            pending_connections: RwLock::new(HashSet::new()),
            ban_duration_secs,
            connect_timeout_ms: AtomicU64::new(DEFAULT_CONNECT_TIMEOUT_MS),
            ibd: ibd.clone(),
            connect_signal: connect_signal.clone(),
            proxy,
            onion_proxy,
            connect_peer_addrs: RwLock::new(Vec::new()),
            max_ahead,
            ibd_eta_secs: Arc::new(AtomicU64::new(0)),
            orphanage: Arc::new(TxOrphanage::with_defaults()),
            #[cfg(feature = "block-filter-index")]
            filter_index: std::sync::OnceLock::new(),
            #[cfg(feature = "block-filter-index")]
            peer_serve_filters: std::sync::atomic::AtomicBool::new(false),
        });

        // Spawn block processing thread
        let cs = chain_state;
        let mp = mempool;
        let fe = fee_estimator;
        let prune_mb = prune_target_mb;
        let eta_secs = mgr.ibd_eta_secs.clone();
        let orph = mgr.orphanage.clone();
        std::thread::spawn(move || {
            Self::block_processor(block_rx, cs, mp, fe, prune_mb, connect_signal, ibd, prefetch_workers, max_ahead, ibd_l0_pause_at, network, eta_secs, orph);
        });

        mgr
    }

    /// Set the handshake timeout (Bitcoin Core's `-timeout`), in
    /// milliseconds. Call once at startup before peers connect. A value
    /// of 0 is clamped to 1ms so the handshake can never block forever.
    pub fn set_connect_timeout_ms(&self, ms: u64) {
        self.connect_timeout_ms.store(ms.max(1), Ordering::Relaxed);
    }

    /// Resolve a max_ahead config value to an effective count.
    /// Values > 1_000_000_000 encode a percentage: 1_000_000_000 + pct.
    fn resolve_max_ahead(max_ahead: u32, target_height: u32, tip_height: u32) -> u32 {
        if max_ahead > 1_000_000_000 {
            let pct = max_ahead - 1_000_000_000;
            let remaining = target_height.saturating_sub(tip_height);
            (remaining as u64 * pct as u64 / 100) as u32
        } else {
            max_ahead
        }
    }

    /// Expose the orphanage so the RPC layer can report diagnostics.
    pub fn orphanage(&self) -> Arc<TxOrphanage> {
        self.orphanage.clone()
    }

    /// Wire the BIP 158 filter index handle. Called once at startup
    /// after both `PeerManager` and `RocksFilterIndex` are constructed.
    /// Idempotent on duplicate calls (later sets are silently ignored).
    /// `peer_serve` is the operator-side advertisement flag
    /// (`--peerblockfilters=1`).
    #[cfg(feature = "block-filter-index")]
    pub fn set_filter_index(
        &self,
        index: Arc<dyn node_filter_index::FilterIndex>,
        peer_serve: bool,
    ) {
        let _ = self.filter_index.set(index);
        self.peer_serve_filters
            .store(peer_serve, std::sync::atomic::Ordering::Relaxed);
    }

    /// Predicate consulted by `handle_message` and the version
    /// handshake: serve filters only when the operator opted in
    /// (`--peerblockfilters=1`) AND the index is complete. Backfill
    /// in flight → false (prevents advertising a service we cannot
    /// faithfully provide).
    #[cfg(feature = "block-filter-index")]
    fn peer_serve_filters_ready(&self) -> bool {
        if !self
            .peer_serve_filters
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return false;
        }
        match self.filter_index.get() {
            Some(idx) => idx.is_complete(),
            None => false,
        }
    }

    /// Register addresses for auto-reconnect.
    ///
    /// Deduped: addr/addrv2 gossip from multiple peers frequently announces
    /// the same socket address many times. Without dedup, the reconnect
    /// loop spawns one `connect_outbound` task per duplicate, and a remote
    /// peer's per-IP rate limit will FIN all but the first within a few
    /// hundred ms — surfacing as severe peer churn.
    pub fn add_connect_addr(&self, addr: SocketAddr) {
        let mut addrs = self.connect_addrs.write();
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }

    /// Register a PeerAddr (socket or .onion) for auto-reconnect. Same
    /// dedup rationale as `add_connect_addr`.
    pub fn add_peer_addr(&self, addr: PeerAddr) {
        match &addr {
            PeerAddr::Socket(sa) => {
                let mut addrs = self.connect_addrs.write();
                if !addrs.contains(sa) {
                    addrs.push(*sa);
                }
            }
            PeerAddr::Onion { .. } => {
                let mut addrs = self.connect_peer_addrs.write();
                if !addrs.contains(&addr) {
                    addrs.push(addr);
                }
            }
        }
    }

    /// Count inbound peers, returning `(total_inbound, same_ip_inbound)`.
    /// Pulled out for unit-testing the per-IP cap without a real `TcpStream`.
    ///
    /// Includes both `Connecting` and `Connected` inbound peers — review
    /// F4 (PR #181): counting only `Connected` let concurrent handshake
    /// bursts from one IP exceed `maxinboundperip` for the duration of
    /// the handshake. Pending inbound peers consume a slot from the
    /// moment we accept the TCP stream until the peer task terminates
    /// (handshake success → `Connected`, or handshake failure → peer
    /// dropped from `self.peers`). Outbound peers and disconnected
    /// peers don't count.
    fn count_inbound(peers: &HashMap<PeerId, PeerHandle>, ip: IpAddr) -> (usize, usize) {
        let mut total = 0usize;
        let mut same_ip = 0usize;
        for h in peers.values() {
            if h.info.direction != Direction::Inbound
                || h.info.state == PeerState::Disconnected
            {
                continue;
            }
            total += 1;
            if h.info.addr.ip() == ip {
                same_ip += 1;
            }
        }
        (total, same_ip)
    }

    /// Get the number of connected outbound peers.
    pub fn outbound_count(&self) -> usize {
        let peers = self.peers.read();
        peers
            .values()
            .filter(|h| {
                h.info.direction == Direction::Outbound
                    && h.info.state == PeerState::Connected
            })
            .count()
    }

    /// Check outbound connection limit.
    fn check_outbound_limit(&self) -> Result<(), String> {
        let max_outbound = if self.is_ibd() {
            MAX_OUTBOUND_IBD
        } else {
            self.max_connections.min(MAX_OUTBOUND)
        };
        let outbound = self.outbound_count();
        if outbound >= max_outbound {
            return Err("max outbound connections reached".to_string());
        }
        Ok(())
    }

    /// Connect to an outbound peer.
    pub async fn connect_outbound(self: &Arc<Self>, addr: SocketAddr) -> Result<(), String> {
        self.check_outbound_limit()?;

        // Claim the dial slot before doing any network I/O. Without this,
        // the reconnect loop can spawn multiple concurrent `connect_outbound`
        // tasks for the same addr (the addr is removed from `connect_addrs`
        // after the dial returns, not before it starts), and a remote
        // peer's per-IP rate limit will FIN all but the first.
        {
            let mut pending = self.pending_connections.write();
            if pending.contains(&addr) {
                return Err(format!("connect already in flight to {}", addr));
            }
            if self.is_addr_connected(&addr) {
                return Err(format!("already connected to {}", addr));
            }
            pending.insert(addr);
        }
        // RAII guard so the slot is released on every exit path, including
        // panics from the await points below.
        struct PendingGuard<'a> {
            set: &'a RwLock<HashSet<SocketAddr>>,
            addr: SocketAddr,
        }
        impl<'a> Drop for PendingGuard<'a> {
            fn drop(&mut self) {
                self.set.write().remove(&self.addr);
            }
        }
        let _guard = PendingGuard {
            set: &self.pending_connections,
            addr,
        };

        let stream = if let Some(ref proxy_addr) = self.proxy {
            proxy::connect_socks5(proxy_addr, addr).await?
        } else {
            TcpStream::connect(addr)
                .await
                .map_err(|e| format!("connect failed: {}", e))?
        };

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        tracing::info!(%addr, id, "Connecting to peer");

        self.spawn_peer(id, addr, stream, Direction::Outbound);
        Ok(())
    }

    /// Connect to a .onion peer address via SOCKS5 proxy.
    pub async fn connect_outbound_onion(
        self: &Arc<Self>,
        host: &str,
        port: u16,
    ) -> Result<(), String> {
        self.check_outbound_limit()?;

        // Use onion-specific proxy, or fall back to general proxy
        let proxy_addr = self
            .onion_proxy
            .as_deref()
            .or(self.proxy.as_deref())
            .ok_or("no proxy configured for .onion connections")?;

        let stream = proxy::connect_socks5_onion(proxy_addr, host, port).await?;

        // Use a placeholder SocketAddr for .onion peers (the actual routing is via proxy)
        let placeholder_addr: SocketAddr = ([0, 0, 0, 0], port).into();

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        tracing::info!(onion = host, id, "Connecting to .onion peer via proxy");

        self.spawn_peer(id, placeholder_addr, stream, Direction::Outbound);
        Ok(())
    }

    /// Connect to a PeerAddr (either socket or .onion).
    pub async fn connect_peer_addr(self: &Arc<Self>, addr: &PeerAddr) -> Result<(), String> {
        match addr {
            PeerAddr::Socket(sa) => self.connect_outbound(*sa).await,
            PeerAddr::Onion { host, port } => self.connect_outbound_onion(host, *port).await,
        }
    }

    /// Accept an inbound connection.
    ///
    /// Cap-check and slot reservation happen atomically under one
    /// write lock so concurrent accepts cannot both observe a below-
    /// limit count and proceed. Without this, the earlier shape
    /// (read-lock for count, drop lock, write-lock for insert) left
    /// a TOCTOU window that, combined with counting only `Connected`
    /// peers, let handshake bursts bypass the per-IP cap. Review F4.
    pub fn accept_inbound(self: &Arc<Self>, stream: TcpStream, addr: SocketAddr) {
        let ip = addr.ip();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let msg_rx = {
            let mut peers = self.peers.write();
            let (inbound_count, same_ip_count) = Self::count_inbound(&peers, ip);
            if inbound_count >= self.max_connections.saturating_sub(MAX_OUTBOUND) {
                tracing::warn!(%addr, "Max inbound connections reached, dropping connection");
                return;
            }
            if same_ip_count >= self.max_inbound_per_ip {
                tracing::warn!(
                    %addr,
                    same_ip_count,
                    limit = self.max_inbound_per_ip,
                    "Per-IP inbound limit reached, dropping connection",
                );
                return;
            }
            // Reserve the slot under the same write lock so further
            // accepts on this thread (or another) see this peer in
            // count_inbound's tally before they themselves cap-check.
            let (msg_tx, msg_rx) = mpsc::channel::<NetworkMessage>(256);
            let info = PeerInfo::new(id, addr, Direction::Inbound);
            peers.insert(id, PeerHandle { info, msg_tx });
            msg_rx
        };
        tracing::info!(%addr, id, "Accepted inbound peer");
        self.spawn_peer_task(id, addr, stream, Direction::Inbound, msg_rx);
    }

    /// Listen for inbound connections.
    pub async fn listen(self: &Arc<Self>, bind_addr: SocketAddr) -> Result<(), String> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("listen failed: {}", e))?;
        tracing::info!(%bind_addr, "P2P listening");

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    self.accept_inbound(stream, addr);
                }
                Err(e) => {
                    tracing::warn!("Accept error: {}", e);
                }
            }
        }
    }

    /// Disconnect a peer by address.
    pub fn disconnect(&self, addr: &SocketAddr) -> bool {
        let peers = self.peers.read();
        for (_id, handle) in peers.iter() {
            if handle.info.addr == *addr {
                let _ = handle.msg_tx.try_send(NetworkMessage::Ping(0));
                return true;
            }
        }
        false
    }

    /// Get info about all connected peers.
    pub fn get_peer_info(&self) -> Vec<serde_json::Value> {
        let peers = self.peers.read();
        peers
            .values()
            .filter(|h| h.info.state == PeerState::Connected)
            .map(|h| h.info.to_rpc_json())
            .collect()
    }

    /// Get connection count.
    pub fn connection_count(&self) -> usize {
        let peers = self.peers.read();
        peers
            .values()
            .filter(|h| h.info.state == PeerState::Connected)
            .count()
    }

    /// Get IBD download progress for the TUI dashboard.
    pub fn get_ibd_progress(&self) -> Option<serde_json::Value> {
        let ibd = self.ibd.read();
        let scheduler = ibd.as_ref()?;
        let (downloaded, in_flight, pending, target) = scheduler.progress();
        let cursor = scheduler.connect_cursor();
        let (mut bitmap, bitmap_sampled) = scheduler.block_bitmap();
        let peer_stats = scheduler.peer_stats();
        drop(ibd); // Release scheduler lock before checking chain state

        // Fix display: blocks stored on disk but no longer tracked by the scheduler
        // (downloaded, connected, and removed from scheduler sets) show as state 0.
        // Upgrade them to state 3 (downloaded) if the block data exists.
        let bitmap_start = cursor + 1;
        let total = bitmap.len();
        if total > 0 {
            let step = if bitmap_sampled {
                let range = target.saturating_sub(bitmap_start) + 1;
                range as f64 / total as f64
            } else {
                1.0
            };
            for (i, state) in bitmap.iter_mut().enumerate() {
                if *state == 0 {
                    let h = bitmap_start + (i as f64 * step) as u32;
                    if let Some(hash) = self.chain_state.get_block_hash_by_height(h)
                        && self.chain_state.has_block_data(&hash)
                    {
                        *state = 3; // stored on disk
                    }
                }
            }
        }

        let bitmap_b64 = base64::engine::general_purpose::STANDARD.encode(&bitmap);

        let eta = self.ibd_eta_secs.load(std::sync::atomic::Ordering::Relaxed);

        Some(serde_json::json!({
            "active": true,
            "connect_cursor": cursor,
            "target_height": target,
            "downloaded": downloaded,
            "in_flight": in_flight,
            "pending": pending,
            "bitmap": bitmap_b64,
            "bitmap_start": cursor + 1,
            "bitmap_sampled": bitmap_sampled,
            "eta_secs": eta,
            "peer_download_stats": peer_stats.iter().map(|(id, recv, assigned)| {
                serde_json::json!({"peer_id": id, "blocks_received": recv, "assigned": assigned})
            }).collect::<Vec<_>>(),
        }))
    }

    /// Get the list of currently banned addresses with expiry times.
    pub fn list_banned(&self) -> Vec<serde_json::Value> {
        let banned = self.banned_addrs.read();
        let now = Instant::now();
        banned
            .iter()
            .filter(|(_, expiry)| now < **expiry)
            .map(|(addr, expiry)| {
                let remaining = expiry.duration_since(now).as_secs();
                serde_json::json!({
                    "address": addr.to_string(),
                    "ban_created": 0,
                    "banned_until": remaining,
                    "ban_duration": self.ban_duration_secs,
                    "ban_reason": "node misbehaving",
                })
            })
            .collect()
    }

    /// Manually ban or unban an address.
    pub fn set_ban(&self, addr: SocketAddr, ban: bool) {
        if ban {
            self.banned_addrs
                .write()
                
                .insert(addr, Instant::now() + Duration::from_secs(self.ban_duration_secs));
        } else {
            self.banned_addrs.write().remove(&addr);
        }
    }

    /// Clear all bans.
    pub fn clear_banned(&self) {
        self.banned_addrs.write().clear();
    }

    /// Send a ping to all connected peers.
    pub fn ping_all(&self) {
        let peers = self.peers.read();
        for (_, handle) in peers.iter() {
            if handle.info.state == PeerState::Connected {
                let _ = handle.msg_tx.try_send(NetworkMessage::Ping(rand::random()));
            }
        }
    }

    /// Get the list of configured connect addresses.
    pub fn get_added_node_info(&self) -> Vec<serde_json::Value> {
        let addrs = self.connect_addrs.read();
        let peers = self.peers.read();
        addrs
            .iter()
            .map(|addr| {
                let connected = peers
                    .values()
                    .any(|h| h.info.addr == *addr && h.info.state == PeerState::Connected);
                serde_json::json!({
                    "addednode": addr.to_string(),
                    "connected": connected,
                    "addresses": [{
                        "address": addr.to_string(),
                        "connected": if connected { "outbound" } else { "false" },
                    }],
                })
            })
            .collect()
    }

    /// Check if we are in Initial Block Download.
    /// True when our validated tip is more than 24 blocks behind the highest
    /// header height received from peers, or when no headers have been received.
    fn is_ibd(&self) -> bool {
        let tip = self.chain_state.tip_height();
        let htip = self.headers_tip.load(Ordering::Relaxed) as u32;
        htip == 0 || tip + 24 < htip
    }

    /// Check if we already have a connection to this address.
    fn is_addr_connected(&self, addr: &SocketAddr) -> bool {
        let peers = self.peers.read();
        peers
            .values()
            .any(|h| h.info.addr == *addr && h.info.state != PeerState::Disconnected)
    }

    /// Check if an address is currently banned.
    fn is_addr_banned(&self, addr: &SocketAddr) -> bool {
        let banned = self.banned_addrs.read();
        matches!(banned.get(addr), Some(expiry) if Instant::now() < *expiry)
    }

    /// Add ban score to a peer. If the score exceeds BAN_THRESHOLD, the peer
    /// is disconnected, removed, and its address is banned.
    fn add_ban_score(&self, id: PeerId, score: u32, reason: &str) {
        let mut peers = self.peers.write();
        let (should_ban, ban_addr) = if let Some(handle) = peers.get_mut(&id) {
            handle.info.ban_score += score;
            if handle.info.ban_score >= BAN_THRESHOLD {
                tracing::warn!(id, addr = %handle.info.addr, score = handle.info.ban_score, reason, "Banning peer");
                (true, Some(handle.info.addr))
            } else {
                tracing::debug!(id, score = handle.info.ban_score, reason, "Increased ban score");
                (false, None)
            }
        } else {
            (false, None)
        };
        if should_ban {
            peers.remove(&id);
            if let Some(addr) = ban_addr {
                drop(peers); // release peers lock before acquiring banned_addrs lock
                self.banned_addrs
                    .write()
                    
                    .insert(addr, Instant::now() + Duration::from_secs(self.ban_duration_secs));
            }
        }
    }

    /// Run the main event loop. Returns when shutdown signal is received.
    pub async fn run(self: &Arc<Self>) {
        let mut event_rx = self.event_rx.lock().await;
        let mut sync_interval = tokio::time::interval(std::time::Duration::from_millis(500));
        let mut last_tip: u32 = 0;
        let mut ticks: u64 = 0;
        let shutdown = self.shutdown.clone();

        loop {
            // Manager-loop heartbeat: bumped on every iteration so the
            // stall watchdog has a "loop is alive" signal that is
            // independent of block arrivals. At mainnet tip the
            // connector heartbeat can be quiet for >10 min between
            // blocks, but this counter keeps ticking every ~500 ms as
            // long as the manager loop and tokio runtime are healthy.
            self.chain_state.bump_manager_heartbeat();

            // Check for shutdown
            if *shutdown.borrow() {
                tracing::info!("P2P manager shutting down");
                // Drop all peers to close connections
                self.peers.write().clear();
                return;
            }
            // Process up to 64 events per iteration, then yield for sync
            let mut processed = 0;
            loop {
                if processed >= 64 {
                    break;
                }
                match event_rx.try_recv() {
                    Ok(NetEvent::PeerConnected { id, addr: _, version }) => {
                        self.handle_peer_connected(id, version);
                    }
                    Ok(NetEvent::PeerDisconnected { id }) => {
                        self.handle_peer_disconnected(id);
                    }
                    Ok(NetEvent::MessageReceived { id, msg }) => {
                        self.handle_message(id, msg);
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => return,
                }
                processed += 1;
            }

            // Check sync progress and request more blocks
            let tip = self.chain_state.tip_height();
            let _htip = self.headers_tip.load(Ordering::Relaxed) as u32;

            // When chain advances, immediately request more blocks (don't wait for timer)
            let tip_advanced = tip != last_tip;
            if tip_advanced {
                last_tip = tip;
                // Reset reconnect backoff on chain progress
                let mut backoff = self.reconnect_backoff.write();
                for state in backoff.values_mut() {
                    state.reset();
                }
            }

            // IBD scheduler maintenance
            let has_ibd = self.ibd.read().is_some();
            if has_ibd {
                // Every 4 ticks (2s): stall detection and reassignment
                if ticks.is_multiple_of(4) {
                    let (stalled, stale_heights, silent) = {
                        let mut ibd = self.ibd.write();
                        if let Some(scheduler) = ibd.as_mut() {
                            let stalled = scheduler.detect_stalls(Duration::from_secs(15));
                            // Per-height timeout: catch heights stuck with an active peer
                            let stale = scheduler.release_stale_inflight(
                                Duration::from_secs(60),
                                Duration::from_secs(15),
                            );
                            // Silent peers are scanned AFTER releases so a
                            // peer that hit its third release on this pass
                            // gets dropped on the same tick.
                            let silent = scheduler.silent_peers(
                                crate::net::ibd::SILENT_PEER_FAILURE_THRESHOLD,
                            );
                            (stalled, stale, silent)
                        } else {
                            (Vec::new(), 0, Vec::new())
                        }
                    };
                    for peer_id in stalled {
                        tracing::debug!(peer_id, "IBD: peer stalled, reassigning blocks");
                    }
                    if stale_heights > 0 {
                        tracing::info!(stale_heights, "IBD: stale in-flight heights returned to pending");
                    }
                    for peer_id in silent {
                        let addr = self
                            .peers
                            .read()
                            .get(&peer_id)
                            .map(|h| h.info.addr.to_string())
                            .unwrap_or_else(|| "<gone>".to_string());
                        tracing::warn!(
                            peer_id,
                            addr = %addr,
                            "IBD: dropping silent peer — repeatedly failed to deliver assigned blocks"
                        );
                        // Reuse the normal disconnect flow so the scheduler
                        // gets its in-flight heights back via peer_disconnected.
                        self.handle_peer_disconnected(peer_id);
                    }
                    // Assign work to any idle peers
                    self.assign_all_peers();
                }

                // Every 20 ticks (10s): progress logging
                if ticks.is_multiple_of(20) {
                    let (cursor, target) = {
                        let ibd = self.ibd.read();
                        match ibd.as_ref() {
                            Some(s) => (s.connect_cursor(), s.target_height()),
                            None => (0, 0),
                        }
                    };
                    let (dl, inf, pend, _) = {
                        let ibd = self.ibd.read();
                        ibd.as_ref()
                            .map(|s| s.progress())
                            .unwrap_or((0, 0, 0, 0))
                    };
                    let peers_active = self.connection_count();
                    // "stored" is the count of blocks already connected,
                    // which is exactly `connect_cursor`. The prior formula
                    // `target - dl - inf - pend` (plus dl) underflowed when
                    // pending and downloaded overlapped: the priority-zone
                    // scan does not pop from pending, so an assigned and
                    // then delivered height can appear in both `downloaded`
                    // and `pending` simultaneously, making the subtraction
                    // wrap below zero. That panic crashed the sync loop and
                    // wedged IBD with the trailing blocks unrequested.
                    tracing::info!(
                        "IBD download: {}/{} stored, {} in-flight, {} pending, {} peers",
                        cursor,
                        target,
                        inf,
                        pend,
                        peers_active
                    );
                    let _ = dl; // retained for future per-tick stats
                }
            }

            // Request blocks: immediately on tip advance, or every 10 ticks as fallback
            // Skip during IBD swarming — the scheduler handles block requests
            if !has_ibd && (tip_advanced || ticks.is_multiple_of(10)) {
                let peer_ids: Vec<PeerId> = {
                    let peers = self.peers.read();
                    peers.iter()
                        .filter(|(_, h)| h.info.state == PeerState::Connected)
                        .map(|(id, _)| *id)
                        .collect()
                };
                for pid in &peer_ids {
                    self.request_missing_blocks(*pid);
                }
            }

            // Request headers: during IBD, request every 4 ticks (2s) from a few peers.
            // Requesting from ALL peers floods them and triggers rate limits.
            if self.is_ibd() && ticks.is_multiple_of(4) {
                let peer_ids: Vec<PeerId> = {
                    let peers = self.peers.read();
                    peers.iter()
                        .filter(|(_, h)| h.info.state == PeerState::Connected)
                        .map(|(id, _)| *id)
                        .take(3)
                        .collect()
                };
                for pid in &peer_ids {
                    self.send_to_peer(*pid, sync::make_getheaders(&self.chain_state));
                }
            } else if !self.is_ibd() && ticks.is_multiple_of(20) {
                let peer_ids: Vec<PeerId> = {
                    let peers = self.peers.read();
                    peers.iter()
                        .filter(|(_, h)| h.info.state == PeerState::Connected)
                        .map(|(id, _)| *id)
                        .collect()
                };
                for pid in &peer_ids {
                    self.send_to_peer(*pid, sync::make_getheaders(&self.chain_state));
                }
            }

            ticks += 1;

            // Every 60 ticks (30 seconds), expire old mempool transactions
            // and sweep expired orphans.
            if ticks.is_multiple_of(60) {
                self.mempool.remove_expired();
                let expired = self.orphanage.expire(Instant::now());
                if !expired.is_empty() {
                    tracing::debug!(count = expired.len(), "Expired orphan transactions");
                }
            }

            // Every 20 ticks (10 seconds), reconnect if below outbound target
            if ticks.is_multiple_of(20) {
                let outbound = self.outbound_count();
                let target = if self.is_ibd() { MAX_OUTBOUND_IBD } else { MAX_OUTBOUND };
                let need_peers = outbound < target;
                if need_peers {
                    let addrs = self.connect_addrs.read().clone();
                    let now = Instant::now();

                    // Clean expired bans
                    {
                        let mut banned = self.banned_addrs.write();
                        banned.retain(|_, expiry| now < *expiry);
                    }

                    for addr in addrs {
                        // Skip if already connected
                        if self.is_addr_connected(&addr) {
                            continue;
                        }
                        // Skip if banned
                        if self.is_addr_banned(&addr) {
                            continue;
                        }
                        // Check backoff timer
                        {
                            let backoff = self.reconnect_backoff.read();
                            if let Some(state) = backoff.get(&addr)
                                && now < state.next_attempt {
                                    continue;
                                }
                        }

                        // Don't exceed target
                        if self.check_outbound_limit().is_err() {
                            break;
                        }

                        let pm = Arc::clone(self);
                        tokio::spawn(async move {
                            match pm.connect_outbound(addr).await {
                                Ok(_) => {
                                    let mut backoff = pm.reconnect_backoff.write();
                                    backoff
                                        .entry(addr)
                                        .or_insert_with(ReconnectState::new)
                                        .reset();
                                }
                                Err(e) => {
                                    tracing::debug!(%addr, "Reconnect failed: {}", e);
                                    let mut backoff = pm.reconnect_backoff.write();
                                    backoff
                                        .entry(addr)
                                        .or_insert_with(ReconnectState::new)
                                        .record_failure();
                                }
                            }
                        });
                    }

                    // Also reconnect .onion peers
                    let onion_addrs = self.connect_peer_addrs.read().clone();
                    for peer_addr in onion_addrs {
                        let pm = Arc::clone(self);
                        tokio::spawn(async move {
                            if let Err(e) = pm.connect_peer_addr(&peer_addr).await {
                                tracing::debug!(%peer_addr, "Onion reconnect failed: {}", e);
                            }
                        });
                    }
                }
            }

            // Yield to tokio runtime
            sync_interval.tick().await;
        }
    }

    fn handle_peer_connected(&self, id: PeerId, version: VersionMessage) {
        {
            let mut peers = self.peers.write();
            if let Some(handle) = peers.get_mut(&id) {
                handle.info.set_version(version);
                handle.info.state = PeerState::Connected;
                tracing::info!(
                    id,
                    addr = %handle.info.addr,
                    user_agent = %handle.info.user_agent,
                    height = handle.info.best_height,
                    "Peer connected"
                );
            }
        }
        // Assign IBD work to the new peer
        let has_ibd = self.ibd.read().is_some();
        if has_ibd {
            self.assign_peer_work(id);
        }
    }

    fn handle_peer_disconnected(&self, id: PeerId) {
        let mut peers = self.peers.write();
        if let Some(handle) = peers.remove(&id) {
            tracing::info!(id, addr = %handle.info.addr, "Peer disconnected");
        }
        drop(peers);
        // Notify IBD scheduler so in-flight blocks get reassigned
        let mut ibd = self.ibd.write();
        if let Some(scheduler) = ibd.as_mut() {
            scheduler.peer_disconnected(id);
        }
    }

    fn handle_message(&self, id: PeerId, msg: NetworkMessage) {
        match msg {
            NetworkMessage::Ping(nonce) => {
                self.send_to_peer(id, NetworkMessage::Pong(nonce));
            }
            NetworkMessage::Inv(inventory) => {
                self.handle_inv(id, inventory);
            }
            NetworkMessage::Headers(headers) => {
                self.handle_headers(id, headers);
            }
            NetworkMessage::Block(block) => {
                self.handle_block(id, block);
            }
            NetworkMessage::Tx(tx) => {
                self.handle_tx(id, tx);
            }
            NetworkMessage::GetHeaders(msg) => {
                self.handle_getheaders(id, msg);
            }
            NetworkMessage::GetData(inv) => {
                self.handle_getdata(id, inv);
            }
            NetworkMessage::SendCmpct(msg) => {
                let mut peers = self.peers.write();
                if let Some(handle) = peers.get_mut(&id) {
                    handle.info.compact_blocks = msg.send_compact;
                    tracing::debug!(id, version = msg.version, "Peer supports compact blocks");
                }
            }
            NetworkMessage::CmpctBlock(msg) => {
                self.handle_compact_block(id, msg.compact_block);
            }
            NetworkMessage::GetBlockTxn(msg) => {
                self.handle_get_block_txn(id, msg.txs_request);
            }
            NetworkMessage::BlockTxn(msg) => {
                self.handle_block_txn(id, msg.transactions);
            }
            NetworkMessage::FeeFilter(rate) => {
                let mut peers = self.peers.write();
                if let Some(handle) = peers.get_mut(&id) {
                    handle.info.fee_filter = rate as u64;
                    tracing::debug!(id, rate, "Peer set fee filter");
                }
            }
            NetworkMessage::Addr(addrs) => {
                tracing::debug!(id, count = addrs.len(), "Received addr");
                for (_, addr) in &addrs {
                    if let Ok(sock_addr) = addr.socket_addr()
                        && !self.is_addr_connected(&sock_addr)
                        && !self.is_addr_banned(&sock_addr)
                    {
                        self.add_connect_addr(sock_addr);
                    }
                }
            }
            NetworkMessage::GetAddr => {
                // Respond with addresses of our connected peers
                let peers = self.peers.read();
                let wants_v2 = peers.get(&id).is_some_and(|h| h.info.wants_addrv2);
                let addr_entries: Vec<_> = peers
                    .values()
                    .filter(|h| h.info.state == PeerState::Connected)
                    .collect();

                if wants_v2 {
                    let addrs: Vec<bitcoin::p2p::address::AddrV2Message> = addr_entries
                        .iter()
                        .map(|h| {
                            let time = h.info.conn_time
                                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as u32;
                            bitcoin::p2p::address::AddrV2Message {
                                time,
                                services: h.info.services,
                                addr: bitcoin::p2p::address::AddrV2::Ipv4(match h.info.addr.ip() {
                                    std::net::IpAddr::V4(ip) => ip,
                                    std::net::IpAddr::V6(ip) => {
                                        // Try to extract mapped IPv4, otherwise skip
                                        if let Some(ip4) = ip.to_ipv4_mapped() {
                                            ip4
                                        } else {
                                            // Fall back — use AddrV2::Ipv6 instead
                                            return bitcoin::p2p::address::AddrV2Message {
                                                time,
                                                services: h.info.services,
                                                addr: bitcoin::p2p::address::AddrV2::Ipv6(ip),
                                                port: h.info.addr.port(),
                                            };
                                        }
                                    }
                                }),
                                port: h.info.addr.port(),
                            }
                        })
                        .collect();
                    if !addrs.is_empty() {
                        self.send_to_peer(id, NetworkMessage::AddrV2(addrs));
                    }
                } else {
                    let addrs: Vec<(u32, bitcoin::p2p::Address)> = addr_entries
                        .iter()
                        .map(|h| {
                            let time = h.info.conn_time
                                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as u32;
                            (time, bitcoin::p2p::Address::new(&h.info.addr, h.info.services))
                        })
                        .collect();
                    if !addrs.is_empty() {
                        self.send_to_peer(id, NetworkMessage::Addr(addrs));
                    }
                }
            }
            NetworkMessage::AddrV2(addrs) => {
                tracing::debug!(id, count = addrs.len(), "Received addrv2");
                for addr_msg in &addrs {
                    if let Ok(sock_addr) = addr_msg.socket_addr()
                        && !self.is_addr_connected(&sock_addr)
                        && !self.is_addr_banned(&sock_addr)
                    {
                        self.add_connect_addr(sock_addr);
                    }
                }
            }
            NetworkMessage::SendAddrV2 => {
                let mut peers = self.peers.write();
                if let Some(handle) = peers.get_mut(&id) {
                    handle.info.wants_addrv2 = true;
                    tracing::debug!(id, "Peer supports addrv2");
                }
            }
            NetworkMessage::NotFound(inventory) => {
                // Authoritative "I don't have this" from the peer. Until
                // this commit we logged at debug and did nothing, so the
                // height stayed in_flight for the full 60s
                // `release_stale_inflight` window before any other peer
                // could be assigned. When ALL near-cursor peers respond
                // notfound (e.g. they're pruned or not synced past the
                // connect cursor's depth), the connector wedges
                // indefinitely. Release the heights now so the next
                // `assign_all_peers` tick can try a different peer.
                let mut block_hashes: Vec<bitcoin::BlockHash> = Vec::new();
                for inv in &inventory {
                    if let Inventory::Block(h) | Inventory::WitnessBlock(h) = inv {
                        block_hashes.push(*h);
                    }
                }
                if block_hashes.is_empty() {
                    tracing::debug!(id, count = inventory.len(), "Peer sent notfound (non-block)");
                } else {
                    let mut released_heights: Vec<u32> = Vec::new();
                    {
                        let mut ibd = self.ibd.write();
                        if let Some(scheduler) = ibd.as_mut() {
                            for h in &block_hashes {
                                if let Some(entry) = self.chain_state.get_block_index(h)
                                    && scheduler.release_height(entry.height, id)
                                {
                                    released_heights.push(entry.height);
                                }
                            }
                        }
                    }
                    if released_heights.is_empty() {
                        tracing::debug!(
                            id,
                            count = block_hashes.len(),
                            "Peer sent notfound for blocks not currently in_flight to this peer"
                        );
                    } else {
                        tracing::info!(
                            peer_id = id,
                            count = released_heights.len(),
                            min_height = released_heights.iter().min().copied(),
                            max_height = released_heights.iter().max().copied(),
                            "Peer notfound: heights released for reassignment to a different peer"
                        );
                        // Trigger immediate reassignment instead of waiting
                        // for the next 2s scheduler tick.
                        self.assign_all_peers();
                    }
                }
            }
            NetworkMessage::SendHeaders => {
                tracing::debug!(id, "Peer prefers headers announcements");
            }
            #[cfg(feature = "block-filter-index")]
            NetworkMessage::GetCFilters(req) => {
                if self.peer_serve_filters_ready() {
                    self.handle_get_cfilters(id, req);
                }
                // Silent drop per BIP 157 when not serving.
            }
            #[cfg(feature = "block-filter-index")]
            NetworkMessage::GetCFHeaders(req) => {
                if self.peer_serve_filters_ready() {
                    self.handle_get_cfheaders(id, req);
                }
            }
            #[cfg(feature = "block-filter-index")]
            NetworkMessage::GetCFCheckpt(req) => {
                if self.peer_serve_filters_ready() {
                    self.handle_get_cfcheckpt(id, req);
                }
            }
            _ => {}
        }
    }

    fn handle_inv(&self, id: PeerId, inventory: Vec<Inventory>) {
        let mut blocks_to_get = Vec::new();
        let mut txs_to_get = Vec::new();

        for inv in inventory {
            match inv {
                Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
                    if self.chain_state.get_block_index(&hash).is_none() {
                        blocks_to_get.push(hash);
                    }
                }
                Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                    // Don't request transactions during IBD — we can't validate them
                    if !self.is_ibd() && self.mempool.get(&txid).is_none() {
                        txs_to_get.push(txid);
                    }
                }
                _ => {}
            }
        }

        if !blocks_to_get.is_empty() {
            self.send_to_peer(id, sync::make_getdata_blocks(&blocks_to_get));
        }
        if !txs_to_get.is_empty() {
            self.send_to_peer(id, sync::make_getdata_txs(&txs_to_get));
        }
    }

    fn handle_headers(&self, id: PeerId, headers: Vec<bitcoin::block::Header>) {
        if headers.is_empty() {
            return;
        }

        let (accepted, err) = self.chain_state.accept_headers(&headers);
        if let Some(e) = err
            && !matches!(e, crate::chain::state::ChainError::Duplicate)
        {
            self.add_ban_score(id, 20, &format!("Header rejected: {}", e));
        }

        if accepted > 0 {
            // Update headers tip tracking from actual chain state
            let htip = self.chain_state.headers_tip_height() as u64;
            self.headers_tip.store(htip, Ordering::Relaxed);

            tracing::debug!(id, accepted, headers_tip = htip, "Headers accepted");

            // Request more headers if peer sent a full batch
            if headers.len() >= 2000 {
                self.send_to_peer(id, sync::make_getheaders(&self.chain_state));
                // During header download, request from other peers too for redundancy
                let peer_ids: Vec<PeerId> = {
                    let peers = self.peers.read();
                    peers.iter()
                        .filter(|(pid, h)| **pid != id && h.info.state == PeerState::Connected)
                        .map(|(pid, _)| *pid)
                        .take(3)
                        .collect()
                };
                for pid in peer_ids {
                    self.send_to_peer(pid, sync::make_getheaders(&self.chain_state));
                }
            }

            // Start or extend IBD scheduler when headers are ahead of blocks.
            //
            // The +24 threshold only gates *creation* — once a scheduler
            // exists, extension must happen unconditionally on any new
            // headers past its target. Otherwise a late-arriving headers
            // batch (e.g. the last few blocks of a small chain) lands
            // while tip is already close to the prior target, the
            // `>tip+24` gate fails, the scheduler keeps its old target,
            // and the connector declares IBD complete with the new
            // headers' blocks unrequested. Observed on regtest
            // test_parallel_ibd: connector wedges at tip < headers tip
            // forever because request_missing_blocks (the non-IBD path)
            // only runs inside handle_headers and never sees another
            // batch trigger it.
            let tip = self.chain_state.tip_height();
            let headers_tip = htip as u32;
            {
                let mut ibd = self.ibd.write();
                if ibd.is_none() && headers_tip > tip + 24 {
                    let effective_max_ahead = Self::resolve_max_ahead(self.max_ahead, headers_tip, tip);
                    let sched = IbdScheduler::new(headers_tip, tip, &self.chain_state, effective_max_ahead);
                    let (_, _, pending, target) = sched.progress();
                    tracing::info!(
                        target_height = target,
                        blocks_to_download = pending,
                        "Starting parallel block download"
                    );
                    *ibd = Some(sched);
                    drop(ibd);
                    // Wake the block processor thread so it enters IBD mode
                    let (lock, cvar) = &*self.connect_signal;
                    *lock.lock() = true;
                    cvar.notify_one();
                    // Assign work to all connected peers
                    self.assign_all_peers();
                } else if let Some(scheduler) = ibd.as_mut()
                    && headers_tip > scheduler.target_height()
                {
                    scheduler.extend_target(headers_tip, &self.chain_state);
                    drop(ibd);
                    self.assign_all_peers();
                }
                // Scope ends here — write lock dropped before the read
                // lock below. Without the scope, the no-branch path held
                // the write lock through `self.ibd.read()`, deadlocking
                // handle_headers and wedging every test that depends on
                // block propagation (test_block_propagation,
                // test_block_sync_between_nodes, the p2p_orphan suite).
            }

            // Request blocks (legacy path for non-IBD or fallback)
            let has_ibd = self.ibd.read().is_some();
            if !has_ibd {
                self.request_missing_blocks(id);
            }
        }
    }

    /// Assign download work to all connected peers during IBD.
    fn assign_all_peers(&self) {
        let peer_ids: Vec<PeerId> = {
            let peers = self.peers.read();
            peers.iter()
                .filter(|(_, h)| h.info.state == PeerState::Connected)
                .map(|(id, _)| *id)
                .collect()
        };
        for pid in peer_ids {
            self.assign_peer_work(pid);
        }
    }

    /// Assign IBD download work to a specific peer.
    ///
    /// Skips peers whose advertised best_height in the version message is
    /// more than 1000 blocks behind our target. The 2026-05-13 mainnet
    /// wedge showed inbound peers connecting with `height=0` (likely spam
    /// or pre-sync nodes) consuming priority-zone assignments they cannot
    /// fulfill, then holding them for the full stale-timeout window
    /// before any useful peer is tried.
    fn assign_peer_work(&self, peer_id: PeerId) {
        let target_height = match self.ibd.read().as_ref() {
            Some(s) => s.target_height(),
            None => return,
        };
        let peer_height = {
            let peers = self.peers.read();
            peers.get(&peer_id).map(|h| h.info.best_height).unwrap_or(0)
        };
        // i32::saturating_sub avoids underflow for early-IBD targets.
        if (peer_height as i64) < (target_height as i64).saturating_sub(1000) {
            // Peer is not synced enough to be a useful IBD source. Skip.
            return;
        }
        let mut ibd = self.ibd.write();
        if let Some(scheduler) = ibd.as_mut() {
            scheduler.register_peer(peer_id);
            let hashes = scheduler.assign_blocks(peer_id);
            if !hashes.is_empty() {
                drop(ibd);
                for chunk in hashes.chunks(128) {
                    self.send_to_peer(peer_id, sync::make_getdata_blocks(chunk));
                }
            }
        }
    }

    fn handle_block(&self, id: PeerId, block: bitcoin::Block) {
        // Check if IBD scheduler is active
        let has_ibd = self.ibd.read().is_some();
        if has_ibd {
            let hash = block.block_hash();
            match self.chain_state.store_block(&block) {
                Ok((_, height)) => {
                    let needs_more = {
                        let mut ibd = self.ibd.write();
                        if let Some(scheduler) = ibd.as_mut() {
                            scheduler.block_received(id, height)
                        } else {
                            false
                        }
                    };
                    // Wake connect thread
                    let (lock, cvar) = &*self.connect_signal;
                    *lock.lock() = true;
                    cvar.notify_one();
                    // Assign more work if peer has capacity
                    if needs_more {
                        self.assign_peer_work(id);
                    }
                }
                Err(crate::chain::state::ChainError::Duplicate) => {
                    // Already have it, mark in scheduler anyway
                    if let Some(entry) = self.chain_state.get_block_index(&hash) {
                        let mut ibd = self.ibd.write();
                        if let Some(scheduler) = ibd.as_mut() {
                            scheduler.block_received(id, entry.height);
                        }
                    }
                }
                Err(crate::chain::state::ChainError::BadPrevBlock) => {
                    // Parent header not yet accepted — normal during swarm IBD.
                    // Don't penalize the peer; the block may become valid later.
                    tracing::debug!(%hash, "IBD block store: parent unknown, skipping");
                }
                Err(e) => {
                    tracing::debug!(%hash, "IBD block store failed: {}", e);
                    self.add_ban_score(id, 10, &format!("block rejected: {}", e));
                }
            }
            return;
        }
        // Normal mode
        let _ = self.block_tx.send(block);
    }

    /// Block processing runs on a dedicated OS thread (not tokio) to avoid
    /// blocking the async event loop during CPU-intensive validation.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn block_processor(
        mut rx: mpsc::UnboundedReceiver<bitcoin::Block>,
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
        fee_estimator: Arc<FeeEstimator>,
        prune_target_mb: u64,
        connect_signal: Arc<(parking_lot::Mutex<bool>, Condvar)>,
        ibd: Arc<parking_lot::RwLock<Option<IbdScheduler>>>,
        prefetch_workers: usize,
        max_ahead: u32,
        ibd_l0_pause_at: u32,
        network: Network,
        ibd_eta_secs: Arc<AtomicU64>,
        orphanage: Arc<TxOrphanage>,
    ) {
        let mut last_log_height: u32 = 0;
        let mut last_prune_height: u32 = 0;

        // Compute keep_blocks from prune target.
        let keep_blocks: u32 = if prune_target_mb > 0 {
            ((prune_target_mb * 1_000_000 / (2 * 1_000_000)) as u32).max(288)
        } else {
            0
        };

        // IBD connect loop: walk from tip forward, connecting stored blocks
        if ibd.read().is_some() {
            Self::ibd_connect_loop(
                &chain_state,
                &fee_estimator,
                &connect_signal,
                &ibd,
                keep_blocks,
                prefetch_workers,
                &mut last_log_height,
                &mut last_prune_height,
                max_ahead,
                ibd_l0_pause_at,
                network,
                &ibd_eta_secs,
            );
        }

        // Normal mode: process blocks from the channel.
        // Periodically check if the IBD scheduler was activated (header download completed
        // while we were in normal mode), and switch to the IBD connect loop if so.
        let mut block_buffer: HashMap<bitcoin::BlockHash, bitcoin::Block> = HashMap::new();
        loop {
            // Check if IBD scheduler was activated
            if ibd.read().is_some() {
                Self::ibd_connect_loop(
                    &chain_state,
                    &fee_estimator,
                    &connect_signal,
                    &ibd,
                    keep_blocks,
                    prefetch_workers,
                    &mut last_log_height,
                    &mut last_prune_height,
                    max_ahead,
                    ibd_l0_pause_at,
                    network,
                    &ibd_eta_secs,
                );
                continue;
            }

            // Wait for a block from the channel, but wake up periodically
            // to check for IBD scheduler activation
            let (lock, cvar) = &*connect_signal;
            let mut ready = lock.lock();
            *ready = false;
            // Wait up to 500ms — will be woken immediately if a block is stored
            let _ = cvar.wait_for(&mut ready, Duration::from_millis(500));

            // Drain all available blocks from the channel
            while let Ok(block) = rx.try_recv() {
                let hash = block.block_hash();
                // Compute fees BEFORE accept_block — connect_block removes spent coins.
                let fees = Self::compute_block_fee_rates(&block, &chain_state);
                match chain_state.accept_block(&block) {
                    Ok(_) => {
                        chain_state.bump_connect_heartbeat();
                        fee_estimator.record_block(&fees);
                        mempool.remove_for_block(&block, chain_state.tip_height());
                        reconsider_orphans_on_block(&orphanage, &mempool, &chain_state, &block);
                        // Drain buffer
                        loop {
                            let tip = chain_state.tip_hash();
                            match block_buffer.remove(&tip) {
                                Some(b) => {
                                    let b_fees = Self::compute_block_fee_rates(&b, &chain_state);
                                    match chain_state.accept_block(&b) {
                                        Ok(_) => {
                                            chain_state.bump_connect_heartbeat();
                                            fee_estimator.record_block(&b_fees);
                                            mempool.remove_for_block(&b, chain_state.tip_height());
                                            reconsider_orphans_on_block(&orphanage, &mempool, &chain_state, &b);
                                        }
                                        Err(_) => break,
                                    }
                                }
                                None => break,
                            }
                        }
                        let height = chain_state.tip_height();
                        if height / 1000 > last_log_height / 1000 {
                            tracing::info!(height, buffered = block_buffer.len(), "IBD progress");
                            last_log_height = height;
                        }

                        // Flush UTXO cache immediately in normal mode (not IBD).
                        // This only happens once per ~10 min so has no performance impact.
                        let _ = chain_state.flush_coin_cache();

                        // Periodic pruning
                        if keep_blocks > 0 && height > keep_blocks
                            && height / 1000 > last_prune_height / 1000
                        {
                            let deleted = chain_state.prune_blocks(keep_blocks);
                            if deleted > 0 {
                                tracing::info!(height, deleted, "Pruned old block files");
                            }
                            last_prune_height = height;
                        }
                    }
                    Err(crate::chain::state::ChainError::Duplicate) => {}
                    Err(crate::chain::state::ChainError::BadPrevBlock) => {
                        if block_buffer.len() < 8192 {
                            block_buffer.insert(block.header.prev_blockhash, block);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%hash, "Block rejected: {}", e);
                    }
                }
            }
        }
    }

    /// IBD connect loop: sequentially connect stored blocks from tip forward.
    /// Uses a prefetch pipeline to read and pre-process upcoming blocks in
    /// background threads while the connect thread works on the current block.
    /// Sleeps (via condvar) when the next block isn't downloaded yet.
    ///
    /// Write-mode lifecycle: enters BulkLoad via `BulkLoadGuard::new`;
    /// restores Normal (and runs a best-effort durable flush) from the
    /// guard's `Drop` impl. That covers every exit path — clean success,
    /// persistent-failure break, scheduler-cleared break, and panic unwind
    /// — so BulkLoad semantics cannot leak into steady-state operation.
    #[allow(clippy::too_many_arguments)]
    fn ibd_connect_loop(
        chain_state: &ChainState,
        _fee_estimator: &FeeEstimator,
        connect_signal: &Arc<(parking_lot::Mutex<bool>, Condvar)>,
        ibd: &Arc<parking_lot::RwLock<Option<IbdScheduler>>>,
        keep_blocks: u32,
        prefetch_workers: usize,
        last_log_height: &mut u32,
        last_prune_height: &mut u32,
        max_ahead: u32,
        ibd_l0_pause_at: u32,
        network: Network,
        ibd_eta_secs: &Arc<AtomicU64>,
    ) {
        let mut connected_count = 0u64;
        let mut retry_count = 0u32;
        let start_time = Instant::now();
        let perf = std::sync::Arc::new(crate::perf::IbdPerf::new());

        // Weight-aware ETA estimator
        let target = ibd.read().as_ref().map(|s| s.target_height()).unwrap_or(0);
        let is_mainnet = network == Network::Bitcoin;
        let mut eta_estimator = crate::ibd_eta::IbdEtaEstimator::new(
            chain_state.tip_height(), target, is_mainnet,
        );

        // Start the prefetch pipeline
        let store: Arc<dyn crate::storage::Store + Send + Sync> =
            chain_state.store_ref().clone();
        let assumevalid_active = chain_state.is_assumevalid_active();
        let primary_engine = chain_state.primary_engine();
        tracing::info!(?primary_engine, "Prefetch speculative verifier engine");
        let prefetch_handle = crate::chain::prefetch::start_prefetcher(
            store,
            chain_state.blocks_dir().to_path_buf(),
            chain_state.tip_height() + 1,
            prefetch_workers,
            128, // lookahead blocks
            assumevalid_active,
            primary_engine,
        );

        // Enter BulkLoad mode via an RAII guard: subsequent RocksDB writes
        // skip the WAL for the duration of IBD. The guard's Drop impl runs
        // on *every* exit path from this function — normal break, panic,
        // early return — ensuring we never leak WAL-disabled semantics
        // into steady-state operation. We still call `flush_durable` every
        // 1000 blocks below so a crash during IBD replays at most ~1000
        // blocks of work.
        let _bulk_guard = BulkLoadGuard::new(chain_state);
        tracing::info!("IBD write mode: BulkLoad (WAL disabled, flush every 1000 blocks)");

        // RocksDB compaction backpressure state. We log a single warn when
        // we first start pausing in a sustained-pressure window, and a
        // single info when we resume — without this throttling the
        // backpressure loop would spam every 500ms it stays paused.
        let mut backpressure_paused = false;
        let mut backpressure_pause_started: Option<Instant> = None;

        // Track which height we've already logged as "stuck waiting for
        // block data" so we don't flood the log when the connector spins
        // for 5+ minutes on a missing height. One line per stuck height,
        // plus one refresh every 60s while still stuck.
        let mut last_stuck_log: Option<(u32, Instant)> = None;

        loop {
            // Backpressure: if RocksDB has accumulated too many L0 SST files,
            // the chainstate is on the path that wedged a 78-GB process
            // during a mainnet IBD (10k+ L0 SSTs, 4h cumulative write-stall).
            // Pause the connector here to give compaction a chance to drain
            // before we add another batch of writes. We cap the per-iteration
            // wait so a buggy or stuck compactor cannot deadlock the loop —
            // the periodic forced-compactor (a separate thread) is the
            // backstop for that case.
            if ibd_l0_pause_at > 0 {
                let mut waited = Duration::ZERO;
                let max_wait = Duration::from_secs(60);
                let poll = Duration::from_millis(500);
                loop {
                    let l0 = chain_state.chainstate_l0_files();
                    if l0 < ibd_l0_pause_at as u64 {
                        if backpressure_paused {
                            let dur = backpressure_pause_started
                                .map(|t| t.elapsed())
                                .unwrap_or_default();
                            tracing::info!(
                                l0_files = l0,
                                paused_secs = dur.as_secs(),
                                "IBD: L0 below threshold, resuming connector"
                            );
                            backpressure_paused = false;
                            backpressure_pause_started = None;
                        }
                        break;
                    }
                    if !backpressure_paused {
                        let pending = chain_state.chainstate_pending_compaction_bytes();
                        tracing::warn!(
                            l0_files = l0,
                            threshold = ibd_l0_pause_at,
                            pending_compaction_bytes = pending,
                            "IBD: L0 above pause threshold, pausing connector for compaction"
                        );
                        backpressure_paused = true;
                        backpressure_pause_started = Some(Instant::now());
                    }
                    if waited >= max_wait {
                        tracing::warn!(
                            l0_files = l0,
                            threshold = ibd_l0_pause_at,
                            waited_secs = waited.as_secs(),
                            "IBD: backpressure max-wait exceeded, proceeding anyway"
                        );
                        break;
                    }
                    std::thread::sleep(poll);
                    waited += poll;
                }
            }

            let target_height = {
                let sched = ibd.read();
                match sched.as_ref() {
                    Some(s) => s.target_height(),
                    None => break, // Scheduler cleared
                }
            };

            let tip_height = chain_state.tip_height();
            let next_height = tip_height + 1;

            if next_height > target_height {
                // Check if more headers have arrived since we started
                let headers_tip = chain_state.headers_tip_height();
                if headers_tip > target_height + 24 {
                    // More headers available — create a new scheduler for the next batch
                    tracing::info!(
                        height = tip_height,
                        blocks = connected_count,
                        new_target = headers_tip,
                        elapsed_secs = start_time.elapsed().as_secs(),
                        "IBD batch complete, starting next batch"
                    );
                    let effective_max_ahead = Self::resolve_max_ahead(max_ahead, headers_tip, tip_height);
                    let new_sched = IbdScheduler::new(headers_tip, tip_height, chain_state, effective_max_ahead);
                    *ibd.write() = Some(new_sched);
                    connected_count = 0;
                    // Update prefetch cursor for the new batch
                    prefetch_handle.advance_cursor(tip_height + 1);
                    // The run() loop will detect has_ibd=true within 2s and assign peers
                    continue;
                }
                // Truly done — flush UTXO cache and force a durable
                // checkpoint before marking IBD complete. Fail-closed: if
                // either step errors, we loop back instead of claiming
                // completion, so subsequent retries can attempt to
                // checkpoint again. The BulkLoadGuard restores Normal
                // write mode on any actual exit path.
                chain_state.connect_phases().enter(ConnectPhase::FlushingCoinCache);
                if let Err(e) = chain_state.flush_coin_cache() {
                    tracing::error!(
                        error = %e,
                        "IBD completion: flush_coin_cache failed; deferring completion"
                    );
                    chain_state.connect_phases().enter(ConnectPhase::Idle);
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
                chain_state.connect_phases().enter(ConnectPhase::FlushDurable);
                if let Err(e) = chain_state.flush_durable() {
                    tracing::error!(
                        error = %e,
                        "IBD completion: flush_durable failed; deferring completion \
                         (will retry on next loop iteration)"
                    );
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
                tracing::info!(
                    height = tip_height,
                    blocks = connected_count,
                    elapsed_secs = start_time.elapsed().as_secs(),
                    "IBD complete"
                );
                *ibd.write() = None;
                break;
            }

            let hash = match chain_state.get_block_hash_by_height(next_height) {
                Some(h) => h,
                None => {
                    // No header for this height yet — wait
                    chain_state.connect_phases().enter(ConnectPhase::WaitingForHeader);
                    let (lock, cvar) = &**connect_signal;
                    let mut ready = lock.lock();
                    *ready = false;
                    let _ = cvar.wait_for(&mut ready, Duration::from_secs(1));
                    chain_state.connect_phases().enter(ConnectPhase::Idle);
                    continue;
                }
            };

            if chain_state.has_block_data(&hash) {
                // Try to get a pre-processed block from the prefetcher
                let connect_start = Instant::now();
                let connect_result = match prefetch_handle.take_block(next_height) {
                    Some(pre) if pre.hash == hash => {
                        perf.prefetch_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let spec_count = pre.script_verified_txs.len() as u64;
                        if spec_count > 0 {
                            perf.spec_verify_skipped.fetch_add(spec_count, std::sync::atomic::Ordering::Relaxed);
                        }
                        chain_state.connect_preprocessed_block(pre)
                    }
                    _ => {
                        perf.prefetch_misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        chain_state.connect_stored_block(&hash)
                    }
                };
                perf.connect_ns.fetch_add(connect_start.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
                perf.connect_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                match connect_result {
                    Ok(_) => {
                        connected_count += 1;
                        retry_count = 0;
                        // Lock-free progress signal for the stall watchdog.
                        // Must run on every successful connect, before any
                        // subsequent step that takes a lock the watchdog
                        // would otherwise block on.
                        chain_state.bump_connect_heartbeat();
                        // Clear any prior connect-failure warnings now that
                        // we've made forward progress.
                        chain_state.warnings().clear("connect.persistent_failure");
                        chain_state.warnings().clear("connect.retry");
                        // Update scheduler connect cursor
                        {
                            let mut sched = ibd.write();
                            if let Some(s) = sched.as_mut() {
                                s.connect_cursor_advanced(next_height);
                            }
                        }
                        // Tell the prefetcher we've advanced
                        prefetch_handle.advance_cursor(next_height + 1);

                        // Skip fee recording during IBD — the coins are already
                        // spent so get_coin returns None for every input, and fee
                        // data from old blocks is useless for estimation anyway.

                        // Flush if dirty map is getting large (caps memory usage)
                        if chain_state.cache_dirty_count() > chain_state.flush_threshold() {
                            chain_state.connect_phases().enter(ConnectPhase::FlushingCoinCache);
                            if let Err(e) = chain_state.flush_coin_cache() {
                                tracing::error!("Failed to flush cache: {}", e);
                                chain_state.warnings().record(
                                    "storage.flush_coin_cache_failed",
                                    crate::warnings::Severity::Error,
                                    format!("UTXO cache flush failed: {}", e),
                                    serde_json::json!({ "height": next_height, "error": e.to_string() }),
                                );
                            } else {
                                chain_state.warnings().clear("storage.flush_coin_cache_failed");
                            }
                            chain_state.connect_phases().enter(ConnectPhase::Idle);
                        }

                        // Log progress
                        if next_height / 1000 > *last_log_height / 1000 {
                            let elapsed = start_time.elapsed().as_secs().max(1);
                            let rate = connected_count / elapsed;
                            let (dl, inf, pend, _) = {
                                let sched = ibd.read();
                                sched.as_ref()
                                    .map(|s| s.progress())
                                    .unwrap_or((0, 0, 0, 0))
                            };
                            // Transfer cache perf counters and report
                            {
                                let store = chain_state.store_ref();
                                perf.cache_dirty_hits.fetch_add(
                                    store.perf_dirty_hits.swap(0, std::sync::atomic::Ordering::Relaxed),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                perf.cache_clean_hits.fetch_add(
                                    store.perf_clean_hits.swap(0, std::sync::atomic::Ordering::Relaxed),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                perf.cache_store_misses.fetch_add(
                                    store.perf_store_misses.swap(0, std::sync::atomic::Ordering::Relaxed),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                            }
                            perf.report(next_height);

                            // Feed the ETA estimator with this interval's wall-clock time
                            let interval_ms = perf.last_interval_ms.load(std::sync::atomic::Ordering::Relaxed);
                            eta_estimator.record_interval(next_height, interval_ms as f64 / 1000.0);
                            let eta_str = match eta_estimator.estimate_eta(next_height, target_height) {
                                Some(secs) => {
                                    ibd_eta_secs.store(secs, std::sync::atomic::Ordering::Relaxed);
                                    format!("ETA: {}", crate::ibd_eta::format_eta(secs))
                                }
                                None => {
                                    ibd_eta_secs.store(0, std::sync::atomic::Ordering::Relaxed);
                                    "ETA: --".to_string()
                                }
                            };

                            tracing::info!(
                                height = next_height,
                                "IBD: {}/{} connected, {} downloaded ahead, {} in-flight, {} pending ({} blk/s, {})",
                                next_height,
                                target_height,
                                dl,
                                inf,
                                pend,
                                rate,
                                eta_str,
                            );
                            *last_log_height = next_height;

                            // Flush UTXO cache to disk every 1000 blocks, then
                            // force a durable checkpoint. With BulkLoad mode
                            // (WAL disabled) this bounds crash-recovery replay
                            // work to the last ~1000 blocks.
                            chain_state.connect_phases().enter(ConnectPhase::FlushingCoinCache);
                            if let Err(e) = chain_state.flush_coin_cache() {
                                tracing::error!("Failed to flush UTXO cache: {}", e);
                                chain_state.warnings().record(
                                    "storage.flush_coin_cache_failed",
                                    crate::warnings::Severity::Error,
                                    format!("UTXO cache flush failed: {}", e),
                                    serde_json::json!({ "height": next_height, "error": e.to_string() }),
                                );
                            } else {
                                chain_state.warnings().clear("storage.flush_coin_cache_failed");
                            }
                            chain_state.connect_phases().enter(ConnectPhase::FlushDurable);
                            if let Err(e) = chain_state.flush_durable() {
                                tracing::error!("Failed durable checkpoint: {}", e);
                                chain_state.warnings().record(
                                    "storage.flush_durable_failed",
                                    crate::warnings::Severity::Error,
                                    format!("durable checkpoint failed: {}", e),
                                    serde_json::json!({ "height": next_height, "error": e.to_string() }),
                                );
                            } else {
                                chain_state.warnings().clear("storage.flush_durable_failed");
                            }
                            chain_state.connect_phases().enter(ConnectPhase::Idle);
                        }
                        // Periodic pruning
                        if keep_blocks > 0 && next_height > keep_blocks
                            && next_height / 1000 > *last_prune_height / 1000
                        {
                            let deleted = chain_state.prune_blocks(keep_blocks);
                            if deleted > 0 {
                                tracing::info!(height = next_height, deleted, "Pruned old block files");
                            }
                            *last_prune_height = next_height;
                        }
                        continue; // Immediately try next block
                    }
                    Err(crate::chain::state::ChainError::Duplicate) => {
                        // Already connected (shouldn't happen but harmless)
                        continue;
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count >= 30 {
                            tracing::error!(
                                height = next_height, %hash, retries = retry_count,
                                "Persistent connect failure, giving up: {}", e
                            );
                            chain_state.warnings().record(
                                "connect.persistent_failure",
                                crate::warnings::Severity::Error,
                                format!(
                                    "block {} ({}) failed to connect after {} retries: {}",
                                    next_height, hash, retry_count, e
                                ),
                                serde_json::json!({
                                    "height": next_height,
                                    "hash": hash.to_string(),
                                    "retries": retry_count,
                                    "error": e.to_string(),
                                }),
                            );
                            // Force a restart by breaking the loop — systemd will restart us
                            break;
                        }
                        if retry_count.is_multiple_of(10) {
                            tracing::warn!(
                                height = next_height, %hash, retries = retry_count,
                                "Connect stored block failed (retrying): {}", e
                            );
                            chain_state.warnings().record(
                                "connect.retry",
                                crate::warnings::Severity::Warn,
                                format!(
                                    "block {} ({}) connect retry {}: {}",
                                    next_height, hash, retry_count, e
                                ),
                                serde_json::json!({
                                    "height": next_height,
                                    "hash": hash.to_string(),
                                    "retries": retry_count,
                                    "error": e.to_string(),
                                }),
                            );
                        }
                        chain_state.connect_phases().enter(ConnectPhase::CondvarWait);
                        let (lock, cvar) = &**connect_signal;
                        let mut ready = lock.lock();
                        *ready = false;
                        let _ = cvar.wait_for(&mut ready, Duration::from_secs(1));
                        chain_state.connect_phases().enter(ConnectPhase::Idle);
                        continue;
                    }
                }
            } else {
                // Next block not downloaded yet — wait for signal
                chain_state.connect_phases().enter(ConnectPhase::WaitingForBlockData);
                // Diagnostic for the wedge class where the connector spins
                // forever on a HeaderOnly entry whose data never arrives.
                // Log once per stuck height, then refresh every 60s with a
                // scheduler-state snapshot so we can see if the downloader
                // is even trying. Cheap: the scheduler read is a single
                // RwLock::read() and three HashMap lookups.
                let should_log = match last_stuck_log {
                    None => true,
                    Some((h, _)) if h != next_height => true,
                    Some((_, t)) => t.elapsed() >= Duration::from_secs(60),
                };
                if should_log {
                    let (
                        in_pending,
                        in_flight,
                        downloaded,
                        has_height_to_hash,
                        inflight_peer,
                        inflight_age,
                        peer_load,
                    ) = {
                        let sched = ibd.read();
                        match sched.as_ref() {
                            Some(s) => {
                                let p = s.inflight_peer(next_height);
                                (
                                    s.pending_contains(next_height),
                                    s.in_flight_contains(next_height),
                                    s.is_downloaded(next_height),
                                    s.height_to_hash_contains(next_height),
                                    p,
                                    s.inflight_age_secs(next_height),
                                    p.map(|pid| s.peer_inflight_count(pid)),
                                )
                            }
                            None => (false, false, false, false, None, None, None),
                        }
                    };
                    let inflight_peer_height = inflight_peer.and_then(|pid| {
                        // Note: we don't have a back-ref to `self` here
                        // (this is in block_processor), so look up via the
                        // ChainState-less PeerManager Arc would require
                        // passing it in. Leaving as None for now keeps
                        // this diagnostic single-purpose — the peer ID is
                        // enough to grep the journal for that peer's
                        // version log.
                        let _ = pid;
                        None::<i32>
                    });
                    let entry = chain_state.get_block_index(&hash);
                    tracing::warn!(
                        height = next_height,
                        %hash,
                        in_pending,
                        in_flight,
                        downloaded,
                        has_height_to_hash,
                        ?inflight_peer,
                        ?inflight_age,
                        ?peer_load,
                        ?inflight_peer_height,
                        block_index_status = ?entry.as_ref().map(|e| e.status),
                        file_number = entry.as_ref().map(|e| e.file_number),
                        data_pos = entry.as_ref().map(|e| e.data_pos),
                        "Connector stuck waiting for block data; scheduler state for this height"
                    );
                    last_stuck_log = Some((next_height, Instant::now()));
                }
                let (lock, cvar) = &**connect_signal;
                let mut ready = lock.lock();
                *ready = false;
                let _ = cvar.wait_for(&mut ready, Duration::from_secs(1));
                chain_state.connect_phases().enter(ConnectPhase::Idle);
            }
        }

        // Stop the prefetch pipeline
        prefetch_handle.stop();
    }

    /// Extract fee rates from a connected block and feed them to the fee estimator.
    /// Compute per-tx fee rates (sat/kvB) for a block. Must be called BEFORE
    /// `accept_block`, since connect_block removes spent coins from the UTXO set.
    /// Intra-block spends are skipped (the prior tx's outputs are not yet in
    /// the UTXO set at this point).
    fn compute_block_fee_rates(block: &bitcoin::Block, chain_state: &ChainState) -> Vec<u64> {
        let mut fee_rates = Vec::new();
        for tx in &block.txdata {
            if tx.is_coinbase() {
                continue;
            }
            let weight = tx.weight().to_wu();
            if weight == 0 {
                continue;
            }
            let mut sum_inputs: u64 = 0;
            let mut inputs_found = true;
            for input in &tx.input {
                match chain_state.get_coin(&input.previous_output) {
                    Some(coin) => sum_inputs += coin.amount,
                    None => {
                        inputs_found = false;
                        break;
                    }
                }
            }
            if !inputs_found {
                continue;
            }
            let sum_outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
            if sum_inputs >= sum_outputs {
                let fee = sum_inputs - sum_outputs;
                let fee_rate = fee * 1000 / weight; // sat/kvB
                fee_rates.push(fee_rate);
            }
        }
        fee_rates
    }

    fn handle_tx(&self, id: PeerId, tx: bitcoin::Transaction) {
        // During IBD, ignore relayed transactions — our UTXO set is incomplete
        // so validation would produce false MissingInputs rejections.
        if self.is_ibd() {
            return;
        }

        let txid = tx.compute_txid();
        match self.mempool.accept_transaction(
            tx.clone(),
            &self.chain_state,
            self.chain_state.script_verifier(),
        ) {
            Ok(_) => {
                self.broadcast_inv(id, txid);
                // A new parent just entered the mempool — walk orphans
                // that were waiting on it and try to admit them.
                self.drain_orphans_for_parent(txid);
            }
            Err(MempoolError::MissingInputs) => {
                // Don't ban — peer may just be ahead of us. Defer to
                // orphanage and ask the same peer for the parents.
                let missing = self.collect_missing_parents(&tx);
                match self.orphanage.add(tx, id, missing.clone()) {
                    Ok(AddOutcome::Added) => {
                        let want: Vec<bitcoin::Txid> = missing.into_iter().collect();
                        self.send_to_peer(id, sync::make_getdata_txs(&want));
                        tracing::debug!(%txid, peer = id, "Tx deferred to orphanage");
                    }
                    Ok(AddOutcome::Duplicate) => {
                        // Peer resent an orphan we already hold. Don't
                        // amplify their traffic by re-requesting the same
                        // parents; parents are already being awaited from
                        // the original sender (and natural propagation).
                        tracing::trace!(
                            %txid,
                            peer = id,
                            "Duplicate orphan, skipping parent re-request"
                        );
                    }
                    Err(OrphanReject::NoMissingParents) => {
                        // Race: parent entered mempool between accept and
                        // collect. Drop silently — the peer will re-relay
                        // the child via normal INV once we announce the
                        // parent, or another peer will redeliver.
                        tracing::debug!(
                            %txid,
                            peer = id,
                            "Orphan with no resolvable missing parents, dropping"
                        );
                    }
                    Err(OrphanReject::TooLarge) => {
                        self.add_ban_score(id, 1, "orphan too large");
                    }
                }
            }
            Err(e) => {
                tracing::debug!(%txid, "Tx rejected: {}", e);
                self.add_ban_score(id, 1, &format!("Tx rejected: {}", e));
            }
        }
    }

    /// Inspect `tx`'s inputs and return the set of parent txids whose
    /// outputs we can't resolve in either the confirmed UTXO set or the
    /// current mempool. Used to decide which parents to ask for after
    /// orphaning a tx.
    fn collect_missing_parents(
        &self,
        tx: &bitcoin::Transaction,
    ) -> std::collections::HashSet<bitcoin::Txid> {
        let mut missing = std::collections::HashSet::new();
        for input in &tx.input {
            let parent = input.previous_output.txid;
            if self.chain_state.get_coin(&input.previous_output).is_some() {
                continue;
            }
            if self.mempool.get(&parent).is_some() {
                continue;
            }
            missing.insert(parent);
        }
        missing
    }

    /// Relay a newly-admitted tx to other peers whose fee filter allows it.
    fn broadcast_inv(&self, from: PeerId, txid: bitcoin::Txid) {
        let entry_fee_rate = self.mempool.get(&txid).map(|e| e.fee_rate).unwrap_or(0);
        let inv = NetworkMessage::Inv(vec![Inventory::WitnessTransaction(txid)]);
        let peers = self.peers.read();
        for (peer_id, handle) in peers.iter() {
            if *peer_id != from
                && handle.info.state == PeerState::Connected
                && entry_fee_rate >= handle.info.fee_filter
            {
                let _ = handle.msg_tx.try_send(inv.clone());
            }
        }
    }

    /// BFS-drain orphans that listed `parent` as a missing parent. Newly
    /// admitted children recursively trigger further drains. Orphans that
    /// still don't validate (other missing parents, or genuinely invalid)
    /// are re-orphaned or silently dropped.
    fn drain_orphans_for_parent(&self, parent: bitcoin::Txid) {
        use std::collections::VecDeque;
        let mut queue: VecDeque<bitcoin::Txid> =
            self.orphanage.children_of(&parent).into_iter().collect();
        while let Some(child_txid) = queue.pop_front() {
            let Some(child) = self.orphanage.remove(&child_txid) else {
                continue;
            };
            let result = self.mempool.accept_transaction(
                child.tx.clone(),
                &self.chain_state,
                self.chain_state.script_verifier(),
            );
            match result {
                Ok(_) => {
                    self.broadcast_inv(child.from_peer, child_txid);
                    for grandchild in self.orphanage.children_of(&child_txid) {
                        queue.push_back(grandchild);
                    }
                }
                Err(MempoolError::MissingInputs) => {
                    // Other parents still missing — re-orphan. If
                    // `collect_missing_parents` now returns empty (race),
                    // `add` returns NoMissingParents and we drop silently.
                    let missing = self.collect_missing_parents(&child.tx);
                    let _ = self.orphanage.add(child.tx, child.from_peer, missing);
                }
                Err(e) => {
                    tracing::debug!(%child_txid, "Orphan re-evaluation failed: {}", e);
                }
            }
        }
    }

    /// Called after a block connects: reconsider orphans whose missing
    /// parent is now confirmed. Used from the block-processor thread via
    /// the free-standing [`reconsider_orphans_on_block`] helper below.
    /// Orphans admitted here are not relayed — peers will naturally
    /// re-announce, and the block-connect path has no peer context.
    pub fn reconsider_orphans_for_block(&self, block: &bitcoin::Block) {
        reconsider_orphans_on_block(
            &self.orphanage,
            &self.mempool,
            &self.chain_state,
            block,
        );
    }

    /// `getcfilters` handler per BIP 157.
    /// Validates filter type, range bounds, and active-chain stop hash;
    /// silent-drops any violation. On success, replies with one
    /// `CFilter` per height in the requested range (BIP 157 specifies
    /// per-height responses, not a batched form).
    #[cfg(feature = "block-filter-index")]
    fn handle_get_cfilters(&self, id: PeerId, req: bitcoin::p2p::message_filter::GetCFilters) {
        use crate::index::filter::lookups::MAX_GETCFILTERS_SIZE;
        use node_filter_index::FILTER_TYPE_BASIC;
        let bitcoin::p2p::message_filter::GetCFilters {
            filter_type,
            start_height,
            stop_hash,
        } = req;
        // Filter type guard.
        if filter_type != FILTER_TYPE_BASIC {
            return;
        }
        // Resolve stop_hash → stop_height via block_index.
        let Some(stop_entry) = self.chain_state.get_block_index(&stop_hash) else {
            return;
        };
        let stop_height = stop_entry.height;
        // BIP 157: stop_height ≥ start_height, range < 1000.
        if stop_height < start_height {
            return;
        }
        if stop_height - start_height >= MAX_GETCFILTERS_SIZE {
            return;
        }
        // Active-chain check: stop_hash must match the active chain at stop_height.
        match self.chain_state.get_block_hash_by_height(stop_height) {
            Some(h) if h == stop_hash => {}
            _ => return,
        }
        let Some(idx) = self.filter_index.get() else {
            return;
        };
        // Stream responses via an async task with backpressure. The
        // 256-slot per-peer mpsc channel cannot fit a full
        // 1000-message response; `try_send` would silently drop the
        // tail (review 2026-05-04 H3). Spawn a task that holds the
        // peer's `Sender` clone and `await`s each send so the slow-
        // consumer/queue-full case naturally backpressures instead of
        // truncating the protocol response.
        let msg_tx = {
            let peers = self.peers.read();
            peers.get(&id).map(|h| h.msg_tx.clone())
        };
        let Some(msg_tx) = msg_tx else {
            return;
        };
        let chain_state = self.chain_state.clone();
        let idx = idx.clone();
        tokio::spawn(async move {
            for h in start_height..=stop_height {
                let Some(block_hash) = chain_state.get_block_hash_by_height(h) else {
                    return;
                };
                let Ok(filter) = idx.filter_at(filter_type, h) else {
                    return;
                };
                if msg_tx
                    .send(NetworkMessage::CFilter(
                        bitcoin::p2p::message_filter::CFilter {
                            filter_type,
                            block_hash,
                            filter,
                        },
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
    }

    /// `getcfheaders` handler per BIP 157.
    /// Replies with a single `CFHeaders` carrying
    /// `previous_filter_header` plus per-height filter hashes (computed
    /// on the fly from the stored filter blob — see plan §"Filter-hash
    /// CF for getcfheaders recompute" for why we don't persist a third
    /// CF).
    #[cfg(feature = "block-filter-index")]
    fn handle_get_cfheaders(&self, id: PeerId, req: bitcoin::p2p::message_filter::GetCFHeaders) {
        use crate::index::filter::lookups::MAX_GETCFHEADERS_SIZE;
        use bitcoin::bip158::FilterHash;
        use bitcoin::hashes::Hash;
        use node_filter_index::FILTER_TYPE_BASIC;
        let bitcoin::p2p::message_filter::GetCFHeaders {
            filter_type,
            start_height,
            stop_hash,
        } = req;
        if filter_type != FILTER_TYPE_BASIC {
            return;
        }
        let Some(stop_entry) = self.chain_state.get_block_index(&stop_hash) else {
            return;
        };
        let stop_height = stop_entry.height;
        if stop_height < start_height {
            return;
        }
        // Bitcoin Core / BIP 157 cap getcfheaders at 2000, not the 1000
        // that applies to getcfilters. Review 2026-05-04 M1.
        if stop_height - start_height >= MAX_GETCFHEADERS_SIZE {
            return;
        }
        match self.chain_state.get_block_hash_by_height(stop_height) {
            Some(h) if h == stop_hash => {}
            _ => return,
        }
        let Some(idx) = self.filter_index.get() else {
            return;
        };
        // previous_filter_header: header at start_height - 1, or all-zeros for height 0.
        let previous_filter_header = if start_height == 0 {
            bitcoin::bip158::FilterHeader::from_byte_array([0u8; 32])
        } else {
            let Ok(prev) = idx.header_at(filter_type, start_height - 1) else {
                return;
            };
            bitcoin::bip158::FilterHeader::from_byte_array(prev)
        };
        // filter_hashes: sha256d(filter_blob) per height.
        let mut filter_hashes = Vec::with_capacity((stop_height - start_height + 1) as usize);
        for h in start_height..=stop_height {
            let Ok(blob) = idx.filter_at(filter_type, h) else {
                return;
            };
            let hash = bitcoin::hashes::sha256d::Hash::hash(&blob).to_byte_array();
            filter_hashes.push(FilterHash::from_byte_array(hash));
        }
        self.send_to_peer(
            id,
            NetworkMessage::CFHeaders(bitcoin::p2p::message_filter::CFHeaders {
                filter_type,
                stop_hash,
                previous_filter_header,
                filter_hashes,
            }),
        );
    }

    /// `getcfcheckpt` handler per BIP 157 — filter headers at every
    /// 1000-block boundary up to (and including) the highest 1000-block
    /// boundary ≤ `stop_height`.
    #[cfg(feature = "block-filter-index")]
    fn handle_get_cfcheckpt(&self, id: PeerId, req: bitcoin::p2p::message_filter::GetCFCheckpt) {
        use bitcoin::hashes::Hash;
        use node_filter_index::FILTER_TYPE_BASIC;
        let bitcoin::p2p::message_filter::GetCFCheckpt {
            filter_type,
            stop_hash,
        } = req;
        if filter_type != FILTER_TYPE_BASIC {
            return;
        }
        let Some(stop_entry) = self.chain_state.get_block_index(&stop_hash) else {
            return;
        };
        let stop_height = stop_entry.height;
        match self.chain_state.get_block_hash_by_height(stop_height) {
            Some(h) if h == stop_hash => {}
            _ => return,
        }
        let Some(idx) = self.filter_index.get() else {
            return;
        };
        let max_idx = stop_height / 1000;
        let mut filter_headers = Vec::with_capacity(max_idx as usize);
        for i in 1..=max_idx {
            let h = i * 1000;
            if h > stop_height {
                break;
            }
            let Ok(header) = idx.header_at(filter_type, h) else {
                return;
            };
            filter_headers.push(bitcoin::bip158::FilterHeader::from_byte_array(header));
        }
        self.send_to_peer(
            id,
            NetworkMessage::CFCheckpt(bitcoin::p2p::message_filter::CFCheckpt {
                filter_type,
                stop_hash,
                filter_headers,
            }),
        );
    }

    fn handle_getheaders(
        &self,
        id: PeerId,
        msg: bitcoin::p2p::message_blockdata::GetHeadersMessage,
    ) {
        let mut start_height = None;
        for hash in &msg.locator_hashes {
            if let Some(entry) = self.chain_state.get_block_index(hash) {
                start_height = Some(entry.height + 1);
                break;
            }
        }

        let start = start_height.unwrap_or(0);
        let tip = self.chain_state.tip_height();
        let end = std::cmp::min(start + 2000, tip + 1);

        let mut headers = Vec::new();
        for h in start..end {
            if let Some(hash) = self.chain_state.get_block_hash_by_height(h)
                && let Some(entry) = self.chain_state.get_block_index(&hash) {
                    headers.push(entry.header);
                }
        }

        // Always send a Headers reply, even when empty. Bitcoin Core and
        // btcd both unconditionally respond to getheaders; some Core
        // versions track silent-drops as soft misbehavior. Empty reply
        // signals "I have nothing newer than your locator."
        self.send_to_peer(id, NetworkMessage::Headers(headers));
    }

    fn handle_getdata(&self, id: PeerId, inventory: Vec<Inventory>) {
        let mut not_found = Vec::new();
        for inv in inventory {
            match inv {
                Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
                    if let Some(block) = self.chain_state.get_block(&hash) {
                        self.send_to_peer(id, NetworkMessage::Block(block));
                    } else {
                        not_found.push(inv);
                    }
                }
                Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                    if let Some(entry) = self.mempool.get(&txid) {
                        self.send_to_peer(id, NetworkMessage::Tx(entry.tx));
                    } else {
                        not_found.push(inv);
                    }
                }
                _ => {}
            }
        }
        if !not_found.is_empty() {
            self.send_to_peer(id, NetworkMessage::NotFound(not_found));
        }
    }

    fn handle_compact_block(&self, id: PeerId, compact: bitcoin::bip152::HeaderAndShortIds) {
        let block_hash = compact.header.block_hash();

        // Skip if we already have this block
        if let Some(entry) = self.chain_state.get_block_index(&block_hash)
            && entry.status != crate::storage::blockindex::BlockStatus::HeaderOnly {
                return;
            }

        match compact::try_reconstruct(&compact, &self.mempool) {
            Ok(block) => {
                tracing::debug!(%block_hash, "Compact block fully reconstructed from mempool");
                let _ = self.block_tx.send(block);
            }
            Err(pending) => {
                if pending.missing_indices.is_empty() {
                    return; // Malformed
                }
                tracing::debug!(
                    %block_hash,
                    missing = pending.missing_indices.len(),
                    "Compact block incomplete, requesting missing txs"
                );
                let request = compact::make_get_block_txn(block_hash, &pending.missing_indices);
                self.send_to_peer(
                    id,
                    NetworkMessage::GetBlockTxn(
                        bitcoin::p2p::message_compact_blocks::GetBlockTxn {
                            txs_request: request,
                        },
                    ),
                );
                self.pending_compact.write().insert(block_hash, pending);
            }
        }
    }

    fn handle_get_block_txn(
        &self,
        id: PeerId,
        request: bitcoin::bip152::BlockTransactionsRequest,
    ) {
        if let Some(block) = self.chain_state.get_block(&request.block_hash) {
            match bitcoin::bip152::BlockTransactions::from_request(&request, &block) {
                Ok(txns) => {
                    self.send_to_peer(
                        id,
                        NetworkMessage::BlockTxn(
                            bitcoin::p2p::message_compact_blocks::BlockTxn {
                                transactions: txns,
                            },
                        ),
                    );
                }
                Err(e) => {
                    tracing::debug!(id, "GetBlockTxn request out of range: {}", e);
                }
            }
        }
    }

    fn handle_block_txn(&self, _id: PeerId, txns: bitcoin::bip152::BlockTransactions) {
        let block_hash = txns.block_hash;
        let pending = self.pending_compact.write().remove(&block_hash);
        if let Some(pending) = pending {
            if let Some(block) = compact::complete_pending(pending, &txns) {
                tracing::debug!(%block_hash, "Compact block completed with BlockTxn");
                let _ = self.block_tx.send(block);
            } else {
                tracing::debug!(%block_hash, "Failed to complete compact block");
            }
        }
    }

    fn request_missing_blocks(&self, id: PeerId) {
        let tip = self.chain_state.tip_height();
        let mut to_request = Vec::new();

        // Request blocks from tip+1 upward where we have headers but no block data
        for h in (tip + 1)..=(tip + 512) {
            if let Some(hash) = self.chain_state.get_block_hash_by_height(h) {
                if !self.chain_state.has_block_data(&hash) {
                    to_request.push(hash);
                    if to_request.len() >= 128 {
                        break;
                    }
                }
            } else {
                break;
            }
        }

        if !to_request.is_empty() {
            tracing::debug!(tip, count = to_request.len(), "Requesting blocks");
            self.send_to_peer(id, sync::make_getdata_blocks(&to_request));
        }
    }

    fn send_to_peer(&self, id: PeerId, msg: NetworkMessage) {
        let peers = self.peers.read();
        if let Some(handle) = peers.get(&id) {
            let _ = handle.msg_tx.try_send(msg);
        }
    }

    #[allow(dead_code)]
    fn broadcast(&self, msg: NetworkMessage) {
        self.broadcast_except(0, msg);
    }

    #[allow(dead_code)]
    fn broadcast_except(&self, exclude_id: PeerId, msg: NetworkMessage) {
        let peers = self.peers.read();
        for (id, handle) in peers.iter() {
            if *id != exclude_id && handle.info.state == PeerState::Connected {
                let _ = handle.msg_tx.try_send(msg.clone());
            }
        }
    }

    /// Spawn read/write tasks for a new peer connection.
    fn spawn_peer(
        self: &Arc<Self>,
        id: PeerId,
        addr: SocketAddr,
        stream: TcpStream,
        direction: Direction,
    ) {
        let (msg_tx, msg_rx) = mpsc::channel::<NetworkMessage>(256);
        let info = PeerInfo::new(id, addr, direction);
        let handle = PeerHandle { info, msg_tx };
        {
            let mut peers = self.peers.write();
            peers.insert(id, handle);
        }
        self.spawn_peer_task(id, addr, stream, direction, msg_rx);
    }

    /// Inner half of `spawn_peer`: spawns the peer task once the
    /// `PeerHandle` is already in `self.peers`. Split out so
    /// `accept_inbound` can do the cap-check + insertion atomically
    /// under one write lock and then call this without re-inserting.
    fn spawn_peer_task(
        self: &Arc<Self>,
        id: PeerId,
        addr: SocketAddr,
        stream: TcpStream,
        direction: Direction,
        msg_rx: mpsc::Receiver<NetworkMessage>,
    ) {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = manager.peer_task(id, stream, direction, msg_rx).await {
                tracing::warn!(id, %addr, "Peer task ended: {}", e);
            }
            let _ = manager.event_tx.send(NetEvent::PeerDisconnected { id }).await;
        });
    }

    /// The main task for a single peer.
    async fn peer_task(
        self: &Arc<Self>,
        id: PeerId,
        stream: TcpStream,
        direction: Direction,
        mut msg_rx: mpsc::Receiver<NetworkMessage>,
    ) -> Result<(), String> {
        let mut conn = Connection::new(stream, self.network);

        // Perform handshake with timeout
        let version = self.perform_handshake(id, &mut conn, direction).await?;

        // Notify manager
        let addr = conn.peer_addr().map_err(|e| e.to_string())?;
        self.event_tx
            .send(NetEvent::PeerConnected {
                id,
                addr,
                version,
            })
            .await
            .map_err(|e| e.to_string())?;

        // Split connection into read/write halves to avoid cancel-safety issues.
        // read_exact is not cancel-safe — if tokio::select! drops a recv() future
        // mid-read, consumed bytes are lost and the stream becomes misaligned.
        // By running the reader in a dedicated task, it is never cancelled.
        let (mut reader, mut writer) = conn.split();

        // Request headers to start sync
        let getheaders = sync::make_getheaders(&self.chain_state);
        writer.send(getheaders)
            .await
            .map_err(|e| e.to_string())?;

        // Negotiate compact block support (BIP 152, version 2 = with witness)
        writer.send(NetworkMessage::SendCmpct(
            bitcoin::p2p::message_compact_blocks::SendCmpct {
                send_compact: true,
                version: 2,
            },
        ))
        .await
        .map_err(|e| format!("send sendcmpct: {}", e))?;

        // Send our fee filter (BIP 133) so peer doesn't relay low-fee txs to us
        writer.send(NetworkMessage::FeeFilter(self.mempool.policy().min_fee_rate as i64))
            .await
            .map_err(|e| format!("send feefilter: {}", e))?;

        // Spawn a dedicated read task that forwards messages via a channel.
        // This task is never cancelled, so read_exact always completes.
        let (read_tx, mut read_rx) = mpsc::channel::<NetworkMessage>(64);
        let read_task = tokio::spawn(async move {
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(600),
                    reader.recv(),
                )
                .await
                {
                    Ok(Ok(msg)) => {
                        if read_tx.send(msg).await.is_err() {
                            break; // receiver dropped, peer_task ended
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("Read error: {}", e);
                        break;
                    }
                    Err(_) => {
                        tracing::debug!("Peer idle timeout");
                        break;
                    }
                }
            }
        });

        // Main loop: receive from reader task OR send outbound messages
        let result = Self::peer_write_loop(id, &self.event_tx, &mut writer, &mut msg_rx, &mut read_rx).await;

        read_task.abort();
        result
    }

    /// Write loop for a peer: forwards received messages to the manager
    /// and sends outbound messages. Separated for clarity.
    ///
    /// Termination contract:
    ///   - `read_rx` closing → reader task ended; exit with error so the
    ///     outer `peer_task` emits `NetEvent::PeerDisconnected`.
    ///   - `msg_rx` closing → manager dropped our `PeerHandle` (e.g. the
    ///     silent-peer drop path, or a deliberate `handle_peer_disconnected`
    ///     call). Exit too, so the TCP socket and reader task actually
    ///     terminate instead of leaving an untracked peer feeding events.
    ///     The earlier `Some(msg) = msg_rx.recv()` pattern silently
    ///     disabled the branch on close — review F2 (PRs #180-#184).
    async fn peer_write_loop(
        id: PeerId,
        event_tx: &mpsc::Sender<NetEvent>,
        writer: &mut ConnectionWriter,
        msg_rx: &mut mpsc::Receiver<NetworkMessage>,
        read_rx: &mut mpsc::Receiver<NetworkMessage>,
    ) -> Result<(), String> {
        loop {
            tokio::select! {
                msg = read_rx.recv() => {
                    match msg {
                        Some(msg) => {
                            event_tx
                                .send(NetEvent::MessageReceived { id, msg })
                                .await
                                .map_err(|e| e.to_string())?;
                        }
                        None => {
                            // Reader task ended (error or timeout)
                            return Err("connection closed".to_string());
                        }
                    }
                }
                msg = msg_rx.recv() => {
                    match msg {
                        Some(msg) => {
                            writer.send(msg).await.map_err(|e| e.to_string())?;
                        }
                        None => {
                            // Manager dropped our handle. Return so the
                            // outer task aborts the reader and closes
                            // the TCP socket; without this exit, the
                            // task would keep running on `read_rx` and
                            // emit `MessageReceived` events for a peer
                            // no longer in `self.peers`.
                            return Err("disconnected by manager".to_string());
                        }
                    }
                }
            }
        }
    }

    /// Receive a message with timeout.
    async fn recv_with_timeout(conn: &mut Connection, timeout: Duration) -> Result<NetworkMessage, String> {
        tokio::time::timeout(timeout, conn.recv())
            .await
            .map_err(|_| "handshake timeout".to_string())?
            .map_err(|e| format!("recv: {}", e))
    }

    /// Perform the version/verack handshake with timeouts.
    async fn perform_handshake(
        &self,
        _id: PeerId,
        conn: &mut Connection,
        direction: Direction,
    ) -> Result<VersionMessage, String> {
        let our_version = self.build_version_message(conn.peer_addr().map_err(|e| e.to_string())?);
        // Bitcoin Core's `-timeout` (default 5000ms), set from config at
        // startup; bounds each step of the version/verack exchange.
        let timeout = Duration::from_millis(self.connect_timeout_ms.load(Ordering::Relaxed));

        match direction {
            Direction::Outbound => {
                conn.send(NetworkMessage::Version(our_version))
                    .await
                    .map_err(|e| format!("send version: {}", e))?;

                // BIP 155: signal addrv2 support after Version, before Verack
                conn.send(NetworkMessage::SendAddrV2)
                    .await
                    .map_err(|e| format!("send sendaddrv2: {}", e))?;

                let their_version = loop {
                    let msg = Self::recv_with_timeout(conn, timeout).await?;
                    if let NetworkMessage::Version(v) = msg {
                        break v;
                    }
                };

                conn.send(NetworkMessage::Verack)
                    .await
                    .map_err(|e| format!("send verack: {}", e))?;

                loop {
                    let msg = Self::recv_with_timeout(conn, timeout).await?;
                    if matches!(msg, NetworkMessage::Verack) {
                        break;
                    }
                }

                conn.send(NetworkMessage::SendHeaders)
                    .await
                    .map_err(|e| format!("send sendheaders: {}", e))?;

                Ok(their_version)
            }
            Direction::Inbound => {
                let their_version = loop {
                    let msg = Self::recv_with_timeout(conn, timeout).await?;
                    if let NetworkMessage::Version(v) = msg {
                        break v;
                    }
                };

                conn.send(NetworkMessage::Version(our_version))
                    .await
                    .map_err(|e| format!("send version: {}", e))?;

                // BIP 155: signal addrv2 support after Version, before Verack
                conn.send(NetworkMessage::SendAddrV2)
                    .await
                    .map_err(|e| format!("send sendaddrv2: {}", e))?;

                conn.send(NetworkMessage::Verack)
                    .await
                    .map_err(|e| format!("send verack: {}", e))?;

                loop {
                    let msg = Self::recv_with_timeout(conn, timeout).await?;
                    if matches!(msg, NetworkMessage::Verack) {
                        break;
                    }
                }

                Ok(their_version)
            }
        }
    }

    fn build_version_message(&self, receiver: SocketAddr) -> VersionMessage {
        let mut services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        // BIP 157 NODE_COMPACT_FILTERS (bit 6) — advertised at version
        // time when the runtime predicate is true. Re-evaluated per
        // outgoing handshake so a node that finishes a backfill or
        // toggles `peerblockfilters` mid-run picks up the change for
        // new connections without a restart.
        #[cfg(feature = "block-filter-index")]
        if self.peer_serve_filters_ready() {
            services |= ServiceFlags::COMPACT_FILTERS;
        }
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let sender = SocketAddr::from(([0, 0, 0, 0], 0));

        VersionMessage {
            version: 70016,
            services,
            timestamp,
            receiver: Address::new(&receiver, ServiceFlags::NONE),
            sender: Address::new(&sender, services),
            nonce: rand::random(),
            user_agent: crate::USER_AGENT.to_string(),
            start_height: self.chain_state.tip_height() as i32,
            relay: true,
        }
    }
}

/// Reconsider orphans whose missing parent was just confirmed in `block`.
///
/// Standalone so the `block_processor` thread — which doesn't have a
/// `PeerManager` handle — can invoke it after `remove_for_block`.
/// No peer relay: orphans admitted here are in our local mempool; peers
/// will re-announce on their own schedule.
pub fn reconsider_orphans_on_block(
    orphanage: &Arc<TxOrphanage>,
    mempool: &Arc<Mempool>,
    chain_state: &Arc<ChainState>,
    block: &bitcoin::Block,
) {
    use std::collections::VecDeque;
    let mut queue: VecDeque<bitcoin::Txid> = VecDeque::new();
    for tx in &block.txdata {
        let confirmed_txid = tx.compute_txid();
        // Drop any orphan that is itself the confirmed tx.
        let _ = orphanage.remove(&confirmed_txid);
        for child in orphanage.children_of(&confirmed_txid) {
            queue.push_back(child);
        }
    }
    while let Some(child_txid) = queue.pop_front() {
        let Some(child) = orphanage.remove(&child_txid) else {
            continue;
        };
        let result = mempool.accept_transaction(
            child.tx.clone(),
            chain_state,
            chain_state.script_verifier(),
        );
        match result {
            Ok(_) => {
                for grandchild in orphanage.children_of(&child_txid) {
                    queue.push_back(grandchild);
                }
            }
            Err(MempoolError::MissingInputs) => {
                // Other parents still unresolved — re-orphan with updated
                // set. If the set is empty (race), `add` returns
                // NoMissingParents and we drop silently rather than
                // stranding an unreachable orphan.
                let mut missing = std::collections::HashSet::new();
                for input in &child.tx.input {
                    let parent = input.previous_output.txid;
                    if chain_state.get_coin(&input.previous_output).is_some() {
                        continue;
                    }
                    if mempool.get(&parent).is_some() {
                        continue;
                    }
                    missing.insert(parent);
                }
                let _ = orphanage.add(child.tx, child.from_peer, missing);
            }
            Err(e) => {
                tracing::debug!(%child_txid, "Orphan dropped on block-connect re-eval: {}", e);
            }
        }
    }
}

/// RAII guard that scopes `WriteMode::BulkLoad` to a lexical region.
///
/// Constructor sets BulkLoad. `Drop` attempts a best-effort
/// `flush_durable` and then unconditionally restores `Normal`, so WAL-
/// disabled write behavior cannot leak past IBD even if the IBD loop
/// exits via a non-success path or panics.
///
/// Callers on the clean-success IBD-complete path should still invoke
/// `flush_durable` explicitly and fail-closed if it errors — a silent
/// "IBD complete" with a failed checkpoint must not be allowed. The
/// guard's `Drop` is a backstop, not the primary durability contract.
struct BulkLoadGuard<'a> {
    chain_state: &'a ChainState,
}

impl<'a> BulkLoadGuard<'a> {
    fn new(chain_state: &'a ChainState) -> Self {
        chain_state.set_write_mode(crate::storage::WriteMode::BulkLoad);
        Self { chain_state }
    }
}

impl Drop for BulkLoadGuard<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.chain_state.flush_durable() {
            tracing::error!(
                error = %e,
                "BulkLoadGuard: durable flush failed on IBD exit. \
                 Restoring Normal write mode anyway; next startup will \
                 replay any lost BulkLoad writes from the flat-file block \
                 store (DataStored -> Valid replay path)."
            );
        }
        self.chain_state.set_write_mode(crate::storage::WriteMode::Normal);
        tracing::info!("BulkLoadGuard: restored Normal write mode");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::peer::{Direction, PeerInfo, PeerState};

    fn mk_handle(id: PeerId, addr: SocketAddr, dir: Direction, state: PeerState) -> PeerHandle {
        let mut info = PeerInfo::new(id, addr, dir);
        info.state = state;
        // 1-slot channel; we never send on the test side.
        let (tx, _rx) = mpsc::channel::<NetworkMessage>(1);
        PeerHandle { info, msg_tx: tx }
    }

    #[test]
    fn count_inbound_classifies_by_direction_and_state() {
        let mut peers = HashMap::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // Inbound + Connected: counts.
        peers.insert(
            1,
            mk_handle(1, SocketAddr::new(ip, 8333), Direction::Inbound, PeerState::Connected),
        );
        // Outbound + Connected: not counted as inbound.
        peers.insert(
            2,
            mk_handle(2, SocketAddr::new(ip, 8333), Direction::Outbound, PeerState::Connected),
        );
        // Inbound + Connecting (handshake in progress): F4 fix — must
        // count toward the cap, otherwise concurrent handshake bursts
        // from one IP bypass the limit until handshakes complete.
        peers.insert(
            3,
            mk_handle(3, SocketAddr::new(ip, 8333), Direction::Inbound, PeerState::Connecting),
        );
        // Inbound + Disconnected: stale entry, no real socket, doesn't
        // count.
        peers.insert(
            4,
            mk_handle(4, SocketAddr::new(ip, 8333), Direction::Inbound, PeerState::Disconnected),
        );
        let (total, same_ip) = PeerManager::count_inbound(&peers, ip);
        assert_eq!(total, 2);
        assert_eq!(same_ip, 2);
    }

    #[test]
    fn count_inbound_caps_against_handshake_burst() {
        // Regression for review F4: a burst of inbound TCP accepts from
        // a single IP must not all squeeze through the per-IP cap
        // while still in handshake. With the old semantics
        // (Connected-only), the entire burst could insert as
        // Connecting and each accept would observe same_ip_count == 0.
        let mut peers = HashMap::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // Simulate four concurrent accepts from the same IP that all
        // landed in Connecting before any handshake completed.
        for id in 1..=4u32 {
            peers.insert(
                id as PeerId,
                mk_handle(
                    id as PeerId,
                    SocketAddr::new(ip, 8333 + id as u16),
                    Direction::Inbound,
                    PeerState::Connecting,
                ),
            );
        }
        let (total, same_ip) = PeerManager::count_inbound(&peers, ip);
        assert_eq!(total, 4, "handshake-in-progress peers must consume slots");
        assert_eq!(same_ip, 4);
    }

    #[test]
    fn count_inbound_groups_by_ip() {
        let mut peers = HashMap::new();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
        for (id, ip) in [(1, ip_a), (2, ip_a), (3, ip_a), (4, ip_b)] {
            peers.insert(
                id,
                mk_handle(
                    id,
                    SocketAddr::new(ip, 8333 + id as u16),
                    Direction::Inbound,
                    PeerState::Connected,
                ),
            );
        }
        let (total_a, same_a) = PeerManager::count_inbound(&peers, ip_a);
        assert_eq!(total_a, 4);
        assert_eq!(same_a, 3);
        let (total_b, same_b) = PeerManager::count_inbound(&peers, ip_b);
        assert_eq!(total_b, 4);
        assert_eq!(same_b, 1);
    }

    #[test]
    fn pending_connections_guard_releases_on_drop() {
        // Mirrors the RAII pattern inside `connect_outbound`. The guard
        // exists to ensure the pending slot is released even when the
        // dial fails or panics across an await point.
        let set: RwLock<HashSet<SocketAddr>> = RwLock::new(HashSet::new());
        let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();

        struct PendingGuard<'a> {
            set: &'a RwLock<HashSet<SocketAddr>>,
            addr: SocketAddr,
        }
        impl<'a> Drop for PendingGuard<'a> {
            fn drop(&mut self) {
                self.set.write().remove(&self.addr);
            }
        }

        {
            set.write().insert(addr);
            assert!(set.read().contains(&addr));
            let _g = PendingGuard { set: &set, addr };
            // ... pretend a dial happens here ...
        }
        assert!(!set.read().contains(&addr), "guard should release slot on drop");
    }

    #[test]
    fn add_connect_addr_dedups() {
        // Pure-Vec test of the dedup idiom used inside add_connect_addr.
        let mut addrs: Vec<SocketAddr> = Vec::new();
        let a: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let b: SocketAddr = "1.2.3.5:8333".parse().unwrap();
        for _ in 0..5 {
            if !addrs.contains(&a) {
                addrs.push(a);
            }
        }
        for _ in 0..3 {
            if !addrs.contains(&b) {
                addrs.push(b);
            }
        }
        assert_eq!(addrs, vec![a, b]);
    }
}
