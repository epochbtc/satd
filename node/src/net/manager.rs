use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};
use bitcoin::Network;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, RwLock};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use base64::Engine;

use crate::chain::state::ChainState;
use crate::mempool::fee::FeeEstimator;
use crate::mempool::pool::Mempool;
use crate::net::compact;
use crate::net::connection::{Connection, ConnectionWriter};
use crate::net::ibd::IbdScheduler;
use crate::net::peer::{Direction, PeerAddr, PeerId, PeerInfo, PeerState};
use crate::net::proxy;
use crate::net::sync;

const MAX_OUTBOUND: usize = 8;
const MAX_OUTBOUND_IBD: usize = 64;
const BAN_THRESHOLD: u32 = 100;

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
    /// Ban duration in seconds (default: 86400).
    ban_duration_secs: u64,
    /// IBD scheduler for parallel block download (shared with connect thread).
    ibd: Arc<std::sync::RwLock<Option<IbdScheduler>>>,
    /// Signal to wake the connect thread when a block is stored.
    connect_signal: Arc<(std::sync::Mutex<bool>, Condvar)>,
    /// SOCKS5 proxy for all outbound connections (e.g. "127.0.0.1:9050").
    proxy: Option<String>,
    /// Separate SOCKS5 proxy for .onion connections (defaults to proxy).
    onion_proxy: Option<String>,
    /// Configured outbound .onion and hostname-based peer addresses for auto-reconnect.
    connect_peer_addrs: RwLock<Vec<PeerAddr>>,
    /// Max blocks downloaded ahead of connect cursor during IBD.
    max_ahead: u32,
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
        Self::with_config(chain_state, mempool, fee_estimator, network, shutdown, 0, 125, 86400, None, None, workers, 50_000)
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
        Self::with_config(chain_state, mempool, fee_estimator, network, shutdown, prune_target_mb, 125, 86400, None, None, workers, 50_000)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub fn with_config(
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
        fee_estimator: Arc<FeeEstimator>,
        network: Network,
        shutdown: tokio::sync::watch::Receiver<bool>,
        prune_target_mb: u64,
        max_connections: usize,
        ban_duration_secs: u64,
        proxy: Option<String>,
        onion_proxy: Option<String>,
        prefetch_workers: usize,
        max_ahead: u32,
    ) -> Arc<Self> {
        let (event_tx, event_rx) = mpsc::channel(4096);
        let (block_tx, block_rx) = mpsc::unbounded_channel();
        let connect_signal = Arc::new((std::sync::Mutex::new(false), Condvar::new()));

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
        let ibd = Arc::new(std::sync::RwLock::new(ibd_scheduler));

        let mgr = Arc::new(Self {
            peers: RwLock::new(HashMap::new()),
            chain_state: chain_state.clone(),
            mempool: mempool.clone(),
            network,
            next_id: AtomicU64::new(1),
            event_tx,
            event_rx: tokio::sync::Mutex::new(event_rx),
            headers_tip: AtomicU64::new(0),
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
            ban_duration_secs,
            ibd: ibd.clone(),
            connect_signal: connect_signal.clone(),
            proxy,
            onion_proxy,
            connect_peer_addrs: RwLock::new(Vec::new()),
            max_ahead,
        });

        // Spawn block processing thread
        let cs = chain_state;
        let mp = mempool;
        let fe = fee_estimator;
        let prune_mb = prune_target_mb;
        std::thread::spawn(move || {
            Self::block_processor(block_rx, cs, mp, fe, prune_mb, connect_signal, ibd, prefetch_workers, max_ahead);
        });

        mgr
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

    /// Register addresses for auto-reconnect.
    pub fn add_connect_addr(&self, addr: SocketAddr) {
        self.connect_addrs.write().unwrap().push(addr);
    }

    /// Register a PeerAddr (socket or .onion) for auto-reconnect.
    pub fn add_peer_addr(&self, addr: PeerAddr) {
        match &addr {
            PeerAddr::Socket(sa) => self.connect_addrs.write().unwrap().push(*sa),
            PeerAddr::Onion { .. } => self.connect_peer_addrs.write().unwrap().push(addr),
        }
    }

    /// Get the number of connected outbound peers.
    pub fn outbound_count(&self) -> usize {
        let peers = self.peers.read().unwrap();
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
    pub fn accept_inbound(self: &Arc<Self>, stream: TcpStream, addr: SocketAddr) {
        {
            let peers = self.peers.read().unwrap();
            let inbound_count = peers
                .values()
                .filter(|h| {
                    h.info.direction == Direction::Inbound
                        && h.info.state == PeerState::Connected
                })
                .count();
            if inbound_count >= self.max_connections.saturating_sub(MAX_OUTBOUND) {
                tracing::warn!(%addr, "Max inbound connections reached, dropping connection");
                return;
            }
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        tracing::info!(%addr, id, "Accepted inbound peer");
        self.spawn_peer(id, addr, stream, Direction::Inbound);
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
        let peers = self.peers.read().unwrap();
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
        let peers = self.peers.read().unwrap();
        peers
            .values()
            .filter(|h| h.info.state == PeerState::Connected)
            .map(|h| h.info.to_rpc_json())
            .collect()
    }

    /// Get connection count.
    pub fn connection_count(&self) -> usize {
        let peers = self.peers.read().unwrap();
        peers
            .values()
            .filter(|h| h.info.state == PeerState::Connected)
            .count()
    }

    /// Get IBD download progress for the TUI dashboard.
    pub fn get_ibd_progress(&self) -> Option<serde_json::Value> {
        let ibd = self.ibd.read().unwrap();
        let scheduler = ibd.as_ref()?;
        let (downloaded, in_flight, pending, target) = scheduler.progress();
        let cursor = scheduler.connect_cursor();
        let (bitmap, bitmap_sampled) = scheduler.block_bitmap();
        let peer_stats = scheduler.peer_stats();

        let bitmap_b64 = base64::engine::general_purpose::STANDARD.encode(&bitmap);

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
            "peer_download_stats": peer_stats.iter().map(|(id, recv, assigned)| {
                serde_json::json!({"peer_id": id, "blocks_received": recv, "assigned": assigned})
            }).collect::<Vec<_>>(),
        }))
    }

    /// Get the list of currently banned addresses with expiry times.
    pub fn list_banned(&self) -> Vec<serde_json::Value> {
        let banned = self.banned_addrs.read().unwrap();
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
                .unwrap()
                .insert(addr, Instant::now() + Duration::from_secs(self.ban_duration_secs));
        } else {
            self.banned_addrs.write().unwrap().remove(&addr);
        }
    }

    /// Clear all bans.
    pub fn clear_banned(&self) {
        self.banned_addrs.write().unwrap().clear();
    }

    /// Send a ping to all connected peers.
    pub fn ping_all(&self) {
        let peers = self.peers.read().unwrap();
        for (_, handle) in peers.iter() {
            if handle.info.state == PeerState::Connected {
                let _ = handle.msg_tx.try_send(NetworkMessage::Ping(rand::random()));
            }
        }
    }

    /// Get the list of configured connect addresses.
    pub fn get_added_node_info(&self) -> Vec<serde_json::Value> {
        let addrs = self.connect_addrs.read().unwrap();
        let peers = self.peers.read().unwrap();
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
        let peers = self.peers.read().unwrap();
        peers
            .values()
            .any(|h| h.info.addr == *addr && h.info.state != PeerState::Disconnected)
    }

    /// Check if an address is currently banned.
    fn is_addr_banned(&self, addr: &SocketAddr) -> bool {
        let banned = self.banned_addrs.read().unwrap();
        matches!(banned.get(addr), Some(expiry) if Instant::now() < *expiry)
    }

    /// Add ban score to a peer. If the score exceeds BAN_THRESHOLD, the peer
    /// is disconnected, removed, and its address is banned.
    fn add_ban_score(&self, id: PeerId, score: u32, reason: &str) {
        let mut peers = self.peers.write().unwrap();
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
                    .unwrap()
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
            // Check for shutdown
            if *shutdown.borrow() {
                tracing::info!("P2P manager shutting down");
                // Drop all peers to close connections
                self.peers.write().unwrap().clear();
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
                let mut backoff = self.reconnect_backoff.write().unwrap();
                for state in backoff.values_mut() {
                    state.reset();
                }
            }

            // IBD scheduler maintenance
            let has_ibd = self.ibd.read().unwrap().is_some();
            if has_ibd {
                // Every 4 ticks (2s): stall detection and reassignment
                if ticks.is_multiple_of(4) {
                    let stalled = {
                        let mut ibd = self.ibd.write().unwrap();
                        if let Some(scheduler) = ibd.as_mut() {
                            scheduler.detect_stalls(Duration::from_secs(60))
                        } else {
                            Vec::new()
                        }
                    };
                    for peer_id in stalled {
                        tracing::debug!(peer_id, "IBD: peer stalled, reassigning blocks");
                    }
                    // Assign work to any idle peers
                    self.assign_all_peers();
                }

                // Every 20 ticks (10s): progress logging
                if ticks.is_multiple_of(20) {
                    let (dl, inf, pend, target) = {
                        let ibd = self.ibd.read().unwrap();
                        ibd.as_ref()
                            .map(|s| s.progress())
                            .unwrap_or((0, 0, 0, 0))
                    };
                    let peers_active = self.connection_count();
                    tracing::info!(
                        "IBD download: {}/{} stored, {} in-flight, {} pending, {} peers",
                        dl + (target as usize - dl - inf - pend),
                        target,
                        inf,
                        pend,
                        peers_active
                    );
                }
            }

            // Request blocks: immediately on tip advance, or every 10 ticks as fallback
            // Skip during IBD swarming — the scheduler handles block requests
            if !has_ibd && (tip_advanced || ticks.is_multiple_of(10)) {
                let peer_ids: Vec<PeerId> = {
                    let peers = self.peers.read().unwrap();
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
                    let peers = self.peers.read().unwrap();
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
                    let peers = self.peers.read().unwrap();
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
            if ticks.is_multiple_of(60) {
                self.mempool.remove_expired();
            }

            // Every 20 ticks (10 seconds), reconnect if below outbound target
            if ticks.is_multiple_of(20) {
                let outbound = self.outbound_count();
                let target = if self.is_ibd() { MAX_OUTBOUND_IBD } else { MAX_OUTBOUND };
                let need_peers = outbound < target;
                if need_peers {
                    let addrs = self.connect_addrs.read().unwrap().clone();
                    let now = Instant::now();

                    // Clean expired bans
                    {
                        let mut banned = self.banned_addrs.write().unwrap();
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
                            let backoff = self.reconnect_backoff.read().unwrap();
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
                                    let mut backoff = pm.reconnect_backoff.write().unwrap();
                                    backoff
                                        .entry(addr)
                                        .or_insert_with(ReconnectState::new)
                                        .reset();
                                }
                                Err(e) => {
                                    tracing::debug!(%addr, "Reconnect failed: {}", e);
                                    let mut backoff = pm.reconnect_backoff.write().unwrap();
                                    backoff
                                        .entry(addr)
                                        .or_insert_with(ReconnectState::new)
                                        .record_failure();
                                }
                            }
                        });
                    }

                    // Also reconnect .onion peers
                    let onion_addrs = self.connect_peer_addrs.read().unwrap().clone();
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
            let mut peers = self.peers.write().unwrap();
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
        let has_ibd = self.ibd.read().unwrap().is_some();
        if has_ibd {
            self.assign_peer_work(id);
        }
    }

    fn handle_peer_disconnected(&self, id: PeerId) {
        let mut peers = self.peers.write().unwrap();
        if let Some(handle) = peers.remove(&id) {
            tracing::info!(id, addr = %handle.info.addr, "Peer disconnected");
        }
        drop(peers);
        // Notify IBD scheduler so in-flight blocks get reassigned
        let mut ibd = self.ibd.write().unwrap();
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
                let mut peers = self.peers.write().unwrap();
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
                let mut peers = self.peers.write().unwrap();
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
                let peers = self.peers.read().unwrap();
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
                let mut peers = self.peers.write().unwrap();
                if let Some(handle) = peers.get_mut(&id) {
                    handle.info.wants_addrv2 = true;
                    tracing::debug!(id, "Peer supports addrv2");
                }
            }
            NetworkMessage::NotFound(inventory) => {
                tracing::debug!(id, count = inventory.len(), "Peer sent notfound");
            }
            NetworkMessage::SendHeaders => {
                tracing::debug!(id, "Peer prefers headers announcements");
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
                    let peers = self.peers.read().unwrap();
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

            // Start or extend IBD scheduler as soon as headers are far enough
            // ahead of the block tip. Don't wait for header download to finish —
            // pipeline block downloads alongside header sync.
            let tip = self.chain_state.tip_height();
            let headers_tip = htip as u32;
            if headers_tip > tip + 24 {
                let mut ibd = self.ibd.write().unwrap();
                if ibd.is_none() {
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
                    *lock.lock().unwrap() = true;
                    cvar.notify_one();
                    // Assign work to all connected peers
                    self.assign_all_peers();
                } else if let Some(scheduler) = ibd.as_mut() {
                    // Headers advanced — extend the scheduler target so it
                    // keeps downloading without waiting for the current batch
                    // to fully complete first.
                    if headers_tip > scheduler.target_height() {
                        scheduler.extend_target(headers_tip, &self.chain_state);
                        drop(ibd);
                        // Assign more work now that we have more blocks to fetch
                        self.assign_all_peers();
                    }
                }
            }

            // Request blocks (legacy path for non-IBD or fallback)
            let has_ibd = self.ibd.read().unwrap().is_some();
            if !has_ibd {
                self.request_missing_blocks(id);
            }
        }
    }

    /// Assign download work to all connected peers during IBD.
    fn assign_all_peers(&self) {
        let peer_ids: Vec<PeerId> = {
            let peers = self.peers.read().unwrap();
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
    fn assign_peer_work(&self, peer_id: PeerId) {
        let mut ibd = self.ibd.write().unwrap();
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
        let has_ibd = self.ibd.read().unwrap().is_some();
        if has_ibd {
            let hash = block.block_hash();
            match self.chain_state.store_block(&block) {
                Ok((_, height)) => {
                    let needs_more = {
                        let mut ibd = self.ibd.write().unwrap();
                        if let Some(scheduler) = ibd.as_mut() {
                            scheduler.block_received(id, height)
                        } else {
                            false
                        }
                    };
                    // Wake connect thread
                    let (lock, cvar) = &*self.connect_signal;
                    *lock.lock().unwrap() = true;
                    cvar.notify_one();
                    // Assign more work if peer has capacity
                    if needs_more {
                        self.assign_peer_work(id);
                    }
                }
                Err(crate::chain::state::ChainError::Duplicate) => {
                    // Already have it, mark in scheduler anyway
                    if let Some(entry) = self.chain_state.get_block_index(&hash) {
                        let mut ibd = self.ibd.write().unwrap();
                        if let Some(scheduler) = ibd.as_mut() {
                            scheduler.block_received(id, entry.height);
                        }
                    }
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
    fn block_processor(
        mut rx: mpsc::UnboundedReceiver<bitcoin::Block>,
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
        fee_estimator: Arc<FeeEstimator>,
        prune_target_mb: u64,
        connect_signal: Arc<(std::sync::Mutex<bool>, Condvar)>,
        ibd: Arc<std::sync::RwLock<Option<IbdScheduler>>>,
        prefetch_workers: usize,
        max_ahead: u32,
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
        if ibd.read().unwrap().is_some() {
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
            );
        }

        // Normal mode: process blocks from the channel.
        // Periodically check if the IBD scheduler was activated (header download completed
        // while we were in normal mode), and switch to the IBD connect loop if so.
        let mut block_buffer: HashMap<bitcoin::BlockHash, bitcoin::Block> = HashMap::new();
        loop {
            // Check if IBD scheduler was activated
            if ibd.read().unwrap().is_some() {
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
                );
                continue;
            }

            // Wait for a block from the channel, but wake up periodically
            // to check for IBD scheduler activation
            let (lock, cvar) = &*connect_signal;
            let mut ready = lock.lock().unwrap();
            *ready = false;
            // Wait up to 500ms — will be woken immediately if a block is stored
            let _ = cvar.wait_timeout(ready, Duration::from_millis(500));

            // Drain all available blocks from the channel
            while let Ok(block) = rx.try_recv() {
                let hash = block.block_hash();
                match chain_state.accept_block(&block) {
                    Ok(_) => {
                        Self::record_block_fees(&block, &chain_state, &fee_estimator);
                        mempool.remove_for_block(&block);
                        // Drain buffer
                        loop {
                            let tip = chain_state.tip_hash();
                            match block_buffer.remove(&tip) {
                                Some(b) => {
                                    match chain_state.accept_block(&b) {
                                        Ok(_) => {
                                            Self::record_block_fees(&b, &chain_state, &fee_estimator);
                                            mempool.remove_for_block(&b);
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
    #[allow(clippy::too_many_arguments)]
    fn ibd_connect_loop(
        chain_state: &ChainState,
        _fee_estimator: &FeeEstimator,
        connect_signal: &Arc<(std::sync::Mutex<bool>, Condvar)>,
        ibd: &Arc<std::sync::RwLock<Option<IbdScheduler>>>,
        keep_blocks: u32,
        prefetch_workers: usize,
        last_log_height: &mut u32,
        last_prune_height: &mut u32,
        max_ahead: u32,
    ) {
        let mut connected_count = 0u64;
        let start_time = Instant::now();

        // Start the prefetch pipeline
        let store: Arc<dyn crate::storage::Store + Send + Sync> =
            chain_state.store_ref().clone();
        let (prefetch_rx, prefetch_handle) = crate::chain::prefetch::start_prefetcher(
            store,
            chain_state.blocks_dir().to_path_buf(),
            chain_state.tip_height() + 1,
            prefetch_workers,
            32, // lookahead blocks
        );

        loop {
            let target_height = {
                let sched = ibd.read().unwrap();
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
                    *ibd.write().unwrap() = Some(new_sched);
                    connected_count = 0;
                    // Update prefetch cursor for the new batch
                    prefetch_handle.advance_cursor(tip_height + 1);
                    // The run() loop will detect has_ibd=true within 2s and assign peers
                    continue;
                }
                // Truly done — flush UTXO cache before exiting IBD
                if let Err(e) = chain_state.flush_coin_cache() {
                    tracing::error!("Failed to flush UTXO cache at IBD completion: {}", e);
                }
                tracing::info!(
                    height = tip_height,
                    blocks = connected_count,
                    elapsed_secs = start_time.elapsed().as_secs(),
                    "IBD complete"
                );
                *ibd.write().unwrap() = None;
                break;
            }

            let hash = match chain_state.get_block_hash_by_height(next_height) {
                Some(h) => h,
                None => {
                    // No header for this height yet — wait
                    let (lock, cvar) = &**connect_signal;
                    let mut ready = lock.lock().unwrap();
                    *ready = false;
                    let _ = cvar.wait_timeout(ready, Duration::from_secs(1));
                    continue;
                }
            };

            if chain_state.has_block_data(&hash) {
                // Try to get a pre-processed block from the prefetcher
                let connect_result = match prefetch_rx.try_recv() {
                    Ok(pre) if pre.height == next_height && pre.hash == hash => {
                        chain_state.connect_preprocessed_block(pre)
                    }
                    _ => {
                        // Prefetcher not ready or wrong block — fall back to normal path
                        chain_state.connect_stored_block(&hash)
                    }
                };

                match connect_result {
                    Ok(_) => {
                        connected_count += 1;
                        // Update scheduler connect cursor
                        {
                            let mut sched = ibd.write().unwrap();
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
                        if chain_state.cache_dirty_count() > chain_state.flush_threshold()
                            && let Err(e) = chain_state.flush_coin_cache() {
                                tracing::error!("Failed to flush cache: {}", e);
                        }

                        // Log progress
                        if next_height / 1000 > *last_log_height / 1000 {
                            let elapsed = start_time.elapsed().as_secs().max(1);
                            let rate = connected_count / elapsed;
                            let (dl, inf, pend, _) = {
                                let sched = ibd.read().unwrap();
                                sched.as_ref()
                                    .map(|s| s.progress())
                                    .unwrap_or((0, 0, 0, 0))
                            };
                            tracing::info!(
                                height = next_height,
                                "IBD: {}/{} connected, {} downloaded ahead, {} in-flight, {} pending ({} blk/s)",
                                next_height,
                                target_height,
                                dl,
                                inf,
                                pend,
                                rate
                            );
                            *last_log_height = next_height;

                            // Flush UTXO cache to disk every 1000 blocks
                            if let Err(e) = chain_state.flush_coin_cache() {
                                tracing::error!("Failed to flush UTXO cache: {}", e);
                            }
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
                        tracing::warn!(height = next_height, %hash, "Connect stored block failed: {}", e);
                        // Wait and retry — might be a transient issue
                        let (lock, cvar) = &**connect_signal;
                        let mut ready = lock.lock().unwrap();
                        *ready = false;
                        let _ = cvar.wait_timeout(ready, Duration::from_secs(1));
                        continue;
                    }
                }
            } else {
                // Next block not downloaded yet — wait for signal
                let (lock, cvar) = &**connect_signal;
                let mut ready = lock.lock().unwrap();
                *ready = false;
                let _ = cvar.wait_timeout(ready, Duration::from_secs(1));
            }
        }

        // Stop the prefetch pipeline
        prefetch_handle.stop();
    }

    /// Extract fee rates from a connected block and feed them to the fee estimator.
    fn record_block_fees(
        block: &bitcoin::Block,
        chain_state: &ChainState,
        fee_estimator: &FeeEstimator,
    ) {
        let mut fee_rates = Vec::new();
        for tx in &block.txdata {
            if tx.is_coinbase() {
                continue;
            }
            let weight = tx.weight().to_wu();
            if weight == 0 {
                continue;
            }
            // Compute fee from inputs - outputs
            let mut sum_inputs: u64 = 0;
            let mut inputs_found = true;
            for input in &tx.input {
                match chain_state.get_coin(&input.previous_output) {
                    Some(coin) => sum_inputs += coin.amount,
                    None => {
                        // Coin already spent (removed during connect_block) — skip this tx
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
        fee_estimator.record_block(&fee_rates);
    }

    fn handle_tx(&self, id: PeerId, tx: bitcoin::Transaction) {
        // During IBD, ignore relayed transactions — our UTXO set is incomplete
        // so validation would produce false MissingInputs rejections.
        if self.is_ibd() {
            return;
        }

        let txid = tx.compute_txid();
        let fee_rate = {
            let weight = tx.weight().to_wu();
            if weight > 0 {
                // We'll get the actual fee rate from the mempool entry after acceptance
                0u64 // placeholder, updated below
            } else {
                0
            }
        };
        match self.mempool.accept_transaction(
            tx,
            &self.chain_state,
            self.chain_state.script_verifier(),
        ) {
            Ok(_) => {
                // Get the actual fee rate from the accepted entry
                let entry_fee_rate = self.mempool.get(&txid)
                    .map(|e| e.fee_rate)
                    .unwrap_or(fee_rate);
                // Relay to peers whose fee filter allows this tx
                let inv = NetworkMessage::Inv(vec![Inventory::WitnessTransaction(txid)]);
                let peers = self.peers.read().unwrap();
                for (peer_id, handle) in peers.iter() {
                    if *peer_id != id
                        && handle.info.state == PeerState::Connected
                        && entry_fee_rate >= handle.info.fee_filter
                    {
                        let _ = handle.msg_tx.try_send(inv.clone());
                    }
                }
            }
            Err(e) => {
                tracing::debug!(%txid, "Tx rejected: {}", e);
                self.add_ban_score(id, 1, &format!("Tx rejected: {}", e));
            }
        }
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

        if !headers.is_empty() {
            self.send_to_peer(id, NetworkMessage::Headers(headers));
        }
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
                self.pending_compact.write().unwrap().insert(block_hash, pending);
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
        let pending = self.pending_compact.write().unwrap().remove(&block_hash);
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
        let peers = self.peers.read().unwrap();
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
        let peers = self.peers.read().unwrap();
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
            let mut peers = self.peers.write().unwrap();
            peers.insert(id, handle);
        }

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
                Some(msg) = msg_rx.recv() => {
                    writer.send(msg).await.map_err(|e| e.to_string())?;
                }
            }
        }
    }

    /// Receive a message with timeout.
    async fn recv_with_timeout(conn: &mut Connection, secs: u64) -> Result<NetworkMessage, String> {
        tokio::time::timeout(std::time::Duration::from_secs(secs), conn.recv())
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
        let timeout_secs = 10;

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
                    let msg = Self::recv_with_timeout(conn, timeout_secs).await?;
                    if let NetworkMessage::Version(v) = msg {
                        break v;
                    }
                };

                conn.send(NetworkMessage::Verack)
                    .await
                    .map_err(|e| format!("send verack: {}", e))?;

                loop {
                    let msg = Self::recv_with_timeout(conn, timeout_secs).await?;
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
                    let msg = Self::recv_with_timeout(conn, timeout_secs).await?;
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
                    let msg = Self::recv_with_timeout(conn, timeout_secs).await?;
                    if matches!(msg, NetworkMessage::Verack) {
                        break;
                    }
                }

                Ok(their_version)
            }
        }
    }

    fn build_version_message(&self, receiver: SocketAddr) -> VersionMessage {
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
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
