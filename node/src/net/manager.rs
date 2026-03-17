use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};
use bitcoin::Network;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::net::connection::Connection;
use crate::net::peer::{Direction, PeerId, PeerInfo, PeerState};
use crate::net::sync;

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
    /// Track blocks we've already requested to avoid duplicate getdata.
    requested_blocks: RwLock<std::collections::HashSet<bitcoin::BlockHash>>,
    /// Configured outbound peer addresses for auto-reconnect.
    connect_addrs: RwLock<Vec<SocketAddr>>,
    /// Channel to send received blocks to the processing thread.
    block_tx: mpsc::UnboundedSender<bitcoin::Block>,
}

impl PeerManager {
    pub fn new(
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
        network: Network,
    ) -> Arc<Self> {
        let (event_tx, event_rx) = mpsc::channel(4096);
        let (block_tx, block_rx) = mpsc::unbounded_channel();

        let mgr = Arc::new(Self {
            peers: RwLock::new(HashMap::new()),
            chain_state: chain_state.clone(),
            mempool: mempool.clone(),
            network,
            next_id: AtomicU64::new(1),
            event_tx,
            event_rx: tokio::sync::Mutex::new(event_rx),
            headers_tip: AtomicU64::new(0),
            requested_blocks: RwLock::new(std::collections::HashSet::new()),
            connect_addrs: RwLock::new(Vec::new()),
            block_tx,
        });

        // Spawn block processing thread
        let cs = chain_state;
        let mp = mempool;
        std::thread::spawn(move || {
            Self::block_processor(block_rx, cs, mp);
        });

        mgr
    }

    /// Register addresses for auto-reconnect.
    pub fn add_connect_addr(&self, addr: SocketAddr) {
        self.connect_addrs.write().unwrap().push(addr);
    }

    /// Connect to an outbound peer.
    pub async fn connect_outbound(self: &Arc<Self>, addr: SocketAddr) -> Result<(), String> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect failed: {}", e))?;

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        tracing::info!(%addr, id, "Connecting to peer");

        self.spawn_peer(id, addr, stream, Direction::Outbound);
        Ok(())
    }

    /// Accept an inbound connection.
    pub fn accept_inbound(self: &Arc<Self>, stream: TcpStream, addr: SocketAddr) {
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

    /// Run the main event loop.
    pub async fn run(self: &Arc<Self>) {
        let mut event_rx = self.event_rx.lock().await;
        let mut sync_interval = tokio::time::interval(std::time::Duration::from_millis(500));
        let mut last_tip: u32 = 0;
        let mut ticks: u64 = 0;

        loop {
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
            let htip = self.headers_tip.load(Ordering::Relaxed) as u32;

            if tip != last_tip {
                last_tip = tip;
            }

            // Request more blocks if we're behind headers and have capacity
            if tip < htip {
                let req_count = self.requested_blocks.read().unwrap().len();
                if req_count < 256 {
                    let peer_ids: Vec<PeerId> = {
                        let peers = self.peers.read().unwrap();
                        peers.iter()
                            .filter(|(_, h)| h.info.state == PeerState::Connected)
                            .map(|(id, _)| *id)
                            .collect()
                    };
                    for pid in peer_ids {
                        self.request_missing_blocks(pid);
                    }
                }
            }

            ticks += 1;
            // Every 20 ticks (10 seconds), clear stale requests and check peers
            if ticks % 20 == 0 {
                self.requested_blocks.write().unwrap().clear();

                // Auto-reconnect if no peers connected
                if self.connection_count() == 0 {
                    let addrs = self.connect_addrs.read().unwrap().clone();
                    for addr in addrs {
                        let pm = Arc::clone(&self);
                        tokio::spawn(async move {
                            if let Err(e) = pm.connect_outbound(addr).await {
                                tracing::debug!(%addr, "Reconnect failed: {}", e);
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

    fn handle_peer_disconnected(&self, id: PeerId) {
        let mut peers = self.peers.write().unwrap();
        if let Some(handle) = peers.remove(&id) {
            tracing::info!(id, addr = %handle.info.addr, "Peer disconnected");
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
                    if self.mempool.get(&txid).is_none() {
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

        let mut accepted = 0;
        let mut max_height = 0u32;
        for header in &headers {
            match self.chain_state.accept_header(header) {
                Ok(_) => {
                    accepted += 1;
                }
                Err(e) => {
                    tracing::warn!(id, "Header rejected: {}", e);
                    break;
                }
            }
        }

        if accepted > 0 {
            // Update headers tip tracking
            // We don't know exact height here, estimate from accept_header
            let htip = self.headers_tip.load(Ordering::Relaxed) + accepted as u64;
            self.headers_tip.store(htip, Ordering::Relaxed);

            tracing::debug!(id, accepted, headers_tip = htip, "Headers accepted");

            // Request more headers
            self.send_to_peer(id, sync::make_getheaders(&self.chain_state));

            // Immediately request blocks if we have none in flight
            self.request_missing_blocks(id);
        }
    }

    fn handle_block(&self, _id: PeerId, block: bitcoin::Block) {
        let hash = block.block_hash();
        // Remove from requested tracking and send to processing thread
        self.requested_blocks.write().unwrap().remove(&hash);
        let _ = self.block_tx.send(block);
    }

    /// Block processing runs on a dedicated OS thread (not tokio) to avoid
    /// blocking the async event loop during CPU-intensive validation.
    fn block_processor(
        mut rx: mpsc::UnboundedReceiver<bitcoin::Block>,
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
    ) {
        let mut block_buffer: HashMap<bitcoin::BlockHash, bitcoin::Block> = HashMap::new();
        let mut last_log_height: u32 = 0;

        while let Some(block) = rx.blocking_recv() {
            let hash = block.block_hash();
            match chain_state.accept_block(&block) {
                Ok(_) => {
                    mempool.remove_for_block(&block);
                    // Drain buffer
                    loop {
                        let tip = chain_state.tip_hash();
                        match block_buffer.remove(&tip) {
                            Some(b) => {
                                match chain_state.accept_block(&b) {
                                    Ok(_) => { mempool.remove_for_block(&b); }
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

    fn handle_tx(&self, _id: PeerId, tx: bitcoin::Transaction) {
        let txid = tx.compute_txid();
        match self.mempool.accept_transaction(
            tx,
            &self.chain_state,
            self.chain_state.script_verifier(),
        ) {
            Ok(_) => {
                self.broadcast(NetworkMessage::Inv(vec![Inventory::WitnessTransaction(
                    txid,
                )]));
            }
            Err(e) => {
                tracing::debug!(%txid, "Tx rejected: {}", e);
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
            if let Some(hash) = self.chain_state.get_block_hash_by_height(h) {
                if let Some(entry) = self.chain_state.get_block_index(&hash) {
                    headers.push(entry.header);
                }
            }
        }

        if !headers.is_empty() {
            self.send_to_peer(id, NetworkMessage::Headers(headers));
        }
    }

    fn handle_getdata(&self, id: PeerId, inventory: Vec<Inventory>) {
        for inv in inventory {
            match inv {
                Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
                    if let Some(block) = self.chain_state.get_block(&hash) {
                        self.send_to_peer(id, NetworkMessage::Block(block));
                    }
                }
                Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                    if let Some(entry) = self.mempool.get(&txid) {
                        self.send_to_peer(id, NetworkMessage::Tx(entry.tx));
                    }
                }
                _ => {}
            }
        }
    }

    fn request_missing_blocks(&self, id: PeerId) {
        let tip = self.chain_state.tip_height();
        let mut to_request = Vec::new();
        let requested = self.requested_blocks.read().unwrap();

        // Request blocks from tip+1 upward where we have headers but no data
        for h in (tip + 1)..=(tip + 512) {
            if let Some(hash) = self.chain_state.get_block_hash_by_height(h) {
                if !self.chain_state.has_block_data(&hash) && !requested.contains(&hash) {
                    to_request.push(hash);
                    if to_request.len() >= 128 {
                        break;
                    }
                }
            } else {
                break;
            }
        }
        drop(requested);

        if !to_request.is_empty() {
            // Mark as requested
            let mut req = self.requested_blocks.write().unwrap();
            for hash in &to_request {
                req.insert(*hash);
            }
            drop(req);

            self.send_to_peer(id, sync::make_getdata_blocks(&to_request));
        }
    }

    fn send_to_peer(&self, id: PeerId, msg: NetworkMessage) {
        let peers = self.peers.read().unwrap();
        if let Some(handle) = peers.get(&id) {
            let _ = handle.msg_tx.try_send(msg);
        }
    }

    fn broadcast(&self, msg: NetworkMessage) {
        self.broadcast_except(0, msg);
    }

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
                tracing::debug!(id, %addr, "Peer task ended: {}", e);
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

        // Request headers to start sync
        let getheaders = sync::make_getheaders(&self.chain_state);
        conn.send(getheaders)
            .await
            .map_err(|e| e.to_string())?;

        // Main message loop with idle timeout
        loop {
            tokio::select! {
                result = tokio::time::timeout(
                    std::time::Duration::from_secs(600),
                    conn.recv()
                ) => {
                    match result {
                        Ok(Ok(msg)) => {
                            self.event_tx
                                .send(NetEvent::MessageReceived { id, msg })
                                .await
                                .map_err(|e| e.to_string())?;
                        }
                        Ok(Err(e)) => {
                            return Err(format!("recv error: {}", e));
                        }
                        Err(_) => {
                            return Err("peer idle timeout".to_string());
                        }
                    }
                }
                Some(msg) = msg_rx.recv() => {
                    conn.send(msg).await.map_err(|e| e.to_string())?;
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
            user_agent: "/btcd:0.1.0/".to_string(),
            start_height: self.chain_state.tip_height() as i32,
            relay: true,
        }
    }
}
