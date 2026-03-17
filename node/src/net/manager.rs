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
    /// Buffer for blocks received out of order (parent not yet connected).
    block_buffer: RwLock<HashMap<bitcoin::BlockHash, bitcoin::Block>>,
}

impl PeerManager {
    pub fn new(
        chain_state: Arc<ChainState>,
        mempool: Arc<Mempool>,
        network: Network,
    ) -> Arc<Self> {
        let (event_tx, event_rx) = mpsc::channel(256);
        Arc::new(Self {
            peers: RwLock::new(HashMap::new()),
            chain_state,
            mempool,
            network,
            next_id: AtomicU64::new(1),
            event_tx,
            event_rx: tokio::sync::Mutex::new(event_rx),
            block_buffer: RwLock::new(HashMap::new()),
        })
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
        for (id, handle) in peers.iter() {
            if handle.info.addr == *addr {
                // Drop the sender to signal disconnect
                let _ = handle.msg_tx.try_send(NetworkMessage::Ping(0));
                tracing::info!(%addr, id, "Disconnecting peer");
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

    /// Run the main event loop. Call from a spawned task.
    pub async fn run(self: &Arc<Self>) {
        let mut event_rx = self.event_rx.lock().await;
        let mut block_request_interval = tokio::time::interval(std::time::Duration::from_secs(2));

        loop {
            tokio::select! {
                event = event_rx.recv() => {
                    match event {
                        Some(NetEvent::PeerConnected { id, addr: _, version }) => {
                            self.handle_peer_connected(id, version);
                        }
                        Some(NetEvent::PeerDisconnected { id }) => {
                            self.handle_peer_disconnected(id);
                        }
                        Some(NetEvent::MessageReceived { id, msg }) => {
                            self.handle_message(id, msg).await;
                        }
                        None => break,
                    }
                }
                _ = block_request_interval.tick() => {
                    // Periodically request missing blocks from all connected peers
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

    async fn handle_message(&self, id: PeerId, msg: NetworkMessage) {
        match msg {
            NetworkMessage::Ping(nonce) => {
                self.send_to_peer(id, NetworkMessage::Pong(nonce));
            }
            NetworkMessage::Inv(inventory) => {
                self.handle_inv(id, inventory).await;
            }
            NetworkMessage::Headers(headers) => {
                self.handle_headers(id, headers).await;
            }
            NetworkMessage::Block(block) => {
                self.handle_block(id, block).await;
            }
            NetworkMessage::Tx(tx) => {
                self.handle_tx(id, tx).await;
            }
            NetworkMessage::GetHeaders(msg) => {
                self.handle_getheaders(id, msg).await;
            }
            NetworkMessage::GetData(inv) => {
                self.handle_getdata(id, inv).await;
            }
            _ => {
                // Ignore unhandled messages
            }
        }
    }

    async fn handle_inv(&self, id: PeerId, inventory: Vec<Inventory>) {
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

    async fn handle_headers(&self, id: PeerId, headers: Vec<bitcoin::block::Header>) {
        if headers.is_empty() {
            return;
        }

        let mut accepted = 0;
        for header in &headers {
            match self.chain_state.accept_header(header) {
                Ok(_) => accepted += 1,
                Err(e) => {
                    tracing::warn!(id, "Header rejected: {}", e);
                    break;
                }
            }
        }

        if accepted > 0 {
            tracing::debug!(id, accepted, "Headers accepted");
            // Request more headers
            self.send_to_peer(id, sync::make_getheaders(&self.chain_state));

            // Request blocks for headers we don't have data for
            // Only if we're not already downloading
            let tip = self.chain_state.tip_height();
            if tip == 0 || tip % 128 == 0 {
                self.request_missing_blocks(id);
            }
        }
    }

    async fn handle_block(&self, id: PeerId, block: bitcoin::Block) {
        let hash = block.block_hash();
        match self.chain_state.accept_block(&block) {
            Ok(_) => {
                self.mempool.remove_for_block(&block);
                let height = self.chain_state.tip_height();
                if height % 1000 == 0 {
                    tracing::info!(height, %hash, "IBD progress");
                }
                self.broadcast_except(id, sync::make_block_inv(hash));
                // Try to drain buffered blocks that may now connect
                self.drain_block_buffer(id).await;
            }
            Err(crate::chain::state::ChainError::Duplicate) => {}
            Err(crate::chain::state::ChainError::BadPrevBlock) => {
                // Out-of-order: buffer for later
                let mut buf = self.block_buffer.write().unwrap();
                if buf.len() < 1024 {
                    buf.insert(block.header.prev_blockhash, block);
                }
            }
            Err(e) => {
                tracing::warn!(%hash, "Block rejected: {}", e);
            }
        }
    }

    /// Try to connect buffered blocks whose parents are now available.
    async fn drain_block_buffer(&self, id: PeerId) {
        loop {
            let tip_hash = self.chain_state.tip_hash();
            let block = {
                let mut buf = self.block_buffer.write().unwrap();
                buf.remove(&tip_hash)
            };
            match block {
                Some(b) => {
                    let hash = b.block_hash();
                    match self.chain_state.accept_block(&b) {
                        Ok(_) => {
                            self.mempool.remove_for_block(&b);
                            let height = self.chain_state.tip_height();
                            if height % 1000 == 0 {
                                tracing::info!(height, %hash, "IBD progress");
                            }
                            self.broadcast_except(id, sync::make_block_inv(hash));
                            // Continue draining
                        }
                        Err(e) => {
                            tracing::debug!(%hash, "Buffered block failed: {}", e);
                            break;
                        }
                    }
                }
                None => break,
            }
        }
    }

    async fn handle_tx(&self, _id: PeerId, tx: bitcoin::Transaction) {
        let txid = tx.compute_txid();
        match self.mempool.accept_transaction(
            tx,
            &self.chain_state,
            self.chain_state.script_verifier(),
        ) {
            Ok(_) => {
                // Announce to peers
                self.broadcast(NetworkMessage::Inv(vec![Inventory::WitnessTransaction(
                    txid,
                )]));
            }
            Err(e) => {
                tracing::debug!(%txid, "Tx rejected: {}", e);
            }
        }
    }

    async fn handle_getheaders(
        &self,
        id: PeerId,
        msg: bitcoin::p2p::message_blockdata::GetHeadersMessage,
    ) {
        // Find the first locator hash we have
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

    async fn handle_getdata(&self, id: PeerId, inventory: Vec<Inventory>) {
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

        // Scan from current tip upward for blocks with headers but no data
        for h in (tip + 1)..=(tip + 2000) {
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
            let count = to_request.len();
            self.send_to_peer(id, sync::make_getdata_blocks(&to_request));
            if count % 1000 == 0 || count >= 128 {
                tracing::info!(tip, requesting = count, "Requesting blocks");
            }
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
        let (msg_tx, msg_rx) = mpsc::channel::<NetworkMessage>(64);

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

    /// The main task for a single peer (handles handshake + message loop).
    async fn peer_task(
        self: &Arc<Self>,
        id: PeerId,
        stream: TcpStream,
        direction: Direction,
        mut msg_rx: mpsc::Receiver<NetworkMessage>,
    ) -> Result<(), String> {
        let mut conn = Connection::new(stream, self.network);

        // Perform handshake
        let version = self.perform_handshake(id, &mut conn, direction).await?;

        // Notify manager of successful connection
        let addr = conn.peer_addr().map_err(|e| e.to_string())?;
        self.event_tx
            .send(NetEvent::PeerConnected {
                id,
                addr,
                version: version.clone(),
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
                // Receive from network (with 5-minute idle timeout)
                result = tokio::time::timeout(
                    std::time::Duration::from_secs(300),
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
                // Send to network
                Some(msg) = msg_rx.recv() => {
                    conn.send(msg).await.map_err(|e| e.to_string())?;
                }
            }
        }
    }

    /// Receive a message with a timeout.
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
