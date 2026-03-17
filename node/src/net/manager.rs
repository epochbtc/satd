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

        while let Some(event) = event_rx.recv().await {
            match event {
                NetEvent::PeerConnected { id, addr: _, version } => {
                    self.handle_peer_connected(id, version);
                }
                NetEvent::PeerDisconnected { id } => {
                    self.handle_peer_disconnected(id);
                }
                NetEvent::MessageReceived { id, msg } => {
                    self.handle_message(id, msg).await;
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
        }

        // Request blocks for headers we don't have data for
        self.request_missing_blocks(id);
    }

    async fn handle_block(&self, _id: PeerId, block: bitcoin::Block) {
        let hash = block.block_hash();
        match self.chain_state.accept_block(&block) {
            Ok(_) => {
                self.mempool.remove_for_block(&block);
                // Announce to other peers
                self.broadcast_except(0, sync::make_block_inv(hash));
            }
            Err(crate::chain::state::ChainError::Duplicate) => {
                // Already have it, ignore
            }
            Err(e) => {
                tracing::warn!(%hash, "Block rejected: {}", e);
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
        // Simple approach: request blocks we have headers for but no data
        // Walk from genesis to tip looking for HeaderOnly entries
        let tip = self.chain_state.tip_height();
        let mut to_request = Vec::new();

        // Check a window above the current tip (headers may be ahead)
        for h in 0..=(tip + 2000) {
            if let Some(hash) = self.chain_state.get_block_hash_by_height(h) {
                if !self.chain_state.has_block_data(&hash) {
                    to_request.push(hash);
                    if to_request.len() >= 16 {
                        break;
                    }
                }
            } else {
                break;
            }
        }

        if !to_request.is_empty() {
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

        // Main message loop
        loop {
            tokio::select! {
                // Receive from network
                result = conn.recv() => {
                    match result {
                        Ok(msg) => {
                            self.event_tx
                                .send(NetEvent::MessageReceived { id, msg })
                                .await
                                .map_err(|e| e.to_string())?;
                        }
                        Err(e) => {
                            return Err(format!("recv error: {}", e));
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

    /// Perform the version/verack handshake.
    async fn perform_handshake(
        &self,
        _id: PeerId,
        conn: &mut Connection,
        direction: Direction,
    ) -> Result<VersionMessage, String> {
        let our_version = self.build_version_message(conn.peer_addr().map_err(|e| e.to_string())?);

        match direction {
            Direction::Outbound => {
                // Send our version first
                conn.send(NetworkMessage::Version(our_version))
                    .await
                    .map_err(|e| format!("send version: {}", e))?;

                // Wait for their version
                let their_version = loop {
                    let msg = conn.recv().await.map_err(|e| format!("recv: {}", e))?;
                    if let NetworkMessage::Version(v) = msg {
                        break v;
                    }
                };

                // Send verack
                conn.send(NetworkMessage::Verack)
                    .await
                    .map_err(|e| format!("send verack: {}", e))?;

                // Wait for their verack
                loop {
                    let msg = conn.recv().await.map_err(|e| format!("recv: {}", e))?;
                    if matches!(msg, NetworkMessage::Verack) {
                        break;
                    }
                }

                // Send SendHeaders to request header announcements
                conn.send(NetworkMessage::SendHeaders)
                    .await
                    .map_err(|e| format!("send sendheaders: {}", e))?;

                Ok(their_version)
            }
            Direction::Inbound => {
                // Wait for their version
                let their_version = loop {
                    let msg = conn.recv().await.map_err(|e| format!("recv: {}", e))?;
                    if let NetworkMessage::Version(v) = msg {
                        break v;
                    }
                };

                // Send our version
                conn.send(NetworkMessage::Version(our_version))
                    .await
                    .map_err(|e| format!("send version: {}", e))?;

                // Send verack
                conn.send(NetworkMessage::Verack)
                    .await
                    .map_err(|e| format!("send verack: {}", e))?;

                // Wait for their verack
                loop {
                    let msg = conn.recv().await.map_err(|e| format!("recv: {}", e))?;
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
