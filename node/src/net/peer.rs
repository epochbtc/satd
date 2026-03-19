use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;
use std::fmt;
use std::net::SocketAddr;
use std::time::SystemTime;

/// Address that can represent either a regular socket address or a .onion hostname.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PeerAddr {
    Socket(SocketAddr),
    Onion { host: String, port: u16 },
}

impl PeerAddr {
    /// Returns true if this is a .onion address.
    pub fn is_onion(&self) -> bool {
        matches!(self, PeerAddr::Onion { .. })
    }

    /// Returns the port number.
    pub fn port(&self) -> u16 {
        match self {
            PeerAddr::Socket(addr) => addr.port(),
            PeerAddr::Onion { port, .. } => *port,
        }
    }

    /// Try to parse a string as a PeerAddr.
    /// Handles "host:port" where host can be a .onion address or IP.
    pub fn parse(s: &str) -> Result<Self, String> {
        // Check if it's a .onion address
        if let Some((host, port_str)) = s.rsplit_once(':') {
            if host.ends_with(".onion") {
                let port: u16 = port_str
                    .parse()
                    .map_err(|_| format!("invalid port in onion address: {}", s))?;
                return Ok(PeerAddr::Onion {
                    host: host.to_string(),
                    port,
                });
            }
        } else if s.ends_with(".onion") {
            return Err(format!("onion address missing port: {}", s));
        }

        // Try as regular SocketAddr
        s.parse::<SocketAddr>()
            .map(PeerAddr::Socket)
            .map_err(|e| format!("invalid address '{}': {}", s, e))
    }
}

impl fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerAddr::Socket(addr) => write!(f, "{}", addr),
            PeerAddr::Onion { host, port } => write!(f, "{}:{}", host, port),
        }
    }
}

/// Unique peer identifier.
pub type PeerId = u64;

/// Connection direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Peer connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    SentVersion,
    Connected,
    Disconnected,
}

/// Per-peer state tracked by the peer manager.
#[derive(Debug)]
pub struct PeerInfo {
    pub id: PeerId,
    pub addr: SocketAddr,
    pub direction: Direction,
    pub state: PeerState,
    pub version: Option<VersionMessage>,
    pub services: ServiceFlags,
    pub best_height: i32,
    pub user_agent: String,
    pub ban_score: u32,
    pub compact_blocks: bool,
    /// Peer signaled BIP 155 addrv2 support via SendAddrV2.
    pub wants_addrv2: bool,
    /// Peer's minimum fee rate for tx relay (BIP 133 feefilter), in sat/kvB.
    pub fee_filter: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub conn_time: SystemTime,
}

impl PeerInfo {
    pub fn new(id: PeerId, addr: SocketAddr, direction: Direction) -> Self {
        Self {
            id,
            addr,
            direction,
            state: PeerState::Connecting,
            version: None,
            services: ServiceFlags::NONE,
            best_height: 0,
            user_agent: String::new(),
            ban_score: 0,
            compact_blocks: false,
            wants_addrv2: false,
            fee_filter: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            conn_time: SystemTime::now(),
        }
    }

    /// Update peer info after receiving their version message.
    pub fn set_version(&mut self, version: VersionMessage) {
        self.services = version.services;
        self.best_height = version.start_height;
        self.user_agent = version.user_agent.clone();
        self.version = Some(version);
    }

    /// Convert to JSON-compatible format for getpeerinfo RPC.
    pub fn to_rpc_json(&self) -> serde_json::Value {
        let conntime = self
            .conn_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        serde_json::json!({
            "id": self.id,
            "addr": self.addr.to_string(),
            "services": format!("{:016x}", self.services.to_u64()),
            "servicesnames": [],
            "lastsend": 0,
            "lastrecv": 0,
            "bytessent": self.bytes_sent,
            "bytesrecv": self.bytes_recv,
            "conntime": conntime,
            "version": self.version.as_ref().map(|v| v.version).unwrap_or(0),
            "subver": &self.user_agent,
            "inbound": self.direction == Direction::Inbound,
            "startingheight": self.best_height,
            "synced_headers": -1,
            "synced_blocks": -1,
            "minfeefilter": self.fee_filter as f64 / 100_000_000.0,
            "connection_type": match self.direction {
                Direction::Inbound => "inbound-full-relay",
                Direction::Outbound => "outbound-full-relay",
            },
        })
    }
}
