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

/// The wire transport carrying a peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// Legacy plaintext v1.
    V1,
    /// BIP 324 v2 encrypted transport.
    V2,
}

impl TransportProtocol {
    /// Bitcoin Core's `getpeerinfo.transport_protocol_type` string.
    pub fn as_str(self) -> &'static str {
        match self {
            TransportProtocol::V1 => "v1",
            TransportProtocol::V2 => "v2",
        }
    }

    /// Whether this is the BIP 324 v2 transport.
    pub fn is_v2(self) -> bool {
        matches!(self, TransportProtocol::V2)
    }
}

/// Per-peer state tracked by the peer manager.
#[derive(Debug)]
pub struct PeerInfo {
    pub id: PeerId,
    pub addr: SocketAddr,
    pub direction: Direction,
    /// Wire transport (v1 plaintext or BIP 324 v2). Set once the
    /// connection is established; defaults to v1.
    pub transport: TransportProtocol,
    pub state: PeerState,
    pub version: Option<VersionMessage>,
    pub services: ServiceFlags,
    pub best_height: i32,
    pub user_agent: String,
    pub ban_score: u32,
    pub compact_blocks: bool,
    /// Peer requested BIP 130 header announcements via `sendheaders`.
    /// When true, new-tip blocks are announced to this peer with a
    /// `headers` message rather than a legacy `inv`.
    pub prefers_headers: bool,
    /// Peer signaled BIP 155 addrv2 support via SendAddrV2.
    pub wants_addrv2: bool,
    /// Peer's minimum fee rate for tx relay (BIP 133 feefilter), in sat/kvB.
    pub fee_filter: u64,
    pub conn_time: SystemTime,
    /// Net permissions granted via -whitelist / -whitebind (noban,
    /// relay, ...). Default empty.
    pub permissions: crate::net::permissions::NetPermissions,
    /// For outbound `.onion` peers: the Tor v3 hostname we dialed. `addr`
    /// is a shared `0.0.0.0:port` placeholder for all onion peers (routing
    /// is via the proxy, so there is no clearnet socket), which makes it
    /// useless for identity. This carries the real per-peer identity so
    /// dedup, getpeerinfo, and addrman can distinguish onion peers. `None`
    /// for clearnet and inbound peers.
    pub onion_host: Option<String>,
}

impl PeerInfo {
    pub fn new(id: PeerId, addr: SocketAddr, direction: Direction) -> Self {
        Self {
            id,
            addr,
            direction,
            transport: TransportProtocol::V1,
            state: PeerState::Connecting,
            version: None,
            services: ServiceFlags::NONE,
            best_height: 0,
            user_agent: String::new(),
            ban_score: 0,
            compact_blocks: false,
            prefers_headers: false,
            wants_addrv2: false,
            fee_filter: 0,
            conn_time: SystemTime::now(),
            permissions: crate::net::permissions::NetPermissions::NONE,
            onion_host: None,
        }
    }

    /// Update peer info after receiving their version message.
    pub fn set_version(&mut self, version: VersionMessage) {
        self.services = version.services;
        self.best_height = version.start_height;
        self.user_agent = version.user_agent.clone();
        self.version = Some(version);
    }

    /// Whether this peer participates in tx relay — the BIP 37 `fRelay`
    /// flag from its version message. A peer that set `relay = false`
    /// (e.g. Bitcoin Core under `-blocksonly`, or a block-relay-only
    /// connection) must never be sent tx invs: Core treats a tx inv on
    /// such a connection as a protocol violation and disconnects.
    /// Defaults to `true` when no version has been received yet (such a
    /// peer is not `Connected`, so announce paths skip it anyway).
    pub fn relays_txs(&self) -> bool {
        self.version.as_ref().map(|v| v.relay).unwrap_or(true)
    }

    /// Convert to JSON-compatible format for getpeerinfo RPC. `stats` carries
    /// the live wire counters (bytes + last-activity timestamps) recorded by
    /// the connection read/write halves.
    pub fn to_rpc_json(&self, stats: &crate::net::stats::PeerStats) -> serde_json::Value {
        let conntime = self
            .conn_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Onion peers share the 0.0.0.0 placeholder socket; report the real
        // .onion hostname so getpeerinfo identifies them (matches Core, which
        // shows `<base32>.onion:port`).
        let addr_str = match &self.onion_host {
            Some(host) => format!("{host}:{}", self.addr.port()),
            None => self.addr.to_string(),
        };
        serde_json::json!({
            "id": self.id,
            "addr": addr_str,
            "services": format!("{:016x}", self.services.to_u64()),
            "servicesnames": [],
            "lastsend": stats.last_send(),
            "lastrecv": stats.last_recv(),
            "bytessent": stats.bytes_sent(),
            "bytesrecv": stats.bytes_recv(),
            "conntime": conntime,
            "version": self.version.as_ref().map(|v| v.version).unwrap_or(0),
            "subver": &self.user_agent,
            "inbound": self.direction == Direction::Inbound,
            "transport_protocol_type": self.transport.as_str(),
            "startingheight": self.best_height,
            "synced_headers": -1,
            "synced_blocks": -1,
            // Bitcoin Core always emits these two; canonical Core client
            // libraries read them without a null guard. NBitcoin's
            // `GetPeersInfoAsync` does `(long)peer["timeoffset"]` and
            // `peer["inflight"].Select(..)` — a missing field throws and
            // aborts the client's node connection (this is what made the
            // NBXplorer canary churn until the per-IP cap locked it out).
            // satd does not track a per-peer clock offset, so 0 (no
            // offset) is the truthful value; `inflight` is the set of
            // block heights being downloaded from this peer, empty here
            // since block-download scheduling is owned by the IBD layer,
            // not this per-peer record.
            "timeoffset": 0,
            "inflight": [],
            "minfeefilter": self.fee_filter as f64 / 100_000_000.0,
            "connection_type": match self.direction {
                Direction::Inbound => "inbound-full-relay",
                Direction::Outbound => "outbound-full-relay",
            },
        })
    }
}

/// Derive the Tor v3 `.onion` hostname from the 32-byte ed25519 public key
/// carried in a BIP 155 `AddrV2::TorV3` gossip entry.
///
/// Per rend-spec-v3 §6: the address is `base32(PUBKEY ‖ CHECKSUM ‖ VERSION)`
/// lowercased, where `VERSION = 0x03` and
/// `CHECKSUM = SHA3_256(".onion checksum" ‖ PUBKEY ‖ VERSION)[..2]`.
/// Needed because `AddrV2::socket_addr()` only yields IPv4/IPv6 — without this,
/// onion peers learned from gossip can't be turned back into a dialable host,
/// so a node running over a proxy never discovers onion peers beyond its
/// hardcoded seeds.
pub fn torv3_to_onion_host(pubkey: &[u8; 32]) -> String {
    use sha3::{Digest, Sha3_256};
    const VERSION: u8 = 0x03;

    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([VERSION]);
    let checksum = hasher.finalize();

    let mut data = Vec::with_capacity(35);
    data.extend_from_slice(pubkey);
    data.extend_from_slice(&checksum[..2]);
    data.push(VERSION);

    let encoded = data_encoding::BASE32_NOPAD.encode(&data).to_lowercase();
    format!("{encoded}.onion")
}

/// Inverse of [`torv3_to_onion_host`]: recover the 32-byte ed25519 public key
/// from a v3 `.onion` hostname, validating the version byte and the embedded
/// SHA3-256 checksum. Returns `None` for anything that isn't a well-formed v3
/// onion address. Needed to advertise our own hidden service over BIP 155 —
/// `AddrV2::TorV3` carries the pubkey, but Tor only hands back the base32
/// ServiceID string.
pub fn onion_host_to_torv3_pubkey(host: &str) -> Option<[u8; 32]> {
    use sha3::{Digest, Sha3_256};
    const VERSION: u8 = 0x03;

    let label = host.strip_suffix(".onion")?;
    // A v3 ServiceID is base32(32-byte pubkey ‖ 2-byte checksum ‖ 1-byte
    // version) = 35 bytes → exactly 56 base32 chars.
    if label.len() != 56 {
        return None;
    }
    let data = data_encoding::BASE32_NOPAD
        .decode(label.to_uppercase().as_bytes())
        .ok()?;
    if data.len() != 35 || data[34] != VERSION {
        return None;
    }
    let pubkey: [u8; 32] = data[..32].try_into().ok()?;

    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([VERSION]);
    let checksum = hasher.finalize();
    // Constant comparison isn't security-critical here (public address data),
    // but reject a mismatched checksum so we never advertise a garbage key.
    if data[32..34] != checksum[..2] {
        return None;
    }
    Some(pubkey)
}

#[cfg(test)]
mod onion_addr_tests {
    use super::{onion_host_to_torv3_pubkey, torv3_to_onion_host};

    /// Round-trip against a real Tor-generated v3 address (one of satd's own
    /// hardcoded mainnet onion seeds): decode it to recover the pubkey, then
    /// re-derive the full address. This validates the SHA3-256 checksum, the
    /// version byte, and the base32 encoding all at once against ground truth.
    #[test]
    fn torv3_derivation_matches_real_onion() {
        let onion = "5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpfid.onion";
        let b32 = onion.strip_suffix(".onion").unwrap().to_uppercase();
        let decoded = data_encoding::BASE32_NOPAD.decode(b32.as_bytes()).unwrap();
        assert_eq!(decoded.len(), 35, "pubkey(32) + checksum(2) + version(1)");
        assert_eq!(decoded[34], 0x03, "v3 version byte");

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&decoded[..32]);
        assert_eq!(torv3_to_onion_host(&pubkey), onion);
    }

    /// `onion_host_to_torv3_pubkey` is the exact inverse of
    /// `torv3_to_onion_host`: host → pubkey → host returns the original.
    #[test]
    fn onion_host_pubkey_roundtrip() {
        let onion = "5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpfid.onion";
        let pubkey = onion_host_to_torv3_pubkey(onion).expect("valid v3 onion");
        assert_eq!(torv3_to_onion_host(&pubkey), onion);
    }

    /// Malformed inputs are rejected rather than yielding a bogus key we'd
    /// then advertise to the network.
    #[test]
    fn onion_host_pubkey_rejects_malformed() {
        // Not an onion host.
        assert!(onion_host_to_torv3_pubkey("example.com:8333").is_none());
        // v2-length (16-char) onion.
        assert!(onion_host_to_torv3_pubkey("expyuzz4wqqyqhjn.onion").is_none());
        // Right shape, corrupted checksum (flip one base32 char).
        let bad = "5g72ppm3krkorsfopcm2bi7wlv4ohhs4u4mlseymasn7g7zhdcyjpgid.onion";
        assert!(onion_host_to_torv3_pubkey(bad).is_none());
        // Empty / suffix only.
        assert!(onion_host_to_torv3_pubkey(".onion").is_none());
    }
}
