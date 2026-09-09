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

    /// Parse an address string, using `default_port` when the input has no port.
    ///
    /// Pure: `.onion` targets and IP literals only. Anything needing a name
    /// lookup belongs to [`crate::net::dns::resolve_peer_target`], which is
    /// async and honours `-proxy` and `-dns`; this used to call the
    /// **blocking** `ToSocketAddrs` from inside async handlers, and did it
    /// with the local resolver even under `-proxy`.
    pub fn parse_with_default_port(s: &str, default_port: u16) -> Result<Self, String> {
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

        // Try as regular SocketAddr (strict numeric IP:port).
        if let Ok(sa) = s.parse::<SocketAddr>() {
            return Ok(PeerAddr::Socket(sa));
        }
        // A bare IP literal takes the default port. Checked before the
        // bracket form below, because every IPv6 literal contains colons: with
        // only a colon test, `-connect=2001:db8::1` fell through to "could not
        // resolve" while `-connect=1.2.3.4` worked. Core's `Lookup(…,
        // default_port)` accepts both.
        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
            return Ok(PeerAddr::Socket(SocketAddr::new(ip, default_port)));
        }
        // `[2001:db8::1]` — bracketed, portless.
        if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']'))
            && let Ok(ip) = inner.parse::<std::net::Ipv6Addr>()
        {
            return Ok(PeerAddr::Socket(SocketAddr::new(ip.into(), default_port)));
        }
        Err(format!("invalid address '{}': could not resolve", s))
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

/// How this connection came about — Bitcoin Core's `ConnectionType`.
///
/// Core does not treat these as decoration: the type decides whether we ask
/// the peer for transactions, whether we relay addresses to it, and how long
/// we keep it. `getpeerinfo`'s `connection_type` reports it verbatim, and the
/// functional-test framework's `add_outbound_p2p_connection` selects one
/// through the hidden `addconnection` RPC.
///
/// satd does not open `feeler` or `addr-fetch` connections of its own accord
/// (it has no automatic connection scheduler that would); they exist here
/// because `addconnection` can ask for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnType {
    /// A peer that dialled us.
    Inbound,
    /// `addnode` / `-connect` / `-addnode`.
    Manual,
    /// The ordinary outbound peer: blocks, transactions and addresses.
    OutboundFullRelay,
    /// Blocks only. No transaction relay, no address relay — Core's
    /// anti-partition connections, deliberately invisible to a tx-graph
    /// observer.
    BlockRelay,
    /// Opened to ask one peer for addresses, then dropped.
    AddrFetch,
    /// Opened only to see whether the address is still alive; closed as soon
    /// as the peer's `version` arrives.
    Feeler,
}

impl ConnType {
    /// Core's spelling, as `getpeerinfo.connection_type` reports it and
    /// `addconnection` accepts it.
    pub fn as_str(self) -> &'static str {
        match self {
            ConnType::Inbound => "inbound",
            ConnType::Manual => "manual",
            ConnType::OutboundFullRelay => "outbound-full-relay",
            ConnType::BlockRelay => "block-relay-only",
            ConnType::AddrFetch => "addr-fetch",
            ConnType::Feeler => "feeler",
        }
    }

    /// Parse the four types `addconnection` may open. `inbound` and `manual`
    /// are deliberately absent: Core's `CConnman::AddConnection` returns false
    /// for them, so they are not openable this way.
    pub fn from_addconnection_str(s: &str) -> Option<Self> {
        match s {
            "outbound-full-relay" => Some(ConnType::OutboundFullRelay),
            "block-relay-only" => Some(ConnType::BlockRelay),
            "addr-fetch" => Some(ConnType::AddrFetch),
            "feeler" => Some(ConnType::Feeler),
            _ => None,
        }
    }

    /// Whether we ask this peer to relay transactions to us — the `fRelay`
    /// flag in the `version` we send. Core clears it for block-relay-only and
    /// feeler connections (`CNode::IsBlockOnlyConn() || IsFeelerConn()`).
    pub fn wants_tx_relay(self) -> bool {
        !matches!(self, ConnType::BlockRelay | ConnType::Feeler)
    }

    /// Whether we relay addresses over this connection. Core sets up a peer's
    /// address-relay state for everything except block-relay-only.
    pub fn relays_addrs(self) -> bool {
        !matches!(self, ConnType::BlockRelay)
    }
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
    /// BIP 324 session ID, for a v2 peer. `None` on v1.
    ///
    /// `getpeerinfo.session_id` exists for out-of-band MITM detection: both
    /// ends compare it, and a mismatch means someone is in between. satd
    /// reported `""` for every peer — indistinguishable from "no session", so
    /// the one check the field is for could not be made.
    pub session_id: Option<[u8; 32]>,
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
    /// Whether address relay is set up on this link — Core's
    /// `Peer::m_addr_relay_enabled`, latched by `SetupAddressRelay`.
    ///
    /// A block-relay-only link never enables it, in either direction. An
    /// outbound link enables it once the handshake completes (that is when
    /// Core sends its one-shot `getaddr`); an *inbound* link enables it
    /// lazily, on the first addr-related message the peer sends, so a peer
    /// that never participates in addr relay is never counted as doing so.
    pub addr_relay_enabled: bool,
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
    /// The local socket address this connection is bound to
    /// (`getsockname()`), behind `getpeerinfo`'s `addrbind`. `None` until the
    /// socket exists, and for onion peers, whose local end belongs to the
    /// proxy rather than to us.
    pub bind_addr: Option<SocketAddr>,
    /// How this connection came about. Drives `getpeerinfo`'s
    /// `connection_type`, the `fRelay` flag we send, and address relay.
    pub conn_type: ConnType,
}

/// Render a per-message-type byte tally as `getpeerinfo` reports it.
///
/// Bitcoin Core emits only the entries with a non-zero count, so a peer that
/// has exchanged nothing yields an empty object rather than a wall of zeros.
fn per_msg_json(counts: &std::collections::BTreeMap<&'static str, u64>) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for (cmd, bytes) in counts {
        if *bytes > 0 {
            obj.insert((*cmd).to_string(), serde_json::json!(bytes));
        }
    }
    serde_json::Value::Object(obj)
}

impl PeerInfo {
    pub fn new(id: PeerId, addr: SocketAddr, direction: Direction) -> Self {
        Self {
            id,
            addr,
            direction,
            transport: TransportProtocol::V1,
            session_id: None,
            state: PeerState::Connecting,
            version: None,
            services: ServiceFlags::NONE,
            best_height: -1,
            user_agent: String::new(),
            ban_score: 0,
            compact_blocks: false,
            prefers_headers: false,
            wants_addrv2: false,
            addr_relay_enabled: false,
            fee_filter: 0,
            conn_time: std::time::UNIX_EPOCH + std::time::Duration::from_secs(crate::time::now_secs()),
            permissions: crate::net::permissions::NetPermissions::NONE,
            bind_addr: None,
            onion_host: None,
            conn_type: match direction {
                Direction::Inbound => ConnType::Inbound,
                Direction::Outbound => ConnType::OutboundFullRelay,
            },
        }
    }

    /// Update peer info after receiving their version message.
    pub fn set_version(&mut self, version: VersionMessage) {
        self.services = version.services;
        self.best_height = version.start_height;
        self.user_agent = version.user_agent.clone();
        // The peer's own `fRelay` is kept on the stored `version` message;
        // `relays_txs()` is the answer to "do *we* relay to them", which
        // depends on the connection type rather than on what they asked for.
        self.version = Some(version);
    }

    /// Whether we sync headers and request blocks from this peer. Core
    /// excludes addr-fetch connections from both (`fPreferredDownload` and
    /// `CanServeBlocks` are false for them): the connection is opened to
    /// collect addresses and dropped straight afterwards.
    pub fn serves_blocks(&self) -> bool {
        self.conn_type != ConnType::AddrFetch
    }

    /// Whether this peer participates in tx relay — the BIP 37 `fRelay`
    /// flag from its version message. A peer that set `relay = false`
    /// (e.g. Bitcoin Core under `-blocksonly`, or a block-relay-only
    /// connection) must never be sent tx invs: Core treats a tx inv on
    /// such a connection as a protocol violation and disconnects.
    /// Defaults to `true` when no version has been received yet (such a
    /// peer is not `Connected`, so announce paths skip it anyway).
    pub fn relays_txs(&self) -> bool {
        // Both directions matter. The peer's `fRelay` says whether it wants
        // our transactions; our own connection type says whether this link is
        // allowed to carry any. A block-relay-only or feeler connection
        // carries none, and reading only the remote's flag meant satd
        // announced its own transactions over the very links opened to avoid
        // exactly that -- Core clears `fRelay` on the way out and never
        // announces on such a peer.
        self.conn_type.wants_tx_relay() && self.version.as_ref().map(|v| v.relay).unwrap_or(true)
    }

    /// Whether addresses may be relayed over this connection, in either
    /// direction (Core's `SetupAddressRelay`, `net_processing.cpp:5608`:
    /// "We don't participate in addr relay with outbound block-relay-only
    /// connections to prevent providing adversaries with the additional
    /// information of addr traffic to infer the link").
    pub fn relays_addrs(&self) -> bool {
        self.conn_type.relays_addrs()
    }

    /// How this peer is named to operators -- what `getpeerinfo` reports as
    /// `addr`, and what `disconnectnode` matches an address against.
    ///
    /// Onion peers share the 0.0.0.0 placeholder socket, so the real
    /// `<base32>.onion:port` hostname is reported instead (as Core does).
    /// The two callers must agree, or an address satd itself printed cannot
    /// be fed back to it.
    pub fn addr_string(&self) -> String {
        match &self.onion_host {
            Some(host) => format!("{host}:{}", self.addr.port()),
            None => self.addr.to_string(),
        }
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

        let addr_str = self.addr_string();
        // Derive the peer's network from its address.
        let network = if let Some(ref onion) = self.onion_host {
            let _ = onion; // suppress unused
            "onion"
        } else if !crate::net::is_routable(self.addr.ip()) {
            "not_publicly_routable"
        } else {
            match self.addr.ip() {
                std::net::IpAddr::V4(_) => "ipv4",
                std::net::IpAddr::V6(_) => "ipv6",
            }
        };

        // Build the services-name list matching Core's format.
        let svc_u64 = self.services.to_u64();
        // Core's `serviceFlagsToStr` (`protocol.cpp`) walks bits 0..64 in
        // order and emits each set bit's name, falling back to
        // `UNKNOWN[2^i]`. satd listed every known flag first and then every
        // unknown one, so a peer advertising bits 0, 1 and 2 came back as
        // `[NETWORK, BLOOM, UNKNOWN[2^1]]` where Core says
        // `[NETWORK, UNKNOWN[2^1], BLOOM]` — and `rpc_net.py` compares the
        // list.
        let mut svc_names: Vec<String> = Vec::new();
        for bit in 0..64u32 {
            if svc_u64 & (1u64 << bit) == 0 {
                continue;
            }
            svc_names.push(match bit {
                0 => "NETWORK".to_string(),
                2 => "BLOOM".to_string(),
                3 => "WITNESS".to_string(),
                6 => "COMPACT_FILTERS".to_string(),
                10 => "NETWORK_LIMITED".to_string(),
                11 => "P2P_V2".to_string(),
                other => format!("UNKNOWN[2^{other}]"),
            });
        }

        let connection_type = self.conn_type.as_str();

        let mut obj = serde_json::json!({
            "id": self.id,
            "addr": addr_str,
            "services": format!("{:016x}", self.services.to_u64()),
            "servicesnames": svc_names,
            // Core: "Whether we relay transactions to this peer". It builds
            // no TxRelay structure for a block-relay-only or feeler
            // connection, so `getpeerinfo` reports false for both regardless
            // of what the peer's own `fRelay` said.
            "relaytxes": self.relays_txs(),
            "lastsend": stats.last_send(),
            "lastrecv": stats.last_recv(),
            "last_block": stats.last_block(),
            "last_transaction": stats.last_transaction(),
            "bytessent": stats.bytes_sent(),
            "bytesrecv": stats.bytes_recv(),
            "conntime": conntime,
            "version": self.version.as_ref().map(|v| v.version).unwrap_or(0),
            "subver": &self.user_agent,
            "inbound": self.direction == Direction::Inbound,
            "network": network,
            "transport_protocol_type": self.transport.as_str(),
            "startingheight": self.best_height,
            "presynced_headers": -1,
            "synced_headers": -1,
            "synced_blocks": -1,
            // Core's `NetPermissions::ToStrings` of the flags actually
            // granted. This was hardcoded `[]` while `self.permissions` was
            // populated all along -- and an empty array reads as "no
            // permissions granted", not "not implemented", which is the
            // opposite claim for a `-whitelist`ed peer.
            "permissions": self.permissions.to_strings(),
            "addr_processed": 0,
            "addr_rate_limited": 0,
            // Core withholds address relay from block-relay-only peers --
            // that is the whole point of the connection type. For everyone
            // else this is latched by `SetupAddressRelay`, not derived from
            // the direction: an inbound peer that has exchanged addr traffic
            // does relay addresses, and reporting it as `false` misdescribes
            // every inbound link on the node.
            "addr_relay_enabled": self.addr_relay_enabled,
            "bip152_hb_from": false,
            "bip152_hb_to": false,
            "inv_to_send": 0,
            "last_inv_sequence": 0,
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
            // Per-message-type wire tallies. Core omits zero entries, so an
            // idle peer yields `{}` rather than a table of zeros.
            "bytessent_per_msg": per_msg_json(&stats.bytes_sent_per_msg()),
            "bytesrecv_per_msg": per_msg_json(&stats.bytes_recv_per_msg()),
            "minfeefilter": self.fee_filter as f64 / 100_000_000.0,
            "connection_type": connection_type,
            // Core pushes this only for a v2 peer (`if (transport ==
            // V2) ... HexStr(session_id)`), so v1 keeps Core's empty string.
            "session_id": match self.session_id {
                Some(id) => hex::encode(id),
                None => String::new(),
            },
        });
        // Core reports the local end of the connection here, and its own test
        // framework matches a peer by it — but only when it has one: the field
        // is documented optional and pushed under `if (addrBind.IsValid())`.
        // Rendering an unset bind as `0.0.0.0:0` would invent a listener
        // address that no peer is actually on.
        if let Some(bind) = self.bind_addr {
            obj["addrbind"] = serde_json::Value::String(bind.to_string());
        }
        // Ping round-trip timings. Core pushes each of these only when it has
        // a value -- a peer that has not completed a ping/pong exchange yet
        // reports no `pingtime` rather than a zero, which would read as an
        // instantaneous link.
        if let Some(secs) = stats.ping_time_secs() {
            obj["pingtime"] = serde_json::json!(secs);
        }
        if let Some(secs) = stats.min_ping_secs() {
            obj["minping"] = serde_json::json!(secs);
        }
        if let Some(secs) = stats.ping_wait_secs() {
            obj["pingwait"] = serde_json::json!(secs);
        }
        obj
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
mod rpc_json_tests {
    use super::*;
    use crate::net::stats::{NetTotals, PeerStats};

    fn peer_json(bind: Option<&str>, wire: &[(&'static str, usize)]) -> serde_json::Value {
        let mut info = PeerInfo::new(7, "203.0.113.9:8333".parse().unwrap(), Direction::Outbound);
        info.bind_addr = bind.map(|b| b.parse().unwrap());
        let stats = PeerStats::new(NetTotals::new());
        for (cmd, n) in wire {
            stats.record_sent(*n);
            stats.attribute_sent(cmd, *n);
        }
        info.to_rpc_json(&stats)
    }

    /// Core's framework reads `bytes*_per_msg` without a null guard, so those
    /// keys must always be present -- a missing one raises KeyError and aborts
    /// the client. `addrbind` is present whenever there is a bind address to
    /// report, which is how the framework matches a peer.
    #[test]
    fn core_fields_are_always_present() {
        let v = peer_json(Some("127.0.0.1:18445"), &[]);
        assert_eq!(v["addrbind"], "127.0.0.1:18445");
        assert!(v["bytessent_per_msg"].is_object());
        assert!(v["bytesrecv_per_msg"].is_object());
        // Nothing exchanged yet: empty objects, not absent keys.
        assert_eq!(v["bytessent_per_msg"].as_object().unwrap().len(), 0);
    }

    /// A peer whose local address is unknown (proxied, or the socket is gone)
    /// omits the key, as Core does: it pushes `addrbind` only under
    /// `if (stats.addrBind.IsValid())` and documents the field optional.
    /// Rendering `0.0.0.0:0` would name a listener no peer is on.
    #[test]
    fn unknown_bind_address_omits_addrbind_like_core() {
        let v = peer_json(None, &[]);
        assert!(v.get("addrbind").is_none(), "{v}");
        // The unconditional keys are still there.
        assert!(v["bytessent_per_msg"].is_object());
        assert!(v["bytesrecv_per_msg"].is_object());
    }

    /// `network` is Core's `GetNetworkName(stats.m_network)`, and
    /// `CNetAddr::GetNetwork()` folds *every* unroutable address into
    /// `NET_UNROUTABLE` before the ipv4/ipv6 split. Classifying by address
    /// family alone reported a peer on a private LAN or a link-local
    /// address as `ipv4`/`ipv6`, which `feature_proxy.py` asserts against
    /// directly.
    #[test]
    fn unroutable_peers_are_not_reported_as_ipv4_or_ipv6() {
        let json_for = |addr: &str| {
            let info = PeerInfo::new(1, addr.parse().unwrap(), Direction::Outbound);
            info.to_rpc_json(&PeerStats::new(NetTotals::new()))["network"]
                .as_str()
                .unwrap()
                .to_string()
        };
        // Routable.
        assert_eq!(json_for("8.8.8.8:8333"), "ipv4");
        assert_eq!(json_for("[2606:4700::1]:8333"), "ipv6");
        // RFC1918 / RFC6598 / loopback / link-local / RFC5737 doc range.
        for addr in [
            "10.0.0.1:8333",
            "172.16.0.1:8333",
            "192.168.1.1:8333",
            "100.64.0.1:8333",
            "127.0.0.1:8333",
            "169.254.1.1:8333",
            "192.0.2.1:8333",
            // RFC3849 IPv6 documentation prefix is *not* in Core's
            // unroutable set, so it is deliberately absent here.
        ] {
            assert_eq!(json_for(addr), "not_publicly_routable", "{addr}");
        }
        // ULA / IPv6 link-local / IPv6 loopback / RFC4843 ORCHID.
        for addr in [
            "[fc00::1]:8333",
            "[fe80::1]:8333",
            "[::1]:8333",
            "[2001:10::1]:8333",
        ] {
            assert_eq!(json_for(addr), "not_publicly_routable", "{addr}");
        }
    }

    /// `rpc_net.py` compares `servicesnames` element by element against the
    /// bits it set, so the list has to come out in bit order with exactly
    /// the named bits Core knows.
    #[test]
    fn servicesnames_is_emitted_in_bit_order() {
        let mut info = PeerInfo::new(1, "203.0.113.9:8333".parse().unwrap(), Direction::Outbound);
        // NETWORK (bit 0) | WITNESS (bit 3) | NETWORK_LIMITED (bit 10),
        // plus an unnamed high bit that must not appear.
        info.services = ServiceFlags::from(
            (1 << 0) | (1 << 3) | (1 << 10) | (1u64 << 40),
        );
        let v = info.to_rpc_json(&PeerStats::new(NetTotals::new()));
        let names: Vec<&str> = v["servicesnames"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap())
            .collect();
        // Core's `serviceFlagToStr` falls through to `UNKNOWN[2^<bit>]`
        // rather than dropping a bit it has no name for, so the list is a
        // faithful rendering of the flags word.
        assert_eq!(
            names,
            ["NETWORK", "WITNESS", "NETWORK_LIMITED", "UNKNOWN[2^40]"],
            "{v}"
        );
    }

    /// Core latches `addr_relay_enabled` in `SetupAddressRelay`; it is not a
    /// function of the direction. Deriving it from `Direction::Outbound`
    /// reported every inbound peer as `false` even while it was actively
    /// exchanging addr messages with us.
    #[test]
    fn addr_relay_enabled_reports_the_latch_not_the_direction() {
        let mut inbound = PeerInfo::new(1, "203.0.113.9:8333".parse().unwrap(), Direction::Inbound);
        inbound.conn_type = ConnType::Inbound;
        let stats = PeerStats::new(NetTotals::new());
        assert_eq!(
            inbound.to_rpc_json(&stats)["addr_relay_enabled"],
            false,
            "no addr traffic yet"
        );
        inbound.addr_relay_enabled = true;
        assert_eq!(
            inbound.to_rpc_json(&stats)["addr_relay_enabled"],
            true,
            "an inbound peer that has exchanged addrs does relay them"
        );
    }

    /// Core emits only non-zero entries.
    #[test]
    fn per_message_counters_omit_zero_entries() {
        let v = peer_json(Some("127.0.0.1:1"), &[("ping", 32), ("pong", 32), ("ping", 32)]);
        let sent = v["bytessent_per_msg"].as_object().unwrap();
        assert_eq!(sent.len(), 2, "only the types actually sent: {sent:?}");
        assert_eq!(sent["ping"], 64);
        assert_eq!(sent["pong"], 32);
        assert_eq!(v["bytesrecv_per_msg"].as_object().unwrap().len(), 0);
    }
}

#[cfg(test)]
mod default_port_tests {
    use super::*;

    /// `-connect`/`-addnode` entries with no port take the *network's* port.
    /// This is the whole of change #1 in #690: reverting the call sites to a
    /// literal 8333 must fail a named test, and before this one nothing did.
    #[test]
    fn a_portless_entry_takes_the_networks_default() {
        for (network, port) in [
            (bitcoin::Network::Bitcoin, 8333u16),
            (bitcoin::Network::Testnet, 18333),
            (bitcoin::Network::Testnet4, 48333),
            (bitcoin::Network::Signet, 38333),
            (bitcoin::Network::Regtest, 18444),
        ] {
            assert_eq!(default_p2p_port(network), port, "{network}");
            let addr = PeerAddr::parse_with_default_port("1.2.3.4", port)
                .unwrap_or_else(|e| panic!("{network}: {e}"));
            assert_eq!(addr.to_string(), format!("1.2.3.4:{port}"), "{network}");
            // An explicit port always wins over the network default.
            let addr = PeerAddr::parse_with_default_port("1.2.3.4:1234", port).unwrap();
            assert_eq!(addr.to_string(), "1.2.3.4:1234", "{network}");
        }
    }

    /// Every IPv6 literal contains colons, so the "has no port" test alone
    /// rejected them: `-connect=2001:db8::1` was "could not resolve" while
    /// `-connect=1.2.3.4` worked. The manual promises both.
    #[test]
    fn a_bare_ipv6_literal_takes_the_default_port_too() {
        let addr = PeerAddr::parse_with_default_port("2001:db8::1", 38333).expect("bare IPv6");
        assert_eq!(addr.to_string(), "[2001:db8::1]:38333");
        let addr = PeerAddr::parse_with_default_port("::1", 18444).expect("loopback IPv6");
        assert_eq!(addr.to_string(), "[::1]:18444");
        // A bracketed literal with an explicit port keeps it.
        let addr = PeerAddr::parse_with_default_port("[2001:db8::1]:1234", 38333).unwrap();
        assert_eq!(addr.to_string(), "[2001:db8::1]:1234");
    }
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

/// Default P2P port for each network, matching Bitcoin Core's chainparams.
pub fn default_p2p_port(network: bitcoin::Network) -> u16 {
    match network {
        bitcoin::Network::Bitcoin => 8333,
        bitcoin::Network::Testnet => 18333,
        bitcoin::Network::Testnet4 => 48333,
        bitcoin::Network::Signet => 38333,
        bitcoin::Network::Regtest => 18444,
    }
}
