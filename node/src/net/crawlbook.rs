//! The crawl frontier (`CrawlBook`): every address an optional crawl mode
//! has learned, when each is next due a session, and what the last one
//! showed.
//!
//! A crawl walks the reachable network: it asks nodes for addresses
//! (`getaddr`), dials what they name, and records which addresses complete
//! a handshake. This book is its own structure, kept apart from the address
//! manager: nothing here is ever written to addrman, relayed, served on
//! `getaddr`, or offered to the node's own dialer.
//!
//! This module is the pure part: admission of `addr`/`addrv2` answers, the
//! per-address timers and backoff, the reachable snapshot, the size bound
//! and [`CRAWL_FILE`]. The connections are the engine's. No method reads the
//! clock: every one that needs the time takes `now` (Unix seconds).
//!
//! # Admission
//!
//! An answer of more than [`MAX_ANSWER_ENTRIES`] entries is dropped whole.
//! From the rest, at most [`MAX_ADMITTED_PER_ANSWER`] new addresses are
//! admitted. An entry is ignored when its `nTime` is older than
//! [`BookParams::max_age_secs`] or more than [`MAX_FUTURE_SECS`] ahead, when
//! its address is not public unicast (private, reserved, multicast and the
//! other ranges [`is_public_unicast`] refuses), when its port is one Core's
//! `IsBadPort` avoids, or when its network is one the book does not know
//! (TORv2, unknown BIP 155 ids). A new IPv6 address is admitted only while
//! the book holds fewer than [`IPV6_PER_64`] in its `/64`, a new IPv4 one
//! while it holds fewer than [`BookParams::ipv4_per_24`] in its `/24`. Onion,
//! I2P and CJDNS addresses are derived from keys, so a prefix says nothing
//! about who runs them, and they have no prefix cap. I2P and CJDNS entries
//! are recorded and counted but never dialled: satd has no transport for
//! either.
//!
//! An address already in the book is not admitted again; it is *named*
//! again: its source joins the distinct sources that named it, and an
//! address only one source ever named is dialled after the others, so one
//! node flooding its answers cannot set the crawl's agenda.
//!
//! # Timers
//!
//! | Session | When |
//! |---|---|
//! | [`SessionKind::Discovery`] | On first contact, then once per [`DISCOVERY_INTERVAL_SECS`]: a Core node answers `getaddr` from a cache that lives about a day, so asking sooner learns nothing. |
//! | [`SessionKind::Liveness`] | Every [`BookParams::liveness_secs`] after the last completed handshake. |
//! | [`SessionKind::V1Recheck`] | For an address whose last v2 attempt succeeded: on first contact, then every [`V1_RECHECK_INTERVAL_SECS`]. A v1 failure next to a v2 success marks it v2-only. |
//! | Unreachable retry | After [`BACKOFF_SECS`] (1 h, 4 h, 24 h, then daily). An address failing for [`DROP_AFTER_SECS`] that no source named in that time is dropped. |
//!
//! The file holds peer addresses. It is written with the data directory's
//! permissions (execute bits dropped), as `peersurvey.dat` is.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;

use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::ServiceFlags;

use crate::net::fingerprint::{AddrKind, Fingerprint};
use crate::net::v2transport::V2Greeting;
use crate::net::peer::PeerAddr;
use crate::net::survey::{self, Probe, ProbeOutcome, ProbeResults, Reader};

/// The file's name in the network data directory.
pub const CRAWL_FILE: &str = "crawlbook.dat";

/// The most entries kept; past it the least recently used goes first.
pub const MAX_ENTRIES: usize = 250_000;

/// An answer with more entries than this is dropped whole. Core never
/// sends more (`MAX_ADDR_TO_SEND`).
pub const MAX_ANSWER_ENTRIES: usize = 1_000;

/// The most new addresses one answer admits.
pub const MAX_ADMITTED_PER_ANSWER: usize = 500;

/// An entry whose `nTime` is further ahead of our clock than this is
/// ignored.
pub const MAX_FUTURE_SECS: u64 = 10 * 60;

/// The default for [`BookParams::max_age_secs`]: five days.
pub const DEFAULT_MAX_AGE_SECS: u64 = 5 * 24 * 60 * 60;

/// New IPv6 addresses admitted per `/64`.
pub const IPV6_PER_64: u32 = 1;

/// The default for [`BookParams::ipv4_per_24`].
pub const DEFAULT_IPV4_PER_24: u32 = 8;

/// The default for [`BookParams::liveness_secs`]: two hours.
pub const DEFAULT_LIVENESS_SECS: u64 = 2 * 60 * 60;

/// How long after a discovery session the next one is due.
pub const DISCOVERY_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// How long after a v1 recheck the next one is due.
pub const V1_RECHECK_INTERVAL_SECS: u64 = 7 * 24 * 60 * 60;

/// The wait after the first, second and third failure in a row; every
/// later failure waits as long as the last.
pub const BACKOFF_SECS: [u64; 3] = [60 * 60, 4 * 60 * 60, 24 * 60 * 60];

/// An address failing this long, and named by no source in this time, is
/// dropped. A never-dialled (I2P, CJDNS) entry not named this long is
/// dropped too.
pub const DROP_AFTER_SECS: u64 = 30 * 24 * 60 * 60;

/// The most distinct sources an entry remembers; past it the count stays.
pub const MAX_SOURCES: usize = 16;

/// A session open this long with no result is taken as abandoned (its
/// task cancelled or gone without reporting): the address is due, droppable
/// and evictable again. Far above the longest session a crawl runs (a Tor
/// connect, the handshake, the `getaddr` wait and the probes).
pub const ABANDONED_AFTER_SECS: u64 = 10 * 60;

/// The source [`CrawlBook::seed`] records: seeds are one source between
/// them.
const SEED_SOURCE: u64 = 0;

const FILE_MAGIC: [u8; 8] = *b"satdcrwl";
/// 2: an unknown shape's raw features.
const FILE_VERSION: u32 = 2;

/// An address in the book. Dialable addresses are [`PeerAddr`]s; I2P and
/// CJDNS are kept to be counted, never dialled.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CrawlAddr {
    Peer(PeerAddr),
    I2p { dest: [u8; 32], port: u16 },
    Cjdns { ip: Ipv6Addr, port: u16 },
}

impl CrawlAddr {
    pub fn network(&self) -> Network {
        match self {
            CrawlAddr::Peer(PeerAddr::Onion { .. }) => Network::Onion,
            CrawlAddr::Peer(PeerAddr::Socket(sa)) => match sa.ip().to_canonical() {
                IpAddr::V4(_) => Network::Ipv4,
                IpAddr::V6(_) => Network::Ipv6,
            },
            CrawlAddr::I2p { .. } => Network::I2p,
            CrawlAddr::Cjdns { .. } => Network::Cjdns,
        }
    }

    /// Whether the crawl may ever dial it.
    pub fn dialable(&self) -> bool {
        matches!(self, CrawlAddr::Peer(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Ipv4,
    Ipv6,
    Onion,
    I2p,
    Cjdns,
}

impl Network {
    pub const ALL: [Network; 5] = [Network::Ipv4, Network::Ipv6, Network::Onion, Network::I2p, Network::Cjdns];

    pub fn name(self) -> &'static str {
        match self {
            Network::Ipv4 => "ipv4",
            Network::Ipv6 => "ipv6",
            Network::Onion => "onion",
            Network::I2p => "i2p",
            Network::Cjdns => "cjdns",
        }
    }
}

/// What one crawl session to an address is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SessionKind {
    /// v2 then v1, the handshake, `getaddr`, the probes.
    Discovery,
    /// v1 only, the handshake: tells a v2-only node from one that does both.
    V1Recheck,
    /// v2 then v1, the handshake only.
    Liveness,
}

/// How one transport attempt of a session went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Attempt {
    #[default]
    NotTried,
    Failed,
    /// The handshake completed.
    Ok,
}

/// The answer to a discovery session's `getaddr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetaddrResult {
    /// Entries in the answer, and milliseconds from `getaddr` to it.
    Answered { entries: u32, delay_ms: u32 },
    /// Nothing came within the session's wait.
    NoAnswer,
}

/// Where a peer's chain stands against ours, from the chain check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainCheck {
    /// It has the block after our locator.
    OnChain,
    /// It does not have our locator's block yet.
    Behind,
    /// It answered with a block that is not ours.
    Fork,
    /// It is on another chain under this network's magic.
    OtherChain,
}

impl ChainCheck {
    const ALL: [ChainCheck; 4] = [ChainCheck::OnChain, ChainCheck::Behind, ChainCheck::Fork, ChainCheck::OtherChain];
}

/// What the last session with a completed handshake showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Unix seconds.
    pub at: u64,
    pub fingerprint: Fingerprint,
    /// The user agent, sanitized as `getpeerinfo.subver` is. Peer text.
    pub user_agent: String,
    pub protocol_version: u32,
    /// The services in the peer's `version`.
    pub services: u64,
    /// The address's autonomous system under `-asmap`.
    pub asn: Option<u32>,
    pub probes: ProbeResults,
    /// The session ran over BIP 324.
    pub v2: bool,
    /// The peer's `start_height`.
    pub height: i32,
    /// Our tip's height when the peer's `version` came.
    pub our_height: u32,
    pub chain_check: Option<ChainCheck>,
    /// The peer's `version` timestamp less our clock, seconds.
    pub clock_offset_secs: Option<i64>,
    /// From our `version` to the peer's `verack`, milliseconds.
    pub handshake_rtt_ms: Option<u32>,
    /// `None` when the session did not send `getaddr`.
    pub getaddr: Option<GetaddrResult>,
    /// For an unknown fingerprint only: what the classifier read that the
    /// fields above do not hold.
    pub shape: Option<UnknownShape>,
}

/// The raw features of a crawl session no crawl row matched, kept so that
/// a new implementation shows up as a cluster of records of one shape
/// before it has a row. The `version` fields and the probes' answers are
/// in the [`Observation`] itself. Bounded: at most
/// [`HANDSHAKE_CAPTURE_MAX`](crate::net::behavior::HANDSHAKE_CAPTURE_MAX)
/// commands of at most [`SHAPE_COMMAND_LEN`] bytes each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownShape {
    /// The handshake transcript (peer text, `?` for an unprintable byte).
    pub commands: Vec<String>,
    /// The `relay` flag of the peer's `version`.
    pub relay: bool,
    /// What the peer sent inside BIP 324 before its first message; `None`
    /// over v1.
    pub v2: Option<V2Greeting>,
    /// The message the `getaddr` answer came in, when one came.
    pub getaddr: Option<AddrKind>,
}

/// The longest command an [`UnknownShape`] keeps: the wire's command field.
pub const SHAPE_COMMAND_LEN: usize = 12;

impl Observation {
    /// Our tip less the peer's height: positive when the peer lags.
    pub fn height_gap(&self) -> i64 {
        i64::from(self.our_height) - i64::from(self.height)
    }
}

/// What a finished session reports.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionResult {
    pub v2: Attempt,
    pub v1: Attempt,
    /// What the handshake showed, when one completed.
    pub observation: Option<Observation>,
}

impl SessionResult {
    fn reached(&self) -> bool {
        self.v2 == Attempt::Ok || self.v1 == Attempt::Ok
    }
}

/// One address's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlEntry {
    // Learned.
    pub first_learned: u64,
    /// The last time a source named it (or it was seeded).
    pub last_named: u64,
    /// The distinct sources that named it, at most [`MAX_SOURCES`].
    sources: Vec<u64>,
    /// The services the last answer naming it advertised.
    pub advertised_services: u64,
    /// The newest `nTime` any answer gave it.
    pub best_time: u32,

    // Dialling.
    pub attempts: u32,
    pub last_attempt: Option<u64>,
    /// The last completed handshake, any session kind.
    pub last_success: Option<u64>,
    pub last_discovery: Option<u64>,
    pub last_v1_check: Option<u64>,
    /// Sessions in a row that completed no handshake.
    pub failures: u32,
    /// The first of those failures.
    pub failing_since: Option<u64>,
    /// No session before this, while failing.
    pub retry_at: Option<u64>,
    /// When the open session started, and its token; `None` with none
    /// open.
    in_flight: Option<(u64, u64)>,
    /// The last session token handed out: a counter, so two sessions
    /// opened in the same second never share one.
    sessions: u64,

    // Transport.
    /// The last v2 attempt's outcome.
    pub v2_ok: Option<bool>,
    /// The last v1 attempt's outcome.
    pub v1_ok: Option<bool>,
    last_v2_ok: Option<u64>,
    /// The last v1 failure on a session whose v2 did not also fail.
    last_v1_fail: Option<u64>,
    /// A v1 attempt failed within a liveness window of a v2 success.
    pub v2_only: bool,

    // History.
    pub reachable_count: u32,
    pub first_reachable: Option<u64>,

    pub observation: Option<Observation>,
}

impl CrawlEntry {
    fn new(now: u64, source: u64, services: u64, time: u32) -> Self {
        CrawlEntry {
            first_learned: now,
            last_named: now,
            sources: vec![source],
            advertised_services: services,
            best_time: time,
            attempts: 0,
            last_attempt: None,
            last_success: None,
            last_discovery: None,
            last_v1_check: None,
            failures: 0,
            failing_since: None,
            retry_at: None,
            in_flight: None,
            sessions: 0,
            v2_ok: None,
            v1_ok: None,
            last_v2_ok: None,
            last_v1_fail: None,
            v2_only: false,
            reachable_count: 0,
            first_reachable: None,
            observation: None,
        }
    }

    /// How many distinct sources named it (seeds count as one), at most
    /// [`MAX_SOURCES`].
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Whether the address was advertised with `NODE_P2P_V2`.
    pub fn v2_advertised(&self) -> bool {
        ServiceFlags::from(self.advertised_services).has(ServiceFlags::P2P_V2)
    }

    /// The last completed handshake, as the history counts it.
    pub fn last_reachable(&self) -> Option<u64> {
        self.last_success
    }

    /// Whether a session is open to it at `now`: one opened and neither
    /// reported nor abandoned ([`ABANDONED_AFTER_SECS`]).
    pub fn in_flight(&self, now: u64) -> bool {
        self.in_flight.is_some_and(|(opened, _)| now.saturating_sub(opened) < ABANDONED_AFTER_SECS)
    }

    fn named(&mut self, source: u64, services: u64, time: u32, now: u64) {
        self.last_named = self.last_named.max(now);
        self.seeded(source, services);
        self.best_time = self.best_time.max(time);
    }

    /// Note `source` among its sources without counting as a naming: a
    /// seed handed in again does not keep a failing address in the book.
    fn seeded(&mut self, source: u64, services: u64) {
        if self.sources.len() < MAX_SOURCES && !self.sources.contains(&source) {
            self.sources.push(source);
        }
        self.advertised_services = services;
    }

    /// The recency LRU eviction goes by.
    fn lru_key(&self) -> u64 {
        self.last_named.max(self.last_success.unwrap_or(0))
    }

    /// Whether it has failed for [`DROP_AFTER_SECS`] with no source naming
    /// it in that time.
    fn droppable(&self, dialable: bool, now: u64) -> bool {
        let unnamed = now.saturating_sub(self.last_named) >= DROP_AFTER_SECS;
        if !dialable {
            return unnamed;
        }
        unnamed && self.failing_since.is_some_and(|f| now.saturating_sub(f) >= DROP_AFTER_SECS)
    }

    /// When it is due and for what; `None` while not due.
    fn due(&self, now: u64, liveness_secs: u64) -> Option<(u64, SessionKind)> {
        if self.in_flight(now) {
            return None;
        }
        if self.retry_at.is_some_and(|retry| now < retry) {
            return None;
        }
        let Some(success) = self.last_success else {
            // First contact.
            return Some((self.retry_at.unwrap_or(self.first_learned), SessionKind::Discovery));
        };
        let discovery = self.last_discovery.map_or(success, |d| d + DISCOVERY_INTERVAL_SECS);
        if let Some(retry) = self.retry_at {
            let kind = if discovery <= now { SessionKind::Discovery } else { SessionKind::Liveness };
            return Some((retry, kind));
        }
        if discovery <= now {
            return Some((discovery, SessionKind::Discovery));
        }
        if self.v2_ok == Some(true) {
            let v1 = self.last_v1_check.map_or(success, |c| c + V1_RECHECK_INTERVAL_SECS);
            if v1 <= now {
                return Some((v1, SessionKind::V1Recheck));
            }
        }
        let liveness = success + liveness_secs;
        (liveness <= now).then_some((liveness, SessionKind::Liveness))
    }
}

/// The book's tunable bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BookParams {
    /// The most entries kept.
    pub max_entries: usize,
    /// An entry whose `nTime` is older than this is ignored (`-crawlmaxage`).
    pub max_age_secs: u64,
    /// New IPv4 addresses admitted per `/24`.
    pub ipv4_per_24: u32,
    /// How often a reachable address is checked again, and how far back
    /// the snapshot looks (`-crawlliveness`).
    pub liveness_secs: u64,
    /// Admit loopback and private addresses too, so a regtest crawl can
    /// walk nodes on one host. Only [`Self::for_network`] on regtest sets
    /// it; no option does.
    pub allow_local: bool,
}

impl BookParams {
    /// The defaults for `network`: local addresses are admitted on regtest
    /// alone.
    pub fn for_network(network: bitcoin::Network) -> Self {
        BookParams { allow_local: network == bitcoin::Network::Regtest, ..BookParams::default() }
    }

    /// Whether an IP address may enter the book: public unicast, or under
    /// [`Self::allow_local`] any address that names a host.
    fn admits_ip(&self, ip: IpAddr) -> bool {
        is_public_unicast(ip) || (self.allow_local && crate::net::is_valid(ip))
    }
}

impl Default for BookParams {
    fn default() -> Self {
        BookParams {
            max_entries: MAX_ENTRIES,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            ipv4_per_24: DEFAULT_IPV4_PER_24,
            liveness_secs: DEFAULT_LIVENESS_SECS,
            allow_local: false,
        }
    }
}

/// What [`CrawlBook::admit`] did with one answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmitReport {
    /// Entries in the answer.
    pub entries: usize,
    /// The answer was over [`MAX_ANSWER_ENTRIES`] and nothing in it was read.
    pub dropped_whole: bool,
    /// New addresses entered the book.
    pub admitted: usize,
    /// Addresses already in the book, named again.
    pub named_again: usize,
    pub too_old: usize,
    pub in_future: usize,
    /// Not public unicast.
    pub not_public: usize,
    pub bad_port: usize,
    /// TORv2 or an unknown network id.
    pub unsupported: usize,
    pub ipv6_prefix_full: usize,
    pub ipv4_prefix_full: usize,
    /// New addresses past [`MAX_ADMITTED_PER_ANSWER`].
    pub over_source_cap: usize,
    /// Admitted, then evicted at once: the book is full and every older
    /// entry has a session open.
    pub not_kept: usize,
}

/// Entries per network, and how many of them were ever reached.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetworkCounts {
    /// [`Network::ALL`]'s order.
    pub learned: [usize; Network::ALL.len()],
    pub reached: [usize; Network::ALL.len()],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Prefix {
    V4([u8; 3]),
    V6([u8; 8]),
}

/// The IP of a socket address, canonical.
fn socket_ip(addr: &CrawlAddr) -> Option<IpAddr> {
    let CrawlAddr::Peer(PeerAddr::Socket(sa)) = addr else {
        return None;
    };
    Some(sa.ip().to_canonical())
}

fn prefix(ip: IpAddr) -> Prefix {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Prefix::V4([o[0], o[1], o[2]])
        }
        IpAddr::V6(v6) => Prefix::V6(v6.octets()[..8].try_into().expect("8 bytes")),
    }
}

/// Whether a crawl may admit `ip`: routable as Core judges it
/// ([`crate::net::is_routable`]), and not multicast or reserved. IPv4
/// multicast (`224.0.0.0/4`), the reserved `240.0.0.0/4` and the IETF
/// protocol block `192.0.0.0/24` are refused, and every IPv6 address
/// outside global unicast (`2000::/3`), which takes in multicast
/// (`ff00::/8`) and the unassigned and translation ranges.
pub fn is_public_unicast(ip: IpAddr) -> bool {
    if !crate::net::is_routable(ip) {
        return false;
    }
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_multicast() || o[0] >= 240 || (o[0] == 192 && o[1] == 0 && o[2] == 0))
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xe000) == 0x2000,
    }
}

/// The book's id for a source: the first eight bytes of the SHA-256 of
/// its address as the file stores it. Stable across versions, since the
/// file holds it.
fn source_id(source: &PeerAddr) -> u64 {
    let mut buf = Vec::new();
    survey::encode_addr(&mut buf, source);
    let h = sha256::Hash::hash(&buf);
    u64::from_le_bytes(h.as_byte_array()[..8].try_into().expect("8 bytes"))
}

/// Why an answer entry is not an address the book can hold.
enum Unusable {
    NotPublic,
    Unsupported,
}

fn crawl_addr(m: &AddrV2Message, params: &BookParams) -> Result<CrawlAddr, Unusable> {
    let ip = match &m.addr {
        AddrV2::Ipv4(v4) => IpAddr::V4(*v4),
        AddrV2::Ipv6(v6) => IpAddr::V6(*v6).to_canonical(),
        AddrV2::TorV3(key) => {
            return Ok(CrawlAddr::Peer(PeerAddr::Onion { host: crate::net::peer::torv3_to_onion_host(key), port: m.port }))
        }
        AddrV2::I2p(dest) => return Ok(CrawlAddr::I2p { dest: *dest, port: m.port }),
        AddrV2::Cjdns(ip) if ip.octets()[0] == 0xfc => return Ok(CrawlAddr::Cjdns { ip: *ip, port: m.port }),
        AddrV2::Cjdns(_) => return Err(Unusable::NotPublic),
        AddrV2::TorV2(_) | AddrV2::Unknown(..) => return Err(Unusable::Unsupported),
    };
    if !params.admits_ip(ip) {
        return Err(Unusable::NotPublic);
    }
    Ok(CrawlAddr::Peer(PeerAddr::Socket(std::net::SocketAddr::new(ip, m.port))))
}

/// The crawl frontier.
#[derive(Debug, Clone)]
pub struct CrawlBook {
    entries: HashMap<CrawlAddr, CrawlEntry>,
    /// Every entry by [`CrawlEntry::lru_key`], least recent first.
    lru: BTreeSet<(u64, CrawlAddr)>,
    /// Distinct IPs per IPv4 `/24` and IPv6 `/64`.
    prefixes: HashMap<Prefix, u32>,
    /// Entries (one per port) per IP.
    ips: HashMap<IpAddr, u32>,
    params: BookParams,
}

impl Default for CrawlBook {
    fn default() -> Self {
        Self::new(BookParams::default())
    }
}

impl CrawlBook {
    pub fn new(params: BookParams) -> Self {
        CrawlBook { entries: HashMap::new(), lru: BTreeSet::new(), prefixes: HashMap::new(), ips: HashMap::new(), params }
    }

    pub fn params(&self) -> &BookParams {
        &self.params
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, addr: &CrawlAddr) -> Option<&CrawlEntry> {
        self.entries.get(addr)
    }

    /// Every entry, by address.
    pub fn rows(&self) -> impl Iterator<Item = (&CrawlAddr, &CrawlEntry)> {
        self.entries.iter()
    }

    /// Read the addresses of one `addr` or `addrv2` answer from `source`.
    pub fn admit(&mut self, source: &PeerAddr, answer: &[AddrV2Message], now: u64) -> AdmitReport {
        let mut report = AdmitReport { entries: answer.len(), ..AdmitReport::default() };
        if answer.len() > MAX_ANSWER_ENTRIES {
            report.dropped_whole = true;
            return report;
        }
        let source = source_id(source);
        for m in answer {
            let time = u64::from(m.time);
            if now.saturating_sub(time) > self.params.max_age_secs {
                report.too_old += 1;
                continue;
            }
            if time > now + MAX_FUTURE_SECS {
                report.in_future += 1;
                continue;
            }
            let addr = match crawl_addr(m, &self.params) {
                Ok(a) => a,
                Err(Unusable::NotPublic) => {
                    report.not_public += 1;
                    continue;
                }
                Err(Unusable::Unsupported) => {
                    report.unsupported += 1;
                    continue;
                }
            };
            if crate::net::is_bad_port(m.port) {
                report.bad_port += 1;
                continue;
            }
            if self.entries.contains_key(&addr) {
                self.update(&addr, |e| e.named(source, m.services.to_u64(), m.time, now));
                report.named_again += 1;
                continue;
            }
            if report.admitted >= MAX_ADMITTED_PER_ANSWER {
                report.over_source_cap += 1;
                continue;
            }
            // The caps count IPs: another port of an IP already in the
            // book takes no prefix slot.
            match socket_ip(&addr).filter(|ip| !self.ips.contains_key(ip)).map(prefix) {
                Some(p @ Prefix::V6(_)) if self.prefix_count(p) >= IPV6_PER_64 => {
                    report.ipv6_prefix_full += 1;
                    continue;
                }
                Some(p @ Prefix::V4(_)) if self.prefix_count(p) >= self.params.ipv4_per_24 => {
                    report.ipv4_prefix_full += 1;
                    continue;
                }
                _ => {}
            }
            if self.insert(addr, CrawlEntry::new(now, source, m.services.to_u64(), m.time), now) {
                report.admitted += 1;
            } else {
                report.not_kept += 1;
            }
        }
        report
    }

    /// Add a seed (a DNS seed's answer, a fixed seed, an address-manager
    /// sample, `-crawlseed`). The address rules hold, the answer and prefix
    /// caps do not: a seed is not gossip. Seeds count as one source between
    /// them. Seeding an address already in the book is not a source naming
    /// it again: it does not hold off the drop of an address that keeps
    /// failing. Returns whether the address is in the book afterwards.
    pub fn seed(&mut self, addr: PeerAddr, services: u64, now: u64) -> bool {
        let addr = match addr {
            PeerAddr::Socket(sa) => PeerAddr::Socket(std::net::SocketAddr::new(sa.ip().to_canonical(), sa.port())),
            onion @ PeerAddr::Onion { .. } => onion,
        };
        let usable = match &addr {
            PeerAddr::Socket(sa) => self.params.admits_ip(sa.ip()),
            PeerAddr::Onion { .. } => true,
        };
        if !usable || crate::net::is_bad_port(addr.port()) {
            return false;
        }
        let addr = CrawlAddr::Peer(addr);
        if self.entries.contains_key(&addr) {
            self.update(&addr, |e| e.seeded(SEED_SOURCE, services));
            true
        } else {
            self.insert(addr, CrawlEntry::new(now, SEED_SOURCE, services, 0), now)
        }
    }

    /// At most `limit` of the addresses due a session at `now`, in the
    /// order to dial them: those more than one source named first, then
    /// each group by when it fell due, a discovery before a v1 recheck
    /// before a liveness check. An address with a session open is not due.
    pub fn next_due(&self, now: u64, limit: usize) -> Vec<(PeerAddr, SessionKind)> {
        self.next_due_where(now, limit, |_| true)
    }

    /// [`Self::next_due`] over the addresses `dialable` accepts: the
    /// engine passes over those on a network it does not reach, so they
    /// do not fill the `limit` ahead of the ones it can dial.
    pub fn next_due_where(
        &self,
        now: u64,
        limit: usize,
        dialable: impl Fn(&PeerAddr) -> bool,
    ) -> Vec<(PeerAddr, SessionKind)> {
        let liveness = self.params.liveness_secs;
        let mut due: Vec<(bool, u64, SessionKind, &PeerAddr)> = self
            .entries
            .iter()
            .filter_map(|(addr, e)| {
                let CrawlAddr::Peer(peer) = addr else { return None };
                let (at, kind) = e.due(now, liveness)?;
                if !dialable(peer) {
                    return None;
                }
                Some((e.sources.len() < 2, at, kind, peer))
            })
            .collect();
        due.sort_unstable();
        due.into_iter().take(limit).map(|(_, _, kind, peer)| (peer.clone(), kind)).collect()
    }

    /// Note a session opened to `addr`: it is not due again until
    /// [`Self::record_result`] with the token returned here (a
    /// per-entry counter). `None` when the address is not in the book, cannot be
    /// dialled, or already has a session open.
    pub fn mark_dialling(&mut self, addr: &PeerAddr, now: u64) -> Option<u64> {
        match self.entries.get_mut(&CrawlAddr::Peer(addr.clone())) {
            Some(e) if !e.in_flight(now) => {
                e.sessions = e.sessions.wrapping_add(1);
                e.in_flight = Some((now, e.sessions));
                Some(e.sessions)
            }
            _ => None,
        }
    }

    /// Record how a session of `kind` to `addr` went. A v1 recheck that
    /// fails is not a reachability failure; any other session that
    /// completes no handshake backs the address off, and drops it once it
    /// has failed for [`DROP_AFTER_SECS`] with no source naming it.
    ///
    /// `session` is the token [`Self::mark_dialling`] returned (`None` for
    /// a result with no session marked). A result whose token is not the
    /// session open now is stale, from a session abandoned and since
    /// replaced or already superseded, and is ignored: it neither clears
    /// the newer session's marker nor counts as the current outcome.
    /// Returns whether the result was applied.
    pub fn record_result(
        &mut self,
        addr: &PeerAddr,
        session: Option<u64>,
        kind: SessionKind,
        result: SessionResult,
        now: u64,
    ) -> bool {
        let key = CrawlAddr::Peer(addr.clone());
        match self.entries.get(&key) {
            Some(e) if e.in_flight.map(|(_, token)| token) == session => {}
            _ => return false,
        }
        let liveness = self.params.liveness_secs;
        let mut drop = false;
        self.update(&key, |e| {
            e.in_flight = None;
            e.attempts = e.attempts.saturating_add(1);
            e.last_attempt = Some(now);
            let within = |t: Option<u64>| t.is_some_and(|t| now.saturating_sub(t) <= liveness);
            if result.v2 != Attempt::NotTried {
                e.v2_ok = Some(result.v2 == Attempt::Ok);
            }
            if result.v1 != Attempt::NotTried {
                e.v1_ok = Some(result.v1 == Attempt::Ok);
            }
            // A v1 failure says the node refuses v1 only when v2 did not
            // fail too; both failing says it is down.
            if result.v1 == Attempt::Failed && result.v2 != Attempt::Failed {
                e.last_v1_fail = Some(now);
                if within(e.last_v2_ok) {
                    e.v2_only = true;
                }
            }
            if result.v2 == Attempt::Ok {
                e.last_v2_ok = Some(now);
                if result.v1 != Attempt::Ok && within(e.last_v1_fail) {
                    e.v2_only = true;
                }
            }
            if result.v1 == Attempt::Ok {
                e.v2_only = false;
            }
            if kind == SessionKind::V1Recheck {
                e.last_v1_check = Some(now);
                if !result.reached() {
                    return;
                }
            }
            if result.reached() {
                e.last_success = Some(now);
                e.failures = 0;
                e.failing_since = None;
                e.retry_at = None;
                e.reachable_count = e.reachable_count.saturating_add(1);
                e.first_reachable.get_or_insert(now);
                if kind == SessionKind::Discovery {
                    e.last_discovery = Some(now);
                }
                if let Some(mut obs) = result.observation {
                    // A session that did not send `getaddr`, probe or check
                    // the chain keeps what the last one that did found.
                    if let Some(old) = e.observation.take() {
                        obs.getaddr = obs.getaddr.or(old.getaddr);
                        obs.chain_check = obs.chain_check.or(old.chain_check);
                        if !obs.probes.any() {
                            obs.probes = old.probes;
                        }
                    }
                    e.observation = Some(obs);
                }
            } else {
                e.failures = e.failures.saturating_add(1);
                e.failing_since.get_or_insert(now);
                let wait = BACKOFF_SECS[(e.failures as usize).min(BACKOFF_SECS.len()) - 1];
                e.retry_at = Some(now + wait);
                drop = e.droppable(true, now);
            }
        });
        if drop {
            self.remove(&key);
        }
        true
    }

    /// The reachable set: addresses whose last completed handshake is
    /// within the liveness window before `now`.
    pub fn snapshot(&self, now: u64) -> impl Iterator<Item = (&PeerAddr, &CrawlEntry)> {
        let since = now.saturating_sub(self.params.liveness_secs);
        self.entries.iter().filter_map(move |(addr, e)| match addr {
            CrawlAddr::Peer(peer) if e.last_success.is_some_and(|s| s >= since) => Some((peer, e)),
            _ => None,
        })
    }

    pub fn counts(&self) -> NetworkCounts {
        let mut c = NetworkCounts::default();
        for (addr, e) in &self.entries {
            let i = Network::ALL.iter().position(|n| *n == addr.network()).expect("every network is in ALL");
            c.learned[i] += 1;
            if e.last_success.is_some() {
                c.reached[i] += 1;
            }
        }
        c
    }

    /// Drop every entry past [`DROP_AFTER_SECS`] as of `now`, except one
    /// with a session open: its result decides.
    pub fn expire(&mut self, now: u64) {
        let gone: Vec<CrawlAddr> = self
            .entries
            .iter()
            .filter(|(a, e)| !e.in_flight(now) && e.droppable(a.dialable(), now))
            .map(|(a, _)| a.clone())
            .collect();
        for addr in gone {
            self.remove(&addr);
        }
    }

    fn prefix_count(&self, p: Prefix) -> u32 {
        self.prefixes.get(&p).copied().unwrap_or(0)
    }

    /// Past the bound the least recently used entry without a session open
    /// goes. The entry just inserted has none open, so one always can; when
    /// every older entry has one, that is the new entry itself. Returns
    /// whether the new entry was kept.
    fn insert(&mut self, addr: CrawlAddr, entry: CrawlEntry, now: u64) -> bool {
        if let Some(ip) = socket_ip(&addr) {
            let n = self.ips.entry(ip).or_default();
            *n += 1;
            if *n == 1 {
                *self.prefixes.entry(prefix(ip)).or_default() += 1;
            }
        }
        self.lru.insert((entry.lru_key(), addr.clone()));
        self.entries.insert(addr.clone(), entry);
        while self.entries.len() > self.params.max_entries {
            let Some(oldest) = self.lru.iter().map(|(_, a)| a).find(|a| !self.entries[*a].in_flight(now)).cloned()
            else {
                break;
            };
            self.remove(&oldest);
        }
        self.entries.contains_key(&addr)
    }

    fn remove(&mut self, addr: &CrawlAddr) {
        let Some(e) = self.entries.remove(addr) else { return };
        self.lru.remove(&(e.lru_key(), addr.clone()));
        let Some(ip) = socket_ip(addr) else { return };
        let Some(n) = self.ips.get_mut(&ip) else { return };
        *n -= 1;
        if *n > 0 {
            return;
        }
        self.ips.remove(&ip);
        let p = prefix(ip);
        if let Some(n) = self.prefixes.get_mut(&p) {
            *n -= 1;
            if *n == 0 {
                self.prefixes.remove(&p);
            }
        }
    }

    /// Change one entry, keeping the LRU order in step.
    fn update(&mut self, addr: &CrawlAddr, f: impl FnOnce(&mut CrawlEntry)) {
        let Some(e) = self.entries.get_mut(addr) else { return };
        let before = e.lru_key();
        f(e);
        let after = e.lru_key();
        if before != after {
            self.lru.remove(&(before, addr.clone()));
            self.lru.insert((after, addr.clone()));
        }
    }

    /// The file's bytes: a magic, the format version, the network magic,
    /// the entries, then the hash256 of everything before it. Sessions open
    /// at the time are not recorded.
    pub fn encode(&self, network_magic: [u8; 4]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20 + self.entries.len() * 120);
        buf.extend_from_slice(&FILE_MAGIC);
        buf.extend_from_slice(&FILE_VERSION.to_le_bytes());
        buf.extend_from_slice(&network_magic);
        buf.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        let mut rows: Vec<(&CrawlAddr, &CrawlEntry)> = self.entries.iter().collect();
        rows.sort_unstable_by(|a, b| a.0.cmp(b.0));
        for (addr, e) in rows {
            encode_crawl_addr(&mut buf, addr);
            encode_entry(&mut buf, e);
        }
        let checksum = sha256d::Hash::hash(&buf);
        buf.extend_from_slice(checksum.as_byte_array());
        buf
    }

    /// Read [`Self::encode`]'s bytes under `params`, dropping what has
    /// expired as of `now` and the least recently used past the size bound.
    pub fn decode(bytes: &[u8], network_magic: [u8; 4], now: u64, params: BookParams) -> Result<Self, String> {
        if bytes.len() < FILE_MAGIC.len() + 4 + 4 + 4 + 32 {
            return Err("file too short".to_string());
        }
        let (body, checksum) = bytes.split_at(bytes.len() - 32);
        if sha256d::Hash::hash(body).as_byte_array() != checksum {
            return Err("checksum mismatch".to_string());
        }
        let mut r = Reader(body);
        if r.take(8)? != FILE_MAGIC {
            return Err("not a crawl book file".to_string());
        }
        let version = r.u32()?;
        if version != FILE_VERSION {
            return Err(format!("unknown crawl book version {version}"));
        }
        if r.take(4)? != network_magic {
            return Err("written for another network".to_string());
        }
        let count = r.u32()? as usize;
        let mut entries = HashMap::with_capacity(count.min(MAX_ENTRIES));
        for _ in 0..count {
            let addr = decode_crawl_addr(&mut r)?;
            let entry = decode_entry(&mut r)?;
            if entries.insert(addr, entry).is_some() {
                return Err("duplicate address".to_string());
            }
        }
        if !r.0.is_empty() {
            return Err("trailing bytes".to_string());
        }
        let mut book = CrawlBook::new(params);
        // Most recent last, so the bound drops the least recently used.
        let mut rows: Vec<(CrawlAddr, CrawlEntry)> = entries.into_iter().collect();
        rows.sort_unstable_by(|a, b| (a.1.lru_key(), &a.0).cmp(&(b.1.lru_key(), &b.0)));
        for (addr, entry) in rows {
            book.insert(addr, entry, 0); // nothing loaded has a session open: any time will do
        }
        book.expire(now);
        Ok(book)
    }

    /// Read the book from `path` under `params`; an absent file is an
    /// empty book.
    pub fn load(path: &Path, network_magic: [u8; 4], now: u64, params: BookParams) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(bytes) => Self::decode(&bytes, network_magic, now, params),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new(params)),
            Err(e) => Err(format!("reading {}: {e}", path.display())),
        }
    }

    /// Write the book to `path`, as `peersurvey.dat` is written.
    pub fn save(&self, path: &Path, network_magic: [u8; 4]) -> Result<(), String> {
        survey::write_private_file(path, &self.encode(network_magic))
    }
}

fn encode_crawl_addr(buf: &mut Vec<u8>, addr: &CrawlAddr) {
    match addr {
        // Tags 0 and 1, as `peersurvey.dat` writes them.
        CrawlAddr::Peer(peer) => survey::encode_addr(buf, peer),
        CrawlAddr::I2p { dest, port } => {
            buf.push(2);
            buf.extend_from_slice(dest);
            buf.extend_from_slice(&port.to_le_bytes());
        }
        CrawlAddr::Cjdns { ip, port } => {
            buf.push(3);
            buf.extend_from_slice(&ip.octets());
            buf.extend_from_slice(&port.to_le_bytes());
        }
    }
}

fn decode_crawl_addr(r: &mut Reader) -> Result<CrawlAddr, String> {
    match r.0.first() {
        Some(0 | 1) => Ok(CrawlAddr::Peer(survey::decode_addr(r)?)),
        Some(2) => {
            r.u8()?;
            let dest: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
            Ok(CrawlAddr::I2p { dest, port: r.u16()? })
        }
        Some(3) => {
            r.u8()?;
            let octets: [u8; 16] = r.take(16)?.try_into().expect("16 bytes");
            if octets[0] != 0xfc {
                return Err("bad CJDNS address".to_string());
            }
            Ok(CrawlAddr::Cjdns { ip: Ipv6Addr::from(octets), port: r.u16()? })
        }
        Some(t) => Err(format!("bad address type {t}")),
        None => Err("file truncated".to_string()),
    }
}

fn put_opt_u64(buf: &mut Vec<u8>, v: Option<u64>) {
    buf.push(u8::from(v.is_some()));
    buf.extend_from_slice(&v.unwrap_or(0).to_le_bytes());
}

fn get_opt_u64(r: &mut Reader) -> Result<Option<u64>, String> {
    let present = get_flag(r)?;
    let v = r.u64()?;
    Ok(present.then_some(v))
}

fn put_opt_bool(buf: &mut Vec<u8>, v: Option<bool>) {
    buf.push(match v {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    });
}

fn get_opt_bool(r: &mut Reader) -> Result<Option<bool>, String> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(false)),
        2 => Ok(Some(true)),
        b => Err(format!("bad optional flag {b}")),
    }
}

fn get_flag(r: &mut Reader) -> Result<bool, String> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        b => Err(format!("bad flag {b}")),
    }
}

fn encode_entry(buf: &mut Vec<u8>, e: &CrawlEntry) {
    buf.extend_from_slice(&e.first_learned.to_le_bytes());
    buf.extend_from_slice(&e.last_named.to_le_bytes());
    buf.push(e.sources.len() as u8);
    for s in &e.sources {
        buf.extend_from_slice(&s.to_le_bytes());
    }
    buf.extend_from_slice(&e.advertised_services.to_le_bytes());
    buf.extend_from_slice(&e.best_time.to_le_bytes());
    buf.extend_from_slice(&e.attempts.to_le_bytes());
    put_opt_u64(buf, e.last_attempt);
    put_opt_u64(buf, e.last_success);
    put_opt_u64(buf, e.last_discovery);
    put_opt_u64(buf, e.last_v1_check);
    buf.extend_from_slice(&e.failures.to_le_bytes());
    put_opt_u64(buf, e.failing_since);
    put_opt_u64(buf, e.retry_at);
    put_opt_bool(buf, e.v2_ok);
    put_opt_bool(buf, e.v1_ok);
    put_opt_u64(buf, e.last_v2_ok);
    put_opt_u64(buf, e.last_v1_fail);
    buf.push(u8::from(e.v2_only));
    buf.extend_from_slice(&e.reachable_count.to_le_bytes());
    put_opt_u64(buf, e.first_reachable);
    match &e.observation {
        None => buf.push(0),
        Some(o) => {
            buf.push(1);
            encode_observation(buf, o);
        }
    }
}

fn decode_entry(r: &mut Reader) -> Result<CrawlEntry, String> {
    let first_learned = r.u64()?;
    let last_named = r.u64()?;
    let n = usize::from(r.u8()?);
    if n > MAX_SOURCES {
        return Err(format!("{n} sources"));
    }
    let mut sources = Vec::with_capacity(n);
    for _ in 0..n {
        sources.push(r.u64()?);
    }
    Ok(CrawlEntry {
        first_learned,
        last_named,
        sources,
        advertised_services: r.u64()?,
        best_time: r.u32()?,
        attempts: r.u32()?,
        last_attempt: get_opt_u64(r)?,
        last_success: get_opt_u64(r)?,
        last_discovery: get_opt_u64(r)?,
        last_v1_check: get_opt_u64(r)?,
        failures: r.u32()?,
        failing_since: get_opt_u64(r)?,
        retry_at: get_opt_u64(r)?,
        in_flight: None,
        sessions: 0,
        v2_ok: get_opt_bool(r)?,
        v1_ok: get_opt_bool(r)?,
        last_v2_ok: get_opt_u64(r)?,
        last_v1_fail: get_opt_u64(r)?,
        v2_only: get_flag(r)?,
        reachable_count: r.u32()?,
        first_reachable: get_opt_u64(r)?,
        observation: if get_flag(r)? { Some(decode_observation(r)?) } else { None },
    })
}

fn encode_observation(buf: &mut Vec<u8>, o: &Observation) {
    buf.extend_from_slice(&o.at.to_le_bytes());
    survey::encode_fingerprint(buf, o.fingerprint);
    let ua = o.user_agent.as_bytes();
    let ua = &ua[..ua.len().min(crate::MAX_SUBVERSION_LENGTH)];
    buf.extend_from_slice(&(ua.len() as u16).to_le_bytes());
    buf.extend_from_slice(ua);
    buf.extend_from_slice(&o.protocol_version.to_le_bytes());
    buf.extend_from_slice(&o.services.to_le_bytes());
    buf.push(u8::from(o.asn.is_some()));
    buf.extend_from_slice(&o.asn.unwrap_or(0).to_le_bytes());
    for p in Probe::ALL {
        let (code, value) = o.probes.get(p).map_or((0, 0), ProbeOutcome::code);
        buf.push(code);
        buf.extend_from_slice(&value.to_le_bytes());
    }
    buf.push(u8::from(o.v2));
    buf.extend_from_slice(&o.height.to_le_bytes());
    buf.extend_from_slice(&o.our_height.to_le_bytes());
    buf.push(o.chain_check.map_or(0, |c| 1 + ChainCheck::ALL.iter().position(|x| *x == c).expect("in ALL") as u8));
    buf.push(u8::from(o.clock_offset_secs.is_some()));
    buf.extend_from_slice(&o.clock_offset_secs.unwrap_or(0).to_le_bytes());
    buf.push(u8::from(o.handshake_rtt_ms.is_some()));
    buf.extend_from_slice(&o.handshake_rtt_ms.unwrap_or(0).to_le_bytes());
    let (tag, entries, delay) = match o.getaddr {
        None => (0, 0, 0),
        Some(GetaddrResult::NoAnswer) => (1, 0, 0),
        Some(GetaddrResult::Answered { entries, delay_ms }) => (2, entries, delay_ms),
    };
    buf.push(tag);
    buf.extend_from_slice(&entries.to_le_bytes());
    buf.extend_from_slice(&delay.to_le_bytes());
    buf.push(u8::from(o.shape.is_some()));
    if let Some(shape) = &o.shape {
        encode_shape(buf, shape);
    }
}

fn encode_shape(buf: &mut Vec<u8>, s: &UnknownShape) {
    let commands = &s.commands[..s.commands.len().min(crate::net::behavior::HANDSHAKE_CAPTURE_MAX)];
    buf.push(commands.len() as u8);
    for c in commands {
        let b = c.as_bytes();
        let b = &b[..b.len().min(SHAPE_COMMAND_LEN)];
        buf.push(b.len() as u8);
        buf.extend_from_slice(b);
    }
    buf.push(u8::from(s.relay));
    buf.push(u8::from(s.v2.is_some()));
    let g = s.v2.unwrap_or_default();
    buf.extend_from_slice(&g.garbage_len.to_le_bytes());
    buf.extend_from_slice(&g.decoys.to_le_bytes());
    buf.extend_from_slice(&g.version_len.to_le_bytes());
    buf.push(match s.getaddr {
        None => 0,
        Some(AddrKind::Addr) => 1,
        Some(AddrKind::AddrV2) => 2,
    });
}

fn decode_shape(r: &mut Reader) -> Result<UnknownShape, String> {
    let n = usize::from(r.u8()?);
    if n > crate::net::behavior::HANDSHAKE_CAPTURE_MAX {
        return Err(format!("shape of {n} commands"));
    }
    let mut commands = Vec::with_capacity(n);
    for _ in 0..n {
        let len = usize::from(r.u8()?);
        if len > SHAPE_COMMAND_LEN {
            return Err(format!("shape command of {len} bytes"));
        }
        let text: String =
            r.take(len)?.iter().map(|b| if b.is_ascii_graphic() { char::from(*b) } else { '?' }).collect();
        commands.push(text);
    }
    let relay = get_flag(r)?;
    let has_v2 = get_flag(r)?;
    let garbage_len = r.u16()?;
    let decoys = r.u32()?;
    let version_len = r.u32()?;
    let v2 = has_v2.then_some(V2Greeting { garbage_len, decoys, version_len });
    let getaddr = match r.u8()? {
        0 => None,
        1 => Some(AddrKind::Addr),
        2 => Some(AddrKind::AddrV2),
        k => return Err(format!("bad getaddr kind {k}")),
    };
    Ok(UnknownShape { commands, relay, v2, getaddr })
}

fn decode_observation(r: &mut Reader) -> Result<Observation, String> {
    let at = r.u64()?;
    let fingerprint = survey::decode_fingerprint(r)?;
    let ua_len = usize::from(r.u16()?);
    let user_agent = crate::net::limits::sanitize_string(&String::from_utf8_lossy(r.take(ua_len)?));
    let protocol_version = r.u32()?;
    let services = r.u64()?;
    let has_asn = get_flag(r)?;
    let asn = Some(r.u32()?).filter(|_| has_asn);
    let mut probes = ProbeResults::default();
    for p in Probe::ALL {
        let code = r.u8()?;
        let value = r.u32()?;
        if let Some(o) = ProbeOutcome::from_code(code, value)? {
            probes.set(p, o);
        }
    }
    let v2 = get_flag(r)?;
    let height = i32::from_le_bytes(r.take(4)?.try_into().expect("4 bytes"));
    let our_height = r.u32()?;
    let chain_check = match r.u8()? {
        0 => None,
        c => Some(*ChainCheck::ALL.get(usize::from(c) - 1).ok_or_else(|| format!("bad chain check {c}"))?),
    };
    let has_offset = get_flag(r)?;
    let offset = i64::from_le_bytes(r.take(8)?.try_into().expect("8 bytes"));
    let has_rtt = get_flag(r)?;
    let rtt = r.u32()?;
    let tag = r.u8()?;
    let entries = r.u32()?;
    let delay_ms = r.u32()?;
    let getaddr = match tag {
        0 => None,
        1 => Some(GetaddrResult::NoAnswer),
        2 => Some(GetaddrResult::Answered { entries, delay_ms }),
        t => return Err(format!("bad getaddr result {t}")),
    };
    let shape = if get_flag(r)? { Some(decode_shape(r)?) } else { None };
    Ok(Observation {
        at,
        fingerprint,
        user_agent,
        protocol_version,
        services,
        asn,
        probes,
        v2,
        height,
        our_height,
        chain_check,
        clock_offset_secs: has_offset.then_some(offset),
        handshake_rtt_ms: has_rtt.then_some(rtt),
        getaddr,
        shape,
    })
}

#[cfg(test)]
#[path = "crawlbook_tests.rs"]
mod tests;
