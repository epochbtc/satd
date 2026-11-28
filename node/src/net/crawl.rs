//! The optional crawl mode (`-crawl`): its settings, its politeness limits
//! and the scheduler that holds sessions to them.
//!
//! A crawl walks the reachable network: from seeds it dials addresses, asks
//! reachable nodes for theirs (`getaddr`), and records which addresses
//! complete a handshake, in a [`CrawlBook`](crate::net::crawlbook::CrawlBook)
//! of its own. The sessions are the peer manager's (`manager_crawl.rs`); this
//! module is the pure part: the configuration, the limits with their hard
//! ceilings, the network group a target falls in, the user agent, and the
//! [`Scheduler`], which decides whether one more session may start now.
//!
//! # Limits
//!
//! | Limit | Default | Ceiling |
//! |---|---|---|
//! | Clearnet sessions open (`-crawlconcurrency`) | [`DEFAULT_CONCURRENCY`] | [`MAX_CONCURRENCY`] |
//! | Tor sessions open (`-crawltorconcurrency`) | [`DEFAULT_TOR_CONCURRENCY`] | [`MAX_CONCURRENCY`] |
//! | New sessions per second, all networks (`-crawlrate`) | [`DEFAULT_RATE`] | [`MAX_RATE`] |
//! | Sessions per target | 1 at a time | — |
//! | Sessions per network group | [`NETGROUP_CONCURRENCY`] per IPv4 `/16` or IPv6 `/32` | — |
//!
//! The ceilings hold whatever the options say: [`Limits::new`] clamps to
//! them, so no caller can lift one.
//!
//! A session's length is bounded per phase ([`Timings`]) and as a whole
//! ([`Timings::session_cap`]): the handshake and [`PASSIVE_WAIT`] for every
//! session, and at most [`Timings::discovery`] more for a discovery session's
//! `getaddr` and probes.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use crate::net::crawlbook::{ChainCheck, Network, SessionKind};
use crate::net::peer::PeerAddr;
use crate::net::survey::{PASSIVE_WAIT, PROBE_REPLY_WAIT, UNKNOWN_PROBE_WAIT};

/// `-crawlconcurrency`'s default.
pub const DEFAULT_CONCURRENCY: usize = 32;
/// `-crawltorconcurrency`'s default.
pub const DEFAULT_TOR_CONCURRENCY: usize = 8;
/// `-crawlrate`'s default: new sessions a second, all networks together.
pub const DEFAULT_RATE: u32 = 10;
/// The most sessions open on one kind of network, whatever the options say.
pub const MAX_CONCURRENCY: usize = 256;
/// The most new sessions a second, whatever the options say.
pub const MAX_RATE: u32 = 100;
/// Sessions open at once to one IPv4 `/16` or IPv6 `/32`.
pub const NETGROUP_CONCURRENCY: u32 = 2;

/// The protocol version a crawl session states: BIP 155's and BIP 339's,
/// so the peer negotiates both, and no newer feature.
pub const CRAWL_PROTOCOL_VERSION: u32 = 70016;

/// How often the book is written while the crawl runs; it is also written
/// at shutdown.
pub const SAVE_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How often the crawl seeds itself again: the DNS and fixed seeds,
/// `-crawlseed` and a sample of the address book.
pub const SEED_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How many address-book entries a seeding round reads, drawn uniformly.
pub const ADDRMAN_SAMPLE: usize = 1_000;

/// How often the scheduler looks for due addresses.
pub const TICK: Duration = Duration::from_secs(1);

/// `-crawlliveness` may not be set lower: at the default every reachable
/// target sees at most 14 sessions a day (12 liveness, a discovery and a
/// v1 recheck).
pub const MIN_LIVENESS_SECS: u64 = crate::net::crawlbook::DEFAULT_LIVENESS_SECS;

/// `-crawlmaxage` may not be set lower than an hour.
pub const MIN_MAX_AGE_SECS: u64 = 60 * 60;

/// The bounds of one session's phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timings {
    /// Reaching a clearnet target: directly, or through `-crawlproxy`
    /// from the proxy's greeting reply on (its CONNECT).
    pub connect: Duration,
    /// Reaching `-crawlproxy` itself: its TCP accept and its greeting
    /// reply, before [`Self::connect`] starts. Apart from the target's
    /// budget so that a proxy host slow to answer under load neither
    /// eats into the target's dial nor reads as a failed proxy.
    pub proxy_greeting: Duration,
    /// Reaching an onion through the proxy.
    pub tor_connect: Duration,
    /// From the connection to the peer's `verack`, the v2 key exchange
    /// included, clearnet.
    pub handshake: Duration,
    /// The same over Tor.
    pub tor_handshake: Duration,
    /// The listening after the handshake ([`PASSIVE_WAIT`]).
    pub passive: Duration,
    /// A discovery session's `getaddr` wait and probes, together.
    pub discovery: Duration,
    /// A probe's wait for its answer.
    pub probe_reply: Duration,
    /// The unknown-message probe's wait.
    pub unknown_probe: Duration,
    /// The wait for the peer to close after our close.
    pub close: Duration,
}

impl Timings {
    pub const DEFAULT: Timings = Timings {
        connect: Duration::from_secs(5),
        proxy_greeting: Duration::from_secs(15),
        tor_connect: Duration::from_secs(30),
        handshake: Duration::from_secs(5),
        tor_handshake: Duration::from_secs(30),
        passive: PASSIVE_WAIT,
        discovery: Duration::from_secs(90),
        probe_reply: PROBE_REPLY_WAIT,
        unknown_probe: UNKNOWN_PROBE_WAIT,
        close: Duration::from_secs(1),
    };

    /// The longest a session of `kind` may last, every redial included: a
    /// session still open then is closed. Each transport attempt is a dial
    /// and a handshake (two for a v2 attempt that falls back to v1), then
    /// the passive wait, then for a discovery session its `getaddr` and
    /// probes, then the close. A clearnet dial through `-crawlproxy`
    /// (`proxied`) has the proxy's greeting first.
    pub fn session_cap(&self, kind: SessionKind, tor: bool, proxied: bool) -> Duration {
        let (connect, handshake) = if tor {
            (self.tor_connect, self.tor_handshake)
        } else if proxied {
            (self.proxy_greeting + self.connect, self.handshake)
        } else {
            (self.connect, self.handshake)
        };
        let attempts = if kind == SessionKind::V1Recheck { 1 } else { 2 };
        let extra = if kind == SessionKind::Discovery {
            self.discovery
        } else {
            Duration::ZERO
        };
        (connect + handshake) * attempts + self.passive + extra + self.close
    }
}

impl Default for Timings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The concurrency and rate limits, within their ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Clearnet sessions open at once.
    pub clearnet: usize,
    /// Onion sessions open at once.
    pub tor: usize,
    /// New sessions a second.
    pub rate: u32,
}

impl Limits {
    /// The limits asked for, each clamped to its ceiling.
    pub fn new(clearnet: usize, tor: usize, rate: u32) -> Self {
        Limits {
            clearnet: clearnet.min(MAX_CONCURRENCY),
            tor: tor.min(MAX_CONCURRENCY),
            rate: rate.min(MAX_RATE),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits::new(DEFAULT_CONCURRENCY, DEFAULT_TOR_CONCURRENCY, DEFAULT_RATE)
    }
}

/// `-crawl` and its options, as the peer manager runs them.
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    pub limits: Limits,
    /// `-crawlliveness`, seconds.
    pub liveness_secs: u64,
    /// `-crawlmaxage`, seconds.
    pub max_age_secs: u64,
    /// `-crawlnet`: the networks the crawl may dial, within those the node
    /// reaches. `None` is every one the node reaches.
    pub networks: Option<Vec<Network>>,
    /// `-crawlbind`: the source address of direct IPv4 and IPv6 dials.
    pub bind_v4: Option<Ipv4Addr>,
    pub bind_v6: Option<Ipv6Addr>,
    /// `-crawlproxy`: a SOCKS5 proxy (no authentication) every IPv4 and
    /// IPv6 crawl dial goes through, `-crawlbind` not applying. Onion dials
    /// keep `-onion`/`-proxy`.
    pub proxy: Option<std::net::SocketAddr>,
    /// `-crawlseed`.
    pub seeds: Vec<PeerAddr>,
    /// `-crawluacomment`.
    pub ua_comment: Option<String>,
    /// `-crawlprobes`.
    pub probes: bool,
    /// Seed from the DNS seeds (`-dns` and `-dnsseed`), through the proxy's
    /// onion seeds when the node uses one.
    pub dns_seeds: bool,
    /// Seed from the fixed seeds (`-fixedseeds`).
    pub fixed_seeds: bool,
    /// `-signetseednode`, for the DNS seeding round on signet.
    pub signet_seeds: Vec<String>,
    /// Where the book is kept (`crawlbook.dat`); `None` keeps it in memory.
    pub path: Option<PathBuf>,
    /// Where the hourly snapshots go (`crawl/`); `None` writes none.
    pub snapshot_dir: Option<PathBuf>,
    /// The keyed export's key: `crawlexport.key`, or
    /// `-crawlexportkeyfile`. `None` refuses keyed exports.
    pub export_key: Option<crate::net::crawlsnapshot::KeySource>,
    /// `-crawlexportmink`.
    pub export_min_k: u32,
    pub timings: Timings,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        CrawlConfig {
            limits: Limits::default(),
            liveness_secs: crate::net::crawlbook::DEFAULT_LIVENESS_SECS,
            max_age_secs: crate::net::crawlbook::DEFAULT_MAX_AGE_SECS,
            networks: None,
            bind_v4: None,
            bind_v6: None,
            proxy: None,
            seeds: Vec::new(),
            ua_comment: None,
            probes: true,
            dns_seeds: true,
            fixed_seeds: true,
            signet_seeds: Vec::new(),
            path: None,
            snapshot_dir: None,
            export_key: None,
            export_min_k: crate::net::crawlsnapshot::DEFAULT_EXPORT_MIN_K,
            timings: Timings::DEFAULT,
        }
    }
}

/// The user agent a crawl session states: `/satd:<version>(crawler)/`, with
/// `-crawluacomment` as a second BIP 14 comment. The node's own
/// `-uacomment` is never in it.
pub fn user_agent(comment: Option<&str>) -> Result<String, String> {
    let mut comments = vec!["crawler".to_string()];
    comments.extend(comment.map(str::to_string));
    crate::format_user_agent(&comments)
}

/// Parse a `-crawlnet` value. I2P and CJDNS are refused: the crawl records
/// them as learned and never dials them.
pub fn parse_network(s: &str) -> Result<Network, String> {
    match s.to_ascii_lowercase().as_str() {
        "ipv4" => Ok(Network::Ipv4),
        "ipv6" => Ok(Network::Ipv6),
        "onion" => Ok(Network::Onion),
        "i2p" | "cjdns" => Err(format!(
            "-crawlnet={s}: the crawl never dials {s} addresses"
        )),
        _ => Err(format!(
            "-crawlnet={s}: unknown network (ipv4, ipv6 or onion)"
        )),
    }
}

/// The network a dialable address is on.
pub fn network_of(addr: &PeerAddr) -> Network {
    match addr {
        PeerAddr::Onion { .. } => Network::Onion,
        PeerAddr::Socket(sa) => match sa.ip().to_canonical() {
            IpAddr::V4(_) => Network::Ipv4,
            IpAddr::V6(_) => Network::Ipv6,
        },
    }
}

/// The group the per-group limit counts a target in: its IPv4 `/16` or
/// IPv6 `/32`. An onion is in none: its address says nothing about who
/// hosts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Netgroup {
    V4([u8; 2]),
    V6([u8; 4]),
}

pub fn netgroup(addr: &PeerAddr) -> Option<Netgroup> {
    let PeerAddr::Socket(sa) = addr else {
        return None;
    };
    Some(match sa.ip().to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Netgroup::V4([o[0], o[1]])
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            Netgroup::V6([o[0], o[1], o[2], o[3]])
        }
    })
}

/// Why the scheduler would not start a session now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A session to the target is open.
    TargetBusy,
    /// Every session of the target's kind of network is taken.
    Concurrency,
    /// The target's network group has its sessions.
    Netgroup,
    /// The rate allows no new session yet.
    Rate,
}

/// The sessions open and the rate's budget.
///
/// Every start goes through [`Self::try_start`], every end through
/// [`Self::finish`]. The rate is a token bucket that holds a second's
/// worth of sessions and refills continuously; time is passed in, in
/// milliseconds on any monotonic clock.
#[derive(Debug)]
pub struct Scheduler {
    limits: Limits,
    open: HashMap<PeerAddr, Option<Netgroup>>,
    groups: HashMap<Netgroup, u32>,
    clearnet: usize,
    tor: usize,
    /// Thousandths of a session.
    tokens: u64,
    last_ms: u64,
}

impl Scheduler {
    pub fn new(limits: Limits, now_ms: u64) -> Self {
        let limits = Limits::new(limits.clearnet, limits.tor, limits.rate);
        Scheduler {
            limits,
            open: HashMap::new(),
            groups: HashMap::new(),
            clearnet: 0,
            tor: 0,
            tokens: u64::from(limits.rate) * 1000,
            last_ms: now_ms,
        }
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    fn refill(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.last_ms);
        self.last_ms = self.last_ms.max(now_ms);
        let cap = u64::from(self.limits.rate) * 1000;
        self.tokens = (self.tokens + elapsed.saturating_mul(u64::from(self.limits.rate))).min(cap);
    }

    /// Whether a session to `addr` may start at `now_ms`, without starting
    /// it. The rate is checked last.
    pub fn check(&mut self, addr: &PeerAddr, now_ms: u64) -> Result<(), Refusal> {
        if self.open.contains_key(addr) {
            return Err(Refusal::TargetBusy);
        }
        let (open, limit) = if addr.is_onion() {
            (self.tor, self.limits.tor)
        } else {
            (self.clearnet, self.limits.clearnet)
        };
        if open >= limit {
            return Err(Refusal::Concurrency);
        }
        if let Some(g) = netgroup(addr)
            && self.groups.get(&g).copied().unwrap_or(0) >= NETGROUP_CONCURRENCY
        {
            return Err(Refusal::Netgroup);
        }
        self.refill(now_ms);
        if self.tokens < 1000 {
            return Err(Refusal::Rate);
        }
        Ok(())
    }

    /// Start a session to `addr` if [`Self::check`] allows it.
    pub fn try_start(&mut self, addr: &PeerAddr, now_ms: u64) -> Result<(), Refusal> {
        self.check(addr, now_ms)?;
        self.tokens -= 1000;
        let group = netgroup(addr);
        if let Some(g) = group {
            *self.groups.entry(g).or_default() += 1;
        }
        if addr.is_onion() {
            self.tor += 1;
        } else {
            self.clearnet += 1;
        }
        self.open.insert(addr.clone(), group);
        Ok(())
    }

    /// The session to `addr` ended.
    pub fn finish(&mut self, addr: &PeerAddr) {
        let Some(group) = self.open.remove(addr) else {
            return;
        };
        if let Some(g) = group
            && let Some(n) = self.groups.get_mut(&g)
        {
            *n -= 1;
            if *n == 0 {
                self.groups.remove(&g);
            }
        }
        if addr.is_onion() {
            self.tor -= 1;
        } else {
            self.clearnet -= 1;
        }
    }

    /// Sessions open: clearnet, then Tor.
    pub fn open(&self) -> (usize, usize) {
        (self.clearnet, self.tor)
    }

    /// Whether any session could start on either kind of network, the
    /// rate aside.
    pub fn has_room(&self) -> bool {
        self.clearnet < self.limits.clearnet || self.tor < self.limits.tor
    }

    /// Whole sessions the rate allows now.
    pub fn budget(&mut self, now_ms: u64) -> usize {
        self.refill(now_ms);
        (self.tokens / 1000) as usize
    }
}

// ---- The chain check ----

/// Where a block stands on our side, for the chain check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OurBlock {
    /// On our active chain, at this height.
    Active(u32),
    /// Known to us, off our active chain.
    Stale,
    /// Not a block we know.
    Unknown,
}

/// The chain check: what the answer to the `getheaders` probe says of the
/// peer's chain. The probe's locator is `locator`, a recent block of our
/// active chain at `locator_height`, and its stop hash `stop`, the block
/// after it; `peer_height` is the peer's `start_height`. `ours` places a
/// block hash on our side. It is asked about two hashes at most, so the
/// check costs a few index reads whatever the answer holds.
///
/// A node answers with the headers after the last locator block on its
/// active chain, up to the stop hash, and with the headers from its genesis
/// when it has none of them (Core's `FindForkInGlobalIndex`):
///
/// - no header: it has our locator's block and nothing past it, so it is
///   behind (by a block);
/// - a header after our locator: our stop block is on chain, another one a
///   fork;
/// - headers from a block of ours below our locator: it does not have our
///   locator's block on its chain. If its headers end on our active chain
///   it is behind, unless the answer was a full one
///   ([`MAX_HEADERS_RESULTS`](crate::net::limits::MAX_HEADERS_RESULTS)) and
///   it states a height of at least our locator's: then its chain leaves
///   ours past what it showed, a fork. If they leave our chain, a fork;
/// - headers from a block we hold off our chain: a fork;
/// - headers from a block we do not know: another chain under this
///   network's magic (its genesis is not ours).
pub fn chain_check(
    locator: &bitcoin::BlockHash,
    locator_height: u32,
    stop: &bitcoin::BlockHash,
    headers: &[bitcoin::block::Header],
    peer_height: i32,
    ours: impl Fn(&bitcoin::BlockHash) -> OurBlock,
) -> ChainCheck {
    let Some(first) = headers.first() else {
        return ChainCheck::Behind;
    };
    if first.prev_blockhash == *locator {
        return if first.block_hash() == *stop {
            ChainCheck::OnChain
        } else {
            ChainCheck::Fork
        };
    }
    // An answer may start with a genesis header itself (no parent): judge
    // it by the genesis, which is ours or another chain's.
    let anchor =
        if first.prev_blockhash == <bitcoin::BlockHash as bitcoin::hashes::Hash>::all_zeros() {
            first.block_hash()
        } else {
            first.prev_blockhash
        };
    match ours(&anchor) {
        OurBlock::Unknown => ChainCheck::OtherChain,
        OurBlock::Stale => ChainCheck::Fork,
        // Past our locator on our chain: it has the locator's block.
        OurBlock::Active(h) if h >= locator_height => ChainCheck::OnChain,
        OurBlock::Active(_) => {
            // The last header that links to the one before it.
            let mut last = first;
            for h in &headers[1..] {
                if h.prev_blockhash != last.block_hash() {
                    break;
                }
                last = h;
            }
            match ours(&last.block_hash()) {
                OurBlock::Active(_)
                    if headers.len() >= crate::net::limits::MAX_HEADERS_RESULTS
                        && i64::from(peer_height) >= i64::from(locator_height) =>
                {
                    ChainCheck::Fork
                }
                OurBlock::Active(_) => ChainCheck::Behind,
                OurBlock::Stale | OurBlock::Unknown => ChainCheck::Fork,
            }
        }
    }
}

#[cfg(test)]
#[path = "crawl_tests.rs"]
mod tests;
