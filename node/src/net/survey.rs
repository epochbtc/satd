//! The network survey (`-peersurvey`): which implementations are reachable.
//!
//! With the survey on, the node opens one extra outbound connection at a
//! time, every `-peersurveyinterval`, to an address drawn uniformly from the
//! address book. The connection completes the handshake a full-relay
//! outbound would, listens for up to [`PASSIVE_WAIT`] while the peer
//! announces what it supports, optionally sends a few [`Probe`]s, and
//! closes. What the peer showed is kept here, one [`SurveyRecord`] per
//! address, and written to [`SURVEY_FILE`] in the data directory.
//!
//! This module is the pure part: the records, their store and file, the
//! aggregate `getpeersurvey` reports, and the probe messages. The connection
//! itself is the peer manager's.
//!
//! The file holds peer addresses. It is written with the data directory's
//! permissions (execute bits dropped), and only the RPC, behind its
//! authentication, reads it back.

use std::collections::HashMap;
use std::io::Write as _;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::p2p::message::{CommandString, NetworkMessage};
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::BlockHash;
use rand::seq::SliceRandom as _;
use rand::Rng;

use crate::net::fingerprint::{Confidence, Family, Fingerprint};
use crate::net::peer::PeerAddr;

/// The file's name in the network data directory.
pub const SURVEY_FILE: &str = "peersurvey.dat";

/// The most records kept; past it the least recently seen goes first.
pub const MAX_RECORDS: usize = 250_000;

/// A record not seen again for this long is dropped.
pub const EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;

/// `-peersurveyinterval`'s default, seconds.
pub const DEFAULT_INTERVAL_SECS: u64 = 60;

/// How long a survey connection listens after the handshake for the
/// peer's announcements, unless its transcript closes first. The same as
/// the classifier's settle time, so a peer that announces nothing (btcd
/// when we dial it) has shown its whole shape by then.
pub const PASSIVE_WAIT: Duration = Duration::from_secs(crate::net::fingerprint::SETTLE_SECS);

/// How long a probe waits for its answer.
pub const PROBE_REPLY_WAIT: Duration = Duration::from_secs(5);

/// How long the unknown-message probe waits to see whether the peer
/// closes the connection over it. It expects no answer.
pub const UNKNOWN_PROBE_WAIT: Duration = Duration::from_secs(2);

/// How often the store is written while the survey runs; it is also
/// written at shutdown.
pub const SAVE_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How many autonomous systems the aggregate lists.
pub const TOP_AS: usize = 10;

const FILE_MAGIC: [u8; 8] = *b"satdsrv1";

/// A message sent on a survey connection after the passive wait, to tell
/// apart implementations whose handshakes look alike. Each was checked
/// against Bitcoin Core v32.1 (the pinned Core) for no misbehaviour and no
/// disconnect: `satd/tests/core_survey_probes.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Probe {
    /// `ping` with a random nonce: the `pong`'s round trip.
    Ping,
    /// `getheaders` with a one-hash locator and a stop hash one block on:
    /// how many headers come back.
    GetHeaders,
    /// `getdata` for a random transaction the peer cannot have: Core
    /// answers `notfound` (`ProcessGetData`, v32.1
    /// `src/net_processing.cpp:2796`); some clients stay silent.
    GetData,
    /// A message type nobody defines: Core logs it and reads on (v32.1
    /// `src/net_processing.cpp:5360`).
    Unknown,
}

impl Probe {
    pub const ALL: [Probe; 4] = [Probe::Ping, Probe::GetHeaders, Probe::GetData, Probe::Unknown];

    pub fn name(self) -> &'static str {
        match self {
            Probe::Ping => "ping",
            Probe::GetHeaders => "getheaders",
            Probe::GetData => "getdata",
            Probe::Unknown => "unknown",
        }
    }

    fn index(self) -> usize {
        Probe::ALL.iter().position(|p| *p == self).expect("every probe is in ALL")
    }
}

/// A random subset of the probes, in random order: each is in it with
/// even odds, so a survey connection does not always send the same
/// sequence.
pub fn choose_probes(rng: &mut impl Rng) -> Vec<Probe> {
    let mut chosen: Vec<Probe> = Probe::ALL.into_iter().filter(|_| rng.gen_bool(0.5)).collect();
    chosen.shuffle(rng);
    chosen
}

/// Every message type Core v32.1 or satd reads (Core's
/// `ALL_NET_MESSAGE_TYPES`, `src/protocol.h`, and the older ones satd
/// still names). An unknown-message probe never uses one.
const KNOWN_COMMANDS: &[&str] = &[
    "version", "verack", "addr", "addrv2", "sendaddrv2", "inv", "getdata", "merkleblock", "getblocks",
    "getheaders", "tx", "headers", "block", "getaddr", "mempool", "ping", "pong", "notfound", "filterload",
    "filteradd", "filterclear", "sendheaders", "feefilter", "sendcmpct", "cmpctblock", "getblocktxn",
    "blocktxn", "getcfilters", "cfilter", "getcfheaders", "cfheaders", "getcfcheckpt", "cfcheckpt",
    "wtxidrelay", "sendtxrcncl", "reject", "alert", "getnapatt", "napatt",
];

/// What the probes of one connection send: drawn once per connection.
#[derive(Debug, Clone)]
pub struct ProbeContext {
    /// The `ping` nonce.
    pub nonce: u64,
    /// The `getheaders` locator: one block hash of our active chain.
    pub locator: BlockHash,
    /// The `getheaders` stop hash: the block after [`Self::locator`]. At
    /// the genesis tip there is none and the probe is not sent.
    pub stop: BlockHash,
    /// The transaction asked for: random, so no peer has it.
    pub txid: [u8; 32],
    /// Ask by wtxid (`MSG_WTX`), as to a peer that sent `wtxidrelay`.
    pub wtxid_relay: bool,
    /// The unknown message's type: random lowercase letters.
    pub unknown_command: CommandString,
}

impl ProbeContext {
    pub fn new(rng: &mut impl Rng, locator: BlockHash, stop: BlockHash, wtxid_relay: bool) -> Self {
        let mut txid = [0u8; 32];
        rng.fill(&mut txid[..]);
        ProbeContext { nonce: rng.r#gen(), locator, stop, txid, wtxid_relay, unknown_command: unknown_command(rng) }
    }
}

/// A message type of six to eleven random lowercase letters that no one
/// defines.
pub fn unknown_command(rng: &mut impl Rng) -> CommandString {
    loop {
        let len = rng.gen_range(6..=11);
        let s: String = (0..len).map(|_| char::from(rng.gen_range(b'a'..=b'z'))).collect();
        if !KNOWN_COMMANDS.contains(&s.as_str()) {
            return CommandString::try_from(s).expect("at most 12 ASCII letters");
        }
    }
}

/// The message `probe` sends.
pub fn probe_message(probe: Probe, ctx: &ProbeContext) -> NetworkMessage {
    match probe {
        Probe::Ping => NetworkMessage::Ping(ctx.nonce),
        // Built as every `getheaders` the node sends is (`sync`).
        Probe::GetHeaders => NetworkMessage::GetHeaders(GetHeadersMessage::new(vec![ctx.locator], ctx.stop)),
        Probe::GetData => NetworkMessage::GetData(vec![probe_inventory(ctx)]),
        Probe::Unknown => NetworkMessage::Unknown { command: ctx.unknown_command.clone(), payload: Vec::new() },
    }
}

/// The inventory the `getdata` probe asks for.
pub fn probe_inventory(ctx: &ProbeContext) -> Inventory {
    if ctx.wtxid_relay {
        Inventory::WTx(bitcoin::Wtxid::from_byte_array(ctx.txid))
    } else {
        Inventory::Transaction(bitcoin::Txid::from_byte_array(ctx.txid))
    }
}

/// How one probe went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Its answer came: for `ping` the round trip in milliseconds, for
    /// `getheaders` the number of headers, for `getdata` the number of
    /// `notfound` entries naming our transaction.
    Answered(u32),
    /// No answer within the wait, and the connection stayed open. The
    /// expected outcome of the unknown-message probe.
    Silent,
    /// The peer closed the connection while the probe waited.
    Disconnected,
}

impl ProbeOutcome {
    fn code(self) -> (u8, u32) {
        match self {
            ProbeOutcome::Answered(v) => (1, v),
            ProbeOutcome::Silent => (2, 0),
            ProbeOutcome::Disconnected => (3, 0),
        }
    }

    fn from_code(code: u8, value: u32) -> Result<Option<Self>, String> {
        Ok(match code {
            0 => None,
            1 => Some(ProbeOutcome::Answered(value)),
            2 => Some(ProbeOutcome::Silent),
            3 => Some(ProbeOutcome::Disconnected),
            c => return Err(format!("bad probe outcome {c}")),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            ProbeOutcome::Answered(_) => "answered",
            ProbeOutcome::Silent => "silent",
            ProbeOutcome::Disconnected => "disconnected",
        }
    }
}

/// Each probe's outcome on the last survey of an address; `None` where it
/// was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProbeResults([Option<ProbeOutcome>; 4]);

impl ProbeResults {
    pub fn set(&mut self, probe: Probe, outcome: ProbeOutcome) {
        self.0[probe.index()] = Some(outcome);
    }

    pub fn get(&self, probe: Probe) -> Option<ProbeOutcome> {
        self.0[probe.index()]
    }

    pub fn any(&self) -> bool {
        self.0.iter().any(Option::is_some)
    }
}

/// What one survey connection learned about an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurveyRecord {
    pub fingerprint: Fingerprint,
    /// The user agent, sanitized as `getpeerinfo.subver` is. Peer text.
    pub user_agent: String,
    pub protocol_version: u32,
    pub services: u64,
    /// The connection ran over BIP 324.
    pub v2: bool,
    /// The address's autonomous system under `-asmap`; `None` without one,
    /// or for an onion.
    pub asn: Option<u32>,
    /// Unix seconds.
    pub first_seen: u64,
    pub last_seen: u64,
    pub probes: ProbeResults,
}

/// `getpeersurvey`'s aggregate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Aggregate {
    /// Records counted.
    pub addresses: usize,
    /// Records per observed family; [`Family::ALL`]'s order.
    pub families: [usize; Family::ALL.len()],
    /// Records whose handshake matched no family.
    pub unknown: usize,
    /// Records whose user agent names one family and handshake another.
    pub mismatches: usize,
    /// Records reached over BIP 324.
    pub v2: usize,
    /// The autonomous systems with the most records, most first, at most
    /// [`TOP_AS`].
    pub top_as: Vec<(u32, usize)>,
    /// Records that carry at least one probe outcome.
    pub probed: usize,
}

/// The survey's records, one per address.
#[derive(Debug, Clone)]
pub struct SurveyStore {
    records: HashMap<PeerAddr, SurveyRecord>,
    max_records: usize,
}

impl Default for SurveyStore {
    fn default() -> Self {
        Self::with_limit(MAX_RECORDS)
    }
}

impl SurveyStore {
    /// An empty store that keeps at most `max_records`.
    pub fn with_limit(max_records: usize) -> Self {
        SurveyStore { records: HashMap::new(), max_records }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, addr: &PeerAddr) -> Option<&SurveyRecord> {
        self.records.get(addr)
    }

    /// Record a survey of `addr`. An address seen before keeps its
    /// `first_seen`. Expired records go, then the least recently seen until
    /// the store is within its limit.
    pub fn insert(&mut self, addr: PeerAddr, mut record: SurveyRecord, now: u64) {
        if let Some(old) = self.records.get(&addr) {
            record.first_seen = old.first_seen.min(record.first_seen);
        }
        self.records.insert(addr, record);
        self.expire(now);
        self.evict_to_limit();
    }

    /// Drop the records not seen for [`EXPIRY_SECS`].
    pub fn expire(&mut self, now: u64) {
        let cutoff = now.saturating_sub(EXPIRY_SECS);
        self.records.retain(|_, r| r.last_seen >= cutoff);
    }

    fn evict_to_limit(&mut self) {
        let excess = self.records.len().saturating_sub(self.max_records);
        if excess == 0 {
            return;
        }
        // Least recently seen first; the address breaks a tie, so which
        // goes does not depend on the map's order.
        let mut by_age: Vec<(u64, &PeerAddr)> = self.records.iter().map(|(a, r)| (r.last_seen, a)).collect();
        by_age.sort_unstable();
        let gone: Vec<PeerAddr> = by_age.into_iter().take(excess).map(|(_, a)| a.clone()).collect();
        for addr in gone {
            self.records.remove(&addr);
        }
    }

    /// Every record, by address.
    pub fn rows(&self) -> impl Iterator<Item = (&PeerAddr, &SurveyRecord)> {
        self.records.iter()
    }

    pub fn aggregate(&self) -> Aggregate {
        let mut agg = Aggregate { addresses: self.records.len(), ..Aggregate::default() };
        let mut by_as: HashMap<u32, usize> = HashMap::new();
        for r in self.records.values() {
            match r.fingerprint.observed() {
                Some(f) => agg.families[family_index(f)] += 1,
                None => agg.unknown += 1,
            }
            if matches!(r.fingerprint, Fingerprint::Mismatch { .. }) {
                agg.mismatches += 1;
            }
            if r.v2 {
                agg.v2 += 1;
            }
            if r.probes.any() {
                agg.probed += 1;
            }
            if let Some(asn) = r.asn {
                *by_as.entry(asn).or_default() += 1;
            }
        }
        let mut top: Vec<(u32, usize)> = by_as.into_iter().collect();
        top.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        top.truncate(TOP_AS);
        agg.top_as = top;
        agg
    }

    /// The file's bytes: a magic, the network magic, the records, then the
    /// hash256 of everything before it.
    pub fn encode(&self, network_magic: [u8; 4]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.records.len() * 100);
        buf.extend_from_slice(&FILE_MAGIC);
        buf.extend_from_slice(&network_magic);
        buf.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        let mut rows: Vec<(&PeerAddr, &SurveyRecord)> = self.records.iter().collect();
        rows.sort_unstable_by(|a, b| a.0.cmp(b.0));
        for (addr, r) in rows {
            encode_addr(&mut buf, addr);
            encode_fingerprint(&mut buf, r.fingerprint);
            let ua = r.user_agent.as_bytes();
            let ua = &ua[..ua.len().min(crate::MAX_SUBVERSION_LENGTH)];
            buf.extend_from_slice(&(ua.len() as u16).to_le_bytes());
            buf.extend_from_slice(ua);
            buf.extend_from_slice(&r.protocol_version.to_le_bytes());
            buf.extend_from_slice(&r.services.to_le_bytes());
            buf.push(u8::from(r.v2));
            buf.extend_from_slice(&r.asn.unwrap_or(0).to_le_bytes());
            buf.extend_from_slice(&r.first_seen.to_le_bytes());
            buf.extend_from_slice(&r.last_seen.to_le_bytes());
            for p in Probe::ALL {
                let (code, value) = r.probes.get(p).map_or((0, 0), ProbeOutcome::code);
                buf.push(code);
                buf.extend_from_slice(&value.to_le_bytes());
            }
        }
        let checksum = sha256d::Hash::hash(&buf);
        buf.extend_from_slice(checksum.as_byte_array());
        buf
    }

    /// Read [`Self::encode`]'s bytes, keeping at most `max_records` and
    /// dropping the expired ones as of `now`.
    pub fn decode(bytes: &[u8], network_magic: [u8; 4], now: u64, max_records: usize) -> Result<Self, String> {
        if bytes.len() < FILE_MAGIC.len() + 4 + 4 + 32 {
            return Err("file too short".to_string());
        }
        let (body, checksum) = bytes.split_at(bytes.len() - 32);
        if sha256d::Hash::hash(body).as_byte_array() != checksum {
            return Err("checksum mismatch".to_string());
        }
        let mut r = Reader(body);
        if r.take(8)? != FILE_MAGIC {
            return Err("not a survey file".to_string());
        }
        if r.take(4)? != network_magic {
            return Err("written for another network".to_string());
        }
        let count = r.u32()? as usize;
        let mut store = SurveyStore::with_limit(max_records);
        for _ in 0..count {
            let addr = decode_addr(&mut r)?;
            let fingerprint = decode_fingerprint(&mut r)?;
            let ua_len = r.u16()? as usize;
            let user_agent = crate::net::limits::sanitize_string(&String::from_utf8_lossy(r.take(ua_len)?));
            let protocol_version = r.u32()?;
            let services = r.u64()?;
            let v2 = r.u8()? != 0;
            let asn = Some(r.u32()?).filter(|a| *a != 0);
            let first_seen = r.u64()?;
            let last_seen = r.u64()?;
            let mut probes = ProbeResults::default();
            for p in Probe::ALL {
                let code = r.u8()?;
                let value = r.u32()?;
                if let Some(o) = ProbeOutcome::from_code(code, value)? {
                    probes.set(p, o);
                }
            }
            store.records.insert(
                addr,
                SurveyRecord { fingerprint, user_agent, protocol_version, services, v2, asn, first_seen, last_seen, probes },
            );
        }
        if !r.0.is_empty() {
            return Err("trailing bytes".to_string());
        }
        store.expire(now);
        store.evict_to_limit();
        Ok(store)
    }

    /// Read the store from `path`; an absent file is an empty store.
    pub fn load(path: &Path, network_magic: [u8; 4], now: u64) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(bytes) => Self::decode(&bytes, network_magic, now, MAX_RECORDS),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("reading {}: {e}", path.display())),
        }
    }

    /// Write the store to `path`, through a temporary file renamed over
    /// it. The file takes the permissions of the directory it is in, less
    /// the execute bits: it holds peer addresses, so it is never more open
    /// than the data directory.
    pub fn save(&self, path: &Path, network_magic: [u8; 4]) -> Result<(), String> {
        let buf = self.encode(network_magic);
        let tmp = path.with_extension("dat.tmp");
        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| format!("creating {}: {e}", tmp.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
                let dir_mode =
                    std::fs::metadata(dir).map_err(|e| format!("reading {}: {e}", dir.display()))?.permissions().mode();
                f.set_permissions(std::fs::Permissions::from_mode(dir_mode & 0o666))
                    .map_err(|e| format!("setting the permissions of {}: {e}", tmp.display()))?;
            }
            f.write_all(&buf).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
            f.sync_all().map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("renaming {} -> {}: {e}", tmp.display(), path.display()))
    }
}

/// The network an address is on, as `getnodeaddresses` names it.
pub fn network_name(addr: &PeerAddr) -> &'static str {
    match addr {
        PeerAddr::Onion { .. } => "onion",
        PeerAddr::Socket(sa) => match sa.ip().to_canonical() {
            IpAddr::V4(_) => "ipv4",
            IpAddr::V6(_) => "ipv6",
        },
    }
}

fn family_index(f: Family) -> usize {
    Family::ALL.iter().position(|x| *x == f).expect("every family is in ALL")
}

fn family_byte(f: Option<Family>) -> u8 {
    f.map_or(0xff, |f| family_index(f) as u8)
}

fn family_from_byte(b: u8) -> Result<Family, String> {
    Family::ALL.get(usize::from(b)).copied().ok_or_else(|| format!("bad family {b}"))
}

fn encode_fingerprint(buf: &mut Vec<u8>, fp: Fingerprint) {
    let (tag, a, b) = match fp {
        Fingerprint::Unknown => (0, None, None),
        Fingerprint::Known(f, Confidence::High) => (1, Some(f), None),
        Fingerprint::Known(f, Confidence::Low) => (2, Some(f), None),
        Fingerprint::Mismatch { claimed, observed } => (3, Some(observed), Some(claimed)),
    };
    buf.extend_from_slice(&[tag, family_byte(a), family_byte(b)]);
}

fn decode_fingerprint(r: &mut Reader) -> Result<Fingerprint, String> {
    let tag = r.u8()?;
    let a = r.u8()?;
    let b = r.u8()?;
    Ok(match tag {
        0 => Fingerprint::Unknown,
        1 => Fingerprint::Known(family_from_byte(a)?, Confidence::High),
        2 => Fingerprint::Known(family_from_byte(a)?, Confidence::Low),
        3 => Fingerprint::Mismatch { observed: family_from_byte(a)?, claimed: family_from_byte(b)? },
        t => return Err(format!("bad fingerprint tag {t}")),
    })
}

fn encode_addr(buf: &mut Vec<u8>, addr: &PeerAddr) {
    match addr {
        PeerAddr::Socket(sa) => {
            buf.push(0);
            let ip = match sa.ip() {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            buf.extend_from_slice(&ip.octets());
            buf.extend_from_slice(&sa.port().to_le_bytes());
        }
        PeerAddr::Onion { host, port } => {
            buf.push(1);
            let host = host.as_bytes();
            buf.push(host.len().min(255) as u8);
            buf.extend_from_slice(&host[..host.len().min(255)]);
            buf.extend_from_slice(&port.to_le_bytes());
        }
    }
}

fn decode_addr(r: &mut Reader) -> Result<PeerAddr, String> {
    match r.u8()? {
        0 => {
            let octets: [u8; 16] = r.take(16)?.try_into().expect("16 bytes");
            let ip = Ipv6Addr::from(octets).to_canonical();
            Ok(PeerAddr::Socket(SocketAddr::new(ip, r.u16()?)))
        }
        1 => {
            let len = usize::from(r.u8()?);
            let host = String::from_utf8(r.take(len)?.to_vec()).map_err(|_| "onion host is not UTF-8".to_string())?;
            if !host.ends_with(".onion") {
                return Err("bad onion host".to_string());
            }
            Ok(PeerAddr::Onion { host, port: r.u16()? })
        }
        t => Err(format!("bad address type {t}")),
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("file truncated".to_string());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }
}

/// `getpeersurvey`'s answer: the aggregate, and with `verbose` a row per
/// address. `completed` and `failed` count this run's survey connections.
pub fn survey_json(store: &SurveyStore, verbose: bool, settings: &serde_json::Value) -> serde_json::Value {
    let mut out = aggregate_json(&store.aggregate(), settings);
    if verbose {
        let mut rows: Vec<(&PeerAddr, &SurveyRecord)> = store.rows().collect();
        rows.sort_unstable_by(|a, b| b.1.last_seen.cmp(&a.1.last_seen).then(a.0.cmp(b.0)));
        out["peers"] = rows.into_iter().map(|(addr, r)| row_json(addr, r)).collect();
    }
    out
}

/// [`survey_json`] without the rows, from an aggregate already taken.
pub fn aggregate_json(agg: &Aggregate, settings: &serde_json::Value) -> serde_json::Value {
    let share = |n: usize| if agg.addresses == 0 { 0.0 } else { n as f64 / agg.addresses as f64 };
    let mut families = serde_json::Map::new();
    for (f, n) in Family::ALL.iter().zip(agg.families) {
        families.insert(f.name().to_string(), serde_json::json!({ "count": n, "share": share(n) }));
    }
    families.insert("unknown".to_string(), serde_json::json!({ "count": agg.unknown, "share": share(agg.unknown) }));
    let mut out = serde_json::json!({
        "addresses": agg.addresses,
        "families": families,
        "mismatches": agg.mismatches,
        "v2": { "count": agg.v2, "share": share(agg.v2) },
        "top_as": agg.top_as.iter().map(|(asn, n)| serde_json::json!({ "asn": asn, "count": n })).collect::<Vec<_>>(),
        "probed": agg.probed,
    });
    if let (Some(o), Some(s)) = (out.as_object_mut(), settings.as_object()) {
        for (k, v) in s {
            o.insert(k.clone(), v.clone());
        }
    }
    out
}

fn row_json(addr: &PeerAddr, r: &SurveyRecord) -> serde_json::Value {
    let (claimed, mismatch) = match r.fingerprint {
        Fingerprint::Mismatch { claimed, .. } => (Some(claimed.name()), true),
        _ => (None, false),
    };
    let mut probes = serde_json::Map::new();
    for p in Probe::ALL {
        if let Some(o) = r.probes.get(p) {
            let mut v = serde_json::json!({ "result": o.name() });
            if let ProbeOutcome::Answered(n) = o {
                v["value"] = serde_json::json!(n);
            }
            probes.insert(p.name().to_string(), v);
        }
    }
    let addr_text = match addr {
        PeerAddr::Socket(sa) => sa.to_string(),
        PeerAddr::Onion { host, port } => format!("{host}:{port}"),
    };
    serde_json::json!({
        "addr": addr_text,
        "network": network_name(addr),
        "fingerprint": r.fingerprint.to_string(),
        "family": r.fingerprint.observed().map(Family::name),
        "claimed": claimed.or_else(|| Family::claimed_by(&r.user_agent).map(Family::name)),
        "mismatch": mismatch,
        "subver": r.user_agent,
        "version": r.protocol_version,
        "services": format!("{:016x}", r.services),
        "v2": r.v2,
        "asn": r.asn,
        "first_seen": r.first_seen,
        "last_seen": r.last_seen,
        "probes": probes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng as _;

    const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];
    const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    const NOW: u64 = 1_790_000_000;

    fn record(fp: Fingerprint, last_seen: u64) -> SurveyRecord {
        SurveyRecord {
            fingerprint: fp,
            user_agent: "/Satoshi:32.1.0/".to_string(),
            protocol_version: 70016,
            services: 0x409,
            v2: true,
            asn: Some(64496),
            first_seen: last_seen,
            last_seen,
            probes: ProbeResults::default(),
        }
    }

    fn v4(i: u32) -> PeerAddr {
        PeerAddr::Socket(SocketAddr::from((std::net::Ipv4Addr::from(0x0a00_0000 + i), 8333)))
    }

    /// Every field survives the file, onion and IPv6 addresses included,
    /// and a record seen again keeps its first sighting.
    #[test]
    fn records_round_trip_through_the_file() {
        let mut store = SurveyStore::default();
        let mut probed = record(Fingerprint::Mismatch { claimed: Family::Core, observed: Family::Btcd }, NOW);
        probed.probes.set(Probe::Ping, ProbeOutcome::Answered(42));
        probed.probes.set(Probe::Unknown, ProbeOutcome::Disconnected);
        probed.probes.set(Probe::GetData, ProbeOutcome::Silent);
        probed.asn = None;
        store.insert(v4(1), probed, NOW);
        store.insert(
            PeerAddr::Socket("[2001:db8::1]:18333".parse().unwrap()),
            record(Fingerprint::Known(Family::Satd, Confidence::Low), NOW - 5),
            NOW,
        );
        store.insert(PeerAddr::Onion { host: ONION.to_string(), port: 8333 }, record(Fingerprint::Unknown, NOW - 9), NOW);
        let mut again = record(Fingerprint::Known(Family::Core, Confidence::High), NOW);
        again.first_seen = NOW;
        store.insert(v4(2), record(Fingerprint::Known(Family::Core, Confidence::High), NOW - 100), NOW);
        store.insert(v4(2), again, NOW);
        assert_eq!(store.get(&v4(2)).unwrap().first_seen, NOW - 100, "the first sighting is kept");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SURVEY_FILE);
        store.save(&path, MAGIC).unwrap();
        let back = SurveyStore::load(&path, MAGIC, NOW).unwrap();
        assert_eq!(back.len(), 4);
        for (addr, r) in store.rows() {
            assert_eq!(back.get(addr), Some(r), "{addr:?}");
        }
    }

    /// A damaged file, one for another network, and one that is not a
    /// survey file are refused rather than read.
    #[test]
    fn a_bad_file_is_refused() {
        let mut store = SurveyStore::default();
        store.insert(v4(1), record(Fingerprint::Unknown, NOW), NOW);
        let bytes = store.encode(MAGIC);
        assert!(SurveyStore::decode(&bytes, MAGIC, NOW, MAX_RECORDS).is_ok());
        assert!(SurveyStore::decode(&bytes, [0, 1, 2, 3], NOW, MAX_RECORDS).unwrap_err().contains("another network"));
        let mut flipped = bytes.clone();
        flipped[20] ^= 1;
        assert!(SurveyStore::decode(&flipped, MAGIC, NOW, MAX_RECORDS).unwrap_err().contains("checksum"));
        assert!(SurveyStore::decode(&bytes[..10], MAGIC, NOW, MAX_RECORDS).is_err());
        let anchors = vec![0u8; 64];
        assert!(SurveyStore::decode(&anchors, MAGIC, NOW, MAX_RECORDS).is_err());
    }

    /// Past its limit the store drops the least recently seen records, and
    /// the file read back obeys the limit too.
    #[test]
    fn the_store_is_bounded_least_recently_seen_first() {
        let mut store = SurveyStore::with_limit(3);
        for i in 0..5 {
            store.insert(v4(i), record(Fingerprint::Unknown, NOW - 100 + u64::from(i)), NOW);
        }
        assert_eq!(store.len(), 3);
        assert!(store.get(&v4(0)).is_none() && store.get(&v4(1)).is_none(), "the two oldest went");
        // Seen again, the oldest survivor becomes the newest.
        store.insert(v4(2), record(Fingerprint::Unknown, NOW), NOW);
        store.insert(v4(9), record(Fingerprint::Unknown, NOW - 1), NOW);
        assert!(store.get(&v4(2)).is_some() && store.get(&v4(3)).is_none());

        let bytes = store.encode(MAGIC);
        let back = SurveyStore::decode(&bytes, MAGIC, NOW, 2).unwrap();
        assert_eq!(back.len(), 2);
        assert!(back.get(&v4(4)).is_none(), "the least recently seen goes on read too");
        assert_eq!(SurveyStore::default().max_records, 250_000);
    }

    /// A record not seen for 30 days goes, on insert and on read.
    #[test]
    fn records_expire_after_thirty_days() {
        let mut store = SurveyStore::default();
        store.insert(v4(1), record(Fingerprint::Unknown, NOW - EXPIRY_SECS), NOW);
        store.insert(v4(2), record(Fingerprint::Unknown, NOW - EXPIRY_SECS - 1), NOW);
        assert!(store.get(&v4(1)).is_some(), "exactly 30 days is kept");
        assert!(store.get(&v4(2)).is_none(), "older is dropped on insert");

        let bytes = store.encode(MAGIC);
        let later = SurveyStore::decode(&bytes, MAGIC, NOW + 1, MAX_RECORDS).unwrap();
        assert!(later.is_empty(), "and on read");
        assert_eq!(EXPIRY_SECS, 2_592_000);
    }

    /// The file takes the directory's permissions without execute bits.
    #[cfg(unix)]
    #[test]
    fn the_file_takes_the_directorys_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let mut store = SurveyStore::default();
        store.insert(v4(1), record(Fingerprint::Unknown, NOW), NOW);
        let path = dir.path().join(SURVEY_FILE);
        for (dir_mode, file_mode) in [(0o700, 0o600), (0o750, 0o640)] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(dir_mode)).unwrap();
            store.save(&path, MAGIC).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, file_mode, "directory {dir_mode:o}");
        }
    }

    /// The aggregate counts each family, mismatches, v2 and the busiest
    /// autonomous systems.
    #[test]
    fn the_aggregate_counts_what_the_records_hold() {
        let mut store = SurveyStore::default();
        let mut i = 0;
        let mut add = |fp: Fingerprint, v2: bool, asn: Option<u32>| {
            let mut r = record(fp, NOW);
            r.v2 = v2;
            r.asn = asn;
            i += 1;
            store.insert(v4(i), r, NOW);
        };
        add(Fingerprint::Known(Family::Core, Confidence::High), true, Some(1));
        add(Fingerprint::Known(Family::Core, Confidence::High), true, Some(1));
        add(Fingerprint::Mismatch { claimed: Family::Core, observed: Family::Btcd }, false, Some(2));
        add(Fingerprint::Unknown, false, None);
        let agg = store.aggregate();
        assert_eq!(agg.addresses, 4);
        assert_eq!(agg.families[0], 2, "core");
        assert_eq!(agg.families[1], 1, "btcd, observed");
        assert_eq!((agg.unknown, agg.mismatches, agg.v2), (1, 1, 2));
        assert_eq!(agg.top_as, vec![(1, 2), (2, 1)]);

        let json = survey_json(&store, true, &serde_json::json!({ "enabled": true }));
        assert_eq!(json["families"]["core"]["count"], 2);
        assert_eq!(json["families"]["core"]["share"], 0.5);
        assert_eq!(json["families"]["unknown"]["count"], 1);
        assert_eq!(json["enabled"], true);
        assert_eq!(json["peers"].as_array().unwrap().len(), 4);
        assert!(survey_json(&store, false, &serde_json::Value::Null).get("peers").is_none());
    }

    /// Each connection's probes are a subset of the four, without repeats,
    /// and over many connections every one and every order turns up.
    #[test]
    fn probes_are_a_random_subset_in_random_order() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let mut sizes = [0usize; 5];
        let mut firsts = std::collections::HashSet::new();
        for _ in 0..2_000 {
            let chosen = choose_probes(&mut rng);
            let unique: std::collections::HashSet<_> = chosen.iter().collect();
            assert_eq!(unique.len(), chosen.len(), "no probe twice");
            sizes[chosen.len()] += 1;
            if let Some(first) = chosen.first() {
                firsts.insert(*first);
            }
        }
        assert!(sizes.iter().all(|n| *n > 0), "every subset size occurs: {sizes:?}");
        assert_eq!(firsts.len(), 4, "every probe comes first sometimes");
    }

    /// The messages: a one-hash locator, a `getdata` by wtxid to a peer
    /// that relays by wtxid, and a type nobody defines.
    #[test]
    fn probe_messages_have_the_vetted_shapes() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let a = BlockHash::from_byte_array([1; 32]);
        let b = BlockHash::from_byte_array([2; 32]);
        let ctx = ProbeContext::new(&mut rng, a, b, true);
        match probe_message(Probe::GetHeaders, &ctx) {
            NetworkMessage::GetHeaders(m) => {
                assert_eq!(m.locator_hashes, vec![a]);
                assert_eq!(m.stop_hash, b);
            }
            m => panic!("{m:?}"),
        }
        assert!(matches!(probe_message(Probe::GetData, &ctx), NetworkMessage::GetData(v) if matches!(v[..], [Inventory::WTx(_)])));
        let legacy = ProbeContext { wtxid_relay: false, ..ctx.clone() };
        assert!(matches!(probe_message(Probe::GetData, &legacy), NetworkMessage::GetData(v) if matches!(v[..], [Inventory::Transaction(_)])));
        assert_eq!(probe_message(Probe::Ping, &ctx), NetworkMessage::Ping(ctx.nonce));
        for _ in 0..1_000 {
            let c = unknown_command(&mut rng);
            let s: &str = c.as_ref();
            assert!((6..=11).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase()), "{s}");
            assert!(!KNOWN_COMMANDS.contains(&s));
        }
    }
}
