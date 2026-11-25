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

/// The file as written: each record ends with its [`SurveyShape`], when it
/// has one, its [`Verdict`], then its [`ClosedEarlyRetry`].
const FILE_MAGIC: [u8; 8] = *b"satdsrv4";
/// The third format: verdicts, no retry schedule. Its records are current
/// and kept, each with no retry scheduled.
const FILE_MAGIC_V3: [u8; 8] = *b"satdsrv3";
/// The second format: shapes, no verdict. It never stored whether the peer
/// closed the connection during the passive wait, so a closed-early record
/// cannot be told from the rest, and none of its records is kept: such a
/// file reads as an empty store, as a `satdsrv1` one does.
const FILE_MAGIC_V2: [u8; 8] = *b"satdsrv2";
/// The first format. Its records were judged before the trait rows and
/// hold no shape, so none of them is kept: such a file reads as an empty
/// store, and the survey fills again from the current classifier.
const FILE_MAGIC_V1: [u8; 8] = *b"satdsrv1";

/// The most commands a [`SurveyShape`] keeps, and the longest each one is.
pub const SHAPE_COMMANDS_MAX: usize = crate::net::behavior::HANDSHAKE_CAPTURE_MAX;
pub const SHAPE_COMMAND_LEN: usize = 12;

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
    pub(crate) fn code(self) -> (u8, u32) {
        match self {
            ProbeOutcome::Answered(v) => (1, v),
            ProbeOutcome::Silent => (2, 0),
            ProbeOutcome::Disconnected => (3, 0),
        }
    }

    pub(crate) fn from_code(code: u8, value: u32) -> Result<Option<Self>, String> {
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
    /// For a record no row matched only (an unknown or a claimed
    /// fingerprint): what the classifier read that the fields above do not
    /// hold, so that the next round of unknown shapes can be told apart.
    pub shape: Option<SurveyShape>,
    /// What the session showed besides its fingerprint: whether the peer
    /// closed early, or claimed a family it did not behave as.
    pub verdict: Verdict,
    /// For a closed-early record only: when the address is dialled again.
    /// Empty for every other record.
    pub retry: ClosedEarlyRetry,
}

/// How a survey or crawl session's passive wait ended, as far as
/// [`session_verdict`] reads it. A wait the node itself cut short (`disconnectnode`, a ban,
/// `setnetworkactive false`, shutdown) is none of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassiveEnd {
    /// The peer's handshake transcript closed: it sent a message past its
    /// announcements.
    Settled,
    /// The wait ran out with the connection still open.
    Timeout,
    /// The peer closed the connection.
    PeerClosed,
}

/// What a survey session showed besides its [`Fingerprint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verdict {
    /// The fingerprint stands: a row matched, the user agent's family is
    /// claimed, or the record is unknown.
    #[default]
    Classified,
    /// The session is [`is_fake_core`]'s: a user agent naming this family
    /// (only Core has the rule) on a session no release of it produces.
    /// Counted apart, never as the family, a claim or unknown.
    Fake(Family),
    /// The peer closed the connection before its handshake transcript
    /// settled ([`session_verdict`]). The record keeps what the `version`
    /// said and has no fingerprint ([`Fingerprint::Unknown`]): a node with
    /// full inbound slots evicts its newest inbound connection, which a
    /// survey connection seconds old is, so the short transcript says
    /// nothing about the implementation.
    ClosedEarly,
}

impl Verdict {
    /// A row's `fingerprint` as `getpeersurvey`'s verbose rows and the
    /// crawl's rows give it: `fake/<family>`, `closed-early`, or the
    /// fingerprint itself (`core/high`, `core/claimed`, `unknown`, ...).
    pub fn fingerprint_text(self, fingerprint: Fingerprint) -> String {
        match self {
            Verdict::Classified => fingerprint.to_string(),
            Verdict::Fake(f) => format!("fake/{f}"),
            Verdict::ClosedEarly => "closed-early".to_string(),
        }
    }
}

/// How many times an address whose session closed early is dialled again
/// before the schedule stops ([`ClosedEarlyRetry`]).
pub const CLOSED_EARLY_RETRIES: u8 = 10;

/// The wait before the first, second, third and fourth retry of an address
/// whose session closed early; every later retry waits as long as the last.
pub const CLOSED_EARLY_RETRY_SECS: [u64; 5] = [15 * 60, 30 * 60, 60 * 60, 2 * 60 * 60, 4 * 60 * 60];

/// Each retry's wait is spread at random by up to this share of it, either
/// way, so a retry is not dialled at a time a peer could predict.
pub const CLOSED_EARLY_RETRY_SPREAD_PERCENT: u64 = 20;

/// The retry schedule of an address whose sessions closed early
/// ([`Verdict::ClosedEarly`]) and that has no settled session yet. A node
/// with full inbound slots evicts its newest inbound connection within a
/// second of `verack`; dialled again later, it often has room. After each
/// closed-early session (and each retry that did not connect) the next
/// retry is due after [`CLOSED_EARLY_RETRY_SECS`], spread by
/// [`CLOSED_EARLY_RETRY_SPREAD_PERCENT`], until [`CLOSED_EARLY_RETRIES`]
/// have been scheduled; then none is, and the address waits for an
/// ordinary visit. A settled session (classified or fake) clears it. The
/// survey's records and the crawl's entries both hold one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClosedEarlyRetry {
    /// Retries scheduled since the address's first closed-early session, at
    /// most [`CLOSED_EARLY_RETRIES`].
    pub count: u8,
    /// When the next retry is due, Unix seconds; `None` with none scheduled.
    pub next_due: Option<u64>,
}

impl ClosedEarlyRetry {
    /// The wait before retry `n` (the first is 1), before its spread.
    pub fn delay_secs(n: u8) -> u64 {
        let i = usize::from(n.max(1)).min(CLOSED_EARLY_RETRY_SECS.len()) - 1;
        CLOSED_EARLY_RETRY_SECS[i]
    }

    /// Schedule the next retry after a closed-early session, or after a
    /// retry that did not connect, at `now`: due after the next wait,
    /// spread at random. Once [`CLOSED_EARLY_RETRIES`] have been scheduled
    /// none is, and the schedule is exhausted. Returns whether one was.
    pub fn schedule(&mut self, now: u64, rng: &mut impl Rng) -> bool {
        if self.count >= CLOSED_EARLY_RETRIES {
            self.next_due = None;
            return false;
        }
        self.count += 1;
        let base = Self::delay_secs(self.count);
        let spread = base * CLOSED_EARLY_RETRY_SPREAD_PERCENT / 100;
        self.next_due = Some(now + rng.gen_range(base - spread..=base + spread));
        true
    }

    /// Whether a retry is due at `now`.
    pub fn due(&self, now: u64) -> bool {
        self.next_due.is_some_and(|d| now >= d)
    }

    /// Whether a retry is scheduled.
    pub fn pending(&self) -> bool {
        self.next_due.is_some()
    }

    /// Whether every retry has been scheduled and none is left.
    pub fn exhausted(&self) -> bool {
        self.count >= CLOSED_EARLY_RETRIES && self.next_due.is_none()
    }

    /// The schedule as the rows give it: `{ "count", "next_due" }`.
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({ "count": self.count, "next_due": self.next_due })
    }
}

/// The lowest common protocol version at which Core sends `wtxidrelay`
/// (BIP 339) and `sendaddrv2` (BIP 155) before its `verack`.
pub const FAKE_CORE_MIN_COMMON_VERSION: u32 = 70016;

/// Whether a survey or crawl session is an impostor claiming to be Core.
/// All must hold:
///
/// - the user agent names Core ([`Family::claimed_by`]);
/// - the common protocol version (the lower of the peer's and ours) is at
///   least [`FAKE_CORE_MIN_COMMON_VERSION`], so a real Core (0.21 or later)
///   sends both negotiation messages before its `verack`;
/// - the transcript is exactly `version`, `verack`: no negotiation message
///   between them, nothing after;
/// - the passive wait ended by its timeout, the connection still open
///   ([`PassiveEnd::Timeout`]). A peer that sent nothing more and then
///   closed is closed early instead.
///
/// Every Core release since 0.21 sends both messages to the node that
/// dials it, and a message after `verack` within the wait (the fixtures
/// `core-*-outbound-survey*`); no trait row can match a transcript this
/// short at these versions. Only Core has the rule: the evidence, peers
/// that claim a Core user agent and stay connected and silent, exists for
/// Core alone.
pub fn is_fake_core(
    user_agent: &str,
    their_version: u32,
    our_version: u32,
    transcript: &[String],
    passive: PassiveEnd,
) -> bool {
    Family::claimed_by(user_agent) == Some(Family::Core)
        && their_version.min(our_version) >= FAKE_CORE_MIN_COMMON_VERSION
        && transcript == ["version", "verack"]
        && passive == PassiveEnd::Timeout
}

/// A survey or crawl session's [`Verdict`] from how its passive wait
/// ended and what its transcript holds; `our_version` is the protocol
/// version the session's own `version` stated. The peer closing while its transcript is still
/// open is [`Verdict::ClosedEarly`]; [`is_fake_core`] is
/// [`Verdict::Fake`]; anything else keeps its fingerprint. `passive` is
/// `None` where the node cut the wait short.
pub fn session_verdict(
    passive: Option<PassiveEnd>,
    capture: &crate::net::behavior::HandshakeCapture,
    user_agent: &str,
    their_version: u32,
    our_version: u32,
) -> Verdict {
    let Some(passive) = passive else {
        return Verdict::Classified;
    };
    if passive == PassiveEnd::PeerClosed && capture.is_open() {
        return Verdict::ClosedEarly;
    }
    let transcript: Vec<String> = capture.commands().collect();
    if is_fake_core(user_agent, their_version, our_version, &transcript, passive) {
        return Verdict::Fake(Family::Core);
    }
    Verdict::Classified
}

/// The raw features of a survey session no row matched. The `version`'s
/// protocol, services and user agent are in the [`SurveyRecord`] itself.
/// Bounded: at most [`SHAPE_COMMANDS_MAX`] commands of at most
/// [`SHAPE_COMMAND_LEN`] bytes each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurveyShape {
    /// The handshake transcript (peer text, `?` for an unprintable byte).
    pub commands: Vec<String>,
    /// The `relay` flag of the peer's `version`.
    pub relay: bool,
}

impl SurveyShape {
    /// The shape of a session's transcript and `version`.
    pub fn of(capture: &crate::net::behavior::HandshakeCapture, relay: bool) -> SurveyShape {
        SurveyShape { commands: capture.commands().take(SHAPE_COMMANDS_MAX).collect(), relay }
    }
}

/// `getpeersurvey`'s aggregate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Aggregate {
    /// Records counted.
    pub addresses: usize,
    /// Records per observed family; [`Family::ALL`]'s order.
    pub families: [usize; Family::ALL.len()],
    /// Records whose handshake matched no family and whose user agent
    /// names none: neither claimed, fake nor closed early.
    pub unknown: usize,
    /// The records no row matched whose user agent names a family (a
    /// [`Confidence::Claimed`] fingerprint), per family; [`Family::ALL`]'s
    /// order. Never counted in `families` or `unknown`.
    pub claimed: [usize; Family::ALL.len()],
    /// The [`Verdict::Fake`] records, per claimed family; [`Family::ALL`]'s
    /// order. Never counted in `families`, `claimed` or `unknown`.
    pub fake: [usize; Family::ALL.len()],
    /// The [`Verdict::ClosedEarly`] records: counted nowhere else but the
    /// v2, probe and autonomous-system tallies.
    pub closed_early: usize,
    /// Records whose user agent names one family and handshake another.
    pub mismatches: usize,
    /// Records reached over BIP 324.
    pub v2: usize,
    /// The autonomous systems with the most records, most first, at most
    /// [`TOP_AS`].
    pub top_as: Vec<(u32, usize)>,
    /// Records that carry at least one probe outcome.
    pub probed: usize,
    /// Closed-early records with a retry scheduled.
    pub retries_pending: usize,
    /// Closed-early records with no retry left ([`ClosedEarlyRetry::exhausted`]).
    pub retries_exhausted: usize,
}

/// The survey's records, one per address.
#[derive(Debug, Clone)]
pub struct SurveyStore {
    records: HashMap<PeerAddr, SurveyRecord>,
    max_records: usize,
    /// Records the file held in a format whose records are not kept
    /// (`satdsrv1`, `satdsrv2`), dropped as it was read. Never written.
    dropped_old_format: usize,
}

impl Default for SurveyStore {
    fn default() -> Self {
        Self::with_limit(MAX_RECORDS)
    }
}

impl SurveyStore {
    /// An empty store that keeps at most `max_records`.
    pub fn with_limit(max_records: usize) -> Self {
        SurveyStore { records: HashMap::new(), max_records, dropped_old_format: 0 }
    }

    /// How many records the file read held in an older format, all of them
    /// dropped: a `satdsrv1` file's were judged before the trait rows, and
    /// neither it nor a `satdsrv2` file stored whether the peer closed the
    /// connection early.
    pub fn dropped_old_format(&self) -> usize {
        self.dropped_old_format
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
    ///
    /// A closed-early session never replaces a settled record (classified
    /// or fake): that record keeps its fingerprint, verdict and transcript,
    /// and only its `last_seen` moves on. Only an address with no settled
    /// record is recorded closed early, and it is given its next retry
    /// ([`ClosedEarlyRetry::schedule`]). A settled session replaces any
    /// record (a fake one a classified one too) and clears the schedule.
    pub fn insert(&mut self, addr: PeerAddr, record: SurveyRecord, now: u64) {
        self.insert_with(addr, record, now, &mut rand::thread_rng());
    }

    /// [`Self::insert`], its retry spread drawn from `rng`.
    pub fn insert_with(&mut self, addr: PeerAddr, mut record: SurveyRecord, now: u64, rng: &mut impl Rng) {
        let old = self.records.get(&addr);
        if let Some(old) = old {
            record.first_seen = old.first_seen.min(record.first_seen);
        }
        let record = match (old, record.verdict) {
            (Some(old), Verdict::ClosedEarly) if old.verdict != Verdict::ClosedEarly => SurveyRecord {
                first_seen: record.first_seen,
                last_seen: old.last_seen.max(record.last_seen),
                retry: ClosedEarlyRetry::default(),
                ..old.clone()
            },
            (old, Verdict::ClosedEarly) => {
                let mut retry = old.map(|o| o.retry).unwrap_or_default();
                retry.schedule(now, rng);
                SurveyRecord { retry, ..record }
            }
            _ => SurveyRecord { retry: ClosedEarlyRetry::default(), ..record },
        };
        self.records.insert(addr, record);
        self.expire(now);
        self.evict_to_limit();
    }

    /// A retry of `addr` that was due at `now` did not connect (the dial
    /// or the handshake failed): it counts as a retry, and the next is
    /// scheduled. Returns whether the record changed.
    pub fn retry_failed(&mut self, addr: &PeerAddr, now: u64) -> bool {
        match self.records.get_mut(addr) {
            Some(r) if r.verdict == Verdict::ClosedEarly && r.retry.due(now) => {
                r.retry.schedule(now, &mut rand::thread_rng());
                true
            }
            _ => false,
        }
    }

    /// The addresses whose closed-early retry is due at `now`, the longest
    /// due first, then by address.
    pub fn due_retries(&self, now: u64) -> Vec<PeerAddr> {
        let mut due: Vec<(u64, &PeerAddr)> = self
            .records
            .iter()
            .filter(|(_, r)| r.retry.due(now))
            .filter_map(|(a, r)| r.retry.next_due.map(|d| (d, a)))
            .collect();
        due.sort_unstable();
        due.into_iter().map(|(_, a)| a.clone()).collect()
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
            match r.verdict {
                Verdict::ClosedEarly => agg.closed_early += 1,
                Verdict::Fake(f) => agg.fake[family_index(f)] += 1,
                Verdict::Classified => match r.fingerprint {
                    Fingerprint::Known(f, Confidence::Claimed) => agg.claimed[family_index(f)] += 1,
                    Fingerprint::Known(f, _) => agg.families[family_index(f)] += 1,
                    Fingerprint::Mismatch { observed, .. } => {
                        agg.families[family_index(observed)] += 1;
                        agg.mismatches += 1;
                    }
                    Fingerprint::Unknown => agg.unknown += 1,
                },
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
            if r.retry.pending() {
                agg.retries_pending += 1;
            }
            if r.verdict == Verdict::ClosedEarly && r.retry.exhausted() {
                agg.retries_exhausted += 1;
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
        self.encode_as(network_magic, 4)
    }

    /// The bytes in format `format`: 4, the current one; 3 (`satdsrv3`),
    /// which holds no retry schedule; 2 (`satdsrv2`), which holds no
    /// verdict either; or 1 (`satdsrv1`), which holds no shape either. The
    /// older ones are for the tests of how such a file reads.
    fn encode_as(&self, network_magic: [u8; 4], format: u8) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.records.len() * 100);
        buf.extend_from_slice(match format {
            1 => &FILE_MAGIC_V1,
            2 => &FILE_MAGIC_V2,
            3 => &FILE_MAGIC_V3,
            _ => &FILE_MAGIC,
        });
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
            if format >= 2 {
                encode_shape(&mut buf, r.shape.as_ref());
            }
            if format >= 3 {
                encode_verdict(&mut buf, r.verdict);
            }
            if format >= 4 {
                encode_retry(&mut buf, r.retry);
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
        let format = match r.take(8)? {
            m if m == FILE_MAGIC => 4,
            m if m == FILE_MAGIC_V3 => 3,
            m if m == FILE_MAGIC_V2 => 2,
            m if m == FILE_MAGIC_V1 => 1,
            _ => return Err("not a survey file".to_string()),
        };
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
            let shape = if format >= 2 { decode_shape(&mut r)? } else { None };
            let verdict = if format >= 3 { decode_verdict(&mut r)? } else { Verdict::Classified };
            // A `satdsrv3` record has no schedule: its address is retried
            // after its next closed-early session.
            let retry = if format >= 4 { decode_retry(&mut r)? } else { ClosedEarlyRetry::default() };
            if verdict != Verdict::ClosedEarly && retry != ClosedEarlyRetry::default() {
                return Err("a retry on a settled record".to_string());
            }
            store.records.insert(
                addr,
                SurveyRecord {
                    fingerprint,
                    user_agent,
                    protocol_version,
                    services,
                    v2,
                    asn,
                    first_seen,
                    last_seen,
                    probes,
                    shape,
                    verdict,
                    retry,
                },
            );
        }
        if !r.0.is_empty() {
            return Err("trailing bytes".to_string());
        }
        // Read whole first, so a damaged old file is still refused and set
        // aside like any other; then dropped, every record of it.
        if format < 3 {
            store.dropped_old_format = store.records.len();
            store.records.clear();
            return Ok(store);
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
        write_private_file(path, &self.encode(network_magic))
    }
}

/// Write `buf` to `path` through a temporary file renamed over it. The file
/// takes the permissions of the directory it is in, less the execute bits:
/// the files written this way hold peer addresses, so they are never more
/// open than the data directory.
pub(crate) fn write_private_file(path: &Path, buf: &[u8]) -> Result<(), String> {
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
        f.write_all(buf).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
        f.sync_all().map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("renaming {} -> {}: {e}", tmp.display(), path.display()))
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

pub(crate) fn encode_fingerprint(buf: &mut Vec<u8>, fp: Fingerprint) {
    let (tag, a, b) = match fp {
        Fingerprint::Unknown => (0, None, None),
        Fingerprint::Known(f, Confidence::High) => (1, Some(f), None),
        Fingerprint::Known(f, Confidence::Low) => (2, Some(f), None),
        Fingerprint::Mismatch { claimed, observed } => (3, Some(observed), Some(claimed)),
        // A shape no row matches, under a user agent that names a family:
        // `crawlbook.dat`, the survey's records and the alt-slot records
        // all hold it.
        Fingerprint::Known(f, Confidence::Claimed) => (4, Some(f), None),
    };
    buf.extend_from_slice(&[tag, family_byte(a), family_byte(b)]);
}

pub(crate) fn decode_fingerprint(r: &mut Reader) -> Result<Fingerprint, String> {
    let tag = r.u8()?;
    let a = r.u8()?;
    let b = r.u8()?;
    Ok(match tag {
        0 => Fingerprint::Unknown,
        1 => Fingerprint::Known(family_from_byte(a)?, Confidence::High),
        2 => Fingerprint::Known(family_from_byte(a)?, Confidence::Low),
        3 => Fingerprint::Mismatch { observed: family_from_byte(a)?, claimed: family_from_byte(b)? },
        4 => Fingerprint::Known(family_from_byte(a)?, Confidence::Claimed),
        t => return Err(format!("bad fingerprint tag {t}")),
    })
}

/// A verdict: a tag (0 classified, 1 fake, 2 closed early), then the fake
/// one's claimed family, `0xff` for the others. `peersurvey.dat` and
/// `crawlbook.dat` both hold it.
pub(crate) fn encode_verdict(buf: &mut Vec<u8>, verdict: Verdict) {
    let (tag, family) = match verdict {
        Verdict::Classified => (0, None),
        Verdict::Fake(f) => (1, Some(f)),
        Verdict::ClosedEarly => (2, None),
    };
    buf.extend_from_slice(&[tag, family_byte(family)]);
}

pub(crate) fn decode_verdict(r: &mut Reader) -> Result<Verdict, String> {
    let tag = r.u8()?;
    let family = r.u8()?;
    match (tag, family) {
        (0, 0xff) => Ok(Verdict::Classified),
        (1, f) => Ok(Verdict::Fake(family_from_byte(f)?)),
        (2, 0xff) => Ok(Verdict::ClosedEarly),
        (t, f) => Err(format!("bad verdict {t}/{f}")),
    }
}

/// A retry schedule: its count, then a presence byte and the next due time
/// (zero with none). `peersurvey.dat` and `crawlbook.dat` both hold it.
pub(crate) fn encode_retry(buf: &mut Vec<u8>, retry: ClosedEarlyRetry) {
    buf.push(retry.count);
    buf.push(u8::from(retry.next_due.is_some()));
    buf.extend_from_slice(&retry.next_due.unwrap_or(0).to_le_bytes());
}

pub(crate) fn decode_retry(r: &mut Reader) -> Result<ClosedEarlyRetry, String> {
    let count = r.u8()?;
    let present = r.u8()?;
    let at = r.u64()?;
    let next_due = match present {
        0 if at == 0 => None,
        1 if count > 0 => Some(at),
        _ => return Err(format!("bad retry schedule {count}/{present}")),
    };
    if count > CLOSED_EARLY_RETRIES {
        return Err(format!("retry count {count}"));
    }
    Ok(ClosedEarlyRetry { count, next_due })
}

/// A shape: a presence byte, then the relay flag, the command count and
/// each command as a length and its bytes.
fn encode_shape(buf: &mut Vec<u8>, shape: Option<&SurveyShape>) {
    let Some(s) = shape else {
        buf.push(0);
        return;
    };
    buf.push(1);
    buf.push(u8::from(s.relay));
    let commands = &s.commands[..s.commands.len().min(SHAPE_COMMANDS_MAX)];
    buf.push(commands.len() as u8);
    for c in commands {
        let c = &c.as_bytes()[..c.len().min(SHAPE_COMMAND_LEN)];
        buf.push(c.len() as u8);
        buf.extend_from_slice(c);
    }
}

fn decode_shape(r: &mut Reader) -> Result<Option<SurveyShape>, String> {
    match r.u8()? {
        0 => return Ok(None),
        1 => {}
        t => return Err(format!("bad shape tag {t}")),
    }
    let relay = r.u8()? != 0;
    let n = usize::from(r.u8()?);
    if n > SHAPE_COMMANDS_MAX {
        return Err(format!("shape of {n} commands"));
    }
    let mut commands = Vec::with_capacity(n);
    for _ in 0..n {
        let len = usize::from(r.u8()?);
        if len > SHAPE_COMMAND_LEN {
            return Err(format!("shape command of {len} bytes"));
        }
        let text: String = r
            .take(len)?
            .iter()
            .map(|b| if b.is_ascii_graphic() { char::from(*b) } else { '?' })
            .collect();
        commands.push(text);
    }
    Ok(Some(SurveyShape { commands, relay }))
}

pub(crate) fn encode_addr(buf: &mut Vec<u8>, addr: &PeerAddr) {
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

pub(crate) fn decode_addr(r: &mut Reader) -> Result<PeerAddr, String> {
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

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("file truncated".to_string());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, String> {
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
    let per_family = |counts: &[usize]| {
        let mut out = serde_json::Map::new();
        for (f, n) in Family::ALL.iter().zip(counts) {
            out.insert(f.name().to_string(), serde_json::json!({ "count": n, "share": share(*n) }));
        }
        out
    };
    let mut out = serde_json::json!({
        "addresses": agg.addresses,
        "families": families,
        "claimed": per_family(&agg.claimed),
        "fake": per_family(&agg.fake),
        "closed_early": { "count": agg.closed_early, "share": share(agg.closed_early) },
        "mismatches": agg.mismatches,
        "v2": { "count": agg.v2, "share": share(agg.v2) },
        "top_as": agg.top_as.iter().map(|(asn, n)| serde_json::json!({ "asn": asn, "count": n })).collect::<Vec<_>>(),
        "probed": agg.probed,
        "retries": { "pending": agg.retries_pending, "exhausted": agg.retries_exhausted },
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
    let addr_text = match addr {
        PeerAddr::Socket(sa) => sa.to_string(),
        PeerAddr::Onion { host, port } => format!("{host}:{port}"),
    };
    let mut row = serde_json::json!({
        "addr": addr_text,
        "network": network_name(addr),
        "fingerprint": r.verdict.fingerprint_text(r.fingerprint),
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
        "probes": probes_json(&r.probes),
    });
    if let Some(shape) = &r.shape {
        row["handshake"] = serde_json::json!(shape.commands);
        row["relay"] = serde_json::json!(shape.relay);
    }
    if r.verdict == Verdict::ClosedEarly {
        row["retry"] = r.retry.json();
    }
    row
}

/// The probe outcomes as a row reports them: by probe name, its result and,
/// for an answer, its value. A probe not sent is absent.
pub fn probes_json(results: &ProbeResults) -> serde_json::Value {
    let mut probes = serde_json::Map::new();
    for p in Probe::ALL {
        if let Some(o) = results.get(p) {
            let mut v = serde_json::json!({ "result": o.name() });
            if let ProbeOutcome::Answered(n) = o {
                v["value"] = serde_json::json!(n);
            }
            probes.insert(p.name().to_string(), v);
        }
    }
    serde_json::Value::Object(probes)
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
            shape: None,
            verdict: Verdict::Classified,
            retry: ClosedEarlyRetry::default(),
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
        let mut unmatched = record(Fingerprint::Unknown, NOW - 9);
        unmatched.shape = Some(SurveyShape { commands: vec!["version".into(), "verack".into(), "inv".into()], relay: false });
        store.insert(PeerAddr::Onion { host: ONION.to_string(), port: 8333 }, unmatched, NOW);
        let mut claimed = record(Fingerprint::Known(Family::Core, Confidence::Claimed), NOW - 7);
        claimed.shape = Some(SurveyShape { commands: vec!["version".into(); SHAPE_COMMANDS_MAX], relay: true });
        store.insert(v4(3), claimed, NOW);
        let mut fake = record(Fingerprint::Known(Family::Core, Confidence::Claimed), NOW - 8);
        fake.verdict = Verdict::Fake(Family::Core);
        fake.shape = Some(SurveyShape { commands: vec!["version".into(), "verack".into()], relay: true });
        store.insert(v4(4), fake, NOW);
        let mut early = record(Fingerprint::Unknown, NOW - 6);
        early.verdict = Verdict::ClosedEarly;
        store.insert(v4(5), early, NOW);
        let mut again = record(Fingerprint::Known(Family::Core, Confidence::High), NOW);
        again.first_seen = NOW;
        store.insert(v4(2), record(Fingerprint::Known(Family::Core, Confidence::High), NOW - 100), NOW);
        store.insert(v4(2), again, NOW);
        assert_eq!(store.get(&v4(2)).unwrap().first_seen, NOW - 100, "the first sighting is kept");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SURVEY_FILE);
        store.save(&path, MAGIC).unwrap();
        assert_eq!(&std::fs::read(&path).unwrap()[..8], b"satdsrv4");
        let back = SurveyStore::load(&path, MAGIC, NOW).unwrap();
        assert_eq!(back.len(), 7);
        assert_eq!(back.dropped_old_format(), 0);
        assert_eq!(back.get(&v4(4)).unwrap().verdict, Verdict::Fake(Family::Core));
        assert_eq!(back.get(&v4(5)).unwrap().verdict, Verdict::ClosedEarly);
        assert_eq!(back.get(&v4(5)).unwrap().retry.count, 1, "the retry schedule survives the file");
        assert!(back.get(&v4(5)).unwrap().retry.pending());
        for (addr, r) in store.rows() {
            assert_eq!(back.get(addr), Some(r), "{addr:?}");
        }
    }

    /// A file in an older format, as earlier builds wrote it, reads as an
    /// empty store and the count dropped is reported: `satdsrv1` (no
    /// shapes; judged before the trait rows) and `satdsrv2` (no verdict;
    /// whether the peer closed early was never stored). `satdsrv2` is the
    /// current format less the ten retry bytes and two verdict bytes per
    /// record, `satdsrv1` less the shape's byte too, and each is still
    /// checked whole: a damaged one is refused, not read as empty.
    #[test]
    fn a_file_in_an_older_format_is_dropped() {
        let mut store = SurveyStore::default();
        store.insert(v4(1), record(Fingerprint::Known(Family::Core, Confidence::High), NOW), NOW);
        store.insert(v4(2), record(Fingerprint::Mismatch { claimed: Family::Core, observed: Family::Btcd }, NOW), NOW);
        store.insert(v4(3), record(Fingerprint::Unknown, NOW - 3), NOW);
        let current_len = store.encode(MAGIC).len();
        for (format, magic, less) in [(1u8, b"satdsrv1", 13), (2, b"satdsrv2", 12)] {
            let old = store.encode_as(MAGIC, format);
            assert_eq!(&old[..8], magic);
            assert_eq!(old.len() + less * store.len(), current_len, "format {format}");
            let back = SurveyStore::decode(&old, MAGIC, NOW, MAX_RECORDS).unwrap();
            assert!(back.is_empty(), "format {format}");
            assert_eq!(back.dropped_old_format(), 3, "format {format}");
            assert_eq!(back.aggregate().addresses, 0);
            // Written again, it is in the current format, empty.
            let again = back.encode(MAGIC);
            assert_eq!(&again[..8], b"satdsrv4");
            assert_eq!(SurveyStore::decode(&again, MAGIC, NOW, MAX_RECORDS).unwrap().len(), 0);
            // An old file cut short is refused, not read as empty.
            let mut cut = old[..old.len() - 32 - 1].to_vec();
            let sum = sha256d::Hash::hash(&cut);
            cut.extend_from_slice(sum.as_byte_array());
            assert!(SurveyStore::decode(&cut, MAGIC, NOW, MAX_RECORDS).is_err(), "format {format}");
            // And one damaged in its body.
            let mut flipped = old.clone();
            flipped[20] ^= 1;
            assert!(SurveyStore::decode(&flipped, MAGIC, NOW, MAX_RECORDS).unwrap_err().contains("checksum"));
        }
        // A current-format file of the same records keeps them all.
        let current = SurveyStore::decode(&store.encode(MAGIC), MAGIC, NOW, MAX_RECORDS).unwrap();
        assert_eq!(current.len(), 3);
        assert_eq!(current.dropped_old_format(), 0);
    }

    /// A verdict out of its range is refused, as a damaged file: an unknown
    /// tag, a fake one naming no family, or a family on another verdict.
    #[test]
    fn a_bad_verdict_is_refused() {
        let mut store = SurveyStore::default();
        store.insert(v4(1), record(Fingerprint::Unknown, NOW), NOW);
        let bytes = store.encode(MAGIC);
        let body = &bytes[..bytes.len() - 32];
        // The verdict ends the record but for its ten retry bytes.
        let reseal = |tag: u8, family: u8| {
            let mut body = body.to_vec();
            let n = body.len() - 10;
            body[n - 2] = tag;
            body[n - 1] = family;
            let sum = sha256d::Hash::hash(&body);
            body.extend_from_slice(sum.as_byte_array());
            body
        };
        assert_eq!(SurveyStore::decode(&reseal(0, 0xff), MAGIC, NOW, MAX_RECORDS).unwrap().len(), 1);
        let fake = SurveyStore::decode(&reseal(1, 0), MAGIC, NOW, MAX_RECORDS).unwrap();
        assert_eq!(fake.get(&v4(1)).unwrap().verdict, Verdict::Fake(Family::Core));
        for (tag, family) in [(3, 0xff), (1, 0xff), (0, 0), (2, 1)] {
            let err = SurveyStore::decode(&reseal(tag, family), MAGIC, NOW, MAX_RECORDS).unwrap_err();
            assert!(err.contains("verdict") || err.contains("family"), "{tag}/{family}: {err}");
        }
    }

    /// The schedule: 15 min, 30 min, 1 h, 2 h, then 4 h for every later
    /// retry, each spread by at most a fifth either way; ten retries, then
    /// none, and the schedule is exhausted.
    #[test]
    fn the_retry_schedule_waits_longer_each_time_and_stops_at_ten() {
        let expect = [900, 1_800, 3_600, 7_200, 14_400, 14_400, 14_400, 14_400, 14_400, 14_400];
        for (i, want) in expect.iter().enumerate() {
            assert_eq!(ClosedEarlyRetry::delay_secs(i as u8 + 1), *want, "retry {}", i + 1);
        }
        assert_eq!(ClosedEarlyRetry::delay_secs(200), 14_400, "capped at 4 h");
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let mut r = ClosedEarlyRetry::default();
        assert!(!r.pending() && !r.exhausted() && !r.due(NOW));
        for (i, want) in expect.iter().enumerate() {
            let now = NOW + i as u64 * 100_000;
            assert!(r.schedule(now, &mut rng), "retry {} is scheduled", i + 1);
            assert_eq!(r.count, i as u8 + 1);
            let due = r.next_due.unwrap();
            assert!((now + want * 4 / 5..=now + want * 6 / 5).contains(&due), "retry {}: {}", i + 1, due - now);
            assert!(r.pending() && !r.exhausted());
            assert!(!r.due(due - 1) && r.due(due));
        }
        assert!(!r.schedule(NOW + 2_000_000, &mut rng), "no eleventh");
        assert_eq!((r.count, r.next_due), (CLOSED_EARLY_RETRIES, None));
        assert!(r.exhausted() && !r.pending());
        assert!(!r.schedule(NOW + 3_000_000, &mut rng), "and none after");
        assert_eq!(CLOSED_EARLY_RETRIES, 10);
    }

    /// The spread covers its whole range, a fifth either way, and no more.
    #[test]
    fn the_retry_spread_is_a_fifth_either_way() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let (mut lo, mut hi) = (u64::MAX, 0);
        for _ in 0..4_000 {
            let mut r = ClosedEarlyRetry::default();
            r.schedule(NOW, &mut rng);
            let wait = r.next_due.unwrap() - NOW;
            lo = lo.min(wait);
            hi = hi.max(wait);
        }
        assert!((720..=730).contains(&lo), "{lo}");
        assert!((1_070..=1_080).contains(&hi), "{hi}");
    }

    fn early(last_seen: u64) -> SurveyRecord {
        SurveyRecord { verdict: Verdict::ClosedEarly, shape: None, ..record(Fingerprint::Unknown, last_seen) }
    }

    /// A closed-early session never replaces a settled record, classified
    /// at any confidence or fake: the record keeps its fingerprint, verdict
    /// and transcript, its `last_seen` moves on, and it gets no retry. A
    /// fake session replaces a classified record, and a classified session
    /// any record.
    #[test]
    fn a_closed_early_session_keeps_a_settled_record() {
        let mut store = SurveyStore::default();
        let mut settled = Vec::new();
        for (i, (fp, verdict)) in [
            (Fingerprint::Known(Family::Core, Confidence::High), Verdict::Classified),
            (Fingerprint::Known(Family::Btcd, Confidence::Low), Verdict::Classified),
            (Fingerprint::Known(Family::Core, Confidence::Claimed), Verdict::Classified),
            (Fingerprint::Mismatch { claimed: Family::Core, observed: Family::Btcd }, Verdict::Classified),
            (Fingerprint::Unknown, Verdict::Classified),
            (Fingerprint::Known(Family::Core, Confidence::Claimed), Verdict::Fake(Family::Core)),
        ]
        .into_iter()
        .enumerate()
        {
            let mut r = record(fp, NOW - 100);
            r.verdict = verdict;
            r.shape = Some(SurveyShape { commands: vec!["version".into(), "verack".into()], relay: true });
            r.probes.set(Probe::Ping, ProbeOutcome::Answered(9));
            store.insert(v4(i as u32), r.clone(), NOW - 100);
            settled.push((v4(i as u32), r));
        }
        for (addr, before) in &settled {
            let mut later = early(NOW);
            later.v2 = !before.v2;
            store.insert(addr.clone(), later, NOW);
            let after = store.get(addr).unwrap();
            assert_eq!(after.last_seen, NOW, "{addr:?}: last seen moves on");
            assert_eq!(&SurveyRecord { last_seen: before.last_seen, ..after.clone() }, before, "{addr:?}: all else kept");
            assert_eq!(after.retry, ClosedEarlyRetry::default(), "{addr:?}: no retry");
        }
        let agg = store.aggregate();
        assert_eq!((agg.closed_early, agg.retries_pending, agg.retries_exhausted), (0, 0, 0));

        // A fake session replaces a classified record.
        let mut fake = record(Fingerprint::Known(Family::Core, Confidence::Claimed), NOW + 1);
        fake.verdict = Verdict::Fake(Family::Core);
        store.insert(v4(0), fake, NOW + 1);
        assert_eq!(store.get(&v4(0)).unwrap().verdict, Verdict::Fake(Family::Core));
        // A classified session replaces a fake one.
        store.insert(v4(5), record(Fingerprint::Known(Family::Core, Confidence::High), NOW + 1), NOW + 1);
        assert_eq!(store.get(&v4(5)).unwrap().verdict, Verdict::Classified);
        assert_eq!(store.get(&v4(5)).unwrap().fingerprint, Fingerprint::Known(Family::Core, Confidence::High));
    }

    /// An address with no settled record is recorded closed early and given
    /// a retry after each closed-early session, ten in all; the first
    /// settled session clears the schedule. Once exhausted, a later
    /// closed-early session schedules none. A retry that did not connect is
    /// spent only while due.
    #[test]
    fn a_closed_early_address_is_retried_until_it_settles() {
        let mut store = SurveyStore::default();
        let mut rng = rand::rngs::StdRng::seed_from_u64(5);
        store.insert_with(v4(1), early(NOW), NOW, &mut rng);
        let r = store.get(&v4(1)).unwrap().retry;
        assert_eq!(r.count, 1);
        let due = r.next_due.unwrap();
        assert!((NOW + 720..=NOW + 1_080).contains(&due));
        assert!(store.due_retries(due - 1).is_empty());
        assert_eq!(store.due_retries(due), vec![v4(1)]);
        let agg = store.aggregate();
        assert_eq!((agg.closed_early, agg.retries_pending, agg.retries_exhausted), (1, 1, 0));
        let json = survey_json(&store, true, &serde_json::Value::Null);
        assert_eq!(json["retries"], serde_json::json!({ "pending": 1, "exhausted": 0 }));
        assert_eq!(json["peers"][0]["retry"], serde_json::json!({ "count": 1, "next_due": due }));

        // A failed dial before the retry is due spends nothing; one when it
        // is due spends it.
        assert!(!store.retry_failed(&v4(1), due - 1));
        assert_eq!(store.get(&v4(1)).unwrap().retry.count, 1);
        assert!(store.retry_failed(&v4(1), due));
        assert_eq!(store.get(&v4(1)).unwrap().retry.count, 2);
        assert!(!store.retry_failed(&v4(9), due), "no record");

        // Closed early again: each time the next retry, then a settled
        // session clears it.
        store.insert_with(v4(1), early(NOW + 10), NOW + 10, &mut rng);
        assert_eq!(store.get(&v4(1)).unwrap().retry.count, 3);
        store.insert_with(v4(1), record(Fingerprint::Known(Family::Core, Confidence::High), NOW + 20), NOW + 20, &mut rng);
        let settled = store.get(&v4(1)).unwrap();
        assert_eq!((settled.verdict, settled.retry), (Verdict::Classified, ClosedEarlyRetry::default()), "reset");
        assert_eq!(settled.first_seen, NOW, "the first sighting is kept");

        // Ten closed-early sessions after the first, then none scheduled.
        store.insert_with(v4(2), early(NOW), NOW, &mut rng);
        for i in 1..=10 {
            store.insert_with(v4(2), early(NOW + i), NOW + i, &mut rng);
        }
        let r = store.get(&v4(2)).unwrap().retry;
        assert_eq!((r.count, r.next_due), (CLOSED_EARLY_RETRIES, None));
        assert!(store.due_retries(NOW + 1_000_000).is_empty());
        assert!(!store.retry_failed(&v4(2), NOW + 1_000_000), "nothing due");
        store.insert_with(v4(2), early(NOW + 100), NOW + 100, &mut rng);
        assert_eq!(store.get(&v4(2)).unwrap().retry.next_due, None, "a later closed-early session does not restart it");
        let agg = store.aggregate();
        assert_eq!((agg.closed_early, agg.retries_pending, agg.retries_exhausted), (1, 0, 1));
        let json = survey_json(&store, true, &serde_json::Value::Null);
        assert_eq!(json["retries"], serde_json::json!({ "pending": 0, "exhausted": 1 }));
        let rows = json["peers"].as_array().unwrap();
        let row = rows.iter().find(|r| r["fingerprint"] == "closed-early").unwrap();
        assert_eq!(row["retry"], serde_json::json!({ "count": 10, "next_due": null }));
        assert!(rows.iter().find(|r| r["fingerprint"] != "closed-early").unwrap().get("retry").is_none());
        // Settled after all: cleared.
        store.insert_with(v4(2), record(Fingerprint::Unknown, NOW + 200), NOW + 200, &mut rng);
        assert_eq!(store.get(&v4(2)).unwrap().retry, ClosedEarlyRetry::default());
        assert_eq!(store.aggregate().retries_exhausted, 0);
    }

    /// Due retries come longest due first, then by address.
    #[test]
    fn due_retries_come_longest_due_first() {
        let mut store = SurveyStore::default();
        for i in 1..=3 {
            store.insert(v4(i), early(NOW), NOW);
        }
        let due = |a: &PeerAddr| store.get(a).unwrap().retry.next_due.unwrap();
        let mut want = vec![v4(1), v4(2), v4(3)];
        want.sort_by_key(|a| (due(a), a.clone()));
        assert_eq!(store.due_retries(NOW + 2_000), want);
    }

    /// A `satdsrv3` file, as the previous build wrote it, keeps every
    /// record and its verdict, each with no retry scheduled; it is the
    /// current format less the ten retry bytes per record, and still
    /// checked whole.
    #[test]
    fn a_satdsrv3_file_keeps_its_records_with_no_retry() {
        let mut store = SurveyStore::default();
        store.insert(v4(1), record(Fingerprint::Known(Family::Core, Confidence::High), NOW), NOW);
        store.insert(v4(2), early(NOW), NOW);
        let mut fake = record(Fingerprint::Known(Family::Core, Confidence::Claimed), NOW);
        fake.verdict = Verdict::Fake(Family::Core);
        store.insert(v4(3), fake, NOW);
        assert!(store.get(&v4(2)).unwrap().retry.pending(), "fixture");
        let old = store.encode_as(MAGIC, 3);
        assert_eq!(&old[..8], b"satdsrv3");
        assert_eq!(old.len() + 10 * store.len(), store.encode(MAGIC).len());
        let back = SurveyStore::decode(&old, MAGIC, NOW, MAX_RECORDS).unwrap();
        assert_eq!((back.len(), back.dropped_old_format()), (3, 0));
        for (addr, r) in store.rows() {
            let b = back.get(addr).unwrap();
            assert_eq!(b, &SurveyRecord { retry: ClosedEarlyRetry::default(), ..r.clone() }, "{addr:?}");
        }
        assert_eq!(back.get(&v4(2)).unwrap().verdict, Verdict::ClosedEarly);
        assert_eq!(back.aggregate().retries_pending, 0);
        assert_eq!(&back.encode(MAGIC)[..8], b"satdsrv4");
        let mut flipped = old.clone();
        flipped[20] ^= 1;
        assert!(SurveyStore::decode(&flipped, MAGIC, NOW, MAX_RECORDS).unwrap_err().contains("checksum"));
        let mut cut = old[..old.len() - 32 - 1].to_vec();
        let sum = sha256d::Hash::hash(&cut);
        cut.extend_from_slice(sum.as_byte_array());
        assert!(SurveyStore::decode(&cut, MAGIC, NOW, MAX_RECORDS).is_err());
    }

    /// A retry schedule out of its range is refused, as a damaged file: a
    /// count past ten, a bad presence byte, a due time with no count, a
    /// time with no presence, or a schedule on a settled record.
    #[test]
    fn a_bad_retry_schedule_is_refused() {
        let mut store = SurveyStore::default();
        store.insert(v4(1), early(NOW), NOW);
        let bytes = store.encode(MAGIC);
        let body = &bytes[..bytes.len() - 32];
        let reseal = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut body = body.to_vec();
            f(&mut body);
            let sum = sha256d::Hash::hash(&body);
            body.extend_from_slice(sum.as_byte_array());
            body
        };
        let n = body.len();
        // The record ends: verdict (2), count, presence, time (8).
        assert_eq!(body[n - 12], 2, "fixture: closed early");
        assert!(SurveyStore::decode(&reseal(&|_| {}), MAGIC, NOW, MAX_RECORDS).is_ok());
        let ten = SurveyStore::decode(&reseal(&|b| b[n - 10] = 10), MAGIC, NOW, MAX_RECORDS).unwrap();
        assert_eq!(ten.get(&v4(1)).unwrap().retry.count, 10);
        for (what, f) in [
            ("count 11", &(|b: &mut Vec<u8>| b[n - 10] = 11) as &dyn Fn(&mut Vec<u8>)),
            ("presence 2", &|b: &mut Vec<u8>| b[n - 9] = 2),
            ("due with no count", &|b: &mut Vec<u8>| b[n - 10] = 0),
            ("time with no presence", &|b: &mut Vec<u8>| b[n - 9] = 0),
            ("on a classified record", &|b: &mut Vec<u8>| b[n - 12] = 0),
        ] {
            let err = SurveyStore::decode(&reseal(f), MAGIC, NOW, MAX_RECORDS).unwrap_err();
            assert!(err.contains("retry"), "{what}: {err}");
        }
    }

    /// A shape out of its bounds is refused, as a damaged file.
    #[test]
    fn a_shape_past_its_bounds_is_refused() {
        let mut store = SurveyStore::default();
        let mut r = record(Fingerprint::Unknown, NOW);
        r.shape = Some(SurveyShape { commands: vec!["version".into()], relay: true });
        store.insert(v4(1), r, NOW);
        let bytes = store.encode(MAGIC);
        // The shape ends the record but for its two verdict bytes and ten
        // retry bytes: tag, relay, count, then `version`.
        let body = &bytes[..bytes.len() - 32 - 12];
        let count_at = body.len() - 1 - "version".len() - 1;
        let verdict = bytes[bytes.len() - 32 - 12..bytes.len() - 32].to_vec();
        let reseal = |mut body: Vec<u8>| {
            body.extend_from_slice(&verdict);
            let sum = sha256d::Hash::hash(&body);
            body.extend_from_slice(sum.as_byte_array());
            body
        };
        let mut many = body.to_vec();
        many[count_at] = (SHAPE_COMMANDS_MAX + 1) as u8;
        assert!(SurveyStore::decode(&reseal(many), MAGIC, NOW, MAX_RECORDS).unwrap_err().contains("commands"));
        let mut tag = body.to_vec();
        tag[count_at - 2] = 7;
        assert!(SurveyStore::decode(&reseal(tag), MAGIC, NOW, MAX_RECORDS).unwrap_err().contains("shape tag"));
        assert!(SurveyStore::decode(&bytes, MAGIC, NOW, MAX_RECORDS).is_ok());
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
        add(Fingerprint::Known(Family::Core, Confidence::Claimed), false, None);
        add(Fingerprint::Known(Family::Btcd, Confidence::Claimed), false, None);
        let mut special = |fp: Fingerprint, verdict: Verdict, ua: &str| {
            let mut r = record(fp, NOW);
            r.verdict = verdict;
            r.user_agent = ua.to_string();
            r.asn = None;
            r.v2 = false;
            i += 1;
            store.insert(v4(i), r, NOW);
        };
        special(Fingerprint::Known(Family::Core, Confidence::Claimed), Verdict::Fake(Family::Core), "/Satoshi:25.0.0/");
        special(Fingerprint::Known(Family::Core, Confidence::Claimed), Verdict::Fake(Family::Core), "/Satoshi:25.1.0/");
        special(Fingerprint::Unknown, Verdict::ClosedEarly, "/Satoshi:28.1.0/");
        let agg = store.aggregate();
        assert_eq!(agg.addresses, 9);
        assert_eq!(agg.families[0], 2, "core, observed only: a claim or a fake is never counted as the family");
        assert_eq!(agg.families[1], 1, "btcd, observed");
        assert_eq!((agg.unknown, agg.mismatches, agg.v2), (1, 1, 2), "unknown: neither claimed, fake nor closed early");
        assert_eq!(agg.claimed[0], 1, "core, claimed: the fakes are not");
        assert_eq!(agg.claimed[1], 1, "btcd, claimed");
        assert_eq!(agg.claimed.iter().sum::<usize>(), 2);
        assert_eq!(agg.fake[0], 2, "core, fake");
        assert_eq!(agg.fake.iter().sum::<usize>(), 2);
        assert_eq!(agg.closed_early, 1);
        let counted = agg.families.iter().sum::<usize>()
            + agg.unknown
            + agg.claimed.iter().sum::<usize>()
            + agg.fake.iter().sum::<usize>()
            + agg.closed_early;
        assert_eq!(counted, agg.addresses, "each record in exactly one tally");
        assert_eq!(agg.top_as, vec![(1, 2), (2, 1)]);

        let json = survey_json(&store, true, &serde_json::json!({ "enabled": true }));
        assert_eq!(json["families"]["core"]["count"], 2);
        assert_eq!(json["families"]["core"]["share"], 2.0 / 9.0);
        assert_eq!(json["families"]["unknown"]["count"], 1);
        assert_eq!(json["claimed"]["core"]["count"], 1);
        assert_eq!(json["claimed"]["btcd"]["count"], 1);
        assert_eq!(json["claimed"]["satd"]["count"], 0);
        assert!(json["claimed"].get("unknown").is_none());
        assert_eq!(json["fake"]["core"]["count"], 2);
        assert_eq!(json["fake"]["core"]["share"], 2.0 / 9.0, "shares are of all records");
        assert_eq!(json["fake"]["btcd"]["count"], 0);
        assert!(json["fake"].get("unknown").is_none());
        assert_eq!(json["closed_early"]["count"], 1);
        assert_eq!(json["closed_early"]["share"], 1.0 / 9.0);
        assert_eq!(json["enabled"], true);
        let peers = json["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 9);
        let claimed_row = peers.iter().find(|p| p["fingerprint"] == "core/claimed").unwrap();
        assert_eq!(claimed_row["family"], serde_json::Value::Null, "a claim is no observed family");
        assert_eq!(claimed_row["claimed"], "core");
        let fake_rows: Vec<_> = peers.iter().filter(|p| p["fingerprint"] == "fake/core").collect();
        assert_eq!(fake_rows.len(), 2);
        assert_eq!(fake_rows[0]["family"], serde_json::Value::Null, "a fake is no observed family");
        assert_eq!(fake_rows[0]["claimed"], "core");
        let early = peers.iter().find(|p| p["fingerprint"] == "closed-early").unwrap();
        assert_eq!(early["family"], serde_json::Value::Null);
        assert_eq!(early["claimed"], "core", "the user agent's claim is kept");
        assert_eq!(early["subver"], "/Satoshi:28.1.0/");
        assert!(survey_json(&store, false, &serde_json::Value::Null).get("peers").is_none());
    }

    fn capture_of(commands: &[&str]) -> crate::net::behavior::HandshakeCapture {
        let mut c = crate::net::behavior::HandshakeCapture::default();
        for cmd in commands {
            c.observe(cmd, false);
        }
        c
    }

    fn transcript(commands: &[&str]) -> Vec<String> {
        commands.iter().map(|c| c.to_string()).collect()
    }

    const CORE_25: &str = "/Satoshi:25.0.0/";
    const BARE: &[&str] = &["version", "verack"];

    /// The fake rule holds for a Core user agent at a common version of
    /// 70016, a transcript of exactly `version`, `verack`, and a wait that
    /// timed out; each condition turned the other way breaks it.
    #[test]
    fn the_fake_core_rule_needs_every_condition() {
        let bare = transcript(BARE);
        assert!(is_fake_core(CORE_25, 70016, 70016, &bare, PassiveEnd::Timeout));
        assert!(is_fake_core("/Satoshi:25.1.0/", 70016, 70016, &bare, PassiveEnd::Timeout));
        assert!(is_fake_core("/Satoshi:28.1.0/Knots:20250305/", 70016, 70016, &bare, PassiveEnd::Timeout), "Knots is Core");
        assert!(is_fake_core(CORE_25, 70017, 70016, &bare, PassiveEnd::Timeout), "the common version is ours");

        // A user agent naming another family, or none.
        assert!(!is_fake_core("/btcwire:0.5.0/btcd:0.24.2/", 70016, 70016, &bare, PassiveEnd::Timeout), "btcd");
        assert!(!is_fake_core("/satd:0.8.0/", 70016, 70016, &bare, PassiveEnd::Timeout), "satd");
        assert!(!is_fake_core("/something:1.0/", 70016, 70016, &bare, PassiveEnd::Timeout), "no family");
        // A common version below 70016, on either side.
        assert!(!is_fake_core(CORE_25, 70015, 70016, &bare, PassiveEnd::Timeout), "theirs 70015");
        assert!(!is_fake_core(CORE_25, 70016, 70015, &bare, PassiveEnd::Timeout), "ours 70015");
        // A transcript with a negotiation message, or anything more.
        for t in [
            &["version", "wtxidrelay", "verack"][..],
            &["version", "sendaddrv2", "verack"],
            &["version", "wtxidrelay", "sendaddrv2", "verack"],
            &["version", "verack", "ping"],
            &["version"],
        ] {
            assert!(!is_fake_core(CORE_25, 70016, 70016, &transcript(t), PassiveEnd::Timeout), "{t:?}");
        }
        // A wait that did not time out.
        assert!(!is_fake_core(CORE_25, 70016, 70016, &bare, PassiveEnd::PeerClosed), "the peer closed");
        assert!(!is_fake_core(CORE_25, 70016, 70016, &bare, PassiveEnd::Settled), "settled");
    }

    /// The verdict a session gets: the peer closing on an open transcript
    /// is closed early, whatever the user agent; the fake rule is fake;
    /// the rest keep their fingerprint, and a wait the node cut short is
    /// never judged.
    #[test]
    fn the_session_verdict() {
        let bare = capture_of(BARE);
        let negotiated = capture_of(&["version", "wtxidrelay", "sendaddrv2", "verack"]);
        let settled = capture_of(&["version", "wtxidrelay", "sendaddrv2", "verack", "sendcmpct", "ping"]);
        assert!(bare.is_open() && negotiated.is_open() && !settled.is_open(), "fixture");
        let v = |p, c, ua, theirs| session_verdict(p, c, ua, theirs, 70016);

        assert_eq!(v(Some(PassiveEnd::Timeout), &bare, CORE_25, 70016), Verdict::Fake(Family::Core));
        assert_eq!(v(Some(PassiveEnd::PeerClosed), &bare, CORE_25, 70016), Verdict::ClosedEarly, "closed early, not fake");
        assert_eq!(v(Some(PassiveEnd::PeerClosed), &negotiated, "/Satoshi:32.1.0/", 70016), Verdict::ClosedEarly);
        assert_eq!(v(Some(PassiveEnd::PeerClosed), &negotiated, "/btcwire:0.5.0/btcd:0.27.0/", 70016), Verdict::ClosedEarly);
        assert_eq!(v(Some(PassiveEnd::PeerClosed), &negotiated, "", 70016), Verdict::ClosedEarly, "with no user agent");
        // The peer closing once its transcript has settled is judged as it is.
        assert_eq!(v(Some(PassiveEnd::PeerClosed), &settled, "/Satoshi:32.1.0/", 70016), Verdict::Classified);
        assert_eq!(v(Some(PassiveEnd::Settled), &settled, "/Satoshi:32.1.0/", 70016), Verdict::Classified);
        // A timeout on a negotiated transcript (btcd's shape) is no fake.
        assert_eq!(v(Some(PassiveEnd::Timeout), &negotiated, CORE_25, 70016), Verdict::Classified);
        assert_eq!(v(Some(PassiveEnd::Timeout), &bare, "/btcwire:0.5.0/btcd:0.27.0/", 70016), Verdict::Classified);
        assert_eq!(v(Some(PassiveEnd::Timeout), &bare, CORE_25, 70015), Verdict::Classified);
        // The node cut the wait short: no verdict.
        assert_eq!(v(None, &bare, CORE_25, 70016), Verdict::Classified);
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
