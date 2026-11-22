//! What each peer does on the wire, kept per peer in fixed-size counters.
//!
//! A [`PeerBehavior`] rides on [`crate::net::peer::PeerInfo`] and is updated
//! by the message handlers that already touch the peer. It records, it does
//! not judge: nothing here changes how a peer is treated, and nothing reads
//! it yet beyond the debug line written when the peer goes. Its size is fixed
//! when the peer connects: counters, a handshake transcript of at most
//! [`HANDSHAKE_CAPTURE_MAX`] commands, a ring of the last
//! [`ANNOUNCE_RING`] transactions announced to the peer, and a histogram of
//! [`LATENCY_BUCKETS`] buckets. No message makes it grow.

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;

/// The most commands the handshake transcript keeps.
pub const HANDSHAKE_CAPTURE_MAX: usize = 16;

/// The longest message command on the wire (the header's command field).
const COMMAND_LEN: usize = 12;

/// How many of the transactions announced to a peer are remembered, with
/// when, to time the peer's `getdata` for them.
pub const ANNOUNCE_RING: usize = 128;

/// Upper bounds of the `getdata` latency buckets, in milliseconds. A last
/// bucket takes everything slower.
pub const LATENCY_BOUNDS_MS: [u64; 12] = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1_000, 2_000, 5_000];

/// Number of `getdata` latency buckets.
pub const LATENCY_BUCKETS: usize = LATENCY_BOUNDS_MS.len() + 1;

/// The messages a peer sends once, at connection setup, to say what it
/// supports or wants: `wtxidrelay` (BIP 339), `sendaddrv2` (BIP 155),
/// `sendtxrcncl` (BIP 330), `sendheaders` (BIP 130), `sendcmpct` (BIP 152)
/// and `feefilter` (BIP 133). The transcript runs past `verack` while the
/// peer sends these, and ends at the first message that is not one.
pub fn is_handshake_announcement(command: &str) -> bool {
    matches!(command, "wtxidrelay" | "sendaddrv2" | "sendtxrcncl" | "sendheaders" | "sendcmpct" | "feefilter")
}

/// A message's command as it came over the wire: the peer's own text for a
/// type satd does not decode.
pub fn wire_command(msg: &NetworkMessage) -> &str {
    match msg {
        NetworkMessage::Unknown { command, .. } => command.as_ref(),
        m => m.cmd(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureState {
    /// Nothing recorded: waiting for the peer's `version`.
    Waiting,
    /// Recording from `version` up to the peer's `verack`.
    Handshake,
    /// Past `verack`, recording while the peer sends announcements.
    Announcing,
    /// Done.
    Closed,
}

/// The ordered commands a peer sent from its `version` through the first
/// message after its `verack` that is not a handshake-phase announcement
/// ([`is_handshake_announcement`]), at most [`HANDSHAKE_CAPTURE_MAX`].
///
/// Replies to our own requests (a `pong`, and a `headers` or `notfound`
/// while we have a request out to the peer) are neither recorded nor end
/// the transcript: where they fall depends on timing, not on the peer.
#[derive(Clone)]
pub struct HandshakeCapture {
    commands: [[u8; COMMAND_LEN]; HANDSHAKE_CAPTURE_MAX],
    len: u8,
    state: CaptureState,
}

impl Default for HandshakeCapture {
    fn default() -> Self {
        Self { commands: [[0; COMMAND_LEN]; HANDSHAKE_CAPTURE_MAX], len: 0, state: CaptureState::Waiting }
    }
}

impl HandshakeCapture {
    /// Take one received message's command; `reply` is whether it answers a
    /// request of ours. Returns whether the transcript is still open.
    pub fn observe(&mut self, command: &str, reply: bool) -> bool {
        match self.state {
            CaptureState::Closed => return false,
            CaptureState::Waiting if command != "version" => return true,
            _ => {}
        }
        if reply {
            return true;
        }
        let mut word = [0u8; COMMAND_LEN];
        let bytes = command.as_bytes();
        let n = bytes.len().min(COMMAND_LEN);
        word[..n].copy_from_slice(&bytes[..n]);
        self.commands[usize::from(self.len)] = word;
        self.len += 1;
        self.state = match self.state {
            _ if usize::from(self.len) >= HANDSHAKE_CAPTURE_MAX => CaptureState::Closed,
            CaptureState::Waiting => CaptureState::Handshake,
            CaptureState::Handshake if command == "verack" => CaptureState::Announcing,
            CaptureState::Announcing if !is_handshake_announcement(command) => CaptureState::Closed,
            s => s,
        };
        self.is_open()
    }

    /// Whether more commands may still be recorded.
    pub fn is_open(&self) -> bool {
        self.state != CaptureState::Closed
    }

    /// The recorded commands, in order. A command that is not printable
    /// ASCII is shown with `?` in its place: it is the peer's own text.
    pub fn commands(&self) -> impl Iterator<Item = String> + '_ {
        self.commands[..usize::from(self.len)].iter().map(|word| {
            word.iter()
                .take_while(|b| **b != 0)
                .map(|b| if b.is_ascii_graphic() { char::from(*b) } else { '?' })
                .collect()
        })
    }

    /// How many commands are recorded.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Whether nothing is recorded.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for HandshakeCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.commands()).finish()
    }
}

/// The fields of the peer's `version` the transcript keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionFields {
    pub protocol_version: u32,
    pub services: u64,
    pub relay: bool,
    pub start_height: i32,
    /// Sanitized as `getpeerinfo.subver` is, and at most
    /// `MAX_SUBVERSION_LENGTH` bytes: a longer one is never accepted.
    pub user_agent: String,
}

/// A fixed histogram of delays, bucketed by [`LATENCY_BOUNDS_MS`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LatencyHistogram {
    buckets: [u32; LATENCY_BUCKETS],
}

impl LatencyHistogram {
    /// Count one delay.
    pub fn record(&mut self, delay: Duration) {
        let ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
        // A bound is inclusive above: under 1 ms goes in the first bucket.
        let i = LATENCY_BOUNDS_MS.iter().position(|bound| ms < *bound).unwrap_or(LATENCY_BOUNDS_MS.len());
        self.buckets[i] = self.buckets[i].saturating_add(1);
    }

    /// Delays counted.
    pub fn count(&self) -> u64 {
        self.buckets.iter().map(|n| u64::from(*n)).sum()
    }

    /// The bucket counts, fastest first.
    pub fn buckets(&self) -> &[u32; LATENCY_BUCKETS] {
        &self.buckets
    }

    /// The upper bound, in milliseconds, of the bucket holding quantile `q`
    /// (0 < q ≤ 1), or `None` with nothing counted. The last bucket has no
    /// bound and reports `u64::MAX`.
    pub fn quantile_ms(&self, q: f64) -> Option<u64> {
        let total = self.count();
        if total == 0 {
            return None;
        }
        let rank = ((q * total as f64).ceil() as u64).clamp(1, total);
        let mut seen = 0;
        for (i, n) in self.buckets.iter().enumerate() {
            seen += u64::from(*n);
            if seen >= rank {
                return Some(LATENCY_BOUNDS_MS.get(i).copied().unwrap_or(u64::MAX));
            }
        }
        None
    }

    /// The median's bucket bound, in milliseconds.
    pub fn median_ms(&self) -> Option<u64> {
        self.quantile_ms(0.5)
    }

    /// The 10th percentile's bucket bound, in milliseconds.
    pub fn p10_ms(&self) -> Option<u64> {
        self.quantile_ms(0.1)
    }
}

/// The last [`ANNOUNCE_RING`] transactions announced to a peer, by a salted
/// 64-bit key of the hash announced, with when. The oldest is overwritten
/// first; one the peer asks for is taken out.
struct AnnounceRing {
    slots: Box<[(u64, Option<Instant>); ANNOUNCE_RING]>,
    next: usize,
    salt: RandomState,
}

impl Default for AnnounceRing {
    fn default() -> Self {
        Self { slots: Box::new([(0, None); ANNOUNCE_RING]), next: 0, salt: RandomState::new() }
    }
}

impl fmt::Debug for AnnounceRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let held = self.slots.iter().filter(|(_, at)| at.is_some()).count();
        f.debug_struct("AnnounceRing").field("held", &held).finish()
    }
}

impl AnnounceRing {
    fn key(&self, hash: &[u8; 32]) -> u64 {
        let mut h = self.salt.build_hasher();
        h.write(hash);
        h.finish()
    }

    fn insert(&mut self, hash: &[u8; 32], at: Instant) {
        let key = self.key(hash);
        self.slots[self.next] = (key, Some(at));
        self.next = (self.next + 1) % ANNOUNCE_RING;
    }

    fn take(&mut self, hash: &[u8; 32]) -> Option<Instant> {
        let key = self.key(hash);
        self.slots.iter_mut().find(|(k, at)| *k == key && at.is_some()).and_then(|(_, at)| at.take())
    }

    fn held(&self) -> usize {
        self.slots.iter().filter(|(_, at)| at.is_some()).count()
    }
}

/// The hash a transaction entry of an `inv`, `getdata` or `notfound` names.
fn tx_hash(inv: &Inventory) -> Option<[u8; 32]> {
    match inv {
        Inventory::Transaction(t) | Inventory::WitnessTransaction(t) => Some(t.to_byte_array()),
        Inventory::WTx(w) => Some(w.to_byte_array()),
        _ => None,
    }
}

/// Whether an `inv` or `getdata` entry names a block.
fn is_block(inv: &Inventory) -> bool {
    matches!(inv, Inventory::Block(_) | Inventory::WitnessBlock(_) | Inventory::CompactBlock(_))
}

/// One peer's record. See the module documentation.
#[derive(Debug, Default)]
pub struct PeerBehavior {
    /// The handshake transcript.
    pub handshake: HandshakeCapture,
    /// The peer's `version` fields, once it has sent one.
    pub version: Option<VersionFields>,
    /// Transactions the peer announced to us (`inv` entries).
    pub inv_tx_in: u64,
    /// Transactions the peer asked us for (`getdata` entries).
    pub getdata_tx_in: u64,
    /// Delay between our `inv` and the peer's `getdata` for the same
    /// transaction.
    pub getdata_latency: LatencyHistogram,
    /// Transactions we announced to the peer.
    pub inv_tx_announced_to: u64,
    /// `getheaders` the peer sent.
    pub headers_req: u64,
    /// Blocks the peer asked for: `getdata` block entries and `getblocktxn`.
    pub blocks_req: u64,
    /// `getaddr` the peer sent.
    pub getaddr_in: u64,
    /// Addresses the peer sent us, in `addr` and `addrv2`.
    pub addr_in: u64,
    /// Addresses we sent the peer.
    pub addr_out: u64,
    /// Transactions the peer announced, was asked for, and answered
    /// `notfound` for.
    pub notfound_after_inv: u64,
    /// The largest amount by which the peer's `start_height` exceeded the
    /// chain it then served, measured when it answered a `getheaders` with
    /// fewer than `MAX_HEADERS_RESULTS` headers.
    pub height_claim_gap: u32,
    /// Block-download stalls: heights it was asked for and did not deliver
    /// while other peers did, and a stall disconnect.
    pub stalls: u32,
    /// Why the connection ended, once it has.
    pub disconnect_reason: Option<&'static str>,
    /// Whether `start_height` was above our tip when the peer connected.
    /// The gap is measured only then: a claim at or below our tip is one
    /// our own chain already covers.
    pub claim_above_tip: bool,
    /// The height of the first hash of the last `getheaders` locator we
    /// sent the peer: where an empty answer says its chain ends.
    pub last_locator_top: Option<u32>,
    announced: AnnounceRing,
}

impl PeerBehavior {
    /// The peer's `version` arrived, with our tip's height then.
    pub fn note_version(&mut self, version: &bitcoin::p2p::message_network::VersionMessage, our_tip: u32) {
        self.version = Some(VersionFields {
            protocol_version: version.version,
            services: version.services.to_u64(),
            relay: version.relay,
            start_height: version.start_height,
            user_agent: crate::net::limits::sanitize_string(&version.user_agent),
        });
        self.claim_above_tip = i64::from(version.start_height) > i64::from(our_tip);
    }

    /// Whether [`Self::note_received`] counts anything for `msg`, so a
    /// caller takes the peer's lock only for those.
    pub fn counts(msg: &NetworkMessage) -> bool {
        matches!(
            msg,
            NetworkMessage::Inv(_)
                | NetworkMessage::GetData(_)
                | NetworkMessage::GetHeaders(_)
                | NetworkMessage::GetBlockTxn(_)
                | NetworkMessage::GetAddr
                | NetworkMessage::Addr(_)
                | NetworkMessage::AddrV2(_)
        )
    }

    /// Count a message the peer sent, received at `now`.
    pub fn note_received(&mut self, msg: &NetworkMessage, now: Instant) {
        match msg {
            NetworkMessage::Inv(inv) => {
                let txs = inv.iter().filter(|i| tx_hash(i).is_some()).count();
                self.inv_tx_in = self.inv_tx_in.saturating_add(txs as u64);
            }
            NetworkMessage::GetData(inv) => {
                for i in inv {
                    if let Some(hash) = tx_hash(i) {
                        self.getdata_tx_in = self.getdata_tx_in.saturating_add(1);
                        if let Some(at) = self.announced.take(&hash) {
                            self.getdata_latency.record(now.saturating_duration_since(at));
                        }
                    } else if is_block(i) {
                        self.blocks_req = self.blocks_req.saturating_add(1);
                    }
                }
            }
            NetworkMessage::GetHeaders(_) => self.headers_req = self.headers_req.saturating_add(1),
            NetworkMessage::GetBlockTxn(_) => self.blocks_req = self.blocks_req.saturating_add(1),
            NetworkMessage::GetAddr => self.getaddr_in = self.getaddr_in.saturating_add(1),
            NetworkMessage::Addr(a) => self.addr_in = self.addr_in.saturating_add(a.len() as u64),
            NetworkMessage::AddrV2(a) => self.addr_in = self.addr_in.saturating_add(a.len() as u64),
            _ => {}
        }
    }

    /// We announced the transaction `hash` (by the id the peer relays by)
    /// to the peer at `now`.
    pub fn note_tx_announced(&mut self, hash: &[u8; 32], now: Instant) {
        self.inv_tx_announced_to = self.inv_tx_announced_to.saturating_add(1);
        self.announced.insert(hash, now);
    }

    /// We sent the peer `count` addresses.
    pub fn note_addrs_sent(&mut self, count: usize) {
        self.addr_out = self.addr_out.saturating_add(count as u64);
    }

    /// The peer answered `notfound` for `count` transactions it had
    /// announced and been asked for.
    pub fn note_notfound_after_inv(&mut self, count: usize) {
        self.notfound_after_inv = self.notfound_after_inv.saturating_add(count as u64);
    }

    /// The peer answered a `getheaders` with fewer than
    /// `MAX_HEADERS_RESULTS` headers: its chain ends at `served`, the most
    /// it has shown us. Keeps the largest shortfall against `start_height`.
    pub fn note_headers_served(&mut self, served: u32) {
        if !self.claim_above_tip {
            return;
        }
        let Some(claimed) = self.version.as_ref().map(|v| v.start_height) else {
            return;
        };
        let gap = (i64::from(claimed) - i64::from(served)).clamp(0, i64::from(u32::MAX)) as u32;
        self.height_claim_gap = self.height_claim_gap.max(gap);
    }

    /// The block download charged the peer with a stall.
    pub fn note_stall(&mut self) {
        self.stalls = self.stalls.saturating_add(1);
    }

    /// Transactions announced to the peer whose `getdata` has not yet come.
    pub fn announced_held(&self) -> usize {
        self.announced.held()
    }
}

impl fmt::Display for PeerBehavior {
    /// The one-line form written when the peer goes. No address: the caller
    /// names the peer by id.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let handshake: Vec<String> = self.handshake.commands().collect();
        write!(f, "handshake=[{}]", handshake.join(","))?;
        if let Some(v) = &self.version {
            write!(
                f,
                " version={} services={:016x} relay={} start_height={} subver={:?}",
                v.protocol_version, v.services, v.relay, v.start_height, v.user_agent
            )?;
        }
        let ms = |q: Option<u64>| q.map_or_else(|| "-".to_string(), |v| v.to_string());
        write!(
            f,
            " inv_tx_in={} getdata_tx_in={} getdata_latency_ms(p10={} median={} n={}) inv_tx_announced_to={} \
             headers_req={} blocks_req={} getaddr_in={} addr_in={} addr_out={} notfound_after_inv={} \
             height_claim_gap={} stalls={} disconnect_reason={}",
            self.inv_tx_in,
            self.getdata_tx_in,
            ms(self.getdata_latency.p10_ms()),
            ms(self.getdata_latency.median_ms()),
            self.getdata_latency.count(),
            self.inv_tx_announced_to,
            self.headers_req,
            self.blocks_req,
            self.getaddr_in,
            self.addr_in,
            self.addr_out,
            self.notfound_after_inv,
            self.height_claim_gap,
            self.stalls,
            self.disconnect_reason.unwrap_or("-"),
        )
    }
}

/// A capture under `contrib/peer-fingerprint/fixtures`, replayed through
/// the handshake capture as the node would take it.
#[cfg(test)]
pub(crate) struct Replayed {
    pub capture: HandshakeCapture,
    pub version: Option<VersionFields>,
    /// The peer dialed the recorder (the fixture's `connection`).
    pub inbound: bool,
}

#[cfg(test)]
fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../contrib/peer-fingerprint/fixtures")
}

/// The fixtures' names, without `.json`, sorted.
#[cfg(test)]
pub(crate) fn fixture_names() -> Vec<String> {
    let dir = fixture_dir();
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".json").map(str::to_string))
        .collect();
    names.sort();
    names
}

/// Replay one fixture. The recorder's own requests are in its `sent` list,
/// so a `headers` or `notfound` received while one of its `getheaders` or
/// `getdata` was unanswered is a reply, as is every `pong`.
#[cfg(test)]
pub(crate) fn replay_fixture(name: &str) -> Replayed {
    let text = std::fs::read_to_string(fixture_dir().join(format!("{name}.json"))).unwrap();
    let fixture: serde_json::Value = serde_json::from_str(&text).unwrap();
    // (time, sent first on a tie, command)
    let mut events: Vec<(u64, bool, String)> = Vec::new();
    for (key, sent) in [("sent", true), ("received", false)] {
        for m in fixture[key].as_array().unwrap() {
            events.push((m["t_ms"].as_u64().unwrap(), !sent, m["command"].as_str().unwrap().to_string()));
        }
    }
    events.sort_by_key(|(t, received, _)| (*t, *received));
    let (mut getheaders_out, mut getdata_out) = (0u32, 0u32);
    let mut capture = HandshakeCapture::default();
    for (_, received, cmd) in &events {
        if !received {
            match cmd.as_str() {
                "getheaders" => getheaders_out += 1,
                "getdata" => getdata_out += 1,
                _ => {}
            }
            continue;
        }
        let reply = match cmd.as_str() {
            "pong" => true,
            "headers" if getheaders_out > 0 => {
                getheaders_out -= 1;
                true
            }
            "notfound" if getdata_out > 0 => {
                getdata_out -= 1;
                true
            }
            _ => false,
        };
        capture.observe(cmd, reply);
    }
    let v = &fixture["version"];
    let version = v.is_object().then(|| VersionFields {
        protocol_version: v["protocol_version"].as_u64().unwrap() as u32,
        services: v["services"].as_u64().unwrap(),
        relay: v["relay"].as_bool().unwrap(),
        start_height: v["start_height"].as_i64().unwrap() as i32,
        user_agent: crate::net::limits::sanitize_string(v["user_agent"].as_str().unwrap()),
    });
    Replayed { capture, version, inbound: fixture["connection"] == "inbound" }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(seq: &[(&str, bool)]) -> Vec<String> {
        let mut c = HandshakeCapture::default();
        for (cmd, reply) in seq {
            c.observe(cmd, *reply);
        }
        c.commands().collect()
    }

    #[test]
    fn the_transcript_starts_at_version_and_ends_after_the_announcements() {
        let got = capture(&[
            ("ping", false),
            ("version", false),
            ("wtxidrelay", false),
            ("sendaddrv2", false),
            ("verack", false),
            ("sendheaders", false),
            ("sendcmpct", false),
            ("getheaders", false),
            ("feefilter", false),
            ("getaddr", false),
        ]);
        assert_eq!(got, ["version", "wtxidrelay", "sendaddrv2", "verack", "sendheaders", "sendcmpct", "getheaders"]);
    }

    #[test]
    fn replies_are_neither_recorded_nor_end_the_transcript() {
        let got = capture(&[
            ("version", false),
            ("verack", false),
            ("pong", true),
            ("headers", true),
            ("feefilter", false),
            ("getaddr", false),
        ]);
        assert_eq!(got, ["version", "verack", "feefilter", "getaddr"]);
    }

    #[test]
    fn anything_before_verack_is_recorded() {
        // Core ignores a non-negotiation message before `verack`, but the
        // peer sent it, and it is the kind of thing that tells peers apart.
        let got = capture(&[("version", false), ("getaddr", false), ("verack", false), ("ping", false)]);
        assert_eq!(got, ["version", "getaddr", "verack", "ping"]);
    }

    /// The transcript stops at 16 commands, however long the peer keeps
    /// announcing, and a closed one takes nothing more.
    #[test]
    fn the_transcript_is_bounded() {
        let mut c = HandshakeCapture::default();
        c.observe("version", false);
        c.observe("verack", false);
        for _ in 0..1_000 {
            c.observe("feefilter", false);
        }
        assert_eq!(c.len(), HANDSHAKE_CAPTURE_MAX);
        assert!(!c.is_open());
        assert!(!c.observe("version", false));
        assert_eq!(c.len(), HANDSHAKE_CAPTURE_MAX);
    }

    #[test]
    fn an_unprintable_command_is_shown_escaped() {
        let mut c = HandshakeCapture::default();
        c.observe("version", false);
        c.observe("verack", false);
        c.observe("ab\ncd", false);
        assert_eq!(c.commands().collect::<Vec<_>>(), ["version", "verack", "ab?cd"]);
    }

    /// The announcement ring holds at most 128 entries however many are
    /// announced, and an entry the peer asks for is taken out.
    #[test]
    fn the_announcement_ring_is_bounded() {
        let mut b = PeerBehavior::default();
        let t0 = Instant::now();
        for i in 0..10_000u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_le_bytes());
            b.note_tx_announced(&h, t0);
        }
        assert_eq!(b.announced_held(), ANNOUNCE_RING);
        assert_eq!(b.inv_tx_announced_to, 10_000);
        // The newest is still held, the oldest gone.
        let mut newest = [0u8; 32];
        newest[..4].copy_from_slice(&9_999u32.to_le_bytes());
        let oldest = [0u8; 32];
        let getdata = |h: [u8; 32]| {
            NetworkMessage::GetData(vec![Inventory::WTx(bitcoin::Wtxid::from_byte_array(h))])
        };
        b.note_received(&getdata(oldest), t0);
        assert_eq!(b.getdata_latency.count(), 0, "the oldest announcement was overwritten");
        b.note_received(&getdata(newest), t0 + Duration::from_millis(3));
        assert_eq!(b.getdata_latency.count(), 1);
        assert_eq!(b.announced_held(), ANNOUNCE_RING - 1);
        // Asked again: nothing left to pair with.
        b.note_received(&getdata(newest), t0 + Duration::from_millis(9));
        assert_eq!(b.getdata_latency.count(), 1);
        assert_eq!(b.getdata_tx_in, 3);
    }

    #[test]
    fn latency_quantiles_come_from_the_bucket_bounds() {
        let mut h = LatencyHistogram::default();
        assert_eq!(h.median_ms(), None);
        // Nine fast, one slow: p10 and the median are in the fast bucket.
        for _ in 0..9 {
            h.record(Duration::from_micros(300));
        }
        h.record(Duration::from_secs(30));
        assert_eq!(h.p10_ms(), Some(1));
        assert_eq!(h.median_ms(), Some(1));
        assert_eq!(h.quantile_ms(1.0), Some(u64::MAX));
        assert_eq!(h.buckets()[0], 9);
        assert_eq!(h.buckets()[LATENCY_BUCKETS - 1], 1);
        // Bounds are exclusive above: 5 ms is in the (5, 10] bucket.
        let mut h = LatencyHistogram::default();
        h.record(Duration::from_millis(5));
        assert_eq!(h.median_ms(), Some(10));
    }

    #[test]
    fn the_height_gap_is_measured_only_for_a_claim_above_our_tip() {
        let version = |start_height| bitcoin::p2p::message_network::VersionMessage {
            version: 70016,
            services: bitcoin::p2p::ServiceFlags::NONE,
            timestamp: 0,
            receiver: bitcoin::p2p::Address::new(&"0.0.0.0:0".parse().unwrap(), bitcoin::p2p::ServiceFlags::NONE),
            sender: bitcoin::p2p::Address::new(&"0.0.0.0:0".parse().unwrap(), bitcoin::p2p::ServiceFlags::NONE),
            nonce: 0,
            user_agent: "/x/".into(),
            start_height,
            relay: true,
        };
        let mut b = PeerBehavior::default();
        b.note_version(&version(1_000), 100);
        b.note_headers_served(400);
        b.note_headers_served(900);
        assert_eq!(b.height_claim_gap, 600, "the largest gap is kept");
        b.note_headers_served(1_200);
        assert_eq!(b.height_claim_gap, 600);

        let mut b = PeerBehavior::default();
        b.note_version(&version(100), 100);
        b.note_headers_served(0);
        assert_eq!(b.height_claim_gap, 0, "a claim at our tip is not measured");
    }

    /// Fixture replay: the handshake capture of every capture under
    /// `contrib/peer-fingerprint/fixtures` gives the transcript listed here.
    /// The recorder's own requests are in each fixture's `sent` list, so a
    /// `headers` or `notfound` received while one of its `getheaders` or
    /// `getdata` was unanswered is a reply, as is every `pong`.
    #[test]
    fn the_fingerprint_fixtures_replay_through_the_handshake_capture() {
        const EXPECTED: &[(&str, &str)] = &[
            ("bcoin-2.2.0-inbound-v2", "version verack addr"),
            ("bcoin-2.2.0-inbound", "version verack addr"),
            ("bcoin-2.2.0-outbound-v2", ""),
            ("bcoin-2.2.0-outbound", "version verack addr"),
            ("bitcoin-seeder-92d2b46-inbound-v2", "version verack getaddr"),
            ("bitcoin-seeder-92d2b46-inbound", "version verack getaddr"),
            ("bitnodes-036dc5c-inbound-v2", "version sendaddrv2 verack getaddr"),
            ("bitnodes-036dc5c-inbound", "version sendaddrv2 verack getaddr"),
            ("btcd-0.27.0-inbound-v2", "version sendaddrv2 verack getaddr"),
            ("btcd-0.27.0-inbound", "version sendaddrv2 verack getaddr"),
            ("btcd-0.27.0-outbound-v2", ""),
            ("btcd-0.27.0-outbound", "version sendaddrv2 verack"),
            ("core-31.2-inbound-s2", "version wtxidrelay sendaddrv2 verack getaddr"),
            ("core-31.2-inbound-v2-s2", "version wtxidrelay sendaddrv2 verack getaddr"),
            ("core-31.2-inbound-v2", "version wtxidrelay sendaddrv2 verack getaddr"),
            ("core-31.2-inbound", "version wtxidrelay sendaddrv2 verack getaddr"),
            ("core-31.2-outbound-v2", "version wtxidrelay sendaddrv2 verack sendcmpct ping"),
            ("core-31.2-outbound", "version wtxidrelay sendaddrv2 verack sendcmpct ping"),
            ("floresta-0.9.1-inbound-s2", "version sendaddrv2 verack getaddr"),
            ("floresta-0.9.1-inbound-v2", "version sendaddrv2 verack feefilter getaddr"),
            ("floresta-0.9.1-inbound", "version sendaddrv2 verack getaddr"),
            ("knots-29.4.3.knots20260508-inbound-s2", "version wtxidrelay sendaddrv2 verack getaddr"),
            ("knots-29.4.3.knots20260508-inbound-v2-s2", "version wtxidrelay sendaddrv2 verack getaddr"),
            ("knots-29.4.3.knots20260508-inbound-v2", "version wtxidrelay sendaddrv2 verack getaddr"),
            ("knots-29.4.3.knots20260508-inbound", "version wtxidrelay sendaddrv2 verack getaddr"),
            ("knots-29.4.3.knots20260508-outbound-v2", "version wtxidrelay sendaddrv2 verack sendcmpct ping"),
            ("knots-29.4.3.knots20260508-outbound", "version wtxidrelay sendaddrv2 verack sendcmpct ping"),
            ("libbitcoin-3.8.0-inbound-s2", "version verack"),
            ("libbitcoin-3.8.0-inbound-v2-s2", "version verack"),
            ("libbitcoin-3.8.0-inbound-v2", "version verack"),
            ("libbitcoin-3.8.0-inbound", "version verack"),
            ("libbitcoin-3.8.0-outbound-v2", ""),
            ("libbitcoin-3.8.0-outbound", "version verack"),
            ("rbitcoin-0.8.0-inbound-v2-s2", "version wtxidrelay sendaddrv2 verack sendheaders sendcmpct ping"),
            ("rbitcoin-0.8.0-inbound-v2", "version wtxidrelay sendaddrv2 verack"),
            ("rbitcoin-0.8.0-inbound", ""),
            ("rbitcoin-0.8.0-outbound-v2", "version wtxidrelay sendaddrv2 verack sendheaders sendcmpct ping"),
            ("rbitcoin-0.8.0-outbound", ""),
            ("satd-0.7.0-inbound-s2", "version wtxidrelay sendaddrv2 verack sendheaders getheaders"),
            ("satd-0.7.0-inbound-v2-s2", "version wtxidrelay sendaddrv2 verack sendheaders getheaders"),
            ("satd-0.7.0-inbound-v2", "version wtxidrelay sendaddrv2 verack sendheaders getheaders"),
            ("satd-0.7.0-inbound", "version wtxidrelay sendaddrv2 verack sendheaders getheaders"),
            ("satd-0.7.0-outbound-v2", "version wtxidrelay sendaddrv2 verack getheaders"),
            ("satd-0.7.0-outbound", "version wtxidrelay sendaddrv2 verack getheaders"),
        ];
        let names = fixture_names();
        let mut listed: Vec<String> = EXPECTED.iter().map(|(n, _)| n.to_string()).collect();
        listed.sort();
        assert_eq!(names, listed, "every fixture has a row here, and every row a fixture");

        for (name, want) in EXPECTED {
            let got: Vec<String> = replay_fixture(name).capture.commands().collect();
            assert_eq!(got.join(" "), *want, "{name}");
        }
    }
}
