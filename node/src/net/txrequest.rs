//! Transaction download scheduling: Bitcoin Core's `TxRequestTracker`
//! (`src/txrequest.{h,cpp}`) plus the announcement policy of its
//! `TxDownloadManagerImpl` (`src/node/txdownloadman_impl.cpp`).
//!
//! Every `inv` for a transaction we lack is recorded as an *announcement*,
//! one per (peer, txhash), where a txhash is a txid or a wtxid. At most one
//! request for a txhash is outstanding across all peers. The rest wait as
//! candidates and are asked in turn when the outstanding request expires
//! (`GETDATA_TX_INTERVAL`), the peer answers `notfound`, or it disconnects.
//! Without this, a transaction announced by k peers before it arrived was
//! downloaded k times.
//!
//! An announcement moves through the states of Core's tracker:
//!
//! - `Delayed`: a candidate whose request time has not come yet;
//! - `Ready`: a candidate whose request time has passed;
//! - `Best`: the one `Ready` candidate per txhash that would be requested
//!   now, which exists only while no request for the txhash is outstanding;
//! - `Requested`: asked for, waiting for a reply until its expiry;
//! - `Completed`: answered, refused or timed out. Kept only so the same peer
//!   is never asked twice; once a txhash has nothing but `Completed`
//!   announcements, they are all forgotten.
//!
//! Among the ready candidates for a txhash a preferred (outbound) one always
//! wins, and among equals the choice is a salted hash of txhash and peer, so
//! an attacker cannot predict or bias it (`txrequest.cpp` `PriorityComputer`).
//!
//! Time is microseconds on the node clock ([`crate::time::now_micros`]), as
//! Core reads `GetTime<std::chrono::microseconds>()`, so `setmocktime` moves
//! the delays and expiries. The tracker itself never reads a clock: every
//! operation that depends on time takes `now`, which keeps it testable.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use bitcoin::hashes::Hash as _;

use crate::net::peer::PeerId;

/// One microsecond-denominated second.
const SECOND: u64 = 1_000_000;

/// Requests in flight to one peer at which its new announcements are
/// delayed by [`OVERLOADED_PEER_TX_DELAY`]. Not a hard limit.
/// Core: `src/node/txdownloadman.h:25`.
pub const MAX_PEER_TX_REQUEST_IN_FLIGHT: usize = 100;
/// Announcements tracked per peer; a peer's announcements beyond this are
/// ignored, unless it holds the `relay` permission.
/// Core: `src/node/txdownloadman.h:30`.
pub const MAX_PEER_TX_ANNOUNCEMENTS: usize = 5000;
/// Delay for an announcement by txid while any connected peer relays by
/// wtxid. Core: `src/node/txdownloadman.h:32`.
pub const TXID_RELAY_DELAY: u64 = 2 * SECOND;
/// Delay for an announcement from a non-preferred (inbound) peer.
/// Core: `src/node/txdownloadman.h:34`.
pub const NONPREF_PEER_TX_DELAY: u64 = 2 * SECOND;
/// Delay for an announcement from a peer with at least
/// [`MAX_PEER_TX_REQUEST_IN_FLIGHT`] requests in flight.
/// Core: `src/node/txdownloadman.h:36`.
pub const OVERLOADED_PEER_TX_DELAY: u64 = 2 * SECOND;
/// How long a request may go unanswered before the next announcer is asked.
/// Core: `src/node/txdownloadman.h:38`.
pub const GETDATA_TX_INTERVAL: u64 = 60 * SECOND;

/// Entries per `getdata` message the scheduler sends.
/// Core: `src/net_processing.cpp:128`.
pub const MAX_GETDATA_SZ: usize = 1000;

/// A transaction identifier as announced: by txid (`MSG_TX`) or by wtxid
/// (`MSG_WTX`, BIP 339). Core's `GenTxid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GenTxid {
    Txid(bitcoin::Txid),
    Wtxid(bitcoin::Wtxid),
}

impl GenTxid {
    /// The 32 bytes the tracker keys on. A txid and a wtxid with the same
    /// bytes are the same txhash, as in Core: equal ids mean a transaction
    /// without a witness, which may be fetched either way.
    pub fn hash(&self) -> [u8; 32] {
        match self {
            GenTxid::Txid(t) => t.to_byte_array(),
            GenTxid::Wtxid(w) => w.to_byte_array(),
        }
    }

    pub fn is_wtxid(&self) -> bool {
        matches!(self, GenTxid::Wtxid(_))
    }
}

/// What the announcement policy needs to know about the announcing peer:
/// Core's `TxDownloadConnectionInfo` (`src/node/txdownloadman.h`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnnouncerInfo {
    /// Core's `fPreferredDownload`: outbound or `noban`, not addr-fetch, and
    /// able to serve blocks.
    pub preferred: bool,
    /// The `relay` permission: exempt from the announcement cap and the
    /// overload delay.
    pub relay_permission: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Delayed,
    Ready,
    Best,
    Requested,
    Completed,
}

impl State {
    fn is_candidate(self) -> bool {
        matches!(self, State::Delayed | State::Ready | State::Best)
    }
}

type TxHash = [u8; 32];

#[derive(Clone, Debug)]
struct Announcement {
    peer: PeerId,
    gtxid: GenTxid,
    /// Request time for a candidate, expiry for `Requested`.
    time: u64,
    /// Fixed at announcement, as Core's `m_preferred`: a peer whose
    /// preferredness changes keeps its old announcements as they were.
    priority: u64,
    /// Announcement order, so a peer's requests go out in the order it
    /// announced (parents before children).
    seq: u64,
    state: State,
}

#[derive(Default, Debug)]
struct PeerAnnouncements {
    /// Every announcement of this peer, by sequence.
    all: BTreeMap<u64, TxHash>,
    /// Its `Best` announcements, by sequence: what `get_requestable` returns.
    best: BTreeMap<u64, TxHash>,
    /// How many are `Requested`.
    requested: usize,
}

/// Core's `TxRequestTracker`, with its `TxDownloadManagerImpl` announcement
/// policy in [`TxRequestTracker::add_announcement`].
pub struct TxRequestTracker {
    txs: HashMap<TxHash, Vec<Announcement>>,
    peers: HashMap<PeerId, PeerAnnouncements>,
    /// `Delayed` candidates by request time and `Requested` ones by expiry:
    /// what `set_time_point` moves forward.
    timeline: BTreeSet<(u64, TxHash, PeerId)>,
    /// `Ready` and `Best` candidates by request time: what a clock that went
    /// backwards moves back to `Delayed`.
    ready: BTreeSet<(u64, TxHash, PeerId)>,
    next_seq: u64,
    k0: u64,
    k1: u64,
}

impl Default for TxRequestTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TxRequestTracker {
    /// A tracker with random priority salt, as Core's.
    pub fn new() -> Self {
        use rand::Rng as _;
        let mut rng = rand::thread_rng();
        Self::with_keys(rng.r#gen(), rng.r#gen())
    }

    /// A tracker whose choice among equal candidates is reproducible: Core's
    /// `deterministic` constructor uses zero keys.
    pub fn deterministic() -> Self {
        Self::with_keys(0, 0)
    }

    fn with_keys(k0: u64, k1: u64) -> Self {
        Self {
            txs: HashMap::new(),
            peers: HashMap::new(),
            timeline: BTreeSet::new(),
            ready: BTreeSet::new(),
            next_seq: 0,
            k0,
            k1,
        }
    }

    /// Core's `PriorityComputer` (`txrequest.cpp:115-119`): a preferred peer
    /// in the top bit, a salted SipHash of txhash and peer below it.
    fn priority(&self, hash: &TxHash, peer: PeerId, preferred: bool) -> u64 {
        let mut data = [0u8; 40];
        data[..32].copy_from_slice(hash);
        data[32..].copy_from_slice(&peer.to_le_bytes());
        let low = bitcoin::hashes::siphash24::Hash::hash_to_u64_with_keys(self.k0, self.k1, &data) >> 1;
        low | (u64::from(preferred) << 63)
    }

    /// Core's `AddTxAnnouncement` after its `AlreadyHaveTx` check
    /// (`txdownloadman_impl.cpp:196-223`): drop the announcement if the peer
    /// is over [`MAX_PEER_TX_ANNOUNCEMENTS`], otherwise record it with the
    /// delays that apply. `wtxid_peers` is the number of connected peers that
    /// negotiated wtxid relay. Returns whether it was recorded.
    pub fn add_announcement(
        &mut self,
        peer: PeerId,
        gtxid: GenTxid,
        info: AnnouncerInfo,
        wtxid_peers: usize,
        now: u64,
    ) -> bool {
        if !info.relay_permission && self.count(peer) >= MAX_PEER_TX_ANNOUNCEMENTS {
            return false;
        }
        let mut delay = 0;
        if !info.preferred {
            delay += NONPREF_PEER_TX_DELAY;
        }
        if !gtxid.is_wtxid() && wtxid_peers > 0 {
            delay += TXID_RELAY_DELAY;
        }
        if !info.relay_permission && self.count_in_flight(peer) >= MAX_PEER_TX_REQUEST_IN_FLIGHT {
            delay += OVERLOADED_PEER_TX_DELAY;
        }
        self.received_inv(peer, gtxid, info.preferred, now.saturating_add(delay))
    }

    /// Core's `MaybeAddOrphanResolutionCandidate`
    /// (`txdownloadman_impl.cpp:226-262`): treat `peer` as having announced
    /// every missing parent of an orphan, by txid. The cap counts all the
    /// parents at once, and the txid delay applies whenever any peer relays
    /// by wtxid, as the parents are fetched by txid. Returns whether the
    /// peer was taken as a candidate.
    pub fn add_orphan_resolution_candidate(
        &mut self,
        peer: PeerId,
        parents: &[bitcoin::Txid],
        info: AnnouncerInfo,
        wtxid_peers: usize,
        now: u64,
    ) -> bool {
        if !info.relay_permission && self.count(peer) + parents.len() > MAX_PEER_TX_ANNOUNCEMENTS {
            return false;
        }
        let mut delay = 0;
        if !info.preferred {
            delay += NONPREF_PEER_TX_DELAY;
        }
        if wtxid_peers > 0 {
            delay += TXID_RELAY_DELAY;
        }
        if !info.relay_permission && self.count_in_flight(peer) >= MAX_PEER_TX_REQUEST_IN_FLIGHT {
            delay += OVERLOADED_PEER_TX_DELAY;
        }
        for parent in parents {
            self.received_inv(peer, GenTxid::Txid(*parent), info.preferred, now.saturating_add(delay));
        }
        true
    }

    /// Core's `ReceivedInv`: a new `Delayed` candidate, unless this peer
    /// already has an announcement for the txhash in any state.
    pub fn received_inv(&mut self, peer: PeerId, gtxid: GenTxid, preferred: bool, reqtime: u64) -> bool {
        let hash = gtxid.hash();
        if self.txs.get(&hash).is_some_and(|anns| anns.iter().any(|a| a.peer == peer)) {
            return false;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        let priority = self.priority(&hash, peer, preferred);
        self.txs.entry(hash).or_default().push(Announcement {
            peer,
            gtxid,
            time: reqtime,
            priority,
            seq,
            state: State::Delayed,
        });
        self.peers.entry(peer).or_default().all.insert(seq, hash);
        self.timeline.insert((reqtime, hash, peer));
        true
    }

    /// Core's `DisconnectedPeer`: forget every announcement of `peer`. A
    /// transaction it was asked for goes to the next candidate.
    pub fn disconnected_peer(&mut self, peer: PeerId) {
        let Some(pa) = self.peers.remove(&peer) else { return };
        for hash in pa.all.into_values() {
            let Some(anns) = self.txs.get_mut(&hash) else { continue };
            if let Some(i) = anns.iter().position(|a| a.peer == peer) {
                let a = anns.swap_remove(i);
                Self::unindex(&mut self.timeline, &mut self.ready, &hash, &a);
            }
            self.reselect(&hash);
        }
    }

    /// Core's `ForgetTxHash`: drop every announcement of `hash` from every
    /// peer. Called once the transaction is no longer needed.
    pub fn forget_tx_hash(&mut self, hash: &[u8; 32]) {
        let Some(anns) = self.txs.remove(hash) else { return };
        for a in anns {
            Self::unindex(&mut self.timeline, &mut self.ready, hash, &a);
            if let Some(pa) = self.peers.get_mut(&a.peer) {
                pa.all.remove(&a.seq);
                pa.best.remove(&a.seq);
                if a.state == State::Requested {
                    pa.requested -= 1;
                }
                if pa.all.is_empty() {
                    self.peers.remove(&a.peer);
                }
            }
        }
    }

    /// Core's `GetRequestable`: advance to `now` (promoting candidates whose
    /// time came, expiring requests whose time ran out — returned as
    /// `expired`), then return what to ask `peer` for now, in announcement
    /// order. The caller marks each one it sends with
    /// [`requested_tx`](Self::requested_tx).
    pub fn get_requestable(&mut self, peer: PeerId, now: u64) -> (Vec<GenTxid>, Vec<(PeerId, GenTxid)>) {
        let expired = self.set_time_point(now);
        let Some(pa) = self.peers.get(&peer) else { return (Vec::new(), expired) };
        let selected = pa
            .best
            .values()
            .filter_map(|hash| self.txs.get(hash)?.iter().find(|a| a.peer == peer).map(|a| a.gtxid))
            .collect();
        (selected, expired)
    }

    /// Core's `RequestedTx`: the candidate from `peer` becomes `Requested`
    /// with `expiry`. Any other outstanding request for the txhash is
    /// completed, as nothing is waited for on it any more. No effect unless
    /// `peer` has a candidate announcement for it.
    pub fn requested_tx(&mut self, peer: PeerId, hash: &[u8; 32], expiry: u64) {
        let Some(anns) = self.txs.get_mut(hash) else { return };
        let Some(i) = anns.iter().position(|a| a.peer == peer && a.state.is_candidate()) else {
            return;
        };
        for (j, other) in anns.iter_mut().enumerate() {
            if j != i && other.state == State::Requested {
                Self::unindex(&mut self.timeline, &mut self.ready, hash, other);
                other.state = State::Completed;
                if let Some(pa) = self.peers.get_mut(&other.peer) {
                    pa.requested -= 1;
                }
            }
        }
        let a = anns[i].clone();
        Self::unindex(&mut self.timeline, &mut self.ready, hash, &a);
        let pa = self.peers.get_mut(&peer).expect("an announcement's peer is indexed");
        pa.best.remove(&a.seq);
        pa.requested += 1;
        anns[i].state = State::Requested;
        anns[i].time = expiry;
        self.timeline.insert((expiry, *hash, peer));
        self.reselect(hash);
    }

    /// Core's `ReceivedResponse`: `peer` answered for `hash` with the
    /// transaction or `notfound`. Its candidate or request is completed, and
    /// the next candidate becomes eligible.
    pub fn received_response(&mut self, peer: PeerId, hash: &[u8; 32]) {
        let Some(anns) = self.txs.get_mut(hash) else { return };
        let Some(i) = anns.iter().position(|a| a.peer == peer && a.state != State::Completed) else {
            return;
        };
        let a = anns[i].clone();
        Self::unindex(&mut self.timeline, &mut self.ready, hash, &a);
        anns[i].state = State::Completed;
        if let Some(pa) = self.peers.get_mut(&peer) {
            pa.best.remove(&a.seq);
            if a.state == State::Requested {
                pa.requested -= 1;
            }
        }
        self.reselect(hash);
    }

    /// Requests outstanding to `peer`. Core's `CountInFlight`.
    pub fn count_in_flight(&self, peer: PeerId) -> usize {
        self.peers.get(&peer).map_or(0, |pa| pa.requested)
    }

    /// Candidate announcements of `peer`. Core's `CountCandidates`.
    pub fn count_candidates(&self, peer: PeerId) -> usize {
        let Some(pa) = self.peers.get(&peer) else { return 0 };
        pa.all
            .values()
            .filter(|h| {
                self.txs
                    .get(*h)
                    .and_then(|anns| anns.iter().find(|a| a.peer == peer))
                    .is_some_and(|a| a.state.is_candidate())
            })
            .count()
    }

    /// Announcements of `peer` in any state. Core's `Count`.
    pub fn count(&self, peer: PeerId) -> usize {
        self.peers.get(&peer).map_or(0, |pa| pa.all.len())
    }

    /// Announcements tracked across all peers. Core's `Size`.
    pub fn size(&self) -> usize {
        self.txs.values().map(Vec::len).sum()
    }

    /// Whether nothing is tracked at all: lets the periodic tick skip the
    /// per-peer pass on a node with no transaction downloads pending.
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Peers with a candidate or outstanding request for `hash`. Core's
    /// `GetCandidatePeers`.
    pub fn candidate_peers(&self, hash: &[u8; 32]) -> Vec<PeerId> {
        self.txs
            .get(hash)
            .map(|anns| anns.iter().filter(|a| a.state != State::Completed).map(|a| a.peer).collect())
            .unwrap_or_default()
    }

    /// Core's `SetTimePoint` (`txrequest.cpp:484-513`).
    fn set_time_point(&mut self, now: u64) -> Vec<(PeerId, GenTxid)> {
        let mut expired = Vec::new();
        while let Some(&(time, hash, peer)) = self.timeline.first() {
            if time > now {
                break;
            }
            self.timeline.pop_first();
            let Some(anns) = self.txs.get_mut(&hash) else { continue };
            let Some(a) = anns.iter_mut().find(|a| a.peer == peer) else { continue };
            match a.state {
                State::Delayed => {
                    a.state = State::Ready;
                    self.ready.insert((time, hash, peer));
                }
                State::Requested => {
                    a.state = State::Completed;
                    expired.push((peer, a.gtxid));
                    if let Some(pa) = self.peers.get_mut(&peer) {
                        pa.requested -= 1;
                    }
                }
                _ => continue,
            }
            self.reselect(&hash);
        }
        // A clock that went backwards: candidates no longer due are delayed
        // again. Unusual, but `setmocktime` can do it.
        while let Some(&(time, hash, peer)) = self.ready.last() {
            if time <= now {
                break;
            }
            self.ready.pop_last();
            let Some(anns) = self.txs.get_mut(&hash) else { continue };
            let Some(a) = anns.iter_mut().find(|a| a.peer == peer) else { continue };
            if a.state == State::Best
                && let Some(pa) = self.peers.get_mut(&peer)
            {
                pa.best.remove(&a.seq);
            }
            a.state = State::Delayed;
            self.timeline.insert((time, hash, peer));
            self.reselect(&hash);
        }
        expired
    }

    /// Remove `a` from whichever time index holds it.
    fn unindex(
        timeline: &mut BTreeSet<(u64, TxHash, PeerId)>,
        ready: &mut BTreeSet<(u64, TxHash, PeerId)>,
        hash: &TxHash,
        a: &Announcement,
    ) {
        match a.state {
            State::Delayed | State::Requested => {
                timeline.remove(&(a.time, *hash, a.peer));
            }
            State::Ready | State::Best => {
                ready.remove(&(a.time, *hash, a.peer));
            }
            State::Completed => {}
        }
    }

    /// Restore the per-txhash invariants after any change to `hash`'s
    /// announcements: nothing `Best` while a request is outstanding, else
    /// the highest-priority ready candidate is `Best`; and a txhash with
    /// only `Completed` announcements is forgotten entirely.
    fn reselect(&mut self, hash: &TxHash) {
        let Some(anns) = self.txs.get_mut(hash) else { return };
        if anns.iter().all(|a| a.state == State::Completed) {
            self.forget_tx_hash(hash);
            return;
        }
        let requested = anns.iter().any(|a| a.state == State::Requested);
        let winner = if requested {
            None
        } else {
            anns.iter()
                .enumerate()
                .filter(|(_, a)| matches!(a.state, State::Ready | State::Best))
                .max_by(|(_, x), (_, y)| x.priority.cmp(&y.priority).then(y.seq.cmp(&x.seq)))
                .map(|(i, _)| i)
        };
        for (i, a) in anns.iter_mut().enumerate() {
            let want = if Some(i) == winner {
                State::Best
            } else if a.state == State::Best {
                State::Ready
            } else {
                continue;
            };
            if a.state == want {
                continue;
            }
            a.state = want;
            if let Some(pa) = self.peers.get_mut(&a.peer) {
                if want == State::Best {
                    pa.best.insert(a.seq, *hash);
                } else {
                    pa.best.remove(&a.seq);
                }
            }
        }
    }

    /// Check every index against the announcements (tests only): Core's
    /// `SanityCheck`.
    #[cfg(test)]
    pub fn sanity_check(&self) {
        let mut per_peer: HashMap<PeerId, (usize, usize, usize)> = HashMap::new();
        let mut timeline = 0;
        let mut ready = 0;
        for (hash, anns) in &self.txs {
            assert!(!anns.is_empty());
            assert!(anns.iter().any(|a| a.state != State::Completed), "only completed remain");
            let requested = anns.iter().filter(|a| a.state == State::Requested).count();
            let best = anns.iter().filter(|a| a.state == State::Best).count();
            assert!(requested + best <= 1, "at most one selected per txhash");
            let any_ready = anns.iter().any(|a| matches!(a.state, State::Ready | State::Best));
            if requested == 0 && any_ready {
                assert_eq!(best, 1, "a ready candidate and no request means one best");
                let b = anns.iter().find(|a| a.state == State::Best).unwrap();
                for a in anns.iter().filter(|a| a.state == State::Ready) {
                    assert!(a.priority <= b.priority);
                }
            }
            for a in anns {
                assert_eq!(anns.iter().filter(|o| o.peer == a.peer).count(), 1);
                let e = per_peer.entry(a.peer).or_default();
                e.0 += 1;
                if a.state == State::Requested {
                    e.1 += 1;
                }
                if a.state == State::Best {
                    e.2 += 1;
                    assert_eq!(self.peers[&a.peer].best.get(&a.seq), Some(hash));
                }
                assert_eq!(self.peers[&a.peer].all.get(&a.seq), Some(hash));
                match a.state {
                    State::Delayed | State::Requested => {
                        timeline += 1;
                        assert!(self.timeline.contains(&(a.time, *hash, a.peer)));
                    }
                    State::Ready | State::Best => {
                        ready += 1;
                        assert!(self.ready.contains(&(a.time, *hash, a.peer)));
                    }
                    State::Completed => {}
                }
            }
        }
        assert_eq!(timeline, self.timeline.len());
        assert_eq!(ready, self.ready.len());
        assert_eq!(per_peer.len(), self.peers.len());
        for (peer, (all, requested, best)) in per_peer {
            let pa = &self.peers[&peer];
            assert_eq!(pa.all.len(), all);
            assert_eq!(pa.requested, requested);
            assert_eq!(pa.best.len(), best);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wtxid(n: u8) -> GenTxid {
        GenTxid::Wtxid(bitcoin::Wtxid::from_byte_array([n; 32]))
    }

    fn txid(n: u8) -> GenTxid {
        GenTxid::Txid(bitcoin::Txid::from_byte_array([n; 32]))
    }

    const PREF: AnnouncerInfo = AnnouncerInfo { preferred: true, relay_permission: false };
    const NONPREF: AnnouncerInfo = AnnouncerInfo { preferred: false, relay_permission: false };
    const T0: u64 = 1_000 * SECOND;

    /// Ask every peer what it should be sent at `now`, mark it requested,
    /// and return (peer, gtxid) pairs, as the manager's tick does.
    fn tick(t: &mut TxRequestTracker, peers: &[PeerId], now: u64) -> Vec<(PeerId, GenTxid)> {
        let mut out = Vec::new();
        for &p in peers {
            let (req, _) = t.get_requestable(p, now);
            for g in req {
                t.requested_tx(p, &g.hash(), now + GETDATA_TX_INTERVAL);
                out.push((p, g));
            }
        }
        t.sanity_check();
        out
    }

    #[test]
    fn one_request_at_a_time_and_expiry_falls_back() {
        let mut t = TxRequestTracker::deterministic();
        assert!(t.add_announcement(1, wtxid(1), PREF, 1, T0));
        assert!(t.add_announcement(2, wtxid(1), PREF, 1, T0));
        let first = tick(&mut t, &[1, 2], T0);
        assert_eq!(first.len(), 1, "two announcers, one request");
        let asked = first[0].0;
        let other = if asked == 1 { 2 } else { 1 };
        assert!(tick(&mut t, &[1, 2], T0 + GETDATA_TX_INTERVAL - 1).is_empty(), "nothing before expiry");
        let (_, expired) = t.get_requestable(other, T0 + GETDATA_TX_INTERVAL);
        assert_eq!(expired, vec![(asked, wtxid(1))]);
        assert_eq!(tick(&mut t, &[1, 2], T0 + GETDATA_TX_INTERVAL), vec![(other, wtxid(1))]);
        // The first peer is never asked again, and once both failed the
        // txhash is forgotten.
        assert!(tick(&mut t, &[1, 2], T0 + 2 * GETDATA_TX_INTERVAL).is_empty());
        assert_eq!(t.size(), 0);
    }

    #[test]
    fn notfound_and_disconnect_fall_back_at_once() {
        let mut t = TxRequestTracker::deterministic();
        for p in [1, 2, 3] {
            t.add_announcement(p, wtxid(7), PREF, 1, T0);
        }
        let a = tick(&mut t, &[1, 2, 3], T0)[0].0;
        t.received_response(a, &wtxid(7).hash());
        let b = tick(&mut t, &[1, 2, 3], T0);
        assert_eq!(b.len(), 1);
        assert_ne!(b[0].0, a);
        t.disconnected_peer(b[0].0);
        let c = tick(&mut t, &[1, 2, 3], T0);
        assert_eq!(c.len(), 1);
        assert!(c[0].0 != a && c[0].0 != b[0].0);
    }

    #[test]
    fn a_non_preferred_announcer_waits_and_a_preferred_one_wins_meanwhile() {
        let mut t = TxRequestTracker::deterministic();
        t.add_announcement(1, wtxid(3), NONPREF, 1, T0);
        assert!(tick(&mut t, &[1], T0 + NONPREF_PEER_TX_DELAY - 1).is_empty());
        t.add_announcement(2, wtxid(3), PREF, 1, T0 + SECOND);
        assert_eq!(tick(&mut t, &[1, 2], T0 + SECOND), vec![(2, wtxid(3))]);
        assert!(tick(&mut t, &[1, 2], T0 + NONPREF_PEER_TX_DELAY).is_empty(), "already in flight");

        // Alone, the inbound one is asked exactly at its delay.
        let mut t = TxRequestTracker::deterministic();
        t.add_announcement(1, wtxid(3), NONPREF, 1, T0);
        assert_eq!(tick(&mut t, &[1], T0 + NONPREF_PEER_TX_DELAY), vec![(1, wtxid(3))]);
    }

    #[test]
    fn preferred_always_beats_non_preferred_when_both_ready() {
        // Whatever the salt, a ready preferred candidate is chosen first.
        for seed in 0..32u64 {
            let mut t = TxRequestTracker::with_keys(seed, seed.wrapping_mul(7919));
            for p in 10..20 {
                t.add_announcement(p, wtxid(4), NONPREF, 1, T0);
            }
            t.add_announcement(5, wtxid(4), PREF, 1, T0);
            let asked = tick(&mut t, &(5..20).collect::<Vec<_>>(), T0 + NONPREF_PEER_TX_DELAY);
            assert_eq!(asked, vec![(5, wtxid(4))]);
        }
    }

    #[test]
    fn txid_announcements_wait_only_when_a_wtxid_peer_exists() {
        let mut t = TxRequestTracker::deterministic();
        t.add_announcement(1, txid(5), PREF, 0, T0);
        assert_eq!(tick(&mut t, &[1], T0), vec![(1, txid(5))], "no wtxid peers: no delay");
        t.add_announcement(1, txid(6), PREF, 1, T0);
        assert!(tick(&mut t, &[1], T0 + TXID_RELAY_DELAY - 1).is_empty());
        assert_eq!(tick(&mut t, &[1], T0 + TXID_RELAY_DELAY), vec![(1, txid(6))]);
        // Delays add up: inbound and by txid.
        t.add_announcement(2, txid(8), NONPREF, 1, T0);
        assert!(tick(&mut t, &[2], T0 + NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY - 1).is_empty());
        assert_eq!(tick(&mut t, &[2], T0 + NONPREF_PEER_TX_DELAY + TXID_RELAY_DELAY).len(), 1);
    }

    #[test]
    fn overloaded_peer_is_delayed_unless_it_has_relay_permission() {
        let mut t = TxRequestTracker::deterministic();
        for i in 0..MAX_PEER_TX_REQUEST_IN_FLIGHT as u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_le_bytes());
            t.add_announcement(1, GenTxid::Wtxid(bitcoin::Wtxid::from_byte_array(h)), PREF, 1, T0);
        }
        assert_eq!(tick(&mut t, &[1], T0).len(), MAX_PEER_TX_REQUEST_IN_FLIGHT);
        assert_eq!(t.count_in_flight(1), MAX_PEER_TX_REQUEST_IN_FLIGHT);
        t.add_announcement(1, wtxid(0xee), PREF, 1, T0);
        assert!(tick(&mut t, &[1], T0 + OVERLOADED_PEER_TX_DELAY - 1).is_empty());
        assert_eq!(tick(&mut t, &[1], T0 + OVERLOADED_PEER_TX_DELAY), vec![(1, wtxid(0xee))]);

        let relay = AnnouncerInfo { preferred: true, relay_permission: true };
        t.add_announcement(1, wtxid(0xef), relay, 1, T0 + OVERLOADED_PEER_TX_DELAY);
        assert_eq!(tick(&mut t, &[1], T0 + OVERLOADED_PEER_TX_DELAY), vec![(1, wtxid(0xef))]);
    }

    #[test]
    fn announcements_are_capped_per_peer_unless_it_has_relay_permission() {
        let mut t = TxRequestTracker::deterministic();
        let g = |i: u32| {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_le_bytes());
            GenTxid::Wtxid(bitcoin::Wtxid::from_byte_array(h))
        };
        for i in 0..MAX_PEER_TX_ANNOUNCEMENTS as u32 {
            assert!(t.add_announcement(1, g(i), NONPREF, 1, T0));
        }
        assert!(!t.add_announcement(1, g(u32::MAX), NONPREF, 1, T0), "the 5001st is ignored");
        assert_eq!(t.count(1), MAX_PEER_TX_ANNOUNCEMENTS);
        let relay = AnnouncerInfo { preferred: false, relay_permission: true };
        assert!(t.add_announcement(1, g(u32::MAX), relay, 1, T0));
        // Another peer is unaffected.
        assert!(t.add_announcement(2, g(u32::MAX), NONPREF, 1, T0));
        t.sanity_check();
    }

    #[test]
    fn forgetting_a_txhash_drops_every_announcer() {
        let mut t = TxRequestTracker::deterministic();
        for p in [1, 2, 3] {
            t.add_announcement(p, wtxid(9), PREF, 1, T0);
        }
        assert_eq!(tick(&mut t, &[1, 2, 3], T0).len(), 1);
        t.forget_tx_hash(&wtxid(9).hash());
        t.sanity_check();
        assert_eq!(t.size(), 0);
        assert_eq!(t.count_in_flight(1) + t.count_in_flight(2) + t.count_in_flight(3), 0);
        assert!(tick(&mut t, &[1, 2, 3], T0 + 10 * GETDATA_TX_INTERVAL).is_empty());
    }

    #[test]
    fn a_duplicate_announcement_from_the_same_peer_is_ignored() {
        let mut t = TxRequestTracker::deterministic();
        assert!(t.add_announcement(1, wtxid(2), PREF, 1, T0));
        assert!(!t.add_announcement(1, wtxid(2), PREF, 1, T0));
        // The same 32 bytes as a txid are the same txhash.
        assert!(!t.received_inv(1, txid(2), true, T0));
        assert_eq!(tick(&mut t, &[1], T0).len(), 1);
        // A requested-then-failed peer re-announcing is not asked again
        // while another candidate keeps the txhash tracked.
        t.add_announcement(2, wtxid(2), NONPREF, 1, T0);
        t.received_response(1, &wtxid(2).hash());
        assert!(!t.add_announcement(1, wtxid(2), PREF, 1, T0));
        // Once only failed announcements remain, all are forgotten, and a
        // fresh announcement counts again (Core: "unless the announcement
        // was forgotten in between").
        t.received_response(2, &wtxid(2).hash());
        assert_eq!(t.size(), 0);
        assert!(t.add_announcement(1, wtxid(2), PREF, 1, T0));
    }

    #[test]
    fn requests_go_out_in_announcement_order() {
        let mut t = TxRequestTracker::deterministic();
        let order = [9u8, 3, 7, 1, 5];
        for n in order {
            t.add_announcement(1, wtxid(n), PREF, 1, T0);
        }
        let (got, _) = t.get_requestable(1, T0);
        assert_eq!(got, order.iter().map(|n| wtxid(*n)).collect::<Vec<_>>());
    }

    #[test]
    fn a_clock_that_goes_backwards_delays_candidates_again() {
        let mut t = TxRequestTracker::deterministic();
        t.add_announcement(1, wtxid(1), NONPREF, 1, T0);
        let (got, _) = t.get_requestable(1, T0 + NONPREF_PEER_TX_DELAY);
        assert_eq!(got.len(), 1);
        t.sanity_check();
        let (got, _) = t.get_requestable(1, T0);
        assert!(got.is_empty(), "no longer due");
        t.sanity_check();
        assert_eq!(tick(&mut t, &[1], T0 + NONPREF_PEER_TX_DELAY).len(), 1);
    }

    #[test]
    fn orphan_parents_are_announced_by_txid_with_the_txid_delay() {
        let mut t = TxRequestTracker::deterministic();
        let parents = [bitcoin::Txid::from_byte_array([1; 32]), bitcoin::Txid::from_byte_array([2; 32])];
        assert!(t.add_orphan_resolution_candidate(1, &parents, PREF, 1, T0));
        assert!(tick(&mut t, &[1], T0 + TXID_RELAY_DELAY - 1).is_empty());
        assert_eq!(tick(&mut t, &[1], T0 + TXID_RELAY_DELAY), vec![(1, txid(1)), (1, txid(2))]);
        // With no wtxid peers, a preferred peer is asked at once.
        let mut t = TxRequestTracker::deterministic();
        assert!(t.add_orphan_resolution_candidate(1, &parents, PREF, 0, T0));
        assert_eq!(tick(&mut t, &[1], T0).len(), 2);
    }

    /// Random operations keep every index consistent.
    #[test]
    fn random_operations_keep_the_indexes_consistent() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let mut t = TxRequestTracker::new();
        let mut now = T0;
        for _ in 0..20_000 {
            let peer = rng.gen_range(0..6u64);
            let hash = rng.gen_range(0..12u8);
            let g = if rng.r#gen() { wtxid(hash) } else { txid(hash) };
            match rng.gen_range(0..9) {
                0 | 1 => {
                    let info = AnnouncerInfo { preferred: rng.r#gen(), relay_permission: rng.r#gen() };
                    t.add_announcement(peer, g, info, rng.gen_range(0..2), now);
                }
                2 => {
                    let (req, _) = t.get_requestable(peer, now);
                    for r in req {
                        t.requested_tx(peer, &r.hash(), now + GETDATA_TX_INTERVAL);
                    }
                }
                3 => t.requested_tx(peer, &g.hash(), now + rng.gen_range(0..GETDATA_TX_INTERVAL)),
                4 => t.received_response(peer, &g.hash()),
                5 => t.forget_tx_hash(&g.hash()),
                6 if rng.gen_range(0..10) == 0 => t.disconnected_peer(peer),
                7 => now = now.saturating_add(rng.gen_range(0..3 * SECOND)),
                8 if rng.gen_range(0..20) == 0 => now = now.saturating_sub(rng.gen_range(0..5 * SECOND)),
                _ => {}
            }
            t.sanity_check();
        }
    }
}
