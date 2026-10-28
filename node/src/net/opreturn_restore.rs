//! The `-restoreopreturns` download (plan §11.4): fetch every OP_RETURN
//! stripped block again from peers that keep the whole chain, so the node
//! can become a full archive peer again.
//!
//! A mini-IBD rather than one block at a time, but simpler than the forward
//! [`IbdScheduler`](crate::net::ibd): the blocks are already validated and
//! connected, each one is restored on its own (no connect order), and each
//! restore is crash-safe. So the state is a work list fixed when a pass
//! starts, a window of it taken at a time, and the requests in flight.
//!
//! Each peer has at most [`PER_PEER`] blocks outstanding, as Core caps
//! `MAX_BLOCKS_IN_TRANSIT_PER_PEER`, and the window holds at most
//! [`WINDOW`] blocks. A request older than [`STALL`] goes to another peer and
//! costs the slow one a slot; a delivery earns one back. A peer that answers
//! `notfound`, or sends a copy that does not restore, is not asked for that
//! block again in the pass. A block every connected peer has refused is left
//! for the next pass, which reads the records again: straight away when the
//! pass restored something or a new peer has connected since, else after a
//! minute.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use bitcoin::BlockHash;

use crate::chain::state::{RestoreItem, RestoreProgress};
use crate::net::peer::PeerId;

/// Most blocks outstanding to one peer (Core's
/// `MAX_BLOCKS_IN_TRANSIT_PER_PEER`).
pub const PER_PEER: usize = 16;
/// Most blocks the download works on at once (R-2). The free-space check
/// runs before each window.
pub const WINDOW: usize = 1024;
/// How long a request may go unanswered before it is given to another
/// peer: the IBD scheduler's stall timeout.
pub const STALL: Duration = crate::net::ibd::STALL_TIMEOUT_BASE;
/// How long after a pass that restored nothing the next one starts, unless
/// a new peer connects first.
const FRUITLESS_PASS_WAIT: Duration = Duration::from_secs(60);

pub struct RestoreDownloader {
    /// The pass's work list not yet in the window, in order.
    queue: VecDeque<RestoreItem>,
    /// The blocks being fetched, in work-list order: neither restored nor
    /// given up on yet.
    window: Vec<RestoreItem>,
    /// Requests out: block → (peer, when asked).
    in_flight: HashMap<BlockHash, (PeerId, Instant)>,
    /// Peers not to ask for a block again this pass: they answered
    /// `notfound`, or their copy did not restore.
    refused: HashMap<BlockHash, HashSet<PeerId>>,
    /// The peer a stalled request was taken from, given the block again
    /// only when no other peer has room.
    released_from: HashMap<BlockHash, PeerId>,
    /// Slots per peer below [`PER_PEER`]: halved by a stall, one back per
    /// delivery. A peer not here has all of them.
    caps: HashMap<PeerId, usize>,
    /// Blocks every connected peer refused, left for the next pass.
    skipped: u64,
    /// Where the next assignment starts its round-robin over the peers.
    next_start: usize,
    /// How many peers the download could ask when last driven.
    pub peers: usize,
    total_blocks: u64,
    remaining_bytes: u64,
    restored_blocks: u64,
    bytes_downloaded: u64,
    restored_this_pass: u64,
    /// When the last pass ended without restoring anything, and the peers
    /// connected then: `None` for a pass that had nothing to fetch, which a
    /// new peer does not change.
    fruitless_at: Option<(Instant, Option<HashSet<PeerId>>)>,
    /// When the first pass started, for the rate.
    started: Option<Instant>,
    /// Since when the free-space check has held the download back.
    pub disk_wait_since: Option<Instant>,
    /// When the free-space check last ran while holding it back.
    pub disk_checked_at: Option<Instant>,
}

impl Default for RestoreDownloader {
    fn default() -> Self {
        Self::new()
    }
}

impl RestoreDownloader {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            window: Vec::new(),
            in_flight: HashMap::new(),
            refused: HashMap::new(),
            released_from: HashMap::new(),
            caps: HashMap::new(),
            skipped: 0,
            next_start: 0,
            peers: 0,
            total_blocks: 0,
            remaining_bytes: 0,
            restored_blocks: 0,
            bytes_downloaded: 0,
            restored_this_pass: 0,
            fruitless_at: None,
            started: None,
            disk_wait_since: None,
            disk_checked_at: None,
        }
    }

    /// Whether the pass is over: nothing queued, nothing in the window.
    pub fn is_idle(&self) -> bool {
        self.queue.is_empty() && self.window.is_empty()
    }

    /// Whether a new pass may start now, with `peers` connected: not within a
    /// minute of a pass that restored nothing, which would only ask the same
    /// peers again, unless one of `peers` was not connected then.
    pub fn may_start_pass(&self, now: Instant, peers: &[PeerId]) -> bool {
        self.fruitless_at.as_ref().is_none_or(|(at, then)| {
            now.duration_since(*at) >= FRUITLESS_PASS_WAIT
                || then.as_ref().is_some_and(|then| peers.iter().any(|p| !then.contains(p)))
        })
    }

    /// Start a pass over `work`, the stripped blocks in the order to fetch
    /// them.
    pub fn start_pass(&mut self, work: Vec<RestoreItem>, now: Instant) {
        self.total_blocks = work.len() as u64;
        self.remaining_bytes = work.iter().map(|i| i.len).sum();
        self.queue = work.into();
        self.window.clear();
        self.in_flight.clear();
        self.refused.clear();
        self.released_from.clear();
        self.skipped = 0;
        self.restored_this_pass = 0;
        self.fruitless_at = None;
        self.started.get_or_insert(now);
        self.end_pass_if_idle(now, None);
    }

    /// The bytes the pass has left to download.
    pub fn remaining_bytes(&self) -> u64 {
        self.remaining_bytes
    }

    pub fn window_is_empty(&self) -> bool {
        self.window.is_empty()
    }

    /// Fill the window from the queue.
    pub fn next_window(&mut self) {
        while self.window.len() < WINDOW
            && let Some(item) = self.queue.pop_front()
        {
            self.window.push(item);
        }
    }

    fn cap(&self, peer: PeerId) -> usize {
        self.caps.get(&peer).copied().unwrap_or(PER_PEER)
    }

    fn outstanding(&self, peer: PeerId) -> usize {
        self.in_flight.values().filter(|(p, _)| *p == peer).count()
    }

    /// Share the window's unrequested blocks out over `peers`, each up to its
    /// slots, round-robin, and record every request. A block no peer in
    /// `peers` may be asked for any more is dropped from the window for this
    /// pass. Returns the hashes to ask of each peer.
    pub fn assign(&mut self, peers: &[PeerId], now: Instant) -> Vec<(PeerId, Vec<BlockHash>)> {
        if peers.is_empty() {
            return Vec::new();
        }
        let mut room: Vec<usize> =
            peers.iter().map(|p| self.cap(*p).saturating_sub(self.outstanding(*p))).collect();
        let mut out: Vec<Vec<BlockHash>> = vec![Vec::new(); peers.len()];
        let mut next = self.next_start % peers.len();
        self.next_start = self.next_start.wrapping_add(1);
        let mut given_up = Vec::new();
        for item in &self.window {
            if self.in_flight.contains_key(&item.hash) {
                continue;
            }
            let refused = self.refused.get(&item.hash);
            let may_ask = |i: usize| refused.is_none_or(|r| !r.contains(&peers[i]));
            if !(0..peers.len()).any(may_ask) {
                given_up.push(item.hash);
                continue;
            }
            let avoid = self.released_from.get(&item.hash).copied();
            let order = (0..peers.len()).map(|k| (next + k) % peers.len());
            let pick = order
                .clone()
                .find(|&i| room[i] > 0 && may_ask(i) && Some(peers[i]) != avoid)
                .or_else(|| order.clone().find(|&i| room[i] > 0 && may_ask(i)));
            let Some(i) = pick else {
                continue;
            };
            room[i] -= 1;
            out[i].push(item.hash);
            self.in_flight.insert(item.hash, (peers[i], now));
            next = i + 1;
        }
        for hash in given_up {
            self.drop_from_window(&hash);
            self.skipped += 1;
        }
        self.end_pass_if_idle(now, Some(peers));
        peers.iter().copied().zip(out).filter(|(_, hashes)| !hashes.is_empty()).collect()
    }

    fn drop_from_window(&mut self, hash: &BlockHash) -> Option<RestoreItem> {
        let at = self.window.iter().position(|i| i.hash == *hash)?;
        self.in_flight.remove(hash);
        self.refused.remove(hash);
        self.released_from.remove(hash);
        Some(self.window.remove(at))
    }

    fn end_pass_if_idle(&mut self, now: Instant, peers: Option<&[PeerId]>) {
        if self.is_idle() && self.restored_this_pass == 0 && self.fruitless_at.is_none() {
            self.fruitless_at = Some((now, peers.map(|p| p.iter().copied().collect())));
        }
    }

    /// `hash` was restored from `peer`'s copy of `bytes` bytes. Returns
    /// whether it was a block of this pass's window.
    pub fn note_restored(&mut self, hash: &BlockHash, peer: PeerId, bytes: u64) -> bool {
        let Some(item) = self.drop_from_window(hash) else {
            return false;
        };
        self.restored_blocks += 1;
        self.restored_this_pass += 1;
        self.bytes_downloaded += bytes;
        self.remaining_bytes = self.remaining_bytes.saturating_sub(item.len);
        if let Some(cap) = self.caps.get_mut(&peer) {
            *cap += 1;
            if *cap >= PER_PEER {
                self.caps.remove(&peer);
            }
        }
        true
    }

    /// `peer`'s copy of `hash` did not restore it: ask another peer. Returns
    /// whether the block was this pass's.
    pub fn note_failed(&mut self, hash: &BlockHash, peer: PeerId) -> bool {
        if !self.window.iter().any(|i| i.hash == *hash) {
            return false;
        }
        if self.in_flight.get(hash).is_some_and(|(p, _)| *p == peer) {
            self.in_flight.remove(hash);
        }
        self.refused.entry(*hash).or_default().insert(peer);
        true
    }

    /// `peer` answered `notfound` for `hash`. Returns whether it had been
    /// asked for it.
    pub fn note_not_found(&mut self, hash: &BlockHash, peer: PeerId) -> bool {
        if self.in_flight.get(hash).is_none_or(|(p, _)| *p != peer) {
            return false;
        }
        self.in_flight.remove(hash);
        self.refused.entry(*hash).or_default().insert(peer);
        true
    }

    /// `peer` disconnected: its requests go to other peers.
    pub fn note_peer_gone(&mut self, peer: PeerId) {
        self.in_flight.retain(|_, (p, _)| *p != peer);
        self.released_from.retain(|_, p| *p != peer);
        self.caps.remove(&peer);
        for refused in self.refused.values_mut() {
            refused.remove(&peer);
        }
    }

    /// Take back every request older than [`STALL`], for another peer, and
    /// halve the slots of each peer that held one. Returns how many.
    pub fn release_stale(&mut self, now: Instant) -> usize {
        let mut slow = HashSet::new();
        let released_from = &mut self.released_from;
        self.in_flight.retain(|hash, (peer, at)| {
            let keep = now.duration_since(*at) < STALL;
            if !keep {
                released_from.insert(*hash, *peer);
                slow.insert(*peer);
            }
            keep
        });
        for peer in &slow {
            let cap = self.caps.get(peer).copied().unwrap_or(PER_PEER);
            self.caps.insert(*peer, (cap / 2).max(1));
        }
        slow.len()
    }

    /// Whether `hash` is being asked of `peer`.
    pub fn is_requested_from(&self, hash: &BlockHash, peer: PeerId) -> bool {
        self.in_flight.get(hash).is_some_and(|(p, _)| *p == peer)
    }

    pub fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    pub fn restored_blocks(&self) -> u64 {
        self.restored_blocks
    }

    /// Blocks restored per second since the first pass started.
    pub fn rate(&self, now: Instant) -> f64 {
        let secs = self.started.map_or(0.0, |s| now.duration_since(s).as_secs_f64());
        if secs > 0.0 { self.restored_blocks as f64 / secs } else { 0.0 }
    }

    /// The counts for `getopreturnpruneinfo`.
    pub fn progress(&self) -> RestoreProgress {
        RestoreProgress {
            total_blocks: self.total_blocks,
            remaining_blocks: self.queue.len() as u64 + self.window.len() as u64 + self.skipped,
            restored_blocks: self.restored_blocks,
            bytes_downloaded: self.bytes_downloaded,
            remaining_bytes: self.remaining_bytes,
            in_flight: self.in_flight.len() as u64,
            peers: self.peers as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn item(n: u32) -> RestoreItem {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&n.to_le_bytes());
        RestoreItem {
            hash: BlockHash::from_byte_array(bytes),
            height: n,
            len: 1000,
        }
    }

    fn started(n: u32) -> RestoreDownloader {
        let mut dl = RestoreDownloader::new();
        dl.start_pass((0..n).map(item).collect(), Instant::now());
        dl.next_window();
        dl
    }

    fn asked(out: &[(PeerId, Vec<BlockHash>)], peer: PeerId) -> usize {
        out.iter().filter(|(p, _)| *p == peer).map(|(_, h)| h.len()).sum()
    }

    #[test]
    fn each_peer_gets_at_most_its_slots_and_the_window_is_capped() {
        let mut dl = started(5000);
        assert_eq!(dl.window.len(), WINDOW, "one window at a time");
        let out = dl.assign(&[1, 2, 3], Instant::now());
        for peer in [1, 2, 3] {
            assert_eq!(asked(&out, peer), PER_PEER);
        }
        assert!(dl.assign(&[1, 2, 3], Instant::now()).is_empty(), "no room until a block arrives");
        let first = out[0].1[0];
        assert!(dl.note_restored(&first, out[0].0, 1000));
        assert_eq!(asked(&dl.assign(&[1, 2, 3], Instant::now()), out[0].0), 1, "a delivery frees a slot");
    }

    #[test]
    fn a_stalled_request_goes_to_another_peer_and_costs_the_slow_one_slots() {
        let mut dl = started(100);
        let t0 = Instant::now();
        let out = dl.assign(&[1], t0);
        assert_eq!(asked(&out, 1), PER_PEER);
        assert_eq!(dl.release_stale(t0 + STALL - Duration::from_millis(1)), 0, "not yet stale");
        assert_eq!(dl.release_stale(t0 + STALL), 1);
        assert_eq!(dl.in_flight_len(), 0);
        let out = dl.assign(&[1, 2], t0 + STALL);
        assert_eq!(asked(&out, 1), PER_PEER / 2, "the slow peer's slots are halved");
        assert_eq!(asked(&out, 2), PER_PEER);
        let stalled: HashSet<_> = (0..PER_PEER as u32).map(|n| item(n).hash).collect();
        let to_one: HashSet<_> = out.iter().filter(|(p, _)| *p == 1).flat_map(|(_, h)| h.iter().copied()).collect();
        assert!(stalled.is_disjoint(&to_one), "a stalled block goes to the other peer");
        // A delivery earns a slot back.
        dl.note_restored(&out[0].1[0], 1, 1);
        assert_eq!(dl.cap(1), PER_PEER / 2 + 1);
    }

    #[test]
    fn a_notfound_peer_is_not_asked_for_that_block_again() {
        let mut dl = started(1);
        let hash = item(0).hash;
        let out = dl.assign(&[1, 2], Instant::now());
        let first = out[0].0;
        let other = if first == 1 { 2 } else { 1 };
        assert!(!dl.note_not_found(&hash, other), "never asked of it");
        assert!(dl.note_not_found(&hash, first));
        let out = dl.assign(&[1, 2], Instant::now());
        assert_eq!(out, vec![(other, vec![hash])], "the other peer is asked");
        assert!(dl.note_not_found(&hash, other));
        assert!(dl.assign(&[1, 2], Instant::now()).is_empty());
        assert!(dl.is_idle(), "refused by every peer: left for the next pass");
        assert_eq!(dl.progress().remaining_blocks, 1, "still counted as remaining");
        assert!(!dl.may_start_pass(Instant::now(), &[1, 2]), "a pass that restored nothing waits");
        assert!(dl.may_start_pass(Instant::now() + FRUITLESS_PASS_WAIT, &[1, 2]));
        assert!(dl.may_start_pass(Instant::now(), &[1, 2, 3]), "unless a new peer has connected");
        dl.start_pass(vec![item(0)], Instant::now());
        dl.next_window();
        assert_eq!(dl.assign(&[1, 2], Instant::now()).len(), 1, "a new pass asks the same peers again");
    }

    #[test]
    fn a_bad_copy_moves_the_block_to_another_peer() {
        let mut dl = started(1);
        let hash = item(0).hash;
        let out = dl.assign(&[1, 2], Instant::now());
        let first = out[0].0;
        assert!(dl.note_failed(&hash, first));
        let out = dl.assign(&[1, 2], Instant::now());
        assert_eq!(out.len(), 1);
        assert_ne!(out[0].0, first);
    }

    #[test]
    fn a_departed_peer_s_requests_are_asked_again() {
        let mut dl = started(10);
        let out = dl.assign(&[1], Instant::now());
        assert_eq!(asked(&out, 1), 10);
        dl.note_peer_gone(1);
        assert_eq!(dl.in_flight_len(), 0);
        assert_eq!(asked(&dl.assign(&[2], Instant::now()), 2), 10);
    }

    #[test]
    fn progress_counts_down_to_nothing() {
        let mut dl = started(3);
        assert_eq!(dl.progress().remaining_bytes, 3000);
        let out = dl.assign(&[7], Instant::now());
        for hash in &out[0].1 {
            assert!(dl.note_restored(hash, 7, 1200));
        }
        assert!(!dl.note_restored(&out[0].1[0], 7, 1200), "counted once");
        let p = dl.progress();
        assert_eq!((p.total_blocks, p.remaining_blocks, p.restored_blocks), (3, 0, 3));
        assert_eq!((p.bytes_downloaded, p.remaining_bytes, p.in_flight), (3600, 0, 0));
        assert!(dl.is_idle());
        assert!(dl.may_start_pass(Instant::now(), &[7]), "a pass that restored something does not wait");
        dl.start_pass(Vec::new(), Instant::now());
        assert!(!dl.may_start_pass(Instant::now(), &[7]), "an empty pass waits too");
    }
}
