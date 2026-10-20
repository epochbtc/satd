//! Bounded orphan transaction pool.
//!
//! When a peer relays a transaction that spends inputs we don't yet know
//! about — because the parent is still propagating, or we just finished
//! IBD with an empty mempool — mempool admission fails with
//! [`MempoolError::MissingInputs`]. Without deferral, every such
//! rejection increments the peer's ban score and we quickly shotgun good
//! peers.
//!
//! [`TxOrphanage`] holds these "missing-parent" transactions in a
//! bounded side pool. Callers reconsider them when a parent tx enters
//! the mempool or when a new block connects. It follows Bitcoin Core's
//! v30 `TxOrphanage` (`src/node/txorphanage.cpp`):
//!
//! - It holds announcements: one per (orphan, peer that sent or announced
//!   it). Orphans are keyed by wtxid, so two with the same txid and
//!   different witnesses are both kept. An orphan stays while it has an
//!   announcer.
//! - Two global limits. The latency score, one per announcement plus
//!   one per ten inputs of each orphan, at most 3,000. The orphans'
//!   total weight, at most 404,000 Wu for each peer with an
//!   announcement.
//! - Past either limit, the peer with the highest DoS score loses its
//!   oldest announcements until the orphanage is back within limits.
//!   The DoS score is the larger of the peer's share of the latency limit
//!   and of its weight reservation. A peer within its share is not
//!   evicted for another peer's orphans.
//!
//! There is no count limit and no expiry: Core v30 dropped both
//! (`-maxorphantx`, `ORPHAN_TX_EXPIRE_TIME`).
//!
//! Core also orders a peer's announcements that are waiting to be
//! reconsidered after the others, for eviction. satd reconsiders an
//! orphan as soon as its parent arrives, so no announcement is ever left
//! waiting and the order is plain oldest first.

use bitcoin::{OutPoint, Transaction, Txid, Wtxid};
use parking_lot::Mutex;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet};

use crate::mempool::policy::MAX_STANDARD_TX_WEIGHT;
use crate::net::peer::PeerId;

/// Core's `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE`: the global limit on the
/// latency score.
pub const DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE: u32 = 3_000;

/// Core's `DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER`: the weight each peer
/// with an announcement adds to the global weight limit.
pub const DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER: u64 = 404_000;

#[derive(Debug, Clone)]
pub struct OrphanageConfig {
    pub max_global_latency_score: u32,
    pub reserved_peer_usage: u64,
}

impl Default for OrphanageConfig {
    fn default() -> Self {
        Self {
            max_global_latency_score: DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE,
            reserved_peer_usage: DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OrphanReject {
    #[error("orphan tx exceeds MAX_STANDARD_TX_WEIGHT")]
    TooLarge,
    /// Caller collected zero missing parents — orphaning would strand the tx
    /// (the `by_parent` index keys off `missing_parents`, so an empty set is
    /// unreachable from `children_of()`). Reachable under the parent-arrives-
    /// between-accept-and-collect race; callers drop silently.
    #[error("orphan has no missing parents — would be unreachable from reconsideration")]
    NoMissingParents,
}

/// Outcome of a successful [`TxOrphanage::add`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    /// A new orphan.
    Added,
    /// An orphan with the same wtxid was already held; the peer is now one
    /// of its announcers. Callers should NOT re-request missing parents on
    /// a duplicate — doing so lets a peer amplify outbound `getdata`
    /// traffic by resending the same orphan.
    Duplicate,
}

/// One orphan, a copy of what the orphanage holds.
#[derive(Debug, Clone)]
pub struct OrphanEntry {
    pub tx: Transaction,
    pub txid: Txid,
    pub wtxid: Wtxid,
    /// The parents it still waits for.
    pub missing_parents: HashSet<Txid>,
    /// Each peer that sent or announced it, with the sequence number of
    /// that announcement: Core's `Announcement::m_entry_sequence`.
    announcers: BTreeMap<PeerId, u64>,
    bytes: usize,
    weight: u64,
}

impl OrphanEntry {
    /// The peers that sent or announced it, lowest id first.
    pub fn announcers(&self) -> Vec<PeerId> {
        self.announcers.keys().copied().collect()
    }

    /// Core's `Announcement::GetLatencyScore`: one, plus one for every ten
    /// inputs, for the work each announcement costs a block or a departing
    /// peer.
    fn latency_score(&self) -> u32 {
        1 + Self::input_score(&self.tx)
    }

    fn input_score(tx: &Transaction) -> u32 {
        (tx.input.len() / 10) as u32
    }
}

/// Core's `PeerDoSInfo`: what one peer's announcements cost, and the
/// announcements themselves, oldest first.
#[derive(Debug, Default)]
struct PeerUsage {
    weight: u64,
    latency_score: u32,
    announcements: BTreeMap<u64, Wtxid>,
}

/// A ratio `num / den` ordered as Core orders a `FeeFrac`: by value, and
/// between equal values the one with the smaller denominator is greater
/// (`FeeFrac::operator<=>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DosScore {
    num: u64,
    den: u64,
}

impl DosScore {
    const ONE: DosScore = DosScore { num: 1, den: 1 };

    /// Strictly greater by value alone: Core's `FeeFrac::operator>>`.
    fn exceeds(self, other: DosScore) -> bool {
        u128::from(self.num) * u128::from(other.den) > u128::from(other.num) * u128::from(self.den)
    }
}

impl Ord for DosScore {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = u128::from(self.num) * u128::from(other.den);
        let b = u128::from(other.num) * u128::from(self.den);
        a.cmp(&b).then_with(|| other.den.cmp(&self.den))
    }
}

impl PartialOrd for DosScore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct OrphanageInner {
    by_wtxid: HashMap<Wtxid, OrphanEntry>,
    /// The wtxids held under each txid. More than one when orphans differ
    /// only in their witness.
    by_txid: HashMap<Txid, HashSet<Wtxid>>,
    /// The orphans waiting for each parent.
    by_parent: HashMap<Txid, HashSet<Wtxid>>,
    /// The orphans spending each outpoint: Core's
    /// `m_outpoint_to_orphan_wtxids`, for those a block conflicts with.
    by_outpoint: HashMap<OutPoint, HashSet<Wtxid>>,
    /// Every peer with an announcement. Its size is the number of peers the
    /// limits are shared between.
    peers: HashMap<PeerId, PeerUsage>,
    /// The number of announcements.
    announcements: u32,
    /// The orphans' weight, each counted once: Core's
    /// `m_unique_orphan_usage`.
    unique_weight: u64,
    /// The orphans' serialized size, each counted once.
    unique_bytes: usize,
    /// One per ten inputs of each orphan, counted once: Core's
    /// `m_unique_rounded_input_scores`.
    unique_input_score: u32,
    /// The next announcement's sequence number.
    next_seq: u64,
}

pub struct TxOrphanage {
    inner: Mutex<OrphanageInner>,
    config: OrphanageConfig,
}

impl TxOrphanage {
    pub fn new(config: OrphanageConfig) -> Self {
        Self {
            inner: Mutex::new(OrphanageInner {
                by_wtxid: HashMap::new(),
                by_txid: HashMap::new(),
                by_parent: HashMap::new(),
                by_outpoint: HashMap::new(),
                peers: HashMap::new(),
                announcements: 0,
                unique_weight: 0,
                unique_bytes: 0,
                unique_input_score: 0,
                next_seq: 0,
            }),
            config,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(OrphanageConfig::default())
    }

    pub fn config(&self) -> &OrphanageConfig {
        &self.config
    }

    /// Core's `AddTx`: hold `tx` as an orphan `from_peer` sent, then trim
    /// the orphanage back within its limits, which may evict this orphan
    /// too. `missing_parents` MUST be non-empty — an orphan with an empty
    /// set is reachable from no reconsideration path
    /// ([`children_of`](Self::children_of) walks `by_parent`), so it could
    /// only leave by eviction. Returns [`OrphanReject::NoMissingParents`]
    /// in that case; the caller's correct response is to drop the tx (the
    /// peer will re-relay via normal propagation if the condition was a
    /// race).
    ///
    /// When an orphan with the same wtxid is held, `from_peer` becomes one
    /// of its announcers and the outcome is [`AddOutcome::Duplicate`];
    /// callers MUST NOT re-send `getdata` for the parents in that case.
    pub fn add(
        &self,
        tx: Transaction,
        from_peer: PeerId,
        missing_parents: HashSet<Txid>,
    ) -> Result<AddOutcome, OrphanReject> {
        if missing_parents.is_empty() {
            return Err(OrphanReject::NoMissingParents);
        }
        let weight = tx.weight().to_wu();
        if weight as usize > MAX_STANDARD_TX_WEIGHT {
            return Err(OrphanReject::TooLarge);
        }
        let wtxid = tx.compute_wtxid();
        let mut inner = self.inner.lock();
        if inner.by_wtxid.contains_key(&wtxid) {
            if Self::announce_locked(&mut inner, &wtxid, from_peer) {
                self.limit_orphans(&mut inner);
            }
            return Ok(AddOutcome::Duplicate);
        }
        let txid = tx.compute_txid();
        let entry = OrphanEntry {
            bytes: bitcoin::consensus::serialize(&tx).len(),
            tx,
            txid,
            wtxid,
            missing_parents,
            announcers: BTreeMap::new(),
            weight,
        };
        inner.unique_weight += entry.weight;
        inner.unique_bytes += entry.bytes;
        inner.unique_input_score += OrphanEntry::input_score(&entry.tx);
        inner.by_txid.entry(txid).or_default().insert(wtxid);
        for parent in &entry.missing_parents {
            inner.by_parent.entry(*parent).or_default().insert(wtxid);
        }
        for input in &entry.tx.input {
            inner.by_outpoint.entry(input.previous_output).or_default().insert(wtxid);
        }
        inner.by_wtxid.insert(wtxid, entry);
        Self::announce_locked(&mut inner, &wtxid, from_peer);
        self.limit_orphans(&mut inner);
        Ok(AddOutcome::Added)
    }

    /// Core's `AddAnnouncer`: record that `peer` announced the orphan
    /// `wtxid` too, then trim the orphanage back within its limits. False
    /// when there is no such orphan or `peer` is already one of its
    /// announcers.
    pub fn add_announcer(&self, wtxid: &Wtxid, peer: PeerId) -> bool {
        let mut inner = self.inner.lock();
        if !Self::announce_locked(&mut inner, wtxid, peer) {
            return false;
        }
        self.limit_orphans(&mut inner);
        true
    }

    /// Add the announcement (`wtxid`, `peer`). False when the orphan is not
    /// held or the announcement exists.
    fn announce_locked(inner: &mut OrphanageInner, wtxid: &Wtxid, peer: PeerId) -> bool {
        let seq = inner.next_seq;
        let Some(entry) = inner.by_wtxid.get_mut(wtxid) else { return false };
        if entry.announcers.contains_key(&peer) {
            return false;
        }
        entry.announcers.insert(peer, seq);
        let (weight, latency_score) = (entry.weight, entry.latency_score());
        inner.next_seq += 1;
        inner.announcements += 1;
        let usage = inner.peers.entry(peer).or_default();
        usage.weight += weight;
        usage.latency_score += latency_score;
        usage.announcements.insert(seq, *wtxid);
        true
    }

    /// Remove the announcement (`wtxid`, `peer`), and the orphan with it if
    /// it was the last. True when the orphan went.
    fn drop_announcement_locked(inner: &mut OrphanageInner, wtxid: &Wtxid, peer: PeerId) -> bool {
        let Some(entry) = inner.by_wtxid.get_mut(wtxid) else { return false };
        let Some(seq) = entry.announcers.remove(&peer) else { return false };
        let last = entry.announcers.is_empty();
        let (weight, latency_score) = (entry.weight, entry.latency_score());
        inner.announcements -= 1;
        if let Some(usage) = inner.peers.get_mut(&peer) {
            usage.weight -= weight;
            usage.latency_score -= latency_score;
            usage.announcements.remove(&seq);
            // A peer with no announcements is not tracked, and not counted
            // among the peers that share the limits.
            if usage.announcements.is_empty() {
                inner.peers.remove(&peer);
            }
        }
        if last {
            Self::remove_unannounced_locked(inner, wtxid);
        }
        last
    }

    /// Take out an orphan whose last announcement has gone.
    fn remove_unannounced_locked(inner: &mut OrphanageInner, wtxid: &Wtxid) {
        let Some(entry) = inner.by_wtxid.remove(wtxid) else { return };
        debug_assert!(entry.announcers.is_empty());
        inner.unique_weight -= entry.weight;
        inner.unique_bytes -= entry.bytes;
        inner.unique_input_score -= OrphanEntry::input_score(&entry.tx);
        Self::unindex(&mut inner.by_txid, &entry.txid, wtxid);
        for parent in &entry.missing_parents {
            Self::unindex(&mut inner.by_parent, parent, wtxid);
        }
        for input in &entry.tx.input {
            Self::unindex(&mut inner.by_outpoint, &input.previous_output, wtxid);
        }
    }

    fn unindex<K: std::hash::Hash + Eq>(index: &mut HashMap<K, HashSet<Wtxid>>, key: &K, wtxid: &Wtxid) {
        if let Some(set) = index.get_mut(key) {
            set.remove(wtxid);
            if set.is_empty() {
                index.remove(key);
            }
        }
    }

    /// Remove every announcement of `wtxid`, and so the orphan. True when
    /// it was held.
    fn erase_locked(inner: &mut OrphanageInner, wtxid: &Wtxid) -> bool {
        let Some(peers) = inner.by_wtxid.get(wtxid).map(OrphanEntry::announcers) else { return false };
        for peer in peers {
            Self::drop_announcement_locked(inner, wtxid, peer);
        }
        true
    }

    /// Core's `EraseTx`: the orphan `wtxid` goes, whoever announced it.
    /// Removing it lowers the limits if a peer is left without
    /// announcements, so the orphanage is trimmed after.
    pub fn erase(&self, wtxid: &Wtxid) -> bool {
        let mut inner = self.inner.lock();
        let erased = Self::erase_locked(&mut inner, wtxid);
        self.limit_orphans(&mut inner);
        erased
    }

    /// Core's `EraseForPeer`: `peer` is no longer an announcer of anything,
    /// and an orphan no other peer announced goes. Returns those removed.
    pub fn erase_for_peer(&self, peer: PeerId) -> Vec<Wtxid> {
        let mut inner = self.inner.lock();
        let wtxids: Vec<Wtxid> =
            inner.peers.get(&peer).map(|u| u.announcements.values().copied().collect()).unwrap_or_default();
        let removed =
            wtxids.into_iter().filter(|wtxid| Self::drop_announcement_locked(&mut inner, wtxid, peer)).collect();
        self.limit_orphans(&mut inner);
        removed
    }

    /// Core's `EraseForBlock`: every orphan spending an outpoint a
    /// transaction in `block` spends goes, both those the block includes
    /// and those it conflicts with. Returns those removed.
    pub fn erase_for_block(&self, block: &bitcoin::Block) -> Vec<Wtxid> {
        let mut inner = self.inner.lock();
        if inner.by_wtxid.is_empty() {
            return Vec::new();
        }
        let mut doomed = BTreeSet::new();
        for tx in &block.txdata {
            for input in &tx.input {
                if let Some(set) = inner.by_outpoint.get(&input.previous_output) {
                    doomed.extend(set.iter().copied());
                }
            }
        }
        let removed: Vec<Wtxid> = doomed.into_iter().filter(|w| Self::erase_locked(&mut inner, w)).collect();
        self.limit_orphans(&mut inner);
        removed
    }

    /// Record the parents the orphan `wtxid` still waits for, after a
    /// reconsideration found it still missing inputs. An orphan left with
    /// none would be unreachable, so it goes instead. False when it is not
    /// held, or went.
    pub fn set_missing_parents(&self, wtxid: &Wtxid, missing_parents: HashSet<Txid>) -> bool {
        let mut inner = self.inner.lock();
        if missing_parents.is_empty() {
            Self::erase_locked(&mut inner, wtxid);
            self.limit_orphans(&mut inner);
            return false;
        }
        let Some(entry) = inner.by_wtxid.get_mut(wtxid) else { return false };
        let old = std::mem::replace(&mut entry.missing_parents, missing_parents.clone());
        for parent in old.difference(&missing_parents) {
            Self::unindex(&mut inner.by_parent, parent, wtxid);
        }
        for parent in missing_parents.difference(&old) {
            inner.by_parent.entry(*parent).or_default().insert(*wtxid);
        }
        true
    }

    /// The orphan with this wtxid, Core's `GetTx`.
    pub fn get_by_wtxid(&self, wtxid: &Wtxid) -> Option<Transaction> {
        self.inner.lock().by_wtxid.get(wtxid).map(|e| e.tx.clone())
    }

    /// A copy of the orphan `wtxid`, with its missing parents and
    /// announcers.
    pub fn entry(&self, wtxid: &Wtxid) -> Option<OrphanEntry> {
        self.inner.lock().by_wtxid.get(wtxid).cloned()
    }

    /// Core's `HaveTx`: an orphan with this wtxid is held.
    pub fn contains_wtxid(&self, wtxid: &Wtxid) -> bool {
        self.inner.lock().by_wtxid.contains_key(wtxid)
    }

    /// An orphan with this txid is held, whatever its witness.
    pub fn contains(&self, txid: &Txid) -> bool {
        self.inner.lock().by_txid.contains_key(txid)
    }

    /// Core's `HaveTxFromPeer`: `peer` is an announcer of the orphan `wtxid`.
    pub fn has_announcer(&self, wtxid: &Wtxid, peer: PeerId) -> bool {
        self.inner.lock().by_wtxid.get(wtxid).is_some_and(|e| e.announcers.contains_key(&peer))
    }

    /// Every orphan with its announcers, in wtxid order: Core's
    /// `GetOrphanTransactions`, for `getorphantxs`.
    pub fn orphans(&self) -> Vec<(Transaction, Vec<PeerId>)> {
        let inner = self.inner.lock();
        let mut entries: Vec<&OrphanEntry> = inner.by_wtxid.values().collect();
        entries.sort_by_key(|e| e.wtxid);
        entries.into_iter().map(|e| (e.tx.clone(), e.announcers())).collect()
    }

    /// The orphans waiting for `parent_txid`, in wtxid order. Caller
    /// typically retries `accept_transaction` on each.
    pub fn children_of(&self, parent_txid: &Txid) -> Vec<Wtxid> {
        let inner = self.inner.lock();
        let mut kids: Vec<Wtxid> =
            inner.by_parent.get(parent_txid).map(|set| set.iter().copied().collect()).unwrap_or_default();
        kids.sort_unstable();
        kids
    }

    /// Core's `GetChildrenFromSamePeer`: the orphans `peer` announced that
    /// spend `parent`, its newest announcement first. Only that peer's, so
    /// another peer cannot crowd out the real child with fake ones.
    pub fn children_from_peer(&self, parent: &Txid, peer: PeerId) -> Vec<Transaction> {
        let inner = self.inner.lock();
        let mut kids: Vec<(u64, Transaction)> = inner
            .by_parent
            .get(parent)
            .into_iter()
            .flatten()
            .filter_map(|w| inner.by_wtxid.get(w))
            .filter_map(|e| e.announcers.get(&peer).map(|seq| (*seq, e.tx.clone())))
            .collect();
        kids.sort_by(|a, b| b.0.cmp(&a.0));
        kids.into_iter().map(|(_, tx)| tx).collect()
    }

    /// Number of unique orphans: Core's `CountUniqueOrphans`.
    pub fn len(&self) -> usize {
        self.inner.lock().by_wtxid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().by_wtxid.is_empty()
    }

    /// The orphans' serialized size, each counted once.
    pub fn bytes(&self) -> usize {
        self.inner.lock().unique_bytes
    }

    /// The orphans' weight, each counted once: Core's `TotalOrphanUsage`.
    pub fn weight(&self) -> u64 {
        self.inner.lock().unique_weight
    }

    /// Core's `CountAnnouncements`.
    pub fn announcements(&self) -> u32 {
        self.inner.lock().announcements
    }

    /// Core's `TotalLatencyScore`.
    pub fn latency_score(&self) -> u32 {
        let inner = self.inner.lock();
        Self::total_latency_score(&inner)
    }

    /// Core's `MaxGlobalLatencyScore`.
    pub fn max_latency_score(&self) -> u32 {
        self.config.max_global_latency_score
    }

    /// Core's `MaxGlobalUsage`: the reserved weight times the number of
    /// peers with an announcement, or one peer's when there are none.
    pub fn max_weight(&self) -> u64 {
        let inner = self.inner.lock();
        self.max_global_usage(&inner)
    }

    /// Core's `AnnouncementsFromPeer`.
    pub fn announcements_from_peer(&self, peer: PeerId) -> u32 {
        self.inner.lock().peers.get(&peer).map_or(0, |u| u.announcements.len() as u32)
    }

    /// Core's `LatencyScoreFromPeer`.
    pub fn latency_score_from_peer(&self, peer: PeerId) -> u32 {
        self.inner.lock().peers.get(&peer).map_or(0, |u| u.latency_score)
    }

    /// Core's `UsageByPeer`.
    pub fn weight_from_peer(&self, peer: PeerId) -> u64 {
        self.inner.lock().peers.get(&peer).map_or(0, |u| u.weight)
    }

    fn total_latency_score(inner: &OrphanageInner) -> u32 {
        inner.unique_input_score + inner.announcements
    }

    fn peer_count(inner: &OrphanageInner) -> u64 {
        (inner.peers.len() as u64).max(1)
    }

    fn max_global_usage(&self, inner: &OrphanageInner) -> u64 {
        self.config.reserved_peer_usage * Self::peer_count(inner)
    }

    /// Core's `MaxPeerLatencyScore`: the latency limit shared equally
    /// between the peers with an announcement.
    fn max_peer_latency_score(&self, inner: &OrphanageInner) -> u32 {
        // Never zero: the score divides by it.
        (u64::from(self.config.max_global_latency_score) / Self::peer_count(inner)).max(1) as u32
    }

    /// Core's `NeedsTrim`.
    fn needs_trim(&self, inner: &OrphanageInner) -> bool {
        Self::total_latency_score(inner) > self.config.max_global_latency_score
            || inner.unique_weight > self.max_global_usage(inner)
    }

    /// Core's `PeerDoSInfo::GetDosScore`: the larger of the peer's share of
    /// its latency limit and of its weight reservation.
    fn dos_score(usage: &PeerUsage, max_latency: u32, max_weight: u64) -> DosScore {
        let latency = DosScore { num: u64::from(usage.latency_score), den: u64::from(max_latency) };
        let weight = DosScore { num: usage.weight, den: max_weight.max(1) };
        latency.max(weight)
    }

    /// Core's `LimitOrphans`: while the orphanage is past a global limit,
    /// take the peer with the highest DoS score and drop its oldest
    /// announcements until it no longer has the highest score. Between
    /// equal scores the higher peer id, the more recent connection, goes
    /// first. A peer whose score is within 1 is never chosen, and while
    /// the orphanage is past a limit some peer's score is above 1.
    fn limit_orphans(&self, inner: &mut OrphanageInner) {
        if !self.needs_trim(inner) {
            return;
        }
        // The same limits throughout, as in Core, though dropping a peer's
        // last announcement raises the per-peer latency share.
        let max_latency = self.max_peer_latency_score(inner);
        let max_weight = self.config.reserved_peer_usage;
        let mut heap: BinaryHeap<(DosScore, PeerId)> = inner
            .peers
            .iter()
            .map(|(peer, usage)| (Self::dos_score(usage, max_latency, max_weight), *peer))
            .filter(|(score, _)| score.exceeds(DosScore::ONE))
            .collect();
        while let Some((_, worst)) = heap.pop() {
            let threshold = heap.peek().map_or(DosScore::ONE, |(score, _)| *score);
            while self.needs_trim(inner) {
                let Some((_, wtxid)) =
                    inner.peers.get(&worst).and_then(|u| u.announcements.first_key_value()).map(|(s, w)| (*s, *w))
                else {
                    break;
                };
                Self::drop_announcement_locked(inner, &wtxid, worst);
                match inner.peers.get(&worst) {
                    Some(usage) if Self::dos_score(usage, max_latency, max_weight) > threshold => {}
                    _ => break,
                }
            }
            if !self.needs_trim(inner) {
                return;
            }
            // Still over: the peer goes back in the heap and may be chosen
            // again.
            if let Some(usage) = inner.peers.get(&worst) {
                heap.push((Self::dos_score(usage, max_latency, max_weight), worst));
            }
        }
    }

    /// Core's `SanityCheck`: every index and running total agrees with the
    /// orphans held.
    #[cfg(test)]
    fn sanity_check(&self) {
        let inner = self.inner.lock();
        let mut peers: HashMap<PeerId, (u64, u32, usize)> = HashMap::new();
        let (mut weight, mut bytes, mut input_score, mut announcements) = (0, 0, 0, 0);
        for (wtxid, entry) in &inner.by_wtxid {
            assert!(!entry.announcers.is_empty(), "an orphan with no announcer");
            weight += entry.weight;
            bytes += entry.bytes;
            input_score += OrphanEntry::input_score(&entry.tx);
            announcements += entry.announcers.len() as u32;
            for (peer, seq) in &entry.announcers {
                assert_eq!(inner.peers[peer].announcements.get(seq), Some(wtxid));
                let p = peers.entry(*peer).or_default();
                p.0 += entry.weight;
                p.1 += entry.latency_score();
                p.2 += 1;
            }
            assert!(inner.by_txid[&entry.txid].contains(wtxid));
            for parent in &entry.missing_parents {
                assert!(inner.by_parent[parent].contains(wtxid));
            }
            for input in &entry.tx.input {
                assert!(inner.by_outpoint[&input.previous_output].contains(wtxid));
            }
        }
        assert_eq!(inner.unique_weight, weight);
        assert_eq!(inner.unique_bytes, bytes);
        assert_eq!(inner.unique_input_score, input_score);
        assert_eq!(inner.announcements, announcements);
        assert_eq!(inner.peers.len(), peers.len(), "a peer is tracked with no announcement");
        for (peer, (w, l, n)) in peers {
            let usage = &inner.peers[&peer];
            assert_eq!((usage.weight, usage.latency_score, usage.announcements.len()), (w, l, n));
        }
        let indexed: usize = inner.by_txid.values().map(HashSet::len).sum();
        assert_eq!(indexed, inner.by_wtxid.len());
        for set in inner.by_parent.values().chain(inner.by_outpoint.values()) {
            assert!(!set.is_empty() && set.iter().all(|w| inner.by_wtxid.contains_key(w)));
        }
    }
}

#[cfg(test)]
#[path = "orphanage_tests.rs"]
mod tests;
