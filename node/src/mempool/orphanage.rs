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
//! the mempool or when a new block connects. Mirrors Bitcoin Core's
//! `TxOrphanage` at the fidelity satd needs today: global count cap +
//! per-peer count quota + time-based expiry. Weight-based per-peer
//! CPU/memory DoS scoring (Core 30+) is out of scope.

use bitcoin::{Transaction, Txid, Wtxid};
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::mempool::policy::MAX_STANDARD_TX_WEIGHT;
use crate::net::peer::PeerId;

/// Default global cap. Matches Bitcoin Core's pre-v30 `-maxorphantx`
/// default; v1 deliberately does not track weight, only count.
pub const DEFAULT_MAX_ORPHAN_COUNT: usize = 100;

/// Default per-peer cap. Half of the global cap: one misbehaving peer
/// can occupy at most half of the pool.
pub const DEFAULT_MAX_ORPHAN_PER_PEER: usize = 50;

/// Default expiry. Matches Bitcoin Core's `ORPHAN_TX_EXPIRE_TIME`.
pub const DEFAULT_ORPHAN_EXPIRY: Duration = Duration::from_secs(20 * 60);

#[derive(Debug, Clone)]
pub struct OrphanageConfig {
    pub max_count: usize,
    pub max_per_peer: usize,
    pub expiry: Duration,
}

impl Default for OrphanageConfig {
    fn default() -> Self {
        Self {
            max_count: DEFAULT_MAX_ORPHAN_COUNT,
            max_per_peer: DEFAULT_MAX_ORPHAN_PER_PEER,
            expiry: DEFAULT_ORPHAN_EXPIRY,
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
    /// Fresh insertion.
    Added,
    /// An orphan with the same `txid` was already present; pool state
    /// unchanged. Callers should NOT re-request missing parents on a
    /// duplicate — doing so lets a peer amplify outbound `getdata` traffic
    /// by resending the same orphan.
    Duplicate,
}

#[derive(Debug, Clone)]
pub struct OrphanEntry {
    pub tx: Transaction,
    pub wtxid: Wtxid,
    /// The peers that sent or announced it, Core's `announcers`
    /// (`src/node/txorphanage.h`). It stays while any of them does.
    pub announcers: BTreeSet<PeerId>,
    pub added_at: Instant,
    pub missing_parents: HashSet<Txid>,
    pub bytes: usize,
    /// Its key in the orphanage's arrival-order queue.
    seq: u64,
}

struct OrphanageInner {
    by_txid: HashMap<Txid, OrphanEntry>,
    by_wtxid: HashMap<Wtxid, Txid>,
    by_parent: HashMap<Txid, HashSet<Txid>>,
    by_peer: HashMap<PeerId, HashSet<Txid>>,
    total_bytes: usize,
    /// The live orphans in arrival order, for FIFO eviction, keyed by an
    /// arrival sequence number as Core's orphanage keys its announcements
    /// (`m_entry_sequence`, src/node/txorphanage.cpp). Every removal takes
    /// its orphan's key out, so this holds exactly the orphans in `by_txid`.
    order: BTreeMap<u64, Txid>,
    /// The next arrival's key in `order`.
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
                by_txid: HashMap::new(),
                by_wtxid: HashMap::new(),
                by_parent: HashMap::new(),
                by_peer: HashMap::new(),
                total_bytes: 0,
                order: BTreeMap::new(),
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

    /// Insert `tx` as an orphan. `missing_parents` MUST be non-empty — an
    /// orphan with an empty set is indexed only under `by_txid`/`by_peer`
    /// and would be unreachable from the reconsideration paths
    /// ([`children_of`](Self::children_of) walks `by_parent`), so it could
    /// only exit via expiry or FIFO eviction. Returns
    /// [`OrphanReject::NoMissingParents`] in that case; the caller's
    /// correct response is to drop the tx (the peer will re-relay via
    /// normal propagation if the condition was a race).
    ///
    /// On duplicate `txid`, returns [`AddOutcome::Duplicate`] without
    /// mutating the pool — callers MUST NOT re-send `getdata` for the
    /// parents in that case.
    pub fn add(
        &self,
        tx: Transaction,
        from_peer: PeerId,
        missing_parents: HashSet<Txid>,
    ) -> Result<AddOutcome, OrphanReject> {
        if missing_parents.is_empty() {
            return Err(OrphanReject::NoMissingParents);
        }
        let weight = tx.weight().to_wu() as usize;
        if weight > MAX_STANDARD_TX_WEIGHT {
            return Err(OrphanReject::TooLarge);
        }
        let bytes = bitcoin::consensus::serialize(&tx).len();
        let txid = tx.compute_txid();
        let announcers = BTreeSet::from([from_peer]);
        Ok(self.add_at(tx, txid, announcers, missing_parents, bytes, Instant::now()))
    }

    /// Put back an orphan taken out with [`remove`](Self::remove) that is
    /// still missing parents, with every peer that announced it.
    pub fn restore(
        &self,
        entry: OrphanEntry,
        missing_parents: HashSet<Txid>,
    ) -> Result<AddOutcome, OrphanReject> {
        if missing_parents.is_empty() {
            return Err(OrphanReject::NoMissingParents);
        }
        let txid = entry.tx.compute_txid();
        Ok(self.add_at(entry.tx, txid, entry.announcers, missing_parents, entry.bytes, Instant::now()))
    }

    fn add_at(
        &self,
        tx: Transaction,
        txid: Txid,
        announcers: BTreeSet<PeerId>,
        missing_parents: HashSet<Txid>,
        bytes: usize,
        added_at: Instant,
    ) -> AddOutcome {
        let mut inner = self.inner.lock();

        // Idempotent on duplicate txid — report so the caller can skip
        // re-requesting parents.
        if inner.by_txid.contains_key(&txid) {
            return AddOutcome::Duplicate;
        }

        // Per-peer quota: make room in each announcer's share first.
        for peer in &announcers {
            self.make_room_for(&mut inner, *peer);
        }

        // Global cap: evict oldest (FIFO) until we have room.
        while inner.by_txid.len() >= self.config.max_count {
            if let Some(victim) = Self::oldest(&inner) {
                Self::remove_locked(&mut inner, &victim);
            } else {
                break;
            }
        }

        let seq = inner.next_seq;
        inner.next_seq += 1;
        let wtxid = tx.compute_wtxid();
        let entry = OrphanEntry {
            tx,
            wtxid,
            announcers: announcers.clone(),
            added_at,
            missing_parents: missing_parents.clone(),
            bytes,
            seq,
        };
        inner.by_txid.insert(txid, entry);
        inner.by_wtxid.insert(wtxid, txid);
        inner.total_bytes += bytes;
        inner.order.insert(seq, txid);
        for parent in &missing_parents {
            inner.by_parent.entry(*parent).or_default().insert(txid);
        }
        for peer in announcers {
            inner.by_peer.entry(peer).or_default().insert(txid);
        }
        AddOutcome::Added
    }

    /// Core's `AddAnnouncer`: record that `peer` announced the orphan
    /// `wtxid` too. False when there is no such orphan or `peer` is already
    /// one of its announcers.
    pub fn add_announcer(&self, wtxid: &Wtxid, peer: PeerId) -> bool {
        let mut inner = self.inner.lock();
        let Some(txid) = inner.by_wtxid.get(wtxid).copied() else { return false };
        if inner.by_txid.get(&txid).is_some_and(|e| e.announcers.contains(&peer)) {
            return false;
        }
        self.make_room_for(&mut inner, peer);
        // Making room may have dropped this very orphan.
        let Some(entry) = inner.by_txid.get_mut(&txid) else { return false };
        entry.announcers.insert(peer);
        inner.by_peer.entry(peer).or_default().insert(txid);
        true
    }

    /// Core's `EraseForPeer`: `peer` is no longer an announcer of anything,
    /// and an orphan no other peer announced goes. Returns those removed.
    pub fn erase_for_peer(&self, peer: PeerId) -> Vec<Txid> {
        let mut inner = self.inner.lock();
        let Some(txids) = inner.by_peer.get(&peer).cloned() else { return Vec::new() };
        txids.into_iter().filter(|txid| Self::drop_announcer_locked(&mut inner, txid, peer)).collect()
    }

    /// The orphan with this wtxid, Core's `GetTx`.
    pub fn get_by_wtxid(&self, wtxid: &Wtxid) -> Option<Transaction> {
        let inner = self.inner.lock();
        inner.by_wtxid.get(wtxid).and_then(|t| inner.by_txid.get(t)).map(|e| e.tx.clone())
    }

    /// Core's `HaveTx`: an orphan with this wtxid is held.
    pub fn contains_wtxid(&self, wtxid: &Wtxid) -> bool {
        self.inner.lock().by_wtxid.contains_key(wtxid)
    }

    /// Core's `HaveTxFromPeer`: `peer` is an announcer of the orphan `wtxid`.
    pub fn has_announcer(&self, wtxid: &Wtxid, peer: PeerId) -> bool {
        let inner = self.inner.lock();
        inner
            .by_wtxid
            .get(wtxid)
            .and_then(|t| inner.by_txid.get(t))
            .is_some_and(|e| e.announcers.contains(&peer))
    }

    /// Every orphan with its announcers, oldest first: Core's
    /// `GetOrphanTransactions`, for `getorphantxs`.
    pub fn orphans(&self) -> Vec<(Transaction, Vec<PeerId>)> {
        let inner = self.inner.lock();
        inner
            .order
            .values()
            .filter_map(|t| inner.by_txid.get(t))
            .map(|e| (e.tx.clone(), e.announcers.iter().copied().collect()))
            .collect()
    }

    /// Keep `peer` within its per-peer quota before it announces one more
    /// orphan: it stops announcing its oldest, which goes if no other peer
    /// announced it.
    fn make_room_for(&self, inner: &mut OrphanageInner, peer: PeerId) {
        if let Some(peer_set) = inner.by_peer.get(&peer)
            && peer_set.len() >= self.config.max_per_peer
            && let Some(victim) = Self::oldest_for_peer(inner, peer)
        {
            Self::drop_announcer_locked(inner, &victim, peer);
        }
    }

    /// `peer` stops announcing `txid`; the orphan goes when it was the last.
    /// True when the orphan went.
    fn drop_announcer_locked(inner: &mut OrphanageInner, txid: &Txid, peer: PeerId) -> bool {
        let Some(entry) = inner.by_txid.get_mut(txid) else { return false };
        entry.announcers.remove(&peer);
        let last = entry.announcers.is_empty();
        // The peer's index is cleaned here, before `remove_locked`, which
        // cleans only the announcers the orphan still has.
        if let Some(set) = inner.by_peer.get_mut(&peer) {
            set.remove(txid);
            if set.is_empty() {
                inner.by_peer.remove(&peer);
            }
        }
        if last {
            Self::remove_locked(inner, txid);
        }
        last
    }

    /// Return child-orphan txids that list `parent_txid` as a missing
    /// parent. Caller typically calls [`remove`](Self::remove) on each
    /// child and retries `accept_transaction`.
    pub fn children_of(&self, parent_txid: &Txid) -> Vec<Txid> {
        let inner = self.inner.lock();
        inner
            .by_parent
            .get(parent_txid)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Core's `GetChildrenFromSamePeer`: the orphans `peer` sent that spend
    /// `parent`, newest first. Only that peer's, so another peer cannot
    /// crowd out the real child with fake ones.
    pub fn children_from_peer(&self, parent: &Txid, peer: PeerId) -> Vec<Transaction> {
        let inner = self.inner.lock();
        let mut kids: Vec<(u64, Transaction)> = inner
            .by_parent
            .get(parent)
            .into_iter()
            .flatten()
            .filter_map(|t| inner.by_txid.get(t))
            .filter(|e| e.announcers.contains(&peer))
            .map(|e| (e.seq, e.tx.clone()))
            .collect();
        kids.sort_by(|a, b| b.0.cmp(&a.0));
        kids.into_iter().map(|(_, tx)| tx).collect()
    }

    /// Remove and return the orphan entry for `txid`, if present. Cleans
    /// all indexes atomically.
    pub fn remove(&self, txid: &Txid) -> Option<OrphanEntry> {
        let mut inner = self.inner.lock();
        Self::remove_locked(&mut inner, txid)
    }

    fn remove_locked(inner: &mut OrphanageInner, txid: &Txid) -> Option<OrphanEntry> {
        let entry = inner.by_txid.remove(txid)?;
        inner.total_bytes = inner.total_bytes.saturating_sub(entry.bytes);
        for parent in &entry.missing_parents {
            if let Some(set) = inner.by_parent.get_mut(parent) {
                set.remove(txid);
                if set.is_empty() {
                    inner.by_parent.remove(parent);
                }
            }
        }
        inner.by_wtxid.remove(&entry.wtxid);
        for peer in &entry.announcers {
            if let Some(set) = inner.by_peer.get_mut(peer) {
                set.remove(txid);
                if set.is_empty() {
                    inner.by_peer.remove(peer);
                }
            }
        }
        inner.order.remove(&entry.seq);
        Some(entry)
    }

    /// Sweep entries past expiry. `now` is injected so tests can drive
    /// the clock.
    pub fn expire(&self, now: Instant) -> Vec<Txid> {
        let mut inner = self.inner.lock();
        let expiry = self.config.expiry;
        let victims: Vec<Txid> = inner
            .by_txid
            .iter()
            .filter(|(_, e)| now.duration_since(e.added_at) >= expiry)
            .map(|(txid, _)| *txid)
            .collect();
        for txid in &victims {
            Self::remove_locked(&mut inner, txid);
        }
        victims
    }

    pub fn len(&self) -> usize {
        self.inner.lock().by_txid.len()
    }

    pub fn bytes(&self) -> usize {
        self.inner.lock().total_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().by_txid.is_empty()
    }

    pub fn contains(&self, txid: &Txid) -> bool {
        self.inner.lock().by_txid.contains_key(txid)
    }

    fn oldest(inner: &OrphanageInner) -> Option<Txid> {
        inner.order.first_key_value().map(|(_, txid)| *txid)
    }

    /// The peer's oldest orphan: a scan of that peer's own orphans, at most
    /// `config.max_per_peer` of them.
    fn oldest_for_peer(inner: &OrphanageInner, peer: PeerId) -> Option<Txid> {
        inner
            .by_peer
            .get(&peer)?
            .iter()
            .filter_map(|txid| inner.by_txid.get(txid).map(|e| (e.seq, *txid)))
            .min()
            .map(|(_, txid)| txid)
    }
}

#[cfg(test)]
#[path = "orphanage_order_tests.rs"]
mod order_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn make_tx(parent: Txid, vout: u32, out_value: u64) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: parent, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(out_value),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn rand_txid(seed: u8) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        Txid::from_slice(&bytes).unwrap()
    }

    #[test]
    fn test_add_remove_roundtrip() {
        let pool = TxOrphanage::with_defaults();
        let parent = rand_txid(1);
        let tx = make_tx(parent, 0, 100);
        let txid = tx.compute_txid();
        let mut missing = HashSet::new();
        missing.insert(parent);

        pool.add(tx, 42, missing).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&txid));
        assert_eq!(pool.children_of(&parent), vec![txid]);

        let entry = pool.remove(&txid).unwrap();
        assert_eq!(entry.announcers, BTreeSet::from([42]));
        assert_eq!(pool.len(), 0);
        assert!(pool.children_of(&parent).is_empty());
        assert_eq!(pool.bytes(), 0);
    }

    #[test]
    fn test_global_fifo_eviction() {
        let config = OrphanageConfig {
            max_count: 3,
            max_per_peer: 10,
            expiry: DEFAULT_ORPHAN_EXPIRY,
        };
        let pool = TxOrphanage::new(config);
        let mut txids = Vec::new();
        for i in 0..3 {
            let tx = make_tx(rand_txid(i as u8 + 1), 0, 100 + i);
            txids.push(tx.compute_txid());
            let mut missing = HashSet::new();
            missing.insert(rand_txid(i as u8 + 1));
            pool.add(tx, 1, missing).unwrap();
        }
        assert_eq!(pool.len(), 3);

        // Adding a 4th should evict the oldest (index 0).
        let tx = make_tx(rand_txid(99), 0, 200);
        let new_txid = tx.compute_txid();
        let mut missing = HashSet::new();
        missing.insert(rand_txid(99));
        pool.add(tx, 1, missing).unwrap();

        assert_eq!(pool.len(), 3);
        assert!(!pool.contains(&txids[0]), "oldest should be evicted");
        assert!(pool.contains(&txids[1]));
        assert!(pool.contains(&txids[2]));
        assert!(pool.contains(&new_txid));
    }

    #[test]
    fn test_per_peer_quota() {
        let config = OrphanageConfig {
            max_count: 100,
            max_per_peer: 2,
            expiry: DEFAULT_ORPHAN_EXPIRY,
        };
        let pool = TxOrphanage::new(config);

        // Peer A: 2 orphans (hits quota).
        let mut a_txids = Vec::new();
        for i in 0..2 {
            let tx = make_tx(rand_txid(i as u8 + 1), 0, 100 + i);
            a_txids.push(tx.compute_txid());
            let mut missing = HashSet::new();
            missing.insert(rand_txid(i as u8 + 1));
            pool.add(tx, 1, missing).unwrap();
        }

        // Peer B: 2 orphans (its own quota). Peer A's orphans untouched.
        let mut b_txids = Vec::new();
        for i in 0..2 {
            let tx = make_tx(rand_txid(i as u8 + 10), 0, 200 + i);
            b_txids.push(tx.compute_txid());
            let mut missing = HashSet::new();
            missing.insert(rand_txid(i as u8 + 10));
            pool.add(tx, 2, missing).unwrap();
        }
        assert_eq!(pool.len(), 4);

        // Peer A adds a 3rd: should evict A's oldest, NOT touch B.
        let tx = make_tx(rand_txid(50), 0, 999);
        let new_a = tx.compute_txid();
        let mut missing = HashSet::new();
        missing.insert(rand_txid(50));
        pool.add(tx, 1, missing).unwrap();

        assert_eq!(pool.len(), 4);
        assert!(!pool.contains(&a_txids[0]), "A's oldest evicted");
        assert!(pool.contains(&a_txids[1]));
        assert!(pool.contains(&new_a));
        assert!(pool.contains(&b_txids[0]), "B untouched");
        assert!(pool.contains(&b_txids[1]), "B untouched");
    }

    #[test]
    fn test_expiry() {
        let config = OrphanageConfig {
            max_count: 100,
            max_per_peer: 100,
            expiry: Duration::from_secs(60),
        };
        let pool = TxOrphanage::new(config);

        let t0 = Instant::now();
        // Inject two orphans at t0 and one at t0 + 90s.
        let tx_old = make_tx(rand_txid(1), 0, 100);
        let old_txid = tx_old.compute_txid();
        pool.add_at(
            tx_old,
            old_txid,
            BTreeSet::from([1]),
            [rand_txid(1)].into_iter().collect(),
            250,
            t0,
        );
        let tx_fresh = make_tx(rand_txid(2), 0, 100);
        let fresh_txid = tx_fresh.compute_txid();
        pool.add_at(
            tx_fresh,
            fresh_txid,
            BTreeSet::from([1]),
            [rand_txid(2)].into_iter().collect(),
            250,
            t0 + Duration::from_secs(90),
        );

        // Sweep at t0 + 90s: old expired, fresh still in.
        let victims = pool.expire(t0 + Duration::from_secs(90));
        assert_eq!(victims, vec![old_txid]);
        assert!(!pool.contains(&old_txid));
        assert!(pool.contains(&fresh_txid));

        // Sweep at t0 + 151s: fresh also expired.
        let victims = pool.expire(t0 + Duration::from_secs(151));
        assert_eq!(victims, vec![fresh_txid]);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_children_of_index_maintained() {
        let pool = TxOrphanage::with_defaults();
        let parent = rand_txid(7);

        // Three children of the same parent.
        let mut child_txids = Vec::new();
        for i in 0..3 {
            let tx = make_tx(parent, i, 100);
            child_txids.push(tx.compute_txid());
            let mut missing = HashSet::new();
            missing.insert(parent);
            pool.add(tx, 1, missing).unwrap();
        }

        let children = pool.children_of(&parent);
        assert_eq!(children.len(), 3);
        for c in &child_txids {
            assert!(children.contains(c));
        }

        // Remove one; index shrinks.
        pool.remove(&child_txids[1]).unwrap();
        let children = pool.children_of(&parent);
        assert_eq!(children.len(), 2);
        assert!(!children.contains(&child_txids[1]));

        // Remove remaining; parent key disappears.
        pool.remove(&child_txids[0]).unwrap();
        pool.remove(&child_txids[2]).unwrap();
        assert!(pool.children_of(&parent).is_empty());
        let inner = pool.inner.lock();
        assert!(
            !inner.by_parent.contains_key(&parent),
            "empty parent bucket should be dropped"
        );
    }

    #[test]
    fn test_too_large_rejected() {
        let pool = TxOrphanage::with_defaults();
        // Build a transaction with a single output script > MAX_STANDARD_TX_WEIGHT vbytes.
        // Easiest: huge OP_RETURN-like scriptpubkey. Weight = 4*size for non-witness.
        let huge_script = ScriptBuf::from_bytes(vec![0u8; 200_000]);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: rand_txid(1),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: huge_script,
            }],
        };
        assert!(tx.weight().to_wu() as usize > MAX_STANDARD_TX_WEIGHT);

        let missing = [rand_txid(1)].into_iter().collect();
        let err = pool.add(tx, 1, missing).unwrap_err();
        assert!(matches!(err, OrphanReject::TooLarge));
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_add_duplicate_returns_duplicate_outcome() {
        let pool = TxOrphanage::with_defaults();
        let parent = rand_txid(1);
        let tx = make_tx(parent, 0, 100);
        let txid = tx.compute_txid();
        let missing: HashSet<Txid> = [parent].into_iter().collect();

        let first = pool.add(tx.clone(), 1, missing.clone()).unwrap();
        assert_eq!(first, AddOutcome::Added);

        // Same tx, different peer — must report Duplicate and leave the
        // pool unchanged (including the original peer's index entry).
        let second = pool.add(tx, 2, missing).unwrap();
        assert_eq!(second, AddOutcome::Duplicate);
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&txid));

        let inner = pool.inner.lock();
        assert!(inner.by_peer.get(&1).is_some_and(|s| s.contains(&txid)));
        assert!(
            !inner.by_peer.contains_key(&2),
            "duplicate add must not touch peer-2 index"
        );
    }

    #[test]
    fn test_add_empty_missing_parents_rejected() {
        // Empty `missing_parents` would strand the orphan: `by_parent`
        // stays empty for it, so `children_of()` never returns it and it
        // can only exit via FIFO eviction or expiry. `add` must reject.
        let pool = TxOrphanage::with_defaults();
        let tx = make_tx(rand_txid(1), 0, 100);
        let err = pool.add(tx, 1, HashSet::new()).unwrap_err();
        assert!(matches!(err, OrphanReject::NoMissingParents));
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.bytes(), 0);
    }

    fn add_orphan(pool: &TxOrphanage, seed: u8, peer: PeerId) -> Transaction {
        let tx = make_tx(rand_txid(seed), 0, 1_000);
        pool.add(tx.clone(), peer, [rand_txid(seed)].into_iter().collect()).unwrap();
        tx
    }

    fn announcers(pool: &TxOrphanage, tx: &Transaction) -> Vec<PeerId> {
        let txid = tx.compute_txid();
        pool.orphans()
            .into_iter()
            .find(|(t, _)| t.compute_txid() == txid)
            .map(|(_, from)| from)
            .unwrap_or_default()
    }

    /// Core's `AddAnnouncer`: a second peer is recorded once, and only for
    /// an orphan that is held.
    #[test]
    fn a_second_peer_is_recorded_as_an_announcer() {
        let pool = TxOrphanage::with_defaults();
        let tx = add_orphan(&pool, 1, 1);
        let wtxid = tx.compute_wtxid();
        assert!(pool.add_announcer(&wtxid, 2));
        assert!(!pool.add_announcer(&wtxid, 2), "already an announcer");
        assert!(!pool.add_announcer(&make_tx(rand_txid(9), 0, 1).compute_wtxid(), 2), "no such orphan");
        assert_eq!(announcers(&pool, &tx), vec![1, 2]);
        assert!(pool.has_announcer(&wtxid, 2));
        assert_eq!(pool.children_from_peer(&rand_txid(1), 2), vec![tx.clone()], "peer 2's child too");
    }

    /// Core's `EraseForPeer`: a departing peer stops announcing, and only
    /// the orphans no other peer announced go.
    #[test]
    fn a_departing_peer_takes_only_its_own_orphans() {
        let pool = TxOrphanage::with_defaults();
        let shared = add_orphan(&pool, 1, 1);
        let own = add_orphan(&pool, 2, 1);
        pool.add_announcer(&shared.compute_wtxid(), 2);

        assert_eq!(pool.erase_for_peer(1), vec![own.compute_txid()]);
        assert!(!pool.contains(&own.compute_txid()));
        assert!(!pool.contains_wtxid(&own.compute_wtxid()), "every index forgets it");
        assert_eq!(announcers(&pool, &shared), vec![2]);
        assert!(pool.children_from_peer(&rand_txid(1), 1).is_empty());
        assert!(pool.erase_for_peer(1).is_empty());
    }

    /// A peer past its quota stops announcing its oldest orphan; that orphan
    /// stays while another peer announces it.
    #[test]
    fn a_peer_over_its_quota_drops_its_oldest_announcement() {
        let pool = TxOrphanage::new(OrphanageConfig { max_count: 10, max_per_peer: 2, ..Default::default() });
        let shared = add_orphan(&pool, 1, 1);
        pool.add_announcer(&shared.compute_wtxid(), 2);
        let second = add_orphan(&pool, 2, 1);
        let third = add_orphan(&pool, 3, 1);

        assert!(pool.contains(&shared.compute_txid()), "peer 2 still announces it");
        assert_eq!(announcers(&pool, &shared), vec![2]);
        assert_eq!(announcers(&pool, &second), vec![1]);
        assert_eq!(announcers(&pool, &third), vec![1]);
    }

    /// An orphan taken out for another look and put back keeps every
    /// announcer.
    #[test]
    fn a_restored_orphan_keeps_its_announcers() {
        let pool = TxOrphanage::with_defaults();
        let tx = add_orphan(&pool, 1, 1);
        pool.add_announcer(&tx.compute_wtxid(), 2);
        let entry = pool.remove(&tx.compute_txid()).unwrap();
        assert!(!pool.contains_wtxid(&tx.compute_wtxid()));
        pool.restore(entry, [rand_txid(1)].into_iter().collect()).unwrap();
        assert_eq!(announcers(&pool, &tx), vec![1, 2]);
        assert_eq!(pool.get_by_wtxid(&tx.compute_wtxid()), Some(tx));
    }

    /// A peer's index holds only the orphans it still announces: after its
    /// quota drops its oldest, and after it departs.
    #[test]
    fn a_peer_s_index_holds_only_what_it_announces() {
        let pool = TxOrphanage::new(OrphanageConfig { max_count: 100, max_per_peer: 2, ..Default::default() });
        for seed in 1..=5 {
            add_orphan(&pool, seed, 1);
        }
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.inner.lock().by_peer.get(&1).map(|s| s.len()), Some(2));

        pool.erase_for_peer(1);
        assert!(pool.is_empty());
        assert!(pool.inner.lock().by_peer.is_empty(), "no index left for the departed peer");
    }
}
