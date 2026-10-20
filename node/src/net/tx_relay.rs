//! Core's transaction announcement schedule (`Peer::TxRelay` and the
//! transaction part of `PeerManagerImpl::SendMessages`).
//!
//! A transaction that enters the mempool is not announced at once. It is
//! queued for each peer that does not already know it, and each peer's
//! queue is flushed on a Poisson timer: on average every 2 s for an
//! outbound peer, and every 5 s for inbound peers, which share one timer
//! per network they reached the node on. A peer with `noban` is flushed
//! every time. A flush announces at most 70 transactions (more when the
//! queue is long), fewest unconfirmed ancestors first, then highest
//! feerate, so a child is never announced before its parent.
//!
//! Delaying the announcement hides when the transaction arrived. So that a
//! peer cannot learn it anyway by asking, a peer is served a transaction
//! from the mempool only if it entered before the peer's last flush (Core's
//! `m_last_inv_sequence`, checked by `CTxMemPool::info_for_relay`).

use std::cmp::Ordering;
use std::collections::{HashSet, VecDeque};
use std::hash::{BuildHasher, Hasher};

use bitcoin::{Txid, Wtxid};

/// Core's `INBOUND_INVENTORY_BROADCAST_INTERVAL`: the mean time between
/// flushes to inbound peers, in microseconds.
pub const INBOUND_INVENTORY_BROADCAST_INTERVAL: u64 = 5_000_000;

/// Core's `OUTBOUND_INVENTORY_BROADCAST_INTERVAL`, in microseconds.
pub const OUTBOUND_INVENTORY_BROADCAST_INTERVAL: u64 = 2_000_000;

/// Core's `INVENTORY_BROADCAST_TARGET`: 14 a second over the inbound
/// interval, the most announced in one flush of a short queue.
pub const INVENTORY_BROADCAST_TARGET: usize = 14 * 5;

/// Core's `INVENTORY_BROADCAST_MAX`: the most announced in one flush.
pub const INVENTORY_BROADCAST_MAX: usize = 1_000;

/// The capacity of Core's `m_tx_inventory_known_filter`.
pub const KNOWN_INVENTORY_CAPACITY: usize = 50_000;

/// How many of a queue of `queued` one flush announces: Core's
/// `broadcast_max`, five more for each thousand queued.
pub fn broadcast_max(queued: usize) -> usize {
    (INVENTORY_BROADCAST_TARGET + (queued / 1_000) * 5).min(INVENTORY_BROADCAST_MAX)
}

/// An exponentially distributed delay with mean `mean` microseconds: Core's
/// `FastRandomContext::rand_exp_duration`, which makes the flushes a
/// Poisson process.
pub fn exp_delay(mean: u64) -> u64 {
    // In (0, 1], so the logarithm is finite.
    let unit = 1.0 - rand::random::<f64>();
    (-unit.ln() * mean as f64) as u64
}

/// The hashes of transactions a peer is known to have: Core's
/// `m_tx_inventory_known_filter`, a rolling filter of 50,000 entries. Here a
/// bounded set of salted 64-bit hashes, oldest forgotten first, as
/// `recent_rejects` keeps its filters.
#[derive(Debug)]
struct KnownInventory {
    keys: HashSet<u64>,
    order: VecDeque<u64>,
    salt: std::collections::hash_map::RandomState,
}

impl Default for KnownInventory {
    fn default() -> Self {
        Self { keys: HashSet::new(), order: VecDeque::new(), salt: std::collections::hash_map::RandomState::new() }
    }
}

impl KnownInventory {
    fn key(&self, hash: &[u8; 32]) -> u64 {
        let mut h = self.salt.build_hasher();
        h.write(hash);
        h.finish()
    }

    fn insert(&mut self, hash: &[u8; 32]) {
        let key = self.key(hash);
        if !self.keys.insert(key) {
            return;
        }
        self.order.push_back(key);
        if self.order.len() > KNOWN_INVENTORY_CAPACITY
            && let Some(old) = self.order.pop_front()
        {
            self.keys.remove(&old);
        }
    }

    fn contains(&self, hash: &[u8; 32]) -> bool {
        self.keys.contains(&self.key(hash))
    }
}

/// One peer's announcement state: Core's `Peer::TxRelay`.
#[derive(Debug)]
pub struct TxRelay {
    /// Core's `m_tx_inventory_to_send`: queued for the next flush.
    to_send: HashSet<Wtxid>,
    /// Core's `m_tx_inventory_known_filter`, by wtxid for a peer that
    /// relays by wtxid and by txid for the rest.
    known: KnownInventory,
    /// Core's `m_next_inv_send_time`, on the node clock in microseconds.
    /// `None` until the version handshake completes: nothing is queued for
    /// a peer before then, so a transaction arriving during the handshake
    /// is not announced without delay.
    next_send: Option<u64>,
    /// Core's `m_last_inv_sequence`: the mempool sequence at the last flush.
    /// A transaction that entered the mempool before it may be fetched.
    last_inv_sequence: u64,
    /// Core's `m_send_mempool`: a BIP 35 `mempool` request to answer at the
    /// next flush.
    send_mempool: bool,
    /// What a flush that could not send everything it chose did announce,
    /// by the id announced. `last_inv_sequence` stays where it was then, so
    /// that what was not sent stays unservable; these may be fetched all
    /// the same, until the next complete flush moves the sequence past them.
    announced_out_of_sequence: HashSet<[u8; 32]>,
}

impl Default for TxRelay {
    fn default() -> Self {
        Self {
            to_send: HashSet::new(),
            known: KnownInventory::default(),
            next_send: None,
            // Core starts it at 1, the mempool's first sequence number.
            last_inv_sequence: 1,
            send_mempool: false,
            announced_out_of_sequence: HashSet::new(),
        }
    }
}

/// What one flush is to do for a peer, taken from its state.
#[derive(Debug, Default)]
pub struct Flush {
    /// Queued transactions to consider, all of the queue.
    pub queued: Vec<Wtxid>,
    /// Answer a BIP 35 `mempool` request with the whole mempool.
    pub mempool: bool,
}

impl TxRelay {
    /// Core's `AddKnownTx`: the peer has this transaction, by the id it
    /// relays by.
    pub fn add_known(&mut self, hash: &[u8; 32]) {
        self.known.insert(hash);
    }

    pub fn knows(&self, hash: &[u8; 32]) -> bool {
        self.known.contains(hash)
    }

    /// The handshake is done and the first flush has run: transactions may
    /// be queued.
    pub fn started(&self) -> bool {
        self.next_send.is_some()
    }

    /// Core's `RelayTransaction`, for this peer: queue `wtxid` unless the
    /// peer knows it by `hash`, its id the way the peer relays.
    pub fn queue(&mut self, wtxid: Wtxid, hash: &[u8; 32]) {
        if self.started() && !self.known.contains(hash) {
            self.to_send.insert(wtxid);
        }
    }

    /// `getpeerinfo`'s `inv_to_send`.
    pub fn inv_to_send(&self) -> usize {
        self.to_send.len()
    }

    /// `getpeerinfo`'s `last_inv_sequence`.
    pub fn last_inv_sequence(&self) -> u64 {
        self.last_inv_sequence
    }

    /// Core's `m_send_mempool = true`.
    pub fn request_mempool(&mut self) {
        self.send_mempool = true;
    }

    /// Core's `fSendTrickle`: whether the peer is flushed now. When its
    /// timer has passed (or it has never run), the next time is drawn with
    /// `next`. A `noban` peer is flushed every time, its timer kept all the
    /// same.
    pub fn due(&mut self, now: u64, noban: bool, next: impl FnOnce() -> u64) -> bool {
        if self.next_send.is_none_or(|t| t < now) {
            self.next_send = Some(next());
            return true;
        }
        noban
    }

    /// Start a flush: everything queued, and whether a `mempool` request
    /// waits. A peer that does not want transactions has its queue
    /// dropped.
    pub fn take(&mut self, relays_txs: bool) -> Flush {
        if !relays_txs {
            self.to_send.clear();
        }
        Flush {
            queued: self.to_send.drain().collect(),
            mempool: std::mem::take(&mut self.send_mempool),
        }
    }

    /// Finish a flush: what was not announced goes back in the queue, and
    /// the mempool sequence, if given, becomes the peer's
    /// `last_inv_sequence`. A flush that could not send everything it chose
    /// gives none.
    pub fn finish(&mut self, unsent: impl IntoIterator<Item = Wtxid>, mempool_sequence: Option<u64>) {
        self.to_send.extend(unsent);
        if let Some(sequence) = mempool_sequence {
            self.last_inv_sequence = sequence;
            self.announced_out_of_sequence.clear();
        }
    }

    /// Record an announcement made by a flush that will not move
    /// `last_inv_sequence`, so the peer may still fetch it.
    pub fn announced_out_of_sequence(&mut self, hash: &[u8; 32]) {
        self.announced_out_of_sequence.insert(*hash);
    }

    /// Whether the peer was announced `hash`, which entered the mempool at
    /// `entry_sequence`: before the peer's last flush, or by a flush that
    /// could not send everything it chose. Core's `info_for_relay` check.
    pub fn was_announced(&self, entry_sequence: u64, hash: &[u8; 32]) -> bool {
        entry_sequence < self.last_inv_sequence || self.announced_out_of_sequence.contains(hash)
    }

    /// Make the peer due at the next flush, as if its timer had passed.
    #[cfg(test)]
    pub fn make_due(&mut self) {
        if self.next_send.is_some() {
            self.next_send = Some(0);
        }
    }

    /// Drop `wtxid` from the queue: Core's BIP 35 answer erases each
    /// transaction it announces.
    pub fn unqueue(&mut self, wtxid: &Wtxid) {
        self.to_send.remove(wtxid);
    }
}

/// A queued transaction as the mempool holds it, for ordering a flush.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub wtxid: Wtxid,
    pub txid: Txid,
    /// In-mempool ancestors, itself included: Core's
    /// `GetCountWithAncestors`.
    pub ancestors: u64,
    /// The fee with any `prioritisetransaction` delta.
    pub modified_fee: i64,
    pub vsize: u64,
    /// sat/kvB, compared with the peer's `feefilter`.
    pub fee_rate: u64,
}

/// Core's `CompareInvMempoolOrder` (`CompareDepthAndScore`): fewer
/// ancestors first, then the higher modified feerate, then the lower txid.
pub fn announce_order(a: &Candidate, b: &Candidate) -> Ordering {
    a.ancestors.cmp(&b.ancestors).then_with(|| {
        let fa = i128::from(a.modified_fee) * i128::from(b.vsize);
        let fb = i128::from(b.modified_fee) * i128::from(a.vsize);
        fb.cmp(&fa).then_with(|| a.txid.cmp(&b.txid))
    })
}

#[cfg(test)]
#[path = "tx_relay_tests.rs"]
mod tests;
