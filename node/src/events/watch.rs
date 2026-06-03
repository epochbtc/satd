//! Live outpoint/script watch registry — the streaming-API differentiator.
//!
//! satd has a *query* spend index (`node_index::SpendIndex`) and a *push*
//! scripthash registry (Electrum / Esplora SSE), but no live **outpoint
//! subscription**. This module adds an outpoint-keyed and script-keyed
//! matcher: a client registers a watch-set, and the matcher emits a
//! [`WatchMatch`] the moment a watched outpoint is spent or a watched
//! script is paid, both in the mempool (unconfirmed) and as blocks connect
//! (confirmed).
//!
//! **Outpoint subscription is the base primitive.** Lightning channel-close
//! detection, watchtower triggers, exchange deposit confirmation, and theft
//! monitoring all reduce to it; address-watching is outpoint-watching with
//! a derivation rule on top (the descriptor layer, a later PR, expands a
//! descriptor into a script watch-set over this registry).
//!
//! ## Consensus safety
//!
//! This registry is **publish/read-only and fully decoupled from the
//! consensus hot path**. The matcher is driven by [`run_watch_matcher`],
//! a task that consumes the *existing* chain/mempool event broadcasts and
//! re-reads the just-connected block (or accepted tx) the node already
//! holds — it adds **no code to `accept_block` or `accept_transaction`**,
//! so it cannot block, lock, or backpressure block connection. Delivery to
//! a subscriber is non-blocking `try_send`: a slow client's channel fills
//! and matches are dropped-with-notice, never stalling the matcher.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use bitcoin::{Block, BlockHash, OutPoint, Transaction, Txid};
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, warn};

use node_index::keys::{scripthash_of, Scripthash};

use crate::chain::events::ChainEvent;
use crate::mempool::events::{EvictReason, MempoolEvent};
use crate::storage::undo::UndoData;

/// Default per-subscriber match-channel depth. A subscriber that falls
/// further behind than this loses matches (drop-with-notice) rather than
/// backpressuring the matcher.
pub const WATCH_CHANNEL_CAPACITY: usize = 1024;

/// A match against a registered watch-set, routed to the subscriber(s)
/// whose watch matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchMatch {
    /// A watched outpoint was spent.
    OutpointSpent {
        outpoint: OutPoint,
        spending_txid: Txid,
        spending_vin: u32,
        /// `true` once seen in a connected block; `false` while only in the
        /// mempool.
        confirmed: bool,
        /// Block height when `confirmed`; `None` in the mempool.
        height: Option<u32>,
    },
    /// A watched script was matched by a transaction.
    ///
    /// `is_output` distinguishes the two sides:
    /// - `true` — **funding**: an output pays the script (`index` = vout).
    ///   Detected in both the mempool and connected blocks.
    /// - `false` — **spending**: an input spends an output that paid the
    ///   script (`index` = vin). Detected for **connected blocks only**,
    ///   using the block's undo data to recover the spent prevout's
    ///   `scriptPubKey` (the spending tx does not carry it). Unconfirmed
    ///   spends are not matched on the script side; a client tracks those by
    ///   watching the funding outpoint (which `OutpointSpent` detects in the
    ///   mempool).
    ScriptMatched {
        scripthash: Scripthash,
        txid: Txid,
        is_output: bool,
        /// `vout` for a funding match (`is_output = true`); `vin` for a
        /// spending match (`is_output = false`).
        index: u32,
        confirmed: bool,
        height: Option<u32>,
    },
    /// A watched transaction id appeared — in the mempool (`confirmed =
    /// false`) or a connected block (`confirmed = true`). The "seen/confirmed"
    /// legs of the txid lifecycle, complementing the outpoint/script watches.
    TxidMatched {
        txid: Txid,
        confirmed: bool,
        /// Block height when `confirmed`; `None` in the mempool.
        height: Option<u32>,
    },
    /// Lifecycle: a watched tx was replaced in the mempool by a conflicting
    /// RBF candidate (`replacing_txid` is the incoming tx that evicted it).
    TxidReplaced { txid: Txid, replacing_txid: Txid },
    /// Lifecycle: a watched tx left the mempool by policy (full pool / expiry /
    /// block conflict) — not a confirmation and not an RBF replacement.
    TxidEvicted { txid: Txid, reason: EvictReason },
    /// Lifecycle: a watched tx's confirming block was rolled back by a reorg;
    /// it is back in flight. `prev_height` is the height it had been confirmed at.
    TxidUnconfirmed { txid: Txid, prev_height: u32 },
    /// A depth alarm fired: the watched tx reached the requested confirmation
    /// depth. Single-shot — the alarm self-evicts after this.
    TxidDepthReached { txid: Txid, depth: u32, height: u32 },
    /// A lifecycle watch's `auto_close_depth` was reached: terminal notice, the
    /// lifecycle watch has self-evicted (its quota unit is released).
    TxidFinalized { txid: Txid, depth: u32, height: u32 },
}

/// Opaque per-subscriber identifier.
type SubId = u64;

/// Distinguishes the two kinds of depth-tracked entry that share the per-block
/// tick: a single-shot client `Alarm` (`TxidDepthReached`) and a lifecycle
/// watch's auto-close trigger (`TxidFinalized`). Part of the depth key so an
/// alarm at depth N and an auto-close at depth N on the same `(sub, txid)`
/// never collide.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum DepthKind {
    Alarm,
    Close,
}

/// Key identifying one depth-tracked entry: subscriber, txid, threshold, kind.
type DepthKey = (SubId, Txid, u32, DepthKind);

struct Subscriber {
    sender: mpsc::Sender<WatchMatch>,
    outpoints: HashSet<OutPoint>,
    scripthashes: HashSet<Scripthash>,
    /// Lifecycle watches (one per txid).
    txids: HashSet<Txid>,
    /// Depth-tracked entries: single-shot alarms and lifecycle auto-close
    /// triggers, distinguished by [`DepthKind`].
    tx_depths: HashSet<(Txid, u32, DepthKind)>,
}

#[derive(Default)]
struct Inner {
    subs: HashMap<SubId, Subscriber>,
    /// Inverted index: watched outpoint → subscribers watching it. Gives
    /// O(1) matching per transaction input.
    by_outpoint: HashMap<OutPoint, HashSet<SubId>>,
    /// Inverted index: watched scripthash → subscribers watching it.
    by_scripthash: HashMap<Scripthash, HashSet<SubId>>,
    /// Inverted index: watched txid → subscribers watching it. O(1) per tx.
    by_txid: HashMap<Txid, HashSet<SubId>>,
    /// Inverted index: txid → depth-tracked entries keyed on it. Used to arm an
    /// entry when its txid first appears in a connected block.
    by_txid_depth: HashMap<Txid, HashSet<DepthKey>>,
    /// Confirm anchor per depth entry: `None` until the txid is observed in a
    /// connected block (or resolved via the txindex probe); `Some((height,
    /// hash))` once armed. The hash makes the per-block tick reorg-safe.
    depth_anchor: HashMap<DepthKey, Option<(u32, BlockHash)>>,
    /// Armed depth entries (anchor is `Some`) — the set the per-block tick walks.
    armed: HashSet<DepthKey>,
    /// Newly-added depth entries awaiting a one-shot txindex probe (for txs
    /// already confirmed before the watch was registered). Drained each tick.
    probe_queue: Vec<DepthKey>,
}

/// Registry of per-subscriber outpoint/script watch-sets with O(1)
/// matching. Cheap to consult when empty (a single atomic load).
pub struct WatchRegistry {
    inner: RwLock<Inner>,
    next_id: AtomicU64,
    /// Lock-free count of registered watch *items* (outpoints + scripts)
    /// across all subscribers. The matcher checks this before re-reading a
    /// block, so a node with no watchers does zero extra work.
    watch_items: AtomicUsize,
    /// Lock-free count of registered *script* items only. Gates the
    /// input-side script match: the matcher fetches a block's undo data (to
    /// recover spent prevout scriptPubKeys) only when some script is watched,
    /// so an outpoint-only watch-set pays nothing extra.
    script_items: AtomicUsize,
    /// Lock-free count of registered *txid* items only. Gates the per-tx txid
    /// lookup so a watch-set with no txids pays nothing for it.
    txid_items: AtomicUsize,
    /// Lock-free count of registered *depth* entries (alarms + auto-close).
    /// Gates the per-block arm/tick so a watch-set with no depth entries pays
    /// nothing for the confirmation tracking.
    depth_items: AtomicUsize,
}

impl Default for WatchRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchRegistry {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
            next_id: AtomicU64::new(1),
            watch_items: AtomicUsize::new(0),
            script_items: AtomicUsize::new(0),
            txid_items: AtomicUsize::new(0),
            depth_items: AtomicUsize::new(0),
        }
    }

    /// `true` if any subscriber is watching at least one outpoint or
    /// script. Lock-free; the matcher gate.
    pub fn has_watchers(&self) -> bool {
        self.watch_items.load(Ordering::Acquire) > 0
    }

    /// `true` if any subscriber is watching at least one script. Lock-free;
    /// gates the input-side undo-data fetch.
    pub fn has_script_watchers(&self) -> bool {
        self.script_items.load(Ordering::Acquire) > 0
    }

    /// `true` if any subscriber is watching at least one txid. Lock-free;
    /// gates the per-tx txid lookup.
    pub fn has_txid_watchers(&self) -> bool {
        self.txid_items.load(Ordering::Acquire) > 0
    }

    /// `true` if any subscriber has a depth-tracked entry (alarm or auto-close).
    /// Lock-free; gates the per-block depth arm/tick.
    pub fn has_depth_watchers(&self) -> bool {
        self.depth_items.load(Ordering::Acquire) > 0
    }

    fn lock_inner(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|p| p.into_inner())
    }

    fn read_inner(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Register a new subscriber. Returns a [`WatchHandle`] used to manage
    /// the watch-set (and which de-registers on drop) and the receiver the
    /// caller streams matches from.
    pub fn register(
        self: &Arc<Self>,
        capacity: usize,
    ) -> (WatchHandle, mpsc::Receiver<WatchMatch>) {
        let (tx, rx) = mpsc::channel(capacity);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.lock_inner().subs.insert(
            id,
            Subscriber {
                sender: tx,
                outpoints: HashSet::new(),
                scripthashes: HashSet::new(),
                txids: HashSet::new(),
                tx_depths: HashSet::new(),
            },
        );
        (
            WatchHandle {
                registry: self.clone(),
                id,
            },
            rx,
        )
    }

    /// Add outpoints to a subscriber's watch-set. Returns the number newly
    /// added (already-watched outpoints are not double-counted).
    fn add_outpoints(&self, id: SubId, outpoints: &[OutPoint]) -> usize {
        let mut inner = self.lock_inner();
        let mut added = 0;
        for op in outpoints {
            let Some(sub) = inner.subs.get_mut(&id) else {
                return added;
            };
            if sub.outpoints.insert(*op) {
                added += 1;
                inner.by_outpoint.entry(*op).or_default().insert(id);
            }
        }
        self.watch_items.fetch_add(added, Ordering::AcqRel);
        added
    }

    /// Add scripthashes to a subscriber's watch-set. Returns the number
    /// newly added.
    fn add_scripthashes(&self, id: SubId, scripthashes: &[Scripthash]) -> usize {
        let mut inner = self.lock_inner();
        let mut added = 0;
        for sh in scripthashes {
            let Some(sub) = inner.subs.get_mut(&id) else {
                return added;
            };
            if sub.scripthashes.insert(*sh) {
                added += 1;
                inner.by_scripthash.entry(*sh).or_default().insert(id);
            }
        }
        self.watch_items.fetch_add(added, Ordering::AcqRel);
        self.script_items.fetch_add(added, Ordering::AcqRel);
        added
    }

    /// Remove outpoints from a subscriber's watch-set. Returns the number
    /// removed.
    fn remove_outpoints(&self, id: SubId, outpoints: &[OutPoint]) -> usize {
        let mut inner = self.lock_inner();
        let mut removed = 0;
        for op in outpoints {
            let Some(sub) = inner.subs.get_mut(&id) else {
                break;
            };
            if sub.outpoints.remove(op) {
                removed += 1;
                if let Some(set) = inner.by_outpoint.get_mut(op) {
                    set.remove(&id);
                    if set.is_empty() {
                        inner.by_outpoint.remove(op);
                    }
                }
            }
        }
        self.watch_items.fetch_sub(removed, Ordering::AcqRel);
        removed
    }

    /// Remove scripthashes from a subscriber's watch-set. Returns the
    /// number removed.
    fn remove_scripthashes(&self, id: SubId, scripthashes: &[Scripthash]) -> usize {
        let mut inner = self.lock_inner();
        let mut removed = 0;
        for sh in scripthashes {
            let Some(sub) = inner.subs.get_mut(&id) else {
                break;
            };
            if sub.scripthashes.remove(sh) {
                removed += 1;
                if let Some(set) = inner.by_scripthash.get_mut(sh) {
                    set.remove(&id);
                    if set.is_empty() {
                        inner.by_scripthash.remove(sh);
                    }
                }
            }
        }
        self.watch_items.fetch_sub(removed, Ordering::AcqRel);
        self.script_items.fetch_sub(removed, Ordering::AcqRel);
        removed
    }

    /// Add txids as lifecycle watches. `auto_close_depth >= 1` also arms a
    /// `Close` depth entry that self-evicts the lifecycle watch (emitting
    /// `TxidFinalized`) once the tx is that many confirmations deep. Returns the
    /// number of lifecycle watches newly added.
    fn add_txids(&self, id: SubId, txids: &[Txid], auto_close_depth: u32) -> usize {
        let mut inner = self.lock_inner();
        let mut added = 0;
        let mut closes = 0;
        for t in txids {
            let is_new = match inner.subs.get_mut(&id) {
                Some(sub) => sub.txids.insert(*t),
                None => break,
            };
            if is_new {
                added += 1;
                inner.by_txid.entry(*t).or_default().insert(id);
                if auto_close_depth >= 1
                    && insert_depth_entry(&mut inner, id, *t, auto_close_depth, DepthKind::Close)
                {
                    closes += 1;
                }
            }
        }
        self.watch_items.fetch_add(added, Ordering::AcqRel);
        self.txid_items.fetch_add(added, Ordering::AcqRel);
        // Close entries gate the tick (depth_items) but are free of quota and do
        // NOT bump watch_items — the lifecycle txid already keeps the reread gate hot.
        self.depth_items.fetch_add(closes, Ordering::AcqRel);
        added
    }

    /// Remove lifecycle watches. Also removes any auto-close (`Close`) depth
    /// entry tied to each removed txid. Returns the number of watches removed.
    fn remove_txids(&self, id: SubId, txids: &[Txid]) -> usize {
        let mut inner = self.lock_inner();
        let mut removed = 0;
        let mut closes_removed = 0;
        for t in txids {
            let was = match inner.subs.get_mut(&id) {
                Some(sub) => sub.txids.remove(t),
                None => break,
            };
            if was {
                removed += 1;
                if let Some(set) = inner.by_txid.get_mut(t) {
                    set.remove(&id);
                    if set.is_empty() {
                        inner.by_txid.remove(t);
                    }
                }
                // Tear down any auto-close entry for this lifecycle watch.
                let closes: Vec<u32> = inner
                    .subs
                    .get(&id)
                    .map(|s| {
                        s.tx_depths
                            .iter()
                            .filter(|(tx, _, k)| tx == t && *k == DepthKind::Close)
                            .map(|(_, d, _)| *d)
                            .collect()
                    })
                    .unwrap_or_default();
                for d in closes {
                    if remove_depth_entry(&mut inner, id, *t, d, DepthKind::Close) {
                        closes_removed += 1;
                    }
                }
            }
        }
        self.watch_items.fetch_sub(removed, Ordering::AcqRel);
        self.txid_items.fetch_sub(removed, Ordering::AcqRel);
        self.depth_items.fetch_sub(closes_removed, Ordering::AcqRel);
        removed
    }

    /// Add single-shot depth alarms keyed `(txid, depth)`. Returns the number
    /// newly added (already-registered `(txid, depth)` pairs are not re-counted).
    fn add_tx_depths(&self, id: SubId, items: &[(Txid, u32)]) -> usize {
        let mut inner = self.lock_inner();
        let mut added = 0;
        for (t, d) in items {
            if insert_depth_entry(&mut inner, id, *t, *d, DepthKind::Alarm) {
                added += 1;
            }
        }
        // An alarm may have no lifecycle watch behind it, so it bumps watch_items
        // (reread gate) as well as depth_items (tick gate).
        self.watch_items.fetch_add(added, Ordering::AcqRel);
        self.depth_items.fetch_add(added, Ordering::AcqRel);
        added
    }

    /// Remove depth alarms keyed `(txid, depth)`. Returns the number removed.
    fn remove_tx_depths(&self, id: SubId, items: &[(Txid, u32)]) -> usize {
        let mut inner = self.lock_inner();
        let mut removed = 0;
        for (t, d) in items {
            if remove_depth_entry(&mut inner, id, *t, *d, DepthKind::Alarm) {
                removed += 1;
            }
        }
        self.watch_items.fetch_sub(removed, Ordering::AcqRel);
        self.depth_items.fetch_sub(removed, Ordering::AcqRel);
        removed
    }

    /// De-register a subscriber and all its watches (called on
    /// [`WatchHandle`] drop).
    fn deregister(&self, id: SubId) {
        let mut inner = self.lock_inner();
        let Some(sub) = inner.subs.remove(&id) else {
            return;
        };
        let freed_scripts = sub.scripthashes.len();
        let freed_txids = sub.txids.len();
        // Alarms bump watch_items; Close entries don't (their lifecycle txid does).
        let alarm_count = sub
            .tx_depths
            .iter()
            .filter(|(_, _, k)| *k == DepthKind::Alarm)
            .count();
        let depth_count = sub.tx_depths.len();
        let freed = sub.outpoints.len() + sub.scripthashes.len() + sub.txids.len() + alarm_count;
        for op in &sub.outpoints {
            if let Some(set) = inner.by_outpoint.get_mut(op) {
                set.remove(&id);
                if set.is_empty() {
                    inner.by_outpoint.remove(op);
                }
            }
        }
        for sh in &sub.scripthashes {
            if let Some(set) = inner.by_scripthash.get_mut(sh) {
                set.remove(&id);
                if set.is_empty() {
                    inner.by_scripthash.remove(sh);
                }
            }
        }
        for t in &sub.txids {
            if let Some(set) = inner.by_txid.get_mut(t) {
                set.remove(&id);
                if set.is_empty() {
                    inner.by_txid.remove(t);
                }
            }
        }
        for (txid, depth, kind) in &sub.tx_depths {
            let key: DepthKey = (id, *txid, *depth, *kind);
            if let Some(set) = inner.by_txid_depth.get_mut(txid) {
                set.remove(&key);
                if set.is_empty() {
                    inner.by_txid_depth.remove(txid);
                }
            }
            inner.depth_anchor.remove(&key);
            inner.armed.remove(&key);
            // Stale probe_queue entries (if any) no-op next tick — the tick's
            // probe drain skips keys whose depth_anchor is gone.
        }
        self.watch_items.fetch_sub(freed, Ordering::AcqRel);
        self.script_items.fetch_sub(freed_scripts, Ordering::AcqRel);
        self.txid_items.fetch_sub(freed_txids, Ordering::AcqRel);
        self.depth_items.fetch_sub(depth_count, Ordering::AcqRel);
    }

    /// Scan every transaction in a connected block, routing matches to
    /// subscribers (confirmed). Cheap early-out when no one is watching.
    ///
    /// `undo` is the block's undo data (spent coins, one per non-coinbase
    /// input in connect order). When present and some script is watched, it
    /// drives **input-side** script matching: a watched script is matched when
    /// an output paying it is *spent*, which the spending tx alone cannot
    /// reveal (it carries no prevout `scriptPubKey`). The caller passes `None`
    /// when no script is watched (or the undo is unavailable, e.g. pruned), in
    /// which case only outpoint-spend and output-side script matching run.
    pub fn scan_block(&self, block: &Block, height: u32, undo: Option<&UndoData>) {
        if !self.has_watchers() {
            return;
        }
        let inner = self.read_inner();
        for tx in &block.txdata {
            scan_tx(&inner, tx, true, Some(height));
        }
        // Input-side script matching: only meaningful with watched scripts and
        // the undo data to recover the spent prevout scriptPubKeys.
        if let Some(undo) = undo
            && !inner.by_scripthash.is_empty()
        {
            scan_block_spent_scripts(&inner, block, height, undo);
        }
    }

    /// Scan a single mempool transaction, routing matches to subscribers
    /// (unconfirmed). Cheap early-out when no one is watching.
    pub fn scan_mempool_tx(&self, tx: &Transaction) {
        if !self.has_watchers() {
            return;
        }
        let inner = self.read_inner();
        scan_tx(&inner, tx, false, None);
    }

    /// Arm depth entries whose txid appears in a freshly connected block,
    /// anchoring each on `(height, block_hash)`. Gated by `has_depth_watchers`.
    fn arm_depths_for_block(&self, block: &Block, height: u32) {
        if !self.has_depth_watchers() {
            return;
        }
        let bh = block.block_hash();
        let mut inner = self.lock_inner();
        if inner.by_txid_depth.is_empty() {
            return;
        }
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            let keys: Vec<DepthKey> = match inner.by_txid_depth.get(&txid) {
                Some(set) => set.iter().copied().collect(),
                None => continue,
            };
            for key in keys {
                inner.depth_anchor.insert(key, Some((height, bh)));
                inner.armed.insert(key);
            }
        }
    }

    /// Per-block tick: drain the one-shot txindex probe queue, then evaluate
    /// every armed depth entry against `tip`. Fires `TxidDepthReached` (alarm) or
    /// `TxidFinalized` (auto-close) at the threshold and de-arms; reverts an
    /// entry whose confirming block was reorged off the active chain. Reorg-safe
    /// via [`DepthChainView::active_chain_hash_at_height`].
    fn tick_depths(&self, tip: u32, chain: &dyn DepthChainView) {
        if !self.has_depth_watchers() {
            return;
        }
        let mut inner = self.lock_inner();

        // 1. Probe: arm entries whose tx confirmed BEFORE the watch was added
        //    (no live block to arm them). Best-effort — a disabled/incomplete
        //    txindex returns None and the entry waits for live observation.
        let probes = std::mem::take(&mut inner.probe_queue);
        for key in probes {
            let (_id, txid, _depth, _kind) = key;
            // Skip entries removed since they were queued, or already armed by a
            // live block that beat the probe.
            if !inner.depth_anchor.contains_key(&key) || inner.armed.contains(&key) {
                continue;
            }
            if let Some((h, bh)) = chain.tx_confirmation(&txid)
                && chain.active_chain_hash_at_height(h) == Some(bh)
            {
                inner.depth_anchor.insert(key, Some((h, bh)));
                inner.armed.insert(key);
            }
        }

        // 2. Evaluate armed entries against the tip.
        let armed: Vec<DepthKey> = inner.armed.iter().copied().collect();
        let mut fires: Vec<(SubId, WatchMatch, DepthKey)> = Vec::new();
        for key in armed {
            let (_id, _txid, depth, _kind) = key;
            let Some(Some((h, bh))) = inner.depth_anchor.get(&key).copied() else {
                inner.armed.remove(&key);
                continue;
            };
            // Reorg-safety: the confirming block must still be THE active-chain
            // block at its height. If not, revert to unarmed — it re-arms if the
            // tx reappears in a replacement block.
            if chain.active_chain_hash_at_height(h) != Some(bh) {
                inner.depth_anchor.insert(key, None);
                inner.armed.remove(&key);
                continue;
            }
            let cur_depth = tip.saturating_sub(h) + 1;
            if cur_depth >= depth {
                let (id, txid, depth, kind) = key;
                // Emit the REQUESTED threshold (`depth`), not the actual reached
                // depth: it is the alarm's identity (which alarm fired) and the
                // key the carrier uses to release the quota lease on eviction.
                // (cur_depth == depth in steady state; cur_depth > depth only on
                // a late arm — txindex probe of an already-buried tx, or a resync
                // window.) The client can recompute actual depth from `height`.
                let m = match kind {
                    DepthKind::Alarm => WatchMatch::TxidDepthReached {
                        txid,
                        depth,
                        height: h,
                    },
                    DepthKind::Close => WatchMatch::TxidFinalized {
                        txid,
                        depth,
                        height: h,
                    },
                };
                fires.push((id, m, key));
            }
        }

        // Server-authoritative eviction of fired single-shot entries. Doing the
        // teardown HERE (not waiting for the carrier to forward the terminal
        // match over the lossy match channel) guarantees: a fired key can never
        // re-arm if its txid reappears in a later block (no duplicate terminal),
        // and the registry's counters/gate are freed even if the terminal match
        // is dropped to a lagging client. The carrier still calls
        // remove_tx_depths/remove_txids on forwarding — now an idempotent no-op
        // registry-side, but it is what releases the carrier-held quota lease.
        // (Residual: a terminal match dropped to a full channel holds that lease
        // until disconnect — bounded by the connection and the per-token quota.)
        let mut depth_dec = 0usize;
        let mut watch_dec = 0usize;
        let mut txid_dec = 0usize;
        for (_id, _m, key) in &fires {
            let (id, txid, depth, kind) = *key;
            if remove_depth_entry(&mut inner, id, txid, depth, kind) {
                depth_dec += 1;
                if kind == DepthKind::Alarm {
                    watch_dec += 1;
                }
            }
            if kind == DepthKind::Close {
                // Auto-close is terminal for the lifecycle watch: remove it too
                // so it stops narrating once finalized.
                let removed = match inner.subs.get_mut(&id) {
                    Some(sub) => sub.txids.remove(&txid),
                    None => false,
                };
                if removed {
                    txid_dec += 1;
                    watch_dec += 1;
                    if let Some(set) = inner.by_txid.get_mut(&txid) {
                        set.remove(&id);
                        if set.is_empty() {
                            inner.by_txid.remove(&txid);
                        }
                    }
                }
            }
        }
        for (id, m, _key) in &fires {
            deliver(&inner, *id, m);
        }
        drop(inner);
        self.depth_items.fetch_sub(depth_dec, Ordering::AcqRel);
        self.watch_items.fetch_sub(watch_dec, Ordering::AcqRel);
        self.txid_items.fetch_sub(txid_dec, Ordering::AcqRel);
    }

    /// Deliver a lifecycle transition to every subscriber watching `txid`.
    fn notify_lifecycle(&self, txid: &Txid, m: WatchMatch) {
        if !self.has_txid_watchers() {
            return;
        }
        let inner = self.read_inner();
        if let Some(subs) = inner.by_txid.get(txid) {
            for sid in subs {
                deliver(&inner, *sid, &m);
            }
        }
    }

    /// Lifecycle: a watched tx was RBF-replaced in the mempool.
    fn notify_replaced(&self, txid: Txid, replacing_txid: Txid) {
        self.notify_lifecycle(&txid, WatchMatch::TxidReplaced { txid, replacing_txid });
    }

    /// Lifecycle: a watched tx was evicted from the mempool by policy.
    fn notify_evicted(&self, txid: Txid, reason: EvictReason) {
        self.notify_lifecycle(&txid, WatchMatch::TxidEvicted { txid, reason });
    }

    /// Scan a disconnected block: emit `TxidUnconfirmed` for watched txids in it
    /// (their confirming block was rolled back by a reorg). Best-effort — the
    /// caller skips this when the block data is unavailable (pruned).
    fn scan_block_disconnected(&self, block: &Block, height: u32) {
        if !self.has_txid_watchers() {
            return;
        }
        let inner = self.read_inner();
        if inner.by_txid.is_empty() {
            return;
        }
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            if let Some(subs) = inner.by_txid.get(&txid) {
                let m = WatchMatch::TxidUnconfirmed {
                    txid,
                    prev_height: height,
                };
                for sid in subs {
                    deliver(&inner, *sid, &m);
                }
            }
        }
    }
}

/// Minimal chain view the depth tick needs. Decouples the per-block tick from
/// the full `ChainState` so it is unit-testable with a mock, mirroring the A4
/// `BlockCursorSource` pattern. Implemented for [`crate::chain::state::ChainState`].
pub trait DepthChainView {
    /// Active-chain block hash at `height` (reorg-safe; walks from the tip).
    fn active_chain_hash_at_height(&self, height: u32) -> Option<BlockHash>;
    /// Confirming `(height, block_hash)` for a txid via the txindex, or `None`
    /// when txindex is disabled / the tx is unknown.
    fn tx_confirmation(&self, txid: &Txid) -> Option<(u32, BlockHash)>;
}

impl DepthChainView for crate::chain::state::ChainState {
    fn active_chain_hash_at_height(&self, height: u32) -> Option<BlockHash> {
        crate::chain::state::ChainState::active_chain_hash_at_height(self, height)
    }
    fn tx_confirmation(&self, txid: &Txid) -> Option<(u32, BlockHash)> {
        let bh = self.get_tx_location(txid)?;
        let entry = self.get_block_index(&bh)?;
        Some((entry.height, bh))
    }
}

/// Insert a depth-tracked entry (unarmed) into the indexes and queue a one-shot
/// txindex probe. Returns false if the subscriber already held this exact entry.
fn insert_depth_entry(
    inner: &mut Inner,
    id: SubId,
    txid: Txid,
    depth: u32,
    kind: DepthKind,
) -> bool {
    let inserted = match inner.subs.get_mut(&id) {
        Some(sub) => sub.tx_depths.insert((txid, depth, kind)),
        None => return false,
    };
    if !inserted {
        return false;
    }
    let key: DepthKey = (id, txid, depth, kind);
    inner.by_txid_depth.entry(txid).or_default().insert(key);
    inner.depth_anchor.insert(key, None);
    inner.probe_queue.push(key);
    true
}

/// Remove a depth-tracked entry from all indexes. Returns false if it was not
/// registered.
fn remove_depth_entry(
    inner: &mut Inner,
    id: SubId,
    txid: Txid,
    depth: u32,
    kind: DepthKind,
) -> bool {
    let removed = match inner.subs.get_mut(&id) {
        Some(sub) => sub.tx_depths.remove(&(txid, depth, kind)),
        None => return false,
    };
    if !removed {
        return false;
    }
    let key: DepthKey = (id, txid, depth, kind);
    if let Some(set) = inner.by_txid_depth.get_mut(&txid) {
        set.remove(&key);
        if set.is_empty() {
            inner.by_txid_depth.remove(&txid);
        }
    }
    inner.depth_anchor.remove(&key);
    inner.armed.remove(&key);
    true
}

/// Match a single transaction against the watch-set and deliver to the
/// matching subscribers. Pure given `inner`; the hot loop the matcher runs.
fn scan_tx(inner: &Inner, tx: &Transaction, confirmed: bool, height: Option<u32>) {
    let txid = tx.compute_txid();

    // Inputs → watched-outpoint spends.
    for (vin, input) in tx.input.iter().enumerate() {
        if let Some(subs) = inner.by_outpoint.get(&input.previous_output) {
            let m = WatchMatch::OutpointSpent {
                outpoint: input.previous_output,
                spending_txid: txid,
                spending_vin: vin as u32,
                confirmed,
                height,
            };
            for sid in subs {
                deliver(inner, *sid, &m);
            }
        }
    }

    // Outputs → watched-script funding.
    if !inner.by_scripthash.is_empty() {
        for (vout, out) in tx.output.iter().enumerate() {
            let sh = scripthash_of(&out.script_pubkey);
            if let Some(subs) = inner.by_scripthash.get(&sh) {
                let m = WatchMatch::ScriptMatched {
                    scripthash: sh,
                    txid,
                    is_output: true,
                    index: vout as u32,
                    confirmed,
                    height,
                };
                for sid in subs {
                    deliver(inner, *sid, &m);
                }
            }
        }
    }

    // Txid → watched-transaction appearance (mempool or block).
    if !inner.by_txid.is_empty()
        && let Some(subs) = inner.by_txid.get(&txid)
    {
        let m = WatchMatch::TxidMatched {
            txid,
            confirmed,
            height,
        };
        for sid in subs {
            deliver(inner, *sid, &m);
        }
    }
}

/// Input-side script matching for a connected block: emit a `ScriptMatched`
/// (`is_output = false`) when a watched script's output is *spent*.
///
/// The spending transaction carries no prevout `scriptPubKey`, so the spent
/// scripts come from the block's undo data. `undo.spent_coins` holds one
/// `Coin` per non-coinbase input in connect order — exactly the order this
/// walk produces (`block.txdata`, skipping `is_coinbase()`, then `tx.input`),
/// so the running `undo_idx` stays aligned with `tx.input[vin]`. This is the
/// one piece of spend-detection the funding-side/outpoint primitives cannot
/// give for a script whose funding the matcher never observed (e.g. a UTXO
/// that predates the watch).
fn scan_block_spent_scripts(inner: &Inner, block: &Block, height: u32, undo: &UndoData) {
    let mut undo_idx = 0usize;
    for tx in &block.txdata {
        if tx.is_coinbase() {
            continue; // coinbase has no spent prevouts in undo
        }
        let txid = tx.compute_txid();
        for (vin, _input) in tx.input.iter().enumerate() {
            let Some(spent) = undo.spent_coins.get(undo_idx) else {
                // Undo shorter than the block's non-coinbase inputs: should
                // never happen given the connect-order invariant (the consensus
                // disconnect path validates the exact length). Stop rather than
                // mis-align the remaining indices — this can only cause MISSED
                // (never false) input-side matches. Log it: a short undo means
                // a corrupt undo row or a broken invariant worth investigating.
                warn!(
                    target: "events::watch",
                    height,
                    have = undo.spent_coins.len(),
                    "resync/scan: undo shorter than non-coinbase inputs; \
                     input-side script matches truncated for this block"
                );
                return;
            };
            undo_idx += 1;
            let sh = scripthash_of(&spent.script_pubkey);
            if let Some(subs) = inner.by_scripthash.get(&sh) {
                let m = WatchMatch::ScriptMatched {
                    scripthash: sh,
                    txid,
                    is_output: false,
                    index: vin as u32,
                    confirmed: true,
                    height: Some(height),
                };
                for sid in subs {
                    deliver(inner, *sid, &m);
                }
            }
        }
    }
}

/// Non-blocking delivery to one subscriber. A full channel means the client
/// is too slow: drop-with-notice (warn), never block the matcher.
fn deliver(inner: &Inner, id: SubId, m: &WatchMatch) {
    if let Some(sub) = inner.subs.get(&id) {
        match sub.sender.try_send(m.clone()) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(target: "events::watch", sub = id, "watch subscriber lagged; dropping match");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Receiver gone; the WatchHandle drop will de-register it.
            }
        }
    }
}

/// RAII handle to a subscriber's watch-set. De-registers the subscriber
/// (and all its watches) on drop — disconnect reconciliation.
pub struct WatchHandle {
    registry: Arc<WatchRegistry>,
    id: SubId,
}

impl WatchHandle {
    /// Add outpoints to this subscriber's watch-set; returns the count
    /// newly added.
    pub fn add_outpoints(&self, outpoints: &[OutPoint]) -> usize {
        self.registry.add_outpoints(self.id, outpoints)
    }

    /// Add scripthashes to this subscriber's watch-set; returns the count
    /// newly added.
    pub fn add_scripthashes(&self, scripthashes: &[Scripthash]) -> usize {
        self.registry.add_scripthashes(self.id, scripthashes)
    }

    /// Remove outpoints; returns the count removed.
    pub fn remove_outpoints(&self, outpoints: &[OutPoint]) -> usize {
        self.registry.remove_outpoints(self.id, outpoints)
    }

    /// Remove scripthashes; returns the count removed.
    pub fn remove_scripthashes(&self, scripthashes: &[Scripthash]) -> usize {
        self.registry.remove_scripthashes(self.id, scripthashes)
    }

    /// Add lifecycle watches for `txids`. `auto_close_depth >= 1` self-evicts each
    /// (emitting `TxidFinalized`) once that deep. Returns the count newly added.
    pub fn add_txids(&self, txids: &[Txid], auto_close_depth: u32) -> usize {
        self.registry.add_txids(self.id, txids, auto_close_depth)
    }

    /// Remove lifecycle watches (and any auto-close entry); returns the count removed.
    pub fn remove_txids(&self, txids: &[Txid]) -> usize {
        self.registry.remove_txids(self.id, txids)
    }

    /// Add single-shot depth alarms keyed `(txid, depth)`; returns the count newly added.
    pub fn add_tx_depths(&self, items: &[(Txid, u32)]) -> usize {
        self.registry.add_tx_depths(self.id, items)
    }

    /// Remove depth alarms keyed `(txid, depth)`; returns the count removed.
    pub fn remove_tx_depths(&self, items: &[(Txid, u32)]) -> usize {
        self.registry.remove_tx_depths(self.id, items)
    }
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        self.registry.deregister(self.id);
    }
}

/// Compute the height range the matcher must rescan after lagging the chain
/// event broadcast **when its frontier block is still on the active chain**,
/// capping the span to `max` blocks.
///
/// This is the forward-only case: the lower bound is anchored just above
/// `last_scanned`. It is correct even if a reorg occurred *above* the frontier
/// while we lagged — [`ChainState::get_block_hash_by_height`] returns
/// active-chain hashes, so rescanning `last_scanned+1..=tip` naturally picks up
/// the post-reorg blocks. It is NOT correct if the reorg reached down to or
/// below `last_scanned` (that height's block may have been replaced); the
/// caller detects that via a frontier-hash check and uses
/// [`reorg_resync_range`] instead.
///
/// Returns `Some((from, to, skipped))` — an inclusive `from..=to` range to
/// rescan plus the number of older blocks the cap dropped (always logged,
/// never silent) — or `None` when there is nothing to rescan (the matcher is
/// already at or beyond the tip).
///
/// `max == 0` disables the cap (rescan the whole gap).
fn resync_range(last_scanned: u32, tip: u32, max: u32) -> Option<(u32, u32, u32)> {
    if tip <= last_scanned {
        return None;
    }
    let from = last_scanned + 1;
    let span = tip - from + 1;
    if max != 0 && span > max {
        // Keep the most recent `max` blocks; the client can backfill the
        // older tail via Subscribe(from_cursor).
        Some((tip - max + 1, tip, span - max))
    } else {
        Some((from, tip, 0))
    }
}

/// Compute the rescan range after a lag during which the matcher's frontier
/// block was reorged off the active chain.
///
/// Unlike [`resync_range`], the lower bound is **not** anchored to
/// `last_scanned`: that height's block may have been replaced, and the lag may
/// have dropped the very `BlockConnected` events for the replacement blocks, so
/// anchoring above the old frontier would permanently miss matches in the
/// replacements (heights `<= last_scanned`). Instead we rescan the most recent
/// `max` blocks ending at `tip`, re-covering reorg-replacement blocks at or
/// below the old frontier. Unchanged blocks in that window are re-scanned and
/// may re-emit matches — clients dedup confirmed matches by (item, height), and
/// a reorg-during-lag is rare — so the bounded duplication is an acceptable
/// cost of never silently dropping a replacement match.
///
/// `max == 0` rescans from genesis. Returns `Some((from, to, skipped))` with
/// the same shape as [`resync_range`].
fn reorg_resync_range(tip: u32, max: u32) -> Option<(u32, u32, u32)> {
    // `from = tip - max + 1`, floored at genesis; `(tip + 1) - max` avoids
    // underflow. `max == 0` (cap disabled) rescans from genesis.
    let from = if max == 0 {
        0
    } else {
        (tip + 1).saturating_sub(max)
    };
    // Heights `0..from` are below the kept window and not rescanned.
    Some((from, tip, from))
}

/// Fetch a block's undo data for input-side script matching — but only when
/// some script is watched, so an outpoint-only watch-set never pays even the
/// (cached) undo read. Returns `None` when no script is watched or the undo is
/// unavailable (e.g. pruned), in which case `scan_block` does funding/outpoint
/// matching only.
fn block_undo_for_scan(
    registry: &WatchRegistry,
    chain: &crate::chain::state::ChainState,
    hash: &bitcoin::BlockHash,
) -> Option<UndoData> {
    if registry.has_script_watchers() {
        chain.get_undo(hash)
    } else {
        None
    }
}

/// Drive the watch matcher off the existing event broadcasts. Decoupled
/// from consensus: on `BlockConnected` it re-reads the (already durable)
/// block and scans it; on a mempool `Enter` it fetches the accepted tx and
/// scans it. Both are gated by [`WatchRegistry::has_watchers`], so a node
/// with no active watches does zero extra work (no block re-read).
///
/// If the chain-event broadcast lags (a slow matcher under a burst of
/// blocks), the dropped blocks would otherwise be silently un-scanned and
/// every watcher would miss matches in that window. On a lag the matcher
/// rescans the missed blocks the node already holds, capped by
/// `max_resync_blocks`, without ever backpressuring the publisher. It tracks
/// its frontier block *hash* (not just height) so it can tell whether a reorg
/// reached at or below that frontier while it was lagged: if the frontier is
/// intact, a forward rescan from there is exact (see [`resync_range`]); if the
/// frontier block was reorged off the active chain, the lag may have dropped
/// the replacement blocks' `BlockConnected` events too, so it rescans the cap
/// window ending at the tip (see [`reorg_resync_range`]) to re-cover them.
///
/// Runs until `shutdown` flips or both broadcasts close. Intended to be
/// spawned on the API runtime, alongside the other event sinks.
pub async fn run_watch_matcher(
    registry: Arc<WatchRegistry>,
    chain: Arc<crate::chain::state::ChainState>,
    mempool: Arc<crate::mempool::pool::Mempool>,
    mut chain_rx: broadcast::Receiver<ChainEvent>,
    mut mempool_rx: broadcast::Receiver<MempoolEvent>,
    max_resync_blocks: u32,
    mut shutdown: watch::Receiver<bool>,
) {
    debug!(target: "events::watch", "watch matcher started");
    // Frontier of what the matcher has scanned: the height AND hash of the last
    // block it scanned. Initialized to the current tip — history before the
    // matcher starts is the client's replay concern (Subscribe(from_cursor)),
    // not the live matcher's. The hash lets a lag handler detect whether a reorg
    // replaced the frontier block (then forward-rescanning from `height` would
    // miss the replacement blocks at or below it). Captured atomically via
    // `tip_snapshot` so height and hash agree.
    let (tip_hash, tip_height) = chain.tip_snapshot();
    let mut last_scanned_height = tip_height;
    let mut last_scanned_hash: Option<BlockHash> = Some(tip_hash);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            res = chain_rx.recv() => match res {
                Ok(ChainEvent::BlockConnected { hash, height }) => {
                    if registry.has_watchers()
                        && let Some(block) = chain.get_block(&hash)
                    {
                        let undo = block_undo_for_scan(&registry, &chain, &hash);
                        registry.scan_block(&block, height, undo.as_ref());
                        // Arm depth entries whose txid is in this block.
                        registry.arm_depths_for_block(&block, height);
                    }
                    // Tick depth entries against the new tip (fires alarms /
                    // auto-close, reverts reorged-out anchors, drains the probe
                    // queue). Cheap no-op when no depth entries exist.
                    registry.tick_depths(height, chain.as_ref());
                    last_scanned_height = height;
                    last_scanned_hash = Some(hash);
                }
                // A disconnected block rolls back its txs' confirmations: emit
                // TxidUnconfirmed for watched txids in it (best-effort — skipped
                // if the block data is pruned). The depth tick reverts any armed
                // anchor on the next connect via its active-chain check. The
                // Reorg marker itself is a first-class firehose event; the
                // matcher takes no action on it directly.
                Ok(ChainEvent::BlockDisconnected { hash, height }) => {
                    if registry.has_txid_watchers()
                        && let Some(block) = chain.get_block(&hash)
                    {
                        registry.scan_block_disconnected(&block, height);
                    }
                }
                Ok(ChainEvent::Reorg { .. }) => {}
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Rescan the missed window so watchers do not silently miss
                    // matches. Reading blocks the node already holds; never
                    // blocks the publisher.
                    //
                    // Snapshot the active-chain tip ONCE and derive everything
                    // below from it, so the rescan is internally consistent even
                    // if the tip advances meanwhile.
                    let (tip_hash, tip) = chain.tip_snapshot();
                    // Is the block we last scanned still on the ACTIVE chain at
                    // its recorded height? Use the authoritative active-chain
                    // lookup: `get_block_hash_by_height` reads the `height_hash`
                    // index ("best known at height"), which side-chain
                    // `store_block`/header-first writes can clobber — so it could
                    // both spuriously report a reorg AND point the rescan at a
                    // side-chain block (a false `confirmed` match). If the
                    // frontier is intact the reorg (if any) was ABOVE it and a
                    // forward rescan is exact; if not, the reorg reached at/below
                    // the frontier and the lag may have dropped the replacements'
                    // BlockConnected events, so we rescan the cap window ending at
                    // the tip rather than only heights above the (stale) frontier.
                    let frontier_intact = match last_scanned_hash {
                        Some(h) => {
                            chain.active_chain_hash_at_height(last_scanned_height) == Some(h)
                        }
                        None => false,
                    };
                    let range = if frontier_intact {
                        resync_range(last_scanned_height, tip, max_resync_blocks)
                    } else {
                        reorg_resync_range(tip, max_resync_blocks)
                    };
                    if let Some((from, to, skipped)) = range {
                        warn!(
                            target: "events::watch",
                            dropped = n, from, to, skipped, reorg = !frontier_intact,
                            "watch matcher lagged on chain events; resyncing to tip"
                        );
                        if skipped > 0 {
                            warn!(
                                target: "events::watch",
                                skipped, cap = max_resync_blocks,
                                "resync span exceeds streammaxresyncblocks; older blocks not \
                                 rescanned (clients can backfill via Subscribe(from_cursor))"
                            );
                        }
                        if registry.has_watchers() {
                            // Resolve the ACTIVE-chain hash for every height in
                            // `from..=to` (== tip) by walking back from the tip
                            // ONCE via prev_blockhash: per-height
                            // `active_chain_hash_at_height` would be O(span^2), and
                            // `get_block_hash_by_height` could yield side-chain
                            // blocks. Collect descending, then scan ascending so
                            // matches are delivered in block order like the live
                            // path.
                            let mut active: Vec<(u32, BlockHash)> = Vec::new();
                            let mut cur = tip_hash;
                            let mut h = to;
                            loop {
                                active.push((h, cur));
                                if h == from {
                                    break;
                                }
                                match chain.get_block_index(&cur) {
                                    Some(entry) => {
                                        cur = entry.header.prev_blockhash;
                                        h -= 1;
                                    }
                                    // An index gap below the tip should not happen
                                    // for the active chain (block-index entries
                                    // are never pruned, only block data). Log it
                                    // rather than silently dropping the lower part
                                    // of the window, and stop rather than
                                    // fabricate heights.
                                    None => {
                                        warn!(
                                            target: "events::watch",
                                            height = h, hash = %cur, from,
                                            "resync: active-chain block index gap; \
                                             lower window not rescanned"
                                        );
                                        break;
                                    }
                                }
                            }
                            for (i, (h, hash)) in active.iter().rev().enumerate() {
                                // Honor shutdown promptly and yield periodically so a
                                // large catch-up (up to max_resync_blocks, or unbounded
                                // when the cap is disabled) cannot monopolize the API
                                // runtime worker or stall graceful shutdown. Each read
                                // is still non-blocking w.r.t. the consensus publisher.
                                if *shutdown.borrow() {
                                    break;
                                }
                                if i % 64 == 63 {
                                    tokio::task::yield_now().await;
                                }
                                match chain.get_block(hash) {
                                    Some(block) => {
                                        let undo = block_undo_for_scan(&registry, &chain, hash);
                                        registry.scan_block(&block, *h, undo.as_ref());
                                        registry.arm_depths_for_block(&block, *h);
                                    }
                                    None => debug!(
                                        target: "events::watch",
                                        height = *h,
                                        "resync: block data unavailable (pruned?); skipping"
                                    ),
                                }
                            }
                            // Fire any depth entries that became deep enough across
                            // the rescanned window.
                            registry.tick_depths(tip, chain.as_ref());
                        }
                        last_scanned_height = tip;
                        last_scanned_hash = Some(tip_hash);
                    } else {
                        warn!(
                            target: "events::watch",
                            dropped = n,
                            "watch matcher lagged on chain events; already at tip, nothing to resync"
                        );
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            res = mempool_rx.recv() => match res {
                Ok(MempoolEvent::Enter { txid, .. }) => {
                    if registry.has_watchers()
                        && let Some(entry) = mempool.get(&txid)
                    {
                        registry.scan_mempool_tx(&entry.tx);
                    }
                }
                // Lifecycle: RBF replacement and policy eviction route to any
                // lifecycle watcher of the affected txid. Confirmation
                // (LeaveConfirmed) is intentionally NOT handled here — the
                // confirmed leg is sourced from scan_block, which also catches
                // txs that were never in this node's mempool.
                Ok(MempoolEvent::LeaveReplaced { txid, replacing_txid }) => {
                    registry.notify_replaced(txid, replacing_txid);
                }
                Ok(MempoolEvent::LeaveEvicted { txid, reason }) => {
                    registry.notify_evicted(txid, reason);
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(target: "events::watch", dropped = n, "watch matcher lagged on mempool events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
        }
    }
    debug!(target: "events::watch", "watch matcher stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn outpoint(byte: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32])),
            vout,
        }
    }

    fn spending_tx(spends: OutPoint) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spends,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![],
        }
    }

    fn funding_tx(spk: ScriptBuf) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: spk,
            }],
        }
    }

    #[test]
    fn matches_watched_outpoint_spend() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let op = outpoint(0xaa, 3);
        assert_eq!(handle.add_outpoints(&[op]), 1);
        assert!(reg.has_watchers());

        reg.scan_mempool_tx(&spending_tx(op));
        match rx.try_recv().expect("a match was delivered") {
            WatchMatch::OutpointSpent {
                outpoint,
                spending_vin,
                confirmed,
                height,
                ..
            } => {
                assert_eq!(outpoint, op);
                assert_eq!(spending_vin, 0);
                assert!(!confirmed);
                assert_eq!(height, None);
            }
            other => panic!("wrong match: {other:?}"),
        }
    }

    #[test]
    fn matches_watched_script_funding_confirmed() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spk = ScriptBuf::from(vec![0x51]); // OP_TRUE, arbitrary
        let sh = scripthash_of(&spk);
        assert_eq!(handle.add_scripthashes(&[sh]), 1);

        // Wrap in a block at height 7 → confirmed match.
        let block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::TWO,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![funding_tx(spk)],
        };
        reg.scan_block(&block, 7, None);
        match rx.try_recv().expect("a match was delivered") {
            WatchMatch::ScriptMatched {
                scripthash,
                is_output,
                index,
                confirmed,
                height,
                ..
            } => {
                assert_eq!(scripthash, sh);
                assert!(is_output);
                assert_eq!(index, 0);
                assert!(confirmed);
                assert_eq!(height, Some(7));
            }
            other => panic!("wrong match: {other:?}"),
        }
    }

    #[test]
    fn no_match_for_unwatched_outpoint() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        handle.add_outpoints(&[outpoint(0x01, 0)]);
        reg.scan_mempool_tx(&spending_tx(outpoint(0x02, 0)));
        assert!(rx.try_recv().is_err(), "unwatched spend must not match");
    }

    #[test]
    fn matches_watched_txid_mempool_then_confirmed() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let tx = funding_tx(ScriptBuf::from(vec![0x51]));
        let txid = tx.compute_txid();
        assert_eq!(handle.add_txids(&[txid], 0), 1);
        assert!(reg.has_watchers());
        assert!(reg.has_txid_watchers());

        // Mempool sighting → unconfirmed match.
        reg.scan_mempool_tx(&tx);
        match rx.try_recv().expect("mempool match") {
            WatchMatch::TxidMatched {
                txid: t,
                confirmed,
                height,
            } => {
                assert_eq!(t, txid);
                assert!(!confirmed);
                assert_eq!(height, None);
            }
            other => panic!("wrong match: {other:?}"),
        }

        // Then in a block at height 9 → confirmed match.
        reg.scan_block(&block_with(vec![tx]), 9, None);
        match rx.try_recv().expect("confirmed match") {
            WatchMatch::TxidMatched {
                confirmed, height, ..
            } => {
                assert!(confirmed);
                assert_eq!(height, Some(9));
            }
            other => panic!("wrong match: {other:?}"),
        }

        // Remove → no longer a watcher, no further match.
        assert_eq!(handle.remove_txids(&[txid]), 1);
        assert!(!reg.has_txid_watchers());
        reg.scan_mempool_tx(&funding_tx(ScriptBuf::from(vec![0x51])));
        assert!(rx.try_recv().is_err(), "removed txid must not match");
    }

    #[test]
    fn unwatched_txid_does_not_match() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let watched = funding_tx(ScriptBuf::from(vec![0x51])).compute_txid();
        handle.add_txids(&[watched], 0);
        // A different transaction (distinct script → distinct txid).
        reg.scan_mempool_tx(&funding_tx(ScriptBuf::from(vec![0x52])));
        assert!(rx.try_recv().is_err(), "unwatched txid must not match");
    }

    // --- lifecycle transitions + depth alarms / auto-close (PR6) ---

    /// A block with a distinct `nonce` so its `block_hash()` is unique (the
    /// other test helpers hard-code an all-zeros header → identical hashes).
    fn block_at(nonce: u32, txs: Vec<Transaction>) -> Block {
        Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::TWO,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0),
                nonce,
            },
            txdata: txs,
        }
    }

    /// In-memory [`DepthChainView`]: an active-chain `height → hash` map and a
    /// txindex `txid → (height, hash)` map, both set by the test.
    #[derive(Default)]
    struct MockChain {
        active: HashMap<u32, BlockHash>,
        txloc: HashMap<Txid, (u32, BlockHash)>,
    }
    impl DepthChainView for MockChain {
        fn active_chain_hash_at_height(&self, height: u32) -> Option<BlockHash> {
            self.active.get(&height).copied()
        }
        fn tx_confirmation(&self, txid: &Txid) -> Option<(u32, BlockHash)> {
            self.txloc.get(txid).copied()
        }
    }

    fn tx_with(spk: u8) -> Transaction {
        funding_tx(ScriptBuf::from(vec![spk]))
    }

    #[test]
    fn lifecycle_replaced_fires() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let txid = tx_with(0x51).compute_txid();
        let replacing = tx_with(0x52).compute_txid();
        handle.add_txids(&[txid], 0);
        reg.notify_replaced(txid, replacing);
        match rx.try_recv().expect("replaced fires") {
            WatchMatch::TxidReplaced {
                txid: t,
                replacing_txid,
            } => {
                assert_eq!(t, txid);
                assert_eq!(replacing_txid, replacing);
            }
            other => panic!("wrong match: {other:?}"),
        }
        // Unwatched txid → no fire.
        reg.notify_replaced(tx_with(0x99).compute_txid(), replacing);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn lifecycle_evicted_fires_with_reason() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let txid = tx_with(0x51).compute_txid();
        handle.add_txids(&[txid], 0);
        reg.notify_evicted(txid, EvictReason::BlockConflict);
        match rx.try_recv().expect("evicted fires") {
            WatchMatch::TxidEvicted { txid: t, reason } => {
                assert_eq!(t, txid);
                assert_eq!(reason, EvictReason::BlockConflict);
            }
            other => panic!("wrong match: {other:?}"),
        }
    }

    #[test]
    fn lifecycle_unconfirmed_on_disconnect() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let tx = tx_with(0x51);
        let txid = tx.compute_txid();
        handle.add_txids(&[txid], 0);
        reg.scan_block_disconnected(&block_at(1, vec![tx]), 10);
        match rx.try_recv().expect("unconfirmed fires") {
            WatchMatch::TxidUnconfirmed { txid: t, prev_height } => {
                assert_eq!(t, txid);
                assert_eq!(prev_height, 10);
            }
            other => panic!("wrong match: {other:?}"),
        }
    }

    #[test]
    fn depth_fires_at_threshold_not_before() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let tx = tx_with(0x51);
        let txid = tx.compute_txid();
        assert_eq!(handle.add_tx_depths(&[(txid, 3)]), 1);
        assert!(reg.has_depth_watchers());

        let block = block_at(1, vec![tx]);
        let mut chain = MockChain::default();
        chain.active.insert(10, block.block_hash());

        reg.arm_depths_for_block(&block, 10);
        reg.tick_depths(10, &chain); // depth 1
        assert!(rx.try_recv().is_err(), "depth 1 < 3");
        reg.tick_depths(11, &chain); // depth 2
        assert!(rx.try_recv().is_err(), "depth 2 < 3");
        reg.tick_depths(12, &chain); // depth 3
        match rx.try_recv().expect("alarm fires at depth 3") {
            WatchMatch::TxidDepthReached {
                txid: t,
                depth,
                height,
            } => {
                assert_eq!(t, txid);
                assert_eq!(depth, 3, "reports requested threshold");
                assert_eq!(height, 10);
            }
            other => panic!("wrong match: {other:?}"),
        }
        // Single-shot: no re-fire as it buries deeper.
        reg.tick_depths(13, &chain);
        assert!(rx.try_recv().is_err(), "single-shot, no re-fire");
    }

    #[test]
    fn two_depths_one_txid_fire_independently() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let tx = tx_with(0x51);
        let txid = tx.compute_txid();
        assert_eq!(handle.add_tx_depths(&[(txid, 1), (txid, 3)]), 2);

        let block = block_at(1, vec![tx]);
        let mut chain = MockChain::default();
        chain.active.insert(10, block.block_hash());
        reg.arm_depths_for_block(&block, 10);

        reg.tick_depths(10, &chain); // depth 1 → (X,1) fires, (X,3) waits
        match rx.try_recv().expect("(X,1) fires") {
            WatchMatch::TxidDepthReached { depth, .. } => assert_eq!(depth, 1),
            other => panic!("wrong: {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "(X,3) not yet");
        reg.tick_depths(12, &chain); // depth 3 → (X,3) fires
        match rx.try_recv().expect("(X,3) fires") {
            WatchMatch::TxidDepthReached { depth, .. } => assert_eq!(depth, 3),
            other => panic!("wrong: {other:?}"),
        }
    }

    #[test]
    fn depth_reverts_on_reorg_then_rearms_at_new_height() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let tx = tx_with(0x51);
        let txid = tx.compute_txid();
        handle.add_tx_depths(&[(txid, 2)]);

        let block_a = block_at(1, vec![tx.clone()]);
        let mut chain = MockChain::default();
        chain.active.insert(10, block_a.block_hash());
        reg.arm_depths_for_block(&block_a, 10);
        reg.tick_depths(10, &chain); // depth 1 < 2
        assert!(rx.try_recv().is_err());

        // Reorg: height 10 is now a DIFFERENT block → anchor stale → revert.
        chain.active.insert(10, block_at(2, vec![]).block_hash());
        reg.tick_depths(11, &chain);
        assert!(rx.try_recv().is_err(), "reverted, no fire on stale anchor");

        // Tx re-mined at height 11 in a replacement block → re-arm and fire.
        let block_c = block_at(3, vec![tx]);
        chain.active.insert(11, block_c.block_hash());
        reg.arm_depths_for_block(&block_c, 11);
        reg.tick_depths(12, &chain); // depth = 12-11+1 = 2
        match rx.try_recv().expect("re-armed alarm fires at new height") {
            WatchMatch::TxidDepthReached { depth, height, .. } => {
                assert_eq!(depth, 2);
                assert_eq!(height, 11);
            }
            other => panic!("wrong: {other:?}"),
        }
    }

    #[test]
    fn already_confirmed_arms_via_txindex_probe() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let tx = tx_with(0x51);
        let txid = tx.compute_txid();
        handle.add_tx_depths(&[(txid, 3)]); // queued for probe

        // Tx already confirmed at height 10; tip is 12 → already 3 deep.
        let bh = block_at(1, vec![tx]).block_hash();
        let mut chain = MockChain::default();
        chain.txloc.insert(txid, (10, bh));
        chain.active.insert(10, bh);

        reg.tick_depths(12, &chain); // probe arms (10,bh), then fires
        match rx.try_recv().expect("probe arms an already-buried tx and fires") {
            WatchMatch::TxidDepthReached { depth, height, .. } => {
                assert_eq!(depth, 3);
                assert_eq!(height, 10);
            }
            other => panic!("wrong: {other:?}"),
        }
    }

    #[test]
    fn no_txindex_waits_for_live_observation() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let tx = tx_with(0x51);
        let txid = tx.compute_txid();
        handle.add_tx_depths(&[(txid, 2)]);

        // txindex disabled (empty txloc) → probe finds nothing → no arm/fire.
        let mut chain = MockChain::default();
        reg.tick_depths(20, &chain);
        assert!(rx.try_recv().is_err(), "no txindex → no probe arm");

        // Live observation arms it.
        let block = block_at(1, vec![tx]);
        chain.active.insert(19, block.block_hash());
        reg.arm_depths_for_block(&block, 19);
        reg.tick_depths(20, &chain); // depth = 20-19+1 = 2
        assert!(matches!(
            rx.try_recv(),
            Ok(WatchMatch::TxidDepthReached { depth: 2, .. })
        ));
    }

    #[test]
    fn auto_close_fires_finalized() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let tx = tx_with(0x51);
        let txid = tx.compute_txid();
        handle.add_txids(&[txid], 6); // lifecycle + auto-close at depth 6

        let block = block_at(1, vec![tx]);
        let mut chain = MockChain::default();
        chain.active.insert(10, block.block_hash());
        reg.scan_block(&block, 10, None); // delivers the lifecycle "confirmed"
        reg.arm_depths_for_block(&block, 10);
        // Drain the confirmed TxidMatched.
        assert!(matches!(
            rx.try_recv(),
            Ok(WatchMatch::TxidMatched {
                confirmed: true,
                ..
            })
        ));

        reg.tick_depths(14, &chain); // depth 5 < 6
        assert!(rx.try_recv().is_err());
        reg.tick_depths(15, &chain); // depth 6 → finalize
        match rx.try_recv().expect("auto-close fires TxidFinalized") {
            WatchMatch::TxidFinalized {
                txid: t,
                depth,
                height,
            } => {
                assert_eq!(t, txid);
                assert_eq!(depth, 6);
                assert_eq!(height, 10);
            }
            other => panic!("wrong: {other:?}"),
        }
    }

    #[test]
    fn auto_close_holds_through_reorg_below_depth() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let tx = tx_with(0x51);
        let txid = tx.compute_txid();
        handle.add_txids(&[txid], 6);

        let block = block_at(1, vec![tx]);
        let mut chain = MockChain::default();
        chain.active.insert(10, block.block_hash());
        reg.scan_block(&block, 10, None);
        reg.arm_depths_for_block(&block, 10);
        let _ = rx.try_recv(); // confirmed

        // Reorg below the close depth → revert, NO premature finalize.
        chain.active.insert(10, block_at(2, vec![]).block_hash());
        reg.tick_depths(13, &chain);
        assert!(rx.try_recv().is_err(), "no premature finalize on reorg");
        // Lifecycle watch survives (not evicted).
        assert!(reg.has_txid_watchers(), "lifecycle watch held through reorg");
    }

    #[test]
    fn auto_close_leaves_independent_alarms_intact() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let tx = tx_with(0x51);
        let txid = tx.compute_txid();
        handle.add_txids(&[txid], 6); // lifecycle + Close@6
        handle.add_tx_depths(&[(txid, 3)]); // independent Alarm@3

        // Removing the lifecycle watch tears down the Close entry but NOT the
        // independently-registered alarm.
        handle.remove_txids(&[txid]);
        assert!(!reg.has_txid_watchers(), "lifecycle gone");
        assert!(reg.has_depth_watchers(), "independent alarm survives");

        // The alarm still arms + fires, and self-evicts server-side on fire.
        let block = block_at(1, vec![tx]);
        let mut chain = MockChain::default();
        chain.active.insert(10, block.block_hash());
        reg.arm_depths_for_block(&block, 10);
        reg.tick_depths(12, &chain);
        assert!(
            !reg.has_depth_watchers(),
            "single-shot alarm self-evicts server-side on fire"
        );
    }

    #[test]
    fn depth_fire_self_evicts_registry_state() {
        // A fired alarm is fully removed from the registry on fire (not left
        // inert awaiting the carrier), so it cannot re-arm if its txid reappears
        // in a later block, and the counters are freed regardless of delivery.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let tx = tx_with(0x51);
        let txid = tx.compute_txid();
        handle.add_tx_depths(&[(txid, 1)]);

        let block_a = block_at(1, vec![tx.clone()]);
        let mut chain = MockChain::default();
        chain.active.insert(10, block_a.block_hash());
        reg.arm_depths_for_block(&block_a, 10);
        reg.tick_depths(10, &chain); // depth 1 → fires + self-evicts
        assert!(matches!(
            rx.try_recv(),
            Ok(WatchMatch::TxidDepthReached { depth: 1, .. })
        ));
        assert!(!reg.has_depth_watchers(), "self-evicted on fire");
        {
            let inner = reg.read_inner();
            assert!(inner.by_txid_depth.is_empty());
            assert!(inner.depth_anchor.is_empty());
            assert!(inner.armed.is_empty());
        }

        // The same txid re-mined in a later block must NOT resurrect a duplicate
        // terminal (the entry is gone, so arming finds nothing).
        let block_b = block_at(2, vec![tx]);
        chain.active.insert(11, block_b.block_hash());
        reg.arm_depths_for_block(&block_b, 11);
        reg.tick_depths(11, &chain);
        assert!(rx.try_recv().is_err(), "no duplicate terminal on re-mine");
    }

    #[test]
    fn auto_close_finalize_evicts_lifecycle_watch() {
        // TxidFinalized is terminal for the lifecycle watch: after it fires, the
        // lifecycle watch is gone (stops narrating) without a carrier round-trip.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let tx = tx_with(0x51);
        let txid = tx.compute_txid();
        handle.add_txids(&[txid], 2);

        let block = block_at(1, vec![tx]);
        let mut chain = MockChain::default();
        chain.active.insert(10, block.block_hash());
        reg.scan_block(&block, 10, None);
        reg.arm_depths_for_block(&block, 10);
        let _ = rx.try_recv(); // confirmed TxidMatched
        reg.tick_depths(11, &chain); // depth 2 → TxidFinalized
        assert!(matches!(rx.try_recv(), Ok(WatchMatch::TxidFinalized { .. })));
        assert!(!reg.has_txid_watchers(), "lifecycle watch evicted on finalize");
        assert!(!reg.has_depth_watchers(), "close entry evicted on finalize");
        assert!(!reg.has_watchers(), "no residual watch items");
    }

    #[test]
    fn deregister_clears_depth_structures() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let txid = tx_with(0x51).compute_txid();
        let txid2 = tx_with(0x52).compute_txid();
        handle.add_txids(&[txid], 6);
        handle.add_tx_depths(&[(txid2, 2), (txid2, 4)]);
        assert!(reg.has_depth_watchers());
        drop(handle);
        assert!(!reg.has_depth_watchers());
        assert!(!reg.has_watchers());
        let inner = reg.read_inner();
        assert!(inner.by_txid_depth.is_empty());
        assert!(inner.depth_anchor.is_empty());
        assert!(inner.armed.is_empty());
    }

    // --- input-side script matching (B1, confirmed via undo data) ---

    fn coin_with_spk(spk: ScriptBuf) -> crate::storage::coinview::Coin {
        crate::storage::coinview::Coin {
            amount: 1000,
            script_pubkey: spk,
            height: 1,
            coinbase: false,
        }
    }

    fn coinbase_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn block_with(txs: Vec<Transaction>) -> Block {
        Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::TWO,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: txs,
        }
    }

    #[test]
    fn input_side_script_match_from_undo() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        // Watch the script that the SPENT prevout pays — the spending tx does
        // not carry it, so the match can only come from the block's undo.
        let spent_spk = ScriptBuf::from(vec![0x52]);
        let sh = scripthash_of(&spent_spk);
        assert_eq!(handle.add_scripthashes(&[sh]), 1);
        assert!(reg.has_script_watchers());

        let op = outpoint(0xaa, 3);
        let block = block_with(vec![coinbase_tx(), spending_tx(op)]);
        // Undo: one spent coin (the non-coinbase input), carrying the watched
        // scriptPubKey.
        let undo = UndoData {
            spent_coins: vec![coin_with_spk(spent_spk)],
        };

        reg.scan_block(&block, 9, Some(&undo));
        match rx.try_recv().expect("an input-side match was delivered") {
            WatchMatch::ScriptMatched {
                scripthash,
                is_output,
                index,
                confirmed,
                height,
                ..
            } => {
                assert_eq!(scripthash, sh);
                assert!(!is_output, "input-side match → is_output = false");
                assert_eq!(index, 0, "vin of the spending input");
                assert!(confirmed);
                assert_eq!(height, Some(9));
            }
            other => panic!("wrong match: {other:?}"),
        }
    }

    #[test]
    fn input_side_skips_coinbase_and_aligns_undo_across_txs() {
        // Two non-coinbase txs after the coinbase; the watched script is the
        // prevout of the SECOND tx's input. Proves the coinbase is skipped and
        // the running undo index stays aligned with tx/input order.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let watched = ScriptBuf::from(vec![0x53]);
        let sh = scripthash_of(&watched);
        handle.add_scripthashes(&[sh]);

        let block = block_with(vec![
            coinbase_tx(),
            spending_tx(outpoint(0xb1, 0)),
            spending_tx(outpoint(0xb2, 1)),
        ]);
        // Undo order = non-coinbase inputs in connect order: [tx1.in0, tx2.in0].
        let undo = UndoData {
            spent_coins: vec![
                coin_with_spk(ScriptBuf::from(vec![0x99])), // tx1's prevout (unwatched)
                coin_with_spk(watched),                     // tx2's prevout (watched)
            ],
        };

        reg.scan_block(&block, 5, Some(&undo));
        match rx.try_recv().expect("the second tx's spend matched") {
            WatchMatch::ScriptMatched {
                scripthash,
                is_output,
                index,
                ..
            } => {
                assert_eq!(scripthash, sh);
                assert!(!is_output);
                assert_eq!(index, 0, "vin within the matching (second) tx");
            }
            other => panic!("wrong match: {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "only one input-side match expected");
    }

    #[test]
    fn input_side_inert_without_undo_or_script_watch() {
        // No undo → no input-side scan, even with a script watched.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spk = ScriptBuf::from(vec![0x54]);
        handle.add_scripthashes(&[scripthash_of(&spk)]);
        let block = block_with(vec![coinbase_tx(), spending_tx(outpoint(0xcc, 0))]);
        reg.scan_block(&block, 3, None);
        assert!(rx.try_recv().is_err(), "no undo → no input-side match");

        // Outpoint-only watch-set → has_script_watchers() is false.
        let reg2 = Arc::new(WatchRegistry::new());
        let (h2, _rx2) = reg2.register(WATCH_CHANNEL_CAPACITY);
        h2.add_outpoints(&[outpoint(0x01, 0)]);
        assert!(!reg2.has_script_watchers());
    }

    #[test]
    fn empty_registry_is_a_noop() {
        let reg = Arc::new(WatchRegistry::new());
        assert!(!reg.has_watchers());
        // No panic, no work; the matcher gate keeps this cheap.
        reg.scan_mempool_tx(&spending_tx(outpoint(0x09, 0)));
    }

    #[test]
    fn drop_handle_deregisters_and_clears_watch_count() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        handle.add_outpoints(&[outpoint(0x01, 0), outpoint(0x02, 1)]);
        handle.add_scripthashes(&[[7u8; 32]]);
        assert!(reg.has_watchers());
        drop(handle);
        assert!(!reg.has_watchers(), "drop must clear all watches");
        // Inverted indexes emptied too.
        let inner = reg.read_inner();
        assert!(inner.by_outpoint.is_empty());
        assert!(inner.by_scripthash.is_empty());
        assert!(inner.subs.is_empty());
    }

    #[test]
    fn remove_outpoint_stops_matching() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let op = outpoint(0x05, 2);
        handle.add_outpoints(&[op]);
        assert_eq!(handle.remove_outpoints(&[op]), 1);
        assert!(!reg.has_watchers());
        reg.scan_mempool_tx(&spending_tx(op));
        assert!(rx.try_recv().is_err(), "removed outpoint must not match");
    }

    #[test]
    fn two_subscribers_each_get_their_own_match() {
        let reg = Arc::new(WatchRegistry::new());
        let (h1, mut rx1) = reg.register(WATCH_CHANNEL_CAPACITY);
        let (h2, mut rx2) = reg.register(WATCH_CHANNEL_CAPACITY);
        let op1 = outpoint(0x11, 0);
        let op2 = outpoint(0x22, 0);
        h1.add_outpoints(&[op1]);
        h2.add_outpoints(&[op2]);
        // tx spends op1 only → only subscriber 1 hears it.
        reg.scan_mempool_tx(&spending_tx(op1));
        assert!(matches!(
            rx1.try_recv(),
            Ok(WatchMatch::OutpointSpent { .. })
        ));
        assert!(rx2.try_recv().is_err(), "subscriber 2 watches a different outpoint");
    }

    // --- resync_range (matcher lag catch-up window) ---

    #[test]
    fn resync_range_normal_gap_within_cap_rescans_whole_gap() {
        // Scanned through 100, tip now 105, generous cap → rescan 101..=105.
        assert_eq!(resync_range(100, 105, 10_000), Some((101, 105, 0)));
    }

    #[test]
    fn resync_range_caught_up_is_none() {
        // tip == last scanned: nothing to do.
        assert_eq!(resync_range(105, 105, 10_000), None);
    }

    #[test]
    fn resync_range_tip_below_last_scanned_is_none() {
        // The forward helper returns None when tip <= last_scanned. This is only
        // reached when the frontier block is still on the active chain (the
        // caller's frontier-hash check passed), so tip < last_scanned cannot be
        // a reorg that replaced our frontier — that case routes to
        // `reorg_resync_range` instead. Here there is simply nothing above the
        // frontier to forward-rescan.
        assert_eq!(resync_range(105, 102, 10_000), None);
    }

    #[test]
    fn resync_range_gap_exceeds_cap_keeps_most_recent_and_reports_skipped() {
        // Scanned through 0, tip 10_000, cap 100 → rescan only the most recent
        // 100 blocks (9901..=10000) and report 9900 skipped.
        assert_eq!(resync_range(0, 10_000, 100), Some((9_901, 10_000, 9_900)));
        // The kept window is exactly `cap` blocks wide.
        let (from, to, _) = resync_range(0, 10_000, 100).unwrap();
        assert_eq!(to - from + 1, 100);
    }

    #[test]
    fn resync_range_exactly_at_cap_does_not_skip() {
        // span == cap → no skip, full gap rescanned.
        assert_eq!(resync_range(0, 100, 100), Some((1, 100, 0)));
    }

    #[test]
    fn resync_range_zero_cap_disables_cap() {
        // max == 0 → rescan the entire gap regardless of size.
        assert_eq!(resync_range(0, 1_000_000, 0), Some((1, 1_000_000, 0)));
    }

    // --- reorg_resync_range (lag during which the frontier was reorged off) ---

    #[test]
    fn reorg_resync_range_rescans_cap_window_ending_at_tip() {
        // A reorg reached at/below the frontier during the lag: rescan the most
        // recent `max` blocks ending at tip (NOT anchored above the old, now
        // stale, frontier), re-covering replacement blocks at lower heights.
        // tip 105, cap 100 → 6..=105 (100 blocks), 6 older heights skipped.
        assert_eq!(reorg_resync_range(105, 100), Some((6, 105, 6)));
        let (from, to, _) = reorg_resync_range(105, 100).unwrap();
        assert_eq!(to - from + 1, 100, "window is exactly `cap` blocks wide");
    }

    #[test]
    fn reorg_resync_range_window_wider_than_chain_starts_at_genesis() {
        // cap exceeds the chain height → rescan from genesis, nothing skipped.
        assert_eq!(reorg_resync_range(50, 100), Some((0, 50, 0)));
    }

    #[test]
    fn reorg_resync_range_zero_cap_rescans_from_genesis() {
        // cap disabled → rescan the whole active chain from genesis.
        assert_eq!(reorg_resync_range(1_000, 0), Some((0, 1_000, 0)));
    }

    #[test]
    fn reorg_resync_range_covers_heights_at_or_below_old_frontier() {
        // The defect this guards against: a reorg replaces blocks 98,99,100 with
        // 98',99',100',101' while the matcher (frontier height 100) is lagged.
        // The forward-only resync_range(100, 101, ..) would scan ONLY 101,
        // missing replacements 98'..100'. The reorg window must include them.
        let (from, to, _) = reorg_resync_range(101, 10_000).unwrap();
        assert!(from <= 98, "must rescan down to the replaced heights, got {from}");
        assert_eq!(to, 101);
        // Contrast: the forward helper would have started at 101.
        assert_eq!(resync_range(100, 101, 10_000), Some((101, 101, 0)));
    }
}
