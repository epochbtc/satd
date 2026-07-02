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

use bitcoin::{Block, BlockHash, OutPoint, ScriptBuf, Transaction, Txid};
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
    /// A transaction fell inside a watched **script-prefix bucket** — the
    /// privacy-preserving watch (§7.5). Carries the full serialized tx so the
    /// client filters the bucket against its real scripts locally, with no
    /// precise follow-up fetch that would re-leak the exact interest. Boxed
    /// because the payload (a whole tx) dwarfs the other variants.
    PrefixMatched(Box<PrefixMatch>),
}

/// One matched spent prevout on the spend side of a [`PrefixMatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpentPrevoutMeta {
    /// The outpoint consumed by the spending input.
    pub outpoint: OutPoint,
    /// The spent prevout's `scriptPubKey`. Present for **confirmed** spends
    /// (recovered from undo data) and for **mempool** spends when
    /// `streamprevoutmeta = full`; **empty** otherwise (hash/amount tier), in
    /// which case the client resolves the prevout from its own UTXO set.
    pub script_pubkey: ScriptBuf,
    /// The spent prevout's value (satoshis). `Some` for confirmed spends and for
    /// mempool spends when `streamprevoutmeta >= amount` (the default); `None`
    /// under the `hash` tier.
    pub amount: Option<u64>,
}

/// Payload of a [`WatchMatch::PrefixMatched`]: a transaction that fell inside a
/// watched k-bit `sha256(scriptPubKey)` prefix bucket, on either side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixMatch {
    /// The registered prefix that fired, as `(masked_top32, bits)` — the top
    /// `bits` of the scripthash, with the low `32 - bits` zeroed. Lets the
    /// client tell which of its prefixes matched.
    pub prefix: (u32, u8),
    /// The full consensus-serialized matching transaction. Self-contained: the
    /// client decodes it and filters the bucket locally. `Arc`-wrapped so the
    /// per-subscriber delivery clone is a refcount bump, not a full-body copy.
    pub raw_tx: Arc<[u8]>,
    /// `true` in a connected block, `false` in the mempool.
    pub confirmed: bool,
    /// Block height when `confirmed`; `None` in the mempool.
    pub height: Option<u32>,
    /// Spend side: the matched spent-prevout(s) for inputs whose prevout script
    /// fell in the bucket. Empty for a pure funding (output-side) match. Lets a
    /// client confirm "a coin of mine was spent" — from the carried script
    /// directly (confirmed, or mempool under `full`) or against its own UTXO set
    /// (mempool under hash/amount, where the script is empty).
    pub matched_prevouts: Vec<SpentPrevoutMeta>,
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
    /// Watched scripthashes → per-script `min_value` floor (satoshis). A floor
    /// of `0` means "deliver every match" (the common case). The floor is a
    /// server-side delivery filter: an output/funding match is suppressed unless
    /// the output value is `>= floor`; a spend match unless the spent prevout's
    /// value is `>= floor` (symmetric). The value itself never enters the wire
    /// event — the floor only gates delivery.
    scripthashes: HashMap<Scripthash, u64>,
    /// Lifecycle watches (one per txid).
    txids: HashSet<Txid>,
    /// Depth-tracked entries: single-shot alarms and lifecycle auto-close
    /// triggers, distinguished by [`DepthKind`].
    tx_depths: HashSet<(Txid, u32, DepthKind)>,
    /// Privacy-preserving script-prefix buckets, as `(bits, masked_top32)`.
    prefixes: HashSet<(u8, u32)>,
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
    /// Inverted index: watched script-prefix bucket `(bits, masked_top32)` →
    /// subscribers. The privacy-preserving prefix watch (§7.5).
    by_prefix: HashMap<(u8, u32), HashSet<SubId>>,
    /// Distinct prefix bit-lengths currently registered → count of distinct
    /// `(bits, masked)` buckets at that length. A length is "active" while its
    /// count is `> 0`; the per-output/per-prevout scan iterates only these
    /// lengths (typically one or two), so its cost is O(distinct lengths),
    /// independent of subscriber count.
    prefix_lens: HashMap<u8, usize>,
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
    /// Lock-free count of registered *prefix* buckets (§7.5). Gates the
    /// per-output/per-prevout prefix scan and the undo-data fetch, so a
    /// watch-set with no prefixes pays nothing for them.
    prefix_items: AtomicUsize,
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
            prefix_items: AtomicUsize::new(0),
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

    /// `true` if any subscriber is watching at least one script-prefix bucket.
    /// Lock-free; gates the prefix scan and (with `has_script_watchers`) the
    /// input-side undo-data fetch.
    pub fn has_prefix_watchers(&self) -> bool {
        self.prefix_items.load(Ordering::Acquire) > 0
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
                scripthashes: HashMap::new(),
                txids: HashSet::new(),
                tx_depths: HashSet::new(),
                prefixes: HashSet::new(),
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

    /// Add scripthashes to a subscriber's watch-set, each with a `min_value`
    /// floor (satoshis; `0` = no floor). Returns the number *newly* added.
    /// Re-asserting an already-watched scripthash updates its floor in place and
    /// is not counted as new (dedup, matching the quota layer).
    fn add_scripthashes(&self, id: SubId, items: &[(Scripthash, u64)]) -> usize {
        let mut inner = self.lock_inner();
        let mut added = 0;
        for (sh, floor) in items {
            let is_new = match inner.subs.get_mut(&id) {
                Some(sub) => {
                    let is_new = !sub.scripthashes.contains_key(sh);
                    // Insert or update the floor either way.
                    sub.scripthashes.insert(*sh, *floor);
                    is_new
                }
                None => return added,
            };
            if is_new {
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
            if sub.scripthashes.remove(sh).is_some() {
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

    /// Add script-prefix buckets `(bits, masked_top32)` to a subscriber's
    /// watch-set. Returns the number newly added (already-watched buckets are
    /// not double-counted). Each prefix bumps `watch_items` (the block-reread
    /// gate) so a prefix-only watch-set still triggers block scans.
    fn add_prefixes(&self, id: SubId, prefixes: &[(u8, u32)]) -> usize {
        let mut inner = self.lock_inner();
        let mut added = 0;
        for &(bits, masked) in prefixes {
            let is_new = match inner.subs.get_mut(&id) {
                Some(sub) => sub.prefixes.insert((bits, masked)),
                None => break,
            };
            if is_new {
                added += 1;
                let set = inner.by_prefix.entry((bits, masked)).or_default();
                let first_for_bucket = set.is_empty();
                set.insert(id);
                if first_for_bucket {
                    *inner.prefix_lens.entry(bits).or_insert(0) += 1;
                }
            }
        }
        self.watch_items.fetch_add(added, Ordering::AcqRel);
        self.prefix_items.fetch_add(added, Ordering::AcqRel);
        added
    }

    /// Remove script-prefix buckets from a subscriber's watch-set. Returns the
    /// number removed.
    fn remove_prefixes(&self, id: SubId, prefixes: &[(u8, u32)]) -> usize {
        let mut inner = self.lock_inner();
        let mut removed = 0;
        for &(bits, masked) in prefixes {
            let was = match inner.subs.get_mut(&id) {
                Some(sub) => sub.prefixes.remove(&(bits, masked)),
                None => break,
            };
            if was {
                removed += 1;
                drop_prefix_bucket(&mut inner, id, bits, masked);
            }
        }
        self.watch_items.fetch_sub(removed, Ordering::AcqRel);
        self.prefix_items.fetch_sub(removed, Ordering::AcqRel);
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
        let freed_prefixes = sub.prefixes.len();
        // Alarms bump watch_items; Close entries don't (their lifecycle txid does).
        let alarm_count = sub
            .tx_depths
            .iter()
            .filter(|(_, _, k)| *k == DepthKind::Alarm)
            .count();
        let depth_count = sub.tx_depths.len();
        let freed = sub.outpoints.len()
            + sub.scripthashes.len()
            + sub.txids.len()
            + alarm_count
            + sub.prefixes.len();
        for op in &sub.outpoints {
            if let Some(set) = inner.by_outpoint.get_mut(op) {
                set.remove(&id);
                if set.is_empty() {
                    inner.by_outpoint.remove(op);
                }
            }
        }
        for sh in sub.scripthashes.keys() {
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
        let prefixes: Vec<(u8, u32)> = sub.prefixes.iter().copied().collect();
        for (bits, masked) in prefixes {
            drop_prefix_bucket(&mut inner, id, bits, masked);
        }
        self.watch_items.fetch_sub(freed, Ordering::AcqRel);
        self.script_items.fetch_sub(freed_scripts, Ordering::AcqRel);
        self.txid_items.fetch_sub(freed_txids, Ordering::AcqRel);
        self.depth_items.fetch_sub(depth_count, Ordering::AcqRel);
        self.prefix_items.fetch_sub(freed_prefixes, Ordering::AcqRel);
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
        let mut sink = LiveSink;
        for tx in &block.txdata {
            scan_tx(&inner, tx, true, Some(height), &mut sink);
        }
        // Input-side script/prefix matching: only meaningful with a watched
        // script or prefix and the undo data to recover the spent prevout
        // scriptPubKeys.
        if let Some(undo) = undo
            && (!inner.by_scripthash.is_empty() || !inner.prefix_lens.is_empty())
        {
            scan_block_spent_scripts(&inner, block, height, undo, &mut sink);
        }
    }

    /// Scan a connected block against this registry and **collect** the matches
    /// rather than delivering them to subscriber channels — the ordered,
    /// backpressure-safe path a bounded historical rescan
    /// ([`run_bounded_rescan`](crate::events::run_bounded_rescan)) uses. Runs
    /// the exact same matcher as [`scan_block`]; returns the matches in scan
    /// order (per tx: outpoint spends, then funding-script/prefix; then the
    /// block's input-side script/prefix matches recovered from `undo`).
    ///
    /// Intended for an ephemeral registry built by
    /// [`clone_for_rescan`](Self::clone_for_rescan), which holds exactly one
    /// subscriber's watch-set, so every collected match belongs to that
    /// subscriber — there is no cross-subscriber leakage and no drop-on-lag.
    pub fn scan_block_collect(
        &self,
        block: &Block,
        height: u32,
        undo: Option<&UndoData>,
    ) -> Vec<WatchMatch> {
        let mut sink = CollectSink { out: Vec::new() };
        if !self.has_watchers() {
            return sink.out;
        }
        let inner = self.read_inner();
        for tx in &block.txdata {
            scan_tx(&inner, tx, true, Some(height), &mut sink);
        }
        if let Some(undo) = undo
            && (!inner.by_scripthash.is_empty() || !inner.prefix_lens.is_empty())
        {
            scan_block_spent_scripts(&inner, block, height, undo, &mut sink);
        }
        sink.out
    }

    /// Build a standalone registry holding a **copy** of subscriber `id`'s
    /// current watch-set — exact scripts (with their `min_value` floors),
    /// outpoints, txids, and prefix buckets — for an isolated single-subscriber
    /// historical rescan. Because the returned registry has exactly one
    /// subscriber, matches produced against it (via
    /// [`scan_block_collect`](Self::scan_block_collect)) can never reach any
    /// other connection's channel.
    ///
    /// Depth alarms and txid-lifecycle auto-close entries are intentionally
    /// **not** copied: a bounded rescan reproduces the confirmed
    /// script/outpoint/txid/prefix matches a live block scan would, not the
    /// forward-looking, stateful depth/lifecycle transitions (those have no
    /// meaning replayed over a closed historical range).
    ///
    /// Returns `None` when `id` is unknown or its watch-set is empty (a rescan
    /// that could match nothing).
    pub fn clone_for_rescan(&self, id: SubId) -> Option<Arc<WatchRegistry>> {
        let src = self.read_inner();
        let sub = src.subs.get(&id)?;
        if sub.outpoints.is_empty()
            && sub.scripthashes.is_empty()
            && sub.txids.is_empty()
            && sub.prefixes.is_empty()
        {
            return None;
        }
        let registry = Arc::new(WatchRegistry::new());
        // A single synthetic subscriber holds the copied watch-set. Its channel
        // is never used — the collect path routes through `CollectSink`, not
        // `deliver` — but `Subscriber` owns a `Sender`, so create a throwaway.
        let (tx, _rx) = mpsc::channel(1);
        let new_id = registry.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut ni = registry.lock_inner();
            ni.subs.insert(
                new_id,
                Subscriber {
                    sender: tx,
                    outpoints: sub.outpoints.clone(),
                    scripthashes: sub.scripthashes.clone(),
                    txids: sub.txids.clone(),
                    tx_depths: HashSet::new(), // depth entries are not rescanned
                    prefixes: sub.prefixes.clone(),
                },
            );
            // Rebuild the inverted indexes this one subscriber contributes.
            for op in &sub.outpoints {
                ni.by_outpoint.entry(*op).or_default().insert(new_id);
            }
            for sh in sub.scripthashes.keys() {
                ni.by_scripthash.entry(*sh).or_default().insert(new_id);
            }
            for t in &sub.txids {
                ni.by_txid.entry(*t).or_default().insert(new_id);
            }
            for &(bits, masked) in &sub.prefixes {
                ni.by_prefix.entry((bits, masked)).or_default().insert(new_id);
                *ni.prefix_lens.entry(bits).or_default() += 1;
            }
        }
        // Gate counters, mirroring the `add_*` accounting: every kind bumps
        // `watch_items` (the `has_watchers` gate); scripts/txids/prefixes each
        // also bump their per-kind gate.
        let n_out = sub.outpoints.len();
        let n_scr = sub.scripthashes.len();
        let n_txid = sub.txids.len();
        let n_pfx = sub.prefixes.len();
        registry
            .watch_items
            .fetch_add(n_out + n_scr + n_txid + n_pfx, Ordering::AcqRel);
        registry.script_items.fetch_add(n_scr, Ordering::AcqRel);
        registry.txid_items.fetch_add(n_txid, Ordering::AcqRel);
        registry.prefix_items.fetch_add(n_pfx, Ordering::AcqRel);
        Some(registry)
    }

    /// Scan a single mempool transaction, routing matches to subscribers
    /// (unconfirmed). Cheap early-out when no one is watching.
    pub fn scan_mempool_tx(&self, tx: &Transaction) {
        if !self.has_watchers() {
            return;
        }
        let inner = self.read_inner();
        scan_tx(&inner, tx, false, None, &mut LiveSink);
    }

    /// Mempool **spend-side** script matching: the unconfirmed analogue of
    /// [`scan_block_spent_scripts`]. Fires when an accepted mempool tx spends a
    /// prevout whose `scriptPubKey` is **exactly watched** (`by_scripthash` →
    /// `ScriptMatched{is_output:false}`) or **hashes into a watched prefix
    /// bucket** (`by_prefix` → `PrefixMatched`). The spending tx carries no
    /// prevout script, so the caller supplies the prevout scripthashes
    /// (`prev_scripthashes[i]` ↔ `tx.input[i]`), retained on the
    /// [`MempoolEntry`](crate::mempool::pool::MempoolEntry) at admission.
    ///
    /// This closes the one spend-detection gap in the script/prefix watches:
    /// without it an *unconfirmed* spend of a watched script is observable only
    /// by *also* watching the funding outpoint (which a privacy/prefix client
    /// cannot name without leaking it). The confirmed side comes from block undo
    /// data; this is its mempool twin, off the same retained hashes.
    ///
    /// Exact `ScriptMatched` carries the watched scripthash (which the client
    /// already knows), so it is fully self-describing. Prefix delivery's
    /// `matched_prevouts` carry the spent outpoint plus whatever the retention
    /// tier kept: the prevout value under `streamprevoutmeta >= amount` (the
    /// default) and the full prevout `scriptPubKey` under `full` (empty
    /// otherwise → the client resolves the prevout from its own UTXO set). The
    /// confirmed (undo) path always carries both. Funding-side matches and all
    /// outpoint/txid matches are handled by
    /// [`scan_mempool_tx`](Self::scan_mempool_tx); call both per accepted tx.
    ///
    /// Self-gates on [`has_script_watchers`](Self::has_script_watchers) /
    /// [`has_prefix_watchers`](Self::has_prefix_watchers): a no-op (and no
    /// serialization) unless some spend-side watch is live, so the per-input
    /// scripthash retention on every entry is harmless when unused.
    /// `prev_amounts` is the spent prevout values (input order), retained on the
    /// entry only when `streamprevoutmeta >= amount`; it may be empty (the
    /// `hash` tier). It is consulted only for the exact-script `min_value` floor:
    /// when a watched script carries a non-zero floor but the spent value is not
    /// available here, the match is suppressed (fail-closed) rather than
    /// delivered unfiltered — so a `min_value` watcher never receives a dust
    /// unconfirmed spend it asked to be spared, regardless of the retention tier.
    pub fn scan_mempool_spent_scripts(
        &self,
        tx: &Transaction,
        prev_scripthashes: &[Scripthash],
        prev_amounts: &[u64],
        prev_scripts: &[ScriptBuf],
    ) {
        if !self.has_script_watchers() && !self.has_prefix_watchers() {
            return;
        }
        let inner = self.read_inner();
        let scan_scripts = !inner.by_scripthash.is_empty();
        let scan_prefixes = !inner.prefix_lens.is_empty();
        if !scan_scripts && !scan_prefixes {
            return;
        }
        let txid = tx.compute_txid();
        // Prefix matches are aggregated per bucket across this tx's inputs (one
        // PrefixMatched per bucket, mirroring the confirmed undo path); exact
        // matches fire per input. `zip` aligns each input with its prevout hash
        // and tolerates a short/empty slice (delivers nothing rather than
        // misalign); `enumerate` over the zip yields the input index (1:1).
        let mut prefix_spends: HashMap<(u8, u32), Vec<SpentPrevoutMeta>> = HashMap::new();
        for (vin, (input, sh)) in tx.input.iter().zip(prev_scripthashes.iter()).enumerate() {
            if scan_scripts
                && let Some(subs) = inner.by_scripthash.get(sh)
            {
                let m = WatchMatch::ScriptMatched {
                    scripthash: *sh,
                    txid,
                    is_output: false,
                    index: vin as u32,
                    confirmed: false,
                    height: None,
                };
                // Mempool-input `min_value`: gate on the spent prevout's value
                // when retained (`streamprevoutmeta >= amount`). `None` (hash
                // tier) fails closed for a floored script (see `floor_allows`).
                let value = prev_amounts.get(vin).copied();
                for sid in subs {
                    if floor_allows(&inner, *sid, sh, value) {
                        deliver(&inner, *sid, &m);
                    }
                }
            }
            if scan_prefixes {
                // Carry whatever the retention tier kept: the full prevout script
                // under `full` (else empty → client resolves it itself), and the
                // value under `>= amount` (the default). The outpoint is always
                // known (from the spending tx).
                let script_pubkey = prev_scripts.get(vin).cloned().unwrap_or_default();
                let amount = prev_amounts.get(vin).copied();
                let top = prefix_top32(sh);
                for &bits in inner.prefix_lens.keys() {
                    let key = (bits, top & prefix_mask(bits));
                    if inner.by_prefix.contains_key(&key) {
                        prefix_spends.entry(key).or_default().push(SpentPrevoutMeta {
                            outpoint: input.previous_output,
                            script_pubkey: script_pubkey.clone(),
                            amount,
                        });
                    }
                }
            }
        }
        if prefix_spends.is_empty() {
            return;
        }
        let raw: Arc<[u8]> = Arc::from(bitcoin::consensus::serialize(tx));
        for (key, matched_prevouts) in prefix_spends {
            if let Some(subs) = inner.by_prefix.get(&key) {
                let m = WatchMatch::PrefixMatched(Box::new(PrefixMatch {
                    prefix: (key.1, key.0),
                    raw_tx: raw.clone(),
                    confirmed: false,
                    height: None,
                    matched_prevouts,
                }));
                for sid in subs {
                    deliver(&inner, *sid, &m);
                }
            }
        }
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

/// Remove subscriber `id` from a prefix bucket, dropping the bucket (and
/// decrementing its length refcount) when the last subscriber leaves.
fn drop_prefix_bucket(inner: &mut Inner, id: SubId, bits: u8, masked: u32) {
    if let Some(set) = inner.by_prefix.get_mut(&(bits, masked)) {
        set.remove(&id);
        if set.is_empty() {
            inner.by_prefix.remove(&(bits, masked));
            if let Some(c) = inner.prefix_lens.get_mut(&bits) {
                *c -= 1;
                if *c == 0 {
                    inner.prefix_lens.remove(&bits);
                }
            }
        }
    }
}

/// Mask keeping the top `bits` of a `u32` (the high bits of a scripthash),
/// zeroing the low `32 - bits`. `bits == 0` → all-zero; `bits >= 32` → all-one.
fn prefix_mask(bits: u8) -> u32 {
    match bits {
        0 => 0,
        b if b >= 32 => u32::MAX,
        b => u32::MAX << (32 - b),
    }
}

/// The top 32 bits of a scripthash, as a `u32` — the value prefix buckets key on.
fn prefix_top32(sh: &Scripthash) -> u32 {
    u32::from_be_bytes([sh[0], sh[1], sh[2], sh[3]])
}

/// Bucket key for a client-supplied prefix: the first (up to 4) `prefix` bytes,
/// left-aligned and zero-padded into a `u32`, masked to `bits`. The single
/// source of truth for the carrier's `(bits, key)` and the registry's per-script
/// lookup — a script funds/spends inside the bucket iff
/// `prefix_top32(sh) & prefix_mask(bits) == prefix_bucket_key(prefix, bits)`.
/// The caller validates `prefix.len() == bits.div_ceil(8)` and the `bits` range.
pub fn prefix_bucket_key(prefix: &[u8], bits: u8) -> u32 {
    let mut buf = [0u8; 4];
    let n = prefix.len().min(4);
    buf[..n].copy_from_slice(&prefix[..n]);
    u32::from_be_bytes(buf) & prefix_mask(bits)
}

/// Funding (output-side) prefix delivery for one output's scripthash. A funding
/// match's payload is identical for every output that lands in the same bucket
/// (it carries no vout and no prevout — just "this tx funds bucket B"), so
/// `fired` dedups per `(bits, masked)` bucket across the tx's outputs: one event
/// per bucket per tx, not one per matching output. `raw_tx` is the per-tx
/// serialization cache, filled at most once and only on a real match.
#[allow(clippy::too_many_arguments)] // threaded matcher context + delivery sink
fn deliver_prefix_funding(
    inner: &Inner,
    sh: &Scripthash,
    raw_tx: &mut Option<Arc<[u8]>>,
    tx: &Transaction,
    confirmed: bool,
    height: Option<u32>,
    fired: &mut HashSet<(u8, u32)>,
    sink: &mut dyn MatchSink,
) {
    if inner.prefix_lens.is_empty() {
        return;
    }
    let top = prefix_top32(sh);
    for &bits in inner.prefix_lens.keys() {
        let key = (bits, top & prefix_mask(bits));
        if !fired.contains(&key)
            && let Some(subs) = inner.by_prefix.get(&key)
        {
            fired.insert(key);
            let raw = raw_tx.get_or_insert_with(|| Arc::from(bitcoin::consensus::serialize(tx)));
            let m = WatchMatch::PrefixMatched(Box::new(PrefixMatch {
                prefix: (key.1, key.0),
                raw_tx: raw.clone(),
                confirmed,
                height,
                matched_prevouts: Vec::new(),
            }));
            for sid in subs {
                sink.emit(inner, *sid, &m);
            }
        }
    }
}

/// Where the matcher routes a produced match. The live path
/// ([`LiveSink`]) delivers to the owning subscriber's channel with
/// drop-with-notice on lag; a bounded historical rescan ([`CollectSink`])
/// gathers them for its single ephemeral subscriber into a `Vec` for ordered,
/// backpressure-safe forwarding. Threaded through the block-scan matcher
/// (`scan_tx`, `deliver_prefix_funding`, `scan_block_spent_scripts`) so both
/// paths share one matcher and cannot drift.
trait MatchSink {
    fn emit(&mut self, inner: &Inner, id: SubId, m: &WatchMatch);
}

/// Live delivery — the standing behavior: non-blocking `try_send` to each
/// matched subscriber's channel (see [`deliver`]).
struct LiveSink;
impl MatchSink for LiveSink {
    #[inline]
    fn emit(&mut self, inner: &Inner, id: SubId, m: &WatchMatch) {
        deliver(inner, id, m);
    }
}

/// Collecting sink for a single-subscriber ephemeral registry (rescan): every
/// emitted match belongs to that one subscriber, so it is pushed verbatim in
/// scan order. No channel, no drops.
struct CollectSink {
    out: Vec<WatchMatch>,
}
impl MatchSink for CollectSink {
    #[inline]
    fn emit(&mut self, _inner: &Inner, _id: SubId, m: &WatchMatch) {
        self.out.push(m.clone());
    }
}

/// Match a single transaction against the watch-set and deliver to the
/// matching subscribers. Pure given `inner`; the hot loop the matcher runs.
fn scan_tx(
    inner: &Inner,
    tx: &Transaction,
    confirmed: bool,
    height: Option<u32>,
    sink: &mut dyn MatchSink,
) {
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
                sink.emit(inner, *sid, &m);
            }
        }
    }

    // Outputs → watched-script funding (exact scripts and prefix buckets).
    let scan_scripts = !inner.by_scripthash.is_empty();
    let scan_prefixes = !inner.prefix_lens.is_empty();
    if scan_scripts || scan_prefixes {
        // Per-tx serialization cache for prefix deliveries: filled lazily on the
        // first prefix match so an unmatched tx never serializes. `fired` dedups
        // funding-side prefix matches per bucket across this tx's outputs.
        let mut raw_tx: Option<Arc<[u8]>> = None;
        let mut fired = HashSet::new();
        for (vout, out) in tx.output.iter().enumerate() {
            let sh = scripthash_of(&out.script_pubkey);
            if scan_scripts
                && let Some(subs) = inner.by_scripthash.get(&sh)
            {
                let m = WatchMatch::ScriptMatched {
                    scripthash: sh,
                    txid,
                    is_output: true,
                    index: vout as u32,
                    confirmed,
                    height,
                };
                // Output-side `min_value`: gate on the funded output's value.
                let value = out.value.to_sat();
                for sid in subs {
                    if passes_floor(inner, *sid, &sh, value) {
                        sink.emit(inner, *sid, &m);
                    }
                }
            }
            if scan_prefixes {
                deliver_prefix_funding(
                    inner, &sh, &mut raw_tx, tx, confirmed, height, &mut fired, sink,
                );
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
            sink.emit(inner, *sid, &m);
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
fn scan_block_spent_scripts(
    inner: &Inner,
    block: &Block,
    height: u32,
    undo: &UndoData,
    sink: &mut dyn MatchSink,
) {
    let scan_scripts = !inner.by_scripthash.is_empty();
    let scan_prefixes = !inner.prefix_lens.is_empty();
    let mut undo_idx = 0usize;
    for tx in &block.txdata {
        if tx.is_coinbase() {
            continue; // coinbase has no spent prevouts in undo
        }
        let txid = tx.compute_txid();
        // Spend-side prefix matches are aggregated per bucket across this tx's
        // inputs: all matched prevouts for a bucket ride one PrefixMatched (one
        // full-tx body), not one event per input.
        let mut prefix_spends: HashMap<(u8, u32), Vec<SpentPrevoutMeta>> = HashMap::new();
        for (vin, input) in tx.input.iter().enumerate() {
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
            if scan_scripts
                && let Some(subs) = inner.by_scripthash.get(&sh)
            {
                let m = WatchMatch::ScriptMatched {
                    scripthash: sh,
                    txid,
                    is_output: false,
                    index: vin as u32,
                    confirmed: true,
                    height: Some(height),
                };
                // Input-side `min_value`: gate on the spent prevout's value,
                // recovered from undo data (symmetric with the output side).
                let value = spent.amount;
                for sid in subs {
                    if passes_floor(inner, *sid, &sh, value) {
                        sink.emit(inner, *sid, &m);
                    }
                }
            }
            if scan_prefixes {
                // Group the spent prevout under each bucket it lands in. Confirmed
                // spends always carry the full prevout script and value (both come
                // from the undo `Coin`).
                let top = prefix_top32(&sh);
                for &bits in inner.prefix_lens.keys() {
                    let key = (bits, top & prefix_mask(bits));
                    if inner.by_prefix.contains_key(&key) {
                        prefix_spends.entry(key).or_default().push(SpentPrevoutMeta {
                            outpoint: input.previous_output,
                            script_pubkey: spent.script_pubkey.clone(),
                            amount: Some(spent.amount),
                        });
                    }
                }
            }
        }
        // One PrefixMatched per matched bucket, carrying all its spent prevouts.
        if !prefix_spends.is_empty() {
            let raw: Arc<[u8]> = Arc::from(bitcoin::consensus::serialize(tx));
            for (key, matched_prevouts) in prefix_spends {
                if let Some(subs) = inner.by_prefix.get(&key) {
                    let m = WatchMatch::PrefixMatched(Box::new(PrefixMatch {
                        prefix: (key.1, key.0),
                        raw_tx: raw.clone(),
                        confirmed: true,
                        height: Some(height),
                        matched_prevouts,
                    }));
                    for sid in subs {
                        sink.emit(inner, *sid, &m);
                    }
                }
            }
        }
    }
}

/// Whether a script match for subscriber `id` on scripthash `sh` clears that
/// subscriber's `min_value` floor, given the matched value (the controlled
/// coin's value: output value for funding, spent-prevout value for spending).
///
/// `value` is `None` when the value is unavailable — only on the **mempool**
/// spend side under `streamprevoutmeta = hash`. In that case a *floored* script
/// **fails closed** (no delivery): we cannot prove the spend clears the floor,
/// so a `min_value` watcher is never handed a possibly-dust unconfirmed spend.
/// A floor of `0` (or no floor / absent subscriber) always delivers.
fn floor_allows(inner: &Inner, id: SubId, sh: &Scripthash, value: Option<u64>) -> bool {
    match inner.subs.get(&id).and_then(|s| s.scripthashes.get(sh)) {
        None | Some(0) => true,
        Some(&floor) => value.is_some_and(|v| v >= floor),
    }
}

/// Convenience for sites where the matched value is always known (output and
/// confirmed-block-input sides). See [`floor_allows`].
fn passes_floor(inner: &Inner, id: SubId, sh: &Scripthash, value: u64) -> bool {
    floor_allows(inner, id, sh, Some(value))
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
    /// This subscriber's registry id. Used to build an isolated ephemeral
    /// registry for a bounded historical rescan
    /// ([`WatchRegistry::clone_for_rescan`]).
    pub fn sub_id(&self) -> u64 {
        self.id
    }

    /// Add outpoints to this subscriber's watch-set; returns the count
    /// newly added.
    pub fn add_outpoints(&self, outpoints: &[OutPoint]) -> usize {
        self.registry.add_outpoints(self.id, outpoints)
    }

    /// Add scripthashes to this subscriber's watch-set with no `min_value`
    /// floor (deliver every match); returns the count newly added.
    pub fn add_scripthashes(&self, scripthashes: &[Scripthash]) -> usize {
        let items: Vec<(Scripthash, u64)> = scripthashes.iter().map(|sh| (*sh, 0)).collect();
        self.registry.add_scripthashes(self.id, &items)
    }

    /// Add scripthashes each with a `min_value` floor (satoshis; `0` = none);
    /// returns the count newly added. Re-asserting a watched scripthash updates
    /// its floor without re-counting.
    pub fn add_scripthashes_with_floors(&self, items: &[(Scripthash, u64)]) -> usize {
        self.registry.add_scripthashes(self.id, items)
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

    /// Add script-prefix buckets `(bits, masked_top32)` (§7.5); returns the
    /// count newly added.
    pub fn add_prefixes(&self, prefixes: &[(u8, u32)]) -> usize {
        self.registry.add_prefixes(self.id, prefixes)
    }

    /// Remove script-prefix buckets; returns the count removed.
    pub fn remove_prefixes(&self, prefixes: &[(u8, u32)]) -> usize {
        self.registry.remove_prefixes(self.id, prefixes)
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
    if registry.has_script_watchers() || registry.has_prefix_watchers() {
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
                        // Mempool spend-side script + prefix matching (unconfirmed
                        // analogue of the undo-driven confirmed path). Uses the
                        // prevout scripthashes retained on the entry; self-gates
                        // on has_script_watchers()/has_prefix_watchers() so it's
                        // free when no spend-side watch is live.
                        registry.scan_mempool_spent_scripts(
                            &entry.tx,
                            &entry.prev_scripthashes,
                            &entry.prev_amounts,
                            &entry.prev_scripts,
                        );
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

    fn coin_with_value(spk: ScriptBuf, amount: u64) -> crate::storage::coinview::Coin {
        crate::storage::coinview::Coin {
            amount,
            script_pubkey: spk,
            height: 1,
            coinbase: false,
        }
    }

    fn funding_tx_value(spk: ScriptBuf, value: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: spk,
            }],
        }
    }

    #[test]
    fn min_value_floor_filters_output_funding() {
        // A per-script min_value floor suppresses funding matches whose output
        // value is below the floor, and lets matches at/above it through.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spk = ScriptBuf::from(vec![0x51]);
        let sh = scripthash_of(&spk);
        assert_eq!(handle.add_scripthashes_with_floors(&[(sh, 1_000)]), 1);

        // Below the floor: dropped.
        reg.scan_block(&block_with(vec![funding_tx_value(spk.clone(), 999)]), 7, None);
        assert!(rx.try_recv().is_err(), "999 < 1000 floor → suppressed");

        // At the floor: delivered.
        reg.scan_block(&block_with(vec![funding_tx_value(spk.clone(), 1_000)]), 8, None);
        match rx.try_recv().expect("1000 >= floor → delivered") {
            WatchMatch::ScriptMatched {
                scripthash,
                is_output,
                ..
            } => {
                assert_eq!(scripthash, sh);
                assert!(is_output);
            }
            other => panic!("wrong match: {other:?}"),
        }

        // Above the floor: delivered.
        reg.scan_block(&block_with(vec![funding_tx_value(spk, 5_000)]), 9, None);
        assert!(
            matches!(rx.try_recv(), Ok(WatchMatch::ScriptMatched { .. })),
            "5000 > floor → delivered"
        );
    }

    #[test]
    fn min_value_floor_filters_confirmed_input_spend() {
        // The floor is symmetric: a spend match is gated on the SPENT prevout's
        // value (recovered from undo), not the output value.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spent_spk = ScriptBuf::from(vec![0x52]);
        let sh = scripthash_of(&spent_spk);
        assert_eq!(handle.add_scripthashes_with_floors(&[(sh, 1_000)]), 1);

        let op = outpoint(0xaa, 3);
        let block = block_with(vec![coinbase_tx(), spending_tx(op)]);

        // Spent prevout worth 999 < floor → suppressed.
        let undo_low = UndoData {
            spent_coins: vec![coin_with_value(spent_spk.clone(), 999)],
        };
        reg.scan_block(&block, 9, Some(&undo_low));
        assert!(rx.try_recv().is_err(), "spent value below floor → suppressed");

        // Spent prevout worth 1000 == floor → delivered.
        let undo_ok = UndoData {
            spent_coins: vec![coin_with_value(spent_spk, 1_000)],
        };
        reg.scan_block(&block, 10, Some(&undo_ok));
        match rx.try_recv().expect("spent value at floor → delivered") {
            WatchMatch::ScriptMatched {
                scripthash,
                is_output,
                confirmed,
                ..
            } => {
                assert_eq!(scripthash, sh);
                assert!(!is_output, "spend side");
                assert!(confirmed);
            }
            other => panic!("wrong match: {other:?}"),
        }
    }

    #[test]
    fn min_value_reassert_updates_floor_without_recount() {
        // Re-asserting a watched scripthash updates its floor in place and is not
        // counted as newly added (dedup), and the *new* floor governs delivery.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spk = ScriptBuf::from(vec![0x51]);
        let sh = scripthash_of(&spk);

        // Initial floor 500.
        assert_eq!(handle.add_scripthashes_with_floors(&[(sh, 500)]), 1);
        // Re-assert with a higher floor: no new item, floor updated to 2000.
        assert_eq!(
            handle.add_scripthashes_with_floors(&[(sh, 2_000)]),
            0,
            "re-assert is not a new item"
        );

        // A 1000-value funding now falls below the updated 2000 floor → dropped.
        reg.scan_block(&block_with(vec![funding_tx_value(spk.clone(), 1_000)]), 7, None);
        assert!(rx.try_recv().is_err(), "updated floor (2000) governs");

        // 2000 clears it.
        reg.scan_block(&block_with(vec![funding_tx_value(spk, 2_000)]), 8, None);
        assert!(matches!(
            rx.try_recv(),
            Ok(WatchMatch::ScriptMatched { .. })
        ));
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

    // ---- §7.5 privacy-preserving script-prefix watch ----

    /// Bucket key a client would register for `sh` at `k` bits.
    fn bucket(sh: &Scripthash, k: u8) -> (u8, u32) {
        (k, prefix_top32(sh) & prefix_mask(k))
    }

    #[test]
    fn prefix_mask_boundaries() {
        assert_eq!(prefix_mask(0), 0);
        assert_eq!(prefix_mask(8), 0xFF00_0000);
        assert_eq!(prefix_mask(16), 0xFFFF_0000);
        assert_eq!(prefix_mask(32), 0xFFFF_FFFF);
        assert_eq!(prefix_mask(40), 0xFFFF_FFFF, ">= 32 saturates");
    }

    #[test]
    fn prefix_bucket_key_matches_registry_masking() {
        // The carrier builds the bucket key from the client's prefix BYTES; the
        // registry builds it from a script's scripthash. They must agree.
        let sh = scripthash_of(&ScriptBuf::from(vec![0x51]));
        for k in [1u8, 8, 13, 16, 32] {
            let nbytes = (k as usize).div_ceil(8);
            assert_eq!(
                prefix_bucket_key(&sh[..nbytes], k),
                prefix_top32(&sh) & prefix_mask(k),
                "carrier byte-path and registry masking disagree at k={k}",
            );
        }
    }

    #[test]
    fn prefix_funding_match_mempool_and_confirmed() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spk = ScriptBuf::from(vec![0x51]);
        let sh = scripthash_of(&spk);
        assert_eq!(handle.add_prefixes(&[bucket(&sh, 12)]), 1);
        assert!(reg.has_watchers() && reg.has_prefix_watchers());

        let tx = funding_tx(spk);
        reg.scan_mempool_tx(&tx);
        match rx.try_recv().expect("mempool prefix match") {
            WatchMatch::PrefixMatched(pm) => {
                assert_eq!(pm.prefix, (prefix_top32(&sh) & prefix_mask(12), 12));
                assert!(!pm.confirmed);
                assert_eq!(pm.height, None);
                assert!(pm.matched_prevouts.is_empty(), "funding side carries no prevout");
                let decoded: Transaction = bitcoin::consensus::deserialize(pm.raw_tx.as_ref()).unwrap();
                assert_eq!(decoded.compute_txid(), tx.compute_txid(), "raw_tx is the full tx");
            }
            other => panic!("wrong match: {other:?}"),
        }

        reg.scan_block(&block_with(vec![tx]), 7, None);
        match rx.try_recv().expect("confirmed prefix match") {
            WatchMatch::PrefixMatched(pm) => {
                assert!(pm.confirmed);
                assert_eq!(pm.height, Some(7));
            }
            other => panic!("wrong match: {other:?}"),
        }
    }

    #[test]
    fn prefix_spend_match_confirmed_via_undo() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spent_spk = ScriptBuf::from(vec![0x52]);
        let sh = scripthash_of(&spent_spk);
        handle.add_prefixes(&[bucket(&sh, 12)]);
        // Prefix watch fetches undo when a prefix is watched, like a script watch.
        assert!(reg.has_prefix_watchers());

        let op = outpoint(0xaa, 3);
        let block = block_with(vec![coinbase_tx(), spending_tx(op)]);
        let undo = UndoData {
            spent_coins: vec![coin_with_spk(spent_spk.clone())],
        };
        reg.scan_block(&block, 9, Some(&undo));
        match rx.try_recv().expect("input-side prefix match") {
            WatchMatch::PrefixMatched(pm) => {
                assert!(pm.confirmed);
                assert_eq!(pm.height, Some(9));
                assert_eq!(pm.matched_prevouts.len(), 1, "spend side carries the prevout");
                let mp0 = &pm.matched_prevouts[0];
                let (mop, mspk) = (&mp0.outpoint, &mp0.script_pubkey);
                assert_eq!(*mop, op);
                assert_eq!(*mspk, spent_spk);
            }
            other => panic!("wrong match: {other:?}"),
        }
    }

    #[test]
    fn two_prefix_lengths_match_independently() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spk = ScriptBuf::from(vec![0x51]);
        let sh = scripthash_of(&spk);
        assert_eq!(handle.add_prefixes(&[bucket(&sh, 8), bucket(&sh, 16)]), 2);

        reg.scan_mempool_tx(&funding_tx(spk));
        let mut bits_seen = Vec::new();
        while let Ok(WatchMatch::PrefixMatched(pm)) = rx.try_recv() {
            bits_seen.push(pm.prefix.1);
        }
        bits_seen.sort_unstable();
        assert_eq!(bits_seen, vec![8, 16], "both lengths fire as independent items");
    }

    #[test]
    fn prefix_no_match_outside_bucket() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let watched = scripthash_of(&ScriptBuf::from(vec![0x51]));
        handle.add_prefixes(&[bucket(&watched, 16)]);
        // A different script (overwhelmingly likely in a different 16-bit bucket).
        reg.scan_mempool_tx(&funding_tx(ScriptBuf::from(vec![0x52, 0x53, 0x54])));
        assert!(rx.try_recv().is_err(), "script outside the bucket must not match");
    }

    #[test]
    fn deregister_clears_prefix_state() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let sh = scripthash_of(&ScriptBuf::from(vec![0x51]));
        handle.add_prefixes(&[bucket(&sh, 8), bucket(&sh, 16)]);
        assert!(reg.has_prefix_watchers());
        drop(handle);
        assert!(!reg.has_prefix_watchers(), "prefix counter cleared on deregister");
        assert!(!reg.has_watchers(), "prefixes also clear the reread gate");
        let inner = reg.read_inner();
        assert!(inner.by_prefix.is_empty() && inner.prefix_lens.is_empty());
    }

    #[test]
    fn remove_prefix_releases_reread_gate() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let sh = scripthash_of(&ScriptBuf::from(vec![0x51]));
        let key = bucket(&sh, 12);
        handle.add_prefixes(&[key]);
        assert!(reg.has_prefix_watchers() && reg.has_watchers());
        assert_eq!(handle.remove_prefixes(&[key]), 1);
        assert!(!reg.has_prefix_watchers());
        assert!(!reg.has_watchers());
    }

    #[test]
    fn tx_matching_both_sides_emits_two_prefix_matches() {
        // A tx that funds one bucket (output) and spends another (input, via
        // undo) fires twice — once funding (no prevout), once spend (with
        // prevout) — mirroring ScriptMatched's per-side emission.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let out_spk = ScriptBuf::from(vec![0x51]);
        let in_spk = ScriptBuf::from(vec![0x52]);
        handle.add_prefixes(&[
            bucket(&scripthash_of(&out_spk), 12),
            bucket(&scripthash_of(&in_spk), 12),
        ]);

        let op = outpoint(0xcc, 1);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: out_spk,
            }],
        };
        let block = block_with(vec![coinbase_tx(), tx]);
        let undo = UndoData {
            spent_coins: vec![coin_with_spk(in_spk)],
        };
        reg.scan_block(&block, 3, Some(&undo));

        let (mut funding, mut spend) = (0, 0);
        while let Ok(WatchMatch::PrefixMatched(pm)) = rx.try_recv() {
            if pm.matched_prevouts.is_empty() {
                funding += 1;
            } else {
                spend += 1;
            }
        }
        assert_eq!((funding, spend), (1, 1), "one funding + one spend prefix match");
    }

    #[test]
    fn funding_side_dedups_per_bucket_across_outputs() {
        // A tx with MULTIPLE outputs in the same bucket must fire the funding
        // match ONCE (the payload is identical — no vout), not once per output.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spk = ScriptBuf::from(vec![0x51]);
        let sh = scripthash_of(&spk);
        handle.add_prefixes(&[bucket(&sh, 12)]);

        // Three outputs, all the same script → same bucket.
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut { value: Amount::from_sat(1), script_pubkey: spk.clone() },
                TxOut { value: Amount::from_sat(2), script_pubkey: spk.clone() },
                TxOut { value: Amount::from_sat(3), script_pubkey: spk },
            ],
        };
        reg.scan_mempool_tx(&tx);
        let mut n = 0;
        while let Ok(WatchMatch::PrefixMatched(_)) = rx.try_recv() {
            n += 1;
        }
        assert_eq!(n, 1, "one funding event per bucket per tx, not one per output");
    }

    #[test]
    fn spend_side_aggregates_prevouts_per_bucket() {
        // A tx spending TWO prevouts in the same bucket fires ONE spend event
        // carrying both prevouts, not two events.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spent_spk = ScriptBuf::from(vec![0x52]);
        let sh = scripthash_of(&spent_spk);
        handle.add_prefixes(&[bucket(&sh, 12)]);

        let op0 = outpoint(0xa0, 0);
        let op1 = outpoint(0xa1, 1);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn { previous_output: op0, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
                TxIn { previous_output: op1, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
            ],
            output: vec![],
        };
        let block = block_with(vec![coinbase_tx(), tx]);
        let undo = UndoData {
            spent_coins: vec![coin_with_spk(spent_spk.clone()), coin_with_spk(spent_spk)],
        };
        reg.scan_block(&block, 4, Some(&undo));

        match rx.try_recv().expect("one aggregated spend match") {
            WatchMatch::PrefixMatched(pm) => {
                assert_eq!(pm.matched_prevouts.len(), 2, "both prevouts in one event");
                let ops: Vec<OutPoint> = pm.matched_prevouts.iter().map(|m| m.outpoint).collect();
                assert!(ops.contains(&op0) && ops.contains(&op1));
            }
            other => panic!("wrong match: {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "no second spend event for the same bucket");
    }

    #[test]
    fn prefix_spend_match_mempool() {
        // The unconfirmed spend-side path: a mempool tx spends a prevout whose
        // scripthash lands in a watched bucket. Delivery is hash-only — the
        // matched prevout carries the spent outpoint but an EMPTY script.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spent_spk = ScriptBuf::from(vec![0x52]);
        let sh = scripthash_of(&spent_spk);
        handle.add_prefixes(&[bucket(&sh, 12)]);
        assert!(reg.has_prefix_watchers());

        let op = outpoint(0xaa, 3);
        let tx = spending_tx(op);
        reg.scan_mempool_spent_scripts(&tx, &[sh], &[], &[]);

        match rx.try_recv().expect("mempool spend-side prefix match") {
            WatchMatch::PrefixMatched(pm) => {
                assert_eq!(pm.prefix, (prefix_top32(&sh) & prefix_mask(12), 12));
                assert!(!pm.confirmed, "mempool spend is unconfirmed");
                assert_eq!(pm.height, None);
                assert_eq!(pm.matched_prevouts.len(), 1);
                let mp0 = &pm.matched_prevouts[0];
                let (mop, mspk) = (&mp0.outpoint, &mp0.script_pubkey);
                assert_eq!(*mop, op, "outpoint comes from the spending tx");
                assert!(
                    mspk.is_empty(),
                    "hash-only: prevout script not retained in mempool"
                );
                let decoded: Transaction =
                    bitcoin::consensus::deserialize(pm.raw_tx.as_ref()).unwrap();
                assert_eq!(decoded.compute_txid(), tx.compute_txid(), "raw_tx is the full tx");
            }
            other => panic!("wrong match: {other:?}"),
        }
    }

    #[test]
    fn mempool_spend_no_match_outside_bucket() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let watched = scripthash_of(&ScriptBuf::from(vec![0x52]));
        handle.add_prefixes(&[bucket(&watched, 16)]);

        // A spend whose prevout hashes into a different 16-bit bucket.
        let other = scripthash_of(&ScriptBuf::from(vec![0x53, 0x54, 0x55]));
        reg.scan_mempool_spent_scripts(&spending_tx(outpoint(0xbb, 0)), &[other], &[], &[]);
        assert!(rx.try_recv().is_err(), "prevout outside the bucket must not match");
    }

    #[test]
    fn mempool_spend_side_noop_without_prefix_watchers() {
        // Retention on every entry is harmless: with no prefix bucket live, the
        // spend-side scan delivers nothing (and never serializes the tx). An
        // outpoint-only watcher must not turn into a spurious prefix match.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        handle.add_outpoints(&[outpoint(0xaa, 3)]);
        assert!(reg.has_watchers() && !reg.has_prefix_watchers());

        let spent_spk = ScriptBuf::from(vec![0x52]);
        reg.scan_mempool_spent_scripts(
            &spending_tx(outpoint(0xaa, 3)),
            &[scripthash_of(&spent_spk)],
            &[],
            &[],
        );
        assert!(rx.try_recv().is_err(), "no prefix watchers → no spend-side delivery");
    }

    #[test]
    fn mempool_spend_aggregates_prevouts_per_bucket() {
        // Two mempool-spent prevouts in the same bucket → ONE event carrying
        // both outpoints, mirroring the confirmed undo path.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spent_spk = ScriptBuf::from(vec![0x52]);
        let sh = scripthash_of(&spent_spk);
        handle.add_prefixes(&[bucket(&sh, 12)]);

        let op0 = outpoint(0xa0, 0);
        let op1 = outpoint(0xa1, 1);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn { previous_output: op0, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
                TxIn { previous_output: op1, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
            ],
            output: vec![],
        };
        // Both inputs spend the same script → same bucket (input-aligned hashes).
        reg.scan_mempool_spent_scripts(&tx, &[sh, sh], &[], &[]);

        match rx.try_recv().expect("one aggregated mempool spend match") {
            WatchMatch::PrefixMatched(pm) => {
                assert!(!pm.confirmed);
                assert_eq!(pm.matched_prevouts.len(), 2, "both prevouts in one event");
                let ops: Vec<OutPoint> = pm.matched_prevouts.iter().map(|m| m.outpoint).collect();
                assert!(ops.contains(&op0) && ops.contains(&op1));
            }
            other => panic!("wrong match: {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "no second event for the same bucket");
    }

    #[test]
    fn mempool_spend_separates_distinct_buckets() {
        // A tx spending two prevouts in DIFFERENT watched buckets fires one
        // event per bucket, each carrying only its own prevout — verifies the
        // per-bucket aggregation map keys correctly, not just collapses inputs.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spk_a = ScriptBuf::from(vec![0x52]);
        let spk_b = ScriptBuf::from(vec![0x53]);
        let sh_a = scripthash_of(&spk_a);
        let sh_b = scripthash_of(&spk_b);
        // At 32 bits the two distinct scripts occupy distinct buckets; guard the
        // precondition so a (vanishingly unlikely) top-32 collision can't make
        // the "two events" assertion flaky.
        let (ba, bb) = (bucket(&sh_a, 32), bucket(&sh_b, 32));
        assert_ne!(ba, bb, "test setup: scripts must be in different buckets");
        handle.add_prefixes(&[ba, bb]);

        let op_a = outpoint(0xa0, 0);
        let op_b = outpoint(0xb0, 1);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn { previous_output: op_a, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
                TxIn { previous_output: op_b, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
            ],
            output: vec![],
        };
        reg.scan_mempool_spent_scripts(&tx, &[sh_a, sh_b], &[], &[]);

        // Collect both events and map each bucket to the single outpoint it carries.
        let mut by_bucket: std::collections::HashMap<(u8, u32), Vec<OutPoint>> =
            std::collections::HashMap::new();
        while let Ok(WatchMatch::PrefixMatched(pm)) = rx.try_recv() {
            let key = (pm.prefix.1, pm.prefix.0);
            let ops: Vec<OutPoint> = pm.matched_prevouts.iter().map(|m| m.outpoint).collect();
            by_bucket.insert(key, ops);
        }
        assert_eq!(by_bucket.len(), 2, "one event per distinct bucket");
        assert_eq!(by_bucket.get(&ba), Some(&vec![op_a]), "bucket A carries only its prevout");
        assert_eq!(by_bucket.get(&bb), Some(&vec![op_b]), "bucket B carries only its prevout");
    }

    #[test]
    fn prefix_mempool_spend_carries_script_and_amount_when_retained() {
        // Under `full` retention the mempool prefix spend side carries the real
        // prevout script (so a chainstate-less client confirms the match without
        // resolving the outpoint); under `amount` it carries the value but an
        // empty script; under `hash` neither (empty script, no amount).
        let spk = ScriptBuf::from(vec![0x52]);
        let sh = scripthash_of(&spk);
        let b = bucket(&sh, 32);
        let op = outpoint(0xa0, 0);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![],
        };

        // `full`: script + amount both carried.
        {
            let reg = Arc::new(WatchRegistry::new());
            let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
            handle.add_prefixes(&[b]);
            reg.scan_mempool_spent_scripts(&tx, &[sh], &[5_000], std::slice::from_ref(&spk));
            match rx.try_recv().expect("prefix spend match") {
                WatchMatch::PrefixMatched(pm) => {
                    assert_eq!(pm.matched_prevouts.len(), 1);
                    let m = &pm.matched_prevouts[0];
                    assert_eq!(m.outpoint, op);
                    assert_eq!(m.script_pubkey, spk, "full tier carries the real script");
                    assert_eq!(m.amount, Some(5_000), "full tier carries the value");
                }
                other => panic!("wrong match: {other:?}"),
            }
        }

        // `amount`: value carried, script empty (client resolves it).
        {
            let reg = Arc::new(WatchRegistry::new());
            let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
            handle.add_prefixes(&[b]);
            reg.scan_mempool_spent_scripts(&tx, &[sh], &[5_000], &[]);
            match rx.try_recv().expect("prefix spend match") {
                WatchMatch::PrefixMatched(pm) => {
                    let m = &pm.matched_prevouts[0];
                    assert!(m.script_pubkey.is_empty(), "amount tier: no script");
                    assert_eq!(m.amount, Some(5_000), "amount tier carries the value");
                }
                other => panic!("wrong match: {other:?}"),
            }
        }

        // `hash`: neither script nor amount.
        {
            let reg = Arc::new(WatchRegistry::new());
            let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
            handle.add_prefixes(&[b]);
            reg.scan_mempool_spent_scripts(&tx, &[sh], &[], &[]);
            match rx.try_recv().expect("prefix spend match") {
                WatchMatch::PrefixMatched(pm) => {
                    let m = &pm.matched_prevouts[0];
                    assert!(m.script_pubkey.is_empty(), "hash tier: no script");
                    assert_eq!(m.amount, None, "hash tier: no amount");
                }
                other => panic!("wrong match: {other:?}"),
            }
        }
    }

    #[test]
    fn exact_script_spend_match_mempool() {
        // The exact-`AddScripts` mempool spend side: a watched script's prior
        // output spent in the mempool fires ScriptMatched{is_output:false,
        // confirmed:false} — the unconfirmed twin of the undo-driven confirmed
        // path, off the same retained prevout scripthashes. Previously a watched
        // script saw mempool spends only via a separate outpoint watch.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spent_spk = ScriptBuf::from(vec![0x52]);
        let sh = scripthash_of(&spent_spk);
        assert_eq!(handle.add_scripthashes(&[sh]), 1);
        assert!(reg.has_script_watchers());

        let op = outpoint(0xaa, 3);
        reg.scan_mempool_spent_scripts(&spending_tx(op), &[sh], &[], &[]);

        match rx.try_recv().expect("mempool exact-script spend match") {
            WatchMatch::ScriptMatched {
                scripthash,
                is_output,
                index,
                confirmed,
                height,
                ..
            } => {
                assert_eq!(scripthash, sh);
                assert!(!is_output, "spend side");
                assert_eq!(index, 0, "input index");
                assert!(!confirmed, "mempool spend is unconfirmed");
                assert_eq!(height, None);
            }
            other => panic!("wrong match: {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one spend match");
    }

    #[test]
    fn min_value_floor_filters_mempool_input_spend() {
        // Mempool spend-side min_value: gate on the spent prevout value passed
        // alongside the scripthash (retained at admission under
        // streamprevoutmeta >= amount). Below floor → suppressed; at/above →
        // delivered.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spent_spk = ScriptBuf::from(vec![0x52]);
        let sh = scripthash_of(&spent_spk);
        assert_eq!(handle.add_scripthashes_with_floors(&[(sh, 1_000)]), 1);

        let op = outpoint(0xaa, 3);
        // Spent value 999 < floor → suppressed.
        reg.scan_mempool_spent_scripts(&spending_tx(op), &[sh], &[999], &[]);
        assert!(rx.try_recv().is_err(), "999 < floor → suppressed");

        // Spent value 1000 == floor → delivered.
        reg.scan_mempool_spent_scripts(&spending_tx(op), &[sh], &[1_000], &[]);
        match rx.try_recv().expect("1000 >= floor → delivered") {
            WatchMatch::ScriptMatched {
                is_output,
                confirmed,
                ..
            } => {
                assert!(!is_output, "spend side");
                assert!(!confirmed, "mempool");
            }
            other => panic!("wrong match: {other:?}"),
        }
    }

    #[test]
    fn min_value_floor_fails_closed_when_amount_unavailable() {
        // Under streamprevoutmeta=hash the entry retains no amounts, so the
        // mempool spend side has no value to test. A *floored* script must fail
        // closed (no delivery) — a min_value watcher is never handed a possibly
        // dust unconfirmed spend. A *non-floored* watch still delivers.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spent_spk = ScriptBuf::from(vec![0x52]);
        let sh = scripthash_of(&spent_spk);
        assert_eq!(handle.add_scripthashes_with_floors(&[(sh, 1_000)]), 1);

        // Empty amounts (hash tier) + a non-zero floor → fail closed.
        reg.scan_mempool_spent_scripts(&spending_tx(outpoint(0xaa, 3)), &[sh], &[], &[]);
        assert!(
            rx.try_recv().is_err(),
            "floored script + no amount available → suppressed (fail-closed)"
        );

        // A second subscriber with no floor still gets the match.
        let (handle2, mut rx2) = reg.register(WATCH_CHANNEL_CAPACITY);
        assert_eq!(handle2.add_scripthashes(&[sh]), 1);
        reg.scan_mempool_spent_scripts(&spending_tx(outpoint(0xaa, 3)), &[sh], &[], &[]);
        assert!(
            matches!(rx2.try_recv(), Ok(WatchMatch::ScriptMatched { .. })),
            "no-floor watcher delivers regardless of amount availability"
        );
        // ...and the floored one still doesn't.
        assert!(rx.try_recv().is_err(), "floored watcher still suppressed");
    }

    #[test]
    fn exact_script_spend_multi_input_reports_correct_vin() {
        // A multi-input tx where a non-zero input spends the watched script must
        // report that input's index as `vin`, proving the enumerate-over-zip
        // index is the true input position (not a match counter).
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let watched_spk = ScriptBuf::from(vec![0x52]);
        let watched = scripthash_of(&watched_spk);
        let other = scripthash_of(&ScriptBuf::from(vec![0x99, 0x98]));
        handle.add_scripthashes(&[watched]);

        // Three inputs; only input index 2 spends the watched script.
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn { previous_output: outpoint(0xa0, 0), script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
                TxIn { previous_output: outpoint(0xa1, 1), script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
                TxIn { previous_output: outpoint(0xa2, 2), script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() },
            ],
            output: vec![],
        };
        // prev_scripthashes aligned to inputs: only index 2 is the watched hash.
        reg.scan_mempool_spent_scripts(&tx, &[other, other, watched], &[], &[]);

        match rx.try_recv().expect("the matching input fires") {
            WatchMatch::ScriptMatched { scripthash, is_output, index, confirmed, .. } => {
                assert_eq!(scripthash, watched);
                assert!(!is_output);
                assert_eq!(index, 2, "vin is the true input index, not a match counter");
                assert!(!confirmed);
            }
            other => panic!("wrong match: {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "only the watched input matches");
    }

    #[test]
    fn exact_script_spend_no_match_outside_watch() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        handle.add_scripthashes(&[scripthash_of(&ScriptBuf::from(vec![0x52]))]);
        // A spend of a different (unwatched) prevout script.
        let other = scripthash_of(&ScriptBuf::from(vec![0x53, 0x54]));
        reg.scan_mempool_spent_scripts(&spending_tx(outpoint(0xbb, 0)), &[other], &[], &[]);
        assert!(rx.try_recv().is_err(), "unwatched prevout script must not match");
    }

    #[test]
    fn mempool_spend_side_noop_without_any_spend_watcher() {
        // With neither an exact-script nor a prefix watcher live, the spend-side
        // scan is a no-op (and never serializes), even with an outpoint watcher
        // present — the per-entry hash retention stays harmless.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        handle.add_outpoints(&[outpoint(0xaa, 3)]);
        assert!(!reg.has_script_watchers() && !reg.has_prefix_watchers());
        reg.scan_mempool_spent_scripts(
            &spending_tx(outpoint(0xaa, 3)),
            &[scripthash_of(&ScriptBuf::from(vec![0x52]))],
            &[],
            &[],
        );
        assert!(rx.try_recv().is_err(), "no spend-side watcher → no spend-side delivery");
    }

    #[test]
    fn exact_and_prefix_spend_both_fire_mempool() {
        // One prevout that is BOTH exactly watched and inside a watched bucket
        // fires both an exact ScriptMatched and a PrefixMatched — independent
        // watch items, per-side emission consistent with the confirmed path.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spent_spk = ScriptBuf::from(vec![0x52]);
        let sh = scripthash_of(&spent_spk);
        handle.add_scripthashes(&[sh]);
        handle.add_prefixes(&[bucket(&sh, 12)]);

        reg.scan_mempool_spent_scripts(&spending_tx(outpoint(0xaa, 3)), &[sh], &[], &[]);

        let (mut exact, mut prefix) = (0, 0);
        while let Ok(m) = rx.try_recv() {
            match m {
                WatchMatch::ScriptMatched { is_output: false, confirmed: false, .. } => exact += 1,
                WatchMatch::PrefixMatched(pm) if !pm.confirmed => prefix += 1,
                other => panic!("unexpected match: {other:?}"),
            }
        }
        assert_eq!((exact, prefix), (1, 1), "one exact + one prefix spend match");
    }

    // --- Bounded historical rescan (§6.1) -----------------------------------

    #[test]
    fn clone_for_rescan_none_for_empty_watchset() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        assert!(reg.clone_for_rescan(handle.sub_id()).is_none());
    }

    #[test]
    fn clone_for_rescan_none_for_unknown_sub() {
        let reg = Arc::new(WatchRegistry::new());
        assert!(reg.clone_for_rescan(999).is_none());
    }

    #[test]
    fn rescan_collects_output_and_outpoint_matches() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, mut rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spk = ScriptBuf::from(vec![0x51]);
        let sh = scripthash_of(&spk);
        let op = outpoint(0xcc, 1);
        assert_eq!(handle.add_scripthashes(&[sh]), 1);
        assert_eq!(handle.add_outpoints(&[op]), 1);

        let eph = reg.clone_for_rescan(handle.sub_id()).expect("non-empty watch-set");
        // A block funding the watched script (output side) and spending the
        // watched outpoint.
        let block = block_with(vec![funding_tx(spk), spending_tx(op)]);
        let matches = eph.scan_block_collect(&block, 42, None);

        let mut script = 0;
        let mut spent = 0;
        for m in &matches {
            match m {
                WatchMatch::ScriptMatched {
                    is_output: true,
                    height,
                    confirmed,
                    ..
                } => {
                    assert_eq!(*height, Some(42));
                    assert!(*confirmed);
                    script += 1;
                }
                WatchMatch::OutpointSpent {
                    outpoint,
                    height,
                    confirmed,
                    ..
                } => {
                    assert_eq!(*outpoint, op);
                    assert_eq!(*height, Some(42));
                    assert!(*confirmed);
                    spent += 1;
                }
                other => panic!("unexpected: {other:?}"),
            }
        }
        assert_eq!((script, spent), (1, 1));
        // The collect path must NOT deliver to the live subscriber channel.
        assert!(
            rx.try_recv().is_err(),
            "rescan collect must not touch the channel"
        );
    }

    #[test]
    fn rescan_collects_input_side_from_undo() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spent_spk = ScriptBuf::from(vec![0x52]);
        let sh = scripthash_of(&spent_spk);
        assert_eq!(handle.add_scripthashes(&[sh]), 1);

        let eph = reg.clone_for_rescan(handle.sub_id()).expect("non-empty watch-set");
        assert!(eph.has_script_watchers());
        let block = block_with(vec![coinbase_tx(), spending_tx(outpoint(0xaa, 3))]);
        let undo = UndoData {
            spent_coins: vec![coin_with_spk(spent_spk)],
        };
        let matches = eph.scan_block_collect(&block, 9, Some(&undo));
        assert_eq!(matches.len(), 1);
        match &matches[0] {
            WatchMatch::ScriptMatched {
                scripthash,
                is_output,
                confirmed,
                height,
                ..
            } => {
                assert_eq!(*scripthash, sh);
                assert!(!*is_output, "input-side match → is_output = false");
                assert!(*confirmed);
                assert_eq!(*height, Some(9));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rescan_is_isolated_from_other_subscribers() {
        // Two subscribers on the same registry watching disjoint scripts. A
        // rescan cloned from sub A must see only A's matches, never B's — the
        // ephemeral registry holds A's watch-set alone.
        let reg = Arc::new(WatchRegistry::new());
        let (handle_a, _rx_a) = reg.register(WATCH_CHANNEL_CAPACITY);
        let (handle_b, mut rx_b) = reg.register(WATCH_CHANNEL_CAPACITY);
        handle_a.add_scripthashes(&[scripthash_of(&ScriptBuf::from(vec![0x51]))]);
        let spk_b = ScriptBuf::from(vec![0x52]);
        handle_b.add_scripthashes(&[scripthash_of(&spk_b)]);

        let eph = reg.clone_for_rescan(handle_a.sub_id()).expect("non-empty");
        // Block funds only B's script.
        let block = block_with(vec![funding_tx(spk_b)]);
        assert!(
            eph.scan_block_collect(&block, 5, None).is_empty(),
            "A's rescan must not collect B's match"
        );
        // B's live channel is untouched by A's rescan (collect, not deliver).
        assert!(rx_b.try_recv().is_err());
    }

    #[test]
    fn rescan_collects_nothing_when_range_has_no_match() {
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        handle.add_scripthashes(&[scripthash_of(&ScriptBuf::from(vec![0x51]))]);
        let eph = reg.clone_for_rescan(handle.sub_id()).expect("non-empty");
        // Block funds a different script.
        let block = block_with(vec![funding_tx(ScriptBuf::from(vec![0x99]))]);
        assert!(eph.scan_block_collect(&block, 1, None).is_empty());
    }

    #[test]
    fn rescan_preserves_min_value_floor() {
        // A per-script `min_value` floor must survive the clone into the
        // ephemeral registry and gate rescan matches exactly as the live path:
        // a below-floor funding output is dropped, an at/above-floor one is
        // collected.
        let reg = Arc::new(WatchRegistry::new());
        let (handle, _rx) = reg.register(WATCH_CHANNEL_CAPACITY);
        let spk = ScriptBuf::from(vec![0x51]);
        let sh = scripthash_of(&spk);
        assert_eq!(handle.add_scripthashes_with_floors(&[(sh, 1_000)]), 1);

        let eph = reg.clone_for_rescan(handle.sub_id()).expect("non-empty watch-set");

        // Below the floor: no match collected.
        let below = block_with(vec![funding_tx_value(spk.clone(), 999)]);
        assert!(
            eph.scan_block_collect(&below, 7, None).is_empty(),
            "sub-floor funding must be filtered in rescan, as live"
        );

        // At the floor: exactly one funding match collected.
        let at = block_with(vec![funding_tx_value(spk, 1_000)]);
        let matches = eph.scan_block_collect(&at, 8, None);
        assert_eq!(matches.len(), 1, "at-floor funding must match in rescan");
        match &matches[0] {
            WatchMatch::ScriptMatched {
                scripthash,
                is_output: true,
                confirmed,
                height,
                ..
            } => {
                assert_eq!(*scripthash, sh);
                assert!(*confirmed);
                assert_eq!(*height, Some(8));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
