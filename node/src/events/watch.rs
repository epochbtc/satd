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
use crate::mempool::events::MempoolEvent;

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
    /// A watched script was paid by a transaction output.
    ///
    /// PR scope: **funding (output) side only**. Detecting that a watched
    /// script was *spent* (input side) needs the prevout's scriptPubKey,
    /// which is not present in the spending transaction; clients track
    /// spends by watching the funding outpoint (the descriptor layer wires
    /// this automatically). `is_output` is therefore always `true` today,
    /// but is carried so input-side matching can be added without a wire
    /// change.
    ScriptMatched {
        scripthash: Scripthash,
        txid: Txid,
        is_output: bool,
        /// `vout` (output index) for a funding match.
        index: u32,
        confirmed: bool,
        height: Option<u32>,
    },
}

/// Opaque per-subscriber identifier.
type SubId = u64;

struct Subscriber {
    sender: mpsc::Sender<WatchMatch>,
    outpoints: HashSet<OutPoint>,
    scripthashes: HashSet<Scripthash>,
}

#[derive(Default)]
struct Inner {
    subs: HashMap<SubId, Subscriber>,
    /// Inverted index: watched outpoint → subscribers watching it. Gives
    /// O(1) matching per transaction input.
    by_outpoint: HashMap<OutPoint, HashSet<SubId>>,
    /// Inverted index: watched scripthash → subscribers watching it.
    by_scripthash: HashMap<Scripthash, HashSet<SubId>>,
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
        }
    }

    /// `true` if any subscriber is watching at least one outpoint or
    /// script. Lock-free; the matcher gate.
    pub fn has_watchers(&self) -> bool {
        self.watch_items.load(Ordering::Acquire) > 0
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
        removed
    }

    /// De-register a subscriber and all its watches (called on
    /// [`WatchHandle`] drop).
    fn deregister(&self, id: SubId) {
        let mut inner = self.lock_inner();
        let Some(sub) = inner.subs.remove(&id) else {
            return;
        };
        let freed = sub.outpoints.len() + sub.scripthashes.len();
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
        self.watch_items.fetch_sub(freed, Ordering::AcqRel);
    }

    /// Scan every transaction in a connected block, routing matches to
    /// subscribers (confirmed). Cheap early-out when no one is watching.
    pub fn scan_block(&self, block: &Block, height: u32) {
        if !self.has_watchers() {
            return;
        }
        let inner = self.read_inner();
        for tx in &block.txdata {
            scan_tx(&inner, tx, true, Some(height));
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
                        registry.scan_block(&block, height);
                    }
                    last_scanned_height = height;
                    last_scanned_hash = Some(hash);
                }
                // Disconnects and the reorg marker are surfaced to clients
                // as first-class events; the matcher itself is spend/funding
                // oriented (append-only) and takes no action on either.
                // Clients roll back their own confirmed state on a Reorg.
                Ok(ChainEvent::BlockDisconnected { .. }) | Ok(ChainEvent::Reorg { .. }) => {}
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
                                    // for the active chain; stop rather than
                                    // fabricate heights.
                                    None => break,
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
                                    Some(block) => registry.scan_block(&block, *h),
                                    None => debug!(
                                        target: "events::watch",
                                        height = *h,
                                        "resync: block data unavailable (pruned?); skipping"
                                    ),
                                }
                            }
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
        reg.scan_block(&block, 7);
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
