//! Reconnect, watch-set replay, and re-anchor layer over [`StreamClient::watch`].
//!
//! [`ResilientSubscription`](crate::ResilientSubscription) wraps the one-way
//! `Subscribe` firehose; [`ResilientWatch`] is its twin for the bidirectional
//! `Watch` stream. It exists because the two recovery stories differ:
//!
//! - **The watch-set is per-connection.** The server holds no principal-keyed
//!   state — when a `Watch` stream drops, its server-side watch-set and quota
//!   leases are torn down with it. A reconnect therefore starts blank, so the
//!   SDK has to **mirror** every add/remove the caller makes and **re-register**
//!   the whole set on the new stream before anything matches again.
//! - **Re-anchor is in-band and deterministic (#439/#441).** Once the watch-set
//!   is back, a single `set_cursor` replays confirmed history; the server
//!   answers with exactly one [`Event::CursorAccepted`] (replaying — watch
//!   `clamped` for an authoritative replay-window gap) or
//!   [`Event::CursorRejected`]. [`ResilientWatch`] drives its catch-up off those
//!   deterministic results instead of inferring a gap from the event flow.
//!
//! What it handles for the caller:
//!
//! - **Reconnect with backoff** — a transport error or clean server close
//!   triggers an exponential-backoff reconnect (the shared [`Backoff`]).
//! - **Watch-set replay** — the mirrored watch-set (scripts + floors, outpoints,
//!   tx lifecycles, depth alarms, descriptors, prefixes, category filter) is
//!   re-sent on every (re)connect, in place of a manual re-add. Integrators whose
//!   watch-set has a durable source-of-truth outside the wrapper can instead
//!   install a [`watch_set_loader`](ResilientWatchConfig::watch_set_loader) that
//!   rebuilds the canonical set from that truth on every (re)connect — closing
//!   the restart-loses-mirror and truth-drift-during-disconnect gaps.
//! - **Re-anchor in place** — after replay it `set_cursor`s to the persisted
//!   high-water and resumes confirmed replay. Transient rejects
//!   (`RateLimited`, `ConcurrentReanchor`) are backed off and retried in place;
//!   terminal ones (`NoSource`, …) and the `clamped` accept are surfaced so the
//!   caller can escalate to a full resnapshot — the exception, not the rule.
//! - **Cursor persistence** — confirmed cursors are committed-on-poll to a
//!   shared [`CursorStore`], so a resume survives reconnects and restarts.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use satd_events_proto::v1 as pb;
use satd_events_proto::v1::subscribe_control::Msg;

use crate::client::{validate_prefix, AutoClose, EventStream, StreamClient, WatchHandle};
use crate::error::StreamError;
use crate::event::{Cursor, CursorRejectReason, Event};
use crate::resilience::{Backoff, CursorStore, NoopCursorStore};

/// A boxed integrator error returned by a watch-set loader.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The stored watch-set loader closure: takes a fresh [`WatchSetBuilder`],
/// populates it (typically from a durable source-of-truth), and resolves to
/// `Ok(())` once the canonical set is declared. Boxed so the loader can be any
/// async closure the integrator supplies.
type WatchSetLoaderFn =
    dyn Fn(WatchSetBuilder) -> Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send>>
        + Send
        + Sync;

/// A scripthash (`sha256(scriptPubKey)`).
type Scripthash = [u8; 32];
/// A txid (32 raw bytes, internal order).
type Txid = [u8; 32];

/// A client-side mirror of the watch-set registered on a `Watch` stream, so it
/// can be re-registered verbatim after a reconnect.
///
/// Each kind is stored as its **net** set (adds minus removes), keyed so a
/// re-assertion overwrites rather than duplicates — exactly the server's own
/// semantics. [`control_messages`](Self::control_messages) renders the net set
/// back into the [`SubscribeControl`](pb::SubscribeControl) `Add*` messages that
/// reconstruct it.
#[derive(Debug, Default, Clone)]
pub(crate) struct WatchSetMirror {
    /// Scripthash → optional `min_value` floor (a re-assert updates the floor).
    scripts: BTreeMap<Scripthash, Option<u64>>,
    /// Watched outpoints (`txid`, `vout`).
    outpoints: BTreeSet<(Txid, u32)>,
    /// Txid → lifecycle auto-close policy.
    tx_lifecycles: BTreeMap<Txid, AutoClose>,
    /// Single-shot depth alarms, as flattened `(txid, depth)` pairs.
    depth_alarms: BTreeSet<(Txid, u32)>,
    /// Descriptor → its latest `(gap_limit, start)` window.
    descriptors: BTreeMap<String, (u32, u32)>,
    /// Script-prefix buckets, as `(bits, prefix)` (validated on insert).
    prefixes: BTreeSet<(u32, Vec<u8>)>,
    /// The live category filter, if the caller set one.
    categories: Option<u32>,
    /// The raw-tx opt-in (SetWatchOptions), if the caller set one. Replayed on
    /// reconnect so `include_raw_tx` survives a stream tear-down.
    include_raw_tx: Option<bool>,
}

impl WatchSetMirror {
    fn add_scripts(&mut self, items: &[(Scripthash, Option<u64>)]) {
        for (h, floor) in items {
            self.scripts.insert(*h, *floor);
        }
    }

    fn remove_scripts(&mut self, hashes: &[Scripthash]) {
        for h in hashes {
            self.scripts.remove(h);
        }
    }

    fn add_outpoints(&mut self, items: &[(Txid, u32)]) {
        self.outpoints.extend(items.iter().copied());
    }

    fn remove_outpoints(&mut self, items: &[(Txid, u32)]) {
        for op in items {
            self.outpoints.remove(op);
        }
    }

    fn add_tx_lifecycle(&mut self, txids: &[Txid], auto_close: AutoClose) {
        for t in txids {
            self.tx_lifecycles.insert(*t, auto_close);
        }
    }

    fn remove_tx_lifecycle(&mut self, txids: &[Txid]) {
        for t in txids {
            self.tx_lifecycles.remove(t);
        }
    }

    fn add_depth_alarms(&mut self, pairs: &[(Txid, u32)]) {
        self.depth_alarms.extend(pairs.iter().copied());
    }

    fn remove_depth_alarms(&mut self, pairs: &[(Txid, u32)]) {
        for p in pairs {
            self.depth_alarms.remove(p);
        }
    }

    fn add_descriptor(&mut self, descriptor: String, gap_limit: u32, start: u32) {
        self.descriptors.insert(descriptor, (gap_limit, start));
    }

    fn remove_descriptor(&mut self, descriptor: &str) {
        self.descriptors.remove(descriptor);
    }

    fn add_prefixes(&mut self, items: &[pb::ScriptPrefix]) {
        for sp in items {
            self.prefixes.insert((sp.bits, sp.prefix.clone()));
        }
    }

    fn remove_prefixes(&mut self, items: &[pb::ScriptPrefix]) {
        for sp in items {
            self.prefixes.remove(&(sp.bits, sp.prefix.clone()));
        }
    }

    fn set_categories(&mut self, categories: u32) {
        self.categories = Some(categories);
    }

    fn set_watch_options(&mut self, include_raw_tx: bool) {
        self.include_raw_tx = Some(include_raw_tx);
    }

    /// Render the net watch-set into the control messages that reconstruct it on
    /// a fresh stream. The category filter goes first (so it is in effect before
    /// matches flow); the rest are grouped to match the wire shapes the
    /// [`WatchHandle`] helpers emit:
    /// - scripts in one `AddScripts` (parallel `min_values`, or empty when no
    ///   floor is set on any script);
    /// - lifecycles grouped by `auto_close_depth` (empty `min_depths`);
    /// - depth alarms grouped by txid (non-empty `min_depths` — the server
    ///   dispatches on that), one message per txid;
    /// - one `AddDescriptor` per descriptor; prefixes in one `AddScriptPrefixes`.
    fn control_messages(&self) -> Vec<Msg> {
        let mut out = Vec::new();

        if let Some(c) = self.categories {
            out.push(Msg::SetCategories(pb::SetCategories { categories: c }));
        }

        // Re-apply the raw-tx opt-in before matches flow, so replayed and live
        // ScriptMatched carry raw_tx exactly as before the reconnect.
        if let Some(include_raw_tx) = self.include_raw_tx {
            out.push(Msg::SetWatchOptions(pb::SetWatchOptions { include_raw_tx }));
        }

        if !self.scripts.is_empty() {
            let scripthashes: Vec<Vec<u8>> = self.scripts.keys().map(|h| h.to_vec()).collect();
            // Parallel `min_values` only when some script carries a floor (a 0
            // stands in for the unfloored entries to keep the vecs parallel);
            // empty otherwise, matching `WatchHandle::add_scripts`.
            let min_values = if self.scripts.values().any(Option::is_some) {
                self.scripts.values().map(|f| f.unwrap_or(0)).collect()
            } else {
                Vec::new()
            };
            out.push(Msg::AddScripts(pb::AddScripts { scripthashes, min_values }));
        }

        if !self.outpoints.is_empty() {
            let outpoints = self
                .outpoints
                .iter()
                .map(|(t, v)| pb::Outpoint { txid: t.to_vec(), vout: *v })
                .collect();
            out.push(Msg::AddOutpoints(pb::AddOutpoints { outpoints }));
        }

        if !self.tx_lifecycles.is_empty() {
            let mut by_depth: BTreeMap<u32, Vec<Vec<u8>>> = BTreeMap::new();
            for (txid, ac) in &self.tx_lifecycles {
                let depth = match ac {
                    AutoClose::Never => 0,
                    AutoClose::AtDepth(d) => *d,
                };
                by_depth.entry(depth).or_default().push(txid.to_vec());
            }
            for (auto_close_depth, txids) in by_depth {
                out.push(Msg::AddTransactions(pb::AddTransactions {
                    txids,
                    min_depths: Vec::new(),
                    auto_close_depth,
                }));
            }
        }

        if !self.depth_alarms.is_empty() {
            let mut by_txid: BTreeMap<Txid, Vec<u32>> = BTreeMap::new();
            for (txid, depth) in &self.depth_alarms {
                by_txid.entry(*txid).or_default().push(*depth);
            }
            for (txid, min_depths) in by_txid {
                out.push(Msg::AddTransactions(pb::AddTransactions {
                    txids: vec![txid.to_vec()],
                    min_depths,
                    auto_close_depth: 0,
                }));
            }
        }

        for (descriptor, (gap_limit, start)) in &self.descriptors {
            out.push(Msg::AddDescriptor(pb::AddDescriptor {
                descriptor: descriptor.clone(),
                gap_limit: *gap_limit,
                start: *start,
            }));
        }

        if !self.prefixes.is_empty() {
            let prefixes = self
                .prefixes
                .iter()
                .map(|(bits, prefix)| pb::ScriptPrefix { prefix: prefix.clone(), bits: *bits })
                .collect();
            out.push(Msg::AddScriptPrefixes(pb::AddScriptPrefixes { prefixes }));
        }

        out
    }

    /// Render the whole net watch-set as a single `SetWatchSet` snapshot — the
    /// atomic-replace payload [`reload`](ResilientWatch::reload) sends. Unlike
    /// [`control_messages`](Self::control_messages) (a fresh-stream replay) or a
    /// `reconcile_to` delta, this is the COMPLETE desired membership in one
    /// message: the server reconciles it under its lock by effective coverage, so
    /// there is no client-computed Add*/Remove* ordering to strand coverage or
    /// over-charge at quota.
    fn to_set_watch_set(&self) -> pb::SetWatchSet {
        let scripthashes: Vec<Vec<u8>> = self.scripts.keys().map(|h| h.to_vec()).collect();
        let min_values = if self.scripts.values().any(Option::is_some) {
            self.scripts.values().map(|f| f.unwrap_or(0)).collect()
        } else {
            Vec::new()
        };
        pb::SetWatchSet {
            categories: self.categories.unwrap_or(0),
            scripthashes,
            min_values,
            outpoints: self
                .outpoints
                .iter()
                .map(|(t, v)| pb::Outpoint { txid: t.to_vec(), vout: *v })
                .collect(),
            descriptors: self
                .descriptors
                .iter()
                .map(|(d, (gap_limit, start))| pb::AddDescriptor {
                    descriptor: d.clone(),
                    gap_limit: *gap_limit,
                    start: *start,
                })
                .collect(),
            prefixes: self
                .prefixes
                .iter()
                .map(|(bits, prefix)| pb::ScriptPrefix { prefix: prefix.clone(), bits: *bits })
                .collect(),
            lifecycles: self
                .tx_lifecycles
                .iter()
                .map(|(t, ac)| pb::WatchLifecycle {
                    txid: t.to_vec(),
                    auto_close_depth: match ac {
                        AutoClose::Never => 0,
                        AutoClose::AtDepth(d) => *d,
                    },
                })
                .collect(),
            depth_alarms: self
                .depth_alarms
                .iter()
                .map(|(t, d)| pb::WatchDepthAlarm { txid: t.to_vec(), depth: *d })
                .collect(),
        }
    }

    /// Compute the minimal control messages that transform `self` (the current
    /// net watch-set) into `target`, plus item counts — the delta a
    /// [`reload`](ResilientWatch::reload) applies on the live wire. Only the
    /// differences are emitted: items present-and-equal in both are left alone,
    /// so the stream is never cleared and rebuilt. `Remove*`/`RemoveDescriptor`
    /// lead (after any category change) so a removal frees its quota unit before
    /// the replacement `Add*` claims it — a swap at quota would otherwise have its
    /// net-new adds silently rejected while the removes still applied. See the
    /// ordering note at the tail of this function for the full rationale. A
    /// descriptor whose window changed is one `AddDescriptor` (the server
    /// reconciles the slid window); a descriptor that disappeared is a
    /// `RemoveDescriptor`.
    fn reconcile_to(&self, target: &WatchSetMirror) -> (Vec<Msg>, ReloadCounts) {
        let mut lead = Vec::new();
        let mut adds = Vec::new();
        let mut removes = Vec::new();
        let mut c = ReloadCounts::default();

        // Category filter (not a watch *item*, so it does not move the counts).
        // `None` and `Some(0)` both mean "all categories" — the wire spells "all"
        // as `SetCategories { categories: 0 }` (both carriers map 0 → u32::MAX).
        // Compare the *effective* masks, not the raw `Option`: a reload that
        // relaxes the filter (`Some(n)` → truth has no filter) must emit an
        // explicit `SetCategories { 0 }` reset, or the mirror would adopt "no
        // filter" while the live server stayed filtered until the next reconnect,
        // silently dropping the now-in-scope events. A no-op `None` ↔ `Some(0)`
        // change emits nothing.
        let target_mask = target.categories.unwrap_or(0);
        let live_mask = self.categories.unwrap_or(0);
        if target_mask != live_mask {
            lead.push(Msg::SetCategories(pb::SetCategories { categories: target_mask }));
        }

        // Scripts: new or changed-floor → AddScripts; vanished → RemoveScripts.
        {
            let mut changed: Vec<(Scripthash, Option<u64>)> = Vec::new();
            for (h, floor) in &target.scripts {
                match self.scripts.get(h) {
                    Some(f) if f == floor => c.unchanged += 1,
                    _ => changed.push((*h, *floor)),
                }
            }
            let gone: Vec<Scripthash> =
                self.scripts.keys().filter(|h| !target.scripts.contains_key(*h)).copied().collect();
            if !changed.is_empty() {
                c.added += changed.len();
                let scripthashes = changed.iter().map(|(h, _)| h.to_vec()).collect();
                let min_values = if changed.iter().any(|(_, f)| f.is_some()) {
                    changed.iter().map(|(_, f)| f.unwrap_or(0)).collect()
                } else {
                    Vec::new()
                };
                adds.push(Msg::AddScripts(pb::AddScripts { scripthashes, min_values }));
            }
            if !gone.is_empty() {
                c.removed += gone.len();
                removes.push(Msg::RemoveScripts(pb::RemoveScripts {
                    scripthashes: gone.iter().map(|h| h.to_vec()).collect(),
                }));
            }
        }

        // Outpoints.
        {
            let add: Vec<_> = target.outpoints.difference(&self.outpoints).copied().collect();
            let gone: Vec<_> = self.outpoints.difference(&target.outpoints).copied().collect();
            c.unchanged += target.outpoints.intersection(&self.outpoints).count();
            if !add.is_empty() {
                c.added += add.len();
                adds.push(Msg::AddOutpoints(pb::AddOutpoints {
                    outpoints: add.iter().map(|(t, v)| pb::Outpoint { txid: t.to_vec(), vout: *v }).collect(),
                }));
            }
            if !gone.is_empty() {
                c.removed += gone.len();
                removes.push(Msg::RemoveOutpoints(pb::RemoveOutpoints {
                    outpoints: gone.iter().map(|(t, v)| pb::Outpoint { txid: t.to_vec(), vout: *v }).collect(),
                }));
            }
        }

        // Tx lifecycles: new or changed auto-close → AddTransactions (grouped by
        // depth, empty min_depths); vanished → RemoveTransactions (lifecycle).
        {
            let mut by_depth: BTreeMap<u32, Vec<Vec<u8>>> = BTreeMap::new();
            for (txid, ac) in &target.tx_lifecycles {
                match self.tx_lifecycles.get(txid) {
                    Some(old) if old == ac => c.unchanged += 1,
                    _ => {
                        let depth = match ac {
                            AutoClose::Never => 0,
                            AutoClose::AtDepth(d) => *d,
                        };
                        by_depth.entry(depth).or_default().push(txid.to_vec());
                        c.added += 1;
                    }
                }
            }
            for (auto_close_depth, txids) in by_depth {
                adds.push(Msg::AddTransactions(pb::AddTransactions {
                    txids,
                    min_depths: Vec::new(),
                    auto_close_depth,
                }));
            }
            let gone: Vec<Vec<u8>> = self
                .tx_lifecycles
                .keys()
                .filter(|t| !target.tx_lifecycles.contains_key(*t))
                .map(|t| t.to_vec())
                .collect();
            if !gone.is_empty() {
                c.removed += gone.len();
                removes.push(Msg::RemoveTransactions(pb::RemoveTransactions {
                    txids: gone,
                    min_depths: Vec::new(),
                }));
            }
        }

        // Depth alarms, grouped per txid (non-empty min_depths marks the kind).
        {
            let add: Vec<_> = target.depth_alarms.difference(&self.depth_alarms).copied().collect();
            let gone: Vec<_> = self.depth_alarms.difference(&target.depth_alarms).copied().collect();
            c.unchanged += target.depth_alarms.intersection(&self.depth_alarms).count();
            if !add.is_empty() {
                c.added += add.len();
                let mut by_txid: BTreeMap<Txid, Vec<u32>> = BTreeMap::new();
                for (t, d) in add {
                    by_txid.entry(t).or_default().push(d);
                }
                for (txid, min_depths) in by_txid {
                    adds.push(Msg::AddTransactions(pb::AddTransactions {
                        txids: vec![txid.to_vec()],
                        min_depths,
                        auto_close_depth: 0,
                    }));
                }
            }
            if !gone.is_empty() {
                c.removed += gone.len();
                let mut by_txid: BTreeMap<Txid, Vec<u32>> = BTreeMap::new();
                for (t, d) in gone {
                    by_txid.entry(t).or_default().push(d);
                }
                for (txid, min_depths) in by_txid {
                    removes.push(Msg::RemoveTransactions(pb::RemoveTransactions {
                        txids: vec![txid.to_vec()],
                        min_depths,
                    }));
                }
            }
        }

        // Descriptors: new or changed window → AddDescriptor (server reconciles);
        // vanished → RemoveDescriptor.
        {
            for (d, win) in &target.descriptors {
                match self.descriptors.get(d) {
                    Some(old) if old == win => c.unchanged += 1,
                    _ => {
                        c.added += 1;
                        adds.push(Msg::AddDescriptor(pb::AddDescriptor {
                            descriptor: d.clone(),
                            gap_limit: win.0,
                            start: win.1,
                        }));
                    }
                }
            }
            for d in self.descriptors.keys() {
                if !target.descriptors.contains_key(d) {
                    c.removed += 1;
                    removes.push(Msg::RemoveDescriptor(pb::RemoveDescriptor { descriptor: d.clone() }));
                }
            }
        }

        // Prefix buckets.
        {
            let add: Vec<_> = target.prefixes.difference(&self.prefixes).cloned().collect();
            let gone: Vec<_> = self.prefixes.difference(&target.prefixes).cloned().collect();
            c.unchanged += target.prefixes.intersection(&self.prefixes).count();
            if !add.is_empty() {
                c.added += add.len();
                adds.push(Msg::AddScriptPrefixes(pb::AddScriptPrefixes {
                    prefixes: add.iter().map(|(bits, p)| pb::ScriptPrefix { prefix: p.clone(), bits: *bits }).collect(),
                }));
            }
            if !gone.is_empty() {
                c.removed += gone.len();
                removes.push(Msg::RemoveScriptPrefixes(pb::RemoveScriptPrefixes {
                    prefixes: gone.iter().map(|(bits, p)| pb::ScriptPrefix { prefix: p.clone(), bits: *bits }).collect(),
                }));
            }
        }

        // Order: category filter, then **Remove* before Add***. A removal frees
        // its quota unit, so a reload that swaps N watches for N disjoint ones
        // fits even when the tenant is exactly at quota. The opposite order
        // (Add* first) is a false promise at quota: the server has no per-message
        // ack and silently drops a quota-over add without closing the stream, so
        // the net-new adds would be rejected, the removes would then apply, and
        // the mirror would adopt a target the server never registered — a
        // permanent silent divergence until the next reconnect. Remove-first
        // cannot regress coverage of any still-wanted item: `reconcile_to` only
        // removes items *absent* from the target, and no concrete watch key is
        // ever both removed and added (removes are self-keys-not-in-target, adds
        // are target-keys). The lone exception is a single scripthash that
        // changes *mechanism* across the reload (a direct add becoming
        // descriptor-covered, or vice versa) — invisible to this key-level diff,
        // so it briefly unwatches between the RemoveScripts and the AddDescriptor.
        // That sub-millisecond gap on a rare manual-reload transition is the
        // deliberate trade for eliminating the permanent-divergence failure.
        lead.extend(removes);
        lead.extend(adds);
        (lead, c)
    }
}

/// Item counts from a [`reconcile_to`](WatchSetMirror::reconcile_to) diff.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ReloadCounts {
    added: usize,
    removed: usize,
    unchanged: usize,
}

/// The canonical watch-set declared by a [`watch_set_loader`] on every
/// (re)connect. It is a thin recording facade over a fresh [`WatchSetMirror`]:
/// each `add_*` / [`set_categories`](Self::set_categories) call records interest
/// the way the matching [`ResilientWatch`] method would, so the populated set
/// renders to exactly the same control messages a manual replay would. The
/// wrapper adopts the builder's set as the mirror once the loader returns, then
/// re-registers it and re-anchors as usual.
///
/// Only declarative `add_*` methods are exposed (no `remove_*`): the loader
/// builds a complete set from the integrator's source-of-truth into an empty
/// mirror, where a removal has nothing to act on. Methods are synchronous —
/// they only record — so a loader does its own `await`ing against its truth
/// (DB, config, upstream service) between calls.
///
/// [`watch_set_loader`]: ResilientWatchConfig::watch_set_loader
pub struct WatchSetBuilder {
    mirror: Arc<Mutex<WatchSetMirror>>,
}

impl WatchSetBuilder {
    fn with(&self, f: impl FnOnce(&mut WatchSetMirror)) {
        // The mutex is only contended if a loader clones the builder across
        // tasks; a poisoned lock means a prior loader panicked mid-build — recover
        // the inner mirror rather than propagating the panic into the reconnect.
        let mut m = self.mirror.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut m);
    }

    /// Declare scripthashes (each `sha256(scriptPubKey)`) with an optional
    /// per-script `min_value` floor. See [`ResilientWatch::add_scripts`].
    pub fn add_scripts(&self, items: impl IntoIterator<Item = (Scripthash, Option<u64>)>) {
        let items: Vec<_> = items.into_iter().collect();
        self.with(|m| m.add_scripts(&items));
    }

    /// Declare outpoints (`txid:vout`). See [`ResilientWatch::add_outpoints`].
    pub fn add_outpoints(&self, outpoints: impl IntoIterator<Item = (Txid, u32)>) {
        let items: Vec<_> = outpoints.into_iter().collect();
        self.with(|m| m.add_outpoints(&items));
    }

    /// Declare lifecycle watches on txids. See [`ResilientWatch::add_tx_lifecycle`].
    pub fn add_tx_lifecycle(&self, txids: impl IntoIterator<Item = Txid>, auto_close: AutoClose) {
        let txids: Vec<_> = txids.into_iter().collect();
        if txids.is_empty() {
            return;
        }
        self.with(|m| m.add_tx_lifecycle(&txids, auto_close));
    }

    /// Arm single-shot depth alarms over the cross product of `txids` and
    /// `depths` (depths `< 1` dropped). See [`ResilientWatch::add_depth_alarms`].
    pub fn add_depth_alarms(
        &self,
        txids: impl IntoIterator<Item = Txid>,
        depths: impl IntoIterator<Item = u32>,
    ) {
        let txids: Vec<_> = txids.into_iter().collect();
        let depths: Vec<u32> = depths.into_iter().filter(|d| *d >= 1).collect();
        if txids.is_empty() || depths.is_empty() {
            return;
        }
        let pairs = cross_product(&txids, &depths);
        self.with(|m| m.add_depth_alarms(&pairs));
    }

    /// Declare a public output descriptor's `(gap_limit, start)` watch window.
    /// See [`ResilientWatch::add_descriptor`].
    pub fn add_descriptor(&self, descriptor: impl Into<String>, gap_limit: u32, start: u32) {
        let descriptor = descriptor.into();
        self.with(|m| m.add_descriptor(descriptor, gap_limit, start));
    }

    /// Declare script-prefix buckets (validated client-side, same as the live
    /// path). An invalid `(prefix, bits)` aborts the load with
    /// [`StreamError::InvalidArgument`], which the loader propagates as a
    /// (retryable) loader failure. See [`ResilientWatch::add_script_prefixes`].
    pub fn add_script_prefixes(
        &self,
        prefixes: impl IntoIterator<Item = (Vec<u8>, u32)>,
    ) -> Result<(), StreamError> {
        let validated = validate_prefixes(prefixes)?;
        if validated.is_empty() {
            return Ok(());
        }
        self.with(|m| m.add_prefixes(&validated));
        Ok(())
    }

    /// Declare the live category filter. See [`ResilientWatch::set_categories`].
    pub fn set_categories(&self, categories: u32) {
        self.with(|m| m.set_categories(categories));
    }

    /// Declare the raw-tx opt-in. See
    /// [`ResilientWatch::set_watch_options`]. A loader that wants
    /// `raw_tx` on ScriptMatched must re-declare this each rebuild, exactly like
    /// [`set_categories`](Self::set_categories) — the loader is canonical.
    pub fn set_watch_options(&self, include_raw_tx: bool) {
        self.with(|m| m.set_watch_options(include_raw_tx));
    }
}

/// Knobs for [`StreamClient::resilient_watch`]. Reuses the [`Backoff`] and
/// [`CursorStore`] from the [`ResilientSubscription`](crate::ResilientSubscription)
/// resilience layer.
pub struct ResilientWatchConfig {
    /// Reconnect (and re-anchor-retry) backoff schedule.
    pub backoff: Backoff,
    /// Where the resume cursor is persisted across reconnects and restarts.
    pub cursor_store: Arc<dyn CursorStore>,
    /// Initial resume anchor used on the first connect when the store is empty.
    pub from_cursor: Option<Cursor>,
    /// Optional canonical watch-set loader. When set, it is run on every
    /// (re)connect to rebuild the watch-set from the integrator's
    /// source-of-truth (see [`watch_set_loader`](Self::watch_set_loader)).
    pub(crate) watch_set_loader: Option<Arc<WatchSetLoaderFn>>,
}

impl Default for ResilientWatchConfig {
    fn default() -> Self {
        ResilientWatchConfig {
            backoff: Backoff::default(),
            cursor_store: Arc::new(NoopCursorStore),
            from_cursor: None,
            watch_set_loader: None,
        }
    }
}

impl std::fmt::Debug for ResilientWatchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResilientWatchConfig")
            .field("backoff", &self.backoff)
            .field("cursor_store", &"<dyn CursorStore>")
            .field("from_cursor", &self.from_cursor)
            .field("watch_set_loader", &self.watch_set_loader.as_ref().map(|_| "<loader>"))
            .finish()
    }
}

impl ResilientWatchConfig {
    /// Start from the defaults (forever-retry backoff, no persistence, no
    /// initial cursor).
    pub fn new() -> Self {
        Self::default()
    }

    /// Persist the resume cursor through `store`.
    pub fn cursor_store(mut self, store: Arc<dyn CursorStore>) -> Self {
        self.cursor_store = store;
        self
    }

    /// Override the reconnect / re-anchor-retry backoff.
    pub fn backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Seed the first connect's resume anchor (used only when the store has no
    /// persisted cursor).
    pub fn from_cursor(mut self, cursor: Cursor) -> Self {
        self.from_cursor = Some(cursor);
        self
    }

    /// Install a canonical watch-set loader for integrators whose watch-set has
    /// a durable source-of-truth (a DB, a config file, an upstream service)
    /// outside the wrapper.
    ///
    /// Without a loader, [`ResilientWatch`] re-registers its in-memory mirror of
    /// the `add_*` / `remove_*` calls made through it — correct when the
    /// watch-set is built once at startup and never drifts, but the mirror is
    /// empty after a process restart and goes stale if the truth changes while
    /// the stream is down. With a loader, the mirror is treated as a *cache* of
    /// the external truth:
    ///
    /// - The loader runs once after **every** successful (re)connect, **before**
    ///   the consumer's event stream resumes — so the first events pumped after
    ///   a reconnect already land on a fully-populated subscription. It receives
    ///   a fresh [`WatchSetBuilder`] and declares the canonical set into it
    ///   (typically by querying its truth with its own `await`s between calls).
    /// - On return, the builder's set **replaces** the mirror: it is canonical.
    ///   In-process `add_*` / `remove_*` calls still mutate the mirror and send
    ///   live, but the next reconnect re-derives the set from the loader, so the
    ///   integrator's truth — not the accumulated in-process edits — is the
    ///   record across reconnects (this is what closes the restart-loses-mirror
    ///   and truth-drift-during-disconnect gaps).
    /// - A loader error is **transient**: it maps to
    ///   [`StreamError::WatchSetLoader`], which the reconnect loop backs off and
    ///   retries on the next connect rather than surfacing — a momentary failure
    ///   of the integrator's truth must not crash a consumer whose contract is
    ///   at-least-once. A *permanent* loader error (a config typo, a closure that
    ///   always fails) is indistinguishable from a transient one and so is retried
    ///   indefinitely: with the default backoff (`max_retries: None`) the stream
    ///   never resumes and [`next`](ResilientWatch::next) simply never yields.
    ///   Set [`Backoff::max_retries`](crate::Backoff::max_retries) if you need a
    ///   permanently-failing loader to surface a terminal error instead of
    ///   retrying forever. The loader should return `Err` rather than panic — a
    ///   panic unwinds through the reconnect and aborts the current `next()`; it
    ///   is not caught.
    ///
    /// The resume cursor is independent of the watch-set: it still comes from the
    /// [`cursor_store`](Self::cursor_store) / [`from_cursor`](Self::from_cursor)
    /// and the re-anchor runs after the loaded set is registered, exactly as
    /// without a loader.
    ///
    /// ```no_run
    /// # use satd_events_client::{ResilientWatchConfig, WatchSetBuilder};
    /// # async fn rows() -> Result<Vec<([u8; 32], Option<u64>)>, Box<dyn std::error::Error + Send + Sync>> { Ok(vec![]) }
    /// let config = ResilientWatchConfig::new().watch_set_loader(|builder: WatchSetBuilder| async move {
    ///     // Query the durable source-of-truth and declare the canonical set.
    ///     let scripts = rows().await?;
    ///     builder.add_scripts(scripts);
    ///     Ok(())
    /// });
    /// # let _ = config;
    /// ```
    pub fn watch_set_loader<F, Fut>(mut self, loader: F) -> Self
    where
        F: Fn(WatchSetBuilder) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), BoxError>> + Send + 'static,
    {
        self.watch_set_loader = Some(Arc::new(move |b| Box::pin(loader(b))));
        self
    }
}

/// The outcome of [`ResilientWatch::reload`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReloadSummary {
    /// Watch items added or changed (a changed floor / descriptor window / tx
    /// auto-close counts as added).
    pub added: usize,
    /// Watch items removed.
    pub removed: usize,
    /// Watch items present and identical in both the old and reloaded set.
    pub unchanged: usize,
    /// Whether the delta was sent on the live stream now (`true`), or deferred to
    /// the next reconnect's loader because the stream was down — or dropped
    /// mid-reload (`false`). When `false` the mirror still reflects the reloaded
    /// set, so the pending reconnect re-registers it from the same loader.
    pub applied: bool,
}

/// Why a [`ResilientWatch::reload`] could not run.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    /// `reload` requires a [`watch_set_loader`](ResilientWatchConfig::watch_set_loader);
    /// none was configured.
    #[error("reload requires a watch_set_loader, but none is configured")]
    NoLoader,
    /// The loader itself returned an error. Unlike a connect-time loader failure
    /// (which is retried on reconnect), an explicit `reload` surfaces it so the
    /// caller decides whether to retry.
    #[error("watch-set loader failed: {0}")]
    Loader(#[source] BoxError),
}

/// A transient-reject re-anchor retry deferred out of [`handle_event`] so it can
/// be driven — and cancelled — safely from [`ResilientWatch::next`]. Recording
/// the retry as data (rather than sleeping + re-sending inline) is what makes
/// `next` cancel-safe: the budget counter is charged once when the retry is
/// recorded, and the pending slot is only cleared after the re-send has been
/// attempted, so a cancelled `next` re-enters and completes the *same* retry
/// instead of burning the counter without the re-send reaching the wire.
///
/// Only the backoff *deadline* is captured — the drive re-sends the *live*
/// `desired_cursor`, so an intervening [`set_cursor`](ResilientWatch::set_cursor)
/// (or a connect that re-anchors from `resume`) is honoured rather than
/// clobbered by a stale snapshot.
///
/// [`handle_event`]: ResilientWatch::handle_event
#[derive(Clone, Copy)]
struct PendingReanchor {
    /// When the backoff sleep ends. Stored as an absolute deadline (not a
    /// duration) so a cancelled-then-resumed drive waits out the *remaining*
    /// backoff rather than restarting it.
    deadline: tokio::time::Instant,
}

/// A `Watch` stream that reconnects, re-registers its watch-set, and re-anchors
/// off the deterministic [`Event::CursorAccepted`] / [`Event::CursorRejected`]
/// results on the caller's behalf.
///
/// Construct it with [`StreamClient::resilient_watch`]. Register interest with
/// the typed `add_*` / `remove_*` / [`set_categories`](Self::set_categories)
/// methods (which both update the mirror and, while connected, send live), then
/// drive it by calling [`next`](Self::next) in a loop. The model is
/// single-task, like [`ResilientSubscription`](crate::ResilientSubscription):
/// interleave watch-set edits with [`next`](Self::next) calls from one task
/// (the [`descriptor_wallet`] usage shape — react to a match, then adjust the
/// watch-set). When the watch-set has a durable source-of-truth, configure a
/// [`watch_set_loader`](ResilientWatchConfig::watch_set_loader) and call
/// [`reload`](Self::reload) to realign the live stream with that truth on demand.
///
/// [`descriptor_wallet`]: https://github.com/epochbtc/satd/blob/master/satd-events-client/examples/descriptor_wallet.rs
pub struct ResilientWatch {
    client: StreamClient,
    config: ResilientWatchConfig,
    mirror: WatchSetMirror,
    /// Live control handle + event stream when connected; `None` when between
    /// connections (edits land in the mirror and replay on the next connect).
    handle: Option<WatchHandle>,
    stream: Option<EventStream>,
    /// Confirmed high-water cursor; the anchor a (re)connect re-anchors to.
    resume: Option<Cursor>,
    /// The cursor most recently requested via `set_cursor` (or the connect-time
    /// re-anchor), re-sent if a transient reject asks us to retry.
    desired_cursor: Option<Cursor>,
    /// High-water armed for commit on the next poll (commit-on-poll).
    commit_next: Option<Cursor>,
    /// The cursor last written to the store (skips redundant writes).
    committed: Option<Cursor>,
    /// Whether `seed_resume` has run (resume may legitimately stay `None`).
    seeded: bool,
    /// Consecutive reconnects that produced no event; drives backoff + give-up.
    reconnect_attempts: u32,
    /// Consecutive transient re-anchor rejects; drives the in-place retry backoff.
    reanchor_attempts: u32,
    /// A deferred transient-reject retry awaiting its backoff + re-send, driven by
    /// [`next`](Self::next). `Some` between recording the retry (in `handle_event`)
    /// and completing it; keeping it in `self` rather than on `next`'s stack is
    /// what lets a cancelled `next` resume the retry (see [`PendingReanchor`]).
    pending_reanchor: Option<PendingReanchor>,
    /// The most recent retryable error, surfaced if `max_retries` is exhausted.
    last_error: Option<StreamError>,
}

impl ResilientWatch {
    pub(crate) fn new(client: StreamClient, config: ResilientWatchConfig) -> Self {
        ResilientWatch {
            client,
            config,
            mirror: WatchSetMirror::default(),
            handle: None,
            stream: None,
            resume: None,
            desired_cursor: None,
            commit_next: None,
            committed: None,
            seeded: false,
            reconnect_attempts: 0,
            reanchor_attempts: 0,
            pending_reanchor: None,
            last_error: None,
        }
    }

    // --- watch-set registration (mirror + live send) --------------------------

    /// Add scripthashes (each `sha256(scriptPubKey)`) with an optional per-script
    /// `min_value` floor. See [`WatchHandle::add_scripts`].
    pub async fn add_scripts(
        &mut self,
        items: impl IntoIterator<Item = (Scripthash, Option<u64>)>,
    ) -> Result<(), StreamError> {
        let items: Vec<_> = items.into_iter().collect();
        if items.is_empty() {
            return Ok(());
        }
        self.mirror.add_scripts(&items);
        let res = match &self.handle {
            Some(h) => Some(h.add_scripts(items).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Remove scripthashes from the watch-set. See [`WatchHandle::remove_scripts`].
    pub async fn remove_scripts(
        &mut self,
        hashes: impl IntoIterator<Item = Scripthash>,
    ) -> Result<(), StreamError> {
        let hashes: Vec<_> = hashes.into_iter().collect();
        if hashes.is_empty() {
            return Ok(());
        }
        self.mirror.remove_scripts(&hashes);
        let res = match &self.handle {
            Some(h) => Some(h.remove_scripts(hashes).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Add outpoints (`txid:vout`). See [`WatchHandle::add_outpoints`].
    pub async fn add_outpoints(
        &mut self,
        outpoints: impl IntoIterator<Item = (Txid, u32)>,
    ) -> Result<(), StreamError> {
        let items: Vec<_> = outpoints.into_iter().collect();
        if items.is_empty() {
            return Ok(());
        }
        self.mirror.add_outpoints(&items);
        let res = match &self.handle {
            Some(h) => Some(h.add_outpoints(items).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Remove outpoints. See [`WatchHandle::remove_outpoints`].
    pub async fn remove_outpoints(
        &mut self,
        outpoints: impl IntoIterator<Item = (Txid, u32)>,
    ) -> Result<(), StreamError> {
        let items: Vec<_> = outpoints.into_iter().collect();
        if items.is_empty() {
            return Ok(());
        }
        self.mirror.remove_outpoints(&items);
        let res = match &self.handle {
            Some(h) => Some(h.remove_outpoints(items).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Add lifecycle watches on txids. See [`WatchHandle::add_tx_lifecycle`].
    pub async fn add_tx_lifecycle(
        &mut self,
        txids: impl IntoIterator<Item = Txid>,
        auto_close: AutoClose,
    ) -> Result<(), StreamError> {
        let txids: Vec<_> = txids.into_iter().collect();
        if txids.is_empty() {
            return Ok(());
        }
        self.mirror.add_tx_lifecycle(&txids, auto_close);
        let res = match &self.handle {
            Some(h) => Some(h.add_tx_lifecycle(txids, auto_close).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Remove lifecycle watches. See [`WatchHandle::remove_tx_lifecycle`].
    pub async fn remove_tx_lifecycle(
        &mut self,
        txids: impl IntoIterator<Item = Txid>,
    ) -> Result<(), StreamError> {
        let txids: Vec<_> = txids.into_iter().collect();
        if txids.is_empty() {
            return Ok(());
        }
        self.mirror.remove_tx_lifecycle(&txids);
        let res = match &self.handle {
            Some(h) => Some(h.remove_tx_lifecycle(txids).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Arm single-shot depth alarms over the cross product of `txids` and
    /// `depths` (depths `< 1` dropped). See [`WatchHandle::add_depth_alarms`].
    pub async fn add_depth_alarms(
        &mut self,
        txids: impl IntoIterator<Item = Txid>,
        depths: impl IntoIterator<Item = u32>,
    ) -> Result<(), StreamError> {
        let txids: Vec<_> = txids.into_iter().collect();
        let depths: Vec<u32> = depths.into_iter().filter(|d| *d >= 1).collect();
        if txids.is_empty() || depths.is_empty() {
            return Ok(());
        }
        let pairs = cross_product(&txids, &depths);
        self.mirror.add_depth_alarms(&pairs);
        let res = match &self.handle {
            Some(h) => Some(h.add_depth_alarms(txids, depths).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Remove depth alarms over the cross product of `txids` and `depths`.
    /// See [`WatchHandle::remove_depth_alarms`].
    pub async fn remove_depth_alarms(
        &mut self,
        txids: impl IntoIterator<Item = Txid>,
        depths: impl IntoIterator<Item = u32>,
    ) -> Result<(), StreamError> {
        let txids: Vec<_> = txids.into_iter().collect();
        let depths: Vec<u32> = depths.into_iter().filter(|d| *d >= 1).collect();
        if txids.is_empty() || depths.is_empty() {
            return Ok(());
        }
        let pairs = cross_product(&txids, &depths);
        self.mirror.remove_depth_alarms(&pairs);
        let res = match &self.handle {
            Some(h) => Some(h.remove_depth_alarms(txids, depths).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Register a public output descriptor's watch window. The latest
    /// `(gap_limit, start)` per descriptor is what replays on reconnect — advance
    /// `start` to slide the window (the server reconciles the slid window). See
    /// [`WatchHandle::add_descriptor`].
    pub async fn add_descriptor(
        &mut self,
        descriptor: impl Into<String>,
        gap_limit: u32,
        start: u32,
    ) -> Result<(), StreamError> {
        let descriptor = descriptor.into();
        self.mirror.add_descriptor(descriptor.clone(), gap_limit, start);
        let res = match &self.handle {
            Some(h) => Some(h.add_descriptor(descriptor, gap_limit, start).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Remove a descriptor previously added with [`add_descriptor`](Self::add_descriptor),
    /// dropping it from the mirror so it is not replayed on reconnect and (while
    /// connected) releasing the scripthashes its window contributed whose last
    /// owner this drops. See [`WatchHandle::remove_descriptor`].
    pub async fn remove_descriptor(
        &mut self,
        descriptor: impl Into<String>,
    ) -> Result<(), StreamError> {
        let descriptor = descriptor.into();
        self.mirror.remove_descriptor(&descriptor);
        let res = match &self.handle {
            Some(h) => Some(h.remove_descriptor(descriptor).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Add script-prefix buckets (validated client-side). See
    /// [`WatchHandle::add_script_prefixes`].
    pub async fn add_script_prefixes(
        &mut self,
        prefixes: impl IntoIterator<Item = (Vec<u8>, u32)>,
    ) -> Result<(), StreamError> {
        let validated = validate_prefixes(prefixes)?;
        if validated.is_empty() {
            return Ok(());
        }
        self.mirror.add_prefixes(&validated);
        let res = match &self.handle {
            Some(h) => Some(
                h.send_control(pb::SubscribeControl {
                    msg: Some(Msg::AddScriptPrefixes(pb::AddScriptPrefixes {
                        prefixes: validated,
                    })),
                })
                .await,
            ),
            None => None,
        };
        self.after_send(res)
    }

    /// Remove script-prefix buckets. See [`WatchHandle::remove_script_prefixes`].
    pub async fn remove_script_prefixes(
        &mut self,
        prefixes: impl IntoIterator<Item = (Vec<u8>, u32)>,
    ) -> Result<(), StreamError> {
        let validated = validate_prefixes(prefixes)?;
        if validated.is_empty() {
            return Ok(());
        }
        self.mirror.remove_prefixes(&validated);
        let res = match &self.handle {
            Some(h) => Some(
                h.send_control(pb::SubscribeControl {
                    msg: Some(Msg::RemoveScriptPrefixes(pb::RemoveScriptPrefixes {
                        prefixes: validated,
                    })),
                })
                .await,
            ),
            None => None,
        };
        self.after_send(res)
    }

    /// Adjust the live firehose category bitfield (see
    /// [`Categories`](crate::Categories)). Replayed on reconnect.
    pub async fn set_categories(&mut self, categories: u32) -> Result<(), StreamError> {
        self.mirror.set_categories(categories);
        let res = match &self.handle {
            Some(h) => Some(h.set_categories(categories).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Set the per-stream raw-tx opt-in (see
    /// [`StreamControls::set_watch_options`](crate::WatchControls::set_watch_options)).
    /// With `include_raw_tx = true`, [`Event::ScriptMatched`](crate::Event::ScriptMatched)
    /// carry the full serialized tx in `raw_tx`. Recorded in the mirror and
    /// re-applied on every reconnect, so the opt-in survives a stream tear-down.
    pub async fn set_watch_options(&mut self, include_raw_tx: bool) -> Result<(), StreamError> {
        self.mirror.set_watch_options(include_raw_tx);
        let res = match &self.handle {
            Some(h) => Some(h.set_watch_options(include_raw_tx).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Request a mid-stream re-anchor to `cursor` (replay confirmed history from
    /// it). The outcome arrives in-band on [`next`](Self::next) as
    /// [`Event::CursorAccepted`] / [`Event::CursorRejected`]; transient rejects
    /// are retried in place automatically.
    pub async fn set_cursor(&mut self, cursor: Cursor) -> Result<(), StreamError> {
        self.desired_cursor = Some(cursor);
        self.reanchor_attempts = 0;
        // This live send is the fresh re-anchor; it supersedes any deferred
        // transient-reject retry, so drop the pending slot rather than let `next`
        // fire a redundant second `set_cursor` for the same anchor afterwards.
        self.pending_reanchor = None;
        let res = match &self.handle {
            Some(h) => Some(h.set_cursor(cursor).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Request a bounded historical rescan of the current watch-set over the
    /// inclusive height range `[from_height, to_height]` (see
    /// [`WatchHandle::rescan`](crate::WatchHandle::rescan)). The ack and any
    /// matches arrive in-band on [`next`](Self::next): [`Event::RescanAccepted`]
    /// → confirmed matches (height order) → [`Event::RescanComplete`], or
    /// [`Event::RescanRejected`].
    ///
    /// Unlike [`set_cursor`](Self::set_cursor), a rescan touches **no** resilient
    /// state: it is a side query, orthogonal to the watch-set mirror and the
    /// resume cursor, so it is neither replayed on reconnect nor retried in
    /// place. If the stream drops mid-rescan, re-issue it after reconnect. With
    /// the stream currently down this is a no-op returning `Ok(())`.
    pub async fn rescan(&mut self, from_height: u32, to_height: u32) -> Result<(), StreamError> {
        let res = match &self.handle {
            Some(h) => Some(h.rescan(from_height, to_height).await),
            None => None,
        };
        self.after_send(res)
    }

    /// Re-run the configured [`watch_set_loader`](ResilientWatchConfig::watch_set_loader),
    /// diff the freshly-loaded canonical set against the live watch-set, and apply
    /// **only the delta** on the wire — realigning the subscription with the
    /// integrator's source-of-truth without dropping and rebuilding the stream
    /// (which would throw away the backoff / cursor re-anchor plumbing).
    ///
    /// This is the on-demand companion to the connect-time loader (which fires on
    /// every reconnect, [`watch_set_loader`](ResilientWatchConfig::watch_set_loader)):
    /// use it when the durable truth changes *while the stream is up* and you want
    /// it pushed now — a bulk import or migration that wrote truth outside the
    /// hot-add path, an admin/external rotation, or an operator "make the wire
    /// match truth" reconciliation.
    ///
    /// Semantics:
    ///
    /// - **Diff, not blast.** Only added/changed/removed items are sent;
    ///   identical items are untouched. `Remove*` / `RemoveDescriptor` lead so a
    ///   removal frees its quota unit before the replacement `Add*` claims it —
    ///   which is what lets a swap of N watches for N disjoint ones apply cleanly
    ///   even when the tenant is exactly at quota (the server silently drops a
    ///   quota-over add, so an add-first order would leave the mirror claiming
    ///   watches the server never registered). A descriptor whose window changed
    ///   is re-asserted (the server reconciles); a vanished descriptor is dropped
    ///   with `RemoveDescriptor`.
    /// - **Atomic w.r.t. concurrent edits.** `&mut self` serializes `reload`
    ///   against `add_*` / `remove_*` / [`next`](Self::next), so no hot-add can
    ///   interleave with the diff.
    /// - **The reloaded set becomes the mirror.** Subsequent reconnects replay it
    ///   (and re-run the loader), exactly as for the connect-time path.
    /// - **Disconnected (or dropped mid-reload) defers, never errors.** With the
    ///   stream down there is nothing to apply now; the mirror is still updated to
    ///   the reloaded set and the next reconnect's loader re-registers it from
    ///   truth. [`ReloadSummary::applied`] reports which happened.
    ///
    /// Returns [`ReloadError::NoLoader`] if no loader is configured, or
    /// [`ReloadError::Loader`] if the loader itself fails (surfaced, not retried —
    /// an explicit `reload` lets the caller decide).
    pub async fn reload(&mut self) -> Result<ReloadSummary, ReloadError> {
        let loader = self.config.watch_set_loader.clone().ok_or(ReloadError::NoLoader)?;
        // Build the canonical set from the integrator's truth into a fresh mirror.
        let shared = Arc::new(Mutex::new(WatchSetMirror::default()));
        loader(WatchSetBuilder { mirror: shared.clone() })
            .await
            .map_err(ReloadError::Loader)?;
        let loaded = std::mem::take(&mut *shared.lock().unwrap_or_else(|p| p.into_inner()));

        // Counts (added/removed/unchanged) for the summary — advisory; the
        // server's WatchSetResult carries the authoritative counts by effective
        // coverage. The delta messages are discarded: reload no longer applies a
        // client-computed Add*/Remove* delta (whose ordering could strand
        // coverage or over-charge at quota — the Rounds 2/3 failures). It sends
        // ONE SetWatchSet and lets the server reconcile atomically under its lock.
        let (_delta, counts) = self.mirror.reconcile_to(&loaded);

        // Push the whole desired set as a single atomic replace if connected; a
        // send failure means the stream is gone, so defer to the reconnect loader
        // rather than erroring. The deterministic WatchSetResult
        // (accepted/rejected) arrives in-band on [`next`](Self::next).
        let mut applied = false;
        if let Some(h) = &self.handle {
            let msg = Msg::SetWatchSet(loaded.to_set_watch_set());
            let set_res = h.send_control(pb::SubscribeControl { msg: Some(msg) }).await;
            // SetWatchSet carries the category filter but NOT the raw-tx opt-in,
            // so reconcile it separately — and in BOTH directions. The reconnect
            // path renders it via `control_messages` on a fresh (default-off)
            // stream, but this atomic-replace path runs against a LIVE stream: if
            // the reloaded truth drops an opt-in the stream still has, we must
            // explicitly turn it off, or the server keeps serializing full txs
            // against the reloaded set until an incidental reconnect. Compare the
            // pre-reload mirror's effective value (None == off) to truth and send
            // only on a real change. Both awaits complete while `h` is borrowed;
            // `teardown` (needs `&mut self`) runs only after.
            let old_raw_tx = self.mirror.include_raw_tx.unwrap_or(false);
            let new_raw_tx = loaded.include_raw_tx.unwrap_or(false);
            let opt_res = match &set_res {
                Ok(()) if old_raw_tx != new_raw_tx => Some(h.set_watch_options(new_raw_tx).await),
                _ => None,
            };
            if set_res.is_ok() && !matches!(opt_res, Some(Err(_))) {
                applied = true;
            } else {
                self.teardown();
            }
        }

        // Adopt the reloaded set as the canonical mirror regardless: a deferred
        // reload is rebuilt from the same loader on the next reconnect.
        self.mirror = loaded;

        Ok(ReloadSummary {
            added: counts.added,
            removed: counts.removed,
            unchanged: counts.unchanged,
            applied,
        })
    }

    // --- driving the stream ---------------------------------------------------

    /// The resume cursor the next reconnect would re-anchor to.
    pub fn resume_cursor(&self) -> Option<&Cursor> {
        self.resume.as_ref()
    }

    /// Persist the most-recently-delivered event's cursor now (rather than on the
    /// implicit ack at the next [`next`](Self::next)). Call before a clean
    /// shutdown. Idempotent; a failing store `save` is surfaced.
    pub fn commit(&mut self) -> Result<(), StreamError> {
        self.commit_due()
    }

    /// Yield the next event, reconnecting, re-registering the watch-set, and
    /// re-anchoring underneath as needed.
    ///
    /// Loops internally: a transport failure becomes a backoff + reconnect +
    /// watch-set replay + `set_cursor` re-anchor, a transient re-anchor reject
    /// becomes a backoff + in-place retry, and only a real event (including the
    /// deterministic `CursorAccepted` / terminal `CursorRejected`, which the
    /// caller may act on) returns.
    ///
    /// # Cancel safety
    ///
    /// `next` is cancel-safe: dropping the future — e.g. losing a
    /// `tokio::select!` race to a command arriving on another branch — never
    /// leaves `self` holding a charged-but-unsent retry or a half-applied cursor,
    /// so it is always safe to call `next` again afterwards. An interleaving
    /// caller (an actor that drives `next` in a `select!` alongside a command
    /// channel) can therefore cancel it freely.
    ///
    /// It suspends at four kinds of await, each of which a cancel leaves either
    /// resumable or idempotent on re-entry:
    ///
    /// - The reconnect **backoff sleep** holds no uncommitted state — the
    ///   `reconnect_attempts` bump happened on a prior iteration, so a cancel just
    ///   re-sleeps the (recomputed) delay next time.
    /// - **`connect()`** only commits the new `handle` / `stream` at its very end;
    ///   a cancel partway drops the half-open stream and re-enters `connect` from
    ///   scratch, which fully rebuilds from `resume` (the resume/commit state it
    ///   touches is either unchanged or re-derived on the retry).
    /// - The transport **`message()` poll** is cancel-safe (its decoder state
    ///   lives on the retained `stream`, not on the dropped future).
    /// - The deferred transient-reject **backoff + re-send** is recorded as
    ///   internal state and driven from here, so a cancel mid-backoff or
    ///   mid-re-send resumes the *same* retry on the next call — with its budget
    ///   charged exactly once — rather than burning the counter without the
    ///   re-send reaching the wire.
    pub async fn next(&mut self) -> Result<Event, StreamError> {
        self.commit_due()?;
        loop {
            // Finish any deferred transient-reject retry before touching the
            // stream. Resumable and cancel-safe (see `drive_pending_reanchor`).
            if self.pending_reanchor.is_some() {
                self.drive_pending_reanchor().await?;
                continue;
            }
            if self.stream.is_none() {
                if self.reconnect_attempts > 0 {
                    if let Some(max) = self.config.backoff.max_retries
                        && self.reconnect_attempts > max
                    {
                        return Err(self.last_error.take().unwrap_or(StreamError::ControlClosed));
                    }
                    let delay = self.config.backoff.delay_for(self.reconnect_attempts - 1);
                    tokio::time::sleep(delay).await;
                }
                match self.connect().await {
                    Ok(()) => {}
                    Err(e) if is_reconnectable(&e) => {
                        self.teardown();
                        self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
                        self.last_error = Some(e);
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }

            let stream = self.stream.as_mut().expect("connected");
            match stream.message().await {
                Ok(Some(ev)) => {
                    self.reconnect_attempts = 0;
                    self.last_error = None;
                    let cur = self.stream.as_ref().and_then(|s| s.cursor().copied());
                    if let Some(out) = self.handle_event(ev, cur).await? {
                        self.arm_commit();
                        return Ok(out);
                    }
                    // Handled internally (a transient re-anchor retry): loop.
                }
                Ok(None) => {
                    self.teardown();
                    self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
                }
                Err(e) if e.is_retryable() => {
                    self.teardown();
                    self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
                    self.last_error = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Process one inbound event. Advances the confirmed high-water, and drives
    /// the re-anchor catch-up off the deterministic results: a transient reject
    /// (`RateLimited` / `ConcurrentReanchor`) is backed off and re-sent in place
    /// (returning `Ok(None)` so [`next`](Self::next) loops); everything else —
    /// including `CursorAccepted` (watch `clamped`) and a terminal reject — is
    /// handed to the caller.
    async fn handle_event(
        &mut self,
        ev: Event,
        cur: Option<Cursor>,
    ) -> Result<Option<Event>, StreamError> {
        if let Some(c) = cur {
            self.resume = Some(c);
        }

        // One-shot watches the server auto-evicts when their terminal event
        // fires: prune the mirror to match, so a reconnect does not re-register
        // an already-fired watch (which would duplicate the terminal
        // notification and burn watch quota on a completed txid). The server
        // emits the *requested* threshold as `depth` (its alarm identity), so it
        // is the exact `(txid, depth)` key to drop; a finalize evicts the whole
        // lifecycle watch for the txid.
        match &ev {
            Event::TxidDepthReached { txid, depth, .. } => {
                if let Ok(t) = <[u8; 32]>::try_from(txid.as_slice()) {
                    self.mirror.remove_depth_alarms(&[(t, *depth)]);
                }
            }
            Event::TxidFinalized { txid, .. } => {
                if let Ok(t) = <[u8; 32]>::try_from(txid.as_slice()) {
                    self.mirror.remove_tx_lifecycle(&[t]);
                }
            }
            _ => {}
        }

        let transient_reject = matches!(
            &ev,
            Event::CursorRejected {
                reason: CursorRejectReason::RateLimited | CursorRejectReason::ConcurrentReanchor,
                ..
            }
        );
        if transient_reject {
            // Bounded in-place retry: back off and re-send the same re-anchor. If
            // we exhaust the retry budget, surface the reject so the caller can
            // escalate rather than spinning forever.
            if let Some(max) = self.config.backoff.max_retries
                && self.reanchor_attempts >= max
            {
                self.reanchor_attempts = 0;
                // Surfacing the reject ends the retry: drop any pending re-send so
                // `next` does not fire one more `set_cursor` after we told the
                // caller the budget is exhausted.
                self.pending_reanchor = None;
                return Ok(Some(ev));
            }
            // Record the retry as resumable state and return; `next` drives the
            // backoff + re-send via `drive_pending_reanchor`. Doing the charge here
            // (synchronously, no await between the budget read and the counter
            // bump) and the awaits there is what makes `next` cancel-safe: a
            // cancelled drive resumes this same retry instead of burning the
            // counter without the re-send landing. The deadline is absolute so a
            // resumed drive waits out only the remaining backoff. Only the deadline
            // is captured — the drive re-sends the live `desired_cursor`.
            let delay = self.config.backoff.delay_for(self.reanchor_attempts);
            self.reanchor_attempts = self.reanchor_attempts.saturating_add(1);
            self.pending_reanchor =
                Some(PendingReanchor { deadline: tokio::time::Instant::now() + delay });
            return Ok(None);
        }

        if let Event::CursorAccepted { from, .. } = &ev {
            // The server has committed to replaying from this anchor. Adopt it as
            // the resume / re-anchor point *now* — not only once the first
            // replayed confirmed event advances the high-water. If the stream
            // drops after this ack but before that first replayed event, the
            // reconnect re-anchors from `resume`; leaving it at the stale
            // high-water would silently skip the requested catch-up window and
            // break at-least-once coverage. (`cur` is None for this control
            // frame, so the high-water line above left `resume` untouched; we set
            // it to the accepted anchor here. A clamped accept re-clamps the same
            // way on reconnect, so re-anchoring from `from` stays correct.)
            if let Some(c) = from {
                self.resume = Some(*c);
                self.desired_cursor = Some(*c);
            }
            // The re-anchor landed: reset the transient-retry counter.
            self.reanchor_attempts = 0;
        }
        Ok(Some(ev))
    }

    /// Drive a deferred transient-reject retry ([`PendingReanchor`], recorded by
    /// `handle_event`) to completion: wait out the remaining backoff, then re-send
    /// the current re-anchor. Cancel-safe: the pending slot is cleared only *after*
    /// the re-send await resolves, so a cancellation before then leaves the retry
    /// recorded for the next [`next`](Self::next) to resume — the budget was
    /// already charged when the retry was recorded, so a resume never re-charges
    /// it. There is no await between the send resolving and the slot clearing, so a
    /// cancel either drops the future before the send lands (the slot survives and
    /// the next `next` sends once) or after it lands and the slot is already
    /// cleared — the same re-send never goes out twice. The cursor is read *live*
    /// from `desired_cursor`, not snapshotted, so a re-anchor changed between the
    /// record and the drive is honoured; a no-op while disconnected (no
    /// `desired_cursor` / no `handle`) still clears the slot.
    async fn drive_pending_reanchor(&mut self) -> Result<(), StreamError> {
        let Some(pending) = self.pending_reanchor else {
            return Ok(());
        };
        tokio::time::sleep_until(pending.deadline).await;
        let res = match (self.desired_cursor, &self.handle) {
            (Some(c), Some(h)) => Some(h.set_cursor(c).await),
            _ => None,
        };
        // Only now that the re-send has been attempted is the retry done; a
        // cancellation before this line leaves `pending_reanchor` set to resume.
        self.pending_reanchor = None;
        self.after_send(res)
    }

    /// Open a fresh `Watch` stream, re-register the mirrored watch-set, and
    /// re-anchor to the resume cursor. A control-send failure here means the new
    /// stream is already unusable — surfaced as an error for [`next`](Self::next)
    /// to back off and retry.
    async fn connect(&mut self) -> Result<(), StreamError> {
        self.seed_resume()?;
        let (handle, stream) = self.client.watch().await?;
        // When a loader is configured it is canonical: rebuild the watch-set from
        // the integrator's source-of-truth into a fresh mirror, then adopt it.
        // This runs before the watch-set is registered (below) and before any
        // event is pumped, so the first events after a reconnect land on a fully
        // populated subscription. A loader error is a transient reconnect-level
        // condition (see `is_reconnectable`), so a freshly-opened stream we will
        // not use is dropped here and the next attempt retries the load.
        if let Some(loader) = self.config.watch_set_loader.clone() {
            let shared = Arc::new(Mutex::new(WatchSetMirror::default()));
            loader(WatchSetBuilder { mirror: shared.clone() })
                .await
                .map_err(StreamError::WatchSetLoader)?;
            // Take the loaded set regardless of whether the loader stashed a
            // builder clone; the builder only records, so nothing races here.
            self.mirror = std::mem::take(&mut *shared.lock().unwrap_or_else(|p| p.into_inner()));
        }
        for msg in self.mirror.control_messages() {
            handle.send_control(pb::SubscribeControl { msg: Some(msg) }).await?;
        }
        self.desired_cursor = self.resume;
        self.reanchor_attempts = 0;
        // `teardown` already dropped any deferred retry against the old stream;
        // this fresh stream re-anchors from `resume` right here.
        debug_assert!(self.pending_reanchor.is_none());
        if let Some(c) = self.resume {
            handle.set_cursor(c).await?;
        }
        self.handle = Some(handle);
        self.stream = Some(stream);
        Ok(())
    }

    /// Establish the resume anchor on the first connect (no I/O): store, else the
    /// configured `from_cursor`. A cursor read back from the store is already
    /// durably committed, so it also seeds `committed` to elide a redundant first
    /// write.
    fn seed_resume(&mut self) -> Result<(), StreamError> {
        if !self.seeded {
            let loaded = self.config.cursor_store.load()?;
            if let Some(c) = loaded {
                self.committed.get_or_insert(c);
            }
            self.resume = self.resume.or(loaded).or(self.config.from_cursor);
            self.seeded = true;
        }
        Ok(())
    }

    /// Drop the live connection so the next [`next`](Self::next) reconnects.
    fn teardown(&mut self) {
        self.handle = None;
        self.stream = None;
        // A deferred re-anchor retry is meaningless once the stream it targeted is
        // gone — the reconnect re-anchors from `resume` itself. Drop it so `next`
        // does not sleep out a stale backoff against a dead handle before
        // reconnecting.
        self.pending_reanchor = None;
    }

    /// Resolve a live control-send result: a `ControlClosed` means the stream
    /// died, so drop it (the edit is safe in the mirror and replays on
    /// reconnect); any other error propagates; success and the disconnected
    /// (`None`) case are no-ops.
    fn after_send(&mut self, res: Option<Result<(), StreamError>>) -> Result<(), StreamError> {
        match res {
            Some(Err(StreamError::ControlClosed)) => {
                self.teardown();
                Ok(())
            }
            Some(Err(e)) => Err(e),
            _ => Ok(()),
        }
    }

    /// Arm the just-delivered event's high-water for commit on the next poll.
    fn arm_commit(&mut self) {
        self.commit_next = self.resume;
    }

    /// Commit-on-poll flush: persist the armed high-water if it differs from the
    /// store's current value.
    fn commit_due(&mut self) -> Result<(), StreamError> {
        if let Some(c) = self.commit_next.take()
            && self.committed != Some(c)
        {
            self.config.cursor_store.save(c)?;
            self.committed = Some(c);
        }
        Ok(())
    }
}

/// `txids × depths` as flattened pairs.
fn cross_product(txids: &[Txid], depths: &[u32]) -> Vec<(Txid, u32)> {
    let mut out = Vec::with_capacity(txids.len() * depths.len());
    for t in txids {
        for d in depths {
            out.push((*t, *d));
        }
    }
    out
}

/// Validate a batch of `(prefix, bits)` pairs up front (so a bad one is rejected
/// before any mirror mutation), reusing the same check as [`WatchHandle`].
fn validate_prefixes(
    prefixes: impl IntoIterator<Item = (Vec<u8>, u32)>,
) -> Result<Vec<pb::ScriptPrefix>, StreamError> {
    prefixes
        .into_iter()
        .map(|(prefix, bits)| validate_prefix(prefix, bits))
        .collect()
}

/// Whether a `connect()` failure should be retried by reconnecting. Adds
/// `ControlClosed` and `WatchSetLoader` to the transport-retryable set: a
/// freshly-opened stream that rejects the watch-set replay is a transient
/// failure to reconnect through, and a watch-set loader that fails to reach its
/// source-of-truth should be retried on the next connect rather than crashing
/// the consumer — neither is a caller-facing error.
fn is_reconnectable(e: &StreamError) -> bool {
    e.is_retryable() || matches!(e, StreamError::ControlClosed | StreamError::WatchSetLoader(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // --- watch-set mirror -----------------------------------------------------

    #[test]
    fn mirror_scripts_floor_overwrite_and_remove() {
        let mut m = WatchSetMirror::default();
        m.add_scripts(&[([1u8; 32], Some(5_000)), ([2u8; 32], None)]);
        // Re-assert updates the floor in place (no duplicate).
        m.add_scripts(&[([1u8; 32], Some(9_000))]);
        m.remove_scripts(&[[2u8; 32]]);

        let msgs = m.control_messages();
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Msg::AddScripts(a) => {
                assert_eq!(a.scripthashes, vec![[1u8; 32].to_vec()]);
                // One script, floored → parallel min_values of length 1.
                assert_eq!(a.min_values, vec![9_000]);
            }
            other => panic!("expected AddScripts, got {other:?}"),
        }
    }

    #[test]
    fn mirror_unfloored_scripts_emit_empty_min_values() {
        let mut m = WatchSetMirror::default();
        m.add_scripts(&[([1u8; 32], None), ([2u8; 32], None)]);
        match &m.control_messages()[0] {
            Msg::AddScripts(a) => assert!(a.min_values.is_empty(), "no floor → empty min_values"),
            other => panic!("expected AddScripts, got {other:?}"),
        }
    }

    #[test]
    fn mirror_lifecycle_grouped_by_autoclose_depth() {
        let mut m = WatchSetMirror::default();
        m.add_tx_lifecycle(&[[1u8; 32], [2u8; 32]], AutoClose::AtDepth(6));
        m.add_tx_lifecycle(&[[3u8; 32]], AutoClose::Never);
        let groups: Vec<_> = m
            .control_messages()
            .into_iter()
            .filter_map(|msg| match msg {
                Msg::AddTransactions(a) => Some((a.auto_close_depth, a.min_depths, a.txids.len())),
                _ => None,
            })
            .collect();
        // One group at depth 0 (Never, 1 txid), one at depth 6 (2 txids); both
        // lifecycle (empty min_depths).
        assert!(groups.contains(&(0, vec![], 1)));
        assert!(groups.contains(&(6, vec![], 2)));
    }

    #[test]
    fn mirror_depth_alarms_grouped_by_txid_with_min_depths() {
        let mut m = WatchSetMirror::default();
        m.add_depth_alarms(&[([7u8; 32], 3), ([7u8; 32], 6)]);
        let alarms: Vec<_> = m
            .control_messages()
            .into_iter()
            .filter_map(|msg| match msg {
                Msg::AddTransactions(a) => Some((a.txids.len(), a.min_depths, a.auto_close_depth)),
                _ => None,
            })
            .collect();
        // One per-txid message carrying both depths; non-empty min_depths marks
        // it a depth alarm (not a lifecycle), auto_close_depth 0.
        assert_eq!(alarms, vec![(1, vec![3, 6], 0)]);
    }

    #[test]
    fn mirror_categories_replayed_first() {
        let mut m = WatchSetMirror::default();
        m.add_outpoints(&[([1u8; 32], 0)]);
        m.set_categories(crate::Categories::CHAIN);
        let msgs = m.control_messages();
        assert!(matches!(msgs[0], Msg::SetCategories(_)), "categories lead the replay");
    }

    #[test]
    fn mirror_raw_tx_opt_in_replayed() {
        // The raw-tx opt-in survives a reconnect: it renders into the replay
        // control messages, before the watch-set adds so it is in effect when
        // matches flow. Unset → no SetWatchOptions in the replay.
        let mut m = WatchSetMirror::default();
        m.add_scripts(&[([9u8; 32], None)]);
        assert!(
            !m.control_messages()
                .iter()
                .any(|msg| matches!(msg, Msg::SetWatchOptions(_))),
            "no opt-in → no SetWatchOptions replayed"
        );

        m.set_watch_options(true);
        let msgs = m.control_messages();
        let opt = msgs.iter().find_map(|msg| match msg {
            Msg::SetWatchOptions(o) => Some(o.include_raw_tx),
            _ => None,
        });
        assert_eq!(opt, Some(true), "opt-in replayed as SetWatchOptions{{true}}");
        // It leads the watch-set adds (like categories), so raw_tx is on from
        // the first replayed match.
        let opt_pos = msgs
            .iter()
            .position(|msg| matches!(msg, Msg::SetWatchOptions(_)))
            .unwrap();
        let add_pos = msgs
            .iter()
            .position(|msg| matches!(msg, Msg::AddScripts(_)))
            .unwrap();
        assert!(opt_pos < add_pos, "options precede the watch-set adds");
    }

    #[test]
    fn mirror_descriptor_latest_window_wins() {
        let mut m = WatchSetMirror::default();
        m.add_descriptor("wpkh(xpub...)".into(), 20, 0);
        m.add_descriptor("wpkh(xpub...)".into(), 20, 5); // window advanced
        let descs: Vec<_> = m
            .control_messages()
            .into_iter()
            .filter_map(|msg| match msg {
                Msg::AddDescriptor(d) => Some((d.gap_limit, d.start)),
                _ => None,
            })
            .collect();
        assert_eq!(descs, vec![(20, 5)], "only the latest window replays");
    }

    #[test]
    fn mirror_removed_descriptor_is_not_replayed() {
        let mut m = WatchSetMirror::default();
        m.add_descriptor("wpkh(a)".into(), 20, 0);
        m.add_descriptor("wpkh(b)".into(), 20, 0);
        m.remove_descriptor("wpkh(a)");
        let descs: Vec<_> = m
            .control_messages()
            .into_iter()
            .filter_map(|msg| match msg {
                Msg::AddDescriptor(d) => Some(d.descriptor),
                _ => None,
            })
            .collect();
        // The removed descriptor is gone from the replay; a reconnect re-registers
        // only the surviving one (the fresh stream has nothing to RemoveDescriptor).
        assert_eq!(descs, vec!["wpkh(b)".to_string()]);
    }

    #[test]
    fn mirror_empty_renders_nothing() {
        assert!(WatchSetMirror::default().control_messages().is_empty());
    }

    // --- a CursorStore we can assert against ----------------------------------

    #[derive(Default)]
    struct MemStore(Mutex<Option<Cursor>>);
    impl CursorStore for MemStore {
        fn load(&self) -> Result<Option<Cursor>, StreamError> {
            Ok(*self.0.lock().unwrap())
        }
        fn save(&self, cursor: Cursor) -> Result<(), StreamError> {
            *self.0.lock().unwrap() = Some(cursor);
            Ok(())
        }
    }

    fn watch_with(store: &Arc<MemStore>) -> ResilientWatch {
        ResilientWatch::new(
            StreamClient::for_test(),
            ResilientWatchConfig::new().cursor_store(store.clone()),
        )
    }

    fn cur(height: u32) -> Cursor {
        Cursor { height, tx_index: 0, mempool_seq: 0, instance_id: 1 }
    }

    // --- offline edits land in the mirror -------------------------------------

    #[tokio::test]
    async fn offline_edits_accumulate_for_replay() {
        let store = Arc::new(MemStore::default());
        let mut w = watch_with(&store);
        // Disconnected: every edit records to the mirror and sends nothing.
        w.add_scripts([([1u8; 32], None)]).await.unwrap();
        w.add_outpoints([([9u8; 32], 2)]).await.unwrap();
        w.add_depth_alarms([[7u8; 32]], [0]).await.unwrap(); // all depths invalid → no-op
        let kinds: Vec<_> = w
            .mirror
            .control_messages()
            .into_iter()
            .map(|m| std::mem::discriminant(&m))
            .collect();
        // Scripts + outpoints recorded; the all-invalid depth alarm did not.
        assert_eq!(kinds.len(), 2);
        assert!(w.handle.is_none(), "still disconnected");
    }

    // --- re-anchor catch-up ---------------------------------------------------

    #[tokio::test]
    async fn cursor_accepted_is_surfaced_and_resets_retry_counter() {
        let store = Arc::new(MemStore::default());
        let mut w = watch_with(&store);
        w.reanchor_attempts = 3;
        let ev = Event::CursorAccepted { from: Some(cur(100)), clamped: false, earliest_replayed: 100 };
        let out = w.handle_event(ev, None).await.unwrap();
        assert!(matches!(out, Some(Event::CursorAccepted { .. })), "accept surfaces to caller");
        assert_eq!(w.reanchor_attempts, 0, "a landed re-anchor resets the retry counter");
    }

    #[tokio::test]
    async fn cursor_accepted_adopts_anchor_before_any_replayed_event() {
        let store = Arc::new(MemStore::default());
        let mut w = watch_with(&store);
        // High-water sits forward (e.g. from prior live events); the caller
        // re-anchors backward to replay a window.
        w.resume = Some(cur(1000));
        w.desired_cursor = Some(cur(200));
        // Server admits the re-anchor. No replayed confirmed event has arrived yet
        // (this control frame carries no cursor).
        let ev = Event::CursorAccepted { from: Some(cur(200)), clamped: false, earliest_replayed: 200 };
        let out = w.handle_event(ev, None).await.unwrap();
        assert!(matches!(out, Some(Event::CursorAccepted { .. })));
        // The accepted anchor is adopted immediately, so a reconnect *before* the
        // first replayed event re-anchors from 200, not the stale high-water 1000.
        assert_eq!(w.resume, Some(cur(200)), "accepted anchor becomes the resume point at once");
        assert_eq!(w.desired_cursor, Some(cur(200)));
    }

    #[tokio::test]
    async fn terminal_reject_is_surfaced_for_escalation() {
        let store = Arc::new(MemStore::default());
        let mut w = watch_with(&store);
        let ev = Event::CursorRejected {
            reason: CursorRejectReason::NoSource,
            current_head: Some(cur(500)),
        };
        let out = w.handle_event(ev, None).await.unwrap();
        assert!(
            matches!(out, Some(Event::CursorRejected { reason: CursorRejectReason::NoSource, .. })),
            "NoSource is terminal — surfaced so the caller can resnapshot"
        );
    }

    #[tokio::test]
    async fn transient_reject_retries_in_place_until_budget_exhausted() {
        let store = Arc::new(MemStore::default());
        let mut w = ResilientWatch::new(
            StreamClient::for_test(),
            ResilientWatchConfig::new()
                .cursor_store(store.clone())
                // Tiny backoff + a 2-retry budget so the test is fast and bounded.
                .backoff(Backoff {
                    initial: std::time::Duration::from_millis(0),
                    max: std::time::Duration::from_millis(0),
                    multiplier: 1.0,
                    max_retries: Some(2),
                }),
        );
        w.desired_cursor = Some(cur(100));
        let reject = || Event::CursorRejected {
            reason: CursorRejectReason::RateLimited,
            current_head: None,
        };
        // `handle_event` now records each transient reject as a pending retry
        // (the backoff + re-send is driven by `next`); we assert the budget
        // accounting and that the reject is consumed (Ok(None)) until exhausted,
        // then surfaced.
        assert!(w.handle_event(reject(), None).await.unwrap().is_none(), "retry 1 consumed");
        assert!(w.pending_reanchor.is_some(), "retry 1 deferred to a pending slot");
        assert!(w.handle_event(reject(), None).await.unwrap().is_none(), "retry 2 consumed");
        let out = w.handle_event(reject(), None).await.unwrap();
        assert!(
            matches!(out, Some(Event::CursorRejected { .. })),
            "budget exhausted → surfaced for the caller to escalate"
        );
        assert_eq!(w.reanchor_attempts, 0, "counter resets after surfacing");
    }

    #[tokio::test]
    async fn transient_reject_retry_is_cancel_safe() {
        // Regression for #453: cancelling `next` (e.g. losing a `select!` race)
        // while a transient-reject retry is mid-backoff must not burn the retry
        // budget without the re-send landing. The retry lives in `self` as
        // pending state and is driven by `drive_pending_reanchor`, so a cancelled
        // drive resumes the *same* retry.
        let store = Arc::new(MemStore::default());
        let mut w = ResilientWatch::new(
            StreamClient::for_test(),
            ResilientWatchConfig::new().cursor_store(store.clone()).backoff(Backoff {
                // A long backoff so the drive is guaranteed to park in the sleep
                // (never reaching the re-send) before we cancel it.
                initial: std::time::Duration::from_secs(30),
                max: std::time::Duration::from_secs(30),
                multiplier: 1.0,
                max_retries: Some(3),
            }),
        );
        w.desired_cursor = Some(cur(100));

        // A transient reject charges the budget once and defers the retry — no
        // inline await in `handle_event` any more.
        let out = w
            .handle_event(
                Event::CursorRejected { reason: CursorRejectReason::RateLimited, current_head: None },
                None,
            )
            .await
            .unwrap();
        assert!(out.is_none(), "transient reject consumed");
        assert_eq!(w.reanchor_attempts, 1, "one retry charged");
        assert!(w.pending_reanchor.is_some(), "retry deferred to a resumable slot");

        // Cancel the drive while it is parked in the 30s backoff: `biased` polls
        // the drive first (it parks), then the 1ms timer fires and preempts it,
        // dropping the drive future.
        tokio::select! {
            biased;
            _ = w.drive_pending_reanchor() => unreachable!("30s backoff cannot have elapsed"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(1)) => {}
        }
        assert!(w.pending_reanchor.is_some(), "a cancelled drive leaves the retry resumable");
        assert_eq!(w.reanchor_attempts, 1, "the cancelled drive did not re-charge the budget");

        // Resume to completion. Collapse the remaining backoff so the test stays
        // fast; disconnected, so the re-send is a no-op and the slot just clears.
        w.pending_reanchor.as_mut().unwrap().deadline = tokio::time::Instant::now();
        w.drive_pending_reanchor().await.unwrap();
        assert!(w.pending_reanchor.is_none(), "the resumed drive completes the retry");
        assert_eq!(w.reanchor_attempts, 1, "resuming does not re-charge the budget");
    }

    // Drain the cursor of every `SetCursor` control message queued on a test
    // handle's receiver, in send order.
    fn drained_set_cursors(
        rx: &mut tokio::sync::mpsc::Receiver<pb::SubscribeControl>,
    ) -> Vec<Cursor> {
        let mut out = Vec::new();
        while let Ok(ctrl) = rx.try_recv() {
            if let Some(Msg::SetCursor(s)) = ctrl.msg {
                out.push(s.cursor.expect("a SetCursor carries a cursor"));
            }
        }
        out
    }

    #[tokio::test]
    async fn set_cursor_supersedes_a_pending_transient_retry() {
        // Regression for the #455 review: a deferred transient-reject retry must
        // not re-send a now-stale anchor after the caller has explicitly
        // re-anchored elsewhere. The exposing sequence is the #453 actor pattern —
        // cancel `next` mid-retry, then issue `set_cursor` before resuming.
        let store = Arc::new(MemStore::default());
        let (handle, mut rx) = crate::client::WatchHandle::for_test();
        let mut w = watch_with(&store);
        w.handle = Some(handle);
        w.desired_cursor = Some(cur(100));

        // A transient reject defers a retry that would re-send the anchor at 100.
        w.handle_event(
            Event::CursorRejected { reason: CursorRejectReason::RateLimited, current_head: None },
            None,
        )
        .await
        .unwrap();
        assert!(w.pending_reanchor.is_some(), "retry deferred");

        // The caller now re-anchors to 200: sends set_cursor(200) live, and must
        // supersede the deferred retry for 100.
        w.set_cursor(cur(200)).await.unwrap();
        assert!(w.pending_reanchor.is_none(), "explicit re-anchor drops the stale deferred retry");
        assert_eq!(drained_set_cursors(&mut rx), vec![cur(200)], "only the fresh anchor is sent");

        // Driving the (now-cleared) retry re-sends nothing — in particular not the
        // stale 100 that would clobber the caller's 200.
        w.drive_pending_reanchor().await.unwrap();
        assert!(drained_set_cursors(&mut rx).is_empty(), "a superseded retry re-sends nothing");
    }

    #[tokio::test]
    async fn a_deferred_retry_re_sends_the_live_desired_cursor() {
        // The drive reads `desired_cursor` live, not a snapshot taken when the
        // reject was recorded, so an anchor that moved between the reject and the
        // drive is what re-lands on the wire.
        let store = Arc::new(MemStore::default());
        let (handle, mut rx) = crate::client::WatchHandle::for_test();
        let mut w = ResilientWatch::new(
            StreamClient::for_test(),
            ResilientWatchConfig::new().cursor_store(store.clone()).backoff(Backoff {
                initial: std::time::Duration::ZERO,
                max: std::time::Duration::ZERO,
                multiplier: 1.0,
                max_retries: Some(3),
            }),
        );
        w.handle = Some(handle);
        w.desired_cursor = Some(cur(100));

        // Defer a retry (recorded while the desire is 100)…
        w.handle_event(
            Event::CursorRejected {
                reason: CursorRejectReason::ConcurrentReanchor,
                current_head: None,
            },
            None,
        )
        .await
        .unwrap();
        // …then the desire advances to 200 while the retry is still pending.
        w.desired_cursor = Some(cur(200));

        // The drive re-sends the live 200, never the stale 100.
        w.drive_pending_reanchor().await.unwrap();
        assert_eq!(drained_set_cursors(&mut rx), vec![cur(200)], "the live anchor is re-sent");
        assert!(w.pending_reanchor.is_none(), "the retry completed");
    }

    // --- one-shot watch eviction sync -----------------------------------------

    #[tokio::test]
    async fn fired_depth_alarm_is_pruned_from_the_mirror() {
        let store = Arc::new(MemStore::default());
        let mut w = watch_with(&store);
        // Arm two alarms on one txid; the server fires and self-evicts the
        // depth-3 one (reporting the requested threshold 3, not actual confs).
        w.add_depth_alarms([[7u8; 32]], [3, 6]).await.unwrap();
        let ev = Event::TxidDepthReached { txid: [7u8; 32].to_vec(), depth: 3, height: 100 };
        let out = w.handle_event(ev, None).await.unwrap();
        assert!(matches!(out, Some(Event::TxidDepthReached { .. })), "still surfaced to caller");
        // Fired (txid,3) pruned so a reconnect won't re-register it; (txid,6)
        // stays for replay.
        assert!(!w.mirror.depth_alarms.contains(&([7u8; 32], 3)), "fired alarm pruned");
        assert!(w.mirror.depth_alarms.contains(&([7u8; 32], 6)), "unfired alarm retained");
    }

    #[tokio::test]
    async fn finalized_lifecycle_watch_is_pruned_from_the_mirror() {
        let store = Arc::new(MemStore::default());
        let mut w = watch_with(&store);
        w.add_tx_lifecycle([[8u8; 32]], AutoClose::AtDepth(6)).await.unwrap();
        let ev = Event::TxidFinalized { txid: [8u8; 32].to_vec(), depth: 6, height: 200 };
        let out = w.handle_event(ev, None).await.unwrap();
        assert!(matches!(out, Some(Event::TxidFinalized { .. })), "still surfaced to caller");
        assert!(
            !w.mirror.tx_lifecycles.contains_key(&[8u8; 32]),
            "auto-close finalize prunes the lifecycle watch the server evicted"
        );
    }

    // --- cursor persistence (commit-on-poll) ----------------------------------

    #[tokio::test]
    async fn confirmed_cursor_commits_on_the_following_poll() {
        let store = Arc::new(MemStore::default());
        let mut w = watch_with(&store);
        let c = cur(900);

        // Deliver a confirmed event carrying cursor c.
        w.commit_due().unwrap();
        let out = w
            .handle_event(Event::BlockConnected { hash: vec![0xaa], height: 900 }, Some(c))
            .await
            .unwrap();
        assert!(out.is_some());
        w.arm_commit();
        // Not yet committed — the caller has the event but hasn't polled again.
        assert_eq!(store.load().unwrap(), None);

        // The next poll acks it.
        w.commit_due().unwrap();
        assert_eq!(store.load().unwrap(), Some(c));
    }

    #[tokio::test]
    async fn seed_resume_prefers_store_over_from_cursor() {
        let store = Arc::new(MemStore::default());
        store.save(cur(800)).unwrap();
        let mut w = ResilientWatch::new(
            StreamClient::for_test(),
            ResilientWatchConfig::new().cursor_store(store.clone()).from_cursor(cur(1)),
        );
        w.seed_resume().unwrap();
        assert_eq!(w.resume, Some(cur(800)), "persisted cursor wins over from_cursor");
        assert_eq!(w.committed, Some(cur(800)), "loaded cursor seeds committed");
    }

    // --- watch-set loader (#447) ----------------------------------------------

    /// Drive the loader step exactly as `connect` does — populate a fresh shared
    /// mirror through the builder, then take it — without needing a live stream.
    async fn run_loader(config: &ResilientWatchConfig) -> Result<WatchSetMirror, StreamError> {
        let loader = config.watch_set_loader.clone().expect("loader configured");
        let shared = Arc::new(Mutex::new(WatchSetMirror::default()));
        loader(WatchSetBuilder { mirror: shared.clone() })
            .await
            .map_err(StreamError::WatchSetLoader)?;
        Ok(std::mem::take(&mut *shared.lock().unwrap()))
    }

    #[test]
    fn builder_facade_records_every_watch_kind() {
        let m = Arc::new(Mutex::new(WatchSetMirror::default()));
        let b = WatchSetBuilder { mirror: m.clone() };
        b.set_categories(crate::Categories::CHAIN);
        b.add_scripts([([1u8; 32], Some(5_000))]);
        b.add_outpoints([([2u8; 32], 0)]);
        b.add_tx_lifecycle([[3u8; 32]], AutoClose::AtDepth(6));
        b.add_depth_alarms([[4u8; 32]], [3, 6]);
        b.add_descriptor("wpkh(xpub...)", 20, 0);
        b.add_script_prefixes([(vec![0xab], 8)]).unwrap();

        let mirror = std::mem::take(&mut *m.lock().unwrap());
        let kinds: Vec<_> = mirror
            .control_messages()
            .into_iter()
            .map(|msg| std::mem::discriminant(&msg))
            .collect();
        // Categories + scripts + outpoints + lifecycle + depth-alarm + descriptor
        // + prefixes = 7 messages, the same shapes a manual replay emits.
        assert_eq!(kinds.len(), 7, "every declared kind renders to a control message");
        assert!(
            matches!(mirror.control_messages()[0], Msg::SetCategories(_)),
            "categories still lead the replay"
        );
    }

    #[test]
    fn builder_depth_alarms_filter_and_cross_product() {
        let m = Arc::new(Mutex::new(WatchSetMirror::default()));
        let b = WatchSetBuilder { mirror: m.clone() };
        // Depth 0 is invalid and dropped; the two txids × the one valid depth (5)
        // cross-multiply into two alarms.
        b.add_depth_alarms([[1u8; 32], [2u8; 32]], [0, 5]);
        let mirror = std::mem::take(&mut *m.lock().unwrap());
        assert!(mirror.depth_alarms.contains(&([1u8; 32], 5)));
        assert!(mirror.depth_alarms.contains(&([2u8; 32], 5)));
        assert_eq!(mirror.depth_alarms.len(), 2, "depth 0 dropped, depth 5 kept");
    }

    #[test]
    fn builder_prefix_validation_error_aborts_the_load() {
        let m = Arc::new(Mutex::new(WatchSetMirror::default()));
        let b = WatchSetBuilder { mirror: m };
        // bits 0 is out of the 1..=32 range — rejected the same as the live path.
        assert!(matches!(
            b.add_script_prefixes([(vec![], 0)]),
            Err(StreamError::InvalidArgument(_))
        ));
    }

    #[tokio::test]
    async fn loader_rebuilds_the_canonical_watch_set() {
        let config = ResilientWatchConfig::new().watch_set_loader(|b: WatchSetBuilder| async move {
            // Stand-in for "query the durable truth, then declare the set."
            b.add_scripts([([7u8; 32], None), ([8u8; 32], Some(1_000))]);
            b.add_outpoints([([9u8; 32], 1)]);
            Ok(())
        });
        let mirror = run_loader(&config).await.expect("loader succeeds");
        assert!(mirror.scripts.contains_key(&[7u8; 32]));
        assert_eq!(mirror.scripts.get(&[8u8; 32]), Some(&Some(1_000)));
        assert!(mirror.outpoints.contains(&([9u8; 32], 1)));
    }

    #[tokio::test]
    async fn loader_canonical_set_replaces_prior_in_process_edits() {
        // A loaded canonical set must REPLACE whatever the in-process mirror held
        // (truth-of-record is external), not merge with it.
        let mut w = ResilientWatch::new(
            StreamClient::for_test(),
            ResilientWatchConfig::new().watch_set_loader(|b: WatchSetBuilder| async move {
                b.add_scripts([([2u8; 32], None)]);
                Ok(())
            }),
        );
        // Pre-existing in-process edit the loader does not know about.
        w.add_scripts([([1u8; 32], None)]).await.unwrap();
        assert!(w.mirror.scripts.contains_key(&[1u8; 32]));
        // Adopt the loaded set the way `connect` does.
        w.mirror = run_loader(&w.config).await.unwrap();
        assert!(!w.mirror.scripts.contains_key(&[1u8; 32]), "stale in-process edit dropped");
        assert!(w.mirror.scripts.contains_key(&[2u8; 32]), "canonical loaded script present");
    }

    #[tokio::test]
    async fn loader_error_maps_to_watch_set_loader_and_is_reconnectable() {
        let config = ResilientWatchConfig::new().watch_set_loader(|_b: WatchSetBuilder| async move {
            Err("source-of-truth unreachable".into())
        });
        let err = run_loader(&config).await.expect_err("loader failure surfaces");
        assert!(matches!(err, StreamError::WatchSetLoader(_)));
        assert!(
            is_reconnectable(&err),
            "a loader failure is a transient reconnect-level condition, not caller-facing"
        );
        // And the inner integrator message is preserved.
        assert!(err.to_string().contains("source-of-truth unreachable"));
    }

    #[test]
    fn no_loader_leaves_behavior_unchanged() {
        // The default config has no loader: mirror-replay is untouched.
        assert!(ResilientWatchConfig::new().watch_set_loader.is_none());
    }

    // --- reload(): diff the live set against truth and apply the delta ---------

    #[test]
    fn reconcile_to_emits_only_the_delta_removes_before_adds() {
        // Old set vs a target that adds, removes, and changes one of each kind.
        let mut old = WatchSetMirror::default();
        old.add_scripts(&[([1u8; 32], None), ([2u8; 32], Some(500))]); // 2 kept-ish
        old.add_outpoints(&[([9u8; 32], 0)]);
        old.add_descriptor("desc-keep".into(), 20, 0);
        old.add_descriptor("desc-drop".into(), 20, 0);

        let mut new = WatchSetMirror::default();
        new.add_scripts(&[([1u8; 32], None), ([2u8; 32], Some(999))]); // sh2 floor changed
        new.add_scripts(&[([3u8; 32], None)]); // sh3 new
        // sh? none removed here besides via descriptors; outpoint 9 removed (absent)
        new.add_descriptor("desc-keep".into(), 20, 0); // unchanged
        // desc-drop removed; desc-new added
        new.add_descriptor("desc-new".into(), 20, 0);

        let (msgs, counts) = old.reconcile_to(&new);

        // sh3 + sh2(changed) added (2), desc-new added (1) → added 3.
        // outpoint 9 removed (1), desc-drop removed (1) → removed 2.
        // sh1 + desc-keep unchanged → unchanged 2.
        assert_eq!(counts.added, 3, "sh2(changed) + sh3 + desc-new");
        assert_eq!(counts.removed, 2, "outpoint + desc-drop");
        assert_eq!(counts.unchanged, 2, "sh1 + desc-keep");

        // Every Remove*/RemoveDescriptor comes before any watch-adding Add* — a
        // removal must free its quota unit before the replacement add claims it,
        // so a swap at quota does not have its adds silently rejected.
        let last_remove = msgs.iter().rposition(|m| {
            matches!(
                m,
                Msg::RemoveScripts(_)
                    | Msg::RemoveOutpoints(_)
                    | Msg::RemoveTransactions(_)
                    | Msg::RemoveScriptPrefixes(_)
                    | Msg::RemoveDescriptor(_)
            )
        });
        let first_add = msgs.iter().position(|m| {
            matches!(
                m,
                Msg::AddScripts(_)
                    | Msg::AddOutpoints(_)
                    | Msg::AddTransactions(_)
                    | Msg::AddDescriptor(_)
                    | Msg::AddScriptPrefixes(_)
            )
        });
        if let (Some(lr), Some(fa)) = (last_remove, first_add) {
            assert!(lr < fa, "every Remove must precede every quota-consuming Add");
        }
        // A vanished descriptor is dropped with RemoveDescriptor, not by scripthash.
        assert!(msgs.iter().any(|m| matches!(m, Msg::RemoveDescriptor(d) if d.descriptor == "desc-drop")));
    }

    #[test]
    fn reconcile_disjoint_swap_removes_before_adds_for_quota_safety() {
        // A tenant at quota N reloading N old watches → N disjoint new watches.
        // The removes must precede the adds so the server frees the N old units
        // before the N new adds are charged; add-first would let the server
        // silently reject the over-quota adds and then apply the removes.
        let mut live = WatchSetMirror::default();
        live.add_scripts(&[([1u8; 32], None), ([2u8; 32], None), ([3u8; 32], None)]);
        let mut target = WatchSetMirror::default();
        target.add_scripts(&[([4u8; 32], None), ([5u8; 32], None), ([6u8; 32], None)]);

        let (msgs, counts) = live.reconcile_to(&target);
        assert_eq!((counts.added, counts.removed, counts.unchanged), (3, 3, 0));

        let remove_pos = msgs.iter().position(|m| matches!(m, Msg::RemoveScripts(_)));
        let add_pos = msgs.iter().position(|m| matches!(m, Msg::AddScripts(_)));
        assert!(
            remove_pos < add_pos,
            "RemoveScripts must be sent before AddScripts so freed quota covers the replacements",
        );
    }

    #[test]
    fn reconcile_identical_sets_is_empty() {
        let mut m = WatchSetMirror::default();
        m.add_scripts(&[([1u8; 32], Some(5))]);
        m.add_descriptor("d".into(), 20, 0);
        let (msgs, counts) = m.reconcile_to(&m.clone());
        assert!(msgs.is_empty(), "no churn when nothing changed");
        assert_eq!((counts.added, counts.removed), (0, 0));
        assert_eq!(counts.unchanged, 2);
    }

    #[test]
    fn reconcile_categories_relaxation_emits_an_explicit_reset() {
        // Live server is filtered to CHAIN; truth (the reload target) has no
        // category filter. reconcile must emit SetCategories{0} ("all") so the
        // relaxation takes effect live — not silently leave the server filtered.
        let mut live = WatchSetMirror::default();
        live.set_categories(crate::Categories::CHAIN);
        let target = WatchSetMirror::default(); // no filter

        let (msgs, _) = live.reconcile_to(&target);
        assert_eq!(
            msgs.iter()
                .filter_map(|m| match m {
                    Msg::SetCategories(s) => Some(s.categories),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            vec![0],
            "relaxing a filter to all-categories emits SetCategories{{0}}",
        );

        // Setting a filter from none, and changing between filters, still emit.
        let none = WatchSetMirror::default();
        let mut chain = WatchSetMirror::default();
        chain.set_categories(crate::Categories::CHAIN);
        assert!(
            matches!(none.reconcile_to(&chain).0.first(), Some(Msg::SetCategories(s)) if s.categories == crate::Categories::CHAIN),
            "setting a filter from unfiltered emits it",
        );

        // None ↔ Some(0) are both "all categories": no spurious message.
        let mut all = WatchSetMirror::default();
        all.set_categories(0);
        assert!(
            !none.reconcile_to(&all).0.iter().any(|m| matches!(m, Msg::SetCategories(_))),
            "None and Some(0) are the same effective filter — no reset emitted",
        );
    }

    #[tokio::test]
    async fn reload_without_loader_errors() {
        let store = Arc::new(MemStore::default());
        let mut w = watch_with(&store);
        assert!(matches!(w.reload().await, Err(ReloadError::NoLoader)));
    }

    #[tokio::test]
    async fn reload_surfaces_loader_error() {
        let mut w = ResilientWatch::new(
            StreamClient::for_test(),
            ResilientWatchConfig::new()
                .watch_set_loader(|_b: WatchSetBuilder| async move { Err("truth down".into()) }),
        );
        let err = w.reload().await.expect_err("loader failure surfaces");
        assert!(matches!(err, ReloadError::Loader(_)));
        assert!(err.to_string().contains("truth down"));
    }

    #[tokio::test]
    async fn reload_while_disconnected_defers_but_updates_the_mirror() {
        let mut w = ResilientWatch::new(
            StreamClient::for_test(),
            ResilientWatchConfig::new().watch_set_loader(|b: WatchSetBuilder| async move {
                b.add_scripts([([5u8; 32], None)]);
                Ok(())
            }),
        );
        // Pre-existing live edit the loader will not reproduce.
        w.add_scripts([([1u8; 32], None)]).await.unwrap();

        let summary = w.reload().await.expect("reload ok");
        assert!(!summary.applied, "no live stream → deferred to reconnect loader");
        assert_eq!(summary.added, 1, "sh5 added");
        assert_eq!(summary.removed, 1, "stale sh1 removed");
        // The mirror now reflects truth, so a reconnect re-registers the right set.
        assert!(w.mirror.scripts.contains_key(&[5u8; 32]));
        assert!(!w.mirror.scripts.contains_key(&[1u8; 32]));
    }

    #[tokio::test]
    async fn reload_while_connected_sends_only_the_delta() {
        let mut w = ResilientWatch::new(
            StreamClient::for_test(),
            ResilientWatchConfig::new().watch_set_loader(|b: WatchSetBuilder| async move {
                // Truth: keep sh1, drop sh2, add sh3.
                b.add_scripts([([1u8; 32], None), ([3u8; 32], None)]);
                Ok(())
            }),
        );
        w.add_scripts([([1u8; 32], None), ([2u8; 32], None)]).await.unwrap();

        // Inject a live handle whose receiver we can inspect.
        let (handle, mut rx) = crate::client::WatchHandle::for_test();
        w.handle = Some(handle);

        let summary = w.reload().await.expect("reload ok");
        assert!(summary.applied, "connected → applied live");
        // Advisory client counts (server's WatchSetResult is authoritative).
        assert_eq!((summary.added, summary.removed, summary.unchanged), (1, 1, 1));

        // Exactly ONE SetWatchSet carrying the whole desired set (sh1 + sh3)
        // reached the wire — no client-computed Add*/Remove* delta.
        let mut msgs = Vec::new();
        while let Ok(ctrl) = rx.try_recv() {
            msgs.push(ctrl.msg.unwrap());
        }
        assert_eq!(msgs.len(), 1, "reload sends exactly one control message");
        let Msg::SetWatchSet(sws) = &msgs[0] else {
            panic!("expected a SetWatchSet, got {:?}", msgs[0]);
        };
        let mut got: Vec<Vec<u8>> = sws.scripthashes.clone();
        got.sort();
        assert_eq!(
            got,
            vec![[1u8; 32].to_vec(), [3u8; 32].to_vec()],
            "the snapshot is the full desired set, not a delta",
        );
    }

    #[tokio::test]
    async fn reload_turns_off_raw_tx_opt_in_when_truth_drops_it() {
        // A live stream opted into raw_tx directly; the reloaded truth does NOT
        // declare it (a delivery knob, not watch-set truth — the common case).
        // reload must explicitly send SetWatchOptions{false} so the server stops
        // inlining full txs, not silently leave it on until an incidental
        // reconnect. SetWatchSet does not carry the opt-in, so this is the only
        // signal that reconciles it.
        let mut w = ResilientWatch::new(
            StreamClient::for_test(),
            ResilientWatchConfig::new().watch_set_loader(|b: WatchSetBuilder| async move {
                b.add_scripts([([1u8; 32], None)]);
                Ok(())
            }),
        );
        w.add_scripts([([1u8; 32], None)]).await.unwrap();
        w.set_watch_options(true).await.unwrap(); // opt in on the live mirror
        assert_eq!(w.mirror.include_raw_tx, Some(true));

        let (handle, mut rx) = crate::client::WatchHandle::for_test();
        w.handle = Some(handle);

        w.reload().await.expect("reload ok");

        let mut msgs = Vec::new();
        while let Ok(ctrl) = rx.try_recv() {
            msgs.push(ctrl.msg.unwrap());
        }
        // reload sent the SetWatchSet snapshot AND an explicit turn-off.
        let opt = msgs.iter().find_map(|m| match m {
            Msg::SetWatchOptions(o) => Some(o.include_raw_tx),
            _ => None,
        });
        assert_eq!(opt, Some(false), "reload turns the opt-in OFF to match truth");
        // The mirror now reflects truth (no opt-in), so a reconnect stays off.
        assert_eq!(w.mirror.include_raw_tx, None);
    }

    #[tokio::test]
    async fn reload_does_not_touch_raw_tx_opt_in_when_unchanged() {
        // Neither the live stream nor truth wants raw_tx → reload must not emit a
        // spurious SetWatchOptions (None and false are the same effective state).
        let mut w = ResilientWatch::new(
            StreamClient::for_test(),
            ResilientWatchConfig::new().watch_set_loader(|b: WatchSetBuilder| async move {
                b.add_scripts([([1u8; 32], None)]);
                Ok(())
            }),
        );
        w.add_scripts([([1u8; 32], None)]).await.unwrap();

        let (handle, mut rx) = crate::client::WatchHandle::for_test();
        w.handle = Some(handle);

        w.reload().await.expect("reload ok");

        let mut msgs = Vec::new();
        while let Ok(ctrl) = rx.try_recv() {
            msgs.push(ctrl.msg.unwrap());
        }
        assert!(
            !msgs.iter().any(|m| matches!(m, Msg::SetWatchOptions(_))),
            "no opt-in change → no SetWatchOptions churn, got {msgs:?}",
        );
    }
}
