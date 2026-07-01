//! Per-subscription watch-set with per-item quota leases.
//!
//! Both streaming carriers (gRPC `Watch` and the `--streamws` WS/SSE
//! transport) let a client add and remove outpoint/script watches on a live
//! subscription, each watch item charging one unit of the per-token watch
//! quota (N items = N units). This module owns the bookkeeping that ties a
//! quota lease to an individual watch item, giving two properties the original
//! "push a per-message batch lease onto a `Vec`" approach lacked:
//!
//! * **Cross-message dedup** — re-adding an item the subscription already
//!   watches (even in a later control message) is charged once and registered
//!   once. The registry itself dedups on insert, so without this the quota
//!   would be over-charged for a re-assert.
//! * **Per-remove release** — removing a watch drops exactly that item's lease
//!   and returns its unit immediately, instead of holding all quota until the
//!   whole subscription disconnects. This is what makes a long-lived client
//!   that rotates its watch-set (e.g. a descriptor sliding window) viable
//!   without monotonically exhausting its quota.
//!
//! Charging stays **atomic and all-or-nothing per add**: the net-new items are
//! reserved in one [`Principal::acquire_watch`] call, then split into per-item
//! leases via [`WatchLease::split_off_one`] (which moves units without touching
//! the store). If the reservation does not fit the quota, none of the add's
//! items are registered — the protocol has no per-item ack, so a partial add
//! would be a silent partial failure.
//!
//! A `WatchSet` is held behind the subscription-scoped `Arc<Mutex<..>>` shared
//! by the inbound control reader and the outbound stream, so the quota is tied
//! to the subscription's lifetime — not to a control-stream half-close.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use bitcoin::{OutPoint, Txid};
use tracing::warn;

/// Per-control-message cap on the `(txid × distinct-depth)` cross-product for
/// the depth-alarm add/remove paths. A malformed control message carrying huge
/// `txids` and `min_depths` lists must not allocate billions of tuples (OOM)
/// *before* the quota check — and the remove path performs no quota check at
/// all, so an unauthenticated / subscribe-only client could otherwise exhaust
/// memory with a single frame. 65536 pairs (~2.3 MiB of tuples) is generous for
/// any legitimate batch; larger sets are split across messages.
pub(crate) const MAX_TXID_DEPTH_PAIRS: usize = 65_536;

/// Build the `(txid × distinct-depth)` watch pairs for a depth-alarm
/// add/remove, or `None` if the cross-product would exceed
/// [`MAX_TXID_DEPTH_PAIRS`]. Depths are de-duplicated first so a client cannot
/// inflate the product (or the registry) by repeating a threshold.
pub(crate) fn bounded_txid_depth_pairs(txids: &[Txid], depths: &[u32]) -> Option<Vec<(Txid, u32)>> {
    let mut distinct: Vec<u32> = depths.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    let count = txids.len().saturating_mul(distinct.len());
    if count > MAX_TXID_DEPTH_PAIRS {
        return None;
    }
    let mut pairs = Vec::with_capacity(count);
    for t in txids {
        for d in &distinct {
            pairs.push((*t, *d));
        }
    }
    Some(pairs)
}

/// A scripthash is `sha256(scriptPubKey)`. Mirrors `node_index::keys::Scripthash`
/// (the type `WatchHandle::add_scripthashes` takes) without this crate having to
/// depend on `node-index`.
type Scripthash = [u8; 32];

/// A privacy-preserving script-prefix bucket, as `(bits, masked_top32)` — the
/// type `WatchHandle::add_prefixes` takes. `bits` is the prefix length; the
/// `u32` is the top 32 bits of `sha256(spk)` masked to `bits`.
type PrefixKey = (u8, u32);

/// Cap on the coarseness multiplier's shift. A prefix `bits` below `K_MAX`
/// charges `1 << (K_MAX - bits)` units — honest bandwidth pricing (a coarser
/// bucket delivers proportionally more) — but capped here so a very coarse
/// bucket cannot demand an astronomical quota. With the cap a bucket `≥ 8` bits
/// coarser than the finest allowed charges a flat 256 units; the `K_MIN` floor
/// (operator config) is the real coarseness guard.
pub(crate) const MAX_PREFIX_UNIT_SHIFT: u8 = 8;

/// Quota cost of one prefix watch, priced by coarseness: the finest allowed
/// (`bits == k_max`) costs 1 unit, each bit coarser doubles, capped at
/// `1 << MAX_PREFIX_UNIT_SHIFT`.
pub(crate) fn prefix_units(bits: u8, k_max: u8) -> u64 {
    let shift = k_max.saturating_sub(bits).min(MAX_PREFIX_UNIT_SHIFT);
    1u64 << shift
}

/// Validate and normalize a client-supplied script prefix into a registry
/// bucket key. Rejects (returns `None`) when `bits` is outside the operator
/// range `[k_min, k_max]` or the prefix byte length is not exactly
/// `ceil(bits/8)` (a malformed frame). On success returns `(bits, masked_top32)`
/// — the same key the registry computes per script — paired with its quota cost.
pub(crate) fn parse_prefix(
    prefix: &[u8],
    bits: u32,
    k_min: u8,
    k_max: u8,
) -> Option<(PrefixKey, u64)> {
    if bits < k_min as u32 || bits > k_max as u32 {
        return None;
    }
    let bits = bits as u8;
    if prefix.len() != (bits as usize).div_ceil(8) {
        return None;
    }
    let key = node::events::prefix_bucket_key(prefix, bits);
    Some(((bits, key), prefix_units(bits, k_max)))
}

/// The node-registry operations [`WatchSet::replace`] drives to reconcile the
/// matcher's per-subscriber index with a new watch-set. Registry membership is a
/// per-subscriber set (idempotent re-add, floor-updated in place), so re-adding
/// a kept item is a no-op and only genuinely departed items are removed —
/// keeping the trait thin and letting `replace` stay decoupled from
/// `node::events::WatchHandle` (and mockable in tests).
pub(crate) trait WatchRegistry {
    fn add_scripthashes_with_floors(&self, items: &[(Scripthash, u64)]);
    fn remove_scripthashes(&self, scripthashes: &[Scripthash]);
    fn add_outpoints(&self, outpoints: &[OutPoint]);
    fn remove_outpoints(&self, outpoints: &[OutPoint]);
    fn add_txids(&self, txids: &[Txid], auto_close_depth: u32);
    fn remove_txids(&self, txids: &[Txid]);
    fn add_tx_depths(&self, items: &[(Txid, u32)]);
    fn remove_tx_depths(&self, items: &[(Txid, u32)]);
    fn add_prefixes(&self, prefixes: &[PrefixKey]);
    fn remove_prefixes(&self, prefixes: &[PrefixKey]);
}

impl WatchRegistry for node::events::WatchHandle {
    fn add_scripthashes_with_floors(&self, items: &[(Scripthash, u64)]) {
        node::events::WatchHandle::add_scripthashes_with_floors(self, items);
    }
    fn remove_scripthashes(&self, scripthashes: &[Scripthash]) {
        node::events::WatchHandle::remove_scripthashes(self, scripthashes);
    }
    fn add_outpoints(&self, outpoints: &[OutPoint]) {
        node::events::WatchHandle::add_outpoints(self, outpoints);
    }
    fn remove_outpoints(&self, outpoints: &[OutPoint]) {
        node::events::WatchHandle::remove_outpoints(self, outpoints);
    }
    fn add_txids(&self, txids: &[Txid], auto_close_depth: u32) {
        node::events::WatchHandle::add_txids(self, txids, auto_close_depth);
    }
    fn remove_txids(&self, txids: &[Txid]) {
        node::events::WatchHandle::remove_txids(self, txids);
    }
    fn add_tx_depths(&self, items: &[(Txid, u32)]) {
        node::events::WatchHandle::add_tx_depths(self, items);
    }
    fn remove_tx_depths(&self, items: &[(Txid, u32)]) {
        node::events::WatchHandle::remove_tx_depths(self, items);
    }
    fn add_prefixes(&self, prefixes: &[PrefixKey]) {
        node::events::WatchHandle::add_prefixes(self, prefixes);
    }
    fn remove_prefixes(&self, prefixes: &[PrefixKey]) {
        node::events::WatchHandle::remove_prefixes(self, prefixes);
    }
}

/// A complete desired watch-set for [`WatchSet::replace`]. Each field is the FULL
/// membership of its kind, not a delta. Descriptors arrive pre-expanded by the
/// carrier (`descriptor string → derived scripthashes`), so `replace` reconciles
/// by effective scripthash coverage without re-deriving.
pub(crate) struct DesiredWatchSet {
    /// Directly-watched scripthashes, each with its `min_value` floor (0 = none).
    pub scripts: Vec<(Scripthash, u64)>,
    /// Descriptor string → the scripthashes its window expands to (deduped by the
    /// carrier). A scripthash may also appear in `scripts` or another descriptor;
    /// it is charged once and owned by each source.
    pub descriptors: Vec<(String, Vec<Scripthash>)>,
    pub outpoints: Vec<OutPoint>,
    /// Lifecycle watches: `(txid, auto_close_depth)` (0 = persist until removed).
    pub lifecycles: Vec<(Txid, u32)>,
    /// Single-shot depth alarms: `(txid, depth)`.
    pub depth_alarms: Vec<(Txid, u32)>,
    /// Prefix buckets with their (coarseness-priced) unit cost.
    pub prefixes: Vec<(PrefixKey, u64)>,
}

/// Outcome of an atomic [`WatchSet::replace`].
#[derive(Debug)]
pub(crate) enum ReplaceOutcome {
    /// The replace applied; counts are by effective coverage.
    Accepted { added: u32, removed: u32, unchanged: u32 },
    /// The target's total unit cost exceeds the principal's quota; the watch-set
    /// is left unchanged.
    Rejected { required: u64, quota: u64 },
}

/// A subscription's live watch-set: the outpoints and scripts it watches, each
/// paired with the [`WatchLease`](satd_auth::WatchLease) backing its quota unit
/// (`None` when auth is disabled — loopback trust, unlimited).
#[derive(Default)]
pub(crate) struct WatchSet {
    outpoints: HashMap<OutPoint, Option<satd_auth::WatchLease>>,
    /// Effectively-watched scripthashes, each holding its quota lease. A
    /// scripthash is present here iff it has at least one owner (see
    /// `script_owners`): a direct `add_scripts` and/or one or more descriptors.
    /// The lease — and the script's registry watch — is released only when its
    /// **last** owner goes, so a script shared by a direct add and a descriptor
    /// (or by two descriptors) is not dropped while any source still wants it.
    scripts: HashMap<Scripthash, Option<satd_auth::WatchLease>>,
    /// Per-scripthash owner count = (1 if directly added) + (number of
    /// descriptors whose window currently contains it). Maintained in lockstep
    /// with `scripts`: a script is in `scripts` iff its count here is `> 0`.
    script_owners: HashMap<Scripthash, u32>,
    /// Scripthashes a direct `add_scripts` owns. Makes the direct add/remove
    /// path idempotent (a repeated direct add is one owner; one direct remove
    /// drops it) and distinct from descriptor ownership.
    script_direct: HashSet<Scripthash>,
    /// Descriptor string → the scripthashes its current `[start, start+gap)`
    /// window expands to. Retained so a `RemoveDescriptor` (or a re-asserted,
    /// slid window) can release exactly the scripts that descriptor contributed,
    /// decrementing `script_owners` rather than blindly dropping shared scripts.
    descriptors: HashMap<String, Vec<Scripthash>>,
    /// Lifecycle watches (one quota unit per txid). An `auto_close_depth` rides
    /// on the lifecycle watch server-side and is NOT a separate charged item.
    txids: HashMap<Txid, Option<satd_auth::WatchLease>>,
    /// Single-shot depth alarms, keyed `(txid, depth)` — one quota unit per
    /// pair, so an alarm on the same txid at two depths charges two units.
    tx_depths: HashMap<(Txid, u32), Option<satd_auth::WatchLease>>,
    /// Privacy-preserving script-prefix buckets (§7.5), keyed `(bits, masked)`.
    /// Unlike the others these are **priced by coarseness** — a coarser bucket
    /// (smaller `bits`) holds a multi-unit lease (see [`prefix_units`]).
    prefixes: HashMap<PrefixKey, Option<satd_auth::WatchLease>>,
}

impl WatchSet {
    /// Add outpoints, charging the quota only for items not already watched and
    /// registering the net-new ones via `register`. All-or-nothing per call.
    pub(crate) fn add_outpoints(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        incoming: impl IntoIterator<Item = OutPoint>,
        register: impl FnOnce(&[OutPoint]),
    ) {
        add_items(&mut self.outpoints, principal, incoming, "outpoints", register, |_| {});
    }

    /// Add **directly-watched** scripthashes (an `AddScripts` control message).
    /// `kind` only labels the rejection log line. `register` receives the net-new
    /// scripthashes (those charged against the quota); `reassert` receives
    /// scripthashes already watched, so the caller can refresh their per-item
    /// metadata (the `min_value` floor) without re-charging quota.
    ///
    /// Idempotent in direct ownership: re-adding a script already held directly
    /// only refreshes its floor. A script that a descriptor already watches is
    /// not re-charged (it is in `scripts`), but it gains a *second* owner here,
    /// so a later `remove_scripts` drops only the direct ownership and the
    /// descriptor keeps it alive.
    pub(crate) fn add_scripts(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        incoming: impl IntoIterator<Item = Scripthash>,
        kind: &'static str,
        register: impl FnOnce(&[Scripthash]),
        reassert: impl FnOnce(&[Scripthash]),
    ) {
        let items: Vec<Scripthash> = incoming.into_iter().collect();
        // The registry/lease/floor handling is unchanged: `add_items` charges
        // net-new (scripts not already in `scripts`) and refreshes re-asserts.
        add_items(&mut self.scripts, principal, items.iter().copied(), kind, register, reassert);
        // Reconcile direct ownership for whatever is now watched: every script
        // that ended up in `scripts` (net-new committed, or already held) and is
        // not yet a direct owner becomes one. A net-new that failed the quota is
        // absent, so it is correctly skipped.
        for s in &items {
            if self.scripts.contains_key(s) && self.script_direct.insert(*s) {
                *self.script_owners.entry(*s).or_insert(0) += 1;
            }
        }
    }

    /// Remove **direct** ownership of scripthashes (a `RemoveScripts` control
    /// message). A script's lease is released — and `unregister` called for it —
    /// only when this drops its **last** owner; a script a descriptor still
    /// watches stays. Removing a script held *only* by a descriptor is a no-op
    /// (slide or `RemoveDescriptor` the descriptor instead).
    pub(crate) fn remove_scripts(
        &mut self,
        incoming: impl IntoIterator<Item = Scripthash>,
        unregister: impl FnOnce(&[Scripthash]),
    ) {
        let mut to_release = Vec::new();
        for s in incoming {
            if self.script_direct.remove(&s) {
                self.release_owner(s, &mut to_release);
            }
        }
        remove_items(&mut self.scripts, to_release, unregister);
    }

    /// Register a descriptor's expanded window. `derived` is the full set of
    /// scripthashes the descriptor's current `[start, start+gap)` window expands
    /// to (the carrier expands it). Re-asserting the same descriptor with a
    /// **slid** window reconciles: scripts that left the window lose this
    /// descriptor's ownership (released if it was their last owner), scripts that
    /// entered are added. `register` / `reassert` / `unregister` mirror the
    /// other paths. All-or-nothing on quota: if the net-new scripts do not fit,
    /// the whole (re)assert is rejected and the descriptor's membership is left
    /// unchanged.
    pub(crate) fn add_descriptor(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        descriptor: String,
        derived: impl IntoIterator<Item = Scripthash>,
        register: impl FnOnce(&[Scripthash]),
        unregister: impl FnOnce(&[Scripthash]),
    ) {
        // Dedup the new membership, preserving first-seen order.
        let mut new: Vec<Scripthash> = Vec::new();
        let mut new_set = HashSet::new();
        for s in derived {
            if new_set.insert(s) {
                new.push(s);
            }
        }
        let old: Vec<Scripthash> = self.descriptors.get(&descriptor).cloned().unwrap_or_default();
        let old_set: HashSet<Scripthash> = old.iter().copied().collect();

        // Scripts entering this descriptor's window (gain it as an owner).
        let to_add: Vec<Scripthash> = new.iter().copied().filter(|s| !old_set.contains(s)).collect();
        // Among those, the ones not currently watched at all are net-new to the
        // registry and must fit the quota atomically.
        let net_new: Vec<Scripthash> =
            to_add.iter().copied().filter(|s| !self.scripts.contains_key(s)).collect();

        if !net_new.is_empty()
            && !reserve_scripts(&mut self.scripts, principal, &net_new, "descriptor", register)
        {
            // Quota/rate rejected the net-new batch: change nothing (membership,
            // ownership, and the prior window all stay as they were).
            return;
        }
        // Commit ownership for every script that gained this descriptor.
        for s in &to_add {
            *self.script_owners.entry(*s).or_insert(0) += 1;
        }

        // Scripts leaving the window lose this descriptor's ownership.
        let mut to_release = Vec::new();
        for s in &old {
            if !new_set.contains(s) {
                self.release_owner(*s, &mut to_release);
            }
        }
        remove_items(&mut self.scripts, to_release, unregister);

        self.descriptors.insert(descriptor, new);
    }

    /// Remove a descriptor entirely (a `RemoveDescriptor` control message),
    /// releasing each of its scripts whose last owner this drops. Scripts the
    /// descriptor shares with a direct add or another descriptor stay. Removing
    /// an unknown descriptor is a no-op.
    pub(crate) fn remove_descriptor(
        &mut self,
        descriptor: &str,
        unregister: impl FnOnce(&[Scripthash]),
    ) {
        let Some(members) = self.descriptors.remove(descriptor) else {
            return;
        };
        let mut to_release = Vec::new();
        for s in members {
            self.release_owner(s, &mut to_release);
        }
        remove_items(&mut self.scripts, to_release, unregister);
    }

    /// Atomically replace the entire watch-set with `desired` (a `SetWatchSet`).
    /// Reconciles by **effective scripthash coverage** — descriptors arrive
    /// pre-expanded, so a scripthash covered by both the old and new set (even if
    /// its *mechanism* changed: direct ↔ descriptor) is KEPT: its registry entry
    /// and quota unit are never dropped, so the matcher sees no unwatch/rewatch
    /// gap. Quota is all-or-nothing on the whole target: if the target's total
    /// unit cost exceeds the principal's ceiling the watch-set is left UNCHANGED
    /// and [`ReplaceOutcome::Rejected`] is returned. Runs under the per-connection
    /// watch-set lock the carrier already holds — the reconcile is not observable
    /// mid-flight.
    pub(crate) fn replace(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        desired: DesiredWatchSet,
        reg: &impl WatchRegistry,
    ) -> ReplaceOutcome {
        // ---- Build the target effective sets -----------------------------
        // Direct scripts (floor kept; direct floor wins over a descriptor's 0).
        let mut target_floors: HashMap<Scripthash, u64> = HashMap::new();
        let mut target_owners: HashMap<Scripthash, u32> = HashMap::new();
        let mut target_direct: HashSet<Scripthash> = HashSet::new();
        for (sh, floor) in &desired.scripts {
            if target_direct.insert(*sh) {
                *target_owners.entry(*sh).or_insert(0) += 1;
            }
            target_floors.insert(*sh, *floor);
        }
        // Descriptors: dedup each window, add an owner per membership.
        let mut target_descriptors: HashMap<String, Vec<Scripthash>> = HashMap::new();
        for (desc, shs) in &desired.descriptors {
            let mut seen = HashSet::new();
            let mut members = Vec::new();
            for sh in shs {
                if seen.insert(*sh) {
                    members.push(*sh);
                    *target_owners.entry(*sh).or_insert(0) += 1;
                    target_floors.entry(*sh).or_insert(0);
                }
            }
            target_descriptors.insert(desc.clone(), members);
        }
        let target_scripts: HashSet<Scripthash> = target_owners.keys().copied().collect();
        let target_outpoints: HashSet<OutPoint> = desired.outpoints.iter().copied().collect();
        let target_txids: HashMap<Txid, u32> = desired.lifecycles.iter().copied().collect();
        let target_depths: HashSet<(Txid, u32)> = desired.depth_alarms.iter().copied().collect();
        let target_prefixes: HashMap<PrefixKey, u64> = desired.prefixes.iter().copied().collect();

        let target_units: u64 = target_scripts.len() as u64
            + target_outpoints.len() as u64
            + target_txids.len() as u64
            + target_depths.len() as u64
            + target_prefixes.values().sum::<u64>();

        // ---- Diff vs the current set (registry lists + counts) -----------
        // For scripts and lifecycles the full target is re-registered so a kept
        // item's metadata (floor / auto-close) is refreshed in place; membership
        // is idempotent so this never double-registers. Only genuinely departed
        // items are removed. Metadata-less kinds register net-new only.
        let departed_scripts: Vec<Scripthash> =
            self.scripts.keys().filter(|k| !target_scripts.contains(*k)).copied().collect();
        let all_target_scripts: Vec<(Scripthash, u64)> =
            target_scripts.iter().map(|sh| (*sh, target_floors.get(sh).copied().unwrap_or(0))).collect();
        let departed_outpoints: Vec<OutPoint> =
            self.outpoints.keys().filter(|k| !target_outpoints.contains(*k)).copied().collect();
        let new_outpoints: Vec<OutPoint> =
            target_outpoints.iter().filter(|k| !self.outpoints.contains_key(*k)).copied().collect();
        let departed_txids: Vec<Txid> =
            self.txids.keys().filter(|k| !target_txids.contains_key(*k)).copied().collect();
        let departed_depths: Vec<(Txid, u32)> =
            self.tx_depths.keys().filter(|k| !target_depths.contains(*k)).copied().collect();
        let new_depths: Vec<(Txid, u32)> =
            target_depths.iter().filter(|k| !self.tx_depths.contains_key(*k)).copied().collect();
        let departed_prefixes: Vec<PrefixKey> =
            self.prefixes.keys().filter(|k| !target_prefixes.contains_key(*k)).copied().collect();
        let new_prefixes: Vec<PrefixKey> =
            target_prefixes.keys().filter(|k| !self.prefixes.contains_key(*k)).copied().collect();

        // Counts by effective coverage (kept = in both, added = net-new).
        let kept_scripts = self.scripts.len() - departed_scripts.len();
        let kept_outpoints = self.outpoints.len() - departed_outpoints.len();
        let kept_txids = self.txids.len() - departed_txids.len();
        let kept_depths = self.tx_depths.len() - departed_depths.len();
        let kept_prefixes = self.prefixes.len() - departed_prefixes.len();
        let unchanged = (kept_scripts + kept_outpoints + kept_txids + kept_depths + kept_prefixes) as u32;
        let removed = (departed_scripts.len()
            + departed_outpoints.len()
            + departed_txids.len()
            + departed_depths.len()
            + departed_prefixes.len()) as u32;
        let added = ((target_scripts.len() - kept_scripts)
            + (target_outpoints.len() - kept_outpoints)
            + (target_txids.len() - kept_txids)
            + (target_depths.len() - kept_depths)
            + (target_prefixes.len() - kept_prefixes)) as u32;

        // ---- Quota: atomically swap the reservation current → target -------
        // One locked read-modify-write in the store (`replace_watch`): no window
        // where the old units are freed but the target's are not yet held. So a
        // same-size swap fits at exactly the quota ceiling (no transient
        // over-count), and a REJECT leaves the reservation — and every existing
        // lease — exactly as it was (no rollback, no race where a concurrent
        // stream for this principal steals momentarily-freed units). On accept the
        // swap already handed off the old units, so defuse the old lease objects
        // before rebuilding lest their `Drop` release the same units twice.
        // `batch` is one lease, so per-item leases split cleanly (incl. prefixes).
        let batch: Option<satd_auth::WatchLease> = if let Some(p) = principal {
            let current_units = self.scripts.len() as u64
                + self.outpoints.len() as u64
                + self.txids.len() as u64
                + self.tx_depths.len() as u64
                + self
                    .prefixes
                    .values()
                    .filter_map(|l| l.as_ref().map(satd_auth::WatchLease::units))
                    .sum::<u64>();
            match p.replace_watch(current_units, target_units) {
                Ok(b) => {
                    self.defuse_leases();
                    Some(b)
                }
                Err(satd_auth::WatchReject::QuotaExceeded(q)) => {
                    return ReplaceOutcome::Rejected { required: target_units, quota: q.max };
                }
                Err(_) => {
                    // Lacks `stream:watch`: no headroom, set left unchanged.
                    return ReplaceOutcome::Rejected { required: target_units, quota: 0 };
                }
            }
        } else {
            None
        };

        // ---- Commit: rebuild membership, splitting per-item leases --------
        let mut b = batch;
        let mut take = |units: u64| b.as_mut().and_then(|l| l.split_off(units));
        self.scripts = target_scripts.iter().map(|sh| (*sh, take(1))).collect();
        self.outpoints = target_outpoints.iter().map(|op| (*op, take(1))).collect();
        self.txids = target_txids.keys().map(|t| (*t, take(1))).collect();
        self.tx_depths = target_depths.iter().map(|k| (*k, take(1))).collect();
        self.prefixes = target_prefixes.iter().map(|(k, units)| (*k, take(*units))).collect();
        self.script_owners = target_owners;
        self.script_direct = target_direct;
        self.descriptors = target_descriptors;

        // ---- Registry reconcile (kept items untouched → no gap) ----------
        if !all_target_scripts.is_empty() {
            reg.add_scripthashes_with_floors(&all_target_scripts);
        }
        if !departed_scripts.is_empty() {
            reg.remove_scripthashes(&departed_scripts);
        }
        if !new_outpoints.is_empty() {
            reg.add_outpoints(&new_outpoints);
        }
        if !departed_outpoints.is_empty() {
            reg.remove_outpoints(&departed_outpoints);
        }
        // Lifecycle re-adds refresh auto-close on kept txids; grouped by depth.
        let mut by_auto_close: HashMap<u32, Vec<Txid>> = HashMap::new();
        for (t, ac) in &target_txids {
            by_auto_close.entry(*ac).or_default().push(*t);
        }
        for (ac, txids) in by_auto_close {
            reg.add_txids(&txids, ac);
        }
        if !departed_txids.is_empty() {
            reg.remove_txids(&departed_txids);
        }
        if !new_depths.is_empty() {
            reg.add_tx_depths(&new_depths);
        }
        if !departed_depths.is_empty() {
            reg.remove_tx_depths(&departed_depths);
        }
        if !new_prefixes.is_empty() {
            reg.add_prefixes(&new_prefixes);
        }
        if !departed_prefixes.is_empty() {
            reg.remove_prefixes(&departed_prefixes);
        }

        ReplaceOutcome::Accepted { added, removed, unchanged }
    }

    /// Defuse (drop **without** releasing) every current per-item lease. Used by
    /// [`replace`](Self::replace) after an atomic quota swap
    /// ([`Principal::replace_watch`](satd_auth::Principal::replace_watch)) has
    /// already handed off the old units — their `Drop` must not release them a
    /// second time. The maps are rebuilt wholesale immediately after.
    fn defuse_leases(&mut self) {
        for v in self.outpoints.values_mut() {
            if let Some(l) = v.take() {
                l.defuse();
            }
        }
        for v in self.scripts.values_mut() {
            if let Some(l) = v.take() {
                l.defuse();
            }
        }
        for v in self.txids.values_mut() {
            if let Some(l) = v.take() {
                l.defuse();
            }
        }
        for v in self.tx_depths.values_mut() {
            if let Some(l) = v.take() {
                l.defuse();
            }
        }
        for v in self.prefixes.values_mut() {
            if let Some(l) = v.take() {
                l.defuse();
            }
        }
    }

    /// Drop one owner from a scripthash. If that was its last owner, queue it in
    /// `to_release` (the caller then `remove_items` it, dropping the lease and
    /// unregistering). Clears the `script_owners` entry on reaching zero so the
    /// map stays in lockstep with `scripts`.
    fn release_owner(&mut self, s: Scripthash, to_release: &mut Vec<Scripthash>) {
        if let Some(c) = self.script_owners.get_mut(&s) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.script_owners.remove(&s);
                to_release.push(s);
            }
        }
    }

    /// Remove outpoints, releasing each removed item's quota unit (lease drop)
    /// and de-registering the ones that were actually watched.
    pub(crate) fn remove_outpoints(
        &mut self,
        incoming: impl IntoIterator<Item = OutPoint>,
        unregister: impl FnOnce(&[OutPoint]),
    ) {
        remove_items(&mut self.outpoints, incoming, unregister);
    }

    /// Add txids, charging the quota only for items not already watched.
    pub(crate) fn add_transactions(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        incoming: impl IntoIterator<Item = Txid>,
        register: impl FnOnce(&[Txid]),
    ) {
        add_items(&mut self.txids, principal, incoming, "transactions", register, |_| {});
    }

    /// Remove txids, releasing each removed item's quota unit.
    pub(crate) fn remove_transactions(
        &mut self,
        incoming: impl IntoIterator<Item = Txid>,
        unregister: impl FnOnce(&[Txid]),
    ) {
        remove_items(&mut self.txids, incoming, unregister);
    }

    /// Add depth alarms keyed `(txid, depth)`, charging one unit per net-new
    /// pair. All-or-nothing per call, like the other add paths.
    pub(crate) fn add_tx_depths(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        incoming: impl IntoIterator<Item = (Txid, u32)>,
        register: impl FnOnce(&[(Txid, u32)]),
    ) {
        add_items(&mut self.tx_depths, principal, incoming, "tx_depths", register, |_| {});
    }

    /// Remove depth alarms, releasing each removed pair's quota unit.
    pub(crate) fn remove_tx_depths(
        &mut self,
        incoming: impl IntoIterator<Item = (Txid, u32)>,
        unregister: impl FnOnce(&[(Txid, u32)]),
    ) {
        remove_items(&mut self.tx_depths, incoming, unregister);
    }

    /// Add prefix watches, charging each net-new bucket its coarseness-priced
    /// unit cost (see [`prefix_units`]). `incoming` yields `(key, units)` pairs
    /// from [`parse_prefix`]. All-or-nothing per call like the other add paths.
    pub(crate) fn add_prefixes(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        incoming: impl IntoIterator<Item = (PrefixKey, u64)>,
        register: impl FnOnce(&[PrefixKey]),
    ) {
        // Collect the (key → cost) of net-new buckets up front so the priced
        // charge can read each item's cost. `add_items_priced` re-derives the
        // cost via the closure; a HashMap lookup keeps the two in lockstep.
        let costs: HashMap<PrefixKey, u64> = incoming.into_iter().collect();
        add_items_priced(
            &mut self.prefixes,
            principal,
            costs.keys().copied(),
            |k| costs.get(k).copied().unwrap_or(1),
            "prefixes",
            register,
            |_| {},
        );
    }

    /// Remove prefix watches, releasing each removed bucket's (multi-unit) lease.
    pub(crate) fn remove_prefixes(
        &mut self,
        incoming: impl IntoIterator<Item = PrefixKey>,
        unregister: impl FnOnce(&[PrefixKey]),
    ) {
        remove_items(&mut self.prefixes, incoming, unregister);
    }

    /// Total watched items across all kinds. Used to enforce the per-connection
    /// watch-set cap and in tests. A prefix counts as one item regardless of its
    /// (coarseness-priced) unit cost.
    pub(crate) fn len(&self) -> usize {
        self.outpoints.len()
            + self.scripts.len()
            + self.txids.len()
            + self.tx_depths.len()
            + self.prefixes.len()
    }
}

fn add_items<T: Eq + Hash + Copy>(
    held: &mut HashMap<T, Option<satd_auth::WatchLease>>,
    principal: Option<&satd_auth::Principal>,
    incoming: impl IntoIterator<Item = T>,
    kind: &'static str,
    register: impl FnOnce(&[T]),
    reassert: impl FnOnce(&[T]),
) {
    // The common case: every item costs exactly one unit.
    add_items_priced(held, principal, incoming, |_| 1, kind, register, reassert);
}

/// Generalization of [`add_items`] where each item carries its own quota cost
/// (`cost`). The whole net-new batch is reserved atomically as `sum(cost)` units,
/// then split into per-item leases via [`WatchLease::split_off`], so a removal
/// returns exactly that item's units. Used by the coarseness-priced prefix add;
/// `add_items` is the `cost = 1` specialization.
fn add_items_priced<T: Eq + Hash + Copy>(
    held: &mut HashMap<T, Option<satd_auth::WatchLease>>,
    principal: Option<&satd_auth::Principal>,
    incoming: impl IntoIterator<Item = T>,
    cost: impl Fn(&T) -> u64,
    kind: &'static str,
    register: impl FnOnce(&[T]),
    reassert: impl FnOnce(&[T]),
) {
    // Partition `incoming` into net-new items (not yet watched) and re-asserted
    // items (already watched). Both are deduped within this message via `seen`.
    let mut seen = HashSet::new();
    let mut net_new: Vec<T> = Vec::new();
    let mut reasserted: Vec<T> = Vec::new();
    for it in incoming {
        if !seen.insert(it) {
            continue; // intra-message duplicate
        }
        if held.contains_key(&it) {
            reasserted.push(it);
        } else {
            net_new.push(it);
        }
    }

    // Re-asserted items are already inside the quota, so refreshing their
    // per-item metadata (e.g. a script's `min_value` floor) is free: it charges
    // neither quota nor a rate token. This MUST happen even when there is no
    // net-new item — a client re-asserting a held watch to change its floor is
    // the whole point. (For item kinds with no mutable metadata the closure is
    // a no-op.)
    if !reasserted.is_empty() {
        reassert(&reasserted);
    }

    if net_new.is_empty() {
        // No new watches to charge — re-assert-only or empty add. The metadata
        // refresh above (if any) has already run.
        return;
    }

    // Per-add rate limit (C4): bound the RATE of EFFECTIVE watch-adds — those
    // that register net-new items — not just the steady-state quota. One
    // effective add = one token. Placed AFTER the net-new/dedup short-circuit
    // so a no-op (empty or fully-duplicate) add cannot burn the bucket out from
    // under a subsequent real add. The bucket is per-principal (shared across
    // the tenant's connections and with the connection-admission check), so an
    // operator should size the policy with headroom for the expected add
    // cadence — e.g. a descriptor sliding window spends one token per
    // AddDescriptor slide. Operator/loopback and no-policy principals always
    // Allow. An over-budget add is shed without tearing down the stream — no
    // per-message ack, same posture as the quota-reject path below.
    if let Some(p) = principal
        && let satd_auth::RateDecision::Throttle { retry_after_secs } = p.check_rate()
    {
        warn!(
            target: "events::watchset",
            kind,
            retry_after_secs,
            "watch add rate-limited; skipping",
        );
        return;
    }
    let total: u64 = net_new.iter().map(&cost).sum();
    match principal {
        // Reserve all net-new units atomically (all-or-nothing), then split
        // the batch into per-item leases so each can be released on removal.
        Some(p) => match p.acquire_watch(total) {
            Ok(mut batch) => {
                register(&net_new);
                for it in net_new {
                    let lease = batch.split_off(cost(&it));
                    // Conservation invariant: acquire_watch charged exactly
                    // `total` units = sum(cost), and we split exactly that many,
                    // so every split yields Some. A None here would mean an item
                    // charged in the store with no per-item lease backing it —
                    // a unit leaked until teardown. Pin it so a future refactor
                    // can't silently regress.
                    debug_assert!(
                        lease.is_some(),
                        "split_off drained before all items got a lease",
                    );
                    held.insert(it, lease);
                }
            }
            Err(reject) => {
                warn!(
                    target: "events::watchset",
                    kind,
                    reject = ?reject,
                    "watch add rejected (capability or quota)",
                );
            }
        },
        // Auth disabled (loopback trust): unlimited, no lease.
        None => {
            register(&net_new);
            for it in net_new {
                held.insert(it, None);
            }
        }
    }
}

/// Reserve quota for a batch of net-new scripthashes (one unit each), all-or-
/// nothing, inserting each with its split lease and calling `register` on
/// success. Returns whether the batch was committed (always `true` when auth is
/// disabled or the batch is empty). Mirrors the net-new arm of
/// [`add_items_priced`], but *reports* success so a descriptor (re)assert can
/// stay atomic — rejecting the whole window rather than partially registering.
fn reserve_scripts(
    held: &mut HashMap<Scripthash, Option<satd_auth::WatchLease>>,
    principal: Option<&satd_auth::Principal>,
    net_new: &[Scripthash],
    kind: &'static str,
    register: impl FnOnce(&[Scripthash]),
) -> bool {
    if net_new.is_empty() {
        return true;
    }
    // Per-add rate limit (C4): one effective add = one token, checked after the
    // empty short-circuit so a no-op cannot burn the bucket.
    if let Some(p) = principal
        && let satd_auth::RateDecision::Throttle { retry_after_secs } = p.check_rate()
    {
        warn!(
            target: "events::watchset",
            kind,
            retry_after_secs,
            "watch add rate-limited; skipping",
        );
        return false;
    }
    match principal {
        Some(p) => match p.acquire_watch(net_new.len() as u64) {
            Ok(mut batch) => {
                register(net_new);
                for s in net_new {
                    let lease = batch.split_off(1);
                    debug_assert!(
                        lease.is_some(),
                        "split_off drained before all scripts got a lease",
                    );
                    held.insert(*s, lease);
                }
                true
            }
            Err(reject) => {
                warn!(
                    target: "events::watchset",
                    kind,
                    reject = ?reject,
                    "watch add rejected (capability or quota)",
                );
                false
            }
        },
        // Auth disabled (loopback trust): unlimited, no lease.
        None => {
            register(net_new);
            for s in net_new {
                held.insert(*s, None);
            }
            true
        }
    }
}

fn remove_items<T: Eq + Hash + Copy>(
    held: &mut HashMap<T, Option<satd_auth::WatchLease>>,
    incoming: impl IntoIterator<Item = T>,
    unregister: impl FnOnce(&[T]),
) {
    let mut removed = Vec::new();
    for it in incoming {
        // `remove` drops the item's lease here, releasing its unit. A request
        // to remove something not watched is a no-op (no spurious unregister).
        if held.remove(&it).is_some() {
            removed.push(it);
        }
    }
    if !removed.is_empty() {
        unregister(&removed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satd_auth::{Accounting, Capability, CapabilitySet, LocalAccounting, Principal};
    use std::sync::Arc;

    fn op(b: u8, vout: u32) -> OutPoint {
        use bitcoin::hashes::Hash;
        OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([b; 32]),
            ),
            vout,
        }
    }

    /// A principal with `stream:watch` and a quota of `max` units.
    fn tenant(max: u64) -> (Principal, Arc<dyn Accounting>) {
        let acct: Arc<dyn Accounting> = Arc::new(LocalAccounting::new());
        let p = Principal::token(
            Arc::from("tenant"),
            CapabilitySet::EMPTY.with(Capability::StreamWatch),
            Some(max),
            None,
            acct.clone(),
        );
        (p, acct)
    }

    #[test]
    fn add_then_remove_releases_quota_per_item() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        let mut registered = 0;
        ws.add_outpoints(Some(&p), [op(1, 0), op(2, 0), op(3, 0)], |items| {
            registered = items.len();
        });
        assert_eq!(registered, 3);
        assert_eq!(q.current("tenant"), 3, "three items charged 3 units");
        assert_eq!(ws.len(), 3);

        // Remove one item → exactly one unit released.
        let mut unregistered = 0;
        ws.remove_outpoints([op(2, 0)], |items| unregistered = items.len());
        assert_eq!(unregistered, 1);
        assert_eq!(q.current("tenant"), 2, "per-remove release frees one unit");
        assert_eq!(ws.len(), 2);
    }

    #[test]
    fn cross_message_re_add_is_charged_once() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        ws.add_outpoints(Some(&p), [op(1, 0), op(2, 0)], |_| {});
        assert_eq!(q.current("tenant"), 2);

        // A SEPARATE message re-asserts op(1) and adds op(3): only op(3) is new.
        let mut registered = Vec::new();
        ws.add_outpoints(Some(&p), [op(1, 0), op(3, 0)], |items| {
            registered = items.to_vec();
        });
        assert_eq!(registered, vec![op(3, 0)], "only the net-new item registers");
        assert_eq!(q.current("tenant"), 3, "the re-asserted item is not double-charged");
    }

    fn sh(b: u8) -> Scripthash {
        [b; 32]
    }

    #[test]
    fn add_scripts_reasserts_held_scripts_for_metadata_refresh() {
        // Regression: re-asserting an already-watched scripthash (e.g. to change
        // its `min_value` floor) must surface that script to the caller via the
        // `reassert` callback — WITHOUT charging quota or a rate token — even
        // when the add contains no net-new item. Previously the net-new
        // short-circuit dropped the whole add and the floor was never refreshed.
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        let mut net_new = Vec::new();
        ws.add_scripts(Some(&p), [sh(1), sh(2)], "scripts", |s| net_new = s.to_vec(), |_| {});
        assert_eq!(net_new, vec![sh(1), sh(2)], "first add registers both as net-new");
        assert_eq!(q.current("tenant"), 2);

        // Re-assert sh(1) (held) and add sh(3) (new) in one message: sh(1) must
        // reach `reassert`, sh(3) must reach `register`, and only sh(3) is charged.
        let mut net_new2 = Vec::new();
        let mut reasserted = Vec::new();
        ws.add_scripts(
            Some(&p),
            [sh(1), sh(3)],
            "scripts",
            |s| net_new2 = s.to_vec(),
            |s| reasserted = s.to_vec(),
        );
        assert_eq!(net_new2, vec![sh(3)], "only the new script registers");
        assert_eq!(reasserted, vec![sh(1)], "the held script is surfaced for refresh");
        assert_eq!(q.current("tenant"), 3, "re-assert charges no extra quota");

        // A re-assert-ONLY message (no net-new) must still fire `reassert`.
        let mut net_new3 = false;
        let mut reasserted3 = Vec::new();
        ws.add_scripts(
            Some(&p),
            [sh(1), sh(2)],
            "scripts",
            |_| net_new3 = true,
            |s| reasserted3 = s.to_vec(),
        );
        assert!(!net_new3, "no net-new registration on a re-assert-only add");
        assert_eq!(reasserted3, vec![sh(1), sh(2)], "both held scripts are surfaced");
        assert_eq!(q.current("tenant"), 3, "re-assert-only add charges nothing");
    }

    #[test]
    fn add_scripts_reassert_does_not_burn_rate_token() {
        use satd_auth::RatePolicy;
        // burst = 1: the first (net-new) add spends the only token; a subsequent
        // re-assert-only add must NOT be throttled (it spends no token) and must
        // still fire `reassert`.
        let acct: Arc<dyn Accounting> = Arc::new(LocalAccounting::new());
        let p = Principal::token(
            Arc::from("tenant"),
            CapabilitySet::EMPTY.with(Capability::StreamWatch),
            Some(100),
            Some(RatePolicy { burst: 1, per_sec: 1 }),
            acct.clone(),
        );
        let mut ws = WatchSet::default();

        ws.add_scripts(Some(&p), [sh(1)], "scripts", |_| {}, |_| {});
        // Bucket now empty. Re-assert sh(1): a net-new add here would be
        // throttled, but a re-assert must bypass the rate limiter entirely.
        let mut reasserted = Vec::new();
        ws.add_scripts(Some(&p), [sh(1)], "scripts", |_| {}, |s| reasserted = s.to_vec());
        assert_eq!(reasserted, vec![sh(1)], "re-assert fires even with an empty rate bucket");
    }

    #[test]
    fn over_quota_add_is_all_or_nothing() {
        let (p, acct) = tenant(2);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        // Three net-new items but quota is 2 → the whole add is rejected.
        let mut registered = false;
        ws.add_outpoints(Some(&p), [op(1, 0), op(2, 0), op(3, 0)], |_| registered = true);
        assert!(!registered, "an add that overflows quota registers nothing");
        assert_eq!(q.current("tenant"), 0, "no units charged on a rejected add");
        assert_eq!(ws.len(), 0);
    }

    fn txid(b: u8) -> Txid {
        use bitcoin::hashes::Hash;
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([b; 32]))
    }

    #[test]
    fn add_transactions_charges_and_releases_quota() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        ws.add_transactions(Some(&p), [txid(1), txid(2)], |items| {
            assert_eq!(items.len(), 2)
        });
        assert_eq!(q.current("tenant"), 2, "two txids charge 2 units");
        ws.remove_transactions([txid(1)], |items| assert_eq!(items.len(), 1));
        assert_eq!(q.current("tenant"), 1, "per-remove release frees one unit");
        assert_eq!(ws.len(), 1);
    }

    #[test]
    fn bounded_pairs_dedups_and_caps() {
        // Distinct depths only (repeated thresholds can't inflate the product).
        let pairs = bounded_txid_depth_pairs(&[txid(1), txid(2)], &[3, 3, 1, 3]).unwrap();
        assert_eq!(pairs.len(), 4, "2 txids × {{1,3}} distinct = 4 pairs");

        // Over the cap → rejected (None) BEFORE allocating the product. 64 txids
        // × 4096 distinct depths = 262144 > MAX_TXID_DEPTH_PAIRS (65536).
        let many_depths: Vec<u32> = (1..=4096).collect();
        let many_txids: Vec<Txid> = (0..64).map(txid).collect();
        assert!(
            bounded_txid_depth_pairs(&many_txids, &many_depths).is_none(),
            "huge cross-product is rejected, not allocated",
        );
    }

    #[test]
    fn add_tx_depths_charges_per_pair() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        // Two depths on the SAME txid are two distinct items → two units.
        ws.add_tx_depths(Some(&p), [(txid(1), 1), (txid(1), 3)], |items| {
            assert_eq!(items.len(), 2)
        });
        assert_eq!(q.current("tenant"), 2, "(X,1) and (X,3) charge 2 units");
        assert_eq!(ws.len(), 2);

        // Re-adding (X,1) dedups; (X,6) is net-new.
        let mut reg = Vec::new();
        ws.add_tx_depths(Some(&p), [(txid(1), 1), (txid(1), 6)], |items| {
            reg = items.to_vec()
        });
        assert_eq!(reg, vec![(txid(1), 6)], "only the net-new pair registers");
        assert_eq!(q.current("tenant"), 3);

        // Removing one pair releases exactly one unit.
        ws.remove_tx_depths([(txid(1), 3)], |items| assert_eq!(items.len(), 1));
        assert_eq!(q.current("tenant"), 2, "per-pair release frees one unit");
        assert_eq!(ws.len(), 2);
    }

    #[test]
    fn removing_unwatched_item_is_a_noop() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        ws.add_outpoints(Some(&p), [op(1, 0)], |_| {});

        let mut called = false;
        ws.remove_outpoints([op(9, 9)], |_| called = true);
        assert!(!called, "removing something not watched does not unregister");
        assert_eq!(q.current("tenant"), 1, "quota unchanged");
    }

    #[test]
    fn dropping_watchset_releases_all_quota() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        ws.add_outpoints(Some(&p), [op(1, 0), op(2, 0)], |_| {});
        assert_eq!(q.current("tenant"), 2);
        drop(ws);
        assert_eq!(q.current("tenant"), 0, "full teardown releases all leases");
    }

    #[test]
    fn no_principal_is_unlimited_and_leaseless() {
        let mut ws = WatchSet::default();
        let mut registered = 0;
        // No principal → no quota, items still tracked for dedup/removal.
        ws.add_outpoints(None, [op(1, 0), op(1, 0), op(2, 0)], |items| {
            registered = items.len();
        });
        assert_eq!(registered, 2, "intra-message dedup still applies");
        assert_eq!(ws.len(), 2);
    }

    #[test]
    fn rate_limited_add_is_shed_without_dropping() {
        use satd_auth::RatePolicy;
        // burst = 1 → the first add is within budget, the second (immediate)
        // add is throttled.
        let acct: Arc<dyn Accounting> = Arc::new(LocalAccounting::new());
        let p = Principal::token(
            Arc::from("tenant"),
            CapabilitySet::EMPTY.with(Capability::StreamWatch),
            Some(100),
            Some(RatePolicy { burst: 1, per_sec: 1 }),
            acct.clone(),
        );
        let q = acct.quota();
        let mut ws = WatchSet::default();

        let mut reg1 = 0;
        ws.add_outpoints(Some(&p), [op(1, 0)], |items| reg1 = items.len());
        assert_eq!(reg1, 1, "first add is within the burst");
        assert_eq!(q.current("tenant"), 1);

        // Bucket now empty; an immediate second add is throttled → nothing
        // registered or charged, and the existing watch-set is intact (no
        // teardown).
        let mut reg2 = 0;
        ws.add_outpoints(Some(&p), [op(2, 0)], |items| reg2 = items.len());
        assert_eq!(reg2, 0, "rate-limited add registers nothing");
        assert_eq!(q.current("tenant"), 1, "rate-limited add charges no quota");
        assert_eq!(ws.len(), 1, "earlier watch remains after a shed add");
    }

    #[test]
    fn prefix_units_scale_with_coarseness() {
        // Finest allowed = 1 unit; each bit coarser doubles, capped.
        assert_eq!(prefix_units(32, 32), 1);
        assert_eq!(prefix_units(31, 32), 2);
        assert_eq!(prefix_units(24, 32), 1 << 8);
        // 24 bits coarser than k_max is capped, not 1<<24.
        assert_eq!(prefix_units(8, 32), 1 << MAX_PREFIX_UNIT_SHIFT);
        // Finest is relative to k_max, not an absolute.
        assert_eq!(prefix_units(16, 16), 1);
    }

    #[test]
    fn parse_prefix_validates_range_and_length() {
        // valid 16-bit prefix (2 bytes)
        assert!(parse_prefix(&[0xab, 0xcd], 16, 8, 32).is_some());
        // below the operator minimum
        assert!(parse_prefix(&[0xab], 4, 8, 32).is_none());
        // above the operator maximum
        assert!(parse_prefix(&[0u8; 5], 40, 8, 32).is_none());
        // byte length must be exactly ceil(bits/8): 16 bits needs 2 bytes
        assert!(parse_prefix(&[0xab], 16, 8, 32).is_none());
        // 13 bits → ceil = 2 bytes
        assert!(parse_prefix(&[0xab, 0xc0], 13, 8, 32).is_some());
    }

    #[test]
    fn add_prefixes_charges_by_coarseness_and_releases() {
        let (p, acct) = tenant(1000);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        let c24 = parse_prefix(&[0xaa, 0xbb, 0xcc], 24, 8, 32).unwrap(); // 1<<8 units
        let c32 = parse_prefix(&[0x11, 0x22, 0x33, 0x44], 32, 8, 32).unwrap(); // 1 unit

        let mut reg = 0;
        ws.add_prefixes(Some(&p), [c24, c32], |keys| reg = keys.len());
        assert_eq!(reg, 2);
        assert_eq!(q.current("tenant"), (1 << 8) + 1, "coarseness-priced units");
        assert_eq!(ws.len(), 2, "two buckets = two items regardless of unit cost");

        // Removing the coarse bucket releases all of its units.
        ws.remove_prefixes([c24.0], |keys| assert_eq!(keys.len(), 1));
        assert_eq!(q.current("tenant"), 1, "per-bucket release frees its full cost");
        assert_eq!(ws.len(), 1);
    }

    #[test]
    fn add_prefixes_dedups_cross_message() {
        let (p, acct) = tenant(1000);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        let a = parse_prefix(&[0xaa, 0xbb], 16, 8, 32).unwrap();
        ws.add_prefixes(Some(&p), [a], |_| {});
        let charged = q.current("tenant");

        let mut called = false;
        ws.add_prefixes(Some(&p), [a], |_| called = true);
        assert!(!called, "re-asserted bucket registers nothing");
        assert_eq!(q.current("tenant"), charged, "dedup: the bucket is not double-charged");
    }

    #[test]
    fn over_quota_prefix_add_is_all_or_nothing() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        // A k=24 prefix costs 1<<8 = 256 units > quota 10 → whole add rejected.
        let c = parse_prefix(&[0xaa, 0xbb, 0xcc], 24, 8, 32).unwrap();
        let mut registered = false;
        ws.add_prefixes(Some(&p), [c], |_| registered = true);
        assert!(!registered, "a prefix add that overflows quota registers nothing");
        assert_eq!(q.current("tenant"), 0);
        assert_eq!(ws.len(), 0);
    }

    #[test]
    fn no_op_add_does_not_consume_rate_budget() {
        // Regression for the review fix: the rate check sits AFTER the
        // net-new/dedup short-circuit, so an empty or fully-duplicate add costs
        // no token and cannot throttle a later real add. With burst = 2:
        //   add(op1) → registers (token 2→1)
        //   add(op1) again (duplicate, no-op) → must NOT consume a token
        //   add(op2) → still has budget → registers (token 1→0)
        // If the check ran before dedup, the no-op would spend the 2nd token and
        // op2 would be throttled (ws.len() == 1).
        use satd_auth::RatePolicy;
        let acct: Arc<dyn Accounting> = Arc::new(LocalAccounting::new());
        let p = Principal::token(
            Arc::from("tenant"),
            CapabilitySet::EMPTY.with(Capability::StreamWatch),
            Some(100),
            Some(RatePolicy { burst: 2, per_sec: 1 }),
            acct.clone(),
        );
        let mut ws = WatchSet::default();

        ws.add_outpoints(Some(&p), [op(1, 0)], |_| {});
        ws.add_outpoints(Some(&p), [op(1, 0)], |_| {}); // duplicate → no-op, free
        let mut reg3 = 0;
        ws.add_outpoints(Some(&p), [op(2, 0)], |items| reg3 = items.len());

        assert_eq!(reg3, 1, "a no-op duplicate must not have spent the rate budget");
        assert_eq!(ws.len(), 2, "both distinct watches registered");
    }

    // --- descriptor membership + ownership (RemoveDescriptor) ------------------

    #[test]
    fn descriptor_add_then_remove_releases_its_scripts() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        let mut registered = Vec::new();
        ws.add_descriptor(
            Some(&p),
            "D".into(),
            [sh(1), sh(2), sh(3)],
            |s| registered = s.to_vec(),
            |_| {},
        );
        assert_eq!(registered, vec![sh(1), sh(2), sh(3)], "every derived script registers");
        assert_eq!(q.current("tenant"), 3, "one unit per derived script");
        assert_eq!(ws.len(), 3);

        let mut unregistered = Vec::new();
        ws.remove_descriptor("D", |s| unregistered = s.to_vec());
        assert_eq!(unregistered.len(), 3, "removing the descriptor releases all its scripts");
        assert_eq!(q.current("tenant"), 0, "all units returned");
        assert_eq!(ws.len(), 0);
    }

    #[test]
    fn script_shared_by_direct_add_and_descriptor_held_until_last_owner() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        // Directly watch sh(2), then a descriptor whose window also contains it.
        ws.add_scripts(Some(&p), [sh(2)], "scripts", |_| {}, |_| {});
        assert_eq!(q.current("tenant"), 1);
        let mut registered = Vec::new();
        ws.add_descriptor(
            Some(&p),
            "D".into(),
            [sh(1), sh(2), sh(3)],
            |s| registered = s.to_vec(),
            |_| {},
        );
        // sh(2) was already watched → only sh(1), sh(3) are net-new.
        assert_eq!(registered, vec![sh(1), sh(3)], "the shared script is not re-charged");
        assert_eq!(q.current("tenant"), 3, "sh1 + sh2(direct) + sh3");

        // Removing the descriptor drops sh(1)/sh(3) but NOT sh(2) — the direct
        // add still owns it.
        let mut unregistered = Vec::new();
        ws.remove_descriptor("D", |s| unregistered = s.to_vec());
        assert_eq!(unregistered.len(), 2, "only the descriptor-only scripts release");
        assert!(!unregistered.contains(&sh(2)), "the shared, still-direct script stays");
        assert_eq!(q.current("tenant"), 1, "sh(2) lease held by its direct owner");
        assert_eq!(ws.len(), 1);

        // Now the direct remove drops the last owner.
        ws.remove_scripts([sh(2)], |_| {});
        assert_eq!(q.current("tenant"), 0);
        assert_eq!(ws.len(), 0);
    }

    #[test]
    fn two_overlapping_descriptors_each_hold_the_shared_script() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        ws.add_descriptor(Some(&p), "D1".into(), [sh(1), sh(2)], |_| {}, |_| {});
        ws.add_descriptor(Some(&p), "D2".into(), [sh(2), sh(3)], |_| {}, |_| {});
        // sh(2) shared → charged once; total sh1 + sh2 + sh3.
        assert_eq!(q.current("tenant"), 3);
        assert_eq!(ws.len(), 3);

        // Drop D1: sh(1) releases, sh(2) stays (still owned by D2).
        let mut unregistered = Vec::new();
        ws.remove_descriptor("D1", |s| unregistered = s.to_vec());
        assert_eq!(unregistered, vec![sh(1)], "only D1's exclusive script releases");
        assert_eq!(q.current("tenant"), 2);

        // Drop D2: sh(2) and sh(3) release.
        ws.remove_descriptor("D2", |_| {});
        assert_eq!(q.current("tenant"), 0);
        assert_eq!(ws.len(), 0);
    }

    #[test]
    fn re_asserting_a_descriptor_with_a_slid_window_reconciles() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        ws.add_descriptor(Some(&p), "D".into(), [sh(1), sh(2), sh(3)], |_| {}, |_| {});
        assert_eq!(q.current("tenant"), 3);

        // Slide the window forward: {1,2,3} → {3,4,5}. 1,2 leave; 4,5 enter; 3 stays.
        let mut registered = Vec::new();
        let mut unregistered = Vec::new();
        ws.add_descriptor(
            Some(&p),
            "D".into(),
            [sh(3), sh(4), sh(5)],
            |s| registered = s.to_vec(),
            |s| unregistered = s.to_vec(),
        );
        assert_eq!(registered, vec![sh(4), sh(5)], "scripts entering the window register");
        let mut u = unregistered.clone();
        u.sort();
        assert_eq!(u, vec![sh(1), sh(2)], "scripts leaving the window release");
        assert_eq!(q.current("tenant"), 3, "net quota unchanged: -2 +2");
        assert_eq!(ws.len(), 3);
    }

    #[test]
    fn remove_scripts_on_a_descriptor_only_script_is_a_noop() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        ws.add_descriptor(Some(&p), "D".into(), [sh(1)], |_| {}, |_| {});
        assert_eq!(q.current("tenant"), 1);

        // A direct RemoveScripts does not touch descriptor ownership.
        let mut unregistered = 0;
        ws.remove_scripts([sh(1)], |s| unregistered = s.len());
        assert_eq!(unregistered, 0, "no direct owner to drop");
        assert_eq!(q.current("tenant"), 1, "the descriptor still holds it");
        assert_eq!(ws.len(), 1);
    }

    #[test]
    fn descriptor_add_is_all_or_nothing_on_quota() {
        let (p, acct) = tenant(2); // room for 2 units only
        let q = acct.quota();
        let mut ws = WatchSet::default();

        // A 3-script descriptor does not fit → the whole add is rejected.
        let mut registered = false;
        ws.add_descriptor(
            Some(&p),
            "D".into(),
            [sh(1), sh(2), sh(3)],
            |_| registered = true,
            |_| {},
        );
        assert!(!registered, "an over-quota descriptor registers nothing");
        assert_eq!(q.current("tenant"), 0, "no units charged");
        assert_eq!(ws.len(), 0);
        // And its membership was not recorded, so a later remove is a clean no-op.
        ws.remove_descriptor("D", |_| panic!("nothing should release"));
    }

    #[test]
    fn re_adding_an_identical_descriptor_window_is_idempotent() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        ws.add_descriptor(Some(&p), "D".into(), [sh(1), sh(2)], |_| {}, |_| {});
        // Same descriptor, same window: nothing net-new, nothing released.
        let mut registered = false;
        let mut unregistered = false;
        ws.add_descriptor(
            Some(&p),
            "D".into(),
            [sh(1), sh(2)],
            |_| registered = true,
            |_| unregistered = true,
        );
        assert!(!registered && !unregistered, "a no-op re-assert touches nothing");
        assert_eq!(q.current("tenant"), 2, "no double-charge");

        // One removal clears it (ownership was counted once, not twice).
        ws.remove_descriptor("D", |_| {});
        assert_eq!(q.current("tenant"), 0);
    }

    #[test]
    fn remove_unknown_descriptor_is_a_noop() {
        let mut ws = WatchSet::default();
        ws.remove_descriptor("never-added", |_| panic!("must not unregister anything"));
        assert_eq!(ws.len(), 0);
    }

    // Records the registry reconcile calls so a test can assert which items were
    // (de)registered — in particular that a KEPT scripthash is never removed.
    #[derive(Default)]
    struct MockReg {
        added_scripts: std::cell::RefCell<Vec<Scripthash>>,
        removed_scripts: std::cell::RefCell<Vec<Scripthash>>,
    }
    impl WatchRegistry for MockReg {
        fn add_scripthashes_with_floors(&self, items: &[(Scripthash, u64)]) {
            self.added_scripts.borrow_mut().extend(items.iter().map(|(s, _)| *s));
        }
        fn remove_scripthashes(&self, s: &[Scripthash]) {
            self.removed_scripts.borrow_mut().extend_from_slice(s);
        }
        fn add_outpoints(&self, _: &[OutPoint]) {}
        fn remove_outpoints(&self, _: &[OutPoint]) {}
        fn add_txids(&self, _: &[Txid], _: u32) {}
        fn remove_txids(&self, _: &[Txid]) {}
        fn add_tx_depths(&self, _: &[(Txid, u32)]) {}
        fn remove_tx_depths(&self, _: &[(Txid, u32)]) {}
        fn add_prefixes(&self, _: &[PrefixKey]) {}
        fn remove_prefixes(&self, _: &[PrefixKey]) {}
    }

    fn desired_scripts(scripts: &[Scripthash]) -> DesiredWatchSet {
        DesiredWatchSet {
            scripts: scripts.iter().map(|s| (*s, 0)).collect(),
            descriptors: Vec::new(),
            outpoints: Vec::new(),
            lifecycles: Vec::new(),
            depth_alarms: Vec::new(),
            prefixes: Vec::new(),
        }
    }

    #[test]
    fn replace_at_quota_disjoint_swap_fits() {
        let (p, acct) = tenant(3); // room for exactly 3 units
        let q = acct.quota();
        let mut ws = WatchSet::default();
        ws.replace(Some(&p), desired_scripts(&[sh(1), sh(2), sh(3)]), &MockReg::default());
        assert_eq!(q.current("tenant"), 3);

        // Swap all three for three DISJOINT scripts. At quota this only fits
        // because the replace releases the old units before acquiring the new
        // (no transient doubling — the tenant can never hold 6).
        let outcome = ws.replace(Some(&p), desired_scripts(&[sh(4), sh(5), sh(6)]), &MockReg::default());
        assert!(
            matches!(outcome, ReplaceOutcome::Accepted { added: 3, removed: 3, unchanged: 0 }),
            "disjoint same-size swap must fit at quota, got {outcome:?}",
        );
        assert_eq!(q.current("tenant"), 3, "still exactly 3 units held");
        assert!(ws.scripts.contains_key(&sh(4)) && !ws.scripts.contains_key(&sh(1)));
    }

    #[test]
    fn replace_keeps_a_cross_mechanism_script_without_a_gap() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        // sh1 watched as a DIRECT script.
        ws.add_scripts(Some(&p), [sh(1)], "s", |_| {}, |_| {});
        assert_eq!(q.current("tenant"), 1);

        // Reload covers the same scripthash via a DESCRIPTOR instead — the exact
        // cross-mechanism transition the client-side diff could not see. The
        // server diffs by effective coverage, so sh1 is `unchanged`.
        let desired = DesiredWatchSet {
            scripts: Vec::new(),
            descriptors: vec![("d".to_string(), vec![sh(1)])],
            outpoints: Vec::new(),
            lifecycles: Vec::new(),
            depth_alarms: Vec::new(),
            prefixes: Vec::new(),
        };
        let reg = MockReg::default();
        let outcome = ws.replace(Some(&p), desired, &reg);
        assert!(
            matches!(outcome, ReplaceOutcome::Accepted { added: 0, removed: 0, unchanged: 1 }),
            "same effective scripthash → unchanged, got {outcome:?}",
        );
        // The kept scripthash was NEVER unregistered → no matcher gap.
        assert!(reg.removed_scripts.borrow().is_empty(), "a kept script must not be unregistered");
        assert_eq!(q.current("tenant"), 1, "no re-charge for the kept script");
        assert!(ws.descriptors.contains_key("d") && !ws.script_direct.contains(&sh(1)));
        assert!(ws.scripts.contains_key(&sh(1)), "still effectively watched");
    }

    #[test]
    fn replace_over_quota_leaves_the_set_unchanged() {
        let (p, acct) = tenant(2);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        ws.replace(Some(&p), desired_scripts(&[sh(1), sh(2)]), &MockReg::default());
        assert_eq!(q.current("tenant"), 2);

        // Target needs 3 units > quota 2 → rejected whole; the old set stays.
        let reg = MockReg::default();
        let outcome = ws.replace(Some(&p), desired_scripts(&[sh(3), sh(4), sh(5)]), &reg);
        assert!(
            matches!(outcome, ReplaceOutcome::Rejected { required: 3, quota: 2 }),
            "over-quota target must be rejected, got {outcome:?}",
        );
        assert!(ws.scripts.contains_key(&sh(1)) && ws.scripts.contains_key(&sh(2)));
        assert_eq!(ws.scripts.len(), 2, "old set intact");
        assert_eq!(q.current("tenant"), 2, "still exactly the old 2 units");
        assert!(
            reg.added_scripts.borrow().is_empty() && reg.removed_scripts.borrow().is_empty(),
            "a rejected replace touches nothing in the registry",
        );
    }

    #[test]
    fn replace_empty_target_clears_everything() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        ws.replace(Some(&p), desired_scripts(&[sh(1), sh(2)]), &MockReg::default());
        let reg = MockReg::default();
        let outcome = ws.replace(Some(&p), desired_scripts(&[]), &reg);
        assert!(matches!(outcome, ReplaceOutcome::Accepted { added: 0, removed: 2, unchanged: 0 }));
        assert_eq!(ws.scripts.len(), 0);
        assert_eq!(q.current("tenant"), 0, "all units released");
        let mut rmd = reg.removed_scripts.borrow().clone();
        rmd.sort();
        assert_eq!(rmd, vec![sh(1), sh(2)]);
    }

    #[test]
    fn replace_without_auth_holds_no_leases() {
        let mut ws = WatchSet::default();
        let outcome = ws.replace(None, desired_scripts(&[sh(1), sh(2)]), &MockReg::default());
        assert!(matches!(outcome, ReplaceOutcome::Accepted { added: 2, .. }));
        assert_eq!(ws.scripts.len(), 2);
        assert!(ws.scripts.values().all(Option::is_none), "auth disabled → no leases");
    }
}
