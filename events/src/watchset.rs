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
//! net-new items are registered, and the add returns an [`AddRejected`] naming
//! them, which the carrier reports in-band (`WatchAddRejected`). A partial add
//! would leave the client unable to tell which items it holds.
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

/// Per-connection cap on the number of distinct descriptors retained for
/// `RemoveDescriptor` / slide reconciliation. Each retained descriptor costs a
/// map entry — the descriptor string plus its membership `Vec<Scripthash>`.
/// A descriptor whose window expands entirely to already-watched scripts has an
/// empty `net_new` set, so it charges no quota unit and (without this) consumes
/// no rate token, yet still grows the `descriptors` map. Neither the per-token
/// watch quota nor the per-connection watch-set cap (`len()`) counts descriptor
/// membership, so absent this bound a client could stream unboundedly-many
/// distinct descriptor strings — each resolving to a single already-held script
/// — and grow the map until OOM, invisibly to every other limit. 256 distinct
/// descriptors is generous for any real wallet (roughly one per account /
/// keychain); a client at the cap must `RemoveDescriptor` before adding a new
/// one. Re-asserting (sliding) an already-retained descriptor never grows the
/// map and is always allowed.
pub(crate) const MAX_DESCRIPTORS_PER_CONNECTION: usize = 256;

/// Per-connection cap on the number of BIP 352 silent-payment scan-key targets
/// (Tier 2, §4.2.1). Each target costs one ECDH multiplication per eligible
/// transaction in every scanned block — the ECC analogue of
/// [`MAX_DESCRIPTORS_PER_CONNECTION`], but priced far lower because the work is
/// per-transaction elliptic-curve math, not a hash-map lookup. 16 registered
/// targets covers a wallet watching several accounts plus their change/label
/// keys; a client at the cap must remove one before adding another.
pub(crate) const MAX_SP_TARGETS_PER_CONNECTION: usize = 16;

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

/// A descriptor's expanded window as `(branch, derivation_index, scripthash)`
/// tuples — the coordinates [`expand_descriptor`](crate::descriptor::expand_descriptor)
/// produces, carried through to the match-attribution reverse index.
pub(crate) type DescriptorWindow = Vec<(u32, u32, Scripthash)>;

/// A privacy-preserving script-prefix bucket, as `(bits, masked_top32)` — the
/// type `WatchHandle::add_prefixes` takes. `bits` is the prefix length; the
/// `u32` is the top 32 bits of `sha256(spk)` masked to `bits`.
type PrefixKey = (u8, u32);

/// Why an incremental `Add*` registered none of its net-new items. The carrier
/// reports it in-band as a `WatchAddRejected` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddRejectReason {
    /// The net-new items cost `required` units; the principal already holds
    /// `held` of its `quota`.
    QuotaExceeded { required: u64, held: u64, quota: u64 },
    /// The per-principal add rate limit is spent.
    RateLimited { retry_after_secs: u32 },
    /// A per-connection cap: the add would bring the count to `requested`, past
    /// `limit`.
    CapExceeded { requested: u64, limit: u64 },
    /// The principal lacks the `stream:watch` capability.
    PermissionDenied,
    /// The carrier could not apply the message as a whole (a `min_values` list
    /// that is not parallel to its scripthashes, an invalid descriptor, a txid ×
    /// depth product over [`MAX_TXID_DEPTH_PAIRS`]).
    Malformed,
}

/// The items a rejected add named, in registry form. None of them is watched.
/// Only the add's net-new items appear: items it re-asserted were already
/// watched and stay watched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RejectedItems {
    Scripts(Vec<Scripthash>),
    Outpoints(Vec<OutPoint>),
    Transactions(Vec<Txid>),
    DepthAlarms(Vec<(Txid, u32)>),
    /// The descriptor and the window the add asked for. `kept` is true when an
    /// earlier window of the same descriptor stays watched.
    Descriptor { descriptor: String, gap_limit: u32, start: u32, kept: bool },
    Prefixes(Vec<PrefixKey>),
    /// Silent-payment targets by identity `b_scan·G`, never the scan secret.
    SilentPayments(Vec<[u8; 33]>),
}

/// An incremental add the watch-set refused, for the carrier to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddRejected {
    pub reason: AddRejectReason,
    pub items: RejectedItems,
}

/// Map a quota-store refusal to the reason the client is told.
fn watch_reject_reason(reject: satd_auth::WatchReject) -> AddRejectReason {
    match reject {
        satd_auth::WatchReject::MissingCapability(_) => AddRejectReason::PermissionDenied,
        satd_auth::WatchReject::QuotaExceeded(q) => AddRejectReason::QuotaExceeded {
            required: q.requested,
            held: q.current,
            quota: q.max,
        },
    }
}

/// The per-connection entry cap an incremental add is checked against: the
/// watch-set's size across all kinds, and its cap (`0` = none).
#[derive(Debug, Clone, Copy)]
struct Room {
    len: usize,
    cap: usize,
}

impl Room {
    /// Refuse an add that brings `adding` new entries to a set already at its
    /// cap. A set below the cap takes the whole add, so one message may
    /// overshoot by its own size, itself bounded by the inbound frame cap.
    fn check(self, adding: usize) -> Result<(), AddRejectReason> {
        if self.cap != 0 && adding > 0 && self.len >= self.cap {
            return Err(AddRejectReason::CapExceeded {
                requested: (self.len + adding) as u64,
                limit: self.cap as u64,
            });
        }
        Ok(())
    }
}

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
    fn add_silent_payments(&self, targets: &[node::events::SpWatchTarget]);
    fn remove_silent_payments(&self, scan_pubkeys: &[[u8; 33]]);
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
    fn add_silent_payments(&self, targets: &[node::events::SpWatchTarget]) {
        node::events::WatchHandle::add_silent_payments(self, targets);
    }
    fn remove_silent_payments(&self, scan_pubkeys: &[[u8; 33]]) {
        node::events::WatchHandle::remove_silent_payments(self, scan_pubkeys);
    }
}

/// A complete desired watch-set for [`WatchSet::replace`]. Each field is the FULL
/// membership of its kind, not a delta. Descriptors arrive pre-expanded by the
/// carrier (`descriptor string → derived scripthashes`), so `replace` reconciles
/// by effective scripthash coverage without re-deriving.
pub(crate) struct DesiredWatchSet {
    /// Directly-watched scripthashes, each with its `min_value` floor (0 = none).
    pub scripts: Vec<(Scripthash, u64)>,
    /// Descriptor string → its expanded window as `(branch, derivation_index,
    /// scripthash)` tuples (the coordinates `expand_descriptor` produced). A
    /// scripthash may also appear in `scripts` or another descriptor; it is
    /// charged once and owned by each source. The coordinates feed the match
    /// attribution reverse index so a `SetWatchSet` replace keeps it correct.
    pub descriptors: Vec<(String, DescriptorWindow)>,
    pub outpoints: Vec<OutPoint>,
    /// Lifecycle watches: `(txid, auto_close_depth)` (0 = persist until removed).
    pub lifecycles: Vec<(Txid, u32)>,
    /// Single-shot depth alarms: `(txid, depth)`.
    pub depth_alarms: Vec<(Txid, u32)>,
    /// Prefix buckets with their (coarseness-priced) unit cost.
    pub prefixes: Vec<(PrefixKey, u64)>,
    /// BIP 352 silent-payment scan-key targets (Tier 2, §4). Full membership;
    /// deduplicated by identity (`b_scan·G`) in [`WatchSet::replace`].
    pub sp_targets: Vec<node::events::SpWatchTarget>,
}

/// Outcome of an atomic [`WatchSet::replace`].
#[derive(Debug)]
pub(crate) enum ReplaceOutcome {
    /// The replace applied; counts are by effective coverage.
    Accepted { added: u32, removed: u32, unchanged: u32 },
    /// The target's total unit cost exceeds the principal's quota; the watch-set
    /// is left unchanged.
    Rejected { required: u64, quota: u64 },
    /// The target's watch-set **entry** count exceeds the per-connection cap
    /// (`max_items`, e.g. WS `streamwsmaxsubscriptions`); the watch-set is left
    /// unchanged. Distinct from [`Rejected`](Self::Rejected): a loopback/no-auth
    /// connection has no quota but is still entry-capped, and this bound is by
    /// item count (a prefix is one entry regardless of its unit cost).
    CapExceeded { limit: u64, requested: u64 },
    /// The target snapshot contained an element the carrier could not parse or
    /// expand. A full replace is all-or-nothing, so the snapshot is refused whole
    /// and the live watch-set is left unchanged — never silently shrunk by the
    /// dropped item. Constructed by the carrier before [`replace`](WatchSet::replace)
    /// is ever called.
    Malformed,
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
    /// window expands to (in expansion order). Retained so a `RemoveDescriptor`
    /// (or a re-asserted, slid window) can release exactly the scripts that
    /// descriptor contributed, decrementing `script_owners` rather than blindly
    /// dropping shared scripts.
    descriptors: HashMap<String, Vec<Scripthash>>,
    /// Reverse index: scripthash → the descriptor(s) whose window contains it,
    /// each paired with the script's **position** in that window (expansion
    /// order). Drives match attribution (`ScriptMatched.descriptor_matches`): a
    /// match on a descriptor-derived script reports which descriptor + window
    /// offset it came from. The offset is purely positional (relative to the
    /// registered window), never the absolute derivation index — the server
    /// holds no derivation indices. A script appears once per descriptor that
    /// contains it (overlap → multiple entries). The descriptor name is shared
    /// (`Arc<str>`) so a large window does not store the string per script.
    /// Reverse index: matched scripthash → the descriptors currently covering it,
    /// each with the exact `(branch, derivation_index)` the server derived it at
    /// (BIP-389 branch + absolute index — not a positional offset). Powers
    /// `descriptor_attribution` on the match path.
    script_descriptors: HashMap<Scripthash, Vec<(std::sync::Arc<str>, u32, u32)>>,
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
    /// BIP 352 silent-payment scan-key targets (Tier 2, §4), keyed by identity
    /// `b_scan·G`, each holding its quota lease (one unit per target). Only the
    /// identity + lease live here; the scan secret itself lives solely in the
    /// node-side matcher registry (§4.3) — never copied into the carrier's
    /// bookkeeping.
    silent_payments: HashMap<[u8; 33], Option<satd_auth::WatchLease>>,
    /// Per-connection entry cap on incremental adds (`0` = none). WS sets
    /// `streamwsmaxsubscriptions`; gRPC, whose bound is the quota, has none.
    entry_cap: usize,
}

impl WatchSet {
    /// A watch-set whose incremental adds are refused once it holds `entry_cap`
    /// entries across all kinds (`0` = no cap).
    pub(crate) fn with_entry_cap(entry_cap: usize) -> Self {
        Self { entry_cap, ..Self::default() }
    }

    /// The per-connection entry cap (`0` = none).
    pub(crate) fn entry_cap(&self) -> usize {
        self.entry_cap
    }

    fn room(&self) -> Room {
        Room { len: self.len(), cap: self.entry_cap }
    }

    /// Add outpoints, charging the quota only for items not already watched and
    /// registering the net-new ones via `register`. All-or-nothing per call.
    pub(crate) fn add_outpoints(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        incoming: impl IntoIterator<Item = OutPoint>,
        register: impl FnOnce(&[OutPoint]),
    ) -> Result<(), AddRejected> {
        let room = self.room();
        add_items(&mut self.outpoints, principal, incoming, "outpoints", room, register, |_| {})
            .map_err(|(reason, items)| AddRejected { reason, items: RejectedItems::Outpoints(items) })
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
    ) -> Result<(), AddRejected> {
        let items: Vec<Scripthash> = incoming.into_iter().collect();
        // The registry/lease/floor handling is unchanged: `add_items` charges
        // net-new (scripts not already in `scripts`) and refreshes re-asserts.
        let room = self.room();
        let added =
            add_items(&mut self.scripts, principal, items.iter().copied(), kind, room, register, reassert)
                .map_err(|(reason, items)| AddRejected { reason, items: RejectedItems::Scripts(items) });
        // Reconcile direct ownership for whatever is now watched: every script
        // that ended up in `scripts` (net-new committed, or already held) and is
        // not yet a direct owner becomes one. A net-new that failed the quota is
        // absent, so it is correctly skipped.
        for s in &items {
            if self.scripts.contains_key(s) && self.script_direct.insert(*s) {
                *self.script_owners.entry(*s).or_insert(0) += 1;
            }
        }
        added
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
    /// unchanged. On rejection the `bool` is true when the descriptor was already
    /// held, so its earlier window stays watched.
    pub(crate) fn add_descriptor(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        descriptor: String,
        derived: impl IntoIterator<Item = (u32, u32, Scripthash)>,
        register: impl FnOnce(&[Scripthash]),
        unregister: impl FnOnce(&[Scripthash]),
    ) -> Result<(), (AddRejectReason, bool)> {
        // Dedup the new membership, preserving first-seen order. `new_coords` runs
        // parallel to `new`, carrying each scripthash's `(branch, index)` from the
        // expansion (first occurrence wins if a script recurs across branches).
        let mut new: Vec<Scripthash> = Vec::new();
        let mut new_set = HashSet::new();
        let mut new_coords: Vec<(u32, u32)> = Vec::new();
        for (branch, index, s) in derived {
            if new_set.insert(s) {
                new.push(s);
                new_coords.push((branch, index));
            }
        }
        let is_new_descriptor = !self.descriptors.contains_key(&descriptor);
        // Memory-DoS guard: a brand-new descriptor that expands entirely to
        // already-watched scripts has an empty `net_new` set, so the quota and
        // rate checks below are skipped — yet it still costs a retained map
        // entry. Cap the count of distinct descriptors so such "free"
        // descriptors cannot be streamed without bound. A re-asserted (slid)
        // descriptor is already in the map, never grows it, and passes through.
        if is_new_descriptor && self.descriptors.len() >= MAX_DESCRIPTORS_PER_CONNECTION {
            warn!(
                target: "events::watchset",
                cap = MAX_DESCRIPTORS_PER_CONNECTION,
                "descriptor count cap reached; rejecting new descriptor",
            );
            return Err((
                AddRejectReason::CapExceeded {
                    requested: self.descriptors.len() as u64 + 1,
                    limit: MAX_DESCRIPTORS_PER_CONNECTION as u64,
                },
                false,
            ));
        }

        let old: Vec<Scripthash> = self.descriptors.get(&descriptor).cloned().unwrap_or_default();
        let old_set: HashSet<Scripthash> = old.iter().copied().collect();

        // Scripts entering this descriptor's window (gain it as an owner).
        let to_add: Vec<Scripthash> = new.iter().copied().filter(|s| !old_set.contains(s)).collect();
        // Among those, the ones not currently watched at all are net-new to the
        // registry and must fit the quota atomically.
        let net_new: Vec<Scripthash> =
            to_add.iter().copied().filter(|s| !self.scripts.contains_key(s)).collect();

        if !net_new.is_empty() {
            let room = self.room();
            if let Err(reason) =
                reserve_scripts(&mut self.scripts, principal, &net_new, "descriptor", room, register)
            {
                // Quota/rate/cap rejected the net-new batch: change nothing
                // (membership, ownership, and the prior window all stay as they
                // were).
                return Err((reason, !is_new_descriptor));
            }
        } else if !to_add.is_empty() || old_set.iter().any(|s| !new_set.contains(s)) {
            // Membership changed (scripts entered the window from another owner,
            // or scripts left it) but nothing is net-new to the registry, so
            // `reserve_scripts` — which carries the per-add rate token — was
            // skipped. Charge the rate token here so descriptor churn / a slid
            // window is bounded like any other effective add; loopback and
            // no-policy principals always Allow. Throttled ⇒ leave unchanged.
            if let Some(p) = principal
                && let satd_auth::RateDecision::Throttle { retry_after_secs } = p.check_rate()
            {
                warn!(
                    target: "events::watchset",
                    kind = "descriptor",
                    retry_after_secs,
                    "descriptor re-assert rate-limited; skipping",
                );
                return Err((AddRejectReason::RateLimited { retry_after_secs }, !is_new_descriptor));
            }
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

        // Rebuild this descriptor's reverse-index entries: a slid window changes
        // which indices the surviving scripts sit at, so drop the old entries
        // wholesale and re-record `(descriptor, branch, index)` for the new
        // membership from the coordinates the expansion produced.
        self.clear_reverse_index(&descriptor, &old);
        let key: std::sync::Arc<str> = std::sync::Arc::from(descriptor.as_str());
        for (s, (branch, index)) in new.iter().zip(new_coords.iter()) {
            self.script_descriptors.entry(*s).or_default().push((key.clone(), *branch, *index));
        }

        self.descriptors.insert(descriptor, new);
        Ok(())
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
        self.clear_reverse_index(descriptor, &members);
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
    /// `max_items` is the per-connection watch-set **entry** cap (0 = unlimited):
    /// a target whose effective entry count exceeds it is rejected whole
    /// ([`ReplaceOutcome::CapExceeded`]), leaving the set unchanged. This mirrors
    /// the incremental `Add*` shed on the same carrier — WS passes
    /// `streamwsmaxsubscriptions`; gRPC, which entry-caps neither its incremental
    /// adds nor a replace (quota is its bound), passes 0.
    ///
    /// Note `replace` deliberately does NOT charge the per-add rate limiter that
    /// the incremental `Add*` paths do. `replace` is the watch-set
    /// re-establishment primitive (reconnect / `ResilientWatch::reload`); rate-
    /// limiting it would let a reconnect storm block clients from restoring their
    /// watch-set exactly when they must. The per-add limiter bounds incremental
    /// churn cadence; steady-state size is still bounded here by quota and
    /// `max_items`.
    pub(crate) fn replace(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        desired: DesiredWatchSet,
        max_items: usize,
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
        // Descriptors: dedup each window, add an owner per membership. A descriptor
        // *string* identifies one watch (the `descriptors` map is keyed by it), so
        // a duplicate entry in the snapshot is the same descriptor and is counted
        // ONCE — first occurrence wins. Processing it twice would `+1` each script's
        // owner count per occurrence while only one membership vec survives the map
        // insert, inflating `script_owners` above the memberships a later
        // `RemoveDescriptor` can decrement and stranding live scripthash watches.
        let mut target_descriptors: HashMap<String, Vec<Scripthash>> = HashMap::new();
        // Rebuilt reverse index (scripthash → (descriptor, branch, index)) so match
        // attribution stays correct across a replace — wholesale, so departed
        // descriptors' entries simply don't reappear.
        let mut target_script_descriptors: HashMap<Scripthash, Vec<(std::sync::Arc<str>, u32, u32)>> =
            HashMap::new();
        for (desc, coords) in &desired.descriptors {
            if target_descriptors.contains_key(desc) {
                continue;
            }
            let key: std::sync::Arc<str> = std::sync::Arc::from(desc.as_str());
            let mut seen = HashSet::new();
            let mut members = Vec::new();
            for (branch, index, sh) in coords {
                if seen.insert(*sh) {
                    members.push(*sh);
                    target_script_descriptors.entry(*sh).or_default().push((
                        key.clone(),
                        *branch,
                        *index,
                    ));
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
        // Silent-payment targets: dedup by identity (`b_scan·G`), first
        // occurrence wins. One quota unit each; no shared ownership.
        let mut target_sp: HashMap<[u8; 33], node::events::SpWatchTarget> = HashMap::new();
        for t in &desired.sp_targets {
            target_sp.entry(t.scan_pubkey()).or_insert_with(|| t.clone());
        }
        // Per-connection SP cap applies regardless of the generic entry cap
        // (`max_items` is 0/unlimited on the gRPC carrier). Checked before any
        // mutation so a rejection leaves the live set untouched.
        if target_sp.len() > MAX_SP_TARGETS_PER_CONNECTION {
            return ReplaceOutcome::CapExceeded {
                limit: MAX_SP_TARGETS_PER_CONNECTION as u64,
                requested: target_sp.len() as u64,
            };
        }

        // Per-connection entry cap: bound the target the same way the incremental
        // adds are bounded on this carrier. Count effective ENTRIES (a prefix is
        // one entry regardless of its unit cost) — this matches `len()`. Checked
        // BEFORE the quota swap and any mutation, so a rejection leaves the live
        // set (and its leases) untouched. `max_items == 0` ⇒ unlimited.
        let target_len = target_scripts.len()
            + target_outpoints.len()
            + target_txids.len()
            + target_depths.len()
            + target_prefixes.len()
            + target_sp.len();
        if max_items != 0 && target_len > max_items {
            return ReplaceOutcome::CapExceeded {
                limit: max_items as u64,
                requested: target_len as u64,
            };
        }

        let target_units: u64 = target_scripts.len() as u64
            + target_outpoints.len() as u64
            + target_txids.len() as u64
            + target_depths.len() as u64
            + target_prefixes.values().sum::<u64>()
            + target_sp.len() as u64;

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
        // SP: departed = held identity absent from target; the full target set is
        // re-registered (kept + new) so a kept identity's label set is refreshed
        // in place (the node registry replaces by identity).
        let departed_sp: Vec<[u8; 33]> =
            self.silent_payments.keys().filter(|k| !target_sp.contains_key(*k)).copied().collect();
        let all_target_sp: Vec<node::events::SpWatchTarget> = target_sp.values().cloned().collect();

        // Counts by effective coverage (kept = in both, added = net-new).
        let kept_scripts = self.scripts.len() - departed_scripts.len();
        let kept_outpoints = self.outpoints.len() - departed_outpoints.len();
        let kept_txids = self.txids.len() - departed_txids.len();
        let kept_depths = self.tx_depths.len() - departed_depths.len();
        let kept_prefixes = self.prefixes.len() - departed_prefixes.len();
        let kept_sp = self.silent_payments.len() - departed_sp.len();
        let unchanged = (kept_scripts
            + kept_outpoints
            + kept_txids
            + kept_depths
            + kept_prefixes
            + kept_sp) as u32;
        let removed = (departed_scripts.len()
            + departed_outpoints.len()
            + departed_txids.len()
            + departed_depths.len()
            + departed_prefixes.len()
            + departed_sp.len()) as u32;
        let added = ((target_scripts.len() - kept_scripts)
            + (target_outpoints.len() - kept_outpoints)
            + (target_txids.len() - kept_txids)
            + (target_depths.len() - kept_depths)
            + (target_prefixes.len() - kept_prefixes)
            + (target_sp.len() - kept_sp)) as u32;

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
                    .sum::<u64>()
                + self.silent_payments.len() as u64;
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
        self.silent_payments = target_sp.keys().map(|id| (*id, take(1))).collect();
        self.script_owners = target_owners;
        self.script_direct = target_direct;
        self.descriptors = target_descriptors;
        self.script_descriptors = target_script_descriptors;

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
        // SP: register the full target set (kept identities refresh their labels
        // in place — the node registry replaces by identity); remove departed.
        if !all_target_sp.is_empty() {
            reg.add_silent_payments(&all_target_sp);
        }
        if !departed_sp.is_empty() {
            reg.remove_silent_payments(&departed_sp);
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
        for v in self.silent_payments.values_mut() {
            if let Some(l) = v.take() {
                l.defuse();
            }
        }
    }

    /// Drop `descriptor`'s entries from the reverse index for each of `members`,
    /// removing a script's bucket entirely once it has no descriptor left.
    fn clear_reverse_index(&mut self, descriptor: &str, members: &[Scripthash]) {
        for s in members {
            if let Some(v) = self.script_descriptors.get_mut(s) {
                v.retain(|(d, _, _)| d.as_ref() != descriptor);
                if v.is_empty() {
                    self.script_descriptors.remove(s);
                }
            }
        }
    }

    /// The descriptor attribution for a matched scripthash: `(descriptor, branch,
    /// derivation_index)` for each descriptor whose window currently contains it —
    /// the exact BIP-389 branch and absolute index the server derived it at, so a
    /// client needs no positional arithmetic. Empty for a directly-watched
    /// (non-descriptor) script. The carrier attaches this to `ScriptMatched`.
    /// Whether `descriptor` has a window watched on this connection.
    pub(crate) fn holds_descriptor(&self, descriptor: &str) -> bool {
        self.descriptors.contains_key(descriptor)
    }

    pub(crate) fn descriptor_attribution(
        &self,
        scripthash: &Scripthash,
    ) -> &[(std::sync::Arc<str>, u32, u32)] {
        self.script_descriptors.get(scripthash).map(Vec::as_slice).unwrap_or(&[])
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
    ) -> Result<(), AddRejected> {
        let room = self.room();
        add_items(&mut self.txids, principal, incoming, "transactions", room, register, |_| {})
            .map_err(|(reason, items)| AddRejected { reason, items: RejectedItems::Transactions(items) })
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
    ) -> Result<(), AddRejected> {
        let room = self.room();
        add_items(&mut self.tx_depths, principal, incoming, "tx_depths", room, register, |_| {})
            .map_err(|(reason, items)| AddRejected { reason, items: RejectedItems::DepthAlarms(items) })
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
    ) -> Result<(), AddRejected> {
        // Collect the (key → cost) of net-new buckets up front so the priced
        // charge can read each item's cost. `add_items_priced` re-derives the
        // cost via the closure; a HashMap lookup keeps the two in lockstep.
        let costs: HashMap<PrefixKey, u64> = incoming.into_iter().collect();
        let room = self.room();
        add_items_priced(
            &mut self.prefixes,
            principal,
            costs.keys().copied(),
            |k| costs.get(k).copied().unwrap_or(1),
            "prefixes",
            room,
            register,
            |_| {},
        )
        .map_err(|(reason, items)| AddRejected { reason, items: RejectedItems::Prefixes(items) })
    }

    /// Remove prefix watches, releasing each removed bucket's (multi-unit) lease.
    pub(crate) fn remove_prefixes(
        &mut self,
        incoming: impl IntoIterator<Item = PrefixKey>,
        unregister: impl FnOnce(&[PrefixKey]),
    ) {
        remove_items(&mut self.prefixes, incoming, unregister);
    }

    /// Add silent-payment scan-key targets (Tier 2, §4), one quota unit each,
    /// keyed by identity `b_scan·G`. A target whose identity is already held is
    /// **re-registered in place**, not dropped: its label set is mutable
    /// server-side metadata (labels drive `scan_outputs`' label points), so a
    /// re-assert carrying a changed label set — e.g. a wallet that starts
    /// catching its own change (`m = 0`) after registering label-less — must
    /// reach the matcher or those payments are silently missed. The matcher
    /// replaces the target in place and counts only genuinely-new identities, so
    /// a re-assert charges no quota unit and does not grow the retained set.
    /// Bounded by [`MAX_SP_TARGETS_PER_CONNECTION`]: if the net-new targets would
    /// push the retained count over the cap, the whole add is shed (like a
    /// descriptor over its cap). All-or-nothing on quota. `register` receives the
    /// net-new targets AND the re-asserted ones so the caller applies label
    /// updates in the matcher. A re-assert is free (no rate token) and its label
    /// update applies even when the add's net-new targets are refused; a
    /// rejection names only the net-new targets, by identity.
    pub(crate) fn add_silent_payments(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        targets: Vec<node::events::SpWatchTarget>,
        register: impl FnOnce(&[node::events::SpWatchTarget]),
    ) -> Result<(), AddRejected> {
        // Partition into net-new (identity not yet held) and re-asserts (held;
        // may carry a changed label set). Dedup within the message.
        let mut seen = HashSet::new();
        let mut net_new: Vec<node::events::SpWatchTarget> = Vec::new();
        let mut reassert: Vec<node::events::SpWatchTarget> = Vec::new();
        for t in targets {
            let id = t.scan_pubkey();
            if !seen.insert(id) {
                continue; // intra-message duplicate identity
            }
            if self.silent_payments.contains_key(&id) {
                reassert.push(t);
            } else {
                net_new.push(t);
            }
        }
        if net_new.is_empty() && reassert.is_empty() {
            return Ok(());
        }
        // A re-asserted target is already inside every limit, so its label update
        // is free and always applies, like a re-asserted script's floor in
        // `add_items_priced`. Only net-new targets are charged, and only they can
        // be refused.
        if net_new.is_empty() {
            register(&reassert);
            return Ok(());
        }
        let rejected = |reason, net_new: &[node::events::SpWatchTarget]| AddRejected {
            reason,
            items: RejectedItems::SilentPayments(net_new.iter().map(|t| t.scan_pubkey()).collect()),
        };
        // Per-connection SP cap: only net-new grows the retained set.
        if self.silent_payments.len() + net_new.len() > MAX_SP_TARGETS_PER_CONNECTION {
            warn!(
                target: "events::watchset",
                held = self.silent_payments.len(),
                adding = net_new.len(),
                cap = MAX_SP_TARGETS_PER_CONNECTION,
                "silent-payment target cap exceeded; skipping add",
            );
            let reason = AddRejectReason::CapExceeded {
                requested: (self.silent_payments.len() + net_new.len()) as u64,
                limit: MAX_SP_TARGETS_PER_CONNECTION as u64,
            };
            if !reassert.is_empty() {
                register(&reassert);
            }
            return Err(rejected(reason, &net_new));
        }
        if let Err(reason) = self.room().check(net_new.len()) {
            warn!(
                target: "events::watchset",
                kind = "silent_payments",
                "watch-set at per-connection entry cap; skipping add",
            );
            if !reassert.is_empty() {
                register(&reassert);
            }
            return Err(rejected(reason, &net_new));
        }
        // Per-add rate limit (mirrors `add_items_priced`): one token per add
        // with net-new targets, after the short-circuits above so a re-assert
        // or an empty message cannot burn the bucket.
        if let Some(p) = principal
            && let satd_auth::RateDecision::Throttle { retry_after_secs } = p.check_rate()
        {
            warn!(
                target: "events::watchset",
                kind = "silent_payments",
                retry_after_secs,
                "watch add rate-limited; skipping",
            );
            if !reassert.is_empty() {
                register(&reassert);
            }
            return Err(rejected(AddRejectReason::RateLimited { retry_after_secs }, &net_new));
        }
        let new_ids: Vec<[u8; 33]> = net_new.iter().map(|t| t.scan_pubkey()).collect();
        // Register net-new first (indices `[0, n_new)`) then the re-asserts, and
        // call `register` (an `FnOnce`) exactly once with the final slice.
        let n_new = net_new.len();
        let mut to_register = net_new;
        to_register.extend(reassert);
        match principal {
            Some(p) => {
                // Charge quota for net-new only; re-asserts (label updates) are
                // free. `acquire_watch` only when there is something to charge.
                let batch = if n_new > 0 {
                    match p.acquire_watch(n_new as u64) {
                        Ok(b) => Ok(Some(b)),
                        Err(reject) => {
                            warn!(
                                target: "events::watchset",
                                kind = "silent_payments",
                                reject = ?reject,
                                "watch add rejected (capability or quota)",
                            );
                            Err(watch_reject_reason(reject))
                        }
                    }
                } else {
                    Ok(None)
                };
                match batch {
                    Ok(Some(mut b)) => {
                        register(&to_register);
                        for t in to_register.iter().take(n_new) {
                            let lease = b.split_off(1);
                            debug_assert!(
                                lease.is_some(),
                                "split_off drained before all sp targets got a lease",
                            );
                            self.silent_payments.insert(t.scan_pubkey(), lease);
                        }
                        Ok(())
                    }
                    // Nothing net-new: apply the re-asserted label updates.
                    Ok(None) => {
                        register(&to_register[n_new..]);
                        Ok(())
                    }
                    // Quota denied: the re-asserted label updates still apply;
                    // nothing new is retained.
                    Err(reason) => {
                        register(&to_register[n_new..]);
                        Err(AddRejected { reason, items: RejectedItems::SilentPayments(new_ids) })
                    }
                }
            }
            // Auth disabled (loopback trust): unlimited, no lease.
            None => {
                register(&to_register);
                for t in to_register.iter().take(n_new) {
                    self.silent_payments.insert(t.scan_pubkey(), None);
                }
                Ok(())
            }
        }
    }

    /// Remove silent-payment targets by identity `b_scan·G`, releasing each
    /// removed target's quota lease.
    pub(crate) fn remove_silent_payments(
        &mut self,
        scan_pubkeys: impl IntoIterator<Item = [u8; 33]>,
        unregister: impl FnOnce(&[[u8; 33]]),
    ) {
        remove_items(&mut self.silent_payments, scan_pubkeys, unregister);
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
            + self.silent_payments.len()
    }
}

/// An add's refusal and the net-new items it refused, in registry form.
type Refused<T> = (AddRejectReason, Vec<T>);

fn add_items<T: Eq + Hash + Copy>(
    held: &mut HashMap<T, Option<satd_auth::WatchLease>>,
    principal: Option<&satd_auth::Principal>,
    incoming: impl IntoIterator<Item = T>,
    kind: &'static str,
    room: Room,
    register: impl FnOnce(&[T]),
    reassert: impl FnOnce(&[T]),
) -> Result<(), Refused<T>> {
    // The common case: every item costs exactly one unit.
    add_items_priced(held, principal, incoming, |_| 1, kind, room, register, reassert)
}

/// Generalization of [`add_items`] where each item carries its own quota cost
/// (`cost`). The whole net-new batch is reserved atomically as `sum(cost)` units,
/// then split into per-item leases via [`WatchLease::split_off`], so a removal
/// returns exactly that item's units. Used by the coarseness-priced prefix add;
/// `add_items` is the `cost = 1` specialization. A refusal returns the net-new
/// items, none of which is registered; re-asserted items are refreshed either
/// way.
#[allow(clippy::too_many_arguments)] // the shared add path's knobs stay unbundled
fn add_items_priced<T: Eq + Hash + Copy>(
    held: &mut HashMap<T, Option<satd_auth::WatchLease>>,
    principal: Option<&satd_auth::Principal>,
    incoming: impl IntoIterator<Item = T>,
    cost: impl Fn(&T) -> u64,
    kind: &'static str,
    room: Room,
    register: impl FnOnce(&[T]),
    reassert: impl FnOnce(&[T]),
) -> Result<(), Refused<T>> {
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
        return Ok(());
    }

    // Per-connection entry cap (WS `streamwsmaxsubscriptions`). Checked before
    // the rate limit so a capped add does not spend a token.
    if let Err(reason) = room.check(net_new.len()) {
        warn!(target: "events::watchset", kind, "watch-set at per-connection entry cap; skipping add");
        return Err((reason, net_new));
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
    // Allow. An over-budget add is refused without tearing down the stream, and
    // the carrier reports it in-band like the quota-reject path below.
    if let Some(p) = principal
        && let satd_auth::RateDecision::Throttle { retry_after_secs } = p.check_rate()
    {
        warn!(
            target: "events::watchset",
            kind,
            retry_after_secs,
            "watch add rate-limited; skipping",
        );
        return Err((AddRejectReason::RateLimited { retry_after_secs }, net_new));
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
                Ok(())
            }
            Err(reject) => {
                warn!(
                    target: "events::watchset",
                    kind,
                    reject = ?reject,
                    "watch add rejected (capability or quota)",
                );
                Err((watch_reject_reason(reject), net_new))
            }
        },
        // Auth disabled (loopback trust): unlimited, no lease.
        None => {
            register(&net_new);
            for it in net_new {
                held.insert(it, None);
            }
            Ok(())
        }
    }
}

/// Reserve quota for a batch of net-new scripthashes (one unit each), all-or-
/// nothing, inserting each with its split lease and calling `register` on
/// success. Returns why the batch was refused (it always commits when auth is
/// disabled and no entry cap applies, or the batch is empty). Mirrors the
/// net-new arm of [`add_items_priced`] so a descriptor (re)assert can stay
/// atomic — rejecting the whole window rather than partially registering.
fn reserve_scripts(
    held: &mut HashMap<Scripthash, Option<satd_auth::WatchLease>>,
    principal: Option<&satd_auth::Principal>,
    net_new: &[Scripthash],
    kind: &'static str,
    room: Room,
    register: impl FnOnce(&[Scripthash]),
) -> Result<(), AddRejectReason> {
    if net_new.is_empty() {
        return Ok(());
    }
    if let Err(reason) = room.check(net_new.len()) {
        warn!(target: "events::watchset", kind, "watch-set at per-connection entry cap; skipping add");
        return Err(reason);
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
        return Err(AddRejectReason::RateLimited { retry_after_secs });
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
                Ok(())
            }
            Err(reject) => {
                warn!(
                    target: "events::watchset",
                    kind,
                    reject = ?reject,
                    "watch add rejected (capability or quota)",
                );
                Err(watch_reject_reason(reject))
            }
        },
        // Auth disabled (loopback trust): unlimited, no lease.
        None => {
            register(net_new);
            for s in net_new {
                held.insert(*s, None);
            }
            Ok(())
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
        }).unwrap();
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

        ws.add_outpoints(Some(&p), [op(1, 0), op(2, 0)], |_| {}).unwrap();
        assert_eq!(q.current("tenant"), 2);

        // A SEPARATE message re-asserts op(1) and adds op(3): only op(3) is new.
        let mut registered = Vec::new();
        ws.add_outpoints(Some(&p), [op(1, 0), op(3, 0)], |items| {
            registered = items.to_vec();
        }).unwrap();
        assert_eq!(registered, vec![op(3, 0)], "only the net-new item registers");
        assert_eq!(q.current("tenant"), 3, "the re-asserted item is not double-charged");
    }

    fn sh(b: u8) -> Scripthash {
        [b; 32]
    }

    /// A single-branch descriptor window: `(branch 0, index = position, sh)` —
    /// the shape a real `expand_descriptor` yields for a `/0/*` descriptor, so
    /// the reverse index records index == position (matching the old positional
    /// offset for a single branch).
    fn win(shs: &[Scripthash]) -> Vec<(u32, u32, Scripthash)> {
        shs.iter().enumerate().map(|(i, s)| (0u32, i as u32, *s)).collect()
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
        ws.add_scripts(Some(&p), [sh(1), sh(2)], "scripts", |s| net_new = s.to_vec(), |_| {}).unwrap();
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
        ).unwrap();
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
        ).unwrap();
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

        ws.add_scripts(Some(&p), [sh(1)], "scripts", |_| {}, |_| {}).unwrap();
        // Bucket now empty. Re-assert sh(1): a net-new add here would be
        // throttled, but a re-assert must bypass the rate limiter entirely.
        let mut reasserted = Vec::new();
        ws.add_scripts(Some(&p), [sh(1)], "scripts", |_| {}, |s| reasserted = s.to_vec()).unwrap();
        assert_eq!(reasserted, vec![sh(1)], "re-assert fires even with an empty rate bucket");
    }

    #[test]
    fn over_quota_add_is_all_or_nothing() {
        let (p, acct) = tenant(2);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        // Three net-new items but quota is 2 → the whole add is rejected.
        let mut registered = false;
        let rejected = ws
            .add_outpoints(Some(&p), [op(1, 0), op(2, 0), op(3, 0)], |_| registered = true)
            .unwrap_err();
        assert!(!registered, "an add that overflows quota registers nothing");
        assert_eq!(q.current("tenant"), 0, "no units charged on a rejected add");
        assert_eq!(ws.len(), 0);
        assert_eq!(
            rejected,
            AddRejected {
                reason: AddRejectReason::QuotaExceeded { required: 3, held: 0, quota: 2 },
                items: RejectedItems::Outpoints(vec![op(1, 0), op(2, 0), op(3, 0)]),
            },
            "the refusal names the cost, the quota and every refused item",
        );
    }

    #[test]
    fn refused_add_names_only_its_net_new_items() {
        let (p, acct) = tenant(2);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        ws.add_outpoints(Some(&p), [op(1, 0)], |_| {}).unwrap();

        // op(1) is a re-assert (held, free); op(2) and op(3) need 2 units but only
        // 1 is free, so they are refused and op(1) stays watched.
        let rejected = ws
            .add_outpoints(Some(&p), [op(1, 0), op(2, 0), op(3, 0)], |_| {})
            .unwrap_err();
        assert_eq!(rejected.reason, AddRejectReason::QuotaExceeded { required: 2, held: 1, quota: 2 });
        assert_eq!(
            rejected.items,
            RejectedItems::Outpoints(vec![op(2, 0), op(3, 0)]),
            "a re-asserted item is still watched, so it is not named",
        );
        assert_eq!(ws.len(), 1);
        assert_eq!(q.current("tenant"), 1);
    }

    #[test]
    fn add_without_stream_watch_is_refused_as_permission_denied() {
        let acct: Arc<dyn Accounting> = Arc::new(LocalAccounting::new());
        let p = Principal::token(
            Arc::from("reader"),
            CapabilitySet::EMPTY.with(Capability::StreamSubscribe),
            Some(10),
            None,
            acct,
        );
        let mut ws = WatchSet::default();
        let rejected = ws.add_scripts(Some(&p), [sh(1)], "scripts", |_| {}, |_| {}).unwrap_err();
        assert_eq!(rejected.reason, AddRejectReason::PermissionDenied);
        assert_eq!(rejected.items, RejectedItems::Scripts(vec![sh(1)]));
        assert_eq!(ws.len(), 0);
    }

    #[test]
    fn entry_cap_refuses_growth_but_not_reasserts() {
        let mut ws = WatchSet::with_entry_cap(2);
        ws.add_outpoints(None, [op(1, 0), op(2, 0)], |_| {}).unwrap();
        // At the cap, a message that only re-asserts held items grows nothing.
        ws.add_outpoints(None, [op(1, 0)], |_| {}).unwrap();
        let mut registered = false;
        let rejected = ws
            .add_scripts(None, [sh(9)], "scripts", |_| registered = true, |_| {})
            .unwrap_err();
        assert!(!registered);
        assert_eq!(
            rejected,
            AddRejected {
                reason: AddRejectReason::CapExceeded { requested: 3, limit: 2 },
                items: RejectedItems::Scripts(vec![sh(9)]),
            },
            "the cap spans every kind of watch",
        );
        assert_eq!(ws.len(), 2);
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
        }).unwrap();
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
        }).unwrap();
        assert_eq!(q.current("tenant"), 2, "(X,1) and (X,3) charge 2 units");
        assert_eq!(ws.len(), 2);

        // Re-adding (X,1) dedups; (X,6) is net-new.
        let mut reg = Vec::new();
        ws.add_tx_depths(Some(&p), [(txid(1), 1), (txid(1), 6)], |items| {
            reg = items.to_vec()
        }).unwrap();
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
        ws.add_outpoints(Some(&p), [op(1, 0)], |_| {}).unwrap();

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
        ws.add_outpoints(Some(&p), [op(1, 0), op(2, 0)], |_| {}).unwrap();
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
        }).unwrap();
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
        ws.add_outpoints(Some(&p), [op(1, 0)], |items| reg1 = items.len()).unwrap();
        assert_eq!(reg1, 1, "first add is within the burst");
        assert_eq!(q.current("tenant"), 1);

        // Bucket now empty; an immediate second add is throttled → nothing
        // registered or charged, and the existing watch-set is intact (no
        // teardown).
        let mut reg2 = 0;
        let rejected = ws.add_outpoints(Some(&p), [op(2, 0)], |items| reg2 = items.len()).unwrap_err();
        assert!(
            matches!(rejected.reason, AddRejectReason::RateLimited { retry_after_secs } if retry_after_secs >= 1),
            "a throttled add says when to retry: {rejected:?}",
        );
        assert_eq!(rejected.items, RejectedItems::Outpoints(vec![op(2, 0)]));
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
        ws.add_prefixes(Some(&p), [c24, c32], |keys| reg = keys.len()).unwrap();
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
        ws.add_prefixes(Some(&p), [a], |_| {}).unwrap();
        let charged = q.current("tenant");

        let mut called = false;
        ws.add_prefixes(Some(&p), [a], |_| called = true).unwrap();
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
        let rejected = ws.add_prefixes(Some(&p), [c], |_| registered = true).unwrap_err();
        assert_eq!(
            rejected,
            AddRejected {
                reason: AddRejectReason::QuotaExceeded { required: 1 << 8, held: 0, quota: 10 },
                items: RejectedItems::Prefixes(vec![c.0]),
            },
            "a prefix refusal states its coarseness price",
        );
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

        ws.add_outpoints(Some(&p), [op(1, 0)], |_| {}).unwrap();
        ws.add_outpoints(Some(&p), [op(1, 0)], |_| {}).unwrap(); // duplicate → no-op, free
        let mut reg3 = 0;
        ws.add_outpoints(Some(&p), [op(2, 0)], |items| reg3 = items.len()).unwrap();

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
            win(&[sh(1), sh(2), sh(3)]),
            |s| registered = s.to_vec(),
            |_| {},
        ).unwrap();
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
        ws.add_scripts(Some(&p), [sh(2)], "scripts", |_| {}, |_| {}).unwrap();
        assert_eq!(q.current("tenant"), 1);
        let mut registered = Vec::new();
        ws.add_descriptor(
            Some(&p),
            "D".into(),
            win(&[sh(1), sh(2), sh(3)]),
            |s| registered = s.to_vec(),
            |_| {},
        ).unwrap();
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

        ws.add_descriptor(Some(&p), "D1".into(), win(&[sh(1), sh(2)]), |_| {}, |_| {}).unwrap();
        ws.add_descriptor(Some(&p), "D2".into(), win(&[sh(2), sh(3)]), |_| {}, |_| {}).unwrap();
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

        ws.add_descriptor(Some(&p), "D".into(), win(&[sh(1), sh(2), sh(3)]), |_| {}, |_| {}).unwrap();
        assert_eq!(q.current("tenant"), 3);

        // Slide the window forward: {1,2,3} → {3,4,5}. 1,2 leave; 4,5 enter; 3 stays.
        let mut registered = Vec::new();
        let mut unregistered = Vec::new();
        ws.add_descriptor(
            Some(&p),
            "D".into(),
            win(&[sh(3), sh(4), sh(5)]),
            |s| registered = s.to_vec(),
            |s| unregistered = s.to_vec(),
        ).unwrap();
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

        ws.add_descriptor(Some(&p), "D".into(), win(&[sh(1)]), |_| {}, |_| {}).unwrap();
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
        let rejected = ws.add_descriptor(
            Some(&p),
            "D".into(),
            win(&[sh(1), sh(2), sh(3)]),
            |_| registered = true,
            |_| {},
        );
        assert_eq!(
            rejected,
            Err((AddRejectReason::QuotaExceeded { required: 3, held: 0, quota: 2 }, false)),
            "a new descriptor that does not fit is refused and not kept",
        );
        assert!(!registered, "an over-quota descriptor registers nothing");
        assert_eq!(q.current("tenant"), 0, "no units charged");
        assert_eq!(ws.len(), 0);
        // And its membership was not recorded, so a later remove is a clean no-op.
        ws.remove_descriptor("D", |_| panic!("nothing should release"));
    }

    #[test]
    fn refused_descriptor_slide_keeps_the_earlier_window() {
        let (p, acct) = tenant(2);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        ws.add_descriptor(Some(&p), "D".into(), win(&[sh(1)]), |_| {}, |_| {}).unwrap();

        // Sliding to two new scripts needs 2 units with only 1 free.
        let rejected = ws.add_descriptor(Some(&p), "D".into(), win(&[sh(2), sh(3)]), |_| {}, |_| {});
        assert_eq!(
            rejected,
            Err((AddRejectReason::QuotaExceeded { required: 2, held: 1, quota: 2 }, true)),
            "a refused slide reports that the earlier window is kept",
        );
        assert!(ws.holds_descriptor("D"));
        assert!(ws.scripts.contains_key(&sh(1)), "the earlier window still watches its script");
        assert_eq!(q.current("tenant"), 1);
    }

    #[test]
    fn re_adding_an_identical_descriptor_window_is_idempotent() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        ws.add_descriptor(Some(&p), "D".into(), win(&[sh(1), sh(2)]), |_| {}, |_| {}).unwrap();
        // Same descriptor, same window: nothing net-new, nothing released.
        let mut registered = false;
        let mut unregistered = false;
        ws.add_descriptor(
            Some(&p),
            "D".into(),
            win(&[sh(1), sh(2)]),
            |_| registered = true,
            |_| unregistered = true,
        ).unwrap();
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
        added_sp: std::cell::RefCell<Vec<[u8; 33]>>,
        removed_sp: std::cell::RefCell<Vec<[u8; 33]>>,
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
        fn add_silent_payments(&self, targets: &[node::events::SpWatchTarget]) {
            self.added_sp.borrow_mut().extend(targets.iter().map(|t| t.scan_pubkey()));
        }
        fn remove_silent_payments(&self, scan_pubkeys: &[[u8; 33]]) {
            self.removed_sp.borrow_mut().extend_from_slice(scan_pubkeys);
        }
    }

    fn desired_scripts(scripts: &[Scripthash]) -> DesiredWatchSet {
        DesiredWatchSet {
            scripts: scripts.iter().map(|s| (*s, 0)).collect(),
            descriptors: Vec::new(),
            outpoints: Vec::new(),
            lifecycles: Vec::new(),
            depth_alarms: Vec::new(),
            prefixes: Vec::new(),
            sp_targets: Vec::new(),
        }
    }

    #[test]
    fn replace_at_quota_disjoint_swap_fits() {
        let (p, acct) = tenant(3); // room for exactly 3 units
        let q = acct.quota();
        let mut ws = WatchSet::default();
        ws.replace(Some(&p), desired_scripts(&[sh(1), sh(2), sh(3)]), 0, &MockReg::default());
        assert_eq!(q.current("tenant"), 3);

        // Swap all three for three DISJOINT scripts. At quota this only fits
        // because the replace releases the old units before acquiring the new
        // (no transient doubling — the tenant can never hold 6).
        let outcome = ws.replace(Some(&p), desired_scripts(&[sh(4), sh(5), sh(6)]), 0, &MockReg::default());
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
        ws.add_scripts(Some(&p), [sh(1)], "s", |_| {}, |_| {}).unwrap();
        assert_eq!(q.current("tenant"), 1);

        // Reload covers the same scripthash via a DESCRIPTOR instead — the exact
        // cross-mechanism transition the client-side diff could not see. The
        // server diffs by effective coverage, so sh1 is `unchanged`.
        let desired = DesiredWatchSet {
            scripts: Vec::new(),
            descriptors: vec![("d".to_string(), vec![(0, 0, sh(1))])],
            outpoints: Vec::new(),
            lifecycles: Vec::new(),
            depth_alarms: Vec::new(),
            prefixes: Vec::new(),
            sp_targets: Vec::new(),
        };
        let reg = MockReg::default();
        let outcome = ws.replace(Some(&p), desired, 0, &reg);
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
    fn replace_rebuilds_the_descriptor_attribution_reverse_index() {
        // A SetWatchSet replace must keep the match-attribution reverse index in
        // sync with the new descriptor set — new descriptors attribute at their
        // real (branch, index), and a descriptor dropped by the replace leaves no
        // stale attribution. Regression: replace() predates the reverse index, so
        // the #450/#451 merge had to thread coordinates through DesiredWatchSet and
        // rebuild `script_descriptors`; without it attribution would go stale.
        let (p, _acct) = tenant(10);
        let mut ws = WatchSet::default();
        let d1 = DesiredWatchSet {
            scripts: Vec::new(),
            descriptors: vec![("a".to_string(), vec![(0, 5, sh(1))])],
            outpoints: Vec::new(),
            lifecycles: Vec::new(),
            depth_alarms: Vec::new(),
            prefixes: Vec::new(),
            sp_targets: Vec::new(),
        };
        ws.replace(Some(&p), d1, 0, &MockReg::default());
        assert_eq!(attrib(&ws, sh(1)), vec![("a".to_string(), 0, 5)], "new descriptor attributes at its coordinate");

        // Replace with a different descriptor covering a different script.
        let d2 = DesiredWatchSet {
            scripts: Vec::new(),
            descriptors: vec![("b".to_string(), vec![(1, 9, sh(2))])],
            outpoints: Vec::new(),
            lifecycles: Vec::new(),
            depth_alarms: Vec::new(),
            prefixes: Vec::new(),
            sp_targets: Vec::new(),
        };
        ws.replace(Some(&p), d2, 0, &MockReg::default());
        assert_eq!(attrib(&ws, sh(2)), vec![("b".to_string(), 1, 9)], "replaced-in descriptor attributes correctly");
        assert!(
            ws.descriptor_attribution(&sh(1)).is_empty(),
            "a descriptor dropped by the replace leaves no stale attribution",
        );
    }

    #[test]
    fn replace_dedups_a_duplicate_descriptor_so_removedescriptor_fully_clears() {
        // A snapshot listing the same descriptor string twice is the same watch:
        // it must be counted once. Otherwise `script_owners` is inflated (+1 per
        // occurrence) while only one membership vec survives, and a later
        // RemoveDescriptor decrements ownership once — leaving the scripthash
        // stranded as a live watch that can't be cleared.
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        let desired = DesiredWatchSet {
            scripts: Vec::new(),
            descriptors: vec![
                ("d".to_string(), vec![(0, 0, sh(1)), (0, 1, sh(2))]),
                ("d".to_string(), vec![(0, 0, sh(1)), (0, 1, sh(2))]),
            ],
            outpoints: Vec::new(),
            lifecycles: Vec::new(),
            depth_alarms: Vec::new(),
            prefixes: Vec::new(),
            sp_targets: Vec::new(),
        };
        let outcome = ws.replace(Some(&p), desired, 0, &MockReg::default());
        assert!(
            matches!(outcome, ReplaceOutcome::Accepted { added: 2, removed: 0, unchanged: 0 }),
            "duplicate descriptor counts its scripts once, got {outcome:?}",
        );
        assert_eq!(q.current("tenant"), 2, "two scripthashes, two units — not four");
        assert_eq!(ws.script_owners.get(&sh(1)), Some(&1), "one owner, not two");
        assert_eq!(ws.script_owners.get(&sh(2)), Some(&1));

        // The single RemoveDescriptor now fully clears both scripthashes.
        let mut unregistered = Vec::new();
        ws.remove_descriptor("d", |s| unregistered.extend_from_slice(s));
        assert!(ws.scripts.is_empty(), "RemoveDescriptor clears the whole descriptor's coverage");
        assert!(ws.script_owners.is_empty(), "no stranded owners");
        assert_eq!(unregistered.len(), 2, "both scripthashes unregistered from the matcher");
        assert_eq!(q.current("tenant"), 0, "all units released");
    }

    #[test]
    fn replace_over_quota_leaves_the_set_unchanged() {
        let (p, acct) = tenant(2);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        ws.replace(Some(&p), desired_scripts(&[sh(1), sh(2)]), 0, &MockReg::default());
        assert_eq!(q.current("tenant"), 2);

        // Target needs 3 units > quota 2 → rejected whole; the old set stays.
        let reg = MockReg::default();
        let outcome = ws.replace(Some(&p), desired_scripts(&[sh(3), sh(4), sh(5)]), 0, &reg);
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
    fn replace_over_entry_cap_is_rejected_and_leaves_the_set_unchanged() {
        // The per-connection entry cap bounds a replace the same way it bounds
        // incremental adds — and it applies even with NO principal (loopback/
        // no-auth), where there is no quota to fall back on. That is exactly the
        // case the cap exists to protect: a single SetWatchSet cannot install more
        // than `max_items` entries.
        let mut ws = WatchSet::default();
        // Seed a 2-entry set within a cap of 2 (no auth → no quota bound).
        let outcome = ws.replace(None, desired_scripts(&[sh(1), sh(2)]), 2, &MockReg::default());
        assert!(matches!(outcome, ReplaceOutcome::Accepted { added: 2, .. }));
        assert_eq!(ws.len(), 2);

        // A target of 3 entries exceeds the cap of 2 → rejected whole, old set kept.
        let reg = MockReg::default();
        let outcome = ws.replace(None, desired_scripts(&[sh(3), sh(4), sh(5)]), 2, &reg);
        assert!(
            matches!(outcome, ReplaceOutcome::CapExceeded { limit: 2, requested: 3 }),
            "over-cap target must be rejected, got {outcome:?}",
        );
        assert_eq!(ws.len(), 2, "old set intact");
        assert!(ws.scripts.contains_key(&sh(1)) && ws.scripts.contains_key(&sh(2)));
        assert!(
            reg.added_scripts.borrow().is_empty() && reg.removed_scripts.borrow().is_empty(),
            "a cap-rejected replace touches nothing in the registry",
        );

        // A target of exactly the cap (2) is allowed — and may swap membership.
        let outcome = ws.replace(None, desired_scripts(&[sh(6), sh(7)]), 2, &MockReg::default());
        assert!(matches!(outcome, ReplaceOutcome::Accepted { .. }), "at-cap target fits");
        assert_eq!(ws.len(), 2);
        // max_items = 0 disables the cap entirely.
        let outcome = ws.replace(None, desired_scripts(&[sh(1), sh(2), sh(3), sh(4)]), 0, &MockReg::default());
        assert!(matches!(outcome, ReplaceOutcome::Accepted { .. }), "cap 0 ⇒ unlimited");
        assert_eq!(ws.len(), 4);
    }

    #[test]
    fn replace_empty_target_clears_everything() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        ws.replace(Some(&p), desired_scripts(&[sh(1), sh(2)]), 0, &MockReg::default());
        let reg = MockReg::default();
        let outcome = ws.replace(Some(&p), desired_scripts(&[]), 0, &reg);
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
        let outcome = ws.replace(None, desired_scripts(&[sh(1), sh(2)]), 0, &MockReg::default());
        assert!(matches!(outcome, ReplaceOutcome::Accepted { added: 2, .. }));
        assert_eq!(ws.scripts.len(), 2);
        assert!(ws.scripts.values().all(Option::is_none), "auth disabled → no leases");
    }

    #[test]
    fn descriptor_count_is_capped_per_connection() {
        let mut ws = WatchSet::default();
        // Loopback (no auth): no quota or rate gate, so only the descriptor-count
        // cap can bound growth. Every descriptor expands to the *same* already-held
        // script, so each past the first has an empty net-new set — exactly the
        // "free descriptor" path (no quota unit, no rate token) the cap bounds.
        for i in 0..MAX_DESCRIPTORS_PER_CONNECTION {
            ws.add_descriptor(None, format!("D{i}"), win(&[sh(1)]), |_| {}, |_| {}).unwrap();
        }
        assert_eq!(ws.descriptors.len(), MAX_DESCRIPTORS_PER_CONNECTION);

        // One more *distinct* descriptor is rejected outright — the map, which is
        // invisible to the quota and to `len()`, does not grow past the cap.
        let mut registered = false;
        let rejected =
            ws.add_descriptor(None, "overflow".into(), win(&[sh(1)]), |_| registered = true, |_| {});
        assert_eq!(
            rejected,
            Err((
                AddRejectReason::CapExceeded {
                    requested: MAX_DESCRIPTORS_PER_CONNECTION as u64 + 1,
                    limit: MAX_DESCRIPTORS_PER_CONNECTION as u64,
                },
                false,
            )),
        );
        assert!(!registered, "a descriptor rejected by the cap registers nothing");
        assert_eq!(
            ws.descriptors.len(),
            MAX_DESCRIPTORS_PER_CONNECTION,
            "a new descriptor past the cap is rejected",
        );
        assert!(!ws.descriptors.contains_key("overflow"));

        // Re-asserting (sliding) an already-retained descriptor at the cap still
        // works — the count cap must never block a window slide.
        let mut slid = Vec::new();
        ws.add_descriptor(None, "D0".into(), win(&[sh(2)]), |s| slid = s.to_vec(), |_| {}).unwrap();
        assert_eq!(
            ws.descriptors.len(),
            MAX_DESCRIPTORS_PER_CONNECTION,
            "re-asserting an existing descriptor does not grow the map",
        );
        assert_eq!(
            ws.descriptors.get("D0").map(Vec::as_slice),
            Some([sh(2)].as_slice()),
            "the slid window replaced D0's membership",
        );
        assert_eq!(slid, vec![sh(2)], "the slid-in script registers");
    }

    // --- descriptor match attribution (reverse index) -------------------------

    /// `(descriptor, branch, index)` attribution as plain owned tuples for
    /// assertions.
    fn attrib(ws: &WatchSet, sh: Scripthash) -> Vec<(String, u32, u32)> {
        ws.descriptor_attribution(&sh)
            .iter()
            .map(|(d, branch, index)| (d.to_string(), *branch, *index))
            .collect()
    }

    #[test]
    fn attribution_reports_descriptor_branch_and_index() {
        let (p, _acct) = tenant(10);
        let mut ws = WatchSet::default();
        ws.add_descriptor(Some(&p), "D".into(), win(&[sh(10), sh(11), sh(12)]), |_| {}, |_| {}).unwrap();
        // `win` models a single-branch /0/* window: branch 0, index = position.
        assert_eq!(attrib(&ws, sh(10)), vec![("D".to_string(), 0, 0)]);
        assert_eq!(attrib(&ws, sh(11)), vec![("D".to_string(), 0, 1)]);
        assert_eq!(attrib(&ws, sh(12)), vec![("D".to_string(), 0, 2)]);
    }

    #[test]
    fn attribution_reports_the_multipath_branch() {
        // A two-branch window (external=0, change=1) attributes each script to its
        // real branch and index — the case a positional offset could not express.
        let (p, _acct) = tenant(10);
        let mut ws = WatchSet::default();
        let two_branch = vec![(0u32, 7u32, sh(1)), (1u32, 7u32, sh(2))];
        ws.add_descriptor(Some(&p), "M".into(), two_branch, |_| {}, |_| {}).unwrap();
        assert_eq!(attrib(&ws, sh(1)), vec![("M".to_string(), 0, 7)], "external branch");
        assert_eq!(attrib(&ws, sh(2)), vec![("M".to_string(), 1, 7)], "change branch, same index");
    }

    #[test]
    fn direct_scripts_have_no_attribution() {
        let (p, _acct) = tenant(10);
        let mut ws = WatchSet::default();
        ws.add_scripts(Some(&p), [sh(1)], "scripts", |_| {}, |_| {}).unwrap();
        assert!(ws.descriptor_attribution(&sh(1)).is_empty());
    }

    #[test]
    fn overlapping_descriptors_attribute_a_shared_script_to_both() {
        let (p, _acct) = tenant(10);
        let mut ws = WatchSet::default();
        ws.add_descriptor(Some(&p), "A".into(), win(&[sh(1), sh(2)]), |_| {}, |_| {}).unwrap();
        ws.add_descriptor(Some(&p), "B".into(), win(&[sh(9), sh(2)]), |_| {}, |_| {}).unwrap();
        // sh(2) is offset 1 in A and offset 1 in B.
        let mut got = attrib(&ws, sh(2));
        got.sort();
        assert_eq!(got, vec![("A".to_string(), 0, 1), ("B".to_string(), 0, 1)]);
    }

    #[test]
    fn sliding_a_window_updates_offsets_and_drops_departed_scripts() {
        let (p, _acct) = tenant(10);
        let mut ws = WatchSet::default();
        ws.add_descriptor(Some(&p), "D".into(), win(&[sh(1), sh(2), sh(3)]), |_| {}, |_| {}).unwrap();
        // Slide: {1,2,3} → {3,4,5}. sh(3) moves from offset 2 to offset 0.
        ws.add_descriptor(Some(&p), "D".into(), win(&[sh(3), sh(4), sh(5)]), |_| {}, |_| {}).unwrap();
        assert_eq!(attrib(&ws, sh(3)), vec![("D".to_string(), 0, 0)], "surviving script re-offset");
        assert_eq!(attrib(&ws, sh(4)), vec![("D".to_string(), 0, 1)]);
        assert!(ws.descriptor_attribution(&sh(1)).is_empty(), "departed script loses attribution");
    }

    #[test]
    fn removing_a_descriptor_clears_attribution_but_keeps_shared() {
        let (p, _acct) = tenant(10);
        let mut ws = WatchSet::default();
        ws.add_descriptor(Some(&p), "A".into(), win(&[sh(1), sh(2)]), |_| {}, |_| {}).unwrap();
        ws.add_descriptor(Some(&p), "B".into(), win(&[sh(2)]), |_| {}, |_| {}).unwrap();
        ws.remove_descriptor("A", |_| {});
        assert!(ws.descriptor_attribution(&sh(1)).is_empty(), "A's exclusive script cleared");
        assert_eq!(attrib(&ws, sh(2)), vec![("B".to_string(), 0, 0)], "B still attributes the shared script");
    }

    // ---- Silent-payment (Tier 2) watch-set tests -------------------------

    /// A distinct SP target per `seed` (distinct `b_scan` ⇒ distinct identity),
    /// all sharing one valid spend pubkey.
    fn sp_target(seed: u8) -> node::events::SpWatchTarget {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let spend = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x22u8; 32]).unwrap());
        node::events::SpWatchTarget::new([seed; 32], &spend.serialize(), vec![]).unwrap()
    }

    #[test]
    fn sp_add_then_remove_releases_quota() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();

        let mut registered = 0;
        ws.add_silent_payments(Some(&p), vec![sp_target(1), sp_target(2)], |ts| {
            registered = ts.len();
        }).unwrap();
        assert_eq!(registered, 2);
        assert_eq!(q.current("tenant"), 2, "two SP targets charge 2 units");
        assert_eq!(ws.len(), 2);

        // Re-asserting a held identity is not double-charged.
        ws.add_silent_payments(Some(&p), vec![sp_target(1)], |_| {}).unwrap();
        assert_eq!(q.current("tenant"), 2, "re-asserted identity is not recharged");

        let mut unregistered = 0;
        ws.remove_silent_payments([sp_target(1).scan_pubkey()], |ids| unregistered = ids.len());
        assert_eq!(unregistered, 1);
        assert_eq!(q.current("tenant"), 1, "per-remove release frees one unit");
        assert_eq!(ws.len(), 1);
    }

    #[test]
    fn sp_reassert_is_free_and_applies_when_new_targets_are_refused() {
        use satd_auth::RatePolicy;
        let acct: Arc<dyn Accounting> = Arc::new(LocalAccounting::new());
        let p = Principal::token(
            Arc::from("tenant"),
            CapabilitySet::EMPTY.with(Capability::StreamWatch),
            Some(100),
            Some(RatePolicy { burst: 1, per_sec: 1 }),
            acct,
        );
        let mut ws = WatchSet::default();
        ws.add_silent_payments(Some(&p), vec![sp_target(1)], |_| {}).unwrap(); // the only token

        // A label-only re-assert needs no token: it applies and nothing is refused.
        let mut applied = Vec::new();
        ws.add_silent_payments(Some(&p), vec![sp_target(1)], |ts| {
            applied = ts.iter().map(|t| t.scan_pubkey()).collect();
        })
        .unwrap();
        assert_eq!(applied, vec![sp_target(1).scan_pubkey()]);

        // A new target with the bucket empty is refused; the re-assert in the
        // same message still applies, and only the new target is named.
        let mut applied = Vec::new();
        let rejected = ws
            .add_silent_payments(Some(&p), vec![sp_target(1), sp_target(2)], |ts| {
                applied = ts.iter().map(|t| t.scan_pubkey()).collect();
            })
            .unwrap_err();
        assert!(matches!(rejected.reason, AddRejectReason::RateLimited { .. }), "{rejected:?}");
        assert_eq!(rejected.items, RejectedItems::SilentPayments(vec![sp_target(2).scan_pubkey()]));
        assert_eq!(applied, vec![sp_target(1).scan_pubkey()], "the re-assert's labels still apply");
        assert_eq!(ws.len(), 1);
    }

    #[test]
    fn sp_reassert_reregisters_for_label_updates() {
        // A held scan key re-added (e.g. a wallet that starts catching its own
        // change by adding label 0) must reach the matcher so its label set is
        // updated in place — before this fix a held identity was dropped from
        // `net_new` and `register` was never called, silently missing every
        // labeled/change payment. It must still not be recharged or grow the set.
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        ws.add_silent_payments(Some(&p), vec![sp_target(1)], |_| {}).unwrap();
        assert_eq!(ws.len(), 1);
        assert_eq!(q.current("tenant"), 1);

        let id1 = sp_target(1).scan_pubkey();
        let mut forwarded: Vec<[u8; 33]> = Vec::new();
        ws.add_silent_payments(Some(&p), vec![sp_target(1)], |ts| {
            forwarded = ts.iter().map(|t| t.scan_pubkey()).collect();
        }).unwrap();
        assert_eq!(
            forwarded,
            vec![id1],
            "a re-asserted identity is forwarded to the matcher (label update), not dropped",
        );
        assert_eq!(ws.len(), 1, "re-assert does not grow the retained set");
        assert_eq!(q.current("tenant"), 1, "re-assert charges no quota unit");
    }

    #[test]
    fn sp_incremental_add_respects_cap() {
        // No quota bound (loopback): only the SP cap gates the add.
        let mut ws = WatchSet::default();
        let full: Vec<_> = (1..=MAX_SP_TARGETS_PER_CONNECTION as u8).map(sp_target).collect();
        ws.add_silent_payments(None, full, |_| {}).unwrap();
        assert_eq!(ws.len(), MAX_SP_TARGETS_PER_CONNECTION);
        // One more target over the cap is refused whole; the set is unchanged.
        let mut registered = false;
        let rejected =
            ws.add_silent_payments(None, vec![sp_target(200)], |_| registered = true).unwrap_err();
        assert!(!registered, "an over-cap target reaches no matcher");
        assert_eq!(
            rejected,
            AddRejected {
                reason: AddRejectReason::CapExceeded {
                    requested: MAX_SP_TARGETS_PER_CONNECTION as u64 + 1,
                    limit: MAX_SP_TARGETS_PER_CONNECTION as u64,
                },
                items: RejectedItems::SilentPayments(vec![sp_target(200).scan_pubkey()]),
            },
            "an SP refusal names the target by identity",
        );
        assert_eq!(ws.len(), MAX_SP_TARGETS_PER_CONNECTION, "over-cap add is shed");
    }

    #[test]
    fn sp_replace_reconciles_and_reports() {
        let (p, acct) = tenant(10);
        let q = acct.quota();
        let mut ws = WatchSet::default();
        let reg = MockReg::default();

        let mut d = desired_scripts(&[]);
        d.sp_targets = vec![sp_target(1), sp_target(2)];
        let outcome = ws.replace(Some(&p), d, 0, &reg);
        assert!(
            matches!(outcome, ReplaceOutcome::Accepted { added: 2, removed: 0, unchanged: 0 }),
            "two SP targets added, got {outcome:?}",
        );
        assert_eq!(reg.added_sp.borrow().len(), 2, "both identities registered");
        assert_eq!(q.current("tenant"), 2);

        // Replace keeping target 1, dropping 2, adding 3.
        let mut d2 = desired_scripts(&[]);
        d2.sp_targets = vec![sp_target(1), sp_target(3)];
        reg.added_sp.borrow_mut().clear();
        let outcome = ws.replace(Some(&p), d2, 0, &reg);
        assert!(
            matches!(outcome, ReplaceOutcome::Accepted { added: 1, removed: 1, unchanged: 1 }),
            "one kept, one dropped, one added, got {outcome:?}",
        );
        assert_eq!(
            reg.removed_sp.borrow().as_slice(),
            &[sp_target(2).scan_pubkey()],
            "only target 2 departs the registry",
        );
        assert_eq!(q.current("tenant"), 2, "quota holds at two targets");
    }

    #[test]
    fn sp_replace_over_cap_rejected() {
        let mut ws = WatchSet::default();
        let reg = MockReg::default();
        let mut d = desired_scripts(&[]);
        d.sp_targets = (1..=(MAX_SP_TARGETS_PER_CONNECTION as u8 + 1)).map(sp_target).collect();
        let outcome = ws.replace(None, d, 0, &reg);
        assert!(
            matches!(outcome, ReplaceOutcome::CapExceeded { limit, .. } if limit == MAX_SP_TARGETS_PER_CONNECTION as u64),
            "over the SP cap is rejected, got {outcome:?}",
        );
        assert_eq!(ws.len(), 0, "rejected replace leaves the set unchanged");
        assert!(reg.added_sp.borrow().is_empty(), "no registration on a rejected replace");
    }
}
