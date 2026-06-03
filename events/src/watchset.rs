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

/// A scripthash is `sha256(scriptPubKey)`. Mirrors `node_index::keys::Scripthash`
/// (the type `WatchHandle::add_scripthashes` takes) without this crate having to
/// depend on `node-index`.
type Scripthash = [u8; 32];

/// A subscription's live watch-set: the outpoints and scripts it watches, each
/// paired with the [`WatchLease`](satd_auth::WatchLease) backing its quota unit
/// (`None` when auth is disabled — loopback trust, unlimited).
#[derive(Default)]
pub(crate) struct WatchSet {
    outpoints: HashMap<OutPoint, Option<satd_auth::WatchLease>>,
    scripts: HashMap<Scripthash, Option<satd_auth::WatchLease>>,
    /// Lifecycle watches (one quota unit per txid). An `auto_close_depth` rides
    /// on the lifecycle watch server-side and is NOT a separate charged item.
    txids: HashMap<Txid, Option<satd_auth::WatchLease>>,
    /// Single-shot depth alarms, keyed `(txid, depth)` — one quota unit per
    /// pair, so an alarm on the same txid at two depths charges two units.
    tx_depths: HashMap<(Txid, u32), Option<satd_auth::WatchLease>>,
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
        add_items(&mut self.outpoints, principal, incoming, "outpoints", register);
    }

    /// Add scripthashes (direct or descriptor-derived). `kind` only labels the
    /// rejection log line.
    pub(crate) fn add_scripts(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        incoming: impl IntoIterator<Item = Scripthash>,
        kind: &'static str,
        register: impl FnOnce(&[Scripthash]),
    ) {
        add_items(&mut self.scripts, principal, incoming, kind, register);
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

    /// Remove scripthashes, releasing each removed item's quota unit.
    pub(crate) fn remove_scripts(
        &mut self,
        incoming: impl IntoIterator<Item = Scripthash>,
        unregister: impl FnOnce(&[Scripthash]),
    ) {
        remove_items(&mut self.scripts, incoming, unregister);
    }

    /// Add txids, charging the quota only for items not already watched.
    pub(crate) fn add_transactions(
        &mut self,
        principal: Option<&satd_auth::Principal>,
        incoming: impl IntoIterator<Item = Txid>,
        register: impl FnOnce(&[Txid]),
    ) {
        add_items(&mut self.txids, principal, incoming, "transactions", register);
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
        add_items(&mut self.tx_depths, principal, incoming, "tx_depths", register);
    }

    /// Remove depth alarms, releasing each removed pair's quota unit.
    pub(crate) fn remove_tx_depths(
        &mut self,
        incoming: impl IntoIterator<Item = (Txid, u32)>,
        unregister: impl FnOnce(&[(Txid, u32)]),
    ) {
        remove_items(&mut self.tx_depths, incoming, unregister);
    }

    /// Total watched items across all kinds. Used to enforce the per-connection
    /// watch-set cap and in tests.
    pub(crate) fn len(&self) -> usize {
        self.outpoints.len() + self.scripts.len() + self.txids.len() + self.tx_depths.len()
    }
}

fn add_items<T: Eq + Hash + Copy>(
    held: &mut HashMap<T, Option<satd_auth::WatchLease>>,
    principal: Option<&satd_auth::Principal>,
    incoming: impl IntoIterator<Item = T>,
    kind: &'static str,
    register: impl FnOnce(&[T]),
) {
    // Distinct items not already watched: dedups both within this message
    // (`seen`) and against the live watch-set (`held`).
    let mut seen = HashSet::new();
    let net_new: Vec<T> = incoming
        .into_iter()
        .filter(|it| !held.contains_key(it) && seen.insert(*it))
        .collect();
    if net_new.is_empty() {
        // Empty or fully-duplicate add (e.g. a client re-asserting a watch it
        // already holds): a no-op — charges neither quota NOR a rate token.
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
    match principal {
        // Reserve all net-new units atomically (all-or-nothing), then split
        // the batch into per-item leases so each can be released on removal.
        Some(p) => match p.acquire_watch(net_new.len() as u64) {
            Ok(mut batch) => {
                register(&net_new);
                for it in net_new {
                    let lease = batch.split_off_one();
                    // Conservation invariant: acquire_watch charged exactly
                    // net_new.len() units, and we split exactly that many, so
                    // every split yields Some. A None here would mean an item
                    // charged in the store with no per-item lease backing it —
                    // a unit leaked until teardown. Pin it so a future refactor
                    // can't silently regress.
                    debug_assert!(
                        lease.is_some(),
                        "split_off_one drained before all items got a lease",
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
}
