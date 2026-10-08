//! Per-scripthash subscription registry + Electrum-compatible
//! status-hash computation.
//!
//! Subscribers obtain a `tokio::broadcast::Receiver<StatusUpdate>`
//! for a scripthash. Each time a chain or mempool event touches the
//! scripthash, the notifier (M5) recomputes the status hash from the
//! merged confirmed-history + mempool view, and — only if the value
//! changed — sends a `StatusUpdate` on that scripthash's channel.
//!
//! Status-hash is the Electrum protocol's canonical
//! "tell me my address state changed" signal:
//!
//! ```text
//! status_hash = sha256(
//!   "<txid_hex>:<height>:<txid_hex>:<height>:..."
//! )
//! ```
//!
//! over the history in Electrum history order — confirmed rows by height
//! and block position, then mempool rows, height `0` before `-1` — which
//! is the order `get_history` lists it in. [`crate::history`] builds the
//! rows in that order; the hash takes them as given. The trailing colon
//! after the last entry is included per Electrum-server convention. An
//! empty-history scripthash has status `[0u8; 32]`, which the wire layer
//! sends as `null`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use bitcoin::Txid;
use parking_lot::Mutex;
use tokio::sync::broadcast;

use crate::keys::Scripthash;
use crate::types::StatusUpdate;

/// Per-scripthash status-update broadcaster. The notifier holds the
/// `Mutex<HashMap<...>>`; subscribers hold a `Receiver` they got from
/// `subscribe`. A slow subscriber that lags sees `RecvError::Lagged`
/// and is expected to resync via `confirmed_history` / `mempool_history`.
pub struct SubscriptionRegistry {
    channels: Mutex<HashMap<Scripthash, broadcast::Sender<StatusUpdate>>>,
    /// Maximum concurrent scripthashes; default 10000 per
    /// `--addrindexsubscriptions=N`. Past the cap, `subscribe` returns
    /// `Err(SubscribeError::CapReached)`. Atomic so a SIGHUP reload can
    /// raise/lower the cap live via [`set_max_subs`](Self::set_max_subs);
    /// the check in `subscribe` reads it fresh. Lowering below the live
    /// count keeps existing subscriptions and only rejects new ones.
    max_subs: AtomicUsize,
    /// Capacity of each scripthash's broadcast channel. Slow
    /// subscribers see `RecvError::Lagged` past this depth.
    per_channel_capacity: usize,
    /// Last-seen status hash per scripthash. The notifier consults
    /// this to skip "no actual change" updates that would otherwise
    /// fire on every block touching unrelated scripthashes.
    last_status: Mutex<HashMap<Scripthash, [u8; 32]>>,
}

#[derive(Debug, thiserror::Error)]
pub enum SubscribeError {
    #[error("subscription cap reached ({0} scripthashes)")]
    CapReached(usize),
}

impl SubscriptionRegistry {
    pub fn new(max_subs: usize, per_channel_capacity: usize) -> Self {
        Self {
            channels: Mutex::new(HashMap::new()),
            max_subs: AtomicUsize::new(max_subs),
            per_channel_capacity,
            last_status: Mutex::new(HashMap::new()),
        }
    }

    /// Update the subscription cap live (SIGHUP `--addrindexsubscriptions`).
    /// Affects subsequent `subscribe` calls only; subscriptions already
    /// established when the cap is lowered are not torn down.
    pub fn set_max_subs(&self, max_subs: usize) {
        self.max_subs.store(max_subs, Ordering::Relaxed);
    }

    /// Current subscription cap.
    pub fn max_subs(&self) -> usize {
        self.max_subs.load(Ordering::Relaxed)
    }

    /// Subscribe to status updates for `sh`. Multiple subscribers per
    /// scripthash share the same broadcast channel. Returns
    /// `CapReached` when adding a brand-new scripthash would exceed
    /// the configured limit.
    ///
    /// Channels with zero remaining receivers (e.g. after the
    /// subscriber dropped its `Receiver`) are pruned in-line before
    /// the cap check, so abandoned subscriptions cannot permanently
    /// exhaust the cap.
    pub fn subscribe(
        &self,
        sh: Scripthash,
    ) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
        let mut channels = self.channels.lock();
        if let Some(tx) = channels.get(&sh)
            && tx.receiver_count() > 0
        {
            return Ok(tx.subscribe());
        }
        // Sweep abandoned channels under the same lock so the cap
        // check below sees the live count, not the high-water mark.
        channels.retain(|_, tx| tx.receiver_count() > 0);
        // Drop last_status for any pruned scripthashes. A re-subscribe
        // is supposed to recompute status_hash from current state; a
        // stale dedup entry from a prior incarnation could match the
        // recomputed hash and silently swallow the first notification.
        let live_keys: std::collections::HashSet<Scripthash> = channels.keys().copied().collect();
        self.last_status
            .lock()
            
            .retain(|sh, _| live_keys.contains(sh));
        let max_subs = self.max_subs.load(Ordering::Relaxed);
        if channels.len() >= max_subs {
            return Err(SubscribeError::CapReached(max_subs));
        }
        let (tx, rx) = broadcast::channel(self.per_channel_capacity);
        channels.insert(sh, tx);
        Ok(rx)
    }

    /// Number of distinct scripthashes currently subscribed. Used by
    /// the `satd_addrindex_subscriptions_active` Prometheus gauge.
    pub fn active_count(&self) -> usize {
        self.channels.lock().len()
    }

    /// Forget all per-scripthash channels with zero remaining
    /// subscribers. Called periodically from the notifier so
    /// abandoned channels don't accumulate forever.
    pub fn prune_empty(&self) {
        let mut channels = self.channels.lock();
        channels.retain(|_, tx| tx.receiver_count() > 0);
        // Drop matching last_status entries — a future re-subscribe
        // recomputes status_hash from current state, which is correct.
        let live_keys: std::collections::HashSet<Scripthash> = channels.keys().copied().collect();
        self.last_status
            .lock()
            
            .retain(|sh, _| live_keys.contains(sh));
    }

    /// All scripthashes with at least one active subscriber. Filters
    /// channels whose receivers have all dropped — those should not
    /// drive notifier work or `last_status` updates, both of which
    /// would be wasted.
    pub fn active_scripthashes(&self) -> Vec<Scripthash> {
        self.channels
            .lock()
            
            .iter()
            .filter_map(|(sh, tx)| {
                if tx.receiver_count() > 0 {
                    Some(*sh)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Send a status update to the channel for `sh`, if the
    /// recomputed `status_hash` differs from the last-seen value.
    ///
    /// Skips entirely (no `last_status` write) when the channel has
    /// zero receivers — a stale `last_status` value left behind by a
    /// dropped receiver could cause a future re-subscriber to miss
    /// the first notification if the recomputed hash happened to
    /// match the stale entry.
    pub fn maybe_notify(&self, sh: Scripthash, status_hash: [u8; 32]) {
        let channels = self.channels.lock();
        let tx = match channels.get(&sh) {
            Some(tx) if tx.receiver_count() > 0 => tx.clone(),
            _ => return,
        };
        drop(channels);

        let mut last = self.last_status.lock();
        if last.get(&sh) == Some(&status_hash) {
            return;
        }
        last.insert(sh, status_hash);
        drop(last);

        // Best-effort: SendError means no receivers between our check
        // and the send (a tiny race window); not an error.
        let _ = tx.send(StatusUpdate {
            scripthash: sh,
            status_hash,
        });
    }

    /// Record `status_hash` as the status the subscriber that just
    /// subscribed to `sh` was answered with, so the next
    /// [`maybe_notify`](Self::maybe_notify) that finds the same status does
    /// not push it again. Without it, the first block or mempool event
    /// after a subscribe re-pushed the unchanged status (a `null` for an
    /// unused address).
    ///
    /// Seeds only a channel whose one receiver is the caller's, and only
    /// while no status is recorded for it:
    ///
    /// - With a second receiver present, that subscriber may not have seen
    ///   this status. Recording it would make `maybe_notify` treat the
    ///   status as already delivered and swallow the push that subscriber
    ///   still needs.
    /// - A recorded status came from a `maybe_notify` push to the caller's
    ///   receiver. A push queued while the subscribe was being answered
    ///   reaches the client after the answer, so the pushed value, not the
    ///   answer, is what the client last saw. Keeping it costs at most one
    ///   redundant push; overwriting it could suppress a push the client
    ///   needs.
    ///
    /// The caller must hold a receiver for `sh` (call this right after the
    /// [`subscribe`](Self::subscribe) that returned it) and must have
    /// computed `status_hash` after that subscribe.
    pub fn seed_status(&self, sh: Scripthash, status_hash: [u8; 32]) {
        // The channels lock is held across the seed so no second
        // subscriber can join between the receiver count and the write.
        let channels = self.channels.lock();
        if channels.get(&sh).map(|tx| tx.receiver_count()) != Some(1) {
            return;
        }
        self.last_status.lock().entry(sh).or_insert(status_hash);
    }
}

/// Compute the Electrum status hash over `entries`, taken in the order
/// given.
///
/// `entries` is `(height, txid)` per row, where `height` is signed:
/// - positive: confirmed block height
/// - `0`: unconfirmed mempool tx with no unconfirmed inputs
/// - `-1`: unconfirmed tx that spends an unconfirmed parent
///
/// The rows must already be in Electrum history order (confirmed by
/// height and block position, then mempool `0` before `-1`, then display
/// txid); [`crate::history::history_rows`] builds them that way. The hash
/// does not re-sort: a client hashes `get_history` in the order it
/// arrives, so the status has to cover the same order.
///
/// Returns the all-zero hash for an empty history (canonical
/// "no data" sentinel). Otherwise sha256 of
/// `"<txid>:<height>:<txid>:<height>:..."`.
pub fn status_hash(entries: &[(i64, Txid)]) -> [u8; 32] {
    crate::history::status_hash_of(entries.iter().copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    fn fixture_txid(byte: u8) -> Txid {
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    #[test]
    fn test_address_index_status_hash_empty_is_zero() {
        let h = status_hash(&[]);
        assert_eq!(h, [0u8; 32]);
    }

    #[test]
    fn test_address_index_status_hash_changes_on_new_entry() {
        let txid_a = fixture_txid(0x01);
        let txid_b = fixture_txid(0x02);
        let h1 = status_hash(&[(100, txid_a)]);
        let h2 = status_hash(&[(100, txid_a), (101, txid_b)]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_address_index_status_hash_follows_input_order() {
        // The hash covers rows in the order given, which is the order
        // `get_history` lists them in. Re-sorting here is what made the
        // status disagree with the history a client hashes.
        let txid_a = fixture_txid(0x10);
        let txid_b = fixture_txid(0x20);
        let h1 = status_hash(&[(50, txid_a), (60, txid_b)]);
        let h2 = status_hash(&[(60, txid_b), (50, txid_a)]);
        assert_ne!(h1, h2);
        let text = format!("{txid_a}:50:{txid_b}:60:");
        assert_eq!(
            h1,
            bitcoin::hashes::sha256::Hash::hash(text.as_bytes()).to_byte_array()
        );
    }

    #[test]
    fn test_address_index_status_hash_mempool_height_zero() {
        let txid_mp = fixture_txid(0x30);
        let txid_conf = fixture_txid(0x31);
        let h_with_mp = status_hash(&[(100, txid_conf), (0, txid_mp)]);
        let h_no_mp = status_hash(&[(100, txid_conf)]);
        assert_ne!(
            h_with_mp, h_no_mp,
            "adding a mempool entry must change status hash"
        );
    }

    #[test]
    fn test_address_index_status_hash_distinguishes_unconfirmed_with_deps() {
        // electrs `Height::Unconfirmed { has_unconfirmed_inputs }`
        // distinguishes plain unconfirmed (height=0) from
        // chained-mempool (height=-1). The two MUST hash differently
        // so wallet clients see a status change when a mempool tx
        // gains/loses an unconfirmed parent.
        let txid_mp = fixture_txid(0x30);
        let h_no_deps = status_hash(&[(0, txid_mp)]);
        let h_with_deps = status_hash(&[(-1, txid_mp)]);
        assert_ne!(h_no_deps, h_with_deps);
    }

    #[test]
    fn test_address_index_subscribe_returns_receiver() {
        let reg = SubscriptionRegistry::new(100, 32);
        let sh = [0xab; 32];
        let _rx = reg.subscribe(sh).expect("subscribe ok");
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn test_address_index_subscribe_max_count_enforced() {
        let reg = SubscriptionRegistry::new(2, 32);
        // Hold receivers in scope so channels stay alive (otherwise
        // `prune_empty` could drop them between attempts).
        let _rx_a = reg.subscribe([0xaa; 32]).unwrap();
        let _rx_b = reg.subscribe([0xbb; 32]).unwrap();
        let third = reg.subscribe([0xcc; 32]);
        assert!(matches!(third, Err(SubscribeError::CapReached(2))));
    }

    #[test]
    fn test_address_index_set_max_subs_live() {
        // SIGHUP `--addrindexsubscriptions` reload: the cap is read fresh on
        // every subscribe, so raising it lets previously-rejected scripthashes
        // through, and lowering it rejects new ones without tearing down
        // existing subscriptions.
        let reg = SubscriptionRegistry::new(1, 32);
        let _rx_a = reg.subscribe([0xaa; 32]).unwrap();
        assert!(matches!(
            reg.subscribe([0xbb; 32]),
            Err(SubscribeError::CapReached(1))
        ));

        // Raise the cap live → the previously-rejected scripthash now fits.
        reg.set_max_subs(3);
        assert_eq!(reg.max_subs(), 3);
        let _rx_b = reg.subscribe([0xbb; 32]).unwrap();
        let _rx_c = reg.subscribe([0xcc; 32]).unwrap();
        assert!(matches!(
            reg.subscribe([0xdd; 32]),
            Err(SubscribeError::CapReached(3))
        ));

        // Lower the cap below the live count → existing subscriptions survive
        // (re-subscribing an already-open scripthash still works), but a brand
        // new scripthash is rejected.
        reg.set_max_subs(1);
        assert!(reg.subscribe([0xaa; 32]).is_ok(), "existing sub still served");
        assert!(matches!(
            reg.subscribe([0xee; 32]),
            Err(SubscribeError::CapReached(1))
        ));
    }

    #[test]
    fn test_address_index_subscribe_cap_recovers_after_drop() {
        // Drop receivers and confirm new scripthashes can subscribe
        // again — the prior implementation never pruned, so a client
        // that subscribed-then-disconnected could permanently exhaust
        // the cap.
        let reg = SubscriptionRegistry::new(2, 32);
        {
            let _rx_a = reg.subscribe([0xa1; 32]).unwrap();
            let _rx_b = reg.subscribe([0xb1; 32]).unwrap();
        }
        // Receivers dropped → subscribe must reclaim slots.
        let _rx_c = reg
            .subscribe([0xc1; 32])
            .expect("cap should be reclaimable after receivers drop");
        let _rx_d = reg
            .subscribe([0xd1; 32])
            .expect("second reclaimed slot must work too");
        let third = reg.subscribe([0xe1; 32]);
        assert!(matches!(third, Err(SubscribeError::CapReached(2))));
    }

    #[tokio::test]
    async fn test_address_index_resubscribe_after_drop_sees_first_notify() {
        // Earlier behavior: last_status was retained after subscribers
        // dropped, and was even written for zero-receiver channels by
        // maybe_notify. A re-subscriber whose recomputed status_hash
        // happened to match the stale entry would silently miss the
        // first notification. Verify the new prune-on-resubscribe +
        // skip-when-zero-receivers contract closes that.
        use tokio::time::{Duration, timeout};
        let reg = SubscriptionRegistry::new(100, 32);
        let sh = [0xfe; 32];

        // First subscriber sees a hash, then drops.
        let h_initial = [0x99; 32];
        {
            let mut rx = reg.subscribe(sh).unwrap();
            reg.maybe_notify(sh, h_initial);
            let _ = timeout(Duration::from_millis(50), rx.recv()).await;
        }

        // While no receiver exists, a stale subsystem somehow tries to
        // notify the same hash — must not write last_status.
        reg.maybe_notify(sh, h_initial);

        // New subscriber re-subscribes; same hash must arrive on the
        // first notify (not be dedup'd by stale state).
        let mut rx2 = reg.subscribe(sh).unwrap();
        reg.maybe_notify(sh, h_initial);
        let got = timeout(Duration::from_millis(100), rx2.recv())
            .await
            .expect("recv timeout — first post-resubscribe notify was dropped")
            .expect("recv ok");
        assert_eq!(got.status_hash, h_initial);
    }

    #[test]
    fn test_address_index_active_scripthashes_filters_zero_receivers() {
        let reg = SubscriptionRegistry::new(100, 32);
        let sh_live = [0x10; 32];
        let sh_dead = [0x20; 32];
        let _live = reg.subscribe(sh_live).unwrap();
        {
            let _dead = reg.subscribe(sh_dead).unwrap();
            // _dead drops at the end of this scope.
        }
        let active = reg.active_scripthashes();
        assert!(active.contains(&sh_live));
        assert!(
            !active.contains(&sh_dead),
            "active_scripthashes must not include zero-receiver channels"
        );
    }

    #[test]
    fn test_address_index_subscribe_dedup_under_cap() {
        let reg = SubscriptionRegistry::new(2, 32);
        let sh = [0x42; 32];
        // Two subscribers to the same scripthash share one channel,
        // so they shouldn't double-count toward the cap.
        let _rx_1 = reg.subscribe(sh).unwrap();
        let _rx_2 = reg.subscribe(sh).unwrap();
        assert_eq!(reg.active_count(), 1);
    }

    #[tokio::test]
    async fn test_address_index_maybe_notify_dedups_repeated_status() {
        use tokio::time::{Duration, timeout};
        let reg = SubscriptionRegistry::new(100, 32);
        let sh = [0x10; 32];
        let mut rx = reg.subscribe(sh).unwrap();

        let h1 = [0x42; 32];
        reg.maybe_notify(sh, h1);
        // First notify must arrive.
        let got1 = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("recv timeout")
            .expect("recv ok");
        assert_eq!(got1.status_hash, h1);

        // Same status repeated — must NOT notify again.
        reg.maybe_notify(sh, h1);
        let got2 = timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(got2.is_err(), "duplicate status must not re-notify");

        // Different status — fires once.
        let h2 = [0x43; 32];
        reg.maybe_notify(sh, h2);
        let got3 = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("recv timeout")
            .expect("recv ok");
        assert_eq!(got3.status_hash, h2);
    }

    #[tokio::test]
    async fn test_address_index_seed_status_suppresses_the_unchanged_push() {
        use tokio::time::{Duration, timeout};
        let reg = SubscriptionRegistry::new(100, 32);
        let sh = [0x31; 32];
        let mut rx = reg.subscribe(sh).unwrap();

        // The subscriber was answered `h0`; a recompute that finds `h0`
        // again has nothing new to say.
        let h0 = [0x50; 32];
        reg.seed_status(sh, h0);
        reg.maybe_notify(sh, h0);
        assert!(
            timeout(Duration::from_millis(50), rx.recv()).await.is_err(),
            "an unchanged status must not be pushed after the subscribe answer"
        );

        // A real change still goes out.
        let h1 = [0x51; 32];
        reg.maybe_notify(sh, h1);
        let got = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("recv timeout — a changed status was not pushed")
            .expect("recv ok");
        assert_eq!(got.status_hash, h1);
    }

    #[tokio::test]
    async fn test_address_index_seed_status_skips_a_shared_channel() {
        // A second subscriber may not have seen the seeding subscriber's
        // answer, so the seed must not mark it delivered.
        use tokio::time::{Duration, timeout};
        let reg = SubscriptionRegistry::new(100, 32);
        let sh = [0x32; 32];
        let mut rx_a = reg.subscribe(sh).unwrap();
        let mut rx_b = reg.subscribe(sh).unwrap();

        let h = [0x60; 32];
        reg.seed_status(sh, h);
        reg.maybe_notify(sh, h);
        for rx in [&mut rx_a, &mut rx_b] {
            let got = timeout(Duration::from_millis(100), rx.recv())
                .await
                .expect("recv timeout — push swallowed by a seed on a shared channel")
                .expect("recv ok");
            assert_eq!(got.status_hash, h);
        }
    }

    #[tokio::test]
    async fn test_address_index_seed_status_keeps_a_pushed_status() {
        // A status already pushed to the subscriber is what it last saw;
        // a seed must not replace it.
        use tokio::time::{Duration, timeout};
        let reg = SubscriptionRegistry::new(100, 32);
        let sh = [0x33; 32];
        let mut rx = reg.subscribe(sh).unwrap();

        let pushed = [0x70; 32];
        reg.maybe_notify(sh, pushed);
        let _ = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("recv timeout")
            .expect("recv ok");

        let answered = [0x71; 32];
        reg.seed_status(sh, answered);
        reg.maybe_notify(sh, answered);
        let got = timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("recv timeout — the seed overwrote the pushed status")
            .expect("recv ok");
        assert_eq!(got.status_hash, answered);
    }
}
