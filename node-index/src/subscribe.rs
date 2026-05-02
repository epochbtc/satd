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
//! ordered by `(height_or_zero, txid)`, with mempool entries assigned
//! `height = 0`. The trailing colon after the last entry is included
//! per Electrum-server convention. An empty-history scripthash has
//! status `[0u8; 32]` (the sha256 of the empty string is the
//! Electrum canonical "no data" sentinel — but the protocol uses
//! the all-zero array; we mirror that).

use std::collections::HashMap;
use std::sync::Mutex;

use bitcoin::Txid;
use bitcoin::hashes::{Hash, sha256};
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
    /// `Err(SubscribeError::CapReached)`.
    max_subs: usize,
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
            max_subs,
            per_channel_capacity,
            last_status: Mutex::new(HashMap::new()),
        }
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
        let mut channels = self.channels.lock().unwrap();
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
        let live_keys: std::collections::HashSet<Scripthash> =
            channels.keys().copied().collect();
        self.last_status
            .lock()
            .unwrap()
            .retain(|sh, _| live_keys.contains(sh));
        if channels.len() >= self.max_subs {
            return Err(SubscribeError::CapReached(self.max_subs));
        }
        let (tx, rx) = broadcast::channel(self.per_channel_capacity);
        channels.insert(sh, tx);
        Ok(rx)
    }

    /// Number of distinct scripthashes currently subscribed. Used by
    /// the `satd_addrindex_subscriptions_active` Prometheus gauge.
    pub fn active_count(&self) -> usize {
        self.channels.lock().unwrap().len()
    }

    /// Forget all per-scripthash channels with zero remaining
    /// subscribers. Called periodically from the notifier so
    /// abandoned channels don't accumulate forever.
    pub fn prune_empty(&self) {
        let mut channels = self.channels.lock().unwrap();
        channels.retain(|_, tx| tx.receiver_count() > 0);
        // Drop matching last_status entries — a future re-subscribe
        // recomputes status_hash from current state, which is correct.
        let live_keys: std::collections::HashSet<Scripthash> = channels.keys().copied().collect();
        self.last_status
            .lock()
            .unwrap()
            .retain(|sh, _| live_keys.contains(sh));
    }

    /// All scripthashes with at least one active subscriber. Filters
    /// channels whose receivers have all dropped — those should not
    /// drive notifier work or `last_status` updates, both of which
    /// would be wasted.
    pub fn active_scripthashes(&self) -> Vec<Scripthash> {
        self.channels
            .lock()
            .unwrap()
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
        let channels = self.channels.lock().unwrap();
        let tx = match channels.get(&sh) {
            Some(tx) if tx.receiver_count() > 0 => tx.clone(),
            _ => return,
        };
        drop(channels);

        let mut last = self.last_status.lock().unwrap();
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
}

/// Compute the Electrum status hash for a scripthash given:
///
/// - `confirmed`: list of `(height, txid)` for confirmed history,
///   in `(height, txid)` ascending order.
/// - `mempool`: list of mempool txids — assigned `height=0` per
///   Electrum convention.
///
/// Returns the all-zero hash for an empty history (canonical
/// "no data" sentinel). Otherwise sha256 of
/// `"<txid>:<height>:<txid>:<height>:..."`.
pub fn status_hash(confirmed: &[(u32, Txid)], mempool: &[Txid]) -> [u8; 32] {
    if confirmed.is_empty() && mempool.is_empty() {
        return [0u8; 32];
    }

    // Build sorted (height, txid) pairs. Mempool entries get height=0
    // so they sort first when interleaved with low-height confirmations.
    // Within a height, sort by txid.
    let mut entries: Vec<(u32, Txid)> = Vec::with_capacity(confirmed.len() + mempool.len());
    for &(h, t) in confirmed {
        entries.push((h, t));
    }
    for t in mempool {
        entries.push((0, *t));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut concat = String::new();
    for (h, t) in &entries {
        // Electrum hex encoding of txid: hex of byte-reversed (display)
        // form, which is what `Txid::to_string()` produces in rust-
        // bitcoin.
        concat.push_str(&t.to_string());
        concat.push(':');
        concat.push_str(&h.to_string());
        concat.push(':');
    }
    sha256::Hash::hash(concat.as_bytes()).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_txid(byte: u8) -> Txid {
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    #[test]
    fn test_address_index_status_hash_empty_is_zero() {
        let h = status_hash(&[], &[]);
        assert_eq!(h, [0u8; 32]);
    }

    #[test]
    fn test_address_index_status_hash_changes_on_new_entry() {
        let txid_a = fixture_txid(0x01);
        let txid_b = fixture_txid(0x02);
        let h1 = status_hash(&[(100, txid_a)], &[]);
        let h2 = status_hash(&[(100, txid_a), (101, txid_b)], &[]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_address_index_status_hash_stable_under_input_reordering() {
        let txid_a = fixture_txid(0x10);
        let txid_b = fixture_txid(0x20);
        let h1 = status_hash(&[(50, txid_a), (60, txid_b)], &[]);
        let h2 = status_hash(&[(60, txid_b), (50, txid_a)], &[]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_address_index_status_hash_mempool_height_zero() {
        let txid_mp = fixture_txid(0x30);
        let txid_conf = fixture_txid(0x31);
        let h_with_mp = status_hash(&[(100, txid_conf)], &[txid_mp]);
        let h_no_mp = status_hash(&[(100, txid_conf)], &[]);
        assert_ne!(
            h_with_mp, h_no_mp,
            "adding a mempool entry must change status hash"
        );
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
}
