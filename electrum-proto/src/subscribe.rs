//! Per-connection subscription state.
//!
//! Each Electrum client connection holds:
//! - A map of scripthash → forwarding-task handle. The task owns a
//!   `broadcast::Receiver<StatusUpdate>` from
//!   [`AddressIndex::subscribe`](node_index::AddressIndex::subscribe),
//!   converts each update into a JSON-RPC notification string, and
//!   pushes it onto the per-connection mpsc fan-in.
//! - An optional headers task. Same shape but the source is the
//!   [`ChainEvent`](node::chain::events::ChainEvent) broadcast and the
//!   notification method is `blockchain.headers.subscribe`.
//! - The mpsc sender end so spawned tasks can push.
//!
//! The per-connection main loop selects between inbound requests and
//! the mpsc receiver end (see [`crate::server`]). When a notification
//! lands, it's written to the wire as a JSON-RPC notification (no
//! `id`).
//!
//! Tasks are aborted on [`Subscriptions::drop`] so any
//! `node_index::SubscriptionRegistry` slot the connection occupied is
//! released as soon as the connection closes.

use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::consensus::encode::serialize;
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::warn;

use node::chain::events::ChainEvent;
use node_index::{AddressIndex, Scripthash, StatusUpdate};

use crate::dispatch::Notification;
use crate::error::JsonRpcError;
use crate::extras::ElectrumExtras;
use crate::status::status_hash_to_json;

/// Capacity of the per-connection mpsc fan-in. Each spawned subscription
/// task pushes one message per upstream notification; if the client is
/// slow, the channel fills and the task awaits, providing backpressure
/// instead of unbounded memory growth.
pub const NOTIFY_CHANNEL_CAP: usize = 256;

/// Source of chain-tip notifications. Implemented by `ChainState`'s
/// `subscribe_chain_events`. A trait so tests can inject a fake.
pub trait HeadersSource: Send + Sync {
    fn subscribe(&self) -> Option<broadcast::Receiver<ChainEvent>>;
}

impl HeadersSource for node::chain::state::ChainState {
    fn subscribe(&self) -> Option<broadcast::Receiver<ChainEvent>> {
        self.subscribe_chain_events()
    }
}

/// Owns one connection's subscription state. Construct via
/// [`Subscriptions::new`]; pass `&mut self` to the registration
/// methods. Drop aborts every spawned forwarder task.
pub struct Subscriptions {
    scripthash_tasks: HashMap<Scripthash, JoinHandle<()>>,
    headers_task: Option<JoinHandle<()>>,
    notify_tx: mpsc::Sender<String>,
    max_per_conn: usize,
}

impl Subscriptions {
    pub fn new(notify_tx: mpsc::Sender<String>, max_per_conn: usize) -> Self {
        Self {
            scripthash_tasks: HashMap::new(),
            headers_task: None,
            notify_tx,
            max_per_conn,
        }
    }

    /// Number of active scripthash subscriptions on this connection.
    pub fn scripthash_count(&self) -> usize {
        self.scripthash_tasks.len()
    }

    /// Whether this connection is subscribed to header updates.
    pub fn has_headers(&self) -> bool {
        self.headers_task.is_some()
    }

    /// Register a scripthash subscription. Idempotent: re-subscribing
    /// an already-registered scripthash is a no-op (the existing
    /// forwarder keeps running). Errors with
    /// `JsonRpcError::subscription_cap` when the per-connection cap
    /// would be exceeded.
    pub fn add_scripthash(
        &mut self,
        sh: Scripthash,
        idx: &dyn AddressIndex,
    ) -> Result<(), JsonRpcError> {
        // Already-subscribed: re-subscribe is a no-op per Electrum spec.
        if let Some(handle) = self.scripthash_tasks.get(&sh)
            && !handle.is_finished()
        {
            return Ok(());
        }

        if self.scripthash_tasks.len() >= self.max_per_conn {
            return Err(JsonRpcError::subscription_cap(self.max_per_conn));
        }

        // Acquire a receiver from the global registry. May fail with
        // `CapReached` (server-wide cap), which we surface to the
        // client.
        let receiver = idx
            .subscribe(sh)
            .map_err(|e| JsonRpcError::bad_request(format!("subscribe: {e}")))?;

        let tx = self.notify_tx.clone();
        let handle = tokio::spawn(async move {
            forward_scripthash(sh, receiver, tx).await;
        });
        self.scripthash_tasks.insert(sh, handle);
        Ok(())
    }

    /// Cancel a scripthash subscription. Returns `true` if there was a
    /// subscription to cancel (matches electrs's response shape, but
    /// the Electrum spec actually says always-true; the caller maps
    /// however it wants).
    pub fn remove_scripthash(&mut self, sh: &Scripthash) -> bool {
        if let Some(handle) = self.scripthash_tasks.remove(sh) {
            handle.abort();
            true
        } else {
            false
        }
    }

    /// Register a headers subscription. Idempotent. The connection
    /// will receive `blockchain.headers.subscribe` notifications on
    /// every chain-tip extension. Reorg-disconnect notifications are
    /// suppressed because the Electrum protocol's
    /// `headers.subscribe` is documented to fire on new tips, not on
    /// disconnections — clients re-derive their tip view from the
    /// next BlockConnected.
    pub fn add_headers(
        &mut self,
        chain: &dyn HeadersSource,
        extras: Arc<dyn ElectrumExtras>,
    ) -> Result<(), JsonRpcError> {
        if let Some(h) = &self.headers_task
            && !h.is_finished()
        {
            return Ok(());
        }
        let receiver = chain
            .subscribe()
            .ok_or_else(|| JsonRpcError::internal("chain event broadcast not wired"))?;
        let tx = self.notify_tx.clone();
        let handle = tokio::spawn(async move {
            forward_headers(receiver, extras, tx).await;
        });
        self.headers_task = Some(handle);
        Ok(())
    }
}

impl Drop for Subscriptions {
    fn drop(&mut self) {
        for (_sh, handle) in self.scripthash_tasks.drain() {
            handle.abort();
        }
        if let Some(h) = self.headers_task.take() {
            h.abort();
        }
    }
}

/// Forwarder task: consume `StatusUpdate`s for one scripthash and
/// push `blockchain.scripthash.subscribe` notifications onto the
/// per-connection mpsc.
///
/// On `RecvError::Lagged`: the global registry's broadcast channel
/// dropped messages because we couldn't keep up. We don't have the
/// dropped messages but the next live update will carry the
/// up-to-date status, so we just log + count and continue. (Same
/// contract every other consumer of the registry follows.)
async fn forward_scripthash(
    sh: Scripthash,
    mut rx: broadcast::Receiver<StatusUpdate>,
    tx: mpsc::Sender<String>,
) {
    loop {
        match rx.recv().await {
            Ok(update) => {
                let status_param = match status_hash_to_json(update.status_hash) {
                    Some(s) => Value::String(s),
                    None => Value::Null,
                };
                let notif = Notification::new(
                    "blockchain.scripthash.subscribe",
                    json!([crate::types::scripthash_to_wire_hex(&sh), status_param]),
                );
                let s = match serde_json::to_string(&notif) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "scripthash notification serialize failed");
                        continue;
                    }
                };
                if tx.send(s).await.is_err() {
                    // Receiver gone — connection closed. Exit.
                    return;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(
                    target = "electrum::subscribe",
                    scripthash = %crate::types::scripthash_to_wire_hex(&sh),
                    dropped = n,
                    "scripthash subscription lagged",
                );
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

/// Forwarder task: consume `ChainEvent`s and push
/// `blockchain.headers.subscribe` notifications. We only forward
/// `BlockConnected` — `BlockDisconnected` during a reorg yields a new
/// `BlockConnected` for the replacement tip, and notifying twice
/// (once with the old, once with the new) confuses clients that don't
/// distinguish.
async fn forward_headers(
    mut rx: broadcast::Receiver<ChainEvent>,
    extras: Arc<dyn ElectrumExtras>,
    tx: mpsc::Sender<String>,
) {
    loop {
        match rx.recv().await {
            Ok(ChainEvent::BlockConnected { hash: _, height }) => {
                let header = match extras.header_at(height) {
                    Some(h) => h,
                    None => {
                        // Race: the event arrived before
                        // get_block_index could resolve it. Skip
                        // this notification; the next BlockConnected
                        // (or a re-resolve on reconnect) will catch
                        // the client up.
                        continue;
                    }
                };
                let notif = Notification::new(
                    "blockchain.headers.subscribe",
                    json!([{
                        "height": height,
                        "hex": hex::encode(serialize(&header)),
                    }]),
                );
                let s = match serde_json::to_string(&notif) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "headers notification serialize failed");
                        continue;
                    }
                };
                if tx.send(s).await.is_err() {
                    return;
                }
            }
            Ok(ChainEvent::BlockDisconnected { .. }) => {
                // Suppress — see fn doc.
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(
                    target = "electrum::subscribe",
                    dropped = n,
                    "headers subscription lagged",
                );
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash as _;
    use bitcoin::pow::CompactTarget;
    use bitcoin::{BlockHash, Txid};
    use node_index::{
        AddressIndex, HistoryEntry, IndexError, MempoolHistoryEntry, StatusUpdate, SubscribeError,
        Utxo,
    };
    use parking_lot::Mutex;

    /// Trivial ElectrumExtras stub that returns a fixed header at
    /// every height. Used by the headers-forwarder test so the task
    /// can resolve the announced height to a header without needing
    /// a live ChainState.
    struct StubExtras {
        header: Header,
    }
    impl ElectrumExtras for StubExtras {
        fn header_at(&self, _h: u32) -> Option<Header> {
            Some(self.header)
        }
        fn tip(&self) -> (u32, Header) {
            (0, self.header)
        }
        fn raw_tx(&self, _t: &Txid) -> Option<Vec<u8>> {
            None
        }
        fn confirmation(&self, _t: &Txid) -> Option<crate::extras::TxConfirmation> {
            None
        }
        fn tx_merkle(&self, _t: &Txid) -> Option<crate::extras::TxMerkleProof> {
            None
        }
        fn txid_at_pos(&self, _h: u32, _p: u32) -> Option<Txid> {
            None
        }
    }

    fn fixture_header() -> Header {
        Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        }
    }

    /// AddressIndex stub that hands out a single broadcast::Sender per
    /// scripthash on subscribe. Tests drive the sender to inject
    /// StatusUpdates into the forwarder.
    struct ProgrammableIndex {
        senders: Mutex<HashMap<Scripthash, broadcast::Sender<StatusUpdate>>>,
        cap_full: bool,
    }

    impl ProgrammableIndex {
        fn new() -> Self {
            Self {
                senders: Mutex::new(HashMap::new()),
                cap_full: false,
            }
        }

        fn cap_full() -> Self {
            Self {
                senders: Mutex::new(HashMap::new()),
                cap_full: true,
            }
        }

        fn fire(&self, sh: Scripthash, status: [u8; 32]) {
            if let Some(tx) = self.senders.lock().get(&sh) {
                let _ = tx.send(StatusUpdate {
                    scripthash: sh,
                    status_hash: status,
                });
            }
        }
    }

    impl AddressIndex for ProgrammableIndex {
        fn confirmed_history(&self, _: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
            Ok(Vec::new())
        }
        fn mempool_history(&self, _: &Scripthash) -> Vec<MempoolHistoryEntry> {
            Vec::new()
        }
        fn balance(&self, _: &Scripthash) -> Result<(u64, i64), IndexError> {
            Ok((0, 0))
        }
        fn utxos(&self, _: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
            Ok(Vec::new())
        }
        fn subscribe(
            &self,
            sh: Scripthash,
        ) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
            if self.cap_full {
                return Err(SubscribeError::CapReached(0));
            }
            let mut map = self.senders.lock();
            let tx = map.entry(sh).or_insert_with(|| broadcast::channel(16).0);
            Ok(tx.subscribe())
        }
    }

    struct ChainEventFake {
        sender: broadcast::Sender<ChainEvent>,
    }

    impl ChainEventFake {
        fn new() -> Self {
            let (tx, _rx) = broadcast::channel(16);
            Self { sender: tx }
        }

        fn fire_connect(&self, hash: BlockHash, height: u32) {
            let _ = self
                .sender
                .send(ChainEvent::BlockConnected { hash, height });
        }
    }

    impl HeadersSource for ChainEventFake {
        fn subscribe(&self) -> Option<broadcast::Receiver<ChainEvent>> {
            Some(self.sender.subscribe())
        }
    }

    #[tokio::test]
    async fn add_scripthash_pushes_notification_on_status_update() {
        let idx = ProgrammableIndex::new();
        let (tx, mut rx) = mpsc::channel(8);
        let mut subs = Subscriptions::new(tx, 10);
        let sh: Scripthash = [0x42; 32];

        subs.add_scripthash(sh, &idx).unwrap();
        assert_eq!(subs.scripthash_count(), 1);

        // Yield once to let the forwarder task subscribe.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        idx.fire(sh, [0x99; 32]);

        let got = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        let v: Value = serde_json::from_str(&got).unwrap();
        assert_eq!(v["method"], "blockchain.scripthash.subscribe");
        assert_eq!(v["params"][0].as_str().unwrap(), &"42".repeat(32));
        // Status param should be the hex-encoded non-zero status.
        assert_eq!(v["params"][1].as_str().unwrap(), &"99".repeat(32));
    }

    #[tokio::test]
    async fn empty_status_renders_as_json_null() {
        let idx = ProgrammableIndex::new();
        let (tx, mut rx) = mpsc::channel(8);
        let mut subs = Subscriptions::new(tx, 10);
        let sh: Scripthash = [0x10; 32];
        subs.add_scripthash(sh, &idx).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        idx.fire(sh, [0u8; 32]);
        let got = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let v: Value = serde_json::from_str(&got).unwrap();
        assert!(v["params"][1].is_null());
    }

    #[tokio::test]
    async fn add_scripthash_per_conn_cap() {
        let idx = ProgrammableIndex::new();
        let (tx, _rx) = mpsc::channel(8);
        let mut subs = Subscriptions::new(tx, 1);
        subs.add_scripthash([0x01; 32], &idx).unwrap();
        let err = subs.add_scripthash([0x02; 32], &idx).unwrap_err();
        assert_eq!(err.code, 3);
    }

    #[tokio::test]
    async fn add_scripthash_idempotent() {
        let idx = ProgrammableIndex::new();
        let (tx, _rx) = mpsc::channel(8);
        let mut subs = Subscriptions::new(tx, 2);
        let sh: Scripthash = [0xaa; 32];
        subs.add_scripthash(sh, &idx).unwrap();
        subs.add_scripthash(sh, &idx).unwrap();
        assert_eq!(subs.scripthash_count(), 1);
    }

    #[tokio::test]
    async fn add_scripthash_surfaces_global_cap_error() {
        let idx = ProgrammableIndex::cap_full();
        let (tx, _rx) = mpsc::channel(8);
        let mut subs = Subscriptions::new(tx, 100);
        let err = subs.add_scripthash([0xbb; 32], &idx).unwrap_err();
        // Server-wide cap surfaced via electrs-style BadRequest (code 1)
        // — same code the at-capacity overflow path uses so retrying
        // wallets can converge on a single backoff behaviour.
        assert_eq!(err.code, 1);
    }

    #[tokio::test]
    async fn remove_scripthash_aborts_forwarder() {
        let idx = ProgrammableIndex::new();
        let (tx, mut rx) = mpsc::channel(8);
        let mut subs = Subscriptions::new(tx, 10);
        let sh: Scripthash = [0xcc; 32];
        subs.add_scripthash(sh, &idx).unwrap();
        assert!(subs.remove_scripthash(&sh));
        assert_eq!(subs.scripthash_count(), 0);

        // After remove, firing a status update must not produce a
        // notification.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        idx.fire(sh, [0x77; 32]);
        let got = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
        assert!(got.is_err(), "got unexpected notification: {got:?}");
    }

    #[tokio::test]
    async fn add_headers_pushes_notification_on_block_connected() {
        let chain = ChainEventFake::new();
        let extras: Arc<dyn ElectrumExtras> = Arc::new(StubExtras {
            header: fixture_header(),
        });
        let (tx, mut rx) = mpsc::channel(8);
        let mut subs = Subscriptions::new(tx, 10);
        subs.add_headers(&chain, extras).unwrap();
        assert!(subs.has_headers());

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        chain.fire_connect(BlockHash::all_zeros(), 700_000);

        let got = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let v: Value = serde_json::from_str(&got).unwrap();
        assert_eq!(v["method"], "blockchain.headers.subscribe");
        assert_eq!(v["params"][0]["height"], 700_000);
    }

    #[tokio::test]
    async fn drop_aborts_all_forwarders() {
        let idx = ProgrammableIndex::new();
        let (tx, mut rx) = mpsc::channel(8);
        {
            let mut subs = Subscriptions::new(tx, 10);
            subs.add_scripthash([0x01; 32], &idx).unwrap();
            subs.add_scripthash([0x02; 32], &idx).unwrap();
            assert_eq!(subs.scripthash_count(), 2);
        }
        // After drop, sender side closes; rx eventually drains. The
        // tasks were aborted; firing a status update post-drop must
        // not produce a notification. Both outcomes are valid:
        // - Err(Elapsed): timeout (channel still has senders somewhere
        //   but nothing arrived — also fine)
        // - Ok(None): channel closed because every Sender clone dropped
        //   (the spawned forwarder tasks were aborted and the inner
        //   notify_tx was the only other clone).
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        idx.fire([0x01; 32], [0x99; 32]);
        let got = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
        match got {
            Ok(None) | Err(_) => {}
            Ok(Some(s)) => panic!("subscriptions drop failed to abort: got {s}"),
        }
    }
}
