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
//!   re-sent on every (re)connect, in place of a manual re-add.
//! - **Re-anchor in place** — after replay it `set_cursor`s to the persisted
//!   high-water and resumes confirmed replay. Transient rejects
//!   (`RateLimited`, `ConcurrentReanchor`) are backed off and retried in place;
//!   terminal ones (`NoSource`, …) and the `clamped` accept are surfaced so the
//!   caller can escalate to a full resnapshot — the exception, not the rule.
//! - **Cursor persistence** — confirmed cursors are committed-on-poll to a
//!   shared [`CursorStore`], so a resume survives reconnects and restarts.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use satd_events_proto::v1 as pb;
use satd_events_proto::v1::subscribe_control::Msg;

use crate::client::{validate_prefix, AutoClose, EventStream, StreamClient, WatchHandle};
use crate::error::StreamError;
use crate::event::{Cursor, CursorRejectReason, Event};
use crate::resilience::{Backoff, CursorStore, NoopCursorStore};

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
}

impl Default for ResilientWatchConfig {
    fn default() -> Self {
        ResilientWatchConfig {
            backoff: Backoff::default(),
            cursor_store: Arc::new(NoopCursorStore),
            from_cursor: None,
        }
    }
}

impl std::fmt::Debug for ResilientWatchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResilientWatchConfig")
            .field("backoff", &self.backoff)
            .field("cursor_store", &"<dyn CursorStore>")
            .field("from_cursor", &self.from_cursor)
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
/// watch-set).
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
    /// `start` to slide the window (fine-grained mid-window script trims are not
    /// separately preserved across a reconnect). See [`WatchHandle::add_descriptor`].
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

    /// Request a mid-stream re-anchor to `cursor` (replay confirmed history from
    /// it). The outcome arrives in-band on [`next`](Self::next) as
    /// [`Event::CursorAccepted`] / [`Event::CursorRejected`]; transient rejects
    /// are retried in place automatically.
    pub async fn set_cursor(&mut self, cursor: Cursor) -> Result<(), StreamError> {
        self.desired_cursor = Some(cursor);
        self.reanchor_attempts = 0;
        let res = match &self.handle {
            Some(h) => Some(h.set_cursor(cursor).await),
            None => None,
        };
        self.after_send(res)
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
    pub async fn next(&mut self) -> Result<Event, StreamError> {
        self.commit_due()?;
        loop {
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
                return Ok(Some(ev));
            }
            let delay = self.config.backoff.delay_for(self.reanchor_attempts);
            self.reanchor_attempts = self.reanchor_attempts.saturating_add(1);
            tokio::time::sleep(delay).await;
            if let Some(c) = self.desired_cursor {
                let res = match &self.handle {
                    Some(h) => Some(h.set_cursor(c).await),
                    None => None,
                };
                self.after_send(res)?;
            }
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

    /// Open a fresh `Watch` stream, re-register the mirrored watch-set, and
    /// re-anchor to the resume cursor. A control-send failure here means the new
    /// stream is already unusable — surfaced as an error for [`next`](Self::next)
    /// to back off and retry.
    async fn connect(&mut self) -> Result<(), StreamError> {
        self.seed_resume()?;
        let (handle, stream) = self.client.watch().await?;
        for msg in self.mirror.control_messages() {
            handle.send_control(pb::SubscribeControl { msg: Some(msg) }).await?;
        }
        self.desired_cursor = self.resume;
        self.reanchor_attempts = 0;
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
/// `ControlClosed` to the transport-retryable set: a freshly-opened stream that
/// rejects the watch-set replay is itself a transient failure to reconnect
/// through, not a caller-facing error.
fn is_reconnectable(e: &StreamError) -> bool {
    e.is_retryable() || matches!(e, StreamError::ControlClosed)
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
        // Disconnected, so the in-place re-send is a no-op; we only assert the
        // retry budget accounting and that the reject is consumed (Ok(None))
        // until exhausted, then surfaced.
        assert!(w.handle_event(reject(), None).await.unwrap().is_none(), "retry 1 consumed");
        assert!(w.handle_event(reject(), None).await.unwrap().is_none(), "retry 2 consumed");
        let out = w.handle_event(reject(), None).await.unwrap();
        assert!(
            matches!(out, Some(Event::CursorRejected { .. })),
            "budget exhausted → surfaced for the caller to escalate"
        );
        assert_eq!(w.reanchor_attempts, 0, "counter resets after surfacing");
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
}
