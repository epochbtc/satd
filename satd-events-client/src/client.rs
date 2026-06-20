//! The streaming client: connect, `Subscribe` firehose, and a minimal `Watch`
//! handle. Typed watch helpers and the reconnect/replay resilience layer are
//! added in later revisions; this module establishes the connection, auth, and
//! cursor-capturing event stream they build on.

use std::time::Duration;

use satd_events_proto::v1 as pb;
use satd_events_proto::v1::node_event_stream_client::NodeEventStreamClient;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Channel, Endpoint};

use crate::error::StreamError;
use crate::event::{Cursor, Event};

/// Bounded control-channel depth for a `Watch` stream.
const CONTROL_BUFFER: usize = 16;

/// Category bitfield helpers for [`SubscribeOptions::categories`].
///
/// `0` (the default, [`Categories::ALL`]) means "all categories". Combine the
/// others with `|`.
pub struct Categories;

impl Categories {
    /// All categories (the server default).
    pub const ALL: u32 = 0;
    /// Mempool events.
    pub const MEMPOOL: u32 = 1;
    /// Chain (block connect/disconnect/reorg) events.
    pub const CHAIN: u32 = 2;
    /// Heartbeats.
    pub const HEARTBEAT: u32 = 4;
}

/// Options for a [`StreamClient::subscribe`] firehose.
#[derive(Debug, Clone, Default)]
pub struct SubscribeOptions {
    /// Category bitfield; `0` = all. See [`Categories`].
    pub categories: u32,
    /// Durable replay anchor. When set, the server replays confirmed history
    /// forward from this cursor, then joins live with no gap or duplicate.
    pub from_cursor: Option<Cursor>,
    /// Forward-only dedup filter: drop events with `seq <= since_seq`. Use after
    /// a brief reconnect within the broadcast window — not for durable replay.
    pub since_seq: Option<u64>,
}

impl SubscribeOptions {
    fn into_request(self) -> pb::SubscribeRequest {
        pb::SubscribeRequest {
            categories: self.categories,
            since_seq: self.since_seq,
            from_cursor: self.from_cursor,
        }
    }
}

/// A live stream of typed [`Event`]s, shared by `Subscribe` and `Watch`.
///
/// As confirmed events flow, the stream captures their durable [`Cursor`];
/// [`cursor`](Self::cursor) returns the latest, which a consumer persists and
/// presents as [`SubscribeOptions::from_cursor`] to resume.
pub struct EventStream {
    inner: tonic::Streaming<pb::NodeEvent>,
    last_cursor: Option<Cursor>,
}

impl EventStream {
    /// Await the next event. Returns `Ok(None)` when the server closes the
    /// stream.
    pub async fn message(&mut self) -> Result<Option<Event>, StreamError> {
        match self.inner.message().await {
            Ok(Some(ev)) => {
                if let Some(c) = ev.cursor {
                    self.last_cursor = Some(c);
                }
                Ok(Some(Event::from(ev)))
            }
            Ok(None) => Ok(None),
            Err(status) => Err(StreamError::from_status(status)),
        }
    }

    /// The most recent durable cursor seen on this stream, if any. Persist it
    /// to resume after a disconnect.
    pub fn cursor(&self) -> Option<&Cursor> {
        self.last_cursor.as_ref()
    }
}

/// Auto-close policy for a transaction lifecycle watch: self-evict and emit
/// `TxidFinalized` once the tx is buried this many confirmations deep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AutoClose {
    /// Never auto-close; the lifecycle watch persists until removed.
    #[default]
    Never,
    /// Auto-close once the tx reaches this confirmation depth (>= 1).
    AtDepth(u32),
}

impl AutoClose {
    fn depth(self) -> u32 {
        match self {
            AutoClose::Never => 0,
            AutoClose::AtDepth(d) => d,
        }
    }
}

/// A handle to send control messages on a bidirectional `Watch` stream.
///
/// Typed helpers build and send the right [`SubscribeControl`](pb::SubscribeControl)
/// for each watch kind; [`send_control`](Self::send_control) remains for raw
/// access. Empty inputs are no-ops (nothing is sent). Dropping the handle closes
/// the control channel, which the server uses to tear the stream down.
pub struct WatchHandle {
    tx: mpsc::Sender<pb::SubscribeControl>,
}

impl WatchHandle {
    /// Send a raw [`SubscribeControl`](pb::SubscribeControl) message.
    pub async fn send_control(&self, ctrl: pb::SubscribeControl) -> Result<(), StreamError> {
        self.tx.send(ctrl).await.map_err(|_| StreamError::ControlClosed)
    }

    async fn send_msg(&self, msg: pb::subscribe_control::Msg) -> Result<(), StreamError> {
        self.send_control(pb::SubscribeControl { msg: Some(msg) }).await
    }

    /// Add scripthashes (each `sha256(scriptPubKey)`), with an optional per-script
    /// `min_value` floor in satoshis. Matches below a script's floor are
    /// suppressed (a `None` floor delivers everything). Re-asserting a held
    /// scripthash updates its floor. Charges one watch-quota unit per scripthash.
    pub async fn add_scripts(
        &self,
        items: impl IntoIterator<Item = ([u8; 32], Option<u64>)>,
    ) -> Result<(), StreamError> {
        let items: Vec<_> = items.into_iter().collect();
        if items.is_empty() {
            return Ok(());
        }
        let scripthashes = items.iter().map(|(h, _)| h.to_vec()).collect();
        // `min_values` is empty when no floor is set on any script; otherwise it
        // must be parallel to `scripthashes`, with 0 (deliver-all) for the
        // unfloored entries.
        let min_values = if items.iter().any(|(_, f)| f.is_some()) {
            items.iter().map(|(_, f)| f.unwrap_or(0)).collect()
        } else {
            Vec::new()
        };
        self.send_msg(pb::subscribe_control::Msg::AddScripts(pb::AddScripts {
            scripthashes,
            min_values,
        }))
        .await
    }

    /// Remove scripthashes from the watch-set, releasing their quota.
    pub async fn remove_scripts(
        &self,
        scripthashes: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<(), StreamError> {
        let scripthashes: Vec<Vec<u8>> = scripthashes.into_iter().map(|h| h.to_vec()).collect();
        if scripthashes.is_empty() {
            return Ok(());
        }
        self.send_msg(pb::subscribe_control::Msg::RemoveScripts(pb::RemoveScripts {
            scripthashes,
        }))
        .await
    }

    /// Add outpoints (`txid:vout`) to the watch-set. Charges one unit each.
    pub async fn add_outpoints(
        &self,
        outpoints: impl IntoIterator<Item = ([u8; 32], u32)>,
    ) -> Result<(), StreamError> {
        let outpoints: Vec<pb::Outpoint> = outpoints
            .into_iter()
            .map(|(txid, vout)| pb::Outpoint { txid: txid.to_vec(), vout })
            .collect();
        if outpoints.is_empty() {
            return Ok(());
        }
        self.send_msg(pb::subscribe_control::Msg::AddOutpoints(pb::AddOutpoints { outpoints }))
            .await
    }

    /// Remove outpoints from the watch-set, releasing their quota.
    pub async fn remove_outpoints(
        &self,
        outpoints: impl IntoIterator<Item = ([u8; 32], u32)>,
    ) -> Result<(), StreamError> {
        let outpoints: Vec<pb::Outpoint> = outpoints
            .into_iter()
            .map(|(txid, vout)| pb::Outpoint { txid: txid.to_vec(), vout })
            .collect();
        if outpoints.is_empty() {
            return Ok(());
        }
        self.send_msg(pb::subscribe_control::Msg::RemoveOutpoints(pb::RemoveOutpoints {
            outpoints,
        }))
        .await
    }

    /// Add persistent lifecycle watches on txids (seen → confirmed → replaced /
    /// evicted / unconfirmed). `auto_close` optionally self-evicts the watch once
    /// the tx is buried. Charges one unit per txid.
    pub async fn add_tx_lifecycle(
        &self,
        txids: impl IntoIterator<Item = [u8; 32]>,
        auto_close: AutoClose,
    ) -> Result<(), StreamError> {
        let txids: Vec<Vec<u8>> = txids.into_iter().map(|t| t.to_vec()).collect();
        if txids.is_empty() {
            return Ok(());
        }
        self.send_msg(pb::subscribe_control::Msg::AddTransactions(pb::AddTransactions {
            txids,
            min_depths: Vec::new(),
            auto_close_depth: auto_close.depth(),
        }))
        .await
    }

    /// Remove lifecycle watches on txids.
    pub async fn remove_tx_lifecycle(
        &self,
        txids: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<(), StreamError> {
        let txids: Vec<Vec<u8>> = txids.into_iter().map(|t| t.to_vec()).collect();
        if txids.is_empty() {
            return Ok(());
        }
        self.send_msg(pb::subscribe_control::Msg::RemoveTransactions(pb::RemoveTransactions {
            txids,
            min_depths: Vec::new(),
        }))
        .await
    }

    /// Arm single-shot depth alarms over the **cross product** of `txids` and
    /// `depths`: each txid fires `TxidDepthReached` once it is `depth`
    /// confirmations deep, then self-evicts. Charges one unit per (txid, depth).
    ///
    /// Depths must be `>= 1`; depths `< 1` are dropped client-side. If that
    /// leaves no valid depths (or no txids), this is a no-op — importantly, it
    /// does **not** send an empty `min_depths`, which the server would otherwise
    /// reinterpret as a *lifecycle* add rather than a depth alarm.
    pub async fn add_depth_alarms(
        &self,
        txids: impl IntoIterator<Item = [u8; 32]>,
        depths: impl IntoIterator<Item = u32>,
    ) -> Result<(), StreamError> {
        let txids: Vec<Vec<u8>> = txids.into_iter().map(|t| t.to_vec()).collect();
        let min_depths: Vec<u32> = depths.into_iter().filter(|d| *d >= 1).collect();
        if txids.is_empty() || min_depths.is_empty() {
            return Ok(());
        }
        self.send_msg(pb::subscribe_control::Msg::AddTransactions(pb::AddTransactions {
            txids,
            min_depths,
            auto_close_depth: 0,
        }))
        .await
    }

    /// Remove depth alarms over the cross product of `txids` and `depths`.
    /// Depths `< 1` are dropped client-side; an all-invalid (or empty) call is a
    /// no-op and never sends an empty `min_depths` (which would target lifecycle
    /// watches instead).
    pub async fn remove_depth_alarms(
        &self,
        txids: impl IntoIterator<Item = [u8; 32]>,
        depths: impl IntoIterator<Item = u32>,
    ) -> Result<(), StreamError> {
        let txids: Vec<Vec<u8>> = txids.into_iter().map(|t| t.to_vec()).collect();
        let min_depths: Vec<u32> = depths.into_iter().filter(|d| *d >= 1).collect();
        if txids.is_empty() || min_depths.is_empty() {
            return Ok(());
        }
        self.send_msg(pb::subscribe_control::Msg::RemoveTransactions(pb::RemoveTransactions {
            txids,
            min_depths,
        }))
        .await
    }

    /// Expand a public output descriptor into a watch-set over the window
    /// `[start, start + gap_limit)`. The client owns gap-limit advancement:
    /// re-send with an advanced `start` (and remove trailing scripts) as funding
    /// nears the window's high end.
    pub async fn add_descriptor(
        &self,
        descriptor: impl Into<String>,
        gap_limit: u32,
        start: u32,
    ) -> Result<(), StreamError> {
        self.send_msg(pb::subscribe_control::Msg::AddDescriptor(pb::AddDescriptor {
            descriptor: descriptor.into(),
            gap_limit,
            start,
        }))
        .await
    }

    /// Add privacy-preserving script-prefix buckets: each is a `bits`-bit prefix
    /// of `sha256(scriptPubKey)`, carried as the top `ceil(bits/8)` bytes. The
    /// server delivers every tx in the `2^-bits` bucket and the client filters
    /// locally, so the server learns only the bucket. Charged by coarseness
    /// (smaller `bits` costs more). `bits` must be in `1..=256` and `prefix`
    /// exactly `ceil(bits/8)` bytes; the server additionally enforces its
    /// configured `[streamprefixminbits, streamprefixmaxbits]` range.
    pub async fn add_script_prefixes(
        &self,
        prefixes: impl IntoIterator<Item = (Vec<u8>, u32)>,
    ) -> Result<(), StreamError> {
        let prefixes: Vec<pb::ScriptPrefix> = prefixes
            .into_iter()
            .map(|(prefix, bits)| validate_prefix(prefix, bits))
            .collect::<Result<_, _>>()?;
        if prefixes.is_empty() {
            return Ok(());
        }
        self.send_msg(pb::subscribe_control::Msg::AddScriptPrefixes(pb::AddScriptPrefixes {
            prefixes,
        }))
        .await
    }

    /// Remove script-prefix buckets, releasing their quota.
    pub async fn remove_script_prefixes(
        &self,
        prefixes: impl IntoIterator<Item = (Vec<u8>, u32)>,
    ) -> Result<(), StreamError> {
        let prefixes: Vec<pb::ScriptPrefix> = prefixes
            .into_iter()
            .map(|(prefix, bits)| validate_prefix(prefix, bits))
            .collect::<Result<_, _>>()?;
        if prefixes.is_empty() {
            return Ok(());
        }
        self.send_msg(pb::subscribe_control::Msg::RemoveScriptPrefixes(
            pb::RemoveScriptPrefixes { prefixes },
        ))
        .await
    }

    /// Adjust the live firehose category bitfield (see [`Categories`]). Applies
    /// immediately; does not affect the watch-set.
    pub async fn set_categories(&self, categories: u32) -> Result<(), StreamError> {
        self.send_msg(pb::subscribe_control::Msg::SetCategories(pb::SetCategories {
            categories,
        }))
        .await
    }

    /// Mid-stream re-anchor: replay confirmed history forward from `cursor`, then
    /// resume live, without tearing down the watch-set. Rate-limited per
    /// principal; only one re-anchor drains at a time.
    ///
    /// **Best-effort:** `Ok(())` means the request was sent, not that the
    /// re-anchor ran. The server silently drops an over-rate or concurrent
    /// re-anchor (no error is returned), so do not rely on this for critical
    /// resynchronization — for that, reconnect with `from_cursor`.
    pub async fn set_cursor(&self, cursor: Cursor) -> Result<(), StreamError> {
        self.send_msg(pb::subscribe_control::Msg::SetCursor(pb::SetCursor {
            cursor: Some(cursor),
        }))
        .await
    }
}

/// Validate a prefix/bits pair before it reaches the wire.
fn validate_prefix(prefix: Vec<u8>, bits: u32) -> Result<pb::ScriptPrefix, StreamError> {
    if !(1..=256).contains(&bits) {
        return Err(StreamError::InvalidArgument(format!(
            "prefix bits {bits} out of range 1..=256"
        )));
    }
    let want = bits.div_ceil(8) as usize;
    if prefix.len() != want {
        return Err(StreamError::InvalidArgument(format!(
            "prefix for {bits} bits must be {want} bytes, got {}",
            prefix.len()
        )));
    }
    Ok(pb::ScriptPrefix { prefix, bits })
}

/// Builder for a [`StreamClient`].
///
/// `Debug` is hand-written to redact the bearer token — never derive it here.
#[derive(Clone)]
pub struct StreamClientBuilder {
    endpoint: String,
    token: Option<String>,
    keepalive: Option<(Duration, Duration)>,
}

impl std::fmt::Debug for StreamClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamClientBuilder")
            .field("endpoint", &self.endpoint)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("keepalive", &self.keepalive)
            .finish()
    }
}

impl StreamClientBuilder {
    /// Attach a bearer token, sent as `authorization: Bearer <token>` metadata
    /// on every RPC.
    ///
    /// The token is only honored when the server enforces auth
    /// (`-eventsgrpcauth`); a no-auth (loopback-trust) server ignores it. **This
    /// build does not use TLS**, so over a plaintext `http://` endpoint the token
    /// travels in cleartext — only use it over loopback or through a
    /// TLS-terminating proxy until TLS support lands.
    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Configure client-side HTTP/2 keepalive. Defaults match the server
    /// (30s interval / 20s timeout) when [`keepalive_default`](Self::keepalive_default)
    /// is used; this overrides with explicit seconds.
    pub fn keepalive(mut self, interval_secs: u64, timeout_secs: u64) -> Self {
        self.keepalive =
            Some((Duration::from_secs(interval_secs), Duration::from_secs(timeout_secs)));
        self
    }

    /// Use the server-matching keepalive defaults (30s interval / 20s timeout).
    pub fn keepalive_default(self) -> Self {
        self.keepalive(30, 20)
    }

    /// Connect the transport and return a ready [`StreamClient`].
    pub async fn connect(self) -> Result<StreamClient, StreamError> {
        let auth = match self.token {
            Some(t) => Some(
                format!("Bearer {t}")
                    .parse::<MetadataValue<Ascii>>()
                    .map_err(|_| StreamError::InvalidToken)?,
            ),
            None => None,
        };

        let mut endpoint = Endpoint::from_shared(self.endpoint)
            .map_err(|e| StreamError::InvalidEndpoint(e.to_string()))?;
        if let Some((interval, timeout)) = self.keepalive {
            endpoint = endpoint
                .http2_keep_alive_interval(interval)
                .keep_alive_timeout(timeout)
                .keep_alive_while_idle(true);
        }

        let channel = endpoint.connect().await?;
        Ok(StreamClient { inner: NodeEventStreamClient::new(channel), auth })
    }
}

/// An async client for the satd `satd.events.v1` streaming API.
///
/// `Debug` is hand-written to redact the auth credential — never derive it here.
#[derive(Clone)]
pub struct StreamClient {
    inner: NodeEventStreamClient<Channel>,
    auth: Option<MetadataValue<Ascii>>,
}

impl std::fmt::Debug for StreamClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamClient")
            .field("auth", &self.auth.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl StreamClient {
    /// Start building a client for `endpoint` (e.g. `http://node:50051`).
    pub fn builder(endpoint: impl Into<String>) -> StreamClientBuilder {
        StreamClientBuilder { endpoint: endpoint.into(), token: None, keepalive: None }
    }

    /// Wrap a message in a request carrying the configured auth metadata.
    fn authed<T>(&self, msg: T) -> tonic::Request<T> {
        let mut req = tonic::Request::new(msg);
        if let Some(value) = &self.auth {
            req.metadata_mut().insert("authorization", value.clone());
        }
        req
    }

    /// Open a server-streaming firehose. Requires the `stream:subscribe`
    /// capability when the server enforces auth.
    pub async fn subscribe(
        &mut self,
        opts: SubscribeOptions,
    ) -> Result<EventStream, StreamError> {
        let req = self.authed(opts.into_request());
        let inner = self.inner.subscribe(req).await?.into_inner();
        Ok(EventStream { inner, last_cursor: None })
    }

    /// Open a reconnect-and-replay-aware firehose. Unlike [`subscribe`](Self::subscribe),
    /// the returned [`ResilientSubscription`](crate::ResilientSubscription)
    /// reconnects with backoff, persists and replays the resume cursor, recovers
    /// from `Lagged` per the [`LagPolicy`](crate::LagPolicy), and surfaces
    /// replay-truncation gaps. Connects lazily on the first
    /// [`next`](crate::ResilientSubscription::next).
    pub fn resilient_subscribe(
        &self,
        opts: SubscribeOptions,
        config: crate::ResilientConfig,
    ) -> crate::ResilientSubscription {
        crate::ResilientSubscription::new(self.clone(), opts, config)
    }

    /// Open a bidirectional watch stream, returning a [`WatchHandle`] to send
    /// control messages and an [`EventStream`] of matches + firehose.
    pub async fn watch(&mut self) -> Result<(WatchHandle, EventStream), StreamError> {
        let (tx, rx) = mpsc::channel::<pb::SubscribeControl>(CONTROL_BUFFER);
        let req = self.authed(ReceiverStream::new(rx));
        let inner = self.inner.watch(req).await?.into_inner();
        Ok((WatchHandle { tx }, EventStream { inner, last_cursor: None }))
    }
}

#[cfg(test)]
impl StreamClient {
    /// Build a client over a lazily-connected channel to a dummy endpoint, for
    /// unit tests of layers (e.g. [`ResilientSubscription`](crate::ResilientSubscription))
    /// that need a `StreamClient` value but drive their logic via injected events
    /// and never actually poll the transport. `connect_lazy` performs no I/O, so
    /// no server is required; it must be called from within a Tokio runtime.
    pub(crate) fn for_test() -> Self {
        let channel = Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        StreamClient { inner: NodeEventStreamClient::new(channel), auth: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb::subscribe_control::Msg;

    /// A handle wired to a receiver we can inspect — no server needed.
    fn handle() -> (WatchHandle, mpsc::Receiver<pb::SubscribeControl>) {
        let (tx, rx) = mpsc::channel(16);
        (WatchHandle { tx }, rx)
    }

    fn next(rx: &mut mpsc::Receiver<pb::SubscribeControl>) -> Msg {
        rx.try_recv().expect("a control message was sent").msg.expect("msg set")
    }

    #[tokio::test]
    async fn add_scripts_mixed_floors_emits_parallel_min_values() {
        let (h, mut rx) = handle();
        h.add_scripts([([1u8; 32], Some(5_000)), ([2u8; 32], None)]).await.unwrap();
        match next(&mut rx) {
            Msg::AddScripts(a) => {
                assert_eq!(a.scripthashes.len(), 2);
                // Unfloored entry becomes a 0 floor to keep the vec parallel.
                assert_eq!(a.min_values, vec![5_000, 0]);
            }
            other => panic!("expected AddScripts, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn add_scripts_no_floors_emits_empty_min_values() {
        let (h, mut rx) = handle();
        h.add_scripts([([1u8; 32], None), ([2u8; 32], None)]).await.unwrap();
        match next(&mut rx) {
            Msg::AddScripts(a) => assert!(a.min_values.is_empty()),
            other => panic!("expected AddScripts, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_inputs_send_nothing() {
        let (h, mut rx) = handle();
        h.add_scripts([]).await.unwrap();
        h.add_outpoints([]).await.unwrap();
        h.add_depth_alarms([[1u8; 32]], []).await.unwrap(); // empty depths
        h.add_depth_alarms([], [3]).await.unwrap(); // empty txids
        // depths < 1 are filtered out; an all-invalid call must NOT send an
        // empty min_depths (the server would treat that as a lifecycle add).
        h.add_depth_alarms([[1u8; 32]], [0]).await.unwrap();
        assert!(rx.try_recv().is_err(), "no message should have been sent");
    }

    #[tokio::test]
    async fn lifecycle_vs_depth_alarms_dispatch_on_min_depths() {
        let (h, mut rx) = handle();
        h.add_tx_lifecycle([[7u8; 32]], AutoClose::AtDepth(6)).await.unwrap();
        match next(&mut rx) {
            Msg::AddTransactions(a) => {
                assert!(a.min_depths.is_empty(), "lifecycle => empty min_depths");
                assert_eq!(a.auto_close_depth, 6);
            }
            other => panic!("expected AddTransactions, got {other:?}"),
        }

        h.add_depth_alarms([[7u8; 32], [8u8; 32]], [3, 6]).await.unwrap();
        match next(&mut rx) {
            Msg::AddTransactions(a) => {
                assert_eq!(a.txids.len(), 2);
                assert_eq!(a.min_depths, vec![3, 6]); // cross product, server-side
                assert_eq!(a.auto_close_depth, 0);
            }
            other => panic!("expected AddTransactions, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn prefix_validation_rejects_bad_length_and_bits() {
        let (h, mut rx) = handle();
        // 16 bits needs 2 bytes; give 1.
        let err = h.add_script_prefixes([(vec![0xab], 16)]).await.unwrap_err();
        assert!(matches!(err, StreamError::InvalidArgument(_)));
        // bits out of range.
        let err = h.add_script_prefixes([(vec![], 0)]).await.unwrap_err();
        assert!(matches!(err, StreamError::InvalidArgument(_)));
        // Nothing reached the wire.
        assert!(rx.try_recv().is_err());

        // Valid: 16 bits, 2 bytes.
        h.add_script_prefixes([(vec![0xab, 0xcd], 16)]).await.unwrap();
        match next(&mut rx) {
            Msg::AddScriptPrefixes(a) => {
                assert_eq!(a.prefixes.len(), 1);
                assert_eq!(a.prefixes[0].bits, 16);
                assert_eq!(a.prefixes[0].prefix, vec![0xab, 0xcd]);
            }
            other => panic!("expected AddScriptPrefixes, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn set_cursor_wraps_cursor() {
        let (h, mut rx) = handle();
        let cursor = Cursor { height: 9, tx_index: 0, mempool_seq: 1, instance_id: 2 };
        h.set_cursor(cursor).await.unwrap();
        match next(&mut rx) {
            Msg::SetCursor(s) => assert_eq!(s.cursor, Some(cursor)),
            other => panic!("expected SetCursor, got {other:?}"),
        }
    }
}
