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

/// A handle to send control messages on a bidirectional `Watch` stream.
///
/// This revision exposes the low-level [`send_control`](Self::send_control);
/// typed helpers (`add_scripts`, `add_outpoints`, `set_cursor`, …) are layered
/// on in a later revision. Dropping the handle closes the control channel,
/// which the server uses to tear the stream down.
pub struct WatchHandle {
    tx: mpsc::Sender<pb::SubscribeControl>,
}

impl WatchHandle {
    /// Send a raw [`SubscribeControl`](pb::SubscribeControl) message.
    pub async fn send_control(&self, ctrl: pb::SubscribeControl) -> Result<(), StreamError> {
        self.tx.send(ctrl).await.map_err(|_| StreamError::ControlClosed)
    }
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

    /// Open a bidirectional watch stream, returning a [`WatchHandle`] to send
    /// control messages and an [`EventStream`] of matches + firehose.
    pub async fn watch(&mut self) -> Result<(WatchHandle, EventStream), StreamError> {
        let (tx, rx) = mpsc::channel::<pb::SubscribeControl>(CONTROL_BUFFER);
        let req = self.authed(ReceiverStream::new(rx));
        let inner = self.inner.watch(req).await?.into_inner();
        Ok((WatchHandle { tx }, EventStream { inner, last_cursor: None }))
    }
}
