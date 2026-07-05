//! The streaming client: connect, `Subscribe` firehose, and the `Watch` handle
//! with its typed watch helpers. This module establishes the connection, auth,
//! and cursor-capturing event stream that the reconnect/replay resilience layer
//! (the `resilience` module) builds on.

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
    /// `[start, start + gap_limit)`. The server retains the descriptor →
    /// scripthashes membership, so the client owns gap-limit advancement by
    /// re-sending with an advanced `start` (the server reconciles the slid
    /// window) and can drop the whole window with
    /// [`remove_descriptor`](Self::remove_descriptor).
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

    /// Remove a descriptor previously added with [`add_descriptor`](Self::add_descriptor),
    /// releasing every scripthash its window contributed whose last owner this
    /// drops. A scripthash the descriptor shares with a direct `add_scripts` or
    /// another descriptor stays watched. `descriptor` must byte-match the string
    /// it was added with; removing an unknown descriptor is a no-op.
    pub async fn remove_descriptor(
        &self,
        descriptor: impl Into<String>,
    ) -> Result<(), StreamError> {
        self.send_msg(pb::subscribe_control::Msg::RemoveDescriptor(pb::RemoveDescriptor {
            descriptor: descriptor.into(),
        }))
        .await
    }

    /// Add privacy-preserving script-prefix buckets: each is a `bits`-bit prefix
    /// of `sha256(scriptPubKey)`, carried as the top `ceil(bits/8)` bytes. The
    /// server delivers every tx in the `2^-bits` bucket and the client filters
    /// locally, so the server learns only the bucket. Charged by coarseness
    /// (smaller `bits` costs more). `bits` must be in `1..=32` (the server
    /// buckets on the top 32 bits of the scripthash; wider is meaningless and
    /// silently dropped) and `prefix` exactly `ceil(bits/8)` bytes; the server
    /// additionally enforces its configured
    /// `[streamprefixminbits, streamprefixmaxbits]` range.
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

    /// Set per-stream delivery options. With `include_raw_tx = true`, subsequent
    /// [`Event::ScriptMatched`](crate::Event::ScriptMatched) on this stream carry
    /// the full serialized matching transaction in
    /// [`raw_tx`](crate::Event::ScriptMatched); `false` restores the default
    /// (empty). Applies immediately; does not affect the watch-set. Bandwidth-
    /// heavy — the value fields (`amount`) already cover the common case, so
    /// enable this only when you need the whole transaction.
    ///
    /// When driving a [`ResilientWatch`](crate::ResilientWatch), prefer its
    /// [`set_watch_options`](crate::ResilientWatch::set_watch_options) so the
    /// opt-in is re-applied across reconnects.
    pub async fn set_watch_options(&self, include_raw_tx: bool) -> Result<(), StreamError> {
        self.send_msg(pb::subscribe_control::Msg::SetWatchOptions(
            pb::SetWatchOptions { include_raw_tx },
        ))
        .await
    }

    /// Mid-stream re-anchor: replay confirmed history forward from `cursor`, then
    /// resume live, without tearing down the watch-set. Rate-limited per
    /// principal; only one re-anchor drains at a time.
    ///
    /// `Ok(())` means the request was written to the control stream — **not**
    /// that the re-anchor ran. The outcome arrives **in-band on the event
    /// stream** as exactly one of (#439):
    ///
    /// - [`Event::CursorAccepted`](crate::Event::CursorAccepted) — admitted;
    ///   confirmed-history replay follows it (watch for `clamped` to learn the
    ///   server truncated the lower end and you must full-resync below
    ///   `earliest_replayed`).
    /// - [`Event::CursorRejected`](crate::Event::CursorRejected) — declined
    ///   (rate-limited, concurrent re-anchor, empty cursor, or no block source);
    ///   the live stream is unchanged. Retry, back off, or escalate to a full
    ///   resnapshot per the [`reason`](crate::CursorRejectReason).
    ///
    /// A consumer that needs at-least-once delivery should drive its catch-up
    /// state machine off these events rather than treating `Ok(())` as success.
    pub async fn set_cursor(&self, cursor: Cursor) -> Result<(), StreamError> {
        self.send_msg(pb::subscribe_control::Msg::SetCursor(pb::SetCursor {
            cursor: Some(cursor),
        }))
        .await
    }

    /// Request a bounded historical rescan of the current watch-set over the
    /// inclusive height range `[from_height, to_height]`. The outcome arrives
    /// in-band on the event stream as [`Event`](crate::Event)`::RescanAccepted` /
    /// `RescanRejected`; on accept, confirmed watch-matches for the range follow
    /// in height order, terminated by `RescanComplete`.
    ///
    /// A side query: it does not move the durable cursor and runs independently
    /// of the live tail or any in-flight re-anchor. The server span-caps the
    /// range and admits at most one rescan at a time (a second is rejected
    /// `ConcurrentRescan`). `Ok(())` means the request was sent, not that it was
    /// admitted — drive off the in-band result.
    pub async fn rescan(&self, from_height: u32, to_height: u32) -> Result<(), StreamError> {
        self.send_msg(pb::subscribe_control::Msg::RescanBlocks(pb::RescanBlocks {
            from_height,
            to_height,
        }))
        .await
    }
}

/// The maximum meaningful prefix width. The server buckets on the top 32 bits of
/// `sha256(scriptPubKey)` (its mask saturates at 32) and its default
/// `streamprefixmaxbits` is 32, so a `bits > 32` registration can never be more
/// selective and is silently dropped server-side (the control path has no ack).
/// We reject it client-side rather than let a caller believe a watch was
/// installed. A server may further *lower* the max via `streamprefixmaxbits`;
/// that bound is not advertised over the wire, so an over-precise (but ≤ 32)
/// prefix can still be silently dropped — there is no client-side signal for it.
pub(crate) const MAX_PREFIX_BITS: u32 = 32;

/// Validate a prefix/bits pair before it reaches the wire.
pub(crate) fn validate_prefix(
    prefix: Vec<u8>,
    bits: u32,
) -> Result<pb::ScriptPrefix, StreamError> {
    if !(1..=MAX_PREFIX_BITS).contains(&bits) {
        return Err(StreamError::InvalidArgument(format!(
            "prefix bits {bits} out of range 1..={MAX_PREFIX_BITS}"
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

/// TLS settings assembled by the `StreamClientBuilder::tls*` methods and applied
/// in [`connect`](StreamClientBuilder::connect). `Some(..)` on the builder means
/// TLS is enabled; the fields refine trust and identity.
#[cfg(feature = "tls")]
#[derive(Clone, Default)]
struct TlsSettings {
    /// PEM CA (or self-signed leaf) to verify the server cert. `None` → trust the
    /// bundled Mozilla webpki roots (public-CA servers).
    ca_pem: Option<Vec<u8>>,
    /// mTLS client identity: `(cert_pem, key_pem)`.
    identity: Option<(Vec<u8>, Vec<u8>)>,
    /// SNI / certificate domain-name override (e.g. when connecting by IP).
    domain: Option<String>,
}

/// Builder for a [`StreamClient`].
///
/// `Debug` is hand-written to redact the bearer token (and never leak TLS key
/// material) — never derive it here.
#[derive(Clone)]
pub struct StreamClientBuilder {
    endpoint: String,
    token: Option<String>,
    keepalive: Option<(Duration, Duration)>,
    #[cfg(feature = "tls")]
    tls: Option<TlsSettings>,
}

impl std::fmt::Debug for StreamClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("StreamClientBuilder");
        d.field("endpoint", &self.endpoint)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("keepalive", &self.keepalive);
        #[cfg(feature = "tls")]
        d.field("tls", &self.tls.is_some());
        d.finish()
    }
}

impl StreamClientBuilder {
    /// Attach a bearer token, sent as `authorization: Bearer <token>` metadata
    /// on every RPC.
    ///
    /// The token is only honored when the server enforces auth
    /// (`-eventsgrpcauth`); a no-auth (loopback-trust) server ignores it. Over a
    /// plaintext `http://` endpoint the token travels in cleartext — enable
    /// [`tls`](Self::tls) (or [`tls_ca_pem`](Self::tls_ca_pem)) so the connection
    /// is encrypted, or restrict bearer auth to loopback / a TLS-terminating
    /// proxy.
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

    /// Enable TLS for the connection, trusting the bundled Mozilla root CAs
    /// (for a server with a publicly-trusted certificate). For a private or
    /// self-signed CA — the usual case for a satd node — use
    /// [`tls_ca_pem`](Self::tls_ca_pem) instead. Requires the `tls` feature
    /// (on by default).
    #[cfg(feature = "tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
    pub fn tls(mut self) -> Self {
        self.tls.get_or_insert_with(TlsSettings::default);
        self
    }

    /// Enable TLS and verify the server certificate against the PEM CA (or
    /// self-signed leaf) in `pem` — the usual choice for a satd node serving its
    /// own certificate. Replaces the bundled roots for this connection.
    #[cfg(feature = "tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
    pub fn tls_ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.tls.get_or_insert_with(TlsSettings::default).ca_pem = Some(pem.into());
        self
    }

    /// Enable mutual TLS: present this PEM client certificate + private key to a
    /// server configured for mTLS (`-eventsgrpcmtls`). Combine with
    /// [`tls_ca_pem`](Self::tls_ca_pem) to pin the server's CA — without it the
    /// *server* certificate is verified against the bundled public Mozilla roots,
    /// so a self-signed satd node (the usual mTLS case) will fail the handshake
    /// unless you also call `tls_ca_pem`.
    #[cfg(feature = "tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
    pub fn tls_client_identity(
        mut self,
        cert_pem: impl Into<Vec<u8>>,
        key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        self.tls.get_or_insert_with(TlsSettings::default).identity =
            Some((cert_pem.into(), key_pem.into()));
        self
    }

    /// Override the certificate domain name verified during the TLS handshake
    /// (SNI). Use when the endpoint host differs from the certificate subject —
    /// e.g. connecting by IP, or through a proxy. Enables TLS if not already.
    #[cfg(feature = "tls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
    pub fn tls_domain(mut self, domain: impl Into<String>) -> Self {
        self.tls.get_or_insert_with(TlsSettings::default).domain = Some(domain.into());
        self
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

        // TLS is selected by tonic purely from the URI scheme, *not* from
        // whether a `ClientTlsConfig` is attached: an `http://` (or scheme-less)
        // endpoint silently connects in cleartext even with TLS configured,
        // leaking the bearer token and the whole event stream while the caller
        // believes the link is encrypted. Fail closed rather than downgrade.
        #[cfg(feature = "tls")]
        if self.tls.is_some() {
            let scheme_is_https = self
                .endpoint
                .split_once("://")
                .map(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
                .unwrap_or(false);
            if !scheme_is_https {
                return Err(StreamError::InvalidEndpoint(
                    "TLS was requested (tls / tls_ca_pem / tls_client_identity / tls_domain) but \
                     the endpoint scheme is not https:// — refusing to connect in cleartext; use \
                     an https:// endpoint"
                        .to_string(),
                ));
            }
        }

        let mut endpoint = Endpoint::from_shared(self.endpoint)
            .map_err(|e| StreamError::InvalidEndpoint(e.to_string()))?;
        if let Some((interval, timeout)) = self.keepalive {
            endpoint = endpoint
                .http2_keep_alive_interval(interval)
                .keep_alive_timeout(timeout)
                .keep_alive_while_idle(true);
        }
        #[cfg(feature = "tls")]
        if let Some(tls) = self.tls {
            ensure_crypto_provider();
            let mut cfg = tonic::transport::ClientTlsConfig::new();
            // A pinned CA verifies exactly that authority (the satd self-signed
            // case); otherwise fall back to the bundled public roots.
            cfg = match tls.ca_pem {
                Some(ca) => cfg.ca_certificate(tonic::transport::Certificate::from_pem(ca)),
                None => cfg.with_webpki_roots(),
            };
            if let Some((cert, key)) = tls.identity {
                cfg = cfg.identity(tonic::transport::Identity::from_pem(cert, key));
            }
            if let Some(domain) = tls.domain {
                cfg = cfg.domain_name(domain);
            }
            endpoint = endpoint.tls_config(cfg)?;
        }

        let channel = endpoint.connect().await?;
        Ok(StreamClient { inner: NodeEventStreamClient::new(channel), auth })
    }
}

/// Install `ring` as the process-default rustls `CryptoProvider`, once. In this
/// workspace `tonic/tls` resolves to ring only, so rustls already auto-selects
/// it; this is belt-and-suspenders for a build that *also* compiled `aws-lc-rs`
/// (a downstream consumer that doesn't pin the provider), where the default
/// would otherwise be ambiguous and panic. Best-effort — if the application
/// already installed a provider, that one stays.
#[cfg(feature = "tls")]
fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
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
    /// Start building a client for `endpoint` (e.g. `http://node:50051`, or
    /// `https://node:50051` with [`tls`](StreamClientBuilder::tls)).
    pub fn builder(endpoint: impl Into<String>) -> StreamClientBuilder {
        StreamClientBuilder {
            endpoint: endpoint.into(),
            token: None,
            keepalive: None,
            #[cfg(feature = "tls")]
            tls: None,
        }
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

    /// Open a reconnect-and-replay-aware bidirectional watch. Unlike
    /// [`watch`](Self::watch), the returned [`ResilientWatch`](crate::ResilientWatch)
    /// mirrors the watch-set and re-registers it on reconnect, re-anchors off the
    /// deterministic `set_cursor` results, and persists the resume cursor.
    /// Connects lazily on the first [`next`](crate::ResilientWatch::next).
    pub fn resilient_watch(&self, config: crate::ResilientWatchConfig) -> crate::ResilientWatch {
        crate::ResilientWatch::new(self.clone(), config)
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
impl WatchHandle {
    /// A handle wired to an inspectable receiver — for unit tests in sibling
    /// modules (e.g. `ResilientWatch::reload`) that assert the control messages a
    /// layer sends. No server needed.
    pub(crate) fn for_test() -> (Self, mpsc::Receiver<pb::SubscribeControl>) {
        let (tx, rx) = mpsc::channel(64);
        (WatchHandle { tx }, rx)
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
        // bits out of range (too small).
        let err = h.add_script_prefixes([(vec![], 0)]).await.unwrap_err();
        assert!(matches!(err, StreamError::InvalidArgument(_)));
        // bits above the server's 32-bit ceiling: rejected client-side rather
        // than sent and silently dropped by the server (5 bytes = ceil(33/8)).
        let err = h.add_script_prefixes([(vec![0u8; 5], 33)]).await.unwrap_err();
        assert!(matches!(err, StreamError::InvalidArgument(_)));
        // Nothing reached the wire.
        assert!(rx.try_recv().is_err());

        // Valid boundary: exactly 32 bits, 4 bytes.
        h.add_script_prefixes([(vec![0xde, 0xad, 0xbe, 0xef], 32)]).await.unwrap();
        match next(&mut rx) {
            Msg::AddScriptPrefixes(a) => assert_eq!(a.prefixes[0].bits, 32),
            other => panic!("expected AddScriptPrefixes, got {other:?}"),
        }

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

    /// The builder's `Debug` must show only that TLS is enabled — never the CA
    /// bytes, the client key, or the bearer token.
    #[cfg(feature = "tls")]
    #[test]
    fn tls_builder_debug_redacts_secrets() {
        let b = StreamClient::builder("https://node:50051")
            .bearer_token("SUPER_SECRET_TOKEN")
            .tls_ca_pem(b"-----BEGIN CERTIFICATE-----SECRET_CA_BYTES".to_vec())
            .tls_client_identity(b"CLIENT_CERT".to_vec(), b"CLIENT_PRIVATE_KEY".to_vec());
        let dbg = format!("{b:?}");
        assert!(dbg.contains("tls: true"), "expected tls: true, got {dbg}");
        assert!(dbg.contains("<redacted>"), "token should be redacted: {dbg}");
        assert!(!dbg.contains("SUPER_SECRET_TOKEN"));
        assert!(!dbg.contains("SECRET_CA_BYTES"));
        assert!(!dbg.contains("CLIENT_PRIVATE_KEY"));
    }

    /// The TLS connect path assembles a rustls config and installs the `ring`
    /// provider without panicking; against a dead port it fails cleanly (a
    /// transport error, not `InvalidEndpoint`/`InvalidToken`). Exercises the
    /// whole `tls()` → `ClientTlsConfig::with_webpki_roots` → `tls_config`
    /// assembly end to end, no server required.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn tls_connect_assembles_and_fails_cleanly() {
        let err = StreamClient::builder("https://127.0.0.1:1")
            .tls()
            .tls_domain("node.example")
            .connect()
            .await
            .expect_err("connect to a dead port must fail");
        assert!(
            !matches!(err, StreamError::InvalidEndpoint(_) | StreamError::InvalidToken),
            "expected a transport/connect error, got {err:?}",
        );
    }

    /// TLS requested over a plaintext `http://` endpoint must fail closed at
    /// `connect()` rather than silently connecting in cleartext — tonic selects
    /// TLS from the URI scheme alone, so without this guard the bearer token and
    /// event stream would leak on the wire. Covers `http://` and a scheme-less
    /// endpoint; the `https://` happy path is exercised above.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn tls_over_non_https_endpoint_is_refused() {
        for ep in ["http://127.0.0.1:1", "127.0.0.1:1"] {
            let err = StreamClient::builder(ep)
                .tls_ca_pem(b"-----BEGIN CERTIFICATE-----".to_vec())
                .bearer_token("SECRET")
                .connect()
                .await
                .expect_err("TLS over non-https must be refused");
            match err {
                StreamError::InvalidEndpoint(msg) => assert!(
                    msg.contains("https"),
                    "expected an https-scheme error for {ep}, got {msg}"
                ),
                other => panic!("expected InvalidEndpoint for {ep}, got {other:?}"),
            }
        }
    }
}
