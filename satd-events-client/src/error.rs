//! Error type for the streaming client.

use std::time::Duration;

/// An error from the streaming client.
///
/// `Lagged` is deliberately **not** here — a slow-consumer lag notice is a
/// normal [`Event`](crate::Event), recoverable and carrying a resume cursor.
/// Variants here are conditions that stop forward progress on a call.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StreamError {
    /// An unclassified transport or RPC status from the server.
    #[error("rpc error: {0}")]
    Transport(#[source] tonic::Status),

    /// Failed to establish the underlying transport channel.
    #[error("connect error: {0}")]
    Connect(#[source] tonic::transport::Error),

    /// The endpoint string could not be parsed.
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),

    /// The supplied bearer token is not a valid HTTP header value.
    #[error("invalid bearer token: not a valid header value")]
    InvalidToken,

    /// Authentication failed or the principal lacks the required capability
    /// (`stream:subscribe` to open, `stream:watch` to add watches). Maps from
    /// gRPC `UNAUTHENTICATED` / `PERMISSION_DENIED`.
    #[error("authentication failed or capability denied")]
    Auth,

    /// The per-token watch quota or the server's subscription cap is exhausted.
    /// Maps from gRPC `RESOURCE_EXHAUSTED`.
    #[error("watch quota or subscription limit exhausted")]
    QuotaExhausted,

    /// A control operation was rate-limited (e.g. back-to-back `SetCursor`
    /// re-anchors). `retry_after` is a hint when the server provides one.
    #[error("rate limited")]
    RateLimited {
        /// Suggested backoff before retrying, if known.
        retry_after: Option<Duration>,
    },

    /// `from_cursor` replay was requested but the server has no block source
    /// configured, so the subscription is forward-only.
    #[error("cursor replay unavailable: server has no block source")]
    ReplayUnavailable,

    /// A prefix watch was rejected because `bits` is outside the server's
    /// configured `[streamprefixminbits, streamprefixmaxbits]` range.
    #[error("prefix bits {got} out of server range [{min}, {max}]")]
    PrefixBitsOutOfRange {
        /// The `bits` value that was rejected.
        got: u32,
        /// Server minimum.
        min: u32,
        /// Server maximum.
        max: u32,
    },

    /// A received message could not be decoded into a typed value.
    #[error("decode error: {0}")]
    Decode(String),

    /// The control channel was closed before the message could be sent (the
    /// watch stream has been torn down).
    #[error("control channel closed")]
    ControlClosed,
}

impl StreamError {
    /// Classify a tonic [`Status`](tonic::Status) into a typed variant.
    pub(crate) fn from_status(status: tonic::Status) -> Self {
        use tonic::Code;
        match status.code() {
            Code::Unauthenticated | Code::PermissionDenied => StreamError::Auth,
            Code::ResourceExhausted => StreamError::QuotaExhausted,
            _ => StreamError::Transport(status),
        }
    }
}

impl From<tonic::Status> for StreamError {
    fn from(s: tonic::Status) -> Self {
        StreamError::from_status(s)
    }
}

impl From<tonic::transport::Error> for StreamError {
    fn from(e: tonic::transport::Error) -> Self {
        StreamError::Connect(e)
    }
}
