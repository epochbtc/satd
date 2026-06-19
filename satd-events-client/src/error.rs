//! Error type for the streaming client.

use std::time::Duration;

/// An error from the streaming client.
///
/// `Lagged` is deliberately **not** here — a slow-consumer lag notice is a
/// normal [`Event`](crate::Event), recoverable and carrying a resume cursor.
/// Variants here are conditions that stop forward progress on a call.
///
/// The variants that wrap a [`tonic::Status`] keep it boxed so the server's
/// message and details survive classification; use [`is_retryable`](Self::is_retryable)
/// to decide whether to back off and retry versus give up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StreamError {
    /// An unclassified transport or RPC status from the server.
    #[error("rpc error: {0}")]
    Transport(#[source] Box<tonic::Status>),

    /// Failed to establish the underlying transport channel.
    #[error("connect error: {0}")]
    Connect(#[source] tonic::transport::Error),

    /// The endpoint string could not be parsed.
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),

    /// The supplied bearer token is not a valid HTTP header value.
    #[error("invalid bearer token: not a valid header value")]
    InvalidToken,

    /// The bearer token was missing, malformed, or rejected (gRPC
    /// `UNAUTHENTICATED`). Potentially fixable by presenting a valid token.
    #[error("unauthenticated: {0}")]
    Unauthenticated(#[source] Box<tonic::Status>),

    /// The principal is authenticated but lacks the required capability
    /// (`stream:subscribe` to open, `stream:watch` to add watches) — gRPC
    /// `PERMISSION_DENIED`. A permanent configuration error, not retryable.
    #[error("permission denied: {0}")]
    PermissionDenied(#[source] Box<tonic::Status>),

    /// The server's subscription cap, a per-principal rate limit, or the
    /// per-token watch quota was hit (gRPC `RESOURCE_EXHAUSTED`). The first two
    /// are transient (back off and retry); a genuinely full watch quota is not.
    /// Inspect the boxed status message to distinguish.
    #[error("resource exhausted: {0}")]
    QuotaExhausted(#[source] Box<tonic::Status>),

    /// Reserved for explicit rate-limit signaling in the resilience layer. The
    /// current server does not return a status for an over-rate `SetCursor`
    /// re-anchor — it silently drops it — so this is not produced yet.
    #[error("rate limited")]
    RateLimited {
        /// Suggested backoff before retrying, if known.
        retry_after: Option<Duration>,
    },

    /// Reserved. `from_cursor` replay against a server with no block source is a
    /// silent server-side fallback to forward-only (no status), so this is not
    /// produced from the wire yet; the resilience layer detects the degraded
    /// case from the event stream.
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

    /// A client-side argument was rejected before reaching the wire (e.g. a
    /// prefix whose byte length does not match its `bits`).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// A received message could not be decoded into a typed value.
    #[error("decode error: {0}")]
    Decode(String),

    /// The control channel was closed before the message could be sent (the
    /// watch stream has been torn down).
    #[error("control channel closed")]
    ControlClosed,
}

impl StreamError {
    /// Classify a tonic [`Status`](tonic::Status) into a typed variant, keeping
    /// the original status (boxed) so its message and details are preserved.
    pub(crate) fn from_status(status: tonic::Status) -> Self {
        use tonic::Code;
        match status.code() {
            Code::Unauthenticated => StreamError::Unauthenticated(Box::new(status)),
            Code::PermissionDenied => StreamError::PermissionDenied(Box::new(status)),
            Code::ResourceExhausted => StreamError::QuotaExhausted(Box::new(status)),
            _ => StreamError::Transport(Box::new(status)),
        }
    }

    /// Whether retrying the operation (after a backoff) could plausibly succeed.
    ///
    /// `true` for transport failures the gRPC layer marks transient
    /// (`UNAVAILABLE`, `DEADLINE_EXCEEDED`, `ABORTED`, `CANCELLED`,
    /// `RESOURCE_EXHAUSTED`), for connection failures, and for the reserved
    /// `RateLimited`. `false` for permanent conditions — bad endpoint/token,
    /// `PERMISSION_DENIED`, client-side argument errors. `Unauthenticated` is
    /// reported non-retryable: a blind retry with the same token will not help;
    /// the caller should re-auth and reconnect deliberately.
    pub fn is_retryable(&self) -> bool {
        use tonic::Code;
        match self {
            StreamError::Connect(_) => true,
            StreamError::RateLimited { .. } => true,
            StreamError::QuotaExhausted(_) => true,
            StreamError::Transport(s) => matches!(
                s.code(),
                Code::Unavailable
                    | Code::DeadlineExceeded
                    | Code::Aborted
                    | Code::Cancelled
                    | Code::ResourceExhausted
            ),
            _ => false,
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
