//! Error type for handler responses. Maps to upstream Esplora's
//! plain-text error shape (404 / 400 / 500 with a short message).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum EsploraError {
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    BadRequest(String),
    #[error("address index disabled — restart with --addressindex=1 to enable")]
    IndexDisabled,
    #[error("service unavailable")]
    ServiceUnavailable,
    /// The authenticated principal lacks the `stream:watch` capability needed to
    /// open a live address/scripthash subscription. 403.
    #[error("{0}")]
    Forbidden(String),
    /// The principal's per-tenant watch-set quota is exhausted. 429 — distinct
    /// from the node-wide `addrindexsubscriptions` cap (which is `ServiceUnavailable`/503).
    #[error("watch-set quota exceeded")]
    WatchQuotaExceeded,
    #[error("internal: {0}")]
    Internal(String),
}

impl From<node_index::IndexError> for EsploraError {
    fn from(value: node_index::IndexError) -> Self {
        match value {
            node_index::IndexError::Disabled => EsploraError::IndexDisabled,
            // The address/spend index lookup couldn't return a
            // definitive answer because on-disk data is incomplete
            // (e.g. an upgrade gap). 503 mirrors the disabled path
            // so clients treat both as transient. (Round-3 H2 added
            // the variant in node-index; round-4 B1 moved the
            // mapping arm down into PR #100 so the intermediate
            // stack heads compile, leaving this PR's earlier copy
            // redundant.)
            node_index::IndexError::Incomplete => EsploraError::ServiceUnavailable,
            node_index::IndexError::Storage(s) => EsploraError::Internal(s),
        }
    }
}

impl IntoResponse for EsploraError {
    fn into_response(self) -> Response {
        let status = match &self {
            EsploraError::NotFound => StatusCode::NOT_FOUND,
            EsploraError::BadRequest(_) => StatusCode::BAD_REQUEST,
            EsploraError::IndexDisabled => StatusCode::SERVICE_UNAVAILABLE,
            EsploraError::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            EsploraError::Forbidden(_) => StatusCode::FORBIDDEN,
            EsploraError::WatchQuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
            EsploraError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let msg = self.to_string();
        // Log every error response so client-facing failures are
        // visible server-side (previously only Internal was logged,
        // making config/capacity rejections undiagnosable). 5xx and
        // capacity/config conditions (503 index-disabled, 429 quota)
        // are operator-actionable → warn; routine 4xx (404/400/403) →
        // debug to avoid log spam at the default level. The TraceLayer
        // separately records method/path/status; this adds the reason.
        if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
            tracing::warn!(target: "esplora::error", status = status.as_u16(), error = %msg, "esplora error response");
        } else {
            tracing::debug!(target: "esplora::error", status = status.as_u16(), error = %msg, "esplora error response");
        }
        // Plain-text body matches upstream Esplora's error shape so
        // BDK / mempool.space-style clients parse it identically.
        (status, msg).into_response()
    }
}

pub type EsploraResult<T> = Result<T, EsploraError>;
