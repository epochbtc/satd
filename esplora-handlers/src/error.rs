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
    #[error("internal: {0}")]
    Internal(String),
}

impl From<node_index::IndexError> for EsploraError {
    fn from(value: node_index::IndexError) -> Self {
        match value {
            node_index::IndexError::Disabled => EsploraError::IndexDisabled,
            node_index::IndexError::Storage(s) => EsploraError::Internal(s),
        }
    }
}

impl IntoResponse for EsploraError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            EsploraError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            EsploraError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            EsploraError::IndexDisabled => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            EsploraError::ServiceUnavailable => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            EsploraError::Internal(_) => {
                tracing::warn!(error = %self, "esplora internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        // Plain-text body matches upstream Esplora's error shape so
        // BDK / mempool.space-style clients parse it identically.
        (status, msg).into_response()
    }
}

pub type EsploraResult<T> = Result<T, EsploraError>;
