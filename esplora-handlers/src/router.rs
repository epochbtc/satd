//! Build the axum `Router` for the Esplora server. Wires handler
//! routes + middleware (CORS, timeout, concurrency limit, optional
//! auth).
//!
//! All endpoints from later PRs (block, tx, address, mempool,
//! outspend, fee, root) plug into this router — keep the structure
//! flat so adding routes is a single `route(...)` line.

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::auth::AuthExpectation;
use crate::config::EsploraConfig;
use crate::handlers::chain;
use crate::state::EsploraState;

#[derive(Debug, thiserror::Error)]
pub enum RouterBuildError {
    #[error("esplora auth init failed: {0}")]
    Auth(String),
    #[error("esplora cors: invalid origin {origin:?}: {detail}")]
    InvalidCors { origin: String, detail: String },
    #[error("esplora prefix must start with '/' (got {0:?})")]
    InvalidPrefix(String),
}

/// Construct the `Router` with all routes mounted under the configured
/// prefix. Returns `Err` if auth or CORS / prefix configuration is
/// invalid — callers (the daemon) MUST treat this as a hard startup
/// error rather than running an unauthenticated listener (review H1).
pub fn build_router(state: EsploraState) -> Result<Router, RouterBuildError> {
    let cfg = state.config.clone();

    // Build the route table first; auth, CORS, and prefix nesting are
    // applied around it.
    let routes = Router::new()
        .route("/blocks/tip/hash", get(chain::tip_hash))
        .route("/blocks/tip/height", get(chain::tip_height))
        .route("/blocks", get(chain::blocks_recent))
        .route("/blocks/{start_height}", get(chain::blocks_at_or_below))
        .route("/block-height/{height}", get(chain::block_height))
        .with_state(state);

    let routes = if cfg.auth.is_enabled() {
        let expected = AuthExpectation::build(&cfg.auth)
            .map_err(RouterBuildError::Auth)?;
        let expected = Arc::new(expected);
        routes.layer(axum::middleware::from_fn_with_state(
            expected,
            crate::auth::require_auth,
        ))
    } else {
        routes
    };

    // Apply the trace + timeout middleware unconditionally; CORS only
    // when origins are configured.
    let routes = routes
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            cfg.request_timeout,
        ));

    let routes = if !cfg.cors_origins.is_empty() {
        routes.layer(build_cors_layer(&cfg)?)
    } else {
        routes
    };

    let routes = if cfg.max_concurrency > 0 {
        routes.layer(ConcurrencyLimitLayer::new(cfg.max_concurrency))
    } else {
        routes
    };

    // Mount under the configured prefix. `/` is a no-op; non-root
    // prefixes use `Router::nest` so `/api/blocks/tip/hash` resolves
    // (review H2).
    let prefix = cfg.prefix.trim_end_matches('/');
    if prefix.is_empty() {
        Ok(routes)
    } else if prefix.starts_with('/') {
        Ok(Router::new().nest(prefix, routes))
    } else {
        Err(RouterBuildError::InvalidPrefix(cfg.prefix.clone()))
    }
}

fn build_cors_layer(cfg: &EsploraConfig) -> Result<CorsLayer, RouterBuildError> {
    let layer = CorsLayer::new()
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ]);
    if cfg.cors_origins.iter().any(|o| o == "*") {
        return Ok(layer.allow_origin(AllowOrigin::any()));
    }
    // Validate every origin so a typo doesn't silently produce an
    // empty allowlist (review L2).
    let mut origins: Vec<axum::http::HeaderValue> = Vec::with_capacity(cfg.cors_origins.len());
    for raw in &cfg.cors_origins {
        let parsed = raw
            .parse::<axum::http::HeaderValue>()
            .map_err(|e| RouterBuildError::InvalidCors {
                origin: raw.clone(),
                detail: e.to_string(),
            })?;
        origins.push(parsed);
    }
    Ok(layer.allow_origin(origins))
}
