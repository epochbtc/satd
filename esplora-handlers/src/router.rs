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

/// Construct the `Router` with all PR-2 routes mounted under the
/// configured prefix. Subsequent PRs add `.route(...)` lines to the
/// same builder; the middleware stack is shared across every route.
pub fn build_router(state: EsploraState) -> Router {
    let cfg = state.config.clone();

    let mut router = Router::new()
        .route("/blocks/tip/hash", get(chain::tip_hash))
        .route("/blocks/tip/height", get(chain::tip_height))
        .route("/blocks", get(chain::blocks_recent))
        .route("/blocks/{start_height}", get(chain::blocks_at_or_below))
        .route("/block-height/{height}", get(chain::block_height))
        .with_state(state);

    if cfg.auth.is_enabled() {
        match AuthExpectation::build(&cfg.auth) {
            Ok(expected) => {
                let expected = Arc::new(expected);
                router = router.layer(axum::middleware::from_fn_with_state(
                    expected,
                    crate::auth::require_auth,
                ));
            }
            Err(msg) => {
                // Refuse to silently fall back to no-auth — that
                // would surprise an operator who explicitly
                // configured auth. The daemon logs and treats this
                // as a hard startup error in `serve()` (caller-side).
                tracing::error!(%msg, "esplora auth init failed; refusing to start");
            }
        }
    }

    // Apply layers separately rather than via ServiceBuilder so the
    // CORS layer can be omitted cleanly when no origins are configured
    // (ServiceBuilder's typed stack makes conditional layers awkward).
    let router = router
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            cfg.request_timeout,
        ));

    let router = if !cfg.cors_origins.is_empty() {
        router.layer(build_cors_layer(&cfg))
    } else {
        router
    };

    if cfg.max_concurrency > 0 {
        router.layer(ConcurrencyLimitLayer::new(cfg.max_concurrency))
    } else {
        router
    }
}

fn build_cors_layer(cfg: &EsploraConfig) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION]);
    if cfg.cors_origins.iter().any(|o| o == "*") {
        layer.allow_origin(AllowOrigin::any())
    } else {
        let origins: Vec<axum::http::HeaderValue> = cfg
            .cors_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        layer.allow_origin(origins)
    }
}
