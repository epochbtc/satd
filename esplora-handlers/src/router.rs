//! Build the axum `Router` for the Esplora server. Wires handler
//! routes + middleware (CORS, timeout, concurrency limit, optional
//! auth).
//!
//! All endpoints from later PRs (block, tx, address, mempool,
//! outspend, fee, root) plug into this router — keep the structure
//! flat so adding routes is a single `route(...)` line.

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::auth::AuthExpectation;
use crate::config::EsploraConfig;
use crate::handlers::{address, block, chain, mempool, outspend, tx};
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
        .route("/block/{hash}", get(block::block_detail))
        .route("/block/{hash}/header", get(block::block_header))
        .route("/block/{hash}/raw", get(block::block_raw))
        .route("/block/{hash}/status", get(block::block_status))
        .route("/block/{hash}/txs", get(block::block_txs))
        .route("/block/{hash}/txs/{start_index}", get(block::block_txs_page))
        .route("/block/{hash}/txid/{index}", get(block::block_txid_at_index))
        .route("/block/{hash}/txids", get(block::block_txids))
        .route("/tx/{txid}", get(tx::tx_detail))
        .route("/tx/{txid}/status", get(tx::tx_status))
        .route("/tx/{txid}/hex", get(tx::tx_hex))
        .route("/tx/{txid}/raw", get(tx::tx_raw))
        // Outspend + merkle-proof endpoints (Esplora plan PR 6).
        .route("/tx/{txid}/outspend/{vout}", get(outspend::tx_outspend))
        .route("/tx/{txid}/outspends", get(outspend::tx_outspends))
        .route("/tx/{txid}/merkle-proof", get(outspend::tx_merkle_proof))
        .route(
            "/tx/{txid}/merkleblock-proof",
            get(outspend::tx_merkleblock_proof),
        )
        // Body cap for broadcast. `MAX_STANDARD_TX_WEIGHT` is 400_000
        // weight units; a witness-heavy standard tx can serialize to
        // around 400 KB, so hex-encoded the body can approach 800 KB.
        // 1 MB covers that with margin and stays well under the 4 MB
        // consensus block limit. Per-route layer so the cap doesn't
        // apply to GET endpoints that don't accept bodies. (Review M4
        // round 1 + round 2.)
        .route(
            "/tx",
            post(tx::tx_broadcast).layer(DefaultBodyLimit::max(1024 * 1024)),
        )
        // Address-string family (Esplora plan PR 5).
        .route("/address/{addr}", get(address::address_info))
        .route("/address/{addr}/txs", get(address::address_txs_combined))
        .route("/address/{addr}/txs/chain", get(address::address_txs_chain))
        .route(
            "/address/{addr}/txs/chain/{last_seen_txid}",
            get(address::address_txs_chain_paged),
        )
        .route(
            "/address/{addr}/txs/mempool",
            get(address::address_txs_mempool),
        )
        .route("/address/{addr}/utxo", get(address::address_utxo))
        // Scripthash family — parallel set; same handlers branched on
        // a different parser.
        .route("/scripthash/{hash}", get(address::scripthash_info))
        .route(
            "/scripthash/{hash}/txs",
            get(address::scripthash_txs_combined),
        )
        .route(
            "/scripthash/{hash}/txs/chain",
            get(address::scripthash_txs_chain),
        )
        .route(
            "/scripthash/{hash}/txs/chain/{last_seen_txid}",
            get(address::scripthash_txs_chain_paged),
        )
        .route(
            "/scripthash/{hash}/txs/mempool",
            get(address::scripthash_txs_mempool),
        )
        .route("/scripthash/{hash}/utxo", get(address::scripthash_utxo))
        // Mempool / fee / root (Esplora plan PR 7).
        .route("/", get(mempool::root))
        .route("/mempool", get(mempool::mempool_summary))
        .route("/mempool/txids", get(mempool::mempool_txids))
        .route("/mempool/recent", get(mempool::mempool_recent))
        .route("/fee-estimates", get(mempool::fee_estimates))
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
