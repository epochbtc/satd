//! Chain-tip headers: every chain-backed response names the tip it was read
//! at, and answers for that tip alone.
//!
//! `X-Bitcoin-Chain-Tip` is the tip's block hash and
//! `X-Bitcoin-Chain-Tip-Height` its height. A client making several requests
//! compares the hash across them: if it changed, the answers come from
//! different chains (a reorg, or just a new block) and the batch should be
//! fetched again. Comparing hashes rather than heights catches a same-height
//! replacement too. The proposal is mempool/mempool#6584; rbitcoin serves the
//! same two headers.
//!
//! A request is pinned to the tip it starts at. The middleware takes a
//! [`ChainView`] before the handler runs and hands the handler a [`Pin`] of
//! that tip; the handler reads nothing above the pin's height, and treats a
//! transaction confirmed above it as the unconfirmed one it was when the
//! request started. Blocks that connect on top of the pinned tip while the
//! request runs leave everything at and below it as it was, so the answer
//! stands and names the pinned tip. Only a disconnect (a reorg, or
//! `invalidateblock`) can change what the pinned heights hold: then the answer
//! is discarded and the request run again at the new tip, and a chain that
//! retreats under [`VIEW_ATTEMPTS`] runs in a row is 503 `chain view moved`.
//!
//! The mempool is read as it is when the handler reads it. Only routes that
//! read the chain are pinned and carry the headers: the mempool and fee
//! routes, `POST /tx`, the `/txs/mempool` lists and the SSE streams are
//! mounted without this layer.
//!
//! `?asof=<blockhash>` pins a request to that block instead of the tip, while
//! it is on the best chain, and leaves the mempool out of the answer: the
//! wallet as of that block. The block's hash and height go in the headers. A
//! block that is not on the best chain, or leaves it while the request runs,
//! is 404, never an answer from another block at its height. Only the routes
//! in [`AsOf::Accepted`] take it; on any other route, pinned or not, an
//! `asof` parameter is 404.

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bitcoin::BlockHash;
use node::chain::state::{ChainState, ChainView, ViewChange};

use crate::state::EsploraState;

/// The tip's block hash, display hex.
pub const CHAIN_TIP_HEADER: HeaderName = HeaderName::from_static("x-bitcoin-chain-tip");
/// The tip's height, decimal.
pub const CHAIN_TIP_HEIGHT_HEADER: HeaderName =
    HeaderName::from_static("x-bitcoin-chain-tip-height");

/// How many runs a request gets before a chain that retreated under every
/// one is answered with 503. The same budget as `ChainState::coherent_read`.
pub const VIEW_ATTEMPTS: usize = 8;

/// How long to wait for a chain mutation in flight to finish, before a run
/// and after one, as `ChainState::coherent_read` waits.
const VIEW_WAIT: Duration = Duration::from_millis(500);

/// The body of the 503 for a chain that retreated under every run.
pub const CHAIN_VIEW_MOVED: &str = "chain view moved";

/// The block a chain route answers for. Every chain read the handler makes
/// is bounded to it: nothing above `height` is confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pin {
    pub hash: BlockHash,
    pub height: u32,
    /// The answer includes the mempool: a live request pinned to the tip.
    /// `false` for `?asof=`, which answers with confirmed data only, and
    /// treats a transaction confirmed above the pin as unknown rather than
    /// unconfirmed.
    pub mempool: bool,
}

impl Pin {
    /// A block at `height` is confirmed as of this pin.
    pub fn covers(&self, height: u32) -> bool {
        height <= self.height
    }

    /// The pinned chain's block at `height`, from the height index. The
    /// index row for a height at or below the pin is the pinned chain's
    /// until a disconnect, which reruns the request.
    pub fn hash_at_height(&self, chain: &ChainState, height: u32) -> Option<BlockHash> {
        if !self.covers(height) {
            return None;
        }
        if height == self.height {
            return Some(self.hash);
        }
        chain.get_block_hash_by_height(height)
    }
}

/// Whether a pinned route takes `?asof=`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsOf {
    Accepted,
    Refused,
}

/// The state [`stamp_chain_tip`] runs with.
#[derive(Clone)]
pub struct PinnedRoutes {
    pub state: EsploraState,
    pub asof: AsOf,
}

/// The `asof` query parameter: `Ok(None)` when absent, `Err` when present
/// but not a block hash (empty, or not 64 hex characters).
fn asof_param(uri: &axum::http::Uri) -> Result<Option<BlockHash>, ()> {
    let Some(query) = uri.query() else {
        return Ok(None);
    };
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "asof" {
            return value.parse::<BlockHash>().map(Some).map_err(|_| ());
        }
    }
    Ok(None)
}

fn not_found() -> Response {
    crate::error::EsploraError::NotFound.into_response()
}

/// On routes that are not pinned: an `asof` parameter is 404, as on a
/// pinned route that does not take it.
pub async fn refuse_asof(req: Request, next: Next) -> Response {
    if !matches!(asof_param(req.uri()), Ok(None)) {
        return not_found();
    }
    next.run(req).await
}

/// The pin for `?asof=<hash>`: the block, if it is on the best chain at or
/// below `view`'s tip.
fn asof_pin(chain: &ChainState, view: &ChainView, hash: BlockHash) -> Option<Pin> {
    let entry = chain.get_block_index(&hash)?;
    if entry.height > view.tip_height || !chain.active_chain_contains(&hash, entry.height) {
        return None;
    }
    Some(Pin {
        hash,
        height: entry.height,
        mempool: false,
    })
}

/// Run the request pinned to the current tip, or to its `?asof=` block, and
/// stamp the block it was pinned to.
pub async fn stamp_chain_tip(
    State(routes): State<PinnedRoutes>,
    req: Request,
    next: Next,
) -> Response {
    let state = routes.state;
    let asof = match asof_param(req.uri()) {
        Ok(None) => None,
        Ok(Some(_)) if routes.asof == AsOf::Refused => return not_found(),
        Ok(Some(hash)) => Some(hash),
        Err(()) => return not_found(),
    };
    let (parts, body) = req.into_parts();
    let mut body = Some(body);
    for _ in 0..VIEW_ATTEMPTS {
        let Some(view) = settled_view(&state.chain).await else {
            return chain_view_moved();
        };
        let pin = match asof {
            // Not on the best chain: 404, now or after a retreat, with no
            // retry onto another block at its height.
            Some(hash) => match asof_pin(&state.chain, &view, hash) {
                Some(pin) => pin,
                None => return not_found(),
            },
            None => Pin {
                hash: view.tip_hash,
                height: view.tip_height,
                mempool: true,
            },
        };
        // Every pinned route is a GET, whose handler reads no body. A rerun
        // gets an empty one; the first run keeps whatever was sent.
        let mut run = Request::new(body.take().unwrap_or_else(Body::empty));
        *run.method_mut() = parts.method.clone();
        *run.uri_mut() = parts.uri.clone();
        *run.version_mut() = parts.version;
        *run.headers_mut() = parts.headers.clone();
        *run.extensions_mut() = parts.extensions.clone();
        run.extensions_mut().insert(pin);
        let mut resp = next.clone().run(run).await;
        match settled_change(&state.chain, &view).await {
            Some(ViewChange::Unchanged | ViewChange::Extended) => {
                stamp(&mut resp, &pin);
                return resp;
            }
            Some(ViewChange::Retreated) => continue,
            Some(ViewChange::InFlight) | None => return chain_view_moved(),
        }
    }
    chain_view_moved()
}

fn chain_view_moved() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, CHAIN_VIEW_MOVED).into_response()
}

/// A view of a settled chainstate, waiting out a mutation already in flight.
/// `None` when one stays in flight past [`VIEW_WAIT`].
async fn settled_view(chain: &ChainState) -> Option<ChainView> {
    let deadline = Instant::now() + VIEW_WAIT;
    loop {
        if let Some(view) = chain.begin_view() {
            return Some(view);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// How the chain changed since `view`, waiting out a mutation in flight: a
/// mutation that has committed but not yet finished may be a disconnect.
/// `None` when one stays in flight past [`VIEW_WAIT`].
async fn settled_change(chain: &ChainState, view: &ChainView) -> Option<ViewChange> {
    let deadline = Instant::now() + VIEW_WAIT;
    loop {
        let change = chain.view_change(view);
        if change != ViewChange::InFlight {
            return Some(change);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

fn stamp(resp: &mut Response, pin: &Pin) {
    let headers = resp.headers_mut();
    headers.insert(
        CHAIN_TIP_HEADER,
        HeaderValue::from_str(&pin.hash.to_string()).expect("hex is a header value"),
    );
    headers.insert(CHAIN_TIP_HEIGHT_HEADER, HeaderValue::from(pin.height));
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::routing::get;
    use tower::ServiceExt as _;

    use bitcoin::hashes::Hash as _;

    use super::*;
    use crate::test_support::{extend_tip, regtest_state};

    /// A router whose one route runs `handler` behind [`stamp_chain_tip`].
    fn stamped(state: EsploraState, handler: impl Fn(&ChainState) + Clone + Send + Sync + 'static) -> Router {
        let chain = state.chain.clone();
        Router::new()
            .route(
                "/probe",
                get(move || {
                    let chain = chain.clone();
                    let handler = handler.clone();
                    async move {
                        handler(&chain);
                        "ok"
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                PinnedRoutes {
                    state,
                    asof: AsOf::Refused,
                },
                stamp_chain_tip,
            ))
    }

    async fn call(router: Router) -> Response {
        router
            .oneshot(Request::get("/probe").body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    fn header<'a>(resp: &'a Response, name: &HeaderName) -> Option<&'a str> {
        resp.headers().get(name).map(|v| v.to_str().unwrap())
    }

    #[tokio::test]
    async fn a_response_names_the_tip_it_was_read_at() {
        let (state, _dir) = regtest_state();
        let tip = extend_tip(&state.chain, 0);
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = runs.clone();
        let resp = call(stamped(state, move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
        }))
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, &CHAIN_TIP_HEADER), Some(tip.to_string().as_str()));
        assert_eq!(header(&resp, &CHAIN_TIP_HEIGHT_HEADER), Some("1"));
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    /// Blocks that connect on top of the pinned tip while the handler runs
    /// leave everything at and below it as it was: the answer stands, once,
    /// and names the tip the request started at.
    #[tokio::test]
    async fn blocks_connected_mid_request_leave_the_answer_pinned() {
        let (state, _dir) = regtest_state();
        let start = extend_tip(&state.chain, 0);
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = runs.clone();
        let resp = call(stamped(state.clone(), move |chain| {
            counted.fetch_add(1, Ordering::SeqCst);
            extend_tip(chain, 1);
            extend_tip(chain, 2);
        }))
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(runs.load(Ordering::SeqCst), 1, "an extension does not rerun");
        assert_eq!(state.chain.tip_height(), 3);
        assert_eq!(header(&resp, &CHAIN_TIP_HEADER), Some(start.to_string().as_str()));
        assert_eq!(header(&resp, &CHAIN_TIP_HEIGHT_HEADER), Some("1"));
    }

    /// A disconnect while the handler runs can change what the pinned heights
    /// hold: the answer is discarded and the request run again at the new
    /// tip.
    #[tokio::test]
    async fn a_disconnect_mid_request_reruns_it_at_the_new_tip() {
        let (state, _dir) = regtest_state();
        let one = extend_tip(&state.chain, 0);
        let two = extend_tip(&state.chain, 0);
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = runs.clone();
        let resp = call(stamped(state.clone(), move |chain| {
            if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                chain.invalidate_block(two).unwrap();
            }
        }))
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(runs.load(Ordering::SeqCst), 2, "the first run was discarded");
        assert_eq!(header(&resp, &CHAIN_TIP_HEADER), Some(one.to_string().as_str()));
        assert_eq!(header(&resp, &CHAIN_TIP_HEIGHT_HEADER), Some("1"));
    }

    /// The handler sees the pin the response is stamped with.
    #[tokio::test]
    async fn the_handler_reads_the_pin_it_is_stamped_with() {
        let (state, _dir) = regtest_state();
        let tip = extend_tip(&state.chain, 0);
        let chain = state.chain.clone();
        let router = Router::new()
            .route(
                "/probe",
                get(move |axum::Extension(pin): axum::Extension<Pin>| {
                    let chain = chain.clone();
                    async move {
                        extend_tip(&chain, 1);
                        format!("{} {}", pin.hash, pin.height)
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                PinnedRoutes {
                    state,
                    asof: AsOf::Refused,
                },
                stamp_chain_tip,
            ));
        let resp = call(router).await;
        assert_eq!(header(&resp, &CHAIN_TIP_HEADER), Some(tip.to_string().as_str()));
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], format!("{tip} 1").as_bytes());
    }

    /// A chain that retreats under every run is 503, with no stamp, once the
    /// attempts are spent.
    #[tokio::test]
    async fn a_chain_that_retreats_under_every_run_is_503() {
        let (state, _dir) = regtest_state();
        for salt in 0..VIEW_ATTEMPTS as u32 {
            extend_tip(&state.chain, salt);
        }
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = runs.clone();
        let resp = call(stamped(state, move |chain| {
            counted.fetch_add(1, Ordering::SeqCst);
            chain.invalidate_block(chain.tip_hash()).unwrap();
        }))
        .await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(runs.load(Ordering::SeqCst), VIEW_ATTEMPTS);
        assert!(header(&resp, &CHAIN_TIP_HEADER).is_none());
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], CHAIN_VIEW_MOVED.as_bytes());
    }

    async fn get_path(router: &Router, path: &str) -> Response {
        router
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// `?asof=` pins a request to that block, with no mempool, on the routes
    /// that take it; anywhere else, or for a block not on the best chain, or
    /// one that is not a hash, it is 404.
    #[tokio::test]
    async fn asof_pins_to_a_best_chain_block_on_the_routes_that_take_it() {
        let (state, _dir) = regtest_state();
        let one = extend_tip(&state.chain, 0);
        let two = extend_tip(&state.chain, 0);
        let pins = Router::new()
            .route(
                "/probe",
                get(|axum::Extension(pin): axum::Extension<Pin>| async move {
                    format!("{} {} {}", pin.hash, pin.height, pin.mempool)
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                PinnedRoutes {
                    state: state.clone(),
                    asof: AsOf::Accepted,
                },
                stamp_chain_tip,
            ));

        let resp = get_path(&pins, &format!("/probe?asof={one}")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, &CHAIN_TIP_HEADER), Some(one.to_string().as_str()));
        assert_eq!(header(&resp, &CHAIN_TIP_HEIGHT_HEADER), Some("1"));
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], format!("{one} 1 false").as_bytes());

        let resp = get_path(&pins, "/probe?other=1").await;
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], format!("{two} 2 true").as_bytes(), "no asof: the live tip");

        // A side block at height 1, not on the best chain.
        let side = crate::test_support::regtest_block(state.chain.get_block_hash_by_height(0).unwrap(), 1, 7);
        let _ = state.chain.accept_block(&side);
        let zero = BlockHash::all_zeros();
        for query in [
            format!("asof={zero}"),
            format!("asof={}", side.block_hash()),
            "asof=".to_string(),
            "asof=nothex".to_string(),
        ] {
            let resp = get_path(&pins, &format!("/probe?{query}")).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{query}");
            assert!(header(&resp, &CHAIN_TIP_HEADER).is_none(), "{query}");
        }

        // Through the real router: a pinned route that does not take asof,
        // and an unpinned one, are 404.
        let router = crate::build_router(state).unwrap();
        for path in [format!("/tx/{zero}?asof={one}"), format!("/mempool?asof={one}")] {
            assert_eq!(get_path(&router, &path).await.status(), StatusCode::NOT_FOUND, "{path}");
        }
        assert_eq!(get_path(&router, &format!("/blocks/tip/hash?asof={one}")).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(get_path(&router, "/mempool").await.status(), StatusCode::OK);
    }

    /// An asof block that a disconnect takes off the best chain while the
    /// request runs is 404, not an answer from whatever replaced it.
    #[tokio::test]
    async fn an_asof_block_disconnected_mid_request_is_404() {
        let (state, _dir) = regtest_state();
        extend_tip(&state.chain, 0);
        let two = extend_tip(&state.chain, 0);
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = runs.clone();
        let chain = state.chain.clone();
        let router = Router::new()
            .route(
                "/probe",
                get(move || {
                    let chain = chain.clone();
                    let counted = counted.clone();
                    async move {
                        if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                            chain.invalidate_block(two).unwrap();
                        }
                        "ok"
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                PinnedRoutes {
                    state,
                    asof: AsOf::Accepted,
                },
                stamp_chain_tip,
            ));
        let resp = get_path(&router, &format!("/probe?asof={two}")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(header(&resp, &CHAIN_TIP_HEADER).is_none());
    }

    /// Through the real router: chain routes carry the stamp and agree with
    /// their own answer; mempool and fee routes do not carry it.
    #[tokio::test]
    async fn the_router_stamps_chain_routes_only() {
        let (state, _dir) = regtest_state();
        let tip = extend_tip(&state.chain, 0);
        let router = crate::build_router(state).unwrap();

        let resp = router
            .clone()
            .oneshot(Request::get("/blocks/tip/hash").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, &CHAIN_TIP_HEADER), Some(tip.to_string().as_str()));
        assert_eq!(header(&resp, &CHAIN_TIP_HEIGHT_HEADER), Some("1"));
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], tip.to_string().as_bytes());

        // A 404 from a chain route is an answer about that chain too.
        let missing = "00".repeat(32);
        let resp = router
            .clone()
            .oneshot(Request::get(format!("/tx/{missing}/status")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(header(&resp, &CHAIN_TIP_HEADER), Some(tip.to_string().as_str()));

        for path in ["/mempool", "/fee-estimates"] {
            let resp = router
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
            assert!(header(&resp, &CHAIN_TIP_HEADER).is_none(), "{path} is not a chain read");
        }
    }
}
