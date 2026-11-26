//! Running a handler's index and store reads on the blocking pool.
//!
//! The address handlers read RocksDB and the flat files synchronously. Run
//! inline in the `async fn`, that work held an API-runtime worker for as
//! long as it took (shared with Electrum, events gRPC and `/metrics`), and
//! the request `TimeoutLayer` could not answer until it finished, since a
//! future that never yields cannot be dropped early. On the blocking pool
//! the worker stays free and the timeout answers on time.
//!
//! The work itself cannot be stopped once it starts, so it holds a permit
//! from [`EsploraState::work_permits`] until it ends, including after its
//! request has timed out. The permits are sized from `--esploramaxconns`:
//! requests whose work outlives their timeout keep counting against that
//! cap, so retrying after every timeout cannot pile up running work.

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::error::{EsploraError, EsploraResult};
use crate::state::EsploraState;

/// The work-permit pool for `max_concurrency` (`--esploramaxconns`): `None`
/// when the cap is disabled (`0`), as the request cap is.
pub fn work_permits_for(max_concurrency: usize) -> Option<Arc<Semaphore>> {
    (max_concurrency > 0)
        .then(|| Arc::new(Semaphore::new(node::http_serve::clamp_cap(max_concurrency))))
}

/// Run `work` on the blocking pool under a work permit and return its
/// result. Waits for a permit when all are taken; the request timeout
/// bounds that wait.
pub(crate) async fn off_worker<T, F>(state: &EsploraState, work: F) -> EsploraResult<T>
where
    T: Send + 'static,
    F: FnOnce(&EsploraState) -> EsploraResult<T> + Send + 'static,
{
    let permit = match &state.work_permits {
        Some(permits) => Some(
            permits
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| EsploraError::ServiceUnavailable)?,
        ),
        None => None,
    };
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work(&state)
    })
    .await
    .map_err(|e| EsploraError::Internal(format!("handler task failed: {e}")))?
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    use crate::test_support::regtest_state;

    /// Every cap option accepts any `usize`, and tokio's semaphore (under
    /// both the work permits and tower's `ConcurrencyLimitLayer`) panics
    /// above `usize::MAX >> 3`. With the largest value the router still
    /// builds and serves: the cap is clamped, not handed through.
    #[tokio::test]
    async fn an_oversized_request_cap_is_clamped_not_panicking() {
        let permits = super::work_permits_for(usize::MAX).expect("a cap");
        assert_eq!(permits.available_permits(), node::http_serve::CAP_CEILING);

        let (mut state, _dir) = regtest_state();
        state.config = Arc::new(crate::EsploraConfig {
            max_concurrency: usize::MAX,
            ..Default::default()
        });
        state.work_permits = Some(permits);
        let router = crate::build_router(state).unwrap();
        let resp = router
            .oneshot(
                Request::get("/blocks/tip/height")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
