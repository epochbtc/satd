//! `/block/:hash/txs/:start_index` paging bounds.

use axum::http::StatusCode;
use axum::response::IntoResponse;

use super::*;

fn refusal(tx_count: usize, start_index: usize) -> (StatusCode, String) {
    let err = block_page_bounds(tx_count, start_index)
        .expect_err("expected the start index to be refused");
    let msg = err.to_string();
    (err.into_response().status(), msg)
}

#[test]
fn block_page_bounds_serves_aligned_starts_inside_the_block() {
    assert_eq!(block_page_bounds(1, 0).unwrap(), 0..1);
    assert_eq!(block_page_bounds(60, 0).unwrap(), 0..25);
    assert_eq!(block_page_bounds(60, 25).unwrap(), 25..50);
    assert_eq!(block_page_bounds(60, 50).unwrap(), 50..60);
}

#[test]
fn block_page_bounds_past_the_end_is_404_start_index_out_of_range() {
    let out_of_range = (StatusCode::NOT_FOUND, "start index out of range".to_string());
    assert_eq!(refusal(1, 25), out_of_range);
    assert_eq!(refusal(50, 50), out_of_range);
    assert_eq!(refusal(60, usize::MAX - usize::MAX % 25), out_of_range);
    // Past the end is checked first, so an unaligned start past the end is
    // out of range too.
    assert_eq!(refusal(1, 1), out_of_range);
    assert_eq!(refusal(1, usize::MAX), out_of_range);
}

#[test]
fn block_page_bounds_unaligned_start_is_400() {
    let unaligned = (
        StatusCode::BAD_REQUEST,
        "start index must be a multiple of 25".to_string(),
    );
    assert_eq!(refusal(2, 1), unaligned);
    assert_eq!(refusal(60, 24), unaligned);
    assert_eq!(refusal(60, 26), unaligned);
}
