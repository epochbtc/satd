//! `?after_txid=` on `/address/:addr/txs` and the mempool order it relies on.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use bitcoin::hashes::Hash as _;

use super::*;

fn txid(byte: u8) -> Txid {
    Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
}

// Where a confirmed cursor continues, and that a cursor outside the
// confirmed history is `None` (422 here), is the address index's
// `confirmed_txs_newest_first`, tested in `node`.

#[test]
fn without_after_txid_the_page_starts_at_the_first_mempool_tx() {
    let mempool = [(txid(1), ()), (txid(2), ())];
    assert_eq!(mempool_start(&mempool, None), Some(0));
    assert_eq!(mempool_start::<()>(&[], None), Some(0));
}

#[test]
fn after_txid_in_the_mempool_continues_after_it() {
    let mempool = [(txid(1), ()), (txid(2), ())];
    assert_eq!(mempool_start(&mempool, Some(txid(1))), Some(1));
    // The last mempool transaction: the rest is the confirmed history.
    assert_eq!(mempool_start(&mempool, Some(txid(2))), Some(2));
}

#[test]
fn after_txid_outside_the_mempool_continues_in_the_confirmed_history() {
    assert_eq!(mempool_start(&[(txid(1), ())], Some(txid(10))), None);
    assert_eq!(mempool_start::<()>(&[], Some(txid(10))), None);

    // In neither list: 422 `after_txid not found`.
    let err = after_txid_not_found();
    assert_eq!(err.to_string(), "after_txid not found");
    assert_eq!(err.into_response().status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn after_txid_query_parses_or_is_a_bad_request() {
    let q = |s: Option<&str>| TxsQuery {
        after_txid: s.map(str::to_string),
    };
    assert_eq!(parse_after_txid(&q(None)).unwrap(), None);
    // An empty value is no cursor, the first page.
    assert_eq!(parse_after_txid(&q(Some(""))).unwrap(), None);
    let t = txid(7);
    assert_eq!(parse_after_txid(&q(Some(&t.to_string()))).unwrap(), Some(t));
    let err = parse_after_txid(&q(Some("nothex"))).unwrap_err();
    assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
}

#[test]
fn mempool_rows_sort_in_admission_order_then_by_txid() {
    let mut rows = vec![
        (300u64, txid(1), ()),
        (200, txid(9), ()),
        (100, txid(3), ()),
        (200, txid(2), ()),
    ];
    sort_in_admission_order(&mut rows);
    let order: Vec<(u64, Txid)> = rows.into_iter().map(|(t, id, ())| (t, id)).collect();
    assert_eq!(
        order,
        vec![(100, txid(3)), (200, txid(2)), (200, txid(9)), (300, txid(1))]
    );
}
