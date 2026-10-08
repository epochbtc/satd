//! `?after_txid=` on `/address/:addr/txs` and the mempool order it relies on.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use bitcoin::hashes::Hash as _;

use super::*;

fn txid(byte: u8) -> Txid {
    Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
}

#[test]
fn after_txid_in_the_confirmed_history_continues_after_it() {
    let mempool = [txid(1), txid(2)];
    let confirmed = [txid(10), txid(11), txid(12)];
    assert_eq!(
        locate_after_txid(&mempool, &confirmed, &txid(10)),
        Some(AfterTxid::Confirmed(1))
    );
    // The oldest confirmed transaction: the rest of the history is empty.
    assert_eq!(
        locate_after_txid(&mempool, &confirmed, &txid(12)),
        Some(AfterTxid::Confirmed(3))
    );
}

#[test]
fn after_txid_in_the_mempool_continues_after_it() {
    let mempool = [txid(1), txid(2)];
    let confirmed = [txid(10)];
    assert_eq!(
        locate_after_txid(&mempool, &confirmed, &txid(1)),
        Some(AfterTxid::Mempool(1))
    );
    assert_eq!(
        locate_after_txid(&mempool, &confirmed, &txid(2)),
        Some(AfterTxid::Mempool(2))
    );
}

/// Between a block connecting and the mempool dropping its transactions, a
/// transaction can be in both lists. The confirmed history is where it ends
/// up, so the cursor continues there, after it, instead of restarting the
/// confirmed history from its newest entry (the cursor itself).
#[test]
fn after_txid_in_both_lists_resolves_to_the_confirmed_one() {
    let mempool = [txid(1), txid(10)];
    let confirmed = [txid(10), txid(11)];
    assert_eq!(
        locate_after_txid(&mempool, &confirmed, &txid(10)),
        Some(AfterTxid::Confirmed(1))
    );
}

#[test]
fn after_txid_outside_the_history_is_422_after_txid_not_found() {
    assert_eq!(locate_after_txid(&[txid(1)], &[txid(10)], &txid(99)), None);
    assert_eq!(locate_after_txid(&[], &[], &txid(99)), None);

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
        (300u64, txid(1)),
        (200, txid(9)),
        (100, txid(3)),
        (200, txid(2)),
    ];
    sort_in_admission_order(&mut rows);
    assert_eq!(
        rows,
        vec![(100, txid(3)), (200, txid(2)), (200, txid(9)), (300, txid(1))]
    );
}

/// A transaction both lists hold (a block just connected, the mempool has
/// not dropped it yet) is listed once, as confirmed.
#[test]
fn mempool_rows_already_confirmed_are_listed_only_as_confirmed() {
    let confirmed = [
        ConfirmedTxRef {
            txid: txid(10),
            height: 7,
        },
        ConfirmedTxRef {
            txid: txid(11),
            height: 6,
        },
    ];
    assert_eq!(
        without_confirmed(vec![txid(1), txid(10), txid(2)], &confirmed),
        vec![txid(1), txid(2)]
    );
    assert_eq!(
        without_confirmed(vec![txid(1), txid(2)], &[]),
        vec![txid(1), txid(2)]
    );
}
