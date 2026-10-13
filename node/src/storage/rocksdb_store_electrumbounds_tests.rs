//! `addr_rows_desc` on RocksDB: a reverse seek over both address families
//! that stays inside the scripthash's key prefix and never splits a
//! transaction's rows between two runs.

use super::RocksDbStore;
use crate::index::address::{AddrFundingRowV3, AddrSpendingRowV3, Scripthash};
use crate::storage::{AddrRowKey, AddrRowsDesc, Store, StoreBatch};

const SH: Scripthash = [0x11; 32];

fn funding(sh: Scripthash, txseq: u64, vout: u32) -> AddrFundingRowV3 {
    AddrFundingRowV3 {
        scripthash: sh,
        txseq,
        vout,
        amount_sat: 1,
    }
}

fn spending(sh: Scripthash, txseq: u64, vin: u32) -> AddrSpendingRowV3 {
    AddrSpendingRowV3 {
        scripthash: sh,
        txseq,
        vin,
        funding_txseq: 1,
        funding_vout: 0,
    }
}

fn f(txseq: u64, index: u32) -> AddrRowKey {
    AddrRowKey {
        txseq,
        spending: false,
        index,
    }
}

fn s(txseq: u64, index: u32) -> AddrRowKey {
    AddrRowKey {
        txseq,
        spending: true,
        index,
    }
}

/// `SH`'s rows at ordinals 5, 9, 12 and 20, with the neighbouring key
/// prefixes holding rows at ordinals on both sides of them.
fn store() -> (RocksDbStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = RocksDbStore::open(dir.path(), true, 16, false, -1).unwrap();
    let below: Scripthash = [0x10; 32];
    let above: Scripthash = [0x12; 32];
    let mut batch = StoreBatch::default();
    batch.addr_funding_puts.extend([
        funding(SH, 5, 0),
        funding(SH, 5, 1),
        funding(SH, 9, 0),
        funding(SH, 20, 0),
        funding(SH, 20, 1),
        funding(SH, 20, 2),
        funding(SH, 20, 3),
    ]);
    batch.addr_spending_puts.extend([spending(SH, 5, 0), spending(SH, 12, 0)]);
    for neighbour in [below, above] {
        for txseq in [1, 7, 15, 30] {
            batch.addr_funding_puts.push(funding(neighbour, txseq, 0));
            batch.addr_spending_puts.push(spending(neighbour, txseq, 0));
        }
    }
    store.write_batch(batch).unwrap();
    (store, dir)
}

#[test]
fn reads_both_families_newest_first_within_the_prefix() {
    let (store, _dir) = store();
    assert_eq!(
        store.addr_rows_desc(&SH, None, 100),
        AddrRowsDesc {
            rows: vec![
                f(20, 3),
                f(20, 2),
                f(20, 1),
                f(20, 0),
                s(12, 0),
                f(9, 0),
                s(5, 0),
                f(5, 1),
                f(5, 0),
            ],
            next_below: None,
        }
    );
}

#[test]
fn runs_stop_after_min_txs_and_continue_below() {
    let (store, _dir) = store();
    // Two ordinals; all four rows of ordinal 20 come in one run.
    let first = store.addr_rows_desc(&SH, None, 2);
    assert_eq!(first.rows, vec![f(20, 3), f(20, 2), f(20, 1), f(20, 0), s(12, 0)]);
    assert_eq!(first.next_below, Some(12));

    let second = store.addr_rows_desc(&SH, first.next_below, 1);
    assert_eq!(second.rows, vec![f(9, 0)]);
    assert_eq!(second.next_below, Some(9));

    // The last ordinal: both families' rows, then the end of the history.
    let third = store.addr_rows_desc(&SH, second.next_below, 1);
    assert_eq!(third.rows, vec![s(5, 0), f(5, 1), f(5, 0)]);
    assert_eq!(third.next_below, None);

    // `below` is exclusive, and an ordinal between rows starts at the next
    // one down.
    assert_eq!(store.addr_rows_desc(&SH, Some(20), 1).rows, vec![s(12, 0)]);
    assert_eq!(store.addr_rows_desc(&SH, Some(19), 1).rows, vec![s(12, 0)]);
    assert_eq!(store.addr_rows_desc(&SH, Some(21), 1).rows.len(), 4);
    assert_eq!(store.addr_rows_desc(&SH, Some(5), 10), AddrRowsDesc::default());
    assert_eq!(store.addr_rows_desc(&SH, Some(0), 10), AddrRowsDesc::default());
    // Scripthashes with no rows, whose prefixes sort just below and just
    // above `SH`'s: the seek lands on a neighbour's row and must stop there.
    for last in [0x10, 0x12] {
        let mut empty = SH;
        empty[15] = last;
        assert_eq!(store.addr_rows_desc(&empty, None, 10), AddrRowsDesc::default());
    }
}
