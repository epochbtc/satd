//! `Mempool::admission_times`: the entries' admission times, without the
//! transactions.

use bitcoin::hashes::Hash as _;

use super::*;

fn txid(byte: u8) -> Txid {
    Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
}

/// A distinct transaction per `byte`: the pool keeps one entry per wtxid.
fn tx(byte: u8) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: OutPoint {
                txid: txid(byte),
                vout: 0,
            },
            ..Default::default()
        }],
        output: Vec::new(),
    }
}

#[test]
fn admission_times_reports_each_pooled_txid_and_skips_the_rest() {
    let pool = Mempool::new(1_000_000, 1_000);
    for (byte, time) in [(1u8, 300u64), (2, 100)] {
        pool.insert_entry_for_test(txid(byte), tx(byte), 1_000);
        pool.inner.write().entries.get_mut(&txid(byte)).unwrap().time = time;
    }
    assert_eq!(
        pool.admission_times(&[txid(2), txid(9), txid(1)]),
        vec![(txid(2), 100), (txid(1), 300)],
        "in request order, without the txid that is not in the pool"
    );
    assert_eq!(pool.admission_times(&[]), Vec::new());
}
