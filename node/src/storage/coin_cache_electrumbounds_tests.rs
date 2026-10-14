//! `addr_rows_desc` through the cache: the not-yet-flushed rows are merged
//! in exactly as the flush will write them, whatever the run size.

use bitcoin::OutPoint;
use bitcoin::hashes::Hash as _;

use super::CoinCache;
use crate::index::address::{AddrFundingKeyV3, AddrFundingRowV3, AddrSpendingKeyV3, AddrSpendingRowV3, Scripthash};
use crate::storage::coinview::Coin;
use crate::storage::db::InMemoryStore;
use crate::storage::{AddrRowKey, Store, StoreBatch};

const SH: Scripthash = [0x11; 32];

fn funding(txseq: u64, vout: u32) -> AddrFundingRowV3 {
    AddrFundingRowV3 {
        scripthash: SH,
        txseq,
        vout,
        amount_sat: 1,
    }
}

fn spending(txseq: u64, vin: u32) -> AddrSpendingRowV3 {
    AddrSpendingRowV3 {
        scripthash: SH,
        txseq,
        vin,
        funding_txseq: 1,
        funding_vout: 0,
    }
}

/// Every run, `min_txs` ordinals at a time, concatenated. Also checks that
/// no ordinal is split between two runs.
fn walk(store: &dyn Store, min_txs: usize) -> Vec<AddrRowKey> {
    let mut out: Vec<AddrRowKey> = Vec::new();
    let mut below = None;
    loop {
        let run = store.addr_rows_desc(&SH, below, min_txs);
        if let (Some(prev), Some(first)) = (out.last(), run.rows.first()) {
            assert!(first.txseq < prev.txseq, "ordinal {} split across runs", prev.txseq);
        }
        out.extend(run.rows);
        match run.next_below {
            Some(b) => below = Some(b),
            None => return out,
        }
    }
}

#[test]
fn pending_rows_merge_as_the_flush_will_write_them() {
    let cache = CoinCache::new(Box::new(InMemoryStore::new()), 16);

    let mut flushed = StoreBatch::default();
    flushed.addr_funding_puts.extend([
        funding(2, 0),
        funding(4, 0),
        funding(4, 1),
        funding(6, 0),
        funding(8, 0),
        funding(12, 0),
    ]);
    flushed.addr_spending_puts.extend([spending(6, 0), spending(9, 0)]);
    cache.write_batch(flushed).unwrap();
    cache.flush_durable().unwrap();

    // Pending: a new newest ordinal, one between flushed ones, a second
    // row for a flushed ordinal, a flushed row removed, a flushed ordinal
    // removed outright, and a put and a remove of one key in one batch.
    let mut pending = StoreBatch::default();
    pending.addr_funding_puts.extend([funding(14, 0), funding(5, 0), funding(4, 2), funding(3, 0)]);
    pending.addr_funding_removes.extend([
        AddrFundingKeyV3 { scripthash: SH, txseq: 8, vout: 0 },
        AddrFundingKeyV3 { scripthash: SH, txseq: 3, vout: 0 },
    ]);
    pending
        .addr_spending_removes
        .push(AddrSpendingKeyV3 { scripthash: SH, txseq: 9, vin: 0 });
    // A coin keeps the batch in the cache rather than passing it through.
    pending.coin_puts.push((
        OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x61; 32]),
            vout: 0,
        },
        Coin {
            amount: 1_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 1,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        },
    ));
    cache.write_batch(pending).unwrap();

    let f = |txseq, index| AddrRowKey { txseq, spending: false, index };
    let s = |txseq, index| AddrRowKey { txseq, spending: true, index };
    let expected = vec![
        f(14, 0),
        f(12, 0),
        s(6, 0),
        f(6, 0),
        f(5, 0),
        f(4, 2),
        f(4, 1),
        f(4, 0),
        f(2, 0),
    ];
    for min_txs in 1..=8 {
        assert_eq!(walk(&cache, min_txs), expected, "before the flush, runs of {min_txs}");
    }
    cache.flush_durable().unwrap();
    for min_txs in [1, 3, 8] {
        assert_eq!(walk(&cache, min_txs), expected, "after the flush, runs of {min_txs}");
    }
}
