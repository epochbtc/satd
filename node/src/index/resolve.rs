//! Resolving transaction ordinals back to the identifiers the public
//! surfaces speak.
//!
//! Index rows key on a dense chain-order ordinal rather than a 32-byte
//! txid — that is what makes them small. Nothing outside the storage
//! layer sees an ordinal: every row is resolved back to `(height, txid)`
//! before it leaves, so the `AddressIndex` and `SpendIndex` traits, the
//! Electrum and Esplora responses, and the RPC shapes are all unchanged.
//!
//! The resolution has to be **batched**. One scan over a busy
//! scripthash's history can return tens of thousands of rows, and a
//! per-row point read against the reverse map would put back most of
//! what the smaller rows saved. [`resolve_txseqs`] does one `multi_get`
//! over the distinct ordinals and one block lookup per distinct block,
//! whatever the row count.

use std::collections::HashMap;

use bitcoin::Txid;

use crate::storage::Store;

/// What an ordinal resolves to on a public surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub height: u32,
    pub txid: Txid,
}

/// Resolve a slice of ordinals to `(height, txid)`, preserving order.
///
/// `None` in a slot means the ordinal has no row. On a healthy
/// chainstate that cannot happen for an ordinal that came out of an
/// index row — the rows are written in the same atomic batch as the
/// ordinal families — so callers treat it as local corruption: skip the
/// row and log, rather than emit a placeholder a consumer would read as
/// real.
///
/// Costs one `multi_get` over the distinct ordinals plus one
/// `block_of_seq` per distinct block, regardless of how many rows are
/// passed in. Duplicate ordinals are free: a transaction with twenty
/// outputs paying one script yields twenty rows and one lookup.
pub fn resolve_txseqs(store: &dyn Store, seqs: &[u64]) -> Vec<Option<Resolved>> {
    if seqs.is_empty() {
        return Vec::new();
    }

    // Distinct ordinals, sorted: sorted keys let RocksDB's `multi_get`
    // walk each SST block once instead of seeking back and forth, and
    // the block cache below is keyed on the ordinal's block, which
    // consecutive ordinals share.
    let mut distinct: Vec<u64> = seqs.to_vec();
    distinct.sort_unstable();
    distinct.dedup();

    let txids = store.txids_of_seqs(&distinct);

    // One `block_of_seq` per distinct block, not per ordinal. Walking
    // the distinct ordinals in ascending order means the block found for
    // one usually covers the next several, so the cached range answers
    // without another seek.
    let mut heights: HashMap<u64, u32> = HashMap::with_capacity(distinct.len());
    let mut cached: Option<(u64, u64, u32)> = None; // (first_txseq, end_txseq, height)
    for &seq in &distinct {
        if let Some((first, end, height)) = cached
            && seq >= first
            && seq < end
        {
            heights.insert(seq, height);
            continue;
        }
        let Some((first, height)) = store.block_of_seq(seq) else {
            continue;
        };
        heights.insert(seq, height);
        // The block's ordinal range ends where the next block's begins.
        // `block_of_seq` already bounded the answer by the block's
        // transaction count, so re-deriving that count here would be a
        // second read for something the first call proved; instead cache
        // conservatively from `first` to `seq + 1` and widen as later
        // ordinals in the same block confirm it.
        cached = Some(match cached {
            Some((cf, ce, ch)) if cf == first && ch == height => (cf, ce.max(seq + 1), ch),
            _ => (first, seq + 1, height),
        });
    }

    let by_seq: HashMap<u64, Txid> = distinct
        .iter()
        .zip(txids)
        .filter_map(|(seq, txid)| txid.map(|t| (*seq, t)))
        .collect();

    seqs.iter()
        .map(|seq| {
            let txid = by_seq.get(seq)?;
            let height = heights.get(seq)?;
            Some(Resolved {
                height: *height,
                txid: *txid,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StoreBatch;
    use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};
    use crate::storage::test_store::ControllableStore;
    use bitcoin::hashes::Hash;

    fn txid(byte: u8) -> Txid {
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
    }

    /// Two blocks, three transactions each. Build the ordinal families
    /// by hand so the test owns the numbering it asserts on.
    fn store_with_two_blocks() -> ControllableStore {
        let store = ControllableStore::new();
        let g = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let mut batch = StoreBatch::default();
        for (height, first, hash_byte) in [(0u32, 0u64, 0xA0u8), (1, 3, 0xA1)] {
            let hash = bitcoin::BlockHash::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([hash_byte; 32]),
            );
            batch.block_index_puts.push((
                hash,
                BlockIndexEntry {
                    header: g.header,
                    height,
                    status: BlockStatus::Valid,
                    num_tx: 3,
                    file_number: 0,
                    data_pos: 0,
                    chainwork: [0u8; 32],
                },
            ));
            batch.height_hash_puts.push((height, hash));
            batch.txseq_block_puts.push((first, height));
            for i in 0..3u64 {
                let t = txid((first + i) as u8 + 1);
                batch.tx_loc_puts.push((t, first + i));
                batch.txseq_txid_puts.push((first + i, t));
            }
        }
        store.write_batch(batch).unwrap();
        store
    }

    #[test]
    fn resolve_txseqs_returns_height_and_txid_in_input_order() {
        let store = store_with_two_blocks();
        // Deliberately out of order and with a duplicate.
        let got = resolve_txseqs(&store, &[4, 0, 4, 2]);
        assert_eq!(
            got,
            vec![
                Some(Resolved { height: 1, txid: txid(5) }),
                Some(Resolved { height: 0, txid: txid(1) }),
                Some(Resolved { height: 1, txid: txid(5) }),
                Some(Resolved { height: 0, txid: txid(3) }),
            ]
        );
    }

    /// The whole point of the helper: one lookup per scan, not per row.
    /// A per-row implementation returns identical answers, so nothing
    /// about the output would show the difference.
    #[test]
    fn resolve_txseqs_costs_one_reverse_lookup_per_call() {
        let store = store_with_two_blocks();
        let controls = store.controls();
        controls.reset_ordinal_read_counts();

        // 500 rows over 6 distinct ordinals — the shape a busy
        // scripthash's history has.
        let seqs: Vec<u64> = (0..500).map(|i| (i % 6) as u64).collect();
        let got = resolve_txseqs(&store, &seqs);
        assert_eq!(got.len(), 500);
        assert!(got.iter().all(|r| r.is_some()));

        assert_eq!(
            controls.txids_of_seqs_calls(),
            1,
            "resolution must be one batched lookup per scan; a per-row \
             implementation returns the same answers and costs 500"
        );
    }

    /// The funding iterator resolves its whole scan in one batch. A
    /// per-row implementation returns identical rows, so only the call
    /// count can tell them apart — and on a busy scripthash the
    /// difference is one lookup against tens of thousands.
    ///
    /// Exercised through the helper the iterator calls, because that is
    /// the boundary a counting wrapper can observe: an iterator on a
    /// concrete store resolves against itself.
    #[test]
    fn funding_rows_resolve_in_one_batch_for_the_whole_scan() {
        let store = store_with_two_blocks();
        let controls = store.controls();
        let sh = [0x7c; 32];

        // 500 rows over the 6 ordinals the fixture chain holds — one
        // transaction paying the same script many times, which is the
        // shape that makes per-row resolution expensive.
        let raw: Vec<(u64, u32, u64)> = (0..500u32).map(|i| ((i % 6) as u64, i, 1u64)).collect();

        controls.reset_ordinal_read_counts();
        let rows = crate::storage::rocksdb_store::resolve_funding_rows_for(&store, &sh, raw);

        assert_eq!(rows.len(), 500, "every row resolves");
        assert_eq!(
            controls.txids_of_seqs_calls(),
            1,
            "the scan must resolve once, not once per row"
        );
        // And the result is in the documented order.
        let mut sorted = rows.clone();
        sorted.sort_by(|(a, _), (b, _)| {
            (a.height, a.txid.to_string(), a.vout).cmp(&(b.height, b.txid.to_string(), b.vout))
        });
        assert_eq!(rows, sorted, "rows come back in (height, txid, vout) order");
    }

    /// An ordinal with no reverse row is local corruption. It must come
    /// back as `None` — a caller can then skip the row and say so —
    /// rather than as a zeroed or invented txid a consumer would read as
    /// a real transaction.
    #[test]
    fn resolve_txseqs_reports_an_unresolvable_ordinal_as_none() {
        let store = store_with_two_blocks();
        let got = resolve_txseqs(&store, &[0, 99, 1]);
        assert_eq!(got[0].map(|r| r.txid), Some(txid(1)));
        assert_eq!(got[1], None, "an ordinal past the chain has no answer");
        assert_eq!(got[2].map(|r| r.txid), Some(txid(2)));
    }

    #[test]
    fn resolve_txseqs_on_an_empty_slice_reads_nothing() {
        let store = store_with_two_blocks();
        let controls = store.controls();
        controls.reset_ordinal_read_counts();
        assert!(resolve_txseqs(&store, &[]).is_empty());
        assert_eq!(controls.txids_of_seqs_calls(), 0);
    }
}
