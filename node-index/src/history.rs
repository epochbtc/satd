//! Electrum history order, shared by the status hash and the history
//! responses.
//!
//! The Electrum protocol (protocol-basics, "Status") defines a scripthash's
//! status as the sha256 of `"tx_hash:height:"` over its history in one order:
//!
//! 1. confirmed transactions by ascending height, and by position in the block
//!    when one block holds more than one;
//! 2. then mempool transactions by `(-height, tx_hash)`: height `0` (every
//!    input confirmed) before height `-1` (spends an unconfirmed parent), then
//!    the txid in its displayed (hex) byte order.
//!
//! `blockchain.scripthash.get_history` lists the history in that same order,
//! and a client checks an announced status by hashing the `get_history`
//! response as it arrived. So the status, `get_history` and `get_mempool` all
//! build their rows here, and [`history_status_hash`] hashes them without
//! re-sorting. romanz/electrs and ElectrumX build the history the same way;
//! like them, a mempool-index row whose transaction has already left the
//! mempool is left out rather than reported with a guessed height and no fee.

use std::collections::BTreeSet;

use bitcoin::Txid;
use bitcoin::hashes::{Hash, sha256};

use crate::keys::Scripthash;
use crate::trait_def::AddressIndex;
use crate::types::IndexError;

/// What a history row needs to know about a mempool transaction. The caller
/// looks it up in its mempool; this crate has none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MempoolTxFacts {
    /// The transaction spends an output of another mempool transaction.
    pub has_unconfirmed_inputs: bool,
    /// The transaction's fee, in satoshis.
    pub fee_sat: u64,
}

/// One transaction in a scripthash's Electrum history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryRow {
    /// The block height for a confirmed transaction. For a mempool
    /// transaction, `0` when every input is confirmed and `-1` when one
    /// spends an unconfirmed parent.
    pub height: i64,
    pub txid: Txid,
    /// The fee in satoshis; set on mempool rows only.
    pub fee_sat: Option<u64>,
}

/// The txid's bytes in display order (the order of its hex string), which is
/// the reverse of `Txid`'s internal byte order and of its `Ord`.
fn display_bytes(txid: &Txid) -> [u8; 32] {
    let mut b = txid.to_byte_array();
    b.reverse();
    b
}

/// Put distinct confirmed `(height, txid)` rows in history order: ascending
/// height, then position in the block.
///
/// `chain_position` returns a transaction's chain-order ordinal (its
/// position in the chain, so also its position within its block). It is
/// only asked about heights that hold more than one row; a transaction it
/// cannot place sorts after the ones it can, by txid, so the order stays
/// deterministic.
pub fn sort_confirmed_rows(
    rows: &mut [(u32, Txid)],
    mut chain_position: impl FnMut(&Txid) -> Option<u64>,
) {
    rows.sort_by_key(|(height, _)| *height);
    for block in rows.chunk_by_mut(|a, b| a.0 == b.0) {
        if block.len() > 1 {
            block.sort_by_cached_key(|(_, txid)| {
                let pos = chain_position(txid);
                (pos.is_none(), pos, *txid)
            });
        }
    }
}

/// Put mempool rows in history order: `(-height, tx_hash)`, that is height
/// `0` before `-1`, then the txid compared in display byte order.
pub fn sort_mempool_rows(rows: &mut [HistoryRow]) {
    rows.sort_by(|a, b| {
        b.height
            .cmp(&a.height)
            .then_with(|| display_bytes(&a.txid).cmp(&display_bytes(&b.txid)))
    });
}

/// The mempool part of `sh`'s history, in history order: one row per
/// transaction still in the mempool.
pub fn mempool_history_rows(
    idx: &dyn AddressIndex,
    sh: &Scripthash,
    mempool: impl Fn(&Txid) -> Option<MempoolTxFacts>,
) -> Vec<HistoryRow> {
    let txids: BTreeSet<Txid> = idx.mempool_history(sh).into_iter().map(|e| e.txid).collect();
    let mut rows: Vec<HistoryRow> = txids
        .into_iter()
        .filter_map(|txid| {
            let facts = mempool(&txid)?;
            Some(HistoryRow {
                height: if facts.has_unconfirmed_inputs { -1 } else { 0 },
                txid,
                fee_sat: Some(facts.fee_sat),
            })
        })
        .collect();
    sort_mempool_rows(&mut rows);
    rows
}

/// `sh`'s Electrum history in protocol order, confirmed rows then mempool
/// rows, at most `limit` of them. A caller enforcing a cap passes `cap + 1`
/// and treats a longer answer as too large.
pub fn history_rows(
    idx: &dyn AddressIndex,
    sh: &Scripthash,
    limit: usize,
    mempool: impl Fn(&Txid) -> Option<MempoolTxFacts>,
) -> Result<Vec<HistoryRow>, IndexError> {
    let mut rows: Vec<HistoryRow> = idx
        .confirmed_txs_in_chain_order(sh, limit)?
        .into_iter()
        .map(|(height, txid)| HistoryRow {
            height: i64::from(height),
            txid,
            fee_sat: None,
        })
        .collect();
    if rows.len() < limit {
        let room = limit - rows.len();
        rows.extend(mempool_history_rows(idx, sh, mempool).into_iter().take(room));
    }
    Ok(rows)
}

/// The Electrum status of a history already in protocol order: sha256 over
/// `"tx_hash:height:"` per row, rows taken in the order given. The all-zero
/// array stands for an empty history (the wire answer is `null`).
pub fn history_status_hash(rows: &[HistoryRow]) -> [u8; 32] {
    status_hash_of(rows.iter().map(|r| (r.height, r.txid)))
}

pub(crate) fn status_hash_of(rows: impl Iterator<Item = (i64, Txid)>) -> [u8; 32] {
    let mut concat = String::new();
    for (height, txid) in rows {
        // `Txid`'s Display is the byte-reversed hex the protocol uses.
        concat.push_str(&txid.to_string());
        concat.push(':');
        concat.push_str(&height.to_string());
        concat.push(':');
    }
    if concat.is_empty() {
        return [0u8; 32];
    }
    sha256::Hash::hash(concat.as_bytes()).to_byte_array()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitcoin::OutPoint;
    use tokio::sync::broadcast;

    use super::*;
    use crate::subscribe::SubscribeError;
    use crate::types::{HistoryEntry, MempoolHistoryEntry, StatusUpdate, Utxo};

    /// A txid whose internal bytes start with `first` and end with `last`.
    /// `Txid`'s `Ord` follows `first`; its display hex is the reverse, so it
    /// follows `last`.
    fn txid(first: u8, last: u8) -> Txid {
        let mut b = [0u8; 32];
        b[0] = first;
        b[31] = last;
        Txid::from_byte_array(b)
    }

    /// In-memory index: confirmed rows as given (they must already be in
    /// `(height, txid)` order, as the trait promises), mempool txids as given.
    #[derive(Default)]
    struct FakeIndex {
        confirmed: Vec<HistoryEntry>,
        mempool: Vec<Txid>,
    }

    impl AddressIndex for FakeIndex {
        fn confirmed_history(&self, _sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
            Ok(self.confirmed.clone())
        }
        fn mempool_history(&self, _sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
            self.mempool
                .iter()
                .map(|txid| MempoolHistoryEntry { txid: *txid })
                .collect()
        }
        fn balance(&self, _sh: &Scripthash) -> Result<(u64, i64), IndexError> {
            Ok((0, 0))
        }
        fn utxos(&self, _sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
            Ok(Vec::new())
        }
        fn subscribe(
            &self,
            _sh: Scripthash,
        ) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
            unreachable!("not used by the history tests")
        }
    }

    fn funding(height: u32, txid: Txid) -> HistoryEntry {
        HistoryEntry::Funding {
            height,
            txid,
            vout: 0,
            amount_sat: 1_000,
        }
    }

    #[test]
    fn mempool_rows_put_height_zero_first_then_display_order() {
        let free_a = txid(0x01, 0x30); // first by `Ord`, second by display
        let free_b = txid(0x30, 0x10); // second by `Ord`, first by display
        let chained = txid(0x00, 0x00);
        let mut rows = vec![
            HistoryRow { height: -1, txid: chained, fee_sat: Some(1) },
            HistoryRow { height: 0, txid: free_a, fee_sat: Some(2) },
            HistoryRow { height: 0, txid: free_b, fee_sat: Some(3) },
        ];
        sort_mempool_rows(&mut rows);
        let got: Vec<(i64, Txid)> = rows.iter().map(|r| (r.height, r.txid)).collect();
        assert_eq!(got, vec![(0, free_b), (0, free_a), (-1, chained)]);
        // Display order is the order of the hex strings.
        assert!(free_b.to_string() < free_a.to_string());
    }

    #[test]
    fn confirmed_rows_follow_block_position() {
        // Three transactions in one block whose block order differs from
        // both their `Ord` order (p1, p2, p0) and their display order
        // (p2, p0, p1).
        let p0 = txid(0x03, 0x02);
        let p1 = txid(0x01, 0x03);
        let p2 = txid(0x02, 0x01);
        let alone = txid(0x09, 0x09);
        let positions: HashMap<Txid, u64> =
            [(alone, 40), (p0, 100), (p1, 101), (p2, 102)].into_iter().collect();

        let mut rows = vec![(10, p1), (5, alone), (10, p2), (10, p0)];
        let mut asked = Vec::new();
        sort_confirmed_rows(&mut rows, |t| {
            asked.push(*t);
            positions.get(t).copied()
        });
        assert_eq!(rows, vec![(5, alone), (10, p0), (10, p1), (10, p2)]);
        // Only a height holding more than one row needs a position.
        assert!(!asked.contains(&alone), "asked about a lone row: {asked:?}");
        assert_eq!(asked.len(), 3);
    }

    #[test]
    fn confirmed_row_without_a_position_sorts_last_in_its_block() {
        let known_late = txid(0x01, 0x01);
        let known_early = txid(0x02, 0x02);
        let unknown = txid(0x00, 0x00);
        let mut rows = vec![(7, unknown), (7, known_late), (7, known_early)];
        sort_confirmed_rows(&mut rows, |t| match *t {
            t if t == known_early => Some(1),
            t if t == known_late => Some(2),
            _ => None,
        });
        assert_eq!(rows, vec![(7, known_early), (7, known_late), (7, unknown)]);
    }

    #[test]
    fn status_hash_covers_rows_in_the_order_given() {
        let a = txid(0x01, 0x02);
        let b = txid(0x03, 0x04);
        let c = txid(0x05, 0x06);
        let rows = [
            HistoryRow { height: 5, txid: a, fee_sat: None },
            HistoryRow { height: 0, txid: b, fee_sat: Some(10) },
            HistoryRow { height: -1, txid: c, fee_sat: Some(20) },
        ];
        let text = format!("{a}:5:{b}:0:{c}:-1:");
        let expected = sha256::Hash::hash(text.as_bytes()).to_byte_array();
        assert_eq!(history_status_hash(&rows), expected);

        let reversed = [rows[2], rows[1], rows[0]];
        assert_ne!(
            history_status_hash(&reversed),
            expected,
            "the status follows row order; it must not re-sort"
        );
        assert_eq!(history_status_hash(&[]), [0u8; 32]);
    }

    #[test]
    fn history_rows_lists_confirmed_then_mempool_in_protocol_order() {
        let early = txid(0x40, 0x40);
        let late = txid(0x20, 0x20);
        let free = txid(0x10, 0x90);
        let chained = txid(0x90, 0x10);
        let gone = txid(0x50, 0x50);
        let idx = FakeIndex {
            // `late` funds and spends the script in one tx: two rows, one entry.
            confirmed: vec![
                funding(3, early),
                funding(7, late),
                HistoryEntry::Spending {
                    height: 7,
                    txid: late,
                    vin: 0,
                    prev_outpoint: OutPoint { txid: early, vout: 0 },
                },
            ],
            mempool: vec![chained, gone, free],
        };
        // `gone` is still in the mempool index but no longer in the mempool.
        let facts = |t: &Txid| match *t {
            t if t == free => Some(MempoolTxFacts { has_unconfirmed_inputs: false, fee_sat: 300 }),
            t if t == chained => Some(MempoolTxFacts { has_unconfirmed_inputs: true, fee_sat: 400 }),
            _ => None,
        };

        let rows = history_rows(&idx, &[0u8; 32], usize::MAX, facts).unwrap();
        assert_eq!(
            rows,
            vec![
                HistoryRow { height: 3, txid: early, fee_sat: None },
                HistoryRow { height: 7, txid: late, fee_sat: None },
                HistoryRow { height: 0, txid: free, fee_sat: Some(300) },
                HistoryRow { height: -1, txid: chained, fee_sat: Some(400) },
            ]
        );
        assert_eq!(mempool_history_rows(&idx, &[0u8; 32], facts), rows[2..].to_vec());

        // A cap of N is enforced by asking for N + 1 rows.
        let capped = history_rows(&idx, &[0u8; 32], 3, facts).unwrap();
        assert_eq!(capped, rows[..3].to_vec());
    }
}
