//! Newest-first confirmed pages (Esplora's `/txs/chain[/:last_seen_txid]`)
//! read from the cursor rather than from the top of the history.
//!
//! The trait's default reads and resolves the whole history for every page.
//! These tests hold the chainstate index's paged read to the default's
//! answers, cursor by cursor, and to a cost that follows the page rather
//! than the history.

use std::sync::Arc;

use bitcoin::Txid;
use bitcoin::hashes::Hash as _;
use tokio::sync::broadcast;

use super::RocksAddressIndex;
use crate::index::address::config::AddressIndexConfig;
use crate::index::address::keys::{AddrFundingRowV3, AddrSpendingRowV3, Scripthash};
use crate::index::address::subscribe::SubscribeError;
use crate::index::address::trait_def::AddressIndex;
use crate::index::address::types::{HistoryEntry, IndexError, MempoolHistoryEntry, StatusUpdate, Utxo};
use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};
use crate::storage::test_store::{ControllableStore, StoreControls};
use crate::storage::{Store, StoreBatch};

const SH: Scripthash = [0x11; 32];
const OTHER: Scripthash = [0x22; 32];

/// A txid whose `Txid` order runs against block position: byte 0, which
/// decides the order, falls as the position rises.
fn txid(height: u32, pos: u32) -> Txid {
    let mut b = [0u8; 32];
    b[0] = 0xFF - pos as u8;
    b[1..5].copy_from_slice(&height.to_be_bytes());
    b[5..9].copy_from_slice(&pos.to_be_bytes());
    Txid::from_byte_array(b)
}

/// What one transaction does to the two scripts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Touch {
    Nothing,
    /// Pays `SH` this many outputs.
    Pays(u32),
    /// Spends one `SH` output.
    Spends,
    /// Pays `SH` twice and spends one `SH` output.
    PaysAndSpends,
    /// Touches only `OTHER`.
    Other,
}

/// Heights `1..=heights`, `per_block` transactions each, numbered in chain
/// order from ordinal 1; `touch` decides each transaction's rows. Returns
/// the index and the store's controls.
fn chain(
    heights: u32,
    per_block: u32,
    touch: impl Fn(u32, u32) -> Touch,
) -> (RocksAddressIndex, StoreControls) {
    let store = ControllableStore::new();
    let controls = store.controls();
    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
    let mut batch = StoreBatch::default();
    let mut seq = 1u64;
    for height in 1..=heights {
        let hash = bitcoin::BlockHash::from_byte_array(*txid(height, 0xFF).as_byte_array());
        batch.block_index_puts.push((
            hash,
            BlockIndexEntry {
                header: genesis.header,
                height,
                status: BlockStatus::Valid,
                num_tx: per_block,
                file_number: 0,
                data_pos: 0,
                chainwork: [0u8; 32],
            },
        ));
        batch.height_hash_puts.push((height, hash));
        batch.txseq_block_puts.push((seq, height));
        for pos in 0..per_block {
            let t = txid(height, pos);
            batch.tx_loc_puts.push((t, seq));
            batch.txseq_txid_puts.push((seq, t));
            let pay = |sh: Scripthash, vout: u32| AddrFundingRowV3 {
                scripthash: sh,
                txseq: seq,
                vout,
                amount_sat: 1_000,
            };
            // Every spend consumes the first transaction's output.
            let spend = |vin: u32| AddrSpendingRowV3 {
                scripthash: SH,
                txseq: seq,
                vin,
                funding_txseq: 1,
                funding_vout: 0,
            };
            match touch(height, pos) {
                Touch::Nothing => {}
                Touch::Pays(n) => {
                    for vout in 0..n {
                        batch.addr_funding_puts.push(pay(SH, vout));
                    }
                }
                Touch::Spends => batch.addr_spending_puts.push(spend(0)),
                Touch::PaysAndSpends => {
                    batch.addr_funding_puts.push(pay(SH, 0));
                    batch.addr_funding_puts.push(pay(SH, 3));
                    batch.addr_spending_puts.push(spend(1));
                }
                Touch::Other => batch.addr_funding_puts.push(pay(OTHER, 0)),
            }
            seq += 1;
        }
    }
    store.write_batch(batch).unwrap();
    let store: Arc<dyn Store> = Arc::new(store);
    (
        RocksAddressIndex::new(store, AddressIndexConfig::default()),
        controls,
    )
}

/// The same index without the paged read: the trait's default, which reads
/// the whole history. That is the order and the answers Esplora served
/// before.
struct WholeHistory<'a>(&'a RocksAddressIndex);

impl AddressIndex for WholeHistory<'_> {
    fn confirmed_history(&self, sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
        self.0.confirmed_history(sh)
    }
    fn mempool_history(&self, sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
        self.0.mempool_history(sh)
    }
    fn balance(&self, sh: &Scripthash) -> Result<(u64, i64), IndexError> {
        self.0.balance(sh)
    }
    fn utxos(&self, sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
        self.0.utxos(sh)
    }
    fn subscribe(
        &self,
        sh: Scripthash,
    ) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
        self.0.subscribe(sh)
    }
}

/// A mix: blocks where several of `SH`'s transactions share the block (and
/// sort by txid against their position), blocks with one, blocks with none,
/// transactions with several rows, and `OTHER`'s rows in between.
fn mixed(height: u32, pos: u32) -> Touch {
    match (height % 5, pos) {
        (0, 1) | (0, 2) => Touch::Pays(1),
        (0, 3) => Touch::PaysAndSpends,
        (1, 0) => Touch::Pays(2),
        (2, 2) => Touch::Spends,
        (3, 0) => Touch::Nothing,
        (3, _) => Touch::Other,
        (4, 1) => Touch::Other,
        (4, 3) => Touch::Pays(1),
        _ => Touch::Nothing,
    }
}

#[test]
fn pages_match_the_whole_history_from_every_cursor() {
    let (index, _) = chain(60, 4, mixed);
    let whole = WholeHistory(&index);
    let all = whole
        .confirmed_txs_newest_first(&SH, None, usize::MAX)
        .unwrap()
        .unwrap();
    assert!(all.len() > 50, "the fixture spans more than two pages");
    // Several of the script's transactions share a block, in an order
    // that differs from their block position.
    assert!(all.windows(2).any(|w| w[0].0 == w[1].0));

    let mut cursors: Vec<Option<Txid>> = vec![None];
    cursors.extend(all.iter().map(|(_, t)| Some(*t)));
    // Not the script's: a block-mate of its transactions, `OTHER`'s in a
    // block the script also has rows in, one in a block the script has no
    // rows in, and one that does not exist.
    cursors.extend([
        Some(txid(5, 0)),
        Some(txid(9, 1)),
        Some(txid(8, 0)),
        Some(Txid::from_byte_array([0x42; 32])),
    ]);
    for limit in [1, 2, 7, 25] {
        for cursor in &cursors {
            assert_eq!(
                index.confirmed_txs_newest_first(&SH, *cursor, limit).unwrap(),
                whole.confirmed_txs_newest_first(&SH, *cursor, limit).unwrap(),
                "limit {limit}, cursor {cursor:?}"
            );
        }
    }
}

#[test]
fn a_cursor_outside_the_confirmed_history_is_none() {
    let (index, _) = chain(10, 4, mixed);
    for cursor in [
        txid(5, 0),                        // a block-mate of SH's transactions
        txid(9, 1),                        // OTHER's, in a block SH has rows in
        txid(8, 0),                        // in a block SH has no rows in
        Txid::from_byte_array([0x42; 32]), // unknown
    ] {
        assert_eq!(
            index.confirmed_txs_newest_first(&SH, Some(cursor), 25).unwrap(),
            None,
            "cursor {cursor}"
        );
    }
    // The last page after the oldest transaction is empty, not None.
    let all = index
        .confirmed_txs_newest_first(&SH, None, usize::MAX)
        .unwrap()
        .unwrap();
    let oldest = all.last().unwrap().1;
    assert_eq!(
        index.confirmed_txs_newest_first(&SH, Some(oldest), 25).unwrap(),
        Some(Vec::new())
    );
}

/// The point of the paged read: a page deep in a long history reads and
/// resolves the transactions near it, not the whole history. Walking an
/// `N`-transaction history 25 at a time used to read and resolve all `N`
/// for every page.
#[test]
fn a_deep_page_resolves_only_the_rows_near_it() {
    let (index, controls) = chain(3_000, 2, |_, pos| {
        if pos == 1 { Touch::Pays(1) } else { Touch::Nothing }
    });
    let whole = WholeHistory(&index);
    let all = whole
        .confirmed_txs_newest_first(&SH, None, usize::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(all.len(), 3_000);

    for cursor in [None, Some(all[1_500].1), Some(all[2_950].1)] {
        controls.reset_ordinal_read_counts();
        let page = index.confirmed_txs_newest_first(&SH, cursor, 25).unwrap();
        let (read, resolved) = (controls.addr_rows_served(), controls.ordinals_resolved());
        assert!(
            read <= 100 && resolved <= 100,
            "a 25-row page at cursor {cursor:?} read {read} rows and resolved {resolved} \
             ordinals of a 3000-transaction history"
        );
        assert_eq!(page, whole.confirmed_txs_newest_first(&SH, cursor, 25).unwrap());
    }
}

// ── History cap: refuse an over-long history after reading O(cap) ────

/// The distinct confirmed transactions of `SH`, from the unbounded read.
fn distinct_count(index: &RocksAddressIndex) -> usize {
    index
        .confirmed_distinct_history_limited(&SH, usize::MAX)
        .unwrap()
        .len()
}

/// The cap counts distinct transactions, not rows: the mixed fixture has
/// transactions with several funding rows and transactions that both fund
/// and spend, so a row count would refuse a history at the cap.
#[test]
fn check_history_cap_counts_transactions_and_refuses_one_past_the_cap() {
    let (index, _) = chain(60, 4, mixed);
    let n = distinct_count(&index);
    let rows = index.confirmed_history(&SH).unwrap().len();
    assert!(rows > n, "fixture premise: more rows ({rows}) than transactions ({n})");

    assert!(index.check_history_cap(&SH, n).is_ok(), "a history at the cap is served");
    assert!(index.check_history_cap(&SH, n + 1).is_ok());
    assert!(matches!(
        index.check_history_cap(&SH, n - 1),
        Err(IndexError::HistoryTooLarge { cap }) if cap == n - 1
    ));
    assert!(matches!(
        index.check_history_cap(&SH, 0),
        Err(IndexError::HistoryTooLarge { cap: 0 })
    ));
    // `OTHER`'s rows are not `SH`'s, and an unknown script has none.
    assert!(index.check_history_cap(&[0x77; 32], 0).is_ok());
}

/// The point of the cap: refusing a long history reads about `cap` rows
/// and resolves none of them. Before, the Electrum `get_history` refusal
/// read and resolved every row of the history first, and the status,
/// balance and Esplora stats read it with no cap at all.
#[test]
fn refusing_a_long_history_reads_only_about_cap_rows() {
    let (index, controls) = chain(3_000, 2, |_, pos| {
        if pos == 1 { Touch::Pays(1) } else { Touch::Nothing }
    });
    assert_eq!(distinct_count(&index), 3_000);

    controls.reset_ordinal_read_counts();
    assert!(matches!(
        index.check_history_cap(&SH, 100),
        Err(IndexError::HistoryTooLarge { cap: 100 })
    ));
    let (read, resolved) = (controls.addr_rows_served(), controls.ordinals_resolved());
    assert!(
        read <= 101 && resolved == 0,
        "refusing at cap 100 read {read} rows and resolved {resolved} ordinals of a \
         3000-transaction history"
    );

    // The Electrum path: the status and `get_history` build their rows
    // through `capped_history_rows`.
    controls.reset_ordinal_read_counts();
    let refused = node_index::capped_history_rows(&index, &SH, 100, |_| None);
    assert!(matches!(refused, Err(IndexError::HistoryTooLarge { cap: 100 })));
    let (read, resolved) = (controls.addr_rows_served(), controls.ordinals_resolved());
    assert!(
        read <= 101 && resolved == 0,
        "capped_history_rows at cap 100 read {read} rows and resolved {resolved} ordinals"
    );
}

/// The count runs over several `addr_rows_desc` runs once the cap is past
/// one run's worth of transactions, and stops in the run that passes it.
#[test]
fn the_count_spans_several_runs_and_stops_past_the_cap() {
    let total = crate::storage::ADDR_COUNT_RUN_TXS as u32 + 700;
    let (index, controls) = chain(total, 1, |_, _| Touch::Pays(1));
    let cap = crate::storage::ADDR_COUNT_RUN_TXS + 300;

    controls.reset_ordinal_read_counts();
    assert!(matches!(
        index.check_history_cap(&SH, cap),
        Err(IndexError::HistoryTooLarge { .. })
    ));
    assert_eq!(
        controls.addr_rows_served(),
        cap as u64 + 1,
        "the count must stop at the first transaction past the cap"
    );
    assert!(index.check_history_cap(&SH, total as usize).is_ok());
}

/// Under the cap, the capped rows are the uncapped rows: same transactions,
/// same order, nothing dropped.
#[test]
fn capped_history_rows_under_the_cap_match_the_uncapped_rows() {
    let (index, _) = chain(60, 4, mixed);
    let n = distinct_count(&index);
    let uncapped = node_index::history_rows(&index, &SH, usize::MAX, |_| None).unwrap();
    assert_eq!(uncapped.len(), n);
    assert_eq!(
        node_index::capped_history_rows(&index, &SH, n, |_| None).unwrap(),
        uncapped
    );
    assert!(matches!(
        node_index::capped_history_rows(&index, &SH, n - 1, |_| None),
        Err(IndexError::HistoryTooLarge { .. })
    ));
}

/// `confirmed_history`'s order is `(height, display txid, funding first)`.
/// The sort key now compares reversed bytes instead of building hex strings;
/// the order must be the one the strings gave.
#[test]
fn confirmed_history_order_is_the_display_string_order() {
    let (index, _) = chain(60, 4, mixed);
    let got = index.confirmed_history(&SH).unwrap();
    // `got` is in the old comparator's order exactly when sorting it by
    // that comparator leaves it unchanged.
    let mut expected = got.clone();
    expected.sort_by(|a, b| {
        let key = |e: &HistoryEntry| {
            (e.height(), e.txid().to_string(), matches!(e, HistoryEntry::Spending { .. }))
        };
        key(a).cmp(&key(b))
    });
    assert_eq!(got, expected);
    // Fixture premise: some block holds several distinct txids.
    assert!(got.windows(2).any(|w| w[0].height() == w[1].height() && w[0].txid() != w[1].txid()));
}

/// What `get_first_use` answered before: the lowest `(height, txid)` over
/// the whole confirmed history.
fn first_use_from_whole_history(index: &RocksAddressIndex) -> Option<(u32, Txid)> {
    index
        .confirmed_history(&SH)
        .unwrap()
        .iter()
        .min_by_key(|e| (e.height(), e.txid()))
        .map(|e| (e.height(), e.txid()))
}

#[test]
fn first_confirmed_tx_is_the_lowest_txid_of_the_first_block() {
    // The first block holds three of `SH`'s transactions, and `txid` runs
    // against block position, so the answer is the LAST of them by
    // position.
    let (index, _) = chain(20, 4, |height, pos| match (height, pos) {
        (1, 1..=3) => Touch::Pays(1),
        (1, _) => Touch::Nothing,
        _ => mixed(height, pos),
    });
    let got = index.first_confirmed_tx(&SH).unwrap();
    assert_eq!(got, Some((1, txid(1, 3))));
    assert_eq!(got, first_use_from_whole_history(&index));

    // An empty history has no first use.
    assert_eq!(index.first_confirmed_tx(&[0x77; 32]).unwrap(), None);

    // The first block's rows outnumber the first read window: a
    // transaction with many outputs, then a lower txid in the same block.
    let (index, _) = chain(20, 3, |height, pos| match (height, pos) {
        (1, 0) => Touch::Pays(40),
        (1, 2) => Touch::Pays(1),
        (1, _) => Touch::Nothing,
        _ => Touch::Pays(1),
    });
    assert_eq!(index.first_confirmed_tx(&SH).unwrap(), Some((1, txid(1, 2))));
    assert_eq!(index.first_confirmed_tx(&SH).unwrap(), first_use_from_whole_history(&index));

    // A script whose first row is a spend.
    let (index, _) = chain(10, 2, |height, pos| match (height, pos) {
        (3, 1) => Touch::Spends,
        (5, _) => Touch::Pays(1),
        _ => Touch::Nothing,
    });
    assert_eq!(index.first_confirmed_tx(&SH).unwrap(), Some((3, txid(3, 1))));
}

/// `get_first_use` read and resolved the whole history to report its first
/// row; it now reads the first block's rows.
#[test]
fn first_confirmed_tx_reads_only_the_first_rows_of_a_long_history() {
    let (index, controls) = chain(3_000, 2, |_, pos| {
        if pos == 1 { Touch::Pays(1) } else { Touch::Nothing }
    });
    controls.reset_ordinal_read_counts();
    let got = index.first_confirmed_tx(&SH).unwrap();
    let read = controls.addr_rows_served();
    assert_eq!(got, Some((1, txid(1, 1))));
    assert!(read <= 32, "first use read {read} rows of a 3000-transaction history");
}
