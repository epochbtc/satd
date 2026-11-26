//! `/address/:addr/txs/summary[/:last_seen_txid]`: the `/txs/chain` page as
//! compact rows, each with the script's net value in that transaction.
//!
//! The first tests read the history-cap tests' five transactions:
//!
//! | tx | height | funds | spends | net |
//! |---|---|---|---|---|
//! | 1 | 3 | 1,000 | | +1,000 |
//! | 2 | 5 | 2,000 | tx 1's 1,000 | +1,000 |
//! | 3 | 5 | 3,000 | | +3,000 |
//! | 4 | 8 | 4,000 + 5,000 | | +9,000 |
//! | 5 | 9 | | tx 2's 2,000 | -2,000 |

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use bitcoin::hashes::Hash as _;
use bitcoin::{BlockHash, OutPoint, Txid};
use node_index::{
    AddressIndex, HistoryEntry, IndexError, MempoolHistoryEntry, Scripthash, StatusUpdate,
    SubscribeError, Utxo,
};
use tokio::sync::broadcast;

use super::historycap_tests::{SH, esplora_state, history, txid};
use super::{
    TxSummaryJson, build_address_info, build_chain_txs, build_summary_txs, net_values, pinned_page,
};
use crate::chain_tip::Pin;
use crate::error::EsploraError;
use crate::state::EsploraState;

fn pin_at(height: u32) -> Pin {
    Pin {
        hash: BlockHash::all_zeros(),
        height,
        mempool: true,
    }
}

fn asof(height: u32) -> Pin {
    Pin {
        mempool: false,
        ..pin_at(height)
    }
}

/// `(txid byte, value, height)` of each row.
fn rows(page: &[TxSummaryJson]) -> Vec<(u8, i64, u32)> {
    page.iter()
        .map(|row| {
            let id: Txid = row.txid.parse().expect("a txid");
            (id.to_byte_array()[0], row.value, row.height)
        })
        .collect()
}

/// An index over a given history, for every script.
struct ListIndex(Vec<HistoryEntry>);

impl AddressIndex for ListIndex {
    fn confirmed_history(&self, _sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
        Ok(self.0.clone())
    }
    fn mempool_history(&self, _sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
        Vec::new()
    }
    fn balance(&self, _sh: &Scripthash) -> Result<(u64, i64), IndexError> {
        unreachable!("Esplora derives balances from the history")
    }
    fn utxos(&self, _sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
        unreachable!("the summary reads no UTXO")
    }
    fn subscribe(
        &self,
        _sh: Scripthash,
    ) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
        unreachable!("the summary opens no stream")
    }
}

fn state_over(history: Vec<HistoryEntry>) -> (EsploraState, tempfile::TempDir) {
    let (mut state, dir) = esplora_state(1_000);
    state.address_index = Arc::new(ListIndex(history));
    (state, dir)
}

fn fund(height: u32, n: u8, vout: u32, amount_sat: u64) -> HistoryEntry {
    HistoryEntry::Funding {
        height,
        txid: txid(n),
        vout,
        amount_sat,
    }
}

fn spend(height: u32, n: u8, vin: u32, of: u8, vout: u32) -> HistoryEntry {
    HistoryEntry::Spending {
        height,
        txid: txid(n),
        vin,
        prev_outpoint: OutPoint {
            txid: txid(of),
            vout,
        },
    }
}

/// A receive is positive, a spend negative, and a transaction that both
/// spends from the script and pays it shows the difference. Newest first.
#[test]
fn rows_carry_the_net_value_newest_first() {
    let (state, _dir) = esplora_state(100);
    let page = build_summary_txs(&state, &pin_at(9), &SH, None).unwrap();
    assert_eq!(
        rows(&page),
        vec![
            (5, -2_000, 9),
            (4, 9_000, 8),
            (3, 3_000, 5),
            (2, 1_000, 5),
            (1, 1_000, 3)
        ]
    );

    // The values add up to the balance the stats give.
    let stats = build_address_info(&state, &pin_at(9), "label", &SH)
        .unwrap()
        .chain_stats;
    assert_eq!(
        page.iter().map(|row| row.value).sum::<i64>(),
        (stats.funded_txo_sum - stats.spent_txo_sum) as i64
    );

    // The same transactions in the same order as `/txs/chain`.
    let chain_order: Vec<Txid> = pinned_page(&state, &pin_at(9), &SH, None)
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|(_, t)| t)
        .collect();
    assert_eq!(
        page.iter().map(|row| row.txid.clone()).collect::<Vec<_>>(),
        chain_order.iter().map(Txid::to_string).collect::<Vec<_>>()
    );
}

/// The wire shape: `{txid, value, height, time, tx_position}` in that order,
/// `tx_position` left out when the store cannot place the transaction (the
/// in-memory store here keeps no ordinals, and holds no header, so `time`
/// is 0).
#[test]
fn row_shape_is_the_one_rbitcoins_esplora_serves() {
    let (state, _dir) = esplora_state(100);
    let page = build_summary_txs(&state, &pin_at(9), &SH, None).unwrap();
    assert_eq!(
        serde_json::to_string(&page[0]).unwrap(),
        format!(
            r#"{{"txid":"{}","value":-2000,"height":9,"time":0}}"#,
            txid(5)
        )
    );
    let placed = TxSummaryJson {
        txid: txid(7).to_string(),
        value: 12,
        height: 4,
        time: 1_700_000_000,
        tx_position: Some(3),
    };
    assert_eq!(
        serde_json::to_string(&placed).unwrap(),
        format!(
            r#"{{"txid":"{}","value":12,"height":4,"time":1700000000,"tx_position":3}}"#,
            txid(7)
        )
    );
}

/// Spends and receives inside one transaction, in every mix, and a child
/// that spends its parent in the same block while its txid sorts first.
#[test]
fn value_is_funded_minus_spent_for_the_script() {
    let history = vec![
        // tx 0x10 pays the script twice.
        fund(1, 0x10, 0, 7_000),
        fund(1, 0x10, 3, 500),
        // tx 0x20 spends both and pays back exactly as much: a self-transfer.
        spend(2, 0x20, 0, 0x10, 0),
        spend(2, 0x20, 1, 0x10, 3),
        fund(2, 0x20, 0, 7_500),
        // tx 0x30 spends that and pays back less: change.
        spend(3, 0x30, 0, 0x20, 0),
        fund(3, 0x30, 1, 2_500),
        // Height 4: the child 0x05 spends the parent 0x40's output, and its
        // rows come first.
        spend(4, 0x05, 0, 0x40, 0),
        fund(4, 0x40, 0, 900),
        // tx 0x50 spends the change and pays nothing back.
        spend(5, 0x50, 0, 0x30, 1),
    ];
    let (state, _dir) = state_over(history.clone());
    let page = build_summary_txs(&state, &pin_at(5), &SH, None).unwrap();
    assert_eq!(
        rows(&page),
        vec![
            (0x50, -2_500, 5),
            (0x40, 900, 4),
            (0x05, -900, 4),
            (0x30, -5_000, 3),
            (0x20, 0, 2),
            (0x10, 7_500, 1),
        ]
    );
    assert_eq!(
        page.iter().map(|row| row.value).sum::<i64>(),
        0,
        "everything was spent"
    );

    // The same values whatever order the rows are in.
    let page_txs: Vec<(u32, Txid)> = page
        .iter()
        .map(|row| (row.height, row.txid.parse().unwrap()))
        .collect();
    let mut reversed = history.clone();
    reversed.reverse();
    assert_eq!(
        net_values(&page_txs, &history),
        net_values(&page_txs, &reversed)
    );
}

/// 60 transactions: 25, 25, 10, then an empty page, each row exactly once,
/// and each page the one `/txs/chain` pages to.
#[test]
fn pages_hold_25_rows_and_the_cursor_continues_below_itself() {
    // Transaction `n` at height `n` pays `n * 100`; every third one also
    // spends the output of the one before it.
    let mut history = Vec::new();
    for n in 1..=60u8 {
        if n.is_multiple_of(3) {
            history.push(spend(u32::from(n), n, 0, n - 1, 0));
        }
        history.push(fund(u32::from(n), n, 0, u64::from(n) * 100));
    }
    let expected = |n: u8| -> i64 {
        let funded = i64::from(n) * 100;
        if n.is_multiple_of(3) {
            funded - (i64::from(n) - 1) * 100
        } else {
            funded
        }
    };
    let (state, _dir) = state_over(history);
    let pin = pin_at(60);

    let mut seen = Vec::new();
    let mut cursor = None;
    let mut sizes = Vec::new();
    loop {
        let page = build_summary_txs(&state, &pin, &SH, cursor).unwrap();
        sizes.push(page.len());
        let Some(last) = page.last() else { break };
        // `/txs/chain` cannot render here (no block is stored), so compare
        // with the page it would render.
        let chain: Vec<String> = pinned_page(&state, &pin, &SH, cursor)
            .unwrap()
            .unwrap()
            .iter()
            .map(|(_, t)| t.to_string())
            .collect();
        assert_eq!(
            page.iter().map(|row| row.txid.clone()).collect::<Vec<_>>(),
            chain
        );
        cursor = Some(last.txid.parse().unwrap());
        seen.extend(rows(&page));
    }
    assert_eq!(sizes, vec![25, 25, 10, 0]);
    assert_eq!(
        seen,
        (1..=60u8)
            .rev()
            .map(|n| (n, expected(n), u32::from(n)))
            .collect::<Vec<_>>()
    );
}

/// A cursor that is not in the script's confirmed history is 422, never an
/// empty page (which means the history ended) or the first page again.
#[test]
fn an_unknown_cursor_is_422() {
    let (state, _dir) = esplora_state(100);
    let err = build_summary_txs(&state, &pin_at(9), &SH, Some(txid(0xee))).expect_err("unknown");
    assert!(matches!(err, EsploraError::Unprocessable(_)), "{err:?}");
    assert_eq!(err.to_string(), "after_txid not found");
    assert_eq!(
        err.into_response().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // The oldest transaction as the cursor: the end, an empty page.
    assert!(
        build_summary_txs(&state, &pin_at(9), &SH, Some(txid(1)))
            .unwrap()
            .is_empty()
    );
    // `/txs/chain` keeps its own answer for an unknown cursor.
    assert!(
        build_chain_txs(&state, &pin_at(9), &SH, Some(txid(0xee)))
            .unwrap()
            .is_empty()
    );
}

/// As of a block: the transactions confirmed up to it, with the values they
/// had (a spend above the pin changes nothing below it).
#[test]
fn rows_are_as_of_the_pin() {
    let (state, _dir) = esplora_state(100);
    for pin in [asof(5), pin_at(5)] {
        let page = build_summary_txs(&state, &pin, &SH, None).unwrap();
        assert_eq!(
            rows(&page),
            vec![(3, 3_000, 5), (2, 1_000, 5), (1, 1_000, 3)]
        );
    }
    let page = build_summary_txs(&state, &asof(8), &SH, Some(txid(4))).unwrap();
    assert_eq!(
        rows(&page),
        vec![(3, 3_000, 5), (2, 1_000, 5), (1, 1_000, 3)]
    );
    assert!(
        build_summary_txs(&state, &asof(2), &SH, None)
            .unwrap()
            .is_empty()
    );
}

/// The values need the whole history, so the route takes the history cap
/// like the stats: refused over it, served at it.
#[test]
fn summary_is_refused_over_the_history_cap_and_served_at_it() {
    let (state, _dir) = esplora_state(4);
    for cursor in [None, Some(txid(4)), Some(txid(0xee))] {
        let err = build_summary_txs(&state, &pin_at(9), &SH, cursor).expect_err("over the cap");
        assert!(matches!(err, EsploraError::HistoryTooLarge(4)), "{err:?}");
        assert_eq!(
            err.to_string(),
            "Too many history entries (more than 4 transactions)"
        );
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
    }
    let (state, _dir) = esplora_state(5);
    assert_eq!(
        build_summary_txs(&state, &pin_at(9), &SH, None)
            .unwrap()
            .len(),
        5
    );
    assert_eq!(history().len(), 7, "five transactions in seven rows");
}
