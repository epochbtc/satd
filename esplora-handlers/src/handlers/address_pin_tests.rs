//! The address routes answer for the pinned tip (`crate::chain_tip`): rows
//! confirmed above it confirmed while the request ran, and are served as
//! the unconfirmed transactions they were at the pin.
//!
//! The history is the history-cap tests' five transactions, at heights 3,
//! 5, 5, 8 and 9 (the last spends an output of the one at 5). Pinned at 5,
//! the transactions at 8 and 9 are late.

use bitcoin::BlockHash;
use bitcoin::hashes::Hash as _;

use super::historycap_tests::{SH, esplora_state, history, txid};
use super::{build_address_info, build_utxos, compute_chain_stats_from_history, pinned_page};
use crate::chain_tip::Pin;

fn pin_at(height: u32) -> Pin {
    Pin {
        hash: BlockHash::all_zeros(),
        height,
    }
}

#[test]
fn stats_count_rows_above_the_pin_as_unconfirmed() {
    let (state, _dir) = esplora_state(100);
    let info = build_address_info(&state, &pin_at(5), "label", &SH).unwrap();
    let pinned: Vec<_> = history().into_iter().filter(|e| e.height() <= 5).collect();
    assert_eq!(
        serde_json::to_value(&info.chain_stats).unwrap(),
        serde_json::to_value(compute_chain_stats_from_history(&pinned)).unwrap()
    );
    // Late: tx 4 funds 4,000 + 5,000; tx 5 spends tx 2's 2,000 output.
    assert_eq!(
        serde_json::to_value(&info.mempool_stats).unwrap(),
        serde_json::json!({
            "tx_count": 2,
            "funded_txo_count": 2,
            "funded_txo_sum": 9_000,
            "spent_txo_count": 1,
            "spent_txo_sum": 2_000,
        })
    );

    // Pinned above the history, chain stats are the whole history and the
    // mempool stats are empty, as before pinning.
    let info = build_address_info(&state, &pin_at(9), "label", &SH).unwrap();
    assert_eq!(
        serde_json::to_value(&info.chain_stats).unwrap(),
        serde_json::to_value(compute_chain_stats_from_history(&history())).unwrap()
    );
    assert_eq!(info.mempool_stats.tx_count, 0);
}

#[test]
fn utxos_created_above_the_pin_are_unconfirmed() {
    let (state, _dir) = esplora_state(100);
    let got: Vec<(String, u32, bool, Option<u32>)> = build_utxos(&state, &pin_at(5), &SH)
        .unwrap()
        .into_iter()
        .map(|u| (u.txid, u.vout, u.status.confirmed, u.status.block_height))
        .collect();
    assert_eq!(
        got,
        vec![
            (txid(3).to_string(), 1, true, Some(5)),
            (txid(4).to_string(), 0, false, None),
            (txid(4).to_string(), 1, false, None),
        ]
    );
}

#[test]
fn confirmed_pages_hold_only_rows_at_or_below_the_pin() {
    let (state, _dir) = esplora_state(100);
    let rows = |pin: u32, after| -> Option<Vec<u32>> {
        pinned_page(&state, &pin_at(pin), &SH, after)
            .unwrap()
            .map(|page| page.into_iter().map(|(h, _)| h).collect())
    };
    assert_eq!(rows(9, None), Some(vec![9, 8, 5, 5, 3]));
    assert_eq!(rows(5, None), Some(vec![5, 5, 3]));
    assert_eq!(rows(4, None), Some(vec![3]));
    assert_eq!(rows(2, None), Some(vec![]));
    // A cursor continues below itself; one not in the history is None.
    assert_eq!(rows(5, Some(txid(4))), Some(vec![5, 5, 3]));
    assert_eq!(rows(5, Some(txid(0xee))), None);
}
