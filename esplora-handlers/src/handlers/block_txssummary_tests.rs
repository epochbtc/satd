//! `/block/:hash/txs/summary`: the row shape, where fees come from, and the
//! refusals.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use node::storage::coinview::Coin;
use tower::ServiceExt as _;

use super::*;
use crate::test_support::{extend_tip, regtest_block, regtest_state};

fn tx(inputs: &[OutPoint], outputs: &[u64]) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs
            .iter()
            .map(|sat| TxOut {
                value: Amount::from_sat(*sat),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            })
            .collect(),
    }
}

fn outpoint(n: u8, vout: u32) -> OutPoint {
    OutPoint { txid: Txid::from_byte_array([n; 32]), vout }
}

fn coin(amount: u64) -> Coin {
    Coin {
        amount,
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        height: 1,
        coinbase: false,
        txseq: 1,
    }
}

/// A coinbase and two spends: the first of two coins (700 + 500) paying
/// 1,000 and 150, the second of one coin (9,000) paying 8,990.
fn three_tx_block() -> (Block, UndoData) {
    let mut block = regtest_block(BlockHash::all_zeros(), 1, 0);
    block.txdata.push(tx(&[outpoint(1, 0), outpoint(2, 3)], &[1_000, 150]));
    block.txdata.push(tx(&[outpoint(3, 1)], &[8_990]));
    let undo = UndoData { spent_coins: vec![coin(700), coin(500), coin(9_000)] };
    (block, undo)
}

fn txids_of(block: &Block) -> Vec<Txid> {
    block.txdata.iter().map(|tx| tx.compute_txid()).collect()
}

fn refusal(block: &Block, undo: Option<&UndoData>) -> (StatusCode, String) {
    let err = block_summary_rows(block, &txids_of(block), undo)
        .expect_err("expected the block to be refused");
    let msg = err.to_string();
    (err.into_response().status(), msg)
}

#[test]
fn rows_are_txid_fee_weight_value_in_block_order_coinbase_first() {
    let (block, undo) = three_tx_block();
    let txids = txids_of(&block);
    let rows = block_summary_rows(&block, &txids, Some(&undo)).unwrap();

    let weight = |i: usize| block.txdata[i].weight().to_wu();
    assert_eq!(
        rows,
        vec![
            // The coinbase: fee 0, and its output value is what it claims.
            BlockTxSummaryRow(txids[0].to_string(), 0, weight(0), 1_000),
            // 700 + 500 in, 1,000 + 150 out.
            BlockTxSummaryRow(txids[1].to_string(), 50, weight(1), 1_150),
            // 9,000 in, 8,990 out.
            BlockTxSummaryRow(txids[2].to_string(), 10, weight(2), 8_990),
        ]
    );
    // The three weights differ, so a row with two fields swapped cannot pass.
    assert!(weight(0) != weight(1) && weight(1) != weight(2));

    // On the wire each row is a four-element array, not an object.
    assert_eq!(
        serde_json::to_string(&rows[1]).unwrap(),
        format!(r#"["{}",50,{},1150]"#, txids[1], weight(1))
    );
}

#[test]
fn txids_are_the_ones_given_not_recomputed() {
    // An OP_RETURN-stripped block's txids come from its strip record.
    let (block, undo) = three_tx_block();
    let recorded: Vec<Txid> = (0..3u8).map(|n| Txid::from_byte_array([0xA0 + n; 32])).collect();
    let rows = block_summary_rows(&block, &recorded, Some(&undo)).unwrap();
    let got: Vec<&str> = rows.iter().map(|row| row.0.as_str()).collect();
    let want: Vec<String> = recorded.iter().map(|t| t.to_string()).collect();
    assert_eq!(got, want);
}

#[test]
fn a_coinbase_only_block_needs_no_undo_data() {
    let block = regtest_block(BlockHash::all_zeros(), 1, 0);
    let txids = txids_of(&block);
    let want = vec![BlockTxSummaryRow(
        txids[0].to_string(),
        0,
        block.txdata[0].weight().to_wu(),
        1_000,
    )];
    assert_eq!(block_summary_rows(&block, &txids, None).unwrap(), want);
    let empty = UndoData { spent_coins: Vec::new() };
    assert_eq!(block_summary_rows(&block, &txids, Some(&empty)).unwrap(), want);
}

#[test]
fn a_spending_block_without_undo_data_is_404() {
    let (block, _) = three_tx_block();
    assert_eq!(
        refusal(&block, None),
        (StatusCode::NOT_FOUND, BLOCK_UNDO_UNAVAILABLE.to_string())
    );
}

#[test]
fn undo_data_that_does_not_match_the_block_is_500() {
    let (block, mut undo) = three_tx_block();
    // One coin short.
    undo.spent_coins.pop();
    assert_eq!(refusal(&block, Some(&undo)).0, StatusCode::INTERNAL_SERVER_ERROR);
    // The right count, but the last transaction pays out more than it spends.
    undo.spent_coins.push(coin(8_989));
    assert_eq!(refusal(&block, Some(&undo)).0, StatusCode::INTERNAL_SERVER_ERROR);
    // One txid short.
    let (block, undo) = three_tx_block();
    let txids = &txids_of(&block)[..2];
    let err = block_summary_rows(&block, txids, Some(&undo)).unwrap_err();
    assert_eq!(err.into_response().status(), StatusCode::INTERNAL_SERVER_ERROR);
}

async fn get(router: &axum::Router, path: &str) -> (StatusCode, Option<String>, String) {
    let resp = router
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let tip = resp
        .headers()
        .get("x-bitcoin-chain-tip")
        .map(|v| v.to_str().unwrap().to_string());
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, tip, String::from_utf8(body.to_vec()).unwrap())
}

/// Through the router: the route is not taken for `/txs/:start_index`, names
/// the tip it answered for, and is 404 for a block that is unknown or not on
/// the best chain.
#[tokio::test]
async fn the_route_serves_best_chain_blocks_only_and_names_the_tip() {
    let (state, _dir) = regtest_state();
    let genesis = state.chain.get_block_hash_by_height(0).unwrap();
    let one = extend_tip(&state.chain, 0);
    let two = extend_tip(&state.chain, 0);
    // A side block at height 1: stored, but not on the best chain.
    let side = regtest_block(genesis, 1, 7);
    let _ = state.chain.accept_block(&side);
    let side_hash = side.block_hash();
    assert!(state.chain.get_stored_block(&side_hash).is_some(), "the side block is stored");
    let stored = state.chain.get_stored_block(&one).unwrap();
    let router = crate::build_router(state).unwrap();

    let (status, tip, body) = get(&router, &format!("/block/{one}/txs/summary")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(tip, Some(two.to_string()));
    let coinbase = &stored.block.txdata[0];
    assert_eq!(
        body,
        format!(r#"[["{}",0,{},1000]]"#, coinbase.compute_txid(), coinbase.weight().to_wu())
    );

    // Genesis has no undo row and spends nothing.
    let (status, _, body) = get(&router, &format!("/block/{genesis}/txs/summary")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap().as_array().unwrap().len(), 1);

    // The sibling route serves the side block; this one does not.
    let (status, _, _) = get(&router, &format!("/block/{side_hash}/txids")).await;
    assert_eq!(status, StatusCode::OK);
    for hash in [side_hash, BlockHash::all_zeros()] {
        let (status, tip, body) = get(&router, &format!("/block/{hash}/txs/summary")).await;
        assert_eq!((status, body.as_str()), (StatusCode::NOT_FOUND, "not found"), "{hash}");
        // A handler's 404 names the tip it was decided at, like any answer.
        assert_eq!(tip, Some(two.to_string()), "{hash}");
    }
    let (status, _, _) = get(&router, "/block/nothex/txs/summary").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
