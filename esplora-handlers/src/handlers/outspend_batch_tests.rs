//! `GET /txs/outspends?txids=`: one `/tx/:txid/outspends` answer per txid in
//! request order, the limit, and the refusals.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bitcoin::BlockHash;
use node_index::{IndexError, SpendIndex, SpendingRef};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::*;
use crate::test_support::{extend_tip, regtest_state};

/// A spend index holding the given spends.
struct Spends(Vec<(OutPoint, SpendingRef)>);

impl SpendIndex for Spends {
    fn spend_of(&self, outpoint: &OutPoint) -> Result<Option<SpendingRef>, IndexError> {
        Ok(self
            .0
            .iter()
            .find(|(spent, _)| spent == outpoint)
            .map(|(_, by)| *by))
    }
    fn spends_of_tx(&self, txid: &Txid) -> Result<Vec<(u32, SpendingRef)>, IndexError> {
        Ok(self
            .0
            .iter()
            .filter(|(spent, _)| spent.txid == *txid)
            .map(|(spent, by)| (spent.vout, *by))
            .collect())
    }
}

const UNKNOWN: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

struct Fixture {
    router: axum::Router,
    /// The hashes of blocks 1 to 3.
    blocks: [BlockHash; 3],
    /// Their coinbases. The first one's output is spent in block 2.
    coinbases: [Txid; 3],
    spender: Txid,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let (mut state, dir) = regtest_state();
    let blocks = [0, 1, 2].map(|salt| extend_tip(&state.chain, salt));
    let coinbases = blocks
        .map(|hash| state.chain.get_stored_block(&hash).unwrap().block.txdata[0].compute_txid());
    let spender = Txid::from_byte_array([0xab; 32]);
    state.spend_index = Arc::new(Spends(vec![(
        OutPoint {
            txid: coinbases[0],
            vout: 0,
        },
        SpendingRef {
            spending_txid: spender,
            spending_vin: 3,
            height: 2,
        },
    )]));
    Fixture {
        router: crate::build_router(state).unwrap(),
        blocks,
        coinbases,
        spender,
        _dir: dir,
    }
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
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, tip, String::from_utf8(body.to_vec()).unwrap())
}

async fn get_json(router: &axum::Router, path: &str) -> Value {
    let (status, _, body) = get(router, path).await;
    assert_eq!(status, StatusCode::OK, "{path}: {body}");
    serde_json::from_str(&body).unwrap()
}

#[tokio::test]
async fn each_txid_gets_its_single_route_answer_in_request_order() {
    let f = fixture();
    let [a, b, c] = f.coinbases;
    let mut single = Vec::new();
    for txid in [a, b, c] {
        single.push(get_json(&f.router, &format!("/tx/{txid}/outspends")).await);
    }
    // The fixture's two kinds of answer, written out.
    assert_eq!(
        single[0],
        json!([{
            "spent": true,
            "txid": f.spender.to_string(),
            "vin": 3,
            "status": {
                "confirmed": true,
                "block_height": 2,
                "block_hash": f.blocks[1].to_string(),
                "block_time": 1_708_000_000u32 + 600 * 2 + 1,
            },
        }])
    );
    assert_eq!(single[1], json!([{"spent": false}]));

    let (status, tip, body) = get(&f.router, &format!("/txs/outspends?txids={b},{a},{c}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        tip,
        Some(f.blocks[2].to_string()),
        "stamped with the tip it was read at"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!([single[1], single[0], single[2]])
    );

    // One txid is still an array of arrays.
    assert_eq!(
        get_json(&f.router, &format!("/txs/outspends?txids={a}")).await,
        json!([single[0]])
    );
}

#[tokio::test]
async fn a_malformed_or_unknown_txid_gets_an_empty_array_in_its_place() {
    let f = fixture();
    let a = f.coinbases[0];
    let spent = get_json(&f.router, &format!("/tx/{a}/outspends")).await;
    // On the single route these are refused.
    assert_eq!(
        get(&f.router, &format!("/tx/{UNKNOWN}/outspends")).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&f.router, "/tx/zz/outspends").await.0,
        StatusCode::BAD_REQUEST
    );

    // Not hex, unknown, an empty item, a short one: each holds its slot.
    let got = get_json(
        &f.router,
        &format!("/txs/outspends?txids={a},zz,{UNKNOWN},,abcd,{a}"),
    )
    .await;
    assert_eq!(got, json!([spent, [], [], [], [], spent]));
    assert_eq!(
        get_json(&f.router, &format!("/txs/outspends?txids={UNKNOWN}")).await,
        json!([[]])
    );
    assert_eq!(
        get_json(&f.router, "/txs/outspends?txids=zz").await,
        json!([[]])
    );
}

#[tokio::test]
async fn a_txid_given_twice_is_answered_twice() {
    let f = fixture();
    let [a, b, _] = f.coinbases;
    let got = get_json(&f.router, &format!("/txs/outspends?txids={a},{b},{a},{a}")).await;
    let rows = got.as_array().unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0][0]["spent"], true);
    assert_eq!(rows[1], json!([{"spent": false}]));
    assert_eq!((&rows[2], &rows[3]), (&rows[0], &rows[0]));
}

#[tokio::test]
async fn no_txids_is_400() {
    let f = fixture();
    for path in [
        "/txs/outspends",
        "/txs/outspends?txids=",
        "/txs/outspends?txid=ab",
    ] {
        let (status, _, body) = get(&f.router, path).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::BAD_REQUEST, "No txids specified"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn fifty_txids_are_answered_and_fifty_one_refused() {
    let f = fixture();
    let a = f.coinbases[0].to_string();
    let list = |n: usize, item: &str| vec![item; n].join(",");

    let got = get_json(&f.router, &format!("/txs/outspends?txids={}", list(50, &a))).await;
    let rows = got.as_array().unwrap();
    assert_eq!(rows.len(), MAX_OUTSPENDS_TXIDS);
    assert!(rows.iter().all(|row| row[0]["spent"] == true), "{got}");

    // Items are counted before they are read as txids.
    for item in [a.as_str(), UNKNOWN, "zz", ""] {
        let (status, _, body) = get(
            &f.router,
            &format!("/txs/outspends?txids={}", list(51, item)),
        )
        .await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::BAD_REQUEST, "Too many txids requested"),
            "51 of {item:?}"
        );
    }
}

#[tokio::test]
async fn asof_answers_as_the_single_route_does() {
    let f = fixture();
    let [a, b, c] = f.coinbases;
    // As of block 1 the spend at height 2 has not happened, and the
    // coinbases of blocks 2 and 3 are still known to the txindex.
    for (asof, a_spent) in [(f.blocks[0], false), (f.blocks[1], true)] {
        let mut single = Vec::new();
        for txid in [a, b, c] {
            single.push(get_json(&f.router, &format!("/tx/{txid}/outspends?asof={asof}")).await);
        }
        assert_eq!(single[0][0]["spent"], a_spent, "as of {asof}");
        let path = format!("/txs/outspends?txids={a},{b},{c},{UNKNOWN}&asof={asof}");
        let (status, tip, body) = get(&f.router, &path).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(tip, Some(asof.to_string()), "stamped with the asof block");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!([single[0], single[1], single[2], []])
        );
    }
    // A block that is not on the chain is 404, as on every asof route.
    let (status, _, _) = get(
        &f.router,
        &format!("/txs/outspends?txids={a}&asof={UNKNOWN}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[test]
fn the_list_is_split_on_commas_and_capped() {
    let a = Txid::from_byte_array([7; 32]);
    assert_eq!(parse_txid_list(&a.to_string()).unwrap(), vec![Some(a)]);
    assert_eq!(
        parse_txid_list(&format!("{a},x,")).unwrap(),
        vec![Some(a), None, None]
    );
    // No trimming: a padded txid is not a txid.
    assert_eq!(parse_txid_list(&format!(" {a}")).unwrap(), vec![None]);
    assert_eq!(parse_txid_list(&vec!["x"; 50].join(",")).unwrap().len(), 50);
    assert!(parse_txid_list(&vec!["x"; 51].join(",")).is_err());
}
