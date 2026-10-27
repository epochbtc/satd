//! Esplora `?asof=<blockhash>`: answers as of a block still on the best chain,
//! and the chain-tip headers that name the block an answer was read at.
//!
//! The chain: `w` mines 101 blocks, so its coinbase at height 1 is mature.
//! Block 102 is empty; block 103 holds `spend`, which pays that coinbase to
//! `dest`. As of block 102 the coinbase is unspent and `dest` has no history.

use std::str::FromStr;

use super::{E2eNode, EsploraClient, esplora_e2e_args, esplora_for};
use crate::common::{self, DeterministicWallet, build_signed_p2wpkh_spend_of_coinbase};

const TIP: &str = "x-bitcoin-chain-tip";
const TIP_HEIGHT: &str = "x-bitcoin-chain-tip-height";

fn mine(e2e: &E2eNode, n: u64, wallet: &DeterministicWallet) {
    e2e.node.rpc_ok(
        "generatetoaddress",
        vec![
            serde_json::json!(n),
            serde_json::json!(wallet.address.to_string()),
        ],
    );
}

fn block_hash_at(e2e: &E2eNode, height: u64) -> String {
    e2e.node
        .rpc_ok("getblockhash", vec![serde_json::json!(height)])
        .as_str()
        .expect("hash string")
        .to_string()
}

/// GET `path`: status, the two chain-tip headers, and the body.
fn get(esplora: &EsploraClient, path: &str) -> (u16, Option<String>, Option<String>, String) {
    let resp = esplora.get(path);
    let status = resp.status().as_u16();
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .map(|v| v.to_str().expect("ascii header").to_string())
    };
    let tip = header(TIP);
    let height = header(TIP_HEIGHT);
    (status, tip, height, resp.text().expect("body utf8"))
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"))
}

/// Chain routes name the tip they answered for, and agree with their own
/// answer; mempool routes carry no tip.
#[test]
fn test_e2e_esplora_chain_tip_headers() {
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let w = DeterministicWallet::from_secret([0x31u8; 32]);
    mine(&e2e, 5, &w);
    let tip = block_hash_at(&e2e, 5);

    let (status, h, height, body) = get(&esplora, "/blocks/tip/hash");
    assert_eq!((status, h.as_deref(), height.as_deref()), (200, Some(tip.as_str()), Some("5")));
    assert_eq!(body, tip);
    let (_, h, _, body) = get(&esplora, &format!("/address/{}/utxo", w.address));
    assert_eq!(h.as_deref(), Some(tip.as_str()));
    assert_eq!(json(&body).as_array().unwrap().len(), 5);

    for path in ["/mempool", "/fee-estimates", "/mempool/txids"] {
        let (status, h, height, _) = get(&esplora, path);
        assert_eq!(status, 200, "{path}");
        assert_eq!((h, height), (None, None), "{path} does not read the chain");
    }
    e2e.node.stop();
}

#[test]
fn test_e2e_esplora_asof_answers_as_of_an_ancestor() {
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let w = DeterministicWallet::from_secret([0x32u8; 32]);
    let dest = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("address")
        .assume_checked();
    mine(&e2e, 102, &w);
    let h102 = block_hash_at(&e2e, 102);
    let (raw, spend) =
        build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &w, 1, dest.script_pubkey(), 1_000);
    assert_eq!(esplora.post_tx(&raw).status(), 200);
    mine(&e2e, 1, &w);
    let h103 = block_hash_at(&e2e, 103);
    let coinbase1 = common::coinbase_txid_at(&e2e.node, 1);
    let asof = format!("asof={h102}");

    // The spend: confirmed at 103 live, not yet as of 102.
    let (status, h, height, body) = get(&esplora, &format!("/tx/{spend}/status"));
    assert_eq!((status, h.as_deref(), height.as_deref()), (200, Some(h103.as_str()), Some("103")));
    assert_eq!(json(&body)["block_height"], 103);
    let (status, h, height, body) = get(&esplora, &format!("/tx/{spend}/status?{asof}"));
    assert_eq!((status, h.as_deref(), height.as_deref()), (200, Some(h102.as_str()), Some("102")));
    assert_eq!(json(&body), serde_json::json!({ "confirmed": false }));

    // The coinbase's output: spent live, unspent as of 102.
    let (_, _, _, body) = get(&esplora, &format!("/tx/{coinbase1}/outspend/0"));
    assert_eq!(json(&body)["spent"], true);
    assert_eq!(json(&body)["txid"], spend.as_str());
    let (status, h, _, body) = get(&esplora, &format!("/tx/{coinbase1}/outspend/0?{asof}"));
    assert_eq!((status, h.as_deref()), (200, Some(h102.as_str())));
    assert_eq!(json(&body), serde_json::json!({ "spent": false }));
    // Every output of the coinbase (the payout and the witness commitment).
    let (_, _, _, body) = get(&esplora, &format!("/tx/{coinbase1}/outspends?{asof}"));
    let outs = json(&body);
    assert!(
        outs.as_array().unwrap().iter().all(|o| *o == serde_json::json!({ "spent": false })),
        "{outs}"
    );
    let (_, _, _, body) = get(&esplora, &format!("/tx/{coinbase1}/outspends"));
    assert_eq!(json(&body)[0]["spent"], true);

    // `w`'s UTXOs: as of 102 the height-1 coinbase is there, live it is not.
    let utxo_txids = |body: &str| -> Vec<String> {
        json(body)
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["txid"].as_str().unwrap().to_string())
            .collect()
    };
    let (_, _, _, live) = get(&esplora, &format!("/address/{}/utxo", w.address));
    let (_, h, _, then) = get(&esplora, &format!("/address/{}/utxo?{asof}", w.address));
    assert_eq!(h.as_deref(), Some(h102.as_str()));
    assert!(!utxo_txids(&live).contains(&coinbase1));
    assert!(utxo_txids(&then).contains(&coinbase1));
    assert_eq!(utxo_txids(&then).len(), 102, "one coinbase per block 1..=102");

    // `dest`: one transaction live, none as of 102.
    let (_, _, _, body) = get(&esplora, &format!("/address/{dest}"));
    assert_eq!(json(&body)["chain_stats"]["tx_count"], 1);
    let (_, _, _, body) = get(&esplora, &format!("/address/{dest}?{asof}"));
    assert_eq!(json(&body)["chain_stats"]["tx_count"], 0);
    assert_eq!(json(&body)["mempool_stats"]["tx_count"], 0);
    for route in ["/txs", "/txs/chain", "/utxo"] {
        let (status, _, _, body) = get(&esplora, &format!("/address/{dest}{route}?{asof}"));
        assert_eq!((status, json(&body)), (200, serde_json::json!([])), "{route}");
    }
    let (_, _, _, body) = get(&esplora, &format!("/address/{dest}/txs/chain?asof={h103}"));
    assert_eq!(json(&body).as_array().unwrap().len(), 1);

    // A mempool-only transaction is unknown as of any block.
    let (raw, pending) =
        build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &w, 2, dest.script_pubkey(), 1_000);
    assert_eq!(esplora.post_tx(&raw).status(), 200);
    assert_eq!(get(&esplora, &format!("/tx/{pending}/status")).0, 200);
    assert_eq!(get(&esplora, &format!("/tx/{pending}/status?{asof}")).0, 404);
    // As of a block, the mempool is not part of the answer.
    let (_, _, _, body) = get(&esplora, &format!("/address/{dest}/txs?asof={h103}"));
    assert_eq!(json(&body).as_array().unwrap().len(), 1, "no mempool rows: {body}");

    // Unknown, malformed or empty asof, and asof on a route that does not
    // take it, are 404 with no tip.
    let zero = "00".repeat(32);
    for path in [
        format!("/tx/{spend}/status?asof={zero}"),
        format!("/tx/{spend}/status?asof=nothex"),
        format!("/tx/{spend}/status?asof="),
        format!("/tx/{spend}?{asof}"),
        format!("/address/{dest}/txs/mempool?{asof}"),
        format!("/mempool?{asof}"),
        format!("/blocks/tip/hash?{asof}"),
    ] {
        let (status, h, _, _) = get(&esplora, &path);
        assert_eq!((status, h), (404, None), "{path}");
    }

    // Once block 102 leaves the best chain, asof it is 404; there is no
    // retry onto whatever replaces it.
    e2e.node.rpc_ok("invalidateblock", vec![serde_json::json!(h102)]);
    let (status, h, _, _) = get(&esplora, &format!("/tx/{spend}/status?{asof}"));
    assert_eq!((status, h), (404, None));
    let (status, h, height, _) = get(&esplora, "/blocks/tip/height");
    assert_eq!((status, height.as_deref()), (200, Some("101")));
    assert_eq!(h.as_deref(), Some(block_hash_at(&e2e, 101).as_str()));

    e2e.node.stop();
}
