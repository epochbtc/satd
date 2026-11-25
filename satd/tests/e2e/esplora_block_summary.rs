//! Esplora `/block/:hash/txs/summary`: one `[txid, fee, weight, value]` row
//! per transaction in block order, as rbitcoin's Esplora answers it.
//!
//! The chain: `w` mines 101 blocks, so its coinbases at heights 1 and 2 are
//! mature. Block 102 holds two spends of them, paying fees of 1,000 and
//! 2,500 sats. Every expected figure is worked out here from the signed
//! transactions and the coins they spend, not read back from the node's own
//! fee fields.

use std::str::FromStr;

use super::{E2eNode, EsploraClient, esplora_e2e_args, esplora_for, esplora_get_json};
use crate::common::{self, DeterministicWallet, build_signed_p2wpkh_spend_of_coinbase};

const TIP: &str = "x-bitcoin-chain-tip";

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

/// GET `path`: status, the chain-tip header, and the body.
fn get(esplora: &EsploraClient, path: &str) -> (u16, Option<String>, String) {
    let resp = esplora.get(path);
    let status = resp.status().as_u16();
    let tip = resp
        .headers()
        .get(TIP)
        .map(|v| v.to_str().expect("ascii header").to_string());
    (status, tip, resp.text().expect("body utf8"))
}

fn sats(btc: &serde_json::Value) -> u64 {
    (btc.as_f64().expect("a BTC amount") * 1e8).round() as u64
}

/// The coinbase of the block at `height`, as `getblock` verbosity 2 gives it.
fn coinbase_at(e2e: &E2eNode, height: u64) -> serde_json::Value {
    let hash = block_hash_at(e2e, height);
    e2e.node
        .rpc_ok("getblock", vec![serde_json::json!(hash), serde_json::json!(2)])["tx"][0]
        .clone()
}

fn output_sum(tx: &serde_json::Value) -> u64 {
    tx["vout"]
        .as_array()
        .expect("vout")
        .iter()
        .map(|out| sats(&out["value"]))
        .sum()
}

#[test]
fn test_e2e_esplora_block_txs_summary() {
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let w = DeterministicWallet::from_secret([0x41u8; 32]);
    mine(&e2e, 101, &w);
    let dest = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("address")
        .assume_checked()
        .script_pubkey();

    // Two spends, each of one coinbase's only spendable output. What each
    // must show: its txid, inputs minus outputs, its weight, its outputs.
    let mut expected = std::collections::HashMap::new();
    for (height, fee) in [(1u64, 1_000u64), (2, 2_500)] {
        let (raw, txid) =
            build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &w, height, dest.clone(), fee);
        let tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize_hex(&raw).expect("the signed spend decodes");
        assert_eq!(tx.input.len(), 1);
        let spent = sats(&coinbase_at(&e2e, height)["vout"][tx.input[0].previous_output.vout as usize]["value"]);
        let paid: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(spent - paid, fee, "the helper pays the fee it was asked for");
        expected.insert(txid, (spent - paid, tx.weight().to_wu(), paid));
        let r = esplora.post_tx(&raw);
        assert_eq!(r.status(), 200, "broadcast: {}", r.text().unwrap_or_default());
    }
    mine(&e2e, 1, &w);
    let h102 = block_hash_at(&e2e, 102);

    let (status, tip, body) = get(&esplora, &format!("/block/{h102}/txs/summary"));
    assert_eq!(status, 200, "{body}");
    assert_eq!(tip.as_deref(), Some(h102.as_str()), "stamped with the tip it was read at");
    let rows: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    let rows = rows.as_array().expect("an array of rows");
    assert_eq!(rows.len(), 3, "{body}");

    // Block order: the rows' txids are `/block/:hash/txids`.
    let txids = esplora_get_json(&esplora, &format!("/block/{h102}/txids"));
    let row_txids: Vec<&serde_json::Value> = rows.iter().map(|row| &row[0]).collect();
    assert_eq!(row_txids, txids.as_array().expect("txids").iter().collect::<Vec<_>>());

    // The coinbase first: fee 0, and it pays out the subsidy and both fees.
    let coinbase = coinbase_at(&e2e, 102);
    let claimed = output_sum(&coinbase);
    assert_eq!(claimed, 50 * 100_000_000 + 3_500);
    assert_eq!(
        rows[0],
        serde_json::json!([coinbase["txid"], 0, coinbase["weight"], claimed]),
        "the coinbase row"
    );
    assert_eq!(rows[0][0], serde_json::json!(common::coinbase_txid_at(&e2e.node, 102)));

    // The two spends, in whichever order the block holds them.
    for row in &rows[1..] {
        let row = row.as_array().expect("a row is an array");
        assert_eq!(row.len(), 4, "[txid, fee, weight, value]");
        let txid = row[0].as_str().expect("txid");
        let (fee, weight, value) = expected.remove(txid).unwrap_or_else(|| panic!("unexpected {txid}"));
        assert_eq!(
            (row[1].as_u64(), row[2].as_u64(), row[3].as_u64()),
            (Some(fee), Some(weight), Some(value)),
            "{txid}"
        );
    }
    assert!(expected.is_empty(), "both spends are listed");

    // A block that only holds its coinbase.
    let h1 = block_hash_at(&e2e, 1);
    let one = esplora_get_json(&esplora, &format!("/block/{h1}/txs/summary"));
    let coinbase = coinbase_at(&e2e, 1);
    assert_eq!(
        one,
        serde_json::json!([[coinbase["txid"], 0, coinbase["weight"], 50u64 * 100_000_000]])
    );

    // Not a block: 404. Not a hash: 400, as on the other block routes.
    let zero = "0000000000000000000000000000000000000000000000000000000000000000";
    let (status, _, body) = get(&esplora, &format!("/block/{zero}/txs/summary"));
    assert_eq!((status, body.as_str()), (404, "not found"));
    let (status, _, _) = get(&esplora, "/block/nothex/txs/summary");
    assert_eq!(status, 400);

    // Once block 102 leaves the best chain it is 404, though the node still
    // holds it and `/txids` still lists it.
    e2e.node.rpc_ok("invalidateblock", vec![serde_json::json!(h102)]);
    let (status, _, body) = get(&esplora, &format!("/block/{h102}/txs/summary"));
    assert_eq!((status, body.as_str()), (404, "not found"));
    let (status, _, _) = get(&esplora, &format!("/block/{h102}/txids"));
    assert_eq!(status, 200, "the block itself is still stored");
    // Blocks below it are still served.
    let (status, tip, _) = get(&esplora, &format!("/block/{h1}/txs/summary"));
    assert_eq!(status, 200);
    assert_eq!(tip, Some(block_hash_at(&e2e, 101)));

    e2e.node.stop();
}
