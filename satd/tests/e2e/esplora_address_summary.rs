//! Esplora `/address/:addr/txs/summary[/:last_seen_txid]` and the scripthash
//! form: the `/txs/chain` pages as compact `{txid, value, height, time,
//! tx_position}` rows, as rbitcoin's Esplora answers them.
//!
//! The chain: `a` mines blocks 1..=30 and `w` blocks 31..=131, so `a`'s
//! coinbases are mature. Block 132 holds three transactions that touch `a`:
//! one spends a coinbase of its own away, one spends two of them and pays
//! half back, one pays it a coinbase of `w`'s. That is 33 rows, two pages.
//! Every expected figure is worked out here from the signed transactions and
//! the blocks, not read back from the node's address routes.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use super::{E2eNode, EsploraClient, esplora_e2e_args, esplora_for, esplora_get_json,
    esplora_scripthash_of_spk};
use crate::common::{
    self, DeterministicWallet, build_signed_p2wpkh_spend_of_coinbase,
    build_signed_p2wpkh_spend_of_coinbases,
};

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

fn block_at(e2e: &E2eNode, height: u64, verbosity: u8) -> serde_json::Value {
    let hash = e2e.node.rpc_ok("getblockhash", vec![serde_json::json!(height)]);
    e2e.node.rpc_ok("getblock", vec![hash, serde_json::json!(verbosity)])
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

/// Page `base` (a `/txs/summary` or `/txs/chain` route, with `query` on every
/// request) to its end, each page after the last row of the one before.
/// Returns the pages; the walk ends on the first empty one, which is not
/// kept.
fn walk(esplora: &EsploraClient, base: &str, query: &str) -> Vec<Vec<serde_json::Value>> {
    let mut pages = Vec::new();
    let mut path = format!("{base}{query}");
    loop {
        let page = esplora_get_json(esplora, &path);
        let page = page.as_array().unwrap_or_else(|| panic!("{path}: not an array")).clone();
        assert!(page.len() <= 25, "{path}: {} rows", page.len());
        let Some(last) = page.last() else { break };
        path = format!("{base}/{}{query}", last["txid"].as_str().expect("txid"));
        pages.push(page);
        assert!(pages.len() <= 10, "the walk does not end");
    }
    pages
}

#[test]
fn test_e2e_esplora_address_txs_summary() {
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let a = DeterministicWallet::from_secret([0x51u8; 32]);
    let w = DeterministicWallet::from_secret([0x52u8; 32]);
    let dest = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("address")
        .assume_checked()
        .script_pubkey();
    let a_spk = a.address.script_pubkey();
    let a_spk_hex = hex::encode(a_spk.as_bytes());
    mine(&e2e, 30, &a);
    mine(&e2e, 101, &w);
    let h131 = block_at(&e2e, 131, 1)["hash"].as_str().expect("hash").to_string();

    // What `a` holds: the outputs of its 30 coinbases that pay its script.
    // `expected` is txid -> (value, height); each coinbase is a receive.
    let mut coins: HashMap<(String, u32), u64> = HashMap::new();
    let mut expected: HashMap<String, (i64, u64)> = HashMap::new();
    for height in 1..=30u64 {
        let coinbase = block_at(&e2e, height, 2)["tx"][0].clone();
        let txid = coinbase["txid"].as_str().expect("txid").to_string();
        let mut received = 0u64;
        for out in coinbase["vout"].as_array().expect("vout") {
            if out["scriptPubKey"]["hex"] == a_spk_hex.as_str() {
                let n = out["n"].as_u64().expect("n") as u32;
                coins.insert((txid.clone(), n), sats(&out["value"]));
                received += sats(&out["value"]);
            }
        }
        assert_eq!(received, 50 * 100_000_000, "block {height} pays `a` the subsidy");
        expected.insert(txid, (received as i64, height));
    }

    // Block 132: a spend, a spend that pays half back, and a receive.
    let (away, _) = build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &a, 1, dest.clone(), 1_000);
    let (half_back, _) = build_signed_p2wpkh_spend_of_coinbases(
        &e2e.node,
        &[(2, &a), (3, &a)],
        &[a_spk.clone(), dest.clone()],
        3_000,
    );
    let (receive, _) = build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &w, 31, a_spk.clone(), 500);
    // The script's net in a transaction: what its outputs pay the script,
    // less the coins of the script its inputs spend.
    let net = |raw: &str| -> (String, i64) {
        let tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize_hex(raw).expect("the signed tx decodes");
        let paid: u64 = tx
            .output
            .iter()
            .filter(|o| o.script_pubkey == a_spk)
            .map(|o| o.value.to_sat())
            .sum();
        let spent: u64 = tx
            .input
            .iter()
            .filter_map(|i| coins.get(&(i.previous_output.txid.to_string(), i.previous_output.vout)))
            .sum();
        (tx.compute_txid().to_string(), paid as i64 - spent as i64)
    };
    let mut block_132 = Vec::new();
    for raw in [&away, &half_back, &receive] {
        let (txid, value) = net(raw);
        expected.insert(txid.clone(), (value, 132));
        block_132.push((txid, value));
        let r = esplora.post_tx(raw);
        assert_eq!(r.status(), 200, "broadcast: {}", r.text().unwrap_or_default());
    }
    // A spend is negative, a receive positive, and the transaction that does
    // both shows the difference.
    assert_eq!(
        block_132.iter().map(|(_, v)| *v).collect::<Vec<_>>(),
        vec![-5_000_000_000, 4_999_998_500 - 10_000_000_000, 4_999_999_500]
    );
    mine(&e2e, 1, &w);
    let h132 = block_at(&e2e, 132, 1)["hash"].as_str().expect("hash").to_string();

    // The whole row each transaction must show: the block's time and the
    // transaction's index in it come from `getblock`.
    let mut blocks: HashMap<u64, serde_json::Value> = HashMap::new();
    let mut expected_row = |txid: &str| -> serde_json::Value {
        let (value, height) = expected[txid];
        let block = blocks.entry(height).or_insert_with(|| block_at(&e2e, height, 1));
        let position = block["tx"]
            .as_array()
            .expect("tx")
            .iter()
            .position(|t| t == txid)
            .unwrap_or_else(|| panic!("{txid} is in block {height}"));
        serde_json::json!({
            "txid": txid,
            "value": value,
            "height": height,
            "time": block["time"],
            "tx_position": position,
        })
    };

    let base = format!("/address/{}/txs/summary", a.address);
    let pages = walk(&esplora, &base, "");
    assert_eq!(pages.iter().map(Vec::len).collect::<Vec<_>>(), vec![25, 8]);
    let rows: Vec<serde_json::Value> = pages.concat();
    // Every row exactly once, and each exactly as worked out above.
    let listed: HashSet<&str> = rows.iter().map(|r| r["txid"].as_str().expect("txid")).collect();
    assert_eq!(listed.len(), 33, "no row twice");
    assert_eq!(listed, expected.keys().map(String::as_str).collect::<HashSet<_>>());
    for row in &rows {
        assert_eq!(*row, expected_row(row["txid"].as_str().unwrap()));
        assert_eq!(row.as_object().unwrap().len(), 5, "{row}");
    }
    // Newest first, and the block-132 transactions sit at positions 1..=3.
    let heights: Vec<u64> = rows.iter().map(|r| r["height"].as_u64().unwrap()).collect();
    assert!(heights.windows(2).all(|p| p[0] >= p[1]), "{heights:?}");
    assert_eq!(&heights[..4], &[132, 132, 132, 30]);
    let mut positions: Vec<u64> =
        rows[..3].iter().map(|r| r["tx_position"].as_u64().unwrap()).collect();
    positions.sort_unstable();
    assert_eq!(positions, vec![1, 2, 3]);

    // The values add up to the confirmed balance the stats report.
    let stats = esplora_get_json(&esplora, &format!("/address/{}", a.address));
    let balance = stats["chain_stats"]["funded_txo_sum"].as_i64().unwrap()
        - stats["chain_stats"]["spent_txo_sum"].as_i64().unwrap();
    assert_eq!(rows.iter().map(|r| r["value"].as_i64().unwrap()).sum::<i64>(), balance);
    assert_eq!(balance, expected.values().map(|(v, _)| *v).sum::<i64>());

    // The same transactions in the same order as `/txs/chain`, page by page.
    let chain = walk(&esplora, &format!("/address/{}/txs/chain", a.address), "");
    let txids = |pages: &[Vec<serde_json::Value>]| -> Vec<Vec<String>> {
        pages
            .iter()
            .map(|p| p.iter().map(|r| r["txid"].as_str().unwrap().to_string()).collect())
            .collect()
    };
    assert_eq!(txids(&pages), txids(&chain));

    // The scripthash form answers the same pages, and `?after_txid=` the
    // same page as the path cursor.
    let sh_base = format!("/scripthash/{}/txs/summary", esplora_scripthash_of_spk(&a_spk));
    assert_eq!(walk(&esplora, &sh_base, ""), pages);
    let cursor = pages[0][24]["txid"].as_str().unwrap();
    for path in [format!("{base}?after_txid={cursor}"), format!("{sh_base}?after_txid={cursor}")] {
        assert_eq!(esplora_get_json(&esplora, &path), serde_json::json!(pages[1]), "{path}");
    }
    // After the oldest row: an empty page, the end of the history.
    let oldest = pages[1][7]["txid"].as_str().unwrap();
    let (status, tip, body) = get(&esplora, &format!("{base}/{oldest}"));
    assert_eq!((status, tip.as_deref(), body.as_str()), (200, Some(h132.as_str()), "[]"));

    // As of block 131: the 30 coinbases, none of block 132, stamped 131.
    let asof = format!("?asof={h131}");
    let (status, tip, _) = get(&esplora, &format!("{base}{asof}"));
    assert_eq!((status, tip.as_deref()), (200, Some(h131.as_str())));
    let then = walk(&esplora, &base, &asof);
    assert_eq!(then.iter().map(Vec::len).collect::<Vec<_>>(), vec![25, 5]);
    let then: Vec<serde_json::Value> = then.concat();
    assert_eq!(then, rows[3..].to_vec(), "the rows below block 132, unchanged");
    assert!(then.iter().all(|r| r["value"] == 5_000_000_000i64));
    assert_eq!(walk(&esplora, &sh_base, &asof).concat(), then);
    // A block-132 cursor is not in the history as of 131.
    let late = rows[0]["txid"].as_str().unwrap();
    let (status, _, body) = get(&esplora, &format!("{base}/{late}{asof}"));
    assert_eq!((status, body.as_str()), (422, "after_txid not found"));

    // An unconfirmed spend is not listed: confirmed rows only.
    let (pending, pending_txid) =
        build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &a, 4, dest.clone(), 1_000);
    assert_eq!(esplora.post_tx(&pending).status(), 200);
    let mempool_path = format!("/address/{}/txs/mempool", a.address);
    common::poll_until_json(
        || esplora_get_json(&esplora, &mempool_path),
        |v| v.as_array().is_some_and(|l| l.len() == 1 && l[0]["txid"] == pending_txid.as_str()),
        10,
    );
    assert_eq!(walk(&esplora, &base, ""), pages);
    // It is no cursor either, like any transaction outside the confirmed
    // history: 422, where an empty page would read as the end.
    let not_of_a = common::coinbase_txid_at(&e2e.node, 40);
    let zero = "00".repeat(32);
    for unknown in [pending_txid.as_str(), not_of_a.as_str(), zero.as_str()] {
        for path in [
            format!("{base}/{unknown}"),
            format!("{sh_base}/{unknown}"),
            format!("{base}?after_txid={unknown}"),
        ] {
            let (status, _, body) = get(&esplora, &path);
            assert_eq!((status, body.as_str()), (422, "after_txid not found"), "{path}");
        }
    }

    // Malformed input is 400, as on the other address routes; an unknown
    // `asof` 404.
    for path in [
        format!("{base}/nothex"),
        format!("{base}?after_txid=nothex"),
        "/address/notanaddress/txs/summary".to_string(),
        "/scripthash/abcd/txs/summary".to_string(),
        format!("/scripthash/nothex/txs/summary/{cursor}"),
    ] {
        assert_eq!(get(&esplora, &path).0, 400, "{path}");
    }
    assert_eq!(get(&esplora, &format!("{base}?asof={zero}")).0, 404);

    e2e.node.stop();
}
