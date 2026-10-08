//! Esplora paging and transaction JSON against upstream Esplora's rules.
//!
//! - `/address/:addr/txs?after_txid=<txid>` (and the scripthash form) continues
//!   the history after that transaction, as mempool.space's electrs does. An
//!   `after_txid` that is in neither the mempool nor the confirmed history of
//!   the script is 422 `after_txid not found`.
//! - `/block/:hash/txs/:start_index` answers 404 `start index out of range` at
//!   or past the end of the block, and 400 when `start_index` is not a
//!   multiple of 25.
//! - A `vin` entry carries `witness` only when the input has one.

use std::str::FromStr;

use super::{E2eNode, EsploraClient, esplora_e2e_args, esplora_for, esplora_get_json,
    esplora_scripthash_of_spk};
use crate::common::{self, DeterministicWallet, build_signed_p2wpkh_spend_of_coinbase};

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

/// GET `path`, returning the status and the body text.
fn get_text(esplora: &EsploraClient, path: &str) -> (u16, String) {
    let resp = esplora.get(path);
    let status = resp.status().as_u16();
    (status, resp.text().expect("body utf8"))
}

fn txids(page: &serde_json::Value) -> Vec<String> {
    page.as_array()
        .unwrap_or_else(|| panic!("expected a JSON array, got {page}"))
        .iter()
        .map(|t| t["txid"].as_str().expect("txid").to_string())
        .collect()
}

fn heights(page: &serde_json::Value) -> Vec<u64> {
    page.as_array()
        .unwrap_or_else(|| panic!("expected a JSON array, got {page}"))
        .iter()
        .map(|t| t["status"]["block_height"].as_u64().expect("confirmed"))
        .collect()
}

/// `?after_txid=` on `/txs` pages the history: a confirmed cursor continues
/// with the next 25 confirmed transactions (the same page as the path form
/// `/txs/chain/:last_seen_txid`), a mempool cursor with the mempool
/// transactions after it. A cursor in neither list is 422, a malformed one 400.
#[test]
fn test_e2e_esplora_txs_after_txid_continues_the_history() {
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    // `a` mines 30 coinbases (heights 1..=30): 25 on the first page, 5 after.
    let a = DeterministicWallet::from_secret([0x21u8; 32]);
    // `w` mines the next 101, so its coinbases at 31 and 32 are mature.
    let w = DeterministicWallet::from_secret([0x22u8; 32]);
    // `b` only ever receives the two unconfirmed spends of `w`'s coinbases.
    let b = DeterministicWallet::from_secret([0x23u8; 32]);
    mine(&e2e, 30, &a);
    mine(&e2e, 101, &w);

    let a_str = a.address.to_string();
    let a_sh = esplora_scripthash_of_spk(&a.address.script_pubkey());

    let page1 = esplora_get_json(&esplora, &format!("/address/{a_str}/txs"));
    assert_eq!(heights(&page1), (6..=30).rev().collect::<Vec<u64>>());
    let cursor = txids(&page1)[24].clone();

    let page2 = esplora_get_json(&esplora, &format!("/address/{a_str}/txs?after_txid={cursor}"));
    assert_eq!(
        heights(&page2),
        vec![5, 4, 3, 2, 1],
        "after_txid must continue after the cursor, not repeat the first page"
    );
    // The path form answers the same page, and so does the scripthash family.
    let chain_page2 = esplora_get_json(&esplora, &format!("/address/{a_str}/txs/chain/{cursor}"));
    assert_eq!(txids(&page2), txids(&chain_page2));
    let sh_page2 = esplora_get_json(&esplora, &format!("/scripthash/{a_sh}/txs?after_txid={cursor}"));
    assert_eq!(txids(&page2), txids(&sh_page2));

    // After the oldest transaction there is nothing more.
    let last = txids(&page2)[4].clone();
    let page3 = esplora_get_json(&esplora, &format!("/address/{a_str}/txs?after_txid={last}"));
    assert_eq!(txids(&page3), Vec::<String>::new());

    // An empty `after_txid` is the first page.
    let empty = esplora_get_json(&esplora, &format!("/address/{a_str}/txs?after_txid="));
    assert_eq!(txids(&empty), txids(&page1));

    // A real transaction that is not in `a`'s history, and one that does not
    // exist at all: 422, as mempool.space answers.
    let not_a_tx = common::coinbase_txid_at(&e2e.node, 31);
    let zero = "0000000000000000000000000000000000000000000000000000000000000000";
    for unknown in [not_a_tx.as_str(), zero] {
        let (status, body) =
            get_text(&esplora, &format!("/address/{a_str}/txs?after_txid={unknown}"));
        assert_eq!((status, body.as_str()), (422, "after_txid not found"));
        let (status, body) =
            get_text(&esplora, &format!("/scripthash/{a_sh}/txs?after_txid={unknown}"));
        assert_eq!((status, body.as_str()), (422, "after_txid not found"));
    }
    let (status, _) = get_text(&esplora, &format!("/address/{a_str}/txs?after_txid=nothex"));
    assert_eq!(status, 400, "a malformed after_txid is a bad request");

    // Mempool cursor: `b` has two unconfirmed transactions and no confirmed
    // history. After the first comes the second; after the second, nothing.
    for height in [31u64, 32] {
        let (raw, _) =
            build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &w, height, b.address.script_pubkey(), 1000);
        let r = esplora.post_tx(&raw);
        assert_eq!(r.status(), 200, "broadcast: {}", r.text().unwrap_or_default());
    }
    let b_str = b.address.to_string();
    let b_path = format!("/address/{b_str}/txs");
    let b_page1 = common::poll_until_json(
        || esplora_get_json(&esplora, &b_path),
        |v| v.as_array().is_some_and(|a| a.len() == 2),
        10,
    );
    assert!(
        b_page1
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["status"]["confirmed"] == false),
        "both of b's transactions are unconfirmed: {b_page1}"
    );
    let b_txids = txids(&b_page1);
    let after_first =
        esplora_get_json(&esplora, &format!("{b_path}?after_txid={}", b_txids[0]));
    assert_eq!(txids(&after_first), vec![b_txids[1].clone()]);
    let after_second =
        esplora_get_json(&esplora, &format!("{b_path}?after_txid={}", b_txids[1]));
    assert_eq!(txids(&after_second), Vec::<String>::new());

    e2e.node.stop();
}

/// `/block/:hash/txs/:start_index`: a start at or past the end of the block is
/// 404 `start index out of range`, and a start that is not a multiple of 25 is
/// 400, while an aligned start inside the block serves the page.
#[test]
fn test_e2e_esplora_block_txs_start_index_rules() {
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let w = DeterministicWallet::from_secret([0x24u8; 32]);
    mine(&e2e, 101, &w);
    // Block 102 holds a coinbase and one spend.
    let dest = bitcoin::Address::from_str("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202")
        .expect("address")
        .assume_checked()
        .script_pubkey();
    let (raw, spend_txid) = build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &w, 1, dest, 1000);
    assert_eq!(esplora.post_tx(&raw).status(), 200);
    mine(&e2e, 1, &w);
    let h102 = block_hash_at(&e2e, 102);

    for path in [format!("/block/{h102}/txs"), format!("/block/{h102}/txs/0")] {
        let page = esplora_get_json(&esplora, &path);
        assert_eq!(txids(&page).len(), 2, "{path}");
        assert_eq!(txids(&page)[1], spend_txid, "{path}");
    }

    assert_eq!(
        get_text(&esplora, &format!("/block/{h102}/txs/1")),
        (400, "start index must be a multiple of 25".to_string()),
        "an unaligned start inside the block"
    );
    assert_eq!(
        get_text(&esplora, &format!("/block/{h102}/txs/25")),
        (404, "start index out of range".to_string()),
        "an aligned start past the end"
    );
    assert_eq!(
        get_text(&esplora, &format!("/block/{h102}/txs/{}", usize::MAX)),
        (404, "start index out of range".to_string()),
        "the largest start index"
    );
    // A start past the end is out of range before it is unaligned.
    let h1 = block_hash_at(&e2e, 1);
    assert_eq!(
        get_text(&esplora, &format!("/block/{h1}/txs/1")),
        (404, "start index out of range".to_string()),
        "start 1 of a one-transaction block"
    );

    e2e.node.stop();
}

/// A `vin` entry has no `witness` key when the input has no witness (the
/// genesis coinbase here), and lists the stack when it has one.
#[test]
fn test_e2e_esplora_vin_witness_left_out_when_empty() {
    let mut e2e = E2eNode::boot_with(&esplora_e2e_args());
    let esplora = esplora_for(&e2e);
    let w = DeterministicWallet::from_secret([0x25u8; 32]);
    mine(&e2e, 101, &w);

    let genesis = block_hash_at(&e2e, 0);
    let page = esplora_get_json(&esplora, &format!("/block/{genesis}/txs"));
    let vin0 = &page[0]["vin"][0];
    assert_eq!(vin0["is_coinbase"], true, "{page}");
    assert!(
        vin0.get("witness").is_none(),
        "an input without a witness must not carry a `witness` key: {vin0}"
    );

    let (raw, spend_txid) =
        build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &w, 1, w.address.script_pubkey(), 1000);
    assert_eq!(esplora.post_tx(&raw).status(), 200);
    let tx = esplora_get_json(&esplora, &format!("/tx/{spend_txid}"));
    let witness = tx["vin"][0]["witness"]
        .as_array()
        .unwrap_or_else(|| panic!("a P2WPKH input lists its witness: {tx}"));
    assert_eq!(witness.len(), 2, "signature and public key: {tx}");

    e2e.node.stop();
}
