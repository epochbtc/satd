//! Electrum scripthash status against `blockchain.scripthash.get_history`.
//!
//! The Electrum protocol defines a scripthash's status as the sha256 of
//! `"tx_hash:height:"` over its history in one order (protocol-basics,
//! "Status"): confirmed transactions by height and position in the block, then
//! mempool transactions by `(-height, tx_hash)` — height 0 before height -1,
//! then the txid as displayed. `get_history` returns the history in that same
//! order. Electrum's synchronizer checks every announced status by hashing the
//! `get_history` response in the order it arrived, and disconnects when the two
//! keep disagreeing. So the status satd announces, on subscribe and in every
//! notification, has to equal that hash.

use bitcoin::hashes::{Hash as _, sha256};
use electrum_client::ElectrumApi;

use super::{E2eNode, electrum_e2e_args, electrum_url_for};
use crate::common::{
    DeterministicWallet, build_signed_p2wpkh_spend_of_coinbase, e2e_test_timeout,
};

/// The status a client derives from a `get_history` response: sha256 over
/// `"tx_hash:height:"` for each row, in the order received. This is what
/// Electrum's `history_status` computes.
fn client_status(history: &[electrum_client::GetHistoryRes]) -> Option<[u8; 32]> {
    if history.is_empty() {
        return None;
    }
    let mut s = String::new();
    for row in history {
        s.push_str(&format!("{}:{}:", row.tx_hash, row.height));
    }
    Some(sha256::Hash::hash(s.as_bytes()).to_byte_array())
}

/// Sign a P2WPKH spend of `prevout` (worth `prev_value_sat`, paying
/// `wallet.address`) to `dest`, less `fee_sat`. Returns the raw hex.
fn sign_p2wpkh_spend(
    wallet: &DeterministicWallet,
    prevout: bitcoin::OutPoint,
    prev_value_sat: u64,
    dest: bitcoin::ScriptBuf,
    fee_sat: u64,
) -> String {
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_ffff),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(prev_value_sat - fee_sat),
            script_pubkey: dest,
        }],
    };
    let sighash = SighashCache::new(&tx)
        .p2wpkh_signature_hash(
            0,
            &wallet.address.script_pubkey(),
            Amount::from_sat(prev_value_sat),
            EcdsaSighashType::All,
        )
        .expect("sighash");
    let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &wallet.sk);
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut witness = Witness::new();
    witness.push(sig_bytes);
    witness.push(wallet.pk.to_bytes());
    tx.input[0].witness = witness;
    hex::encode(bitcoin::consensus::serialize(&tx))
}

fn send(e2e: &E2eNode, raw_hex: &str) -> bitcoin::Txid {
    let resp = e2e
        .node
        .rpc_call_with_params("sendrawtransaction", vec![serde_json::json!(raw_hex)])
        .expect("sendrawtransaction");
    resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("sendrawtransaction failed: {resp}"))
        .parse()
        .expect("txid")
}

/// An address with confirmed history, two mempool txs whose inputs are all
/// confirmed (height 0) and one that spends an unconfirmed parent (height -1).
/// The subscribe reply, the pushed notification and a fresh subscribe must all
/// equal the hash of `get_history` as the client received it, and
/// `get_history` must list the rows in protocol order.
#[test]
fn test_e2e_electrum_status_matches_get_history_with_mempool_rows() {
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum connect");

    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let script = wallet.address.script_pubkey();
    let _ = e2e
        .node
        .rpc_call_with_params(
            "generatetoaddress",
            vec![
                serde_json::json!(101),
                serde_json::json!(wallet.address.to_string()),
            ],
        )
        .expect("generatetoaddress 101");

    // Confirmed-only history: status and history already agree.
    let deadline = std::time::Instant::now() + e2e_test_timeout(20);
    let confirmed = loop {
        let h = client.script_get_history(&script).expect("get_history");
        if h.len() == 101 {
            break h;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "address history never reached 101 confirmed rows (got {})",
            h.len()
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    let initial = client.script_subscribe(&script).expect("subscribe");
    assert_eq!(
        initial.map(|s| *s),
        client_status(&confirmed),
        "subscribe status for a confirmed-only history must equal sha256 over get_history"
    );

    // tx_a and tx_c spend confirmed coinbases (height 0); tx_b spends
    // tx_a's output while tx_a is still unconfirmed (height -1). All three
    // pay the same address back, so every one of them is in its history.
    let fee = 1_000u64;
    let (raw_a, _) = build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &wallet, 1, script.clone(), fee);
    let txid_a = send(&e2e, &raw_a);
    let raw_b = sign_p2wpkh_spend(
        &wallet,
        bitcoin::OutPoint { txid: txid_a, vout: 0 },
        50 * 100_000_000 - fee,
        script.clone(),
        fee,
    );
    let txid_b = send(&e2e, &raw_b);
    let (raw_c, _) = build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &wallet, 2, script.clone(), fee);
    let txid_c = send(&e2e, &raw_c);

    // Wait until the history carries all three mempool rows and the latest
    // pushed status equals the hash of that history.
    let deadline = std::time::Instant::now() + e2e_test_timeout(20);
    let mut last_pushed: Option<[u8; 32]> = None;
    let history = loop {
        client.ping().expect("ping");
        while let Some(s) = client.script_pop(&script).expect("script_pop") {
            last_pushed = Some(*s);
        }
        let h = client.script_get_history(&script).expect("get_history");
        if h.len() == 104 && last_pushed.is_some() && last_pushed == client_status(&h) {
            break h;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "pushed status never matched sha256 over get_history: \
                 pushed {:?}, history-derived {:?}, {} rows, mempool rows {:?}",
                last_pushed.map(hex::encode),
                client_status(&h).map(hex::encode),
                h.len(),
                h.iter()
                    .filter(|r| r.height <= 0)
                    .map(|r| (r.height, r.tx_hash.to_string()))
                    .collect::<Vec<_>>(),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };

    // A fresh subscribe (new connection) answers the same status.
    let fresh = electrum_client::Client::new(&url).expect("electrum connect");
    let status = fresh.script_subscribe(&script).expect("subscribe");
    assert_eq!(
        status.map(|s| *s),
        client_status(&history),
        "subscribe status must equal sha256 over get_history; mempool rows {:?}",
        history[101..].iter().map(|r| (r.height, r.tx_hash.to_string())).collect::<Vec<_>>(),
    );

    // Protocol order: confirmed by ascending height, then height 0 before -1,
    // then display-hex txid order within one height.
    let heights: Vec<i32> = history.iter().map(|r| r.height).collect();
    let expected_confirmed: Vec<i32> = (1..=101).collect();
    assert_eq!(&heights[..101], &expected_confirmed[..], "confirmed rows first, by height");
    assert_eq!(&heights[101..], &[0, 0, -1], "mempool rows: height 0 before -1");
    let mut zero_rows = [txid_a.to_string(), txid_c.to_string()];
    zero_rows.sort();
    assert_eq!(
        [history[101].tx_hash.to_string(), history[102].tx_hash.to_string()],
        zero_rows,
        "height-0 rows ordered by display-hex txid"
    );
    assert_eq!(history[103].tx_hash, txid_b, "the tx spending an unconfirmed parent is last");
    for row in &history[101..] {
        assert_eq!(row.fee, Some(fee), "mempool rows carry their fee");
    }

    e2e.node.stop();
}

/// A subscriber is not sent its own subscribe answer again. A block that
/// leaves the address untouched must push nothing; the next real change
/// pushes exactly once.
#[test]
fn test_e2e_electrum_subscribe_does_not_repush_an_unchanged_status() {
    let mut e2e = E2eNode::boot_with(&electrum_e2e_args());
    let url = electrum_url_for(&e2e);
    let client = electrum_client::Client::new(&url).expect("electrum connect");

    let wallet = DeterministicWallet::from_secret([0x11u8; 32]);
    let script = wallet.address.script_pubkey();
    let mine = |n: u64, to: &bitcoin::Address| {
        let _ = e2e
            .node
            .rpc_call_with_params(
                "generatetoaddress",
                vec![serde_json::json!(n), serde_json::json!(to.to_string())],
            )
            .expect("generatetoaddress");
    };
    mine(101, &wallet.address);
    let deadline = std::time::Instant::now() + e2e_test_timeout(20);
    while client.script_get_history(&script).expect("get_history").len() < 101 {
        assert!(std::time::Instant::now() < deadline, "history never reached 101 rows");
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    let answered = client
        .script_subscribe(&script)
        .expect("subscribe")
        .map(|s| *s)
        .expect("an address with history has a status");

    // A block paying someone else does not change this address's status.
    let other = DeterministicWallet::from_secret([0x22u8; 32]);
    mine(1, &other.address);
    std::thread::sleep(std::time::Duration::from_secs(1));

    // A real change: spend one of the address's coinbases back to it.
    let (raw, _) =
        build_signed_p2wpkh_spend_of_coinbase(&e2e.node, &wallet, 1, script.clone(), 1_000);
    send(&e2e, &raw);

    let mut pushed: Vec<[u8; 32]> = Vec::new();
    let deadline = std::time::Instant::now() + e2e_test_timeout(20);
    loop {
        client.ping().expect("ping");
        while let Some(s) = client.script_pop(&script).expect("script_pop") {
            pushed.push(*s);
        }
        let history = client.script_get_history(&script).expect("get_history");
        if history.len() == 102 && pushed.last().copied() == client_status(&history) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "no push of the changed status: pushed {:?}",
                pushed.iter().map(hex::encode).collect::<Vec<_>>()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    // Anything the unrelated block pushed was queued before the change's push.
    std::thread::sleep(std::time::Duration::from_millis(500));
    client.ping().expect("ping");
    while let Some(s) = client.script_pop(&script).expect("script_pop") {
        pushed.push(*s);
    }
    assert!(
        !pushed.contains(&answered),
        "the unchanged subscribe answer {} was pushed again: {:?}",
        hex::encode(answered),
        pushed.iter().map(hex::encode).collect::<Vec<_>>()
    );
    assert_eq!(pushed.len(), 1, "exactly one push for one change: {pushed:?}");

    e2e.node.stop();
}
