//! Mempool-facing RPCs checked against Bitcoin Core: `getmempoolinfo`
//! (`MempoolInfoToJSON`, src/rpc/mempool.cpp), `gettxout` with
//! `include_mempool` (src/rpc/blockchain.cpp) and the checks
//! `sendrawtransaction` makes before it submits (`BroadcastTransaction`,
//! src/node/transaction.cpp).

use super::*;
use crate::mempool::pool::{MempoolConfig, TxSource};
use crate::mining::template::tests::make_funded_template_env_with;
use crate::rpc::blockchain::get_tx_out_view;
use crate::storage::coinview::Coin;
use crate::validation::script::NoopVerifier;
use bitcoin::Txid;

const COIN_VALUE: u64 = 100_000;

fn prev(tag: u8) -> OutPoint {
    OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: 0 }
}

fn p2wpkh(tag: u8) -> bitcoin::ScriptBuf {
    let mut spk = vec![0x00, 0x14];
    spk.extend_from_slice(&[tag; 20]);
    bitcoin::ScriptBuf::from_bytes(spk)
}

fn coin(amount: u64) -> Coin {
    Coin {
        amount,
        script_pubkey: p2wpkh(0x11),
        height: 1,
        coinbase: false,
        txseq: node_index::TXSEQ_UNKNOWN,
    }
}

/// Spend `prev` to one P2WPKH output per `(value, tag)`.
fn spend(prev: OutPoint, outs: &[(u64, u8)]) -> Transaction {
    Transaction {
        version: Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outs
            .iter()
            .map(|&(value, tag)| TxOut { value: Amount::from_sat(value), script_pubkey: p2wpkh(tag) })
            .collect(),
    }
}

/// A regtest chain holding `coins`, and an empty pool with no relay floor.
fn env(coins: &[(OutPoint, Coin)]) -> (ChainState, Mempool, std::path::PathBuf) {
    let (cs, mp, dir) = make_funded_template_env_with(coins, Box::new(NoopVerifier));
    mp.reload_policy(MempoolConfig { max_size_bytes: 1_000_000, min_fee_rate: 0, ..Default::default() });
    (cs, mp, dir)
}

fn admit(mp: &Mempool, cs: &ChainState, tx: Transaction) -> Txid {
    mp.accept_transaction(tx, cs, &NoopVerifier, TxSource::Rpc, false).expect("admitted")
}

#[test]
fn getmempoolinfo_loaded_waits_for_the_load() {
    // Core's `loaded` is `GetLoadTried()`: false until the startup load of
    // mempool.dat has finished.
    let mp = Mempool::new(1_000_000, 0);
    assert_eq!(get_mempool_info(&mp)["loaded"], false);
    mp.set_load_tried(true);
    assert_eq!(get_mempool_info(&mp)["loaded"], true);
}

#[test]
fn getmempoolinfo_bytes_is_vsize_and_total_fee_is_base_fees() {
    let (cs, mp, dir) = env(&[(prev(1), coin(COIN_VALUE))]);
    let mut tx = spend(prev(1), &[(COIN_VALUE - 1_234, 2)]);
    tx.input[0].witness = Witness::from_slice(&[[0x01]]);
    let weight = tx.weight().to_wu();
    assert_ne!(weight % 4, 0, "the fixture's weight must not be a multiple of four");
    let txid = admit(&mp, &cs, tx);
    mp.prioritise_transaction(&txid, 10_000).expect("prioritised");

    let info = get_mempool_info(&mp);
    // `GetTotalTxSize`: virtual sizes, rounded up.
    assert_eq!(info["bytes"].as_u64(), Some(weight.div_ceil(4)), "{info}");
    // `GetTotalFee`: base fees, "ignoring modified fees through
    // prioritisetransaction".
    assert_eq!(info["total_fee"].to_string(), "0.00001234", "{info}");
    assert!(info["usage"].as_u64().unwrap() > 0, "{info}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gettxout_hides_an_output_spent_in_the_mempool() {
    let (cs, mp, dir) = env(&[(prev(1), coin(COIN_VALUE))]);
    let txid = prev(1).txid.to_string();
    assert!(get_tx_out_view(&cs, Some(&mp), &txid, 0).unwrap().is_object());

    admit(&mp, &cs, spend(prev(1), &[(COIN_VALUE - 1_000, 2)]));
    // Core: "an unspent output that is spent in the mempool won't appear".
    assert!(get_tx_out_view(&cs, Some(&mp), &txid, 0).unwrap().is_null());
    // `include_mempool=false` reads the UTXO set alone.
    let chain_only = get_tx_out_view(&cs, None, &txid, 0).unwrap();
    assert_eq!(chain_only["value"].to_string(), "0.00100000", "{chain_only}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gettxout_reports_a_mempool_output_with_no_confirmations() {
    let (cs, mp, dir) = env(&[(prev(1), coin(COIN_VALUE))]);
    let tx = spend(prev(1), &[(COIN_VALUE - 1_000, 2)]);
    let spk_hex = hex::encode(tx.output[0].script_pubkey.as_bytes());
    let txid = admit(&mp, &cs, tx).to_string();

    let out = get_tx_out_view(&cs, Some(&mp), &txid, 0).unwrap();
    assert_eq!(out["confirmations"], 0, "{out}");
    assert_eq!(out["value"].to_string(), "0.00099000", "{out}");
    assert_eq!(out["scriptPubKey"]["hex"], spk_hex.as_str(), "{out}");
    assert_eq!(out["coinbase"], false, "{out}");
    assert_eq!(out["bestblock"], cs.tip_hash().to_string(), "{out}");
    // An output the pool transaction does not have.
    assert!(get_tx_out_view(&cs, Some(&mp), &txid, 1).unwrap().is_null());
    // Without the mempool there is no such coin yet.
    assert!(get_tx_out_view(&cs, None, &txid, 0).unwrap().is_null());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gettxout_does_not_see_a_quarantined_transaction() {
    // A held transaction is invisible on every standard surface, as on a
    // Core node whose relay policy refused it: the coin it spends is still
    // unspent, and its outputs do not exist.
    let (cs, mp, dir) = env(&[(prev(1), coin(COIN_VALUE))]);
    let rs = satd_policy::parse_ruleset("version 1\nquarantine hold on relay when tx.version == 2")
        .expect("ruleset");
    mp.set_policy(std::sync::Arc::new(rs));
    let tx = spend(prev(1), &[(COIN_VALUE - 1_000, 2)]);
    let txid = mp
        .accept_transaction(tx, &cs, &NoopVerifier, TxSource::Rpc, true)
        .expect("held")
        .to_string();
    assert!(mp.get(&txid.parse().unwrap()).is_some(), "the transaction is held");

    assert!(get_tx_out_view(&cs, Some(&mp), &prev(1).txid.to_string(), 0).unwrap().is_object());
    assert!(get_tx_out_view(&cs, Some(&mp), &txid, 0).unwrap().is_null());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gettxout_trusts_the_pool_only_while_the_coins_it_spends_remain() {
    // A block is committed before `remove_for_block` updates the pool, so
    // for a moment the pool still holds what the tip has confirmed. The
    // reply must describe the tip it names.
    let (cs, mp, dir) = env(&[(prev(1), coin(COIN_VALUE))]);
    let tx = spend(prev(1), &[(COIN_VALUE - 1_000, 2)]);
    let out = OutPoint { txid: tx.compute_txid(), vout: 0 };
    let txid = admit(&mp, &cs, tx.clone()).to_string();
    assert_eq!(get_tx_out_view(&cs, Some(&mp), &txid, 0).unwrap()["confirmations"], 0);

    // The tip confirms the transaction; the pool has not caught up.
    let mut batch = crate::storage::StoreBatch::default();
    batch.coin_removes.push((prev(1), COIN_VALUE, 1));
    batch.coin_puts.push((out, Coin { amount: COIN_VALUE - 1_000, height: 0, ..coin(0) }));
    cs.store_ref().write_batch(batch).unwrap();
    assert!(mp.get(&tx.compute_txid()).is_some(), "the pool still holds it");
    let confirmed = get_tx_out_view(&cs, Some(&mp), &txid, 0).unwrap();
    assert_eq!(confirmed["confirmations"], 1, "the chain answers: {confirmed}");

    // The tip also spends that output.
    let mut batch = crate::storage::StoreBatch::default();
    batch.coin_removes.push((out, COIN_VALUE - 1_000, 0));
    cs.store_ref().write_batch(batch).unwrap();
    assert!(get_tx_out_view(&cs, Some(&mp), &txid, 0).unwrap().is_null());
    let _ = std::fs::remove_dir_all(&dir);
}

/// `gettxout` writes the scriptPubKey as Core's `ScriptToUniv` with the
/// address included: `asm`, `desc`, `hex`, `address`, `type`, from the pool
/// and from the chain alike. Perturbation: go back to `asm`/`hex` only in
/// either branch and that half fails.
#[test]
fn gettxout_names_the_script_type_address_and_descriptor() {
    let (cs, mp, dir) = env(&[(prev(1), coin(COIN_VALUE))]);
    let tx = spend(prev(1), &[(COIN_VALUE - 1_000, 2)]);
    let txid = admit(&mp, &cs, tx.clone()).to_string();
    let addr = bitcoin::Address::from_script(&p2wpkh(2), bitcoin::Network::Regtest).unwrap().to_string();
    let check = |spk: &Value, from: &str| {
        assert_eq!(spk["type"], "witness_v0_keyhash", "{from}: {spk}");
        assert_eq!(spk["address"], addr.as_str(), "{from}: {spk}");
        let desc = spk["desc"].as_str().unwrap_or_else(|| panic!("{from}: no desc in {spk}"));
        assert!(desc.starts_with(&format!("addr({addr})#")), "{from}: {desc}");
        assert_eq!(spk["hex"], hex::encode(p2wpkh(2).as_bytes()), "{from}");
        assert!(spk["asm"].is_string(), "{from}");
    };
    check(&get_tx_out_view(&cs, Some(&mp), &txid, 0).unwrap()["scriptPubKey"], "pool");
    let funding = get_tx_out_view(&cs, None, &prev(1).txid.to_string(), 0).unwrap();
    assert_eq!(funding["scriptPubKey"]["type"], "witness_v0_keyhash", "chain: {funding}");
    assert_eq!(
        funding["scriptPubKey"]["address"],
        bitcoin::Address::from_script(&p2wpkh(0x11), bitcoin::Network::Regtest).unwrap().to_string(),
        "chain: {funding}"
    );
    assert!(funding["scriptPubKey"]["desc"].as_str().is_some_and(|d| d.starts_with("addr(")), "chain: {funding}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `script_type` names every script as Core's `Solver` does. Before, bare
/// P2PK, bare multisig, anchors and witness v2+ were all "nonstandard", and
/// any OP_RETURN script was "nulldata".
#[test]
fn script_type_follows_core_solver() {
    let k33 = format!("02{}", "11".repeat(32));
    let k65 = format!("04{}", "22".repeat(64));
    let cases: &[(String, &str)] = &[
        (format!("21{k33}ac"), "pubkey"),
        (format!("41{k65}ac"), "pubkey"),
        // A 33-byte push whose prefix calls for 65 bytes fails `ValidSize`.
        (format!("2104{}ac", "11".repeat(32)), "nonstandard"),
        (format!("5121{k33}41{k65}52ae"), "multisig"),
        (format!("5221{k33}51ae"), "nonstandard"), // m > n
        ("51024e73".to_string(), "anchor"),
        (format!("5220{}", "33".repeat(32)), "witness_unknown"),
        (format!("5102{}", "4e74"), "witness_unknown"),
        (format!("0019{}", "44".repeat(25)), "nonstandard"), // v0, wrong length
        ("6a0548656c6c6f".to_string(), "nulldata"),
        ("6a".to_string(), "nulldata"),
        ("6aac".to_string(), "nonstandard"), // not push-only after OP_RETURN
        (format!("76a914{}88ac", "55".repeat(20)), "pubkeyhash"),
        (format!("a914{}87", "66".repeat(20)), "scripthash"),
        (format!("0014{}", "77".repeat(20)), "witness_v0_keyhash"),
        (format!("0020{}", "88".repeat(32)), "witness_v0_scripthash"),
        (format!("5120{}", "99".repeat(32)), "witness_v1_taproot"),
        ("ac".to_string(), "nonstandard"),
    ];
    for (hex_spk, want) in cases {
        let spk = bitcoin::ScriptBuf::from_bytes(hex::decode(hex_spk).unwrap());
        assert_eq!(script_type(&spk), *want, "{hex_spk}");
    }
}

#[test]
fn a_negative_amount_formats_as_core_does() {
    use crate::rpc::amounts::{AmountUnit, format_signed_amount};
    assert_eq!(format_signed_amount(-1_000, AmountUnit::Btc).to_string(), "-0.00001000");
    assert_eq!(format_signed_amount(-250_000_000, AmountUnit::Btc).to_string(), "-2.50000000");
    assert_eq!(format_signed_amount(1_000, AmountUnit::Btc).to_string(), "0.00001000");
    assert_eq!(format_signed_amount(-1_000, AmountUnit::Sats).to_string(), "-1000");
}

#[test]
fn preflight_finds_a_confirmed_transaction_in_the_utxo_set() {
    // Core answers -27 when one of the transaction's outputs is a coin,
    // which needs no txindex.
    let tx = spend(prev(1), &[(50_000, 2), (40_000, 3)]);
    let confirmed_out = OutPoint { txid: tx.compute_txid(), vout: 1 };
    let (cs, mp, dir) = env(&[(confirmed_out, coin(40_000))]);
    assert_eq!(
        send_raw_transaction_preflight(&cs, &mp, &tx, 10_000_000),
        Err((-27, "Transaction outputs already in utxo set".to_string()))
    );

    // A transaction none of whose outputs is a coin goes on.
    let other = spend(prev(4), &[(50_000, 2)]);
    assert_eq!(send_raw_transaction_preflight(&cs, &mp, &other, 0), Ok(()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_caps_the_fee_rate() {
    let (cs, mp, dir) = env(&[(prev(1), coin(COIN_VALUE))]);
    // 50,000 sat on 82 vB: about 610,000 sat/kvB.
    let tx = spend(prev(1), &[(COIN_VALUE - 50_000, 2)]);
    assert_eq!(
        send_raw_transaction_preflight(&cs, &mp, &tx, 100_000),
        Err((-25, "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)".to_string()))
    );
    assert_eq!(send_raw_transaction_preflight(&cs, &mp, &tx, 1_000_000), Ok(()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_caps_the_fee_of_a_transaction_only_a_policy_admits() {
    // Two dust outputs make the transaction non-standard, so the dry run
    // refuses it; the `allow` rule forgives that on submission. The cap
    // must hold on the transaction the submission would admit.
    let (cs, mp, dir) = env(&[(prev(1), coin(COIN_VALUE))]);
    let rs = satd_policy::parse_ruleset("version 1\nallow mine when tx.source == rpc")
        .expect("ruleset");
    mp.set_policy(std::sync::Arc::new(rs));
    // 50,000 sat in fees.
    let tx = spend(prev(1), &[(1, 2), (1, 3), (COIN_VALUE - 50_002, 4)]);
    assert!(
        mp.test_accept(&tx, &cs, &NoopVerifier).is_err(),
        "the fixture must be one the dry run refuses"
    );

    assert_eq!(
        send_raw_transaction_preflight(&cs, &mp, &tx, 100_000),
        Err((-25, "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)".to_string()))
    );
    // With no cap it goes on, and the submission does admit it.
    assert_eq!(send_raw_transaction_preflight(&cs, &mp, &tx, 0), Ok(()));
    admit(&mp, &cs, tx);
    let _ = std::fs::remove_dir_all(&dir);
}
