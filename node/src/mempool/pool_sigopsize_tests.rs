//! `-bytespersigop`: a transaction is priced at Core's sigop-adjusted size,
//! `max(weight, sigop cost × 20) / 4` (`GetSigOpsAdjustedWeight`,
//! `GetVirtualTransactionSize`). satd priced every transaction at its
//! weight alone, so one dense in signature checks paid up to about five
//! times less than in Core for the share of a block's 80000 sigop budget
//! it takes.
//!
//! The P2WSH spend here reveals `OP_0 OP_IF OP_1 OP_CHECKMULTISIG×198
//! OP_ENDIF OP_1`: 3941 sigops by Core's accurate count, so 78820 adjusted
//! weight, 19705 vbytes, against a few hundred by its weight.

use super::*;
use crate::mining::template::tests::make_funded_template_env_with;
use crate::storage::coinview::Coin;
use crate::validation::script::NoopVerifier;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, Witness};

const COIN_VALUE: u64 = 100_000;
const HEAVY_SIGOPS: u64 = 1 + 197 * 20;
/// 3941 × 20 / 4.
const HEAVY_VSIZE: u64 = 19_705;

fn heavy_script() -> Vec<u8> {
    let mut s = vec![0x00, 0x63, 0x51];
    s.extend(std::iter::repeat_n(0xae, 198));
    s.extend([0x68, 0x51]);
    s
}

/// `OP_CHECKSIG OP_1`: one sigop, far below its weight.
fn light_script() -> Vec<u8> {
    vec![0xac, 0x51]
}

fn prev(tag: u8) -> OutPoint {
    OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: 0 }
}

fn p2wsh_coin(script: &[u8]) -> Coin {
    Coin {
        amount: COIN_VALUE,
        script_pubkey: ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(script.to_vec()).wscript_hash()),
        height: 0,
        coinbase: false,
        txseq: node_index::TXSEQ_UNKNOWN,
    }
}

fn spend(prevout: OutPoint, script: &[u8], fee: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[script]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(COIN_VALUE - fee),
            script_pubkey: ScriptBuf::from_bytes([&[0x00, 0x14][..], &[prevout.txid[0]; 20]].concat()),
        }],
    }
}

#[test]
fn the_adjusted_weight_is_the_larger_of_weight_and_sigops_times_twenty() {
    assert_eq!(policy::bytes_per_sigop(), policy::DEFAULT_BYTES_PER_SIGOP);
    assert_eq!(policy::sigops_adjusted_weight(1_000, 10), 1_000);
    assert_eq!(policy::sigops_adjusted_weight(1_000, 50), 1_000);
    assert_eq!(policy::sigops_adjusted_weight(1_000, 51), 1_020);
    assert_eq!(policy::sigops_adjusted_weight(400, HEAVY_SIGOPS), 4 * HEAVY_VSIZE);
}

/// The relay floor, `testmempoolaccept`'s `vsize` and `getmempoolentry`'s
/// `vsize` are all over the adjusted size; `weight` stays the transaction's.
#[test]
fn a_sigop_dense_transaction_pays_for_its_adjusted_size() {
    let ws = heavy_script();
    let coins = vec![(prev(1), p2wsh_coin(&ws)), (prev(2), p2wsh_coin(&ws))];
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    mp.config.write().min_fee_rate = 1_000; // 1 sat/vB

    // 1000 sat covers its weight many times over, and 19705 vbytes not.
    let cheap = spend(prev(1), &ws, 1_000);
    assert!(cheap.weight().to_wu() < 1_000, "{}", cheap.weight());
    let err = mp.accept_transaction(cheap.clone(), &cs, &NoopVerifier, TxSource::Rpc, false).expect_err("refused");
    assert_eq!(err.state_string(), format!("min relay fee not met, 1000 < {HEAVY_VSIZE}"));
    let err = mp.test_accept(&cheap, &cs, &NoopVerifier).expect_err("refused");
    assert_eq!(err.reject_reason(), "min relay fee not met");

    let paid = spend(prev(2), &ws, HEAVY_VSIZE);
    let (_, vsize, _) = mp.test_accept(&paid, &cs, &NoopVerifier).expect("accepted");
    assert_eq!(vsize as u64, HEAVY_VSIZE);
    let weight = paid.weight().to_wu();
    let txid = mp.accept_transaction(paid, &cs, &NoopVerifier, TxSource::Rpc, false).expect("admitted");
    let entry = mp.get_entry_verbose(&txid).expect("resident");
    assert_eq!(entry["vsize"], serde_json::json!(HEAVY_VSIZE));
    assert_eq!(entry["weight"], serde_json::json!(weight));
    assert_eq!(mp.get(&txid).unwrap().fee_rate, 1_000);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The template ranks by the adjusted feerate: a light spend paying 1000 sat
/// goes ahead of a heavy one paying 15000, which by weight alone pays far
/// more per vbyte.
#[test]
fn the_template_ranks_by_the_adjusted_feerate() {
    let (heavy, light) = (heavy_script(), light_script());
    let coins = vec![(prev(1), p2wsh_coin(&heavy)), (prev(2), p2wsh_coin(&light))];
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    let heavy_tx = mp
        .accept_transaction(spend(prev(1), &heavy, 15_000), &cs, &NoopVerifier, TxSource::Rpc, false)
        .expect("admitted");
    let light_tx = mp
        .accept_transaction(spend(prev(2), &light, 1_000), &cs, &NoopVerifier, TxSource::Rpc, false)
        .expect("admitted");

    let template = crate::mining::template::create_template(&cs, &mp);
    let order: Vec<Txid> = template.transactions.iter().map(|t| t.tx.compute_txid()).collect();
    assert_eq!(order, vec![light_tx, heavy_tx]);
    // A template transaction's `weight` is its own.
    assert!(template.transactions.iter().all(|t| t.weight == t.tx.weight().to_wu() as usize));
    let _ = std::fs::remove_dir_all(&dir);
}

/// BIP 125 rule 4 charges the replacement's own relay at the incremental
/// feerate over its adjusted size: 1971 sat over 19705 vbytes, where its
/// weight alone asks a dozen.
#[test]
fn a_replacement_pays_relay_for_its_adjusted_size() {
    let ws = heavy_script();
    let coins = vec![(prev(1), p2wsh_coin(&ws))];
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    mp.config.write().incremental_relay_fee = 100;
    mp.accept_transaction(spend(prev(1), &ws, 20_000), &cs, &NoopVerifier, TxSource::Rpc, false).expect("admitted");

    let mut short = spend(prev(1), &ws, 20_500);
    short.output[0].script_pubkey = ScriptBuf::from_bytes([&[0x00, 0x14][..], &[0x77; 20]].concat());
    let err = mp.accept_transaction(short, &cs, &NoopVerifier, TxSource::Rpc, false).expect_err("refused");
    assert_eq!(err.reject_reason(), "insufficient fee", "{err:?}");
    assert!(err.state_string().contains("not enough additional fees to relay"), "{}", err.state_string());

    let mut enough = spend(prev(1), &ws, 20_000 + 1_971);
    enough.output[0].script_pubkey = ScriptBuf::from_bytes([&[0x00, 0x14][..], &[0x78; 20]].concat());
    mp.accept_transaction(enough, &cs, &NoopVerifier, TxSource::Rpc, false).expect("pays its relay");
    let _ = std::fs::remove_dir_all(&dir);
}
