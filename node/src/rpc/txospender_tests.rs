//! `gettxspendingprevout` against Core v31.1's `rpc_gettxspendingprevout.py`.

use super::*;
use crate::mempool::pool::{MempoolConfig, TxSource};
use crate::mining::template::tests::make_funded_template_env_with;
use crate::storage::coinview::Coin;
use crate::validation::script::NoopVerifier;
use bitcoin::hashes::Hash as _;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Sequence, TxIn, TxOut, Witness};
use node_index::SpendingRef;
use serde_json::json;

fn prev(tag: u8) -> OutPoint {
    OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: 0 }
}

fn coin() -> Coin {
    Coin {
        amount: 100_000,
        script_pubkey: bitcoin::ScriptBuf::from_bytes([&[0x00, 0x14][..], &[0x11; 20]].concat()),
        height: 1,
        coinbase: false,
        txseq: node_index::TXSEQ_UNKNOWN,
    }
}

fn spend(prev: OutPoint) -> Transaction {
    Transaction {
        version: Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn { previous_output: prev, script_sig: Default::default(), sequence: Sequence::MAX, witness: Witness::new() }],
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: bitcoin::ScriptBuf::from_bytes([&[0x00, 0x14][..], &[0x22; 20]].concat()),
        }],
    }
}

fn env() -> (ChainState, Mempool, std::path::PathBuf) {
    let (cs, mp, dir) = make_funded_template_env_with(&[(prev(1), coin()), (prev(2), coin())], Box::new(NoopVerifier));
    mp.reload_policy(MempoolConfig { max_size_bytes: 1_000_000, min_fee_rate: 0, ..Default::default() });
    (cs, mp, dir)
}

/// A spend index that answers from a fixed list, or fails every lookup.
struct FixedIndex(Result<Vec<(OutPoint, SpendingRef)>, ()>);

impl SpendIndex for FixedIndex {
    fn spend_of(&self, outpoint: &OutPoint) -> Result<Option<SpendingRef>, IndexError> {
        match &self.0 {
            Ok(rows) => Ok(rows.iter().find(|(op, _)| op == outpoint).map(|(_, r)| *r)),
            Err(()) => Err(IndexError::Incomplete),
        }
    }
    fn spends_of_tx(&self, _: &Txid) -> Result<Vec<(u32, SpendingRef)>, IndexError> {
        unreachable!()
    }
}

fn arg(op: OutPoint) -> Value {
    json!({"txid": op.txid.to_string(), "vout": op.vout})
}

fn call(
    cs: &ChainState,
    mp: &Mempool,
    index: Option<&dyn SpendIndex>,
    outputs: Vec<Value>,
    options: Value,
) -> Result<Value, (i32, String)> {
    let options = match options {
        Value::Object(m) => Some(m),
        _ => None,
    };
    get_tx_spending_prevout(cs, mp, index, outputs, options)
}

#[test]
fn a_mempool_spender_is_found_and_an_unspent_output_echoed() {
    let (cs, mp, dir) = env();
    let tx = spend(prev(1));
    mp.accept_transaction(tx.clone(), &cs, &NoopVerifier, TxSource::Rpc, false).expect("admitted");
    let unspent = OutPoint { txid: tx.compute_txid(), vout: 5 };

    let r = call(&cs, &mp, None, vec![arg(prev(1)), arg(unspent)], Value::Null).unwrap();
    assert_eq!(
        r,
        json!([
            {"txid": prev(1).txid.to_string(), "vout": 0, "spendingtxid": tx.compute_txid().to_string()},
            {"txid": tx.compute_txid().to_string(), "vout": 5},
        ])
    );
    let r = call(&cs, &mp, None, vec![arg(prev(1))], json!({"return_spending_tx": true})).unwrap();
    assert_eq!(r[0]["spendingtx"], serialize_hex(&tx));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Without the index, `mempool_only` defaults to true; asking past the
/// mempool is Core's error naming the first outpoint it could not answer.
#[test]
fn without_the_index_only_the_mempool_answers() {
    let (cs, mp, dir) = env();
    let r = call(&cs, &mp, None, vec![arg(prev(2))], json!({"mempool_only": false}));
    assert_eq!(
        r,
        Err((-1, format!("No spending tx for the outpoint {}:0 in mempool, and txospenderindex is unavailable.", prev(2).txid)))
    );
    // An index still filling is unavailable too.
    let filling = FixedIndex(Err(()));
    let r = call(&cs, &mp, Some(&filling), vec![arg(prev(2))], Value::Null);
    assert_eq!(r.unwrap_err().0, -1);

    let _ = std::fs::remove_dir_all(&dir);
}

/// With the index, an output spent in a block names the spender and its
/// block, and the transaction itself when asked; `mempool_only` skips it.
#[test]
fn the_index_names_a_confirmed_spender_and_its_block() {
    let (cs, mp, dir) = env();
    let genesis = cs.get_block_hash_by_height(0).expect("genesis");
    let coinbase = cs.get_block(&genesis).expect("genesis block").txdata[0].clone();
    let index = FixedIndex(Ok(vec![(prev(2), SpendingRef { spending_txid: coinbase.compute_txid(), spending_vin: 0, height: 0 })]));
    let mempool_spend = spend(prev(1));
    mp.accept_transaction(mempool_spend.clone(), &cs, &NoopVerifier, TxSource::Rpc, false).expect("admitted");
    let unspent = OutPoint { txid: coinbase.compute_txid(), vout: 0 };

    let r = call(&cs, &mp, Some(&index), vec![arg(prev(2)), arg(prev(1)), arg(unspent)], json!({"return_spending_tx": true}))
        .unwrap();
    assert_eq!(
        r,
        json!([
            {
                "txid": prev(2).txid.to_string(), "vout": 0,
                "spendingtxid": coinbase.compute_txid().to_string(),
                "blockhash": genesis.to_string(),
                "spendingtx": serialize_hex(&coinbase),
            },
            {
                "txid": prev(1).txid.to_string(), "vout": 0,
                "spendingtxid": mempool_spend.compute_txid().to_string(),
                "spendingtx": serialize_hex(&mempool_spend),
            },
            {"txid": unspent.txid.to_string(), "vout": 0},
        ]),
        "input order is kept"
    );
    let r = call(&cs, &mp, Some(&index), vec![arg(prev(2))], json!({"mempool_only": true})).unwrap();
    assert_eq!(r, json!([arg(prev(2))]));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn arguments_are_checked_as_core_checks_them() {
    let (cs, mp, dir) = env();
    let txid = prev(1).txid.to_string();
    let err = |outputs: Vec<Value>, options: Value| call(&cs, &mp, None, outputs, options).unwrap_err();

    assert_eq!(err(vec![], Value::Null), (-8, "Invalid parameter, outputs are missing".into()));
    assert_eq!(err(vec![json!({"txid": txid, "vout": 1, "unknown": 42})], Value::Null), (-3, "Unexpected key unknown".into()));
    assert_eq!(err(vec![json!({"txid": txid, "vout": -1})], Value::Null), (-8, "Invalid parameter, vout cannot be negative".into()));
    assert_eq!(
        err(vec![json!({"txid": 42, "vout": 0})], Value::Null),
        (-3, "JSON value of type number for field txid is not of expected type string".into())
    );
    assert_eq!(err(vec![json!({"txid": txid})], Value::Null), (-3, "Missing vout".into()));
    assert_eq!(err(vec![json!({"vout": 3})], Value::Null), (-3, "Missing txid".into()));
    assert_eq!(err(vec![json!({"txid": "ab", "vout": 0})], Value::Null), (-8, "txid must be of length 64 (not 2, for 'ab')".into()));
    assert_eq!(err(vec![arg(prev(1))], json!({"other": true})), (-3, "Unexpected key other".into()));
    assert_eq!(
        err(vec![arg(prev(1))], json!({"mempool_only": 1})),
        (-3, "JSON value of type number for field mempool_only is not of expected type bool".into())
    );

    let _ = std::fs::remove_dir_all(&dir);
}
