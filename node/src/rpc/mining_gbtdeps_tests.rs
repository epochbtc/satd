//! `getblocktemplate`'s per-transaction `hash` and `depends`, as Core's
//! `getblocktemplate` (`src/rpc/mining.cpp`) builds them: `hash` is the
//! wtxid, and `depends` holds, for each input that spends an earlier template
//! transaction, that transaction's 1-based index in `transactions`, in input
//! order and with repeats.

use crate::mempool::pool::TxSource;
use crate::mining::template::tests::make_funded_template_env_with;
use crate::storage::coinview::Coin;
use crate::validation::script::NoopVerifier;
use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

const COIN_VALUE: u64 = 100_000;

/// `OP_1`: anything spends it.
fn op_true() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51])
}

fn p2wsh_coin() -> Coin {
    Coin {
        amount: COIN_VALUE,
        script_pubkey: ScriptBuf::new_p2wsh(&op_true().wscript_hash()),
        height: 0,
        coinbase: false,
        txseq: node_index::TXSEQ_UNKNOWN,
    }
}

/// Spend `prevs` (each worth `each`) to `outs` P2WSH outputs, less `fee`.
fn spend(prevs: &[OutPoint], each: u64, outs: usize, fee: u64) -> Transaction {
    let total = each * prevs.len() as u64 - fee;
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: prevs
            .iter()
            .map(|p| TxIn {
                previous_output: *p,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[op_true().as_bytes()]),
            })
            .collect(),
        output: (0..outs)
            .map(|_| TxOut {
                value: Amount::from_sat(total / outs as u64),
                script_pubkey: ScriptBuf::new_p2wsh(&op_true().wscript_hash()),
            })
            .collect(),
    }
}

#[test]
fn template_transactions_carry_cores_hash_and_depends() {
    let a = OutPoint { txid: Txid::from_byte_array([1; 32]), vout: 0 };
    let b = OutPoint { txid: Txid::from_byte_array([2; 32]), vout: 0 };
    let (cs, mp, dir) = make_funded_template_env_with(&[(a, p2wsh_coin()), (b, p2wsh_coin())], Box::new(NoopVerifier));

    // A parent with two outputs, a child spending both, and an unrelated
    // transaction. The child's fee carries the parent's package ahead of the
    // unrelated one, so the template order is parent, child, unrelated.
    let parent = spend(&[a], COIN_VALUE, 2, 2_000);
    let each = parent.output[0].value.to_sat();
    let child = spend(
        &[OutPoint { txid: parent.compute_txid(), vout: 0 }, OutPoint { txid: parent.compute_txid(), vout: 1 }],
        each,
        1,
        20_000,
    );
    let unrelated = spend(&[b], COIN_VALUE, 1, 1_000);
    for tx in [&parent, &child, &unrelated] {
        mp.accept_transaction(tx.clone(), &cs, &NoopVerifier, TxSource::Rpc, false).expect("admitted");
    }

    let gbt = crate::rpc::mining::get_block_template(&cs, &mp).unwrap();
    let txs = gbt["transactions"].as_array().unwrap();
    let txid = |t: &serde_json::Value| t["txid"].as_str().unwrap().to_string();
    let order: Vec<String> = txs.iter().map(txid).collect();
    assert_eq!(
        order,
        vec![parent.compute_txid().to_string(), child.compute_txid().to_string(), unrelated.compute_txid().to_string()]
    );

    for (t, tx) in txs.iter().zip([&parent, &child, &unrelated]) {
        assert_eq!(t["hash"].as_str().unwrap(), tx.compute_wtxid().to_string(), "hash is the wtxid");
        assert_ne!(t["hash"], t["txid"], "a witness spend's wtxid differs from its txid");
    }
    assert_eq!(txs[0]["depends"], serde_json::json!([]));
    assert_eq!(txs[1]["depends"], serde_json::json!([1, 1]), "one entry per input that spends the parent");
    assert_eq!(txs[2]["depends"], serde_json::json!([]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Core's `getblocktemplate` gate: on mainnet, no peers is -9 and initial
/// block download is -10, checked in that order; test chains are never
/// gated. Perturbation: drop either check and its assertion fails.
#[test]
fn template_gate_refuses_mainnet_without_peers_or_in_ibd() {
    use super::template_gate;
    use bitcoin::Network;
    assert_eq!(template_gate(Network::Bitcoin, 0, false).unwrap_err().0, -9);
    assert_eq!(template_gate(Network::Bitcoin, 0, true).unwrap_err().0, -9, "no peers is reported first");
    assert_eq!(template_gate(Network::Bitcoin, 3, true).unwrap_err().0, -10);
    assert!(template_gate(Network::Bitcoin, 3, false).is_ok());
    for net in [Network::Testnet, Network::Testnet4, Network::Signet, Network::Regtest] {
        assert!(template_gate(net, 0, true).is_ok(), "{net:?} is a test chain");
    }
}
