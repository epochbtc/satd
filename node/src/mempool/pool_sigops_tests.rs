//! Mempool sigop cost, counted as Bitcoin Core counts it, and the block
//! template budget that reads it.
//!
//! The P2WSH inputs here reveal `OP_0 OP_IF OP_1 OP_CHECKMULTISIG×198
//! OP_ENDIF OP_1`. Core's `GetSigOpCount(fAccurate=true)`
//! (src/script/script.cpp) reads the opcode immediately before each
//! `OP_CHECKMULTISIG`: the first follows `OP_1` and counts 1, the other 197
//! follow `OP_CHECKMULTISIG` and count 20 each, 3,941 in all. Core's mempool
//! stores that cost on the entry (`GetTransactionSigOpCost` with the
//! standard flags, src/validation.cpp `PreChecks`), and its block assembler
//! budgets by it.

use super::*;
use crate::mining::template::tests::make_funded_template_env_with;
use crate::storage::coinview::Coin;
use crate::validation::script::NoopVerifier;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_ENDIF, OP_IF, OP_PUSHNUM_1};
use bitcoin::opcodes::OP_0;
use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, Witness};

/// Core's count for one input revealing [`heavy_script`].
const HEAVY: u64 = 1 + 197 * 20;
const COIN_VALUE: u64 = 100_000;

fn heavy_script() -> ScriptBuf {
    let mut s = vec![OP_0.to_u8(), OP_IF.to_u8(), OP_PUSHNUM_1.to_u8()];
    s.extend(std::iter::repeat_n(OP_CHECKMULTISIG.to_u8(), 198));
    s.extend([OP_ENDIF.to_u8(), OP_PUSHNUM_1.to_u8()]);
    ScriptBuf::from_bytes(s)
}

/// `OP_CHECKSIG OP_1`: one sigop by any count.
fn light_script() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![OP_CHECKSIG.to_u8(), OP_PUSHNUM_1.to_u8()])
}

fn prev(tag: u8) -> OutPoint {
    OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: 0 }
}

/// A confirmed P2WSH coin committing to `witness_script`.
fn p2wsh_coin(witness_script: &ScriptBuf) -> Coin {
    Coin {
        amount: COIN_VALUE,
        script_pubkey: ScriptBuf::new_p2wsh(&witness_script.wscript_hash()),
        height: 0,
        coinbase: false,
        txseq: node_index::TXSEQ_UNKNOWN,
    }
}

/// Spend each of `prevs` by revealing `witness_script`, paying all but `fee`
/// to one P2WPKH output.
fn spend_p2wsh(prevs: &[OutPoint], witness_script: &ScriptBuf, fee: u64, out_tag: u8) -> Transaction {
    let mut spk = vec![0x00, 0x14];
    spk.extend_from_slice(&[out_tag; 20]);
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: prevs
            .iter()
            .map(|p| TxIn {
                previous_output: *p,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[witness_script.as_bytes()]),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(COIN_VALUE * prevs.len() as u64 - fee),
            script_pubkey: ScriptBuf::from_bytes(spk),
        }],
    }
}

/// Admission records Core's count: four heavy inputs cost 15,764, which
/// is under Core's standard per-transaction 16,000.
#[test]
fn an_entry_carries_cores_sigop_cost() {
    let ws = heavy_script();
    let prevs: Vec<OutPoint> = (1..=4).map(prev).collect();
    let coins: Vec<(OutPoint, Coin)> = prevs.iter().map(|p| (*p, p2wsh_coin(&ws))).collect();
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));

    let txid = mp
        .accept_transaction(spend_p2wsh(&prevs, &ws, 1_000, 0x21), &cs, &NoopVerifier, TxSource::Rpc, false)
        .expect("admitted");
    assert_eq!(mp.get(&txid).unwrap().sigop_cost, 4 * HEAVY);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The policy engine's `tx.sigops_cost` is the same number: a rule that
/// holds transactions above 3,000 holds the heavy spend (3,941) and not the
/// light one (1).
#[test]
fn the_policy_view_sees_cores_sigop_cost() {
    let (heavy, light) = (heavy_script(), light_script());
    let coins = vec![(prev(1), p2wsh_coin(&heavy)), (prev(2), p2wsh_coin(&light))];
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    let rs = satd_policy::parse_ruleset("version 1\nquarantine sigops when tx.sigops_cost > 3000")
        .expect("ruleset compiles");
    mp.set_policy(std::sync::Arc::new(rs));

    let held = mp
        .accept_transaction(spend_p2wsh(&[prev(1)], &heavy, 1_000, 0x21), &cs, &NoopVerifier, TxSource::P2p, false)
        .expect("admitted into quarantine");
    let free = mp
        .accept_transaction(spend_p2wsh(&[prev(2)], &light, 1_000, 0x22), &cs, &NoopVerifier, TxSource::P2p, false)
        .expect("admitted");
    let inner = mp.inner.read();
    assert!(inner.entries.get(&held).unwrap().scope.is_quarantined(), "3,941 is over 3,000");
    assert!(inner.entries.get(&free).unwrap().scope.is_acting());
    drop(inner);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A `submitpackage` ephemeral-dust parent enters through the fee-bypass
/// path. It records the same sigop cost and prevout metadata as any other
/// admission; it recorded zero and nothing, so the template under-counted
/// it.
#[test]
fn a_fee_bypass_admission_records_its_sigop_cost_and_prevouts() {
    let ws = heavy_script();
    let coins = vec![(prev(1), p2wsh_coin(&ws))];
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));

    let txid = mp
        .accept_transaction_bypass_fee(spend_p2wsh(&[prev(1)], &ws, 0, 0x21), &cs, &NoopVerifier)
        .expect("admitted");
    let entry = mp.get(&txid).unwrap();
    assert_eq!(entry.sigop_cost, HEAVY);
    let spk = p2wsh_coin(&ws).script_pubkey;
    assert_eq!(entry.prev_scripthashes, vec![scripthash_of(&spk)]);
    // The default `streamprevoutmeta` level keeps amounts, not scripts.
    assert_eq!(entry.prev_amounts, vec![COIN_VALUE]);
    assert!(entry.prev_scripts.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Six transactions of four heavy inputs each, 15,764 apiece by Core's
/// count. The template reserves 400 for the coinbase and refuses a
/// transaction that would bring the total to 80,000 (Core's
/// `TestChunkBlockLimits`, src/node/miner.cpp), so five fit (79,220) and
/// the sixth does not. getblocktemplate reports each one's cost, and the
/// block built from the template passes the structural validity check.
#[test]
fn a_template_keeps_to_the_sigop_limit_by_cores_count() {
    let ws = heavy_script();
    let prevs: Vec<OutPoint> = (1..=24).map(prev).collect();
    let coins: Vec<(OutPoint, Coin)> = prevs.iter().map(|p| (*p, p2wsh_coin(&ws))).collect();
    let (cs, mp, dir) = make_funded_template_env_with(&coins, Box::new(NoopVerifier));
    for (i, four) in prevs.chunks(4).enumerate() {
        // Higher fee first, so the one left out is the last.
        let fee = 10_000 - 1_000 * i as u64;
        mp.accept_transaction(spend_p2wsh(four, &ws, fee, 0x30 + i as u8), &cs, &NoopVerifier, TxSource::Rpc, false)
            .expect("admitted");
    }

    let template = crate::mining::template::create_template(&cs, &mp);
    assert_eq!(template.transactions.len(), 5, "five of six fit under 80,000");
    for t in &template.transactions {
        assert_eq!(t.sigop_cost, 4 * HEAVY);
    }

    let gbt = crate::rpc::mining::get_block_template(&cs, &mp).unwrap();
    let reported: Vec<u64> = gbt["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["sigops"].as_u64().unwrap())
        .collect();
    assert_eq!(reported, vec![4 * HEAVY; 5]);

    let block = crate::mining::miner::build_block_to_script(&cs, &mp, ScriptBuf::new(), None)
        .expect("the template's block passes the structural check");
    assert_eq!(block.txdata.len(), 6);

    let _ = std::fs::remove_dir_all(&dir);
}
