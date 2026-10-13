//! `connect_block`'s block sigop limit, counted as Bitcoin Core counts it.
//!
//! The witness scripts here put `OP_CHECKMULTISIG` after another signature
//! opcode. Core's `GetSigOpCount(fAccurate=true)` (src/script/script.cpp)
//! reads the opcode immediately before each `OP_CHECKMULTISIG`, so only the
//! first one, after `OP_1`, counts 1 and every later one counts 20.

use super::*;
use crate::storage::db::InMemoryStore;
use crate::validation::script::NoopVerifier;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_ENDIF, OP_IF, OP_PUSHNUM_1};
use bitcoin::opcodes::OP_0;
use bitcoin::pow::CompactTarget;
use bitcoin::transaction::Version;
use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, Witness};

/// `OP_0 OP_IF OP_1 OP_CHECKMULTISIG×k OP_ENDIF OP_1`: the branch never runs
/// and the script leaves `[1]`. Core counts `1 + 20·(k-1)`.
fn stale_op_n_script(k: usize) -> ScriptBuf {
    let mut s = vec![OP_0.to_u8(), OP_IF.to_u8(), OP_PUSHNUM_1.to_u8()];
    s.extend(std::iter::repeat_n(OP_CHECKMULTISIG.to_u8(), k));
    s.extend([OP_ENDIF.to_u8(), OP_PUSHNUM_1.to_u8()]);
    ScriptBuf::from_bytes(s)
}

/// `OP_CHECKSIG×n OP_1`. Core counts `n`.
fn checksig_script(n: usize) -> ScriptBuf {
    let mut s = vec![OP_CHECKSIG.to_u8(); n];
    s.push(OP_PUSHNUM_1.to_u8());
    ScriptBuf::from_bytes(s)
}

const COIN_VALUE: u64 = 100_000;

/// A regtest block at height 1 whose second transaction spends one P2WSH
/// coin per witness script, each revealing its script in the witness.
/// Returns the store holding those coins and the block.
fn block_spending_p2wsh(witness_scripts: &[ScriptBuf]) -> (InMemoryStore, Block) {
    let store = InMemoryStore::new();
    let mut batch = StoreBatch::default();
    batch.chain_tx_puts.push((BlockHash::all_zeros(), 0));

    let mut inputs = Vec::new();
    for (i, ws) in witness_scripts.iter().enumerate() {
        let outpoint = OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x70 ^ (i as u8); 32]),
            vout: i as u32,
        };
        batch.coin_puts.push((
            outpoint,
            Coin {
                amount: COIN_VALUE,
                script_pubkey: ScriptBuf::new_p2wsh(&ws.wscript_hash()),
                height: 0,
                coinbase: false,
                txseq: node_index::TXSEQ_UNKNOWN,
            },
        ));
        inputs.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[ws.as_bytes()]),
        });
    }
    store.write_batch(batch).unwrap();

    let height = 1;
    let coinbase = Transaction {
        version: Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::script::Builder::new()
                .push_int(height as i64)
                .push_opcode(OP_0)
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(block_subsidy(Network::Regtest, height)),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let spend = Transaction {
        version: Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: vec![TxOut {
            value: Amount::from_sat(COIN_VALUE * witness_scripts.len() as u64),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let mut block = Block {
        header: Header {
            version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase, spend],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    (store, block)
}

fn connect_at_height_1(store: &InMemoryStore, block: &Block) -> Result<StoreBatch, ConnectError> {
    connect_block(&ConnectParams {
        replay_plan: None,
        store,
        block,
        height: 1,
        parent_chainwork: &[0u8; 32],
        flat_pos: FlatFilePos { file_number: 0, data_pos: 0 },
        script_verifier: &NoopVerifier,
        median_time_past: 0,
        network: Network::Regtest,
        pre_verified_txs: None,
        num_threads: 1,
        precomputed_txids: None,
        address_index: &Default::default(),
        sp_index: &Default::default(),
        #[cfg(feature = "block-filter-index")]
        filter_index: &Default::default(),
        phase_tracker: None,
        interrupt: None,
    })
}

/// Twenty inputs at 3,941 each (78,820) plus one more to reach the limit
/// exactly: a block at 80,000 connects and one at 80,001 is
/// `bad-blk-sigops`, as `MAX_BLOCK_SIGOPS_COST` is applied in Core's
/// `ConnectBlock` (`nSigOpsCost > MAX_BLOCK_SIGOPS_COST`).
///
/// Witness sigops are not scaled, so each input adds its witness script's
/// accurate count. A counter that keeps an earlier `OP_1` across later
/// `OP_CHECKMULTISIG`s sees 198 per heavy input and about 5,140 in all,
/// and lets the 80,001 block through.
#[test]
fn a_block_one_sigop_over_the_limit_by_cores_count_is_refused() {
    let heavy = stale_op_n_script(198);
    let mut scripts = vec![heavy; 20];
    scripts.push(checksig_script(80_000 - 20 * 3_941));
    let (store, at_limit) = block_spending_p2wsh(&scripts);
    connect_at_height_1(&store, &at_limit).expect("a block at exactly 80,000 sigop cost connects");

    *scripts.last_mut().unwrap() = checksig_script(80_000 - 20 * 3_941 + 1);
    let (store, over) = block_spending_p2wsh(&scripts);
    assert!(
        matches!(connect_at_height_1(&store, &over), Err(ConnectError::BadBlockSigops)),
        "a block at 80,001 sigop cost is bad-blk-sigops"
    );
}

/// The block-level wrapper applies Core's `GetTransactionSigOpCost` to the
/// resolved prevouts: one P2WSH input whose script is `OP_1 OP_CHECKSIG
/// OP_CHECKMULTISIG` costs 21, not 2.
#[test]
fn the_block_sigop_cost_of_a_p2wsh_spend_follows_cores_count() {
    let ws = ScriptBuf::from_bytes(vec![0x51, 0xac, 0xae]);
    let (_store, block) = block_spending_p2wsh(std::slice::from_ref(&ws));
    let prevouts = vec![TxOut {
        value: Amount::from_sat(COIN_VALUE),
        script_pubkey: ScriptBuf::new_p2wsh(&ws.wscript_hash()),
    }];
    assert_eq!(transaction_sigop_cost(&block.txdata[1], Network::Regtest, 1, &prevouts), 21);
    // Below the P2SH gate only legacy sigops count (issue #724 tracks that
    // gate), and this transaction has none.
    assert_eq!(transaction_sigop_cost(&block.txdata[1], Network::Bitcoin, 1, &prevouts), 0);
}
