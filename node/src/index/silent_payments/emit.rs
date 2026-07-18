//! Emission helper for the BIP 352 silent-payment tweak index.
//!
//! `build_sp_row` is called once per block at the end of `connect_block`'s
//! per-tx loop — the same end-of-block hook the filter index uses, not the
//! address index's per-output hook, because SP eligibility needs the whole
//! transaction plus its prevouts. The caller applies the taproot-activation
//! gate (no row at all below activation, §3.2) and pushes the returned row
//! into `StoreBatch::sp_tweak_puts`; `disconnect_block` pushes the height
//! onto `sp_tweak_removes`.
//!
//! The helper is a no-op when the index is disabled at runtime, mirroring
//! the filter emit helper's convention.

use std::collections::HashMap;

use bitcoin::{Block, BlockHash, OutPoint, ScriptBuf};

use node_sp_index::{SpBlockRow, SpIndexConfig, compute_tweak};

/// Emit error surface. A missing prev-output script is fail-closed: it
/// would let an eligible input go unclassified and produce a wrong tweak,
/// so the connect path surfaces it rather than silently indexing a
/// partial row. In practice unreachable on the live path — the caller
/// populates the prev-output map from the same coins it just resolved for
/// script verification.
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    #[error("missing prev-output script for outpoint {0}")]
    MissingPrevOutput(OutPoint),
}

/// Build the `sp_tweaks` row for `block` (the caller keys it by height).
///
/// Returns `Ok(None)` when the index is disabled at runtime, so callers
/// can wrap the call in one line. At/above taproot activation (the
/// caller's gate) an enabled index always yields a row — empty when the
/// block has no eligible transactions — so row-presence distinguishes
/// "indexed, no eligible txs" from "not indexed". Coinbase transactions
/// are skipped (never eligible: no contributing inputs).
///
/// `prev_output_scripts` must map every non-coinbase input's `OutPoint`
/// to its resolved prev-output `scriptPubKey`; a missing entry is an
/// error (see [`EmitError`]).
pub fn build_sp_row(
    cfg: &SpIndexConfig,
    block: &Block,
    block_hash: BlockHash,
    prev_output_scripts: &HashMap<OutPoint, ScriptBuf>,
) -> Result<Option<SpBlockRow>, EmitError> {
    if !cfg.enabled {
        return Ok(None);
    }

    let mut entries = Vec::new();
    for tx in &block.txdata {
        if tx.is_coinbase() {
            continue;
        }
        // Aligned prev-output scriptPubKeys for this tx's inputs — the
        // kernel classifies eligibility by prevout script, so alignment
        // with `tx.input` is required.
        let mut spks = Vec::with_capacity(tx.input.len());
        for txin in &tx.input {
            match prev_output_scripts.get(&txin.previous_output) {
                Some(spk) => spks.push(spk.clone()),
                None => return Err(EmitError::MissingPrevOutput(txin.previous_output)),
            }
        }
        if let Some(entry) = compute_tweak(tx, &spks) {
            entries.push(entry);
        }
    }
    Ok(Some(SpBlockRow::new(block_hash, entries)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Witness,
    };

    fn coinbase_tx() -> Transaction {
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from(vec![0x51, 0x52]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from(vec![0x51, 0x20, 0x00]),
            }],
        }
    }

    fn synth_block(txs: Vec<Transaction>) -> Block {
        let mut block = Block {
            header: Header {
                version: BlockVersion::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata: txs,
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block
    }

    fn enabled() -> SpIndexConfig {
        SpIndexConfig { enabled: true }
    }

    #[test]
    fn disabled_emits_nothing() {
        let block = synth_block(vec![coinbase_tx()]);
        let map = HashMap::new();
        let out =
            build_sp_row(&SpIndexConfig::default(), &block, block.block_hash(), &map).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn coinbase_only_block_yields_present_empty_row() {
        // An indexed block with no eligible txs still gets a row (with the
        // block hash), so row-presence means "indexed, none".
        let block = synth_block(vec![coinbase_tx()]);
        let map = HashMap::new();
        let row = build_sp_row(&enabled(), &block, block.block_hash(), &map)
            .unwrap()
            .unwrap();
        assert_eq!(row.block_hash, block.block_hash());
        assert!(row.entries.is_empty());
    }

    #[test]
    fn missing_prevout_is_error() {
        // A non-coinbase input whose prevout script is absent from the map
        // must fail closed rather than index a partial row.
        let spending = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([7u8; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from(vec![0x51, 0x20, 0x00]),
            }],
        };
        let block = synth_block(vec![coinbase_tx(), spending]);
        let map = HashMap::new();
        let r = build_sp_row(&enabled(), &block, block.block_hash(), &map);
        assert!(matches!(r, Err(EmitError::MissingPrevOutput(_))));
    }
}
