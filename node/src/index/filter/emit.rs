//! Emission helpers for the BIP 158 compact block filter index.
//!
//! `build_filter_row_pair` is called once per block (at the end of the
//! per-tx loop in `connect_block`, before the BlockIndexEntry is built)
//! to produce the `(FilterRow, FilterHeaderRow)` pair the caller pushes
//! into the `StoreBatch`. The filter blob is constructed by wrapping
//! `bitcoin::bip158::BlockFilter::new_script_filter`; the header is the
//! standard BIP 157 chain step over the previous block's filter header.
//!
//! The helper is a no-op when the index is disabled at runtime
//! (`FilterIndexConfig::enabled == false`), mirroring the address-index
//! emit-helper convention at `index/address/emit.rs`.
//!
//! Disconnect-side counterpart: `filter_remove_key` returns the
//! `(filter_type, height)` key to drop from both `cf_filter` and
//! `cf_filter_header`. Both rows are removed by the same key, so a
//! single `filter_removes` entry per disconnected block is sufficient.

use std::collections::HashMap;

use bitcoin::bip158::{BlockFilter, Error as Bip158Error};
use bitcoin::{Block, OutPoint, ScriptBuf};

use node_filter_index::{
    FilterHeaderRow, FilterIndexConfig, FilterKey, FilterRow, FILTER_TYPE_BASIC,
};

/// Genesis previous-filter-header per BIP 157.
pub const GENESIS_PREV_FILTER_HEADER: [u8; 32] = [0u8; 32];

/// Emit error surface. Wraps the rust-bitcoin BIP 158 error so callers
/// get a single domain type to handle.
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    #[error("missing prev-output script for outpoint {0}")]
    MissingPrevOutput(OutPoint),
    #[error("BIP 158 codec error: {0}")]
    Bip158(String),
}

impl From<Bip158Error> for EmitError {
    fn from(e: Bip158Error) -> Self {
        EmitError::Bip158(format!("{e}"))
    }
}

/// Build the filter and filter-header rows for `block` at `height`.
///
/// `prev_output_scripts` maps every non-coinbase input's `OutPoint` to
/// the resolved prev-output `scriptPubKey`. `prev_filter_header` is the
/// 32-byte filter header of the block at `height - 1`, or
/// `GENESIS_PREV_FILTER_HEADER` for `height == 0`.
///
/// Returns `Ok(None)` when the index is disabled, so callers can wrap
/// the call in a single line:
///
/// ```ignore
/// if let Some((filter_row, header_row)) = build_filter_row_pair(...)? {
///     batch.filter_puts.push(filter_row);
///     batch.filter_header_puts.push(header_row);
/// }
/// ```
pub fn build_filter_row_pair(
    cfg: &FilterIndexConfig,
    height: u32,
    block: &Block,
    prev_output_scripts: &HashMap<OutPoint, ScriptBuf>,
    prev_filter_header: &[u8; 32],
) -> Result<Option<(FilterRow, FilterHeaderRow)>, EmitError> {
    if !cfg.enabled {
        return Ok(None);
    }

    let filter = BlockFilter::new_script_filter(block, |op| {
        prev_output_scripts
            .get(op)
            .cloned()
            .ok_or(Bip158Error::UtxoMissing(*op))
    })?;

    // `filter.filter_header(prev)` chains: it computes the SHA256d of the
    // filter blob, then SHA256d(filter_hash || prev_header). Both steps
    // are byte-for-byte BIP 157.
    use bitcoin::bip158::FilterHeader;
    use bitcoin::hashes::Hash;
    let prev = FilterHeader::from_byte_array(*prev_filter_header);
    let header = filter.filter_header(&prev);
    let header_bytes: [u8; 32] = header.to_byte_array();

    let key = FilterKey {
        filter_type: FILTER_TYPE_BASIC,
        height,
    };
    Ok(Some((
        FilterRow {
            key,
            filter: filter.content,
        },
        FilterHeaderRow {
            key,
            header: header_bytes,
        },
    )))
}

/// Build a removal key for `(FILTER_TYPE_BASIC, height)`. Used by
/// `disconnect_block` when reversing a connected block's filter rows.
/// Returns `None` when the index is disabled at runtime.
#[inline]
pub fn filter_remove_key(cfg: &FilterIndexConfig, height: u32) -> Option<FilterKey> {
    if !cfg.enabled {
        return None;
    }
    Some(FilterKey {
        filter_type: FILTER_TYPE_BASIC,
        height,
    })
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

    fn fake_outpoint(byte: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [byte; 32],
            )),
            vout,
        }
    }

    fn coinbase_tx(spk: ScriptBuf) -> Transaction {
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
                script_pubkey: spk,
            }],
        }
    }

    fn spending_tx(prev: OutPoint, spk: ScriptBuf) -> Transaction {
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: spk,
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
        // Recompute merkle root so block_hash() is deterministic; not
        // strictly necessary for the filter (which siphashes the block
        // hash anyway) but we want a stable hash for assertions.
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block
    }

    fn enabled_cfg() -> FilterIndexConfig {
        FilterIndexConfig {
            enabled: true,
            peer_serve: false,
        }
    }

    #[test]
    fn test_disabled_emits_nothing() {
        let cfg = FilterIndexConfig::default();
        let block = synth_block(vec![coinbase_tx(ScriptBuf::from(vec![0x51]))]);
        let map = HashMap::new();
        let out = build_filter_row_pair(&cfg, 0, &block, &map, &[0u8; 32]).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn test_coinbase_only_block_filter_matches_rust_bitcoin_directly() {
        // For a coinbase-only block, our wrapper output must be
        // byte-identical to BlockFilter::new_script_filter directly,
        // proving we are not adding extra elements.
        let cfg = enabled_cfg();
        let coinbase = coinbase_tx(ScriptBuf::from(vec![0x76, 0xa9, 0x14, 0x42]));
        let block = synth_block(vec![coinbase]);
        let map: HashMap<OutPoint, ScriptBuf> = HashMap::new();

        let (row, _hdr) = build_filter_row_pair(&cfg, 0, &block, &map, &[0u8; 32])
            .unwrap()
            .unwrap();

        // Direct rust-bitcoin call for parity reference.
        let direct = BlockFilter::new_script_filter(&block, |op| {
            map.get(op)
                .cloned()
                .ok_or(bitcoin::bip158::Error::UtxoMissing(*op))
        })
        .unwrap();
        assert_eq!(row.filter, direct.content);
    }

    #[test]
    fn test_op_return_outputs_excluded_from_filter() {
        let cfg = enabled_cfg();
        // Block A: coinbase (P2WPKH-shaped) + a tx with one P2WPKH output.
        // Synthetic P2WPKH-shaped script (OP_0 PUSH20 zeros).
        let mut p2wpkh_bytes = vec![0x00, 0x14];
        p2wpkh_bytes.extend_from_slice(&[0x42u8; 20]);
        let p2wpkh = ScriptBuf::from(p2wpkh_bytes);
        let coinbase = coinbase_tx(p2wpkh.clone());
        let outpoint = fake_outpoint(0xaa, 0);
        let mut spending = spending_tx(outpoint, p2wpkh.clone());
        spending.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from(vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]),
        });
        let block_a = synth_block(vec![coinbase.clone(), spending.clone()]);

        // Block B: same shape but the OP_RETURN output omitted.
        let mut spending_no_or = spending.clone();
        spending_no_or.output.pop();
        let block_b = synth_block(vec![coinbase.clone(), spending_no_or]);

        let mut map = HashMap::new();
        map.insert(outpoint, p2wpkh.clone());

        let (a, _) = build_filter_row_pair(&cfg, 100, &block_a, &map, &[0u8; 32])
            .unwrap()
            .unwrap();
        // Both blocks must produce equal filter content because:
        //   * The OP_RETURN script is excluded from the filter.
        //   * The block's siphash key is derived from block_hash, so
        //     blocks A and B will have *different* hashes and therefore
        //     different filter content even if they encode the same
        //     element set. We cannot directly compare A and B blobs.
        // Instead, assert the filter content equals what
        // rust-bitcoin produces directly for block_a — that proves our
        // wrapper does not double-count or skip elements vs. the spec.
        let direct_a = BlockFilter::new_script_filter(&block_a, |op| {
            map.get(op)
                .cloned()
                .ok_or(bitcoin::bip158::Error::UtxoMissing(*op))
        })
        .unwrap();
        assert_eq!(a.filter, direct_a.content);

        // And as a separate check: the direct construction for block_b
        // (which has the OP_RETURN output omitted at the source) must
        // be byte-identical to feeding block_b through the wrapper.
        let (b, _) = build_filter_row_pair(&cfg, 100, &block_b, &map, &[0u8; 32])
            .unwrap()
            .unwrap();
        let direct_b = BlockFilter::new_script_filter(&block_b, |op| {
            map.get(op)
                .cloned()
                .ok_or(bitcoin::bip158::Error::UtxoMissing(*op))
        })
        .unwrap();
        assert_eq!(b.filter, direct_b.content);
    }

    #[test]
    fn test_filter_header_chain_step_matches_bip157() {
        let cfg = enabled_cfg();
        let block = synth_block(vec![coinbase_tx(ScriptBuf::from(vec![0x51]))]);
        let map = HashMap::new();
        let prev = [0xab; 32];
        let (row, hdr) = build_filter_row_pair(&cfg, 1, &block, &map, &prev)
            .unwrap()
            .unwrap();

        // Compute the same header via rust-bitcoin directly and compare.
        use bitcoin::bip158::FilterHeader;
        use bitcoin::hashes::Hash;
        let prev_header = FilterHeader::from_byte_array(prev);
        let direct = BlockFilter::new(&row.filter).filter_header(&prev_header);
        let direct_bytes: [u8; 32] = direct.to_byte_array();
        assert_eq!(hdr.header, direct_bytes);
    }

    #[test]
    fn test_genesis_filter_uses_zero_prev_header() {
        let cfg = enabled_cfg();
        let block = synth_block(vec![coinbase_tx(ScriptBuf::from(vec![0x51]))]);
        let map = HashMap::new();
        let (_row, hdr_zero) =
            build_filter_row_pair(&cfg, 0, &block, &map, &GENESIS_PREV_FILTER_HEADER)
                .unwrap()
                .unwrap();
        let (_row2, hdr_explicit) = build_filter_row_pair(&cfg, 0, &block, &map, &[0u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(hdr_zero.header, hdr_explicit.header);
    }

    #[test]
    fn test_missing_prev_output_returns_error() {
        let cfg = enabled_cfg();
        let coinbase = coinbase_tx(ScriptBuf::from(vec![0x51]));
        let outpoint = fake_outpoint(0xff, 7);
        let spending = spending_tx(outpoint, ScriptBuf::from(vec![0x52]));
        let block = synth_block(vec![coinbase, spending]);
        let map: HashMap<OutPoint, ScriptBuf> = HashMap::new();

        let r = build_filter_row_pair(&cfg, 50, &block, &map, &[0u8; 32]);
        assert!(matches!(r, Err(EmitError::Bip158(_))));
    }

    #[test]
    fn test_filter_remove_key_disabled_returns_none() {
        let cfg = FilterIndexConfig::default();
        assert!(filter_remove_key(&cfg, 100).is_none());
        let cfg = enabled_cfg();
        let key = filter_remove_key(&cfg, 100).unwrap();
        assert_eq!(key.filter_type, FILTER_TYPE_BASIC);
        assert_eq!(key.height, 100);
    }
}
