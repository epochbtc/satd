//! Serve-side joins for silent-payment tweak rows.
//!
//! The `sp_tweaks` index is deliberately lean: one 33-byte tweak per eligible
//! transaction, plus the txid and the largest taproot output's value. It stores
//! **no per-output data**, because every serving surface that needs the outputs
//! already holds the block they came from.
//!
//! Two surfaces need exactly that join — the streaming `tweaks` category
//! (`tweak_outputs` / `tweak_unspent_only`) and the Electrum
//! `blockchain.tweaks.subscribe` stream, whose wire format always carries the
//! outputs. This module is the one implementation both use, so a client cannot
//! see different output sets depending on which surface it asked through.

use std::collections::{HashMap, HashSet};

use bitcoin::{Block, OutPoint, Txid};

use crate::events::SpTaprootOutput;

/// Enumerate the taproot outputs of each transaction named in `wanted`, as they
/// appear in `block`.
///
/// The set is always complete — every taproot output of the transaction, spent
/// or not. Cut-through is expressed by dropping whole entries via
/// [`any_unspent`], never by trimming this list: see that function for why.
///
/// Reading the returned map:
///
/// - **txid absent** — the block does not contain that transaction. That is a
///   reorg race between the index row and the block read, not evidence about
///   spentness, so a caller filtering on spentness must not treat it as "all
///   spent".
/// - **txid present** — the transaction is in the block, and the vec is its
///   taproot outputs in vout order (empty only if it has none, which the index
///   never writes an entry for).
pub fn taproot_outputs_by_txid(
    block: &Block,
    wanted: &HashSet<Txid>,
) -> HashMap<Txid, Vec<SpTaprootOutput>> {
    let mut by_txid: HashMap<Txid, Vec<SpTaprootOutput>> = HashMap::new();
    for tx in &block.txdata {
        let txid = tx.compute_txid();
        if !wanted.contains(&txid) {
            continue;
        }
        by_txid.insert(txid, SpTaprootOutput::from_tx(tx));
        // Every wanted txid appears at most once in a block (duplicate txids
        // are a consensus failure), so there is nothing to merge.
    }
    by_txid
}

/// Whether any of `outs` (the taproot outputs of `txid`) is still unspent.
///
/// This is the whole of the cut-through decision, and it is deliberately
/// entry-level. Spentness may decide that an entry is *gone*; it must never
/// decide which outputs a surviving entry carries. BIP 352 scanning walks
/// `k = 0, 1, 2, …` and stops at the first `k` with no match among the outputs
/// it was handed, so serving only the unspent subset would truncate the walk: a
/// wallet paid twice in one transaction that has since spent its `k = 0` coin
/// would derive `P_0`, miss, stop, and never reach the `k = 1` coin it still
/// owns. A transaction with nothing left unspent holds no coin at any `k`, so
/// dropping it whole loses nothing.
///
/// The predicate is a callback rather than a chain handle so this stays usable
/// from both carriers and from tests without a store. It short-circuits, so the
/// common case (a live coin early in the list) costs one lookup.
pub fn any_unspent(
    txid: Txid,
    outs: &[SpTaprootOutput],
    is_unspent: &dyn Fn(&OutPoint) -> bool,
) -> bool {
    outs.iter().any(|o| is_unspent(&OutPoint { txid, vout: o.vout }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};

    /// A raw `OP_1 <32-byte push>` scriptPubKey. The join slices the push out
    /// verbatim and never lifts it to a curve point, so any 32 bytes will do.
    fn p2tr(key: [u8; 32]) -> ScriptBuf {
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&key);
        ScriptBuf::from(spk)
    }

    fn block_with(outs: Vec<TxOut>) -> (Block, Txid) {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: outs,
        };
        let txid = tx.compute_txid();
        let block = Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::TWO,
                prev_blockhash: bitcoin::BlockHash::from_raw_hash(
                    bitcoin::hashes::Hash::all_zeros(),
                ),
                merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                    bitcoin::hashes::Hash::all_zeros(),
                ),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![tx],
        };
        (block, txid)
    }

    fn sample() -> (Block, Txid) {
        block_with(vec![
            TxOut { value: Amount::from_sat(4_000), script_pubkey: p2tr([0x02; 32]) },
            // Non-taproot: never enumerated, and must not shift the vout of
            // the taproot output that follows it.
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from(vec![0x00, 0x14]),
            },
            TxOut { value: Amount::from_sat(9_000), script_pubkey: p2tr([0x03; 32]) },
        ])
    }

    #[test]
    fn enumerates_taproot_outputs_in_vout_order() {
        let (block, txid) = sample();
        let wanted = [txid].into_iter().collect();
        let got = taproot_outputs_by_txid(&block, &wanted);
        let outs = got.get(&txid).expect("txid is in the block");
        assert_eq!(outs.len(), 2);
        assert_eq!((outs[0].vout, outs[0].value), (0, 4_000));
        assert_eq!((outs[1].vout, outs[1].value), (2, 9_000));
    }

    #[test]
    fn a_spent_output_is_still_enumerated() {
        // The join never trims: cut-through is an entry-level drop, so a
        // surviving entry must carry the spent output too or BIP 352 `k`
        // enumeration stops at it and hides every higher-k coin.
        let (block, txid) = sample();
        let wanted = [txid].into_iter().collect();
        let spent = OutPoint { txid, vout: 0 };
        let got = taproot_outputs_by_txid(&block, &wanted);
        let outs = got.get(&txid).expect("txid is in the block");
        assert_eq!(outs.len(), 2, "the full candidate set, spent outputs included");
        assert!(any_unspent(txid, outs, &|op: &OutPoint| *op != spent));
    }

    #[test]
    fn any_unspent_is_false_only_when_every_output_is_spent() {
        let (block, txid) = sample();
        let wanted = [txid].into_iter().collect();
        let got = taproot_outputs_by_txid(&block, &wanted);
        let outs = got.get(&txid).expect("in the block");
        // Nothing left: this is the case a caller drops.
        assert!(!any_unspent(txid, outs, &|_: &OutPoint| false));
        // Anything left: the entry survives, carrying all of `outs`.
        assert!(any_unspent(txid, outs, &|_: &OutPoint| true));
    }

    #[test]
    fn a_txid_the_block_does_not_carry_is_absent_not_empty() {
        // Absent: a txid the block does not carry says nothing about spentness,
        // so it must not be confusable with "all spent".
        let (block, _txid) = sample();
        let (other, other_txid) = block_with(vec![TxOut {
            value: Amount::from_sat(7),
            script_pubkey: p2tr([0x09; 32]),
        }]);
        let _ = other;
        let got = taproot_outputs_by_txid(&block, &[other_txid].into_iter().collect());
        assert!(!got.contains_key(&other_txid));
    }

    #[test]
    fn untracked_transactions_are_not_enumerated() {
        let (block, _txid) = sample();
        let got = taproot_outputs_by_txid(&block, &HashSet::new());
        assert!(got.is_empty(), "only the named transactions are walked");
    }
}
