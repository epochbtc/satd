//! Electrum-spec merkle proof construction.
//!
//! Two helpers:
//! - [`compute_merkle_branch`] returns the bottom-up sibling sequence
//!   for a tx at a given position within a block's tx list. The
//!   protocol expects this branch in display-order hex; serialization
//!   happens at the response-shaping layer in
//!   [`crate::types::merkle_node_to_hex`].
//! - [`merkle_root`] is provided so callers can verify a constructed
//!   branch against a block's known root in tests.
//!
//! The pairing rule is Bitcoin's standard `sha256d` of concatenated
//! sibling hashes with odd-out duplication (the last hash at each
//! level is paired with itself when the level has an odd count).
//!
//! Design lineage: matches `romanz/electrs`'s
//! `blockchain.transaction.get_merkle` shape and Bitcoin Core's
//! historical `getmerkleproof`.

use bitcoin::TxMerkleNode;
use bitcoin::hashes::Hash as _;
use bitcoin::hashes::sha256d;

/// Compute the inclusion branch for `pos` within `txids`. Returns the
/// bottom-up sibling sequence; an empty `Vec` for a single-tx block (the
/// tx hash IS the root) or for `pos >= txids.len()`.
///
/// `txids` is read in chain order; sibling output is in
/// `bitcoin::TxMerkleNode` form, which the wire-shaping layer renders
/// as display-order hex.
pub fn compute_merkle_branch(txids: &[bitcoin::Txid], pos: usize) -> Vec<TxMerkleNode> {
    if txids.is_empty() || pos >= txids.len() {
        return Vec::new();
    }

    let mut current: Vec<[u8; 32]> = txids
        .iter()
        .map(|t| t.to_raw_hash().to_byte_array())
        .collect();
    let mut idx = pos;
    let mut branch: Vec<TxMerkleNode> = Vec::new();

    while current.len() > 1 {
        // Bitcoin convention: when a level has an odd count, the last
        // hash is duplicated before pairing.
        if !current.len().is_multiple_of(2) {
            current.push(*current.last().unwrap());
        }
        let sib = current[idx ^ 1];
        let sib_hash = sha256d::Hash::from_byte_array(sib);
        branch.push(TxMerkleNode::from_raw_hash(sib_hash));

        let mut next = Vec::with_capacity(current.len() / 2);
        for i in (0..current.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&current[i]);
            combined[32..].copy_from_slice(&current[i + 1]);
            let h = sha256d::Hash::hash(&combined);
            next.push(h.to_byte_array());
        }
        current = next;
        idx /= 2;
    }
    branch
}

/// Compute the merkle root over `txids` using the same pairing rule
/// (`sha256d`, odd-out duplication). Used in tests to verify a
/// constructed branch reconstructs the expected root, and exposed in
/// case future handlers need the root directly.
pub fn merkle_root(txids: &[bitcoin::Txid]) -> Option<TxMerkleNode> {
    if txids.is_empty() {
        return None;
    }
    let mut current: Vec<[u8; 32]> = txids
        .iter()
        .map(|t| t.to_raw_hash().to_byte_array())
        .collect();
    while current.len() > 1 {
        if !current.len().is_multiple_of(2) {
            current.push(*current.last().unwrap());
        }
        let mut next = Vec::with_capacity(current.len() / 2);
        for i in (0..current.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&current[i]);
            combined[32..].copy_from_slice(&current[i + 1]);
            next.push(sha256d::Hash::hash(&combined).to_byte_array());
        }
        current = next;
    }
    Some(TxMerkleNode::from_raw_hash(sha256d::Hash::from_byte_array(
        current[0],
    )))
}

/// Reconstruct a candidate root from `tx_hash` + its computed `branch`
/// at `pos`. Used in tests (and available to future client-side
/// helpers) to verify a returned branch.
pub fn root_from_branch(
    tx_hash: bitcoin::Txid,
    branch: &[TxMerkleNode],
    mut pos: usize,
) -> TxMerkleNode {
    let mut acc = tx_hash.to_raw_hash().to_byte_array();
    for sibling in branch {
        let sib = sibling.to_raw_hash().to_byte_array();
        let mut combined = [0u8; 64];
        // pos's low bit = 0 → acc is left, sibling is right; else swap.
        if pos & 1 == 0 {
            combined[..32].copy_from_slice(&acc);
            combined[32..].copy_from_slice(&sib);
        } else {
            combined[..32].copy_from_slice(&sib);
            combined[32..].copy_from_slice(&acc);
        }
        acc = sha256d::Hash::hash(&combined).to_byte_array();
        pos /= 2;
    }
    TxMerkleNode::from_raw_hash(sha256d::Hash::from_byte_array(acc))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_txid(byte: u8) -> bitcoin::Txid {
        bitcoin::Txid::from_raw_hash(sha256d::Hash::from_byte_array([byte; 32]))
    }

    #[test]
    fn single_tx_branch_empty_and_root_eq_tx() {
        let txids = vec![fixture_txid(1)];
        assert!(compute_merkle_branch(&txids, 0).is_empty());
        let root = merkle_root(&txids).unwrap();
        assert_eq!(
            root.to_raw_hash().to_byte_array(),
            txids[0].to_raw_hash().to_byte_array()
        );
    }

    #[test]
    fn branch_reconstructs_root_two_txs() {
        let txids: Vec<_> = (1u8..=2).map(fixture_txid).collect();
        let root = merkle_root(&txids).unwrap();
        for pos in 0..txids.len() {
            let branch = compute_merkle_branch(&txids, pos);
            let recon = root_from_branch(txids[pos], &branch, pos);
            assert_eq!(
                recon.to_raw_hash().to_byte_array(),
                root.to_raw_hash().to_byte_array(),
                "branch reconstruction failed at pos {pos}"
            );
        }
    }

    #[test]
    fn branch_reconstructs_root_seven_txs_odd_out() {
        // Seven leaves exercises the odd-out duplication at every
        // level (level 0: 7 → pad to 8; level 1: 4; level 2: 2).
        let txids: Vec<_> = (1u8..=7).map(fixture_txid).collect();
        let root = merkle_root(&txids).unwrap();
        for pos in 0..txids.len() {
            let branch = compute_merkle_branch(&txids, pos);
            assert_eq!(branch.len(), 3, "expected 3-level branch at pos {pos}");
            let recon = root_from_branch(txids[pos], &branch, pos);
            assert_eq!(
                recon.to_raw_hash().to_byte_array(),
                root.to_raw_hash().to_byte_array(),
                "pos {pos}"
            );
        }
    }

    #[test]
    fn branch_length_log2_for_powers_of_two() {
        for &(n, expected) in &[(2usize, 1), (4, 2), (8, 3), (16, 4)] {
            let txids: Vec<_> = (0u8..n as u8).map(fixture_txid).collect();
            for pos in 0..n {
                assert_eq!(
                    compute_merkle_branch(&txids, pos).len(),
                    expected,
                    "n={n} pos={pos}"
                );
            }
        }
    }

    #[test]
    fn out_of_range_pos_returns_empty() {
        let txids: Vec<_> = (1u8..=4).map(fixture_txid).collect();
        assert!(compute_merkle_branch(&txids, 4).is_empty());
        assert!(compute_merkle_branch(&txids, usize::MAX).is_empty());
    }

    #[test]
    fn empty_txids_yields_no_root() {
        assert!(merkle_root(&[]).is_none());
    }
}
