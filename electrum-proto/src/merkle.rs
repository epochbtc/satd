//! Electrum-spec merkle proof construction.
//!
//! ## Vendoring
//!
//! The `Proof` struct, `Proof::create`, and `Proof::to_hex` below are
//! vendored verbatim from `romanz/electrs` v0.11.1
//! (commit `35216c6d30148be8e6763d913d437330f431fc03`), file
//! `src/merkle.rs`. License: MIT — see `vendor/electrs.MIT` for the
//! upstream LICENSE text and full attribution.
//!
//! The pairing rule is Bitcoin's standard `sha256d` of concatenated
//! sibling hashes with odd-out duplication (the last hash at each
//! level is paired with itself when the level has an odd count).
//!
//! The thin wrapper helpers below ([`compute_merkle_branch`],
//! [`merkle_root`], [`root_from_branch`]) are satd-local conveniences
//! used by [`crate::extras::RocksElectrumExtras::tx_merkle`] and unit
//! tests; they are NOT vendored.

use bitcoin::TxMerkleNode;
use bitcoin::Txid;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256d;

// ── Vendored: romanz/electrs v0.11.1 src/merkle.rs (MIT) ──────────
//
// Copyright (c) 2018-2024 Roman Zeyde and contributors.
// See vendor/electrs.MIT.
//
// `clippy::manual_is_multiple_of` is allowed across the vendored
// block because rewriting `% 2` to `is_multiple_of(2)` would diverge
// from the upstream source — the whole point of vendoring this file
// is byte-equivalence with electrs.

/// Bottom-up Electrum merkle proof: the sibling sequence consumed by
/// `blockchain.transaction.get_merkle` clients to verify inclusion.
pub struct Proof {
    proof: Vec<TxMerkleNode>,
    position: usize,
}

impl Proof {
    #[allow(clippy::manual_is_multiple_of)]
    pub fn create(txids: &[Txid], position: usize) -> Self {
        assert!(position < txids.len());
        let mut offset = position;
        let mut hashes: Vec<TxMerkleNode> = txids
            .iter()
            .map(|txid| TxMerkleNode::from_raw_hash(txid.to_raw_hash()))
            .collect();

        let mut proof = vec![];
        while hashes.len() > 1 {
            if hashes.len() % 2 != 0 {
                let last = *hashes.last().unwrap();
                hashes.push(last);
            }
            offset = if offset % 2 == 0 {
                offset + 1
            } else {
                offset - 1
            };
            proof.push(hashes[offset]);
            offset /= 2;
            hashes = hashes
                .chunks(2)
                .map(|pair| {
                    let left = pair[0];
                    let right = pair[1];
                    let input = [&left[..], &right[..]].concat();
                    TxMerkleNode::hash(&input)
                })
                .collect()
        }
        Self { proof, position }
    }

    pub fn to_hex(&self) -> Vec<String> {
        self.proof
            .iter()
            .map(|node| format!("{:x}", node))
            .collect()
    }

    pub fn position(&self) -> usize {
        self.position
    }

    /// Borrow the underlying sibling sequence. satd-local — used by
    /// the verify helpers below.
    pub fn branch(&self) -> &[TxMerkleNode] {
        &self.proof
    }
}

// ── End vendored block ────────────────────────────────────────────

/// Compute the inclusion branch for `pos` within `txids`. Wraps
/// [`Proof::create`] for callers that just want the sibling sequence
/// (e.g. [`crate::extras::RocksElectrumExtras::tx_merkle`]). Returns
/// an empty `Vec` for an out-of-range `pos` or an empty `txids` —
/// `Proof::create` would panic in that case, so the wrapper guards it.
pub fn compute_merkle_branch(txids: &[Txid], pos: usize) -> Vec<TxMerkleNode> {
    if txids.is_empty() || pos >= txids.len() {
        return Vec::new();
    }
    Proof::create(txids, pos).proof
}

/// Compute the merkle root over `txids` using Bitcoin's pairing rule
/// (`sha256d`, odd-out duplication). Used in tests to verify a
/// constructed branch reconstructs the expected root.
pub fn merkle_root(txids: &[Txid]) -> Option<TxMerkleNode> {
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
/// at `pos`. Used in tests to verify a returned branch.
pub fn root_from_branch(tx_hash: Txid, branch: &[TxMerkleNode], mut pos: usize) -> TxMerkleNode {
    let mut acc = tx_hash.to_raw_hash().to_byte_array();
    for sibling in branch {
        let sib = sibling.to_raw_hash().to_byte_array();
        let mut combined = [0u8; 64];
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

    fn fixture_txid(byte: u8) -> Txid {
        Txid::from_raw_hash(sha256d::Hash::from_byte_array([byte; 32]))
    }

    #[test]
    fn proof_create_position_round_trip() {
        let txids: Vec<_> = (1u8..=4).map(fixture_txid).collect();
        let p = Proof::create(&txids, 2);
        assert_eq!(p.position(), 2);
    }

    #[test]
    fn proof_to_hex_lowercase_display_order() {
        let txids: Vec<_> = (1u8..=2).map(fixture_txid).collect();
        let p = Proof::create(&txids, 0);
        let hex = p.to_hex();
        assert_eq!(hex.len(), 1);
        // 32 hex bytes per node (no 0x prefix), all lowercase, display
        // (reversed) order. Sibling is fixture_txid(2) which is all
        // 0x02 bytes — display-order reversal is a no-op for a
        // constant-byte hash.
        assert_eq!(hex[0], "02".repeat(32));
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

    #[test]
    fn proof_create_matches_compute_merkle_branch() {
        // Cross-check that the vendored Proof::create produces the
        // same branch as our existing wrapper. This is a guard against
        // accidental drift if either side is edited.
        let txids: Vec<_> = (1u8..=11).map(fixture_txid).collect();
        for pos in 0..txids.len() {
            let p = Proof::create(&txids, pos);
            let wrapper = compute_merkle_branch(&txids, pos);
            assert_eq!(p.branch(), wrapper.as_slice(), "pos={pos}");
        }
    }
}
