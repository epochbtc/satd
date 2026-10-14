//! The retarget seed comes from the candidate's own branch, and the testnet
//! 20-minute rule cannot overflow.

use super::*;
use crate::storage::blockindex::BlockStatus;
use bitcoin::hashes::Hash as _;
use std::collections::HashMap;

fn entry(prev: BlockHash, height: u32, time: u32, bits: u32, tag: u32) -> BlockIndexEntry {
    BlockIndexEntry {
        header: Header {
            version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: prev,
            // Distinguishes the two branches' blocks at one height.
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([tag as u8; 32]),
            time,
            bits: CompactTarget::from_consensus(bits),
            nonce: height,
        },
        height,
        status: BlockStatus::Valid,
        num_tx: 1,
        file_number: 0,
        data_pos: 0,
        chainwork: [0u8; 32],
    }
}

/// Extend `from` to `to_height` (inclusive), one block every `spacing`
/// seconds, adding each entry to `index`. Returns the last entry.
fn extend(
    index: &mut HashMap<BlockHash, BlockIndexEntry>,
    from: &BlockIndexEntry,
    to_height: u32,
    spacing: u32,
    tag: u32,
) -> BlockIndexEntry {
    let mut cur = from.clone();
    for h in (from.height + 1)..=to_height {
        let e = entry(cur.header.block_hash(), h, cur.header.time + spacing, MAINNET_POWLIMIT_BITS, tag);
        index.insert(e.header.block_hash(), e.clone());
        cur = e;
    }
    cur
}

/// Two branches that fork at height 1000, below the period that starts at
/// 2016. The block at 4032 on the second branch is judged against that
/// branch's own period start (Core: `pindexLast->GetAncestor(nHeightFirst)`,
/// `pow.cpp` `GetNextWorkRequired`), whatever chain the height index
/// follows.
#[test]
fn retarget_seed_is_the_branchs_own_ancestor() {
    let mut index = HashMap::new();
    let root = entry(BlockHash::all_zeros(), 0, 1_300_000_000, MAINNET_POWLIMIT_BITS, 0);
    index.insert(root.header.block_hash(), root.clone());
    let fork = extend(&mut index, &root, 1000, 600, 0);
    // A height index would follow branch A; the seed must not come from it.
    let a_tip = extend(&mut index, &fork, 4031, 600, 1);
    let b_tip = extend(&mut index, &fork, 4031, 450, 2);

    let mut a_rows = HashMap::new();
    let mut cur = a_tip.clone();
    loop {
        a_rows.insert(cur.height, cur.clone());
        match index.get(&cur.header.prev_blockhash) {
            Some(p) => cur = p.clone(),
            None => break,
        }
    }
    let mut b_first = b_tip.clone();
    while b_first.height > 2016 {
        b_first = index[&b_first.header.prev_blockhash].clone();
    }
    let expected = retarget(
        b_tip.header.bits,
        (b_tip.header.time - b_first.header.time).clamp(TARGET_TIMESPAN / 4, TARGET_TIMESPAN * 4),
        MAINNET_POWLIMIT_BITS,
    );
    let a_seeded = retarget(
        b_tip.header.bits,
        (b_tip.header.time - a_rows[&2016].header.time).clamp(TARGET_TIMESPAN / 4, TARGET_TIMESPAN * 4),
        MAINNET_POWLIMIT_BITS,
    );
    assert_ne!(expected, a_seeded, "fixture: the two seeds must give different bits");

    for network in [Network::Bitcoin, Network::Testnet, Network::Testnet4] {
        let bits = next_bits(
            network,
            &b_tip,
            b_tip.header.time + 600,
            |h| index.get(h).cloned(),
        )
        .unwrap();
        assert_eq!(bits.to_consensus(), expected, "{network:?}: seeded from the other branch");
    }
}

/// The retarget fails closed when an ancestor in the period is missing.
#[test]
fn retarget_seed_missing_ancestor_fails_closed() {
    let mut index = HashMap::new();
    let root = entry(BlockHash::all_zeros(), 0, 1_300_000_000, MAINNET_POWLIMIT_BITS, 0);
    index.insert(root.header.block_hash(), root.clone());
    let tip = extend(&mut index, &root, 2015, 600, 0);
    let mut hole = tip.clone();
    while hole.height > 1500 {
        hole = index[&hole.header.prev_blockhash].clone();
    }
    index.remove(&hole.header.block_hash());
    assert!(matches!(
        next_bits(Network::Bitcoin, &tip, tip.header.time + 600, |h| index.get(h).cloned()),
        Err(ValidationError::BadDifficulty)
    ));
}

/// The 20-minute rule compares in 64 bits, as Core does (`pow.cpp`
/// `GetNextWorkRequired`, `int64_t` block times). A parent timestamp within
/// 20 minutes of `u32::MAX` does not wrap.
#[test]
fn testnet_min_difficulty_rule_does_not_overflow() {
    let prev = entry(BlockHash::all_zeros(), 5, u32::MAX - 100, 0x1c00_ffff, 0);
    for network in [Network::Testnet, Network::Testnet4] {
        let bits = next_bits(network, &prev, u32::MAX, |_| None).unwrap();
        assert_eq!(bits.to_consensus(), 0x1c00_ffff, "{network:?}: within 20 minutes keeps the parent's bits");
    }
    let prev = entry(BlockHash::all_zeros(), 5, u32::MAX - 2000, 0x1c00_ffff, 0);
    for network in [Network::Testnet, Network::Testnet4] {
        let bits = next_bits(network, &prev, u32::MAX, |_| None).unwrap();
        assert_eq!(bits.to_consensus(), TESTNET_POWLIMIT_BITS, "{network:?}: after 20 minutes, minimum difficulty");
    }
}
