//! Headers and blocks are held to the network's proof-of-work limit, as
//! Core's `CheckProofOfWork` holds them to `powLimit` (`pow.cpp`
//! `DeriveTarget`), on both the header path (`validation.cpp`
//! `CheckBlockHeader`) and the block path (`CheckBlock`).
//!
//! On signet `check_difficulty` does not pin `nBits` to the retarget
//! schedule, so before this the only check on a signet header's work was the
//! header's own claimed target.

use super::tests::{build_test_block, grind_test_pow, make_chain_state};
use super::*;
use crate::storage::db::InMemoryStore;
use crate::storage::flatfile::FlatFileManager;

fn chain_state_on(network: Network) -> (ChainState, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let cs = ChainState::new(
        Box::new(InMemoryStore::new()),
        FlatFileManager::new(&dir.path().join("blocks")).unwrap(),
        network,
        Box::new(crate::validation::script::NoopVerifier),
        AssumeValid::Disabled,
        450,
        4,
        Default::default(),
        Default::default(),
        Default::default(),
    )
    .unwrap();
    (cs, dir)
}

/// A block on `network`'s genesis claiming the regtest target `0x207fffff`.
fn easy_block(network: Network) -> Block {
    let parent = bitcoin::constants::genesis_block(network).block_hash();
    let genesis_time = bitcoin::constants::genesis_block(network).header.time;
    let mut block = build_test_block(parent, 1, genesis_time + 600);
    block.header.bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
    grind_test_pow(&mut block);
    block
}

fn is_bad_pow(e: &ChainError) -> bool {
    matches!(e, ChainError::Validation(crate::validation::ValidationError::BadProofOfWork))
}

#[test]
fn signet_header_easier_than_pow_limit_is_rejected() {
    let (cs, _dir) = chain_state_on(Network::Signet);
    let block = easy_block(Network::Signet);
    let hash = block.block_hash();

    let (accepted, err) = cs.accept_headers(&[block.header]);
    assert_eq!(accepted, 0);
    assert!(err.as_ref().is_some_and(is_bad_pow), "accept_headers: {err:?}");
    let err = cs.accept_header(&block.header).unwrap_err();
    assert!(is_bad_pow(&err), "accept_header: {err:?}");
    assert!(cs.get_block_index(&hash).is_none(), "no index row for the header");
}

#[test]
fn signet_block_easier_than_pow_limit_is_rejected() {
    let (cs, _dir) = chain_state_on(Network::Signet);
    let block = easy_block(Network::Signet);
    let err = cs.accept_block(&block).unwrap_err();
    assert!(is_bad_pow(&err), "accept_block: {err:?}");
}

/// The bound is the network's own limit: on regtest `0x207fffff` is the limit
/// itself, and headers and blocks at it are accepted.
#[test]
fn regtest_header_and_block_at_pow_limit_are_accepted() {
    let (cs, _path) = make_chain_state();
    let block = easy_block(Network::Regtest);
    let (accepted, err) = cs.accept_headers(&[block.header]);
    assert_eq!((accepted, err.map(|e| e.to_string())), (1, None));
    cs.accept_block(&block).expect("regtest block at powLimit connects");
    assert_eq!(cs.tip_height(), 1);
}
