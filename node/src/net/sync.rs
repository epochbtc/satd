use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::BlockHash;

use crate::chain::state::ChainState;

/// Build a block locator for getheaders messages.
/// Returns hashes at heights: tip, tip-1, ..., tip-10, then exponentially spaced.
pub fn build_locator(chain_state: &ChainState) -> Vec<BlockHash> {
    let tip_height = chain_state.tip_height();
    let mut locator = Vec::new();
    let mut step = 1u32;
    let mut height = tip_height as i64;

    while height >= 0 {
        if let Some(hash) = chain_state.get_block_hash_by_height(height as u32) {
            locator.push(hash);
        }
        if locator.len() >= 10 {
            step *= 2;
        }
        height -= step as i64;
    }

    // Always include genesis
    if let Some(hash) = chain_state.get_block_hash_by_height(0) {
        if locator.last() != Some(&hash) {
            locator.push(hash);
        }
    }

    locator
}

/// Create a GetHeaders message using the current chain state.
pub fn make_getheaders(chain_state: &ChainState) -> NetworkMessage {
    let locator = build_locator(chain_state);
    NetworkMessage::GetHeaders(GetHeadersMessage::new(
        locator,
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32])),
    ))
}

/// Create an Inv message for a block hash.
pub fn make_block_inv(hash: BlockHash) -> NetworkMessage {
    NetworkMessage::Inv(vec![Inventory::WitnessBlock(hash)])
}

/// Create a GetData message for block hashes.
pub fn make_getdata_blocks(hashes: &[BlockHash]) -> NetworkMessage {
    let inv: Vec<Inventory> = hashes
        .iter()
        .map(|h| Inventory::WitnessBlock(*h))
        .collect();
    NetworkMessage::GetData(inv)
}

/// Create a GetData message for transaction IDs.
pub fn make_getdata_txs(txids: &[bitcoin::Txid]) -> NetworkMessage {
    let inv: Vec<Inventory> = txids
        .iter()
        .map(|t| Inventory::WitnessTransaction(*t))
        .collect();
    NetworkMessage::GetData(inv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;
    use bitcoin::Network;

    #[test]
    fn test_build_locator_genesis_only() {
        let dir = std::env::temp_dir().join(format!("btcd-sync-test-{}", std::process::id()));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(store, flat_files, Network::Regtest, Box::new(NoopVerifier), None).unwrap();

        let locator = build_locator(&cs);
        assert!(!locator.is_empty());
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        assert_eq!(locator[0], genesis.block_hash());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
