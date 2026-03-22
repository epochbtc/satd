use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::BlockHash;

use crate::chain::state::ChainState;

/// Build a block locator for getheaders messages.
/// Uses the highest header height (not block tip) so headers can run ahead of blocks during IBD.
/// Returns hashes at heights: tip, tip-1, ..., tip-10, then exponentially spaced.
pub fn build_locator(chain_state: &ChainState) -> Vec<BlockHash> {
    let tip_height = chain_state.headers_tip_height().max(chain_state.tip_height());
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
    if let Some(hash) = chain_state.get_block_hash_by_height(0)
        && locator.last() != Some(&hash) {
            locator.push(hash);
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
    use crate::chain::state::AssumeValid;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;
    use bitcoin::Network;

    #[test]
    fn test_build_locator_genesis_only() {
        let dir = std::env::temp_dir().join(format!("satd-sync-test-{}", std::process::id()));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(store, flat_files, Network::Regtest, Box::new(NoopVerifier), AssumeValid::Disabled, 450).unwrap();

        let locator = build_locator(&cs);
        assert!(!locator.is_empty());
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        assert_eq!(locator[0], genesis.block_hash());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_locator_always_includes_genesis() {
        use crate::chain::state::tests::build_test_block;

        let dir = std::env::temp_dir().join(format!(
            "satd-sync-locator-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
        )
        .unwrap();

        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let genesis_hash = genesis.block_hash();

        // Build a chain of several blocks (timestamps must be > genesis time 1296688602)
        let mut parent = genesis_hash;
        for h in 1..=20u32 {
            let block = build_test_block(parent, h, 1_300_000_000 + h);
            cs.accept_block(&block).unwrap();
            parent = block.block_hash();
        }
        assert_eq!(cs.tip_height(), 20);

        let locator = build_locator(&cs);
        // The locator must always include the genesis hash as the last entry
        assert!(!locator.is_empty());
        assert_eq!(
            *locator.last().unwrap(),
            genesis_hash,
            "Locator must end with genesis hash"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_make_getdata_blocks() {
        use bitcoin::hashes::Hash;

        let h1 = BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x01; 32]),
        );
        let h2 = BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x02; 32]),
        );
        let h3 = BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x03; 32]),
        );

        let msg = make_getdata_blocks(&[h1, h2, h3]);
        match msg {
            NetworkMessage::GetData(inv) => {
                assert_eq!(inv.len(), 3);
                assert_eq!(inv[0], Inventory::WitnessBlock(h1));
                assert_eq!(inv[1], Inventory::WitnessBlock(h2));
                assert_eq!(inv[2], Inventory::WitnessBlock(h3));
            }
            _ => panic!("Expected GetData message"),
        }
    }

    #[test]
    fn test_make_getdata_txs() {
        use bitcoin::hashes::Hash;

        let t1 = bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]),
        );
        let t2 = bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0xbb; 32]),
        );

        let msg = make_getdata_txs(&[t1, t2]);
        match msg {
            NetworkMessage::GetData(inv) => {
                assert_eq!(inv.len(), 2);
                assert_eq!(inv[0], Inventory::WitnessTransaction(t1));
                assert_eq!(inv[1], Inventory::WitnessTransaction(t2));
            }
            _ => panic!("Expected GetData message"),
        }
    }

    #[test]
    fn test_make_getheaders() {
        let dir = std::env::temp_dir().join(format!(
            "satd-sync-getheaders-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
        )
        .unwrap();

        let msg = make_getheaders(&cs);
        match msg {
            NetworkMessage::GetHeaders(_) => {
                // Success — it returned a GetHeaders message
            }
            _ => panic!("Expected GetHeaders message"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
