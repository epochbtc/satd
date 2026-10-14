use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::BlockHash;

use crate::chain::state::ChainState;

/// Build a block locator for getheaders messages.
/// Uses the highest header height (not block tip) so headers can run ahead of blocks during IBD.
/// Returns hashes at heights: tip, tip-1, ..., tip-10, then exponentially spaced.
pub fn build_locator(chain_state: &ChainState) -> Vec<BlockHash> {
    build_locator_from(chain_state, best_known_height(chain_state))
}

/// The height of the best header we know, or of the tip if no header runs
/// ahead of it.
fn best_known_height(chain_state: &ChainState) -> u32 {
    chain_state.headers_tip_height().max(chain_state.tip_height())
}

/// A block locator starting at `tip_height`.
fn build_locator_from(chain_state: &ChainState, tip_height: u32) -> Vec<BlockHash> {
    let mut locator = Vec::new();
    extend_locator_from_rows(chain_state, &mut locator, 1, tip_height as i64);
    locator
}

/// Continue `locator` down the height rows from `height`, spacing entries as
/// [`build_locator`] does (`step` is the current spacing), and end it with
/// genesis.
fn extend_locator_from_rows(
    chain_state: &ChainState,
    locator: &mut Vec<BlockHash>,
    mut step: u32,
    mut height: i64,
) {
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
}

/// How many parent links [`build_locator_for_branch`] follows before it
/// falls back to the height rows. The first locator entries are the ones a
/// peer on that branch matches; the cap bounds the index reads one locator
/// can cost when the branch is long and not on the height rows.
const BRANCH_LOCATOR_MAX_WALK: u32 = 4096;

/// A block locator that starts at `start` and follows `start`'s own branch
/// (Core's `GetLocator(pindex)`), not the node's height rows.
///
/// Once the branch reaches a block the height rows also hold, the rest of the
/// locator comes from the rows, which below that point are the same chain.
/// `None` if `start` is not in the block index.
pub fn build_locator_for_branch(chain_state: &ChainState, start: BlockHash) -> Option<Vec<BlockHash>> {
    let mut entry = chain_state.get_block_index(&start)?;
    let mut hash = start;
    let mut locator = Vec::new();
    let mut step = 1u32;
    let mut walked = 0u32;
    loop {
        if chain_state.get_block_hash_by_height(entry.height) == Some(hash) {
            extend_locator_from_rows(chain_state, &mut locator, step, entry.height as i64);
            return Some(locator);
        }
        locator.push(hash);
        if locator.len() >= 10 {
            step = step.saturating_mul(2);
        }
        let Some(target) = entry.height.checked_sub(step) else {
            // Below the first spaced entry: only genesis is left.
            extend_locator_from_rows(chain_state, &mut locator, step, -1);
            return Some(locator);
        };
        while entry.height > target {
            if walked >= BRANCH_LOCATOR_MAX_WALK {
                extend_locator_from_rows(chain_state, &mut locator, step, target as i64);
                return Some(locator);
            }
            hash = entry.header.prev_blockhash;
            match chain_state.get_block_index(&hash) {
                Some(parent) if parent.height + 1 == entry.height => entry = parent,
                _ => {
                    extend_locator_from_rows(chain_state, &mut locator, step, target as i64);
                    return Some(locator);
                }
            }
            walked += 1;
        }
    }
}

/// The `getheaders` that follows a full `headers` batch: it continues from
/// the last header the peer sent, as Core's `ProcessHeadersMessage` does
/// (`MaybeSendGetHeaders(pfrom, GetLocator(pindexLast))`). A locator from the
/// node's own height rows would not do: when those rows are on a competing
/// branch with more work than the peer's chain has shown so far, the peer
/// matches only the fork point and sends the same headers again.
pub fn make_getheaders_after(chain_state: &ChainState, last: BlockHash) -> NetworkMessage {
    match build_locator_for_branch(chain_state, last) {
        Some(locator) => NetworkMessage::GetHeaders(GetHeadersMessage::new(
            locator,
            BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32])),
        )),
        None => make_getheaders(chain_state),
    }
}

/// Create a GetHeaders message using the current chain state.
pub fn make_getheaders(chain_state: &ChainState) -> NetworkMessage {
    let locator = build_locator(chain_state);
    NetworkMessage::GetHeaders(GetHeadersMessage::new(
        locator,
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32])),
    ))
}

/// The `getheaders` that opens a connection. It starts one header below the
/// best we know, as Core's initial `getheaders` does (`SendMessages`, "start
/// at the block preceding the currently best known header"): a peer that is
/// up to date then answers with at least that header instead of with
/// nothing, and that header is how we learn the peer's best block. Without
/// it, a peer on our tip is known to have nothing until it next announces a
/// block, and `sendheaders` waits on exactly that knowledge.
pub fn make_initial_getheaders(chain_state: &ChainState) -> NetworkMessage {
    let locator = build_locator_from(chain_state, best_known_height(chain_state).saturating_sub(1));
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

/// Create a GetData message asking for one block as a BIP 152 `cmpctblock`
/// (`MSG_CMPCT_BLOCK`).
pub fn make_getdata_compact_block(hash: BlockHash) -> NetworkMessage {
    NetworkMessage::GetData(vec![Inventory::CompactBlock(hash)])
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
        let cs = ChainState::new(store, flat_files, Network::Regtest, Box::new(NoopVerifier), AssumeValid::Disabled, 450, 4, Default::default(), Default::default(), Default::default()).unwrap();

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
        4,
        Default::default(),
        Default::default(),
            Default::default(),)
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
        4,
        Default::default(),
        Default::default(),
            Default::default(),)
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

    /// The connection's first `getheaders` starts one below the best header,
    /// as Core's does, so a peer on the same tip answers with that header
    /// instead of an empty `headers`; on a chain of genesis alone there is
    /// nothing below, and it starts at genesis.
    #[test]
    fn the_initial_getheaders_starts_below_the_best_header() {
        use crate::chain::state::tests::{build_test_block, make_chain_state};
        let (cs, _dir) = make_chain_state();
        let genesis = bitcoin::constants::genesis_block(Network::Regtest).block_hash();
        let first_locator_hash = |msg: NetworkMessage| match msg {
            NetworkMessage::GetHeaders(g) => g.locator_hashes[0],
            other => panic!("expected getheaders, got {other:?}"),
        };
        assert_eq!(first_locator_hash(make_initial_getheaders(&cs)), genesis);

        let mut parent = genesis;
        let mut hashes = vec![genesis];
        for h in 1..=3u32 {
            let block = build_test_block(parent, h, 1_300_000_000 + h);
            cs.accept_block(&block).unwrap();
            parent = block.block_hash();
            hashes.push(parent);
        }
        assert_eq!(first_locator_hash(make_initial_getheaders(&cs)), hashes[2]);
        assert_eq!(first_locator_hash(make_getheaders(&cs)), hashes[3], "the steady-state locator is unchanged");
    }
}
