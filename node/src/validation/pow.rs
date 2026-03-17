use bitcoin::block::Header;
use bitcoin::Network;

use crate::storage::blockindex::BlockIndexEntry;
use crate::validation::ValidationError;

/// Check that the block header hash meets the proof-of-work target.
pub fn check_proof_of_work(header: &Header) -> Result<(), ValidationError> {
    let target = header.target();
    // validate_pow checks that block_hash <= target
    header
        .validate_pow(target)
        .map_err(|_| ValidationError::BadProofOfWork)?;
    Ok(())
}

/// Check that the block's difficulty bits match the expected value for this network.
/// For regtest, difficulty is always the minimum (0x207fffff).
pub fn check_difficulty(
    header: &Header,
    _prev: &BlockIndexEntry,
    network: Network,
) -> Result<(), ValidationError> {
    match network {
        Network::Regtest => {
            // Regtest always uses minimum difficulty
            if header.bits.to_consensus() != 0x207fffff {
                return Err(ValidationError::BadDifficulty);
            }
            Ok(())
        }
        _ => {
            // TODO: Implement full 2016-block retarget for mainnet/testnet
            // For now, accept whatever bits are set (will be tightened in later milestones)
            Ok(())
        }
    }
}

/// Check that the block timestamp is greater than the median of the previous 11 blocks.
/// `get_ancestor` returns the BlockIndexEntry at a given height.
pub fn check_timestamp<F>(header: &Header, height: u32, get_ancestor: F) -> Result<(), ValidationError>
where
    F: Fn(u32) -> Option<BlockIndexEntry>,
{
    if height == 0 {
        // Genesis block has no ancestors to check against
        return Ok(());
    }

    // Collect timestamps of up to 11 previous blocks
    let start = if height > 11 { height - 11 } else { 0 };
    let mut timestamps: Vec<u32> = Vec::new();
    for h in start..height {
        if let Some(entry) = get_ancestor(h) {
            timestamps.push(entry.header.time);
        }
    }

    if timestamps.is_empty() {
        return Ok(());
    }

    timestamps.sort();
    let median = timestamps[timestamps.len() / 2];

    if header.time <= median {
        return Err(ValidationError::TimeTooOld);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regtest_genesis_pow() {
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        assert!(check_proof_of_work(&genesis.header).is_ok());
    }

    #[test]
    fn test_regtest_difficulty_check() {
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let entry = BlockIndexEntry {
            header: genesis.header,
            height: 0,
            status: crate::storage::blockindex::BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        };
        assert!(check_difficulty(&genesis.header, &entry, Network::Regtest).is_ok());
    }

    #[test]
    fn test_bad_difficulty_regtest() {
        let mut genesis = bitcoin::constants::genesis_block(Network::Regtest);
        genesis.header.bits = bitcoin::pow::CompactTarget::from_consensus(0x1d00ffff); // mainnet difficulty
        let entry = BlockIndexEntry {
            header: genesis.header,
            height: 0,
            status: crate::storage::blockindex::BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        };
        assert!(check_difficulty(&genesis.header, &entry, Network::Regtest).is_err());
    }
}
