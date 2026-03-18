use bitcoin::block::Header;
use bitcoin::pow::CompactTarget;
use bitcoin::Network;

use crate::storage::blockindex::{target_from_compact, compact_from_target, BlockIndexEntry};
use crate::validation::ValidationError;

/// Mainnet minimum difficulty target.
const MAINNET_POWLIMIT_BITS: u32 = 0x1d00ffff;
/// Regtest minimum difficulty target.
const REGTEST_POWLIMIT_BITS: u32 = 0x207fffff;
/// Testnet minimum difficulty target (same as mainnet).
const TESTNET_POWLIMIT_BITS: u32 = 0x1d00ffff;
/// Number of blocks between difficulty retargets.
const RETARGET_INTERVAL: u32 = 2016;
/// Target time span for one retarget period (14 days in seconds).
const TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60;
/// Testnet: allow minimum difficulty if block is >20 minutes after previous.
const TESTNET_ALLOW_MIN_DIFF_AFTER: u32 = 20 * 60;

/// Check that the block header hash meets the proof-of-work target.
pub fn check_proof_of_work(header: &Header) -> Result<(), ValidationError> {
    let target = header.target();
    header
        .validate_pow(target)
        .map_err(|_| ValidationError::BadProofOfWork)?;
    Ok(())
}

/// Check that the block's difficulty bits match the expected value for this network.
/// `get_ancestor` looks up a block index entry by height.
pub fn check_difficulty<F>(
    header: &Header,
    prev: &BlockIndexEntry,
    network: Network,
    get_ancestor: F,
) -> Result<(), ValidationError>
where
    F: Fn(u32) -> Option<BlockIndexEntry>,
{
    let height = prev.height + 1;

    match network {
        Network::Regtest => {
            if header.bits.to_consensus() != REGTEST_POWLIMIT_BITS {
                return Err(ValidationError::BadDifficulty);
            }
            Ok(())
        }
        Network::Testnet => {
            let expected = calculate_next_bits_testnet(height, header, prev, &get_ancestor);
            if header.bits.to_consensus() != expected {
                return Err(ValidationError::BadDifficulty);
            }
            Ok(())
        }
        Network::Signet => {
            // Signet consensus is enforced by block signing, not PoW difficulty.
            // Accept whatever bits are set (PoW check still validates hash <= target).
            Ok(())
        }
        _ => {
            // Mainnet
            let expected = calculate_next_bits(height, prev, &get_ancestor);
            if header.bits.to_consensus() != expected {
                return Err(ValidationError::BadDifficulty);
            }
            Ok(())
        }
    }
}

/// Calculate expected difficulty bits for mainnet.
fn calculate_next_bits<F>(height: u32, prev: &BlockIndexEntry, get_ancestor: &F) -> u32
where
    F: Fn(u32) -> Option<BlockIndexEntry>,
{
    // If not at a retarget boundary, bits must match parent
    if !height.is_multiple_of(RETARGET_INTERVAL) {
        return prev.header.bits.to_consensus();
    }

    // At retarget boundary: calculate new target
    let retarget_start_height = height - RETARGET_INTERVAL;
    let first_entry = match get_ancestor(retarget_start_height) {
        Some(e) => e,
        None => return prev.header.bits.to_consensus(),
    };

    let actual_timespan = prev.header.time.saturating_sub(first_entry.header.time);

    // Clamp to [TARGET_TIMESPAN/4, TARGET_TIMESPAN*4]
    let actual_timespan = actual_timespan.clamp(TARGET_TIMESPAN / 4, TARGET_TIMESPAN * 4);

    retarget(prev.header.bits, actual_timespan, MAINNET_POWLIMIT_BITS)
}

/// Calculate expected difficulty bits for testnet (with special min-difficulty rule).
fn calculate_next_bits_testnet<F>(
    height: u32,
    header: &Header,
    prev: &BlockIndexEntry,
    get_ancestor: &F,
) -> u32
where
    F: Fn(u32) -> Option<BlockIndexEntry>,
{
    // At retarget boundary: use standard algorithm
    if height.is_multiple_of(RETARGET_INTERVAL) {
        return calculate_next_bits(height, prev, get_ancestor);
    }

    // Testnet special rule: if >20 minutes since last block, allow min difficulty
    if header.time > prev.header.time + TESTNET_ALLOW_MIN_DIFF_AFTER {
        return TESTNET_POWLIMIT_BITS;
    }

    // Otherwise, walk back to find the last non-min-difficulty block
    let mut current = prev.clone();
    loop {
        if current.height.is_multiple_of(RETARGET_INTERVAL) {
            break;
        }
        if current.header.bits.to_consensus() != TESTNET_POWLIMIT_BITS {
            break;
        }
        if current.height == 0 {
            break;
        }
        match get_ancestor(current.height - 1) {
            Some(e) => current = e,
            None => break,
        }
    }

    current.header.bits.to_consensus()
}

/// Compute new target bits after retarget.
/// new_target = old_target * actual_timespan / TARGET_TIMESPAN
/// Clamped to not exceed powlimit.
fn retarget(old_bits: CompactTarget, actual_timespan: u32, powlimit_bits: u32) -> u32 {
    use crate::storage::blockindex::{mul_u256_u32, div_u256_u32};

    let old_target = target_from_compact(old_bits);

    // new_target = old_target * actual_timespan / TARGET_TIMESPAN
    let scaled = mul_u256_u32(&old_target, actual_timespan);
    let new_target = div_u256_u32(&scaled, TARGET_TIMESPAN);

    // Clamp to powlimit
    let powlimit = target_from_compact(CompactTarget::from_consensus(powlimit_bits));
    let clamped = if compare_targets(&new_target, &powlimit) > 0 {
        powlimit
    } else {
        new_target
    };

    compact_from_target(&clamped)
}

/// Compare two big-endian U256 values. Returns 1 if a > b, -1 if a < b, 0 if equal.
fn compare_targets(a: &[u8; 32], b: &[u8; 32]) -> i32 {
    for i in 0..32 {
        if a[i] > b[i] { return 1; }
        if a[i] < b[i] { return -1; }
    }
    0
}

/// Check that the block timestamp is greater than the median of the previous 11 blocks.
pub fn check_timestamp<F>(header: &Header, height: u32, get_ancestor: F) -> Result<(), ValidationError>
where
    F: Fn(u32) -> Option<BlockIndexEntry>,
{
    if height == 0 {
        return Ok(());
    }

    let start = height.saturating_sub(11);
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
    use crate::storage::blockindex::BlockStatus;

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
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        };
        assert!(check_difficulty(&genesis.header, &entry, Network::Regtest, |_| None).is_ok());
    }

    #[test]
    fn test_bad_difficulty_regtest() {
        let mut genesis = bitcoin::constants::genesis_block(Network::Regtest);
        genesis.header.bits = CompactTarget::from_consensus(0x1d00ffff);
        let entry = BlockIndexEntry {
            header: genesis.header,
            height: 0,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        };
        assert!(check_difficulty(&genesis.header, &entry, Network::Regtest, |_| None).is_err());
    }

    #[test]
    fn test_mainnet_no_retarget_mid_period() {
        // Mid-period: bits must match parent's bits
        let genesis = bitcoin::constants::genesis_block(Network::Bitcoin);
        let prev = BlockIndexEntry {
            header: genesis.header,
            height: 100, // not a retarget boundary
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        };
        // Expected bits = parent bits (since not at retarget boundary)
        assert!(check_difficulty(&genesis.header, &prev, Network::Bitcoin, |_| None).is_ok());
    }
}
