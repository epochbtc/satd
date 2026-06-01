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
/// BIP 94 (testnet4) timewarp guard: the first block of a retarget period
/// may not have a timestamp more than this many seconds before its parent.
const MAX_TIMEWARP: u32 = 600;
/// Bitcoin Core's `MAX_FUTURE_BLOCK_TIME` (2 hours): a block whose timestamp
/// is more than this far ahead of the node's current time is rejected.
const MAX_FUTURE_BLOCK_TIME: u64 = 2 * 60 * 60;

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
            let expected =
                calculate_next_bits_testnet(height, header, prev, &get_ancestor, false);
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
        Network::Testnet4 => {
            // Testnet4 uses testnet3's 20-minute min-difficulty rule, plus
            // two BIP 94 changes: (1) the timewarp guard — the first block
            // of each retarget period must not be timestamped more than
            // MAX_TIMEWARP before its parent; (2) the retarget is seeded
            // from the first block of the period (see
            // calculate_next_bits_bip94), so an end-of-period min-difficulty
            // block can't reset the real difficulty.
            if height.is_multiple_of(RETARGET_INTERVAL)
                && header.time < prev.header.time.saturating_sub(MAX_TIMEWARP)
            {
                return Err(ValidationError::TimewarpAttack);
            }
            let expected =
                calculate_next_bits_testnet(height, header, prev, &get_ancestor, true);
            if header.bits.to_consensus() != expected {
                return Err(ValidationError::BadDifficulty);
            }
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

/// Retarget calculation under BIP 94 (testnet4). Identical to
/// [`calculate_next_bits`] except the new target is seeded from the
/// *first* block of the difficulty period (`pindexFirst->nBits` in
/// Core's `CalculateNextWorkRequired` when `enforce_BIP94`), not the
/// previous block. This prevents a testnet min-difficulty block at the
/// end of a period from resetting the period's real difficulty.
fn calculate_next_bits_bip94<F>(height: u32, prev: &BlockIndexEntry, get_ancestor: &F) -> u32
where
    F: Fn(u32) -> Option<BlockIndexEntry>,
{
    if !height.is_multiple_of(RETARGET_INTERVAL) {
        return prev.header.bits.to_consensus();
    }
    let retarget_start_height = height - RETARGET_INTERVAL;
    let first_entry = match get_ancestor(retarget_start_height) {
        Some(e) => e,
        None => return prev.header.bits.to_consensus(),
    };
    let actual_timespan = prev.header.time.saturating_sub(first_entry.header.time);
    let actual_timespan = actual_timespan.clamp(TARGET_TIMESPAN / 4, TARGET_TIMESPAN * 4);
    // BIP 94: seed from the first block of the period, not `prev`.
    retarget(first_entry.header.bits, actual_timespan, MAINNET_POWLIMIT_BITS)
}

/// Calculate expected difficulty bits for testnet (with special min-difficulty rule).
fn calculate_next_bits_testnet<F>(
    height: u32,
    header: &Header,
    prev: &BlockIndexEntry,
    get_ancestor: &F,
    bip94: bool,
) -> u32
where
    F: Fn(u32) -> Option<BlockIndexEntry>,
{
    // At retarget boundary: use standard algorithm. Under BIP 94
    // (testnet4) the retarget is seeded from the *first* block of the
    // period rather than the previous block, so a min-difficulty block at
    // the end of the period cannot reset the period's real difficulty.
    if height.is_multiple_of(RETARGET_INTERVAL) {
        if bip94 {
            return calculate_next_bits_bip94(height, prev, get_ancestor);
        }
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

/// Reject a header whose timestamp is more than `MAX_FUTURE_BLOCK_TIME`
/// (2 hours) ahead of `now` (seconds since the Unix epoch). Mirrors Bitcoin
/// Core's `time-too-new` check in `ContextualCheckBlockHeader`.
///
/// `now` is the node's current/adjusted time; live callers pass wall-clock.
/// Historical replay (IBD, reindex, background validation) is unaffected:
/// past blocks are never ahead of the present, so this check is a no-op
/// for them. Core uses median-of-peers adjusted time; satd uses system
/// time, which Core's own `MAX_FUTURE_BLOCK_TIME` slack (2h) absorbs.
pub fn check_future_timestamp(header: &Header, now: u64) -> Result<(), ValidationError> {
    if header.time as u64 > now.saturating_add(MAX_FUTURE_BLOCK_TIME) {
        return Err(ValidationError::TimeTooNew);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::blockindex::BlockStatus;

    #[test]
    fn test_future_timestamp_2h_window() {
        let now = 1_700_000_000u64;
        let mut h = bitcoin::constants::genesis_block(Network::Regtest).header;
        // Exactly at the 2-hour boundary is accepted (Core uses strict `>`).
        h.time = (now + MAX_FUTURE_BLOCK_TIME) as u32;
        assert!(check_future_timestamp(&h, now).is_ok());
        // One second past the window is rejected.
        h.time = (now + MAX_FUTURE_BLOCK_TIME + 1) as u32;
        assert!(matches!(
            check_future_timestamp(&h, now),
            Err(ValidationError::TimeTooNew)
        ));
        // A historical block (timestamp in the past) always passes — this is
        // why the check is a no-op during IBD / background replay.
        h.time = 1_500_000_000;
        assert!(check_future_timestamp(&h, now).is_ok());
    }

    fn entry(header: Header, height: u32) -> BlockIndexEntry {
        BlockIndexEntry {
            header,
            height,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        }
    }

    #[test]
    fn testnet4_timewarp_rejected_at_retarget_boundary() {
        // BIP 94: the first block of a retarget period (height % 2016 == 0)
        // may not be timestamped more than 600s before its parent.
        let genesis = bitcoin::constants::genesis_block(Network::Testnet4);
        let mut prev_header = genesis.header;
        prev_header.time = 1_700_000_000;
        let prev = entry(prev_header, 2015); // child height 2016 = boundary

        let mut new_header = genesis.header;
        new_header.time = prev_header.time - 601; // 601s before parent → violation
        let res = check_difficulty(&new_header, &prev, Network::Testnet4, |_| None);
        assert!(matches!(res, Err(ValidationError::TimewarpAttack)), "got {res:?}");

        // Exactly 600s before is allowed by the timewarp rule.
        new_header.time = prev_header.time - 600;
        let res = check_difficulty(&new_header, &prev, Network::Testnet4, |_| None);
        assert!(!matches!(res, Err(ValidationError::TimewarpAttack)), "600s must pass timewarp");
    }

    #[test]
    fn testnet4_uses_testnet_min_difficulty_rule() {
        // Mid-period, >20 minutes since parent → min-difficulty allowed,
        // same as testnet3.
        let genesis = bitcoin::constants::genesis_block(Network::Testnet4);
        let mut prev_header = genesis.header;
        prev_header.time = 1_700_000_000;
        prev_header.bits = CompactTarget::from_consensus(0x1a00ffff); // non-powlimit
        let prev = entry(prev_header, 100); // child height 101, not a boundary

        let mut new_header = genesis.header;
        new_header.time = prev_header.time + TESTNET_ALLOW_MIN_DIFF_AFTER + 1;
        new_header.bits = CompactTarget::from_consensus(TESTNET_POWLIMIT_BITS);
        assert!(check_difficulty(&new_header, &prev, Network::Testnet4, |_| None).is_ok());
    }

    #[test]
    fn testnet4_bip94_retarget_seeds_from_first_block_not_prev() {
        // BIP 94: at a retarget boundary the new target is computed from the
        // FIRST block of the period, not the previous block. This matters
        // when the period ends on a min-difficulty (powlimit) block: Core
        // (enforce_BIP94) seeds from the first block's real difficulty, so
        // seeding from `prev` (powlimit) — the testnet3 behaviour — would
        // diverge from Core. Here the first block carries the real
        // difficulty and `prev` is a powlimit min-diff block.
        let period_bits = 0x1c00ffffu32; // harder than powlimit
        let t0 = 1_700_000_000u32;

        let genesis = bitcoin::constants::genesis_block(Network::Testnet4);
        let mut first_header = genesis.header;
        first_header.time = t0;
        first_header.bits = CompactTarget::from_consensus(period_bits);
        let first_entry = entry(first_header, 2016); // start of the 2nd period

        let mut prev_header = genesis.header;
        prev_header.time = t0 + TARGET_TIMESPAN; // exactly on-target timespan
        prev_header.bits = CompactTarget::from_consensus(TESTNET_POWLIMIT_BITS);
        let prev = entry(prev_header, 4031); // child height 4032 = boundary

        let get_ancestor = |h: u32| -> Option<BlockIndexEntry> {
            if h == 2016 { Some(first_entry.clone()) } else { None }
        };

        // Core/BIP94 expected target: seeded from the first block's bits.
        let expected_bip94 = retarget(
            CompactTarget::from_consensus(period_bits),
            TARGET_TIMESPAN,
            MAINNET_POWLIMIT_BITS,
        );
        // The two seeds must actually differ, or the test proves nothing.
        assert_ne!(expected_bip94, TESTNET_POWLIMIT_BITS);

        let mut new_header = genesis.header;
        new_header.time = prev_header.time;

        // A block carrying the BIP94 (first-block-seeded) bits is accepted.
        new_header.bits = CompactTarget::from_consensus(expected_bip94);
        assert!(
            check_difficulty(&new_header, &prev, Network::Testnet4, get_ancestor).is_ok(),
            "BIP94 first-block-seeded difficulty must be accepted on testnet4"
        );

        // A block carrying the old testnet3 (prev-seeded = powlimit) bits is
        // rejected — that's the consensus divergence this fix closes.
        new_header.bits = CompactTarget::from_consensus(TESTNET_POWLIMIT_BITS);
        assert!(
            matches!(
                check_difficulty(&new_header, &prev, Network::Testnet4, get_ancestor),
                Err(ValidationError::BadDifficulty)
            ),
            "prev-seeded (testnet3) difficulty must be rejected on testnet4"
        );
    }

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

    #[test]
    fn test_retarget_clamp_too_fast() {
        // At retarget boundary (height 4032), with a tiny timespan (1 second),
        // the new bits should be clamped to TARGET_TIMESPAN / 4.
        let genesis = bitcoin::constants::genesis_block(Network::Bitcoin);
        let base_time = genesis.header.time;

        // prev at height 4031
        let mut prev_header = genesis.header;
        prev_header.time = base_time + 1; // Only 1 second after the first_entry
        let prev = BlockIndexEntry {
            header: prev_header,
            height: 4031,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        };

        // first_entry at height 2016 (the start of this retarget period)
        let mut first_header = genesis.header;
        first_header.time = base_time;
        let first_entry = BlockIndexEntry {
            header: first_header,
            height: 2016,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        };

        // Compute expected bits: the timespan of 1 second will be clamped to TARGET_TIMESPAN/4
        let expected_bits = retarget(
            prev_header.bits,
            TARGET_TIMESPAN / 4, // clamped minimum
            MAINNET_POWLIMIT_BITS,
        );

        let mut new_header = genesis.header;
        new_header.bits = CompactTarget::from_consensus(expected_bits);

        let get_ancestor = |h: u32| -> Option<BlockIndexEntry> {
            if h == 2016 {
                Some(first_entry.clone())
            } else {
                None
            }
        };

        assert!(check_difficulty(&new_header, &prev, Network::Bitcoin, get_ancestor).is_ok());
    }

    #[test]
    fn test_retarget_clamp_too_slow() {
        // At retarget boundary (height 4032), with a very large timespan,
        // the new bits should be clamped to TARGET_TIMESPAN * 4.
        let genesis = bitcoin::constants::genesis_block(Network::Bitcoin);
        let base_time = genesis.header.time;

        // prev at height 4031 with timestamp far in the future
        let mut prev_header = genesis.header;
        prev_header.time = base_time + TARGET_TIMESPAN * 10; // Way too slow
        let prev = BlockIndexEntry {
            header: prev_header,
            height: 4031,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        };

        // first_entry at height 2016
        let mut first_header = genesis.header;
        first_header.time = base_time;
        let first_entry = BlockIndexEntry {
            header: first_header,
            height: 2016,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        };

        // Compute expected bits: timespan clamped to TARGET_TIMESPAN * 4
        let expected_bits = retarget(
            prev_header.bits,
            TARGET_TIMESPAN * 4, // clamped maximum
            MAINNET_POWLIMIT_BITS,
        );

        let mut new_header = genesis.header;
        new_header.bits = CompactTarget::from_consensus(expected_bits);

        let get_ancestor = |h: u32| -> Option<BlockIndexEntry> {
            if h == 2016 {
                Some(first_entry.clone())
            } else {
                None
            }
        };

        assert!(check_difficulty(&new_header, &prev, Network::Bitcoin, get_ancestor).is_ok());
    }

    #[test]
    fn test_signet_any_bits_accepted() {
        // On Signet, any bits value should pass check_difficulty.
        let genesis = bitcoin::constants::genesis_block(Network::Signet);
        let prev = BlockIndexEntry {
            header: genesis.header,
            height: 100,
            status: BlockStatus::Valid,
            num_tx: 1,
            file_number: 0,
            data_pos: 0,
            chainwork: [0u8; 32],
        };

        // Use an arbitrary bits value that would fail on other networks
        let mut header = genesis.header;
        header.bits = CompactTarget::from_consensus(0x1a0fffff);

        assert!(check_difficulty(&header, &prev, Network::Signet, |_| None).is_ok());
    }

    #[test]
    fn test_timestamp_above_median_passes() {
        // Build 11 ancestors with increasing timestamps, header time above median -> pass.
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let base_time = 1_000_000u32;

        let entries: Vec<BlockIndexEntry> = (0..11)
            .map(|i| {
                let mut hdr = genesis.header;
                hdr.time = base_time + i * 100;
                BlockIndexEntry {
                    header: hdr,
                    height: i,
                    status: BlockStatus::Valid,
                    num_tx: 1,
                    file_number: 0,
                    data_pos: 0,
                    chainwork: [0u8; 32],
                }
            })
            .collect();

        // Median of [base, base+100, ..., base+1000] sorted = base+500
        let mut header = genesis.header;
        header.time = base_time + 501; // Above median

        let get_ancestor = |h: u32| -> Option<BlockIndexEntry> {
            entries.get(h as usize).cloned()
        };

        assert!(check_timestamp(&header, 11, get_ancestor).is_ok());
    }

    #[test]
    fn test_timestamp_at_median_fails() {
        // Header time equal to median of previous 11 blocks -> TimeTooOld.
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let base_time = 1_000_000u32;

        let entries: Vec<BlockIndexEntry> = (0..11)
            .map(|i| {
                let mut hdr = genesis.header;
                hdr.time = base_time + i * 100;
                BlockIndexEntry {
                    header: hdr,
                    height: i,
                    status: BlockStatus::Valid,
                    num_tx: 1,
                    file_number: 0,
                    data_pos: 0,
                    chainwork: [0u8; 32],
                }
            })
            .collect();

        // Median of [base, base+100, ..., base+1000] sorted = base+500
        let mut header = genesis.header;
        header.time = base_time + 500; // Equal to median

        let get_ancestor = |h: u32| -> Option<BlockIndexEntry> {
            entries.get(h as usize).cloned()
        };

        assert!(matches!(
            check_timestamp(&header, 11, get_ancestor),
            Err(ValidationError::TimeTooOld)
        ));
    }

    #[test]
    fn test_check_pow_invalid_hash() {
        // Use mainnet difficulty bits (very hard), any random header will fail.
        let mut header = bitcoin::constants::genesis_block(Network::Regtest).header;
        header.bits = CompactTarget::from_consensus(MAINNET_POWLIMIT_BITS);
        // The regtest genesis header hash won't meet mainnet difficulty
        assert!(matches!(
            check_proof_of_work(&header),
            Err(ValidationError::BadProofOfWork)
        ));
    }
}
