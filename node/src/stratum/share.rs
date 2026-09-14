//! Share validation and the difficulty ↔ target arithmetic behind it.
//!
//! Targets are 256-bit big-endian byte arrays, the representation
//! [`target_from_compact`](crate::storage::blockindex::target_from_compact)
//! returns, so they compare lexicographically.

use bitcoin::Block;
use bitcoin::hashes::Hash;

use super::template::ActiveTemplate;

/// The pool difficulty-1 target, `0x00000000FFFF0000…0000`.
///
/// Stratum difficulty is measured against this rather than the true
/// proof-of-work limit, by long convention: a share of difficulty `d` is a
/// header hash at or below `DIFF1_TARGET / d`.
pub const DIFF1_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    t[4] = 0xff;
    t[5] = 0xff;
    t
};

/// The outcome of checking one submitted solution.
#[derive(Debug)]
pub enum ShareResult {
    /// The header meets the block target. The block is fully assembled.
    Block(Box<Block>),
    /// The header meets the share target but not the block target.
    Share,
    /// The header does not meet the share target.
    LowDifficulty,
    /// The job is unknown or superseded, or its timestamp would change the
    /// block's required difficulty.
    Stale,
    /// The same solution was already submitted for this job.
    Duplicate,
    /// The timestamp is below the median time past or too far in the future.
    BadTime,
}

/// `DIFF1_TARGET / difficulty`. A difficulty of zero is treated as one.
pub fn share_target(difficulty: u64) -> [u8; 32] {
    div_u256_u64(&DIFF1_TARGET, difficulty.max(1))
}

/// The target a share is actually checked against: the easier of the
/// session's share target and the block target.
///
/// A share target harder than the block target would reject a header that
/// is a valid block. On regtest, whose block target is far easier than
/// difficulty 1, that is every block a miner finds; on mainnet it is a
/// session whose difficulty drifted above the network's.
pub fn effective_share_target(difficulty: u64, block_target: &[u8; 32]) -> [u8; 32] {
    let share = share_target(difficulty);
    if share >= *block_target { share } else { *block_target }
}

/// The network difficulty implied by a block target, in pool-difficulty
/// units, rounded down and never below one.
pub fn network_difficulty(block_target: &[u8; 32]) -> u64 {
    let target = u256_to_f64(block_target);
    if target <= 0.0 {
        return u64::MAX;
    }
    let d = u256_to_f64(&DIFF1_TARGET) / target;
    if d >= u64::MAX as f64 { u64::MAX } else { (d as u64).max(1) }
}

/// Whether a block hash, as a 256-bit number, is at or below `target`.
pub fn hash_meets_target(hash: &bitcoin::BlockHash, target: &[u8; 32]) -> bool {
    let mut be = hash.to_byte_array();
    be.reverse();
    be <= *target
}

/// Judge a solution against a job.
///
/// `extranonce` is the full hole in the coinbase (for SV1, the server's
/// extranonce1 followed by the miner's extranonce2) and must be exactly the
/// job's length. `version` is the header version the miner hashed; the caller
/// has already applied the negotiated rolling mask. `now` is the node clock,
/// in seconds.
///
/// Returns `Err` only for a malformed extranonce; every judgement about the
/// work itself is a [`ShareResult`].
pub fn validate_share(
    job: &ActiveTemplate,
    extranonce: &[u8],
    ntime: u32,
    nonce: u32,
    version: i32,
    share_target: &[u8; 32],
    now: u64,
) -> Result<ShareResult, ShareError> {
    if extranonce.len() != job.extranonce_len {
        return Err(ShareError::ExtranonceLength {
            expected: job.extranonce_len,
            got: extranonce.len(),
        });
    }
    let work = &job.work;
    if ntime < work.min_time
        || u64::from(ntime) > now.saturating_add(crate::validation::pow::MAX_FUTURE_BLOCK_TIME)
    {
        return Ok(ShareResult::BadTime);
    }
    // testnet3/testnet4: the job's bits were computed for `cur_time`. A block
    // stamped on the other side of the 20-minute minimum-difficulty boundary
    // needs different bits, so the job no longer describes it.
    if let Some(boundary) = work.min_difficulty_after
        && (work.cur_time > boundary) != (ntime > boundary)
    {
        return Ok(ShareResult::Stale);
    }
    let header = job.header(extranonce, ntime, nonce, version);
    let hash = header.block_hash();
    if hash_meets_target(&hash, &work.block_target) {
        return Ok(ShareResult::Block(Box::new(job.reconstruct_block(
            extranonce, ntime, nonce, version,
        ))));
    }
    if hash_meets_target(&hash, share_target) {
        Ok(ShareResult::Share)
    } else {
        Ok(ShareResult::LowDifficulty)
    }
}

/// A solution that cannot be judged at all.
#[derive(Debug, thiserror::Error)]
pub enum ShareError {
    #[error("extranonce is {got} bytes, the job expects {expected}")]
    ExtranonceLength { expected: usize, got: usize },
}

fn div_u256_u64(a: &[u8; 32], d: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut rem: u128 = 0;
    for i in 0..4 {
        let limb = u64::from_be_bytes(a[i * 8..(i + 1) * 8].try_into().expect("8 bytes"));
        let cur = (rem << 64) | u128::from(limb);
        let q = cur / u128::from(d);
        rem = cur % u128::from(d);
        out[i * 8..(i + 1) * 8].copy_from_slice(&(q as u64).to_be_bytes());
    }
    out
}

fn u256_to_f64(a: &[u8; 32]) -> f64 {
    a.iter().fold(0.0, |acc, &b| acc * 256.0 + f64::from(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::blockindex::target_from_compact;
    use bitcoin::pow::CompactTarget;

    #[test]
    fn difficulty_one_is_the_diff1_target() {
        assert_eq!(share_target(1), DIFF1_TARGET);
        assert_eq!(share_target(0), DIFF1_TARGET);
        // 0xFFFF / 2 = 0x7FFF with a carry of 0x8000 into the next bytes.
        let half = share_target(2);
        assert_eq!(&half[..8], &[0, 0, 0, 0, 0x7f, 0xff, 0x80, 0x00]);
        assert!(share_target(10_000) < share_target(1_000));
    }

    #[test]
    fn share_target_is_never_harder_than_block_target() {
        // Regtest's block target is far easier than difficulty 1: a header
        // that meets it but not DIFF1 is a block, and must not be refused as
        // low difficulty.
        let regtest = target_from_compact(CompactTarget::from_consensus(0x207fffff));
        assert!(regtest > DIFF1_TARGET);
        assert_eq!(effective_share_target(1, &regtest), regtest);
        assert_eq!(effective_share_target(1_000_000, &regtest), regtest);

        // Mainnet at minimum difficulty: a session above the network
        // difficulty is clamped to the block target, one below keeps its own.
        let mainnet = target_from_compact(CompactTarget::from_consensus(0x1d00ffff));
        assert_eq!(effective_share_target(2, &mainnet), mainnet);
        let hard = target_from_compact(CompactTarget::from_consensus(0x17034219));
        assert_eq!(effective_share_target(10_000, &hard), share_target(10_000));
    }

    fn job(bits: u32) -> ActiveTemplate {
        ActiveTemplate::build(
            crate::stratum::template::tests::work_with(2, bits),
            1,
            bitcoin::ScriptBuf::new_op_return([3]),
            8,
        )
        .unwrap()
    }

    const NTIME: u32 = 1_700_000_000;

    #[test]
    fn share_meeting_block_target_yields_block() {
        // Regtest: about half of all headers meet the block target.
        let job = job(0x207fffff);
        let target = effective_share_target(1, &job.work.block_target);
        let extranonce = [5u8; 8];
        let (nonce, result) = (0u32..64)
            .find_map(|nonce| {
                match validate_share(&job, &extranonce, NTIME, nonce, 0x2000_0000, &target, u64::from(NTIME)).unwrap() {
                    ShareResult::Block(block) => Some((nonce, block)),
                    _ => None,
                }
            })
            .expect("a regtest block within 64 nonces");
        assert_eq!(result.header.nonce, nonce);
        assert!(result.header.validate_pow(result.header.target()).is_ok());
        assert!(result.check_merkle_root());
        assert!(result.check_witness_commitment());
    }

    #[test]
    fn share_below_target_is_rejected() {
        // Minimum mainnet difficulty and a share difficulty of 2^40: a random
        // header clears neither.
        let job = job(0x1d00ffff);
        let target = effective_share_target(1 << 40, &job.work.block_target);
        assert_eq!(target, job.work.block_target, "clamped to the block target");
        let result = validate_share(&job, &[0u8; 8], NTIME, 7, 0x2000_0000, &target, u64::from(NTIME)).unwrap();
        assert!(matches!(result, ShareResult::LowDifficulty), "{result:?}");

        let mut hard = [0u8; 32];
        hard[31] = 1;
        let result = validate_share(&job, &[0u8; 8], NTIME, 7, 0x2000_0000, &hard, u64::from(NTIME)).unwrap();
        assert!(matches!(result, ShareResult::LowDifficulty), "{result:?}");

        assert!(validate_share(&job, &[0u8; 4], NTIME, 7, 0x2000_0000, &hard, 0).is_err());
    }

    #[test]
    fn ntime_outside_the_valid_window_is_refused() {
        let job = job(0x207fffff);
        let easy = [0xff; 32];
        let now = u64::from(NTIME);
        let below_mtp = job.work.min_time - 1;
        assert!(matches!(
            validate_share(&job, &[0; 8], below_mtp, 0, 0x2000_0000, &easy, now).unwrap(),
            ShareResult::BadTime
        ));
        let too_far = NTIME + crate::validation::pow::MAX_FUTURE_BLOCK_TIME as u32 + 1;
        assert!(matches!(
            validate_share(&job, &[0; 8], too_far, 0, 0x2000_0000, &easy, now).unwrap(),
            ShareResult::BadTime
        ));
    }

    #[test]
    fn a_share_across_the_testnet_min_difficulty_boundary_is_stale() {
        // Parent at T; the job was built at T+600, under the period's
        // difficulty. At T+1201 a block would need the minimum difficulty, so
        // the job's bits no longer apply.
        let parent = 1_700_000_000u32;
        let template = crate::mining::template::BlockTemplate {
            version: 0x2000_0000,
            prev_hash: bitcoin::BlockHash::from_byte_array([1; 32]),
            height: 101,
            bits: CompactTarget::from_consensus(0x207fffff),
            cur_time: parent + 600,
            min_time: parent - 3_000,
            transactions: Vec::new(),
            coinbase_value: 1,
        };
        let work = std::sync::Arc::new(crate::stratum::template::Work::new(
            template,
            bitcoin::Network::Testnet4,
            parent,
        ));
        assert_eq!(work.min_difficulty_after, Some(parent + 1_200));
        let job = ActiveTemplate::build(work, 1, bitcoin::ScriptBuf::new_op_return([3]), 8).unwrap();
        let easy = [0xff; 32];
        let now = u64::from(parent + 2_000);
        assert!(!matches!(
            validate_share(&job, &[0; 8], parent + 1_200, 0, 0x2000_0000, &easy, now).unwrap(),
            ShareResult::Stale
        ));
        assert!(matches!(
            validate_share(&job, &[0; 8], parent + 1_201, 0, 0x2000_0000, &easy, now).unwrap(),
            ShareResult::Stale
        ));
    }

    #[test]
    fn network_difficulty_matches_the_block_target() {
        let minimum = target_from_compact(CompactTarget::from_consensus(0x1d00ffff));
        assert_eq!(network_difficulty(&minimum), 1);
        let regtest = target_from_compact(CompactTarget::from_consensus(0x207fffff));
        assert_eq!(network_difficulty(&regtest), 1, "floors at one");
        // 0x1b0404cb is the textbook difficulty-16307.42 example.
        let t = target_from_compact(CompactTarget::from_consensus(0x1b0404cb));
        assert_eq!(network_difficulty(&t), 16307);
    }
}
