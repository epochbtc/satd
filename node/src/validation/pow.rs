use bitcoin::block::Header;
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::{BlockHash, Network};

use crate::storage::blockindex::{target_from_compact, compact_from_target, BlockIndexEntry};
use crate::validation::ValidationError;

/// Mainnet minimum difficulty target.
const MAINNET_POWLIMIT_BITS: u32 = 0x1d00ffff;
/// Regtest minimum difficulty target.
const REGTEST_POWLIMIT_BITS: u32 = 0x207fffff;
/// Testnet minimum difficulty target (same as mainnet).
const TESTNET_POWLIMIT_BITS: u32 = 0x1d00ffff;
/// Signet minimum difficulty target (Core's signet `powLimit`,
/// `00000377ae…`). Only the retarget clamp in [`next_bits`] reads it: signet
/// validation does not check `nBits` (the block signature is the gate).
const SIGNET_POWLIMIT_BITS: u32 = 0x1e0377ae;
/// Number of blocks between difficulty retargets.
/// Bitcoin's difficulty adjustment interval, in blocks (Core's
/// `Consensus::Params::DifficultyAdjustmentInterval()`). The same on every
/// network satd supports.
pub const RETARGET_INTERVAL: u32 = 2016;
/// Target time span for one retarget period (14 days in seconds).
const TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60;
/// Testnet: allow minimum difficulty if block is >20 minutes after previous.
const TESTNET_ALLOW_MIN_DIFF_AFTER: u32 = 20 * 60;
/// BIP 94 (testnet4) timewarp guard: the first block of a retarget period
/// may not have a timestamp more than this many seconds before its parent.
const MAX_TIMEWARP: u32 = 600;
/// Bitcoin Core's `MAX_FUTURE_BLOCK_TIME` (2 hours): a block whose timestamp
/// is more than this far ahead of the node's current time is rejected.
pub const MAX_FUTURE_BLOCK_TIME: u64 = 2 * 60 * 60;

/// Check that the block header hash meets the proof-of-work target.
pub fn check_proof_of_work(header: &Header) -> Result<(), ValidationError> {
    let target = header.target();
    header
        .validate_pow(target)
        .map_err(|_| ValidationError::BadProofOfWork)?;
    Ok(())
}

/// The network's proof-of-work limit, as compact bits: Core's
/// `consensus.powLimit`. No valid block on the network may claim an easier
/// target than this.
pub fn pow_limit_bits(network: Network) -> u32 {
    match network {
        Network::Regtest => REGTEST_POWLIMIT_BITS,
        Network::Signet => SIGNET_POWLIMIT_BITS,
        Network::Testnet | Network::Testnet4 => TESTNET_POWLIMIT_BITS,
        _ => MAINNET_POWLIMIT_BITS,
    }
}

/// Bitcoin Core's `DeriveTarget`: the target `bits` encodes, or `None` if it
/// is not one a block on `network` could legitimately claim.
///
/// Rejects, in Core's order, a negative encoding, a zero target, an encoding
/// that overflows 256 bits, and a target easier than the network's
/// `powLimit`. The last two matter most: [`Header::target`] decodes whatever
/// the header says, its shift wraps on an overflowing exponent, and nothing
/// stops a header claiming `0x20ffffff` — a target near 2^256 that essentially
/// any nonce meets. A check that trusts the header's own `bits` therefore
/// bounds nothing; this is what makes "the hash meets the target" mean the
/// header cost real work.
pub fn derive_target(bits: CompactTarget, network: Network) -> Option<Target> {
    let raw = bits.to_consensus();
    let size = raw >> 24;
    let word = raw & 0x007f_ffff;
    let negative = word != 0 && raw & 0x0080_0000 != 0;
    let overflow = word != 0
        && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
    if negative || overflow {
        return None;
    }
    let target = Target::from_compact(bits);
    let limit = Target::from_compact(CompactTarget::from_consensus(pow_limit_bits(network)));
    if target == Target::ZERO || target > limit {
        return None;
    }
    Some(target)
}

/// Bitcoin Core's `CheckProofOfWork`: the header's hash meets its claimed
/// target, *and* that target is one the network allows.
///
/// [`check_proof_of_work`] checks only the first half, and the second is
/// what gives the first any weight — see [`derive_target`]. On accepted
/// blocks the gap is covered by [`check_difficulty`], which pins `bits` to
/// the chain's schedule; this is for the places that must judge a header
/// before, or without, knowing where it sits in the chain.
pub fn check_proof_of_work_bounded(header: &Header, network: Network) -> Result<(), ValidationError> {
    let target = derive_target(header.bits, network).ok_or(ValidationError::BadProofOfWork)?;
    if target.is_met_by(header.block_hash()) {
        Ok(())
    } else {
        Err(ValidationError::BadProofOfWork)
    }
}

/// Check that the block's difficulty bits match the expected value for this network.
/// `get_ancestor` looks up a block index entry by height.
pub fn check_difficulty<F, G>(
    header: &Header,
    prev: &BlockIndexEntry,
    network: Network,
    get_ancestor: F,
    get_by_hash: G,
) -> Result<(), ValidationError>
where
    F: Fn(u32) -> Option<BlockIndexEntry>,
    G: Fn(&BlockHash) -> Option<BlockIndexEntry>,
{
    let height = prev.height + 1;

    match network {
        // Signet consensus is enforced by block signing, which satd verifies
        // on every signet (`check_signet_block_solution`), not PoW difficulty.
        // Accept whatever bits are set (PoW check still validates hash <= target).
        // Core also checks signet `nBits` against the retarget schedule (#838).
        Network::Signet => return Ok(()),
        // Testnet4 adds the BIP 94 timewarp guard: the first block of each
        // retarget period must not be timestamped more than MAX_TIMEWARP
        // before its parent. The seeding change lives in `next_bits`.
        Network::Testnet4
            if height.is_multiple_of(RETARGET_INTERVAL)
                && header.time < prev.header.time.saturating_sub(MAX_TIMEWARP) =>
        {
            return Err(ValidationError::TimewarpAttack);
        }
        _ => {}
    }

    let expected = next_bits(network, prev, header.time, get_ancestor, get_by_hash)?;
    if header.bits != expected {
        return Err(ValidationError::BadDifficulty);
    }
    Ok(())
}

/// The `nBits` a block building on `prev` with timestamp `header_time` must
/// carry — Core's `GetNextWorkRequired`.
///
/// [`check_difficulty`] compares a received header against this; block
/// template assembly calls it directly so a template is valid at a retarget
/// boundary. The timestamp matters only on testnet3 and testnet4, where a
/// block more than 20 minutes after its parent may use the minimum
/// difficulty. `get_ancestor` looks up an entry by height (the retarget
/// seed); `get_by_hash` follows parent pointers (the testnet walk-back).
///
/// Signet validation does not check `nBits`, but a template still needs the
/// right value: signet retargets with the mainnet rules against its own
/// proof-of-work limit.
pub fn next_bits<F, G>(
    network: Network,
    prev: &BlockIndexEntry,
    header_time: u32,
    get_ancestor: F,
    get_by_hash: G,
) -> Result<CompactTarget, ValidationError>
where
    F: Fn(u32) -> Option<BlockIndexEntry>,
    G: Fn(&BlockHash) -> Option<BlockIndexEntry>,
{
    let height = prev.height + 1;
    let bits = match network {
        Network::Regtest => REGTEST_POWLIMIT_BITS,
        Network::Testnet => calculate_next_bits_testnet(
            height,
            header_time,
            prev,
            &get_ancestor,
            &get_by_hash,
            false,
        )?,
        // Testnet4 uses testnet3's 20-minute min-difficulty rule, with the
        // retarget seeded from the first block of the period (see
        // calculate_next_bits_bip94), so an end-of-period min-difficulty
        // block can't reset the real difficulty.
        Network::Testnet4 => calculate_next_bits_testnet(
            height,
            header_time,
            prev,
            &get_ancestor,
            &get_by_hash,
            true,
        )?,
        Network::Signet => calculate_next_bits(height, prev, &get_ancestor, SIGNET_POWLIMIT_BITS)?,
        // Mainnet
        _ => calculate_next_bits(height, prev, &get_ancestor, MAINNET_POWLIMIT_BITS)?,
    };
    Ok(CompactTarget::from_consensus(bits))
}

/// Calculate expected difficulty bits for mainnet.
///
/// Fails closed (`BadDifficulty`) if the retarget-period seed block cannot be
/// found: a missing seed means we cannot compute the expected difficulty, so we
/// must reject rather than substitute `prev`'s bits (which would let an
/// under-difficulty block through at a retarget boundary on a damaged index).
fn calculate_next_bits<F>(
    height: u32,
    prev: &BlockIndexEntry,
    get_ancestor: &F,
    powlimit_bits: u32,
) -> Result<u32, ValidationError>
where
    F: Fn(u32) -> Option<BlockIndexEntry>,
{
    // If not at a retarget boundary, bits must match parent
    if !height.is_multiple_of(RETARGET_INTERVAL) {
        return Ok(prev.header.bits.to_consensus());
    }

    // At retarget boundary: calculate new target
    let retarget_start_height = height - RETARGET_INTERVAL;
    let first_entry = get_ancestor(retarget_start_height).ok_or(ValidationError::BadDifficulty)?;

    let actual_timespan = prev.header.time.saturating_sub(first_entry.header.time);

    // Clamp to [TARGET_TIMESPAN/4, TARGET_TIMESPAN*4]
    let actual_timespan = actual_timespan.clamp(TARGET_TIMESPAN / 4, TARGET_TIMESPAN * 4);

    Ok(retarget(prev.header.bits, actual_timespan, powlimit_bits))
}

/// Retarget calculation under BIP 94 (testnet4). Identical to
/// [`calculate_next_bits`] except the new target is seeded from the
/// *first* block of the difficulty period (`pindexFirst->nBits` in
/// Core's `CalculateNextWorkRequired` when `enforce_BIP94`), not the
/// previous block. This prevents a testnet min-difficulty block at the
/// end of a period from resetting the period's real difficulty.
fn calculate_next_bits_bip94<F>(
    height: u32,
    prev: &BlockIndexEntry,
    get_ancestor: &F,
) -> Result<u32, ValidationError>
where
    F: Fn(u32) -> Option<BlockIndexEntry>,
{
    if !height.is_multiple_of(RETARGET_INTERVAL) {
        return Ok(prev.header.bits.to_consensus());
    }
    let retarget_start_height = height - RETARGET_INTERVAL;
    // Fail closed if the period's first block is missing (see `calculate_next_bits`).
    let first_entry = get_ancestor(retarget_start_height).ok_or(ValidationError::BadDifficulty)?;
    let actual_timespan = prev.header.time.saturating_sub(first_entry.header.time);
    let actual_timespan = actual_timespan.clamp(TARGET_TIMESPAN / 4, TARGET_TIMESPAN * 4);
    // BIP 94: seed from the first block of the period, not `prev`.
    Ok(retarget(first_entry.header.bits, actual_timespan, MAINNET_POWLIMIT_BITS))
}

/// Calculate expected difficulty bits for testnet (with special min-difficulty rule).
///
/// `get_ancestor` (by height) is used only for the retarget-boundary seed. The
/// min-difficulty walk-back follows **parent pointers** (`prev_blockhash`) via
/// `get_by_hash`, mirroring Bitcoin Core's `pindex->pprev` walk. This must NOT
/// use the height→hash index: that index is the *active chain* and can have gaps
/// (reorg artifacts, or the corruption class fixed in the block-index hardening
/// work). A single missing height there would stop the walk-back early and
/// return powlimit instead of the period's real difficulty — rejecting a valid
/// block as `bad-diffbits`. Parent pointers are always present for any ancestor
/// we hold, so the walk is gap-immune.
fn calculate_next_bits_testnet<F, G>(
    height: u32,
    header_time: u32,
    prev: &BlockIndexEntry,
    get_ancestor: &F,
    get_by_hash: &G,
    bip94: bool,
) -> Result<u32, ValidationError>
where
    F: Fn(u32) -> Option<BlockIndexEntry>,
    G: Fn(&BlockHash) -> Option<BlockIndexEntry>,
{
    // At retarget boundary: use standard algorithm. Under BIP 94
    // (testnet4) the retarget is seeded from the *first* block of the
    // period rather than the previous block, so a min-difficulty block at
    // the end of the period cannot reset the period's real difficulty.
    if height.is_multiple_of(RETARGET_INTERVAL) {
        if bip94 {
            return calculate_next_bits_bip94(height, prev, get_ancestor);
        }
        return calculate_next_bits(height, prev, get_ancestor, TESTNET_POWLIMIT_BITS);
    }

    // Testnet special rule: if >20 minutes since last block, allow min difficulty
    if header_time > prev.header.time + TESTNET_ALLOW_MIN_DIFF_AFTER {
        return Ok(TESTNET_POWLIMIT_BITS);
    }

    // Otherwise, walk back (via parent pointers) to the last block that is
    // either a retarget boundary or not a min-difficulty (powlimit) block, and
    // use its bits — exactly Core's testnet `pprev` walk.
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
        match get_by_hash(&current.header.prev_blockhash) {
            Some(e) => current = e,
            // Fail closed. A non-boundary, non-genesis, min-difficulty block
            // whose parent we cannot resolve by hash means we are missing an
            // ancestor we should hold (a store-integrity violation, not a mere
            // height-index gap). Returning here would otherwise yield powlimit
            // and accept an under-difficulty block — reject instead.
            None => return Err(ValidationError::BadDifficulty),
        }
    }

    Ok(current.header.bits.to_consensus())
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

/// Check that the block timestamp is greater than the median time past of its
/// own ancestors — Bitcoin Core's `block.GetBlockTime() > pindexPrev->GetMedianTimePast()`.
///
/// The median is taken over `prev` and up to its 10 ancestors, reached by
/// walking **parent pointers** (`prev_blockhash`) via `get_by_hash` — exactly
/// Core's `pindex->pprev` walk in `GetMedianTimePast`.
///
/// This must NOT resolve ancestors through the height→hash index. That index
/// tracks the *active chain*, so for a block on a competing branch it returns
/// the active chain's blocks at those heights rather than the candidate block's
/// real ancestors. On testnet4's min-difficulty timestamp sawtooth a competing
/// branch routinely carries timestamps lower than the current fork tip, so a
/// height-indexed MTP would spuriously reject the branch as `time-too-old` and
/// permanently block the reorg onto it. Parent pointers are always present for
/// any ancestor we hold, so the walk is immune to active-chain index gaps —
/// the same hazard already avoided in the difficulty walk-back above.
pub fn check_timestamp<G>(
    header: &Header,
    prev: &BlockIndexEntry,
    get_by_hash: G,
) -> Result<(), ValidationError>
where
    G: Fn(&BlockHash) -> Option<BlockIndexEntry>,
{
    const MEDIAN_TIME_SPAN: usize = 11;

    let mut timestamps: Vec<u32> = Vec::with_capacity(MEDIAN_TIME_SPAN);
    let mut current = Some(prev.clone());
    while let Some(entry) = current {
        timestamps.push(entry.header.time);
        if timestamps.len() == MEDIAN_TIME_SPAN || entry.height == 0 {
            break;
        }
        current = get_by_hash(&entry.header.prev_blockhash);
    }

    if timestamps.is_empty() {
        return Ok(());
    }

    timestamps.sort_unstable();
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
    use bitcoin::pow::Target;

    /// First nonce under 64 at which `check` accepts `header` with these
    /// `bits` — a stand-in for "how much work does it take".
    fn cheap_nonce(bits: u32, check: impl Fn(&Header) -> bool) -> Option<u32> {
        let mut h = bitcoin::constants::genesis_block(Network::Bitcoin).header;
        h.bits = CompactTarget::from_consensus(bits);
        (0..64).find(|&n| {
            h.nonce = n;
            check(&h)
        })
    }

    #[test]
    fn a_header_that_names_its_own_easy_target_costs_nothing_until_bounded() {
        // The gap: the hash against the header's *own* bits. Two encodings
        // that pass it on the first nonce tried —
        //   0x207fffff  a target near 2^255, the easiest honest encoding;
        //   0x2101ffff  overflows 256 bits, and the decoder's shift wraps it
        //               to a target near 2^256.
        // (The encoding one might reach for first, 0x20ffffff, is not one of
        // them: its mantissa sign bit is set, so it decodes to zero and meets
        // nothing. The free ones are the non-negative ones.)
        let unbounded = |h: &Header| check_proof_of_work(h).is_ok();
        let bounded = |h: &Header| check_proof_of_work_bounded(h, Network::Bitcoin).is_ok();
        for bits in [0x207f_ffff, 0x2101_ffff] {
            assert!(
                cheap_nonce(bits, unbounded).is_some(),
                "{bits:08x}: expected the unbounded check to be free, which is the defect"
            );
            assert_eq!(
                cheap_nonce(bits, bounded),
                None,
                "{bits:08x}: bounded by mainnet's powLimit it must not be"
            );
        }

        // And real work still passes, so the bound is not refusing everything.
        let genesis = bitcoin::constants::genesis_block(Network::Bitcoin).header;
        assert!(check_proof_of_work_bounded(&genesis, Network::Bitcoin).is_ok());
    }

    #[test]
    fn derive_target_follows_core_derive_target() {
        let t = |bits: u32, net| derive_target(CompactTarget::from_consensus(bits), net);

        // Each network's own limit is allowed, exactly.
        for (net, limit) in [
            (Network::Bitcoin, MAINNET_POWLIMIT_BITS),
            (Network::Testnet, TESTNET_POWLIMIT_BITS),
            (Network::Testnet4, TESTNET_POWLIMIT_BITS),
            (Network::Signet, SIGNET_POWLIMIT_BITS),
            (Network::Regtest, REGTEST_POWLIMIT_BITS),
        ] {
            assert!(t(limit, net).is_some(), "{net:?} accepts its own powLimit");
        }
        // One mantissa step easier than mainnet's limit is not.
        assert!(t(0x1d01_0000, Network::Bitcoin).is_none(), "above powLimit");
        // Regtest's limit is regtest's alone.
        assert!(t(REGTEST_POWLIMIT_BITS, Network::Bitcoin).is_none());

        // Harder than the limit is always fine.
        assert!(t(0x1c00_ffff, Network::Bitcoin).is_some());

        // Core's encoding rejections, each on a network where the limit
        // would otherwise allow the value.
        assert!(t(0x0492_3456, Network::Regtest).is_none(), "negative");
        assert!(t(0x0000_0000, Network::Regtest).is_none(), "zero");
        assert!(t(0x2101_ffff, Network::Regtest).is_none(), "overflow past 256 bits");
        assert!(t(0x2300_0001, Network::Regtest).is_none(), "overflow by exponent alone");
        // A zero mantissa with the sign bit set is zero, not negative.
        assert!(t(0x0480_0000, Network::Regtest).is_none());

        // The value itself matches the unchecked decode when it is valid.
        assert_eq!(
            t(MAINNET_POWLIMIT_BITS, Network::Bitcoin),
            Some(Target::from_compact(CompactTarget::from_consensus(MAINNET_POWLIMIT_BITS)))
        );
    }
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
        let res = check_difficulty(&new_header, &prev, Network::Testnet4, |_| None, |_| None);
        assert!(matches!(res, Err(ValidationError::TimewarpAttack)), "got {res:?}");

        // Exactly 600s before is allowed by the timewarp rule.
        new_header.time = prev_header.time - 600;
        let res = check_difficulty(&new_header, &prev, Network::Testnet4, |_| None, |_| None);
        assert!(!matches!(res, Err(ValidationError::TimewarpAttack)), "600s must pass timewarp");
    }

    /// Regression for the live testnet4 wedge (node stuck at 138567): the
    /// min-difficulty walk-back must follow PARENT POINTERS, not the height→hash
    /// index. A run of min-difficulty blocks sits between the block being
    /// validated and the last real-difficulty block; if the walk used the
    /// height index and that index had a gap (here at height 105), it stopped
    /// early and returned powlimit, rejecting a valid real-difficulty block as
    /// `bad-diffbits`. Parent pointers are gap-immune.
    #[test]
    fn testnet_min_difficulty_walkback_is_immune_to_height_index_gaps() {
        use std::collections::HashMap;
        let real_bits = 0x1a00ffffu32; // any non-powlimit difficulty
        let pow = TESTNET_POWLIMIT_BITS;

        // Linked chain: height 100 = real-difficulty, 101..=110 = min-difficulty.
        let mut by_height: HashMap<u32, BlockIndexEntry> = HashMap::new();
        let mut by_hash: HashMap<BlockHash, BlockIndexEntry> = HashMap::new();
        let mut prev_hash = bitcoin::constants::genesis_block(Network::Testnet4).block_hash();
        let base_time = 1_700_000_000u32;
        for h in 100..=110u32 {
            let mut hdr = bitcoin::constants::genesis_block(Network::Testnet4).header;
            hdr.prev_blockhash = prev_hash;
            hdr.time = base_time + (h - 100) * 100; // <20min apart
            hdr.bits = CompactTarget::from_consensus(if h == 100 { real_bits } else { pow });
            let e = entry(hdr, h);
            let hash = hdr.block_hash();
            by_height.insert(h, e.clone());
            by_hash.insert(hash, e);
            prev_hash = hash;
        }

        // Block 111: <20min after parent → not min-difficulty → walk-back runs.
        let prev = by_height[&110].clone();
        let mut new_header = bitcoin::constants::genesis_block(Network::Testnet4).header;
        new_header.prev_blockhash = prev.header.block_hash();
        new_header.time = prev.header.time + 100;
        new_header.bits = CompactTarget::from_consensus(real_bits);

        // Height index has a GAP at 105 (the live corruption); parent pointers don't.
        let get_ancestor = |h: u32| if h == 105 { None } else { by_height.get(&h).cloned() };
        let get_by_hash = |hsh: &BlockHash| by_hash.get(hsh).cloned();

        assert!(
            check_difficulty(&new_header, &prev, Network::Testnet4, get_ancestor, get_by_hash)
                .is_ok(),
            "walk-back must follow parent pointers and survive the height-index gap"
        );
    }

    /// Companion to the walk-back gap test: if the by-hash walk itself cannot
    /// resolve a mid-walk ancestor (a store-integrity violation, not merely a
    /// height-index gap), difficulty computation must FAIL CLOSED — reject as
    /// `BadDifficulty` rather than fall through to powlimit and accept an
    /// under-difficulty block.
    #[test]
    fn testnet_min_difficulty_walkback_missing_ancestor_is_fail_closed() {
        use std::collections::HashMap;
        let pow = TESTNET_POWLIMIT_BITS;

        let mut by_height: HashMap<u32, BlockIndexEntry> = HashMap::new();
        let mut by_hash: HashMap<BlockHash, BlockIndexEntry> = HashMap::new();
        let mut prev_hash = bitcoin::constants::genesis_block(Network::Testnet4).block_hash();
        let base_time = 1_700_000_000u32;
        for h in 100..=110u32 {
            let mut hdr = bitcoin::constants::genesis_block(Network::Testnet4).header;
            hdr.prev_blockhash = prev_hash;
            hdr.time = base_time + (h - 100) * 100; // <20min apart
            hdr.bits = CompactTarget::from_consensus(if h == 100 { 0x1a00ffff } else { pow });
            let e = entry(hdr, h);
            let hash = hdr.block_hash();
            by_height.insert(h, e.clone());
            // Height 105 is genuinely absent from the by-hash store: the walk
            // (110→…→106) must request 105 by parent hash and find nothing.
            if h != 105 {
                by_hash.insert(hash, e);
            }
            prev_hash = hash;
        }

        let prev = by_height[&110].clone();
        let mut new_header = bitcoin::constants::genesis_block(Network::Testnet4).header;
        new_header.prev_blockhash = prev.header.block_hash();
        new_header.time = prev.header.time + 100; // <20min → walk-back runs
        new_header.bits = CompactTarget::from_consensus(0x1a00ffff);

        let get_ancestor = |h: u32| by_height.get(&h).cloned();
        let get_by_hash = |hsh: &BlockHash| by_hash.get(hsh).cloned();

        assert!(
            matches!(
                check_difficulty(&new_header, &prev, Network::Testnet4, get_ancestor, get_by_hash),
                Err(ValidationError::BadDifficulty)
            ),
            "a missing by-hash ancestor mid-walk must fail closed, not return powlimit"
        );
    }

    /// Mainnet retarget must fail closed if the period's seed block is missing
    /// from the index, rather than substituting `prev`'s bits — which would
    /// accept an under-difficulty block at the boundary on a damaged index.
    #[test]
    fn mainnet_retarget_missing_seed_is_fail_closed() {
        // prev at height 2015 → child height 2016 is a retarget boundary.
        let genesis = bitcoin::constants::genesis_block(Network::Bitcoin);
        let mut prev_header = genesis.header;
        prev_header.bits = CompactTarget::from_consensus(0x1a00ffff);
        let prev = entry(prev_header, 2015);

        let mut new_header = genesis.header;
        new_header.bits = prev_header.bits;

        // The seed lookup (height 0) returns None → retarget cannot be computed.
        let res = check_difficulty(&new_header, &prev, Network::Bitcoin, |_| None, |_| None);
        assert!(
            matches!(res, Err(ValidationError::BadDifficulty)),
            "missing retarget seed must fail closed, got {res:?}"
        );
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
        assert!(check_difficulty(&new_header, &prev, Network::Testnet4, |_| None, |_| None).is_ok());
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
            check_difficulty(&new_header, &prev, Network::Testnet4, get_ancestor, |_| None).is_ok(),
            "BIP94 first-block-seeded difficulty must be accepted on testnet4"
        );

        // A block carrying the old testnet3 (prev-seeded = powlimit) bits is
        // rejected — that's the consensus divergence this fix closes.
        new_header.bits = CompactTarget::from_consensus(TESTNET_POWLIMIT_BITS);
        assert!(
            matches!(
                check_difficulty(&new_header, &prev, Network::Testnet4, get_ancestor, |_| None),
                Err(ValidationError::BadDifficulty)
            ),
            "prev-seeded (testnet3) difficulty must be rejected on testnet4"
        );
    }

    /// Block templates take their `nBits` from `next_bits`, and a received
    /// block is judged by `check_difficulty`. Where the two disagree, a miner
    /// hashing the template finds a block the node itself rejects. The case
    /// that matters is a retarget boundary, where the answer is not the
    /// parent's bits; the mid-period testnet case shows the timestamp is an
    /// input.
    #[test]
    fn next_bits_agrees_with_check_difficulty_at_period_boundary() {
        let t0 = 1_700_000_000u32;
        let period_bits = 0x1c00ffffu32;

        for network in [Network::Bitcoin, Network::Testnet4] {
            let genesis = bitcoin::constants::genesis_block(network);
            let mut first_header = genesis.header;
            first_header.time = t0;
            first_header.bits = CompactTarget::from_consensus(period_bits);
            let first_entry = entry(first_header, 2016);

            // The period ran twice as fast as intended, so the target halves.
            let mut prev_header = genesis.header;
            prev_header.time = t0 + TARGET_TIMESPAN / 2;
            prev_header.bits = CompactTarget::from_consensus(period_bits);
            let prev = entry(prev_header, 4031);
            let get_ancestor =
                |h: u32| if h == 2016 { Some(first_entry.clone()) } else { None };

            let header_time = prev_header.time + 600;
            let bits = next_bits(network, &prev, header_time, get_ancestor, |_| None)
                .expect("the seed is present");
            assert_ne!(
                bits, prev_header.bits,
                "{network}: premise — a boundary block does not inherit its parent's bits"
            );

            let mut header = genesis.header;
            header.time = header_time;
            header.bits = bits;
            assert!(
                check_difficulty(&header, &prev, network, get_ancestor, |_| None).is_ok(),
                "{network}: the bits next_bits computes must pass check_difficulty"
            );
            header.bits = prev_header.bits;
            assert!(
                matches!(
                    check_difficulty(&header, &prev, network, get_ancestor, |_| None),
                    Err(ValidationError::BadDifficulty)
                ),
                "{network}: the parent's bits are wrong at the boundary"
            );
        }

        // Mid-period on testnet4 the header's own timestamp decides: within 20
        // minutes of the parent the period difficulty holds, past it the
        // minimum difficulty applies.
        let genesis = bitcoin::constants::genesis_block(Network::Testnet4);
        let mut prev_header = genesis.header;
        prev_header.time = t0;
        prev_header.bits = CompactTarget::from_consensus(period_bits);
        let prev = entry(prev_header, 100);
        let soon = prev_header.time + TESTNET_ALLOW_MIN_DIFF_AFTER;
        let late = soon + 1;
        let at_soon = next_bits(Network::Testnet4, &prev, soon, |_| None, |_| None).unwrap();
        let at_late = next_bits(Network::Testnet4, &prev, late, |_| None, |_| None).unwrap();
        assert_eq!(at_soon.to_consensus(), period_bits);
        assert_eq!(at_late.to_consensus(), TESTNET_POWLIMIT_BITS);
        for (time, bits) in [(soon, at_soon), (late, at_late)] {
            let mut header = genesis.header;
            header.time = time;
            header.bits = bits;
            assert!(check_difficulty(&header, &prev, Network::Testnet4, |_| None, |_| None).is_ok());
        }
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
        assert!(check_difficulty(&genesis.header, &entry, Network::Regtest, |_| None, |_| None).is_ok());
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
        assert!(check_difficulty(&genesis.header, &entry, Network::Regtest, |_| None, |_| None).is_err());
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
        assert!(check_difficulty(&genesis.header, &prev, Network::Bitcoin, |_| None, |_| None).is_ok());
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

        assert!(check_difficulty(&new_header, &prev, Network::Bitcoin, get_ancestor, |_| None).is_ok());
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

        assert!(check_difficulty(&new_header, &prev, Network::Bitcoin, get_ancestor, |_| None).is_ok());
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

        assert!(check_difficulty(&header, &prev, Network::Signet, |_| None, |_| None).is_ok());
    }

    /// Build a parent-pointer-chained run of `count` block-index entries whose
    /// timestamps are produced by `time_at(height)`, returning the entries plus
    /// a by-hash resolver (mirroring `Store::get_block_index`). Each entry's
    /// `prev_blockhash` links to the previous entry's real `block_hash()`, so a
    /// `check_timestamp` walk reaches the intended ancestors.
    fn build_chain(
        count: u32,
        time_at: impl Fn(u32) -> u32,
    ) -> (Vec<BlockIndexEntry>, std::collections::HashMap<BlockHash, BlockIndexEntry>) {
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let mut entries: Vec<BlockIndexEntry> = Vec::with_capacity(count as usize);
        for i in 0..count {
            let mut hdr = genesis.header;
            hdr.time = time_at(i);
            if i > 0 {
                hdr.prev_blockhash = entries[(i - 1) as usize].header.block_hash();
            }
            entries.push(BlockIndexEntry {
                header: hdr,
                height: i,
                status: BlockStatus::Valid,
                num_tx: 1,
                file_number: 0,
                data_pos: 0,
                chainwork: [0u8; 32],
            });
        }
        let map = entries
            .iter()
            .map(|e| (e.header.block_hash(), e.clone()))
            .collect();
        (entries, map)
    }

    #[test]
    fn test_timestamp_above_median_passes() {
        // Build 11 ancestors with increasing timestamps, header time above median -> pass.
        let base_time = 1_000_000u32;
        let (entries, map) = build_chain(11, |i| base_time + i * 100);
        let prev = entries.last().unwrap().clone();

        // Median of [base, base+100, ..., base+1000] sorted = base+500
        let mut header = prev.header;
        header.time = base_time + 501; // Above median

        assert!(check_timestamp(&header, &prev, |h| map.get(h).cloned()).is_ok());
    }

    #[test]
    fn test_timestamp_at_median_fails() {
        // Header time equal to median of previous 11 blocks -> TimeTooOld.
        let base_time = 1_000_000u32;
        let (entries, map) = build_chain(11, |i| base_time + i * 100);
        let prev = entries.last().unwrap().clone();

        // Median of [base, base+100, ..., base+1000] sorted = base+500
        let mut header = prev.header;
        header.time = base_time + 500; // Equal to median

        assert!(matches!(
            check_timestamp(&header, &prev, |h| map.get(h).cloned()),
            Err(ValidationError::TimeTooOld)
        ));
    }

    #[test]
    fn test_timestamp_walks_candidate_branch_not_active_chain() {
        // Regression for the testnet4 reorg wedge (node stuck at height 139,285):
        // a block on a competing branch must have its median-time-past computed
        // from *its own* ancestors via the parent-pointer walk, not from whatever
        // the active-chain height index holds at those heights.
        //
        // Two branches share heights 0..=2, then diverge for the entire 11-block
        // MTP window: the canonical branch carries low timestamps, the active
        // fork carries high ones. A candidate extending the canonical branch is
        // judged only against canonical ancestors, so it is accepted even though
        // its timestamp sits far below the active fork's MTP — letting the reorg
        // proceed. Resolved by active-chain height index, the same candidate
        // would have been rejected `time-too-old` and wedged the node.
        let base = 1_000_000u32;

        // Canonical branch, heights 0..=13, steadily increasing low timestamps.
        let (canonical, mut map) = build_chain(14, |h| base + h * 100);

        // Competing fork: shares heights 0..=2, then heights 3..=13 with high
        // timestamps, linked by their own parent pointers (vector index == height).
        let mut fork: Vec<BlockIndexEntry> = canonical[..3].to_vec();
        for h in 3..=13u32 {
            let mut e = canonical[h as usize].clone();
            e.header.time = base + 50_000 + h * 100;
            e.header.prev_blockhash = fork[(h - 1) as usize].header.block_hash();
            fork.push(e);
        }
        for e in &fork {
            map.insert(e.header.block_hash(), e.clone());
        }

        let canon_tip = canonical[13].clone();
        let fork_tip = fork[13].clone();

        // Candidate on the canonical branch: above the canonical MTP (base+800),
        // below the fork MTP (base+50_800).
        let mut candidate = canon_tip.header;
        candidate.prev_blockhash = canon_tip.header.block_hash();
        candidate.time = base + 900;

        // Walking the candidate's own (canonical) ancestors accepts it...
        assert!(
            check_timestamp(&candidate, &canon_tip, |h| map.get(h).cloned()).is_ok(),
            "candidate must pass against its own canonical ancestors"
        );

        // ...whereas judging it against the active fork's ancestors rejects it —
        // exactly the by-height behaviour that wedged the testnet4 node.
        assert!(
            matches!(
                check_timestamp(&candidate, &fork_tip, |h| map.get(h).cloned()),
                Err(ValidationError::TimeTooOld)
            ),
            "the active fork's MTP is higher — the old by-height walk wedged here"
        );
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
