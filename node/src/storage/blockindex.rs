use bitcoin::block::Header;
use bitcoin::pow::CompactTarget;
use serde::{Deserialize, Serialize};

/// Status of a block in the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockStatus {
    HeaderOnly,
    DataStored,
    Valid,
    Invalid,
    Pruned,
}

/// Metadata for a block stored in the block index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockIndexEntry {
    #[serde(with = "header_serde")]
    pub header: Header,
    pub height: u32,
    pub status: BlockStatus,
    pub num_tx: u32,
    pub file_number: u32,
    pub data_pos: u32,
    pub chainwork: [u8; 32],
}

/// Compute the work represented by a single block with the given target bits.
/// Returns 2^256 / (target + 1) as a big-endian [u8; 32].
pub fn work_for_bits(bits: CompactTarget) -> [u8; 32] {
    let target = target_from_compact(bits);

    // work = (2^256 - target - 1) / (target + 1) + 1
    // which equals floor(2^256 / (target + 1))
    let target_plus_one = add_one_u256(&target);
    if target_plus_one == [0u8; 32] {
        // target was max (all 0xff), work is 1
        let mut result = [0u8; 32];
        result[31] = 1;
        return result;
    }
    div_2_256_by(&target_plus_one)
}

/// Add two big-endian U256 values.
pub fn add_u256(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    result
}

/// Convert CompactTarget (nBits) to a 256-bit target as big-endian [u8; 32].
pub fn target_from_compact(bits: CompactTarget) -> [u8; 32] {
    let bits_u32 = bits.to_consensus();
    let exponent = (bits_u32 >> 24) as usize;
    let mantissa = bits_u32 & 0x007f_ffff;

    let mut target = [0u8; 32];
    if exponent == 0 {
        return target;
    }

    // The mantissa occupies 3 bytes starting at position (32 - exponent)
    let byte_offset = 32usize.saturating_sub(exponent);
    if byte_offset < 32 {
        target[byte_offset] = ((mantissa >> 16) & 0xff) as u8;
    }
    if byte_offset + 1 < 32 {
        target[byte_offset + 1] = ((mantissa >> 8) & 0xff) as u8;
    }
    if byte_offset + 2 < 32 {
        target[byte_offset + 2] = (mantissa & 0xff) as u8;
    }

    // If the high bit of mantissa is set, the value is negative in Bitcoin's encoding.
    // For valid PoW targets, this doesn't happen.
    target
}

/// Add 1 to a big-endian U256.
fn add_one_u256(a: &[u8; 32]) -> [u8; 32] {
    let mut result = *a;
    for i in (0..32).rev() {
        let (val, overflow) = result[i].overflowing_add(1);
        result[i] = val;
        if !overflow {
            break;
        }
    }
    result
}

/// Compute floor(2^256 / divisor) for a big-endian U256 divisor.
/// Uses long division.
fn div_2_256_by(divisor: &[u8; 32]) -> [u8; 32] {
    // Use Bitcoin Core's GetBlockProof() approach:
    // result = (~divisor) / divisor + 1
    // which equals floor(2^256 / (divisor))
    // But since divisor here is already (target+1), this gives floor(2^256 / (target+1))
    let mut neg = [0u8; 32];
    for i in 0..32 {
        neg[i] = !divisor[i];
    }

    // result = neg / divisor + 1
    // Use simple repeated subtraction? No, too slow.
    // For regtest (target is huge, work is tiny ~2), this is fine with a direct approach.

    // Let's just do the division properly with u128s
    // Convert neg and divisor to little-endian u64 limbs for easier math
    let mut n_le = [0u64; 4]; // ~divisor in LE limbs
    let mut d_le = [0u64; 4]; // divisor in LE limbs
    for i in 0..4 {
        let be_idx = 3 - i;
        let off = be_idx * 8;
        n_le[i] = u64::from_be_bytes([
            neg[off],
            neg[off + 1],
            neg[off + 2],
            neg[off + 3],
            neg[off + 4],
            neg[off + 5],
            neg[off + 6],
            neg[off + 7],
        ]);
        d_le[i] = u64::from_be_bytes([
            divisor[off],
            divisor[off + 1],
            divisor[off + 2],
            divisor[off + 3],
            divisor[off + 4],
            divisor[off + 5],
            divisor[off + 6],
            divisor[off + 7],
        ]);
    }

    // Simple long division: n_le / d_le
    let q_le = div_u256_le(&n_le, &d_le);

    // Add 1
    let mut carry = 1u64;
    let mut result_le = [0u64; 4];
    for (i, limb) in q_le.iter().enumerate() {
        let (v, c1) = limb.overflowing_add(carry);
        result_le[i] = v;
        carry = u64::from(c1);
    }

    // Convert back to big-endian bytes
    let mut result = [0u8; 32];
    for (i, limb) in result_le.iter().enumerate() {
        let be_idx = 3 - i;
        let bytes = limb.to_be_bytes();
        let off = be_idx * 8;
        result[off..off + 8].copy_from_slice(&bytes);
    }

    result
}

/// Divide a 256-bit number by another, both in little-endian u64 limbs.
/// Returns the quotient.
fn div_u256_le(numerator: &[u64; 4], divisor: &[u64; 4]) -> [u64; 4] {
    // Find highest non-zero limb of divisor
    let mut d_top = 3;
    while d_top > 0 && divisor[d_top] == 0 {
        d_top -= 1;
    }

    if divisor[d_top] == 0 {
        // Division by zero - return max
        return [u64::MAX; 4];
    }

    // For the common case (regtest), the divisor is very large and the quotient is very small.
    // Use a simple shift-and-subtract algorithm.
    let mut rem = *numerator;
    let mut quot = [0u64; 4];

    // Find the number of significant bits
    let num_bits = 256 - leading_zeros_u256_le(numerator);
    let div_bits = 256 - leading_zeros_u256_le(divisor);

    if num_bits < div_bits {
        return [0u64; 4]; // numerator < divisor
    }

    let shift = num_bits - div_bits;

    // Shift divisor left by `shift` bits
    let mut shifted_div = shl_u256_le(divisor, shift);

    for i in (0..=shift).rev() {
        if gte_u256_le(&rem, &shifted_div) {
            rem = sub_u256_le(&rem, &shifted_div);
            // Set bit i in quotient
            quot[(i / 64) as usize] |= 1u64 << (i % 64);
        }
        shifted_div = shr_u256_le(&shifted_div, 1);
    }

    quot
}

fn leading_zeros_u256_le(val: &[u64; 4]) -> u32 {
    for i in (0..4).rev() {
        if val[i] != 0 {
            return (3 - i as u32) * 64 + val[i].leading_zeros();
        }
    }
    256
}

fn shl_u256_le(val: &[u64; 4], shift: u32) -> [u64; 4] {
    if shift >= 256 {
        return [0u64; 4];
    }
    let limb_shift = (shift / 64) as usize;
    let bit_shift = shift % 64;
    let mut result = [0u64; 4];
    for i in limb_shift..4 {
        result[i] = val[i - limb_shift] << bit_shift;
        if bit_shift > 0 && i > limb_shift {
            result[i] |= val[i - limb_shift - 1] >> (64 - bit_shift);
        }
    }
    result
}

fn shr_u256_le(val: &[u64; 4], shift: u32) -> [u64; 4] {
    if shift >= 256 {
        return [0u64; 4];
    }
    let limb_shift = (shift / 64) as usize;
    let bit_shift = shift % 64;
    let mut result = [0u64; 4];
    for i in 0..(4 - limb_shift) {
        result[i] = val[i + limb_shift] >> bit_shift;
        if bit_shift > 0 && i + limb_shift + 1 < 4 {
            result[i] |= val[i + limb_shift + 1] << (64 - bit_shift);
        }
    }
    result
}

fn gte_u256_le(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true // equal
}

fn sub_u256_le(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (diff, b1) = a[i].overflowing_sub(b[i]);
        let (diff2, b2) = diff.overflowing_sub(borrow);
        result[i] = diff2;
        borrow = if b1 || b2 { 1 } else { 0 };
    }
    result
}

/// Compute difficulty as a float from compact target bits.
/// difficulty = max_target / current_target
/// For regtest, max_target uses exponent 0x20.
pub fn target_to_difficulty(bits: CompactTarget) -> f64 {
    let bits_u32 = bits.to_consensus();
    let exponent = (bits_u32 >> 24) as i32;
    let mantissa = (bits_u32 & 0x00ff_ffff) as f64;
    if mantissa == 0.0 {
        return 0.0;
    }

    // Bitcoin Core formula (matches getdifficulty RPC):
    // difficulty = 0x0000ffff / mantissa * 2^(8*(0x1d - exponent))
    let shift = 8 * (0x1d - exponent);
    let diff = 0x0000ffff as f64 / mantissa;
    if shift >= 0 {
        diff * (2.0_f64).powi(shift)
    } else {
        diff / (2.0_f64).powi(-shift)
    }
}

/// Convert a big-endian [u8; 32] target back to CompactTarget (nBits).
pub fn compact_from_target(target: &[u8; 32]) -> u32 {
    // Find first non-zero byte
    let mut first_nonzero = 0;
    while first_nonzero < 32 && target[first_nonzero] == 0 {
        first_nonzero += 1;
    }

    if first_nonzero == 32 {
        return 0; // Zero target
    }

    let exponent = (32 - first_nonzero) as u32;

    // Extract 3-byte mantissa
    let mut mantissa: u32 = (target[first_nonzero] as u32) << 16;
    if first_nonzero + 1 < 32 {
        mantissa |= (target[first_nonzero + 1] as u32) << 8;
    }
    if first_nonzero + 2 < 32 {
        mantissa |= target[first_nonzero + 2] as u32;
    }

    // If high bit of mantissa is set, shift right and increment exponent
    if mantissa & 0x00800000 != 0 {
        mantissa >>= 8;
        return ((exponent + 1) << 24) | mantissa;
    }

    (exponent << 24) | mantissa
}

/// Multiply a big-endian U256 by a u32.
pub fn mul_u256_u32(a: &[u8; 32], b: u32) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry: u64 = 0;
    for i in (0..32).rev() {
        let prod = a[i] as u64 * b as u64 + carry;
        result[i] = prod as u8;
        carry = prod >> 8;
    }
    result
}

/// Divide a big-endian U256 by a u32.
pub fn div_u256_u32(a: &[u8; 32], b: u32) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut rem: u64 = 0;
    for i in 0..32 {
        let cur = (rem << 8) | a[i] as u64;
        result[i] = (cur / b as u64) as u8;
        rem = cur % b as u64;
    }
    result
}

/// Custom serde for bitcoin::block::Header via consensus encoding.
mod header_serde {
    use bitcoin::block::Header;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(header: &Header, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = bitcoin::consensus::serialize(header);
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Header, D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        bitcoin::consensus::deserialize(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_work_for_regtest_min_difficulty() {
        // Regtest min difficulty: 0x207fffff
        let bits = CompactTarget::from_consensus(0x207fffff);
        let work = work_for_bits(bits);
        // Expected work is 2 for regtest min difficulty
        assert_eq!(work[31], 2);
        assert!(work[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_add_u256() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 1;
        b[31] = 2;
        let result = add_u256(&a, &b);
        assert_eq!(result[31], 3);
    }

    #[test]
    fn test_target_from_compact() {
        // 0x207fffff should give a target with 0x7fffff at byte offset 32-0x20=0
        let bits = CompactTarget::from_consensus(0x207fffff);
        let target = target_from_compact(bits);
        assert_eq!(target[0], 0x7f);
        assert_eq!(target[1], 0xff);
        assert_eq!(target[2], 0xff);
        // Rest should be zero
        assert!(target[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_chainwork_accumulation() {
        let bits = CompactTarget::from_consensus(0x207fffff);
        let work = work_for_bits(bits);
        // 10 blocks of regtest work
        let mut total = [0u8; 32];
        for _ in 0..10 {
            total = add_u256(&total, &work);
        }
        assert_eq!(total[31], 20);
    }

    #[test]
    fn test_target_to_difficulty_regtest() {
        let bits = CompactTarget::from_consensus(0x207fffff);
        let diff = target_to_difficulty(bits);
        // Regtest min difficulty is approximately 4.6565e-10
        assert!(diff > 4e-10 && diff < 5e-10, "got {}", diff);
    }

    #[test]
    fn test_add_u256_carry_propagation() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 0xFF;
        b[31] = 0x01;
        let result = add_u256(&a, &b);
        // 0xFF + 0x01 = 0x100: byte 31 should be 0x00, carry propagates to byte 30
        assert_eq!(result[31], 0x00);
        assert_eq!(result[30], 0x01);
        assert!(result[..30].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_add_u256_max_overflow() {
        let a = [0xFFu8; 32];
        let mut b = [0u8; 32];
        b[31] = 0x01;
        let result = add_u256(&a, &b);
        // All-0xFF + 1 should wrap to all-0x00 (overflow wraps)
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_mul_u256_u32_basic() {
        let mut a = [0u8; 32];
        a[31] = 3;
        let result = mul_u256_u32(&a, 5);
        assert_eq!(result[31], 15);
        assert!(result[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_mul_u256_u32_large_carry() {
        let mut a = [0u8; 32];
        a[31] = 0xFF;
        let result = mul_u256_u32(&a, 256);
        // 0xFF * 256 = 0xFF00
        assert_eq!(result[30], 0xFF);
        assert_eq!(result[31], 0x00);
        assert!(result[..30].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_div_u256_u32_exact() {
        let mut a = [0u8; 32];
        a[31] = 30;
        let result = div_u256_u32(&a, 5);
        assert_eq!(result[31], 6);
        assert!(result[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_div_u256_u32_with_remainder() {
        let mut a = [0u8; 32];
        a[31] = 7;
        let result = div_u256_u32(&a, 2);
        // 7 / 2 = 3 (truncated)
        assert_eq!(result[31], 3);
        assert!(result[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_compact_from_target_roundtrip() {
        // Regtest min difficulty: 0x207fffff
        let bits1 = CompactTarget::from_consensus(0x207fffff);
        let target1 = target_from_compact(bits1);
        let recovered1 = compact_from_target(&target1);
        assert_eq!(recovered1, 0x207fffff);

        // Mainnet genesis difficulty: 0x1d00ffff
        let bits2 = CompactTarget::from_consensus(0x1d00ffff);
        let target2 = target_from_compact(bits2);
        let recovered2 = compact_from_target(&target2);
        assert_eq!(recovered2, 0x1d00ffff);
    }

    #[test]
    fn test_target_from_compact_mainnet() {
        // 0x1d00ffff: exponent=0x1d=29, mantissa=0x00ffff
        // byte_offset = 32 - 29 = 3
        // target[3] = (0x00ffff >> 16) & 0xff = 0x00
        // target[4] = (0x00ffff >> 8) & 0xff  = 0xFF
        // target[5] = 0x00ffff & 0xff          = 0xFF
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let target = target_from_compact(bits);
        assert_eq!(target[3], 0x00);
        assert_eq!(target[4], 0xFF);
        assert_eq!(target[5], 0xFF);
        // All other bytes should be zero
        assert!(target[..3].iter().all(|&b| b == 0));
        assert!(target[6..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_work_for_mainnet_bits() {
        // Mainnet genesis: 0x1d00ffff
        // work = 2^256 / (target + 1)
        // target = 0xFFFF * 2^208, so work ~ 2^256 / (0xFFFF * 2^208)
        //        = 2^48 / 0xFFFF ~ 2^32 * (1 + 2^-16 + ...) ~ 0x01_0001_0001
        // This is a 5-byte value starting at byte index 27.
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let work = work_for_bits(bits);
        // Work should be non-zero
        assert_ne!(work, [0u8; 32]);
        // Bytes 0..27 should all be zero (the value fits in ~5 bytes)
        assert!(work[..27].iter().all(|&b| b == 0), "upper bytes should be zero");
        // Byte 27 should be non-zero (it's 0x01 for the leading byte of ~0x100010001)
        assert!(work[27] > 0, "byte 27 should be nonzero, got 0x{:02x}", work[27]);
    }
}
