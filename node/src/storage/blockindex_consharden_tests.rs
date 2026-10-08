//! A block's work is Core's `GetBitsProof`, including for bits no valid
//! header carries.
//!
//! Every expected value below is Core's: `GetBitsProof` from `chain.cpp`,
//! copied verbatim and compiled with Core's own `arith_uint256.cpp` at commit
//! 16613c9de9, run over each `bits`.

use super::*;
use bitcoin::hex::DisplayHex;

fn work_hex(bits: u32) -> String {
    work_for_bits(CompactTarget::from_consensus(bits)).to_lower_hex_string()
}

/// `(bits, GetBitsProof(bits))`, the work as 64 hex digits without leading
/// zeros.
const CORE_WORK: &[(u32, &str)] = &[
    // Zero targets: an exponent or a mantissa of zero, or a mantissa shifted
    // out by a small exponent.
    (0x0000_0000, "0"),
    (0x0012_3456, "0"),
    (0x0100_3456, "0"),
    (0x0300_0000, "0"),
    (0x0480_0000, "0"),
    (0x1d00_0000, "0"),
    (0x0180_0000, "0"),
    (0x2100_0000, "0"),
    (0x2300_0000, "0"),
    // Negative: the sign bit with a nonzero mantissa.
    (0x0492_3456, "0"),
    (0x1d80_ffff, "0"),
    (0x01fe_dcba, "0"),
    // Overflowing: more than 256 bits.
    (0x2200_0100, "0"),
    (0x2200_ffff, "0"),
    (0x2300_0001, "0"),
    (0x2101_0000, "0"),
    (0xff12_3456, "0"),
    // Small exponents keep the mantissa's top bytes.
    (0x0112_3456, "d79435e50d79435e50d79435e50d79435e50d79435e50d79435e50d79435e50"),
    (0x0212_3456, "e0f7d0fc35d34ac057e0cda2850689332253d0537bf68d97f968bd609c6c4"),
    (0x0312_3456, "e0fff97690309e2f96677e115e465ed2d49ebff2a34c636177dcdb14856"),
    // Exponents 33 and 34 that do not overflow.
    (0x2100_00ff, "101"),
    (0x2100_0100, "ff"),
    (0x2100_ffff, "1"),
    (0x2200_00ff, "1"),
    // Real targets: mainnet genesis, a mainnet retarget, regtest.
    (0x1d00_ffff, "100010001"),
    (0x1703_4219, "4e9235f043634662e0cb"),
    (0x207f_ffff, "2"),
];

#[test]
fn block_work_is_cores_get_bits_proof() {
    for (bits, core) in CORE_WORK {
        assert_eq!(work_hex(*bits), format!("{core:0>64}"), "bits {bits:08x}");
    }
}

/// Bits that carry no work add none: a zero target used to count as
/// 2^256 - 1, more than any chain.
#[test]
fn bits_without_work_add_nothing_to_chainwork() {
    let parent = work_for_bits(CompactTarget::from_consensus(0x1d00_ffff));
    for bits in [0x0000_0000u32, 0x0492_3456, 0x2300_0001] {
        assert_eq!(add_u256(&parent, &work_for_bits(CompactTarget::from_consensus(bits))), parent);
    }
}

/// Every target a header's proof of work can meet decodes as before, so no
/// chainwork already in an index changes.
#[test]
fn work_is_unchanged_for_every_target_a_header_can_meet() {
    let mantissas = [
        0x00_0001, 0x00_00ff, 0x00_0100, 0x00_ffff, 0x01_0000, 0x12_3456, 0x7f_ffff, 0x00_8000,
        0x7f_0000, 0x40_0000, 0x00_7fff, 0x03_77ae,
    ];
    for exponent in 1u32..=32 {
        for mantissa in mantissas {
            let bits = CompactTarget::from_consensus((exponent << 24) | mantissa);
            let old_target = target_from_compact(bits);
            assert_eq!(
                target_with_work(bits),
                (old_target != [0u8; 32]).then_some(old_target),
                "bits {:08x}",
                bits.to_consensus()
            );
        }
    }
}
