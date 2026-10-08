//! OP_SUCCESSx set and pay-to-anchor handling, checked against Bitcoin Core.

use super::*;
use crate::checker::NoopChecker;

/// BIP342's OP_SUCCESSx opcodes, as Core's `IsOpSuccess` lists them
/// (src/script/script.cpp:364-370): 80, 98, 126-129, 131-134, 137-138,
/// 141-142, 149-153, 187-254. Written out one by one so that this table
/// does not share a range expression with the code under test.
const CORE_OP_SUCCESS: [u8; 87] = [
    80, 98, 126, 127, 128, 129, 131, 132, 133, 134, 137, 138, 141, 142, 149, 150, 151, 152, 153,
    187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204,
    205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222,
    223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
    241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
];

#[test]
fn op_success_set_matches_core_for_every_opcode() {
    for op in 0..=255u8 {
        assert_eq!(
            is_op_success(op),
            CORE_OP_SUCCESS.contains(&op),
            "opcode {op} ({op:#04x})"
        );
    }
}

#[test]
fn op_success_prescan_finds_left_right_and_bitwise_opcodes() {
    // OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND, OP_OR, OP_XOR: disabled in legacy
    // script, OP_SUCCESSx in tapscript.
    for op in [0x80u8, 0x81, 0x83, 0x84, 0x85, 0x86] {
        // Anywhere in the leaf, including after an unexecuted IF.
        for leaf in [vec![op], vec![0x00, 0x63, op, 0x68, 0x51]] {
            assert_eq!(scan_for_op_success(&leaf, 0), Some(Ok(())), "leaf {leaf:02x?}");
            assert_eq!(
                scan_for_op_success(&leaf, flags::VERIFY_DISCOURAGE_OP_SUCCESS),
                Some(Err(ScriptError::DiscourageOpSuccess)),
                "leaf {leaf:02x?}"
            );
        }
    }
    // OP_SIZE (0x82) sits between them and is an ordinary opcode.
    assert_eq!(scan_for_op_success(&[0x82], 0), None);
}

const P2A_PROGRAM: [u8; 2] = [0x4e, 0x73];

fn discourage() -> u32 {
    flags::VERIFY_P2SH | flags::VERIFY_WITNESS | flags::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
}

#[test]
fn pay_to_anchor_is_not_discouraged() {
    // Core: `!is_p2sh && CScript::IsPayToAnchor(witversion, program)` returns
    // true ahead of the DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM branch
    // (src/script/interpreter.cpp:1990), whatever the witness holds.
    for witness in [vec![], vec![vec![0x01]]] {
        let r = verify_witness_program(&witness, 1, &P2A_PROGRAM, discourage(), &NoopChecker, false);
        assert_eq!(r, Ok(()), "witness {witness:?}");
    }
    let r = verify_witness_program(&[], 1, &P2A_PROGRAM, flags::VERIFY_P2SH | flags::VERIFY_WITNESS, &NoopChecker, false);
    assert_eq!(r, Ok(()));
}

#[test]
fn programs_next_to_pay_to_anchor_stay_discouraged() {
    let cases: [(u8, &[u8], bool); 5] = [
        // P2SH-wrapped anchor: is_p2sh, so not exempt.
        (1, &P2A_PROGRAM, true),
        // Other version, other program bytes, other length.
        (2, &P2A_PROGRAM, false),
        (1, &[0x4e, 0x74], false),
        (1, &[0x4e, 0x73, 0x00], false),
        (16, &[0x4e, 0x73], false),
    ];
    for (version, program, is_p2sh) in cases {
        let r = verify_witness_program(&[], version, program, discourage(), &NoopChecker, is_p2sh);
        assert_eq!(
            r,
            Err(ScriptError::DiscourageUpgradableWitnessProgram),
            "v{version} {program:02x?} p2sh={is_p2sh}"
        );
        // Without the policy flag they are anyone-can-spend, as in Core.
        let r = verify_witness_program(
            &[],
            version,
            program,
            flags::VERIFY_P2SH | flags::VERIFY_WITNESS,
            &NoopChecker,
            is_p2sh,
        );
        assert_eq!(r, Ok(()), "v{version} {program:02x?} p2sh={is_p2sh}");
    }
}
