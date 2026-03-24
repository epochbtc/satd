use crate::checker::{ExecData, SignatureChecker, SigVersion};
use crate::condition::ConditionStack;
use crate::encoding;
use crate::error::ScriptError;
use crate::flags;
use crate::scriptnum::ScriptNum;
use crate::stack::{self, StackItem};

use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use ripemd::Ripemd160;

/// Maximum number of bytes pushable to the stack.
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// Maximum number of non-push operations per script.
const MAX_OPS_PER_SCRIPT: usize = 201;
/// Maximum number of public keys per multisig.
const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
/// Maximum script length in bytes.
const MAX_SCRIPT_SIZE: usize = 10000;
/// Maximum number of values on script interpreter stack.
const MAX_STACK_SIZE: usize = 1000;
/// Validation weight per passing signature (Tapscript only, BIP 342).
const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;

// Opcode constants (raw byte values matching Bitcoin Core).
#[allow(dead_code)]
mod op {
    pub const OP_0: u8 = 0x00;
    pub const OP_PUSHDATA1: u8 = 0x4c;
    pub const OP_PUSHDATA2: u8 = 0x4d;
    pub const OP_PUSHDATA4: u8 = 0x4e;
    pub const OP_1NEGATE: u8 = 0x4f;
    pub const OP_RESERVED: u8 = 0x50;
    pub const OP_1: u8 = 0x51;
    pub const OP_16: u8 = 0x60;
    pub const OP_NOP: u8 = 0x61;
    pub const OP_VER: u8 = 0x62;
    pub const OP_IF: u8 = 0x63;
    pub const OP_NOTIF: u8 = 0x64;
    pub const OP_VERIF: u8 = 0x65;
    pub const OP_VERNOTIF: u8 = 0x66;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_VERIFY: u8 = 0x69;
    pub const OP_RETURN: u8 = 0x6a;
    pub const OP_TOALTSTACK: u8 = 0x6b;
    pub const OP_FROMALTSTACK: u8 = 0x6c;
    pub const OP_2DROP: u8 = 0x6d;
    pub const OP_2DUP: u8 = 0x6e;
    pub const OP_3DUP: u8 = 0x6f;
    pub const OP_2OVER: u8 = 0x70;
    pub const OP_2ROT: u8 = 0x71;
    pub const OP_2SWAP: u8 = 0x72;
    pub const OP_IFDUP: u8 = 0x73;
    pub const OP_DEPTH: u8 = 0x74;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_NIP: u8 = 0x77;
    pub const OP_OVER: u8 = 0x78;
    pub const OP_PICK: u8 = 0x79;
    pub const OP_ROLL: u8 = 0x7a;
    pub const OP_ROT: u8 = 0x7b;
    pub const OP_SWAP: u8 = 0x7c;
    pub const OP_TUCK: u8 = 0x7d;
    pub const OP_CAT: u8 = 0x7e;
    pub const OP_SUBSTR: u8 = 0x7f;
    pub const OP_LEFT: u8 = 0x80;
    pub const OP_RIGHT: u8 = 0x81;
    pub const OP_SIZE: u8 = 0x82;
    pub const OP_INVERT: u8 = 0x83;
    pub const OP_AND: u8 = 0x84;
    pub const OP_OR: u8 = 0x85;
    pub const OP_XOR: u8 = 0x86;
    pub const OP_EQUAL: u8 = 0x87;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_RESERVED1: u8 = 0x89;
    pub const OP_RESERVED2: u8 = 0x8a;
    pub const OP_1ADD: u8 = 0x8b;
    pub const OP_1SUB: u8 = 0x8c;
    pub const OP_2MUL: u8 = 0x8d;
    pub const OP_2DIV: u8 = 0x8e;
    pub const OP_NEGATE: u8 = 0x8f;
    pub const OP_ABS: u8 = 0x90;
    pub const OP_NOT: u8 = 0x91;
    pub const OP_0NOTEQUAL: u8 = 0x92;
    pub const OP_ADD: u8 = 0x93;
    pub const OP_SUB: u8 = 0x94;
    pub const OP_MUL: u8 = 0x95;
    pub const OP_DIV: u8 = 0x96;
    pub const OP_MOD: u8 = 0x97;
    pub const OP_LSHIFT: u8 = 0x98;
    pub const OP_RSHIFT: u8 = 0x99;
    pub const OP_BOOLAND: u8 = 0x9a;
    pub const OP_BOOLOR: u8 = 0x9b;
    pub const OP_NUMEQUAL: u8 = 0x9c;
    pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
    pub const OP_NUMNOTEQUAL: u8 = 0x9e;
    pub const OP_LESSTHAN: u8 = 0x9f;
    pub const OP_GREATERTHAN: u8 = 0xa0;
    pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
    pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
    pub const OP_MIN: u8 = 0xa3;
    pub const OP_MAX: u8 = 0xa4;
    pub const OP_WITHIN: u8 = 0xa5;
    pub const OP_RIPEMD160: u8 = 0xa6;
    pub const OP_SHA1: u8 = 0xa7;
    pub const OP_SHA256: u8 = 0xa8;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_HASH256: u8 = 0xaa;
    pub const OP_CODESEPARATOR: u8 = 0xab;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_CHECKSIGVERIFY: u8 = 0xad;
    pub const OP_CHECKMULTISIG: u8 = 0xae;
    pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
    pub const OP_NOP1: u8 = 0xb0;
    pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1; // OP_NOP2
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2; // OP_NOP3
    pub const OP_NOP4: u8 = 0xb3;
    pub const OP_NOP5: u8 = 0xb4;
    pub const OP_NOP6: u8 = 0xb5;
    pub const OP_NOP7: u8 = 0xb6;
    pub const OP_NOP8: u8 = 0xb7;
    pub const OP_NOP9: u8 = 0xb8;
    pub const OP_NOP10: u8 = 0xb9;
    pub const OP_CHECKSIGADD: u8 = 0xba;

    /// Is this opcode disabled (CVE-2010-5137)?
    pub fn is_disabled(opcode: u8) -> bool {
        matches!(
            opcode,
            OP_CAT
                | OP_SUBSTR
                | OP_LEFT
                | OP_RIGHT
                | OP_INVERT
                | OP_AND
                | OP_OR
                | OP_XOR
                | OP_2MUL
                | OP_2DIV
                | OP_MUL
                | OP_DIV
                | OP_MOD
                | OP_LSHIFT
                | OP_RSHIFT
        )
    }
}

/// Read one instruction from the script, advancing `pc`.
///
/// Returns `(opcode, push_data)`. For push operations, `push_data` contains the
/// pushed bytes. For non-push operations, `push_data` is empty.
/// Returns None if the script is malformed.
fn read_instruction(script: &[u8], pc: &mut usize) -> Option<(u8, Vec<u8>)> {
    if *pc >= script.len() {
        return None;
    }
    let opcode = script[*pc];
    *pc += 1;

    if opcode == 0 {
        // OP_0: push empty
        return Some((opcode, Vec::new()));
    }

    if opcode <= 75 {
        // Direct push: next `opcode` bytes
        let n = opcode as usize;
        if *pc + n > script.len() {
            return None; // truncated
        }
        let data = script[*pc..*pc + n].to_vec();
        *pc += n;
        return Some((opcode, data));
    }

    if opcode == op::OP_PUSHDATA1 {
        if *pc >= script.len() {
            return None;
        }
        let n = script[*pc] as usize;
        *pc += 1;
        if *pc + n > script.len() {
            return None;
        }
        let data = script[*pc..*pc + n].to_vec();
        *pc += n;
        return Some((opcode, data));
    }

    if opcode == op::OP_PUSHDATA2 {
        if *pc + 1 >= script.len() {
            return None;
        }
        let n = script[*pc] as usize | ((script[*pc + 1] as usize) << 8);
        *pc += 2;
        if *pc + n > script.len() {
            return None;
        }
        let data = script[*pc..*pc + n].to_vec();
        *pc += n;
        return Some((opcode, data));
    }

    if opcode == op::OP_PUSHDATA4 {
        if *pc + 3 >= script.len() {
            return None;
        }
        let n = script[*pc] as usize
            | ((script[*pc + 1] as usize) << 8)
            | ((script[*pc + 2] as usize) << 16)
            | ((script[*pc + 3] as usize) << 24);
        *pc += 4;
        if *pc + n > script.len() {
            return None;
        }
        let data = script[*pc..*pc + n].to_vec();
        *pc += n;
        return Some((opcode, data));
    }

    // Non-push opcode
    Some((opcode, Vec::new()))
}

/// Evaluate a Bitcoin script.
///
/// This is the main script interpreter, matching Bitcoin Core's `EvalScript()`.
#[allow(clippy::too_many_arguments, clippy::collapsible_if)]
pub fn eval_script(
    stack: &mut Vec<StackItem>,
    script: &[u8],
    script_flags: u32,
    checker: &dyn SignatureChecker,
    sig_version: SigVersion,
    exec_data: &mut ExecData,
) -> Result<(), ScriptError> {
    assert!(
        sig_version == SigVersion::Base
            || sig_version == SigVersion::WitnessV0
            || sig_version == SigVersion::Tapscript
    );

    // Script size limit (not enforced for tapscript)
    if (sig_version == SigVersion::Base || sig_version == SigVersion::WitnessV0)
        && script.len() > MAX_SCRIPT_SIZE
    {
        return Err(ScriptError::ScriptSize);
    }

    let mut pc: usize = 0;
    let mut pbegincodehash: usize = 0;
    let mut altstack: Vec<StackItem> = Vec::new();
    let mut vf_exec = ConditionStack::new();
    let mut n_op_count: usize = 0;
    let require_minimal = flags::has_flag(script_flags, flags::VERIFY_MINIMALDATA);
    let mut opcode_pos: u32 = 0;
    exec_data.codeseparator_pos = 0xFFFFFFFF;
    exec_data.codeseparator_pos_init = true;

    // The main evaluation loop.
    // Wrapping in a closure to catch ScriptNumError -> ScriptError::ScriptNum.
    let result = (|| -> Result<(), ScriptError> {
        while pc < script.len() {
            let f_exec = vf_exec.all_true();

            // Read instruction
            let (opcode, push_data) = read_instruction(script, &mut pc)
                .ok_or(ScriptError::BadOpcode)?;

            if push_data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(ScriptError::PushSize);
            }

            // Op count limit (not enforced for tapscript)
            if sig_version == SigVersion::Base || sig_version == SigVersion::WitnessV0 {
                if opcode > op::OP_16 {
                    n_op_count += 1;
                    if n_op_count > MAX_OPS_PER_SCRIPT {
                        return Err(ScriptError::OpCount);
                    }
                }
            }

            // Disabled opcodes fail even in unexecuted branches
            if op::is_disabled(opcode) {
                return Err(ScriptError::DisabledOpcode);
            }

            // OP_CODESEPARATOR in non-segwit with CONST_SCRIPTCODE
            if opcode == op::OP_CODESEPARATOR
                && sig_version == SigVersion::Base
                && flags::has_flag(script_flags, flags::VERIFY_CONST_SCRIPTCODE)
            {
                return Err(ScriptError::OpCodeSeparator);
            }

            // Push data operations
            if f_exec && opcode <= op::OP_PUSHDATA4 {
                if require_minimal && !encoding::check_minimal_push(&push_data, opcode) {
                    return Err(ScriptError::MinimalData);
                }
                stack.push(push_data);
            } else if f_exec || (op::OP_IF..=op::OP_ENDIF).contains(&opcode) {
                match opcode {
                    // Push value: OP_1NEGATE, OP_1..OP_16
                    op::OP_1NEGATE | op::OP_1..=op::OP_16 => {
                        let n = opcode as i64 - (op::OP_1 as i64 - 1);
                        stack.push(ScriptNum::new(n).serialize());
                    }

                    // Control flow
                    op::OP_NOP => {}

                    op::OP_CHECKLOCKTIMEVERIFY => {
                        if flags::has_flag(script_flags, flags::VERIFY_CHECKLOCKTIMEVERIFY) {
                            if stack.is_empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                            let n_lock_time = ScriptNum::from_bytes(
                                stack.last().unwrap(),
                                require_minimal,
                                5,
                            )
                            .map_err(|_| ScriptError::ScriptNum)?;
                            if n_lock_time < 0 {
                                return Err(ScriptError::NegativeLocktime);
                            }
                            if !checker.check_lock_time(&n_lock_time) {
                                return Err(ScriptError::UnsatisfiedLocktime);
                            }
                        }
                        // else: treat as NOP2
                    }

                    op::OP_CHECKSEQUENCEVERIFY => {
                        if !flags::has_flag(script_flags, flags::VERIFY_CHECKSEQUENCEVERIFY) {
                            // treat as NOP3 — continue to next opcode
                        } else {
                            if stack.is_empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                            let n_sequence = ScriptNum::from_bytes(
                                stack.last().unwrap(),
                                require_minimal,
                                5,
                            )
                            .map_err(|_| ScriptError::ScriptNum)?;
                            if n_sequence < 0 {
                                return Err(ScriptError::NegativeLocktime);
                            }
                            // If disable flag is set, treat as NOP
                            if (n_sequence.value() as u32) & (1 << 31) != 0 {
                                // SEQUENCE_LOCKTIME_DISABLE_FLAG
                                // continue to next opcode
                            } else if !checker.check_sequence(&n_sequence) {
                                return Err(ScriptError::UnsatisfiedLocktime);
                            }
                        }
                    }

                    op::OP_NOP1 | op::OP_NOP4..=op::OP_NOP10 => {
                        if flags::has_flag(script_flags, flags::VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return Err(ScriptError::DiscourageUpgradableNops);
                        }
                    }

                    op::OP_IF | op::OP_NOTIF => {
                        let mut f_value = false;
                        if f_exec {
                            if stack.is_empty() {
                                return Err(ScriptError::InvalidStackOperation);
                            }
                            let vch = stack.last().unwrap();

                            // Tapscript: mandatory minimal IF
                            if sig_version == SigVersion::Tapscript {
                                if vch.len() > 1 || (vch.len() == 1 && vch[0] != 1) {
                                    return Err(ScriptError::TapscriptMinimalIf);
                                }
                            }
                            // Witness v0: policy rule MINIMALIF
                            if sig_version == SigVersion::WitnessV0
                                && flags::has_flag(script_flags, flags::VERIFY_MINIMALIF)
                            {
                                if vch.len() > 1 {
                                    return Err(ScriptError::MinimalIf);
                                }
                                if vch.len() == 1 && vch[0] != 1 {
                                    return Err(ScriptError::MinimalIf);
                                }
                            }

                            f_value = stack::cast_to_bool(vch);
                            if opcode == op::OP_NOTIF {
                                f_value = !f_value;
                            }
                            stack.pop();
                        }
                        vf_exec.push_back(f_value);
                    }

                    op::OP_ELSE => {
                        if vf_exec.is_empty() {
                            return Err(ScriptError::UnbalancedConditional);
                        }
                        vf_exec.toggle_top();
                    }

                    op::OP_ENDIF => {
                        if vf_exec.is_empty() {
                            return Err(ScriptError::UnbalancedConditional);
                        }
                        vf_exec.pop_back();
                    }

                    op::OP_VERIFY => {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        if stack::cast_to_bool(stack.last().unwrap()) {
                            stack.pop();
                        } else {
                            return Err(ScriptError::Verify);
                        }
                    }

                    op::OP_RETURN => {
                        return Err(ScriptError::OpReturn);
                    }

                    // Stack ops
                    op::OP_TOALTSTACK => {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        altstack.push(stack.pop().unwrap());
                    }

                    op::OP_FROMALTSTACK => {
                        if altstack.is_empty() {
                            return Err(ScriptError::InvalidAltstackOperation);
                        }
                        stack.push(altstack.pop().unwrap());
                    }

                    op::OP_2DROP => {
                        if stack.len() < 2 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        stack.pop();
                        stack.pop();
                    }

                    op::OP_2DUP => {
                        if stack.len() < 2 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let len = stack.len();
                        let vch1 = stack[len - 2].clone();
                        let vch2 = stack[len - 1].clone();
                        stack.push(vch1);
                        stack.push(vch2);
                    }

                    op::OP_3DUP => {
                        if stack.len() < 3 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let len = stack.len();
                        let vch1 = stack[len - 3].clone();
                        let vch2 = stack[len - 2].clone();
                        let vch3 = stack[len - 1].clone();
                        stack.push(vch1);
                        stack.push(vch2);
                        stack.push(vch3);
                    }

                    op::OP_2OVER => {
                        if stack.len() < 4 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let len = stack.len();
                        let vch1 = stack[len - 4].clone();
                        let vch2 = stack[len - 3].clone();
                        stack.push(vch1);
                        stack.push(vch2);
                    }

                    op::OP_2ROT => {
                        if stack.len() < 6 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let len = stack.len();
                        let vch1 = stack[len - 6].clone();
                        let vch2 = stack[len - 5].clone();
                        stack.drain(len - 6..len - 4);
                        stack.push(vch1);
                        stack.push(vch2);
                    }

                    op::OP_2SWAP => {
                        if stack.len() < 4 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let len = stack.len();
                        stack.swap(len - 4, len - 2);
                        stack.swap(len - 3, len - 1);
                    }

                    op::OP_IFDUP => {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let vch = stack.last().unwrap().clone();
                        if stack::cast_to_bool(&vch) {
                            stack.push(vch);
                        }
                    }

                    op::OP_DEPTH => {
                        let bn = ScriptNum::new(stack.len() as i64);
                        stack.push(bn.serialize());
                    }

                    op::OP_DROP => {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        stack.pop();
                    }

                    op::OP_DUP => {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let vch = stack.last().unwrap().clone();
                        stack.push(vch);
                    }

                    op::OP_NIP => {
                        if stack.len() < 2 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let len = stack.len();
                        stack.remove(len - 2);
                    }

                    op::OP_OVER => {
                        if stack.len() < 2 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let len = stack.len();
                        let vch = stack[len - 2].clone();
                        stack.push(vch);
                    }

                    op::OP_PICK | op::OP_ROLL => {
                        if stack.len() < 2 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let n = ScriptNum::from_bytes_default(stack.last().unwrap(), require_minimal)
                            .map_err(|_| ScriptError::ScriptNum)?
                            .getint();
                        stack.pop();
                        if n < 0 || n as usize >= stack.len() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let len = stack.len();
                        let vch = stack[len - n as usize - 1].clone();
                        if opcode == op::OP_ROLL {
                            stack.remove(len - n as usize - 1);
                        }
                        stack.push(vch);
                    }

                    op::OP_ROT => {
                        if stack.len() < 3 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let len = stack.len();
                        stack.swap(len - 3, len - 2);
                        stack.swap(len - 2, len - 1);
                    }

                    op::OP_SWAP => {
                        if stack.len() < 2 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let len = stack.len();
                        stack.swap(len - 2, len - 1);
                    }

                    op::OP_TUCK => {
                        if stack.len() < 2 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let vch = stack.last().unwrap().clone();
                        let len = stack.len();
                        stack.insert(len - 2, vch);
                    }

                    op::OP_SIZE => {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let bn = ScriptNum::new(stack.last().unwrap().len() as i64);
                        stack.push(bn.serialize());
                    }

                    // Bitwise logic
                    op::OP_EQUAL | op::OP_EQUALVERIFY => {
                        if stack.len() < 2 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let vch2 = stack.pop().unwrap();
                        let vch1 = stack.pop().unwrap();
                        let f_equal = vch1 == vch2;
                        stack.push(if f_equal {
                            stack::STACK_TRUE.to_vec()
                        } else {
                            stack::STACK_FALSE.to_vec()
                        });
                        if opcode == op::OP_EQUALVERIFY {
                            if f_equal {
                                stack.pop();
                            } else {
                                return Err(ScriptError::EqualVerify);
                            }
                        }
                    }

                    // Unary numeric operations
                    op::OP_1ADD | op::OP_1SUB | op::OP_NEGATE | op::OP_ABS | op::OP_NOT
                    | op::OP_0NOTEQUAL => {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let bn = ScriptNum::from_bytes_default(stack.last().unwrap(), require_minimal)
                            .map_err(|_| ScriptError::ScriptNum)?;
                        let result = match opcode {
                            op::OP_1ADD => bn + ScriptNum::new(1),
                            op::OP_1SUB => bn - ScriptNum::new(1),
                            op::OP_NEGATE => -bn,
                            op::OP_ABS => {
                                if bn < 0 {
                                    -bn
                                } else {
                                    bn
                                }
                            }
                            op::OP_NOT => ScriptNum::from(bn == 0),
                            op::OP_0NOTEQUAL => ScriptNum::from(bn != 0),
                            _ => unreachable!(),
                        };
                        stack.pop();
                        stack.push(result.serialize());
                    }

                    // Binary numeric operations
                    op::OP_ADD
                    | op::OP_SUB
                    | op::OP_BOOLAND
                    | op::OP_BOOLOR
                    | op::OP_NUMEQUAL
                    | op::OP_NUMEQUALVERIFY
                    | op::OP_NUMNOTEQUAL
                    | op::OP_LESSTHAN
                    | op::OP_GREATERTHAN
                    | op::OP_LESSTHANOREQUAL
                    | op::OP_GREATERTHANOREQUAL
                    | op::OP_MIN
                    | op::OP_MAX => {
                        if stack.len() < 2 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let len = stack.len();
                        let bn2 = ScriptNum::from_bytes_default(&stack[len - 1], require_minimal)
                            .map_err(|_| ScriptError::ScriptNum)?;
                        let bn1 = ScriptNum::from_bytes_default(&stack[len - 2], require_minimal)
                            .map_err(|_| ScriptError::ScriptNum)?;

                        let result = match opcode {
                            op::OP_ADD => bn1 + bn2,
                            op::OP_SUB => bn1 - bn2,
                            op::OP_BOOLAND => ScriptNum::from(bn1 != 0 && bn2 != 0),
                            op::OP_BOOLOR => ScriptNum::from(bn1 != 0 || bn2 != 0),
                            op::OP_NUMEQUAL | op::OP_NUMEQUALVERIFY => {
                                ScriptNum::from(bn1 == bn2)
                            }
                            op::OP_NUMNOTEQUAL => ScriptNum::from(bn1 != bn2),
                            op::OP_LESSTHAN => ScriptNum::from(bn1 < bn2),
                            op::OP_GREATERTHAN => ScriptNum::from(bn1 > bn2),
                            op::OP_LESSTHANOREQUAL => ScriptNum::from(bn1 <= bn2),
                            op::OP_GREATERTHANOREQUAL => ScriptNum::from(bn1 >= bn2),
                            op::OP_MIN => {
                                if bn1 < bn2 {
                                    bn1
                                } else {
                                    bn2
                                }
                            }
                            op::OP_MAX => {
                                if bn1 > bn2 {
                                    bn1
                                } else {
                                    bn2
                                }
                            }
                            _ => unreachable!(),
                        };
                        stack.pop();
                        stack.pop();
                        stack.push(result.serialize());

                        if opcode == op::OP_NUMEQUALVERIFY {
                            if stack::cast_to_bool(stack.last().unwrap()) {
                                stack.pop();
                            } else {
                                return Err(ScriptError::NumEqualVerify);
                            }
                        }
                    }

                    op::OP_WITHIN => {
                        if stack.len() < 3 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let len = stack.len();
                        let bn3 = ScriptNum::from_bytes_default(&stack[len - 1], require_minimal)
                            .map_err(|_| ScriptError::ScriptNum)?;
                        let bn2 = ScriptNum::from_bytes_default(&stack[len - 2], require_minimal)
                            .map_err(|_| ScriptError::ScriptNum)?;
                        let bn1 = ScriptNum::from_bytes_default(&stack[len - 3], require_minimal)
                            .map_err(|_| ScriptError::ScriptNum)?;
                        let f_value = bn2 <= bn1 && bn1 < bn3;
                        stack.pop();
                        stack.pop();
                        stack.pop();
                        stack.push(if f_value {
                            stack::STACK_TRUE.to_vec()
                        } else {
                            stack::STACK_FALSE.to_vec()
                        });
                    }

                    // Crypto
                    op::OP_RIPEMD160 => {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let data = stack.pop().unwrap();
                        let mut hasher = Ripemd160::new();
                        ripemd::Digest::update(&mut hasher, &data);
                        let hash: [u8; 20] = ripemd::Digest::finalize(hasher).into();
                        stack.push(hash.to_vec());
                    }

                    op::OP_SHA1 => {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let data = stack.pop().unwrap();
                        let mut hasher = Sha1::new();
                        sha1::Digest::update(&mut hasher, &data);
                        let hash: [u8; 20] = sha1::Digest::finalize(hasher).into();
                        stack.push(hash.to_vec());
                    }

                    op::OP_SHA256 => {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let data = stack.pop().unwrap();
                        let hash = Sha256::digest(&data);
                        stack.push(hash.to_vec());
                    }

                    op::OP_HASH160 => {
                        // RIPEMD160(SHA256(x))
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let data = stack.pop().unwrap();
                        let sha = Sha256::digest(&data);
                        let mut hasher = Ripemd160::new();
                        ripemd::Digest::update(&mut hasher, sha);
                        let hash: [u8; 20] = ripemd::Digest::finalize(hasher).into();
                        stack.push(hash.to_vec());
                    }

                    op::OP_HASH256 => {
                        // SHA256(SHA256(x))
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let data = stack.pop().unwrap();
                        let hash1 = Sha256::digest(&data);
                        let hash2 = Sha256::digest(hash1);
                        stack.push(hash2.to_vec());
                    }

                    op::OP_CODESEPARATOR => {
                        pbegincodehash = pc;
                        exec_data.codeseparator_pos = opcode_pos;
                    }

                    op::OP_CHECKSIG | op::OP_CHECKSIGVERIFY => {
                        if stack.len() < 2 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let vch_pubkey = stack.pop().unwrap();
                        let vch_sig = stack.pop().unwrap();

                        let mut f_success = true;
                        let script_code = &script[pbegincodehash..];

                        eval_checksig(
                            &vch_sig,
                            &vch_pubkey,
                            script_code,
                            exec_data,
                            script_flags,
                            checker,
                            sig_version,
                            &mut f_success,
                        )?;

                        stack.push(if f_success {
                            stack::STACK_TRUE.to_vec()
                        } else {
                            stack::STACK_FALSE.to_vec()
                        });

                        if opcode == op::OP_CHECKSIGVERIFY {
                            if f_success {
                                stack.pop();
                            } else {
                                return Err(ScriptError::CheckSigVerify);
                            }
                        }
                    }

                    op::OP_CHECKSIGADD => {
                        // Only available in tapscript
                        if sig_version == SigVersion::Base || sig_version == SigVersion::WitnessV0
                        {
                            return Err(ScriptError::BadOpcode);
                        }
                        if stack.len() < 3 {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let pubkey = stack.pop().unwrap();
                        let num = ScriptNum::from_bytes_default(
                            stack.last().unwrap(),
                            require_minimal,
                        )
                        .map_err(|_| ScriptError::ScriptNum)?;
                        stack.pop();
                        let sig = stack.pop().unwrap();

                        let mut success = true;
                        let script_code = &script[pbegincodehash..];
                        eval_checksig(
                            &sig,
                            &pubkey,
                            script_code,
                            exec_data,
                            script_flags,
                            checker,
                            sig_version,
                            &mut success,
                        )?;
                        let result = num + ScriptNum::new(if success { 1 } else { 0 });
                        stack.push(result.serialize());
                    }

                    op::OP_CHECKMULTISIG | op::OP_CHECKMULTISIGVERIFY => {
                        if sig_version == SigVersion::Tapscript {
                            return Err(ScriptError::TapscriptCheckMultiSig);
                        }

                        let mut i: usize = 1;
                        if stack.len() < i {
                            return Err(ScriptError::InvalidStackOperation);
                        }

                        let n_keys_count = ScriptNum::from_bytes_default(
                            &stack[stack.len() - i],
                            require_minimal,
                        )
                        .map_err(|_| ScriptError::ScriptNum)?
                        .getint();

                        if n_keys_count < 0 || n_keys_count as usize > MAX_PUBKEYS_PER_MULTISIG {
                            return Err(ScriptError::PubkeyCount);
                        }
                        n_op_count += n_keys_count as usize;
                        if n_op_count > MAX_OPS_PER_SCRIPT {
                            return Err(ScriptError::OpCount);
                        }

                        let mut ikey = {
                            i += 1;
                            i
                        };
                        let mut ikey2 = n_keys_count as usize + 2;
                        i += n_keys_count as usize;

                        if stack.len() < i {
                            return Err(ScriptError::InvalidStackOperation);
                        }

                        let mut n_sigs_count = ScriptNum::from_bytes_default(
                            &stack[stack.len() - i],
                            require_minimal,
                        )
                        .map_err(|_| ScriptError::ScriptNum)?
                        .getint();

                        if n_sigs_count < 0 || n_sigs_count > n_keys_count {
                            return Err(ScriptError::SigCount);
                        }

                        let mut isig = {
                            i += 1;
                            i
                        };
                        i += n_sigs_count as usize;

                        if stack.len() < i {
                            return Err(ScriptError::InvalidStackOperation);
                        }

                        // Build scriptCode from pbegincodehash
                        let mut script_code = script[pbegincodehash..].to_vec();

                        // FindAndDelete signatures from scriptCode in pre-segwit
                        if sig_version == SigVersion::Base {
                            for k in 0..n_sigs_count as usize {
                                let sig_data = &stack[stack.len() - isig - k];
                                // Build the push pattern: length-prefix + data
                                let mut pattern = Vec::new();
                                let sig_len = sig_data.len();
                                if sig_len <= 75 {
                                    pattern.push(sig_len as u8);
                                } else if sig_len <= 255 {
                                    pattern.push(0x4c);
                                    pattern.push(sig_len as u8);
                                } else if sig_len <= 65535 {
                                    pattern.push(0x4d);
                                    pattern.push(sig_len as u8);
                                    pattern.push((sig_len >> 8) as u8);
                                }
                                pattern.extend_from_slice(sig_data);

                                let (new_code, found) =
                                    encoding::find_and_delete(&script_code, &pattern);
                                if found > 0
                                    && flags::has_flag(
                                        script_flags,
                                        flags::VERIFY_CONST_SCRIPTCODE,
                                    )
                                {
                                    return Err(ScriptError::SigFindAndDelete);
                                }
                                script_code = new_code;
                            }
                        }

                        let mut f_success = true;
                        let mut n_keys_remaining = n_keys_count;
                        while f_success && n_sigs_count > 0 {
                            let vch_sig = stack[stack.len() - isig].clone();
                            let vch_pubkey = stack[stack.len() - ikey].clone();

                            encoding::check_signature_encoding(&vch_sig, script_flags)?;
                            encoding::check_pubkey_encoding(
                                &vch_pubkey,
                                script_flags,
                                sig_version,
                            )?;

                            let f_ok = checker.check_ecdsa_signature(
                                &vch_sig,
                                &vch_pubkey,
                                &script_code,
                                sig_version,
                            );

                            if f_ok {
                                isig += 1;
                                n_sigs_count -= 1;
                            }
                            ikey += 1;
                            n_keys_remaining -= 1;

                            if n_sigs_count > n_keys_remaining {
                                f_success = false;
                            }
                        }

                        // Clean up stack
                        while i > 1 {
                            i -= 1;
                            if !f_success
                                && flags::has_flag(script_flags, flags::VERIFY_NULLFAIL)
                                && ikey2 == 0
                                && !stack[stack.len() - 1].is_empty()
                            {
                                return Err(ScriptError::SigNullFail);
                            }
                            ikey2 = ikey2.saturating_sub(1);
                            stack.pop();
                        }

                        // Bug: CHECKMULTISIG consumes one extra argument
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        if flags::has_flag(script_flags, flags::VERIFY_NULLDUMMY)
                            && !stack.last().unwrap().is_empty()
                        {
                            return Err(ScriptError::SigNullDummy);
                        }
                        stack.pop();

                        stack.push(if f_success {
                            stack::STACK_TRUE.to_vec()
                        } else {
                            stack::STACK_FALSE.to_vec()
                        });

                        if opcode == op::OP_CHECKMULTISIGVERIFY {
                            if f_success {
                                stack.pop();
                            } else {
                                return Err(ScriptError::CheckMultiSigVerify);
                            }
                        }
                    }

                    _ => {
                        return Err(ScriptError::BadOpcode);
                    }
                }
            }

            // Size limits
            if stack.len() + altstack.len() > MAX_STACK_SIZE {
                return Err(ScriptError::StackSize);
            }

            opcode_pos += 1;
        }

        Ok(())
    })();

    result?;

    if !vf_exec.is_empty() {
        return Err(ScriptError::UnbalancedConditional);
    }

    Ok(())
}

/// Helper for OP_CHECKSIG / OP_CHECKSIGVERIFY / OP_CHECKSIGADD.
///
/// Routes to pre-tapscript or tapscript signature checking.
#[allow(clippy::too_many_arguments)]
fn eval_checksig(
    sig: &[u8],
    pubkey: &[u8],
    script_code: &[u8],
    exec_data: &mut ExecData,
    script_flags: u32,
    checker: &dyn SignatureChecker,
    sig_version: SigVersion,
    success: &mut bool,
) -> Result<(), ScriptError> {
    match sig_version {
        SigVersion::Base | SigVersion::WitnessV0 => {
            eval_checksig_pre_tapscript(
                sig,
                pubkey,
                script_code,
                script_flags,
                checker,
                sig_version,
                success,
            )
        }
        SigVersion::Tapscript => {
            eval_checksig_tapscript(sig, pubkey, exec_data, script_flags, checker, success)
        }
        SigVersion::Taproot => {
            panic!("Key path spending in Taproot has no script");
        }
    }
}

/// Pre-tapscript CHECKSIG evaluation (Base and WitnessV0).
fn eval_checksig_pre_tapscript(
    sig: &[u8],
    pubkey: &[u8],
    script_code: &[u8],
    script_flags: u32,
    checker: &dyn SignatureChecker,
    sig_version: SigVersion,
    success: &mut bool,
) -> Result<(), ScriptError> {
    // Build scriptCode, applying FindAndDelete for pre-segwit
    let mut code = script_code.to_vec();
    if sig_version == SigVersion::Base {
        // Build push pattern: length-prefix + sig
        let mut pattern = Vec::new();
        if sig.len() <= 75 {
            pattern.push(sig.len() as u8);
        } else if sig.len() <= 255 {
            pattern.push(0x4c);
            pattern.push(sig.len() as u8);
        } else if sig.len() <= 65535 {
            pattern.push(0x4d);
            pattern.push(sig.len() as u8);
            pattern.push((sig.len() >> 8) as u8);
        }
        pattern.extend_from_slice(sig);

        let (new_code, found) = encoding::find_and_delete(&code, &pattern);
        if found > 0 && flags::has_flag(script_flags, flags::VERIFY_CONST_SCRIPTCODE) {
            return Err(ScriptError::SigFindAndDelete);
        }
        code = new_code;
    }

    encoding::check_signature_encoding(sig, script_flags)?;
    encoding::check_pubkey_encoding(pubkey, script_flags, sig_version)?;

    *success = checker.check_ecdsa_signature(sig, pubkey, &code, sig_version);

    if !*success && flags::has_flag(script_flags, flags::VERIFY_NULLFAIL) && !sig.is_empty() {
        return Err(ScriptError::SigNullFail);
    }

    Ok(())
}

/// Tapscript CHECKSIG evaluation.
fn eval_checksig_tapscript(
    sig: &[u8],
    pubkey: &[u8],
    exec_data: &mut ExecData,
    script_flags: u32,
    checker: &dyn SignatureChecker,
    success: &mut bool,
) -> Result<(), ScriptError> {
    *success = !sig.is_empty();

    if *success {
        // Signature weight budget
        assert!(exec_data.validation_weight_left_init);
        exec_data.validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
        if exec_data.validation_weight_left < 0 {
            return Err(ScriptError::TapscriptValidationWeight);
        }
    }

    if pubkey.is_empty() {
        return Err(ScriptError::TapscriptEmptyPubkey);
    } else if pubkey.len() == 32 {
        if *success {
            let ok = checker
                .check_schnorr_signature(sig, pubkey, SigVersion::Tapscript, exec_data)?;
            if !ok {
                return Err(ScriptError::SchnorrSig);
            }
        }
    } else {
        // Unknown pubkey version — upgradable
        if flags::has_flag(script_flags, flags::VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE) {
            return Err(ScriptError::DiscourageUpgradablePubkeyType);
        }
    }

    Ok(())
}

/// Convenience wrapper: evaluate script with a fresh ExecData.
pub fn eval_script_simple(
    stack: &mut Vec<StackItem>,
    script: &[u8],
    script_flags: u32,
    checker: &dyn SignatureChecker,
    sig_version: SigVersion,
) -> Result<(), ScriptError> {
    let mut exec_data = ExecData::new();
    eval_script(stack, script, script_flags, checker, sig_version, &mut exec_data)
}
