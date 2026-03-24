//! VerifyScript — the top-level script verification orchestrator.
//!
//! Chains scriptSig → scriptPubKey → P2SH → witness evaluation.

use crate::checker::{ExecData, SignatureChecker, SigVersion};
use crate::error::ScriptError;
use crate::eval::eval_script;
use crate::flags;
use crate::stack::{self, StackItem};
use crate::witness;

/// Check if a script is push-only (all opcodes are push operations).
fn is_push_only(script: &[u8]) -> bool {
    let mut pc = 0;
    while pc < script.len() {
        let opcode = script[pc];
        if opcode > 0x60 {
            // OP_16 = 0x60, anything above is a non-push opcode
            return false;
        }
        pc += 1;
        if opcode <= 75 {
            pc += opcode as usize;
        } else if opcode == 0x4c {
            if pc >= script.len() {
                return false;
            }
            let n = script[pc] as usize;
            pc += 1 + n;
        } else if opcode == 0x4d {
            if pc + 1 >= script.len() {
                return false;
            }
            let n = script[pc] as usize | ((script[pc + 1] as usize) << 8);
            pc += 2 + n;
        } else if opcode == 0x4e {
            if pc + 3 >= script.len() {
                return false;
            }
            let n = script[pc] as usize
                | ((script[pc + 1] as usize) << 8)
                | ((script[pc + 2] as usize) << 16)
                | ((script[pc + 3] as usize) << 24);
            pc += 4 + n;
        }
    }
    true
}

/// Check if a script is P2SH: OP_HASH160 <20 bytes> OP_EQUAL (exactly 23 bytes).
fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23
        && script[0] == 0xa9  // OP_HASH160
        && script[1] == 0x14  // Push 20 bytes
        && script[22] == 0x87 // OP_EQUAL
}

/// Check if a script is a witness program: OP_n <2-40 bytes>.
/// Returns (version, program) or None.
fn is_witness_program(script: &[u8]) -> Option<(u8, &[u8])> {
    if script.len() < 4 || script.len() > 42 {
        return None;
    }
    // First byte must be OP_0 (0x00) or OP_1..OP_16 (0x51..0x60)
    let version_opcode = script[0];
    let version = if version_opcode == 0x00 {
        0
    } else if (0x51..=0x60).contains(&version_opcode) {
        version_opcode - 0x50
    } else {
        return None;
    };
    // Second byte is the push length
    let program_len = script[1] as usize;
    if program_len < 2 || program_len > 40 {
        return None;
    }
    if script.len() != 2 + program_len {
        return None;
    }
    Some((version, &script[2..]))
}

/// Verify a complete Bitcoin script (scriptSig + scriptPubKey + optional witness).
///
/// This is the top-level entry point matching Bitcoin Core's `VerifyScript()`.
pub fn verify_script(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &[StackItem],
    script_flags: u32,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    let mut had_witness = false;

    // SIGPUSHONLY check
    if flags::has_flag(script_flags, flags::VERIFY_SIGPUSHONLY) && !is_push_only(script_sig) {
        return Err(ScriptError::SigPushOnly);
    }

    // Evaluate scriptSig
    let mut stack: Vec<StackItem> = Vec::new();
    let mut exec_data = ExecData::new();
    eval_script(
        &mut stack,
        script_sig,
        script_flags,
        checker,
        SigVersion::Base,
        &mut exec_data,
    )?;

    // Save stack copy for P2SH
    let stack_copy = if flags::has_flag(script_flags, flags::VERIFY_P2SH) {
        Some(stack.clone())
    } else {
        None
    };

    // Evaluate scriptPubKey
    eval_script(
        &mut stack,
        script_pubkey,
        script_flags,
        checker,
        SigVersion::Base,
        &mut exec_data,
    )?;

    // Check result
    if stack.is_empty() {
        return Err(ScriptError::EvalFalse);
    }
    if !stack::cast_to_bool(stack.last().unwrap()) {
        return Err(ScriptError::EvalFalse);
    }

    // Bare witness programs
    if flags::has_flag(script_flags, flags::VERIFY_WITNESS) {
        if let Some((wit_version, wit_program)) = is_witness_program(script_pubkey) {
            had_witness = true;
            if !script_sig.is_empty() {
                return Err(ScriptError::WitnessMalleated);
            }
            witness::verify_witness_program(
                witness,
                wit_version,
                wit_program,
                script_flags,
                checker,
                false,
            )?;
            // Bypass cleanstack
            stack.resize(1, Vec::new());
        }
    }

    // P2SH evaluation
    if flags::has_flag(script_flags, flags::VERIFY_P2SH) && is_p2sh(script_pubkey) {
        // scriptSig must be push-only for P2SH
        if !is_push_only(script_sig) {
            return Err(ScriptError::SigPushOnly);
        }

        // Restore stack from before scriptPubKey evaluation
        let mut stack = stack_copy.unwrap();
        assert!(!stack.is_empty());

        let redeem_script = stack.pop().unwrap();

        // Evaluate redeem script
        eval_script(
            &mut stack,
            &redeem_script,
            script_flags,
            checker,
            SigVersion::Base,
            &mut exec_data,
        )?;

        if stack.is_empty() {
            return Err(ScriptError::EvalFalse);
        }
        if !stack::cast_to_bool(stack.last().unwrap()) {
            return Err(ScriptError::EvalFalse);
        }

        // P2SH witness program
        if flags::has_flag(script_flags, flags::VERIFY_WITNESS) {
            if let Some((wit_version, wit_program)) = is_witness_program(&redeem_script) {
                had_witness = true;
                // scriptSig must be exactly a single push of the redeemScript
                let expected = build_single_push(&redeem_script);
                if script_sig != expected.as_slice() {
                    return Err(ScriptError::WitnessMalleatedP2sh);
                }
                witness::verify_witness_program(
                    witness,
                    wit_version,
                    wit_program,
                    script_flags,
                    checker,
                    true,
                )?;
                stack.resize(1, Vec::new());
            }
        }

        // CLEANSTACK after P2SH
        if flags::has_flag(script_flags, flags::VERIFY_CLEANSTACK) {
            if stack.len() != 1 {
                return Err(ScriptError::CleanStack);
            }
        }
    } else {
        // CLEANSTACK (non-P2SH path)
        if flags::has_flag(script_flags, flags::VERIFY_CLEANSTACK) {
            if stack.len() != 1 {
                return Err(ScriptError::CleanStack);
            }
        }
    }

    // Witness unexpected check
    if flags::has_flag(script_flags, flags::VERIFY_WITNESS) {
        if !had_witness && !witness.is_empty() {
            return Err(ScriptError::WitnessUnexpected);
        }
    }

    Ok(())
}

/// Build a scriptSig that is a single push of `data`.
fn build_single_push(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let len = data.len();
    if len <= 75 {
        result.push(len as u8);
    } else if len <= 255 {
        result.push(0x4c); // OP_PUSHDATA1
        result.push(len as u8);
    } else if len <= 65535 {
        result.push(0x4d); // OP_PUSHDATA2
        result.push(len as u8);
        result.push((len >> 8) as u8);
    } else {
        result.push(0x4e); // OP_PUSHDATA4
        result.push(len as u8);
        result.push((len >> 8) as u8);
        result.push((len >> 16) as u8);
        result.push((len >> 24) as u8);
    }
    result.extend_from_slice(data);
    result
}
