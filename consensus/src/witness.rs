//! Witness program verification: VerifyWitnessProgram, ExecuteWitnessScript,
//! and taproot commitment verification.

use sha2::{Digest, Sha256};

use crate::checker::{ExecData, SignatureChecker, SigVersion};
use crate::error::ScriptError;
use crate::eval::eval_script;
use crate::flags;
use crate::stack::{self, StackItem};

const WITNESS_V0_KEYHASH_SIZE: usize = 20;
const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;
const WITNESS_V1_TAPROOT_SIZE: usize = 32;
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
const MAX_STACK_SIZE: usize = 1000;
const TAPROOT_LEAF_MASK: u8 = 0xfe;
const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;
const ANNEX_TAG: u8 = 0x50;
const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// Execute a witness script with implicit cleanstack enforcement.
pub fn execute_witness_script(
    initial_stack: &[StackItem],
    exec_script: &[u8],
    script_flags: u32,
    sig_version: SigVersion,
    checker: &dyn SignatureChecker,
    exec_data: &mut ExecData,
) -> Result<(), ScriptError> {
    let mut stack: Vec<StackItem> = initial_stack.to_vec();

    if sig_version == SigVersion::Tapscript {
        // OP_SUCCESSx processing overrides everything
        if let Some(result) = scan_for_op_success(exec_script, script_flags) {
            return result;
        }
        // Tapscript enforces initial stack size limits
        if stack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
    }

    // Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
    for elem in &stack {
        if elem.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
    }

    // Run the script interpreter
    eval_script(
        &mut stack,
        exec_script,
        script_flags,
        checker,
        sig_version,
        exec_data,
    )?;

    // Scripts inside witness implicitly require cleanstack
    if stack.len() != 1 {
        return Err(ScriptError::CleanStack);
    }
    if !stack::cast_to_bool(&stack[0]) {
        return Err(ScriptError::EvalFalse);
    }

    Ok(())
}

/// Scan a tapscript for OP_SUCCESSx opcodes. If found, immediately succeed
/// (or fail if DISCOURAGE_OP_SUCCESS flag is set).
///
/// Matches Bitcoin Core's OP_SUCCESSx pre-scan in ExecuteWitnessScript.
/// Walks the script using GetOp semantics; if a GetOp fails (truncated push),
/// returns None (not OP_SUCCESSx — EvalScript will catch the parse error).
fn scan_for_op_success(script: &[u8], script_flags: u32) -> Option<Result<(), ScriptError>> {
    let mut pc = 0;
    while pc < script.len() {
        let opcode = script[pc];
        pc += 1;

        // Advance past push data
        if opcode <= 75 {
            pc += opcode as usize;
        } else if opcode == 0x4c {
            // OP_PUSHDATA1
            if pc >= script.len() {
                return None; // truncated — let EvalScript handle it
            }
            let n = script[pc] as usize;
            pc += 1 + n;
        } else if opcode == 0x4d {
            // OP_PUSHDATA2
            if pc + 1 >= script.len() {
                return None;
            }
            let n = script[pc] as usize | ((script[pc + 1] as usize) << 8);
            pc += 2 + n;
        } else if opcode == 0x4e {
            // OP_PUSHDATA4
            if pc + 3 >= script.len() {
                return None;
            }
            let n = script[pc] as usize
                | ((script[pc + 1] as usize) << 8)
                | ((script[pc + 2] as usize) << 16)
                | ((script[pc + 3] as usize) << 24);
            pc += 4 + n;
        } else if is_op_success(opcode) {
            if flags::has_flag(script_flags, flags::VERIFY_DISCOURAGE_OP_SUCCESS) {
                return Some(Err(ScriptError::DiscourageOpSuccess));
            }
            return Some(Ok(()));
        }
        // else: non-push, non-SUCCESS opcode — just continue
    }
    None
}

/// Check if an opcode is an OP_SUCCESSx (BIP342).
fn is_op_success(opcode: u8) -> bool {
    matches!(
        opcode,
        0x50 | 0x62 | 0x7e | 0x7f | 0x89 | 0x8a | 0x8d | 0x8e
            | 0x95..=0x99 | 0xbb..=0xfe
    )
}

/// Verify a witness program (v0 P2WPKH, v0 P2WSH, v1 Taproot).
pub fn verify_witness_program(
    witness_stack: &[StackItem],
    wit_version: u8,
    program: &[u8],
    script_flags: u32,
    checker: &dyn SignatureChecker,
    is_p2sh: bool,
) -> Result<(), ScriptError> {
    let mut exec_data = ExecData::new();

    if wit_version == 0 {
        if program.len() == WITNESS_V0_SCRIPTHASH_SIZE {
            // P2WSH: 32-byte witness v0 program
            if witness_stack.is_empty() {
                return Err(ScriptError::WitnessProgramWitnessEmpty);
            }
            let script_bytes = &witness_stack[witness_stack.len() - 1];
            let stack = &witness_stack[..witness_stack.len() - 1];

            // SHA256(script) must match program
            let hash = Sha256::digest(script_bytes);
            if hash.as_slice() != program {
                return Err(ScriptError::WitnessProgramMismatch);
            }

            return execute_witness_script(
                stack,
                script_bytes,
                script_flags,
                SigVersion::WitnessV0,
                checker,
                &mut exec_data,
            );
        } else if program.len() == WITNESS_V0_KEYHASH_SIZE {
            // P2WPKH: 20-byte witness v0 program
            if witness_stack.len() != 2 {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            // Build implied P2PKH script: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
            let mut exec_script = Vec::with_capacity(25);
            exec_script.push(0x76); // OP_DUP
            exec_script.push(0xa9); // OP_HASH160
            exec_script.push(0x14); // Push 20 bytes
            exec_script.extend_from_slice(program);
            exec_script.push(0x88); // OP_EQUALVERIFY
            exec_script.push(0xac); // OP_CHECKSIG

            return execute_witness_script(
                witness_stack,
                &exec_script,
                script_flags,
                SigVersion::WitnessV0,
                checker,
                &mut exec_data,
            );
        } else {
            return Err(ScriptError::WitnessProgramWrongLength);
        }
    } else if wit_version == 1 && program.len() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh {
        // Taproot: 32-byte witness v1 program
        if !flags::has_flag(script_flags, flags::VERIFY_TAPROOT) {
            return Ok(());
        }
        if witness_stack.is_empty() {
            return Err(ScriptError::WitnessProgramWitnessEmpty);
        }

        let mut stack: Vec<StackItem> = witness_stack.to_vec();

        // Check for annex (last element starts with 0x50)
        if stack.len() >= 2 && !stack.last().unwrap().is_empty() && stack.last().unwrap()[0] == ANNEX_TAG {
            let annex = stack.pop().unwrap();
            exec_data.annex_hash = Sha256::digest(&annex).into();
            exec_data.annex_present = true;
        } else {
            exec_data.annex_present = false;
        }
        exec_data.annex_init = true;

        if stack.len() == 1 {
            // Key path spending
            let sig = &stack[0];
            match checker.check_schnorr_signature(sig, program, SigVersion::Taproot, &exec_data) {
                Ok(true) => return Ok(()),
                Ok(false) => return Err(ScriptError::SchnorrSig),
                Err(e) => return Err(e),
            }
        } else {
            // Script path spending
            let control = stack.pop().unwrap();
            let script = stack.pop().unwrap();

            if control.len() < TAPROOT_CONTROL_BASE_SIZE
                || control.len() > TAPROOT_CONTROL_MAX_SIZE
                || !(control.len() - TAPROOT_CONTROL_BASE_SIZE).is_multiple_of(TAPROOT_CONTROL_NODE_SIZE)
            {
                return Err(ScriptError::TaprootWrongControlSize);
            }

            let leaf_version = control[0] & TAPROOT_LEAF_MASK;
            exec_data.tapleaf_hash = compute_tapleaf_hash(leaf_version, &script);
            if !verify_taproot_commitment(&control, program, &exec_data.tapleaf_hash) {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            exec_data.tapleaf_hash_init = true;

            if leaf_version == TAPROOT_LEAF_TAPSCRIPT {
                // Tapscript (leaf version 0xc0)
                exec_data.validation_weight_left =
                    witness_serialized_size(witness_stack) as i64 + VALIDATION_WEIGHT_OFFSET;
                exec_data.validation_weight_left_init = true;
                return execute_witness_script(
                    &stack,
                    &script,
                    script_flags,
                    SigVersion::Tapscript,
                    checker,
                    &mut exec_data,
                );
            }
            if flags::has_flag(script_flags, flags::VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION) {
                return Err(ScriptError::DiscourageUpgradableTaprootVersion);
            }
            return Ok(());
        }
    } else {
        if flags::has_flag(script_flags, flags::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
            return Err(ScriptError::DiscourageUpgradableWitnessProgram);
        }
        // Other version/size/p2sh combinations return Ok for future softfork compatibility
        return Ok(());
    }
}

/// Compute BIP341 tapleaf hash: SHA256(SHA256("TapLeaf") || SHA256("TapLeaf") || leaf_version || compact_size(script.len()) || script)
fn compute_tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let tag_hash = sha256::Hash::hash(b"TapLeaf");
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(&[leaf_version]);
    // Compact size encoding of script length
    let compact = bitcoin::consensus::encode::serialize(&bitcoin::VarInt(script.len() as u64));
    engine.input(&compact);
    engine.input(script);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Compute BIP341 tapbranch hash.
fn compute_tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let tag_hash = sha256::Hash::hash(b"TapBranch");
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    if a < b {
        engine.input(a);
        engine.input(b);
    } else {
        engine.input(b);
        engine.input(a);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Compute the taproot merkle root from a control block and tapleaf hash.
fn compute_taproot_merkle_root(control: &[u8], tapleaf_hash: &[u8; 32]) -> [u8; 32] {
    let path_len = (control.len() - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE;
    let mut k = *tapleaf_hash;
    for i in 0..path_len {
        let offset = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * i;
        let mut node = [0u8; 32];
        node.copy_from_slice(&control[offset..offset + 32]);
        k = compute_tapbranch_hash(&k, &node);
    }
    k
}

/// Verify taproot commitment: output pubkey = internal_pubkey tweaked by merkle_root.
fn verify_taproot_commitment(control: &[u8], program: &[u8], tapleaf_hash: &[u8; 32]) -> bool {
    use bitcoin::secp256k1::{self, XOnlyPublicKey};

    let internal_key = match XOnlyPublicKey::from_slice(&control[1..33]) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let output_key = match XOnlyPublicKey::from_slice(program) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let merkle_root = compute_taproot_merkle_root(control, tapleaf_hash);
    let parity_bit = control[0] & 1;

    // Compute tweaked key: internal_key + H("TapTweak" || internal_key || merkle_root) * G
    let tweak = compute_tap_tweak_hash(&internal_key.serialize(), &merkle_root);
    let secp = secp256k1::Secp256k1::verification_only();
    let tweak_scalar = match secp256k1::Scalar::from_be_bytes(tweak) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let (tweaked, tweaked_parity) = match internal_key.add_tweak(&secp, &tweak_scalar) {
        Ok(pair) => pair,
        Err(_) => return false,
    };

    let expected_parity = if parity_bit == 1 {
        secp256k1::Parity::Odd
    } else {
        secp256k1::Parity::Even
    };

    tweaked == output_key && tweaked_parity == expected_parity
}

/// Compute TapTweak hash.
fn compute_tap_tweak_hash(internal_key: &[u8; 32], merkle_root: &[u8; 32]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let tag_hash = sha256::Hash::hash(b"TapTweak");
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(internal_key);
    engine.input(merkle_root);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Approximate serialized size of witness stack (for validation weight budget).
fn witness_serialized_size(stack: &[StackItem]) -> usize {
    let mut size = bitcoin::consensus::encode::VarInt(stack.len() as u64).size();
    for elem in stack {
        size += bitcoin::consensus::encode::VarInt(elem.len() as u64).size();
        size += elem.len();
    }
    size
}
