//! Core's standardness rules for what a transaction spends and how it spends
//! it (`src/policy/policy.cpp`): `ValidateInputsStandardness`, with BIP 54's
//! legacy sigop limit, and `IsWitnessStandard`. They keep spends of unknown
//! script types and future witness versions, P2SH redeem scripts with many
//! signature checks, and bloated witnesses out of the mempool, without
//! touching what a block may contain.

use bitcoin::{Script, Transaction, TxOut};

use crate::validation::sigops::{p2sh_sigop_count, script_sigop_count};

/// Core's `MAX_P2SH_SIGOPS`: signature checks a P2SH redeem script may hold.
pub const MAX_P2SH_SIGOPS: u64 = 15;
/// Core's `MAX_TX_LEGACY_SIGOPS` (BIP 54): non-witness signature checks
/// across a transaction's inputs, counted in the spent outputs too.
pub const MAX_TX_LEGACY_SIGOPS: u64 = 2_500;
/// Core's `MAX_STANDARD_TX_SIGOPS_COST`: a fifth of the block's sigop budget.
pub const MAX_STANDARD_TX_SIGOPS_COST: u64 = 16_000;
/// Core's `MAX_STANDARD_P2WSH_STACK_ITEMS`.
pub const MAX_STANDARD_P2WSH_STACK_ITEMS: usize = 100;
/// Core's `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE`.
pub const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE: usize = 80;
/// Core's `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE`.
pub const MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE: usize = 80;
/// Core's `MAX_STANDARD_P2WSH_SCRIPT_SIZE`.
pub const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 3_600;

/// BIP 341's annex prefix.
const ANNEX_TAG: u8 = 0x50;
/// BIP 341's leaf-version mask and BIP 342's tapscript leaf version.
const TAPROOT_LEAF_MASK: u8 = 0xfe;
const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;

/// What Core's `Solver` (`src/script/solver.cpp`) makes of a spent output,
/// as far as `ValidateInputsStandardness` cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Spent {
    /// Any of the types Core names other than the three below.
    Known,
    /// `SCRIPTHASH`.
    ScriptHash,
    /// `NONSTANDARD`.
    Nonstandard,
    /// `WITNESS_UNKNOWN`: a witness program of no version or size Core
    /// knows how to validate.
    WitnessUnknown,
}

/// Core's `Solver`, in its order.
fn solve(spk: &Script) -> Spent {
    if spk.is_p2sh() {
        return Spent::ScriptHash;
    }
    if is_pay_to_anchor(spk) {
        return Spent::Known;
    }
    if let Some(version) = spk.witness_version() {
        let program_len = spk.len() - 2;
        return match (version.to_num(), program_len) {
            (0, 20) | (0, 32) | (1, 32) => Spent::Known,
            (0, _) => Spent::Nonstandard,
            _ => Spent::WitnessUnknown,
        };
    }
    let b = spk.as_bytes();
    if b.first() == Some(&0x6a) && Script::from_bytes(&b[1..]).is_push_only() {
        return Spent::Known; // NULL_DATA
    }
    if is_p2pk(spk) || spk.is_p2pkh() || match_multisig(spk) {
        return Spent::Known;
    }
    Spent::Nonstandard
}

/// Core's `IsPayToAnchor`: `OP_1 <0x4e73>`.
fn is_pay_to_anchor(spk: &Script) -> bool {
    spk.as_bytes() == [0x51, 0x02, 0x4e, 0x73]
}

/// Core's `CPubKey::ValidSize`: the length the first byte implies.
fn valid_pubkey_size(key: &[u8]) -> bool {
    match key.first() {
        Some(0x02 | 0x03) => key.len() == 33,
        Some(0x04 | 0x06 | 0x07) => key.len() == 65,
        _ => false,
    }
}

/// Core's `MatchPayToPubkey`.
fn is_p2pk(spk: &Script) -> bool {
    let b = spk.as_bytes();
    matches!(b.len(), 35 | 67)
        && usize::from(b[0]) == b.len() - 2
        && b[b.len() - 1] == 0xac
        && valid_pubkey_size(&b[1..b.len() - 1])
}

/// One operation of a script, as Core's `CScript::GetOp` reads it: the
/// opcode, the data it pushes, and the offset after it. `None` past the end
/// or on a push that runs off it.
fn get_op(script: &[u8], pc: usize) -> Option<(u8, &[u8], usize)> {
    let &op = script.get(pc)?;
    let mut pc = pc + 1;
    let len = match op {
        0x01..=0x4b => usize::from(op),
        0x4c => {
            let n = usize::from(*script.get(pc)?);
            pc += 1;
            n
        }
        0x4d => {
            let n = usize::from(u16::from_le_bytes(script.get(pc..pc + 2)?.try_into().ok()?));
            pc += 2;
            n
        }
        0x4e => {
            let n = u32::from_le_bytes(script.get(pc..pc + 4)?.try_into().ok()?) as usize;
            pc += 4;
            n
        }
        _ => 0,
    };
    let data = script.get(pc..pc.checked_add(len)?)?;
    Some((op, data, pc + len))
}

/// Core's `CheckMinimalPush`: `data` pushed with the shortest opcode.
fn is_minimal_push(op: u8, data: &[u8]) -> bool {
    match data.len() {
        0 => op == 0x00,
        1 if (1..=16).contains(&data[0]) => false,
        1 if data[0] == 0x81 => false,
        n if n <= 75 => usize::from(op) == n,
        n if n <= 255 => op == 0x4c,
        n if n <= 65_535 => op == 0x4d,
        _ => true,
    }
}

/// Core's `GetScriptNumber`: `OP_1`..`OP_16`, or a minimally pushed,
/// minimally encoded number, in `min..=max`.
fn script_number(op: u8, data: &[u8], min: i64, max: i64) -> Option<i64> {
    let n = match op {
        0x51..=0x60 => i64::from(op - 0x50),
        0x01..=0x4e => {
            if !is_minimal_push(op, data) || data.len() > 4 {
                return None;
            }
            // `CScriptNum(data, fRequireMinimal = true)`.
            if let Some(&last) = data.last()
                && last & 0x7f == 0
                && (data.len() <= 1 || data[data.len() - 2] & 0x80 == 0)
            {
                return None;
            }
            let mut v: i64 = 0;
            for (i, &b) in data.iter().enumerate() {
                v |= i64::from(b) << (8 * i);
            }
            match data.last() {
                Some(&last) if last & 0x80 != 0 => -(v & !(0x80i64 << (8 * (data.len() - 1)))),
                _ => v,
            }
        }
        _ => return None,
    };
    (min..=max).contains(&n).then_some(n)
}

/// Core's `MAX_PUBKEYS_PER_MULTISIG`.
const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;

/// Core's `MatchMultisig`: a count of required signatures, then keys of
/// valid size, then the count of keys, then `OP_CHECKMULTISIG` and nothing
/// after it. Each count is `OP_n` or a minimal push (so up to 20 keys), and
/// any push form carries a key, as Core's `GetOp` reads them.
/// rust-bitcoin's `is_multisig` does not check the keys, and stops at 16.
fn match_multisig(spk: &Script) -> bool {
    let b = spk.as_bytes();
    if b.last() != Some(&0xae) {
        return false;
    }
    let Some((op, data, mut pc)) = get_op(b, 0) else { return false };
    let Some(required) = script_number(op, data, 1, MAX_PUBKEYS_PER_MULTISIG) else { return false };
    let mut keys = 0i64;
    let (op, data) = loop {
        let Some((op, data, next)) = get_op(b, pc) else { return false };
        pc = next;
        if !valid_pubkey_size(data) {
            break (op, data);
        }
        keys += 1;
    };
    script_number(op, data, required, MAX_PUBKEYS_PER_MULTISIG) == Some(keys) && pc + 1 == b.len()
}

/// The stack a scriptSig leaves, run with no flags and a checker that fails
/// every signature: Core's `EvalScript(stack, scriptSig, SCRIPT_VERIFY_NONE,
/// BaseSignatureChecker(), SigVersion::BASE)`, which both checks use to find
/// a P2SH redeem script without validating anything.
fn script_sig_stack(script_sig: &Script) -> Result<Vec<Vec<u8>>, consensus::error::ScriptError> {
    let mut stack = Vec::new();
    consensus::eval::eval_script_simple(
        &mut stack,
        script_sig.as_bytes(),
        consensus::flags::VERIFY_NONE,
        &consensus::checker::NoopChecker,
        consensus::checker::SigVersion::Base,
    )?;
    Ok(stack)
}

/// BIP 54's limit as Core's `CheckSigopsBIP54` applies it: the accurate
/// count of each input's scriptSig and of the output it spends (with the
/// redeem script, for P2SH), summed over the inputs.
fn within_legacy_sigop_limit(tx: &Transaction, prevouts: &[TxOut]) -> bool {
    let mut sigops = 0u64;
    for (input, prev) in tx.input.iter().zip(prevouts) {
        sigops += script_sigop_count(&input.script_sig, true);
        sigops += p2sh_sigop_count(&prev.script_pubkey, &input.script_sig);
        if sigops > MAX_TX_LEGACY_SIGOPS {
            return false;
        }
    }
    true
}

/// Core's `ValidateInputsStandardness`. `Err` carries Core's debug message
/// for the `bad-txns-nonstandard-inputs` rejection. `prevouts` are the
/// outputs `tx` spends, in input order.
pub fn validate_inputs_standardness(tx: &Transaction, prevouts: &[TxOut]) -> Result<(), String> {
    if tx.is_coinbase() {
        return Ok(());
    }
    if !within_legacy_sigop_limit(tx, prevouts) {
        return Err("non-witness sigops exceed bip54 limit".to_string());
    }
    for (i, (input, prev)) in tx.input.iter().zip(prevouts).enumerate() {
        match solve(&prev.script_pubkey) {
            Spent::Known => {}
            Spent::Nonstandard => return Err(format!("input {i} script unknown")),
            Spent::WitnessUnknown => return Err(format!("input {i} witness program is undefined")),
            Spent::ScriptHash => {
                let stack = script_sig_stack(&input.script_sig)
                    .map_err(|e| format!("p2sh scriptsig malformed (input {i}: {e})"))?;
                let Some(redeem) = stack.last() else {
                    return Err(format!("input {i} P2SH redeemscript missing"));
                };
                let sigops = script_sigop_count(Script::from_bytes(redeem), true);
                if sigops > MAX_P2SH_SIGOPS {
                    return Err(format!(
                        "p2sh redeemscript sigops exceed limit (input {i}: {sigops} > {MAX_P2SH_SIGOPS})"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Core's `IsWitnessStandard`: a witness only where the spent output (or its
/// P2SH redeem script) is a witness program, never on a pay-to-anchor spend,
/// P2WSH within its script, item-count and item-size limits, and a taproot
/// spend with no annex and tapscript items of at most 80 bytes.
pub fn is_witness_standard(tx: &Transaction, prevouts: &[TxOut]) -> bool {
    if tx.is_coinbase() {
        return true;
    }
    for (input, prev) in tx.input.iter().zip(prevouts) {
        if input.witness.is_empty() {
            continue;
        }
        // Witness stuffing.
        if is_pay_to_anchor(&prev.script_pubkey) {
            return false;
        }
        let mut program_script = prev.script_pubkey.clone();
        let mut p2sh = false;
        if prev.script_pubkey.is_p2sh() {
            let Ok(stack) = script_sig_stack(&input.script_sig) else { return false };
            let Some(redeem) = stack.last() else { return false };
            program_script = bitcoin::ScriptBuf::from_bytes(redeem.clone());
            p2sh = true;
        }
        let Some(version) = program_script.witness_version() else {
            return false;
        };
        let program_len = program_script.len() - 2;
        let witness: Vec<&[u8]> = input.witness.iter().collect();

        if version.to_num() == 0 && program_len == 32 {
            let (script, items) = witness.split_last().expect("not empty");
            if script.len() > MAX_STANDARD_P2WSH_SCRIPT_SIZE
                || items.len() > MAX_STANDARD_P2WSH_STACK_ITEMS
                || items.iter().any(|item| item.len() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
            {
                return false;
            }
        }

        if version.to_num() == 1 && program_len == 32 && !p2sh {
            let mut stack = &witness[..];
            if stack.len() >= 2 && stack.last().is_some_and(|a| a.first() == Some(&ANNEX_TAG)) {
                // No semantics are defined for the annex yet.
                return false;
            }
            if stack.len() >= 2 {
                let (control, rest) = stack.split_last().expect("two items");
                let (_script, items) = rest.split_last().expect("one item");
                stack = items;
                let Some(&leaf) = control.first() else { return false };
                if leaf & TAPROOT_LEAF_MASK == TAPROOT_LEAF_TAPSCRIPT
                    && stack.iter().any(|item| item.len() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE)
                {
                    return false;
                }
            } else if stack.is_empty() {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
#[path = "input_policy_tests.rs"]
mod tests;
