//! Signature-operation counting, ported from Bitcoin Core.
//!
//! Every sigop number satd acts on comes from here: the block limit in
//! `connect_block` and `check_block`, the cost the mempool records on each
//! entry (which the block template budgets by and getblocktemplate reports),
//! the policy engine's `tx.sigops_cost`, and the Stratum coinbase bound.
//!
//! | here | Bitcoin Core |
//! |---|---|
//! | [`script_sigop_count`] | `CScript::GetSigOpCount(bool fAccurate)`, src/script/script.cpp |
//! | [`p2sh_sigop_count`] | `CScript::GetSigOpCount(const CScript& scriptSig)`, src/script/script.cpp |
//! | [`witness_sigop_count`] | `CountWitnessSigOps`, src/script/interpreter.cpp |
//! | [`legacy_sigop_count`] | `GetLegacySigOpCount`, src/consensus/tx_verify.cpp |
//! | [`transaction_p2sh_sigop_count`] | `GetP2SHSigOpCount`, src/consensus/tx_verify.cpp |
//! | [`transaction_sigop_cost`] | `GetTransactionSigOpCost`, src/consensus/tx_verify.cpp |
//!
//! rust-bitcoin 0.32's `Script::count_sigops` is not used. In accurate mode
//! it keeps the last `OP_1`..`OP_16` it saw until a push or a
//! non-signature opcode replaces it, so an `OP_CHECKMULTISIG` that follows
//! `OP_CHECKSIG` or another `OP_CHECKMULTISIG` takes that earlier number.
//! Core sets `lastOpcode` after every opcode, and such an `OP_CHECKMULTISIG`
//! counts 20: `OP_1 OP_CHECKSIG OP_CHECKMULTISIG` is 21 in Core and 2 in
//! rust-bitcoin 0.32 (rust-bitcoin issue #6368). The parsing here is Core's
//! `GetScriptOp` too, so a truncated push ends a count exactly where Core's
//! does.

use bitcoin::opcodes::all::{
    OP_CHECKMULTISIG as CHECKMULTISIG, OP_CHECKMULTISIGVERIFY as CHECKMULTISIGVERIFY,
    OP_CHECKSIG as CHECKSIG, OP_CHECKSIGVERIFY as CHECKSIGVERIFY, OP_EQUAL as EQUAL,
    OP_HASH160 as HASH160, OP_INVALIDOPCODE as INVALIDOPCODE, OP_PUSHDATA1 as PUSHDATA1,
    OP_PUSHDATA2 as PUSHDATA2, OP_PUSHDATA4 as PUSHDATA4, OP_PUSHNUM_1 as PUSHNUM_1,
    OP_PUSHNUM_16 as PUSHNUM_16,
};
use bitcoin::{Script, Transaction, TxOut, Witness};

/// Core's `MAX_PUBKEYS_PER_MULTISIG` (src/script/script.h): what a
/// multisig opcode counts when the count is not accurate, or when the opcode
/// before it is not `OP_1`..`OP_16`.
pub const MAX_PUBKEYS_PER_MULTISIG: u64 = 20;

/// Core's `WITNESS_SCALE_FACTOR` (src/consensus/consensus.h): legacy and
/// P2SH sigops cost this much each, witness sigops one.
pub const WITNESS_SCALE_FACTOR: u64 = 4;

/// Core's `WITNESS_V0_KEYHASH_SIZE` and `WITNESS_V0_SCRIPTHASH_SIZE`
/// (src/script/interpreter.h).
const WITNESS_V0_KEYHASH_SIZE: usize = 20;
const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;

const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = PUSHDATA1.to_u8();
const OP_PUSHDATA2: u8 = PUSHDATA2.to_u8();
const OP_PUSHDATA4: u8 = PUSHDATA4.to_u8();
const OP_1: u8 = PUSHNUM_1.to_u8();
const OP_16: u8 = PUSHNUM_16.to_u8();
const OP_EQUAL: u8 = EQUAL.to_u8();
const OP_HASH160: u8 = HASH160.to_u8();
const OP_CHECKSIG: u8 = CHECKSIG.to_u8();
const OP_CHECKSIGVERIFY: u8 = CHECKSIGVERIFY.to_u8();
const OP_CHECKMULTISIG: u8 = CHECKMULTISIG.to_u8();
const OP_CHECKMULTISIGVERIFY: u8 = CHECKMULTISIGVERIFY.to_u8();
const OP_INVALIDOPCODE: u8 = INVALIDOPCODE.to_u8();

/// The script-verify flags Core's `GetTransactionSigOpCost` reads.
///
/// `SCRIPT_VERIFY_P2SH` adds the sigops of P2SH redeem scripts and
/// `SCRIPT_VERIFY_WITNESS` those of witness programs. Core's
/// `CountWitnessSigOps` asserts P2SH whenever WITNESS is set, so these are
/// the only three combinations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigOpFlags {
    /// Neither flag: legacy sigops only.
    Legacy,
    /// `SCRIPT_VERIFY_P2SH` alone.
    P2sh,
    /// `SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS`. Core's mempool counts
    /// with these (both are in its standard script flags), and Core's
    /// `GetBlockScriptFlags` sets both on every block but two exceptions.
    P2shWitness,
}

impl SigOpFlags {
    fn p2sh(self) -> bool {
        !matches!(self, SigOpFlags::Legacy)
    }

    fn witness(self) -> bool {
        matches!(self, SigOpFlags::P2shWitness)
    }
}

/// Core's `GetScriptOp`: the opcode at `*pc` and the data it pushes (empty
/// for an opcode that pushes nothing), with `*pc` moved past both. `None`
/// where Core returns false: past the end of the script, or a push whose
/// length bytes or data run past it.
fn get_op<'a>(script: &'a [u8], pc: &mut usize) -> Option<(u8, &'a [u8])> {
    let opcode = *script.get(*pc)?;
    *pc += 1;
    let size = match opcode {
        OP_PUSHDATA1 => {
            let n = *script.get(*pc)?;
            *pc += 1;
            usize::from(n)
        }
        OP_PUSHDATA2 => {
            let b = script.get(*pc..*pc + 2)?;
            *pc += 2;
            usize::from(u16::from_le_bytes([b[0], b[1]]))
        }
        OP_PUSHDATA4 => {
            let b = script.get(*pc..*pc + 4)?;
            *pc += 4;
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
        }
        n if n < OP_PUSHDATA1 => usize::from(n),
        _ => return Some((opcode, &[])),
    };
    let data = script.get(*pc..pc.checked_add(size)?)?;
    *pc += size;
    Some((opcode, data))
}

/// Core's `CScript::DecodeOP_N`, for `OP_0` and `OP_1`..`OP_16`.
fn decode_op_n(opcode: u8) -> u8 {
    debug_assert!(opcode == OP_0 || (OP_1..=OP_16).contains(&opcode));
    if opcode == OP_0 { 0 } else { opcode - (OP_1 - 1) }
}

/// Core's `CScript::IsPayToScriptHash`.
fn is_pay_to_script_hash(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == OP_HASH160 && script[1] == 0x14 && script[22] == OP_EQUAL
}

/// Core's `CScript::IsPushOnly`: every opcode parses and is `OP_16` or
/// below (which takes in `OP_1NEGATE` and `OP_RESERVED`).
fn is_push_only(script: &[u8]) -> bool {
    let mut pc = 0;
    while pc < script.len() {
        match get_op(script, &mut pc) {
            Some((opcode, _)) if opcode <= OP_16 => {}
            _ => return false,
        }
    }
    true
}

/// Core's `CScript::IsWitnessProgram`: a version opcode (`OP_0`,
/// `OP_1`..`OP_16`) and one direct push of 2 to 40 bytes that ends the
/// script. Returns the version and the program.
fn witness_program(script: &[u8]) -> Option<(u8, &[u8])> {
    if script.len() < 4 || script.len() > 42 {
        return None;
    }
    if script[0] != OP_0 && !(OP_1..=OP_16).contains(&script[0]) {
        return None;
    }
    if usize::from(script[1]) + 2 == script.len() {
        return Some((decode_op_n(script[0]), &script[2..]));
    }
    None
}

/// Core's `CScript::GetSigOpCount(bool fAccurate)`.
///
/// `OP_CHECKSIG` and `OP_CHECKSIGVERIFY` count 1. `OP_CHECKMULTISIG` and
/// `OP_CHECKMULTISIGVERIFY` count the number pushed by the opcode right
/// before them when `accurate` and that opcode is `OP_1`..`OP_16`, and 20
/// otherwise. Counting stops at the first opcode that does not parse.
pub fn script_sigop_count(script: &Script, accurate: bool) -> u64 {
    let script = script.as_bytes();
    let mut n = 0;
    let mut pc = 0;
    let mut last_opcode = OP_INVALIDOPCODE;
    while pc < script.len() {
        let Some((opcode, _)) = get_op(script, &mut pc) else {
            break;
        };
        if opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY {
            n += 1;
        } else if opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY {
            if accurate && (OP_1..=OP_16).contains(&last_opcode) {
                n += u64::from(decode_op_n(last_opcode));
            } else {
                n += MAX_PUBKEYS_PER_MULTISIG;
            }
        }
        last_opcode = opcode;
    }
    n
}

/// Core's `CScript::GetSigOpCount(const CScript& scriptSig)`: the sigops of
/// the redeem script `script_sig` reveals for the P2SH `script_pubkey`.
///
/// The redeem script is what the last opcode of `script_sig` pushes, counted
/// accurately. A `script_sig` with an opcode above `OP_16`, or one that does
/// not parse, counts 0, and so does one that ends in a number opcode, which
/// pushes no data. A `script_pubkey` that is not P2SH is counted accurately
/// itself.
pub fn p2sh_sigop_count(script_pubkey: &Script, script_sig: &Script) -> u64 {
    if !is_pay_to_script_hash(script_pubkey.as_bytes()) {
        return script_sigop_count(script_pubkey, true);
    }
    let sig = script_sig.as_bytes();
    let mut pc = 0;
    let mut data: &[u8] = &[];
    while pc < sig.len() {
        let Some((opcode, pushed)) = get_op(sig, &mut pc) else {
            return 0;
        };
        if opcode > OP_16 {
            return 0;
        }
        data = pushed;
    }
    script_sigop_count(Script::from_bytes(data), true)
}

/// Core's `WitnessSigOps`: a version 0 key-hash program costs 1, a version 0
/// script-hash program the accurate count of the witness script (the last
/// witness item), and anything else 0.
fn witness_program_sigops(version: u8, program: &[u8], witness: &Witness) -> u64 {
    if version == 0 {
        if program.len() == WITNESS_V0_KEYHASH_SIZE {
            return 1;
        }
        if program.len() == WITNESS_V0_SCRIPTHASH_SIZE
            && let Some(witness_script) = witness.last()
        {
            return script_sigop_count(Script::from_bytes(witness_script), true);
        }
    }
    0
}

/// Core's `CountWitnessSigOps`: the witness sigops of one input that spends
/// `script_pubkey`, either a witness program itself or P2SH wrapping one in a
/// push-only `script_sig`. 0 unless `flags` has `SCRIPT_VERIFY_WITNESS`.
pub fn witness_sigop_count(
    script_sig: &Script,
    script_pubkey: &Script,
    witness: &Witness,
    flags: SigOpFlags,
) -> u64 {
    if !flags.witness() {
        return 0;
    }
    if let Some((version, program)) = witness_program(script_pubkey.as_bytes()) {
        return witness_program_sigops(version, program, witness);
    }
    let sig = script_sig.as_bytes();
    if is_pay_to_script_hash(script_pubkey.as_bytes()) && is_push_only(sig) {
        let mut pc = 0;
        let mut data: &[u8] = &[];
        while pc < sig.len() {
            // `is_push_only` parsed every opcode already.
            let Some((_, pushed)) = get_op(sig, &mut pc) else {
                break;
            };
            data = pushed;
        }
        if let Some((version, program)) = witness_program(data) {
            return witness_program_sigops(version, program, witness);
        }
    }
    0
}

/// Core's `GetLegacySigOpCount`: the inaccurate count of every scriptSig and
/// every output script of `tx`.
pub fn legacy_sigop_count(tx: &Transaction) -> u64 {
    let inputs: u64 = tx.input.iter().map(|i| script_sigop_count(&i.script_sig, false)).sum();
    let outputs: u64 = tx.output.iter().map(|o| script_sigop_count(&o.script_pubkey, false)).sum();
    inputs + outputs
}

/// Panics unless `prevouts` holds one output per input, as Core's
/// `assert(!coin.IsSpent())` does for a coin that is not there.
fn assert_prevouts(tx: &Transaction, prevouts: &[TxOut]) {
    assert_eq!(
        prevouts.len(),
        tx.input.len(),
        "sigop counting needs the output each input spends, in input order"
    );
}

/// Core's `GetP2SHSigOpCount`: the redeem-script sigops of every input of
/// `tx` that spends a P2SH output. `prevouts` holds the output each input
/// spends, in input order. A coinbase counts 0 and its `prevouts` are not
/// read.
pub fn transaction_p2sh_sigop_count(tx: &Transaction, prevouts: &[TxOut]) -> u64 {
    if tx.is_coinbase() {
        return 0;
    }
    assert_prevouts(tx, prevouts);
    tx.input
        .iter()
        .zip(prevouts)
        .filter(|(_, prevout)| is_pay_to_script_hash(prevout.script_pubkey.as_bytes()))
        .map(|(input, prevout)| p2sh_sigop_count(&prevout.script_pubkey, &input.script_sig))
        .sum()
}

/// Core's `GetTransactionSigOpCost`: legacy sigops × 4, plus P2SH sigops × 4
/// under `SCRIPT_VERIFY_P2SH`, plus witness sigops under
/// `SCRIPT_VERIFY_WITNESS`. A coinbase counts its legacy sigops alone and its
/// `prevouts` are not read; any other transaction needs the output each
/// input spends, in input order.
pub fn transaction_sigop_cost(tx: &Transaction, prevouts: &[TxOut], flags: SigOpFlags) -> u64 {
    let mut cost = legacy_sigop_count(tx) * WITNESS_SCALE_FACTOR;
    if tx.is_coinbase() {
        return cost;
    }
    assert_prevouts(tx, prevouts);
    if flags.p2sh() {
        cost += transaction_p2sh_sigop_count(tx, prevouts) * WITNESS_SCALE_FACTOR;
    }
    for (input, prevout) in tx.input.iter().zip(prevouts) {
        cost += witness_sigop_count(&input.script_sig, &prevout.script_pubkey, &input.witness, flags);
    }
    cost
}

#[cfg(test)]
#[path = "sigops_tests.rs"]
mod tests;
