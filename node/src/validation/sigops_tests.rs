//! Bitcoin Core's sigop-counting test vectors, and the cases where the
//! opcode before a multisig opcode decides its count.
//!
//! The ports keep Core's test and variable names. Keys and signatures are
//! placeholders of the right length: no count reads their bytes.

use super::*;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, Txid};

const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_11: u8 = 0x5b;
const OP_15: u8 = 0x5f;
const OP_IF: u8 = 0x63;
const OP_ENDIF: u8 = 0x68;
const OP_DROP: u8 = 0x75;
const OP_2DUP: u8 = 0x6e;
const OP_NOT: u8 = 0x91;
const OP_NOP: u8 = 0x61;
const OP_RESERVED: u8 = 0x50;
const OP_1NEGATE: u8 = 0x4f;

/// A script built the way Core's `CScript` `operator<<` builds one.
#[derive(Clone, Default)]
struct S(Vec<u8>);

impl S {
    fn new() -> S {
        S::default()
    }

    /// `<< opcode`.
    fn op(mut self, opcode: u8) -> S {
        self.0.push(opcode);
        self
    }

    /// `<< std::vector<unsigned char>`: a direct push below 76 bytes, then
    /// `OP_PUSHDATA1`/`2`/`4`. Never an `OP_N`, even for one small byte.
    fn push(mut self, data: &[u8]) -> S {
        let n = data.len();
        if n < usize::from(OP_PUSHDATA1) {
            self.0.push(n as u8);
        } else if n <= 0xff {
            self.0.extend([OP_PUSHDATA1, n as u8]);
        } else if n <= 0xffff {
            self.0.push(OP_PUSHDATA2);
            self.0.extend((n as u16).to_le_bytes());
        } else {
            self.0.push(OP_PUSHDATA4);
            self.0.extend((n as u32).to_le_bytes());
        }
        self.0.extend_from_slice(data);
        self
    }

    fn script(&self) -> ScriptBuf {
        ScriptBuf::from_bytes(self.0.clone())
    }
}

fn script(bytes: &[u8]) -> ScriptBuf {
    ScriptBuf::from_bytes(bytes.to_vec())
}

fn accurate(bytes: &[u8]) -> u64 {
    script_sigop_count(&script(bytes), true)
}

fn inaccurate(bytes: &[u8]) -> u64 {
    script_sigop_count(&script(bytes), false)
}

/// A compressed public key's worth of bytes.
fn pubkey(tag: u8) -> [u8; 33] {
    let mut k = [tag; 33];
    k[0] = 0x02;
    k
}

/// A DER signature's worth of bytes.
const SIG: [u8; 72] = [0x30; 72];

/// Core's `GetScriptForDestination(ScriptHash(s))`.
fn p2sh_of(s: &ScriptBuf) -> ScriptBuf {
    ScriptBuf::new_p2sh(&s.script_hash())
}

/// Core's `GetScriptForMultisig(n, keys)`.
fn multisig(n: u8, keys: &[[u8; 33]]) -> S {
    let mut s = S::new().op(OP_1 + n - 1);
    for k in keys {
        s = s.push(k);
    }
    s.op(OP_1 + keys.len() as u8 - 1).op(OP_CHECKMULTISIG)
}

fn txid(tag: u8) -> Txid {
    Txid::from_byte_array([tag; 32])
}

fn input(prevout: OutPoint, script_sig: ScriptBuf, witness: Witness) -> TxIn {
    TxIn { previous_output: prevout, script_sig, sequence: Sequence::MAX, witness }
}

fn tx(input: Vec<TxIn>, output: Vec<TxOut>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(1),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input,
        output,
    }
}

fn out(script_pubkey: ScriptBuf) -> TxOut {
    TxOut { value: Amount::from_sat(1), script_pubkey }
}

/// Core: src/test/sigopcount_tests.cpp, `GetSigOpCount`.
#[test]
fn core_get_sig_op_count() {
    let s1 = S::new();
    assert_eq!(script_sigop_count(&s1.script(), false), 0);
    assert_eq!(script_sigop_count(&s1.script(), true), 0);

    let dummy = [0u8; 20];
    let s1 = s1.op(OP_1).push(&dummy).push(&dummy).op(OP_2).op(OP_CHECKMULTISIG);
    assert_eq!(script_sigop_count(&s1.script(), true), 2);
    let s1 = s1.op(OP_IF).op(OP_CHECKSIG).op(OP_ENDIF);
    assert_eq!(script_sigop_count(&s1.script(), true), 3);
    assert_eq!(script_sigop_count(&s1.script(), false), 21);

    let p2sh = p2sh_of(&s1.script());
    let script_sig = S::new().op(OP_0).push(&s1.0).script();
    assert_eq!(p2sh_sigop_count(&p2sh, &script_sig), 3);

    let keys = [pubkey(1), pubkey(2), pubkey(3)];
    let s2 = multisig(1, &keys);
    assert_eq!(script_sigop_count(&s2.script(), true), 3);
    assert_eq!(script_sigop_count(&s2.script(), false), 20);

    let p2sh = p2sh_of(&s2.script());
    assert_eq!(script_sigop_count(&p2sh, true), 0);
    assert_eq!(script_sigop_count(&p2sh, false), 0);
    let script_sig2 = S::new().op(OP_1).push(&dummy).push(&dummy).push(&s2.0).script();
    assert_eq!(p2sh_sigop_count(&p2sh, &script_sig2), 3);
}

/// Core reads the opcode immediately before a multisig opcode
/// (`lastOpcode`, set after every opcode). Only `OP_1`..`OP_16` there gives
/// an accurate count below 20.
#[test]
fn a_multisig_count_reads_the_opcode_right_before_it() {
    // OP_1 OP_CHECKSIG OP_CHECKMULTISIG: 1 + 20. rust-bitcoin 0.32 says 2.
    assert_eq!(accurate(&[0x51, 0xac, 0xae]), 21);
    assert_eq!(inaccurate(&[0x51, 0xac, 0xae]), 21);
    // OP_1 OP_CHECKMULTISIG OP_CHECKMULTISIG: 1 + 20. rust-bitcoin 0.32 says 2.
    assert_eq!(accurate(&[0x51, 0xae, 0xae]), 21);
    assert_eq!(inaccurate(&[0x51, 0xae, 0xae]), 40);
    // The VERIFY forms are the same opcodes to the count.
    assert_eq!(accurate(&[0x51, 0xad, 0xaf]), 21);
    assert_eq!(accurate(&[0x51, 0xaf, 0xaf]), 21);
    assert_eq!(accurate(&[0x52, 0xae]), 2);
    assert_eq!(accurate(&[0x60, 0xaf]), 16);
    // OP_1NEGATE and OP_0 are not OP_1..OP_16.
    assert_eq!(accurate(&[OP_1NEGATE, 0xae]), 20);
    assert_eq!(accurate(&[OP_0, 0xae]), 20);
    // Neither is a push of the same byte, nor a NOP in between.
    assert_eq!(accurate(&[0x01, 0x01, 0xae]), 20);
    assert_eq!(accurate(&[0x51, OP_NOP, 0xae]), 20);
    assert_eq!(accurate(&[0x51, 0x01, 0x01, 0xae]), 20);

    // 198 multisigs after one OP_1, in a branch that never runs: 1 + 197 × 20.
    let mut heavy = vec![OP_0, OP_IF, 0x51];
    heavy.extend([0xae; 198]);
    heavy.extend([OP_ENDIF, 0x51]);
    assert_eq!(accurate(&heavy), 3_941);
}

/// Core's `GetScriptOp` fails on a push that runs past the end, and the
/// count keeps what it had (`if (!GetOp(pc, opcode)) break;`).
#[test]
fn a_count_stops_where_the_script_stops_parsing() {
    assert_eq!(accurate(&[0xac, OP_PUSHDATA1]), 1);
    assert_eq!(accurate(&[0xac, 0x03, 0x00, 0xac]), 1);
    assert_eq!(accurate(&[0xac, OP_PUSHDATA2, 0x01]), 1);
    assert_eq!(accurate(&[0xac, OP_PUSHDATA4, 0xff, 0xff, 0xff, 0xff, 0xac]), 1);
    // A push that fits, including a zero-length PUSHDATA, is skipped whole.
    assert_eq!(accurate(&[OP_PUSHDATA1, 0x00, 0xac]), 1);
    assert_eq!(accurate(&[OP_PUSHDATA2, 0x01, 0x00, 0xae, 0xac]), 1);
    assert_eq!(accurate(&[OP_PUSHDATA4, 0x02, 0, 0, 0, 0xae, 0xae, 0xac]), 1);
    assert_eq!(accurate(&[0x02, 0xac, 0xac]), 0);
}

/// Core's `GetSigOpCount(scriptSig)` counts the data of the scriptSig's last
/// opcode, and only when every opcode parses and is `OP_16` or below.
#[test]
fn p2sh_counts_the_last_push_of_a_push_only_script_sig() {
    let redeem = script(&[0x51, 0xac, 0xae]);
    let p2sh = p2sh_of(&redeem);
    assert_eq!(p2sh_sigop_count(&p2sh, &S::new().push(redeem.as_bytes()).script()), 21);
    // OP_RESERVED and OP_1NEGATE are at or below OP_16.
    let sig = S::new().op(OP_RESERVED).op(OP_1NEGATE).push(redeem.as_bytes()).script();
    assert_eq!(p2sh_sigop_count(&p2sh, &sig), 21);
    // Any push form.
    let mut long_redeem = redeem.as_bytes().to_vec();
    long_redeem.extend([OP_NOP; 300]);
    assert_eq!(p2sh_sigop_count(&p2sh, &S::new().push(&long_redeem).script()), 21);
    // A NOP anywhere: 0.
    let sig = S::new().op(OP_NOP).push(redeem.as_bytes()).script();
    assert_eq!(p2sh_sigop_count(&p2sh, &sig), 0);
    // Ending on a number opcode pushes no data: 0.
    let sig = S::new().push(redeem.as_bytes()).op(OP_1).script();
    assert_eq!(p2sh_sigop_count(&p2sh, &sig), 0);
    // Nothing, or a scriptSig that does not parse: 0.
    assert_eq!(p2sh_sigop_count(&p2sh, &ScriptBuf::new()), 0);
    let mut truncated = S::new().push(redeem.as_bytes()).0;
    truncated.push(0x05);
    assert_eq!(p2sh_sigop_count(&p2sh, &script(&truncated)), 0);
    // A push that claims more bytes than follow is not a redeem script, even
    // when the bytes that do follow would count: 0, not 21.
    assert_eq!(p2sh_sigop_count(&p2sh, &script(&[0x05, 0x51, 0xac, 0xae])), 0);
    // A scriptPubKey that is not P2SH is counted itself, accurately.
    assert_eq!(p2sh_sigop_count(&redeem, &ScriptBuf::new()), 21);
}

/// Core: src/test/script_p2sh_tests.cpp, `AreInputsStandard`, the
/// `GetP2SHSigOpCount` checks.
#[test]
fn core_are_inputs_standard_p2sh_sig_op_counts() {
    let key: Vec<[u8; 33]> = (1..=6).map(pubkey).collect();
    let pay1 = S::new().push(&key[0]).op(OP_CHECKSIG);
    let pay1of3 = multisig(1, &key[0..3]);
    let one_and_two = S::new()
        .op(OP_1)
        .push(&key[0])
        .push(&key[1])
        .push(&key[2])
        .op(OP_3)
        .op(OP_CHECKMULTISIGVERIFY)
        .op(OP_2)
        .push(&key[3])
        .push(&key[4])
        .push(&key[5])
        .op(OP_3)
        .op(OP_CHECKMULTISIG);
    let mut fifteen_sigops = S::new().op(OP_1);
    for i in 0..15 {
        fifteen_sigops = fifteen_sigops.push(&key[i % 3]);
    }
    let fifteen_sigops = fifteen_sigops.op(OP_15).op(OP_CHECKMULTISIG);
    let sixteen_sigops = S::new().op(OP_16).op(OP_CHECKMULTISIG);
    let twenty_sigops = S::new().op(OP_CHECKMULTISIG);

    let tx_from: Vec<TxOut> = vec![
        out(p2sh_of(&pay1.script())),
        out(pay1.script()),
        out(pay1of3.script()),
        out(p2sh_of(&one_and_two.script())),
        out(p2sh_of(&fifteen_sigops.script())),
        out(p2sh_of(&sixteen_sigops.script())),
        out(p2sh_of(&twenty_sigops.script())),
    ];
    let from = txid(0xf0);
    let spend = |vout: u32, script_sig: ScriptBuf| input(OutPoint { txid: from, vout }, script_sig, Witness::new());

    // What SignSignature produces for vin[0..3], then Core's dummy
    // scriptSigs for vin[3] and vin[4].
    let tx_to = tx(
        vec![
            spend(0, S::new().push(&SIG).push(&pay1.0).script()),
            spend(1, S::new().push(&SIG).script()),
            spend(2, S::new().op(OP_0).push(&SIG).script()),
            spend(3, S::new().op(OP_11).op(OP_11).push(&one_and_two.0).script()),
            spend(4, S::new().push(&fifteen_sigops.0).script()),
        ],
        vec![out(ScriptBuf::new())],
    );
    // 22 P2SH sigops for all inputs (1 for vin[0], 6 for vin[3], 15 for vin[4]).
    assert_eq!(transaction_p2sh_sigop_count(&tx_to, &tx_from[0..5]), 22);

    let coinbase_tx = tx(vec![input(OutPoint::null(), ScriptBuf::new(), Witness::new())], vec![]);
    assert!(coinbase_tx.is_coinbase());
    assert_eq!(transaction_p2sh_sigop_count(&coinbase_tx, &[]), 0);

    let tx_to_non_std1 = tx(vec![spend(5, S::new().push(&sixteen_sigops.0).script())], vec![]);
    assert_eq!(transaction_p2sh_sigop_count(&tx_to_non_std1, &tx_from[5..6]), 16);

    let tx_to_non_std2 = tx(vec![spend(6, S::new().push(&twenty_sigops.0).script())], vec![]);
    assert_eq!(transaction_p2sh_sigop_count(&tx_to_non_std2, &tx_from[6..7]), 20);
}

/// Core: src/test/transaction_tests.cpp, `max_standard_legacy_sigops`, the
/// `GetP2SHSigOpCount` checks.
#[test]
fn core_max_standard_legacy_sigops_p2sh_counts() {
    let mut redeem = S::new().push(&[]).push(&pubkey(7));
    for _ in 0..14 {
        redeem = redeem.op(OP_2DUP).op(OP_CHECKSIG).op(OP_DROP);
    }
    let redeem = redeem.op(OP_CHECKSIG).op(OP_NOT);
    let p2sh = p2sh_of(&redeem.script());

    for (inputs, expected) in [(166u32, 2_490), (167, 2_505)] {
        let tx_max_sigops = tx(
            (0..inputs)
                .map(|i| input(OutPoint { txid: txid(0xf1), vout: i }, S::new().push(&redeem.0).script(), Witness::new()))
                .collect(),
            vec![],
        );
        let prevouts = vec![out(p2sh.clone()); inputs as usize];
        assert_eq!(transaction_p2sh_sigop_count(&tx_max_sigops, &prevouts), expected);
    }
}

/// Core: src/test/sigopcount_tests.cpp, `GetTxSigOpCost`.
#[test]
fn core_get_tx_sig_op_cost() {
    let flags = SigOpFlags::P2shWitness;
    let pk = pubkey(9);
    let creation = |script_pubkey: ScriptBuf| {
        tx(vec![input(OutPoint::null(), ScriptBuf::new(), Witness::new())], vec![out(script_pubkey)])
    };
    let spending = |creation_tx: &Transaction, script_sig: ScriptBuf, witness: Witness| {
        tx(
            vec![input(OutPoint { txid: creation_tx.compute_txid(), vout: 0 }, script_sig, witness)],
            vec![out(ScriptBuf::new())],
        )
    };
    let two_empty = || Witness::from_slice(&[&[][..], &[][..]]);
    let multisig_1_of_2 = S::new().op(OP_1).push(&pk).push(&pk).op(OP_2).op(OP_CHECKMULTISIGVERIFY);

    // Multisig script (legacy counting).
    {
        let script_pubkey = multisig_1_of_2.script();
        let script_sig = S::new().op(OP_0).op(OP_0).script();
        let creation_tx = creation(script_pubkey);
        let spending_tx = spending(&creation_tx, script_sig, Witness::new());
        let prevouts = creation_tx.output.clone();
        // Legacy counting only includes signature operations in scriptSigs
        // and scriptPubKeys of a transaction.
        assert_eq!(transaction_sigop_cost(&spending_tx, &prevouts, flags), 0);
        // creationTx contains two signature operations in its scriptPubKey,
        // but legacy counting is not accurate.
        assert_eq!(
            transaction_sigop_cost(&creation_tx, &[], flags),
            MAX_PUBKEYS_PER_MULTISIG * WITNESS_SCALE_FACTOR
        );
    }

    // Multisig nested in P2SH.
    {
        let redeem_script = multisig_1_of_2.clone();
        let creation_tx = creation(p2sh_of(&redeem_script.script()));
        let script_sig = S::new().op(OP_0).op(OP_0).push(&redeem_script.0).script();
        let spending_tx = spending(&creation_tx, script_sig, Witness::new());
        let prevouts = creation_tx.output.clone();
        assert_eq!(transaction_sigop_cost(&spending_tx, &prevouts, flags), 2 * WITNESS_SCALE_FACTOR);
        // P2SH sigops are not counted without SCRIPT_VERIFY_P2SH.
        assert_eq!(transaction_sigop_cost(&spending_tx, &prevouts, SigOpFlags::Legacy), 0);
    }

    // P2WPKH witness program.
    {
        let mut script_pubkey = S::new().op(OP_0).push(&[0x33; 20]).0;
        let creation_tx = creation(script(&script_pubkey));
        let spending_tx = spending(&creation_tx, ScriptBuf::new(), two_empty());
        let prevouts = creation_tx.output.clone();
        assert_eq!(transaction_sigop_cost(&spending_tx, &prevouts, flags), 1);
        // No signature operations if we don't verify the witness.
        assert_eq!(transaction_sigop_cost(&spending_tx, &prevouts, SigOpFlags::P2sh), 0);

        // The sig op cost for witness version != 0 is zero.
        assert_eq!(script_pubkey[0], 0x00);
        script_pubkey[0] = 0x51;
        let creation_tx = creation(script(&script_pubkey));
        let spending_tx = spending(&creation_tx, ScriptBuf::new(), two_empty());
        assert_eq!(transaction_sigop_cost(&spending_tx, &creation_tx.output, flags), 0);
        script_pubkey[0] = 0x00;
        let creation_tx = creation(script(&script_pubkey));
        let mut spending_tx = spending(&creation_tx, ScriptBuf::new(), two_empty());

        // The witness of a coinbase transaction is not taken into account.
        spending_tx.input[0].previous_output = OutPoint::null();
        assert_eq!(transaction_sigop_cost(&spending_tx, &creation_tx.output, flags), 0);
    }

    // P2WPKH nested in P2SH.
    {
        let program = S::new().op(OP_0).push(&[0x33; 20]);
        let creation_tx = creation(p2sh_of(&program.script()));
        let script_sig = S::new().push(&program.0).script();
        let spending_tx = spending(&creation_tx, script_sig, two_empty());
        assert_eq!(transaction_sigop_cost(&spending_tx, &creation_tx.output, flags), 1);
    }

    // P2WSH witness program.
    {
        let witness_script = multisig_1_of_2.script();
        let creation_tx = creation(ScriptBuf::new_p2wsh(&witness_script.wscript_hash()));
        let witness = Witness::from_slice(&[&[][..], &[][..], witness_script.as_bytes()]);
        let spending_tx = spending(&creation_tx, ScriptBuf::new(), witness);
        assert_eq!(transaction_sigop_cost(&spending_tx, &creation_tx.output, flags), 2);
        assert_eq!(transaction_sigop_cost(&spending_tx, &creation_tx.output, SigOpFlags::P2sh), 0);
    }

    // P2WSH nested in P2SH.
    {
        let witness_script = multisig_1_of_2.script();
        let redeem_script = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        let creation_tx = creation(p2sh_of(&redeem_script));
        let script_sig = S::new().push(redeem_script.as_bytes()).script();
        let witness = Witness::from_slice(&[&[][..], &[][..], witness_script.as_bytes()]);
        let spending_tx = spending(&creation_tx, script_sig, witness);
        assert_eq!(transaction_sigop_cost(&spending_tx, &creation_tx.output, flags), 2);
    }
}

/// Witness sigops follow Core's `IsWitnessProgram` and `WitnessSigOps`, and
/// the witness script is counted accurately.
#[test]
fn witness_sigops_follow_cores_program_rules() {
    let flags = SigOpFlags::P2shWitness;
    let ws = script(&[0x51, 0xac, 0xae]);
    let p2wsh = ScriptBuf::new_p2wsh(&ws.wscript_hash());
    let with_ws = Witness::from_slice(&[ws.as_bytes()]);
    // The witness script is the last item, counted accurately: 21.
    assert_eq!(witness_sigop_count(&ScriptBuf::new(), &p2wsh, &with_ws, flags), 21);
    // An empty witness has no script: 0.
    assert_eq!(witness_sigop_count(&ScriptBuf::new(), &p2wsh, &Witness::new(), flags), 0);
    // P2SH-wrapped, but the scriptSig is not push-only: 0.
    let wrapped = p2sh_of(&p2wsh);
    let sig = S::new().op(OP_NOP).push(p2wsh.as_bytes()).script();
    assert_eq!(witness_sigop_count(&sig, &wrapped, &with_ws, flags), 0);
    let sig = S::new().push(p2wsh.as_bytes()).script();
    assert_eq!(witness_sigop_count(&sig, &wrapped, &with_ws, flags), 21);
    // A scriptSig whose push runs one byte past the end is not push-only.
    let mut short = sig.as_bytes().to_vec();
    short[0] += 1;
    assert_eq!(witness_sigop_count(&script(&short), &wrapped, &with_ws, flags), 0);
    // A version 0 program of another length, a 41-byte program, and a
    // push that does not end the script are not counted.
    let v0_40 = S::new().op(OP_0).push(&[0x44; 40]).script();
    assert_eq!(witness_sigop_count(&ScriptBuf::new(), &v0_40, &with_ws, flags), 0);
    let v0_41 = S::new().op(OP_0).push(&[0x44; 41]).script();
    assert_eq!(witness_program(v0_41.as_bytes()), None);
    let mut trailing = S::new().op(OP_0).push(&[0x44; 20]).0;
    trailing.push(OP_NOP);
    assert_eq!(witness_sigop_count(&ScriptBuf::new(), &script(&trailing), &with_ws, flags), 0);
    // OP_1NEGATE is not a version opcode.
    let negate = S::new().op(OP_1NEGATE).push(&[0x44; 20]).script();
    assert_eq!(witness_program(negate.as_bytes()), None);
    // Version 16 is a program, of no sigops.
    let v16 = S::new().op(OP_16).push(&[0x44; 32]).script();
    assert_eq!(witness_program(v16.as_bytes()).map(|(v, p)| (v, p.len())), Some((16, 32)));
    assert_eq!(witness_sigop_count(&ScriptBuf::new(), &v16, &with_ws, flags), 0);
}

/// Four P2WSH inputs of 3,941 each cost 15,764, unscaled.
#[test]
fn four_heavy_p2wsh_inputs_cost_their_accurate_count() {
    let mut heavy = vec![OP_0, OP_IF, 0x51];
    heavy.extend([0xae; 198]);
    heavy.extend([OP_ENDIF, 0x51]);
    let ws = script(&heavy);
    let prevouts = vec![out(ScriptBuf::new_p2wsh(&ws.wscript_hash())); 4];
    let spend = tx(
        (0..4)
            .map(|i| input(OutPoint { txid: txid(0xf2), vout: i }, ScriptBuf::new(), Witness::from_slice(&[ws.as_bytes()])))
            .collect(),
        vec![out(ScriptBuf::new())],
    );
    assert_eq!(transaction_sigop_cost(&spend, &prevouts, SigOpFlags::P2shWitness), 4 * 3_941);
    // Without SCRIPT_VERIFY_WITNESS none of it counts.
    assert_eq!(transaction_sigop_cost(&spend, &prevouts, SigOpFlags::P2sh), 0);
}

/// Like Core's `assert(!coin.IsSpent())`, a missing prevout is a bug in the
/// caller, not a count of zero.
#[test]
#[should_panic(expected = "sigop counting needs the output each input spends")]
fn a_missing_prevout_is_refused() {
    let spend = tx(vec![input(OutPoint { txid: txid(0xf3), vout: 0 }, ScriptBuf::new(), Witness::new())], vec![]);
    transaction_sigop_cost(&spend, &[], SigOpFlags::P2shWitness);
}
