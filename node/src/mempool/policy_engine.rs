//! The bridge between the node and the [`satd_policy`] transaction-filtering
//! engine (design §7): policy-file loading and the per-transaction *view
//! builder* that feeds the evaluator at the single mempool eval point.
//!
//! The engine itself ([`satd_policy`]) is pure and does no transaction parsing
//! or consensus computation — it only reads borrowed [`TxView`]/[`Ctx`]
//! structures. This module is where the node fills those in: classifying script
//! types, extracting the executed leaf script, computing Core's dust verdict and
//! per-output OP_RETURN payload size, and snapshotting the node context. Each of
//! these is something the language deliberately *cannot* express (§4.3); the node
//! computes them once, during validation, and hands the evaluator cheap field
//! reads.
//!
//! The evaluator borrows slices out of the transaction and the resolved prevouts
//! (both of which outlive a single [`evaluate`] call) plus two small owned
//! buffers for the 32-byte txids; everything is constructed and consumed inside
//! one stack frame, so no heap-resident view outlives the evaluation.

use std::collections::HashMap;
use std::path::Path;

use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::{Network as BNetwork, OutPoint, Script, Transaction, TxIn, TxOut, Txid};

use satd_policy::{
    CompiledRuleset, Ctx, InputView, Network, OutputView, ScriptType, Source, TxView, Verdict,
    parse_ruleset,
};

use crate::mempool::policy;
use crate::mempool::pool::{MempoolConfig, QuarantineScope, TxSource};

/// Summary of a freshly-loaded ruleset — for the fail-loud startup log line
/// (§8) and, later, `getpolicyinfo` (PR 7).
#[derive(Debug, Clone)]
pub struct PolicyLoad {
    pub rules: usize,
    pub total_cost: u64,
    pub sha256: String,
    pub has_allow: bool,
    pub version: u32,
}

/// Read, parse, typecheck and cost-check a policy file. **Fail-loud**: any
/// failure is returned as a rendered, file-anchored diagnostic — the exact
/// message `policylint` prints. The caller decides what to do with it (abort at
/// startup; keep last-good on reload, PR 6).
pub fn load_policy_file(path: &Path) -> Result<(CompiledRuleset, PolicyLoad), String> {
    let src = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read policy file {}: {e}", path.display()))?;
    let ruleset = parse_ruleset(&src).map_err(|e| e.render(&src))?;
    let load = PolicyLoad {
        rules: ruleset.rules().len(),
        total_cost: ruleset.total_cost().total(),
        sha256: sha256_hex(src.as_bytes()),
        has_allow: ruleset.has_allow(),
        version: ruleset.version(),
    };
    Ok((ruleset, load))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let h = sha256::Hash::hash(bytes);
    hex::encode(h.to_byte_array())
}

/// The node-side context the evaluator's `node.*` family reads (§4.3). Snapshot
/// once per evaluation; the fee floors come from [`MempoolConfig`].
#[derive(Debug, Clone, Copy)]
pub struct PolicyCtx {
    pub network: BNetwork,
    pub height: u32,
    pub mempool_bytes: usize,
}

/// Map the node's [`TxSource`] onto the engine's [`Source`] (`tx.source`).
pub fn map_source(s: TxSource) -> Source {
    match s {
        TxSource::P2p => Source::P2p,
        TxSource::Rpc => Source::Rpc,
        TxSource::Electrum => Source::Electrum,
        TxSource::Esplora => Source::Esplora,
        TxSource::Mcp => Source::Mcp,
        TxSource::Reload => Source::Reload,
    }
}

/// Map the engine's verdict scope onto the mempool's [`QuarantineScope`].
pub fn map_scope(s: satd_policy::ScopeSet) -> QuarantineScope {
    QuarantineScope {
        relay: s.relay,
        template: s.template,
    }
}

fn map_network(n: BNetwork) -> Network {
    match n {
        BNetwork::Bitcoin => Network::Mainnet,
        BNetwork::Testnet => Network::Testnet,
        BNetwork::Testnet4 => Network::Testnet4,
        BNetwork::Signet => Network::Signet,
        BNetwork::Regtest => Network::Regtest,
    }
}

/// Pay-to-anchor (BIP-0xx ephemeral anchor): witness v1, 2-byte program
/// `0x4e73` ⇒ scriptPubKey `OP_1 OP_PUSHBYTES_2 4e73`. `rust-bitcoin` exposes
/// `is_p2a` only on `WitnessProgram`, so match the canonical bytes directly.
fn is_p2a(script: &Script) -> bool {
    script.as_bytes() == [0x51, 0x02, 0x4e, 0x73]
}

/// Classify a scriptPubKey into the engine's closed [`ScriptType`] universe
/// (§4.2). Order matters: the standard witness types are tested before the
/// generic `witness_unknown` catch-all, and P2A before either.
pub fn classify_script(script: &Script) -> ScriptType {
    if script.is_p2pkh() {
        ScriptType::P2pkh
    } else if script.is_p2sh() {
        ScriptType::P2sh
    } else if script.is_p2wpkh() {
        ScriptType::P2wpkh
    } else if script.is_p2wsh() {
        ScriptType::P2wsh
    } else if script.is_p2tr() {
        ScriptType::P2tr
    } else if is_p2a(script) {
        ScriptType::P2a
    } else if script.is_op_return() {
        ScriptType::OpReturn
    } else if script.is_p2pk() {
        ScriptType::P2pk
    } else if script.is_multisig() {
        ScriptType::BareMultisig
    } else if script.is_witness_program() {
        ScriptType::WitnessUnknown
    } else {
        ScriptType::Nonstandard
    }
}

/// The embedded script an input executes (`in.leaf_script`): the tapleaf for a
/// p2tr script-path spend, the witnessScript for p2wsh, or the redeemScript for
/// p2sh. Empty for key-path and non-script spends. Borrowed straight out of the
/// transaction's witness / scriptSig.
///
/// p2sh-wrapped segwit is **not** unwrapped here: its inner script lives in the
/// witness, and the p2tr/p2wsh arms handle it only when the *prevout itself* is
/// the witness program. A bare p2sh prevout yields its redeemScript (the last
/// scriptSig push), matching what an operator means by "the script this input
/// runs".
fn leaf_script<'a>(input: &'a TxIn, prevout_script: &Script) -> &'a [u8] {
    let w = &input.witness;
    if prevout_script.is_p2tr() {
        w.taproot_leaf_script()
            .map(|ls| ls.script.as_bytes())
            .unwrap_or(&[])
    } else if prevout_script.is_p2wsh() {
        w.witness_script().map(Script::as_bytes).unwrap_or(&[])
    } else if prevout_script.is_p2sh() {
        last_push(&input.script_sig)
    } else {
        &[]
    }
}

/// The last pushed-data element of a script (the redeemScript in a bare-p2sh
/// scriptSig). A malformed script just stops the scan at the bad instruction.
fn last_push(script: &Script) -> &[u8] {
    let mut last: &[u8] = &[];
    for ins in script.instructions() {
        if let Ok(Instruction::PushBytes(b)) = ins {
            last = b.as_bytes();
        }
    }
    last
}

/// Total pushed OP_RETURN payload bytes (`out.op_return_size`) — the data
/// carried, not the whole scriptPubKey (the leading `OP_RETURN` opcode and any
/// pushdata length prefixes are excluded). Matches the engine's documented
/// "payload size" semantics.
fn op_return_payload_size(script: &Script) -> i128 {
    let mut total = 0i128;
    for ins in script.instructions() {
        if let Ok(Instruction::PushBytes(b)) = ins {
            total += b.len() as i128;
        }
    }
    total
}

/// Core's dust verdict for an output (`out.is_dust`). OP_RETURN outputs are
/// never dust (they are intentionally unspendable). The effective dust rate is
/// the configured `-dustrelayfee`, falling back to the protocol default when the
/// operator has set it to 0 (disabling the *relay* check) so `is_dust` stays a
/// meaningful predicate for rules regardless of the relay toggle.
fn output_is_dust(out: &TxOut, cfg: &MempoolConfig) -> bool {
    if out.script_pubkey.is_op_return() {
        return false;
    }
    let rate = if cfg.dust_relay_fee > 0 {
        cfg.dust_relay_fee
    } else {
        policy::DUST_RELAY_FEE_RATE
    };
    let threshold = policy::dust_threshold_with_rate(&out.script_pubkey, rate);
    threshold > 0 && out.value.to_sat() < threshold
}

/// Build the [`TxView`]/[`Ctx`] for `tx` and evaluate `ruleset` against them
/// once, first-match-wins (§5/§7). `prev_outputs` and `prev_is_coinbase` are in
/// input order (aligned with `tx.input`). The returned [`Verdict`] owns its rule
/// name, so all the borrowed view state is free to drop with this frame.
#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    ruleset: &CompiledRuleset,
    tx: &Transaction,
    txid: &Txid,
    prev_outputs: &[TxOut],
    prev_is_coinbase: &[bool],
    fee: u64,
    fee_rate: u64,
    weight: usize,
    cfg: &MempoolConfig,
    ctx: PolicyCtx,
    source: TxSource,
    from_whitelisted_peer: bool,
) -> Verdict {
    with_view(
        tx,
        txid,
        prev_outputs,
        prev_is_coinbase,
        fee,
        fee_rate,
        weight,
        cfg,
        ctx,
        source,
        from_whitelisted_peer,
        |view, ctxv| ruleset.evaluate(view, ctxv),
    )
}

/// Like [`evaluate`], but returns the full per-rule trace alongside the verdict
/// — the `policytest` dry-run surface (design §10, PR 7d). Identical view
/// construction; the ruleset records each rule's matched/not result, stopping
/// at the first match (first-match-wins) exactly as the node would.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_trace(
    ruleset: &CompiledRuleset,
    tx: &Transaction,
    txid: &Txid,
    prev_outputs: &[TxOut],
    prev_is_coinbase: &[bool],
    fee: u64,
    fee_rate: u64,
    weight: usize,
    cfg: &MempoolConfig,
    ctx: PolicyCtx,
    source: TxSource,
    from_whitelisted_peer: bool,
) -> (Vec<satd_policy::RuleTrace>, Verdict) {
    with_view(
        tx,
        txid,
        prev_outputs,
        prev_is_coinbase,
        fee,
        fee_rate,
        weight,
        cfg,
        ctx,
        source,
        from_whitelisted_peer,
        |view, ctxv| ruleset.evaluate_trace(view, ctxv),
    )
}

/// Build the borrowed [`TxView`]/[`Ctx`] for `tx` and run `f` against them. The
/// view borrows slices out of `tx`/`prev_outputs` plus a couple of owned txid
/// buffers, all of which live for the duration of `f` and drop with this frame —
/// so nothing heap-resident outlives the evaluation. Shared by [`evaluate`] and
/// [`evaluate_trace`] so the two cannot diverge in how the view is filled.
#[allow(clippy::too_many_arguments)]
fn with_view<R>(
    tx: &Transaction,
    txid: &Txid,
    prev_outputs: &[TxOut],
    prev_is_coinbase: &[bool],
    fee: u64,
    fee_rate: u64,
    weight: usize,
    cfg: &MempoolConfig,
    ctx: PolicyCtx,
    source: TxSource,
    from_whitelisted_peer: bool,
    f: impl FnOnce(&TxView, &Ctx) -> R,
) -> R {
    // Owned 32-byte txid buffers — the only view state not borrowed from `tx`
    // or `prev_outputs`.
    let txid_bytes = txid.to_byte_array();
    let prevout_txids: Vec<[u8; 32]> = tx
        .input
        .iter()
        .map(|i| i.previous_output.txid.to_byte_array())
        .collect();

    // sigop cost (`tx.sigops_cost`), computed against the resolved prevouts
    // exactly as the entry accounting does at insert time.
    let prev_map: HashMap<OutPoint, TxOut> = tx
        .input
        .iter()
        .zip(prev_outputs.iter())
        .map(|(i, o)| (i.previous_output, o.clone()))
        .collect();
    let sigops_cost = tx.total_sigop_cost(|op| prev_map.get(op).cloned()) as i128;

    let mut inputs: Vec<InputView> = Vec::with_capacity(tx.input.len());
    for (idx, tin) in tx.input.iter().enumerate() {
        let prevout = &prev_outputs[idx];
        let pscript = &prevout.script_pubkey;
        let w = &tin.witness;
        let witness_size: i128 = w.iter().map(|e| e.len() as i128).sum();
        let max_witness_item = w.iter().map(|e| e.len() as i128).max().unwrap_or(0);
        inputs.push(InputView {
            prevout_txid: &prevout_txids[idx],
            prevout_vout: tin.previous_output.vout as i128,
            sequence: tin.sequence.0 as i128,
            script_sig: tin.script_sig.as_bytes(),
            witness_items: w.len() as i128,
            witness_size,
            max_witness_item,
            has_annex: pscript.is_p2tr() && w.taproot_annex().is_some(),
            prevout_value: prevout.value.to_sat() as i128,
            prevout_script_type: classify_script(pscript),
            prevout_script: pscript.as_bytes(),
            spends_coinbase: prev_is_coinbase.get(idx).copied().unwrap_or(false),
            leaf_script: leaf_script(tin, pscript),
        });
    }

    let mut outputs: Vec<OutputView> = Vec::with_capacity(tx.output.len());
    for tout in &tx.output {
        let s = &tout.script_pubkey;
        let st = classify_script(s);
        let op_return_size = if st == ScriptType::OpReturn {
            op_return_payload_size(s)
        } else {
            0
        };
        outputs.push(OutputView {
            value: tout.value.to_sat() as i128,
            script_type: st,
            script: s.as_bytes(),
            op_return_size,
            is_dust: output_is_dust(tout, cfg),
        });
    }

    let total_witness_size: i128 = inputs.iter().map(|i| i.witness_size).sum();

    let view = TxView {
        version: tx.version.0 as i128,
        locktime: tx.lock_time.to_consensus_u32() as i128,
        vsize: policy::weight_to_vsize(weight as u64) as i128,
        weight: weight as i128,
        total_witness_size,
        signals_rbf: tx.input.iter().any(|i| i.sequence.0 < 0xffff_fffe),
        txid: &txid_bytes,
        fee: fee as i128,
        fee_rate: fee_rate as i128,
        sigops_cost,
        source: map_source(source),
        from_whitelisted_peer,
        inputs: &inputs,
        outputs: &outputs,
    };

    let ctxv = Ctx {
        network: map_network(ctx.network),
        height: ctx.height as i128,
        min_relay_fee: cfg.min_fee_rate as i128,
        dust_relay_fee: cfg.dust_relay_fee as i128,
        mempool_bytes: ctx.mempool_bytes as i128,
        // No separate dynamic eviction floor is tracked yet; the static relay
        // floor is the closest honest value for `node.mempool_min_fee`.
        mempool_min_fee: cfg.min_fee_rate as i128,
    };

    f(&view, &ctxv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;

    fn spk(bytes: Vec<u8>) -> ScriptBuf {
        ScriptBuf::from_bytes(bytes)
    }

    #[test]
    fn classify_common_script_types() {
        // P2WPKH: OP_0 PUSH20
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(&[0u8; 20]);
        assert_eq!(classify_script(&spk(p2wpkh)), ScriptType::P2wpkh);

        // P2TR: OP_1 PUSH32
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0u8; 32]);
        assert_eq!(classify_script(&spk(p2tr)), ScriptType::P2tr);

        // OP_RETURN
        assert_eq!(classify_script(&spk(vec![0x6a, 0x01, 0x00])), ScriptType::OpReturn);

        // P2A anchor
        assert_eq!(classify_script(&spk(vec![0x51, 0x02, 0x4e, 0x73])), ScriptType::P2a);

        // Garbage ⇒ nonstandard
        assert_eq!(classify_script(&spk(vec![0xff, 0xff])), ScriptType::Nonstandard);
    }

    #[test]
    fn p2a_is_not_a_generic_witness_unknown() {
        // The anchor must classify as P2a, never as the witness-unknown catch-all
        // (a dust filter that carved out P2a depends on this — design §17.3 E1).
        assert_eq!(classify_script(&spk(vec![0x51, 0x02, 0x4e, 0x73])), ScriptType::P2a);
        // A different 2-byte v1 program is witness_unknown, not P2a.
        assert_eq!(classify_script(&spk(vec![0x51, 0x02, 0x00, 0x00])), ScriptType::WitnessUnknown);
    }

    #[test]
    fn op_return_payload_excludes_opcode_overhead() {
        // OP_RETURN OP_PUSHBYTES_3 0xaabbcc ⇒ payload is 3 bytes, not 5.
        let s = spk(vec![0x6a, 0x03, 0xaa, 0xbb, 0xcc]);
        assert_eq!(op_return_payload_size(&s), 3);
    }

    /// End-to-end view-builder test: a real `Transaction` + resolved prevouts run
    /// through `evaluate` against a ruleset that keys on output script type, the
    /// OP_RETURN payload size, and `tx.source` — the output OutputView fields the
    /// node fills. Exercises the builder in isolation from the mempool.
    #[test]
    fn evaluate_builds_view_and_quarantines_oversized_op_return() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness, transaction};

        // 90-byte OP_RETURN payload (> 83) on a low-effort spend.
        let mut op_return = vec![0x6a, 0x4c, 90u8]; // OP_RETURN OP_PUSHDATA1 90
        op_return.extend_from_slice(&[0xab; 90]);

        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([7u8; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(op_return),
            }],
        };
        let txid = tx.compute_txid();
        let prev = vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: {
                let mut v = vec![0x00, 0x14];
                v.extend_from_slice(&[0u8; 20]);
                ScriptBuf::from_bytes(v)
            },
        }];

        let ruleset = satd_policy::parse_ruleset(
            "version 1\nquarantine bulk when any output (out.script_type == op_return and out.op_return_size > 83)",
        )
        .unwrap();
        let cfg = MempoolConfig::default();
        let ctx = PolicyCtx {
            network: BNetwork::Regtest,
            height: 1,
            mempool_bytes: 0,
        };
        let verdict = evaluate(
            &ruleset,
            &tx,
            &txid,
            &prev,
            &[false],
            10_000, // fee
            1_000,  // fee_rate
            tx.weight().to_wu() as usize,
            &cfg,
            ctx,
            TxSource::P2p,
            false,
        );
        match verdict {
            satd_policy::Verdict::Quarantine { rule, .. } => assert_eq!(rule, "bulk"),
            other => panic!("expected quarantine, got {other:?}"),
        }
    }

    /// `evaluate_trace` must report every rule's matched/not, mark the first
    /// match decisive, and leave rules after it not-evaluated (first-match-wins).
    #[test]
    fn evaluate_trace_is_first_match_wins() {
        use bitcoin::blockdata::locktime::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness, transaction};

        let mut op_return = vec![0x6a, 0x4c, 90u8];
        op_return.extend_from_slice(&[0xab; 90]);
        let tx = Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([7u8; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::from_bytes(op_return),
            }],
        };
        let txid = tx.compute_txid();
        let prev = vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: {
                let mut v = vec![0x00, 0x14];
                v.extend_from_slice(&[0u8; 20]);
                ScriptBuf::from_bytes(v)
            },
        }];

        // first: won't match (version != 99); bulk: matches (decisive);
        // later: would match but is never reached.
        let ruleset = satd_policy::parse_ruleset(
            "version 1\n\
             quarantine first when tx.version == 99\n\
             quarantine bulk when any output (out.script_type == op_return and out.op_return_size > 83)\n\
             allow later when tx.version == 2",
        )
        .unwrap();
        let cfg = MempoolConfig::default();
        let ctx = PolicyCtx {
            network: BNetwork::Regtest,
            height: 1,
            mempool_bytes: 0,
        };
        let (traces, verdict) = evaluate_trace(
            &ruleset,
            &tx,
            &txid,
            &prev,
            &[false],
            10_000,
            1_000,
            tx.weight().to_wu() as usize,
            &cfg,
            ctx,
            TxSource::P2p,
            false,
        );

        assert_eq!(traces.len(), 3);
        assert_eq!(traces[0].name, "first");
        assert!(traces[0].evaluated && !traces[0].matched && !traces[0].decisive);
        assert_eq!(traces[1].name, "bulk");
        assert!(traces[1].evaluated && traces[1].matched && traces[1].decisive);
        assert_eq!(traces[2].name, "later");
        assert!(!traces[2].evaluated, "later rule is never reached (first-match-wins)");
        assert!(matches!(verdict, satd_policy::Verdict::Quarantine { .. }));
        assert_eq!(verdict.rule(), Some("bulk"));
    }
}
