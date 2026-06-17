//! Structural LN-enforcement danger analysis (§2.5 — the gate-grade tier).
//!
//! The [`advisory`](crate::advisory) module is a *syntactic* signal: it flags a
//! rule whose AST mentions L2-ish features. That is right for a warning but too
//! imprecise to *block* on — it fires on rules that merely reference witness size
//! or a small value, even when the predicate could never match a real
//! enforcement transaction. This module is the *semantic* counterpart: it
//! evaluates the *whole* ruleset (with the engine's own first-match-wins
//! semantics) against a curated set of synthetic transactions shaped like real
//! Lightning enforcement traffic, and reports only the rules that *actually
//! quarantine* one of them. The finding is "this rule
//! would withhold *this* enforcement shape", not "this rule is in the
//! neighborhood", so false positives are near-zero — which is what makes it
//! safe to gate a load on (`--allow-dangerous-filters`).
//!
//! Detectability splits exactly as the protocols do:
//! - **BOLT-3 (legacy / anchor)** enforcement scripts are spec-mandated, so a
//!   faithful vector is an exact probe: commitment (force-close) with its anchor
//!   outputs, the breach-remedy **justice** transaction (the time-critical E1
//!   case) spending a revoked `to_local`, and second-stage HTLC timeout/success.
//! - **Taproot-channel key-path force-closes** are *indistinguishable* from any
//!   other P2TR key-path spend, so they cannot be detected directly. The probe
//!   is instead a generic, healthy P2TR key-path spend: a rule that quarantines
//!   it is structurally over-broad and necessarily sweeps TR force-closes with
//!   it. Note the probe is deliberately *healthy* (normal fee rate and size), so
//!   a rule that only bites unhealthy traffic (a low-fee or oversize threshold)
//!   does **not** match — that distribution-dependent breadth is left to the
//!   advisory and the runtime hit-rate, never gated here.
//! - **Taproot-channel script-path enforcement** (justice / HTLC) reveals a
//!   tapleaf and is partially recognizable.
//!
//! `allow` rules are never dangerous: they only widen relay, never withhold.

use crate::ruleset::CompiledRuleset;
use crate::scope::ScopeSet;
use crate::script::{OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY};
use crate::value::{Network, ScriptType, Source};
use crate::verdict::Verdict;
use crate::view::{Ctx, InputView, OutputView, TxView};

/// The Lightning enforcement shape a probe vector represents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LnShape {
    /// A force-close commitment transaction (legacy anchor channel): a `to_local`
    /// delayed output plus two 330-sat P2A anchor outputs.
    Bolt3Commitment,
    /// A force-close commitment of a TRUC / zero-fee-commitment channel: a single
    /// 0-value (ephemeral) P2A anchor. Covers the dust/zero-value anchor shape
    /// that the legacy 330-sat anchors do not.
    Bolt3CommitmentEphemeralAnchor,
    /// A breach-remedy (justice / penalty) transaction spending a revoked
    /// `to_local` via the revocation branch (carries `OP_CSV`). The time-critical
    /// E1 case.
    Bolt3Justice,
    /// An offered-HTLC spend (the HTLC-timeout path): a faithful BOLT-3
    /// offered-HTLC witness script (`OP_CHECKMULTISIG` + hash-lock structure); the
    /// spending transaction is `OP_CLTV`-locktimed.
    Bolt3HtlcTimeout,
    /// A received-HTLC spend (the preimage / success path): a faithful BOLT-3
    /// received-HTLC witness script, whose remote-timeout branch carries
    /// `OP_CLTV` in-script.
    Bolt3HtlcSuccess,
    /// A simple-taproot-channel force-close: a P2TR key-path spend,
    /// byte-shaped like any other. Stands in for the indistinguishable case.
    TaprootKeyspendForceClose,
    /// A simple-taproot-channel script-path justice spend, revealing a tapleaf.
    TaprootScriptPathJustice,
    /// A generic, healthy P2TR key-path spend — the breadth probe.
    GenericP2trKeyspend,
}

impl LnShape {
    pub fn label(self) -> &'static str {
        match self {
            LnShape::Bolt3Commitment => "BOLT-3 force-close commitment (anchor channel)",
            LnShape::Bolt3CommitmentEphemeralAnchor => {
                "BOLT-3 force-close commitment (TRUC / ephemeral-anchor channel)"
            }
            LnShape::Bolt3Justice => "BOLT-3 breach-remedy (justice) transaction",
            LnShape::Bolt3HtlcTimeout => "BOLT-3 HTLC-timeout transaction",
            LnShape::Bolt3HtlcSuccess => "BOLT-3 HTLC-success transaction",
            LnShape::TaprootKeyspendForceClose => "taproot-channel key-path force-close",
            LnShape::TaprootScriptPathJustice => "taproot-channel script-path justice spend",
            LnShape::GenericP2trKeyspend => "generic P2TR key-path spend",
        }
    }
}

/// How a danger finding should be treated by a gate. All three are *structural*
/// (proven by an actual vector match), so all are gate-grade; they are
/// distinguished for messaging and for callers that want to weight them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DangerClass {
    /// Matched a spec-mandated BOLT-3 enforcement vector — highest confidence.
    Bolt3Enforcement,
    /// Matched a taproot-channel script-path enforcement vector.
    TaprootScriptPath,
    /// Matched a generic P2TR key-path spend — structurally over-broad, so it
    /// necessarily catches taproot-channel key-path force-closes.
    TaprootKeyspendBreadth,
}

impl DangerClass {
    pub fn headline(self) -> &'static str {
        match self {
            DangerClass::Bolt3Enforcement => {
                "would quarantine Lightning BOLT-3 enforcement transactions"
            }
            DangerClass::TaprootScriptPath => {
                "would quarantine taproot-channel script-path enforcement transactions"
            }
            DangerClass::TaprootKeyspendBreadth => {
                "is broad enough over P2TR key-path spends to sweep taproot-channel \
                 force-closes (which are indistinguishable from ordinary P2TR spends)"
            }
        }
    }
}

/// One danger finding: the offending rule, what shape it matched, the class, and
/// the rule's quarantine scope (so a gate can weight relay-withholding rules —
/// the E1-relevant ones — more heavily than `on template`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DangerFinding {
    pub rule: String,
    pub shape: LnShape,
    pub class: DangerClass,
    pub scope: ScopeSet,
}

impl DangerFinding {
    /// Whether this finding withholds relay assistance (relay or both). E1 turns
    /// on relay homogeneity, so a relay-withholding match is the dangerous one; a
    /// pure `on template` match degrades only this node's own block building.
    pub fn withholds_relay(&self) -> bool {
        self.scope.relay
    }
}

/// Analyze a ruleset for rules that structurally quarantine Lightning
/// enforcement traffic. Returns one finding per (rule, matched shape), in rule
/// order. Empty when the ruleset is safe.
pub fn analyze_danger(rs: &CompiledRuleset) -> Vec<DangerFinding> {
    let mut out = Vec::new();
    for v in vectors() {
        // Evaluate the *whole* ruleset against the vector with the engine's own
        // first-match-wins semantics: an earlier `allow` (or an earlier
        // quarantine) that matches the enforcement probe decides the verdict, so
        // a later quarantine rule it shadows is never reached — exactly as at
        // runtime. Only a quarantine verdict means the tx would actually be
        // withheld. (`Pass`/`Allow` ⇒ the probe is relayed; no finding.)
        if let Verdict::Quarantine { rule, scope } = v.verdict(rs) {
            out.push(DangerFinding {
                rule,
                shape: v.shape,
                class: v.shape.class(),
                scope,
            });
        }
    }
    out
}

impl LnShape {
    fn class(self) -> DangerClass {
        match self {
            LnShape::Bolt3Commitment
            | LnShape::Bolt3CommitmentEphemeralAnchor
            | LnShape::Bolt3Justice
            | LnShape::Bolt3HtlcTimeout
            | LnShape::Bolt3HtlcSuccess => DangerClass::Bolt3Enforcement,
            LnShape::TaprootScriptPathJustice => DangerClass::TaprootScriptPath,
            LnShape::TaprootKeyspendForceClose | LnShape::GenericP2trKeyspend => {
                DangerClass::TaprootKeyspendBreadth
            }
        }
    }
}

// ─── Synthetic vectors ──────────────────────────────────────────────────────
//
// Each vector owns its backing byte buffers; `matches` builds the borrowed
// `TxView` from them and evaluates a rule's condition in one scope. Scripts use
// real opcodes so `count_op` / `contains_ops` and script-type predicates see
// faithful structure.

// Opcodes assembled inline (only OP_CLTV/OP_CSV are exported by `script`).
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_DROP: u8 = 0x75;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_2: u8 = 0x52;
const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_SWAP: u8 = 0x7c;
const OP_SIZE: u8 = 0x82;
const OP_NOTIF: u8 = 0x64;

/// Push `n` zero bytes as a data push (`<len> <bytes…>`), for placeholder keys
/// and hashes. `n` must be ≤ 75 (single-byte push opcode).
fn push(n: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(n as usize + 1);
    v.push(n);
    v.extend(std::iter::repeat_n(0u8, n as usize));
    v
}

/// The `to_local` witness script: `OP_IF <revocation_pk> OP_ELSE <to_self_delay>
/// OP_CSV OP_DROP <delayed_pk> OP_ENDIF OP_CHECKSIG` (BOLT-3). A justice spend
/// takes the revocation branch; the script carries OP_CSV either way.
fn to_local_script() -> Vec<u8> {
    let mut s = vec![OP_IF];
    s.extend(push(33)); // revocation pubkey
    s.push(OP_ELSE);
    s.extend([0x02, 0x90, 0x00]); // to_self_delay (144) as a 2-byte scriptnum push
    s.push(OP_CHECKSEQUENCEVERIFY);
    s.push(OP_DROP);
    s.extend(push(33)); // delayed pubkey
    s.push(OP_ENDIF);
    s.push(OP_CHECKSIG);
    s
}

/// The funding 2-of-2 multisig witness script the commitment transaction spends.
fn funding_2of2_script() -> Vec<u8> {
    let mut s = vec![OP_2];
    s.extend(push(33));
    s.extend(push(33));
    s.push(OP_2);
    s.push(OP_CHECKMULTISIG);
    s
}

/// A faithful BOLT-3 first-stage HTLC witness script (§ "Offered/Received HTLC
/// Outputs"). `offered = true` builds the offered-HTLC script (redeemed remotely
/// by preimage, or locally via the locktimed HTLC-timeout transaction);
/// `offered = false` builds the received-HTLC script, whose remote-timeout branch
/// carries `OP_CLTV` in-script. Both share the distinctive revocation-hash +
/// `OP_SIZE 32 OP_EQUAL` + `OP_CHECKMULTISIG` structure that an anti-HTLC filter
/// would key on. (First-stage HTLC scripts do not carry `OP_CSV`; the CSV delay
/// lives on the *second-stage* `to_local` output, covered by [`to_local_script`].
/// We deliberately do not synthesize an unrealistic CSV∧CLTV-in-one-script
/// vector, because no real BOLT-3 script combines them.)
fn htlc_script(offered: bool) -> Vec<u8> {
    // OP_DUP OP_HASH160 <RIPEMD160(revocationpubkey)> OP_EQUAL
    let mut s = vec![OP_DUP, OP_HASH160];
    s.extend(push(20)); // revocation pubkey hash
    s.push(OP_EQUAL);
    // OP_IF OP_CHECKSIG  (revocation branch)
    s.push(OP_IF);
    s.push(OP_CHECKSIG);
    s.push(OP_ELSE);
    // <remote_htlcpubkey> OP_SWAP OP_SIZE 32 OP_EQUAL
    s.extend(push(33)); // remote htlc pubkey
    s.push(OP_SWAP);
    s.push(OP_SIZE);
    s.extend([0x01, 0x20]); // push 32 (preimage length check)
    s.push(OP_EQUAL);
    if offered {
        // OP_NOTIF  (not a preimage → local sweeps via HTLC-timeout tx)
        s.push(OP_NOTIF);
        s.push(OP_DROP);
        // 2 OP_SWAP <local_htlcpubkey> 2 OP_CHECKMULTISIG
        s.push(OP_2);
        s.push(OP_SWAP);
        s.extend(push(33)); // local htlc pubkey
        s.push(OP_2);
        s.push(OP_CHECKMULTISIG);
        s.push(OP_ELSE);
        // OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY OP_CHECKSIG
        s.push(OP_HASH160);
        s.extend(push(20));
        s.push(OP_EQUALVERIFY);
        s.push(OP_CHECKSIG);
        s.push(OP_ENDIF);
    } else {
        // OP_IF  (preimage → local success via 2-of-2)
        s.push(OP_IF);
        s.push(OP_HASH160);
        s.extend(push(20)); // payment hash
        s.push(OP_EQUALVERIFY);
        s.push(OP_2);
        s.push(OP_SWAP);
        s.extend(push(33)); // local htlc pubkey
        s.push(OP_2);
        s.push(OP_CHECKMULTISIG);
        s.push(OP_ELSE);
        // OP_DROP <cltv_expiry> OP_CLTV OP_DROP OP_CHECKSIG  (remote timeout)
        s.push(OP_DROP);
        s.extend([0x03, 0xc0, 0x27, 0x09]); // cltv_expiry (600000) as scriptnum push
        s.push(OP_CHECKLOCKTIMEVERIFY);
        s.push(OP_DROP);
        s.push(OP_CHECKSIG);
        s.push(OP_ENDIF);
    }
    s.push(OP_ENDIF);
    s
}

/// A taproot revocation tapleaf: `<rev_pk> OP_CHECKSIG <delay> OP_CSV` style —
/// carries OP_CSV, revealed by a script-path justice spend.
fn taproot_justice_leaf() -> Vec<u8> {
    let mut s = push(32); // x-only revocation key
    s.push(OP_CHECKSIG);
    s.extend([0x02, 0x90, 0x00]); // delay
    s.push(OP_CHECKSEQUENCEVERIFY);
    s
}

fn p2wsh_spk() -> Vec<u8> {
    let mut v = vec![0x00, 0x20];
    v.extend(std::iter::repeat_n(0u8, 32));
    v
}
fn p2tr_spk() -> Vec<u8> {
    let mut v = vec![0x51, 0x20];
    v.extend(std::iter::repeat_n(0u8, 32));
    v
}
fn p2wpkh_spk() -> Vec<u8> {
    let mut v = vec![0x00, 0x14];
    v.extend(std::iter::repeat_n(0u8, 20));
    v
}
/// A pay-to-anchor (P2A) output script: `OP_1 <0x4e73>` (BIP / ephemeral anchor
/// shape). 240-sat value at the call site.
fn p2a_spk() -> Vec<u8> {
    vec![0x51, 0x02, 0x4e, 0x73]
}

struct OwnedIn {
    prevout_txid: Vec<u8>,
    prevout_vout: i128,
    sequence: i128,
    script_sig: Vec<u8>,
    witness_items: i128,
    witness_size: i128,
    max_witness_item: i128,
    has_annex: bool,
    prevout_value: i128,
    prevout_script_type: ScriptType,
    prevout_script: Vec<u8>,
    spends_coinbase: bool,
    leaf_script: Vec<u8>,
}

struct OwnedOut {
    value: i128,
    script_type: ScriptType,
    script: Vec<u8>,
    op_return_size: i128,
    is_dust: bool,
}

struct Vector {
    shape: LnShape,
    version: i128,
    locktime: i128,
    vsize: i128,
    weight: i128,
    total_witness_size: i128,
    signals_rbf: bool,
    fee: i128,
    fee_rate: i128,
    sigops_cost: i128,
    txid: Vec<u8>,
    ins: Vec<OwnedIn>,
    outs: Vec<OwnedOut>,
}

impl Vector {
    /// Evaluate the whole ruleset against this vector with first-match-wins
    /// semantics (so `allow` shielding and rule order are honored exactly).
    fn verdict(&self, rs: &CompiledRuleset) -> Verdict {
        let ins: Vec<InputView> = self
            .ins
            .iter()
            .map(|i| InputView {
                prevout_txid: &i.prevout_txid,
                prevout_vout: i.prevout_vout,
                sequence: i.sequence,
                script_sig: &i.script_sig,
                witness_items: i.witness_items,
                witness_size: i.witness_size,
                max_witness_item: i.max_witness_item,
                has_annex: i.has_annex,
                prevout_value: i.prevout_value,
                prevout_script_type: i.prevout_script_type,
                prevout_script: &i.prevout_script,
                spends_coinbase: i.spends_coinbase,
                leaf_script: &i.leaf_script,
            })
            .collect();
        let outs: Vec<OutputView> = self
            .outs
            .iter()
            .map(|o| OutputView {
                value: o.value,
                script_type: o.script_type,
                script: &o.script,
                op_return_size: o.op_return_size,
                is_dust: o.is_dust,
            })
            .collect();
        let tx = TxView {
            version: self.version,
            locktime: self.locktime,
            vsize: self.vsize,
            weight: self.weight,
            total_witness_size: self.total_witness_size,
            signals_rbf: self.signals_rbf,
            txid: &self.txid,
            fee: self.fee,
            fee_rate: self.fee_rate,
            sigops_cost: self.sigops_cost,
            source: Source::P2p,
            from_whitelisted_peer: false,
            inputs: &ins,
            outputs: &outs,
        };
        // Probes are evaluated under a single mainnet / P2p-relay snapshot: E1 is
        // about relay homogeneity, and enforcement traffic reaches the mempool
        // over P2p, so this is the surface that matters. A rule scoped on a
        // narrower submission context (e.g. `tx.source == rpc`, or a non-mainnet
        // `node.network`) only affects locally-submitted or off-mainnet traffic,
        // does not degrade network-wide relay homogeneity, and is intentionally
        // out of scope for the gate.
        let ctx = Ctx {
            network: Network::Mainnet,
            height: 800_000,
            min_relay_fee: 1_000,
            dust_relay_fee: 3_000,
            mempool_bytes: 0,
            mempool_min_fee: 1_000,
        };
        rs.evaluate(&tx, &ctx)
    }
}

/// A spending input shaped like an enforcement spend of `leaf` from a prevout of
/// `pst`, with a realistic enforcement witness size.
fn enforcement_in(pst: ScriptType, leaf: Vec<u8>, witness_size: i128) -> OwnedIn {
    OwnedIn {
        prevout_txid: vec![0x11; 32],
        prevout_vout: 0,
        sequence: 0x0000_0001, // enforcement spends often set a CSV-driven sequence
        script_sig: Vec::new(),
        witness_items: 3,
        witness_size,
        // The largest witness element a real enforcement spend reveals is the
        // bigger of a ~72-byte signature and the witness script itself (an HTLC
        // script is ~140 B, a to_local script ~77 B), so anti-spam witness-item
        // caps that would catch real enforcement are caught here too.
        max_witness_item: (leaf.len() as i128).max(72),
        has_annex: false,
        prevout_value: 200_000,
        prevout_script_type: pst,
        prevout_script: match pst {
            ScriptType::P2wsh => p2wsh_spk(),
            ScriptType::P2tr => p2tr_spk(),
            _ => p2wpkh_spk(),
        },
        spends_coinbase: false,
        leaf_script: leaf,
    }
}

fn out(value: i128, st: ScriptType, script: Vec<u8>, is_dust: bool) -> OwnedOut {
    OwnedOut {
        value,
        script_type: st,
        script,
        op_return_size: 0,
        is_dust,
    }
}

/// The probe set. Healthy/realistic field values throughout, so only structural
/// matches register (a distribution-dependent threshold won't trip these).
fn vectors() -> Vec<Vector> {
    let base = |shape: LnShape, locktime: i128, ins: Vec<OwnedIn>, outs: Vec<OwnedOut>| {
        // Derive the tx-level witness total from the inputs so witness-size
        // predicates see a realistic enforcement footprint (not a flat 220).
        let total_witness_size: i128 = ins.iter().map(|i| i.witness_size).sum();
        Vector {
            shape,
            version: 2,
            locktime,
            vsize: 200,
            weight: 800,
            total_witness_size,
            signals_rbf: false,
            fee: 2_000,
            fee_rate: 10_000, // healthy
            sigops_cost: 0,
            txid: vec![0x22; 32],
            ins,
            outs,
        }
    };

    vec![
        // Force-close commitment (legacy anchor channel): funding 2-of-2 spent;
        // to_local + to_remote + two 330-sat P2A anchors (the canonical anchor
        // value; below Core's ~330-sat P2WSH dust floor, so value/dust sweeps
        // catch it).
        base(
            LnShape::Bolt3Commitment,
            0,
            vec![enforcement_in(ScriptType::P2wsh, funding_2of2_script(), 240)],
            vec![
                out(150_000, ScriptType::P2wsh, p2wsh_spk(), false), // to_local
                out(40_000, ScriptType::P2wpkh, p2wpkh_spk(), false), // to_remote
                out(330, ScriptType::P2a, p2a_spk(), true),          // local anchor
                out(330, ScriptType::P2a, p2a_spk(), true),          // remote anchor
            ],
        ),
        // Force-close commitment (TRUC / zero-fee-commitment channel): a single
        // 0-value ephemeral P2A anchor, so `out.value == 0` / `out.value < N`
        // sweeps are caught regardless of the 330-sat convention.
        base(
            LnShape::Bolt3CommitmentEphemeralAnchor,
            0,
            vec![enforcement_in(ScriptType::P2wsh, funding_2of2_script(), 240)],
            vec![
                out(150_000, ScriptType::P2wsh, p2wsh_spk(), false), // to_local
                out(40_000, ScriptType::P2wpkh, p2wpkh_spk(), false), // to_remote
                out(0, ScriptType::P2a, p2a_spk(), true),            // ephemeral anchor
            ],
        ),
        // Justice: spend a revoked to_local via the revocation branch. Realistic
        // witness (revocation sig + ~77-byte witness script).
        base(
            LnShape::Bolt3Justice,
            0,
            vec![enforcement_in(ScriptType::P2wsh, to_local_script(), 200)],
            vec![out(190_000, ScriptType::P2wpkh, p2wpkh_spk(), false)],
        ),
        // Offered-HTLC spend via the locktimed HTLC-timeout transaction. The
        // ~140-byte witness script and non-zero CLTV locktime are both faithful.
        base(
            LnShape::Bolt3HtlcTimeout,
            600_000,
            vec![enforcement_in(ScriptType::P2wsh, htlc_script(true), 280)],
            vec![out(95_000, ScriptType::P2wsh, p2wsh_spk(), false)],
        ),
        // Received-HTLC spend (preimage path); its remote-timeout branch carries
        // OP_CLTV in-script.
        base(
            LnShape::Bolt3HtlcSuccess,
            0,
            vec![enforcement_in(ScriptType::P2wsh, htlc_script(false), 280)],
            vec![out(95_000, ScriptType::P2wsh, p2wsh_spk(), false)],
        ),
        // Taproot script-path justice: tapleaf revealed, carries OP_CSV.
        base(
            LnShape::TaprootScriptPathJustice,
            0,
            vec![enforcement_in(ScriptType::P2tr, taproot_justice_leaf(), 180)],
            vec![out(190_000, ScriptType::P2tr, p2tr_spk(), false)],
        ),
        // Taproot key-path force-close: indistinguishable from a plain keyspend.
        base(
            LnShape::TaprootKeyspendForceClose,
            0,
            vec![keyspend_in()],
            vec![
                out(150_000, ScriptType::P2tr, p2tr_spk(), false),
                out(40_000, ScriptType::P2tr, p2tr_spk(), false),
            ],
        ),
        // Generic healthy P2TR keyspend — the breadth probe.
        base(
            LnShape::GenericP2trKeyspend,
            0,
            vec![keyspend_in()],
            vec![out(99_800, ScriptType::P2tr, p2tr_spk(), false)],
        ),
    ]
}

/// A plain P2TR key-path spend input: empty leaf script, single ~64-byte
/// Schnorr signature witness.
fn keyspend_in() -> OwnedIn {
    OwnedIn {
        prevout_txid: vec![0x11; 32],
        prevout_vout: 0,
        sequence: 0xffff_fffd,
        script_sig: Vec::new(),
        witness_items: 1,
        witness_size: 65,
        max_witness_item: 64,
        has_annex: false,
        prevout_value: 100_000,
        prevout_script_type: ScriptType::P2tr,
        prevout_script: p2tr_spk(),
        spends_coinbase: false,
        leaf_script: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_ruleset;

    fn findings(src: &str) -> Vec<DangerFinding> {
        analyze_danger(&parse_ruleset(src).unwrap())
    }
    fn shapes(src: &str) -> Vec<LnShape> {
        findings(src).into_iter().map(|f| f.shape).collect()
    }

    #[test]
    fn justice_csv_rule_is_caught() {
        let s = shapes(
            "version 1\nquarantine j when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)",
        );
        assert!(s.contains(&LnShape::Bolt3Justice), "{s:?}");
    }

    #[test]
    fn htlc_cltv_rule_is_caught() {
        // Only the received-HTLC (success) witness script carries OP_CLTV
        // in-script; the offered-HTLC timeout path enforces its timeout via the
        // spending tx locktime, not the witness script.
        let s = shapes(
            "version 1\nquarantine h when any inputs (in.leaf_script.count_op(OP_CHECKLOCKTIMEVERIFY) > 0)",
        );
        assert!(s.contains(&LnShape::Bolt3HtlcSuccess), "{s:?}");
    }

    #[test]
    fn htlc_structure_rule_is_caught() {
        // A filter keyed on the distinctive BOLT-3 HTLC 2-of-2 structure
        // (OP_CHECKMULTISIG inside the hash-locked branch) catches both HTLC
        // shapes — proving the witness scripts are faithful, not opcode soup.
        let s = shapes(
            "version 1\nquarantine m when any inputs (in.leaf_script.count_op(OP_CHECKMULTISIG) > 0)",
        );
        assert!(s.contains(&LnShape::Bolt3HtlcTimeout), "{s:?}");
        assert!(s.contains(&LnShape::Bolt3HtlcSuccess), "{s:?}");
    }

    #[test]
    fn oversize_witness_item_cap_catches_htlc() {
        // An anti-spam per-item witness cap that would catch a real ~140-byte
        // HTLC witness script must trip the gate.
        let s = shapes("version 1\nquarantine bigitem when any inputs (in.max_witness_item > 100)");
        assert!(
            s.contains(&LnShape::Bolt3HtlcTimeout) || s.contains(&LnShape::Bolt3HtlcSuccess),
            "witness-item cap must catch an HTLC enforcement spend: {s:?}"
        );
    }

    #[test]
    fn witness_size_cap_catches_enforcement() {
        // A too-aggressive total-witness-size cap that would catch real
        // enforcement traffic must trip the gate.
        let s = shapes("version 1\nquarantine bigwit when tx.total_witness_size > 250");
        assert!(
            s.contains(&LnShape::Bolt3HtlcTimeout) || s.contains(&LnShape::Bolt3HtlcSuccess),
            "witness-size cap must catch an HTLC enforcement spend: {s:?}"
        );
    }

    #[test]
    fn dust_value_sweep_catches_anchor() {
        // A sub-330-sat value sweep catches the 0-value ephemeral anchor; a dust
        // predicate catches the legacy 330-sat anchors too.
        let low = shapes("version 1\nquarantine lowval when any outputs (out.value < 330)");
        assert!(
            low.contains(&LnShape::Bolt3CommitmentEphemeralAnchor),
            "sub-330 value sweep must catch the ephemeral anchor: {low:?}"
        );
        let dust = shapes("version 1\nquarantine dust when any outputs (out.is_dust)");
        assert!(
            dust.contains(&LnShape::Bolt3Commitment),
            "dust sweep must catch the legacy 330-sat anchors: {dust:?}"
        );
    }

    #[test]
    fn anchor_rule_catches_commitment() {
        let s = shapes("version 1\nquarantine a when any outputs (out.script_type == p2a)");
        assert!(s.contains(&LnShape::Bolt3Commitment), "{s:?}");
        assert_eq!(
            findings("version 1\nquarantine a when any outputs (out.script_type == p2a)")[0].class,
            DangerClass::Bolt3Enforcement
        );
    }

    #[test]
    fn broad_p2tr_keyspend_rule_is_caught_as_breadth() {
        // A rule that quarantines P2TR key-path spends generally sweeps taproot
        // force-closes.
        let f = findings(
            "version 1\nquarantine t when any inputs (in.prevout_script_type == p2tr)",
        );
        assert!(
            f.iter().any(|x| x.class == DangerClass::TaprootKeyspendBreadth),
            "{f:?}"
        );
    }

    #[test]
    fn healthy_keyspend_probe_resists_distributional_rules() {
        // A low-fee threshold rule must NOT match the healthy keyspend probe —
        // distributional breadth is not gated here.
        let f = findings("version 1\nquarantine lowfee when tx.fee_rate < 1000");
        assert!(
            !f.iter().any(|x| x.shape == LnShape::GenericP2trKeyspend),
            "distributional rule must not trip the structural probe: {f:?}"
        );
    }

    #[test]
    fn anti_inscription_witness_rule_does_not_hit_keyspend_forceclose() {
        // The canonical anti-inscription rule (big witness) must not flag the
        // key-path force-close, whose witness is tiny.
        let f = findings("version 1\nquarantine bigwit on template when tx.total_witness_size > 100000");
        assert!(
            !f.iter().any(|x| x.class == DangerClass::TaprootKeyspendBreadth),
            "{f:?}"
        );
    }

    #[test]
    fn ordinals_marker_rule_is_safe() {
        // The cookbook ordinals rule keys on a self-identifying marker, not on
        // enforcement structure — no findings.
        let f = findings(
            "version 1\nquarantine ordinals when any inputs (in.leaf_script.contains_ops(script(OP_FALSE OP_IF push(0x6f7264))))",
        );
        assert!(f.is_empty(), "unexpected danger findings: {f:?}");
    }

    #[test]
    fn allow_rules_are_never_dangerous() {
        let f = findings(
            "version 1\nallow a when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)",
        );
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn earlier_allow_shadows_a_later_quarantine() {
        // Review round 2 (PR 408): the analyzer honors first-match-wins. An
        // `allow` that matches the enforcement probe first shields it, so the
        // later quarantine on the SAME condition never fires at runtime — and
        // must not be reported as dangerous.
        let f = findings(
            "version 1\n\
             allow ln when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)\n\
             quarantine csv when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)\n",
        );
        assert!(f.is_empty(), "first-match allow must shadow the quarantine: {f:?}");

        // Sanity: without the shielding allow, the same quarantine IS flagged.
        let g = findings(
            "version 1\nquarantine csv when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)\n",
        );
        assert!(!g.is_empty(), "control: bare quarantine should be flagged");
    }

    #[test]
    fn earlier_quarantine_attributes_the_finding() {
        // First-match also means the FIRST matching quarantine owns the finding,
        // not a later one that also matches.
        let f = findings(
            "version 1\n\
             quarantine first when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)\n\
             quarantine second when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)\n",
        );
        assert!(f.iter().all(|x| x.rule == "first"), "{f:?}");
    }

    #[test]
    fn scope_is_reported_for_weighting() {
        let f = findings(
            "version 1\nquarantine j on template when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)",
        );
        assert!(!f.is_empty());
        assert!(!f[0].withholds_relay(), "on template ⇒ relay not withheld");
        let g = findings(
            "version 1\nquarantine j when any inputs (in.leaf_script.count_op(OP_CHECKSEQUENCEVERIFY) > 0)",
        );
        assert!(g[0].withholds_relay(), "bare quarantine ⇒ relay withheld");
    }
}
