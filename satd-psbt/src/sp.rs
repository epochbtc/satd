//! BIP 375 verification: is this PSBT really going to pay the silent payment
//! addresses it names?
//!
//! The question matters because nothing else in the transaction answers it. A
//! silent payment output is a bare P2TR script; on the wire it is
//! indistinguishable from any other. If the ECDH share a Signer supplied is
//! wrong, the derived script is wrong, and the money goes to a key nobody
//! holds. The recipient finds nothing, the sender sees a confirmed
//! transaction, and there is no recovery. That is the failure this module
//! exists to catch before `finalizepsbt` hands back a transaction.
//!
//! The checks, in the order BIP 375 states them:
//!
//! 1. Which inputs are eligible to contribute to the shared secret (§352).
//! 2. Which public key each eligible input actually has — **bound to its
//!    previous output**, not merely asserted by the PSBT (see
//!    [`bound_public_key`]).
//! 3. Every ECDH share has a DLEQ proof that verifies against that key.
//! 4. The output script each silent payment code derives to, compared against
//!    what the PSBT says.
//!
//! Nothing here holds a secret or signs anything.


use bitcoin::hashes::{Hash, hash160};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1};
use bitcoin::{OutPoint, ScriptBuf, TxOut, WitnessVersion};

use crate::dleq;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::error::PsbtError;
use crate::keys;
use crate::v2::{InputView, SpV0Info, V2View};

/// BIP 352's scan limit. A receiving wallet tries `k = 0, 1, 2, …` until it
/// stops finding outputs; past this many outputs to one scan key, a compliant
/// receiver gives up and the payment is lost even though the transaction is
/// valid.
pub const K_MAX: u32 = 2323;

/// The most work one PSBT may ask the verifier for, in units of roughly one
/// elliptic-curve operation.
///
/// Two things are counted, and the unit of each matters. **Shares are
/// verified per scan key, not per output** — a scan key's outputs share one
/// ECDH point, however many of them there are — so the proof count is
/// (distinct scan keys) x (eligible inputs), the walk over the inputs looking
/// for each scan key's shares being the cost whether or not an input turns
/// out to carry one. **Scripts are derived per output**, twice, since two `k`
/// orderings may be tried. Both are products, not sums, and `analyzepsbt` is
/// a read-capability method, so a PSBT that merely fits inside the 20 MiB
/// request limit could otherwise ask for tens of seconds of curve arithmetic.
/// Measured at about 128 microseconds per proof in a release build, this cap
/// is worth under two seconds.
///
/// It is far above anything real. A thousand inputs paying ten distinct
/// recipients is ten thousand units, and a transaction with a thousand inputs
/// is already at the edge of standardness. Counting per output instead would
/// refuse a legal transaction: BIP 352 lets one scan key take `K_MAX` outputs,
/// and a handful of inputs paying that many would cross the cap while asking
/// for a handful of proofs.
pub const MAX_CURVE_OPERATIONS: usize = 10_000;

/// BIP 341's nothing-up-my-sleeve point. A taproot output whose internal key
/// is this one is provably script-path only, so nobody holds the key-path
/// secret and the input cannot contribute to a shared secret.
pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// What a node was able to say about an input's previous output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrevoutSource {
    /// No UTXO set was consulted.
    NotChecked,
    /// Found in the UTXO set and identical to what the PSBT says.
    UtxoSet,
    /// Not in the UTXO set — spent, unconfirmed, or from another chain — so
    /// the PSBT's own copy is all there is.
    Psbt,
    /// Found in the UTXO set and **different** from what the PSBT says.
    Mismatch,
}

/// Why an input contributes nothing to the shared secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ineligible {
    /// The PSBT does not say what this input spends.
    NoPrevout,
    /// BIP 352 lists the script types that may contribute; this is not one.
    ScriptType,
    /// A taproot input committed to the nothing-up-my-sleeve internal key.
    NumsInternalKey,
    /// A P2SH input whose redeem script is not P2WPKH, or does not hash to
    /// the script it claims.
    NotNestedP2wpkh,
    /// An eligible script whose public key the PSBT does not pin down. This
    /// is not "ineligible" in BIP 352's sense — the input does contribute —
    /// it is satd being unable to check the contribution.
    UnboundKey(String),
}

impl Ineligible {
    pub fn reason(&self) -> String {
        match self {
            Ineligible::NoPrevout => "the PSBT does not say what this input spends".to_string(),
            Ineligible::ScriptType => {
                "the previous output's script type cannot contribute to a silent payment"
                    .to_string()
            }
            Ineligible::NumsInternalKey => {
                "the taproot internal key is the nothing-up-my-sleeve point".to_string()
            }
            Ineligible::NotNestedP2wpkh => {
                "the redeem script is not the P2WPKH this script commits to".to_string()
            }
            Ineligible::UnboundKey(why) => why.clone(),
        }
    }

    /// Whether this is satd declining to check rather than BIP 352 excluding
    /// the input. The distinction decides whether a verdict is `unverifiable`
    /// or simply a smaller set of contributing inputs.
    pub fn is_unverifiable(&self) -> bool {
        matches!(self, Ineligible::UnboundKey(_) | Ineligible::NoPrevout)
    }
}

/// What one input contributes.
#[derive(Debug, Clone)]
pub struct InputReport {
    pub index: usize,
    pub outpoint: OutPoint,
    pub prevout: Option<TxOut>,
    pub prevout_source: PrevoutSource,
    /// The public key bound to the previous output, when there is one.
    pub public_key: Option<PublicKey>,
    pub ineligible: Option<Ineligible>,
}

impl InputReport {
    pub fn eligible(&self) -> bool {
        self.ineligible.is_none()
    }
}

/// Whether a silent payment output's script is there, and right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptState {
    /// Not computed yet, which BIP 375 allows until the Signer is done.
    Absent,
    Matches,
    Mismatch,
}

impl ScriptState {
    pub fn as_str(self) -> &'static str {
        match self {
            ScriptState::Absent => "absent",
            ScriptState::Matches => "matches",
            ScriptState::Mismatch => "mismatch",
        }
    }
}

/// The verdict on one silent payment output.
///
/// The order here is the precedence order: a transaction-wide problem is
/// reported before an output-specific one, and "we could not check" before
/// "we checked and it is wrong", so that an operator reads the first thing
/// that needs fixing rather than a consequence of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OutputStatus {
    /// A previous output disagrees with the UTXO set. Nothing derived from it
    /// can be trusted, the input public keys included.
    InvalidPrevout,
    /// The transaction cannot carry a silent payment at all: a segwit v2+
    /// input, a sighash that is not SIGHASH_ALL, or a degenerate key sum.
    InvalidInputs,
    /// An eligible input's public key is not pinned down by the PSBT, so its
    /// share cannot be checked.
    Unverifiable,
    /// A DLEQ proof does not verify.
    InvalidProof,
    /// An eligible input owes an ECDH share for this scan key.
    MissingShares,
    /// `PSBT_OUT_SCRIPT` is present and is not what the shares derive to.
    InvalidScript,
    /// Shares complete, proofs valid, keys bound, and the script either absent
    /// or equal to the derived one.
    Ready,
}

impl OutputStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            OutputStatus::InvalidPrevout => "invalid_prevout",
            OutputStatus::InvalidInputs => "invalid_inputs",
            OutputStatus::Unverifiable => "unverifiable",
            OutputStatus::InvalidProof => "invalid_proof",
            OutputStatus::MissingShares => "missing_shares",
            OutputStatus::InvalidScript => "invalid_script",
            OutputStatus::Ready => "ready",
        }
    }
}

/// The verdict on one silent payment output.
#[derive(Debug, Clone)]
pub struct OutputReport {
    pub index: usize,
    pub scan_key: PublicKey,
    pub spend_key: PublicKey,
    pub label: Option<u32>,
    /// The `k` this output was assigned within its scan key's group.
    pub k: u32,
    pub status: OutputStatus,
    /// Eligible inputs that owe an ECDH share for this scan key.
    pub missing_inputs: Vec<usize>,
    /// Inputs whose share for this scan key did not check out, and why.
    pub invalid_inputs: Vec<(usize, String)>,
    pub script_state: ScriptState,
    /// Whether the PSBT carried a non-empty `PSBT_OUT_SCRIPT` for this output.
    /// Separate from `script_state`, which says whether it was *right*: an
    /// output with no script yet is in progress, not wrong.
    pub script_present: bool,
    /// The script the PSBT carries for this output, if any.
    pub declared_script: Option<ScriptBuf>,
    pub derived_script: Option<ScriptBuf>,
    pub reason: Option<String>,
}

/// The whole verdict.
#[derive(Debug, Clone)]
pub struct SpReport {
    pub inputs: Vec<InputReport>,
    pub outputs: Vec<OutputReport>,
}

impl SpReport {
    pub fn eligible_inputs(&self) -> Vec<usize> {
        self.inputs
            .iter()
            .filter(|i| i.eligible())
            .map(|i| i.index)
            .collect()
    }

    /// Whether every silent payment output is ready *and* carries the script
    /// it derives to. This is the extractor's gate: a PSBT that is merely
    /// `ready` with no script yet is not finished, it is waiting on a Signer.
    pub fn extractable(&self) -> bool {
        self.outputs
            .iter()
            .all(|o| o.status == OutputStatus::Ready && o.script_state == ScriptState::Matches)
    }

    /// The first output that is not extractable, for an error message.
    pub fn first_problem(&self) -> Option<&OutputReport> {
        self.outputs
            .iter()
            .find(|o| o.status != OutputStatus::Ready || o.script_state != ScriptState::Matches)
    }
}

/// How to look a previous output up in a UTXO set. A node passes one; a
/// client that has no chain passes `None`.
pub type PrevoutLookup<'a> = dyn Fn(&OutPoint) -> Option<TxOut> + 'a;

/// How much to trust the public key a PSBT claims for an input.
///
/// BIP 375's reference validator takes the first `PSBT_IN_BIP32_DERIVATION`
/// key and never checks it against the previous output's script, and the
/// BIP's published vectors are generated the same way: 46 of the 49
/// non-taproot inputs across them carry a key that does not hash to their own
/// `witness_utxo`. So the two modes here are not a preference — they are the
/// difference between refereeing the derivation arithmetic against the BIP's
/// vectors and refereeing a real PSBT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBinding {
    /// The key must hash to the previous output's script. Anything else is
    /// `unverifiable`: the proof would be about a key with no relationship to
    /// the money being spent.
    ///
    /// This is what the node uses, always.
    Required,
    /// Take the key the PSBT declares, as the reference validator does. Only
    /// for refereeing against the BIP's own vectors, which do not bind.
    Declared,
}

/// Verify every silent payment output in a version 2 PSBT.
///
/// `lookup`, when given, cross-checks each previous output against the UTXO
/// set. That is the one check a node can do and a hardware wallet cannot: a
/// `witness_utxo` is whatever the PSBT's author wrote, and for a taproot input
/// it *is* the public key the share is supposed to belong to.
pub fn verify(view: &V2View<'_>, lookup: Option<&PrevoutLookup<'_>>) -> Result<SpReport, PsbtError> {
    verify_with_binding(view, lookup, KeyBinding::Required)
}

/// [`verify`], with the key-binding rule chosen explicitly. See [`KeyBinding`]
/// for why anything but `Required` exists.
pub fn verify_with_binding(
    view: &V2View<'_>,
    lookup: Option<&PrevoutLookup<'_>>,
    binding: KeyBinding,
) -> Result<SpReport, PsbtError> {
    let inputs = input_reports(view, lookup, binding)?;

    // Transaction-wide conditions, checked before anything derived from them.
    let blocking = blocking_condition(view, &inputs)?;

    let secp = Secp256k1::verification_only();
    let key_sum = sum_public_keys(inputs.iter().filter_map(|i| {
        if i.eligible() {
            i.public_key.as_ref()
        } else {
            None
        }
    }));
    let outpoints: Vec<OutPoint> = inputs.iter().map(|i| i.outpoint).collect();

    // `input_hash` is over *every* outpoint, eligible or not: BIP 352 takes
    // the lowest outpoint of the transaction, which is a property of the
    // transaction rather than of the contributing set.
    let input_hash = key_sum.as_ref().and_then(|sum| input_hash(&outpoints, sum));

    // Outputs grouped by scan key, in output order. `k` counts within a
    // group, so the group is the unit of work: the shares for a scan key are
    // verified once for the group, however many outputs it holds.
    //
    // The index beside the vec is what keeps grouping off the output count.
    // Scanning the groups already built for each output would be quadratic,
    // and this runs before the work below is capped.
    let mut groups: Vec<(SpV0Info, Vec<usize>)> = Vec::new();
    let mut group_of: HashMap<[u8; 33], usize> = HashMap::new();
    for output in view.outputs() {
        let Some(info) = output.sp_v0_info()? else {
            continue;
        };
        match group_of.entry(info.scan_key.serialize()) {
            Entry::Occupied(at) => groups[*at.get()].1.push(output.index()),
            Entry::Vacant(slot) => {
                slot.insert(groups.len());
                groups.push((info, vec![output.index()]));
            }
        }
    }

    // How much work this PSBT is asking for, counted before any of it is
    // done. See [`MAX_CURVE_OPERATIONS`].
    let eligible: Vec<&InputReport> = inputs.iter().filter(|i| i.eligible()).collect();
    let mut work = 0usize;
    for (group, members) in &groups {
        // Each output's script is derived once per `k` ordering tried, and
        // `assign_k` tries two.
        work = work.saturating_add(2 * members.len());
        // One proof for a global share, and the whole eligible set walked
        // looking for per-input ones — whether or not each input turns out to
        // carry one, since finding that out is itself the walk.
        if view
            .raw()
            .global
            .contains(keys::global::SP_ECDH_SHARE, &group.scan_key.serialize())
        {
            work = work.saturating_add(1);
        }
        work = work.saturating_add(eligible.len());
        if work > MAX_CURVE_OPERATIONS {
            return Err(PsbtError::TooMuchWork {
                limit: MAX_CURVE_OPERATIONS,
            });
        }
    }

    let mut outputs: Vec<OutputReport> = Vec::new();
    for (group, members) in groups {
        let mut reports: Vec<OutputReport> = Vec::with_capacity(members.len());
        for index in &members {
            let output = view
                .output(*index)
                .ok_or_else(|| PsbtError::structure("output index out of range"))?;
            let info = output.sp_v0_info()?.expect("the group was built from it");
            let script = output.map().get_single(keys::output::SCRIPT);
            reports.push(OutputReport {
                index: *index,
                scan_key: info.scan_key,
                spend_key: info.spend_key,
                label: output.sp_v0_label()?,
                k: 0,
                status: OutputStatus::Ready,
                missing_inputs: Vec::new(),
                invalid_inputs: Vec::new(),
                script_state: ScriptState::Absent,
                script_present: script.is_some_and(|s| !s.is_empty()),
                declared_script: script
                    .filter(|s| !s.is_empty())
                    .map(|s| ScriptBuf::from_bytes(s.to_vec())),
                derived_script: None,
                reason: None,
            });
        }

        // A transaction-wide problem applies to every output in every group.
        if let Some((status, reason)) = &blocking {
            for report in &mut reports {
                report.status = *status;
                report.reason = Some(reason.clone());
                if report.script_present {
                    report.script_state = ScriptState::Mismatch;
                }
            }
            outputs.extend(reports);
            continue;
        }

        // BIP 352's scan limit: past it a compliant receiver stops looking,
        // so the payment is lost even though the transaction is valid.
        if members.len() > K_MAX as usize {
            for report in &mut reports {
                report.status = OutputStatus::InvalidScript;
                report.reason = Some("too many outputs for one scan key".to_string());
            }
            outputs.extend(reports);
            continue;
        }

        let outcome = collect_share(view, &inputs, &group.scan_key, key_sum.as_ref())?;
        for report in &mut reports {
            report.missing_inputs.clone_from(&outcome.missing_inputs);
            report.invalid_inputs.clone_from(&outcome.invalid_inputs);
        }
        let (Some(ecdh), Some(input_hash)) = (outcome.ecdh, input_hash) else {
            let (status, reason) = match outcome.status {
                Some(status) => (status, outcome.reason.clone()),
                None => (
                    OutputStatus::InvalidInputs,
                    Some(
                        "the eligible inputs' public keys do not sum to a usable value"
                            .to_string(),
                    ),
                ),
            };
            for report in &mut reports {
                report.status = status;
                report.reason.clone_from(&reason);
                if report.script_present {
                    report.script_state = ScriptState::Mismatch;
                }
            }
            outputs.extend(reports);
            continue;
        };

        assign_k(&secp, &ecdh, &input_hash, &mut reports);
        outputs.extend(reports);
    }

    outputs.sort_by_key(|o| o.index);
    Ok(SpReport { inputs, outputs })
}

/// Which `k` each output in a scan-key group gets, and whether its script
/// matches.
///
/// **BIP 352 states no ordering.** Its "Creating outputs" section says only
/// "for each `B_m` in the group … `k++`", and its closing requirement is that
/// every `k` from 0 upwards is used with no gap, because a receiver stops
/// scanning at the first miss. Which output takes which `k` is not specified,
/// and the two specifications' own vectors disagree about it:
///
/// - BIP 375's valid vector 9 has two outputs under one scan key whose spend
///   keys *descend* with output index, and its scripts reproduce only under
///   `k = position in output order`.
/// - BIP 352's "un-labeled and labeled address" sending vector has two
///   recipients under one scan key, and its expected outputs reproduce only
///   under `k = position in spend-key order`.
///
/// Insisting on either one alone would refuse transactions the other
/// specification publishes as correct — and both orderings pay the recipient
/// exactly the same money, since a receiver scans `k = 0, 1, 2, …` and finds
/// whatever is there. So satd accepts either, and reports which it used
/// through each output's `k`. An assignment that is neither is refused, which
/// keeps BIP 375's invalid vector 21 (a scrambled `k`) invalid.
fn assign_k(
    secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    ecdh: &PublicKey,
    input_hash: &Scalar,
    reports: &mut [OutputReport],
) {
    // The two published orderings: output order, and spend-key order with
    // output index breaking a tie.
    let by_index: Vec<usize> = (0..reports.len()).collect();
    let mut by_spend_key: Vec<usize> = by_index.clone();
    by_spend_key.sort_by_key(|i| (reports[*i].spend_key.serialize(), reports[*i].index));

    let mut chosen: Option<(Vec<usize>, Vec<Option<ScriptBuf>>)> = None;
    for order in [&by_index, &by_spend_key] {
        let mut scripts: Vec<Option<ScriptBuf>> = vec![None; reports.len()];
        let mut all_match = true;
        for (k, position) in order.iter().enumerate() {
            let report = &reports[*position];
            let script =
                derive_script(secp, ecdh, input_hash, &report.spend_key, k as u32);
            if report.script_present && script.as_ref() != report.declared_script.as_ref() {
                all_match = false;
            }
            scripts[*position] = script;
        }
        if chosen.is_none() {
            // Output order is the one reported when neither matches, so that
            // an error message names the conventional derivation.
            chosen = Some((order.to_vec(), scripts.clone()));
        }
        if all_match {
            chosen = Some((order.to_vec(), scripts));
            break;
        }
    }

    let (order, scripts) = chosen.expect("at least one ordering was tried");
    for (k, position) in order.iter().enumerate() {
        reports[*position].k = k as u32;
    }
    for (position, script) in scripts.into_iter().enumerate() {
        let report = &mut reports[position];
        match script {
            None => {
                report.status = OutputStatus::InvalidInputs;
                report.reason =
                    Some("the shared secret does not derive a usable output key".to_string());
                if report.script_present {
                    report.script_state = ScriptState::Mismatch;
                }
            }
            Some(script) => {
                report.script_state = match &report.declared_script {
                    None => ScriptState::Absent,
                    Some(declared) if *declared == script => ScriptState::Matches,
                    Some(_) => ScriptState::Mismatch,
                };
                if report.script_state == ScriptState::Mismatch {
                    report.status = OutputStatus::InvalidScript;
                    report.reason =
                        Some("PSBT_OUT_SCRIPT is not what the ECDH shares derive to".to_string());
                }
                report.derived_script = Some(script);
            }
        }
    }
}


/// Per-input eligibility, key binding and previous-output cross-check.
fn input_reports(
    view: &V2View<'_>,
    lookup: Option<&PrevoutLookup<'_>>,
    binding: KeyBinding,
) -> Result<Vec<InputReport>, PsbtError> {
    let mut out = Vec::with_capacity(view.input_count());
    for input in view.inputs() {
        let outpoint = input.outpoint()?;
        let prevout = input.prevout()?;

        let prevout_source = match (lookup, &prevout) {
            (None, _) | (_, None) => PrevoutSource::NotChecked,
            (Some(lookup), Some(claimed)) => match lookup(&outpoint) {
                None => PrevoutSource::Psbt,
                Some(actual) if actual == *claimed => PrevoutSource::UtxoSet,
                Some(_) => PrevoutSource::Mismatch,
            },
        };

        let (public_key, ineligible) = match &prevout {
            None => (None, Some(Ineligible::NoPrevout)),
            Some(prevout) => classify(&input, prevout, binding)?,
        };

        out.push(InputReport {
            index: input.index(),
            outpoint,
            prevout,
            prevout_source,
            public_key,
            ineligible,
        });
    }
    Ok(out)
}

/// A condition that stops the whole transaction from carrying a silent
/// payment, whatever any individual output says.
fn blocking_condition(
    view: &V2View<'_>,
    inputs: &[InputReport],
) -> Result<Option<(OutputStatus, String)>, PsbtError> {
    for report in inputs {
        if report.prevout_source == PrevoutSource::Mismatch {
            return Ok(Some((
                OutputStatus::InvalidPrevout,
                format!(
                    "input {}: the previous output in the PSBT is not the one in the UTXO set",
                    report.index
                ),
            )));
        }
    }

    if let Some(why) = check_input_constraints(view)? {
        return Ok(Some((OutputStatus::InvalidInputs, why)));
    }

    let any_eligible = inputs.iter().any(|i| i.eligible());
    if !any_eligible {
        let unverifiable = inputs.iter().find(|i| {
            i.ineligible
                .as_ref()
                .is_some_and(Ineligible::is_unverifiable)
        });
        return Ok(Some(match unverifiable {
            Some(report) => (
                OutputStatus::Unverifiable,
                format!("input {}: {}", report.index, report.ineligible.as_ref()
                    .map(Ineligible::reason)
                    .unwrap_or_default()),
            ),
            None => (
                OutputStatus::InvalidInputs,
                "no input can contribute to a silent payment".to_string(),
            ),
        }));
    }

    // An eligible input whose key is not pinned down makes the whole
    // derivation uncheckable: its key is part of the sum.
    if let Some(report) = inputs.iter().find(|i| {
        i.ineligible
            .as_ref()
            .is_some_and(Ineligible::is_unverifiable)
    }) {
        return Ok(Some((
            OutputStatus::Unverifiable,
            format!(
                "input {}: {}",
                report.index,
                report
                    .ineligible
                    .as_ref()
                    .map(Ineligible::reason)
                    .unwrap_or_default()
            ),
        )));
    }

    Ok(None)
}

/// BIP 375's input-eligibility rules that apply to the whole transaction
/// rather than to one input's contribution.
///
/// Separate from the rest so a Signer can run it before it starts work, and
/// so the BIP's own vectors can exercise it on its own the way their `checks`
/// override asks.
pub fn check_input_constraints(view: &V2View<'_>) -> Result<Option<String>, PsbtError> {
    if !view.has_sp_outputs() {
        return Ok(None);
    }
    for input in view.inputs() {
        // A segwit v2+ input has no defined way to contribute a public key,
        // so BIP 352 forbids one anywhere in a transaction that pays a silent
        // payment address.
        if let Some(prevout) = input.prevout()?
            && let Some(version) = prevout.script_pubkey.witness_version()
            && version > WitnessVersion::V1
        {
            return Ok(Some(format!(
                "input {} spends a segwit version {} output, which cannot contribute to a \
                 silent payment",
                input.index(),
                version.to_num()
            )));
        }

        // Every signature must commit to every output, or the outputs the
        // shared secret was computed from could still change under it.
        if let Some(sighash) = input.sighash_type()?
            && sighash != 1
        {
            return Ok(Some(format!(
                "input {} uses sighash type {sighash}; a silent payment needs SIGHASH_ALL",
                input.index()
            )));
        }
        // A 65-byte Schnorr signature carries its sighash byte; 64 bytes means
        // the default, which is SIGHASH_ALL.
        if let Some(sig) = input.tap_key_sig()
            && sig.len() == 65
            && sig[64] != 1
        {
            return Ok(Some(format!(
                "input {} carries a taproot signature with sighash type {}; a silent payment \
                 needs SIGHASH_ALL",
                input.index(),
                sig[64]
            )));
        }
    }
    Ok(None)
}

/// What the shares for one scan key add up to, and what went wrong.
#[derive(Debug, Default)]
struct ShareOutcome {
    /// The ECDH share to derive from, when there is a usable one.
    ecdh: Option<PublicKey>,
    /// The verdict to report when there is not.
    status: Option<OutputStatus>,
    reason: Option<String>,
    missing_inputs: Vec<usize>,
    invalid_inputs: Vec<(usize, String)>,
}

/// Gather the ECDH shares for one scan key and check every proof covering it.
fn collect_share(
    view: &V2View<'_>,
    inputs: &[InputReport],
    scan_key: &PublicKey,
    key_sum: Option<&PublicKey>,
) -> Result<ShareOutcome, PsbtError> {
    let scan_bytes = scan_key.serialize();
    let mut outcome = ShareOutcome::default();

    // A global share stands for the whole eligible set at once, so it is
    // proven against the sum of their public keys.
    let global = view.raw().global.get(keys::global::SP_ECDH_SHARE, &scan_bytes);
    let mut global_point = None;
    if let Some(share) = global {
        let Some(sum) = key_sum else {
            outcome.status = Some(OutputStatus::InvalidInputs);
            outcome.reason =
                Some("the eligible inputs' public keys do not sum to a usable value".to_string());
            return Ok(outcome);
        };
        let Some(proof) = view.raw().global.get(keys::global::SP_DLEQ, &scan_bytes) else {
            outcome.status = Some(OutputStatus::MissingShares);
            outcome.reason =
                Some("the global ECDH share has no DLEQ proof for this scan key".to_string());
            return Ok(outcome);
        };
        match check_share(sum, scan_key, share, proof) {
            Ok(point) => global_point = Some(point),
            Err(why) => {
                outcome.status = Some(OutputStatus::InvalidProof);
                outcome.reason = Some(format!("the global ECDH share {why}"));
                return Ok(outcome);
            }
        }
    }

    // Per-input shares are checked whether or not a global one is present:
    // BIP 375 allows both, and a share that is carried but wrong is worth
    // reporting even when the derivation does not use it.
    let mut per_input = PointSum::Empty;
    for report_input in inputs.iter().filter(|i| i.eligible()) {
        let input = view
            .input(report_input.index)
            .ok_or_else(|| PsbtError::structure("input index out of range"))?;
        let Some(share) = input.map().get(keys::input::SP_ECDH_SHARE, &scan_bytes) else {
            outcome.missing_inputs.push(report_input.index);
            continue;
        };
        let Some(proof) = input.map().get(keys::input::SP_DLEQ, &scan_bytes) else {
            outcome
                .invalid_inputs
                .push((report_input.index, "the ECDH share has no DLEQ proof".to_string()));
            continue;
        };
        let Some(key) = report_input.public_key.as_ref() else {
            outcome.invalid_inputs.push((
                report_input.index,
                "the input's public key is not pinned down by the PSBT".to_string(),
            ));
            continue;
        };
        match check_share(key, scan_key, share, proof) {
            // Same rule as the public keys: an intermediate infinity is a
            // value, not a failure. Only the final sum has to be a point.
            Ok(point) => per_input = per_input.add(&point),
            Err(why) => outcome
                .invalid_inputs
                .push((report_input.index, format!("the ECDH share {why}"))),
        }
    }

    if !outcome.invalid_inputs.is_empty() {
        outcome.status = Some(OutputStatus::InvalidProof);
        return Ok(outcome);
    }

    // A global share covers every eligible input at once, so a per-input gap
    // is not a gap.
    if let Some(point) = global_point {
        outcome.missing_inputs.clear();
        outcome.ecdh = Some(point);
        return Ok(outcome);
    }
    if !outcome.missing_inputs.is_empty() {
        outcome.status = Some(OutputStatus::MissingShares);
        return Ok(outcome);
    }
    match per_input {
        PointSum::Point(point) => {
            outcome.ecdh = Some(point);
            Ok(outcome)
        }
        PointSum::Infinity => {
            outcome.status = Some(OutputStatus::InvalidInputs);
            outcome.reason = Some("the per-input ECDH shares sum to infinity".to_string());
            Ok(outcome)
        }
        PointSum::Empty => {
            outcome.status = Some(OutputStatus::MissingShares);
            outcome.reason = Some("no ECDH share covers this scan key".to_string());
            Ok(outcome)
        }
    }
}

/// Parse an ECDH share and check its DLEQ proof against the public key that
/// is supposed to have produced it.
fn check_share(
    public_key: &PublicKey,
    scan_key: &PublicKey,
    share: &[u8],
    proof: &[u8],
) -> Result<PublicKey, String> {
    let share = PublicKey::from_slice(share).map_err(|_| "is not a valid point".to_string())?;
    if proof.len() != 64 {
        return Err(format!("has a {}-byte DLEQ proof, not 64", proof.len()));
    }
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(proof);
    if dleq::verify_proof(public_key, scan_key, &share, &bytes, None) {
        Ok(share)
    } else {
        Err("has a DLEQ proof that does not verify".to_string())
    }
}

/// Eligibility and key binding for one input.
///
/// **This is where satd is stricter than BIP 375's reference validator.** The
/// reference takes the first `PSBT_IN_BIP32_DERIVATION` key and never checks
/// it against the previous output's script. A PSBT can therefore name any key
/// it likes, produce a DLEQ proof that verifies against it, and derive an
/// output the recipient cannot spend. Binding the key to the script it must
/// hash to is the check a wallet cannot safely skip.
fn classify(
    input: &InputView<'_>,
    prevout: &TxOut,
    binding: KeyBinding,
) -> Result<(Option<PublicKey>, Option<Ineligible>), PsbtError> {
    let script = &prevout.script_pubkey;

    if script.is_p2tr() {
        if input.tap_internal_key()? == Some(NUMS_H) {
            return Ok((None, Some(Ineligible::NumsInternalKey)));
        }
        if binding == KeyBinding::Declared
            && let Some(declared) = declared_key(input)
        {
            return Ok((Some(declared), None));
        }
        // The contributing key for a taproot input is the *output* key, and
        // it is right there in the script. Nothing to bind: it is the script.
        let bytes = script.as_bytes();
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&bytes[2..34]);
        return match PublicKey::from_slice(&compressed) {
            Ok(key) => Ok((Some(key), None)),
            Err(_) => Ok((
                None,
                Some(Ineligible::UnboundKey(
                    "the taproot output key is not a point on the curve".to_string(),
                )),
            )),
        };
    }

    let (hash, what) = if script.is_p2wpkh() {
        (script.as_bytes()[2..22].to_vec(), "P2WPKH")
    } else if script.is_p2pkh() {
        (script.as_bytes()[3..23].to_vec(), "P2PKH")
    } else if script.is_p2sh() {
        let Some(redeem) = input.redeem_script()? else {
            return Ok((None, Some(Ineligible::NotNestedP2wpkh)));
        };
        if !redeem.is_p2wpkh() {
            return Ok((None, Some(Ineligible::NotNestedP2wpkh)));
        }
        // The redeem script must be the one this P2SH output commits to, or
        // it is somebody else's script being waved at us.
        if hash160::Hash::hash(redeem.as_bytes()).to_byte_array() != script.as_bytes()[2..22] {
            return Ok((None, Some(Ineligible::NotNestedP2wpkh)));
        }
        (redeem.as_bytes()[2..22].to_vec(), "P2SH-P2WPKH")
    } else {
        return Ok((None, Some(Ineligible::ScriptType)));
    };

    if binding == KeyBinding::Declared {
        return match declared_key(input) {
            Some(key) => Ok((Some(key), None)),
            None => Ok((
                None,
                Some(Ineligible::UnboundKey(format!(
                    "this {what} input declares no public key"
                ))),
            )),
        };
    }

    let mut saw_uncompressed = false;
    for candidate in key_candidates(input) {
        let candidate = candidate.as_slice();
        if candidate.len() == 65 && hash160::Hash::hash(candidate).to_byte_array()[..] == hash[..] {
            // BIP 352 skips uncompressed keys outright: they cannot be used
            // for a silent payment, so this input contributes nothing.
            saw_uncompressed = true;
            continue;
        }
        if candidate.len() != 33 {
            continue;
        }
        if hash160::Hash::hash(candidate).to_byte_array()[..] != hash[..] {
            continue;
        }
        return match PublicKey::from_slice(candidate) {
            Ok(key) => Ok((Some(key), None)),
            Err(_) => Ok((
                None,
                Some(Ineligible::UnboundKey(format!(
                    "the {what} input's key hashes correctly but is not a point on the curve"
                ))),
            )),
        };
    }

    if saw_uncompressed {
        return Ok((None, Some(Ineligible::ScriptType)));
    }
    Ok((
        None,
        Some(Ineligible::UnboundKey(format!(
            "no key in this {what} input hashes to the previous output's script"
        ))),
    ))
}

/// The key a PSBT claims for an input, with no check that it belongs there.
/// Mirrors the reference validator's `pubkey_from_eligible_input`.
fn declared_key(input: &InputView<'_>) -> Option<PublicKey> {
    let first = input.bip32_derivations().next().map(|(key, _)| key)?;
    PublicKey::from_slice(first).ok()
}

/// Every place an input's public key might be written down. None of them is
/// trusted; [`classify`] keeps only the one that hashes to the script.
fn key_candidates(input: &InputView<'_>) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    out.extend(input.bip32_derivations().map(|(key, _)| key.to_vec()));
    out.extend(input.partial_sigs().map(|(key, _)| key.to_vec()));
    // A finalised input's key is the last element of its witness.
    if let Some(raw) = input.final_script_witness()
        && let Ok(witness) = bitcoin::consensus::deserialize::<bitcoin::Witness>(raw)
        && let Some(last) = witness.last()
    {
        out.push(last.to_vec());
    }
    out
}

/// A running point sum in which the point at infinity is a value.
///
/// secp256k1 has no representation for infinity, so `PublicKey::combine`
/// reports it as an error. Treating that error as failure would be wrong:
/// BIP 352 sums *scalars*, and an intermediate sum of zero is perfectly
/// legal as long as the final sum is not. BIP 352 ships a vector for exactly
/// this ("Input keys intermediate sum is zero but final sum is non-zero"),
/// and a left fold that gives up on the first infinity fails it.
#[derive(Debug, Clone, Copy)]
enum PointSum {
    Empty,
    Infinity,
    Point(PublicKey),
}

impl PointSum {
    fn add(self, key: &PublicKey) -> Self {
        match self {
            PointSum::Empty | PointSum::Infinity => PointSum::Point(*key),
            PointSum::Point(sum) => match sum.combine(key) {
                Ok(next) => PointSum::Point(next),
                // The only error `combine` has is the infinity case.
                Err(_) => PointSum::Infinity,
            },
        }
    }

    fn finish(self) -> Option<PublicKey> {
        match self {
            PointSum::Empty | PointSum::Infinity => None,
            PointSum::Point(point) => Some(point),
        }
    }
}

/// `Σ A_i`, or `None` when there is nothing to sum or the sum is infinity.
///
/// An *intermediate* sum of infinity is not a failure; see [`PointSum`].
pub fn sum_public_keys<'a>(keys: impl Iterator<Item = &'a PublicKey>) -> Option<PublicKey> {
    keys.fold(PointSum::Empty, |acc, key| acc.add(key)).finish()
}

/// BIP 352's `input_hash`: the lowest outpoint of the transaction, then the
/// sum of the contributing public keys.
///
/// The lowest outpoint is taken over **every** input, contributing or not: it
/// is a property of the transaction, and it is what stops one shared secret
/// being reusable across two different transactions.
pub fn input_hash(outpoints: &[OutPoint], key_sum: &PublicKey) -> Option<Scalar> {
    let mut serialized: Vec<Vec<u8>> = outpoints
        .iter()
        .map(bitcoin::consensus::serialize)
        .collect();
    serialized.sort();
    let lowest = serialized.first()?;
    let hash = dleq::tagged_hash("BIP0352/Inputs", &[lowest, &key_sum.serialize()]);
    // A hash at or above the group order, or zero, has no usable scalar. Both
    // are astronomically unlikely and both must be reported rather than
    // panicked on.
    Scalar::from_be_bytes(hash).ok()
}

/// BIP 352's output derivation: `P_k = B_spend + t_k·G`, where
/// `t_k = hash(shared_secret || k)` and `shared_secret = input_hash · ecdh`.
pub fn derive_output_script(
    ecdh: &PublicKey,
    input_hash: &Scalar,
    spend_key: &PublicKey,
    k: u32,
) -> Option<ScriptBuf> {
    derive_script(&Secp256k1::verification_only(), ecdh, input_hash, spend_key, k)
}

fn derive_script(
    secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    ecdh: &PublicKey,
    input_hash: &Scalar,
    spend_key: &PublicKey,
    k: u32,
) -> Option<ScriptBuf> {
    let shared = ecdh.mul_tweak(secp, input_hash).ok()?;
    let t_k = dleq::tagged_hash(
        "BIP0352/SharedSecret",
        &[&shared.serialize(), &k.to_be_bytes()],
    );
    let tweak = Scalar::from_be_bytes(t_k).ok()?;
    let output_key = spend_key.add_exp_tweak(secp, &tweak).ok()?;
    let (xonly, _) = output_key.x_only_public_key();
    Some(ScriptBuf::new_p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly),
    ))
}
