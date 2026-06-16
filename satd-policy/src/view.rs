//! Borrowed views over a transaction and the node context (§4.3).
//!
//! These are the data the evaluator reads. They are deliberately plain,
//! pre-computed, borrowed structures: the *node* fills them in at the single
//! evaluation point (PR 4c), computing the things that are not expressible in
//! the language (Core's dust formula, fee rate floor semantics, sigop cost,
//! script-type classification) once, during validation, and handing the
//! evaluator cheap field reads. This crate does no transaction parsing and no
//! consensus computation — it only reads the view.
//!
//! All integer fields are `i128` so the saturating-arithmetic evaluator never
//! has to widen at use sites; the node widens once when building the view.

use crate::value::{Network, ScriptType, Source};

/// A single transaction input, as seen by the evaluator.
#[derive(Clone, Copy, Debug)]
pub struct InputView<'a> {
    // --- context-free ---
    pub prevout_txid: &'a [u8],
    pub prevout_vout: i128,
    pub sequence: i128,
    /// Raw scriptSig (empty for native segwit).
    pub script_sig: &'a [u8],
    pub witness_items: i128,
    pub witness_size: i128,
    /// Size of the largest single witness element.
    pub max_witness_item: i128,
    pub has_annex: bool,
    // --- prevout-derived (after input resolution) ---
    pub prevout_value: i128,
    pub prevout_script_type: ScriptType,
    pub prevout_script: &'a [u8],
    pub spends_coinbase: bool,
    /// The embedded script this input executes: tapleaf (p2tr script-path),
    /// witnessScript (p2wsh) or redeemScript (p2sh); empty for key-path and
    /// non-script spends.
    pub leaf_script: &'a [u8],
}

/// A single transaction output, as seen by the evaluator.
#[derive(Clone, Copy, Debug)]
pub struct OutputView<'a> {
    pub value: i128,
    pub script_type: ScriptType,
    /// Raw scriptPubKey.
    pub script: &'a [u8],
    /// Pushed OP_RETURN payload bytes (0 unless `script_type == op_return`).
    pub op_return_size: i128,
    /// Core's dust verdict for this output (script-type dependent; computed by
    /// the node, not expressible in-language).
    pub is_dust: bool,
}

/// The whole-transaction view. Inputs/outputs are borrowed slices; quantifiers
/// iterate them.
#[derive(Clone, Copy, Debug)]
pub struct TxView<'a> {
    // --- context-free ---
    pub version: i128,
    pub locktime: i128,
    pub vsize: i128,
    pub weight: i128,
    pub total_witness_size: i128,
    /// BIP125: any input sequence < 0xfffffffe.
    pub signals_rbf: bool,
    pub txid: &'a [u8],
    // --- prevout-derived ---
    pub fee: i128,
    /// sat/kvB, floor.
    pub fee_rate: i128,
    pub sigops_cost: i128,
    // --- submission context ---
    pub source: Source,
    pub from_whitelisted_peer: bool,
    // --- elements ---
    pub inputs: &'a [InputView<'a>],
    pub outputs: &'a [OutputView<'a>],
}

impl<'a> TxView<'a> {
    /// `tx.input_count` (derived from the slice; not stored redundantly).
    pub fn input_count(&self) -> i128 {
        self.inputs.len() as i128
    }
    /// `tx.output_count`.
    pub fn output_count(&self) -> i128 {
        self.outputs.len() as i128
    }
}

/// The node-context snapshot (`node.*`), taken once per evaluation (§4.3).
#[derive(Clone, Copy, Debug)]
pub struct Ctx {
    pub network: Network,
    pub height: i128,
    pub min_relay_fee: i128,
    pub dust_relay_fee: i128,
    pub mempool_bytes: i128,
    pub mempool_min_fee: i128,
}
