//! Transaction-level handlers (Esplora plan PR 4):
//! - `GET /tx/:txid`        → full tx JSON (vin/vout/status/fee)
//! - `GET /tx/:txid/status` → `{confirmed, block_height?, block_hash?, block_time?}`
//! - `GET /tx/:txid/hex`    → hex-encoded raw tx (text/plain)
//! - `GET /tx/:txid/raw`    → raw tx bytes (application/octet-stream)
//! - `POST /tx`             → broadcast: body is hex-encoded tx, returns txid
//!
//! Outspend (`/tx/:txid/outspend/:vout`, `/tx/:txid/outspends`) and
//! merkle-proof endpoints land in PR 6.

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, Response};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::{Address, Block, BlockHash, Network, Script, Transaction, Txid};
use node::storage::Store;
use serde::Serialize;

use crate::error::{EsploraError, EsploraResult};
use crate::state::EsploraState;

fn parse_txid(s: &str) -> EsploraResult<Txid> {
    s.parse::<Txid>()
        .map_err(|e| EsploraError::BadRequest(format!("bad txid: {e}")))
}

/// `/tx/:txid` → full tx JSON. Looks up via txindex first; falls back
/// to the mempool when not yet confirmed.
pub async fn tx_detail(
    State(state): State<EsploraState>,
    Path(txid): Path<String>,
) -> EsploraResult<Json<TxJson>> {
    let txid = parse_txid(&txid)?;
    if let Some((tx, location)) = lookup_confirmed(&state, &txid)? {
        Ok(Json(build_tx_json(&state, &tx, Some(location))?))
    } else if let Some(tx) = lookup_mempool(&state, &txid) {
        Ok(Json(build_tx_json(&state, &tx, None)?))
    } else {
        Err(EsploraError::NotFound)
    }
}

/// `/tx/:txid/status` → `{confirmed, block_height?, block_hash?, block_time?}`.
pub async fn tx_status(
    State(state): State<EsploraState>,
    Path(txid): Path<String>,
) -> EsploraResult<Json<TxStatusJson>> {
    let txid = parse_txid(&txid)?;
    if let Some((_, location)) = lookup_confirmed(&state, &txid)? {
        Ok(Json(TxStatusJson {
            confirmed: true,
            block_height: Some(location.height),
            block_hash: Some(location.block_hash.to_string()),
            block_time: Some(location.block_time),
        }))
    } else if lookup_mempool(&state, &txid).is_some() {
        Ok(Json(TxStatusJson {
            confirmed: false,
            block_height: None,
            block_hash: None,
            block_time: None,
        }))
    } else {
        Err(EsploraError::NotFound)
    }
}

/// `/tx/:txid/hex` → hex-encoded serialized tx.
pub async fn tx_hex(
    State(state): State<EsploraState>,
    Path(txid): Path<String>,
) -> EsploraResult<String> {
    let txid = parse_txid(&txid)?;
    let tx = lookup_any(&state, &txid)?;
    Ok(hex::encode(serialize(&tx)))
}

/// `/tx/:txid/raw` → raw tx bytes.
pub async fn tx_raw(
    State(state): State<EsploraState>,
    Path(txid): Path<String>,
) -> EsploraResult<Response<Body>> {
    let txid = parse_txid(&txid)?;
    let tx = lookup_any(&state, &txid)?;
    let mut resp = Response::new(Body::from(serialize(&tx)));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(resp)
}

/// `POST /tx` → broadcast. Body: hex-encoded tx bytes. Returns the
/// txid as plain text, matching upstream Esplora.
pub async fn tx_broadcast(
    State(state): State<EsploraState>,
    body: String,
) -> EsploraResult<String> {
    let bytes = hex::decode(body.trim())
        .map_err(|e| EsploraError::BadRequest(format!("bad hex: {e}")))?;
    let tx: Transaction = deserialize(&bytes)
        .map_err(|e| EsploraError::BadRequest(format!("decode: {e}")))?;
    // Accept + announce in one step so the tx actually propagates — a bare
    // mempool accept leaves it sitting on this node, unannounced.
    let txid = state
        .tx_broadcaster
        .submit_and_announce(tx)
        .map_err(|e| EsploraError::BadRequest(format!("mempool reject: {e}")))?;
    Ok(txid.to_string())
}

// ── JSON shapes ──

#[derive(Debug, Serialize)]
pub struct TxStatusJson {
    pub confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_time: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct PrevOutJson {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    /// Serialized as `null` for non-standard scripts to match upstream
    /// Esplora's wire shape exactly (review L3).
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

#[derive(Debug, Serialize)]
pub struct VinJson {
    /// Outpoint txid. ALWAYS present, including for coinbase inputs —
    /// upstream Esplora emits the all-zeros txid for coinbase, so a
    /// coinbase's `previous_output.txid` (which IS the null txid)
    /// serializes to "0000…0000", byte-for-byte matching upstream.
    /// Must not be omitted: strict typed clients (e.g. BDK's
    /// `esplora_client`) type this as a required field and fail to
    /// deserialize the whole tx if it is absent.
    pub txid: String,
    /// Outpoint vout. ALWAYS present; `4294967295` for coinbase (the
    /// null outpoint's vout). Same required-field rationale as `txid`.
    pub vout: u32,
    /// Resolved previous output, or `null`. Serialized as explicit
    /// `null` (not omitted) for coinbase inputs and for any input whose
    /// prevout could not be resolved — matching upstream Esplora, which
    /// always emits the `prevout` key.
    pub prevout: Option<PrevOutJson>,
    pub scriptsig: String,
    pub scriptsig_asm: String,
    pub witness: Vec<String>,
    pub is_coinbase: bool,
    pub sequence: u32,
}

#[derive(Debug, Serialize)]
pub struct VoutJson {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    /// `null` for non-standard scripts (review L3).
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

#[derive(Debug, Serialize)]
pub struct TxJson {
    pub txid: String,
    pub version: i32,
    pub locktime: u32,
    pub vin: Vec<VinJson>,
    pub vout: Vec<VoutJson>,
    pub size: u32,
    pub weight: u32,
    /// Total input value − total output value. `null` when at least
    /// one prevout could not be resolved (e.g. txindex disabled, the
    /// previous tx is missing) — distinguishes "actually zero fee"
    /// from "we can't tell" (review L4). `Some(0)` for coinbase txs.
    pub fee: Option<u64>,
    pub status: TxStatusJson,
}

// ── Helpers ──

#[derive(Debug, Clone, Copy)]
struct ConfirmedLocation {
    block_hash: BlockHash,
    height: u32,
    block_time: u32,
}

/// Find a tx via the txindex. Returns `Ok(None)` when txindex is
/// disabled or the txid has never been confirmed.
fn lookup_confirmed(
    state: &EsploraState,
    txid: &Txid,
) -> EsploraResult<Option<(Transaction, ConfirmedLocation)>> {
    if !state.chain.store_ref().has_txindex() {
        return Ok(None);
    }
    let block_hash = match state.chain.store_ref().get_tx_location(txid) {
        Some(h) => h,
        None => return Ok(None),
    };
    let block = state
        .chain
        .get_block(&block_hash)
        .ok_or_else(|| EsploraError::Internal(format!(
            "txindex points at {block_hash} but block data is missing"
        )))?;
    let entry = state.chain.get_block_index(&block_hash).ok_or_else(|| {
        EsploraError::Internal(format!(
            "txindex points at {block_hash} but block index entry is missing"
        ))
    })?;
    let tx = block
        .txdata
        .iter()
        .find(|t| t.compute_txid() == *txid)
        .cloned()
        .ok_or_else(|| {
            EsploraError::Internal(format!(
                "txindex points at {block_hash} but tx {txid} not present in block"
            ))
        })?;
    Ok(Some((
        tx,
        ConfirmedLocation {
            block_hash,
            height: entry.height,
            block_time: entry.header.time,
        },
    )))
}

fn lookup_mempool(state: &EsploraState, txid: &Txid) -> Option<Transaction> {
    state.mempool.get(txid).map(|entry| entry.tx)
}

fn lookup_any(state: &EsploraState, txid: &Txid) -> EsploraResult<Transaction> {
    if let Some((tx, _)) = lookup_confirmed(state, txid)? {
        return Ok(tx);
    }
    if let Some(tx) = lookup_mempool(state, txid) {
        return Ok(tx);
    }
    Err(EsploraError::NotFound)
}

/// Resolve a previous-output for a given input. Try (in order):
/// 1. The current UTXO set — works only when the input's prev_output is
///    still unspent (not the common case for confirmed inputs). For
///    mempool inputs spending on-chain UTXOs this is the hot path.
/// 2. The txindex → look up the block containing the prev txid, find
///    the prev tx, and return its `output[vout]`. Required for
///    confirmed inputs.
/// 3. The mempool — for child-of-mempool inputs.
fn resolve_prev_output(
    state: &EsploraState,
    prev: &bitcoin::OutPoint,
) -> Option<bitcoin::TxOut> {
    if let Some(coin) = state.chain.get_coin(prev) {
        return Some(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(coin.amount),
            script_pubkey: coin.script_pubkey,
        });
    }
    if state.chain.store_ref().has_txindex()
        && let Some(block_hash) = state.chain.store_ref().get_tx_location(&prev.txid)
        && let Some(block) = state.chain.get_block(&block_hash)
        && let Some(tx) = block.txdata.iter().find(|t| t.compute_txid() == prev.txid)
        && let Some(out) = tx.output.get(prev.vout as usize)
    {
        return Some(out.clone());
    }
    if let Some(entry) = state.mempool.get(&prev.txid)
        && let Some(out) = entry.tx.output.get(prev.vout as usize)
    {
        return Some(out.clone());
    }
    None
}

fn build_tx_json(
    state: &EsploraState,
    tx: &Transaction,
    location: Option<ConfirmedLocation>,
) -> EsploraResult<TxJson> {
    let txid = tx.compute_txid();

    let mut vin = Vec::with_capacity(tx.input.len());
    let mut sum_inputs: u64 = 0;
    let mut have_all_prevouts = true;
    for input in &tx.input {
        let is_coinbase = input.previous_output.is_null();
        let prevout = if is_coinbase {
            None
        } else {
            match resolve_prev_output(state, &input.previous_output) {
                Some(out) => {
                    sum_inputs += out.value.to_sat();
                    Some(prevout_json(&out, state.network))
                }
                None => {
                    have_all_prevouts = false;
                    None
                }
            }
        };
        let witness: Vec<String> = input.witness.iter().map(hex::encode).collect();
        vin.push(VinJson {
            // Always emit txid/vout from the outpoint. For coinbase the
            // outpoint is null → "0000…0000" / 4294967295, exactly what
            // upstream Esplora returns.
            txid: input.previous_output.txid.to_string(),
            vout: input.previous_output.vout,
            prevout,
            scriptsig: hex::encode(input.script_sig.as_bytes()),
            scriptsig_asm: input.script_sig.to_asm_string(),
            witness,
            is_coinbase,
            sequence: input.sequence.to_consensus_u32(),
        });
    }

    let vout: Vec<VoutJson> = tx
        .output
        .iter()
        .map(|out| VoutJson {
            scriptpubkey: hex::encode(out.script_pubkey.as_bytes()),
            scriptpubkey_asm: out.script_pubkey.to_asm_string(),
            scriptpubkey_type: script_type_str(&out.script_pubkey).to_string(),
            scriptpubkey_address: derive_address(&out.script_pubkey, state.network),
            value: out.value.to_sat(),
        })
        .collect();

    let sum_outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let fee = if tx.is_coinbase() {
        Some(0)
    } else if !have_all_prevouts {
        None
    } else {
        Some(sum_inputs.saturating_sub(sum_outputs))
    };

    let status = match location {
        Some(loc) => TxStatusJson {
            confirmed: true,
            block_height: Some(loc.height),
            block_hash: Some(loc.block_hash.to_string()),
            block_time: Some(loc.block_time),
        },
        None => TxStatusJson {
            confirmed: false,
            block_height: None,
            block_hash: None,
            block_time: None,
        },
    };

    Ok(TxJson {
        txid: txid.to_string(),
        version: tx.version.0,
        locktime: tx.lock_time.to_consensus_u32(),
        vin,
        vout,
        size: serialize(tx).len() as u32,
        weight: tx.weight().to_wu() as u32,
        fee,
        status,
    })
}

fn prevout_json(out: &bitcoin::TxOut, network: Network) -> PrevOutJson {
    PrevOutJson {
        scriptpubkey: hex::encode(out.script_pubkey.as_bytes()),
        scriptpubkey_asm: out.script_pubkey.to_asm_string(),
        scriptpubkey_type: script_type_str(&out.script_pubkey).to_string(),
        scriptpubkey_address: derive_address(&out.script_pubkey, network),
        value: out.value.to_sat(),
    }
}

/// Map a scriptPubKey to its Esplora-flavored type tag. Strings match
/// upstream `blockstream.info` so consumer tooling parses identically.
fn script_type_str(spk: &Script) -> &'static str {
    if spk.is_p2pk() {
        "p2pk"
    } else if spk.is_p2pkh() {
        "p2pkh"
    } else if spk.is_p2sh() {
        "p2sh"
    } else if spk.is_p2wpkh() {
        "v0_p2wpkh"
    } else if spk.is_p2wsh() {
        "v0_p2wsh"
    } else if spk.is_p2tr() {
        "v1_p2tr"
    } else if spk.is_op_return() {
        "op_return"
    } else if spk.is_multisig() {
        "multisig"
    } else {
        "unknown"
    }
}

fn derive_address(spk: &Script, network: Network) -> Option<String> {
    Address::from_script(spk, network).ok().map(|a| a.to_string())
}

/// Used by `block::block_txs[_page]` so the page handler doesn't
/// re-fetch the containing block once per tx. Returns the same
/// `TxJson` shape as `tx_detail` would for a confirmed tx.
pub fn build_block_tx_json(
    state: &EsploraState,
    tx: &Transaction,
    block_hash: BlockHash,
    height: u32,
    block_time: u32,
) -> EsploraResult<TxJson> {
    build_tx_json(
        state,
        tx,
        Some(ConfirmedLocation {
            block_hash,
            height,
            block_time,
        }),
    )
}

/// Build a full Esplora-shape JSON for a confirmed tx given only its
/// `txid` and `height`. Used by the address-history pagination paths,
/// which know `(txid, height)` from index rows but not the block.
///
/// Resolves the containing block via `txindex`: if txindex is disabled,
/// returns 503 ServiceUnavailable so the operator sees a clear failure
/// signal rather than a partial result. The daemon reconciliation in
/// `satd/src/config.rs` auto-enables txindex when esplora is on, so a
/// 503 here only fires under operator override (`--txindex=0` with
/// `--esplora=1`).
pub fn build_confirmed_tx_json(
    state: &EsploraState,
    txid: &Txid,
    _height: u32,
) -> EsploraResult<TxJson> {
    if !state.chain.store_ref().has_txindex() {
        return Err(EsploraError::ServiceUnavailable);
    }
    let block_hash = state
        .chain
        .store_ref()
        .get_tx_location(txid)
        .ok_or(EsploraError::NotFound)?;
    let block = state
        .chain
        .get_block(&block_hash)
        .ok_or_else(|| {
            EsploraError::Internal(format!(
                "txindex points at {block_hash} but block data is missing"
            ))
        })?;
    let entry = state
        .chain
        .get_block_index(&block_hash)
        .ok_or_else(|| {
            EsploraError::Internal(format!(
                "txindex points at {block_hash} but block index entry is missing"
            ))
        })?;
    let tx = block
        .txdata
        .iter()
        .find(|t| t.compute_txid() == *txid)
        .ok_or_else(|| {
            EsploraError::Internal(format!(
                "txindex points at {block_hash} but tx {txid} not present in block"
            ))
        })?;
    build_block_tx_json(state, tx, block_hash, entry.height, entry.header.time)
}

/// Build a JSON for an unconfirmed mempool tx. `status.confirmed` is
/// `false` and the block fields are absent. Used by the address-history
/// mempool-tx page.
pub fn build_mempool_tx_json(
    state: &EsploraState,
    tx: &Transaction,
) -> EsploraResult<TxJson> {
    build_tx_json(state, tx, None)
}

#[allow(dead_code)]
fn _block_unused(_: Block) {}
