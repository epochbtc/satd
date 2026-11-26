//! Block-detail handlers (Esplora plan PR 3):
//! - `GET /block/:hash`              → block summary JSON
//! - `GET /block/:hash/header`       → 80-byte block header, hex
//! - `GET /block/:hash/raw`          → full block, raw bytes
//! - `GET /block/:hash/status`       → `{in_best_chain, height?, next_best?}`
//! - `GET /block/:hash/txs`          → first 25 txs as JSON array (PR 4
//!   fills the full vin/vout/status shape; PR 3 returns a minimal
//!   `{txid}` stub so paging and indexing work)
//! - `GET /block/:hash/txs/:i`       → 25 txs starting at `i` (a multiple
//!   of 25; 404 `start index out of range` at or past the end)
//! - `GET /block/:hash/txid/:i`      → `<txid hex>` for tx at index `i`
//! - `GET /block/:hash/txids`        → array of every txid in the block
//! - `GET /block/:hash/txs/summary`  → `[txid, fee, weight, value]` for
//!   every tx in the block (an extension, as rbitcoin's Esplora serves it)
//!
//! Every handler reads through `get_stored_block`, so an OP_RETURN-stripped
//! block is served from its strip record: txids from the record, sizes and
//! weights from the filled form, which equal the original's. Only its raw
//! bytes are refused (404, [`BLOCK_DATA_STRIPPED`]).
//!
//! Wire shapes match upstream Esplora exactly. The `BlockHeaderJson`
//! summary defined in `crate::encode` is now populated with real
//! `size`, `weight`, and `mediantime` since this PR pulls the full
//! block from flat files.

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, Response, StatusCode};
use bitcoin::consensus::{Encodable, encode::serialize};
use bitcoin::{Block, BlockHash, Txid};
use node::mining::fee_profile::BlockFeeProfile;
use node::storage::undo::UndoData;

use crate::chain_tip::Pin;
use crate::encode::{BlockHeaderJson, block_header_json};
use crate::error::{EsploraError, EsploraResult};
use crate::handlers::tx::{TxJson, build_block_tx_json};
use crate::state::EsploraState;

const BLOCK_TXS_PAGE: usize = 25;

/// The body of a 404 for a stripped block's raw bytes.
pub(crate) const BLOCK_DATA_STRIPPED: &str = "block data not available (OP_RETURN data stripped)";

fn parse_hash(s: &str) -> EsploraResult<BlockHash> {
    s.parse::<BlockHash>()
        .map_err(|e| EsploraError::BadRequest(format!("bad block hash: {e}")))
}

/// `/block/:hash` → block summary.
pub async fn block_detail(
    State(state): State<EsploraState>,
    Path(hash): Path<String>,
) -> EsploraResult<Json<BlockHeaderJson>> {
    let hash = parse_hash(&hash)?;
    let entry = state
        .chain
        .get_block_index(&hash)
        .ok_or(EsploraError::NotFound)?;
    let (size, weight) =
        try_compute_block_size_weight(&state, &hash).ok_or(EsploraError::NotFound)?;
    // Median Time Past for the API field is the median of the
    // target block + up to 10 ancestors (Bitcoin Core / Esplora
    // explorer convention). The consensus helper
    // `get_median_time_past(h)` returns the MTP "as of just before"
    // height `h` (median of `h-11..h`); call with `h+1` so the target
    // block is included in the median set. (Review-2 M2.)
    let mediantime = state
        .chain
        .get_median_time_past(entry.height.saturating_add(1));
    Ok(Json(block_header_json(
        &hash,
        &entry,
        state.network,
        size,
        weight,
        mediantime,
    )))
}

/// `/block/:hash/header` → 80-byte serialized header, hex-encoded.
pub async fn block_header(
    State(state): State<EsploraState>,
    Path(hash): Path<String>,
) -> EsploraResult<String> {
    let hash = parse_hash(&hash)?;
    let entry = state
        .chain
        .get_block_index(&hash)
        .ok_or(EsploraError::NotFound)?;
    Ok(hex::encode(serialize(&entry.header)))
}

/// `/block/:hash/raw` → raw block bytes (binary). Buffered: blocks
/// can be hundreds of KB to multiple MB — we read once into a Vec
/// rather than streaming because flat-file reads return the whole
/// block in one shot anyway.
pub async fn block_raw(
    State(state): State<EsploraState>,
    Path(hash): Path<String>,
) -> EsploraResult<Response<Body>> {
    let hash = parse_hash(&hash)?;
    let stored = state
        .chain
        .get_stored_block(&hash)
        .ok_or(EsploraError::NotFound)?;
    // The filled form of a stripped block is not the block: never serve it.
    let block = stored
        .into_intact()
        .ok_or_else(|| EsploraError::NotFoundReason(BLOCK_DATA_STRIPPED.to_string()))?;
    let buf = serialize(&block);
    let mut resp = Response::new(Body::from(buf));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(resp)
}

/// `/block/:hash/status` → `{in_best_chain, height?, next_best?}`.
/// Matches upstream Esplora's shape.
#[derive(serde::Serialize)]
pub struct BlockStatusJson {
    pub in_best_chain: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_best: Option<String>,
}

pub async fn block_status(
    State(state): State<EsploraState>,
    axum::Extension(pin): axum::Extension<Pin>,
    Path(hash): Path<String>,
) -> EsploraResult<Json<BlockStatusJson>> {
    let hash = parse_hash(&hash)?;
    let entry = state
        .chain
        .get_block_index(&hash)
        .ok_or(EsploraError::NotFound)?;
    // Status as of the pinned tip: a block above it is not yet in the best
    // chain, and the pinned tip has no next block.
    let in_best = pin.hash_at_height(&state.chain, entry.height) == Some(hash);
    let next_best = if in_best {
        pin.hash_at_height(&state.chain, entry.height + 1)
            .map(|h| h.to_string())
    } else {
        None
    };
    Ok(Json(BlockStatusJson {
        in_best_chain: in_best,
        height: Some(entry.height),
        next_best,
    }))
}

/// `/block/:hash/txids` → array of every txid in the block.
pub async fn block_txids(
    State(state): State<EsploraState>,
    Path(hash): Path<String>,
) -> EsploraResult<Json<Vec<String>>> {
    let hash = parse_hash(&hash)?;
    let block = state
        .chain
        .get_stored_block(&hash)
        .ok_or(EsploraError::NotFound)?;
    Ok(Json(block.txids().iter().map(|t| t.to_string()).collect()))
}

/// The body of a 404 for a block whose fees cannot be computed because its
/// undo data is gone.
pub(crate) const BLOCK_UNDO_UNAVAILABLE: &str = "block undo data not available";

/// One row of `/block/:hash/txs/summary`, serialized as the JSON array
/// `[txid, fee, weight, value]`: fee and total output value in satoshis,
/// BIP 141 weight in weight units (not sigop-adjusted).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlockTxSummaryRow(pub String, pub u64, pub u64, pub u64);

/// `/block/:hash/txs/summary` → one `[txid, fee, weight, value]` row per
/// transaction in block order, the coinbase first with fee 0. Not part of
/// upstream Esplora: the route and its shape are those of rbitcoin's
/// Esplora, for a client that lists a whole block without fetching every
/// transaction in full.
///
/// 404 for a hash that is unknown, not on the best chain as of the pinned
/// tip, or whose block data is pruned, as rbitcoin answers. Fees come from
/// the block's undo data, as in `getblock` verbosity 2 and `getblockstats`;
/// a block that spends coins and has no undo row is 404
/// [`BLOCK_UNDO_UNAVAILABLE`], and an undo row that cannot be read or does
/// not match the block is a 500, never a row with a made-up fee.
pub async fn block_txs_summary(
    State(state): State<EsploraState>,
    axum::Extension(pin): axum::Extension<Pin>,
    Path(hash): Path<String>,
) -> EsploraResult<Json<Vec<BlockTxSummaryRow>>> {
    let hash = parse_hash(&hash)?;
    let entry = state
        .chain
        .get_block_index(&hash)
        .ok_or(EsploraError::NotFound)?;
    if pin.hash_at_height(&state.chain, entry.height) != Some(hash) {
        return Err(EsploraError::NotFound);
    }
    let stored = state
        .chain
        .get_stored_block(&hash)
        .ok_or(EsploraError::NotFound)?;
    let undo = state
        .chain
        .read_undo(&hash)
        .map_err(|e| EsploraError::Internal(format!("undo data for block {hash}: {e}")))?;
    block_summary_rows(&stored.block, &stored.txids(), undo.as_ref()).map(Json)
}

/// The rows of `/block/:hash/txs/summary` for `block`, whose transactions
/// have `txids` (from the strip record for an OP_RETURN-stripped block,
/// whose filled form keeps the original weights and output values).
fn block_summary_rows(
    block: &Block,
    txids: &[Txid],
    undo: Option<&UndoData>,
) -> EsploraResult<Vec<BlockTxSummaryRow>> {
    let spending = block.txdata.iter().filter(|tx| !tx.is_coinbase()).count();
    let profile = match undo {
        Some(undo) => BlockFeeProfile::from_undo(block, undo)
            .map_err(|e| EsploraError::Internal(e.to_string()))?,
        // A block of coinbases only (genesis, an empty block) spends nothing.
        None if spending == 0 => BlockFeeProfile::default(),
        None => {
            return Err(EsploraError::NotFoundReason(
                BLOCK_UNDO_UNAVAILABLE.to_string(),
            ));
        }
    };
    // The profile leaves out a transaction whose outputs exceed its inputs.
    // No connected block holds one, so a short profile means the undo row is
    // not this block's.
    if profile.txs.len() != spending || txids.len() != block.txdata.len() {
        return Err(EsploraError::Internal(
            "undo data is inconsistent with the block".to_string(),
        ));
    }
    let mut fees = profile.txs.iter().map(|priced| priced.fee);
    Ok(block
        .txdata
        .iter()
        .zip(txids)
        .map(|(tx, txid)| {
            let fee = if tx.is_coinbase() {
                0
            } else {
                fees.next().unwrap_or(0)
            };
            let value: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
            BlockTxSummaryRow(txid.to_string(), fee, tx.weight().to_wu(), value)
        })
        .collect())
}

/// `/block/:hash/txid/:index` → `<txid hex>` at the given index.
pub async fn block_txid_at_index(
    State(state): State<EsploraState>,
    Path((hash, index)): Path<(String, usize)>,
) -> EsploraResult<String> {
    let hash = parse_hash(&hash)?;
    let block = state
        .chain
        .get_stored_block(&hash)
        .ok_or(EsploraError::NotFound)?;
    if index >= block.block.txdata.len() {
        return Err(EsploraError::NotFound);
    }
    Ok(block.txid(index).to_string())
}

/// `/block/:hash/txs[/:start_index]` → page of 25 full Esplora-shape
/// txs (vin/vout/status/fee). PR 4 replaced PR 3's `{txid}` stub.
pub async fn block_txs(
    State(state): State<EsploraState>,
    Path(hash): Path<String>,
) -> EsploraResult<Json<Vec<TxJson>>> {
    block_txs_page(State(state), Path((hash, 0))).await
}

pub async fn block_txs_page(
    State(state): State<EsploraState>,
    Path((hash, start_index)): Path<(String, usize)>,
) -> EsploraResult<Json<Vec<TxJson>>> {
    let hash = parse_hash(&hash)?;
    let block = state
        .chain
        .get_stored_block(&hash)
        .ok_or(EsploraError::NotFound)?;
    let entry = state
        .chain
        .get_block_index(&hash)
        .ok_or(EsploraError::NotFound)?;
    let page = block_page_bounds(block.block.txdata.len(), start_index)?;
    let mut out = Vec::with_capacity(page.len());
    for i in page {
        out.push(build_block_tx_json(
            &state,
            &block,
            i,
            hash,
            entry.height,
            entry.header.time,
        )?);
    }
    Ok(Json(out))
}

/// The transactions `/block/:hash/txs/:start_index` serves: up to 25 from
/// `start_index`. A start at or past the end of the block is 404
/// `start index out of range`, and a start that is not a multiple of 25 is
/// 400, in that order, as mempool.space's electrs answers (`rest.rs`, the
/// `block/:hash/txs` route). Blockstream's electrs answers 400 for both,
/// with the same texts. The range check comes first and needs no
/// arithmetic, so `usize::MAX` cannot overflow (review H5).
fn block_page_bounds(tx_count: usize, start_index: usize) -> EsploraResult<std::ops::Range<usize>> {
    if start_index >= tx_count {
        return Err(EsploraError::NotFoundReason(
            "start index out of range".to_string(),
        ));
    }
    if !start_index.is_multiple_of(BLOCK_TXS_PAGE) {
        return Err(EsploraError::BadRequest(format!(
            "start index must be a multiple of {BLOCK_TXS_PAGE}"
        )));
    }
    let end = start_index.saturating_add(BLOCK_TXS_PAGE).min(tx_count);
    Ok(start_index..end)
}

#[cfg(test)]
#[path = "block_esplorapaging_tests.rs"]
mod esplorapaging_tests;

#[cfg(test)]
#[path = "block_txssummary_tests.rs"]
mod txssummary_tests;

/// Reusable helper exposed for the `/blocks` page summary in
/// `chain::collect_blocks_descending`. Returns
/// `(serialized_size_bytes, weight_units)`. A stripped block's filled form
/// has the original's size and weight.
pub fn try_compute_block_size_weight(state: &EsploraState, hash: &BlockHash) -> Option<(u32, u32)> {
    let block = state.chain.get_stored_block(hash)?.block;
    Some((
        serialize(&block).len() as u32,
        block.weight().to_wu() as u32,
    ))
}

#[allow(dead_code)]
fn _status_code_unused() -> StatusCode {
    StatusCode::OK
}

#[allow(dead_code)]
fn _encodable_unused<E: Encodable>(_: E) {}
