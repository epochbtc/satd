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
//!
//! Wire shapes match upstream Esplora exactly. The `BlockHeaderJson`
//! summary defined in `crate::encode` is now populated with real
//! `size`, `weight`, and `mediantime` since this PR pulls the full
//! block from flat files.

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, Response, StatusCode};
use bitcoin::BlockHash;
use bitcoin::consensus::{Encodable, encode::serialize};

use crate::encode::{BlockHeaderJson, block_header_json};
use crate::error::{EsploraError, EsploraResult};
use crate::handlers::tx::{TxJson, build_block_tx_json};
use crate::state::EsploraState;

const BLOCK_TXS_PAGE: usize = 25;

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
    let block = state
        .chain
        .get_block(&hash)
        .ok_or(EsploraError::NotFound)?;
    let size = serialize(&block).len() as u32;
    let weight = block.weight().to_wu() as u32;
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
    let block = state
        .chain
        .get_block(&hash)
        .ok_or(EsploraError::NotFound)?;
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
    Path(hash): Path<String>,
) -> EsploraResult<Json<BlockStatusJson>> {
    let hash = parse_hash(&hash)?;
    let entry = state
        .chain
        .get_block_index(&hash)
        .ok_or(EsploraError::NotFound)?;
    let in_best = state
        .chain
        .get_block_hash_by_height(entry.height)
        .map(|h| h == hash)
        .unwrap_or(false);
    let next_best = if in_best {
        state
            .chain
            .get_block_hash_by_height(entry.height + 1)
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
        .get_block(&hash)
        .ok_or(EsploraError::NotFound)?;
    Ok(Json(
        block
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().to_string())
            .collect(),
    ))
}

/// `/block/:hash/txid/:index` → `<txid hex>` at the given index.
pub async fn block_txid_at_index(
    State(state): State<EsploraState>,
    Path((hash, index)): Path<(String, usize)>,
) -> EsploraResult<String> {
    let hash = parse_hash(&hash)?;
    let block = state
        .chain
        .get_block(&hash)
        .ok_or(EsploraError::NotFound)?;
    let tx = block.txdata.get(index).ok_or(EsploraError::NotFound)?;
    Ok(tx.compute_txid().to_string())
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
        .get_block(&hash)
        .ok_or(EsploraError::NotFound)?;
    let entry = state
        .chain
        .get_block_index(&hash)
        .ok_or(EsploraError::NotFound)?;
    let page = block_page_bounds(block.txdata.len(), start_index)?;
    let mut out = Vec::with_capacity(page.len());
    for tx in &block.txdata[page] {
        out.push(build_block_tx_json(
            &state,
            tx,
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
fn block_page_bounds(
    tx_count: usize,
    start_index: usize,
) -> EsploraResult<std::ops::Range<usize>> {
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

/// Reusable helper exposed for the `/blocks` page summary in
/// `chain::collect_blocks_descending`. Returns
/// `(serialized_size_bytes, weight_units)`.
pub fn try_compute_block_size_weight(
    state: &EsploraState,
    hash: &BlockHash,
) -> Option<(u32, u32)> {
    let block = state.chain.get_block(hash)?;
    Some((serialize(&block).len() as u32, block.weight().to_wu() as u32))
}

#[allow(dead_code)]
fn _status_code_unused() -> StatusCode {
    StatusCode::OK
}

#[allow(dead_code)]
fn _encodable_unused<E: Encodable>(_: E) {}
