//! Chain-tip handlers:
//! - `GET /blocks/tip/hash` → `<hash hex>` (text/plain)
//! - `GET /blocks/tip/height` → `<height>` (text/plain)
//! - `GET /block-height/:height` → `<hash hex>` (text/plain)
//! - `GET /blocks` → 10 most recent block-summary objects (JSON)
//! - `GET /blocks/:start_height` → 10 block-summary objects ending at
//!   `start_height` inclusive (JSON)
//!
//! Plain-text responses match upstream Esplora exactly so existing
//! BDK / Mutiny clients deserialize identically. Block-summary JSON
//! shape is `BlockHeaderJson` from `crate::encode`.

use axum::Json;
use axum::extract::{Path, State};

use crate::encode::{BlockHeaderJson, block_header_json};
use crate::error::{EsploraError, EsploraResult};
use crate::state::EsploraState;

/// `/blocks/tip/hash`. Plain-text big-endian hex (matches upstream).
pub async fn tip_hash(State(state): State<EsploraState>) -> String {
    state.chain.tip_hash().to_string()
}

/// `/blocks/tip/height`. Plain-text decimal.
pub async fn tip_height(State(state): State<EsploraState>) -> String {
    state.chain.tip_height().to_string()
}

/// `/block-height/:height` → block hash at that active-chain height.
/// 404 when the height is past tip or otherwise unknown.
pub async fn block_height(
    State(state): State<EsploraState>,
    Path(height): Path<u32>,
) -> EsploraResult<String> {
    state
        .chain
        .get_block_hash_by_height(height)
        .map(|h| h.to_string())
        .ok_or(EsploraError::NotFound)
}

/// `/blocks` → 10 most recent block-summary objects, descending by
/// height (newest first). Empty when chain is at genesis.
pub async fn blocks_recent(
    State(state): State<EsploraState>,
) -> EsploraResult<Json<Vec<BlockHeaderJson>>> {
    let tip = state.chain.tip_height();
    Ok(Json(collect_blocks_descending(&state, tip)?))
}

/// `/blocks/:start_height` → 10 block-summary objects ending at
/// `start_height` inclusive, descending. 404 when start_height > tip.
pub async fn blocks_at_or_below(
    State(state): State<EsploraState>,
    Path(start_height): Path<u32>,
) -> EsploraResult<Json<Vec<BlockHeaderJson>>> {
    if start_height > state.chain.tip_height() {
        return Err(EsploraError::NotFound);
    }
    Ok(Json(collect_blocks_descending(&state, start_height)?))
}

/// Walk down at most 10 active-chain blocks ending at `start_height`,
/// emitting `BlockHeaderJson` for each. Stops at genesis or when no
/// more height entries resolve.
fn collect_blocks_descending(
    state: &EsploraState,
    start_height: u32,
) -> Result<Vec<BlockHeaderJson>, EsploraError> {
    const PAGE: u32 = 10;
    let mut out = Vec::with_capacity(PAGE as usize);
    for offset in 0..PAGE {
        let h = match start_height.checked_sub(offset) {
            Some(h) => h,
            None => break,
        };
        let Some(hash) = state.chain.get_block_hash_by_height(h) else {
            break;
        };
        let Some(entry) = state.chain.get_block_index(&hash) else {
            break;
        };
        // PR 2 ships the bare-bones header summary. PR 3 fills in
        // `size` / `weight` / `mediantime` from block data on the
        // block-detail handler; here we report 0 for the size/weight
        // fields and the header timestamp for `mediantime`. Upstream
        // BDK consumers tolerate this for the tip-list shape — they
        // call /block/:hash for full detail.
        let mediantime = entry.header.time;
        out.push(block_header_json(
            &hash,
            &entry,
            state.network,
            0,
            0,
            mediantime,
        ));
    }
    Ok(out)
}
