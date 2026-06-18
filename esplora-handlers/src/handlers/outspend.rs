//! Outspend + merkle-proof handlers (Esplora plan PR 6).
//!
//! Endpoints:
//! - `GET /tx/:txid/outspend/:vout`        → single outspend
//! - `GET /tx/:txid/outspends`             → array of outspends, one per output
//! - `GET /tx/:txid/merkle-proof`          → JSON merkle path
//! - `GET /tx/:txid/merkleblock-proof`     → hex-encoded MerkleBlock
//!
//! Outspend backed by `SpendIndex::spend_of` for confirmed-side lookups
//! plus a one-shot mempool scan for unconfirmed spends. Merkle paths
//! computed directly from block txids using the standard Bitcoin
//! double-sha256 pairing rule (odd-out duplication).

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, State};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::merkle_tree::MerkleBlock;
use bitcoin::{Block, OutPoint, TxMerkleNode, Txid};
use node::storage::Store;
use serde::Serialize;

use crate::error::{EsploraError, EsploraResult};
use crate::handlers::tx::TxStatusJson;
use crate::state::EsploraState;

// ── JSON shapes ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct OutspendJson {
    pub spent: bool,
    /// Spending txid — present only when `spent: true`. Mirrors upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    /// Spending input index (vin) — present only when `spent: true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vin: Option<u32>,
    /// Spending tx's confirmation status — present only when
    /// `spent: true`. `confirmed: false` for mempool spends.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<TxStatusJson>,
}

#[derive(Debug, Serialize)]
pub struct MerkleProofJson {
    pub block_height: u32,
    /// Sibling hashes from leaf level upward, hex-encoded in display
    /// (reversed) byte order — matches upstream Esplora and Bitcoin
    /// Core's `getmerkleproof`-style outputs.
    pub merkle: Vec<String>,
    /// Position of the tx within the block's tx list (0-indexed).
    pub pos: u32,
}

// ── Handlers ───────────────────────────────────────────────────────

pub async fn tx_outspend(
    State(state): State<EsploraState>,
    Path((txid_s, vout)): Path<(String, u32)>,
) -> EsploraResult<Json<OutspendJson>> {
    let txid = parse_txid(&txid_s)?;
    // Reject unknown txids and out-of-range vouts up front (review H1).
    // Without this check, every malformed request fell through to the
    // bottom of build_outspend and returned `200 {spent:false}`, which
    // looks indistinguishable from a real unspent outpoint.
    let output_count = output_count_of(&state, &txid)?;
    if vout as usize >= output_count {
        return Err(EsploraError::NotFound);
    }
    let outpoint = OutPoint { txid, vout };
    Ok(Json(build_outspend_one(&state, &outpoint)?))
}

pub async fn tx_outspends(
    State(state): State<EsploraState>,
    Path(txid_s): Path<String>,
) -> EsploraResult<Json<Vec<OutspendJson>>> {
    let txid = parse_txid(&txid_s)?;

    // Determine the tx's output count. For confirmed txs we look up the
    // tx body via txindex; for mempool txs we read it from the entry.
    // Either path returns the output count without serializing the body.
    let output_count = output_count_of(&state, &txid)?;

    // Precompute the mempool's prev_output → (spending_txid, vin)
    // index once per request so /outspends is O(N) rather than
    // O(N × mempool_size).
    let mempool_index = build_mempool_spent_index(&state);

    let mut out = Vec::with_capacity(output_count);
    for vout in 0..output_count as u32 {
        out.push(build_outspend(
            &state,
            &OutPoint { txid, vout },
            &mempool_index,
        )?);
    }
    Ok(Json(out))
}

pub async fn tx_merkle_proof(
    State(state): State<EsploraState>,
    Path(txid_s): Path<String>,
) -> EsploraResult<Json<MerkleProofJson>> {
    let txid = parse_txid(&txid_s)?;
    let (block, height, pos) = locate_confirmed_tx(&state, &txid)?;
    let txids: Vec<Txid> = block.txdata.iter().map(|t| t.compute_txid()).collect();
    let branch = compute_merkle_branch(&txids, pos);
    Ok(Json(MerkleProofJson {
        block_height: height,
        // Display-form (reversed) hex matches upstream Esplora.
        merkle: branch.iter().map(|h| h.to_string()).collect(),
        pos: pos as u32,
    }))
}

pub async fn tx_merkleblock_proof(
    State(state): State<EsploraState>,
    Path(txid_s): Path<String>,
) -> EsploraResult<String> {
    let txid = parse_txid(&txid_s)?;
    let (block, _height, _pos) = locate_confirmed_tx(&state, &txid)?;
    // Build a partial-merkle-tree containing only this txid. Encoded as
    // a P2P MerkleBlock and hex-stringified, matching upstream.
    let mb = MerkleBlock::from_block_with_predicate(&block, |t| *t == txid);
    Ok(hex::encode(serialize(&mb)))
}

// ── Helpers ────────────────────────────────────────────────────────

fn parse_txid(s: &str) -> EsploraResult<Txid> {
    s.parse::<Txid>()
        .map_err(|e| EsploraError::BadRequest(format!("bad txid: {e}")))
}

/// Build the (one-shot) `prev_output → (spending_txid, vin)` map across
/// the entire mempool. Used to surface mempool spends from /outspend
/// endpoints in O(1) per lookup. The clone-cost is bounded by mempool
/// size; for typical Esplora deployments this is well under a millisecond.
fn build_mempool_spent_index(state: &EsploraState) -> HashMap<OutPoint, (Txid, u32)> {
    let mut map: HashMap<OutPoint, (Txid, u32)> = HashMap::new();
    // Standard surface (design §6.1): acting class only — a quarantined spender
    // must not surface as the spending tx on /outspend, just as it is absent
    // from getrawmempool. (Infectious propagation means an acting tx can't have
    // a quarantined ancestor, so this never hides a legitimately-relayed spend.)
    for (txid, entry) in state.mempool.get_acting_entries() {
        for (vin, input) in entry.tx.input.iter().enumerate() {
            if input.previous_output.is_null() {
                continue;
            }
            // First-write-wins: a prevout can only be consumed once
            // legitimately, but in case of a transient inconsistency we
            // prefer the earliest-seen mempool entry's claim.
            map.entry(input.previous_output)
                .or_insert((txid, vin as u32));
        }
    }
    map
}

/// Render a single outspend response using the precomputed mempool
/// map. Used by `/outspends` so the N-output loop runs in O(N) total
/// instead of O(N × mempool_size).
fn build_outspend(
    state: &EsploraState,
    outpoint: &OutPoint,
    mempool_index: &HashMap<OutPoint, (Txid, u32)>,
) -> EsploraResult<OutspendJson> {
    if let Some(sref) = state.spend_index.spend_of(outpoint)? {
        return Ok(confirmed_outspend(state, &sref));
    }
    if let Some((spend_txid, vin)) = mempool_index.get(outpoint) {
        return Ok(mempool_outspend(*spend_txid, *vin));
    }
    Ok(unspent_outspend())
}

/// Single-shot outspend lookup. No precomputation: confirmed via
/// `SpendIndex` (O(log N) point lookup), mempool via the new cheap
/// `Mempool::spending_tx` accessor (O(1) outer + O(input_count) inner).
/// Replaces the former whole-mempool clone for `/tx/:txid/outspend/:vout`
/// (review M4).
fn build_outspend_one(
    state: &EsploraState,
    outpoint: &OutPoint,
) -> EsploraResult<OutspendJson> {
    if let Some(sref) = state.spend_index.spend_of(outpoint)? {
        return Ok(confirmed_outspend(state, &sref));
    }
    // Acting-only (design §6.1): a quarantined spender must not surface here,
    // matching the batched `/outspends` path (`build_mempool_spent_index`) and
    // `getrawmempool`. The single-output path previously used the unfiltered
    // `spending_tx`, so the two endpoints disagreed for the same outpoint.
    if let Some((spend_txid, vin)) = state.mempool.spending_tx_acting(outpoint) {
        return Ok(mempool_outspend(spend_txid, vin));
    }
    Ok(unspent_outspend())
}

fn confirmed_outspend(
    state: &EsploraState,
    sref: &node_index::SpendingRef,
) -> OutspendJson {
    let block_hash = state.chain.get_block_hash_by_height(sref.height);
    let block_time = block_hash
        .and_then(|h| state.chain.get_block_index(&h))
        .map(|e| e.header.time);
    OutspendJson {
        spent: true,
        txid: Some(sref.spending_txid.to_string()),
        vin: Some(sref.spending_vin),
        status: Some(TxStatusJson {
            confirmed: true,
            block_height: Some(sref.height),
            block_hash: block_hash.map(|h| h.to_string()),
            block_time,
        }),
    }
}

fn mempool_outspend(spend_txid: Txid, vin: u32) -> OutspendJson {
    OutspendJson {
        spent: true,
        txid: Some(spend_txid.to_string()),
        vin: Some(vin),
        status: Some(TxStatusJson {
            confirmed: false,
            block_height: None,
            block_hash: None,
            block_time: None,
        }),
    }
}

fn unspent_outspend() -> OutspendJson {
    OutspendJson {
        spent: false,
        txid: None,
        vin: None,
        status: None,
    }
}

/// Resolve a tx's output count without serializing the body. Confirmed
/// txs are looked up via txindex; mempool txs are read from the entry.
fn output_count_of(state: &EsploraState, txid: &Txid) -> EsploraResult<usize> {
    if state.chain.store_ref().has_txindex()
        && let Some(block_hash) = state.chain.store_ref().get_tx_location(txid)
        && let Some(block) = state.chain.get_block(&block_hash)
        && let Some(tx) = block.txdata.iter().find(|t| t.compute_txid() == *txid)
    {
        return Ok(tx.output.len());
    }
    if let Some(entry) = state.mempool.get(txid) {
        return Ok(entry.tx.output.len());
    }
    Err(EsploraError::NotFound)
}

/// Locate a confirmed tx and return its containing block + height +
/// position within the block's tx list. Used by both merkle-proof
/// endpoints. Returns 404 if the tx is unknown or unconfirmed (mempool
/// txs have no merkle proof until a block confirms them) — matches
/// upstream Esplora.
fn locate_confirmed_tx(
    state: &EsploraState,
    txid: &Txid,
) -> EsploraResult<(Block, u32, usize)> {
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
    let pos = block
        .txdata
        .iter()
        .position(|t| t.compute_txid() == *txid)
        .ok_or_else(|| {
            EsploraError::Internal(format!(
                "txindex points at {block_hash} but tx {txid} not present in block"
            ))
        })?;
    Ok((block, entry.height, pos))
}

/// Compute the merkle inclusion branch for `pos` within `txids`,
/// using Bitcoin's double-sha256 pairing rule (odd-out duplication).
/// Returns the bottom-up sibling sequence — the same shape upstream
/// Esplora's `merkle-proof` endpoint exposes.
fn compute_merkle_branch(txids: &[Txid], pos: usize) -> Vec<TxMerkleNode> {
    if txids.is_empty() || pos >= txids.len() {
        return Vec::new();
    }

    let mut current: Vec<[u8; 32]> = txids
        .iter()
        .map(|t| t.to_raw_hash().to_byte_array())
        .collect();
    let mut idx = pos;
    let mut branch: Vec<TxMerkleNode> = Vec::new();

    while current.len() > 1 {
        // Bitcoin convention: when the level has an odd count, the
        // last hash is duplicated before pairing.
        if !current.len().is_multiple_of(2) {
            current.push(*current.last().unwrap());
        }
        let sib = current[idx ^ 1];
        let sib_hash =
            bitcoin::hashes::sha256d::Hash::from_byte_array(sib);
        branch.push(TxMerkleNode::from_raw_hash(sib_hash));

        let mut next = Vec::with_capacity(current.len() / 2);
        for i in (0..current.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&current[i]);
            combined[32..].copy_from_slice(&current[i + 1]);
            let h = bitcoin::hashes::sha256d::Hash::hash(&combined);
            next.push(h.to_byte_array());
        }
        current = next;
        idx /= 2;
    }
    branch
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_txid(byte: u8) -> Txid {
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [byte; 32],
        ))
    }

    /// Single-tx block: branch is empty (the tx hash IS the root).
    #[test]
    fn merkle_branch_single_tx_is_empty() {
        let txids = vec![fixture_txid(1)];
        let b = compute_merkle_branch(&txids, 0);
        assert!(b.is_empty());
    }

    /// Two-tx block: branch is the sibling hash.
    #[test]
    fn merkle_branch_two_txs_returns_sibling() {
        let a = fixture_txid(1);
        let b = fixture_txid(2);
        let txids = vec![a, b];
        let path_a = compute_merkle_branch(&txids, 0);
        let path_b = compute_merkle_branch(&txids, 1);
        assert_eq!(path_a.len(), 1);
        assert_eq!(path_b.len(), 1);
        // a's sibling is b; b's sibling is a.
        assert_eq!(
            path_a[0].to_byte_array(),
            b.to_raw_hash().to_byte_array()
        );
        assert_eq!(
            path_b[0].to_byte_array(),
            a.to_raw_hash().to_byte_array()
        );
    }

    /// Three-tx block: odd-out path duplicates the last hash. Position 2
    /// (the odd one out) must pair with itself at the leaf level.
    #[test]
    fn merkle_branch_odd_out_duplicates_last() {
        let a = fixture_txid(1);
        let b = fixture_txid(2);
        let c = fixture_txid(3);
        let txids = vec![a, b, c];
        // Position 2 (c): sibling at leaf = c (duplicated). Then second
        // level has 2 nodes (hash(a,b), hash(c,c)); position 1 there →
        // sibling is hash(a,b).
        let path_c = compute_merkle_branch(&txids, 2);
        assert_eq!(path_c.len(), 2);
        assert_eq!(
            path_c[0].to_byte_array(),
            c.to_raw_hash().to_byte_array()
        );
    }

    /// Branches at heights computed are exactly `ceil(log2(n))` for
    /// well-formed trees. For 4 txs it's 2 levels.
    #[test]
    fn merkle_branch_length_log2() {
        let txids: Vec<Txid> = (1u8..=4).map(fixture_txid).collect();
        for pos in 0..4 {
            assert_eq!(
                compute_merkle_branch(&txids, pos).len(),
                2,
                "pos={pos}"
            );
        }
        let txids: Vec<Txid> = (1u8..=8).map(fixture_txid).collect();
        for pos in 0..8 {
            assert_eq!(
                compute_merkle_branch(&txids, pos).len(),
                3,
                "pos={pos}"
            );
        }
    }
}
