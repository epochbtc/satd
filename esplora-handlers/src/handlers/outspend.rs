//! Outspend + merkle-proof handlers (Esplora plan PR 6).
//!
//! Endpoints:
//! - `GET /tx/:txid/outspend/:vout`        → single outspend
//! - `GET /tx/:txid/outspends`             → array of outspends, one per output
//! - `GET /tx/:txid/merkle-proof`          → JSON merkle path
//! - `GET /tx/:txid/merkleblock-proof`     → hex-encoded MerkleBlock
//!
//! Outspend backed by `SpendIndex::spend_of` for confirmed-side lookups
//! plus the mempool's spends index for unconfirmed spends. Merkle paths
//! computed directly from block txids using the standard Bitcoin
//! double-sha256 pairing rule (odd-out duplication).

use std::collections::HashMap;

use axum::Json;
use axum::Extension;
use axum::extract::{Path, State};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::merkle_tree::MerkleBlock;
use bitcoin::{OutPoint, TxMerkleNode, Txid};
use node::storage::Store;
use node::storage::opreturn_strip::StoredBlock;
use serde::Serialize;

use crate::chain_tip::Pin;
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
    Extension(pin): Extension<Pin>,
    Path((txid_s, vout)): Path<(String, u32)>,
) -> EsploraResult<Json<OutspendJson>> {
    let txid = parse_txid(&txid_s)?;
    // Reject unknown txids and out-of-range vouts up front (review H1).
    // Without this check, every malformed request fell through to the
    // bottom of build_outspend and returned `200 {spent:false}`, which
    // looks indistinguishable from a real unspent outpoint.
    let output_count = output_count_of(&state, &pin, &txid)?;
    if vout as usize >= output_count {
        return Err(EsploraError::NotFound);
    }
    let outpoint = OutPoint { txid, vout };
    Ok(Json(build_outspend_one(&state, &pin, &outpoint)?))
}

pub async fn tx_outspends(
    State(state): State<EsploraState>,
    Extension(pin): Extension<Pin>,
    Path(txid_s): Path<String>,
) -> EsploraResult<Json<Vec<OutspendJson>>> {
    let txid = parse_txid(&txid_s)?;

    // Determine the tx's output count. For confirmed txs we look up the
    // tx body via txindex; for mempool txs we read it from the entry.
    // Either path returns the output count without serializing the body.
    let output_count = output_count_of(&state, &pin, &txid)?;

    // The mempool spender of each output, from the mempool's own spends
    // index under one lock: O(outputs), with nothing copied. Building a
    // whole-mempool map here copied every mempool transaction per request,
    // on a route anyone who can reach Esplora may call.
    let mempool_index = if pin.mempool {
        state.mempool.acting_spenders_of_outputs(&txid, output_count as u32)
    } else {
        HashMap::new()
    };

    // Confirmed spends for the whole transaction in one prefix scan.
    // The spend index keys on the funding transaction's ordinal, so all
    // of a transaction's spends sit together; asking per output would
    // re-derive that ordinal from the txid N times and do N point reads.
    let confirmed: HashMap<u32, node_index::SpendingRef> =
        state.spend_index.spends_of_tx(&txid)?.into_iter().collect();

    let mut out = Vec::with_capacity(output_count);
    for vout in 0..output_count as u32 {
        out.push(match confirmed.get(&vout) {
            Some(sref) => confirmed_outspend(&state, &pin, sref),
            None => build_outspend(&state, &pin, &OutPoint { txid, vout }, mempool_index.get(&vout))?,
        });
    }
    Ok(Json(out))
}

pub async fn tx_merkle_proof(
    State(state): State<EsploraState>,
    Extension(pin): Extension<Pin>,
    Path(txid_s): Path<String>,
) -> EsploraResult<Json<MerkleProofJson>> {
    let txid = parse_txid(&txid_s)?;
    let (block, height, pos) = locate_confirmed_tx(&state, &pin, &txid)?;
    let txids = block.txids();
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
    Extension(pin): Extension<Pin>,
    Path(txid_s): Path<String>,
) -> EsploraResult<String> {
    let txid = parse_txid(&txid_s)?;
    let (block, _height, _pos) = locate_confirmed_tx(&state, &pin, &txid)?;
    // Build a partial-merkle-tree containing only this txid. Encoded as
    // a P2P MerkleBlock and hex-stringified, matching upstream.
    // From the header and the stored txids, which a stripped block's
    // strip record holds.
    let mb = MerkleBlock::from_header_txids_with_predicate(&block.block.header, &block.txids(), |t| {
        *t == txid
    });
    Ok(hex::encode(serialize(&mb)))
}

// ── Helpers ────────────────────────────────────────────────────────

fn parse_txid(s: &str) -> EsploraResult<Txid> {
    s.parse::<Txid>()
        .map_err(|e| EsploraError::BadRequest(format!("bad txid: {e}")))
}

/// Render a single outspend response, given the output's acting mempool
/// spender if it has one. Used by `/outspends`, whose spenders come from
/// one [`node::mempool::Mempool::acting_spenders_of_outputs`] read.
fn build_outspend(
    state: &EsploraState,
    pin: &Pin,
    outpoint: &OutPoint,
    mempool_spender: Option<&(Txid, u32)>,
) -> EsploraResult<OutspendJson> {
    if let Some(sref) = state.spend_index.spend_of(outpoint)? {
        return Ok(confirmed_outspend(state, pin, &sref));
    }
    // Empty as of a block (`?asof=`).
    if let Some((spend_txid, vin)) = mempool_spender {
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
    pin: &Pin,
    outpoint: &OutPoint,
) -> EsploraResult<OutspendJson> {
    if let Some(sref) = state.spend_index.spend_of(outpoint)? {
        return Ok(confirmed_outspend(state, pin, &sref));
    }
    // Acting-only (design §6.1): a quarantined spender must not surface here,
    // matching the batched `/outspends` path (`acting_spenders_of_outputs`) and
    // `getrawmempool`. The single-output path previously used the unfiltered
    // `spending_tx`, so the two endpoints disagreed for the same outpoint.
    if !pin.mempool {
        return Ok(unspent_outspend());
    }
    if let Some((spend_txid, vin)) = state.mempool.spending_tx_acting(outpoint) {
        return Ok(mempool_outspend(spend_txid, vin));
    }
    Ok(unspent_outspend())
}

/// A spend the spend index holds. One confirmed above the pinned tip
/// confirmed while the request ran: as of the pin it was a mempool spend.
/// As of a block (`?asof=`), with no mempool, the output was unspent.
fn confirmed_outspend(
    state: &EsploraState,
    pin: &Pin,
    sref: &node_index::SpendingRef,
) -> OutspendJson {
    if !pin.covers(sref.height) {
        return if pin.mempool {
            mempool_outspend(sref.spending_txid, sref.spending_vin)
        } else {
            unspent_outspend()
        };
    }
    let block_hash = pin.hash_at_height(&state.chain, sref.height);
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
///
/// As of a block (`?asof=`) a transaction only in the mempool is unknown. One
/// the txindex holds is known at any height, as rbitcoin answers: its
/// outputs are unspent until a spend at or below the pin.
fn output_count_of(state: &EsploraState, pin: &Pin, txid: &Txid) -> EsploraResult<usize> {
    if state.chain.store_ref().has_txindex()
        && let Some(block_hash) = state.chain.store_ref().get_tx_location(txid)
        && let Some(block) = state.chain.get_stored_block(&block_hash)
        && let Some(i) = block.txids().iter().position(|t| t == txid)
    {
        // A stripped transaction keeps every output, OP_RETURNs included.
        return Ok(block.block.txdata[i].output.len());
    }
    if pin.mempool
        && let Some(entry) = state.mempool.get(txid)
    {
        return Ok(entry.tx.output.len());
    }
    Err(EsploraError::NotFound)
}

/// Locate a confirmed tx and return its containing block + height +
/// position within the block's tx list. Used by both merkle-proof
/// endpoints. Returns 404 if the tx is unknown or unconfirmed (mempool
/// txs have no merkle proof until a block confirms them) — matches
/// upstream Esplora. The block is as stored: a stripped one still proves.
fn locate_confirmed_tx(
    state: &EsploraState,
    pin: &Pin,
    txid: &Txid,
) -> EsploraResult<(StoredBlock, u32, usize)> {
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
        .get_stored_block(&block_hash)
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
    // Confirmed above the pinned tip: unconfirmed as of the pin, and a
    // mempool transaction has no merkle proof.
    if !pin.covers(entry.height) {
        return Err(EsploraError::NotFound);
    }
    let pos = block
        .txids()
        .iter()
        .position(|t| t == txid)
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
