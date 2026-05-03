//! Address & scripthash handlers (Esplora plan PR 5).
//!
//! Endpoints (each implemented twice — once under `/address/:addr` and
//! once under `/scripthash/:hash` for parallel access):
//!
//! - `GET /address/:addr`                            → chain + mempool stats
//! - `GET /address/:addr/txs`                        → up to 50 mempool txs + first 25 confirmed
//! - `GET /address/:addr/txs/chain[/:last_seen_txid]` → 25 confirmed per page (newest first)
//! - `GET /address/:addr/txs/mempool`                → up to 50 mempool txs (no paging)
//! - `GET /address/:addr/utxo`                       → live UTXOs with status
//!
//! Wire shapes match upstream Esplora exactly. The `address` field in
//! `/address/:addr` is the literal string the client supplied; under
//! `/scripthash/:hash` it is the hex scripthash. This mirrors
//! blockstream.info / mempool.space.
//!
//! All endpoints require both `--addressindex=1` (the read surface) and
//! `--txindex=1` (to render confirmed tx bodies). The daemon
//! reconciliation in `satd/src/config.rs` auto-enables both when esplora
//! is on, so a misconfiguration would have been caught at startup; the
//! handlers still surface a 503 if either turns out disabled at request
//! time so an operator running a degraded configuration sees a clear
//! signal rather than partial data.

use std::collections::{BTreeSet, HashMap};

use axum::Json;
use axum::extract::{Path, State};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Network, OutPoint, Txid};
use node_index::{HistoryEntry, Scripthash, scripthash_of};
use serde::Serialize;

use crate::error::{EsploraError, EsploraResult};
use crate::handlers::tx::{TxJson, TxStatusJson, build_confirmed_tx_json};
use crate::state::EsploraState;

/// Esplora's mempool-txs cap. Matches the upstream contract: `/txs`
/// returns "up to 50 mempool transactions plus the first 25 confirmed";
/// `/txs/mempool` returns "up to 50 transactions (no paging)".
const MEMPOOL_TXS_LIMIT: usize = 50;
/// Esplora's confirmed-history page size — used by `/txs/chain` and
/// the confirmed slice of `/txs`.
const CONFIRMED_TXS_PAGE: usize = 25;

// ── JSON shapes ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct AddressStatsJson {
    pub tx_count: u64,
    pub funded_txo_count: u64,
    pub funded_txo_sum: u64,
    pub spent_txo_count: u64,
    pub spent_txo_sum: u64,
}

#[derive(Debug, Serialize)]
pub struct AddressInfoJson {
    /// The literal address string the client supplied (or the hex
    /// scripthash for the `/scripthash/:hash` family). Matches upstream
    /// Esplora's contract.
    pub address: String,
    pub chain_stats: AddressStatsJson,
    pub mempool_stats: AddressStatsJson,
}

#[derive(Debug, Serialize)]
pub struct UtxoJson {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: TxStatusJson,
}

// ── Address-string handlers ────────────────────────────────────────

pub async fn address_info(
    State(state): State<EsploraState>,
    Path(addr): Path<String>,
) -> EsploraResult<Json<AddressInfoJson>> {
    let sh = parse_address(&addr, state.network)?;
    Ok(Json(build_address_info(&state, &addr, &sh)?))
}

pub async fn address_txs_combined(
    State(state): State<EsploraState>,
    Path(addr): Path<String>,
) -> EsploraResult<Json<Vec<TxJson>>> {
    let sh = parse_address(&addr, state.network)?;
    Ok(Json(build_combined_txs(&state, &sh)?))
}

pub async fn address_txs_chain(
    State(state): State<EsploraState>,
    Path(addr): Path<String>,
) -> EsploraResult<Json<Vec<TxJson>>> {
    let sh = parse_address(&addr, state.network)?;
    Ok(Json(build_chain_txs(&state, &sh, None)?))
}

pub async fn address_txs_chain_paged(
    State(state): State<EsploraState>,
    Path((addr, last_seen)): Path<(String, String)>,
) -> EsploraResult<Json<Vec<TxJson>>> {
    let sh = parse_address(&addr, state.network)?;
    let last_seen = parse_txid(&last_seen)?;
    Ok(Json(build_chain_txs(&state, &sh, Some(last_seen))?))
}

pub async fn address_txs_mempool(
    State(state): State<EsploraState>,
    Path(addr): Path<String>,
) -> EsploraResult<Json<Vec<TxJson>>> {
    let sh = parse_address(&addr, state.network)?;
    Ok(Json(build_mempool_txs(&state, &sh)?))
}

pub async fn address_utxo(
    State(state): State<EsploraState>,
    Path(addr): Path<String>,
) -> EsploraResult<Json<Vec<UtxoJson>>> {
    let sh = parse_address(&addr, state.network)?;
    Ok(Json(build_utxos(&state, &sh)?))
}

// ── Scripthash handlers (parallel set) ─────────────────────────────

pub async fn scripthash_info(
    State(state): State<EsploraState>,
    Path(hash): Path<String>,
) -> EsploraResult<Json<AddressInfoJson>> {
    let sh = parse_scripthash(&hash)?;
    Ok(Json(build_address_info(&state, &hash, &sh)?))
}

pub async fn scripthash_txs_combined(
    State(state): State<EsploraState>,
    Path(hash): Path<String>,
) -> EsploraResult<Json<Vec<TxJson>>> {
    let sh = parse_scripthash(&hash)?;
    Ok(Json(build_combined_txs(&state, &sh)?))
}

pub async fn scripthash_txs_chain(
    State(state): State<EsploraState>,
    Path(hash): Path<String>,
) -> EsploraResult<Json<Vec<TxJson>>> {
    let sh = parse_scripthash(&hash)?;
    Ok(Json(build_chain_txs(&state, &sh, None)?))
}

pub async fn scripthash_txs_chain_paged(
    State(state): State<EsploraState>,
    Path((hash, last_seen)): Path<(String, String)>,
) -> EsploraResult<Json<Vec<TxJson>>> {
    let sh = parse_scripthash(&hash)?;
    let last_seen = parse_txid(&last_seen)?;
    Ok(Json(build_chain_txs(&state, &sh, Some(last_seen))?))
}

pub async fn scripthash_txs_mempool(
    State(state): State<EsploraState>,
    Path(hash): Path<String>,
) -> EsploraResult<Json<Vec<TxJson>>> {
    let sh = parse_scripthash(&hash)?;
    Ok(Json(build_mempool_txs(&state, &sh)?))
}

pub async fn scripthash_utxo(
    State(state): State<EsploraState>,
    Path(hash): Path<String>,
) -> EsploraResult<Json<Vec<UtxoJson>>> {
    let sh = parse_scripthash(&hash)?;
    Ok(Json(build_utxos(&state, &sh)?))
}

// ── Parsing ────────────────────────────────────────────────────────

fn parse_address(s: &str, network: Network) -> EsploraResult<Scripthash> {
    let unchecked: Address<NetworkUnchecked> = s
        .parse()
        .map_err(|e| EsploraError::BadRequest(format!("bad address '{s}': {e}")))?;
    let address = unchecked
        .require_network(network)
        .map_err(|e| {
            EsploraError::BadRequest(format!("address '{s}' not valid for network: {e}"))
        })?;
    Ok(scripthash_of(&address.script_pubkey()))
}

fn parse_scripthash(s: &str) -> EsploraResult<Scripthash> {
    let bytes = hex::decode(s)
        .map_err(|e| EsploraError::BadRequest(format!("bad scripthash hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(EsploraError::BadRequest(format!(
            "scripthash must be 32 bytes (64 hex chars); got {}",
            bytes.len()
        )));
    }
    let mut sh = [0u8; 32];
    sh.copy_from_slice(&bytes);
    Ok(sh)
}

fn parse_txid(s: &str) -> EsploraResult<Txid> {
    s.parse::<Txid>()
        .map_err(|e| EsploraError::BadRequest(format!("bad txid: {e}")))
}

// ── Stats / info ───────────────────────────────────────────────────

fn build_address_info(
    state: &EsploraState,
    label: &str,
    sh: &Scripthash,
) -> EsploraResult<AddressInfoJson> {
    let chain_stats = build_chain_stats(state, sh)?;
    let mempool_stats = build_mempool_stats(state, sh);
    Ok(AddressInfoJson {
        address: label.to_string(),
        chain_stats,
        mempool_stats,
    })
}

/// Chain stats — derived purely from confirmed-history rows.
fn build_chain_stats(
    state: &EsploraState,
    sh: &Scripthash,
) -> EsploraResult<AddressStatsJson> {
    let history = state.address_index.confirmed_history(sh)?;
    Ok(compute_chain_stats_from_history(&history))
}

/// Pure history-reduction helper, exposed so unit tests can hit it
/// with synthetic rows. Two-pass:
///
/// 1. Collect every funding row's amount + counts.
/// 2. Resolve spending rows against the complete funding map.
///
/// The two-pass form is order-independent. A single pass would
/// undercount `spent_txo_sum` for same-block parent/child spends
/// where the child's txid sorts before the parent's — `confirmed_history`
/// orders by `(height, txid_string, is_spending)`, not by topological
/// order within a block (review M1).
fn compute_chain_stats_from_history(history: &[HistoryEntry]) -> AddressStatsJson {
    let mut tx_set: BTreeSet<Txid> = BTreeSet::new();
    let mut funded_txo_count: u64 = 0;
    let mut funded_txo_sum: u64 = 0;
    let mut spent_txo_count: u64 = 0;
    let mut spent_txo_sum: u64 = 0;
    let mut funding_amount: HashMap<(Txid, u32), u64> = HashMap::new();

    // Pass 1: every funding row contributes to funded_* and to the
    // (txid, vout) → amount lookup map.
    for entry in history {
        if let HistoryEntry::Funding {
            txid,
            vout,
            amount_sat,
            ..
        } = entry
        {
            funded_txo_count = funded_txo_count.saturating_add(1);
            funded_txo_sum = funded_txo_sum.saturating_add(*amount_sat);
            funding_amount.insert((*txid, *vout), *amount_sat);
            tx_set.insert(*txid);
        }
    }

    // Pass 2: spending rows count + look up the prev_outpoint's amount.
    // Now safe regardless of intra-block parent/child txid ordering.
    for entry in history {
        if let HistoryEntry::Spending {
            txid,
            prev_outpoint,
            ..
        } = entry
        {
            spent_txo_count = spent_txo_count.saturating_add(1);
            if let Some(&amt) =
                funding_amount.get(&(prev_outpoint.txid, prev_outpoint.vout))
            {
                spent_txo_sum = spent_txo_sum.saturating_add(amt);
            }
            tx_set.insert(*txid);
        }
    }

    AddressStatsJson {
        tx_count: tx_set.len() as u64,
        funded_txo_count,
        funded_txo_sum,
        spent_txo_count,
        spent_txo_sum,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::OutPoint;

    fn fixture_txid(byte: u8) -> Txid {
        use bitcoin::hashes::Hash as _;
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [byte; 32],
        ))
    }

    /// Review M1: same-block parent funds + child spends. The child's
    /// txid sorts BEFORE the parent's (lower byte). With a naive
    /// single-pass implementation, the spending row would be processed
    /// first and `spent_txo_sum` would miss the funding lookup.
    #[test]
    fn chain_stats_handles_child_spend_before_parent_funding_in_history() {
        let parent = fixture_txid(0x99);
        let child = fixture_txid(0x11);
        // Parent funds the address with 5000 sat. Child spends parent's
        // vout 0 (immediately, same block, height 100). Both rows touch
        // the same scripthash — the parent via funding, the child via
        // spending the outpoint that the parent created.
        let history = vec![
            // Spending row appears first because child txid (0x11) <
            // parent txid (0x99) in lexicographic byte-order.
            HistoryEntry::Spending {
                height: 100,
                txid: child,
                vin: 0,
                prev_outpoint: OutPoint {
                    txid: parent,
                    vout: 0,
                },
            },
            HistoryEntry::Funding {
                height: 100,
                txid: parent,
                vout: 0,
                amount_sat: 5000,
            },
        ];

        let stats = compute_chain_stats_from_history(&history);
        assert_eq!(stats.funded_txo_count, 1);
        assert_eq!(stats.funded_txo_sum, 5000);
        assert_eq!(stats.spent_txo_count, 1);
        assert_eq!(
            stats.spent_txo_sum, 5000,
            "spent_txo_sum must be order-independent (review M1)"
        );
        // tx_count: parent + child = 2 distinct txids.
        assert_eq!(stats.tx_count, 2);
    }

    #[test]
    fn chain_stats_unspent_funding_only() {
        let txid = fixture_txid(0xaa);
        let history = vec![HistoryEntry::Funding {
            height: 1,
            txid,
            vout: 0,
            amount_sat: 1000,
        }];
        let stats = compute_chain_stats_from_history(&history);
        assert_eq!(stats.funded_txo_count, 1);
        assert_eq!(stats.funded_txo_sum, 1000);
        assert_eq!(stats.spent_txo_count, 0);
        assert_eq!(stats.spent_txo_sum, 0);
        assert_eq!(stats.tx_count, 1);
    }

    #[test]
    fn chain_stats_empty_history() {
        let stats = compute_chain_stats_from_history(&[]);
        assert_eq!(stats.funded_txo_count, 0);
        assert_eq!(stats.funded_txo_sum, 0);
        assert_eq!(stats.spent_txo_count, 0);
        assert_eq!(stats.spent_txo_sum, 0);
        assert_eq!(stats.tx_count, 0);
    }
}

/// Mempool stats — derived on demand from the mempool index's tx-set
/// for `sh`. For each tx in that set we re-resolve its outputs (funding
/// against `sh`) and inputs (spending against `sh`) using the chain
/// UTXO set + mempool ancestors, mirroring the address-index's mempool
/// resolver. Bounded by `mempool-txs-touching-sh × tx-input/output-count`.
fn build_mempool_stats(state: &EsploraState, sh: &Scripthash) -> AddressStatsJson {
    let entries = state.address_index.mempool_history(sh);

    let mut tx_count: u64 = 0;
    let mut funded_txo_count: u64 = 0;
    let mut funded_txo_sum: u64 = 0;
    let mut spent_txo_count: u64 = 0;
    let mut spent_txo_sum: u64 = 0;

    for e in entries {
        let Some(entry) = state.mempool.get(&e.txid) else {
            continue;
        };
        let mut touched = false;
        for out in &entry.tx.output {
            if &scripthash_of(&out.script_pubkey) == sh {
                funded_txo_count = funded_txo_count.saturating_add(1);
                funded_txo_sum = funded_txo_sum.saturating_add(out.value.to_sat());
                touched = true;
            }
        }
        for input in &entry.tx.input {
            if input.previous_output.is_null() {
                continue;
            }
            if let Some(coin) = state.chain.get_coin(&input.previous_output) {
                if &scripthash_of(&coin.script_pubkey) == sh {
                    spent_txo_count = spent_txo_count.saturating_add(1);
                    spent_txo_sum = spent_txo_sum.saturating_add(coin.amount);
                    touched = true;
                }
            } else if let Some(parent) = state.mempool.get(&input.previous_output.txid)
                && let Some(parent_out) =
                    parent.tx.output.get(input.previous_output.vout as usize)
                && &scripthash_of(&parent_out.script_pubkey) == sh
            {
                spent_txo_count = spent_txo_count.saturating_add(1);
                spent_txo_sum = spent_txo_sum.saturating_add(parent_out.value.to_sat());
                touched = true;
            }
        }
        if touched {
            tx_count = tx_count.saturating_add(1);
        }
    }

    AddressStatsJson {
        tx_count,
        funded_txo_count,
        funded_txo_sum,
        spent_txo_count,
        spent_txo_sum,
    }
}

// ── Tx pagination ──────────────────────────────────────────────────

/// One distinct confirmed tx touching `sh`, ordered by (height, txid).
#[derive(Debug, Clone, Copy)]
struct ConfirmedTxRef {
    txid: Txid,
    height: u32,
}

/// Walk the confirmed history once and reduce to the set of distinct
/// (height, txid) pairs. Returned ascending by `(height, txid)`; callers
/// reverse for newest-first display.
fn distinct_confirmed_txs(history: &[HistoryEntry]) -> Vec<ConfirmedTxRef> {
    let mut seen: BTreeSet<(u32, Txid)> = BTreeSet::new();
    for entry in history {
        seen.insert((entry.height(), entry.txid()));
    }
    seen.into_iter()
        .map(|(height, txid)| ConfirmedTxRef { txid, height })
        .collect()
}

/// `/address/:addr/txs` and `/scripthash/:hash/txs` — combined: up to 50
/// mempool txs (newest first by mempool-touched order, which is the
/// HashSet iteration order — Esplora's contract is "up to 50", not a
/// strict ordering, but we prefer a stable order for clients). Followed
/// by the first 25 confirmed (newest first).
fn build_combined_txs(
    state: &EsploraState,
    sh: &Scripthash,
) -> EsploraResult<Vec<TxJson>> {
    let mut out = build_mempool_txs(state, sh)?;
    out.extend(build_chain_txs(state, sh, None)?);
    Ok(out)
}

/// `/address/:addr/txs/chain[/:last_seen_txid]` — confirmed txs only,
/// newest first, 25 per page. With `last_seen_txid` the page starts
/// strictly after that txid in the descending list — i.e. the next 25
/// confirmed txs older than it. An unknown `last_seen_txid` yields an
/// empty page (the upstream contract: clients use the previous page's
/// final txid; "unknown" only happens if the index changed under them
/// or they hand-crafted a request).
fn build_chain_txs(
    state: &EsploraState,
    sh: &Scripthash,
    last_seen: Option<Txid>,
) -> EsploraResult<Vec<TxJson>> {
    let history = state.address_index.confirmed_history(sh)?;
    let mut txs = distinct_confirmed_txs(&history);
    txs.reverse(); // newest first

    let start = match last_seen {
        None => 0,
        Some(tx) => match txs.iter().position(|t| t.txid == tx) {
            Some(p) => p + 1,
            None => return Ok(Vec::new()),
        },
    };
    let end = start
        .saturating_add(CONFIRMED_TXS_PAGE)
        .min(txs.len());

    let page = &txs[start..end];
    let mut out = Vec::with_capacity(page.len());
    for t in page {
        // Render full Esplora-shape tx JSON. Requires txindex (to find
        // the containing block); if disabled, surface as 503 — see
        // module-level note. The reconciliation in `satd/src/config.rs`
        // auto-enables txindex when esplora is on, so this is a defense
        // against operator overrides that won't normally fire.
        let json = build_confirmed_tx_json(state, &t.txid, t.height)?;
        out.push(json);
    }
    Ok(out)
}

/// `/address/:addr/txs/mempool` — up to 50 mempool txs, no paging. The
/// upstream contract doesn't pin a specific ordering; we return the
/// HashSet iteration order trimmed to the cap. Clients that need
/// strict ordering should call `/txs/chain` after a confirmation.
fn build_mempool_txs(
    state: &EsploraState,
    sh: &Scripthash,
) -> EsploraResult<Vec<TxJson>> {
    let mut entries = state.address_index.mempool_history(sh);
    if entries.len() > MEMPOOL_TXS_LIMIT {
        entries.truncate(MEMPOOL_TXS_LIMIT);
    }
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        if let Some(entry) = state.mempool.get(&e.txid) {
            // Mempool tx → no ConfirmedLocation; rendered with
            // `confirmed: false`. We re-use the lower-level builder
            // exposed by tx.rs.
            let json = crate::handlers::tx::build_mempool_tx_json(state, &entry.tx)?;
            out.push(json);
        }
    }
    Ok(out)
}

// ── UTXO list ──────────────────────────────────────────────────────

/// `/address/:addr/utxo` — live UTXOs spendable by this address.
///
/// Three components:
///
/// 1. Confirmed UTXOs from the address index (`AddressIndex::utxos`)
///    that are not also spent by an unconfirmed mempool tx.
/// 2. Mempool funding outputs (this address received a deposit in an
///    unconfirmed tx) that are not themselves spent in the mempool.
///
/// Wallet-correctness: a confirmed UTXO with a mempool spend is NOT
/// listed (review H2). Listing it would let clients double-spend the
/// outpoint by signing a fresh tx against the same input.
fn build_utxos(
    state: &EsploraState,
    sh: &Scripthash,
) -> EsploraResult<Vec<UtxoJson>> {
    // Build the mempool-spent-outpoint set up front so we can filter
    // both confirmed and mempool-created UTXOs against it. The set
    // covers every prev_output of every mempool tx touching `sh`.
    let mempool_entries = state.address_index.mempool_history(sh);
    let mempool_spends: std::collections::HashSet<OutPoint> =
        collect_mempool_spent_outpoints(state, &mempool_entries);

    let utxos = state.address_index.utxos(sh)?;
    let mut out = Vec::with_capacity(utxos.len());
    for u in utxos {
        let outpoint = OutPoint {
            txid: u.txid,
            vout: u.vout,
        };
        // Skip confirmed UTXOs already consumed by an unconfirmed
        // mempool tx (review H2).
        if mempool_spends.contains(&outpoint) {
            continue;
        }
        let block_hash = state.chain.get_block_hash_by_height(u.height);
        let block_time = block_hash
            .and_then(|h| state.chain.get_block_index(&h))
            .map(|entry| entry.header.time);
        out.push(UtxoJson {
            txid: u.txid.to_string(),
            vout: u.vout,
            value: u.amount_sat,
            status: TxStatusJson {
                confirmed: true,
                block_height: Some(u.height),
                block_hash: block_hash.map(|h| h.to_string()),
                block_time,
            },
        });
    }

    // Mempool funding outputs: walk the mempool history for sh, scan
    // each tx's outputs for ones whose script hashes to sh and whose
    // resulting OutPoint isn't already spent (within the mempool).
    for e in mempool_entries {
        let Some(entry) = state.mempool.get(&e.txid) else {
            continue;
        };
        for (i, output) in entry.tx.output.iter().enumerate() {
            if &scripthash_of(&output.script_pubkey) != sh {
                continue;
            }
            let outpoint = OutPoint {
                txid: e.txid,
                vout: i as u32,
            };
            if mempool_spends.contains(&outpoint) {
                continue;
            }
            out.push(UtxoJson {
                txid: e.txid.to_string(),
                vout: i as u32,
                value: output.value.to_sat(),
                status: TxStatusJson {
                    confirmed: false,
                    block_height: None,
                    block_hash: None,
                    block_time: None,
                },
            });
        }
    }

    Ok(out)
}

fn collect_mempool_spent_outpoints(
    state: &EsploraState,
    entries: &[node_index::MempoolHistoryEntry],
) -> std::collections::HashSet<OutPoint> {
    let mut out = std::collections::HashSet::new();
    for e in entries {
        if let Some(entry) = state.mempool.get(&e.txid) {
            for input in &entry.tx.input {
                if input.previous_output.is_null() {
                    continue;
                }
                out.insert(input.previous_output);
            }
        }
    }
    out
}
