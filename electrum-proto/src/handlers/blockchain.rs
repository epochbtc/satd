//! `blockchain.*` method handlers.
//!
//! Read-side methods (`get_history`, `get_balance`, `listunspent`,
//! `headers.*`, `block.*`, `transaction.get*`) call directly into the
//! `node-index` traits + the `ElectrumExtras` adapter.
//!
//! Write-side method (`transaction.broadcast`) routes through
//! [`Mempool::accept_transaction`] — same path Esplora's `POST /tx`
//! endpoint takes.
//!
//! [`scripthash_subscribe`] returns the synchronous initial status
//! response. The push-notification side lives in PR-4
//! ([`crate::subscribe`]).

use bitcoin::Transaction;
use bitcoin::consensus::encode::{deserialize, serialize};
use serde_json::{Value, json};

use crate::dispatch::{require_array, require_array_range};
use crate::error::JsonRpcError;
use crate::merkle::compute_merkle_branch;
use crate::state::ElectrumState;
use crate::status::{compute_status_hash, status_hash_to_json};
use crate::types::{
    BalanceResponse, FeeHistogramEntry, GetMerkleResponse, HeadersResponse, HistoryEntry,
    ListUnspentEntry, ScripthashHex, TxidHex, merkle_node_to_hex,
};

// ── blockchain.headers.* ──────────────────────────────────────────

pub fn headers_subscribe(state: &ElectrumState) -> Result<Value, JsonRpcError> {
    // Synchronous initial response. PR-4 wires the actual
    // ChainEvent-driven notification side; PR-2 just gives the
    // current tip so a one-shot client gets a useful answer.
    let (height, header) = state.electrum_extras.tip();
    Ok(json!({
        "height": height,
        "hex": hex::encode(serialize(&header)),
    }))
}

pub fn headers_get(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    let arr = require_array(&params, 1, "blockchain.headers.get")?;
    let height = parse_height(&arr[0])?;
    let header = state
        .electrum_extras
        .header_at(height)
        .ok_or_else(|| JsonRpcError::invalid_params(format!("no header at height {height}")))?;
    Ok(json!({
        "height": height,
        "hex": hex::encode(serialize(&header)),
    }))
}

// ── blockchain.block.* ────────────────────────────────────────────

pub fn block_header(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    // `(height, [cp_height])` — we accept the cp_height arg for
    // protocol compatibility but ignore it (no checkpoint-proof
    // support in v1; the caller gets the raw header alone).
    let arr = require_array_range(&params, 1, 2, "blockchain.block.header")?;
    let height = parse_height(&arr[0])?;
    let header = state
        .electrum_extras
        .header_at(height)
        .ok_or_else(|| JsonRpcError::invalid_params(format!("no header at height {height}")))?;
    Ok(Value::String(hex::encode(serialize(&header))))
}

pub fn block_headers(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    // `(start_height, count, [cp_height])`
    let arr = require_array_range(&params, 2, 3, "blockchain.block.headers")?;
    let start = parse_height(&arr[0])?;
    let count_req = parse_u32(&arr[1], "count")?;
    let max = state.config.max_headers_per_request;
    let want = count_req.min(max);

    // Build the concatenated raw-header hex up to the tip, returning
    // however many we actually got (`count` may be < requested if
    // start runs past tip).
    let mut hex_buf = String::new();
    let mut got = 0u32;
    for h in start..start.saturating_add(want) {
        match state.electrum_extras.header_at(h) {
            Some(header) => {
                hex_buf.push_str(&hex::encode(serialize(&header)));
                got += 1;
            }
            None => break,
        }
    }

    let resp = HeadersResponse {
        count: got,
        hex: hex_buf,
        max,
    };
    Ok(serde_json::to_value(&resp).unwrap())
}

// ── blockchain.scripthash.* ───────────────────────────────────────

pub fn scripthash_get_history(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    let sh = parse_scripthash(&params, "blockchain.scripthash.get_history")?;
    let confirmed = state
        .address_index
        .confirmed_history(&sh.0)
        .map_err(JsonRpcError::from_index)?;

    if confirmed.len() > state.config.max_history_entries {
        return Err(JsonRpcError::history_too_large(
            state.config.max_history_entries,
        ));
    }

    // Dedup confirmed rows by `(height, txid)` — Electrum reports one
    // history entry per distinct tx touching the scripthash, regardless
    // of whether the tx funded + spent it in the same block. Order:
    // ascending by `(height, txid)`.
    let mut pairs: Vec<(u32, bitcoin::Txid)> =
        confirmed.iter().map(|e| (e.height(), e.txid())).collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    pairs.dedup();

    let mut out: Vec<HistoryEntry> = pairs
        .into_iter()
        .map(|(h, t)| HistoryEntry {
            height: h as i64,
            tx_hash: TxidHex(t),
            fee: None,
        })
        .collect();

    // Mempool entries come last, in protocol-canonical "txid order"
    // (which matches the ascending-txid order our mempool index
    // produces today).
    let mempool = state.address_index.mempool_history(&sh.0);
    let mut mp_txids: Vec<bitcoin::Txid> = mempool.into_iter().map(|m| m.txid).collect();
    mp_txids.sort();
    for t in mp_txids {
        // We don't compute the unconfirmed fee in v1; Electrum allows
        // omitting `fee` on unconfirmed entries (the field is documented
        // as optional). PR-2 ships without it; PR-4 may add it once the
        // mempool delta path is wired through SpendIndex.
        out.push(HistoryEntry {
            height: 0,
            tx_hash: TxidHex(t),
            fee: None,
        });
    }

    Ok(serde_json::to_value(&out).unwrap())
}

pub fn scripthash_get_balance(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    let sh = parse_scripthash(&params, "blockchain.scripthash.get_balance")?;
    let (confirmed, unconfirmed) = state
        .address_index
        .balance(&sh.0)
        .map_err(JsonRpcError::from_index)?;
    Ok(serde_json::to_value(BalanceResponse {
        confirmed,
        unconfirmed,
    })
    .unwrap())
}

pub fn scripthash_listunspent(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    let sh = parse_scripthash(&params, "blockchain.scripthash.listunspent")?;
    let utxos = state
        .address_index
        .utxos(&sh.0)
        .map_err(JsonRpcError::from_index)?;

    // Walk funding rows in `(height, txid, vout)` order — already the
    // natural order of `utxos()` per the trait contract. Listunspent
    // is bounded by max_history_entries since it can't exceed it
    // (each UTXO descends from a funding row).
    if utxos.len() > state.config.max_history_entries {
        return Err(JsonRpcError::history_too_large(
            state.config.max_history_entries,
        ));
    }

    let out: Vec<ListUnspentEntry> = utxos
        .into_iter()
        .map(|u| ListUnspentEntry {
            height: u.height,
            tx_hash: TxidHex(u.txid),
            tx_pos: u.vout,
            value: u.amount_sat,
        })
        .collect();
    Ok(serde_json::to_value(&out).unwrap())
}

pub fn scripthash_get_mempool(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    let sh = parse_scripthash(&params, "blockchain.scripthash.get_mempool")?;
    let mempool = state.address_index.mempool_history(&sh.0);
    let mut txids: Vec<bitcoin::Txid> = mempool.into_iter().map(|m| m.txid).collect();
    txids.sort();
    let out: Vec<HistoryEntry> = txids
        .into_iter()
        .map(|t| HistoryEntry {
            height: 0,
            tx_hash: TxidHex(t),
            fee: None,
        })
        .collect();
    Ok(serde_json::to_value(&out).unwrap())
}

pub fn scripthash_get_first_use(
    state: &ElectrumState,
    params: Value,
) -> Result<Value, JsonRpcError> {
    let sh = parse_scripthash(&params, "blockchain.scripthash.get_first_use")?;
    let confirmed = state
        .address_index
        .confirmed_history(&sh.0)
        .map_err(JsonRpcError::from_index)?;
    let earliest = confirmed
        .iter()
        .min_by_key(|e| (e.height(), e.txid()))
        .map(|e| (e.height(), e.txid()));
    match earliest {
        Some((height, txid)) => {
            let block_hash = state
                .chain
                .get_block_hash_by_height(height)
                .map(|h| h.to_string())
                .unwrap_or_default();
            Ok(json!({
                "height": height,
                "block_hash": block_hash,
                "tx_hash": txid.to_string(),
            }))
        }
        None => Ok(Value::Null),
    }
}

pub fn scripthash_subscribe(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    let sh = parse_scripthash(&params, "blockchain.scripthash.subscribe")?;
    let h =
        compute_status_hash(state.address_index.as_ref(), sh).map_err(JsonRpcError::from_index)?;
    Ok(match status_hash_to_json(h) {
        Some(s) => Value::String(s),
        None => Value::Null,
    })
}

pub fn scripthash_unsubscribe(
    _state: &ElectrumState,
    params: Value,
) -> Result<Value, JsonRpcError> {
    // Validate the scripthash param to surface client-side errors,
    // even though PR-2 has no per-connection state to clean up. PR-4
    // wires the actual unsubscribe.
    let _sh = parse_scripthash(&params, "blockchain.scripthash.unsubscribe")?;
    Ok(Value::Bool(true))
}

// ── blockchain.transaction.* ──────────────────────────────────────

pub fn transaction_get(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    // `(txid, [verbose])` — verbose=true returns full json; we
    // return the hex-encoded raw tx in v1 (the bare-string variant).
    // verbose=true is rejected because the json shape we'd produce
    // would not match Bitcoin Core's `getrawtransaction verbose=1`
    // wire shape exactly, and a half-shaped lie is worse than a
    // protocol error the client can fall back from.
    let arr = require_array_range(&params, 1, 2, "blockchain.transaction.get")?;
    let txid = parse_txid_hex(&arr[0])?;
    let verbose = arr.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
    if verbose {
        return Err(JsonRpcError::invalid_params(
            "verbose mode is not supported by this server; use blockchain.transaction.get(txid)",
        ));
    }
    let raw = state
        .electrum_extras
        .raw_tx(&txid)
        .or_else(|| state.mempool.get(&txid).map(|entry| serialize(&entry.tx)))
        .ok_or_else(|| JsonRpcError::invalid_params(format!("tx not found: {txid}")))?;
    Ok(Value::String(hex::encode(raw)))
}

pub fn transaction_get_merkle(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    // `(txid, [height])` — `height` is optional and used only as a
    // sanity hint by some clients; we recompute the proof anyway.
    let arr = require_array_range(&params, 1, 2, "blockchain.transaction.get_merkle")?;
    let txid = parse_txid_hex(&arr[0])?;
    let proof = state.electrum_extras.tx_merkle(&txid).ok_or_else(|| {
        JsonRpcError::invalid_params(format!("tx {txid} is not confirmed or not indexed"))
    })?;
    let resp = GetMerkleResponse {
        merkle: proof
            .branch
            .iter()
            .map(|n| {
                // GetMerkleResponse uses TxidHex for hex display order.
                // Forge a TxidHex via the merkle node's display string.
                let s = merkle_node_to_hex(n);
                let txid: bitcoin::Txid =
                    s.parse().expect("merkle node display order is valid hex");
                TxidHex(txid)
            })
            .collect(),
        block_height: proof.height,
        pos: proof.position,
    };
    Ok(serde_json::to_value(&resp).unwrap())
}

pub fn transaction_broadcast(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    let arr = require_array(&params, 1, "blockchain.transaction.broadcast")?;
    let hex_str = arr[0]
        .as_str()
        .ok_or_else(|| JsonRpcError::invalid_params("broadcast expects a hex string"))?;
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| JsonRpcError::invalid_params(format!("bad hex: {e}")))?;
    let tx: Transaction =
        deserialize(&bytes).map_err(|e| JsonRpcError::invalid_params(format!("decode: {e}")))?;
    let txid = state
        .mempool
        .accept_transaction(tx, &state.chain, state.chain.script_verifier())
        .map_err(|e| JsonRpcError::new(1, format!("mempool reject: {e}")))?;
    Ok(Value::String(txid.to_string()))
}

pub fn transaction_id_from_pos(
    state: &ElectrumState,
    params: Value,
) -> Result<Value, JsonRpcError> {
    // `(height, tx_pos, [merkle])` — `merkle=true` adds the proof.
    let arr = require_array_range(&params, 2, 3, "blockchain.transaction.id_from_pos")?;
    let height = parse_height(&arr[0])?;
    let tx_pos = parse_u32(&arr[1], "tx_pos")?;
    let merkle = arr.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
    let txid = state
        .electrum_extras
        .txid_at_pos(height, tx_pos)
        .ok_or_else(|| {
            JsonRpcError::invalid_params(format!("no tx at height={height} pos={tx_pos}"))
        })?;
    if !merkle {
        return Ok(Value::String(txid.to_string()));
    }
    // merkle=true: include the branch alongside the txid.
    let block_hash = state
        .chain
        .get_block_hash_by_height(height)
        .ok_or_else(|| JsonRpcError::internal("height resolved txid but not block hash"))?;
    let block = state
        .chain
        .get_block(&block_hash)
        .ok_or_else(|| JsonRpcError::internal("block resolved hash but data missing"))?;
    let txids: Vec<bitcoin::Txid> = block.txdata.iter().map(|t| t.compute_txid()).collect();
    let branch = compute_merkle_branch(&txids, tx_pos as usize);
    let merkle_hex: Vec<String> = branch.iter().map(merkle_node_to_hex).collect();
    Ok(json!({
        "tx_hash": txid.to_string(),
        "merkle": merkle_hex,
    }))
}

// ── fees ──────────────────────────────────────────────────────────

pub fn estimatefee(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    let arr = require_array(&params, 1, "blockchain.estimatefee")?;
    let target = parse_u32(&arr[0], "num_blocks")?;
    let est = state.fee_estimator.estimate_fee(target);
    // Electrum returns BTC/kB or -1 if unknown. `estimate_fee` is
    // sat/kvB.
    Ok(match est {
        Some(sats_per_kvb) => json!((sats_per_kvb as f64) / 1.0e8),
        None => json!(-1.0),
    })
}

pub fn relayfee(state: &ElectrumState) -> Result<Value, JsonRpcError> {
    // Same conversion: sat/kvB → BTC/kB.
    let sats_per_kvb = state.mempool.policy().min_fee_rate;
    Ok(json!((sats_per_kvb as f64) / 1.0e8))
}

// ── helpers ───────────────────────────────────────────────────────

fn parse_scripthash(params: &Value, method: &str) -> Result<ScripthashHex, JsonRpcError> {
    let arr = require_array_range(params, 1, 1, method)?;
    let s = arr[0].as_str().ok_or_else(|| {
        JsonRpcError::invalid_params(format!("{method}: scripthash must be a string"))
    })?;
    let bytes =
        hex::decode(s).map_err(|e| JsonRpcError::invalid_params(format!("bad scripthash: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsonRpcError::invalid_params(
            "scripthash must be 64 hex chars (32 bytes)",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(ScripthashHex(arr))
}

fn parse_txid_hex(v: &Value) -> Result<bitcoin::Txid, JsonRpcError> {
    let s = v
        .as_str()
        .ok_or_else(|| JsonRpcError::invalid_params("txid must be a string"))?;
    s.parse::<bitcoin::Txid>()
        .map_err(|e| JsonRpcError::invalid_params(format!("bad txid: {e}")))
}

fn parse_height(v: &Value) -> Result<u32, JsonRpcError> {
    parse_u32(v, "height")
}

fn parse_u32(v: &Value, name: &str) -> Result<u32, JsonRpcError> {
    v.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| {
            JsonRpcError::invalid_params(format!("{name} must be a non-negative integer (≤ u32)"))
        })
}

// ── fee_histogram bucketer (used by mempool::get_fee_histogram) ───

pub(crate) const FEE_HIST_BUCKET_VBYTES: u64 = 50_000;

pub(crate) fn fee_histogram_buckets(
    entries: &[(u64 /* sat/vbyte */, u64 /* vbytes */)],
) -> Vec<FeeHistogramEntry> {
    let mut sorted: Vec<(u64, u64)> = entries.to_vec();
    // Descending fee-rate order per the protocol.
    sorted.sort_by(|a, b| b.0.cmp(&a.0));

    let mut out: Vec<FeeHistogramEntry> = Vec::new();
    let mut cur_size: u64 = 0;
    let mut last_rate: u64 = 0;
    for (rate, size) in sorted {
        cur_size += size;
        last_rate = rate;
        if cur_size >= FEE_HIST_BUCKET_VBYTES {
            out.push(FeeHistogramEntry(rate, cur_size));
            cur_size = 0;
        }
    }
    if cur_size > 0 {
        out.push(FeeHistogramEntry(last_rate, cur_size));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scripthash_accepts_64_hex_chars() {
        let p = json!(["aa".repeat(32)]);
        let sh = parse_scripthash(&p, "x").unwrap();
        assert_eq!(sh.0, [0xaa; 32]);
    }

    #[test]
    fn parse_scripthash_rejects_short() {
        let p = json!(["abc"]);
        assert!(parse_scripthash(&p, "x").is_err());
    }

    #[test]
    fn fee_histogram_descending_and_bucket_threshold() {
        // Two entries at high rate consume past the 50_000-vbyte bucket,
        // a third at low rate forms its own bucket.
        let entries = vec![(200u64, 60_000), (100, 10_000), (50, 30_000)];
        let buckets = fee_histogram_buckets(&entries);
        assert_eq!(buckets.len(), 2);
        // First bucket includes the 200 sat/vbyte entry that crossed
        // the threshold.
        assert_eq!(buckets[0].0, 200);
        assert!(buckets[0].1 >= FEE_HIST_BUCKET_VBYTES);
        // Second bucket holds the trailing low-rate entries.
        assert_eq!(buckets[1].0, 50);
    }

    #[test]
    fn fee_histogram_empty_input_yields_empty_output() {
        let buckets = fee_histogram_buckets(&[]);
        assert!(buckets.is_empty());
    }
}
