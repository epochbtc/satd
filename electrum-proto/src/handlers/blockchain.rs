//! `blockchain.*` method handlers.
//!
//! Read-side methods (`get_history`, `get_balance`, `listunspent`,
//! `headers.*`, `block.*`, `transaction.get*`) call directly into the
//! `node-index` traits + the `ElectrumExtras` adapter.
//!
//! Write-side methods (`transaction.broadcast`, `broadcast_package`)
//! route through the [`TxBroadcaster`](node::net::manager::TxBroadcaster)
//! injected on the state — accept into the mempool *and* announce to
//! peers, so the tx actually propagates — the same path Esplora's
//! `POST /tx` endpoint takes.
//!
//! [`scripthash_subscribe`] returns the synchronous initial status
//! response. The push-notification side lives in PR-4
//! ([`crate::subscribe`]).

use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::consensus::encode::{deserialize, serialize};
use node_index::scripthash_of;
use serde_json::{Value, json};

use crate::dispatch::{require_array, require_array_range};
use crate::error::JsonRpcError;
use crate::merkle::compute_merkle_branch;
use crate::state::ElectrumState;
use crate::status::{compute_status_hash, status_hash_to_json};
use crate::types::{
    BalanceResponse, FeeHistogramEntry, GetMerkleResponse, HeadersResponse, HistoryEntry,
    ListUnspentEntry, ScripthashHex, TxidHex, merkle_node_to_hex, parse_wire_scripthash,
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
        .ok_or_else(|| JsonRpcError::bad_request(format!("no header at height {height}")))?;
    Ok(json!({
        "height": height,
        "hex": hex::encode(serialize(&header)),
    }))
}

// ── blockchain.block.* ────────────────────────────────────────────

pub fn block_header(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    // `(height, [cp_height])` — `cp_height=0` (or omitted) returns
    // the raw 80-byte header. Nonzero `cp_height` requests a
    // checkpoint proof against block `cp_height`'s merkle root over
    // headers, which v1 doesn't implement. Per M3 (review round 1),
    // silently returning the proof-less response was a compatibility
    // hazard — clients that pass `cp_height` get a structured error
    // they can surface, instead of a half-shaped lie.
    let arr = require_array_range(&params, 1, 2, "blockchain.block.header")?;
    let height = parse_height(&arr[0])?;
    let cp_height = arr.get(1).map(|v| parse_u32(v, "cp_height")).transpose()?;
    if cp_height.unwrap_or(0) != 0 {
        return Err(JsonRpcError::bad_request(
            "checkpoint proof (nonzero cp_height) is not supported by this server",
        ));
    }
    let header = state
        .electrum_extras
        .header_at(height)
        .ok_or_else(|| JsonRpcError::bad_request(format!("no header at height {height}")))?;
    Ok(Value::String(hex::encode(serialize(&header))))
}

pub fn block_headers(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    // `(start_height, count, [cp_height])` — same `cp_height`
    // semantics as `block_header`. Reject nonzero values until
    // checkpoint proofs are implemented (M3, review round 1).
    let arr = require_array_range(&params, 2, 3, "blockchain.block.headers")?;
    let start = parse_height(&arr[0])?;
    let count_req = parse_u32(&arr[1], "count")?;
    let cp_height = arr.get(2).map(|v| parse_u32(v, "cp_height")).transpose()?;
    if cp_height.unwrap_or(0) != 0 {
        return Err(JsonRpcError::bad_request(
            "checkpoint proof (nonzero cp_height) is not supported by this server",
        ));
    }
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
    let cap = state.config.max_history_entries;

    // Round-3 review H1: ask the index for at most `cap + 1` DISTINCT
    // (height, txid) entries — the only wire-relevant dimension.
    // The address-index schema emits one row per matching output AND
    // per matching input, so a fixed raw-row duplicate factor is
    // unsound; a scripthash with many outputs per tx could see a raw
    // scan truncate before reaching `cap + 1` distinct entries and
    // silently return a partial history. The new helper streams
    // funding+spending in lockstep and dedupes inline so it stops
    // only at storage exhaustion or `cap + 1` distinct pairs.
    let pairs = state
        .address_index
        .confirmed_distinct_history_limited(&sh.0, cap.saturating_add(1))
        .map_err(JsonRpcError::from_index)?;

    if pairs.len() > cap {
        return Err(JsonRpcError::history_too_large(cap));
    }

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
    // produces today). Each carries a signed `height` per electrs's
    // `Height::as_i64`: `-1` if it spends an unconfirmed parent, `0`
    // otherwise. `fee` (sats) comes from the live mempool entry which
    // already pre-computes it at admission.
    //
    // Round-2 review M1: enforce the cap as we push — a scripthash
    // with `cap` confirmed entries plus any mempool entries previously
    // pushed past the cap silently.
    let mempool_pool = state.mempool.as_ref();
    let mempool = state.address_index.mempool_history(&sh.0);
    let mut mp_txids: Vec<bitcoin::Txid> = mempool.into_iter().map(|m| m.txid).collect();
    mp_txids.sort();
    for t in mp_txids {
        if out.len() >= cap {
            return Err(JsonRpcError::history_too_large(cap));
        }
        let (height, fee) = match mempool_pool.get(&t) {
            Some(entry) => {
                let h = if mempool_tx_has_unconfirmed_inputs(&entry.tx, mempool_pool) {
                    -1
                } else {
                    0
                };
                (h, Some(entry.fee))
            }
            None => (0, None), // raced with eviction; best-effort
        };
        out.push(HistoryEntry {
            height,
            tx_hash: TxidHex(t),
            fee,
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
    // Round-1 review M4: bound the index walk at cap + 1 UTXOs.
    let cap = state.config.max_history_entries;
    let utxos = state
        .address_index
        .utxos_limited(&sh.0, cap.saturating_add(1))
        .map_err(JsonRpcError::from_index)?;

    // Walk funding rows in `(height, txid, vout)` order — already the
    // natural order of `utxos_limited()` per the trait contract.
    // Listunspent is bounded by max_history_entries since it can't
    // exceed it (each UTXO descends from a funding row).
    if utxos.len() > cap {
        return Err(JsonRpcError::history_too_large(cap));
    }

    // Mempool merge — mirrors `romanz/electrs`'s `Unspent::build`:
    // start with confirmed UTXOs, drop any that are spent by a mempool
    // tx, then add mempool tx outputs that fund this scripthash and
    // aren't themselves yet spent in the mempool.
    let mempool = state.mempool.as_ref();
    let mut out: Vec<ListUnspentEntry> = utxos
        .into_iter()
        .filter(|u| {
            // Drop confirmed UTXOs whose outpoint is consumed by a
            // mempool spend — wallets shouldn't see them as spendable.
            mempool
                .spending_tx(&OutPoint {
                    txid: u.txid,
                    vout: u.vout,
                })
                .is_none()
        })
        .map(|u| ListUnspentEntry {
            height: u.height as i64,
            tx_hash: TxidHex(u.txid),
            tx_pos: u.vout,
            value: u.amount_sat,
        })
        .collect();

    // Mempool funding additions. Round-2 review M2: cap-check on
    // every push so a single unconfirmed tx with many outputs to
    // `sh`, or a flood of mempool funding txs, can't push the
    // response past `cap` entries.
    for mp in state.address_index.mempool_history(&sh.0) {
        let entry = match mempool.get(&mp.txid) {
            Some(e) => e,
            None => continue, // raced with eviction
        };
        let height: i64 = if mempool_tx_has_unconfirmed_inputs(&entry.tx, mempool) {
            -1
        } else {
            0
        };
        for (vout, txout) in entry.tx.output.iter().enumerate() {
            if scripthash_of(txout.script_pubkey.as_script()) != sh.0 {
                continue;
            }
            let outpoint = OutPoint {
                txid: mp.txid,
                vout: vout as u32,
            };
            if mempool.spending_tx(&outpoint).is_some() {
                continue; // already spent by a child mempool tx
            }
            if out.len() >= cap {
                return Err(JsonRpcError::history_too_large(cap));
            }
            out.push(ListUnspentEntry {
                height,
                tx_hash: TxidHex(mp.txid),
                tx_pos: vout as u32,
                value: txout.value.to_sat(),
            });
        }
    }

    Ok(serde_json::to_value(&out).unwrap())
}

pub fn scripthash_get_mempool(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    let sh = parse_scripthash(&params, "blockchain.scripthash.get_mempool")?;
    let mempool_pool = state.mempool.as_ref();
    let mempool = state.address_index.mempool_history(&sh.0);
    let mut txids: Vec<bitcoin::Txid> = mempool.into_iter().map(|m| m.txid).collect();
    txids.sort();
    let out: Vec<HistoryEntry> = txids
        .into_iter()
        .map(|t| {
            let (height, fee) = match mempool_pool.get(&t) {
                Some(entry) => {
                    let h = if mempool_tx_has_unconfirmed_inputs(&entry.tx, mempool_pool) {
                        -1
                    } else {
                        0
                    };
                    (h, Some(entry.fee))
                }
                None => (0, None),
            };
            HistoryEntry {
                height,
                tx_hash: TxidHex(t),
                fee,
            }
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
    let h = compute_status_hash(state.address_index.as_ref(), state.mempool.as_ref(), sh)
        .map_err(JsonRpcError::from_index)?;
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
    // `(txid, [verbose])` — `verbose=false` (default) returns the hex
    // string. `verbose=true` returns the full JSON shape Bitcoin Core
    // produces for `getrawtransaction <txid> 1`, which is what
    // `romanz/electrs` proxies through to bitcoind.
    let arr = require_array_range(&params, 1, 2, "blockchain.transaction.get")?;
    let txid = parse_txid_hex(&arr[0])?;
    let verbose = arr.get(1).and_then(|v| v.as_bool()).unwrap_or(false);

    // Resolve the tx — mempool first, then txindex fallback. Same
    // priority order satd's own `getrawtransaction` uses.
    let (tx, location): (Transaction, Option<TxLocation>) =
        if let Some(entry) = state.mempool.get(&txid) {
            (entry.tx, None)
        } else if let Some(raw) = state.electrum_extras.raw_tx(&txid) {
            let parsed: Transaction = deserialize(&raw)
                .map_err(|e| JsonRpcError::internal(format!("stored tx decode failed: {e}")))?;
            let confirmation = state.electrum_extras.confirmation(&txid);
            let tip = state.chain.tip_height();
            let location = confirmation.map(|c| TxLocation {
                block_hash: c.block_hash,
                height: c.height,
                block_time: c.block_time,
                confirmations: tip.saturating_sub(c.height).saturating_add(1),
            });
            (parsed, location)
        } else {
            return Err(JsonRpcError::bad_request(format!("tx not found: {txid}")));
        };

    if verbose {
        Ok(verbose_transaction_json(&tx, location.as_ref(), state.network))
    } else {
        Ok(Value::String(hex::encode(serialize(&tx))))
    }
}

/// Confirmation envelope used by [`verbose_transaction_json`].
/// `height` is captured for symmetry with Core's verbose tx response
/// even though we currently fold it into `confirmations`; keeping it
/// here so future callers (RPC `getblockheader` cross-reference,
/// reorg-aware shaping) don't have to plumb it again.
#[allow(dead_code)]
struct TxLocation {
    block_hash: bitcoin::BlockHash,
    height: u32,
    block_time: u32,
    confirmations: u32,
}

/// Build Bitcoin Core's `getrawtransaction <txid> 1` JSON shape.
///
/// Mirrors Core's verbose output exactly (txid, hash, version, size,
/// vsize, weight, locktime, vin, vout, hex; plus blockhash,
/// confirmations, time, blocktime when `location` is `Some`).
///
/// `network` is the active chain network (mainnet / testnet / signet
/// / regtest). It controls the address prefix in
/// `vout[].scriptPubKey.address` so verbose responses are
/// network-correct on every chain. Hardcoding mainnet would emit
/// `1...`/`bc1...` strings on regtest, which wallets reject.
///
/// Notes on wire fidelity:
/// - `vout[].value` is BTC as a JSON number. Core emits 8-decimal
///   strings (e.g. `0.00050000`); serde_json renders f64 without
///   trailing zeros (`0.0005`). Both parse to the same numeric value;
///   wallets that consume `value` numerically are unaffected.
/// - `scriptSig.asm` / `scriptPubKey.asm` use rust-bitcoin's `Display`
///   impl on `Script`, which matches Bitcoin Core's `ScriptToAsmStr`
///   for all standard opcodes.
/// - `coinbase` variant of `vin[]` omits txid/vout/scriptSig per Core.
/// - `txinwitness` is omitted (not present in JSON) for non-segwit
///   inputs, matching Core.
fn verbose_transaction_json(
    tx: &Transaction,
    location: Option<&TxLocation>,
    network: bitcoin::Network,
) -> Value {
    let raw = serialize(tx);
    let txid = tx.compute_txid();
    let wtxid = tx.compute_wtxid();
    let weight = tx.weight().to_wu();
    let vsize = weight.div_ceil(4);

    let vin: Vec<Value> = tx
        .input
        .iter()
        .enumerate()
        .map(|(i, input)| {
            if tx.is_coinbase() && i == 0 {
                let mut v = json!({
                    "coinbase": hex::encode(input.script_sig.as_bytes()),
                    "sequence": input.sequence.0,
                });
                if !input.witness.is_empty() {
                    let witness: Vec<String> = input.witness.iter().map(hex::encode).collect();
                    v["txinwitness"] = json!(witness);
                }
                v
            } else {
                let mut v = json!({
                    "txid": input.previous_output.txid.to_string(),
                    "vout": input.previous_output.vout,
                    "scriptSig": {
                        "asm": format!("{}", input.script_sig),
                        "hex": hex::encode(input.script_sig.as_bytes()),
                    },
                    "sequence": input.sequence.0,
                });
                if !input.witness.is_empty() {
                    let witness: Vec<String> = input.witness.iter().map(hex::encode).collect();
                    v["txinwitness"] = json!(witness);
                }
                v
            }
        })
        .collect();

    let vout: Vec<Value> = tx
        .output
        .iter()
        .enumerate()
        .map(|(n, output)| {
            let mut spk = json!({
                "asm": format!("{}", output.script_pubkey),
                "hex": hex::encode(output.script_pubkey.as_bytes()),
                "type": script_type_label(&output.script_pubkey),
            });
            // Core only emits `address` for outputs that resolve to a
            // single canonical address (P2PKH, P2SH, P2WPKH, P2WSH,
            // P2TR). `Address::from_script` returns Err for
            // multisig / OP_RETURN / nonstandard so we omit gracefully.
            if let Ok(addr) = bitcoin::Address::from_script(&output.script_pubkey, network) {
                spk["address"] = Value::String(addr.to_string());
            }
            json!({
                "value": output.value.to_sat() as f64 / 100_000_000.0,
                "n": n,
                "scriptPubKey": spk,
            })
        })
        .collect();

    let mut result = json!({
        "txid": txid.to_string(),
        "hash": wtxid.to_string(),
        "version": tx.version.0,
        "size": raw.len(),
        "vsize": vsize,
        "weight": weight,
        "locktime": tx.lock_time.to_consensus_u32(),
        "vin": vin,
        "vout": vout,
        "hex": hex::encode(&raw),
    });

    if let Some(loc) = location {
        result["blockhash"] = Value::String(loc.block_hash.to_string());
        result["confirmations"] = json!(loc.confirmations);
        result["time"] = json!(loc.block_time);
        result["blocktime"] = json!(loc.block_time);
    }

    result
}

/// Classify a script for Bitcoin Core's `scriptPubKey.type` field.
/// Returns the same labels Core's `GetTxOutputType` produces.
fn script_type_label(script: &bitcoin::Script) -> &'static str {
    if script.is_p2pk() {
        "pubkey"
    } else if script.is_p2pkh() {
        "pubkeyhash"
    } else if script.is_p2sh() {
        "scripthash"
    } else if script.is_p2wpkh() {
        "witness_v0_keyhash"
    } else if script.is_p2wsh() {
        "witness_v0_scripthash"
    } else if script.is_p2tr() {
        "witness_v1_taproot"
    } else if script.is_op_return() {
        "nulldata"
    } else if script.is_multisig() {
        "multisig"
    } else {
        "nonstandard"
    }
}

pub fn transaction_get_merkle(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    // `(txid, [height])` — `height` is optional and used only as a
    // sanity hint by some clients; we recompute the proof anyway.
    let arr = require_array_range(&params, 1, 2, "blockchain.transaction.get_merkle")?;
    let txid = parse_txid_hex(&arr[0])?;
    let proof = state.electrum_extras.tx_merkle(&txid).ok_or_else(|| {
        JsonRpcError::bad_request(format!("tx {txid} is not confirmed or not indexed"))
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
    // Accept + announce in one step so the tx actually propagates — a bare
    // mempool accept leaves it sitting on this node, unannounced.
    let txid = state
        .tx_broadcaster
        // The Electrum wire protocol has no per-request flag, so it cannot carry
        // an `allowquarantined` override (§6.1): a relay-quarantined submission is
        // refused with the rule named. Use the RPC/Esplora/MCP surfaces to hold
        // one locally.
        .submit_and_announce(tx, node::mempool::pool::TxSource::Electrum, false)
        .map_err(|e| JsonRpcError::bad_request(format!("mempool reject: {e}")))?;
    Ok(Value::String(txid.to_string()))
}

/// `blockchain.transaction.broadcast_package(txs[, verbose])` — accept
/// an array of hex-encoded transactions and submit each to the local
/// mempool. The return shape mirrors `romanz/electrs`'s non-verbose
/// path: `{"success": <bool>}` when every tx accepted, plus an
/// `"errors": [{"txid": ..., "error": ...}, ...]` array for any
/// rejections. `success` is true only when no rejections occurred.
///
/// `verbose=true` is accepted but treated as identical to `false` —
/// electrs forwards bitcoind's full `submitpackage` JSON in verbose
/// mode; satd doesn't have a package-level submission API yet (the
/// Mempool admits per-tx). Documenting this divergence as a known
/// v1 limitation; clients that pass `verbose=true` get the same
/// summary shape and can cross-check against per-tx broadcast.
pub fn transaction_broadcast_package(
    state: &ElectrumState,
    params: Value,
) -> Result<Value, JsonRpcError> {
    let arr = require_array_range(&params, 1, 2, "blockchain.transaction.broadcast_package")?;
    let txs_array = arr[0].as_array().ok_or_else(|| {
        JsonRpcError::invalid_params("first arg must be an array of tx hex strings")
    })?;
    let _verbose = arr.get(1).and_then(|v| v.as_bool()).unwrap_or(false);

    let max_pkg = state.config.max_broadcast_package_txs;
    if txs_array.len() > max_pkg {
        return Err(JsonRpcError::bad_request(format!(
            "broadcast package too large: {} txs (cap = {max_pkg})",
            txs_array.len()
        )));
    }

    // Decode every tx up front so a single bad hex doesn't leave us
    // with a half-broadcast package. Decode failures are JSON-RPC
    // -32602 (invalid params) — same as `transaction_broadcast`.
    let mut decoded = Vec::with_capacity(txs_array.len());
    for v in txs_array {
        let s = v
            .as_str()
            .ok_or_else(|| JsonRpcError::invalid_params("tx must be a hex string"))?;
        let bytes = hex::decode(s.trim())
            .map_err(|e| JsonRpcError::invalid_params(format!("bad hex: {e}")))?;
        let tx: Transaction = deserialize(&bytes)
            .map_err(|e| JsonRpcError::invalid_params(format!("decode: {e}")))?;
        decoded.push(tx);
    }

    // Accept + announce each tx so accepted ones propagate; a bare
    // mempool accept would leave them sitting on this node. Submit in
    // passes until a fixpoint so the package may arrive in any order: a
    // child listed before its parent fails its first pass on missing
    // inputs, then succeeds once the parent is admitted. (Core's
    // `submitpackage` rejects unsorted packages with `package-not-sorted`;
    // accepting any order is strictly more permissive.) Only the final
    // no-progress pass's failures are reported.
    let mut errors: Vec<Value> = Vec::new();
    let mut pending: Vec<usize> = (0..decoded.len()).collect();
    loop {
        let mut next_pending: Vec<usize> = Vec::new();
        let mut pass_errors: Vec<(usize, String)> = Vec::new();
        for &i in &pending {
            if let Err(e) = state
                .tx_broadcaster
                .submit_and_announce(decoded[i].clone(), node::mempool::pool::TxSource::Electrum, false)
            {
                next_pending.push(i);
                pass_errors.push((i, e.to_string()));
            }
        }
        if next_pending.len() == pending.len() {
            // No progress this pass — the remaining failures are final.
            for (i, err) in pass_errors {
                errors.push(json!({
                    "txid": decoded[i].compute_txid().to_string(),
                    "error": err,
                }));
            }
            break;
        }
        if next_pending.is_empty() {
            break;
        }
        pending = next_pending;
    }

    let success = errors.is_empty();
    Ok(if errors.is_empty() {
        json!({ "success": success })
    } else {
        json!({ "success": success, "errors": errors })
    })
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
            JsonRpcError::bad_request(format!("no tx at height={height} pos={tx_pos}"))
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
    // Unified through the shared `smart_fees` resolver (blend mode) so
    // Electrum agrees with the JSON-RPC `estimatefees`, the TUI and Esplora.
    // Unauthenticated surface, so the expensive mempool simulation comes from
    // the shared short-TTL cache instead of being rebuilt per request.
    let floor_sat_per_kvb = state.mempool.min_fee_rate().max(1_000);
    let est = state.fee_estimator.cached_mempool_estimate(&state.mempool);
    let sf = node::mempool::estimate::smart_fees_from_estimate(
        &est,
        &state.fee_estimator,
        &[target],
        node::mempool::estimate::EstimateMode::Blend,
        floor_sat_per_kvb,
    );
    // Electrum convention: `-1` signals "no estimate available". Emit it only
    // on a cold node — no mempool signal (thin) *and* no historical data.
    // Otherwise return the blended estimate in BTC/kB.
    if sf.thin_block && state.fee_estimator.estimate_fee(target).is_none() {
        return Ok(json!(-1.0));
    }
    let sat_per_kvb = sf
        .targets
        .first()
        .map(|t| t.feerate_sat_per_kvb)
        .unwrap_or(floor_sat_per_kvb);
    Ok(json!(sat_per_kvb_to_btc_per_kb(sat_per_kvb)))
}

pub fn relayfee(state: &ElectrumState) -> Result<Value, JsonRpcError> {
    // `min_fee_rate` is the mempool admission floor in sat/kvB (sat per 1000
    // *virtual* bytes) since PR #355. Electrum's wire unit is BTC/kB.
    let sat_per_kvb = state.mempool.min_fee_rate();
    Ok(json!(sat_per_kvb_to_btc_per_kb(sat_per_kvb)))
}

/// Convert satd's internal sat/kvB (sat per 1000 *virtual* bytes) fee rate to
/// the BTC/kB unit Electrum clients expect on the wire. For fee-rate purposes
/// 1 kB ≈ 1 kvB, so `BTC/kB = sat/kvB / 1e8`. (The earlier `×4` was written
/// for the pre-#355 per-weight-unit value and overreported fees ~4×.)
pub(crate) fn sat_per_kvb_to_btc_per_kb(sat_per_kvb: u64) -> f64 {
    sat_per_kvb as f64 / 100_000_000.0
}

// ── helpers ───────────────────────────────────────────────────────

fn parse_scripthash(params: &Value, method: &str) -> Result<ScripthashHex, JsonRpcError> {
    let arr = require_array_range(params, 1, 1, method)?;
    let s = arr[0].as_str().ok_or_else(|| {
        JsonRpcError::invalid_params(format!("{method}: scripthash must be a string"))
    })?;
    // Wire scripthash is display-order (reversed) hex per Electrum
    // spec; `parse_wire_scripthash` returns natural sha256 byte order
    // for index lookup.
    parse_wire_scripthash(s).map(ScripthashHex)
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

/// Returns `true` if `tx` spends at least one output that belongs to
/// another tx currently in the mempool. Per the Electrum spec
/// (`romanz/electrs::Height`), this distinguishes the wire `height`
/// for an unconfirmed entry: `0` for unconfirmed-no-deps, `-1` for
/// unconfirmed-with-unconfirmed-parents.
pub(crate) fn mempool_tx_has_unconfirmed_inputs(
    tx: &Transaction,
    mempool: &node::mempool::pool::Mempool,
) -> bool {
    tx.input
        .iter()
        .any(|inp| mempool.get(&inp.previous_output.txid).is_some())
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

    #[test]
    fn fee_unit_conversion_matches_known_fixture() {
        // Since PR #355 internal fee rates are sat/kvB (per vbyte): a 1 sat/vB
        // tx has internal `fee_rate = 1000`, a 10 sat/vB tx `10000`. Electrum
        // wire is BTC/kB = sat/kvB / 1e8. (The earlier ×4 against the old
        // per-weight-unit value overreported every rate ~4×.)
        let one_sat_per_vb = 1000u64;
        let btc_per_kb = sat_per_kvb_to_btc_per_kb(one_sat_per_vb);
        // Allow tiny float epsilon.
        assert!((btc_per_kb - 0.00001000).abs() < 1e-12, "{btc_per_kb}");

        // 10 sat/vB → internal 10000 → 0.0001 BTC/kB.
        assert!((sat_per_kvb_to_btc_per_kb(10_000) - 0.0001).abs() < 1e-12);

        // 0 / unknown stays 0.
        assert_eq!(sat_per_kvb_to_btc_per_kb(0), 0.0);
    }
}
