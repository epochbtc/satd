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

use std::collections::{HashMap, HashSet};

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::{OutPoint, Transaction, Txid};
use node::chain::pin::Pin;
use node_index::{
    HistoryEntry, HistoryRow, MempoolTxFacts, mempool_history_rows, scripthash_of,
    sort_mempool_rows,
};
use serde_json::{Value, json};

use crate::dispatch::{require_array, require_array_range};
use crate::error::JsonRpcError;
use crate::merkle::compute_merkle_branch;
use crate::state::ElectrumState;
use crate::status::{compute_status_hash, mempool_facts, status_hash_to_json};
use crate::types::{
    BalanceResponse, FeeHistogramEntry, GetMerkleResponse, HeadersResponse,
    HistoryEntry as WireHistoryEntry, ListUnspentEntry, ScripthashHex, TxidHex, merkle_node_to_hex, parse_wire_scripthash,
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

pub fn scripthash_get_history(
    state: &ElectrumState,
    params: Value,
    pin: &Pin,
) -> Result<Value, JsonRpcError> {
    let sh = parse_scripthash(&params, "blockchain.scripthash.get_history")?;
    let cap = state.config.max_history_entries;

    // The rows come out in Electrum history order — confirmed by height
    // and block position, then mempool with height 0 before -1, then
    // display txid — from the same helper the subscribe status and the
    // notifier hash. A client checks the announced status by hashing this
    // response in the order it arrives, so the two must agree row for row.
    //
    // A history over `cap` transactions (confirmed, or confirmed plus
    // mempool) is refused with `history too large`. The confirmed part is
    // counted first by a read that stops at the first transaction past
    // the cap, so the refusal costs `O(cap)` reads and memory, never the
    // whole history; the cap counts DISTINCT transactions (round-3 review
    // H1 — the schema has one row per matching output AND input).
    let rows = pinned_history_rows(state, &sh.0, cap, pin)?;

    // `fee` (sats) is set on mempool rows only, from the live mempool
    // entry, which pre-computes it at admission.
    let out: Vec<WireHistoryEntry> = rows
        .into_iter()
        .map(|r| WireHistoryEntry {
            height: r.height,
            tx_hash: TxidHex(r.txid),
            fee: r.fee_sat,
        })
        .collect();

    Ok(serde_json::to_value(&out).unwrap())
}

/// `sh`'s history as of the pin, in protocol order, refused above `cap`
/// transactions as [`node_index::capped_history_rows`] refuses it.
///
/// The mempool part is read before the confirmed part. A transaction that
/// confirms between the two reads is then in both, and
/// [`unconfirm_late_rows`] lists it once, as the unconfirmed transaction it
/// was at the pin (it confirmed above it). Read the other way round, as
/// `capped_history_rows` reads, it would be in neither.
fn pinned_history_rows(
    state: &ElectrumState,
    sh: &node_index::Scripthash,
    cap: usize,
    pin: &Pin,
) -> Result<Vec<HistoryRow>, JsonRpcError> {
    let idx = state.address_index.as_ref();
    let mempool = state.mempool.as_ref();
    idx.check_history_cap(sh, cap)
        .map_err(JsonRpcError::from_index)?;
    // `-1` as of the pin, not as of now: a parent that confirmed above the
    // pin was unconfirmed then. Worked out in the same mempool read as the
    // rest of the row, so a transaction leaving the pool cannot keep a
    // height read before it left.
    let mempool_rows = mempool_history_rows(idx, sh, |txid| {
        let entry = mempool.get(txid)?;
        Some(MempoolTxFacts {
            has_unconfirmed_inputs: mempool_tx_has_unconfirmed_inputs(&entry.tx, mempool)
                || spends_above_pin(state, &entry.tx, pin),
            fee_sat: entry.fee,
        })
    });
    let mut rows: Vec<HistoryRow> = idx
        .confirmed_txs_in_chain_order(sh, cap.saturating_add(1))
        .map_err(JsonRpcError::from_index)?
        .into_iter()
        .map(|(height, txid)| HistoryRow {
            height: i64::from(height),
            txid,
            fee_sat: None,
        })
        .collect();
    rows.extend(mempool_rows);
    let rows = unconfirm_late_rows(state, rows, pin);
    if rows.len() > cap {
        return Err(JsonRpcError::history_too_large(cap));
    }
    Ok(rows)
}

/// `rows` as of the pin: a transaction confirmed above it was unconfirmed
/// when the request started, so it leaves the confirmed part and joins the
/// mempool part, in that part's order, with the height and fee
/// [`LateFacts::of`] gives it.
///
/// The confirmed rows have no fee and the mempool rows each have theirs, so
/// the fee tells the two apart.
fn unconfirm_late_rows(state: &ElectrumState, rows: Vec<HistoryRow>, pin: &Pin) -> Vec<HistoryRow> {
    let (mut mempool, confirmed): (Vec<HistoryRow>, Vec<HistoryRow>) =
        rows.into_iter().partition(|r| r.fee_sat.is_some());
    let (late, mut out): (Vec<HistoryRow>, Vec<HistoryRow>) = confirmed
        .into_iter()
        .partition(|r| r.height > i64::from(pin.height));
    if late.is_empty() {
        out.extend(mempool);
        return out;
    }
    let mut facts = LateFacts::new(state, pin);
    for row in late {
        // The mempool part was read first (`pinned_history_rows`), so a
        // transaction that confirmed between the two reads is in both: it
        // keeps its mempool row, which has its fee.
        if mempool.iter().any(|m| m.txid == row.txid) {
            continue;
        }
        let (height, fee_sat) = facts.of(&row.txid);
        mempool.push(HistoryRow {
            height,
            txid: row.txid,
            fee_sat,
        });
    }
    sort_mempool_rows(&mut mempool);
    out.extend(mempool);
    out
}

/// What the transactions confirmed above the pin were as of the pin, for
/// one request. Each transaction it reads from the txindex, a late one or a
/// parent, is read once, as one block load, however many late rows or
/// inputs name it.
struct LateFacts<'a> {
    state: &'a ElectrumState,
    pin: &'a Pin,
    /// The confirmed transactions read so far, with the height each
    /// confirmed at; `None` for one the txindex cannot return.
    read: HashMap<Txid, Option<(Transaction, u32)>>,
}

impl<'a> LateFacts<'a> {
    fn new(state: &'a ElectrumState, pin: &'a Pin) -> Self {
        Self {
            state,
            pin,
            read: HashMap::new(),
        }
    }

    /// A confirmed transaction and its height, from the txindex.
    fn confirmed(&mut self, txid: &Txid) -> Option<&(Transaction, u32)> {
        let chain = &self.state.chain;
        self.read
            .entry(*txid)
            .or_insert_with(|| {
                let hash = chain.get_tx_location(txid)?;
                let height = chain.get_block_index(&hash)?.height;
                let block = chain.get_block(&hash)?;
                let tx = block.txdata.into_iter().find(|t| t.compute_txid() == *txid)?;
                Some((tx, height))
            })
            .as_ref()
    }

    /// The Electrum mempool height `txid`, confirmed above the pin, had as of
    /// it: `-1` when it spends a transaction that was also unconfirmed then
    /// (in the mempool, or confirmed above the pin too) and `0` otherwise;
    /// and its fee when every parent's output can be read, from the mempool
    /// or the txindex. A transaction the txindex cannot return is height `0`
    /// with no fee.
    fn of(&mut self, txid: &Txid) -> (i64, Option<u64>) {
        let Some((tx, _)) = self.confirmed(txid).cloned() else {
            return (0, None);
        };
        if tx.is_coinbase() {
            return (0, None);
        }
        let mut unconfirmed_parent = false;
        let mut input_sum = Some(0u64);
        for input in &tx.input {
            let prev = input.previous_output;
            let value = if let Some(entry) = self.state.mempool.get(&prev.txid) {
                unconfirmed_parent = true;
                entry.tx.output.get(prev.vout as usize).map(|o| o.value.to_sat())
            } else {
                let pin = *self.pin;
                self.confirmed(&prev.txid).and_then(|(parent, height)| {
                    if !pin.covers(*height) {
                        unconfirmed_parent = true;
                    }
                    parent.output.get(prev.vout as usize).map(|o| o.value.to_sat())
                })
            };
            input_sum = input_sum.zip(value).and_then(|(sum, v)| sum.checked_add(v));
        }
        let output_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        let fee = input_sum.and_then(|sum| sum.checked_sub(output_sum));
        (if unconfirmed_parent { -1 } else { 0 }, fee)
    }
}

/// Whether `tx`, in the mempool now, spends a transaction confirmed above
/// the pin: one that was unconfirmed as of the pin, which makes `tx`'s
/// Electrum height `-1` as of it, as [`LateFacts::of`] counts it for a late
/// transaction. Nothing is confirmed above the pin until the tip passes it,
/// so the usual request, whose tip has not moved, reads nothing here; one
/// whose tip has moved reads each input's block index entry, no block.
fn spends_above_pin(state: &ElectrumState, tx: &Transaction, pin: &Pin) -> bool {
    if state.chain.tip_height() <= pin.height {
        return false;
    }
    tx.input.iter().any(|input| {
        state
            .chain
            .get_tx_location(&input.previous_output.txid)
            .and_then(|hash| state.chain.get_block_index(&hash))
            .is_some_and(|entry| !pin.covers(entry.height))
    })
}

/// Whether `sh` has a transaction confirmed above the pin: one read of the
/// newest confirmed transaction.
fn confirmed_above(state: &ElectrumState, sh: &node_index::Scripthash, pin: &Pin) -> Result<bool, JsonRpcError> {
    let newest = state
        .address_index
        .confirmed_txs_newest_first(sh, None, 1)
        .map_err(JsonRpcError::from_index)?;
    Ok(newest
        .and_then(|page| page.first().copied())
        .is_some_and(|(height, _)| !pin.covers(height)))
}

/// The confirmed balance as of the pin, from the history: what was funded
/// at or below it and not spent at or below it.
fn confirmed_balance_at(history: &[HistoryEntry], pin: &Pin) -> u64 {
    let spent: std::collections::HashSet<OutPoint> = history
        .iter()
        .filter_map(|e| match e {
            HistoryEntry::Spending {
                height,
                prev_outpoint,
                ..
            } if pin.covers(*height) => Some(*prev_outpoint),
            _ => None,
        })
        .collect();
    history
        .iter()
        .filter_map(|e| match e {
            HistoryEntry::Funding {
                height,
                txid,
                vout,
                amount_sat,
            } if pin.covers(*height)
                && !spent.contains(&OutPoint {
                    txid: *txid,
                    vout: *vout,
                }) =>
            {
                Some(*amount_sat)
            }
            _ => None,
        })
        .fold(0u64, u64::saturating_add)
}

pub fn scripthash_get_balance(
    state: &ElectrumState,
    params: Value,
    pin: &Pin,
) -> Result<Value, JsonRpcError> {
    let sh = parse_scripthash(&params, "blockchain.scripthash.get_balance")?;
    // The confirmed balance is summed over every funding row, so its cost
    // follows the history. Refuse a history over the cap first, as Fulcrum
    // does for `get_balance` above its `max_history`.
    let cap = state.config.max_history_entries;
    state
        .address_index
        .check_history_cap(&sh.0, cap)
        .map_err(JsonRpcError::from_index)?;
    let (confirmed, unconfirmed, at_pin) = {
        let mut attempt = 0;
        loop {
            let (confirmed, unconfirmed) = state
                .address_index
                .balance(&sh.0)
                .map_err(JsonRpcError::from_index)?;
            // Read after the balance, so a block that connected before it
            // shows up here. Normally nothing has confirmed above the pin,
            // and the live balance is the answer.
            if !confirmed_above(state, &sh.0, pin)? {
                return Ok(serde_json::to_value(BalanceResponse {
                    confirmed,
                    unconfirmed,
                })
                .unwrap());
            }
            // What confirmed above the pin was unconfirmed as of it: the
            // confirmed balance is the history's at the pin, and the
            // difference moves to the unconfirmed delta. A transaction the
            // live balance counts, as confirmed or as unconfirmed, is counted
            // once either way, provided the history is the one the balance
            // was read from: a block that connects between the two reads is
            // in the history but not the balance, and a transaction in it
            // that the balance did not count as unconfirmed would count
            // nowhere. The history's own confirmed balance shows it; read
            // both again.
            let history = state
                .address_index
                .confirmed_history(&sh.0)
                .map_err(JsonRpcError::from_index)?;
            let everything = Pin {
                height: u32::MAX,
                ..*pin
            };
            if confirmed_balance_at(&history, &everything) == confirmed {
                break (confirmed, unconfirmed, confirmed_balance_at(&history, pin));
            }
            // The two disagree only when a block connected between them:
            // unspendable outputs are in neither, and every funding row the
            // history holds is one the balance walks. Blocks connecting
            // under every attempt are a chain view that would not settle.
            attempt += 1;
            if attempt >= node::chain::pin::VIEW_ATTEMPTS {
                return Err(JsonRpcError::bad_request(node::chain::pin::CHAIN_VIEW_MOVED));
            }
        }
    };
    let unconfirmed = unconfirmed
        .saturating_add(i64::try_from(confirmed).unwrap_or(i64::MAX))
        .saturating_sub(i64::try_from(at_pin).unwrap_or(i64::MAX));
    let confirmed = at_pin;
    Ok(serde_json::to_value(BalanceResponse {
        confirmed,
        unconfirmed,
    })
    .unwrap())
}

pub fn scripthash_listunspent(
    state: &ElectrumState,
    params: Value,
    pin: &Pin,
) -> Result<Value, JsonRpcError> {
    let sh = parse_scripthash(&params, "blockchain.scripthash.listunspent")?;
    // Round-1 review M4: bound the index walk at cap + 1 UTXOs.
    let cap = state.config.max_history_entries;
    // The UTXO walk checks every funding row for a live coin, so its cost
    // follows the history, not the UTXO count: refuse a history over the
    // cap before it starts (Fulcrum refuses `listunspent` above its
    // `max_history` too).
    state
        .address_index
        .check_history_cap(&sh.0, cap)
        .map_err(JsonRpcError::from_index)?;

    // The mempool part is read before the coin set, as `pinned_history_rows`
    // reads the history: a transaction that confirms between the two reads
    // is then in both, and listed once, as the unconfirmed transaction it
    // was at the pin; a spend that confirms between them is in the mempool
    // part or has removed the coin. Read the other way round, the first
    // would be in neither and the second would leave the output listed.
    let mempool = state.mempool.as_ref();
    let mempool_txs: Vec<_> = state
        .address_index
        .mempool_history(&sh.0)
        .into_iter()
        .filter_map(|mp| mempool.get(&mp.txid).map(|entry| (mp.txid, entry)))
        .collect();
    let mempool_txids: HashSet<Txid> = mempool_txs.iter().map(|(txid, _)| *txid).collect();
    let mempool_spent: HashSet<OutPoint> = mempool_txs
        .iter()
        .flat_map(|(_, entry)| entry.tx.input.iter().map(|i| i.previous_output))
        .collect();
    let spent = |outpoint: &OutPoint| {
        mempool_spent.contains(outpoint) || mempool.spending_tx(outpoint).is_some()
    };

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
    //
    // A UTXO created above the pin was an unconfirmed output as of it, and
    // is listed after the confirmed ones with its creating transaction's
    // mempool height. One spent above the pin is gone from the coin set: as
    // of the pin it had an unconfirmed spend, and a confirmed output with a
    // mempool spend is not listed.
    let (mut out, mut late): (Vec<ListUnspentEntry>, Vec<ListUnspentEntry>) = (Vec::new(), Vec::new());
    let mut facts = LateFacts::new(state, pin);
    for u in utxos {
        // Drop confirmed UTXOs whose outpoint is consumed by a
        // mempool spend — wallets shouldn't see them as spendable.
        if spent(&OutPoint {
            txid: u.txid,
            vout: u.vout,
        }) {
            continue;
        }
        let entry = ListUnspentEntry {
            height: u.height as i64,
            tx_hash: TxidHex(u.txid),
            tx_pos: u.vout,
            value: u.amount_sat,
        };
        if pin.covers(u.height) {
            out.push(entry);
        } else if !mempool_txids.contains(&u.txid) {
            // A transaction in the mempool part is listed with it.
            late.push(ListUnspentEntry {
                height: facts.of(&u.txid).0,
                ..entry
            });
        }
    }
    out.extend(late);

    // Mempool funding additions. Round-2 review M2: cap-check on
    // every push so a single unconfirmed tx with many outputs to
    // `sh`, or a flood of mempool funding txs, can't push the
    // response past `cap` entries.
    for (txid, entry) in mempool_txs {
        let height: i64 = if mempool_tx_has_unconfirmed_inputs(&entry.tx, mempool)
            || spends_above_pin(state, &entry.tx, pin)
        {
            -1
        } else {
            0
        };
        for (vout, txout) in entry.tx.output.iter().enumerate() {
            if scripthash_of(txout.script_pubkey.as_script()) != sh.0 {
                continue;
            }
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            if spent(&outpoint) {
                continue; // already spent by a child mempool tx
            }
            if out.len() >= cap {
                return Err(JsonRpcError::history_too_large(cap));
            }
            out.push(ListUnspentEntry {
                height,
                tx_hash: TxidHex(txid),
                tx_pos: vout as u32,
                value: txout.value.to_sat(),
            });
        }
    }

    Ok(serde_json::to_value(&out).unwrap())
}

pub fn scripthash_get_mempool(state: &ElectrumState, params: Value) -> Result<Value, JsonRpcError> {
    let sh = parse_scripthash(&params, "blockchain.scripthash.get_mempool")?;
    // The mempool part of `get_history`, in the same order.
    let mempool = state.mempool.as_ref();
    let out: Vec<WireHistoryEntry> =
        mempool_history_rows(state.address_index.as_ref(), &sh.0, |txid| {
            mempool_facts(mempool, txid)
        })
        .into_iter()
        .map(|r| WireHistoryEntry {
            height: r.height,
            tx_hash: TxidHex(r.txid),
            fee: r.fee_sat,
        })
        .collect();
    Ok(serde_json::to_value(&out).unwrap())
}

pub fn scripthash_get_first_use(
    state: &ElectrumState,
    params: Value,
) -> Result<Value, JsonRpcError> {
    let sh = parse_scripthash(&params, "blockchain.scripthash.get_first_use")?;
    // Only the script's first block is read, so this is not capped: the
    // answer costs the same for a history of one transaction or millions.
    let earliest = state
        .address_index
        .first_confirmed_tx(&sh.0)
        .map_err(JsonRpcError::from_index)?;
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
    let h = compute_status_hash(
        state.address_index.as_ref(),
        state.mempool.as_ref(),
        sh,
        state.config.max_history_entries,
    )
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

pub fn transaction_get(state: &ElectrumState, params: Value, pin: &Pin) -> Result<Value, JsonRpcError> {
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
        // Acting-only (design §6.1): a relay-quarantined tx is invisible to a
        // client that learned the txid elsewhere — matching satd's own
        // `getrawtransaction` (`rawtx.rs`), which filters to the acting class.
        // Without this filter any Electrum client could pull a withheld tx by
        // txid. Fall through to the txindex/not-found path when quarantined.
        if let Some(entry) = state.mempool.get(&txid).filter(|e| e.scope.is_acting()) {
            (entry.tx, None)
        } else if let Some(raw) = state.electrum_extras.raw_tx(&txid) {
            let parsed: Transaction = deserialize(&raw)
                .map_err(|e| JsonRpcError::internal(format!("stored tx decode failed: {e}")))?;
            // A transaction confirmed above the pin was unconfirmed as of it,
            // and has no block yet.
            let confirmation = state
                .electrum_extras
                .confirmation(&txid)
                .filter(|c| pin.covers(c.height));
            let location = confirmation.map(|c| TxLocation {
                block_hash: c.block_hash,
                height: c.height,
                block_time: c.block_time,
                confirmations: pin.height.saturating_sub(c.height).saturating_add(1),
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

pub fn transaction_get_merkle(
    state: &ElectrumState,
    params: Value,
    pin: &Pin,
) -> Result<Value, JsonRpcError> {
    // `(txid, [height])` — `height` is optional and used only as a
    // sanity hint by some clients; we recompute the proof anyway.
    let arr = require_array_range(&params, 1, 2, "blockchain.transaction.get_merkle")?;
    let txid = parse_txid_hex(&arr[0])?;
    // A transaction confirmed above the pin was not confirmed as of it.
    let proof = state
        .electrum_extras
        .tx_merkle(&txid)
        .filter(|p| pin.covers(p.height))
        .ok_or_else(|| {
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
    pin: &Pin,
) -> Result<Value, JsonRpcError> {
    // `(height, tx_pos, [merkle])` — `merkle=true` adds the proof.
    let arr = require_array_range(&params, 2, 3, "blockchain.transaction.id_from_pos")?;
    let height = parse_height(&arr[0])?;
    let tx_pos = parse_u32(&arr[1], "tx_pos")?;
    let merkle = arr.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
    // A block above the pin had not connected as of it.
    let txid = pin
        .covers(height)
        .then(|| state.electrum_extras.txid_at_pos(height, tx_pos))
        .flatten()
        .ok_or_else(|| {
            JsonRpcError::bad_request(format!("no tx at height={height} pos={tx_pos}"))
        })?;
    if !merkle {
        return Ok(Value::String(txid.to_string()));
    }
    // merkle=true: include the branch alongside the txid.
    let block_hash = pin
        .hash_at_height(&state.chain, height)
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
#[path = "blockchain_historycap_tests.rs"]
mod historycap_tests;

#[cfg(test)]
#[path = "blockchain_pin_tests.rs"]
mod pin_tests;

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
