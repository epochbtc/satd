//! `gettxspendingprevout`: which transaction spends each of the given
//! outputs, as Core v31.1 answers it (`src/rpc/mempool.cpp`).
//!
//! The mempool is searched first. An output it has no spender for is looked
//! up in the confirmed spend index when the caller allows it (`mempool_only`
//! false, the default under `-txospenderindex`). satd's spend index is the
//! address index's `spent` rows, which `connect_block` and
//! `disconnect_block` keep in step with the active chain; Core's
//! `txospenderindex` is a background index of its own.

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{OutPoint, Transaction, Txid};
use node_index::{IndexError, SpendIndex};
use serde_json::{Map, Value};

use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::rpc::util::parse_hash_v;
use crate::storage::Store as _;

/// The JSON type names Core's `uvTypeName` prints.
fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Core's `RPCTypeCheckObj` with `fStrict`: every expected key in order
/// (missing, then mistyped), then any key it does not expect.
fn check_obj(o: &Map<String, Value>, expected: &[(&str, &str)], allow_null: bool) -> Result<(), (i32, String)> {
    for (key, ty) in expected {
        let v = o.get(*key).unwrap_or(&Value::Null);
        if !allow_null && v.is_null() {
            return Err((-3, format!("Missing {key}")));
        }
        let actual = type_name(v);
        if actual != *ty && !(allow_null && v.is_null()) {
            return Err((-3, format!("JSON value of type {actual} for field {key} is not of expected type {ty}")));
        }
    }
    if let Some(k) = o.keys().find(|k| !expected.iter().any(|(e, _)| e == k)) {
        return Err((-3, format!("Unexpected key {k}")));
    }
    Ok(())
}

/// The confirmed spender of `outpoint` and the block holding it, read as
/// one view of the chain. `Ok(None)` is unspent on the active chain.
fn confirmed_spender(
    chain: &ChainState,
    index: &dyn SpendIndex,
    outpoint: &OutPoint,
) -> Result<Option<(Txid, bitcoin::BlockHash)>, IndexError> {
    let read = || -> Result<Option<(Txid, bitcoin::BlockHash)>, IndexError> {
        let Some(spend) = index.spend_of(outpoint)? else { return Ok(None) };
        let hash = chain
            .store_ref()
            .get_block_hash_by_height(spend.height)
            .ok_or_else(|| IndexError::Storage(format!("no block at height {}", spend.height)))?;
        Ok(Some((spend.spending_txid, hash)))
    };
    chain
        .coherent_read(read)
        .unwrap_or_else(|| Err(IndexError::Storage("the chain kept moving; ask again".into())))
}

/// `gettxspendingprevout outputs ( options )`.
///
/// `index` is the confirmed spend index when `-txospenderindex` is on, and
/// `None` otherwise; it decides `mempool_only`'s default, as
/// `g_txospenderindex` does in Core.
pub fn get_tx_spending_prevout(
    chain: &ChainState,
    mempool: &Mempool,
    index: Option<&dyn SpendIndex>,
    outputs: Vec<Value>,
    options: Option<Map<String, Value>>,
) -> Result<Value, (i32, String)> {
    if outputs.is_empty() {
        return Err((-8, "Invalid parameter, outputs are missing".into()));
    }
    let options = options.unwrap_or_default();
    check_obj(&options, &[("mempool_only", "bool"), ("return_spending_tx", "bool")], true)?;
    let flag = |k: &str| options.get(k).and_then(Value::as_bool);
    let mempool_only = flag("mempool_only").unwrap_or(index.is_none());
    let return_spending_tx = flag("return_spending_tx").unwrap_or(false);

    let mut prevouts: Vec<(OutPoint, Map<String, Value>)> = Vec::with_capacity(outputs.len());
    for o in outputs {
        let Value::Object(o) = o else {
            return Err((-3, format!("JSON value of type {} is not of expected type object", type_name(&o))));
        };
        check_obj(&o, &[("txid", "string"), ("vout", "number")], false)?;
        let txid: Txid = parse_hash_v(o["txid"].as_str().unwrap_or_default(), "txid")?;
        let vout = o["vout"]
            .as_i64()
            .filter(|n| i32::try_from(*n).is_ok())
            .ok_or((-1, "JSON integer out of range".to_string()))?;
        if vout < 0 {
            return Err((-8, "Invalid parameter, vout cannot be negative".into()));
        }
        prevouts.push((OutPoint { txid, vout: vout as u32 }, o));
    }

    let with_tx = |o: &mut Map<String, Value>, tx: &Transaction| {
        if return_spending_tx {
            o.insert("spendingtx".into(), Value::String(serialize_hex(tx)));
        }
    };
    let mut result = Vec::with_capacity(prevouts.len());
    for (outpoint, mut o) in prevouts {
        if let Some(tx) = mempool.spending_transaction_acting(&outpoint) {
            o.insert("spendingtxid".into(), Value::String(tx.compute_txid().to_string()));
            with_tx(&mut o, &tx);
        } else if !mempool_only {
            let unavailable = || {
                (-1, format!(
                    "No spending tx for the outpoint {}:{} in mempool, and txospenderindex is unavailable.",
                    outpoint.txid, outpoint.vout
                ))
            };
            let index = index.ok_or_else(unavailable)?;
            match confirmed_spender(chain, index, &outpoint) {
                Ok(None) => {}
                Ok(Some((spending_txid, block_hash))) => {
                    o.insert("spendingtxid".into(), Value::String(spending_txid.to_string()));
                    o.insert("blockhash".into(), Value::String(block_hash.to_string()));
                    if return_spending_tx {
                        let tx = chain
                            .get_block(&block_hash)
                            .and_then(|b| b.txdata.into_iter().find(|t| t.compute_txid() == spending_txid))
                            .ok_or((-1, format!("Block {block_hash} not available")))?;
                        with_tx(&mut o, &tx);
                    }
                }
                // Core's `BlockUntilSyncedToCurrentChain` failing: the index
                // cannot answer for this chain yet.
                Err(IndexError::Disabled | IndexError::Incomplete) => return Err(unavailable()),
                Err(IndexError::Storage(e)) => return Err((-1, e)),
                Err(e) => return Err((-1, e.to_string())),
            }
        }
        result.push(Value::Object(o));
    }
    Ok(Value::Array(result))
}

#[cfg(test)]
#[path = "txospender_tests.rs"]
mod tests;
