use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::mining::template::create_template;
use serde_json::{json, Value};

/// Handle the `submitblock` RPC call.
pub fn submit_block(chain_state: &ChainState, mempool: &Mempool, hex_block: &str) -> Value {
    let block_bytes = match hex::decode(hex_block) {
        Ok(b) => b,
        Err(_) => return Value::String("Block decode failed".to_string()),
    };

    let block: bitcoin::Block = match bitcoin::consensus::deserialize(&block_bytes) {
        Ok(b) => b,
        Err(_) => return Value::String("Block decode failed".to_string()),
    };

    match chain_state.accept_block(&block) {
        Ok(_) => {
            mempool.remove_for_block(&block);
            Value::Null
        }
        Err(e) => Value::String(e.to_string()),
    }
}

/// Handle the `generatetoaddress` RPC call (regtest only).
pub fn generate_to_address(
    chain_state: &ChainState,
    mempool: &Mempool,
    nblocks: u32,
    address: &str,
) -> Result<Value, (i32, String)> {
    if chain_state.network != bitcoin::Network::Regtest {
        return Err((-1, "generatetoaddress is only available in regtest mode".to_string()));
    }

    let hashes = crate::mining::miner::mine_blocks(chain_state, mempool, address, nblocks)
        .map_err(|e| (-1, e.to_string()))?;

    Ok(json!(hashes))
}

/// Handle the `generateblock` RPC call (regtest only).
pub fn generate_block(
    chain_state: &ChainState,
    mempool: &Mempool,
    address: &str,
) -> Result<Value, (i32, String)> {
    if chain_state.network != bitcoin::Network::Regtest {
        return Err((-1, "generateblock is only available in regtest mode".to_string()));
    }

    let block = crate::mining::miner::mine_block(chain_state, mempool, address)
        .map_err(|e| (-1, e.to_string()))?;

    Ok(json!({ "hash": block.block_hash().to_string() }))
}

/// Handle the `getblocktemplate` RPC call.
pub fn get_block_template(chain_state: &ChainState, mempool: &Mempool) -> Value {
    let template = create_template(chain_state, mempool);

    let txs: Vec<Value> = template
        .transactions
        .iter()
        .map(|ttx| {
            let raw = bitcoin::consensus::serialize(&ttx.tx);
            json!({
                "data": hex::encode(&raw),
                "txid": ttx.tx.compute_txid().to_string(),
                "fee": ttx.fee,
                "weight": ttx.weight,
            })
        })
        .collect();

    // Compute target from compact bits
    let target = crate::storage::blockindex::target_from_compact(template.bits);
    let target_hex = hex::encode(target);

    json!({
        "version": template.version,
        "rules": ["csv", "segwit", "taproot"],
        "vbavailable": {},
        "vbrequired": 0,
        "previousblockhash": template.prev_hash.to_string(),
        "transactions": txs,
        "coinbaseaux": { "flags": "" },
        "coinbasevalue": template.coinbase_value,
        "target": format!("{:0>64}", target_hex),
        "mintime": template.cur_time,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "capabilities": ["proposal"],
        "sigoplimit": 80000,
        "sizelimit": 4000000,
        "weightlimit": 4000000,
        "curtime": template.cur_time,
        "bits": format!("{:08x}", template.bits.to_consensus()),
        "height": template.height,
        "default_witness_commitment": "",
    })
}
