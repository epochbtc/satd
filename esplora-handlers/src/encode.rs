//! Wire-shape encoders that match upstream Esplora.
//!
//! Block JSON shape (per `blockstream.info` API):
//! ```json
//! {
//!   "id": "<hash hex>",
//!   "height": <u32>,
//!   "version": <i32>,
//!   "timestamp": <u32>,
//!   "tx_count": <u32>,
//!   "size": <u32>,           // total block size in bytes
//!   "weight": <u32>,         // BIP141 weight units
//!   "merkle_root": "<hash hex>",
//!   "previousblockhash": "<hash hex>" | null,
//!   "mediantime": <u32>,
//!   "nonce": <u32>,
//!   "bits": <u32>,
//!   "difficulty": <f64>
//! }
//! ```

use bitcoin::block::Header;
use bitcoin::{BlockHash, Network};
use serde::Serialize;

use node::storage::blockindex::BlockIndexEntry;

#[derive(Debug, Serialize)]
pub struct BlockHeaderJson {
    pub id: String,
    pub height: u32,
    pub version: i32,
    pub timestamp: u32,
    pub tx_count: u32,
    pub size: u32,
    pub weight: u32,
    pub merkle_root: String,
    pub previousblockhash: Option<String>,
    pub mediantime: u32,
    pub nonce: u32,
    pub bits: u32,
    pub difficulty: f64,
}

/// Build the per-Esplora block-summary JSON from a `BlockIndexEntry`.
/// `size` and `weight` are not stored on the index entry; pass them
/// in if known (block-detail handlers in PR 3 will compute on demand).
pub fn block_header_json(
    hash: &BlockHash,
    entry: &BlockIndexEntry,
    network: Network,
    size: u32,
    weight: u32,
    mediantime: u32,
) -> BlockHeaderJson {
    let header = entry.header;
    BlockHeaderJson {
        id: hash.to_string(),
        height: entry.height,
        version: header.version.to_consensus(),
        timestamp: header.time,
        tx_count: entry.num_tx,
        size,
        weight,
        merkle_root: header.merkle_root.to_string(),
        previousblockhash: if entry.height == 0 {
            None
        } else {
            Some(header.prev_blockhash.to_string())
        },
        mediantime,
        nonce: header.nonce,
        bits: header.bits.to_consensus(),
        difficulty: difficulty_from_target(header, network),
    }
}

/// Bitcoin Core's `getdifficulty` formula. We re-implement here so
/// `esplora-handlers` doesn't need a back-reference into RPC code.
fn difficulty_from_target(header: Header, _network: Network) -> f64 {
    // difficulty = 0xffff * 2^208 / target.
    // Using rust-bitcoin's `difficulty()` method which already
    // returns the canonical f64.
    use bitcoin::Target;
    let target: Target = header.target();
    target.difficulty_float()
}
