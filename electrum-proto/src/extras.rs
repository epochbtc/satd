//! [`ElectrumExtras`] — the chainstate surface needed by Electrum
//! handlers that lives outside the `node-index` trait.
//!
//! The address index covers scripthash history, balance, and UTXOs.
//! The Electrum protocol additionally needs:
//! - block headers by height (`blockchain.block.header(s)`,
//!   `blockchain.headers.{subscribe,get}`)
//! - raw tx bytes by txid (`blockchain.transaction.get`)
//! - confirmed-tx location (block + height + position) for
//!   `blockchain.transaction.get_merkle`
//! - txid-by-position-within-block for
//!   `blockchain.transaction.id_from_pos`
//!
//! Concrete impl [`RocksElectrumExtras`] is defined below — it's a
//! thin wrapper around `Arc<ChainState>` reusing the same lookup paths
//! Esplora already uses. The implementation lives here (rather than in
//! `node` like the address-index impl) to avoid a dependency cycle:
//! this crate already pulls in `node` for `Mempool` / `FeeEstimator` /
//! `ChainState`, so adding `node → electrum-proto` for the trait alone
//! would form a cycle. Putting the concrete impl on this side of the
//! boundary breaks the symmetry but matches the actual dependency
//! direction.

use std::sync::Arc;

use bitcoin::block::Header;
use bitcoin::consensus::encode::serialize;
use bitcoin::{BlockHash, Txid};

use node::chain::state::ChainState;

use crate::merkle::compute_merkle_branch;

/// Read-only chainstate surface beyond the address index.
///
/// All methods return `Option` rather than `Result`: a missing height /
/// txid is a normal "not found" outcome at the Electrum protocol level,
/// not an internal error. Higher-level errors (storage corruption,
/// disabled indexes) bubble up from the underlying handlers as JSON-RPC
/// errors via the `dispatch` layer.
pub trait ElectrumExtras: Send + Sync {
    /// Return the block header at exactly `height`, or `None` if the
    /// height is beyond the active tip / has no header indexed.
    fn header_at(&self, height: u32) -> Option<Header>;

    /// Return `(tip_height, tip_header)`. Used as the synchronous
    /// initial response to `blockchain.headers.subscribe`. Headers are
    /// always available at the active tip; impls may panic only if
    /// the chainstate is in a known-impossible state (no genesis).
    fn tip(&self) -> (u32, Header);

    /// Raw consensus-encoded tx bytes for `txid`, or `None` if not
    /// found / not indexed (txindex disabled, or txid never confirmed
    /// and not in mempool).
    fn raw_tx(&self, txid: &Txid) -> Option<Vec<u8>>;

    /// Confirmed location of `txid`. `None` for unconfirmed / unknown.
    fn confirmation(&self, txid: &Txid) -> Option<TxConfirmation>;

    /// Build the Electrum merkle proof for a confirmed `txid`. `None`
    /// for unconfirmed / unknown / when txindex is disabled.
    fn tx_merkle(&self, txid: &Txid) -> Option<TxMerkleProof>;

    /// Return the txid at `tx_pos` within the block at `height`, or
    /// `None` if either is out of range. Used by
    /// `blockchain.transaction.id_from_pos`.
    fn txid_at_pos(&self, height: u32, tx_pos: u32) -> Option<Txid>;
}

/// Confirmation details attached to a tx by [`ElectrumExtras::confirmation`].
#[derive(Debug, Clone, Copy)]
pub struct TxConfirmation {
    pub block_hash: BlockHash,
    pub height: u32,
    pub block_time: u32,
    pub position: u32,
}

/// Result of [`ElectrumExtras::tx_merkle`]. `branch` is the bottom-up
/// sibling sequence in raw 32-byte big-endian form (display-order
/// reversal happens at the wire-shaping layer in
/// [`crate::types::merkle_node_to_hex`]).
#[derive(Debug, Clone)]
pub struct TxMerkleProof {
    pub block_hash: BlockHash,
    pub height: u32,
    pub position: u32,
    pub branch: Vec<bitcoin::TxMerkleNode>,
}

/// `ChainState`-backed [`ElectrumExtras`] implementation. All reads
/// are safe to call from any thread; the underlying `ChainState`
/// already serializes its own internal mutability.
pub struct RocksElectrumExtras {
    chain: Arc<ChainState>,
}

impl RocksElectrumExtras {
    pub fn new(chain: Arc<ChainState>) -> Self {
        Self { chain }
    }
}

impl ElectrumExtras for RocksElectrumExtras {
    fn header_at(&self, height: u32) -> Option<Header> {
        let hash = self.chain.get_block_hash_by_height(height)?;
        let entry = self.chain.get_block_index(&hash)?;
        Some(entry.header)
    }

    fn tip(&self) -> (u32, Header) {
        let height = self.chain.tip_height();
        let hash = self.chain.tip_hash();
        let header = self
            .chain
            .get_block_index(&hash)
            .map(|e| e.header)
            .expect("tip block must have an index entry");
        (height, header)
    }

    fn raw_tx(&self, txid: &Txid) -> Option<Vec<u8>> {
        let hash = self.chain.get_tx_location(txid)?;
        let block = self.chain.get_block(&hash)?;
        let tx = block.txdata.iter().find(|t| t.compute_txid() == *txid)?;
        Some(serialize(tx))
    }

    fn confirmation(&self, txid: &Txid) -> Option<TxConfirmation> {
        let block_hash = self.chain.get_tx_location(txid)?;
        let block = self.chain.get_block(&block_hash)?;
        let entry = self.chain.get_block_index(&block_hash)?;
        let position = block
            .txdata
            .iter()
            .position(|t| t.compute_txid() == *txid)? as u32;
        Some(TxConfirmation {
            block_hash,
            height: entry.height,
            block_time: entry.header.time,
            position,
        })
    }

    fn tx_merkle(&self, txid: &Txid) -> Option<TxMerkleProof> {
        let block_hash = self.chain.get_tx_location(txid)?;
        let block = self.chain.get_block(&block_hash)?;
        let entry = self.chain.get_block_index(&block_hash)?;
        let position = block
            .txdata
            .iter()
            .position(|t| t.compute_txid() == *txid)? as u32;
        let txids: Vec<Txid> = block.txdata.iter().map(|t| t.compute_txid()).collect();
        let branch = compute_merkle_branch(&txids, position as usize);
        Some(TxMerkleProof {
            block_hash,
            height: entry.height,
            position,
            branch,
        })
    }

    fn txid_at_pos(&self, height: u32, tx_pos: u32) -> Option<Txid> {
        let hash = self.chain.get_block_hash_by_height(height)?;
        let block = self.chain.get_block(&hash)?;
        let tx = block.txdata.get(tx_pos as usize)?;
        Some(tx.compute_txid())
    }
}
