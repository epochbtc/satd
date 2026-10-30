//! [`ElectrumExtras`] — the chainstate surface needed by Electrum
//! handlers that lives outside the `node-index` trait.
//!
//! The address index covers scripthash history, balance, and UTXOs.
//! The Electrum protocol additionally needs:
//! - block headers by height (`blockchain.block.header(s)`,
//!   `blockchain.headers.{subscribe,get}`)
//! - a confirmed tx by txid, as stored (`blockchain.transaction.get`)
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
use bitcoin::{BlockHash, Transaction, Txid, Wtxid};

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

    /// The confirmed tx `txid` as stored, or `None` if not found / not
    /// indexed (txindex disabled, or txid never confirmed).
    fn stored_tx(&self, txid: &Txid) -> Option<StoredTx>;

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

/// A confirmed transaction as stored, from [`ElectrumExtras::stored_tx`].
///
/// For a transaction in an OP_RETURN-stripped block, `tx` is the filled form:
/// its size, weight, inputs and output values are the original's, but its
/// bytes are not the transaction's, so they must never be served as such.
/// `txid` and `wtxid` come from the strip record.
#[derive(Debug, Clone)]
pub struct StoredTx {
    pub tx: Transaction,
    pub txid: Txid,
    pub wtxid: Wtxid,
    /// `(vout, original script length)` of each stripped output; `None`
    /// when the transaction is intact.
    pub stripped: Option<Vec<(u32, u64)>>,
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
        // M6 (review round 1): use `tip_snapshot()` so `(hash, height)`
        // come from the same `tip.read()` guard. Two separate
        // `tip_hash()` / `tip_height()` calls could pair an old hash
        // with a new height if a block connects between them, causing
        // `headers.subscribe`'s initial response to mismatch.
        let (hash, height) = self.chain.tip_snapshot();
        let header = self
            .chain
            .get_block_index(&hash)
            .map(|e| e.header)
            .expect("tip block must have an index entry");
        (height, header)
    }

    // Every read below goes through `get_stored_block`, and every txid comes
    // from the stored block: an OP_RETURN-stripped transaction's is in its
    // strip record, and its filled bytes hash to something else.

    fn stored_tx(&self, txid: &Txid) -> Option<StoredTx> {
        let hash = self.chain.get_tx_location(txid)?;
        let mut stored = self.chain.get_stored_block(&hash)?;
        let i = stored.txids().iter().position(|t| t == txid)?;
        Some(StoredTx {
            txid: *txid,
            wtxid: stored.wtxid(i),
            stripped: stored.tx_is_stripped(i).then(|| stored.stripped_outputs(i)),
            tx: stored.block.txdata.swap_remove(i),
        })
    }

    fn confirmation(&self, txid: &Txid) -> Option<TxConfirmation> {
        let block_hash = self.chain.get_tx_location(txid)?;
        let stored = self.chain.get_stored_block(&block_hash)?;
        let entry = self.chain.get_block_index(&block_hash)?;
        let position = stored.txids().iter().position(|t| t == txid)? as u32;
        Some(TxConfirmation {
            block_hash,
            height: entry.height,
            block_time: entry.header.time,
            position,
        })
    }

    fn tx_merkle(&self, txid: &Txid) -> Option<TxMerkleProof> {
        let block_hash = self.chain.get_tx_location(txid)?;
        let stored = self.chain.get_stored_block(&block_hash)?;
        let entry = self.chain.get_block_index(&block_hash)?;
        let txids = stored.txids();
        let position = txids.iter().position(|t| t == txid)? as u32;
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
        let stored = self.chain.get_stored_block(&hash)?;
        let i = tx_pos as usize;
        (i < stored.block.txdata.len()).then(|| stored.txid(i))
    }
}
