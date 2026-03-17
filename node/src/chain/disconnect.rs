use bitcoin::{Block, OutPoint};

use crate::storage::undo::UndoData;
use crate::storage::StoreBatch;

/// Disconnect a block: reverse its effects on the UTXO set.
/// Restores spent coins from undo data and removes created outputs.
pub fn disconnect_block(
    block: &Block,
    undo: &UndoData,
    block_height: u32,
    prev_hash: bitcoin::BlockHash,
) -> StoreBatch {
    let mut batch = StoreBatch::default();

    // Remove outputs created by this block (in reverse order)
    for tx in block.txdata.iter().rev() {
        let txid = tx.compute_txid();
        for (vout, _) in tx.output.iter().enumerate() {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            batch.coin_removes.push(outpoint);
        }
    }

    // Restore spent coins from undo data
    for (op_ser, coin) in &undo.spent_coins {
        let outpoint = op_ser.to_outpoint();
        batch.coin_puts.push((outpoint, coin.clone()));
    }

    // Update tip to previous block and clean height index
    batch.tip = Some(prev_hash);
    batch.height_hash_removes.push(block_height);

    batch
}
