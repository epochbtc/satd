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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::connect::{block_subsidy, connect_block};
    use crate::storage::coinview::Coin;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFilePos;
    use crate::storage::undo::UndoData;
    use crate::storage::{Store, StoreBatch};
    use crate::validation::script::NoopVerifier;
    use bitcoin::block::Header;
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, Block, BlockHash, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    // ── helpers (duplicated from connect.rs tests, since those are private) ──

    /// Create an InMemoryStore pre-loaded with a single coin.
    fn make_test_store_with_coin(
        coin_height: u32,
        coinbase: bool,
    ) -> (InMemoryStore, OutPoint, Coin) {
        let store = InMemoryStore::new();
        let txid = bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x42; 32]),
        );
        let outpoint = OutPoint { txid, vout: 0 };
        let coin = Coin {
            amount: 50_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: coin_height,
            coinbase,
        };

        let mut batch = StoreBatch::default();
        batch.coin_puts.push((outpoint, coin.clone()));
        store.write_batch(batch).unwrap();

        (store, outpoint, coin)
    }

    /// Build a block with a coinbase and a spending tx that consumes `outpoint`.
    fn make_block_spending(
        outpoint: OutPoint,
        height: u32,
        tx_version: i32,
        sequence: u32,
        locktime: u32,
    ) -> Block {
        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(height as i64)
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();
        let coinbase = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: coinbase_script,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(block_subsidy(height)),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let spending_tx = Transaction {
            version: Version(tx_version),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(locktime),
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence(sequence),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let txdata = vec![coinbase, spending_tx];
        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block
    }

    /// Build a coinbase-only block at the given height.
    fn make_coinbase_only_block(height: u32, prev_blockhash: BlockHash) -> Block {
        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(height as i64)
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();
        let coinbase = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: coinbase_script,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(block_subsidy(height)),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let txdata = vec![coinbase];
        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block
    }

    fn default_pos() -> FlatFilePos {
        FlatFilePos {
            file_number: 0,
            data_pos: 0,
        }
    }

    /// Add a coin to the store at a specific outpoint.
    fn add_coin_to_store(store: &InMemoryStore, outpoint: OutPoint, coin: Coin) {
        let mut batch = StoreBatch::default();
        batch.coin_puts.push((outpoint, coin));
        store.write_batch(batch).unwrap();
    }

    /// Make a unique OutPoint from a single-byte seed.
    fn make_outpoint(seed: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::sha256d::Hash::from_byte_array([seed; 32]),
            ),
            vout,
        }
    }

    // ── tests ────────────────────────────────────────────────────────────

    #[test]
    fn test_disconnect_coinbase_only() {
        // Connect a coinbase-only block at height 1, then disconnect it.
        let store = InMemoryStore::new();
        let prev_hash = BlockHash::all_zeros();
        let block = make_coinbase_only_block(1, prev_hash);
        let block_hash = block.block_hash();

        let connect_batch =
            connect_block(&store, &block, 1, &[0u8; 32], default_pos(), &NoopVerifier, 0)
                .unwrap();

        // Extract undo data (for non-genesis coinbase-only blocks, undo has no spent coins)
        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap_or_default();

        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&block, &undo, 1, prev_hash);

        // coin_removes should contain the coinbase output(s)
        let coinbase_txid = block.txdata[0].compute_txid();
        assert!(
            batch
                .coin_removes
                .iter()
                .any(|op| op.txid == coinbase_txid && op.vout == 0),
            "coin_removes should contain the coinbase output"
        );

        // No spent coins to restore for a coinbase-only block
        assert!(
            batch.coin_puts.is_empty(),
            "coin_puts should be empty for a coinbase-only block (no inputs spent)"
        );

        // Tip should be set to prev_hash
        assert_eq!(batch.tip, Some(prev_hash));
    }

    #[test]
    fn test_disconnect_spending_block() {
        // Create a store with a spendable coin, connect a block spending it, then disconnect.
        let (store, outpoint, _original_coin) = make_test_store_with_coin(0, false);
        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();
        let prev_hash = BlockHash::all_zeros();

        let connect_batch =
            connect_block(&store, &block, 1, &[0u8; 32], default_pos(), &NoopVerifier, 0)
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&block, &undo, 1, prev_hash);

        // The spent coin should be restored
        assert_eq!(batch.coin_puts.len(), 1, "should restore exactly one spent coin");
        assert_eq!(batch.coin_puts[0].0, outpoint);

        // All outputs from both txs should be removed
        let spending_txid = block.txdata[1].compute_txid();
        let coinbase_txid = block.txdata[0].compute_txid();
        assert!(
            batch.coin_removes.iter().any(|op| op.txid == spending_txid),
            "spending tx outputs should be in coin_removes"
        );
        assert!(
            batch.coin_removes.iter().any(|op| op.txid == coinbase_txid),
            "coinbase outputs should be in coin_removes"
        );
    }

    #[test]
    fn test_disconnect_restores_correct_amounts() {
        // Verify the restored coin has the exact same amount and script_pubkey.
        let (store, outpoint, original_coin) = make_test_store_with_coin(0, false);
        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();
        let prev_hash = BlockHash::all_zeros();

        let connect_batch =
            connect_block(&store, &block, 1, &[0u8; 32], default_pos(), &NoopVerifier, 0)
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&block, &undo, 1, prev_hash);

        let (restored_op, restored_coin) = &batch.coin_puts[0];
        assert_eq!(*restored_op, outpoint);
        assert_eq!(restored_coin.amount, original_coin.amount);
        assert_eq!(restored_coin.script_pubkey, original_coin.script_pubkey);
        assert_eq!(restored_coin.height, original_coin.height);
        assert_eq!(restored_coin.coinbase, original_coin.coinbase);
    }

    #[test]
    fn test_disconnect_height_index_cleaned() {
        let block = make_coinbase_only_block(5, BlockHash::all_zeros());
        let undo = UndoData::default();

        let batch = disconnect_block(&block, &undo, 5, BlockHash::all_zeros());

        assert_eq!(batch.height_hash_removes, vec![5]);
    }

    #[test]
    fn test_disconnect_tip_set_to_prev() {
        let prev_hash = BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0xaa; 32]),
        );
        let block = make_coinbase_only_block(3, prev_hash);
        let undo = UndoData::default();

        let batch = disconnect_block(&block, &undo, 3, prev_hash);

        assert_eq!(batch.tip, Some(prev_hash));
    }

    #[test]
    fn test_disconnect_multi_tx() {
        // Block with coinbase + 2 spending transactions.
        // We need 2 coins in the store.
        let store = InMemoryStore::new();
        let op1 = make_outpoint(0x10, 0);
        let op2 = make_outpoint(0x20, 0);
        let coin1 = Coin {
            amount: 30_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: false,
        };
        let coin2 = Coin {
            amount: 20_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: false,
        };
        add_coin_to_store(&store, op1, coin1.clone());
        add_coin_to_store(&store, op2, coin2.clone());

        // Build block: coinbase + tx1 (spends op1) + tx2 (spends op2)
        let height = 1u32;
        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(height as i64)
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();
        let coinbase_tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: coinbase_script,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(block_subsidy(height)),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let tx1 = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op1,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(30_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let tx2 = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op2,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(20_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase_tx, tx1, tx2],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        let block_hash = block.block_hash();
        let connect_batch =
            connect_block(&store, &block, height, &[0u8; 32], default_pos(), &NoopVerifier, 0)
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&block, &undo, height, BlockHash::all_zeros());

        // All 3 txs' outputs should be in coin_removes
        // coinbase has 1 output, tx1 has 1, tx2 has 1 = 3 total
        assert_eq!(batch.coin_removes.len(), 3);

        // The 2 spent coins should be restored
        assert_eq!(batch.coin_puts.len(), 2);
        let restored_ops: Vec<OutPoint> = batch.coin_puts.iter().map(|(op, _)| *op).collect();
        assert!(restored_ops.contains(&op1));
        assert!(restored_ops.contains(&op2));
    }

    #[test]
    fn test_disconnect_multi_input_tx() {
        // Single tx spending 3 different inputs.
        let store = InMemoryStore::new();
        let op1 = make_outpoint(0x31, 0);
        let op2 = make_outpoint(0x32, 0);
        let op3 = make_outpoint(0x33, 0);
        let coin = Coin {
            amount: 10_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: false,
        };
        add_coin_to_store(&store, op1, coin.clone());
        add_coin_to_store(&store, op2, coin.clone());
        add_coin_to_store(&store, op3, coin.clone());

        let height = 1u32;
        let coinbase_script = bitcoin::script::Builder::new()
            .push_int(height as i64)
            .push_opcode(bitcoin::opcodes::OP_FALSE)
            .into_script();
        let coinbase_tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: coinbase_script,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(block_subsidy(height)),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let multi_input_tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: op1,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: op2,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: op3,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(30_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase_tx, multi_input_tx],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        let block_hash = block.block_hash();
        let connect_batch =
            connect_block(&store, &block, height, &[0u8; 32], default_pos(), &NoopVerifier, 0)
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&block, &undo, height, BlockHash::all_zeros());

        // All 3 spent inputs should be restored
        assert_eq!(batch.coin_puts.len(), 3);
        let restored_ops: Vec<OutPoint> = batch.coin_puts.iter().map(|(op, _)| *op).collect();
        assert!(restored_ops.contains(&op1));
        assert!(restored_ops.contains(&op2));
        assert!(restored_ops.contains(&op3));
    }

    #[test]
    fn test_disconnect_preserves_other_utxos() {
        // After applying disconnect batch, UTXOs from other blocks remain untouched.
        let store = InMemoryStore::new();

        // Create an "other" coin that should survive the disconnect.
        let other_op = make_outpoint(0xee, 0);
        let other_coin = Coin {
            amount: 99_000_000,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            height: 0,
            coinbase: false,
        };
        add_coin_to_store(&store, other_op, other_coin.clone());

        // Create a spendable coin for the block.
        let spend_op = make_outpoint(0x42, 0);
        let spend_coin = Coin {
            amount: 50_000_000,
            script_pubkey: bitcoin::ScriptBuf::new(),
            height: 0,
            coinbase: false,
        };
        add_coin_to_store(&store, spend_op, spend_coin);

        let block = make_block_spending(spend_op, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();

        let connect_batch =
            connect_block(&store, &block, 1, &[0u8; 32], default_pos(), &NoopVerifier, 0)
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        store.write_batch(connect_batch).unwrap();

        // The other coin should still be there after connect
        assert!(store.get_coin(&other_op).is_some());

        // Disconnect
        let batch = disconnect_block(&block, &undo, 1, BlockHash::all_zeros());
        store.write_batch(batch).unwrap();

        // The other coin should still be present
        let recovered = store.get_coin(&other_op).unwrap();
        assert_eq!(recovered.amount, other_coin.amount);
        assert_eq!(recovered.script_pubkey, other_coin.script_pubkey);
    }

    #[test]
    fn test_disconnect_then_reconnect() {
        // Disconnect a block, apply the batch, then reconnect the same block.
        // Final state should match the original connected state.
        let (store, outpoint, _coin) = make_test_store_with_coin(0, false);
        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();
        let prev_hash = BlockHash::all_zeros();

        // Connect
        let connect_batch =
            connect_block(&store, &block, 1, &[0u8; 32], default_pos(), &NoopVerifier, 0)
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        // Save coin state after connect for comparison
        store.write_batch(connect_batch).unwrap();
        let coins_after_connect: Vec<(OutPoint, Coin)> = {
            // Collect all coins by checking known outpoints
            let mut coins = Vec::new();
            for tx in &block.txdata {
                let tid = tx.compute_txid();
                for vout in 0..tx.output.len() {
                    let op = OutPoint {
                        txid: tid,
                        vout: vout as u32,
                    };
                    if let Some(c) = store.get_coin(&op) {
                        coins.push((op, c));
                    }
                }
            }
            coins
        };
        // The original spent coin should be gone
        assert!(store.get_coin(&outpoint).is_none());

        // Disconnect
        let disconnect_batch = disconnect_block(&block, &undo, 1, prev_hash);
        store.write_batch(disconnect_batch).unwrap();

        // After disconnect, the original coin should be back
        assert!(store.get_coin(&outpoint).is_some());

        // Reconnect
        let reconnect_batch =
            connect_block(&store, &block, 1, &[0u8; 32], default_pos(), &NoopVerifier, 0)
                .unwrap();
        store.write_batch(reconnect_batch).unwrap();

        // After reconnect, state should match original connected state
        assert!(store.get_coin(&outpoint).is_none(), "spent coin should be gone again");
        for (op, coin) in &coins_after_connect {
            let recovered = store.get_coin(op).expect("coin should exist after reconnect");
            assert_eq!(recovered.amount, coin.amount);
            assert_eq!(recovered.height, coin.height);
        }
    }

    #[test]
    fn test_disconnect_empty_undo() {
        // Coinbase-only block (not genesis) with empty undo data works fine.
        let prev_hash = BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0xbb; 32]),
        );
        let block = make_coinbase_only_block(10, prev_hash);
        let undo = UndoData::default();

        let batch = disconnect_block(&block, &undo, 10, prev_hash);

        // Should still remove coinbase outputs
        assert!(!batch.coin_removes.is_empty());
        // No coins to restore
        assert!(batch.coin_puts.is_empty());
        // Tip and height index should be updated
        assert_eq!(batch.tip, Some(prev_hash));
        assert_eq!(batch.height_hash_removes, vec![10]);
    }

    #[test]
    fn test_disconnect_txindex_removes() {
        // Verify that disconnect doesn't currently populate tx_index_removes.
        // This documents the current behavior: disconnect_block does not clean up
        // the txindex. This may be a gap to fix later.
        let (store, outpoint, _coin) = make_test_store_with_coin(0, false);
        let block = make_block_spending(outpoint, 1, 2, 0xffff_ffff, 0);
        let block_hash = block.block_hash();

        let connect_batch =
            connect_block(&store, &block, 1, &[0u8; 32], default_pos(), &NoopVerifier, 0)
                .unwrap();

        let undo = connect_batch
            .undo_puts
            .iter()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, u)| u.clone())
            .unwrap();

        store.write_batch(connect_batch).unwrap();

        let batch = disconnect_block(&block, &undo, 1, BlockHash::all_zeros());

        // Current implementation does NOT populate tx_index_removes
        assert!(
            batch.tx_index_removes.is_empty(),
            "disconnect_block currently does not populate tx_index_removes"
        );
    }

    #[test]
    fn test_disconnect_via_chain_state() {
        // Use ChainState to build chain A1->A2, then B1->B2->B3 triggering reorg.
        // After reorg, verify the height index is correct for the B chain.
        use crate::chain::state::tests::build_test_block;
        use crate::chain::state::{AssumeValid, ChainState};
        use crate::storage::flatfile::FlatFileManager;

        let dir = std::env::temp_dir().join(format!(
            "satd-disconnect-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let blocks_dir = dir.join("blocks");
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&blocks_dir).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
        )
        .unwrap();

        let genesis_hash = bitcoin::constants::genesis_block(Network::Regtest).block_hash();

        // Build chain A: genesis -> A1 -> A2
        let a1 = build_test_block(genesis_hash, 1, 1_300_000_001);
        let a1_hash = cs.accept_block(&a1).expect("accept A1");
        let a2 = build_test_block(a1_hash, 2, 1_300_000_002);
        let _a2_hash = cs.accept_block(&a2).expect("accept A2");

        // Build chain B: genesis -> B1 -> B2 -> B3 (more work => triggers reorg)
        let b1 = build_test_block(genesis_hash, 1, 1_300_000_003);
        let b1_hash = cs.accept_block(&b1).expect("accept B1");
        let b2 = build_test_block(b1_hash, 2, 1_300_000_004);
        let b2_hash = cs.accept_block(&b2).expect("accept B2");
        let b3 = build_test_block(b2_hash, 3, 1_300_000_005);
        let b3_hash = cs.accept_block(&b3).expect("accept B3");

        // Tip should be B3
        assert_eq!(cs.tip_height(), 3);
        assert_eq!(cs.tip_hash(), b3_hash);

        // After reorg, height index should map to B-chain blocks
        assert_eq!(
            cs.get_block_hash_by_height(0),
            Some(genesis_hash),
            "height 0 should be genesis"
        );
        assert_eq!(
            cs.get_block_hash_by_height(1),
            Some(b1_hash),
            "height 1 should be B1 after reorg"
        );
        assert_eq!(
            cs.get_block_hash_by_height(2),
            Some(b2_hash),
            "height 2 should be B2 after reorg"
        );
        assert_eq!(
            cs.get_block_hash_by_height(3),
            Some(b3_hash),
            "height 3 should be B3 after reorg"
        );

        // A-chain heights should no longer map to A blocks
        // (height 1 and 2 were overwritten by B chain)
        assert_ne!(
            cs.get_block_hash_by_height(1),
            Some(a1_hash),
            "height 1 should NOT be A1 after reorg"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
