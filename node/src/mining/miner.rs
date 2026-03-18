use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;
use bitcoin::{
    Address, Amount, Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};

use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::mining::template::create_template;

#[derive(Debug, thiserror::Error)]
pub enum MineError {
    #[error("invalid address: {0}")]
    BadAddress(String),
    #[error("mining failed: {0}")]
    Failed(String),
    #[error("block rejected: {0}")]
    Rejected(String),
}

/// Mine a single block on regtest, paying the coinbase to the given address.
pub fn mine_block(
    chain_state: &ChainState,
    mempool: &Mempool,
    address: &str,
) -> Result<Block, MineError> {
    let template = create_template(chain_state, mempool);

    // Parse address and get script_pubkey
    let addr: Address<bitcoin::address::NetworkUnchecked> = address
        .parse()
        .map_err(|e| MineError::BadAddress(format!("{}", e)))?;

    let addr = addr
        .require_network(chain_state.network)
        .map_err(|e| MineError::BadAddress(format!("{}", e)))?;

    let coinbase_script = addr.script_pubkey();

    // Build coinbase transaction
    let mut coinbase_tx = build_coinbase(template.height, template.coinbase_value, &coinbase_script);

    // Assemble non-coinbase transactions
    let other_txs: Vec<Transaction> = template.transactions.iter().map(|t| t.tx.clone()).collect();

    // Check if any transaction has witness data
    let has_witness = other_txs.iter().any(|tx| {
        tx.input.iter().any(|i| !i.witness.is_empty())
    });

    if has_witness {
        // Compute witness commitment (BIP 141)
        let witness_root = compute_witness_root(&coinbase_tx, &other_txs);
        let witness_nonce = [0u8; 32];
        let mut commitment_preimage = [0u8; 64];
        commitment_preimage[..32].copy_from_slice(&witness_root);
        commitment_preimage[32..].copy_from_slice(&witness_nonce);
        let commitment = bitcoin::hashes::sha256d::Hash::hash(&commitment_preimage);

        // Add witness commitment output to coinbase
        let mut commitment_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment_script.extend_from_slice(&commitment.to_byte_array());
        coinbase_tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(commitment_script),
        });

        // Set coinbase witness to single 32-byte zero item
        coinbase_tx.input[0].witness = Witness::from_slice(&[witness_nonce]);
    }

    // Assemble final transaction list
    let mut txdata = vec![coinbase_tx];
    txdata.extend(other_txs);

    // Compute merkle root (uses txids, not wtxids)
    let merkle_root = compute_merkle_root(&txdata);

    // Build header
    let mut header = Header {
        version: Version::from_consensus(template.version),
        prev_blockhash: template.prev_hash,
        merkle_root,
        time: template.cur_time,
        bits: template.bits,
        nonce: 0,
    };

    // Mine: increment nonce until PoW valid
    // On regtest (0x207fffff), almost any nonce works
    loop {
        let target = header.target();
        match header.validate_pow(target) {
            Ok(_) => break,
            Err(_) => {
                header.nonce += 1;
                if header.nonce == 0 {
                    // Wrapped around — try different time
                    header.time += 1;
                }
            }
        }
    }

    let block = Block { header, txdata };

    // Accept the block
    chain_state
        .accept_block(&block)
        .map_err(|e| MineError::Rejected(e.to_string()))?;

    mempool.remove_for_block(&block);

    Ok(block)
}

/// Mine multiple blocks, returning their hashes.
pub fn mine_blocks(
    chain_state: &ChainState,
    mempool: &Mempool,
    address: &str,
    count: u32,
) -> Result<Vec<String>, MineError> {
    let mut hashes = Vec::new();
    for _ in 0..count {
        let block = mine_block(chain_state, mempool, address)?;
        hashes.push(block.block_hash().to_string());
    }
    Ok(hashes)
}

/// Build a coinbase transaction for the given height and value.
fn build_coinbase(height: u32, value: u64, output_script: &ScriptBuf) -> Transaction {
    // BIP 34: height in coinbase scriptSig
    let height_script = Builder::new()
        .push_int(height as i64)
        .push_opcode(opcodes::OP_FALSE) // extra nonce space
        .into_script();

    let coinbase_input = TxIn {
        previous_output: OutPoint::null(),
        script_sig: height_script,
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };

    let coinbase_output = TxOut {
        value: Amount::from_sat(value),
        script_pubkey: output_script.clone(),
    };

    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
        input: vec![coinbase_input],
        output: vec![coinbase_output],
    }
}

/// Compute the merkle root from a list of transactions.
fn compute_merkle_root(txdata: &[Transaction]) -> bitcoin::TxMerkleNode {
    use bitcoin::hashes::Hash;
    let hashes: Vec<bitcoin::Txid> = txdata.iter().map(|tx| tx.compute_txid()).collect();

    if hashes.is_empty() {
        return bitcoin::TxMerkleNode::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32]),
        );
    }

    let mut current: Vec<[u8; 32]> = hashes.iter().map(|h| h.to_raw_hash().to_byte_array()).collect();

    while current.len() > 1 {
        if current.len() % 2 != 0 {
            let last = *current.last().unwrap();
            current.push(last);
        }
        let mut next = Vec::new();
        for i in (0..current.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&current[i]);
            combined[32..].copy_from_slice(&current[i + 1]);
            let hash = bitcoin::hashes::sha256d::Hash::hash(&combined);
            next.push(hash.to_byte_array());
        }
        current = next;
    }

    bitcoin::TxMerkleNode::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
        current[0],
    ))
}

/// Compute witness root from transaction list.
/// Coinbase wtxid is defined as all zeros.
fn compute_witness_root(_coinbase: &Transaction, others: &[Transaction]) -> [u8; 32] {
    let mut hashes: Vec<[u8; 32]> = Vec::new();

    // Coinbase wtxid = 0x00...00
    hashes.push([0u8; 32]);

    // Other transactions use wtxid
    for tx in others {
        hashes.push(tx.compute_wtxid().to_raw_hash().to_byte_array());
    }

    // Compute merkle root from these hashes
    if hashes.is_empty() {
        return [0u8; 32];
    }

    let mut current = hashes;
    while current.len() > 1 {
        if current.len() % 2 != 0 {
            let last = *current.last().unwrap();
            current.push(last);
        }
        let mut next = Vec::new();
        for i in (0..current.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&current[i]);
            combined[32..].copy_from_slice(&current[i + 1]);
            let hash = bitcoin::hashes::sha256d::Hash::hash(&combined);
            next.push(hash.to_byte_array());
        }
        current = next;
    }

    current[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;

    #[test]
    fn test_mine_single_block() {
        let dir = std::env::temp_dir().join(format!("satd-miner-test-{}", std::process::id()));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            None,
        )
        .unwrap();
        let mp = Mempool::new(1_000_000, 0);

        // Use a regtest P2SH address (doesn't matter what for coinbase)
        // bcrt1q... format for regtest bech32
        let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";

        let block = mine_block(&cs, &mp, addr).unwrap();
        assert_eq!(cs.tip_height(), 1);
        assert_eq!(cs.tip_hash(), block.block_hash());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mine_multiple_blocks() {
        let dir = std::env::temp_dir().join(format!(
            "satd-miner-multi-test-{}",
            std::process::id()
        ));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            None,
        )
        .unwrap();
        let mp = Mempool::new(1_000_000, 0);

        let addr = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202";
        let hashes = mine_blocks(&cs, &mp, addr, 10).unwrap();
        assert_eq!(hashes.len(), 10);
        assert_eq!(cs.tip_height(), 10);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
