use bitcoin::hashes::Hash;
use bitcoin::Block;

use crate::validation::ValidationError;

/// Maximum block weight (4 million weight units, per BIP 141).
const MAX_BLOCK_WEIGHT: usize = 4_000_000;

/// BIP 141 witness commitment header (OP_RETURN + push 36 bytes + magic).
const WITNESS_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// Perform context-free validation checks on a block.
pub fn check_block(block: &Block) -> Result<(), ValidationError> {
    // Block must have at least one transaction
    if block.txdata.is_empty() {
        return Err(ValidationError::EmptyBlock);
    }

    // First transaction must be coinbase
    if !block.txdata[0].is_coinbase() {
        return Err(ValidationError::NoCoinbase);
    }

    // No other transaction may be coinbase
    for tx in &block.txdata[1..] {
        if tx.is_coinbase() {
            return Err(ValidationError::MultipleCoinbase);
        }
    }

    // Check merkle root
    let computed = block.compute_merkle_root();
    match computed {
        Some(root) => {
            if root != block.header.merkle_root {
                return Err(ValidationError::BadMerkleRoot);
            }
        }
        None => {
            return Err(ValidationError::EmptyBlock);
        }
    }

    // Check block weight
    let weight = block.weight().to_wu() as usize;
    if weight > MAX_BLOCK_WEIGHT {
        return Err(ValidationError::OversizedBlock);
    }

    // Check witness commitment (BIP 141)
    check_witness_commitment(block)?;

    Ok(())
}

/// Validate the witness commitment in a block (BIP 141).
/// If any non-coinbase transaction has witness data, the coinbase must contain
/// a valid witness commitment output.
fn check_witness_commitment(block: &Block) -> Result<(), ValidationError> {
    let has_witness = block.txdata[1..].iter().any(|tx| {
        tx.input.iter().any(|i| !i.witness.is_empty())
    });

    if !has_witness {
        return Ok(()); // No witness data, no commitment needed
    }

    // Find the witness commitment in coinbase outputs (last matching one wins)
    let coinbase = &block.txdata[0];
    let mut commitment_hash = None;

    for output in coinbase.output.iter().rev() {
        let script = output.script_pubkey.as_bytes();
        if script.len() >= 38 && script[..6] == WITNESS_COMMITMENT_HEADER {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&script[6..38]);
            commitment_hash = Some(hash);
            break;
        }
    }

    let expected_commitment = match commitment_hash {
        Some(h) => h,
        None => return Err(ValidationError::BadWitnessCommitment),
    };

    // Get the witness nonce from coinbase witness
    let witness_nonce = if !coinbase.input[0].witness.is_empty() {
        let item = coinbase.input[0].witness.nth(0).unwrap_or(&[0u8; 32]);
        if item.len() == 32 {
            let mut nonce = [0u8; 32];
            nonce.copy_from_slice(item);
            nonce
        } else {
            [0u8; 32]
        }
    } else {
        [0u8; 32]
    };

    // Compute witness root from wtxids (coinbase wtxid = 0x00...00)
    let mut wtxid_hashes: Vec<[u8; 32]> = Vec::new();
    wtxid_hashes.push([0u8; 32]); // coinbase
    for tx in &block.txdata[1..] {
        wtxid_hashes.push(tx.compute_wtxid().to_raw_hash().to_byte_array());
    }

    let witness_root = compute_merkle_root_from_hashes(&wtxid_hashes);

    // Compute commitment: SHA256d(witness_root || witness_nonce)
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&witness_root);
    preimage[32..].copy_from_slice(&witness_nonce);
    let computed = bitcoin::hashes::sha256d::Hash::hash(&preimage).to_byte_array();

    if computed != expected_commitment {
        return Err(ValidationError::BadWitnessCommitment);
    }

    Ok(())
}

fn compute_merkle_root_from_hashes(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }

    let mut current = hashes.to_vec();
    while current.len() > 1 {
        if !current.len().is_multiple_of(2) {
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

    #[test]
    fn test_regtest_genesis_passes_check() {
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        assert!(check_block(&genesis).is_ok());
    }

    #[test]
    fn test_mainnet_genesis_passes_check() {
        let genesis = bitcoin::constants::genesis_block(Network::Bitcoin);
        assert!(check_block(&genesis).is_ok());
    }

    #[test]
    fn test_empty_block_rejected() {
        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata.clear();
        assert!(matches!(check_block(&block), Err(ValidationError::EmptyBlock)));
    }
}
