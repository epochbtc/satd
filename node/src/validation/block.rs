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

    // CVE-2012-2459: reject a merkle-mutated block. A tx list that duplicates a
    // trailing subtree (e.g. `[cb, t1, t2, t2]`) yields the SAME merkle root as
    // the honest `[cb, t1, t2]`, so the comparison above passes. Core computes a
    // `mutated` flag inside ComputeMerkleRoot and rejects `bad-txns-duplicate`;
    // we mirror that flag here so the malleated copy is rejected cheaply, at the
    // right stage, rather than later in connect_block as a double-spend.
    if merkle_tree_mutated(block) {
        return Err(ValidationError::BadTxDuplicate);
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

    // Get the witness nonce from the coinbase's first input. `check_block`
    // already rejected a non-coinbase first tx (a coinbase has exactly one
    // input), so `input[0]` is present on the validated path; use `first()`
    // anyway so this function never panics if called in another context.
    let coinbase_witness = coinbase.input.first().map(|i| &i.witness);
    let witness_nonce = if coinbase_witness.is_some_and(|w| !w.is_empty()) {
        let item = coinbase_witness.unwrap().nth(0).unwrap_or(&[0u8; 32]);
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

/// CVE-2012-2459 detection. Mirrors the `mutated` out-flag of Bitcoin Core's
/// `ComputeMerkleRoot`: walking the merkle tree level by level over the block's
/// txids, a merkle root is "mutated" iff at some level two adjacent hashes in an
/// even-indexed pair are equal. The equality is tested BEFORE the odd-length
/// tail is duplicated for that level, so the honest odd-node padding is not
/// itself counted — only a transaction list that already contains the duplicate
/// (the malleated copy of a valid block) trips it.
fn merkle_tree_mutated(block: &Block) -> bool {
    let mut current: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().to_raw_hash().to_byte_array())
        .collect();
    if current.is_empty() {
        return false;
    }
    while current.len() > 1 {
        // Equal adjacent pairs in the current (pre-padding) level signal a
        // duplicated subtree. Check before the odd-tail duplication below.
        let mut i = 0;
        while i + 1 < current.len() {
            if current[i] == current[i + 1] {
                return true;
            }
            i += 2;
        }
        if !current.len().is_multiple_of(2) {
            let last = *current.last().unwrap();
            current.push(last);
        }
        let mut next = Vec::with_capacity(current.len() / 2);
        for j in (0..current.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&current[j]);
            combined[32..].copy_from_slice(&current[j + 1]);
            let hash = bitcoin::hashes::sha256d::Hash::hash(&combined);
            next.push(hash.to_byte_array());
        }
        current = next;
    }
    false
}

/// Detect a "mutated" block per Bitcoin Core's `IsBlockMutated` — the P2P-layer
/// anti-malleation gate, distinct from consensus `check_block`. A block is
/// mutated if its merkle tree is malleable (CVE-2012-2459; see
/// `merkle_tree_mutated`) or it contains a transaction whose non-witness
/// serialized size is exactly 64 bytes. A 64-byte transaction can be
/// reinterpreted as a pair of 32-byte hashes (an internal merkle node),
/// enabling forged merkle proofs against SPV clients. Core refuses to process a
/// mutated block and penalizes the sender, but does NOT mark the block
/// permanently invalid (an honest block sharing the same hash must remain
/// acceptable). satd applies this at block receipt, before acceptance.
pub fn is_block_mutated(block: &Block) -> bool {
    merkle_tree_mutated(block) || block.txdata.iter().any(|tx| tx.base_size() == 64)
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

    #[test]
    fn test_non_coinbase_first_rejected() {
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness, Txid};
        use bitcoin::hashes::Hash as _;

        // Build a tx whose first input is NOT a coinbase (has a real previous_output)
        let non_coinbase = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata = vec![non_coinbase];
        // Fix merkle root so we don't fail on that first
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        assert!(matches!(check_block(&block), Err(ValidationError::NoCoinbase)));
    }

    #[test]
    fn test_multiple_coinbase_rejected() {
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

        let coinbase1 = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from(vec![0x04, 0xff, 0xff, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let coinbase2 = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from(vec![0x04, 0xaa, 0xbb, 0xcc]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(25_0000_0000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata = vec![coinbase1, coinbase2];
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        assert!(matches!(
            check_block(&block),
            Err(ValidationError::MultipleCoinbase)
        ));
    }

    #[test]
    fn test_bad_merkle_root_rejected() {
        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        // Tamper the merkle root
        block.header.merkle_root =
            bitcoin::TxMerkleNode::from_byte_array([0xde; 32]);
        assert!(matches!(
            check_block(&block),
            Err(ValidationError::BadMerkleRoot)
        ));
    }

    #[test]
    fn test_oversized_block_rejected() {
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

        // Create a coinbase with many huge outputs to exceed 4M weight.
        // Each output with a large script_pubkey contributes significantly to weight.
        // A single output with ~33000 bytes of script_pubkey = ~33000 * 4 = ~132000 WU (non-witness).
        // We need ~4M / 132000 ≈ 31 outputs, but let's be generous.
        let mut outputs = Vec::new();
        for _ in 0..40 {
            outputs.push(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::from(vec![0x00; 30_000]),
            });
        }

        let coinbase = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from(vec![0x04, 0xff, 0xff, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: outputs,
        };

        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata = vec![coinbase];
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        assert!(matches!(
            check_block(&block),
            Err(ValidationError::OversizedBlock)
        ));
    }

    #[test]
    fn test_no_witness_no_commitment_ok() {
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
        use bitcoin::hashes::Hash as _;

        let coinbase = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from(vec![0x04, 0xff, 0xff, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        // Non-witness spending tx (no witness data)
        let spending = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::from(vec![0x00; 20]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata = vec![coinbase, spending];
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        assert!(check_block(&block).is_ok());
    }

    #[test]
    fn test_witness_valid_commitment() {
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
        use bitcoin::hashes::Hash as _;

        let witness_nonce = [0u8; 32];

        // Build a spending tx with witness data
        let mut witness = Witness::new();
        witness.push([0x01; 72]); // fake signature
        let spending = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        // Compute witness merkle root: coinbase wtxid = 0x00...00, then spending wtxid
        let wtxid_hashes: Vec<[u8; 32]> = vec![
            [0u8; 32], // coinbase
            spending.compute_wtxid().to_raw_hash().to_byte_array(),
        ];

        let witness_root = compute_merkle_root_from_hashes(&wtxid_hashes);

        // Compute commitment = SHA256d(witness_root || witness_nonce)
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&witness_root);
        preimage[32..].copy_from_slice(&witness_nonce);
        let commitment = bitcoin::hashes::sha256d::Hash::hash(&preimage).to_byte_array();

        // Build the witness commitment script: OP_RETURN + PUSH_36 + magic + commitment
        let mut commitment_script = Vec::with_capacity(38);
        commitment_script.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
        commitment_script.extend_from_slice(&commitment);

        // Coinbase with witness nonce and commitment output
        let mut coinbase_witness = Witness::new();
        coinbase_witness.push(witness_nonce);
        let coinbase = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from(vec![0x04, 0xff, 0xff, 0x00]),
                sequence: Sequence::MAX,
                witness: coinbase_witness,
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: bitcoin::ScriptBuf::from(commitment_script),
                },
            ],
        };

        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata = vec![coinbase, spending];
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        assert!(check_block(&block).is_ok());
    }

    #[test]
    fn test_witness_missing_commitment() {
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
        use bitcoin::hashes::Hash as _;

        // Spending tx WITH witness data
        let mut witness = Witness::new();
        witness.push([0x01; 72]);
        let spending = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        // Coinbase WITHOUT any witness commitment output
        let coinbase = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from(vec![0x04, 0xff, 0xff, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata = vec![coinbase, spending];
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        assert!(matches!(
            check_block(&block),
            Err(ValidationError::BadWitnessCommitment)
        ));
    }

    #[test]
    fn test_witness_wrong_commitment() {
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
        use bitcoin::hashes::Hash as _;

        // Spending tx WITH witness data
        let mut witness = Witness::new();
        witness.push([0x01; 72]);
        let spending = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xab; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        // Build a witness commitment with the WRONG hash (all 0xde bytes)
        let mut wrong_commitment_script = Vec::with_capacity(38);
        wrong_commitment_script.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
        wrong_commitment_script.extend_from_slice(&[0xde; 32]); // wrong hash

        let mut coinbase_witness = Witness::new();
        coinbase_witness.push([0u8; 32]);
        let coinbase = Transaction {
            version: Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from(vec![0x04, 0xff, 0xff, 0x00]),
                sequence: Sequence::MAX,
                witness: coinbase_witness,
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: bitcoin::ScriptBuf::from(wrong_commitment_script),
                },
            ],
        };

        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata = vec![coinbase, spending];
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        assert!(matches!(
            check_block(&block),
            Err(ValidationError::BadWitnessCommitment)
        ));
    }

    // -- CVE-2012-2459 merkle mutation --

    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    fn dummy_spend(seed: u8) -> Transaction {
        Transaction {
            version: TxVersion::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([seed; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn test_merkle_mutation_rejected() {
        // [cb, t1, t2, t2] has the same merkle root as the honest [cb, t1, t2]
        // (the odd-node duplication). check_block must reject bad-txns-duplicate
        // rather than letting the root match and accepting.
        let coinbase = bitcoin::constants::genesis_block(Network::Regtest).txdata[0].clone();
        let t1 = dummy_spend(0x11);
        let t2 = dummy_spend(0x22);
        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata = vec![coinbase, t1, t2.clone(), t2];
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        assert!(matches!(
            check_block(&block),
            Err(ValidationError::BadTxDuplicate)
        ));
    }

    #[test]
    fn test_honest_odd_tx_count_not_mutated() {
        // The honest [cb, t1, t2] (3 txs → odd-node padding at level 0) must NOT
        // be flagged as mutated: the padded duplicate is not a real adjacent pair.
        let coinbase = bitcoin::constants::genesis_block(Network::Regtest).txdata[0].clone();
        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata = vec![coinbase, dummy_spend(0x11), dummy_spend(0x22)];
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        assert!(!merkle_tree_mutated(&block));
        assert!(check_block(&block).is_ok());
    }

    // -- IsBlockMutated (P2P-layer 64-byte / merkle malleation gate) --

    #[test]
    fn test_is_block_mutated_64byte_tx() {
        // A 1-in/1-out tx serializes (no witness) to 60 bytes + the output
        // script length; a 4-byte output script makes it exactly 64 bytes — the
        // merkle-node-confusion vector. is_block_mutated must flag it even though
        // the block is otherwise well-formed (correct merkle root, no dup txs).
        let coinbase = bitcoin::constants::genesis_block(Network::Regtest).txdata[0].clone();
        let tx64 = Transaction {
            version: TxVersion::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x33; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::from(vec![0x6a, 0x00, 0x00, 0x00]),
            }],
        };
        assert_eq!(tx64.base_size(), 64, "test setup: tx must be 64 base bytes");
        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata = vec![coinbase, tx64];
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        assert!(is_block_mutated(&block));
    }

    #[test]
    fn test_is_block_mutated_flags_merkle_mutation() {
        // The CVE-2012-2459 case is also covered by is_block_mutated.
        let coinbase = bitcoin::constants::genesis_block(Network::Regtest).txdata[0].clone();
        let t2 = dummy_spend(0x22);
        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata = vec![coinbase, dummy_spend(0x11), t2.clone(), t2];
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        assert!(is_block_mutated(&block));
    }

    #[test]
    fn test_honest_block_not_mutated() {
        // The plain regtest genesis block (coinbase only) is not mutated.
        let block = bitcoin::constants::genesis_block(Network::Regtest);
        assert!(!is_block_mutated(&block));
    }
}
