use bitcoin::hashes::Hash;
use bitcoin::{Block, Network};

use crate::validation::script::activation_heights;
use crate::validation::ValidationError;

/// Maximum block weight (4 million weight units, per BIP 141).
const MAX_BLOCK_WEIGHT: usize = 4_000_000;

/// BIP 141 witness commitment header (OP_RETURN + push 36 bytes + magic).
const WITNESS_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// Validate a block's structure and its BIP 141 witness data.
///
/// This is Bitcoin Core's `CheckBlock` (structure, merkle root, CVE-2012-2459
/// mutation, weight) plus the witness half of `ContextualCheckBlock`
/// ([`check_witness_rules`]). Core splits the two because it reaches them at
/// different points; satd keeps them together so that *every* caller which
/// validates a block gets both halves.
///
/// The witness rules are gated on segwit activation exactly as Core gates them
/// on `DEPLOYMENT_SEGWIT`, which is why this is not context-free: it needs
/// `network` and `height` to decide. Threading them through the signature
/// rather than reading them from an optional argument is deliberate — the
/// compiler makes a new caller supply the context instead of silently
/// inheriting the laxer, context-free behaviour.
pub fn check_block(
    block: &Block,
    network: Network,
    height: u32,
) -> Result<(), ValidationError> {
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

    // Check block weight.
    //
    // Core runs this AFTER the witness rules below, because it can mark a
    // block permanently failed: an attacker who pads the coinbase witness
    // inflates the weight without changing the block hash, so weighing first
    // would let a mutated copy poison the index against the honest block.
    // satd never persists a verdict from this function — a rejected block
    // leaves no `block_index` entry, and only the `invalidateblock` RPC ever
    // marks a hash `Invalid` — so the cheap check can stay first. If a failure
    // here ever becomes durable, this ordering must flip to Core's.
    let weight = block.weight().to_wu() as usize;
    if weight > MAX_BLOCK_WEIGHT {
        return Err(ValidationError::OversizedBlock);
    }

    // Witness commitment (BIP 141), height-gated as Core gates it.
    check_witness_rules(block, height >= activation_heights(network).segwit)?;

    Ok(())
}

/// The witness half of Bitcoin Core's `ContextualCheckBlock`, rule for rule.
///
/// Two rules, and a block is subject to exactly one of them:
///
/// - **A commitment output is present** (and segwit is active at this height):
///   the coinbase witness must be exactly one 32-byte item — Core's
///   `bad-witness-nonce-size` — and the BIP 141 commitment must verify.
/// - **Otherwise**: no transaction may carry witness data at all, coinbase
///   *included* — Core's `unexpected-witness`.
///
/// Together they pin the block's entire serialization. The header's merkle
/// root commits to txids, and so authenticates every non-witness byte, but
/// nothing in the block hash covers witnesses. The first rule closes that: the
/// commitment covers every non-coinbase witness (their wtxids feed the witness
/// root) and the nonce (the other input to the commitment hash), while the
/// coinbase wtxid is hardcoded to zero. The second rule closes the case where
/// there is no commitment to lean on.
///
/// Both halves used to be laxer than Core (issue #538), and in both the
/// *coinbase* side was what was missing:
///
/// - the `unexpected-witness` scan ran over `txdata[1..]`, so witness data
///   hung off the coinbase input alone was accepted;
/// - there was no nonce-size rule at all — [`verify_witness_commitment`] took
///   witness item 0 when it happened to be 32 bytes and silently substituted
///   an all-zero nonce otherwise. Since Core mines a zero nonce, that fallback
///   *is* the real value for essentially the whole chain, so a coinbase
///   witness could be truncated, padded with junk items, or dropped entirely
///   and the commitment would still recompute;
/// - the commitment was only verified when some non-coinbase transaction
///   carried witness data, so a witness-stripped copy of a segwit block —
///   same block hash, same merkle root — skipped the check outright.
///
/// Each of those accepts a block Core rejects as `BLOCK_MUTATED`: a chain
/// split with satd on the losing side. They also matter for any path that
/// *stores* the bytes without re-running scripts (`repair_block_data`), where
/// a non-canonical copy would be persisted as authoritative, re-accepted by a
/// later `-reindex`, and grounds for every Core peer to ban us the moment we
/// served that block.
///
/// `segwit_active` gates the first rule exactly as Core gates it on
/// `DEPLOYMENT_SEGWIT`, so a pre-activation block whose coinbase happens to
/// carry a commitment-shaped `OP_RETURN` — mainnet has these, from miners
/// running segwit-ready software before lock-in — is judged by the second rule
/// and is not spuriously rejected.
fn check_witness_rules(block: &Block, segwit_active: bool) -> Result<(), ValidationError> {
    let mut commits_to_witnesses = false;

    if segwit_active && has_witness_commitment_output(block) {
        // `has_witness_commitment_output` only returns true for a non-empty
        // `txdata`, so the coinbase is present here.
        let coinbase_witness = block.txdata[0].input.first().map(|i| &i.witness);
        let nonce = coinbase_witness
            .filter(|w| w.len() == 1)
            .and_then(|w| w.nth(0))
            .and_then(|item| <[u8; 32]>::try_from(item).ok())
            .ok_or(ValidationError::BadWitnessNonceSize)?;
        verify_witness_commitment(block, nonce)?;
        commits_to_witnesses = true;
    }

    if !commits_to_witnesses
        && block
            .txdata
            .iter()
            .any(|tx| tx.input.iter().any(|i| !i.witness.is_empty()))
    {
        return Err(ValidationError::UnexpectedWitness);
    }

    Ok(())
}

/// Whether the coinbase carries a BIP 141 witness-commitment output.
pub fn has_witness_commitment_output(block: &Block) -> bool {
    block
        .txdata
        .first()
        .is_some_and(|coinbase| {
            coinbase.output.iter().any(|output| {
                let script = output.script_pubkey.as_bytes();
                script.len() >= 38 && script[..6] == WITNESS_COMMITMENT_HEADER
            })
        })
}

/// Verify the BIP 141 commitment against a caller-validated 32-byte nonce.
///
/// Taking the nonce as a parameter is what keeps [`check_witness_rules`]'
/// `bad-witness-nonce-size` rule from being quietly re-opened here: there is
/// no way to reach this code with a coinbase witness that Core would have
/// rejected, and no fallback value to substitute when one is missing.
///
/// Runs unconditionally once a commitment output is present — no "the block
/// carries no witnesses, so there is nothing to check" short-circuit. That
/// short-circuit is what let a peer hand back a *witness-stripped* copy of a
/// segwit block: the merkle root commits to txids only, so stripping every
/// witness leaves the block hash and merkle root intact and the check skipped.
/// A genuinely witness-free block that carries a commitment output is still
/// accepted rather than rejected — with no witnesses every wtxid equals its
/// txid, so the commitment recomputes and matches.
fn verify_witness_commitment(
    block: &Block,
    witness_nonce: [u8; 32],
) -> Result<(), ValidationError> {
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
        assert!(check_block(&genesis, Network::Regtest, 0).is_ok());
    }

    #[test]
    fn test_mainnet_genesis_passes_check() {
        let genesis = bitcoin::constants::genesis_block(Network::Bitcoin);
        assert!(check_block(&genesis, Network::Regtest, 0).is_ok());
    }

    #[test]
    fn test_empty_block_rejected() {
        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        block.txdata.clear();
        assert!(matches!(check_block(&block, Network::Regtest, 0), Err(ValidationError::EmptyBlock)));
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

        assert!(matches!(check_block(&block, Network::Regtest, 0), Err(ValidationError::NoCoinbase)));
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
            check_block(&block, Network::Regtest, 0),
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
            check_block(&block, Network::Regtest, 0),
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
            check_block(&block, Network::Regtest, 0),
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

        assert!(check_block(&block, Network::Regtest, 0).is_ok());
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

        assert!(check_block(&block, Network::Regtest, 0).is_ok());
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

        // Core's verdict for "witness data, no commitment output" is
        // `unexpected-witness`, not `bad-witness-merkle-match`: with no
        // commitment there is nothing to match against. satd reported the
        // latter until issue #538.
        assert!(matches!(
            check_block(&block, Network::Regtest, 0),
            Err(ValidationError::UnexpectedWitness)
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
            check_block(&block, Network::Regtest, 0),
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
            check_block(&block, Network::Regtest, 0),
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
        assert!(check_block(&block, Network::Regtest, 0).is_ok());
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

    /// A segwit block whose coinbase carries a valid BIP 141 commitment and
    /// whose single spend carries witness data. Mirrors the construction in
    /// `test_witness_valid_commitment`.
    fn segwit_block_with_commitment() -> Block {
        use bitcoin::hashes::Hash as _;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

        let witness_nonce = [0u8; 32];

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

        let wtxid_hashes: Vec<[u8; 32]> = vec![
            [0u8; 32],
            spending.compute_wtxid().to_raw_hash().to_byte_array(),
        ];
        let witness_root = compute_merkle_root_from_hashes(&wtxid_hashes);
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&witness_root);
        preimage[32..].copy_from_slice(&witness_nonce);
        let commitment = bitcoin::hashes::sha256d::Hash::hash(&preimage).to_byte_array();

        let mut commitment_script = Vec::with_capacity(38);
        commitment_script.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
        commitment_script.extend_from_slice(&commitment);

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
        block
    }

    /// Segwit-active and segwit-inactive contexts for the fixtures below.
    ///
    /// Mainnet's boundary is used rather than regtest's always-on 0 so the
    /// pair also pins the gate against Core's `consensus.SegwitHeight`.
    const SEGWIT_ON: (Network, u32) = (Network::Bitcoin, 481_824);
    const SEGWIT_OFF: (Network, u32) = (Network::Bitcoin, 481_823);

    fn check(block: &Block, ctx: (Network, u32)) -> Result<(), ValidationError> {
        check_block(block, ctx.0, ctx.1)
    }

    /// Stripping every witness from a segwit block leaves the txids — and so
    /// the merkle root and the block hash — untouched. satd used to accept the
    /// result: its commitment check short-circuited on "no witnesses present"
    /// (issue #538). Core rejects it as `BLOCK_MUTATED`.
    #[test]
    fn witness_stripped_block_is_rejected() {
        let block = segwit_block_with_commitment();
        assert!(check(&block, SEGWIT_ON).is_ok(), "the honest block is valid");

        let mut stripped = block.clone();
        for tx in &mut stripped.txdata {
            for input in &mut tx.input {
                input.witness = bitcoin::Witness::new();
            }
        }

        // The strip is invisible to everything the block hash commits to.
        assert_eq!(
            stripped.block_hash(),
            block.block_hash(),
            "stripping witnesses must not change the block hash — that is why \
             the hash alone cannot authenticate a block body"
        );
        assert_eq!(stripped.header.merkle_root, block.header.merkle_root);
        assert!(
            stripped.txdata.iter().any(|tx| tx.input.iter().any(|i| i.witness.is_empty())),
            "the fixture must actually be stripped"
        );

        assert!(
            matches!(
                check(&stripped, SEGWIT_ON),
                Err(ValidationError::BadWitnessNonceSize)
            ),
            "a witness-stripped copy must be rejected, as Core rejects it"
        );
    }

    /// Nothing in the block commits to the *coinbase* witness — the merkle
    /// root covers txids, and the coinbase wtxid is hardcoded to zero in the
    /// witness root — so a peer could append junk to it, shorten it, or drop
    /// it, and the block hash, merkle root and commitment were all unchanged.
    /// Core's `bad-witness-nonce-size` is what closes this; satd had no
    /// equivalent (issue #538).
    #[test]
    fn coinbase_witness_forgeries_are_rejected() {
        let honest = segwit_block_with_commitment();
        assert!(check(&honest, SEGWIT_ON).is_ok());

        // Every case below is the genuine block with only the coinbase
        // witness altered.
        let mut extra_item = honest.clone();
        extra_item.txdata[0].input[0].witness.push([0xde; 900]);

        let mut short_item = honest.clone();
        short_item.txdata[0].input[0].witness = bitcoin::Witness::new();
        short_item.txdata[0].input[0].witness.push([0x11; 7]);

        let mut no_witness = honest.clone();
        no_witness.txdata[0].input[0].witness = bitcoin::Witness::new();

        for (label, forged) in [
            ("junk appended after the nonce", extra_item),
            ("nonce replaced with a 7-byte item", short_item),
            ("coinbase witness dropped entirely", no_witness),
        ] {
            assert_eq!(
                forged.block_hash(),
                honest.block_hash(),
                "{label}: the forgery must be invisible to the block hash — \
                 that is what makes it dangerous"
            );
            assert!(
                bitcoin::consensus::serialize(&forged)
                    != bitcoin::consensus::serialize(&honest),
                "{label}: the fixture must actually change the serialized bytes"
            );
            assert!(
                matches!(
                    check(&forged, SEGWIT_ON),
                    Err(ValidationError::BadWitnessNonceSize)
                ),
                "{label}: must be rejected"
            );
        }
    }

    /// The second half of the rule: a block that commits to no witnesses must
    /// carry none — including on the coinbase, which is exactly where satd's
    /// `txdata[1..]` scan was blind (issue #538).
    #[test]
    fn witness_injected_into_a_commitment_less_block_is_rejected() {
        let mut block = bitcoin::constants::genesis_block(Network::Regtest);
        assert!(!has_witness_commitment_output(&block));
        assert!(check(&block, SEGWIT_ON).is_ok());
        let honest_hash = block.block_hash();

        block.txdata[0].input[0].witness.push([0xab; 64]);
        assert_eq!(
            block.block_hash(),
            honest_hash,
            "injecting a coinbase witness must not change the block hash"
        );
        assert!(
            matches!(
                check(&block, SEGWIT_ON),
                Err(ValidationError::UnexpectedWitness)
            ),
            "a block committing to no witnesses must carry none"
        );
    }

    /// A commitment output demands a verified commitment even when no
    /// transaction in the block carries witness data. satd used to skip the
    /// check entirely in that case (issue #538); Core does not.
    #[test]
    fn wrong_commitment_is_rejected_even_with_no_witness_transactions() {
        let mut block = segwit_block_with_commitment();
        for tx in &mut block.txdata[1..] {
            for input in &mut tx.input {
                input.witness = bitcoin::Witness::new();
            }
        }
        // The commitment still covers the pre-strip wtxid set, so it is now
        // wrong for this block — and no witness data remains to hint at it.
        assert!(has_witness_commitment_output(&block));
        assert_eq!(block.txdata[0].input[0].witness.len(), 1);
        assert!(
            !block.txdata[1..]
                .iter()
                .any(|tx| tx.input.iter().any(|i| !i.witness.is_empty())),
            "the fixture must carry no non-coinbase witnesses"
        );
        assert!(matches!(
            check(&block, SEGWIT_ON),
            Err(ValidationError::BadWitnessCommitment)
        ));
    }

    /// The strict nonce rule is gated on segwit activation exactly as Core
    /// gates it on `DEPLOYMENT_SEGWIT`, so a pre-activation block whose
    /// coinbase happens to carry a commitment-shaped `OP_RETURN` — mainnet has
    /// these — is not spuriously rejected, and an honest peer serving one is
    /// not banned for it.
    #[test]
    fn pre_segwit_block_with_a_commitment_shaped_output_is_not_rejected() {
        let mut block = segwit_block_with_commitment();
        // Pre-segwit serialization: no witnesses anywhere.
        for tx in &mut block.txdata {
            for input in &mut tx.input {
                input.witness = bitcoin::Witness::new();
            }
        }
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        assert!(has_witness_commitment_output(&block));
        assert!(
            check(&block, SEGWIT_OFF).is_ok(),
            "one block below mainnet's segwit height the commitment output is \
             just an OP_RETURN"
        );
        // ...and at the activation height the same block is refused, because a
        // commitment then demands a well-formed nonce.
        assert!(matches!(
            check(&block, SEGWIT_ON),
            Err(ValidationError::BadWitnessNonceSize)
        ));
    }

    /// A real mainnet block shape: a commitment plus a zero nonce and no
    /// witness transactions. It must still pass — the rule pins the coinbase
    /// witness to one 32-byte item, it does not require that item to be
    /// non-zero or that the block carry witness transactions.
    #[test]
    fn committed_block_with_no_witness_transactions_is_accepted() {
        use bitcoin::hashes::Hash as _;

        let mut block = segwit_block_with_commitment();
        // Strip the spend's witness but keep the coinbase's 32-byte nonce,
        // then rebuild the commitment over the resulting wtxid set.
        for tx in &mut block.txdata[1..] {
            for input in &mut tx.input {
                input.witness = bitcoin::Witness::new();
            }
        }
        let wtxid_hashes: Vec<[u8; 32]> = std::iter::once([0u8; 32])
            .chain(
                block.txdata[1..]
                    .iter()
                    .map(|tx| tx.compute_wtxid().to_raw_hash().to_byte_array()),
            )
            .collect();
        let witness_root = compute_merkle_root_from_hashes(&wtxid_hashes);
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&witness_root);
        // The fixture's nonce is 32 zero bytes, which is what Core mines.
        let commitment = bitcoin::hashes::sha256d::Hash::hash(&preimage).to_byte_array();
        let mut script = Vec::with_capacity(38);
        script.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
        script.extend_from_slice(&commitment);
        let last = block.txdata[0].output.len() - 1;
        block.txdata[0].output[last].script_pubkey = bitcoin::ScriptBuf::from(script);
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        assert!(has_witness_commitment_output(&block));
        assert_eq!(block.txdata[0].input[0].witness.len(), 1);
        assert!(
            check(&block, SEGWIT_ON).is_ok(),
            "a committed block with a zero nonce and no witness txs is the \
             common mainnet shape and must pass"
        );
    }
}
