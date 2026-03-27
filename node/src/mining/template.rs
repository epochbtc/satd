use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::{BlockHash, Transaction};

use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;

/// Maximum block weight (4 million weight units).
const MAX_BLOCK_WEIGHT: usize = 4_000_000;
/// Reserve weight for coinbase transaction.
const COINBASE_WEIGHT_RESERVE: usize = 4_000;

/// A selected transaction for the block template.
pub struct TemplateTx {
    pub tx: Transaction,
    pub fee: u64,
    pub weight: usize,
}

/// Block template ready for mining.
pub struct BlockTemplate {
    pub version: i32,
    pub prev_hash: BlockHash,
    pub height: u32,
    pub bits: CompactTarget,
    pub cur_time: u32,
    pub transactions: Vec<TemplateTx>,
    pub coinbase_value: u64,
}

/// Create a block template from the current chain state and mempool.
pub fn create_template(chain_state: &ChainState, mempool: &Mempool) -> BlockTemplate {
    let tip_hash = chain_state.tip_hash();
    let tip_entry = chain_state.get_block_index(&tip_hash).unwrap();
    let height = tip_entry.height + 1;
    let subsidy = crate::chain::connect::block_subsidy(height);

    // Determine bits (difficulty)
    let bits = match chain_state.network {
        bitcoin::Network::Regtest => CompactTarget::from_consensus(0x207fffff),
        _ => tip_entry.header.bits, // Simplified; full retarget in pow.rs
    };

    // Select transactions from mempool by effective fee rate (includes fee_delta)
    let mut entries = mempool.get_all_entries();
    entries.sort_by(|a, b| {
        let eff_a = (a.1.fee as i64 + a.1.fee_delta).max(0) as u64 * 1000
            / a.1.weight.max(1) as u64;
        let eff_b = (b.1.fee as i64 + b.1.fee_delta).max(0) as u64 * 1000
            / b.1.weight.max(1) as u64;
        eff_b.cmp(&eff_a)
    });

    let mut transactions = Vec::new();
    let mut total_weight = COINBASE_WEIGHT_RESERVE;
    let mut total_fees = 0u64;

    for (_txid, entry) in entries {
        if total_weight + entry.weight > MAX_BLOCK_WEIGHT {
            continue;
        }
        total_weight += entry.weight;
        total_fees += entry.fee;
        transactions.push(TemplateTx {
            tx: entry.tx,
            fee: entry.fee,
            weight: entry.weight,
        });
    }

    // Timestamp: max of current time and parent time + 1
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let cur_time = std::cmp::max(now, tip_entry.header.time + 1);

    BlockTemplate {
        version: 0x20000000, // BIP 9 version bits
        prev_hash: tip_hash,
        height,
        bits,
        cur_time,
        transactions,
        coinbase_value: subsidy + total_fees,
    }
}

/// Compute merkle root from a list of 32-byte hashes.
fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
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

/// Compute the default witness commitment hex for a block template.
/// Returns the full OP_RETURN script hex (6a24aa21a9ed + 32-byte commitment).
/// Returns empty string if no transactions have witness data.
pub fn compute_witness_commitment_hex(txs: &[TemplateTx]) -> String {
    let has_witness = txs
        .iter()
        .any(|ttx| ttx.tx.input.iter().any(|i| !i.witness.is_empty()));
    if !has_witness {
        return String::new();
    }

    // Coinbase wtxid = 0x00...00, then wtxids of included transactions
    let mut hashes: Vec<[u8; 32]> = vec![[0u8; 32]];
    for ttx in txs {
        hashes.push(ttx.tx.compute_wtxid().to_raw_hash().to_byte_array());
    }
    let witness_root = merkle_root(&hashes);

    // commitment = SHA256d(witness_root || witness_nonce)
    let witness_nonce = [0u8; 32];
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&witness_root);
    preimage[32..].copy_from_slice(&witness_nonce);
    let commitment = bitcoin::hashes::sha256d::Hash::hash(&preimage);

    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(&commitment.to_byte_array());
    hex::encode(script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::state::AssumeValid;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;
    use bitcoin::Network;

    #[test]
    fn test_create_empty_template() {
        let dir = std::env::temp_dir().join(format!("satd-template-test-{}", std::process::id()));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(store, flat_files, Network::Regtest, Box::new(NoopVerifier), AssumeValid::Disabled, 450, 4).unwrap();
        let mp = Mempool::new(1_000_000, 0);

        let template = create_template(&cs, &mp);

        assert_eq!(template.height, 1);
        assert_eq!(template.bits.to_consensus(), 0x207fffff);
        assert!(template.transactions.is_empty());
        assert_eq!(template.coinbase_value, 50 * 100_000_000); // 50 BTC subsidy

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_template_env() -> (ChainState, Mempool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "satd-template-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(
            store,
            flat_files,
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
        4,
        )
        .unwrap();
        let mp = Mempool::new(1_000_000, 0);
        (cs, mp, dir)
    }

    #[test]
    fn test_template_height_increments() {
        let (cs, mp, dir) = make_template_env();

        let template = create_template(&cs, &mp);
        // At genesis (height 0), the next block should be height 1
        assert_eq!(template.height, cs.tip_height() + 1);
        assert_eq!(template.height, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_template_coinbase_subsidy_only() {
        let (cs, mp, dir) = make_template_env();

        let template = create_template(&cs, &mp);
        let expected_subsidy = crate::chain::connect::block_subsidy(template.height);
        // With empty mempool, coinbase_value should equal the subsidy alone
        assert_eq!(template.coinbase_value, expected_subsidy);
        assert_eq!(template.coinbase_value, 50 * 100_000_000);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_template_bits_regtest() {
        let (cs, mp, dir) = make_template_env();

        let template = create_template(&cs, &mp);
        assert_eq!(template.bits.to_consensus(), 0x207fffff);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_template_prev_hash() {
        let (cs, mp, dir) = make_template_env();

        let tip_hash = cs.tip_hash();
        let template = create_template(&cs, &mp);
        // Template's prev_hash must be the current tip hash
        assert_eq!(template.prev_hash, tip_hash);
        // At genesis, that should be the regtest genesis hash
        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        assert_eq!(template.prev_hash, genesis.block_hash());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
