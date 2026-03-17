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

    // Select transactions from mempool by fee rate
    let mut entries = mempool.get_all_entries();
    entries.sort_by(|a, b| b.1.fee_rate.cmp(&a.1.fee_rate));

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;
    use bitcoin::Network;

    #[test]
    fn test_create_empty_template() {
        let dir = std::env::temp_dir().join(format!("btcd-template-test-{}", std::process::id()));
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        let cs = ChainState::new(store, flat_files, Network::Regtest, Box::new(NoopVerifier)).unwrap();
        let mp = Mempool::new(1_000_000, 0);

        let template = create_template(&cs, &mp);

        assert_eq!(template.height, 1);
        assert_eq!(template.bits.to_consensus(), 0x207fffff);
        assert!(template.transactions.is_empty());
        assert_eq!(template.coinbase_value, 50 * 100_000_000); // 50 BTC subsidy

        let _ = std::fs::remove_dir_all(&dir);
    }
}
