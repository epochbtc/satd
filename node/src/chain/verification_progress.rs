//! `verificationprogress`, computed the way Bitcoin Core computes it.
//!
//! Core's `ChainstateManager::GuessVerificationProgress` (`validation.cpp`,
//! v32.1) estimates the share of all transactions ever confirmed that the
//! chain up to a block contains. Each network carries a `ChainTxData`
//! snapshot, a cumulative transaction count at a known time plus the rate
//! transactions have arrived at since. The count at the block comes from the
//! block index. A block within two hours of the clock is positioned by its
//! height against the best header instead of its timestamp, so a synced node
//! reports exactly 1.0 and falls below it the moment a new header arrives.
//!
//! satd used to report the tip's timestamp divided by the current time, both
//! in seconds since 1970. A node at genesis read about 0.69, and a year of
//! blocks moved the figure by under two points.

use bitcoin::Network;

/// Core's `ChainTxData`: the cumulative transaction count at `time`, and the
/// rate, in transactions per second, assumed after it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChainTxData {
    pub time: i64,
    pub tx_count: u64,
    pub tx_rate: f64,
}

/// Core's `nPowTargetSpacing`, the same on every network.
const POW_TARGET_SPACING: i64 = 10 * 60;

/// The window inside which a block is positioned by height, not timestamp.
const RECENT_WINDOW_SECS: i64 = 2 * 60 * 60;

/// Each network's `ChainTxData`, copied from Bitcoin Core v32.1
/// `src/kernel/chainparams.cpp` (`git show v32.1:src/kernel/chainparams.cpp`).
/// Regtest's is unchanged since v31.1. A custom signet (`-signetchallenge`) has no
/// data, as in Core, and so does not estimate from a snapshot.
pub fn chain_tx_data(network: Network, custom_signet: bool) -> ChainTxData {
    match network {
        // getchaintxstats 4096 00000000000000000000748969ec33043c0e52a763c6dd5193861f559f2c72e3
        Network::Bitcoin => ChainTxData {
            time: 1788925573,
            tx_count: 1434982600,
            tx_rate: 7.851784479579372,
        },
        // getchaintxstats 4096 00000000b318a3703d14a844c55ef507f4c2fc8f8766e24271fd43c180c51637
        Network::Testnet => ChainTxData {
            time: 1788932318,
            tx_count: 536748780,
            tx_rate: 0.02306697351149596,
        },
        // getchaintxstats 4096 0000000021df65b91665a342e26ceb05e54826ad7d8fcd40316230058fa3b865
        Network::Testnet4 => ChainTxData {
            time: 1788932739,
            tx_count: 14825119,
            tx_rate: 0.1148250171344748,
        },
        Network::Signet if custom_signet => ChainTxData {
            time: 0,
            tx_count: 0,
            tx_rate: 0.0,
        },
        // getchaintxstats 4096 00000002a5e0ba0498f1e9f4591af0b66b63c654665efe65206fd0ae7bbaf923
        Network::Signet => ChainTxData {
            time: 1788925860,
            tx_count: 32273793,
            tx_rate: 0.3977566114505673,
        },
        // Core: "Set a non-zero rate to make it testable".
        _ => ChainTxData {
            time: 0,
            tx_count: 0,
            tx_rate: 0.001,
        },
    }
}

/// What the estimate needs to know about one block.
#[derive(Debug, Clone, Copy)]
pub struct BlockPosition {
    pub height: u32,
    pub time: u32,
    /// Transactions from genesis through this block, or `None` when the
    /// index has no count for it yet, which Core reports as 0.0.
    pub chain_tx_count: Option<u64>,
}

/// Core's `GuessVerificationProgress`, operation for operation: the same
/// integer and floating-point steps in the same order, so the result matches
/// Core's bit for bit.
///
/// `best_header_height` is the height of the best known header, and `now` the
/// node clock (mockable, like Core's `NodeClock`).
pub fn guess_verification_progress(
    data: ChainTxData,
    block: BlockPosition,
    best_header_height: u32,
    now: i64,
) -> f64 {
    let chain_tx_count = match block.chain_tx_count {
        Some(n) if n > 0 => n,
        _ => return 0.0,
    };
    let block_time_raw = i64::from(block.time);
    let block_time = if (now - block_time_raw).abs() <= RECENT_WINDOW_SECS
        && best_header_height >= block.height
    {
        now - i64::from(best_header_height - block.height) * POW_TARGET_SPACING
    } else {
        block_time_raw
    };

    let tx_total: f64 = if chain_tx_count <= data.tx_count {
        data.tx_count as f64 + (now - data.time) as f64 * data.tx_rate
    } else {
        chain_tx_count as f64 + (now - block_time) as f64 * data.tx_rate
    };

    (chain_tx_count as f64 / tx_total).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(height: u32, time: u32, count: u64) -> BlockPosition {
        BlockPosition {
            height,
            time,
            chain_tx_count: Some(count),
        }
    }

    #[test]
    fn an_unset_count_is_zero_as_in_core() {
        let data = chain_tx_data(Network::Bitcoin, false);
        let block = BlockPosition {
            height: 5,
            time: 1231006505,
            chain_tx_count: None,
        };
        assert_eq!(guess_verification_progress(data, block, 5, 1789000000), 0.0);
        let zero = BlockPosition {
            chain_tx_count: Some(0),
            ..block
        };
        assert_eq!(guess_verification_progress(data, zero, 5, 1789000000), 0.0);
    }

    /// The defect this replaces: timestamp over clock read 0.688 at genesis.
    #[test]
    fn genesis_on_mainnet_is_nowhere_near_two_thirds() {
        let data = chain_tx_data(Network::Bitcoin, false);
        let p = guess_verification_progress(data, at(0, 1231006505, 1), 0, 1789000000);
        assert!(p < 1e-8, "{p}");
    }

    /// A count at or below the snapshot's is measured against the snapshot
    /// projected to now, as Core's `GuessVerificationProgress` does.
    #[test]
    fn a_block_below_the_snapshot_is_measured_against_the_projected_total() {
        let data = chain_tx_data(Network::Bitcoin, false);
        let now = 1789000000;
        let p = guess_verification_progress(data, at(0, 1231006505, 1), 0, now);
        let projected = 1434982600.0 + (now - 1788925573) as f64 * 7.851784479579372;
        assert_eq!(p, 1.0 / projected);
    }

    #[test]
    fn a_recent_tip_is_exactly_one_and_a_newer_header_drops_it() {
        let data = chain_tx_data(Network::Regtest, false);
        let tip = at(200, 1_700_000_000, 201);
        // Two hours after the tip: still "recent", positioned by height.
        assert_eq!(
            guess_verification_progress(data, tip, 200, 1_700_000_000 + 7200),
            1.0
        );
        // One second later the timestamp is used, and the rate adds work.
        assert!(guess_verification_progress(data, tip, 200, 1_700_000_000 + 7201) < 1.0);
        // A header above the tip moves it back by one spacing.
        assert!(guess_verification_progress(data, tip, 201, 1_700_000_000) < 1.0);
    }

    /// Every network's data, pinned to Bitcoin Core v32.1
    /// (`src/kernel/chainparams.cpp` at tag `v32.1`, each `chainTxData`).
    #[test]
    fn chain_tx_data_is_core_v32_1() {
        let pinned = [
            (Network::Bitcoin, 1788925573, 1434982600, 7.851784479579372),
            (Network::Testnet, 1788932318, 536748780, 0.02306697351149596),
            (Network::Testnet4, 1788932739, 14825119, 0.1148250171344748),
            (Network::Signet, 1788925860, 32273793, 0.3977566114505673),
            (Network::Regtest, 0, 0, 0.001),
        ];
        for (network, time, tx_count, tx_rate) in pinned {
            assert_eq!(
                chain_tx_data(network, false),
                ChainTxData {
                    time,
                    tx_count,
                    tx_rate,
                },
                "{network:?}"
            );
        }
        assert_eq!(
            chain_tx_data(Network::Signet, true),
            ChainTxData {
                time: 0,
                tx_count: 0,
                tx_rate: 0.0,
            }
        );
    }

    #[test]
    fn a_custom_signet_has_no_snapshot() {
        assert_eq!(chain_tx_data(Network::Signet, true).tx_count, 0);
        assert_ne!(chain_tx_data(Network::Signet, false).tx_count, 0);
    }
}
