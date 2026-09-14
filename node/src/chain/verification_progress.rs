//! `verificationprogress`, computed the way Bitcoin Core computes it.
//!
//! Core's `ChainstateManager::GuessVerificationProgress` (`validation.cpp`,
//! v31.1) estimates the share of all transactions ever confirmed that the
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

/// Each network's `ChainTxData`, copied from Bitcoin Core v31.1
/// `src/kernel/chainparams.cpp`. A custom signet (`-signetchallenge`) has no
/// data, as in Core, and so does not estimate from a snapshot.
pub fn chain_tx_data(network: Network, custom_signet: bool) -> ChainTxData {
    match network {
        // getchaintxstats 4096 00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac
        Network::Bitcoin => ChainTxData {
            time: 1772055173,
            tx_count: 1315805869,
            tx_rate: 5.40111006496122,
        },
        // getchaintxstats 4096 000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4
        Network::Testnet => ChainTxData {
            time: 1772051651,
            tx_count: 536108416,
            tx_rate: 0.02691479016257117,
        },
        // getchaintxstats 4096 0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a
        Network::Testnet4 => ChainTxData {
            time: 1772013387,
            tx_count: 14191421,
            tx_rate: 0.01848579579528412,
        },
        Network::Signet if custom_signet => ChainTxData {
            time: 0,
            tx_count: 0,
            tx_rate: 0.0,
        },
        // getchaintxstats 4096 00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329
        Network::Signet => ChainTxData {
            time: 1772055248,
            tx_count: 28676833,
            tx_rate: 0.06736623436338929,
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

    #[test]
    fn a_recent_tip_is_exactly_one_and_a_newer_header_drops_it() {
        let data = chain_tx_data(Network::Regtest, false);
        let tip = at(200, 1_700_000_000, 201);
        // Two hours after the tip: still "recent", positioned by height.
        assert_eq!(guess_verification_progress(data, tip, 200, 1_700_000_000 + 7200), 1.0);
        // One second later the timestamp is used, and the rate adds work.
        assert!(guess_verification_progress(data, tip, 200, 1_700_000_000 + 7201) < 1.0);
        // A header above the tip moves it back by one spacing.
        assert!(guess_verification_progress(data, tip, 201, 1_700_000_000) < 1.0);
    }

    #[test]
    fn a_custom_signet_has_no_snapshot() {
        assert_eq!(chain_tx_data(Network::Signet, true).tx_count, 0);
        assert_ne!(chain_tx_data(Network::Signet, false).tx_count, 0);
    }
}
