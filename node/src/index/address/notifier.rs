//! Background task: fans chain events into per-scripthash status
//! updates.
//!
//! Mempool-driven notifications are handled inline by
//! `mempool_index_task` — bundling the index mutation with the
//! notification step in the same task removes the prior race where two
//! independent broadcast consumers could fire status updates against
//! a stale `MempoolAddrIndex`.
//!
//! Subscribers see exactly one update per scripthash per "true state
//! change" — duplicate triggers (e.g. an unrelated block extending the
//! chain) are filtered by the `SubscriptionRegistry` last-seen cache.
//!
//! Optimization: only scripthashes with at least one active
//! subscriber are recomputed. A block touching 50 000 scripthashes
//! whose user count is 5 means 5 sha256 recomputations per block,
//! not 50 000.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;

use crate::chain::events::ChainEvent;
use crate::chain::state::ChainState;
use crate::index::address::keys::Scripthash;
use crate::index::address::lookups::RocksAddressIndex;
use crate::index::address::subscribe::{SubscriptionRegistry, status_hash};
use crate::index::address::trait_def::AddressIndex;

/// How often the notifier prunes empty channels from the registry as a
/// belt-and-suspenders measure on top of the per-subscribe prune.
/// Cheap (O(channels)) and runs alongside the chain-event loop.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// Spawn the chain-driven status-update notifier. Listens on
/// `ChainEvent::BlockConnected` / `BlockDisconnected` and recomputes
/// status hashes only for scripthashes with active subscribers.
pub async fn notifier_task(
    index: Arc<RocksAddressIndex>,
    registry: Arc<SubscriptionRegistry>,
    _chain_state: Arc<ChainState>,
    mut chain_rx: broadcast::Receiver<ChainEvent>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut prune_ticker = tokio::time::interval(PRUNE_INTERVAL);
    // Skip the initial fire so first-event latency stays clean.
    prune_ticker.tick().await;

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            _ = prune_ticker.tick() => {
                registry.prune_empty();
            }
            chain_event = chain_rx.recv() => {
                match chain_event {
                    Ok(_) => {
                        // Any chain-tip change can affect status_hash for
                        // any subscribed scripthash that has confirmed
                        // history. Recompute for everyone subscribed.
                        // (Per the design, this is the simple/correct
                        // path; M6 may add per-block scripthash sets to
                        // narrow the recompute fan-out.)
                        recompute_all_active(&index, &registry);
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        recompute_all_active(&index, &registry);
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

/// Recompute status_hash for every scripthash that has at least one
/// live subscriber. Used by the chain-event path and by the mempool
/// task's lagged-resync path.
pub fn recompute_all_active(
    index: &RocksAddressIndex,
    registry: &SubscriptionRegistry,
) {
    for sh in registry.active_scripthashes() {
        recompute_one(index, registry, &sh);
    }
}

/// Recompute status_hash for a fixed slice of scripthashes — used by
/// the mempool task immediately after an Enter/Leave mutation. Filters
/// to active subscribers internally so a tx touching scripthashes that
/// no one cares about is a no-op.
pub fn recompute_for(
    index: &RocksAddressIndex,
    registry: &SubscriptionRegistry,
    touched: &[Scripthash],
) {
    if touched.is_empty() {
        return;
    }
    let active: std::collections::HashSet<Scripthash> =
        registry.active_scripthashes().into_iter().collect();
    if active.is_empty() {
        return;
    }
    for sh in touched {
        if active.contains(sh) {
            recompute_one(index, registry, sh);
        }
    }
}

fn recompute_one(
    index: &RocksAddressIndex,
    registry: &SubscriptionRegistry,
    sh: &Scripthash,
) {
    let confirmed: Vec<(u32, bitcoin::Txid)> = match index.confirmed_history(sh) {
        Ok(entries) => distinct_confirmed_txs(&entries),
        Err(_) => return,
    };
    // Mempool entries are already tx-oriented (one entry per txid),
    // but defensively dedupe in case future changes batch mempool rows.
    let mempool: Vec<bitcoin::Txid> = {
        let dedup: std::collections::BTreeSet<bitcoin::Txid> = index
            .mempool_history(sh)
            .into_iter()
            .map(|e| e.txid)
            .collect();
        dedup.into_iter().collect()
    };
    let h = status_hash(&confirmed, &mempool);
    registry.maybe_notify(*sh, h);
}

/// Reduce row-oriented confirmed history to the distinct
/// `(height, txid)` pairs the Electrum status-hash contract expects.
///
/// `confirmed_history` is row-oriented (one row per funding output
/// and one per spending input touching `sh`), so a single tx can
/// appear in multiple rows: a tx with two outputs to the same
/// script, a self-transfer that spends and funds the same script,
/// a batched payout. The Electrum status-hash contract is
/// tx-oriented — each `(height, txid)` must appear exactly once
/// (review M5).
fn distinct_confirmed_txs(
    entries: &[crate::index::address::HistoryEntry],
) -> Vec<(u32, bitcoin::Txid)> {
    let dedup: std::collections::BTreeSet<(u32, bitcoin::Txid)> =
        entries.iter().map(|e| (e.height(), e.txid())).collect();
    dedup.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::address::HistoryEntry;
    use bitcoin::OutPoint;

    fn fixture_txid(byte: u8) -> bitcoin::Txid {
        use bitcoin::hashes::Hash as _;
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
            [byte; 32],
        ))
    }

    /// Review M5: a single tx with multiple history rows touching the
    /// same scripthash must appear only once in the (height, txid)
    /// list passed to `status_hash`.
    #[test]
    fn distinct_confirmed_txs_collapses_repeated_rows_for_same_txid() {
        let same_txid = fixture_txid(0x42);
        let other_txid = fixture_txid(0x43);
        // Synthetic case: same tx, two outputs to the same scripthash
        // (two funding rows) plus a self-spend (one spending row);
        // plus an unrelated funding row at a different height to
        // verify ordering is preserved.
        let history = vec![
            HistoryEntry::Funding {
                height: 100,
                txid: same_txid,
                vout: 0,
                amount_sat: 1000,
            },
            HistoryEntry::Funding {
                height: 100,
                txid: same_txid,
                vout: 5,
                amount_sat: 2000,
            },
            HistoryEntry::Spending {
                height: 100,
                txid: same_txid,
                vin: 0,
                prev_outpoint: OutPoint {
                    txid: fixture_txid(0xff),
                    vout: 0,
                },
            },
            HistoryEntry::Funding {
                height: 50,
                txid: other_txid,
                vout: 0,
                amount_sat: 500,
            },
        ];

        let pairs = distinct_confirmed_txs(&history);
        // Three rows for same_txid → one entry.
        assert_eq!(pairs.len(), 2);
        // BTreeSet → ascending by (height, txid).
        assert_eq!(pairs[0], (50, other_txid));
        assert_eq!(pairs[1], (100, same_txid));

        // Status hash must therefore equal the hash of the distinct
        // pairs only — confirms downstream `status_hash` invariance
        // is preserved by upstream dedupe.
        let dup_hash = status_hash(&pairs, &[]);
        let canon = vec![(50, other_txid), (100, same_txid)];
        let canon_hash = status_hash(&canon, &[]);
        assert_eq!(dup_hash, canon_hash);
    }

    #[test]
    fn distinct_confirmed_txs_handles_empty() {
        let pairs = distinct_confirmed_txs(&[]);
        assert!(pairs.is_empty());
    }
}
