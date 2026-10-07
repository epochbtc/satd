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
use crate::index::address::subscribe::SubscriptionRegistry;
use crate::mempool::pool::Mempool;
use node_index::{MempoolTxFacts, history_rows, history_status_hash};

/// How often the notifier prunes empty channels from the registry as a
/// belt-and-suspenders measure on top of the per-subscribe prune.
/// Cheap (O(channels)) and runs alongside the chain-event loop.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// Spawn the chain-driven status-update notifier. Listens on
/// `ChainEvent::BlockConnected` / `BlockDisconnected` and recomputes
/// status hashes only for scripthashes with active subscribers.
///
/// `mempool` is required so the recompute path can tag mempool tx
/// status entries with `-1` for unconfirmed-with-unconfirmed-parents
/// vs `0` for unconfirmed-no-deps (Electrum spec / electrs `Height`).
pub async fn notifier_task(
    index: Arc<RocksAddressIndex>,
    registry: Arc<SubscriptionRegistry>,
    _chain_state: Arc<ChainState>,
    mempool: Arc<Mempool>,
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
                        recompute_all_active(&index, &registry, &mempool);
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        recompute_all_active(&index, &registry, &mempool);
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
    mempool: &Mempool,
) {
    for sh in registry.active_scripthashes() {
        recompute_one(index, registry, mempool, &sh);
    }
}

/// Recompute status_hash for a fixed slice of scripthashes — used by
/// the mempool task immediately after an Enter/Leave mutation. Filters
/// to active subscribers internally so a tx touching scripthashes that
/// no one cares about is a no-op.
pub fn recompute_for(
    index: &RocksAddressIndex,
    registry: &SubscriptionRegistry,
    mempool: &Mempool,
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
            recompute_one(index, registry, mempool, sh);
        }
    }
}

fn recompute_one(
    index: &RocksAddressIndex,
    registry: &SubscriptionRegistry,
    mempool: &Mempool,
    sh: &Scripthash,
) {
    // The status covers the history in Electrum history order, the order
    // `blockchain.scripthash.get_history` lists it in: a client checks the
    // pushed status by hashing that response as it arrived. Building the
    // rows through the same helper as the Electrum handlers keeps the two
    // from drifting apart.
    let Ok(rows) = history_rows(index, sh, usize::MAX, |txid| mempool_facts(mempool, txid))
    else {
        return;
    };
    registry.maybe_notify(*sh, history_status_hash(&rows));
}

/// What a history row needs about a mempool transaction, or `None` once it
/// has left the mempool. Tagged `-1` when it spends an unconfirmed parent
/// (electrs `Height::Unconfirmed { has_unconfirmed_inputs: true }`).
fn mempool_facts(mempool: &Mempool, txid: &bitcoin::Txid) -> Option<MempoolTxFacts> {
    let entry = mempool.get(txid)?;
    Some(MempoolTxFacts {
        has_unconfirmed_inputs: has_unconfirmed_inputs(&entry.tx, mempool),
        fee_sat: entry.fee,
    })
}

/// Returns `true` if `tx` spends at least one output that belongs to
/// another tx currently in `mempool`. Mirrors electrs's
/// `has_unconfirmed_inputs` check inside `Height::compute`.
fn has_unconfirmed_inputs(tx: &bitcoin::Transaction, mempool: &Mempool) -> bool {
    tx.input
        .iter()
        .any(|inp| mempool.get(&inp.previous_output.txid).is_some())
}

#[cfg(test)]
#[path = "notifier_electrumstatus_tests.rs"]
mod electrumstatus_tests;
