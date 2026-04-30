//! Background task: fans chain + mempool events into per-scripthash
//! status updates.
//!
//! The notifier maintains the contract that subscribers see exactly
//! one update per scripthash per "true state change" — duplicate
//! triggers (e.g. an unrelated block extending the chain) are
//! filtered by the `SubscriptionRegistry` last-seen cache.
//!
//! Optimization: only scripthashes with at least one active
//! subscriber are recomputed. A block touching 50 000 scripthashes
//! whose user count is 5 means 5 sha256 recomputations per block,
//! not 50 000.

use std::sync::{Arc, RwLock};

use tokio::sync::broadcast;

use crate::chain::events::ChainEvent;
use crate::chain::state::ChainState;
use crate::index::address::keys::Scripthash;
use crate::index::address::lookups::RocksAddressIndex;
use crate::index::address::mempool::MempoolAddrIndex;
use crate::index::address::subscribe::{SubscriptionRegistry, status_hash};
use crate::index::address::trait_def::AddressIndex;
use crate::mempool::events::MempoolEvent;

/// Spawn the per-scripthash status-update notifier. Subscribes to
/// chain + mempool events and recomputes status hashes only for
/// scripthashes with active subscribers.
///
/// `index` provides the read-side (used to recompute status hash).
/// `registry` is the per-scripthash subscriber registry.
/// `mempool_idx` is the in-memory mempool variant — used to short-
/// circuit "does any active scripthash care about this txid?"
pub async fn notifier_task(
    index: Arc<RocksAddressIndex>,
    registry: Arc<SubscriptionRegistry>,
    mempool_idx: Arc<RwLock<MempoolAddrIndex>>,
    _chain_state: Arc<ChainState>,
    mut chain_rx: broadcast::Receiver<ChainEvent>,
    mut mempool_rx: broadcast::Receiver<MempoolEvent>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
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
                        recompute_all_active(&index, &registry, &mempool_idx);
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        recompute_all_active(&index, &registry, &mempool_idx);
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
            mempool_event = mempool_rx.recv() => {
                match mempool_event {
                    Ok(event) => {
                        // For mempool events we narrow the recompute
                        // to only the scripthashes that the touched
                        // txid actually maps to. The MempoolAddrIndex
                        // already maintains txid → scripthashes (the
                        // `by_txid` inverse), so this is O(1) in
                        // typical fan-out.
                        let touched_txid = *event.txid();
                        let touched: Vec<Scripthash> = {
                            // First check active subscribers — no point
                            // narrowing if no one subscribed.
                            let active = registry.active_scripthashes();
                            if active.is_empty() {
                                Vec::new()
                            } else {
                                // Resolve the scripthashes the tx
                                // touched. The `by_txid` map holds
                                // them post-add; on remove events the
                                // entry has already been dropped, so
                                // we fall back to "recompute all
                                // active" for those.
                                let idx = mempool_idx.read().unwrap();
                                let touched_for_tx = idx.scripthashes_for(&touched_txid);
                                drop(idx);
                                if touched_for_tx.is_empty() {
                                    active
                                } else {
                                    // Intersect with active subscribers.
                                    let active_set: std::collections::HashSet<Scripthash> =
                                        active.iter().copied().collect();
                                    touched_for_tx
                                        .into_iter()
                                        .filter(|sh| active_set.contains(sh))
                                        .collect()
                                }
                            }
                        };
                        for sh in &touched {
                            recompute_one(&index, &registry, sh);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Lagged on mempool: recompute all active so
                        // we converge on the truth even though we
                        // missed the per-tx narrowing window.
                        recompute_all_active(&index, &registry, &mempool_idx);
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

fn recompute_all_active(
    index: &RocksAddressIndex,
    registry: &SubscriptionRegistry,
    _mempool_idx: &Arc<RwLock<MempoolAddrIndex>>,
) {
    for sh in registry.active_scripthashes() {
        recompute_one(index, registry, &sh);
    }
}

fn recompute_one(
    index: &RocksAddressIndex,
    registry: &SubscriptionRegistry,
    sh: &Scripthash,
) {
    // Confirmed history → (height, txid) pairs.
    let confirmed: Vec<(u32, bitcoin::Txid)> = match index.confirmed_history(sh) {
        Ok(entries) => entries
            .into_iter()
            .map(|e| (e.height(), e.txid()))
            .collect(),
        Err(_) => return,
    };
    let mempool: Vec<bitcoin::Txid> = index
        .mempool_history(sh)
        .into_iter()
        .map(|e| e.txid)
        .collect();
    let h = status_hash(&confirmed, &mempool);
    registry.maybe_notify(*sh, h);
}
