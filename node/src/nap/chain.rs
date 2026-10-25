//! The node's chain state as a NAP [`ChainView`].

use bitcoin::{Amount, BlockHash, OutPoint};

use super::publisher::ChainSource;
use super::{ChainView, Coin};
use crate::chain::state::ChainState;

/// [`ChainState`] read directly. Only meaningful inside
/// [`ChainState::coherent_read`], which is what [`ChainSource::read`] runs
/// it under: the tip, the block hashes and the coins are then one state.
struct View<'a>(&'a ChainState);

impl ChainView for View<'_> {
    fn network(&self) -> bitcoin::Network {
        self.0.network
    }

    fn tip_height(&self) -> u32 {
        self.0.tip_height()
    }

    fn block_hash(&self, height: u32) -> Option<BlockHash> {
        self.0.active_chain_hash_at_height_indexed(height)
    }

    fn median_time_past(&self, height: u32) -> u32 {
        self.0.get_median_time_past(height)
    }

    fn coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.0.get_coin(outpoint).map(|c| Coin {
            value: Amount::from_sat(c.amount),
            script_pubkey: c.script_pubkey,
            height: c.height,
            coinbase: c.coinbase,
        })
    }

    fn utxo_total(&self) -> Amount {
        // The store's running total, kept with the coins, so a report reads
        // it without walking the set.
        Amount::from_sat(self.0.coin_total_amount())
    }
}

impl ChainSource for ChainState {
    fn read<T>(&self, read: &dyn Fn(&dyn ChainView) -> T) -> Option<T> {
        self.coherent_read(|| read(&View(self)))
    }
}

/// How often [`follow_tip`] checks the tip without an event. Blocks that
/// initial block download connects emit no chain event.
const TIP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Judge the publisher's attestations at each new tip until `shutdown`.
/// Skipped during initial block download, when the tip moves too fast for
/// it to matter; the first tip after it catches up.
pub async fn follow_tip(
    publisher: std::sync::Arc<super::publisher::Publisher>,
    chain: std::sync::Arc<ChainState>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let c = chain.clone();
    follow_tip_with(chain, shutdown, move || publisher.on_tip(&*c)).await
}

/// Judge the aggregator's set at each new tip until `shutdown`, as
/// [`follow_tip`] does the publisher's.
pub async fn follow_tip_aggregate(
    aggregate: std::sync::Arc<super::collect::Collector>,
    chain: std::sync::Arc<ChainState>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let c = chain.clone();
    follow_tip_with(chain, shutdown, move || {
        aggregate.aggregate().on_tip(&*c);
    })
    .await
}

/// Run `pass` on a blocking thread at each new tip until `shutdown`, outside
/// initial block download.
async fn follow_tip_with(
    chain: std::sync::Arc<ChainState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    pass: impl Fn() + Send + Sync + 'static,
) {
    let pass = std::sync::Arc::new(pass);
    let mut events = chain.subscribe_chain_events();
    let mut poll = tokio::time::interval(TIP_POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut judged = chain.tip_snapshot();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            event = next_event(&mut events) => {
                if event.is_none() {
                    // The sender is gone; the tip poll carries on alone.
                    events = None;
                    continue;
                }
                // A burst of connects needs one pass, not one per block.
                if let Some(rx) = events.as_mut() {
                    while rx.try_recv().is_ok() {}
                }
            }
            _ = poll.tick() => {}
        }
        let tip = chain.tip_snapshot();
        if tip == judged || chain.is_initial_block_download() {
            continue;
        }
        let p = pass.clone();
        judge_at(tip, &mut judged, move || p()).await;
    }
}

/// Run `pass` on a blocking thread, and record `tip` as judged only if it
/// finished: a pass that panicked is tried again at the next poll, not left
/// until the tip moves.
async fn judge_at<T: Copy, F: FnOnce() + Send + 'static>(tip: T, judged: &mut T, pass: F) {
    match tokio::task::spawn_blocking(pass).await {
        Ok(()) => *judged = tip,
        Err(_) => tracing::error!(target: "nap", "NAP: judging attestations at the new tip panicked; will retry"),
    }
}

async fn next_event(
    events: &mut Option<tokio::sync::broadcast::Receiver<crate::chain::events::ChainEvent>>,
) -> Option<()> {
    use tokio::sync::broadcast::error::RecvError;
    let Some(rx) = events.as_mut() else {
        return std::future::pending().await;
    };
    match rx.recv().await {
        Ok(_) | Err(RecvError::Lagged(_)) => Some(()),
        Err(RecvError::Closed) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::judge_at;

    #[tokio::test]
    async fn a_pass_that_panics_is_not_recorded_as_judged() {
        let mut judged = 1u32;
        judge_at(2, &mut judged, || panic!("a failed pass")).await;
        assert_eq!(judged, 1, "retried at the next poll");
        judge_at(2, &mut judged, || {}).await;
        assert_eq!(judged, 2);
    }
}
