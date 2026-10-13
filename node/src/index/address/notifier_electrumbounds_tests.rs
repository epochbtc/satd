//! Where the status recompute runs, and how often.
//!
//! A recompute reads every subscribed scripthash's history from the index:
//! synchronous RocksDB work, as long as the busiest subscribed history.
//! Run inline in the notifier tasks it held a runtime worker for that long
//! on every block and on every mempool event touching a subscription. The
//! store here sleeps inside each history read, which is what a long read
//! looks like to the runtime; on a current-thread runtime a read on the
//! runtime's own thread stops everything else on it, so a short sleep in
//! the test body shows whether the read ran there.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash as _;
use bitcoin::{BlockHash, Network, Txid};
use parking_lot::RwLock;
use tokio::sync::{broadcast, watch};

use super::notifier_task;
use crate::chain::events::ChainEvent;
use crate::chain::state::{AssumeValid, ChainState};
use crate::index::address::config::AddressIndexConfig;
use crate::index::address::keys::Scripthash;
use crate::index::address::lookups::RocksAddressIndex;
use crate::index::address::mempool::{MempoolAddrIndex, NotifyBundle, mempool_index_task};
use crate::index::address::trait_def::AddressIndex;
use crate::index::address::types::StatusUpdate;
use crate::mempool::events::{EvictReason, MempoolEvent};
use crate::mempool::pool::Mempool;
use crate::storage::Store;
use crate::storage::db::InMemoryStore;
use crate::storage::flatfile::FlatFileManager;
use crate::storage::test_store::{ControllableStore, StoreControls};
use crate::validation::script::NoopVerifier;

const SH: Scripthash = [0x5b; 32];
const READ: Duration = Duration::from_millis(800);

struct Fixture {
    index: Arc<RocksAddressIndex>,
    mempool_index: Arc<RwLock<MempoolAddrIndex>>,
    controls: StoreControls,
    chain: Arc<ChainState>,
    mempool: Arc<Mempool>,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let store = ControllableStore::new();
    let controls = store.controls();
    let mempool_index = Arc::new(RwLock::new(MempoolAddrIndex::new()));
    let index = Arc::new(RocksAddressIndex::with_mempool_index(
        Arc::new(store) as Arc<dyn Store>,
        AddressIndexConfig::default(),
        mempool_index.clone(),
    ));
    let dir = tempfile::TempDir::new().unwrap();
    let chain = Arc::new(
        ChainState::new(
            Box::new(InMemoryStore::new()),
            FlatFileManager::new(&dir.path().join("blocks")).unwrap(),
            Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            16,
            1,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap(),
    );
    Fixture {
        index,
        mempool_index,
        controls,
        chain,
        mempool: Arc::new(Mempool::new(1_000_000, 0)),
        _dir: dir,
    }
}

fn block(height: u32) -> ChainEvent {
    ChainEvent::BlockConnected {
        hash: BlockHash::from_byte_array([height as u8; 32]),
        height,
    }
}

/// How long a 50 ms sleep in the test body takes. Far longer means the
/// runtime's only thread was busy with something else meanwhile.
async fn short_sleep() -> Duration {
    let started = Instant::now();
    tokio::time::sleep(Duration::from_millis(50)).await;
    started.elapsed()
}

async fn next_push(rx: &mut broadcast::Receiver<StatusUpdate>) -> StatusUpdate {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("no status push within 10s")
        .expect("a status push")
}

#[tokio::test(flavor = "current_thread")]
async fn a_block_recompute_does_not_run_on_the_runtime_thread() {
    let f = fixture();
    let mut rx = f.index.subscribe(SH).unwrap();
    let (chain_tx, chain_rx) = broadcast::channel(16);
    let (sd_tx, sd_rx) = watch::channel(false);
    tokio::spawn(notifier_task(
        f.index.clone(),
        f.index.subscription_registry(),
        f.chain.clone(),
        f.mempool.clone(),
        chain_rx,
        sd_rx,
    ));
    tokio::task::yield_now().await;

    f.controls.set_addr_read_delay(READ);
    chain_tx.send(block(1)).unwrap();
    let slept = short_sleep().await;
    assert!(
        slept < READ / 2,
        "a 50ms sleep took {slept:?}: the recompute's history read ran on the runtime thread"
    );
    next_push(&mut rx).await;
    sd_tx.send(true).unwrap();
}

/// Each recompute reads the index as it stands, so it covers every block
/// event queued before it starts. Running one per queued event repeated the
/// same work, and during IBD or after a reorg that is one full pass over
/// every subscribed history per block.
#[tokio::test(flavor = "current_thread")]
async fn queued_block_events_share_one_recompute() {
    let f = fixture();
    let mut rx = f.index.subscribe(SH).unwrap();
    let (chain_tx, chain_rx) = broadcast::channel(16);
    for height in 1..=5 {
        chain_tx.send(block(height)).unwrap();
    }
    let (sd_tx, sd_rx) = watch::channel(false);
    tokio::spawn(notifier_task(
        f.index.clone(),
        f.index.subscription_registry(),
        f.chain.clone(),
        f.mempool.clone(),
        chain_rx,
        sd_rx,
    ));
    next_push(&mut rx).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        f.controls.addr_reads(),
        1,
        "five queued block events should cost one pass over the subscribed histories"
    );

    // A block after that pass gets a pass of its own.
    chain_tx.send(block(6)).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(f.controls.addr_reads(), 2);
    sd_tx.send(true).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn a_mempool_recompute_does_not_run_on_the_runtime_thread() {
    let f = fixture();
    let txid = Txid::from_byte_array([0x77; 32]);
    f.mempool_index.write().add_tx(txid, &[(SH, 1_000)], &[]);
    let mut rx = f.index.subscribe(SH).unwrap();
    let (event_tx, event_rx) = broadcast::channel(16);
    let (sd_tx, sd_rx) = watch::channel(false);
    tokio::spawn(mempool_index_task(
        f.mempool_index.clone(),
        f.mempool.clone(),
        f.chain.clone(),
        event_rx,
        sd_rx,
        Some(NotifyBundle {
            index: f.index.clone(),
            registry: f.index.subscription_registry(),
        }),
    ));
    tokio::task::yield_now().await;

    f.controls.set_addr_read_delay(READ);
    event_tx
        .send(MempoolEvent::LeaveEvicted {
            txid,
            reason: EvictReason::Expiry,
        })
        .unwrap();
    let slept = short_sleep().await;
    assert!(
        slept < READ / 2,
        "a 50ms sleep took {slept:?}: the recompute's history read ran on the runtime thread"
    );
    next_push(&mut rx).await;
    sd_tx.send(true).unwrap();
}
