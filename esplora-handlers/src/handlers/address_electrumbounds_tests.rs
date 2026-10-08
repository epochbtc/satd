//! Address routes do their index reads on the blocking pool.
//!
//! The index here sleeps the thread inside `confirmed_history`, which is
//! what a long read of a busy script looks like to the runtime. The clients
//! are blocking sockets on their own OS threads, so what they measure does
//! not depend on the runtime under test having a free worker.

use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bitcoin::{Network, OutPoint, Txid};
use node::chain::state::{AssumeValid, ChainState};
use node::mempool::fee::FeeEstimator;
use node::mempool::pool::Mempool;
use node::storage::db::InMemoryStore;
use node::storage::flatfile::FlatFileManager;
use node::validation::script::NoopVerifier;
use node_index::{
    AddressIndex, HistoryEntry, IndexError, MempoolHistoryEntry, Scripthash, SpendIndex,
    SpendingRef, StatusUpdate, SubscribeError, Utxo,
};
use tokio::sync::{Semaphore, broadcast};

use crate::config::EsploraConfig;
use crate::router::build_router;
use crate::state::EsploraState;
use crate::work_permits_for;

/// How long the slow index holds its thread.
const SLOW: Duration = Duration::from_millis(1_500);

/// An address index whose history read sleeps for `delay_ms` and counts
/// itself.
#[derive(Default)]
struct SlowIndex {
    delay_ms: AtomicU64,
    reads: AtomicU64,
}

impl AddressIndex for SlowIndex {
    fn confirmed_history(&self, _sh: &Scripthash) -> Result<Vec<HistoryEntry>, IndexError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(self.delay_ms.load(Ordering::SeqCst)));
        Ok(Vec::new())
    }
    fn mempool_history(&self, _sh: &Scripthash) -> Vec<MempoolHistoryEntry> {
        Vec::new()
    }
    fn balance(&self, _sh: &Scripthash) -> Result<(u64, i64), IndexError> {
        Ok((0, 0))
    }
    fn utxos(&self, _sh: &Scripthash) -> Result<Vec<Utxo>, IndexError> {
        Ok(Vec::new())
    }
    fn subscribe(&self, _sh: Scripthash) -> Result<broadcast::Receiver<StatusUpdate>, SubscribeError> {
        Err(SubscribeError::CapReached(0))
    }
}

struct NoSpends;

impl SpendIndex for NoSpends {
    fn spend_of(&self, _outpoint: &OutPoint) -> Result<Option<SpendingRef>, IndexError> {
        Ok(None)
    }
    fn spends_of_tx(&self, _txid: &Txid) -> Result<Vec<(u32, SpendingRef)>, IndexError> {
        Ok(Vec::new())
    }
}

struct NoBroadcast;

impl node::net::manager::TxBroadcaster for NoBroadcast {
    fn submit_and_announce(
        &self,
        _tx: bitcoin::Transaction,
        _source: node::mempool::pool::TxSource,
        _allow_quarantined: bool,
    ) -> Result<Txid, node::mempool::pool::MempoolError> {
        unreachable!("no test broadcasts")
    }
}

/// An Esplora listener over an empty regtest chain and `index`, served on
/// the runtime the test runs on.
async fn serve(
    index: Arc<SlowIndex>,
    request_timeout: Duration,
    max_concurrency: usize,
) -> (SocketAddr, tempfile::TempDir) {
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
    let config = EsploraConfig {
        request_timeout,
        max_concurrency,
        ..Default::default()
    };
    let state = EsploraState {
        chain,
        mempool: Arc::new(Mempool::new(1_000_000, 0)),
        tx_broadcaster: Arc::new(NoBroadcast),
        address_index: index,
        spend_index: Arc::new(NoSpends),
        fee_estimator: Arc::new(FeeEstimator::new()),
        network: Network::Regtest,
        config: Arc::new(config),
        sse_semaphore: Arc::new(Semaphore::new(16)),
        work_permits: work_permits_for(max_concurrency),
    };
    let router = build_router(state).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (addr, dir)
}

/// A one-shot `GET` on a blocking socket: the status code and how long the
/// answer took.
fn get(addr: SocketAddr, path: &str) -> (u16, Duration) {
    let started = Instant::now();
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(stream, "GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP status in {response:?}"));
    (status, started.elapsed())
}

/// Run `client` on its own OS thread and re-raise its panic, if any.
async fn on_thread(client: impl FnOnce() + Send + 'static) {
    let handle = std::thread::spawn(client);
    if let Err(panic) = tokio::task::spawn_blocking(move || handle.join()).await.unwrap() {
        std::panic::resume_unwind(panic);
    }
}

const SH_PATH: &str = "/scripthash/1111111111111111111111111111111111111111111111111111111111111111";

/// One runtime worker, as on a small box: a slow address read must not
/// hold the worker every other Esplora request (and Electrum, gRPC and
/// `/metrics`) runs on.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_slow_address_read_does_not_hold_up_other_requests() {
    let index = Arc::new(SlowIndex::default());
    index.delay_ms.store(SLOW.as_millis() as u64, Ordering::SeqCst);
    let (addr, _dir) = serve(index, Duration::from_secs(30), 256).await;

    on_thread(move || {
        let slow = std::thread::spawn(move || get(addr, &format!("{SH_PATH}/txs/chain")));
        // Let the slow request reach the index.
        std::thread::sleep(Duration::from_millis(200));
        let (status, waited) = get(addr, "/blocks/tip/height");
        assert_eq!(status, 200);
        assert!(
            waited < Duration::from_millis(700),
            "/blocks/tip/height waited {waited:?} behind a slow address read"
        );
        // Slow but inside the timeout: answered normally.
        assert_eq!(slow.join().unwrap().0, 200);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_address_read_past_the_request_timeout_is_answered_503_on_time() {
    let index = Arc::new(SlowIndex::default());
    index.delay_ms.store(SLOW.as_millis() as u64, Ordering::SeqCst);
    let (addr, _dir) = serve(index, Duration::from_millis(300), 256).await;

    on_thread(move || {
        for route in ["", "/txs", "/txs/chain", "/utxo"] {
            let path = format!("{SH_PATH}{route}");
            let (status, waited) = get(addr, &path);
            if route == "/utxo" {
                // `/utxo` reads no history; it answers at once.
                assert_eq!(status, 200, "{path}");
                continue;
            }
            assert_eq!(status, 503, "{path}");
            assert!(
                waited < SLOW - Duration::from_millis(400),
                "{path}: the timeout answer took {waited:?}; it must not wait for the read"
            );
        }
    })
    .await;
}

/// Work that outlives its request keeps its permit, so a client retrying
/// after every timeout cannot run more reads at once than
/// `--esploramaxconns`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timed_out_read_keeps_its_work_permit_until_it_ends() {
    let index = Arc::new(SlowIndex::default());
    index.delay_ms.store(SLOW.as_millis() as u64, Ordering::SeqCst);
    let (addr, _dir) = serve(index.clone(), Duration::from_millis(300), 1).await;

    on_thread(move || {
        let started = Instant::now();
        assert_eq!(get(addr, &format!("{SH_PATH}/txs/chain")).0, 503);
        // The first read is still sleeping; the retry waits for its permit
        // and times out without starting a second read.
        assert_eq!(get(addr, &format!("{SH_PATH}/txs/chain")).0, 503);
        assert!(started.elapsed() < SLOW - Duration::from_millis(200));
        assert_eq!(
            index.reads.load(Ordering::SeqCst),
            1,
            "a second read started while the first still held the only permit"
        );

        // Once the first read has ended its permit is free again.
        index.delay_ms.store(0, Ordering::SeqCst);
        std::thread::sleep((SLOW + Duration::from_millis(200)).saturating_sub(started.elapsed()));
        assert_eq!(get(addr, &format!("{SH_PATH}/txs/chain")).0, 200);
        assert_eq!(index.reads.load(Ordering::SeqCst), 2);
    })
    .await;
}
