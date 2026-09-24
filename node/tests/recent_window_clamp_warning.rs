//! The recent-height UTXO window warns once, not once per batch, when a
//! removal would take a count below zero, and clamps the count to zero.
//!
//! Its own test binary because the warning is once per process and the
//! capture needs a process-wide subscriber: see `Logs`.

use std::sync::atomic::AtomicBool;

use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};
use node::storage::coinview::Coin;
use node::storage::rocksdb_store::RocksDbStore;
use node::storage::{Store, StoreBatch};

thread_local! {
    static THREAD_LOGS: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

struct ThreadLogs;

impl std::io::Write for ThreadLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        THREAD_LOGS.with(|l| l.borrow_mut().extend_from_slice(buf));
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One process-wide subscriber writing into a per-thread buffer, never a
/// scoped `set_default`: whether a `warn!` is evaluated at all is decided by
/// tracing's process-wide callsite interest, which a scoped subscriber on
/// any thread moves.
struct Logs;

impl Logs {
    fn capture() -> Self {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            use tracing_subscriber::layer::SubscriberExt as _;
            use tracing_subscriber::util::SubscriberInitExt as _;
            let _ = tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(|| ThreadLogs),
                )
                .with(tracing_subscriber::filter::LevelFilter::TRACE)
                .try_init();
        });
        THREAD_LOGS.with(|l| l.borrow_mut().clear());
        Logs
    }

    fn lines(&self) -> Vec<String> {
        THREAD_LOGS.with(|l| {
            String::from_utf8(l.borrow().clone())
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect()
        })
    }
}

fn outpoint(n: u32) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([0x5a; 32]),
        vout: n,
    }
}

#[test]
fn a_negative_recent_window_count_warns_once_and_clamps() {
    let logs = Logs::capture();
    let dir = tempfile::tempdir().unwrap();
    let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
    store.build_recent_window(&AtomicBool::new(false)).unwrap();

    let mut batch = StoreBatch::default();
    batch.coin_puts.push((
        outpoint(0),
        Coin {
            amount: 1_000,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            height: 9,
            coinbase: false,
            txseq: node_index::TXSEQ_UNKNOWN,
        },
    ));
    store.write_batch(batch).unwrap();

    // Three batches each removing a coin the window never counted: the
    // first goes to zero legitimately, the next two would go negative.
    for n in 0..3 {
        let mut batch = StoreBatch::default();
        batch.coin_removes.push((outpoint(n), 1_000, 9));
        store.write_batch(batch).unwrap();
    }

    let window = store.utxo_recent_heights().expect("window is live");
    assert_eq!(window.count_at(9), Some(0), "clamped at zero, not wrapped");
    let warnings: Vec<String> = logs
        .lines()
        .into_iter()
        .filter(|l| l.contains("WARN") && l.contains("never counted"))
        .collect();
    assert_eq!(
        warnings.len(),
        1,
        "two clamping batches must produce exactly one warning: {warnings:#?}"
    );
    assert!(
        warnings[0].contains("height=9"),
        "the warning names the height: {}",
        warnings[0]
    );
}
