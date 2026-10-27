//! Two properties of the pending batch that the index read paths rely on.
//!
//! 1. A flush moves the buffered rows from `pending_batch` to the backing
//!    store. A read that runs while that write is in progress must find
//!    each row in one place or the other. It must never find it in neither,
//!    which is what a read saw while the batch had been taken out of
//!    `pending_batch` but not yet written.
//!
//! 2. A batch that moves the tip is buffered even when it carries no coins.
//!    A block whose outputs are all unspendable and which spends nothing
//!    produces exactly that batch. Sending it straight to the backing store
//!    let a reorg's earlier removes (still pending) delete its rows at the
//!    next flush, and let a reorg abort leave its rows behind.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use bitcoin::hashes::Hash as _;
use bitcoin::{BlockHash, OutPoint, Txid};

use super::CoinCache;
use crate::storage::blockindex::BlockIndexEntry;
use crate::storage::coinview::Coin;
use crate::storage::db::InMemoryStore;
use crate::storage::undo::UndoData;
use crate::storage::{CoinSnapshotBase, Store, StoreBatch, StoreError, WriteMode};

/// Pauses the first armed `write_batch_recoverable` until the test lets it
/// go, and can make that one write fail.
#[derive(Default)]
struct WriteGate {
    armed: AtomicBool,
    fail: AtomicBool,
    entered: std::sync::Mutex<Option<mpsc::Sender<()>>>,
    release: std::sync::Mutex<Option<mpsc::Receiver<()>>>,
}

impl WriteGate {
    /// Arm the gate. Returns (a receiver that fires when the gated write is
    /// parked, a sender that lets it continue).
    fn arm(&self, fail: bool) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *self.entered.lock().unwrap() = Some(entered_tx);
        *self.release.lock().unwrap() = Some(release_rx);
        self.fail.store(fail, Ordering::SeqCst);
        self.armed.store(true, Ordering::SeqCst);
        (entered_rx, release_tx)
    }

    /// Returns true when this write must fail.
    fn pass(&self) -> bool {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return false;
        }
        let entered = self.entered.lock().unwrap().take();
        let release = self.release.lock().unwrap().take();
        if let Some(tx) = entered {
            let _ = tx.send(());
        }
        if let Some(rx) = release {
            let _ = rx.recv();
        }
        self.fail.swap(false, Ordering::SeqCst)
    }
}

/// An `InMemoryStore` whose batch write can be held open by a [`WriteGate`].
struct GatedStore {
    inner: InMemoryStore,
    gate: Arc<WriteGate>,
}

impl Store for GatedStore {
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndexEntry> {
        self.inner.get_block_index(hash)
    }
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.inner.get_coin(outpoint)
    }
    fn has_coin(&self, outpoint: &OutPoint) -> bool {
        self.inner.has_coin(outpoint)
    }
    fn get_tip(&self) -> Option<BlockHash> {
        self.inner.get_tip()
    }
    fn get_block_hash_by_height(&self, height: u32) -> Option<BlockHash> {
        self.inner.get_block_hash_by_height(height)
    }
    fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        self.inner.write_batch(batch)
    }
    fn write_batch_recoverable(
        &self,
        batch: StoreBatch,
        mode: WriteMode,
    ) -> Result<(), (Option<Box<StoreBatch>>, StoreError)> {
        if self.gate.pass() {
            return Err((
                Some(Box::new(batch)),
                StoreError::Database("injected write failure".into()),
            ));
        }
        self.inner.write_batch_recoverable(batch, mode)
    }
    fn get_undo(&self, hash: &BlockHash) -> Option<UndoData> {
        self.inner.get_undo(hash)
    }
    fn get_opreturn_strip(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.get_opreturn_strip(hash)
    }
    fn opreturn_strip_meta(&self) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.opreturn_strip_meta()
    }
    fn coin_count(&self) -> u64 {
        self.inner.coin_count()
    }
    fn coin_total_amount(&self) -> u64 {
        self.inner.coin_total_amount()
    }
    fn utxo_height_hist(&self) -> Vec<u64> {
        self.inner.utxo_height_hist()
    }
    fn get_tx_location(&self, txid: &Txid) -> Option<BlockHash> {
        self.inner.get_tx_location(txid)
    }
    fn has_txindex(&self) -> bool {
        self.inner.has_txindex()
    }
    fn get_tx_seq(&self, txid: &Txid) -> Option<u64> {
        self.inner.get_tx_seq(txid)
    }
    fn txids_of_seqs(&self, seqs: &[u64]) -> Vec<Option<Txid>> {
        self.inner.txids_of_seqs(seqs)
    }
    fn clear_chainstate(&self) -> Result<(), StoreError> {
        self.inner.clear_chainstate()
    }
    fn clear_all(&self) -> Result<(), StoreError> {
        self.inner.clear_all()
    }
    fn for_each_coin_snapshot(
        &self,
        f: &mut dyn FnMut(&OutPoint, &Coin) -> Result<(), StoreError>,
    ) -> Result<CoinSnapshotBase, StoreError> {
        self.inner.for_each_coin_snapshot(f)
    }
}

fn gated_cache() -> (Arc<CoinCache>, Arc<WriteGate>) {
    let gate = Arc::new(WriteGate::default());
    let store = GatedStore {
        inner: InMemoryStore::new(),
        gate: gate.clone(),
    };
    (Arc::new(CoinCache::new(Box::new(store), 10)), gate)
}

fn txid(byte: u8) -> Txid {
    Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
}

fn block_hash(byte: u8) -> BlockHash {
    BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32]))
}

fn coin(amount: u64, height: u32) -> Coin {
    Coin {
        amount,
        script_pubkey: bitcoin::ScriptBuf::new(),
        height,
        coinbase: false,
        txseq: node_index::TXSEQ_UNKNOWN,
    }
}

/// A connect-shaped batch: one new coin plus the transaction's ordinal rows.
/// The coin is what routes it into the pending batch.
fn connect_batch(seq: u64, tx: Txid) -> StoreBatch {
    let mut batch = StoreBatch::default();
    batch.coin_puts.push((OutPoint { txid: tx, vout: 0 }, coin(1_000, 1)));
    batch.tx_loc_puts.push((tx, seq));
    batch.txseq_txid_puts.push((seq, tx));
    batch
}

/// What a reader sees for the ordinal rows of `(seq, tx)`.
fn read_rows(cache: &CoinCache, seq: u64, tx: Txid) -> (Option<Txid>, Option<u64>) {
    (cache.txids_of_seqs(&[seq])[0], cache.get_tx_seq(&tx))
}

/// Start a reader on its own thread once the flush is parked in the inner
/// write, give it time to finish if it is not blocked, then let the write
/// go. Returns what the reader saw.
fn read_while_flush_is_writing(
    cache: &Arc<CoinCache>,
    gate: &WriteGate,
    fail: bool,
    seq: u64,
    tx: Txid,
) -> (Option<Txid>, Option<u64>) {
    let (entered, release) = gate.arm(fail);
    let flusher = {
        let cache = cache.clone();
        std::thread::spawn(move || cache.flush())
    };
    entered
        .recv_timeout(Duration::from_secs(10))
        .expect("the flush reaches the inner write");

    let (started_tx, started_rx) = mpsc::channel();
    let reader = {
        let cache = cache.clone();
        std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            read_rows(&cache, seq, tx)
        })
    };
    started_rx.recv().unwrap();
    // Long enough for an unblocked read to complete. A blocked one waits
    // for the release below.
    std::thread::sleep(Duration::from_millis(200));
    release.send(()).unwrap();

    let flushed = flusher.join().unwrap();
    assert_eq!(flushed.is_err(), fail, "flush result: {flushed:?}");
    reader.join().unwrap()
}

/// Fails without the fix: the reader ran while the batch had been taken
/// out of `pending_batch` and not yet written, and saw `(None, None)`.
#[test]
fn a_read_during_a_flush_finds_the_rows_in_pending_or_in_the_store() {
    let (cache, gate) = gated_cache();
    let tx = txid(0x41);
    cache.write_batch(connect_batch(7, tx)).unwrap();
    // Buffered, not yet written.
    assert_eq!(read_rows(&cache, 7, tx), (Some(tx), Some(7)));

    let seen = read_while_flush_is_writing(&cache, &gate, false, 7, tx);
    assert_eq!(
        seen,
        (Some(tx), Some(7)),
        "a read during the flush missed rows that were neither pending nor written"
    );
    // And the write did land.
    assert_eq!(cache.inner_for_test().get_tx_seq(&tx), Some(7));
    assert_eq!(read_rows(&cache, 7, tx), (Some(tx), Some(7)));
}

/// The same read while the write fails. The rows go back into the pending
/// batch before the reader can look, so it finds them there.
///
/// Fails without the fix: the reader saw `(None, None)` during the write.
#[test]
fn a_read_during_a_failed_flush_finds_the_restored_rows() {
    let (cache, gate) = gated_cache();
    let tx = txid(0x42);
    cache.write_batch(connect_batch(9, tx)).unwrap();

    let seen = read_while_flush_is_writing(&cache, &gate, true, 9, tx);
    assert_eq!(
        seen,
        (Some(tx), Some(9)),
        "a read during a failed flush missed rows the failure was about to restore"
    );
    assert_eq!(cache.inner_for_test().get_tx_seq(&tx), None, "the write failed");
    // The next flush writes them.
    cache.flush().unwrap();
    assert_eq!(cache.inner_for_test().get_tx_seq(&tx), Some(9));
    assert_eq!(read_rows(&cache, 9, tx), (Some(tx), Some(9)));
}

/// A connect-shaped write that arrives while a flush holds the pending batch
/// waits for it and then lands; nothing deadlocks. The write takes the
/// dirty-coin lock (released by the flush before its inner write) and then
/// the pending batch (held by the flush until the write returns).
#[test]
fn a_write_during_a_flush_completes_once_the_flush_returns() {
    let (cache, gate) = gated_cache();
    let first = txid(0x43);
    let second = txid(0x44);
    cache.write_batch(connect_batch(11, first)).unwrap();

    let (entered, release) = gate.arm(false);
    let flusher = {
        let cache = cache.clone();
        std::thread::spawn(move || cache.flush())
    };
    entered.recv_timeout(Duration::from_secs(10)).unwrap();

    let (done_tx, done_rx) = mpsc::channel();
    let writer = {
        let cache = cache.clone();
        std::thread::spawn(move || {
            let r = cache.write_batch(connect_batch(12, second));
            done_tx.send(()).unwrap();
            r
        })
    };
    std::thread::sleep(Duration::from_millis(100));
    release.send(()).unwrap();
    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the write completes after the flush returns");
    writer.join().unwrap().unwrap();
    flusher.join().unwrap().unwrap();

    assert_eq!(read_rows(&cache, 11, first), (Some(first), Some(11)));
    assert_eq!(read_rows(&cache, 12, second), (Some(second), Some(12)));
    cache.flush().unwrap();
    assert_eq!(cache.inner_for_test().get_tx_seq(&second), Some(12));
}

// ---------------------------------------------------------------------------
// Coin-free batches that move the tip
// ---------------------------------------------------------------------------

const H: u32 = 5;

#[cfg(feature = "block-filter-index")]
fn filter_key() -> node_filter_index::FilterKey {
    node_filter_index::FilterKey {
        filter_type: node_filter_index::FILTER_TYPE_BASIC,
        height: H,
    }
}

/// The rows a block at height `H` writes, with no coins: what an
/// all-unspendable, spend-nothing block produces.
fn coin_free_connect(hash: BlockHash, header: [u8; 32]) -> StoreBatch {
    let mut batch = StoreBatch::default();
    batch.height_hash_puts.push((H, hash));
    #[cfg(feature = "block-filter-index")]
    {
        batch.filter_puts.push(node_filter_index::FilterRow {
            key: filter_key(),
            filter: header.to_vec(),
        });
        batch
            .filter_header_puts
            .push(node_filter_index::FilterHeaderRow { key: filter_key(), header });
    }
    #[cfg(not(feature = "block-filter-index"))]
    let _ = header;
    batch.tip = Some(hash);
    batch
}

/// Disconnecting the block at `H`: restores a coin, removes the height's
/// rows, moves the tip back.
fn disconnect(parent: BlockHash) -> StoreBatch {
    let mut batch = StoreBatch::default();
    batch
        .coin_puts
        .push((OutPoint { txid: txid(0x50), vout: 0 }, coin(5_000, 3)));
    batch.height_hash_removes.push(H);
    #[cfg(feature = "block-filter-index")]
    batch.filter_removes.push(filter_key());
    batch.tip = Some(parent);
    batch
}

/// A cache whose backing store holds block `old` at height `H`.
fn cache_with_old_block(old: BlockHash) -> CoinCache {
    let cache = CoinCache::new(Box::new(InMemoryStore::new()), 10);
    cache.write_batch(coin_free_connect(old, [0xAA; 32])).unwrap();
    cache.flush().unwrap();
    cache.drop_read_overlays();
    assert_eq!(cache.inner_for_test().get_block_hash_by_height(H), Some(old));
    cache
}

/// A reorg replaces the block at `H` with a block that carries no coin
/// changes. The replacement's rows must survive the disconnect's removes,
/// which are still in the pending batch.
///
/// Fails without the fix: the replacement's rows went straight to the
/// backing store, the pending removes hid them from reads and then deleted
/// them at the flush.
#[test]
fn a_coin_free_block_after_a_disconnect_keeps_its_rows() {
    let old = block_hash(0xA1);
    let new = block_hash(0xB1);
    let cache = cache_with_old_block(old);

    cache.write_batch(disconnect(block_hash(0x01))).unwrap();
    cache.write_batch(coin_free_connect(new, [0xBB; 32])).unwrap();

    #[cfg(feature = "block-filter-index")]
    assert_eq!(
        cache.get_filter_header(node_filter_index::FILTER_TYPE_BASIC, H),
        Some([0xBB; 32]),
        "the new block's filter header is hidden by the pending remove"
    );

    cache.flush().unwrap();
    cache.drop_read_overlays();
    assert_eq!(
        cache.get_block_hash_by_height(H),
        Some(new),
        "the flush deleted the new block's height row"
    );
    #[cfg(feature = "block-filter-index")]
    assert_eq!(
        cache.get_filter_header(node_filter_index::FILTER_TYPE_BASIC, H),
        Some([0xBB; 32]),
        "the flush deleted the new block's filter header"
    );
}

/// A reorg that connects a coin-free block and then aborts must take that
/// block's rows back out with everything else it buffered.
///
/// Fails without the fix: the coin-free block's rows had already reached
/// the backing store, so the discard could not retract them.
#[test]
fn a_coin_free_block_in_an_aborted_reorg_is_retracted() {
    let old = block_hash(0xA2);
    let new = block_hash(0xB2);
    let cache = cache_with_old_block(old);

    let excl = cache.lock_flush_exclusion();
    excl.flush().unwrap();
    cache.write_batch(disconnect(block_hash(0x02))).unwrap();
    cache.write_batch(coin_free_connect(new, [0xBC; 32])).unwrap();
    cache.discard_uncommitted(&excl).expect("own thread's writes only");
    drop(excl);

    assert_eq!(
        cache.get_block_hash_by_height(H),
        Some(old),
        "the aborted reorg's coin-free block left its height row behind"
    );
    #[cfg(feature = "block-filter-index")]
    assert_eq!(
        cache.get_filter_header(node_filter_index::FILTER_TYPE_BASIC, H),
        Some([0xAA; 32]),
        "the aborted reorg's coin-free block left its filter header behind"
    );
}

/// Batches that do not move the tip (a stored block, a header, an index
/// backfill) still go straight to the backing store.
#[test]
fn a_coin_free_batch_without_a_tip_still_passes_through() {
    let cache = CoinCache::new(Box::new(InMemoryStore::new()), 10);
    let mut batch = coin_free_connect(block_hash(0xC1), [0xCC; 32]);
    batch.tip = None;
    cache.write_batch(batch).unwrap();
    assert_eq!(
        cache.inner_for_test().get_block_hash_by_height(H),
        Some(block_hash(0xC1)),
        "a tip-less coin-free batch is written through, not buffered"
    );
}
