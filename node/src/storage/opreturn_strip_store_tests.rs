//! Storage plumbing for OP_RETURN strip records: the lazily created column
//! family, `StoreBatch` merging, and how each layered store routes and reads
//! the records.

use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, Txid};
use rocksdb::{ColumnFamilyDescriptor, DB, Options};

use super::coin_cache::CoinCache;
use super::coinview::Coin;
use super::db::InMemoryStore;
use super::rocksdb_store::RocksDbStore;
use super::split_store::SplitStore;
use super::{Store, StoreBatch};

const STRIP_CF: &str = "opreturn_strip";

fn hash(b: u8) -> BlockHash {
    BlockHash::from_byte_array([b; 32])
}

fn put(h: BlockHash, record: &[u8]) -> StoreBatch {
    StoreBatch {
        opreturn_strip_puts: vec![(h, record.to_vec())],
        ..Default::default()
    }
}

fn remove(h: BlockHash) -> StoreBatch {
    StoreBatch {
        opreturn_strip_removes: vec![h],
        ..Default::default()
    }
}

fn chainstate_cfs(datadir: &std::path::Path) -> Vec<String> {
    DB::list_cf(&Options::default(), datadir.join("chainstate")).unwrap()
}

/// Open the chainstate as a release from before the strip family would:
/// declaring every family it knows, which is every family except that one.
fn open_without_strip_cf(datadir: &std::path::Path) -> Result<DB, rocksdb::Error> {
    let known: Vec<ColumnFamilyDescriptor> = chainstate_cfs(datadir)
        .into_iter()
        .filter(|n| n != STRIP_CF)
        .map(|n| ColumnFamilyDescriptor::new(n, Options::default()))
        .collect();
    DB::open_cf_descriptors(&Options::default(), datadir.join("chainstate"), known)
}

/// The family exists only once something has been stripped. A remove does
/// not create it: every block write carries one, and creating the family on
/// it would make every datadir one an older release refuses.
#[test]
fn the_strip_family_is_created_by_the_first_put_and_not_by_a_remove() {
    let dir = tempfile::tempdir().unwrap();
    {
        let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        assert!(!chainstate_cfs(dir.path()).contains(&STRIP_CF.to_string()), "fresh datadir");
        assert_eq!(store.get_opreturn_strip(&hash(1)).unwrap(), None);
        assert_eq!(store.opreturn_strip_meta().unwrap(), None);

        store.write_batch(remove(hash(1))).unwrap();
        assert!(
            !chainstate_cfs(dir.path()).contains(&STRIP_CF.to_string()),
            "a remove must not create the family"
        );

        store.write_batch(put(hash(1), b"record")).unwrap();
        assert!(chainstate_cfs(dir.path()).contains(&STRIP_CF.to_string()));
        assert_eq!(store.get_opreturn_strip(&hash(1)).unwrap().as_deref(), Some(&b"record"[..]));
    }
    // And it is declared again on the next open, record intact.
    let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
    assert_eq!(store.get_opreturn_strip(&hash(1)).unwrap().as_deref(), Some(&b"record"[..]));
    store.write_batch(remove(hash(1))).unwrap();
    assert_eq!(store.get_opreturn_strip(&hash(1)).unwrap(), None);
}

/// Meta alone also creates the family, and lives under its own key.
#[test]
fn strip_meta_round_trips_beside_the_records() {
    let (store, _dir) = {
        let dir = tempfile::tempdir().unwrap();
        (RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap(), dir)
    };
    store
        .write_batch(StoreBatch {
            opreturn_strip_meta: Some(b"cursor".to_vec()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(store.opreturn_strip_meta().unwrap().as_deref(), Some(&b"cursor"[..]));
    // A batch without meta leaves it alone.
    store.write_batch(put(hash(2), b"r")).unwrap();
    assert_eq!(store.opreturn_strip_meta().unwrap().as_deref(), Some(&b"cursor"[..]));
}

/// A release that predates the family declares every family but it, and
/// RocksDB refuses to open a database with an undeclared one. That refusal
/// is the point: such a release would serve the zeroed bytes as blocks.
/// The same open succeeds on a datadir that never stripped.
#[test]
fn an_older_release_cannot_open_a_datadir_that_has_stripped() {
    let dir = tempfile::tempdir().unwrap();
    drop(RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap());
    open_without_strip_cf(dir.path()).expect("a datadir that never stripped stays openable");

    {
        let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
        store.write_batch(put(hash(1), b"record")).unwrap();
    }
    assert!(
        open_without_strip_cf(dir.path()).is_err(),
        "a datadir with strip records must be refused by a release that does not know them"
    );
}

/// Both rebuilds keep the records: they describe the block files, which a
/// rebuild keeps, keyed by hash, which a rebuild does not change.
#[test]
fn reindex_clears_keep_the_strip_records() {
    let dir = tempfile::tempdir().unwrap();
    let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
    store.write_batch(put(hash(1), b"record")).unwrap();
    store
        .write_batch(StoreBatch {
            opreturn_strip_meta: Some(b"cursor".to_vec()),
            ..Default::default()
        })
        .unwrap();

    store.clear_chainstate().unwrap();
    assert_eq!(store.get_opreturn_strip(&hash(1)).unwrap().as_deref(), Some(&b"record"[..]));
    store.clear_all().unwrap();
    assert_eq!(store.get_opreturn_strip(&hash(1)).unwrap().as_deref(), Some(&b"record"[..]));
    assert_eq!(store.opreturn_strip_meta().unwrap().as_deref(), Some(&b"cursor"[..]));
}

#[test]
fn in_memory_clears_keep_the_strip_records() {
    let store = InMemoryStore::new();
    store.write_batch(put(hash(1), b"record")).unwrap();
    store.clear_chainstate().unwrap();
    store.clear_all().unwrap();
    assert_eq!(store.get_opreturn_strip(&hash(1)).unwrap().as_deref(), Some(&b"record"[..]));
}

/// `merge` is last-writer-wins by hash, and a later batch without meta does
/// not erase an earlier batch's meta.
#[test]
fn merge_is_last_writer_wins_by_hash_and_keeps_meta() {
    let mut a = put(hash(1), b"one");
    a.opreturn_strip_meta = Some(b"meta".to_vec());
    a.merge(remove(hash(1)));
    assert!(a.opreturn_strip_puts.is_empty(), "a later remove drops the put");
    assert_eq!(a.opreturn_strip_removes, vec![hash(1)]);
    assert_eq!(a.opreturn_strip_meta.as_deref(), Some(&b"meta"[..]), "None must not erase Some");

    a.merge(put(hash(1), b"again"));
    assert!(a.opreturn_strip_removes.is_empty(), "a later put drops the remove");
    assert_eq!(a.opreturn_strip_puts, vec![(hash(1), b"again".to_vec())]);

    a.merge(StoreBatch {
        opreturn_strip_meta: Some(b"newer".to_vec()),
        ..Default::default()
    });
    assert_eq!(a.opreturn_strip_meta.as_deref(), Some(&b"newer"[..]));
}

fn coin_batch() -> StoreBatch {
    StoreBatch {
        coin_puts: vec![(
            OutPoint {
                txid: Txid::from_byte_array([7; 32]),
                vout: 0,
            },
            Coin {
                amount: 1,
                script_pubkey: bitcoin::ScriptBuf::new(),
                height: 1,
                coinbase: false,
                txseq: node_index::TXSEQ_UNKNOWN,
            },
        )],
        ..Default::default()
    }
}

/// A batch carrying only strip records is coin-free, so the cache hands it
/// straight to the backing store. The strip worker relies on this: its
/// record must be durable before it punches.
#[test]
fn a_coin_free_strip_batch_goes_straight_to_the_backing_store() {
    let cache = CoinCache::new(Box::new(InMemoryStore::new()), 10);
    cache.write_batch(put(hash(1), b"record")).unwrap();
    assert_eq!(
        cache.inner_for_test().get_opreturn_strip(&hash(1)).unwrap().as_deref(),
        Some(&b"record"[..]),
        "the record must not wait for a flush"
    );
}

/// A remove that rides a connect is buffered with it. Reads must see it at
/// once, and the flush must apply it.
#[test]
fn a_buffered_remove_is_seen_by_reads_and_applied_by_the_flush() {
    let cache = CoinCache::new(Box::new(InMemoryStore::new()), 10);
    cache.write_batch(put(hash(1), b"record")).unwrap();

    let mut connect = coin_batch();
    connect.opreturn_strip_removes.push(hash(1));
    cache.write_batch(connect).unwrap();
    assert!(
        cache.inner_for_test().get_opreturn_strip(&hash(1)).unwrap().is_some(),
        "premise: the remove is still buffered"
    );
    assert_eq!(cache.get_opreturn_strip(&hash(1)).unwrap(), None, "reads see the buffered remove");

    cache.flush().unwrap();
    assert_eq!(cache.inner_for_test().get_opreturn_strip(&hash(1)).unwrap(), None);
}

/// A record written after a buffered remove of the same block is newer. It
/// must win in reads, and the flush must not delete it: the punched bytes
/// would then read as an intact block.
#[test]
fn a_pass_through_put_supersedes_a_buffered_remove() {
    let cache = CoinCache::new(Box::new(InMemoryStore::new()), 10);
    let mut connect = coin_batch();
    connect.opreturn_strip_removes.push(hash(1));
    cache.write_batch(connect).unwrap();

    cache.write_batch(put(hash(1), b"record")).unwrap();
    assert_eq!(cache.get_opreturn_strip(&hash(1)).unwrap().as_deref(), Some(&b"record"[..]));
    cache.flush().unwrap();
    assert_eq!(
        cache.inner_for_test().get_opreturn_strip(&hash(1)).unwrap().as_deref(),
        Some(&b"record"[..]),
        "the flush must not replay the older remove over the record"
    );
}

/// Records live with the shared block store, beside the block index that
/// points at the bytes they describe.
#[test]
fn split_store_keeps_strip_records_in_the_block_store() {
    let block_store = Arc::new(InMemoryStore::new());
    let coins_store = Arc::new(InMemoryStore::new());
    let split = SplitStore::new(block_store.clone(), coins_store.clone(), None);
    let mut batch = put(hash(1), b"record");
    batch.opreturn_strip_meta = Some(b"meta".to_vec());
    split.write_batch(batch).unwrap();

    assert_eq!(block_store.get_opreturn_strip(&hash(1)).unwrap().as_deref(), Some(&b"record"[..]));
    assert_eq!(block_store.opreturn_strip_meta().unwrap().as_deref(), Some(&b"meta"[..]));
    assert_eq!(coins_store.get_opreturn_strip(&hash(1)).unwrap(), None);
    assert_eq!(coins_store.opreturn_strip_meta().unwrap(), None);
    assert_eq!(split.get_opreturn_strip(&hash(1)).unwrap().as_deref(), Some(&b"record"[..]));
    assert_eq!(split.opreturn_strip_meta().unwrap().as_deref(), Some(&b"meta"[..]));
}

/// One batch can carry a put and a remove for the same block. Every store
/// applies puts before removes, so it lands as removed, and a read of it
/// while still buffered must say the same.
#[test]
fn a_buffered_put_and_remove_in_one_batch_reads_as_it_flushes() {
    let cache = CoinCache::new(Box::new(InMemoryStore::new()), 10);
    let mut connect = coin_batch();
    connect.opreturn_strip_puts.push((hash(1), b"record".to_vec()));
    connect.opreturn_strip_removes.push(hash(1));
    cache.write_batch(connect).unwrap();
    assert_eq!(cache.get_opreturn_strip(&hash(1)).unwrap(), None, "buffered");
    cache.flush().unwrap();
    assert_eq!(cache.inner_for_test().get_opreturn_strip(&hash(1)).unwrap(), None, "flushed");
}
