//! A coin the chainstate database cannot read stops the node. It is never
//! reported as missing.
//!
//! "Missing" is an answer about the UTXO set: `connect_block` refuses a block
//! that spends a missing coin (`bad-txns-inputs-missingorspent`) and
//! `accept_block` records the block as invalid. A failed read, or a row that
//! does not decode, says nothing about the coin. Bitcoin Core stops on a
//! coins read error for this reason (`CCoinsViewErrorCatcher`, `coins.cpp`).
//!
//! The read errors here are real ones: the coin's SST file is damaged on
//! disk, and RocksDB's block checksum refuses the read.

use super::*;
use crate::chain::state::tests::{build_test_block_spending, make_chain_state_with_store};
use crate::storage::coin_cache::CoinCache;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

fn spendable_outpoint() -> OutPoint {
    OutPoint {
        txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x5d; 32])),
        vout: 0,
    }
}

fn spendable_coin() -> Coin {
    Coin {
        amount: 50_000,
        script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
        height: 0,
        coinbase: false,
        txseq: 0,
    }
}

/// A store holding one coin, flushed to an SST file of its own. Returns the
/// store, its directory, and the path of that file.
fn store_with_a_coin_on_disk() -> (RocksDbStore, tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let store = RocksDbStore::open(dir.path(), false, 16, false, -1).unwrap();
    let mut batch = StoreBatch::default();
    batch.coin_puts.push((spendable_outpoint(), spendable_coin()));
    store.write_batch(batch).unwrap();

    let cf = store.cf(CF_COINS);
    let mut flush = rocksdb::FlushOptions::default();
    flush.set_wait(true);
    store.db.flush_cfs_opt(&[&cf], &flush).unwrap();
    drop(cf);

    let ssts: Vec<_> = store
        .db
        .live_files()
        .unwrap()
        .into_iter()
        .filter(|f| f.column_family_name == CF_COINS)
        .collect();
    assert_eq!(ssts.len(), 1, "fixture: the coin is in one SST file");
    let sst = store.db.path().join(ssts[0].name.trim_start_matches('/'));
    (store, dir, sst)
}

/// Flip the first bytes of `sst`, inside its first data block, so that
/// RocksDB's block checksum fails every read of the coin. The file is
/// written in place, as a failing disk would leave it.
fn damage(sst: &std::path::Path) {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(sst).unwrap();
    let mut head = [0u8; 16];
    file.read_exact(&mut head).unwrap();
    for b in &mut head {
        *b ^= 0xff;
    }
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&head).unwrap();
    file.sync_all().unwrap();
}

/// Run `f`. Returns the message it stopped the node with, or `Err` with
/// what it returned if it did not stop.
fn stopped_with<R: std::fmt::Debug>(f: impl FnOnce() -> R) -> Result<String, String> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(returned) => Err(format!("{returned:?}")),
        Err(payload) => Ok(payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()),
    }
}

fn assert_stops(what: &str, outcome: Result<String, String>) {
    match outcome {
        Ok(message) => assert!(
            message.contains("Error reading from database"),
            "{what}: stopped with an unexpected message: {message}"
        ),
        Err(returned) => panic!("{what}: a coin that cannot be read must stop the node, but the read returned {returned}"),
    }
}

/// Every coin read, `get_coin`, `get_coins_batch` and `has_coin`, stops the
/// node when RocksDB cannot read the row. The same reads of an undamaged copy
/// find the coin, so the reads below do reach the damaged block.
///
/// Fails without the fix: `get_coin` returned `None`, `get_coins_batch`
/// `[None]` and `has_coin` `false`, as if the coin had been spent.
#[test]
fn a_coin_read_error_stops_the_node_and_is_never_read_as_missing() {
    let op = spendable_outpoint();

    let (intact, _intact_dir, _) = store_with_a_coin_on_disk();
    assert_eq!(intact.get_coin(&op), Some(spendable_coin()));
    assert_eq!(intact.get_coins_batch(&[op]), vec![Some(spendable_coin())]);
    assert!(intact.has_coin(&op));

    let (store, _dir, sst) = store_with_a_coin_on_disk();
    damage(&sst);
    assert_stops("get_coin", stopped_with(|| store.get_coin(&op)));
    assert_stops("get_coins_batch", stopped_with(|| store.get_coins_batch(&[op])));
    assert_stops("has_coin", stopped_with(|| store.has_coin(&op)));
}

/// A row that is present but does not decode as a coin is not a missing coin
/// either. A row in a layout this binary does not read should have been
/// refused by the schema check at open; one that slips past it is damage.
///
/// Fails without the fix: both reads logged "corrupt coin" and returned
/// `None`.
#[test]
fn an_undecodable_coin_row_stops_the_node_and_is_never_read_as_missing() {
    let (store, _dir, _) = store_with_a_coin_on_disk();
    let op = OutPoint { vout: 1, ..spendable_outpoint() };
    let cf = store.cf(CF_COINS);
    store.db.put_cf(&cf, outpoint_to_key(&op), b"").unwrap();
    drop(cf);
    assert!(Coin::deserialize_compact(b"").is_none(), "fixture: the row does not decode");

    assert_stops("get_coin", stopped_with(|| store.get_coin(&op)));
    assert_stops("get_coins_batch", stopped_with(|| store.get_coins_batch(&[spendable_outpoint(), op])));
    // The coin beside it still reads.
    assert_eq!(store.get_coin(&spendable_outpoint()), Some(spendable_coin()));
}

/// A block that spends a coin the database cannot read is not refused and
/// not recorded as invalid: the node stops before it reaches a verdict, and
/// the block is judged again after the restart. The same block over an
/// undamaged copy of the database connects.
///
/// The store is wrapped in the coin cache, as the node runs it.
///
/// Fails without the fix: `accept_block` returned
/// `bad-txns-inputs-missingorspent` and the block's index entry was
/// `Invalid`, which survives a restart and keeps the node off any chain
/// that includes the block.
#[test]
fn a_block_spending_a_coin_that_cannot_be_read_is_not_marked_invalid() {
    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).block_hash();
    let block = build_test_block_spending(genesis, 1, 1_707_300_001, spendable_outpoint());
    let hash = block.block_hash();

    let (intact, _intact_db, _) = store_with_a_coin_on_disk();
    let (cs, dir) = make_chain_state_with_store(Box::new(CoinCache::new(Box::new(intact), 16)));
    cs.accept_block(&block).expect("over an undamaged database the block connects");
    assert_eq!(cs.tip_hash(), hash);
    drop(cs);
    let _ = std::fs::remove_dir_all(&dir);

    let (store, _db, sst) = store_with_a_coin_on_disk();
    let (cs, dir) = make_chain_state_with_store(Box::new(CoinCache::new(Box::new(store), 16)));
    damage(&sst);
    let outcome = stopped_with(|| cs.accept_block(&block).map(|a| a.hash()));
    let status = cs.get_block_index(&hash).map(|e| e.status);
    assert_ne!(
        status,
        Some(BlockStatus::Invalid),
        "a read error is not a verdict on the block (accept_block: {outcome:?})"
    );
    assert_stops("accept_block", outcome);
    assert_eq!(cs.tip_hash(), genesis, "the tip must not move");
    let _ = std::fs::remove_dir_all(&dir);
}
