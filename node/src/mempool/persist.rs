//! Mempool persistence across restarts — Bitcoin Core's `-persistmempool`.
//!
//! On clean shutdown the in-memory transaction set is written to
//! `<net_datadir>/mempool.dat`; on startup it is read back and each
//! transaction is RE-VALIDATED against the current chainstate before
//! re-admission. Transactions that have since confirmed, expired, or
//! become invalid are silently dropped — the file is a hint, never a
//! trusted input.
//!
//! The on-disk format is satd's own (Core's `mempool.dat` layout is not
//! consumed — satd's datadir is not byte-compatible with Core's anyway;
//! see `CORE_DIFFERENCES.md`). It is versioned so the format can evolve:
//!
//! ```text
//! magic     [4]   b"SMPL"
//! version   u32   little-endian (currently 2; v1 files still load)
//! count     u64   little-endian number of entries
//! entries:
//!   time      u64   little-endian admission time (unix secs)
//!   fee_delta i64   little-endian prioritisetransaction delta
//!   flags     u8    (v2+) bit 0: tx was in the unbroadcast set
//!   tx_len    u32   little-endian length of the encoded tx
//!   tx_bytes  [tx_len]  consensus-encoded transaction
//! deltas (optional trailer):
//!   count     u64   little-endian number of deltas
//!   txid      [32]  a transaction not in the pool
//!   delta     i64   little-endian prioritisetransaction delta
//! ```
//!
//! v2 added the `flags` byte so the unbroadcast set survives a restart —
//! Bitcoin Core persists `m_unbroadcast_txids` in its mempool.dat for the
//! same reason: a tx submitted just before shutdown that never reached a
//! peer must resume rebroadcasting after the restart, not strand.
//!
//! The deltas trailer carries `prioritisetransaction` deltas set for
//! transactions the pool does not hold, as Core's `DumpMempool` writes
//! `mapDeltas` after the transactions, without the in-pool ones (#981). It
//! needs no version bump: a file without it has no such deltas, and a reader
//! from before it stops after the records.

use std::path::Path;

use bitcoin::hashes::Hash as _;

use crate::chain::state::ChainState;
use crate::mempool::pool::Mempool;
use crate::validation::script::ScriptVerifier;

const MAGIC: &[u8; 4] = b"SMPL";
const VERSION: u32 = 2;
/// Record flag bit: the tx was pending propagation confirmation.
const FLAG_UNBROADCAST: u8 = 1 << 0;
const FILE_NAME: &str = "mempool.dat";

/// Outcome of a [`load_mempool`] call, for logging.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LoadStats {
    /// Entries successfully re-admitted to the mempool.
    pub accepted: usize,
    /// Entries skipped (no longer valid against the current chainstate,
    /// or a decode error on a single record).
    pub skipped: usize,
    /// Entries not offered at all because they entered the pool longer
    /// than `-mempoolexpiry` ago.
    pub expired: usize,
    /// `prioritisetransaction` deltas restored for transactions not in the
    /// pool.
    pub deltas: usize,
}

/// Serialize the current mempool to `<net_datadir>/mempool.dat`.
///
/// Writes to a temp file and renames so a crash mid-write can't leave a
/// torn file that breaks the next startup. Returns the number of
/// transactions written.
pub fn dump_mempool(mempool: &Mempool, net_datadir: &Path) -> std::io::Result<usize> {
    // Parents before children, as Core writes its file (`DumpMempool` takes
    // `infoAll()`, which is in topological order), so a reload that admits
    // records in file order never meets a child before its parent.
    // One snapshot of both, so a delta is in its entry's record or in the
    // deltas trailer, never both and never neither.
    let (mut entries, mut deltas) = mempool.persist_snapshot();
    entries.sort_by_key(|(txid, e)| (e.time, *txid));
    let order = parent_first_order(entries.iter().map(|(_, e)| &e.tx));
    let entries = permute(entries, &order);
    let unbroadcast: std::collections::HashSet<bitcoin::Txid> =
        mempool.unbroadcast_txids().into_iter().collect();

    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for (txid, e) in &entries {
        buf.extend_from_slice(&e.time.to_le_bytes());
        buf.extend_from_slice(&e.fee_delta.to_le_bytes());
        let flags = if unbroadcast.contains(txid) { FLAG_UNBROADCAST } else { 0 };
        buf.push(flags);
        let tx_bytes = bitcoin::consensus::serialize(&e.tx);
        buf.extend_from_slice(&(tx_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&tx_bytes);
    }
    // Deltas for transactions not in the pool, after the records, as Core
    // writes `mapDeltas`. Sorted so the same state writes the same file.
    deltas.sort();
    buf.extend_from_slice(&(deltas.len() as u64).to_le_bytes());
    for (txid, delta) in &deltas {
        buf.extend_from_slice(txid.as_byte_array());
        buf.extend_from_slice(&delta.to_le_bytes());
    }

    let final_path = net_datadir.join(FILE_NAME);
    let tmp_path = net_datadir.join(format!("{FILE_NAME}.new"));

    // Write + fsync the temp file, rename over the target, then fsync the
    // directory so the replacement is durable across power loss. The file
    // is only a hint, but a half-written dump must not survive a good one.
    // Clean up the temp file on any failure so it can't be mistaken for a
    // valid dump later.
    let write_and_sync = || -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(&buf)?;
        f.sync_all()
    };
    if let Err(e) = write_and_sync() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    // Best-effort directory fsync — not all platforms/filesystems require
    // or support it, so failure here is not fatal.
    if let Ok(dir) = std::fs::File::open(net_datadir) {
        let _ = dir.sync_all();
    }
    Ok(entries.len())
}

/// Read `<net_datadir>/mempool.dat` (if present) and re-admit each
/// transaction, re-validating against `chain_state`. Missing file is
/// not an error (returns zeroed stats). A truncated or corrupt file is
/// tolerated: parsing stops at the first bad record and whatever was
/// admitted up to that point is kept, so a damaged dump can never block
/// startup.
pub fn load_mempool(
    mempool: &Mempool,
    chain_state: &ChainState,
    script_verifier: &dyn ScriptVerifier,
    net_datadir: &Path,
) -> std::io::Result<LoadStats> {
    let path = net_datadir.join(FILE_NAME);

    // Bound the read by the configured mempool budget plus framing
    // overhead, so a corrupt or oversized mempool.dat can't force a large
    // allocation (startup OOM) before the header checks even run.
    let max_bytes = mempool
        .max_size_bytes()
        .saturating_mul(2)
        .saturating_add(16 * 1024 * 1024) as u64;
    match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > max_bytes => {
            tracing::warn!(
                size = meta.len(),
                cap = max_bytes,
                "mempool.dat exceeds the size cap (2× -maxmempool + 16 MiB); \
                 ignoring persisted mempool"
            );
            return Ok(LoadStats::default());
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LoadStats::default()),
        Err(e) => return Err(e),
    }

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LoadStats::default()),
        Err(e) => return Err(e),
    };

    let parsed = match parse(&data) {
        Ok(p) => p,
        Err(reason) => {
            tracing::warn!(%reason, "ignoring persisted mempool: mempool.dat unparseable");
            return Ok(LoadStats::default());
        }
    };
    if let Some(note) = &parsed.truncation {
        tracing::warn!(%note, "persisted mempool body was truncated/corrupt; loaded the valid prefix");
    }

    // Re-admit oldest-first, but never a child before a parent that is in
    // the same file. `time` has one-second resolution, so a parent and its
    // child often tie, and a file written by an older satd is in no
    // particular order; the dependency pass puts every in-file parent ahead
    // of its children whatever the times say. A child whose parent fails
    // still just gets skipped.
    let mut records = parsed.records;
    records.sort_by_key(|r| r.time);
    let order = parent_first_order(records.iter().map(|r| &r.tx));
    let records = permute(records, &order);

    // Core's `LoadMempool` (src/node/mempool_persist.cpp): the delta first,
    // so a transaction that met the floor only through
    // `prioritisetransaction` still does, then `AcceptToMemoryPool` with the
    // persisted time, for a record that has not expired yet.
    let expiry_secs = mempool.policy().expiry_secs;
    let now = crate::time::now_secs();
    let mut stats = LoadStats::default();
    for rec in records {
        let fee_delta = rec.fee_delta;
        let unbroadcast = rec.flags & FLAG_UNBROADCAST != 0;
        if fee_delta != 0 {
            let txid = rec.tx.compute_txid();
            if let Err(e) = mempool.prioritise_transaction(&txid, fee_delta) {
                tracing::debug!(%txid, err = %e, "persisted fee_delta not applied");
            }
        }
        // Core keeps a record only when `nTime > now - expiry`.
        if rec.time <= now.saturating_sub(expiry_secs) {
            stats.expired += 1;
            continue;
        }
        match mempool.accept_persisted_transaction(rec.tx, chain_state, script_verifier, rec.time) {
            Ok(txid) => {
                if unbroadcast {
                    // Resume durable rebroadcast across the restart — the tx
                    // had not yet been confirmed propagated when we shut down.
                    mempool.mark_unbroadcast(txid);
                }
                stats.accepted += 1;
            }
            Err(_) => stats.skipped += 1,
        }
    }
    // Core's `LoadMempool` applies `mapDeltas` after the transactions.
    for (txid, delta) in parsed.deltas {
        match mempool.prioritise_transaction(&txid, delta) {
            Ok(_) => stats.deltas += 1,
            Err(e) => tracing::debug!(%txid, err = %e, "persisted fee_delta not applied"),
        }
    }
    Ok(stats)
}

/// A stable topological order of `txs`: indices into the input, every
/// transaction after each of its parents that is also in the input, and
/// otherwise in input order. One depth-first pass over the spend edges, so
/// linear in the number of inputs. A duplicate txid links its children to
/// the first copy; a cycle cannot occur between real transactions (a txid
/// commits to its inputs) and would just be broken where it was entered.
fn parent_first_order<'a>(txs: impl Iterator<Item = &'a bitcoin::Transaction>) -> Vec<usize> {
    let txs: Vec<&bitcoin::Transaction> = txs.collect();
    let mut index: std::collections::HashMap<bitcoin::Txid, usize> =
        std::collections::HashMap::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        index.entry(tx.compute_txid()).or_insert(i);
    }

    const UNSEEN: u8 = 0;
    const OPEN: u8 = 1;
    const DONE: u8 = 2;
    let mut state = vec![UNSEEN; txs.len()];
    let mut order = Vec::with_capacity(txs.len());
    // (transaction, next input to look at)
    let mut stack: Vec<(usize, usize)> = Vec::new();
    for root in 0..txs.len() {
        if state[root] != UNSEEN {
            continue;
        }
        state[root] = OPEN;
        stack.push((root, 0));
        while let Some((node, next)) = stack.last_mut() {
            let node = *node;
            if let Some(input) = txs[node].input.get(*next) {
                *next += 1;
                if let Some(&parent) = index.get(&input.previous_output.txid)
                    && state[parent] == UNSEEN
                {
                    state[parent] = OPEN;
                    stack.push((parent, 0));
                }
            } else {
                state[node] = DONE;
                order.push(node);
                stack.pop();
            }
        }
    }
    order
}

/// `items` rearranged so that position `k` holds the item at `order[k]`.
/// `order` must be a permutation of `0..items.len()`.
fn permute<T>(items: Vec<T>, order: &[usize]) -> Vec<T> {
    let mut slots: Vec<Option<T>> = items.into_iter().map(Some).collect();
    order.iter().filter_map(|&i| slots[i].take()).collect()
}

struct Record {
    time: u64,
    fee_delta: i64,
    flags: u8,
    tx: bitcoin::Transaction,
}

/// A successfully-headered parse: the records recovered, plus a
/// human-readable note if the body stopped early (truncation / decode
/// failure at a specific record).
struct ParsedDump {
    records: Vec<Record>,
    /// The deltas trailer; empty for a file without one.
    deltas: Vec<(bitcoin::Txid, i64)>,
    truncation: Option<String>,
}

/// Parse the dump. `Err(reason)` for a fatal header problem (bad magic,
/// unsupported version, truncated header). Otherwise `Ok`, with
/// `truncation` set if the body ended early — the valid prefix is kept
/// either way, so a damaged file degrades gracefully instead of
/// aborting startup. The distinct reasons aid production diagnosis of
/// "why didn't my mempool reload?".
fn parse(data: &[u8]) -> Result<ParsedDump, String> {
    let mut cur = Cursor::new(data);
    match cur.take(4) {
        Some(m) if m == MAGIC => {}
        Some(_) => return Err("bad magic (not a satd mempool.dat)".to_string()),
        None => return Err("truncated header (no magic)".to_string()),
    }
    // v1 records lack the flags byte; anything newer than us is rejected
    // (we can't know how its records are framed).
    let version = match cur.take(4).and_then(|b| b.try_into().ok()) {
        Some(b) => {
            let v = u32::from_le_bytes(b);
            if v == 0 || v > VERSION {
                return Err(format!("unsupported version {v} (expected 1..={VERSION})"));
            }
            v
        }
        None => return Err("truncated header (no version)".to_string()),
    };
    let count = match cur.take(8).and_then(|b| b.try_into().ok()) {
        Some(b) => u64::from_le_bytes(b),
        None => return Err("truncated header (no count)".to_string()),
    };

    let mut records = Vec::with_capacity(count.min(100_000) as usize);
    let mut truncation = None;
    for i in 0..count {
        let time = match cur.take(8).and_then(|b| b.try_into().ok()) {
            Some(b) => u64::from_le_bytes(b),
            None => {
                truncation = Some(format!("truncated at record {i} (time field)"));
                break;
            }
        };
        let fee_delta = match cur.take(8).and_then(|b| b.try_into().ok()) {
            Some(b) => i64::from_le_bytes(b),
            None => {
                truncation = Some(format!("truncated at record {i} (fee_delta field)"));
                break;
            }
        };
        let flags = if version >= 2 {
            match cur.take(1) {
                Some(b) => b[0],
                None => {
                    truncation = Some(format!("truncated at record {i} (flags field)"));
                    break;
                }
            }
        } else {
            0
        };
        let tx_len = match cur.take(4).and_then(|b| b.try_into().ok()) {
            Some(b) => u32::from_le_bytes(b) as usize,
            None => {
                truncation = Some(format!("truncated at record {i} (tx length field)"));
                break;
            }
        };
        let tx_bytes = match cur.take(tx_len) {
            Some(b) => b,
            None => {
                truncation = Some(format!("truncated at record {i} (tx body)"));
                break;
            }
        };
        match bitcoin::consensus::deserialize::<bitcoin::Transaction>(tx_bytes) {
            Ok(tx) => records.push(Record {
                time,
                fee_delta,
                flags,
                tx,
            }),
            Err(_) => {
                truncation = Some(format!("decode failure at record {i}"));
                break;
            }
        }
    }
    // The deltas trailer, after a complete body. None at all is a file from
    // before it; a trailer cut short keeps the deltas before the cut.
    let mut deltas = Vec::new();
    if truncation.is_none()
        && let Some(b) = cur.take(8)
    {
        let n = u64::from_le_bytes(b.try_into().unwrap());
        for i in 0..n {
            let (Some(txid), Some(delta)) = (cur.take(32), cur.take(8)) else {
                truncation = Some(format!("truncated at delta {i}"));
                break;
            };
            deltas.push((
                bitcoin::Txid::from_byte_array(txid.try_into().unwrap()),
                i64::from_le_bytes(delta.try_into().unwrap()),
            ));
        }
    }
    Ok(ParsedDump {
        records,
        deltas,
        truncation,
    })
}

/// Minimal forward-only byte cursor with bounds-checked reads.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Read `n` bytes, advancing the cursor. Returns `None` if fewer than
    /// `n` bytes remain.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
}

#[cfg(test)]
#[path = "persist_reload_order_tests.rs"]
mod reload_order_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::state::{AssumeValid, ChainState};
    use crate::mempool::pool::Mempool;
    use crate::storage::db::InMemoryStore;
    use crate::storage::flatfile::FlatFileManager;
    use crate::validation::script::NoopVerifier;
    use bitcoin::blockdata::locktime::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness, transaction};

    fn temp_datadir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "satd-mempool-persist-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn empty_chainstate(dir: &std::path::Path) -> ChainState {
        let store = Box::new(InMemoryStore::new());
        let flat_files = FlatFileManager::new(&dir.join("blocks")).unwrap();
        ChainState::new(
            store,
            flat_files,
            bitcoin::Network::Regtest,
            Box::new(NoopVerifier),
            AssumeValid::Disabled,
            450,
            4,
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap()
    }

    pub(super) fn dummy_tx(nonce: u8) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([nonce; 32]),
                    ),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    /// Frame records exactly as `dump_mempool` does (current version), for
    /// load-side tests.
    pub(super) fn frame(records: &[(u64, i64, bitcoin::Transaction)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&(records.len() as u64).to_le_bytes());
        for (time, fee_delta, tx) in records {
            buf.extend_from_slice(&time.to_le_bytes());
            buf.extend_from_slice(&fee_delta.to_le_bytes());
            buf.push(0u8); // flags
            let tx_bytes = bitcoin::consensus::serialize(tx);
            buf.extend_from_slice(&(tx_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&tx_bytes);
        }
        buf
    }

    /// Frame records in the legacy v1 layout (no flags byte), to prove a
    /// pre-upgrade mempool.dat still loads.
    fn frame_v1(records: &[(u64, i64, bitcoin::Transaction)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&(records.len() as u64).to_le_bytes());
        for (time, fee_delta, tx) in records {
            buf.extend_from_slice(&time.to_le_bytes());
            buf.extend_from_slice(&fee_delta.to_le_bytes());
            let tx_bytes = bitcoin::consensus::serialize(tx);
            buf.extend_from_slice(&(tx_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&tx_bytes);
        }
        buf
    }

    #[test]
    fn load_missing_file_is_ok() {
        let dir = temp_datadir("missing");
        let cs = empty_chainstate(&dir);
        let mp = Mempool::new(300_000_000, 1000);
        let stats = load_mempool(&mp, &cs, &NoopVerifier, &dir).unwrap();
        assert_eq!(stats, LoadStats::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_dump_round_trips() {
        let dir = temp_datadir("empty");
        let mp = Mempool::new(300_000_000, 1000);
        let n = dump_mempool(&mp, &dir).unwrap();
        assert_eq!(n, 0);
        assert!(dir.join("mempool.dat").exists());

        let cs = empty_chainstate(&dir);
        let fresh = Mempool::new(300_000_000, 1000);
        let stats = load_mempool(&fresh, &cs, &NoopVerifier, &dir).unwrap();
        assert_eq!(stats, LoadStats::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_decodes_records_but_skips_unfunded() {
        // A well-formed file with two txs whose inputs don't exist in the
        // (empty) UTXO set: both decode (proving the framing parses) and
        // both are skipped by re-validation. Recent times, so that expiry
        // is not what skips them.
        let dir = temp_datadir("decode");
        let now = crate::time::now_secs();
        let buf = frame(&[(now - 200, 0, dummy_tx(1)), (now - 100, 500, dummy_tx(2))]);
        std::fs::write(dir.join("mempool.dat"), &buf).unwrap();

        let cs = empty_chainstate(&dir);
        let mp = Mempool::new(300_000_000, 1000);
        let stats = load_mempool(&mp, &cs, &NoopVerifier, &dir).unwrap();
        assert_eq!(stats.accepted, 0);
        assert_eq!(stats.skipped, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v1_file_still_parses() {
        // A legacy (pre-flags) dump parses fully — same two records, no
        // flags byte — and flows through re-validation like any other.
        let buf = frame_v1(&[(100, 0, dummy_tx(1)), (200, 500, dummy_tx(2))]);
        let parsed = parse(&buf).unwrap();
        assert!(parsed.truncation.is_none(), "v1 body must parse cleanly");
        assert_eq!(parsed.records.len(), 2);
        assert!(parsed.records.iter().all(|r| r.flags == 0));
    }

    #[test]
    fn unbroadcast_flag_round_trips() {
        // The flags byte survives dump framing → parse.
        let mut buf = frame(&[(100, 0, dummy_tx(1)), (200, 0, dummy_tx(2))]);
        // Flip the first record's flags byte to FLAG_UNBROADCAST: the flags
        // byte sits after magic(4)+version(4)+count(8)+time(8)+fee_delta(8).
        buf[32] = FLAG_UNBROADCAST;
        let parsed = parse(&buf).unwrap();
        assert!(parsed.truncation.is_none());
        assert_eq!(parsed.records[0].flags, FLAG_UNBROADCAST);
        assert_eq!(parsed.records[1].flags, 0);
    }

    /// #981: a `prioritisetransaction` delta for a transaction the pool does
    /// not hold survives a restart, as Core's `mapDeltas` does in its
    /// `mempool.dat`. Only in-pool deltas were written.
    #[test]
    fn a_delta_for_a_transaction_not_in_the_pool_survives_a_restart() {
        let dir = temp_datadir("deltas");
        let mp = Mempool::new(300_000_000, 1000);
        let absent = dummy_tx(7).compute_txid();
        mp.prioritise_transaction(&absent, 12_345).unwrap();
        dump_mempool(&mp, &dir).unwrap();

        let cs = empty_chainstate(&dir);
        let fresh = Mempool::new(300_000_000, 1000);
        let stats = load_mempool(&fresh, &cs, &NoopVerifier, &dir).unwrap();
        assert_eq!(stats.deltas, 1);
        assert_eq!(
            fresh.get_prioritised_transactions().get(&absent),
            Some(&(12_345, false, None)),
            "the delta set ahead of the transaction was lost"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #1007 review: each delta is written once. An in-pool transaction's
    /// rides in its record and not in the trailer; an absent one's in the
    /// trailer only. Both come back exactly, not doubled.
    #[test]
    fn each_delta_is_written_once_and_restored_once() {
        let (cs, mp, dir) = funded(&[3], 0);
        let tx = funded_spend(3, 1_000);
        let resident = tx.compute_txid();
        mp.accept_persisted_transaction(tx, &cs, &NoopVerifier, crate::time::now_secs() - 60).unwrap();
        mp.prioritise_transaction(&resident, 700).unwrap();
        let absent = dummy_tx(9).compute_txid();
        mp.prioritise_transaction(&absent, 300).unwrap();
        dump_mempool(&mp, &dir).unwrap();

        let written = parse(&std::fs::read(dir.join("mempool.dat")).unwrap()).unwrap();
        assert_eq!(written.records.iter().map(|r| r.fee_delta).collect::<Vec<_>>(), [700]);
        assert_eq!(written.deltas, vec![(absent, 300)], "the resident delta must not ride in the trailer too");

        let fresh = Mempool::new(300_000_000, 0);
        load_mempool(&fresh, &cs, &NoopVerifier, &dir).unwrap();
        let got = fresh.get_prioritised_transactions();
        assert_eq!(got.get(&resident).map(|d| (d.0, d.1)), Some((700, true)));
        assert_eq!(got.get(&absent).map(|d| (d.0, d.1)), Some((300, false)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file from before the trailer ends after its records: it parses
    /// cleanly with no deltas. A trailer cut short keeps the records and the
    /// deltas before the cut.
    #[test]
    fn the_deltas_trailer_is_optional_and_a_short_one_keeps_the_rest() {
        let buf = frame(&[(100, 0, dummy_tx(1))]);
        let parsed = parse(&buf).unwrap();
        assert!(parsed.truncation.is_none());
        assert!(parsed.deltas.is_empty());

        let mut buf = buf;
        buf.extend_from_slice(&2u64.to_le_bytes());
        buf.extend_from_slice(&[0xab; 32]);
        buf.extend_from_slice(&(-5i64).to_le_bytes());
        buf.extend_from_slice(&[0xcd; 20]); // the second delta, cut short
        let parsed = parse(&buf).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.deltas, vec![(bitcoin::Txid::from_byte_array([0xab; 32]), -5)]);
        assert!(parsed.truncation.as_deref().is_some_and(|t| t.contains("delta 1")));
    }

    #[test]
    fn future_version_is_rejected() {
        let mut buf = frame(&[]);
        buf[4..8].copy_from_slice(&(VERSION + 1).to_le_bytes());
        assert!(parse(&buf).is_err(), "unknown future format must not be guessed at");
    }

    #[test]
    fn bad_magic_is_ignored() {
        let dir = temp_datadir("badmagic");
        std::fs::write(dir.join("mempool.dat"), b"XXXXnonsense").unwrap();
        let cs = empty_chainstate(&dir);
        let mp = Mempool::new(300_000_000, 1000);
        let stats = load_mempool(&mp, &cs, &NoopVerifier, &dir).unwrap();
        assert_eq!(stats, LoadStats::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A regtest chain holding one coin per `tag`, and an empty pool under
    /// `min_fee_rate`.
    pub(super) fn funded(tags: &[u8], min_fee_rate: u64) -> (ChainState, Mempool, std::path::PathBuf) {
        let coins: Vec<(OutPoint, crate::storage::coinview::Coin)> = tags
            .iter()
            .map(|t| {
                (
                    funded_prev(*t),
                    crate::storage::coinview::Coin {
                        amount: 100_000,
                        script_pubkey: p2wpkh(0x11),
                        height: 1,
                        coinbase: false,
                        txseq: node_index::TXSEQ_UNKNOWN,
                    },
                )
            })
            .collect();
        let (cs, mp, dir) = crate::mining::template::tests::make_funded_template_env_with(
            &coins,
            Box::new(NoopVerifier),
        );
        mp.reload_policy(crate::mempool::pool::MempoolConfig {
            max_size_bytes: 1_000_000,
            min_fee_rate,
            ..Default::default()
        });
        (cs, mp, dir)
    }

    fn funded_prev(tag: u8) -> OutPoint {
        OutPoint {
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [tag; 32],
            )),
            vout: 0,
        }
    }

    pub(super) fn p2wpkh(tag: u8) -> ScriptBuf {
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[tag; 20]);
        ScriptBuf::from_bytes(spk)
    }

    /// A standard spend of the coin `funded` made for `tag`, paying `fee`.
    pub(super) fn funded_spend(tag: u8, fee: u64) -> bitcoin::Transaction {
        let mut tx = dummy_tx(tag);
        tx.input[0].previous_output = funded_prev(tag);
        tx.output[0] = TxOut { value: Amount::from_sat(100_000 - fee), script_pubkey: p2wpkh(tag) };
        tx
    }

    #[test]
    fn load_keeps_each_records_entry_time() {
        // Core's `LoadMempool` hands the persisted `nTime` to
        // `AcceptToMemoryPool`, so the entry time — and the expiry clock —
        // carry over a restart.
        let (cs, mp, dir) = funded(&[1], 0);
        let then = crate::time::now_secs() - 3_600;
        let tx = funded_spend(1, 1_000);
        let txid = tx.compute_txid();
        std::fs::write(dir.join("mempool.dat"), frame(&[(then, 0, tx)])).unwrap();

        let stats = load_mempool(&mp, &cs, &NoopVerifier, &dir).unwrap();
        assert_eq!(stats.accepted, 1);
        assert_eq!(mp.get(&txid).expect("re-admitted").time, then);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_skips_a_record_past_expiry() {
        // Core keeps a record only when `nTime > now - expiry`.
        let (cs, mp, dir) = funded(&[1, 2], 0);
        let expiry = mp.policy().expiry_secs;
        let now = crate::time::now_secs();
        let old = funded_spend(1, 1_000);
        let fresh = funded_spend(2, 1_000);
        let (old_txid, fresh_txid) = (old.compute_txid(), fresh.compute_txid());
        std::fs::write(
            dir.join("mempool.dat"),
            frame(&[(now - expiry - 60, 0, old), (now - 60, 0, fresh)]),
        )
        .unwrap();

        let stats = load_mempool(&mp, &cs, &NoopVerifier, &dir).unwrap();
        assert_eq!((stats.accepted, stats.skipped, stats.expired), (1, 0, 1));
        assert!(mp.get(&old_txid).is_none(), "an expired record must not re-enter");
        assert!(mp.get(&fresh_txid).is_some(), "a fresh record does");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_applies_the_delta_before_admission() {
        // A transaction that met the relay floor only through
        // `prioritisetransaction`: Core applies the persisted delta first,
        // so it is re-admitted, with the delta counted once.
        let (cs, mp, dir) = funded(&[1, 2], 1_000);
        let now = crate::time::now_secs();
        let lifted = funded_spend(1, 0);
        let plain = funded_spend(2, 0);
        let (lifted_txid, plain_txid) = (lifted.compute_txid(), plain.compute_txid());
        std::fs::write(
            dir.join("mempool.dat"),
            frame(&[(now - 60, 10_000, lifted), (now - 60, 0, plain)]),
        )
        .unwrap();

        let stats = load_mempool(&mp, &cs, &NoopVerifier, &dir).unwrap();
        assert_eq!(stats.accepted, 1);
        assert_eq!(mp.get(&lifted_txid).expect("re-admitted").fee_delta, 10_000);
        assert!(mp.get(&plain_txid).is_none(), "without the delta the floor still refuses it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncated_body_is_tolerated() {
        // Header claims one record but the body is missing — must not
        // panic; just yields nothing.
        let dir = temp_datadir("trunc");
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&1u64.to_le_bytes()); // count=1, no body
        std::fs::write(dir.join("mempool.dat"), &buf).unwrap();

        let cs = empty_chainstate(&dir);
        let mp = Mempool::new(300_000_000, 1000);
        let stats = load_mempool(&mp, &cs, &NoopVerifier, &dir).unwrap();
        assert_eq!(stats, LoadStats::default());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
