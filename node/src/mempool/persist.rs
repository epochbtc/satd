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
//! ```
//!
//! v2 added the `flags` byte so the unbroadcast set survives a restart —
//! Bitcoin Core persists `m_unbroadcast_txids` in its mempool.dat for the
//! same reason: a tx submitted just before shutdown that never reached a
//! peer must resume rebroadcasting after the restart, not strand.

use std::path::Path;

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
}

/// Serialize the current mempool to `<net_datadir>/mempool.dat`.
///
/// Writes to a temp file and renames so a crash mid-write can't leave a
/// torn file that breaks the next startup. Returns the number of
/// transactions written.
pub fn dump_mempool(mempool: &Mempool, net_datadir: &Path) -> std::io::Result<usize> {
    let entries = mempool.get_all_entries();
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

    // Re-admit oldest-first so a parent that entered before its child is
    // accepted first; a child whose parent fails still just gets skipped.
    let mut records = parsed.records;
    records.sort_by_key(|r| r.time);

    let mut stats = LoadStats::default();
    for rec in records {
        let fee_delta = rec.fee_delta;
        let unbroadcast = rec.flags & FLAG_UNBROADCAST != 0;
        match mempool.accept_transaction(rec.tx, chain_state, script_verifier) {
            Ok(txid) => {
                if fee_delta != 0 && !mempool.prioritise_transaction(&txid, fee_delta) {
                    tracing::debug!(%txid, "persisted fee_delta not applied (tx absent post-accept)");
                }
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
    Ok(stats)
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
    Ok(ParsedDump {
        records,
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
        )
        .unwrap()
    }

    fn dummy_tx(nonce: u8) -> bitcoin::Transaction {
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
    fn frame(records: &[(u64, i64, bitcoin::Transaction)]) -> Vec<u8> {
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
        // both are skipped by re-validation.
        let dir = temp_datadir("decode");
        let buf = frame(&[(100, 0, dummy_tx(1)), (200, 500, dummy_tx(2))]);
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
