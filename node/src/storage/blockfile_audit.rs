//! Block-file slack audit.
//!
//! Compares the byte ranges referenced by `block_index` entries against the
//! actual on-disk size of every `blk*.dat` file. Any difference is "slack":
//! either gaps between consecutive referenced records (orphan / superseded
//! writes) or trailing bytes at the tail of a file that no index entry points
//! into.
//!
//! Read-only diagnostic. Pulls the 8-byte record header for each indexed
//! block to learn its length (BlockIndexEntry currently stores `file_number`
//! and `data_pos` but not `size`). Cost: ~one seek+read per indexed block,
//! plus one `stat()` per `blk*.dat` file. No full block content is read.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};

use crate::storage::Store;
use crate::storage::blockindex::BlockIndexEntry;

/// Per-file slack accounting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAudit {
    pub file_no: u32,
    pub file_size: u64,
    /// Sum of `8 + record.size` across every `block_index` entry that points
    /// into this file. Reading those 8-byte headers is what we use to learn
    /// each record's length.
    pub referenced_bytes: u64,
    /// `file_size - referenced_bytes`. Positive means there are bytes on disk
    /// that no `block_index` entry covers; negative (rare) means index entries
    /// claim more than fits on disk, i.e. corruption or truncation.
    pub slack_bytes: i64,
    pub indexed_block_count: u64,
    /// Bytes between the end of the highest-positioned indexed record and
    /// the file size. Trailing slack typically means writes happened after
    /// the last `block_index` flush and were never re-referenced.
    pub trailing_slack_bytes: u64,
    /// Bytes covered by gaps between consecutive indexed records within the
    /// file. Inter-record slack typically means a superseded record (block
    /// re-written elsewhere after a reorg or restart).
    pub gap_slack_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditTotals {
    pub file_count: u64,
    pub file_bytes_total: u64,
    pub referenced_bytes_total: u64,
    pub slack_bytes_total: i64,
    pub indexed_block_count: u64,
    pub trailing_slack_total: u64,
    pub gap_slack_total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockfileAuditReport {
    pub blocks_dir: String,
    pub files: Vec<FileAudit>,
    pub totals: AuditTotals,
    pub duration_ms: u64,
    /// Index entries we couldn't locate on disk — usually because the file
    /// no longer exists (pruned) or the position falls past EOF. Diagnostic
    /// signal; non-zero counts are reported separately so slack accounting
    /// stays clean.
    pub unresolved_entries: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("io error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Stream every blk*.dat file in `blocks_dir`, comparing each file's on-disk
/// size against the byte ranges that `block_index` claims live inside it.
///
/// Returns a report keyed by file number. Files with no `block_index`
/// references but that exist on disk show up as 100% slack. Files referenced
/// by the index but missing on disk increment `unresolved_entries`.
pub fn audit_blockfiles(
    store: &dyn Store,
    blocks_dir: &Path,
) -> Result<BlockfileAuditReport, AuditError> {
    let started = Instant::now();

    // 1. Walk block_index, bucket entries by file_number.
    let mut by_file: HashMap<u32, Vec<u32>> = HashMap::new();
    store
        .for_each_block_index(&mut |_hash: BlockHash, entry: BlockIndexEntry| {
            // Pruned blocks have no on-disk data — skip them. They're
            // recorded in block_index for chain bookkeeping but their
            // `(file_number, data_pos)` is stale.
            if matches!(
                entry.status,
                crate::storage::blockindex::BlockStatus::Pruned
            ) {
                return;
            }
            // HeaderOnly entries (header received, data not yet stored)
            // also have no real (file, pos). Skip.
            if matches!(
                entry.status,
                crate::storage::blockindex::BlockStatus::HeaderOnly
            ) {
                return;
            }
            by_file.entry(entry.file_number).or_default().push(entry.data_pos);
        })
        .map_err(|e| AuditError::Storage(format!("{:?}", e)))?;

    // 2. Discover every blk*.dat file on disk (even if no index entry
    // references it — that's the interesting case we want to surface).
    let mut on_disk: HashMap<u32, u64> = HashMap::new();
    let read_dir = std::fs::read_dir(blocks_dir).map_err(|e| AuditError::Io {
        path: blocks_dir.display().to_string(),
        source: e,
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|e| AuditError::Io {
            path: blocks_dir.display().to_string(),
            source: e,
        })?;
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(n) => n,
            None => continue,
        };
        // Match exactly `blk<5 digits>.dat`. Anything else is foreign.
        if !name.starts_with("blk") || !name.ends_with(".dat") || name.len() != 12 {
            continue;
        }
        let digits = &name[3..8];
        let Ok(file_no) = digits.parse::<u32>() else {
            continue;
        };
        let meta = entry.metadata().map_err(|e| AuditError::Io {
            path: entry.path().display().to_string(),
            source: e,
        })?;
        on_disk.insert(file_no, meta.len());
    }

    // 3. For each file present on disk OR referenced by the index, compute
    // the audit. Union both sets so a file that lost its index entries (or
    // index entries that point at a deleted file) both show up.
    let mut all_files: std::collections::BTreeSet<u32> = on_disk.keys().copied().collect();
    for fno in by_file.keys() {
        all_files.insert(*fno);
    }

    let mut files: Vec<FileAudit> = Vec::with_capacity(all_files.len());
    let mut unresolved_entries: u64 = 0;
    let mut totals = AuditTotals::default();

    for file_no in all_files {
        let file_size = on_disk.get(&file_no).copied().unwrap_or(0);
        let positions = by_file.remove(&file_no).unwrap_or_default();

        let (referenced_bytes, indexed_block_count, gap_slack, trailing_slack, unresolved) =
            if file_size == 0 || positions.is_empty() {
                // No file on disk OR file with no indexed records.
                // Either way: every indexed position is unresolved, every
                // on-disk byte is slack (trailing).
                (0u64, 0u64, 0u64, file_size, positions.len() as u64)
            } else {
                measure_file(blocks_dir, file_no, positions, file_size)?
            };

        unresolved_entries += unresolved;
        let slack = file_size as i64 - referenced_bytes as i64;
        totals.file_count += 1;
        totals.file_bytes_total += file_size;
        totals.referenced_bytes_total += referenced_bytes;
        totals.slack_bytes_total += slack;
        totals.indexed_block_count += indexed_block_count;
        totals.trailing_slack_total += trailing_slack;
        totals.gap_slack_total += gap_slack;

        files.push(FileAudit {
            file_no,
            file_size,
            referenced_bytes,
            slack_bytes: slack,
            indexed_block_count,
            trailing_slack_bytes: trailing_slack,
            gap_slack_bytes: gap_slack,
        });
    }

    Ok(BlockfileAuditReport {
        blocks_dir: blocks_dir.display().to_string(),
        files,
        totals,
        duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        unresolved_entries,
    })
}

/// Per-file slack measurement. Sorts the indexed positions, reads an 8-byte
/// record header for each one to learn the record length, and accumulates
/// slack between consecutive records plus any trailing bytes past the highest
/// indexed end-of-record.
///
/// Returns `(referenced_bytes, indexed_block_count, gap_slack,
/// trailing_slack, unresolved_count)`.
fn measure_file(
    blocks_dir: &Path,
    file_no: u32,
    mut positions: Vec<u32>,
    file_size: u64,
) -> Result<(u64, u64, u64, u64, u64), AuditError> {
    positions.sort_unstable();
    let path = blocks_dir.join(format!("blk{:05}.dat", file_no));
    let mut file = File::open(&path).map_err(|e| AuditError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut referenced_bytes: u64 = 0;
    let mut indexed_count: u64 = 0;
    let mut gap_slack: u64 = 0;
    let mut unresolved: u64 = 0;
    let mut prev_end: u64 = 0; // exclusive upper bound of the previous record

    let mut header = [0u8; 8];
    for pos in positions {
        let pos64 = pos as u64;
        if pos64 + 8 > file_size {
            unresolved += 1;
            continue;
        }
        // Gap from the previous record's end to this record's start is slack
        // (some superseded write that block_index moved away from).
        if pos64 > prev_end {
            gap_slack += pos64 - prev_end;
        }
        // (pos64 < prev_end would mean overlapping records — corruption.
        // We don't double-count: the overlapping bytes count as referenced
        // by both, which inflates the reference total slightly, which the
        // operator sees as a negative slack on the totals line. That's the
        // honest reporting we want.)
        if let Err(e) = file.seek(SeekFrom::Start(pos64)) {
            return Err(AuditError::Io {
                path: path.display().to_string(),
                source: e,
            });
        }
        if let Err(e) = file.read_exact(&mut header) {
            // EOF mid-header: unresolved.
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                unresolved += 1;
                continue;
            }
            return Err(AuditError::Io {
                path: path.display().to_string(),
                source: e,
            });
        }
        let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as u64;
        let record_size = 8 + size;
        if pos64 + record_size > file_size {
            // Record claims to extend past EOF: truncated or corrupt entry.
            // Count what fits and flag it as unresolved so the slack total
            // doesn't go negative on this file.
            unresolved += 1;
            continue;
        }
        referenced_bytes += record_size;
        indexed_count += 1;
        prev_end = pos64 + record_size;
    }

    let trailing_slack = file_size.saturating_sub(prev_end);
    Ok((
        referenced_bytes,
        indexed_count,
        gap_slack,
        trailing_slack,
        unresolved,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StoreBatch;
    use crate::storage::blockindex::{BlockIndexEntry, BlockStatus};
    use crate::storage::flatfile::FlatFileManager;
    use crate::storage::rocksdb_store::RocksDbStore;
    use bitcoin::block::Header;
    use bitcoin::hashes::Hash;
    use bitcoin::pow::CompactTarget;
    use bitcoin::{BlockHash, TxMerkleNode};

    fn dummy_header() -> Header {
        Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        }
    }

    fn dummy_index_entry(file_number: u32, data_pos: u32) -> BlockIndexEntry {
        BlockIndexEntry {
            header: dummy_header(),
            height: 0,
            status: BlockStatus::DataStored,
            num_tx: 1,
            file_number,
            data_pos,
            chainwork: [0u8; 32],
        }
    }

    fn make_hash(n: u8) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(bytes))
    }

    fn open_store(dir: &Path) -> RocksDbStore {
        RocksDbStore::open(dir, false, 16, false, -1).unwrap()
    }

    /// Smoke test: a fresh blocks dir with two written blocks and matching
    /// block_index entries → 0 slack.
    #[test]
    fn audit_zero_slack_when_index_matches_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let blocks_dir = tmp.path().join("blocks");
        let db_dir = tmp.path().join("db");
        std::fs::create_dir_all(&blocks_dir).unwrap();
        std::fs::create_dir_all(&db_dir).unwrap();

        let mut flat = FlatFileManager::new(&blocks_dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda];
        let block_a = vec![0xAAu8; 1024];
        let block_b = vec![0xBBu8; 2048];
        let pos_a = flat.write_block(&block_a, magic).unwrap();
        let pos_b = flat.write_block(&block_b, magic).unwrap();
        drop(flat);

        let store = open_store(&db_dir);
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((
            make_hash(1),
            dummy_index_entry(pos_a.file_number, pos_a.data_pos),
        ));
        batch.block_index_puts.push((
            make_hash(2),
            dummy_index_entry(pos_b.file_number, pos_b.data_pos),
        ));
        store.write_batch(batch).unwrap();

        let report = audit_blockfiles(&store, &blocks_dir).unwrap();
        assert_eq!(report.totals.file_count, 1);
        assert_eq!(report.totals.indexed_block_count, 2);
        assert_eq!(report.totals.slack_bytes_total, 0);
        assert_eq!(report.unresolved_entries, 0);
        assert_eq!(report.files[0].slack_bytes, 0);
        assert_eq!(report.files[0].gap_slack_bytes, 0);
        assert_eq!(report.files[0].trailing_slack_bytes, 0);
    }

    /// Write three blocks, but only index the first and third. The middle
    /// block's bytes show up as gap_slack.
    #[test]
    fn audit_detects_gap_slack_for_unreferenced_records() {
        let tmp = tempfile::tempdir().unwrap();
        let blocks_dir = tmp.path().join("blocks");
        let db_dir = tmp.path().join("db");
        std::fs::create_dir_all(&blocks_dir).unwrap();
        std::fs::create_dir_all(&db_dir).unwrap();

        let mut flat = FlatFileManager::new(&blocks_dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda];
        let block_a = vec![0xAAu8; 1024];
        let block_b = vec![0xBBu8; 4096];
        let block_c = vec![0xCCu8; 512];
        let pos_a = flat.write_block(&block_a, magic).unwrap();
        let _pos_b = flat.write_block(&block_b, magic).unwrap();
        let pos_c = flat.write_block(&block_c, magic).unwrap();
        drop(flat);

        let store = open_store(&db_dir);
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((
            make_hash(1),
            dummy_index_entry(pos_a.file_number, pos_a.data_pos),
        ));
        batch.block_index_puts.push((
            make_hash(3),
            dummy_index_entry(pos_c.file_number, pos_c.data_pos),
        ));
        store.write_batch(batch).unwrap();

        let report = audit_blockfiles(&store, &blocks_dir).unwrap();
        assert_eq!(report.totals.indexed_block_count, 2);
        assert_eq!(report.files[0].gap_slack_bytes, 8 + 4096);
        assert_eq!(report.files[0].trailing_slack_bytes, 0);
        assert_eq!(report.totals.slack_bytes_total, 8 + 4096);
    }

    /// HeaderOnly and Pruned entries don't reference on-disk data; they
    /// must not influence the audit. Verifies the early-return guards in
    /// the visitor closure: without those, a HeaderOnly entry pointing at
    /// a stale `(file, pos)` would inflate `unresolved_entries` and skew
    /// the slack accounting.
    #[test]
    fn audit_ignores_header_only_and_pruned_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let blocks_dir = tmp.path().join("blocks");
        let db_dir = tmp.path().join("db");
        std::fs::create_dir_all(&blocks_dir).unwrap();
        std::fs::create_dir_all(&db_dir).unwrap();

        let mut flat = FlatFileManager::new(&blocks_dir).unwrap();
        let pos = flat
            .write_block(&[0u8; 128], [0xfa, 0xbf, 0xb5, 0xda])
            .unwrap();
        drop(flat);

        let store = open_store(&db_dir);
        let mut entry_header_only = dummy_index_entry(0, 9_999_999);
        entry_header_only.status = BlockStatus::HeaderOnly;
        let mut entry_pruned = dummy_index_entry(0, 9_999_999);
        entry_pruned.status = BlockStatus::Pruned;
        let mut batch = StoreBatch::default();
        batch.block_index_puts.push((make_hash(1), entry_header_only));
        batch.block_index_puts.push((make_hash(2), entry_pruned));
        batch.block_index_puts.push((
            make_hash(3),
            dummy_index_entry(pos.file_number, pos.data_pos),
        ));
        store.write_batch(batch).unwrap();

        let report = audit_blockfiles(&store, &blocks_dir).unwrap();
        assert_eq!(report.unresolved_entries, 0);
        assert_eq!(report.totals.indexed_block_count, 1);
        assert_eq!(report.totals.slack_bytes_total, 0);
    }

    /// A file referenced by no index entry shows up as 100% trailing slack
    /// — this is what we expect to see if a `blk*.dat` got written but the
    /// corresponding block_index entry was lost or moved to a different
    /// (file, pos).
    #[test]
    fn audit_reports_unreferenced_files_as_trailing_slack() {
        let tmp = tempfile::tempdir().unwrap();
        let blocks_dir = tmp.path().join("blocks");
        let db_dir = tmp.path().join("db");
        std::fs::create_dir_all(&blocks_dir).unwrap();
        std::fs::create_dir_all(&db_dir).unwrap();

        let mut flat = FlatFileManager::new(&blocks_dir).unwrap();
        let block_a = vec![0xAAu8; 512];
        let _pos = flat
            .write_block(&block_a, [0xfa, 0xbf, 0xb5, 0xda])
            .unwrap();
        drop(flat);

        let store = open_store(&db_dir);
        // No block_index entries.
        let report = audit_blockfiles(&store, &blocks_dir).unwrap();
        assert_eq!(report.totals.file_count, 1);
        assert_eq!(report.totals.indexed_block_count, 0);
        assert_eq!(report.files[0].trailing_slack_bytes, 8 + 512);
        assert_eq!(report.files[0].slack_bytes, 8 + 512);
    }
}
