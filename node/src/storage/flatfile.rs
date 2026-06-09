use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAX_FILE_SIZE: u64 = 128 * 1024 * 1024; // 128 MB

/// Position of a block within the flat file set.
#[derive(Debug, Clone, Copy)]
pub struct FlatFilePos {
    pub file_number: u32,
    pub data_pos: u32,
}

/// Manages sequential block storage in blk*.dat files.
pub struct FlatFileManager {
    blocks_dir: PathBuf,
    current_file: u32,
    current_pos: u64,
    /// Cached write handle for the current append file.
    write_handle: Option<File>,
    /// True when the current append file has writes not yet fsync'd.
    /// Invariant: only the *current* file can ever be dirty — a file
    /// being rotated out is fsync'd before its handle is dropped, so
    /// `sync_all` never has to chase closed files.
    dirty: bool,
    /// Cached read handles keyed by file number (small LRU).
    read_cache: std::collections::HashMap<u32, File>,
}

impl FlatFileManager {
    pub fn new(blocks_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(blocks_dir)?;

        // Find the latest file and its size
        let mut file_num = 0u32;
        loop {
            let path = blocks_dir.join(format!("blk{:05}.dat", file_num + 1));
            if path.exists() {
                file_num += 1;
            } else {
                break;
            }
        }

        let current_pos = {
            let path = blocks_dir.join(format!("blk{:05}.dat", file_num));
            if path.exists() {
                std::fs::metadata(&path)?.len()
            } else {
                0
            }
        };

        Ok(Self {
            blocks_dir: blocks_dir.to_path_buf(),
            current_file: file_num,
            current_pos,
            write_handle: None,
            dirty: false,
            read_cache: std::collections::HashMap::new(),
        })
    }

    /// Get the blocks directory path.
    pub fn blocks_dir(&self) -> &Path {
        &self.blocks_dir
    }

    fn file_path(&self, file_number: u32) -> PathBuf {
        self.blocks_dir
            .join(format!("blk{:05}.dat", file_number))
    }

    /// Write a block to the flat files. Returns the position where it was stored.
    pub fn write_block(
        &mut self,
        block_data: &[u8],
        network_magic: [u8; 4],
    ) -> std::io::Result<FlatFilePos> {
        // Total size: 4 (magic) + 4 (size) + block_data.len()
        let record_size = 8 + block_data.len() as u64;

        // Roll over to next file if current would exceed max. Fsync the
        // outgoing file first: it will never be written again, and syncing
        // it here keeps the "only the current file can be dirty" invariant
        // that lets `sync_all` ignore closed files.
        if self.current_pos > 0 && self.current_pos + record_size > MAX_FILE_SIZE {
            if self.dirty
                && let Some(f) = &self.write_handle
            {
                f.sync_data()?;
                self.dirty = false;
            }
            self.current_file += 1;
            self.current_pos = 0;
            self.write_handle = None; // Close old handle, open new file below
        }

        let pos = FlatFilePos {
            file_number: self.current_file,
            data_pos: self.current_pos as u32,
        };

        // Reuse cached write handle or open new one
        let file = match &mut self.write_handle {
            Some(f) => f,
            None => {
                let path = self.file_path(self.current_file);
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;
                self.write_handle = Some(f);
                self.write_handle.as_mut().unwrap()
            }
        };

        file.write_all(&network_magic)?;
        file.write_all(&(block_data.len() as u32).to_le_bytes())?;
        file.write_all(block_data)?;

        self.current_pos += record_size;
        self.dirty = true;

        Ok(pos)
    }

    /// Fsync any unsynced block-file writes (Core's `FlushBlockFile`).
    ///
    /// Block data is appended without fsync for throughput, so until this
    /// runs it can sit in the OS page cache — safe across a process crash,
    /// gone on kernel panic/power loss. Callers MUST invoke this before
    /// making any RocksDB state durable that *references* the data
    /// (`block_index` entries with a `FlatFilePos`), or a power loss can
    /// leave the index pointing at truncated files ("block data missing").
    /// `ChainState::flush_durable` does this ordering; rotation in
    /// `write_block` syncs each file as it fills, so at most one file
    /// (the current one) is ever unsynced.
    pub fn sync_all(&mut self) -> std::io::Result<()> {
        if self.dirty
            && let Some(f) = &self.write_handle
        {
            f.sync_data()?;
            self.dirty = false;
        }
        Ok(())
    }

    /// Whether the current append file has unsynced writes (test hook).
    #[cfg(test)]
    pub fn has_unsynced_writes(&self) -> bool {
        self.dirty
    }

    /// Check whether a given flat file exists on disk.
    pub fn file_exists(&self, file_number: u32) -> bool {
        self.file_path(file_number).exists()
    }

    /// Delete a flat file from disk. Invalidates any cached read handle.
    pub fn delete_file(&mut self, file_number: u32) -> std::io::Result<()> {
        self.read_cache.remove(&file_number);
        let path = self.file_path(file_number);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Read a block from the flat files at the given position.
    /// Uses cached file handles to avoid repeated open() syscalls.
    pub fn read_block(&mut self, pos: &FlatFilePos) -> std::io::Result<Vec<u8>> {
        let file = if let Some(f) = self.read_cache.get_mut(&pos.file_number) {
            f
        } else {
            // Evict oldest if cache is large (keep at most 8 open readers)
            if self.read_cache.len() >= 8 {
                let oldest = *self.read_cache.keys().next().unwrap();
                self.read_cache.remove(&oldest);
            }
            let path = self.file_path(pos.file_number);
            let f = File::open(&path)?;
            self.read_cache.entry(pos.file_number).or_insert(f)
        };

        file.seek(SeekFrom::Start(pos.data_pos as u64))?;

        // Read magic (4 bytes) + size (4 bytes)
        let mut header = [0u8; 8];
        file.read_exact(&mut header)?;
        let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;

        let mut data = vec![0u8; size];
        file.read_exact(&mut data)?;
        Ok(data)
    }

    /// Stream every block in `blk*.dat` files, invoking `visit` for each.
    ///
    /// Used by `-reindex` to rebuild the block index from flat files without
    /// holding all blocks in memory at once. The previous `scan_all_blocks`
    /// API returned `Vec<(Vec<u8>, FlatFilePos)>`, which forced ~900 GB of
    /// resident memory on a fully-synced mainnet (945k × ~1 MB) and OOM-
    /// killed the process during reindex.
    ///
    /// Files are read into a 128 MB buffer (one whole `blk*.dat` at a time),
    /// then walked record-by-record. The visitor sees each block's payload
    /// as a borrowed `&[u8]` plus its `FlatFilePos`. The buffer is reused
    /// across files, so peak memory is `O(MAX_FILE_SIZE)` regardless of how
    /// many flat files exist.
    ///
    /// Returns the total number of blocks visited.
    pub fn for_each_block<F>(&self, mut visit: F) -> std::io::Result<u64>
    where
        F: FnMut(&[u8], FlatFilePos) -> std::ops::ControlFlow<()>,
    {
        // Unbounded scan: iterate file 0, 1, 2, ... and stop at the
        // first non-existent file. Cannot delegate to
        // `for_each_block_in_files(0..u32::MAX, ...)` because that
        // iterator would scan 4 billion `path.exists()` calls past the
        // real end of the chain.
        let mut count = 0u64;
        for file_num in 0u32.. {
            let path = self.file_path(file_num);
            if !path.exists() {
                break;
            }
            match Self::scan_one_file(&path, file_num, &mut count, &mut visit)? {
                std::ops::ControlFlow::Break(()) => return Ok(count),
                std::ops::ControlFlow::Continue(()) => {}
            }
        }
        Ok(count)
    }

    /// Scan every block in the given file-number range. Stops on the
    /// first `ControlFlow::Break` returned by the visitor (use this to
    /// early-exit when you've found everything you're looking for).
    ///
    /// Non-existent file numbers are skipped silently (so ranges that
    /// overshoot the actual file set are fine). Use this when you know
    /// which file numbers contain the blocks you care about — it
    /// avoids the full-scan cost of `for_each_block`.
    pub fn for_each_block_in_files<I, F>(
        &self,
        files: I,
        mut visit: F,
    ) -> std::io::Result<u64>
    where
        I: IntoIterator<Item = u32>,
        F: FnMut(&[u8], FlatFilePos) -> std::ops::ControlFlow<()>,
    {
        let mut count = 0u64;
        for file_num in files {
            let path = self.file_path(file_num);
            if !path.exists() {
                continue;
            }
            match Self::scan_one_file(&path, file_num, &mut count, &mut visit)? {
                std::ops::ControlFlow::Break(()) => return Ok(count),
                std::ops::ControlFlow::Continue(()) => {}
            }
        }
        Ok(count)
    }

    /// Scan a single flat-file path: parse each record and invoke the
    /// visitor. Updates `count` per block successfully read. Returns
    /// `Break` if the visitor short-circuits.
    fn scan_one_file<F>(
        path: &std::path::Path,
        file_num: u32,
        count: &mut u64,
        visit: &mut F,
    ) -> std::io::Result<std::ops::ControlFlow<()>>
    where
        F: FnMut(&[u8], FlatFilePos) -> std::ops::ControlFlow<()>,
    {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return Ok(std::ops::ControlFlow::Continue(())),
        };
        let mut offset = 0usize;
        while offset + 8 <= data.len() {
            let size = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;
            if size == 0 || offset + 8 + size > data.len() {
                break;
            }
            let block_slice = &data[offset + 8..offset + 8 + size];
            if let std::ops::ControlFlow::Break(()) = visit(
                block_slice,
                FlatFilePos {
                    file_number: file_num,
                    data_pos: offset as u32,
                },
            ) {
                *count += 1;
                return Ok(std::ops::ControlFlow::Break(()));
            }
            *count += 1;
            offset += 8 + size;
        }
        Ok(std::ops::ControlFlow::Continue(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_read_block() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda]; // regtest
        let block_data = b"fake block data for testing";

        let pos = mgr.write_block(block_data, magic).unwrap();
        assert_eq!(pos.file_number, 0);
        assert_eq!(pos.data_pos, 0);

        let read_back = mgr.read_block(&pos).unwrap();
        assert_eq!(read_back, block_data);

        // Write another block
        let pos2 = mgr.write_block(b"second block", magic).unwrap();
        assert_eq!(pos2.file_number, 0);
        assert!(pos2.data_pos > 0);

        let read_back2 = mgr.read_block(&pos2).unwrap();
        assert_eq!(read_back2, b"second block");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_multiple_blocks_same_file() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-multi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda];

        let pos1 = mgr.write_block(b"block one", magic).unwrap();
        let pos2 = mgr.write_block(b"block two", magic).unwrap();
        let pos3 = mgr.write_block(b"block three", magic).unwrap();

        // All three should be in file 0
        assert_eq!(pos1.file_number, 0);
        assert_eq!(pos2.file_number, 0);
        assert_eq!(pos3.file_number, 0);

        // Positions should be strictly increasing
        assert!(pos2.data_pos > pos1.data_pos);
        assert!(pos3.data_pos > pos2.data_pos);

        // All blocks should be readable
        assert_eq!(mgr.read_block(&pos1).unwrap(), b"block one");
        assert_eq!(mgr.read_block(&pos2).unwrap(), b"block two");
        assert_eq!(mgr.read_block(&pos3).unwrap(), b"block three");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn for_each_block_streams_all_records_in_order() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-stream-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda];
        let payloads: Vec<&[u8]> = vec![b"block one", b"second block payload", b"third"];
        let mut written = Vec::new();
        for p in &payloads {
            written.push(mgr.write_block(p, magic).unwrap());
        }

        let mut visited: Vec<(Vec<u8>, FlatFilePos)> = Vec::new();
        let count = mgr
            .for_each_block(|data, pos| {
                visited.push((data.to_vec(), pos));
                std::ops::ControlFlow::Continue(())
            })
            .unwrap();

        assert_eq!(count, payloads.len() as u64);
        assert_eq!(visited.len(), payloads.len());
        for (i, (data, pos)) in visited.iter().enumerate() {
            assert_eq!(data, payloads[i]);
            assert_eq!(pos.file_number, written[i].file_number);
            assert_eq!(pos.data_pos, written[i].data_pos);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn for_each_block_handles_empty_blocks_dir() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mgr = FlatFileManager::new(&dir).unwrap();
        let mut count = 0;
        mgr.for_each_block(|_, _| {
            count += 1;
            std::ops::ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(count, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_nonexistent() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-noexist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let pos = FlatFilePos {
            file_number: 99,
            data_pos: 0,
        };
        // Reading from a file that doesn't exist should return an error
        assert!(mgr.read_block(&pos).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_exists_and_delete() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-del-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda];

        // Before writing, file 0 doesn't exist
        assert!(!mgr.file_exists(0));

        mgr.write_block(b"data", magic).unwrap();

        // After writing, file 0 exists
        assert!(mgr.file_exists(0));

        // Delete it
        mgr.delete_file(0).unwrap();
        assert!(!mgr.file_exists(0));

        // Deleting a non-existent file should not error
        assert!(mgr.delete_file(99).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_resume_from_existing() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let magic = [0xfa, 0xbf, 0xb5, 0xda];

        // First manager: write one block
        let pos1 = {
            let mut mgr = FlatFileManager::new(&dir).unwrap();
            mgr.write_block(b"first block", magic).unwrap()
        };
        // mgr is dropped here

        // Second manager: should resume from where the first left off
        let mut mgr2 = FlatFileManager::new(&dir).unwrap();
        let pos2 = mgr2.write_block(b"second block", magic).unwrap();

        // Both should be in file 0 and the second should not overwrite the first
        assert_eq!(pos1.file_number, 0);
        assert_eq!(pos2.file_number, 0);
        assert!(pos2.data_pos > pos1.data_pos);

        // Both blocks should be readable
        assert_eq!(mgr2.read_block(&pos1).unwrap(), b"first block");
        assert_eq!(mgr2.read_block(&pos2).unwrap(), b"second block");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_multiple_reads_same_file() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-mread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda];

        let data_a = vec![0xAA; 1024]; // 1 KB block
        let data_b = vec![0xBB; 2048]; // 2 KB block

        let pos_a = mgr.write_block(&data_a, magic).unwrap();
        let pos_b = mgr.write_block(&data_b, magic).unwrap();

        // Read both multiple times — should be consistent
        for _ in 0..3 {
            assert_eq!(mgr.read_block(&pos_a).unwrap(), data_a);
            assert_eq!(mgr.read_block(&pos_b).unwrap(), data_b);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `sync_all` must fsync pending block-file writes, and rotation must
    /// sync the outgoing file so only the current file is ever unsynced —
    /// the invariant `ChainState::flush_durable` relies on to order
    /// "block data durable" before "block_index durable".
    #[test]
    fn sync_all_clears_unsynced_writes_and_rotation_syncs_old_file() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda];

        // Fresh manager: nothing to sync; sync_all is a no-op Ok.
        assert!(!mgr.has_unsynced_writes());
        mgr.sync_all().unwrap();

        // A write dirties the current file; sync_all clears it.
        let pos_a = mgr.write_block(&vec![0xAA; 1024], magic).unwrap();
        assert!(mgr.has_unsynced_writes());
        mgr.sync_all().unwrap();
        assert!(!mgr.has_unsynced_writes());

        // Force a rotation: a write that would exceed MAX_FILE_SIZE rolls
        // to the next file, fsyncing the outgoing one. Afterward only the
        // new (current) file is dirty, and both blocks read back fine.
        mgr.write_block(&vec![0xBB; 512], magic).unwrap(); // dirty file 0 again
        mgr.current_pos = MAX_FILE_SIZE - 4; // next record won't fit
        let pos_c = mgr.write_block(&vec![0xCC; 1024], magic).unwrap();
        assert_eq!(pos_c.file_number, 1, "write must have rotated to a new file");
        assert!(mgr.has_unsynced_writes(), "new current file is dirty");
        mgr.sync_all().unwrap();
        assert!(!mgr.has_unsynced_writes());
        assert_eq!(mgr.read_block(&pos_a).unwrap(), vec![0xAA; 1024]);
        assert_eq!(mgr.read_block(&pos_c).unwrap(), vec![0xCC; 1024]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
