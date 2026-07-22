use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAX_FILE_SIZE: u64 = 128 * 1024 * 1024; // 128 MB

/// The all-zero XOR key: on-disk bytes are stored as-is (plaintext).
const ZERO_XOR_KEY: [u8; 8] = [0u8; 8];

/// How to initialize the blocks-dir obfuscation key when `blocks/xor.dat`
/// is absent. An *existing* `xor.dat` is always honored regardless of mode
/// (except that [`XorMode::Disabled`] refuses a nonzero stored key, matching
/// Bitcoin Core's fatal error for `-blocksxor=0`).
///
/// Bitcoin Core v28.0+ XOR-obfuscates `blk*.dat` / `rev*.dat` payloads on
/// disk with a random 8-byte key persisted in `blocks/xor.dat` (default
/// `-blocksxor=1`). Each byte at absolute file offset `o` is stored as
/// `plain[o] ^ key[o % 8]`. Supporting that key is what lets satd reuse a
/// modern Core `blocks/` directory; plaintext (the zero key) remains satd's
/// native format and fully supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XorMode {
    /// satd's default: honor an existing key; initialize a missing
    /// `xor.dat` to the zero key so fresh satd datadirs stay plaintext.
    #[default]
    Auto,
    /// Core's `-blocksxor=1`: honor an existing key; generate a *random*
    /// key when initializing a brand-new (first-run) blocks dir. Like
    /// Core, an already-populated plaintext dir keeps the zero key —
    /// existing files cannot be obfuscated retroactively.
    Enabled,
    /// Core's `-blocksxor=0`: demand plaintext. Initializes a missing
    /// `xor.dat` to the zero key and refuses to open a blocks dir whose
    /// stored key is nonzero (Core parity — silently ignoring the key
    /// would corrupt every subsequent write).
    Disabled,
}

/// XOR `data` in place against the repeating 8-byte `key`, where `data[0]`
/// sits at absolute file offset `offset`. No-op for the zero key, so the
/// plaintext path costs one comparison. Processes 8 bytes per step via a
/// phase-rotated `u64` so full-file de-obfuscation during `-reindex` runs at
/// memory bandwidth rather than byte-at-a-time.
pub(crate) fn xor_in_place(data: &mut [u8], key: &[u8; 8], offset: u64) {
    if *key == ZERO_XOR_KEY {
        return;
    }
    // rot[i] == key[(offset + i) % 8]: the key phase-shifted to `offset`.
    let phase = (offset % 8) as usize;
    let mut rot = [0u8; 8];
    for (i, r) in rot.iter_mut().enumerate() {
        *r = key[(phase + i) % 8];
    }
    let word = u64::from_ne_bytes(rot);
    let mut chunks = data.chunks_exact_mut(8);
    for chunk in &mut chunks {
        let v = u64::from_ne_bytes(chunk.try_into().unwrap()) ^ word;
        chunk.copy_from_slice(&v.to_ne_bytes());
    }
    for (i, b) in chunks.into_remainder().iter_mut().enumerate() {
        *b ^= rot[i % 8];
    }
}

/// Read the blocks-dir obfuscation key from `blocks/xor.dat`, or the zero
/// key if the file does not exist. Read-only companion to the loading done
/// by [`FlatFileManager::with_xor_mode`] for consumers (e.g. the block-file
/// audit) that inspect raw record headers without opening a manager.
pub fn read_xor_key(blocks_dir: &Path) -> std::io::Result<[u8; 8]> {
    let path = blocks_dir.join("xor.dat");
    match std::fs::read(&path) {
        Ok(bytes) => bytes.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{}: expected exactly 8 key bytes, found {}",
                    path.display(),
                    bytes.len()
                ),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ZERO_XOR_KEY),
        Err(e) => Err(e),
    }
}

/// Load the obfuscation key per `mode`, creating `xor.dat` if missing.
/// Mirrors Bitcoin Core's `InitBlocksdirXorKey`: a dir is "first-run" when
/// it contains only hidden (dot-prefixed) entries — a `.lock` file may
/// already exist, so an empty-dir check would be too strict.
fn init_xor_key(blocks_dir: &Path, mode: XorMode) -> std::io::Result<[u8; 8]> {
    let path = blocks_dir.join("xor.dat");
    if path.exists() {
        let key = read_xor_key(blocks_dir)?;
        if mode == XorMode::Disabled && key != ZERO_XOR_KEY {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "blocksxor=0 but {} holds the nonzero key {} — the existing \
                     *.dat files are XOR-obfuscated with it and cannot be read as \
                     plaintext. Remove blocksxor=0 to use the stored key.",
                    path.display(),
                    key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                ),
            ));
        }
        return Ok(key);
    }

    let first_run = std::fs::read_dir(blocks_dir)?.try_fold(true, |acc, entry| {
        entry.map(|e| acc && e.file_name().to_string_lossy().starts_with('.'))
    })?;
    let key = if mode == XorMode::Enabled && first_run {
        rand::random::<[u8; 8]>()
    } else {
        ZERO_XOR_KEY
    };
    // create_new: never clobber a key racing into existence — a wrong key
    // silently corrupts every subsequent write.
    let mut f = OpenOptions::new().write(true).create_new(true).open(&path)?;
    f.write_all(&key)?;
    f.sync_all()?;
    Ok(key)
}

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
    /// Blocks-dir obfuscation key from `xor.dat` (Core v28+). The zero key
    /// means plaintext and short-circuits every XOR call.
    xor_key: [u8; 8],
}

impl FlatFileManager {
    /// Open `blocks_dir` with [`XorMode::Auto`]: honor an existing
    /// `xor.dat` (so Core v28+ obfuscated dirs read transparently),
    /// initialize fresh dirs to plaintext.
    pub fn new(blocks_dir: &Path) -> std::io::Result<Self> {
        Self::with_xor_mode(blocks_dir, XorMode::Auto)
    }

    pub fn with_xor_mode(blocks_dir: &Path, mode: XorMode) -> std::io::Result<Self> {
        std::fs::create_dir_all(blocks_dir)?;
        let xor_key = init_xor_key(blocks_dir, mode)?;

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
            xor_key,
        })
    }

    /// Get the blocks directory path.
    pub fn blocks_dir(&self) -> &Path {
        &self.blocks_dir
    }

    /// The active `xor.dat` obfuscation key (zero = plaintext).
    pub fn xor_key(&self) -> [u8; 8] {
        self.xor_key
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

        if self.xor_key == ZERO_XOR_KEY {
            file.write_all(&network_magic)?;
            file.write_all(&(block_data.len() as u32).to_le_bytes())?;
            file.write_all(block_data)?;
        } else {
            // Obfuscated (Core v28+ `xor.dat`): every on-disk byte is
            // XORed with the key at its absolute file offset.
            let mut header = [0u8; 8];
            header[..4].copy_from_slice(&network_magic);
            header[4..].copy_from_slice(&(block_data.len() as u32).to_le_bytes());
            xor_in_place(&mut header, &self.xor_key, self.current_pos);
            file.write_all(&header)?;
            let mut payload = block_data.to_vec();
            xor_in_place(&mut payload, &self.xor_key, self.current_pos + 8);
            file.write_all(&payload)?;
        }

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
        xor_in_place(&mut header, &self.xor_key, pos.data_pos as u64);
        let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;

        // A record never exceeds one flat file (write_block rolls over).
        // A larger size means a corrupt header or data written under a
        // different xor key — fail cleanly instead of attempting a
        // multi-GB allocation off garbage length bytes.
        if size as u64 + 8 > MAX_FILE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "block record at blk{:05}.dat:{} claims {} bytes (max {}): \
                     corrupt header or mismatched blocks-dir xor key",
                    pos.file_number,
                    pos.data_pos,
                    size,
                    MAX_FILE_SIZE - 8,
                ),
            ));
        }

        let mut data = vec![0u8; size];
        file.read_exact(&mut data)?;
        xor_in_place(&mut data, &self.xor_key, pos.data_pos as u64 + 8);
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
            match self.scan_one_file(&path, file_num, &mut count, &mut visit)? {
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
            match self.scan_one_file(&path, file_num, &mut count, &mut visit)? {
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
        &self,
        path: &std::path::Path,
        file_num: u32,
        count: &mut u64,
        visit: &mut F,
    ) -> std::io::Result<std::ops::ControlFlow<()>>
    where
        F: FnMut(&[u8], FlatFilePos) -> std::ops::ControlFlow<()>,
    {
        let mut data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return Ok(std::ops::ControlFlow::Continue(())),
        };
        xor_in_place(&mut data, &self.xor_key, 0);
        let key = &self.xor_key;
        let mut offset = 0usize;
        while offset + 8 <= data.len() {
            // Terminate on zero-preallocated padding. Bitcoin Core extends
            // its current blk file in chunks of raw zeros written *without*
            // obfuscation, so after de-obfuscation a padding byte at
            // absolute offset `o` reads as `key[o % 8]`. A whole header of
            // that pattern is EOF padding, not a record (a real record
            // matching it needs magic AND length to collide with the key
            // phase: ~2^-64). With the zero key this degenerates to the
            // classic all-zero header, which the size == 0 check below
            // also catches.
            if data[offset..offset + 8]
                .iter()
                .enumerate()
                .all(|(i, b)| *b == key[(offset + i) % 8])
            {
                break;
            }
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

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "satd-flatfile-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Reference implementation: byte-at-a-time absolute-offset XOR, the
    /// operation Bitcoin Core's `util::Xor` performs on blocksdir files.
    fn naive_xor(data: &mut [u8], key: &[u8; 8], offset: u64) {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= key[((offset as usize) + i) % 8];
        }
    }

    #[test]
    fn xor_in_place_matches_naive_at_all_phases() {
        let key = [0x1d, 0x02, 0xff, 0x80, 0x00, 0xa5, 0x5a, 0x33];
        for offset in 0u64..17 {
            for len in 0usize..40 {
                let plain: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                let mut fast = plain.clone();
                let mut slow = plain.clone();
                xor_in_place(&mut fast, &key, offset);
                naive_xor(&mut slow, &key, offset);
                assert_eq!(fast, slow, "offset={offset} len={len}");
                // Involution: applying twice restores the plaintext.
                xor_in_place(&mut fast, &key, offset);
                assert_eq!(fast, plain, "offset={offset} len={len}");
            }
        }
        // Zero key is a strict no-op.
        let mut buf = vec![0xAB; 32];
        xor_in_place(&mut buf, &ZERO_XOR_KEY, 5);
        assert_eq!(buf, vec![0xAB; 32]);
    }

    #[test]
    fn keyed_round_trip_with_rotation_reopen_and_scan() {
        let dir = temp_dir("keyed-rt");
        let magic = [0xfa, 0xbf, 0xb5, 0xda];

        // Fresh dir + Enabled = random key (Core -blocksxor=1 first run).
        let (positions, key) = {
            let mut mgr = FlatFileManager::with_xor_mode(&dir, XorMode::Enabled).unwrap();
            let key = mgr.xor_key();
            let mut positions = Vec::new();
            positions.push(mgr.write_block(&[0x11; 300], magic).unwrap());
            positions.push(mgr.write_block(&[0x22; 5000], magic).unwrap());
            // Force rotation into a second file so the key phase restarts
            // at a fresh absolute offset 0.
            mgr.current_pos = MAX_FILE_SIZE - 4;
            positions.push(mgr.write_block(&[0x33; 700], magic).unwrap());
            assert_eq!(positions[2].file_number, 1);
            (positions, key)
        };
        // On-disk bytes must NOT contain the plaintext run when keyed.
        if key != ZERO_XOR_KEY {
            let raw = std::fs::read(dir.join("blk00000.dat")).unwrap();
            assert_ne!(&raw[8..16], &[0x11; 8], "payload must be obfuscated on disk");
        }

        // Reopen with the plain constructor: xor.dat is honored automatically.
        let mut mgr = FlatFileManager::new(&dir).unwrap();
        assert_eq!(mgr.xor_key(), key);
        assert_eq!(mgr.read_block(&positions[0]).unwrap(), vec![0x11; 300]);
        assert_eq!(mgr.read_block(&positions[1]).unwrap(), vec![0x22; 5000]);
        assert_eq!(mgr.read_block(&positions[2]).unwrap(), vec![0x33; 700]);

        // The reindex scan path de-obfuscates too.
        let mut seen = Vec::new();
        let count = mgr
            .for_each_block(|data, pos| {
                seen.push((data.to_vec(), pos.file_number, pos.data_pos));
                std::ops::ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(count, 3);
        assert_eq!(seen[0].0, vec![0x11; 300]);
        assert_eq!(seen[2].0, vec![0x33; 700]);
        assert_eq!(seen[2].1, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Golden cross-check against an independently-constructed obfuscated
    /// file: build the plaintext record image, XOR it with the reference
    /// (naive) implementation exactly the way Core stores it, drop in an
    /// `xor.dat`, and require both read paths to recover the payloads.
    #[test]
    fn core_style_obfuscated_dir_reads_back() {
        let dir = temp_dir("core-golden");
        std::fs::create_dir_all(&dir).unwrap();
        let magic = [0xf9, 0xbe, 0xb4, 0xd9]; // mainnet
        let key = [0x8f, 0x1a, 0x00, 0xc4, 0x5e, 0x21, 0xd0, 0x77];
        let payloads: [&[u8]; 2] = [b"first mainnet-ish block payload", b"second"];

        let mut image = Vec::new();
        let mut positions = Vec::new();
        for p in payloads {
            positions.push(image.len() as u32);
            image.extend_from_slice(&magic);
            image.extend_from_slice(&(p.len() as u32).to_le_bytes());
            image.extend_from_slice(p);
        }
        naive_xor(&mut image, &key, 0);
        std::fs::write(dir.join("blk00000.dat"), &image).unwrap();
        std::fs::write(dir.join("xor.dat"), key).unwrap();

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        assert_eq!(mgr.xor_key(), key);
        for (p, &data_pos) in payloads.iter().zip(&positions) {
            let pos = FlatFilePos { file_number: 0, data_pos };
            assert_eq!(mgr.read_block(&pos).unwrap(), *p);
        }
        let mut seen = Vec::new();
        mgr.for_each_block(|data, _| {
            seen.push(data.to_vec());
            std::ops::ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(seen, payloads.iter().map(|p| p.to_vec()).collect::<Vec<_>>());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Core zero-preallocates the tail of the current blk file with raw
    /// (unobfuscated) zeros. The scan must stop there, not chain garbage.
    #[test]
    fn scan_terminates_on_raw_zero_padding_under_nonzero_key() {
        let dir = temp_dir("padding");
        std::fs::create_dir_all(&dir).unwrap();
        let magic = [0xf9, 0xbe, 0xb4, 0xd9];
        let key = [0x07, 0xc3, 0x19, 0x00, 0xee, 0x42, 0x9d, 0x61];
        std::fs::write(dir.join("xor.dat"), key).unwrap();

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        mgr.write_block(b"real block", magic).unwrap();
        // Simulate Core's preallocation: raw zeros appended after the record.
        {
            use std::io::Write as _;
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.join("blk00000.dat"))
                .unwrap();
            f.write_all(&[0u8; 4096]).unwrap();
        }
        let mut seen = 0u32;
        let count = mgr
            .for_each_block(|data, _| {
                assert_eq!(data, b"real block");
                seen += 1;
                std::ops::ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(seen, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn xor_key_initialization_matrix() {
        // Fresh dir, Auto: plaintext zero key, xor.dat created.
        let dir = temp_dir("init-auto");
        let mgr = FlatFileManager::new(&dir).unwrap();
        assert_eq!(mgr.xor_key(), ZERO_XOR_KEY);
        assert_eq!(std::fs::read(dir.join("xor.dat")).unwrap(), vec![0u8; 8]);
        let _ = std::fs::remove_dir_all(&dir);

        // Fresh dir, Disabled: zero key.
        let dir = temp_dir("init-disabled");
        let mgr = FlatFileManager::with_xor_mode(&dir, XorMode::Disabled).unwrap();
        assert_eq!(mgr.xor_key(), ZERO_XOR_KEY);
        let _ = std::fs::remove_dir_all(&dir);

        // Fresh dir containing only hidden entries is still "first run":
        // Enabled generates a random key (2^-64 flake accepted).
        let dir = temp_dir("init-enabled");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".lock"), b"").unwrap();
        let mgr = FlatFileManager::with_xor_mode(&dir, XorMode::Enabled).unwrap();
        assert_ne!(mgr.xor_key(), ZERO_XOR_KEY);
        let _ = std::fs::remove_dir_all(&dir);

        // Populated plaintext dir (blk files, xor.dat gone — the pre-xor
        // satd upgrade path), Enabled: NOT first run, so the key stays
        // zero — existing plaintext can't be obfuscated retroactively.
        let dir = temp_dir("init-populated");
        {
            let mut mgr = FlatFileManager::new(&dir).unwrap();
            mgr.write_block(b"old plaintext block", [0xfa, 0xbf, 0xb5, 0xda])
                .unwrap();
        }
        std::fs::remove_file(dir.join("xor.dat")).unwrap();
        let mut mgr = FlatFileManager::with_xor_mode(&dir, XorMode::Enabled).unwrap();
        assert_eq!(mgr.xor_key(), ZERO_XOR_KEY);
        assert_eq!(
            mgr.read_block(&FlatFilePos { file_number: 0, data_pos: 0 })
                .unwrap(),
            b"old plaintext block"
        );
        let _ = std::fs::remove_dir_all(&dir);

        // Disabled + stored nonzero key: refuse (Core parity).
        let dir = temp_dir("init-conflict");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("xor.dat"), [1u8; 8]).unwrap();
        let err = FlatFileManager::with_xor_mode(&dir, XorMode::Disabled)
            .err()
            .expect("must refuse nonzero stored key with Disabled");
        assert!(err.to_string().contains("blocksxor=0"), "{err}");
        // Auto and Enabled both honor it.
        assert_eq!(FlatFileManager::new(&dir).unwrap().xor_key(), [1u8; 8]);
        assert_eq!(
            FlatFileManager::with_xor_mode(&dir, XorMode::Enabled)
                .unwrap()
                .xor_key(),
            [1u8; 8]
        );
        let _ = std::fs::remove_dir_all(&dir);

        // Truncated xor.dat: hard error, never guess a key.
        let dir = temp_dir("init-badlen");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("xor.dat"), [1u8; 5]).unwrap();
        assert!(FlatFileManager::new(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reading under the wrong key must fail cleanly (garbage length is
    /// rejected), never allocate off garbage or hand back scrambled bytes
    /// as a "block".
    #[test]
    fn wrong_key_read_errors_cleanly() {
        let dir = temp_dir("wrong-key");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("xor.dat"), [0xAA; 8]).unwrap();
        let pos = {
            let mut mgr = FlatFileManager::new(&dir).unwrap();
            mgr.write_block(&[0x44; 2048], [0xf9, 0xbe, 0xb4, 0xd9]).unwrap()
        };
        // Swap the key out from under the files.
        std::fs::write(dir.join("xor.dat"), [0x55; 8]).unwrap();
        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let res = mgr.read_block(&pos);
        match res {
            Err(_) => {}
            Ok(data) => assert_ne!(data, vec![0x44; 2048], "must not decode under wrong key"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
