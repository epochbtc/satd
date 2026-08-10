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
            // Fsync the outgoing file first: it will never be written again,
            // and syncing it here keeps the "only the current file can be
            // dirty" invariant that lets `sync_all` ignore closed files.
            self.release_write_handle()?;
            self.current_file += 1;
            // Derive the new offset from the file rather than assuming zero.
            // The next file number is normally absent, but it need not be:
            // `with_xor_mode`'s discovery loop stops at the first *gap*, and
            // `delete_file` (pruning) makes gaps by removing low-numbered
            // files. A pruned datadir can therefore reopen with a low
            // `current_file` while populated files sit above it, and rotating
            // into one of those with `current_pos = 0` would record every
            // subsequent record at an offset it was not written at — the
            // append-mode corruption `resync_append_pos` exists to prevent,
            // reached through the rotation door.
            self.resync_append_pos()?;
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
                let existed = path.exists();
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;
                if !existed {
                    // fsync the directory so the new file's name is durable.
                    // Without this a power loss can leave a fully-fsync'd blk
                    // file with no directory entry while the `block_index`
                    // rows pointing into it are committed — the same
                    // "pointer outlives the data" failure this module guards
                    // against, once per 128 MB rollover. Best-effort: not
                    // every platform/filesystem supports directory fsync.
                    if let Ok(dir) = File::open(&self.blocks_dir) {
                        let _ = dir.sync_all();
                    }
                }
                self.write_handle = Some(f);
                self.write_handle.as_mut().unwrap()
            }
        };

        // Copy what the write needs so the closure borrows only `file` —
        // `file` is itself borrowed from `self.write_handle`, and the error
        // arm below needs `&mut self`.
        let xor_key = self.xor_key;
        let record_start = self.current_pos;
        let write_result = (|| -> std::io::Result<()> {
            if xor_key == ZERO_XOR_KEY {
                file.write_all(&network_magic)?;
                file.write_all(&(block_data.len() as u32).to_le_bytes())?;
                file.write_all(block_data)?;
            } else {
                // Obfuscated (Core v28+ `xor.dat`): every on-disk byte is
                // XORed with the key at its absolute file offset.
                let mut header = [0u8; 8];
                header[..4].copy_from_slice(&network_magic);
                header[4..].copy_from_slice(&(block_data.len() as u32).to_le_bytes());
                xor_in_place(&mut header, &xor_key, record_start);
                file.write_all(&header)?;
                let mut payload = block_data.to_vec();
                xor_in_place(&mut payload, &xor_key, record_start + 8);
                file.write_all(&payload)?;
            }
            Ok(())
        })();

        if let Err(e) = write_result {
            // A failed `write_all` — ENOSPC mid-record is the realistic one —
            // may still have put bytes on disk. `current_pos` was not advanced,
            // so it now understates the real end of file, and because the
            // handle is `append(true)` the next write would land at the true
            // EOF while being *recorded* at this stale, lower offset: every
            // subsequent index entry would point into the middle of its
            // predecessor's record.
            //
            // Cut the torn record off rather than appending past it. Adopting
            // the torn EOF would keep the offsets honest but leave a record
            // whose length field describes bytes that were never written, and
            // the sequential scanners (`for_each_block`, used by `-reindex`
            // and the hole repair) have no resynchronization: they read that
            // length, step over it, land mid-stream, and `break` — silently
            // dropping every remaining block in a file that can hold 128 MB of
            // them. Truncation is safe by construction, since `current_pos`
            // was never advanced and so no `block_index` entry can reference
            // anything at or after `record_start`.
            // The write error is what the caller needs to see, so it wins.
            // A truncation failure is strictly worse — it leaves the torn
            // record in place with `current_pos` still pointing before it, so
            // the next write would append over it and record the new block at
            // a stale offset — but it is also strictly rarer, and losing the
            // original cause would make the common case undiagnosable. Log it
            // loudly and return the cause.
            if let Err(te) = self.truncate_current_file_to(record_start) {
                tracing::error!(
                    file = self.current_file,
                    record_start,
                    "failed to truncate a torn block record after a failed write: {te}; \
                     the file may now contain a partial record"
                );
            }
            return Err(e);
        }

        self.current_pos += record_size;
        self.dirty = true;

        Ok(pos)
    }

    /// Cut the current append file back to `len` and resync the append offset.
    /// Used to discard a torn record after a failed write.
    fn truncate_current_file_to(&mut self, len: u64) -> std::io::Result<()> {
        self.release_write_handle()?;
        let path = self.file_path(self.current_file);
        if path.exists() {
            let f = OpenOptions::new().write(true).open(&path)?;
            f.set_len(len)?;
            f.sync_data()?;
        }
        self.current_pos = len;
        Ok(())
    }

    /// Fsync and drop the cached write handle, preserving the "dirty implies a
    /// live handle" invariant.
    ///
    /// The fsync error is **propagated**, not swallowed. Clearing `dirty` after
    /// a failed sync would leave completed records unsynced while `sync_all`
    /// reports success — so `flush_durable` would go on to make their
    /// `block_index` entries durable over bytes that never reached disk, which
    /// is precisely the hole this module exists to keep shut. A caller on an
    /// error path should prefer its own error but must not treat this as
    /// having succeeded.
    fn release_write_handle(&mut self) -> std::io::Result<()> {
        if self.dirty
            && let Some(f) = &self.write_handle
        {
            f.sync_data()?;
        }
        self.dirty = false;
        self.write_handle = None;
        Ok(())
    }

    /// Recompute the append offset from the file on disk and drop the cached
    /// write handle.
    ///
    /// `current_pos` is a cached mirror of the current file's length. The two
    /// diverge when bytes reach the file without this manager accounting for
    /// them (a partially-completed `write_block`) or when the file is
    /// shortened underneath it (a crash that lost an unsynced tail). Since
    /// writes are appends, a stale `current_pos` does not misplace the bytes —
    /// it misreports *where they went*, which is worse: the `block_index`
    /// entry ends up pointing at the wrong offset.
    ///
    /// Opening the manager already derives `current_pos` this way, so a
    /// restart is self-correcting; this makes the same correction available
    /// without one.
    pub fn resync_append_pos(&mut self) -> std::io::Result<()> {
        // Flush what the outgoing handle already wrote before dropping it:
        // records completed before the divergence may already be referenced by
        // a `block_index` entry, and once the handle is gone `sync_all` has
        // nothing to fsync through. A failure here is propagated rather than
        // ignored — see `release_write_handle`.
        self.release_write_handle()?;
        let path = self.file_path(self.current_file);
        // Compute into a local first: on error, leaving `current_pos` at its
        // stale value while the handle has been dropped would reintroduce the
        // mis-recorded-offset corruption this method exists to prevent. Better
        // to fail loudly with the old value untouched.
        let len = if path.exists() {
            std::fs::metadata(&path)?.len()
        } else {
            0
        };
        self.current_pos = len;
        Ok(())
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
    ///
    /// **Refuses the current append file.** Deleting it would unlink the inode
    /// `write_handle` still points at: subsequent `write_block` calls would
    /// succeed, `sync_all` would succeed, and the `block_index` entries
    /// committed alongside them would reference a path that does not exist —
    /// the "entry outlives its bytes" failure this module exists to prevent,
    /// with every block written after the unlink lost for good.
    ///
    /// The pruner alone could never select it: it only prunes files whose
    /// every block is at or below the prune horizon, and the current file
    /// always also holds the blocks just connected. `repair_block_data`
    /// breaks that invariant — it appends an *old-height* block's record to
    /// the current file, and if that append rotates, the fresh file holds
    /// nothing but a prunable-height block. Hence the guard here rather than
    /// at the call site: the invariant belongs to whoever owns the handle.
    pub fn delete_file(&mut self, file_number: u32) -> std::io::Result<()> {
        if file_number == self.current_file {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "refusing to delete blk{file_number:05}.dat: it is the current append file"
                ),
            ));
        }
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

    /// Deleting the file we are still appending to would unlink the inode
    /// `write_handle` points at: later writes and their fsyncs would all
    /// "succeed" into a file that no longer exists, and every `block_index`
    /// entry committed alongside them would reference a missing path.
    ///
    /// Only the repair path can put the pruner in a position to try it (it
    /// appends an old-height block's record to the current file), so the guard
    /// lives here, with the handle, rather than at the call site.
    #[test]
    fn delete_file_refuses_the_current_append_file() {
        let dir = std::env::temp_dir()
            .join(format!("satd-flatfile-delcur-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda];

        let pos = mgr.write_block(b"a block", magic).unwrap();
        let err = mgr
            .delete_file(pos.file_number)
            .expect_err("the current append file must not be deletable");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        // The file is still there and still writable through the same handle.
        assert!(mgr.file_exists(pos.file_number));
        let second = mgr.write_block(b"another block", magic).unwrap();
        assert_eq!(second.file_number, pos.file_number);
        assert_eq!(mgr.read_block(&second).unwrap(), b"another block");

        let _ = std::fs::remove_dir_all(&dir);
    }

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

        // File 0 is the current append file, so it is exempt from deletion
        // (see `delete_file_refuses_the_current_append_file`). Advance past it
        // the way a restart after rotation would: `new` adopts the
        // highest-numbered file present.
        drop(mgr);
        std::fs::write(dir.join("blk00001.dat"), b"").unwrap();
        let mut mgr = FlatFileManager::new(&dir).unwrap();
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

    /// `current_pos` is a cached mirror of the file length. If the file is
    /// shortened underneath the manager — a crash that lost an unsynced tail —
    /// the cache overstates it, and because writes are appends the next record
    /// lands at the real EOF while being *recorded* at the stale offset. A
    /// `block_index` entry built from that offset points at nothing.
    #[test]
    fn resync_append_pos_recovers_the_offset_after_the_file_is_shortened() {
        let dir = temp_dir("resync-append-pos");
        let magic = [0xfa, 0xbf, 0xb5, 0xda];
        let mut mgr = FlatFileManager::new(&dir).unwrap();

        let first = mgr.write_block(&vec![0xAA; 4096], magic).unwrap();
        mgr.sync_all().unwrap();

        // Lose the tail of the file, as an unsynced page-cache loss would.
        let path = dir.join("blk00000.dat");
        let truncated_len = 2048u64;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(truncated_len)
            .unwrap();

        // Without a resync the manager still believes the file is long, so it
        // hands back an offset the record was not written at.
        let stale = mgr.write_block(&vec![0xBB; 512], magic).unwrap();
        assert!(
            !matches!(mgr.read_block(&stale), Ok(ref d) if d.as_slice() == [0xBB; 512]),
            "the stale offset must not resolve to the record just written"
        );

        // A resync on the SAME manager restores the truth — deliberately not
        // a fresh `FlatFileManager::new`, whose constructor would recompute
        // the offset by itself and so prove nothing about this method.
        let real_len = std::fs::metadata(&path).unwrap().len();
        mgr.resync_append_pos().unwrap();
        assert_eq!(
            mgr.current_pos, real_len,
            "resync must adopt the real file length"
        );

        // Records written afterwards read back at the offset reported.
        let good = mgr.write_block(&vec![0xCC; 777], magic).unwrap();
        assert_eq!(mgr.read_block(&good).unwrap(), vec![0xCC; 777]);
        assert_eq!(
            good.data_pos as u64, real_len,
            "the new record must be recorded at the real end of file"
        );

        // The first record's offset is unchanged, but its payload was cut, so
        // it must now fail to read rather than return short or stale bytes.
        assert_eq!(first.data_pos, 0);
        assert!(
            mgr.read_block(&first).is_err(),
            "the truncated record must not read back as if intact"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A write that fails partway must leave the file *scannable*. Adopting the
    /// torn EOF and appending after it keeps offsets honest but leaves a record
    /// whose length field describes bytes that were never written — and
    /// `for_each_block` (used by `-reindex`) has no resynchronization: it steps
    /// over that phantom length, lands mid-stream, and stops, silently dropping
    /// every remaining block in a file that can hold 128 MB of them.
    #[test]
    fn a_torn_record_is_truncated_so_the_file_stays_scannable() {
        let dir = temp_dir("torn-record-truncate");
        let magic = [0xfa, 0xbf, 0xb5, 0xda];
        let mut mgr = FlatFileManager::new(&dir).unwrap();

        let a = mgr.write_block(&vec![0xAA; 256], magic).unwrap();
        let clean_len = std::fs::metadata(dir.join("blk00000.dat")).unwrap().len();

        // Simulate the aftermath of a torn write: a record header claiming far
        // more payload than actually landed, with `current_pos` still at the
        // pre-write value (the error path never advances it).
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(dir.join("blk00000.dat"))
                .unwrap();
            f.write_all(&magic).unwrap();
            f.write_all(&(9_000_000u32).to_le_bytes()).unwrap();
            f.write_all(&[0x77; 64]).unwrap();
            f.sync_all().unwrap();
        }
        assert!(std::fs::metadata(dir.join("blk00000.dat")).unwrap().len() > clean_len);

        // The recovery the error arm performs.
        mgr.truncate_current_file_to(clean_len).unwrap();

        let b = mgr.write_block(&[0xBB; 128], magic).unwrap();
        assert_eq!(
            b.data_pos as u64, clean_len,
            "the next record must start where the torn one was cut off"
        );

        // Both real records are visible to a sequential scan — the property a
        // reindex depends on and that adopting the torn EOF would destroy.
        let mut seen = Vec::new();
        mgr.for_each_block(|data, _pos| {
            seen.push(data.len());
            std::ops::ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(
            seen,
            vec![256, 128],
            "the scan must find exactly the two intact records"
        );
        assert_eq!(mgr.read_block(&a).unwrap(), vec![0xAA; 256]);
        assert_eq!(mgr.read_block(&b).unwrap(), vec![0xBB; 128]);

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
