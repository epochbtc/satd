//! Hole punching: zero a byte range of a file in place and give the whole
//! filesystem blocks inside it back to the filesystem.
//!
//! No offset in the file moves and its apparent size does not change, so
//! every position recorded elsewhere (block index entries, txindex offsets)
//! stays valid. The range reads back as zeros afterwards. Only whole
//! filesystem blocks are deallocated, so the space returned for a range
//! `[s, e)` is `floor(e / bs) * bs - ceil(s / bs) * bs` (or nothing), while
//! the zeroing itself is exact to the byte.
//!
//! - Linux (gnu and musl): `fallocate(FALLOC_FL_PUNCH_HOLE |
//!   FALLOC_FL_KEEP_SIZE)`. The kernel zeroes the partial blocks at the edges
//!   and deallocates the whole ones in one call.
//! - macOS: `fcntl(F_PUNCHHOLE)`, which APFS accepts only on block-aligned
//!   ranges. The aligned middle is punched and the unaligned edges are
//!   overwritten with zeros.
//! - Anything else reports [`PunchError::Unsupported`].
//!
//! Punching is not a secure erase: it makes no attempt to overwrite the
//! physical storage the deallocated blocks occupied.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// Name of the scratch file [`probe`] creates (and removes) in the directory
/// it tests.
pub const PROBE_FILE_NAME: &str = ".satd-punch-probe";

/// What [`probe`] learned about a directory's filesystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PunchCaps {
    /// The filesystem's fundamental block size: the unit space is returned in.
    pub fs_block: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum PunchError {
    /// The platform or the filesystem has no hole-punch support.
    #[error("hole punching is not supported here: {0}")]
    Unsupported(io::Error),
    /// The punch call succeeded but did not do what it promises.
    #[error("hole punch probe in {}: {reason}", .dir.display())]
    ProbeFailed { dir: PathBuf, reason: String },
    #[error("hole punch probe in {}: {source}", .dir.display())]
    Io { dir: PathBuf, source: io::Error },
}

/// Classify a failed punch call: the errors that mean "this filesystem or
/// kernel cannot punch holes" become [`PunchError::Unsupported`]; anything
/// else is a real I/O failure.
pub(crate) fn classify(err: io::Error, dir: &Path) -> PunchError {
    match err.raw_os_error() {
        Some(code) if code == libc::EOPNOTSUPP || code == libc::ENOTSUP || code == libc::ENOSYS => {
            PunchError::Unsupported(err)
        }
        _ => PunchError::Io {
            dir: dir.to_path_buf(),
            source: err,
        },
    }
}

/// Bytes deallocated when `[offset, offset + len)` is punched on a
/// filesystem with block size `fs_block`: the whole blocks inside the range.
pub fn freed_bytes(offset: u64, len: u64, fs_block: u64) -> u64 {
    if fs_block == 0 {
        return 0;
    }
    let end = offset.saturating_add(len);
    let first = offset.div_ceil(fs_block) * fs_block;
    let last = (end / fs_block) * fs_block;
    last.saturating_sub(first)
}

/// Zero `[offset, offset + len)` of `file` and deallocate the whole
/// filesystem blocks inside it. `file` must be open for writing.
///
/// The range must lie inside the file: a range past the end is refused
/// rather than punched, so the file never grows (macOS writes the
/// unaligned edges, which past the end would extend it) and both platforms
/// behave the same. `caps.fs_block` must be a power of two no larger than
/// 1 MiB, as [`probe`] guarantees.
///
/// Returns the bytes the alignment arithmetic of [`freed_bytes`] says the
/// range contains. That is an upper bound, not a measurement: punching a
/// range again (a redo after a crash) or a range that is already a hole
/// returns the same value and frees nothing, so a caller keeping a running
/// total must count each span once. Nothing is synced: the caller decides
/// when to `sync_data`.
pub fn zero_and_punch(file: &File, offset: u64, len: u64, caps: &PunchCaps) -> io::Result<u64> {
    if !valid_fs_block(caps.fs_block) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid filesystem block size {}", caps.fs_block),
        ));
    }
    if len == 0 {
        return Ok(0);
    }
    let end = offset
        .checked_add(len)
        .filter(|end| *end <= i64::MAX as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "punch range overflows"))?;
    let file_len = file.metadata()?.len();
    if end > file_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("punch range ends at {end}, past the end of the file ({file_len})"),
        ));
    }
    sys::punch(file, offset, len, caps.fs_block)?;
    Ok(freed_bytes(offset, len, caps.fs_block))
}

fn valid_fs_block(fs_block: u64) -> bool {
    fs_block.is_power_of_two() && fs_block <= 1 << 20
}

/// Check that hole punching works in `dir` and learn its block size.
///
/// Writes four blocks of non-zero data to a scratch file, punches the
/// middle two, and requires both that the allocated size dropped and that
/// the range reads back as zeros. The scratch file is removed either way.
pub fn probe(dir: &Path) -> Result<PunchCaps, PunchError> {
    let path = dir.join(PROBE_FILE_NAME);
    let result = probe_at(&path, dir);
    let _ = std::fs::remove_file(&path);
    result
}

fn probe_at(path: &Path, dir: &Path) -> Result<PunchCaps, PunchError> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::MetadataExt;

    let io_err = |source: io::Error| PunchError::Io {
        dir: dir.to_path_buf(),
        source,
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(io_err)?;
    let fs_block = sys::fs_block_size(&file).map_err(io_err)?;
    if !valid_fs_block(fs_block) {
        return Err(PunchError::ProbeFailed {
            dir: dir.to_path_buf(),
            reason: format!("implausible filesystem block size {fs_block}"),
        });
    }
    let caps = PunchCaps { fs_block };
    file.write_all(&vec![0xa5u8; (4 * fs_block) as usize])
        .map_err(io_err)?;
    file.sync_all().map_err(io_err)?;
    let before = file.metadata().map_err(io_err)?.blocks();

    if let Err(e) = zero_and_punch(&file, fs_block, 2 * fs_block, &caps) {
        return Err(classify(e, dir));
    }
    file.sync_all().map_err(io_err)?;
    let after = file.metadata().map_err(io_err)?.blocks();

    let mut back = vec![0u8; (2 * fs_block) as usize];
    file.seek(SeekFrom::Start(fs_block)).map_err(io_err)?;
    file.read_exact(&mut back).map_err(io_err)?;
    if back.iter().any(|b| *b != 0) {
        return Err(PunchError::ProbeFailed {
            dir: dir.to_path_buf(),
            reason: "the punched range did not read back as zeros".into(),
        });
    }
    if after >= before {
        return Err(PunchError::ProbeFailed {
            dir: dir.to_path_buf(),
            reason: format!(
                "the punch returned no space (allocated 512-byte blocks {before} before, {after} after)"
            ),
        });
    }
    Ok(caps)
}

#[cfg(target_os = "linux")]
mod sys {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    pub(super) fn punch(file: &File, offset: u64, len: u64, _fs_block: u64) -> io::Result<()> {
        loop {
            // SAFETY: a plain syscall on a file descriptor `file` keeps open.
            let rc = unsafe {
                libc::fallocate(
                    file.as_raw_fd(),
                    libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    offset as libc::off_t,
                    len as libc::off_t,
                )
            };
            if rc == 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            // Retried as std's own file calls are: a signal is not a failure.
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    pub(super) fn fs_block_size(file: &File) -> io::Result<u64> {
        super::fstatvfs_block(file)
    }
}

#[cfg(target_os = "macos")]
mod sys {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileExt;

    pub(super) fn punch(file: &File, offset: u64, len: u64, fs_block: u64) -> io::Result<()> {
        let end = offset + len;
        let first = offset.div_ceil(fs_block) * fs_block;
        let last = (end / fs_block) * fs_block;
        if last > first {
            let arg = libc::fpunchhole_t {
                fp_flags: 0,
                reserved: 0,
                fp_offset: first as libc::off_t,
                fp_length: (last - first) as libc::off_t,
            };
            loop {
                // SAFETY: `arg` is a valid `fpunchhole_t` for the duration
                // of the call, on a file descriptor `file` keeps open.
                let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &arg) };
                if rc != -1 {
                    break;
                }
                let err = io::Error::last_os_error();
                // Retried as std's own file calls are.
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
            write_zeros(file, offset, first - offset)?;
            write_zeros(file, last, end - last)?;
        } else {
            // No whole block inside the range: nothing to deallocate.
            write_zeros(file, offset, len)?;
        }
        Ok(())
    }

    fn write_zeros(file: &File, offset: u64, len: u64) -> io::Result<()> {
        if len > 0 {
            file.write_all_at(&vec![0u8; len as usize], offset)?;
        }
        Ok(())
    }

    pub(super) fn fs_block_size(file: &File) -> io::Result<u64> {
        super::fstatvfs_block(file)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod sys {
    use std::fs::File;
    use std::io;

    pub(super) fn punch(_file: &File, _offset: u64, _len: u64, _fs_block: u64) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    pub(super) fn fs_block_size(file: &File) -> io::Result<u64> {
        super::fstatvfs_block(file)
    }
}

/// The filesystem's fundamental block size (`f_frsize`, or `f_bsize` where
/// a filesystem leaves `f_frsize` zero).
fn fstatvfs_block(file: &File) -> io::Result<u64> {
    use std::os::fd::AsRawFd;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `st` is a writable `statvfs` the call fills in, on a file
    // descriptor `file` keeps open.
    let rc = unsafe { libc::fstatvfs(file.as_raw_fd(), st.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so `st` is initialised.
    let st = unsafe { st.assume_init() };
    #[allow(clippy::unnecessary_cast)]
    let frsize = st.f_frsize as u64;
    #[allow(clippy::unnecessary_cast)]
    let bsize = st.f_bsize as u64;
    Ok(if frsize > 0 { frsize } else { bsize })
}

#[cfg(test)]
#[path = "punch_tests.rs"]
mod tests;
