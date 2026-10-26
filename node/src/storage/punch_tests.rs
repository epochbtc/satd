use super::*;

#[test]
fn freed_bytes_counts_only_whole_blocks_inside_the_range() {
    const BS: u64 = 4096;
    // (offset, len, freed)
    let cases = [
        (0, BS, BS),
        (1, BS, 0),
        (0, BS - 1, 0),
        (100, 2 * BS, BS),
        (BS / 2, 3 * BS, 2 * BS),
        (BS, 2 * BS, 2 * BS),
        (BS - 1, 2 * BS + 2, 2 * BS),
        (5, 0, 0),
        (100_000, 100_000, 94_208),
    ];
    for (offset, len, freed) in cases {
        assert_eq!(freed_bytes(offset, len, BS), freed, "offset {offset} len {len}");
    }
    assert_eq!(freed_bytes(0, BS, 0), 0, "a zero block size frees nothing");
}

#[test]
fn unsupported_errors_are_told_apart_from_io_failures() {
    let dir = Path::new("/blocks");
    for code in [libc::EOPNOTSUPP, libc::ENOTSUP, libc::ENOSYS] {
        assert!(
            matches!(classify(io::Error::from_raw_os_error(code), dir), PunchError::Unsupported(_)),
            "errno {code} must read as unsupported"
        );
    }
    for code in [libc::EIO, libc::ENOSPC, libc::EBADF] {
        assert!(
            matches!(classify(io::Error::from_raw_os_error(code), dir), PunchError::Io { .. }),
            "errno {code} is an I/O failure, not a missing feature"
        );
    }
    let msg = classify(io::Error::from_raw_os_error(libc::EOPNOTSUPP), dir).to_string();
    assert!(msg.contains("not supported"), "{msg}");
}

#[test]
fn zero_length_punch_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(dir.path().join("f")).unwrap();
    let caps = PunchCaps { fs_block: 4096 };
    assert_eq!(zero_and_punch(&file, 10, 0, &caps).unwrap(), 0);
}

#[test]
fn an_overflowing_range_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let file = std::fs::File::create(dir.path().join("f")).unwrap();
    let caps = PunchCaps { fs_block: 4096 };
    let err = zero_and_punch(&file, u64::MAX - 1, 10, &caps).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    let err = zero_and_punch(&file, i64::MAX as u64, 1, &caps).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod on_disk {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;

    const FILL: u8 = 0xa5;
    const FILE_LEN: usize = 64 * 1024;

    /// A synced 64 KiB file of non-zero bytes, and the caps of its
    /// filesystem.
    fn filled_file(dir: &Path) -> (File, PunchCaps) {
        let caps = probe(dir).expect("the test filesystem supports hole punching");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.join("blk00000.dat"))
            .unwrap();
        file.write_all(&[FILL; FILE_LEN]).unwrap();
        file.sync_all().unwrap();
        (file, caps)
    }

    fn contents(dir: &Path) -> Vec<u8> {
        let mut v = Vec::new();
        File::open(dir.join("blk00000.dat"))
            .unwrap()
            .read_to_end(&mut v)
            .unwrap();
        v
    }

    #[test]
    fn probe_passes_and_leaves_no_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let caps = probe(dir.path()).expect("probe passes");
        assert!(caps.fs_block >= 512 && caps.fs_block.is_power_of_two(), "{caps:?}");
        assert!(!dir.path().join(PROBE_FILE_NAME).exists());
    }

    #[test]
    fn probe_replaces_a_stale_probe_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PROBE_FILE_NAME), vec![1u8; 100_000]).unwrap();
        probe(dir.path()).expect("probe passes over a leftover from a crash");
        assert!(!dir.path().join(PROBE_FILE_NAME).exists());
    }

    #[test]
    fn probe_of_a_missing_directory_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-dir");
        assert!(matches!(probe(&missing), Err(PunchError::Io { .. })));
    }

    /// Punch a range covering two whole blocks with ragged edges: the range
    /// reads back as zeros, every byte outside it is untouched, the apparent
    /// size is unchanged, and the allocation drops by the two blocks.
    #[test]
    fn punch_zeroes_the_range_and_returns_the_whole_blocks_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let (file, caps) = filled_file(dir.path());
        let bs = caps.fs_block;
        let before = file.metadata().unwrap().blocks();

        let (offset, len) = (bs / 2, 3 * bs);
        let freed = zero_and_punch(&file, offset, len, &caps).unwrap();
        file.sync_all().unwrap();
        assert_eq!(freed, 2 * bs);

        let after = file.metadata().unwrap();
        assert_eq!(after.len(), FILE_LEN as u64, "the apparent size must not change");
        assert!(
            before - after.blocks() >= 2 * bs / 512,
            "allocation must drop by two blocks: {before} -> {} (512-byte units)",
            after.blocks()
        );

        let data = contents(dir.path());
        let (s, e) = (offset as usize, (offset + len) as usize);
        assert!(data[s..e].iter().all(|b| *b == 0), "the range must read back as zeros");
        assert!(data[..s].iter().all(|b| *b == FILL), "bytes before the range changed");
        assert!(data[e..].iter().all(|b| *b == FILL), "bytes after the range changed");
    }

    /// A range with no whole block inside it is still zeroed exactly, and
    /// frees nothing.
    #[test]
    fn a_range_inside_one_block_is_zeroed_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let (file, caps) = filled_file(dir.path());
        let (offset, len) = (caps.fs_block + 100, 83);
        assert_eq!(zero_and_punch(&file, offset, len, &caps).unwrap(), 0);
        file.sync_all().unwrap();

        let data = contents(dir.path());
        let (s, e) = (offset as usize, (offset + len) as usize);
        assert!(data[s..e].iter().all(|b| *b == 0));
        assert!(data[..s].iter().all(|b| *b == FILL));
        assert!(data[e..].iter().all(|b| *b == FILL));
        assert_eq!(data.len(), FILE_LEN);
    }

    /// Punching a range twice (a redo after a crash) is harmless.
    #[test]
    fn punching_twice_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let (file, caps) = filled_file(dir.path());
        let bs = caps.fs_block;
        zero_and_punch(&file, 10, 2 * bs, &caps).unwrap();
        let once = contents(dir.path());
        zero_and_punch(&file, 10, 2 * bs, &caps).unwrap();
        assert_eq!(contents(dir.path()), once);
    }
}
