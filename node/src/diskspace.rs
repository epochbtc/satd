//! Free-space probe, shared by the deferred-index backfill guards and the
//! `disk_low` health detector.
//!
//! Each index runner grew its own private copy of this while the backfill
//! preflight checks were written; the health detector needs the same number, so
//! the three copies are consolidated here. Linux-only by design — the shipped
//! binaries are musl-static Linux builds, and a `None` on other platforms means
//! callers degrade to "unknown, don't block" rather than guessing.

/// Bytes available to an unprivileged user under `path`, or `None` if the
/// filesystem cannot be interrogated (bad path, permission error, or a platform
/// with no `statvfs`).
///
/// Uses `f_bavail`, not `f_bfree`: the reserved-blocks pool a root process could
/// still write into is not space satd may plan on.
#[cfg(target_os = "linux")]
pub fn free_disk_bytes(path: &std::path::Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: zero-init s; libc::statvfs is the canonical free-space syscall.
    unsafe {
        let mut s: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(cpath.as_ptr(), &mut s) != 0 {
            return None;
        }
        Some(s.f_bavail.saturating_mul(s.f_frsize))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn free_disk_bytes(_path: &std::path::Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn reports_space_for_a_real_directory() {
        let dir = tempfile::tempdir().unwrap();
        let free = free_disk_bytes(dir.path()).expect("statvfs on a temp dir");
        // Any writable temp dir has *some* space; the point is that the syscall
        // succeeded and the multiply did not overflow to zero.
        assert!(free > 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn missing_path_is_none_not_a_panic() {
        assert_eq!(
            free_disk_bytes(std::path::Path::new("/nonexistent/satd/disk/probe")),
            None,
        );
    }
}
