//! Platform memory observation for adaptive cache sizing.
//!
//! Linux only: the host figures come from `/proc/meminfo`, and are then
//! clamped to the memory cgroup the process runs in (systemd `MemoryMax=`,
//! Docker `--memory`, an app-store container limit). On other platforms the
//! functions return `None` and callers are expected to fall back to a static
//! configured cache size (adaptive mode just becomes a no-op).

use std::fs;
use std::path::Path;

/// Total and available memory observed from the OS, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

/// Read memory stats: the host's `/proc/meminfo`, clamped to the process's
/// memory cgroup limits. Returns `None` on non-Linux or when `/proc/meminfo`
/// cannot be parsed. Missing or unreadable cgroup files never fail this:
/// they leave the host figures in place.
pub fn meminfo() -> Option<MemInfo> {
    meminfo_at(Path::new("/proc"), Path::new("/sys/fs/cgroup"))
}

/// `meminfo` with the `/proc` and `/sys/fs/cgroup` roots injected, so tests
/// can run against a fake tree.
fn meminfo_at(proc_root: &Path, cgroup_root: &Path) -> Option<MemInfo> {
    let text = fs::read_to_string(proc_root.join("meminfo")).ok()?;
    let host = parse_meminfo(&text)?;
    #[cfg(target_os = "linux")]
    let host = match cgroup::limit(proc_root, cgroup_root) {
        Some(cg) => clamp_to_cgroup(host, cg),
        None => host,
    };
    #[cfg(not(target_os = "linux"))]
    let _ = cgroup_root;
    Some(host)
}

/// The tightest cgroup bound on the process's path.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CgroupLimit {
    /// Smallest limit on the path, in bytes.
    total_bytes: u64,
    /// Smallest headroom on the path: limit - usage + reclaimable page
    /// cache. `None` when no level with a limit reported its usage.
    available_bytes: Option<u64>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn clamp_to_cgroup(host: MemInfo, cg: CgroupLimit) -> MemInfo {
    let total_bytes = host.total_bytes.min(cg.total_bytes);
    let available_bytes = cg
        .available_bytes
        .map_or(host.available_bytes, |a| host.available_bytes.min(a))
        .min(total_bytes);
    MemInfo {
        total_bytes,
        available_bytes,
    }
}

#[cfg(target_os = "linux")]
mod cgroup {
    //! Memory cgroup limits along the process's cgroup path.
    //!
    //! cgroup v2 (unified): `/proc/self/cgroup` has a `0::<path>` line; each
    //! level from `<root>/<path>` up to `<root>` may carry `memory.max` and
    //! `memory.high` (`max` = unlimited), `memory.current` and `memory.stat`.
    //!
    //! cgroup v1: a `N:...memory...:<path>` line; the hierarchy is mounted at
    //! `<root>/memory`, each level with `memory.limit_in_bytes`,
    //! `memory.usage_in_bytes` and `memory.stat` (`total_active_file`,
    //! `total_inactive_file`). An unlimited v1 group reports a huge number,
    //! which the min against the host total discards.
    //!
    //! Both are tried and the tighter wins, which also covers the hybrid
    //! layout (v2 mounted, memory controller still on v1). Mount points are
    //! the standard ones; `/proc/self/mountinfo` is not consulted. The root
    //! of each mount is always read too: in a container without a private
    //! cgroup namespace the path names the host's view, absent inside, while
    //! the container's own group is what is mounted at the root.

    use std::fs;
    use std::path::{Path, PathBuf};

    use super::CgroupLimit;

    struct Files {
        limits: &'static [&'static str],
        usage: &'static str,
        active_file: &'static str,
        inactive_file: &'static str,
    }

    const V2: Files = Files {
        limits: &["memory.max", "memory.high"],
        usage: "memory.current",
        active_file: "active_file",
        inactive_file: "inactive_file",
    };

    const V1: Files = Files {
        limits: &["memory.limit_in_bytes"],
        usage: "memory.usage_in_bytes",
        active_file: "total_active_file",
        inactive_file: "total_inactive_file",
    };

    pub(super) fn limit(proc_root: &Path, cgroup_root: &Path) -> Option<CgroupLimit> {
        let text = fs::read_to_string(proc_root.join("self/cgroup")).ok()?;
        let mut best: Option<CgroupLimit> = None;
        for line in text.lines() {
            let mut parts = line.splitn(3, ':');
            let (Some(id), Some(controllers), Some(path)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let found = if id == "0" && controllers.is_empty() {
                walk(cgroup_root, path, &V2)
            } else if controllers.split(',').any(|c| c == "memory") {
                walk(&cgroup_root.join("memory"), path, &V1)
            } else {
                None
            };
            best = merge(best, found);
        }
        best
    }

    fn merge(a: Option<CgroupLimit>, b: Option<CgroupLimit>) -> Option<CgroupLimit> {
        match (a, b) {
            (None, x) | (x, None) => x,
            (Some(a), Some(b)) => Some(CgroupLimit {
                total_bytes: a.total_bytes.min(b.total_bytes),
                available_bytes: match (a.available_bytes, b.available_bytes) {
                    (None, x) | (x, None) => x,
                    (Some(x), Some(y)) => Some(x.min(y)),
                },
            }),
        }
    }

    /// Visit `<mount>/<path>` and every ancestor up to `<mount>` itself.
    fn walk(mount: &Path, path: &str, files: &Files) -> Option<CgroupLimit> {
        let mut dir = PathBuf::from(mount);
        let mut levels = vec![dir.clone()];
        for component in path.split('/').filter(|c| !c.is_empty()) {
            // A path is the kernel's own; refuse anything that would leave
            // the mount rather than trust it.
            if component == ".." || component == "." {
                return None;
            }
            dir.push(component);
            levels.push(dir.clone());
        }
        levels
            .iter()
            .map(|level| read_level(level, files))
            .fold(None, merge)
    }

    fn read_level(dir: &Path, files: &Files) -> Option<CgroupLimit> {
        let limit = files
            .limits
            .iter()
            .filter_map(|name| read_limit(&dir.join(name)))
            .min()?;
        let available_bytes = read_u64(&dir.join(files.usage)).map(|usage| {
            let reclaimable = read_stat(dir, files).unwrap_or(0);
            limit
                .saturating_sub(usage)
                .saturating_add(reclaimable)
                .min(limit)
        });
        Some(CgroupLimit {
            total_bytes: limit,
            available_bytes,
        })
    }

    /// A limit file: a byte count, or `max` (unlimited, `None`). Anything
    /// unreadable or unparsable is treated as no limit.
    fn read_limit(path: &Path) -> Option<u64> {
        let text = fs::read_to_string(path).ok()?;
        let value = text.trim();
        if value == "max" {
            return None;
        }
        value.parse().ok()
    }

    fn read_u64(path: &Path) -> Option<u64> {
        fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    /// Reclaimable page cache from `memory.stat`: active + inactive file.
    fn read_stat(dir: &Path, files: &Files) -> Option<u64> {
        let text = fs::read_to_string(dir.join("memory.stat")).ok()?;
        let mut active = None;
        let mut inactive = None;
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
                continue;
            };
            if key == files.active_file {
                active = value.parse::<u64>().ok();
            } else if key == files.inactive_file {
                inactive = value.parse::<u64>().ok();
            }
        }
        Some(active.unwrap_or(0).saturating_add(inactive.unwrap_or(0)))
    }
}

fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let mut total = None;
    let mut available = None;
    for line in text.lines() {
        if let Some(v) = parse_kib_line(line, "MemTotal:") {
            total = Some(v);
        } else if let Some(v) = parse_kib_line(line, "MemAvailable:") {
            available = Some(v);
        }
    }
    Some(MemInfo {
        total_bytes: total?,
        available_bytes: available?,
    })
}

fn parse_kib_line(line: &str, prefix: &str) -> Option<u64> {
    let rest = line.strip_prefix(prefix)?;
    let kib: u64 = rest.trim().trim_end_matches(" kB").trim().parse().ok()?;
    Some(kib.saturating_mul(1024))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_realistic_meminfo() {
        let sample = "\
MemTotal:       32768000 kB
MemFree:         1000000 kB
MemAvailable:   20000000 kB
Buffers:          500000 kB
Cached:          8000000 kB
";
        let info = parse_meminfo(sample).expect("must parse");
        assert_eq!(info.total_bytes, 32_768_000u64 * 1024);
        assert_eq!(info.available_bytes, 20_000_000u64 * 1024);
    }

    #[test]
    fn returns_none_when_fields_missing() {
        let sample = "MemFree: 1000 kB\n";
        assert!(parse_meminfo(sample).is_none());
    }

    #[test]
    fn kib_line_tolerates_internal_whitespace() {
        assert_eq!(
            parse_kib_line("MemTotal:       1024 kB", "MemTotal:"),
            Some(1024 * 1024)
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod cgroup_tests {
    use super::*;
    use std::path::PathBuf;

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    /// A fake `/proc` + `/sys/fs/cgroup` pair. The host has 32 GiB total,
    /// 20 GiB available.
    struct Fake {
        _dir: tempfile::TempDir,
        proc_root: PathBuf,
        cgroup_root: PathBuf,
    }

    impl Fake {
        fn new(self_cgroup: Option<&str>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let proc_root = dir.path().join("proc");
            let cgroup_root = dir.path().join("sys/fs/cgroup");
            fs::create_dir_all(proc_root.join("self")).unwrap();
            fs::create_dir_all(&cgroup_root).unwrap();
            fs::write(
                proc_root.join("meminfo"),
                format!(
                    "MemTotal: {} kB\nMemAvailable: {} kB\n",
                    32 * GIB / 1024,
                    20 * GIB / 1024
                ),
            )
            .unwrap();
            if let Some(text) = self_cgroup {
                fs::write(proc_root.join("self/cgroup"), text).unwrap();
            }
            Fake {
                _dir: dir,
                proc_root,
                cgroup_root,
            }
        }

        /// Write `name` = `value` in the cgroup directory `rel`.
        fn set(&self, rel: &str, name: &str, value: impl ToString) {
            let dir = self.cgroup_root.join(rel);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(name), value.to_string()).unwrap();
        }

        fn read(&self) -> MemInfo {
            meminfo_at(&self.proc_root, &self.cgroup_root).expect("host meminfo parses")
        }
    }

    const HOST: MemInfo = MemInfo {
        total_bytes: 32 * GIB,
        available_bytes: 20 * GIB,
    };

    const LEAF: &str = "system.slice/satd.service";

    fn v2() -> Fake {
        Fake::new(Some("0::/system.slice/satd.service\n"))
    }

    #[test]
    fn no_cgroup_files_keeps_host_figures() {
        // No /proc/self/cgroup at all.
        assert_eq!(Fake::new(None).read(), HOST);
        // A cgroup path whose directories do not exist.
        assert_eq!(v2().read(), HOST);
    }

    #[test]
    fn memory_max_unlimited_keeps_host_figures() {
        let f = v2();
        f.set(LEAF, "memory.max", "max\n");
        f.set(LEAF, "memory.high", "max\n");
        f.set(LEAF, "memory.current", GIB);
        assert_eq!(f.read(), HOST);
    }

    #[test]
    fn leaf_limit_bounds_total_and_available() {
        let f = v2();
        f.set(LEAF, "memory.max", 2 * GIB);
        f.set(LEAF, "memory.current", 512 * MIB);
        let want = MemInfo {
            total_bytes: 2 * GIB,
            available_bytes: 2 * GIB - 512 * MIB,
        };
        assert_eq!(f.read(), want);
    }

    #[test]
    fn tighter_ancestor_limit_wins() {
        let f = v2();
        f.set(LEAF, "memory.max", 4 * GIB);
        f.set(LEAF, "memory.current", 512 * MIB);
        f.set("system.slice", "memory.max", GIB);
        f.set("system.slice", "memory.current", 768 * MIB);
        let want = MemInfo {
            total_bytes: GIB,
            available_bytes: 256 * MIB,
        };
        assert_eq!(f.read(), want);
    }

    #[test]
    fn memory_high_below_max_wins() {
        let f = v2();
        f.set(LEAF, "memory.max", 4 * GIB);
        f.set(LEAF, "memory.high", 3 * GIB);
        f.set(LEAF, "memory.current", GIB);
        let want = MemInfo {
            total_bytes: 3 * GIB,
            available_bytes: 2 * GIB,
        };
        assert_eq!(f.read(), want);
    }

    #[test]
    fn reclaimable_file_cache_counts_as_available() {
        let f = v2();
        f.set(LEAF, "memory.max", 2 * GIB);
        f.set(LEAF, "memory.current", 1800 * MIB);
        let stat = format!(
            "anon {}\nfile {}\nactive_file {}\ninactive_file {}\nactive_anon 0\n",
            800 * MIB,
            1000 * MIB,
            300 * MIB,
            400 * MIB
        );
        f.set(LEAF, "memory.stat", stat);
        let want = MemInfo {
            total_bytes: 2 * GIB,
            available_bytes: 2 * GIB - 1800 * MIB + 700 * MIB,
        };
        assert_eq!(f.read(), want);
    }

    #[test]
    fn available_never_exceeds_the_limit() {
        let f = v2();
        f.set(LEAF, "memory.max", GIB);
        f.set(LEAF, "memory.current", 900 * MIB);
        f.set(LEAF, "memory.stat", format!("inactive_file {}\n", 2 * GIB));
        assert_eq!(f.read().available_bytes, GIB);
    }

    #[test]
    fn garbage_contents_fall_back_to_host() {
        let f = Fake::new(Some("\u{0}garbage\nno colons here\n0::/../../etc\n"));
        f.set("", "memory.max", GIB);
        assert_eq!(f.read(), HOST);

        let f = v2();
        f.set(LEAF, "memory.max", "12 GiB\n");
        f.set(LEAF, "memory.high", "");
        f.set(LEAF, "memory.current", "nope");
        f.set(LEAF, "memory.stat", "active_file x\ninactive_file\n");
        assert_eq!(f.read(), HOST);

        // A valid limit with garbage usage still bounds the total; the
        // available figure stays the host's (clamped to the total).
        let f = v2();
        f.set(LEAF, "memory.max", 30 * GIB);
        f.set(LEAF, "memory.current", "nope");
        let want = MemInfo {
            total_bytes: 30 * GIB,
            available_bytes: 20 * GIB,
        };
        assert_eq!(f.read(), want);
    }

    #[test]
    fn limit_at_the_mount_root_applies() {
        // A container without a private cgroup namespace: the path names
        // the host's view and is absent; the container's own group is the
        // mount root.
        let f = Fake::new(Some("0::/docker/abc123\n"));
        f.set("", "memory.max", GIB);
        f.set("", "memory.current", 100 * MIB);
        let want = MemInfo {
            total_bytes: GIB,
            available_bytes: GIB - 100 * MIB,
        };
        assert_eq!(f.read(), want);
    }

    #[test]
    fn cgroup_v1_limit_applies() {
        let f = Fake::new(Some(
            "12:cpu,cpuacct:/user.slice\n4:memory:/user.slice/app\n0::/user.slice\n",
        ));
        let app = "memory/user.slice/app";
        f.set(app, "memory.limit_in_bytes", 2 * GIB);
        f.set(app, "memory.usage_in_bytes", GIB);
        let stat = format!(
            "active_file 1\ntotal_active_file {}\ntotal_inactive_file {}\n",
            100 * MIB,
            50 * MIB
        );
        f.set(app, "memory.stat", stat);
        // An unlimited v1 parent reports PAGE_COUNTER_MAX.
        let unlimited = 9223372036854771712u64;
        f.set("memory/user.slice", "memory.limit_in_bytes", unlimited);
        let want = MemInfo {
            total_bytes: 2 * GIB,
            available_bytes: GIB + 150 * MIB,
        };
        assert_eq!(f.read(), want);
    }
}
