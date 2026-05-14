//! Storage-tuning profiles for the RocksDB chainstate.
//!
//! The same tunables that keep up with mainnet IBD on NVMe (high
//! parallelism, large WAL trigger) thrash an HDD into seek-bound
//! collapse. Operators select a profile via `--storage-profile=ssd|hdd`
//! and may override individual knobs with `--rocksdb-background-jobs`,
//! `--rocksdb-subcompactions`, and `--rocksdb-wal-mb`.
//!
//! Defaults were sized from a real incident: a mainnet sync with
//! `--txindex --addressindex=1` accumulated 13,037 SST files and
//! ~370 GB of pending compaction across the four high-write index
//! column families before exhausting a 1.8 TB volume. Root cause was
//! a `max_total_wal_size` (256 MB) smaller than the total memtable
//! capacity (~680 MB), combined with `max_background_jobs=6` shared
//! across 12+ CFs. The `ssd` profile fixes both.

use std::str::FromStr;

/// Storage class profile. Selects sensible RocksDB tunable defaults
/// for the underlying media.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StorageProfile {
    /// Fast random-access media (NVMe, SATA SSD). High background
    /// parallelism, large WAL trigger, small fsync batches.
    #[default]
    Ssd,
    /// Rotational disks. Single-threaded compactions and large fsync
    /// batches to minimise seek thrash; smaller WAL to bound the
    /// crash-recovery replay window on slow writes.
    Hdd,
}

impl FromStr for StorageProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "ssd" | "nvme" | "fast" => Ok(Self::Ssd),
            "hdd" | "rotational" | "slow" => Ok(Self::Hdd),
            other => Err(format!(
                "unknown storage profile '{}'; expected 'ssd' or 'hdd'",
                other
            )),
        }
    }
}

impl std::fmt::Display for StorageProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ssd => f.write_str("ssd"),
            Self::Hdd => f.write_str("hdd"),
        }
    }
}

/// Resolved RocksDB tunables. Build with [`StorageTuning::for_profile`]
/// and optionally apply raw-knob overrides via the `with_*` setters.
///
/// Numeric fields use the same units the underlying RocksDB calls take
/// (bytes, raw thread counts). The CLI parses friendlier units (MB for
/// WAL size) and converts before constructing this struct.
#[derive(Debug, Clone, Copy)]
pub struct StorageTuning {
    pub profile: StorageProfile,
    /// Maximum concurrent flush + compaction jobs across all column
    /// families. Maps to `Options::set_max_background_jobs`.
    pub max_background_jobs: i32,
    /// Sub-thread parallelism within a single compaction job. Maps to
    /// `Options::set_max_subcompactions`. Useful for the bottom level
    /// of the secondary index CFs, which otherwise compact serially.
    pub max_subcompactions: u32,
    /// WAL size threshold (bytes) above which RocksDB force-flushes
    /// the CFs tied to the oldest live WAL file. Maps to
    /// `Options::set_max_total_wal_size`. Must be larger than the sum
    /// of `write_buffer_size * max_write_buffer_number` across all
    /// CFs, otherwise flushes are driven by WAL pressure (frequent
    /// half-empty atomic flushes → tiny L0 files → compaction storm).
    pub max_total_wal_size: u64,
    /// `bytes_per_sync` for SST writes. Larger values batch fsyncs;
    /// HDDs benefit, NVMe is indifferent.
    pub bytes_per_sync: u64,
    /// `wal_bytes_per_sync` for WAL writes.
    pub wal_bytes_per_sync: u64,
    /// `target_file_size_base` for the high-write secondary index
    /// CFs (`addr_funding`, `addr_spending`, `outpoint_spend`,
    /// `undo`). Larger values produce fewer, larger SSTs at the
    /// bottom level — reduces metadata overhead and total compaction
    /// count, at the cost of longer individual compactions.
    pub hot_cf_target_file_size_base: u64,
}

impl StorageTuning {
    /// Resolve tunables for the given profile using the host's CPU
    /// count for parallelism knobs.
    pub fn for_profile(profile: StorageProfile) -> Self {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4) as i32;
        match profile {
            StorageProfile::Ssd => Self {
                profile,
                // Use all logical CPUs. RocksDB defaults plus our prior
                // cap of 6 starved compaction on a 12-CF schema; the
                // address-history CFs accumulated thousands of SSTs
                // each because their compaction quota was a fraction
                // of one thread.
                max_background_jobs: cpus.max(8),
                // Parallelise within a single compaction job using
                // key-range partitioning. Critical for L5→L6 on the
                // secondary indexes, which run for hours single-
                // threaded otherwise.
                max_subcompactions: ((cpus / 2).max(4)) as u32,
                // Sized at ~2× the sum of per-CF write buffers (~680
                // MB across the 12+ CFs) so the WAL trigger fires
                // only on genuine memtable pressure, not constantly.
                // Bounds crash-recovery WAL replay to ~1.5 GB.
                max_total_wal_size: 1536 * 1024 * 1024,
                bytes_per_sync: 1024 * 1024,
                wal_bytes_per_sync: 1024 * 1024,
                hot_cf_target_file_size_base: 64 * 1024 * 1024,
            },
            StorageProfile::Hdd => Self {
                profile,
                // Few concurrent compactions: each one is a read+
                // write storm on slow media, and concurrent
                // compactions thrash the disk head between key
                // ranges. Four is a reasonable middle ground.
                max_background_jobs: 4,
                // Single-threaded compactions: parallel writes to the
                // same key range cause seek thrash on rotational
                // media, more than negating the parallelism win.
                max_subcompactions: 1,
                // Smaller WAL bounds crash-recovery replay time on
                // slow writes; large WAL on HDD means a restart can
                // spend an hour replaying.
                max_total_wal_size: 512 * 1024 * 1024,
                // Larger fsync batches: per-syscall overhead
                // dominates HDD throughput, so 16 MB chunks let the
                // disk firmware coalesce them efficiently.
                bytes_per_sync: 16 * 1024 * 1024,
                wal_bytes_per_sync: 16 * 1024 * 1024,
                // Fewer, larger bottom-level SSTs: less metadata
                // seek and a smaller compaction count to chew
                // through on a slow disk.
                hot_cf_target_file_size_base: 256 * 1024 * 1024,
            },
        }
    }

    /// Apply an optional `max_background_jobs` override.
    pub fn with_background_jobs(mut self, override_: Option<i32>) -> Self {
        if let Some(v) = override_ {
            self.max_background_jobs = v;
        }
        self
    }

    /// Apply an optional `max_subcompactions` override.
    pub fn with_subcompactions(mut self, override_: Option<u32>) -> Self {
        if let Some(v) = override_ {
            self.max_subcompactions = v;
        }
        self
    }

    /// Apply an optional `max_total_wal_size` override, expressed in
    /// megabytes for CLI ergonomics.
    pub fn with_wal_mb(mut self, override_: Option<u64>) -> Self {
        if let Some(mb) = override_ {
            self.max_total_wal_size = mb * 1024 * 1024;
        }
        self
    }
}

impl Default for StorageTuning {
    fn default() -> Self {
        Self::for_profile(StorageProfile::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_parses_aliases() {
        assert_eq!("ssd".parse::<StorageProfile>().unwrap(), StorageProfile::Ssd);
        assert_eq!("NVME".parse::<StorageProfile>().unwrap(), StorageProfile::Ssd);
        assert_eq!("hdd".parse::<StorageProfile>().unwrap(), StorageProfile::Hdd);
        assert_eq!("Rotational".parse::<StorageProfile>().unwrap(), StorageProfile::Hdd);
        assert!("garbage".parse::<StorageProfile>().is_err());
    }

    #[test]
    fn ssd_defaults_exceed_wal_capacity() {
        // Regression guard for the 256 MB WAL / 680 MB memtable mismatch
        // that triggered the incident: ssd profile must keep WAL trigger
        // above the sum of per-CF write buffers (~680 MB).
        let t = StorageTuning::for_profile(StorageProfile::Ssd);
        assert!(t.max_total_wal_size >= 1024 * 1024 * 1024);
    }

    #[test]
    fn hdd_defaults_avoid_seek_thrash() {
        let t = StorageTuning::for_profile(StorageProfile::Hdd);
        assert_eq!(t.max_subcompactions, 1);
        assert!(t.max_background_jobs <= 8);
        assert!(t.bytes_per_sync >= 4 * 1024 * 1024);
    }

    #[test]
    fn overrides_replace_profile_defaults() {
        let t = StorageTuning::for_profile(StorageProfile::Ssd)
            .with_background_jobs(Some(2))
            .with_subcompactions(Some(1))
            .with_wal_mb(Some(64));
        assert_eq!(t.max_background_jobs, 2);
        assert_eq!(t.max_subcompactions, 1);
        assert_eq!(t.max_total_wal_size, 64 * 1024 * 1024);
        assert_eq!(t.profile, StorageProfile::Ssd);
    }
}
