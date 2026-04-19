//! Platform memory observation for adaptive cache sizing.
//!
//! Today we only implement Linux via `/proc/meminfo`. On other platforms the
//! functions return `None` and callers are expected to fall back to a static
//! configured cache size (adaptive mode just becomes a no-op).

use std::fs;

/// Total and available memory observed from the OS, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

/// Read memory stats. Returns `None` on non-Linux or parse failure.
pub fn meminfo() -> Option<MemInfo> {
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    parse_meminfo(&text)
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
