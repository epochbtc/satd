//! The crawl's snapshots (`-crawl`): the hourly files under `crawl/` and
//! the export `dumpcrawlsnapshot` returns.
//!
//! A snapshot is the reachable set: every address whose last completed
//! handshake is within the liveness window ([`CrawlBook::snapshot`]).
//!
//! # Hourly files
//!
//! Once an hour the crawl writes the snapshot to `crawl/<unix time>.jsonl.gz`
//! in the network's data directory: gzip-compressed JSON lines, one line per
//! reachable node, with raw addresses ([`snapshot_lines`]). Each write prunes
//! the directory ([`prune_plan`]): every file younger than
//! [`HOURLY_KEEP_SECS`] (7 days) is kept, of the older ones only the first of
//! each UTC day, and none older than [`DAILY_KEEP_SECS`] (90 days). The
//! directory is created with the data directory's permissions, and the files
//! are written as `crawlbook.dat` is (the directory's permissions, execute
//! bits dropped): they hold raw IP addresses.
//!
//! # The export
//!
//! [`export_json`] is shaped as a Bitnodes snapshot: `timestamp`,
//! `total_nodes`, `latest_height` (our tip) and `nodes`, each node an array
//! of Bitnodes' thirteen fields (protocol version, user agent, connected
//! since, services, height, hostname, city, country, latitude, longitude,
//! timezone, ASN, organization) followed by a `satd` object with our own
//! fields. The node does no geolocation and no reverse lookup: hostname,
//! the geographic fields and the organization are null. So is connected
//! since: the crawl holds no long-lived connection to measure it.
//!
//! **Keyed** (the default), a clearnet node is keyed by its node ID,
//! [`node_id`]: HMAC-SHA256 under a 32-byte key of `ip:port`, truncated to
//! [`NODE_ID_BYTES`]. Without the key an ID cannot be tested against a
//! guessed address, and the same key gives the same ID in every export, so
//! a node's history can be followed. Onion addresses are listed raw (the
//! host; the port as for every node): their operators publish them to be
//! dialled, and they say nothing about where a node is. I2P and CJDNS addresses are never reachable (the crawl does not
//! dial them) and appear only as counts. The ASN comes only from `-asmap`;
//! an ASN with fewer than `-crawlexportmink` nodes in the export is
//! `"other"`. The port is only `default` or `other`. The user agent and
//! height are given per node.
//!
//! **Raw** (`raw=true`), nodes are keyed by address and the ASN is exact.
//!
//! The key is `crawlexport.key` in the network's data directory, created
//! (mode 0600) by the first keyed export, or the file `-crawlexportkeyfile`
//! names, which satd never creates. satd never rotates it: replacing the file
//! is the operator's act, and it changes every ID from the next export on.
//!
//! This module is the pure part, apart from the file I/O: every function
//! that needs the time takes `now` (Unix seconds).

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::net::crawl::network_of;
use crate::net::crawlbook::{CrawlBook, CrawlEntry, Network};
use crate::net::crawlreport::{self, Transport};
use crate::net::fingerprint::{Family, Fingerprint};
use crate::net::peer::PeerAddr;
use crate::net::survey;

/// The snapshot directory, in the network's data directory.
pub const SNAPSHOT_DIR: &str = "crawl";

/// The export key's file, in the network's data directory, unless
/// `-crawlexportkeyfile` names another.
pub const EXPORT_KEY_FILE: &str = "crawlexport.key";

/// The export key's length.
pub const EXPORT_KEY_BYTES: usize = 32;

/// How much of the HMAC a node ID keeps: 128 bits, 32 hex digits. Twice
/// the length at which a collision among a few million addresses is
/// conceivable, and still short enough to read.
pub const NODE_ID_BYTES: usize = 16;

/// `-crawlexportmink`'s default: an ASN with fewer nodes than this in a
/// keyed export is `"other"`.
pub const DEFAULT_EXPORT_MIN_K: u32 = 10;

/// `-crawlexportmink`'s ceiling.
pub const MAX_EXPORT_MIN_K: u32 = 100_000;

const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;

/// Every hourly snapshot younger than this is kept.
pub const HOURLY_KEEP_SECS: u64 = 7 * DAY;

/// No snapshot older than this is kept; between [`HOURLY_KEEP_SECS`] and
/// this, the first of each UTC day.
pub const DAILY_KEEP_SECS: u64 = 90 * DAY;

/// How often the crawl checks whether a snapshot is due.
pub const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

const SNAPSHOT_SUFFIX: &str = ".jsonl.gz";

// ---- node IDs and the key ----

/// The secret a keyed export's node IDs are computed under.
#[derive(Clone, PartialEq, Eq)]
pub struct ExportKey(pub [u8; EXPORT_KEY_BYTES]);

impl std::fmt::Debug for ExportKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExportKey(..)")
    }
}

/// The text a node ID is computed over: `ip:port`, `[ipv6]:port`, an
/// IPv4-mapped IPv6 address as IPv4.
pub fn id_message(addr: &std::net::SocketAddr) -> String {
    std::net::SocketAddr::new(addr.ip().to_canonical(), addr.port()).to_string()
}

/// A clearnet node's ID: HMAC-SHA256 under `key` of [`id_message`],
/// truncated to [`NODE_ID_BYTES`], in lowercase hex.
pub fn node_id(key: &ExportKey, addr: &std::net::SocketAddr) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key.0).expect("HMAC takes a key of any length");
    mac.update(id_message(addr).as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..NODE_ID_BYTES])
}

/// Where the export key comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// `crawlexport.key` in the data directory: created by the first keyed
    /// export.
    Default(PathBuf),
    /// `-crawlexportkeyfile`: the operator's file, never created here.
    Supplied(PathBuf),
}

impl KeySource {
    pub fn path(&self) -> &Path {
        match self {
            KeySource::Default(p) | KeySource::Supplied(p) => p,
        }
    }
}

/// Read a key file: exactly [`EXPORT_KEY_BYTES`] bytes.
pub fn read_key(path: &Path) -> Result<ExportKey, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading the export key {}: {e}", path.display()))?;
    let key: [u8; EXPORT_KEY_BYTES] = bytes.as_slice().try_into().map_err(|_| {
        format!("the export key {} must be {EXPORT_KEY_BYTES} bytes, not {}", path.display(), bytes.len())
    })?;
    Ok(ExportKey(key))
}

/// The export key from `source`. The default file is created on first use,
/// mode 0600, from the system's random source, and read as it stands every
/// time after; two first exports at once agree on one key. A supplied file
/// must exist.
pub fn load_key(source: &KeySource) -> Result<ExportKey, String> {
    match source {
        KeySource::Supplied(path) => read_key(path),
        KeySource::Default(path) => match read_key(path) {
            Ok(key) => Ok(key),
            Err(_) => {
                // Absent, or created by a concurrent first export since the
                // read: create it unless it is there (the link never
                // replaces one), then read what is there. Another
                // export's key wins; a file of the wrong length still errs.
                let mut key = [0u8; EXPORT_KEY_BYTES];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
                create_key_file(path, &key)?;
                read_key(path)
            }
        },
    }
}

/// Write `key` to `path` unless a file is there: the key goes to a
/// private temporary file first, which is then linked into place, so the
/// file is never seen short and an existing one is never replaced.
fn create_key_file(path: &Path, key: &[u8; EXPORT_KEY_BYTES]) -> Result<(), String> {
    let tmp = path.with_extension(format!("key.new-{}-{:016x}", std::process::id(), rand::random::<u64>()));
    let result = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts.open(&tmp).map_err(|e| format!("creating {}: {e}", tmp.display()))?;
        f.write_all(key).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
        f.sync_all().map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        match std::fs::hard_link(&tmp, path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(format!("creating the export key {}: {e}", path.display())),
        }
    })();
    let _ = std::fs::remove_file(&tmp);
    result
}

// ---- the export ----

/// How an export lists its nodes.
#[derive(Debug, Clone)]
pub enum Mode {
    /// Clearnet nodes by node ID, ASNs under `min_k` nodes folded.
    Keyed { key: ExportKey, min_k: u32 },
    /// Every node by its address, the ASN exact.
    Raw,
}

/// What an export states besides the book.
#[derive(Debug, Clone, Copy)]
pub struct ExportContext<'a> {
    /// Unix seconds: the snapshot's time.
    pub now: u64,
    /// Our tip's height.
    pub latest_height: u32,
    /// The network's P2P port: a node on it is on the `default` port.
    pub default_port: u16,
    /// The chain, as `-chain` names it.
    pub chain: &'a str,
}

/// The port as an export gives it.
fn port_class(peer: &PeerAddr, default_port: u16) -> &'static str {
    if peer.port() == default_port { "default" } else { "other" }
}

/// Our fields of a node, the `satd` object after Bitnodes' thirteen.
fn satd_fields(peer: &PeerAddr, e: &CrawlEntry, default_port: u16) -> serde_json::Value {
    let o = e.observation.as_ref();
    let fp = o.map(|o| o.fingerprint).unwrap_or_default();
    // `claimed` confidence comes with a null `family`: the user agent named
    // the family and no row matched, so nothing was observed.
    let confidence = match fp {
        Fingerprint::Known(_, c) => Some(c.name()),
        _ => None,
    };
    serde_json::json!({
        "network": network_of(peer).name(),
        "port": port_class(peer, default_port),
        "transport": Transport::of(e).name(),
        "v2_advertised": e.v2_advertised(),
        "family": fp.observed().map(Family::name),
        "confidence": confidence,
        "claimed": o.and_then(|o| Family::claimed_by(&o.user_agent)).map(Family::name),
        "mismatch": matches!(fp, Fingerprint::Mismatch { .. }),
        "chain_check": o.and_then(|o| o.chain_check).map(crawlreport::chain_check_name),
        "last_seen": e.last_success,
    })
}

/// A node as Bitnodes lists one, then our `satd` object.
fn node_value(peer: &PeerAddr, e: &CrawlEntry, asn: Option<String>, default_port: u16) -> serde_json::Value {
    let o = e.observation.as_ref();
    serde_json::json!([
        o.map(|o| o.protocol_version),
        o.map(|o| o.user_agent.as_str()),
        // connected since: no long-lived connection measures it.
        null,
        o.map(|o| o.services),
        o.map(|o| o.height),
        // hostname, city, country, latitude, longitude, timezone
        null,
        null,
        null,
        null,
        null,
        null,
        asn,
        // organization
        null,
        satd_fields(peer, e, default_port),
    ])
}

fn asn_text(asn: u32) -> String {
    format!("AS{asn}")
}

/// The export of `book`'s reachable set as of `ctx.now`.
pub fn export_json(book: &CrawlBook, ctx: &ExportContext<'_>, mode: &Mode) -> serde_json::Value {
    let reachable: Vec<(&PeerAddr, &CrawlEntry)> = book.snapshot(ctx.now).collect();
    let asn_of = |e: &CrawlEntry| e.observation.as_ref().and_then(|o| o.asn);
    // Nodes per ASN, for the folding.
    let mut per_asn: BTreeMap<u32, u32> = BTreeMap::new();
    for (_, e) in &reachable {
        if let Some(a) = asn_of(e) {
            *per_asn.entry(a).or_default() += 1;
        }
    }
    let mut nodes = serde_json::Map::new();
    for (peer, e) in &reachable {
        let (key, asn) = match (mode, peer) {
            (Mode::Raw, _) => (peer.to_string(), asn_of(e).map(asn_text)),
            // The onion raw. On the network's port it is listed by host
            // alone (its port class says `default`); on another port the
            // port is kept, so two services of one onion are two nodes.
            // An onion's port is as public as its address.
            (Mode::Keyed { .. }, PeerAddr::Onion { host, port }) => {
                let key = if *port == ctx.default_port { host.clone() } else { format!("{host}:{port}") };
                (key, asn_of(e).map(asn_text))
            }
            (Mode::Keyed { key, min_k }, PeerAddr::Socket(sa)) => {
                let asn = asn_of(e).map(|a| {
                    if per_asn.get(&a).copied().unwrap_or(0) < *min_k { "other".to_string() } else { asn_text(a) }
                });
                (node_id(key, sa), asn)
            }
        };
        nodes.insert(key, node_value(peer, e, asn, ctx.default_port));
    }
    let counts = book.counts();
    let learned = |n: Network| counts.learned[Network::ALL.iter().position(|x| *x == n).expect("in ALL")];
    let mut satd = serde_json::json!({
        "export": match mode { Mode::Keyed { .. } => "keyed", Mode::Raw => "raw" },
        "chain": ctx.chain,
        "liveness": book.params().liveness_secs,
        "learned_not_dialled": { "i2p": learned(Network::I2p), "cjdns": learned(Network::Cjdns) },
    });
    if let Mode::Keyed { min_k, .. } = mode {
        satd["node_id"] = serde_json::json!(format!("hmac-sha256-{}", NODE_ID_BYTES * 8));
        satd["asn_min_count"] = serde_json::json!(min_k);
    }
    serde_json::json!({
        "timestamp": ctx.now,
        "total_nodes": nodes.len(),
        "latest_height": ctx.latest_height,
        "nodes": nodes,
        "satd": satd,
    })
}

/// An hourly snapshot's lines, uncompressed: per reachable node, one JSON
/// object, `{"timestamp", "latest_height", "addr", "node"}`, `node` as the
/// raw export lists it. Sorted by address.
pub fn snapshot_lines(book: &CrawlBook, ctx: &ExportContext<'_>) -> Vec<u8> {
    let mut reachable: Vec<(&PeerAddr, &CrawlEntry)> = book.snapshot(ctx.now).collect();
    reachable.sort_unstable_by(|a, b| a.0.cmp(b.0));
    let mut out = Vec::new();
    for (peer, e) in reachable {
        let asn = e.observation.as_ref().and_then(|o| o.asn).map(asn_text);
        let line = serde_json::json!({
            "timestamp": ctx.now,
            "latest_height": ctx.latest_height,
            "addr": peer.to_string(),
            "node": node_value(peer, e, asn, ctx.default_port),
        });
        serde_json::to_writer(&mut out, &line).expect("a JSON value serializes");
        out.push(b'\n');
    }
    out
}

// ---- gzip ----

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// CRC-32 (IEEE 802.3), as gzip's trailer has it.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c = CRC_TABLE[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// `data` as a gzip member (RFC 1952): no name, no extra fields, `mtime`
/// in the header, DEFLATE at level 6.
pub fn gzip(data: &[u8], mtime: u32) -> Vec<u8> {
    let body = miniz_oxide::deflate::compress_to_vec(data, 6);
    let mut out = Vec::with_capacity(body.len() + 18);
    out.extend_from_slice(&[0x1f, 0x8b, 8, 0]);
    out.extend_from_slice(&mtime.to_le_bytes());
    // XFL 0, OS 255 (unknown).
    out.extend_from_slice(&[0, 0xff]);
    out.extend_from_slice(&body);
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// Read back a member [`gzip`] wrote: for tests.
#[cfg(test)]
pub fn gunzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < 18 || bytes[..4] != [0x1f, 0x8b, 8, 0] {
        return Err("not a gzip member this module wrote".into());
    }
    let (body, trailer) = bytes[10..].split_at(bytes.len() - 18);
    let data = miniz_oxide::inflate::decompress_to_vec(body).map_err(|e| format!("inflate: {e:?}"))?;
    let crc = u32::from_le_bytes(trailer[..4].try_into().unwrap());
    let len = u32::from_le_bytes(trailer[4..].try_into().unwrap());
    if crc != crc32(&data) || len != data.len() as u32 {
        return Err("bad trailer".into());
    }
    Ok(data)
}

// ---- the hourly files ----

/// A snapshot's file name at `time`.
pub fn snapshot_file_name(time: u64) -> String {
    format!("{time}{SNAPSHOT_SUFFIX}")
}

/// The time of a snapshot file by its name; `None` for any other file.
pub fn parse_snapshot_name(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(SNAPSHOT_SUFFIX)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The snapshots in `dir`, oldest first; none when it does not exist.
pub fn list_snapshots(dir: &Path) -> Result<Vec<u64>, String> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("reading {}: {e}", dir.display())),
    };
    let mut times: Vec<u64> = rd
        .filter_map(Result::ok)
        .filter_map(|d| d.file_name().to_str().and_then(parse_snapshot_name))
        .collect();
    times.sort_unstable();
    Ok(times)
}

/// Which of the snapshots at `times` to delete as of `now`: none younger
/// than [`HOURLY_KEEP_SECS`]; every one at least [`DAILY_KEEP_SECS`] old;
/// between the two, all but the first of each UTC day. A snapshot dated
/// after `now` (the clock went back) is young.
pub fn prune_plan(times: &[u64], now: u64) -> Vec<u64> {
    // The band a snapshot of this age is in: hourly, daily or gone.
    let daily = |t: u64| (HOURLY_KEEP_SECS..DAILY_KEEP_SECS).contains(&now.saturating_sub(t));
    let gone = |t: u64| now.saturating_sub(t) >= DAILY_KEEP_SECS;
    let mut first_of_day: BTreeMap<u64, u64> = BTreeMap::new();
    for &t in times.iter().filter(|t| daily(**t)) {
        first_of_day.entry(t / DAY).and_modify(|f| *f = (*f).min(t)).or_insert(t);
    }
    let mut delete: Vec<u64> = times
        .iter()
        .copied()
        .filter(|&t| gone(t) || (daily(t) && first_of_day.get(&(t / DAY)) != Some(&t)))
        .collect();
    delete.sort_unstable();
    delete
}

/// What one write did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub path: PathBuf,
    pub bytes: usize,
    /// Snapshots the pruning deleted.
    pub pruned: usize,
}

/// The snapshot directory and the time of its newest snapshot.
#[derive(Debug)]
pub struct SnapshotStore {
    dir: PathBuf,
    last: Option<u64>,
    /// When the last write failed: none is tried again for
    /// [`SNAPSHOT_RETRY_SECS`].
    failed: Option<u64>,
}

/// After a failed write, how long before the next try: each try builds the
/// whole reachable set under the book's lock.
pub const SNAPSHOT_RETRY_SECS: u64 = 10 * 60;

impl SnapshotStore {
    /// The store at `dir`; its newest snapshot, if any, is the last write,
    /// so a restart within the hour writes none.
    pub fn open(dir: PathBuf) -> Self {
        let last = list_snapshots(&dir).ok().and_then(|t| t.last().copied());
        SnapshotStore { dir, last, failed: None }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether a snapshot is due at `now`: none was written in this UTC
    /// hour.
    pub fn due(&self, now: u64) -> bool {
        self.last.is_none_or(|l| l / HOUR != now / HOUR)
            && self.failed.is_none_or(|f| now.saturating_sub(f) >= SNAPSHOT_RETRY_SECS)
    }

    /// Note a failed write at `now`: [`Self::due`] waits
    /// [`SNAPSHOT_RETRY_SECS`] before the next try.
    pub fn failed(&mut self, now: u64) {
        self.failed = Some(now);
    }

    /// Write `lines` as the snapshot at `now`, then prune.
    pub fn write(&mut self, now: u64, lines: &[u8]) -> Result<Written, String> {
        self.ensure_dir()?;
        let path = self.dir.join(snapshot_file_name(now));
        let gz = gzip(lines, now as u32);
        survey::write_private_file(&path, &gz)?;
        self.last = Some(now);
        self.failed = None;
        let mut pruned = 0;
        // The snapshot is written: a failure to prune is a warning, not
        // a failed write.
        let existing = list_snapshots(&self.dir).unwrap_or_else(|e| {
            tracing::warn!(dir = %self.dir.display(), "Could not list the crawl snapshots to prune: {e}");
            Vec::new()
        });
        for t in prune_plan(&existing, now) {
            let p = self.dir.join(snapshot_file_name(t));
            match std::fs::remove_file(&p) {
                Ok(()) => pruned += 1,
                Err(e) => tracing::warn!(file = %p.display(), "Could not delete an old crawl snapshot: {e}"),
            }
        }
        Ok(Written { path, bytes: gz.len(), pruned })
    }

    /// Create the directory, with its parent's permissions, if it is not
    /// there.
    fn ensure_dir(&self) -> Result<(), String> {
        if self.dir.is_dir() {
            return Ok(());
        }
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
            let parent = self.dir.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
            let mode =
                std::fs::metadata(parent).map_err(|e| format!("reading {}: {e}", parent.display()))?.permissions().mode();
            builder.mode(mode & 0o777);
        }
        builder.create(&self.dir).map_err(|e| format!("creating {}: {e}", self.dir.display()))
    }
}

#[cfg(test)]
#[path = "crawlsnapshot_tests.rs"]
mod tests;
