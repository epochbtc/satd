//! The publisher's file, `<datadir>/nap/attestations.dat`.
//!
//! ```text
//! magic     "SNAP"
//! version   u32 LE    // 1
//! count     u32 LE
//! entries   count attestations, each in its wire form
//! checksum  [32]      // SHA256 of everything before it
//! ```
//!
//! The wire form is self-delimiting, so entries need no length prefix.
//! [`save`] writes a temporary file, syncs it and renames it over the old
//! one, so a crash leaves either the old file or the new one.
//!
//! The publisher keeps a [`Journal`] beside the file, `attestations.journal`,
//! so a change costs one appended record rather than a rewrite of the whole
//! store:
//!
//! ```text
//! magic     "SNAJ"
//! version   u32 LE    // 1
//! base      [32]      // the checksum of the file it follows; zeros for none
//! records   each { kind u8, length u32 LE, payload, checksum [32] }
//! ```
//!
//! A record is `PUT` (payload: an attestation's wire form, which replaces
//! any stored for its outpoint and key) or `REMOVE` (payload: the outpoint,
//! 36 bytes, then the key). Its checksum is SHA256 of its kind, length and
//! payload. Each record is synced before the change it makes is reported.
//! When the journal outgrows the file, the store is written whole and the
//! journal started again ([`Journal::compact`]). A crash between the two
//! leaves a journal naming the old file, which the new file already
//! includes, so it is ignored, with a warning. A last record cut short by a
//! crash, or left as zeros, was never reported done and is dropped; anything
//! else wrong is an error, a length longer than any record included.

use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use bitcoin::hashes::{Hash as _, sha256};

use bitcoin::OutPoint;
use bitcoin::consensus::encode;

use super::{Attestation, MAX_ATTESTATION_SIZE, MAX_KEY_LEN};

const MAGIC: &[u8; 4] = b"SNAP";
/// The file format version.
pub const FILE_VERSION: u32 = 1;
const HEADER_LEN: usize = 12;
const CHECKSUM_LEN: usize = 32;

/// The file's bytes for `attestations`.
pub fn encode<'a>(attestations: impl ExactSizeIterator<Item = &'a Attestation>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN + CHECKSUM_LEN);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&FILE_VERSION.to_le_bytes());
    buf.extend_from_slice(&(attestations.len() as u32).to_le_bytes());
    for att in attestations {
        buf.extend_from_slice(&att.to_bytes());
    }
    let checksum = sha256::Hash::hash(&buf);
    buf.extend_from_slice(checksum.as_byte_array());
    buf
}

/// Parse the file's bytes. Anything other than exactly what [`encode`]
/// writes is an error: the file is the operator's, and a part of it is not
/// worth guessing at.
pub fn decode(bytes: &[u8]) -> Result<Vec<Attestation>, String> {
    if bytes.len() < HEADER_LEN + CHECKSUM_LEN {
        return Err("the file is truncated".into());
    }
    let (body, checksum) = bytes.split_at(bytes.len() - CHECKSUM_LEN);
    if sha256::Hash::hash(body).as_byte_array() != checksum {
        return Err("the checksum does not match".into());
    }
    if &body[..4] != MAGIC {
        return Err("the file is not a NAP attestation store".into());
    }
    let version = u32::from_le_bytes(body[4..8].try_into().expect("4 bytes"));
    if version != FILE_VERSION {
        return Err(format!("unsupported file version {version}"));
    }
    let count = u32::from_le_bytes(body[8..12].try_into().expect("4 bytes"));
    let mut rest = &body[HEADER_LEN..];
    // Every attestation is longer than a byte, so `count` cannot exceed what
    // is left; that bounds the allocation.
    let mut out = Vec::with_capacity((count as usize).min(rest.len()));
    for i in 0..count {
        let att = Attestation::decode_from(&mut rest).map_err(|e| format!("entry {i}: {e}"))?;
        out.push(att);
    }
    if !rest.is_empty() {
        return Err(format!("{} bytes follow the last entry", rest.len()));
    }
    Ok(out)
}

/// Read the file at `path`. A missing file is an empty store.
pub fn load(path: &Path) -> Result<Vec<Attestation>, String> {
    match std::fs::read(path) {
        Ok(bytes) => decode(&bytes).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

/// Write `bytes` to `path` through a synced temporary file and a rename,
/// creating the directory if it is missing.
pub fn save(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("dat.tmp");
    let written = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("writing {}: {e}", path.display()));
    }
    Ok(())
}

const JOURNAL_MAGIC: &[u8; 4] = b"SNAJ";
/// The journal format version.
pub const JOURNAL_VERSION: u32 = 1;
const JOURNAL_HEADER_LEN: usize = 4 + 4 + 32;
const PUT: u8 = 1;
const REMOVE: u8 = 2;
/// A record's kind and length.
const RECORD_HEADER_LEN: usize = 1 + 4;
/// A journal is folded into the file once it is larger than the file and
/// at least this long, so a small store is not rewritten every few changes.
pub const MIN_COMPACT_LEN: u64 = 1 << 20;

/// One change, as the journal records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// Store this attestation, replacing any for its outpoint and key.
    Put(Attestation),
    /// Drop the attestation for this outpoint and key.
    Remove(OutPoint, String),
}

impl Record {
    fn encode(&self) -> Vec<u8> {
        let (kind, payload) = match self {
            Record::Put(att) => (PUT, att.to_bytes()),
            Record::Remove(outpoint, key) => {
                let mut p = encode::serialize(outpoint);
                p.extend_from_slice(key.as_bytes());
                (REMOVE, p)
            }
        };
        let mut out = Vec::with_capacity(RECORD_HEADER_LEN + payload.len() + CHECKSUM_LEN);
        out.push(kind);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        let checksum = sha256::Hash::hash(&out);
        out.extend_from_slice(checksum.as_byte_array());
        out
    }

    fn decode(kind: u8, payload: &[u8]) -> Result<Self, String> {
        match kind {
            PUT => Attestation::from_bytes(payload).map(Record::Put).map_err(|e| e.to_string()),
            REMOVE if payload.len() >= 36 => {
                let outpoint: OutPoint = encode::deserialize(&payload[..36]).map_err(|e| e.to_string())?;
                let key = String::from_utf8(payload[36..].to_vec()).map_err(|_| "the key is not text".to_string())?;
                Ok(Record::Remove(outpoint, key))
            }
            REMOVE => Err("a removal shorter than an outpoint".into()),
            other => Err(format!("unknown record kind {other}")),
        }
    }
}

/// The journal beside the file at `path`.
pub fn journal_path(path: &Path) -> PathBuf {
    path.with_extension("journal")
}

/// The checksum a journal names its file by: the file's own, the last 32
/// bytes; zeros when there is no file.
fn base_checksum(base: Option<&[u8]>) -> [u8; 32] {
    base.map_or([0; 32], |b| b[b.len() - CHECKSUM_LEN..].try_into().expect("a decoded file holds its checksum"))
}

/// The checksum of the file a journal's bytes name, from its header.
fn journal_base(bytes: &[u8]) -> Result<[u8; 32], String> {
    if bytes.len() < JOURNAL_HEADER_LEN {
        // The header is written whole before the journal takes its name, so
        // a short one is not a journal this node wrote.
        return Err("the journal is truncated".into());
    }
    if &bytes[..4] != JOURNAL_MAGIC {
        return Err("the file is not a NAP attestation journal".into());
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes"));
    if version != JOURNAL_VERSION {
        return Err(format!("unsupported journal version {version}"));
    }
    Ok(bytes[8..JOURNAL_HEADER_LEN].try_into().expect("32 bytes"))
}

/// The longest payload a record of `kind` can have, or `None` for a kind
/// the journal does not write.
fn max_payload(kind: u8) -> Option<usize> {
    match kind {
        PUT => Some(MAX_ATTESTATION_SIZE),
        REMOVE => Some(36 + MAX_KEY_LEN),
        _ => None,
    }
}

/// A journal's records, after its header, and how many of its bytes are
/// whole. A crash can leave only the last record incomplete: cut short,
/// whole but for its checksum, or as zeros a filesystem filled in. Those
/// are left out. Anything else wrong is an error, so damage before the end
/// is never cut off with the records behind it: a record's kind and length
/// are checked against what the journal writes before its length is
/// trusted to find the end.
fn journal_records(bytes: &[u8]) -> Result<(Vec<Record>, usize), String> {
    let mut records = Vec::new();
    let mut at = JOURNAL_HEADER_LEN;
    while at < bytes.len() {
        let rest = &bytes[at..];
        if rest.iter().all(|b| *b == 0) {
            break; // zeros past the last write
        }
        let Some(max) = max_payload(rest[0]) else {
            return Err(format!("journal record at byte {at}: unknown record kind {}", rest[0]));
        };
        let Some(len) = rest.get(1..RECORD_HEADER_LEN).map(|l| u32::from_le_bytes(l.try_into().expect("4 bytes")) as usize)
        else {
            break; // cut short
        };
        if len > max {
            return Err(format!("journal record at byte {at}: a length of {len}, longer than any record"));
        }
        let end = RECORD_HEADER_LEN + len + CHECKSUM_LEN;
        if rest.len() < end {
            break; // cut short
        }
        let (body, checksum) = rest[..end].split_at(end - CHECKSUM_LEN);
        if sha256::Hash::hash(body).as_byte_array() != checksum {
            if rest.len() == end {
                break; // the last record, torn
            }
            return Err(format!("journal record at byte {at}: the checksum does not match"));
        }
        let record = Record::decode(rest[0], &body[RECORD_HEADER_LEN..])
            .map_err(|e| format!("journal record at byte {at}: {e}"))?;
        records.push(record);
        at += end;
    }
    Ok((records, at))
}

/// The store read back from disk, and the journal to record changes in.
pub struct Opened {
    /// The file's attestations, in its order, then the journal's records
    /// that follow it.
    pub base: Vec<Attestation>,
    pub records: Vec<Record>,
    pub journal: Journal,
}

/// Read the file at `path` and its journal. A missing file is an empty
/// store and a missing journal an empty one. A journal that names another
/// file is left over from a compaction the new file already holds: its
/// records are not read. A journal's torn last record is cut off.
pub fn read(path: &Path) -> Result<Opened, String> {
    let base_bytes = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };
    let base = match &base_bytes {
        Some(bytes) => decode(bytes).map_err(|e| format!("{}: {e}", path.display()))?,
        None => Vec::new(),
    };
    let checksum = base_checksum(base_bytes.as_deref());
    let base_len = base_bytes.as_ref().map_or(0, |b| b.len() as u64);
    let jpath = journal_path(path);
    let mut journal =
        Journal { path: jpath.clone(), file: None, len: 0, base: checksum, base_len, compact_at: MIN_COMPACT_LEN, retry_at: 0,
        #[cfg(test)]
        compactions: 0,
    };
    let records = match std::fs::read(&jpath) {
        Ok(bytes) => {
            let named = journal_base(&bytes).map_err(|e| format!("{}: {e}", jpath.display()))?;
            if named != checksum {
                // Left by a compaction that wrote the file and stopped before
                // starting a new journal, which the file already holds; or by
                // an older file restored over a newer journal, whose changes
                // are then lost. Neither is read, damaged or not.
                tracing::warn!(
                    target: "nap",
                    "NAP: ignoring {} ({} bytes): it follows another {}; the next change replaces it",
                    jpath.display(),
                    bytes.len(),
                    path.display()
                );
                Vec::new()
            } else {
                let (records, whole) = journal_records(&bytes).map_err(|e| format!("{}: {e}", jpath.display()))?;
                let file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&jpath)
                    .map_err(|e| format!("opening {}: {e}", jpath.display()))?;
                if whole < bytes.len() {
                    file.set_len(whole as u64)
                        .and_then(|()| file.sync_all())
                        .map_err(|e| format!("cutting the torn end off {}: {e}", jpath.display()))?;
                }
                journal.file = Some(file);
                journal.len = whole as u64;
                records
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("reading {}: {e}", jpath.display())),
    };
    Ok(Opened { base, records, journal })
}

/// The journal a publisher records its changes in.
#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    /// Open for appending, once the journal on disk names the current file.
    file: Option<File>,
    /// Its whole length.
    len: u64,
    /// The checksum of the file it follows.
    base: [u8; 32],
    base_len: u64,
    /// The shortest journal folded in; [`MIN_COMPACT_LEN`] but in tests.
    compact_at: u64,
    /// After a compaction fails, the length the journal must reach before
    /// the next is tried, so a file that cannot be written does not cost a
    /// whole rewrite on every change.
    retry_at: u64,
    /// Compactions tried, for tests.
    #[cfg(test)]
    pub(super) compactions: u32,
}

impl Journal {
    /// Append `record` and sync it. On an error the journal is as it was.
    pub fn append(&mut self, record: &Record) -> Result<(), String> {
        if self.file.is_none() {
            self.start()?;
        }
        let file = self.file.as_mut().expect("started");
        let bytes = record.encode();
        let written = file.write_all(&bytes).and_then(|()| file.sync_data());
        if let Err(e) = written {
            // Leave no partial record for the next one to follow.
            let _ = file.set_len(self.len);
            return Err(format!("writing {}: {e}", self.path.display()));
        }
        self.len += bytes.len() as u64;
        Ok(())
    }

    /// Whether the journal has outgrown the file it follows.
    pub fn wants_compaction(&self) -> bool {
        self.len >= self.compact_at && self.len > self.base_len && self.len >= self.retry_at
    }

    /// The journal's length on disk, in bytes.
    pub fn bytes(&self) -> u64 {
        self.len
    }

    #[cfg(test)]
    pub fn set_compact_at(&mut self, len: u64) {
        self.compact_at = len;
    }

    /// Write `attestations` whole to `path`, the file this journal follows,
    /// and start the journal again after it.
    pub fn compact<'a>(
        &mut self,
        path: &Path,
        attestations: impl ExactSizeIterator<Item = &'a Attestation>,
    ) -> Result<(), String> {
        #[cfg(test)]
        {
            self.compactions += 1;
        }
        let bytes = encode(attestations);
        if let Err(e) = save(path, &bytes) {
            self.retry_at = self.len.saturating_mul(2);
            return Err(e);
        }
        sync_dir(path);
        // The file is the store now; a journal naming the old one is
        // ignored, so until the new journal is in place nothing is lost.
        self.base = base_checksum(Some(&bytes));
        self.base_len = bytes.len() as u64;
        self.file = None;
        self.len = 0;
        self.start()
    }

    /// Put an empty journal naming the current file in place, through a
    /// synced temporary file and a rename, and open it for appending.
    fn start(&mut self) -> Result<(), String> {
        let mut header = Vec::with_capacity(JOURNAL_HEADER_LEN);
        header.extend_from_slice(JOURNAL_MAGIC);
        header.extend_from_slice(&JOURNAL_VERSION.to_le_bytes());
        header.extend_from_slice(&self.base);
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        }
        let tmp = self.path.with_extension("journal.tmp");
        let placed = (|| {
            let mut f = File::create(&tmp)?;
            f.write_all(&header)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)?;
            std::fs::OpenOptions::new().append(true).open(&self.path)
        })();
        match placed {
            Ok(file) => {
                sync_dir(&self.path);
                self.file = Some(file);
                self.len = JOURNAL_HEADER_LEN as u64;
                Ok(())
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(format!("writing {}: {e}", self.path.display()))
            }
        }
    }
}

/// Sync the directory holding `path`, so a rename into it outlives a power
/// loss. Not every platform opens directories for syncing; the files
/// themselves are already synced.
fn sync_dir(path: &Path) {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty())
        && let Ok(d) = File::open(dir)
    {
        let _ = d.sync_all();
    }
}
