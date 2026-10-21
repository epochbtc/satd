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

use std::io::Write as _;
use std::path::Path;

use bitcoin::hashes::{Hash as _, sha256};

use super::Attestation;

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
