//! The signed message text.
//!
//! ```text
//! satd NAP attestation v1
//! outpoint: <txid>:<vout>
//! key: <key>
//! value: <value>
//! anchor: <height> <block hash>
//! ```
//!
//! LF line endings, no trailing newline. Keys and values are printable ASCII
//! (0x20–0x7E), so neither can start a new line. There is exactly one text
//! per attestation: [`parse`] accepts only what [`render`] produces.

use bitcoin::{BlockHash, OutPoint};

use super::{FormatError, MAX_KEY_LEN, MAX_VALUE_LEN};

/// The first line.
pub const HEADER: &str = "satd NAP attestation v1";

/// The fields of a parsed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub outpoint: OutPoint,
    pub key: String,
    pub value: String,
    pub anchor_height: u32,
    pub anchor_hash: BlockHash,
}

/// The message text for these fields. The caller checks the key and value
/// ([`check_key`], [`check_value`]); [`super::Attestation`] always has.
pub fn render(
    outpoint: &OutPoint,
    key: &str,
    value: &str,
    anchor_height: u32,
    anchor_hash: &BlockHash,
) -> String {
    format!(
        "{HEADER}\noutpoint: {}:{}\nkey: {key}\nvalue: {value}\nanchor: {anchor_height} {anchor_hash}",
        outpoint.txid, outpoint.vout
    )
}

/// Parse a message text, accepting only the canonical form: the text must be
/// exactly what [`render`] makes from the fields it names (lowercase hex,
/// decimal without leading zeros or signs, LF only, no trailing newline).
pub fn parse(text: &str) -> Result<Message, FormatError> {
    let bad = |what: &'static str| FormatError::Message(what);
    let mut lines = text.split('\n');
    let mut field = |prefix: &'static str| {
        lines.next().and_then(|l| l.strip_prefix(prefix)).ok_or(bad(prefix))
    };
    if !field(HEADER)?.is_empty() {
        return Err(bad(HEADER));
    }
    let (txid, vout) = field("outpoint: ")?.split_once(':').ok_or(bad("outpoint: "))?;
    let outpoint = OutPoint {
        txid: txid.parse().map_err(|_| bad("outpoint: "))?,
        vout: vout.parse().map_err(|_| bad("outpoint: "))?,
    };
    let key = field("key: ")?.to_owned();
    let value = field("value: ")?.to_owned();
    let (height, hash) = field("anchor: ")?.split_once(' ').ok_or(bad("anchor: "))?;
    let anchor_height = height.parse().map_err(|_| bad("anchor: "))?;
    let anchor_hash = hash.parse().map_err(|_| bad("anchor: "))?;
    if lines.next().is_some() {
        return Err(bad("end of message"));
    }
    check_key(key.as_bytes())?;
    check_value(value.as_bytes())?;
    let m = Message { outpoint, key, value, anchor_height, anchor_hash };
    if render(&m.outpoint, &m.key, &m.value, m.anchor_height, &m.anchor_hash) != text {
        return Err(FormatError::Message("non-canonical text"));
    }
    Ok(m)
}

fn printable(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| (0x20..=0x7e).contains(b))
}

/// A key: 1 to [`MAX_KEY_LEN`] printable ASCII bytes.
pub fn check_key(key: &[u8]) -> Result<(), FormatError> {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return Err(FormatError::KeyLength(key.len()));
    }
    if !printable(key) {
        return Err(FormatError::KeyCharacters);
    }
    Ok(())
}

/// A value: 0 to [`MAX_VALUE_LEN`] printable ASCII bytes.
pub fn check_value(value: &[u8]) -> Result<(), FormatError> {
    if value.len() > MAX_VALUE_LEN {
        return Err(FormatError::ValueLength(value.len()));
    }
    if !printable(value) {
        return Err(FormatError::ValueCharacters);
    }
    Ok(())
}
