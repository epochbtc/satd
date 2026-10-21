//! The wire form.
//!
//! ```text
//! attestation {
//!     version        u8         // 1
//!     outpoint       txid, vout
//!     key            varstr
//!     value          varstr
//!     anchor_height  u32
//!     anchor_hash    [32]
//!     sig_format     u8         // 0 simple, 1 full, 2 legacy
//!     signature      varbytes
//! }
//! ```
//!
//! Integers are little-endian and lengths are Bitcoin compact sizes, as in
//! every other P2P message. The signature bytes are the consensus-encoded
//! witness stack (simple), the consensus-encoded `to_sign` (full), or the
//! 65-byte compact signature (legacy).
//!
//! Decoding is strict: it accepts only the bytes encoding produces, so an
//! attestation has exactly one serialized form and one [`Attestation::id`].
//! Non-minimal compact sizes and non-canonical signature encodings are
//! refused.

use bitcoin::consensus::encode::{self, Decodable, Encodable};
use bitcoin::{BlockHash, OutPoint, Transaction, Witness};

use super::{Attestation, LEGACY_SIGNATURE_LEN, MAX_ATTESTATION_SIZE, NapSignature, VERSION, message};

/// Why bytes or fields do not make an attestation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    #[error("attestation is {0} bytes, over the {MAX_ATTESTATION_SIZE}-byte limit")]
    TooLarge(usize),
    #[error("unknown attestation version {0}")]
    Version(u8),
    #[error("key must be 1 to 128 bytes, not {0}")]
    KeyLength(usize),
    #[error("key must be printable ASCII")]
    KeyCharacters,
    #[error("value must be at most 128 bytes, not {0}")]
    ValueLength(usize),
    #[error("value must be printable ASCII")]
    ValueCharacters,
    #[error("unknown signature format {0}")]
    SignatureFormat(u8),
    #[error("signature does not decode for its format: {0}")]
    Signature(String),
    #[error("malformed attestation: {0}")]
    Decode(String),
    #[error("malformed message text at {0:?}")]
    Message(&'static str),
}

impl From<encode::Error> for FormatError {
    fn from(e: encode::Error) -> Self {
        FormatError::Decode(e.to_string())
    }
}

impl NapSignature {
    /// The signature bytes, without the format byte or length.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            NapSignature::Simple(w) => encode::serialize(w),
            NapSignature::Full(tx) => encode::serialize(tx),
            NapSignature::Legacy(sig) => sig.to_vec(),
        }
    }

    /// Decode signature bytes of `format`, refusing any encoding but the
    /// one [`Self::to_bytes`] produces.
    pub fn from_bytes(format: u8, bytes: &[u8]) -> Result<Self, FormatError> {
        let sig = match format {
            0 => NapSignature::Simple(
                encode::deserialize::<Witness>(bytes).map_err(|e| FormatError::Signature(e.to_string()))?,
            ),
            1 => NapSignature::Full(
                encode::deserialize::<Transaction>(bytes)
                    .map_err(|e| FormatError::Signature(e.to_string()))?,
            ),
            2 => NapSignature::Legacy(bytes.try_into().map_err(|_| {
                FormatError::Signature(format!(
                    "a legacy signature is {LEGACY_SIGNATURE_LEN} bytes, not {}",
                    bytes.len()
                ))
            })?),
            f => return Err(FormatError::SignatureFormat(f)),
        };
        // rust-bitcoin already refuses the non-canonical forms known to us
        // (non-minimal compact sizes, a segwit marker with no witness); this
        // keeps the one-encoding guarantee if a decoder ever relaxes.
        if sig.to_bytes() != bytes {
            return Err(FormatError::Signature("non-canonical encoding".into()));
        }
        Ok(sig)
    }
}

impl Encodable for Attestation {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = VERSION.consensus_encode(w)?;
        len += self.outpoint.consensus_encode(w)?;
        len += self.key.as_bytes().to_vec().consensus_encode(w)?;
        len += self.value.as_bytes().to_vec().consensus_encode(w)?;
        len += self.anchor_height.consensus_encode(w)?;
        len += self.anchor_hash.consensus_encode(w)?;
        len += self.signature.format().consensus_encode(w)?;
        len += self.signature.to_bytes().consensus_encode(w)?;
        Ok(len)
    }
}

pub(super) fn serialized_size(att: &Attestation) -> usize {
    att.consensus_encode(&mut bitcoin::io::sink()).expect("a sink does not fail")
}

impl Attestation {
    /// The serialized form.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode::serialize(self)
    }

    /// Decode one serialized attestation, which must be the whole of `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut r = bytes;
        let att = Self::decode_from(&mut r)?;
        if !r.is_empty() {
            return Err(FormatError::Decode(format!("{} trailing bytes", r.len())));
        }
        Ok(att)
    }

    /// Decode one attestation from the front of `r`, advancing it past the
    /// attestation: for a message that carries a list of them. Refuses
    /// anything over [`MAX_ATTESTATION_SIZE`] before reading its signature.
    pub fn decode_from(r: &mut &[u8]) -> Result<Self, FormatError> {
        let start = *r;
        let version = u8::consensus_decode(r)?;
        if version != VERSION {
            return Err(FormatError::Version(version));
        }
        let outpoint = OutPoint::consensus_decode(r)?;
        let key = bytes(r)?;
        message::check_key(&key)?;
        let value = bytes(r)?;
        message::check_value(&value)?;
        let anchor_height = u32::consensus_decode(r)?;
        let anchor_hash = BlockHash::consensus_decode(r)?;
        let format = u8::consensus_decode(r)?;
        let sig = bytes(r)?;
        let size = start.len() - r.len();
        if size > MAX_ATTESTATION_SIZE {
            return Err(FormatError::TooLarge(size));
        }
        let signature = NapSignature::from_bytes(format, &sig)?;
        // Printable ASCII is UTF-8.
        let key = String::from_utf8(key).expect("checked printable");
        let value = String::from_utf8(value).expect("checked printable");
        Ok(Attestation { outpoint, key, value, anchor_height, anchor_hash, signature })
    }
}

/// A compact-size-prefixed byte string, refused before allocation if it
/// claims more bytes than an attestation can hold.
fn bytes(r: &mut &[u8]) -> Result<Vec<u8>, FormatError> {
    let len = encode::VarInt::consensus_decode(r)?.0;
    if len > MAX_ATTESTATION_SIZE as u64 {
        return Err(FormatError::TooLarge(usize::try_from(len).unwrap_or(usize::MAX)));
    }
    let len = len as usize;
    if r.len() < len {
        return Err(FormatError::Decode("truncated".into()));
    }
    let (head, tail) = r.split_at(len);
    *r = tail;
    Ok(head.to_vec())
}
