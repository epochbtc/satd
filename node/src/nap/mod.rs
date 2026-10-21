//! Node Attestation Protocol (NAP): attestation types, encodings and validity.
//!
//! An attestation is a holder's signed statement of one key-value pair for
//! one outpoint, anchored to a recent block. It is valid at an evaluation tip
//! while its anchor is on the active chain and fresh, and its coin is unspent
//! and old enough; it counts with the coin's value. Nothing here touches the
//! network or the store: [`validity`] reads chain state through
//! [`validity::ChainView`].
//!
//! - [`message`]: the text the holder signs, rendered and parsed strictly.
//! - [`wire`]: the serialized form, which peers exchange and which
//!   [`Attestation::id`] hashes.
//! - [`validity`]: the validity rules at a tip, and supersession.

pub mod message;
pub mod validity;
pub mod wire;

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::{BlockHash, OutPoint, Transaction, Witness};

pub use validity::{ChainView, Coin, Rejection, evaluate, select, supersedes};
pub use wire::FormatError;

/// The attestation format version, the first byte of the wire form.
pub const VERSION: u8 = 1;
/// How long a signature stands without re-signing: valid while
/// `tip_height - anchor_height < FRESHNESS_WINDOW` (~6 months).
pub const FRESHNESS_WINDOW: u32 = 26_208;
/// How old a coin must be at the anchor: its confirmation height is at most
/// `anchor_height - MIN_COIN_AGE` (~4 weeks). Larger than coinbase maturity,
/// so it covers that too.
pub const MIN_COIN_AGE: u32 = 4_032;
/// How far below the tip `createnapattestation` anchors.
pub const ANCHOR_DEPTH: u32 = 6;
/// The largest serialized attestation, in bytes.
pub const MAX_ATTESTATION_SIZE: usize = 4_000;
/// The longest key, in bytes. Keys are at least one byte.
pub const MAX_KEY_LEN: usize = 128;
/// The longest value, in bytes. An empty value is a withdrawal.
pub const MAX_VALUE_LEN: usize = 128;
/// The keys a publisher stores and serves per outpoint. A resource bound,
/// not a counting rule: aggregators count every valid key.
pub const MAX_KEYS_PER_OUTPOINT: usize = 32;
/// A legacy (Bitcoin Core `signmessage`) signature's length.
pub const LEGACY_SIGNATURE_LEN: usize = 65;

/// An attestation's signature, by format. The discriminant is the wire
/// `sig_format` byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NapSignature {
    /// Format 0, BIP 322 simple: the witness stack. Native segwit only.
    Simple(Witness),
    /// Format 1, BIP 322 full: the whole `to_sign` transaction.
    Full(Transaction),
    /// Format 2, legacy: Bitcoin Core's compact recoverable signature.
    /// P2PKH only.
    Legacy([u8; LEGACY_SIGNATURE_LEN]),
}

impl NapSignature {
    /// The wire `sig_format` byte.
    pub fn format(&self) -> u8 {
        match self {
            NapSignature::Simple(_) => 0,
            NapSignature::Full(_) => 1,
            NapSignature::Legacy(_) => 2,
        }
    }
}

/// One signed statement. The fields are checked on construction (key and
/// value characters and lengths, serialized size), so every `Attestation`
/// is well formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    outpoint: OutPoint,
    key: String,
    value: String,
    anchor_height: u32,
    anchor_hash: BlockHash,
    signature: NapSignature,
}

impl Attestation {
    pub fn new(
        outpoint: OutPoint,
        key: String,
        value: String,
        anchor_height: u32,
        anchor_hash: BlockHash,
        signature: NapSignature,
    ) -> Result<Self, FormatError> {
        message::check_key(key.as_bytes())?;
        message::check_value(value.as_bytes())?;
        let att = Attestation { outpoint, key, value, anchor_height, anchor_hash, signature };
        let size = wire::serialized_size(&att);
        if size > MAX_ATTESTATION_SIZE {
            return Err(FormatError::TooLarge(size));
        }
        Ok(att)
    }

    pub fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    /// An empty value withdraws the holder's earlier value for the key.
    pub fn is_withdrawal(&self) -> bool {
        self.value.is_empty()
    }

    pub fn anchor_height(&self) -> u32 {
        self.anchor_height
    }

    pub fn anchor_hash(&self) -> BlockHash {
        self.anchor_hash
    }

    pub fn signature(&self) -> &NapSignature {
        &self.signature
    }

    /// The text the holder signed.
    pub fn message(&self) -> String {
        message::render(&self.outpoint, &self.key, &self.value, self.anchor_height, &self.anchor_hash)
    }

    /// SHA256 of the serialized form: the supersession tie-break and the
    /// identity of an attestation however many peers serve it.
    pub fn id(&self) -> sha256::Hash {
        sha256::Hash::hash(&self.to_bytes())
    }
}

#[cfg(test)]
mod tests;
