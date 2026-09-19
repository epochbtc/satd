//! BIP 352 silent payment addresses (`sp1…`).
//!
//! A silent payment address is a bech32m string carrying a version and two
//! compressed public keys: the scan key the sender does ECDH against, and the
//! spend key the output is derived from. It is not a script, and nothing on
//! chain ever contains it — which is the point. The sender turns it into an
//! ordinary taproot output that only the recipient can recognise.
//!
//! Two things about the encoding catch people out. The string is about 117
//! characters, well past BIP 173's 90-character limit for segwit addresses,
//! so anything that reuses a segwit address decoder rejects every valid
//! silent payment address. And the version lives in the first data character,
//! outside the payload, the way a witness version does.

use bitcoin::Network;
use bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bitcoin::bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
use bitcoin::bech32::{Bech32m, Fe32, Hrp};
use bitcoin::secp256k1::PublicKey;

/// The human-readable part for mainnet.
pub const HRP_MAINNET: &str = "sp";
/// The human-readable part for every test network.
pub const HRP_TESTNET: &str = "tsp";

/// The size of a version 0 payload: two compressed public keys.
const PAYLOAD_LEN: usize = 66;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("not a bech32m string: {0}")]
    Malformed(String),

    #[error(
        "silent payment address has the human-readable part {found:?}, but this network uses \
         {expected:?}"
    )]
    WrongNetwork { found: String, expected: String },

    #[error("{0:?} is not a silent payment address human-readable part")]
    UnknownHrp(String),

    #[error("silent payment address has no version character")]
    NoVersion,

    #[error("silent payment address version {0} is not defined")]
    UnknownVersion(u8),

    #[error(
        "silent payment address version {version} carries {len} bytes, expected {expected}"
    )]
    BadPayloadLength {
        version: u8,
        len: usize,
        expected: usize,
    },

    #[error("silent payment address has trailing bits that are not zero")]
    NonZeroPadding,

    #[error("silent payment address does not carry two valid public keys")]
    BadKeys,

    #[error("this node can only create version 0 silent payment outputs, not version {0}")]
    UnsupportedForCreation(u8),
}

/// A decoded silent payment address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpAddress {
    /// The address version. 0 is the only one defined; 1 to 30 are reserved
    /// for forward-compatible extensions and carry at least these two keys.
    pub version: u8,
    /// `B_scan`.
    pub scan_key: PublicKey,
    /// `B_spend`.
    pub spend_key: PublicKey,
}

impl SpAddress {
    /// The human-readable part a network uses. Every test network shares one,
    /// as BIP 352 specifies.
    pub fn hrp_for(network: Network) -> &'static str {
        match network {
            Network::Bitcoin => HRP_MAINNET,
            _ => HRP_TESTNET,
        }
    }

    /// Whether a string could be a silent payment address for this network.
    /// Cheap enough to run before deciding how to parse an output key.
    pub fn looks_like(s: &str, network: Network) -> bool {
        let hrp = Self::hrp_for(network);
        let lower = s.to_ascii_lowercase();
        lower.starts_with(&format!("{hrp}1"))
    }

    /// Decode an address and require it to be for this network.
    pub fn decode(s: &str, network: Network) -> Result<Self, AddressError> {
        let (address, hrp) = Self::decode_any(s)?;
        let expected = Self::hrp_for(network);
        if hrp != expected {
            return Err(AddressError::WrongNetwork {
                found: hrp,
                expected: expected.to_string(),
            });
        }
        Ok(address)
    }

    /// Decode an address without checking which network it is for. Returns the
    /// address and the human-readable part it carried.
    pub fn decode_any(s: &str) -> Result<(Self, String), AddressError> {
        // Deliberately not a segwit decoder: those cap the string at BIP 173's
        // 90 characters, and every silent payment address is longer.
        let checked = CheckedHrpstring::new::<Bech32m>(s)
            .map_err(|e| AddressError::Malformed(e.to_string()))?;
        let hrp = checked.hrp().to_lowercase();
        if hrp != HRP_MAINNET && hrp != HRP_TESTNET {
            return Err(AddressError::UnknownHrp(hrp));
        }

        let ascii = checked.data_part_ascii_no_checksum();
        let (version_char, rest) = ascii.split_first().ok_or(AddressError::NoVersion)?;
        let version_fe =
            Fe32::from_char(char::from(*version_char)).map_err(|_| AddressError::NoVersion)?;
        let version = version_fe.to_u8();
        // Version 31 is reserved so that a future format change cannot be
        // silently misread as an address a wallet can already pay.
        if version == 31 {
            return Err(AddressError::UnknownVersion(version));
        }

        let fes: Vec<Fe32> = rest
            .iter()
            .map(|b| Fe32::from_char(char::from(*b)).expect("checked bech32 characters"))
            .collect();
        // The payload is 5 bits per character regrouped into 8. Any bits left
        // over must be zero, or two different strings would decode alike.
        let bits = fes.len() * 5;
        let payload: Vec<u8> = fes.iter().copied().fes_to_bytes().collect();
        if payload.len() * 8 + 5 <= bits {
            return Err(AddressError::NonZeroPadding);
        }
        let leftover = bits - payload.len() * 8;
        if leftover > 0 {
            let last = fes.last().copied().unwrap_or(Fe32::Q).to_u8();
            if last & ((1u8 << leftover) - 1) != 0 {
                return Err(AddressError::NonZeroPadding);
            }
        }

        match version {
            // Version 0 is exact: a longer payload means something the reader
            // does not understand, and paying it would be a guess.
            0 if payload.len() != PAYLOAD_LEN => {
                return Err(AddressError::BadPayloadLength {
                    version,
                    len: payload.len(),
                    expected: PAYLOAD_LEN,
                });
            }
            // 1 to 30 are forward-compatible: read the two keys and ignore
            // whatever follows, as BIP 352 says.
            _ if payload.len() < PAYLOAD_LEN => {
                return Err(AddressError::BadPayloadLength {
                    version,
                    len: payload.len(),
                    expected: PAYLOAD_LEN,
                });
            }
            _ => {}
        }

        let scan_key =
            PublicKey::from_slice(&payload[..33]).map_err(|_| AddressError::BadKeys)?;
        let spend_key =
            PublicKey::from_slice(&payload[33..66]).map_err(|_| AddressError::BadKeys)?;
        Ok((
            SpAddress {
                version,
                scan_key,
                spend_key,
            },
            hrp,
        ))
    }

    /// The `(scan, spend)` pair, as a `PSBT_OUT_SP_V0_INFO` value.
    pub fn to_info(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAYLOAD_LEN);
        out.extend_from_slice(&self.scan_key.serialize());
        out.extend_from_slice(&self.spend_key.serialize());
        out
    }

    /// Build a version 0 address from the two keys.
    pub fn new(scan_key: PublicKey, spend_key: PublicKey) -> Self {
        SpAddress {
            version: 0,
            scan_key,
            spend_key,
        }
    }

    /// Encode for a network.
    pub fn encode(&self, network: Network) -> String {
        self.encode_with_hrp(Self::hrp_for(network))
    }

    fn encode_with_hrp(&self, hrp: &str) -> String {
        let hrp = Hrp::parse_unchecked(hrp);
        let version = Fe32::try_from(self.version).unwrap_or(Fe32::Q);
        self.to_info()
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version)
            .chars()
            .collect()
    }

    /// Refuse anything this node cannot turn into an output. A version above 0
    /// carries fields satd does not understand, and paying it by reading only
    /// the first two keys would be guessing at what the extra data meant.
    pub fn require_v0(&self) -> Result<(), AddressError> {
        if self.version != 0 {
            return Err(AddressError::UnsupportedForCreation(self.version));
        }
        Ok(())
    }
}
