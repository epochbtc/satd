//! Bitcoin Core's message signing: `verifymessage` and
//! `signmessagewithprivkey`.
//!
//! A port of `src/common/signmessage.cpp` and `src/rpc/signmessage.cpp` at
//! Core v31.1. The format is the legacy one BIP322 keeps for P2PKH: a 65-byte
//! compact recoverable ECDSA signature over
//! `SHA256d(compact_size("Bitcoin Signed Message:\n") || compact_size(msg) || msg)`,
//! base64-encoded, whose first byte carries the recovery id and whether the
//! key is compressed.
//!
//! The parsing is Core's, not `rust-bitcoin`'s, in the two places they
//! differ. Core decodes base64 strictly (`DecodeBase64`), and reads the header
//! byte as `(header - 27) & 3` and `& 4` in `int` arithmetic, so a header
//! below 27 still yields a recovery id; `MessageSignature::from_slice` refuses
//! those. A signature only Core accepts would otherwise verify on Core and not
//! here.

use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::{Network, NetworkKind, PrivateKey, PublicKey};

use crate::rpc::address_decode::{Decoded, decode_destination};

/// Core's `COMPACT_SIGNATURE_SIZE`.
const COMPACT_SIGNATURE_SIZE: usize = 65;

/// The longest string Core's `DecodeSecret` can accept: it calls
/// `DecodeBase58Check(str, data, 34)`, and 34 payload bytes plus the 4-byte
/// checksum need at most ceil(38 * 8 / log2(58)) = 52 Base58 characters.
/// `rust-bitcoin`'s Base58 decoder has no cap and is quadratic in the input
/// length (see `address_decode::decode_destination`), so anything longer is
/// refused before it is decoded. Core answers such a string "Invalid private
/// key" as well.
const MAX_WIF_LEN: usize = 60;

/// Core's `MessageVerificationResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageVerificationResult {
    /// The address is not a valid destination on this network.
    InvalidAddress,
    /// The address is valid but is not P2PKH.
    AddressNoKey,
    /// The signature is not valid base64.
    MalformedSignature,
    /// No public key could be recovered from the signature.
    PubkeyNotRecovered,
    /// A key was recovered, but it is not the address's key.
    NotSigned,
    /// The message was signed by the address's key.
    Ok,
}

/// Core's `MessageHash`: double SHA256 over the magic and the message, each
/// serialized with its compact-size length.
pub fn message_hash(message: &str) -> [u8; 32] {
    bitcoin::sign_message::signed_msg_hash(message).to_byte_array()
}

/// Core's `DecodeBase64` (`src/util/strencodings.cpp`): the length must be a
/// multiple of four, at most two trailing `=` are stripped, every remaining
/// character must be in the standard alphabet, and the leftover bits must be
/// fewer than six and all zero.
pub fn decode_base64(s: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let mut bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    for _ in 0..2 {
        if let Some((&b'=', rest)) = bytes.split_last() {
            bytes = rest;
        }
    }

    // `ConvertBits<6, 8, false>`.
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for &c in bytes {
        acc = ((acc << 6) | value(c)?) & 0x1fff;
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 6 || (acc << (8 - bits)) & 0xff != 0 {
        return None;
    }
    Some(out)
}

/// Core's `CPubKey::RecoverCompact`: the public key that made `sig` over
/// `hash`, or `None` if the signature does not parse or recover.
pub fn recover_compact(hash: &[u8; 32], sig: &[u8]) -> Option<PublicKey> {
    if sig.len() != COMPACT_SIGNATURE_SIZE {
        return None;
    }
    // `int recid = (vchSig[0] - 27) & 3; bool fComp = ((vchSig[0] - 27) & 4) != 0;`
    // `vchSig[0]` is promoted to `int`, so a header below 27 goes negative
    // and the masks act on its two's-complement form.
    let header = i32::from(sig[0]) - 27;
    let recid = RecoveryId::from_i32(header & 3).ok()?;
    let compressed = header & 4 != 0;
    let sig = RecoverableSignature::from_compact(&sig[1..], recid).ok()?;
    let secp = Secp256k1::verification_only();
    let key = secp.recover_ecdsa(&Message::from_digest(*hash), &sig).ok()?;
    Some(PublicKey { compressed, inner: key })
}

/// Core's `MessageVerify`.
pub fn message_verify(
    address: &str,
    signature: &str,
    message: &str,
    network: Network,
) -> MessageVerificationResult {
    let address = match decode_destination(address, network) {
        Decoded::Valid(a) => a,
        Decoded::Invalid { .. } => return MessageVerificationResult::InvalidAddress,
    };
    let bitcoin::address::AddressData::P2pkh { pubkey_hash } = address.to_address_data() else {
        return MessageVerificationResult::AddressNoKey;
    };
    let Some(sig) = decode_base64(signature) else {
        return MessageVerificationResult::MalformedSignature;
    };
    match recover_compact(&message_hash(message), &sig) {
        None => MessageVerificationResult::PubkeyNotRecovered,
        Some(key) if key.pubkey_hash() == pubkey_hash => MessageVerificationResult::Ok,
        Some(_) => MessageVerificationResult::NotSigned,
    }
}

/// Core's `DecodeSecret`: a WIF key for this network, or `None`.
///
/// `rust-bitcoin` accepts either network's version byte; Core accepts only
/// the one for the chain it runs, so a mainnet key on regtest is invalid.
pub fn decode_secret(wif: &str, network: Network) -> Option<PrivateKey> {
    if wif.len() > MAX_WIF_LEN {
        return None;
    }
    let key = PrivateKey::from_wif(wif).ok()?;
    (key.network == NetworkKind::from(network)).then_some(key)
}

/// Core's `MessageSign`: the base64 compact signature of `message` by `key`.
///
/// Core's `CKey::SignCompact` signs with RFC6979 nonces and no extra entropy,
/// as `sign_ecdsa_recoverable` does, so the signature is deterministic and
/// byte-identical to Core's.
pub fn message_sign(key: &PrivateKey, message: &str) -> String {
    use base64::Engine as _;
    let secp = Secp256k1::signing_only();
    let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(message_hash(message)), &key.inner);
    let (recid, compact) = sig.serialize_compact();
    let mut out = [0u8; COMPACT_SIGNATURE_SIZE];
    out[0] = 27 + recid.to_i32() as u8 + if key.compressed { 4 } else { 0 };
    out[1..].copy_from_slice(&compact);
    base64::engine::general_purpose::STANDARD.encode(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `rpc_signmessagewithprivkey.py` (Core v31.1).
    const CORE_KEY: &str = "cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N";
    const CORE_MESSAGE: &str = "This is just a test message";
    const CORE_SIGNATURE: &str =
        "INbVnW4e6PeRmsv2Qgu8NuopvrVjkcxob+sX8OcZG0SALhWybUjzMLPdAsXI46YZGb0KQTRii+wWIQzRpG/U+S0=";
    const CORE_ADDRESS: &str = "mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB";

    #[test]
    fn signs_core_functional_vector_byte_for_byte() {
        let key = decode_secret(CORE_KEY, Network::Regtest).unwrap();
        assert_eq!(message_sign(&key, CORE_MESSAGE), CORE_SIGNATURE);
    }

    #[test]
    fn verifies_core_functional_vector() {
        assert_eq!(
            message_verify(CORE_ADDRESS, CORE_SIGNATURE, CORE_MESSAGE, Network::Regtest),
            MessageVerificationResult::Ok
        );
        assert_eq!(
            message_verify(CORE_ADDRESS, CORE_SIGNATURE, "another message", Network::Regtest),
            MessageVerificationResult::NotSigned
        );
    }

    /// Core's `message_verify` unit test (`src/test/util_tests.cpp`), which
    /// runs on mainnet parameters.
    #[test]
    fn core_util_tests_message_verify() {
        let net = Network::Bitcoin;
        assert_eq!(
            message_verify("invalid address", "signature should be irrelevant", "message too", net),
            MessageVerificationResult::InvalidAddress
        );
        assert_eq!(
            message_verify(
                "3B5fQsEXEaV8v6U3ejYc8XaKXAkyQj2MjV",
                "signature should be irrelevant",
                "message too",
                net
            ),
            MessageVerificationResult::AddressNoKey
        );
        assert_eq!(
            message_verify(
                "1KqbBpLy5FARmTPD4VZnDDpYjkUvkr82Pm",
                "invalid signature, not in base64 encoding",
                "message should be irrelevant",
                net
            ),
            MessageVerificationResult::MalformedSignature
        );
        assert_eq!(
            message_verify(
                "1KqbBpLy5FARmTPD4VZnDDpYjkUvkr82Pm",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "message should be irrelevant",
                net
            ),
            MessageVerificationResult::PubkeyNotRecovered
        );
        assert_eq!(
            message_verify(
                "15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs",
                "IPojfrX2dfPnH26UegfbGQQLrdK844DlHq5157/P6h57WyuS/Qsl+h/WSVGDF4MUi4rWSswW38oimDYfNNUBUOk=",
                "I never signed this",
                net
            ),
            MessageVerificationResult::NotSigned
        );
        assert_eq!(
            message_verify(
                "15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs",
                "IPojfrX2dfPnH26UegfbGQQLrdK844DlHq5157/P6h57WyuS/Qsl+h/WSVGDF4MUi4rWSswW38oimDYfNNUBUOk=",
                "Trust no one",
                net
            ),
            MessageVerificationResult::Ok
        );
        assert_eq!(
            message_verify(
                "11canuhp9X2NocwCq7xNrQYTmUgZAnLK3",
                "IIcaIENoYW5jZWxsb3Igb24gYnJpbmsgb2Ygc2Vjb25kIGJhaWxvdXQgZm9yIGJhbmtzIAaHRtbCeDZINyavx14=",
                "Trust me",
                net
            ),
            MessageVerificationResult::Ok
        );
    }

    /// Core's `message_hash` unit test: the magic and the message, each
    /// prefixed by its one-byte compact size, double-SHA256'd.
    #[test]
    fn message_hash_is_cores() {
        use bitcoin::hashes::sha256d;
        let magic = "Bitcoin Signed Message:\n";
        let msg = "...";
        let mut prefixed = vec![magic.len() as u8];
        prefixed.extend_from_slice(magic.as_bytes());
        prefixed.push(msg.len() as u8);
        prefixed.extend_from_slice(msg.as_bytes());
        assert_eq!(message_hash(msg), sha256d::Hash::hash(&prefixed).to_byte_array());
        assert_ne!(message_hash(msg), sha256d::Hash::hash(msg.as_bytes()).to_byte_array());
    }

    #[test]
    fn base64_matches_core_strictness() {
        assert_eq!(decode_base64(""), Some(vec![]));
        assert_eq!(decode_base64("Zm9v"), Some(b"foo".to_vec()));
        assert_eq!(decode_base64("Zm8="), Some(b"fo".to_vec()));
        assert_eq!(decode_base64("Zg=="), Some(b"f".to_vec()));
        // Length not a multiple of four, unpadded.
        assert_eq!(decode_base64("Zm8"), None);
        // Non-zero leftover bits ("Zh==" decodes to 'f' plus a stray bit).
        assert_eq!(decode_base64("Zh=="), None);
        // Only two '=' are stripped: "Z===" leaves "Z=", and '=' is not in
        // the alphabet.
        assert_eq!(decode_base64("Z==="), None);
        // Whitespace and URL-safe characters are not in Core's table.
        assert_eq!(decode_base64("Zm9v Zm9v"), None);
        assert_eq!(decode_base64("Zm9-"), None);
    }

    /// A header byte below 27 still yields a recovery id in Core's `int`
    /// arithmetic; `rust-bitcoin`'s parser refuses it.
    #[test]
    fn header_below_27_recovers_as_core_does() {
        let key = decode_secret(CORE_KEY, Network::Regtest).unwrap();
        let mut sig = decode_base64(&message_sign(&key, CORE_MESSAGE)).unwrap();
        let header = i32::from(sig[0]) - 27;
        // A compressed key's header is 31..=34. Eight lower keeps the low
        // three bits of (h - 27), so the same recovery id and compression
        // flag, but puts the header below 27.
        sig[0] -= 8;
        assert!(sig[0] < 27);
        assert_eq!((i32::from(sig[0]) - 27) & 7, header & 7);
        assert!(bitcoin::sign_message::MessageSignature::from_slice(&sig).is_err());
        let recovered = recover_compact(&message_hash(CORE_MESSAGE), &sig).unwrap();
        assert_eq!(recovered, key.public_key(&Secp256k1::new()));
    }

    #[test]
    fn decode_secret_checks_network_and_length() {
        assert!(decode_secret(CORE_KEY, Network::Regtest).is_some());
        assert!(decode_secret(CORE_KEY, Network::Signet).is_some());
        assert!(decode_secret(CORE_KEY, Network::Bitcoin).is_none());
        assert!(decode_secret("invalid_key", Network::Regtest).is_none());
        assert!(decode_secret(&"1".repeat(10_000), Network::Regtest).is_none());
    }
}
