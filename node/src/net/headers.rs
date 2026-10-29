//! `headers` payloads, read the way Bitcoin Core reads them.
//!
//! Each 80-byte header in a `headers` message is followed by a transaction
//! count, left over from the message once carrying blocks. Core reads it as
//! a CompactSize and ignores the value (`src/net_processing.cpp:4747`,
//! "ignore tx count; assume it is 0").
//!
//! rust-bitcoin's `HeaderDeserializationWrapper`, and the `bip324` crate's
//! copy of it for v2 connections, read the count as one byte and refuse the
//! whole message when it is not zero ("Headers message should not contain
//! transactions"). Peers on the network send non-zero counts, and every
//! header announcement in such a message was lost. A count written as a
//! multi-byte CompactSize (`fd ...`) would also misalign their reader.
//!
//! [`decode_payload`] mirrors Core's loop: a CompactSize header count, then
//! per header the 80 bytes and a CompactSize read and dropped. Both
//! CompactSizes are read as Core's `ReadCompactSize` reads them, so a
//! non-canonical encoding or a value above `MAX_SIZE` is refused, as is a
//! truncated payload.

use bitcoin::block::Header;
use bitcoin::consensus::encode::{self, Decodable, VarInt};
use bitcoin::hashes::{sha256d, Hash};

/// The `headers` command as it sits in a v1 header and in a v2 long-form
/// message type: ASCII, NUL-padded to 12 bytes.
pub const HEADERS_COMMAND: [u8; 12] = *b"headers\0\0\0\0\0";

/// The smallest encoded entry: an 80-byte header and a 1-byte tx count.
/// Bounds the up-front allocation by the bytes actually present.
const MIN_ENTRY_LEN: usize = 81;

/// Why a `headers` payload could not be read.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeadersDecodeError {
    #[error("headers payload truncated")]
    Truncated,
    #[error("non-canonical CompactSize")]
    NonCanonicalCompactSize,
    #[error("CompactSize exceeds MAX_SIZE")]
    SizeTooLarge,
    #[error("v1 checksum mismatch")]
    BadChecksum,
    #[error("headers payload malformed: {0}")]
    Malformed(String),
}

impl From<encode::Error> for HeadersDecodeError {
    fn from(e: encode::Error) -> Self {
        // rust-bitcoin's `VarInt` decoder is Core's `ReadCompactSize` with
        // the range check: canonical form, and at most `MAX_SIZE`
        // (`MAX_COMPACT_SIZE`). Reading from a slice, an I/O error can only
        // be running out of bytes.
        match e {
            encode::Error::Io(_) => HeadersDecodeError::Truncated,
            encode::Error::NonMinimalVarInt => HeadersDecodeError::NonCanonicalCompactSize,
            encode::Error::OversizedVarInt => HeadersDecodeError::SizeTooLarge,
            other => HeadersDecodeError::Malformed(other.to_string()),
        }
    }
}

/// Decode a `headers` message payload (the bytes after the v1 header or the
/// v2 message type). Bytes past the last entry are ignored, as Core ignores
/// them.
///
/// The header count is not capped here: the message handler refuses more
/// than `MAX_HEADERS_RESULTS` with a misbehavior score, and the transport's
/// message size limit bounds the work.
pub fn decode_payload(payload: &[u8]) -> Result<Vec<Header>, HeadersDecodeError> {
    let mut r = payload;
    let count = VarInt::consensus_decode(&mut r)?.0;
    let mut out = Vec::with_capacity((count as usize).min(payload.len() / MIN_ENTRY_LEN));
    for _ in 0..count {
        out.push(Header::consensus_decode(&mut r)?);
        // The tx count: read as a CompactSize and ignored, as Core does.
        VarInt::consensus_decode(&mut r)?;
    }
    Ok(out)
}

/// Check a v1 frame's checksum (`header[20..24]`) and decode its payload.
/// Core drops a frame whose checksum does not match (`V1Transport`,
/// `src/net.cpp:826`).
pub fn decode_v1_payload(header: &[u8], payload: &[u8]) -> Result<Vec<Header>, HeadersDecodeError> {
    if sha256d::Hash::hash(payload)[..4] != header[20..24] {
        return Err(HeadersDecodeError::BadChecksum);
    }
    decode_payload(payload)
}

/// A `headers` payload of the given headers, each followed by the raw tx
/// count bytes in `tx_counts`. Built by hand: rust-bitcoin's encoder always
/// writes a zero count. For the transport tests.
#[cfg(test)]
pub(crate) fn payload_with_tx_counts(headers: &[Header], tx_counts: &[&[u8]]) -> Vec<u8> {
    assert_eq!(headers.len(), tx_counts.len());
    let mut v = encode::serialize(&VarInt(headers.len() as u64));
    for (h, count) in headers.iter().zip(tx_counts) {
        v.extend(encode::serialize(h));
        v.extend_from_slice(count);
    }
    v
}

/// Two distinct headers, for the tests: regtest genesis and a copy with a
/// different nonce.
#[cfg(test)]
pub(crate) fn test_headers() -> [Header; 2] {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header;
    let mut other = genesis;
    other.nonce ^= 1;
    [genesis, other]
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
    use bitcoin::p2p::Magic;

    /// A regtest v1 `headers` frame around `payload`.
    fn v1_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Magic::REGTEST.to_bytes().to_vec();
        frame.extend_from_slice(&HEADERS_COMMAND);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&sha256d::Hash::hash(payload)[..4]);
        frame.extend_from_slice(payload);
        frame
    }

    /// The defect: a non-zero tx count after a header made rust-bitcoin
    /// refuse the whole message. Core reads any canonical CompactSize there,
    /// including the multi-byte forms, and so must we.
    #[test]
    fn a_nonzero_tx_count_is_read_and_ignored() {
        let hs = test_headers();
        for count in [&[0x01][..], &[0xfc], &[0xfd, 0x00, 0x01], &[0xfe, 0x00, 0x00, 0x01, 0x00]] {
            let p = payload_with_tx_counts(&hs, &[&[0x00], count]);
            assert_eq!(decode_payload(&p).unwrap(), hs, "tx count {count:02x?}");
            // In the first entry too, where a misread count shifts the next
            // header.
            let p = payload_with_tx_counts(&hs, &[count, &[0x00]]);
            assert_eq!(decode_payload(&p).unwrap(), hs, "tx count {count:02x?} first");
        }
        let p = payload_with_tx_counts(&hs, &[&[0x01], &[0x00]]);
        assert!(
            bitcoin::consensus::deserialize::<RawNetworkMessage>(&v1_frame(&p)).is_err(),
            "rust-bitcoin refuses this payload; if it stops refusing, this module can go"
        );
    }

    /// Whatever rust-bitcoin writes, we read the same.
    #[test]
    fn agrees_with_rust_bitcoin_on_zero_counts() {
        let hs = test_headers().to_vec();
        let frame = encode::serialize(&RawNetworkMessage::new(Magic::REGTEST, NetworkMessage::Headers(hs.clone())));
        assert_eq!(frame, v1_frame(&payload_with_tx_counts(&hs, &[&[0x00], &[0x00]])));
        assert_eq!(decode_v1_payload(&frame[..24], &frame[24..]).unwrap(), hs);
        assert_eq!(decode_payload(&[0x00]).unwrap(), vec![]);
    }

    /// More than `MAX_HEADERS_RESULTS` still decodes, so the message
    /// handler sees the count and scores the peer, as before.
    #[test]
    fn a_count_over_max_headers_results_still_decodes() {
        let n = crate::net::limits::MAX_HEADERS_RESULTS + 1;
        let h = test_headers()[0];
        let p = payload_with_tx_counts(&vec![h; n], &vec![&[0x00][..]; n]);
        assert_eq!(decode_payload(&p).unwrap().len(), n);
    }

    /// What Core refuses, we refuse.
    #[test]
    fn refuses_what_core_refuses() {
        let hs = test_headers();
        // A non-canonical tx count (Core's `ReadCompactSize` throws).
        let p = payload_with_tx_counts(&hs, &[&[0x00], &[0xfd, 0x01, 0x00]]);
        assert_eq!(decode_payload(&p), Err(HeadersDecodeError::NonCanonicalCompactSize));
        // A tx count past MAX_SIZE (range-checked by default in Core).
        let p = payload_with_tx_counts(&hs, &[&[0x00], &[0xfe, 0x01, 0x00, 0x00, 0x02]]);
        assert_eq!(decode_payload(&p), Err(HeadersDecodeError::SizeTooLarge));
        // A non-canonical header count.
        let mut p = payload_with_tx_counts(&hs, &[&[0x00], &[0x00]]);
        p.splice(0..1, [0xfd, 0x02, 0x00]);
        assert_eq!(decode_payload(&p), Err(HeadersDecodeError::NonCanonicalCompactSize));
        // A header count past MAX_SIZE.
        assert_eq!(
            decode_payload(&[0xfe, 0x01, 0x00, 0x00, 0x02]),
            Err(HeadersDecodeError::SizeTooLarge)
        );
        // Truncated: in a header, in a multi-byte tx count, and a count
        // promising more entries than are present.
        let p = payload_with_tx_counts(&hs, &[&[0x00], &[0x00]]);
        assert_eq!(decode_payload(&p[..p.len() - 2]), Err(HeadersDecodeError::Truncated));
        let p = payload_with_tx_counts(&hs, &[&[0x00], &[0xfd, 0x00, 0x01]]);
        assert_eq!(decode_payload(&p[..p.len() - 1]), Err(HeadersDecodeError::Truncated));
        let p = payload_with_tx_counts(&hs, &[&[0x00], &[0x00]]);
        assert_eq!(decode_payload(&p[..p.len() - 1]), Err(HeadersDecodeError::Truncated));
        assert_eq!(decode_payload(&[]), Err(HeadersDecodeError::Truncated));
    }

    #[test]
    fn v1_payload_needs_its_checksum() {
        let hs = test_headers();
        let p = payload_with_tx_counts(&hs, &[&[0x01], &[0xfd, 0x00, 0x01]]);
        let mut header = [0u8; 24];
        header[20..24].copy_from_slice(&sha256d::Hash::hash(&p)[..4]);
        assert_eq!(decode_v1_payload(&header, &p).unwrap(), hs);
        header[20] ^= 1;
        assert_eq!(decode_v1_payload(&header, &p), Err(HeadersDecodeError::BadChecksum));
    }
}
