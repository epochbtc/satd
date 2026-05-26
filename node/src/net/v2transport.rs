//! BIP 324 v2 encrypted P2P transport.
//!
//! This module holds the v2 side of the transport seam introduced in
//! `connection.rs`. The types below are the encrypted counterparts of
//! `V1Connection` / `V1Reader` / `V1Writer`: once the v2 handshake
//! (ElligatorSwift ECDH + key derivation) has run on the raw socket, the
//! resulting cipher session is wrapped here so the rest of the peer
//! pipeline continues to speak `NetworkMessage` without knowing the link
//! is encrypted.
//!
//! The v2 wire protocol and cryptography are provided by the rust-bitcoin
//! [`bip324`] crate (same `bitcoin 0.32` / `secp256k1 0.29` it shares with
//! the rest of satd). This module wraps that crate rather than
//! reimplementing the ElligatorSwift handshake, the garbage/decoy dance,
//! or the ChaCha20-Poly1305 packet cipher.
//!
//! What lands here in this PR: the `NetworkMessage` ⇄ BIP 324 packet
//! "contents" codec ([`encode_message`] / [`decode_message`]) plus tests
//! that pin the BIP 324 short-ID mapping and exercise a full in-memory
//! handshake to an encrypted round-trip. The handshake-driving and the
//! `Connection` enum wiring (the `unimplemented!()` stubs below) are
//! filled in by later PRs of the v2 stack.

use bitcoin::p2p::message::NetworkMessage;
use std::io;

/// Errors from the v2 message codec.
#[derive(Debug, thiserror::Error)]
pub enum V2CodecError {
    /// The decrypted packet contents were too short to hold a v2 message.
    #[error("v2 message buffer truncated")]
    Truncated,
    /// The BIP 324 deserializer rejected the contents (bad short ID or
    /// malformed payload).
    #[error("v2 message deserialization failed: {0}")]
    Deserialize(String),
}

/// Encode a [`NetworkMessage`] into BIP 324 v2 packet "contents".
///
/// The result is the plaintext that gets sealed by the packet cipher — a
/// 1-byte short message-type ID (or a zero byte followed by the 12-byte
/// ASCII command for the unoptimized message types) followed by the
/// consensus-encoded payload. This is *not* yet a wire packet; the cipher
/// adds the length prefix, header byte, and authentication tag.
pub fn encode_message(msg: NetworkMessage) -> Vec<u8> {
    bip324::serde::serialize(msg)
}

/// Decode BIP 324 v2 packet "contents" back into a [`NetworkMessage`].
///
/// `contents` is the decrypted packet payload with the leading protocol
/// header byte already stripped (i.e. what the peer passed to
/// [`encode_message`]).
pub fn decode_message(contents: &[u8]) -> Result<NetworkMessage, V2CodecError> {
    // Guard the two indexing paths in `bip324::serde::deserialize` that
    // assume a minimum length (it reads `buffer[0]`, and for the zero-byte
    // command form reads `buffer[1..13]`). Decrypted-and-authenticated
    // bytes can still be truncated/garbage, so fail closed rather than
    // panic.
    if contents.is_empty() || (contents[0] == 0 && contents.len() < 13) {
        return Err(V2CodecError::Truncated);
    }
    bip324::serde::deserialize(contents).map_err(|e| V2CodecError::Deserialize(e.to_string()))
}

/// Encrypted v2 P2P connection (pre-split).
pub struct V2Connection;

/// Read half of a split [`V2Connection`].
pub struct V2Reader;

/// Write half of a split [`V2Connection`].
pub struct V2Writer;

impl V2Connection {
    /// Split into separate read and write halves.
    pub fn split(self) -> (V2Reader, V2Writer) {
        unimplemented!("BIP 324 v2 transport — wired in a later PR of the v2 stack")
    }

    /// Send a network message over the encrypted channel.
    pub async fn send(&mut self, _msg: NetworkMessage) -> io::Result<()> {
        unimplemented!("BIP 324 v2 transport — wired in a later PR of the v2 stack")
    }

    /// Receive the next network message from the encrypted channel.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        unimplemented!("BIP 324 v2 transport — wired in a later PR of the v2 stack")
    }

    /// Get the peer's remote address.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        unimplemented!("BIP 324 v2 transport — wired in a later PR of the v2 stack")
    }
}

impl V2Writer {
    /// Send a network message over the encrypted channel.
    pub async fn send(&mut self, _msg: NetworkMessage) -> io::Result<()> {
        unimplemented!("BIP 324 v2 transport — wired in a later PR of the v2 stack")
    }
}

impl V2Reader {
    /// Receive the next network message from the encrypted channel.
    ///
    /// As with [`V1Reader`](crate::net::connection), this must NOT be used
    /// inside `tokio::select!` — it is not cancel-safe.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        unimplemented!("BIP 324 v2 transport — wired in a later PR of the v2 stack")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip324::{
        CipherSession, GarbageResult, Handshake, Initialized, PacketType, ReceivedKey, Role,
        VersionResult,
    };
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::Network;

    /// The 1-byte short IDs are defined by BIP 324. Pin a representative
    /// set so a future `bip324` bump that changed the mapping would fail
    /// here rather than silently break wire compatibility.
    #[test]
    fn short_ids_match_bip324() {
        assert_eq!(encode_message(NetworkMessage::Ping(0))[0], 18);
        assert_eq!(encode_message(NetworkMessage::Pong(0))[0], 19);
        assert_eq!(encode_message(NetworkMessage::FeeFilter(0))[0], 5);
        assert_eq!(encode_message(NetworkMessage::MemPool)[0], 15);
        assert_eq!(encode_message(NetworkMessage::FilterClear)[0], 7);
        // Unoptimized types use the zero-byte + 12-ASCII-command form.
        assert_eq!(encode_message(NetworkMessage::Verack)[0], 0);
        assert_eq!(encode_message(NetworkMessage::SendHeaders)[0], 0);
    }

    #[test]
    fn codec_round_trips_messages() {
        let cases = vec![
            NetworkMessage::Ping(0xdead_beef),
            NetworkMessage::Pong(0x0102_0304),
            NetworkMessage::Verack,
            NetworkMessage::SendHeaders,
            NetworkMessage::GetAddr,
            NetworkMessage::SendAddrV2,
            NetworkMessage::FeeFilter(1234),
            NetworkMessage::MemPool,
            NetworkMessage::FilterClear,
        ];
        for msg in cases {
            let encoded = encode_message(msg.clone());
            let decoded = decode_message(&encoded).expect("decode");
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn decode_rejects_truncated_contents() {
        assert!(matches!(decode_message(&[]), Err(V2CodecError::Truncated)));
        // Zero-byte command form requires at least 13 bytes.
        assert!(matches!(
            decode_message(&[0u8, 1, 2]),
            Err(V2CodecError::Truncated)
        ));
    }

    /// Drive a `Handshake<SentVersion>` to completion against a remote's
    /// post-key byte stream (garbage terminator + version packet, no
    /// garbage or decoys). Mirrors the reference driver in
    /// `bip324::io::handshake_with_initialized`.
    fn complete_handshake(
        hs: Handshake<bip324::SentVersion>,
        remote_stream: &[u8],
    ) -> CipherSession {
        let (mut hs, consumed) = match hs.receive_garbage(remote_stream).expect("garbage") {
            GarbageResult::FoundGarbage {
                handshake,
                consumed_bytes,
            } => (handshake, consumed_bytes),
            GarbageResult::NeedMoreData(_) => panic!("unexpected NeedMoreData with no garbage"),
        };
        let mut rest = &remote_stream[consumed..];
        loop {
            let mut len_bytes = [0u8; 3];
            len_bytes.copy_from_slice(&rest[..3]);
            let packet_len = hs.decrypt_packet_len(len_bytes).expect("packet len");
            let mut packet = rest[3..3 + packet_len].to_vec();
            rest = &rest[3 + packet_len..];
            match hs.receive_version(&mut packet).expect("version") {
                VersionResult::Complete { cipher } => return cipher,
                VersionResult::Decoy(h) => hs = h,
            }
        }
    }

    #[test]
    fn full_handshake_and_encrypted_round_trip() {
        let net = Network::Bitcoin;
        let init = Handshake::new(net, Role::Initiator).expect("init handshake");
        let resp = Handshake::new(net, Role::Responder).expect("resp handshake");

        // Exchange ElligatorSwift public keys (no garbage).
        let mut init_key = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
        let init = init.send_key(None, &mut init_key).expect("init send_key");
        let mut resp_key = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
        let resp = resp.send_key(None, &mut resp_key).expect("resp send_key");

        let init = init
            .receive_key(resp_key[..64].try_into().unwrap())
            .expect("init receive_key");
        let resp = resp
            .receive_key(init_key[..64].try_into().unwrap())
            .expect("resp receive_key");

        // Send garbage terminator + version packet (no decoys).
        let mut init_ver = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
        let init = init.send_version(&mut init_ver, None).expect("init version");
        let mut resp_ver = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
        let resp = resp.send_version(&mut resp_ver, None).expect("resp version");

        let init_cipher = complete_handshake(init, &resp_ver);
        let resp_cipher = complete_handshake(resp, &init_ver);

        // Both ends derived the same session.
        assert_eq!(init_cipher.id(), resp_cipher.id());

        // Initiator → responder: encode, encrypt, decrypt, decode.
        let (_init_in, mut init_out) = init_cipher.into_split();
        let (mut resp_in, _resp_out) = resp_cipher.into_split();

        let msg = NetworkMessage::Ping(0x1234_5678_9abc_def0);
        let contents = encode_message(msg.clone());
        let packet = init_out.encrypt_to_vec(&contents, PacketType::Genuine, None);

        let mut len_bytes = [0u8; 3];
        len_bytes.copy_from_slice(&packet[..3]);
        let packet_len = resp_in.decrypt_packet_len(len_bytes);
        let (ptype, plaintext) = resp_in
            .decrypt_to_vec(&packet[3..3 + packet_len], None)
            .expect("decrypt");
        assert_eq!(ptype, PacketType::Genuine);

        // The decrypted buffer leads with the protocol header byte; the v2
        // message contents follow.
        let decoded = decode_message(&plaintext[1..]).expect("decode");
        assert_eq!(decoded, msg);
    }
}
