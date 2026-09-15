//! The Stratum V2 transport: a Noise NX handshake, then encrypted frames.
//!
//! Handshake (`Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256`): the miner
//! sends a 64-byte ElligatorSwift ephemeral key; the server answers with 234
//! bytes carrying its own ephemeral key, its static key and a signature over
//! it by the authority key. Both sides then hold a [`NoiseCodec`].
//!
//! After the handshake a frame is its 6-byte header (`extension_type: u16`,
//! `msg_type: u8`, `msg_length: u24`, little-endian) encrypted as one AEAD
//! chunk — 22 bytes on the wire — followed by the payload encrypted in chunks
//! of at most 65,519 plaintext bytes, each with its own 16-byte tag. There is
//! no outer length prefix.

use std::time::Duration;

use stratum_core::noise_sv2::{
    ELLSWIFT_ENCODING_SIZE, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, NoiseCodec, Responder,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::wire::is_channel_message;

/// Plaintext frame header size.
pub const HEADER_SIZE: usize = 6;
/// AEAD tag size.
pub const MAC_LEN: usize = 16;
/// Header size on the wire.
pub const ENCRYPTED_HEADER_SIZE: usize = HEADER_SIZE + MAC_LEN;
/// Largest plaintext in one encrypted payload chunk.
pub const MAX_CHUNK_PLAINTEXT: usize = 65_535 - MAC_LEN;
/// Largest payload accepted from a miner. Everything a miner sends is a few
/// dozen bytes; this bounds what a hostile peer can make the server buffer.
pub const MAX_INBOUND_PAYLOAD: usize = 1 << 16;
/// `channel_msg` bit in `extension_type`.
const CHANNEL_MSG_BIT: u16 = 0x8000;
/// How long the server's signature over its static key is valid. Miners
/// check it against their clock at handshake time.
const CERT_VALIDITY: Duration = Duration::from_secs(3600);

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise: {0}")]
    Noise(String),
    #[error("payload of {0} bytes exceeds the {MAX_INBOUND_PAYLOAD}-byte limit")]
    TooLarge(usize),
}

/// Run the responder side of the handshake.
///
/// The caller bounds this with a timeout: a miner that never sends its first
/// message must not hold a connection slot.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    authority_public: &[u8; 32],
    authority_private: &[u8; 32],
) -> Result<NoiseCodec, TransportError> {
    let mut responder =
        Responder::from_authority_kp(authority_public, authority_private, CERT_VALIDITY)
            .map_err(|e| TransportError::Noise(format!("authority key: {e:?}")))?;
    let mut initiator_msg = [0u8; ELLSWIFT_ENCODING_SIZE];
    stream.read_exact(&mut initiator_msg).await?;
    let (reply, codec) = responder
        .step_1(initiator_msg)
        .map_err(|e| TransportError::Noise(format!("handshake: {e:?}")))?;
    let reply: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] = reply;
    stream.write_all(&reply).await?;
    stream.flush().await?;
    Ok(codec)
}

/// Encrypt one message into its wire bytes.
pub fn encode_frame(
    codec: &mut NoiseCodec,
    msg_type: u8,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let len = payload.len();
    debug_assert!(len < 1 << 24, "msg_length is 24 bits");
    let chunks = len.div_ceil(MAX_CHUNK_PLAINTEXT);
    let mut out = Vec::with_capacity(ENCRYPTED_HEADER_SIZE + len + chunks * MAC_LEN);

    let extension_type: u16 = if is_channel_message(msg_type) { CHANNEL_MSG_BIT } else { 0 };
    let mut header = Vec::with_capacity(ENCRYPTED_HEADER_SIZE);
    header.extend_from_slice(&extension_type.to_le_bytes());
    header.push(msg_type);
    header.extend_from_slice(&(len as u32).to_le_bytes()[..3]);
    codec.encrypt(&mut header).map_err(|e| TransportError::Noise(format!("encrypt: {e:?}")))?;
    out.extend_from_slice(&header);

    for chunk in payload.chunks(MAX_CHUNK_PLAINTEXT) {
        let mut buf = Vec::with_capacity(chunk.len() + MAC_LEN);
        buf.extend_from_slice(chunk);
        codec.encrypt(&mut buf).map_err(|e| TransportError::Noise(format!("encrypt: {e:?}")))?;
        out.extend_from_slice(&buf);
    }
    Ok(out)
}

/// Read and decrypt one message: `(msg_type, payload)`.
///
/// Not cancel-safe: run it in a task of its own rather than in a `select!`.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    codec: &mut NoiseCodec,
) -> Result<(u8, Vec<u8>), TransportError> {
    let mut header = vec![0u8; ENCRYPTED_HEADER_SIZE];
    reader.read_exact(&mut header).await?;
    codec.decrypt(&mut header).map_err(|e| TransportError::Noise(format!("decrypt: {e:?}")))?;
    if header.len() != HEADER_SIZE {
        return Err(TransportError::Noise("decrypted header is not 6 bytes".into()));
    }
    let msg_type = header[2];
    let len = u32::from_le_bytes([header[3], header[4], header[5], 0]) as usize;
    if len > MAX_INBOUND_PAYLOAD {
        return Err(TransportError::TooLarge(len));
    }
    let mut payload = Vec::with_capacity(len);
    let mut remaining = len;
    while remaining > 0 {
        let plain = remaining.min(MAX_CHUNK_PLAINTEXT);
        let mut chunk = vec![0u8; plain + MAC_LEN];
        reader.read_exact(&mut chunk).await?;
        codec.decrypt(&mut chunk).map_err(|e| TransportError::Noise(format!("decrypt: {e:?}")))?;
        payload.extend_from_slice(&chunk);
        remaining -= plain;
    }
    Ok((msg_type, payload))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use stratum_core::noise_sv2::Initiator;

    pub(crate) fn authority() -> ([u8; 32], [u8; 32]) {
        let private = [0x11u8; 32];
        let public = super::super::authority::authority_pubkey(&private).unwrap();
        (public, private)
    }

    /// Handshake over an in-memory pipe, with the miner pinning the key.
    async fn connected_pair() -> (NoiseCodec, NoiseCodec, tokio::io::DuplexStream, tokio::io::DuplexStream) {
        let (public, private) = authority();
        let (mut server_io, mut client_io) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let codec = handshake(&mut server_io, &public, &private).await.unwrap();
            (codec, server_io)
        });
        let mut initiator = Initiator::from_raw_k(public).unwrap();
        let first = initiator.step_0().unwrap();
        client_io.write_all(&first).await.unwrap();
        let mut reply = [0u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
        client_io.read_exact(&mut reply).await.unwrap();
        let client_codec = initiator.step_2(reply).expect("the pinned key verifies");
        let (server_codec, server_io) = server.await.unwrap();
        (server_codec, client_codec, server_io, client_io)
    }

    #[tokio::test]
    async fn frames_round_trip_both_ways_across_a_real_handshake() {
        let (mut server, mut client, mut server_io, mut client_io) = connected_pair().await;
        for payload in [Vec::new(), (0u8..42).collect(), vec![7u8; MAX_INBOUND_PAYLOAD]] {
            let wire = encode_frame(&mut server, super::super::wire::SET_TARGET, &payload).unwrap();
            let chunks = payload.len().div_ceil(MAX_CHUNK_PLAINTEXT);
            assert_eq!(wire.len(), ENCRYPTED_HEADER_SIZE + payload.len() + chunks * MAC_LEN);
            server_io.write_all(&wire).await.unwrap();
            let (t, p) = read_frame(&mut client_io, &mut client).await.unwrap();
            assert_eq!(t, super::super::wire::SET_TARGET);
            assert_eq!(p, payload);
        }
        // A payload past the inbound limit is refused before it is buffered.
        let wire = encode_frame(&mut server, super::super::wire::SET_TARGET, &vec![0u8; MAX_INBOUND_PAYLOAD + 1]).unwrap();
        server_io.write_all(&wire).await.unwrap();
        assert!(matches!(read_frame(&mut client_io, &mut client).await, Err(TransportError::TooLarge(_))));
        let (mut server, mut client, mut server_io, mut client_io) = connected_pair().await;
        let wire = encode_frame(&mut client, super::super::wire::SETUP_CONNECTION, b"hello").unwrap();
        client_io.write_all(&wire).await.unwrap();
        let (t, p) = read_frame(&mut server_io, &mut server).await.unwrap();
        assert_eq!((t, p.as_slice()), (super::super::wire::SETUP_CONNECTION, &b"hello"[..]));
    }

    #[tokio::test]
    async fn a_miner_pinning_another_key_refuses_the_handshake() {
        let (public, private) = authority();
        let (mut server_io, mut client_io) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let _ = handshake(&mut server_io, &public, &private).await;
        });
        let other = super::super::authority::authority_pubkey(&[0x22u8; 32]).unwrap();
        let mut initiator = Initiator::from_raw_k(other).unwrap();
        client_io.write_all(&initiator.step_0().unwrap()).await.unwrap();
        let mut reply = [0u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
        client_io.read_exact(&mut reply).await.unwrap();
        assert!(initiator.step_2(reply).is_err());
    }

    #[test]
    fn channel_messages_carry_the_channel_bit() {
        let (mut server, mut client) = {
            let (public, private) = authority();
            let mut responder = Responder::from_authority_kp(&public, &private, CERT_VALIDITY).unwrap();
            let mut initiator = Initiator::without_pk().unwrap();
            let (reply, server) = responder.step_1(initiator.step_0().unwrap()).unwrap();
            (server, initiator.step_2(reply).unwrap())
        };
        for (msg_type, bit) in [
            (super::super::wire::SET_NEW_PREV_HASH, CHANNEL_MSG_BIT),
            (super::super::wire::OPEN_STANDARD_MINING_CHANNEL_SUCCESS, 0),
        ] {
            let wire = encode_frame(&mut server, msg_type, &[1, 2, 3]).unwrap();
            let mut header = wire[..ENCRYPTED_HEADER_SIZE].to_vec();
            client.decrypt(&mut header).unwrap();
            assert_eq!(u16::from_le_bytes([header[0], header[1]]), bit);
            let mut rest = wire[ENCRYPTED_HEADER_SIZE..].to_vec();
            client.decrypt(&mut rest).unwrap();
        }
    }
}
