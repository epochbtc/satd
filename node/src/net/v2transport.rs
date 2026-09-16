//! BIP 324 v2 encrypted P2P transport.
//!
//! This module holds the v2 side of the transport seam introduced in
//! `connection.rs`. The types here are the encrypted counterparts of
//! `V1Connection` / `V1Reader` / `V1Writer`: once the v2 handshake
//! (ElligatorSwift ECDH + key derivation) has run on the raw socket, the
//! resulting [`bip324::CipherSession`] is wrapped so the rest of the peer
//! pipeline continues to speak `NetworkMessage` without knowing the link
//! is encrypted.
//!
//! The v2 wire protocol and cryptography are provided by the rust-bitcoin
//! [`bip324`] crate (same `bitcoin 0.32` / `secp256k1 0.29` it shares with
//! the rest of satd). This module wraps that crate rather than
//! reimplementing the ElligatorSwift handshake, the garbage/decoy dance,
//! or the ChaCha20-Poly1305 packet cipher.
//!
//! The handshake driver ([`responder_handshake`] / [`initiator_handshake`])
//! is a tokio port of the crate's synchronous `bip324::io` reference
//! driver. As of this PR only the responder (inbound) path is wired into
//! the peer manager; the initiator (outbound) path and the operator
//! toggles follow in later PRs of the v2 stack.

use bitcoin::p2p::message::NetworkMessage;
use bitcoin::Network;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use crate::net::stats::PeerStats;

use bip324::{
    CipherSession, GarbageResult, Handshake, InboundCipher, Initialized, OutboundCipher, PacketType,
    ReceivedKey, Role, VersionResult,
};

/// Length of an ElligatorSwift public key in bytes.
const ELLSWIFT_KEY_LEN: usize = 64;
/// Length of the BIP 324 garbage terminator in bytes.
const GARBAGE_TERMINATOR_LEN: usize = 16;
/// Length of the encrypted packet-length prefix in bytes.
const LENGTH_FIELD_LEN: usize = 3;
/// Minimum decryptable packet: 1 header byte + 16-byte Poly1305 tag.
const MIN_PACKET_LEN: usize = 1 + 16;
/// Upper bound on a v2 packet we will allocate for. Core's
/// `MAX_CONTENTS_LEN` is a long-encoding byte, a 12-byte message type and a
/// `MAX_PROTOCOL_MESSAGE_LENGTH` (4 MB) payload; `decrypt_packet_len` also
/// counts the header byte and the 16-byte tag.
const MAX_V2_PACKET_LEN: usize = 1 + 12 + 4_000_000 + 1 + 16;

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

/// Counts raw handshake bytes into the peer's totals as they cross the
/// socket. Core's `bytesrecv` moves with every byte of the key, the garbage
/// and the version packet, so a peer stalled mid-handshake shows its
/// progress in `getpeerinfo`.
struct CountingStream<'a, S> {
    inner: &'a mut S,
    counters: Option<&'a Arc<PeerStats>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut *self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > 0
            && let Some(c) = self.counters
        {
            c.record_recv(n);
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut *self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &res
            && let Some(c) = self.counters
        {
            c.record_sent(*n);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

fn handshake_io_err(e: bip324::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("v2 handshake: {e}"))
}

/// Read exactly `n` bytes, draining `leftover` first and only then the
/// socket. Carries the post-handshake spill (bytes read past the version
/// packet) into the steady-state read path.
async fn read_exact_buffered<S: AsyncRead + Unpin>(
    stream: &mut S,
    leftover: &mut Vec<u8>,
    n: usize,
) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    let from_leftover = leftover.len().min(n);
    if from_leftover > 0 {
        out[..from_leftover].copy_from_slice(&leftover[..from_leftover]);
        leftover.drain(..from_leftover);
    }
    if from_leftover < n {
        stream.read_exact(&mut out[from_leftover..]).await?;
    }
    Ok(out)
}

/// Receive the next genuine `NetworkMessage` from an encrypted stream,
/// transparently skipping decoy packets.
///
/// Not cancel-safe — performs multiple awaited reads per message and must
/// run in a dedicated task, exactly like the v1 read path.
async fn recv_v2<S: AsyncRead + Unpin>(
    stream: &mut S,
    cipher: &mut InboundCipher,
    leftover: &mut Vec<u8>,
    counters: Option<&Arc<PeerStats>>,
) -> io::Result<NetworkMessage> {
    loop {
        let len_bytes = read_exact_buffered(stream, leftover, LENGTH_FIELD_LEN).await?;
        let packet_len = cipher.decrypt_packet_len([len_bytes[0], len_bytes[1], len_bytes[2]]);
        if packet_len > MAX_V2_PACKET_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("v2 packet too large: {packet_len} bytes"),
            ));
        }
        if packet_len < MIN_PACKET_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "v2 packet too small",
            ));
        }
        let ciphertext = read_exact_buffered(stream, leftover, packet_len).await?;
        // On-wire bytes for this packet: the 3-byte length prefix + the
        // encrypted body. Counted per packet, including decoys (which loop).
        let wire_len = LENGTH_FIELD_LEN + packet_len;
        if let Some(c) = counters {
            c.record_recv(wire_len);
        }
        let (packet_type, plaintext) = cipher
            .decrypt_to_vec(&ciphertext, None)
            .map_err(handshake_io_err)?;
        // Decoys carry no message; the cipher state has already advanced.
        // Their bytes are real and already counted, so they are attributed to
        // `*other*` rather than dropped -- otherwise the per-type tallies
        // would not sum to `bytesrecv` on a peer that sends decoys.
        if packet_type == PacketType::Decoy {
            if let Some(c) = counters {
                c.attribute_recv(crate::net::stats::MSG_TYPE_OTHER, wire_len);
            }
            continue;
        }
        // plaintext[0] is the protocol header byte; the message contents
        // follow. An empty-contents genuine packet is not a valid message.
        if plaintext.len() <= 1 {
            if let Some(c) = counters {
                c.attribute_recv(crate::net::stats::MSG_TYPE_OTHER, wire_len);
            }
            continue;
        }
        let msg = decode_message(&plaintext[1..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if let Some(c) = counters {
            c.attribute_recv(msg.cmd(), wire_len);
        }
        return Ok(msg);
    }
}

/// Encode, encrypt, and write a single `NetworkMessage` as a genuine v2
/// packet. Returns the number of on-wire (ciphertext-framed) bytes written.
async fn send_v2<S: AsyncWrite + Unpin>(
    stream: &mut S,
    cipher: &mut OutboundCipher,
    msg: NetworkMessage,
) -> io::Result<usize> {
    let contents = encode_message(msg);
    let packet = cipher.encrypt_to_vec(&contents, PacketType::Genuine, None);
    stream.write_all(&packet).await?;
    Ok(packet.len())
}

/// Drive a full BIP 324 v2 handshake to completion on `stream`, returning
/// the established cipher session and any bytes read past the remote's
/// version packet (carried into the steady-state read path).
///
/// `prefetch` is bytes already consumed off the socket that belong to the
/// front of the remote's ElligatorSwift key — used by the responder, which
/// must read the first bytes to distinguish v1 from v2 before the
/// handshake begins. Pass an empty slice for the initiator.
///
/// Mirrors the reference driver in `bip324::io::handshake_with_initialized`
/// with no local garbage or decoy packets.
async fn drive_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    network: Network,
    role: Role,
    prefetch: &[u8],
    peer: u64,
) -> io::Result<(CipherSession, Vec<u8>)> {
    let handshake = Handshake::new(network, role).map_err(handshake_io_err)?;

    // Send our ElligatorSwift public key (no garbage).
    let mut key_buf = vec![0u8; Handshake::<Initialized>::send_key_len(None)];
    let handshake = handshake
        .send_key(None, &mut key_buf)
        .map_err(handshake_io_err)?;
    tracing::debug!("start sending v2 handshake to peer={peer}");
    stream.write_all(&key_buf).await?;
    stream.flush().await?;

    // Receive the remote's key (the first `prefetch.len()` bytes were
    // already read during transport detection).
    let mut their_key = [0u8; ELLSWIFT_KEY_LEN];
    their_key[..prefetch.len()].copy_from_slice(prefetch);
    stream.read_exact(&mut their_key[prefetch.len()..]).await?;
    let handshake = handshake.receive_key(their_key).map_err(handshake_io_err)?;

    // Send our garbage terminator + version packet (no decoys).
    let mut version_buf = vec![0u8; Handshake::<ReceivedKey>::send_version_len(None)];
    let handshake = handshake
        .send_version(&mut version_buf, None)
        .map_err(handshake_io_err)?;
    stream.write_all(&version_buf).await?;
    stream.flush().await?;

    // Find the remote's garbage terminator, extending the buffer until it
    // appears (we send no garbage, but the peer may).
    let mut garbage_buf = vec![0u8; GARBAGE_TERMINATOR_LEN];
    stream.read_exact(&mut garbage_buf).await?;
    let mut sent_version = handshake;
    let (mut received_garbage, consumed) = loop {
        let received = sent_version.receive_garbage(&garbage_buf);
        if let Err(bip324::Error::NoGarbageTerminator) = &received {
            tracing::debug!("V2 transport error: missing garbage terminator, peer={peer}");
        }
        match received.map_err(handshake_io_err)? {
            GarbageResult::FoundGarbage {
                handshake,
                consumed_bytes,
            } => break (handshake, consumed_bytes),
            GarbageResult::NeedMoreData(h) => {
                sent_version = h;
                let mut tmp = [0u8; 256];
                let n = stream.read(&mut tmp).await?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "eof during v2 garbage exchange",
                    ));
                }
                garbage_buf.extend_from_slice(&tmp[..n]);
            }
        }
    };

    // Process packets after the garbage terminator until the version
    // packet completes the handshake; decoys advance the cipher and loop.
    let mut leftover: Vec<u8> = garbage_buf[consumed..].to_vec();
    loop {
        let len_bytes = read_exact_buffered(stream, &mut leftover, LENGTH_FIELD_LEN).await?;
        let packet_len = received_garbage
            .decrypt_packet_len([len_bytes[0], len_bytes[1], len_bytes[2]])
            .map_err(handshake_io_err)?;
        if packet_len > MAX_V2_PACKET_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "v2 version packet too large",
            ));
        }
        let mut packet = read_exact_buffered(stream, &mut leftover, packet_len).await?;
        match received_garbage
            .receive_version(&mut packet)
            .map_err(handshake_io_err)?
        {
            VersionResult::Complete { cipher } => return Ok((cipher, leftover)),
            VersionResult::Decoy(h) => received_garbage = h,
        }
    }
}

/// Run the responder (inbound) side of a v2 handshake. `prefetch` is the
/// bytes already read off the socket during v1/v2 detection; the caller
/// has counted them. Handshake bytes are counted into `counters`.
pub async fn responder_handshake(
    stream: &mut TcpStream,
    network: Network,
    prefetch: &[u8],
    peer: u64,
    counters: Option<&Arc<PeerStats>>,
) -> io::Result<(CipherSession, Vec<u8>)> {
    counted_handshake(stream, network, Role::Responder, prefetch, peer, counters).await
}

/// Run the initiator (outbound) side of a v2 handshake.
pub async fn initiator_handshake(
    stream: &mut TcpStream,
    network: Network,
    peer: u64,
    counters: Option<&Arc<PeerStats>>,
) -> io::Result<(CipherSession, Vec<u8>)> {
    counted_handshake(stream, network, Role::Initiator, &[], peer, counters).await
}

async fn counted_handshake(
    stream: &mut TcpStream,
    network: Network,
    role: Role,
    prefetch: &[u8],
    peer: u64,
    counters: Option<&Arc<PeerStats>>,
) -> io::Result<(CipherSession, Vec<u8>)> {
    let mut counted = CountingStream { inner: stream, counters };
    let (cipher, leftover) = drive_handshake(&mut counted, network, role, prefetch, peer).await?;
    // Bytes read past the version packet belong to the next packet, which
    // the steady-state reader counts whole when it frames it.
    if let Some(c) = counters {
        c.discount_recv(leftover.len());
    }
    Ok((cipher, leftover))
}

/// Encrypted v2 P2P connection (pre-split).
pub struct V2Connection {
    stream: TcpStream,
    cipher: CipherSession,
    leftover: Vec<u8>,
    counters: Option<Arc<PeerStats>>,
}

/// Read half of a split [`V2Connection`].
pub struct V2Reader {
    stream: ReadHalf<TcpStream>,
    cipher: InboundCipher,
    leftover: Vec<u8>,
    counters: Option<Arc<PeerStats>>,
}

/// Write half of a split [`V2Connection`].
pub struct V2Writer {
    stream: WriteHalf<TcpStream>,
    cipher: OutboundCipher,
    counters: Option<Arc<PeerStats>>,
}

impl V2Connection {
    /// The BIP 324 session ID for this connection.
    ///
    /// Reported by `getpeerinfo.session_id`, whose entire purpose is
    /// out-of-band MITM detection: both ends compare the value, and a
    /// mismatch means someone is between them. satd reported `""` for every
    /// peer, v2 included, which is indistinguishable from "no session" — so
    /// the check the field exists for silently could not be made.
    pub fn session_id(&self) -> [u8; 32] {
        *self.cipher.id()
    }

    /// Wrap a socket and an established cipher session. `leftover` is any
    /// bytes read past the handshake's version packet.
    pub fn new(stream: TcpStream, cipher: CipherSession, leftover: Vec<u8>) -> Self {
        Self {
            stream,
            cipher,
            leftover,
            counters: None,
        }
    }

    /// Attach the per-peer counters, so the version handshake's messages
    /// are counted and attributed as the steady-state ones are.
    pub fn set_counters(&mut self, counters: Arc<PeerStats>) {
        self.counters = Some(counters);
    }

    /// Split into separate read and write halves.
    pub fn split(self) -> (V2Reader, V2Writer) {
        let (read_half, write_half) = tokio::io::split(self.stream);
        let (inbound, outbound) = self.cipher.into_split();
        (
            V2Reader {
                stream: read_half,
                cipher: inbound,
                leftover: self.leftover,
                counters: self.counters.clone(),
            },
            V2Writer {
                stream: write_half,
                cipher: outbound,
                counters: self.counters,
            },
        )
    }

    /// Send a network message over the encrypted channel. Pre-split
    /// (handshake) path, counted once counters are attached.
    pub async fn send(&mut self, msg: NetworkMessage) -> io::Result<()> {
        let cmd = msg.cmd();
        let n = send_v2(&mut self.stream, self.cipher.outbound(), msg).await?;
        if let Some(c) = &self.counters {
            c.record_sent(n);
            c.attribute_sent(cmd, n);
        }
        Ok(())
    }

    /// Receive the next network message from the encrypted channel. Pre-split
    /// (handshake) path, counted once counters are attached.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        recv_v2(
            &mut self.stream,
            self.cipher.inbound(),
            &mut self.leftover,
            self.counters.as_ref(),
        )
        .await
    }

    /// Get the peer's remote address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    /// Get the local address this connection is bound to (`getsockname()`).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }
}

impl V2Writer {
    /// Send a network message over the encrypted channel, recording on-wire
    /// (ciphertext-framed) bytes if counters are set.
    pub async fn send(&mut self, msg: NetworkMessage) -> io::Result<()> {
        let cmd = msg.cmd();
        let n = send_v2(&mut self.stream, &mut self.cipher, msg).await?;
        if let Some(c) = &self.counters {
            c.record_sent(n);
            c.attribute_sent(cmd, n);
        }
        Ok(())
    }

    /// Attach the per-peer byte/activity counters.
    pub fn set_counters(&mut self, counters: Arc<PeerStats>) {
        self.counters = Some(counters);
    }
}

impl V2Reader {
    /// Receive the next network message from the encrypted channel.
    ///
    /// As with [`V1Reader`](crate::net::connection), this must NOT be used
    /// inside `tokio::select!` — it is not cancel-safe.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        recv_v2(
            &mut self.stream,
            &mut self.cipher,
            &mut self.leftover,
            self.counters.as_ref(),
        )
        .await
    }

    /// Attach the per-peer byte/activity counters.
    pub fn set_counters(&mut self, counters: Arc<PeerStats>) {
        self.counters = Some(counters);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::Network;
    use tokio::net::TcpListener;

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

    /// End-to-end: a real loopback TCP pair runs the initiator and
    /// responder handshake drivers, then exchanges encrypted messages
    /// through `V2Connection` in both directions. Mirrors the inbound
    /// detection (responder reads the first 4 bytes, then drives the
    /// handshake with them as prefetch).
    #[tokio::test]
    async fn v2_handshake_over_tcp_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let net = Network::Bitcoin;

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Mimic the manager's v1/v2 detection: read the first 4 bytes
            // (which are the start of the initiator's ellswift key here).
            let mut first = [0u8; 4];
            sock.read_exact(&mut first).await.unwrap();
            let (cipher, leftover) = drive_handshake(&mut sock, net, Role::Responder, &first, 0)
                .await
                .unwrap();
            let mut conn = V2Connection::new(sock, cipher, leftover);

            let got = conn.recv().await.unwrap();
            assert_eq!(got, NetworkMessage::Ping(7));
            conn.send(NetworkMessage::Pong(7)).await.unwrap();
            // A second message after a split to exercise the reader half.
            let got2 = conn.recv().await.unwrap();
            assert_eq!(got2, NetworkMessage::GetAddr);
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let (cipher, leftover) = initiator_handshake(&mut client, net, 0, None).await.unwrap();
        let mut conn = V2Connection::new(client, cipher, leftover);

        conn.send(NetworkMessage::Ping(7)).await.unwrap();
        let reply = conn.recv().await.unwrap();
        assert_eq!(reply, NetworkMessage::Pong(7));
        conn.send(NetworkMessage::GetAddr).await.unwrap();

        server.await.unwrap();
    }

    /// A handshake pair over loopback, each side counting into its own stats.
    async fn counted_pair(
        net: Network,
    ) -> (V2Connection, V2Connection, Arc<PeerStats>, Arc<PeerStats>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_stats = PeerStats::new(crate::net::stats::NetTotals::new());
        let client_stats = PeerStats::new(crate::net::stats::NetTotals::new());
        let ss = server_stats.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (cipher, leftover) =
                responder_handshake(&mut sock, net, &[], 1, Some(&ss)).await.unwrap();
            V2Connection::new(sock, cipher, leftover)
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (cipher, leftover) =
            initiator_handshake(&mut client, net, 2, Some(&client_stats)).await.unwrap();
        let client = V2Connection::new(client, cipher, leftover);
        (server.await.unwrap(), client, server_stats, client_stats)
    }

    /// Every byte one side of the handshake writes, the other counts as read.
    #[tokio::test]
    async fn handshake_bytes_are_counted_on_both_sides() {
        let (_server, _client, server_stats, client_stats) = counted_pair(Network::Regtest).await;
        assert!(client_stats.bytes_sent() > 64, "at least the key went out");
        assert_eq!(server_stats.bytes_recv(), client_stats.bytes_sent());
        assert_eq!(client_stats.bytes_recv(), server_stats.bytes_sent());
    }

    /// Core's `MAX_CONTENTS_LEN` admits a 4 MB payload under a 12-byte
    /// message type; the packet framing around it must not be refused.
    #[tokio::test]
    async fn a_four_megabyte_message_fits_a_v2_packet() {
        let (mut server, mut client, _, _) = counted_pair(Network::Regtest).await;
        let msg = NetworkMessage::Unknown {
            command: bitcoin::p2p::message::CommandString::try_from_static("unknown").unwrap(),
            payload: vec![0xab; 4_000_000],
        };
        let sent = msg.clone();
        let send = tokio::spawn(async move { client.send(sent).await.map(|_| client) });
        let got = server.recv().await.expect("a 4 MB message is accepted");
        assert_eq!(got, msg);
        send.await.unwrap().unwrap();
    }

    /// A v2 initiator against a v1-only peer must fail the handshake — this
    /// is the trigger for the outbound v1 downgrade in the peer manager.
    /// The "v1 peer" replies to the initiator's key with bytes whose first
    /// four are the network magic, which BIP 324 treats as a v1 fallback.
    #[tokio::test]
    async fn initiator_handshake_fails_against_v1_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Consume the initiator's ellswift key.
            let mut key = [0u8; 64];
            sock.read_exact(&mut key).await.unwrap();
            // Respond as a v1 peer would: a message starting with the
            // network magic (padded to a full ellswift-key read).
            let magic = bitcoin::p2p::Magic::from(Network::Bitcoin).to_bytes();
            let mut reply = magic.to_vec();
            reply.extend_from_slice(&[0u8; 60]);
            let _ = sock.write_all(&reply).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let result = initiator_handshake(&mut client, Network::Bitcoin, 0, None).await;
        assert!(
            result.is_err(),
            "v2 initiator handshake must fail against a v1 peer"
        );
        let _ = server.await;
    }
}
