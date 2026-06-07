use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::Magic;
use bitcoin::Network;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use crate::net::stats::PeerStats;
use crate::net::v2transport::{V2Connection, V2Reader, V2Writer};

/// Wire-level P2P connection.
///
/// This is the transport seam: every peer connection is either a plaintext
/// v1 link (`V1`) or a BIP 324 v2 encrypted link (`V2`). The rest of the
/// peer pipeline (handshake, read/write tasks, manager event loop) speaks
/// `NetworkMessage` and is unaware of which transport carries it. The v2
/// arms are scaffolding wired in a later PR of the BIP 324 stack.
pub enum Connection {
    V1(V1Connection),
    V2(V2Connection),
}

/// Read half of a split [`Connection`]. Used in a dedicated read task
/// to avoid cancel-safety issues with `tokio::select!`.
pub enum ConnectionReader {
    V1(V1Reader),
    V2(V2Reader),
}

/// Write half of a split [`Connection`].
pub enum ConnectionWriter {
    V1(V1Writer),
    V2(V2Writer),
}

impl Connection {
    pub fn new(stream: TcpStream, network: Network) -> Self {
        Self::with_magic(stream, Magic::from(network))
    }

    /// Construct a v1 connection with an explicit network magic. Used for
    /// custom signet, whose magic is derived from the challenge rather
    /// than the `Network` enum (BIP 325).
    pub fn with_magic(stream: TcpStream, magic: Magic) -> Self {
        Connection::V1(V1Connection {
            stream,
            magic,
            buf: Vec::with_capacity(4096),
            leading: None,
        })
    }

    /// Construct a v1 connection where `leading` bytes were already read
    /// off the socket (e.g. during v1/v2 transport detection) and must be
    /// replayed before the rest of the stream. The first `recv` consumes
    /// `leading` ahead of any socket reads.
    pub fn v1_with_leading(stream: TcpStream, magic: Magic, leading: Vec<u8>) -> Self {
        Connection::V1(V1Connection {
            stream,
            magic,
            buf: Vec::with_capacity(4096),
            leading: Some(leading),
        })
    }

    /// Wrap an established BIP 324 v2 encrypted connection.
    pub fn v2(conn: V2Connection) -> Self {
        Connection::V2(conn)
    }

    /// Split into separate read and write halves.
    ///
    /// This is used after the handshake to avoid cancel-safety issues:
    /// the reader runs in a dedicated task that is never cancelled,
    /// preventing stream misalignment from partial reads.
    pub fn split(self) -> (ConnectionReader, ConnectionWriter) {
        match self {
            Connection::V1(c) => {
                let (r, w) = c.split();
                (ConnectionReader::V1(r), ConnectionWriter::V1(w))
            }
            Connection::V2(c) => {
                let (r, w) = c.split();
                (ConnectionReader::V2(r), ConnectionWriter::V2(w))
            }
        }
    }

    /// Send a network message.
    pub async fn send(&mut self, msg: NetworkMessage) -> io::Result<()> {
        match self {
            Connection::V1(c) => c.send(msg).await,
            Connection::V2(c) => c.send(msg).await,
        }
    }

    /// Receive the next network message. Skips messages that fail to deserialize.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        match self {
            Connection::V1(c) => c.recv().await,
            Connection::V2(c) => c.recv().await,
        }
    }

    /// Get the peer's remote address.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        match self {
            Connection::V1(c) => c.peer_addr(),
            Connection::V2(c) => c.peer_addr(),
        }
    }

    /// Which wire transport this connection uses.
    pub fn transport_protocol(&self) -> crate::net::peer::TransportProtocol {
        match self {
            Connection::V1(_) => crate::net::peer::TransportProtocol::V1,
            Connection::V2(_) => crate::net::peer::TransportProtocol::V2,
        }
    }
}

impl ConnectionWriter {
    /// Send a network message.
    pub async fn send(&mut self, msg: NetworkMessage) -> io::Result<()> {
        match self {
            ConnectionWriter::V1(w) => w.send(msg).await,
            ConnectionWriter::V2(w) => w.send(msg).await,
        }
    }

    /// Attach the per-peer byte/activity counters, recorded on every send.
    /// Called once after [`Connection::split`], when the peer's `PeerStats`
    /// is known.
    pub fn set_counters(&mut self, counters: Arc<PeerStats>) {
        match self {
            ConnectionWriter::V1(w) => w.counters = Some(counters),
            ConnectionWriter::V2(w) => w.set_counters(counters),
        }
    }
}

impl ConnectionReader {
    /// Receive the next network message. Skips messages that fail to deserialize.
    ///
    /// This method must NOT be used inside `tokio::select!` — it is not
    /// cancel-safe. Instead, run it in a dedicated task that is never cancelled.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        match self {
            ConnectionReader::V1(r) => r.recv().await,
            ConnectionReader::V2(r) => r.recv().await,
        }
    }

    /// Attach the per-peer byte/activity counters, recorded on every recv.
    /// Called once after [`Connection::split`], when the peer's `PeerStats`
    /// is known.
    pub fn set_counters(&mut self, counters: Arc<PeerStats>) {
        match self {
            ConnectionReader::V1(r) => r.counters = Some(counters),
            ConnectionReader::V2(r) => r.set_counters(counters),
        }
    }
}

/// Plaintext v1 P2P connection wrapping a TCP stream.
pub struct V1Connection {
    stream: TcpStream,
    magic: Magic,
    buf: Vec<u8>,
    /// Bytes already read off the socket before the connection was built
    /// (transport detection), replayed ahead of the socket on the first
    /// `recv`. Consumed during the version handshake, before `split`.
    leading: Option<Vec<u8>>,
}

/// Read half of a split [`V1Connection`].
pub struct V1Reader {
    stream: ReadHalf<TcpStream>,
    magic: Magic,
    buf: Vec<u8>,
    counters: Option<Arc<PeerStats>>,
}

/// Write half of a split [`V1Connection`].
pub struct V1Writer {
    stream: WriteHalf<TcpStream>,
    magic: Magic,
    counters: Option<Arc<PeerStats>>,
}

/// Size of a P2P message header: 4 (magic) + 12 (command) + 4 (length) + 4 (checksum).
const HEADER_SIZE: usize = 24;
/// Maximum message payload size (32 MB).
const MAX_PAYLOAD_SIZE: usize = 32 * 1024 * 1024;
/// Maximum bytes to scan when resyncing to magic after stream misalignment.
const MAX_RESYNC_BYTES: usize = 256 * 1024;

impl V1Connection {
    /// Split into separate read and write halves.
    pub fn split(self) -> (V1Reader, V1Writer) {
        let (read_half, write_half) = tokio::io::split(self.stream);
        (
            V1Reader {
                stream: read_half,
                magic: self.magic,
                buf: self.buf,
                counters: None,
            },
            V1Writer {
                stream: write_half,
                magic: self.magic,
                counters: None,
            },
        )
    }

    /// Send a network message. Pre-split (handshake) path — uncounted.
    pub async fn send(&mut self, msg: NetworkMessage) -> io::Result<()> {
        let raw = RawNetworkMessage::new(self.magic, msg);
        let bytes = serialize(&raw);
        self.stream.write_all(&bytes).await
    }

    /// Receive the next network message. Skips messages that fail to
    /// deserialize. Pre-split (handshake) path — uncounted.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        if let Some(lead) = self.leading.take() {
            let mut reader = LeadingReader::new(lead, &mut self.stream);
            return recv_message(&mut reader, self.magic, &mut self.buf, None).await;
        }
        recv_message(&mut self.stream, self.magic, &mut self.buf, None).await
    }

    /// Get the peer's remote address.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
}

/// An `AsyncRead` adapter that yields a fixed prefix of bytes before
/// delegating to an inner reader. Used to replay bytes consumed during
/// transport detection without losing stream alignment.
struct LeadingReader<'a, R> {
    lead: Vec<u8>,
    pos: usize,
    inner: &'a mut R,
}

impl<'a, R> LeadingReader<'a, R> {
    fn new(lead: Vec<u8>, inner: &'a mut R) -> Self {
        Self {
            lead,
            pos: 0,
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for LeadingReader<'_, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.lead.len() {
            let remaining = &self.lead[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl V1Writer {
    /// Send a network message, recording on-wire bytes if counters are set.
    pub async fn send(&mut self, msg: NetworkMessage) -> io::Result<()> {
        let raw = RawNetworkMessage::new(self.magic, msg);
        let bytes = serialize(&raw);
        self.stream.write_all(&bytes).await?;
        if let Some(c) = &self.counters {
            c.record_sent(bytes.len());
        }
        Ok(())
    }
}

impl V1Reader {
    /// Receive the next network message. Skips messages that fail to deserialize.
    ///
    /// This method must NOT be used inside `tokio::select!` — it is not
    /// cancel-safe. Instead, run it in a dedicated task that is never cancelled.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        recv_message(&mut self.stream, self.magic, &mut self.buf, self.counters.as_ref()).await
    }
}

/// Shared recv implementation for both V1Connection and V1Reader. When
/// `counters` is set, the on-wire size (header + payload) of every framed
/// message — including ones skipped as unparseable — is recorded.
async fn recv_message<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    magic: Magic,
    buf: &mut Vec<u8>,
    counters: Option<&Arc<PeerStats>>,
) -> io::Result<NetworkMessage> {
    let expected = magic.to_bytes();

    loop {
        // Read 24-byte header
        let mut header = [0u8; HEADER_SIZE];
        stream.read_exact(&mut header).await?;

        // Validate magic BEFORE trusting payload_len
        if header[0..4] != expected {
            tracing::warn!(
                expected = %format!("{:02x}{:02x}{:02x}{:02x}", expected[0], expected[1], expected[2], expected[3]),
                got = %format!("{:02x}{:02x}{:02x}{:02x}", header[0], header[1], header[2], header[3]),
                header_hex = %hex::encode(header),
                "Bad magic bytes in header, attempting stream resync",
            );
            header = resync_to_magic(stream, &header, expected).await?;
        }

        // Parse payload length from header bytes 16..20 (little-endian u32)
        let payload_len =
            u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("payload too large: {} bytes", payload_len),
            ));
        }

        // Read payload
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            stream.read_exact(&mut payload).await?;
        }

        // Record on-wire bytes for this framed message (counted even if it
        // fails to deserialize below — the bytes were still received).
        if let Some(c) = counters {
            c.record_recv(HEADER_SIZE + payload_len);
        }

        // Combine header + payload and deserialize
        buf.clear();
        buf.extend_from_slice(&header);
        buf.extend_from_slice(&payload);

        match deserialize::<RawNetworkMessage>(buf) {
            Ok(raw) => {
                if *raw.magic() != magic {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "wrong network magic",
                    ));
                }
                return Ok(raw.payload().clone());
            }
            Err(_) => {
                let cmd = String::from_utf8_lossy(&header[4..16]);
                tracing::debug!(cmd = %cmd.trim_end_matches('\0'), "Skipping unparseable message");
                continue;
            }
        }
    }
}

/// Scan the stream for the expected magic bytes after a misaligned read.
async fn resync_to_magic<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    failed_header: &[u8; HEADER_SIZE],
    expected: [u8; 4],
) -> io::Result<[u8; HEADER_SIZE]> {
    let leftover = &failed_header[1..];
    let mut leftover_pos: usize = 0;
    let mut scanned: usize = 0;

    let mut window = [0u8; 4];
    let mut window_len: usize = 0;

    loop {
        let byte = if leftover_pos < leftover.len() {
            let b = leftover[leftover_pos];
            leftover_pos += 1;
            b
        } else {
            let mut buf = [0u8; 1];
            stream.read_exact(&mut buf).await?;
            buf[0]
        };

        scanned += 1;
        if scanned > MAX_RESYNC_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("stream resync failed after scanning {} bytes", scanned),
            ));
        }

        if window_len < 4 {
            window[window_len] = byte;
            window_len += 1;
        } else {
            window[0] = window[1];
            window[1] = window[2];
            window[2] = window[3];
            window[3] = byte;
        }

        if window_len == 4 && window == expected {
            let mut header = [0u8; HEADER_SIZE];
            header[0..4].copy_from_slice(&expected);

            let leftover_remaining = &leftover[leftover_pos..];
            let usable = leftover_remaining.len().min(20);
            header[4..4 + usable].copy_from_slice(&leftover_remaining[..usable]);
            if usable < 20 {
                stream.read_exact(&mut header[4 + usable..]).await?;
            }

            tracing::debug!(scanned, "Stream resynced after skipping bytes");
            return Ok(header);
        }
    }
}
