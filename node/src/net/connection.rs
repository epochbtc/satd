use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::Magic;
use bitcoin::Network;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

/// Wire-level P2P connection wrapping a TCP stream.
pub struct Connection {
    stream: TcpStream,
    magic: Magic,
    buf: Vec<u8>,
}

/// Read half of a split Connection. Used in a dedicated read task
/// to avoid cancel-safety issues with tokio::select!.
pub struct ConnectionReader {
    stream: ReadHalf<TcpStream>,
    magic: Magic,
    buf: Vec<u8>,
}

/// Write half of a split Connection.
pub struct ConnectionWriter {
    stream: WriteHalf<TcpStream>,
    magic: Magic,
}

/// Size of a P2P message header: 4 (magic) + 12 (command) + 4 (length) + 4 (checksum).
const HEADER_SIZE: usize = 24;
/// Maximum message payload size (32 MB).
const MAX_PAYLOAD_SIZE: usize = 32 * 1024 * 1024;
/// Maximum bytes to scan when resyncing to magic after stream misalignment.
const MAX_RESYNC_BYTES: usize = 256 * 1024;

impl Connection {
    pub fn new(stream: TcpStream, network: Network) -> Self {
        Self::with_magic(stream, Magic::from(network))
    }

    /// Construct a connection with an explicit network magic. Used for
    /// custom signet, whose magic is derived from the challenge rather
    /// than the `Network` enum (BIP 325).
    pub fn with_magic(stream: TcpStream, magic: Magic) -> Self {
        Self {
            stream,
            magic,
            buf: Vec::with_capacity(4096),
        }
    }

    /// Split into separate read and write halves.
    ///
    /// This is used after the handshake to avoid cancel-safety issues:
    /// the reader runs in a dedicated task that is never cancelled,
    /// preventing stream misalignment from partial reads.
    pub fn split(self) -> (ConnectionReader, ConnectionWriter) {
        let (read_half, write_half) = tokio::io::split(self.stream);
        (
            ConnectionReader {
                stream: read_half,
                magic: self.magic,
                buf: self.buf,
            },
            ConnectionWriter {
                stream: write_half,
                magic: self.magic,
            },
        )
    }

    /// Send a network message.
    pub async fn send(&mut self, msg: NetworkMessage) -> io::Result<()> {
        let raw = RawNetworkMessage::new(self.magic, msg);
        let bytes = serialize(&raw);
        self.stream.write_all(&bytes).await
    }

    /// Receive the next network message. Skips messages that fail to deserialize.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        recv_message(&mut self.stream, self.magic, &mut self.buf).await
    }

    /// Get the peer's remote address.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
}

impl ConnectionWriter {
    /// Send a network message.
    pub async fn send(&mut self, msg: NetworkMessage) -> io::Result<()> {
        let raw = RawNetworkMessage::new(self.magic, msg);
        let bytes = serialize(&raw);
        self.stream.write_all(&bytes).await
    }
}

impl ConnectionReader {
    /// Receive the next network message. Skips messages that fail to deserialize.
    ///
    /// This method must NOT be used inside tokio::select! — it is not cancel-safe.
    /// Instead, run it in a dedicated task that is never cancelled.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        recv_message(&mut self.stream, self.magic, &mut self.buf).await
    }
}

/// Shared recv implementation for both Connection and ConnectionReader.
async fn recv_message<R: AsyncReadExt + Unpin>(
    stream: &mut R,
    magic: Magic,
    buf: &mut Vec<u8>,
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
