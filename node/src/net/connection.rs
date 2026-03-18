use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::Magic;
use bitcoin::Network;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Wire-level P2P connection wrapping a TCP stream.
pub struct Connection {
    stream: TcpStream,
    magic: Magic,
    buf: Vec<u8>,
}

/// Size of a P2P message header: 4 (magic) + 12 (command) + 4 (length) + 4 (checksum).
const HEADER_SIZE: usize = 24;
/// Maximum message payload size (32 MB).
const MAX_PAYLOAD_SIZE: usize = 32 * 1024 * 1024;
/// Maximum bytes to scan when resyncing to magic after stream misalignment.
const MAX_RESYNC_BYTES: usize = 256 * 1024;

impl Connection {
    pub fn new(stream: TcpStream, network: Network) -> Self {
        Self {
            stream,
            magic: Magic::from(network),
            buf: Vec::with_capacity(4096),
        }
    }

    /// Send a network message.
    pub async fn send(&mut self, msg: NetworkMessage) -> io::Result<()> {
        let raw = RawNetworkMessage::new(self.magic, msg);
        let bytes = serialize(&raw);
        self.stream.write_all(&bytes).await
    }

    /// Receive the next network message. Skips messages that fail to deserialize.
    pub async fn recv(&mut self) -> io::Result<NetworkMessage> {
        let expected = self.magic.to_bytes();

        loop {
            // Read 24-byte header
            let mut header = [0u8; HEADER_SIZE];
            self.stream.read_exact(&mut header).await?;

            // Validate magic BEFORE trusting payload_len
            if header[0..4] != expected {
                tracing::warn!("Bad magic bytes in header, attempting stream resync");
                header = self.resync_to_magic(&header).await?;
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
                self.stream.read_exact(&mut payload).await?;
            }

            // Combine header + payload and deserialize
            self.buf.clear();
            self.buf.extend_from_slice(&header);
            self.buf.extend_from_slice(&payload);

            match deserialize::<RawNetworkMessage>(&self.buf) {
                Ok(raw) => {
                    if *raw.magic() != self.magic {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "wrong network magic",
                        ));
                    }
                    return Ok(raw.payload().clone());
                }
                Err(_) => {
                    // Unknown or malformed message — skip it and read the next one.
                    // Extract command name from header for logging.
                    let cmd = String::from_utf8_lossy(&header[4..16]);
                    tracing::debug!(cmd = %cmd.trim_end_matches('\0'), "Skipping unparseable message");
                    continue;
                }
            }
        }
    }

    /// Scan the stream for the expected magic bytes after a misaligned read.
    ///
    /// Takes the failed 24-byte header read and scans through its remaining
    /// bytes (positions 1-23), then reads from the stream byte-by-byte using
    /// a rolling 4-byte window. Once magic is found, reads the remaining 20
    /// header bytes to return a complete 24-byte header.
    async fn resync_to_magic(
        &mut self,
        failed_header: &[u8; HEADER_SIZE],
    ) -> io::Result<[u8; HEADER_SIZE]> {
        let expected = self.magic.to_bytes();
        let leftover = &failed_header[1..]; // 23 bytes remaining after skipping byte 0
        let mut leftover_pos: usize = 0;
        let mut scanned: usize = 0;

        // Rolling window of 4 bytes
        let mut window = [0u8; 4];
        let mut window_len: usize = 0;

        loop {
            // Get next byte: first from leftover, then from stream
            let byte = if leftover_pos < leftover.len() {
                let b = leftover[leftover_pos];
                leftover_pos += 1;
                b
            } else {
                let mut buf = [0u8; 1];
                self.stream.read_exact(&mut buf).await?;
                buf[0]
            };

            scanned += 1;
            if scanned > MAX_RESYNC_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("stream resync failed after scanning {} bytes", scanned),
                ));
            }

            // Shift byte into rolling window
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
                // Found magic. Build the complete header.
                let mut header = [0u8; HEADER_SIZE];
                header[0..4].copy_from_slice(&expected);

                // Some remaining header bytes may still be in leftover
                let leftover_remaining = &leftover[leftover_pos..];
                let usable = leftover_remaining.len().min(20);
                header[4..4 + usable].copy_from_slice(&leftover_remaining[..usable]);
                if usable < 20 {
                    self.stream
                        .read_exact(&mut header[4 + usable..])
                        .await?;
                }

                tracing::debug!(scanned, "Stream resynced after skipping bytes");
                return Ok(header);
            }
        }
    }

    /// Get a reference to the underlying stream (for split operations).
    pub fn into_split(self) -> (TcpStream, Magic) {
        (self.stream, self.magic)
    }

    /// Get the peer's remote address.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
}
