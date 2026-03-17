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
        loop {
            // Read 24-byte header
            let mut header = [0u8; HEADER_SIZE];
            self.stream.read_exact(&mut header).await?;

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

    /// Get a reference to the underlying stream (for split operations).
    pub fn into_split(self) -> (TcpStream, Magic) {
        (self.stream, self.magic)
    }

    /// Get the peer's remote address.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
}
