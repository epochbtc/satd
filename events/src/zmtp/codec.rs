//! ZMTP 3.0 wire pieces the PUB server needs: the greeting, the NULL
//! mechanism's READY command, frame headers, and the inbound frame reader.
//!
//! References: RFC 23 (ZMTP 3.0), RFC 37 (ZMTP 3.1, for the `SUBSCRIBE`,
//! `CANCEL`, `PING` and `PONG` commands a newer peer may send).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Frame flag: more frames follow in this message.
pub(crate) const FLAG_MORE: u8 = 0x01;
/// Frame flag: the size is an 8-byte big-endian integer, not one byte.
pub(crate) const FLAG_LONG: u8 = 0x02;
/// Frame flag: the frame is a command, not part of a message.
pub(crate) const FLAG_COMMAND: u8 = 0x04;

/// The largest frame accepted from a subscriber. A subscriber only sends
/// subscriptions and commands, so anything near this is not a real peer.
pub(crate) const MAX_INBOUND_FRAME: u64 = 1 << 20;

/// Our 64-byte greeting: signature, version 3.0, mechanism `NULL`, as-server
/// 0, filler. As-server is 0 because the NULL mechanism has no roles, and
/// some subscribers (LND's `gozmq`) refuse a NULL greeting that sets it.
pub(crate) const GREETING: [u8; 64] = {
    let mut g = [0u8; 64];
    g[0] = 0xFF;
    g[9] = 0x7F;
    g[10] = 3; // major
    g[11] = 0; // minor
    g[12] = b'N';
    g[13] = b'U';
    g[14] = b'L';
    g[15] = b'L';
    g
};

/// Read and check the peer's greeting, field by field, so an old-protocol
/// or non-ZMTP peer is refused as soon as its signature is wrong.
///
/// Accepts any major version from 3 up, as libzmq does: a 3.1 peer that
/// reads our 3.0 greeting speaks 3.0 to us, apart from possibly sending the
/// 3.1 commands, which the reader understands.
pub(crate) async fn read_peer_greeting<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<()> {
    let mut sig = [0u8; 10];
    r.read_exact(&mut sig).await?;
    if sig[0] != 0xFF || sig[9] & 0x01 == 0 {
        return Err(protocol("peer did not send a ZMTP 3 signature"));
    }
    let mut version = [0u8; 2];
    r.read_exact(&mut version).await?;
    if version[0] < 3 {
        return Err(protocol(format!(
            "peer speaks ZMTP {}.{}; 3.0 or later is required",
            version[0], version[1]
        )));
    }
    let mut mechanism = [0u8; 20];
    r.read_exact(&mut mechanism).await?;
    if &mechanism[..4] != b"NULL" || mechanism[4..].iter().any(|b| *b != 0) {
        return Err(protocol("peer asked for a security mechanism other than NULL"));
    }
    // as-server (1 byte) and filler (31 bytes): nothing to check for NULL.
    let mut rest = [0u8; 32];
    r.read_exact(&mut rest).await?;
    Ok(())
}

/// The NULL mechanism's READY command announcing `Socket-Type: PUB`, as a
/// complete frame.
pub(crate) fn ready_frame() -> Vec<u8> {
    let mut body = Vec::with_capacity(25);
    body.push(5);
    body.extend_from_slice(b"READY");
    body.push(11);
    body.extend_from_slice(b"Socket-Type");
    body.extend_from_slice(&3u32.to_be_bytes());
    body.extend_from_slice(b"PUB");
    command_frame(&body)
}

/// A complete command frame carrying `body` (name length, name, data).
pub(crate) fn command_frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 9);
    out.extend_from_slice(&frame_header(FLAG_COMMAND, body.len()));
    out.extend_from_slice(body);
    out
}

/// A PONG command echoing a PING's context.
pub(crate) fn pong_frame(context: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(5 + context.len());
    body.push(4);
    body.extend_from_slice(b"PONG");
    body.extend_from_slice(context);
    command_frame(&body)
}

/// A frame header: flags then the size, in the short form when it fits in
/// one byte and the long form (with [`FLAG_LONG`] set) otherwise. Returns
/// the header bytes and their length in a fixed buffer.
pub(crate) fn frame_header(flags: u8, len: usize) -> HeaderBuf {
    let mut h = HeaderBuf { bytes: [0; 9], len: 0 };
    if len <= u8::MAX as usize {
        h.bytes[0] = flags;
        h.bytes[1] = len as u8;
        h.len = 2;
    } else {
        h.bytes[0] = flags | FLAG_LONG;
        h.bytes[1..9].copy_from_slice(&(len as u64).to_be_bytes());
        h.len = 9;
    }
    h
}

/// A frame header of at most 9 bytes.
pub(crate) struct HeaderBuf {
    bytes: [u8; 9],
    len: usize,
}

impl std::ops::Deref for HeaderBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// One frame read from a peer.
pub(crate) struct InFrame {
    pub flags: u8,
    pub body: Vec<u8>,
}

impl InFrame {
    pub fn is_command(&self) -> bool {
        self.flags & FLAG_COMMAND != 0
    }

    pub fn more(&self) -> bool {
        self.flags & FLAG_MORE != 0
    }

    /// Split a command frame into its name and data. `None` when the name
    /// length runs past the body.
    pub fn command(&self) -> Option<(&[u8], &[u8])> {
        let (&n, rest) = self.body.split_first()?;
        let n = n as usize;
        (rest.len() >= n).then(|| rest.split_at(n))
    }
}

/// Read one frame. Reserved flag bits, a command with MORE set, or a frame
/// over [`MAX_INBOUND_FRAME`] are protocol errors that close the peer.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<InFrame> {
    let flags = r.read_u8().await?;
    if flags & !(FLAG_MORE | FLAG_LONG | FLAG_COMMAND) != 0 {
        return Err(protocol(format!("reserved frame flag bits set: {flags:#04x}")));
    }
    if flags & FLAG_COMMAND != 0 && flags & FLAG_MORE != 0 {
        return Err(protocol("command frame with MORE set"));
    }
    let len = if flags & FLAG_LONG != 0 {
        r.read_u64().await?
    } else {
        u64::from(r.read_u8().await?)
    };
    if len > MAX_INBOUND_FRAME {
        return Err(protocol(format!("peer frame of {len} bytes is over the limit")));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok(InFrame { flags, body })
}

/// Find `Socket-Type` in a READY command's properties and require a
/// subscriber type. Property names are case-insensitive (RFC 23).
pub(crate) fn check_peer_ready(frame: &InFrame) -> io::Result<()> {
    if !frame.is_command() {
        return Err(protocol("peer sent a message before READY"));
    }
    let Some((name, mut props)) = frame.command() else {
        return Err(protocol("malformed command from peer"));
    };
    if name != b"READY" {
        return Err(protocol(format!(
            "expected READY from peer, got {}",
            String::from_utf8_lossy(name)
        )));
    }
    let mut socket_type: Option<&[u8]> = None;
    while let Some((&n, rest)) = props.split_first() {
        let n = n as usize;
        if rest.len() < n + 4 {
            return Err(protocol("malformed READY metadata"));
        }
        let (key, rest) = rest.split_at(n);
        let (vlen, rest) = rest.split_at(4);
        let vlen = u32::from_be_bytes([vlen[0], vlen[1], vlen[2], vlen[3]]) as usize;
        if rest.len() < vlen {
            return Err(protocol("malformed READY metadata"));
        }
        let (value, rest) = rest.split_at(vlen);
        if key.eq_ignore_ascii_case(b"Socket-Type") {
            socket_type = Some(value);
        }
        props = rest;
    }
    match socket_type {
        Some(b"SUB") | Some(b"XSUB") => Ok(()),
        Some(other) => Err(protocol(format!(
            "a PUB socket only accepts SUB or XSUB peers, not {}",
            String::from_utf8_lossy(other)
        ))),
        None => Err(protocol("peer READY has no Socket-Type")),
    }
}

pub(crate) fn protocol(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}
