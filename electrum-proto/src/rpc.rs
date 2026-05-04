//! Newline-delimited JSON-RPC 2.0 framing helpers.
//!
//! Electrum uses a line-protocol over TCP: requests are JSON objects
//! terminated by `\n`, responses too. A single line carries one
//! request or one response. We deliberately do NOT support batch
//! requests (the spec allows `[req, req, ...]` as an array; almost no
//! Electrum client uses it and it complicates per-request timeouts +
//! subscription state). A batch request sees a JSON-RPC error.

use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedReadHalf;

/// Per-line read cap. A malformed or unbounded write from a client
/// must not OOM the server. 1 MiB is well above any legitimate
/// Electrum request (a `transaction.broadcast` of a maximum-size
/// 400 KB tx is the largest practical case, even hex-encoded).
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum FramingError {
    #[error("connection closed")]
    Closed,
    #[error("line exceeded {0} byte cap")]
    TooLong(usize),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid utf-8 in request line")]
    Utf8,
}

/// Read one newline-terminated line into `buf` (cleared first).
/// Returns the line as `&str` if it's valid UTF-8 within the cap.
///
/// Why not `BufRead::read_line`: it has no built-in cap, so a
/// pathological client sending an unbounded line would grow `buf`
/// without limit. We read byte-by-byte until `\n` or `MAX_LINE_BYTES`,
/// matching electrs's careful framing.
pub async fn read_line_bounded<'a>(
    reader: &mut BufReader<OwnedReadHalf>,
    buf: &'a mut Vec<u8>,
    cap: usize,
) -> Result<&'a str, FramingError> {
    buf.clear();
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Err(FramingError::Closed);
        }
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            // Take through the newline; consume from the buffer.
            buf.extend_from_slice(&chunk[..pos]);
            reader.consume(pos + 1);
            break;
        } else {
            // No newline yet; consume what we have. If absorbing the
            // chunk would exceed the cap we bail BEFORE growing `buf`,
            // so a 100 MB no-newline write can't even land.
            if buf.len() + chunk.len() > cap {
                return Err(FramingError::TooLong(cap));
            }
            buf.extend_from_slice(chunk);
            let len = chunk.len();
            reader.consume(len);
        }
        if buf.len() > cap {
            return Err(FramingError::TooLong(cap));
        }
    }
    // Trim a trailing \r if the client sent CRLF.
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    std::str::from_utf8(buf).map_err(|_| FramingError::Utf8)
}

/// Write a single JSON line + `\n` to the writer half. Flushes once
/// per call so partial writes don't leave a half-line in the kernel
/// send buffer when the connection closes.
pub async fn write_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    json: &str,
) -> Result<(), FramingError> {
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    /// Bind a listener, connect to it, return both ends.
    async fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let connect_fut = TcpStream::connect(addr);
        let accept_fut = async { l.accept().await.unwrap().0 };
        let (a, b) = tokio::join!(connect_fut, accept_fut);
        (a.unwrap(), b)
    }

    #[tokio::test]
    async fn read_line_handles_simple_message() {
        let (mut client, server) = pair().await;
        let (rd, _wr) = server.into_split();
        let mut reader = BufReader::new(rd);
        let mut buf = Vec::new();
        let written = tokio::spawn(async move {
            client.write_all(b"hello\n").await.unwrap();
            client.flush().await.unwrap();
            client
        });
        let line = read_line_bounded(&mut reader, &mut buf, MAX_LINE_BYTES)
            .await
            .unwrap();
        assert_eq!(line, "hello");
        let _ = written.await;
    }

    #[tokio::test]
    async fn read_line_strips_crlf() {
        let (mut client, server) = pair().await;
        let (rd, _wr) = server.into_split();
        let mut reader = BufReader::new(rd);
        let mut buf = Vec::new();
        let _hs = tokio::spawn(async move {
            client.write_all(b"hi\r\n").await.unwrap();
            client.flush().await.unwrap();
            client
        });
        let line = read_line_bounded(&mut reader, &mut buf, MAX_LINE_BYTES)
            .await
            .unwrap();
        assert_eq!(line, "hi");
    }

    #[tokio::test]
    async fn read_line_caps_oversize_input() {
        let (mut client, server) = pair().await;
        let (rd, _wr) = server.into_split();
        let mut reader = BufReader::new(rd);
        let mut buf = Vec::new();
        let _hs = tokio::spawn(async move {
            // 10 KB without a newline.
            let blob = vec![b'x'; 10_000];
            client.write_all(&blob).await.unwrap();
            client.flush().await.unwrap();
            // hold the connection so the server reads to EOF only
            // when we want it to.
            let _ = client;
        });
        // Cap at 4 KB — must error with TooLong, not OOM.
        let res = read_line_bounded(&mut reader, &mut buf, 4096).await;
        assert!(matches!(res, Err(FramingError::TooLong(4096))));
    }

    #[tokio::test]
    async fn read_line_returns_closed_on_eof() {
        let (client, server) = pair().await;
        drop(client); // close before sending anything
        let (rd, _wr) = server.into_split();
        let mut reader = BufReader::new(rd);
        let mut buf = Vec::new();
        let res = read_line_bounded(&mut reader, &mut buf, MAX_LINE_BYTES).await;
        assert!(matches!(res, Err(FramingError::Closed)));
    }

    #[tokio::test]
    async fn write_line_appends_newline_and_flushes() {
        let (client, server) = pair().await;
        let (mut rd, _wr) = client.into_split();
        let (_srd, mut swr) = server.into_split();
        let h = tokio::spawn(async move {
            write_line(&mut swr, r#"{"ok":1}"#).await.unwrap();
            swr.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut rd, &mut got)
            .await
            .unwrap();
        assert_eq!(got, b"{\"ok\":1}\n");
        h.await.unwrap();
    }
}
