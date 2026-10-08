//! The v1 frame limit, the receive buffer's growth and release, and send
//! progress, against Bitcoin Core's `V1Transport` and `SocketSendData`.

use super::*;
use bitcoin::p2p::message::CommandString;
use std::io::Cursor;
use std::time::Duration;

/// A reader that records the largest read it was asked for.
struct MaxAsk<R> {
    inner: R,
    max: usize,
}

impl<R: AsyncRead + Unpin> AsyncRead for MaxAsk<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.max = self.max.max(buf.remaining());
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

fn unknown(len: usize) -> NetworkMessage {
    NetworkMessage::Unknown {
        command: CommandString::try_from_static("bigmsg").unwrap(),
        payload: vec![0x5a; len],
    }
}

fn frame(msg: NetworkMessage) -> Vec<u8> {
    serialize(&RawNetworkMessage::new(Magic::REGTEST, msg))
}

/// Core's `MAX_PROTOCOL_MESSAGE_LENGTH` is 4,000,000 bytes, and a header
/// announcing more ends the connection (`V1Transport::readHeader`). satd
/// took frames up to 32 MiB.
#[tokio::test]
async fn a_frame_over_four_million_bytes_is_refused() {
    let mut buf = Vec::new();
    let mut ok = Cursor::new(frame(unknown(4_000_000)));
    let got = recv_message(&mut ok, Magic::REGTEST, &mut buf, None).await;
    assert!(matches!(got, Ok(NetworkMessage::Unknown { ref payload, .. }) if payload.len() == 4_000_000));

    let mut over = Cursor::new(frame(unknown(4_000_001)));
    let err = recv_message(&mut over, Magic::REGTEST, &mut buf, None)
        .await
        .expect_err("a 4,000,001-byte payload is refused");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
}

/// Core grows the receive buffer as payload bytes arrive, never more than
/// 256 KiB ahead of them (`V1Transport::readData`). satd allocated the whole
/// announced payload before reading any of it, so a peer could make it hold
/// a full frame per connection by announcing one and sending nothing.
#[tokio::test]
async fn the_payload_buffer_grows_with_the_bytes_received() {
    let mut bytes = frame(unknown(4_000_000));
    bytes.truncate(HEADER_SIZE + 1000);
    let mut reader = MaxAsk { inner: Cursor::new(bytes), max: 0 };
    let mut buf = Vec::new();
    let err = recv_message(&mut reader, Magic::REGTEST, &mut buf, None)
        .await
        .expect_err("the payload never arrives");
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    assert!(reader.max <= PAYLOAD_ALLOC_STEP, "asked for {} bytes at once", reader.max);
    assert!(buf.capacity() <= HEADER_SIZE + 2 * PAYLOAD_ALLOC_STEP, "holding {} bytes", buf.capacity());
}

/// The receive buffer is reused between messages, but not at the size of
/// the largest message the connection ever carried.
#[tokio::test]
async fn the_receive_buffer_is_released_after_a_large_message() {
    let mut bytes = frame(unknown(1_000_000));
    bytes.extend(frame(NetworkMessage::Ping(7)));
    let mut reader = Cursor::new(bytes);
    let mut buf = Vec::new();
    let big = recv_message(&mut reader, Magic::REGTEST, &mut buf, None).await.unwrap();
    assert!(matches!(big, NetworkMessage::Unknown { .. }));
    assert!(buf.capacity() <= RECV_BUF_KEEP, "kept {} bytes after a 1 MB message", buf.capacity());
    let small = recv_message(&mut reader, Magic::REGTEST, &mut buf, None).await.unwrap();
    assert_eq!(small, NetworkMessage::Ping(7));
}

/// Bytes are counted as the socket takes them, not once the whole message
/// is out: Core's `m_last_send` and `nSendBytes` move on every partial send
/// (`SocketSendData`), and the send timeout is measured against that.
#[tokio::test]
async fn a_send_counts_its_bytes_as_the_socket_takes_them() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (dialed, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    // The far end never reads.
    let (_far, _) = accepted.unwrap();
    let conn = Connection::with_magic(dialed.unwrap(), Magic::REGTEST);
    let (_reader, mut writer) = conn.split();
    let stats = PeerStats::new(crate::net::stats::NetTotals::new());
    writer.set_counters(stats.clone());

    let msg_len = frame(unknown(3_900_000)).len() as u64;
    let mut completed = 0u64;
    while let Ok(r) = tokio::time::timeout(Duration::from_millis(500), writer.send(unknown(3_900_000))).await {
        r.unwrap();
        completed += msg_len;
        assert!(completed < 512 * 1024 * 1024, "the socket never filled");
    }
    assert!(
        stats.bytes_sent() > completed,
        "a send the socket only partly took is not counted: {} sent, {completed} in whole messages",
        stats.bytes_sent()
    );
}
