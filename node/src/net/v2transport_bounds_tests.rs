//! The v2 receive buffer's growth and send progress, against Bitcoin Core's
//! `V2Transport::ReceivedBytes` and `SocketSendData`.

use super::*;
use std::time::Duration;
use tokio::net::TcpListener;

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

/// Core grows a v2 packet buffer as the bytes arrive, never more than
/// `MAX_RESERVE_AHEAD` (256 KiB) past them. satd allocated the whole
/// announced packet before reading any of it.
#[tokio::test]
async fn a_packet_buffer_grows_with_the_bytes_received() {
    let mut reader = MaxAsk { inner: std::io::Cursor::new(vec![7u8; 1000]), max: 0 };
    let mut leftover = vec![1u8; 10];
    let err = read_exact_buffered(&mut reader, &mut leftover, 4_000_000)
        .await
        .expect_err("the packet never arrives");
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    assert!(reader.max <= MAX_RESERVE_AHEAD, "asked for {} bytes at once", reader.max);

    // And a packet that does arrive is read whole, leftover first.
    let mut reader = std::io::Cursor::new((0..600_000u32).map(|i| i as u8).collect::<Vec<u8>>());
    let mut leftover = vec![0xee; 3];
    let got = read_exact_buffered(&mut reader, &mut leftover, 500_003).await.unwrap();
    assert_eq!(got.len(), 500_003);
    assert_eq!(&got[..3], &[0xee; 3]);
    assert_eq!(got[3..], (0..500_000u32).map(|i| i as u8).collect::<Vec<u8>>()[..]);
    assert!(leftover.is_empty());
}

/// Bytes are counted as the socket takes them, as on v1.
#[tokio::test]
async fn a_send_counts_its_bytes_as_the_socket_takes_them() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let (cipher, leftover) = responder_handshake(&mut sock, Network::Regtest, &[], 1, None).await.unwrap();
        V2Connection::new(sock, cipher, leftover)
    });
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (cipher, leftover) = initiator_handshake(&mut client, Network::Regtest, 2, None).await.unwrap();
    let client = V2Connection::new(client, cipher, leftover);
    // The far end never reads.
    let _server = server.await.unwrap();
    let (_reader, mut writer) = client.split();
    let stats = PeerStats::new(crate::net::stats::NetTotals::new());
    writer.set_counters(stats.clone());

    let msg = || NetworkMessage::Unknown {
        command: bitcoin::p2p::message::CommandString::try_from_static("bigmsg").unwrap(),
        payload: vec![0x5a; 3_900_000],
    };
    let mut completed = 0u64;
    while let Ok(r) = tokio::time::timeout(Duration::from_millis(500), writer.send(msg())).await {
        r.unwrap();
        completed = stats.bytes_sent();
        assert!(completed < 512 * 1024 * 1024, "the socket never filled");
    }
    assert!(
        stats.bytes_sent() > completed,
        "a send the socket only partly took is not counted: {} sent, {completed} in whole messages",
        stats.bytes_sent()
    );
}
