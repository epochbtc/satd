use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Connect to a target address through a SOCKS5 proxy.
/// Returns a TcpStream tunneled through the proxy.
pub async fn connect_socks5(
    proxy_addr: &str,
    target: SocketAddr,
) -> Result<TcpStream, String> {
    let stream = tokio_socks::tcp::Socks5Stream::connect(proxy_addr, target)
        .await
        .map_err(|e| format!("SOCKS5 connect to {} failed: {}", target, e))?;

    Ok(stream.into_inner())
}

/// Connect to a .onion address through a SOCKS5 proxy.
/// Uses hostname-based SOCKS5 CONNECT (the proxy resolves the .onion).
pub async fn connect_socks5_onion(
    proxy_addr: &str,
    onion_host: &str,
    port: u16,
) -> Result<TcpStream, String> {
    let stream = tokio_socks::tcp::Socks5Stream::connect(proxy_addr, (onion_host, port))
        .await
        .map_err(|e| format!("SOCKS5 onion connect to {} failed: {}", onion_host, e))?;

    Ok(stream.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_target_addr_format() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8333));
        assert_eq!(addr.to_string(), "127.0.0.1:8333");
    }

    /// A minimal SOCKS5 server that completes one no-auth CONNECT and reports
    /// back the address type, host bytes, and port the client requested. It
    /// does NOT resolve anything — it just records what the client sent.
    async fn fake_socks5_capture(
        listener: TcpListener,
    ) -> (u8, Vec<u8>, u16) {
        let (mut sock, _) = listener.accept().await.expect("accept");

        // Greeting: VER=0x05, NMETHODS, METHODS...
        let mut head = [0u8; 2];
        sock.read_exact(&mut head).await.expect("read greeting head");
        assert_eq!(head[0], 0x05, "SOCKS version must be 5");
        let nmethods = head[1] as usize;
        let mut methods = vec![0u8; nmethods];
        sock.read_exact(&mut methods).await.expect("read methods");
        // Select "no authentication required".
        sock.write_all(&[0x05, 0x00]).await.expect("write method choice");

        // Request: VER, CMD, RSV, ATYP
        let mut req = [0u8; 4];
        sock.read_exact(&mut req).await.expect("read request head");
        assert_eq!(req[0], 0x05, "request SOCKS version");
        assert_eq!(req[1], 0x01, "CMD must be CONNECT (0x01)");
        assert_eq!(req[2], 0x00, "RSV must be 0");
        let atyp = req[3];

        let host_bytes: Vec<u8> = match atyp {
            0x01 => {
                let mut a = [0u8; 4];
                sock.read_exact(&mut a).await.expect("read ipv4");
                a.to_vec()
            }
            0x03 => {
                let mut len = [0u8; 1];
                sock.read_exact(&mut len).await.expect("read domain len");
                let mut h = vec![0u8; len[0] as usize];
                sock.read_exact(&mut h).await.expect("read domain");
                h
            }
            0x04 => {
                let mut a = [0u8; 16];
                sock.read_exact(&mut a).await.expect("read ipv6");
                a.to_vec()
            }
            other => panic!("unexpected ATYP {other}"),
        };
        let mut port = [0u8; 2];
        sock.read_exact(&mut port).await.expect("read port");
        let port = u16::from_be_bytes(port);

        // Success reply: VER, REP=0x00, RSV, ATYP=IPv4, BND.ADDR(0.0.0.0), BND.PORT(0)
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .expect("write reply");
        let _ = sock.flush().await;

        (atyp, host_bytes, port)
    }

    /// The crux of Tor outbound privacy: a `.onion` target must be handed to the
    /// proxy as an *unresolved hostname* (SOCKS5 domain-name address type 0x03),
    /// never pre-resolved to an IP locally. Resolving locally would both leak a
    /// DNS lookup and fail (onion names aren't in the DNS). This drives the real
    /// `connect_socks5_onion` against a fake SOCKS5 server and asserts the wire
    /// bytes carry the onion hostname verbatim.
    #[tokio::test]
    async fn onion_dial_sends_unresolved_hostname() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = listener.local_addr().expect("addr").to_string();
        let server = tokio::spawn(fake_socks5_capture(listener));

        let onion = "g4bnddmokrstxrbjusq32lucfhffqrygqm3rm33w2qwftqvhxo3enoad.onion";
        let dial = connect_socks5_onion(&proxy_addr, onion, 8333).await;
        assert!(dial.is_ok(), "onion dial should succeed: {dial:?}");

        let (atyp, host_bytes, port) =
            tokio::time::timeout(std::time::Duration::from_secs(5), server)
                .await
                .expect("server did not finish")
                .expect("server task panicked");

        assert_eq!(atyp, 0x03, "onion must use domain-name address type, not a resolved IP");
        assert_eq!(
            host_bytes,
            onion.as_bytes(),
            "the exact .onion hostname must be passed through unresolved"
        );
        assert_eq!(port, 8333, "target port must be preserved");
    }
}
