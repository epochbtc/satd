use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Per-connection SOCKS5 username/password. Tor treats the auth pair as a
/// stream-isolation token (`IsolateSOCKSAuth`, on by default): connections that
/// present distinct credentials are placed on distinct circuits. Supplying a
/// fresh random pair per dial therefore gives each peer its own circuit, so a
/// single guard/exit can't correlate the whole peer set — matching Bitcoin
/// Core's `-proxyrandomize`. `None` uses unauthenticated SOCKS (all streams
/// may share circuits).
pub type SocksCred<'a> = Option<(&'a str, &'a str)>;

/// Connect to a target address through a SOCKS5 proxy.
/// Returns a TcpStream tunneled through the proxy.
pub async fn connect_socks5(
    proxy_addr: &str,
    target: SocketAddr,
    cred: SocksCred<'_>,
) -> Result<TcpStream, String> {
    let stream = match cred {
        Some((user, pass)) => {
            tokio_socks::tcp::Socks5Stream::connect_with_password(proxy_addr, target, user, pass)
                .await
        }
        None => tokio_socks::tcp::Socks5Stream::connect(proxy_addr, target).await,
    }
    .map_err(|e| format!("SOCKS5 connect to {} failed: {}", target, e))?;

    Ok(stream.into_inner())
}

/// Connect to a .onion address through a SOCKS5 proxy.
/// Uses hostname-based SOCKS5 CONNECT (the proxy resolves the .onion).
pub async fn connect_socks5_onion(
    proxy_addr: &str,
    onion_host: &str,
    port: u16,
    cred: SocksCred<'_>,
) -> Result<TcpStream, String> {
    let target = (onion_host, port);
    let stream = match cred {
        Some((user, pass)) => {
            tokio_socks::tcp::Socks5Stream::connect_with_password(proxy_addr, target, user, pass)
                .await
        }
        None => tokio_socks::tcp::Socks5Stream::connect(proxy_addr, target).await,
    }
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
        let dial = connect_socks5_onion(&proxy_addr, onion, 8333, None).await;
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

    /// A fake SOCKS5 server that *requires* username/password auth (method
    /// 0x02), captures the RFC 1929 credentials, then completes the CONNECT.
    /// Returns the (username, password) the client presented.
    async fn fake_socks5_userpass(listener: TcpListener) -> (String, String) {
        let (mut sock, _) = listener.accept().await.expect("accept");

        // Greeting; require the client to offer user/pass (0x02).
        let mut head = [0u8; 2];
        sock.read_exact(&mut head).await.expect("greeting head");
        let nmethods = head[1] as usize;
        let mut methods = vec![0u8; nmethods];
        sock.read_exact(&mut methods).await.expect("methods");
        assert!(methods.contains(&0x02), "client must offer username/password auth");
        sock.write_all(&[0x05, 0x02]).await.expect("select userpass");

        // RFC 1929: VER(0x01), ULEN, UNAME, PLEN, PASSWD.
        let mut v = [0u8; 1];
        sock.read_exact(&mut v).await.expect("auth ver");
        assert_eq!(v[0], 0x01, "auth subnegotiation version");
        let mut ulen = [0u8; 1];
        sock.read_exact(&mut ulen).await.expect("ulen");
        let mut uname = vec![0u8; ulen[0] as usize];
        sock.read_exact(&mut uname).await.expect("uname");
        let mut plen = [0u8; 1];
        sock.read_exact(&mut plen).await.expect("plen");
        let mut passwd = vec![0u8; plen[0] as usize];
        sock.read_exact(&mut passwd).await.expect("passwd");
        sock.write_all(&[0x01, 0x00]).await.expect("auth success");

        // CONNECT request — drain it (ATYP-dependent) and reply success.
        let mut req = [0u8; 4];
        sock.read_exact(&mut req).await.expect("request head");
        match req[3] {
            0x01 => {
                let mut a = [0u8; 4];
                sock.read_exact(&mut a).await.expect("ipv4");
            }
            0x03 => {
                let mut l = [0u8; 1];
                sock.read_exact(&mut l).await.expect("dlen");
                let mut h = vec![0u8; l[0] as usize];
                sock.read_exact(&mut h).await.expect("domain");
            }
            0x04 => {
                let mut a = [0u8; 16];
                sock.read_exact(&mut a).await.expect("ipv6");
            }
            other => panic!("unexpected ATYP {other}"),
        }
        let mut port = [0u8; 2];
        sock.read_exact(&mut port).await.expect("port");
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .expect("reply");
        let _ = sock.flush().await;

        (
            String::from_utf8_lossy(&uname).into_owned(),
            String::from_utf8_lossy(&passwd).into_owned(),
        )
    }

    /// Stream isolation: when credentials are supplied they must reach the
    /// proxy as RFC 1929 username/password — that auth pair is exactly the
    /// token Tor uses to assign a distinct circuit per peer.
    #[tokio::test]
    async fn isolation_sends_socks_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = listener.local_addr().expect("addr").to_string();
        let server = tokio::spawn(fake_socks5_userpass(listener));

        let target: SocketAddr = "203.0.113.7:8333".parse().unwrap();
        let dial = connect_socks5(&proxy_addr, target, Some(("iso-tok-42", "iso-tok-42"))).await;
        assert!(dial.is_ok(), "credentialed dial should succeed: {dial:?}");

        let (user, pass) = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server did not finish")
            .expect("server task panicked");
        assert_eq!(user, "iso-tok-42", "isolation username must reach the proxy");
        assert_eq!(pass, "iso-tok-42", "isolation password must reach the proxy");
    }
}
