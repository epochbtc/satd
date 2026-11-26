use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_socks::IntoTargetAddr;
use tokio_socks::tcp::Socks5Stream;

/// Per-connection SOCKS5 username/password. Tor treats the auth pair as a
/// stream-isolation token (`IsolateSOCKSAuth`, on by default): connections that
/// present distinct credentials are placed on distinct circuits. Supplying a
/// fresh random pair per dial therefore gives each peer its own circuit, so a
/// single guard/exit can't correlate the whole peer set — matching Bitcoin
/// Core's `-proxyrandomize`. `None` uses unauthenticated SOCKS (all streams
/// may share circuits).
pub type SocksCred<'a> = Option<(&'a str, &'a str)>;

/// How long a SOCKS5 dial may take, split the way Bitcoin Core splits it.
///
/// Core's `ConnectThroughProxy` bounds the TCP connect to the proxy by
/// `-timeout` (`nConnectTimeout`), then gives each read of the SOCKS5
/// exchange its own `SOCKS5_RECV_TIMEOUT` of 20 s (netbase.cpp). The proxy is
/// usually local, so the first leg is fast; the second carries the proxy's own
/// connect to the target — for Tor, a circuit build per isolated stream — and
/// routinely runs past a 5 s `-timeout`.
#[derive(Clone, Copy, Debug)]
pub struct DialTimeouts {
    /// Bound on the TCP connect to the proxy itself.
    pub proxy_connect: Duration,
    /// Bound on the SOCKS5 greeting, authentication and CONNECT reply.
    pub exchange: Duration,
}

/// Connect to a target address through a SOCKS5 proxy.
/// Returns a TcpStream tunneled through the proxy.
pub async fn connect_socks5(
    proxy_addr: &str,
    target: SocketAddr,
    cred: SocksCred<'_>,
    timeouts: DialTimeouts,
) -> Result<TcpStream, String> {
    socks5_connect(proxy_addr, target, cred, timeouts)
        .await
        .map_err(|e| format!("SOCKS5 connect to {} failed: {}", target, e))
}

/// Connect to a host name through a SOCKS5 proxy, which resolves it: a
/// SOCKS5 domain-name CONNECT, so no lookup happens here. How a proxied node
/// reaches a DNS seed or a `-seednode` hostname without a local DNS query,
/// as Core's `ConnectNode` does through its name proxy.
pub async fn connect_socks5_name(
    proxy_addr: &str,
    host: &str,
    port: u16,
    cred: SocksCred<'_>,
    timeouts: DialTimeouts,
) -> Result<TcpStream, String> {
    socks5_connect(proxy_addr, (host, port), cred, timeouts)
        .await
        .map_err(|e| format!("SOCKS5 connect to {host}:{port} failed: {e}"))
}

/// Connect to a .onion address through a SOCKS5 proxy.
/// Uses hostname-based SOCKS5 CONNECT (the proxy resolves the .onion).
pub async fn connect_socks5_onion(
    proxy_addr: &str,
    onion_host: &str,
    port: u16,
    cred: SocksCred<'_>,
    timeouts: DialTimeouts,
) -> Result<TcpStream, String> {
    socks5_connect(proxy_addr, (onion_host, port), cred, timeouts)
        .await
        .map_err(|e| format!("SOCKS5 onion connect to {} failed: {}", onion_host, e))
}

async fn socks5_connect<'t>(
    proxy_addr: &str,
    target: impl IntoTargetAddr<'t>,
    cred: SocksCred<'_>,
    timeouts: DialTimeouts,
) -> Result<TcpStream, String> {
    let socket = tokio::time::timeout(timeouts.proxy_connect, TcpStream::connect(proxy_addr))
        .await
        .map_err(|_| {
            format!(
                "proxy {proxy_addr} did not accept within {}ms",
                timeouts.proxy_connect.as_millis()
            )
        })?
        .map_err(|e| format!("proxy {proxy_addr} unreachable: {e}"))?;
    let exchange = async {
        match cred {
            Some((user, pass)) => {
                Socks5Stream::connect_with_password_and_socket(socket, target, user, pass).await
            }
            None => Socks5Stream::connect_with_socket(socket, target).await,
        }
    };
    let stream = tokio::time::timeout(timeouts.exchange, exchange)
        .await
        .map_err(|_| {
            format!(
                "proxy exchange timed out after {}ms",
                timeouts.exchange.as_millis()
            )
        })?
        .map_err(|e| e.to_string())?;
    Ok(stream.into_inner())
}

/// Which side of a SOCKS5 dial failed: the proxy, or the target behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Failure {
    /// The proxy itself: it could not be reached, its greeting failed, or
    /// it answered the CONNECT in a way that says it cannot serve it
    /// (command or address type not supported, an unassigned reply code,
    /// a malformed reply). Nothing is known of the target.
    Proxy(String),
    /// The proxy took the CONNECT and got no answer from the target: reply
    /// 0x01 (general failure), 0x02 (not allowed by ruleset: the proxy's
    /// own policy, given without contacting the target), 0x03 (network
    /// unreachable), 0x04 (host unreachable) or 0x06 (TTL expired), no
    /// reply by the deadline, or the proxy closing the connection instead
    /// of replying. The target's, but also what a proxy whose own uplink is
    /// down gives for every target.
    Target(String),
    /// The target answered, with a refusal: reply 0x05 (connection
    /// refused). The target's, and proof that the proxy reaches the
    /// network.
    Refused(String),
}

/// Send the CONNECT request by `deadline`. A failure here is the proxy's:
/// the target was never asked.
async fn send_request<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    request: &[u8],
    deadline: tokio::time::Instant,
    proxy_addr: SocketAddr,
) -> Result<(), Socks5Failure> {
    use tokio::io::AsyncWriteExt as _;
    match tokio::time::timeout_at(deadline, w.write_all(request)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(Socks5Failure::Proxy(format!(
            "proxy {proxy_addr}: request not sent: {e}"
        ))),
        Err(_) => Err(Socks5Failure::Proxy(format!(
            "proxy {proxy_addr}: request not sent in time"
        ))),
    }
}

/// Connect to `target` through a no-authentication SOCKS5 proxy at
/// `proxy_addr`, telling a failure of the proxy from a failure of the
/// target ([`Socks5Failure`]). The TCP connect to the proxy is bounded by
/// `proxy_connect`, and the whole dial, greeting and CONNECT reply
/// included, by `deadline`.
///
/// Written out rather than through `tokio_socks`, whose single error does
/// not say whether a timeout or an EOF came during the greeting (the proxy)
/// or while the proxy dialled the target. 0x01, general failure, is the
/// target's: a proxy that answered the greeting is up, and a code given per
/// CONNECT held against the proxy would redial that target for ever. Every
/// stage is bounded by `deadline`, the request's write included.
pub async fn connect_socks5_staged(
    proxy_addr: SocketAddr,
    target: SocketAddr,
    proxy_connect: Duration,
    deadline: tokio::time::Instant,
) -> Result<TcpStream, Socks5Failure> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let proxy_err = |what: &str| Socks5Failure::Proxy(format!("proxy {proxy_addr}: {what}"));
    let connect_by = deadline.min(tokio::time::Instant::now() + proxy_connect);
    let mut sock = match tokio::time::timeout_at(connect_by, TcpStream::connect(proxy_addr)).await {
        Err(_) => return Err(proxy_err("did not accept in time")),
        Ok(Err(e)) => return Err(proxy_err(&format!("unreachable: {e}"))),
        Ok(Ok(s)) => s,
    };
    // Greeting: version 5, one method, no authentication.
    let greeting = async {
        sock.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut choice = [0u8; 2];
        sock.read_exact(&mut choice).await?;
        Ok::<_, std::io::Error>(choice)
    };
    match tokio::time::timeout_at(deadline, greeting).await {
        Err(_) => return Err(proxy_err("no greeting reply in time")),
        Ok(Err(e)) => return Err(proxy_err(&format!("greeting failed: {e}"))),
        Ok(Ok([0x05, 0x00])) => {}
        Ok(Ok(choice)) => {
            return Err(proxy_err(&format!(
                "refused the greeting (version {}, method {:#04x})",
                choice[0], choice[1]
            )));
        }
    }
    let mut request = vec![0x05, 0x01, 0x00];
    match target.ip().to_canonical() {
        std::net::IpAddr::V4(v4) => {
            request.push(0x01);
            request.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            request.push(0x04);
            request.extend_from_slice(&v6.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    send_request(&mut sock, &request, deadline, proxy_addr).await?;
    // The reply's head: version, reply code, reserved, address type.
    let mut head = [0u8; 4];
    match tokio::time::timeout_at(deadline, sock.read_exact(&mut head)).await {
        Err(_) => {
            return Err(Socks5Failure::Target(format!(
                "{target}: no CONNECT reply in time"
            )));
        }
        Ok(Err(e)) => {
            return Err(Socks5Failure::Target(format!(
                "{target}: the proxy closed without a reply: {e}"
            )));
        }
        Ok(Ok(_)) => {}
    }
    if head[0] != 0x05 {
        return Err(proxy_err(&format!("reply version {}", head[0])));
    }
    let reason = match head[1] {
        0x00 => None,
        0x01 => Some("general failure"),
        0x02 => Some("not allowed by ruleset"),
        0x03 => Some("network unreachable"),
        0x04 => Some("host unreachable"),
        0x05 => Some("connection refused"),
        0x06 => Some("TTL expired"),
        0x07 => return Err(proxy_err("CONNECT not supported")),
        0x08 => return Err(proxy_err("address type not supported")),
        code => return Err(proxy_err(&format!("unassigned reply code {code:#04x}"))),
    };
    if let Some(reason) = reason {
        let why = format!("{target}: {reason} (SOCKS5 reply {:#04x})", head[1]);
        return Err(if head[1] == 0x05 {
            Socks5Failure::Refused(why)
        } else {
            Socks5Failure::Target(why)
        });
    }
    // The bound address, which nothing here needs.
    let rest = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            match tokio::time::timeout_at(deadline, sock.read_exact(&mut len)).await {
                Ok(Ok(_)) => usize::from(len[0]) + 2,
                _ => return Err(proxy_err("truncated reply")),
            }
        }
        atyp => return Err(proxy_err(&format!("reply address type {atyp}"))),
    };
    let mut bound = vec![0u8; rest];
    match tokio::time::timeout_at(deadline, sock.read_exact(&mut bound)).await {
        Ok(Ok(_)) => Ok(sock),
        _ => Err(proxy_err("truncated reply")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn roomy() -> DialTimeouts {
        DialTimeouts {
            proxy_connect: Duration::from_secs(5),
            exchange: Duration::from_secs(5),
        }
    }

    /// A no-auth SOCKS5 server that answers the CONNECT only after `delay`,
    /// as Tor does while it builds a circuit to the target.
    async fn fake_socks5_slow_connect(listener: TcpListener, delay: Duration) {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut head = [0u8; 2];
        sock.read_exact(&mut head).await.expect("greeting head");
        let mut methods = vec![0u8; head[1] as usize];
        sock.read_exact(&mut methods).await.expect("methods");
        sock.write_all(&[0x05, 0x00]).await.expect("select no-auth");
        // VER CMD RSV ATYP=IPv4, 4 address bytes, 2 port bytes.
        let mut req = [0u8; 10];
        sock.read_exact(&mut req).await.expect("request");
        tokio::time::sleep(delay).await;
        let _ = sock
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        let _ = sock.flush().await;
        // Hold the socket so the client sees the reply, not an EOF.
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    /// The proxy's CONNECT reply is bounded by the exchange budget, not by
    /// the proxy-connect one: a reply slower than `-timeout` but inside the
    /// exchange budget completes the dial, as it does under Core's
    /// `SOCKS5_RECV_TIMEOUT`.
    #[tokio::test]
    async fn slow_connect_reply_within_exchange_budget_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = listener.local_addr().expect("addr").to_string();
        let server = tokio::spawn(fake_socks5_slow_connect(
            listener,
            Duration::from_millis(600),
        ));

        let target: SocketAddr = "203.0.113.7:8333".parse().unwrap();
        let timeouts = DialTimeouts {
            proxy_connect: Duration::from_millis(200),
            exchange: Duration::from_secs(5),
        };
        let dial = connect_socks5(&proxy_addr, target, None, timeouts).await;
        assert!(
            dial.is_ok(),
            "a CONNECT reply inside the exchange budget must succeed: {dial:?}"
        );
        server.abort();
    }

    /// A proxy that never answers the CONNECT fails the dial once the
    /// exchange budget runs out.
    #[tokio::test]
    async fn connect_reply_past_exchange_budget_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = listener.local_addr().expect("addr").to_string();
        let server = tokio::spawn(fake_socks5_slow_connect(listener, Duration::from_secs(5)));

        let target: SocketAddr = "203.0.113.7:8333".parse().unwrap();
        let timeouts = DialTimeouts {
            proxy_connect: Duration::from_secs(5),
            exchange: Duration::from_millis(300),
        };
        let started = std::time::Instant::now();
        let dial = connect_socks5(&proxy_addr, target, None, timeouts).await;
        let err = dial.expect_err("a CONNECT reply past the exchange budget must fail");
        assert!(
            err.contains("exchange timed out"),
            "unexpected error: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the dial must not wait for the reply"
        );
        server.abort();
    }

    #[test]
    fn test_target_addr_format() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8333));
        assert_eq!(addr.to_string(), "127.0.0.1:8333");
    }

    /// A minimal SOCKS5 server that completes one no-auth CONNECT and reports
    /// back the address type, host bytes, and port the client requested. It
    /// does NOT resolve anything — it just records what the client sent.
    async fn fake_socks5_capture(listener: TcpListener) -> (u8, Vec<u8>, u16) {
        let (mut sock, _) = listener.accept().await.expect("accept");

        // Greeting: VER=0x05, NMETHODS, METHODS...
        let mut head = [0u8; 2];
        sock.read_exact(&mut head)
            .await
            .expect("read greeting head");
        assert_eq!(head[0], 0x05, "SOCKS version must be 5");
        let nmethods = head[1] as usize;
        let mut methods = vec![0u8; nmethods];
        sock.read_exact(&mut methods).await.expect("read methods");
        // Select "no authentication required".
        sock.write_all(&[0x05, 0x00])
            .await
            .expect("write method choice");

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
        let dial = connect_socks5_onion(&proxy_addr, onion, 8333, None, roomy()).await;
        assert!(dial.is_ok(), "onion dial should succeed: {dial:?}");

        let (atyp, host_bytes, port) =
            tokio::time::timeout(std::time::Duration::from_secs(5), server)
                .await
                .expect("server did not finish")
                .expect("server task panicked");

        assert_eq!(
            atyp, 0x03,
            "onion must use domain-name address type, not a resolved IP"
        );
        assert_eq!(
            host_bytes,
            onion.as_bytes(),
            "the exact .onion hostname must be passed through unresolved"
        );
        assert_eq!(port, 8333, "target port must be preserved");
    }

    /// #994: a DNS seed or `-seednode` host name reached through the proxy
    /// goes as a SOCKS5 domain name (type 0x03), for the proxy to resolve:
    /// a local lookup would leak it. Perturbation: hand the proxy an IP
    /// address in its place and the address type is 0x01.
    #[tokio::test]
    async fn a_name_dial_sends_the_name_unresolved() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = listener.local_addr().expect("addr").to_string();
        let server = tokio::spawn(fake_socks5_capture(listener));

        let dial = connect_socks5_name(&proxy_addr, "seed.example.org", 8333, None, roomy()).await;
        assert!(dial.is_ok(), "name dial should succeed: {dial:?}");
        let (atyp, host_bytes, port) =
            tokio::time::timeout(std::time::Duration::from_secs(5), server)
                .await
                .expect("server did not finish")
                .expect("server task panicked");
        assert_eq!(atyp, 0x03);
        assert_eq!(host_bytes, b"seed.example.org");
        assert_eq!(port, 8333);
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
        assert!(
            methods.contains(&0x02),
            "client must offer username/password auth"
        );
        sock.write_all(&[0x05, 0x02])
            .await
            .expect("select userpass");

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
        let dial = connect_socks5(
            &proxy_addr,
            target,
            Some(("iso-tok-42", "iso-tok-42")),
            roomy(),
        )
        .await;
        assert!(dial.is_ok(), "credentialed dial should succeed: {dial:?}");

        let (user, pass) = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server did not finish")
            .expect("server task panicked");
        assert_eq!(
            user, "iso-tok-42",
            "isolation username must reach the proxy"
        );
        assert_eq!(
            pass, "iso-tok-42",
            "isolation password must reach the proxy"
        );
    }

    /// How the staged-dial test proxy behaves.
    #[derive(Clone, Copy)]
    enum Staged {
        /// Answer the greeting, then the CONNECT with this reply code, and
        /// the IPv6 or IPv4 request it got.
        Reply(u8),
        /// Accept and say nothing.
        SilentGreeting,
        /// Answer the greeting with a method it was not offered.
        WrongMethod,
        /// Answer the greeting, then say nothing to the CONNECT.
        SilentConnect,
        /// Answer the greeting, then close on the CONNECT.
        CloseOnConnect,
    }

    /// A one-connection proxy behaving as `how`; the request's address
    /// type comes back.
    async fn staged_proxy(how: Staged) -> (SocketAddr, tokio::task::JoinHandle<Option<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.ok()?;
            if let Staged::SilentGreeting = how {
                tokio::time::sleep(Duration::from_secs(10)).await;
                return None;
            }
            let mut head = [0u8; 2];
            sock.read_exact(&mut head).await.ok()?;
            let mut methods = vec![0u8; head[1] as usize];
            sock.read_exact(&mut methods).await.ok()?;
            if let Staged::WrongMethod = how {
                let _ = sock.write_all(&[0x05, 0xff]).await;
                tokio::time::sleep(Duration::from_secs(10)).await;
                return None;
            }
            sock.write_all(&[0x05, 0x00]).await.ok()?;
            let mut req = [0u8; 4];
            sock.read_exact(&mut req).await.ok()?;
            let len = if req[3] == 0x04 { 16 } else { 4 };
            let mut rest = vec![0u8; len + 2];
            sock.read_exact(&mut rest).await.ok()?;
            match how {
                Staged::Reply(code) => {
                    let _ = sock
                        .write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
                Staged::SilentConnect => tokio::time::sleep(Duration::from_secs(10)).await,
                _ => {}
            }
            Some(req[3])
        });
        (addr, task)
    }

    async fn staged(proxy: SocketAddr, target: &str) -> Result<TcpStream, Socks5Failure> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(800);
        connect_socks5_staged(
            proxy,
            target.parse().unwrap(),
            Duration::from_secs(2),
            deadline,
        )
        .await
    }

    /// A staged dial tells the proxy's failures from the target's: a
    /// proxy nothing listens on, one that never greets, or one that refuses
    /// the greeting fails as the proxy; a CONNECT the proxy cannot serve
    /// (0x07, 0x08, an unassigned code) too, and a request the proxy does
    /// not take by the deadline. Replies 0x01, 0x03, 0x04 and 0x06, no reply
    /// in time, and a close instead of a reply are the target's, no answer;
    /// 0x02 (the proxy's ruleset, which never asked the target) too; 0x05
    /// the target's, a refusal.
    /// Perturbation: map 0x05 to `Proxy` and the refused case fails here;
    /// leave the request's write unbounded and the blocked write outlives
    /// the test's own bound.
    #[tokio::test]
    async fn a_staged_dial_tells_the_proxy_from_the_target() {
        let (ok, task) = staged_proxy(Staged::Reply(0x00)).await;
        assert!(staged(ok, "203.0.113.7:8333").await.is_ok());
        assert_eq!(task.await.unwrap(), Some(0x01), "IPv4 by address");
        let (ok6, task) = staged_proxy(Staged::Reply(0x00)).await;
        assert!(staged(ok6, "[2001:db8::7]:8333").await.is_ok());
        assert_eq!(task.await.unwrap(), Some(0x04), "IPv6 by address");

        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        assert!(matches!(
            staged(closed, "203.0.113.7:8333").await,
            Err(Socks5Failure::Proxy(_))
        ));
        for how in [Staged::SilentGreeting, Staged::WrongMethod] {
            let (p, _t) = staged_proxy(how).await;
            assert!(matches!(
                staged(p, "203.0.113.7:8333").await,
                Err(Socks5Failure::Proxy(_))
            ));
        }
        for code in [0x07u8, 0x08, 0x09, 0xff] {
            let (p, _t) = staged_proxy(Staged::Reply(code)).await;
            let got = staged(p, "203.0.113.7:8333").await;
            assert!(
                matches!(got, Err(Socks5Failure::Proxy(_))),
                "{code:#04x}: {got:?}"
            );
        }
        for code in [0x01u8, 0x02, 0x03, 0x04, 0x06] {
            let (p, _t) = staged_proxy(Staged::Reply(code)).await;
            let got = staged(p, "203.0.113.7:8333").await;
            assert!(
                matches!(got, Err(Socks5Failure::Target(_))),
                "{code:#04x}: {got:?}"
            );
        }
        for code in [0x05u8] {
            let (p, _t) = staged_proxy(Staged::Reply(code)).await;
            let got = staged(p, "203.0.113.7:8333").await;
            assert!(
                matches!(got, Err(Socks5Failure::Refused(_))),
                "{code:#04x}: {got:?}"
            );
        }
        // The request's write is bounded and the proxy's. A 10-byte write to
        // a loopback socket never blocks (the kernel buffers it), so the
        // stage is driven over a one-byte in-memory pipe: unread, the write
        // blocks past the deadline; with the far end gone, it fails.
        let any: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let request = [0x05u8, 0x01, 0x00, 0x01, 203, 0, 113, 7, 0x20, 0x8d];
        let (mut near, _far) = tokio::io::duplex(1);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
        let got = tokio::time::timeout(
            Duration::from_secs(2),
            send_request(&mut near, &request, deadline, any),
        )
        .await
        .expect("the request's write is bounded by the deadline");
        assert!(
            matches!(&got, Err(Socks5Failure::Proxy(e)) if e.contains("in time")),
            "{got:?}"
        );
        let (mut near, far) = tokio::io::duplex(1);
        drop(far);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let got = send_request(&mut near, &request, deadline, any).await;
        assert!(
            matches!(&got, Err(Socks5Failure::Proxy(e)) if e.contains("not sent")),
            "{got:?}"
        );
        for how in [Staged::SilentConnect, Staged::CloseOnConnect] {
            let (p, _t) = staged_proxy(how).await;
            let started = std::time::Instant::now();
            assert!(matches!(
                staged(p, "203.0.113.7:8333").await,
                Err(Socks5Failure::Target(_))
            ));
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "bounded by the deadline"
            );
        }
    }
}
