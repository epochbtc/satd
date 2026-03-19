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

    #[test]
    fn test_target_addr_format() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8333));
        assert_eq!(addr.to_string(), "127.0.0.1:8333");
    }
}
