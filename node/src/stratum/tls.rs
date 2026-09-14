//! The TLS side of a listener: handshake, then the mTLS allowlist.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tls_config::{ClientAllowList, TlsAcceptor};

/// How long a client gets to finish the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Complete the handshake and, when `mtls`, check the client certificate
/// against `allow`. `None` means the connection was dropped; the reason is
/// logged here.
pub async fn accept(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    peer: SocketAddr,
    mtls: bool,
    allow: &ClientAllowList,
) -> Option<TlsStream<TcpStream>> {
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!(target: "node::stratum", %peer, error = %e, "TLS handshake failed");
            return None;
        }
        Err(_) => {
            tracing::debug!(target: "node::stratum", %peer, "TLS handshake timed out");
            return None;
        }
    };
    // The allowlist only means something when a client certificate was
    // required: on a plain-TLS listener there is none, and a non-empty list
    // would refuse everyone. Config validation refuses that combination too.
    if mtls {
        let (_, conn) = tls.get_ref();
        if let Err(rejection) = tls_config::check_peer_allowed(conn, allow) {
            tracing::warn!(
                target: "node::stratum",
                %peer,
                subject = %rejection.subject_label,
                "Stratum mTLS client rejected by allowlist"
            );
            return None;
        }
        if let Some(subject) = tls_config::peer_subject_label(conn) {
            tracing::info!(target: "node::stratum", %peer, %subject, "Stratum mTLS client accepted");
        }
    }
    Some(tls)
}

/// Bytes of custom CA certificate ESP-Miner-based firmware (AxeOS) keeps: a
/// 512-byte buffer filled with `strlcpy`, so 511 characters of PEM. Anything
/// longer is truncated without an error and never verifies.
pub const MINER_CA_PEM_LIMIT: usize = 511;

/// The PEM size of the last certificate in a certificate file — in a full
/// chain, the CA a miner would import — when it exceeds
/// [`MINER_CA_PEM_LIMIT`].
pub fn oversized_miner_ca(pem: &str) -> Option<usize> {
    const END: &str = "-----END CERTIFICATE-----";
    let end = pem.rfind(END)? + END.len();
    let begin = pem[..end].rfind("-----BEGIN CERTIFICATE-----")?;
    // Count the newline that terminates the block, as a pasted file has one.
    let size = end - begin + 1;
    (size > MINER_CA_PEM_LIMIT).then_some(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(body_len: usize) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            "A".repeat(body_len)
        )
    }

    #[test]
    fn the_last_certificate_in_the_file_is_measured() {
        // 27 + 1 + body + 1 + 25 + 1 bytes.
        let small = block(400);
        assert_eq!(small.len(), 455);
        assert_eq!(oversized_miner_ca(&small), None);
        let big = block(600);
        assert_eq!(oversized_miner_ca(&big), Some(655));
        // A large leaf followed by a small CA is fine; the reverse is not.
        assert_eq!(oversized_miner_ca(&format!("{big}{small}")), None);
        assert_eq!(oversized_miner_ca(&format!("{small}{big}")), Some(655));
        assert_eq!(oversized_miner_ca("not a certificate"), None);
    }
}
