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
