//! TLS configuration loading for the JSON-RPC server.
//!
//! Operator supplies PEM-encoded certificate + private-key files via
//! `--rpctlscert` / `--rpctlskey`. We load them once at server start
//! and build a [`tokio_rustls::TlsAcceptor`]. Bitcoin Core's RPC is
//! HTTP-only by design; this is a satd-specific addition for operators
//! who want native TLS without a reverse proxy.
//!
//! Mirrors `electrum-proto::tls` and `esplora-handlers::tls` so a
//! single operator mental model covers all three surfaces.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use thiserror::Error;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, Error)]
pub enum TlsConfigError {
    #[error("cannot read TLS file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("no certificates found in {path}")]
    NoCerts { path: String },
    #[error("malformed certificate in {path}: {source}")]
    BadCert {
        path: String,
        source: std::io::Error,
    },
    #[error("no private key found in {path}")]
    NoKey { path: String },
    #[error("rustls config: {0}")]
    Rustls(String),
}

/// Build a [`TlsAcceptor`] from the cert + key paths in the config.
/// Validates that both paths actually parse before returning, so a
/// startup-time misconfiguration becomes a hard error rather than a
/// per-connection mystery later.
pub fn build_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor, TlsConfigError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsConfigError::Rustls(e.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    let path_str = path.display().to_string();
    let file = File::open(path).map_err(|source| TlsConfigError::Io {
        path: path_str.clone(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    // Collect into `Result<Vec<_>, _>` instead of
    // `filter_map(Result::ok)`. A malformed PEM block mixed with
    // valid certs would otherwise be silently discarded — startup
    // succeeds with a partial chain that fails handshakes later.
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsConfigError::BadCert {
            path: path_str.clone(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsConfigError::NoCerts { path: path_str });
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsConfigError> {
    let path_str = path.display().to_string();
    let file = File::open(path).map_err(|source| TlsConfigError::Io {
        path: path_str.clone(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|source| TlsConfigError::Io {
            path: path_str.clone(),
            source,
        })?
        .ok_or(TlsConfigError::NoKey { path: path_str })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_pem(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::File::create(&p)
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        p
    }

    #[test]
    fn build_acceptor_succeeds_with_valid_pem() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let acceptor = build_acceptor(&cert_path, &key_path);
        assert!(acceptor.is_ok());
    }

    #[test]
    fn missing_cert_file_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let result = build_acceptor(&dir.path().join("missing.pem"), &key_path);
        assert!(matches!(result, Err(TlsConfigError::Io { .. })));
    }

    #[test]
    fn empty_cert_file_is_no_certs_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_path = write_pem(dir.path(), "cert.pem", "");
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let result = build_acceptor(&cert_path, &key_path);
        assert!(matches!(result, Err(TlsConfigError::NoCerts { .. })));
    }

    #[test]
    fn missing_key_file_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let result = build_acceptor(&cert_path, &dir.path().join("missing.pem"));
        assert!(matches!(result, Err(TlsConfigError::Io { .. })));
    }
}
