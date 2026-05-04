//! TLS configuration loading.
//!
//! Operator supplies PEM-encoded certificate + private-key files via
//! `--electrumtlscert` / `--electrumtlskey`. We load them once at
//! server start and build a [`tokio_rustls::TlsAcceptor`].
//!
//! v1 ships with operator-supplied PEM only. Self-signed
//! generate-on-first-start is documented as a deferred feature in
//! the plan (raises key-rotation policy questions; defer until we
//! pick a stance).

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
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .filter_map(Result::ok)
        .collect();
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
