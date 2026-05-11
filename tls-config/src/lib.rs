//! Shared TLS configuration loading for satd's server-side TLS surfaces.
//!
//! Operator supplies PEM-encoded certificate + private-key files via
//! per-surface flags (`--electrumtlscert` / `--esploratlscert` /
//! `--rpctlscert`, and their matching `*tlskey`). Each surface loads
//! the same PEM shape and builds a [`tokio_rustls::TlsAcceptor`]; this
//! crate is the single implementation they share. Bitcoin Core's RPC
//! is HTTP-only by design; the JSON-RPC TLS path here is satd-specific.
//!
//! ## mTLS (mutual TLS)
//!
//! By default the acceptor is built with [`ClientAuthPolicy::Disabled`]
//! and presents the standard "TLS server, no client auth" handshake.
//! When the operator opts in with [`ClientAuthPolicy::Required`] the
//! acceptor refuses any handshake without a client cert signed by the
//! supplied CA bundle. The surface MAY also apply a
//! [`ClientAllowList`] after handshake to restrict accepted leaf names
//! to a specific set of CN / DNS-SAN values; an empty allowlist means
//! "any CA-signed cert is allowed" — the CA is the only gate.
//!
//! mTLS here is *strictly additive*: existing per-surface application
//! auth (cookie / userpass / `EsploraAuth`) keeps running on top of the
//! mTLS handshake. Operators who want mTLS to be the only auth use
//! per-surface flags (`--rpcdisableauth`, `--esploraauth=none`).
//!
//! v1 ships with operator-supplied PEM only; self-signed
//! generate-on-first-start, CRL/OCSP support, and `ClientAuthPolicy::
//! Optional` are documented as deferred features.
//!
//! The acceptor and `ServerConnection` types are re-exported so
//! consumers can refer to them through this crate without adding their
//! own `tokio-rustls` dependency just to spell the types.

use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;

pub use tokio_rustls::TlsAcceptor;
pub use tokio_rustls::rustls::ServerConnection;

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
    #[error("no CA certificates found in {path}")]
    NoCaRoots { path: String },
    #[error("malformed CA certificate in {path}: {source}")]
    BadCa {
        path: String,
        source: std::io::Error,
    },
    #[error("rustls config: {0}")]
    Rustls(String),
    #[error("client cert verifier: {0}")]
    ClientVerifier(String),
}

/// How the TLS acceptor handles client certificates.
///
/// `Disabled` is the historical default — plain server-auth TLS. The
/// rustls handshake accepts any client; per-surface application auth
/// (cookie, userpass) gates access.
///
/// `Required` enables mTLS. The acceptor refuses any handshake without
/// a client cert validly chained to the supplied CA bundle. This is
/// purely *additive*: existing application auth (cookie / userpass)
/// continues to run on top unless the operator separately disables it.
///
/// `Optional` (handshake-succeeds-without-cert, app-layer enforces) is
/// deferred to v2; the v1 API leaves room to add it without breaking
/// callers.
#[derive(Debug, Clone)]
pub enum ClientAuthPolicy {
    Disabled,
    Required { ca_path: PathBuf },
}

/// Per-surface allowlist of acceptable client-cert subject identities.
///
/// When non-empty, the surface compares the peer leaf cert's Common
/// Name plus all DNS Subject Alternative Names (case-insensitive)
/// against this set. A connection where none of the leaf's names
/// appear in the set is dropped after handshake.
///
/// An empty allowlist means "no further filter" — any cert validly
/// signed by the CA is accepted. The CA bundle is the only gate in
/// that case. Operators who want this stricter mode supply the flag
/// (e.g. `--rpcmtlsclientallow=alice,bob`); leaving it unset keeps
/// the broader "CA is the allowlist" model.
#[derive(Debug, Clone, Default)]
pub struct ClientAllowList {
    names: HashSet<String>,
}

impl ClientAllowList {
    pub fn new(values: impl IntoIterator<Item = String>) -> Self {
        Self {
            names: values
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }
}

/// Runtime rejection from [`check_peer_allowed`]: the handshake
/// produced a client cert, but none of its CN / DNS-SAN names appear
/// in the configured [`ClientAllowList`].
#[derive(Debug)]
pub struct AllowlistRejection {
    /// Best-effort label for the offending leaf (CN if present, else
    /// first DNS SAN, else `<unknown>`). Suitable for logging only —
    /// not for trust decisions.
    pub subject_label: String,
}

/// Build a [`TlsAcceptor`] from cert + key paths plus a client-auth
/// policy. Validates that all paths actually parse before returning,
/// so a startup-time misconfiguration becomes a hard error rather
/// than a per-connection mystery later.
pub fn build_acceptor(
    cert_path: &Path,
    key_path: &Path,
    client_auth: &ClientAuthPolicy,
) -> Result<TlsAcceptor, TlsConfigError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let builder = tokio_rustls::rustls::ServerConfig::builder();
    let builder = match client_auth {
        ClientAuthPolicy::Disabled => builder.with_no_client_auth(),
        ClientAuthPolicy::Required { ca_path } => {
            let roots = load_ca_roots(ca_path)?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| TlsConfigError::ClientVerifier(e.to_string()))?;
            builder.with_client_cert_verifier(verifier)
        }
    };
    let server_config = builder
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
    // Fail fast at startup so the operator sees the misconfiguration
    // immediately. (Same lesson as electrum-proto round-1 review L1.)
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

/// Load a PEM-encoded CA bundle into a `RootCertStore` for use as the
/// trust anchor set in mTLS verification. Fails fast on empty or
/// malformed input so a startup misconfiguration becomes a hard error
/// rather than per-handshake failures later.
pub fn load_ca_roots(path: &Path) -> Result<RootCertStore, TlsConfigError> {
    let path_str = path.display().to_string();
    let file = File::open(path).map_err(|source| TlsConfigError::Io {
        path: path_str.clone(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsConfigError::BadCa {
            path: path_str.clone(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsConfigError::NoCaRoots { path: path_str });
    }
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|e| TlsConfigError::BadCa {
            path: path_str.clone(),
            source: std::io::Error::other(e.to_string()),
        })?;
    }
    Ok(roots)
}

/// Extract CN + DNS SAN values from a leaf certificate as a
/// lowercased set. Best-effort: returns an empty set on parse failure
/// (caller can treat that as "no match" against the allowlist, which
/// falls through to rejection).
fn extract_leaf_names(der: &[u8]) -> HashSet<String> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::*;
    let mut names = HashSet::new();
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return names;
    };
    for cn in cert.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            names.insert(s.to_ascii_lowercase());
        }
    }
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for general in &san.value.general_names {
            if let GeneralName::DNSName(s) = general {
                names.insert(s.to_ascii_lowercase());
            }
        }
    }
    names
}

/// Best-effort label for the peer's leaf cert. CN if present, else
/// first DNS SAN, else `None`. Suitable for logging only — not for
/// trust decisions (which go through [`check_peer_allowed`] or the
/// rustls verifier).
pub fn peer_subject_label(conn: &ServerConnection) -> Option<String> {
    let chain = conn.peer_certificates()?;
    let leaf = chain.first()?;
    extract_leaf_names(leaf.as_ref()).into_iter().next()
}

/// After a successful mTLS handshake, check the peer's leaf cert
/// against the operator's allowlist. Returns `Ok(())` if the allowlist
/// is empty (no filter), if any of the leaf's CN / DNS-SAN names match,
/// or with `Err(AllowlistRejection { ... })` otherwise.
///
/// `Err` is also returned (with a sentinel `subject_label`) when the
/// connection has no peer cert at all — this is unexpected
/// post-handshake under `ClientAuthPolicy::Required` and indicates a
/// caller wiring bug; the call site should drop the connection.
pub fn check_peer_allowed(
    conn: &ServerConnection,
    allow: &ClientAllowList,
) -> Result<(), AllowlistRejection> {
    if allow.is_empty() {
        return Ok(());
    }
    let Some(chain) = conn.peer_certificates() else {
        return Err(AllowlistRejection {
            subject_label: "<no peer cert>".into(),
        });
    };
    let Some(leaf) = chain.first() else {
        return Err(AllowlistRejection {
            subject_label: "<empty cert chain>".into(),
        });
    };
    let names = extract_leaf_names(leaf.as_ref());
    if names.iter().any(|n| allow.names.contains(n)) {
        return Ok(());
    }
    let subject_label = names
        .into_iter()
        .next()
        .unwrap_or_else(|| "<unknown>".into());
    Err(AllowlistRejection { subject_label })
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

    fn simple_cert() -> rcgen::CertifiedKey {
        rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap()
    }

    #[test]
    fn build_acceptor_no_client_auth_succeeds_with_valid_pem() {
        let dir = tempfile::tempdir().unwrap();
        let cert = simple_cert();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let acceptor = build_acceptor(&cert_path, &key_path, &ClientAuthPolicy::Disabled);
        assert!(acceptor.is_ok());
    }

    #[test]
    fn build_acceptor_required_succeeds_with_valid_ca() {
        let dir = tempfile::tempdir().unwrap();
        let cert = simple_cert();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        // The cert is its own CA (self-signed) — fine for verifying
        // that the verifier *constructs*. Live handshake behavior is
        // exercised by the surface integration tests.
        let ca_path = write_pem(dir.path(), "ca.pem", &cert.cert.pem());
        let acceptor = build_acceptor(
            &cert_path,
            &key_path,
            &ClientAuthPolicy::Required { ca_path },
        );
        assert!(acceptor.is_ok(), "{:?}", acceptor.err());
    }

    #[test]
    fn missing_cert_file_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert = simple_cert();
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let result = build_acceptor(
            &dir.path().join("missing.pem"),
            &key_path,
            &ClientAuthPolicy::Disabled,
        );
        assert!(matches!(result, Err(TlsConfigError::Io { .. })));
    }

    #[test]
    fn empty_cert_file_is_no_certs_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert = simple_cert();
        let cert_path = write_pem(dir.path(), "cert.pem", "");
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let result = build_acceptor(&cert_path, &key_path, &ClientAuthPolicy::Disabled);
        assert!(matches!(result, Err(TlsConfigError::NoCerts { .. })));
    }

    #[test]
    fn missing_key_file_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert = simple_cert();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let result = build_acceptor(
            &cert_path,
            &dir.path().join("missing.pem"),
            &ClientAuthPolicy::Disabled,
        );
        assert!(matches!(result, Err(TlsConfigError::Io { .. })));
    }

    #[test]
    fn missing_ca_file_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert = simple_cert();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let result = build_acceptor(
            &cert_path,
            &key_path,
            &ClientAuthPolicy::Required {
                ca_path: dir.path().join("missing-ca.pem"),
            },
        );
        assert!(matches!(result, Err(TlsConfigError::Io { .. })));
    }

    #[test]
    fn empty_ca_file_is_no_roots_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert = simple_cert();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());
        let ca_path = write_pem(dir.path(), "ca.pem", "");
        let result = build_acceptor(
            &cert_path,
            &key_path,
            &ClientAuthPolicy::Required { ca_path },
        );
        assert!(matches!(result, Err(TlsConfigError::NoCaRoots { .. })));
    }

    #[test]
    fn allowlist_default_is_empty_pass_through() {
        let list = ClientAllowList::default();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn allowlist_new_lowercases_and_dedupes() {
        let list = ClientAllowList::new([
            "Alice".to_string(),
            "alice".to_string(),
            "BOB".to_string(),
        ]);
        assert_eq!(list.len(), 2);
        assert!(list.names.contains("alice"));
        assert!(list.names.contains("bob"));
    }

    #[test]
    fn extract_leaf_names_picks_up_cn_and_san() {
        let mut params =
            rcgen::CertificateParams::new(vec!["server.example".to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "alice.test");
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName(rcgen::Ia5String::try_from("alice.test").unwrap()),
            rcgen::SanType::DnsName(rcgen::Ia5String::try_from("bob.test").unwrap()),
        ];
        let kp = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let der = cert.der();
        let names = extract_leaf_names(der.as_ref());
        assert!(names.contains("alice.test"), "names = {:?}", names);
        assert!(names.contains("bob.test"), "names = {:?}", names);
    }

    #[test]
    fn extract_leaf_names_handles_garbage_input() {
        let names = extract_leaf_names(b"not a cert");
        assert!(names.is_empty());
    }
}
