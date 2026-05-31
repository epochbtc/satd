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
use std::sync::{Arc, Mutex, RwLock};

use thiserror::Error;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::crypto::ring::sign::any_supported_type;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use tokio_rustls::rustls::sign::CertifiedKey;

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
    #[error("malformed private key in {path}: {source}")]
    BadKey {
        path: String,
        source: std::io::Error,
    },
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
///
/// Only `Subject CN` and DNS-typed `SubjectAltName` entries are
/// matched. Other SAN types (email, URI, IP) are ignored. Operators
/// who need richer matching should use a narrower CA bundle.
///
/// **Warning:** the allowlist is meaningful only when mTLS is
/// enabled — without an mTLS handshake there is no peer cert to
/// compare against. Callers MUST gate `check_peer_allowed` on
/// `mtls_enabled` (or the parallel `satd`-level config validation
/// that refuses `*mtlsclientallow` without `*mtls=1`); a non-empty
/// allowlist on a plain-TLS surface would reject every connection.
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
    // Build the server cert behind a runtime-swappable resolver instead of
    // `with_single_cert`, so the leaf cert/key can be hot-reloaded from the
    // SAME paths on SIGUSR1 (see [`reload_all_certs`]) without rebinding the
    // socket. rustls consults the resolver per handshake, so a swap takes
    // effect for new connections; in-flight connections keep their cert.
    let certified = build_certified_key(certs, key)?;
    let resolver = Arc::new(ReloadableCertResolver::new(certified));
    let builder = tokio_rustls::rustls::ServerConfig::builder();
    let builder = match client_auth {
        ClientAuthPolicy::Disabled => builder.with_no_client_auth(),
        ClientAuthPolicy::Required { ca_path } => {
            let roots = load_ca_roots(ca_path)?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| TlsConfigError::ClientVerifier(e.to_string()))?;
            // The client-CA verifier is baked in (the CA is long-lived and
            // does not rotate on the short TTLs that motivate cert reload).
            // A SIGUSR1 reload swaps only the server leaf cert/key; changing
            // the mTLS CA still requires a restart.
            builder.with_client_cert_verifier(verifier)
        }
    };
    let server_config = builder.with_cert_resolver(resolver.clone());
    register_reloader(CertReloader {
        cert_path: cert_path.to_path_buf(),
        key_path: key_path.to_path_buf(),
        resolver,
    });
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Build a rustls [`CertifiedKey`] from a parsed cert chain + private key,
/// validating that the key matches the leaf cert. Uses the `ring` provider's
/// key loader explicitly (the workspace pins `tokio-rustls` to the `ring`
/// provider), so this does not depend on a process-default crypto provider.
fn build_certified_key(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>, TlsConfigError> {
    let signing_key = any_supported_type(&key)
        .map_err(|e| TlsConfigError::Rustls(format!("unsupported private key: {e}")))?;
    let certified = CertifiedKey::new(certs, signing_key);
    // Equivalent to the check `with_single_cert` performed: the private key
    // must correspond to the end-entity cert. Preserves fail-fast on a
    // mismatched cert/key pair (at startup and on every reload).
    certified
        .keys_match()
        .map_err(|e| TlsConfigError::Rustls(format!("certificate/key mismatch: {e}")))?;
    Ok(Arc::new(certified))
}

/// A `ResolvesServerCert` whose certificate can be swapped at runtime. Holds
/// the current [`CertifiedKey`] behind an `RwLock`; `resolve` (per handshake)
/// takes a read lock and clones the `Arc`, and [`reload`](CertReloader::reload)
/// takes a brief write lock to swap it.
#[derive(Debug)]
struct ReloadableCertResolver {
    current: RwLock<Arc<CertifiedKey>>,
}

impl ReloadableCertResolver {
    fn new(certified: Arc<CertifiedKey>) -> Self {
        Self {
            current: RwLock::new(certified),
        }
    }
}

impl ResolvesServerCert for ReloadableCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Lock poisoning can only happen if a writer panicked mid-swap; the
        // swap is a single assignment that can't panic, so this is effectively
        // infallible. Recover the guard rather than panic on the handshake path.
        Some(
            self.current
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
        )
    }
}

/// Handle that reloads one TLS surface's leaf cert/key from its configured
/// paths into the live resolver. Cloneable (cheap: two `PathBuf`s + an `Arc`).
#[derive(Clone)]
struct CertReloader {
    cert_path: PathBuf,
    key_path: PathBuf,
    resolver: Arc<ReloadableCertResolver>,
}

impl CertReloader {
    /// Re-read the cert/key from disk and swap them into the resolver. On any
    /// error (unreadable/missing/malformed/mismatched) the resolver keeps its
    /// previous, still-valid certificate — the live listener is never left
    /// without a usable cert.
    fn reload(&self) -> Result<(), TlsConfigError> {
        let certs = load_certs(&self.cert_path)?;
        let key = load_private_key(&self.key_path)?;
        let certified = build_certified_key(certs, key)?;
        *self
            .resolver
            .current
            .write()
            .unwrap_or_else(|p| p.into_inner()) = certified;
        Ok(())
    }
}

/// Process-wide registry of reloadable TLS surfaces. Append-only at startup
/// (each [`build_acceptor`] pushes one entry), read on SIGUSR1. A global is the
/// least invasive wiring: the three TLS acceptors are built in three different
/// crates (RPC/Esplora/Electrum), and this avoids threading a handle out of
/// each surface's startup into the signal loop.
static CERT_RELOADERS: Mutex<Vec<CertReloader>> = Mutex::new(Vec::new());

fn register_reloader(reloader: CertReloader) {
    CERT_RELOADERS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(reloader);
}

/// Outcome of reloading one TLS surface's certificate.
pub struct CertReloadOutcome {
    /// The cert path that was (re)loaded — identifies the surface in logs.
    pub cert_path: PathBuf,
    /// `Ok(())` if the new cert is now live; `Err` if the reload failed and the
    /// previous cert was kept.
    pub result: Result<(), TlsConfigError>,
}

/// Reload every registered TLS surface's leaf cert/key from its configured
/// paths. Driven by SIGUSR1. Each surface reloads independently — a failure on
/// one keeps that surface's previous cert and is reported in the returned
/// outcomes, never aborting the others or the process.
///
/// The registry lock is released before any disk I/O (the reloaders are cloned
/// out first), so a reload can never block `build_acceptor` or another reload.
pub fn reload_all_certs() -> Vec<CertReloadOutcome> {
    let reloaders: Vec<CertReloader> = CERT_RELOADERS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    reloaders
        .iter()
        .map(|r| CertReloadOutcome {
            cert_path: r.cert_path.clone(),
            result: r.reload(),
        })
        .collect()
}

/// Number of registered reloadable TLS surfaces. Lets the signal handler skip
/// logging entirely when no TLS surface is configured.
pub fn registered_cert_count() -> usize {
    CERT_RELOADERS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .len()
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
    // Distinguish "file unreadable" (Io, raised by File::open above)
    // from "file content is not a valid PEM key" (BadKey). The cert
    // loader uses the analogous BadCert variant; private-key errors
    // historically rolled into Io which was misleading — operators
    // staring at "cannot read TLS file" for a malformed PEM blob were
    // sent looking for permission issues that didn't exist.
    rustls_pemfile::private_key(&mut reader)
        .map_err(|source| TlsConfigError::BadKey {
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

    /// File exists but content isn't a valid PEM private-key blob.
    /// Distinct from "file missing" (Io) and from "file empty but
    /// well-formed" (NoKey). Operators staring at a misleading "cannot
    /// read TLS file" error for malformed PEM was the bug behind the
    /// dedicated `BadKey` variant.
    #[test]
    fn malformed_key_file_is_bad_key_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert = simple_cert();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        // A PEM-shaped blob with a recognized header but garbage body.
        // `rustls_pemfile::private_key` parses the BEGIN/END frame
        // then fails to decode the base64 inside.
        let bad_key = "-----BEGIN PRIVATE KEY-----\nnot-base64-garbage\n-----END PRIVATE KEY-----\n";
        let key_path = write_pem(dir.path(), "key.pem", bad_key);
        let result = build_acceptor(&cert_path, &key_path, &ClientAuthPolicy::Disabled);
        assert!(
            matches!(result, Err(TlsConfigError::BadKey { .. })),
            "expected BadKey, got err: {:?}",
            result.err()
        );
    }

    /// Both PEM blobs parse, but the key doesn't match the cert.
    /// rustls's `with_single_cert` validates the pairing and rejects;
    /// we surface that as `Rustls`. Important because the cert-loader
    /// and key-loader can each succeed in isolation, so a mismatched
    /// pair only surfaces at the acceptor-build step.
    #[test]
    fn mismatched_cert_and_key_is_rustls_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert_a = simple_cert();
        let cert_b = simple_cert();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert_a.cert.pem());
        // Use cert_b's key — well-formed but doesn't match cert_a.
        let key_path = write_pem(dir.path(), "key.pem", &cert_b.key_pair.serialize_pem());
        let result = build_acceptor(&cert_path, &key_path, &ClientAuthPolicy::Disabled);
        assert!(
            matches!(result, Err(TlsConfigError::Rustls(_))),
            "expected Rustls error for cert/key mismatch, got err: {:?}",
            result.err()
        );
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

    // --- TLS cert hot-reload (SIGUSR1) ---

    /// Build a `CertReloader` directly (bypassing the global registry, so these
    /// tests don't pollute it / race with each other).
    fn make_reloader(cert_path: PathBuf, key_path: PathBuf) -> CertReloader {
        let certs = load_certs(&cert_path).unwrap();
        let key = load_private_key(&key_path).unwrap();
        let certified = build_certified_key(certs, key).unwrap();
        CertReloader {
            cert_path,
            key_path,
            resolver: Arc::new(ReloadableCertResolver::new(certified)),
        }
    }

    /// The leaf DER currently served by the resolver.
    fn current_leaf(r: &CertReloader) -> Vec<u8> {
        r.resolver.current.read().unwrap().cert[0].to_vec()
    }

    #[test]
    fn reload_swaps_certificate_from_same_path() {
        let dir = tempfile::tempdir().unwrap();
        let cert_a = simple_cert();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert_a.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert_a.key_pair.serialize_pem());

        let reloader = make_reloader(cert_path.clone(), key_path.clone());
        let before = current_leaf(&reloader);

        // Rotate the cert IN PLACE (same paths) — as cert-manager would.
        let cert_b = simple_cert();
        write_pem(dir.path(), "cert.pem", &cert_b.cert.pem());
        write_pem(dir.path(), "key.pem", &cert_b.key_pair.serialize_pem());

        reloader.reload().expect("reload from same paths succeeds");
        let after = current_leaf(&reloader);
        assert_ne!(before, after, "resolver should serve the rotated cert");
    }

    #[test]
    fn build_certified_key_rejects_mismatched_key() {
        let dir = tempfile::tempdir().unwrap();
        let cert_a = simple_cert();
        let cert_b = simple_cert(); // independent key
        let cert_path = write_pem(dir.path(), "cert.pem", &cert_a.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert_b.key_pair.serialize_pem());

        let certs = load_certs(&cert_path).unwrap();
        let key = load_private_key(&key_path).unwrap();
        let result = build_certified_key(certs, key);
        assert!(
            matches!(result, Err(TlsConfigError::Rustls(_))),
            "mismatched cert/key must fail keys_match: {result:?}"
        );
    }

    #[test]
    fn reload_failure_keeps_previous_cert() {
        let dir = tempfile::tempdir().unwrap();
        let cert_a = simple_cert();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert_a.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert_a.key_pair.serialize_pem());

        let reloader = make_reloader(cert_path.clone(), key_path.clone());
        let original = current_leaf(&reloader);

        // Corrupt the cert file, then attempt a reload.
        write_pem(dir.path(), "cert.pem", "-----BEGIN CERTIFICATE-----\ngarbage\n");
        let result = reloader.reload();
        assert!(result.is_err(), "reload of a corrupt cert must fail");
        assert_eq!(
            current_leaf(&reloader),
            original,
            "failed reload must keep the previous, still-valid cert"
        );
    }

    #[test]
    fn build_acceptor_registers_a_reloader() {
        let dir = tempfile::tempdir().unwrap();
        let cert = simple_cert();
        let cert_path = write_pem(dir.path(), "cert.pem", &cert.cert.pem());
        let key_path = write_pem(dir.path(), "key.pem", &cert.key_pair.serialize_pem());

        let before = registered_cert_count();
        let acceptor = build_acceptor(&cert_path, &key_path, &ClientAuthPolicy::Disabled);
        assert!(acceptor.is_ok());
        // Registry is append-only and shared across parallel tests, so assert
        // monotonic growth rather than an exact count.
        assert!(
            registered_cert_count() > before,
            "build_acceptor should register a reloadable surface"
        );
    }
}
