//! Client-side TLS options for satd's own RPC clients.
//!
//! satd terminates TLS natively on its RPC listener (`-rpctlsbind`), but
//! `sat-cli` and `sat-tui` historically only ever spoke `http://`. That
//! left an operator who had turned TLS on with no first-party client: the
//! plain listener had to stay bound on loopback purely so the shipped
//! tooling could talk to the node. This module closes that gap, and it
//! lives here — beside the server-side acceptor the same operator
//! configured — so the two ends of one connection are described in one
//! crate rather than drifting apart in two binaries.
//!
//! Both binaries expose the same four flags:
//!
//! | Flag | Meaning |
//! |---|---|
//! | `-rpctls` | speak `https://` instead of `http://` |
//! | `-rpccacert=<pem>` | trust this CA (or self-signed server cert) |
//! | `-rpcclientcert=<pem>` | client certificate, for an mTLS listener |
//! | `-rpcclientkey=<pem>` | its private key |
//!
//! Without `-rpccacert` the client trusts the public CA roots compiled into
//! the binary (the Mozilla set from `webpki-roots`), so a node behind a
//! publicly-trusted certificate needs no CA flag at all. With it, the client
//! trusts **only** the certificates in that file. A private CA — which is
//! what `contrib/stack/tls/mkca.sh` issues, and what the appliance image
//! installs — is named explicitly, and naming it also takes every public CA
//! out of the connection: a public CA that issues a certificate for the
//! node's hostname, whether by mistake or because its key leaked, cannot
//! stand in for the node and collect the RPC credential.
//!
//! Point `-rpccacert` at the certificate that **issued** the one the server
//! presents. For a node using a genuinely self-signed certificate, which is
//! its own issuer, that is the server certificate itself. It is NOT the
//! leaf of a chain: a leaf issued by a CA does not anchor its own path, and
//! passing one produces a handshake failure that reads like a connection
//! error.
//!
//! There is deliberately no "skip verification" flag. The two cases above
//! cover every certificate an operator can actually have, and an unverified
//! TLS connection carrying an RPC cookie is a worse posture than the
//! plain-HTTP loopback listener it would replace.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore, pki_types::CertificateDer};

#[derive(Debug, Error)]
pub enum ClientTlsError {
    #[error("cannot read {what} {path}: {source}")]
    Io {
        what: &'static str,
        path: String,
        source: std::io::Error,
    },
    #[error("{path} is not a usable CA certificate: {reason}")]
    BadCa { path: String, reason: String },
    #[error("{path} contains no PEM certificates")]
    EmptyCa { path: String },
    #[error("client certificate/key pair in {cert} + {key} is unusable: {reason}")]
    BadIdentity {
        cert: String,
        key: String,
        reason: String,
    },
    #[error("--rpcclientcert requires --rpcclientkey (and vice versa)")]
    IncompleteIdentity,
    #[error(
        "--rpccacert / --rpcclientcert have no effect without --rpctls; \
         add --rpctls to connect over https"
    )]
    TlsMaterialWithoutTls,
    #[error("cannot build the HTTPS client: {0}")]
    Build(String),
}

/// The client-side TLS flags, as parsed from the command line.
///
/// `Default` is "plain HTTP", which is what every existing invocation
/// gets: the flags are strictly additive and change nothing until
/// `enabled` is set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientTlsOptions {
    /// `-rpctls`: use `https://` for the RPC endpoint.
    pub enabled: bool,
    /// `-rpccacert`: the only trust anchors; replaces the public roots.
    pub ca_cert: Option<PathBuf>,
    /// `-rpcclientcert`: client certificate for an mTLS listener.
    pub client_cert: Option<PathBuf>,
    /// `-rpcclientkey`: the matching private key.
    pub client_key: Option<PathBuf>,
}

impl ClientTlsOptions {
    /// The URL scheme these options imply.
    pub fn scheme(&self) -> &'static str {
        if self.enabled { "https" } else { "http" }
    }

    /// Build the endpoint URL for an RPC host/port under these options.
    pub fn endpoint(&self, host: &str, port: u16) -> String {
        // Bare IPv6 literals need brackets in a URL authority. `sat-cli
        // -rpcconnect=::1` is a reasonable thing to type, and without this
        // it produces `https://::1:8332/`, which does not parse.
        if host.contains(':') && !host.starts_with('[') {
            format!("{}://[{}]:{}/", self.scheme(), host, port)
        } else {
            format!("{}://{}:{}/", self.scheme(), host, port)
        }
    }

    /// Reject flag combinations that cannot mean what the operator wrote.
    ///
    /// Silently ignoring `-rpccacert` when `-rpctls` was forgotten is the
    /// bad outcome here: the request goes out over plain HTTP carrying the
    /// RPC credential, and everything looks like it worked.
    pub fn validate(&self) -> Result<(), ClientTlsError> {
        match (&self.client_cert, &self.client_key) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(ClientTlsError::IncompleteIdentity);
            }
            _ => {}
        }
        if !self.enabled && (self.ca_cert.is_some() || self.client_cert.is_some()) {
            return Err(ClientTlsError::TlsMaterialWithoutTls);
        }
        Ok(())
    }

    /// Apply these options to a `reqwest` client builder.
    ///
    /// Callers keep ownership of the builder so they can set their own
    /// timeouts and headers; this only layers on the TLS material. With
    /// `-rpctls` the builder gets a complete rustls configuration, so any
    /// root certificate or identity already added to `builder` is replaced,
    /// not merged.
    pub fn apply(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::ClientBuilder, ClientTlsError> {
        self.validate()?;
        if !self.enabled {
            return Ok(builder);
        }
        let config = self.client_config(public_roots)?;
        Ok(builder.use_preconfigured_tls(config))
    }

    /// The rustls configuration behind [`apply`](Self::apply).
    /// `public_roots` supplies the trust anchors used when no `-rpccacert`
    /// is given; tests pass a stand-in for the compiled-in set.
    fn client_config(
        &self,
        public_roots: impl FnOnce() -> RootCertStore,
    ) -> Result<ClientConfig, ClientTlsError> {
        let roots = match &self.ca_cert {
            // Only the named file. The public roots are deliberately not
            // added: an operator who names the CA that issued the node's
            // certificate has said which authority may vouch for the node,
            // and any other CA that signs for the same hostname is the
            // attacker this flag exists to keep out.
            Some(path) => ca_roots(path)?,
            None => public_roots(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ClientTlsError::Build(e.to_string()))?
            .with_root_certificates(roots);
        let (Some(cert_path), Some(key_path)) = (&self.client_cert, &self.client_key) else {
            return Ok(builder.with_no_client_auth());
        };
        let bad_identity = |reason: String| ClientTlsError::BadIdentity {
            cert: cert_path.display().to_string(),
            key: key_path.display().to_string(),
            reason,
        };
        let chain = pem_certs(&read_file(cert_path, "client certificate")?)
            .map_err(|e| bad_identity(e.to_string()))?;
        if chain.is_empty() {
            return Err(bad_identity("no certificate in the certificate file".into()));
        }
        let key = rustls_pemfile::private_key(&mut read_file(key_path, "client key")?.as_slice())
            .map_err(|e| bad_identity(e.to_string()))?
            .ok_or_else(|| bad_identity("no private key in the key file".into()))?;
        builder
            .with_client_auth_cert(chain, key)
            .map_err(|e| bad_identity(e.to_string()))
    }

    /// Build a client with these options applied to `builder`.
    pub fn build(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::Client, ClientTlsError> {
        self.apply(builder)?
            .build()
            .map_err(|e| ClientTlsError::Build(e.to_string()))
    }
}

/// The public CA roots compiled into the binary.
fn public_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// Every certificate in a `-rpccacert` file, as the only trust anchors.
fn ca_roots(path: &Path) -> Result<RootCertStore, ClientTlsError> {
    let bad_ca = |reason: String| ClientTlsError::BadCa {
        path: path.display().to_string(),
        reason,
    };
    // A PEM bundle may hold an intermediate as well as the root, and an
    // operator handed a chain file should not have to split it.
    let certs = pem_certs(&read_file(path, "CA certificate")?).map_err(|e| bad_ca(e.to_string()))?;
    // A file with no PEM blocks parses "successfully" into an empty list.
    // Accepting that would add no trust anchor at all and then fail the
    // handshake with an opaque TLS error — the operator who pointed this at
    // a private key, a DER file, or the wrong path would have no way to tell
    // that from an unrelated network problem. Refuse by name instead.
    if certs.is_empty() {
        return Err(ClientTlsError::EmptyCa {
            path: path.display().to_string(),
        });
    }
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|e| bad_ca(e.to_string()))?;
    }
    Ok(roots)
}

fn pem_certs(pem: &[u8]) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut &pem[..]).collect()
}

fn read_file(path: &Path, what: &'static str) -> Result<Vec<u8>, ClientTlsError> {
    std::fs::read(path).map_err(|source| ClientTlsError::Io {
        what,
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_plain_http() {
        let opts = ClientTlsOptions::default();
        assert_eq!(opts.scheme(), "http");
        assert_eq!(opts.endpoint("127.0.0.1", 8332), "http://127.0.0.1:8332/");
        opts.validate().expect("the default must always be valid");
    }

    #[test]
    fn enabled_switches_scheme() {
        let opts = ClientTlsOptions {
            enabled: true,
            ..Default::default()
        };
        assert_eq!(opts.endpoint("node.local", 8336), "https://node.local:8336/");
    }

    #[test]
    fn ipv6_literals_are_bracketed() {
        let opts = ClientTlsOptions {
            enabled: true,
            ..Default::default()
        };
        assert_eq!(opts.endpoint("::1", 8336), "https://[::1]:8336/");
        // Already-bracketed input must not be double-bracketed.
        assert_eq!(opts.endpoint("[::1]", 8336), "https://[::1]:8336/");
    }

    #[test]
    fn half_an_identity_is_rejected() {
        let opts = ClientTlsOptions {
            enabled: true,
            client_cert: Some(PathBuf::from("/nonexistent/cert.pem")),
            ..Default::default()
        };
        assert!(matches!(
            opts.validate(),
            Err(ClientTlsError::IncompleteIdentity)
        ));
    }

    /// The quiet-failure case: TLS material supplied but `-rpctls`
    /// forgotten would otherwise send the RPC credential in the clear.
    #[test]
    fn tls_material_without_rpctls_is_an_error() {
        let opts = ClientTlsOptions {
            enabled: false,
            ca_cert: Some(PathBuf::from("/nonexistent/ca.pem")),
            ..Default::default()
        };
        assert!(matches!(
            opts.validate(),
            Err(ClientTlsError::TlsMaterialWithoutTls)
        ));
    }

    #[test]
    fn missing_ca_file_names_the_path() {
        let opts = ClientTlsOptions {
            enabled: true,
            ca_cert: Some(PathBuf::from("/nonexistent/ca.pem")),
            ..Default::default()
        };
        let err = opts.apply(reqwest::Client::builder()).unwrap_err();
        assert!(
            err.to_string().contains("/nonexistent/ca.pem"),
            "error should name the unreadable file, got: {err}"
        );
    }

    /// A file with no certificates in it must be refused by name. Left
    /// unchecked this adds no trust anchor and surfaces later as a generic
    /// handshake failure, which is indistinguishable from the node being
    /// down.
    #[test]
    fn a_ca_file_with_no_certificates_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, b"this is not a certificate\n").unwrap();
        let opts = ClientTlsOptions {
            enabled: true,
            ca_cert: Some(path.clone()),
            ..Default::default()
        };
        let err = opts.apply(reqwest::Client::builder()).unwrap_err();
        assert!(
            matches!(err, ClientTlsError::EmptyCa { .. }),
            "expected EmptyCa, got: {err}"
        );
        assert!(err.to_string().contains(&path.display().to_string()));
    }

    /// The specific mistake worth naming: pointing `-rpccacert` at the
    /// private key instead of the certificate. It is a valid PEM file, so
    /// only the "are there certificates in it" check catches it.
    #[test]
    fn a_private_key_passed_as_the_ca_is_rejected() {
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leaf.key");
        std::fs::write(&path, cert.key_pair.serialize_pem()).unwrap();
        let opts = ClientTlsOptions {
            enabled: true,
            ca_cert: Some(path),
            ..Default::default()
        };
        assert!(
            opts.apply(reqwest::Client::builder()).is_err(),
            "a key file must not pass as a CA bundle"
        );
    }

    // ---------------------------------------------------------------------
    // Handshake tests
    // ---------------------------------------------------------------------
    //
    // Loading a PEM proves nothing about whether the connection verifies:
    // `reqwest::Certificate::from_pem` accepts any certificate, including
    // ones that cannot anchor a path. These tests therefore run a real
    // handshake against an acceptor built by this crate's own server half,
    // which is the same acceptor satd's RPC listener uses.

    /// Minimal TLS server: one connection, one canned HTTP response.
    /// Returns the bound port and the task handle.
    async fn spawn_tls_server(
        cert_pem: &str,
        key_pem: &str,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        spawn_tls_server_requiring(cert_pem, key_pem, None).await
    }

    /// As `spawn_tls_server`, and with `client_ca` set the server requires
    /// a client certificate issued by it (an mTLS listener).
    async fn spawn_tls_server_requiring(
        cert_pem: &str,
        key_pem: &str,
        client_ca: Option<&str>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();
        let policy = match client_ca {
            Some(pem) => {
                let ca_path = dir.path().join("client-ca.pem");
                std::fs::write(&ca_path, pem).unwrap();
                crate::ClientAuthPolicy::Required { ca_path }
            }
            None => crate::ClientAuthPolicy::Disabled,
        };
        let acceptor = crate::build_acceptor(&cert_path, &key_path, &policy).expect("acceptor");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            // `dir` is moved in so the PEM files outlive the acceptor build.
            let _dir = dir;
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buf = [0u8; 1024];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                              Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (port, handle)
    }

    async fn get(client: &reqwest::Client, port: u16) -> Result<u16, reqwest::Error> {
        client
            .get(format!("https://localhost:{port}/"))
            .send()
            .await
            .map(|r| r.status().as_u16())
    }

    /// A self-signed server certificate is its own issuer, so handing it to
    /// `-rpccacert` has to verify. This is the documented fallback for
    /// operators who ran `openssl req -x509` rather than `mkca.sh`.
    #[tokio::test]
    async fn self_signed_server_cert_verifies_when_named_as_the_ca() {
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let (port, server) = spawn_tls_server(&cert.cert.pem(), &cert.key_pair.serialize_pem()).await;

        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, cert.cert.pem()).unwrap();

        let client = ClientTlsOptions {
            enabled: true,
            ca_cert: Some(ca_path),
            ..Default::default()
        }
        .build(reqwest::Client::builder())
        .unwrap();

        assert_eq!(get(&client, port).await.unwrap(), 200);
        server.abort();
    }

    /// The same server, with no `-rpccacert`: the public roots do not know
    /// this certificate, so the handshake must fail. Without this
    /// the test above would pass even if the CA argument were ignored
    /// entirely.
    #[tokio::test]
    async fn an_untrusted_server_cert_is_rejected() {
        let cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let (port, server) = spawn_tls_server(&cert.cert.pem(), &cert.key_pair.serialize_pem()).await;

        let client = ClientTlsOptions {
            enabled: true,
            ..Default::default()
        }
        .build(reqwest::Client::builder())
        .unwrap();

        assert!(
            get(&client, port).await.is_err(),
            "a certificate signed by nothing the client trusts must not verify"
        );
        server.abort();
    }

    /// Trusting the wrong CA must fail. This is the case that separates
    /// "verification happens" from "any supplied PEM makes it work".
    #[tokio::test]
    async fn the_wrong_ca_is_rejected() {
        let server_cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let (port, server) =
            spawn_tls_server(&server_cert.cert.pem(), &server_cert.key_pair.serialize_pem()).await;

        let other = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("other-ca.pem");
        std::fs::write(&ca_path, other.cert.pem()).unwrap();

        let client = ClientTlsOptions {
            enabled: true,
            ca_cert: Some(ca_path),
            ..Default::default()
        }
        .build(reqwest::Client::builder())
        .unwrap();

        assert!(
            get(&client, port).await.is_err(),
            "an unrelated CA must not verify this server"
        );
        server.abort();
    }

    /// The point of `-rpccacert`: once a CA is named, no other authority the
    /// client would trust can vouch for the server. A public CA that signs
    /// for the node's hostname, by mistake or with a leaked key, is exactly
    /// that other authority. `public` stands in for the compiled-in roots.
    /// The first request proves the server verifies through them, so the
    /// refusal that follows comes from naming the CA and nothing else.
    #[tokio::test]
    async fn rpccacert_replaces_the_public_roots() {
        let server_cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let (port, server) =
            spawn_tls_server(&server_cert.cert.pem(), &server_cert.key_pair.serialize_pem()).await;
        let public = || {
            let mut roots = RootCertStore::empty();
            roots.add(server_cert.cert.der().clone()).unwrap();
            roots
        };
        let client = |opts: ClientTlsOptions| {
            let config = opts.client_config(public).unwrap();
            reqwest::Client::builder()
                .use_preconfigured_tls(config)
                .build()
                .unwrap()
        };

        let no_ca = ClientTlsOptions {
            enabled: true,
            ..Default::default()
        };
        assert_eq!(
            get(&client(no_ca), port).await.unwrap(),
            200,
            "without -rpccacert the public roots must verify the server"
        );

        let operator_ca = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("operator-ca.pem");
        std::fs::write(&ca_path, operator_ca.cert.pem()).unwrap();
        let named_ca = ClientTlsOptions {
            enabled: true,
            ca_cert: Some(ca_path),
            ..Default::default()
        };
        assert!(
            get(&client(named_ca), port).await.is_err(),
            "with -rpccacert, a certificate only a public root vouches for must not verify"
        );
        server.abort();
    }

    /// The name on the certificate still has to match. A private CA is a
    /// trust anchor, not a licence to ignore the SAN — an appliance issues
    /// its leaf for `<host>.local` precisely so this check passes.
    #[tokio::test]
    async fn a_name_mismatch_is_rejected() {
        let cert = rcgen::generate_simple_self_signed(["not-the-host".to_string()]).unwrap();
        let (port, server) = spawn_tls_server(&cert.cert.pem(), &cert.key_pair.serialize_pem()).await;

        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, cert.cert.pem()).unwrap();

        let client = ClientTlsOptions {
            enabled: true,
            ca_cert: Some(ca_path),
            ..Default::default()
        }
        .build(reqwest::Client::builder())
        .unwrap();

        assert!(
            get(&client, port).await.is_err(),
            "a certificate issued for another name must not verify"
        );
        server.abort();
    }

    /// An mTLS listener accepts the client certificate given with
    /// `-rpcclientcert` / `-rpcclientkey`, and refuses the same client
    /// without it, so the identity really is presented in the handshake.
    #[tokio::test]
    async fn the_client_certificate_is_presented_to_an_mtls_listener() {
        let server_cert = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let client_cert = rcgen::generate_simple_self_signed(["client".to_string()]).unwrap();
        let (port, server) = spawn_tls_server_requiring(
            &server_cert.cert.pem(),
            &server_cert.key_pair.serialize_pem(),
            Some(&client_cert.cert.pem()),
        )
        .await;

        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        let cert_path = dir.path().join("client.crt");
        let key_path = dir.path().join("client.key");
        std::fs::write(&ca_path, server_cert.cert.pem()).unwrap();
        std::fs::write(&cert_path, client_cert.cert.pem()).unwrap();
        std::fs::write(&key_path, client_cert.key_pair.serialize_pem()).unwrap();

        let with_identity = ClientTlsOptions {
            enabled: true,
            ca_cert: Some(ca_path.clone()),
            client_cert: Some(cert_path),
            client_key: Some(key_path),
        }
        .build(reqwest::Client::builder())
        .unwrap();
        assert_eq!(get(&with_identity, port).await.unwrap(), 200);

        let without = ClientTlsOptions {
            enabled: true,
            ca_cert: Some(ca_path),
            ..Default::default()
        }
        .build(reqwest::Client::builder())
        .unwrap();
        assert!(
            get(&without, port).await.is_err(),
            "an mTLS listener must refuse a client that presents no certificate"
        );
        server.abort();
    }

    #[test]
    fn client_identity_is_loaded_from_a_split_pair() {
        let cert = rcgen::generate_simple_self_signed(["client".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client.crt");
        let key_path = dir.path().join("client.key");
        // Deliberately written without a trailing newline: concatenating the
        // two files has to insert the separator, or the PEM parser sees
        // `-----END CERTIFICATE----------BEGIN PRIVATE KEY-----`.
        let mut pem = cert.cert.pem();
        while pem.ends_with('\n') {
            pem.pop();
        }
        std::fs::write(&cert_path, pem).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let opts = ClientTlsOptions {
            enabled: true,
            client_cert: Some(cert_path),
            client_key: Some(key_path),
            ..Default::default()
        };
        opts.build(reqwest::Client::builder())
            .expect("a cert/key pair in separate files must load");
    }
}
