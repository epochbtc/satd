//! RPC authentication policy attached to a listener surface.
//!
//! The Bitcoin-Core-compatible credential model (cookie, `-rpcuser`/
//! `-rpcpassword`, `-rpcauth` HMAC) now lives in the transport-agnostic
//! [`satd_auth`] crate; this module is a thin shim that owns the JSON-RPC
//! listener concerns: the reload-able credential set behind a lock, the cookie
//! file lifecycle, and the tower middleware that enforces HTTP Basic auth. The
//! credential *matching* itself (including the constant-time compares) is
//! delegated to [`satd_auth::OperatorCreds`], the single audited verifier.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// Re-export the Core-compatible credential types from their single home so
// existing call sites (`main.rs`, `reload.rs`) keep their import paths.
pub use satd_auth::{
    CookieCredential, OperatorCreds as Credentials, RpcAuthCredential, UserPassCredential,
};

/// RPC authentication policy attached to a listener surface.
///
/// `Disabled` is reserved for the mTLS escape hatch on the TLS surface
/// (`--rpcdisableauth=1` + `--rpcmtls=1`): clients prove identity via the mTLS
/// client cert and the AuthLayer becomes a pass-through. It must NEVER be used
/// on the plain-HTTP surface — the satd binary refuses that configuration at
/// startup.
///
/// `Verify` holds the operator credential set; a request is accepted if ANY
/// single credential validates against the supplied Basic-auth header, matching
/// Bitcoin Core's behaviour. The set is behind an `RwLock` so a SIGHUP config
/// reload can rotate `-rpcuser`/`-rpcpassword`/`-rpcauth` live
/// ([`reload_credentials`](Self::reload_credentials)) without dropping the
/// shared `Arc<RpcAuth>` the listener surfaces hold. The auto-generated cookie
/// credential is preserved across reloads.
#[derive(Debug)]
pub enum RpcAuth {
    Disabled,
    Verify(RwLock<Credentials>),
}

impl RpcAuth {
    /// Build the legacy single-userpass form. Retained for call sites (and
    /// tests) that don't yet need multi-credential support.
    pub fn from_user_pass(username: String, password: String) -> Self {
        RpcAuth::Verify(RwLock::new(Credentials::from_user_pass(username, password)))
    }

    /// Generate the cookie file at the given path with `perms` (octal), and
    /// return the credential-bearing `RpcAuth`. The cookie value stored is
    /// `__cookie__:<token>` per Core's convention. Removed by `cleanup()` on
    /// shutdown.
    ///
    /// The secret must never exist on disk with broader permissions than
    /// requested, even momentarily. On Unix we therefore write to a temp file in
    /// the destination directory created with the target mode at `open(2)` time
    /// (so the kernel applies it before any bytes land), then atomically
    /// `rename(2)` it into place.
    pub fn generate_cookie_with(path: PathBuf, perms: u32) -> std::io::Result<Self> {
        let token: String = {
            let mut rng = rand::thread_rng();
            let bytes: Vec<u8> = (0..32).map(|_| rand::Rng::r#gen::<u8>(&mut rng)).collect();
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        };
        let content = format!("__cookie__:{}", token);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
            // create_new + mode: born with restrictive perms, fails if a stale
            // temp exists rather than reusing a foreign file.
            let mut f = match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(perms)
                .open(&tmp)
            {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = std::fs::remove_file(&tmp);
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(perms)
                        .open(&tmp)?
                }
                Err(e) => return Err(e),
            };
            f.write_all(content.as_bytes())?;
            f.sync_all()?;
            // open() honours mode only when creating; an inherited umask can
            // still mask bits off. Force the exact perms before the rename
            // publishes the file.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(perms))?;
            std::fs::rename(&tmp, &path)?;
        }
        #[cfg(not(unix))]
        {
            // No mode control on non-Unix; perms is best-effort only.
            let _ = perms;
            std::fs::write(&path, &content)?;
        }
        tracing::info!(
            cookie_path = %path.display(),
            perms = format!("0{:o}", perms),
            "Cookie file written"
        );
        Ok(RpcAuth::Verify(RwLock::new(Credentials {
            cookie: Some(CookieCredential { path, token }),
            ..Default::default()
        })))
    }

    /// Convenience for the legacy default path (`$DATADIR/.cookie`, 0600).
    pub fn generate_cookie(datadir: &Path) -> std::io::Result<Self> {
        Self::generate_cookie_with(datadir.join(".cookie"), 0o600)
    }

    /// Validate an HTTP `Authorization` header value. Returns true if `Disabled`
    /// (the mTLS-only path), or if ANY held credential matches. The actual
    /// matching — including the constant-time secret comparisons — is delegated
    /// to [`satd_auth::OperatorCreds::matches`].
    pub fn validate(&self, auth_header: &str) -> bool {
        let guard = match self {
            RpcAuth::Disabled => return true,
            RpcAuth::Verify(c) => c.read(),
        };
        let creds = &*guard;
        let encoded = match auth_header.strip_prefix("Basic ") {
            Some(e) => e,
            None => return false,
        };
        let decoded = match BASE64.decode(encoded) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let decoded_str = match std::str::from_utf8(&decoded) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let (user, pass) = match decoded_str.split_once(':') {
            Some(parts) => parts,
            None => return false,
        };
        creds.matches(user, pass)
    }

    /// Is auth disabled? Used by call sites that want a header-free fast path.
    pub fn is_disabled(&self) -> bool {
        matches!(self, RpcAuth::Disabled)
    }

    /// Delete the cookie file on shutdown.
    pub fn cleanup(&self) {
        if let RpcAuth::Verify(lock) = self
            && let Some(c) = &lock.read().cookie
            && c.path.exists()
        {
            let _ = std::fs::remove_file(&c.path);
            tracing::info!("Cookie file removed");
        }
    }

    /// Rotate the `-rpcuser`/`-rpcpassword` (userpass) and `-rpcauth` credentials
    /// live, preserving the auto-generated cookie credential. Driven by SIGHUP
    /// config reload. No-op on `Disabled`.
    ///
    /// The cookie is intentionally NOT touched: it is generated once at startup
    /// and `sat-cli`'s no-flag default depends on it. If the rotation leaves zero
    /// credentials of any kind, a warning is logged.
    pub fn reload_credentials(
        &self,
        userpass: Vec<UserPassCredential>,
        rpcauth: Vec<RpcAuthCredential>,
    ) {
        if let RpcAuth::Verify(lock) = self {
            let mut creds = lock.write();
            creds.userpass = userpass;
            creds.rpcauth = rpcauth;
            if creds.is_empty() {
                tracing::warn!(
                    "RPC credential reload left no credentials configured — the RPC \
                     interface is now inaccessible until a credential is restored or \
                     the daemon is restarted (restart regenerates the cookie)"
                );
            }
        }
    }
}

/// Read a cookie file and return the full auth string (username:password).
pub fn read_cookie_file(path: &Path) -> Result<(String, String), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read cookie file {}: {}", path.display(), e))?;
    let (user, pass) = content
        .trim()
        .split_once(':')
        .ok_or_else(|| format!("Invalid cookie file format in {}", path.display()))?;
    Ok((user.to_string(), pass.to_string()))
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Tower middleware layer for HTTP auth. Authenticates a request and stashes the
/// resolved [`satd_auth::Principal`] in the request extensions (for the RPC-layer
/// capability filter and method handlers).
///
/// `bearer` is `Some` only on a surface that opted into bearer tokens
/// (`-rpcauthbearer`): such a surface accepts both the Core-compatible
/// Basic/cookie/rpcauth operator credential (→ full-capability operator
/// principal) and an `Authorization: Bearer <token>` resolving to a scoped token
/// principal. When `None`, only the operator path is live (today's behavior).
#[derive(Clone)]
pub struct AuthLayer {
    auth: Arc<RpcAuth>,
    bearer: Option<Arc<satd_auth::TokenStore>>,
}

impl AuthLayer {
    pub fn new(auth: Arc<RpcAuth>, bearer: Option<Arc<satd_auth::TokenStore>>) -> Self {
        Self { auth, bearer }
    }
}

impl<S> tower::Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            auth: self.auth.clone(),
            bearer: self.bearer.clone(),
        }
    }
}

/// Tower service that authenticates a request, stashes the resolved principal in
/// its extensions, and forwards it; an unauthenticated request gets a 401.
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    auth: Arc<RpcAuth>,
    bearer: Option<Arc<satd_auth::TokenStore>>,
}

impl<S, B> tower::Service<hyper::Request<B>> for AuthMiddleware<S>
where
    S: tower::Service<hyper::Request<B>, Response = hyper::Response<jsonrpsee::server::HttpBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: hyper::Request<B>) -> Self::Future {
        let auth = self.auth.clone();
        let bearer = self.bearer.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Auth-disabled (mTLS escape hatch, `--rpcdisableauth=1`): the rustls
            // handshake is the gate. Treat the caller as the full-capability
            // operator so the downstream capability filter (if any) is a no-op.
            if auth.is_disabled() {
                req.extensions_mut().insert(satd_auth::Principal::operator());
                return inner.call(req).await;
            }

            let header = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            // Resolve to a principal: the Core-compatible operator path
            // (cookie / userpass / rpcauth, always tried first so legacy clients
            // are unaffected), else — on a bearer-enabled surface — an opaque
            // bearer token resolving to a scoped token principal.
            let principal: Option<satd_auth::Principal> = match &header {
                Some(h) if auth.validate(h) => Some(satd_auth::Principal::operator()),
                Some(h) => bearer.as_ref().and_then(|store| {
                    let mut scratch = String::new();
                    match satd_auth::Credential::from_authorization(h, &mut scratch) {
                        Some(satd_auth::Credential::Bearer { token }) => {
                            store.resolve(token, now_unix())
                        }
                        _ => None,
                    }
                }),
                None => None,
            };

            match principal {
                Some(p) => {
                    // Per-principal rate limit (operator/loopback bypass). Shed
                    // an over-budget request with 429 + Retry-After; never block.
                    if let satd_auth::RateDecision::Throttle { retry_after_secs } = p.check_rate() {
                        let response = hyper::Response::builder()
                            .status(429)
                            .header("Retry-After", retry_after_secs.to_string())
                            .body(jsonrpsee::server::HttpBody::from("Too Many Requests"))
                            .unwrap();
                        return Ok(response);
                    }
                    req.extensions_mut().insert(p);
                    inner.call(req).await
                }
                None => {
                    let response = hyper::Response::builder()
                        .status(401)
                        .header("WWW-Authenticate", "Basic realm=\"jsonrpc\"")
                        .body(jsonrpsee::server::HttpBody::from("Unauthorized"))
                        .unwrap();
                    Ok(response)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie_auth(token: &str) -> RpcAuth {
        RpcAuth::Verify(RwLock::new(Credentials {
            cookie: Some(CookieCredential {
                path: PathBuf::from("/tmp/test.cookie"),
                token: token.to_string(),
            }),
            ..Default::default()
        }))
    }

    #[test]
    fn test_cookie_validate() {
        let auth = cookie_auth("abcdef1234567890");
        let encoded = BASE64.encode("__cookie__:abcdef1234567890");
        assert!(auth.validate(&format!("Basic {}", encoded)));
        let bad = BASE64.encode("__cookie__:wrongtoken");
        assert!(!auth.validate(&format!("Basic {}", bad)));
    }

    #[test]
    fn test_userpass_validate() {
        let auth = RpcAuth::from_user_pass("alice".to_string(), "secret".to_string());
        let encoded = BASE64.encode("alice:secret");
        assert!(auth.validate(&format!("Basic {}", encoded)));
        let bad = BASE64.encode("alice:wrong");
        assert!(!auth.validate(&format!("Basic {}", bad)));
    }

    #[test]
    fn test_invalid_auth_header() {
        let auth = RpcAuth::from_user_pass("alice".to_string(), "secret".to_string());
        assert!(!auth.validate("Bearer token123"));
        assert!(!auth.validate("Basic !!!invalid-base64!!!"));
        assert!(!auth.validate(""));
    }

    #[test]
    fn test_reload_credentials_rotates_userpass_keeps_cookie() {
        let auth = RpcAuth::Verify(RwLock::new(Credentials {
            cookie: Some(CookieCredential {
                path: PathBuf::from("/tmp/reload.cookie"),
                token: "tok".into(),
            }),
            userpass: vec![UserPassCredential {
                username: "alice".into(),
                password: "secret".into(),
            }],
            ..Default::default()
        }));
        let alice = BASE64.encode("alice:secret");
        let cookie = BASE64.encode("__cookie__:tok");
        assert!(auth.validate(&format!("Basic {}", alice)));
        assert!(auth.validate(&format!("Basic {}", cookie)));

        auth.reload_credentials(
            vec![UserPassCredential {
                username: "bob".into(),
                password: "newpass".into(),
            }],
            vec![],
        );
        let bob = BASE64.encode("bob:newpass");
        assert!(auth.validate(&format!("Basic {}", bob)), "new cred works");
        assert!(
            !auth.validate(&format!("Basic {}", alice)),
            "old userpass revoked"
        );
        assert!(
            auth.validate(&format!("Basic {}", cookie)),
            "cookie preserved across reload"
        );
    }

    #[test]
    fn test_disabled_passes_all() {
        let auth = RpcAuth::Disabled;
        assert!(auth.validate(""));
        assert!(auth.validate("Bearer anything"));
        assert!(auth.validate("Basic garbage"));
    }
}
