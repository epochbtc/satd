use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

/// RPC authentication policy attached to a listener surface.
///
/// `Disabled` is reserved for the mTLS escape hatch on the TLS
/// surface (`--rpcdisableauth=1` + `--rpcmtls=1`): clients prove
/// identity via the mTLS client cert and the AuthLayer becomes a
/// pass-through. It must NEVER be used on the plain-HTTP surface —
/// the satd binary refuses that configuration at startup.
///
/// `Verify` holds zero or more credentials of three Bitcoin-Core-
/// compatible kinds (cookie, userpass, rpcauth). A request is
/// accepted if ANY single credential validates against the supplied
/// Basic-auth header. This matches Bitcoin Core's behaviour, where
/// `-rpcuser`/`-rpcpassword`, `-rpcauth=` (repeatable), and the
/// auto-generated cookie all open the door simultaneously.
#[derive(Debug, Clone)]
pub enum RpcAuth {
    Disabled,
    Verify(Credentials),
}

#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub cookie: Option<CookieCredential>,
    pub userpass: Vec<UserPassCredential>,
    pub rpcauth: Vec<RpcAuthCredential>,
}

#[derive(Debug, Clone)]
pub struct CookieCredential {
    pub path: PathBuf,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct UserPassCredential {
    pub username: String,
    pub password: String,
}

/// One Bitcoin-Core-compatible `-rpcauth` entry, post-parse. `salt` is
/// the printable salt string from the config line; its ASCII bytes are
/// the HMAC key (Core's rpcauth.py does `salt.encode('utf-8')`). `hash`
/// is the expected 32-byte tag.
#[derive(Debug, Clone)]
pub struct RpcAuthCredential {
    pub username: String,
    pub salt: String,
    pub hash: Vec<u8>,
}

impl RpcAuth {
    /// Build the legacy single-userpass form. Retained for call sites
    /// (and tests) that don't yet need multi-credential support.
    pub fn from_user_pass(username: String, password: String) -> Self {
        RpcAuth::Verify(Credentials {
            userpass: vec![UserPassCredential { username, password }],
            ..Default::default()
        })
    }

    /// Generate the cookie file at the given path with `perms` (octal),
    /// and return the credential-bearing `RpcAuth`. The cookie value
    /// stored is `__cookie__:<token>` per Core's convention. Removed by
    /// `cleanup()` on shutdown.
    ///
    /// The secret must never exist on disk with broader permissions than
    /// requested, even momentarily. On Unix we therefore write to a temp
    /// file in the destination directory created with the target mode at
    /// `open(2)` time (so the kernel applies it before any bytes land),
    /// then atomically `rename(2)` it into place. A bare
    /// `write`-then-`chmod` would leave a window where the cookie is
    /// readable per the process umask.
    pub fn generate_cookie_with(
        path: PathBuf,
        perms: u32,
    ) -> std::io::Result<Self> {
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
            // create_new + mode: born with restrictive perms, fails if a
            // stale temp exists rather than reusing a foreign file.
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
            // open() honours mode only when creating; an inherited umask
            // can still mask bits off. Force the exact perms before the
            // rename publishes the file.
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
        Ok(RpcAuth::Verify(Credentials {
            cookie: Some(CookieCredential { path, token }),
            ..Default::default()
        }))
    }

    /// Convenience for the legacy default path (`$DATADIR/.cookie`,
    /// 0600). Equivalent to `generate_cookie_with(datadir.join(".cookie"), 0o600)`.
    pub fn generate_cookie(datadir: &Path) -> std::io::Result<Self> {
        Self::generate_cookie_with(datadir.join(".cookie"), 0o600)
    }

    /// Validate an HTTP Authorization header value. Returns true if
    /// `Disabled` (the mTLS-only path), or if ANY held credential
    /// matches. Constant-time comparison is used for the HMAC tag in
    /// the rpcauth path; cookie / userpass comparisons are plain
    /// `==` (the secret length is fixed and known to the operator).
    pub fn validate(&self, auth_header: &str) -> bool {
        let creds = match self {
            RpcAuth::Disabled => return true,
            RpcAuth::Verify(c) => c,
        };
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

        // Cookie credential — only the `__cookie__` username is valid.
        if let Some(c) = &creds.cookie
            && user == "__cookie__"
            && pass == c.token
        {
            return true;
        }
        // Plain user/password credentials.
        for up in &creds.userpass {
            if user == up.username && pass == up.password {
                return true;
            }
        }
        // rpcauth (HMAC-SHA256). Constant-time tag compare via
        // `Mac::verify_slice` so a timing attack can't peel off the
        // hash one byte at a time.
        for ra in &creds.rpcauth {
            if user != ra.username {
                continue;
            }
            let Ok(mut mac) = HmacSha256::new_from_slice(ra.salt.as_bytes()) else {
                continue;
            };
            mac.update(pass.as_bytes());
            if mac.verify_slice(&ra.hash).is_ok() {
                return true;
            }
        }
        false
    }

    /// Is auth disabled? Used by call sites that want a header-free
    /// fast path (the request middleware can skip reading the header
    /// entirely, including for the `Disabled`-on-mTLS-only path).
    pub fn is_disabled(&self) -> bool {
        matches!(self, RpcAuth::Disabled)
    }

    /// Delete the cookie file on shutdown.
    pub fn cleanup(&self) {
        if let RpcAuth::Verify(creds) = self
            && let Some(c) = &creds.cookie
            && c.path.exists()
        {
            let _ = std::fs::remove_file(&c.path);
            tracing::info!("Cookie file removed");
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

/// Tower middleware layer for HTTP Basic Auth.
#[derive(Clone)]
pub struct AuthLayer {
    auth: Arc<RpcAuth>,
}

impl AuthLayer {
    pub fn new(auth: Arc<RpcAuth>) -> Self {
        Self { auth }
    }
}

impl<S> tower::Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            auth: self.auth.clone(),
        }
    }
}

/// Tower service that checks HTTP Basic Auth before forwarding requests.
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    auth: Arc<RpcAuth>,
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

    fn call(&mut self, req: hyper::Request<B>) -> Self::Future {
        let auth = self.auth.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Auth-disabled short-circuit: skip the header read
            // entirely. Used by the mTLS-only TLS surface when
            // `--rpcdisableauth=1` — the rustls handshake is the
            // actual gate, and clients are not expected to send a
            // Basic header.
            if auth.is_disabled() {
                return inner.call(req).await;
            }
            // Check Authorization header
            let authorized = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(|header| auth.validate(header))
                .unwrap_or(false);

            if !authorized {
                let response = hyper::Response::builder()
                    .status(401)
                    .header("WWW-Authenticate", "Basic realm=\"jsonrpc\"")
                    .body(jsonrpsee::server::HttpBody::from("Unauthorized"))
                    .unwrap();
                return Ok(response);
            }

            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie_auth(token: &str) -> RpcAuth {
        RpcAuth::Verify(Credentials {
            cookie: Some(CookieCredential {
                path: PathBuf::from("/tmp/test.cookie"),
                token: token.to_string(),
            }),
            ..Default::default()
        })
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
    fn test_rpcauth_validate() {
        // FIXED VECTOR from Bitcoin Core's share/rpcauth/rpcauth.py
        // semantics: HMAC-SHA256 with key = salt.encode('utf-8') (the
        // ASCII bytes of the printable salt string, NOT hex-decoded) and
        // message = password. Generated independently with CPython:
        //   hmac.new(salt.encode(), password.encode(), 'sha256').hexdigest()
        // for salt="deadbeefcafef00d1122334455667788",
        //     password="hunter2longpassword".
        // This MUST NOT be re-derived by our own implementation, or it
        // can't catch a salt-handling regression.
        let salt = "deadbeefcafef00d1122334455667788".to_string();
        let hash =
            hex::decode("9383f6d244049af54e59a84188e2f2b1e58ff20de019156bc0c430ff8ae4c7a3")
                .unwrap();
        let auth = RpcAuth::Verify(Credentials {
            rpcauth: vec![RpcAuthCredential {
                username: "alice".to_string(),
                salt,
                hash,
            }],
            ..Default::default()
        });
        let ok = BASE64.encode("alice:hunter2longpassword");
        assert!(auth.validate(&format!("Basic {}", ok)));
        let bad_pass = BASE64.encode("alice:wrong");
        assert!(!auth.validate(&format!("Basic {}", bad_pass)));
        let bad_user = BASE64.encode("bob:hunter2longpassword");
        assert!(!auth.validate(&format!("Basic {}", bad_user)));
    }

    #[test]
    fn test_multi_credential_any_passes() {
        let salt = "aabbccddeeff00112233445566778899".to_string();
        let mut mac = HmacSha256::new_from_slice(salt.as_bytes()).unwrap();
        mac.update(b"p4ss");
        let hash = mac.finalize().into_bytes().to_vec();
        let auth = RpcAuth::Verify(Credentials {
            cookie: Some(CookieCredential {
                path: PathBuf::from("/tmp/x.cookie"),
                token: "tok".to_string(),
            }),
            userpass: vec![UserPassCredential {
                username: "alice".to_string(),
                password: "secret".to_string(),
            }],
            rpcauth: vec![RpcAuthCredential {
                username: "bob".to_string(),
                salt,
                hash,
            }],
        });
        let cookie_ok = BASE64.encode("__cookie__:tok");
        let userpass_ok = BASE64.encode("alice:secret");
        let rpcauth_ok = BASE64.encode("bob:p4ss");
        assert!(auth.validate(&format!("Basic {}", cookie_ok)));
        assert!(auth.validate(&format!("Basic {}", userpass_ok)));
        assert!(auth.validate(&format!("Basic {}", rpcauth_ok)));
        let none = BASE64.encode("eve:noway");
        assert!(!auth.validate(&format!("Basic {}", none)));
    }

    #[test]
    fn test_disabled_passes_all() {
        let auth = RpcAuth::Disabled;
        assert!(auth.validate(""));
        assert!(auth.validate("Bearer anything"));
        assert!(auth.validate("Basic garbage"));
    }
}
