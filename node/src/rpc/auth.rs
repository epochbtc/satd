use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// RPC authentication credentials.
#[derive(Debug, Clone)]
pub enum RpcAuth {
    Cookie { path: PathBuf, token: String },
    UserPass { username: String, password: String },
}

impl RpcAuth {
    /// Generate a cookie file with a random token in the given directory.
    pub fn generate_cookie(datadir: &Path) -> std::io::Result<Self> {
        let token: String = {
            let mut rng = rand::thread_rng();
            let bytes: Vec<u8> = (0..32).map(|_| rand::Rng::r#gen::<u8>(&mut rng)).collect();
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        };
        let path = datadir.join(".cookie");
        let content = format!("__cookie__:{}", token);
        std::fs::write(&path, &content)?;
        // Set file permissions to 0600 on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!("Cookie file written to {}", path.display());
        Ok(RpcAuth::Cookie { path, token })
    }

    /// Create auth from explicit user/password.
    pub fn from_user_pass(username: String, password: String) -> Self {
        RpcAuth::UserPass { username, password }
    }

    /// Validate an HTTP Authorization header value.
    /// Expected format: "Basic <base64(username:password)>"
    pub fn validate(&self, auth_header: &str) -> bool {
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

        match self {
            RpcAuth::Cookie { token, .. } => user == "__cookie__" && pass == token,
            RpcAuth::UserPass {
                username,
                password,
            } => user == username && pass == password,
        }
    }

    /// Delete the cookie file on shutdown.
    pub fn cleanup(&self) {
        if let RpcAuth::Cookie { path, .. } = self
            && path.exists() {
                let _ = std::fs::remove_file(path);
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

    #[test]
    fn test_cookie_validate() {
        let auth = RpcAuth::Cookie {
            path: PathBuf::from("/tmp/test.cookie"),
            token: "abcdef1234567890".to_string(),
        };
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
}
