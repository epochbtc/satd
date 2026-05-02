//! HTTP Basic Auth middleware for the Esplora server. When
//! `EsploraAuth::None` is configured the layer is omitted entirely;
//! otherwise the layer rejects requests missing or carrying an
//! invalid `Authorization: Basic ...` header.
//!
//! The cookie format mirrors the JSON-RPC server's `__cookie__:<hex>`
//! shape so a single `.cookie` file covers both surfaces (the
//! `EsploraAuth::Cookie` variant defaults to that same path).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::config::EsploraAuth;

/// Resolved expected credentials. Built once at server start and
/// shared across requests.
#[derive(Debug, Clone)]
pub enum AuthExpectation {
    None,
    UserPass { username: String, password: String },
}

impl AuthExpectation {
    pub fn build(cfg: &EsploraAuth) -> Result<Self, String> {
        match cfg {
            EsploraAuth::None => Ok(Self::None),
            EsploraAuth::UserPass { username, password } => Ok(Self::UserPass {
                username: username.clone(),
                password: password.clone(),
            }),
            EsploraAuth::Cookie { path } => {
                let content = std::fs::read_to_string(path).map_err(|e| {
                    format!("esplora auth: cannot read cookie {}: {}", path.display(), e)
                })?;
                let (user, pass) = content.trim().split_once(':').ok_or_else(|| {
                    format!("esplora auth: malformed cookie at {}", path.display())
                })?;
                Ok(Self::UserPass {
                    username: user.to_string(),
                    password: pass.to_string(),
                })
            }
        }
    }

    fn check(&self, header: Option<&str>) -> bool {
        let expected = match self {
            Self::None => return true,
            Self::UserPass { username, password } => (username, password),
        };
        let Some(hdr) = header else {
            return false;
        };
        let Some(encoded) = hdr.strip_prefix("Basic ") else {
            return false;
        };
        let Ok(decoded) = BASE64.decode(encoded) else {
            return false;
        };
        let Ok(decoded_str) = std::str::from_utf8(&decoded) else {
            return false;
        };
        let Some((user, pass)) = decoded_str.split_once(':') else {
            return false;
        };
        user == expected.0 && pass == expected.1
    }
}

/// Axum middleware function. Wired only when auth is enabled.
pub async fn require_auth(
    axum::extract::State(expected): axum::extract::State<Arc<AuthExpectation>>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if !expected.check(header.as_deref()) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                axum::http::header::WWW_AUTHENTICATE,
                "Basic realm=\"esplora\"",
            )
            .body(Body::from("Unauthorized"))
            .unwrap();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_none_always_passes() {
        let exp = AuthExpectation::None;
        assert!(exp.check(None));
        assert!(exp.check(Some("garbage")));
    }

    #[test]
    fn test_check_userpass_valid() {
        let exp = AuthExpectation::UserPass {
            username: "alice".into(),
            password: "secret".into(),
        };
        let header = format!("Basic {}", BASE64.encode("alice:secret"));
        assert!(exp.check(Some(&header)));
    }

    #[test]
    fn test_check_userpass_wrong_password() {
        let exp = AuthExpectation::UserPass {
            username: "alice".into(),
            password: "secret".into(),
        };
        let header = format!("Basic {}", BASE64.encode("alice:wrong"));
        assert!(!exp.check(Some(&header)));
    }

    #[test]
    fn test_check_userpass_missing_header() {
        let exp = AuthExpectation::UserPass {
            username: "alice".into(),
            password: "secret".into(),
        };
        assert!(!exp.check(None));
    }

    #[test]
    fn test_check_userpass_non_basic_scheme_rejected() {
        let exp = AuthExpectation::UserPass {
            username: "alice".into(),
            password: "secret".into(),
        };
        assert!(!exp.check(Some("Bearer xyz")));
    }
}
