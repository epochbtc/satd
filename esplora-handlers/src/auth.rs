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
use satd_auth::{Credential, OperatorCreds};

use crate::config::EsploraAuth;

/// Resolved expected credentials. Built once at server start and
/// shared across requests.
///
/// The credential matching (including the constant-time secret compare and the
/// `Authorization`-header parse) is delegated to the shared
/// [`satd_auth`] verifier, so this surface no longer carries a bespoke
/// constant-time routine.
#[derive(Debug, Clone)]
pub enum AuthExpectation {
    None,
    UserPass { creds: OperatorCreds },
}

impl AuthExpectation {
    pub fn build(cfg: &EsploraAuth) -> Result<Self, String> {
        match cfg {
            EsploraAuth::None => Ok(Self::None),
            EsploraAuth::UserPass { username, password } => Ok(Self::UserPass {
                creds: OperatorCreds::from_user_pass(username.clone(), password.clone()),
            }),
            EsploraAuth::Cookie { path } => {
                let content = std::fs::read_to_string(path).map_err(|e| {
                    format!("esplora auth: cannot read cookie {}: {}", path.display(), e)
                })?;
                let (user, pass) = content.trim().split_once(':').ok_or_else(|| {
                    format!("esplora auth: malformed cookie at {}", path.display())
                })?;
                Ok(Self::UserPass {
                    creds: OperatorCreds::from_user_pass(user.to_string(), pass.to_string()),
                })
            }
        }
    }

    fn check(&self, header: Option<&str>) -> bool {
        let creds = match self {
            Self::None => return true,
            Self::UserPass { creds } => creds,
        };
        let Some(hdr) = header else {
            return false;
        };
        // Parse via the shared verifier (RFC 7235 case-insensitive scheme,
        // base64 decode, `user:pass` split), then constant-time match. Only the
        // Basic carrier is honored on this surface in this PR; the bearer carrier
        // is added with the `esploraauthbearer` participation flag.
        let mut scratch = String::new();
        match Credential::from_authorization(hdr, &mut scratch) {
            Some(Credential::Basic { user, pass }) => creds.matches(user, pass),
            _ => false,
        }
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
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    #[test]
    fn test_check_none_always_passes() {
        let exp = AuthExpectation::None;
        assert!(exp.check(None));
        assert!(exp.check(Some("garbage")));
    }

    #[test]
    fn test_check_userpass_valid() {
        let exp = userpass("alice", "secret");
        let header = format!("Basic {}", BASE64.encode("alice:secret"));
        assert!(exp.check(Some(&header)));
    }

    #[test]
    fn test_check_userpass_wrong_password() {
        let exp = userpass("alice", "secret");
        let header = format!("Basic {}", BASE64.encode("alice:wrong"));
        assert!(!exp.check(Some(&header)));
    }

    #[test]
    fn test_check_userpass_missing_header() {
        let exp = userpass("alice", "secret");
        assert!(!exp.check(None));
    }

    #[test]
    fn test_check_userpass_non_basic_scheme_rejected() {
        let exp = userpass("alice", "secret");
        assert!(!exp.check(Some("Bearer xyz")));
    }

    #[test]
    fn test_check_userpass_basic_scheme_case_insensitive() {
        let exp = userpass("alice", "secret");
        let header = format!("basic {}", BASE64.encode("alice:secret"));
        assert!(exp.check(Some(&header)));
        let header2 = format!("BASIC {}", BASE64.encode("alice:secret"));
        assert!(exp.check(Some(&header2)));
    }

    fn userpass(username: &str, password: &str) -> AuthExpectation {
        AuthExpectation::UserPass {
            creds: OperatorCreds::from_user_pass(username.to_string(), password.to_string()),
        }
    }
}
