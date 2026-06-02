//! HTTP Basic Auth middleware for the Esplora server. When
//! `EsploraAuth::None` is configured the layer is omitted entirely;
//! otherwise the layer rejects requests missing or carrying an
//! invalid `Authorization: Basic ...` header.
//!
//! The cookie format mirrors the JSON-RPC server's `__cookie__:<hex>`
//! shape so a single `.cookie` file covers both surfaces (the
//! `EsploraAuth::Cookie` variant defaults to that same path).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;
use satd_auth::{Capability, CapabilitySet, Credential, OperatorCreds, Principal, TokenStore};

use crate::config::EsploraAuth;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Resolved expected credentials. Built once at server start and shared across
/// requests.
///
/// Credential parsing + the constant-time secret compare are delegated to the
/// shared [`satd_auth`] verifier. A request is authorized iff it resolves to a
/// principal holding [`Capability::EsploraRead`]: the legacy operator
/// (cookie / userpass, full capabilities) and — when `-esploraauthbearer` is on
/// — a bearer token carrying `esplora:read`.
#[derive(Clone)]
pub enum AuthExpectation {
    /// Wide-open: no operator credential and no bearer store.
    None,
    /// At least one credential path is configured; a request must satisfy it.
    Required {
        /// Operator credential (cookie / userpass), or `None` when the legacy
        /// `auth` mode is `None` but bearer tokens are enabled.
        operator: Option<OperatorCreds>,
        /// Bearer-token store, `Some` only when `-esploraauthbearer` is set.
        bearer: Option<Arc<TokenStore>>,
    },
}

impl AuthExpectation {
    pub fn build(cfg: &EsploraAuth, bearer: Option<Arc<TokenStore>>) -> Result<Self, String> {
        let operator = match cfg {
            EsploraAuth::None => None,
            EsploraAuth::UserPass { username, password } => {
                Some(OperatorCreds::from_user_pass(username.clone(), password.clone()))
            }
            EsploraAuth::Cookie { path } => {
                let content = std::fs::read_to_string(path).map_err(|e| {
                    format!("esplora auth: cannot read cookie {}: {}", path.display(), e)
                })?;
                let (user, pass) = content.trim().split_once(':').ok_or_else(|| {
                    format!("esplora auth: malformed cookie at {}", path.display())
                })?;
                Some(OperatorCreds::from_user_pass(user.to_string(), pass.to_string()))
            }
        };
        if operator.is_none() && bearer.is_none() {
            Ok(Self::None)
        } else {
            Ok(Self::Required { operator, bearer })
        }
    }

    /// Whether bearer/operator auth is active (the middleware should be wired).
    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Resolve the request's credential to a principal, or `None`.
    fn principal(&self, header: Option<&str>) -> Option<Principal> {
        let (operator, bearer) = match self {
            // Wide-open: a loopback principal with full capabilities.
            Self::None => return Some(Principal::loopback(CapabilitySet::ALL)),
            Self::Required { operator, bearer } => (operator, bearer),
        };
        let hdr = header?;
        let mut scratch = String::new();
        match Credential::from_authorization(hdr, &mut scratch) {
            Some(Credential::Basic { user, pass }) => {
                if operator.as_ref().is_some_and(|c| c.matches(user, pass)) {
                    Some(Principal::operator())
                } else {
                    None
                }
            }
            Some(Credential::Bearer { token }) => {
                bearer.as_ref().and_then(|s| s.resolve(token, now_unix()))
            }
            _ => None,
        }
    }

    /// Evaluate a request: resolve the principal, require `esplora:read`, and
    /// charge the per-principal rate limit. On success the resolved [`Principal`]
    /// is returned so the middleware can stash it in request extensions — the
    /// SSE watch handlers read it to enforce the per-tenant watch-set quota.
    fn evaluate(&self, header: Option<&str>) -> AuthOutcome {
        let Some(principal) = self.principal(header) else {
            return AuthOutcome::Unauthorized;
        };
        if !principal.has(Capability::EsploraRead) {
            return AuthOutcome::Unauthorized;
        }
        match principal.check_rate() {
            satd_auth::RateDecision::Allow => AuthOutcome::Authorized(principal),
            satd_auth::RateDecision::Throttle { retry_after_secs } => {
                AuthOutcome::RateLimited { retry_after_secs }
            }
        }
    }

    #[cfg(test)]
    fn check(&self, header: Option<&str>) -> bool {
        matches!(self.evaluate(header), AuthOutcome::Authorized(_))
    }
}

/// Outcome of evaluating a request's credential against the expectation.
enum AuthOutcome {
    Authorized(Principal),
    Unauthorized,
    RateLimited { retry_after_secs: u32 },
}

/// Axum middleware function. Wired only when auth is enabled.
pub async fn require_auth(
    axum::extract::State(expected): axum::extract::State<Arc<AuthExpectation>>,
    mut req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    match expected.evaluate(header.as_deref()) {
        AuthOutcome::Authorized(principal) => {
            // Stash the resolved principal so downstream handlers (SSE watch
            // quota) can read it. Cheap clone (a few fields + two Arcs).
            req.extensions_mut().insert(principal);
            next.run(req).await
        }
        AuthOutcome::Unauthorized => Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                axum::http::header::WWW_AUTHENTICATE,
                "Basic realm=\"esplora\"",
            )
            .body(Body::from("Unauthorized"))
            .unwrap(),
        // Per-principal rate limit: shed with 429 + Retry-After, never block.
        AuthOutcome::RateLimited { retry_after_secs } => Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header(axum::http::header::RETRY_AFTER, retry_after_secs.to_string())
            .body(Body::from("Too Many Requests"))
            .unwrap(),
    }
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
        AuthExpectation::Required {
            operator: Some(OperatorCreds::from_user_pass(
                username.to_string(),
                password.to_string(),
            )),
            bearer: None,
        }
    }

    fn token_store_with(id: &str, plaintext: &str, caps: &str) -> Arc<TokenStore> {
        use sha2::{Digest, Sha256};
        use std::io::Write;
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let h = format!("sha256:{}", hex::encode(Sha256::digest(plaintext.as_bytes())));
        let caps_list = caps
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let toml = format!(
            "version=1\n[[token]]\nid=\"{id}\"\nhash=\"{h}\"\ncapabilities=[{caps_list}]\n"
        );
        let p = dir.path().join("auth.toml");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Arc::new(TokenStore::load(&p).unwrap())
    }

    #[test]
    fn bearer_token_with_esplora_read_is_accepted() {
        let exp = AuthExpectation::Required {
            operator: None,
            bearer: Some(token_store_with("ro", "esplora-token", "esplora:read")),
        };
        assert!(exp.is_enabled());
        assert!(exp.check(Some("Bearer esplora-token")));
        // A token lacking esplora:read is rejected even though it authenticates.
        let exp2 = AuthExpectation::Required {
            operator: None,
            bearer: Some(token_store_with("rpc", "rpc-token", "rpc:read")),
        };
        assert!(!exp2.check(Some("Bearer rpc-token")));
        // Unknown token rejected.
        assert!(!exp.check(Some("Bearer nope")));
        // Missing header rejected.
        assert!(!exp.check(None));
    }

    #[test]
    fn operator_and_bearer_coexist() {
        let exp = AuthExpectation::Required {
            operator: Some(OperatorCreds::from_user_pass("alice".into(), "secret".into())),
            bearer: Some(token_store_with("ro", "esplora-token", "esplora:read")),
        };
        // Operator Basic works.
        let basic = format!("Basic {}", BASE64.encode("alice:secret"));
        assert!(exp.check(Some(&basic)));
        // Bearer works.
        assert!(exp.check(Some("Bearer esplora-token")));
        // Wrong operator password rejected.
        let bad = format!("Basic {}", BASE64.encode("alice:wrong"));
        assert!(!exp.check(Some(&bad)));
    }
}
