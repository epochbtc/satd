//! The one verifier: resolves a [`Credential`] to a [`Principal`].
//!
//! Consolidating verification in a single, audited, fuzzed gate is the whole
//! point of this crate (SATD_AUTH_PLAN.md §4) — a far smaller security surface
//! than five bespoke schemes. Every surface's carrier adapter funnels through
//! [`Verifier::resolve`].

use std::sync::Arc;

use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::credential::Credential;
use crate::error::AuthError;
use crate::operator::OperatorCreds;
use crate::principal::Principal;
use crate::quota::unlimited;
use crate::store::TokenStore;

/// Resolves credentials to principals against the operator credentials (cookie /
/// userpass / rpcauth → operator principal) and the bearer-token store.
///
/// Operator credentials live behind an `RwLock` so a SIGHUP config reload can
/// rotate `-rpcuser`/`-rpcpassword`/`-rpcauth` live (the cookie is preserved by
/// the reload path). The token store has its own internal reload. `clock`
/// supplies "now" (unix seconds) for token-expiry checks and is injectable in
/// tests.
pub struct Verifier {
    operator: RwLock<OperatorCreds>,
    store: Option<Arc<TokenStore>>,
    clock: fn() -> i64,
}

fn system_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Verifier {
    /// Build a verifier. Pass `store = None` when no `authfile` is configured —
    /// bearer credentials then always fail and only the operator path is live.
    pub fn new(operator: OperatorCreds, store: Option<Arc<TokenStore>>) -> Verifier {
        Verifier {
            operator: RwLock::new(operator),
            store,
            clock: system_now,
        }
    }

    /// Build a verifier with an injected clock (tests).
    pub fn with_clock(
        operator: OperatorCreds,
        store: Option<Arc<TokenStore>>,
        clock: fn() -> i64,
    ) -> Verifier {
        Verifier {
            operator: RwLock::new(operator),
            store,
            clock,
        }
    }

    /// Rotate the operator credentials live (SIGHUP). The token store reloads
    /// independently via its own `reload()`.
    pub fn reload_operator(&self, operator: OperatorCreds) {
        *self.operator.write() = operator;
    }

    /// Is a bearer-token store configured?
    pub fn has_token_store(&self) -> bool {
        self.store.is_some()
    }

    /// Resolve a credential to a principal, or an [`AuthError`].
    pub fn resolve(&self, cred: Credential<'_>) -> Result<Principal, AuthError> {
        match cred {
            Credential::Bearer { token } => self.resolve_bearer(token),
            Credential::Basic { user, pass } => self.resolve_basic(user, pass),
            // mTLS client-cert principals arrive in the Electrum phase; the
            // crate carries the variant now for a stable API.
            Credential::ClientCert { .. } => Err(AuthError::Unsupported),
        }
    }

    fn resolve_basic(&self, user: &str, pass: &str) -> Result<Principal, AuthError> {
        if self.operator.read().matches(user, pass) {
            Ok(Principal::operator())
        } else {
            Err(AuthError::Unauthenticated)
        }
    }

    fn resolve_bearer(&self, token: &str) -> Result<Principal, AuthError> {
        let store = self.store.as_ref().ok_or(AuthError::Unauthenticated)?;
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();

        let table = store.snapshot();
        let entry = table.get(&digest).ok_or(AuthError::Unauthenticated)?;

        // Belt-and-suspenders: the map lookup already matched the key, but run a
        // constant-time compare against the stored hash so the accept decision
        // never short-circuits on a near-collision. (We protect the secret
        // compare; map-key-existence timing is acceptable for ≥256-bit tokens.)
        if !bool::from(entry.hash.ct_eq(&digest)) {
            return Err(AuthError::Unauthenticated);
        }

        // Expiry (a removed/rotated token is revoked by the store reload; this
        // catches time-based expiry of a still-present entry).
        if let Some(exp) = entry.expires
            && (self.clock)() >= exp
        {
            return Err(AuthError::Unauthenticated);
        }

        // Token principals get unlimited (no-op) accounting in this PR; the real
        // per-principal token-bucket / occupancy accounting is wired in later.
        Ok(Principal::token(
            entry.id.clone(),
            entry.caps,
            entry.watch_quota,
            entry.rate_limit,
            unlimited(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;
    use crate::principal::PrincipalKind;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use sha2::Sha256;
    use std::io::Write;
    use std::path::Path;

    fn store_with(tokens: &[(&str, &str, &str)]) -> Arc<TokenStore> {
        // tokens: (id, plaintext, capabilities-csv)
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let mut toml = String::from("version = 1\n");
        for (id, plain, caps) in tokens {
            let h = format!("sha256:{}", hex::encode(Sha256::digest(plain.as_bytes())));
            let caps_list = caps
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|c| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(", ");
            toml.push_str(&format!(
                "[[token]]\nid=\"{id}\"\nhash=\"{h}\"\ncapabilities=[{caps_list}]\n"
            ));
        }
        let p: &Path = Box::leak(Box::new(dir.path().join("auth.toml")));
        let mut f = std::fs::File::create(p).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Arc::new(TokenStore::load(p).unwrap())
    }

    #[test]
    fn operator_basic_resolves_to_operator() {
        let op = OperatorCreds::from_user_pass("alice".into(), "secret".into());
        let v = Verifier::new(op, None);
        let p = v
            .resolve(Credential::Basic {
                user: "alice",
                pass: "secret",
            })
            .unwrap();
        assert!(matches!(p.kind, PrincipalKind::Operator));
        assert!(p.has(Capability::RpcWrite));

        let err = v
            .resolve(Credential::Basic {
                user: "alice",
                pass: "wrong",
            })
            .unwrap_err();
        assert_eq!(err, AuthError::Unauthenticated);
    }

    #[test]
    fn bearer_resolves_with_scoped_caps() {
        let store = store_with(&[("ro", "secret-token", "rpc:read")]);
        let v = Verifier::new(OperatorCreds::default(), Some(store));
        let p = v
            .resolve(Credential::Bearer {
                token: "secret-token",
            })
            .unwrap();
        assert_eq!(p.id(), "ro");
        assert!(p.has(Capability::RpcRead));
        assert!(!p.has(Capability::RpcWrite));

        assert_eq!(
            v.resolve(Credential::Bearer { token: "wrong" }).unwrap_err(),
            AuthError::Unauthenticated
        );
    }

    #[test]
    fn bearer_without_store_always_fails() {
        let v = Verifier::new(OperatorCreds::default(), None);
        assert_eq!(
            v.resolve(Credential::Bearer { token: "anything" })
                .unwrap_err(),
            AuthError::Unauthenticated
        );
    }

    #[test]
    fn expired_token_rejected() {
        // Build a store whose single token expires at t=1000.
        let dir = tempfile::tempdir().unwrap();
        let h = format!("sha256:{}", hex::encode(Sha256::digest(b"tok")));
        let toml = format!(
            "version=1\n[[token]]\nid=\"x\"\nhash=\"{h}\"\nexpires=1970-01-01T00:16:40Z\n"
        );
        let p = dir.path().join("auth.toml");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Arc::new(TokenStore::load(&p).unwrap());

        // clock before expiry → ok; at/after → rejected.
        let before = Verifier::with_clock(OperatorCreds::default(), Some(store.clone()), || 999);
        assert!(before.resolve(Credential::Bearer { token: "tok" }).is_ok());
        let after = Verifier::with_clock(OperatorCreds::default(), Some(store), || 1000);
        assert_eq!(
            after.resolve(Credential::Bearer { token: "tok" }).unwrap_err(),
            AuthError::Unauthenticated
        );
    }

    #[test]
    fn reload_operator_rotates_live() {
        let v = Verifier::new(
            OperatorCreds::from_user_pass("alice".into(), "secret".into()),
            None,
        );
        assert!(v.resolve(Credential::Basic { user: "alice", pass: "secret" }).is_ok());
        v.reload_operator(OperatorCreds::from_user_pass("bob".into(), "newpass".into()));
        assert!(v.resolve(Credential::Basic { user: "alice", pass: "secret" }).is_err());
        assert!(v.resolve(Credential::Basic { user: "bob", pass: "newpass" }).is_ok());
    }

    #[test]
    fn client_cert_unsupported_for_now() {
        let v = Verifier::new(OperatorCreds::default(), None);
        assert_eq!(
            v.resolve(Credential::ClientCert { subject: "cn=x" }).unwrap_err(),
            AuthError::Unsupported
        );
    }

    // Keep the BASE64 import exercised (documents the Basic carrier path).
    #[test]
    fn basic_header_shape_is_what_carriers_send() {
        let op = OperatorCreds::from_user_pass("u".into(), "p".into());
        let v = Verifier::new(op, None);
        let mut scratch = String::new();
        let hdr = format!("Basic {}", BASE64.encode("u:p"));
        let cred = Credential::from_authorization(&hdr, &mut scratch).unwrap();
        assert!(v.resolve(cred).is_ok());
    }
}
