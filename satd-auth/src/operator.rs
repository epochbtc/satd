//! The Core-compatible operator credential set: cookie, `-rpcuser`/`-rpcpassword`,
//! and `-rpcauth` (HMAC-SHA256). Any one matching credential authenticates the
//! operator principal.
//!
//! This is the single home for the Bitcoin-Core-compatible credential logic;
//! `node/src/rpc/auth.rs` becomes a thin shim over it (PR2). The HMAC tag
//! comparison is constant-time (`Mac::verify_slice`) so a timing attack can't
//! peel off the hash one byte at a time.

use std::path::PathBuf;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The auto-generated cookie credential (`__cookie__:<hex>`).
#[derive(Debug, Clone)]
pub struct CookieCredential {
    /// Where the cookie file lives (for cleanup on shutdown).
    pub path: PathBuf,
    /// The 64-hex-char token (the password half; username is always
    /// `__cookie__`).
    pub token: String,
}

/// A `-rpcuser`/`-rpcpassword` pair.
#[derive(Debug, Clone)]
pub struct UserPassCredential {
    /// Username.
    pub username: String,
    /// Password (compared by value; secret length is fixed and operator-known).
    pub password: String,
}

/// One parsed Bitcoin-Core `-rpcauth=user:salt$hash` entry. `salt`'s ASCII bytes
/// are the HMAC key (Core's `rpcauth.py` does `salt.encode('utf-8')`); `hash` is
/// the expected 32-byte tag.
#[derive(Debug, Clone)]
pub struct RpcAuthCredential {
    /// Username.
    pub username: String,
    /// Printable salt string (its ASCII bytes are the HMAC key).
    pub salt: String,
    /// Expected 32-byte HMAC-SHA256 tag.
    pub hash: Vec<u8>,
}

/// Zero or more operator credentials of the three Core-compatible kinds. A
/// request authenticates the operator if **any** credential matches the
/// presented `user:pass` (Core's behaviour: cookie, `-rpcuser`/`-rpcpassword`,
/// and every `-rpcauth=` open the door simultaneously).
#[derive(Debug, Clone, Default)]
pub struct OperatorCreds {
    /// The auto-generated cookie, if one was written.
    pub cookie: Option<CookieCredential>,
    /// `-rpcuser`/`-rpcpassword` pairs.
    pub userpass: Vec<UserPassCredential>,
    /// `-rpcauth` HMAC entries.
    pub rpcauth: Vec<RpcAuthCredential>,
}

impl OperatorCreds {
    /// Build the legacy single-userpass form (call sites / tests that don't need
    /// the full multi-credential set).
    pub fn from_user_pass(username: String, password: String) -> OperatorCreds {
        OperatorCreds {
            userpass: vec![UserPassCredential { username, password }],
            ..Default::default()
        }
    }

    /// Does `user`/`pass` match any held credential? Constant-time for the HMAC
    /// tag compare; cookie/userpass use value equality (fixed, operator-known
    /// secret lengths — same trade-off as Bitcoin Core).
    pub fn matches(&self, user: &str, pass: &str) -> bool {
        // Cookie — only the `__cookie__` username is valid.
        if let Some(c) = &self.cookie
            && user == "__cookie__"
            && pass == c.token
        {
            return true;
        }
        // Plain user/password.
        for up in &self.userpass {
            if user == up.username && pass == up.password {
                return true;
            }
        }
        // rpcauth (HMAC-SHA256), constant-time tag compare.
        for ra in &self.rpcauth {
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

    /// True if no credential of any kind is configured — the operator surface is
    /// then unauthenticatable (caller should warn).
    pub fn is_empty(&self) -> bool {
        self.cookie.is_none() && self.userpass.is_empty() && self.rpcauth.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie(token: &str) -> OperatorCreds {
        OperatorCreds {
            cookie: Some(CookieCredential {
                path: PathBuf::from("/tmp/test.cookie"),
                token: token.to_string(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn cookie_match() {
        let c = cookie("abcdef1234567890");
        assert!(c.matches("__cookie__", "abcdef1234567890"));
        assert!(!c.matches("__cookie__", "wrong"));
        assert!(!c.matches("alice", "abcdef1234567890"));
    }

    #[test]
    fn userpass_match() {
        let c = OperatorCreds::from_user_pass("alice".into(), "secret".into());
        assert!(c.matches("alice", "secret"));
        assert!(!c.matches("alice", "wrong"));
        assert!(!c.matches("bob", "secret"));
    }

    #[test]
    fn rpcauth_match_core_fixed_vector() {
        // FIXED VECTOR generated independently with CPython from Bitcoin Core's
        // share/rpcauth/rpcauth.py semantics: HMAC-SHA256, key = salt.encode()
        // (ASCII bytes of the printable salt, NOT hex-decoded), message =
        // password. salt="deadbeefcafef00d1122334455667788",
        // password="hunter2longpassword". MUST NOT be re-derived by our own
        // code, or it can't catch a salt-handling regression.
        let salt = "deadbeefcafef00d1122334455667788".to_string();
        let hash = hex::decode("9383f6d244049af54e59a84188e2f2b1e58ff20de019156bc0c430ff8ae4c7a3")
            .unwrap();
        let c = OperatorCreds {
            rpcauth: vec![RpcAuthCredential {
                username: "alice".into(),
                salt,
                hash,
            }],
            ..Default::default()
        };
        assert!(c.matches("alice", "hunter2longpassword"));
        assert!(!c.matches("alice", "wrong"));
        assert!(!c.matches("bob", "hunter2longpassword"));
    }

    #[test]
    fn any_credential_opens_the_door() {
        let salt = "aabbccddeeff00112233445566778899".to_string();
        let mut mac = HmacSha256::new_from_slice(salt.as_bytes()).unwrap();
        mac.update(b"p4ss");
        let hash = mac.finalize().into_bytes().to_vec();
        let c = OperatorCreds {
            cookie: Some(CookieCredential {
                path: PathBuf::from("/tmp/x.cookie"),
                token: "tok".into(),
            }),
            userpass: vec![UserPassCredential {
                username: "alice".into(),
                password: "secret".into(),
            }],
            rpcauth: vec![RpcAuthCredential {
                username: "bob".into(),
                salt,
                hash,
            }],
        };
        assert!(c.matches("__cookie__", "tok"));
        assert!(c.matches("alice", "secret"));
        assert!(c.matches("bob", "p4ss"));
        assert!(!c.matches("eve", "noway"));
        assert!(!c.is_empty());
        assert!(OperatorCreds::default().is_empty());
    }
}
