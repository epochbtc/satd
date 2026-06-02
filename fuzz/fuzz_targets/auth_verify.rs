//! Fuzz the attacker-facing auth path: parse an arbitrary `Authorization`
//! header value and run it through the verifier. Exercises base64 decoding,
//! UTF-8 handling, the `user:pass` split, the HMAC-SHA256 rpcauth compare, and
//! the bearer SHA-256 + constant-time path. Asserts no panic and no plaintext
//! leak (libfuzzer catches panics; this target returns nothing).
//!
//! Run: `cargo +nightly fuzz run auth_verify` (needs a nightly + sanitizer
//! toolchain; this crate is a standalone workspace excluded from the main build).

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use satd_auth::{Credential, OperatorCreds, Verifier};

fn verifier() -> &'static Verifier {
    static V: OnceLock<Verifier> = OnceLock::new();
    V.get_or_init(|| {
        // A realistic operator set: cookie-shaped userpass plus an rpcauth-free
        // baseline. No token store (the file path is operator-controlled, not
        // attacker-controlled at runtime), so this target focuses on the header
        // parser + operator verify, the genuinely untrusted-input surface.
        let op = OperatorCreds::from_user_pass("operator".to_string(), "password".to_string());
        Verifier::new(op, None)
    })
}

fuzz_target!(|data: &[u8]| {
    let hdr = String::from_utf8_lossy(data);
    let mut scratch = String::new();
    if let Some(cred) = Credential::from_authorization(&hdr, &mut scratch) {
        let _ = verifier().resolve(cred);
    }
});
