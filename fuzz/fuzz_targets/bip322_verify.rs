//! Fuzz BIP 322 decoding and verification: an arbitrary challenge script,
//! message and signature string. `verifybip322` is a read-capability RPC, so
//! all three are caller-controlled. Exercises the prefix dispatch, strict
//! base64, witness and transaction decoding, the `to_sign` structure checks,
//! the `OP_CODESEPARATOR` scan and both interpreter passes. Asserts no panic
//! (libfuzzer catches it); the result is discarded.
//!
//! Input layout: one length byte for the script, the script, one length byte
//! for the message, the message, and the rest (lossy UTF-8) as the signature.
//!
//! Run: `cargo +nightly fuzz run bip322_verify` (needs a nightly + sanitizer
//! toolchain; this crate is a standalone workspace excluded from the main build).

#![no_main]

use bitcoin::ScriptBuf;
use libfuzzer_sys::fuzz_target;
use node::bip322::{self, Signature};

fn take<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    let Some((&n, rest)) = data.split_first() else { return &[] };
    let n = (n as usize).min(rest.len());
    let (head, tail) = rest.split_at(n);
    *data = tail;
    head
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let challenge = ScriptBuf::from_bytes(take(&mut data).to_vec());
    let message = take(&mut data).to_vec();
    let signature = String::from_utf8_lossy(data);
    if let Ok(Signature::Bip322(proof)) = bip322::decode(&signature, &challenge) {
        let _ = bip322::verify(&challenge, &message, &proof);
    }
});
