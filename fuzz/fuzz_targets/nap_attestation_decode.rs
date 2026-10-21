//! Fuzz the NAP attestation decoder. Attestations arrive from peers in
//! `napatt` messages, so every byte is attacker-controlled. Asserts the
//! decoder accepts only canonical bytes: whatever decodes re-encodes to the
//! same bytes, and so has one id.
//!
//! Run: `cargo +nightly fuzz run nap_attestation_decode` (needs a nightly +
//! sanitizer toolchain; this crate is a standalone workspace excluded from
//! the main build).

#![no_main]

use libfuzzer_sys::fuzz_target;
use node::nap::Attestation;

fuzz_target!(|data: &[u8]| {
    if let Ok(att) = Attestation::from_bytes(data) {
        assert_eq!(att.to_bytes(), data);
        assert!(data.len() <= node::nap::MAX_ATTESTATION_SIZE);
    }
    let mut r = data;
    while let Ok(att) = Attestation::decode_from(&mut r) {
        let _ = att.message();
    }
});
